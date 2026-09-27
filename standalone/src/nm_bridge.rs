//! Bridge between NetworkManager and the GTK main loop.
//!
//! The app owns no tunnel. It activates and deactivates NetworkManager's VPN
//! plugin and renders whatever NM reports, so the window, the tray and GNOME
//! Settings can never disagree about whether the VPN is up — they are all
//! reading the same connection.

use draytek_vpn_nmapi::{
    add_profile, connect_vpn, delete_profile, disconnect_vpn, list_saved_vpns, load_profile,
    monitor_vpn, update_profile, uuid_v4, DraytekProfile, SavedVpn, VpnState,
};
use tokio::sync::watch;
use tracing::{info, warn};
use zbus::zvariant::OwnedObjectPath;
use zbus::Connection;

use crate::glib_channels::GlibSender;

/// The TUN device the NM plugin creates, and therefore the only one this app
/// reads statistics from. NM owns its lifecycle.
const TUN_DEVICE: &str = "draytek0";

/// A live NM session, used to drive connections.
#[derive(Clone)]
pub struct NmSession {
    conn: Connection,
}

impl NmSession {
    /// Open a connection to NetworkManager.
    ///
    /// The **system** bus, not the session bus. NetworkManager is a system
    /// service: it owns no session-bus name at all, so asking the session bus
    /// for it returns `ServiceUnknown` every time — a failure that looks exactly
    /// like NM being absent, and leaves the window permanently reporting
    /// "disconnected" while a VPN is up. Unprivileged clients are expected here;
    /// NM authorises each call itself, prompting through the desktop's agent
    /// only if the connection's policy requires it.
    pub async fn open() -> anyhow::Result<Self> {
        Ok(Self {
            conn: Connection::system().await?,
        })
    }

    /// Activate a saved DrayTek VPN connection.
    pub async fn activate(&self, path: &OwnedObjectPath, name: &str) -> anyhow::Result<()> {
        info!("Requesting NM to activate DrayTek VPN connection {name}");
        connect_vpn(&self.conn, path).await
    }

    /// Deactivate the active DrayTek VPN connection.
    pub async fn deactivate(&self, path: &OwnedObjectPath) -> anyhow::Result<()> {
        disconnect_vpn(&self.conn, path).await
    }

    /// The saved DrayTek VPN connections NM knows about.
    pub async fn saved(&self) -> Vec<SavedVpn> {
        list_saved_vpns(&self.conn).await
    }

    /// Create a new DrayTek VPN connection, returning the path NM gave it.
    pub async fn add(&self, profile: &DraytekProfile) -> anyhow::Result<OwnedObjectPath> {
        add_profile(&self.conn, profile, &uuid_v4()).await
    }

    /// Replace an existing connection's settings.
    pub async fn update(
        &self,
        path: &OwnedObjectPath,
        profile: &DraytekProfile,
    ) -> anyhow::Result<()> {
        update_profile(&self.conn, path, profile).await
    }

    /// Delete a connection.
    pub async fn remove(&self, path: &OwnedObjectPath) -> anyhow::Result<()> {
        delete_profile(&self.conn, path).await
    }

    /// Read a connection's settings back, for populating the edit form.
    pub async fn load(&self, path: &OwnedObjectPath) -> anyhow::Result<Option<DraytekProfile>> {
        load_profile(&self.conn, path).await
    }
}

/// Watch NM and forward every VPN state transition to the GTK main loop.
///
/// A failure to reach NetworkManager is reported as a `Failed` state rather
/// than being swallowed: with no way to ask, the window must not sit there
/// claiming to be disconnected when in fact it simply cannot tell.
pub fn watch_nm(tokio_handle: &tokio::runtime::Handle, on_state: GlibSender<VpnState>) {
    // Cloned so the spawned task owns it: a `&Handle` cannot outlive the
    // function that borrowed it, and the forwarding task below outlives this one.
    let handle = tokio_handle.clone();
    tokio_handle.spawn(async move {
        let session = match NmSession::open().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Cannot reach NetworkManager: {e:#}");
                on_state.send(VpnState::Failed {
                    name: "NetworkManager".to_string(),
                    reason: format!("Cannot reach NetworkManager: {e}"),
                });
                return;
            }
        };

        let (state_tx, mut state_rx) = watch::channel(VpnState::Disconnected);

        // The monitor blocks for as long as the bus lives, so forwarding runs
        // beside it rather than after it.
        let forward = on_state.clone();
        handle.spawn(async move {
            while state_rx.changed().await.is_ok() {
                let state = state_rx.borrow_and_update().clone();
                forward.send(state);
            }
        });

        if let Err(e) = monitor_vpn(session.conn.clone(), state_tx).await {
            warn!("NM monitor ended: {e:#}");
        }
    });
}

/// Keep the saved-connection list fresh, pushing only on a real change.
///
/// A connection can be added or removed from GNOME Settings while this window
/// is open, so the list cannot be fetched once at startup. Rebuilding the
/// dropdown on every poll would also throw away the user's selection, hence the
/// change check.
pub fn watch_saved(
    tokio_handle: &tokio::runtime::Handle,
    session: std::sync::Arc<NmSession>,
    out: GlibSender<Vec<SavedVpn>>,
) {
    tokio_handle.spawn(async move {
        let mut last: Vec<String> = Vec::new();
        loop {
            let saved = session.saved().await;
            let names: Vec<String> = saved.iter().map(|v| v.name.clone()).collect();
            if names != last {
                last = names;
                out.send(saved);
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

/// The tunnel's byte counters, read from sysfs.
///
/// The plugin owns the data path, so the app is a bystander here — but the
/// kernel counts the same packets either way, and reading the counters is how
/// the window shows traffic without owning a single packet of it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TunnelStats {
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub packets_rx: u64,
    pub packets_tx: u64,
}

/// Poll the tunnel interface's counters. Returns `None` while it is not up,
/// which is the normal answer when disconnected.
pub fn read_stats() -> Option<TunnelStats> {
    let read = |field: &str| -> Option<u64> {
        std::fs::read_to_string(format!("/sys/class/net/{TUN_DEVICE}/statistics/{field}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    };
    Some(TunnelStats {
        bytes_rx: read("rx_bytes")?,
        bytes_tx: read("tx_bytes")?,
        packets_rx: read("rx_packets")?,
        packets_tx: read("tx_packets")?,
    })
}
