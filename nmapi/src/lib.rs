//! NetworkManager observation for DrayTek VPN connections.
//!
//! Shared by the tray indicator and the standalone client, because both answer
//! the same question — "is a DrayTek VPN up, and through what?" — and the answer
//! lives in NetworkManager, not in either of them. Both clients are front ends
//! for the same NM VPN plugin; neither owns a tunnel of its own, so there is one
//! source of truth to read and one connection path to drive.

use anyhow::{Context, Result};
use futures_util::{FutureExt, StreamExt};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
use tracing::{debug, info, warn};
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::Connection;

pub mod profile;
pub use profile::{add_profile, delete_profile, load_profile, update_profile, DraytekProfile};

/// The VPN service type the NM plugin registers.
pub const SERVICE_TYPE: &str = "org.freedesktop.NetworkManager.draytek";

/// `NM_SETTINGS_ADD_*`: persist the new connection to disk.
///
/// `AddConnection2` refuses flags of 0 — a connection that exists only in memory
/// would vanish when the daemon restarted, and a profile the user just filled in
/// has to outlive that.
pub const ADD_TO_DISK: u32 = 0x1;

// ── VPN state shared with the front ends ────────────────────────────

#[derive(Debug, Clone, Default)]
pub enum VpnState {
    #[default]
    Disconnected,
    Connecting {
        name: String,
    },
    Connected {
        name: String,
        /// Address assigned to the tunnel interface.
        ip: String,
        /// The VPN *server*, read from `vpn.data.gateway`. Not the in-tunnel
        /// peer — NM does not expose the latter, and conflating the two makes
        /// the display claim a gateway address the tunnel never had.
        server: String,
        /// Resolvers NM applied to the tunnel, from the active connection's
        /// IPv4 config.
        ///
        /// Worth carrying: a full tunnel routes DNS through the tunnel as well,
        /// so a resolver the router cannot reach gives a tunnel that is up,
        /// routed, and unable to resolve anything.
        dns: Vec<String>,
        routes: Vec<String>,
        path: OwnedObjectPath,
        connected_at: u64,
        keepalive: bool,
    },
    /// The connection failed, with the reason the plugin reported.
    ///
    /// Kept distinct from [`VpnState::Disconnected`] so a front end can say
    /// *why* rather than flashing "Disconnected" and looking like nothing
    /// happened.
    Failed {
        name: String,
        reason: String,
    },
}

impl VpnState {
    /// Whether NM's config gave the tunnel the default route.
    ///
    /// NM expresses this as a `0.0.0.0/0` entry in the connection's route data,
    /// so it is read off the routes rather than from a separate flag.
    pub fn has_default_route(&self) -> bool {
        match self {
            VpnState::Connected { routes, .. } => {
                routes.iter().any(|r| r == "0.0.0.0/0" || r == "0.0.0.0")
            }
            _ => false,
        }
    }

    /// Routes to show for a full tunnel: the default route is the headline, and
    /// listing it alongside the split routes it replaces reads as a mistake.
    pub fn display_routes(&self) -> Vec<String> {
        match self {
            VpnState::Connected { routes, .. } => routes
                .iter()
                .filter(|r| *r != "0.0.0.0/0" && *r != "0.0.0.0")
                .cloned()
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// NM VPN failure reasons, as reported in the `Failure` signal.
///
/// Only the two the DrayTek plugin actually emits are named; anything else
/// falls back to the raw number so an unexpected code is still visible instead
/// of being flattened into a generic message.
fn failure_reason(reason: u32) -> String {
    match reason {
        0 => "Login failed — check the username and password".to_string(),
        1 => "Could not reach the VPN server".to_string(),
        other => format!("Connection failed (reason {other})"),
    }
}

// ── NM D-Bus proxy traits ───────────────────────────────────────────

/// org.freedesktop.NetworkManager
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
trait NetworkManager {
    #[zbus(property)]
    fn active_connections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    fn activate_connection(
        &self,
        connection: &OwnedObjectPath,
        device: &OwnedObjectPath,
        specific_object: &OwnedObjectPath,
    ) -> zbus::Result<OwnedObjectPath>;

    fn deactivate_connection(&self, active_connection: &OwnedObjectPath) -> zbus::Result<()>;
}

/// org.freedesktop.NetworkManager.Connection.Active
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Connection.Active",
    default_service = "org.freedesktop.NetworkManager"
)]
trait ActiveConnection {
    #[zbus(property)]
    fn vpn(&self) -> zbus::Result<bool>;

    #[zbus(property)]
    fn id(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn state(&self) -> zbus::Result<u32>;

    #[zbus(property)]
    fn connection(&self) -> zbus::Result<OwnedObjectPath>;

    #[zbus(property)]
    fn ip4_config(&self) -> zbus::Result<OwnedObjectPath>;
}

/// org.freedesktop.NetworkManager.VPN.Connection
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.VPN.Connection",
    default_service = "org.freedesktop.NetworkManager"
)]
trait VpnConnection {
    #[zbus(signal)]
    fn vpn_state_changed(&self, state: u32, reason: u32) -> zbus::Result<()>;
}

/// org.freedesktop.NetworkManager.IP4Config
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.IP4Config",
    default_service = "org.freedesktop.NetworkManager"
)]
trait Ip4Config {
    #[zbus(property)]
    fn address_data(&self) -> zbus::Result<Vec<HashMap<String, zbus::zvariant::OwnedValue>>>;

    #[zbus(property)]
    fn route_data(&self) -> zbus::Result<Vec<HashMap<String, zbus::zvariant::OwnedValue>>>;

    /// The resolvers, as `aa{sv}` entries keyed by `address`.
    ///
    /// Named `NameserverData` since NM 1.40. Older versions called the same
    /// thing `DnsData`, which is why the read below falls back — a proxy
    /// property that does not exist simply errors, so trying both is cheap and
    /// the failure stays a debug line rather than a warning on every connect.
    #[zbus(property)]
    fn nameserver_data(&self) -> zbus::Result<Vec<HashMap<String, zbus::zvariant::OwnedValue>>>;

    /// The pre-1.40 spelling of `nameserver_data`.
    #[zbus(property)]
    fn dns_data(&self) -> zbus::Result<Vec<HashMap<String, zbus::zvariant::OwnedValue>>>;
}

/// org.freedesktop.NetworkManager.Settings.Connection
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Settings.Connection",
    default_service = "org.freedesktop.NetworkManager"
)]
trait SettingsConnection {
    fn get_settings(
        &self,
    ) -> zbus::Result<HashMap<String, HashMap<String, zbus::zvariant::OwnedValue>>>;

    /// Replace this connection's settings.
    ///
    /// One argument, no return value — read off NM 1.54's own introspection
    /// rather than assumed. The three-argument `Update2` (settings, flags, args)
    /// does not exist there and fails with `UnknownMethod`.
    ///
    /// This is a method of the per-connection object, not of `Settings`: calling
    /// it on the `Settings` interface fails the same way, which is the only clue
    /// that the two interfaces are easy to confuse.
    fn update(&self, connection: HashMap<String, HashMap<String, OwnedValue>>) -> zbus::Result<()>;

    /// Delete this connection.
    fn delete(&self) -> zbus::Result<()>;
}

/// org.freedesktop.NetworkManager.Settings
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Settings",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager/Settings"
)]
trait Settings {
    fn list_connections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Add a new connection from a full settings dictionary.
    ///
    /// `AddConnection2` rather than the older `AddConnection`: the newer call
    /// takes flags that let a caller defer persisting, and it is what NM's own
    /// front ends use. `flags` is a bitfield of `NM_SETTINGS_ADD_*`; zero means
    /// "add to disk and to memory", which is what an interactive front end wants.
    /// Returns the new connection's path plus NM's result arguments. The second
    /// half of the tuple is part of the reply signature, so declaring the return
    /// as a bare path makes every call fail with a signature mismatch.
    fn add_connection2(
        &self,
        connection: HashMap<String, HashMap<String, OwnedValue>>,
        flags: u32,
        args: HashMap<String, OwnedValue>,
    ) -> zbus::Result<(OwnedObjectPath, HashMap<String, OwnedValue>)>;
}

// NM VPN connection states
mod vpn_conn_state {
    pub const UNKNOWN: u32 = 0;
    pub const PREPARE: u32 = 1;
    pub const NEED_AUTH: u32 = 2;
    pub const CONNECT: u32 = 3;
    pub const IP_CONFIG_GET: u32 = 4;
    pub const ACTIVATED: u32 = 5;
    pub const FAILED: u32 = 6;
    pub const DISCONNECTED: u32 = 7;
}

// ── Monitor loop ────────────────────────────────────────────────────

/// Monitor NM for DrayTek VPN connections and push state changes.
pub async fn monitor_vpn(conn: Connection, state_tx: watch::Sender<VpnState>) -> Result<()> {
    // Default `CacheProperties::Lazily` — wires up the PropertiesChanged
    // subscription that backs `receive_active_connections_changed()`. With
    // `CacheProperties::No` the property-change stream ends on first poll,
    // putting the monitor in a 5-second restart loop.
    let nm = NetworkManagerProxy::builder(&conn).build().await?;

    // Track which connection paths already have a watcher task
    let watched: Arc<Mutex<HashSet<OwnedObjectPath>>> = Arc::new(Mutex::new(HashSet::new()));

    // Check for an existing DrayTek VPN connection on startup
    check_active_connections(&conn, &nm, &state_tx, &watched).await;

    // Watch for property changes on ActiveConnections
    let mut changes = nm.receive_active_connections_changed().await;

    info!("watching NM ActiveConnections for DrayTek VPN");

    loop {
        // Wait for ActiveConnections property to change
        if changes.next().await.is_none() {
            // Stream ended — reconnect after a delay
            warn!("ActiveConnections stream ended, restarting monitor");
            return Ok(());
        }

        // Debounce: wait briefly then drain any queued signals
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        loop {
            match changes.next().now_or_never() {
                Some(Some(_)) => continue,   // drain buffered event
                Some(None) => return Ok(()), // stream ended
                None => break,               // no more buffered events
            }
        }

        // Skip if we already have a watcher — no need to rescan
        if !watched
            .lock()
            .expect("watched-paths lock poisoned")
            .is_empty()
        {
            continue;
        }

        debug!("ActiveConnections changed, scanning for DrayTek VPN");
        check_active_connections(&conn, &nm, &state_tx, &watched).await;
    }
}

/// Scan active connections for a DrayTek VPN and subscribe to its state.
async fn check_active_connections(
    conn: &Connection,
    nm: &NetworkManagerProxy<'_>,
    state_tx: &watch::Sender<VpnState>,
    watched: &Arc<Mutex<HashSet<OwnedObjectPath>>>,
) {
    let active_paths = match nm.active_connections().await {
        Ok(paths) => paths,
        Err(e) => {
            warn!("failed to get ActiveConnections: {e}");
            return;
        }
    };

    let mut found_draytek = false;

    for path in &active_paths {
        // Skip paths we're already watching
        if watched
            .lock()
            .expect("watched-paths lock poisoned")
            .contains(path)
        {
            found_draytek = true;
            continue;
        }

        if let Some(info) = check_connection(conn, path).await {
            found_draytek = true;

            // Mark as watched before spawning
            watched
                .lock()
                .expect("watched-paths lock poisoned")
                .insert(path.clone());
            info!("watching DrayTek VPN connection: {} at {}", info.name, path);

            let conn2 = conn.clone();
            let state_tx2 = state_tx.clone();
            let path2 = path.clone();
            let watched2 = watched.clone();
            let name = info.name;
            tokio::spawn(async move {
                if let Err(e) = watch_vpn_connection(&conn2, &state_tx2, &path2, &name).await {
                    warn!("VPN connection watcher ended: {e}");
                }
                // Remove from watched set and signal disconnected
                watched2
                    .lock()
                    .expect("watched-paths lock poisoned")
                    .remove(&path2);
                let _ = state_tx2.send(VpnState::Disconnected);
            });
        }
    }

    if !found_draytek {
        // Don't re-broadcast Disconnected when already disconnected. NM emits
        // ActiveConnections changes for unrelated events (wifi blips, IP renewals);
        // each redundant send wakes the main loop and used to trigger a fresh
        // bus-connection-per-refetch, exhausting the per-UID dbus connection limit.
        state_tx.send_if_modified(|cur| {
            if matches!(cur, VpnState::Disconnected) {
                false
            } else {
                *cur = VpnState::Disconnected;
                true
            }
        });
    }
}

struct ConnectionInfo {
    name: String,
}

/// Check if a single active connection is a DrayTek VPN.
async fn check_connection(conn: &Connection, path: &OwnedObjectPath) -> Option<ConnectionInfo> {
    let ac = ActiveConnectionProxy::builder(conn)
        .path(path.as_ref())
        .ok()?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .ok()?;

    // Must be a VPN connection
    if !ac.vpn().await.unwrap_or(false) {
        return None;
    }

    let name = ac.id().await.unwrap_or_default();

    // Check settings to see if it's our service type
    let settings_path = ac.connection().await.ok()?;
    let settings_conn = SettingsConnectionProxy::builder(conn)
        .path(settings_path.as_ref())
        .ok()?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .ok()?;

    let settings = settings_conn.get_settings().await.ok()?;
    let vpn_settings = settings.get("vpn")?;
    let service: String = vpn_settings.get("service-type")?.clone().try_into().ok()?;

    if service == SERVICE_TYPE {
        Some(ConnectionInfo { name })
    } else {
        None
    }
}

/// Watch a specific VPN active connection for state changes.
async fn watch_vpn_connection(
    conn: &Connection,
    state_tx: &watch::Sender<VpnState>,
    path: &OwnedObjectPath,
    name: &str,
) -> Result<()> {
    let vpn_conn = VpnConnectionProxy::builder(conn)
        .path(path.as_ref())?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    let ac = ActiveConnectionProxy::builder(conn)
        .path(path.as_ref())?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    // Check current ActiveConnection state (NM_ACTIVE_CONNECTION_STATE)
    // 0=Unknown, 1=Activating, 2=Activated, 3=Deactivating, 4=Deactivated
    let ac_state = ac.state().await.unwrap_or(0);
    let initial_vpn_state = match ac_state {
        2 => vpn_conn_state::ACTIVATED,
        1 => vpn_conn_state::CONNECT,
        3 => vpn_conn_state::DISCONNECTED,
        4 => vpn_conn_state::DISCONNECTED,
        _ => vpn_conn_state::UNKNOWN,
    };
    handle_vpn_state(conn, state_tx, initial_vpn_state, 0, path, name, &ac).await;

    // Subscribe to VpnStateChanged signal
    let mut signal_stream = vpn_conn.receive_vpn_state_changed().await?;

    while let Some(signal) = signal_stream.next().await {
        let args = match signal.args() {
            Ok(a) => a,
            Err(e) => {
                warn!("Skipping malformed VpnStateChanged signal: {e}");
                continue;
            }
        };
        let state = *args.state();
        let reason = *args.reason();
        debug!("VpnStateChanged: state={state} reason={reason}");

        handle_vpn_state(conn, state_tx, state, reason, path, name, &ac).await;

        // If disconnected or failed, stop watching
        if state == vpn_conn_state::DISCONNECTED || state == vpn_conn_state::FAILED {
            break;
        }
    }

    Ok(())
}

async fn handle_vpn_state(
    conn: &Connection,
    state_tx: &watch::Sender<VpnState>,
    state: u32,
    reason: u32,
    path: &OwnedObjectPath,
    name: &str,
    ac: &ActiveConnectionProxy<'_>,
) {
    let new_state = match state {
        vpn_conn_state::PREPARE
        | vpn_conn_state::NEED_AUTH
        | vpn_conn_state::CONNECT
        | vpn_conn_state::IP_CONFIG_GET => VpnState::Connecting {
            name: name.to_string(),
        },
        vpn_conn_state::ACTIVATED => {
            let ip = read_ip(conn, ac).await.unwrap_or_default();
            let server = read_vpn_server(conn, ac).await.unwrap_or_default();
            let dns = read_dns(conn, ac).await.unwrap_or_default();
            let routes = read_routes(conn, ac).await.unwrap_or_default();
            let connected_at = read_connection_timestamp(conn, ac).await.unwrap_or(0);
            let keepalive = read_vpn_keepalive(conn, ac).await.unwrap_or(false);
            info!("VPN connected: {name} ip={ip} server={server} dns={dns:?} routes={routes:?} timestamp={connected_at} keepalive={keepalive}");
            VpnState::Connected {
                name: name.to_string(),
                ip,
                server,
                dns,
                routes,
                path: path.clone(),
                connected_at,
                keepalive,
            }
        }
        vpn_conn_state::FAILED => VpnState::Failed {
            name: name.to_string(),
            reason: failure_reason(reason),
        },
        vpn_conn_state::DISCONNECTED | vpn_conn_state::UNKNOWN => VpnState::Disconnected,
        _ => return,
    };

    let _ = state_tx.send(new_state);
}

/// Read the IP address from the active connection's Ip4Config.
async fn read_ip(conn: &Connection, ac: &ActiveConnectionProxy<'_>) -> Option<String> {
    let ip4_path = ac.ip4_config().await.ok()?;

    // Skip if path is "/" (no config yet)
    if ip4_path.as_str() == "/" {
        return None;
    }

    let ip4 = Ip4ConfigProxy::builder(conn)
        .path(ip4_path.as_ref())
        .ok()?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .ok()?;

    let addresses = ip4.address_data().await.ok()?;
    let first = addresses.first()?;
    let addr: String = first.get("address")?.clone().try_into().ok()?;
    Some(addr)
}

/// Read the resolvers NM applied, from the active connection's Ip4Config.
///
/// Every failure is logged rather than collapsed into an empty list. "The router
/// gave us no DNS" and "we could not read what NM has" call for opposite
/// reactions — the first is a router problem, the second is a bug here — and the
/// status view cannot tell them apart unless this does.
async fn read_dns(conn: &Connection, ac: &ActiveConnectionProxy<'_>) -> Option<Vec<String>> {
    let ip4_path = match ac.ip4_config().await {
        Ok(p) if p.as_str() != "/" => p,
        Ok(_) => {
            debug!("no IP4Config on the active connection yet; DNS not read");
            return None;
        }
        Err(e) => {
            warn!("could not read the active connection's IP4Config: {e}");
            return None;
        }
    };

    let ip4 = match Ip4ConfigProxy::builder(conn)
        .path(ip4_path.as_ref())
        .ok()
        .map(|b| b.cache_properties(CacheProperties::No))
    {
        Some(builder) => match builder.build().await {
            Ok(p) => p,
            Err(e) => {
                warn!("could not read IP4Config at {ip4_path}: {e}");
                return None;
            }
        },
        None => {
            warn!("IP4Config path {ip4_path} is not a valid object path");
            return None;
        }
    };

    let entries: Vec<HashMap<String, OwnedValue>> = match ip4.nameserver_data().await {
        Ok(e) => e,
        Err(e) => {
            // Pre-1.40 NM spells it `DnsData`. Only worth trying when the modern
            // name is genuinely absent, so a real read error is not masked.
            debug!("nameserver_data unavailable ({e}); trying the pre-1.40 DnsData");
            match ip4.dns_data().await {
                Ok(e) => e,
                Err(e) => {
                    warn!(
                        "IP4Config at {ip4_path} exposes no readable nameserver data \
                         (nameserver_data: {e}; DnsData: {e2})",
                        e2 = e
                    );
                    return None;
                }
            }
        }
    };

    let servers: Vec<String> = entries
        .iter()
        .filter_map(|entry| {
            let value = entry.get("address")?;
            match value.clone().try_into() {
                Ok(s) => Some(s),
                Err(_) => {
                    warn!("dns_data entry has a non-string address: {value:?}");
                    None
                }
            }
        })
        .collect();

    if servers.is_empty() {
        debug!("IP4Config at {ip4_path} reports no DNS servers");
    }
    (!servers.is_empty()).then_some(servers)
}

/// Read routes from the active connection's Ip4Config.
async fn read_routes(conn: &Connection, ac: &ActiveConnectionProxy<'_>) -> Option<Vec<String>> {
    let ip4_path = ac.ip4_config().await.ok()?;
    if ip4_path.as_str() == "/" {
        return None;
    }

    let ip4 = Ip4ConfigProxy::builder(conn)
        .path(ip4_path.as_ref())
        .ok()?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .ok()?;

    let route_data = ip4.route_data().await.ok()?;
    let routes: Vec<String> = route_data
        .iter()
        .filter_map(|entry| {
            let dest: String = entry.get("dest")?.clone().try_into().ok()?;
            let prefix: u32 = entry.get("prefix")?.clone().try_into().ok()?;
            Some(format!("{dest}/{prefix}"))
        })
        .collect();

    if routes.is_empty() {
        None
    } else {
        Some(routes)
    }
}

/// Read the VPN server address from the connection's `vpn.data` settings.
async fn read_vpn_server(conn: &Connection, ac: &ActiveConnectionProxy<'_>) -> Option<String> {
    let settings_path = ac.connection().await.ok()?;
    let sc = SettingsConnectionProxy::builder(conn)
        .path(settings_path.as_ref())
        .ok()?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .ok()?;

    let settings = sc.get_settings().await.ok()?;
    let vpn_section = settings.get("vpn")?;
    let data: HashMap<String, String> = vpn_section.get("data")?.clone().try_into().ok()?;
    let gateway = data.get("gateway")?.clone();
    let port = data
        .get("port")
        .cloned()
        .unwrap_or_else(|| "443".to_string());
    Some(format!("{gateway}:{port}"))
}

/// Read the keepalive flag from the connection's vpn.data settings.
async fn read_vpn_keepalive(conn: &Connection, ac: &ActiveConnectionProxy<'_>) -> Option<bool> {
    let settings_path = ac.connection().await.ok()?;
    let sc = SettingsConnectionProxy::builder(conn)
        .path(settings_path.as_ref())
        .ok()?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .ok()?;

    let settings = sc.get_settings().await.ok()?;
    let vpn_section = settings.get("vpn")?;
    let data: HashMap<String, String> = vpn_section.get("data")?.clone().try_into().ok()?;
    Some(data.get("keepalive").map(|v| v == "yes").unwrap_or(false))
}

/// Read the activation timestamp from the connection's settings.
/// NM stores `connection.timestamp` as a Unix epoch (seconds) updated on activation.
async fn read_connection_timestamp(
    conn: &Connection,
    ac: &ActiveConnectionProxy<'_>,
) -> Option<u64> {
    let settings_path = ac.connection().await.ok()?;
    let sc = SettingsConnectionProxy::builder(conn)
        .path(settings_path.as_ref())
        .ok()?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .ok()?;

    let settings = sc.get_settings().await.ok()?;
    let conn_section = settings.get("connection")?;
    let timestamp: u64 = conn_section.get("timestamp")?.clone().try_into().ok()?;
    Some(timestamp)
}

/// Disconnect a VPN connection by calling DeactivateConnection on NM.
pub async fn disconnect_vpn(conn: &Connection, path: &OwnedObjectPath) -> Result<()> {
    let nm = NetworkManagerProxy::builder(conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    nm.deactivate_connection(path)
        .await
        .context("DeactivateConnection failed")?;

    info!("disconnected VPN at {}", path);
    Ok(())
}

// ── Saved VPN connections ───────────────────────────────────────────

/// A saved DrayTek VPN connection profile in NM.
#[derive(Debug, Clone)]
pub struct SavedVpn {
    pub name: String,
    pub path: OwnedObjectPath,
}

/// List all saved DrayTek VPN connections from NM Settings.
pub async fn list_saved_vpns(conn: &Connection) -> Vec<SavedVpn> {
    match list_saved_vpns_inner(conn).await {
        Ok(vpns) => vpns,
        Err(e) => {
            warn!("failed to list saved VPN connections: {e}");
            Vec::new()
        }
    }
}

async fn list_saved_vpns_inner(conn: &Connection) -> Result<Vec<SavedVpn>> {
    let settings = SettingsProxy::builder(conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    let paths = settings.list_connections().await?;
    let mut vpns = Vec::new();

    for path in &paths {
        let sc = match SettingsConnectionProxy::builder(conn)
            .path(path.as_ref())
            .ok()
            .map(|b| b.cache_properties(CacheProperties::No))
        {
            Some(builder) => match builder.build().await {
                Ok(sc) => sc,
                Err(_) => continue,
            },
            None => continue,
        };

        let all_settings = match sc.get_settings().await {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Check if it's a VPN with our service type
        let vpn_settings = match all_settings.get("vpn") {
            Some(s) => s,
            None => continue,
        };

        let service: String = match vpn_settings
            .get("service-type")
            .and_then(|v| v.clone().try_into().ok())
        {
            Some(s) => s,
            None => continue,
        };

        if service != SERVICE_TYPE {
            continue;
        }

        // Get connection name from the "connection" section
        let name = all_settings
            .get("connection")
            .and_then(|c| c.get("id"))
            .and_then(|v| v.clone().try_into().ok())
            .unwrap_or_else(|| "DrayTek VPN".to_string());

        vpns.push(SavedVpn {
            name,
            path: path.clone(),
        });
    }

    Ok(vpns)
}

/// Activate a saved VPN connection.
pub async fn connect_vpn(conn: &Connection, settings_path: &OwnedObjectPath) -> Result<()> {
    let nm = NetworkManagerProxy::builder(conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    let root: OwnedObjectPath = zbus::zvariant::ObjectPath::try_from("/").unwrap().into();

    nm.activate_connection(settings_path, &root, &root)
        .await
        .context("ActivateConnection failed")?;

    info!("activating VPN connection at {}", settings_path);
    Ok(())
}

/// A random RFC 4122 version 4 UUID, for connections NM has not seen before.
///
/// NM rejects an `AddConnection2` whose `connection.uuid` is not a valid UUID,
/// and it will not invent one. Sixteen bytes from the kernel CSPRNG is the whole
/// requirement, so this avoids taking a dependency for a single formatted
/// random string.
pub fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    // /dev/urandom is always available on Linux and never blocks; getrandom(2)
    // would need a crate or an extern declaration for no benefit here.
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut bytes)
        })
        .is_err()
    {
        // Without randomness there is no safe fallback: a predictable UUID
        // invites a second connection colliding with this one.
        panic!("cannot read /dev/urandom to generate a connection UUID");
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant

    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        hex[0],
        hex[1],
        hex[2],
        hex[3],
        hex[4],
        hex[5],
        hex[6],
        hex[7],
        hex[8],
        hex[9],
        hex[10],
        hex[11],
        hex[12],
        hex[13],
        hex[14],
        hex[15]
    )
}
