/// NetworkManager VPN Plugin D-Bus interface.
///
/// Implements org.freedesktop.NetworkManager.VPN.Plugin on the system bus.
use anyhow::Result;
use std::collections::HashMap;
use tracing::{error, info};
use zbus::object_server::SignalEmitter;
use zbus::{connection, interface, Connection};

use crate::tunnel::TunnelHandle;

/// NM VPN plugin states (from NM source).
mod nm_vpn_state {
    pub const INIT: u32 = 1;
    pub const STARTING: u32 = 3;
    pub const STOPPING: u32 = 5;
    pub const STOPPED: u32 = 6;
}

/// NM VPN failure reasons.
pub mod nm_vpn_failure {
    pub const LOGIN_FAILED: u32 = 0;
    pub const CONNECT_FAILED: u32 = 1;
}

type Settings = HashMap<String, HashMap<String, zbus::zvariant::OwnedValue>>;

pub struct VpnPlugin {
    vpn_state: u32,
    tunnel: Option<TunnelHandle>,
    connection: Connection,
    /// Secrets handed to us by NM through `NewSecrets`.
    ///
    /// NM may deliver the password out-of-band: it calls `NeedSecrets`, gets
    /// the answer from a secret agent, then calls `NewSecrets`. That value is
    /// not present in the `Settings` passed to `ConnectInteractive`, so it has
    /// to be kept here and merged in when the tunnel is actually started.
    /// Discarding it left the profile with an empty password.
    extra_secrets: HashMap<String, String>,
}

impl VpnPlugin {
    fn new(connection: Connection) -> Self {
        VpnPlugin {
            vpn_state: nm_vpn_state::INIT,
            tunnel: None,
            connection,
            extra_secrets: HashMap::new(),
        }
    }

    /// Pull the `vpn.secrets` section out of an NM `Settings` map.
    fn extract_secrets(settings: &Settings) -> HashMap<String, String> {
        settings
            .get("vpn")
            .and_then(|vpn| vpn.get("secrets"))
            .and_then(|secrets| {
                let dict: Result<HashMap<String, String>, _> = secrets.clone().try_into();
                dict.ok()
            })
            .unwrap_or_default()
    }
}

#[interface(name = "org.freedesktop.NetworkManager.VPN.Plugin")]
impl VpnPlugin {
    /// Connect to a VPN using the given settings.
    async fn connect(
        &mut self,
        settings: Settings,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        info!("Connect called");
        self.do_connect(settings, &emitter).await
    }

    /// Connect interactively (same as Connect for us — we don't need interactive secrets).
    async fn connect_interactive(
        &mut self,
        settings: Settings,
        _details: HashMap<String, zbus::zvariant::OwnedValue>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        info!("ConnectInteractive called");
        self.do_connect(settings, &emitter).await
    }

    /// Check if secrets are needed. Returns the setting name that needs secrets, or "".
    async fn need_secrets(&self, settings: Settings) -> zbus::fdo::Result<String> {
        // The name must match the key inside `vpn.secrets`. Returning "vpn"
        // here asked the secret agent for a secret that does not exist, so the
        // agent never answered and NM timed out.
        let has_password = Self::extract_secrets(&settings).contains_key("password");
        if has_password || self.extra_secrets.contains_key("password") {
            info!("NeedSecrets: password already available");
            Ok(String::new())
        } else {
            info!("NeedSecrets: requesting 'password' from secret agent");
            Ok("password".to_string())
        }
    }

    /// Accept updated secrets from NM's secret agent.
    ///
    /// These must be retained: they are not part of the `Settings` NM passes
    /// to `ConnectInteractive`, and the tunnel cannot authenticate without
    /// them.
    async fn new_secrets(&mut self, settings: Settings) -> zbus::fdo::Result<()> {
        let secrets = Self::extract_secrets(&settings);
        info!("NewSecrets called with {} secret(s)", secrets.len());
        self.extra_secrets = secrets;
        Ok(())
    }

    /// Disconnect the active VPN connection.
    ///
    /// Returns as soon as the tunnel has been asked to stop. The tunnel task
    /// emits STOPPING and STOPPED once its teardown has really finished, so
    /// they are not emitted here — and awaiting the task here would deadlock
    /// against the object-server lock the task itself needs (see
    /// `TunnelHandle::disconnect`).
    async fn disconnect(
        &mut self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        info!("Disconnect called");
        match self.tunnel.take() {
            Some(handle) => handle.disconnect(),
            None => {
                // No tunnel running, so there is no task left to report for us.
                Self::state_changed(&emitter, nm_vpn_state::STOPPING)
                    .await
                    .ok();
                Self::state_changed(&emitter, nm_vpn_state::STOPPED)
                    .await
                    .ok();
            }
        }
        self.vpn_state = nm_vpn_state::STOPPED;
        Ok(())
    }

    /// Set a config value (no-op for us).
    async fn set_config(
        &self,
        _config: HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        Ok(())
    }

    /// Set IP4 config (no-op for us).
    async fn set_ip4_config(
        &self,
        _config: HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        Ok(())
    }

    /// Set failure (no-op for us).
    async fn set_failure(&self, _reason: String) -> zbus::fdo::Result<()> {
        Ok(())
    }

    // -- Properties --
    #[zbus(property(emits_changed_signal = "false"), name = "State")]
    async fn state(&self) -> u32 {
        self.vpn_state
    }

    // -- Signals --
    #[zbus(signal)]
    pub async fn state_changed(emitter: &SignalEmitter<'_>, state: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn config(
        emitter: &SignalEmitter<'_>,
        config: HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn ip4_config(
        emitter: &SignalEmitter<'_>,
        config: HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn failure(emitter: &SignalEmitter<'_>, reason: u32) -> zbus::Result<()>;
}

impl VpnPlugin {
    async fn do_connect(
        &mut self,
        settings: Settings,
        emitter: &SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        // Parse settings
        let mut profile = match crate::tunnel::parse_settings(&settings) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to parse settings: {e:#}");
                Self::failure(emitter, nm_vpn_failure::CONNECT_FAILED)
                    .await
                    .ok();
                return Err(zbus::fdo::Error::Failed(format!("Invalid settings: {e:#}")));
            }
        };

        // NM may hand the password over separately via NewSecrets, in which case
        // it is absent from `settings`. Merge it in before authenticating.
        if profile.password.is_empty() {
            if let Some(password) = self.extra_secrets.get("password") {
                info!("Using password supplied via NewSecrets");
                profile.password = password.clone();
            }
        }

        if profile.password.is_empty() {
            error!("No password available — refusing to start a tunnel that cannot authenticate");
            Self::failure(emitter, nm_vpn_failure::LOGIN_FAILED)
                .await
                .ok();
            return Err(zbus::fdo::Error::Failed(
                "No VPN password available".to_string(),
            ));
        }

        // Signal starting
        Self::state_changed(emitter, nm_vpn_state::STARTING)
            .await
            .ok();
        self.vpn_state = nm_vpn_state::STARTING;

        // Spawn tunnel task
        let conn = self.connection.clone();
        let handle = crate::tunnel::spawn_tunnel(profile, conn).await;
        self.tunnel = Some(handle);

        Ok(())
    }
}

/// Run the NM VPN plugin on the system bus.
pub async fn run() -> Result<()> {
    let connection = connection::Builder::system()?
        .name("org.freedesktop.NetworkManager.draytek")?
        .build()
        .await?;

    info!("Acquired D-Bus name: org.freedesktop.NetworkManager.draytek");

    let plugin = VpnPlugin::new(connection.clone());

    connection
        .object_server()
        .at("/org/freedesktop/NetworkManager/VPN/Plugin", plugin)
        .await?;

    info!("Plugin object registered at /org/freedesktop/NetworkManager/VPN/Plugin");

    // Run forever — NM will kill us when done
    std::future::pending::<()>().await;

    Ok(())
}
