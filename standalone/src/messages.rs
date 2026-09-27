/// Status the window renders, derived from what NetworkManager reports.
use draytek_vpn_nmapi::VpnState;

/// Re-exported so the rest of the app does not depend on `nmapi` directly.
pub use draytek_vpn_nmapi::{DraytekProfile, SavedVpn};

/// Everything the connection view needs to draw one frame.
///
/// A flat struct rather than the NM enum: the view asks "is it up, what is the
/// address, what is routed" once per update, and a match over a five-variant
/// enum in the render path would repeat that question at every label.
#[derive(Debug, Clone, Default)]
pub struct StatusView {
    pub phase: Phase,
    pub name: String,
    pub local_ip: String,
    pub server: String,
    /// Routes installed on the tunnel, excluding the default route, which
    /// `is_default_route` already reports.
    pub routes: Vec<String>,
    pub is_default_route: bool,
    /// Seconds since the connection was activated, or 0 if unknown.
    pub connected_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Failed,
}

/// Wall-clock seconds for a `connection.timestamp`, or 0 when it is absent or
/// in the future (which a clock change can make it).
pub fn elapsed_since(timestamp: u64) -> u64 {
    if timestamp == 0 {
        return 0;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp))
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl From<&VpnState> for StatusView {
    fn from(state: &VpnState) -> Self {
        match state {
            VpnState::Disconnected => Self::default(),
            VpnState::Connecting { name } => Self {
                phase: Phase::Connecting,
                name: name.clone(),
                ..Default::default()
            },
            VpnState::Connected {
                name,
                ip,
                server,
                connected_at,
                ..
            } => Self {
                phase: Phase::Connected,
                name: name.clone(),
                local_ip: ip.clone(),
                server: server.clone(),
                routes: state.display_routes(),
                is_default_route: state.has_default_route(),
                connected_secs: elapsed_since(*connected_at),
            },
            VpnState::Failed { name, .. } => Self {
                phase: Phase::Failed,
                name: name.clone(),
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use draytek_vpn_nmapi::VpnState;
    use zbus::zvariant::OwnedObjectPath;

    fn connected(routes: &[&str]) -> VpnState {
        VpnState::Connected {
            name: "Office".to_string(),
            ip: "192.168.1.104".to_string(),
            server: "117.2.126.196:4430".to_string(),
            routes: routes.iter().map(|r| r.to_string()).collect(),
            path: OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/ActiveConnection/1")
                .expect("static path is valid"),
            connected_at: 0,
            keepalive: true,
        }
    }

    /// The default route and the split routes answer different questions, and
    /// a full tunnel that also lists `0.0.0.0/0` among its "additional routes"
    /// reads as though something is wrong with it.
    #[test]
    fn default_route_is_reported_separately() {
        let state = connected(&["0.0.0.0/0", "192.168.1.0/24", "10.0.0.0/8"]);
        let view = StatusView::from(&state);

        assert_eq!(view.phase, Phase::Connected);
        assert!(view.is_default_route);
        assert_eq!(view.routes, vec!["192.168.1.0/24", "10.0.0.0/8"]);
    }

    #[test]
    fn split_tunnel_is_not_a_default_route() {
        let view = StatusView::from(&connected(&["192.168.1.0/24"]));
        assert!(!view.is_default_route);
        assert_eq!(view.routes, vec!["192.168.1.0/24"]);
    }

    /// A failure is its own phase. Folding it into "disconnected" would make a
    /// failed login look like a deliberate disconnect.
    #[test]
    fn failure_is_distinct_from_disconnected() {
        let view = StatusView::from(&VpnState::Failed {
            name: "Office".to_string(),
            reason: "Login failed".to_string(),
        });
        assert_eq!(view.phase, Phase::Failed);
        assert_ne!(view.phase, Phase::Disconnected);
        assert_eq!(view.name, "Office");
    }

    /// A `connection.timestamp` from before the epoch, or one a clock change
    /// pushed into the future, must not produce a huge uptime.
    #[test]
    fn impossible_timestamps_do_not_wrap() {
        assert_eq!(elapsed_since(0), 0);
        let future = u64::MAX / 2;
        assert_eq!(elapsed_since(future), 0);
    }

    #[test]
    fn disconnected_has_no_detail() {
        let view = StatusView::from(&VpnState::Disconnected);
        assert_eq!(view.phase, Phase::Disconnected);
        assert!(view.local_ip.is_empty());
        assert!(!view.is_default_route);
    }
}
