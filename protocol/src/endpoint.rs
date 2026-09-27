//! Keep the VPN endpoint reachable from outside the tunnel.
//!
//! When a connection asks to become the default route, the kernel sends *all*
//! traffic through the tunnel — including the packets of the SSTP connection
//! that carries the tunnel. The server then receives its own control traffic
//! from inside the tunnel and cannot return it, the TCP connection breaks, and
//! the tunnel dies while the default route still points at it. The result is a
//! machine with no working network at all and no way to recover but manual
//! intervention.
//!
//! The fix is the same one OpenVPN and openconnect use: pin the VPN server's
//! own address to the route that reached it *before* the tunnel existed, so the
//! control path always stays on the physical link.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// How the VPN server was reached before the tunnel existed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRoute {
    /// Address of the VPN server.
    pub server: Ipv4Addr,
    /// Next hop towards it, if the route was not directly connected.
    pub gateway: Option<Ipv4Addr>,
    /// Interface that route used.
    pub device: String,
}

impl EndpointRoute {
    /// The address to pin, in CIDR notation.
    pub fn pinned_cidr(&self) -> String {
        format!("{}/32", self.server)
    }
}

/// Resolve a hostname to the IPv4 address of the VPN server.
///
/// Only a single address is returned: a multi-A-record endpoint is not
/// something a single host route can usefully pin.
pub fn resolve_server(host: &str) -> Option<Ipv4Addr> {
    use std::net::ToSocketAddrs;
    (host, 0u16)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| match addr.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        })
}

/// Capture the route currently used to reach `server`.
pub fn probe(server: Ipv4Addr) -> Result<EndpointRoute> {
    let output = Command::new("ip")
        .args(["route", "get", &server.to_string()])
        .output()
        .context("Failed to run 'ip route get'")?;
    if !output.status.success() {
        bail!(
            "ip route get {} failed: {}",
            server,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_route_get(server, &text)
}

/// Parse the output of `ip route get`.
///
/// Accepts both a routed and a directly connected result:
/// `1.2.3.4 via 192.168.0.1 dev wlo1 src 192.168.0.113 uid 1000`
/// `192.168.1.1 dev draytek0 src 192.168.1.105 uid 0`
fn parse_route_get(server: Ipv4Addr, text: &str) -> Result<EndpointRoute> {
    let mut tokens = text.split_whitespace();

    let mut gateway = None;
    let mut device = None;
    while let Some(token) = tokens.next() {
        match token {
            "via" => {
                let value = tokens.next().context("'via' without an address")?;
                gateway = Some(
                    value
                        .parse::<Ipv4Addr>()
                        .with_context(|| format!("bad gateway in route: {value}"))?,
                );
            }
            "dev" => {
                device = Some(tokens.next().context("'dev' without a name")?.to_string());
            }
            _ => {}
        }
    }

    let device = device.context("route to the VPN server has no interface")?;
    if gateway.is_none() && device == "lo" {
        bail!("VPN server resolves to a local address; nothing to pin");
    }

    Ok(EndpointRoute {
        server,
        gateway,
        device,
    })
}

/// Install a host route that keeps `route.server` reachable over the original
/// interface, bypassing the tunnel.
///
/// Uses `replace` so a leftover pin from a previous run is overwritten rather
/// than causing a "File exists" failure.
pub fn pin(route: &EndpointRoute) -> Result<()> {
    let cidr = route.pinned_cidr();
    let mut args: Vec<String> = vec!["route".into(), "replace".into(), cidr.clone()];
    if let Some(gateway) = route.gateway {
        args.push("via".into());
        args.push(gateway.to_string());
    }
    args.push("dev".into());
    args.push(route.device.clone());

    let output = Command::new("ip")
        .args(&args)
        .output()
        .context("Failed to run 'ip route replace'")?;
    if !output.status.success() {
        bail!(
            "ip route replace {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Remove a pin installed by [`pin`]. Best-effort.
pub fn unpin(route: &EndpointRoute) {
    let _ = Command::new("ip")
        .args(["route", "del", &route.pinned_cidr()])
        .output();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> Ipv4Addr {
        Ipv4Addr::new(117, 2, 126, 196)
    }

    #[test]
    fn parse_routed_route() {
        let text =
            "117.2.126.196 via 192.168.0.1 dev wlo1 src 192.168.0.113 uid 1000 \n    cache\n";
        let parsed = parse_route_get(server(), text).unwrap();
        assert_eq!(
            parsed,
            EndpointRoute {
                server: server(),
                gateway: Some(Ipv4Addr::new(192, 168, 0, 1)),
                device: "wlo1".to_string(),
            }
        );
    }

    #[test]
    fn parse_directly_connected_route() {
        let text = "192.168.1.1 dev draytek0 src 192.168.1.105 uid 0 \n    cache\n";
        let parsed = parse_route_get(Ipv4Addr::new(192, 168, 1, 1), text).unwrap();
        assert_eq!(parsed.gateway, None);
        assert_eq!(parsed.device, "draytek0");
    }

    #[test]
    fn parse_rejects_route_without_device() {
        let text = "117.2.126.196 via 192.168.0.1 uid 1000\n";
        assert!(parse_route_get(server(), text).is_err());
    }

    #[test]
    fn parse_rejects_loopback() {
        let text = "127.0.0.1 dev lo src 127.0.0.1 uid 1000\n";
        assert!(parse_route_get(Ipv4Addr::new(127, 0, 0, 1), text).is_err());
    }

    #[test]
    fn pinned_cidr_is_host_route() {
        let route = EndpointRoute {
            server: server(),
            gateway: Some(Ipv4Addr::new(192, 168, 0, 1)),
            device: "wlo1".to_string(),
        };
        assert_eq!(route.pinned_cidr(), "117.2.126.196/32");
    }
}
