/// IPCP (IP Control Protocol) option initialization.
///
/// Sets up options for IP address and DNS negotiation.
use crate::constants::*;
use crate::protocol::fsm::PppFsm;
use crate::protocol::ppp_control::PppControlOption;
use std::net::Ipv4Addr;

/// Netmask proposed to the router when it does not supply one of its own.
pub const DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// Create an IPCP FSM with standard options.
///
/// Initially requests 0.0.0.0 for IP and DNS, letting the router assign values.
/// A /24 netmask is proposed so the router can override it with the real mask.
pub fn create_ipcp_fsm() -> PppFsm {
    let zero_ip = [0u8; 4];

    // Options we propose for our side (start with 0.0.0.0 = "please assign")
    let desired_local = vec![
        PppControlOption::new(PPP_IPCP_CONFIG_IP_ADDR, zero_ip.to_vec()),
        PppControlOption::new(PPP_IPCP_CONFIG_NETMASK, DEFAULT_NETMASK.octets().to_vec()),
        PppControlOption::new(PPP_IPCP_CONFIG_DNS_ADDR, zero_ip.to_vec()),
    ];

    // Options we accept from the router
    let acceptable_remote = vec![
        // Accept any IP address from router
        PppControlOption::new(PPP_IPCP_CONFIG_IP_ADDR, vec![]),
        // Accept any netmask from router
        PppControlOption::new(PPP_IPCP_CONFIG_NETMASK, vec![]),
        // Accept any DNS from router
        PppControlOption::new(PPP_IPCP_CONFIG_DNS_ADDR, vec![]),
    ];

    // Options we want the router to include in its request
    let desired_remote = vec![];

    PppFsm::new("IPCP", desired_local, acceptable_remote, desired_remote)
}

/// Get the assigned local IP address from negotiated IPCP options.
pub fn get_local_ip(fsm: &PppFsm) -> Option<Ipv4Addr> {
    let opt = fsm.get_local_option(PPP_IPCP_CONFIG_IP_ADDR)?;
    parse_ip(&opt.data)
}

/// Get the assigned DNS server address from negotiated IPCP options.
pub fn get_local_dns(fsm: &PppFsm) -> Option<Ipv4Addr> {
    let opt = fsm.get_local_option(PPP_IPCP_CONFIG_DNS_ADDR)?;
    parse_ip(&opt.data)
}

/// Get the remote peer's IP address from negotiated IPCP options.
pub fn get_remote_ip(fsm: &PppFsm) -> Option<Ipv4Addr> {
    let opt = fsm.get_remote_option(PPP_IPCP_CONFIG_IP_ADDR)?;
    parse_ip(&opt.data)
}

/// Get the negotiated netmask, falling back to /24 if the router sent none.
pub fn get_local_netmask(fsm: &PppFsm) -> Ipv4Addr {
    get_local_option_ip(fsm, PPP_IPCP_CONFIG_NETMASK).unwrap_or(DEFAULT_NETMASK)
}

fn get_local_option_ip(fsm: &PppFsm, option_type: u8) -> Option<Ipv4Addr> {
    let opt = fsm.get_local_option(option_type)?;
    parse_ip(&opt.data)
}

/// Convert a netmask to a CIDR prefix length.
///
/// Returns `None` for a non-contiguous mask (e.g. 255.0.255.0), which cannot be
/// expressed as a prefix length.
pub fn netmask_to_prefix(netmask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(netmask);
    // A valid mask is a run of ones followed by zeros, so the inverted value
    // has exactly one set bit cleared by adding one.
    let inverted = !bits;
    if inverted & inverted.wrapping_add(1) != 0 {
        return None;
    }
    Some(bits.count_ones() as u8)
}

/// Build the CIDR notation of the tunnel's network from our address and the
/// negotiated netmask, e.g. `192.168.1.105` + `255.255.255.0` -> `192.168.1.0/24`.
///
/// Returns `None` if the netmask is not a valid contiguous mask.
pub fn network_cidr(ip: Ipv4Addr, netmask: Ipv4Addr) -> Option<String> {
    let prefix = netmask_to_prefix(netmask)?;
    let network = Ipv4Addr::from(u32::from(ip) & u32::from(netmask));
    Some(format!("{network}/{prefix}"))
}

fn parse_ip(data: &[u8]) -> Option<Ipv4Addr> {
    if data.len() >= 4 {
        Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::fsm::{FsmEvent, FsmState};

    #[test]
    fn test_create_ipcp_fsm() {
        let fsm = create_ipcp_fsm();
        assert_eq!(fsm.state, FsmState::Initial);
        assert_eq!(fsm.tag, "IPCP");
        assert_eq!(fsm.desired_local_options.len(), 3);
        let netmask = fsm
            .desired_local_options
            .iter()
            .find(|o| o.option_type == PPP_IPCP_CONFIG_NETMASK)
            .unwrap();
        assert_eq!(netmask.data, vec![255, 255, 255, 0]);
    }

    #[test]
    fn test_netmask_to_prefix() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(
            netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)),
            Some(32)
        );
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), Some(16));
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), Some(8));
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), Some(0));
        // Non-contiguous masks have no prefix-length form
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 255, 0)), None);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 255)), None);
    }

    #[test]
    fn test_network_cidr() {
        assert_eq!(
            network_cidr(
                Ipv4Addr::new(192, 168, 1, 105),
                Ipv4Addr::new(255, 255, 255, 0)
            ),
            Some("192.168.1.0/24".to_string())
        );
        assert_eq!(
            network_cidr(Ipv4Addr::new(10, 5, 3, 7), Ipv4Addr::new(255, 255, 0, 0)),
            Some("10.5.0.0/16".to_string())
        );
        // Host bits must be masked off
        assert_eq!(
            network_cidr(
                Ipv4Addr::new(172, 16, 33, 9),
                Ipv4Addr::new(255, 255, 255, 252)
            ),
            Some("172.16.33.8/30".to_string())
        );
        assert_eq!(
            network_cidr(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(255, 0, 255, 0)),
            None
        );
    }

    #[test]
    fn test_get_local_netmask_defaults_to_slash_24() {
        let fsm = create_ipcp_fsm();
        // Nothing negotiated yet — fall back to the proposed default
        assert_eq!(get_local_netmask(&fsm), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn test_ipcp_nak_assigns_ip() {
        let mut fsm = create_ipcp_fsm();
        fsm.handle_event(FsmEvent::Up);
        let actions = fsm.handle_event(FsmEvent::Open);
        let our_id = match &actions[0] {
            crate::protocol::fsm::FsmAction::SendFrame(f) => f.identifier,
            _ => panic!(),
        };

        // Router NAKs with assigned IP and DNS
        use crate::protocol::ppp_control::PppControlFrame;
        let nak = PppControlFrame::config_nak(
            our_id,
            &[
                PppControlOption::new(PPP_IPCP_CONFIG_IP_ADDR, vec![10, 0, 0, 100]),
                PppControlOption::new(PPP_IPCP_CONFIG_DNS_ADDR, vec![8, 8, 8, 8]),
            ],
        );
        let actions = fsm.handle_event(FsmEvent::ReceiveFrame(nak));
        // Should re-send with updated IP/DNS
        match &actions[0] {
            crate::protocol::fsm::FsmAction::SendFrame(f) => {
                let opts = f.parse_options().unwrap();
                let ip_opt = opts
                    .iter()
                    .find(|o| o.option_type == PPP_IPCP_CONFIG_IP_ADDR)
                    .unwrap();
                assert_eq!(ip_opt.data, vec![10, 0, 0, 100]);
                let dns_opt = opts
                    .iter()
                    .find(|o| o.option_type == PPP_IPCP_CONFIG_DNS_ADDR)
                    .unwrap();
                assert_eq!(dns_opt.data, vec![8, 8, 8, 8]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_ip() {
        assert_eq!(parse_ip(&[10, 0, 0, 1]), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            parse_ip(&[192, 168, 1, 1]),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(parse_ip(&[0, 0, 0, 0]), Some(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(parse_ip(&[1, 2]), None);
    }
}
