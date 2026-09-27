/// Privileged helper binary for DrayTek VPN network operations.
///
/// Invoked via pkexec to create/destroy TUN devices, configure routing, and manage DNS.
/// Designed to be minimal (std-only, no external deps) for security.
use std::net::Ipv4Addr;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: draytek-vpn-helper <setup|teardown|check|pin-endpoint> [options]");
        return ExitCode::from(1);
    }

    let result = match args[1].as_str() {
        "setup" => cmd_setup(&args[2..]),
        "teardown" => cmd_teardown(&args[2..]),
        "check" => cmd_check(),
        "pin-endpoint" => cmd_pin_endpoint(&args[2..]),
        other => {
            eprintln!("Unknown subcommand: {other}");
            Err("Unknown subcommand".into())
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(1)
        }
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────────

struct SetupArgs {
    device: String,
    uid: u32,
    local_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    mtu: u16,
    routes: Vec<String>,
    default_gw: Option<Ipv4Addr>,
    dns: Option<Ipv4Addr>,
    /// Host route that keeps the VPN server reachable outside the tunnel.
    /// Installed before the default route, never after — see `cmd_setup`.
    pin: Option<PinArgs>,
}

struct PinArgs {
    /// Address of the VPN server to pin.
    ip: Ipv4Addr,
    /// Next hop towards it, when the route is not directly connected.
    gateway: Option<Ipv4Addr>,
    /// Interface that reached it before the tunnel existed.
    device: String,
}

struct TeardownArgs {
    device: String,
    restore_dns: bool,
}

fn parse_setup_args(args: &[String]) -> Result<SetupArgs, Box<dyn std::error::Error>> {
    let mut device = None;
    let mut uid = None;
    let mut local_ip = None;
    let mut peer_ip = None;
    let mut mtu = None;
    let mut routes = Vec::new();
    let mut default_gw = None;
    let mut dns = None;
    let mut pin_ip = None;
    let mut pin_gateway = None;
    let mut pin_device = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--device" => {
                i += 1;
                device = Some(args.get(i).ok_or("--device requires a value")?.clone());
            }
            "--uid" => {
                i += 1;
                uid = Some(
                    args.get(i)
                        .ok_or("--uid requires a value")?
                        .parse::<u32>()?,
                );
            }
            "--local-ip" => {
                i += 1;
                local_ip = Some(
                    args.get(i)
                        .ok_or("--local-ip requires a value")?
                        .parse::<Ipv4Addr>()?,
                );
            }
            "--peer-ip" => {
                i += 1;
                peer_ip = Some(
                    args.get(i)
                        .ok_or("--peer-ip requires a value")?
                        .parse::<Ipv4Addr>()?,
                );
            }
            "--mtu" => {
                i += 1;
                mtu = Some(
                    args.get(i)
                        .ok_or("--mtu requires a value")?
                        .parse::<u16>()?,
                );
            }
            "--route" => {
                i += 1;
                routes.push(args.get(i).ok_or("--route requires a value")?.clone());
            }
            "--default-gw" => {
                i += 1;
                default_gw = Some(
                    args.get(i)
                        .ok_or("--default-gw requires a value")?
                        .parse::<Ipv4Addr>()?,
                );
            }
            "--dns" => {
                i += 1;
                dns = Some(
                    args.get(i)
                        .ok_or("--dns requires a value")?
                        .parse::<Ipv4Addr>()?,
                );
            }
            "--pin-ip" => {
                i += 1;
                pin_ip = Some(
                    args.get(i)
                        .ok_or("--pin-ip requires a value")?
                        .parse::<Ipv4Addr>()?,
                );
            }
            "--pin-gateway" => {
                i += 1;
                pin_gateway = Some(
                    args.get(i)
                        .ok_or("--pin-gateway requires a value")?
                        .parse::<Ipv4Addr>()?,
                );
            }
            "--pin-device" => {
                i += 1;
                pin_device = Some(args.get(i).ok_or("--pin-device requires a value")?.clone());
            }
            other => return Err(format!("Unknown option: {other}").into()),
        }
        i += 1;
    }

    // The pin is all-or-nothing: half a pin silently fails to install and the
    // tunnel then routes the SSTP connection into itself.
    let pin = match (pin_ip, pin_device) {
        (Some(ip), Some(device)) => Some(PinArgs {
            ip,
            gateway: pin_gateway,
            device,
        }),
        (None, None) => None,
        _ => {
            return Err("--pin-ip and --pin-device must be supplied together"
                .to_string()
                .into())
        }
    };

    Ok(SetupArgs {
        device: device.ok_or("--device is required")?,
        uid: uid.ok_or("--uid is required")?,
        local_ip: local_ip.ok_or("--local-ip is required")?,
        peer_ip: peer_ip.ok_or("--peer-ip is required")?,
        mtu: mtu.ok_or("--mtu is required")?,
        routes,
        default_gw,
        dns,
        pin,
    })
}

fn parse_teardown_args(args: &[String]) -> Result<TeardownArgs, Box<dyn std::error::Error>> {
    let mut device = None;
    let mut restore_dns = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--device" => {
                i += 1;
                device = Some(args.get(i).ok_or("--device requires a value")?.clone());
            }
            "--restore-dns" => {
                restore_dns = true;
            }
            other => return Err(format!("Unknown option: {other}").into()),
        }
        i += 1;
    }

    Ok(TeardownArgs {
        device: device.ok_or("--device is required")?,
        restore_dns,
    })
}

// ── Validation ────────────────────────────────────────────────────────────────

fn validate_device_name(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if name.is_empty() || name.len() > 15 {
        return Err(format!("Device name must be 1-15 characters, got '{name}'").into());
    }
    if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return Err(format!("Device name must start with a letter: '{name}'").into());
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(format!("Device name must be alphanumeric: '{name}'").into());
    }
    Ok(())
}

/// Validate a physical interface name coming from the kernel.
///
/// Wider than [`validate_device_name`] because that one only ever sees our own
/// short TUN name, while this sees names the kernel handed us. The device
/// reaches `ip` as a separate argv element, so the check keeps shell
/// metacharacters and whitespace out of it.
fn validate_iface_name(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if name.is_empty() || name.len() > 15 {
        return Err(format!("Interface name must be 1-15 characters, got '{name}'").into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(format!("Invalid interface name: {name}").into());
    }
    Ok(())
}

fn validate_mtu(mtu: u16) -> Result<(), Box<dyn std::error::Error>> {
    if !(576..=9000).contains(&mtu) {
        return Err(format!("MTU must be 576-9000, got {mtu}").into());
    }
    Ok(())
}

fn validate_cidr(cidr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR format: {cidr}").into());
    }
    parts[0]
        .parse::<Ipv4Addr>()
        .map_err(|e| format!("Invalid IP in CIDR '{cidr}': {e}"))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|e| format!("Invalid prefix in CIDR '{cidr}': {e}"))?;
    if prefix > 32 {
        return Err(format!("Prefix length must be 0-32, got {prefix}").into());
    }
    Ok(())
}

// ── Command execution ─────────────────────────────────────────────────────────

fn run_cmd(program: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("+ {program} {}", args.join(" "));
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{program} {} failed (exit {}): {}",
            args.join(" "),
            output.status,
            stderr.trim()
        )
        .into());
    }
    Ok(())
}

// ── DNS helpers ──────────────────────────────────────────────────────────

/// Try to configure DNS via resolvectl (systemd-resolved).
/// Returns true on success, false if resolvectl is unavailable or fails.
fn try_resolvectl_dns_setup(device: &str, dns_ip: Ipv4Addr) -> bool {
    let dns_str = dns_ip.to_string();
    if run_cmd("resolvectl", &["dns", device, &dns_str]).is_err() {
        return false;
    }
    if run_cmd("resolvectl", &["domain", device, "~."]).is_err() {
        return false;
    }
    true
}

/// Where the direct-write DNS fallback stashes the original resolv.conf.
const RESOLV_BACKUP_PATH: &str = "/run/draytek-vpn-resolv.bak";

/// Configure DNS by writing directly to /etc/resolv.conf (requires root).
fn direct_dns_setup(dns_ip: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
    let resolv_path = "/etc/resolv.conf";
    let backup_path = RESOLV_BACKUP_PATH;

    // Backup current resolv.conf
    if let Ok(current) = std::fs::read_to_string(resolv_path) {
        std::fs::write(backup_path, &current)
            .map_err(|e| format!("Failed to backup resolv.conf to {backup_path}: {e}"))?;
    }

    // Prepend our nameserver
    let existing = std::fs::read_to_string(resolv_path).unwrap_or_default();
    let new_content = format!("nameserver {dns_ip}\n{existing}");
    std::fs::write(resolv_path, new_content)
        .map_err(|e| format!("Failed to write {resolv_path}: {e}"))?;
    Ok(())
}

// ── Subcommands ───────────────────────────────────────────────────────────────

/// Pin the VPN server's own address to the physical link.
///
/// Once this connection becomes the default route, every packet goes into the
/// tunnel — including the SSTP connection that carries the tunnel. The server
/// then receives its own control traffic from the inside and cannot return it,
/// the TCP connection breaks, and the tunnel dies while the default route still
/// points at it. A host route for the endpoint keeps the control path outside.
fn cmd_pin_endpoint(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut server = None;
    let mut gateway = None;
    let mut device = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ip" => {
                i += 1;
                server = Some(
                    args.get(i)
                        .ok_or("--ip requires a value")?
                        .parse::<Ipv4Addr>()?,
                );
            }
            "--gateway" => {
                i += 1;
                gateway = Some(
                    args.get(i)
                        .ok_or("--gateway requires a value")?
                        .parse::<Ipv4Addr>()?,
                );
            }
            "--device" => {
                i += 1;
                device = Some(args.get(i).ok_or("--device requires a value")?.clone());
            }
            other => return Err(format!("Unknown option: {other}").into()),
        }
        i += 1;
    }

    let server = server.ok_or("--ip is required")?;
    let device = device.ok_or("--device is required")?;
    validate_iface_name(&device)?;

    install_pin(&PinArgs {
        ip: server,
        gateway,
        device,
    })
}

/// Where the current pin is recorded, so teardown can undo it without being told
/// what to undo.
///
/// The pin outlives any single process: it is a host route in the kernel, and
/// nothing removes it when the app is killed. Recording it here means the single
/// teardown path owns both the device and the pin, so no caller has to remember
/// to clean up after itself, and a session that died mid-setup still gets its
/// pin removed by the next run.
const PIN_STATE_PATH: &str = "/run/draytek-vpn-pin";

/// Install the host route that keeps the VPN server outside the tunnel.
fn install_pin(pin: &PinArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cidr = format!("{}/32", pin.ip);
    let mut owned: Vec<String> = vec!["route".into(), "replace".into(), cidr.clone()];
    if let Some(gw) = pin.gateway {
        owned.push("via".into());
        owned.push(gw.to_string());
    }
    owned.push("dev".into());
    owned.push(pin.device.clone());
    let borrowed: Vec<&str> = owned.iter().map(String::as_str).collect();

    run_cmd("ip", &borrowed)?;
    // Record only once the route is actually in place, so the state file never
    // advertises a pin that does not exist.
    if let Err(e) = std::fs::write(PIN_STATE_PATH, &cidr) {
        eprintln!("Warning: failed to record pin state in {PIN_STATE_PATH}: {e}");
    }
    eprintln!("Pinned VPN endpoint {cidr} on {}", pin.device);
    Ok(())
}

/// Remove the pin recorded in [`PIN_STATE_PATH`], if any. Best-effort.
fn remove_recorded_pin() {
    let Ok(cidr) = std::fs::read_to_string(PIN_STATE_PATH) else {
        return;
    };
    let cidr = cidr.trim();
    if cidr.is_empty() {
        let _ = std::fs::remove_file(PIN_STATE_PATH);
        return;
    }
    if let Err(e) = run_cmd("ip", &["route", "del", cidr]) {
        eprintln!("Warning: failed to remove endpoint pin {cidr}: {e}");
    } else {
        eprintln!("+ Removed VPN endpoint pin {cidr}");
    }
    let _ = std::fs::remove_file(PIN_STATE_PATH);
}

fn cmd_setup(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let setup = parse_setup_args(args)?;

    // Validate all inputs before executing anything
    validate_device_name(&setup.device)?;
    validate_mtu(setup.mtu)?;
    for route in &setup.routes {
        validate_cidr(route)?;
    }
    if let Some(pin) = &setup.pin {
        validate_iface_name(&pin.device)?;
    }

    let uid_str = setup.uid.to_string();
    let local_ip_str = setup.local_ip.to_string();
    let peer_ip_str = setup.peer_ip.to_string();
    let mtu_str = setup.mtu.to_string();

    // 1. Create TUN device owned by user (remove stale device from prior session if present)
    if std::path::Path::new(&format!("/sys/class/net/{}", setup.device)).exists() {
        eprintln!("Note: removing stale {} device", setup.device);
        let _ = run_cmd(
            "ip",
            &["tuntap", "del", "dev", &setup.device, "mode", "tun"],
        );
    }
    run_cmd(
        "ip",
        &[
            "tuntap",
            "add",
            "dev",
            &setup.device,
            "mode",
            "tun",
            "user",
            &uid_str,
        ],
    )?;

    // 2. Configure IP address
    run_cmd(
        "ip",
        &[
            "addr",
            "add",
            &local_ip_str,
            "peer",
            &peer_ip_str,
            "dev",
            &setup.device,
        ],
    )?;

    // 3. Set MTU and bring up
    run_cmd("ip", &["link", "set", &setup.device, "mtu", &mtu_str, "up"])?;

    // 4. Pin the VPN server outside the tunnel — strictly before the default
    //    route goes in. Once every packet is routed into the tunnel, the SSTP
    //    connection carrying it is pulled in too, the server cannot return its
    //    own control traffic, and the tunnel tears itself down while the
    //    default route still points at it. Doing it here rather than from the
    //    caller keeps the ordering guaranteed even when privilege elevation
    //    needs a prompt.
    if let Some(pin) = &setup.pin {
        install_pin(pin)?;
    }

    // 5. Add routes. `replace`, not `add`: a route left behind by a session
    //    that died without tearing down would make `add` fail with "File
    //    exists" and abort the whole setup.
    for route in &setup.routes {
        run_cmd("ip", &["route", "replace", route, "dev", &setup.device])?;
    }

    // 6. Default gateway
    if let Some(gw) = setup.default_gw {
        let gw_str = gw.to_string();
        run_cmd(
            "ip",
            &[
                "route",
                "replace",
                "default",
                "via",
                &gw_str,
                "dev",
                &setup.device,
            ],
        )?;
    }

    // 7. DNS configuration
    if let Some(dns_ip) = setup.dns {
        if try_resolvectl_dns_setup(&setup.device, dns_ip) {
            eprintln!("DNS configured via resolvectl for {}", setup.device);
            // A backup from a session that crashed can only be a record of a
            // resolv.conf we are no longer using. Leaving it for teardown to
            // restore would overwrite the current file with a stale copy.
            let _ = std::fs::remove_file(RESOLV_BACKUP_PATH);
        } else {
            eprintln!("resolvectl not available or failed, falling back to /etc/resolv.conf");
            match direct_dns_setup(dns_ip) {
                Ok(()) => eprintln!("DNS configured via /etc/resolv.conf: {dns_ip}"),
                Err(e) => {
                    eprintln!("Warning: DNS configuration failed: {e} — continuing without DNS")
                }
            }
        }
    }

    eprintln!("Setup complete for {}", setup.device);
    Ok(())
}

fn cmd_check() -> Result<(), Box<dyn std::error::Error>> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("Failed to read /proc/self/status: {e}"))?;

    let cap_eff = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .ok_or("CapEff line not found in /proc/self/status")?;

    let hex_str = cap_eff
        .split_whitespace()
        .nth(1)
        .ok_or("Failed to parse CapEff value")?;

    let caps = u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
        .map_err(|e| format!("Failed to parse CapEff hex '{hex_str}': {e}"))?;

    const CAP_NET_ADMIN: u64 = 1 << 12;
    if caps & CAP_NET_ADMIN != 0 {
        eprintln!("capability check: CAP_NET_ADMIN is present in effective set (CapEff={hex_str})");
        Ok(())
    } else {
        eprintln!(
            "capability check: CAP_NET_ADMIN is NOT present in effective set (CapEff={hex_str})"
        );
        Err("CAP_NET_ADMIN not present".into())
    }
}

fn cmd_teardown(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let teardown = parse_teardown_args(args)?;

    validate_device_name(&teardown.device)?;

    // 1. Flush routes (best-effort)
    if let Err(e) = run_cmd("ip", &["route", "flush", "dev", &teardown.device]) {
        eprintln!("Warning: failed to flush routes: {e}");
    }

    // 2. Bring down interface (best-effort)
    if let Err(e) = run_cmd("ip", &["link", "set", &teardown.device, "down"]) {
        eprintln!("Warning: failed to bring down {}: {e}", teardown.device);
    }

    // 3. Delete TUN device
    if let Err(e) = run_cmd(
        "ip",
        &["tuntap", "del", "dev", &teardown.device, "mode", "tun"],
    ) {
        eprintln!("Warning: failed to delete {}: {e}", teardown.device);
    }

    // 4. Remove the endpoint pin (see PIN_STATE_PATH). Done unconditionally:
    //    the route is not tied to the device, so deleting the device above does
    //    not take it with it, and a pin left behind keeps sending the VPN
    //    server's traffic down a gateway from whatever network is current.
    remove_recorded_pin();

    // 5. Restore DNS (try both methods — safe no-ops if nothing to do)
    if teardown.restore_dns {
        // Try resolvectl revert (no-op if resolvectl wasn't used or device is gone)
        match Command::new("resolvectl")
            .args(["revert", &teardown.device])
            .output()
        {
            Ok(output) if output.status.success() => {
                eprintln!("+ Reverted DNS via resolvectl for {}", teardown.device);
            }
            _ => {
                // resolvectl not available or device already gone — that's fine
            }
        }

        // Restore /etc/resolv.conf backup if it exists (covers direct-write case)
        let backup_path = RESOLV_BACKUP_PATH;
        let resolv_path = "/etc/resolv.conf";
        if std::path::Path::new(backup_path).exists() {
            match std::fs::read_to_string(backup_path) {
                Ok(original) => {
                    if let Err(e) = std::fs::write(resolv_path, original) {
                        eprintln!("Warning: failed to restore {resolv_path}: {e}");
                    } else {
                        eprintln!("+ Restored {resolv_path} from backup");
                        let _ = std::fs::remove_file(backup_path);
                    }
                }
                Err(e) => {
                    eprintln!("Warning: failed to read DNS backup {backup_path}: {e}");
                }
            }
        }
    }

    eprintln!("Teardown complete for {}", teardown.device);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// A setup that pins the endpoint is only safe if the pin really is
    /// requested: an accidental `None` here is a tunnel that swallows its own
    /// control connection, and it fails silently.
    #[test]
    fn pin_is_parsed_together() {
        let parsed = parse_setup_args(&args(&[
            "--device",
            "draytek0",
            "--uid",
            "1000",
            "--local-ip",
            "192.168.1.104",
            "--peer-ip",
            "192.168.1.1",
            "--mtu",
            "1280",
            "--pin-ip",
            "117.2.126.196",
            "--pin-device",
            "wlo1",
            "--pin-gateway",
            "192.168.1.1",
        ]))
        .expect("setup args should parse");

        let pin = parsed.pin.expect("pin should be present");
        assert_eq!(pin.ip, Ipv4Addr::new(117, 2, 126, 196));
        assert_eq!(pin.device, "wlo1");
        assert_eq!(pin.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn pin_is_absent_when_not_requested() {
        let parsed = parse_setup_args(&args(&[
            "--device",
            "draytek0",
            "--uid",
            "1000",
            "--local-ip",
            "192.168.1.104",
            "--peer-ip",
            "192.168.1.1",
            "--mtu",
            "1280",
        ]))
        .expect("setup args should parse");
        assert!(parsed.pin.is_none());
    }

    /// Half a pin installs nothing and fails silently, which is the failure this
    /// rejects: the tunnel would then route the SSTP connection into itself.
    #[test]
    fn half_a_pin_is_rejected() {
        let device_only = parse_setup_args(&args(&[
            "--device",
            "draytek0",
            "--uid",
            "1000",
            "--local-ip",
            "192.168.1.104",
            "--peer-ip",
            "192.168.1.1",
            "--mtu",
            "1280",
            "--pin-device",
            "wlo1",
        ]))
        .err()
        .map(|e| e.to_string())
        .expect("pin without an address should be rejected");
        assert!(device_only.contains("--pin-ip"), "{device_only}");

        let address_only = parse_setup_args(&args(&[
            "--device",
            "draytek0",
            "--uid",
            "1000",
            "--local-ip",
            "192.168.1.104",
            "--peer-ip",
            "192.168.1.1",
            "--mtu",
            "1280",
            "--pin-ip",
            "117.2.126.196",
        ]))
        .err()
        .map(|e| e.to_string())
        .expect("pin without a device should be rejected");
        assert!(address_only.contains("--pin-device"), "{address_only}");
    }

    #[test]
    fn physical_interface_names_are_accepted() {
        // The TUN name is short and alphanumeric; real interface names are not,
        // and rejecting them would make the pin impossible to install.
        for name in [
            "wlo1", "eth0", "enp3s0", "wlp3s0", "br-lan", "veth0_1", "en0.100",
        ] {
            validate_iface_name(name).unwrap_or_else(|e| panic!("{name} should be valid: {e}"));
        }
        for name in ["", "wlo1;reboot", "eth 0", "a/b", "$(id)"] {
            assert!(
                validate_iface_name(name).is_err(),
                "{name} should be rejected"
            );
        }
    }

    #[test]
    fn tun_device_name_stays_restricted() {
        validate_device_name("draytek0").expect("the TUN name is valid");
        // Anything wider belongs to validate_iface_name, not here: this guards
        // the name we hand to `ip tuntap add`.
        assert!(validate_device_name("br-lan").is_err());
        assert!(validate_device_name("0tun").is_err());
    }

    #[test]
    fn default_gateway_and_routes_survive_parsing() {
        let parsed = parse_setup_args(&args(&[
            "--device",
            "draytek0",
            "--uid",
            "1000",
            "--local-ip",
            "192.168.1.104",
            "--peer-ip",
            "192.168.1.1",
            "--mtu",
            "1280",
            "--default-gw",
            "192.168.1.1",
            "--dns",
            "116.97.90.124",
            "--route",
            "192.168.1.0/24",
            "--route",
            "115.73.220.127/32",
        ]))
        .expect("setup args should parse");

        assert_eq!(parsed.default_gw, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(parsed.dns, Some(Ipv4Addr::new(116, 97, 90, 124)));
        assert_eq!(parsed.routes, vec!["192.168.1.0/24", "115.73.220.127/32"]);
    }
}
