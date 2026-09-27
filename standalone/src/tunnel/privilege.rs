/// Privilege separation — invokes draytek-vpn-helper for privileged network ops.
///
/// Three-tier privilege model:
/// - Tier 1: Helper has CAP_NET_ADMIN capability → runs directly (zero prompts)
/// - Tier 2: Polkit policy installed → pkexec with credential caching (one prompt)
/// - Tier 3: Default pkexec → prompt every time
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use tracing::{info, warn};

use draytek_vpn_protocol::endpoint;

/// TUN device name used for the VPN tunnel.
pub const TUN_DEVICE_NAME: &str = "draytek0";

/// Check whether the TUN device exists (stale or active).
pub fn is_device_present(device: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{device}")).exists()
}

/// Check whether a DNS backup from a previous session exists.
pub fn has_dns_backup() -> bool {
    std::path::Path::new("/run/draytek-vpn-resolv.bak").exists()
}

/// Find the helper binary path.
///
/// Resolution order:
/// 1. `$DRAYTEK_VPN_HELPER` env var
/// 2. Same directory as the running binary (development)
/// 3. `/usr/lib/draytek-vpn/draytek-vpn-helper` (installed)
fn find_helper() -> Result<String> {
    // 1. Explicit env var override
    if let Ok(path) = std::env::var("DRAYTEK_VPN_HELPER") {
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
        warn!("DRAYTEK_VPN_HELPER={path} does not exist, trying other locations");
    }

    // 2. Sibling of current executable (development: target/debug/draytek-vpn-helper)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("draytek-vpn-helper");
            if sibling.exists() {
                return Ok(sibling.to_string_lossy().to_string());
            }
        }
    }

    // 3. System install location
    let system_path = "/usr/lib/draytek-vpn/draytek-vpn-helper";
    if std::path::Path::new(system_path).exists() {
        return Ok(system_path.to_string());
    }

    anyhow::bail!(
        "Cannot find draytek-vpn-helper. Set DRAYTEK_VPN_HELPER env var, \
         build with `cargo build` (places it next to the main binary), \
         or install to /usr/lib/draytek-vpn/"
    )
}

/// Get the current user's UID.
fn current_uid() -> u32 {
    // SAFETY: getuid() is always safe to call
    unsafe { libc::getuid() }
}

/// Cached result of whether we need pkexec to run the helper.
static NEEDS_PKEXEC: OnceLock<bool> = OnceLock::new();

/// Check whether the helper needs pkexec (i.e., lacks CAP_NET_ADMIN).
///
/// Runs `helper check` (without pkexec) once per process lifetime.
/// Returns `true` if pkexec is needed (Tier 2/3), `false` if helper has
/// CAP_NET_ADMIN (Tier 1).
fn needs_pkexec() -> bool {
    *NEEDS_PKEXEC.get_or_init(|| {
        let helper = match find_helper() {
            Ok(h) => h,
            Err(e) => {
                warn!("Cannot find helper for capability check: {e:#} — assuming pkexec needed");
                return true;
            }
        };

        match std::process::Command::new(&helper).arg("check").output() {
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                for line in stderr.lines() {
                    if !line.is_empty() {
                        info!("{line}");
                    }
                }
                if output.status.success() {
                    info!("Helper has CAP_NET_ADMIN — running without pkexec");
                    false
                } else {
                    info!("Helper lacks CAP_NET_ADMIN — will use pkexec");
                    true
                }
            }
            Err(e) => {
                warn!("Failed to run helper check: {e} — assuming pkexec needed");
                true
            }
        }
    })
}

/// Pin the VPN server's own address to the physical link.
///
/// Must run before the tunnel's default route is installed. Once every packet
/// is routed into the tunnel, the SSTP connection carrying it is pulled in too
/// and the tunnel tears itself down. See `protocol::endpoint` for details.
pub async fn pin_endpoint(route: &endpoint::EndpointRoute) -> Result<()> {
    let helper = find_helper()?;
    let mut args = vec![
        helper,
        "pin-endpoint".to_string(),
        "--ip".to_string(),
        route.server.to_string(),
        "--device".to_string(),
        route.device.clone(),
    ];
    if let Some(gateway) = route.gateway {
        args.push("--gateway".to_string());
        args.push(gateway.to_string());
    }

    let output = run_helper(args).await?;
    if !output.status.success() {
        anyhow::bail!("Failed to pin VPN endpoint (exit {})", output.status);
    }
    info!("Pinned VPN endpoint {} on {}", route.server, route.device);
    Ok(())
}

/// Remove a pin installed by [`pin_endpoint`]. Best-effort.
pub async fn unpin_endpoint(server: Ipv4Addr) {
    let helper = match find_helper() {
        Ok(h) => h,
        Err(e) => {
            warn!("Cannot find helper to remove endpoint pin: {e:#}");
            return;
        }
    };
    let args = vec![
        helper,
        "unpin-endpoint".to_string(),
        "--ip".to_string(),
        server.to_string(),
    ];
    match run_helper(args).await {
        Ok(output) if !output.status.success() => {
            warn!("Failed to remove VPN endpoint pin (exit {})", output.status);
        }
        Ok(_) => {}
        Err(e) => warn!("Failed to run helper to remove endpoint pin: {e:#}"),
    }
}

/// Run the helper binary, using pkexec only if the helper lacks CAP_NET_ADMIN.
async fn run_helper(args: Vec<String>) -> Result<std::process::Output> {
    if needs_pkexec() {
        tokio::process::Command::new("pkexec")
            .args(&args)
            .output()
            .await
            .context("Failed to execute pkexec — is Polkit installed?")
    } else {
        let (program, cmd_args) = args
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("Empty args for run_helper"))?;
        tokio::process::Command::new(program)
            .args(cmd_args)
            .output()
            .await
            .context("Failed to execute helper binary")
    }
}

/// Set up the TUN device, routing, and DNS via the privileged helper.
///
/// If the helper has CAP_NET_ADMIN, runs directly. Otherwise uses pkexec.
pub async fn setup(
    device: &str,
    local_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    mtu: u16,
    routes: &[String],
    default_gw: Option<Ipv4Addr>,
    dns: Option<Ipv4Addr>,
) -> Result<()> {
    let helper = find_helper()?;
    let uid = current_uid();

    if needs_pkexec() {
        info!("Requesting admin access (via pkexec) to create tunnel device {device}");
    } else {
        info!("Creating tunnel device {device} using CAP_NET_ADMIN capability");
    }

    let mut args = vec![
        helper.clone(),
        "setup".to_string(),
        "--device".to_string(),
        device.to_string(),
        "--uid".to_string(),
        uid.to_string(),
        "--local-ip".to_string(),
        local_ip.to_string(),
        "--peer-ip".to_string(),
        peer_ip.to_string(),
        "--mtu".to_string(),
        mtu.to_string(),
    ];

    for route in routes {
        args.push("--route".to_string());
        args.push(route.clone());
    }

    if let Some(gw) = default_gw {
        args.push("--default-gw".to_string());
        args.push(gw.to_string());
    }

    if let Some(dns_ip) = dns {
        args.push("--dns".to_string());
        args.push(dns_ip.to_string());
    }

    let output = run_helper(args).await?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stderr.lines() {
        if !line.is_empty() {
            info!("helper: {line}");
        }
    }

    if !output.status.success() {
        anyhow::bail!("Privileged setup failed (exit {})", output.status);
    }

    info!("Privileged tunnel setup complete");
    Ok(())
}

/// Tear down the TUN device, routing, and DNS via the privileged helper.
///
/// Best-effort: logs warnings on failure rather than returning errors,
/// since teardown should not prevent the app from continuing.
pub async fn teardown(device: &str, restore_dns: bool) {
    let helper = match find_helper() {
        Ok(h) => h,
        Err(e) => {
            warn!("Cannot find helper for teardown: {e:#}");
            return;
        }
    };

    if needs_pkexec() {
        info!("Requesting admin access (via pkexec) to remove tunnel device {device}");
    } else {
        info!("Removing tunnel device {device} using CAP_NET_ADMIN capability");
    }

    let mut args = vec![
        helper,
        "teardown".to_string(),
        "--device".to_string(),
        device.to_string(),
    ];

    if restore_dns {
        args.push("--restore-dns".to_string());
    }

    match run_helper(args).await {
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            for line in stderr.lines() {
                if !line.is_empty() {
                    info!("helper: {line}");
                }
            }
            if !output.status.success() {
                warn!("Privileged teardown failed (exit {})", output.status);
            } else {
                info!("Privileged tunnel teardown complete");
            }
        }
        Err(e) => {
            warn!("Failed to execute helper for teardown: {e:#}");
        }
    }
}
