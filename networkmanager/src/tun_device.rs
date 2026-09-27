/// TUN device creation for the NM plugin.
///
/// Running as root (spawned by NM), so we can create the TUN device directly
/// without pkexec or capability checks.
use anyhow::{Context, Result};
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use tracing::{info, warn};

// ioctl request code for TUNSETIFF
const TUNSETIFF: libc::c_ulong = 0x400454ca;

/// Create a TUN device, configure its point-to-point address, and bring it up.
///
/// The point-to-point address is set here rather than left to NetworkManager
/// because the kernel then installs its own host route to the peer
/// (`<peer> dev <name> scope link`, metric 0). NM insists on managing the
/// gateway itself and will otherwise resolve it over the *current* default
/// device, installing a /32 host route to the peer via the local link that
/// shadows the tunnel and sends traffic for the VPN router the wrong way.
///
/// Returns the async TUN device for read/write. Since we're running as root
/// (NM spawns VPN plugins as root), no privilege elevation is needed.
pub fn create_tun(
    name: &str,
    local_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    mtu: u16,
) -> Result<tun_rs::AsyncDevice> {
    info!("Creating TUN device {name}");

    // A previous session that did not tear down cleanly (NM restart, SIGKILL,
    // crash, or a stuck data loop) leaves the device behind. `ip tuntap add`
    // then fails with "File exists" and every reconnect dies right here, so
    // clear the leftover before creating ours.
    remove_stale_tun(name);

    // Create the TUN device using ip commands (we're root)
    let output = std::process::Command::new("ip")
        .args(["tuntap", "add", "dev", name, "mode", "tun"])
        .output()
        .context("Failed to run ip tuntap add")?;
    if !output.status.success() {
        anyhow::bail!(
            "ip tuntap add failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    // Configure the point-to-point address, which also creates the kernel host
    // route to the peer.
    let status = std::process::Command::new("ip")
        .args([
            "addr",
            "add",
            &format!("{local_ip}"),
            "peer",
            &format!("{peer_ip}"),
            "dev",
            name,
        ])
        .status()
        .context("Failed to configure IP address")?;
    if !status.success() {
        delete_tun(name);
        anyhow::bail!("ip addr add failed with {status}");
    }

    // Set MTU and bring up
    let status = std::process::Command::new("ip")
        .args(["link", "set", name, "mtu", &mtu.to_string(), "up"])
        .status()
        .context("Failed to set MTU and bring up")?;
    if !status.success() {
        delete_tun(name);
        anyhow::bail!("ip link set failed with {status}");
    }

    // Open the TUN device
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        delete_tun(name);
        return Err(std::io::Error::last_os_error()).context("Failed to open /dev/net/tun");
    }

    let c_name = CString::new(name).context("Invalid TUN device name")?;
    if let Err(e) = attach_tun(fd, &c_name) {
        unsafe {
            libc::close(fd);
        }
        delete_tun(name);
        return Err(e);
    }

    let device = unsafe { tun_rs::AsyncDevice::from_fd(fd) }
        .context("Failed to create AsyncDevice from TUN fd")?;

    info!("TUN device {name} created and configured");
    Ok(device)
}

/// Delete `name` if it still exists, ignoring failures.
///
/// Used before creating a device so a leftover from a crashed session cannot
/// block the next connect attempt.
fn remove_stale_tun(name: &str) {
    if !std::path::Path::new(&format!("/sys/class/net/{name}")).exists() {
        return;
    }
    warn!("Removing stale {name} left over from a previous session");
    let _ = std::process::Command::new("ip")
        .args(["tuntap", "del", "dev", name, "mode", "tun"])
        .status();
}

/// Delete the TUN device.
///
/// `ip tuntap del` is the correct way to remove a TUN interface; `ip link
/// delete` is kept as a fallback in case the device was created another way.
pub fn delete_tun(name: &str) {
    info!("Deleting TUN device {name}");

    match std::process::Command::new("ip")
        .args(["tuntap", "del", "dev", name, "mode", "tun"])
        .status()
    {
        Ok(status) if status.success() => {
            info!("TUN device {name} deleted");
            return;
        }
        Ok(status) => warn!("ip tuntap del {name} exited with {status}"),
        Err(e) => warn!("Failed to run ip tuntap del {name}: {e}"),
    }

    match std::process::Command::new("ip")
        .args(["link", "delete", name])
        .status()
    {
        Ok(status) if status.success() => info!("TUN device {name} deleted via ip link delete"),
        Ok(status) => warn!("ip link delete {name} exited with {status}"),
        Err(e) => warn!("Failed to delete TUN device {name}: {e}"),
    }
}

/// Attach to a TUN device via TUNSETIFF ioctl.
fn attach_tun(fd: RawFd, name: &CString) -> Result<()> {
    unsafe {
        let mut req: libc::ifreq = std::mem::zeroed();

        std::ptr::copy_nonoverlapping(
            name.as_ptr() as *const libc::c_char,
            req.ifr_name.as_mut_ptr(),
            name.as_bytes_with_nul().len(),
        );

        req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

        let ret = libc::ioctl(fd, TUNSETIFF as _, &mut req as *mut _);
        if ret < 0 {
            return Err(std::io::Error::last_os_error()).context("TUNSETIFF ioctl failed");
        }
    }
    Ok(())
}
