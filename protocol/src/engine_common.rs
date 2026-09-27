//! Common engine helpers shared between GUI and NM plugin data loops.

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::pin::Pin;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use crate::protocol::fsm::{FsmAction, PppFsm};
use crate::protocol::ppp::PppFrame;

/// LCP + IPCP finite state machines, used together by both data loops.
pub struct PppFsmPair {
    pub lcp: PppFsm,
    pub ipcp: PppFsm,
}

/// Tunnel IP configuration negotiated during IPCP.
#[derive(Clone, Copy)]
pub struct TunnelAddrs {
    pub mtu: u16,
    pub local_ip: Ipv4Addr,
    pub remote_ip: Ipv4Addr,
}

/// What the data loop should do beyond moving packets.
#[derive(Clone, Copy, Default)]
pub struct DataLoopOptions {
    /// Send periodic ICMP pings so the router does not idle the tunnel out.
    pub keepalive_ping: bool,
    /// Log the kernel's effective route once the routing table has settled.
    ///
    /// Only meaningful when this connection becomes the default route: that is
    /// the one mode where "which device will my packets leave by" is in
    /// question, and where "no internet" has more than one possible cause.
    pub report_effective_route: bool,
}

/// Send a PPP frame wrapped in SSTP over the TLS stream.
pub async fn send_ppp_frame<S: tokio::io::AsyncWrite + Unpin>(
    frame: &PppFrame,
    stream: &mut S,
) -> Result<()> {
    let bytes = frame.to_sstp_bytes();
    Pin::new(stream)
        .write_all(&bytes)
        .await
        .context("Failed to write PPP frame to TLS stream")?;
    Ok(())
}

/// Outcome of a write that can be abandoned on disconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The whole frame was written.
    Sent,
    /// A disconnect was requested first; the write was abandoned.
    Cancelled,
}

/// Send a PPP frame, giving up if a disconnect arrives or the peer stops reading.
///
/// A bare `write_all` can block for a full TCP retransmission timeout when the
/// far end has stopped reading. A future stuck inside a `select!` branch body is
/// not interrupted by the cancel channel, so shutdown then takes tens of
/// seconds — long enough for NM to time the VPN out and delete the TUN device
/// underneath us. Racing the write against the cancel signal (and a timeout)
/// keeps teardown responsive whatever the data path is doing.
pub async fn send_ppp_frame_cancellable<S: tokio::io::AsyncWrite + Unpin>(
    frame: &PppFrame,
    stream: &mut S,
    cancel: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<WriteOutcome> {
    let bytes = frame.to_sstp_bytes();
    let mut pinned = Pin::new(stream);
    let write = pinned.write_all(&bytes);

    tokio::select! {
        biased;
        result = write => {
            result.context("Failed to write PPP frame to TLS stream")?;
            Ok(WriteOutcome::Sent)
        }
        _ = cancel.changed() => Ok(WriteOutcome::Cancelled),
        () = tokio::time::sleep(std::time::Duration::from_secs(WRITE_TIMEOUT_SECS)) => {
            warn!("write timed out after {WRITE_TIMEOUT_SECS}s, abandoning frame");
            Ok(WriteOutcome::Cancelled)
        }
    }
}

/// How long a single tunnel write may block before it is abandoned.
const WRITE_TIMEOUT_SECS: u64 = 10;

/// One-shot data-plane milestones, each logged the first time it happens.
///
/// A tunnel that negotiates, gets its routes installed and then reaches nothing
/// looks identical from the outside: no error, no warning, just no internet. These
/// three lines are what separate "the control path is alive and the router is
/// dropping our traffic" from "the control path itself is dead" in the journal.
#[derive(Default)]
pub struct DataPlaneWitness {
    logged_tx: bool,
    logged_rx: bool,
    logged_reply: bool,
}

impl DataPlaneWitness {
    /// A packet was read from the TUN and handed to the tunnel.
    pub fn on_tun_tx(&mut self, bytes: usize) {
        if !self.logged_tx {
            self.logged_tx = true;
            info!("Data plane: first {bytes} bytes queued into the tunnel");
        }
    }

    /// A packet arrived from the tunnel and is being written to the TUN.
    pub fn on_tunnel_rx(&mut self, bytes: usize) {
        if !self.logged_rx {
            self.logged_rx = true;
            info!("Data plane: first {bytes} bytes received from the tunnel");
        }
    }

    /// The server answered an SSTP keepalive REQUEST.
    ///
    /// The strongest single proof that the control path survived: it is a round
    /// trip over the very connection a default route would otherwise pull into
    /// the tunnel it is carrying.
    pub fn on_keepalive_reply(&mut self) {
        if !self.logged_reply {
            self.logged_reply = true;
            info!("Data plane: control path confirmed — server answered keepalive");
        }
    }
}

/// Execute FSM actions: send frames and check for shutdown/layer-up.
pub async fn execute_actions<S: tokio::io::AsyncWrite + Unpin>(
    actions: &[FsmAction],
    protocol: u16,
    tag: &str,
    stream: &mut S,
) -> Result<()> {
    for action in actions {
        match action {
            FsmAction::SendFrame(ctrl) => {
                let ppp_frame = PppFrame::new(protocol, ctrl.to_bytes());
                send_ppp_frame(&ppp_frame, stream).await?;
            }
            FsmAction::LayerUp => {
                info!("{tag} layer up");
            }
            FsmAction::Shutdown => {
                // Caller handles this via check_shutdown
            }
        }
    }
    Ok(())
}

/// Check if any action is a Shutdown and bail if so.
pub fn check_shutdown(actions: &[FsmAction]) -> Result<()> {
    if actions.iter().any(|a| matches!(a, FsmAction::Shutdown)) {
        bail!("FSM requested shutdown (max retries exceeded or fatal error)");
    }
    Ok(())
}

/// Build a minimal ICMP echo request (ping) packet with IPv4 header.
fn build_icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, seq: u16) -> Vec<u8> {
    let ping_id: u16 = 0x4456; // "DV" for DrayTek VPN

    // ICMP Echo Request: type=8, code=0, checksum, id, seq
    let mut icmp = vec![0u8; 8];
    icmp[0] = 8; // type: echo request
    icmp[1] = 0; // code
                 // checksum at [2..4] filled below
    icmp[2] = 0;
    icmp[3] = 0;
    icmp[4] = (ping_id >> 8) as u8;
    icmp[5] = ping_id as u8;
    icmp[6] = (seq >> 8) as u8;
    icmp[7] = seq as u8;

    // ICMP checksum
    let icmp_cksum = internet_checksum(&icmp);
    icmp[2] = (icmp_cksum >> 8) as u8;
    icmp[3] = icmp_cksum as u8;

    // IPv4 header (20 bytes, no options)
    let total_len: u16 = 20 + icmp.len() as u16;
    let src = src.octets();
    let dst = dst.octets();
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45; // version=4, IHL=5
    ip[1] = 0; // DSCP/ECN
    ip[2] = (total_len >> 8) as u8;
    ip[3] = total_len as u8;
    ip[4] = 0;
    ip[5] = 0; // identification
    ip[6] = 0x40; // flags: Don't Fragment
    ip[7] = 0; // fragment offset
    ip[8] = 64; // TTL
    ip[9] = 1; // protocol: ICMP
               // header checksum at [10..12] filled below
    ip[10] = 0;
    ip[11] = 0;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);

    let ip_cksum = internet_checksum(&ip);
    ip[10] = (ip_cksum >> 8) as u8;
    ip[11] = ip_cksum as u8;

    ip.extend_from_slice(&icmp);
    ip
}

/// Standard internet checksum (RFC 1071).
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Aggregated traffic counters for the data loop.
pub struct TrafficStats {
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub oversized_tx: u64,
    pub oversized_rx: u64,
    pub max_packet_tx: usize,
    pub max_packet_rx: usize,
    pub mtu: usize,
    pub last_sent: tokio::time::Instant,
}

impl TrafficStats {
    pub fn new(mtu: u16) -> Self {
        Self {
            bytes_tx: 0,
            bytes_rx: 0,
            packets_tx: 0,
            packets_rx: 0,
            oversized_tx: 0,
            oversized_rx: 0,
            max_packet_tx: 0,
            max_packet_rx: 0,
            mtu: mtu as usize,
            last_sent: tokio::time::Instant::now(),
        }
    }

    pub fn record_tx(&mut self, size: usize) {
        self.packets_tx += 1;
        self.bytes_tx += size as u64;
        if size > self.mtu {
            self.oversized_tx += 1;
        }
        self.max_packet_tx = self.max_packet_tx.max(size);
    }

    pub fn record_rx(&mut self, size: usize) {
        self.packets_rx += 1;
        self.bytes_rx += size as u64;
        if size > self.mtu {
            self.oversized_rx += 1;
        }
        self.max_packet_rx = self.max_packet_rx.max(size);
    }

    pub fn should_send_update(&self) -> bool {
        self.last_sent.elapsed() >= tokio::time::Duration::from_secs(1)
    }

    pub fn mark_sent(&mut self) {
        self.last_sent = tokio::time::Instant::now();
    }
}

/// ICMP keepalive ping state for the data-plane.
pub struct PingKeeper {
    pub enabled: bool,
    pub seq: u16,
    pub last_sent: tokio::time::Instant,
    pub local_ip: Ipv4Addr,
    pub remote_ip: Ipv4Addr,
}

impl PingKeeper {
    pub fn new(local_ip: Ipv4Addr, remote_ip: Ipv4Addr) -> Self {
        Self {
            enabled: false,
            seq: 0,
            last_sent: tokio::time::Instant::now(),
            local_ip,
            remote_ip,
        }
    }

    /// Toggle keepalive. Returns a frame to send immediately when enabling.
    pub fn set_enabled(&mut self, enabled: bool) -> Option<PppFrame> {
        self.enabled = enabled;
        info!(
            "Data-plane keepalive ping {}",
            if enabled { "enabled" } else { "disabled" }
        );
        if enabled {
            self.send_ping()
        } else {
            None
        }
    }

    /// If enabled and interval has elapsed, returns a ping frame to send.
    pub fn maybe_send(&mut self) -> Option<PppFrame> {
        if self.enabled && self.last_sent.elapsed() >= tokio::time::Duration::from_secs(30) {
            self.send_ping()
        } else {
            None
        }
    }

    fn send_ping(&mut self) -> Option<PppFrame> {
        let icmp_pkt = build_icmp_echo(self.local_ip, self.remote_ip, self.seq);
        let frame = PppFrame::ipv4(icmp_pkt);
        info!("Sent keepalive ping seq={}", self.seq);
        self.seq = self.seq.wrapping_add(1);
        self.last_sent = tokio::time::Instant::now();
        Some(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::SSTP_CMD_DATA;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWrite};

    fn frame() -> PppFrame {
        PppFrame::ipv4(vec![0x45, 0x00, 0x00, 0x1c])
    }

    /// Stands in for a peer that has stopped reading: every write stays pending
    /// forever. This is the case that used to wedge shutdown for tens of
    /// seconds while a TCP retransmission timeout ran out.
    struct StalledWriter;

    impl AsyncWrite for StalledWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn cancellable_write_reports_sent_when_stream_accepts() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        drop(tx);

        let outcome = send_ppp_frame_cancellable(&frame(), &mut client, &mut rx)
            .await
            .expect("write should succeed");
        assert_eq!(outcome, WriteOutcome::Sent);

        let mut head = [0u8; 1];
        server.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], SSTP_CMD_DATA);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellable_write_gives_up_on_disconnect() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let mut writer = StalledWriter;

        let task = tokio::spawn(async move {
            send_ppp_frame_cancellable(&frame(), &mut writer, &mut rx).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tx.send(true).unwrap();

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("write ignored the disconnect request")
            .expect("task panicked")
            .expect("write should not have errored");
        assert_eq!(outcome, WriteOutcome::Cancelled);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellable_write_gives_up_when_the_peer_stalls() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        drop(tx);
        let mut writer = StalledWriter;

        // Paused time means the timeout fires immediately, so this asserts the
        // abandonment path without actually waiting WRITE_TIMEOUT_SECS.
        let outcome = send_ppp_frame_cancellable(&frame(), &mut writer, &mut rx)
            .await
            .expect("write should not have errored");
        assert_eq!(outcome, WriteOutcome::Cancelled);
    }
}
