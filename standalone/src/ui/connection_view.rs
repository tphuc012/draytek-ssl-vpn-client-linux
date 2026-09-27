/// Connection status display + connect/disconnect controls.
use crate::messages::{Phase, StatusView};
use crate::nm_bridge::{read_stats, TunnelStats};
use gtk4::prelude::*;
use std::cell::Cell;

/// Build the connection status view.
#[derive(Clone)]
pub struct ConnectionView {
    /// Status text and detail rows. Meant to go inside a scroller: the amount of
    /// detail varies with the state, and the window can be shorter than the
    /// tallest of them.
    pub container: gtk4::Box,
    /// The connect/disconnect buttons, kept out of `container` on purpose.
    ///
    /// These must stay on screen at every window size. Inside the scroller they
    /// were the first thing to be pushed out of view, which is how a window can
    /// end up showing a status the user has no control over.
    pub actions: gtk4::Box,
    status_label: gtk4::Label,
    timer_label: gtk4::Label,
    /// Status text for the states with no detail to show.
    details_label: gtk4::Label,
    /// Individual info labels (visible when connected).
    info_box: gtk4::Box,
    server_label: gtk4::Label,
    ip_label: gtk4::Label,
    dns_label: gtk4::Label,
    routing_label: gtk4::Label,
    /// Individual stats labels (visible when connected).
    stats_box: gtk4::Box,
    tx_label: gtk4::Label,
    rx_label: gtk4::Label,
    packets_label: gtk4::Label,
    pub connect_btn: gtk4::Button,
    pub disconnect_btn: gtk4::Button,
    status_icon: gtk4::Image,
    /// Seconds connected when the last status update arrived, so the uptime
    /// keeps counting between updates instead of freezing.
    connected_secs: Cell<u64>,
    /// Last counters seen, to derive a rate rather than a total.
    last_stats: Cell<Option<(TunnelStats, std::time::Instant)>>,
}

fn info_label(tooltip: &str) -> gtk4::Label {
    gtk4::Label::builder()
        .css_classes(["dim-label"])
        .xalign(0.0)
        .selectable(true)
        .wrap(true)
        .tooltip_text(tooltip)
        .build()
}

fn stat_label(tooltip: &str) -> gtk4::Label {
    gtk4::Label::builder()
        .css_classes(["monospace", "dim-label"])
        .xalign(0.0)
        .selectable(true)
        .tooltip_text(tooltip)
        .build()
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_duration(secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

impl ConnectionView {
    pub fn new() -> Self {
        let container = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
        container.set_margin_top(16);
        container.set_margin_bottom(8);
        container.set_margin_start(24);
        container.set_margin_end(24);

        let status_icon = gtk4::Image::builder()
            .icon_name("network-offline-symbolic")
            .pixel_size(64)
            .css_classes(["dim-label"])
            .build();

        let status_row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        status_row.set_halign(gtk4::Align::Center);

        let status_label = gtk4::Label::builder()
            .label("Disconnected")
            .css_classes(["title-2"])
            .build();

        let timer_label = gtk4::Label::builder()
            .label("")
            .css_classes(["title-2", "dim-label"])
            .visible(false)
            .build();

        status_row.append(&status_label);
        status_row.append(&timer_label);

        let details_label = gtk4::Label::builder()
            .label("Select a connection and press Connect")
            .css_classes(["dim-label"])
            .xalign(0.0)
            .wrap(true)
            .build();

        let info_box = gtk4::Box::new(gtk4::Orientation::Vertical, 4);
        info_box.set_visible(false);

        let server_label = info_label("The VPN server this connection was made to");
        let ip_label = info_label("Address assigned to the tunnel interface");
        let dns_label = info_label(
            "Name servers the router handed out over IPCP.\n\
             Worth checking when the tunnel is up but nothing resolves: a full \
             tunnel sends DNS through the tunnel too, so an unreachable resolver \
             looks exactly like being offline.",
        );
        let routing_label = info_label(
            "What goes through the tunnel.\n\
             A full tunnel sends everything; otherwise only the listed subnets.",
        );

        info_box.append(&server_label);
        info_box.append(&ip_label);
        info_box.append(&dns_label);
        info_box.append(&routing_label);

        let stats_box = gtk4::Box::new(gtk4::Orientation::Vertical, 4);
        stats_box.set_visible(false);

        let tx_label = stat_label("Bytes sent through the tunnel");
        let rx_label = stat_label("Bytes received through the tunnel");
        let packets_label = stat_label("Packet counts in each direction");

        stats_box.append(&tx_label);
        stats_box.append(&rx_label);
        stats_box.append(&packets_label);

        let connect_btn = gtk4::Button::builder()
            .label("Connect")
            .css_classes(["suggested-action"])
            .build();

        let disconnect_btn = gtk4::Button::builder()
            .label("Disconnect")
            .css_classes(["destructive-action"])
            .visible(false)
            .build();

        container.append(&status_icon);
        container.append(&status_row);
        container.append(&details_label);
        container.append(&info_box);
        container.append(&stats_box);

        // Pinned outside the scrolling area, so the controls survive any window
        // height. See the note on `actions`.
        let actions = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
        actions.set_homogeneous(true);
        actions.set_margin_start(24);
        actions.set_margin_end(24);
        actions.set_margin_bottom(16);
        actions.append(&connect_btn);
        actions.append(&disconnect_btn);

        Self {
            container,
            actions,
            status_label,
            timer_label,
            details_label,
            info_box,
            server_label,
            ip_label,
            dns_label,
            routing_label,
            stats_box,
            tx_label,
            rx_label,
            packets_label,
            connect_btn,
            disconnect_btn,
            status_icon,
            connected_secs: Cell::new(0),
            last_stats: Cell::new(None),
        }
    }

    /// Redraw for a status reported by NetworkManager.
    ///
    /// `failure` carries the reason for [`Phase::Failed`]; NM reports the code
    /// rather than a sentence, and passing it through beats inventing one.
    pub fn update_status(&self, view: &StatusView, failure: Option<&str>) {
        // Reset every conditional widget first: switching straight from
        // connected to failed must not leave the info box on screen.
        self.set_prose(false);
        self.set_detail_rows(false);
        self.set_stats_visibility(false);
        self.set_icon("network-offline-symbolic", false);
        self.connect_btn.set_visible(true);
        self.connect_btn.set_sensitive(true);
        self.disconnect_btn.set_visible(false);
        self.disconnect_btn.set_sensitive(true);
        self.timer_label.set_visible(false);

        match view.phase {
            Phase::Disconnected => {
                self.status_label.set_label("Disconnected");
                self.details_label
                    .set_label("Select a connection and press Connect");
                self.set_prose(true);
                self.connected_secs.set(0);
                self.last_stats.set(None);
            }
            Phase::Connecting => {
                self.status_label.set_label("Connecting...");
                self.details_label
                    .set_label(&format!("Asking NetworkManager to bring up {}", view.name));
                self.set_prose(true);
                self.set_icon("network-transmit-symbolic", true);
                // Disconnect doubles as cancel here, so offer it rather than a
                // Connect that would only queue a second attempt.
                self.connect_btn.set_visible(false);
                self.disconnect_btn.set_visible(true);
            }
            Phase::Failed => {
                self.status_label.set_label("Connection failed");
                self.details_label
                    .set_label(failure.unwrap_or("NetworkManager reported a failure"));
                self.set_prose(true);
                self.set_icon("network-offline-symbolic", false);
            }
            Phase::Connected => {
                self.status_label.set_label("Connected");
                self.connected_secs.set(view.connected_secs);
                self.timer_label
                    .set_label(&format_duration(view.connected_secs));
                self.timer_label.set_visible(true);

                self.server_label
                    .set_label(&format!("Server: {}", display_or_unknown(&view.server)));
                self.ip_label.set_label(&format!(
                    "Tunnel IP: {}",
                    display_or_unknown(&view.local_ip)
                ));
                self.dns_label.set_label(&dns_summary(view));
                self.routing_label.set_label(&routing_summary(view));
                self.set_detail_rows(true);

                self.set_icon("network-vpn-symbolic", true);
                // The reset above left Connect visible; a connected tunnel has
                // nothing to connect, and two lit buttons for opposing actions is
                // how you get a user to press the wrong one.
                self.connect_btn.set_visible(false);
                self.disconnect_btn.set_visible(true);
                self.set_stats_visibility(true);
            }
        }
    }

    /// Advance the uptime and refresh the traffic counters.
    ///
    /// Called on a timer rather than only on status changes, so the clock ticks
    /// and the byte counts move while nothing about the connection changes.
    pub fn tick(&self) {
        if self.connected_secs.get() > 0 {
            self.connected_secs.set(self.connected_secs.get() + 1);
            self.timer_label
                .set_label(&format_duration(self.connected_secs.get()));
        }

        if !self.stats_box.is_visible() {
            return;
        }
        let Some(stats) = read_stats() else {
            return;
        };

        // A counter that went backwards means the interface was recreated, i.e.
        // a reconnect: report the new totals instead of a negative rate.
        let (previous, at) = match self.last_stats.get() {
            Some(v) if v.0.bytes_rx <= stats.bytes_rx && v.0.bytes_tx <= stats.bytes_tx => v,
            _ => {
                self.last_stats
                    .set(Some((stats, std::time::Instant::now())));
                return;
            }
        };
        let elapsed = at.elapsed().as_secs_f64();
        self.last_stats
            .set(Some((stats, std::time::Instant::now())));

        if elapsed < 0.5 {
            return;
        }

        let rate = |now: u64, before: u64| ((now - before) as f64 / elapsed) as u64;
        self.tx_label.set_label(&format!(
            "Sent:     {}  ({} /s)",
            format_bytes(stats.bytes_tx),
            format_bytes(rate(stats.bytes_tx, previous.bytes_tx))
        ));
        self.rx_label.set_label(&format!(
            "Received: {}  ({} /s)",
            format_bytes(stats.bytes_rx),
            format_bytes(rate(stats.bytes_rx, previous.bytes_rx))
        ));
        self.packets_label.set_label(&format!(
            "Packets:  {} sent / {} received",
            stats.packets_tx, stats.packets_rx
        ));
    }

    /// Prose line for the states with no rows to show, versus the detail rows
    /// for the connected state. Exactly one of the two is ever visible, so
    /// every state change resets both before filling one in.
    fn set_prose(&self, visible: bool) {
        self.details_label.set_visible(visible);
    }

    fn set_detail_rows(&self, visible: bool) {
        self.info_box.set_visible(visible);
    }

    fn set_stats_visibility(&self, visible: bool) {
        self.stats_box.set_visible(visible);
    }

    fn set_icon(&self, name: &str, active: bool) {
        self.status_icon.set_icon_name(Some(name));
        if active {
            self.status_icon.remove_css_class("dim-label");
            self.status_icon.add_css_class("success");
        } else {
            self.status_icon.remove_css_class("success");
            self.status_icon.add_css_class("dim-label");
        }
    }
}

fn display_or_unknown(value: &str) -> &str {
    if value.is_empty() {
        "unknown"
    } else {
        value
    }
}

/// One line describing what the tunnel carries.
fn routing_summary(view: &StatusView) -> String {
    if view.is_default_route {
        return "Routing: all traffic (full tunnel)".to_string();
    }
    if view.routes.is_empty() {
        return "Routing: nothing — no traffic goes through the tunnel".to_string();
    }
    format!("Routing: {}", view.routes.join(", "))
}

/// One line naming the resolvers in use.
///
/// Saying "none" plainly matters more than hiding the row: a full tunnel moves
/// DNS onto the tunnel as well, so a resolver the router cannot reach produces
/// a working tunnel that resolves nothing.
fn dns_summary(view: &StatusView) -> String {
    if view.dns.is_empty() {
        return "DNS: none from the router — using the system's".to_string();
    }
    format!("DNS: {}", view.dns.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full tunnel's `0.0.0.0/0` is already conveyed by the phrase "full
    /// tunnel"; listing it as well reads as a misconfiguration.
    #[test]
    fn full_tunnel_routes_read_as_full_tunnel() {
        let view = StatusView {
            is_default_route: true,
            routes: vec!["192.168.1.0/24".to_string()],
            ..Default::default()
        };
        assert_eq!(routing_summary(&view), "Routing: all traffic (full tunnel)");
    }

    /// Saying "no traffic" matters: a split profile with an empty route list
    /// looks identical to a working one unless the window says so.
    #[test]
    fn empty_route_list_says_so() {
        let view = StatusView::default();
        assert_eq!(
            routing_summary(&view),
            "Routing: nothing — no traffic goes through the tunnel"
        );
    }

    #[test]
    fn byte_formatting_is_readable() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn duration_is_zero_padded() {
        assert_eq!(format_duration(0), "00:00:00");
        assert_eq!(format_duration(61), "00:01:01");
        assert_eq!(format_duration(3661), "01:01:01");
    }
}
