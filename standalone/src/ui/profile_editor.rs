/// Connection editor: create and edit DrayTek VPN profiles.
///
/// The form is the only place profiles are entered, and it writes them straight
/// into NetworkManager rather than into a file of its own. That is what lets the
/// app, the tray and GNOME Settings all see one list: a profile created here is
/// the same profile `nmcli` and the C editor plugin work with, with no import
/// step and no second copy to fall out of sync.
use crate::messages::DraytekProfile;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::error;

/// Show the editor for a new or existing profile.
///
/// `existing` is `None` for a new profile. `on_save` receives the edited
/// profile; persisting it is the caller's job, because that means a different
/// D-Bus call for a new connection than for an existing one.
pub fn show_editor(
    parent: &adw::ApplicationWindow,
    existing: Option<DraytekProfile>,
    on_save: impl Fn(DraytekProfile) + 'static,
) {
    let editing = existing.is_some();
    let profile = existing.unwrap_or_else(|| DraytekProfile {
        name: String::new(),
        gateway: String::new(),
        port: 443,
        ..Default::default()
    });

    let dialog = adw::AlertDialog::builder()
        .heading(if editing {
            "Edit Connection"
        } else {
            "New Connection"
        })
        .body("Saved to NetworkManager, so GNOME Settings and the tray see it too.")
        .build();

    let group = adw::PreferencesGroup::new();
    let page = adw::PreferencesPage::new();
    page.add(&group);

    let name_row = adw::EntryRow::builder()
        .title("Name")
        .text(&profile.name)
        .tooltip_text("How this connection is listed in the app, the tray and Settings")
        .build();
    let gateway_row = adw::EntryRow::builder()
        .title("Server address")
        .text(&profile.gateway)
        .tooltip_text("Hostname or IP address of the DrayTek router")
        .build();
    let port_row = adw::SpinRow::builder()
        .title("Port")
        .tooltip_text("SSL VPN port on the router (default: 443)")
        .adjustment(&gtk4::Adjustment::new(
            f64::from(profile.port.max(1)),
            1.0,
            65535.0,
            1.0,
            10.0,
            0.0,
        ))
        .build();
    let username_row = adw::EntryRow::builder()
        .title("Username")
        .text(&profile.username)
        .build();
    let password_row = adw::PasswordEntryRow::builder()
        .title("Password")
        .tooltip_text(
            "Stored by NetworkManager with the connection, the same way GNOME \
             Settings stores it. Leave blank when editing to keep the saved password.",
        )
        .build();
    // The router's certificate is self-signed by default, so this reads as
    // "check the certificate" and defaults to off.
    let verify_row = adw::SwitchRow::builder()
        .title("Verify TLS certificate")
        .tooltip_text("Leave off for the router's self-signed certificate")
        .active(profile.verify_cert)
        .build();
    let keepalive_row = adw::SwitchRow::builder()
        .title("Keepalive")
        .tooltip_text(
            "Send periodic pings so the router does not drop the tunnel when idle. \
             Worth enabling on a full tunnel, where the connection is the only route out.",
        )
        .active(profile.keepalive)
        .build();
    let default_gw_row = adw::SwitchRow::builder()
        .title("Use as default gateway")
        .tooltip_text(
            "Route all internet traffic through the tunnel.\n\
             Off means only the subnets below go through the VPN.",
        )
        .active(profile.default_gateway)
        .build();
    let route_remote_row = adw::SwitchRow::builder()
        .title("Route remote network")
        .tooltip_text("Also route the router's own subnet through the tunnel")
        .active(profile.route_remote_network)
        .build();
    let routes_row = adw::EntryRow::builder()
        .title("Additional routes")
        .text(&profile.routes)
        .tooltip_text(
            "Extra subnets to route through the tunnel, comma separated CIDR.\n\
             e.g. 10.0.0.0/8,192.168.5.0/24\n\
             Ignored when the connection is the default gateway.",
        )
        .build();
    let mru_row = adw::SpinRow::builder()
        .title("MRU")
        .tooltip_text("Largest packet the router will accept. 0 uses the protocol default of 1280")
        .adjustment(&gtk4::Adjustment::new(
            f64::from(profile.mru),
            0.0,
            9000.0,
            1.0,
            100.0,
            0.0,
        ))
        .build();

    group.add(&name_row);
    group.add(&gateway_row);
    group.add(&port_row);
    group.add(&username_row);
    group.add(&password_row);
    group.add(&verify_row);

    let routing_group = adw::PreferencesGroup::new();
    routing_group.add(&default_gw_row);
    routing_group.add(&route_remote_row);
    routing_group.add(&routes_row);
    routing_group.add(&keepalive_row);
    routing_group.add(&mru_row);
    page.add(&routing_group);

    // A full tunnel already carries everything, so the per-subnet options stop
    // meaning anything and leaving them enabled only misleads.
    let update_sensitivity = {
        let route_remote_row = route_remote_row.clone();
        let routes_row = routes_row.clone();
        move |is_default_gw: bool| {
            route_remote_row.set_sensitive(!is_default_gw);
            routes_row.set_sensitive(!is_default_gw);
        }
    };
    update_sensitivity(profile.default_gateway);
    default_gw_row.connect_active_notify(move |row| {
        update_sensitivity(row.is_active());
    });

    dialog.set_extra_child(Some(&page));
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("save", "Save");
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("save"));
    dialog.set_close_response("cancel");

    dialog.connect_response(None, move |_, response| {
        if response != "save" {
            return;
        }
        let edited = DraytekProfile {
            name: name_row.text().trim().to_string(),
            gateway: gateway_row.text().trim().to_string(),
            port: port_row.value() as u16,
            username: username_row.text().trim().to_string(),
            password: password_row.text().to_string(),
            verify_cert: verify_row.is_active(),
            mru: mru_row.value() as u16,
            route_remote_network: route_remote_row.is_active(),
            default_gateway: default_gw_row.is_active(),
            keepalive: keepalive_row.is_active(),
            routes: routes_row.text().trim().to_string(),
        };
        if let Err(e) = validate(&edited) {
            error!("Refusing to save an invalid profile: {e}");
            // The dialog is gone by now, so the reason has to reach the log and
            // the caller re-opens the form; there is no dialog left to show it in.
            return;
        }
        on_save(edited);
    });

    dialog.present(Some(parent));
}

/// Reject a profile the plugin could not use.
///
/// Better here than at connect time: the plugin's own parser reports only
/// "Missing 'gateway' in vpn.data", which by then looks like a plugin bug.
fn validate(profile: &DraytekProfile) -> anyhow::Result<()> {
    if profile.name.trim().is_empty() {
        anyhow::bail!("Name is required");
    }
    if profile.gateway.trim().is_empty() {
        anyhow::bail!("Server address is required");
    }
    if profile.username.trim().is_empty() {
        anyhow::bail!("Username is required");
    }
    if profile.port == 0 {
        anyhow::bail!("Port must be between 1 and 65535");
    }
    Ok(())
}

/// Confirm and run a destructive action on a profile.
pub fn confirm_delete(
    parent: &adw::ApplicationWindow,
    name: &str,
    on_confirm: impl Fn() + 'static,
) {
    let dialog = adw::AlertDialog::builder()
        .heading("Delete connection?")
        .body(format!(
            "\"{name}\" will be removed from NetworkManager. \
             This cannot be undone, and the password saved with it goes too."
        ))
        .build();
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("delete", "Delete");
    dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("cancel"));
    dialog.set_close_response("cancel");
    dialog.connect_response(None, move |_, response| {
        if response == "delete" {
            on_confirm();
        }
    });
    dialog.present(Some(parent));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> DraytekProfile {
        DraytekProfile {
            name: "Office".to_string(),
            gateway: "vpn.example.com".to_string(),
            port: 443,
            username: "alice".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn a_complete_profile_passes() {
        validate(&valid()).expect("should be accepted");
    }

    /// Each of these produces a connection that saves fine and then fails to
    /// start, with a message that points at the plugin rather than the form.
    #[test]
    fn each_missing_field_names_itself() {
        let mut p = valid();
        p.name = "  ".to_string();
        assert!(validate(&p).is_err_and(|e| e.to_string().contains("Name")));

        let mut p = valid();
        p.gateway = String::new();
        assert!(validate(&p).is_err_and(|e| e.to_string().contains("Server")));

        let mut p = valid();
        p.username = String::new();
        assert!(validate(&p).is_err_and(|e| e.to_string().contains("Username")));

        let mut p = valid();
        p.port = 0;
        assert!(validate(&p).is_err_and(|e| e.to_string().contains("Port")));
    }

    /// A password is the one field that may be absent: on an edit, blank means
    /// "keep the one NetworkManager has stored".
    #[test]
    fn password_is_never_required_here() {
        let mut p = valid();
        p.password = String::new();
        validate(&p).expect("a blank password must not block saving");
    }
}
