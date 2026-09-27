/// Main application window.
///
/// The window is a front end for NetworkManager's DrayTek VPN plugin. It holds
/// no tunnel: Connect and Disconnect are NM calls, and everything drawn comes
/// from NM's own reported state.
///
/// That is the point. The tray, GNOME Settings and this window all read the
/// same connection, so they cannot disagree about whether the VPN is up — which
/// is exactly what happened when the app ran a second, independent tunnel of
/// its own and reported "disconnected" while NM was connected.
use crate::glib_channels::GlibSender;
use crate::logging::LogBuffer;
use crate::messages::{DraytekProfile, SavedVpn, StatusView};
use crate::nm_bridge::{self, NmSession};
use crate::ui::connection_view::ConnectionView;
use crate::ui::log_view::LogView;
use crate::ui::profile_editor;
use draytek_vpn_nmapi::VpnState;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::Cell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use tracing::{error, info};
use zbus::zvariant::OwnedObjectPath;

/// How often the uptime and traffic counters advance, and the log repaints.
const TICK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

pub struct MainWindow {
    pub window: adw::ApplicationWindow,
}

impl MainWindow {
    pub fn new(
        app: &adw::Application,
        log_buffer: LogBuffer,
        tokio_handle: tokio::runtime::Handle,
    ) -> Self {
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("DrayTek SSL VPN")
            .default_width(560)
            .default_height(820)
            .width_request(480)
            .height_request(420)
            .build();

        // Shared truth, written from the tokio side and read on the GTK thread.
        // `Arc<Mutex<_>>` rather than `Rc<RefCell<_>>` because the sender side
        // must be `Send + Sync`; the widget side stays on the GTK thread and
        // only ever takes the lock briefly.
        //
        // Each holds the newest value rather than a queue: NM is the only
        // writer, so there is no ordering to preserve and a backlog would just
        // replay states the window has already drawn.
        let state: Arc<Mutex<VpnState>> = Arc::new(Mutex::new(VpnState::Disconnected));
        let saved: Arc<Mutex<Vec<SavedVpn>>> = Arc::new(Mutex::new(Vec::new()));
        // `Arc` rather than a bare `Option<NmSession>`: the click handlers are
        // `Fn`, so each nested save callback has to be able to take its own
        // handle to the session without moving one out of a shared capture.
        let session: Arc<Mutex<Option<Arc<NmSession>>>> = Arc::new(Mutex::new(None));
        // Only ever touched on the GTK thread, so it needs no locking.
        let selected: Rc<Cell<usize>> = Rc::new(Cell::new(0));
        // A profile the async loader has fetched and is waiting for the GTK
        // thread to render into the editor form.
        let pending_edit: Arc<Mutex<Option<(DraytekProfile, OwnedObjectPath)>>> =
            Arc::new(Mutex::new(None));

        let toolbar_view = adw::ToolbarView::new();
        let header = adw::HeaderBar::new();
        toolbar_view.add_top_bar(&header);

        let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);

        // Connection selector, filled from NM's saved VPN connections.
        let selector_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        selector_box.set_margin_start(16);
        selector_box.set_margin_end(16);
        selector_box.set_margin_top(8);

        let dropdown = gtk4::DropDown::builder()
            .hexpand(true)
            .tooltip_text("DrayTek VPN connections saved in NetworkManager")
            .build();

        let add_btn = gtk4::Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text("Add a connection")
            .css_classes(["flat"])
            .build();
        let edit_btn = gtk4::Button::builder()
            .icon_name("document-edit-symbolic")
            .tooltip_text("Edit the selected connection")
            .css_classes(["flat"])
            .build();
        let delete_btn = gtk4::Button::builder()
            .icon_name("user-trash-symbolic")
            .tooltip_text("Delete the selected connection")
            .css_classes(["flat"])
            .build();

        selector_box.append(&dropdown);
        selector_box.append(&add_btn);
        selector_box.append(&edit_btn);
        selector_box.append(&delete_btn);
        content.append(&selector_box);

        let connection_view = ConnectionView::new();
        let log_view = LogView::new(log_buffer);

        // The status area scrolls — the tallest state is the connected one with
        // three detail rows plus three counters — but the buttons below it do
        // not, so shrinking the window never hides the controls.
        let status_scroller = gtk4::ScrolledWindow::builder()
            .hexpand(true)
            .vexpand(true)
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .child(&connection_view.container)
            .build();

        let top_pane = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        top_pane.append(&status_scroller);
        top_pane.append(&connection_view.actions);

        // A resizable split rather than two boxes competing for leftover space:
        // the log used to expand freely and squeeze the status area until the
        // buttons were pushed out of sight.
        let paned = gtk4::Paned::builder()
            .orientation(gtk4::Orientation::Vertical)
            .vexpand(true)
            .build();
        paned.set_start_child(Some(&top_pane));
        paned.set_end_child(Some(&log_view.container));
        paned.set_position(420);
        paned.set_resize_start_child(true);
        paned.set_resize_end_child(true);
        // The status area is the one that must not be starved, so it keeps its
        // size and the log gives way instead.
        paned.set_shrink_start_child(false);
        paned.set_shrink_end_child(true);

        content.append(&paned);
        toolbar_view.set_content(Some(&content));

        // ── NM wiring ────────────────────────────────────────────────────
        // Callbacks cannot touch widgets (the sender must be `Send + Sync`), so
        // they publish the newest value and the GTK timer below draws it.

        {
            let state = state.clone();
            let on_state = GlibSender::new(move |new_state: VpnState| {
                *state.lock().expect("state lock poisoned") = new_state;
            });
            nm_bridge::watch_nm(&tokio_handle, on_state);
        }

        {
            let session = session.clone();
            let saved = saved.clone();
            let on_saved = GlibSender::new(move |list: Vec<SavedVpn>| {
                *saved.lock().expect("saved lock poisoned") = list;
            });

            let session_out = session.clone();
            let handle = tokio_handle.clone();
            let inner = handle.clone();
            handle.spawn(async move {
                match NmSession::open().await {
                    Ok(s) => {
                        let s = Arc::new(s);
                        *session_out.lock().expect("session lock poisoned") = Some(s.clone());
                        nm_bridge::watch_saved(&inner, s, on_saved);
                    }
                    Err(e) => error!("Cannot open a NetworkManager session: {e:#}"),
                }
            });
        }

        {
            let selected = selected.clone();
            dropdown.connect_selected_notify(move |dd| {
                selected.set(dd.selected() as usize);
            });
        }

        // ── Profile editing ───────────────────────────────────────────────
        // Every save goes to NetworkManager, so the app never holds a profile
        // the rest of the system cannot see.

        {
            let session = session.clone();
            let parent = window.clone();
            let handle = tokio_handle.clone();
            add_btn.connect_clicked(move |_| {
                let Some(nm) = session.lock().ok().and_then(|s| s.clone()) else {
                    error!("No NetworkManager session available");
                    return;
                };
                // Cloned per invocation: a click handler is `Fn`, so it may be
                // called again and cannot hand its captures away.
                let parent = parent.clone();
                let handle = handle.clone();
                profile_editor::show_editor(&parent, None, move |profile| {
                    let handle = handle.clone();
                    let nm = nm.clone();
                    handle.spawn(async move {
                        match nm.add(&profile).await {
                            Ok(path) => info!("Saved new connection {} at {path}", profile.name),
                            Err(e) => error!("Could not save {}: {e:#}", profile.name),
                        }
                    });
                });
            });
        }

        {
            let session = session.clone();
            let saved = saved.clone();
            let selected = selected.clone();
            let handle = tokio_handle.clone();
            let pending_edit = pending_edit.clone();
            edit_btn.connect_clicked(move |_| {
                let Some(nm) = session.lock().ok().and_then(|s| s.clone()) else {
                    error!("No NetworkManager session available");
                    return;
                };
                let target = saved
                    .lock()
                    .ok()
                    .and_then(|list| list.get(selected.get()).cloned());
                let Some(target) = target else {
                    error!("No connection selected to edit");
                    return;
                };

                // Reading the stored profile is D-Bus work and has to happen off
                // the GTK thread, but showing the form is widget work and cannot
                // leave it. So the load publishes here and the render timer below
                // picks it up — a GTK widget is not `Send`, so there is no way to
                // hand one to the async task.
                let pending = pending_edit.clone();
                let name = target.name.clone();
                handle.spawn(async move {
                    match nm.load(&target.path).await {
                        Ok(Some(profile)) => {
                            *pending.lock().expect("pending-edit lock poisoned") =
                                Some((profile, target.path));
                        }
                        Ok(None) => error!("{name} is not a DrayTek connection"),
                        Err(e) => error!("Could not read {name}: {e:#}"),
                    }
                });
            });
        }

        {
            let session = session.clone();
            let saved = saved.clone();
            let selected = selected.clone();
            let parent = window.clone();
            let handle = tokio_handle.clone();
            delete_btn.connect_clicked(move |_| {
                let Some(nm) = session.lock().ok().and_then(|s| s.clone()) else {
                    error!("No NetworkManager session available");
                    return;
                };
                let target = saved
                    .lock()
                    .ok()
                    .and_then(|list| list.get(selected.get()).cloned());
                let Some(target) = target else {
                    error!("No connection selected to delete");
                    return;
                };

                let parent = parent.clone();
                let name = target.name.clone();
                let for_delete = handle.clone();
                let shown = name.clone();
                profile_editor::confirm_delete(&parent, &shown, move || {
                    let handle = for_delete.clone();
                    let nm = nm.clone();
                    let path = target.path.clone();
                    let name = name.clone();
                    handle.spawn(async move {
                        if let Err(e) = nm.remove(&path).await {
                            error!("Could not delete {name}: {e:#}");
                        }
                    });
                });
            });
        }

        {
            let session = session.clone();
            let saved = saved.clone();
            let selected = selected.clone();
            let handle = tokio_handle.clone();
            connection_view.connect_btn.connect_clicked(move |_| {
                let vpn = {
                    let list = saved.lock().expect("saved lock poisoned");
                    list.get(selected.get()).cloned()
                };
                let Some(vpn) = vpn else {
                    error!("No DrayTek VPN connection selected");
                    return;
                };

                let session = session.lock().expect("session lock poisoned").clone();
                let Some(session) = session else {
                    error!("No NetworkManager session available");
                    return;
                };
                handle.spawn(async move {
                    if let Err(e) = session.activate(&vpn.path, &vpn.name).await {
                        error!("NetworkManager refused to activate {}: {e:#}", vpn.name);
                    }
                });
            });
        }

        {
            let session = session.clone();
            let state = state.clone();
            let handle = tokio_handle.clone();
            connection_view.disconnect_btn.connect_clicked(move |_| {
                let active = {
                    let current = state.lock().expect("state lock poisoned");
                    match &*current {
                        VpnState::Connected { path, name, .. } => {
                            Some((path.clone(), name.clone()))
                        }
                        _ => None,
                    }
                };
                let Some((path, name)) = active else {
                    error!("Disconnect pressed with no active DrayTek VPN");
                    return;
                };

                let session = session.lock().expect("session lock poisoned").clone();
                let Some(session) = session else {
                    error!("No NetworkManager session available");
                    return;
                };
                handle.spawn(async move {
                    info!("Requesting NetworkManager to deactivate {name}");
                    if let Err(e) = session.deactivate(&path).await {
                        error!("NetworkManager refused to deactivate {name}: {e:#}");
                    }
                });
            });
        }

        // Draw whatever NM last reported, and keep the uptime and counters
        // moving in between. The fingerprint check means a redraw happens on an
        // actual state change rather than twice a second.
        {
            let connection_view = connection_view.clone();
            let log_view = log_view.clone();
            let state = state.clone();
            let saved = saved.clone();
            let dropdown = dropdown.clone();
            let selected = selected.clone();
            let pending_edit = pending_edit.clone();
            let session = session.clone();
            let parent = window.clone();
            let handle = tokio_handle.clone();
            let mut last_drawn: Option<String> = None;
            let mut last_saved: Vec<String> = Vec::new();
            gtk4::glib::timeout_add_local(TICK_INTERVAL, move || {
                // A profile finished loading; present the form now that we are
                // back on the GTK thread.
                let pending = pending_edit.lock().ok().and_then(|mut slot| slot.take());
                if let Some((profile, path)) = pending {
                    let Some(nm) = session.lock().ok().and_then(|s| s.clone()) else {
                        error!("No NetworkManager session available");
                        return gtk4::glib::ControlFlow::Continue;
                    };
                    let parent = parent.clone();
                    let handle = handle.clone();
                    profile_editor::show_editor(&parent, Some(profile), move |edited| {
                        let handle = handle.clone();
                        let nm = nm.clone();
                        let path = path.clone();
                        handle.spawn(async move {
                            if let Err(e) = nm.update(&path, &edited).await {
                                error!("Could not save {}: {e:#}", edited.name);
                            }
                        });
                    });
                }

                let current = state.lock().expect("state lock poisoned").clone();
                let fingerprint = format!("{current:?}");
                if last_drawn.as_deref() != Some(fingerprint.as_str()) {
                    last_drawn = Some(fingerprint);
                    let view = StatusView::from(&current);
                    let failure = match &current {
                        VpnState::Failed { reason, .. } => Some(reason.as_str()),
                        _ => None,
                    };
                    connection_view.update_status(&view, failure);
                }

                // Rebuild the dropdown only when the names differ, so a poll
                // that found nothing new does not discard the user's selection.
                let names: Vec<String> = saved
                    .lock()
                    .expect("saved lock poisoned")
                    .iter()
                    .map(|v| v.name.clone())
                    .collect();
                if names != last_saved {
                    let keep = dropdown.selected() as usize;
                    last_saved = names.clone();
                    if !names.is_empty() {
                        let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
                        dropdown.set_model(Some(&gtk4::StringList::new(&borrowed)));
                        let idx = keep.min(names.len() - 1);
                        dropdown.set_selected(idx as u32);
                        selected.set(idx);
                    } else {
                        dropdown.set_model(Some(&gtk4::StringList::new(&[] as &[&str])));
                        dropdown.set_selected(gtk4::INVALID_LIST_POSITION);
                    }
                }

                connection_view.tick();
                log_view.refresh();
                gtk4::glib::ControlFlow::Continue
            });
        }

        window.set_content(Some(&toolbar_view));
        Self { window }
    }
}
