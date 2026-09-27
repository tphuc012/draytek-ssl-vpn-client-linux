# DrayTek SSL VPN Client for Linux

Native Linux SSL VPN client for DrayTek routers. Same protocol as the Windows Smart VPN Client (TLS → HTTP CONNECT → SSTP → PPP).

## Workspace Layout

Cargo workspace with five members:

- `protocol/` — `draytek-vpn-protocol` lib: TLS connect, SSTP framing, PPP FSM, LCP/IPCP/auth (PAP + MS-CHAPv2), keepalive. Used by the VPN plugin.
- `networkmanager/` — `draytek-vpn-nm` VPN plugin on the system D-Bus (runs as root under NM). **The only component that builds a tunnel.** GTK3/GTK4 editor `.so` and auth-dialog are C (`networkmanager/editor/`, `networkmanager/auth-dialog/`). `networkmanager/src/tunnel.rs` is the data loop.
- `nmapi/` — `draytek-vpn-nmapi` lib: reading and driving NetworkManager's DrayTek VPN over D-Bus (`monitor_vpn`, `connect_vpn`, `disconnect_vpn`, `VpnState`). Shared by the two front ends.
- `standalone/` — `draytek-vpn` GTK4/libadwaita desktop app. A **front end for NM**: it lists NM's saved VPN connections, activates and deactivates them, and renders NM's reported state. It owns no tunnel, needs no privileges, and has no helper binary or polkit policy.
- `networkmanagertray/` — `draytek-vpn-tray` ksni StatusNotifier tray, the same front end in tray form. Watches NM over D-Bus (`nmapi`), renders via `tray_impl.rs`. Autostarts on session login via `networkmanagertray/data/draytek-vpn-tray.desktop` installed to `/etc/xdg/autostart/`. Single-instance via the well-known session-bus name `com.draytek.vpn.Tray` (DoNotQueue): second invocation exits cleanly.

### One connection path

There is exactly one way to establish a tunnel: NetworkManager's VPN plugin. The app and the tray both drive it over D-Bus. They do not negotiate, authenticate, create TUN devices, or install routes themselves.

This is load-bearing. When the app ran its own tunnel, it and NM each had a TUN device, credentials, and a DNS takeover, and they disagreed: the app reported "disconnected" while a tunnel was up under NM, and it offered to "clean up" a device NM was using. One path means one status, and the three front ends cannot drift apart.

## Build & Test

`build.sh` is the canonical build/install entry point. Do not invoke `cargo build` + `makepkg`/`cp` manually — `build.sh` handles distro detection (Debian multiarch vs Arch/Fedora), staging cleanup, and service restarts.

```bash
./build.sh app                  # standalone GTK4 app (debug)
./build.sh app release          # release build
./build.sh app install          # release + install the app and desktop entry
./build.sh nm release           # NM plugin + editor .so + auth-dialog
./build.sh nm install           # build + install + restart NetworkManager
./build.sh tray install         # tray indicator + autostart
./build.sh arch install         # Arch: makepkg -fCsi (clean staging, force, install)
./build.sh all install          # everything
./build.sh clean                # remove build artifacts
```

Packaging:

- Arch: `packaging/arch/PKGBUILD` → `draytek-vpn-standalone` + `draytek-vpn-networkmanager`
- Debian: `./build.sh app deb` / `./build.sh nm deb`
- AppImage: `./build.sh app appimage`

Release profile is defined at workspace root (`Cargo.toml`), not in any member crate — cargo ignores `[profile.*]` outside the workspace root.

### Running locally during development

```bash
./build.sh all install          # builds + installs everything; NM restarts itself
nmcli connection up <name>      # trigger the NM plugin; tray (already running via XDG autostart) shows status
journalctl -u NetworkManager -f # tail plugin logs
```

The standalone GUI is the fastest path for iterating on protocol changes — `./build.sh app run` builds debug and launches it with stderr logs in-terminal.

## Pre-push Checks

Run all three before committing/pushing any Rust changes — adopted from niri's CI standard:

```bash
cargo fmt --check && cargo clippy --all --all-targets && cargo test --all
```

All three must be clean. No warnings allowed in clippy output.

### No `#[allow(...)]` suppressions — code smell

Allow attributes paper over real design issues. When a lint fires, refactor the code honestly:

- `dead_code` → delete the unused code, or actually wire it up
- `too_many_arguments` → bundle args into a struct (see `PppFsmPair` / `TunnelAddrs` in `protocol/src/engine_common.rs`), or split the function
- `derivable_impls` → use `#[derive(Default)]` with `#[default]` on the variant
- any other lint → fix it, don't suppress

Only acceptable exception: the lint is provably wrong for a narrow specific reason, with a comment explaining why.

## Error Handling

Both the library (`protocol/`) and the binaries use `anyhow::Result` end-to-end. This is a deliberate trade-off: the library leaks `anyhow` to consumers, which is fine here because the only consumers are the two internal binaries. If `protocol/` ever grows third-party consumers, migrate its public surface to `thiserror`-derived error enums at that point. `thiserror` is intentionally not a dependency today — do not add it back without a concrete consumer.

## Known Gotchas

- **Compiled `.so` artifacts are tracked in git** (`networkmanager/editor/libnm-*.so`, `networkmanager/auth-dialog/nm-draytek-auth-dialog`). `build.sh` rewrites them in place on every NM build; they'll show as dirty in `git status` after any `./build.sh nm` run. Don't commit these incidentally unless the C sources changed.
- **C editor keys must match Rust `parse_settings`** — any new `vpn.data` key needs a matching `#define NM_DRAYTEK_KEY_*` in `networkmanager/editor/nm-draytek-editor.h` AND a read/write in the `.c` file AND a parser in `networkmanager/src/tunnel.rs::parse_settings`. Mismatches silently drop data.
- **NM plugin runs as root under NetworkManager**; stdin is closed and stderr goes to journald. Don't expect `println!` — use `tracing::{info,warn,error}!`.
- **`tokio::select!` macro hygiene** brings `std::pin::Pin` into scope inside its branches. Prefer a fully-qualified `std::pin::Pin::new(...)` at the call site so the behaviour doesn't depend on macro internals.
- **The VPN plugin is a D-Bus activated service and survives `systemctl restart NetworkManager`.** It holds the well-known name, so NM reconnects to the *old* process and the freshly installed `nm-draytek-service` is never loaded — a reinstall silently tests the previous build. `build.sh nm install` now `pkill`s leftovers first. After a manual install, verify with `ps -o pid,lstart,cmd -p "$(pgrep -f nm-draytek-service)"`: the start time must be *after* the install. Note the data-path binary is `/usr/lib/NetworkManager/nm-draytek-service` (7 MB), **not** `libnm-vpn-plugin-draytek.so` in `$NM_PLUGIN_DIR` (18 KB, the libnm capability shim) — checking the `.so` timestamp tells you nothing about whether the running code is current.
- **The two front ends are not allowed to become tunnel implementations.** If a change to `standalone/` needs a TUN device, a route, a DNS change or a credential store, it belongs in `networkmanager/` instead. The test is whether the app would still be correct when NM already has a DrayTek VPN up: if it would not, the app is doing something it should not.
- **The one-line log that tells you which build is live:** HEAD logs `VPN endpoint ... is reached via ...` on every connect. If it is absent from the journal, the running process predates the endpoint-pin work.

## Key Source Files

- `protocol/src/engine_common.rs` — `PppFsmPair`, `TunnelAddrs`, `DataLoopOptions`, `DataPlaneWitness`, `PingKeeper`, `TrafficStats`, shared helpers used by the plugin data loop
- `protocol/src/negotiate.rs` — PPP negotiation state machine driver (returns `NegotiationResult` to feed into the data loop)
- `protocol/src/protocol/fsm.rs` — generic PPP finite state machine (LCP/IPCP)
- `protocol/src/keepalive.rs` — `KeepaliveTracker`: 10s idle → REQUEST, 3 missed → disconnect
- `protocol/src/endpoint.rs` — probe and pin the VPN server's own route so the SSTP connection stays outside a full tunnel
- `networkmanager/src/tunnel.rs` — NM plugin data loop; emits NM D-Bus signals (`state_changed`, `config`, `ip4_config`)
- `networkmanager/src/plugin.rs` — `org.freedesktop.NetworkManager.VPN.Plugin` D-Bus interface
- `nmapi/src/lib.rs` — NM D-Bus observation and control shared by both front ends; `VpnState` flows over `tokio::sync::watch`
- `standalone/src/nm_bridge.rs` — bridges `nmapi` to the GTK main loop; polls `/sys/class/net/draytek0/statistics` for counters
- `standalone/src/messages.rs` — `StatusView`, the flat render model derived from NM state
- `standalone/src/ui/window.rs` — the window: dropdown of NM connections, connect/disconnect, render loop
- `networkmanagertray/src/tray_impl.rs` — ksni rendering of `VpnState` (icon, tooltip, menu, keepalive status display)
- `networkmanager/editor/nm-draytek-editor.c` — C editor plugin, GTK3/GTK4 variants built from the same sources

## Remotes

- `origin` — GitHub: `git@github.com:tphuc012/draytek-ssl-vpn-client-linux.git`

Push to `master`.

## Runtime Logs

- NM plugin (as root, spawned by NM): `journalctl -u NetworkManager -f` — the plugin's `tracing` output goes to NM's journal stream.
- Tray (user session, systemd-run scope): `journalctl --user -f` — filter by `_COMM=draytek-vpn-tray` if noisy.
- Standalone app: stderr in the launching terminal, or `~/.local/share/draytek-vpn/` logs if launched detached.
