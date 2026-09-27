//! Building and reading DrayTek VPN connection settings for NetworkManager.
//!
//! The key names here are the same ones `networkmanager/editor/nm-draytek-editor.c`
//! writes and `networkmanager/src/tunnel.rs::parse_settings` reads. All three have
//! to agree: a key added in one place and forgotten in another is silently
//! dropped, and a connection with no `gateway` or `username` fails to start with
//! an error that points nowhere near the typo.

use std::collections::HashMap;

use anyhow::{Context, Result};
use tracing::debug;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::Connection;

use crate::{SettingsConnectionProxy, SettingsProxy, ADD_TO_DISK, SERVICE_TYPE};

/// A DrayTek VPN connection, as the user fills it in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DraytekProfile {
    /// Connection name shown in NM and in the front ends.
    pub name: String,
    /// Router address: hostname or IP.
    pub gateway: String,
    /// SSL VPN port.
    pub port: u16,
    pub username: String,
    /// Left empty to keep whatever NM already has stored.
    pub password: String,
    /// Verify the router's TLS certificate. Off matches the router's own
    /// self-signed default, which is what the C editor assumes.
    pub verify_cert: bool,
    /// MRU to propose during LCP. 0 leaves the protocol default.
    pub mru: u16,
    /// Auto-route the router's own subnet.
    pub route_remote_network: bool,
    /// Take over the default route. Inverted to match NM's `never-default`.
    pub default_gateway: bool,
    /// Send periodic ICMP pings to stop the router idling the tunnel out.
    pub keepalive: bool,
    /// Extra subnets to route through the tunnel, CIDR, comma separated.
    pub routes: String,
}

/// Build one NM setting section from literal key/value pairs.
fn dict(pairs: Vec<(&str, Value<'_>)>) -> HashMap<String, OwnedValue> {
    pairs
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                OwnedValue::try_from(v).expect("NM setting values are primitives or string maps"),
            )
        })
        .collect()
}

/// `vpn.data` and `vpn.secrets` are `a{ss}` in NM's schema, not the `a{sv}` a
/// settings section uses. Sending the wrong inner type is rejected with
/// "can't set property of type 'a{ss}' from value of type 'a{sv}'", which says
/// nothing about where the mistake is.
fn nested_strings(section: HashMap<String, String>) -> OwnedValue {
    OwnedValue::from(section)
}

impl DraytekProfile {
    /// The `vpn.data` dictionary, in the shape the C editor produces.
    ///
    /// `password-flags` and `auto-reconnect` are included because NM writes them
    /// itself on existing connections; carrying them keeps an update from
    /// silently resetting them.
    fn vpn_data(&self) -> HashMap<String, String> {
        let mut data: HashMap<String, String> = HashMap::from([
            ("auto-reconnect".to_string(), "no".to_string()),
            ("gateway".to_string(), self.gateway.clone()),
            ("keepalive".to_string(), yes_no(self.keepalive).to_string()),
            ("mru".to_string(), self.mru.to_string()),
            (
                "never-default".to_string(),
                yes_no(!self.default_gateway).to_string(),
            ),
            ("password-flags".to_string(), "0".to_string()),
            ("port".to_string(), self.port.to_string()),
            (
                "route-remote-network".to_string(),
                yes_no(self.route_remote_network).to_string(),
            ),
            ("username".to_string(), self.username.clone()),
            (
                "verify-cert".to_string(),
                yes_no(self.verify_cert).to_string(),
            ),
        ]);
        // Optional keys are omitted rather than written empty: NM treats an
        // empty value as "present but blank", which is not the same as absent.
        let routes = self.routes.trim();
        if !routes.is_empty() {
            data.insert("routes".to_string(), routes.to_string());
        }
        data
    }

    /// A complete NM settings dictionary for this profile.
    pub fn to_settings(&self, uuid: &str) -> HashMap<String, HashMap<String, OwnedValue>> {
        let mut vpn = dict(vec![
            ("service-type", Value::from(SERVICE_TYPE)),
            ("persistent", Value::from(false)),
        ]);
        vpn.insert("data".to_string(), nested_strings(self.vpn_data()));

        // NM_SETTING_SECRET_FLAG_NONE: NM owns the secret and stores it with the
        // connection, the same as the C editor and every other NM VPN plugin.
        // The flag itself rides in `vpn.data` as `password-flags` — NMSettingVPN
        // has no `secrets-flags` property, and sending one is rejected outright.
        //
        // An empty password means "leave the stored one alone", so an edit of
        // some unrelated field does not wipe the credential.
        if !self.password.is_empty() {
            vpn.insert(
                "secrets".to_string(),
                nested_strings(HashMap::from([(
                    "password".to_string(),
                    self.password.clone(),
                )])),
            );
        }

        let mut settings: HashMap<String, HashMap<String, OwnedValue>> = HashMap::new();
        settings.insert(
            "connection".to_string(),
            dict(vec![
                ("id", Value::from(self.name.as_str())),
                ("uuid", Value::from(uuid)),
                ("type", Value::from("vpn")),
                // A VPN that autoconnects fights every other VPN on the machine
                // and can win a race it should not. Explicit connect only.
                ("autoconnect", Value::from(false)),
            ]),
        );
        // The plugin hands NM the addresses and routes, so the connection's own
        // IP config must not try to configure them.
        settings.insert(
            "ipv4".to_string(),
            dict(vec![("method", Value::from("auto"))]),
        );
        settings.insert(
            "ipv6".to_string(),
            dict(vec![("method", Value::from("ignore"))]),
        );
        settings.insert("vpn".to_string(), vpn);
        settings
    }

    /// Read a profile back out of an NM settings dictionary.
    ///
    /// Returns `None` for a connection that is not a DrayTek VPN, so a caller
    /// listing mixed connections can skip rather than show an empty form.
    pub fn from_settings(settings: &HashMap<String, HashMap<String, OwnedValue>>) -> Option<Self> {
        let vpn = settings.get("vpn")?;
        let service: String = vpn.get("service-type")?.clone().try_into().ok()?;
        if service != SERVICE_TYPE {
            return None;
        }

        let data = vpn_data_of(settings);
        let name = settings
            .get("connection")
            .and_then(|c| c.get("id"))
            .and_then(|v| v.clone().try_into().ok())
            .unwrap_or_default();

        // The password never comes back: NM returns it only to callers that pass
        // a GET_SECRETS flag, and a front end has no business asking.
        Some(Self {
            name,
            gateway: data.get("gateway").cloned().unwrap_or_default(),
            port: data
                .get("port")
                .and_then(|p| p.parse().ok())
                .unwrap_or(DEFAULT_PORT),
            username: data.get("username").cloned().unwrap_or_default(),
            password: String::new(),
            verify_cert: data.get("verify-cert").map(|v| v == "yes").unwrap_or(false),
            mru: data.get("mru").and_then(|m| m.parse().ok()).unwrap_or(0),
            route_remote_network: data
                .get("route-remote-network")
                .map(|v| v != "no")
                .unwrap_or(true),
            default_gateway: data
                .get("never-default")
                .map(|v| v == "no")
                .unwrap_or(false),
            keepalive: data.get("keepalive").map(|v| v == "yes").unwrap_or(false),
            routes: data.get("routes").cloned().unwrap_or_default(),
        })
    }
}

const DEFAULT_PORT: u16 = 443;

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn read_string_map(value: &OwnedValue) -> HashMap<String, String> {
    value.clone().try_into().unwrap_or_default()
}

/// Pull `vpn.data` out of a settings dictionary.
fn vpn_data_of(settings: &HashMap<String, HashMap<String, OwnedValue>>) -> HashMap<String, String> {
    settings
        .get("vpn")
        .and_then(|vpn| vpn.get("data"))
        .map(read_string_map)
        .unwrap_or_default()
}

// ── Settings operations ─────────────────────────────────────────────

async fn settings_proxy(conn: &Connection) -> Result<SettingsProxy<'_>> {
    SettingsProxy::builder(conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .context("Cannot reach NetworkManager settings")
}

/// Create a new DrayTek VPN connection, returning the path NM assigned it.
pub async fn add_profile(
    conn: &Connection,
    profile: &DraytekProfile,
    uuid: &str,
) -> Result<OwnedObjectPath> {
    validate(profile)?;
    let proxy = settings_proxy(conn).await?;
    let (path, _result) = proxy
        .add_connection2(profile.to_settings(uuid), ADD_TO_DISK, HashMap::new())
        .await
        .context("NetworkManager rejected the new connection")?;
    debug!("added DrayTek VPN connection {} at {path}", profile.name);
    Ok(path)
}

/// Replace an existing connection's settings.
pub async fn update_profile(
    conn: &Connection,
    path: &OwnedObjectPath,
    profile: &DraytekProfile,
) -> Result<()> {
    validate(profile)?;
    let proxy = connection_proxy(conn, path).await?;
    let existing = proxy.get_settings().await.unwrap_or_default();

    // The uuid is not in the form, so carry the existing one over: NM rejects an
    // update that changes a connection's identity.
    let mut settings = profile.to_settings("");
    let uuid: String = existing
        .get("connection")
        .and_then(|c| c.get("uuid"))
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default();
    if let Some(connection) = settings.get_mut("connection") {
        connection.insert(
            "uuid".to_string(),
            OwnedValue::try_from(Value::from(uuid))
                .expect("uuid is a string, so the conversion cannot fail"),
        );
    }
    // An empty password must not clear the stored secret, so re-send whatever NM
    // already holds rather than sending no secret at all.
    if profile.password.is_empty() {
        if let Some(vpn) = settings.get_mut("vpn") {
            if !vpn.contains_key("secrets") {
                let secrets = existing.get("vpn").and_then(|v| v.get("secrets")).cloned();
                match secrets {
                    Some(s) => {
                        vpn.insert("secrets".to_string(), s);
                    }
                    None => {
                        vpn.remove("secrets");
                    }
                }
            }
        }
    }

    proxy
        .update(settings)
        .await
        .context("NetworkManager rejected the updated connection")?;
    debug!("updated DrayTek VPN connection {}", profile.name);
    Ok(())
}

/// Delete a connection.
pub async fn delete_profile(conn: &Connection, path: &OwnedObjectPath) -> Result<()> {
    connection_proxy(conn, path)
        .await?
        .delete()
        .await
        .context("NetworkManager refused to delete the connection")?;
    Ok(())
}

async fn connection_proxy<'a>(
    conn: &'a Connection,
    path: &'a OwnedObjectPath,
) -> Result<SettingsConnectionProxy<'a>> {
    SettingsConnectionProxy::builder(conn)
        .path(path.as_ref())
        .context("Invalid connection path")?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .context("Cannot reach the connection")
}

/// Read one connection's settings back.
pub async fn load_profile(
    conn: &Connection,
    path: &OwnedObjectPath,
) -> Result<Option<DraytekProfile>> {
    let settings = connection_proxy(conn, path)
        .await?
        .get_settings()
        .await
        .context("Cannot read settings")?;
    Ok(DraytekProfile::from_settings(&settings))
}

/// Reject a profile NM would accept but the plugin could not use.
///
/// The plugin's own parser only reports "Missing 'gateway' in vpn.data", which
/// arrives long after the connection is saved and reads as a plugin bug. Catching
/// it here names the field.
fn validate(profile: &DraytekProfile) -> Result<()> {
    if profile.name.trim().is_empty() {
        anyhow::bail!("Connection name is required");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> DraytekProfile {
        DraytekProfile {
            name: "Office".to_string(),
            gateway: "117.2.126.196".to_string(),
            port: 4430,
            username: "alice".to_string(),
            password: "hunter2".to_string(),
            verify_cert: false,
            mru: 0,
            route_remote_network: true,
            default_gateway: true,
            keepalive: true,
            routes: "10.0.0.0/8, 192.168.5.0/24".to_string(),
        }
    }

    /// The keys are a contract with two other places: the C editor writes them
    /// and the plugin parses them. A renamed key is silently ignored, so the
    /// round trip is asserted against the literal strings.
    #[test]
    fn settings_carry_every_key_the_plugin_reads() {
        let settings = profile().to_settings("some-uuid");
        let data = vpn_data_of(&settings);

        for key in [
            "gateway",
            "port",
            "username",
            "mru",
            "route-remote-network",
            "never-default",
            "keepalive",
            "verify-cert",
            "routes",
        ] {
            assert!(data.contains_key(key), "vpn.data is missing {key}");
        }
        assert_eq!(data["gateway"], "117.2.126.196");
        assert_eq!(data["port"], "4430");
        assert_eq!(data["username"], "alice");
    }

    /// The plugin's default is `never-default = yes`, and the connection type
    /// must be `vpn` or NM will not hand it to the plugin at all.
    #[test]
    fn connection_is_shaped_for_the_vpn_plugin() {
        let settings = profile().to_settings("some-uuid");

        let service: String = settings["vpn"]
            .get("service-type")
            .expect("service-type")
            .clone()
            .try_into()
            .expect("service-type is a string");
        assert_eq!(service, SERVICE_TYPE);

        let kind: String = settings["connection"]
            .get("type")
            .expect("type")
            .clone()
            .try_into()
            .expect("type is a string");
        assert_eq!(kind, "vpn");
    }

    /// `never-default` is the inverse of the switch the user flips, and getting
    /// it backwards turns a full tunnel into a split one with no visible cause.
    #[test]
    fn default_gateway_is_the_inverse_of_never_default() {
        let mut full = profile();
        full.default_gateway = true;
        let data = vpn_data_of(&full.to_settings("u"));
        assert_eq!(data["never-default"], "no");

        full.default_gateway = false;
        let data = vpn_data_of(&full.to_settings("u"));
        assert_eq!(data["never-default"], "yes");
    }

    /// The secret flag travels as `password-flags` inside `vpn.data`.
    /// `NMSettingVPN` has no `secrets-flags` property at all, and NM rejects the
    /// whole settings dictionary when it sees one.
    #[test]
    fn secret_flags_travel_in_vpn_data() {
        let settings = profile().to_settings("u");
        let data = vpn_data_of(&settings);
        assert_eq!(data.get("password-flags").map(String::as_str), Some("0"));
        assert!(
            !settings["vpn"].contains_key("secrets-flags"),
            "NMSettingVPN rejects an unknown secrets-flags property"
        );
    }

    /// An empty route list must be absent, not present-and-blank: NM treats the
    /// two differently and a blank `routes` value confuses the plugin's parser.
    #[test]
    fn empty_routes_are_omitted() {
        let mut p = profile();
        p.routes = "  ".to_string();
        let settings = p.to_settings("u");
        let data = vpn_data_of(&settings);
        assert!(!data.contains_key("routes"));
    }

    /// Editing an unrelated field must not wipe the stored password, so an empty
    /// password produces no secret at all and the caller re-sends the old one.
    #[test]
    fn empty_password_sends_no_secret() {
        let mut p = profile();
        p.password = String::new();
        let settings = p.to_settings("u");
        assert!(!settings["vpn"].contains_key("secrets"));
        // The flag must still be there, or NM stops asking for a secret at all.
        assert!(vpn_data_of(&settings).contains_key("password-flags"));
    }

    /// What NM hands back must reproduce the profile, or an edit form would show
    /// blank fields for a connection that is perfectly configured.
    #[test]
    fn profile_round_trips_through_nm_settings() {
        let original = profile();
        let settings = original.to_settings("u");
        let parsed = DraytekProfile::from_settings(&settings).expect("should parse");

        assert_eq!(parsed.name, original.name);
        assert_eq!(parsed.gateway, original.gateway);
        assert_eq!(parsed.port, original.port);
        assert_eq!(parsed.username, original.username);
        assert_eq!(parsed.verify_cert, original.verify_cert);
        assert_eq!(parsed.mru, original.mru);
        assert_eq!(parsed.route_remote_network, original.route_remote_network);
        assert_eq!(parsed.default_gateway, original.default_gateway);
        assert_eq!(parsed.keepalive, original.keepalive);
        assert_eq!(parsed.routes, original.routes);
        // NM never hands the secret back, and the form must not pretend to.
        assert!(parsed.password.is_empty());
    }

    #[test]
    fn non_draytek_connections_are_skipped() {
        let mut settings = profile().to_settings("u");
        let vpn = settings.get_mut("vpn").expect("vpn");
        vpn.insert(
            "service-type".to_string(),
            dict(vec![(
                "service-type",
                Value::from("org.freedesktop.NetworkManager.openvpn"),
            )])["service-type"]
                .clone(),
        );
        assert!(DraytekProfile::from_settings(&settings).is_none());
    }

    /// A missing gateway or username is the plugin's most confusing failure, so
    /// it has to be caught before the connection is ever saved.
    #[test]
    fn incomplete_profiles_are_rejected_with_a_reason() {
        let mut p = profile();
        p.gateway = String::new();
        assert!(validate(&p).is_err_and(|e| e.to_string().contains("Server")));

        let mut p = profile();
        p.username = String::new();
        assert!(validate(&p).is_err_and(|e| e.to_string().contains("Username")));

        let mut p = profile();
        p.name = String::new();
        assert!(validate(&p).is_err_and(|e| e.to_string().contains("name")));
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::uuid_v4;

    /// NM is the only thing that can tell us the settings dictionary is right.
    /// A unit test proves the keys are spelled consistently with the plugin; only
    /// a real `AddConnection2` proves NM accepts the shape, the section names and
    /// the value types together.
    ///
    /// Ignored by default because it talks to the running NetworkManager and
    /// creates a real connection. Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "creates a real NetworkManager connection"]
    async fn networkmanager_accepts_and_returns_the_profile() {
        let Ok(conn) = Connection::system().await else {
            eprintln!("skipping: no system bus");
            return;
        };

        let profile = DraytekProfile {
            name: format!("draytek-selftest-{}", std::process::id()),
            gateway: "203.0.113.1".to_string(),
            port: 4430,
            username: "selftest".to_string(),
            password: "selftest".to_string(),
            route_remote_network: true,
            default_gateway: true,
            keepalive: true,
            routes: "10.10.0.0/16".to_string(),
            ..Default::default()
        };

        let uuid = uuid_v4();
        let path = add_profile(&conn, &profile, &uuid)
            .await
            .expect("NM should accept the settings");

        let loaded = load_profile(&conn, &path)
            .await
            .expect("should read back")
            .expect("should be a DrayTek profile");

        assert_eq!(loaded.name, profile.name);
        assert_eq!(loaded.gateway, profile.gateway);
        assert_eq!(loaded.port, profile.port);
        assert_eq!(loaded.username, profile.username);
        assert!(loaded.default_gateway);
        assert!(loaded.keepalive);
        assert_eq!(loaded.routes, profile.routes);

        // An update must not disturb the stored secret when the field is left
        // blank — the case an edit form hits on every unrelated change.
        let mut edited = loaded.clone();
        edited.port = 8443;
        update_profile(&conn, &path, &edited)
            .await
            .expect("update should be accepted");
        let reloaded = load_profile(&conn, &path)
            .await
            .expect("should read back")
            .expect("still a DrayTek profile");
        assert_eq!(reloaded.port, 8443);

        delete_profile(&conn, &path)
            .await
            .expect("delete should work");
    }
}
