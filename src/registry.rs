//! Persistent user-created labels. This intentionally does not cache online
//! status, port results or credentials: each scan must provide fresh evidence.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, env, fs, io, net::Ipv4Addr, path::PathBuf};

use crate::{
    discovery::{Device, Scope},
    history,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraRole {
    #[default]
    Unreviewed,
    Possible,
    UserConfirmed,
    NotCamera,
}

impl CameraRole {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unreviewed => "Not reviewed",
            Self::Possible => "Possible camera (user)",
            Self::UserConfirmed => "Camera (user-confirmed)",
            Self::NotCamera => "Not a camera (user)",
        }
    }

    pub fn marked_camera(self) -> bool {
        matches!(self, Self::Possible | Self::UserConfirmed)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraApp {
    #[default]
    Unknown,
    Anran,
    VicoHome,
    Other,
    NoApp,
}

impl CameraApp {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Not identified",
            Self::Anran => "ANRAN (user)",
            Self::VicoHome => "VicoHome (user)",
            Self::Other => "Another app (user)",
            Self::NoApp => "No app / local (user)",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CameraMetadata {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub firmware: String,
    #[serde(default)]
    pub platform: String,
    /// Private, user-entered device identifier. Excluded from copied reports.
    #[serde(default)]
    pub serial: String,
}

impl CameraMetadata {
    pub fn cleaned(&self) -> Self {
        fn clean(input: &str, max: usize) -> String {
            input
                .trim()
                .chars()
                .filter(|ch| !ch.is_control())
                .take(max)
                .collect()
        }
        Self {
            model: clean(&self.model, 80),
            firmware: clean(&self.firmware, 80),
            platform: clean(&self.platform, 80),
            serial: clean(&self.serial, 120),
        }
    }
}

/// User assertions only. A saved profile never proves online status, physical
/// identity, ONVIF support, camera credentials, or a playable video stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CameraProfile {
    pub scope: String,
    pub identity: String,
    pub last_ip: Ipv4Addr,
    pub mac: Option<String>,
    pub role: CameraRole,
    pub app: CameraApp,
    #[serde(default)]
    pub metadata: CameraMetadata,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Registry {
    #[serde(default)]
    aliases: BTreeMap<String, String>,
    #[serde(default)]
    camera_profiles: BTreeMap<String, CameraProfile>,
}

impl CameraProfile {
    /// Editing a saved record requires no live scan. This placeholder contains
    /// identity only; it must never be put into the active discovery map.
    pub fn device_for_editing(&self) -> Device {
        let mut device = Device::new(self.last_ip);
        device.mac = self.mac.clone();
        device
    }
}

impl Registry {
    pub fn load() -> (Self, Option<String>) {
        let Some(path) = registry_path() else {
            return (
                Self::default(),
                Some("HOME and XDG_DATA_HOME are unset; labels will not persist".into()),
            );
        };
        match fs::read_to_string(&path) {
            Ok(data) => match serde_json::from_str(&data) {
                Ok(registry) => (registry, None),
                Err(error) => (
                    Self::default(),
                    Some(format!("Could not read label registry: {error}")),
                ),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => (Self::default(), None),
            Err(error) => (
                Self::default(),
                Some(format!("Could not load labels: {error}")),
            ),
        }
    }

    pub fn alias<'a>(&'a self, device: &Device) -> Option<&'a str> {
        let key = key(device);
        self.aliases.get(&key).map(String::as_str)
    }

    pub fn set_alias(&mut self, device: &Device, input: &str) -> io::Result<()> {
        let name: String = input.trim().chars().take(80).collect();
        let id = key(device);
        if name.is_empty() {
            self.aliases.remove(&id);
        } else {
            self.aliases.insert(id, name);
        }
        self.save()
    }

    pub fn camera_profile<'a>(
        &'a self,
        scope: &Scope,
        device: &Device,
    ) -> Option<&'a CameraProfile> {
        self.camera_profiles.get(&camera_key(scope, device))
    }

    pub fn camera_profiles_for_scope(&self, scope: &Scope) -> Vec<&CameraProfile> {
        let scope_id = history::scope_id(scope);
        let mut rows: Vec<_> = self
            .camera_profiles
            .values()
            .filter(|profile| profile.scope == scope_id)
            .collect();
        rows.sort_by_key(|profile| (profile.last_ip, profile.identity.clone()));
        rows
    }

    pub fn set_camera_profile(
        &mut self,
        scope: &Scope,
        device: &Device,
        role: CameraRole,
        app: CameraApp,
        metadata: &CameraMetadata,
    ) -> io::Result<()> {
        let id = camera_key(scope, device);
        let mut next = self.clone();
        let metadata = metadata.cleaned();
        if role == CameraRole::Unreviewed
            && app == CameraApp::Unknown
            && metadata == CameraMetadata::default()
        {
            next.camera_profiles.remove(&id);
        } else {
            next.camera_profiles.insert(
                id.clone(),
                CameraProfile {
                    scope: history::scope_id(scope),
                    identity: id,
                    last_ip: device.ip,
                    mac: device.mac.as_ref().map(|s| s.to_ascii_lowercase()),
                    role,
                    app,
                    metadata,
                },
            );
        }
        next.save()?;
        *self = next;
        Ok(())
    }

    fn save(&self) -> io::Result<()> {
        let path = registry_path()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME unavailable"))?;
        let dir = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Bad registry path"))?;
        fs::create_dir_all(dir)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        // Write into the same directory, then rename for an atomic update.
        let tmp = path.with_extension("json.tmp");
        // Camera serials are private local data; never leave registry writes
        // under the process umask's potentially world-readable default.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            use std::io::Write as _;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        fs::write(&tmp, bytes)?;
        fs::rename(tmp, path)
    }
}

fn camera_key(scope: &Scope, device: &Device) -> String {
    // Never silently migrate IP-only assertions to a later MAC discovery:
    // that could attach a camera identity to a reassigned DHCP lease.
    let identifier = match device.mac.as_deref() {
        Some(mac)
            if mac.len() == 17
                && mac != "00:00:00:00:00:00"
                && mac.split(':').count() == 6
                && mac.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') =>
        {
            format!("mac:{}", mac.to_ascii_lowercase())
        }
        _ => format!("ip:{}", device.ip),
    };
    format!("{}|{identifier}", history::scope_id(scope))
}

fn key(device: &Device) -> String {
    match device.mac.as_deref() {
        Some(mac) if mac != "00:00:00:00:00:00" => format!("mac:{}", mac.to_ascii_lowercase()),
        _ => format!("ip:{}", device.ip),
    }
}

fn registry_path() -> Option<PathBuf> {
    let base = env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))?;
    Some(base.join("ocularium").join("registry.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn scope(base: [u8; 3]) -> Scope {
        Scope {
            interface: "eno1".into(),
            local_ip: Ipv4Addr::new(base[0], base[1], base[2], 53),
            base,
        }
    }

    #[test]
    fn camera_profiles_are_mac_stable_and_scoped() {
        let mut registry = Registry::default();
        let mut first = Device::new(Ipv4Addr::new(192, 168, 0, 103));
        first.mac = Some("AA:BB:CC:DD:EE:FF".into());
        let a = scope([192, 168, 0]);
        let b = scope([192, 168, 1]);
        // Test insertion separately from disk persistence.
        let key = camera_key(&a, &first);
        registry.camera_profiles.insert(
            key.clone(),
            CameraProfile {
                scope: history::scope_id(&a),
                identity: key,
                last_ip: first.ip,
                mac: first.mac.clone(),
                role: CameraRole::UserConfirmed,
                app: CameraApp::Anran,
                metadata: CameraMetadata::default(),
            },
        );
        let mut moved = Device::new(Ipv4Addr::new(192, 168, 0, 199));
        moved.mac = Some("aa:bb:cc:dd:ee:ff".into());
        assert_eq!(
            registry.camera_profile(&a, &moved).unwrap().role,
            CameraRole::UserConfirmed
        );
        assert!(registry.camera_profile(&b, &moved).is_none());
        assert_eq!(registry.camera_profiles_for_scope(&a).len(), 1);
    }

    #[test]
    fn ip_fallback_cannot_silently_claim_new_mac() {
        let network = scope([192, 168, 0]);
        let first = Device::new(Ipv4Addr::new(192, 168, 0, 103));
        let mut later = first.clone();
        later.mac = Some("aa:bb:cc:dd:ee:ff".into());
        assert_ne!(camera_key(&network, &first), camera_key(&network, &later));
    }

    #[test]
    fn previous_label_registry_json_remains_readable() {
        let old = r#"{"aliases":{"mac:aa:bb:cc:dd:ee:ff":"Front gate"}}"#;
        let registry: Registry = serde_json::from_str(old).unwrap();
        assert!(registry.camera_profiles.is_empty());
        let json = serde_json::to_string(&registry).unwrap();
        let loaded: Registry = serde_json::from_str(&json).unwrap();
        assert!(loaded.camera_profiles.is_empty());
        assert_eq!(registry.aliases, loaded.aliases);
    }

    #[test]
    fn old_camera_profiles_load_without_metadata() {
        let old = r#"{"aliases":{},"camera_profiles":{"net|mac:aa:bb:cc:dd:ee:ff":{"scope":"net","identity":"net|mac:aa:bb:cc:dd:ee:ff","last_ip":"192.168.0.103","mac":"aa:bb:cc:dd:ee:ff","role":"user_confirmed","app":"vico_home"}}}"#;
        let registry: Registry = serde_json::from_str(old).unwrap();
        let profile = registry.camera_profiles.values().next().unwrap();
        assert_eq!(profile.metadata, CameraMetadata::default());
    }

    #[test]
    fn metadata_is_bounded_and_survives_json_round_trip() {
        let metadata = CameraMetadata {
            model: " CQ1F ".into(),
            firmware: "1.14.10".into(),
            platform: "device-v1".into(),
            serial: "example-private-serial".into(),
        };
        assert_eq!(metadata.cleaned().model, "CQ1F");
        assert_eq!(
            CameraMetadata {
                serial: "x".repeat(130),
                ..Default::default()
            }
            .cleaned()
            .serial
            .len(),
            120
        );
        let encoded = serde_json::to_string(&metadata).unwrap();
        let decoded: CameraMetadata = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, metadata);
    }
    #[test]
    fn saved_unreviewed_metadata_is_editable_without_live_discovery() {
        let scope = scope([192, 168, 0]);
        let mut registry = Registry::default();
        let mut device = Device::new(Ipv4Addr::new(192, 168, 0, 105));
        device.mac = Some("b4:61:e9:17:2c:0b".into());
        let identity = camera_key(&scope, &device);
        let profile = CameraProfile {
            scope: history::scope_id(&scope),
            identity: identity.clone(),
            last_ip: device.ip,
            mac: device.mac.clone(),
            role: CameraRole::Unreviewed,
            app: CameraApp::Unknown,
            metadata: CameraMetadata {
                model: "CQ1F".into(),
                ..Default::default()
            },
        };
        registry.camera_profiles.insert(identity, profile);
        let json = serde_json::to_string(&registry).unwrap();
        let reopened: Registry = serde_json::from_str(&json).unwrap();
        let records = reopened.camera_profiles_for_scope(&scope);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].role, CameraRole::Unreviewed);
        assert_eq!(records[0].metadata.model, "CQ1F");
        let editing_device = records[0].device_for_editing();
        assert_eq!(editing_device.ip, device.ip);
        assert_eq!(editing_device.mac, device.mac);
        assert!(editing_device.open_ports.is_empty());
        assert!(!editing_device.rtsp_responded);
        assert!(reopened.camera_profile(&scope, &editing_device).is_some());
    }

    #[test]
    fn uses_stable_mac_when_available() {
        let mut original = Device::new(Ipv4Addr::new(192, 168, 0, 103));
        original.mac = Some("AA:BB:CC:DD:EE:FF".into());
        let mut moved = Device::new(Ipv4Addr::new(192, 168, 0, 213));
        moved.mac = Some("aa:bb:cc:dd:ee:ff".into());
        assert_eq!(key(&original), key(&moved));
    }

    #[test]
    fn backwards_compatible_with_missing_aliases() {
        let registry: Registry = serde_json::from_str("{}").unwrap();
        let device = Device::new(Ipv4Addr::LOCALHOST);
        assert_eq!(registry.alias(&device), None);
    }
}
