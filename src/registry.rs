//! Persistent user-created labels. This intentionally does not cache online
//! status, port results or credentials: each scan must provide fresh evidence.
use std::{collections::BTreeMap, env, fs, io, path::PathBuf};
use serde::{Deserialize, Serialize};

use crate::discovery::Device;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Registry {
    #[serde(default)]
    aliases: BTreeMap<String, String>,
}

impl Registry {
    pub fn load() -> (Self, Option<String>) {
        let Some(path) = registry_path() else {
            return (Self::default(), Some("HOME and XDG_DATA_HOME are unset; labels will not persist".into()));
        };
        match fs::read_to_string(&path) {
            Ok(data) => match serde_json::from_str(&data) {
                Ok(registry) => (registry, None),
                Err(error) => (Self::default(), Some(format!("Could not read label registry: {error}"))),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => (Self::default(), None),
            Err(error) => (Self::default(), Some(format!("Could not load labels: {error}"))),
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

    fn save(&self) -> io::Result<()> {
        let path = registry_path().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME unavailable"))?;
        let dir = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Bad registry path"))?;
        fs::create_dir_all(dir)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        // Write into the same directory, then rename for an atomic update.
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(tmp, path)
    }
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

    #[test]
    fn uses_stable_mac_when_available() {
        let mut original = Device::new(Ipv4Addr::new(192,168,0,103));
        original.mac = Some("AA:BB:CC:DD:EE:FF".into());
        let mut moved = Device::new(Ipv4Addr::new(192,168,0,213));
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
