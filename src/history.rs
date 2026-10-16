//! Local, persistent history of completed discovery scans.
//!
//! Historical sightings do not prove that a device is currently online.
//! No camera credentials, streams, or private inspection replies are stored.
use std::{
    collections::{BTreeMap, HashSet},
    env, fs, io,
    net::Ipv4Addr,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{classify, discovery::{Device, Scope}};

const FORMAT_VERSION: u32 = 1;
const MAX_ENTRIES: usize = 1024;
const MAX_SCANS: usize = 60;
const MAX_IPS: usize = 12;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceHistory {
    pub scope: String,
    pub identity: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub seen_scans: u32,
    pub last_scan_id: u64,
    pub mac: Option<String>,
    pub ips: Vec<Ipv4Addr>,
    pub vendor: Option<String>,
    pub label_hint: Option<String>,
    pub last_classification: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanHistory {
    pub id: u64,
    pub scope: String,
    pub timestamp: u64,
    pub found: usize,
    pub first_seen: usize,
    pub ip_changes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryStore {
    version: u32,
    next_scan_id: u64,
    entries: BTreeMap<String, DeviceHistory>,
    scans: Vec<ScanHistory>,
    #[serde(skip)]
    read_only: bool,
}

impl Default for HistoryStore {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            next_scan_id: 1,
            entries: BTreeMap::new(),
            scans: Vec::new(),
            read_only: false,
        }
    }
}

pub fn scope_id(scope: &Scope) -> String {
    format!(
        "{}:{}.{}.{}.0/24",
        scope.interface, scope.base[0], scope.base[1], scope.base[2]
    )
}

fn valid_mac(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 || !parts.iter().all(|part| {
        part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return None;
    }
    let canonical = parts.join(":").to_ascii_lowercase();
    (canonical != "00:00:00:00:00:00" && canonical != "ff:ff:ff:ff:ff:ff")
        .then_some(canonical)
}

fn identity(scope: &Scope, device: &Device) -> String {
    let scope = scope_id(scope);
    match device.mac.as_deref().and_then(valid_mac) {
        Some(mac) => format!("{scope}|mac:{mac}"),
        None => format!("{scope}|ip:{}", device.ip),
    }
}

fn name_hint(device: &Device) -> Option<String> {
    device.identities.iter()
        .find_map(|id| id.friendly_name.as_deref().or(id.model.as_deref()))
        .or_else(|| device.router_dns_names.first().map(String::as_str))
        .or_else(|| device.mdns_names.first().map(String::as_str))
        .map(|name| name.chars().take(160).collect())
}

fn file_path() -> Option<PathBuf> {
    let base = env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))?;
    Some(base.join("ocularium").join("history.json"))
}

impl HistoryStore {
    pub fn load() -> (Self, Option<String>) {
        let Some(path) = file_path() else {
            return (
                Self::default(),
                Some("HOME / XDG_DATA_HOME is unavailable; scan history cannot be saved".into()),
            );
        };
        match fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Self>(&text) {
                Ok(mut state) if state.version == FORMAT_VERSION => {
                    state.read_only = false;
                    (state, None)
                }
                Ok(mut state) => {
                    state.read_only = true;
                    let version = state.version;
                    (state, Some(format!(
                        "Unsupported history format v{version}; history is read-only until upgraded"
                    )))
                }
                Err(error) => {
                    let state = Self { read_only: true, ..Self::default() };
                    (state, Some(format!(
                        "Could not parse device history; refusing to overwrite it: {error}"
                    )))
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => (Self::default(), None),
            Err(error) => {
                let state = Self { read_only: true, ..Self::default() };
                (state, Some(format!("Cannot read device history (read-only): {error}")))
            }
        }
    }

    pub fn latest_scan(&self, scope: &Scope) -> Option<&ScanHistory> {
        let id = scope_id(scope);
        self.scans.iter().rev().find(|scan| scan.scope == id)
    }

    pub fn known_count(&self, scope: &Scope) -> usize {
        let scope = scope_id(scope);
        self.entries.values().filter(|entry| entry.scope == scope).count()
    }

    pub fn not_seen(&self, scope: &Scope) -> Vec<&DeviceHistory> {
        let Some(latest) = self.latest_scan(scope) else {
            return Vec::new();
        };
        let mut missing: Vec<_> = self.entries.values()
            .filter(|entry| entry.scope == latest.scope && entry.last_scan_id != latest.id)
            .collect();
        missing.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        missing
    }

    pub fn record(&self, scope: &Scope, device: &Device) -> Option<&DeviceHistory> {
        self.entries.get(&identity(scope, device))
    }

    pub fn record_completed_scan(
        &mut self,
        scope: &Scope,
        devices: &BTreeMap<Ipv4Addr, Device>,
        timestamp: u64,
    ) -> io::Result<ScanHistory> {
        if self.read_only {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "History file is read-only; existing data was left unchanged"));
        }
        let mut updated = self.clone();
        let scan = updated.ingest_completed_scan(scope, devices, timestamp);
        updated.save()?;
        *self = updated;
        Ok(scan)
    }

    // Pure in-memory transition, also used by unit tests. Filesystem changes
    // happen only after the updated snapshot is ready for atomic replacement.
    fn ingest_completed_scan(
        &mut self,
        scope: &Scope,
        devices: &BTreeMap<Ipv4Addr, Device>,
        timestamp: u64,
    ) -> ScanHistory {
        let scope_name = scope_id(scope);
        let id = self.next_scan_id;
        self.next_scan_id = self.next_scan_id.saturating_add(1);
        let mut new_count = 0;
        let mut changed_count = 0;
        let mut visited = HashSet::new();

        for device in devices.values() {
            if !scope.contains(device.ip) {
                continue;
            }
            let key = identity(scope, device);
            let mac = device.mac.as_deref().and_then(valid_mac);
            let class = classify::classify(device).label.to_owned();
            let label = name_hint(device);
            if let Some(entry) = self.entries.get_mut(&key) {
                if !entry.ips.contains(&device.ip) {
                    changed_count += 1;
                    if entry.ips.len() == MAX_IPS {
                        entry.ips.remove(0);
                    }
                    entry.ips.push(device.ip);
                }
                if visited.insert(key.clone()) {
                    entry.seen_scans = entry.seen_scans.saturating_add(1);
                }
                entry.last_seen = timestamp;
                entry.last_scan_id = id;
                if device.vendor.is_some() {
                    entry.vendor = device.vendor.clone();
                }
                if label.is_some() {
                    entry.label_hint = label;
                }
                entry.last_classification = class;
            } else {
                new_count += 1;
                visited.insert(key.clone());
                self.entries.insert(key.clone(), DeviceHistory {
                    scope: scope_name.clone(),
                    identity: key,
                    first_seen: timestamp,
                    last_seen: timestamp,
                    seen_scans: 1,
                    last_scan_id: id,
                    mac,
                    ips: vec![device.ip],
                    vendor: device.vendor.clone(),
                    label_hint: label,
                    last_classification: class,
                });
            }
        }

        // A bounded history avoids turning long-running desktop usage into an
        // unbounded, secretly growing database.
        while self.entries.len() > MAX_ENTRIES {
            if let Some(oldest) = self.entries.iter()
                .min_by_key(|(_, value)| (value.last_seen, value.first_seen))
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        let scan = ScanHistory {
            id, scope: scope_name,
            timestamp, found: devices.len(),
            first_seen: new_count, ip_changes: changed_count,
        };
        self.scans.push(scan.clone());
        if self.scans.len() > MAX_SCANS {
            self.scans.drain(..self.scans.len() - MAX_SCANS);
        }
        scan
    }

    pub fn entries_for_scope(&self, scope: &Scope) -> Vec<&DeviceHistory> {
        let scope_name = scope_id(scope);
        let mut rows: Vec<_> = self.entries.values()
            .filter(|entry| entry.scope == scope_name)
            .collect();
        rows.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        rows
    }

    fn save(&self) -> io::Result<()> {
        let path = file_path().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Cannot resolve history directory")
        })?;
        let directory = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid history path")
        })?;
        fs::create_dir_all(directory)?;
        let data = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let temp_path = path.with_extension("json.tmp");
        fs::write(&temp_path, data)?;
        fs::rename(temp_path, path)
    }

    pub fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default().as_secs()
    }
}

pub fn display_time(seconds: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds as i64, 0)
        .map(|value| value.with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "Unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn scope() -> Scope {
        Scope {
            interface: "eno1".into(),
            local_ip: Ipv4Addr::new(192, 168, 0, 53),
            base: [192, 168, 0],
        }
    }

    fn with_devices(items: &[(&str, Option<&str>)]) -> BTreeMap<Ipv4Addr, Device> {
        items.iter().map(|(ip, mac)| {
            let address: Ipv4Addr = ip.parse().unwrap();
            let mut device = Device::new(address);
            device.mac = mac.map(str::to_owned);
            (address, device)
        }).collect()
    }

    #[test]
    fn tracking_is_mac_stable_across_ip_changes() {
        let mut history = HistoryStore::default();
        let first = with_devices(&[("192.168.0.100", Some("aa:bb:cc:dd:ee:ff"))]);
        let second = with_devices(&[("192.168.0.120", Some("AA:BB:CC:DD:EE:FF"))]);
        history.ingest_completed_scan(&scope(), &first, 100);
        let scan_two = history.ingest_completed_scan(&scope(), &second, 200);
        assert_eq!(scan_two.ip_changes, 1);
        let record = history.record(&scope(), second.values().next().unwrap()).unwrap();
        assert_eq!(record.first_seen, 100);
        assert_eq!(record.last_seen, 200);
        assert_eq!(record.seen_scans, 2);
        assert_eq!(record.ips.len(), 2);
    }

    #[test]
    fn not_observed_is_not_offline() {
        let mut store = HistoryStore::default();
        let devices = with_devices(&[("192.168.0.103", Some("aa:bb:cc:dd:ee:ff"))]);
        store.ingest_completed_scan(&scope(), &devices, 100);
        store.ingest_completed_scan(&scope(), &BTreeMap::new(), 200);
        assert_eq!(store.not_seen(&scope()).len(), 1);
        assert_eq!(store.not_seen(&scope())[0].last_seen, 100);
    }

    #[test]
    fn rejects_invalid_mac_and_isolates_ip_fallback_by_scope() {
        let device = with_devices(&[("192.168.0.103", Some("00:00:00:00:00:00"))]);
        let device = device.values().next().unwrap();
        assert!(identity(&scope(), device).contains("|ip:"));
        assert!(valid_mac("not a mac").is_none());
    }

    #[test]
    fn serializes_history_in_versioned_format() {
        let value = serde_json::to_string(&HistoryStore::default()).unwrap();
        let loaded: HistoryStore = serde_json::from_str(&value).unwrap();
        assert_eq!(loaded.version, FORMAT_VERSION);
    }
}
