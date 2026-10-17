//! Normalization of an *authenticated* Meari-family device-list response.
//! Offline only: no HTTP, login, account secrets on disk, raw payload UI or
//! camera connectivity. Source research: MIT-licensed
//! github.com/raulrojas22/Ha-CloudPlus-Meari-ANRAN
//! custom_components/cloudplus/api.py, _collect_devices_from_payload.

use std::collections::BTreeMap;
use crate::meari_vvp::Transport;

const MAX_JSON_BYTES: usize = 512 * 1024;
const MAX_RECORDS: usize = 64;
const MAX_DEPTH: usize = 14;
const MAX_VALUE_BYTES: usize = 256;

/// Camera account material stays in process memory. Intentionally no Debug,
/// Serialize, or persistent store: these fields can include credentials.
pub struct AuthorizedCamera {
    pub device_id: String,
    pub serial: String,
    pub category: Category,
    pub transport: Transport,
    pub host_key: Option<String>,
    pub device_uuid: Option<String>,
    pub p2p_init: Option<String>,
    pub mac: Option<String>,
}

impl AuthorizedCamera {
    pub fn matches_mac(&self, candidate: &str) -> bool {
        self.mac.as_deref().zip(normalize_mac(candidate).as_deref())
            .is_some_and(|(a, b)| a == b)
    }

    fn completeness(&self) -> u8 {
        u8::from(self.transport != Transport::Unknown)
            + u8::from(self.host_key.is_some())
            + u8::from(self.p2p_init.is_some())
            + u8::from(self.mac.is_some())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Wired,
    Battery,
    Doorbell,
    OtherCamera,
}

/// Redacted counts only, with no device identity, MAC, account or key data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogSummary {
    pub cameras: usize,
    pub wired: usize,
    pub battery: usize,
    pub doorbells: usize,
    pub ppcs: usize,
    pub signaling: usize,
    pub transport_unverified: usize,
}

impl CatalogSummary {
    pub fn safe_text(self) -> String {
        format!(
            "Authorized catalog (memory only): {} cameras, wired={}, battery={}, doorbells={}, PPCS={}, signaling={}, unknown transport={}. No video verified.",
            self.cameras, self.wired, self.battery, self.doorbells,
            self.ppcs, self.signaling, self.transport_unverified
        )
    }
}

/// Never derive Debug or Serialize on this type. Account records may contain
/// ephemeral host keys and transport bootstrap material.
pub struct AuthorizedCatalog {
    records: Vec<AuthorizedCamera>,
}

impl AuthorizedCatalog {
    pub fn cameras(&self) -> &[AuthorizedCamera] { &self.records }

    pub fn by_mac(&self, mac: &str) -> Option<&AuthorizedCamera> {
        self.records.iter().find(|camera| camera.matches_mac(mac))
    }

    pub fn summary(&self) -> CatalogSummary {
        let mut summary = CatalogSummary {
            cameras: self.records.len(), wired: 0, battery: 0, doorbells: 0,
            ppcs: 0, signaling: 0, transport_unverified: 0,
        };
        for record in &self.records {
            match record.category {
                Category::Wired => summary.wired += 1,
                Category::Battery => summary.battery += 1,
                Category::Doorbell => summary.doorbells += 1,
                Category::OtherCamera => {}
            }
            match record.transport {
                Transport::Ppcs => summary.ppcs += 1,
                Transport::Signaling => summary.signaling += 1,
                Transport::Unknown => summary.transport_unverified += 1,
            }
        }
        summary
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogError {
    Oversized,
    InvalidJson,
    NotAuthenticated,
    TemporarilyUnavailable,
    TooManyCameras,
}

fn bounded_value(v: Option<&serde_json::Value>) -> Option<String> {
    let value = match v? {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => return None,
    };
    (!value.is_empty() && value.len() <= MAX_VALUE_BYTES).then_some(value)
}

fn normalize_mac(raw: &str) -> Option<String> {
    let octets = raw.split(':')
        .map(|chunk| if chunk.len() == 2 {
            u8::from_str_radix(chunk, 16).ok()
        } else {
            None
        }).collect::<Option<Vec<_>>>()?;
    if octets.len() != 6 || octets.iter().all(|n| *n == 0)
        || octets.iter().all(|n| *n == 255) || octets[0] & 1 != 0
    {
        return None;
    }
    Some(octets.iter().map(|n| format!("{n:02x}")).collect::<Vec<_>>().join(":"))
}

fn category_for(key: &str) -> Option<Category> {
    match key.to_ascii_lowercase().as_str() {
        "ipc" => Some(Category::Wired),
        "snap" => Some(Category::Battery),
        "doorbell" | "voicebell" | "picturedoorbell" => Some(Category::Doorbell),
        "fourthgeneration" | "cellular" | "light" => Some(Category::OtherCamera),
        _ => None,
    }
}

fn parse_device(value: &serde_json::Value, category: Option<Category>) -> Option<AuthorizedCamera> {
    let obj = value.as_object()?;
    let device_id = bounded_value(obj.get("deviceID"))?;
    let serial = bounded_value(obj.get("snNum"))?;
    let category = category.unwrap_or_else(|| {
        if obj.get("devTypeID").and_then(serde_json::Value::as_i64) == Some(5) {
            Category::Battery
        } else {
            Category::Wired
        }
    });
    let mac = ["mac", "macAddr", "macAddress"].iter()
        .filter_map(|key| obj.get(*key).and_then(serde_json::Value::as_str))
        .find_map(normalize_mac);
    Some(AuthorizedCamera {
        device_id, serial, category,
        transport: Transport::from_device_record(value),
        host_key: bounded_value(obj.get("hostKey")),
        device_uuid: bounded_value(obj.get("deviceUUID")),
        p2p_init: bounded_value(obj.get("p2pInitApp"))
            .or_else(|| bounded_value(obj.get("p2pInit"))),
        mac,
    })
}

fn insert_camera(
    value: &serde_json::Value,
    category: Option<Category>,
    output: &mut BTreeMap<String, AuthorizedCamera>,
) -> Result<(), CatalogError> {
    if let Some(record) = parse_device(value, category) {
        // Duplicate owner/shared-home entries: retain richer session data
        // only when deviceID is identical. Never cross-merge different IDs.
        let replace = output.get(&record.device_id)
            .is_none_or(|prev| record.completeness() > prev.completeness());
        if replace {
            output.insert(record.device_id.clone(), record);
        }
        if output.len() > MAX_RECORDS { return Err(CatalogError::TooManyCameras); }
    }
    Ok(())
}

fn collect(
    node: &serde_json::Value,
    category: Option<Category>,
    depth: usize,
    out: &mut BTreeMap<String, AuthorizedCamera>,
) -> Result<(), CatalogError> {
    if depth > MAX_DEPTH { return Err(CatalogError::InvalidJson); }
    match node {
        serde_json::Value::Array(items) => {
            for value in items { collect(value, category, depth + 1, out)?; }
        }
        serde_json::Value::Object(fields) => {
            for (name, child) in fields {
                if let Some(cat) = category_for(name) {
                    if let Some(items) = child.as_array() {
                        for item in items { insert_camera(item, Some(cat), out)?; }
                    }
                } else if name == "deviceList" {
                    if let Some(items) = child.as_array() {
                        for item in items { insert_camera(item, category, out)?; }
                    }
                } else {
                    collect(child, category, depth + 1, out)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn parse_authenticated_device_list(json: &[u8]) -> Result<AuthorizedCatalog, CatalogError> {
    if json.len() > MAX_JSON_BYTES { return Err(CatalogError::Oversized); }
    let value: serde_json::Value = serde_json::from_slice(json)
        .map_err(|_| CatalogError::InvalidJson)?;
    match value.get("resultCode").and_then(serde_json::Value::as_str) {
        Some("1001") => {}
        Some("1023") => return Err(CatalogError::TemporarilyUnavailable),
        _ => return Err(CatalogError::NotAuthenticated),
    }
    let mut records = BTreeMap::new();
    collect(&value, None, 0, &mut records)?;
    Ok(AuthorizedCatalog { records: records.into_values().collect() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_owner_and_shared_home_dedupe_with_private_values_redacted() {
        let response = r#"{
          "resultCode":"1001", "userToken":"private-account-token",
          "result":{
            "ipc":[{"deviceID":1,"snNum":"private-device-A","hostKey":"private-host-key",
              "p2pInit":"private-bootstrap", "deviceP2P":"ppcs",
              "mac":"70:3A:2D:32:F7:D8"}],
            "base":[{"deviceID":9876,"snNum":"not-a-camera"}],
            "homes":[{"deviceList":[
              {"deviceID":"1","snNum":"private-device-A"},
              {"deviceID":2,"snNum":"private-device-B", "devTypeID":5,"deviceP2P":"webrtc"}
            ]}]
          }
        }"#;
        let catalog = parse_authenticated_device_list(response.as_bytes()).unwrap();
        let summary = catalog.summary();
        assert_eq!(summary.cameras, 2);
        assert_eq!(summary.ppcs, 1);
        assert_eq!(summary.signaling, 1);
        assert_eq!(summary.battery, 1);
        assert!(catalog.by_mac("70:3a:2d:32:f7:d8").is_some());
        assert!(catalog.by_mac("70:3a:2d:32:f7:d9").is_none());
        assert_eq!(catalog.by_mac("70:3a:2d:32:f7:d8").unwrap()
            .host_key.as_deref(), Some("private-host-key"));
        let report = summary.safe_text();
        for secret in ["private-device-A","private-account-token",
            "private-host-key","private-bootstrap","70:3a:2d:32:f7:d8"] {
            assert!(!report.contains(secret));
        }
    }

    #[test]
    fn accepts_only_successful_account_responses() {
        for response in [
            r#"{"resultCode":"1002","result":{"ipc":[]}}"#,
            r#"{"resultCode":"401"}"#,
            r#"{"result":{"ipc":[]}}"#,
        ] {
            assert_eq!(parse_authenticated_device_list(response.as_bytes()).err(),
                Some(CatalogError::NotAuthenticated));
        }
        assert_eq!(parse_authenticated_device_list(br#"{"resultCode":"1023"}"#).err(),
            Some(CatalogError::TemporarilyUnavailable));
        assert_eq!(parse_authenticated_device_list(b"bad json").err(),
            Some(CatalogError::InvalidJson));
        assert_eq!(parse_authenticated_device_list(&vec![0; MAX_JSON_BYTES + 1]).err(),
            Some(CatalogError::Oversized));
    }

    #[test]
    fn model_and_ip_cannot_claim_identity_without_matching_mac() {
        for invalid in ["00:00:00:00:00:00","ff:ff:ff:ff:ff:ff",
            "01:00:00:00:00:00","70-3a-2d-32-f7-d8"] {
            assert!(normalize_mac(invalid).is_none());
        }
        let payload = br#"{"resultCode":"1001","result":{"ipc":[
            {"deviceID":1,"snNum":"a","model":"b81","ip":"192.168.0.107"}
        ]}}"#;
        let catalog = parse_authenticated_device_list(payload).unwrap();
        assert_eq!(catalog.summary().cameras, 1);
        assert_eq!(catalog.summary().transport_unverified, 1);
        assert!(catalog.by_mac("70:3a:2d:32:f7:d8").is_none());
    }

    #[test]
    fn bounded_depth_and_record_count() {
        let mut nested = serde_json::json!({"deviceList":[{"deviceID":1,"snNum":"a"}]});
        for _ in 0..MAX_DEPTH + 2 {
            nested = serde_json::json!({"nest":nested});
        }
        let response = serde_json::json!({"resultCode":"1001","result":nested});
        assert_eq!(parse_authenticated_device_list(response.to_string().as_bytes()).err(),
            Some(CatalogError::InvalidJson));
        let entries: Vec<_> = (0..=MAX_RECORDS)
            .map(|n| serde_json::json!({"deviceID":n,"snNum":format!("test-{n}")}))
            .collect();
        let response = serde_json::json!({"resultCode":"1001","result":{"deviceList":entries}});
        assert_eq!(parse_authenticated_device_list(response.to_string().as_bytes()).err(),
            Some(CatalogError::TooManyCameras));
    }
}
