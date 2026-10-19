//! Normalization of an *authenticated* Meari-family device-list response.
//! Offline only: no HTTP, login, account secrets on disk, raw payload UI or
//! camera connectivity. Source research: MIT-licensed
//! github.com/raulrojas22/Ha-CloudPlus-Meari-ANRAN
//! custom_components/cloudplus/api.py, _collect_devices_from_payload.

use crate::{
    meari_ppcs_discovery::{PpcsDeviceIdentity, PpcsDeviceInit},
    meari_vvp::Transport,
};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

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

impl Drop for AuthorizedCamera {
    fn drop(&mut self) {
        // Only best-effort clearing of our owned buffers: parsers and network
        // transports can allocate other temporary copies of response values.
        self.device_id.zeroize();
        self.serial.zeroize();
        for field in [
            &mut self.host_key,
            &mut self.device_uuid,
            &mut self.p2p_init,
            &mut self.mac,
        ] {
            if let Some(value) = field.as_mut() {
                value.zeroize();
            }
        }
    }
}

impl AuthorizedCamera {
    pub fn matches_mac(&self, candidate: &str) -> bool {
        self.mac
            .as_deref()
            .zip(normalize_mac(candidate).as_deref())
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

/// PPCS account-record *format* preflight. A complete row is not
/// authenticated peer access, a working socket, or verified video.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PpcsMetadataSummary {
    pub declared: usize,
    pub fields_valid: usize,
    pub identity_missing: usize,
    pub identity_invalid: usize,
    pub init_missing: usize,
    pub init_invalid: usize,
    pub host_key_missing: usize,
    pub host_key_invalid: usize,
}

impl PpcsMetadataSummary {
    /// Fixed text contains only counts; cannot leak device IDs, host keys,
    /// init strings, relay hosts, or vendor account material.
    pub fn safe_text(self) -> String {
        format!(
            "PPCS account metadata (format only): {} declared, {} with all required fields              syntactically valid; identity missing={}, malformed={};              init missing={}, malformed={}; host key missing={}, malformed={}.              Does not establish peer identity, reachable transport or video access.",
            self.declared,
            self.fields_valid,
            self.identity_missing,
            self.identity_invalid,
            self.init_missing,
            self.init_invalid,
            self.host_key_missing,
            self.host_key_invalid,
        )
    }
}

fn ppcs_fields_valid(camera: &AuthorizedCamera) -> bool {
    camera.transport == Transport::Ppcs
        && camera
            .device_uuid
            .as_deref()
            .is_some_and(|id| PpcsDeviceIdentity::from_factory_uuid(id).is_ok())
        && camera
            .p2p_init
            .as_deref()
            .is_some_and(|init| PpcsDeviceInit::from_device_init(init).is_ok())
        && camera
            .host_key
            .as_deref()
            .is_some_and(|key| !key.is_empty() && key.len() <= 256 && key.is_ascii())
}

/// Aggregate-only local correlation, with no device identifiers or MACs.
///
/// A unique normalized MAC on each side is the only accepted link. A missing
/// MAC, a duplicated MAC, a shared model, or an IP address never establishes
/// that two device records refer to the same camera.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CatalogCorrelation {
    pub saved_records: usize,
    pub exact_unique_matches: usize,
    pub ambiguous_macs: usize,
    pub saved_without_mac: usize,
    pub saved_not_matched: usize,
    pub cloud_without_mac: usize,
}

impl CatalogCorrelation {
    pub fn safe_text(self) -> String {
        format!(
            "Local ANRAN inventory comparison: {} saved records; {} unique MAC matches;              {} ambiguous MAC groups; {} saved records without valid MAC;              {} saved records without a cloud MAC match; {} cloud cameras without valid MAC.              No identity or video access is proven by this comparison.",
            self.saved_records,
            self.exact_unique_matches,
            self.ambiguous_macs,
            self.saved_without_mac,
            self.saved_not_matched,
            self.cloud_without_mac
        )
    }
}

/// Transport split for one-to-one MAC matches only. A valid-looking PPCS
/// record is not an authenticated peer, tested connection, or video session.
/// No MACs, secrets, IPs, or device identifiers cross this summary boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MatchedPpcsSummary {
    pub unique_mac_matches: usize,
    pub ppcs_declared: usize,
    pub ppcs_metadata_valid: usize,
    pub ppcs_metadata_incomplete: usize,
    pub signaling: usize,
    pub unknown_transport: usize,
}

impl MatchedPpcsSummary {
    pub fn safe_text(self) -> String {
        format!(
            "Selected-LAN unique MAC matches: {} total, PPCS={}              (fields valid={}, incomplete={}), signaling={}, unknown={}.              Matched metadata does not authenticate a camera, prove video              compatibility, or authorize a network connection.",
            self.unique_mac_matches,
            self.ppcs_declared,
            self.ppcs_metadata_valid,
            self.ppcs_metadata_incomplete,
            self.signaling,
            self.unknown_transport,
        )
    }
}

/// Never derive Debug or Serialize on this type. Account records may contain
/// ephemeral host keys and transport bootstrap material.
pub struct AuthorizedCatalog {
    records: Vec<AuthorizedCamera>,
}

impl AuthorizedCatalog {
    pub fn cameras(&self) -> &[AuthorizedCamera] {
        &self.records
    }

    pub fn by_mac(&self, mac: &str) -> Option<&AuthorizedCamera> {
        self.records.iter().find(|camera| camera.matches_mac(mac))
    }

    /// Compare only against saved, user-identified ANRAN cameras from the
    /// selected local scope. Nothing is sent to any vendor by this function.
    /// The returned object contains counts only; all normalized MAC copies
    /// use zeroizing buffers and are dropped on return.
    pub fn correlate_saved_macs(&self, saved: &[Option<String>]) -> CatalogCorrelation {
        let mut comparison = CatalogCorrelation {
            saved_records: saved.len(),
            cloud_without_mac: self.records.iter().filter(|cam| cam.mac.is_none()).count(),
            ..Default::default()
        };
        let mut normalized: Vec<Zeroizing<String>> = Vec::new();
        for entry in saved {
            if let Some(mac) = entry.as_deref().and_then(normalize_mac) {
                normalized.push(Zeroizing::new(mac));
            } else {
                comparison.saved_without_mac += 1;
            }
        }
        for (index, mac) in normalized.iter().enumerate() {
            if normalized[..index]
                .iter()
                .any(|previous| previous.as_str() == mac.as_str())
            {
                continue;
            }
            let local_count = normalized
                .iter()
                .filter(|candidate| candidate.as_str() == mac.as_str())
                .count();
            let cloud_count = self
                .records
                .iter()
                .filter(|camera| camera.mac.as_deref() == Some(mac.as_str()))
                .count();
            match (local_count, cloud_count) {
                (_, 0) => comparison.saved_not_matched += local_count,
                (1, 1) => comparison.exact_unique_matches += 1,
                _ => comparison.ambiguous_macs += 1,
            }
        }
        comparison
    }

    /// Correlate the selected saved-camera scope with the temporary authorized
    /// catalog. A match must have exactly one normalized MAC on EACH side.
    /// Duplicated, absent or invalid MACs never grant a match; model, IP,
    /// serial number, and account app labeling are not alternate identifiers.
    /// The returned result contains counts only, and normalizations are
    /// zeroized when this method returns.
    pub fn matched_ppcs_summary(&self, saved: &[Option<String>]) -> MatchedPpcsSummary {
        let local: Vec<Option<Zeroizing<String>>> = saved
            .iter()
            .map(|entry| entry.as_deref().and_then(normalize_mac).map(Zeroizing::new))
            .collect();
        let mut summary = MatchedPpcsSummary::default();
        for (index, mac) in local.iter().enumerate() {
            let Some(mac) = mac.as_ref() else {
                continue;
            };
            if local[..index]
                .iter()
                .flatten()
                .any(|earlier| earlier.as_str() == mac.as_str())
            {
                continue;
            }
            let saved_count = local
                .iter()
                .flatten()
                .filter(|other| other.as_str() == mac.as_str())
                .count();
            if saved_count != 1 {
                continue;
            }
            let mut cloud = self
                .records
                .iter()
                .filter(|camera| camera.mac.as_deref() == Some(mac.as_str()));
            let Some(camera) = cloud.next() else {
                continue;
            };
            if cloud.next().is_some() {
                continue;
            }
            summary.unique_mac_matches += 1;
            match camera.transport {
                Transport::Ppcs => {
                    summary.ppcs_declared += 1;
                    if ppcs_fields_valid(camera) {
                        summary.ppcs_metadata_valid += 1;
                    } else {
                        summary.ppcs_metadata_incomplete += 1;
                    }
                }
                Transport::Signaling => summary.signaling += 1,
                Transport::Unknown => summary.unknown_transport += 1,
            }
        }
        summary
    }

    /// Count which explicitly PPCS-marked catalog records contain parseable
    /// protocol prerequisites. Never attempt DNS, P2P, or key derivation from
    /// unmarked/signaling cameras. Temporary decoded secrets are destroyed.
    pub fn ppcs_metadata_summary(&self) -> PpcsMetadataSummary {
        let mut out = PpcsMetadataSummary::default();
        for camera in &self.records {
            if camera.transport != Transport::Ppcs {
                continue;
            }
            out.declared += 1;
            let valid_identity = match camera.device_uuid.as_deref() {
                Some(uuid) => {
                    let ok = PpcsDeviceIdentity::from_factory_uuid(uuid).is_ok();
                    if !ok {
                        out.identity_invalid += 1;
                    }
                    ok
                }
                None => {
                    out.identity_missing += 1;
                    false
                }
            };
            let valid_init = match camera.p2p_init.as_deref() {
                Some(init) => {
                    let ok = PpcsDeviceInit::from_device_init(init).is_ok();
                    if !ok {
                        out.init_invalid += 1;
                    }
                    ok
                }
                None => {
                    out.init_missing += 1;
                    false
                }
            };
            let valid_host_key = match camera.host_key.as_deref() {
                Some(host_key) => {
                    let ok = !host_key.is_empty() && host_key.len() <= 256 && host_key.is_ascii();
                    if !ok {
                        out.host_key_invalid += 1;
                    }
                    ok
                }
                None => {
                    out.host_key_missing += 1;
                    false
                }
            };
            if valid_identity && valid_init && valid_host_key {
                out.fields_valid += 1;
            }
        }
        out
    }

    /// Merge separate owner and shared-home responses using authoritative
    /// deviceID only. Prefer the more complete record for repeated IDs.
    /// An excess of unique cameras fails closed rather than truncating results.
    pub fn merge(&mut self, other: Self) -> Result<(), CatalogError> {
        let mut by_id = BTreeMap::new();
        for camera in self.records.drain(..) {
            by_id.insert(camera.device_id.clone(), camera);
        }
        for camera in other.records {
            let replace = by_id
                .get(&camera.device_id)
                .is_none_or(|prior: &AuthorizedCamera| {
                    camera.completeness() > prior.completeness()
                });
            if replace {
                by_id.insert(camera.device_id.clone(), camera);
            }
            if by_id.len() > MAX_RECORDS {
                return Err(CatalogError::TooManyCameras);
            }
        }
        self.records = by_id.into_values().collect();
        Ok(())
    }

    pub fn summary(&self) -> CatalogSummary {
        let mut summary = CatalogSummary {
            cameras: self.records.len(),
            wired: 0,
            battery: 0,
            doorbells: 0,
            ppcs: 0,
            signaling: 0,
            transport_unverified: 0,
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
    UnexpectedDeviceListShape,
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
    let octets = raw
        .split(':')
        .map(|chunk| {
            if chunk.len() == 2 {
                u8::from_str_radix(chunk, 16).ok()
            } else {
                None
            }
        })
        .collect::<Option<Vec<_>>>()?;
    if octets.len() != 6
        || octets.iter().all(|n| *n == 0)
        || octets.iter().all(|n| *n == 255)
        || octets[0] & 1 != 0
    {
        return None;
    }
    Some(
        octets
            .iter()
            .map(|n| format!("{n:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Recognized Meari collections that are not cameras according to the
/// pinned reference's CAMERA_CATEGORIES filter. They can legitimately be
/// present in an authenticated device catalog without camera records.
fn accessory_collection(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "nvr" | "nvr-neutral" | "base" | "chime"
    )
}

/// The reference coerces default and shared-home resultCode to text before
/// comparing 1001/1023/1107; avoid rejecting integer-valued vendor codes.
/// Other API stages retain their existing stricter validation.
pub(crate) fn result_code_is(response: &serde_json::Value, code: u64) -> bool {
    match response.get("resultCode") {
        Some(serde_json::Value::String(value)) => value == &code.to_string(),
        Some(serde_json::Value::Number(value)) => value.as_u64() == Some(code),
        _ => false,
    }
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
        // The reference accepts both numeric and string devTypeID.
        let dev_type = obj.get("devTypeID").and_then(|value| match value {
            serde_json::Value::Number(n) => n.as_i64(),
            serde_json::Value::String(s) => s.parse::<i64>().ok(),
            _ => None,
        });
        if dev_type == Some(5) {
            Category::Battery
        } else {
            Category::Wired
        }
    });
    let mac = ["mac", "macAddr", "macAddress"]
        .iter()
        .filter_map(|key| obj.get(*key).and_then(serde_json::Value::as_str))
        .find_map(normalize_mac);
    Some(AuthorizedCamera {
        device_id,
        serial,
        category,
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
        let replace = output
            .get(&record.device_id)
            .is_none_or(|prev| record.completeness() > prev.completeness());
        if replace {
            output.insert(record.device_id.clone(), record);
        }
        if output.len() > MAX_RECORDS {
            return Err(CatalogError::TooManyCameras);
        }
    }
    Ok(())
}

fn collect(
    node: &serde_json::Value,
    category: Option<Category>,
    depth: usize,
    out: &mut BTreeMap<String, AuthorizedCamera>,
) -> Result<(), CatalogError> {
    if depth > MAX_DEPTH {
        return Err(CatalogError::InvalidJson);
    }
    match node {
        serde_json::Value::Array(items) => {
            for value in items {
                collect(value, category, depth + 1, out)?;
            }
        }
        serde_json::Value::Object(fields) => {
            for (name, child) in fields {
                if accessory_collection(name) {
                    // Recognize these shapes without labeling NVRs, bases
                    // or chimes as actual cameras.
                    continue;
                }
                if let Some(cat) = category_for(name) {
                    if let Some(items) = child.as_array() {
                        for item in items {
                            insert_camera(item, Some(cat), out)?;
                        }
                    }
                } else if name == "deviceList" {
                    if let Some(items) = child.as_array() {
                        for item in items {
                            insert_camera(item, category, out)?;
                        }
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

/// A successful API status alone does not establish that we received a
/// camera-list response. Reject unknown, nonempty response shapes rather
/// than silently classifying a vendor/API mismatch as zero cameras.
/// A genuinely empty `result: {}` is allowed, as in the pinned reference.
/// Field names match the same accepted collections used by `collect`.
fn recognizable_device_collection(
    value: &serde_json::Value,
    depth: usize,
) -> Result<bool, CatalogError> {
    if depth > MAX_DEPTH {
        return Err(CatalogError::InvalidJson);
    }
    let mut found = false;
    match value {
        serde_json::Value::Object(fields) => {
            for (name, child) in fields {
                if category_for(name).is_some()
                    || accessory_collection(name)
                    || name == "deviceList"
                {
                    // Another valid list must not mask a malformed known list:
                    // silently accepting this could claim zero cameras.
                    if !child.is_array() {
                        return Err(CatalogError::UnexpectedDeviceListShape);
                    }
                    found = true;
                } else {
                    found |= recognizable_device_collection(child, depth + 1)?;
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                found |= recognizable_device_collection(item, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(found)
}

pub fn parse_authenticated_device_list(json: &[u8]) -> Result<AuthorizedCatalog, CatalogError> {
    if json.len() > MAX_JSON_BYTES {
        return Err(CatalogError::Oversized);
    }
    let value: serde_json::Value =
        serde_json::from_slice(json).map_err(|_| CatalogError::InvalidJson)?;
    if !result_code_is(&value, 1001) {
        return Err(if result_code_is(&value, 1023) {
            CatalogError::TemporarilyUnavailable
        } else {
            CatalogError::NotAuthenticated
        });
    }
    let result = value
        .get("result")
        .ok_or(CatalogError::UnexpectedDeviceListShape)?;
    let empty_result = match result {
        serde_json::Value::Object(fields) => fields.is_empty(),
        serde_json::Value::Array(items) => items.is_empty(),
        _ => return Err(CatalogError::UnexpectedDeviceListShape),
    };
    // The upstream walker also collects camera objects directly nested
    // inside a result array, not just under ipc/deviceList keys.
    let direct_array_records = match result {
        serde_json::Value::Array(items) => items
            .iter()
            .any(|item| parse_device(item, None).is_some()),
        _ => false,
    };
    let recognized_collection = recognizable_device_collection(result, 0)?;
    if !empty_result && !recognized_collection && !direct_array_records {
        return Err(CatalogError::UnexpectedDeviceListShape);
    }
    let mut records = BTreeMap::new();
    if let serde_json::Value::Array(items) = result {
        for item in items {
            insert_camera(item, None, &mut records)?;
        }
    }
    collect(&value, None, 0, &mut records)?;
    let mut cameras = Vec::with_capacity(records.len());
    for (mut key, record) in records {
        key.zeroize();
        cameras.push(record);
    }
    Ok(AuthorizedCatalog { records: cameras })
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
              "mac":"02:AB:CD:12:34:56"}],
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
        assert!(catalog.by_mac("02:ab:cd:12:34:56").is_some());
        assert!(catalog.by_mac("02:ab:cd:12:34:57").is_none());
        assert_eq!(
            catalog
                .by_mac("02:ab:cd:12:34:56")
                .unwrap()
                .host_key
                .as_deref(),
            Some("private-host-key")
        );
        let report = summary.safe_text();
        for secret in [
            "private-device-A",
            "private-account-token",
            "private-host-key",
            "private-bootstrap",
            "02:ab:cd:12:34:56",
        ] {
            assert!(!report.contains(secret));
        }
    }

    #[test]
    fn matched_ppcs_requires_unique_macs_in_both_inventories() {
        let uuid = "01-BCDEF-23B";
        let init = "0S5x0R0o10Kl6mKk3p1w4k0i5zKt5qKr4x3r0j0z1P7y9wJm1q1N:sample-key";
        let response = serde_json::json!({
            "resultCode": "1001", "result": {"ipc": [
                {"deviceID":"good","snNum":"s1","mac":"02:11:22:33:44:01","deviceP2P":"ppcs",
                 "deviceUUID":uuid,"p2pInit":init,"hostKey":"secret-host-key"},
                {"deviceID":"incomplete","snNum":"s2","mac":"02:11:22:33:44:02",
                 "deviceP2P":"ppcs","deviceUUID":uuid,"p2pInit":"invalid",
                 "hostKey":"secret-host-key"},
                {"deviceID":"signaling","snNum":"s3","mac":"02:11:22:33:44:03",
                 "deviceP2P":"webrtc","deviceUUID":uuid,"p2pInit":init},
                {"deviceID":"unknown","snNum":"s4","mac":"02:11:22:33:44:04",
                 "model":"b81","deviceUUID":uuid,"p2pInit":init},
                {"deviceID":"duplicated1","snNum":"s5","mac":"02:11:22:33:44:05",
                 "deviceP2P":"ppcs","deviceUUID":uuid,"p2pInit":init,"hostKey":"secret"},
                {"deviceID":"duplicated2","snNum":"s6","mac":"02:11:22:33:44:05",
                 "deviceP2P":"ppcs","deviceUUID":uuid,"p2pInit":init,"hostKey":"secret"},
                {"deviceID":"unmatched","snNum":"s7","mac":"02:11:22:33:44:07",
                 "deviceP2P":"ppcs","deviceUUID":uuid,"p2pInit":init,"hostKey":"secret"}
            ]}
        });
        let catalog = parse_authenticated_device_list(response.to_string().as_bytes()).unwrap();
        let local = vec![
            Some("02:11:22:33:44:01".into()),
            Some("02:11:22:33:44:02".into()),
            Some("02:11:22:33:44:03".into()),
            Some("02:11:22:33:44:04".into()),
            Some("02:11:22:33:44:05".into()),
            Some("02:11:22:33:44:06".into()),
            Some("02:11:22:33:44:06".into()),
            None,
            Some("not-a-mac".into()),
        ];
        let report = catalog.matched_ppcs_summary(&local);
        assert_eq!(
            report,
            MatchedPpcsSummary {
                unique_mac_matches: 4,
                ppcs_declared: 2,
                ppcs_metadata_valid: 1,
                ppcs_metadata_incomplete: 1,
                signaling: 1,
                unknown_transport: 1,
            }
        );
        let text = report.safe_text();
        for forbidden in [
            "02:11:22:33:44:01",
            "b81",
            "sample-key",
            "secret-host-key",
            uuid,
            init,
            "good",
            "unmatched",
        ] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn matched_ppcs_rejects_duplicate_local_mac_and_never_inferrs_from_model() {
        let raw = br#"{"resultCode":"1001","result":{"ipc":[
          {"deviceID":"a","snNum":"a","mac":"02:11:22:33:44:01",
           "deviceP2P":"ppcs","deviceUUID":"01-BCDEF-23B"},
          {"deviceID":"b","snNum":"b","mac":"02:11:22:33:44:02",
           "model":"b81","hostKey":"private"}
        ]}}"#;
        let catalog = parse_authenticated_device_list(raw).unwrap();
        let saved = [
            Some("02:11:22:33:44:01".into()),
            Some("02:11:22:33:44:01".into()),
            Some("02:11:22:33:44:02".into()),
        ];
        let found = catalog.matched_ppcs_summary(&saved);
        assert_eq!(found.unique_mac_matches, 1);
        assert_eq!(found.ppcs_declared, 0);
        assert_eq!(found.unknown_transport, 1);
    }

    #[test]
    fn matched_ppcs_merges_authorized_shared_home_before_scoring() {
        let mut catalog = parse_authenticated_device_list(
            br#"{"resultCode":"1001","result":{"ipc":[
              {"deviceID":"one","snNum":"serial","deviceP2P":"ppcs"}
            ]}}"#,
        )
        .unwrap();
        let shared = serde_json::json!({
            "resultCode":"1001","result":{"deviceList":[{
                "deviceID":"one","snNum":"serial","deviceP2P":"ppcs",
                "mac":"02:11:22:33:44:03",
                "deviceUUID":"01-BCDEF-23B",
                "p2pInit":"0S5x0R0o10Kl6mKk3p1w4k0i5zKt5qKr4x3r0j0z1P7y9wJm1q1N:sample-key",
                "hostKey":"secret"
            }]}
        });
        catalog
            .merge(parse_authenticated_device_list(shared.to_string().as_bytes()).unwrap())
            .unwrap();
        let found = catalog.matched_ppcs_summary(&[Some("02:11:22:33:44:03".into())]);
        assert_eq!(found.unique_mac_matches, 1);
        assert_eq!(found.ppcs_declared, 1);
        assert_eq!(found.ppcs_metadata_valid, 1);
    }

    #[test]
    fn ppcs_metadata_reports_only_validated_field_counts_without_secrets() {
        let uuid = "01-BCDEF-23B";
        let init = "0S5x0R0o10Kl6mKk3p1w4k0i5zKt5qKr4x3r0j0z1P7y9wJm1q1N:sample-key";
        let entries = vec![
            serde_json::json!({
                "deviceID": "complete-private", "snNum": "secret-a",
                "deviceP2P": "ppcs", "deviceUUID": uuid, "p2pInit": init,
                "hostKey": "private-host-key"
            }),
            serde_json::json!({
                "deviceID": "missing-id", "snNum": "secret-b", "deviceP2P": "ppcs",
                "p2pInit": init, "hostKey": "private-host-key"
            }),
            serde_json::json!({
                "deviceID": "bad-id", "snNum": "secret-c", "deviceP2P": "ppcs",
                "deviceUUID": "fake-uuid", "p2pInit": init, "hostKey": "private-host-key"
            }),
            serde_json::json!({
                "deviceID": "missing-init", "snNum": "secret-d", "deviceP2P": "ppcs",
                "deviceUUID": uuid, "hostKey": "private-host-key"
            }),
            serde_json::json!({
                "deviceID": "bad-init", "snNum": "secret-e", "deviceP2P": "ppcs",
                "deviceUUID": uuid, "p2pInit": "garbage", "hostKey": "private-host-key"
            }),
            serde_json::json!({
                "deviceID": "missing-key", "snNum": "secret-f", "deviceP2P": "ppcs",
                "deviceUUID": uuid, "p2pInit": init
            }),
            serde_json::json!({
                "deviceID": "bad-key", "snNum": "secret-g", "deviceP2P": "ppcs",
                "deviceUUID": uuid, "p2pInit": init, "hostKey": "clé-privée"
            }),
            serde_json::json!({
                "deviceID": "other-protocol", "snNum": "secret-h",
                "deviceP2P": "webrtc", "deviceUUID": uuid,
                "p2pInit": init, "hostKey": "private-host-key"
            }),
        ];
        let json = serde_json::json!({
            "resultCode": "1001", "result": {"ipc": entries}
        });
        let catalog = parse_authenticated_device_list(json.to_string().as_bytes()).unwrap();
        let status = catalog.ppcs_metadata_summary();
        assert_eq!(
            status,
            PpcsMetadataSummary {
                declared: 7,
                fields_valid: 1,
                identity_missing: 1,
                identity_invalid: 1,
                init_missing: 1,
                init_invalid: 1,
                host_key_missing: 1,
                host_key_invalid: 1,
            }
        );
        let safe = status.safe_text();
        assert!(safe.contains("7 declared"));
        for forbidden in [
            uuid,
            init,
            "sample-key",
            "private-host-key",
            "fake-uuid",
            "clé-privée",
        ] {
            assert!(!safe.contains(forbidden));
        }
    }

    #[test]
    fn ppcs_metadata_never_inferrs_transport_from_other_camera_fields() {
        let response = serde_json::json!({
            "resultCode": "1001", "result": {"ipc": [
                {"deviceID": "a", "snNum": "serial", "model": "b81",
                 "deviceUUID": "01-BCDEF-23B", "hostKey": "private"},
                {"deviceID": "b", "snNum": "serial", "deviceP2P": "webrtc",
                 "deviceUUID": "01-BCDEF-23B", "hostKey": "private"}
            ]}
        });
        let catalog = parse_authenticated_device_list(response.to_string().as_bytes()).unwrap();
        assert_eq!(
            catalog.ppcs_metadata_summary(),
            PpcsMetadataSummary::default()
        );
    }

    #[test]
    fn ppcs_metadata_merges_richer_shared_home_fields_without_network() {
        let mut owner = parse_authenticated_device_list(
            br#"{"resultCode":"1001","result":{"ipc":[
                {"deviceID":"a","snNum":"serial","deviceP2P":"ppcs"}
            ]}}"#,
        )
        .unwrap();
        let shared = serde_json::json!({
            "resultCode": "1001", "result": {"deviceList": [{
                "deviceID": "a", "snNum": "serial",
                "deviceP2P": "ppcs", "deviceUUID": "01-BCDEF-23B",
                "p2pInit": "0S5x0R0o10Kl6mKk3p1w4k0i5zKt5qKr4x3r0j0z1P7y9wJm1q1N:sample-key",
                "hostKey": "private"
            }]}
        });
        owner
            .merge(parse_authenticated_device_list(shared.to_string().as_bytes()).unwrap())
            .unwrap();
        let result = owner.ppcs_metadata_summary();
        assert_eq!(result.declared, 1);
        assert_eq!(result.fields_valid, 1);
    }

    #[test]
    fn merging_owner_and_shared_homes_prefers_richer_matching_device_id() {
        let mut owner = parse_authenticated_device_list(
            br#"{"resultCode":"1001","result":{"ipc":[
                {"deviceID":"A","snNum":"one"},
                {"deviceID":"B","snNum":"two","deviceP2P":"ppcs"}
            ]}}"#,
        )
        .unwrap();
        let shared = parse_authenticated_device_list(
            br#"{"resultCode":"1001","result":{"deviceList":[
                {"deviceID":"A","snNum":"one","mac":"02:ab:cd:12:34:56",
                 "deviceP2P":"webrtc"},
                {"deviceID":"C","snNum":"three","mac":"02:ab:cd:12:34:57"}
            ]}}"#,
        )
        .unwrap();
        owner.merge(shared).unwrap();
        assert_eq!(owner.summary().cameras, 3);
        assert_eq!(owner.summary().signaling, 1);
        assert_eq!(owner.summary().ppcs, 1);
        assert!(owner.by_mac("02:ab:cd:12:34:56").is_some());
    }

    #[test]
    fn local_cloud_correlation_requires_unique_mac_on_both_sides() {
        let raw = br#"{"resultCode":"1001","result":{"ipc":[
          {"deviceID":"cam-a","snNum":"a","mac":"02:ab:cd:12:34:56","deviceP2P":"ppcs"},
          {"deviceID":"cam-b","snNum":"b","mac":"02:ab:cd:12:34:57"},
          {"deviceID":"cam-c","snNum":"c","model":"b81","ip":"192.0.2.4"}
        ]}}"#;
        let catalog = parse_authenticated_device_list(raw).unwrap();
        let saved = vec![
            Some("02:AB:CD:12:34:56".into()),
            Some("02:ab:cd:12:34:58".into()),
            None,
            Some("ff:ff:ff:ff:ff:ff".into()),
        ];
        let counts = catalog.correlate_saved_macs(&saved);
        assert_eq!(
            counts,
            CatalogCorrelation {
                saved_records: 4,
                exact_unique_matches: 1,
                ambiguous_macs: 0,
                saved_without_mac: 2,
                saved_not_matched: 1,
                cloud_without_mac: 1,
            }
        );
        let report = counts.safe_text();
        for private in [
            "02:ab:cd:12:34:56",
            "02:ab:cd:12:34:58",
            "cam-a",
            "b81",
            "192.0.2.4",
        ] {
            assert!(!report.contains(private));
        }
    }

    #[test]
    fn duplicated_mac_on_either_side_is_ambiguous_not_a_match() {
        let raw = br#"{"resultCode":"1001","result":{"ipc":[
          {"deviceID":"cam-a","snNum":"a","mac":"02:ab:cd:12:34:56"},
          {"deviceID":"cam-b","snNum":"b","mac":"02:ab:cd:12:34:56"},
          {"deviceID":"cam-c","snNum":"c","mac":"02:ab:cd:12:34:57"}
        ]}}"#;
        let catalog = parse_authenticated_device_list(raw).unwrap();
        let saved = vec![
            Some("02:ab:cd:12:34:56".into()),
            Some("02:ab:cd:12:34:57".into()),
            Some("02:ab:cd:12:34:57".into()),
        ];
        let counts = catalog.correlate_saved_macs(&saved);
        assert_eq!(counts.exact_unique_matches, 0);
        assert_eq!(counts.ambiguous_macs, 2);
        assert_eq!(counts.saved_not_matched, 0);
    }

    #[test]
    fn empty_local_inventory_never_implies_incompatible_backend() {
        let catalog = parse_authenticated_device_list(
            br#"{"resultCode":"1001","result":{"ipc":[
                {"deviceID":"a","snNum":"b","mac":"02:ab:cd:12:34:56"}
            ]}}"#,
        )
        .unwrap();
        assert_eq!(
            catalog.correlate_saved_macs(&[]),
            CatalogCorrelation {
                saved_records: 0,
                ..Default::default()
            }
        );
    }

    #[test]
    fn accepts_only_successful_account_responses() {
        for response in [
            r#"{"resultCode":"1002","result":{"ipc":[]}}"#,
            r#"{"resultCode":"401"}"#,
            r#"{"result":{"ipc":[]}}"#,
        ] {
            assert_eq!(
                parse_authenticated_device_list(response.as_bytes()).err(),
                Some(CatalogError::NotAuthenticated)
            );
        }
        assert_eq!(
            parse_authenticated_device_list(br#"{"resultCode":"1023"}"#).err(),
            Some(CatalogError::TemporarilyUnavailable)
        );
        assert_eq!(
            parse_authenticated_device_list(b"bad json").err(),
            Some(CatalogError::InvalidJson)
        );
        assert_eq!(
            parse_authenticated_device_list(&vec![0; MAX_JSON_BYTES + 1]).err(),
            Some(CatalogError::Oversized)
        );
    }

    #[test]
    fn authenticated_result_requires_a_recognizable_camera_list_shape() {
        // A vendor can return HTTP 200 and resultCode=1001 with an
        // unrelated payload. That is NOT evidence of zero account cameras.
        for invalid in [
            r#"{"resultCode":"1001"}"#,
            r#"{"resultCode":"1001","result":null}"#,
            r#"{"resultCode":"1001","result":"ok"}"#,
            r#"{"resultCode":"1001","result":{"unknownList":[]}}"#,
            r#"{"resultCode":"1001","result":{"status":"ok"}}"#,
            r#"{"resultCode":"1001","result":{"ipc":{}}}"#,
            r#"{"resultCode":"1001","result":{"deviceList":null}}"#,
            // A valid sibling cannot conceal an invalid known list.
            r#"{"resultCode":"1001","result":{"ipc":[],"deviceList":null}}"#,
            r#"{"resultCode":"1001","result":{"deviceList":[],"doorbell":{}}}"#,
            r#"{"resultCode":"1001","result":{"homes":[{"ipc":[]},{"snap":"bad"}]}}"#,
        ] {
            assert_eq!(
                parse_authenticated_device_list(invalid.as_bytes()).err(),
                Some(CatalogError::UnexpectedDeviceListShape)
            );
        }
        // Both a truly empty result and explicitly empty known arrays are
        // legitimate empty catalogs in the reference implementation.
        for valid in [
            r#"{"resultCode":"1001","result":{}}"#,
            r#"{"resultCode":"1001","result":{"ipc":[]}}"#,
            r#"{"resultCode":"1001","result":{"deviceList":[]}}"#,
            r#"{"resultCode":"1001","result":{"homes":[{"deviceList":[]}]}}"#,
        ] {
            let catalog = parse_authenticated_device_list(valid.as_bytes()).unwrap();
            assert_eq!(catalog.summary().cameras, 0);
        }
    }

    #[test]
    fn numeric_catalog_result_codes_match_reference_without_relaxing_other_types() {
        for successful in [
            r#"{"resultCode":1001,"result":{"ipc":[{"deviceID":1,"snNum":"a"}]}}"#,
            r#"{"resultCode":"1001","result":{"ipc":[{"deviceID":1,"snNum":"a"}]}}"#,
        ] {
            let catalog = parse_authenticated_device_list(successful.as_bytes()).unwrap();
            assert_eq!(catalog.summary().cameras, 1);
        }
        for temporarily_unavailable in [
            r#"{"resultCode":1023}"#,
            r#"{"resultCode":"1023"}"#,
        ] {
            assert_eq!(
                parse_authenticated_device_list(temporarily_unavailable.as_bytes()).err(),
                Some(CatalogError::TemporarilyUnavailable)
            );
        }
        for rejected in [
            r#"{"resultCode":true,"result":{"ipc":[]}}"#,
            r#"{"resultCode":1002,"result":{"ipc":[]}}"#,
            r#"{"resultCode":"01001","result":{"ipc":[]}}"#,
        ] {
            assert_eq!(
                parse_authenticated_device_list(rejected.as_bytes()).err(),
                Some(CatalogError::NotAuthenticated)
            );
        }
    }

    #[test]
    fn reference_accessory_collections_do_not_become_fake_cameras() {
        let result = br#"{"resultCode":1001,"result":{
            "NVR":[{"deviceID":1,"snNum":"not-camera"}],
            "nvr-neutral":[],
            "base":[{"deviceID":2,"snNum":"not-camera"}],
            "chime":[{"deviceID":3,"snNum":"not-camera"}],
            "ipc":[{"deviceID":4,"snNum":"camera"}]
        }}"#;
        let catalog = parse_authenticated_device_list(result).unwrap();
        assert_eq!(catalog.summary().cameras, 1);
        let accessories_only =
            br#"{"resultCode":"1001","result":{"nvr":[],"base":[],"chime":[]}}"#;
        assert_eq!(
            parse_authenticated_device_list(accessories_only)
                .unwrap()
                .summary()
                .cameras,
            0
        );
        let malformed =
            br#"{"resultCode":1001,"result":{"ipc":[],"base":{"deviceID":1}}}"#;
        assert_eq!(
            parse_authenticated_device_list(malformed).err(),
            Some(CatalogError::UnexpectedDeviceListShape)
        );
    }

    #[test]
    fn reference_direct_result_array_and_string_device_type() {
        let response = br#"{"resultCode":1001,"result":[
            {"deviceID":1,"snNum":"battery","devTypeID":"5"},
            {"deviceID":2,"snNum":"wired","devTypeID":0}
        ]}"#;
        let catalog = parse_authenticated_device_list(response).unwrap();
        assert_eq!(catalog.summary().cameras, 2);
        assert_eq!(catalog.summary().battery, 1);
        assert_eq!(catalog.summary().wired, 1);
        assert_eq!(
            parse_authenticated_device_list(
                br#"{"resultCode":1001,"result":[{"unrelated":"record"}]}"#
            )
            .err(),
            Some(CatalogError::UnexpectedDeviceListShape)
        );
    }

    #[test]
    fn account_shape_mismatch_does_not_fabricate_camera_compatibility() {
        let value = serde_json::json!({
            "resultCode": "1001",
            "result": {"unknownCameraCollection": [{
                "deviceID": "private-device", "snNum": "private-serial",
                "deviceP2P": "ppcs"
            }]}
        });
        assert_eq!(
            parse_authenticated_device_list(value.to_string().as_bytes()).err(),
            Some(CatalogError::UnexpectedDeviceListShape)
        );
    }

    #[test]
    fn model_and_ip_cannot_claim_identity_without_matching_mac() {
        for invalid in [
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "01:00:00:00:00:00",
            "02-ab-cd-12-34-56",
        ] {
            assert!(normalize_mac(invalid).is_none());
        }
        let payload = br#"{"resultCode":"1001","result":{"ipc":[
            {"deviceID":1,"snNum":"a","model":"b81","ip":"192.0.2.107"}
        ]}}"#;
        let catalog = parse_authenticated_device_list(payload).unwrap();
        assert_eq!(catalog.summary().cameras, 1);
        assert_eq!(catalog.summary().transport_unverified, 1);
        assert!(catalog.by_mac("02:ab:cd:12:34:56").is_none());
    }

    #[test]
    fn bounded_depth_and_record_count() {
        let mut nested = serde_json::json!({"deviceList":[{"deviceID":1,"snNum":"a"}]});
        for _ in 0..MAX_DEPTH + 2 {
            nested = serde_json::json!({"nest":nested});
        }
        let response = serde_json::json!({"resultCode":"1001","result":nested});
        assert_eq!(
            parse_authenticated_device_list(response.to_string().as_bytes()).err(),
            Some(CatalogError::InvalidJson)
        );
        let entries: Vec<_> = (0..=MAX_RECORDS)
            .map(|n| serde_json::json!({"deviceID":n,"snNum":format!("test-{n}")}))
            .collect();
        let response = serde_json::json!({"resultCode":"1001","result":{"deviceList":entries}});
        assert_eq!(
            parse_authenticated_device_list(response.to_string().as_bytes()).err(),
            Some(CatalogError::TooManyCameras)
        );
    }
}
