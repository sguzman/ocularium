//! Offline, mockable ANRAN/Meari account handshake.
//!
//! Protocol researched from the MIT-licensed
//! github.com/raulrojas22/Ha-CloudPlus-Meari-ANRAN
//! custom_components/cloudplus/{api.py,const.py} on 2026-10-17.
//! Production HTTPS is invoked only by a one-shot, consent-gated GUI action.
//! Its community backend is unverified for the household camera, and a real
//! login may disrupt an existing mobile session. Never guess passwords,
//! exports headers, or stores credentials/tokens in the registry.

use crate::meari_devices::{self, AuthorizedCatalog};
use aes::Aes128;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use cbc::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    Encryptor,
};
use des::Des;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

const REDIRECT_ORIGIN: &str = "https://apis.cloudedge360.com";
const REDIRECT_PATH: &str = "/ppstrongs/redirect";
const LOGIN_PATH: &str = "/meari/app/login";
const DEVICE_PATH: &str = "/v1/app/device/info/get";
const HOMES_PATH: &str = "/v1/app/home/list";
const SHARED_DEVICE_PATH: &str = "/v1/app/home/join/device/list";
const PLATFORM_PATH: &str = "/v2/app/config/pf/init";
/// Hard cap on additional account requests per explicit, one-shot UI action.
const MAX_SHARED_HOMES: usize = 8;
const CA_KEY: &str = "bc29be30292a4309877807e101afbd51";
const CA_SECRET: &str = "35a69fd1-6527-4566-b190-921f9a651488";
const DES_KEY: &[u8; 8] = b"12345678";
const DES_IV: &[u8; 8] = b"01234567";
const MAX_RESPONSE: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// Do not implement Debug, Serialize, Display or log this type.
/// Its params and headers can include encrypted credentials or tokens.
pub struct WireRequest {
    pub method: Method,
    pub origin: String,
    pub path: &'static str,
    pub params: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
}

impl Drop for WireRequest {
    fn drop(&mut self) {
        // Best-effort cleanup of the request's own signed headers and form
        // values. HTTP libraries may make additional transient copies.
        for value in self.params.values_mut().chain(self.headers.values_mut()) {
            value.zeroize();
        }
    }
}

/// Injectable transport boundary for synthetic tests and opt-in HTTPS.
pub trait Exchange {
    fn exchange(&mut self, request: WireRequest) -> Result<Vec<u8>, AuthError>;
}

/// Production HTTPS transport, invoked only on explicit GUI consent.
/// Only allowlisted HTTPS host families are permitted. No system
/// proxies, redirects, cookies, persistent sessions or account data on disk.
pub struct HttpsExchange {
    agent: ureq::Agent,
}
impl Default for HttpsExchange {
    fn default() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .try_proxy_from_env(false)
                .timeout_connect(std::time::Duration::from_secs(5))
                .timeout_read(std::time::Duration::from_secs(8))
                .timeout_write(std::time::Duration::from_secs(8))
                .build(),
        }
    }
}

impl Exchange for HttpsExchange {
    fn exchange(&mut self, request: WireRequest) -> Result<Vec<u8>, AuthError> {
        let expected_method = match request.path {
            REDIRECT_PATH | HOMES_PATH | SHARED_DEVICE_PATH | PLATFORM_PATH => Method::Get,
            LOGIN_PATH | DEVICE_PATH => Method::Post,
            _ => return Err(AuthError::InvalidServer),
        };
        if request.method != expected_method
            || (request.origin != REDIRECT_ORIGIN && allowed_api_origin(&request.origin).is_none())
        {
            return Err(AuthError::InvalidServer);
        }
        let url = format!("{}{}", request.origin, request.path);
        let headers = &request.headers;
        let params: Vec<(&str, &str)> = request
            .params
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let builder = match request.method {
            Method::Get => {
                let mut call = self.agent.get(&url);
                for (key, value) in &params {
                    call = call.query(key, value);
                }
                call
            }
            Method::Post => self.agent.post(&url),
        };
        let mut builder = builder.set("Accept", "application/json");
        for (name, value) in headers {
            builder = builder.set(name, value);
        }
        let response = match request.method {
            Method::Get => builder.call(),
            Method::Post => builder.send_form(&params),
        }
        .map_err(|_| AuthError::Transport)?;
        // Do not propagate response bodies or remote error descriptions:
        // servers might reflect account identifiers or session tokens.
        if response.status() != 200 {
            return Err(AuthError::Transport);
        }
        use std::io::Read as _;
        let mut body = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| AuthError::Transport)?;
        if body.len() > MAX_RESPONSE {
            return Err(AuthError::InvalidReply);
        }
        Ok(body)
    }
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn next(&mut self) -> Stamp {
        use std::time::{SystemTime, UNIX_EPOCH};
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |now| now.as_millis().min(i64::MAX as u128) as i64);
        // OS-seeded UUID v4 is generated by the already-present uuid crate.
        let nonce: String = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(12)
            .collect();
        Stamp {
            epoch_ms: millis,
            nonce,
        }
    }
}

pub struct Credentials {
    pub account: Zeroizing<String>,
    pub password: Zeroizing<String>,
    pub country: String,
    pub phone_code: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    InvalidInput,
    InvalidServer,
    InvalidReply,
    LoginRejected,
    DeviceListRejected,
    DeviceListUnavailable(DeviceListDiagnostic),
    Transport,
}

/// Results for individual post-login device-list requests. Only fixed
/// categories, never vendor messages, raw JSON, URLs or token values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ListOutcome {
    #[default]
    NotRequested,
    Accepted,
    TransportFailed,
    TemporarilyUnavailable,
    Rejected,
    Malformed,
}

impl ListOutcome {
    fn safe_label(self) -> &'static str {
        match self {
            Self::NotRequested => "not requested",
            Self::Accepted => "accepted",
            Self::TransportFailed => "HTTP/network failure",
            Self::TemporarilyUnavailable => "temporarily unavailable",
            Self::Rejected => "request rejected",
            Self::Malformed => "unexpected response",
        }
    }
}

fn device_list_outcome(error: meari_devices::CatalogError) -> ListOutcome {
    match error {
        meari_devices::CatalogError::TemporarilyUnavailable => ListOutcome::TemporarilyUnavailable,
        meari_devices::CatalogError::NotAuthenticated => ListOutcome::Rejected,
        _ => ListOutcome::Malformed,
    }
}

/// A failed device-list search *after* a successful login. There are no raw
/// response codes, per-home IDs, account details or camera identities here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceListDiagnostic {
    pub default_list: ListOutcome,
    pub home_list: ListOutcome,
    pub shared_attempted: usize,
    pub shared_transport_failed: usize,
    pub shared_rejected: usize,
    pub shared_malformed: usize,
}

impl DeviceListDiagnostic {
    pub fn safe_text(self) -> String {
        format!(
            "Login was accepted, but camera-list retrieval failed.              Default list: {}; home list: {}; shared-home lists attempted: {},              HTTP/network failures: {}, rejected: {}, unexpected responses: {}.              No retry was attempted. No camera compatibility conclusion.",
            self.default_list.safe_label(),
            self.home_list.safe_label(),
            self.shared_attempted,
            self.shared_transport_failed,
            self.shared_rejected,
            self.shared_malformed,
        )
    }
}

/// Redacted completeness of an account's one-shot camera lookup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiscoveryCoverage {
    pub default_list_ok: bool,
    pub home_list_ok: bool,
    pub homes_attempted: usize,
    pub homes_succeeded: usize,
    pub homes_truncated: bool,
}

impl DiscoveryCoverage {
    pub fn safe_text(self) -> String {
        let complete = self.default_list_ok
            && self.home_list_ok
            && self.homes_attempted == self.homes_succeeded
            && !self.homes_truncated;
        format!(
            "Camera list coverage: {}; default list={}; home list={};              shared homes checked={}; shared homes successful={}.              No automatic retries. An incomplete lookup can omit cameras.",
            if complete { "complete request sequence" } else { "partial / unverified" },
            if self.default_list_ok { "ok" } else { "unavailable" },
            if self.home_list_ok { "ok" } else { "unavailable" },
            self.homes_attempted,
            self.homes_succeeded,
        )
    }
}

/// Contains ephemeral camera records, never safe for Debug or serialization.
pub struct AccountDiscovery {
    catalog: AuthorizedCatalog,
    pub coverage: DiscoveryCoverage,
    pub platform: PlatformSummary,
}

impl AccountDiscovery {
    pub fn summary(&self) -> meari_devices::CatalogSummary {
        self.catalog.summary()
    }

    pub fn correlate_saved_macs(
        &self,
        saved: &[Option<String>],
    ) -> meari_devices::CatalogCorrelation {
        self.catalog.correlate_saved_macs(saved)
    }

    pub fn ppcs_metadata_summary(&self) -> meari_devices::PpcsMetadataSummary {
        self.catalog.ppcs_metadata_summary()
    }

    pub fn matched_ppcs_summary(
        &self,
        saved: &[Option<String>],
    ) -> meari_devices::MatchedPpcsSummary {
        self.catalog.matched_ppcs_summary(saved)
    }
}

/// Optional account configuration inspection. Only fixed, non-secret
/// booleans reach the UI; service hosts, signatures and keys are discarded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PlatformStatus {
    #[default]
    NotRequested,
    Available,
    TemporarilyUnavailable,
    Unavailable,
    InvalidReply,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlatformSummary {
    pub status: PlatformStatus,
    pub openapi_declared: bool,
    pub mqtt_declared: bool,
    pub platform_declared: bool,
    pub encrypted_signature_declared: bool,
}

impl PlatformSummary {
    pub fn safe_text(self) -> String {
        match self.status {
            PlatformStatus::NotRequested => "IoT platform config: not requested.".into(),
            PlatformStatus::TemporarilyUnavailable => {
                "IoT platform config: transiently unavailable; no retry.".into()
            }
            PlatformStatus::Unavailable => "IoT platform config: unavailable; no retry.".into(),
            PlatformStatus::InvalidReply => {
                "IoT platform config: invalid response; no retry.".into()
            }
            PlatformStatus::Available => format!(
                "IoT platform config: present; OpenAPI declared={}, MQTT declared={}, \
                 platform declared={}, encrypted platform signature declared={}. \
                 No endpoints, credentials or connectivity verified.",
                self.openapi_declared,
                self.mqtt_declared,
                self.platform_declared,
                self.encrypted_signature_declared,
            ),
        }
    }
}

/// Read only the shape of the configuration. Never return vendor URLs,
/// access IDs, access keys, decrypted secrets, or raw JSON.
fn summarize_platform_response(bytes: &[u8]) -> PlatformSummary {
    let result = match read_json(bytes) {
        Ok(value) => value,
        Err(_) => {
            return PlatformSummary {
                status: PlatformStatus::InvalidReply,
                ..Default::default()
            };
        }
    };
    match result.get("resultCode").and_then(serde_json::Value::as_str) {
        Some("1023") => PlatformSummary {
            status: PlatformStatus::TemporarilyUnavailable,
            ..Default::default()
        },
        Some("1001") => {
            let Some(config) = result
                .pointer("/result/pfApi")
                .and_then(serde_json::Value::as_object)
            else {
                return PlatformSummary {
                    status: PlatformStatus::InvalidReply,
                    ..Default::default()
                };
            };
            let declared = |branch: &str, key: &str| {
                config
                    .get(branch)
                    .and_then(serde_json::Value::as_object)
                    .and_then(|object| object.get(key))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty() && value.len() <= 2048)
            };
            PlatformSummary {
                status: PlatformStatus::Available,
                openapi_declared: declared("openapi", "domain"),
                mqtt_declared: declared("mqtt", "host"),
                platform_declared: declared("platform", "domain"),
                encrypted_signature_declared: declared("platform", "signature"),
            }
        }
        _ => PlatformSummary {
            status: PlatformStatus::Unavailable,
            ..Default::default()
        },
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiscoveryOptions {
    pub inspect_platform: bool,
}

impl From<meari_devices::CatalogError> for AuthError {
    fn from(_: meari_devices::CatalogError) -> Self {
        Self::DeviceListRejected
    }
}

pub struct Stamp {
    pub epoch_ms: i64,
    pub nonce: String,
}

/// Every request gets a fresh nonce from the caller, never a hard-coded one.
pub trait Clock {
    fn next(&mut self) -> Stamp;
}

struct Session {
    origin: String,
    user_id: Zeroizing<String>,
    token: Zeroizing<String>,
}

fn allowed_api_origin(input: &str) -> Option<String> {
    let hostname = input.strip_prefix("https://")?;
    // No cleartext, non-default ports, IP literals, credentials, subpaths,
    // query strings, fragments, or unknown API origins. No DNS calls here.
    if hostname.len() > 120
        || hostname.is_empty()
        || !hostname.is_ascii()
        || hostname.contains(['/', ':', '@', '?', '#', '[', ']'])
        || hostname.starts_with('.')
        || hostname.ends_with('.')
        || hostname.split('.').any(|part| {
            part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    if !["mearicloud.com", "cloudedge360.com", "meari.com.cn"]
        .iter()
        .any(|root| hostname == *root || hostname.ends_with(&format!(".{root}")))
    {
        return None;
    }
    Some(input.to_string())
}

fn hmac_b64(key: &str, text: &str) -> String {
    let mut signer =
        Hmac::<Sha1>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key size");
    signer.update(text.as_bytes());
    BASE64.encode(signer.finalize().into_bytes())
}

fn user_account_cipher(account: &str, path: &str, millis: i64) -> Result<String, AuthError> {
    // Reproduces the reference app's AES-CBC userAccount field. Legacy cipher
    // is a compatibility requirement, not modern password-storage guidance.
    let raw = format!("{path}84a{millis}");
    let b64 = BASE64.encode(raw.as_bytes());
    let key = b64.as_bytes().get(..16).ok_or(AuthError::InvalidInput)?;
    let encrypted = Encryptor::<Aes128>::new_from_slices(key, key)
        .map_err(|_| AuthError::InvalidInput)?
        .encrypt_padded_vec_mut::<Pkcs7>(account.as_bytes());
    Ok(BASE64.encode(encrypted))
}

fn password_cipher(password: &str) -> String {
    let encrypted = Encryptor::<Des>::new(DES_KEY.into(), DES_IV.into())
        .encrypt_padded_vec_mut::<Pkcs7>(password.as_bytes());
    BASE64.encode(encrypted)
}

fn ca_headers(
    path: &str,
    stamp: &Stamp,
    token: Option<&str>,
) -> Result<BTreeMap<String, String>, AuthError> {
    if stamp.epoch_ms <= 0
        || stamp.nonce.len() < 6
        || stamp.nonce.len() > 36
        || !stamp.nonce.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(AuthError::InvalidInput);
    }
    let millis = stamp.epoch_ms.to_string();
    let (ca_key, secret) = token.map_or((CA_KEY, CA_SECRET), |t| (t, t));
    let to_sign = format!(
        "api=/ppstrongs/{path}|X-Ca-Key={ca_key}|X-Ca-Timestamp={millis}|X-Ca-Nonce={}",
        stamp.nonce
    );
    Ok(BTreeMap::from([
        ("X-Ca-Timestamp".into(), millis),
        ("X-Ca-Key".into(), ca_key.into()),
        ("X-Ca-Nonce".into(), stamp.nonce.clone()),
        ("X-Ca-Sign".into(), hmac_b64(secret, &to_sign)),
    ]))
}

fn form_fields(
    stamp: &Stamp,
    credentials: &Credentials,
) -> Result<BTreeMap<String, String>, AuthError> {
    if credentials.country.len() != 2
        || !credentials.country.bytes().all(|b| b.is_ascii_uppercase())
        || credentials.phone_code.is_empty()
        || credentials.phone_code.len() > 4
        || !credentials.phone_code.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(AuthError::InvalidInput);
    }
    // Timestamp rendered in UTC explicitly. The reference uses local GMT
    // offsets; server compatibility will need hardware validation.
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(stamp.epoch_ms)
        .ok_or(AuthError::InvalidInput)?;
    let time = format!("{}GMT+00:00", dt.format("%Y-%m-%dT%H:%M:%S%.3f"));
    Ok(BTreeMap::from([
        ("phoneType".into(), "i".into()),
        ("sourceApp".into(), "84".into()),
        ("appVer".into(), "6.2.0".into()),
        ("appVerCode".into(), "2026071016".into()),
        ("countryCode".into(), credentials.country.clone()),
        ("phoneCode".into(), credentials.phone_code.clone()),
        ("lngType".into(), "es".into()),
        ("t".into(), stamp.epoch_ms.to_string()),
        ("timestamp".into(), time),
        ("signatureMethod".into(), "HMAC-SHA1".into()),
        ("signatureVersion".into(), "1.0".into()),
        ("signatureNonce".into(), stamp.epoch_ms.to_string()),
    ]))
}

fn read_json(bytes: &[u8]) -> Result<serde_json::Value, AuthError> {
    if bytes.len() > MAX_RESPONSE {
        return Err(AuthError::InvalidReply);
    }
    serde_json::from_slice(bytes).map_err(|_| AuthError::InvalidReply)
}

fn successful(value: &serde_json::Value) -> bool {
    value.get("resultCode").and_then(serde_json::Value::as_str) == Some("1001")
}

fn sign_form(fields: &mut BTreeMap<String, String>, token: &str) {
    let joined = fields
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    fields.insert("signature".into(), hmac_b64(token, &joined));
}

fn redirect_request(credentials: &Credentials, stamp: Stamp) -> Result<WireRequest, AuthError> {
    let mut params = form_fields(&stamp, credentials)?;
    params.remove("timestamp");
    params.remove("signatureMethod");
    params.remove("signatureVersion");
    params.remove("signatureNonce");
    params.insert("localTime".into(), stamp.epoch_ms.to_string());
    params.insert("nonce".into(), stamp.nonce.clone());
    params.insert("partnerId".into(), "84".into());
    params.insert(
        "sign".into(),
        format!(
            "{:x}",
            md5::compute(format!(
                "GET|{REDIRECT_PATH}|{}|apis.meari.com.cn",
                stamp.epoch_ms
            ))
        ),
    );
    params.insert(
        "userAccount".into(),
        user_account_cipher(&credentials.account, REDIRECT_PATH, stamp.epoch_ms)?,
    );
    Ok(WireRequest {
        method: Method::Get,
        origin: REDIRECT_ORIGIN.into(),
        path: REDIRECT_PATH,
        params,
        headers: ca_headers(REDIRECT_PATH, &stamp, None)?,
    })
}

fn login_request(
    credentials: &Credentials,
    origin: String,
    stamp: Stamp,
) -> Result<WireRequest, AuthError> {
    let mut params = form_fields(&stamp, credentials)?;
    for key in [
        "timestamp",
        "signatureMethod",
        "signatureVersion",
        "signatureNonce",
    ] {
        params.remove(key);
    }
    params.insert("localTime".into(), stamp.epoch_ms.to_string());
    params.insert(
        "userAccount".into(),
        user_account_cipher(&credentials.account, LOGIN_PATH, stamp.epoch_ms)?,
    );
    params.insert("password".into(), password_cipher(&credentials.password));
    params.insert("iotType".into(), "4".into());
    params.insert("equipmentNo".into(), " ".into());
    Ok(WireRequest {
        method: Method::Post,
        origin,
        path: LOGIN_PATH,
        params,
        headers: ca_headers(LOGIN_PATH, &stamp, None)?,
    })
}

fn device_request(
    credentials: &Credentials,
    session: &Session,
    stamp: Stamp,
) -> Result<WireRequest, AuthError> {
    let mut params = form_fields(&stamp, credentials)?;
    params.insert("userID".into(), session.user_id.as_str().to_owned());
    params.insert("funSwitch".into(), "1".into());
    sign_form(&mut params, &session.token);
    Ok(WireRequest {
        method: Method::Post,
        origin: session.origin.clone(),
        path: DEVICE_PATH,
        params,
        headers: ca_headers(DEVICE_PATH, &stamp, Some(&session.token))?,
    })
}

fn signed_home_request(
    credentials: &Credentials,
    session: &Session,
    path: &'static str,
    home_id: Option<&str>,
    stamp: Stamp,
) -> Result<WireRequest, AuthError> {
    if path != HOMES_PATH && path != SHARED_DEVICE_PATH {
        return Err(AuthError::InvalidInput);
    }
    if (path == SHARED_DEVICE_PATH) != home_id.is_some() {
        return Err(AuthError::InvalidInput);
    }
    let mut params = form_fields(&stamp, credentials)?;
    params.insert("userID".into(), session.user_id.as_str().to_owned());
    if let Some(home_id) = home_id {
        params.insert("homeID".into(), home_id.to_owned());
        params.insert("funSwitch".into(), "1".into());
    }
    sign_form(&mut params, &session.token);
    Ok(WireRequest {
        method: Method::Get,
        origin: session.origin.clone(),
        path,
        params,
        headers: ca_headers(path, &stamp, Some(&session.token))?,
    })
}

fn platform_request(
    credentials: &Credentials,
    session: &Session,
    stamp: Stamp,
) -> Result<WireRequest, AuthError> {
    let mut params = form_fields(&stamp, credentials)?;
    params.insert("userID".into(), session.user_id.as_str().to_owned());
    params.insert("iotType".into(), "4".into());
    sign_form(&mut params, &session.token);
    Ok(WireRequest {
        method: Method::Get,
        origin: session.origin.clone(),
        path: PLATFORM_PATH,
        params,
        headers: ca_headers(PLATFORM_PATH, &stamp, Some(&session.token))?,
    })
}

struct HomeIds {
    ids: Vec<Zeroizing<String>>,
    truncated: bool,
}

/// Accept only scalar home IDs and never use them as hosts, paths, or headers.
/// Extra homes are not queried; results are expressly marked incomplete.
fn parse_home_ids(bytes: &[u8]) -> Result<HomeIds, ListOutcome> {
    let result = read_json(bytes).map_err(|_| ListOutcome::Malformed)?;
    if !successful(&result) {
        return Err(
            if result.get("resultCode").and_then(serde_json::Value::as_str) == Some("1023") {
                ListOutcome::TemporarilyUnavailable
            } else {
                ListOutcome::Rejected
            },
        );
    }
    let home_result = result
        .get("result")
        .and_then(serde_json::Value::as_object)
        .ok_or(ListOutcome::Malformed)?;
    // The pinned reference treats a successful response without "homes"
    // as an empty household, not an authentication failure.
    let homes = match home_result.get("homes") {
        Some(serde_json::Value::Array(homes)) => homes.as_slice(),
        None => &[],
        _ => return Err(ListOutcome::Malformed),
    };
    let mut ids = Vec::new();
    let mut truncated = homes.len() > MAX_SHARED_HOMES;
    for home in homes {
        let Some(value) = home.get("homeID") else {
            truncated = true;
            continue;
        };
        let raw = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => {
                truncated = true;
                continue;
            }
        };
        let raw = Zeroizing::new(raw);
        if raw.is_empty()
            || raw.len() > 64
            || !raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            truncated = true;
            continue;
        }
        if ids
            .iter()
            .any(|id: &Zeroizing<String>| id.as_str() == raw.as_str())
        {
            continue;
        }
        if ids.len() >= MAX_SHARED_HOMES {
            truncated = true;
            break;
        }
        ids.push(raw);
    }
    Ok(HomeIds { ids, truncated })
}

/// Mockable, one-shot account exchange. The GUI owns explicit consent.
/// No automatic retries or background requests.
pub fn discover_account<T: Exchange, C: Clock>(
    transport: &mut T,
    clock: &mut C,
    credentials: Credentials,
) -> Result<AccountDiscovery, AuthError> {
    discover_account_with_options(transport, clock, credentials, DiscoveryOptions::default())
}

/// Additional opt-in platform query is disabled by default and can never
/// trigger a retry or an additional login. It remains on the login's verified
/// API origin; returned service hosts are not contacted.
pub fn discover_account_with_options<T: Exchange, C: Clock>(
    transport: &mut T,
    clock: &mut C,
    mut credentials: Credentials,
    options: DiscoveryOptions,
) -> Result<AccountDiscovery, AuthError> {
    if credentials.account.is_empty()
        || credentials.account.len() > 254
        || credentials.password.is_empty()
        || credentials.password.len() > 256
    {
        return Err(AuthError::InvalidInput);
    }

    let redirect_bytes =
        Zeroizing::new(transport.exchange(redirect_request(&credentials, clock.next())?)?);
    let response = read_json(&redirect_bytes)?;
    drop(redirect_bytes);
    if !successful(&response) {
        return Err(AuthError::InvalidServer);
    }
    let server = response
        .pointer("/result/apiServer")
        .and_then(serde_json::Value::as_str)
        .ok_or(AuthError::InvalidServer)?;
    let origin = allowed_api_origin(server).ok_or(AuthError::InvalidServer)?;

    let login_request = login_request(&credentials, origin.clone(), clock.next())?;
    // The plaintext account/password are no longer needed after constructing
    // the login request; do not keep them for the device-list round trip.
    credentials.account.zeroize();
    credentials.password.zeroize();
    let login_bytes = Zeroizing::new(transport.exchange(login_request)?);
    let mut login = read_json(&login_bytes)?;
    drop(login_bytes);
    if !successful(&login) {
        return Err(AuthError::LoginRejected);
    }
    let user_id = login
        .pointer("/result/userID")
        .and_then(|v| match v {
            serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
        .filter(|id| id.len() <= 64)
        .ok_or(AuthError::InvalidReply)?;
    let token = login
        .pointer("/result/userToken")
        .and_then(serde_json::Value::as_str)
        .filter(|t| !t.is_empty() && t.len() <= 2048)
        .ok_or(AuthError::InvalidReply)?
        .to_owned();
    // Erase the parsed response's direct copies of these private values.
    if let Some(serde_json::Value::String(value)) = login.pointer_mut("/result/userID") {
        value.zeroize();
    }
    if let Some(serde_json::Value::String(value)) = login.pointer_mut("/result/userToken") {
        value.zeroize();
    }
    let session = Session {
        origin,
        user_id: Zeroizing::new(user_id),
        token: Zeroizing::new(token),
    };
    let platform = if options.inspect_platform {
        match transport.exchange(platform_request(&credentials, &session, clock.next())?) {
            Ok(raw) => {
                let raw = Zeroizing::new(raw);
                summarize_platform_response(&raw)
            }
            Err(_) => PlatformSummary {
                status: PlatformStatus::Unavailable,
                ..Default::default()
            },
        }
    } else {
        PlatformSummary::default()
    };
    let mut coverage = DiscoveryCoverage::default();
    let mut diagnostic = DeviceListDiagnostic::default();
    let mut catalog = meari_devices::parse_authenticated_device_list(
        br#"{"resultCode":"1001","result":{"ipc":[]}}"#,
    )?;
    // A shared-only account can have no default camera list. Preserve a
    // partial result instead of pretending the default list succeeded.
    match transport.exchange(device_request(&credentials, &session, clock.next())?) {
        Ok(raw) => {
            let raw = Zeroizing::new(raw);
            match meari_devices::parse_authenticated_device_list(&raw) {
                Ok(default_catalog) => {
                    diagnostic.default_list = ListOutcome::Accepted;
                    coverage.default_list_ok = true;
                    catalog.merge(default_catalog)?;
                }
                Err(error) => diagnostic.default_list = device_list_outcome(error),
            }
        }
        Err(_) => diagnostic.default_list = ListOutcome::TransportFailed,
    }

    match transport.exchange(signed_home_request(
        &credentials,
        &session,
        HOMES_PATH,
        None,
        clock.next(),
    )?) {
        Ok(raw) => {
            let raw = Zeroizing::new(raw);
            match parse_home_ids(&raw) {
                Ok(homes) => {
                    diagnostic.home_list = ListOutcome::Accepted;
                    coverage.home_list_ok = true;
                    coverage.homes_truncated = homes.truncated;
                    for home_id in homes.ids {
                        coverage.homes_attempted += 1;
                        diagnostic.shared_attempted += 1;
                        let request = signed_home_request(
                            &credentials,
                            &session,
                            SHARED_DEVICE_PATH,
                            Some(&home_id),
                            clock.next(),
                        )?;
                        match transport.exchange(request) {
                            Ok(response) => {
                                let response = Zeroizing::new(response);
                                // 1107 is the documented empty shared-home
                                // response, not a request error.
                                match read_json(&response) {
                                    Ok(parsed)
                                        if parsed
                                            .get("resultCode")
                                            .and_then(serde_json::Value::as_str)
                                            == Some("1107") =>
                                    {
                                        coverage.homes_succeeded += 1;
                                    }
                                    Ok(_) => {
                                        match meari_devices::parse_authenticated_device_list(
                                            &response,
                                        ) {
                                            Ok(shared_catalog) => {
                                                catalog.merge(shared_catalog)?;
                                                coverage.homes_succeeded += 1;
                                            }
                                            Err(meari_devices::CatalogError::NotAuthenticated)
                                            | Err(
                                                meari_devices::CatalogError::TemporarilyUnavailable,
                                            ) => {
                                                diagnostic.shared_rejected += 1;
                                            }
                                            Err(_) => diagnostic.shared_malformed += 1,
                                        }
                                    }
                                    Err(_) => diagnostic.shared_malformed += 1,
                                }
                            }
                            Err(_) => diagnostic.shared_transport_failed += 1,
                        }
                    }
                }
                Err(error) => diagnostic.home_list = error,
            }
        }
        Err(_) => diagnostic.home_list = ListOutcome::TransportFailed,
    }
    if !coverage.default_list_ok && coverage.homes_succeeded == 0 {
        return Err(AuthError::DeviceListUnavailable(diagnostic));
    }
    Ok(AccountDiscovery {
        catalog,
        coverage,
        platform,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestClock {
        n: u32,
    }
    impl Clock for TestClock {
        fn next(&mut self) -> Stamp {
            self.n += 1;
            Stamp {
                epoch_ms: 1_700_000_000_000,
                nonce: format!("12345{}", self.n),
            }
        }
    }
    fn account() -> Credentials {
        Credentials {
            account: Zeroizing::new("test@example.com".into()),
            password: Zeroizing::new("example-password".into()),
            country: "MX".into(),
            phone_code: "52".into(),
        }
    }
    struct Fixture {
        calls: usize,
    }
    impl Exchange for Fixture {
        fn exchange(&mut self, request: WireRequest) -> Result<Vec<u8>, AuthError> {
            self.calls += 1;
            assert!(!request.origin.contains("http://"));
            match self.calls {
                1 => {
                    assert_eq!(request.origin, REDIRECT_ORIGIN);
                    assert_eq!(request.path, REDIRECT_PATH);
                    assert_eq!(request.method, Method::Get);
                    assert_eq!(request.params.get("partnerId").unwrap(), "84");
                    assert_eq!(
                        request.params.get("userAccount").unwrap(),
                        "pIwr3RCVc8chOlAEBnyveA1ESpEe2nXQzt/cyX5oQ7I="
                    );
                    assert_eq!(
                        request.params.get("sign").unwrap(),
                        "854295bbabb44a0df2f72dcebaa3d524"
                    );
                    Ok(br#"{"resultCode":"1001","result":{"apiServer":"https://apis-usce.mearicloud.com"}}"#.to_vec())
                }
                2 => {
                    assert_eq!(request.path, LOGIN_PATH);
                    assert_eq!(request.method, Method::Post);
                    assert_eq!(
                        request.params.get("password").unwrap(),
                        "Xtdq1G25Pq72SreiGApiyOkjhlOYCWX4"
                    );
                    Ok(br#"{"resultCode":"1001","result":{"userID":123,"userToken":"fixture-secret-token"}}"#.to_vec())
                }
                3 => {
                    assert_eq!(request.path, DEVICE_PATH);
                    assert_eq!(request.method, Method::Post);
                    assert!(request.headers.get("X-Ca-Key").unwrap() == "fixture-secret-token");
                    assert!(request.params.contains_key("signature"));
                    Ok(br#"{"resultCode":"1001","result":{"ipc":[{"deviceID":1,"snNum":"FAKE-DEVICE","deviceP2P":"ppcs"}]}}"#.to_vec())
                }
                4 => {
                    assert_eq!(request.path, HOMES_PATH);
                    assert_eq!(request.method, Method::Get);
                    assert!(request.params.contains_key("signature"));
                    assert!(!request.params.contains_key("homeID"));
                    Ok(br#"{"resultCode":"1001","result":{"homes":[]}}"#.to_vec())
                }
                _ => panic!("Unexpected network request"),
            }
        }
    }
    #[test]
    fn reference_post_login_fields_match_independent_us_signature_vectors() {
        // Python hmac/sha1+base64 produced these vectors from the pinned
        // upstream _base_params/_sign_params shape, using a fictional token.
        let credentials = Credentials {
            account: Zeroizing::new("fictional@example.invalid".into()),
            password: Zeroizing::new("fictional-password".into()),
            country: "US".into(),
            phone_code: "1".into(),
        };
        let stamp = || Stamp {
            epoch_ms: 1_700_000_000_000,
            nonce: "12345678".into(),
        };
        let session = Session {
            origin: "https://apis-usce.mearicloud.com".into(),
            user_id: Zeroizing::new("123".into()),
            token: Zeroizing::new("fixture-secret-token".into()),
        };
        let redirect = redirect_request(&credentials, stamp()).unwrap();
        let login = login_request(&credentials, session.origin.clone(), stamp()).unwrap();
        assert!(redirect.params.contains_key("localTime"));
        assert!(login.params.contains_key("localTime"));

        let default = device_request(&credentials, &session, stamp()).unwrap();
        let homes = signed_home_request(&credentials, &session, HOMES_PATH, None, stamp()).unwrap();
        let shared = signed_home_request(
            &credentials,
            &session,
            SHARED_DEVICE_PATH,
            Some("fictional-home"),
            stamp(),
        )
        .unwrap();
        let platform = platform_request(&credentials, &session, stamp()).unwrap();
        for request in [&default, &homes, &shared, &platform] {
            assert!(!request.params.contains_key("localTime"));
            assert_eq!(request.params.get("countryCode").unwrap(), "US");
            assert_eq!(request.params.get("phoneCode").unwrap(), "1");
            assert_eq!(request.params.get("userID").unwrap(), "123");
        }
        assert_eq!(
            default.params.get("signature").unwrap(),
            "amfS1DcXgdMWjUKaoBcchhqfrC4="
        );
        assert_eq!(
            homes.params.get("signature").unwrap(),
            "q13w/SSCemcv7ExQMse7r6IE0MU="
        );
        assert_eq!(default.params.get("funSwitch").unwrap(), "1");
        assert!(!homes.params.contains_key("funSwitch"));
        assert_eq!(shared.params.get("homeID").unwrap(), "fictional-home");
    }

    #[test]
    fn valid_home_response_with_omitted_homes_is_empty_without_extra_calls() {
        let mut transport = ListFailureFixture {
            calls: 0,
            default_response: Some(br#"{"resultCode":"1001","result":{"ipc":[]}}"#),
            home_response: Some(br#"{"resultCode":"1001","result":{}}"#),
        };
        let result = discover_account(&mut transport, &mut TestClock { n: 0 }, account()).unwrap();
        assert!(result.coverage.default_list_ok);
        assert!(result.coverage.home_list_ok);
        assert_eq!(result.coverage.homes_attempted, 0);
        assert_eq!(transport.calls, 4);
    }

    #[test]
    fn one_shot_anran_login_queries_default_list_and_home_list() {
        let mut transport = Fixture { calls: 0 };
        let mut clock = TestClock { n: 0 };
        let catalog = discover_account(&mut transport, &mut clock, account()).unwrap();
        assert_eq!(catalog.summary().cameras, 1);
        assert_eq!(catalog.summary().ppcs, 1);
        assert_eq!(transport.calls, 4);
        assert_eq!(
            catalog.coverage,
            DiscoveryCoverage {
                default_list_ok: true,
                home_list_ok: true,
                ..Default::default()
            }
        );
    }
    struct SharedFixture {
        calls: usize,
        default_failure: bool,
        reject_shared: bool,
    }

    impl Exchange for SharedFixture {
        fn exchange(&mut self, request: WireRequest) -> Result<Vec<u8>, AuthError> {
            self.calls += 1;
            match self.calls {
                1 => Ok(
                    br#"{"resultCode":"1001","result":{"apiServer":"https://apis-usce.mearicloud.com"}}"#
                        .to_vec(),
                ),
                2 => Ok(
                    br#"{"resultCode":"1001","result":{"userID":1,"userToken":"private-token"}}"#
                        .to_vec(),
                ),
                3 => {
                    assert_eq!(request.path, DEVICE_PATH);
                    if self.default_failure {
                        Ok(br#"{"resultCode":"1023"}"#.to_vec())
                    } else {
                        Ok(
                            br#"{"resultCode":"1001","result":{"ipc":[
                              {"deviceID":"alpha","snNum":"private-a","deviceP2P":"ppcs"}
                            ]}}"#
                                .to_vec(),
                        )
                    }
                }
                4 => {
                    assert_eq!(request.path, HOMES_PATH);
                    assert_eq!(request.method, Method::Get);
                    assert_eq!(request.headers.get("X-Ca-Key").unwrap(), "private-token");
                    assert!(request.params.contains_key("signature"));
                    Ok(
                        br#"{"resultCode":"1001","result":{"homes":[
                            {"homeID":"test-home-1"},{"homeID":202}
                        ]}}"#
                            .to_vec(),
                    )
                }
                5 => {
                    assert_eq!(request.path, SHARED_DEVICE_PATH);
                    assert_eq!(request.method, Method::Get);
                    assert_eq!(request.params.get("homeID").unwrap(), "test-home-1");
                    assert_eq!(request.params.get("funSwitch").unwrap(), "1");
                    assert!(request.params.contains_key("signature"));
                    if self.reject_shared {
                        Ok(b"not-json".to_vec())
                    } else {
                        Ok(
                            br#"{"resultCode":"1001","result":{"deviceList":[
                                {"deviceID":"alpha","snNum":"private-a",
                                 "deviceP2P":"webrtc","mac":"02:aa:bb:cc:dd:ee"},
                                {"deviceID":"beta","snNum":"private-b","deviceP2P":"ppcs"}
                            ]}}"#
                                .to_vec(),
                        )
                    }
                }
                6 => {
                    assert_eq!(request.path, SHARED_DEVICE_PATH);
                    assert_eq!(request.params.get("homeID").unwrap(), "202");
                    Ok(br#"{"resultCode":"1107"}"#.to_vec())
                }
                _ => panic!("One-shot login must not retry or fetch unlisted homes"),
            }
        }
    }

    struct ListFailureFixture {
        calls: usize,
        default_response: Option<&'static [u8]>,
        home_response: Option<&'static [u8]>,
    }

    impl Exchange for ListFailureFixture {
        fn exchange(&mut self, request: WireRequest) -> Result<Vec<u8>, AuthError> {
            self.calls += 1;
            match request.path {
                REDIRECT_PATH => Ok(br#"{"resultCode":"1001","result":{"apiServer":"https://apis-usce.mearicloud.com"}}"#.to_vec()),
                LOGIN_PATH => Ok(br#"{"resultCode":"1001","result":{"userID":"private-user","userToken":"private-session-token"}}"#.to_vec()),
                DEVICE_PATH => self.default_response.map(|body| body.to_vec()).ok_or(AuthError::Transport),
                HOMES_PATH => self.home_response.map(|body| body.to_vec()).ok_or(AuthError::Transport),
                _ => panic!("no unexpected retries or shared-home calls"),
            }
        }
    }

    #[test]
    fn successful_login_and_two_transport_failures_report_precise_redacted_stages() {
        let mut transport = ListFailureFixture {
            calls: 0,
            default_response: None,
            home_response: None,
        };
        let mut us = account();
        us.country = "US".into();
        us.phone_code = "1".into();
        let failure = discover_account(&mut transport, &mut TestClock { n: 0 }, us)
            .err()
            .unwrap();
        let AuthError::DeviceListUnavailable(diag) = failure else {
            panic!("login passed; expected device-list-stage failure");
        };
        assert_eq!(transport.calls, 4);
        assert_eq!(diag.default_list, ListOutcome::TransportFailed);
        assert_eq!(diag.home_list, ListOutcome::TransportFailed);
        assert_eq!(diag.shared_attempted, 0);
        let safe = diag.safe_text();
        assert!(safe.contains("Login was accepted"));
        for secret in ["private-session-token", "private-user", "test@example.com"] {
            assert!(!safe.contains(secret));
        }
    }

    #[test]
    fn response_diagnostics_separate_transient_rejection_and_malformed_shapes() {
        let cases = [
            (
                br#"{"resultCode":"1023"}"#.as_slice(),
                br#"{"resultCode":"1002"}"#.as_slice(),
                ListOutcome::TemporarilyUnavailable,
                ListOutcome::Rejected,
            ),
            (
                br#"{"resultCode":"1002","userAccount":"private-user"}"#.as_slice(),
                br#"{"resultCode":"1001","result":{}}"#.as_slice(),
                ListOutcome::Rejected,
                ListOutcome::Malformed,
            ),
            (
                b"not-json".as_slice(),
                br#"{"resultCode":"1023"}"#.as_slice(),
                ListOutcome::Malformed,
                ListOutcome::TemporarilyUnavailable,
            ),
            (
                br#"{"resultCode":"1001","result":{"unknownList":[]}}"#.as_slice(),
                br#"{"resultCode":"1001","result":{"homes":[]}}"#.as_slice(),
                ListOutcome::Malformed,
                ListOutcome::Accepted,
            ),
        ];
        for (default, homes, default_expected, home_expected) in cases {
            let mut transport = ListFailureFixture {
                calls: 0,
                default_response: Some(default),
                home_response: Some(homes),
            };
            let failure = discover_account(&mut transport, &mut TestClock { n: 0 }, account())
                .err()
                .unwrap();
            let AuthError::DeviceListUnavailable(diag) = failure else {
                panic!("expected redacted device-list diagnostics");
            };
            assert_eq!(diag.default_list, default_expected);
            assert_eq!(diag.home_list, home_expected);
            assert_eq!(transport.calls, 4);
            assert!(!diag.safe_text().contains("private-user"));
        }
    }

    #[test]
    fn successful_empty_device_list_is_not_a_transport_failure() {
        let mut transport = ListFailureFixture {
            calls: 0,
            default_response: Some(br#"{"resultCode":"1001","result":{"ipc":[]}}"#),
            home_response: Some(br#"{"resultCode":"1001","result":{"homes":[]}}"#),
        };
        let result = discover_account(&mut transport, &mut TestClock { n: 0 }, account()).unwrap();
        assert!(result.coverage.default_list_ok);
        assert!(result.coverage.home_list_ok);
        assert_eq!(result.summary().cameras, 0);
        assert_eq!(transport.calls, 4);
    }

    #[test]
    fn shared_home_augmentation_merges_on_device_id_and_preserves_coverage() {
        let mut transport = SharedFixture {
            calls: 0,
            default_failure: false,
            reject_shared: false,
        };
        let mut clock = TestClock { n: 0 };
        let discovered = discover_account(&mut transport, &mut clock, account()).unwrap();
        assert_eq!(transport.calls, 6);
        assert_eq!(discovered.summary().cameras, 2);
        assert_eq!(discovered.summary().signaling, 1);
        assert_eq!(discovered.summary().ppcs, 1);
        assert_eq!(
            discovered.coverage,
            DiscoveryCoverage {
                default_list_ok: true,
                home_list_ok: true,
                homes_attempted: 2,
                homes_succeeded: 2,
                homes_truncated: false,
            }
        );
        assert!(discovered
            .coverage
            .safe_text()
            .contains("complete request sequence"));
        let safe = discovered.coverage.safe_text();
        assert!(!safe.contains("test-home-1"));
        assert!(!safe.contains("private"));
    }

    #[test]
    fn shared_only_account_does_not_require_default_camera_list_success() {
        let mut transport = SharedFixture {
            calls: 0,
            default_failure: true,
            reject_shared: false,
        };
        let mut clock = TestClock { n: 0 };
        let discovered = discover_account(&mut transport, &mut clock, account()).unwrap();
        assert_eq!(transport.calls, 6);
        assert_eq!(discovered.summary().cameras, 2);
        assert!(!discovered.coverage.default_list_ok);
        assert_eq!(discovered.coverage.homes_succeeded, 2);
        assert!(discovered
            .coverage
            .safe_text()
            .contains("partial / unverified"));
    }

    #[test]
    fn malformed_shared_home_is_incomplete_with_no_retries() {
        let mut transport = SharedFixture {
            calls: 0,
            default_failure: false,
            reject_shared: true,
        };
        let mut clock = TestClock { n: 0 };
        let discovered = discover_account(&mut transport, &mut clock, account()).unwrap();
        assert_eq!(transport.calls, 6);
        assert_eq!(discovered.summary().cameras, 1);
        assert_eq!(discovered.coverage.homes_attempted, 2);
        assert_eq!(discovered.coverage.homes_succeeded, 1);
        assert!(discovered
            .coverage
            .safe_text()
            .contains("partial / unverified"));
    }

    #[test]
    fn shared_home_id_parser_dedupes_validates_and_caps_requests() {
        let payload = br#"{"resultCode":"1001","result":{"homes":[
            {"homeID":"first"},{"homeID":"first"},{"homeID":"bad/home"},
            {"homeID":1},{"homeID":2},{"homeID":3},{"homeID":4},
            {"homeID":5},{"homeID":6},{"homeID":7},{"homeID":8},{"homeID":9}
        ]}}"#;
        let homes = parse_home_ids(payload).unwrap();
        assert_eq!(homes.ids.len(), MAX_SHARED_HOMES);
        assert!(homes.truncated);
        assert_eq!(homes.ids[0].as_str(), "first");
        assert_eq!(homes.ids[1].as_str(), "1");
        assert!(parse_home_ids(br#"{"resultCode":"1001","result":{}}"#)
            .unwrap()
            .ids
            .is_empty());
        assert!(parse_home_ids(br#"{"resultCode":"1001","result":{"homes":null}}"#).is_err());
        assert!(parse_home_ids(br#"{"resultCode":"1023"}"#).is_err());
    }

    #[test]
    fn platform_shape_inspection_redacts_endpoints_and_credentials() {
        let json = br#"{"resultCode":"1001","result":{"pfApi":{
            "openapi":{"domain":"https://private-openapi.example"},
            "mqtt":{"host":"private-broker.example","port":1883},
            "platform":{"domain":"private-platform.example",
                        "signature":"private-encrypted-signature",
                        "expireTime":"123"}
        }},"secret":"private-account-token"}"#;
        let summary = summarize_platform_response(json);
        assert_eq!(
            summary,
            PlatformSummary {
                status: PlatformStatus::Available,
                openapi_declared: true,
                mqtt_declared: true,
                platform_declared: true,
                encrypted_signature_declared: true,
            }
        );
        let display = summary.safe_text();
        for secret in [
            "private-openapi.example",
            "private-broker.example",
            "private-platform.example",
            "private-encrypted-signature",
            "private-account-token",
        ] {
            assert!(!display.contains(secret));
        }
    }

    #[test]
    fn optional_platform_parser_distinguishes_transient_and_bad_responses() {
        assert_eq!(
            summarize_platform_response(br#"{"resultCode":"1023"}"#).status,
            PlatformStatus::TemporarilyUnavailable,
        );
        assert_eq!(
            summarize_platform_response(br#"{"resultCode":"1002"}"#).status,
            PlatformStatus::Unavailable,
        );
        for input in [
            b"not-json".as_slice(),
            br#"{"resultCode":"1001","result":{}}"#.as_slice(),
            br#"{"resultCode":"1001","result":{"pfApi":[]}}"#.as_slice(),
        ] {
            assert_eq!(
                summarize_platform_response(input).status,
                PlatformStatus::InvalidReply,
            );
        }
    }

    struct PlatformFixture {
        calls: usize,
        status: &'static [u8],
    }

    impl Exchange for PlatformFixture {
        fn exchange(&mut self, request: WireRequest) -> Result<Vec<u8>, AuthError> {
            self.calls += 1;
            match self.calls {
                1 => {
                    assert_eq!(request.path, REDIRECT_PATH);
                    Ok(br#"{"resultCode":"1001","result":{"apiServer":"https://apis-usce.mearicloud.com"}}"#.to_vec())
                }
                2 => {
                    assert_eq!(request.path, LOGIN_PATH);
                    Ok(br#"{"resultCode":"1001","result":{"userID":3,"userToken":"private-token"}}"#.to_vec())
                }
                3 => {
                    assert_eq!(request.path, PLATFORM_PATH);
                    assert_eq!(request.method, Method::Get);
                    assert_eq!(request.params.get("iotType").map(String::as_str), Some("4"));
                    assert_eq!(request.params.get("userID").map(String::as_str), Some("3"));
                    assert!(request.params.contains_key("signature"));
                    assert_eq!(
                        request.headers.get("X-Ca-Key").map(String::as_str),
                        Some("private-token")
                    );
                    Ok(self.status.to_vec())
                }
                4 => {
                    assert_eq!(request.path, DEVICE_PATH);
                    Ok(br#"{"resultCode":"1001","result":{"ipc":[
                        {"deviceID":1,"snNum":"sample"}
                    ]}}"#
                        .to_vec())
                }
                5 => {
                    assert_eq!(request.path, HOMES_PATH);
                    Ok(br#"{"resultCode":"1001","result":{"homes":[]}}"#.to_vec())
                }
                _ => panic!("Unexpected additional request after one-shot platform inspection"),
            }
        }
    }

    #[test]
    fn optional_platform_query_is_exactly_one_signed_get() {
        let mut mock = PlatformFixture {
            calls: 0,
            status: br#"{"resultCode":"1001","result":{"pfApi":{
                "platform":{"domain":"private.example","signature":"encrypted-private"}
            }}}"#,
        };
        let found = discover_account_with_options(
            &mut mock,
            &mut TestClock { n: 0 },
            account(),
            DiscoveryOptions {
                inspect_platform: true,
            },
        )
        .unwrap();
        assert_eq!(mock.calls, 5);
        assert_eq!(found.summary().cameras, 1);
        assert_eq!(found.platform.status, PlatformStatus::Available);
        assert!(found.platform.encrypted_signature_declared);
        assert!(!found.platform.safe_text().contains("private.example"));
    }

    #[test]
    fn transient_platform_failure_never_retries_or_blocks_camera_discovery() {
        let mut mock = PlatformFixture {
            calls: 0,
            status: br#"{"resultCode":"1023"}"#,
        };
        let found = discover_account_with_options(
            &mut mock,
            &mut TestClock { n: 0 },
            account(),
            DiscoveryOptions {
                inspect_platform: true,
            },
        )
        .unwrap();
        assert_eq!(mock.calls, 5);
        assert_eq!(
            found.platform.status,
            PlatformStatus::TemporarilyUnavailable
        );
        assert_eq!(found.summary().cameras, 1);
    }

    #[test]
    fn known_answer_crypto_vectors_match_independent_implementation() {
        let t = Stamp {
            epoch_ms: 1_700_000_000_000,
            nonce: "123456".into(),
        };
        assert_eq!(
            user_account_cipher("test@example.com", REDIRECT_PATH, t.epoch_ms).unwrap(),
            "pIwr3RCVc8chOlAEBnyveA1ESpEe2nXQzt/cyX5oQ7I="
        );
        assert_eq!(
            password_cipher("example-password"),
            "Xtdq1G25Pq72SreiGApiyOkjhlOYCWX4"
        );
        assert_eq!(
            ca_headers(REDIRECT_PATH, &t, None)
                .unwrap()
                .get("X-Ca-Sign")
                .unwrap(),
            "uM2XgqVtuV2K7LzG7O8Uo051zB4="
        );
    }
    #[test]
    fn reject_non_allowlisted_redirect_origins() {
        for url in [
            "http://apis-usce.mearicloud.com",
            "https://8.8.8.8",
            "https://apis-usce.mearicloud.com.evil.org",
            "https://user@apis-usce.mearicloud.com",
            "https://apis-usce.mearicloud.com:443",
            "https://apis-usce.mearicloud.com/redirect",
            "https://127.0.0.1",
            "https://evil.com",
        ] {
            assert!(
                allowed_api_origin(url).is_none(),
                "unsafe redirect must be denied"
            );
        }
        assert!(allowed_api_origin("https://apis-usce.mearicloud.com").is_some());
    }
    #[test]
    fn invalid_region_never_reaches_any_transport() {
        struct MustNotConnect;
        impl Exchange for MustNotConnect {
            fn exchange(&mut self, _: WireRequest) -> Result<Vec<u8>, AuthError> {
                panic!("invalid user input must not reach HTTPS")
            }
        }
        let mut invalid = account();
        invalid.country = "mx".into();
        let mut clock = TestClock { n: 0 };
        assert!(matches!(
            discover_account(&mut MustNotConnect, &mut clock, invalid),
            Err(AuthError::InvalidInput)
        ));
    }

    #[test]
    fn reject_wrong_password_without_retry_or_device_request() {
        struct RejectLogin {
            requests: usize,
        }
        impl Exchange for RejectLogin {
            fn exchange(&mut self, request: WireRequest) -> Result<Vec<u8>, AuthError> {
                self.requests += 1;
                match request.path {
                    REDIRECT_PATH => Ok(br#"{"resultCode":"1001","result":{"apiServer":"https://apis-usce.mearicloud.com"}}"#.to_vec()),
                    LOGIN_PATH => Ok(br#"{"resultCode":"1002","resultMsg":"private details ignored"}"#.to_vec()),
                    _ => panic!("No device requests permitted after rejected login"),
                }
            }
        }
        let mut mock = RejectLogin { requests: 0 };
        let mut clock = TestClock { n: 0 };
        assert!(matches!(
            discover_account(&mut mock, &mut clock, account()),
            Err(AuthError::LoginRejected)
        ));
        assert_eq!(mock.requests, 2);
    }
}
