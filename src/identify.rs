//! Offline, bounded, unauthenticated hints about LAN devices.
//! Never connects to hosts supplied in discovery responses or uses credentials.
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, TcpStream},
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpInfo {
    pub port: u16,
    pub server: Option<String>,
    pub realm: Option<String>,
    pub title: Option<String>,
}

impl HttpInfo {
    pub fn camera_hint(&self) -> bool {
        [self.server.as_deref(), self.realm.as_deref(), self.title.as_deref()]
            .into_iter()
            .flatten()
            .any(camera_words)
    }
}

pub fn camera_words(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "ip camera",
        "ipcam",
        "network camera",
        "hikvision",
        "dahua",
        "reolink",
        "foscam",
        "amcrest",
        "vivotek",
        "axis camera",
        "onvif",
        "camera web",
        "network video recorder",
    ]
    .iter()
    .any(|word| lower.contains(word))
}

/// Intentionally reads a small public HTTP response, with no credentials and
/// no following redirects. 443 is not probed (TLS is not HTTP plaintext).
pub fn http_hint(mut stream: TcpStream, ip: Ipv4Addr, port: u16) -> Option<HttpInfo> {
    let timeout = Duration::from_millis(260);
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let request = format!(
        "GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Ocularium/0.1\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut buffer = [0u8; 4096];
    let count = stream.read(&mut buffer).ok()?;
    let response = String::from_utf8_lossy(&buffer[..count]);
    parse_http(&response, port)
}

fn limit(value: &str) -> String {
    value.trim().chars().take(140).collect()
}

fn extract_html_title(response: &str) -> Option<String> {
    let lowercase = response.to_ascii_lowercase();
    let start = lowercase.find("<title>")? + "<title>".len();
    let end = lowercase[start..].find("</title>")? + start;
    let title = limit(&response[start..end]);
    (!title.is_empty()).then_some(title)
}

pub fn parse_http(response: &str, port: u16) -> Option<HttpInfo> {
    if !response.starts_with("HTTP/1.") {
        return None;
    }
    let headers = response.split_once("\r\n\r\n").map_or(response, |(head, _)| head);
    let read_header = |key: &str| -> Option<String> {
        headers.lines().filter_map(|line| line.split_once(':')).find_map(
            |(name, value)| name.trim().eq_ignore_ascii_case(key).then(|| limit(value)),
        )
    };
    let realm = read_header("WWW-Authenticate").and_then(|value| {
        let at = value.to_ascii_lowercase().find("realm=")?;
        let mut text = value[(at + 6)..].trim();
        if let Some(rest) = text.strip_prefix('"') {
            text = rest.split('"').next().unwrap_or("");
        } else {
            text = text.split(',').next().unwrap_or(text);
        }
        (!text.is_empty()).then(|| limit(text))
    });
    Some(HttpInfo {
        port,
        server: read_header("Server"),
        realm,
        title: extract_html_title(response),
    })
}

#[derive(Default)]
pub struct VendorRegistry {
    vendors: HashMap<String, String>,
}

impl VendorRegistry {
    /// Uses optional, preinstalled Linux data. No online queries or invented
    /// vendor names. Missing files simply result in unknown manufacturer.
    pub fn load() -> Self {
        let mut vendors = HashMap::new();
        for path in [
            "/usr/share/hwdata/oui.txt",
            "/usr/share/ieee-data/oui.txt",
            "/usr/share/nmap/nmap-mac-prefixes",
        ] {
            if let Ok(contents) = fs::read_to_string(path) {
                for line in contents.lines() {
                    if let Some((prefix, vendor)) = parse_vendor_line(line) {
                        vendors.entry(prefix).or_insert(vendor);
                    }
                }
            }
        }
        Self { vendors }
    }

    pub fn vendor(&self, mac: &str) -> Option<String> {
        let raw: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if raw.len() != 12 {
            return None;
        }
        let first = u8::from_str_radix(&raw[..2], 16).ok()?;
        if first & 0x02 != 0 {
            return Some("Locally administered MAC".to_owned());
        }
        self.vendors.get(&raw[..6].to_ascii_uppercase()).cloned()
    }

    pub fn available(&self) -> bool {
        !self.vendors.is_empty()
    }
}

fn parse_vendor_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') || trimmed.is_empty() {
        return None;
    }
    let mut fields = trimmed.split_whitespace();
    let first = fields.next()?;
    let prefix: String = first.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if prefix.len() != 6 || !first.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '-') {
        return None;
    }
    let rest = trimmed[first.len()..].trim();
    let rest = rest
        .strip_prefix("(hex)")
        .or_else(|| rest.strip_prefix("(base 16)"))
        .unwrap_or(rest)
        .trim();
    if rest.is_empty() {
        return None;
    }
    Some((prefix.to_ascii_uppercase(), limit(rest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_oui_formats() {
        assert_eq!(
            parse_vendor_line("00:00:00\tXerox Corporation"),
            Some(("000000".into(), "Xerox Corporation".into()))
        );
        assert_eq!(
            parse_vendor_line("00-00-01   (hex)   Another Company"),
            Some(("000001".into(), "Another Company".into()))
        );
        assert_eq!(
            parse_vendor_line("000002 Vendor Name"),
            Some(("000002".into(), "Vendor Name".into()))
        );
        assert_eq!(parse_vendor_line("not-a-oui Vendor"), None);
    }

    #[test]
    fn locally_administered_macs_are_not_vendor_identified() {
        let registry = VendorRegistry::default();
        assert_eq!(
            registry.vendor("7e:e0:1b:6e:fc:09").as_deref(),
            Some("Locally administered MAC")
        );
        assert_eq!(registry.vendor("invalid"), None);
    }

    #[test]
    fn detects_camera_http_banners() {
        let info = parse_http(
            "HTTP/1.1 401 Unauthorized\r\nServer: lighttpd\r\nWWW-Authenticate: Basic realm=\"IP Camera\"\r\n\r\n",
            80,
        )
        .unwrap();
        assert_eq!(info.server.as_deref(), Some("lighttpd"));
        assert_eq!(info.realm.as_deref(), Some("IP Camera"));
        assert!(info.camera_hint());
        let generic = parse_http("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nhello", 8080).unwrap();
        assert!(!generic.camera_hint());
    }

    #[test]
    fn handles_basic_html_titles() {
        let info = parse_http(
            "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html><TITLE>Network Camera</TITLE></html>",
            80,
        )
        .unwrap();
        assert_eq!(info.title.as_deref(), Some("Network Camera"));
    }
}
