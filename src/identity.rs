//! Credential-free enrichment from self-advertised ONVIF/UPnP descriptions.
//! Network requests are bounded and pinned to the *responding* device IP;
//! never follow links or redirects, use passwords, or fetch remote URLs.
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    time::Duration,
};

const IO_TIMEOUT: Duration = Duration::from_millis(1000);
const MAX_RESPONSE: usize = 65536;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityInfo {
    pub source: &'static str,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub model_number: Option<String>,
    pub device_type: Option<String>,
    pub firmware: Option<String>,
}

impl IdentityInfo {
    pub fn has_values(&self) -> bool {
        self.friendly_name.is_some() || self.manufacturer.is_some()
            || self.model.is_some() || self.model_number.is_some()
            || self.device_type.is_some() || self.firmware.is_some()
    }

    pub fn camera_hint(&self) -> bool {
        [
            self.friendly_name.as_deref(),
            self.model.as_deref(),
            self.model_number.as_deref(),
            self.device_type.as_deref(),
        ].into_iter().flatten().any(crate::identify::camera_words)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AdvertisedEndpoint {
    Ssdp { ip: Ipv4Addr, location: String },
    Onvif { ip: Ipv4Addr, address: String },
}

impl AdvertisedEndpoint {
    pub fn inspect(&self) -> Option<IdentityInfo> {
        match self {
            Self::Ssdp { ip, location } => inspect_ssdp(*ip, location),
            Self::Onvif { ip, address } => inspect_onvif(*ip, address),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct LocalEndpoint {
    ip: Ipv4Addr,
    port: u16,
    path: String,
}

/// Only HTTP on the same IPv4 address that sent the multicast reply.
/// Deliberately disallows DNS, redirects, userinfo, queries, and fragments.
fn endpoint(ip: Ipv4Addr, advertised: &str) -> Option<LocalEndpoint> {
    let raw = advertised.strip_prefix("http://")?;
    let (authority, tail) = raw.split_once('/').unwrap_or((raw, ""));
    if authority.is_empty() || authority.contains('@') || authority.starts_with('[') {
        return None;
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().ok()?),
        None => (authority, 80),
    };
    if port == 0 || host.parse::<Ipv4Addr>().ok()? != ip {
        return None;
    }
    let path = format!("/{tail}");
    if path.len() > 512 || !path.bytes().all(|byte| byte.is_ascii_graphic()
        && byte != b'#' && byte != b'?' && byte != b'\\')
    {
        return None;
    }
    Some(LocalEndpoint { ip, port, path })
}

fn request(target: &LocalEndpoint, soap: Option<&str>) -> Option<String> {
    let addr = SocketAddrV4::new(target.ip, target.port);
    let mut stream = TcpStream::connect_timeout(&addr.into(), IO_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
    let message = match soap {
        Some(body) => format!(
            "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/soap+xml; charset=utf-8; action=\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            target.path, target.ip, body.len(), body
        ),
        None => format!(
            "GET {} HTTP/1.0\r\nHost: {}\r\nAccept: application/xml, text/xml\r\nConnection: close\r\n\r\n",
            target.path, target.ip
        ),
    };
    stream.write_all(message.as_bytes()).ok()?;
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    while data.len() < MAX_RESPONSE {
        let size = chunk.len().min(MAX_RESPONSE - data.len());
        match stream.read(&mut chunk[..size]) {
            Ok(0) => break,
            Ok(len) => data.extend_from_slice(&chunk[..len]),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => break,
            Err(_) => return None,
        }
    }
    let raw = std::str::from_utf8(&data).ok()?;
    let (headers, body) = raw.split_once("\r\n\r\n")?;
    let status = headers.lines().next()?.split_whitespace().nth(1)?;
    if status != "200" || body.is_empty() {
        return None;
    }
    // HTTP/1.1 Transfer-Encoding: chunked is not implemented and cannot
    // be safely passed directly to XML. Ignore it rather than misparse.
    if headers.lines().any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding:")
        && line.to_ascii_lowercase().contains("chunked"))
    {
        return None;
    }
    let declared = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim().eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok()).flatten()
    });
    if declared.is_some_and(|expected| expected > body.len()) {
        return None;
    }
    Some(body.to_owned())
}

fn field(parent: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    let raw = parent.children().find(|node| node.is_element()
        && node.tag_name().name().eq_ignore_ascii_case(name))?.text()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(160).collect())
    }
}

pub fn parse_ssdp_xml(xml: &str) -> Option<IdentityInfo> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let device = doc.descendants().find(|node| node.is_element()
        && node.tag_name().name() == "device")?;
    let info = IdentityInfo {
        source: "UPnP/SSDP",
        friendly_name: field(device, "friendlyName"),
        manufacturer: field(device, "manufacturer"),
        model: field(device, "modelName"),
        model_number: field(device, "modelNumber"),
        device_type: field(device, "deviceType"),
        firmware: None,
    };
    info.has_values().then_some(info)
}

pub fn parse_onvif_xml(xml: &str) -> Option<IdentityInfo> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let response = doc.descendants().find(|node| node.is_element()
        && node.tag_name().name() == "GetDeviceInformationResponse")?;
    let info = IdentityInfo {
        source: "ONVIF",
        friendly_name: None,
        manufacturer: field(response, "Manufacturer"),
        model: field(response, "Model"),
        model_number: None,
        device_type: Some("ONVIF network video device".to_string()),
        firmware: field(response, "FirmwareVersion"),
    };
    info.has_values().then_some(info)
}

pub fn inspect_ssdp(ip: Ipv4Addr, location: &str) -> Option<IdentityInfo> {
    parse_ssdp_xml(&request(&endpoint(ip, location)?, None)?)
}

pub fn inspect_onvif(ip: Ipv4Addr, address: &str) -> Option<IdentityInfo> {
    let soap = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><s:Body><tds:GetDeviceInformation/></s:Body></s:Envelope>"#;
    parse_onvif_xml(&request(&endpoint(ip, address)?, Some(soap))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_remote_hostnames_queries_https_and_redirects() {
        let ip = Ipv4Addr::new(192, 168, 0, 1);
        assert!(endpoint(ip, "http://example.com/desc.xml").is_none());
        assert!(endpoint(ip, "http://192.168.0.2/desc.xml").is_none());
        assert!(endpoint(ip, "https://192.168.0.1/desc.xml").is_none());
        assert!(endpoint(ip, "http://root@192.168.0.1/desc.xml").is_none());
        assert!(endpoint(ip, "http://192.168.0.1/desc.xml?token=secret").is_none());
        assert!(endpoint(ip, "http://192.168.0.1/desc.xml#frag").is_none());
        assert_eq!(endpoint(ip, "http://192.168.0.1:1900/gatedesc.xml").unwrap().port, 1900);
    }

    #[test]
    fn parses_ssdp_device_information_with_namespaces() {
        let xml = r#"<root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType><friendlyName>Living Room</friendlyName><manufacturer>Example Inc</manufacturer><modelName>EX-100</modelName><modelNumber>3</modelNumber></device></root>"#;
        let info = parse_ssdp_xml(xml).unwrap();
        assert_eq!(info.friendly_name.as_deref(), Some("Living Room"));
        assert_eq!(info.manufacturer.as_deref(), Some("Example Inc"));
        assert_eq!(info.model.as_deref(), Some("EX-100"));
        assert!(!info.camera_hint());
    }

    #[test]
    fn parses_onvif_device_information() {
        let xml = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:d="http://www.onvif.org/ver10/device/wsdl"><s:Body><d:GetDeviceInformationResponse><d:Manufacturer>Sample Cameras</d:Manufacturer><d:Model>CAM X</d:Model><d:FirmwareVersion>1.2.3</d:FirmwareVersion></d:GetDeviceInformationResponse></s:Body></s:Envelope>"#;
        let info = parse_onvif_xml(xml).unwrap();
        assert_eq!(info.model.as_deref(), Some("CAM X"));
        assert_eq!(info.firmware.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn ignores_non_device_documents() {
        assert!(parse_ssdp_xml("<html>no UPnP data</html>").is_none());
        assert!(parse_onvif_xml("<html>not a SOAP response</html>").is_none());
    }
}
