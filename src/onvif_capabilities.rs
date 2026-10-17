//! User-triggered, read-only ONVIF capability inspection of one selected LAN device.
//!
//! This does not authenticate, enumerate ports, retrieve video, or attempt
//! undocumented camera URLs. Advertised endpoints must stay on the responding
//! IPv4 host. Without an advertisement we check only the standardized HTTP
//! device-service path once on port 80. Never follow redirects.
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    time::Duration,
};

const TIMEOUT: Duration = Duration::from_secs(2);
const MAX_REPLY: usize = 64 * 1024;
const SOAP: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><s:Body><tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities></s:Body></s:Envelope>"#;

#[derive(Clone, Debug)]
struct Target {
    ip: Ipv4Addr,
    port: u16,
    path: String,
    advertised: bool,
}

impl Target {
    fn from_device(ip: Ipv4Addr, urls: &[String]) -> Self {
        let advertised = urls.iter().find_map(|url| Self::advertised(ip, url));
        advertised.unwrap_or_else(|| Self {
            ip, port: 80, path: "/onvif/device_service".into(), advertised: false,
        })
    }

    fn advertised(ip: Ipv4Addr, value: &str) -> Option<Self> {
        let raw = value.strip_prefix("http://")?;
        let (authority, path) = raw.split_once('/')?;
        if authority.contains(['@', '[', ']', '?', '#']) {
            return None;
        }
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().ok()?),
            None => (authority, 80),
        };
        if host.parse::<Ipv4Addr>().ok()? != ip || port == 0 {
            return None;
        }
        let path = format!("/{path}");
        if path.len() > 512 || !path.bytes().all(|byte|
            byte.is_ascii_graphic() && ![b'?', b'#', b'@', b'\\'].contains(&byte)
        ) {
            return None;
        }
        Some(Self { ip, port, path, advertised: true })
    }
}

#[derive(Clone, Debug)]
pub struct CapabilityResult {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub advertised_endpoint: bool,
    pub status: Option<u16>,
    pub categories: Vec<String>,
    pub same_host_media: bool,
    pub fault: bool,
    pub message: String,
}

impl CapabilityResult {
    fn new(target: &Target) -> Self {
        Self {
            ip: target.ip,
            port: target.port,
            advertised_endpoint: target.advertised,
            status: None,
            categories: Vec::new(),
            same_host_media: false,
            fault: false,
            message: String::new(),
        }
    }

    pub fn safe_summary(&self) -> String {
        format!(
            "ONVIF capability check (no login or endpoint URLs)\nDevice: {}\nPort: {}\nEndpoint source: {}\nHTTP status: {}\nSOAP fault: {}\nCapabilities: {}\nSame-host media service advertised: {}\nAssessment: {}\n",
            self.ip, self.port,
            if self.advertised_endpoint { "WS-Discovery advertisement" } else { "standard path, port 80" },
            self.status.map_or_else(|| "no response".into(), |s| s.to_string()),
            self.fault,
            if self.categories.is_empty() { "none verified".to_string() } else { self.categories.join(", ") },
            self.same_host_media, self.message,
        )
    }
}

fn capability_response(xml: &str, ip: Ipv4Addr) -> Option<(Vec<String>, bool, bool)> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let body = doc.descendants().find(|n| n.is_element() && n.tag_name().name() == "Body")?;
    if body.descendants().any(|n| n.is_element() && n.tag_name().name() == "Fault") {
        return Some((Vec::new(), false, true));
    }
    let response = body.descendants().find(|n|
        n.is_element() && n.tag_name().name() == "GetCapabilitiesResponse"
    )?;
    let caps = response.descendants().find(|n|
        n.is_element() && n.tag_name().name() == "Capabilities"
    )?;
    let mut names = Vec::new();
    let mut local_media = false;
    for child in caps.children().filter(|n| n.is_element()) {
        let name = child.tag_name().name();
        if !matches!(name, "Device" | "Media" | "Media2" | "Events" | "Imaging" |
            "PTZ" | "Analytics" | "Recording" | "Replay") {
            continue;
        }
        if !names.iter().any(|known| known == name) {
            names.push(name.to_owned());
        }
        if name == "Media" || name == "Media2" {
            local_media |= child.descendants()
                .filter(|n| n.is_element() && n.tag_name().name() == "XAddr")
                .filter_map(|n| n.text())
                .any(|address| Target::advertised(ip, address).is_some());
        }
    }
    Some((names, local_media, false))
}

fn read_response(stream: &mut TcpStream) -> Result<(u16, String), String> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let header_end;
    loop {
        if bytes.len() >= MAX_REPLY {
            return Err("HTTP response exceeded 64 KiB".into());
        }
        let limit = buffer.len().min(MAX_REPLY - bytes.len());
        match stream.read(&mut buffer[..limit]) {
            Ok(0) => return Err("Incomplete HTTP response".into()),
            Ok(n) => bytes.extend_from_slice(&buffer[..n]),
            Err(error) => return Err(format!("Reading ONVIF reply: {error}")),
        }
        if let Some(position) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = position + 4;
            break;
        }
    }
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "Invalid HTTP response headers")?;
    let status = headers.lines().next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("Missing HTTP status")?;
    let chunked = headers.lines().any(|line|
        line.split_once(':').is_some_and(|(key, value)|
            key.eq_ignore_ascii_case("Transfer-Encoding") &&
            value.to_ascii_lowercase().contains("chunked")
        )
    );
    if chunked {
        return Err("ONVIF response uses chunked transfer; unsupported by this probe".into());
    }
    let length = headers.lines().filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok());
    if let Some(length) = length {
        if header_end + length > MAX_REPLY {
            return Err("Declared ONVIF response exceeds 64 KiB".into());
        }
        while bytes.len() - header_end < length {
            let limit = buffer.len().min(MAX_REPLY - bytes.len());
            if limit == 0 { return Err("ONVIF response exceeded 64 KiB".into()); }
            let n = stream.read(&mut buffer[..limit])
                .map_err(|e| format!("Reading ONVIF body: {e}"))?;
            if n == 0 { return Err("Incomplete ONVIF response body".into()); }
            bytes.extend_from_slice(&buffer[..n]);
        }
    } else {
        // HTTP/1.0 responses may be close-delimited; never wait beyond our
        // socket timeout, and refuse to present truncated XML as capability data.
        while bytes.len() < MAX_REPLY {
            let limit = buffer.len().min(MAX_REPLY - bytes.len());
            match stream.read(&mut buffer[..limit]) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&buffer[..n]),
                Err(error) if matches!(error.kind(), std::io::ErrorKind::TimedOut |
                    std::io::ErrorKind::WouldBlock) => break,
                Err(error) => return Err(format!("Reading ONVIF body: {error}")),
            }
        }
    }
    let end = length.map_or(bytes.len(), |n| header_end + n);
    let body = String::from_utf8(bytes[header_end..end].to_vec())
        .map_err(|_| "ONVIF response is not UTF-8")?;
    Ok((status, body))
}

pub fn inspect(ip: Ipv4Addr, xaddrs: Vec<String>) -> CapabilityResult {
    let target = Target::from_device(ip, &xaddrs);
    let mut result = CapabilityResult::new(&target);
    if !ip.is_private() || ip.is_loopback() || ip.is_link_local() {
        result.message = "Only private, non-loopback LAN hosts can be checked".into();
        return result;
    }
    let address = SocketAddrV4::new(ip, target.port);
    let mut stream = match TcpStream::connect_timeout(&address.into(), TIMEOUT) {
        Ok(stream) => stream,
        Err(_) => {
            result.message = "No ONVIF HTTP response from selected endpoint".into();
            return result;
        }
    };
    if stream.set_read_timeout(Some(TIMEOUT)).is_err() ||
        stream.set_write_timeout(Some(TIMEOUT)).is_err() {
        result.message = "Could not set ONVIF request timeout".into();
        return result;
    }
    let request = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/soap+xml; charset=utf-8; action=\"http://www.onvif.org/ver10/device/wsdl/GetCapabilities\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        target.path, ip, SOAP.len(), SOAP
    );
    if stream.write_all(request.as_bytes()).is_err() {
        result.message = "Could not send ONVIF GetCapabilities request".into();
        return result;
    }
    match read_response(&mut stream) {
        Ok((status, body)) => {
            result.status = Some(status);
            match status {
                200 | 500 => match capability_response(&body, ip) {
                    Some((categories, local_media, fault)) => {
                        result.categories = categories;
                        result.same_host_media = local_media;
                        result.fault = fault;
                        result.message = if fault {
                            "ONVIF SOAP fault returned (no fault details retained)".into()
                        } else if result.categories.is_empty() {
                            "ONVIF response parsed, but no recognized service capabilities declared".into()
                        } else {
                            "ONVIF capabilities advertised; media service presence does not establish video access".into()
                        };
                    }
                    None => {
                        result.message =
                            "HTTP reply received, but no valid GetCapabilities SOAP response".into();
                    }
                },
                401 => result.message = "ONVIF authentication required; no credentials were attempted".into(),
                403 => result.message = "ONVIF access forbidden; no credentials were attempted".into(),
                404 => result.message = "No ONVIF service at this exact endpoint".into(),
                301 | 302 | 303 | 307 | 308 => result.message =
                    "ONVIF HTTP redirect refused; no other host or endpoint contacted".into(),
                _ => result.message = format!("ONVIF endpoint responded HTTP {status}; capabilities unverified"),
            }
        }
        Err(error) => result.message = error,
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> Ipv4Addr { Ipv4Addr::new(192, 168, 0, 100) }

    #[test]
    fn reject_off_host_and_non_http_xaddrs() {
        assert!(Target::advertised(ip(), "http://192.168.0.101/onvif/device_service").is_none());
        assert!(Target::advertised(ip(), "http://user@192.168.0.100/path").is_none());
        assert!(Target::advertised(ip(), "https://192.168.0.100/path").is_none());
        assert!(Target::advertised(ip(), "http://192.168.0.100/path?token=secret").is_none());
        assert!(Target::advertised(ip(), "http://192.168.0.100:8899/onvif/device_service").is_some());
        let fallback = Target::from_device(ip(), &["https://192.168.0.100/x".into()]);
        assert_eq!(fallback.port, 80);
        assert!(!fallback.advertised);
    }

    #[test]
    fn parse_namespaced_capabilities_without_trusting_external_media_address() {
        let xml = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><s:Body><tds:GetCapabilitiesResponse><tds:Capabilities><tds:Device/><tds:Media><tds:XAddr>http://10.0.0.9/onvif/media_service</tds:XAddr></tds:Media><tds:Events/></tds:Capabilities></tds:GetCapabilitiesResponse></s:Body></s:Envelope>"#;
        let (categories, local, fault) = capability_response(xml, ip()).unwrap();
        assert_eq!(categories, vec!["Device", "Media", "Events"]);
        assert!(!local);
        assert!(!fault);
        assert!(capability_response("<html>not onvif</html>", ip()).is_none());
    }

    #[test]
    fn parse_fault_without_treating_it_as_capabilities() {
        let xml = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Code>Denied</s:Code></s:Fault></s:Body></s:Envelope>"#;
        let (caps, media, fault) = capability_response(xml, ip()).unwrap();
        assert!(caps.is_empty());
        assert!(!media);
        assert!(fault);
    }

    #[test]
    fn mock_onvif_service_returns_media_capability_without_credentials() {
        use std::net::TcpListener;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 4096];
            let count = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..count]);
            assert!(request.contains("GetCapabilities"));
            assert!(!request.contains("Authorization:"));
            let body = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetCapabilitiesResponse><Capabilities><Media><XAddr>http://192.168.0.100/onvif/media_service</XAddr></Media></Capabilities></GetCapabilitiesResponse></s:Body></s:Envelope>"#;
            let reply = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
            stream.write_all(reply.as_bytes()).unwrap();
        });
        // Exercise the complete HTTP parser using a loopback fixture while
        // preserving the private-LAN restriction on actual probe actions.
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        stream.write_all(b"test fixture").unwrap();
        let (status, body) = read_response(&mut stream).unwrap();
        server.join().unwrap();
        assert_eq!(status, 200);
        let (categories, same_host, fault) = capability_response(&body, ip()).unwrap();
        assert_eq!(categories, vec!["Media"]);
        assert!(same_host);
        assert!(!fault);
    }
}
