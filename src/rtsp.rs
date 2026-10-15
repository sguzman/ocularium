//! Read-only RTSP inspection of a selected local device.
//! Optional user-supplied credentials enable exactly one Digest response.
//! No default passwords, endpoint brute-forcing, or credential persistence.
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    time::Duration,
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESPONSE: usize = 16 * 1024;

pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct RtspInspection {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub path: String,
    pub options_status: Option<u16>,
    pub describe_status: Option<u16>,
    pub server: Option<String>,
    pub authentication: Option<String>,
    pub codecs: Vec<String>,
    pub sdp_received: bool,
    pub message: String,
}

impl RtspInspection {
    pub fn summary(&self) -> String {
        let describe = self.describe_status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "no response".to_owned());
        let options = self.options_status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "no response".to_owned());
        format!("OPTIONS {options}; DESCRIBE {} {describe}: {}", self.path, self.message)
    }
}

#[derive(Debug, Default)]
struct Response {
    status: u16,
    server: Option<String>,
    www_authenticate: Option<String>,
    content_type: Option<String>,
    body: String,
}

fn header_value(headers: &str, key: &str) -> Option<String> {
    headers.lines().filter_map(|line| line.split_once(':')).find_map(
        |(name, value)| name.trim().eq_ignore_ascii_case(key)
            .then(|| value.trim().chars().take(1024).collect()),
    )
}

fn parse_response(bytes: &[u8]) -> Option<Response> {
    let raw = String::from_utf8_lossy(bytes);
    let (headers, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status_line = headers.lines().next()?;
    if !status_line.starts_with("RTSP/1.0 ") {
        return None;
    }
    let status = status_line.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    Some(Response {
        status,
        server: header_value(headers, "Server").map(|s| s.chars().take(160).collect()),
        www_authenticate: header_value(headers, "WWW-Authenticate"),
        content_type: header_value(headers, "Content-Type"),
        body: body.to_owned(),
    })
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 256
        && path.bytes().all(|b| b.is_ascii_graphic() && b != b'#' && b != b'@')
}

fn request(
    ip: Ipv4Addr,
    port: u16,
    path: &str,
    method: &str,
    seq: u8,
    authorization: Option<&str>,
) -> Result<Response, String> {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let mut stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT)
        .map_err(|error| format!("Connect: {error}"))?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|e| e.to_string())?;
    let uri = format!("rtsp://{ip}:{port}{path}");
    let mut packet = format!(
        "{method} {uri} RTSP/1.0\r\nCSeq: {seq}\r\nUser-Agent: Ocularium/0.1\r\nAccept: application/sdp\r\n"
    );
    if let Some(value) = authorization {
        packet.push_str("Authorization: ");
        packet.push_str(value);
        packet.push_str("\r\n");
    }
    packet.push_str("\r\n");
    stream.write_all(packet.as_bytes()).map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    let mut chunk = [0u8; 2048];
    while data.len() < MAX_RESPONSE {
        let take = chunk.len().min(MAX_RESPONSE - data.len());
        match stream.read(&mut chunk[..take]) {
            Ok(0) => break,
            Ok(count) => {
                data.extend_from_slice(&chunk[..count]);
                if let Some(separator) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let header_end = separator + 4;
                    let headers = String::from_utf8_lossy(&data[..header_end]);
                    let length = header_value(&headers, "Content-Length")
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(0)
                        .min(MAX_RESPONSE - header_end);
                    if data.len() >= header_end + length {
                        break;
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut
                || err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.to_string()),
        }
    }
    parse_response(&data).ok_or_else(|| "No valid RTSP response".to_owned())
}

// Parse a Digest challenge, respecting commas inside quoted qop lists.
fn challenge_parameters(challenge: &str) -> Result<Vec<(String, String)>, String> {
    let Some(input) = challenge.get(7..) else {
        return Err("Missing Digest challenge".into());
    };
    if !challenge[..7].eq_ignore_ascii_case("Digest ") {
        return Err("This server does not advertise Digest authentication".into());
    }
    let mut parts = Vec::new();
    let mut remaining = input.trim();
    while !remaining.is_empty() {
        let Some(eq) = remaining.find('=') else {
            return Err("Malformed Digest challenge".into());
        };
        let key = remaining[..eq].trim().to_ascii_lowercase();
        remaining = remaining[eq + 1..].trim_start();
        let value;
        if let Some(rest) = remaining.strip_prefix('"') {
            let mut escaped = false;
            let mut result = String::new();
            let mut closing = None;
            for (at, ch) in rest.char_indices() {
                if escaped {
                    result.push(ch);
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    closing = Some(at + 1);
                    break;
                } else {
                    result.push(ch);
                }
            }
            let Some(end) = closing else {
                return Err("Unterminated Digest value".into());
            };
            value = result;
            remaining = rest[end..].trim_start();
        } else {
            let end = remaining.find(',').unwrap_or(remaining.len());
            value = remaining[..end].trim().to_owned();
            remaining = &remaining[end..];
        }
        if key.is_empty() || key.contains(char::is_whitespace) {
            return Err("Invalid Digest key".into());
        }
        parts.push((key, value));
        remaining = remaining.trim_start();
        if let Some(rest) = remaining.strip_prefix(',') {
            remaining = rest.trim_start();
        } else if !remaining.is_empty() {
            return Err("Invalid Digest separator".into());
        }
    }
    Ok(parts)
}

fn escape_quoted(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn md5_hex(value: &str) -> String {
    format!("{:x}", md5::compute(value.as_bytes()))
}

fn digest_authorization(
    challenge: &str,
    credentials: &Credentials,
    method: &str,
    uri: &str,
) -> Result<String, String> {
    if credentials.username.contains(['\r', '\n']) || credentials.username.len() > 128 {
        return Err("Invalid username".into());
    }
    let params = challenge_parameters(challenge)?;
    let get = |name: &str| params.iter().find(|(key, _)| key == name).map(|(_, val)| val.as_str());
    let realm = get("realm").ok_or("Digest challenge has no realm")?;
    let nonce = get("nonce").ok_or("Digest challenge has no nonce")?;
    let algorithm = get("algorithm").unwrap_or("MD5");
    if !algorithm.eq_ignore_ascii_case("MD5") && !algorithm.eq_ignore_ascii_case("MD5-sess") {
        return Err(format!("Unsupported Digest algorithm: {algorithm}"));
    }
    let qop = get("qop");
    if qop.is_some_and(|list| !list.split(',').any(|part| part.trim().eq_ignore_ascii_case("auth"))) {
        return Err("Server requires an unsupported Digest qop".into());
    }
    let cnonce = uuid::Uuid::new_v4().simple().to_string();
    let ha1_initial = md5_hex(&format!("{}:{realm}:{}", credentials.username, credentials.password));
    let ha1 = if algorithm.eq_ignore_ascii_case("MD5-sess") {
        md5_hex(&format!("{ha1_initial}:{nonce}:{cnonce}"))
    } else {
        ha1_initial
    };
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let response = if qop.is_some() {
        md5_hex(&format!("{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}"))
    } else {
        md5_hex(&format!("{ha1}:{nonce}:{ha2}"))
    };
    let mut value = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{response}\"",
        escape_quoted(&credentials.username), escape_quoted(realm), escape_quoted(nonce), escape_quoted(uri)
    );
    if let Some(opaque) = get("opaque") {
        value.push_str(&format!(", opaque=\"{}\"", escape_quoted(opaque)));
    }
    if qop.is_some() {
        value.push_str(&format!(", qop=auth, nc=00000001, cnonce=\"{cnonce}\""));
    }
    if get("algorithm").is_some() {
        value.push_str(&format!(", algorithm={algorithm}"));
    }
    Ok(value)
}

fn codecs(sdp: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in sdp.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("a=rtpmap:") {
            if let Some((_id, encoding)) = value.split_once(' ') {
                let label = encoding.split('/').next().unwrap_or("").trim();
                if !label.is_empty() && !found.iter().any(|v| v == label) {
                    found.push(label.to_owned());
                }
            }
        }
    }
    found
}

/// Only the caller-provided path is tested, and at most one Digest retry is sent.
pub fn inspect(
    ip: Ipv4Addr,
    port: u16,
    path: String,
    credentials: Option<Credentials>,
) -> RtspInspection {
    let mut result = RtspInspection {
        ip,
        port,
        path: path.clone(),
        options_status: None,
        describe_status: None,
        server: None,
        authentication: None,
        codecs: Vec::new(),
        sdp_received: false,
        message: String::new(),
    };
    if !valid_path(&path) {
        result.message = "Path must start with /, contain no spaces, and be at most 256 characters".into();
        return result;
    }
    match request(ip, port, &path, "OPTIONS", 1, None) {
        Ok(response) => {
            result.options_status = Some(response.status);
            result.server = response.server;
        }
        Err(error) => {
            result.message = format!("OPTIONS failed: {error}");
            return result;
        }
    }
    let response = match request(ip, port, &path, "DESCRIBE", 2, None) {
        Ok(response) => response,
        Err(error) => {
            result.message = format!("DESCRIBE failed: {error}");
            return result;
        }
    };
    let mut response = response;
    if let Some(ref challenge) = response.www_authenticate {
        result.authentication = challenge.split_whitespace().next().map(str::to_owned);
    }
    if response.status == 401 {
        if let Some(credentials) = credentials {
            if let Some(challenge) = &response.www_authenticate {
                let uri = format!("rtsp://{ip}:{port}{path}");
                match digest_authorization(challenge, &credentials, "DESCRIBE", &uri) {
                    Ok(authorization) => match request(ip, port, &path, "DESCRIBE", 3, Some(&authorization)) {
                        Ok(retry) => response = retry,
                        Err(error) => {
                            result.message = format!("Authenticated DESCRIBE failed: {error}");
                            return result;
                        }
                    },
                    Err(error) => {
                        result.message = error;
                        return result;
                    }
                }
            }
        }
    }
    result.describe_status = Some(response.status);
    if result.server.is_none() {
        result.server = response.server;
    }
    result.sdp_received = response.status == 200
        && response.content_type.as_deref().is_some_and(|value| {
            value.to_ascii_lowercase().contains("application/sdp")
        });
    result.message = if result.sdp_received {
        result.codecs = codecs(&response.body);
        "SDP description received; video playback not verified".into()
    } else {
        match response.status {
            401 => "Authentication required or supplied credentials rejected".into(),
            403 => "Stream description forbidden".into(),
            404 => "Specified path unavailable; the device may use another path".into(),
            status => format!("RTSP status {status}; no SDP description confirmed"),
        }
    };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_parses_quoted_commas_and_opaque() {
        let c = challenge_parameters("Digest realm=\"Cam A\", nonce=\"xyz\", qop=\"auth,auth-int\", opaque=\"abc,def\"").unwrap();
        assert!(c.contains(&("qop".into(), "auth,auth-int".into())));
        assert!(c.contains(&("opaque".into(), "abc,def".into())));
    }

    #[test]
    fn md5_digest_matches_rfc_2617_example() {
        let creds = Credentials { username: "Mufasa".into(), password: "Circle Of Life".into() };
        // RFC 2617 challenge example uses fixed cnonce, so test the classic
        // RFC 2069 calculation without qop to keep this deterministic.
        let header = digest_authorization(
            "Digest realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"",
            &creds,
            "GET",
            "/dir/index.html",
        ).unwrap();
        assert!(header.contains("Digest username=\"Mufasa\""));
        assert!(header.contains("uri=\"/dir/index.html\""));
        assert!(header.contains("response=\"670fd8c2df070c60b045671b8b24ff02\""));
    }

    #[test]
    fn rejects_invalid_path_and_unsupported_qop() {
        assert!(!valid_path("rtsp://example.com/"));
        assert!(!valid_path("/foo\r\nInjected: yes"));
        let creds = Credentials { username: "u".into(), password: "p".into() };
        assert!(digest_authorization("Digest realm=\"r\", nonce=\"n\", qop=\"auth-int\"", &creds, "DESCRIBE", "/").is_err());
    }

    #[test]
    fn parses_status_and_codecs() {
        let parsed = parse_response(b"RTSP/1.0 401 Unauthorized\r\nServer: YoTek RTSP Server 2.0\r\nWWW-Authenticate: Digest realm=\"cam\"\r\n\r\n").unwrap();
        assert_eq!(parsed.status, 401);
        assert_eq!(parsed.server.as_deref(), Some("YoTek RTSP Server 2.0"));
        let body = "v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=rtpmap:97 H265/90000\r\n";
        assert_eq!(codecs(body), ["H264", "H265"]);
    }
}
