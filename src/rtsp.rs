//! Read-only inspection of a user-selected RTSP service.
//! Sends OPTIONS and DESCRIBE for the root resource without credentials.
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    time::Duration,
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESPONSE: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct RtspInspection {
    pub ip: Ipv4Addr,
    pub port: u16,
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
        let describe = self
            .describe_status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "no response".to_owned());
        let options = self
            .options_status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "no response".to_owned());
        format!("OPTIONS {options}; DESCRIBE / {describe}: {}", self.message)
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
    headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.trim()
                .eq_ignore_ascii_case(key)
                .then(|| value.trim().chars().take(160).collect())
        })
}

fn parse_response(bytes: &[u8]) -> Option<Response> {
    let raw = std::str::from_utf8(bytes).ok()?;
    let (headers, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    let status_line = headers.lines().next()?;
    if !status_line.starts_with("RTSP/1.0 ") {
        return None;
    }
    let status = status_line.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    Some(Response {
        status,
        server: header_value(headers, "Server"),
        www_authenticate: header_value(headers, "WWW-Authenticate"),
        content_type: header_value(headers, "Content-Type"),
        body: body.to_owned(),
    })
}

fn request(ip: Ipv4Addr, port: u16, method: &str, seq: u8) -> Result<Response, String> {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let mut stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT)
        .map_err(|error| format!("Connect: {error}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let packet = format!(
        "{method} rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: {seq}\r\nUser-Agent: Ocularium/0.1\r\nAccept: application/sdp\r\n\r\n"
    );
    stream
        .write_all(packet.as_bytes())
        .map_err(|e| e.to_string())?;
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
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0)
                        .min(MAX_RESPONSE - header_end);
                    if data.len() >= header_end + length {
                        break;
                    }
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock =>
            {
                break
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    parse_response(&data).ok_or_else(|| "No valid RTSP response".to_owned())
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

pub fn inspect(ip: Ipv4Addr, port: u16) -> RtspInspection {
    let mut result = RtspInspection {
        ip,
        port,
        options_status: None,
        describe_status: None,
        server: None,
        authentication: None,
        codecs: Vec::new(),
        sdp_received: false,
        message: String::new(),
    };
    match request(ip, port, "OPTIONS", 1) {
        Ok(response) => {
            result.options_status = Some(response.status);
            result.server = response.server;
        }
        Err(error) => {
            result.message = format!("OPTIONS failed: {error}");
            return result;
        }
    }
    match request(ip, port, "DESCRIBE", 2) {
        Ok(response) => {
            result.describe_status = Some(response.status);
            if result.server.is_none() {
                result.server = response.server;
            }
            if let Some(header) = response.www_authenticate {
                // Store only public challenge scheme, not potentially sensitive parameters.
                result.authentication = header.split_whitespace().next().map(str::to_owned);
            }
            result.sdp_received = response.status == 200
                && response
                    .content_type
                    .as_deref()
                    .is_some_and(|s| s.to_ascii_lowercase().contains("application/sdp"));
            if result.sdp_received {
                result.codecs = codecs(&response.body);
                result.message = "SDP description received, video playback not yet verified".into();
            } else {
                result.message = match response.status {
                    401 => "Authentication required; no credentials were attempted".into(),
                    404 => "Root path not available; camera may use a different stream path".into(),
                    403 => "Stream description forbidden".into(),
                    status => format!("RTSP response {status}; no SDP description confirmed"),
                };
            }
        }
        Err(error) => result.message = format!("DESCRIBE failed: {error}"),
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_auth_challenge_and_status() {
        let r = parse_response(b"RTSP/1.0 401 Unauthorized\r\nServer: Camera Server\r\nWWW-Authenticate: Digest realm=\"camera\"\r\n\r\n").unwrap();
        assert_eq!(r.status, 401);
        assert_eq!(r.server.as_deref(), Some("Camera Server"));
        assert!(r.www_authenticate.unwrap().starts_with("Digest"));
    }

    #[test]
    fn extracts_codecs_from_sdp() {
        let body = "v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=rtpmap:97 H265/90000\r\na=rtpmap:96 H264/90000\r\n";
        assert_eq!(codecs(body), vec!["H264", "H265"]);
    }

    #[test]
    fn rejects_non_rtsp_responses() {
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n\r\n").is_none());
    }
}
