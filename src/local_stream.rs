//! Explicit, unauthenticated LAN MPEG-TS intake.
//!
//! For future camera adapters that can produce an authorized local HTTP stream.
//! The application opens HTTP itself (no redirects, proxies, cookies or DNS),
//! then feeds only video bytes into ffmpeg stdin. URLs and account credentials
//! are never passed to a child process or saved to the device registry.
//! This is not an ANRAN/Meari/VicoHome cloud adapter.
use std::{
    io::{Read, Write},
    net::Ipv4Addr,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_URL: usize = 512;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(12);
const READ_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalEndpoint {
    pub address: Ipv4Addr,
    pub port: u16,
    pub path: String,
}

impl LocalEndpoint {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        // No DNS rebinding, userinfo, tokens or credentials in URL parameters.
        if value.len() > MAX_URL || !value.is_ascii() || !value.starts_with("http://") {
            return Err(
                "Enter an explicit http://private-IPv4:port/path URL (maximum 512 characters)",
            );
        }
        let remainder = &value[7..];
        let (authority, tail) = remainder
            .split_once('/')
            .ok_or("A stream path is required")?;
        if authority.contains(['@', '[', ']', '%', '?', '#']) || authority.is_empty() {
            return Err("Stream authority must contain an IPv4 address without credentials");
        }
        let (address, port) = authority
            .rsplit_once(':')
            .ok_or("An explicit stream port is required")?;
        let address = address
            .parse::<Ipv4Addr>()
            .map_err(|_| "A numeric IPv4 address is required")?;
        let port = port.parse::<u16>().map_err(|_| "Invalid stream port")?;
        if port == 0
            || !(address.is_private() || address.is_loopback())
            || address.is_link_local()
            || address.is_multicast()
        {
            return Err("Only loopback or private LAN IPv4 endpoints are permitted");
        }
        let path = format!("/{tail}");
        if path.len() > 400
            || !path
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !b"?#@\\%".contains(&byte))
        {
            return Err("Path must be printable and must not contain secrets, query parameters, or fragments");
        }
        Ok(Self {
            address,
            port,
            path,
        })
    }

    fn url(&self) -> String {
        format!("http://{}:{}{}", self.address, self.port, self.path)
    }
}

#[derive(Debug)]
pub struct FrameResult {
    pub identity: String,
    pub frame: Option<Vec<u8>>,
    pub error: Option<String>,
}

fn ffmpeg_arguments() -> Vec<&'static str> {
    vec![
        "-hide_banner",
        "-nostdin",
        "-loglevel",
        "error",
        "-probesize",
        "1048576",
        "-analyzeduration",
        "2000000",
        "-f",
        "mpegts",
        "-i",
        "pipe:0",
        "-map",
        "0:v:0",
        "-an",
        "-sn",
        "-dn",
        "-frames:v",
        "1",
        "-threads",
        "1",
        "-vf",
        "scale=640:360:force_original_aspect_ratio=decrease,pad=640:360:(ow-iw)/2:(oh-ih)/2",
        "-pix_fmt",
        "rgb24",
        "-f",
        "rawvideo",
        "pipe:1",
    ]
}

fn validate_pixels(bytes: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    if bytes.len() == crate::snapshot::PIXEL_BYTES {
        Ok(bytes)
    } else {
        Err("No complete video frame was decoded from the local MPEG-TS feed")
    }
}

fn do_capture(endpoint: &LocalEndpoint) -> Result<Vec<u8>, String> {
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .try_proxy_from_env(false)
        .timeout_connect(Duration::from_secs(2))
        .timeout_read(READ_TIMEOUT)
        .build();
    let response = agent.get(&endpoint.url())
        .set("Accept", "video/mp2t, application/octet-stream")
        .call()
        .map_err(|err| match err {
            ureq::Error::Status(status, _) => format!("Local stream returned HTTP {status}; no redirects or authenticated requests were attempted"),
            ureq::Error::Transport(_) => "Could not connect to the local stream endpoint".to_owned(),
        })?;
    if response.status() != 200 {
        return Err(format!(
            "Local stream returned HTTP {}; no redirects were followed",
            response.status()
        ));
    }
    // Fail explicitly rather than unintentionally downloading HTML/error pages.
    if response.header("Content-Type").is_some_and(|content_type| {
        content_type.contains("text/html") || content_type.contains("application/json")
    }) {
        return Err("Local endpoint returned a page or JSON instead of MPEG-TS video".into());
    }
    let reader = response.into_reader();

    let mut child = Command::new("ffmpeg")
        .args(ffmpeg_arguments())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                "ffmpeg is missing; install your distribution's ffmpeg package".to_string()
            } else {
                format!("Cannot start local video decoder: {err}")
            }
        })?;

    let stdin = child.stdin.take().ok_or("Decoder stdin unavailable")?;
    let stdout = child.stdout.take().ok_or("Decoder stdout unavailable")?;
    // A bounded producer and consumer ensure ffmpeg pipe buffers never stall
    // our application UI. Closing stdin signals EOF to the demuxer.
    let producer = thread::spawn(move || {
        let mut source = reader.take(MAX_BYTES as u64);
        let mut dest = stdin;
        let mut bytes = [0u8; 8192];
        while let Ok(count) = source.read(&mut bytes) {
            if count == 0 || dest.write_all(&bytes[..count]).is_err() {
                break;
            }
        }
    });
    let consumer = thread::spawn(move || {
        let mut bytes = Vec::with_capacity(crate::snapshot::PIXEL_BYTES);
        let _ = stdout
            .take((crate::snapshot::PIXEL_BYTES + 1) as u64)
            .read_to_end(&mut bytes);
        bytes
    });
    let started = Instant::now();
    let completed = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status.success()),
            Ok(None) if started.elapsed() < DEADLINE => {
                thread::sleep(Duration::from_millis(70));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("Local video frame decoding exceeded 12 seconds".to_owned());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("Local video decoder process failed".to_owned());
            }
        }
    };
    // The producer's read timeout is bounded. A stalled decoder is killed
    // first, so writing to a full stdin pipe cannot block indefinitely.
    let _ = producer.join();
    let bytes = consumer.join().unwrap_or_default();
    if !completed? {
        return Err("Decoder could not find MPEG-TS video in the supplied local stream".into());
    }
    validate_pixels(bytes).map_err(str::to_owned)
}

/// Explicitly initiated for a saved camera. Never persists its URL.
pub fn capture(identity: String, url: String) -> FrameResult {
    let frame = LocalEndpoint::parse(&url)
        .map_err(str::to_owned)
        .and_then(|endpoint| do_capture(&endpoint));
    match frame {
        Ok(frame) => FrameResult {
            identity,
            frame: Some(frame),
            error: None,
        },
        Err(error) => FrameResult {
            identity,
            frame: None,
            error: Some(error),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_ipv4_only_and_no_tokens_or_cloud() {
        assert_eq!(
            LocalEndpoint::parse("http://127.0.0.1:8080/stream")
                .unwrap()
                .port,
            8080
        );
        assert!(LocalEndpoint::parse("http://192.168.0.107:8090/live.ts").is_ok());
        for url in [
            "https://192.168.0.107:8090/live",
            "http://example.com:8090/live",
            "http://8.8.8.8:8090/live",
            "http://user:pass@192.168.0.107:8090/live",
            "http://192.168.0.107:8090/live?token=secret",
            "http://192.168.0.107:8090/live#fragment",
            "http://192.168.0.107:8090/live\nHeader: attack",
            "http://192.168.0.107:0/stream",
        ] {
            assert!(
                LocalEndpoint::parse(url).is_err(),
                "must reject untrusted URL form"
            );
        }
    }

    #[test]
    fn decoder_gets_bytes_only_never_endpoint_url() {
        let args = ffmpeg_arguments();
        assert!(args.windows(2).any(|pair| pair == ["-i", "pipe:0"]));
        assert!(!args
            .iter()
            .any(|arg| arg.contains("http") || arg.contains("password")));
        assert!(validate_pixels(vec![0; crate::snapshot::PIXEL_BYTES]).is_ok());
        assert!(validate_pixels(vec![0; 100]).is_err());
    }

    #[test]
    fn http_redirect_is_not_followed_even_if_target_is_local() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 2048];
            let size = conn.read(&mut buffer).unwrap();
            assert!(String::from_utf8_lossy(&buffer[..size]).starts_with("GET /video HTTP/1.1"));
            conn.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://8.8.8.8/video\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let endpoint = LocalEndpoint::parse(&format!("http://127.0.0.1:{port}/video")).unwrap();
        let result = do_capture(&endpoint);
        server.join().unwrap();
        assert!(result.unwrap_err().contains("302"));
    }
}
