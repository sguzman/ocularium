//! Optional single-frame RTSP decoding via a local ffmpeg executable.
//! No persistent recorder, daemon, GPU acceleration, cloud or credentials.
//! We intentionally do not put camera passwords in a subprocess command
//! line, where they could be exposed through OS process inspection.
use std::{
    io::Read,
    net::Ipv4Addr,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const WIDTH: usize = 640;
pub const HEIGHT: usize = 360;
pub const PIXEL_BYTES: usize = WIDTH * HEIGHT * 3;
const DEADLINE: Duration = Duration::from_secs(12);

#[derive(Debug)]
pub struct SnapshotResult {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub path: String,
    pub pixels: Option<Vec<u8>>,
    pub error: Option<String>,
}

fn validate(ip: Ipv4Addr, port: u16, path: &str) -> Result<String, String> {
    if !ip.is_private() || ip.is_loopback() || port == 0 {
        return Err("Only a valid local private IPv4 RTSP endpoint is allowed".into());
    }
    if !crate::rtsp::valid_path(path) {
        return Err("RTSP path must start with /, contain no spaces or credentials, and be at most 256 characters".into());
    }
    Ok(format!("rtsp://{ip}:{port}{path}"))
}

fn ffmpeg_args(uri: &str) -> Vec<String> {
    [
        "-hide_banner",
        "-nostdin",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-rw_timeout",
        "3000000",
        "-i",
        uri,
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
    .iter()
    .map(|item| (*item).to_owned())
    .collect()
}

fn checked_pixels(data: Vec<u8>) -> Result<Vec<u8>, String> {
    if data.len() == PIXEL_BYTES {
        Ok(data)
    } else {
        Err(format!(
            "No complete video frame decoded ({} of {} RGB bytes). The RTSP path may require authentication or a different stream path.",
            data.len(), PIXEL_BYTES
        ))
    }
}

/// Called only after the user clicks Capture frame for a discovered local
/// RTSP endpoint. Runs in a worker so the UI never waits for FFmpeg.
pub fn capture(ip: Ipv4Addr, port: u16, path: String) -> SnapshotResult {
    let mut result = SnapshotResult {
        ip,
        port,
        path: path.clone(),
        pixels: None,
        error: None,
    };
    let uri = match validate(ip, port, &path) {
        Ok(value) => value,
        Err(error) => {
            result.error = Some(error);
            return result;
        }
    };
    let mut child = match Command::new("ffmpeg")
        .args(ffmpeg_args(&uri))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            result.error = Some(if error.kind() == std::io::ErrorKind::NotFound {
                "ffmpeg is not installed or not on PATH. Install your distribution's ffmpeg package to enable CPU snapshot capture.".into()
            } else {
                format!("Could not start ffmpeg: {error}")
            });
            return result;
        }
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        result.error = Some("ffmpeg did not open a frame output pipe".into());
        return result;
    };
    // Drain the pipe concurrently to prevent the decoder from blocking on a
    // full OS pipe while we enforce the independent process deadline.
    let reader = thread::spawn(move || {
        let mut bytes = Vec::with_capacity(PIXEL_BYTES);
        let _ = stdout
            .take((PIXEL_BYTES + 1) as u64)
            .read_to_end(&mut bytes);
        bytes
    });
    let began = Instant::now();
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status.success()),
            Ok(None) if began.elapsed() < DEADLINE => thread::sleep(Duration::from_millis(75)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("Frame capture timed out after 12 seconds".to_owned());
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(format!("ffmpeg process error: {error}"));
            }
        }
    };
    let data = reader.join().unwrap_or_default();
    match outcome {
        Ok(true) => match checked_pixels(data) {
            Ok(pixels) => result.pixels = Some(pixels),
            Err(error) => result.error = Some(error),
        },
        Ok(false) => {
            result.error = Some(
                "ffmpeg could not decode a frame. Try Test RTSP access to check whether this path needs credentials, or whether the stream path is correct.".into()
            );
        }
        Err(error) => result.error = Some(error),
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_explicit_local_rtsp_paths() {
        let ip = Ipv4Addr::new(192, 168, 0, 100);
        assert_eq!(
            validate(ip, 8554, "/live").unwrap(),
            "rtsp://192.168.0.100:8554/live"
        );
        assert!(validate(ip, 8554, "rtsp://example.com/live").is_err());
        assert!(validate(ip, 8554, "/camera@evil.test").is_err());
        assert!(validate(Ipv4Addr::new(8, 8, 8, 8), 8554, "/").is_err());
        assert!(validate(ip, 0, "/").is_err());
    }

    #[test]
    fn snapshot_is_bounded_rgb_and_optional_ffmpeg_command_has_no_auth_arguments() {
        assert!(checked_pixels(vec![0; PIXEL_BYTES]).is_ok());
        assert!(checked_pixels(vec![0; PIXEL_BYTES + 1]).is_err());
        let args = ffmpeg_args("rtsp://192.168.0.100:8554/live");
        assert!(args.iter().any(|a| a == "-rtsp_transport"));
        assert!(args.iter().any(|a| a == "-frames:v"));
        assert!(!args
            .iter()
            .any(|a| a.contains("password") || a.contains("user:pass")));
    }
}
