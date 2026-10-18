//! Offline VVP video elementary-stream adapter. Not a network client.
//!
//! Input must already be reassembled, authenticated and decrypted by a
//! separately verified transport. Neither the VVP wrapper nor an app label
//! authorizes P2P access. No guesswork on encrypted codec payloads.
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use zeroize::Zeroize;

use crate::meari_vvp::{parse_frame, FrameError, FrameKind, SequenceGate};

const MAX_BATCH: usize = 16 * 1024 * 1024;
const MAX_PARAMETER_SET: usize = 128 * 1024;
const MAX_DECODE_BYTES: usize = 16 * 1024 * 1024;
const DECODE_DEADLINE: Duration = Duration::from_secs(12);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    Hevc,
}

impl VideoCodec {
    fn ffmpeg_format(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::Hevc => "hevc",
        }
    }

    pub(crate) fn parameter_types(self) -> &'static [u8] {
        match self {
            Self::H264 => &[7, 8],
            Self::Hevc => &[32, 33, 34],
        }
    }

    pub(crate) fn nal_type(self, unit: &[u8]) -> Option<u8> {
        match self {
            Self::H264 if !unit.is_empty() && unit[0] & 0x80 == 0 => Some(unit[0] & 0x1f),
            Self::Hevc if unit.len() >= 2 && unit[0] & 0x80 == 0 && unit[1] & 7 != 0 => {
                Some((unit[0] >> 1) & 0x3f)
            }
            _ => None,
        }
    }

    pub(crate) fn keyframe_type(self, nal_type: u8) -> bool {
        match self {
            Self::H264 => nal_type == 5,
            Self::Hevc => (16..=21).contains(&nal_type),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoError {
    InvalidVvpFrame,
    Oversized,
    InvalidVideoPayload,
    CodecChanged,
    NoDecodableFrame,
    DecoderUnavailable,
    DecodeFailed,
    DecodeTimedOut,
}

impl From<FrameError> for VideoError {
    fn from(error: FrameError) -> Self {
        match error {
            FrameError::Oversized => Self::Oversized,
            _ => Self::InvalidVvpFrame,
        }
    }
}

/// Owned, bounded elementary-stream video access unit. Video data is transient,
/// never persisted, logged, serialized or included in discovery reports.
pub struct EncodedSample {
    pub codec: VideoCodec,
    pub bytes: Vec<u8>,
}

impl Drop for EncodedSample {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Only accepts Annex-B start codes. An encrypted stream, an AVCC/HVCC
/// length-prefixed stream, and a truncated start code are not silently treated
/// as plaintext H.264/HEVC. Returned units exclude their start-code prefix.
pub(crate) fn annexb_units(payload: &[u8]) -> Option<Vec<&[u8]>> {
    if payload.len() < 5 {
        return None;
    }
    fn prefix(data: &[u8], i: usize) -> usize {
        if data.get(i..i + 4) == Some(&[0, 0, 0, 1]) {
            4
        } else if data.get(i..i + 3) == Some(&[0, 0, 1]) {
            3
        } else {
            0
        }
    }
    if prefix(payload, 0) == 0 {
        return None;
    }
    let mut units = Vec::new();
    let mut start = 0;
    while start < payload.len() {
        let len = prefix(payload, start);
        if len == 0 {
            return None;
        }
        let body = start + len;
        let mut end = body;
        while end < payload.len() && prefix(payload, end) == 0 {
            end += 1;
        }
        if body == end || units.len() >= 64 {
            return None;
        }
        units.push(&payload[body..end]);
        start = end;
    }
    Some(units)
}

pub(crate) fn detect_codec(units: &[&[u8]]) -> Option<VideoCodec> {
    // Require an actual parameter-set NAL, not an arbitrary slice header:
    // guessing on an encrypted stream can misclassify random bytes.
    let h264_sps = units.iter().any(|unit| {
        unit.first()
            .is_some_and(|b| *b & 0x80 == 0 && (*b & 0x1f) == 7)
    });
    let hevc_sps = units
        .iter()
        .any(|unit| VideoCodec::Hevc.nal_type(unit) == Some(33));
    match (h264_sps, hevc_sps) {
        (true, false) => Some(VideoCodec::H264),
        (false, true) => Some(VideoCodec::Hevc),
        _ => None,
    }
}

/// Stateful parser for consecutive *complete* reassembled VVP packets.
/// After loss or a discontinuity, waits for a fresh keyframe. Audio and info
/// are ignored. Codecs are never inferred from model, firmware or IP.
#[derive(Default)]
pub struct VvpVideoAdapter {
    codec: Option<VideoCodec>,
    params: BTreeMap<u8, Vec<u8>>,
    gate: SequenceGate,
    previous_sequence: Option<u32>,
}

impl Drop for VvpVideoAdapter {
    fn drop(&mut self) {
        for bytes in self.params.values_mut() {
            bytes.zeroize();
        }
    }
}

impl VvpVideoAdapter {
    pub fn reset(&mut self) {
        self.codec = None;
        for bytes in self.params.values_mut() {
            bytes.zeroize();
        }
        self.params.clear();
        self.gate.reset();
        self.previous_sequence = None;
    }

    fn require_keyframe(&mut self) {
        self.gate.reset();
        self.previous_sequence = None;
    }

    /// One call may contain multiple complete VVP frames; network fragmentation
    /// and partial VVP headers must be reassembled before calling this method.
    /// Output frames are video-only elementary units, suitable for an
    /// in-process video decoder or a bounded CPU FFmpeg stdin.
    pub fn push_reassembled(&mut self, data: &[u8]) -> Result<Vec<EncodedSample>, VideoError> {
        if data.len() > MAX_BATCH {
            self.require_keyframe();
            return Err(VideoError::Oversized);
        }
        let mut out = Vec::new();
        let mut offset = 0;
        let mut emitted_bytes = 0usize;
        while offset < data.len() {
            let (frame, consumed) = match parse_frame(&data[offset..]) {
                Ok(frame) => frame,
                Err(error) => {
                    self.require_keyframe();
                    return Err(VideoError::from(error));
                }
            };
            offset += consumed;
            if !matches!(frame.kind, FrameKind::Keyframe | FrameKind::Predicted) {
                continue;
            }
            let Some(units) = annexb_units(frame.payload) else {
                self.require_keyframe();
                return Err(VideoError::InvalidVideoPayload);
            };
            let contains_h264_sps = units
                .iter()
                .any(|unit| VideoCodec::H264.nal_type(unit) == Some(7));
            let contains_hevc_sps = units
                .iter()
                .any(|unit| VideoCodec::Hevc.nal_type(unit) == Some(33));
            if contains_h264_sps && contains_hevc_sps {
                self.require_keyframe();
                return Err(VideoError::InvalidVideoPayload);
            }
            if let Some(found) = detect_codec(&units) {
                if self.codec.is_some_and(|prior| prior != found) {
                    self.reset();
                    return Err(VideoError::CodecChanged);
                }
                self.codec = Some(found);
            }
            let Some(codec) = self.codec else {
                // No trustworthy SPS yet; do not attempt to decode.
                continue;
            };
            for unit in &units {
                let Some(kind) = codec.nal_type(unit) else {
                    self.require_keyframe();
                    return Err(VideoError::InvalidVideoPayload);
                };
                if codec.parameter_types().contains(&kind) {
                    if unit.len() > MAX_PARAMETER_SET {
                        self.require_keyframe();
                        return Err(VideoError::Oversized);
                    }
                    if let Some(previous) = self.params.insert(kind, unit.to_vec()) {
                        let mut previous = previous;
                        previous.zeroize();
                    }
                }
            }
            let ready = codec
                .parameter_types()
                .iter()
                .all(|kind| self.params.contains_key(kind));
            if !ready {
                self.require_keyframe();
                continue;
            }
            let is_idr = units
                .iter()
                .filter_map(|unit| codec.nal_type(unit))
                .any(|kind| codec.keyframe_type(kind));
            if frame.kind == FrameKind::Keyframe && !is_idr {
                self.require_keyframe();
                continue;
            }
            if frame.kind == FrameKind::Predicted && is_idr {
                self.require_keyframe();
                continue;
            }
            if let (Some(previous), Some(sequence)) = (self.previous_sequence, frame.sequence) {
                if frame.kind == FrameKind::Predicted && sequence != previous.wrapping_add(1) {
                    self.require_keyframe();
                    continue;
                }
            }
            if !self.gate.accept(&frame) {
                continue;
            }
            self.previous_sequence = frame.sequence;
            let mut access_unit = Vec::new();
            if frame.kind == FrameKind::Keyframe {
                // Repeat missing parameter sets in front of a recovery frame,
                // so a fresh decoder does not rely on an earlier transport packet.
                for &param_kind in codec.parameter_types() {
                    if !units
                        .iter()
                        .any(|unit| codec.nal_type(unit) == Some(param_kind))
                    {
                        let param = &self.params[&param_kind];
                        access_unit.extend_from_slice(&[0, 0, 0, 1]);
                        access_unit.extend_from_slice(param);
                    }
                }
            }
            access_unit.extend_from_slice(frame.payload);
            emitted_bytes = emitted_bytes
                .checked_add(access_unit.len())
                .ok_or(VideoError::Oversized)?;
            if emitted_bytes > MAX_BATCH {
                access_unit.zeroize();
                self.require_keyframe();
                return Err(VideoError::Oversized);
            }
            out.push(EncodedSample {
                codec,
                bytes: access_unit,
            });
        }
        Ok(out)
    }
}

/// Decode a bounded, already-authorized elementary stream to one 640x360 RGB
/// frame using CPU FFmpeg. No URL, account, device key, shell or GPU access is
/// handed to the subprocess. Real camera transport is NOT implemented here.
pub fn decode_first_frame(samples: &[EncodedSample]) -> Result<Vec<u8>, VideoError> {
    let codec = samples.first().ok_or(VideoError::NoDecodableFrame)?.codec;
    let total = samples
        .iter()
        .try_fold(0usize, |sum, sample| {
            sum.checked_add(sample.bytes.len())
                .filter(|&size| size <= MAX_DECODE_BYTES)
        })
        .ok_or(VideoError::Oversized)?;
    if total == 0 || samples.iter().any(|sample| sample.codec != codec) {
        return Err(VideoError::InvalidVideoPayload);
    }
    let mut video = Vec::with_capacity(total);
    for sample in samples {
        video.extend_from_slice(&sample.bytes);
    }
    let mut child = Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-nostdin",
            "-loglevel",
            "error",
            "-threads",
            "1",
            "-probesize",
            "1048576",
            "-f",
            codec.ffmpeg_format(),
            "-i",
            "pipe:0",
            "-map",
            "0:v:0",
            "-an",
            "-sn",
            "-dn",
            "-frames:v",
            "1",
            "-vf",
            "scale=640:360:force_original_aspect_ratio=decrease,pad=640:360:(ow-iw)/2:(oh-ih)/2",
            "-pix_fmt",
            "rgb24",
            "-f",
            "rawvideo",
            "pipe:1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| VideoError::DecoderUnavailable)?;
    let stdin = child.stdin.take().ok_or(VideoError::DecodeFailed)?;
    let stdout = child.stdout.take().ok_or(VideoError::DecodeFailed)?;
    let producer = thread::spawn(move || {
        let mut stdin = stdin;
        let _ = stdin.write_all(&video);
        video.zeroize();
    });
    let consumer = thread::spawn(move || {
        let mut pixels = Vec::new();
        let _ = stdout
            .take((crate::snapshot::PIXEL_BYTES + 1) as u64)
            .read_to_end(&mut pixels);
        pixels
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status.success()),
            Ok(None) if started.elapsed() < DECODE_DEADLINE => {
                thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(VideoError::DecodeTimedOut);
            }
        }
    };
    let _ = producer.join();
    let pixels = consumer.join().map_err(|_| VideoError::DecodeFailed)?;
    if !status? || pixels.len() != crate::snapshot::PIXEL_BYTES {
        return Err(VideoError::DecodeFailed);
    }
    Ok(pixels)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: FrameKind, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let header = if kind == FrameKind::Keyframe {
            0x3c
        } else {
            0x34
        };
        let mut bytes = vec![0; header + payload.len()];
        bytes[..3].copy_from_slice(&[0, 0, 1]);
        bytes[3] = if kind == FrameKind::Keyframe {
            0xfc
        } else {
            0xfd
        };
        let sequence_at = if kind == FrameKind::Keyframe {
            0x10
        } else {
            0x08
        };
        let length_at = if kind == FrameKind::Keyframe {
            0x38
        } else {
            0x30
        };
        bytes[sequence_at..sequence_at + 4].copy_from_slice(&sequence.to_le_bytes());
        bytes[length_at..length_at + 4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[header..].copy_from_slice(payload);
        bytes
    }

    const SPS: &[u8] = &[0, 0, 0, 1, 0x67, 0x42, 0, 0x1e];
    const PPS: &[u8] = &[0, 0, 1, 0x68, 0xce, 0x06];
    const IDR: &[u8] = &[0, 0, 1, 0x65, 0x88, 0x84];
    const PFRAME: &[u8] = &[0, 0, 1, 0x41, 0x9a];

    #[test]
    fn detects_only_explicit_annexb_configuration() {
        assert_eq!(
            detect_codec(&annexb_units(SPS).unwrap()),
            Some(VideoCodec::H264)
        );
        let hevc = [0, 0, 0, 1, 0x42, 0x01, 0x01];
        assert_eq!(
            detect_codec(&annexb_units(&hevc).unwrap()),
            Some(VideoCodec::Hevc)
        );
        for bad in [
            &[1, 2, 3, 4, 5][..],
            &[0, 0, 1][..],
            &[0, 0, 1, 0x65, 0, 0, 0, 1][..],
        ] {
            assert!(annexb_units(bad).is_none());
        }
    }

    #[test]
    fn startup_requires_both_params_and_idr_then_rejects_frame_gaps() {
        let mut parser = VvpVideoAdapter::default();
        assert!(parser
            .push_reassembled(&frame(FrameKind::Predicted, 1, PFRAME))
            .unwrap()
            .is_empty());
        let key = frame(FrameKind::Keyframe, 8, &[SPS, PPS, IDR].concat());
        let accepted = parser.push_reassembled(&key).unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].codec, VideoCodec::H264);
        assert!(!accepted[0].bytes.is_empty());
        assert_eq!(
            parser
                .push_reassembled(&frame(FrameKind::Predicted, 9, PFRAME))
                .unwrap()
                .len(),
            1
        );
        assert!(parser
            .push_reassembled(&frame(FrameKind::Predicted, 12, PFRAME))
            .unwrap()
            .is_empty());
        assert!(parser
            .push_reassembled(&frame(FrameKind::Predicted, 13, PFRAME))
            .unwrap()
            .is_empty());
        assert_eq!(
            parser
                .push_reassembled(&frame(FrameKind::Keyframe, 14, IDR))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn cached_parameter_sets_are_prepended_to_followup_idr() {
        let mut parser = VvpVideoAdapter::default();
        let first = frame(FrameKind::Keyframe, 1, &[SPS, PPS, IDR].concat());
        assert_eq!(parser.push_reassembled(&first).unwrap().len(), 1);
        let second = frame(FrameKind::Keyframe, 2, IDR);
        let samples = parser.push_reassembled(&second).unwrap();
        assert_eq!(samples.len(), 1);
        assert!(samples[0].bytes.starts_with(SPS));
        assert!(samples[0]
            .bytes
            .windows(PPS.len())
            .any(|window| window == PPS));
    }

    #[test]
    fn encrypted_or_mixed_codec_payload_is_never_guessed() {
        let mut parser = VvpVideoAdapter::default();
        assert_eq!(
            parser
                .push_reassembled(&frame(FrameKind::Keyframe, 1, &[5, 8, 12, 13, 14]))
                .err(),
            Some(VideoError::InvalidVideoPayload),
        );
        let hevc_sps = [0, 0, 1, 0x42, 1, 0x01];
        assert_eq!(
            parser
                .push_reassembled(&frame(FrameKind::Keyframe, 2, &[SPS, &hevc_sps].concat()))
                .err(),
            Some(VideoError::InvalidVideoPayload),
        );
    }

    #[test]
    fn hevc_parameter_sets_and_irap_are_accepted_without_codec_guessing() {
        let mut parser = VvpVideoAdapter::default();
        let vps = &[0, 0, 0, 1, 0x40, 0x01, 0x0c][..];
        let sps = &[0, 0, 0, 1, 0x42, 0x01, 0x01][..];
        let pps = &[0, 0, 0, 1, 0x44, 0x01, 0x02][..];
        let idr = &[0, 0, 0, 1, 0x26, 0x01, 0x03][..];
        let first = frame(FrameKind::Keyframe, 3, &[vps, sps, pps, idr].concat());
        let accepted = parser.push_reassembled(&first).unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].codec, VideoCodec::Hevc);
        let second = frame(FrameKind::Keyframe, 4, idr);
        let accepted = parser.push_reassembled(&second).unwrap();
        assert!(accepted[0].bytes.starts_with(vps));
    }

    #[test]
    fn switching_codec_requires_reset_and_recovery() {
        let mut parser = VvpVideoAdapter::default();
        let initial = frame(FrameKind::Keyframe, 1, &[SPS, PPS, IDR].concat());
        assert_eq!(parser.push_reassembled(&initial).unwrap().len(), 1);
        let hevc_sps = &[0, 0, 0, 1, 0x42, 0x01, 0x01][..];
        assert_eq!(
            parser
                .push_reassembled(&frame(FrameKind::Keyframe, 2, hevc_sps))
                .err(),
            Some(VideoError::CodecChanged)
        );
        assert!(parser
            .push_reassembled(&frame(FrameKind::Predicted, 3, PFRAME))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn synthetic_h264_vvp_frame_decodes_with_cpu_ffmpeg_when_available() {
        // No camera, cloud, credentials, listener, or GPU. Test video is
        // generated locally. Skip when the optional x264 encoder is absent.
        let encoded = Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-nostdin",
                "-loglevel",
                "error",
                "-f",
                "lavfi",
                "-i",
                "color=c=blue:s=160x90:r=5",
                "-frames:v",
                "1",
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
                "-x264-params",
                "keyint=1:min-keyint=1:scenecut=0",
                "-f",
                "h264",
                "pipe:1",
            ])
            .output();
        let Ok(encoded) = encoded else {
            return;
        };
        if !encoded.status.success() {
            return;
        }
        assert!(!encoded.stdout.is_empty());
        let mut adapter = VvpVideoAdapter::default();
        let vvp = frame(FrameKind::Keyframe, 1, &encoded.stdout);
        let samples = adapter.push_reassembled(&vvp).unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].codec, VideoCodec::H264);
        let rgb = decode_first_frame(&samples).unwrap();
        assert_eq!(rgb.len(), crate::snapshot::PIXEL_BYTES);
        assert!(rgb.iter().any(|&byte| byte != 0));
    }

    #[test]
    fn decoder_never_accepts_missing_or_mixed_video() {
        assert_eq!(
            decode_first_frame(&[]).err(),
            Some(VideoError::NoDecodableFrame)
        );
        let empty = EncodedSample {
            codec: VideoCodec::H264,
            bytes: vec![],
        };
        assert_eq!(
            decode_first_frame(&[empty]).err(),
            Some(VideoError::InvalidVideoPayload)
        );
        let samples = [
            EncodedSample {
                codec: VideoCodec::H264,
                bytes: vec![1],
            },
            EncodedSample {
                codec: VideoCodec::Hevc,
                bytes: vec![2],
            },
        ];
        assert_eq!(
            decode_first_frame(&samples).err(),
            Some(VideoError::InvalidVideoPayload)
        );
    }
}
