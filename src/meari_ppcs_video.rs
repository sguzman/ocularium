//! Session-gated, offline PPCS reliable-channel -> elementary video handoff.
//!
//! PPCS (32-byte media header) is NOT VVP (0xFC/0xFD). This adapter deliberately
//! parses PPCS media directly, reusing only the tested Annex-B codec and CPU
//! decoder support. Input must be from an independently verified and
//! authorized media session whose packet envelopes have already been decoded.
//! The legacy PPCS DID or 0x42 candidate response CANNOT establish that trust:
//! packet obfuscation has no integrity/authentication tag.
//!
//! There are no sockets, background threads, account logins, stream requests,
//! FFmpeg invocations, automatic ACK transmissions, or persistent media here.
//! A separate opt-in caller must establish authenticated media access first.

use std::collections::BTreeMap;

use zeroize::Zeroize;

use crate::{
    meari_ppcs::{
        ChannelAck, PpcsError, PpcsMediaKind, PpcsMediaReassembler, PpcsReliableReceiver,
    },
    meari_video::{annexb_units, detect_codec, EncodedSample, VideoCodec, VideoError},
};

const MAX_ACCESS_UNIT: usize = 8 * 1024 * 1024;
const MAX_PARAMETER_SET: usize = 128 * 1024;
const MAX_OUTPUT_PER_CALL: usize = 16 * 1024 * 1024;
const MAX_OUTPUT_FRAMES: usize = 64;
const VALID_CHANNELS: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipelineError {
    InvalidMediaChannel,
    Channel(PpcsError),
    Codec(VideoError),
    TooMuchVideo,
}

impl From<PpcsError> for PipelineError {
    fn from(error: PpcsError) -> Self {
        Self::Channel(error)
    }
}

/// Acknowledgement metadata is returned only for an independently verified
/// transport's eventual sender. This module never generates outgoing traffic.
pub struct MediaDelivery {
    pub ack: Option<ChannelAck>,
    pub samples: Vec<EncodedSample>,
}

#[derive(Default)]
struct ElementaryGate {
    codec: Option<VideoCodec>,
    params: BTreeMap<u8, Vec<u8>>,
    last_sequence: Option<u32>,
    ready: bool,
}

impl Drop for ElementaryGate {
    fn drop(&mut self) {
        self.clear();
    }
}

impl ElementaryGate {
    fn clear(&mut self) {
        for parameter in self.params.values_mut() {
            parameter.zeroize();
        }
        self.params.clear();
        self.codec = None;
        self.last_sequence = None;
        self.ready = false;
    }

    fn require_keyframe(&mut self) {
        self.ready = false;
    }

    fn push(
        &mut self,
        frame_kind: PpcsMediaKind,
        sequence: u32,
        payload: &[u8],
    ) -> Result<Option<EncodedSample>, VideoError> {
        if frame_kind == PpcsMediaKind::Audio {
            return Ok(None);
        }
        if payload.is_empty() || payload.len() > MAX_ACCESS_UNIT {
            self.require_keyframe();
            return Err(VideoError::Oversized);
        }
        if let Some(previous) = self.last_sequence {
            let delta = sequence.wrapping_sub(previous);
            if delta == 0 || delta > 0x8000_0000 {
                // Duplicate or backwards. Do not touch cached parameters.
                return Ok(None);
            }
            if delta != 1 && frame_kind == PpcsMediaKind::Predicted {
                self.require_keyframe();
                return Ok(None);
            }
        }
        let Some(units) = annexb_units(payload) else {
            self.require_keyframe();
            return Err(VideoError::InvalidVideoPayload);
        };
        let h264_sps = units
            .iter()
            .any(|unit| VideoCodec::H264.nal_type(unit) == Some(7));
        let hevc_sps = units
            .iter()
            .any(|unit| VideoCodec::Hevc.nal_type(unit) == Some(33));
        if h264_sps && hevc_sps {
            self.require_keyframe();
            return Err(VideoError::InvalidVideoPayload);
        }
        if let Some(codec) = detect_codec(&units) {
            if self.codec.is_some_and(|before| before != codec) {
                self.clear();
                return Err(VideoError::CodecChanged);
            }
            self.codec = Some(codec);
        }
        let Some(codec) = self.codec else {
            return Ok(None);
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
                if let Some(mut previous) = self.params.insert(kind, unit.to_vec()) {
                    previous.zeroize();
                }
            }
        }
        if !codec
            .parameter_types()
            .iter()
            .all(|kind| self.params.contains_key(kind))
        {
            self.require_keyframe();
            return Ok(None);
        }
        let contains_idr = units
            .iter()
            .filter_map(|unit| codec.nal_type(unit))
            .any(|kind| codec.keyframe_type(kind));
        match frame_kind {
            PpcsMediaKind::Keyframe if !contains_idr => {
                self.require_keyframe();
                return Ok(None);
            }
            PpcsMediaKind::Predicted if contains_idr => {
                self.require_keyframe();
                return Ok(None);
            }
            PpcsMediaKind::Predicted if !self.ready => return Ok(None),
            _ => {}
        }

        let mut bytes = Vec::new();
        if frame_kind == PpcsMediaKind::Keyframe {
            // Parameter NALs are sometimes transmitted in earlier frames.
            // Include missing cached VPS/SPS/PPS on recovery keyframes.
            for &kind in codec.parameter_types() {
                if !units.iter().any(|unit| codec.nal_type(unit) == Some(kind)) {
                    bytes.extend_from_slice(&[0, 0, 0, 1]);
                    bytes.extend_from_slice(&self.params[&kind]);
                }
            }
        }
        bytes.extend_from_slice(payload);
        if bytes.len() > MAX_ACCESS_UNIT {
            bytes.zeroize();
            self.require_keyframe();
            return Err(VideoError::Oversized);
        }
        self.last_sequence = Some(sequence);
        if frame_kind == PpcsMediaKind::Keyframe {
            self.ready = true;
        }
        Ok(Some(EncodedSample { codec, bytes }))
    }
}

/// The selected channel must come from a verified media session, NOT be
/// inferred from a camera model, a saved IP address or a PPCS root offer.
/// Its reliable-channel sequence starts at zero, as in the pinned reference.
/// A new session must construct or reset a new pipeline.
pub struct PpcsMediaPipeline {
    media_channel: u8,
    reliable: PpcsReliableReceiver,
    frames: PpcsMediaReassembler,
    video: ElementaryGate,
}

impl PpcsMediaPipeline {
    pub fn new_verified_media_channel(media_channel: u8) -> Result<Self, PipelineError> {
        if media_channel >= VALID_CHANNELS {
            return Err(PipelineError::InvalidMediaChannel);
        }
        Ok(Self {
            media_channel,
            reliable: PpcsReliableReceiver::default(),
            frames: PpcsMediaReassembler::default(),
            video: ElementaryGate::default(),
        })
    }

    pub fn reset(&mut self) {
        self.reliable.reset();
        self.frames.reset();
        self.video.clear();
    }

    /// Input: already authenticated sender/session, decrypted PPCS outer
    /// datagram, validated 0xD0 inner packet. No cryptographic verification
    /// happens here. Returns video access units and optional ACK metadata.
    pub fn push_verified_plaintext_data(
        &mut self,
        outer_type: u8,
        inner_packet: &[u8],
    ) -> Result<MediaDelivery, PipelineError> {
        let delivery = match self
            .reliable
            .accept_plaintext_data(outer_type, inner_packet)
        {
            Ok(value) => value,
            Err(error) => {
                self.reset();
                return Err(PipelineError::Channel(error));
            }
        };
        let mut result = MediaDelivery {
            ack: delivery.ack,
            samples: Vec::new(),
        };
        if delivery.channel != self.media_channel {
            return Ok(result);
        }
        let mut total_bytes = 0usize;
        for chunk in &delivery.chunks {
            let frames = match self.frames.push_ordered_chunk(chunk) {
                Ok(frames) => frames,
                Err(error) => {
                    self.reset();
                    return Err(PipelineError::Channel(error));
                }
            };
            for frame in &frames {
                let sample = match self.video.push(frame.kind, frame.sequence, &frame.payload) {
                    Ok(sample) => sample,
                    Err(error) => {
                        self.reset();
                        return Err(PipelineError::Codec(error));
                    }
                };
                if let Some(sample) = sample {
                    total_bytes = match total_bytes.checked_add(sample.bytes.len()) {
                        Some(total) if total <= MAX_OUTPUT_PER_CALL => total,
                        _ => {
                            self.reset();
                            return Err(PipelineError::TooMuchVideo);
                        }
                    };
                    if result.samples.len() >= MAX_OUTPUT_FRAMES {
                        self.reset();
                        return Err(PipelineError::TooMuchVideo);
                    }
                    result.samples.push(sample);
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const H264_SPS: &[u8] = &[0, 0, 0, 1, 0x67, 0x42, 0, 0x1e];
    const H264_PPS: &[u8] = &[0, 0, 1, 0x68, 0xce, 0x06];
    const H264_IDR: &[u8] = &[0, 0, 1, 0x65, 0x88, 0x84];
    const H264_P: &[u8] = &[0, 0, 1, 0x41, 0x9a];

    fn frame(kind: PpcsMediaKind, seq: u32, data: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 32];
        bytes[0..4].copy_from_slice(&seq.to_le_bytes());
        bytes[16] = match kind {
            PpcsMediaKind::Keyframe => 0xf0,
            PpcsMediaKind::Predicted => 0xf1,
            PpcsMediaKind::Audio => 0xfa,
        };
        bytes[20..24].copy_from_slice(&(1234 + seq).to_le_bytes());
        bytes[28..32].copy_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(data);
        bytes
    }

    fn packet(channel: u8, seq: u16, bytes: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xd1, channel];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(bytes);
        packet
    }

    fn feed(
        pipeline: &mut PpcsMediaPipeline,
        channel: u8,
        starting: u16,
        bytes: &[u8],
    ) -> Result<Vec<EncodedSample>, PipelineError> {
        let mut out = Vec::new();
        for (index, chunk) in bytes.chunks(600).enumerate() {
            let packet = packet(channel, starting + index as u16, chunk);
            let result = pipeline.push_verified_plaintext_data(0xd0, &packet)?;
            assert!(result.ack.is_some());
            out.extend(result.samples);
        }
        Ok(out)
    }

    #[test]
    fn only_a_selected_valid_channel_can_produce_video() {
        assert!(matches!(
            PpcsMediaPipeline::new_verified_media_channel(8),
            Err(PipelineError::InvalidMediaChannel)
        ));
        let mut pipeline = PpcsMediaPipeline::new_verified_media_channel(1).unwrap();
        let key = frame(
            PpcsMediaKind::Keyframe,
            0,
            &[H264_SPS, H264_PPS, H264_IDR].concat(),
        );
        assert!(feed(&mut pipeline, 2, 0, &key).unwrap().is_empty());
        let mut pipeline = PpcsMediaPipeline::new_verified_media_channel(1).unwrap();
        let samples = feed(&mut pipeline, 1, 0, &key).unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].codec, VideoCodec::H264);
        assert!(samples[0].bytes.starts_with(H264_SPS));
    }

    #[test]
    fn fragmented_out_of_order_reliable_packets_reassemble_media_before_codec() {
        let mut pipeline = PpcsMediaPipeline::new_verified_media_channel(1).unwrap();
        let key = frame(
            PpcsMediaKind::Keyframe,
            1,
            &[H264_SPS, H264_PPS, H264_IDR].concat(),
        );
        let parts: Vec<&[u8]> = key.chunks(19).collect();
        let second = packet(1, 1, parts[1]);
        let later = pipeline
            .push_verified_plaintext_data(0xd0, &second)
            .unwrap();
        assert!(later.samples.is_empty());
        let first = packet(1, 0, parts[0]);
        let early = pipeline.push_verified_plaintext_data(0xd0, &first).unwrap();
        assert!(early.samples.is_empty());
        let mut out = Vec::new();
        for (idx, chunk) in parts.iter().enumerate().skip(2) {
            let delivery = pipeline
                .push_verified_plaintext_data(0xd0, &packet(1, idx as u16, chunk))
                .unwrap();
            out.extend(delivery.samples);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].codec, VideoCodec::H264);
        let repeated = pipeline.push_verified_plaintext_data(0xd0, &first).unwrap();
        assert!(repeated.samples.is_empty());
    }

    #[test]
    fn predict_frames_need_keyframe_and_missing_sequences_recover() {
        let mut pipeline = PpcsMediaPipeline::new_verified_media_channel(1).unwrap();
        assert!(feed(
            &mut pipeline,
            1,
            0,
            &frame(PpcsMediaKind::Predicted, 1, H264_P)
        )
        .unwrap()
        .is_empty());
        let key = frame(
            PpcsMediaKind::Keyframe,
            2,
            &[H264_SPS, H264_PPS, H264_IDR].concat(),
        );
        assert_eq!(feed(&mut pipeline, 1, 1, &key).unwrap().len(), 1);
        assert_eq!(
            feed(
                &mut pipeline,
                1,
                2,
                &frame(PpcsMediaKind::Predicted, 3, H264_P)
            )
            .unwrap()
            .len(),
            1
        );
        assert!(feed(
            &mut pipeline,
            1,
            3,
            &frame(PpcsMediaKind::Predicted, 9, H264_P)
        )
        .unwrap()
        .is_empty());
        assert!(feed(
            &mut pipeline,
            1,
            4,
            &frame(PpcsMediaKind::Predicted, 10, H264_P)
        )
        .unwrap()
        .is_empty());
        let recovered = feed(
            &mut pipeline,
            1,
            5,
            &frame(PpcsMediaKind::Keyframe, 11, H264_IDR),
        )
        .unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].bytes.starts_with(H264_SPS));
    }

    #[test]
    fn audio_skipped_and_malformed_media_resets_state() {
        let mut pipeline = PpcsMediaPipeline::new_verified_media_channel(0).unwrap();
        let audio = frame(PpcsMediaKind::Audio, 1, b"audio");
        assert!(feed(&mut pipeline, 0, 0, &audio).unwrap().is_empty());
        let key = frame(
            PpcsMediaKind::Keyframe,
            2,
            &[H264_SPS, H264_PPS, H264_IDR].concat(),
        );
        assert_eq!(feed(&mut pipeline, 0, 1, &key).unwrap().len(), 1);
        let mut bad = frame(PpcsMediaKind::Predicted, 3, H264_P);
        bad[16] = 0x12;
        assert_eq!(
            feed(&mut pipeline, 0, 2, &bad).err(),
            Some(PipelineError::Channel(PpcsError::InvalidFrame))
        );
        // Once reset, previously cached SPS/PPS and sequence state are gone.
        assert!(feed(
            &mut pipeline,
            0,
            0,
            &frame(PpcsMediaKind::Keyframe, 4, H264_IDR)
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn encrypted_looking_payload_rejected_without_attempted_decryption() {
        let mut pipeline = PpcsMediaPipeline::new_verified_media_channel(0).unwrap();
        let payload = frame(PpcsMediaKind::Keyframe, 1, &[13, 11, 7, 9, 5]);
        assert_eq!(
            feed(&mut pipeline, 0, 0, &payload).err(),
            Some(PipelineError::Codec(VideoError::InvalidVideoPayload))
        );
    }

    #[test]
    fn hevc_vps_sps_pps_and_idr_are_supported() {
        let mut pipeline = PpcsMediaPipeline::new_verified_media_channel(1).unwrap();
        let vps = &[0, 0, 0, 1, 0x40, 0x01, 0x0c][..];
        let sps = &[0, 0, 0, 1, 0x42, 0x01, 0x01][..];
        let pps = &[0, 0, 0, 1, 0x44, 0x01, 0x02][..];
        let idr = &[0, 0, 0, 1, 0x26, 0x01, 0x03][..];
        let first = frame(PpcsMediaKind::Keyframe, 7, &[vps, sps, pps, idr].concat());
        let output = feed(&mut pipeline, 1, 0, &first).unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].codec, VideoCodec::Hevc);
    }

    #[test]
    fn synthetic_ppcs_h264_keyframe_reaches_cpu_decoder_when_x264_available() {
        let result = Command::new("ffmpeg")
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
        let Ok(result) = result else {
            return;
        };
        if !result.status.success() {
            return;
        }
        assert!(!result.stdout.is_empty());
        let mut pipeline = PpcsMediaPipeline::new_verified_media_channel(1).unwrap();
        let media = frame(PpcsMediaKind::Keyframe, 1, &result.stdout);
        let samples = feed(&mut pipeline, 1, 0, &media).unwrap();
        assert_eq!(samples.len(), 1);
        let pixels = crate::meari_video::decode_first_frame(&samples).unwrap();
        assert_eq!(pixels.len(), crate::snapshot::PIXEL_BYTES);
        assert!(pixels.iter().any(|&value| value != 0));
    }
}
