//! Strict offline legacy Meari VVP video-frame decryption.
//!
//! Based only on the pinned MIT-licensed community reference at
//! raulrojas22/Ha-CloudPlus-Meari-ANRAN
//! custom_components/cloudplus/p2p_streamer/codec.py (c363366e5a712d6a0fee2be811eee23e15ee627a).
//!
//! The vendor applies 3DES-EDE3 ECB (15-byte constant + nine zero bytes)
//! to at most 0x80 bytes starting at offset 0x30 for I-frames or 0x28 for
//! P-frames, rounded to complete 8-byte blocks. This is legacy obfuscation,
//! NOT E2EE, peer authentication or encryption of a complete transport.
//!
//! Accepts only COMPLETE, already reassembled video frames from a separately
//! authorized and independently verified media session. No framing scans,
//! decryption guesses, network calls, credentials, or background processes.

use des::{
    cipher::{Block, BlockDecrypt, KeyInit},
    TdesEde3,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    meari_video::{annexb_units, EncodedSample, VideoError, VvpVideoAdapter},
    meari_vvp::{parse_frame, FrameKind},
};

const MAX_FRAME: usize = 8 * 1024 * 1024 + 0x3c;
const BLOCK_SIZE: usize = 8;
const MAX_ENCRYPTED_WINDOW: usize = 0x80;
const VENDOR_KEY: &[u8; 15] = b"!mearicloud2.0!";

/// Caller explicitly chooses the proven per-session format. Never infer
/// legacy 3DES from model, platform, IP address or an untrusted stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoFrameFormat {
    Plaintext,
    Legacy3Des,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamDecodeError {
    Incomplete,
    Oversized,
    InvalidVideo,
    Codec(VideoError),
}

fn offsets(marker: u8) -> Option<(usize, usize)> {
    match marker {
        0xfc => Some((0x30, 0x3c)),
        0xfd => Some((0x28, 0x34)),
        _ => None,
    }
}

/// Return zeroizing plaintext for exactly one complete VVP video frame.
/// Reject extra bytes, invalid payload signatures and malformed lengths;
/// on failure the caller cannot mistakenly send ciphertext to a decoder.
pub fn decode_complete_video_frame(
    input: &[u8],
    format: VideoFrameFormat,
) -> Result<Zeroizing<Vec<u8>>, StreamDecodeError> {
    if input.len() > MAX_FRAME {
        return Err(StreamDecodeError::Oversized);
    }
    if input.len() < 4 || input[..3] != [0, 0, 1] {
        return Err(StreamDecodeError::InvalidVideo);
    }
    let (crypt_offset, header) = offsets(input[3]).ok_or(StreamDecodeError::InvalidVideo)?;
    if input.len() < header {
        return Err(StreamDecodeError::Incomplete);
    }
    let mut clear = Zeroizing::new(input.to_vec());
    if format == VideoFrameFormat::Legacy3Des {
        let available = clear.len() - crypt_offset;
        let span = available.min(MAX_ENCRYPTED_WINDOW) / BLOCK_SIZE * BLOCK_SIZE;
        // The encrypted video header's payload length is at offset + 8.
        if span < 16 {
            return Err(StreamDecodeError::Incomplete);
        }
        let mut key = [0u8; 24];
        key[..VENDOR_KEY.len()].copy_from_slice(VENDOR_KEY);
        let cipher = TdesEde3::new_from_slice(&key).map_err(|_| StreamDecodeError::InvalidVideo)?;
        key.zeroize();
        for chunk in clear[crypt_offset..crypt_offset + span]
            .as_chunks_mut::<BLOCK_SIZE>()
            .0
        {
            let mut block = Block::<TdesEde3>::default();
            block.copy_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
            block.as_mut_slice().zeroize();
        }
    }
    let (frame, consumed) = parse_frame(&clear).map_err(|error| match error {
        crate::meari_vvp::FrameError::Incomplete => StreamDecodeError::Incomplete,
        crate::meari_vvp::FrameError::Oversized => StreamDecodeError::Oversized,
        _ => StreamDecodeError::InvalidVideo,
    })?;
    if consumed != clear.len()
        || !matches!(frame.kind, FrameKind::Keyframe | FrameKind::Predicted)
        || annexb_units(frame.payload).is_none()
    {
        return Err(StreamDecodeError::InvalidVideo);
    }
    Ok(clear)
}

/// Strict per-session adapter into the existing keyframe/codec gate.
/// Transport and camera authorization MUST happen before using this object.
pub struct VvpDecryptedVideoAdapter {
    format: VideoFrameFormat,
    video: VvpVideoAdapter,
}

impl VvpDecryptedVideoAdapter {
    pub fn new(format: VideoFrameFormat) -> Self {
        Self {
            format,
            video: VvpVideoAdapter::default(),
        }
    }

    pub fn reset(&mut self) {
        self.video.reset();
    }

    pub fn push_complete(&mut self, frame: &[u8]) -> Result<Vec<EncodedSample>, StreamDecodeError> {
        let clear = match decode_complete_video_frame(frame, self.format) {
            Ok(clear) => clear,
            Err(error) => {
                self.video.reset();
                return Err(error);
            }
        };
        match self.video.push_reassembled(&clear) {
            Ok(samples) => Ok(samples),
            Err(error) => {
                self.video.reset();
                Err(StreamDecodeError::Codec(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meari_video::VideoCodec;

    // Independently generated using Python cryptography's TripleDES ECB
    // implementation, not using the Rust code under test.
    const I_CIPHER: [u8; 32] = [
        0xaa, 0x42, 0x97, 0xe9, 0xb5, 0xd1, 0x3d, 0x75, 0x23, 0xe2, 0x0a, 0xbd, 0x05, 0xe9, 0x9b,
        0x22, 0x26, 0xb8, 0x63, 0xa6, 0xbd, 0x6a, 0xc3, 0xf1, 0x68, 0xde, 0xc5, 0x5a, 0x3e, 0xdb,
        0x36, 0x0b,
    ];
    const P_CIPHER: [u8; 16] = [
        0xaa, 0x42, 0x97, 0xe9, 0xb5, 0xd1, 0x3d, 0x75, 0x7e, 0x88, 0xb5, 0x31, 0x8d, 0x4a, 0x46,
        0xda,
    ];
    const H264_KEY_PAYLOAD: [u8; 20] = [
        0, 0, 0, 1, 0x67, 0x42, 0, 0x1e, 0, 0, 1, 0x68, 0xce, 0x06, 0, 0, 1, 0x65, 0x88, 0x84,
    ];
    const H264_P_PAYLOAD: [u8; 6] = [0, 0, 0, 1, 0x41, 0x9a];

    fn synthetic_encrypted(marker: u8, sequence: u32) -> Vec<u8> {
        let (header, offset, payload) = match marker {
            0xfc => (0x3c, 0x30, H264_KEY_PAYLOAD.as_slice()),
            0xfd => (0x34, 0x28, H264_P_PAYLOAD.as_slice()),
            _ => unreachable!(),
        };
        let mut bytes = vec![0u8; header + payload.len()];
        bytes[..4].copy_from_slice(&[0, 0, 1, marker]);
        let sequence_offset = if marker == 0xfc { 0x10 } else { 0x08 };
        bytes[sequence_offset..sequence_offset + 4].copy_from_slice(&sequence.to_le_bytes());
        match marker {
            0xfc => bytes[offset..offset + I_CIPHER.len()].copy_from_slice(&I_CIPHER),
            _ => bytes[offset..offset + P_CIPHER.len()].copy_from_slice(&P_CIPHER),
        }
        // Ciphertext starts at 0x30/0x28; any tail after the last
        // complete 3DES block remains unchanged in the vendor's format.
        if marker == 0xfd {
            bytes[header + 4..].copy_from_slice(&H264_P_PAYLOAD[4..]);
        }
        bytes
    }

    fn synthetic_plain(marker: u8, sequence: u32) -> Vec<u8> {
        let payload = if marker == 0xfc {
            H264_KEY_PAYLOAD.as_slice()
        } else {
            H264_P_PAYLOAD.as_slice()
        };
        let (header, offset, len_pos, seq_pos) = if marker == 0xfc {
            (0x3c, 0x30, 0x38, 0x10)
        } else {
            (0x34, 0x28, 0x30, 0x08)
        };
        let mut clear = vec![0; header + payload.len()];
        clear[..4].copy_from_slice(&[0, 0, 1, marker]);
        clear[seq_pos..seq_pos + 4].copy_from_slice(&sequence.to_le_bytes());
        clear[offset..offset + 4].copy_from_slice(&123456u32.to_le_bytes());
        clear[len_pos..len_pos + 4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        clear[header..].copy_from_slice(payload);
        clear
    }

    #[test]
    fn independent_3des_keyframe_and_predicted_vectors_decrypt_exactly() {
        for marker in [0xfc, 0xfd] {
            let input = synthetic_encrypted(marker, 7);
            let decoded =
                decode_complete_video_frame(&input, VideoFrameFormat::Legacy3Des).unwrap();
            assert_eq!(*decoded, synthetic_plain(marker, 7));
        }
    }

    #[test]
    fn encrypted_h264_stream_passes_existing_codec_and_recovery_gate() {
        let mut adapter = VvpDecryptedVideoAdapter::new(VideoFrameFormat::Legacy3Des);
        let key = adapter
            .push_complete(&synthetic_encrypted(0xfc, 1))
            .unwrap();
        assert_eq!(key.len(), 1);
        assert_eq!(key[0].codec, VideoCodec::H264);
        assert_eq!(key[0].bytes, H264_KEY_PAYLOAD);
        let pred = adapter
            .push_complete(&synthetic_encrypted(0xfd, 2))
            .unwrap();
        assert_eq!(pred.len(), 1);
        assert_eq!(pred[0].bytes, H264_P_PAYLOAD);
        assert!(adapter
            .push_complete(&synthetic_encrypted(0xfd, 4))
            .unwrap()
            .is_empty());
        assert!(adapter
            .push_complete(&synthetic_encrypted(0xfd, 5))
            .unwrap()
            .is_empty());
        let recovery = adapter
            .push_complete(&synthetic_encrypted(0xfc, 6))
            .unwrap();
        assert_eq!(recovery.len(), 1);
    }

    #[test]
    fn plaintext_is_explicit_and_is_never_decrypted_accidentally() {
        let mut decoder = VvpDecryptedVideoAdapter::new(VideoFrameFormat::Plaintext);
        assert_eq!(
            decoder
                .push_complete(&synthetic_plain(0xfc, 1))
                .unwrap()
                .len(),
            1
        );
        assert!(decoder
            .push_complete(&synthetic_encrypted(0xfc, 2))
            .is_err());
        assert!(decode_complete_video_frame(
            &synthetic_plain(0xfc, 1),
            VideoFrameFormat::Legacy3Des
        )
        .is_err());
    }

    #[test]
    fn malformed_corpus_rejected_without_byte_scan_or_partial_fallback() {
        let good = synthetic_encrypted(0xfc, 1);
        let truncated = &good[..good.len() - 1];
        assert!(decode_complete_video_frame(truncated, VideoFrameFormat::Legacy3Des).is_err());
        let mut extra = good.clone();
        extra.extend_from_slice(&[0, 0, 1, 0xfc]);
        assert!(decode_complete_video_frame(&extra, VideoFrameFormat::Legacy3Des).is_err());
        let mut corrupted = good.clone();
        corrupted[0x38] ^= 0xff;
        assert!(decode_complete_video_frame(&corrupted, VideoFrameFormat::Legacy3Des).is_err());
        let mut unknown = good.clone();
        unknown[3] = 0xfa;
        assert_eq!(
            decode_complete_video_frame(&unknown, VideoFrameFormat::Legacy3Des).err(),
            Some(StreamDecodeError::InvalidVideo)
        );
        let mut no_magic = good.clone();
        no_magic[0] = 3;
        assert_eq!(
            decode_complete_video_frame(&no_magic, VideoFrameFormat::Legacy3Des).err(),
            Some(StreamDecodeError::InvalidVideo)
        );
        assert_eq!(
            decode_complete_video_frame(&vec![0; MAX_FRAME + 1], VideoFrameFormat::Legacy3Des)
                .err(),
            Some(StreamDecodeError::Oversized)
        );
    }

    #[test]
    fn failed_packet_resets_old_codec_state_before_new_keyframe() {
        let mut adapter = VvpDecryptedVideoAdapter::new(VideoFrameFormat::Legacy3Des);
        assert_eq!(
            adapter
                .push_complete(&synthetic_encrypted(0xfc, 1))
                .unwrap()
                .len(),
            1
        );
        assert!(adapter.push_complete(&[0, 0, 1, 0xfc]).is_err());
        assert!(adapter
            .push_complete(&synthetic_encrypted(0xfd, 2))
            .unwrap()
            .is_empty());
        assert_eq!(
            adapter
                .push_complete(&synthetic_encrypted(0xfc, 3))
                .unwrap()
                .len(),
            1
        );
    }
}
