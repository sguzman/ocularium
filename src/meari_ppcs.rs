//! Offline receive-side primitives for legacy PPStrong/PPCS camera transport.
//!
//! Layout checked against the MIT-licensed community implementation:
//! raulrojas22/Ha-CloudPlus-Meari-ANRAN p2p_streamer/ppcs.py
//! at c363366e5a712d6a0fee2be811eee23e15ee627a.
//!
//! Input MUST be from an independently authenticated peer with its PPCS
//! envelope already decrypted and validated. These routines make no network
//! connections, perform no rendezvous, no packet decryption, and do not select
//! a video channel. They must never be fed untrusted unauthenticated UDP data.

use std::collections::BTreeMap;

use zeroize::Zeroize;

const CHANNELS: usize = 8;
const CHANNEL_CHUNK_MAX: usize = 1024;
const MAX_PENDING_PER_CHANNEL: usize = 256;
const MAX_SEQUENCE_AHEAD: u16 = 512;
const MEDIA_HEADER: usize = 32;
const MEDIA_PAYLOAD_MAX: usize = 8 * 1024 * 1024;
const MEDIA_BUFFER_MAX: usize = MEDIA_HEADER + MEDIA_PAYLOAD_MAX;
const MAX_FRAMES_PER_CHUNK: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PpcsError {
    InvalidPacket,
    InvalidChannel,
    Oversized,
    ReorderLimit,
    InvalidFrame,
}

#[derive(Default)]
struct ChannelState {
    expected: u16,
    pending: BTreeMap<u16, Vec<u8>>,
}

impl ChannelState {
    fn clear(&mut self) {
        for bytes in self.pending.values_mut() {
            bytes.zeroize();
        }
        self.pending.clear();
        self.expected = 0;
    }
}

impl Drop for ChannelState {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Acknowledge exactly one already-authenticated PPCS channel packet.
/// Only the transport caller can decide when/how to send this ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelAck {
    pub channel: u8,
    pub sequence: u16,
}

/// Ordered channel byte chunks and the sequence requiring acknowledgement.
/// Payloads are not loggable, persistable, or tied to a guessed device.
pub struct ChannelDelivery {
    pub ack: Option<ChannelAck>,
    pub channel: u8,
    pub chunks: Vec<Vec<u8>>,
}

impl Drop for ChannelDelivery {
    fn drop(&mut self) {
        for chunk in &mut self.chunks {
            chunk.zeroize();
        }
    }
}

/// In-memory reliable-channel receiver. It accepts only the plaintext inner
/// payload of outer PPCS packet type 0xD0 and subtype 0xD1; source address,
/// auth, packet cipher and session establishment belong to a future adapter.
pub struct PpcsReliableReceiver {
    channels: [ChannelState; CHANNELS],
}

impl Default for PpcsReliableReceiver {
    fn default() -> Self {
        Self {
            channels: std::array::from_fn(|_| ChannelState::default()),
        }
    }
}

impl PpcsReliableReceiver {
    pub fn reset(&mut self) {
        for channel in &mut self.channels {
            channel.clear();
        }
    }

    pub fn accept_plaintext_data(
        &mut self,
        outer_type: u8,
        data: &[u8],
    ) -> Result<ChannelDelivery, PpcsError> {
        if outer_type != 0xd0 || data.len() < 5 || data[0] != 0xd1 {
            return Err(PpcsError::InvalidPacket);
        }
        let channel = data[1];
        let sequence = u16::from_be_bytes([data[2], data[3]]);
        let chunk = &data[4..];
        if channel as usize >= CHANNELS {
            return Err(PpcsError::InvalidChannel);
        }
        if chunk.is_empty() || chunk.len() > CHANNEL_CHUNK_MAX {
            return Err(PpcsError::Oversized);
        }
        let receiver = &mut self.channels[channel as usize];
        let delta = sequence.wrapping_sub(receiver.expected);
        let mut delivery = ChannelDelivery {
            ack: None,
            channel,
            chunks: Vec::new(),
        };
        if delta == 0 {
            delivery.chunks.push(chunk.to_vec());
            receiver.expected = receiver.expected.wrapping_add(1);
            while let Some(next) = receiver.pending.remove(&receiver.expected) {
                delivery.chunks.push(next);
                receiver.expected = receiver.expected.wrapping_add(1);
            }
            delivery.ack = Some(ChannelAck { channel, sequence });
        } else if delta < 0x8000 {
            if delta > MAX_SEQUENCE_AHEAD {
                return Err(PpcsError::ReorderLimit);
            }
            if !receiver.pending.contains_key(&sequence)
                && receiver.pending.len() >= MAX_PENDING_PER_CHANNEL
            {
                receiver.clear();
                return Err(PpcsError::ReorderLimit);
            }
            receiver
                .pending
                .entry(sequence)
                .or_insert_with(|| chunk.to_vec());
            delivery.ack = Some(ChannelAck { channel, sequence });
        }
        // Old/stale or already-delivered packets are dropped without bytes.
        // No assumption is made about their source or retransmission policy.
        Ok(delivery)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PpcsMediaKind {
    Keyframe,
    Predicted,
    Audio,
}

impl PpcsMediaKind {
    fn parse(value: u8) -> Option<Self> {
        match value {
            0xf0 => Some(Self::Keyframe),
            0xf1 => Some(Self::Predicted),
            0xfa => Some(Self::Audio),
            _ => None,
        }
    }
}

pub struct PpcsMediaFrame {
    pub kind: PpcsMediaKind,
    pub sequence: u32,
    pub timestamp_ms: u32,
    pub payload: Vec<u8>,
}

impl Drop for PpcsMediaFrame {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

/// Incremental parser for the distinct 32-byte legacy PPCS media envelope.
/// Feed ONLY a single video/media channel's ordered reliable bytes, never
/// arbitrary PPCS UDP packets or control-channel data.
#[derive(Default)]
pub struct PpcsMediaReassembler {
    buffer: Vec<u8>,
}

impl Drop for PpcsMediaReassembler {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl PpcsMediaReassembler {
    pub fn reset(&mut self) {
        self.buffer.zeroize();
        self.buffer.clear();
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    pub fn push_ordered_chunk(&mut self, chunk: &[u8]) -> Result<Vec<PpcsMediaFrame>, PpcsError> {
        if chunk.len() > CHANNEL_CHUNK_MAX
            || self.buffer.len().saturating_add(chunk.len()) > MEDIA_BUFFER_MAX
        {
            self.reset();
            return Err(PpcsError::Oversized);
        }
        self.buffer.extend_from_slice(chunk);
        let mut frames = Vec::new();
        let mut offset = 0usize;
        while self.buffer.len() - offset >= MEDIA_HEADER {
            let header = &self.buffer[offset..offset + MEDIA_HEADER];
            let Some(kind) = PpcsMediaKind::parse(header[16]) else {
                self.reset();
                return Err(PpcsError::InvalidFrame);
            };
            let payload_len = u32::from_le_bytes(header[28..32].try_into().unwrap()) as usize;
            if payload_len == 0 || payload_len > MEDIA_PAYLOAD_MAX {
                self.reset();
                return Err(PpcsError::InvalidFrame);
            }
            let total = MEDIA_HEADER + payload_len;
            if self.buffer.len() - offset < total {
                break;
            }
            if frames.len() >= MAX_FRAMES_PER_CHUNK {
                self.reset();
                return Err(PpcsError::Oversized);
            }
            frames.push(PpcsMediaFrame {
                kind,
                sequence: u32::from_le_bytes(header[0..4].try_into().unwrap()),
                timestamp_ms: u32::from_le_bytes(header[20..24].try_into().unwrap()),
                payload: self.buffer[offset + MEDIA_HEADER..offset + total].to_vec(),
            });
            offset += total;
        }
        if offset > 0 {
            self.buffer[..offset].zeroize();
            self.buffer.drain(..offset);
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inner(channel: u8, sequence: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xd1, channel];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn media(kind: u8, sequence: u32, stamp: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; MEDIA_HEADER];
        bytes[0..4].copy_from_slice(&sequence.to_le_bytes());
        bytes[16] = kind;
        bytes[20..24].copy_from_slice(&stamp.to_le_bytes());
        bytes[28..32].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn rejects_unauthenticated_envelopes_and_invalid_channels() {
        let mut rx = PpcsReliableReceiver::default();
        assert_eq!(
            rx.accept_plaintext_data(0xd1, &inner(0, 0, &[1])).err(),
            Some(PpcsError::InvalidPacket)
        );
        assert_eq!(
            rx.accept_plaintext_data(0xd0, &inner(8, 0, &[1])).err(),
            Some(PpcsError::InvalidChannel)
        );
        assert_eq!(
            rx.accept_plaintext_data(0xd0, &inner(1, 0, &[])).err(),
            Some(PpcsError::Oversized)
        );
        assert_eq!(
            rx.accept_plaintext_data(0xd0, &inner(1, 0, &vec![0; 1025]))
                .err(),
            Some(PpcsError::Oversized)
        );
    }

    #[test]
    fn out_of_order_chunks_reassemble_per_channel_and_drop_duplicates() {
        let mut rx = PpcsReliableReceiver::default();
        let later = rx.accept_plaintext_data(0xd0, &inner(2, 1, b"b")).unwrap();
        assert!(later.chunks.is_empty());
        assert_eq!(
            later.ack,
            Some(ChannelAck {
                channel: 2,
                sequence: 1
            })
        );
        assert!(rx
            .accept_plaintext_data(0xd0, &inner(2, 1, b"replay"))
            .unwrap()
            .chunks
            .is_empty());
        let ordered = rx.accept_plaintext_data(0xd0, &inner(2, 0, b"a")).unwrap();
        assert_eq!(ordered.chunks, [b"a".to_vec(), b"b".to_vec()]);
        assert!(rx
            .accept_plaintext_data(0xd0, &inner(2, 1, b"stale"))
            .unwrap()
            .chunks
            .is_empty());
        let another = rx.accept_plaintext_data(0xd0, &inner(3, 0, b"z")).unwrap();
        assert_eq!(another.chunks, [b"z".to_vec()]);
    }

    #[test]
    fn sequence_wrap_and_reorder_limits() {
        let mut rx = PpcsReliableReceiver::default();
        rx.channels[1].expected = u16::MAX;
        assert!(rx
            .accept_plaintext_data(0xd0, &inner(1, 0, b"after"))
            .unwrap()
            .chunks
            .is_empty());
        let emitted = rx
            .accept_plaintext_data(0xd0, &inner(1, u16::MAX, b"before"))
            .unwrap();
        assert_eq!(emitted.chunks, [b"before".to_vec(), b"after".to_vec()]);
        assert_eq!(
            rx.accept_plaintext_data(0xd0, &inner(1, 600, b"far")).err(),
            Some(PpcsError::ReorderLimit)
        );
        assert_eq!(
            rx.accept_plaintext_data(0xd0, &inner(1, 1, b"next"))
                .unwrap()
                .chunks,
            [b"next".to_vec()]
        );
    }

    #[test]
    fn parses_fragmented_media_and_multiple_frames_without_guessing_codec() {
        let first = media(0xf0, 7, 100, b"key");
        let second = media(0xf1, 8, 120, b"pred");
        let third = media(0xfa, 9, 140, b"audio");
        let mut parser = PpcsMediaReassembler::default();
        let all = [first, second, third].concat();
        let mut found = Vec::new();
        for chunk in all.chunks(7) {
            found.extend(parser.push_ordered_chunk(chunk).unwrap());
        }
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].kind, PpcsMediaKind::Keyframe);
        assert_eq!(found[0].sequence, 7);
        assert_eq!(found[0].timestamp_ms, 100);
        assert_eq!(found[0].payload, b"key");
        assert_eq!(found[1].kind, PpcsMediaKind::Predicted);
        assert_eq!(found[2].kind, PpcsMediaKind::Audio);
        assert_eq!(parser.buffered_bytes(), 0);
    }

    #[test]
    fn oversized_and_corrupt_media_reset_parser_without_resync_guesswork() {
        let mut parser = PpcsMediaReassembler::default();
        let mut oversized = media(0xf0, 1, 0, b"x");
        oversized[28..32].copy_from_slice(&((MEDIA_PAYLOAD_MAX + 1) as u32).to_le_bytes());
        assert_eq!(
            parser.push_ordered_chunk(&oversized).err(),
            Some(PpcsError::InvalidFrame)
        );
        assert_eq!(parser.buffered_bytes(), 0);
        assert_eq!(
            parser.push_ordered_chunk(&media(0x55, 1, 0, b"x")).err(),
            Some(PpcsError::InvalidFrame)
        );
        assert_eq!(parser.buffered_bytes(), 0);
        let restored = parser
            .push_ordered_chunk(&media(0xf0, 2, 0, b"safe"))
            .unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].payload, b"safe");
    }

    #[test]
    fn reliable_channel_and_media_reassembly_work_offline_end_to_end() {
        let payload = media(0xf0, 1, 321, b"annexb-in-test");
        let mut receiver = PpcsReliableReceiver::default();
        let mut parser = PpcsMediaReassembler::default();
        let mut frames = Vec::new();
        let chunks: Vec<_> = payload.chunks(13).collect();
        for (index, fragment) in chunks.iter().enumerate().rev() {
            let delivery = receiver
                .accept_plaintext_data(0xd0, &inner(1, index as u16, fragment))
                .unwrap();
            for chunk in &delivery.chunks {
                frames.extend(parser.push_ordered_chunk(chunk).unwrap());
            }
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].sequence, 1);
        assert_eq!(frames[0].payload, b"annexb-in-test");
        assert!(receiver.channels[1].pending.is_empty());
    }
}
