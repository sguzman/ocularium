//! Offline PPCS wire-envelope and substitution-cipher compatibility.
//!
//! Format/lookup table cross-checked with MIT-licensed community reference:
//! raulrojas22/Ha-CloudPlus-Meari-ANRAN, p2p_streamer/ppcs.py
//! at c363366e5a712d6a0fee2be811eee23e15ee627a.
//!
//! This legacy cipher provides *obfuscation, not authentication or integrity*.
//! Decrypting a well-formed envelope is not evidence of a trusted sender.
//! A future connection layer must independently verify the device, peer,
//! authorized session, and packet origin before using any decoded payload.
//! No sockets, cloud requests, key guessing, or peer discovery here.

use zeroize::{Zeroize, Zeroizing};

const HEADER_BYTES: usize = 4;
const MAX_PAYLOAD: usize = 16 * 1024;
const MAGIC: u8 = 0xf1;

// Exact 256-byte legacy substitution table. Not a cryptographic S-box.
const TABLE: [u8; 256] = [
    0x7c, 0x9c, 0xe8, 0x4a, 0x13, 0xde, 0xdc, 0xb2, 0x2f, 0x21, 0x23, 0xe4, 0x30, 0x7b, 0x3d, 0x8c,
    0xbc, 0x0b, 0x27, 0x0c, 0x3c, 0xf7, 0x9a, 0xe7, 0x08, 0x71, 0x96, 0x00, 0x97, 0x85, 0xef, 0xc1,
    0x1f, 0xc4, 0xdb, 0xa1, 0xc2, 0xeb, 0xd9, 0x01, 0xfa, 0xba, 0x3b, 0x05, 0xb8, 0x15, 0x87, 0x83,
    0x28, 0x72, 0xd1, 0x8b, 0x5a, 0xd6, 0xda, 0x93, 0x58, 0xfe, 0xaa, 0xcc, 0x6e, 0x1b, 0xf0, 0xa3,
    0x88, 0xab, 0x43, 0xc0, 0x0d, 0xb5, 0x45, 0x38, 0x4f, 0x50, 0x22, 0x66, 0x20, 0x7f, 0x07, 0x5b,
    0x14, 0x98, 0x1d, 0x9b, 0xa7, 0x2a, 0xb9, 0xa8, 0xcb, 0xf1, 0xfc, 0x49, 0x47, 0x06, 0x3e, 0xb1,
    0x0e, 0x04, 0x3a, 0x94, 0x5e, 0xee, 0x54, 0x11, 0x34, 0xdd, 0x4d, 0xf9, 0xec, 0xc7, 0xc9, 0xe3,
    0x78, 0x1a, 0x6f, 0x70, 0x6b, 0xa4, 0xbd, 0xa9, 0x5d, 0xd5, 0xf8, 0xe5, 0xbb, 0x26, 0xaf, 0x42,
    0x37, 0xd8, 0xe1, 0x02, 0x0a, 0xae, 0x5f, 0x1c, 0xc5, 0x73, 0x09, 0x4e, 0x69, 0x24, 0x90, 0x6d,
    0x12, 0xb3, 0x19, 0xad, 0x74, 0x8a, 0x29, 0x40, 0xf5, 0x2d, 0xbe, 0xa5, 0x59, 0xe0, 0xf4, 0x79,
    0xd2, 0x4b, 0xce, 0x89, 0x82, 0x48, 0x84, 0x25, 0xc6, 0x91, 0x2b, 0xa2, 0xfb, 0x8f, 0xe9, 0xa6,
    0xb0, 0x9e, 0x3f, 0x65, 0xf6, 0x03, 0x31, 0x2e, 0xac, 0x0f, 0x95, 0x2c, 0x5c, 0xed, 0x39, 0xb7,
    0x33, 0x6c, 0x56, 0x7e, 0xb4, 0xa0, 0xfd, 0x7a, 0x81, 0x53, 0x51, 0x86, 0x8d, 0x9f, 0x77, 0xff,
    0x6a, 0x80, 0xdf, 0xe2, 0xbf, 0x10, 0xd7, 0x75, 0x64, 0x57, 0x76, 0xf3, 0x55, 0xcd, 0xd0, 0xc8,
    0x18, 0xe6, 0x36, 0x41, 0x62, 0xcf, 0x99, 0xf2, 0x32, 0x4c, 0x67, 0x60, 0x61, 0x92, 0xca, 0xd3,
    0xea, 0x63, 0x7d, 0x16, 0xb6, 0x8e, 0xd4, 0x68, 0x35, 0xc3, 0x52, 0x9d, 0x46, 0x44, 0x1e, 0x17,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    InvalidKey,
    Oversized,
    InvalidEnvelope,
}

/// Ciphertext owned in short-lived zeroizing memory. It has no Debug or
/// Serialize implementation to keep packet bytes out of accidental reports.
pub struct EncodedPacket {
    bytes: Zeroizing<Vec<u8>>,
}

impl EncodedPacket {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A syntactically decoded packet, NOT an authenticated camera packet.
/// Higher layers must check the sender/session before even invoking decode.
pub struct DecodedPacket {
    kind: u8,
    payload: Zeroizing<Vec<u8>>,
}

impl DecodedPacket {
    pub fn kind(&self) -> u8 {
        self.kind
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Holds only the four derived cipher-state bytes, not the supplied raw key.
/// No Debug/Serialize and state zeroized when the session is dropped.
pub struct PpcsPacketCipher {
    state: [u8; 4],
}

impl Drop for PpcsPacketCipher {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

impl PpcsPacketCipher {
    /// Key is provisioned by a future legitimately authenticated PPCS session.
    /// The vendor cipher uses the first 20 key bytes; no key is persisted.
    pub fn from_session_key(key: &[u8]) -> Result<Self, WireError> {
        if key.is_empty() || key.len() > 128 {
            return Err(WireError::InvalidKey);
        }
        let mut state = [0u8; 4];
        for &byte in key.iter().take(20) {
            state[0] = state[0].wrapping_add(byte);
            state[1] = state[1].wrapping_sub(byte);
            state[2] = state[2].wrapping_add(byte / 3);
            state[3] ^= byte;
        }
        Ok(Self { state })
    }

    fn substitute(&self, bytes: &mut [u8], encrypt: bool) {
        let mut previous = 0u8;
        for byte in bytes {
            let current = *byte;
            let lookup_index = previous.wrapping_add(self.state[(previous & 3) as usize]);
            let output = current ^ TABLE[lookup_index as usize];
            *byte = output;
            previous = if encrypt { output } else { current };
        }
    }

    /// Wrap one PPCS packet with magic, type and big-endian payload length,
    /// then obfuscate it. This does not send a packet.
    pub fn encode(&self, kind: u8, payload: &[u8]) -> Result<EncodedPacket, WireError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(WireError::Oversized);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + payload.len()));
        bytes.push(MAGIC);
        bytes.push(kind);
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(payload);
        self.substitute(&mut bytes, true);
        Ok(EncodedPacket { bytes })
    }

    /// Deobfuscates exactly one datagram and enforces its envelope length.
    /// There is no authentication tag. Never infer trust from success here.
    pub fn decode_obfuscated(&self, wire: &[u8]) -> Result<DecodedPacket, WireError> {
        if wire.len() < HEADER_BYTES {
            return Err(WireError::InvalidEnvelope);
        }
        if wire.len() > HEADER_BYTES + MAX_PAYLOAD {
            return Err(WireError::Oversized);
        }
        let mut plaintext = Zeroizing::new(wire.to_vec());
        self.substitute(&mut plaintext, false);
        if plaintext[0] != MAGIC {
            return Err(WireError::InvalidEnvelope);
        }
        let kind = plaintext[1];
        let advertised = u16::from_be_bytes([plaintext[2], plaintext[3]]) as usize;
        if advertised != plaintext.len() - HEADER_BYTES {
            return Err(WireError::InvalidEnvelope);
        }
        Ok(DecodedPacket {
            kind,
            payload: Zeroizing::new(plaintext[HEADER_BYTES..].to_vec()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meari_ppcs::PpcsReliableReceiver;

    #[test]
    fn known_answer_wire_vectors_match_pinned_reference_implementation() {
        let cipher = PpcsPacketCipher::from_session_key(b"test-packet-key").unwrap();
        let data = [0xd1, 2, 0, 7, b'a', b'b', b'c'];
        let frame = cipher.encode(0xd0, &data).unwrap();
        assert_eq!(
            frame.as_bytes(),
            &[0x02, 0x03, 0xec, 0x7d, 0x1f, 0xc7, 0x28, 0x4d, 0x0e, 0xff, 0x57]
        );
        let decoded = cipher.decode_obfuscated(frame.as_bytes()).unwrap();
        assert_eq!(decoded.kind(), 0xd0);
        assert_eq!(decoded.payload(), data);
        assert_eq!(
            cipher.encode(0xe0, b"").unwrap().as_bytes(),
            &[0x02, 0x33, 0x59, 0xaf]
        );
        assert_eq!(
            cipher.encode(0x41, &[0, 1, 2, 3, 4]).unwrap().as_bytes(),
            &[0x02, 0x92, 0x42, 0x86, 0x70, 0x67, 0x68, 0xc3, 0xbc]
        );
    }

    #[test]
    fn strict_envelope_and_key_bounds() {
        assert!(matches!(
            PpcsPacketCipher::from_session_key(b""),
            Err(WireError::InvalidKey)
        ));
        assert!(matches!(
            PpcsPacketCipher::from_session_key(&[7; 129]),
            Err(WireError::InvalidKey)
        ));
        let cipher = PpcsPacketCipher::from_session_key(b"test-packet-key").unwrap();
        assert!(matches!(
            cipher.encode(0xd0, &vec![1; MAX_PAYLOAD + 1]),
            Err(WireError::Oversized)
        ));
        let packet = cipher.encode(0x42, &[1, 2, 3]).unwrap();
        assert_eq!(
            cipher.decode_obfuscated(&packet.as_bytes()[..3]).err(),
            Some(WireError::InvalidEnvelope)
        );
        assert_eq!(
            cipher.decode_obfuscated(&packet.as_bytes()[..6]).err(),
            Some(WireError::InvalidEnvelope)
        );
        assert_eq!(
            cipher
                .decode_obfuscated(&vec![0; MAX_PAYLOAD + HEADER_BYTES + 1])
                .err(),
            Some(WireError::Oversized)
        );
        // Neither decrypting with the wrong key nor matching a magic byte is
        // a legitimate authorization mechanism.
        let wrong = PpcsPacketCipher::from_session_key(b"other-key").unwrap();
        assert_eq!(
            wrong.decode_obfuscated(packet.as_bytes()).err(),
            Some(WireError::InvalidEnvelope)
        );
    }

    #[test]
    fn decrypted_ppcs_data_can_feed_existing_offline_reliable_receiver() {
        let cipher = PpcsPacketCipher::from_session_key(b"test-packet-key").unwrap();
        let mut receiver = PpcsReliableReceiver::default();
        let second = cipher.encode(0xd0, &[0xd1, 1, 0, 1, b'b']).unwrap();
        let first = cipher.encode(0xd0, &[0xd1, 1, 0, 0, b'a']).unwrap();
        let late = cipher.decode_obfuscated(second.as_bytes()).unwrap();
        let d = receiver.accept_plaintext_data(late.kind(), late.payload()).unwrap();
        assert!(d.chunks.is_empty());
        let early = cipher.decode_obfuscated(first.as_bytes()).unwrap();
        let d = receiver.accept_plaintext_data(early.kind(), early.payload()).unwrap();
        assert_eq!(d.chunks, [b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn max_payload_and_cipher_state_are_bounded_without_raw_key_retention() {
        let cipher = PpcsPacketCipher::from_session_key(b"abcdefgh1234567890").unwrap();
        let packet = cipher.encode(0x20, &vec![0x55; MAX_PAYLOAD]).unwrap();
        let result = cipher.decode_obfuscated(packet.as_bytes()).unwrap();
        assert_eq!(result.payload().len(), MAX_PAYLOAD);
        assert!(std::mem::needs_drop::<PpcsPacketCipher>());
        assert!(std::mem::needs_drop::<DecodedPacket>());
    }
}
