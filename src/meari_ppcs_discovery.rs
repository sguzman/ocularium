//! Offline PPStrong/PPCS factory-9 discovery data and rendezvous preflight.
//!
//! Based on the pinned MIT-licensed community reference:
//! raulrojas22/Ha-CloudPlus-Meari-ANRAN p2p_streamer/ppcs.py
//! c363366e5a712d6a0fee2be811eee23e15ee627a.
//!
//! A parsed factory DID or a response containing its bytes is NOT
//! cryptographic peer authentication. This module never resolves DNS, opens
//! sockets, sends a packet, logs identifiers, or claims a working session.
//! Inputs must ultimately originate from an authorized device-list response.

use std::net::{Ipv4Addr, SocketAddrV4};

use zeroize::{Zeroize, Zeroizing};

use crate::meari_ppcs_wire::{PpcsPacketCipher, WireError};

const MAX_UUID_TEXT: usize = 256;
const MAX_INIT_TEXT: usize = 2048;
const MAX_ROOTS: usize = 16;
const ROOT_PORT: u16 = 32100;
const MAX_OFFERS: usize = 32;
const PUNCH_RADIUS: u16 = 3;

const INIT_SEED: [u8; 54] = [
    0x49, 0x59, 0x43, 0x3d, 0xb5, 0xbf, 0x6d, 0xa3, 0x47, 0x53, 0x4f, 0x61, 0x65, 0xe3, 0x71, 0xe9,
    0x67, 0x7f, 0x02, 0x03, 0x0b, 0xad, 0xb3, 0x89, 0x2b, 0x2f, 0x35, 0xc1, 0x6b, 0x8b, 0x95, 0x97,
    0x11, 0xe5, 0xa7, 0x0d, 0xef, 0xf1, 0x05, 0x07, 0x83, 0xfb, 0x9d, 0x3b, 0xc5, 0xc7, 0x13, 0x17,
    0x1d, 0x1f, 0x25, 0x29, 0xd3, 0xdf,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    InvalidDeviceUuid,
    InvalidInitialization,
    InvalidRoot,
    TooManyRoots,
    InvalidKey,
    InvalidAddress,
    UntrustedRoot,
}

impl From<WireError> for DiscoveryError {
    fn from(_: WireError) -> Self {
        Self::InvalidKey
    }
}

/// Device-provided factory identity. Never log/serialize/debug the DID.
pub struct PpcsDeviceIdentity {
    token: [u8; 20],
}

impl Drop for PpcsDeviceIdentity {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl PpcsDeviceIdentity {
    pub fn from_factory_uuid(uuid: &str) -> Result<Self, DiscoveryError> {
        let uuid = uuid.trim();
        if uuid.len() < 2 || uuid.len() > MAX_UUID_TEXT || !uuid.is_ascii() || !uuid.ends_with('B')
        {
            return Err(DiscoveryError::InvalidDeviceUuid);
        }
        // The final B is the wrapper marker, not part of the decoded DID.
        let mut decoded = Zeroizing::new(Vec::with_capacity(uuid.len() - 1));
        for &byte in &uuid.as_bytes()[..uuid.len() - 1] {
            let translated = match byte {
                b'A'..=b'J' => byte - 0x11,
                b'0'..=b'9' => byte + 0x11,
                b'a'..=b'p' => byte - 0x16,
                b'q'..=b'z' => byte - 0x10,
                b'K'..=b'Z' => byte + 0x20,
                _ => byte,
            };
            decoded.push(translated);
        }
        let did = decoded.split(|&ch| ch == b',').next().unwrap_or_default();
        let parts: Vec<&[u8]> = did.split(|&ch| ch == b'-').collect();
        if parts.len() != 3
            || !valid_uppercase(parts[0])
            || !valid_uppercase(parts[2])
            || parts[1].is_empty()
            || parts[1].len() > 10
            || !parts[1].iter().all(u8::is_ascii_digit)
        {
            return Err(DiscoveryError::InvalidDeviceUuid);
        }
        let number = std::str::from_utf8(parts[1])
            .ok()
            .and_then(|text| text.parse::<u32>().ok())
            .ok_or(DiscoveryError::InvalidDeviceUuid)?;
        let mut token = [0u8; 20];
        token[..parts[0].len()].copy_from_slice(parts[0]);
        token[8..12].copy_from_slice(&number.to_be_bytes());
        token[12..12 + parts[2].len()].copy_from_slice(parts[2]);
        Ok(Self { token })
    }

    pub fn token(&self) -> &[u8; 20] {
        &self.token
    }
}

fn valid_uppercase(bytes: &[u8]) -> bool {
    (1..=8).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_uppercase)
}

/// Session configuration from a legitimately authenticated device record.
/// Only normalized root hostnames and a *derived* packet cipher are retained.
/// A root hostname is never trusted as a remote socket without independent
/// resolution and source-address checks by a future network transport.
pub struct PpcsDeviceInit {
    roots: Vec<Zeroizing<String>>,
    cipher: PpcsPacketCipher,
}

impl PpcsDeviceInit {
    pub fn from_device_init(init: &str) -> Result<Self, DiscoveryError> {
        if init.is_empty() || init.len() > MAX_INIT_TEXT || !init.is_ascii() {
            return Err(DiscoveryError::InvalidInitialization);
        }
        let (encoded, raw_key) = init
            .split_once(':')
            .ok_or(DiscoveryError::InvalidInitialization)?;
        if encoded.is_empty()
            || encoded.len() % 2 != 0
            || raw_key.is_empty()
            || raw_key.len() > 128
            || !raw_key.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(DiscoveryError::InvalidInitialization);
        }
        let cipher = PpcsPacketCipher::from_session_key(raw_key.as_bytes())?;
        let mut text = Zeroizing::new(Vec::with_capacity(encoded.len() / 2));
        let mut checksum = 0x39u8;
        for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
            if !pair.iter().all(u8::is_ascii_alphanumeric) {
                return Err(DiscoveryError::InvalidInitialization);
            }
            let weighted = (pair[1] as u16)
                .wrapping_add((pair[0] as u16) * 16)
                .wrapping_add(0xaf) as u8;
            let decoded = checksum ^ weighted ^ INIT_SEED[index % INIT_SEED.len()];
            text.push(decoded);
            checksum ^= decoded;
        }
        let text = std::str::from_utf8(&text).map_err(|_| DiscoveryError::InvalidRoot)?;
        let mut roots = Vec::new();
        for hostname in text.split(',') {
            let hostname = hostname.trim();
            if !valid_root_hostname(hostname) {
                return Err(DiscoveryError::InvalidRoot);
            }
            if roots
                .iter()
                .any(|value: &Zeroizing<String>| value.as_str() == hostname)
            {
                continue;
            }
            if roots.len() >= MAX_ROOTS {
                return Err(DiscoveryError::TooManyRoots);
            }
            roots.push(Zeroizing::new(hostname.to_owned()));
        }
        if roots.is_empty() {
            return Err(DiscoveryError::InvalidRoot);
        }
        Ok(Self { roots, cipher })
    }

    pub fn root_hosts(&self) -> impl Iterator<Item = &str> {
        self.roots.iter().map(|value| value.as_str())
    }

    pub fn packet_cipher(&self) -> &PpcsPacketCipher {
        &self.cipher
    }
}

fn valid_root_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        // Reject malformed dotted IPs rather than interpreting them as DNS.
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
    })
}

fn address_acceptable(addr: &SocketAddrV4) -> bool {
    let ip = addr.ip();
    addr.port() != 0
        && !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_link_local()
}

/// PPCS's 16-byte IPv4 sockaddr encoding: family 0x0002, little-endian port,
/// IPv4 octets reversed and eight zero bytes. Only a decoded peer *offer*.
pub fn parse_peer_sockaddr(bytes: &[u8]) -> Result<SocketAddrV4, DiscoveryError> {
    if bytes.len() != 16 || bytes[0..2] != [0, 2] || bytes[8..].iter().any(|&b| b != 0) {
        return Err(DiscoveryError::InvalidAddress);
    }
    let port = u16::from_le_bytes([bytes[2], bytes[3]]);
    let ip = Ipv4Addr::new(bytes[7], bytes[6], bytes[5], bytes[4]);
    let addr = SocketAddrV4::new(ip, port);
    if !address_acceptable(&addr) {
        return Err(DiscoveryError::InvalidAddress);
    }
    Ok(addr)
}

pub fn encode_peer_sockaddr(addr: Option<SocketAddrV4>) -> Result<[u8; 16], DiscoveryError> {
    let mut out = [0u8; 16];
    out[..2].copy_from_slice(&[0, 2]);
    if let Some(addr) = addr {
        if !address_acceptable(&addr) {
            return Err(DiscoveryError::InvalidAddress);
        }
        out[2..4].copy_from_slice(&addr.port().to_le_bytes());
        let mut ip = addr.ip().octets();
        ip.reverse();
        out[4..8].copy_from_slice(&ip);
    }
    Ok(out)
}

/// Observable rendezvous preflight outcomes, not cryptographic authentication.
/// Does not include peer IPs or device IDs, so it is safe to count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerObservation {
    Ignored,
    RootOffer,
    PeerChallenge,
    PeerResponse,
}

/// Pure state machine for packets from an already provisioned PPCS session.
/// Roots MUST be independently resolved by a future controlled transport.
/// A matched response remains spoofable: there is no cryptographic MAC.
pub struct PpcsRendezvousPreflight {
    identity: PpcsDeviceIdentity,
    trusted_root_ips: Vec<Ipv4Addr>,
    offered: Vec<SocketAddrV4>,
}

impl PpcsRendezvousPreflight {
    pub fn new(
        identity: PpcsDeviceIdentity,
        trusted_root_ips: &[Ipv4Addr],
    ) -> Result<Self, DiscoveryError> {
        if trusted_root_ips.is_empty()
            || trusted_root_ips.len() > MAX_ROOTS
            || trusted_root_ips.iter().any(|ip| {
                ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
            })
        {
            return Err(DiscoveryError::UntrustedRoot);
        }
        Ok(Self {
            identity,
            trusted_root_ips: trusted_root_ips.to_vec(),
            offered: Vec::new(),
        })
    }

    pub fn observe_plaintext_packet(
        &mut self,
        from: SocketAddrV4,
        packet_type: u8,
        payload: &[u8],
    ) -> PeerObservation {
        if self.trusted_root_ips.contains(from.ip()) {
            if !(ROOT_PORT..=ROOT_PORT + 2).contains(&from.port()) || packet_type != 0x40 {
                return PeerObservation::Ignored;
            }
            let Ok(offer) = parse_peer_sockaddr(payload) else {
                return PeerObservation::Ignored;
            };
            if self.offered.contains(&offer) {
                return PeerObservation::Ignored;
            }
            if self.offered.len() >= MAX_OFFERS {
                return PeerObservation::Ignored;
            }
            self.offered.push(offer);
            return PeerObservation::RootOffer;
        }
        if !matches!(packet_type, 0x41 | 0x42) || payload != self.identity.token() {
            return PeerObservation::Ignored;
        }
        // The upstream client accepts new direct replies by DID alone.
        // Restrict our preflight to a previously offered IP and the bounded
        // 3-port hole-punch radius. Still NOT cryptographic authentication.
        let offered = self.offered.iter().any(|offered| {
            offered.ip() == from.ip() && offered.port().abs_diff(from.port()) <= PUNCH_RADIUS
        });
        if !offered {
            return PeerObservation::Ignored;
        }
        if packet_type == 0x41 {
            PeerObservation::PeerChallenge
        } else {
            PeerObservation::PeerResponse
        }
    }

    pub fn candidate_count(&self) -> usize {
        self.offered.len()
    }

    pub fn reset(&mut self) {
        self.offered.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "01-BCDEF-23B";
    // Independently generated from the pinned Python decode algorithm:
    // relay.example,198.51.100.9; the key is fictitious.
    const INIT: &str = "0S5x0R0o10Kl6mKk3p1w4k0i5zKt5qKr4x3r0j0z1P7y9wJm1q1N:sample-key";

    #[test]
    fn factory9_uuid_known_vector_builds_expected_twenty_byte_identity() {
        let id = PpcsDeviceIdentity::from_factory_uuid(UUID).unwrap();
        let mut expected = [0u8; 20];
        expected[..2].copy_from_slice(b"AB");
        expected[8..12].copy_from_slice(&12345u32.to_be_bytes());
        expected[12..14].copy_from_slice(b"CD");
        assert_eq!(*id.token(), expected);
    }

    #[test]
    fn rejects_untrusted_or_malformed_device_id_wrappers() {
        for invalid in [
            "",
            "01-BCDEF-23",
            "01-BCDEF-23A",
            "01-BCDEF-,B",
            "01-BCDEF-23?B",
            "01-BCDEFGHIJK-23B",
            "01-9999999999-23B",
            "01-BCDEF-23B\0",
        ] {
            assert!(PpcsDeviceIdentity::from_factory_uuid(invalid).is_err());
        }
    }

    #[test]
    fn init_roots_are_decoded_offline_and_packet_cipher_works() {
        let init = PpcsDeviceInit::from_device_init(INIT).unwrap();
        let roots: Vec<_> = init.root_hosts().collect();
        assert_eq!(roots, ["relay.example", "198.51.100.9"]);
        let packet = init.packet_cipher().encode(0xe0, &[]).unwrap();
        assert_eq!(
            init.packet_cipher()
                .decode_obfuscated(packet.as_bytes())
                .unwrap()
                .kind(),
            0xe0
        );
        assert!(std::mem::needs_drop::<PpcsDeviceInit>());
    }

    #[test]
    fn rejects_invalid_initialization_without_network_or_fallback() {
        for invalid in [
            "",
            "not-an-init",
            "abcd:",
            "a:secret",
            "00:secret",
            "0S5x0R0o10Kl6mKk3p1w4k0i5zKt5qKr4x3r0j0z1P7y9wJm1q1N:",
            "0S5x0R0o10Kl6mKk3p1w4k0i5zKt5qKr4x3r0j0z1P7y9wJm1q1N:bad\nkey",
        ] {
            assert!(PpcsDeviceInit::from_device_init(invalid).is_err());
        }
    }

    #[test]
    fn real_wire_layout_combines_offline_seed_offer_and_candidate_response() {
        let identity = PpcsDeviceIdentity::from_factory_uuid(UUID).unwrap();
        let token = *identity.token();
        let init = PpcsDeviceInit::from_device_init(INIT).unwrap();
        let root_ip = Ipv4Addr::new(198, 51, 100, 9);
        let root = SocketAddrV4::new(root_ip, ROOT_PORT);
        let peer = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 99), 39000);
        let mut preflight = PpcsRendezvousPreflight::new(identity, &[root_ip]).unwrap();

        let offer = encode_peer_sockaddr(Some(peer)).unwrap();
        let wire_offer = init.packet_cipher().encode(0x40, &offer).unwrap();
        let decoded_offer = init
            .packet_cipher()
            .decode_obfuscated(wire_offer.as_bytes())
            .unwrap();
        assert_eq!(
            preflight.observe_plaintext_packet(root, decoded_offer.kind(), decoded_offer.payload()),
            PeerObservation::RootOffer
        );

        let wire_reply = init.packet_cipher().encode(0x42, &token).unwrap();
        let decoded_reply = init
            .packet_cipher()
            .decode_obfuscated(wire_reply.as_bytes())
            .unwrap();
        assert_eq!(
            preflight.observe_plaintext_packet(peer, decoded_reply.kind(), decoded_reply.payload()),
            PeerObservation::PeerResponse
        );
        // No peer-authentication or video-transport operation occurred.
    }

    #[test]
    fn sockaddr_wire_vector_and_rejects_malformed_candidates() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 44), 32100);
        let wire = encode_peer_sockaddr(Some(addr)).unwrap();
        assert_eq!(&wire[..8], &[0, 2, 0x64, 0x7d, 44, 2, 0, 192]);
        assert_eq!(parse_peer_sockaddr(&wire).unwrap(), addr);
        assert_eq!(
            encode_peer_sockaddr(None).unwrap(),
            [0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(parse_peer_sockaddr(&encode_peer_sockaddr(None).unwrap()).is_err());
        let mut bad = wire;
        bad[11] = 1;
        assert!(parse_peer_sockaddr(&bad).is_err());
        assert!(parse_peer_sockaddr(&wire[..8]).is_err());
        assert!(encode_peer_sockaddr(Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 32100))).is_err());
    }

    #[test]
    fn state_machine_requires_offered_peer_identity_and_bounded_hole_punch() {
        let id = PpcsDeviceIdentity::from_factory_uuid(UUID).unwrap();
        let token = *id.token();
        let root = Ipv4Addr::new(198, 51, 100, 8);
        let peer = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 44), 39000);
        let root_endpoint = SocketAddrV4::new(root, ROOT_PORT);
        let mut preflight = PpcsRendezvousPreflight::new(id, &[root]).unwrap();
        let offer = encode_peer_sockaddr(Some(peer)).unwrap();
        assert_eq!(
            preflight.observe_plaintext_packet(peer, 0x42, &token),
            PeerObservation::Ignored
        );
        assert_eq!(
            preflight.observe_plaintext_packet(
                SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 9), ROOT_PORT),
                0x40,
                &offer,
            ),
            PeerObservation::Ignored
        );
        assert_eq!(
            preflight.observe_plaintext_packet(root_endpoint, 0x40, &offer),
            PeerObservation::RootOffer
        );
        assert_eq!(preflight.candidate_count(), 1);
        assert_eq!(
            preflight.observe_plaintext_packet(root_endpoint, 0x40, &offer),
            PeerObservation::Ignored
        );
        assert_eq!(
            preflight.observe_plaintext_packet(peer, 0x42, b"other-device"),
            PeerObservation::Ignored
        );
        let nearby = SocketAddrV4::new(*peer.ip(), peer.port() + PUNCH_RADIUS);
        assert_eq!(
            preflight.observe_plaintext_packet(nearby, 0x41, &token),
            PeerObservation::PeerChallenge
        );
        assert_eq!(
            preflight.observe_plaintext_packet(nearby, 0x42, &token),
            PeerObservation::PeerResponse
        );
        let far = SocketAddrV4::new(*peer.ip(), peer.port() + PUNCH_RADIUS + 1);
        assert_eq!(
            preflight.observe_plaintext_packet(far, 0x42, &token),
            PeerObservation::Ignored
        );
        preflight.reset();
        assert_eq!(preflight.candidate_count(), 0);
        assert_eq!(
            preflight.observe_plaintext_packet(peer, 0x42, &token),
            PeerObservation::Ignored
        );
    }
}
