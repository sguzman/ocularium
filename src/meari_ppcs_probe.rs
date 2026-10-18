//! Bounded, explicitly initiated legacy PPCS rendezvous controller.
//!
//! This controller emits and consumes *one* finite set of obfuscated PPCS
//! datagrams through a caller-provided DatagramIo. No socket, account login,
//! GUI trigger, service or periodic worker exists in this module.
//!
//! A valid 0x42 response is an UNVERIFIED peer candidate: PPCS obfuscation
//! carries no authentication tag. Neither this result nor the account's
//! deviceP2P declaration is proof of control of a camera.
//!
//! The caller must separately establish permission to access the camera,
//! resolve only roots listed by the authenticated device record, and bind
//! any subsequent media transport to a verified endpoint/session.

use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, Instant},
};

use zeroize::Zeroizing;

use crate::{
    meari_devices::AuthorizedCamera,
    meari_ppcs_discovery::{
        encode_peer_sockaddr, parse_peer_sockaddr, PeerObservation, PpcsDeviceIdentity,
        PpcsDeviceInit, PpcsRendezvousPreflight,
    },
    meari_vvp::Transport,
};

const MAX_ROOT_ENDPOINTS: usize = 8;
const MAX_CANDIDATE_OFFERS: usize = 4;
const MAX_RX_DATAGRAMS: usize = 64;
const MAX_TX_DATAGRAMS: usize = 48;
const DEADLINE: Duration = Duration::from_secs(5);
const PUNCH_RADIUS: u16 = 3;

/// Does not expose network credentials or reveal endpoint values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    UnsupportedTransport,
    MissingDeviceMaterial,
    InvalidDeviceMaterial,
    InvalidLocalAddress,
    InvalidRoots,
    TransportFailed,
    Closed,
}

/// One datagram is sent synchronously. The caller owns the socket, if any.
/// There is no hidden retry mechanism or default UDP implementation.
pub trait DatagramIo {
    fn send_to(&mut self, payload: &[u8], destination: SocketAddrV4) -> io::Result<usize>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeState {
    Ready,
    Waiting,
    UnverifiedCandidate,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeEvent {
    Ignored,
    RootOffer,
    ChallengeResponded,
    UnverifiedCandidate,
    Stopped,
}

/// Does not implement Debug or Serialize because the original auth material,
/// factory device identity and derived packet cipher are private.
pub struct PpcsOneShotProbe {
    init: PpcsDeviceInit,
    preflight: PpcsRendezvousPreflight,
    local_addr: SocketAddrV4,
    roots: Vec<SocketAddrV4>,
    state: ProbeState,
    ends_at: Option<Instant>,
    sends: usize,
    receives: usize,
    offered: usize,
}

impl PpcsOneShotProbe {
    /// Only explicit, authenticated catalog records that declare PPCS qualify.
    /// Resolved root addresses are provided by a future authorized caller;
    /// that caller MUST resolve only the listed init.root_hosts(), then verify
    /// each address against its original hostname before providing it here.
    /// This constructor alone cannot authenticate DNS or the remote device.
    pub fn from_authorized_record(
        camera: &AuthorizedCamera,
        roots: &[SocketAddrV4],
        local_addr: SocketAddrV4,
    ) -> Result<Self, ProbeError> {
        if camera.transport != Transport::Ppcs {
            return Err(ProbeError::UnsupportedTransport);
        }
        let uuid = camera
            .device_uuid
            .as_deref()
            .ok_or(ProbeError::MissingDeviceMaterial)?;
        let p2p_init = camera
            .p2p_init
            .as_deref()
            .ok_or(ProbeError::MissingDeviceMaterial)?;
        let identity = PpcsDeviceIdentity::from_factory_uuid(uuid)
            .map_err(|_| ProbeError::InvalidDeviceMaterial)?;
        let init = PpcsDeviceInit::from_device_init(p2p_init)
            .map_err(|_| ProbeError::InvalidDeviceMaterial)?;
        if roots.is_empty()
            || roots.len() > MAX_ROOT_ENDPOINTS
            || roots
                .iter()
                .any(|root| root.port() != 32100 || !safe_endpoint(root))
        {
            return Err(ProbeError::InvalidRoots);
        }
        if local_addr.port() == 0
            || local_addr.ip().is_unspecified()
            || local_addr.ip().is_multicast()
            || local_addr.ip().is_broadcast()
        {
            return Err(ProbeError::InvalidLocalAddress);
        }
        let mut root_ips: Vec<Ipv4Addr> = Vec::new();
        for root in roots {
            if !root_ips.contains(root.ip()) {
                root_ips.push(*root.ip());
            }
        }
        let preflight = PpcsRendezvousPreflight::new(identity, &root_ips)
            .map_err(|_| ProbeError::InvalidRoots)?;
        Ok(Self {
            init,
            preflight,
            local_addr,
            roots: roots.to_vec(),
            state: ProbeState::Ready,
            ends_at: None,
            sends: 0,
            receives: 0,
            offered: 0,
        })
    }

    /// The local socket address must match the transport exactly. A guessed
    /// local IP or a bind to a different interface would invalidate the
    /// advertised PPCS rendezvous address.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local_addr
    }

    pub fn state(&self) -> ProbeState {
        self.state
    }

    pub fn transmitted(&self) -> usize {
        self.sends
    }

    pub fn observed(&self) -> usize {
        self.receives
    }

    /// Explicit one-shot start. Exactly two request packets go to each
    /// authorized caller-supplied root: 0x00 hello and 0x20 rendezvous.
    /// Does not transmit automatically during object construction.
    pub fn start(&mut self, io: &mut impl DatagramIo, now: Instant) -> Result<(), ProbeError> {
        if self.state != ProbeState::Ready {
            return Err(ProbeError::Closed);
        }
        let local = encode_peer_sockaddr(Some(self.local_addr))
            .map_err(|_| ProbeError::InvalidLocalAddress)?;
        // The request consists of factory DID bytes followed by the socket.
        let mut request = Zeroizing::new(Vec::with_capacity(36));
        let identity = *self.preflight.identity_bytes();
        request.extend_from_slice(&identity);
        request.extend_from_slice(&local);
        self.ends_at = Some(now + DEADLINE);
        self.state = ProbeState::Waiting;
        let roots = self.roots.clone();
        for root in roots {
            self.send(io, root, 0x00, &[])?;
            self.send(io, root, 0x20, &request)?;
        }
        Ok(())
    }

    /// The caller may call this without receiving traffic. A stopped probe
    /// cannot be restarted or turned into an indefinitely running service.
    pub fn expire_at(&mut self, now: Instant) -> bool {
        if self.state != ProbeState::Waiting {
            return self.state == ProbeState::Stopped;
        }
        if self.ends_at.is_some_and(|end| now >= end) {
            self.close();
            return true;
        }
        false
    }

    /// Caller must supply the actual datagram sender. This merely checks
    /// candidate envelopes from a prescribed root/port and bounded offers;
    /// it does NOT verify network identity or provide an auth capability.
    pub fn receive(
        &mut self,
        io: &mut impl DatagramIo,
        from: SocketAddrV4,
        bytes: &[u8],
        now: Instant,
    ) -> Result<ProbeEvent, ProbeError> {
        if self.expire_at(now) {
            return Ok(ProbeEvent::Stopped);
        }
        if self.state != ProbeState::Waiting {
            return Err(ProbeError::Closed);
        }
        if self.receives >= MAX_RX_DATAGRAMS {
            self.close();
            return Ok(ProbeEvent::Stopped);
        }
        self.receives += 1;
        if bytes.len() > 16 * 1024 + 4 {
            return Ok(ProbeEvent::Ignored);
        }
        let Ok(decoded) = self.init.packet_cipher().decode_obfuscated(bytes) else {
            return Ok(ProbeEvent::Ignored);
        };
        let observation =
            self.preflight
                .observe_plaintext_packet(from, decoded.kind(), decoded.payload());
        match observation {
            PeerObservation::Ignored => Ok(ProbeEvent::Ignored),
            PeerObservation::RootOffer => {
                // parse_peer_sockaddr is called only after the preflight
                // verified the sender's root IP and the offered frame syntax.
                let Ok(candidate) = parse_peer_sockaddr(decoded.payload()) else {
                    return Ok(ProbeEvent::Ignored);
                };
                if self.offered >= MAX_CANDIDATE_OFFERS {
                    return Ok(ProbeEvent::Ignored);
                }
                self.offered += 1;
                let base = candidate.port();
                let identity = *self.preflight.identity_bytes();
                for port in base.saturating_sub(PUNCH_RADIUS)..=base.saturating_add(PUNCH_RADIUS) {
                    if port != 0 {
                        self.send(
                            io,
                            SocketAddrV4::new(*candidate.ip(), port),
                            0x41,
                            &identity,
                        )?;
                    }
                }
                Ok(ProbeEvent::RootOffer)
            }
            PeerObservation::PeerChallenge => {
                let identity = *self.preflight.identity_bytes();
                self.send(io, from, 0x41, &identity)?;
                Ok(ProbeEvent::ChallengeResponded)
            }
            PeerObservation::PeerResponse => {
                self.state = ProbeState::UnverifiedCandidate;
                Ok(ProbeEvent::UnverifiedCandidate)
            }
        }
    }

    pub fn close(&mut self) {
        self.state = ProbeState::Stopped;
        self.ends_at = None;
        self.roots.clear();
        self.preflight.reset();
    }

    fn send(
        &mut self,
        io: &mut impl DatagramIo,
        destination: SocketAddrV4,
        kind: u8,
        payload: &[u8],
    ) -> Result<(), ProbeError> {
        if self.sends >= MAX_TX_DATAGRAMS {
            self.close();
            return Err(ProbeError::TransportFailed);
        }
        self.sends += 1;
        let packet = self
            .init
            .packet_cipher()
            .encode(kind, payload)
            .map_err(|_| ProbeError::InvalidDeviceMaterial)?;
        if io.send_to(packet.as_bytes(), destination).ok() != Some(packet.as_bytes().len()) {
            self.close();
            return Err(ProbeError::TransportFailed);
        }
        Ok(())
    }
}

fn safe_endpoint(addr: &SocketAddrV4) -> bool {
    addr.port() != 0
        && !addr.ip().is_unspecified()
        && !addr.ip().is_loopback()
        && !addr.ip().is_multicast()
        && !addr.ip().is_broadcast()
        && !addr.ip().is_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        meari_devices::Category, meari_ppcs_discovery::PpcsDeviceInit,
        meari_ppcs_wire::PpcsPacketCipher,
    };

    const UUID: &str = "01-BCDEF-23B";
    const INIT: &str = "0S5x0R0o10Kl6mKk3p1w4k0i5zKt5qKr4x3r0j0z1P7y9wJm1q1N:sample-key";

    fn camera(transport: Transport) -> AuthorizedCamera {
        AuthorizedCamera {
            device_id: "synthetic-id".into(),
            serial: "synthetic-serial".into(),
            category: Category::OtherCamera,
            transport,
            host_key: None,
            device_uuid: Some(UUID.into()),
            p2p_init: Some(INIT.into()),
            mac: None,
        }
    }

    fn root() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 9), 32100)
    }

    fn local() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 100), 40000)
    }

    fn peer() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 50), 39000)
    }

    #[derive(Default)]
    struct MockIo {
        sent: Vec<(SocketAddrV4, Vec<u8>)>,
        fail_at: Option<usize>,
    }

    impl DatagramIo for MockIo {
        fn send_to(&mut self, payload: &[u8], to: SocketAddrV4) -> io::Result<usize> {
            if self.fail_at == Some(self.sent.len()) {
                return Err(io::Error::other("synthetic send failure"));
            }
            self.sent.push((to, payload.to_vec()));
            Ok(payload.len())
        }
    }

    fn encoded(kind: u8, data: &[u8]) -> Vec<u8> {
        let cipher = PpcsPacketCipher::from_session_key(b"sample-key").unwrap();
        cipher.encode(kind, data).unwrap().as_bytes().to_vec()
    }

    #[test]
    fn refuses_unverified_transport_missing_secrets_and_bad_roots() {
        let cam = camera(Transport::Unknown);
        assert!(matches!(
            PpcsOneShotProbe::from_authorized_record(&cam, &[root()], local()),
            Err(ProbeError::UnsupportedTransport)
        ));
        let mut cam = camera(Transport::Ppcs);
        cam.p2p_init = None;
        assert!(matches!(
            PpcsOneShotProbe::from_authorized_record(&cam, &[root()], local()),
            Err(ProbeError::MissingDeviceMaterial)
        ));
        let cam = camera(Transport::Ppcs);
        assert!(matches!(
            PpcsOneShotProbe::from_authorized_record(&cam, &[], local()),
            Err(ProbeError::InvalidRoots)
        ));
        assert!(matches!(
            PpcsOneShotProbe::from_authorized_record(
                &cam,
                &[SocketAddrV4::new(Ipv4Addr::LOCALHOST, 32100)],
                local()
            ),
            Err(ProbeError::InvalidRoots)
        ));
    }

    #[test]
    fn no_traffic_before_explicit_start_then_exact_hello_and_request() {
        let cam = camera(Transport::Ppcs);
        let mut probe = PpcsOneShotProbe::from_authorized_record(&cam, &[root()], local()).unwrap();
        let mut io = MockIo::default();
        assert_eq!(probe.state(), ProbeState::Ready);
        assert!(io.sent.is_empty());
        let now = Instant::now();
        probe.start(&mut io, now).unwrap();
        assert_eq!(probe.state(), ProbeState::Waiting);
        assert_eq!(io.sent.len(), 2);
        let cipher = PpcsDeviceInit::from_device_init(INIT).unwrap();
        let hello = cipher
            .packet_cipher()
            .decode_obfuscated(&io.sent[0].1)
            .unwrap();
        assert_eq!(hello.kind(), 0x00);
        assert!(hello.payload().is_empty());
        let request = cipher
            .packet_cipher()
            .decode_obfuscated(&io.sent[1].1)
            .unwrap();
        assert_eq!(request.kind(), 0x20);
        assert_eq!(request.payload().len(), 36);
        assert_eq!(
            &request.payload()[20..],
            &encode_peer_sockaddr(Some(local())).unwrap()
        );
        assert_eq!(io.sent[1].0, root());
        assert_eq!(probe.start(&mut io, now).err(), Some(ProbeError::Closed));
    }

    #[test]
    fn candidate_requires_root_offer_and_correct_identity_and_port() {
        let cam = camera(Transport::Ppcs);
        let mut probe = PpcsOneShotProbe::from_authorized_record(&cam, &[root()], local()).unwrap();
        let mut io = MockIo::default();
        let now = Instant::now();
        probe.start(&mut io, now).unwrap();
        let id = PpcsDeviceIdentity::from_factory_uuid(UUID).unwrap();
        let peer_reply = encoded(0x42, id.token());
        assert_eq!(
            probe.receive(&mut io, peer(), &peer_reply, now).unwrap(),
            ProbeEvent::Ignored
        );
        let candidate = encode_peer_sockaddr(Some(peer())).unwrap();
        let offer = encoded(0x40, &candidate);
        let fake_root = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 8), 32100);
        assert_eq!(
            probe.receive(&mut io, fake_root, &offer, now).unwrap(),
            ProbeEvent::Ignored
        );
        assert_eq!(
            probe.receive(&mut io, root(), &offer, now).unwrap(),
            ProbeEvent::RootOffer
        );
        assert_eq!(io.sent.len(), 9);
        assert_eq!(
            probe
                .receive(&mut io, peer(), &encoded(0x42, b"wrong-id"), now)
                .unwrap(),
            ProbeEvent::Ignored
        );
        assert_eq!(
            probe
                .receive(&mut io, peer(), &encoded(0x41, id.token()), now)
                .unwrap(),
            ProbeEvent::ChallengeResponded
        );
        assert_eq!(io.sent.len(), 10);
        assert_eq!(
            probe.receive(&mut io, peer(), &peer_reply, now).unwrap(),
            ProbeEvent::UnverifiedCandidate
        );
        assert_eq!(probe.state(), ProbeState::UnverifiedCandidate);
        assert_eq!(
            probe.receive(&mut io, peer(), &peer_reply, now).err(),
            Some(ProbeError::Closed)
        );
    }

    #[test]
    fn request_budget_expiry_and_failure_cannot_trigger_retries() {
        let cam = camera(Transport::Ppcs);
        let now = Instant::now();
        let mut probe = PpcsOneShotProbe::from_authorized_record(&cam, &[root()], local()).unwrap();
        let mut io = MockIo::default();
        probe.start(&mut io, now).unwrap();
        assert!(probe.expire_at(now + DEADLINE));
        assert_eq!(probe.state(), ProbeState::Stopped);
        assert_eq!(probe.start(&mut io, now).err(), Some(ProbeError::Closed));
        assert_eq!(
            probe
                .receive(&mut io, peer(), &[0], now + DEADLINE)
                .unwrap(),
            ProbeEvent::Stopped
        );
        let mut failed =
            PpcsOneShotProbe::from_authorized_record(&cam, &[root()], local()).unwrap();
        let mut io = MockIo {
            fail_at: Some(1),
            ..Default::default()
        };
        assert_eq!(
            failed.start(&mut io, now).err(),
            Some(ProbeError::TransportFailed)
        );
        assert_eq!(failed.state(), ProbeState::Stopped);
        assert_eq!(io.sent.len(), 1);
    }

    #[test]
    fn excessive_inbound_traffic_stops_one_shot_without_more_output() {
        let cam = camera(Transport::Ppcs);
        let now = Instant::now();
        let mut probe = PpcsOneShotProbe::from_authorized_record(&cam, &[root()], local()).unwrap();
        let mut io = MockIo::default();
        probe.start(&mut io, now).unwrap();
        for _ in 0..MAX_RX_DATAGRAMS {
            assert_eq!(
                probe
                    .receive(&mut io, peer(), &encoded(0xe0, &[]), now)
                    .unwrap(),
                ProbeEvent::Ignored
            );
        }
        assert_eq!(
            probe.receive(&mut io, peer(), &[0], now).unwrap(),
            ProbeEvent::Stopped
        );
        assert_eq!(probe.state(), ProbeState::Stopped);
        assert_eq!(io.sent.len(), 2);
    }
}
