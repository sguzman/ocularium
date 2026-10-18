//! Opt-in, synchronous UDP socket adapter for the bounded PPCS probe.
//!
//! This is a transport primitive, NOT an automatically running camera client.
//! Nothing in normal Ocularium startup or its GUI invokes this module.
//! Socket binding and sending require a deliberate caller invocation.
//! Peer 0x42 responses remain UNVERIFIED: the PPCS substitution cipher
//! provides neither authenticity nor integrity. Never begin media access
//! merely because this probe reports an unverified candidate.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use zeroize::{Zeroize, Zeroizing};

use crate::meari_ppcs_probe::{
    DatagramIo, PpcsOneShotProbe, ProbeEvent, ProbeState,
};

const MAX_DATAGRAM: usize = 16 * 1024 + 4;
const POLL_TIMEOUT: Duration = Duration::from_millis(75);
const SEND_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpProbeError {
    InvalidBind,
    SocketFailure,
    DatagramTooLarge,
    DifferentBind,
    ProbeRejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpProbeResult {
    UnverifiedCandidate,
    NoCandidate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpProbeSummary {
    pub result: UdpProbeResult,
    pub transmitted: usize,
    pub received: usize,
}

impl UdpProbeSummary {
    pub fn safe_text(self) -> String {
        format!(
            "PPCS one-shot UDP probe: {}; sent {} packets, observed {} packets. \
             No peer authenticated and no video opened.",
            match self.result {
                UdpProbeResult::UnverifiedCandidate => "unverified candidate",
                UdpProbeResult::NoCandidate => "no verified candidate",
            },
            self.transmitted,
            self.received
        )
    }
}

/// Datagram bytes are held in transient zeroizing memory. The sender
/// metadata is used only for the rendezvous preflight's allowlist check.
pub struct ReceivedDatagram {
    sender: SocketAddrV4,
    bytes: Zeroizing<Vec<u8>>,
}

impl ReceivedDatagram {
    pub fn sender(&self) -> SocketAddrV4 {
        self.sender
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Owns a single IPv4 UDP socket and closes it automatically on drop.
/// No clone, thread, listener service, retry queue or address resolver.
pub struct PpcsUdpSocket {
    socket: UdpSocket,
    bound: SocketAddrV4,
}

impl PpcsUdpSocket {
    /// Explicit bind to a concrete IPv4 interface. Port zero is allowed so
    /// tests and future callers can request an OS-assigned ephemeral port.
    /// The actual bound address is used when constructing the PPCS probe.
    pub fn bind_explicit(local: SocketAddrV4) -> Result<Self, UdpProbeError> {
        if !valid_bind_ip(local.ip()) {
            return Err(UdpProbeError::InvalidBind);
        }
        let socket = UdpSocket::bind(local).map_err(|_| UdpProbeError::SocketFailure)?;
        socket
            .set_read_timeout(Some(POLL_TIMEOUT))
            .map_err(|_| UdpProbeError::SocketFailure)?;
        socket
            .set_write_timeout(Some(SEND_TIMEOUT))
            .map_err(|_| UdpProbeError::SocketFailure)?;
        let SocketAddr::V4(bound) = socket
            .local_addr()
            .map_err(|_| UdpProbeError::SocketFailure)?
        else {
            return Err(UdpProbeError::InvalidBind);
        };
        if bound.ip() != local.ip() || bound.port() == 0 {
            return Err(UdpProbeError::InvalidBind);
        }
        Ok(Self { socket, bound })
    }

    pub fn local_addr(&self) -> SocketAddrV4 {
        self.bound
    }

    /// Read at most one datagram, without retrying, DNS lookup or interpreting
    /// any sender as trusted. A 75ms timeout returns Ok(None).
    pub fn receive_once(&self) -> Result<Option<ReceivedDatagram>, UdpProbeError> {
        let mut packet = [0u8; MAX_DATAGRAM + 1];
        let read = self.socket.recv_from(&mut packet);
        match read {
            Ok((count, SocketAddr::V4(sender))) => {
                if count > MAX_DATAGRAM {
                    packet.zeroize();
                    return Err(UdpProbeError::DatagramTooLarge);
                }
                let bytes = Zeroizing::new(packet[..count].to_vec());
                packet.zeroize();
                Ok(Some(ReceivedDatagram { sender, bytes }))
            }
            Ok((_, SocketAddr::V6(_))) => {
                packet.zeroize();
                Err(UdpProbeError::SocketFailure)
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                packet.zeroize();
                Ok(None)
            }
            Err(_) => {
                packet.zeroize();
                Err(UdpProbeError::SocketFailure)
            }
        }
    }

    /// Start the existing bounded probe and poll it until an unverified peer
    /// candidate, five-second expiry, or its receive/send budget exhaustion.
    /// Only an explicitly invoked call here can send datagrams.
    /// No response grants authorization to stream or open further sockets.
    pub fn run_one_shot(
        &mut self,
        probe: &mut PpcsOneShotProbe,
    ) -> Result<UdpProbeSummary, UdpProbeError> {
        if probe.state() != ProbeState::Ready {
            return Err(UdpProbeError::ProbeRejected);
        }
        if probe.local_addr() != self.bound {
            return Err(UdpProbeError::DifferentBind);
        }
        if probe.start(self, Instant::now()).is_err() {
            probe.close();
            return Err(UdpProbeError::ProbeRejected);
        }
        let result = loop {
            if probe.expire_at(Instant::now()) {
                break UdpProbeResult::NoCandidate;
            }
            let received = match self.receive_once() {
                Ok(Some(received)) => received,
                Ok(None) => continue,
                Err(_) => {
                    probe.close();
                    return Err(UdpProbeError::SocketFailure);
                }
            };
            match probe.receive(
                self,
                received.sender(),
                received.bytes(),
                Instant::now(),
            ) {
                Ok(ProbeEvent::UnverifiedCandidate) => {
                    break UdpProbeResult::UnverifiedCandidate;
                }
                Ok(ProbeEvent::Stopped) => break UdpProbeResult::NoCandidate,
                Ok(_) => {}
                Err(_) => {
                    probe.close();
                    return Err(UdpProbeError::ProbeRejected);
                }
            }
        };
        let summary = UdpProbeSummary {
            result,
            transmitted: probe.transmitted(),
            received: probe.observed(),
        };
        probe.close();
        Ok(summary)
    }
}

impl DatagramIo for PpcsUdpSocket {
    fn send_to(&mut self, data: &[u8], destination: SocketAddrV4) -> io::Result<usize> {
        if data.len() < 4 || data.len() > MAX_DATAGRAM || !valid_peer_destination(&destination) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bounded PPCS datagram",
            ));
        }
        self.socket.send_to(data, destination)
    }
}

fn valid_bind_ip(ip: &Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

fn valid_peer_destination(addr: &SocketAddrV4) -> bool {
    addr.port() != 0
        && !addr.ip().is_unspecified()
        && !addr.ip().is_multicast()
        && !addr.ip().is_broadcast()
}

/// Local-only tests: no external DNS, cloud login, household IP or camera.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        meari_devices::{AuthorizedCamera, Category},
        meari_ppcs_wire::PpcsPacketCipher,
        meari_vvp::Transport,
    };

    const INIT: &str =
        "0S5x0R0o10Kl6mKk3p1w4k0i5zKt5qKr4x3r0j0z1P7y9wJm1q1N:sample-key";
    const UUID: &str = "01-BCDEF-23B";

    fn loopback() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)
    }

    fn authorized_camera() -> AuthorizedCamera {
        AuthorizedCamera {
            device_id: "fake-device".into(),
            serial: "fake-serial".into(),
            category: Category::OtherCamera,
            transport: Transport::Ppcs,
            host_key: None,
            device_uuid: Some(UUID.into()),
            p2p_init: Some(INIT.into()),
            mac: None,
        }
    }

    #[test]
    fn bind_requires_an_explicit_interface_but_accepts_ephemeral_port() {
        assert!(matches!(
            PpcsUdpSocket::bind_explicit(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            Err(UdpProbeError::InvalidBind)
        ));
        assert!(matches!(
            PpcsUdpSocket::bind_explicit(SocketAddrV4::new(Ipv4Addr::BROADCAST, 0)),
            Err(UdpProbeError::InvalidBind)
        ));
        let socket = PpcsUdpSocket::bind_explicit(loopback()).unwrap();
        assert_eq!(*socket.local_addr().ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(socket.local_addr().port(), 0);
    }

    #[test]
    fn loopback_udp_roundtrip_can_deobfuscate_one_synthetic_datagram() {
        let mut sender = PpcsUdpSocket::bind_explicit(loopback()).unwrap();
        let receiver = PpcsUdpSocket::bind_explicit(loopback()).unwrap();
        let cipher = PpcsPacketCipher::from_session_key(b"fictional-key").unwrap();
        let sample = cipher.encode(0x41, b"fictional-payload").unwrap();
        assert_eq!(
            sender.send_to(sample.as_bytes(), receiver.local_addr()).unwrap(),
            sample.as_bytes().len()
        );
        let packet = receiver.receive_once().unwrap().unwrap();
        assert_eq!(packet.sender(), sender.local_addr());
        let decoded = cipher.decode_obfuscated(packet.bytes()).unwrap();
        assert_eq!(decoded.kind(), 0x41);
        assert_eq!(decoded.payload(), b"fictional-payload");
        // No camera socket and no background thread.
    }

    #[test]
    fn receive_timeout_does_not_retry_or_create_traffic() {
        let recv = PpcsUdpSocket::bind_explicit(loopback()).unwrap();
        let started = Instant::now();
        assert!(recv.receive_once().unwrap().is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn oversized_udp_datagram_is_rejected_without_partial_packet_parsing() {
        let recv = PpcsUdpSocket::bind_explicit(loopback()).unwrap();
        let sender = UdpSocket::bind(loopback()).unwrap();
        let huge = vec![0x55; MAX_DATAGRAM + 1];
        sender.send_to(&huge, recv.local_addr()).unwrap();
        assert!(matches!(
            recv.receive_once(),
            Err(UdpProbeError::DatagramTooLarge)
        ));
    }

    #[test]
    fn one_shot_cannot_send_when_probe_binding_differs_from_socket() {
        let root = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 9), 32100);
        let camera = authorized_camera();
        let mut udp = PpcsUdpSocket::bind_explicit(loopback()).unwrap();
        let other_local = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40000);
        // The probe is constructed with entirely synthetic account material,
        // but its announced local endpoint must equal the actual socket.
        let mut probe =
            PpcsOneShotProbe::from_authorized_record(&camera, &[root], other_local).unwrap();
        assert!(matches!(
            udp.run_one_shot(&mut probe),
            Err(UdpProbeError::DifferentBind)
        ));
        assert_eq!(probe.state(), ProbeState::Ready);
        assert_eq!(probe.transmitted(), 0);
    }

    #[test]
    fn invalid_destination_or_payload_never_causes_a_network_send() {
        let mut udp = PpcsUdpSocket::bind_explicit(loopback()).unwrap();
        assert!(udp.send_to(&[], udp.local_addr()).is_err());
        assert!(udp
            .send_to(&[0; 4], SocketAddrV4::new(Ipv4Addr::BROADCAST, 32100))
            .is_err());
        assert!(udp
            .send_to(&vec![0; MAX_DATAGRAM + 1], udp.local_addr())
            .is_err());
    }

    #[test]
    fn summary_cannot_disclose_peer_address_or_private_device_material() {
        let report = UdpProbeSummary {
            result: UdpProbeResult::UnverifiedCandidate,
            transmitted: 3,
            received: 4,
        };
        let text = report.safe_text();
        assert!(text.contains("unverified"));
        assert!(!text.contains("198.51.100"));
        assert!(!text.contains(UUID));
        assert!(!text.contains(INIT));
    }
}
