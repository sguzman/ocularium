//! Multicast DNS service discovery on the selected IPv4 interface.
//! Read-only service enumeration; no credentials and no external connections.
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashSet,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
    },
    time::{Duration, Instant},
};

use crate::discovery::{Event, Observation, Scope};

const MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const PORT: u16 = 5353;
const QUERIES: [&str; 5] = [
    "_services._dns-sd._udp.local",
    "_rtsp._tcp.local",
    "_onvif._tcp.local",
    "_http._tcp.local",
    "_axis-video._tcp.local",
];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MdnsInfo {
    pub names: Vec<String>,
    pub services: Vec<String>,
    pub txt: Vec<String>,
}

impl MdnsInfo {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.services.is_empty() && self.txt.is_empty()
    }
}

fn push_unique(items: &mut Vec<String>, value: String) {
    if !value.is_empty() && !items.contains(&value) && items.len() < 30 {
        items.push(value);
    }
}

/// Read DNS names with RFC 1035 compression and a strict pointer depth bound.
fn read_name(packet: &[u8], cursor: &mut usize) -> Option<String> {
    let mut offset = *cursor;
    let mut jumped = false;
    let mut labels = Vec::new();
    for _ in 0..32 {
        let length = *packet.get(offset)?;
        if length & 0xc0 == 0xc0 {
            let second = *packet.get(offset + 1)?;
            let pointer = ((usize::from(length & 0x3f)) << 8) | usize::from(second);
            if pointer >= packet.len() {
                return None;
            }
            if !jumped {
                *cursor = offset + 2;
                jumped = true;
            }
            offset = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        offset += 1;
        if length == 0 {
            if !jumped {
                *cursor = offset;
            }
            return Some(labels.join("."));
        }
        let end = offset.checked_add(usize::from(length))?;
        let label = packet.get(offset..end)?;
        labels.push(String::from_utf8_lossy(label).to_string());
        offset = end;
    }
    None
}

fn be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn reverse_label(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

fn relevant_service(name: &str) -> bool {
    name.to_ascii_lowercase().contains("._tcp.local")
        || name.to_ascii_lowercase().contains("._udp.local")
        || name.to_ascii_lowercase().starts_with("_rtsp.")
        || name.to_ascii_lowercase().starts_with("_onvif.")
}

pub fn parse_packet(packet: &[u8], origin: Ipv4Addr) -> Option<MdnsInfo> {
    if packet.len() < 12 || packet[2] & 0x80 == 0 {
        return None;
    }
    let questions = usize::from(be_u16(packet, 4)?);
    let answers = usize::from(be_u16(packet, 6)?)
        + usize::from(be_u16(packet, 8)?)
        + usize::from(be_u16(packet, 10)?);
    if questions > 40 || answers > 200 {
        return None;
    }

    let mut cursor = 12;
    for _ in 0..questions {
        read_name(packet, &mut cursor)?;
        cursor = cursor.checked_add(4)?;
        if cursor > packet.len() {
            return None;
        }
    }

    let mut info = MdnsInfo::default();
    for _ in 0..answers {
        let owner = read_name(packet, &mut cursor)?;
        let kind = be_u16(packet, cursor)?;
        let length = usize::from(be_u16(packet, cursor + 8)?);
        cursor += 10;
        let end = cursor.checked_add(length)?;
        let data = packet.get(cursor..end)?;
        match kind {
            1 if length == 4 => {
                if Ipv4Addr::new(data[0], data[1], data[2], data[3]) == origin {
                    push_unique(&mut info.names, owner);
                }
            }
            12 => {
                let mut position = cursor;
                if let Some(name) = read_name(packet, &mut position) {
                    if owner.eq_ignore_ascii_case(&reverse_label(origin))
                        && name.to_ascii_lowercase().ends_with(".local")
                    {
                        push_unique(&mut info.names, name.chars().take(140).collect());
                    } else {
                        if relevant_service(&owner) {
                            push_unique(&mut info.services, owner);
                        }
                        if relevant_service(&name) {
                            push_unique(&mut info.services, name);
                        }
                    }
                }
            }
            33 if length >= 7 => {
                if relevant_service(&owner) {
                    push_unique(&mut info.services, owner);
                }
                let mut position = cursor + 6;
                if let Some(name) = read_name(packet, &mut position) {
                    push_unique(&mut info.names, name);
                }
            }
            16 => {
                let mut position = 0;
                while position < data.len() {
                    let size = usize::from(data[position]);
                    position += 1;
                    if position + size > data.len() {
                        break;
                    }
                    let value = String::from_utf8_lossy(&data[position..position + size]);
                    let lower = value.to_ascii_lowercase();
                    if ["model=", "manufacturer=", "product=", "name=", "md="]
                        .iter()
                        .any(|key| lower.starts_with(key))
                    {
                        push_unique(&mut info.txt, value.chars().take(140).collect());
                    }
                    position += size;
                }
            }
            _ => {}
        }
        cursor = end;
    }
    Some(info)
}

fn query_packet(service: &str) -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in service.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&12u16.to_be_bytes()); // PTR
    packet.extend_from_slice(&1u16.to_be_bytes()); // IN
    packet
}

/// Reverse mDNS PTR requests are optional hostname hints, not hardware
/// identification. Queries stay multicast on the selected LAN and response
/// sources must match the already-seen devices.
pub fn probe_reverse(
    scope: &Scope,
    hosts: &[Ipv4Addr],
    tx: &Sender<Event>,
    cancelled: &AtomicBool,
) -> io::Result<usize> {
    if hosts.is_empty() || cancelled.load(Ordering::Relaxed) {
        return Ok(0);
    }
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT).into())?;
    socket.join_multicast_v4(&MULTICAST, &scope.local_ip)?;
    socket.set_multicast_if_v4(&scope.local_ip)?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(Duration::from_millis(160)))?;

    let allowed: HashSet<Ipv4Addr> = hosts.iter().copied()
        .filter(|ip| scope.contains(*ip) && *ip != scope.local_ip)
        .take(64).collect();
    for ip in &allowed {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        socket.send_to(&query_packet(&reverse_label(*ip)), (MULTICAST, PORT))?;
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buffer = [0u8; 9000];
    let mut named_hosts = HashSet::new();
    while Instant::now() < deadline && !cancelled.load(Ordering::Relaxed) {
        if let Ok((n, SocketAddr::V4(source))) = socket.recv_from(&mut buffer) {
            let ip = *source.ip();
            if !allowed.contains(&ip) {
                continue;
            }
            if let Some(info) = parse_packet(&buffer[..n], ip) {
                if !info.names.is_empty() {
                    named_hosts.insert(ip);
                    let _ = tx.send(Event::Found(
                        ip,
                        Observation::Mdns { names: info.names, services: info.services, txt: info.txt },
                    ));
                }
            }
        }
    }
    Ok(named_hosts.len())
}

/// Observe responders only within the selected /24. Multicast sockets share
/// UDP port 5353 with local mDNS daemons using SO_REUSEADDR.
pub fn probe(scope: &Scope, tx: &Sender<Event>, cancelled: &AtomicBool) -> io::Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT).into())?;
    socket.join_multicast_v4(&MULTICAST, &scope.local_ip)?;
    socket.set_multicast_if_v4(&scope.local_ip)?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(Duration::from_millis(160)))?;

    for service in QUERIES {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        socket.send_to(&query_packet(service), (MULTICAST, PORT))?;
    }
    let until = Instant::now() + Duration::from_secs(4);
    let mut buffer = [0u8; 9000];
    while Instant::now() < until && !cancelled.load(Ordering::Relaxed) {
        if let Ok((count, SocketAddr::V4(source))) = socket.recv_from(&mut buffer) {
            if !scope.contains(*source.ip()) {
                continue;
            }
            if let Some(info) = parse_packet(&buffer[..count], *source.ip()) {
                if !info.is_empty() {
                    let _ = tx.send(Event::Found(
                        *source.ip(),
                        Observation::Mdns {
                            names: info.names,
                            services: info.services,
                            txt: info.txt,
                        },
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(buf: &mut Vec<u8>, value: &str) {
        for part in value.split('.') {
            buf.push(part.len() as u8);
            buf.extend_from_slice(part.as_bytes());
        }
        buf.push(0);
    }

    #[test]
    fn reverse_ptr_is_attributed_to_matching_source_only() {
        let ip = Ipv4Addr::new(192, 168, 0, 103);
        let mut packet = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        name(&mut packet, &reverse_label(ip));
        packet.extend_from_slice(&12u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        let mut target = Vec::new();
        name(&mut target, "lobby-camera.local");
        packet.extend_from_slice(&(target.len() as u16).to_be_bytes());
        packet.extend_from_slice(&target);
        let valid = parse_packet(&packet, ip).unwrap();
        assert_eq!(valid.names, vec!["lobby-camera.local"]);
        let mismatch = parse_packet(&packet, Ipv4Addr::new(192, 168, 0, 104)).unwrap();
        assert!(mismatch.names.is_empty());
    }

    #[test]
    fn parses_mdns_ptr_service() {
        let mut packet = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        name(&mut packet, "_rtsp._tcp.local");
        packet.extend_from_slice(&12u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        let mut target = Vec::new();
        name(&mut target, "Camera._rtsp._tcp.local");
        packet.extend_from_slice(&(target.len() as u16).to_be_bytes());
        packet.extend_from_slice(&target);
        let info = parse_packet(&packet, Ipv4Addr::new(192, 168, 0, 100)).unwrap();
        assert!(info.services.iter().any(|value| value.contains("_rtsp")));
    }

    #[test]
    fn rejects_pointer_loops_and_truncated_packets() {
        let packet = [0, 0, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c];
        assert!(parse_packet(&packet, Ipv4Addr::LOCALHOST).is_none());
        assert!(parse_packet(&[], Ipv4Addr::LOCALHOST).is_none());
    }

    #[test]
    fn query_contains_expected_ptr_class() {
        let bytes = query_packet("_onvif._tcp.local");
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 12, 0, 1]);
    }
}
