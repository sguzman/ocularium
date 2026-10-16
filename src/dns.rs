//! Optional, local-router-only DNS PTR lookup for already-discovered devices.
//! Requires no credentials or privileges. The DNS server may not expose any
//! DHCP hostnames; the absence of an answer is not negative camera evidence.
use std::{
    collections::{HashSet, VecDeque},
    fs,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::Sender,
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use crate::discovery::{Event, Observation, Scope};

const TIMEOUT: Duration = Duration::from_millis(450);
const WORKERS: usize = 4;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsReport {
    pub router: Option<Ipv4Addr>,
    pub queried: usize,
    pub answered: usize,
    pub named: usize,
}

impl DnsReport {
    pub fn summary(&self) -> String {
        match self.router {
            Some(router) => format!(
                "Router DNS {router}: {} PTR queries, {} DNS replies, {} hostnames",
                self.queried, self.answered, self.named
            ),
            None => "Router DNS: no on-subnet default gateway found".to_owned(),
        }
    }
}

fn parse_default_gateway(table: &str, scope: &Scope) -> Option<Ipv4Addr> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 8 || fields[0] != scope.interface || fields[1] != "00000000" {
                return None;
            }
            let flags = u32::from_str_radix(fields[3], 16).ok()?;
            if flags & 0x3 != 0x3 {
                return None;
            }
            let raw = u32::from_str_radix(fields[2], 16).ok()?;
            let gateway = Ipv4Addr::from(raw.to_le_bytes());
            if gateway == scope.local_ip || !scope.contains(gateway) {
                return None;
            }
            let metric = fields[6].parse::<u32>().ok()?;
            Some((metric, gateway))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, ip)| ip)
}

fn reverse_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

fn encode_name(name: &str, bytes: &mut Vec<u8>) {
    for segment in name.split('.') {
        bytes.push(segment.len() as u8);
        bytes.extend_from_slice(segment.as_bytes());
    }
    bytes.push(0);
}

fn make_query(ip: Ipv4Addr, id: u16) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&[0x01, 0x00]); // Recursion requested
    bytes.extend_from_slice(&1u16.to_be_bytes()); // One question
    bytes.extend_from_slice(&[0u8; 6]); // No answers, authorities, or additional
    encode_name(&reverse_name(ip), &mut bytes);
    bytes.extend_from_slice(&12u16.to_be_bytes()); // PTR
    bytes.extend_from_slice(&1u16.to_be_bytes()); // IN
    bytes
}

fn read_u16(input: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*input.get(at)?, *input.get(at + 1)?]))
}

fn decode_name(input: &[u8], position: &mut usize) -> Option<String> {
    let mut at = *position;
    let mut followed_pointer = false;
    let mut labels = Vec::new();
    for _ in 0..48 {
        let count = usize::from(*input.get(at)?);
        if count & 0xc0 == 0xc0 {
            let low = usize::from(*input.get(at + 1)?);
            let target = ((count & 0x3f) << 8) | low;
            if target >= input.len() {
                return None;
            }
            if !followed_pointer {
                *position = at + 2;
                followed_pointer = true;
            }
            at = target;
            continue;
        }
        if count & 0xc0 != 0 || count > 63 {
            return None;
        }
        at += 1;
        if count == 0 {
            if !followed_pointer {
                *position = at;
            }
            return Some(labels.join("."));
        }
        let label = input.get(at..at.checked_add(count)?)?;
        if !label.iter().all(|ch| ch.is_ascii_graphic()) {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        at += count;
    }
    None
}

/// A valid DNS reply can be empty. Return None only for malformed, truncated,
/// unexpected-question or mismatched-transaction packets.
fn parse_reply(packet: &[u8], id: u16, ip: Ipv4Addr) -> Option<Vec<String>> {
    if packet.len() < 12 || read_u16(packet, 0)? != id {
        return None;
    }
    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 == 0 || flags & 0x0200 != 0 || !matches!(flags & 0x000f, 0 | 3) {
        return None;
    }
    let questions = usize::from(read_u16(packet, 4)?);
    let answers = usize::from(read_u16(packet, 6)?);
    if questions != 1 || answers > 64 {
        return None;
    }
    let mut cursor = 12;
    let question = decode_name(packet, &mut cursor)?;
    if !question.eq_ignore_ascii_case(&reverse_name(ip)) {
        return None;
    }
    if read_u16(packet, cursor)? != 12 || read_u16(packet, cursor + 2)? != 1 {
        return None;
    }
    cursor += 4;

    let mut names = Vec::new();
    for _ in 0..answers {
        let owner = decode_name(packet, &mut cursor)?;
        let kind = read_u16(packet, cursor)?;
        let class = read_u16(packet, cursor + 2)?;
        let length = usize::from(read_u16(packet, cursor + 8)?);
        cursor += 10;
        let end = cursor.checked_add(length)?;
        packet.get(cursor..end)?;
        if kind == 12 && class == 1 && owner.eq_ignore_ascii_case(&reverse_name(ip)) {
            let mut value_cursor = cursor;
            if let Some(name) = decode_name(packet, &mut value_cursor) {
                // PTR answers are just device-name clues; avoid storing
                // garbage or oversized names from untrusted responses.
                if value_cursor <= end
                    && !name.is_empty()
                    && name.len() <= 160
                    && !names.contains(&name)
                {
                    names.push(name);
                }
            }
        }
        cursor = end;
    }
    Some(names)
}

fn lookup(
    ip: Ipv4Addr,
    router: Ipv4Addr,
    local_ip: Ipv4Addr,
    cancelled: &AtomicBool,
) -> Option<Option<String>> {
    if cancelled.load(Ordering::Relaxed) {
        return None;
    }
    let socket = UdpSocket::bind((local_ip, 0)).ok()?;
    socket.set_read_timeout(Some(TIMEOUT)).ok()?;
    let uuid = uuid::Uuid::new_v4();
    let id = u16::from_be_bytes([uuid.as_bytes()[0], uuid.as_bytes()[1]]);
    socket
        .send_to(&make_query(ip, id), SocketAddrV4::new(router, 53))
        .ok()?;
    let mut buffer = [0u8; 2048];
    // Ignore unrelated packets, while respecting the bounded socket timeout.
    for _ in 0..3 {
        if cancelled.load(Ordering::Relaxed) {
            return None;
        }
        let (size, from) = socket.recv_from(&mut buffer).ok()?;
        if from != SocketAddrV4::new(router, 53).into() {
            continue;
        }
        if let Some(names) = parse_reply(&buffer[..size], id, ip) {
            return Some(names.into_iter().next());
        }
    }
    None
}

/// Queries only the selected subnet's default gateway, and only for already
/// discovered hosts; never uses public resolvers or brute-force hostname lists.
pub fn probe(
    scope: &Scope,
    hosts: &[Ipv4Addr],
    tx: &Sender<Event>,
    cancelled: &AtomicBool,
) -> DnsReport {
    let gateway_table = fs::read_to_string("/proc/net/route").unwrap_or_default();
    let router = parse_default_gateway(&gateway_table, scope);
    let mut report = DnsReport {
        router,
        ..Default::default()
    };
    let Some(router) = router else {
        return report;
    };

    let mut unique = HashSet::new();
    let targets: VecDeque<_> = hosts
        .iter()
        .copied()
        .filter(|ip| scope.contains(*ip) && *ip != scope.local_ip && unique.insert(*ip))
        .take(64)
        .collect();
    let total = targets.len();
    let queue = Arc::new(Mutex::new(targets));
    let queried = AtomicUsize::new(0);
    let answered = AtomicUsize::new(0);
    let named = AtomicUsize::new(0);

    thread::scope(|workers| {
        for _ in 0..WORKERS.min(total) {
            let queue = Arc::clone(&queue);
            let tx = tx.clone();
            let queried = &queried;
            let answered = &answered;
            let named = &named;
            workers.spawn(move || loop {
                if cancelled.load(Ordering::Relaxed) {
                    break;
                }
                let Some(ip) = queue.lock().expect("DNS lookup queue").pop_front() else {
                    break;
                };
                queried.fetch_add(1, Ordering::Relaxed);
                match lookup(ip, router, scope.local_ip, cancelled) {
                    Some(Some(name)) => {
                        answered.fetch_add(1, Ordering::Relaxed);
                        named.fetch_add(1, Ordering::Relaxed);
                        let _ = tx.send(Event::Found(ip, Observation::RouterDns(name)));
                    }
                    Some(None) => {
                        answered.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {}
                }
            });
        }
    });
    report.queried = queried.load(Ordering::Relaxed);
    report.answered = answered.load(Ordering::Relaxed);
    report.named = named.load(Ordering::Relaxed);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        Scope {
            interface: "eno1".to_owned(),
            local_ip: Ipv4Addr::new(192, 168, 0, 53),
            base: [192, 168, 0],
        }
    }

    #[test]
    fn reads_linux_little_endian_default_gateway() {
        let routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
eno1 00000000 0100A8C0 0003 0 0 100 00000000 0 0 0\n\
br-abc 00000000 01001FAC 0003 0 0 50 00000000 0 0 0\n";
        assert_eq!(
            parse_default_gateway(routes, &scope()),
            Some(Ipv4Addr::new(192, 168, 0, 1))
        );
    }

    #[test]
    fn rejects_gateway_outside_selected_subnet() {
        let routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
eno1 00000000 01001FAC 0003 0 0 100 00000000 0 0 0\n";
        assert_eq!(parse_default_gateway(routes, &scope()), None);
    }

    #[test]
    fn accepts_compressed_ptr_response() {
        let ip = Ipv4Addr::new(192, 168, 0, 103);
        let mut packet = make_query(ip, 0x1234);
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[7] = 1;
        // Pointer to original question, type PTR, IN, TTL=60,
        // RDATA = hostname encoded without compression.
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60]);
        let mut data = Vec::new();
        encode_name("camera103.lan", &mut data);
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(&data);
        assert_eq!(parse_reply(&packet, 0x1234, ip).unwrap(), ["camera103.lan"]);
        assert!(parse_reply(&packet, 0x4321, ip).is_none());
        assert!(parse_reply(&packet, 0x1234, Ipv4Addr::new(192, 168, 0, 105)).is_none());
    }

    #[test]
    fn rejects_truncated_ptr_packets() {
        let ip = Ipv4Addr::new(192, 168, 0, 103);
        let mut packet = make_query(ip, 0xabcd);
        packet[2] = 0x83; // QR and truncation
        assert!(parse_reply(&packet, 0xabcd, ip).is_none());
    }
}
