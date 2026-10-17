//! Low-overhead observation of the Linux kernel's ARP neighbor cache.
//!
//! This performs no packet capture or active network requests. The kernel
//! cache only contains neighbors the host happened to learn about, and entries
//! may disappear through expiration; neither is an online/offline verdict.
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::discovery::Scope;
use uuid::Uuid;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
const CANCEL_POLL: Duration = Duration::from_millis(250);
const MAX_EVENTS: usize = 80;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: Ipv4Addr,
    pub mac: String,
}

pub fn parse_neighbors(data: &str, scope: &Scope) -> Vec<Neighbor> {
    let mut found = BTreeMap::new();
    for line in data.lines().skip(1) {
        let columns: Vec<_> = line.split_whitespace().collect();
        if columns.len() < 6 || columns[5] != scope.interface {
            continue;
        }
        let Some(ip) = columns[0].parse::<Ipv4Addr>().ok() else {
            continue;
        };
        if !scope.contains(ip) || ip == scope.local_ip {
            continue;
        }
        let flags = u32::from_str_radix(columns[2].trim_start_matches("0x"), 16).unwrap_or(0);
        if flags & 0x2 == 0 {
            continue;
        }
        let mac = columns[3].to_ascii_lowercase();
        if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" || !valid_mac(&mac) {
            continue;
        }
        found.insert(ip, mac);
    }
    found
        .into_iter()
        .map(|(ip, mac)| Neighbor { ip, mac })
        .collect()
}

fn valid_mac(mac: &str) -> bool {
    let bytes: Vec<&str> = mac.split(':').collect();
    bytes.len() == 6
        && bytes
            .iter()
            .all(|segment| segment.len() == 2 && segment.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug)]
struct Sample {
    taken_at: u64,
    neighbors: Vec<Neighbor>,
}

#[derive(Clone, Debug)]
pub struct Sighting {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub samples: u32,
    /// The latest successful sampling found this IP in the kernel cache.
    pub in_cache: bool,
}

#[derive(Clone, Debug)]
pub struct Change {
    pub at: u64,
    pub sequence: u64,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct MacSighting {
    pub mac: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub samples: u32,
    pub ips: Vec<Ipv4Addr>,
}

enum Event {
    Sample(Sample),
    Warning(String),
}

pub struct NeighborWatch {
    scope: Scope,
    cancel: Arc<AtomicBool>,
    receiver: Receiver<Event>,
    pub observations: BTreeMap<Ipv4Addr, Sighting>,
    pub by_mac: BTreeMap<String, MacSighting>,
    pub session_id: String,
    next_sequence: u64,
    pub changes: Vec<Change>,
    pub sample_count: u32,
    pub last_sample: Option<u64>,
    pub latest_cache_count: usize,
    pub last_warning: Option<String>,
}

impl NeighborWatch {
    pub fn start(scope: Scope) -> Self {
        let (tx, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_scope = scope.clone();
        thread::spawn(move || {
            while !worker_cancel.load(Ordering::Relaxed) {
                match fs::read_to_string("/proc/net/arp") {
                    Ok(data) => {
                        let sample = Sample {
                            taken_at: timestamp(),
                            neighbors: parse_neighbors(&data, &worker_scope),
                        };
                        if tx.send(Event::Sample(sample)).is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        if tx
                            .send(Event::Warning(format!(
                                "Neighbor cache unavailable: {error}"
                            )))
                            .is_err()
                        {
                            return;
                        }
                    }
                }

                let mut waited = Duration::ZERO;
                while waited < SAMPLE_INTERVAL && !worker_cancel.load(Ordering::Relaxed) {
                    thread::sleep(CANCEL_POLL);
                    waited += CANCEL_POLL;
                }
            }
        });
        Self {
            scope,
            cancel,
            receiver,
            observations: BTreeMap::new(),
            by_mac: BTreeMap::new(),
            session_id: Uuid::new_v4().to_string(),
            next_sequence: 1,
            changes: Vec::new(),
            sample_count: 0,
            last_sample: None,
            latest_cache_count: 0,
            last_warning: None,
        }
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Stops sampling but retains this session's observations for inspection.
    pub fn stop(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn poll(&mut self) {
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                Event::Sample(sample) => self.apply_sample(sample),
                Event::Warning(message) => self.last_warning = Some(message),
            }
        }
    }

    pub fn seen(&self, ip: Ipv4Addr) -> Option<&Sighting> {
        self.observations.get(&ip)
    }

    pub fn observed_total(&self) -> usize {
        self.observations.len()
    }

    fn push_change(&mut self, at: u64, detail: String) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.changes.push(Change { at, sequence, detail });
        if self.changes.len() > MAX_EVENTS {
            self.changes.drain(..self.changes.len() - MAX_EVENTS);
        }
    }

    fn apply_sample(&mut self, sample: Sample) {
        self.sample_count = self.sample_count.saturating_add(1);
        self.last_sample = Some(sample.taken_at);
        self.latest_cache_count = sample.neighbors.len();
        self.last_warning = None;

        let now: HashSet<_> = sample.neighbors.iter().map(|value| value.ip).collect();
        let disappeared: Vec<_> = self
            .observations
            .values()
            .filter(|entry| entry.in_cache && !now.contains(&entry.ip))
            .map(|entry| entry.ip)
            .collect();
        for ip in disappeared {
            if let Some(entry) = self.observations.get_mut(&ip) {
                entry.in_cache = false;
            }
            self.push_change(
                sample.taken_at,
                format!("{ip} left kernel neighbor cache (not necessarily offline)"),
            );
        }
        for neighbor in sample.neighbors {
            let mac_record = self.by_mac.entry(neighbor.mac.clone()).or_insert_with(|| {
                MacSighting {
                    mac: neighbor.mac.clone(),
                    first_seen: sample.taken_at,
                    last_seen: sample.taken_at,
                    samples: 0,
                    ips: Vec::new(),
                }
            });
            mac_record.last_seen = sample.taken_at;
            mac_record.samples = mac_record.samples.saturating_add(1);
            if !mac_record.ips.contains(&neighbor.ip) {
                if mac_record.ips.len() >= 12 {
                    mac_record.ips.remove(0);
                }
                mac_record.ips.push(neighbor.ip);
            }
            if let Some(entry) = self.observations.get_mut(&neighbor.ip) {
                let different_mac = entry.mac != neighbor.mac;
                let returned = !entry.in_cache;
                entry.in_cache = true;
                entry.last_seen = sample.taken_at;
                entry.samples = entry.samples.saturating_add(1);
                if different_mac {
                    let old_mac = std::mem::replace(&mut entry.mac, neighbor.mac.clone());
                    self.push_change(
                        sample.taken_at,
                        format!(
                            "{} neighbor MAC changed: {} -> {}",
                            neighbor.ip, old_mac, neighbor.mac
                        ),
                    );
                } else if returned {
                    self.push_change(
                        sample.taken_at,
                        format!("{} reappeared in kernel neighbor cache", neighbor.ip),
                    );
                }
            } else {
                self.observations.insert(
                    neighbor.ip,
                    Sighting {
                        ip: neighbor.ip,
                        mac: neighbor.mac.clone(),
                        first_seen: sample.taken_at,
                        last_seen: sample.taken_at,
                        samples: 1,
                        in_cache: true,
                    },
                );
                self.push_change(
                    sample.taken_at,
                    format!(
                        "{} first seen in kernel neighbor cache ({})",
                        neighbor.ip, neighbor.mac
                    ),
                );
            }
        }
    }
}

impl Drop for NeighborWatch {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        Scope {
            interface: "eno1".into(),
            local_ip: Ipv4Addr::new(192, 168, 0, 53),
            base: [192, 168, 0],
        }
    }

    fn sample(at: u64, items: &[(&str, &str)]) -> Sample {
        Sample {
            taken_at: at,
            neighbors: items
                .iter()
                .map(|(ip, mac)| Neighbor {
                    ip: ip.parse().unwrap(),
                    mac: (*mac).to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn correlates_one_mac_across_multiple_ips_without_merging_changed_mac() {
        let mut watch = NeighborWatch::start(scope());
        watch.stop();
        watch.apply_sample(sample(100, &[("192.168.0.103", "aa:bb:cc:dd:ee:ff")]));
        watch.apply_sample(sample(110, &[("192.168.0.105", "aa:bb:cc:dd:ee:ff")]));
        assert_eq!(watch.by_mac.len(), 1);
        let record = watch.by_mac.get("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(record.ips.len(), 2);
        assert_eq!(record.samples, 2);
        watch.apply_sample(sample(120, &[("192.168.0.105", "aa:bb:cc:dd:ee:01")]));
        assert_eq!(watch.by_mac.len(), 2);
    }

    #[test]
    fn only_selected_interface_and_complete_neighbors_are_included() {
        let raw = "IP address HW type Flags HW address Mask Device\n\
192.168.0.100 0x1 0x2 aa:bb:cc:dd:ee:ff * eno1\n\
192.168.0.103 0x1 0x0 00:00:00:00:00:00 * eno1\n\
192.168.0.105 0x1 0x2 12:34:56:78:90:ab * br-test\n\
172.31.0.2 0x1 0x2 12:34:56:78:90:ab * eno1\n\
192.168.0.53 0x1 0x2 12:34:56:78:90:ab * eno1\n";
        let parsed = parse_neighbors(raw, &scope());
        assert_eq!(
            parsed,
            vec![Neighbor {
                ip: Ipv4Addr::new(192, 168, 0, 100),
                mac: "aa:bb:cc:dd:ee:ff".into(),
            }]
        );
    }

    #[test]
    fn tracks_cache_expiration_without_claiming_offline() {
        let mut watch = NeighborWatch::start(scope());
        watch.cancel.store(true, Ordering::Relaxed);
        watch.apply_sample(sample(100, &[("192.168.0.100", "aa:bb:cc:dd:ee:ff")]));
        watch.apply_sample(sample(110, &[]));
        assert_eq!(watch.observed_total(), 1);
        assert!(
            !watch
                .seen("192.168.0.100".parse().unwrap())
                .unwrap()
                .in_cache
        );
        assert!(watch
            .changes
            .last()
            .unwrap()
            .detail
            .contains("not necessarily offline"));
        watch.apply_sample(sample(120, &[("192.168.0.100", "aa:bb:cc:dd:ee:ff")]));
        assert!(watch.changes.last().unwrap().detail.contains("reappeared"));
    }

    #[test]
    fn changes_in_mac_are_recorded_not_conflated_with_original_identity() {
        let mut watch = NeighborWatch::start(scope());
        watch.cancel.store(true, Ordering::Relaxed);
        watch.apply_sample(sample(100, &[("192.168.0.105", "aa:bb:cc:dd:ee:ff")]));
        watch.apply_sample(sample(110, &[("192.168.0.105", "aa:bb:cc:dd:ee:01")]));
        let record = watch.seen("192.168.0.105".parse().unwrap()).unwrap();
        assert_eq!(record.mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(record.samples, 2);
        assert!(watch.changes.last().unwrap().detail.contains("MAC changed"));
    }
}
