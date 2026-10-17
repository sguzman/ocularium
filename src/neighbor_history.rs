//! Opt-in durable summaries from the *kernel neighbor cache observer*.
//! Stored identities are MAC+selected subnet, not IP. Incomplete cache
//! observations never imply a device is offline or that it is a camera.
use crate::{history, neighbor_watch::NeighborWatch};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, env, fs, io, net::Ipv4Addr, path::PathBuf};

const VERSION: u32 = 1;
const MAX_IDENTITIES: usize = 512;
const MAX_IPS: usize = 12;
const MAX_EVENTS: usize = 200;
const MAX_SESSIONS_TRACKED: usize = 128;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MacHistory {
    pub scope: String,
    pub mac: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub sessions: u32,
    pub sampled_sightings: u64,
    pub ips: Vec<Ipv4Addr>,
    last_session: String,
    last_session_samples: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchivedEvent {
    pub scope: String,
    pub at: u64,
    pub detail: String,
    pub session: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NeighborArchive {
    version: u32,
    identities: BTreeMap<String, MacHistory>,
    events: Vec<ArchivedEvent>,
    #[serde(default)]
    event_checkpoints: BTreeMap<String, u64>,
    #[serde(skip)]
    read_only: bool,
}

impl Default for NeighborArchive {
    fn default() -> Self {
        Self {
            version: VERSION,
            identities: BTreeMap::new(),
            events: Vec::new(),
            event_checkpoints: BTreeMap::new(),
            read_only: false,
        }
    }
}

fn file_path() -> Option<PathBuf> {
    let base = env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))?;
    Some(base.join("ocularium").join("neighbor-history.json"))
}

impl NeighborArchive {
    pub fn load() -> (Self, Option<String>) {
        let Some(path) = file_path() else {
            return (
                Self::default(),
                Some("Passive history unavailable: HOME and XDG_DATA_HOME are unset".into()),
            );
        };
        match fs::read_to_string(path) {
            Ok(data) => match serde_json::from_str::<Self>(&data) {
                Ok(mut archive) if archive.version == VERSION => {
                    archive.read_only = false;
                    (archive, None)
                }
                Ok(mut archive) => {
                    archive.read_only = true;
                    let version = archive.version;
                    (
                        archive,
                        Some(format!(
                            "Unsupported passive history format v{version}; preserved read-only"
                        )),
                    )
                }
                Err(error) => {
                    let archive = Self {
                        read_only: true,
                        ..Self::default()
                    };
                    (
                        archive,
                        Some(format!(
                            "Passive history could not be parsed; existing file preserved: {error}"
                        )),
                    )
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => (Self::default(), None),
            Err(error) => {
                let archive = Self {
                    read_only: true,
                    ..Self::default()
                };
                (
                    archive,
                    Some(format!(
                        "Passive history cannot be opened; file preserved: {error}"
                    )),
                )
            }
        }
    }

    pub fn known_count(&self, scope: &crate::discovery::Scope) -> usize {
        let target = history::scope_id(scope);
        self.identities
            .values()
            .filter(|row| row.scope == target)
            .count()
    }

    pub fn records(&self, scope: &crate::discovery::Scope) -> Vec<&MacHistory> {
        let target = history::scope_id(scope);
        let mut entries: Vec<_> = self
            .identities
            .values()
            .filter(|row| row.scope == target)
            .collect();
        entries.sort_by_key(|row| std::cmp::Reverse(row.last_seen));
        entries
    }

    pub fn by_mac(&self, scope: &crate::discovery::Scope, mac: &str) -> Option<&MacHistory> {
        self.identities.get(&format!(
            "{}|{}",
            history::scope_id(scope),
            mac.to_ascii_lowercase()
        ))
    }

    pub fn events(&self, scope: &crate::discovery::Scope) -> Vec<&ArchivedEvent> {
        let target = history::scope_id(scope);
        self.events
            .iter()
            .rev()
            .filter(|event| event.scope == target)
            .collect()
    }

    /// Idempotent per observer session. Repeated saves only add newly sampled
    /// sightings/events; a MAC at a different IP updates one physical identity.
    fn ingest(&mut self, watch: &NeighborWatch) {
        let scope = history::scope_id(watch.scope());
        for sample in watch.by_mac.values() {
            let key = format!("{scope}|{}", sample.mac);
            if let Some(record) = self.identities.get_mut(&key) {
                if record.last_session == watch.session_id {
                    record.sampled_sightings +=
                        u64::from(sample.samples.saturating_sub(record.last_session_samples));
                } else {
                    record.sessions = record.sessions.saturating_add(1);
                    record.sampled_sightings += u64::from(sample.samples);
                    record.last_session = watch.session_id.clone();
                }
                record.last_session_samples = sample.samples;
                record.first_seen = record.first_seen.min(sample.first_seen);
                record.last_seen = record.last_seen.max(sample.last_seen);
                for ip in &sample.ips {
                    if !record.ips.contains(ip) {
                        if record.ips.len() == MAX_IPS {
                            record.ips.remove(0);
                        }
                        record.ips.push(*ip);
                    }
                }
            } else {
                self.identities.insert(
                    key,
                    MacHistory {
                        scope: scope.clone(),
                        mac: sample.mac.clone(),
                        first_seen: sample.first_seen,
                        last_seen: sample.last_seen,
                        sessions: 1,
                        sampled_sightings: u64::from(sample.samples),
                        ips: sample.ips.clone(),
                        last_session: watch.session_id.clone(),
                        last_session_samples: sample.samples,
                    },
                );
            }
        }
        while self.identities.len() > MAX_IDENTITIES {
            if let Some(oldest) = self
                .identities
                .iter()
                .min_by_key(|(_, record)| record.last_seen)
                .map(|(key, _)| key.clone())
            {
                self.identities.remove(&oldest);
            }
        }

        let seen_seq = self
            .event_checkpoints
            .get(&watch.session_id)
            .copied()
            .unwrap_or(0);
        let mut newest = seen_seq;
        for event in watch
            .changes
            .iter()
            .filter(|change| change.sequence > seen_seq)
        {
            self.events.push(ArchivedEvent {
                scope: scope.clone(),
                at: event.at,
                detail: event.detail.clone(),
                session: watch.session_id.clone(),
                sequence: event.sequence,
            });
            newest = newest.max(event.sequence);
        }
        // Changes may have already rolled out of the bounded in-session log.
        // Advance to the latest sequence even if they could not all be kept.
        if let Some(last) = watch.changes.last() {
            newest = newest.max(last.sequence);
        }
        self.event_checkpoints
            .insert(watch.session_id.clone(), newest);
        if self.events.len() > MAX_EVENTS {
            self.events.drain(..self.events.len() - MAX_EVENTS);
        }
        while self.event_checkpoints.len() > MAX_SESSIONS_TRACKED {
            if let Some(older) = self.event_checkpoints.keys().next().cloned() {
                self.event_checkpoints.remove(&older);
            }
        }
    }

    pub fn record(&mut self, watch: &NeighborWatch) -> Result<(), String> {
        if self.read_only {
            return Err("Passive history file is read-only; it was not overwritten".into());
        }
        let mut candidate = self.clone();
        candidate.ingest(watch);
        candidate
            .save()
            .map_err(|error| format!("Saving passive history: {error}"))?;
        *self = candidate;
        Ok(())
    }

    fn save(&self) -> io::Result<()> {
        let path = file_path()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No writable data directory"))?;
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid passive history directory",
            )
        })?;
        fs::create_dir_all(parent)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let temp = path.with_extension("json.tmp");
        fs::write(&temp, bytes)?;
        fs::rename(temp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{discovery::Scope, neighbor_watch::NeighborWatch};

    fn scope() -> Scope {
        Scope {
            interface: "eno1".into(),
            local_ip: Ipv4Addr::new(192, 168, 0, 53),
            base: [192, 168, 0],
        }
    }

    fn watcher() -> NeighborWatch {
        let watch = NeighborWatch::start(scope());
        watch.stop();
        watch
    }

    #[test]
    fn repeated_flushes_do_not_double_count_samples_or_events() {
        let mut watch = watcher();
        watch.by_mac.insert(
            "aa:bb:cc:dd:ee:ff".into(),
            crate::neighbor_watch::MacSighting {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                first_seen: 10,
                last_seen: 30,
                samples: 3,
                ips: vec![Ipv4Addr::new(192, 168, 0, 103)],
            },
        );
        let mut archive = NeighborArchive::default();
        archive.ingest(&watch);
        archive.ingest(&watch);
        let entry = archive.by_mac(&scope(), "aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(entry.sessions, 1);
        assert_eq!(entry.sampled_sightings, 3);
        watch.by_mac.get_mut("aa:bb:cc:dd:ee:ff").unwrap().samples = 5;
        archive.ingest(&watch);
        assert_eq!(
            archive
                .by_mac(&scope(), "aa:bb:cc:dd:ee:ff")
                .unwrap()
                .sampled_sightings,
            5
        );
    }

    #[test]
    fn same_mac_new_session_and_new_ip_keep_one_identity() {
        let mut archive = NeighborArchive::default();
        let mut first = watcher();
        first.by_mac.insert(
            "aa:bb:cc:dd:ee:ff".into(),
            crate::neighbor_watch::MacSighting {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                first_seen: 10,
                last_seen: 30,
                samples: 2,
                ips: vec![Ipv4Addr::new(192, 168, 0, 103)],
            },
        );
        archive.ingest(&first);
        let mut second = watcher();
        second.by_mac.insert(
            "aa:bb:cc:dd:ee:ff".into(),
            crate::neighbor_watch::MacSighting {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                first_seen: 40,
                last_seen: 50,
                samples: 4,
                ips: vec![Ipv4Addr::new(192, 168, 0, 105)],
            },
        );
        archive.ingest(&second);
        let record = archive.by_mac(&scope(), "aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(record.sessions, 2);
        assert_eq!(record.sampled_sightings, 6);
        assert_eq!(record.ips.len(), 2);
        assert_eq!(archive.known_count(&scope()), 1);
    }

    #[test]
    fn different_macs_at_same_ip_remain_distinct() {
        let mut archive = NeighborArchive::default();
        let mut watch = watcher();
        for mac in ["aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:01"] {
            watch.by_mac.insert(
                mac.into(),
                crate::neighbor_watch::MacSighting {
                    mac: mac.into(),
                    first_seen: 10,
                    last_seen: 30,
                    samples: 1,
                    ips: vec![Ipv4Addr::new(192, 168, 0, 103)],
                },
            );
        }
        archive.ingest(&watch);
        assert_eq!(archive.known_count(&scope()), 2);
    }

    #[test]
    fn persisted_json_restores_known_mac() {
        let mut archive = NeighborArchive::default();
        archive.ingest(&watcher());
        let json = serde_json::to_string(&archive).unwrap();
        let loaded: NeighborArchive = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.version, VERSION);
    }
}
