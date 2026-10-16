//! Imported DHCP client inventories from the router's *documented admin page*.
//! We never log into the router, guess endpoints, or store admin credentials.
//! Imported leases are observations of a router's DHCP table, not evidence
//! that a device is currently reachable or that it is a camera.
use std::{
    collections::{BTreeMap, HashSet},
    env, fs, io,
    net::Ipv4Addr,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use crate::{discovery::{Device, Scope}, history};

const VERSION: u32 = 1;
const MAX_INPUT: usize = 256 * 1024;
const MAX_ROWS: usize = 256;
const MAX_SCOPES: usize = 20;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClient {
    pub name: Option<String>,
    pub mac: String,
    pub ip: Ipv4Addr,
    pub lease_time: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhcpSnapshot {
    pub imported_at: u64,
    pub clients: Vec<DhcpClient>,
}

#[derive(Clone, Debug)]
pub struct ParseResult {
    pub clients: Vec<DhcpClient>,
    pub skipped_out_of_subnet: usize,
    pub rejected_rows: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchKind {
    Mac,
    IpOnly,
}

impl MatchKind {
    pub fn description(self) -> &'static str {
        match self {
            Self::Mac => "MAC match",
            Self::IpOnly => "IP match (device MAC unavailable)",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DhcpStore {
    version: u32,
    scopes: BTreeMap<String, DhcpSnapshot>,
    #[serde(skip)]
    read_only: bool,
}

impl DhcpStore {
    pub fn load() -> (Self, Option<String>) {
        let Some(path) = file_path() else {
            return (Self::default(), Some("DHCP import cannot persist: HOME unavailable".into()));
        };
        match fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str::<Self>(&text) {
                Ok(mut data) if data.version == VERSION => {
                    data.read_only = false;
                    (data, None)
                }
                Ok(mut data) => {
                    let version = data.version;
                    data.read_only = true;
                    (data, Some(format!(
                        "DHCP import file is version {version}; keeping it read-only"
                    )))
                }
                Err(error) => {
                    let data = Self { version: VERSION, read_only: true, ..Default::default() };
                    (data, Some(format!(
                        "Cannot parse DHCP import file; refusing to overwrite: {error}"
                    )))
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                (Self { version: VERSION, ..Default::default() }, None)
            }
            Err(error) => (
                Self { version: VERSION, read_only: true, ..Default::default() },
                Some(format!("Cannot read DHCP import file: {error}")),
            ),
        }
    }

    pub fn snapshot(&self, scope: &Scope) -> Option<&DhcpSnapshot> {
        self.scopes.get(&history::scope_id(scope))
    }

    pub fn match_device<'a>(
        &'a self,
        scope: &Scope,
        device: &Device,
    ) -> Option<(&'a DhcpClient, MatchKind)> {
        let snapshot = self.snapshot(scope)?;
        let mac = device.mac.as_deref().and_then(normalize_mac);
        if let Some(mac) = &mac {
            return snapshot.clients.iter()
                .find(|client| client.mac == *mac)
                .map(|client| (client, MatchKind::Mac));
        }
        snapshot.clients.iter()
            .find(|client| client.ip == device.ip)
            .map(|client| (client, MatchKind::IpOnly))
    }

    pub fn unmatched<'a>(
        &'a self,
        scope: &Scope,
        devices: &BTreeMap<Ipv4Addr, Device>,
    ) -> Vec<&'a DhcpClient> {
        let Some(snapshot) = self.snapshot(scope) else { return Vec::new() };
        snapshot.clients.iter().filter(|client| {
            !devices.values().any(|device| {
                self.match_device(scope, device)
                    .is_some_and(|(matched, _)| matched.mac == client.mac && matched.ip == client.ip)
            })
        }).collect()
    }

    pub fn import(&mut self, scope: &Scope, raw: &str) -> Result<ParseResult, String> {
        if self.read_only {
            return Err("DHCP import file is read-only; the existing data will not be overwritten".into());
        }
        let result = parse_table(raw, scope)?;
        let mut candidate = self.clone();
        candidate.scopes.insert(
            history::scope_id(scope),
            DhcpSnapshot {
                imported_at: SystemTime::now().duration_since(UNIX_EPOCH)
                    .unwrap_or_default().as_secs(),
                clients: result.clients.clone(),
            },
        );
        if candidate.scopes.len() > MAX_SCOPES {
            return Err(format!("DHCP snapshots are limited to {MAX_SCOPES} networks"));
        }
        candidate.save().map_err(|error| format!("Saving DHCP snapshot: {error}"))?;
        *self = candidate;
        Ok(result)
    }

    fn save(&self) -> io::Result<()> {
        let path = file_path()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No data home"))?;
        let parent = path.parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid data path"))?;
        fs::create_dir_all(parent)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let temp = path.with_extension("json.tmp");
        fs::write(&temp, bytes)?;
        fs::rename(temp, path)
    }
}

fn file_path() -> Option<PathBuf> {
    let base = env::var_os("XDG_DATA_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
    Some(base.join("ocularium").join("dhcp.json"))
}

fn normalize_mac(raw: &str) -> Option<String> {
    let value = raw.trim().trim_matches(|ch: char| ",;[]()".contains(ch));
    let bytes: Vec<&str> = if value.contains(':') {
        value.split(':').collect()
    } else if value.contains('-') {
        value.split('-').collect()
    } else if value.len() == 12 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(value.to_ascii_lowercase().as_bytes()
            .chunks(2).map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
            .collect::<Vec<_>>().join(":"));
    } else {
        return None;
    };
    if bytes.len() != 6 || !bytes.iter().all(|part| part.len() == 2 &&
        part.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }
    let normalized = bytes.join(":").to_ascii_lowercase();
    (normalized != "00:00:00:00:00:00" && normalized != "ff:ff:ff:ff:ff:ff")
        .then_some(normalized)
}

fn parse_csv_line(line: &str) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut value = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                value.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                result.push(value.trim().to_string());
                value.clear();
            }
            _ => value.push(ch),
        }
    }
    if quoted { return None; }
    result.push(value.trim().to_string());
    Some(result)
}

fn fields(line: &str) -> Vec<String> {
    if line.contains('\t') {
        line.split('\t').map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()).collect()
    } else if line.contains(',') {
        parse_csv_line(line).unwrap_or_default()
    } else {
        line.split_whitespace().map(str::to_owned).collect()
    }
}

fn parse_line(line: &str) -> Option<DhcpClient> {
    let parts = fields(line);
    let (mac_index, mac) = parts.iter().enumerate()
        .find_map(|(idx, part)| normalize_mac(part).map(|mac| (idx, mac)))?;
    let (ip_index, ip) = parts.iter().enumerate()
        .skip(mac_index + 1)
        .find_map(|(idx, part)| {
            part.trim_matches(|ch: char| ",;[]()".contains(ch))
                .parse::<Ipv4Addr>().ok().map(|ip| (idx, ip))
        })?;
    // TP-Link columns: ID, Client Name, MAC Address, Assigned IP, Lease Time.
    let preceding = &parts[..mac_index];
    let name_fields = if preceding.first().is_some_and(|field| field.parse::<usize>().is_ok()) {
        &preceding[1..]
    } else {
        preceding
    };
    let name = name_fields.join(" ");
    let name = name.trim_matches('"').trim();
    let name = (!name.is_empty() && name != "-" && name != "--")
        .then(|| name.chars().filter(|ch| !ch.is_control()).take(100).collect());
    let lease_time = parts.get(ip_index + 1)
        .map(|value| value.chars().take(32).collect::<String>())
        .filter(|value| !value.is_empty() && value != "-");

    Some(DhcpClient { name, mac, ip, lease_time })
}

pub fn parse_table(raw: &str, scope: &Scope) -> Result<ParseResult, String> {
    if raw.len() > MAX_INPUT {
        return Err("DHCP table text is too large (maximum 256 KiB)".into());
    }
    if raw.trim().is_empty() {
        return Err("Paste the DHCP Clients List first".into());
    }
    let mut clients = Vec::new();
    let mut skipped = 0;
    let mut rejected = 0;
    let mut ips = HashSet::new();
    let mut macs = HashSet::new();

    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        if let Some(client) = parse_line(line) {
            if !scope.contains(client.ip) || client.ip == scope.local_ip {
                skipped += 1;
                continue;
            }
            if !ips.insert(client.ip) || !macs.insert(client.mac.clone()) {
                return Err(format!(
                    "Conflicting duplicate DHCP IP or MAC in pasted table: {} ({})",
                    client.ip, client.mac
                ));
            }
            clients.push(client);
            if clients.len() > MAX_ROWS {
                return Err(format!("DHCP table exceeds {MAX_ROWS} clients"));
            }
        } else if line.contains(|ch: char| ch.is_ascii_digit()) && !line.trim_start().starts_with('#') {
            // A header with "IP" but no address is normal; don't count it.
            let lower = line.to_ascii_lowercase();
            if !lower.contains("lease time") && !lower.contains("client name") &&
                !lower.starts_with("dhcp") && !lower.starts_with("id ") {
                rejected += 1;
            }
        }
    }
    if clients.is_empty() {
        return Err(
            "No valid DHCP clients found. Paste table rows with Client Name, MAC Address and Assigned IP on the same line."
                .into()
        );
    }
    Ok(ParseResult {
        clients, skipped_out_of_subnet: skipped, rejected_rows: rejected
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        Scope { interface: "eno1".into(), local_ip: Ipv4Addr::new(192,168,0,53), base: [192,168,0] }
    }

    #[test]
    fn parses_tp_link_whitespace_and_tabular_rows() {
        let raw = "ID Client Name MAC Address Assigned IP Lease Time\n\
1 Front-Gate 68-8F-C9-F0-70-36 192.168.0.100 01:12:39\n\
2\tPatio Camera\t60:1D:9D:E7:C4:C7\t192.168.0.103\t00:40:00";
        let parsed = parse_table(raw, &scope()).unwrap();
        assert_eq!(parsed.clients.len(), 2);
        assert_eq!(parsed.clients[0].mac, "68:8f:c9:f0:70:36");
        assert_eq!(parsed.clients[1].name.as_deref(), Some("Patio Camera"));
    }

    #[test]
    fn parses_csv_quoted_names_and_rejects_bad_input() {
        let text = "ID,Client Name,MAC Address,Assigned IP,Lease Time\n\
1,\"Patio, Rear\",68:8f:c9:f0:70:36,192.168.0.100,120\n";
        let parsed = parse_table(text, &scope()).unwrap();
        assert_eq!(parsed.clients[0].name.as_deref(), Some("Patio, Rear"));
        assert!(parse_table("no valid table", &scope()).is_err());
    }

    #[test]
    fn ignores_other_subnets_and_fails_on_duplicates() {
        let text = "A aa:bb:cc:dd:ee:ff 10.0.0.4 10\n\
B 12:34:56:78:90:ab 192.168.0.100 10";
        let parsed = parse_table(text, &scope()).unwrap();
        assert_eq!(parsed.clients.len(), 1);
        assert_eq!(parsed.skipped_out_of_subnet, 1);
        let dup = "A aa:bb:cc:dd:ee:ff 192.168.0.100\n\
B aa:bb:cc:dd:ee:ff 192.168.0.101";
        assert!(parse_table(dup, &scope()).is_err());
    }

    #[test]
    fn matching_refuses_mismatched_mac_even_when_ip_matches() {
        let mut store = DhcpStore { version: VERSION, ..Default::default() };
        let parsed = parse_table("Gate aa:bb:cc:dd:ee:ff 192.168.0.100", &scope()).unwrap();
        store.scopes.insert(history::scope_id(&scope()), DhcpSnapshot {
            imported_at: 42, clients: parsed.clients
        });
        let mut device = Device::new(Ipv4Addr::new(192,168,0,100));
        device.mac = Some("68:8f:c9:f0:70:36".into());
        assert!(store.match_device(&scope(), &device).is_none());
        device.mac = None;
        assert_eq!(store.match_device(&scope(), &device).unwrap().1, MatchKind::IpOnly);
        device.mac = Some("aa:bb:cc:dd:ee:ff".into());
        assert_eq!(store.match_device(&scope(), &device).unwrap().1, MatchKind::Mac);
    }

    #[test]
    fn retains_lease_only_devices_outside_live_scan() {
        let mut store = DhcpStore { version: VERSION, ..Default::default() };
        let parsed = parse_table(
            "Gate aa:bb:cc:dd:ee:ff 192.168.0.100\nCamera 12:34:56:78:90:ab 192.168.0.101",
            &scope(),
        ).unwrap();
        store.scopes.insert(history::scope_id(&scope()), DhcpSnapshot {
            imported_at: 42, clients: parsed.clients
        });
        let mut device = Device::new(Ipv4Addr::new(192,168,0,100));
        device.mac = Some("aa:bb:cc:dd:ee:ff".into());
        let found = BTreeMap::from([(device.ip, device)]);
        assert_eq!(store.unmatched(&scope(), &found).len(), 1);
        assert_eq!(store.unmatched(&scope(), &found)[0].ip, Ipv4Addr::new(192,168,0,101));
    }
}
