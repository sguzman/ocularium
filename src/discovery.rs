//! Local, credential-free network discovery. No cloud access or elevated privileges.
use std::{
    collections::{HashSet, VecDeque},
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::Sender,
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use if_addrs::{get_if_addrs, IfAddr};

use crate::{identify::{self, HttpInfo, VendorRegistry}, mdns};

const ONVIF_MULTICAST: (&str, u16) = ("239.255.255.250", 3702);
const SSDP_MULTICAST: (&str, u16) = ("239.255.255.250", 1900);
const PORTS: [u16; 9] = [80, 443, 554, 8554, 8000, 8080, 8899, 5000, 34567];
const CONNECT_TIMEOUT: Duration = Duration::from_millis(170);
const DISCOVERY_WINDOW: Duration = Duration::from_secs(3);
const WORKERS: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub interface: String,
    pub local_ip: Ipv4Addr,
    /// The MVP intentionally scans only the local /24, even for wider networks.
    pub base: [u8; 3],
}

impl Scope {
    pub fn description(&self) -> String {
        format!(
            "{} · {} · {}.{}.{}.0/24",
            self.interface, self.local_ip, self.base[0], self.base[1], self.base[2]
        )
    }

    pub(crate) fn contains(&self, ip: Ipv4Addr) -> bool {
        ip.octets()[..3] == self.base[..]
    }

    fn hosts(&self) -> VecDeque<Ipv4Addr> {
        (1..=254)
            .map(|last| Ipv4Addr::new(self.base[0], self.base[1], self.base[2], last))
            .filter(|ip| *ip != self.local_ip)
            .collect()
    }

    pub fn hosts_total(&self) -> usize {
        self.hosts().len()
    }
}

/// Prefer the interface that carries the system's default route. This keeps
/// Docker/Podman bridges out of the first position on ordinary home LANs.
fn default_route_interface(routes: &str) -> Option<String> {
    routes
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 8 || cols[1] != "00000000" {
                return None;
            }
            let flags = u32::from_str_radix(cols[3], 16).ok()?;
            if flags & 1 == 0 {
                return None;
            }
            let metric = cols[6].parse::<u32>().ok()?;
            Some((metric, cols[0].to_string()))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, name)| name)
}

fn interface_rank(name: &str, default_iface: Option<&str>) -> u8 {
    if Some(name) == default_iface {
        return 0;
    }
    if name.starts_with("en")
        || name.starts_with("eth")
        || name.starts_with("wl")
        || name.starts_with("wlan")
    {
        return 1;
    }
    if name.starts_with("br-")
        || name.starts_with("docker")
        || name.starts_with("veth")
        || name.starts_with("virbr")
        || name.starts_with("podman")
    {
        return 3;
    }
    2
}

pub fn interfaces() -> std::io::Result<Vec<Scope>> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    for item in get_if_addrs()? {
        let IfAddr::V4(addr) = item.addr else {
            continue;
        };
        let ip = addr.ip;
        if !ip.is_private() || ip.is_loopback() || ip.is_link_local() {
            continue;
        }
        let octets = ip.octets();
        let scope = Scope {
            interface: item.name,
            local_ip: ip,
            base: [octets[0], octets[1], octets[2]],
        };
        if seen.insert((scope.interface.clone(), scope.local_ip)) {
            found.push(scope);
        }
    }
    let route = fs::read_to_string("/proc/net/route").unwrap_or_default();
    let preferred = default_route_interface(&route);
    found.sort_by_key(|scope| {
        (
            interface_rank(&scope.interface, preferred.as_deref()),
            scope.interface.clone(),
        )
    });
    Ok(found)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    Onvif {
        xaddrs: Vec<String>,
        scopes: Vec<String>,
        types: Vec<String>,
    },
    Ssdp {
        server: Option<String>,
        location: Option<String>,
        search_target: Option<String>,
    },
    OpenPorts {
        ports: Vec<u16>,
        rtsp_responded: bool,
    },
    Mac(String),
    Vendor(String),
    Http(HttpInfo),
    Mdns {
        names: Vec<String>,
        services: Vec<String>,
        txt: Vec<String>,
    },
}

#[derive(Debug)]
pub enum Event {
    Found(Ipv4Addr, Observation),
    Progress(usize),
    Warning(String),
    Finished { cancelled: bool },
}

#[derive(Debug, Clone)]
pub struct Device {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub http: Vec<HttpInfo>,
    pub mdns_names: Vec<String>,
    pub mdns_services: Vec<String>,
    pub mdns_txt: Vec<String>,
    pub onvif_xaddrs: Vec<String>,
    pub onvif_scopes: Vec<String>,
    pub onvif_types: Vec<String>,
    pub ssdp_server: Option<String>,
    pub ssdp_location: Option<String>,
    pub ssdp_target: Option<String>,
    pub open_ports: Vec<u16>,
    pub rtsp_responded: bool,
}

impl Device {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            mac: None,
            vendor: None,
            http: Vec::new(),
            mdns_names: Vec::new(),
            mdns_services: Vec::new(),
            mdns_txt: Vec::new(),
            onvif_xaddrs: Vec::new(),
            onvif_scopes: Vec::new(),
            onvif_types: Vec::new(),
            ssdp_server: None,
            ssdp_location: None,
            ssdp_target: None,
            open_ports: Vec::new(),
            rtsp_responded: false,
        }
    }

    pub fn apply(&mut self, observation: Observation) {
        match observation {
            Observation::Onvif {
                xaddrs,
                scopes,
                types,
            } => {
                merge_unique(&mut self.onvif_xaddrs, xaddrs);
                merge_unique(&mut self.onvif_scopes, scopes);
                merge_unique(&mut self.onvif_types, types);
            }
            Observation::Ssdp {
                server,
                location,
                search_target,
            } => {
                if self.ssdp_server.is_none() {
                    self.ssdp_server = server;
                }
                if self.ssdp_location.is_none() {
                    self.ssdp_location = location;
                }
                if self.ssdp_target.is_none() {
                    self.ssdp_target = search_target;
                }
            }
            Observation::OpenPorts {
                ports,
                rtsp_responded,
            } => {
                for port in ports {
                    if !self.open_ports.contains(&port) {
                        self.open_ports.push(port);
                    }
                }
                self.open_ports.sort_unstable();
                self.rtsp_responded |= rtsp_responded;
            }
            Observation::Mac(mac) => self.mac = Some(mac),
            Observation::Vendor(vendor) => self.vendor = Some(vendor),
            Observation::Http(info) => {
                if !self.http.iter().any(|item| item.port == info.port) {
                    self.http.push(info);
                }
            }
            Observation::Mdns { names, services, txt } => {
                merge_unique(&mut self.mdns_names, names);
                merge_unique(&mut self.mdns_services, services);
                merge_unique(&mut self.mdns_txt, txt);
            }
        }
    }

    /// A protocol hint, NOT proof that video is accessible.
    pub fn classification(&self) -> &'static str {
        let advertises_video = self
            .onvif_types
            .iter()
            .any(|s| s.to_ascii_lowercase().contains("networkvideotransmitter"));
        if advertises_video {
            "ONVIF camera"
        } else if !self.onvif_xaddrs.is_empty() {
            "ONVIF device"
        } else if self.rtsp_responded {
            "RTSP service"
        } else if self.http.iter().any(HttpInfo::camera_hint) {
            "Camera web interface"
        } else if self.mdns_services.iter().any(|service| {
            let service = service.to_ascii_lowercase();
            service.contains("_rtsp._tcp") || service.contains("_onvif._tcp")
                || service.contains("_axis-video._tcp")
        }) {
            "Camera service advertised"
        } else if self
            .open_ports
            .iter()
            .any(|p| [554, 8554, 8899, 34567].contains(p))
            || self
                .ssdp_target
                .as_ref()
                .is_some_and(|s| s.to_ascii_lowercase().contains("camera"))
        {
            "Possible camera"
        } else {
            "Unidentified device"
        }
    }

    pub fn is_camera_candidate(&self) -> bool {
        self.classification() != "Unidentified device"
    }
}

fn merge_unique(target: &mut Vec<String>, new: Vec<String>) {
    for value in new {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

/// Scans one selected IPv4 /24. The egui thread never runs blocking I/O.
pub fn scan(scope: Scope, tx: Sender<Event>, cancelled: Arc<AtomicBool>) {
    thread::scope(|workers| {
        let tx_mdns = tx.clone();
        let cancel_mdns = Arc::clone(&cancelled);
        let mdns_scope = &scope;
        workers.spawn(move || {
            if let Err(error) = mdns::probe(mdns_scope, &tx_mdns, &cancel_mdns) {
                let _ = tx_mdns.send(Event::Warning(format!("mDNS: {error}")));
            }
        });

        let tx_onvif = tx.clone();
        let cancel_onvif = Arc::clone(&cancelled);
        let onvif_scope = &scope;
        workers.spawn(move || {
            if let Err(error) = probe_onvif(onvif_scope, &tx_onvif, &cancel_onvif) {
                let _ = tx_onvif.send(Event::Warning(format!("ONVIF: {error}")));
            }
        });

        let tx_ssdp = tx.clone();
        let cancel_ssdp = Arc::clone(&cancelled);
        let ssdp_scope = &scope;
        workers.spawn(move || {
            if let Err(error) = probe_ssdp(ssdp_scope, &tx_ssdp, &cancel_ssdp) {
                let _ = tx_ssdp.send(Event::Warning(format!("SSDP: {error}")));
            }
        });

        let tx_tcp = tx.clone();
        let cancel_tcp = Arc::clone(&cancelled);
        let tcp_scope = &scope;
        workers.spawn(move || probe_tcp(tcp_scope, &tx_tcp, &cancel_tcp));
    });

    if !cancelled.load(Ordering::Relaxed) {
        let registry = VendorRegistry::load();
        for (ip, mac) in arp_neighbors(&scope) {
            if let Some(vendor) = registry.vendor(&mac) {
                let _ = tx.send(Event::Found(ip, Observation::Vendor(vendor)));
            }
            let _ = tx.send(Event::Found(ip, Observation::Mac(mac)));
        }
        if !registry.available() {
            let _ = tx.send(Event::Warning(
                "Offline vendor database not found (optional: install hwdata or nmap)".into(),
            ));
        }
    }
    let _ = tx.send(Event::Finished {
        cancelled: cancelled.load(Ordering::Relaxed),
    });
}

fn probe_onvif(scope: &Scope, tx: &Sender<Event>, cancelled: &AtomicBool) -> std::io::Result<()> {
    let socket = UdpSocket::bind((scope.local_ip, 0))?;
    socket.set_read_timeout(Some(Duration::from_millis(180)))?;
    let id = uuid::Uuid::new_v4();
    let probe = format!(
        r#"<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><e:Header><w:MessageID>urn:uuid:{id}</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe/></e:Body></e:Envelope>"#
    );
    socket.send_to(probe.as_bytes(), ONVIF_MULTICAST)?;
    let until = Instant::now() + DISCOVERY_WINDOW;
    let mut buffer = [0u8; 16384];
    while Instant::now() < until && !cancelled.load(Ordering::Relaxed) {
        if let Ok((length, SocketAddr::V4(source))) = socket.recv_from(&mut buffer) {
            if !scope.contains(*source.ip()) {
                continue;
            }
            if let Ok(payload) = std::str::from_utf8(&buffer[..length]) {
                if let Some(observation) = parse_onvif(payload) {
                    let _ = tx.send(Event::Found(*source.ip(), observation));
                }
            }
        }
    }
    Ok(())
}

fn parse_onvif(message: &str) -> Option<Observation> {
    let document = roxmltree::Document::parse(message).ok()?;
    if !document
        .descendants()
        .any(|node| node.is_element() && node.tag_name().name() == "ProbeMatch")
    {
        return None;
    }
    let elements = |name: &str| -> Vec<String> {
        document
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == name)
            .filter_map(|node| node.text())
            .flat_map(|value| value.split_whitespace())
            .map(str::to_string)
            .collect()
    };
    Some(Observation::Onvif {
        xaddrs: elements("XAddrs"),
        scopes: elements("Scopes"),
        types: elements("Types"),
    })
}

fn probe_ssdp(scope: &Scope, tx: &Sender<Event>, cancelled: &AtomicBool) -> std::io::Result<()> {
    let socket = UdpSocket::bind((scope.local_ip, 0))?;
    socket.set_read_timeout(Some(Duration::from_millis(180)))?;
    let request = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
    socket.send_to(request.as_bytes(), SSDP_MULTICAST)?;
    let until = Instant::now() + DISCOVERY_WINDOW;
    let mut buffer = [0u8; 8192];
    while Instant::now() < until && !cancelled.load(Ordering::Relaxed) {
        if let Ok((length, SocketAddr::V4(source))) = socket.recv_from(&mut buffer) {
            if !scope.contains(*source.ip()) {
                continue;
            }
            if let Ok(payload) = std::str::from_utf8(&buffer[..length]) {
                if let Some(observation) = parse_ssdp(payload) {
                    let _ = tx.send(Event::Found(*source.ip(), observation));
                }
            }
        }
    }
    Ok(())
}

fn parse_ssdp(message: &str) -> Option<Observation> {
    let first_line = message.lines().next()?.trim();
    if !first_line.starts_with("HTTP/1.") || !first_line.contains(" 200 ") {
        return None;
    }
    let header = |key: &str| {
        message
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.trim()
                    .eq_ignore_ascii_case(key)
                    .then(|| value.trim().to_owned())
            })
    };
    Some(Observation::Ssdp {
        server: header("SERVER"),
        location: header("LOCATION"),
        search_target: header("ST"),
    })
}

fn probe_tcp(scope: &Scope, tx: &Sender<Event>, cancelled: &AtomicBool) {
    let jobs = Arc::new(Mutex::new(scope.hosts()));
    let total = jobs.lock().expect("scan queue").len();
    let completed = AtomicUsize::new(0);
    thread::scope(|pool| {
        for _ in 0..WORKERS.min(total) {
            let jobs = Arc::clone(&jobs);
            let tx = tx.clone();
            let completed = &completed;
            pool.spawn(move || loop {
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }
                let Some(ip) = jobs.lock().expect("scan queue").pop_front() else {
                    return;
                };
                let mut ports = Vec::new();
                let mut rtsp_responded = false;
                for port in PORTS {
                    if cancelled.load(Ordering::Relaxed) {
                        break;
                    }
                    let address = SocketAddr::V4(SocketAddrV4::new(ip, port));
                    if let Ok(stream) = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
                        if port == 554 || port == 8554 {
                            if rtsp_options(stream, ip, port) {
                                rtsp_responded = true;
                            }
                        } else if port == 80 || port == 8080 || port == 8000 || port == 5000 {
                            if let Some(info) = identify::http_hint(stream, ip, port) {
                                let _ = tx.send(Event::Found(ip, Observation::Http(info)));
                            }
                        }
                        ports.push(port);
                    }
                }
                if !ports.is_empty() {
                    let _ = tx.send(Event::Found(
                        ip,
                        Observation::OpenPorts {
                            ports,
                            rtsp_responded,
                        },
                    ));
                }
                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = tx.send(Event::Progress(done));
            });
        }
    });
}

fn rtsp_options(mut stream: TcpStream, ip: Ipv4Addr, port: u16) -> bool {
    let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));
    let request = format!("OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    matches!(stream.read(&mut buf), Ok(n) if n > 8 && buf[..n].starts_with(b"RTSP/1.0"))
}

fn arp_neighbors(scope: &Scope) -> Vec<(Ipv4Addr, String)> {
    // Linux kernel neighbor cache. Failure to read it is non-fatal.
    let Ok(contents) = fs::read_to_string("/proc/net/arp") else {
        return Vec::new();
    };
    contents
        .lines()
        .skip(1)
        .filter_map(|line| {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() < 6 || columns[2] != "0x2" {
                return None;
            }
            let ip = columns[0].parse::<Ipv4Addr>().ok()?;
            let mac = columns[3].to_owned();
            (scope.contains(ip) && mac != "00:00:00:00:00:00").then_some((ip, mac))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_excludes_own_address() {
        let scope = Scope {
            interface: "wlan0".into(),
            local_ip: Ipv4Addr::new(192, 168, 40, 7),
            base: [192, 168, 40],
        };
        assert!(scope.contains(Ipv4Addr::new(192, 168, 40, 200)));
        assert!(!scope.contains(Ipv4Addr::new(192, 168, 41, 200)));
        assert!(!scope.hosts().contains(&scope.local_ip));
        assert_eq!(scope.hosts_total(), 253);
    }

    #[test]
    fn parse_onvif_scopes_and_addresses() {
        let xml = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><s:Body><d:ProbeMatches><d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>onvif://www.onvif.org/name/Camera</d:Scopes><d:XAddrs>http://192.168.0.9/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"#;
        let observation = parse_onvif(xml).expect("ONVIF response");
        let mut device = Device::new(Ipv4Addr::new(192, 168, 0, 9));
        device.apply(observation.clone());
        device.apply(observation);
        assert_eq!(device.onvif_xaddrs.len(), 1);
        assert_eq!(device.classification(), "ONVIF camera");
    }

    #[test]
    fn ignores_non_discovery_xml() {
        assert!(parse_onvif("<Envelope><Body/></Envelope>").is_none());
    }

    #[test]
    fn ssdp_parses_case_insensitive_headers() {
        let response = "HTTP/1.1 200 OK\r\nserver: Device/1.0\r\nLOCATION: http://192.168.1.2/device.xml\r\nST: urn:schemas-upnp-org:device:Basic:1\r\n\r\n";
        let mut device = Device::new(Ipv4Addr::new(192, 168, 1, 2));
        device.apply(parse_ssdp(response).expect("SSDP response"));
        assert_eq!(device.ssdp_server.as_deref(), Some("Device/1.0"));
        assert_eq!(device.classification(), "Unidentified device");
    }

    #[test]
    fn default_route_prioritizes_primary_lan() {
        let table = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
br-abc 00000000 01001FAC 0003 0 0 250 00000000 0 0 0\n\
eno1 00000000 0100A8C0 0003 0 0 100 00000000 0 0 0\n";
        assert_eq!(default_route_interface(table).as_deref(), Some("eno1"));
        assert!(interface_rank("eno1", Some("eno1")) < interface_rank("br-abc", Some("eno1")));
        assert!(interface_rank("eno1", None) < interface_rank("br-abc", None));
    }

    #[test]
    fn rtsp_port_is_only_a_candidate() {
        let mut device = Device::new(Ipv4Addr::new(192, 168, 1, 13));
        device.apply(Observation::OpenPorts {
            ports: vec![554],
            rtsp_responded: false,
        });
        assert_eq!(device.classification(), "Possible camera");
        assert!(device.is_camera_candidate());
    }
}
