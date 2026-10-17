use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use eframe::egui::{self, Color32, RichText};

use crate::{
    classify::{self, DeviceCategory},
    dhcp::DhcpStore,
    discovery::{self, DeepReport, Device, Event, Scope},
    dns,
    history::{self, HistoryStore},
    neighbor_history::NeighborArchive,
    neighbor_watch::NeighborWatch,
    registry::Registry,
    rtsp::{self, RtspInspection},
    snapshot::{self, SnapshotResult},
};

const HIGHLIGHT: Color32 = Color32::from_rgb(91, 209, 189);
const MUTED: Color32 = Color32::from_rgb(160, 170, 181);

pub struct OculariumApp {
    scopes: Vec<Scope>,
    selected_scope: usize,
    devices: BTreeMap<Ipv4Addr, Device>,
    selected_device: Option<Ipv4Addr>,
    receiver: Option<Receiver<Event>>,
    cancelled: Option<Arc<AtomicBool>>,
    scanning: bool,
    deep_scanning: bool,
    watch: Option<NeighborWatch>,
    watch_running: bool,
    remember_neighbors: bool,
    neighbor_archive: NeighborArchive,
    last_neighbor_flush: Option<Instant>,
    neighbor_archive_status: Option<String>,
    deep_report: Option<DeepReport>,
    completed: usize,
    total: usize,
    camera_only: bool,
    unidentified_only: bool,
    filter: String,
    messages: Vec<String>,
    status: String,
    registry: Registry,
    history: HistoryStore,
    dhcp: DhcpStore,
    dhcp_text: String,
    dhcp_message: Option<String>,
    alias_edit: String,
    rtsp_path: String,
    rtsp_username: String,
    show_rtsp_username: bool,
    rtsp_password: String,
    rtsp_receiver: Option<Receiver<RtspInspection>>,
    inspecting: Option<(Ipv4Addr, u16)>,
    inspections: BTreeMap<(Ipv4Addr, u16), RtspInspection>,
    snapshot_receiver: Option<Receiver<SnapshotResult>>,
    snapshot_busy: Option<(Ipv4Addr, u16)>,
    snapshot_pending: Option<SnapshotResult>,
    snapshot_texture: Option<(Ipv4Addr, u16, String, egui::TextureHandle)>,
    snapshot_error: Option<(Ipv4Addr, u16, String)>,
}

impl OculariumApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let (scopes, messages) = match discovery::interfaces() {
            Ok(scopes) => (scopes, Vec::new()),
            Err(err) => (Vec::new(), vec![format!("Network interfaces: {err}")]),
        };
        let (registry, registry_warning) = Registry::load();
        let mut messages = messages;
        if let Some(warning) = registry_warning {
            messages.push(warning);
        }
        let (history, history_warning) = HistoryStore::load();
        if let Some(warning) = history_warning {
            messages.push(warning);
        }
        let (dhcp, dhcp_warning) = DhcpStore::load();
        if let Some(warning) = dhcp_warning {
            messages.push(warning);
        }
        let (neighbor_archive, archive_warning) = NeighborArchive::load();
        if let Some(warning) = archive_warning {
            messages.push(warning);
        }
        Self {
            scopes,
            selected_scope: 0,
            devices: BTreeMap::new(),
            selected_device: None,
            receiver: None,
            cancelled: None,
            scanning: false,
            deep_scanning: false,
            watch: None,
            watch_running: false,
            remember_neighbors: false,
            neighbor_archive,
            last_neighbor_flush: None,
            neighbor_archive_status: None,
            deep_report: None,
            completed: 0,
            total: 253,
            camera_only: false,
            unidentified_only: false,
            filter: String::new(),
            messages,
            status: "Ready to scan".into(),
            registry,
            history,
            dhcp,
            dhcp_text: String::new(),
            dhcp_message: None,
            alias_edit: String::new(),
            rtsp_path: "/".into(),
            rtsp_username: String::new(),
            show_rtsp_username: false,
            rtsp_password: String::new(),
            rtsp_receiver: None,
            inspecting: None,
            inspections: BTreeMap::new(),
            snapshot_receiver: None,
            snapshot_busy: None,
            snapshot_pending: None,
            snapshot_texture: None,
            snapshot_error: None,
        }
    }

    fn start_scan(&mut self) {
        let Some(scope) = self.scopes.get(self.selected_scope).cloned() else {
            self.messages.push("No LAN interface selected".into());
            return;
        };
        self.devices.clear();
        self.selected_device = None;
        self.alias_edit.clear();
        self.rtsp_path = "/".into();
        self.rtsp_username.clear();
        self.show_rtsp_username = false;
        self.rtsp_password.clear();
        self.rtsp_receiver = None;
        self.inspecting = None;
        self.inspections.clear();
        self.snapshot_receiver = None;
        self.snapshot_busy = None;
        self.snapshot_pending = None;
        self.snapshot_texture = None;
        self.snapshot_error = None;
        self.messages.clear();
        self.completed = 0;
        self.total = scope.hosts_total();
        self.status = format!("Scanning {}", scope.description());
        self.scanning = true;
        self.deep_scanning = false;
        self.deep_report = None;
        let (tx, rx) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancelled);
        thread::spawn(move || discovery::scan(scope, tx, worker_cancel));
        self.receiver = Some(rx);
        self.cancelled = Some(cancelled);
    }

    fn start_deep_scan(&mut self) {
        let Some(scope) = self.scopes.get(self.selected_scope).cloned() else {
            return;
        };
        let targets: Vec<Ipv4Addr> = self
            .devices
            .values()
            .filter(|d| crate::classify::classify(d).needs_identification())
            .map(|d| d.ip)
            .collect();
        if targets.is_empty() {
            self.status = "No unidentified devices to inspect".into();
            return;
        }
        self.completed = 0;
        self.total = targets.len();
        self.scanning = true;
        self.deep_scanning = true;
        self.deep_report = None;
        let (tx, rx) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancelled);
        thread::spawn(move || discovery::deep_scan(scope, targets, tx, worker_cancel));
        self.receiver = Some(rx);
        self.cancelled = Some(cancelled);
    }

    fn persist_neighbor_observations(&mut self) {
        if !self.remember_neighbors {
            return;
        }
        let Some(watch) = &self.watch else {
            return;
        };
        if watch.sample_count == 0 {
            return;
        }
        match self.neighbor_archive.record(watch) {
            Ok(()) => {
                self.neighbor_archive_status = Some(format!(
                    "Saved {} MAC identities from this observation session",
                    watch.by_mac.len(),
                ))
            }
            Err(error) => self.neighbor_archive_status = Some(error),
        }
        self.last_neighbor_flush = Some(Instant::now());
    }

    fn poll(&mut self) {
        if let Some(watch) = &mut self.watch {
            watch.poll();
        }
        if self.watch_running
            && self.remember_neighbors
            && self
                .watch
                .as_ref()
                .is_some_and(|watch| watch.sample_count > 0)
            && self
                .last_neighbor_flush
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(60))
        {
            self.persist_neighbor_observations();
        }
        let mut disconnected = false;
        if let Some(rx) = &self.receiver {
            loop {
                match rx.try_recv() {
                    Ok(Event::Found(ip, observation)) => {
                        self.devices
                            .entry(ip)
                            .or_insert_with(|| Device::new(ip))
                            .apply(observation);
                    }
                    Ok(Event::Status(message)) => self.status = message,
                    Ok(Event::DeepReport(report)) => {
                        self.deep_report = Some(report);
                    }
                    Ok(Event::Progress(completed)) => {
                        self.completed = self.completed.max(completed);
                    }
                    Ok(Event::Warning(message)) => {
                        if self.messages.len() < 8 {
                            self.messages.push(message);
                        }
                    }
                    Ok(Event::Finished { cancelled }) => {
                        // Only a completed full scan counts as a new
                        // historical sighting. Never mistake a cancelled or
                        // targeted deep scan for a complete network snapshot.
                        if !cancelled && !self.deep_scanning {
                            if let Some(scope) = self.scopes.get(self.selected_scope) {
                                if let Err(error) = self.history.record_completed_scan(
                                    scope,
                                    &self.devices,
                                    HistoryStore::now(),
                                ) {
                                    self.messages.push(format!("History not saved: {error}"));
                                }
                            }
                        }
                        self.scanning = false;
                        self.status = match (self.deep_scanning, cancelled) {
                            (true, true) => "Deep scan cancelled".into(),
                            (true, false) => "Deep scan complete".into(),
                            (false, true) => "Scan cancelled".into(),
                            (false, false) => "Scan complete".into(),
                        };
                        self.deep_scanning = false;
                        disconnected = true;
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        self.scanning = false;
                        self.deep_scanning = false;
                        if self.status.starts_with("Scanning")
                            || self.status.starts_with("Deep scanning")
                        {
                            self.status = "Scan stopped unexpectedly".into();
                        }
                        break;
                    }
                }
            }
        }
        if disconnected {
            self.receiver = None;
            self.cancelled = None;
        }
        if let Some(rx) = self.snapshot_receiver.take() {
            match rx.try_recv() {
                Ok(captured) => {
                    self.snapshot_busy = None;
                    self.snapshot_pending = Some(captured);
                }
                Err(mpsc::TryRecvError::Empty) => self.snapshot_receiver = Some(rx),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.snapshot_busy = None;
                    self.snapshot_error = Some((
                        Ipv4Addr::UNSPECIFIED,
                        0,
                        "Snapshot worker stopped unexpectedly".into(),
                    ));
                }
            }
        }
        if let Some(rx) = self.rtsp_receiver.take() {
            match rx.try_recv() {
                Ok(inspection) => {
                    self.inspecting = None;
                    self.inspections
                        .insert((inspection.ip, inspection.port), inspection);
                }
                Err(mpsc::TryRecvError::Empty) => self.rtsp_receiver = Some(rx),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.inspecting = None;
                    self.messages
                        .push("RTSP inspection ended unexpectedly".into());
                }
            }
        }
    }

    fn refresh_interfaces(&mut self) {
        match discovery::interfaces() {
            Ok(scopes) => {
                self.scopes = scopes;
                self.selected_scope = 0;
            }
            Err(err) => self.messages.push(format!("Network interfaces: {err}")),
        }
    }

    fn export_report(&self) -> String {
        use std::fmt::Write as _;
        let mut report = String::from(
            "Ocularium LAN discovery report (device evidence only; no video verified)\n",
        );
        if let Some(scope) = self.scopes.get(self.selected_scope) {
            let _ = writeln!(report, "Scan scope: {}", scope.description());
        }
        let _ = writeln!(
            report,
            "Discovered: {} | Candidates: {}",
            self.devices.len(),
            self.devices
                .values()
                .filter(|d| d.is_camera_candidate())
                .count(),
        );
        if let Some(deep) = &self.deep_report {
            let _ = writeln!(report, "{}", deep.summary());
        }
        if let Some(scope) = self.scopes.get(self.selected_scope) {
            let records = self.neighbor_archive.records(scope);
            let _ = writeln!(
                report,
                "Saved opt-in passive neighbor observations: {} MAC identities (historical, not online status)",
                records.len(),
            );
            for record in records {
                let _ = writeln!(
                    report,
                    "  MAC {} · IPs {:?} · first {} · last {} · {} sessions · {} sampled cache sightings",
                    record.mac, record.ips,
                    history::display_time(record.first_seen),
                    history::display_time(record.last_seen),
                    record.sessions, record.sampled_sightings,
                );
            }
        }
        if let Some(watch) = &self.watch {
            let _ = writeln!(
                report,
                "ARP cache observer ({}): {} samples · {} IPs observed · {} in latest cache sample. Not an online status.",
                if self.watch_running { "running" } else { "stopped" },
                watch.sample_count, watch.observed_total(), watch.latest_cache_count,
            );
            for record in watch.observations.values() {
                let _ = writeln!(
                    report,
                    "  Neighbor {} MAC={} · first {} · last {} · samples {} · in last cache sample {}",
                    record.ip, record.mac,
                    history::display_time(record.first_seen),
                    history::display_time(record.last_seen),
                    record.samples, record.in_cache,
                );
            }
        }
        if let Some(scope) = self.scopes.get(self.selected_scope) {
            if let Some(scan) = self.history.latest_scan(scope) {
                let _ = writeln!(report,
                    "Saved history: last completed {} | observed {} | newly observed {} | IP changes {} | not observed {}",
                    history::display_time(scan.timestamp),
                    scan.found, scan.first_seen, scan.ip_changes,
                    self.history.not_seen(scope).len(),
                );
            }
        }
        if let Some(scope) = self.scopes.get(self.selected_scope) {
            if let Some(snapshot) = self.dhcp.snapshot(scope) {
                let _ = writeln!(
                    report,
                    "Imported DHCP inventory: {} leases · imported {} · {} unmatched",
                    snapshot.clients.len(),
                    history::display_time(snapshot.imported_at),
                    self.dhcp.unmatched(scope, &self.devices).len(),
                );
            }
        }
        for device in self.devices.values() {
            let _ = writeln!(
                report,
                "\n{} - {}\n  MAC: {}\n  Vendor: {}\n  Ports: {:?}\n  RTSP OPTIONS: {}",
                device.ip,
                device.classification(),
                device.mac.as_deref().unwrap_or("-"),
                device.vendor.as_deref().unwrap_or("Unknown"),
                device.open_ports,
                device.rtsp_responded,
            );
            if let Some(alias) = self.registry.alias(device) {
                let _ = writeln!(report, "  User label: {alias}");
            }
            if let Some(scope) = self.scopes.get(self.selected_scope) {
                if let Some((lease, matched_by)) = self.dhcp.match_device(scope, device) {
                    let _ = writeln!(
                        report,
                        "  Router DHCP: name={} · IP={} · {}",
                        lease.name.as_deref().unwrap_or("-"),
                        lease.ip,
                        matched_by.description(),
                    );
                }
            }
            if let Some(scope) = self.scopes.get(self.selected_scope) {
                if let Some(record) = self.history.record(scope, device) {
                    let _ = writeln!(
                        report,
                        "  History: {} completed scans | first {} | last {} | IPs {:?}",
                        record.seen_scans,
                        history::display_time(record.first_seen),
                        history::display_time(record.last_seen),
                        record.ips,
                    );
                }
            }
            for info in self
                .inspections
                .values()
                .filter(|report| report.ip == device.ip)
            {
                let _ = writeln!(
                    report,
                    "  RTSP port {}: {} | server={:?} | codecs={:?}",
                    info.port,
                    info.summary(),
                    info.server,
                    info.codecs,
                );
            }
            let classified = classify::classify(device);
            let _ = writeln!(
                report,
                "  Evidence: {} - {}",
                classified.level.label(),
                classified.reason,
            );
            for id in &device.identities {
                let _ = writeln!(
                    report,
                    "  {}: name={:?}, manufacturer={:?}, model={:?}, model number={:?}, type={:?}, firmware={:?}",
                    id.source, id.friendly_name, id.manufacturer, id.model,
                    id.model_number, id.device_type, id.firmware,
                );
            }
            for service in &device.mdns_services {
                let _ = writeln!(report, "  mDNS: {service}");
            }
            for name in &device.mdns_names {
                let _ = writeln!(report, "  mDNS hostname: {name}");
            }
            for name in &device.router_dns_names {
                let _ = writeln!(report, "  Local router DNS hostname: {name}");
            }
            for text in &device.mdns_txt {
                let _ = writeln!(report, "  TXT: {text}");
            }
            for service in &device.onvif_xaddrs {
                let _ = writeln!(report, "  ONVIF service: {service}");
            }
            for info in &device.http {
                let _ = writeln!(
                    report,
                    "  HTTP port {}: server={:?} title={:?} realm={:?}",
                    info.port, info.server, info.title, info.realm,
                );
            }
        }
        report
    }

    fn overview(&self, ui: &mut egui::Ui) {
        let candidates = self
            .devices
            .values()
            .filter(|d| d.is_camera_candidate())
            .count();
        let unidentified = self
            .devices
            .values()
            .filter(|d| classify::classify(d).needs_identification())
            .count();
        let equipment = self.devices.len().saturating_sub(candidates + unidentified);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("{} discovered devices", self.devices.len())).strong());
            ui.separator();
            ui.label(RichText::new(format!("{candidates} camera candidates")).color(HIGHLIGHT));
            ui.separator();
            ui.label(format!("{equipment} identified equipment"));
            ui.separator();
            ui.label(format!("{unidentified} unidentified"));
            ui.separator();
            ui.label(RichText::new(&self.status).color(MUTED));
            if ui
                .add_enabled(!self.devices.is_empty(), egui::Button::new("Copy report"))
                .clicked()
            {
                ui.ctx().copy_text(self.export_report());
            }
        });
        if let Some(scope) = self.scopes.get(self.selected_scope) {
            if let Some(snapshot) = self.dhcp.snapshot(scope) {
                ui.label(
                    RichText::new(format!(
                        "Imported router DHCP: {} leases · {} not matched · imported {}",
                        snapshot.clients.len(),
                        self.dhcp.unmatched(scope, &self.devices).len(),
                        history::display_time(snapshot.imported_at),
                    ))
                    .color(MUTED)
                    .small(),
                );
            }
            if let Some(scan) = self.history.latest_scan(scope) {
                let missing = self.history.not_seen(scope).len();
                ui.label(
                    RichText::new(format!(
                        "Saved scan: {} · {} new · {} IP changes · {} not observed this scan",
                        history::display_time(scan.timestamp),
                        scan.first_seen,
                        scan.ip_changes,
                        missing,
                    ))
                    .color(MUTED)
                    .small(),
                );
            }
        }
        if let Some(deep) = &self.deep_report {
            ui.label(RichText::new(deep.summary()).color(MUTED).small());
            if deep.open_ports == 0
                && deep.reverse_mdns_hosts == 0
                && deep.router_dns.named == 0
                && !deep.cancelled
            {
                ui.label(
                    RichText::new(
                        "No new port or hostname evidence. This does not rule out outbound-only or cloud-managed cameras.",
                    )
                    .color(MUTED)
                    .small(),
                );
            }
        }
    }

    fn discovery_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Network");
            let selected = self
                .scopes
                .get(self.selected_scope)
                .map(Scope::description)
                .unwrap_or_else(|| "No private IPv4 adapter".into());
            let names: Vec<String> = self.scopes.iter().map(Scope::description).collect();
            ui.add_enabled_ui(!self.scanning && !self.watch_running, |ui| {
                egui::ComboBox::from_id_salt("network_scope")
                    .selected_text(selected)
                    .width(340.0)
                    .show_ui(ui, |ui| {
                        for (index, name) in names.iter().enumerate() {
                            ui.selectable_value(&mut self.selected_scope, index, name);
                        }
                    });
                if ui.button("Refresh interfaces").clicked() {
                    self.refresh_interfaces();
                }
            });
        });
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.scanning && !self.scopes.is_empty(),
                    egui::Button::new(RichText::new("Scan network").strong()),
                )
                .clicked()
            {
                self.start_scan();
            }
            let unidentified = self
                .devices.values()
                .filter(|device| crate::classify::classify(device).needs_identification())
                .count();
            if ui
                .add_enabled(
                    !self.scanning && unidentified > 0,
                    egui::Button::new(format!("Deep scan {unidentified} unknown")),
                )
                .on_hover_text(
                    "Checks additional camera-related ports only on already-found, unidentified devices. No credentials or cloud requests.",
                )
                .clicked()
            {
                self.start_deep_scan();
            }
            if ui
                .add_enabled(self.scanning, egui::Button::new("Cancel"))
                .clicked()
            {
                if let Some(cancel) = &self.cancelled {
                    cancel.store(true, Ordering::Relaxed);
                    self.status = "Stopping scan...".into();
                }
            }
            if self.scanning {
                ui.add(
                    egui::ProgressBar::new(self.completed as f32 / self.total.max(1) as f32)
                        .desired_width(180.0)
                        .show_percentage(),
                );
                let unit = if self.deep_scanning { "devices" } else { "addresses" };
                ui.label(format!("{}/{} {unit}", self.completed, self.total));
            }
        });
        ui.horizontal_wrapped(|ui| {
            if self.watch_running {
                if ui.button("Stop neighbor observation").clicked() {
                    if let Some(watch) = &self.watch {
                        watch.stop();
                    }
                    self.watch_running = false;
                    self.persist_neighbor_observations();
                }
                ui.label(RichText::new("Reading local kernel neighbor cache every 10 seconds").color(HIGHLIGHT).small());
            } else if ui
                .add_enabled(!self.scanning && !self.scopes.is_empty(),
                    egui::Button::new("Observe LAN neighbors"))
                .on_hover_text(
                    "No packet capture or active probing. Reads the Linux kernel ARP cache for the selected interface while Ocularium is open."
                )
                .clicked()
            {
                if let Some(scope) = self.scopes.get(self.selected_scope).cloned() {
                    self.persist_neighbor_observations();
                    self.watch = Some(NeighborWatch::start(scope));
                    self.watch_running = true;
                    self.last_neighbor_flush = None;
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(
                &mut self.remember_neighbors,
                "Save neighbor observations across restarts",
            ).on_hover_text(
                "Off by default. Saves bounded MAC/IP history and cache events locally every 60 seconds and on Stop/Exit. Disabling does not erase previously saved data.",
            );
            if let Some(message) = &self.neighbor_archive_status {
                ui.label(RichText::new(message).small().color(MUTED));
            }
        });
    }

    fn devices_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Discovered devices");
            ui.separator();
            if ui
                .checkbox(&mut self.camera_only, "Camera candidates")
                .changed()
                && self.camera_only
            {
                self.unidentified_only = false;
            }
            if ui
                .checkbox(&mut self.unidentified_only, "Unidentified")
                .changed()
                && self.unidentified_only
            {
                self.camera_only = false;
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.filter).hint_text("Filter IP, model, label"),
            );
        });
        ui.separator();
        let needle = self.filter.trim().to_ascii_lowercase();
        let devices: Vec<Device> = self
            .devices
            .values()
            .filter(|d| !self.camera_only || d.is_camera_candidate())
            .filter(|d| !self.unidentified_only || classify::classify(d).needs_identification())
            .filter(|d| {
                needle.is_empty()
                    || d.ip.to_string().contains(&needle)
                    || self
                        .registry
                        .alias(d)
                        .is_some_and(|name| name.to_ascii_lowercase().contains(&needle))
                    || d.classification().to_ascii_lowercase().contains(&needle)
                    || self
                        .scopes
                        .get(self.selected_scope)
                        .and_then(|scope| self.dhcp.match_device(scope, d))
                        .and_then(|(lease, _)| lease.name.as_deref())
                        .is_some_and(|name| name.to_ascii_lowercase().contains(&needle))
                    || d.identities.iter().any(|info| {
                        [
                            info.friendly_name.as_deref(),
                            info.manufacturer.as_deref(),
                            info.model.as_deref(),
                            info.model_number.as_deref(),
                        ]
                        .into_iter()
                        .flatten()
                        .any(|value| value.to_ascii_lowercase().contains(&needle))
                    })
                    || d.vendor
                        .as_deref()
                        .is_some_and(|s| s.to_ascii_lowercase().contains(&needle))
                    || d.router_dns_names
                        .iter()
                        .any(|value| value.to_ascii_lowercase().contains(&needle))
                    || d.mdns_names
                        .iter()
                        .chain(d.mdns_services.iter())
                        .any(|s| s.to_ascii_lowercase().contains(&needle))
                    || d.http.iter().any(|info| {
                        [
                            info.server.as_deref(),
                            info.title.as_deref(),
                            info.realm.as_deref(),
                        ]
                        .into_iter()
                        .flatten()
                        .any(|s| s.to_ascii_lowercase().contains(&needle))
                    })
                    || d.ssdp_server
                        .as_deref()
                        .is_some_and(|s| s.to_ascii_lowercase().contains(&needle))
                    || d.onvif_scopes
                        .iter()
                        .any(|s| s.to_ascii_lowercase().contains(&needle))
            })
            .cloned()
            .collect();

        if devices.is_empty() {
            ui.add_space(14.0);
            ui.label(if self.scanning {
                "Looking for devices..."
            } else if self.devices.is_empty() {
                "No devices found yet. Select your LAN interface and press Scan network."
            } else {
                "No devices match the selected filters."
            });
            return;
        }

        egui::ScrollArea::both()
            .id_salt("device_list")
            .max_height(285.0)
            .show(ui, |ui| {
                egui::Grid::new("discovery_grid")
                    .striped(true)
                    .min_col_width(100.0)
                    .spacing([22.0, 8.0])
                    .show(ui, |ui| {
                        ui.strong("IP address");
                        ui.strong("Label");
                        ui.strong("DHCP name");
                        ui.strong("Classification");
                        ui.strong("Evidence");
                        ui.strong("Ports");
                        ui.strong("MAC");
                        ui.strong("MAC vendor");
                        ui.strong("Advertised device");
                        ui.end_row();
                        for d in &devices {
                            if ui
                                .selectable_label(
                                    self.selected_device == Some(d.ip),
                                    RichText::new(d.ip.to_string()).monospace(),
                                )
                                .clicked()
                            {
                                self.selected_device = Some(d.ip);
                                self.alias_edit = self.registry.alias(d).unwrap_or("").to_owned();
                                self.rtsp_path = "/".into();
                                self.rtsp_username.clear();
                                self.rtsp_password.clear();
                            }
                            ui.label(self.registry.alias(d).unwrap_or("-"));
                            let match_info = self.scopes.get(self.selected_scope)
                                .and_then(|scope| self.dhcp.match_device(scope, d));
                            let name = match_info.as_ref()
                                .and_then(|(lease, _)| lease.name.as_deref())
                                .unwrap_or("-");
                            ui.label(name).on_hover_text(match_info.map_or_else(
                                || "No matching imported DHCP lease".to_owned(),
                                |(_, how)| format!(
                                    "Router DHCP inventory: {}; client names are only identity clues",
                                    how.description()
                                )
                            ));
                            let classified = classify::classify(d);
                            let color = match classified.category {
                                DeviceCategory::CameraCandidate => HIGHLIGHT,
                                DeviceCategory::IdentifiedEquipment => {
                                    Color32::from_rgb(135, 174, 232)
                                }
                                DeviceCategory::Unidentified => MUTED,
                            };
                            ui.label(RichText::new(classified.label).color(color))
                                .on_hover_text(classified.reason.as_str());
                            ui.label(classified.level.label())
                                .on_hover_text(classified.reason);
                            ui.label(if d.open_ports.is_empty() {
                                "-".into()
                            } else {
                                d.open_ports
                                    .iter()
                                    .map(u16::to_string)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            });
                            ui.label(d.mac.as_deref().unwrap_or("-"));
                            ui.label(d.vendor.as_deref().unwrap_or("Unknown"));
                            let description = d
                                .identities
                                .iter()
                                .find_map(|info| {
                                    info.model.as_deref().or(info.friendly_name.as_deref())
                                })
                                .or_else(|| d.mdns_names.first().map(String::as_str))
                                .or_else(|| d.router_dns_names.first().map(String::as_str))
                                .unwrap_or("-");
                            ui.label(description);
                            ui.end_row();
                        }
                    });
            });
    }

    fn dhcp_panel(&mut self, ui: &mut egui::Ui) {
        let Some(scope) = self.scopes.get(self.selected_scope).cloned() else {
            return;
        };
        ui.separator();
        ui.collapsing("Router DHCP inventory", |ui| {
            ui.label(
                RichText::new(
                    "Paste DHCP client rows from your router's administration page. Ocularium never asks for or stores the router login."
                ).color(MUTED).small(),
            );
            if let Some(gateway) = dns::local_gateway(&scope) {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("Gateway: {gateway}"));
                    ui.hyperlink_to("Open router admin", format!("http://{gateway}/"));
                    if ui.button("Copy router IP").clicked() {
                        ui.ctx().copy_text(gateway.to_string());
                    }
                });
            } else {
                ui.label("No gateway detected for the selected interface.");
            }
            ui.label("TP-Link: DHCP > DHCP Clients List. Copy the rows with client name, MAC, assigned IP and lease time. Tabs, spaces or CSV are accepted.");
            ui.add(
                egui::TextEdit::multiline(&mut self.dhcp_text)
                    .hint_text("1   Camera-Example   AA-BB-CC-DD-EE-FF   192.168.0.100   00:30:00")
                    .desired_rows(5),
            );
            ui.horizontal_wrapped(|ui| {
                if ui.button("Import DHCP table").clicked() {
                    match self.dhcp.import(&scope, &self.dhcp_text) {
                        Ok(parsed) => {
                            self.dhcp_message = Some(format!(
                                "Imported {} leases; {} out-of-subnet rows skipped, {} unrecognized rows.",
                                parsed.clients.len(),
                                parsed.skipped_out_of_subnet,
                                parsed.rejected_rows,
                            ));
                            self.dhcp_text.clear();
                        }
                        Err(error) => self.dhcp_message = Some(error),
                    }
                }
                if ui.button("Clear pasted text").clicked() {
                    self.dhcp_text.clear();
                }
            });
            if let Some(message) = &self.dhcp_message {
                ui.label(message);
            }
            if let Some(snapshot) = self.dhcp.snapshot(&scope) {
                ui.label(format!(
                    "Imported {} · {} leases",
                    history::display_time(snapshot.imported_at),
                    snapshot.clients.len(),
                ));
                let unmatched = self.dhcp.unmatched(&scope, &self.devices);
                ui.strong(format!(
                    "{} DHCP clients without a matching current scan device",
                    unmatched.len()
                ));
                ui.label(
                    RichText::new(
                        "DHCP leases are historical router records. An unmatched client is not proof of a currently connected camera."
                    ).color(MUTED).small(),
                );
                egui::ScrollArea::vertical().id_salt("unmatched_dhcp")
                    .max_height(220.0).show(ui, |ui| {
                        for client in unmatched {
                            ui.label(format!(
                                "{} · {} · {}",
                                client.ip,
                                client.name.as_deref().unwrap_or("Unnamed"),
                                client.mac,
                            ));
                        }
                    });
            }
        });
    }

    fn neighbor_panel(&self, ui: &mut egui::Ui) {
        let Some(watch) = &self.watch else {
            return;
        };
        ui.separator();
        let state = if self.watch_running {
            "running"
        } else {
            "stopped"
        };
        ui.collapsing(format!(
            "Kernel neighbor observation ({state}, {} IPs seen)",
            watch.observed_total()
        ), |ui| {
            ui.label(
                RichText::new(
                    "Reads the existing Linux ARP neighbor cache every 10 seconds. No sniffing, packets, credentials, or background daemon. This cache is incomplete, and entries can expire even when devices are connected. Ordinary network scans may populate it."
                ).color(MUTED).small()
            );
            ui.label(format!(
                "Scope: {} · samples: {} · in last cache sample: {}",
                watch.scope().description(),
                watch.sample_count,
                watch.latest_cache_count,
            ));
            if let Some(at) = watch.last_sample {
                ui.label(format!("Last successful observation: {}", history::display_time(at)));
            }
            if let Some(warning) = &watch.last_warning {
                ui.colored_label(Color32::from_rgb(239, 190, 100), warning);
            }
            ui.collapsing("Observed neighbors", |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("kernel_neighbor_observations")
                    .max_height(230.0)
                    .show(ui, |ui| {
                        for record in watch.observations.values() {
                            let name = self.scopes.get(self.selected_scope)
                                .and_then(|scope| self.dhcp.snapshot(scope))
                                .and_then(|snapshot| snapshot.clients.iter()
                                    .find(|client| client.mac.eq_ignore_ascii_case(&record.mac)))
                                .and_then(|client| client.name.as_deref())
                                .unwrap_or("-");
                            ui.label(format!(
                                "{} · {} · {} · {} samples · last {}",
                                record.ip,
                                name,
                                if record.in_cache { "in cache" } else { "aged out of cache" },
                                record.samples,
                                history::display_time(record.last_seen),
                            ));
                        }
                    });
            });
            ui.collapsing(format!("Changes (last {})", watch.changes.len()), |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("kernel_neighbor_changes")
                    .max_height(220.0)
                    .show(ui, |ui| {
                        for change in watch.changes.iter().rev() {
                            ui.label(format!(
                                "{} · {}",
                                history::display_time(change.at),
                                change.detail
                            ));
                        }
                    });
            });
        });
    }

    fn neighbor_archive_panel(&self, ui: &mut egui::Ui) {
        let Some(scope) = self.scopes.get(self.selected_scope) else {
            return;
        };
        let entries = self.neighbor_archive.records(scope);
        if entries.is_empty() {
            return;
        }
        ui.separator();
        ui.collapsing(format!(
            "Saved passive neighbor history ({} MAC identities)",
            self.neighbor_archive.known_count(scope),
        ), |ui| {
            ui.label(
                RichText::new(
                    "Historical kernel-cache observations, saved only after opt-in. A missing cache entry is not proof the device is offline. A randomized MAC cannot reliably be linked to another identity."
                ).color(MUTED).small()
            );
            egui::ScrollArea::vertical()
                .id_salt("saved_neighbor_macs")
                .max_height(235.0)
                .show(ui, |ui| {
                    for row in entries {
                        let dhcp_name = self.dhcp.snapshot(scope)
                            .and_then(|snapshot| snapshot.clients.iter()
                                .find(|lease| lease.mac.eq_ignore_ascii_case(&row.mac)))
                            .and_then(|client| client.name.as_deref())
                            .unwrap_or("-");
                        ui.label(format!(
                            "{} · {} · {} sessions · IPs {:?} · last {}",
                            row.mac, dhcp_name, row.sessions, row.ips,
                            history::display_time(row.last_seen),
                        ));
                    }
                });
            let events = self.neighbor_archive.events(scope);
            ui.collapsing(format!("Saved cache events (last {})", events.len()), |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("saved_neighbor_events")
                    .max_height(200.0)
                    .show(ui, |ui| {
                        for change in events {
                            ui.label(format!(
                                "{} · {}",
                                history::display_time(change.at), change.detail,
                            ));
                        }
                    });
            });
        });
    }

    fn history_panel(&self, ui: &mut egui::Ui) {
        let Some(scope) = self.scopes.get(self.selected_scope) else {
            return;
        };
        let known = self.history.known_count(scope);
        if known == 0 {
            return;
        }
        ui.separator();
        ui.collapsing(format!("Saved device history ({known} known in this network)"), |ui| {
            ui.label(RichText::new(
                "Historical observations only. A device missing from a scan is not necessarily offline."
            ).color(MUTED).small());
            let missing = self.history.not_seen(scope);
            if let Some(latest) = self.history.latest_scan(scope) {
                ui.label(format!(
                    "Latest completed scan: {} · {} observed · {} new · {} IP changes",
                    history::display_time(latest.timestamp),
                    latest.found, latest.first_seen, latest.ip_changes,
                ));
            }
            if !missing.is_empty() {
                ui.strong(format!(
                    "{} previously known devices not observed in latest completed scan:",
                    missing.len()
                ));
                for record in missing.iter().take(30) {
                    let ip = record.ips.last().map(ToString::to_string)
                        .unwrap_or_else(|| "-".into());
                    ui.label(format!(
                        "{ip} · {} · last observed {} ({} scans)",
                        record.label_hint.as_deref().unwrap_or(&record.last_classification),
                        history::display_time(record.last_seen),
                        record.seen_scans,
                    ));
                }
                if missing.len() > 30 {
                    ui.label(format!("... and {} more", missing.len() - 30));
                }
            } else {
                ui.label("Every previously recorded device was observed in the latest completed scan.");
            }
            ui.collapsing("All recorded devices", |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("historical_devices")
                    .max_height(240.0)
                    .show(ui, |ui| {
                        for record in self.history.entries_for_scope(scope) {
                            let ip = record.ips.last().map(ToString::to_string)
                                .unwrap_or_else(|| "-".into());
                            ui.label(format!(
                                "{ip} · {} · {} sightings · last {}",
                                record.label_hint.as_deref().unwrap_or(&record.last_classification),
                                record.seen_scans,
                                history::display_time(record.last_seen),
                            ));
                        }
                    });
            });
        });
    }

    fn details_panel(&mut self, ui: &mut egui::Ui) {
        ui.separator();
        ui.heading("Device details");
        let Some(device) = self
            .selected_device
            .and_then(|ip| self.devices.get(&ip))
            .cloned()
        else {
            ui.label(RichText::new("Select a device by clicking its IP address.").color(MUTED));
            return;
        };
        if let Some(scope) = self.scopes.get(self.selected_scope) {
            if let Some(mac) = device.mac.as_deref() {
                if let Some(record) = self.neighbor_archive.by_mac(scope, mac) {
                    ui.label(format!(
                        "Saved passive history: {} sessions · first {} · last {} · observed IPs {:?}",
                        record.sessions,
                        history::display_time(record.first_seen),
                        history::display_time(record.last_seen),
                        record.ips,
                    ));
                }
            }
        }
        if let Some(watch) = &self.watch {
            if self.scopes.get(self.selected_scope) == Some(watch.scope()) {
                if let Some(record) = watch.seen(device.ip) {
                    ui.label(format!(
                        "Neighbor-cache observation: last {} · {} samples · {}",
                        history::display_time(record.last_seen),
                        record.samples,
                        if record.in_cache {
                            "present in last cache sample"
                        } else {
                            "not in last cache sample (not necessarily offline)"
                        },
                    ));
                    if device
                        .mac
                        .as_deref()
                        .is_some_and(|mac| !mac.eq_ignore_ascii_case(&record.mac))
                    {
                        ui.colored_label(
                            Color32::from_rgb(239, 190, 100),
                            "Neighbor-cache MAC differs from this scan; check for an IP change or stale discovery",
                        );
                    }
                }
            }
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new(device.ip.to_string()).monospace().strong());
            if ui.button("Copy IP").clicked() {
                ui.ctx().copy_text(device.ip.to_string());
            }
        });
        ui.horizontal(|ui| {
            ui.label("Local label");
            ui.add(
                egui::TextEdit::singleline(&mut self.alias_edit)
                    .hint_text("e.g. Front gate or Patio"),
            );
            if ui.button("Save label").clicked() {
                match self.registry.set_alias(&device, &self.alias_edit) {
                    Ok(()) => self.status = "Device label saved locally".into(),
                    Err(error) => self.messages.push(format!("Could not save label: {error}")),
                }
            }
        });
        if let Some(scope) = self.scopes.get(self.selected_scope) {
            if let Some((lease, matched_by)) = self.dhcp.match_device(scope, &device) {
                ui.group(|ui| {
                    ui.strong("Imported router DHCP lease");
                    ui.label(format!(
                        "Client name: {}",
                        lease.name.as_deref().unwrap_or("Unnamed")
                    ));
                    ui.label(format!("Lease IP: {} · MAC: {}", lease.ip, lease.mac));
                    ui.label(format!("Match type: {}", matched_by.description()));
                    if let Some(time) = &lease.lease_time {
                        ui.label(format!("Lease time at import: {time}"));
                    }
                    ui.label(
                        RichText::new(
                            "This imported lease is not proof the device is online or a camera.",
                        )
                        .color(MUTED)
                        .small(),
                    );
                });
            }
            if let Some(record) = self.history.record(scope, &device) {
                ui.label(format!(
                    "History: {} completed scans · first observed {} · last observed {}",
                    record.seen_scans,
                    history::display_time(record.first_seen),
                    history::display_time(record.last_seen),
                ));
                if record.ips.len() > 1 {
                    let addresses: Vec<_> = record.ips.iter().map(ToString::to_string).collect();
                    ui.label(format!("IP addresses observed: {}", addresses.join(", ")));
                }
            }
        }
        let classified = classify::classify(&device);
        ui.label(RichText::new(format!("Classification: {}", classified.label)).strong());
        ui.label(format!("Evidence level: {}", classified.level.label()));
        ui.label(format!("Why: {}", classified.reason));
        if classified.category == DeviceCategory::Unidentified {
            ui.label(RichText::new(
                "Device type still unknown. MAC vendor names identify networking hardware, not the camera brand.",
            ).color(MUTED).small());
        }
        ui.label(format!(
            "MAC: {} | Offline manufacturer lookup: {}",
            device.mac.as_deref().unwrap_or("Unknown"),
            device.vendor.as_deref().unwrap_or("Unknown"),
        ));
        ui.label(format!(
            "RTSP OPTIONS answered: {} (not a verified playable stream)",
            if device.rtsp_responded { "yes" } else { "no" }
        ));
        let rtsp_ports: Vec<u16> = device
            .open_ports
            .iter()
            .filter(|&&port| [554, 8554, 8555, 10554].contains(&port))
            .copied()
            .collect();
        if !rtsp_ports.is_empty() {
            ui.horizontal(|ui| {
                ui.label("RTSP path");
                ui.add(
                    egui::TextEdit::singleline(&mut self.rtsp_path)
                        .hint_text("/ (or device-provided stream path)")
                        .desired_width(260.0),
                );
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Optional username");
                ui.add(
                    egui::TextEdit::singleline(&mut self.rtsp_username)
                        .password(!self.show_rtsp_username)
                        .desired_width(150.0),
                );
                if ui.small_button(
                    if self.show_rtsp_username { "Hide" } else { "Show" }
                ).on_hover_text("Username is hidden by default to avoid exposing it in screenshots.").clicked() {
                    self.show_rtsp_username = !self.show_rtsp_username;
                }
                ui.label("Password");
                ui.add(
                    egui::TextEdit::singleline(&mut self.rtsp_password)
                        .password(true)
                        .desired_width(150.0),
                );
            });
            ui.label(RichText::new(
                "Optional: enter the camera's RTSP login. Username is hidden by default; password is always masked and cleared after testing. No credentials are saved or exported.",
            ).small().color(MUTED));
        }
        for port in rtsp_ports {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.inspecting.is_none(),
                        egui::Button::new(format!("Test RTSP access :{port}")),
                    )
                    .clicked()
                {
                    if self.rtsp_username.is_empty() != self.rtsp_password.is_empty() {
                        self.messages
                            .push("Enter both username and password, or leave both blank".into());
                    } else {
                        let (tx, rx) = mpsc::channel();
                        let ip = device.ip;
                        let path = self.rtsp_path.clone();
                        let credentials = if self.rtsp_username.is_empty() {
                            None
                        } else {
                            Some(rtsp::Credentials {
                                username: self.rtsp_username.clone(),
                                password: std::mem::take(&mut self.rtsp_password),
                            })
                        };
                        thread::spawn(move || {
                            let _ = tx.send(rtsp::inspect(ip, port, path, credentials));
                        });
                        // Hide the previous result while this attempt is in
                        // progress. Otherwise an old 401 looks like the result
                        // of the newly supplied credentials.
                        self.inspections.remove(&(ip, port));
                        self.rtsp_receiver = Some(rx);
                        self.inspecting = Some((ip, port));
                    }
                }
                if self.inspecting == Some((device.ip, port)) {
                    ui.spinner();
                    ui.label("Testing RTSP access (one optional Digest attempt)");
                }
            });
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        self.snapshot_busy.is_none(),
                        egui::Button::new(format!("Capture one frame :{port}")),
                    )
                    .on_hover_text(
                        "Optional CPU-only ffmpeg preview of the supplied RTSP path. No passwords, recording, or guessed paths.",
                    )
                    .clicked()
                {
                    let (tx, rx) = mpsc::channel();
                    let ip = device.ip;
                    let path = self.rtsp_path.clone();
                    self.snapshot_busy = Some((ip, port));
                    self.snapshot_receiver = Some(rx);
                    self.snapshot_texture = None;
                    self.snapshot_error = None;
                    thread::spawn(move || {
                        let _ = tx.send(snapshot::capture(ip, port, path));
                    });
                }
                if self.snapshot_busy == Some((device.ip, port)) {
                    ui.spinner();
                    ui.label("Attempting one CPU-decoded frame (12s maximum)");
                }
            });
            if let Some((ip, captured_port, path, texture)) = &self.snapshot_texture {
                if *ip == device.ip && *captured_port == port && *path == self.rtsp_path {
                    ui.label(
                        RichText::new("Decoded RTSP frame (memory only; no recording)")
                            .color(HIGHLIGHT),
                    );
                    ui.add(egui::Image::new(texture).max_width(640.0));
                }
            }
            if let Some((ip, captured_port, error)) = &self.snapshot_error {
                if (*ip == device.ip && *captured_port == port)
                    || (*ip == Ipv4Addr::UNSPECIFIED && *captured_port == 0)
                {
                    ui.colored_label(Color32::from_rgb(239, 190, 100), error);
                }
            }
            if !self.rtsp_username.is_empty() {
                ui.label(RichText::new(
                    "Snapshot capture does not use the RTSP username or password. Authenticated snapshots require a secure in-process decoder, not command-line credentials."
                ).color(MUTED).small());
            }
            if let Some(result) = self.inspections.get(&(device.ip, port)) {
                if result.path != self.rtsp_path {
                    ui.label(RichText::new(
                        "Previous RTSP test used a different stream path. Run Test RTSP access again to evaluate this path."
                    ).color(MUTED).small());
                }
                ui.label(result.summary());
                ui.label(format!(
                    "Initial DESCRIBE: {}",
                    result
                        .initial_describe_status
                        .map_or_else(|| "no response".to_owned(), |status| status.to_string()),
                ));
                ui.label(format!(
                    "Authenticated retry sent: {}",
                    if result.retry_attempted { "yes" } else { "no" }
                ));
                if result.retry_attempted {
                    ui.label(format!(
                        "Authenticated retry response: {}",
                        result
                            .authenticated_retry_status
                            .map_or_else(|| "no response".to_owned(), |status| status.to_string()),
                    ));
                }
                if let Some(details) = &result.challenge_summary {
                    ui.label(format!("Challenge (redacted): {details}"));
                }
                ui.label(format!(
                    "Authentication assessment: {}",
                    result.auth_diagnostic
                ));
                if ui.button("Copy safe RTSP diagnostic").on_hover_text(
                    "Copies status codes and compatibility flags only. Does not include login credentials, stream path, Digest realm, nonce, or Authorization header."
                ).clicked() {
                    ui.ctx().copy_text(result.safe_diagnostic());
                }
                if result.describe_status == Some(401) {
                    ui.label(
                        RichText::new(
                            if result.retry_attempted {
                                "Server rejected the authenticated request. This does not establish whether the password, RTSP permissions, stream path, or Digest handling is responsible."
                            } else {
                                "The server requested authentication, but no authenticated response was sent. See the assessment above."
                            }
                        ).color(Color32::from_rgb(239, 190, 100)),
                    );
                } else if result.sdp_received {
                    ui.label(
                        RichText::new("Stream description received. Try Capture one frame to test decoding; continuous playback is not implemented.")
                            .color(HIGHLIGHT),
                    );
                }
                if let Some(server) = &result.server {
                    ui.label(format!("RTSP server: {server}"));
                }
                if let Some(auth) = &result.authentication {
                    ui.label(format!("Authentication scheme: {auth}"));
                }
                if !result.codecs.is_empty() {
                    ui.label(format!("SDP codecs: {}", result.codecs.join(", ")));
                }
                if result.sdp_received {
                    ui.label("SDP received; this does not confirm playable video.");
                }
            }
        }
        if let Some(server) = &device.ssdp_server {
            ui.label(format!("SSDP server: {server}"));
        }
        if let Some(target) = &device.ssdp_target {
            ui.label(format!("SSDP search target: {target}"));
        }
        if let Some(location) = &device.ssdp_location {
            ui.label(format!("SSDP location: {location}"));
        }
        for identity in &device.identities {
            ui.group(|ui| {
                ui.strong(format!("Advertised identity ({})", identity.source));
                for (label, value) in [
                    ("Name", identity.friendly_name.as_deref()),
                    ("Manufacturer", identity.manufacturer.as_deref()),
                    ("Model", identity.model.as_deref()),
                    ("Model number", identity.model_number.as_deref()),
                    ("Device type", identity.device_type.as_deref()),
                    ("Firmware", identity.firmware.as_deref()),
                ] {
                    if let Some(value) = value {
                        ui.label(format!("{label}: {value}"));
                    }
                }
            });
        }
        for info in &device.http {
            ui.label(format!(
                "HTTP port {}: server={} · title={} · auth realm={}",
                info.port,
                info.server.as_deref().unwrap_or("-"),
                info.title.as_deref().unwrap_or("-"),
                info.realm.as_deref().unwrap_or("-"),
            ));
        }
        for (heading, values) in [
            ("mDNS hostnames", &device.mdns_names),
            ("Local router DNS names", &device.router_dns_names),
            ("mDNS services", &device.mdns_services),
            ("mDNS device metadata", &device.mdns_txt),
            ("ONVIF device services", &device.onvif_xaddrs),
            ("ONVIF types", &device.onvif_types),
            ("ONVIF scopes", &device.onvif_scopes),
        ] {
            if !values.is_empty() {
                ui.collapsing(format!("{heading} ({})", values.len()), |ui| {
                    for value in values {
                        ui.label(RichText::new(value).monospace().small());
                    }
                });
            }
        }
    }
}

impl Drop for OculariumApp {
    fn drop(&mut self) {
        if let Some(watch) = &self.watch {
            watch.stop();
        }
        self.persist_neighbor_observations();
    }
}

impl eframe::App for OculariumApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if let Some(result) = self.snapshot_pending.take() {
            if let Some(pixels) = result.pixels {
                let image =
                    egui::ColorImage::from_rgb([snapshot::WIDTH, snapshot::HEIGHT], &pixels);
                let texture = ctx.load_texture(
                    format!("ocularium-rtsp-{}-{}", result.ip, result.port),
                    image,
                    egui::TextureOptions::LINEAR,
                );
                self.snapshot_texture = Some((result.ip, result.port, result.path, texture));
                self.snapshot_error = None;
            } else {
                self.snapshot_texture = None;
                self.snapshot_error = Some((
                    result.ip,
                    result.port,
                    result
                        .error
                        .unwrap_or_else(|| "No frame was decoded".into()),
                ));
            }
        }
        if self.scanning
            || self.inspecting.is_some()
            || self.watch_running
            || self.snapshot_busy.is_some()
        {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().id_salt("main_scroll").show(ui, |ui| {
                ui.heading(RichText::new("OCULARIUM").color(HIGHLIGHT).size(27.0));
                ui.label(
                    RichText::new("Local network discovery · Rust / egui · no server required")
                        .color(MUTED),
                );
                ui.add_space(14.0);
                self.discovery_controls(ui);
                ui.add_space(10.0);
                self.overview(ui);
                for message in &self.messages {
                    ui.colored_label(Color32::from_rgb(242, 180, 91), message);
                }
                ui.add_space(12.0);
                self.devices_panel(ui);
                self.details_panel(ui);
                self.neighbor_panel(ui);
                self.neighbor_archive_panel(ui);
                self.dhcp_panel(ui);
                self.history_panel(ui);
                ui.add_space(12.0);
                ui.label(
                    RichText::new(
                        "Discovery is best effort. Open ports and protocol responses do not prove video access. Scans stay on the selected local /24.",
                    )
                    .small()
                    .color(MUTED),
                );
            });
        });
    }
}
