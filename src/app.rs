use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
    time::Duration,
};

use eframe::egui::{self, Color32, RichText};

use crate::discovery::{self, Device, Event, Scope};

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
    completed: usize,
    total: usize,
    camera_only: bool,
    filter: String,
    messages: Vec<String>,
    status: String,
}

impl OculariumApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let (scopes, messages) = match discovery::interfaces() {
            Ok(scopes) => (scopes, Vec::new()),
            Err(err) => (Vec::new(), vec![format!("Network interfaces: {err}")]),
        };
        Self {
            scopes,
            selected_scope: 0,
            devices: BTreeMap::new(),
            selected_device: None,
            receiver: None,
            cancelled: None,
            scanning: false,
            completed: 0,
            total: 253,
            camera_only: false,
            filter: String::new(),
            messages,
            status: "Ready to scan".into(),
        }
    }

    fn start_scan(&mut self) {
        let Some(scope) = self.scopes.get(self.selected_scope).cloned() else {
            self.messages.push("No LAN interface selected".into());
            return;
        };
        self.devices.clear();
        self.selected_device = None;
        self.messages.clear();
        self.completed = 0;
        self.total = scope.hosts_total();
        self.status = format!("Scanning {}", scope.description());
        self.scanning = true;
        let (tx, rx) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancelled);
        thread::spawn(move || discovery::scan(scope, tx, worker_cancel));
        self.receiver = Some(rx);
        self.cancelled = Some(cancelled);
    }

    fn poll(&mut self) {
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
                    Ok(Event::Progress(completed)) => {
                        self.completed = self.completed.max(completed);
                    }
                    Ok(Event::Warning(message)) => {
                        if self.messages.len() < 8 {
                            self.messages.push(message);
                        }
                    }
                    Ok(Event::Finished { cancelled }) => {
                        self.scanning = false;
                        self.status = if cancelled {
                            "Scan cancelled".into()
                        } else {
                            "Scan complete".into()
                        };
                        disconnected = true;
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        self.scanning = false;
                        if self.status.starts_with("Scanning") {
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

    fn overview(&self, ui: &mut egui::Ui) {
        let candidates = self
            .devices
            .values()
            .filter(|d| d.is_camera_candidate())
            .count();
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("{} discovered devices", self.devices.len())).strong());
            ui.separator();
            ui.label(RichText::new(format!("{candidates} camera candidates")).color(HIGHLIGHT));
            ui.separator();
            ui.label(RichText::new(&self.status).color(MUTED));
        });
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
            ui.add_enabled_ui(!self.scanning, |ui| {
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
                ui.label(format!("{}/{} addresses", self.completed, self.total));
            }
        });
    }

    fn devices_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Discovered devices");
            ui.separator();
            ui.checkbox(&mut self.camera_only, "Camera candidates only");
            ui.add(
                egui::TextEdit::singleline(&mut self.filter).hint_text("Filter IP, service, label"),
            );
        });
        ui.separator();
        let needle = self.filter.trim().to_ascii_lowercase();
        let devices: Vec<Device> = self
            .devices
            .values()
            .filter(|d| !self.camera_only || d.is_camera_candidate())
            .filter(|d| {
                needle.is_empty()
                    || d.ip.to_string().contains(&needle)
                    || d.classification().to_ascii_lowercase().contains(&needle)
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

        egui::ScrollArea::vertical()
            .id_salt("device_list")
            .max_height(285.0)
            .show(ui, |ui| {
                egui::Grid::new("discovery_grid")
                    .striped(true)
                    .min_col_width(100.0)
                    .spacing([22.0, 8.0])
                    .show(ui, |ui| {
                        ui.strong("IP address");
                        ui.strong("Classification");
                        ui.strong("Ports");
                        ui.strong("MAC");
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
                            }
                            let color = if d.is_camera_candidate() {
                                HIGHLIGHT
                            } else {
                                MUTED
                            };
                            ui.label(RichText::new(d.classification()).color(color));
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
                            ui.end_row();
                        }
                    });
            });
    }

    fn details_panel(&self, ui: &mut egui::Ui) {
        ui.separator();
        ui.heading("Device details");
        let Some(device) = self.selected_device.and_then(|ip| self.devices.get(&ip)) else {
            ui.label(RichText::new("Select a device by clicking its IP address.").color(MUTED));
            return;
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(device.ip.to_string()).monospace().strong());
            if ui.button("Copy IP").clicked() {
                ui.ctx().copy_text(device.ip.to_string());
            }
        });
        ui.label(format!("Type: {}", device.classification()));
        ui.label(format!(
            "RTSP OPTIONS answered: {} (not a verified playable stream)",
            if device.rtsp_responded { "yes" } else { "no" }
        ));
        if let Some(server) = &device.ssdp_server {
            ui.label(format!("SSDP server: {server}"));
        }
        if let Some(target) = &device.ssdp_target {
            ui.label(format!("SSDP search target: {target}"));
        }
        if let Some(location) = &device.ssdp_location {
            ui.label(format!("SSDP location: {location}"));
        }
        for (heading, values) in [
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

impl eframe::App for OculariumApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.scanning {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical(|ui| {
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
