mod app;
mod classify;
mod dhcp;
mod discovery;
mod dns;
mod history;
mod identify;
mod identity;
mod local_stream;
// Protocol groundwork has intentionally no network integration yet.
mod mdns;
#[allow(dead_code)]
mod meari_devices;
#[allow(dead_code)]
mod meari_vvp;
mod neighbor_history;
mod neighbor_watch;
mod onvif_capabilities;
mod registry;
mod rtsp;
mod snapshot;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 740.0])
            .with_min_inner_size([760.0, 500.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Ocularium",
        options,
        Box::new(|cc| Ok(Box::new(app::OculariumApp::new(cc)))),
    )
}
