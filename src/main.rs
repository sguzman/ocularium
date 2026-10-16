mod app;
mod classify;
mod discovery;
mod dns;
mod identify;
mod identity;
mod history;
mod mdns;
mod registry;
mod rtsp;

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
