pub mod app;
pub mod state;
pub mod views;

use eframe::egui;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("MIZN"),
        ..Default::default()
    };

    eframe::run_native(
        "MIZN",
        options,
        Box::new(|cc| Ok(Box::new(app::MiznApp::new(cc)))),
    )
}
