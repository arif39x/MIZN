use eframe::egui;
use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &AppState) {
    let telemetry = match state.live_telemetry.read() {
        Ok(guard) => guard.clone(),
        Err(_) => return, // PoisonError
    };

    ui.heading("Process-to-Network Inspector");
    ui.add_space(10.0);
    
    // Sort processes by total active throughput (TX + RX)
    let mut processes: Vec<_> = telemetry.active_process_telemetry.values().collect();
    processes.sort_by(|a, b| {
        let total_b = b.transmission_rate_bytes_per_second + b.reception_rate_bytes_per_second;
        let total_a = a.transmission_rate_bytes_per_second + a.reception_rate_bytes_per_second;
        total_b.cmp(&total_a)
    });

    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("inspector_grid")
            .striped(true)
            .spacing([30.0, 10.0])
            .min_col_width(100.0)
            .show(ui, |ui| {
                ui.strong("PID");
                ui.strong("Process Name");
                ui.strong("Down Rate");
                ui.strong("Up Rate");
                ui.strong("Destination SNI");
                ui.end_row();

                for p in processes.iter().take(50) { // Limit to top 50 to maintain performance
                    ui.label(p.process_identifier.to_string());
                    ui.label(&p.process_nomenclature);
                    ui.label(format!("{}/s", human_bytes::human_bytes(p.reception_rate_bytes_per_second as f64)));
                    ui.label(format!("{}/s", human_bytes::human_bytes(p.transmission_rate_bytes_per_second as f64)));
                    ui.label(if p.sni.is_empty() { "-" } else { &p.sni });
                    ui.end_row();
                }
            });
    });
}
