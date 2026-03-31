use eframe::egui;
use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &AppState, inspected_pid: &mut Option<i32>) {
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
                ui.strong("Action");
                ui.end_row();

                for p in processes.iter().take(50) { // Limit to top 50 to maintain performance
                    ui.label(p.process_identifier.to_string());
                    ui.label(&p.process_nomenclature);
                    ui.label(format!("{}/s", human_bytes::human_bytes(p.reception_rate_bytes_per_second as f64)));
                    ui.label(format!("{}/s", human_bytes::human_bytes(p.transmission_rate_bytes_per_second as f64)));
                    ui.label(if p.sni.is_empty() { "-" } else { &p.sni });
                    if ui.button("🔍 Inspect").clicked() {
                        *inspected_pid = Some(p.process_identifier);
                    }
                    ui.end_row();
                }
            });
    });

    if let Some(pid) = *inspected_pid {
        let mut open = true;
        egui::Window::new(format!("Deep Inspection: PID {}", pid))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .min_width(400.0)
            .show(ui.ctx(), |ui| {
                if let Some(p) = telemetry.active_process_telemetry.get(&pid) {
                    ui.heading(egui::RichText::new(&p.process_nomenclature).color(egui::Color32::from_rgb(0, 255, 180)));
                    ui.add_space(10.0);
                    
                    egui::Grid::new("inspection_details").spacing([40.0, 10.0]).show(ui, |ui| {
                        ui.label("PID:"); ui.label(p.process_identifier.to_string()); ui.end_row();
                        ui.label("TCP Flags:"); ui.label(format!("0x{:02X}", p.tcp_flags)); ui.end_row();
                        ui.label("Download (RX):"); ui.label(format!("{}/s", human_bytes::human_bytes(p.reception_rate_bytes_per_second as f64))); ui.end_row();
                        ui.label("Upload (TX):"); ui.label(format!("{}/s", human_bytes::human_bytes(p.transmission_rate_bytes_per_second as f64))); ui.end_row();
                        ui.label("SNI:"); ui.label(if p.sni.is_empty() { "-" } else { &p.sni }); ui.end_row();
                        
                        let dest_ip = p.last_resolved_remote_peer_ipv4
                            .map(|ip| std::net::Ipv4Addr::from(ip.to_be()).to_string())
                            .unwrap_or_else(|| "Unknown".to_string());
                        ui.label("Remote Peer IPv4:"); ui.label(dest_ip); ui.end_row();
                    });
                } else {
                    ui.label(egui::RichText::new("Process is no longer active.").color(egui::Color32::DARK_GRAY));
                }
            });
        
        if !open {
            *inspected_pid = None;
        }
    }
}
