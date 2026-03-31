use eframe::egui;
use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &AppState) {
    ui.heading("Security Center - Threat Feed");
    ui.add_space(10.0);

    let mut alerts = Vec::new();

    if let Ok(guard) = state.db_pool.lock() {
        if let Some(conn) = &*guard {
            if let Ok(mut stmt) = conn.prepare("SELECT ts, alert_type, attacker_ip, target_port FROM threat_alerts ORDER BY id DESC LIMIT 50") {
                let iter = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                });

                if let Ok(iter) = iter {
                    for alert in iter.flatten() {
                        alerts.push(alert);
                    }
                }
            }
        }
    }

    if alerts.is_empty() {
        ui.label(egui::RichText::new(" No active threats detected.").color(egui::Color32::GREEN));
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        for (ts, a_type, ip, port) in alerts {
            let color = match a_type.as_str() {
                "ARP_SPOOF_ATTACK" => egui::Color32::RED,
                "HONEY_PORT_TRIGGER" => egui::Color32::GOLD,
                _ => egui::Color32::LIGHT_RED,
            };

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(egui::RichText::new(format!("[{}]", a_type)).color(color));
                    ui.separator();
                    ui.label(format!("Attacker: {}", ip));
                    ui.separator();
                    if port > 0 {
                        ui.label(format!("Port: {}", port));
                        ui.separator();
                    }
                    ui.label(format!("TS: {}", ts));
                });
            });
            ui.add_space(5.0);
        }
    });
}
