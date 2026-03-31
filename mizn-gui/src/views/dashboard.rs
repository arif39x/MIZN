use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints, Legend};
use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &AppState) {
    let telemetry = match state.live_telemetry.read() {
        Ok(guard) => guard.clone(),
        Err(_) => return, // PoisonError safeguard
    };

    ui.heading("Global Network Activity");
    ui.add_space(10.0);

    ui.horizontal(|ui| {
        ui.label(format!(
            "Download: {}/s",
            human_bytes::human_bytes(telemetry.aggregate_reception_rate_bytes_per_second as f64)
        ));
        ui.separator();
        ui.label(format!(
            "Upload: {}/s",
            human_bytes::human_bytes(telemetry.aggregate_transmission_rate_bytes_per_second as f64)
        ));
        ui.separator();
        ui.label(format!(
            "Peak Throughput: {}/s",
            human_bytes::human_bytes(telemetry.global_peak_throughput_bytes_per_second as f64)
        ));
    });

    ui.add_space(20.0);

    // Extract sliding window data
    let cursor = telemetry.history_ring_buffer_cursor;
    let mut rx_points = vec![];
    let mut tx_points = vec![];

    // Build the 60-second window correctly handling the ring buffer wraparound
    for i in 0..60 {
        let idx = (cursor + i) % 60;
        let rx_val = telemetry.reception_history_ring_buffer[idx] as f64;
        let tx_val = telemetry.transmission_history_ring_buffer[idx] as f64;

        // Let x-axis be "seconds ago", so -60.0 to 0.0
        let x = i as f64 - 60.0;
        rx_points.push([x, rx_val]);
        tx_points.push([x, tx_val]);
    }

    let rx_line = Line::new(PlotPoints::new(rx_points))
        .name("Download (RX)")
        .fill(0.0)
        .color(egui::Color32::from_rgb(100, 200, 255));

    let tx_line = Line::new(PlotPoints::new(tx_points))
        .name("Upload (TX)")
        .fill(0.0)
        .color(egui::Color32::from_rgb(255, 100, 100));

    Plot::new("GlobalThroughput")
        .legend(Legend::default())
        .view_aspect(2.5) // wide aspect ratio
        .y_axis_formatter(|mark, _val_range| human_bytes::human_bytes(mark.value).into())
        .show(ui, |plot_ui| {
            plot_ui.line(rx_line);
            plot_ui.line(tx_line);
        });
}
