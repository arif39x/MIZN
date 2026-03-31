use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    symbols,
    text::Span,
    widgets::{Axis, Block, BorderType, Borders, Chart, Dataset, GraphType},
    Frame,
};
use crate::app::AppState;
use crate::config::{C_TITLE, C_BORDER, C_DIM, C_GREEN, C_ACCENT2, C_LABEL};
use crate::utils::format_bytes;

pub fn draw_throughput_graph(f: &mut Frame, app: &AppState, area: Rect) {
    let t = &app.telemetry;
    let cursor = t.history_ring_buffer_cursor;

    let mut rx_data = Vec::with_capacity(60);
    let mut tx_data = Vec::with_capacity(60);
    let mut peak = 1.0_f64;

    for i in 0..60 {
        let idx = (cursor + i) % 60;
        let rx = t.reception_history_ring_buffer[idx] as f64;
        let tx = t.transmission_history_ring_buffer[idx] as f64;
        rx_data.push((i as f64, rx));
        tx_data.push((i as f64, tx));
        if rx > peak { peak = rx; }
        if tx > peak { peak = tx; }
    }

    let chart = Chart::new(vec![
        Dataset::default()
            .name("RX")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(C_GREEN))
            .data(&rx_data),
        Dataset::default()
            .name("TX")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(C_ACCENT2))
            .data(&tx_data),
    ])
    .block(
        Block::default()
            .title(Span::styled("  THROUGHPUT  60s ", Style::default().fg(C_TITLE).add_modifier(Modifier::BOLD)))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_BORDER)),
    )
    .x_axis(
        Axis::default()
            .style(Style::default().fg(C_DIM))
            .bounds([0.0, 59.0])
            .labels(vec![
                Span::styled("-60s", Style::default().fg(C_DIM)),
                Span::styled(" now", Style::default().fg(C_DIM)),
            ]),
    )
    .y_axis(
        Axis::default()
            .style(Style::default().fg(C_DIM))
            .bounds([0.0, peak * 1.15])
            .labels(vec![
                Span::raw("0"),
                Span::styled(format_bytes(peak as u64), Style::default().fg(C_LABEL)),
            ]),
    );

    f.render_widget(chart, area);
}
