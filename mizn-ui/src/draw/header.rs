use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};
use crate::app::AppState;
use crate::config::{C_BORDER, C_DIM, C_GREEN, C_ACCENT2, C_WARN, C_TITLE};
use crate::utils::format_bytes;

pub fn draw_header(f: &mut Frame, app: &AppState, area: Rect) {
    let t = &app.telemetry;

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    let border_style = Style::default().fg(C_BORDER);
    let make_block = Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(border_style);

    let rx_text = Text::from(vec![
        Line::from(Span::styled("  ↓ RX / s", Style::default().fg(C_DIM))),
        Line::from(Span::styled(format_bytes(t.aggregate_reception_rate_bytes_per_second), Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD))),
    ]);
    f.render_widget(Paragraph::new(rx_text).alignment(Alignment::Center).block(make_block.clone()), cols[0]);

    let tx_text = Text::from(vec![
        Line::from(Span::styled("  ↑ TX / s", Style::default().fg(C_DIM))),
        Line::from(Span::styled(format_bytes(t.aggregate_transmission_rate_bytes_per_second), Style::default().fg(C_ACCENT2).add_modifier(Modifier::BOLD))),
    ]);
    f.render_widget(Paragraph::new(tx_text).alignment(Alignment::Center).block(make_block.clone()), cols[1]);

    let peak_text = Text::from(vec![
        Line::from(Span::styled("   PEAK", Style::default().fg(C_DIM))),
        Line::from(Span::styled(format_bytes(t.global_peak_throughput_bytes_per_second), Style::default().fg(C_WARN).add_modifier(Modifier::BOLD))),
    ]);
    f.render_widget(Paragraph::new(peak_text).alignment(Alignment::Center).block(make_block.clone()), cols[2]);

    let iface_text = Text::from(vec![
        Line::from(Span::styled("   INTERFACE", Style::default().fg(C_DIM))),
        Line::from(Span::styled(app.iface.clone(), Style::default().fg(C_TITLE).add_modifier(Modifier::BOLD))),
    ]);
    f.render_widget(Paragraph::new(iface_text).alignment(Alignment::Center).block(make_block.clone()), cols[3]);
}
