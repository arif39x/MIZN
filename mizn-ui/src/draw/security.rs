use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::Span,
    widgets::{Block, BorderType, Borders, List, ListItem},
    Frame,
};
use crate::app::AppState;
use crate::config::{C_ALERT, C_BORDER, C_DIM, C_BLOCKED};

pub fn draw_security_panel(f: &mut Frame, app: &AppState, area: Rect) {
    let halves = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let alert_items: Vec<ListItem> = if app.alerts.is_empty() {
        vec![ListItem::new(Span::styled("    No anomalies detected", Style::default().fg(C_DIM)))]
    } else {
        app.alerts.iter().rev().take(halves[0].height.saturating_sub(3) as usize).map(|msg| {
            ListItem::new(Span::styled(format!("  {}", msg), Style::default().fg(C_ALERT)))
        }).collect()
    };

    let alert_list = List::new(alert_items)
        .block(
            Block::default()
                .title(Span::styled("   ACTIVE ALERTS ", Style::default().fg(C_ALERT).add_modifier(Modifier::BOLD)))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(C_BORDER)),
        );
    f.render_widget(alert_list, halves[0]);

    let blocked_items: Vec<ListItem> = if app.blocked_ips.is_empty() {
        vec![ListItem::new(Span::styled("    No blocked IPs — press [B] to drop top host", Style::default().fg(C_DIM)))]
    } else {
        app.blocked_ips.iter().rev().take(halves[1].height.saturating_sub(3) as usize).map(|entry| {
            ListItem::new(Span::styled(format!("  {}", entry), Style::default().fg(C_BLOCKED).add_modifier(Modifier::BOLD)))
        }).collect()
    };

    let blocked_list = List::new(blocked_items)
        .block(
            Block::default()
                .title(Span::styled("  XDP FIREWALL — BLOCKED IPs ", Style::default().fg(C_BLOCKED).add_modifier(Modifier::BOLD)))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(C_BORDER)),
        );
    f.render_widget(blocked_list, halves[1]);
}
