use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, BorderType, Borders, Cell, Row, Table},
    Frame,
};
use crate::app::AppState;
use crate::config::{C_TITLE, C_BORDER, C_DIM, C_GREEN, C_ACCENT2, C_ACCENT, C_WARN, C_ALERT, C_LABEL};
use crate::utils::{format_bytes, fmt_tcp_flags};

pub fn draw_process_table(f: &mut Frame, app: &AppState, area: Rect) {
    const WATCHLIST: &[&str] = &["sshd", "nginx", "systemd"];
    let t = &app.telemetry;
    let mut procs: Vec<_> = t.active_process_telemetry.values().collect();

    procs.sort_by(|a, b| {
        let aw = WATCHLIST.contains(&a.process_nomenclature.as_str());
        let bw = WATCHLIST.contains(&b.process_nomenclature.as_str());
        if aw && !bw { return std::cmp::Ordering::Less; }
        if bw && !aw { return std::cmp::Ordering::Greater; }
        let bv = b.transmission_rate_bytes_per_second + b.reception_rate_bytes_per_second;
        let av = a.transmission_rate_bytes_per_second + a.reception_rate_bytes_per_second;
        bv.cmp(&av)
    });

    let max_rows = area.height.saturating_sub(4) as usize;
    let rows: Vec<Row> = procs.iter().take(max_rows).map(|pm| {
        let total = pm.transmission_rate_bytes_per_second + pm.reception_rate_bytes_per_second;
        let syn_scan = (pm.tcp_flags & 0x02 != 0) && (pm.tcp_flags & 0x10 == 0);

        let name_suffix = if syn_scan {
            " ⚠ SYN SCAN".to_string()
        } else if WATCHLIST.contains(&pm.process_nomenclature.as_str()) {
            " ★ WATCH".to_string()
        } else {
            String::new()
        };

        let row_style = if syn_scan {
            Style::default().fg(C_ALERT).add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else if total > 52_428_800 {
            Style::default().fg(C_WARN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_LABEL)
        };

        let flags = fmt_tcp_flags(pm.tcp_flags);
        let sni = if pm.sni.is_empty() {
            pm.last_resolved_remote_peer_ipv4.map(|ip| std::net::Ipv4Addr::from(ip.to_be()).to_string()).unwrap_or_default()
        } else {
            pm.sni.chars().take(20).collect()
        };

        Row::new(vec![
            Cell::from(pm.process_identifier.to_string()).style(Style::default().fg(C_DIM)),
            Cell::from(format!("{}{}", pm.process_nomenclature, name_suffix)).style(row_style),
            Cell::from(format_bytes(pm.reception_rate_bytes_per_second)).style(Style::default().fg(C_GREEN)),
            Cell::from(format_bytes(pm.transmission_rate_bytes_per_second)).style(Style::default().fg(C_ACCENT2)),
            Cell::from(format_bytes(total)).style(Style::default().fg(C_ACCENT)),
            Cell::from(sni).style(Style::default().fg(C_DIM)),
            Cell::from(flags).style(Style::default().fg(C_WARN)),
        ])
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Min(16),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(20),
            Constraint::Length(8),
        ],
    )
    .header(Row::new(["PID", "BINARY", "RX/s", "TX/s", "TOTAL", "SNI / DEST", "FLAGS"])
            .style(Style::default().fg(C_TITLE).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)))
    .block(Block::default()
            .title("  PROCESS & CONNECTION MONITOR ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_BORDER)))
    .column_spacing(1);

    f.render_widget(table, area);
}
