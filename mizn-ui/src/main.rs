use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use mizn_common::ipc::{IpcState, IpcCommand};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span, Text},
    widgets::{
        Axis, Block, BorderType, Borders, Cell, Chart, Dataset, GraphType, List, ListItem,
        Paragraph, Row, Table,
    },
};
use std::{collections::VecDeque, io, time::Duration};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

// Color Palette

const C_ACCENT:     Color = Color::Rgb(50,  200, 160); // teal/mint — primary accent
const C_ACCENT2:    Color = Color::Rgb(220, 80,  220); // magenta   — TX / secondary
const C_BORDER:     Color = Color::Rgb(60,  80,  90);  // dim slate — borders
const C_TITLE:      Color = Color::Rgb(120, 200, 220); // sky blue  — panel titles
const C_LABEL:      Color = Color::Rgb(200, 200, 200); // offwhite  — labels
const C_DIM:        Color = Color::Rgb(80,  90,  100); // dark grey — dim text
const C_ALERT:      Color = Color::Rgb(240, 80,  80);  // bright red — alerts
const C_WARN:       Color = Color::Rgb(240, 190, 50);  // amber     — warnings
const C_GREEN:      Color = Color::Rgb(60,  220, 120); // green     — RX flows
const C_BLOCKED:    Color = Color::Rgb(180, 40,  40);  // deep red  — blocked ips

// Types

struct AppState {
    telemetry:         IpcState,
    alerts:            VecDeque<String>,
    blocked_ips:       VecDeque<String>,
    iface:             String,
}

impl AppState {
    fn new() -> Self {
        let iface = std::env::var("MIZN_IFACE").unwrap_or_else(|_| {
            std::fs::read_dir("/sys/class/net")
                .ok()
                .and_then(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .filter(|n| n != "lo")
                        .find(|n| {
                            std::fs::read_to_string(format!("/sys/class/net/{}/operstate", n))
                                .map(|s| s.trim() == "up")
                                .unwrap_or(false)
                        })
                })
                .unwrap_or_else(|| "unknown".to_string())
        });

        Self {
            telemetry: IpcState::default(),
            alerts:     VecDeque::with_capacity(32),
            blocked_ips: VecDeque::with_capacity(64),
            iface,
        }
    }

    fn ingest(&mut self, new_state: IpcState) {
        for pm in new_state.active_process_telemetry.values() {
            let syn_no_ack = (pm.tcp_flags & 0x02 != 0) && (pm.tcp_flags & 0x10 == 0);
            if syn_no_ack {
                let msg = format!("  Port Scan Detected: {} (PID {})", pm.process_nomenclature, pm.process_identifier);
                if !self.alerts.contains(&msg) {
                    if self.alerts.len() >= 32 { self.alerts.pop_front(); }
                    self.alerts.push_back(msg);
                }
            }
            let high_bw = (pm.transmission_rate_bytes_per_second + pm.reception_rate_bytes_per_second) > 52_428_800;
            if high_bw {
                let msg = format!(" High Bandwidth: {} (PID {})", pm.process_nomenclature, pm.process_identifier);
                if !self.alerts.contains(&msg) {
                    if self.alerts.len() >= 32 { self.alerts.pop_front(); }
                    self.alerts.push_back(msg);
                }
            }
        }
        self.telemetry = new_state;
    }

    fn record_block(&mut self, ip: u32) {
        let addr = std::net::Ipv4Addr::from(ip.to_be());
        let entry = format!("  {}", addr);
        if self.blocked_ips.len() >= 64 { self.blocked_ips.pop_front(); }
        self.blocked_ips.push_back(entry);
    }
}

//  main

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut unix_stream = match UnixStream::connect("/run/miznd.sock").await {
        Ok(s)  => s,
        Err(_) => {
            eprintln!("[mizn-ui] Cannot connect to /run/miznd.sock. Is miznd running?");
            std::process::exit(1);
        }
    };

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut payload_buf = [0u8; 4];
    let mut state_buf   = vec![0u8; 1024 * 1024];
    let mut app         = AppState::new();

    loop {
        if unix_stream.read_exact(&mut payload_buf).await.is_ok() {
            let sz = u32::from_be_bytes(payload_buf) as usize;
            if sz > 0 && unix_stream.read_exact(&mut state_buf[..sz]).await.is_ok() {
                let archived = unsafe { rkyv::archived_root::<IpcState>(&state_buf[..sz]) };
                if let Ok(state) = rkyv::Deserialize::deserialize(archived, &mut rkyv::Infallible) {
                    app.ingest(state);
                }
            }
        }

        terminal.draw(|f| draw(f, &app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('b') => {
                        if let Some(top) = app.telemetry.active_process_telemetry.values()
                            .max_by_key(|p| p.transmission_rate_bytes_per_second + p.reception_rate_bytes_per_second)
                        {
                            if let Some(ip) = top.last_resolved_remote_peer_ipv4 {
                                send_block_ip(ip);
                                app.record_block(ip);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn send_block_ip(ip: u32) {
    use rkyv::ser::Serializer;
    use std::io::Write;
    if let Ok(mut sock) = std::os::unix::net::UnixStream::connect("/run/miznd_cmd.sock") {
        let cmd = IpcCommand::BlockIp(ip);
        let mut buf     = [0u8; 128];
        let mut scratch = [0u8; 128];
        let mut ser = rkyv::ser::serializers::CompositeSerializer::new(
            rkyv::ser::serializers::BufferSerializer::new(&mut buf),
            rkyv::ser::serializers::BufferScratch::new(&mut scratch),
            rkyv::Infallible,
        );
        if ser.serialize_value(&cmd).is_ok() {
            let len = ser.pos();
            let bytes: Vec<u8> = buf[..len].to_vec();
            let _ = sock.write_all(&bytes);
        }
    }
}

//Draw Routines

fn draw(f: &mut ratatui::Frame, app: &AppState) {
    let area = f.area();

    // Root layout: Header | Graph | [Table | Security] | Footer
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),   // 0: header bar
            Constraint::Length(10),  // 1: throughput graph
            Constraint::Min(8),      // 2: table + security
            Constraint::Length(3),   // 3: footer / keybind bar
        ])
        .split(area);

    draw_header(f, app, root[0]);
    draw_throughput_graph(f, app, root[1]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(root[2]);

    draw_process_table(f, app, bottom[0]);
    draw_security_panel(f, app, bottom[1]);
    draw_footer(f, root[3]);
}

// Header

fn draw_header(f: &mut ratatui::Frame, app: &AppState, area: Rect) {
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

// Throughput Graph

fn draw_throughput_graph(f: &mut ratatui::Frame, app: &AppState, area: Rect) {
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

// Process Table

fn draw_process_table(f: &mut ratatui::Frame, app: &AppState, area: Rect) {
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

        // TCP flags string
        let flags = fmt_tcp_flags(pm.tcp_flags);

        // SNI or dest IP
        let sni = if pm.sni.is_empty() {
            pm.last_resolved_remote_peer_ipv4
                .map(|ip| std::net::Ipv4Addr::from(ip.to_be()).to_string())
                .unwrap_or_default()
        } else {
            pm.sni.chars().take(20).collect()
        };

        Row::new(vec![
            Cell::from(pm.process_identifier.to_string())
                .style(Style::default().fg(C_DIM)),
            Cell::from(format!("{}{}", pm.process_nomenclature, name_suffix))
                .style(row_style),
            Cell::from(format_bytes(pm.reception_rate_bytes_per_second))
                .style(Style::default().fg(C_GREEN)),
            Cell::from(format_bytes(pm.transmission_rate_bytes_per_second))
                .style(Style::default().fg(C_ACCENT2)),
            Cell::from(format_bytes(total))
                .style(Style::default().fg(C_ACCENT)),
            Cell::from(sni)
                .style(Style::default().fg(C_DIM)),
            Cell::from(flags)
                .style(Style::default().fg(C_WARN)),
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
    .header(
        Row::new(["PID", "BINARY", "RX/s", "TX/s", "TOTAL", "SNI / DEST", "FLAGS"])
            .style(Style::default().fg(C_TITLE).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
    )
    .block(
        Block::default()
            .title(Span::styled("  PROCESS & CONNECTION MONITOR ", Style::default().fg(C_TITLE).add_modifier(Modifier::BOLD)))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_BORDER)),
    )
    .column_spacing(1);

    f.render_widget(table, area);
}

// Security & Threat Intel Panel

fn draw_security_panel(f: &mut ratatui::Frame, app: &AppState, area: Rect) {
    let halves = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    // Active alerts
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

    // Sub-panel B: XDP Firewall / Blocked IPs
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

// Footer

fn draw_footer(f: &mut ratatui::Frame, area: Rect) {
    let spans = Line::from(vec![
        Span::styled("  [Q] ", Style::default().fg(C_TITLE).add_modifier(Modifier::BOLD)),
        Span::styled("Quit  ", Style::default().fg(C_LABEL)),
        Span::styled("[B] ", Style::default().fg(C_TITLE).add_modifier(Modifier::BOLD)),
        Span::styled("Block Top IP  ", Style::default().fg(C_LABEL)),
        Span::styled("MIZN", Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(" · kernel agent active ", Style::default().fg(C_DIM)),
    ]);

    let footer = Paragraph::new(Text::from(spans))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(C_BORDER)),
        );
    f.render_widget(footer, area);
}

// Helpers

fn format_bytes(bytes: u64) -> String {
    const G: f64 = 1_073_741_824.0;
    const M: f64 = 1_048_576.0;
    const K: f64 = 1024.0;
    if bytes >= 1_073_741_824 {
        format!("{:.2} GB", bytes as f64 / G)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / M)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / K)
    } else {
        format!("{} B", bytes)
    }
}

fn fmt_tcp_flags(flags: u8) -> String {
    let mut s = String::with_capacity(8);
    if flags & 0x01 != 0 { s.push_str("FIN "); }
    if flags & 0x02 != 0 { s.push_str("SYN "); }
    if flags & 0x04 != 0 { s.push_str("RST "); }
    if flags & 0x08 != 0 { s.push_str("PSH "); }
    if flags & 0x10 != 0 { s.push_str("ACK "); }
    if flags & 0x20 != 0 { s.push_str("URG "); }
    s.trim_end().to_string()
}
