use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use mizn_common::ipc::IpcState;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    symbols,
    text::Span,
    widgets::{
        Axis, Block, BorderType, Borders, Cell, Chart, Dataset, GraphType, Paragraph,
        Row, Table,
    },
};
use std::{io, time::Duration};

const MIZN_STATIC_BANNER_RODATA: &str = r#"
░█▄█░▀█▀░▀▀█░█▀█
░█░█░░█░░▄▀░░█░█
░▀░▀░▀▀▀░▀▀▀░▀░▀
"#;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut unix_stream = match UnixStream::connect("/run/miznd.sock").await {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Failed to connect to /run/miznd.sock. Ensure miznd is running.");
            std::process::exit(1);
        }
    };

    enable_raw_mode()?;
    let mut standard_output_handle = io::stdout();
    execute!(standard_output_handle, EnterAlternateScreen)?;
    let terminal_backend = CrosstermBackend::new(standard_output_handle);
    let mut user_interface_terminal = Terminal::new(terminal_backend)?;

    let mut telemetry_snapshot = IpcState::default();
    let mut payload_size_buffer = [0u8; 4];
    let mut state_buffer = vec![0u8; 1024 * 1024];

    loop {
        if unix_stream.read_exact(&mut payload_size_buffer).await.is_ok() {
            let encoded_size = u32::from_be_bytes(payload_size_buffer) as usize;

            if encoded_size > 0 && unix_stream.read_exact(&mut state_buffer[..encoded_size]).await.is_ok() {
                let archived = unsafe {
                    rkyv::archived_root::<IpcState>(&state_buffer[..encoded_size])
                };

                telemetry_snapshot = rkyv::Deserialize::deserialize(archived, &mut rkyv::Infallible)
                    .expect("Infallible deserialization cannot fail");
            }
        }

        user_interface_terminal.draw(|render_frame| {
            let base_canvas = render_frame.area();

            let primary_vertical_partitions = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(6),
                    Constraint::Length(3),
                    Constraint::Min(10),
                    Constraint::Length(3),
                ])
                .split(base_canvas);

            let banner_widget = Paragraph::new(MIZN_STATIC_BANNER_RODATA)
                .style(Style::default().fg(Color::Rgb(200, 0, 0)).add_modifier(Modifier::BOLD))
                .alignment(Alignment::Center);
            render_frame.render_widget(banner_widget, primary_vertical_partitions[0]);

            let dashboard_header_content = format!(
                " ▶ MIZN NETWORK METRICS | RX: {:>10}/s | TX: {:>10}/s | PEAK: {:>10}/s ",
                format_bytes(telemetry_snapshot.aggregate_reception_rate_bytes_per_second),
                format_bytes(telemetry_snapshot.aggregate_transmission_rate_bytes_per_second),
                format_bytes(telemetry_snapshot.global_peak_throughput_bytes_per_second),
            );

            let header_widget = Paragraph::new(dashboard_header_content).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Thick)
                    .border_style(Style::default().fg(Color::Rgb(180, 0, 0))),
            ).style(Style::default().fg(Color::Rgb(255, 80, 80)).add_modifier(Modifier::BOLD));
            render_frame.render_widget(header_widget, primary_vertical_partitions[1]);

            let core_dashboard_partitions = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(primary_vertical_partitions[2]);

            let mut process_telemetry_vector: Vec<_> = telemetry_snapshot.active_process_telemetry.values().collect();
            process_telemetry_vector.sort_by(|alpha, beta| {
                let beta_throughput = beta.transmission_rate_bytes_per_second + beta.reception_rate_bytes_per_second;
                let alpha_throughput = alpha.transmission_rate_bytes_per_second + alpha.reception_rate_bytes_per_second;
                beta_throughput.cmp(&alpha_throughput)
            });

            let mut process_table_rows = Vec::with_capacity(process_telemetry_vector.len());
            for process_metric in process_telemetry_vector.iter().take(core_dashboard_partitions[0].height.saturating_sub(4) as usize) {
                let combined_throughput = process_metric.transmission_rate_bytes_per_second + process_metric.reception_rate_bytes_per_second;

                let dynamic_style = if combined_throughput > 10_485_760 {
                    Style::default().fg(Color::Rgb(255, 30, 30)).add_modifier(Modifier::BOLD | Modifier::RAPID_BLINK)
                } else {
                    Style::default().fg(Color::Rgb(160, 0, 0))
                };

                process_table_rows.push(Row::new(vec![
                    Cell::from(process_metric.process_identifier.to_string()).style(Style::default().fg(Color::Rgb(80, 0, 0))),
                    Cell::from(process_metric.process_nomenclature.clone()).style(Style::default().fg(Color::Rgb(255, 120, 120)).add_modifier(Modifier::BOLD)),
                    Cell::from(format_bytes(process_metric.reception_rate_bytes_per_second)).style(Style::default().fg(Color::Rgb(220, 50, 50))),
                    Cell::from(format_bytes(process_metric.transmission_rate_bytes_per_second)).style(Style::default().fg(Color::Rgb(180, 0, 0))),
                    Cell::from(format_bytes(combined_throughput)).style(dynamic_style),
                ]));
            }

            let connection_table = Table::new(
                process_table_rows,
                [
                    Constraint::Length(7),
                    Constraint::Min(15),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Length(12),
                ],
            )
            .header(Row::new(vec!["PID", "BINARY", "RX", "TX", "BANDWIDTH"]).style(Style::default().fg(Color::Rgb(255, 60, 60)).add_modifier(Modifier::BOLD)))
            .block(Block::default().title(" LIVE SOCKET TOPOLOGY ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::Rgb(120, 0, 0))))
            .column_spacing(2);

            render_frame.render_widget(connection_table, core_dashboard_partitions[0]);

            let buffer_cursor = telemetry_snapshot.history_ring_buffer_cursor;
            let mut rx_series = Vec::with_capacity(60);
            let mut tx_series = Vec::with_capacity(60);
            let mut peak = 0.0_f64;

            for i in 0..60 {
                let idx = (buffer_cursor + i) % 60;
                let rx = telemetry_snapshot.reception_history_ring_buffer[idx] as f64;
                let tx = telemetry_snapshot.transmission_history_ring_buffer[idx] as f64;
                rx_series.push((i as f64, rx));
                tx_series.push((i as f64, tx));
                if rx > peak { peak = rx; }
                if tx > peak { peak = tx; }
            }

            let chart = Chart::new(vec![
                Dataset::default().name("RX").marker(symbols::Marker::Braille).graph_type(GraphType::Line).style(Style::default().fg(Color::Rgb(255, 80, 80))).data(&rx_series),
                Dataset::default().name("TX").marker(symbols::Marker::Braille).graph_type(GraphType::Line).style(Style::default().fg(Color::Rgb(160, 0, 0))).data(&tx_series),
            ])
            .block(Block::default().title(" THROUGHPUT HISTORY ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::Rgb(120, 0, 0))))
            .x_axis(Axis::default().style(Style::default().fg(Color::Rgb(80, 0, 0))).bounds([0.0, 59.0]))
            .y_axis(Axis::default().style(Style::default().fg(Color::Rgb(80, 0, 0))).bounds([0.0, peak * 1.1]).labels(vec![Span::raw("0"), Span::styled(format_bytes(peak as u64), Style::default().fg(Color::Rgb(255, 60, 60)).add_modifier(Modifier::BOLD))]));

            render_frame.render_widget(chart, core_dashboard_partitions[1]);

            let footer = Paragraph::new(" [Q] EXIT | MIZN KERNEL AGENT ACTIVE ")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Rgb(200, 0, 0)).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).border_type(BorderType::Thick).border_style(Style::default().fg(Color::Rgb(140, 0, 0))));
            render_frame.render_widget(footer, primary_vertical_partitions[3]);
        })?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc { break; }
            }
        }
    }

    disable_raw_mode()?;
        execute!(user_interface_terminal.backend_mut(), LeaveAlternateScreen)?;
        Ok(())
    }

    fn format_bytes(bytes: u64) -> String {
        const GIBIBYTE: f64 = 1_073_741_824.0;
        const MEBIBYTE: f64 = 1_048_576.0;
        const KIBIBYTE: f64 = 1024.0;

        if bytes >= 1_073_741_824 {
            format!("{:.2} GB", bytes as f64 / GIBIBYTE)
        } else if bytes >= 1_048_576 {
            format!("{:.1} MB", bytes as f64 / MEBIBYTE)
        } else if bytes >= 1024 {
            format!("{:.1} KB", bytes as f64 / KIBIBYTE)
        } else {
            format!("{} B", bytes)
        }
    }
