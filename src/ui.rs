use crate::state::State;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use parking_lot::RwLock;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    symbols,
    text::Span,
    widgets::{
        Axis, BarChart, Block, BorderType, Borders, Cell, Chart, Dataset, GraphType, Paragraph,
        Row, Table,
    },
};
use std::{io, sync::Arc, time::Duration};

const MIZN_STATIC_BANNER_RODATA: &str = r#"

▄█████  ██  █████▄   █████▄
▀▀▀▄▄▄  ██  ██▄▄██▄  ██▄▄██▄
█████▀  ██  ██   ██  ██   ██
                          "#;

pub async fn run(global_telemetry_state: Arc<RwLock<State>>) -> Result<(), io::Error> {
    enable_raw_mode()?;
    let mut standard_output_handle = io::stdout();
    execute!(standard_output_handle, EnterAlternateScreen)?;
    let terminal_backend = CrosstermBackend::new(standard_output_handle);
    let mut user_interface_terminal = Terminal::new(terminal_backend)?;

    loop {
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

            let banner_widget = Paragraph::new(STATIC_BANNER_RODATA)
                .style(Style::default().fg(Color::Rgb(255, 0, 85)).add_modifier(Modifier::BOLD))
                .alignment(Alignment::Center);
            render_frame.render_widget(banner_widget, primary_vertical_partitions[0]);

            let telemetry_snapshot = global_telemetry_state.read();
            let execution_uptime_seconds = telemetry_snapshot
                .telemetry_initialization_timestamp
                .elapsed()
                .as_secs();

            let dashboard_header_content = format!(
                " \u{25B6} MIZN NETWORK METRICS | INBOUND: {:>10}/s | OUTBOUND: {:>10}/s | PEAK: {:>10}/s | UPTIME: {:02}:{:02}:{:02} ",
                format_bytes(telemetry_snapshot.aggregate_reception_rate_bytes_per_second),
                format_bytes(telemetry_snapshot.aggregate_transmission_rate_bytes_per_second),
                format_bytes(telemetry_snapshot.global_peak_throughput_bytes_per_second),
                execution_uptime_seconds / 3600,
                (execution_uptime_seconds / 60) % 60,
                execution_uptime_seconds % 60,
            );

            let header_widget = Paragraph::new(dashboard_header_content).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Thick)
                    .border_style(Style::default().fg(Color::Rgb(0, 255, 255))),
            ).style(Style::default().fg(Color::Rgb(255, 255, 255)).add_modifier(Modifier::BOLD));
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
                let combined_temporal_throughput = process_metric.transmission_rate_bytes_per_second + process_metric.reception_rate_bytes_per_second;

                let dynamic_intensity_style = if combined_temporal_throughput > 10_485_760 {
                    Style::default().fg(Color::Rgb(255, 0, 85)).add_modifier(Modifier::BOLD)
                } else if combined_temporal_throughput > 1_048_576 {
                    Style::default().fg(Color::Rgb(255, 215, 0))
                } else {
                    Style::default().fg(Color::Rgb(0, 255, 128))
                };

                let remote_peer_string = match process_metric.last_resolved_remote_peer {
                    Some(ip) => ip.to_string(),
                    None => String::from("LISTENING"),
                };

                process_table_rows.push(Row::new(vec![
                    Cell::from(process_metric.process_identifier.to_string()).style(Style::default().fg(Color::DarkGray)),
                    Cell::from(process_metric.process_nomenclature.clone()).style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Cell::from(format_bytes(process_metric.reception_rate_bytes_per_second)).style(Style::default().fg(Color::Rgb(0, 191, 255))),
                    Cell::from(format_bytes(process_metric.transmission_rate_bytes_per_second)).style(Style::default().fg(Color::Rgb(255, 0, 255))),
                    Cell::from(remote_peer_string).style(Style::default().fg(Color::Rgb(150, 150, 150))),
                    Cell::from(format_bytes(combined_temporal_throughput)).style(dynamic_intensity_style),
                ]));
            }

            let connection_topology_table = Table::new(
                process_table_rows,
                [
                    Constraint::Length(7),
                    Constraint::Min(15),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Length(20),
                    Constraint::Length(12),
                ],
            )
            .header(
                Row::new(vec!["PID", "BINARY", "INBOUND", "OUTBOUND", "TARGET_NODE", "BANDWIDTH"])
                    .style(Style::default().fg(Color::Rgb(0, 255, 255)).add_modifier(Modifier::BOLD))
            )
            .block(Block::default().title(" LIVE SOCKET TOPOLOGY ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)))
            .column_spacing(2);

            render_frame.render_widget(connection_topology_table, core_dashboard_partitions[0]);

            let analytics_partitions = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(core_dashboard_partitions[1]);

            let buffer_cursor = telemetry_snapshot.history_ring_buffer_cursor;
            let mut inbound_temporal_series = Vec::with_capacity(60);
            let mut outbound_temporal_series = Vec::with_capacity(60);
            let mut absolute_maximum_throughput = 0.0_f64;

            for time_delta in 0..60 {
                let physical_index = (buffer_cursor + time_delta) % 60;
                let inbound_value = telemetry_snapshot.reception_history_ring_buffer[physical_index] as f64;
                let outbound_value = telemetry_snapshot.transmission_history_ring_buffer[physical_index] as f64;

                inbound_temporal_series.push((time_delta as f64, inbound_value));
                outbound_temporal_series.push((time_delta as f64, outbound_value));

                if inbound_value > absolute_maximum_throughput { absolute_maximum_throughput = inbound_value; }
                if outbound_value > absolute_maximum_throughput { absolute_maximum_throughput = outbound_value; }
            }

            let bandwidth_datasets = vec![
                Dataset::default()
                    .name("INBOUND (RX)")
                    .marker(symbols::Marker::Braille)
                    .graph_type(GraphType::Line)
                    .style(Style::default().fg(Color::Rgb(0, 191, 255)))
                    .data(&inbound_temporal_series),
                Dataset::default()
                    .name("OUTBOUND (TX)")
                    .marker(symbols::Marker::Braille)
                    .graph_type(GraphType::Line)
                    .style(Style::default().fg(Color::Rgb(255, 0, 255)))
                    .data(&outbound_temporal_series),
            ];

            let upper_y_bound = if absolute_maximum_throughput < 1024.0 { 1024.0 } else { absolute_maximum_throughput * 1.2 };

            let macroscopic_throughput_chart = Chart::new(bandwidth_datasets)
                .block(Block::default().title(" MACROSCOPIC THROUGHPUT ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)))
                .x_axis(Axis::default().style(Style::default().fg(Color::DarkGray)).bounds([0.0, 59.0]))
                .y_axis(Axis::default().style(Style::default().fg(Color::DarkGray)).bounds([0.0, upper_y_bound]).labels(vec![
                    Span::raw("0 B"),
                    Span::raw(format_bytes(upper_y_bound as u64 / 2)),
                    Span::styled(format_bytes(upper_y_bound as u64), Style::default().fg(Color::Rgb(255, 85, 85)).add_modifier(Modifier::BOLD)),
                ]));

            render_frame.render_widget(macroscopic_throughput_chart, analytics_partitions[0]);

            let mut distribution_data: Vec<(&str, u64)> = process_telemetry_vector
                .iter()
                .take(6)
                .map(|metrics| (metrics.process_nomenclature.as_str(), metrics.transmission_rate_bytes_per_second + metrics.reception_rate_bytes_per_second))
                .collect();

            if distribution_data.is_empty() {
                distribution_data.push(("IDLE", 0));
            }

            let resource_distribution_barchart = BarChart::default()
                .block(Block::default().title(" THREAT & RESOURCE DISTRIBUTION ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)))
                .data(&distribution_data)
                .bar_width(10)
                .bar_gap(2)
                .bar_style(Style::default().fg(Color::Rgb(0, 255, 128)))
                .value_style(Style::default().fg(Color::Black).bg(Color::Rgb(0, 255, 128)).add_modifier(Modifier::BOLD));

            render_frame.render_widget(resource_distribution_barchart, analytics_partitions[1]);

            let interface_footer = Paragraph::new(" [Q] TERMINATE LINK | [F] FREEZE FRAME | [S] SORT METRICS ")
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).border_type(BorderType::Thick).border_style(Style::default().fg(Color::Rgb(0, 255, 255))))
                .style(Style::default().fg(Color::Black).bg(Color::Rgb(0, 255, 255)).add_modifier(Modifier::BOLD));

            render_frame.render_widget(interface_footer, primary_vertical_partitions[3]);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key_stroke) = event::read()? {
                if key_stroke.code == KeyCode::Esc || key_stroke.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(user_interface_terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const KIBIBYTE: u64 = 1024;
    const MEBIBYTE: u64 = KIBIBYTE * 1024;
    const GIBIBYTE: u64 = MEBIBYTE * 1024;

    if bytes >= GIBIBYTE {
        format!("{:.2} GB", bytes as f64 / GIBIBYTE as f64)
    } else if bytes >= MEBIBYTE {
        format!("{:.1} MB", bytes as f64 / MEBIBYTE as f64)
    } else if bytes >= KIBIBYTE {
        format!("{:.1} KB", bytes as f64 / KIBIBYTE as f64)
    } else {
        format!("{} B ", bytes)
    }
}
