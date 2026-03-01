use crate::state::State;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use parking_lot::RwLock;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};
use std::{io, sync::Arc, time::Duration};

pub async fn run(state: Arc<RwLock<State>>) -> Result<(), io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(5),
                    Constraint::Length(8),
                    Constraint::Length(3),
                ])
                .split(f.area());

            let st = state.read();
            let up = st.start_time.elapsed().as_secs();

            let header_text = format!(
                " SYSTEM: [D: {}/s] [U: {}/s]      UPTIME: {:02}:{:02}:{:02}",
                format_bytes(st.total_rate_recv_bps),
                format_bytes(st.total_rate_sent_bps),
                up / 3600,
                (up / 60) % 60,
                up % 60
            );
            let header = Paragraph::new(header_text).block(
                Block::default()
                    .title(" [SIRR - ACTIVE MONITOR] ")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            );
            f.render_widget(header, chunks[0]);

            let mut rows = vec![];
            let mut procs: Vec<_> = st.process_metrics.values().collect();
            procs.sort_by(|a, b| {
                let s_b = b.current_rate_sent_bps + b.current_rate_recv_bps;
                let s_a = a.current_rate_sent_bps + a.current_rate_recv_bps;
                s_b.cmp(&s_a)
            });

            for p in procs.iter().take(20) {
                let speed = p.current_rate_sent_bps + p.current_rate_recv_bps;
                let dir = if p.current_rate_sent_bps > p.current_rate_recv_bps {
                    "SEND"
                } else {
                    "RECV"
                };
                let color = if speed > 10_000_000 {
                    Color::Red
                } else if speed > 1_000_000 {
                    Color::Yellow
                } else {
                    Color::Green
                };

                rows.push(Row::new(vec![
                    Cell::from(p.pid.to_string()),
                    Cell::from(p.name.clone()).style(Style::default().fg(Color::Cyan)),
                    Cell::from(dir),
                    Cell::from(p.last_remote_addr.clone()),
                    Cell::from(format_bytes(speed)).style(Style::default().fg(color)),
                ]));
            }

            let table = Table::new(
                rows,
                [
                    Constraint::Length(8),
                    Constraint::Min(15),
                    Constraint::Length(6),
                    Constraint::Length(25),
                    Constraint::Length(15),
                ],
            )
            .header(
                Row::new(vec!["PID", "PROCESS", "DIR", "REMOTE ADDR", "SPEED"])
                    .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(table, chunks[1]);

            let max_val = *st.graph_sent.iter().max().unwrap_or(&1).max(st.graph_recv.iter().max().unwrap_or(&1));
            let max_val = std::cmp::max(max_val, 1);
            let mut graph_str = String::from("  TRAFFIC GRAPH (LAST 60 SECONDS)\n\n");
            graph_str.push_str(&format!("  MAX: {}/s\n", format_bytes(max_val)));
            let avg_s: u64 = if st.graph_sent.is_empty() { 0 } else { st.graph_sent.iter().sum::<u64>() / st.graph_sent.len() as u64 };
            let avg_r: u64 = if st.graph_recv.is_empty() { 0 } else { st.graph_recv.iter().sum::<u64>() / st.graph_recv.len() as u64 };
            graph_str.push_str(&format!("  AVG DOWN: {}/s | AVG UP: {}/s\n", format_bytes(avg_r), format_bytes(avg_s)));

            let graph = Paragraph::new(graph_str).block(Block::default().borders(Borders::ALL));
            f.render_widget(graph, chunks[2]);

            let footer = Paragraph::new(" [ESC] Exit | [TAB] Switch View ")
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(footer, chunks[3]);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn format_bytes(b: u64) -> String {
    if b >= 1_048_576 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{} B", b)
    }
}
