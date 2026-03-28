use ratatui::{layout::{Constraint, Direction, Layout}, Frame};
use crate::app::AppState;

mod header;
mod graph;
mod table;
mod security;

pub fn draw(f: &mut Frame, app: &AppState) {
    let area = f.area();

    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(10),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    header::draw_header(f, app, root[0]);
    graph::draw_throughput_graph(f, app, root[1]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(root[2]);

    table::draw_process_table(f, app, bottom[0]);
    security::draw_security_panel(f, app, bottom[1]);
    draw_footer(f, root[3]);
}

fn draw_footer(f: &mut ratatui::Frame, area: ratatui::layout::Rect) {
    use ratatui::widgets::{Block, Borders, BorderType, Paragraph};
    use ratatui::layout::Alignment;
    use ratatui::text::{Line, Span, Text};
    use ratatui::style::{Style, Modifier};
    use crate::config::{C_TITLE, C_LABEL, C_ACCENT, C_DIM, C_BORDER};

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
