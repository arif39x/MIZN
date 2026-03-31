use ratatui::{layout::{Constraint, Direction, Layout}, Frame};
use crate::app::AppState;

mod header;
mod graph;
mod table;
mod security;

pub fn draw(f: &mut Frame, app: &AppState) {
    let area = f.area();

    match app.view_mode {
        crate::app::ViewMode::Default => {
            let root = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(4), Constraint::Min(10), Constraint::Percentage(20), Constraint::Length(3)])
                .split(area);
            header::draw_header(f, app, root[0]);
            let middle = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(root[1]);
            graph::draw_throughput_graph(f, app, middle[0]);
            table::draw_process_table(f, app, middle[1]);
            security::draw_security_panel(f, app, root[2]);
            draw_footer(f, root[3]);
        }
        crate::app::ViewMode::Table => {
            let root = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(4), Constraint::Min(10), Constraint::Length(3)])
                .split(area);
            header::draw_header(f, app, root[0]);
            table::draw_process_table(f, app, root[1]);
            draw_footer(f, root[2]);
        }
        crate::app::ViewMode::Graph => {
            let root = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(4), Constraint::Min(10), Constraint::Length(3)])
                .split(area);
            header::draw_header(f, app, root[0]);
            graph::draw_throughput_graph(f, app, root[1]);
            draw_footer(f, root[2]);
        }
    }

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
