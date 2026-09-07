use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use mizn_common::ipc::{IPC_STATE_MAX_FRAME_SIZE, IpcState};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{io, time::Duration};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

mod app;
mod config;
mod draw;
mod utils;

fn decode_state(bytes: &[u8]) -> Result<IpcState, String> {
    let archived = rkyv::check_archived_root::<IpcState>(bytes)
        .map_err(|error| format!("validation failed: {error}"))?;
    rkyv::Deserialize::deserialize(archived, &mut rkyv::Infallible)
        .map_err(|error| format!("deserialization failed: {error:?}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut unix_stream = match UnixStream::connect("/run/miznd.sock").await {
        Ok(s) => s,
        Err(_) => std::process::exit(1),
    };

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut payload_buf = [0u8; 4];
    let mut state_buf = vec![0u8; IPC_STATE_MAX_FRAME_SIZE];
    let mut app = app::AppState::new();

    loop {
        if unix_stream.read_exact(&mut payload_buf).await.is_ok() {
            let sz = u32::from_be_bytes(payload_buf) as usize;
            if sz == 0 || sz > IPC_STATE_MAX_FRAME_SIZE {
                eprintln!("[mizn] rejecting invalid telemetry frame length: {sz}");
                continue;
            }

            if unix_stream.read_exact(&mut state_buf[..sz]).await.is_ok() {
                match decode_state(&state_buf[..sz]) {
                    Ok(state) => app.ingest(state),
                    Err(error) => eprintln!("[mizn] rejecting telemetry frame: {error}"),
                }
            }
        }

        terminal.draw(|f| draw::draw(f, &app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('b') => app.block_top_ip(),
                    KeyCode::Char('1') => app.view_mode = app::ViewMode::Default,
                    KeyCode::Char('2') => app.view_mode = app::ViewMode::Table,
                    KeyCode::Char('3') => app.view_mode = app::ViewMode::Graph,
                    KeyCode::Up => app.move_up(),
                    KeyCode::Down => app.move_down(),
                    KeyCode::Char('k') | KeyCode::Char('K') => app.kill_selected(),
                    KeyCode::Char('d') | KeyCode::Char('D') => app.drop_selected(),
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::decode_state;

    #[test]
    fn rejects_malformed_telemetry_without_panicking() {
        assert!(decode_state(&[0; 8]).is_err());
    }
}
