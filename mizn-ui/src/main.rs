use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{io, time::Duration};
use mizn_common::ipc::IpcState;

mod app;
mod config;
mod draw;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut unix_stream = match UnixStream::connect("/run/miznd.sock").await {
        Ok(s)  => s,
        Err(_) => std::process::exit(1),
    };

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut payload_buf = [0u8; 4];
    let mut state_buf   = vec![0u8; 1024 * 1024];
    let mut app         = app::AppState::new();

    loop {
        if unix_stream.read_exact(&mut payload_buf).await.is_ok() {
            let sz = u32::from_be_bytes(payload_buf) as usize;
            if sz > 0 && unix_stream.read_exact(&mut state_buf[..sz]).await.is_ok() {
                let archived = unsafe { rkyv::archived_root::<IpcState>(&state_buf[..sz]) };
                let state: IpcState = rkyv::Deserialize::deserialize(archived, &mut rkyv::Infallible).unwrap();
                app.ingest(state);
            }
        }

        terminal.draw(|f| draw::draw(f, &app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('b') => app.block_top_ip(),
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
