use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use mizn_common::ipc::IpcState;
use rusqlite::Connection;

#[derive(Clone)]
pub struct AppState {
    pub live_telemetry: Arc<RwLock<IpcState>>,
    pub db_pool: Arc<Mutex<Option<Connection>>>, // Fallback if no pool
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            live_telemetry: Arc::new(RwLock::new(IpcState::default())),
            db_pool: Arc::new(Mutex::new(None)),
        }
    }
}

use std::sync::Mutex;

impl AppState {
    pub fn new(ctx: eframe::egui::Context) -> Self {
        let state = Self::default();
        
        // Open read-only SQLite WAL connection
        let db_path = "/home/miku/Desktop/MIZN/miznd_telemetry.db"; // Better to pass via env/args, using local for now
        if let Ok(conn) = Connection::open_with_flags(
            "../miznd_telemetry.db",
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        ) {
            *state.db_pool.lock().unwrap() = Some(conn);
        }

        let telemetry_clone = state.live_telemetry.clone();
        let ctx_clone = ctx.clone();

        // Spawn a background thread to run the Tokio async loops
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                loop {
                    if let Ok(mut stream) = tokio::net::UnixStream::connect("/run/miznd.sock").await {
                        // Connected, read loop
                        loop {
                            let mut len_buf = [0u8; 4];
                            if stream.read_exact(&mut len_buf).await.is_err() {
                                break;
                            }
                            let len = u32::from_be_bytes(len_buf) as usize;
                            if len > 524288 { break; } // Sanity check

                            let mut payload = vec![0u8; len];
                            if stream.read_exact(&mut payload).await.is_err() {
                                break;
                            }

                            use rkyv::Deserialize;
                            // Deserialize zero-copy
                            let archived = unsafe { rkyv::archived_root::<IpcState>(&payload) };
                            let state: IpcState = rkyv::Deserialize::deserialize(archived, &mut rkyv::Infallible).unwrap();
                            *telemetry_clone.write().unwrap() = state;
                            ctx_clone.request_repaint(); // Trigger UI refresh
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });
        });

        state
    }
}
