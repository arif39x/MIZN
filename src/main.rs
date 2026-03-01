mod ingestion;
mod resolver;
mod state;
mod ui;

use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::mpsc;
use std::time::Duration;
use state::State;
use resolver::SocketsMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (tx, mut rx) = mpsc::unbounded_channel();

    let shared_state = Arc::new(RwLock::new(State::new()));
    let sockets_map = Arc::new(RwLock::new(SocketsMap::new()));

    ingestion::start_sniffing(tx);

    let smap_clone = sockets_map.clone();
    tokio::spawn(async move {
        loop {
            let new_map = resolver::refresh_sockets_map();
            *smap_clone.write() = new_map;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    let state_clone = shared_state.clone();
    let smap_agg = sockets_map.clone();
    tokio::spawn(async move {
        while let Some(pkt) = rx.recv().await {
            state::process_packet(&state_clone, &smap_agg, pkt);
        }
    });

    let state_tick = shared_state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            state_tick.write().tick();
        }
    });

    ui::run(shared_state).await?;

    Ok(())
}
