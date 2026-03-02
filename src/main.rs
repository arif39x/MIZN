mod ingestion;
mod resolver;
mod state;
mod ui;

use parking_lot::RwLock;
use resolver::SocketsMap;
use state::State;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const MAXIMUM_INFLIGHT_PACKET_THRESHOLD: usize = 1_048_576;
const SOCKET_REGISTRY_REFRESH_INTERVAL: Duration = Duration::from_millis(500);
const TELEMETRY_AGGREGATION_INTERVAL: Duration = Duration::from_secs(1);

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (telemetry_transmitter, mut telemetry_receiver) =
        mpsc::channel(MAXIMUM_INFLIGHT_PACKET_THRESHOLD);

    let global_telemetry_state = Arc::new(RwLock::new(State::new()));
    let active_socket_registry = Arc::new(RwLock::new(SocketsMap::new()));

    ingestion::start_sniffing(telemetry_transmitter);

    let socket_registry_updater_reference = active_socket_registry.clone();
    tokio::spawn(async move {
        loop {
            let refreshed_socket_topology = resolver::refresh_sockets_map();
            *socket_registry_updater_reference.write() = refreshed_socket_topology;
            tokio::time::sleep(SOCKET_REGISTRY_REFRESH_INTERVAL).await;
        }
    });

    let telemetry_processor_state_reference = global_telemetry_state.clone();
    let telemetry_processor_registry_reference = active_socket_registry.clone();
    tokio::spawn(async move {
        while let Some(network_frame_telemetry) = telemetry_receiver.recv().await {
            state::process_packet(
                &telemetry_processor_state_reference,
                &telemetry_processor_registry_reference,
                network_frame_telemetry,
            );
        }
    });

    let telemetry_aggregation_state_reference = global_telemetry_state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TELEMETRY_AGGREGATION_INTERVAL).await;
            telemetry_aggregation_state_reference.write().tick();
        }
    });

    ui::run(global_telemetry_state).await?;

    Ok(())
}
