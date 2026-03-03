mod resolver;

use aya::{include_bytes_aligned, Ebpf};
use aya::maps::HashMap as BpfHashMap;
use aya::programs::{Xdp, XdpFlags};
use rkyv::ser::serializers::{BufferSerializer, BufferScratch, CompositeSerializer};
use rkyv::ser::Serializer;
use rkyv::Infallible;
use mizn_common::bpf::{FlowKey, FlowMetrics};
use mizn_common::ipc::{IpcProcessMetrics, IpcState};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::sync::RwLock;

const TELEMETRY_BUFFER_SIZE: usize = 524288;
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
const AGGREGATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/mizn-ebpf"
    ))?;

    let program: &mut Xdp = bpf.program_mut("mizn_ebpf").unwrap().try_into()?;
    program.load()?;
    program.attach("eth0", XdpFlags::default())?;

    let socket_registry = Arc::new(RwLock::new(resolver::SocketsMap::with_capacity(8192)));
    let registry_ptr = socket_registry.clone();

    tokio::spawn(async move {
        loop {
            let next_topology = resolver::refresh_sockets_map();
            let mut lock = registry_ptr.write().await;
            *lock = next_topology;
            drop(lock);
            tokio::time::sleep(REFRESH_INTERVAL).await;
        }
    });

    let socket_path = "/run/miznd.sock";
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    let connections = Arc::new(RwLock::new(Vec::with_capacity(16)));
    let conn_pool = connections.clone();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            conn_pool.write().await.push(stream);
        }
    });

    let mut bpf_shadow_map: HashMap<FlowKey, FlowMetrics> = HashMap::with_capacity(10240);
    let mut global_state = IpcState::default();
    let mut serialization_buffer = [0u8; TELEMETRY_BUFFER_SIZE];
    let mut scratch_buffer = [0u8; 4096];

    let flow_metrics_map: BpfHashMap<_, FlowKey, FlowMetrics> =
        BpfHashMap::try_from(bpf.map_mut("FLOW_METRICS").unwrap())?;

    loop {
        tokio::time::sleep(AGGREGATION_INTERVAL).await;

        let registry = socket_registry.read().await;
        let mut delta_tx = 0u64;
        let mut delta_rx = 0u64;

        global_state.active_process_telemetry.values_mut().for_each(|m| {
            m.temporal_transmission_accumulator = 0;
            m.temporal_reception_accumulator = 0;
        });

        for result in flow_metrics_map.iter().filter_map(|r| r.ok()) {
            let (key, metrics) = result;
            let previous = bpf_shadow_map.entry(key).or_insert_with(FlowMetrics::default);
            let bytes_delta = metrics.bytes.wrapping_sub(previous.bytes);

            if bytes_delta > 0 {
                if let Some((pid, name, is_tx)) = resolve_flow(&registry, &key) {
                    let entry = global_state.active_process_telemetry.entry(pid).or_insert_with(|| {
                        IpcProcessMetrics::new(pid, name)
                    });

                    entry.update_from_delta(bytes_delta, is_tx, &metrics);
                    delta_tx += bytes_delta * (is_tx as u64);
                    delta_rx += bytes_delta * (!is_tx as u64);
                }
                *previous = metrics;
            }
        }

        global_state.finalize_tick(delta_tx, delta_rx);

        let mut serializer = CompositeSerializer::new(
            BufferSerializer::new(&mut serialization_buffer),
            BufferScratch::new(&mut scratch_buffer),
            Infallible,
        );

        if serializer.serialize_value(&global_state).is_ok() {
            let bytes_len = serializer.pos();
            broadcast_telemetry(&connections, &serialization_buffer[..bytes_len]).await;
        }
    }
}

#[inline(always)]
fn resolve_flow<'a>(registry: &'a resolver::SocketsMap, key: &FlowKey) -> Option<(i32, String, bool)> {
    registry.get(&key.source_port).map(|s| (s.0, s.1.clone(), true))
        .or_else(|| registry.get(&key.destination_port).map(|s| (s.0, s.1.clone(), false)))
}

async fn broadcast_telemetry(conns: &Arc<RwLock<Vec<tokio::net::UnixStream>>>, data: &[u8]) {
    let mut writable_conns = conns.write().await;
    let data_len = data.len() as u32;
    let mut active = Vec::with_capacity(writable_conns.len());


    for mut conn in writable_conns.drain(..) {
        match conn.write_u32(data_len).await {
            Ok(_) => {
                if conn.write_all(data).await.is_ok() {
                    active.push(conn);
                }
            }
            Err(_) => {}
        }
    }
    *writable_conns = active;
}
