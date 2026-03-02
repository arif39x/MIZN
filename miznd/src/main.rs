mod resolver;

use aya::Ebpf;
use aya::maps::HashMap as BpfHashMap;
use aya::programs::{Xdp, XdpFlags};
use maxminddb::Reader;
use rkyv::ser::Serializer;
use rkyv::ser::serializers::AllocSerializer;
use mizn_common::bpf::{FlowKey, FlowMetrics};
use mizn_common::ipc::{IpcProcessMetrics, IpcState};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::sync::RwLock;

const SOCKET_REGISTRY_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
const TELEMETRY_AGGREGATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interface_name = "eth0";

    let obj_path = "../target/bpfel-unknown-none/release/mizn-ebpf";
    let bpf_result = Ebpf::load_file(obj_path);
    let mut bpf = match bpf_result {
        Ok(bpf) => bpf,
        Err(e) => {
            eprintln!("Failed to load eBPF probe: {}", e);
            std::process::exit(1);
        }
    };
    let program: &mut Xdp = bpf.program_mut("mizn_ebpf").unwrap().try_into()?;
    program.load()?;
    program.attach(interface_name, XdpFlags::default())?;

    let active_socket_registry = Arc::new(RwLock::new(resolver::SocketsMap::new()));
    let socket_registry_updater_reference = active_socket_registry.clone();

    tokio::spawn(async move {
        loop {
            let refreshed_socket_topology = resolver::refresh_sockets_map();
            *socket_registry_updater_reference.write().await = refreshed_socket_topology;
            tokio::time::sleep(SOCKET_REGISTRY_REFRESH_INTERVAL).await;
        }
    });

    let socket_path = "/run/miznd.sock";
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;

    let connections = Arc::new(RwLock::new(Vec::new()));
    let accepts = connections.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            accepts.write().await.push(stream);
        }
    });

    let mut bpf_shadow_map: HashMap<FlowKey, FlowMetrics> = HashMap::new();
    let mut global_state = IpcState::default();

    let db_reader = Reader::open_mmap("/var/lib/GeoIP/GeoLite2-ASN.mmdb").ok();

    loop {
        tokio::time::sleep(TELEMETRY_AGGREGATION_INTERVAL).await;

        let registry = active_socket_registry.read().await;

        let mut flow_metrics_map: BpfHashMap<_, [u8; 16], [u8; 88]> =
            BpfHashMap::try_from(bpf.map_mut("FLOW_METRICS").unwrap())?;

        let mut aggregate_temporal_transmitted = 0;
        let mut aggregate_temporal_received = 0;

        for process_metric_entry in global_state.active_process_telemetry.values_mut() {
            process_metric_entry.temporal_transmission_accumulator = 0;
            process_metric_entry.temporal_reception_accumulator = 0;
        }

        let mut next_shadow = HashMap::new();

        for result in flow_metrics_map.iter() {
            if let Ok((k_bytes, v_bytes)) = result {
                let key: FlowKey = unsafe { std::ptr::read(k_bytes.as_ptr() as *const FlowKey) };
                let metrics: FlowMetrics =
                    unsafe { std::ptr::read(v_bytes.as_ptr() as *const FlowMetrics) };

                next_shadow.insert(key, metrics);

                let previous_metrics = bpf_shadow_map.get(&key).copied().unwrap_or(FlowMetrics {
                    bytes: 0,
                    packets: 0,
                    tcp_flags: 0,
                    _padding: [0; 7],
                    sni: [0; 64],
                });

                let bytes_delta = metrics.bytes.saturating_sub(previous_metrics.bytes);
                if bytes_delta == 0 {
                    continue;
                }

                let resolved_socket = registry
                    .get(&key.source_port)
                    .map(|id| (id.0, id.1.clone(), true))
                    .or_else(|| {
                        registry
                            .get(&key.destination_port)
                            .map(|id| (id.0, id.1.clone(), false))
                    });

                if let Some((pid, name, is_tx)) = resolved_socket {
                    let entry = global_state
                        .active_process_telemetry
                        .entry(pid)
                        .or_insert_with(|| IpcProcessMetrics {
                            process_identifier: pid,
                            process_nomenclature: name,
                            cumulative_bytes_transmitted: 0,
                            cumulative_bytes_received: 0,
                            transmission_rate_bytes_per_second: 0,
                            reception_rate_bytes_per_second: 0,
                            temporal_transmission_accumulator: 0,
                            temporal_reception_accumulator: 0,
                            peak_throughput_bytes_per_second: 0,
                            last_resolved_remote_peer_ipv4: None,
                            tcp_flags: 0,
                            sni: String::new(),
                        });

                    entry.tcp_flags |= metrics.tcp_flags;
                    let last_peer = if is_tx {
                        key.destination_ip
                    } else {
                        key.source_ip
                    };
                    entry.last_resolved_remote_peer_ipv4 = Some(last_peer);

                    if let Ok(s) = std::ffi::CStr::from_bytes_until_nul(&metrics.sni) {
                        entry.sni = s.to_string_lossy().into_owned();
                    } else if let Ok(s) = std::str::from_utf8(&metrics.sni) {
                        entry.sni = s.trim_matches(char::from(0)).to_string();
                    }

                    if is_tx {
                        entry.cumulative_bytes_transmitted += bytes_delta;
                        entry.temporal_transmission_accumulator += bytes_delta;
                        aggregate_temporal_transmitted += bytes_delta;
                        global_state.aggregate_cumulative_bytes_transmitted += bytes_delta;
                    } else {
                        entry.cumulative_bytes_received += bytes_delta;
                        entry.temporal_reception_accumulator += bytes_delta;
                        aggregate_temporal_received += bytes_delta;
                        global_state.aggregate_cumulative_bytes_received += bytes_delta;
                    }
                }
            }
        }

        bpf_shadow_map = next_shadow;

        for process_metric_entry in global_state.active_process_telemetry.values_mut() {
            process_metric_entry.transmission_rate_bytes_per_second =
                process_metric_entry.temporal_transmission_accumulator;
            process_metric_entry.reception_rate_bytes_per_second =
                process_metric_entry.temporal_reception_accumulator;

            let combined = process_metric_entry.temporal_transmission_accumulator
                + process_metric_entry.temporal_reception_accumulator;
            if combined > process_metric_entry.peak_throughput_bytes_per_second {
                process_metric_entry.peak_throughput_bytes_per_second = combined;
            }
        }

        global_state.aggregate_transmission_rate_bytes_per_second = aggregate_temporal_transmitted;
        global_state.aggregate_reception_rate_bytes_per_second = aggregate_temporal_received;

        let combined_global = aggregate_temporal_transmitted + aggregate_temporal_received;
        if combined_global > global_state.global_peak_throughput_bytes_per_second {
            global_state.global_peak_throughput_bytes_per_second = combined_global;
        }

        global_state.transmission_history_ring_buffer[global_state.history_ring_buffer_cursor] =
            aggregate_temporal_transmitted;
        global_state.reception_history_ring_buffer[global_state.history_ring_buffer_cursor] =
            aggregate_temporal_received;
        global_state.history_ring_buffer_cursor =
            (global_state.history_ring_buffer_cursor + 1) % 60;

        let mut serializer = AllocSerializer::<256>::default();
        serializer.serialize_value(&global_state).unwrap();
        let bytes = serializer.into_serializer().into_inner();

        let mut conns = connections.write().await;
        let mut active_conns = Vec::new();
        for mut conn in conns.drain(..) {
            if conn.write_u32(bytes.len() as u32).await.is_ok() {
                if conn.write_all(&bytes).await.is_ok() {
                    active_conns.push(conn);
                }
            }
        }
        *conns = active_conns;
    }
}
