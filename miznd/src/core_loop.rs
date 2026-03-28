use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use rkyv::ser::serializers::{BufferSerializer, BufferScratch, CompositeSerializer};
use rkyv::ser::Serializer;
use rkyv::Infallible;
use aya::maps::HashMap as BpfHashMap;
use mizn_common::bpf::{FlowKey, FlowMetrics};
use mizn_common::ipc::{IpcProcessMetrics, IpcState};
use crate::resolver::SocketsMap;
use crate::telemetry;

const TELEMETRY_BUFFER_SIZE: usize = 524288;
const AGGREGATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

pub struct CoreLoopArgs {
    pub bpf: aya::Ebpf,
    pub cmd_rx: tokio::sync::mpsc::UnboundedReceiver<u32>,
    pub ch_sender: Option<tokio::sync::mpsc::UnboundedSender<Vec<IpcProcessMetrics>>>,
    pub alert_tx: tokio::sync::mpsc::UnboundedSender<IpcState>,
    pub connections: Arc<RwLock<Vec<tokio::net::UnixStream>>>,
    pub socket_registry: Arc<RwLock<SocketsMap>>,
}

pub async fn run(mut args: CoreLoopArgs) {
    let mut bpf_shadow: HashMap<FlowKey, FlowMetrics> = HashMap::with_capacity(10240);
    let mut global_state = IpcState::default();
    let mut serial_buf   = [0u8; TELEMETRY_BUFFER_SIZE];
    let mut scratch_buf  = [0u8; 4096];
    let db = telemetry::open("miznd_telemetry.db").expect("Failed to open SQLite db");

    loop {
        tokio::time::sleep(AGGREGATION_INTERVAL).await;

        if let Ok(mut blocklist) = BpfHashMap::<_, u32, u8>::try_from(args.bpf.map_mut("BLOCKLIST").unwrap()) {
            while let Ok(ip) = args.cmd_rx.try_recv() {
                let _ = blocklist.insert(ip, 1, 0);
                eprintln!("[miznd] Blocked: {}", std::net::Ipv4Addr::from(ip.to_be()));
            }
        }

        let registry  = args.socket_registry.read().await;
        let mut dtx   = 0u64;
        let mut drx   = 0u64;

        global_state.active_process_telemetry.values_mut().for_each(|m| {
            m.temporal_transmission_accumulator = 0;
            m.temporal_reception_accumulator    = 0;
        });

        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

        if let Ok(flow_map) = BpfHashMap::<_, FlowKey, FlowMetrics>::try_from(args.bpf.map_mut("FLOW_METRICS").unwrap()) {
            let mut updates = Vec::new();
            for r in flow_map.iter().filter_map(|r| r.ok()) {
                let (key, metrics) = r;
                let prev        = bpf_shadow.entry(key).or_default();
                let delta_bytes = metrics.bytes.wrapping_sub(prev.bytes);
                if delta_bytes > 0 {
                    updates.push((key, metrics, delta_bytes));
                    *prev = metrics;
                }
            }

            if !updates.is_empty() {
                let port_pid_result = BpfHashMap::<_, u32, u32>::try_from(args.bpf.map_mut("PORT_TO_PID").unwrap());
                for (key, metrics, delta_bytes) in updates {
                    let resolved = if let Ok(ref pp_map) = port_pid_result {
                        pp_map.get(&(key.source_port as u32), 0).ok()
                            .map(|pid| (pid as i32, "kprobe-pid".to_string(), true))
                            .or_else(|| resolve_flow(&registry, &key))
                    } else {
                        resolve_flow(&registry, &key)
                    };

                    if let Some((pid, name, is_tx)) = resolved {
                        let protocol = proto_name(key.protocol);
                        let sni = String::from_utf8_lossy(&metrics.sni).trim_matches(char::from(0)).to_string();
                        let _ = telemetry::record_flow(&db, ts, pid, &name, delta_bytes, &sni, protocol);
                        
                        let entry = global_state.active_process_telemetry.entry(pid).or_insert_with(|| IpcProcessMetrics::new(pid, name));
                        entry.update_from_delta(delta_bytes, is_tx, &metrics);
                        if is_tx { entry.last_resolved_remote_peer_ipv4 = Some(key.destination_ip); } 
                        else { entry.last_resolved_remote_peer_ipv4 = Some(key.source_ip); }
                        if !sni.is_empty() { entry.sni = sni; }

                        dtx += delta_bytes * (is_tx as u64);
                        drx += delta_bytes * (!is_tx as u64);
                    }
                }
            }
        }

        global_state.finalize_tick(dtx, drx);
        let _ = args.alert_tx.send(global_state.clone());

        if let Some(ref ch_tx) = args.ch_sender {
            let rows: Vec<IpcProcessMetrics> = global_state.active_process_telemetry.values().cloned().collect();
            let _ = ch_tx.send(rows);
        }

        let len = {
            let mut ser = CompositeSerializer::new(BufferSerializer::new(&mut serial_buf), BufferScratch::new(&mut scratch_buf), Infallible);
            if ser.serialize_value(&global_state).is_ok() { ser.pos() } else { 0 }
        };
        if len > 0 { broadcast(&args.connections, &serial_buf[..len]).await; }
    }
}

pub fn resolve_flow(reg: &SocketsMap, key: &FlowKey) -> Option<(i32, String, bool)> {
    reg.get(&key.source_port).map(|s| (s.0, s.1.clone(), true))
        .or_else(|| reg.get(&key.destination_port).map(|s| (s.0, s.1.clone(), false)))
}

pub fn proto_name(p: u8) -> &'static str {
    match p { 6 => "TCP", 17 => "UDP", 1 => "ICMP", 58 => "ICMPv6", 47 => "GRE", _ => "OTHER", }
}

async fn broadcast(conns: &Arc<RwLock<Vec<tokio::net::UnixStream>>>, data: &[u8]) {
    let mut guard  = conns.write().await;
    let data_len   = data.len() as u32;
    let mut active = Vec::with_capacity(guard.len());
    for mut c in guard.drain(..) {
        if c.write_u32(data_len).await.is_ok() && c.write_all(data).await.is_ok() {
            active.push(c);
        }
    }
    *guard = active;
}
