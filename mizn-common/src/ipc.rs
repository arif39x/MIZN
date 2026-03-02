use rkyv::{Archive, Deserialize, Serialize};

use std::collections::HashMap;
use std::string::String;

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
pub struct IpcState {
    pub active_process_telemetry: HashMap<i32, IpcProcessMetrics>,
    pub aggregate_cumulative_bytes_transmitted: u64,
    pub aggregate_cumulative_bytes_received: u64,
    pub aggregate_transmission_rate_bytes_per_second: u64,
    pub aggregate_reception_rate_bytes_per_second: u64,
    pub global_peak_throughput_bytes_per_second: u64,
    pub transmission_history_ring_buffer: [u64; 60],
    pub reception_history_ring_buffer: [u64; 60],
    pub history_ring_buffer_cursor: usize,
    pub telemetry_initialization_timestamp_millis: u64,
}

impl Default for IpcState {
    fn default() -> Self {
        Self {
            active_process_telemetry: HashMap::new(),
            aggregate_cumulative_bytes_transmitted: 0,
            aggregate_cumulative_bytes_received: 0,
            aggregate_transmission_rate_bytes_per_second: 0,
            aggregate_reception_rate_bytes_per_second: 0,
            global_peak_throughput_bytes_per_second: 0,
            transmission_history_ring_buffer: [0; 60],
            reception_history_ring_buffer: [0; 60],
            history_ring_buffer_cursor: 0,
            telemetry_initialization_timestamp_millis: 0,
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
pub struct IpcProcessMetrics {
    pub process_identifier: i32,
    pub process_nomenclature: String,
    pub cumulative_bytes_transmitted: u64,
    pub cumulative_bytes_received: u64,
    pub transmission_rate_bytes_per_second: u64,
    pub reception_rate_bytes_per_second: u64,
    pub temporal_transmission_accumulator: u64,
    pub temporal_reception_accumulator: u64,
    pub peak_throughput_bytes_per_second: u64,
    pub last_resolved_remote_peer_ipv4: Option<u32>,
    pub tcp_flags: u8,
    pub sni: String,
}
