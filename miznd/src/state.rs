use mizn_common::bpf::{FlowKey, FlowMetrics};
use mizn_common::ipc::{IpcState, IpcProcessMetrics};
use std::collections::HashMap;
use crate::resolver::SocketsMap;
use std::net::Ipv4Addr;

pub fn merge_bpf_metrics(
    global_state: &mut IpcState,
    bpf_map_dump: &HashMap<FlowKey, FlowMetrics>,
    socket_registry: &SocketsMap,
) {
    let mut aggregate_temporal_transmitted = 0;
    let mut aggregate_temporal_received = 0;

    for process_metric_entry in global_state.active_process_telemetry.values_mut() {
        process_metric_entry.temporal_transmission_accumulator = 0;
        process_metric_entry.temporal_reception_accumulator = 0;
    }

}
