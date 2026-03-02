use crate::ingestion::PacketInfo;
use crate::resolver::SocketsMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug)]
pub struct ProcessMetrics {
    pub process_identifier: i32,
    pub process_nomenclature: String,
    pub cumulative_bytes_transmitted: u64,
    pub cumulative_bytes_received: u64,
    pub transmission_rate_bytes_per_second: u64,
    pub reception_rate_bytes_per_second: u64,
    pub temporal_transmission_accumulator: u64,
    pub temporal_reception_accumulator: u64,
    pub peak_throughput_bytes_per_second: u64,
    pub last_resolved_remote_peer: Option<IpAddr>,
}

pub struct State {
    pub active_process_telemetry: HashMap<i32, ProcessMetrics>,
    pub aggregate_cumulative_bytes_transmitted: u64,
    pub aggregate_cumulative_bytes_received: u64,
    pub aggregate_transmission_rate_bytes_per_second: u64,
    pub aggregate_reception_rate_bytes_per_second: u64,
    pub global_peak_throughput_bytes_per_second: u64,
    pub transmission_history_ring_buffer: [u64; 60],
    pub reception_history_ring_buffer: [u64; 60],
    pub history_ring_buffer_cursor: usize,
    pub telemetry_initialization_timestamp: Instant,
}

impl State {
    pub fn new() -> Self {
        Self {
            active_process_telemetry: HashMap::with_capacity(1024),
            aggregate_cumulative_bytes_transmitted: 0,
            aggregate_cumulative_bytes_received: 0,
            aggregate_transmission_rate_bytes_per_second: 0,
            aggregate_reception_rate_bytes_per_second: 0,
            global_peak_throughput_bytes_per_second: 0,
            transmission_history_ring_buffer: [0; 60],
            reception_history_ring_buffer: [0; 60],
            history_ring_buffer_cursor: 0,
            telemetry_initialization_timestamp: Instant::now(),
        }
    }

    pub fn tick(&mut self) {
        let mut aggregate_temporal_transmitted = 0;
        let mut aggregate_temporal_received = 0;

        for process_metric_entry in self.active_process_telemetry.values_mut() {
            process_metric_entry.transmission_rate_bytes_per_second =
                process_metric_entry.temporal_transmission_accumulator;
            process_metric_entry.reception_rate_bytes_per_second =
                process_metric_entry.temporal_reception_accumulator;

            let combined_throughput = process_metric_entry.temporal_transmission_accumulator
                + process_metric_entry.temporal_reception_accumulator;

            if combined_throughput > process_metric_entry.peak_throughput_bytes_per_second {
                process_metric_entry.peak_throughput_bytes_per_second = combined_throughput;
            }

            aggregate_temporal_transmitted +=
                process_metric_entry.temporal_transmission_accumulator;
            aggregate_temporal_received += process_metric_entry.temporal_reception_accumulator;

            process_metric_entry.temporal_transmission_accumulator = 0;
            process_metric_entry.temporal_reception_accumulator = 0;
        }

        self.aggregate_transmission_rate_bytes_per_second = aggregate_temporal_transmitted;
        self.aggregate_reception_rate_bytes_per_second = aggregate_temporal_received;

        let global_combined_throughput =
            aggregate_temporal_transmitted + aggregate_temporal_received;
        if global_combined_throughput > self.global_peak_throughput_bytes_per_second {
            self.global_peak_throughput_bytes_per_second = global_combined_throughput;
        }

        self.transmission_history_ring_buffer[self.history_ring_buffer_cursor] =
            aggregate_temporal_transmitted;
        self.reception_history_ring_buffer[self.history_ring_buffer_cursor] =
            aggregate_temporal_received;

        self.history_ring_buffer_cursor = (self.history_ring_buffer_cursor + 1) % 60;
    }
}

pub fn process_packet(
    global_telemetry_state: &Arc<RwLock<State>>,
    active_socket_registry: &Arc<RwLock<SocketsMap>>,
    network_frame_telemetry: PacketInfo,
) {
    let resolved_socket_identity = {
        let locked_registry_view = active_socket_registry.read();
        locked_registry_view
            .get(&network_frame_telemetry.source_port)
            .map(|socket_identity| (socket_identity.0, socket_identity.1.clone(), true))
            .or_else(|| {
                locked_registry_view
                    .get(&network_frame_telemetry.destination_port)
                    .map(|socket_identity| (socket_identity.0, socket_identity.1.clone(), false))
            })
    };

    if let Some((process_identifier, process_nomenclature, is_transmission)) =
        resolved_socket_identity
    {
        let frame_payload_length = network_frame_telemetry.payload_length_bytes;
        let remote_peer_identity = if is_transmission {
            network_frame_telemetry.destination_ip
        } else {
            network_frame_telemetry.source_ip
        };

        let mut locked_state_mutation_view = global_telemetry_state.write();

        if is_transmission {
            locked_state_mutation_view.aggregate_cumulative_bytes_transmitted +=
                frame_payload_length;
        } else {
            locked_state_mutation_view.aggregate_cumulative_bytes_received += frame_payload_length;
        }

        let process_telemetry_entry = locked_state_mutation_view
            .active_process_telemetry
            .entry(process_identifier)
            .or_insert_with(|| ProcessMetrics {
                process_identifier,
                process_nomenclature,
                cumulative_bytes_transmitted: 0,
                cumulative_bytes_received: 0,
                transmission_rate_bytes_per_second: 0,
                reception_rate_bytes_per_second: 0,
                temporal_transmission_accumulator: 0,
                temporal_reception_accumulator: 0,
                peak_throughput_bytes_per_second: 0,
                last_resolved_remote_peer: None,
            });

        if is_transmission {
            process_telemetry_entry.cumulative_bytes_transmitted += frame_payload_length;
            process_telemetry_entry.temporal_transmission_accumulator += frame_payload_length;
        } else {
            process_telemetry_entry.cumulative_bytes_received += frame_payload_length;
            process_telemetry_entry.temporal_reception_accumulator += frame_payload_length;
        }

        process_telemetry_entry.last_resolved_remote_peer = Some(remote_peer_identity);
    }
}
