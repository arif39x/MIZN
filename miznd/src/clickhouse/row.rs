use clickhouse::Row;
use mizn_common::ipc::IpcProcessMetrics;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct FlowRow {
    pub ts:           u64,
    pub pid:          i32,
    pub process:      String,
    pub rx_bps:       u64,
    pub tx_bps:       u64,
    pub total_bytes:  u64,
    pub sni:          String,
    pub tcp_flags:    u8,
    pub protocol:     String,
}

impl FlowRow {
    pub fn from_metrics(ts: u64, pm: &IpcProcessMetrics, protocol: &str) -> Self {
        Self {
            ts,
            pid:         pm.process_identifier,
            process:     pm.process_nomenclature.clone(),
            rx_bps:      pm.reception_rate_bytes_per_second,
            tx_bps:      pm.transmission_rate_bytes_per_second,
            total_bytes: pm.cumulative_bytes_transmitted + pm.cumulative_bytes_received,
            sni:         pm.sni.clone(),
            tcp_flags:   pm.tcp_flags,
            protocol:    protocol.to_string(),
        }
    }
}
