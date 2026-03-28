use mizn_common::ipc::IpcState;
use std::time::Instant;
use super::{Alert, AlertConfig, AlertLevel};

pub fn evaluate_rules(state: &IpcState, config: &AlertConfig, out: &mut Vec<Alert>) {
    for pm in state.active_process_telemetry.values() {
        if (pm.tcp_flags & 0x02 != 0) && (pm.tcp_flags & 0x10 == 0) {
            out.push(Alert {
                timestamp:    Instant::now(),
                level:        AlertLevel::Critical,
                message:      format!("⚠ Port Scan: '{}' (PID {}) — SYN flood/scan pattern", pm.process_nomenclature, pm.process_identifier),
                trigger_pcap: true,
            });
        }

        let total = pm.transmission_rate_bytes_per_second + pm.reception_rate_bytes_per_second;
        if total > config.high_bw_threshold {
            out.push(Alert {
                timestamp:    Instant::now(),
                level:        AlertLevel::Warning,
                message:      format!("↑ High Bandwidth: '{}' (PID {}) at {:.1} MB/s", pm.process_nomenclature, pm.process_identifier, total as f64 / 1_048_576.0),
                trigger_pcap: false,
            });
        }
    }

    let global = state.aggregate_reception_rate_bytes_per_second + state.aggregate_transmission_rate_bytes_per_second;
    if global > config.high_bw_threshold * 3 {
        out.push(Alert {
            timestamp:    Instant::now(),
            level:        AlertLevel::Critical,
            message:      format!("⚡ Global spike: {:.1} MB/s — possible DDoS or exfiltration", global as f64 / 1_048_576.0),
            trigger_pcap: true,
        });
    }
}
