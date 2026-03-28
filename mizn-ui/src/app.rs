use std::collections::VecDeque;
use mizn_common::ipc::{IpcState, IpcCommand};
use rkyv::ser::Serializer;
use std::io::Write;

pub struct AppState {
    pub telemetry:   IpcState,
    pub alerts:      VecDeque<String>,
    pub blocked_ips: VecDeque<String>,
    pub iface:       String,
}

impl AppState {
    pub fn new() -> Self {
        let iface = std::env::var("MIZN_IFACE").unwrap_or_else(|_| {
            std::fs::read_dir("/sys/class/net").ok().and_then(|entries| {
                entries.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n != "lo")
                    .find(|n| {
                        std::fs::read_to_string(format!("/sys/class/net/{}/operstate", n))
                            .map(|s| s.trim() == "up").unwrap_or(false)
                    })
            }).unwrap_or_else(|| "unknown".to_string())
        });
        Self {
            telemetry:   IpcState::default(),
            alerts:      VecDeque::with_capacity(32),
            blocked_ips: VecDeque::with_capacity(64),
            iface,
        }
    }

    pub fn ingest(&mut self, new_state: IpcState) {
        for pm in new_state.active_process_telemetry.values() {
            let syn_no_ack = (pm.tcp_flags & 0x02 != 0) && (pm.tcp_flags & 0x10 == 0);
            if syn_no_ack {
                let msg = format!("  Port Scan Detected: {} (PID {})", pm.process_nomenclature, pm.process_identifier);
                if !self.alerts.contains(&msg) {
                    if self.alerts.len() >= 32 { self.alerts.pop_front(); }
                    self.alerts.push_back(msg);
                }
            }
            let high_bw = (pm.transmission_rate_bytes_per_second + pm.reception_rate_bytes_per_second) > 52_428_800;
            if high_bw {
                let msg = format!(" High Bandwidth: {} (PID {})", pm.process_nomenclature, pm.process_identifier);
                if !self.alerts.contains(&msg) {
                    if self.alerts.len() >= 32 { self.alerts.pop_front(); }
                    self.alerts.push_back(msg);
                }
            }
        }
        self.telemetry = new_state;
    }

    pub fn block_top_ip(&mut self) {
        if let Some(top) = self.telemetry.active_process_telemetry.values()
            .max_by_key(|p| p.transmission_rate_bytes_per_second + p.reception_rate_bytes_per_second) {
            if let Some(ip) = top.last_resolved_remote_peer_ipv4 {
                if let Ok(mut sock) = std::os::unix::net::UnixStream::connect("/run/miznd_cmd.sock") {
                    let cmd = IpcCommand::BlockIp(ip);
                    let mut buf     = [0u8; 128];
                    let mut scratch = [0u8; 128];
                    
                    let len = {
                        let mut ser = rkyv::ser::serializers::CompositeSerializer::new(
                            rkyv::ser::serializers::BufferSerializer::new(&mut buf),
                            rkyv::ser::serializers::BufferScratch::new(&mut scratch),
                            rkyv::Infallible,
                        );
                        if ser.serialize_value(&cmd).is_ok() { ser.pos() } else { 0 }
                    };

                    if len > 0 {
                        let _ = sock.write_all(&buf[..len]);
                    }
                }
                let addr = std::net::Ipv4Addr::from(ip.to_be());
                if self.blocked_ips.len() >= 64 { self.blocked_ips.pop_front(); }
                self.blocked_ips.push_back(format!("  {}", addr));
            }
        }
    }
}
