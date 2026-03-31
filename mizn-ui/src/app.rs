use std::collections::VecDeque;
use mizn_common::ipc::{IpcState, IpcCommand};
use rkyv::ser::Serializer;
use std::io::Write;

pub enum ViewMode {
    Default,
    Graph,
    Table,
}

pub struct AppState {
    pub telemetry:   IpcState,
    pub blocked_ips: VecDeque<String>,
    pub iface:       String,
    pub view_mode:   ViewMode,
    pub selected_index: usize,
    pub list_len: usize,
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
            blocked_ips: VecDeque::with_capacity(64),
            iface,
            view_mode: ViewMode::Default,
            selected_index: 0,
            list_len: 0,
        }
    }


    pub fn ingest(&mut self, new_state: IpcState) {
        self.telemetry = new_state;
        self.list_len = self.telemetry.active_process_telemetry.len();
        if self.list_len > 0 && self.selected_index >= self.list_len {
            self.selected_index = self.list_len - 1;
        }
    }

    pub fn move_up(&mut self) {
        if self.selected_index > 0 { self.selected_index -= 1; }
    }

    pub fn move_down(&mut self) {
        if self.list_len > 0 && self.selected_index < self.list_len - 1 {
            self.selected_index += 1;
        }
    }

    pub fn kill_selected(&mut self) {
        if let Some(pid) = self.get_selected_pid() {
            let _ = std::process::Command::new("kill").arg("-9").arg(pid.to_string()).spawn();
        }
    }

    pub fn drop_selected(&mut self) {
        if let Some(ip) = self.get_selected_ip() {
            self.block_ip(ip);
        }
    }
    
    fn get_selected_pid(&self) -> Option<i32> {
        let mut procs: Vec<_> = self.telemetry.active_process_telemetry.values().collect();
        // Uses same logic as table sorting
        procs.sort_by(|a, b| {
            let aw = ["sshd", "nginx", "systemd"].contains(&a.process_nomenclature.as_str());
            let bw = ["sshd", "nginx", "systemd"].contains(&b.process_nomenclature.as_str());
            if aw && !bw { return std::cmp::Ordering::Less; }
            if bw && !aw { return std::cmp::Ordering::Greater; }
            let bv = b.transmission_rate_bytes_per_second + b.reception_rate_bytes_per_second;
            let av = a.transmission_rate_bytes_per_second + a.reception_rate_bytes_per_second;
            bv.cmp(&av)
        });
        procs.get(self.selected_index).map(|pm| pm.process_identifier)
    }

    fn get_selected_ip(&self) -> Option<u32> {
        let mut procs: Vec<_> = self.telemetry.active_process_telemetry.values().collect();
        procs.sort_by(|a, b| {
            let aw = ["sshd", "nginx", "systemd"].contains(&a.process_nomenclature.as_str());
            let bw = ["sshd", "nginx", "systemd"].contains(&b.process_nomenclature.as_str());
            if aw && !bw { return std::cmp::Ordering::Less; }
            if bw && !aw { return std::cmp::Ordering::Greater; }
            let bv = b.transmission_rate_bytes_per_second + b.reception_rate_bytes_per_second;
            let av = a.transmission_rate_bytes_per_second + a.reception_rate_bytes_per_second;
            bv.cmp(&av)
        });
        procs.get(self.selected_index).and_then(|pm| pm.last_resolved_remote_peer_ipv4)
    }

    pub fn block_ip(&mut self, ip: u32) {
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

    pub fn block_top_ip(&mut self) {
        if let Some(top) = self.telemetry.active_process_telemetry.values()
            .max_by_key(|p| p.transmission_rate_bytes_per_second + p.reception_rate_bytes_per_second) {
            if let Some(ip) = top.last_resolved_remote_peer_ipv4 {
                self.block_ip(ip);
            }
        }
    }
}
