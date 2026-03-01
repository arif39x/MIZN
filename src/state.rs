use crate::ingestion::PacketInfo;
use crate::resolver::SocketsMap;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug)]
pub struct ProcessMetrics {
    pub pid: i32,
    pub name: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub current_rate_sent_bps: u64,
    pub current_rate_recv_bps: u64,
    pub current_sec_sent: u64,
    pub current_sec_recv: u64,
    pub last_remote_addr: String,
}

pub struct State {
    pub process_metrics: HashMap<i32, ProcessMetrics>,
    pub total_bytes_sent: u64,
    pub total_bytes_recv: u64,
    pub total_rate_sent_bps: u64,
    pub total_rate_recv_bps: u64,
    pub graph_sent: VecDeque<u64>,
    pub graph_recv: VecDeque<u64>,
    pub start_time: Instant,
}

impl State {
    pub fn new() -> Self {
        let mut graph_sent = VecDeque::with_capacity(60);
        let mut graph_recv = VecDeque::with_capacity(60);
        for _ in 0..60 {
            graph_sent.push_back(0);
            graph_recv.push_back(0);
        }
        Self {
            process_metrics: HashMap::new(),
            total_bytes_sent: 0,
            total_bytes_recv: 0,
            total_rate_sent_bps: 0,
            total_rate_recv_bps: 0,
            graph_sent,
            graph_recv,
            start_time: Instant::now(),
        }
    }

    pub fn tick(&mut self) {
        let mut total_s = 0;
        let mut total_r = 0;
        for pm in self.process_metrics.values_mut() {
            pm.current_rate_sent_bps = pm.current_sec_sent;
            pm.current_rate_recv_bps = pm.current_sec_recv;
            total_s += pm.current_sec_sent;
            total_r += pm.current_sec_recv;
            pm.current_sec_sent = 0;
            pm.current_sec_recv = 0;
        }
        self.total_rate_sent_bps = total_s;
        self.total_rate_recv_bps = total_r;
        
        self.graph_sent.push_back(total_s);
        self.graph_recv.push_back(total_r);
        if self.graph_sent.len() > 60 {
            self.graph_sent.pop_front();
        }
        if self.graph_recv.len() > 60 {
            self.graph_recv.pop_front();
        }
    }
}

pub fn process_packet(
    shared_state: &Arc<RwLock<State>>,
    sockets_map: &Arc<RwLock<SocketsMap>>,
    pkt: PacketInfo,
) {
    let mut pid_name = None;
    let mut sent = false;

    {
        let map = sockets_map.read();
        if let Some(&(pid, ref name)) = map.get(&pkt.src_port) {
            pid_name = Some((pid, name.clone()));
            sent = true;
        } else if let Some(&(pid, ref name)) = map.get(&pkt.dst_port) {
            pid_name = Some((pid, name.clone()));
            sent = false;
        }
    }

    if let Some((pid, name)) = pid_name {
        let mut state = shared_state.write();
        let entry = state.process_metrics.entry(pid).or_insert_with(|| ProcessMetrics {
            pid,
            name,
            bytes_sent: 0,
            bytes_recv: 0,
            current_rate_sent_bps: 0,
            current_rate_recv_bps: 0,
            current_sec_sent: 0,
            current_sec_recv: 0,
            last_remote_addr: String::new(),
        });

        if sent {
            entry.bytes_sent += pkt.length;
            entry.current_sec_sent += pkt.length;
            entry.last_remote_addr = pkt.dst_ip.to_string();
            state.total_bytes_sent += pkt.length;
        } else {
            entry.bytes_recv += pkt.length;
            entry.current_sec_recv += pkt.length;
            entry.last_remote_addr = pkt.src_ip.to_string();
            state.total_bytes_recv += pkt.length;
        }
    }
}
