mod alerting;
pub mod core;
pub mod features;
mod bpf_loader;
mod clickhouse;
mod core_loop;
mod ipc_server;
mod pcap_task;
mod pcap_writer;

use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::var("MIZN_IFACE").unwrap_or_else(|_| detect_iface());
    eprintln!("[miznd] Attaching XDP to interface: {iface}");

    let bpf_ctx = bpf_loader::BpfContext::load_and_attach(&iface)?;


    let db = Arc::new(Mutex::new(
        crate::core::database::open("miznd_telemetry.db").expect("Failed to open SQLite db"),
    ));

    // Socket → PID resolver
    let socket_registry = Arc::new(RwLock::new(crate::features::process_map::SocketsMap::with_capacity(8192)));
    {
        let reg = socket_registry.clone();
        tokio::spawn(async move {
            loop {
                let map = crate::features::process_map::refresh_sockets_map();
                *reg.write().await = map;
                tokio::time::sleep(REFRESH_INTERVAL).await;
            }
        });
    }

    let connections = ipc_server::start_telemetry_socket()?;
    let cmd_rx = ipc_server::start_command_socket()?;

    let ch_sender = clickhouse::try_spawn();
    if ch_sender.is_some() {
        eprintln!(
            "[miznd] ClickHouse streaming enabled → {}",
            std::env::var("MIZN_CH_URL").unwrap_or_default()
        );
    }

    let alert_config = alerting::AlertConfig::default();
    let (alert_tx, alert_rx) = alerting::spawn(alert_config);
    pcap_task::start_alert_handler(alert_rx);

    let (ui_alert_tx, ui_alert_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    // Honey-ports
    crate::features::honey_port::start(db.clone(), ui_alert_tx.clone());

    // ARP Monitoring (Layer 2)
    crate::features::arp_monitor::start(db.clone(), ui_alert_tx.clone());

    // Core loop (eBPF flow aggregation + telemetry)
    core_loop::run(core_loop::CoreLoopArgs {
        bpf: bpf_ctx.ebpf,
        cmd_rx,
        ch_sender,
        alert_tx,
        ui_alert_rx,
        connections,
        socket_registry,
        db,
    })
    .await;

    Ok(())
}

fn detect_iface() -> String {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return "wlan0".to_string();
    };
    let mut list: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n != "lo")
        .filter(|n| {
            std::fs::read_to_string(format!("/sys/class/net/{}/operstate", n))
                .map(|s| s.trim() == "up")
                .unwrap_or(false)
        })
        .collect();
    list.sort_by_key(|n| {
        if n.starts_with("en") || n.starts_with("eth") {
            0u8
        } else if n.starts_with("wlan") || n.starts_with("wlp") {
            1
        } else {
            2
        }
    });
    list.into_iter().next().unwrap_or_else(|| "wlan0".to_string())
}
