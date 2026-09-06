use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::alerting::Alert;
use crate::pcap_writer::PcapWriter;

const PCAP_DIR: &str = "/var/lib/mizn/pcap";

pub fn start_alert_handler(mut alert_rx: tokio::sync::mpsc::UnboundedReceiver<Alert>) {
    let pcap_active = Arc::new(AtomicBool::new(false));
    let pcap_flag   = pcap_active.clone();

    tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            eprintln!("[miznd][ALERT][{:?}] {}", alert.level, alert.message);
            if alert.trigger_pcap && !pcap_flag.load(Ordering::Relaxed) {
                pcap_flag.store(true, Ordering::Relaxed);
                let dir = PCAP_DIR.to_string();
                let flag = pcap_flag.clone();
                tokio::spawn(async move {
                    eprintln!("[miznd][pcap] Starting on-demand capture in {}", dir);
                    match PcapWriter::create_in(&dir) {
                        Ok(mut writer) => {
                            let start = std::time::Instant::now();
                            while start.elapsed().as_secs() < 30
                                && flag.load(Ordering::Relaxed)
                            {
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                            let _ = writer.flush();
                            eprintln!("[miznd][pcap] Capture complete.");
                        }
                        Err(e) => eprintln!("[miznd][pcap] Failed to create file: {}", e),
                    }
                    flag.store(false, Ordering::Relaxed);
                });
            }
        }
    });
}
