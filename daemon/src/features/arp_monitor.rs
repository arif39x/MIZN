//! ARP Monitoring & MAC Tracking (Layer 2)
//!
//! Opens a raw AF_PACKET socket filtered to EtherType 0x0806 (ARP) and
//! maintains an in-memory registry of IP → MAC mappings.
//!
//! Detection events:
//!   - `NEW_DEVICE_DETECTED`  — first time an IP is seen on the network
//!   - `ARP_SPOOF_ATTACK`     — same IP appears with a *different* MAC address
//!
//! Both events are persisted to:
//!   - `arp_registry`   — canonical IP→MAC state table
//!   - `threat_alerts`  — high-severity alerts (spoof only)

use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ARP packet layout offsets (after the 14-byte Ethernet header)
// Byte offsets within the ARP payload (standard 28-byte IPv4 ARP):
//   0–1:  HTYPE  (hardware type)
//   2–3:  PTYPE  (protocol type)
//   4:    HLEN   (hardware address length)
//   5:    PLEN   (protocol address length)
//   6–7:  OPER   (operation: 1=request, 2=reply)
//   8–13: SHA    (sender hardware address = MAC)
//   14–17: SPA   (sender protocol address = IP)
//   18–23: THA   (target hardware address)
//   24–27: TPA   (target protocol address)
const ETH_HLEN: usize = 14;
const ARP_SHA_OFF: usize = ETH_HLEN + 8;
const ARP_SPA_OFF: usize = ETH_HLEN + 14;
const MIN_FRAME_LEN: usize = ETH_HLEN + 28;

/// EtherType for ARP in host byte order (used in sockaddr_ll)
const ETH_P_ARP: u16 = 0x0806;

/// Spawn a dedicated OS thread that reads ARP frames from a raw socket.
pub fn start(db: Arc<Mutex<Connection>>, alert_tx: tokio::sync::mpsc::UnboundedSender<String>) {
    std::thread::Builder::new()
        .name("mizn-arp".into())
        .spawn(move || run_arp_loop(db, alert_tx))
        .expect("failed to spawn ARP monitor thread");
}

fn run_arp_loop(db: Arc<Mutex<Connection>>, alert_tx: tokio::sync::mpsc::UnboundedSender<String>) {
    // Open raw AF_PACKET socket for ARP frames only.
    // SAFETY: libc FFI — standard socket(2) call.
    let sock = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (ETH_P_ARP as u16).to_be() as i32,
        )
    };
    if sock < 0 {
        eprintln!(
            "[miznd][arp] Failed to open raw socket (need CAP_NET_RAW): errno={}",
            std::io::Error::last_os_error()
        );
        return;
    }

    eprintln!("[miznd][arp] ARP monitor active (raw AF_PACKET socket)");

    // In-memory registry: sender_ip → sender_mac
    let mut registry: HashMap<[u8; 4], [u8; 6]> = HashMap::with_capacity(256);
    let mut buf = [0u8; 2048];

    loop {
        let n = unsafe {
            libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };
        if n < 0 {
            eprintln!(
                "[miznd][arp] recv error: {}",
                std::io::Error::last_os_error()
            );
            break;
        }
        let frame = &buf[..n as usize];

        if frame.len() < MIN_FRAME_LEN {
            continue;
        }

        // Verify EtherType == 0x0806
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype != ETH_P_ARP {
            continue;
        }

        // Extract sender MAC and sender IP
        let mut sha = [0u8; 6];
        sha.copy_from_slice(&frame[ARP_SHA_OFF..ARP_SHA_OFF + 6]);

        let mut spa = [0u8; 4];
        spa.copy_from_slice(&frame[ARP_SPA_OFF..ARP_SPA_OFF + 4]);

        // Skip obviously invalid addresses (0.0.0.0, broadcast MAC)
        if spa == [0u8; 4] || sha == [0xFF; 6] {
            continue;
        }

        let ip_str = format!("{}.{}.{}.{}", spa[0], spa[1], spa[2], spa[3]);
        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]
        );

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match registry.get(&spa) {
            None => {
                // First time  seen this IP.
                eprintln!(
                    "[miznd][arp] NEW_DEVICE_DETECTED  ip={ip_str} mac={mac_str}"
                );
                registry.insert(spa, sha);
                if let Ok(conn) = db.lock() {
                    let _ = crate::core::database::upsert_arp_entry(&conn, &ip_str, &mac_str, ts);
                }
            }
            Some(&known_mac) if known_mac != sha => {
                // Same IP, different MAC → ARP spoofing!
                let known_str = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    known_mac[0], known_mac[1], known_mac[2],
                    known_mac[3], known_mac[4], known_mac[5]
                );
                eprintln!(
                    "[miznd][arp][ALERT] ARP_SPOOF_ATTACK ip={ip_str} \
                     known_mac={known_str} attacker_mac={mac_str}"
                );
                // Update registry to latest MAC (could be legitimate change)
                registry.insert(spa, sha);
                let detail = format!("ARP_SPOOF_ATTACK: {ip_str} changed MAC {known_str}→{mac_str}");
                let _ = alert_tx.send(detail.clone());
                if let Ok(conn) = db.lock() {
                    let _ = crate::core::database::upsert_arp_entry(&conn, &ip_str, &mac_str, ts);
                    // Log as a critical threat alert (port 0 = N/A for ARP)
                    let _ = crate::core::database::record_threat_alert(&conn, "ARP_SPOOF_ATTACK", &detail, 0);
                }
            }
            _ => {
                // MAC unchanged — just update last_seen timestamp.
                if let Ok(conn) = db.lock() {
                    let _ = crate::core::database::upsert_arp_entry(&conn, &ip_str, &mac_str, ts);
                }
            }
        }
    }

    unsafe { libc::close(sock) };
}
