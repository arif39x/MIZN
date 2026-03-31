//! Honey-port active deception module.
//!
//! Binds lightweight TCP listeners on known attacker-targeted ports:
//!   - 21   → FTP
//!   - 23   → Telnet
//!   - 2323 → Mirai botnet probe
//!
//! Any inbound connection is immediately closed after the attacker IP and
//! targeted port are logged to the `threat_alerts` SQLite table.

use rusqlite::Connection;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

/// Ports that legitimate software has no reason to contact.
const HONEY_PORTS: &[u16] = &[21, 23, 2323];

/// Spawn async Tokio tasks for all honey-port listeners.
pub fn start(db: Arc<Mutex<Connection>>) {
    for &port in HONEY_PORTS {
        let db = db.clone();
        tokio::spawn(async move {
            let addr = format!("0.0.0.0:{port}");
            let listener = match TcpListener::bind(&addr).await {
                Ok(l) => {
                    eprintln!("[miznd][honey] Listening on {addr}");
                    l
                }
                Err(e) => {
                    eprintln!("[miznd][honey] Failed to bind {addr}: {e}");
                    return;
                }
            };

            loop {
                match listener.accept().await {
                    Ok((socket, remote)) => {
                        // Drop the socket immediately — the tarpit sends nothing.
                        drop(socket);
                        handle_trigger(&db, remote, port);
                    }
                    Err(e) => {
                        eprintln!("[miznd][honey] Accept error on port {port}: {e}");
                    }
                }
            }
        });
    }
}

fn handle_trigger(db: &Arc<Mutex<Connection>>, remote: SocketAddr, port: u16) {
    let attacker_ip = remote.ip().to_string();
    eprintln!(
        "[miznd][honey][ALERT] HONEY_PORT_TRIGGER → attacker={attacker_ip} port={port}"
    );

    if let Ok(conn) = db.lock() {
        if let Err(e) = crate::core::database::record_threat_alert(
            &conn,
            "HONEY_PORT_TRIGGER",
            &attacker_ip,
            port,
        ) {
            eprintln!("[miznd][honey] DB write error: {e}");
        }
    }
}
