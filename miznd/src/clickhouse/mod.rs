use clickhouse::Client;
use mizn_common::ipc::IpcProcessMetrics;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

mod row;

pub fn try_spawn() -> Option<mpsc::UnboundedSender<Vec<IpcProcessMetrics>>> {
    let url = std::env::var("MIZN_CH_URL").ok()?;
    let db  = std::env::var("MIZN_CH_DB").unwrap_or_else(|_| "mizn".into());
    let user = std::env::var("MIZN_CH_USER").unwrap_or_else(|_| "default".into());
    let pass = std::env::var("MIZN_CH_PASSWORD").unwrap_or_default();

    let client = Client::default().with_url(&url).with_database(&db).with_user(&user).with_password(&pass);
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<IpcProcessMetrics>>();

    tokio::spawn(async move {
        let create_sql = "CREATE TABLE IF NOT EXISTS flows (ts UInt64, pid Int32, process String, rx_bps UInt64, tx_bps UInt64, total_bytes UInt64, sni String, tcp_flags UInt8, protocol String) ENGINE = MergeTree() ORDER BY (ts, process)";
        if let Err(e) = client.query(create_sql).execute().await {
            eprintln!("[miznd][clickhouse] Table create error: {}", e);
        } else {
            eprintln!("[miznd][clickhouse] Connected to {} / {}", url, db);
        }

        let mut batch: Vec<row::FlowRow> = Vec::with_capacity(512);
        let mut last_flush = std::time::Instant::now();

        while let Some(metrics_vec) = rx.recv().await {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

            for pm in &metrics_vec {
                batch.push(row::FlowRow::from_metrics(ts, pm, "TCP"));
            }

            if last_flush.elapsed().as_secs() >= 10 || batch.len() > 500 {
                if !batch.is_empty() {
                    let insert = client.insert::<row::FlowRow>("flows");
                    match insert {
                        Ok(mut ins) => {
                            let mut ok = true;
                            for row in &batch {
                                if let Err(e) = ins.write(row).await { eprintln!("[miznd][clickhouse] Write error: {}", e); ok = false; }
                            }
                            if ok {
                                if let Err(e) = ins.end().await { eprintln!("[miznd][clickhouse] Commit error: {}", e); }
                                else { eprintln!("[miznd][clickhouse] Flushed {} rows", batch.len()); }
                            }
                        }
                        Err(e) => eprintln!("[miznd][clickhouse] Insert error: {}", e),
                    }
                    batch.clear();
                }
                last_flush = std::time::Instant::now();
            }
        }
    });

    Some(tx)
}
