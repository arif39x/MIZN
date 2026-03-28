use rusqlite::{Connection, params};

pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;

    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS flow_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          INTEGER NOT NULL,
            pid         INTEGER NOT NULL,
            process     TEXT    NOT NULL,
            bytes_delta INTEGER NOT NULL,
            sni         TEXT,
            protocol    TEXT    NOT NULL DEFAULT 'TCP'
        );
        CREATE INDEX IF NOT EXISTS idx_flow_ts      ON flow_events(ts);
        CREATE INDEX IF NOT EXISTS idx_flow_pid     ON flow_events(pid);
        CREATE INDEX IF NOT EXISTS idx_flow_process ON flow_events(process);
        ",
    )?;

    Ok(conn)
}

#[inline]
pub fn record_flow(
    conn: &Connection,
    ts: u64,
    pid: i32,
    process: &str,
    bytes_delta: u64,
    sni: &str,
    protocol: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO flow_events (ts, pid, process, bytes_delta, sni, protocol)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![ts as i64, pid, process, bytes_delta as i64, sni, protocol],
    )?;
    Ok(())
}
