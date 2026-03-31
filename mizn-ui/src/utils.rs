pub fn format_bytes(bytes: u64) -> String {
    const G: f64 = 1_073_741_824.0;
    const M: f64 = 1_048_576.0;
    const K: f64 = 1024.0;
    if bytes >= 1_073_741_824 {
        format!("{:.2} GB", bytes as f64 / G)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / M)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / K)
    } else {
        format!("{} B", bytes)
    }
}

pub fn fmt_tcp_flags(flags: u8) -> String {
    let mut s = String::with_capacity(8);
    if flags & 0x01 != 0 { s.push_str("FIN "); }
    if flags & 0x02 != 0 { s.push_str("SYN "); }
    if flags & 0x04 != 0 { s.push_str("RST "); }
    if flags & 0x08 != 0 { s.push_str("PSH "); }
    if flags & 0x10 != 0 { s.push_str("ACK "); }
    if flags & 0x20 != 0 { s.push_str("URG "); }
    s.trim_end().to_string()
}
