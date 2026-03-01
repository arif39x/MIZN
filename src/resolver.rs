use procfs::process::Process;
use std::collections::HashMap;

pub type SocketsMap = HashMap<u16, (i32, String)>;

pub fn refresh_sockets_map() -> SocketsMap {
    let mut inode_to_socket = HashMap::new();
    
    if let Ok(tcp) = procfs::net::tcp() {
        for entry in tcp { inode_to_socket.insert(entry.inode, entry.local_address.port()); }
    }
    if let Ok(tcp6) = procfs::net::tcp6() {
        for entry in tcp6 { inode_to_socket.insert(entry.inode, entry.local_address.port()); }
    }
    if let Ok(udp) = procfs::net::udp() {
        for entry in udp { inode_to_socket.insert(entry.inode, entry.local_address.port()); }
    }
    if let Ok(udp6) = procfs::net::udp6() {
        for entry in udp6 { inode_to_socket.insert(entry.inode, entry.local_address.port()); }
    }
    
    let mut map = HashMap::new();
    if let Ok(procs) = procfs::process::all_processes() {
        for p in procs.flatten() {
            let pid = p.pid;
            let name = p.stat().ok().map(|s| s.comm).unwrap_or_else(|| "Unknown".to_string());
            if let Ok(fds) = p.fd() {
                for fd in fds.flatten() {
                    if let procfs::process::FDTarget::Socket(inode) = fd.target {
                        if let Some(&port) = inode_to_socket.get(&inode) {
                            map.insert(port, (pid, name.clone()));
                        }
                    }
                }
            }
        }
    }
    map
}
