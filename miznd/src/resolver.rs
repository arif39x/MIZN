use procfs::process::FDTarget;
use std::collections::HashMap;

pub type SocketsMap = HashMap<u16, (i32, String)>;

pub fn refresh_sockets_map() -> SocketsMap {
    let mut active_inode_to_local_port_registry: HashMap<u64, u16> = HashMap::with_capacity(8192);

    if let Ok(tcp_ipv4_registry) = procfs::net::tcp() {
        for tcp_socket_entry in tcp_ipv4_registry {
            active_inode_to_local_port_registry.insert(
                tcp_socket_entry.inode,
                tcp_socket_entry.local_address.port(),
            );
        }
    }
    if let Ok(tcp_ipv6_registry) = procfs::net::tcp6() {
        for tcp_socket_entry in tcp_ipv6_registry {
            active_inode_to_local_port_registry.insert(
                tcp_socket_entry.inode,
                tcp_socket_entry.local_address.port(),
            );
        }
    }
    if let Ok(udp_ipv4_registry) = procfs::net::udp() {
        for udp_socket_entry in udp_ipv4_registry {
            active_inode_to_local_port_registry.insert(
                udp_socket_entry.inode,
                udp_socket_entry.local_address.port(),
            );
        }
    }
    if let Ok(udp_ipv6_registry) = procfs::net::udp6() {
        for udp_socket_entry in udp_ipv6_registry {
            active_inode_to_local_port_registry.insert(
                udp_socket_entry.inode,
                udp_socket_entry.local_address.port(),
            );
        }
    }

    let mut port_to_process_telemetry_mapping =
        HashMap::with_capacity(active_inode_to_local_port_registry.len());

    if let Ok(system_process_table) = procfs::process::all_processes() {
        for process_descriptor in system_process_table.flatten() {
            let process_identifier = process_descriptor.pid;
            let mut resolved_process_nomenclature: Option<String> = None;

            if let Ok(process_file_descriptors) = process_descriptor.fd() {
                for file_descriptor_entry in process_file_descriptors.flatten() {
                    if let FDTarget::Socket(socket_inode_identifier) = file_descriptor_entry.target
                    {
                        if let Some(&bound_local_port) =
                            active_inode_to_local_port_registry.get(&socket_inode_identifier)
                        {
                            if resolved_process_nomenclature.is_none() {
                                resolved_process_nomenclature = Some(
                                    process_descriptor
                                        .stat()
                                        .ok()
                                        .map(|stat_metrics| stat_metrics.comm)
                                        .unwrap_or_else(|| String::from("unresolved_process")),
                                );
                            }

                            if let Some(ref nomenclature_reference) = resolved_process_nomenclature
                            {
                                port_to_process_telemetry_mapping.insert(
                                    bound_local_port,
                                    (process_identifier, nomenclature_reference.clone()),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    port_to_process_telemetry_mapping
}
