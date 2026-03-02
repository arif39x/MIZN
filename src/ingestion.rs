use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use pcap::{Capture, Device};
use std::net::IpAddr;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy)]
pub struct PacketInfo {
    pub payload_length_bytes: u64,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub transport_protocol: &'static str,
    pub source_port: u16,
    pub destination_port: u16,
}

pub fn start_sniffing(telemetry_transmitter: mpsc::Sender<PacketInfo>) {
    std::thread::spawn(move || {
        let capture_device = Device::list()
            .unwrap_or_default()
            .into_iter()
            .find(|network_interface| {
                !network_interface.addresses.is_empty() && network_interface.name != "lo"
            })
            .unwrap_or_else(|| {
                eprintln!("FATAL_ERROR: hardware_interface_resolution_failure");
                std::process::exit(1);
            });

        let packet_capture_session_result = Capture::from_device(capture_device.clone())
            .unwrap()
            .promisc(true)
            .immediate_mode(true)
            .open();

        let mut packet_capture_session = match packet_capture_session_result {
            Ok(active_session) => active_session,
            Err(kernel_rejection_error) => {
                eprintln!(
                    "FATAL_ERROR: capture_session_activation_failure on [{}]",
                    capture_device.name
                );
                eprintln!("KERNEL_DIAGNOSTIC: {}", kernel_rejection_error);
                eprintln!("RESOLUTION_REQUIRED: execute_with_elevated_capabilities (sudo)");
                std::process::exit(130);
            }
        };

        while let Ok(raw_ethernet_frame) = packet_capture_session.next_packet() {
            if let Ok(parsed_headers) = PacketHeaders::from_ethernet_slice(&raw_ethernet_frame.data)
            {
                let (source_ip, destination_ip) = match parsed_headers.net {
                    Some(NetHeaders::Ipv4(ipv4_header, _)) => (
                        IpAddr::V4(ipv4_header.source.into()),
                        IpAddr::V4(ipv4_header.destination.into()),
                    ),
                    Some(NetHeaders::Ipv6(ipv6_header, _)) => (
                        IpAddr::V6(ipv6_header.source.into()),
                        IpAddr::V6(ipv6_header.destination.into()),
                    ),
                    _ => continue,
                };

                let (source_port, destination_port, transport_protocol) =
                    match parsed_headers.transport {
                        Some(TransportHeader::Tcp(tcp_header)) => {
                            (tcp_header.source_port, tcp_header.destination_port, "TCP")
                        }
                        Some(TransportHeader::Udp(udp_header)) => {
                            (udp_header.source_port, udp_header.destination_port, "UDP")
                        }
                        _ => continue,
                    };

                let frame_info = PacketInfo {
                    payload_length_bytes: raw_ethernet_frame.header.len as u64,
                    source_ip,
                    destination_ip,
                    transport_protocol,
                    source_port,
                    destination_port,
                };

                if telemetry_transmitter.blocking_send(frame_info).is_err() {
                    break;
                }
            }
        }
    });
}
