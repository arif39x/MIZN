use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device};
use std::net::IpAddr;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: u64,
}

pub fn start_sniffing(tx: mpsc::UnboundedSender<PacketInfo>) {
    std::thread::spawn(move || {
        let devices = Device::list().unwrap_or_default();
        let device = devices
            .into_iter()
            .find(|d| d.name != "any" && d.name != "lo" && !d.addresses.is_empty())
            .unwrap_or_else(|| Device::lookup().unwrap().unwrap());

        let mut cap = Capture::from_device(device.clone())
            .unwrap()
            .promisc(true)
            .snaplen(65535)
            .immediate_mode(true)
            .open()
            .unwrap();

        while let Ok(packet) = cap.next_packet() {
            let len = packet.header.len as u64;
            if let Ok(sliced) = SlicedPacket::from_ethernet(&packet.data) {
                let (src_ip, dst_ip) = match sliced.net {
                    Some(NetSlice::Ipv4(h)) => {
                        (IpAddr::V4(h.header().source_addr()), IpAddr::V4(h.header().destination_addr()))
                    }
                    Some(NetSlice::Ipv6(h)) => {
                        (IpAddr::V6(h.header().source_addr()), IpAddr::V6(h.header().destination_addr()))
                    }
                    _ => continue,
                };
                let (src_port, dst_port, protocol) = match sliced.transport {
                    Some(TransportSlice::Tcp(t)) => {
                        (t.source_port(), t.destination_port(), "TCP".to_string())
                    }
                    Some(TransportSlice::Udp(u)) => {
                        (u.source_port(), u.destination_port(), "UDP".to_string())
                    }
                    _ => continue,
                };
                let info = PacketInfo {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    length: len,
                };
                if tx.send(info).is_err() {
                    break;
                }
            }
        }
    });
}
