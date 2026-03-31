use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use mizn_common::bpf::FlowKey;
use core::mem;
use crate::headers::{IcmpHeader, Ipv6Header};
use crate::maps::BLOCKLIST_V6;
use crate::metrics::update_metrics;
use crate::parsing::{ptr_at, PROTO_ICMP6, PROTO_TCP, PROTO_UDP};
use crate::parsing::transport::{handle_transport_v4, TransportArgs};

#[inline(always)]
pub unsafe fn parse_ipv6(ctx: &XdpContext, ip_offset: usize, depth: u8) -> Result<u32, ()> {
    // Only support 1 level of encapsulation
    if depth > 0 { return Ok(xdp_action::XDP_PASS); }

    let ip6: *const Ipv6Header = ptr_at(ctx, ip_offset)?;

    if BLOCKLIST_V6.get(&(*ip6).source_address).is_some() {
        return Ok(xdp_action::XDP_DROP);
    }

    let next    = (*ip6).next_header;
    let xport   = ip_offset + mem::size_of::<Ipv6Header>();
    let pkt_len = (ctx.data_end() - ctx.data()) as u64;

    let src_lo = u32::from_be_bytes([
        (*ip6).source_address[12], (*ip6).source_address[13],
        (*ip6).source_address[14], (*ip6).source_address[15],
    ]);
    let dst_lo = u32::from_be_bytes([
        (*ip6).destination_address[12], (*ip6).destination_address[13],
        (*ip6).destination_address[14], (*ip6).destination_address[15],
    ]);

    match next {
        PROTO_TCP | PROTO_UDP => handle_transport_v4(ctx, &TransportArgs {
            xport_off: xport, protocol: next, src_ip: src_lo, dst_ip: dst_lo, pkt_len
        }),
        PROTO_ICMP6 => {
            let icmp: *const IcmpHeader = ptr_at(ctx, xport)?;
            let key = FlowKey {
                source_ip:          src_lo,
                destination_ip:     dst_lo,
                source_port:        (*icmp).icmp_type as u16,
                destination_port:   (*icmp).code as u16,
                protocol:           PROTO_ICMP6,
                _alignment_padding: [0; 3],
            };
            update_metrics(&key, pkt_len, 0);
            Ok(xdp_action::XDP_PASS)
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}
