#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

use core::mem;
use mizn_common::bpf::{FlowKey, FlowMetrics};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static FLOW_METRICS: HashMap<FlowKey, FlowMetrics> = HashMap::with_max_entries(10240, 0);

#[repr(C)]
struct EthernetHeader {
    destination: [u8; 6],
    source: [u8; 6],
    ether_type: u16,
}

#[repr(C)]
struct Ipv4Header {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    identification: u16,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source_address: u32,
    destination_address: u32,
}

#[repr(C)]
struct TcpHeader {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset_reserved: u8,
    flags: u8,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data() as *const u8;
    let end = ctx.data_end() as *const u8;
    let ptr = unsafe { start.add(offset) } as *const T;

    if unsafe { (ptr as *const u8).add(mem::size_of::<T>()) } > end {
        return Err(());
    }

    Ok(ptr)
}

#[xdp]
pub fn mizn_ebpf(ctx: XdpContext) -> u32 {
    match process_packet(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn process_packet(ctx: XdpContext) -> Result<u32, ()> {
    unsafe {
        let eth: *const EthernetHeader = ptr_at(&ctx, 0)?;
        if u16::from_be((*eth).ether_type) != 0x0800 {
            return Ok(xdp_action::XDP_PASS);
        }

        let ip: *const Ipv4Header = ptr_at(&ctx, mem::size_of::<EthernetHeader>())?;
        if (*ip).protocol != 6 {
            return Ok(xdp_action::XDP_PASS);
        }

        let ip_header_length = (((*ip).version_ihl & 0x0F) as usize) << 2;
        let tcp_offset = mem::size_of::<EthernetHeader>() + ip_header_length;
        let tcp: *const TcpHeader = ptr_at(&ctx, tcp_offset)?;

        let tcp_header_length = (((*tcp).data_offset_reserved >> 4) as usize) << 2;
        let payload_offset = tcp_offset + tcp_header_length;
        let packet_length = (ctx.data_end() - ctx.data()) as u64;

        let flow_key = FlowKey {
            source_ip: (*ip).source_address,
            destination_ip: (*ip).destination_address,
            source_port: u16::from_be((*tcp).source_port),
            destination_port: u16::from_be((*tcp).destination_port),
            protocol: 6,
            _alignment_padding: [0; 3],
        };

        let metrics_ref = FLOW_METRICS.get_ptr_mut(&flow_key);

        if let Some(metrics) = metrics_ref {
            (*metrics).bytes += packet_length;
            (*metrics).packets += 1;
            (*metrics).tcp_flags |= (*tcp).flags;

            if u16::from_be((*tcp).destination_port) == 443 {
                parse_tls_sni(&ctx, payload_offset, metrics);
            }
        } else {
            let mut fresh_metrics = FlowMetrics {
                bytes: packet_length,
                packets: 1,
                tcp_flags: (*tcp).flags,
                _explicit_padding_0: 0,
                _explicit_padding_1: 0,
                _explicit_padding_2: 0,
                sni: [0; 64],
            };

            if u16::from_be((*tcp).destination_port) == 443 {
                parse_tls_sni(&ctx, payload_offset, &mut fresh_metrics);
            }

            let _ = FLOW_METRICS.insert(&flow_key, &fresh_metrics, 0);
        }

        Ok(xdp_action::XDP_PASS)
    }
}

#[inline(always)]
unsafe fn parse_tls_sni(ctx: &XdpContext, offset: usize, metrics: *mut FlowMetrics) {
    if let Ok(tls_type) = unsafe { ptr_at::<u8>(ctx, offset) } {
        if unsafe { *tls_type } == 0x16 {
            let sni_start = offset + 5;
            for j in 0usize..16 {
                if let Ok(bp) = unsafe { ptr_at::<u8>(ctx, sni_start + j) } {
                    let val = unsafe { *bp };
                    let is_printable = (val.wrapping_sub(32) < 95) as u8;
                    unsafe { (*metrics).sni[j] = val * is_printable };
                } else {
                    break;
                }
            }
        }
    }
}
