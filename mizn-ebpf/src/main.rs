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
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    ether_type: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    ihl_version: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    res1_doff: u8,
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn mizn_ebpf(ctx: XdpContext) -> u32 {
    match try_mizn_ebpf(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_mizn_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    unsafe {
        let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
        if u16::from_be((*eth_hdr).ether_type) != 0x0800 {
            return Ok(xdp_action::XDP_PASS);
        }

        let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, mem::size_of::<EthHdr>())?;
        if (*ipv4_hdr).protocol != 6 {
            return Ok(xdp_action::XDP_PASS);
        }

        let ihl = ((*ipv4_hdr).ihl_version & 0x0F) as usize;
        let ipv4_len = ihl << 2;

        let tcp_hdr_offset = mem::size_of::<EthHdr>() + ipv4_len;
        let tcp_hdr: *const TcpHdr = ptr_at(&ctx, tcp_hdr_offset)?;

        let doff = ((*tcp_hdr).res1_doff >> 4) as usize;
        let tcp_len = doff << 2;
        let payload_offset = tcp_hdr_offset + tcp_len;

        let packet_len = (ctx.data_end() - ctx.data()) as u64;

        let key = FlowKey {
            source_ip: (*ipv4_hdr).saddr,
            destination_ip: (*ipv4_hdr).daddr,
            source_port: u16::from_be((*tcp_hdr).source),
            destination_port: u16::from_be((*tcp_hdr).dest),
            protocol: 6,
            _padding: [0; 3],
        };

        let metrics_ptr = FLOW_METRICS.get_ptr_mut(&key);

        if let Some(metrics) = metrics_ptr {
            (*metrics).bytes += packet_len;
            (*metrics).packets += 1;
            (*metrics).tcp_flags |= (*tcp_hdr).flags;

            if u16::from_be((*tcp_hdr).dest) == 443 {
                extract_sni(&ctx, payload_offset, metrics);
            }
        } else {
            let mut new_metrics = FlowMetrics {
                bytes: packet_len,
                packets: 1,
                tcp_flags: (*tcp_hdr).flags,
                _padding: [0; 7],
                sni: [0; 64],
            };

            if u16::from_be((*tcp_hdr).dest) == 443 {
                extract_sni(&ctx, payload_offset, &mut new_metrics as *mut _);
            }

            let _ = FLOW_METRICS.insert(&key, &new_metrics, 0);
        }

        Ok(xdp_action::XDP_PASS)
    }
}

#[inline(always)]
unsafe fn extract_sni(ctx: &XdpContext, offset: usize, metrics: *mut FlowMetrics) {
    unsafe {
        if let Ok(tls_type_ptr) = ptr_at::<u8>(ctx, offset) {
            if *tls_type_ptr == 0x16 {
                let mut i = 0;
                while i < 16 {
                    if let Ok(c_ptr) = ptr_at::<u8>(ctx, offset + 5 + i) {
                        let c = *c_ptr;
                        if c >= 32 && c <= 126 {
                            (*metrics).sni[i] = c;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                    i += 1;
                }
            }
        }
    }
}
