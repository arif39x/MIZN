use aya_ebpf::programs::XdpContext;
use mizn_common::bpf::{FlowKey, FlowMetrics};
use crate::maps::FLOW_METRICS;

// Avoid compiler-generated memset calls. bpf-linker rejects memset in eBPF
// programs, so initialize every field explicitly.
#[inline(always)]
unsafe fn new_metrics(bytes: u64, packets: u64, tcp_flags: u8) -> FlowMetrics {
    let mut value = core::mem::MaybeUninit::<FlowMetrics>::uninit();
    let ptr = value.as_mut_ptr();

    (*ptr).bytes = bytes;
    (*ptr).packets = packets;
    (*ptr).tcp_flags = tcp_flags;
    (*ptr)._explicit_padding_0 = 0;
    (*ptr)._explicit_padding_1 = 0;
    (*ptr)._explicit_padding_2 = 0;

    let mut i = 0;
    while i < 64 {
        (*ptr).sni[i] = 0;
        i += 1;
    }

    value.assume_init()
}

#[inline(always)]
pub unsafe fn update_metrics(key: &FlowKey, pkt_len: u64, flags: u8) {
    if let Some(m) = FLOW_METRICS.get_ptr_mut(key) {
        (*m).bytes    += pkt_len;
        (*m).packets  += 1;
        (*m).tcp_flags |= flags;
    } else {
        let fresh = new_metrics(pkt_len, 1, flags);
        let _ = FLOW_METRICS.insert(key, &fresh, 0);
    }
}

#[inline(always)]
pub unsafe fn update_metrics_with_sni(
    ctx: &XdpContext,
    key: &FlowKey,
    pkt_len: u64,
    flags: u8,
    protocol: u8,
    dst_port: u16,
    payload_off: usize,
) {
    if let Some(m) = FLOW_METRICS.get_ptr_mut(key) {
        (*m).bytes    += pkt_len;
        (*m).packets  += 1;
        (*m).tcp_flags |= flags;
    } else {
        let mut fresh = new_metrics(pkt_len, 1, flags);
        let _ = FLOW_METRICS.insert(key, &fresh, 0);
    }
}
