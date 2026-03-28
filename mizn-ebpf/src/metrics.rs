use aya_ebpf::programs::XdpContext;
use mizn_common::bpf::{FlowKey, FlowMetrics};
use crate::maps::FLOW_METRICS;
use crate::parsing::ptr_at;
use core::slice;

#[inline(always)]
pub unsafe fn update_metrics(key: &FlowKey, pkt_len: u64, flags: u8) {
    if let Some(m) = FLOW_METRICS.get_ptr_mut(key) {
        (*m).bytes    += pkt_len;
        (*m).packets  += 1;
        (*m).tcp_flags |= flags;
    } else {
        let fresh = FlowMetrics {
            bytes:               pkt_len,
            packets:             1,
            tcp_flags:           flags,
            _explicit_padding_0: 0,
            _explicit_padding_1: 0,
            _explicit_padding_2: 0,
            sni:                 [0; 64],
        };
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
        if protocol == 6 && dst_port == 443 {
            parse_tls_sni(ctx, payload_off, m);
        }
    } else {
        let mut fresh = FlowMetrics {
            bytes:               pkt_len,
            packets:             1,
            tcp_flags:           flags,
            _explicit_padding_0: 0,
            _explicit_padding_1: 0,
            _explicit_padding_2: 0,
            sni:                 [0; 64],
        };
        if protocol == 6 && dst_port == 443 {
            parse_tls_sni(ctx, payload_off, &mut fresh);
        }
        let _ = FLOW_METRICS.insert(key, &fresh, 0);
    }
}

#[inline(always)]
unsafe fn parse_tls_sni(ctx: &XdpContext, offset: usize, metrics: *mut FlowMetrics) {
    if let Ok(tls_type) = ptr_at::<u8>(ctx, offset) {
        if *tls_type == 0x16 {
            let sni_start = offset + 5;
            
            // To prevent verifier explosion, copy exactly 16 bytes maximum, unconditionally doing the bounds check once
            if let Ok(sni_bytes) = ptr_at::<[u8; 16]>(ctx, sni_start) {
                // Copy all 16 bytes at once using an intrinsic that the verifier respects
                core::ptr::copy_nonoverlapping(
                    sni_bytes as *const u8,
                    (*metrics).sni.as_mut_ptr(),
                    16
                );
                
                // Sanitize bytes directly on the safe map-value pointer memory
                for j in 0..16 {
                    let val = (*metrics).sni[j];
                    let printable = (val.wrapping_sub(32) < 95) as u8;
                    (*metrics).sni[j] = val * printable;
                }
            }
        }
    }
}

