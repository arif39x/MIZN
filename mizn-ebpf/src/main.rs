#![no_std]
#![no_main]

mod maps;
mod headers;
mod metrics;
mod parsing;

use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn mizn_ebpf(ctx: XdpContext) -> u32 {
    match parsing::process_packet(&ctx) {
        Ok(action) => action,
        Err(_)     => xdp_action::XDP_PASS,
    }
}
