#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod bpf;

#[cfg(feature = "std")]
pub mod ipc;
