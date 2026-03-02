#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug, Hash))]
pub struct FlowKey {
    pub source_ip: u32,
    pub destination_ip: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub _padding: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct FlowMetrics {
    pub bytes: u64,
    pub packets: u64,
    pub tcp_flags: u8,
    pub _padding: [u8; 7],
    pub sni: [u8; 64],
}
