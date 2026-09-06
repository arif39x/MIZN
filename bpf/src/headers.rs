#[repr(C)]
pub struct EthernetHeader {
    pub destination: [u8; 6],
    pub source:      [u8; 6],
    pub ether_type:  u16,
}

#[repr(C)]
pub struct Ipv4Header {
    pub version_ihl:         u8,
    pub tos:                 u8,
    pub total_length:        u16,
    pub identification:      u16,
    pub fragment_offset:     u16,
    pub ttl:                 u8,
    pub protocol:            u8,
    pub checksum:            u16,
    pub source_address:      u32,
    pub destination_address: u32,
}

#[repr(C)]
pub struct Ipv6Header {
    pub version_tc_fl:       u32,
    pub payload_length:      u16,
    pub next_header:         u8,
    pub hop_limit:           u8,
    pub source_address:      [u8; 16],
    pub destination_address: [u8; 16],
}

#[repr(C)]
pub struct TcpHeader {
    pub source_port:          u16,
    pub destination_port:     u16,
    pub sequence_number:      u32,
    pub acknowledgment_number: u32,
    pub data_offset_reserved: u8,
    pub flags:                u8,
    pub window_size:          u16,
    pub checksum:             u16,
    pub urgent_pointer:       u16,
}

#[repr(C)]
pub struct UdpHeader {
    pub source_port:      u16,
    pub destination_port: u16,
    pub length:           u16,
    pub checksum:         u16,
}

#[repr(C)]
pub struct IcmpHeader {
    pub icmp_type:  u8,
    pub code:       u8,
    pub checksum:   u16,
    pub identifier: u16,
    pub sequence:   u16,
}

#[repr(C)]
pub struct GreHeader {
    pub flags_version: u16,
    pub protocol:      u16,
}

#[repr(C)]
pub struct VxlanHeader {
    pub flags:   u32,
    pub vni_rsvd: u32,
}
