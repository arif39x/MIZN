use aya::{include_bytes_aligned, Ebpf};
use aya::programs::{Xdp, XdpFlags};

pub struct BpfContext {
    pub ebpf: Ebpf,
}

impl BpfContext {
    pub fn load_and_attach(iface: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/mizn-ebpf"
        ))?;
        
        let program: &mut Xdp = bpf.program_mut("mizn_ebpf").unwrap().try_into()?;
        program.load()?;
        program.attach(iface, XdpFlags::default())?;
        
        Ok(Self { ebpf: bpf })
    }

}
