use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const PCAP_MAGIC:    u32 = 0xA1B2C3D4;
const PCAP_MAJOR:    u16 = 2;
const PCAP_MINOR:    u16 = 4;
const PCAP_SNAPLEN:  u32 = 65535;
const PCAP_LINKTYPE: u32 = 101;

pub struct PcapWriter {
    writer: BufWriter<File>,
}

impl PcapWriter {
    pub fn create_in(dir: &str) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;

        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let path = format!("{}/mizn-capture-{}.pcap", dir, ts);
        let file = File::create(&path)?;
        eprintln!("[miznd][pcap] Writing capture to: {}", path);

        let mut writer = BufWriter::new(file);

        writer.write_all(&PCAP_MAGIC.to_le_bytes())?;
        writer.write_all(&PCAP_MAJOR.to_le_bytes())?;
        writer.write_all(&PCAP_MINOR.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        writer.write_all(&PCAP_SNAPLEN.to_le_bytes())?;
        writer.write_all(&PCAP_LINKTYPE.to_le_bytes())?;

        Ok(Self { writer })
    }

    #[allow(dead_code)] pub fn write_packet(&mut self, data: &[u8]) -> std::io::Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let ts_sec   = now.as_secs() as u32;
        let ts_usec  = now.subsec_micros();
        let orig_len = data.len() as u32;
        let incl_len = orig_len.min(PCAP_SNAPLEN);

        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&ts_usec.to_le_bytes())?;
        self.writer.write_all(&incl_len.to_le_bytes())?;
        self.writer.write_all(&orig_len.to_le_bytes())?;
        self.writer.write_all(&data[..incl_len as usize])?;

        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
