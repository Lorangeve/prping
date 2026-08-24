//! pcap 文件读写（对标 scapy `wrpcap` / `rdpcap`）。
//!
//! 支持微秒/纳秒时间戳、大小端两种 magic；记录只存原始字节，
//! 反解展示由调用方（`--eng --pcap` / `--pkt` 回显）用 `packet_dsl::dissect` 完成。

use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// 链路类型（pcap network 字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// LINKTYPE_ETHERNET。
    Ethernet = 1,
    /// LINKTYPE_RAW（裸 IP）。
    Raw = 101,
}

/// 一条 pcap 记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapRecord {
    /// 秒（相对 epoch）。
    pub ts_sec: u32,
    /// 微秒或纳秒（取决于文件精度）。
    pub ts_frac: u32,
    /// 捕获的原始字节。
    pub data: Vec<u8>,
}

/// 读取 pcap 文件，返回 (链路类型, 时间戳精度, 记录)。
pub fn read_pcap(path: &Path) -> anyhow::Result<(u16, bool, Vec<PcapRecord>)> {
    let mut r = BufReader::new(std::fs::File::open(path)?);
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    let (le, nano) = match u32::from_le_bytes(magic) {
        0xa1b2c3d4 => (true, false),
        0xa1b23c4d => (true, true),
        _ => match u32::from_be_bytes(magic) {
            0xa1b2c3d4 => (false, false),
            0xa1b23c4d => (false, true),
            _ => anyhow::bail!(
                "不是 pcap 文件（magic 0x{:08x}）",
                u32::from_be_bytes(magic)
            ),
        },
    };
    fn rd(r: &mut impl Read, n: usize) -> anyhow::Result<Vec<u8>> {
        let mut b = vec![0u8; n];
        r.read_exact(&mut b)?;
        Ok(b)
    }
    let u16v = |b: &[u8]| {
        if le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    };
    let u32v = |b: &[u8]| {
        if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let hdr = rd(&mut r, 20)?; // version_major(2) minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
    let _linktype = u32v(&hdr[16..20]);
    let network = u16v(&hdr[16..18]) as u16;
    let mut records = Vec::new();
    loop {
        let mut rec = [0u8; 16];
        match r.read_exact(&mut rec) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let ts_sec = u32v(&rec[0..4]);
        let ts_frac = u32v(&rec[4..8]);
        let incl_len = u32v(&rec[8..12]) as usize;
        let _orig_len = u32v(&rec[12..16]);
        let data = rd(&mut r, incl_len)?;
        records.push(PcapRecord {
            ts_sec,
            ts_frac,
            data,
        });
    }
    Ok((network, nano, records))
}

/// 写 pcap 文件（微秒精度、little-endian）。
pub fn write_pcap(path: &Path, linktype: LinkType, packets: &[Vec<u8>]) -> anyhow::Result<()> {
    let mut w = BufWriter::new(std::fs::File::create(path)?);
    w.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // magic
    w.write_all(&2u16.to_le_bytes())?; // version major
    w.write_all(&4u16.to_le_bytes())?; // version minor
    w.write_all(&0i32.to_le_bytes())?; // thiszone
    w.write_all(&0u32.to_le_bytes())?; // sigfigs
    w.write_all(&65535u32.to_le_bytes())?; // snaplen
    w.write_all(&(linktype as u16 as u32).to_le_bytes())?; // network
    for p in packets {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        w.write_all(&(now.as_secs() as u32).to_le_bytes())?;
        w.write_all(&(now.subsec_micros()).to_le_bytes())?;
        w.write_all(&(p.len() as u32).to_le_bytes())?; // incl_len
        w.write_all(&(p.len() as u32).to_le_bytes())?; // orig_len
        w.write_all(p)?;
    }
    w.flush()?;
    Ok(())
}

/// 按最外层推断链路类型。
pub fn linktype_of(layers: &[packet_dsl::ir::Layer]) -> LinkType {
    match layers.last() {
        Some(packet_dsl::ir::Layer::Ethernet(_)) => LinkType::Ethernet,
        _ => LinkType::Raw,
    }
}
