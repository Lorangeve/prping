//! 默认序列化器：把 `PacketSpec` 变成字节。
//!
//! 自动值约定（IR 里为 `None` 的字段在此补齐）：
//! - 随机：TCP/UDP 源端口、TCP seq、IPv4 id、ICMP id、以太网源 MAC。
//! - 默认：TTL/hop_limit=64、TCP flags=SYN、window=65535、以太网目的=广播。
//! - 自动：IPv4/IPv6 的 proto/next_header 与以太网 ethertype 由内层推导；checksum/length 全自动。
//! - 无外层 IP 包裹 TCP/UDP 时，checksum 伪头部用零地址（IPv4 语义）。

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ir::*;

/// 序列化器 trait（宿主实现或使用 [`DefaultSerializer`]）。
pub trait Serializer {
    fn serialize(&self, spec: &PacketSpec) -> Result<Vec<u8>, SerializeError>;
}

/// 序列化错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SerializeError {
    #[error("空包：没有可序列化的层")]
    EmptyPacket,
    #[error("DNS 域名标签超过 63 字节：`{0}`")]
    DnsLabelTooLong(String),
    #[error("无法确定以太网 ethertype（载荷无法推导，请显式指定 ethertype）")]
    UnknownEthertype,
}

/// 序列化结果：最终字节 + 每层头字节区间（供逐层反解展示）。
pub type SerializedParts = (Vec<u8>, Vec<(usize, usize)>);

/// 默认序列化器：可注入随机种子（`with_seed`），测试用固定种子获得确定字节。
pub struct DefaultSerializer {
    rng: std::cell::RefCell<XorShift64>,
    /// fuzz 模式（对标 scapy `fuzz()`）：未填字段全部随机化。
    fuzz: bool,
}

impl DefaultSerializer {
    /// 以当前时间为种子。
    pub fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        Self::with_seed(seed)
    }

    /// 固定种子（确定性输出）。
    pub fn with_seed(seed: u64) -> Self {
        Self {
            rng: std::cell::RefCell::new(XorShift64::new(seed)),
            fuzz: false,
        }
    }

    /// fuzz 模式（时间种子）。
    pub fn new_fuzz() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        Self::with_seed_fuzz(seed)
    }

    /// fuzz 模式（对标 scapy `fuzz()`）：未填字段（Auto）也随机化。
    pub fn with_seed_fuzz(seed: u64) -> Self {
        Self {
            rng: std::cell::RefCell::new(XorShift64::new(seed)),
            fuzz: true,
        }
    }
}

impl Default for DefaultSerializer {
    fn default() -> Self {
        Self::new()
    }
}

impl Serializer for DefaultSerializer {
    fn serialize(&self, spec: &PacketSpec) -> Result<Vec<u8>, SerializeError> {
        self.serialize_parts(spec).map(|(b, _)| b)
    }
}

impl DefaultSerializer {
    /// 序列化整个包，并返回每层「头字节」在结果中的区间 `(start, end)`（内 → 外）。
    ///
    /// 供宿主逐层反解展示：字节直喂层的字段（len/checksum/proto 等）应从
    /// 序列化后的最终字节读取，而不是构建态占位字节。
    pub fn serialize_parts(&self, spec: &PacketSpec) -> Result<SerializedParts, SerializeError> {
        if spec.layers.is_empty() {
            return Err(SerializeError::EmptyPacket);
        }
        // 预解析显式 Random 字段为具体值（一次消费 RNG）——
        // 保证传输层伪头部与 IP 头里解析出的随机地址一致
        let resolved = self.resolve_random(spec);
        let mut bytes = Vec::new();
        let mut lens = Vec::with_capacity(resolved.layers.len());
        for (i, layer) in resolved.layers.iter().enumerate() {
            bytes = self.serialize_layer(i, layer, &bytes, &resolved.layers)?;
            lens.push(bytes.len());
        }
        // 序列化结果 = 外层头 + 内层全部；每层头长 = lens[i] - lens[i-1]，
        // 最外层头在最前。从外层往回切出每层头区间。
        let n = resolved.layers.len();
        let mut parts = vec![(0usize, 0usize); n];
        let mut start = 0usize;
        for i in (0..n).rev() {
            let head_len = lens[i] - if i == 0 { 0 } else { lens[i - 1] };
            parts[i] = (start, start + head_len);
            start += head_len;
        }
        Ok((bytes, parts))
    }
}

impl DefaultSerializer {
    fn rng(&self) -> std::cell::RefMut<'_, XorShift64> {
        self.rng.borrow_mut()
    }

    /// 字段是否该随机化（显式 Random，或 fuzz 模式下的 Auto）。
    fn is_rand<T: PartialEq>(f: &Field<T>, fuzz: bool) -> bool {
        *f == Field::Random || (fuzz && *f == Field::Auto)
    }

    /// 把 `Field::Random` 解析成具体随机值（fuzz 模式下 Auto 一并随机）。
    fn resolve_random(&self, spec: &PacketSpec) -> PacketSpec {
        use crate::ir::Field;
        let fuzz = self.fuzz;
        let layers = spec
            .layers
            .iter()
            .map(|l| match l {
                Layer::Ethernet(f) => {
                    let mut f = f.clone();
                    if Self::is_rand(&f.src_mac, fuzz) {
                        f.src_mac = Field::Value(self.random_mac());
                    }
                    if Self::is_rand(&f.dst_mac, fuzz) {
                        f.dst_mac = Field::Value(self.random_mac());
                    }
                    Layer::Ethernet(f)
                }
                Layer::Ipv4(f) => {
                    let mut f = f.clone();
                    if Self::is_rand(&f.src, fuzz) {
                        f.src = Field::Value(self.random_ip4());
                    }
                    if Self::is_rand(&f.dst, fuzz) {
                        f.dst = Field::Value(self.random_ip4());
                    }
                    if Self::is_rand(&f.ttl, fuzz) {
                        f.ttl = Field::Value(self.rng().u8().max(1));
                    }
                    // fuzz：tos/flags 也随机（proto 保留自动以免破坏协议栈）
                    if fuzz && f.tos.is_none() {
                        f.tos = Some(self.rng().u8());
                    }
                    if fuzz && f.flags.is_none() {
                        let df = self.rng().u8() & 1 != 0;
                        let mf = self.rng().u8() & 1 != 0;
                        f.flags = Some(Ipv4Flags {
                            df,
                            mf,
                            frag_offset: 0,
                        });
                    }
                    Layer::Ipv4(f)
                }
                Layer::Ipv6(f) => {
                    let mut f = f.clone();
                    if Self::is_rand(&f.src, fuzz) {
                        f.src = Field::Value(self.random_ip6());
                    }
                    if Self::is_rand(&f.dst, fuzz) {
                        f.dst = Field::Value(self.random_ip6());
                    }
                    if Self::is_rand(&f.hop_limit, fuzz) {
                        f.hop_limit = Field::Value(self.rng().u8().max(1));
                    }
                    Layer::Ipv6(f)
                }
                other => other.clone(),
            })
            .collect();
        PacketSpec { layers }
    }

    /// 随机单播 + locally-administered MAC。
    fn random_mac(&self) -> MacAddr {
        let mut b = [0u8; 6];
        for x in &mut b {
            *x = self.rng().u8();
        }
        b[0] = (b[0] & 0xFC) | 0x02; // 单播 + locally administered
        MacAddr(b)
    }

    /// 随机单播 IPv4（首字节 1..=223）。
    fn random_ip4(&self) -> Ipv4Addr {
        let mut o = [0u8; 4];
        for x in &mut o {
            *x = self.rng().u8();
        }
        o[0] = (self.rng().u8() % 223) + 1;
        Ipv4Addr::from(o)
    }

    /// 随机单播 IPv6（2000::/12 前缀）。
    fn random_ip6(&self) -> Ipv6Addr {
        let mut o = [0u8; 16];
        for x in &mut o {
            *x = self.rng().u8();
        }
        o[0] = 0x20 | (o[0] & 0x0F);
        Ipv6Addr::from(o)
    }

    fn serialize_layer(
        &self,
        i: usize,
        layer: &Layer,
        payload: &[u8],
        layers: &[Layer],
    ) -> Result<Vec<u8>, SerializeError> {
        match layer {
            Layer::Raw(r) => {
                let mut out = Vec::with_capacity(r.bytes.len() + payload.len());
                out.extend_from_slice(&r.bytes);
                out.extend_from_slice(payload);
                Ok(out)
            }
            Layer::Ethernet(f) => self.serialize_eth(i, f, payload, layers),
            Layer::Arp(f) => self.serialize_arp(f, payload),
            Layer::Ipv4(f) => self.serialize_ipv4(i, f, payload, layers),
            Layer::Ipv6(f) => self.serialize_ipv6(i, f, payload, layers),
            Layer::Icmp(f) => self.serialize_icmp(f, payload),
            Layer::Tcp(f) => self.serialize_tcp(i, f, payload, layers),
            Layer::Udp(f) => self.serialize_udp(i, f, payload, layers),
            Layer::Http(f) => self.serialize_http(f, payload),
            Layer::Dns(f) => self.serialize_dns(f, payload),
        }
    }

    // ── 链路层 ──────────────────────────────────────────────

    fn serialize_eth(
        &self,
        i: usize,
        f: &EthernetFields,
        payload: &[u8],
        layers: &[Layer],
    ) -> Result<Vec<u8>, SerializeError> {
        if let Some(raw) = &f.raw {
            // bytes= 直喂：整层头完全由调用方指定，引擎不覆盖（不含自动校验和/length）。
            // 唯一例外：ethertype 字节仍是默认 IPv4 占位（0x0800）而内层是 ARP/IPv6 时，
            // 按内层推导（headers.eth 默认 ethertype=0x0800，IPv6 栈需要 0x86dd）。
            let mut out = raw.clone();
            if out.len() >= 14 && u16::from_be_bytes([out[12], out[13]]) == 0x0800 {
                match layers.get(i.wrapping_sub(1)) {
                    Some(Layer::Arp(_)) => {
                        out[12] = 0x08;
                        out[13] = 0x06;
                    }
                    Some(Layer::Ipv6(_)) => {
                        out[12] = 0x86;
                        out[13] = 0xdd;
                    }
                    _ => {}
                }
            }
            out.extend_from_slice(payload);
            return Ok(out);
        }
        use crate::ir::Field;
        let src = match f.src_mac {
            Field::Value(m) => m,
            _ => self.random_mac(), // Auto 与 Random 都已在 resolve_random 后收敛为随机源
        };
        let dst = match f.dst_mac {
            Field::Value(m) => m,
            _ => MacAddr([0xFF; 6]), // Auto 默认广播
        };
        let ethertype = match f.ethertype {
            Some(t) => t,
            None => match layers.get(i.wrapping_sub(1)) {
                Some(Layer::Arp(_)) => 0x0806,
                Some(Layer::Ipv4(_)) => 0x0800,
                Some(Layer::Ipv6(_)) => 0x86DD,
                _ => return Err(SerializeError::UnknownEthertype),
            },
        };
        let mut out = Vec::with_capacity(14 + payload.len());
        out.extend_from_slice(&dst.0);
        out.extend_from_slice(&src.0);
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    fn serialize_arp(&self, f: &ArpFields, payload: &[u8]) -> Result<Vec<u8>, SerializeError> {
        if let Some(raw) = &f.raw {
            let mut out = raw.clone();
            out.extend_from_slice(payload);
            return Ok(out);
        }
        let op = match f.op.unwrap_or(ArpOp::Request) {
            ArpOp::Request => 1u16,
            ArpOp::Reply => 2u16,
        };
        let sha = f.sha.unwrap_or_default();
        let tha = f.tha.unwrap_or_default();
        let spa = f.spa.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let tpa = f.tpa.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let mut out = Vec::with_capacity(28 + payload.len());
        out.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
        out.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
        out.push(6); // hlen
        out.push(4); // plen
        out.extend_from_slice(&op.to_be_bytes());
        out.extend_from_slice(&sha.0);
        out.extend_from_slice(&spa.octets());
        out.extend_from_slice(&tha.0);
        out.extend_from_slice(&tpa.octets());
        out.extend_from_slice(payload);
        Ok(out)
    }

    // ── 网络层 ──────────────────────────────────────────────

    fn serialize_ipv4(
        &self,
        i: usize,
        f: &Ipv4Fields,
        payload: &[u8],
        layers: &[Layer],
    ) -> Result<Vec<u8>, SerializeError> {
        if let Some(raw) = &f.raw {
            // bytes= 直喂：头字节由调用方指定；引擎自动补 total_length 与 header
            // checksum（依赖载荷长度，函数内无法算）。proto 字节仍是默认占位 0 而
            // 内层是 TCP/UDP/ICMP 时按内层推导（headers.ipv4 默认 proto=0）。
            let mut hdr = raw.clone();
            let total = (hdr.len() + payload.len()) as u16;
            if hdr.len() >= 4 {
                hdr[2] = (total >> 8) as u8;
                hdr[3] = total as u8;
            }
            if hdr.len() >= 10 && hdr[9] == 0 {
                hdr[9] = match layers.get(i.wrapping_sub(1)) {
                    Some(Layer::Tcp(_)) => 6,
                    Some(Layer::Udp(_)) => 17,
                    Some(Layer::Icmp(_)) => 1,
                    _ => 0,
                };
            }
            if hdr.len() >= 12 {
                hdr[10] = 0;
                hdr[11] = 0;
                let c = checksum(&hdr);
                hdr[10] = (c >> 8) as u8;
                hdr[11] = c as u8;
            }
            let mut out = hdr;
            out.extend_from_slice(payload);
            return Ok(out);
        }
        use crate::ir::Field;
        let proto = match f.proto {
            Some(p) => p,
            None => match layers.get(i.wrapping_sub(1)) {
                Some(Layer::Tcp(_)) => 6,
                Some(Layer::Udp(_)) => 17,
                Some(Layer::Icmp(_)) => 1,
                _ => 0,
            },
        };
        let src = match f.src {
            Field::Value(a) => a,
            _ => Ipv4Addr::UNSPECIFIED, // Auto 默认 0.0.0.0
        };
        let dst = match f.dst {
            Field::Value(a) => a,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let ttl = match f.ttl {
            Field::Value(t) => t,
            _ => 64,
        };
        let tos = f.tos.unwrap_or(0);
        let id = f.id.unwrap_or_else(|| self.rng().u16());
        let flags = f.flags.unwrap_or_default();
        let total_len = 20 + payload.len();
        let mut header = Vec::with_capacity(20);
        header.push(0x45);
        header.push(tos);
        header.extend_from_slice(&(total_len as u16).to_be_bytes());
        header.extend_from_slice(&id.to_be_bytes());
        let frag = (u16::from(flags.df) << 14)
            | (u16::from(flags.mf) << 13)
            | (flags.frag_offset & 0x1FFF);
        header.extend_from_slice(&frag.to_be_bytes());
        header.push(ttl);
        header.push(proto);
        header.extend_from_slice(&0u16.to_be_bytes()); // checksum 占位
        header.extend_from_slice(&src.octets());
        header.extend_from_slice(&dst.octets());
        let sum = checksum(&header);
        header[10] = (sum >> 8) as u8;
        header[11] = (sum & 0xFF) as u8;
        let mut out = header;
        out.extend_from_slice(payload);
        Ok(out)
    }

    fn serialize_ipv6(
        &self,
        i: usize,
        f: &Ipv6Fields,
        payload: &[u8],
        layers: &[Layer],
    ) -> Result<Vec<u8>, SerializeError> {
        if let Some(raw) = &f.raw {
            // bytes= 直喂：自动补 payload_length（offset 4-5）。
            // next_header 字节仍是默认占位 59（No Next Header）而内层是
            // TCP/UDP/ICMPv6 时按内层推导（headers.ipv6 默认 next_header=59）。
            let mut hdr = raw.clone();
            let plen = payload.len() as u16;
            if hdr.len() >= 6 {
                hdr[4] = (plen >> 8) as u8;
                hdr[5] = plen as u8;
            }
            if hdr.len() >= 7 && hdr[6] == 59 {
                hdr[6] = match layers.get(i.wrapping_sub(1)) {
                    Some(Layer::Tcp(_)) => 6,
                    Some(Layer::Udp(_)) => 17,
                    Some(Layer::Icmp(_)) => 58, // ICMPv6
                    _ => 59,
                };
            }
            let mut out = hdr;
            out.extend_from_slice(payload);
            return Ok(out);
        }
        use crate::ir::Field;
        let next_header = match f.next_header {
            Some(n) => n,
            None => match layers.get(i.wrapping_sub(1)) {
                Some(Layer::Tcp(_)) => 6,
                Some(Layer::Udp(_)) => 17,
                Some(Layer::Icmp(_)) => 58, // ICMPv6
                _ => 59,                    // No Next Header
            },
        };
        let src = match f.src {
            Field::Value(a) => a,
            _ => Ipv6Addr::UNSPECIFIED,
        };
        let dst = match f.dst {
            Field::Value(a) => a,
            _ => Ipv6Addr::UNSPECIFIED,
        };
        let hop_limit = match f.hop_limit {
            Field::Value(h) => h,
            _ => 64,
        };
        let mut out = Vec::with_capacity(40 + payload.len());
        out.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // ver 6, tc 0, flow 0
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.push(next_header);
        out.push(hop_limit);
        out.extend_from_slice(&src.octets());
        out.extend_from_slice(&dst.octets());
        out.extend_from_slice(payload);
        Ok(out)
    }

    fn serialize_icmp(&self, f: &IcmpFields, payload: &[u8]) -> Result<Vec<u8>, SerializeError> {
        if let Some(raw) = &f.raw {
            // bytes= 直喂：自动补 ICMP checksum（offset 2-3，覆盖头+载荷）
            let mut hdr = raw.clone();
            if hdr.len() >= 4 {
                hdr[2] = 0;
                hdr[3] = 0;
                let mut seg = hdr.clone();
                seg.extend_from_slice(payload);
                let c = checksum(&seg);
                hdr[2] = (c >> 8) as u8;
                hdr[3] = c as u8;
            }
            let mut out = hdr;
            out.extend_from_slice(payload);
            return Ok(out);
        }
        let icmp_type = f.icmp_type.unwrap_or(8); // echo request
        let code = f.code.unwrap_or(0);
        let id = f.id.unwrap_or_else(|| self.rng().u16());
        let seq = f.seq.unwrap_or(0);
        let body = f.payload.clone().unwrap_or_default();
        let mut msg = Vec::with_capacity(8 + body.len() + payload.len());
        msg.push(icmp_type);
        msg.push(code);
        msg.extend_from_slice(&0u16.to_be_bytes()); // checksum 占位
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&seq.to_be_bytes());
        msg.extend_from_slice(&body);
        msg.extend_from_slice(payload);
        let sum = checksum(&msg);
        msg[2] = (sum >> 8) as u8;
        msg[3] = (sum & 0xFF) as u8;
        Ok(msg)
    }

    // ── 传输层 ──────────────────────────────────────────────

    fn serialize_tcp(
        &self,
        i: usize,
        f: &TcpFields,
        payload: &[u8],
        layers: &[Layer],
    ) -> Result<Vec<u8>, SerializeError> {
        if let Some(raw) = &f.raw {
            // bytes= 直喂：自动补 TCP checksum（offset 16-17，含外层 IP 伪头部）
            let mut hdr = raw.clone();
            if hdr.len() >= 18 {
                hdr[16] = 0;
                hdr[17] = 0;
                let mut seg = hdr.clone();
                seg.extend_from_slice(payload);
                let c = transport_checksum(layers, i, 6, &seg);
                hdr[16] = (c >> 8) as u8;
                hdr[17] = c as u8;
            }
            let mut out = hdr;
            out.extend_from_slice(payload);
            return Ok(out);
        }
        let sport = f.src_port.unwrap_or_else(|| self.rng().u16().max(1));
        let dport = f.dst_port.unwrap_or(0);
        let seq = f.seq.unwrap_or_else(|| self.rng().u32());
        let ack = f.ack.unwrap_or(0);
        let flags = f.flags.unwrap_or_else(|| TcpFlags {
            syn: true,
            ..Default::default()
        });
        let window = f.window.unwrap_or(65535);
        let mut options = Vec::new();
        for opt in &f.options {
            match opt {
                TcpOption::Mss(m) => {
                    options.extend_from_slice(&[2, 4]);
                    options.extend_from_slice(&m.to_be_bytes());
                }
            }
        }
        while options.len() % 4 != 0 {
            options.push(0);
        }
        let data_offset = 5 + options.len() / 4;
        let mut seg = Vec::with_capacity(20 + options.len() + payload.len());
        seg.extend_from_slice(&sport.to_be_bytes());
        seg.extend_from_slice(&dport.to_be_bytes());
        seg.extend_from_slice(&seq.to_be_bytes());
        seg.extend_from_slice(&ack.to_be_bytes());
        seg.push((data_offset as u8) << 4);
        seg.push(flags.to_byte());
        seg.extend_from_slice(&window.to_be_bytes());
        seg.extend_from_slice(&0u16.to_be_bytes()); // checksum 占位
        seg.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
        seg.extend_from_slice(&options);
        seg.extend_from_slice(payload);
        if f.auto_checksum {
            let sum = transport_checksum(layers, i, 6, &seg);
            seg[16] = (sum >> 8) as u8;
            seg[17] = (sum & 0xFF) as u8;
        }
        Ok(seg)
    }

    fn serialize_udp(
        &self,
        i: usize,
        f: &UdpFields,
        payload: &[u8],
        layers: &[Layer],
    ) -> Result<Vec<u8>, SerializeError> {
        if let Some(raw) = &f.raw {
            // bytes= 直喂：自动补 UDP length（offset 4-5）与 checksum（offset 6-7 伪头部）
            let mut hdr = raw.clone();
            let len = (hdr.len() + payload.len()) as u16;
            if hdr.len() >= 6 {
                hdr[4] = (len >> 8) as u8;
                hdr[5] = len as u8;
            }
            if hdr.len() >= 8 {
                hdr[6] = 0;
                hdr[7] = 0;
                let mut seg = hdr.clone();
                seg.extend_from_slice(payload);
                let c = transport_checksum(layers, i, 17, &seg);
                hdr[6] = (c >> 8) as u8;
                hdr[7] = c as u8;
            }
            let mut out = hdr;
            out.extend_from_slice(payload);
            return Ok(out);
        }
        let sport = f.src_port.unwrap_or_else(|| self.rng().u16().max(1));
        let dport = f.dst_port.unwrap_or(0);
        let len = 8 + payload.len();
        let mut datagram = Vec::with_capacity(len);
        datagram.extend_from_slice(&sport.to_be_bytes());
        datagram.extend_from_slice(&dport.to_be_bytes());
        datagram.extend_from_slice(&(len as u16).to_be_bytes());
        datagram.extend_from_slice(&0u16.to_be_bytes()); // checksum 占位
        datagram.extend_from_slice(payload);
        if f.auto_checksum {
            let sum = transport_checksum(layers, i, 17, &datagram);
            datagram[6] = (sum >> 8) as u8;
            datagram[7] = (sum & 0xFF) as u8;
        }
        Ok(datagram)
    }

    // ── 应用层 ──────────────────────────────────────────────

    fn serialize_http(&self, f: &HttpFields, payload: &[u8]) -> Result<Vec<u8>, SerializeError> {
        if let Some(raw) = &f.raw {
            let mut out = raw.clone();
            out.extend_from_slice(payload);
            return Ok(out);
        }
        let method = f.method.clone().unwrap_or_else(|| "GET".to_string());
        let path = f.path.clone().unwrap_or_else(|| "/".to_string());
        let version = f.version.clone().unwrap_or_else(|| "HTTP/1.1".to_string());
        let body = f.body.clone().unwrap_or_default();
        let mut out = Vec::new();
        out.extend_from_slice(format!("{method} {path} {version}\r\n").as_bytes());
        let mut has_content_length = false;
        for (k, v) in &f.headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
            if k.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
        }
        if !body.is_empty() && !has_content_length {
            out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&body);
        out.extend_from_slice(payload);
        Ok(out)
    }

    fn serialize_dns(&self, f: &DnsFields, payload: &[u8]) -> Result<Vec<u8>, SerializeError> {
        if let Some(raw) = &f.raw {
            let mut out = raw.clone();
            out.extend_from_slice(payload);
            return Ok(out);
        }
        let id = f.id.unwrap_or_else(|| self.rng().u16());
        let mut flags = f.flags.unwrap_or(0x0100); // RD
        if let Some(op) = f.opcode {
            flags = (flags & 0x87FF) | ((op as u16 & 0x0F) << 11);
        }
        let questions: Vec<DnsQuestion> = if f.questions.is_empty() {
            vec![DnsQuestion {
                name: String::new(),
                qtype: None,
                qclass: None,
            }]
        } else {
            f.questions.clone()
        };
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&(questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&(f.answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // nscount
        out.extend_from_slice(&0u16.to_be_bytes()); // arcount
        for q in &questions {
            encode_dns_name(&mut out, &q.name)?;
            out.extend_from_slice(&q.qtype.unwrap_or(1).to_be_bytes());
            out.extend_from_slice(&q.qclass.unwrap_or(1).to_be_bytes());
        }
        for a in &f.answers {
            encode_dns_name(&mut out, &a.name)?;
            out.extend_from_slice(&a.rtype.unwrap_or(1).to_be_bytes());
            out.extend_from_slice(&a.class.unwrap_or(1).to_be_bytes());
            out.extend_from_slice(&a.ttl.unwrap_or(300).to_be_bytes());
            out.extend_from_slice(&(a.rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(&a.rdata);
        }
        out.extend_from_slice(payload);
        Ok(out)
    }
}

// ── 校验和 ───────────────────────────────────────────────────

/// 互联网校验和（RFC 1071，one's complement）。
pub fn checksum(data: &[u8]) -> u16 {
    checksum_with_prev(data, 0)
}

/// 互联网校验和，可带进位（`prev` 为上一段的进位和，供分段计算）。
pub(crate) fn checksum_with_prev(data: &[u8], prev: u32) -> u16 {
    let mut sum = prev;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let &[b] = chunks.remainder() {
        sum += (b as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP/UDP 传输层校验和：伪头部（最近的外层 IP）+ 段。
fn transport_checksum(layers: &[Layer], i: usize, proto: u8, seg: &[u8]) -> u16 {
    // 找包裹本层、最近的 IP 层
    let mut pseudo: Vec<u8> = Vec::new();
    let len = seg.len() as u32;
    let mut found = false;
    for l in layers.iter().skip(i + 1) {
        match l {
            Layer::Ipv4(ip) => {
                let src = match ip.src {
                    crate::ir::Field::Value(a) => a,
                    _ => Ipv4Addr::UNSPECIFIED,
                };
                let dst = match ip.dst {
                    crate::ir::Field::Value(a) => a,
                    _ => Ipv4Addr::UNSPECIFIED,
                };
                pseudo.extend_from_slice(&src.octets());
                pseudo.extend_from_slice(&dst.octets());
                pseudo.push(0);
                pseudo.push(proto);
                found = true;
                break;
            }
            Layer::Ipv6(ip) => {
                let src = match ip.src {
                    crate::ir::Field::Value(a) => a,
                    _ => Ipv6Addr::UNSPECIFIED,
                };
                let dst = match ip.dst {
                    crate::ir::Field::Value(a) => a,
                    _ => Ipv6Addr::UNSPECIFIED,
                };
                pseudo.extend_from_slice(&src.octets());
                pseudo.extend_from_slice(&dst.octets());
                pseudo.extend_from_slice(&len.to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, proto]);
                found = true;
                break;
            }
            _ => {}
        }
    }
    if !found {
        // 无外层 IP：零地址 IPv4 伪头部
        pseudo.extend_from_slice(&[0u8; 8]);
        pseudo.push(0);
        pseudo.push(proto);
    }
    pseudo.extend_from_slice(&(len as u16).to_be_bytes());
    let mut all = pseudo;
    all.extend_from_slice(seg);
    checksum(&all)
}

/// DNS 域名编码（无压缩）。
fn encode_dns_name(out: &mut Vec<u8>, name: &str) -> Result<(), SerializeError> {
    if name.is_empty() {
        out.push(0);
        return Ok(());
    }
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(SerializeError::DnsLabelTooLong(label.to_string()));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

// ── 随机数 ───────────────────────────────────────────────────

/// xorshift64*：轻量、确定性（同种子同序列）。
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        XorShift64(seed.max(1))
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn u8(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }
    fn u16(&mut self) -> u16 {
        (self.next_u64() >> 32) as u16
    }
    fn u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
}
