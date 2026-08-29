//! IR（结构化包描述）：`resolve` 的求值产物。
//!
//! 字段用 `Option` 表示「自动」——宿主序列化时填随机值 / 默认值 / checksum / length。
//! IR 纯净、可复用、可跨进程传递（serde）。

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// 一次求值的结果：多个包（`use` 元件 × 层位变体的笛卡尔积）。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BuildResult {
    pub packets: Vec<PacketSpec>,
}

/// 一个结构化包描述：内 → 外的扁平层列表（`use` 元件展开后拼入）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketSpec {
    pub layers: Vec<Layer>,
}

/// 网络层。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "layer", rename_all = "snake_case")]
pub enum Layer {
    Ethernet(EthernetFields),
    Arp(ArpFields),
    Ipv4(Ipv4Fields),
    Ipv6(Ipv6Fields),
    Icmp(IcmpFields),
    Tcp(TcpFields),
    Udp(UdpFields),
    Http(HttpFields),
    Dns(DnsFields),
    Raw(RawData),
}

/// 字段取值：未填（走每字段既定默认值）/ 显式随机 / 固定值。
///
/// 例：`ipv4(src="random", ttl="random")` → `Field::Random`，序列化时生成随机单播地址 / 随机 TTL；
/// 不写 → `Field::Auto`（如 TTL 默认 64）；写具体值 → `Field::Value`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field<T> {
    /// 未填：自动值（每字段有既定默认，部分默认即随机）。
    #[default]
    Auto,
    /// 显式随机（`"random"` 关键字）。
    Random,
    /// 固定值。
    Value(T),
}

/// MAC 地址。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() != 12 {
            return None;
        }
        let mut b = [0u8; 6];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let v = std::str::from_utf8(chunk).ok()?;
            b[i] = u8::from_str_radix(v, 16).ok()?;
        }
        Some(MacAddr(b))
    }

    pub fn from_u64(v: u64) -> Self {
        let b = v.to_be_bytes();
        MacAddr([b[2], b[3], b[4], b[5], b[6], b[7]])
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl std::str::FromStr for MacAddr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MacAddr::from_str_loose(s).ok_or_else(|| format!("不是合法 MAC 地址：{s}"))
    }
}

/// ARP 操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArpOp {
    Request,
    Reply,
    /// 其它 opcode（RARP=3 等）：保留原始值，roundtrip 不再静默改写成 request。
    Other(u16),
}

impl fmt::Display for ArpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ArpOp::Request => "request",
                ArpOp::Reply => "reply",
                ArpOp::Other(n) => return write!(f, "op={n}"),
            }
        )
    }
}

/// 以太网（Ethernet II）。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EthernetFields {
    /// 自动：随机单播源 MAC。
    pub src_mac: Field<MacAddr>,
    /// 自动：广播；`"random"` → 随机单播。
    pub dst_mac: Field<MacAddr>,
    /// 自动：由上层载荷推导（arp→0x0806 / ipv4→0x0800 / ipv6→0x86dd，否则 0x0800）。
    pub ethertype: Option<u16>,

    /// `bytes=hex("...")` 直喂：序列化时整层头直接用这些字节（绕过语义字段与自动 checksum/length）。
    #[serde(default)]
    pub raw: Option<Vec<u8>>,
}

/// ARP。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ArpFields {
    /// 自动：request。
    pub op: Option<ArpOp>,
    /// 自动：全零。
    pub sha: Option<MacAddr>,
    pub spa: Option<Ipv4Addr>,
    /// 自动：全零。
    pub tha: Option<MacAddr>,
    pub tpa: Option<Ipv4Addr>,

    /// `bytes=hex("...")` 直喂：序列化时整层头直接用这些字节（绕过语义字段与自动 checksum/length）。
    #[serde(default)]
    pub raw: Option<Vec<u8>>,
}

/// IPv4 标志位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Ipv4Flags {
    pub df: bool,
    pub mf: bool,
    pub frag_offset: u16,
}

/// IPv4。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4Fields {
    /// 自动：0.0.0.0；`"random"` → 随机单播地址。
    pub src: Field<Ipv4Addr>,
    /// 自动：0.0.0.0；`"random"` → 随机单播地址。
    pub dst: Field<Ipv4Addr>,
    /// 自动：64；`"random"` → 随机 1..=255。
    pub ttl: Field<u8>,
    /// 自动：由上层载荷推导（tcp→6 / udp→17 / icmp→1，否则 0）。
    pub proto: Option<u8>,
    /// 自动：0。
    pub tos: Option<u8>,
    /// 自动：随机。
    pub id: Option<u16>,
    /// 自动：0。
    pub flags: Option<Ipv4Flags>,
    /// 自动计算 header checksum。
    pub auto_checksum: bool,

    /// 域名来源（`src=params("src", "www.baidu.com")` 等经解析器解析时记录，展示用）。
    #[serde(default)]
    pub src_host: Option<String>,
    #[serde(default)]
    pub dst_host: Option<String>,

    /// `bytes=hex("...")` 直喂：序列化时整层头直接用这些字节（绕过语义字段与自动 checksum/length）。
    #[serde(default)]
    pub raw: Option<Vec<u8>>,
}

impl Default for Ipv4Fields {
    fn default() -> Self {
        Self {
            src: Field::Auto,
            dst: Field::Auto,
            ttl: Field::Auto,
            proto: None,
            tos: None,
            id: None,
            flags: None,
            auto_checksum: true,
            src_host: None,
            dst_host: None,
            raw: None,
        }
    }
}

/// IPv6。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Ipv6Fields {
    /// 自动：::；`"random"` → 随机单播地址（2000::/12 前缀）。
    pub src: Field<Ipv6Addr>,
    /// 自动：::；`"random"` → 随机单播地址（2000::/12 前缀）。
    pub dst: Field<Ipv6Addr>,
    /// 自动：64；`"random"` → 随机 1..=255。
    pub hop_limit: Field<u8>,
    /// 自动：由上层载荷推导（tcp→6 / udp→17 / icmp→58，否则 59）。
    pub next_header: Option<u8>,

    /// 域名来源（展示用，同 Ipv4Fields::src_host/dst_host）。
    #[serde(default)]
    pub src_host: Option<String>,
    #[serde(default)]
    pub dst_host: Option<String>,

    /// `bytes=hex("...")` 直喂：序列化时整层头直接用这些字节（绕过语义字段与自动 checksum/length）。
    #[serde(default)]
    pub raw: Option<Vec<u8>>,
}

/// ICMP（IPv4 语义；IPv6 下为 ICMPv6，类型由宿主注意）。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IcmpFields {
    /// 自动：8（echo request）。
    #[serde(rename = "type")]
    pub icmp_type: Option<u8>,
    /// 自动：0。
    pub code: Option<u8>,
    /// 自动：随机。
    pub id: Option<u16>,
    /// 自动：0。
    pub seq: Option<u16>,
    /// 自动：空。
    pub payload: Option<Vec<u8>>,

    /// `bytes=hex("...")` 直喂：序列化时整层头直接用这些字节（绕过语义字段与自动 checksum/length）。
    #[serde(default)]
    pub raw: Option<Vec<u8>>,
}

/// TCP 标志位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    /// 解析 `"syn"` / `"syn,ack"` / `"SYN|ACK"`（逗号或竖线分隔，大小写不敏感）。
    pub fn from_str_loose(s: &str) -> Option<Self> {
        let mut f = TcpFlags::default();
        for tok in s.split([',', '|']) {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            match tok.to_ascii_lowercase().as_str() {
                "fin" => f.fin = true,
                "syn" => f.syn = true,
                "rst" => f.rst = true,
                "psh" => f.psh = true,
                "ack" => f.ack = true,
                "urg" => f.urg = true,
                "ece" => f.ece = true,
                "cwr" => f.cwr = true,
                _ => return None,
            }
        }
        Some(f)
    }

    pub fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.fin {
            b |= 0x01;
        }
        if self.syn {
            b |= 0x02;
        }
        if self.rst {
            b |= 0x04;
        }
        if self.psh {
            b |= 0x08;
        }
        if self.ack {
            b |= 0x10;
        }
        if self.urg {
            b |= 0x20;
        }
        if self.ece {
            b |= 0x40;
        }
        if self.cwr {
            b |= 0x80;
        }
        b
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.fin {
            parts.push("fin");
        }
        if self.syn {
            parts.push("syn");
        }
        if self.rst {
            parts.push("rst");
        }
        if self.psh {
            parts.push("psh");
        }
        if self.ack {
            parts.push("ack");
        }
        if self.urg {
            parts.push("urg");
        }
        if self.ece {
            parts.push("ece");
        }
        if self.cwr {
            parts.push("cwr");
        }
        write!(f, "{}", parts.join(","))
    }
}

/// TCP 选项（v1：仅 mss）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TcpOption {
    Mss(u16),
}

/// TCP。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFields {
    /// 自动：随机。
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// 自动：随机。
    pub seq: Option<u32>,
    /// 自动：0。
    pub ack: Option<u32>,
    /// 自动：SYN（0x02）。
    pub flags: Option<TcpFlags>,
    /// 自动：65535。
    pub window: Option<u16>,
    pub options: Vec<TcpOption>,
    /// 自动计算 checksum（伪头部来自外层 IP）。
    pub auto_checksum: bool,

    /// `bytes=hex("...")` 直喂：序列化时整层头直接用这些字节（绕过语义字段与自动 checksum/length）。
    #[serde(default)]
    pub raw: Option<Vec<u8>>,
}

impl Default for TcpFields {
    fn default() -> Self {
        Self {
            src_port: None,
            dst_port: None,
            seq: None,
            ack: None,
            flags: None,
            window: None,
            options: Vec::new(),
            auto_checksum: true,
            raw: None,
        }
    }
}

/// UDP。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpFields {
    /// 自动：随机。
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// 自动计算 length / checksum（伪头部来自外层 IP）。
    pub auto_checksum: bool,

    /// `bytes=hex("...")` 直喂：序列化时整层头直接用这些字节（绕过语义字段与自动 checksum/length）。
    #[serde(default)]
    pub raw: Option<Vec<u8>>,
}

impl Default for UdpFields {
    fn default() -> Self {
        Self {
            src_port: None,
            dst_port: None,
            auto_checksum: true,
            raw: None,
        }
    }
}

/// HTTP/1.1 最小报文（请求行 + 头 + 可选 body）。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HttpFields {
    /// 自动：GET。
    pub method: Option<String>,
    /// 自动：/。
    pub path: Option<String>,
    /// 自动：HTTP/1.1。
    pub version: Option<String>,
    /// `Name: value` 对；body 存在且无 Content-Length 时自动补。
    pub headers: Vec<(String, String)>,
    /// 自动：空。
    pub body: Option<Vec<u8>>,

    /// `bytes=hex("...")` 直喂：序列化时整层头直接用这些字节（绕过语义字段与自动 checksum/length）。
    #[serde(default)]
    pub raw: Option<Vec<u8>>,
}

/// DNS 问题（查询）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    /// 自动：A（1）。
    pub qtype: Option<u16>,
    /// 自动：IN（1）。
    pub qclass: Option<u16>,
}

/// DNS 回答记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    /// 自动：A（1）。
    pub rtype: Option<u16>,
    /// 自动：IN（1）。
    pub class: Option<u16>,
    /// 自动：300。
    pub ttl: Option<u32>,
    /// 已编码的 rdata（注册表阶段完成 IP → 字节）。
    pub rdata: Vec<u8>,
}

/// DNS。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DnsFields {
    /// 自动：随机。
    pub id: Option<u16>,
    /// 自动：0x0100（RD）。
    pub flags: Option<u16>,
    /// 自动：0（QUERY），并入 flags。
    pub opcode: Option<u8>,
    /// 自动：单个根 A 查询（name 为空）。
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,

    /// `bytes=hex("...")` 直喂：序列化时整层头直接用这些字节（绕过语义字段与自动 checksum/length）。
    #[serde(default)]
    pub raw: Option<Vec<u8>>,
}

/// 原始字节载荷。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RawData {
    pub bytes: Vec<u8>,
    /// 产出该层的裸协议名（`#[proto]` 无 kind 的声明，如 `quic_initial`）——
    /// 层序检查按它查 proto 注册表的 `#[rule]` 载体集；普通 `raw`/`hex`/反解层为 None。
    #[serde(default)]
    pub proto: Option<String>,
}
