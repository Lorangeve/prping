//! `--pkt`：构建 .pkt 并一次性发送全部变体包到目标。
//!
//! - 默认：提取最外层 TCP/UDP 的应用层载荷，经普通 socket 发送（TCP 建连 / UDP 数据报），
//!   并读取回显（超时）。本地监听的服务能直接收到应用数据。
//! - `--raw`：原始发送完整序列化字节——Linux（需要 root/cap_net_raw）：
//!   eth → AF_PACKET；ipv4 → IPPROTO_RAW + IP_HDRINCL；ipv6 → 原始 IPv6。
//!   Windows/macOS：pcap 链路层注入（`rawpcap.rs` 兼容层，设备选择 + 以太网封装 + 抓包等待）。
//! - `--wait N`（对标 scapy `sr1`）：发送后等待匹配应答并打印 RTT + 反解展示。
//! - `--fuzz`（对标 scapy `fuzz()`）：未填字段全部随机化。
//! - `--out FILE.pcap`（对标 scapy `wrpcap`）：构建的包另存为 pcap。
//!
//! 模块拆分（忠实拆分自原 `engine/pkg.rs`，行为不变）：
//! - `send.rs`：`send_packets` 入口、`send_module` 逐包发送/渲染循环、载荷模式 socket 发送、
//!   目标推导、源地址填充（含 IPv4 checksum 重算）。
//! - `recipe.rs`：`.pktl` 配方执行（`send_recipe`）+ `extract` 回包字段提取。
//! - `sniffer.rs`：`sniffer:` 段回包匹配器（FVal 规范值 / 字段提取 / 字节级 Expr 比较）。
//! - `raw.rs`：原始套接字发送（AF_PACKET / IPPROTO_RAW / raw ICMP 收包）。

mod listen;
mod listen_raw;
mod raw;
mod recipe;
mod send;
mod sniffer;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use packet_dsl::ir::{Layer, PacketSpec};

// ── 类型 ──────────────────────────────────────────────────────

/// 发送方式。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SendMode {
    /// 提取传输层载荷，经普通 TCP/UDP socket 发送。
    #[default]
    Payload,
    /// 原始套接字发送完整字节。
    Raw { iface: Option<String> },
}

/// 传输层。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// 收到的应答。
#[derive(Debug, Clone)]
pub struct Reply {
    /// 往返耗时（毫秒）。
    pub rtt: f64,
    pub bytes: Vec<u8>,
    /// sniffer 匹配结果（字段名, 值）；None = 非 sniffer 匹配的应答。
    pub matched: Option<Vec<(String, String)>>,
}

/// 发送结果。
pub struct SendOutcome {
    pub proto: &'static str,
    pub sent: usize,
    pub received: usize,
    /// 等待到的应答（`--wait`）。
    pub reply: Option<Reply>,
}

/// `--wait` 模式：等待匹配 = 一次性（发后等一个应答）或持续（服务端监听）。
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum WaitMode {
    /// 不等待。
    #[default]
    Off,
    /// `--wait SECS`：发送后等一个匹配应答（超时退出）。
    OneShot(f64),
    /// `--wait`（无值）：持续监听，命中打印匹配详情（纯监听，Ctrl+C 退出）。
    Continuous,
}

impl WaitMode {
    /// 一次性等待的秒数（仅 [`WaitMode::OneShot`] 返回 Some）。
    pub fn one_shot_secs(self) -> Option<f64> {
        match self {
            WaitMode::OneShot(s) => Some(s),
            WaitMode::Off | WaitMode::Continuous => None,
        }
    }
}

/// `--pkt` 的完整选项。
#[derive(Debug, Clone, Default)]
pub struct PkgOptions {
    /// 显式目标（None = 逐包从包内推导；监听模式 = 监听地址）。
    pub target: Option<SocketAddr>,
    pub mode: SendMode,
    /// 运行时参数（`params("name")` 值引用）。
    pub params: Vec<(String, String)>,
    /// 配方全局存储（`-g name=value`（--global）注入；`global("name")` 值原语读取——
    /// 普通 `--pkt` 也生效，配方执行时步骤间由 extract 更新）。
    pub globals: packet_dsl::Globals,
    /// 等待/监听模式：`--wait SECS` = 发送后等一个匹配应答（对标 scapy `sr1`）；
    /// `--wait`（无值）= 持续监听（纯监听：命中打印匹配详情，回应由 .pktl 配方编排）。
    pub wait: WaitMode,
    /// 每个包重复发送次数（`--count N` / 配方步骤 `count: N`，默认 1）。
    pub count: usize,
    /// fuzz 模式：未填字段全部随机化（对标 scapy `fuzz()`）。
    pub fuzz: bool,
    /// 构建的包另存为 pcap（对标 scapy `wrpcap`）。
    pub out: Option<PathBuf>,
    /// 简洁摘要模式：只显示基本信息（传输/目标/字节数），跳过层字段详情与 hex dump。
    pub summary: bool,
    /// pkglang 库目录（import 解析，如发布目录的 `lib/`）。
    pub libs: Vec<PathBuf>,
}

// ── 入口 ──────────────────────────────────────────────────────

/// 构建并发送。`file` 为 .pkt 路径，其余行为由 `opts` 控制。
///
/// 目标推导：取最外层 IP 层的 `dst` 为目标地址；载荷模式还需要传输层 `dport`。
/// 无 TCP/UDP 传输层的包（如 ICMP/ARP）自动改用 raw 发送完整包。
/// `wait` 时：UDP/TCP 载荷模式等匹配应答（DNS 按 id）、raw 模式下 ICMP echo 等回显，
/// 打印 RTT 并反解展示应答。`.pktl` 配方文件请用 [`send_recipe`]。
pub fn send_packets(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    send::send_packets(file, opts)
}

/// 发送配方（`.pktl`）：按顺序执行每个步骤（一个 .pkt 文件），维护 global 存储。
///
/// - `global:` 段声明共享变量（`- 名=值` 一行内联或缩进 `init:` 初始值；CLI -G（--global）
///   覆盖 init；裸 `- 名` = 未初始化，值来自 extract）。
/// - 每步 `--wait` 等回包后按 `extract:` 从回包反解字段取值写入 global
///   （多个回包依次应用，后写覆盖先写）；后续步骤的 .pkt 用 `global("name")` 读取。
/// - 每步 `raw:` 覆盖发送方式（`true`/网卡名 = 强制原始发送、`false` = 强制载荷发送，
///   覆盖 CLI `--raw`；见 [`step_send_mode`]）。
/// - 步骤失败（发送失败 / extract 无回包或字段缺失）默认 stop 整个配方，
///   `on_error: continue` 记录失败继续（退出码仍非零）。
pub fn send_recipe(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    recipe::send_recipe(file, opts)
}

/// 监听模式（`--listen`）：绑定 UDP 地址，按 .pkt 的 sniffer 规则匹配收到的
/// 数据报并打印匹配详情（纯监听；回应包由 .pktl 配方编排）。
pub fn listen_packets(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    listen::listen_packets(file, opts)
}

/// 链路层监听（`--listen --raw`）：持续接收完整帧（AF_PACKET / libpcap），
/// 按 .pkt 的 sniffer 规则匹配，命中打印匹配详情与反解展示（纯监听）。
pub fn listen_raw_packets(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    listen_raw::listen_raw_packets(file, opts)
}

/// 提取最外层 TCP/UDP 的应用层载荷（默认序列化器）。
pub fn extract_payload(pkt: &PacketSpec) -> Option<(Transport, Vec<u8>)> {
    send::extract_payload(pkt)
}

// ── 子模块 re-export（供 lib / 兄弟模块 / rawpcap 使用）──────────

pub use recipe::step_send_mode;
pub use send::{derive_target, patch_zero_src};
pub use sniffer::{SnifferMatcher, sniffer_match, sniffer_match_with};

pub(crate) use send::print_raw_only_hint;
pub use send::raw_only;
pub(crate) use sniffer::{reply_field_names, sniffer_field_names};

// ── 平台无关工具 ──────────────────────────────────────────────

/// 到达 `target` 的本地源地址（UDP connect 路由探测，不发数据）。
/// trace TCP SYN 的 TCP 伪头部校验和也用它取源 IP。
pub fn local_ip_for(target: &SocketAddr) -> Option<IpAddr> {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let s = std::net::UdpSocket::bind(bind).ok()?;
    s.connect(*target).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

/// 198.18.0.0/15（RFC 2544 基准段）——Clash 等代理 fake-ip 模式的常用地址段。
pub fn is_fake_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0], o[1]) == (198, 18) || (o[0], o[1]) == (198, 19)
        }
        _ => false,
    }
}

/// 包内 ICMP echo 的 id/seq（无 sniffer 时 raw `--wait` 按此匹配 echo reply）。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn icmp_echo_ids(pkt: &PacketSpec) -> Option<(u16, u16)> {
    let Some(Layer::Icmp(icmp)) = pkt.layers.iter().find(|l| matches!(l, Layer::Icmp(_))) else {
        return None;
    };
    let (Some(id), Some(seq)) = (icmp.id, icmp.seq) else {
        return None;
    };
    Some((id, seq))
}

/// 回包匹配结果：(应答字节, sniffer 命中字段)。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) type ReplyMatch = Option<(Vec<u8>, Option<Vec<(String, String)>>)>;

/// 用 sniffer（存在）或 ICMP echo id+seq 匹配收到的回包数据。
///
/// 返回 `(应答字节, sniffer 命中字段)`；RTT 由调用方测量后填入 `Reply`。
/// Linux raw ICMP socket（`wait_icmp_reply`）与 pcap 捕获（`rawpcap`）共用。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn match_reply(
    data: &[u8],
    pkt: &PacketSpec,
    sniffer: Option<&SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<ReplyMatch> {
    if let Some(sn) = sniffer {
        let report = sent_report.ok_or_else(|| anyhow::anyhow!("内部错误：sniffer 缺发包反解"))?;
        return Ok(sn
            .matches(data, Some(report))
            .map(|fields| (data.to_vec(), Some(fields))));
    }
    let Some((id, seq)) = icmp_echo_ids(pkt) else {
        return Ok(None);
    };
    let report = packet_dsl::dissect(data);
    let reply_icmp = report.layers.iter().find_map(|l| match l {
        Layer::Icmp(f) => Some(f),
        _ => None,
    });
    let Some(icmp) = reply_icmp else {
        return Ok(None);
    };
    // ICMPv6 echo reply 是 type=129（v4 是 0）：按发包 ICMP 类型取期望回包类型，
    // 避免把 v4 语义的 type=0 硬套到 v6 回包上（v6 --wait 永远匹配不到）。
    let expect_reply_type = match pkt.layers.iter().find_map(|l| match l {
        Layer::Icmp(f) => f.icmp_type,
        _ => None,
    }) {
        Some(128) => 129,
        _ => 0,
    };
    if icmp.icmp_type == Some(expect_reply_type) && icmp.id == Some(id) && icmp.seq == Some(seq) {
        Ok(Some((data.to_vec(), None)))
    } else {
        Ok(None)
    }
}
