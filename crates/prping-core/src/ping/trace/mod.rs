//! 路由跟踪（traceroute）模式（`trace`）：逐跳探测到目标的转发路径。
//!
//! 三种探测技术：
//!
//! - **ICMP echo**（默认，对标 Windows `tracert`）：向目标发 ICMP echo
//!   request，TTL 从 1 起逐跳递增；中间路由器 TTL 耗尽回 ICMP Time Exceeded
//!   （type 11 / ICMPv6 type 3），其源地址即该跳地址；目标本身回 ICMP echo
//!   reply（type 0 / 129）。回复按内嵌原始报文的 id/seq 匹配归属。
//! - **TCP SYN**（`trace HOST:PORT` 带端口自动启用，对标
//!   `tcptraceroute`/`tracetcp`）：
//!   发 TCP SYN（递增 TTL），中间路由回 Time Exceeded，目标回 **SYN-ACK**
//!   （端口开）或 **RST**（端口关）即到达——ICMP 被防火墙过滤时仍可用。
//!   每个探测用独立源端口，按内嵌 TCP 头的 (sport, dport) 匹配归属，无需 seq。
//!   Unix：raw TCP socket 发 SYN（内核构 IP 头）、raw TCP 收 SYN-ACK/RST + raw
//!   ICMP 收 Time Exceeded（双 socket `libc::poll`，见 `tcp.rs`）。Windows：raw
//!   TCP 被禁止，走 Npcap 注入完整帧 + 抓包收回复（`tcpwin.rs`，需 Npcap，仅 IPv4）。
//! - **UDP**（`trace --udp HOST`，经典 Unix traceroute）：普通 UDP socket 发
//!   载荷到递增高段端口（33434 起，每探测 +1），TTL 逐跳递增；中间路由回
//!   Time Exceeded，目标回 **Port Unreachable**（type 3 code 3 / ICMPv6 type 1
//!   code 4）即到达。UDP 头由内核构造（校验和内核算），只需一个 raw ICMP
//!   socket 收包，跨平台可用（Windows 支持普通 UDP + raw ICMP）。
//!
//! 平台差异：IPv4 raw socket 收到的数据恒含 IP 头（ihl 解析）；IPv6 raw
//! socket 收到的数据**不含** IPv6 头（Linux 在 raw6_local_deliver 前
//! pskb_pull 掉了传输偏移），但部分平台（如 Windows）会带上——用
//! 「首字节 version nibble == 6」探测框架，两种惯例都兼容（见
//! `icmp_offset_v6`）。本模块从不读取外层 IP 头的字段（跳地址来自
//! recv_from 的源地址），所以框架探测只需决定载荷从哪开始。
//! TCP 模式的探测源端口限制在 0x4000..=0x5FFF：SYN-ACK/RST 回包的首字节是
//! 源端口高位，0x60-0x6F 会干扰 version-nibble 判断——`match_tcp_reply`
//! 先按无头解析兜底，端口范围再杜绝「带头包被无头解析误中」（无头解析里
//! dst_port 位是 IPv6 头的 0x60xx 版本字段，恰与放宽后的源端口重叠）。

mod dns;
mod icmp;
mod tcp;
// Windows pcap 路径；纯函数（帧构造/回复解析）在 test 下任意平台编译可单测
#[cfg(any(windows, test))]
mod tcpwin;
mod udp;

use std::io::Write;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rust_i18n::t;
use termcolor::StandardStream;

use crate::output;
use crate::stats;
use crate::util::{self, PingConfig};

/// 每跳探测次数（对标 tracert 的 3 次）。
const PROBES_PER_HOP: usize = 3;
/// 单跳收集回复的总超时。
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// 逐跳探测 trait：每种探测技术（ICMP/TCP/UDP）实现此 trait，
/// `trace_loop` 统一管理 hop 循环、interrupted、set_ttl、超时收集。
pub(crate) trait TraceSocket {
    /// 发送本跳全部探测，返回 `(identifier, send_time)` 列表。
    /// `hop_no` 用于 TTL 设置（由 `trace_loop` 已设置，此处可用于端口递增等）。
    fn send_probes(&mut self, hop_no: u32) -> Vec<(u16, Instant)>;

    /// 解析收到的回复数据：返回 `Some((matched_identifier, is_dest_hit))`。
    fn parse_reply(&self, data: &[u8], want: &[u16]) -> Option<(u16, bool)>;

    /// 设置接收超时。
    fn set_recv_timeout(&self, timeout: Duration) -> anyhow::Result<()>;

    /// 接收一个包：返回 `(n_bytes, peer_addr)`。
    fn recv_from(&self, buf: &mut [MaybeUninit<u8>])
    -> std::io::Result<(usize, socket2::SockAddr)>;

    /// trace dump 标签（如 `"icmp-v4"` / `"udp-v6"`）。
    fn dump_label(&self) -> &str;

    /// TTL 设置的 socket（通常与 recv_from 的 socket 相同）。
    fn ttl_socket(&self) -> &socket2::Socket;

    /// 目标是否 IPv6（用于 set_ttl 参数）。
    fn is_ipv6(&self) -> bool;
}

/// 一跳探测的收集结果（逐跳骨架的 hop_body 闭包返回）。
#[derive(Default)]
pub(crate) struct HopCollect {
    /// 本跳回复来源（最后一次匹配回复的 peer；无回复 = None）。
    pub src: Option<IpAddr>,
    /// 每探测的 RTT（未匹配 = None）。
    pub rtts: Vec<Option<Duration>>,
    /// 是否收到目标回包（SYN-ACK/RST / echo reply / Port Unreachable）。
    pub dest_hit: bool,
}

/// 逐跳探测通用骨架：hop_no 循环 + 渲染上一跳（DNS 后台并行）+ interrupted +
/// PendingHop 收尾——ICMP/UDP（trace_loop）、Unix TCP（tcp.rs）、Windows Npcap
/// TCP（tcpwin.rs）三路径共用，各路径只提供 hop_body（set_ttl + 发送 + 收集）。
///
/// hop_body 返回的 rtts 为空表示本跳无探测发出（骨架据此 break）。
pub(crate) fn trace_loop_skeleton<F>(
    cfg: &PingConfig,
    max_hops: u32,
    mut hop_body: F,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)>
where
    F: FnMut(u32) -> anyhow::Result<HopCollect>,
{
    let mut hops: Vec<Hop> = Vec::new();
    let mut reached = false;
    // 上一跳延迟渲染：本跳探测期间其 DNS 在后台并行
    let mut pending: Option<PendingHop> = None;

    for hop_no in 1..=max_hops {
        // 先渲染上一跳（DNS 已并行跑完本跳的探测窗口）
        if let Some(prev) = pending.take() {
            let hostname = dns_hostname(prev.dns_rx);
            let hop = finish_hop(prev.hop_no, prev.src, prev.rtts, hostname, w)?;
            hops.push(hop);
            if prev.dest_hit {
                reached = true;
                break;
            }
        }
        if util::interrupted() {
            break;
        }
        let collected = hop_body(hop_no)?;
        if collected.rtts.is_empty() {
            break;
        }
        pending = Some(PendingHop::new(
            hop_no,
            cfg,
            collected.src,
            collected.rtts,
            collected.dest_hit,
        ));
    }

    // 循环外渲染最后一跳
    if let Some(prev) = pending.take() {
        let hostname = dns_hostname(prev.dns_rx);
        let hop = finish_hop(prev.hop_no, prev.src, prev.rtts, hostname, w)?;
        hops.push(hop);
        if prev.dest_hit {
            reached = true;
        }
    }

    Ok((hops, reached))
}

/// 逐跳探测（ICMP/UDP）：骨架 + TraceSocket 的发送/解析/收包差异点。
fn trace_loop<S: TraceSocket>(
    cfg: &PingConfig,
    max_hops: u32,
    socket: &mut S,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    trace_loop_skeleton(
        cfg,
        max_hops,
        |hop_no| {
            util::set_ttl(socket.ttl_socket(), hop_no, socket.is_ipv6())?;
            let probes = socket.send_probes(hop_no);
            if probes.is_empty() {
                return Ok(HopCollect::default());
            }
            let want: Vec<u16> = probes.iter().map(|&(id, _)| id).collect();
            let deadline = Instant::now() + PROBE_TIMEOUT;
            let mut rtts: Vec<Option<Duration>> = vec![None; probes.len()];
            let mut src: Option<IpAddr> = None;
            let mut dest_hit = false;
            let mut remaining = probes.len();
            let mut buf: [MaybeUninit<u8>; 8192] = [MaybeUninit::new(0u8); 8192];
            while remaining > 0 {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                socket.set_recv_timeout(deadline - now)?;
                match socket.recv_from(&mut buf) {
                    Ok((n, addr)) => {
                        let data: &[u8] = util::init_slice(&buf, n);
                        let peer: IpAddr = addr
                            .as_socket()
                            .map(|s| s.ip())
                            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                        let (id, is_dest) = match socket.parse_reply(data, &want) {
                            Some(r) => r,
                            None => {
                                trace_dump(socket.dump_label(), data, false);
                                continue;
                            }
                        };
                        trace_dump(socket.dump_label(), data, true);
                        if is_dest {
                            dest_hit = true;
                        }
                        if let Some(idx) = probes.iter().position(|&(s, _)| s == id)
                            && rtts[idx].is_none()
                        {
                            let rtt = probes[idx].1.elapsed();
                            rtts[idx] = Some(rtt);
                            remaining -= 1;
                        }
                        src = Some(peer);
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
            Ok(HopCollect {
                src,
                rtts,
                dest_hit,
            })
        },
        w,
    )
}
/// 反向 DNS 查询超时（超时按无 PTR 处理，不阻塞整条路径）。
const DNS_TIMEOUT: Duration = Duration::from_secs(2);

/// 一跳的延迟渲染 + DNS 后台并行：探测下一跳期间，上一跳的反向 DNS 在后台跑，
/// 渲染时 `recv_timeout(DNS_TIMEOUT)` 取回——查询通常已在探测窗口内完成，
/// 未完成最多再等 DNS_TIMEOUT。三条探测路径（ICMP/UDP 的 trace_loop、Unix TCP、
/// Windows Npcap TCP）共用，消除「逐跳串行等 DNS」的总耗时累加。
pub(crate) struct PendingHop {
    pub(crate) hop_no: u32,
    pub(crate) rtts: Vec<Option<Duration>>,
    pub(crate) src: Option<IpAddr>,
    pub(crate) dns_rx: Option<std::sync::mpsc::Receiver<Option<String>>>,
    pub(crate) dest_hit: bool,
}

impl PendingHop {
    pub(crate) fn new(
        hop_no: u32,
        cfg: &PingConfig,
        src: Option<IpAddr>,
        rtts: Vec<Option<Duration>>,
        dest_hit: bool,
    ) -> Self {
        Self {
            hop_no,
            rtts,
            src,
            // -d（no_dns）或本跳无回复时不查询
            dns_rx: if cfg.no_dns {
                None
            } else {
                src.map(dns::spawn_reverse_dns)
            },
            dest_hit,
        }
    }
}

/// 取回后台 DNS 结果（限时 DNS_TIMEOUT；超时按无 PTR 处理）。
pub(crate) fn dns_hostname(
    rx: Option<std::sync::mpsc::Receiver<Option<String>>>,
) -> Option<String> {
    rx.and_then(|rx| rx.recv_timeout(DNS_TIMEOUT).ok().flatten())
}
/// 默认最大跳数（`-m`，对标 tracert/traceroute 的 30）。
pub const DEFAULT_MAX_HOPS: u32 = 30;
/// TTL 上限（IPv4 协议字段上限）。
const MAX_TTL: u32 = 255;

/// 一跳的探测结果。
#[derive(Debug, Clone)]
pub struct Hop {
    pub hop: u32,
    /// 每次探测的 RTT（超时 = None）。
    pub rtts: Vec<Option<Duration>>,
    /// 应答者地址（首个成功探测的源地址；全超时 = None）。
    pub addr: Option<IpAddr>,
    /// 反向 DNS 主机名（无 PTR / -d / 超时 = None）。
    pub hostname: Option<String>,
}

/// 路由跟踪报告。
#[derive(Debug, Clone)]
pub struct TraceReport {
    /// 原始目标串（未解析，供展示）。
    pub target: String,
    /// 解析出的目标 IP。
    pub addr: IpAddr,
    pub max_hops: u32,
    pub hops: Vec<Hop>,
    /// 是否在 max_hops 内收到目标回显（决定退出码）。
    pub reached: bool,
}

/// 路由跟踪入口：按 `cfg.trace_tcp`/`cfg.trace_udp` 选择 ICMP echo / TCP SYN /
/// UDP 技术，打印逐跳进度 + 汇总（文本 / JSON），返回报告。
pub fn traceroute(cfg: &PingConfig) -> anyhow::Result<TraceReport> {
    let addr = util::resolve(&cfg.host, 0, cfg.v4, cfg.v6)?;
    let target_ip = addr.ip();
    let max_hops = cfg.max_hops.clamp(1, MAX_TTL);
    if cfg.trace_tcp {
        ensure_tcp_trace_supported()?;
    }

    if !stats::json() {
        println!(
            "{}",
            t!(
                "trace.tracing",
                host = cfg.host,
                addr = target_ip.to_string(),
                hops = max_hops
            )
        );
    }

    let mut w = output::stdout();
    let (hops, reached) = if cfg.trace_tcp {
        tcp::trace_tcp(cfg, target_ip, max_hops, &mut w)?
    } else if cfg.trace_udp {
        udp::trace_udp(cfg, target_ip, max_hops, &mut w)?
    } else {
        icmp::trace_icmp(cfg, target_ip, max_hops, &mut w)?
    };

    // 汇总（文本 / JSON）
    let report = TraceReport {
        target: cfg.host.clone(),
        addr: target_ip,
        max_hops,
        hops,
        reached,
    };
    if stats::json() {
        let ts = crate::util::unix_ts();
        println!(
            "{}",
            serde_json::json!({
                "type": "traceroute",
                "target": cfg.host,
                "ts": ts,
                "summary": true,
                "reached": reached,
                "hops": report.hops.len(),
            })
        );
    } else {
        println!();
        if reached {
            println!(
                "{}",
                t!("trace.reached", host = cfg.host, hops = report.hops.len())
            );
        } else {
            println!(
                "{}",
                t!("trace.not_reached", host = cfg.host, hops = max_hops)
            );
        }
    }
    Ok(report)
}

/// Windows 前置守卫（在 banner 之前报错）：未装 Npcap 时 trace TCP SYN 不可用
/// （wpcap.dll 延迟加载，探测失败给友好错误而非 delay-load 崩溃）。其余平台恒通过。
fn ensure_tcp_trace_supported() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        tcpwin::ensure()?;
    }
    Ok(())
}

/// 一跳收尾：构造 Hop 并输出（文本/JSON）。hostname 由调用方解析
/// （跨跳并行，见 `PendingHop`/`dns_hostname`），不再在此串行阻塞。
pub(crate) fn finish_hop(
    hop_no: u32,
    src: Option<IpAddr>,
    rtts: Vec<Option<Duration>>,
    hostname: Option<String>,
    w: &mut StandardStream,
) -> anyhow::Result<Hop> {
    let hop = Hop {
        hop: hop_no,
        rtts,
        addr: src,
        hostname,
    };
    if stats::json() {
        print_hop_json(&hop);
    } else {
        print_hop_line(w, &hop)?;
    }
    Ok(hop)
}

/// 匹配 IPv4 TCP SYN 回包核心逻辑（供 tcp.rs 和 tcpwin.rs 共用）。
///
/// `ip` 是纯 IPv4 负载（不含以太网帧头）。检查 src_ip == target、sport == dport、
/// dst_port in want。返回 `Some((matched_port, is_syn_ack_or_rst))`。
pub(crate) fn match_tcp_syn_reply_v4(
    ip: &[u8],
    target: std::net::IpAddr,
    dport: u16,
    want: &[u16],
) -> Option<(u16, bool)> {
    let ihl = util::ipv4_ihl(ip);
    if ip.len() < ihl + 20 {
        return None;
    }
    let src = std::net::IpAddr::V4(std::net::Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    if src != target {
        return None;
    }
    let tcp = &ip[ihl..];
    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if sport != dport || !want.contains(&dst_port) {
        return None;
    }
    let flags = tcp[13];
    let is_dest = flags & 0x12 == 0x12 || flags & 0x04 == 0x04;
    Some((dst_port, is_dest))
}

/// 诊断：`PRPING_TRACE_DUMP=1` 时把收到的原始报文（hex）与匹配结果打到 stderr。
/// 用于排查平台收包格式差异（如 Windows raw ICMP 是否含 IP 头）——
/// 普通模式零开销零输出。
pub(crate) fn trace_dump(what: &str, buf: &[u8], matched: bool) {
    if std::env::var_os("PRPING_TRACE_DUMP").is_none() {
        return;
    }
    let hex: String = buf.iter().take(128).map(|b| format!("{b:02x}")).collect();
    eprintln!(
        "[trace-dump] {what}: {} bytes, matched={matched}, first={:02x}, {hex}",
        buf.len(),
        buf.first().copied().unwrap_or(0)
    );
}

/// 输出一跳（文本格式）。
fn print_hop_line(w: &mut StandardStream, hop: &Hop) -> anyhow::Result<()> {
    use crate::output;

    let hop_str = format!("{:>3}  ", hop.hop);
    output::print_dim(w, &hop_str)?;

    match hop.addr {
        Some(ip) => {
            output::print_cyan(w, output::pad_to(&ip.to_string(), 48))?;
        }
        None => {
            output::print_dim(w, output::pad_to("*", 48))?;
        }
    }

    // RTT 列
    for rtt in &hop.rtts {
        match rtt {
            Some(d) => {
                let ms = d.as_secs_f64() * 1000.0;
                output::print_green(w, format!("{:>8.3} ms", ms))?;
            }
            None => {
                output::print_dim(w, "       *")?;
            }
        }
    }

    // 主机名
    if let Some(name) = &hop.hostname {
        output::print_yellow(w, format!("  {}", name))?;
    }

    writeln!(w)?;
    Ok(())
}

/// 输出一跳（JSON 格式）。
fn print_hop_json(hop: &Hop) {
    let rtts: Vec<Option<f64>> = hop
        .rtts
        .iter()
        .map(|r| r.map(|d| d.as_secs_f64() * 1000.0))
        .collect();
    println!(
        "{}",
        serde_json::json!({
            "type": "traceroute",
            "hop": hop.hop,
            "addr": hop.addr.map(|a| a.to_string()),
            "rtts": rtts,
            "hostname": hop.hostname,
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn v4_echo_reply() {
        // IPv4 头(20B) + ICMP echo reply(8B)
        let mut buf = vec![0u8; 28];
        buf[0] = 0x45; // IHL=5
        buf[8] = 64; // TTL
        buf[9] = 1; // proto=ICMP
        let icmp = &mut buf[20..];
        icmp[0] = 0; // type=echo reply
        icmp[4] = 0x12;
        icmp[5] = 0x34;
        icmp[6] = 0;
        icmp[7] = 5;
        assert_eq!(
            icmp::parse_reply_v4(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x1234, &[5]),
            Some((5, true))
        );
    }

    #[test]
    fn v4_echo_reply_wrong_id() {
        let mut buf = vec![0u8; 28];
        buf[0] = 0x45;
        buf[8] = 64;
        buf[9] = 1;
        let icmp = &mut buf[20..];
        icmp[0] = 0;
        icmp[4] = 0x12;
        icmp[5] = 0x35; // wrong id
        icmp[6] = 0;
        icmp[7] = 5;
        assert_eq!(
            icmp::parse_reply_v4(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x1234, &[5]),
            None
        );
    }

    #[test]
    fn v6_echo_reply_with_header() {
        // IPv6 头(40B) + ICMPv6 echo reply(8B)
        let mut buf = vec![0u8; 48];
        buf[0] = 0x60;
        let icmp = &mut buf[40..];
        icmp[0] = 129; // type=echo reply
        icmp[4] = 0xAB;
        icmp[5] = 0xCD;
        icmp[6] = 0;
        icmp[7] = 5;
        assert_eq!(
            icmp::parse_reply_v6(
                &buf,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                0xABCD,
                &[5]
            ),
            Some((5, true))
        );
    }

    #[test]
    fn v6_echo_reply_without_header() {
        // Linux: direct ICMPv6
        let mut icmp = vec![0u8; 8];
        icmp[0] = 129;
        icmp[4] = 0xAB;
        icmp[5] = 0xCD;
        icmp[6] = 0;
        icmp[7] = 5;
        assert_eq!(
            icmp::parse_reply_v6(
                &icmp,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                0xABCD,
                &[5]
            ),
            Some((5, true))
        );
    }

    #[test]
    fn v6_ttl_exceeded() {
        // ICMPv6 Time Exceeded (type 3 code 0): 8B ICMPv6 + 40B IPv6 + 8B ICMPv6
        let mut icmp = vec![0u8; 8 + 40 + 8];
        icmp[0] = 3;
        icmp[1] = 0;
        icmp[32..48].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // dst ::1
        let eicmp = &mut icmp[8 + 40..];
        eicmp[0] = 128;
        eicmp[4] = 0x12;
        eicmp[5] = 0x34;
        eicmp[6] = 0;
        eicmp[7] = 9;
        assert_eq!(
            icmp::parse_reply_v6(
                &icmp,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                0x1234,
                &[9, 10]
            ),
            Some((9, false))
        );
        assert_eq!(
            icmp::parse_reply_v6(
                &icmp,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                0x1234,
                &[11]
            ),
            None
        );
    }

    #[test]
    fn echo_build_layout() {
        let v4 = crate::ping::icmp::build_v4(0x1234, 7, 32);
        assert_eq!(v4.len(), 40);
        assert_eq!(v4[0], 8);
        assert_eq!(v4[4], 0x12);
        assert_eq!(v4[7], 7);
        assert_eq!(v4[8], 0);
        assert_eq!(v4[39], 31);
        let v6 = crate::ping::icmp::build_v6(0x1234, 7, 32);
        assert_eq!(v6[0], 128);
        assert_eq!(v6[4], 0x12);
    }
}
