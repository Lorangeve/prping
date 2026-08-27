//! 路由跟踪（traceroute）模式（`trace`）：逐跳探测到目标的转发路径。
//!
//! 三种探测技术：
//!
//! - **ICMP echo**（默认，对标 Windows `tracert`）：向目标发 ICMP echo
//!   request，TTL 从 1 起逐跳递增；中间路由器 TTL 耗尽回 ICMP Time Exceeded
//!   （type 11 / ICMPv6 type 3），其源地址即该跳地址；目标本身回 ICMP echo
//!   reply（type 0 / 129）。回复按内嵌原始报文的 id/seq 匹配归属。
//! - **TCP SYN**（`trace --tcp HOST:PORT`，对标 `tcptraceroute`/`tracetcp`）：
//!   发 TCP SYN（递增 TTL），中间路由回 Time Exceeded，目标回 **SYN-ACK**
//!   （端口开）或 **RST**（端口关）即到达——ICMP 被防火墙过滤时仍可用。
//!   每个探测用独立源端口，按内嵌 TCP 头的 (sport, dport) 匹配归属，无需 seq；
//!   收 SYN-ACK/RST 用 raw TCP socket（Windows 禁止 raw TCP，`--tcp` 报错）。
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
mod udp;

use std::io::Write;
use std::net::IpAddr;
use std::time::Duration;

use rust_i18n::t;
use termcolor::StandardStream;

use crate::output;
use crate::stats;
use crate::util::{self, PingConfig};

/// 每跳探测次数（对标 tracert 的 3 次）。
const PROBES_PER_HOP: usize = 3;
/// 单跳收集回复的总超时。
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// 反向 DNS 查询超时（超时按无 PTR 处理，不阻塞整条路径）。
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
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

/// 路由跟踪入口：按 `cfg.trace_tcp` 选择 ICMP echo / TCP SYN 技术，
/// 打印逐跳进度 + 汇总（文本 / JSON），返回报告。
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

/// Windows 前置守卫（在 banner 之前报错）；其余平台恒通过。
fn ensure_tcp_trace_supported() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(windows)]
    {
        anyhow::bail!(t!("errors.tcp_trace_windows"));
    }
}

/// 一跳收尾：反向 DNS + 输出（文本/JSON），返回该跳 Hop。
pub(crate) fn finish_hop(
    hop_no: u32,
    cfg: &PingConfig,
    src: Option<IpAddr>,
    rtts: Vec<Option<Duration>>,
    w: &mut StandardStream,
) -> anyhow::Result<Hop> {
    // 反向 DNS（与收集串行；典型局域网下 PTR 远快于 2s 超时）
    let hostname = if cfg.no_dns {
        None
    } else {
        src.and_then(|ip| dns::reverse_dns_timeout(ip, DNS_TIMEOUT))
    };
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
