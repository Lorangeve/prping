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

use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rust_i18n::t;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use termcolor::{StandardStream, WriteColor};

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
        trace_tcp(cfg, target_ip, max_hops, &mut w)?
    } else if cfg.trace_udp {
        trace_udp(cfg, target_ip, max_hops, &mut w)?
    } else {
        trace_icmp(cfg, target_ip, max_hops, &mut w)?
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
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
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

/// ICMP echo 逐跳：raw ICMP socket 收发，回复按内嵌 ICMP 的 id/seq 匹配。
fn trace_icmp(
    cfg: &PingConfig,
    target_ip: IpAddr,
    max_hops: u32,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    let (sock, target_sa) = create_icmp_socket(target_ip, cfg.source)?;
    let ident = rand_id();

    let mut hops: Vec<Hop> = Vec::new();
    let mut seq_counter: u16 = 0;
    let mut reached = false;

    for hop_no in 1..=max_hops {
        if util::interrupted() {
            break;
        }
        set_ttl(&sock, hop_no, target_ip.is_ipv6())?;

        // 发送本跳全部探测（背靠背，不逐包等待）
        let mut probes: Vec<(u16, Instant)> = Vec::with_capacity(PROBES_PER_HOP);
        for _ in 0..PROBES_PER_HOP {
            let seq = seq_counter;
            seq_counter = seq_counter.wrapping_add(1);
            let pkt = build_echo(target_ip, ident, seq, 32);
            let sent = Instant::now();
            if sock.send_to(&pkt, &target_sa).is_ok() {
                probes.push((seq, sent));
            }
        }
        if probes.is_empty() {
            break; // 发送全部失败（如权限被收回），停止
        }

        // 收集回复直到全部匹配或超时
        let want: Vec<u16> = probes.iter().map(|&(s, _)| s).collect();
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
            sock.set_read_timeout(Some(deadline - now))?;
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let from_ip = from.as_socket().map(|s| s.ip());
                    let data = util::init_slice(&buf, n);
                    let parsed = match target_ip {
                        IpAddr::V4(_) => parse_reply_v4(data, target_ip, ident, &want),
                        IpAddr::V6(_) => parse_reply_v6(data, target_ip, ident, &want),
                    };
                    trace_dump("icmp-recv", data, parsed.is_some());
                    let Some((seq, echo)) = parsed else { continue };
                    let Some(idx) = probes.iter().position(|&(s, _)| s == seq) else {
                        continue;
                    };
                    if rtts[idx].is_some() {
                        continue; // 同一 seq 的重复/迟到回复
                    }
                    rtts[idx] = Some(probes[idx].1.elapsed());
                    if let Some(ip) = from_ip {
                        src.get_or_insert(ip);
                    }
                    if echo {
                        dest_hit = true;
                    }
                    remaining -= 1;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }

        let hop = finish_hop(hop_no, cfg, src, rtts, w)?;
        reached = dest_hit;
        hops.push(hop);
        if dest_hit {
            break;
        }
    }
    Ok((hops, reached))
}

/// UDP 逐跳（`trace --udp HOST`，经典 Unix traceroute）：普通 UDP socket 发
/// 载荷到递增目标端口（33434 起每探测 +1，尽量避开被监听的端口），TTL 逐跳
/// 递增；中间路由回 Time Exceeded，目标回 Port Unreachable（type 3 code 3 /
/// ICMPv6 type 1 code 4）即到达。UDP 头由内核构造（校验和内核算），只需一个
/// raw ICMP socket 收包；回复按内嵌 UDP 头的 (sport, dport) 匹配归属。
///
/// 跨平台：Windows 支持普通 UDP socket + raw ICMP（不像 `--tcp` 被禁止）。
fn trace_udp(
    cfg: &PingConfig,
    target_ip: IpAddr,
    max_hops: u32,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    let (icmp_sock, _) = create_icmp_socket(target_ip, cfg.source)?;
    // 固定源端口（随机），dport 从 33434 起递增——(sport, dport) 唯一标识探测
    let sport = (0x4000 + rand_id() % 0x4000).max(1);
    let udp_sock = create_udp_socket(target_ip, cfg.source, sport)?;

    let mut hops: Vec<Hop> = Vec::new();
    let mut reached = false;
    let mut dport: u16 = 33434;
    let payload = [0u8; 1];
    let mut buf: [MaybeUninit<u8>; 8192] = [MaybeUninit::new(0u8); 8192];

    for hop_no in 1..=max_hops {
        if util::interrupted() {
            break;
        }
        set_ttl(&udp_sock, hop_no, target_ip.is_ipv6())?;

        // 发送本跳全部探测（背靠背；dport 递增）
        let mut probes: Vec<(u16, Instant)> = Vec::with_capacity(PROBES_PER_HOP);
        for _ in 0..PROBES_PER_HOP {
            let dp = dport;
            dport = if dport >= 0xFFF0 { 33434 } else { dport + 1 };
            let sa = SockAddr::from(SocketAddr::new(target_ip, dp));
            let sent = Instant::now();
            if udp_sock.send_to(&payload, &sa).is_ok() {
                probes.push((dp, sent));
            }
        }
        if probes.is_empty() {
            break;
        }

        // 收集回复直到全部匹配或超时
        let deadline = Instant::now() + PROBE_TIMEOUT;
        let mut rtts: Vec<Option<Duration>> = vec![None; probes.len()];
        let mut src: Option<IpAddr> = None;
        let mut dest_hit = false;
        let mut remaining = probes.len();
        while remaining > 0 {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            icmp_sock.set_read_timeout(Some(deadline - now))?;
            match icmp_sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let from_ip = from.as_socket().map(|s| s.ip());
                    let data = util::init_slice(&buf, n);
                    let parsed = parse_udp_icmp(data, target_ip, sport, &probes);
                    trace_dump("udp-icmp-recv", data, parsed.is_some());
                    if let Some((idx, port_unreachable)) = parsed
                        && rtts[idx].is_none()
                    {
                        rtts[idx] = Some(probes[idx].1.elapsed());
                        if let Some(ip) = from_ip {
                            src.get_or_insert(ip);
                        }
                        if port_unreachable {
                            dest_hit = true;
                        }
                        remaining -= 1;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }

        let hop = finish_hop(hop_no, cfg, src, rtts, w)?;
        reached = dest_hit;
        hops.push(hop);
        if dest_hit {
            break;
        }
    }
    Ok((hops, reached))
}

/// TCP SYN 逐跳（`trace --tcp HOST:PORT`）：发 SYN（递增 TTL），中间路由回
/// Time Exceeded，目标回 SYN-ACK（端口开）或 RST（端口关）即到达。
///
/// 每个探测用独立源端口（0x4000..=0x5FFF，见模块文档），按内嵌 TCP 头的
/// (sport, dport) 匹配归属，无需 seq。收包用两个 socket——raw ICMP 收
/// Time Exceeded + raw TCP 收 SYN-ACK/RST——都**先于发送打开**（回环/近零
/// 延迟下回包可能在 send 返回前就回来），libc::poll 同时等待。
#[cfg(unix)]
fn trace_tcp(
    cfg: &PingConfig,
    target_ip: IpAddr,
    max_hops: u32,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    use std::os::fd::AsRawFd;
    let target_port = cfg.port;
    // TCP 伪头部校验和需要源 IP：`-s` 绑定优先，否则 UDP connect 路由探测
    let local_ip = match cfg.source {
        Some(s) => s,
        None => crate::engine::pkg::local_ip_for(&SocketAddr::new(target_ip, target_port))
            .ok_or_else(|| anyhow::anyhow!(t!("errors.trace_no_local_addr")))?,
    };
    let (icmp_sock, _) = create_icmp_socket(target_ip, cfg.source)?;
    let (tcp_sock, target_sa) = create_tcp_socket(target_ip, local_ip)?;

    let mut hops: Vec<Hop> = Vec::new();
    let mut reached = false;
    let mut sport: u16 = 0x4000 + (rand_id() % 0x2000);
    let mut buf: [MaybeUninit<u8>; 8192] = [MaybeUninit::new(0u8); 8192];

    for hop_no in 1..=max_hops {
        if util::interrupted() {
            break;
        }
        set_ttl(&tcp_sock, hop_no, target_ip.is_ipv6())?;

        // 发送本跳全部 SYN（背靠背；每个探测独立源端口）
        let mut probes: Vec<(u16, Instant)> = Vec::with_capacity(PROBES_PER_HOP);
        for _ in 0..PROBES_PER_HOP {
            let sp = sport;
            sport = if sport >= 0x5FFF { 0x4000 } else { sport + 1 };
            let pkt = build_tcp_syn(target_ip, local_ip, sp, target_port);
            let sent = Instant::now();
            if tcp_sock.send_to(&pkt, &target_sa).is_ok() {
                probes.push((sp, sent));
            }
        }
        if probes.is_empty() {
            break;
        }

        // 收集回复直到全部匹配或超时（poll 两个 socket）
        let deadline = Instant::now() + PROBE_TIMEOUT;
        let mut rtts: Vec<Option<Duration>> = vec![None; probes.len()];
        let mut src: Option<IpAddr> = None;
        let mut dest_hit = false;
        let mut remaining = probes.len();
        let icmp_fd = icmp_sock.as_raw_fd();
        let tcp_fd = tcp_sock.as_raw_fd();
        while remaining > 0 {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
            let mut fds = [
                libc::pollfd {
                    fd: icmp_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: tcp_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: fds 指向两个有效 pollfd；超时 ms 为剩余毫秒。
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
            if rc == 0 {
                break; // 超时
            }
            if rc < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            if fds[0].revents & libc::POLLIN != 0 {
                match icmp_sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        let from_ip = from.as_socket().map(|s| s.ip());
                        let data = util::init_slice(&buf, n);
                        let parsed = match_time_exceeded_tcp(data, target_ip, target_port, &probes);
                        trace_dump("tcp-icmp-recv", data, parsed.is_some());
                        if let Some(idx) = parsed
                            && rtts[idx].is_none()
                        {
                            rtts[idx] = Some(probes[idx].1.elapsed());
                            if let Some(ip) = from_ip {
                                src.get_or_insert(ip);
                            }
                            remaining -= 1;
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if fds[1].revents & libc::POLLIN != 0 {
                match tcp_sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        let from_ip = from.as_socket().map(|s| s.ip());
                        let data = util::init_slice(&buf, n);
                        let parsed = match_tcp_reply(data, target_ip, target_port, &probes);
                        trace_dump("tcp-recv", data, parsed.is_some());
                        if let Some(idx) = parsed
                            && rtts[idx].is_none()
                        {
                            rtts[idx] = Some(probes[idx].1.elapsed());
                            if let Some(ip) = from_ip {
                                src.get_or_insert(ip);
                            }
                            dest_hit = true;
                            remaining -= 1;
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }

        let hop = finish_hop(hop_no, cfg, src, rtts, w)?;
        reached = dest_hit;
        hops.push(hop);
        if dest_hit {
            break;
        }
    }
    Ok((hops, reached))
}

/// Windows 禁止 raw TCP socket：`trace --tcp` 不支持（ICMP trace 不受影响）。
#[cfg(windows)]
fn trace_tcp(
    _cfg: &PingConfig,
    _target_ip: IpAddr,
    _max_hops: u32,
    _w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    anyhow::bail!(t!("errors.tcp_trace_windows"));
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
fn finish_hop(
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
        src.and_then(|ip| reverse_dns_timeout(ip, DNS_TIMEOUT))
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
fn trace_dump(what: &str, buf: &[u8], matched: bool) {
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

/// 创建 raw ICMP socket（v4: IPPROTO_ICMP / v6: IPPROTO_ICMPV6），可选源绑定。
fn create_icmp_socket(addr: IpAddr, source: Option<IpAddr>) -> anyhow::Result<(Socket, SockAddr)> {
    match addr {
        IpAddr::V4(v4) => {
            let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                .map_err(crate::ping::icmp::raw_socket_error)?;
            if let Some(src) = source.filter(IpAddr::is_ipv4) {
                sock.bind(&SockAddr::from(SocketAddr::new(src, 0)))?;
            }
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V4(v4), 0))))
        }
        IpAddr::V6(v6) => {
            let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
                .map_err(crate::ping::icmp::raw_socket_error)?;
            if let Some(src) = source.filter(IpAddr::is_ipv6) {
                sock.bind(&SockAddr::from(SocketAddr::new(src, 0)))?;
            }
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V6(v6), 0))))
        }
    }
}

/// 创建 raw TCP socket（`trace --tcp`：发 SYN + 收 SYN-ACK/RST）。
/// 绑定 `local`——保证内核用与伪头部校验和一致的源 IP（收包侧也过滤到该地址）。
#[cfg(unix)]
fn create_tcp_socket(addr: IpAddr, local: IpAddr) -> anyhow::Result<(Socket, SockAddr)> {
    match addr {
        IpAddr::V4(v4) => {
            let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
                .map_err(crate::ping::icmp::raw_socket_error)?;
            sock.bind(&SockAddr::from(SocketAddr::new(local, 0)))?;
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V4(v4), 0))))
        }
        IpAddr::V6(v6) => {
            let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP))
                .map_err(crate::ping::icmp::raw_socket_error)?;
            sock.bind(&SockAddr::from(SocketAddr::new(local, 0)))?;
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V6(v6), 0))))
        }
    }
}

/// 创建普通 UDP socket（`trace --udp`）：绑定固定源端口（`sport`），内核据此
/// 构 UDP 头（校验和内核算）。返回 socket（目标端口每次 send_to 指定）。
fn create_udp_socket(addr: IpAddr, source: Option<IpAddr>, sport: u16) -> anyhow::Result<Socket> {
    let (domain, bind_ip) = match addr {
        IpAddr::V4(_) => (
            Domain::IPV4,
            source
                .filter(IpAddr::is_ipv4)
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        ),
        IpAddr::V6(_) => (
            Domain::IPV6,
            source
                .filter(IpAddr::is_ipv6)
                .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
        ),
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(crate::ping::icmp::raw_socket_error)?;
    sock.bind(&SockAddr::from(SocketAddr::new(bind_ip, sport)))?;
    Ok(sock)
}

/// 设置下一跳 TTL / Hop Limit（IPv4: IP_TTL，IPv6: IPV6_UNICAST_HOPS）。
fn set_ttl(sock: &Socket, ttl: u32, is_v6: bool) -> std::io::Result<()> {
    if is_v6 {
        sock.set_unicast_hops_v6(ttl)
    } else {
        sock.set_ttl_v4(ttl)
    }
}

/// 构建 TCP SYN（20B 无选项），校验和含伪头部（源 IP 由 `local` 给出，
/// 与 `create_tcp_socket` 的绑定一致）。
#[cfg(unix)]
fn build_tcp_syn(target: IpAddr, local: IpAddr, sport: u16, dport: u16) -> Vec<u8> {
    let seq = rand_u32();
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[12] = 5 << 4; // 数据偏移 5（20B）
    tcp[13] = 0x02; // SYN
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // 窗口
    // 伪头部（v4: src+dst+0/proto/len；v6: src+dst+len+0/next） + TCP 段
    let mut sum = Vec::with_capacity(60);
    match (local, target) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum.extend_from_slice(&s.octets());
            sum.extend_from_slice(&d.octets());
            sum.push(0);
            sum.push(6);
            sum.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            sum.extend_from_slice(&s.octets());
            sum.extend_from_slice(&d.octets());
            sum.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
            sum.extend_from_slice(&[0, 0, 0, 6]);
        }
        _ => unreachable!("TCP traceroute 要求源/目标同族"),
    }
    sum.extend_from_slice(&tcp);
    let c = crate::ping::icmp::icmp_cksum(&sum);
    tcp[16] = (c >> 8) as u8;
    tcp[17] = c as u8;
    tcp
}

/// 解析 UDP 模式的 ICMP 回复：Time Exceeded（type 11 code 0 / ICMPv6 type 3
/// code 0）→ 中间跳；Port Unreachable（type 3 code 3 / ICMPv6 type 1 code 4）
/// → 到达目标。回复内嵌原始 UDP 头，按 (sport, dport) 匹配归属。
/// 返回 (命中的探测下标, 是否 Port Unreachable)。
fn parse_udp_icmp(
    buf: &[u8],
    target_ip: IpAddr,
    sport: u16,
    probes: &[(u16, Instant)],
) -> Option<(usize, bool)> {
    let (embedded, is_port_unreachable) = match target_ip {
        IpAddr::V4(_) => {
            if buf.len() < 8 {
                return None;
            }
            let ihl = util::icmp_offset_v4(buf);
            let icmp = buf.get(ihl..)?;
            if icmp.len() < 8 {
                return None;
            }
            match icmp[0] {
                11 if icmp[1] == 0 => {} // Time Exceeded → 中间跳
                3 if icmp[1] == 3 => {}  // Port Unreachable → 到达目标
                _ => return None,        // 其他 ICMP 错误（如 host unreachable）不匹配
            }
            let port_unreachable = icmp[0] == 3;
            // 数据区 = 原始 IP 头 + 前 8B 原始 UDP（unused 在 8B ICMP 头内）
            let body = icmp.get(8..)?;
            if body.is_empty() {
                return None;
            }
            let eihl = ((body[0] & 0x0F) as usize) * 4;
            if eihl < 20 {
                return None;
            }
            // 内嵌 UDP 头被截断（<8B）时按内嵌 dst == 目标归属（与 ICMP/TCP
            // 变体同理）；Port Unreachable 的判定不依赖内嵌内容
            let eip = body.get(0..eihl)?;
            let inner_dst = IpAddr::V4(std::net::Ipv4Addr::new(eip[16], eip[17], eip[18], eip[19]));
            if inner_dst != target_ip {
                return None;
            }
            (body.get(eihl..)?.get(..8), port_unreachable)
        }
        IpAddr::V6(_) => {
            let icmp = if buf.len() >= 48 && buf[0] >> 4 == 6 {
                &buf[40..]
            } else {
                buf
            };
            if icmp.len() < 8 {
                return None;
            }
            match icmp[0] {
                3 if icmp[1] == 0 => {} // Time Exceeded → 中间跳
                1 if icmp[1] == 4 => {} // Port Unreachable → 到达目标
                _ => return None,       // 其他 ICMPv6 错误不匹配
            }
            let port_unreachable = icmp[0] == 1;
            // 数据区 = 原始 IPv6 头(40B) + 前 8B 原始 UDP
            let body = icmp.get(8..)?;
            if body.len() < 40 {
                return None;
            }
            let inner_dst = IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&body[24..40]).ok()?,
            ));
            if inner_dst != target_ip {
                return None;
            }
            (body.get(40..)?.get(..8), port_unreachable)
        }
    };
    let Some(embedded) = embedded else {
        // 截断：按内嵌 dst 归属（Port Unreachable 判定在外层，不受影响）
        return Some((0, is_port_unreachable));
    };
    let esport = u16::from_be_bytes([embedded[0], embedded[1]]);
    let edport = u16::from_be_bytes([embedded[2], embedded[3]]);
    if esport != sport {
        return None;
    }
    probes
        .iter()
        .position(|&(d, _)| d == edport)
        .map(|idx| (idx, is_port_unreachable))
}

/// 解析 TCP 模式的 ICMP Time Exceeded：内嵌原始 TCP 头按 (sport, dport) 匹配
/// 归属（每个探测独立源端口，无需 seq）。返回命中的探测下标（`probes` 内）。
/// 内嵌 TCP 头被路由器截断（<8B）时降级为「内嵌 dst == 目标」归属（记在
/// 首个探测上）——与 ICMP 变体同理（系统 traceroute 连内嵌都不校验）。
#[cfg(unix)]
fn match_time_exceeded_tcp(
    buf: &[u8],
    target_ip: IpAddr,
    dport: u16,
    probes: &[(u16, Instant)],
) -> Option<usize> {
    match target_ip {
        IpAddr::V4(_) => {
            if buf.len() < 8 {
                return None;
            }
            let ihl = util::icmp_offset_v4(buf);
            let icmp = buf.get(ihl..)?;
            if icmp.len() < 8 || icmp[0] != 11 || icmp[1] != 0 {
                return None;
            }
            // 数据区 = 原始 IP 头 + 前 8B 原始 TCP（unused 在 8B ICMP 头内）
            let body = icmp.get(8..)?;
            if body.is_empty() {
                return None;
            }
            let eihl = ((body[0] & 0x0F) as usize) * 4;
            if eihl < 20 {
                return None;
            }
            let eip = body.get(0..eihl)?;
            let inner_dst = IpAddr::V4(std::net::Ipv4Addr::new(eip[16], eip[17], eip[18], eip[19]));
            if inner_dst != target_ip {
                return None;
            }
            match body.get(eihl..)?.get(..8) {
                Some(tcp) => {
                    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
                    let edport = u16::from_be_bytes([tcp[2], tcp[3]]);
                    if edport != dport {
                        return None;
                    }
                    probes.iter().position(|&(s, _)| s == sport)
                }
                None => probes.first().map(|_| 0),
            }
        }
        IpAddr::V6(_) => {
            let icmp = if buf.len() >= 48 && buf[0] >> 4 == 6 {
                &buf[40..]
            } else {
                buf
            };
            if icmp.len() < 8 || icmp[0] != 3 || icmp[1] != 0 {
                return None;
            }
            // 数据区 = 原始 IPv6 头(40B) + 前 8B 原始 TCP
            let body = icmp.get(8..)?;
            if body.len() < 40 {
                return None;
            }
            let inner_dst = IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&body[24..40]).ok()?,
            ));
            if inner_dst != target_ip {
                return None;
            }
            match body.get(40..)?.get(..8) {
                Some(tcp) => {
                    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
                    let edport = u16::from_be_bytes([tcp[2], tcp[3]]);
                    if edport != dport {
                        return None;
                    }
                    probes.iter().position(|&(s, _)| s == sport)
                }
                None => probes.first().map(|_| 0),
            }
        }
    }
}

/// 解析 TCP 模式的 SYN-ACK / RST 回包（raw TCP socket 收到）：源地址须为目标、
/// (src port, dst port) 匹配探测 → 命中下标。SYN-ACK（端口开）与 RST（端口关）
/// 都算到达目标。
#[cfg(unix)]
fn match_tcp_reply(
    buf: &[u8],
    target_ip: IpAddr,
    target_port: u16,
    probes: &[(u16, Instant)],
) -> Option<usize> {
    match target_ip {
        IpAddr::V4(_) => {
            if buf.len() < 8 {
                return None;
            }
            let ihl = util::icmp_offset_v4(buf);
            match_tcp_segment(buf.get(ihl..)?, target_port, probes)
        }
        IpAddr::V6(_) => {
            // Linux 惯例无 IPv6 头；部分平台带头。TCP 首字节是源端口高位，
            // 0x60-0x6F 时 version-nibble 框架判断会误判——先按无头解析，
            // 不中再按带头（无头解析对带头包不会误中：其 src_port 位是 IPv6
            // 载荷长度字段、dst_port 位是 0x60xx——探测源端口限制在 0x4000..
            // 0x5FFF 正是防这里的假命中）。
            if let Some(idx) = match_tcp_segment(buf, target_port, probes) {
                return Some(idx);
            }
            if buf.len() >= 40 && buf[0] >> 4 == 6 {
                match_tcp_segment(buf.get(40..)?, target_port, probes)
            } else {
                None
            }
        }
    }
}

/// 匹配单个 TCP 段（不含外层 IP/IPv6 头）：源端口 = 目标端口、目标端口在探测
/// 源端口表内、标志为 SYN-ACK 或 RST。
#[cfg(unix)]
fn match_tcp_segment(tcp: &[u8], target_port: u16, probes: &[(u16, Instant)]) -> Option<usize> {
    if tcp.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    let syn_ack = flags & 0x12 == 0x12;
    let rst = flags & 0x04 != 0;
    if !(syn_ack || rst) || src_port != target_port {
        return None;
    }
    probes.iter().position(|&(s, _)| s == dst_port)
}

/// 逐跳文本行：`跳号  rtt1  rtt2  rtt3  主机名 (IP)`；超时打印红色 `*`。
fn print_hop_line<W: WriteColor>(w: &mut W, hop: &Hop) -> anyhow::Result<()> {
    write!(w, "{:>3}  ", hop.hop)?;
    for rtt in &hop.rtts {
        match rtt {
            Some(d) => {
                let s = format!("{:.2} ms", d.as_secs_f64() * 1000.0);
                output::print_yellow(w, format!("{s:>9}"))?;
            }
            None => output::print_red(w, format!("{:>9}", "*"))?,
        }
    }
    write!(w, "  ")?;
    match (&hop.hostname, hop.addr) {
        (Some(name), Some(ip)) if name != &ip.to_string() => {
            write!(w, "{name} ")?;
            output::print_dim(w, format!("({ip})"))?;
        }
        (_, Some(ip)) => output::print_cyan(w, ip.to_string())?,
        (None, None) => {}
        // hostname 恒由 addr 派生，此状态仅防御性保留
        (Some(_), None) => {}
    }
    writeln!(w)?;
    Ok(())
}

/// 逐跳 JSONL 行：`{"type":"traceroute","target","ts","hop","addr","hostname","rtt_ms"}`。
/// rtt_ms 中超时项为 null；全超时省略 addr/hostname。
fn print_hop_json(hop: &Hop) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let rtt_ms: Vec<Option<f64>> = hop
        .rtts
        .iter()
        .map(|r| r.map(|d| d.as_secs_f64() * 1000.0))
        .collect();
    let mut line = serde_json::json!({
        "type": "traceroute",
        "hop": hop.hop,
        "ts": ts,
        "rtt_ms": rtt_ms,
    });
    if let Some(ip) = hop.addr {
        line["addr"] = serde_json::json!(ip.to_string());
        if let Some(name) = &hop.hostname {
            line["hostname"] = serde_json::json!(name);
        }
    }
    println!("{line}");
}

/// 解析 IPv4 回复：IP 头 + ICMP。返回 (匹配的 seq, 是否 echo reply)。
///
/// - echo reply（type 0）：id/seq 在 ICMP 头偏移 4/6 → 目标回显。
/// - Time Exceeded（type 11 code 0）：ICMP 数据区含原始报文
///   （内嵌 IP 头 + 前 8 字节 ICMP）。id/seq 精确匹配优先；**内嵌 ICMP 被
///   路由器截断（<8B，常见实现）时降级为「内嵌 dst == 目标」归属**——
///   内嵌 IP 头必完整（RFC 1812 至少整个 IP 头），dst 恒可读；系统
///   traceroute 连内嵌都不校验，我们仍比它严谨（完整 ICMP 的 id/seq 不匹配
///   时不归属，避免误收别人同时段的探测）。
fn parse_reply_v4(buf: &[u8], target: IpAddr, ident: u16, want: &[u16]) -> Option<(u16, bool)> {
    if buf.len() < 8 {
        return None;
    }
    let ihl = util::icmp_offset_v4(buf);
    let icmp = buf.get(ihl..)?;
    if icmp.len() < 8 {
        return None;
    }
    match icmp[0] {
        0 => {
            let id = u16::from_be_bytes([icmp[4], icmp[5]]);
            let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
            (id == ident && want.contains(&seq)).then_some((seq, true))
        }
        11 if icmp[1] == 0 => {
            // Time Exceeded：数据区 = 原始 IP 头 + 前 8B 原始 ICMP
            // （unused 4B 在 8B ICMP 头内，无额外填充——RFC 792）
            let body = icmp.get(8..)?;
            if body.is_empty() {
                return None; // 至少要有内嵌 IP 头的首字节（ihl 字段）
            }
            let eihl = ((body[0] & 0x0F) as usize) * 4;
            if eihl < 20 {
                return None; // 防御非法 IHL
            }
            // 内嵌 IP 头完整（≥20B）→ dst 恒可读，作为截断时的归属依据
            let eip = body.get(0..eihl)?;
            let inner_dst = IpAddr::V4(std::net::Ipv4Addr::new(eip[16], eip[17], eip[18], eip[19]));
            if inner_dst != target {
                return None; // 内嵌报文不是发给目标的探测
            }
            let Some(eicmp) = body.get(eihl..)?.get(..8) else {
                // 截断（<8B ICMP）：按内嵌 dst 归属，RTT 记在首个探测上
                return want.first().copied().map(|s| (s, false));
            };
            let id = u16::from_be_bytes([eicmp[4], eicmp[5]]);
            let seq = u16::from_be_bytes([eicmp[6], eicmp[7]]);
            if id == ident && want.contains(&seq) {
                Some((seq, false))
            } else {
                None // ICMP 完整但 id/seq 不匹配：不是我们的探测
            }
        }
        _ => None,
    }
}

/// 解析 IPv6 回复。`icmp` 起点按框架探测：首字节 version nibble == 6
/// （且长度足够）视为含 40B IPv6 头，否则直接是 ICMPv6（Linux 惯例）。
///
/// - echo reply：type 129，id/seq 在 ICMPv6 头偏移 4/6 → 目标回显。
/// - Time Exceeded：type 3 code 0，数据区含原始报文
///   （内嵌 40B IPv6 头 + 前 8B ICMPv6）。id/seq 精确匹配优先，截断时按
///   内嵌 dst == 目标归属（与 v4 同理）。
fn parse_reply_v6(buf: &[u8], target: IpAddr, ident: u16, want: &[u16]) -> Option<(u16, bool)> {
    let icmp = if buf.len() >= 48 && buf[0] >> 4 == 6 {
        &buf[40..]
    } else {
        buf
    };
    if icmp.len() < 8 {
        return None;
    }
    match icmp[0] {
        129 => {
            let id = u16::from_be_bytes([icmp[4], icmp[5]]);
            let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
            (id == ident && want.contains(&seq)).then_some((seq, true))
        }
        3 if icmp[1] == 0 => {
            // Time Exceeded：数据区 = 原始 IPv6 头(40B) + 前 8B 原始 ICMPv6
            let body = icmp.get(8..)?;
            if body.len() < 40 {
                return None; // 内嵌 IPv6 头完整（40B）即可读 dst
            }
            // 内嵌 IPv6 头从 body[0] 起：dst 在偏移 24..40
            let inner_dst = IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&body[24..40]).ok()?,
            ));
            if inner_dst != target {
                return None;
            }
            let Some(eicmp) = body.get(40..)?.get(..8) else {
                return want.first().copied().map(|s| (s, false));
            };
            let id = u16::from_be_bytes([eicmp[4], eicmp[5]]);
            let seq = u16::from_be_bytes([eicmp[6], eicmp[7]]);
            if id == ident && want.contains(&seq) {
                Some((seq, false))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// 构建 ICMP echo request（type 8 / 128），载荷 32 字节循环填充。
fn build_echo(addr: IpAddr, ident: u16, seq: u16, payload: usize) -> Vec<u8> {
    let mut b = vec![0u8; 8 + payload];
    b[0] = if addr.is_ipv4() { 8 } else { 128 };
    b[1] = 0;
    b[4] = (ident >> 8) as u8;
    b[5] = ident as u8;
    b[6] = (seq >> 8) as u8;
    b[7] = seq as u8;
    for i in 0..payload {
        b[8 + i] = (i % 256) as u8;
    }
    if addr.is_ipv4() {
        let c = crate::ping::icmp::icmp_cksum(&b);
        b[2] = (c >> 8) as u8;
        b[3] = c as u8;
    }
    b
}

fn rand_id() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u16
}

#[cfg(unix)]
fn rand_u32() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u32
}

/// 反向 DNS 查询（限时）：`-d` 之外每跳一次，超时/无 PTR 返回 None。
///
/// getnameinfo 是阻塞 DNS 查询，放在独立线程跑，主流程用 recv_timeout
/// 限时；超时后线程继续在后台等 DNS 完成（至多几秒）自然退出。
fn reverse_dns_timeout(ip: IpAddr, timeout: Duration) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(reverse_dns(ip));
    });
    rx.recv_timeout(timeout).ok().flatten()
}

/// Unix（Linux/macOS/BSD）：libc getnameinfo。
#[cfg(unix)]
fn reverse_dns(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    let mut host = [0i8; libc::NI_MAXHOST as usize];
    let rc = match ip {
        IpAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_be_bytes(v4.octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sa 为按族初始化的有效 sockaddr_in；host 缓冲区足够大（NI_MAXHOST）。
            unsafe {
                libc::getnameinfo(
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.octets(),
                },
                sin6_scope_id: 0,
            };
            // SAFETY: sa 为按族初始化的有效 sockaddr_in6；host 缓冲区足够大（NI_MAXHOST）。
            unsafe {
                libc::getnameinfo(
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    // SAFETY: rc == 0 时 host 是 NUL 结尾的 C 字符串。
    Some(
        unsafe { CStr::from_ptr(host.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Windows：ws2_32 getnameinfo（libc crate 在 Windows 不导出 sockaddr 类型与
/// getnameinfo，按 WinSock 布局自声明；ws2_32.dll 是 WinSock 核心 DLL，Win7 基线可用）。
#[cfg(windows)]
fn reverse_dns(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;

    // WinSock sockaddr 布局（ADDRESS_FAMILY=u16；均为 repr(C)）
    #[repr(C)]
    struct Sockaddr {
        sa_family: u16,
        sa_data: [u8; 14],
    }
    #[repr(C)]
    struct SockaddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: u32, // 网络字节序（BE）
        sin_zero: [u8; 8],
    }
    #[repr(C)]
    struct SockaddrIn6 {
        sin6_family: u16,
        sin6_port: u16,
        sin6_flowinfo: u32,
        sin6_addr: [u8; 16],
        sin6_scope_id: u32,
    }
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 23;
    const NI_NAMEREQD: i32 = 0x4;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn getnameinfo(
            sa: *const Sockaddr,
            salen: i32,
            host: *mut i8,
            hostlen: u32,
            serv: *mut i8,
            servlen: u32,
            flags: i32,
        ) -> i32;
    }

    let mut host = [0i8; 1025];
    let rc = match ip {
        IpAddr::V4(v4) => {
            let sa = SockaddrIn {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: u32::from_be_bytes(v4.octets()),
                sin_zero: [0; 8],
            };
            // SAFETY: sa 为按族初始化的有效 sockaddr_in；host 缓冲区足够大（NI_MAXHOST=1025）。
            unsafe {
                getnameinfo(
                    &sa as *const _ as *const Sockaddr,
                    std::mem::size_of::<SockaddrIn>() as i32,
                    host.as_mut_ptr(),
                    host.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(v6) => {
            let sa = SockaddrIn6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: v6.octets(),
                sin6_scope_id: 0,
            };
            // SAFETY: sa 为按族初始化的有效 sockaddr_in6；host 缓冲区足够大（NI_MAXHOST=1025）。
            unsafe {
                getnameinfo(
                    &sa as *const _ as *const Sockaddr,
                    std::mem::size_of::<SockaddrIn6>() as i32,
                    host.as_mut_ptr(),
                    host.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    // SAFETY: rc == 0 时 host 是 NUL 结尾的 C 字符串。
    Some(
        unsafe { CStr::from_ptr(host.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// 构造「IP 头 + icmp 载荷」的 IPv4 回复（ihl 5）。
    fn v4_frame(icmp: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 20 + icmp.len()];
        b[0] = 0x45;
        b[1] = 0;
        b[8] = 64; // TTL
        b[20..].copy_from_slice(icmp);
        b
    }

    fn echo_icmp(typ: u8, ident: u16, seq: u16) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + 16];
        icmp[0] = typ;
        icmp[4] = (ident >> 8) as u8;
        icmp[5] = ident as u8;
        icmp[6] = (seq >> 8) as u8;
        icmp[7] = seq as u8;
        icmp
    }

    /// Time Exceeded（type 11 code 0）：8B ICMP 头（含 4B unused）+ 内嵌 IP 头(20B) + 内嵌 echo ICMP(8B)。
    fn ttl_exceeded_v4(ident: u16, seq: u16) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + 20 + 8];
        icmp[0] = 11;
        icmp[1] = 0;
        icmp[8] = 0x45; // 内嵌 IP 头：IHL 5（20B）
        icmp[24..28].copy_from_slice(&[8, 8, 8, 8]); // 内嵌 dst（测试目标）
        let mut inner = echo_icmp(8, ident, seq);
        inner.truncate(8);
        icmp[28..36].copy_from_slice(&inner);
        icmp
    }

    #[test]
    fn v4_echo_reply_matches() {
        let buf = v4_frame(&echo_icmp(0, 0x1234, 7));
        assert_eq!(
            parse_reply_v4(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x1234, &[7]),
            Some((7, true))
        );
    }

    #[test]
    fn v4_echo_reply_wrong_id_seq() {
        let buf = v4_frame(&echo_icmp(0, 0x1234, 7));
        assert_eq!(
            parse_reply_v4(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x9999, &[7]),
            None
        );
        assert_eq!(
            parse_reply_v4(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x1234, &[8]),
            None
        );
    }

    #[test]
    fn v4_ttl_exceeded_matches() {
        let buf = v4_frame(&ttl_exceeded_v4(0x1234, 3));
        assert_eq!(
            parse_reply_v4(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x1234, &[3, 4]),
            Some((3, false))
        );
    }

    #[test]
    fn v4_ttl_exceeded_wrong_seq() {
        let buf = v4_frame(&ttl_exceeded_v4(0x1234, 3));
        assert_eq!(
            parse_reply_v4(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x1234, &[9]),
            None
        );
    }

    #[test]
    fn v4_unreachable_ignored() {
        let mut icmp = vec![0u8; 8];
        icmp[0] = 3; // destination unreachable
        assert_eq!(
            parse_reply_v4(
                &v4_frame(&icmp),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                0,
                &[0]
            ),
            None
        );
    }

    #[test]
    fn v4_truncated() {
        assert_eq!(
            parse_reply_v4(&[0u8; 4], IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0, &[0]),
            None
        );
        // 20B 零报文在无头格式下是合法的 echo reply（type 0, id 0, seq 0）——
        // 用不匹配的 id 验证截断不会误中
        let mut b = [0u8; 20];
        b[4] = 1;
        b[5] = 1;
        assert_eq!(
            parse_reply_v4(&b, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0, &[0]),
            None
        );
        // Time Exceeded 内嵌数据不足
        let mut icmp = vec![0u8; 16];
        icmp[0] = 11;
        assert_eq!(
            parse_reply_v4(
                &v4_frame(&icmp),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                0,
                &[0]
            ),
            None
        );
    }

    #[test]
    fn v4_ttl_exceeded_no_echo_data() {
        // 内嵌 20B IP 头但 ICMP 不足 8B：dst 为全零 ≠ 目标 → None
        let mut icmp = vec![0u8; 8 + 20 + 4];
        icmp[0] = 11;
        icmp[1] = 0;
        icmp[8] = 0x45; // 内嵌 IP 头 IHL
        assert_eq!(
            parse_reply_v4(
                &v4_frame(&icmp),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                0,
                &[0]
            ),
            None
        );
    }

    #[test]
    fn v4_ttl_exceeded_truncated_falls_back_to_dst() {
        // 内嵌 ICMP 被路由器截断（仅 4B，RFC 1812 之外常见实现）：
        // 内嵌 IP 头完整（dst 可读）→ 按 dst == 目标归属（系统 traceroute 连
        // 内嵌都不校验，我们仍比它严谨）
        let mut icmp = vec![0u8; 8 + 20 + 4];
        icmp[0] = 11;
        icmp[1] = 0;
        icmp[8] = 0x45; // 内嵌 IP 头 IHL
        icmp[24..28].copy_from_slice(&[8, 8, 8, 8]); // 内嵌 dst
        let buf = v4_frame(&icmp);
        assert_eq!(
            parse_reply_v4(
                &buf,
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                0x1234,
                &[0, 1, 2]
            ),
            Some((0, false)),
            "截断时按内嵌 dst 归属"
        );
        // 内嵌 dst 不是目标 → 不归属
        let mut other = icmp.clone();
        other[27] = 9; // 8.8.8.9
        assert_eq!(
            parse_reply_v4(
                &v4_frame(&other),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                0x1234,
                &[0]
            ),
            None
        );
    }

    #[test]
    fn real_dump_packets_match() {
        // 真实抓包回归（用户 PRPING_TRACE_DUMP 转储）：Time Exceeded 内嵌布局
        // 按 RFC 792——8B ICMP 头（含 4B unused）+ 原始 IP 头 + 原始 ICMP，
        // 内嵌 IP 头从 ICMP 第 8 字节起。曾因误加 4B 偏移导致中间跳全 `*`。
        fn hex(s: &str) -> Vec<u8> {
            s.as_bytes()
                .chunks(2)
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect()
        }
        // 88B：172.18.0.1（Docker 网关）回 Time Exceeded，内嵌完整 60B 探测包
        let full = hex("45c000580d3900003f01afeeac120001c0a85102\
             0b00f4ff00000000\
             4500003c2a7540000101899ac0a851026ef24515\
             08001cf6ea050003\
             000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        assert_eq!(
            parse_reply_v4(
                &full,
                IpAddr::V4(Ipv4Addr::new(110, 242, 69, 21)),
                0xea05,
                &[3, 4, 5]
            ),
            Some((3, false)),
            "完整内嵌（id/seq 可读）按 id/seq 归属"
        );
        // 56B：221.194.45.130 回 Time Exceeded，内嵌仅 28B（20B IP + 8B ICMP，无载荷）
        let trunc = hex("4500003800000000f801a5d5ddc22d82c0a85102\
             0b00e60000000000\
             4500003c36f8400001017d17c0a851026ef24515\
             08001ce4ea050015");
        assert_eq!(
            parse_reply_v4(
                &trunc,
                IpAddr::V4(Ipv4Addr::new(110, 242, 69, 21)),
                0xea05,
                &[21, 22, 23]
            ),
            Some((21, false)),
            "内嵌 8B ICMP 完整（id/seq 可读）仍按 id/seq 归属"
        );
        // 同包但 id 不匹配 → 不归属（防误认）
        assert_eq!(
            parse_reply_v4(
                &trunc,
                IpAddr::V4(Ipv4Addr::new(110, 242, 69, 21)),
                0x9999,
                &[21]
            ),
            None
        );
        // 内嵌 dst 不是目标 → 不归属
        assert_eq!(
            parse_reply_v4(&trunc, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0xea05, &[21]),
            None
        );
    }

    #[test]
    fn v6_framing_with_header() {
        // Windows 惯例：buf 含 40B IPv6 头（version 6）→ ICMPv6 从 40 起
        let mut b = vec![0u8; 40 + 8];
        b[0] = 0x60;
        b[7] = 64;
        let icmp = &mut b[40..];
        icmp[0] = 129; // echo reply
        icmp[4] = 0xAB;
        icmp[5] = 0xCD;
        icmp[6] = 0;
        icmp[7] = 5;
        assert_eq!(
            parse_reply_v6(&b, IpAddr::V6("2001:db8::1".parse().unwrap()), 0xABCD, &[5]),
            Some((5, true))
        );
    }

    #[test]
    fn v6_framing_without_header() {
        // Linux 惯例：直接是 ICMPv6
        let mut icmp = vec![0u8; 8];
        icmp[0] = 129;
        icmp[4] = 0xAB;
        icmp[5] = 0xCD;
        icmp[6] = 0;
        icmp[7] = 5;
        assert_eq!(
            parse_reply_v6(
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
        // ICMPv6 Time Exceeded（type 3 code 0）：8B ICMPv6 头（含 4B unused）+ 内嵌 40B IPv6 头 + 8B ICMPv6
        let mut icmp = vec![0u8; 8 + 40 + 8];
        icmp[0] = 3;
        icmp[1] = 0;
        icmp[32..48].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // 内嵌 dst ::1
        let eicmp = &mut icmp[8 + 40..];
        eicmp[0] = 128;
        eicmp[4] = 0x12;
        eicmp[5] = 0x34;
        eicmp[6] = 0;
        eicmp[7] = 9;
        assert_eq!(
            parse_reply_v6(
                &icmp,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                0x1234,
                &[9, 10]
            ),
            Some((9, false))
        );
        assert_eq!(
            parse_reply_v6(
                &icmp,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                0x1234,
                &[11]
            ),
            None
        );
    }

    #[test]
    fn v6_truncated() {
        assert_eq!(
            parse_reply_v6(
                &[0u8; 4],
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                0,
                &[0]
            ),
            None
        );
        let mut icmp = vec![0u8; 8 + 40 + 4]; // 内嵌 IPv6 头完整但不足 48B
        icmp[0] = 3;
        assert_eq!(
            parse_reply_v6(&icmp, IpAddr::V6("2001:db8::1".parse().unwrap()), 0, &[0]),
            None
        );
    }

    #[test]
    fn echo_build_layout() {
        let v4 = build_echo(IpAddr::V4(Ipv4Addr::LOCALHOST), 0x1234, 7, 32);
        assert_eq!(v4.len(), 40);
        assert_eq!(v4[0], 8);
        assert_eq!(v4[4], 0x12);
        assert_eq!(v4[7], 7);
        assert_eq!(v4[8], 0);
        assert_eq!(v4[39], 31);
        // IPv6 头字节为 type 128、无 checksum 字段依赖
        let v6 = build_echo(IpAddr::V6("::1".parse().unwrap()), 0x1234, 7, 32);
        assert_eq!(v6[0], 128);
        assert_eq!(v6[4], 0x12);
        assert_eq!(v6[7], 7);
    }

    #[test]
    fn hop_line_formatting() {
        let hop = Hop {
            hop: 1,
            rtts: vec![
                Some(Duration::from_millis(1)),
                None,
                Some(Duration::from_millis(2)),
            ],
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            hostname: None,
        };
        let mut w = termcolor::StandardStream::stdout(termcolor::ColorChoice::Never);
        print_hop_line(&mut w, &hop).unwrap();
    }

    #[test]
    fn hop_line_hostname() {
        let hop = Hop {
            hop: 2,
            rtts: vec![Some(Duration::from_millis(5)); 3],
            addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            hostname: Some("gw.example.com".into()),
        };
        let mut w = termcolor::StandardStream::stdout(termcolor::ColorChoice::Never);
        print_hop_line(&mut w, &hop).unwrap();
    }

    // ---------- UDP 探测 ----------

    /// Time Exceeded / Port Unreachable（v4）：8B ICMP 头（含 4B unused）+ 内嵌 IP 头(20B) + 内嵌 UDP(8B)。
    fn udp_icmp_v4(typ: u8, code: u8, sport: u16, dport: u16) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + 20 + 8];
        icmp[0] = typ;
        icmp[1] = code;
        icmp[8] = 0x45; // 内嵌 IP 头：IHL 5
        icmp[24..28].copy_from_slice(&[8, 8, 8, 8]); // 内嵌 dst（测试目标）
        icmp[28..30].copy_from_slice(&sport.to_be_bytes());
        icmp[30..32].copy_from_slice(&dport.to_be_bytes());
        icmp
    }

    fn udp_probes(dports: &[u16]) -> Vec<(u16, Instant)> {
        dports.iter().map(|&d| (d, Instant::now())).collect()
    }

    #[test]
    fn udp_time_exceeded_matches() {
        let icmp = udp_icmp_v4(11, 0, 0x4123, 33435);
        let buf = v4_frame(&icmp);
        let want = udp_probes(&[33434, 33435]);
        assert_eq!(
            parse_udp_icmp(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x4123, &want),
            Some((1, false))
        );
    }

    #[test]
    fn udp_port_unreachable_matches() {
        let icmp = udp_icmp_v4(3, 3, 0x4123, 33436);
        let buf = v4_frame(&icmp);
        let want = udp_probes(&[33436]);
        assert_eq!(
            parse_udp_icmp(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x4123, &want),
            Some((0, true)),
            "Port Unreachable 应标记到达"
        );
    }

    #[test]
    fn udp_wrong_ports_ignored() {
        let want = udp_probes(&[33434]);
        // dport 不匹配
        let icmp = udp_icmp_v4(3, 3, 0x4123, 9999);
        assert_eq!(
            parse_udp_icmp(
                &v4_frame(&icmp),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                0x4123,
                &want
            ),
            None
        );
        // sport 不匹配
        let icmp = udp_icmp_v4(3, 3, 0x9999, 33434);
        assert_eq!(
            parse_udp_icmp(
                &v4_frame(&icmp),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                0x4123,
                &want
            ),
            None
        );
    }

    #[test]
    fn udp_other_icmp_errors_ignored() {
        // host unreachable（type 3 code 1）不匹配
        let icmp = udp_icmp_v4(3, 1, 0x4123, 33434);
        let want = udp_probes(&[33434]);
        assert_eq!(
            parse_udp_icmp(
                &v4_frame(&icmp),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                0x4123,
                &want
            ),
            None
        );
        // 截断
        assert_eq!(
            parse_udp_icmp(&[0u8; 4], IpAddr::V4(Ipv4Addr::LOCALHOST), 0x4123, &want),
            None
        );
    }

    #[test]
    fn udp_v6_matches() {
        // ICMPv6 Port Unreachable（type 1 code 4）：8B ICMPv6 头（含 4B unused）+ 内嵌 40B IPv6 头 + 8B UDP
        let mut icmp = vec![0u8; 8 + 40 + 8];
        icmp[0] = 1;
        icmp[1] = 4;
        icmp[32..48].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // 内嵌 dst（2001:db8::1，测试目标）
        icmp[8 + 40..8 + 42].copy_from_slice(&0x4123u16.to_be_bytes());
        icmp[8 + 42..8 + 44].copy_from_slice(&33435u16.to_be_bytes());
        let want = udp_probes(&[33435]);
        assert_eq!(
            parse_udp_icmp(
                &icmp,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                0x4123,
                &want
            ),
            Some((0, true))
        );
        // ICMPv6 Time Exceeded（type 3 code 0）
        icmp[0] = 3;
        icmp[1] = 0;
        assert_eq!(
            parse_udp_icmp(
                &icmp,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                0x4123,
                &want
            ),
            Some((0, false))
        );
        // dport 不匹配
        assert_eq!(
            parse_udp_icmp(
                &icmp,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                0x4123,
                &udp_probes(&[9999])
            ),
            None
        );
    }

    // ---------- Windows 格式（raw ICMP 收包不含 IP 头）----------

    #[test]
    fn v4_no_header_time_exceeded_matches() {
        // Windows：直接是 ICMP 报文（无外层 IP 头）——Time Exceeded 内嵌
        // 原始 IP 头(20B) + 前 8B ICMP（id/seq 在 eicmp[4..8]，eicmp 从 icmp[28] 起）
        let mut icmp = vec![0u8; 8 + 20 + 8];
        icmp[0] = 11;
        icmp[1] = 0;
        icmp[8] = 0x45; // 内嵌 IP 头 IHL
        icmp[24..28].copy_from_slice(&[8, 8, 8, 8]); // 内嵌 dst（测试目标）
        icmp[32] = 0x12;
        icmp[33] = 0x34; // 内嵌 ICMP id
        icmp[34] = 0;
        icmp[35] = 3; // 内嵌 ICMP seq
        assert_eq!(
            parse_reply_v4(&icmp, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x1234, &[3]),
            Some((3, false))
        );
        // 不含头 echo reply
        let mut reply = vec![0u8; 8 + 8];
        reply[0] = 0; // type 0
        reply[4] = 0x12;
        reply[5] = 0x34;
        reply[6] = 0;
        reply[7] = 7;
        assert_eq!(
            parse_reply_v4(&reply, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x1234, &[7]),
            Some((7, true))
        );
    }

    #[test]
    fn udp_no_header_icmp_matches() {
        // Windows：直接是 ICMP（无 IP 头）——Port Unreachable
        let mut icmp = vec![0u8; 8 + 20 + 8];
        icmp[0] = 3;
        icmp[1] = 3;
        icmp[8] = 0x45;
        icmp[24..28].copy_from_slice(&[8, 8, 8, 8]); // 内嵌 dst（测试目标）
        icmp[28..30].copy_from_slice(&0x4123u16.to_be_bytes());
        icmp[30..32].copy_from_slice(&33434u16.to_be_bytes());
        let want = udp_probes(&[33434]);
        assert_eq!(
            parse_udp_icmp(&icmp, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0x4123, &want),
            Some((0, true)),
            "Windows 无头格式应匹配"
        );
    }
}

// ---------- TCP SYN 探测单测（仅 unix：Windows 无 raw TCP socket）----------

#[cfg(all(test, unix))]
mod tcp_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn probes(sports: &[u16]) -> Vec<(u16, Instant)> {
        sports.iter().map(|&s| (s, Instant::now())).collect()
    }

    /// 构造「IP 头 + icmp 载荷」的 IPv4 报文（ihl 5；与 mod tests 的 v4_frame 同构）。
    fn v4_frame(icmp: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 20 + icmp.len()];
        b[0] = 0x45;
        b[8] = 64;
        b[20..].copy_from_slice(icmp);
        b
    }

    /// 独立反码校验和实现（RFC 1071；与被测 icmp_cksum 代码路径分离）。
    fn naive_cksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in data.chunks(2) {
            let w = if pair.len() == 2 {
                u16::from_be_bytes([pair[0], pair[1]]) as u32
            } else {
                (pair[0] as u32) << 8
            };
            sum += w;
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn tcp_syn_layout_and_checksum() {
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let dst = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let pkt = build_tcp_syn(dst, src, 0x4123, 443);
        assert_eq!(pkt.len(), 20);
        assert_eq!(&pkt[0..2], &[0x41, 0x23], "源端口");
        assert_eq!(&pkt[2..4], &[0x01, 0xBB], "目标端口 443");
        assert_eq!(pkt[12], 5 << 4, "数据偏移");
        assert_eq!(pkt[13], 0x02, "SYN 标志");
        // 校验和：伪头部 + 校验和字段清零的 TCP 段，独立实现应与存储值一致
        let mut sum = Vec::new();
        let (IpAddr::V4(s), IpAddr::V4(d)) = (src, dst) else {
            unreachable!()
        };
        sum.extend_from_slice(&s.octets());
        sum.extend_from_slice(&d.octets());
        sum.extend_from_slice(&[0, 6]);
        sum.extend_from_slice(&(20u16).to_be_bytes());
        let mut tcp = pkt.clone();
        tcp[16] = 0;
        tcp[17] = 0;
        sum.extend_from_slice(&tcp);
        let stored = u16::from_be_bytes([pkt[16], pkt[17]]);
        assert_eq!(naive_cksum(&sum), stored, "独立实现校验和一致");
        assert_ne!(stored, 0);
    }

    #[test]
    fn tcp_syn_v6_layout() {
        let src = IpAddr::V6("fe80::1".parse().unwrap());
        let dst = IpAddr::V6("2001:4860:4860::8888".parse().unwrap());
        let pkt = build_tcp_syn(dst, src, 0x4A01, 22);
        assert_eq!(pkt.len(), 20);
        assert_eq!(pkt[13], 0x02);
        let mut sum = Vec::new();
        let (IpAddr::V6(s), IpAddr::V6(d)) = (src, dst) else {
            unreachable!()
        };
        sum.extend_from_slice(&s.octets());
        sum.extend_from_slice(&d.octets());
        sum.extend_from_slice(&(20u32).to_be_bytes());
        sum.extend_from_slice(&[0, 0, 0, 6]);
        let mut tcp = pkt.clone();
        tcp[16] = 0;
        tcp[17] = 0;
        sum.extend_from_slice(&tcp);
        assert_eq!(naive_cksum(&sum), u16::from_be_bytes([pkt[16], pkt[17]]));
    }

    /// 构造「IP 头 + tcp 段」的 IPv4 raw TCP 回包。
    fn v4_tcp_frame(tcp: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 20 + tcp.len()];
        b[0] = 0x45;
        b[9] = 6; // 协议 TCP
        b[20..].copy_from_slice(tcp);
        b
    }

    fn tcp_seg(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp
    }

    #[test]
    fn tcp_reply_syn_ack_matches() {
        let buf = v4_tcp_frame(&tcp_seg(443, 0x4123, 0x12)); // SYN-ACK
        let want = probes(&[0x4123, 0x4124]);
        assert_eq!(
            match_tcp_reply(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443, &want),
            Some(0)
        );
    }

    #[test]
    fn tcp_reply_rst_matches() {
        let buf = v4_tcp_frame(&tcp_seg(22, 0x4A01, 0x04)); // RST
        let want = probes(&[0x4A00, 0x4A01]);
        assert_eq!(
            match_tcp_reply(&buf, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 22, &want),
            Some(1)
        );
    }

    #[test]
    fn tcp_reply_wrong_port_or_flags() {
        let want = probes(&[0x4123]);
        // 端口不匹配
        let buf = v4_tcp_frame(&tcp_seg(444, 0x4123, 0x12));
        assert_eq!(
            match_tcp_reply(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443, &want),
            None
        );
        // 纯 ACK（非 SYN-ACK/RST）不匹配
        let buf = v4_tcp_frame(&tcp_seg(443, 0x4123, 0x10));
        assert_eq!(
            match_tcp_reply(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443, &want),
            None
        );
        // 截断
        assert_eq!(
            match_tcp_reply(&[0u8; 10], IpAddr::V4(Ipv4Addr::LOCALHOST), 443, &want),
            None
        );
    }

    #[test]
    fn tcp_reply_v6_framing() {
        // 无 IPv6 头（Linux 惯例）：直接是 TCP
        let seg = tcp_seg(443, 0x4A01, 0x12);
        let want = probes(&[0x4A01]);
        assert_eq!(
            match_tcp_reply(&seg, IpAddr::V6("2001:db8::1".parse().unwrap()), 443, &want),
            Some(0)
        );
        // 带头（version 6）：40B IPv6 头 + TCP
        let mut with_hdr = vec![0u8; 40 + 20];
        with_hdr[0] = 0x60;
        with_hdr[40..].copy_from_slice(&seg);
        assert_eq!(
            match_tcp_reply(
                &with_hdr,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                443,
                &want
            ),
            Some(0)
        );
        // 目标端口 0x62xx：回复首字节 = 源端口高位 = 0x6x，且 TCP 段 pad 到
        // 40B 触发 version-nibble 歧义——无头优先解析仍应命中
        let mut seg62 = tcp_seg(0x6201, 0x4A01, 0x12);
        seg62.resize(40, 0); // 模拟带选项的 SYN-ACK
        let want2 = probes(&[0x4A01]);
        assert_eq!(
            match_tcp_reply(
                &seg62,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                0x6201,
                &want2
            ),
            Some(0),
            "0x6201 目标端口应命中（无头优先解析）"
        );
        // 带头包（Windows 惯例）不会被无头解析误中：dst_port 位是 IPv6 头
        // 版本/流标（0x60xx），不在探测源端口范围 0x4000..=0x5FFF 内
        let mut hdr_hazard = vec![0u8; 40 + 20];
        hdr_hazard[0] = 0x60;
        hdr_hazard[40..].copy_from_slice(&tcp_seg(443, 0x4A01, 0x12));
        assert_eq!(
            match_tcp_reply(
                &hdr_hazard,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                443,
                &want
            ),
            Some(0),
            "带头包走带头发分支命中"
        );
    }

    /// Time Exceeded（type 11 code 0）：8B ICMP 头（含 4B unused）+ 内嵌 IP 头(20B) + 内嵌 TCP(8B)。
    fn ttl_exceeded_tcp_v4(sport: u16, dport: u16) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + 20 + 8];
        icmp[0] = 11;
        icmp[1] = 0;
        icmp[8] = 0x45; // 内嵌 IP 头：IHL 5
        icmp[24..28].copy_from_slice(&[8, 8, 8, 8]); // 内嵌 dst（测试目标）
        icmp[28..30].copy_from_slice(&sport.to_be_bytes());
        icmp[30..32].copy_from_slice(&dport.to_be_bytes());
        icmp
    }

    #[test]
    fn tcp_time_exceeded_matches() {
        let icmp = ttl_exceeded_tcp_v4(0x4123, 443);
        let buf = v4_frame(&icmp);
        let want = probes(&[0x4122, 0x4123]);
        assert_eq!(
            match_time_exceeded_tcp(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443, &want),
            Some(1)
        );
    }

    #[test]
    fn tcp_time_exceeded_wrong_port() {
        let icmp = ttl_exceeded_tcp_v4(0x4123, 444);
        let buf = v4_frame(&icmp);
        let want = probes(&[0x4123]);
        assert_eq!(
            match_time_exceeded_tcp(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443, &want),
            None
        );
        let icmp = ttl_exceeded_tcp_v4(0x9999, 443);
        let buf = v4_frame(&icmp);
        assert_eq!(
            match_time_exceeded_tcp(&buf, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443, &want),
            None
        );
    }

    #[test]
    fn tcp_time_exceeded_v6() {
        // ICMPv6 Time Exceeded（type 3 code 0）：8B ICMPv6 头（含 4B unused）+ 内嵌 40B IPv6 头 + 8B TCP
        let mut icmp = vec![0u8; 8 + 40 + 8];
        icmp[0] = 3;
        icmp[1] = 0;
        icmp[32..48].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // 内嵌 dst（2001:db8::1，测试目标）
        icmp[8 + 40..8 + 42].copy_from_slice(&0x4A01u16.to_be_bytes());
        icmp[8 + 42..8 + 44].copy_from_slice(&80u16.to_be_bytes());
        let want = probes(&[0x4A01]);
        assert_eq!(
            match_time_exceeded_tcp(&icmp, IpAddr::V6("2001:db8::1".parse().unwrap()), 80, &want),
            Some(0)
        );
        assert_eq!(
            match_time_exceeded_tcp(&icmp, IpAddr::V6("2001:db8::1".parse().unwrap()), 81, &want),
            None
        );
    }
}
