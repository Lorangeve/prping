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

/// 创建 raw ICMP socket（v4: IPPROTO_ICMP / v6: IPPROTO_ICMPV6），可选源绑定。
pub(crate) fn create_icmp_socket(
    addr: IpAddr,
    source: Option<IpAddr>,
) -> anyhow::Result<(socket2::Socket, socket2::SockAddr)> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    match addr {
        IpAddr::V4(v4) => {
            let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                .map_err(crate::ping::icmp::raw_socket_error)?;
            if let Some(src) = source.filter(IpAddr::is_ipv4) {
                sock.bind(&SockAddr::from(std::net::SocketAddr::new(src, 0)))?;
            }
            Ok((
                sock,
                SockAddr::from(std::net::SocketAddr::new(IpAddr::V4(v4), 0)),
            ))
        }
        IpAddr::V6(v6) => {
            let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
                .map_err(crate::ping::icmp::raw_socket_error)?;
            if let Some(src) = source.filter(IpAddr::is_ipv6) {
                sock.bind(&SockAddr::from(std::net::SocketAddr::new(src, 0)))?;
            }
            Ok((
                sock,
                SockAddr::from(std::net::SocketAddr::new(IpAddr::V6(v6), 0)),
            ))
        }
    }
}

/// 创建 raw TCP socket（`trace --tcp`：发 SYN + 收 SYN-ACK/RST）。
/// 绑定 `local`——保证内核用与伪头部校验和一致的源 IP（收包侧也过滤到该地址）。
#[cfg(unix)]
pub(crate) fn create_tcp_socket(
    addr: IpAddr,
    local: IpAddr,
) -> anyhow::Result<(socket2::Socket, socket2::SockAddr)> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    match addr {
        IpAddr::V4(v4) => {
            let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
                .map_err(crate::ping::icmp::raw_socket_error)?;
            sock.bind(&SockAddr::from(std::net::SocketAddr::new(local, 0)))?;
            Ok((
                sock,
                SockAddr::from(std::net::SocketAddr::new(IpAddr::V4(v4), 0)),
            ))
        }
        IpAddr::V6(v6) => {
            let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP))
                .map_err(crate::ping::icmp::raw_socket_error)?;
            sock.bind(&SockAddr::from(std::net::SocketAddr::new(local, 0)))?;
            Ok((
                sock,
                SockAddr::from(std::net::SocketAddr::new(IpAddr::V6(v6), 0)),
            ))
        }
    }
}

/// 创建普通 UDP socket（`trace --udp`）：绑定固定源端口（`sport`），内核据此
/// 构 UDP 头（校验和内核算）。返回 socket（目标端口每次 send_to 指定）。
pub(crate) fn create_udp_socket(
    addr: IpAddr,
    source: Option<IpAddr>,
    sport: u16,
) -> anyhow::Result<socket2::Socket> {
    use socket2::{Domain, Socket, Type};
    let sock = match addr {
        IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::DGRAM, None)?,
        IpAddr::V6(_) => Socket::new(Domain::IPV6, Type::DGRAM, None)?,
    };
    let bind_addr = std::net::SocketAddr::new(
        source.unwrap_or(if addr.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        }),
        sport,
    );
    sock.bind(&socket2::SockAddr::from(bind_addr))?;
    Ok(sock)
}

/// 设置 TTL / Hop Limit。
pub(crate) fn set_ttl(sock: &socket2::Socket, ttl: u32, is_ipv6: bool) -> anyhow::Result<()> {
    if is_ipv6 {
        sock.set_unicast_hops_v6(ttl)?;
    } else {
        sock.set_ttl_v4(ttl)?;
    }
    Ok(())
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
    use std::mem::MaybeUninit;

    let (addr, addrlen) = match ip {
        IpAddr::V4(v4) => {
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as _;
            addr.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
            (
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        IpAddr::V6(v6) => {
            let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            addr.sin6_family = libc::AF_INET6 as _;
            addr.sin6_addr.s6_addr = v6.octets();
            (
                &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    };
    let mut host: [MaybeUninit<u8>; 1024] = [MaybeUninit::uninit(); 1024];
    let mut serv: [MaybeUninit<u8>; 64] = [MaybeUninit::uninit(); 64];
    let rc = unsafe {
        libc::getnameinfo(
            addr,
            addrlen,
            host.as_mut_ptr() as *mut libc::c_char,
            1024,
            serv.as_mut_ptr() as *mut libc::c_char,
            64,
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let name = unsafe { CStr::from_ptr(host.as_ptr() as *const libc::c_char) };
    name.to_str().ok().map(|s| s.to_string())
}

/// Windows：getnameinfo（ws2_32）。
#[cfg(windows)]
fn reverse_dns(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    use std::mem::MaybeUninit;

    let (addr, addrlen) = match ip {
        IpAddr::V4(v4) => {
            let mut addr: winapi::shared::ws2def::SOCKADDR_IN = unsafe { std::mem::zeroed() };
            addr.sin_family = winapi::shared::ws2def::AF_INET as _;
            addr.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
            (
                &addr as *const _ as *const winapi::shared::ws2def::SOCKADDR,
                std::mem::size_of::<winapi::shared::ws2def::SOCKADDR_IN>() as i32,
            )
        }
        IpAddr::V6(v6) => {
            let mut addr: winapi::shared::ws2ipdef::SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
            addr.sin6_family = winapi::shared::ws2def::AF_INET6 as _;
            addr.sin6_addr.s6_addr = v6.octets();
            (
                &addr as *const _ as *const winapi::shared::ws2def::SOCKADDR,
                std::mem::size_of::<winapi::shared::ws2ipdef::SOCKADDR_IN6>() as i32,
            )
        }
    };
    let mut host: [MaybeUninit<u8>; 1024] = [MaybeUninit::uninit(); 1024];
    let mut serv: [MaybeUninit<u8>; 64] = [MaybeUninit::uninit(); 64];
    let rc = unsafe {
        winapi::um::ws2tcpip::getnameinfo(
            addr,
            addrlen,
            host.as_mut_ptr() as *mut i8,
            1024,
            serv.as_mut_ptr() as *mut i8,
            64,
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let name = unsafe { CStr::from_ptr(host.as_ptr() as *const i8) };
    name.to_str().ok().map(|s| s.to_string())
}

/// 输出一跳（文本格式）。
fn print_hop_line(w: &mut StandardStream, hop: &Hop) -> anyhow::Result<()> {
    use crate::output;

    let hop_str = format!("{:>3}  ", hop.hop);
    output::print_dim(w, &hop_str)?;

    match hop.addr {
        Some(ip) => {
            output::print_cyan(w, format!("{:<48}", ip))?;
        }
        None => {
            output::print_dim(w, format!("{:<48}", "*"))?;
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

/// 随机 u16（用于 ICMP id / TCP 源端口）。
pub(crate) fn rand_id() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u16
}

/// 随机 u32（用于 TCP seq）。
#[cfg(unix)]
pub(crate) fn rand_u32() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u32
}

/// 构建 ICMP echo request（type 8 / 128），载荷 32 字节循环填充。
pub(crate) fn build_echo(addr: IpAddr, ident: u16, seq: u16, payload: usize) -> Vec<u8> {
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
        let v4 = build_echo(IpAddr::V4(Ipv4Addr::LOCALHOST), 0x1234, 7, 32);
        assert_eq!(v4.len(), 40);
        assert_eq!(v4[0], 8);
        assert_eq!(v4[4], 0x12);
        assert_eq!(v4[7], 7);
        assert_eq!(v4[8], 0);
        assert_eq!(v4[39], 31);
        let v6 = build_echo(IpAddr::V6("::1".parse().unwrap()), 0x1234, 7, 32);
        assert_eq!(v6[0], 128);
        assert_eq!(v6[4], 0x12);
    }
}
