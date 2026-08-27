//! ICMP ping — send ICMP echo requests and measure round-trip latency.

use crate::drive::{Probe, ProbeOutcome, drive};
use crate::output;
use crate::stats::{self, Stats};
use crate::util::{self, PingConfig};
use rust_i18n::t;
use std::io::Write;
use std::net::IpAddr;
use std::time::Duration;
use termcolor::StandardStream;

#[cfg(windows)]
use crate::ping::icmpwin::ws::IcmpSession;
#[cfg(not(windows))]
use socket2::{SockAddr, Socket};
#[cfg(not(windows))]
use std::mem::MaybeUninit;
#[cfg(not(windows))]
use std::time::Instant;

/// ICMP 应答失败原因（用于区分超时与网络错误）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum IcmpErr {
    Timeout,
    Unreachable,
    TtlExceeded,
}

/// 返回 `Ok(true)` 表示有丢包（供退出码判断）。
pub fn ping(cfg: &PingConfig) -> anyhow::Result<Stats> {
    let addrs = util::resolve_vec(&cfg.host, 0, cfg.v4, cfg.v6)?;
    if addrs.is_empty() {
        anyhow::bail!(t!("errors.cannot_resolve", host = cfg.host));
    }
    let addr = addrs[0].ip();
    util::print_resolving(&cfg.host, addr);

    if !stats::json() {
        println!(
            "{}",
            t!(
                "icmp.pinging",
                addr = addr.to_string(),
                size = cfg.size.unwrap_or(32)
            )
        );
        if let Some(d) = cfg.duration {
            println!("{}", t!("icmp.duration", secs = d, warmup = cfg.warmup));
        } else {
            println!(
                "{}",
                t!(
                    "icmp.iterations",
                    total = cfg.warmup + cfg.count,
                    warmup = cfg.warmup
                )
            );
        }
    }

    smol::block_on(ping_async(addr, cfg))
}

async fn ping_async(addr: IpAddr, cfg: &PingConfig) -> anyhow::Result<Stats> {
    #[cfg(windows)]
    if cfg.source.is_some() && addr.is_ipv4() {
        // IcmpSendEcho2 无源地址参数：v4 源绑定在 Windows 上不支持（v6 支持）
        let _ = output::writeln_orange(
            &mut output::stderr(),
            format!("  {}", t!("icmp.note_source_ignored_win")),
        );
    }
    let sender = IcmpSender::new(addr, cfg.source)?;
    let mut probe = IcmpProbe { sender, addr, cfg };
    drive(cfg, "icmp", &cfg.host, &mut probe).await
}

/// 探测发送端：Windows 用 ICMP.DLL 会话（raw socket 在 Win7 RTM 有缺陷 + 需
/// 管理员权限，见 icmpwin.rs），其余平台用 raw ICMP socket。
enum IcmpSender {
    #[cfg(windows)]
    Win(IcmpSession),
    #[cfg(not(windows))]
    Raw(smol::Async<Socket>, SockAddr, u16),
}

impl IcmpSender {
    fn new(addr: IpAddr, source: Option<IpAddr>) -> anyhow::Result<IcmpSender> {
        #[cfg(windows)]
        {
            // v4 源绑定不支持（IcmpSendEcho2 无源参数），v6 源绑定在
            // send_recv_win 经 SourceAddress 传入——这里不需要 source
            let _ = source;
            Ok(IcmpSender::Win(IcmpSession::new(addr)?))
        }
        #[cfg(not(windows))]
        {
            let (sock, target) = util::create_icmp_socket(addr, source)?;
            let async_sock = smol::Async::new(sock)?;
            Ok(IcmpSender::Raw(async_sock, target, util::rand_u16()))
        }
    }
}

/// ICMP 探测体：发包 + 收包解析 + 人读行（统计/JSONL 由 drive 统一处理）。
struct IcmpProbe<'a> {
    sender: IcmpSender,
    addr: IpAddr,
    cfg: &'a PingConfig,
}

impl Probe for IcmpProbe<'_> {
    async fn probe(
        &mut self,
        w: &mut StandardStream,
        seq: u64,
        is_warmup: bool,
    ) -> anyhow::Result<ProbeOutcome> {
        // Windows：seq 由 ICMP.DLL 内部匹配，raw 路径才需要
        #[cfg(windows)]
        let _ = seq;
        let size = self.cfg.size.unwrap_or(32);
        let outcome = match &self.sender {
            #[cfg(windows)]
            IcmpSender::Win(session) => {
                send_recv_win(session, self.addr, size, self.cfg.source).await
            }
            #[cfg(not(windows))]
            IcmpSender::Raw(sock, target, ident) => {
                send_recv(sock, target, *ident, seq as u16, size, self.addr).await
            }
        };
        match outcome {
            Ok((rtt, ttl, reply_size)) => {
                if !self.cfg.quiet && !stats::json() {
                    print_reply(w, self.addr, reply_size, rtt, ttl, is_warmup)?;
                }
                Ok(ProbeOutcome::Ok { rtt })
            }
            Err(e) => {
                let json_err = match e {
                    IcmpErr::Timeout => "timeout",
                    IcmpErr::Unreachable => "unreachable",
                    IcmpErr::TtlExceeded => "ttl exceeded",
                };
                if !self.cfg.quiet && !stats::json() {
                    let msg = match e {
                        IcmpErr::Timeout => t!("common.timeout"),
                        IcmpErr::Unreachable => t!("common.dest_unreachable"),
                        IcmpErr::TtlExceeded => t!("common.ttl_expired"),
                    };
                    output::writeln_red(w, &msg)?;
                }
                Ok(ProbeOutcome::Err { json_err })
            }
        }
    }
}

/// Windows：ICMP.DLL 阻塞探测（`smol::unblock` 线程池）。seq 由 API 内部匹配，
/// 不需要 ident/seq 嵌入（与 raw socket 路径的逐包过滤语义等价）。
#[cfg(windows)]
async fn send_recv_win(
    session: &IcmpSession,
    dest: IpAddr,
    payload_size: usize,
    source: Option<IpAddr>,
) -> Result<(Duration, u8, usize), IcmpErr> {
    let payload = echo_payload(payload_size);
    // HANDLE（*mut c_void）非 Send：unblock 闭包须 Send，句柄按 usize 传值
    let handle = session.handle() as usize;
    // v6 源绑定经 SourceAddress 参数；v4 不支持（IcmpSendEcho2 无源地址参数）
    let src6 = match source {
        Some(IpAddr::V6(v)) => Some(v.octets()),
        _ => None,
    };
    smol::unblock(move || {
        crate::ping::icmpwin::ws::probe_once(
            handle as *mut core::ffi::c_void,
            dest,
            &payload,
            src6,
            Duration::from_secs(4),
        )
    })
    .await
}

/// echo 载荷字节（`i % 256` 循环，各平台一致）。
///
/// Windows ICMP.DLL 路径需要 `Vec<u8>` 载荷；非 Windows 路径已改用 `util::echo_fill`。
#[cfg(any(windows, test))]
fn echo_payload(payload_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; payload_size];
    util::echo_fill(&mut buf);
    buf
}

fn print_reply(
    w: &mut StandardStream,
    addr: IpAddr,
    size: usize,
    rtt: Duration,
    ttl: u8,
    warmup: bool,
) -> anyhow::Result<()> {
    output::print_green(w, &t!("common.reply_from"))?;
    output::print_cyan(w, addr.to_string())?;
    write!(w, ": {}={size} ", t!("common.bytes"))?;
    output::print_yellow(
        w,
        format!("{}={:.2}ms", t!("common.time"), rtt.as_secs_f64() * 1000.0),
    )?;
    write!(w, " {}={ttl}", t!("common.ttl"))?;
    if warmup {
        output::print_dim(w, format!(" {}", t!("common.warmup")))?;
    }
    writeln!(w)?;
    Ok(())
}

#[cfg(not(windows))]
async fn send_recv(
    async_sock: &smol::Async<Socket>,
    target: &SockAddr,
    ident: u16,
    seq: u16,
    payload_size: usize,
    addr: IpAddr,
) -> Result<(Duration, u8, usize), IcmpErr> {
    let request = build_icmp_echo(addr, ident, seq, payload_size);
    let send_time = Instant::now();
    async_sock
        .write_with(|sock| sock.send_to(&request, target))
        .await
        .map_err(|_| IcmpErr::Timeout)?;
    // socket2 的 recv_from 只接受 MaybeUninit 缓冲区；用 new(0) 全量初始化，
    // 这样后续以 &[u8] 读取是健全的（不再依赖 recv 返回的写入长度）。
    let mut buf: [MaybeUninit<u8>; 4096] = [MaybeUninit::new(0u8); 4096];
    let timeout = Duration::from_secs(4);
    let recv = smol::future::or(
        async {
            async_sock
                .read_with(|sock| sock.recv_from(&mut buf))
                .await
                .map(|(n, _)| n)
        },
        async {
            smol::Timer::after(timeout).await;
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
        },
    )
    .await;
    match recv {
        Ok(n) => parse_reply(util::init_slice(&buf, n), ident, seq, send_time, addr),
        Err(_) => Err(IcmpErr::Timeout),
    }
}

#[cfg(not(windows))]
fn parse_reply(
    buf: &[u8],
    ident: u16,
    seq: u16,
    send_time: Instant,
    expected_src: IpAddr,
) -> Result<(Duration, u8, usize), IcmpErr> {
    let rtt = send_time.elapsed();
    match expected_src {
        IpAddr::V4(_) => {
            // 外层头偏移：Linux 含 IP 头；Windows 的 raw ICMP 收包不含（见
            // util::icmp_offset_v4）——含头时 TTL 从 IP 头读，不含头时置 0。
            let has_v4_hdr = !buf.is_empty() && buf[0] >> 4 == 4;
            let ip_header_len = util::icmp_offset_v4(buf);
            let icmp = &buf[ip_header_len..];
            if icmp.len() < 8 {
                return Err(IcmpErr::Timeout);
            }
            match icmp[0] {
                0 => {} // echo reply
                3 => return Err(IcmpErr::Unreachable),
                11 => return Err(IcmpErr::TtlExceeded),
                _ => return Err(IcmpErr::Timeout),
            }
            if u16::from_be_bytes([icmp[4], icmp[5]]) != ident
                || u16::from_be_bytes([icmp[6], icmp[7]]) != seq
            {
                return Err(IcmpErr::Timeout);
            }
            let ttl = if has_v4_hdr { buf[8] } else { 0 };
            Ok((rtt, ttl, icmp.len()))
        }
        IpAddr::V6(_) => {
            // 框架探测：Linux raw ICMPv6 收包不含 IPv6 头（pskb_pull），
            // 部分平台（Windows）带头——首字节 version nibble==6 区分。
            let has_v6_hdr = buf.len() >= 48 && buf[0] >> 4 == 6;
            let icmp = if has_v6_hdr { &buf[40..] } else { buf };
            if icmp.len() < 8 {
                return Err(IcmpErr::Timeout);
            }
            match icmp[0] {
                129 => {} // echo reply
                1 => return Err(IcmpErr::Unreachable),
                3 => return Err(IcmpErr::TtlExceeded),
                _ => return Err(IcmpErr::Timeout),
            }
            if u16::from_be_bytes([icmp[4], icmp[5]]) != ident
                || u16::from_be_bytes([icmp[6], icmp[7]]) != seq
            {
                return Err(IcmpErr::Timeout);
            }
            let hop_limit = if has_v6_hdr { buf[7] } else { 0 };
            Ok((rtt, hop_limit, icmp.len()))
        }
    }
}

#[cfg(not(windows))]
fn build_icmp_echo(addr: IpAddr, ident: u16, seq: u16, payload_size: usize) -> Vec<u8> {
    match addr {
        IpAddr::V4(_) => build_v4(ident, seq, payload_size),
        IpAddr::V6(_) => build_v6(ident, seq, payload_size),
    }
}

/// 构建 ICMPv4 echo request（type 8），载荷 `0..255` 循环填充 + checksum。
pub(crate) fn build_v4(ident: u16, seq: u16, payload_size: usize) -> Vec<u8> {
    let total = 8 + payload_size;
    let mut b = vec![0u8; total];
    b[0] = 8;
    b[1] = 0;
    b[4] = (ident >> 8) as u8;
    b[5] = ident as u8;
    b[6] = (seq >> 8) as u8;
    b[7] = seq as u8;
    util::echo_fill(&mut b[8..]);
    let c = icmp_cksum(&b);
    b[2] = (c >> 8) as u8;
    b[3] = c as u8;
    b
}

/// 构建 ICMPv6 echo request（type 128），载荷 `0..255` 循环填充（无 checksum，内核算）。
pub(crate) fn build_v6(ident: u16, seq: u16, payload_size: usize) -> Vec<u8> {
    let total = 8 + payload_size;
    let mut b = vec![0u8; total];
    b[0] = 128;
    b[1] = 0;
    b[4] = (ident >> 8) as u8;
    b[5] = ident as u8;
    b[6] = (seq >> 8) as u8;
    b[7] = seq as u8;
    util::echo_fill(&mut b[8..]);
    b
}
pub(crate) fn icmp_cksum(data: &[u8]) -> u16 {
    let mut s = 0u32;
    for c in data.chunks(2) {
        s += if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]]) as u32
        } else {
            (c[0] as u32) << 8
        }
    }
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16)
    }
    !(s as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_payload_pattern() {
        let p = echo_payload(300);
        assert_eq!(p.len(), 300);
        assert_eq!(p[0], 0);
        assert_eq!(p[255], 255);
        assert_eq!(p[256], 0); // 循环
    }

    #[test]
    fn test_icmp_cksum_known() {
        assert_ne!(
            icmp_cksum(&[8, 0, 0, 0, 0, 1, 0, 1, 0x41, 0x42, 0, 0, 0, 0, 0, 0]),
            0
        );
    }
    #[test]
    fn test_icmp_cksum_zeros() {
        assert_eq!(icmp_cksum(&[0u8; 8]), 0xFFFF);
    }
}

/// raw socket 路径（build/parse）仅非 Windows 编译；Windows 走 ICMP.DLL。
#[cfg(all(test, not(windows)))]
mod raw_tests {
    use super::*;
    use std::net::Ipv4Addr;
    #[test]
    fn test_icmpv4_echo_build() {
        let b = build_v4(0x1234, 0x0001, 32);
        assert_eq!(b.len(), 40);
        assert_eq!(b[0], 8);
        assert_eq!(b[4], 0x12);
    }
    #[test]
    fn test_icmpv6_echo_build() {
        let b = build_v6(0xABCD, 0x0005, 16);
        assert_eq!(b.len(), 24);
        assert_eq!(b[0], 128);
    }
    #[test]
    fn test_ipv4_reply_parse() {
        let ident = 0x1234u16;
        let seq = 0x0002u16;
        let mut p = Vec::new();
        p.extend([
            0x45, 0, 0, 40, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
        ]);
        p.push(0);
        p.push(0);
        p.extend((0u16).to_be_bytes());
        p.extend(ident.to_be_bytes());
        p.extend(seq.to_be_bytes());
        p.extend(vec![0u8; 16]);
        let ttl = p[8];
        let r = parse_reply(
            &p,
            ident,
            seq,
            Instant::now(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );
        assert!(r.is_ok());
        assert_eq!(r.unwrap().1, ttl);
    }

    #[test]
    fn test_ipv4_reply_parse_no_ip_header() {
        // Windows：raw ICMP 收包不含 IP 头——直接是 ICMP 报文，TTL 不可得（0）
        let ident = 0x1234u16;
        let seq = 0x0005u16;
        let mut p = Vec::new();
        p.push(0); // type echo reply
        p.push(0);
        p.extend((0u16).to_be_bytes());
        p.extend(ident.to_be_bytes());
        p.extend(seq.to_be_bytes());
        p.extend(vec![0u8; 8]);
        let r = parse_reply(
            &p,
            ident,
            seq,
            Instant::now(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );
        assert!(r.is_ok(), "无头格式应匹配：{r:?}");
        let (_, ttl, size) = r.unwrap();
        assert_eq!(ttl, 0);
        assert_eq!(size, p.len());
    }

    #[test]
    fn test_ipv6_reply_parse_no_header() {
        // Linux：raw ICMPv6 收包不含 IPv6 头——直接是 ICMPv6，hop limit 不可得（0）
        let ident = 0xABCDu16;
        let seq = 0x0001u16;
        let mut p = Vec::new();
        p.push(129); // type echo reply
        p.push(0);
        p.extend((0u16).to_be_bytes());
        p.extend(ident.to_be_bytes());
        p.extend(seq.to_be_bytes());
        p.extend(vec![0u8; 8]);
        let r = parse_reply(
            &p,
            ident,
            seq,
            Instant::now(),
            IpAddr::V6("::1".parse().unwrap()),
        );
        assert!(r.is_ok(), "无头格式应匹配：{r:?}");
        assert_eq!(r.unwrap().1, 0);
    }
    #[test]
    fn test_ipv4_reply_wrong_ident() {
        let mut p = Vec::new();
        p.extend([
            0x45, 0, 0, 40, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
        ]);
        p.push(0);
        p.push(0);
        p.extend((0u16).to_be_bytes());
        p.extend(0xBBBBu16.to_be_bytes());
        p.extend(1u16.to_be_bytes());
        p.extend(vec![0u8; 16]);
        assert!(
            parse_reply(
                &p,
                0xAAAA,
                1,
                Instant::now(),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
            )
            .is_err()
        );
    }
    #[test]
    fn test_parse_reply_too_short() {
        let p = [0u8; 4];
        assert!(
            parse_reply(
                &p,
                0,
                0,
                Instant::now(),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
            )
            .is_err()
        );
    }
    #[test]
    fn test_parse_reply_unreachable() {
        let mut p = Vec::new();
        p.extend([
            0x45, 0, 0, 40, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
        ]);
        p.push(3);
        p.push(0);
        p.extend((0u16).to_be_bytes());
        p.extend([0u8; 20]);
        let r = parse_reply(
            &p,
            1,
            1,
            Instant::now(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );
        assert_eq!(r, Err(IcmpErr::Unreachable));
    }
    #[test]
    fn test_parse_reply_ttl_expired() {
        let mut p = Vec::new();
        p.extend([
            0x45, 0, 0, 40, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
        ]);
        p.push(11);
        p.push(0);
        p.extend((0u16).to_be_bytes());
        p.extend([0u8; 20]);
        let r = parse_reply(
            &p,
            1,
            1,
            Instant::now(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );
        assert_eq!(r, Err(IcmpErr::TtlExceeded));
    }
}
