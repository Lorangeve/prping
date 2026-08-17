//! ICMP ping — send ICMP echo requests and measure round-trip latency.

use crate::output;
use crate::stats::{self, Stats};
use crate::util::{self, PingConfig, Run};
use rust_i18n::t;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use termcolor::StandardStream;

/// ICMP 应答失败原因（用于区分超时与网络错误）。
#[derive(Debug, Clone, Copy, PartialEq)]
enum IcmpErr {
    Timeout,
    Unreachable,
    TtlExceeded,
}

/// 返回 `Ok(true)` 表示有丢包（供退出码判断）。
pub fn ping(cfg: &PingConfig) -> anyhow::Result<bool> {
    let addrs = util::resolve_all(&cfg.host, cfg.v4, cfg.v6)?;
    if addrs.is_empty() {
        anyhow::bail!(t!("errors.cannot_resolve", host = cfg.host));
    }

    let addr = addrs[0].ip();
    if cfg.host.parse::<IpAddr>().is_err() {
        let stripped = cfg
            .host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(&cfg.host);
        if stripped.parse::<IpAddr>().is_err() && !stats::json() {
            println!(
                "{}",
                t!("common.resolving", host = cfg.host, ip = addr.to_string())
            );
        }
    }

    if !stats::json() {
        println!(
            "{}",
            t!("icmp.pinging", addr = addr.to_string(), size = cfg.size)
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

async fn ping_async(addr: IpAddr, cfg: &PingConfig) -> anyhow::Result<bool> {
    let (sock, target) = create_socket(addr)?;
    let async_sock = smol::Async::new(sock)?;
    let mut stats = Stats::default();
    let mut w = output::stdout();
    let ident = rand_id();
    let mut run = Run::new(cfg.count, cfg.warmup, cfg.duration);

    loop {
        if run.seq() > 0 {
            smol::Timer::after(Duration::from_secs_f64(cfg.interval)).await;
        }
        if run.done() {
            break;
        }
        let is_warmup = run.is_warmup();
        let seq_num = run.seq() as u16;
        match send_recv(&async_sock, &target, ident, seq_num, cfg.size, addr).await {
            Ok((rtt, ttl, reply_size)) => {
                if !is_warmup {
                    stats.record(rtt);
                }
                if !cfg.quiet && !stats::json() {
                    print_reply(&mut w, addr, reply_size, rtt, ttl, is_warmup)?;
                }
            }
            Err(e) => {
                if !is_warmup {
                    stats.record_loss();
                }
                if !cfg.quiet && !stats::json() {
                    match e {
                        IcmpErr::Timeout => output::writeln_red(&mut w, &t!("common.timeout"))?,
                        IcmpErr::Unreachable => {
                            output::writeln_red(&mut w, &t!("common.dest_unreachable"))?
                        }
                        IcmpErr::TtlExceeded => {
                            output::writeln_red(&mut w, &t!("common.ttl_expired"))?
                        }
                    }
                }
            }
        }
        run.advance();
    }

    if !cfg.quiet && !stats::json() {
        println!();
    }
    stats::print_summary(&mut w, &stats, "icmp")?;
    if !stats::json()
        && stats.received > 0
        && let Some(spec) = &cfg.histogram
    {
        stats::print_histogram(&mut w, &stats, spec)?;
    }
    if !stats::json() {
        stats::print_timeline(&mut w, &stats)?;
    }
    Ok(stats.loss_pct() > 0.0)
}

fn create_socket(addr: IpAddr) -> anyhow::Result<(Socket, SockAddr)> {
    match addr {
        IpAddr::V4(v4) => {
            let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                .map_err(|e| anyhow::anyhow!(t!("errors.raw_socket", error = e.to_string())))?;
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V4(v4), 0))))
        }
        IpAddr::V6(v6) => {
            let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
                .map_err(|e| anyhow::anyhow!(t!("errors.raw_socket", error = e.to_string())))?;
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V6(v6), 0))))
        }
    }
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
            if buf.len() < 28 {
                return Err(IcmpErr::Timeout);
            }
            let ip_header_len = ((buf[0] & 0x0F) as usize) * 4;
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
            Ok((rtt, buf[8], buf.len() - ip_header_len))
        }
        IpAddr::V6(_) => {
            if buf.len() < 48 {
                return Err(IcmpErr::Timeout);
            }
            let icmp = &buf[40..];
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
            Ok((rtt, buf[7], buf.len() - 40))
        }
    }
}

fn build_icmp_echo(addr: IpAddr, ident: u16, seq: u16, payload_size: usize) -> Vec<u8> {
    match addr {
        IpAddr::V4(_) => build_v4(ident, seq, payload_size),
        IpAddr::V6(_) => build_v6(ident, seq, payload_size),
    }
}
fn build_v4(ident: u16, seq: u16, payload_size: usize) -> Vec<u8> {
    let total = 8 + payload_size;
    let mut b = vec![0u8; total];
    b[0] = 8;
    b[1] = 0;
    b[4] = (ident >> 8) as u8;
    b[5] = ident as u8;
    b[6] = (seq >> 8) as u8;
    b[7] = seq as u8;
    for i in 0..payload_size {
        b[8 + i] = (i % 256) as u8
    }
    let c = icmp_cksum(&b);
    b[2] = (c >> 8) as u8;
    b[3] = c as u8;
    b
}
fn build_v6(ident: u16, seq: u16, payload_size: usize) -> Vec<u8> {
    let total = 8 + payload_size;
    let mut b = vec![0u8; total];
    b[0] = 128;
    b[1] = 0;
    b[4] = (ident >> 8) as u8;
    b[5] = ident as u8;
    b[6] = (seq >> 8) as u8;
    b[7] = seq as u8;
    for i in 0..payload_size {
        b[8 + i] = (i % 256) as u8
    }
    b
}
fn icmp_cksum(data: &[u8]) -> u16 {
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
fn rand_id() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u16
}

#[cfg(test)]
mod tests {
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
