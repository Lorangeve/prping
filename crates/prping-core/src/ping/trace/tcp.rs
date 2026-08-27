//! TCP SYN 逐跳探测：raw TCP socket 收发，回复按内嵌 TCP 头的 (sport, dport) 匹配。

use std::net::IpAddr;

use termcolor::StandardStream;

use super::{Hop, PingConfig};

// 以下仅 Unix raw TCP 路径使用（Windows 的 trace_tcp 直接报错不支持）
#[cfg(unix)]
use super::{PROBE_TIMEOUT, PROBES_PER_HOP, finish_hop};
#[cfg(unix)]
use crate::util;
#[cfg(unix)]
use std::mem::MaybeUninit;
#[cfg(unix)]
use std::time::{Duration, Instant};

/// TCP SYN 探测源端口范围（避免与 IPv6 version nibble 冲突）。
#[cfg(unix)]
const TCP_SPORT_MIN: u16 = 0x4000;
#[cfg(unix)]
const TCP_SPORT_MAX: u16 = 0x5FFF;

/// 获取本机路由地址（用于源地址填充）。
#[cfg(unix)]
fn local_ip_for(target: IpAddr) -> Option<IpAddr> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect((target, 80)).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// TCP SYN 逐跳：raw TCP socket 收发，回复按内嵌 TCP 头的 (sport, dport) 匹配。
#[cfg(unix)]
pub(crate) fn trace_tcp(
    cfg: &PingConfig,
    target_ip: IpAddr,
    max_hops: u32,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    let local = local_ip_for(target_ip).ok_or_else(|| anyhow::anyhow!("无法获取本机路由地址"))?;
    let (sock, target_sa) = crate::util::create_tcp_socket(target_ip, local)?;
    let dport = cfg.port;

    let mut hops: Vec<Hop> = Vec::new();
    let mut sport_counter: u16 = TCP_SPORT_MIN;
    let mut reached = false;

    for hop_no in 1..=max_hops {
        if util::interrupted() {
            break;
        }
        crate::util::set_ttl(&sock, hop_no, target_ip.is_ipv6())?;

        // 发送本跳全部探测（背靠背，不逐包等待）
        let mut probes: Vec<(u16, Instant)> = Vec::with_capacity(PROBES_PER_HOP);
        for _ in 0..PROBES_PER_HOP {
            let sport = sport_counter;
            sport_counter = sport_counter.wrapping_add(1);
            if sport_counter > TCP_SPORT_MAX {
                sport_counter = TCP_SPORT_MIN;
            }
            let pkt = build_tcp_syn(target_ip, local, sport, dport);
            let sent = Instant::now();
            if sock.send_to(&pkt, &target_sa).is_ok() {
                probes.push((sport, sent));
            }
        }
        if probes.is_empty() {
            break;
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
                Ok((n, addr)) => {
                    let data: &[u8] =
                        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                    let peer: IpAddr = addr
                        .as_socket()
                        .map(|s| s.ip())
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                    let sport = if target_ip.is_ipv6() {
                        match match_tcp_reply_v6(data, target_ip, dport, &want) {
                            Some(s) => s,
                            None => {
                                super::trace_dump("tcp-v6", data, false);
                                continue;
                            }
                        }
                    } else {
                        match match_tcp_reply_v4(data, target_ip, dport, &want) {
                            Some(s) => s,
                            None => {
                                super::trace_dump("tcp-v4", data, false);
                                continue;
                            }
                        }
                    };
                    super::trace_dump(
                        if target_ip.is_ipv6() {
                            "tcp-v6"
                        } else {
                            "tcp-v4"
                        },
                        data,
                        true,
                    );
                    // SYN-ACK/RST 即到达
                    if data.len() >= 14 {
                        let flags = data[13];
                        if flags & 0x12 == 0x12 || flags & 0x04 == 0x04 {
                            dest_hit = true;
                        }
                    }
                    // 记录 RTT
                    if let Some(idx) = probes.iter().position(|&(s, _)| s == sport)
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

        let hop = finish_hop(hop_no, cfg, src, rtts, w)?;
        hops.push(hop);
        if dest_hit {
            reached = true;
            break;
        }
    }

    Ok((hops, reached))
}

/// Windows 不支持 raw TCP socket。
#[cfg(windows)]
pub(crate) fn trace_tcp(
    _cfg: &PingConfig,
    _target_ip: IpAddr,
    _max_hops: u32,
    _w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    use rust_i18n::t;
    anyhow::bail!(t!("errors.tcp_trace_windows"))
}

/// 构建 TCP SYN 段（无 IP 头，raw socket 由内核加 IP 头）。
#[cfg(unix)]
fn build_tcp_syn(dst: IpAddr, src: IpAddr, sport: u16, dport: u16) -> Vec<u8> {
    let mut b = vec![0u8; 20]; // TCP 头最小 20 字节
    b[0] = (sport >> 8) as u8;
    b[1] = sport as u8;
    b[2] = (dport >> 8) as u8;
    b[3] = dport as u8;
    // seq = random
    let seq = crate::util::rand_u32();
    b[4..8].copy_from_slice(&seq.to_be_bytes());
    // ack = 0
    b[8..12].copy_from_slice(&[0; 4]);
    // data offset = 5 (20 bytes), flags = SYN (0x02)
    b[12] = 5 << 4;
    b[13] = 0x02;
    // window = 65535
    b[14] = 0xFF;
    b[15] = 0xFF;
    // checksum (pseudo-header)
    let csum = tcp_checksum(&b, src, dst);
    b[16] = (csum >> 8) as u8;
    b[17] = csum as u8;
    b
}

/// TCP 校验和（伪头部 + TCP 段）。
#[cfg(unix)]
fn tcp_checksum(tcp: &[u8], src: IpAddr, dst: IpAddr) -> u16 {
    let mut sum = 0u32;
    // 伪头部
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum += u16::from_be_bytes([s.octets()[0], s.octets()[1]]) as u32;
            sum += u16::from_be_bytes([s.octets()[2], s.octets()[3]]) as u32;
            sum += u16::from_be_bytes([d.octets()[0], d.octets()[1]]) as u32;
            sum += u16::from_be_bytes([d.octets()[2], d.octets()[3]]) as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            for i in (0..16).step_by(2) {
                sum += u16::from_be_bytes([s.octets()[i], s.octets()[i + 1]]) as u32;
                sum += u16::from_be_bytes([d.octets()[i], d.octets()[i + 1]]) as u32;
            }
        }
        _ => return 0,
    }
    sum += 6u32; // proto=TCP
    sum += tcp.len() as u32;
    // TCP 段
    for pair in tcp.chunks(2) {
        let w = if pair.len() == 2 {
            u16::from_be_bytes([pair[0], pair[1]]) as u32
        } else {
            (pair[0] as u32) << 8
        };
        sum += w;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// 匹配 IPv4 TCP 回包（SYN-ACK/RST）。
#[cfg(unix)]
fn match_tcp_reply_v4(buf: &[u8], _target: IpAddr, dport: u16, want: &[u16]) -> Option<u16> {
    if buf.len() < 20 {
        return None;
    }
    let ihl = (buf[0] & 0x0F) as usize * 4;
    if buf.len() < ihl + 20 {
        return None;
    }
    let tcp = &buf[ihl..];
    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if dst_port != dport || !want.contains(&sport) {
        return None;
    }
    Some(sport)
}

/// 匹配 IPv6 TCP 回包。
#[cfg(unix)]
fn match_tcp_reply_v6(buf: &[u8], _target: IpAddr, dport: u16, want: &[u16]) -> Option<u16> {
    // 框架探测：首字节 version nibble == 6 且长度足够 → 含 40B IPv6 头
    let tcp = if buf.len() >= 60 && buf[0] >> 4 == 6 {
        &buf[40..]
    } else {
        buf
    };
    if tcp.len() < 20 {
        return None;
    }
    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if dst_port != dport || !want.contains(&sport) {
        return None;
    }
    Some(sport)
}
