//! TCP SYN 逐跳探测（Unix）：raw TCP socket 发 SYN（内核构 IP 头）+ **双 socket 收包**——
//! raw TCP 收 SYN-ACK/RST（目标到达）、raw ICMP 收 Time Exceeded（中间路由），
//! `libc::poll` 同时等待两个 socket，回复按内嵌 TCP 头的 (sport, dport) 匹配。
//!
//! Windows 走 Npcap 注入路径（`tcpwin.rs`）：raw TCP socket 在 Windows 被禁止，
//! 改用 pcap 发送完整以太网帧并抓包收回复，语义与本模块一致。

use std::net::IpAddr;

use termcolor::StandardStream;

use super::{Hop, PingConfig};

// 以下仅 Unix raw socket 路径使用（Windows 委托 tcpwin）
#[cfg(unix)]
use super::{PROBE_TIMEOUT, PROBES_PER_HOP, finish_hop};
#[cfg(unix)]
use crate::util;
#[cfg(unix)]
use std::mem::MaybeUninit;
#[cfg(unix)]
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::time::{Duration, Instant};

/// TCP SYN 探测源端口范围（避免与 IPv6 version nibble 冲突）。
#[cfg(unix)]
const TCP_SPORT_MIN: u16 = 0x4000;
#[cfg(unix)]
const TCP_SPORT_MAX: u16 = 0x5FFF;

/// 获取本机路由地址（用于源地址填充；v4/v6 按目标族取）。
#[cfg(unix)]
fn local_ip_for(target: IpAddr) -> Option<IpAddr> {
    crate::engine::pkg::local_ip_for(&SocketAddr::new(target, 80))
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
    // 中间路由回 ICMP Time Exceeded——raw TCP socket 只收 TCP 包（proto 过滤），
    // 必须另开 raw ICMP socket 收；两个 socket 都先于发送打开（回环下回包可能在
    // send 内就完成往返，后开 socket 会漏收）。
    let (icmp_sock, _) = crate::util::create_icmp_socket(target_ip, cfg.source)?;
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

        // 收集回复直到全部匹配或超时：raw TCP（SYN-ACK/RST）+ raw ICMP（Time Exceeded）
        let want: Vec<u16> = probes.iter().map(|&(s, _)| s).collect();
        let deadline = Instant::now() + PROBE_TIMEOUT;
        let mut rtts: Vec<Option<Duration>> = vec![None; probes.len()];
        let mut src: Option<IpAddr> = None;
        let mut dest_hit = false;
        let mut remaining = probes.len();
        let mut tcp_buf: [MaybeUninit<u8>; 8192] = [MaybeUninit::new(0u8); 8192];
        let mut icmp_buf: [MaybeUninit<u8>; 8192] = [MaybeUninit::new(0u8); 8192];
        let mut pfds = [
            libc::pollfd {
                fd: sock.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: icmp_sock.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        while remaining > 0 {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let rc = unsafe {
                libc::poll(
                    pfds.as_mut_ptr(),
                    2,
                    deadline.saturating_duration_since(now).as_millis() as libc::c_int,
                )
            };
            if rc <= 0 {
                break;
            }
            // raw TCP：SYN-ACK / RST（目标到达）
            if pfds[0].revents & libc::POLLIN != 0 {
                let Ok((n, addr)) = sock.recv_from(&mut tcp_buf) else {
                    continue;
                };
                let data: &[u8] =
                    unsafe { std::slice::from_raw_parts(tcp_buf.as_ptr() as *const u8, n) };
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
                if tcp_flags(data, target_ip.is_ipv6())
                    .is_some_and(|f| f & 0x12 == 0x12 || f & 0x04 == 0x04)
                {
                    dest_hit = true;
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
            // raw ICMP：Time Exceeded（中间路由）
            if pfds[1].revents & libc::POLLIN != 0 {
                let Ok((n, addr)) = icmp_sock.recv_from(&mut icmp_buf) else {
                    continue;
                };
                let data: &[u8] =
                    unsafe { std::slice::from_raw_parts(icmp_buf.as_ptr() as *const u8, n) };
                let peer: IpAddr = addr
                    .as_socket()
                    .map(|s| s.ip())
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                let sport = if target_ip.is_ipv6() {
                    match parse_ttl_exceeded_v6(data, target_ip, dport, &want) {
                        Some(s) => s,
                        None => {
                            super::trace_dump("tcp-icmp-v6", data, false);
                            continue;
                        }
                    }
                } else {
                    match parse_ttl_exceeded_v4(data, target_ip, dport, &want) {
                        Some(s) => s,
                        None => {
                            super::trace_dump("tcp-icmp-v4", data, false);
                            continue;
                        }
                    }
                };
                super::trace_dump(
                    if target_ip.is_ipv6() {
                        "tcp-icmp-v6"
                    } else {
                        "tcp-icmp-v4"
                    },
                    data,
                    true,
                );
                // 记录 RTT（Time Exceeded 只算中间跳，不算到达）
                if let Some(idx) = probes.iter().position(|&(s, _)| s == sport)
                    && rtts[idx].is_none()
                {
                    let rtt = probes[idx].1.elapsed();
                    rtts[idx] = Some(rtt);
                    remaining -= 1;
                }
                src = Some(peer);
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

/// Windows：委托 Npcap 路径（`tcpwin.rs`）。
#[cfg(windows)]
pub(crate) fn trace_tcp(
    cfg: &PingConfig,
    target_ip: IpAddr,
    max_hops: u32,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    super::tcpwin::trace_tcp_pcap(cfg, target_ip, max_hops, w)
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
///
/// 回复端口镜像请求：(src port, dst port) = (dport, 我们的源端口)——源端口必须是
/// 目标端口、目的端口必须在我们发出的源端口列表里；源 IP 必须为目标（防伪造/杂包）。
/// 返回该回复对应的探测源端口（= 回复目的端口）。
#[cfg(unix)]
fn match_tcp_reply_v4(buf: &[u8], target: IpAddr, dport: u16, want: &[u16]) -> Option<u16> {
    super::match_tcp_syn_reply_v4(buf, target, dport, want).map(|(port, _)| port)
}

/// 匹配 IPv6 TCP 回包（框架探测：首字节 version nibble == 6 且长度足够 → 含 40B
/// IPv6 头；Linux 惯例是 raw v6 socket 收到不含 IPv6 头的载荷）。
#[cfg(unix)]
fn match_tcp_reply_v6(buf: &[u8], target: IpAddr, dport: u16, want: &[u16]) -> Option<u16> {
    // 框架探测：首字节 version nibble == 6 且长度足够 → 含 40B IPv6 头
    let ip = util::ipv6_frame_skip(buf);
    let tcp = if ip.len() != buf.len() {
        // 带头：顺带校验源地址
        if IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&buf[8..24]).ok()?,
        )) != target
        {
            return None;
        }
        ip
    } else {
        buf
    };
    if tcp.len() < 20 {
        return None;
    }
    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if sport != dport || !want.contains(&dst_port) {
        return None;
    }
    Some(dst_port)
}

/// 解析 IPv4 ICMP Time Exceeded（type 11 code 0），携带我们发出的 SYN：
/// 内嵌报文的 dst == 目标、内嵌 TCP (src port, dst port) == (我们的源端口, 目标端口)。
/// 返回该回复对应的探测源端口。
#[cfg(unix)]
fn parse_ttl_exceeded_v4(buf: &[u8], target: IpAddr, dport: u16, want: &[u16]) -> Option<u16> {
    if buf.len() < 20 {
        return None;
    }
    let ihl = util::ipv4_ihl(buf);
    if buf.len() < ihl + 8 {
        return None;
    }
    let icmp = &buf[ihl..];
    if icmp[0] != 11 || icmp[1] != 0 {
        return None;
    }
    let body = icmp.get(8..)?;
    if body.len() < 20 || (body[0] >> 4) != 4 {
        return None;
    }
    let inner_ihl = util::ipv4_ihl(body);
    if body.len() < inner_ihl + 4 {
        return None;
    }
    let inner_dst = IpAddr::V4(std::net::Ipv4Addr::new(
        body[16], body[17], body[18], body[19],
    ));
    if inner_dst != target {
        return None;
    }
    let tcp = &body[inner_ihl..];
    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if dst_port != dport || !want.contains(&sport) {
        return None;
    }
    Some(sport)
}

/// 解析 IPv6 ICMPv6 Time Exceeded（type 3 code 0），语义同 v4。
#[cfg(unix)]
fn parse_ttl_exceeded_v6(buf: &[u8], target: IpAddr, dport: u16, want: &[u16]) -> Option<u16> {
    let icmp = util::ipv6_frame_skip(buf);
    if icmp.len() < 8 {
        return None;
    }
    if icmp[0] != 3 || icmp[1] != 0 {
        return None;
    }
    let body = icmp.get(8..)?;
    if body.len() < 40 {
        return None;
    }
    let inner_dst = IpAddr::V6(std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&body[24..40]).ok()?,
    ));
    if inner_dst != target {
        return None;
    }
    let tcp = body.get(40..)?;
    if tcp.len() < 4 {
        return None;
    }
    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if dst_port != dport || !want.contains(&sport) {
        return None;
    }
    Some(sport)
}

/// 取 TCP flags（data offset 5 的标准 20B 头；v4 恒含 IP 头，v6 按框架探测）。
#[cfg(unix)]
fn tcp_flags(buf: &[u8], is_v6: bool) -> Option<u8> {
    let tcp = if is_v6 {
        util::ipv6_frame_skip(buf)
    } else {
        let ihl = util::ipv4_ihl(buf);
        buf.get(ihl..)?
    };
    tcp.get(13).copied()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn syn_reply(sport: u16, dport: u16, src: [u8; 4], flags: u8) -> Vec<u8> {
        // 20B IP 头 + 20B TCP
        let mut b = vec![0u8; 40];
        b[0] = 0x45;
        b[9] = 6;
        b[12..16].copy_from_slice(&src);
        b[16..20].copy_from_slice(&[10, 0, 0, 2]);
        b[20..22].copy_from_slice(&sport.to_be_bytes());
        b[22..24].copy_from_slice(&dport.to_be_bytes());
        b[33] = flags;
        b
    }

    #[test]
    fn match_tcp_reply_accepts_synack_and_rst() {
        let want = [0x4000u16, 0x4001, 0x4002];
        // SYN-ACK：源端口 = 目标端口 80，目的端口 = 我们的源端口
        let synack = syn_reply(80, 0x4001, [10, 0, 0, 2], 0x12);
        assert_eq!(
            match_tcp_reply_v4(&synack, "10.0.0.2".parse().unwrap(), 80, &want),
            Some(0x4001)
        );
        // RST
        let rst = syn_reply(80, 0x4002, [10, 0, 0, 2], 0x04);
        assert_eq!(
            match_tcp_reply_v4(&rst, "10.0.0.2".parse().unwrap(), 80, &want),
            Some(0x4002)
        );
    }

    #[test]
    fn match_tcp_reply_rejects_own_syn_and_wrong_ports() {
        let want = [0x4000u16];
        // 自己发出的 SYN 会被 raw socket 回读（回环）：源端口 ∈ want → 必须拒绝
        let own = syn_reply(0x4000, 80, [10, 0, 0, 2], 0x02);
        assert_eq!(
            match_tcp_reply_v4(&own, "10.0.0.2".parse().unwrap(), 80, &want),
            None
        );
        // 端口不镜像（非本会话的包）
        let other = syn_reply(80, 9999, [10, 0, 0, 2], 0x12);
        assert_eq!(
            match_tcp_reply_v4(&other, "10.0.0.2".parse().unwrap(), 80, &want),
            None
        );
        // 源 IP 不是目标（伪造/杂包）
        let spoofed = syn_reply(80, 0x4000, [10, 0, 0, 99], 0x12);
        assert_eq!(
            match_tcp_reply_v4(&spoofed, "10.0.0.2".parse().unwrap(), 80, &want),
            None
        );
    }

    #[test]
    fn ttl_exceeded_v4_carries_syn() {
        // ICMP 头 + 内嵌 IP 头 + 内嵌 TCP 头
        let mut b = vec![0u8; 20 + 8 + 20 + 20];
        b[0] = 0x45; // 外层 IP
        b[9] = 1; // proto ICMP
        b[12..16].copy_from_slice(&[10, 0, 0, 1]); // 路由器源地址
        let icmp = 20;
        b[icmp] = 11; // Time Exceeded
        b[icmp + 1] = 0;
        let inner = icmp + 8;
        b[inner] = 0x45; // 内嵌 IP
        b[inner + 9] = 6; // 内嵌 proto TCP
        b[inner + 16..inner + 20].copy_from_slice(&[10, 0, 0, 2]); // 内嵌 dst = 目标
        let tcp = inner + 20;
        b[tcp..tcp + 2].copy_from_slice(&0x4001u16.to_be_bytes()); // 内嵌源端口
        b[tcp + 2..tcp + 4].copy_from_slice(&80u16.to_be_bytes()); // 内嵌目的端口
        assert_eq!(
            parse_ttl_exceeded_v4(&b, "10.0.0.2".parse().unwrap(), 80, &[0x4001]),
            Some(0x4001)
        );
        // 内嵌 dst 不对 → None
        b[inner + 16] = 11;
        assert_eq!(
            parse_ttl_exceeded_v4(&b, "10.0.0.2".parse().unwrap(), 80, &[0x4001]),
            None
        );
    }

    #[test]
    fn tcp_flags_from_ip_and_tcp() {
        let b = syn_reply(80, 0x4000, [10, 0, 0, 2], 0x14);
        assert_eq!(tcp_flags(&b, false), Some(0x14));
        assert_eq!(tcp_flags(&[], false), None);
    }
}
