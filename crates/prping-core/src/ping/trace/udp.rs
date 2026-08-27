//! UDP 逐跳探测：普通 UDP socket 发送，raw ICMP socket 收取 Time Exceeded / Port Unreachable。

use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use termcolor::StandardStream;

use super::{Hop, PROBE_TIMEOUT, PROBES_PER_HOP, PingConfig, finish_hop};
use crate::util;

/// UDP 起始端口（经典 Unix traceroute）。
const UDP_START_PORT: u16 = 33434;

/// UDP 逐跳：普通 UDP socket 发送，raw ICMP socket 收取 Time Exceeded / Port Unreachable。
pub(crate) fn trace_udp(
    cfg: &PingConfig,
    target_ip: IpAddr,
    max_hops: u32,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    let udp_sock = crate::util::create_udp_socket(target_ip, cfg.source, 0)?;
    let (icmp_sock, _) = crate::util::create_icmp_socket(target_ip, cfg.source)?;

    let mut hops: Vec<Hop> = Vec::new();
    let mut port_counter: u16 = UDP_START_PORT;
    let mut reached = false;

    for hop_no in 1..=max_hops {
        if util::interrupted() {
            break;
        }
        crate::util::set_ttl(&udp_sock, hop_no, target_ip.is_ipv6())?;

        // 发送本跳全部探测
        let mut probes: Vec<(u16, Instant)> = Vec::with_capacity(PROBES_PER_HOP);
        for _ in 0..PROBES_PER_HOP {
            let port = port_counter;
            port_counter = port_counter.wrapping_add(1);
            let target = std::net::SocketAddr::new(target_ip, port);
            let data = vec![0u8; 32]; // 32 字节载荷
            let sent = Instant::now();
            if udp_sock
                .send_to(&data, &socket2::SockAddr::from(target))
                .is_ok()
            {
                probes.push((port, sent));
            }
        }
        if probes.is_empty() {
            break;
        }

        // 收集回复直到全部匹配或超时
        let want: Vec<u16> = probes.iter().map(|&(p, _)| p).collect();
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
            icmp_sock.set_read_timeout(Some(deadline - now))?;
            match icmp_sock.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    let data: &[u8] =
                        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                    let peer: IpAddr = addr
                        .as_socket()
                        .map(|s| s.ip())
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                    let port = if target_ip.is_ipv6() {
                        match parse_udp_icmp_v6(data, target_ip, &want) {
                            Some(p) => p,
                            None => {
                                super::trace_dump("udp-v6", data, false);
                                continue;
                            }
                        }
                    } else {
                        match parse_udp_icmp_v4(data, target_ip, &want) {
                            Some(p) => p,
                            None => {
                                super::trace_dump("udp-v4", data, false);
                                continue;
                            }
                        }
                    };
                    super::trace_dump(
                        if target_ip.is_ipv6() {
                            "udp-v6"
                        } else {
                            "udp-v4"
                        },
                        data,
                        true,
                    );
                    // Port Unreachable 即到达
                    if is_port_unreachable(data, target_ip) {
                        dest_hit = true;
                    }
                    // 记录 RTT
                    if let Some(idx) = probes.iter().position(|&(p, _)| p == port)
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

/// 解析 IPv4 UDP ICMP 回包（Time Exceeded / Port Unreachable）。
fn parse_udp_icmp_v4(buf: &[u8], target: IpAddr, want: &[u16]) -> Option<u16> {
    if buf.len() < 20 {
        return None;
    }
    let ihl = (buf[0] & 0x0F) as usize * 4;
    if buf.len() < ihl + 8 {
        return None;
    }
    let icmp = &buf[ihl..];
    // type 11 (Time Exceeded) 或 type 3 code 3 (Port Unreachable)
    if icmp[0] != 11 && !(icmp[0] == 3 && icmp[1] == 3) {
        return None;
    }
    // 内嵌报文
    let body = icmp.get(8..)?;
    if body.len() < 20 {
        return None;
    }
    let inner_ihl = (body[0] & 0x0F) as usize * 4;
    if body.len() < inner_ihl + 8 {
        return None;
    }
    // 内嵌 dst
    let inner_dst = IpAddr::V4(std::net::Ipv4Addr::new(
        body[16], body[17], body[18], body[19],
    ));
    if inner_dst != target {
        return None;
    }
    // 内嵌 UDP 头：dst port 在偏移 2..4
    let udp = &body[inner_ihl..];
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if want.contains(&dst_port) {
        Some(dst_port)
    } else {
        None
    }
}

/// 解析 IPv6 UDP ICMP 回包。
fn parse_udp_icmp_v6(buf: &[u8], target: IpAddr, want: &[u16]) -> Option<u16> {
    // 框架探测
    let icmp = if buf.len() >= 48 && buf[0] >> 4 == 6 {
        &buf[40..]
    } else {
        buf
    };
    if icmp.len() < 8 {
        return None;
    }
    // type 3 code 0 (Time Exceeded) 或 type 1 code 4 (Port Unreachable)
    if !(icmp[0] == 3 && icmp[1] == 0 || icmp[0] == 1 && icmp[1] == 4) {
        return None;
    }
    // 内嵌报文
    let body = icmp.get(8..)?;
    if body.len() < 40 {
        return None;
    }
    // 内嵌 IPv6 头：dst 在偏移 24..40
    let inner_dst = IpAddr::V6(std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&body[24..40]).ok()?,
    ));
    if inner_dst != target {
        return None;
    }
    // 内嵌 UDP 头：dst port 在偏移 2..4
    let udp = &body[40..];
    if udp.len() < 4 {
        return None;
    }
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if want.contains(&dst_port) {
        Some(dst_port)
    } else {
        None
    }
}

/// 检查是否为 Port Unreachable（到达目标）。
fn is_port_unreachable(buf: &[u8], target: IpAddr) -> bool {
    if buf.is_empty() {
        return false;
    }
    if target.is_ipv6() {
        // ICMPv6 type 1 code 4
        let icmp = if buf[0] >> 4 == 6 && buf.len() >= 48 {
            &buf[40..]
        } else {
            buf
        };
        icmp.len() >= 2 && icmp[0] == 1 && icmp[1] == 4
    } else {
        // ICMP type 3 code 3
        let ihl = (buf[0] & 0x0F) as usize * 4;
        if buf.len() < ihl + 2 {
            return false;
        }
        let icmp = &buf[ihl..];
        icmp[0] == 3 && icmp[1] == 3
    }
}
