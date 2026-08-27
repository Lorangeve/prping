//! ICMP echo 逐跳探测：raw ICMP socket 收发，回复按内嵌 ICMP 的 id/seq 匹配。

use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use termcolor::StandardStream;

use super::{Hop, PROBE_TIMEOUT, PROBES_PER_HOP, PingConfig, finish_hop};
use crate::util;

/// ICMP echo 逐跳：raw ICMP socket 收发，回复按内嵌 ICMP 的 id/seq 匹配。
pub(crate) fn trace_icmp(
    cfg: &PingConfig,
    target_ip: IpAddr,
    max_hops: u32,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    let (sock, target_sa) = crate::util::create_icmp_socket(target_ip, cfg.source)?;
    let ident = crate::util::rand_u16();

    let mut hops: Vec<Hop> = Vec::new();
    let mut seq_counter: u16 = 0;
    let mut reached = false;

    for hop_no in 1..=max_hops {
        if util::interrupted() {
            break;
        }
        crate::util::set_ttl(&sock, hop_no, target_ip.is_ipv6())?;

        // 发送本跳全部探测（背靠背，不逐包等待）
        let mut probes: Vec<(u16, Instant)> = Vec::with_capacity(PROBES_PER_HOP);
        for _ in 0..PROBES_PER_HOP {
            let seq = seq_counter;
            seq_counter = seq_counter.wrapping_add(1);
            let pkt = if target_ip.is_ipv4() {
                crate::ping::icmp::build_v4(ident, seq, 32)
            } else {
                crate::ping::icmp::build_v6(ident, seq, 32)
            };
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
                Ok((n, addr)) => {
                    let data: &[u8] =
                        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                    let peer: IpAddr = addr
                        .as_socket()
                        .map(|s| s.ip())
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                    let (seq, is_echo) = if target_ip.is_ipv6() {
                        match parse_reply_v6(data, target_ip, ident, &want) {
                            Some(r) => r,
                            None => {
                                super::trace_dump("icmp-v6", data, false);
                                continue;
                            }
                        }
                    } else {
                        match parse_reply_v4(data, target_ip, ident, &want) {
                            Some(r) => r,
                            None => {
                                super::trace_dump("icmp-v4", data, false);
                                continue;
                            }
                        }
                    };
                    super::trace_dump(
                        if target_ip.is_ipv6() {
                            "icmp-v6"
                        } else {
                            "icmp-v4"
                        },
                        data,
                        true,
                    );
                    if is_echo {
                        dest_hit = true;
                    }
                    // 记录 RTT
                    if let Some(idx) = probes.iter().position(|&(s, _)| s == seq)
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

/// 解析 IPv4 回复。`buf` 含 IP 头（raw socket 恒含）。
///
/// - echo reply：type 0，id/seq 在 ICMP 头偏移 4/6 → 目标回显。
/// - Time Exceeded：type 11 code 0，数据区含原始 IP 头(20B+) + 前 8B ICMP。
///   id/seq 精确匹配优先；截断（不足 28B）时按内嵌 dst == 目标归属。
pub(crate) fn parse_reply_v4(
    buf: &[u8],
    target: IpAddr,
    ident: u16,
    want: &[u16],
) -> Option<(u16, bool)> {
    if buf.len() < 20 {
        return None;
    }
    let ihl = (buf[0] & 0x0F) as usize * 4;
    if buf.len() < ihl + 8 {
        return None;
    }
    let icmp = &buf[ihl..];
    match icmp[0] {
        0 => {
            // echo reply
            let id = u16::from_be_bytes([icmp[4], icmp[5]]);
            let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
            if id == ident && want.contains(&seq) {
                Some((seq, true))
            } else {
                None
            }
        }
        11 if icmp[1] == 0 => {
            // Time Exceeded：数据区 = 内嵌 IP 头(20B+) + 前 8B ICMP
            let body = icmp.get(8..)?;
            if body.len() < 20 {
                return None;
            }
            let inner_ihl = (body[0] & 0x0F) as usize * 4;
            if body.len() < inner_ihl + 8 {
                return None;
            }
            // 内嵌 dst（偏移 16..20）
            let inner_dst = IpAddr::V4(std::net::Ipv4Addr::new(
                body[16], body[17], body[18], body[19],
            ));
            if inner_dst != target {
                return None;
            }
            let eicmp = &body[inner_ihl..];
            let id = u16::from_be_bytes([eicmp[4], eicmp[5]]);
            let seq = u16::from_be_bytes([eicmp[6], eicmp[7]]);
            if id == ident && want.contains(&seq) {
                Some((seq, false))
            } else {
                // 截断时按 dst 归属
                if !want.is_empty() {
                    Some((want[0], false))
                } else {
                    None
                }
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
pub(crate) fn parse_reply_v6(
    buf: &[u8],
    target: IpAddr,
    ident: u16,
    want: &[u16],
) -> Option<(u16, bool)> {
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
            // Time Exceeded：数据区 = 原始 IPv6 头(40B) + 前 8B ICMPv6
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
