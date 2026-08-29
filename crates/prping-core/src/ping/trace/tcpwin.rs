//! Windows TCP SYN 逐跳探测（`trace HOST:PORT` 带端口自动启用）：Npcap 链路层注入完整帧
//! （eth + ip + tcp SYN，TTL 递增写在 IP 头里）+ pcap 抓包收回复。
//!
//! 背景：Windows 禁止 raw TCP socket（SOCK_RAW + IPPROTO_TCP 创建失败），Unix 的
//! raw socket 路径不可用；改用与 `packet --raw` 相同的 pcap 兼容层（`engine/rawpcap.rs`）：
//!
//! - 发送：`pcap_sendpacket` 注入完整以太网帧（src/dst MAC 经 `GetBestRoute` +
//!   ARP 缓存 + `GetIfEntry` 解析，见 `rawpcap::resolve_macs_win`）。
//! - 接收：同一抓包句柄收 SYN-ACK/RST（目标到达，源 IP = 目标、端口镜像）与
//!   ICMP Time Exceeded（中间路由，内嵌报文 = 我们发出的 SYN）。
//! - 未装 Npcap：`ensure()` 在 banner 前经 `rawpcap::ensure_wpcap()`（LoadLibrary
//!   探测）报友好错误，绝不让 wpcap.dll 的 delay-load 异常走到。
//! - IPv6：仅回环可经 Npcap Loopback Adapter 发送（ND 邻居解析在 Win7 不可枚举），
//!   跨链路 v6 目标报错——本模块只实现 IPv4。
//!
//! 纯函数（帧构造 / 回复解析）带 `#[cfg(any(windows, test))]` 可在任意平台单测；
//! pcap I/O 仅 Windows 编译。

use std::net::{IpAddr, Ipv4Addr};

// pcap I/O 路径（Windows）专用导入；纯函数与测试在任意平台编译
#[cfg(windows)]
use super::{Hop, PROBE_TIMEOUT, PROBES_PER_HOP, PingConfig};
#[cfg(windows)]
use crate::util;
#[cfg(windows)]
use std::net::SocketAddr;
#[cfg(windows)]
use std::time::{Duration, Instant};
#[cfg(windows)]
use termcolor::StandardStream;

/// TCP SYN 探测源端口范围（与 Unix 路径一致）。
#[cfg(windows)]
const TCP_SPORT_MIN: u16 = 0x4000;
#[cfg(windows)]
const TCP_SPORT_MAX: u16 = 0x5FFF;

/// 入口前置检查：未装 Npcap 时在 banner 前报错（`trace/mod.rs::ensure_tcp_trace_supported`）。
#[cfg(windows)]
pub(crate) fn ensure() -> anyhow::Result<()> {
    crate::engine::rawpcap::ensure_wpcap()
}

/// Windows：Npcap 注入 SYN（完整以太网帧）+ 抓包收 SYN-ACK/RST / ICMP Time Exceeded。
///
/// 与 Unix 路径语义一致：每跳 3 个探测（独立源端口 0x4000..=0x5FFF 递增），
/// 回复按内嵌 TCP 头 (sport, dport) 匹配归属；SYN-ACK/RST 算到达，Time Exceeded
/// 算中间跳。抓包句柄先于发送打开（局域网回包可能 <1ms，先发后开会漏抓）。
#[cfg(windows)]
pub(crate) fn trace_tcp_pcap(
    cfg: &PingConfig,
    target_ip: IpAddr,
    max_hops: u32,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    let target_v4 = match target_ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => anyhow::bail!(rust_i18n::t!("errors.tcp_trace_ipv6")),
    };
    let dport = cfg.port;
    // 源 IP：-s 给定（v4）或按路由探测（UDP connect，不发数据）
    let local: Ipv4Addr = match cfg.source.filter(IpAddr::is_ipv4) {
        Some(IpAddr::V4(v4)) => v4,
        Some(IpAddr::V6(_)) => unreachable!("filter(IpAddr::is_ipv4) 已剔除 v6"),
        None => {
            let sa = SocketAddr::new(target_ip, dport);
            match crate::engine::pkg::local_ip_for(&sa) {
                Some(IpAddr::V4(v4)) => v4,
                _ => anyhow::bail!(rust_i18n::t!("errors.trace_no_local_addr")),
            }
        }
    };
    // 设备 + MAC 解析 + 抓包句柄（先开抓包再发送）
    let dev =
        crate::engine::rawpcap::select_device_name(Some(&SocketAddr::new(target_ip, dport)), None)?;
    let (dst_mac, src_mac) = crate::engine::rawpcap::resolve_macs_win(target_v4)?;
    // Windows TCP trace 需要过滤自注入的 SYN 帧
    let mut cap = crate::engine::rawpcap::open_capture(&dev, true)?;

    let mut sport_counter: u16 = TCP_SPORT_MIN;
    // 逐跳骨架共用（渲染上一跳/interrupted/PendingHop 收尾），本路径只提供
    // hop_body：构造并注入 SYN 帧 + pcap next_packet 收集
    super::trace_loop_skeleton(
        cfg,
        max_hops,
        |hop_no| {
            // 构造并注入本跳全部探测（背靠背，不逐包等待）
            let mut probes: Vec<(u16, Instant, Vec<u8>)> = Vec::with_capacity(PROBES_PER_HOP);
            for _ in 0..PROBES_PER_HOP {
                let sport = sport_counter;
                sport_counter = sport_counter.wrapping_add(1);
                if sport_counter > TCP_SPORT_MAX {
                    sport_counter = TCP_SPORT_MIN;
                }
                let frame =
                    build_syn_frame(dst_mac, src_mac, target_v4, local, sport, dport, hop_no);
                let sent = Instant::now();
                if cap.sendpacket(frame.as_slice()).is_ok() {
                    probes.push((sport, sent, frame));
                }
            }
            if probes.is_empty() {
                return Ok(super::HopCollect::default());
            }

            // 收集回复直到全部匹配或超时
            let want: Vec<u16> = probes.iter().map(|&(s, _, _)| s).collect();
            let sent_frames: Vec<&[u8]> = probes.iter().map(|p| p.2.as_slice()).collect();
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
                match cap.next_packet() {
                    Ok(p) => {
                        // Npcap 会把刚注入的帧回读给抓包句柄（direction(In) 过滤在部分
                        // 虚拟网卡上不生效）：与发送帧逐字节相同的帧是自身回读，跳过
                        // （真回包不可能与 SYN 请求逐字节相同）。
                        if sent_frames.iter().any(|f| *f == p.data) {
                            continue;
                        }
                        let Some(m) = parse_reply_frame(p.data, target_v4, dport, &want) else {
                            super::trace_dump("tcp-pcap", p.data, false);
                            continue;
                        };
                        super::trace_dump("tcp-pcap", p.data, true);
                        if m.is_dest {
                            dest_hit = true;
                        }
                        if let Some(idx) = probes.iter().position(|&(s, _, _)| s == m.sport)
                            && rtts[idx].is_none()
                        {
                            rtts[idx] = Some(probes[idx].1.elapsed());
                            remaining -= 1;
                        }
                        src = Some(m.src);
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => return Err(anyhow::anyhow!("pcap 捕获失败：{e}")),
                }
            }
            Ok(super::HopCollect {
                src,
                rtts,
                dest_hit,
            })
        },
        w,
    )
}

/// 单帧回复的解析结果。
#[cfg(any(windows, test))]
struct ReplyMatch {
    /// 该回复对应的探测源端口。
    sport: u16,
    /// 回复者地址（中间路由 / 目标）。
    src: IpAddr,
    /// 是否目标到达（SYN-ACK/RST）。
    is_dest: bool,
}

/// 解析抓包收到的完整以太网帧：TCP 回复（SYN-ACK/RST）或 ICMP Time Exceeded。
///
/// - TCP：源 IP == 目标、TCP (src port, dst port) == (dport, 我们的源端口) →
///   到达（flags 为 SYN-ACK 0x12 或 RST 0x04 时置 is_dest；其它 flags 也按回复计）。
/// - ICMP type 11 code 0：内嵌报文的 dst == 目标、内嵌 TCP 端口镜像 → 中间跳。
#[cfg(any(windows, test))]
fn parse_reply_frame(
    frame: &[u8],
    target: Ipv4Addr,
    dport: u16,
    want: &[u16],
) -> Option<ReplyMatch> {
    if frame.len() < 14 + 20 {
        return None;
    }
    // 以太网帧：ethertype 0x0800 = IPv4
    if frame[12] != 0x08 || frame[13] != 0x00 {
        return None;
    }
    let ip = &frame[14..];
    if (ip[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    if ip.len() < ihl + 8 {
        return None;
    }
    let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    match ip[9] {
        6 => {
            // TCP 回复：复用共享匹配逻辑
            let (sport, is_dest) =
                super::match_tcp_syn_reply_v4(ip, IpAddr::V4(target), dport, want)?;
            Some(ReplyMatch {
                sport,
                src,
                is_dest,
            })
        }
        1 => {
            // ICMP Time Exceeded（type 11 code 0），携带我们发出的 SYN
            let icmp = ip.get(ihl..)?;
            if icmp.len() < 8 || icmp[0] != 11 || icmp[1] != 0 {
                return None;
            }
            let body = icmp.get(8..)?;
            if body.len() < 24 || (body[0] >> 4) != 4 {
                return None;
            }
            let inner_ihl = crate::util::ipv4_ihl(body);
            if body.len() < inner_ihl + 4 {
                return None;
            }
            let inner_dst = Ipv4Addr::new(body[16], body[17], body[18], body[19]);
            if inner_dst != target {
                return None;
            }
            let tcp = &body[inner_ihl..];
            let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
            if dst_port != dport || !want.contains(&sport) {
                return None;
            }
            Some(ReplyMatch {
                sport,
                src,
                is_dest: false,
            })
        }
        _ => None,
    }
}

/// 构建完整以太网帧：14B eth + 20B IPv4（TTL = 跳数，DF 置位）+ 20B TCP SYN。
///
/// IP 头校验和与 TCP 校验和（伪头部）都需手算——pcap 注入的是完整帧，内核不参与。
#[cfg(any(windows, test))]
fn build_syn_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    dst: Ipv4Addr,
    src: Ipv4Addr,
    sport: u16,
    dport: u16,
    ttl: u32,
) -> Vec<u8> {
    let mut b = vec![0u8; 14 + 20 + 20];
    // 以太网头
    b[0..6].copy_from_slice(&dst_mac);
    b[6..12].copy_from_slice(&src_mac);
    b[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
    // IPv4 头（偏移 14）
    b[14] = 0x45; // v4 + IHL 5
    b[16..18].copy_from_slice(&40u16.to_be_bytes()); // total length
    let id = crate::util::rand_u16();
    b[18..20].copy_from_slice(&id.to_be_bytes()); // id
    b[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    b[22] = ttl.min(255) as u8; // TTL = 跳数
    b[23] = 6; // proto TCP
    // b[24..26] = checksum（先置 0 再算）
    b[26..30].copy_from_slice(&src.octets());
    b[30..34].copy_from_slice(&dst.octets());
    let ip_csum = crate::ping::icmp::icmp_cksum(&b[14..34]);
    b[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    // TCP 头（偏移 34）
    b[34..36].copy_from_slice(&sport.to_be_bytes());
    b[36..38].copy_from_slice(&dport.to_be_bytes());
    let seq = crate::util::rand_u32();
    b[38..42].copy_from_slice(&seq.to_be_bytes()); // seq = random
    // b[42..46] = ack = 0
    b[46] = 5 << 4; // data offset 5
    b[47] = 0x02; // SYN
    b[48..50].copy_from_slice(&0xFFFFu16.to_be_bytes()); // window
    // b[50..52] = checksum（先置 0 再算）
    // b[52..54] = urg = 0
    // TCP 校验和：12B 伪头部（src + dst + 0 + proto 6 + 长度 20）+ 20B TCP
    let mut pseudo = Vec::with_capacity(12 + 20);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&20u16.to_be_bytes());
    pseudo.extend_from_slice(&b[34..54]);
    let tcp_csum = crate::ping::icmp::icmp_cksum(&pseudo);
    b[50..52].copy_from_slice(&tcp_csum.to_be_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_frame_layout_and_checksums() {
        let f = build_syn_frame(
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            0x4001,
            80,
            1,
        );
        assert_eq!(f.len(), 54);
        assert_eq!(&f[0..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // dst MAC
        assert_eq!(&f[6..12], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src MAC
        assert_eq!(&f[12..14], &[0x08, 0x00]); // IPv4 ethertype
        assert_eq!(f[14], 0x45);
        assert_eq!(f[22], 1); // TTL
        assert_eq!(f[23], 6); // proto TCP
        assert_eq!(&f[26..30], &[10, 0, 0, 1]); // src IP
        assert_eq!(&f[30..34], &[10, 0, 0, 2]); // dst IP
        assert_eq!(&f[34..36], &0x4001u16.to_be_bytes()); // sport
        assert_eq!(&f[36..38], &80u16.to_be_bytes()); // dport
        assert_eq!(f[47], 0x02); // SYN
        // IP 头校验和自洽（清 0 重算相等）
        let mut ip = f[14..34].to_vec();
        ip[10..12].copy_from_slice(&[0, 0]);
        assert_eq!(
            u16::from_be_bytes([f[24], f[25]]),
            crate::ping::icmp::icmp_cksum(&ip)
        );
        // TCP 校验和自洽
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&f[26..30]);
        pseudo.extend_from_slice(&f[30..34]);
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&20u16.to_be_bytes());
        let mut tcp = f[34..54].to_vec();
        tcp[16..18].copy_from_slice(&[0, 0]);
        pseudo.extend_from_slice(&tcp);
        assert_eq!(
            u16::from_be_bytes([f[50], f[51]]),
            crate::ping::icmp::icmp_cksum(&pseudo)
        );
    }

    fn tcp_reply_frame(sport: u16, dport: u16, src: [u8; 4], flags: u8) -> Vec<u8> {
        // 14B eth + 20B IP + 20B TCP
        let mut f = vec![0u8; 54];
        f[12..14].copy_from_slice(&[0x08, 0x00]);
        f[14] = 0x45;
        f[23] = 6;
        f[26..30].copy_from_slice(&src);
        f[30..34].copy_from_slice(&[10, 0, 0, 2]);
        f[34..36].copy_from_slice(&sport.to_be_bytes());
        f[36..38].copy_from_slice(&dport.to_be_bytes());
        f[47] = flags;
        f
    }

    #[test]
    fn parse_reply_accepts_synack_and_rst() {
        let want = [0x4001u16];
        let synack = tcp_reply_frame(80, 0x4001, [10, 0, 0, 2], 0x12);
        let m = parse_reply_frame(&synack, Ipv4Addr::new(10, 0, 0, 2), 80, &want).unwrap();
        assert_eq!(m.sport, 0x4001);
        assert!(m.is_dest);
        assert_eq!(m.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        let rst = tcp_reply_frame(80, 0x4001, [10, 0, 0, 2], 0x04);
        assert!(
            parse_reply_frame(&rst, Ipv4Addr::new(10, 0, 0, 2), 80, &want)
                .unwrap()
                .is_dest
        );
    }

    #[test]
    fn parse_reply_rejects_own_frame_and_spoof() {
        let want = [0x4001u16];
        // 自己注入的 SYN 被 Npcap 回读：src port ∈ want → 拒绝
        let own = tcp_reply_frame(0x4001, 80, [10, 0, 0, 1], 0x02);
        assert!(parse_reply_frame(&own, Ipv4Addr::new(10, 0, 0, 2), 80, &want).is_none());
        // 源 IP 不是目标
        let spoof = tcp_reply_frame(80, 0x4001, [10, 0, 0, 99], 0x12);
        assert!(parse_reply_frame(&spoof, Ipv4Addr::new(10, 0, 0, 2), 80, &want).is_none());
        // 非本会话端口
        let other = tcp_reply_frame(80, 9999, [10, 0, 0, 2], 0x12);
        assert!(parse_reply_frame(&other, Ipv4Addr::new(10, 0, 0, 2), 80, &want).is_none());
    }

    #[test]
    fn parse_reply_accepts_ttl_exceeded() {
        // 14B eth + 20B IP(proto 1) + 8B ICMP + 20B 内嵌 IP + 20B 内嵌 TCP
        let mut f = vec![0u8; 14 + 20 + 8 + 20 + 20];
        f[12..14].copy_from_slice(&[0x08, 0x00]);
        f[14] = 0x45;
        f[23] = 1; // proto ICMP
        f[26..30].copy_from_slice(&[10, 0, 0, 1]); // 路由器
        f[30..34].copy_from_slice(&[10, 0, 0, 2]);
        let icmp = 14 + 20;
        f[icmp] = 11; // Time Exceeded
        f[icmp + 1] = 0;
        let inner = icmp + 8;
        f[inner] = 0x45; // 内嵌 IP
        f[inner + 9] = 6; // 内嵌 proto TCP
        f[inner + 16..inner + 20].copy_from_slice(&[10, 0, 0, 2]); // 内嵌 dst = 目标
        let tcp = inner + 20;
        f[tcp..tcp + 2].copy_from_slice(&0x4001u16.to_be_bytes()); // 内嵌源端口
        f[tcp + 2..tcp + 4].copy_from_slice(&80u16.to_be_bytes()); // 内嵌目的端口
        let m = parse_reply_frame(&f, Ipv4Addr::new(10, 0, 0, 2), 80, &[0x4001]).unwrap();
        assert_eq!(m.sport, 0x4001);
        assert!(!m.is_dest);
        assert_eq!(m.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        // 内嵌 dst 不对 → None
        f[inner + 16] = 11;
        assert!(parse_reply_frame(&f, Ipv4Addr::new(10, 0, 0, 2), 80, &[0x4001]).is_none());
    }
}
