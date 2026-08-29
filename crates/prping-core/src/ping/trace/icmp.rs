//! ICMP echo 逐跳探测：raw ICMP socket 收发，回复按内嵌 ICMP 的 id/seq 匹配。

use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use termcolor::StandardStream;

use super::{Hop, PingConfig, TraceSocket};
use crate::util;

/// ICMP echo 探测器：实现 `TraceSocket`，供 `trace_loop` 调用。
struct IcmpSocket {
    sock: socket2::Socket,
    target_sa: socket2::SockAddr,
    target_ip: IpAddr,
    ident: u16,
    seq_counter: u16,
}

impl TraceSocket for IcmpSocket {
    fn send_probes(&mut self, _hop_no: u32) -> Vec<(u16, Instant)> {
        let mut probes = Vec::with_capacity(super::PROBES_PER_HOP);
        for _ in 0..super::PROBES_PER_HOP {
            let seq = self.seq_counter;
            self.seq_counter = self.seq_counter.wrapping_add(1);
            let pkt = if self.target_ip.is_ipv4() {
                crate::ping::icmp::build_v4(self.ident, seq, 32)
            } else {
                crate::ping::icmp::build_v6(self.ident, seq, 32)
            };
            let sent = Instant::now();
            if self.sock.send_to(&pkt, &self.target_sa).is_ok() {
                probes.push((seq, sent));
            }
        }
        probes
    }

    fn parse_reply(&self, data: &[u8], want: &[u16]) -> Option<(u16, bool)> {
        if self.target_ip.is_ipv6() {
            parse_reply_v6(data, self.target_ip, self.ident, want)
        } else {
            parse_reply_v4(data, self.target_ip, self.ident, want)
        }
    }

    fn set_recv_timeout(&self, timeout: Duration) -> anyhow::Result<()> {
        self.sock.set_read_timeout(Some(timeout))?;
        Ok(())
    }

    fn recv_from(
        &self,
        buf: &mut [MaybeUninit<u8>],
    ) -> std::io::Result<(usize, socket2::SockAddr)> {
        self.sock.recv_from(buf)
    }

    fn dump_label(&self) -> &str {
        if self.target_ip.is_ipv6() {
            "icmp-v6"
        } else {
            "icmp-v4"
        }
    }

    fn ttl_socket(&self) -> &socket2::Socket {
        &self.sock
    }

    fn is_ipv6(&self) -> bool {
        self.target_ip.is_ipv6()
    }
}

/// ICMP echo 逐跳：raw ICMP socket 收发，回复按内嵌 ICMP 的 id/seq 匹配。
pub(crate) fn trace_icmp(
    cfg: &PingConfig,
    target_ip: IpAddr,
    max_hops: u32,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    let (sock, target_sa) = crate::util::create_icmp_socket(target_ip, cfg.source)?;
    let ident = crate::util::rand_u16();
    let mut socket = IcmpSocket {
        sock,
        target_sa,
        target_ip,
        ident,
        seq_counter: 0,
    };
    super::trace_loop(cfg, max_hops, &mut socket, w)
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
    let ihl = util::ipv4_ihl(buf);
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
            let inner_ihl = util::ipv4_ihl(body);
            // 内嵌 dst（偏移 16..20）
            let inner_dst = IpAddr::V4(std::net::Ipv4Addr::new(
                body[16], body[17], body[18], body[19],
            ));
            if inner_dst != target {
                return None;
            }
            // 内嵌 ICMP 头完整（≥8B）时按 id/seq 精确归属；截断（不少路由只引
            // 用 IP 头前 8 字节）时按 dst == 目标归属首个探测——与 v6 路径一致。
            let Some(eicmp) = body.get(inner_ihl..)?.get(..8) else {
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
    let icmp = util::ipv6_frame_skip(buf);
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
