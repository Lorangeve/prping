//! UDP 逐跳探测：普通 UDP socket 发送，raw ICMP socket 收取 Time Exceeded / Port Unreachable。

use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use termcolor::StandardStream;

use super::{Hop, PingConfig, TraceSocket};
use crate::util;

/// UDP 起始端口（经典 Unix traceroute）。
const UDP_START_PORT: u16 = 33434;

/// UDP 探测器：实现 `TraceSocket`，供 `trace_loop` 调用。
struct UdpTraceSocket {
    udp_sock: socket2::Socket,
    icmp_sock: socket2::Socket,
    target_ip: IpAddr,
    port_counter: u16,
}

impl TraceSocket for UdpTraceSocket {
    fn send_probes(&mut self, _hop_no: u32) -> Vec<(u16, Instant)> {
        let mut probes = Vec::with_capacity(super::PROBES_PER_HOP);
        for _ in 0..super::PROBES_PER_HOP {
            let port = self.port_counter;
            self.port_counter = self.port_counter.wrapping_add(1);
            let target = std::net::SocketAddr::new(self.target_ip, port);
            let data = vec![0u8; 32];
            let sent = Instant::now();
            if self
                .udp_sock
                .send_to(&data, &socket2::SockAddr::from(target))
                .is_ok()
            {
                probes.push((port, sent));
            }
        }
        probes
    }

    fn parse_reply(&self, data: &[u8], want: &[u16]) -> Option<(u16, bool)> {
        let port = if self.target_ip.is_ipv6() {
            parse_udp_icmp_v6(data, self.target_ip, want)?
        } else {
            parse_udp_icmp_v4(data, self.target_ip, want)?
        };
        let is_dest = is_port_unreachable(data, self.target_ip);
        Some((port, is_dest))
    }

    fn set_recv_timeout(&self, timeout: Duration) -> anyhow::Result<()> {
        self.icmp_sock.set_read_timeout(Some(timeout))?;
        Ok(())
    }

    fn recv_from(
        &self,
        buf: &mut [MaybeUninit<u8>],
    ) -> std::io::Result<(usize, socket2::SockAddr)> {
        self.icmp_sock.recv_from(buf)
    }

    fn dump_label(&self) -> &str {
        if self.target_ip.is_ipv6() {
            "udp-v6"
        } else {
            "udp-v4"
        }
    }

    fn ttl_socket(&self) -> &socket2::Socket {
        &self.udp_sock
    }

    fn is_ipv6(&self) -> bool {
        self.target_ip.is_ipv6()
    }
}

/// UDP 逐跳：普通 UDP socket 发送，raw ICMP socket 收取 Time Exceeded / Port Unreachable。
pub(crate) fn trace_udp(
    cfg: &PingConfig,
    target_ip: IpAddr,
    max_hops: u32,
    w: &mut StandardStream,
) -> anyhow::Result<(Vec<Hop>, bool)> {
    let udp_sock = crate::util::create_udp_socket(target_ip, cfg.source, 0)?;
    let (icmp_sock, _) = crate::util::create_icmp_socket(target_ip, cfg.source)?;
    let mut socket = UdpTraceSocket {
        udp_sock,
        icmp_sock,
        target_ip,
        port_counter: UDP_START_PORT,
    };
    super::trace_loop(cfg, max_hops, &mut socket, w)
}

/// 解析 IPv4 UDP ICMP 回包（Time Exceeded / Port Unreachable）。
fn parse_udp_icmp_v4(buf: &[u8], target: IpAddr, want: &[u16]) -> Option<u16> {
    if buf.len() < 20 {
        return None;
    }
    let ihl = util::ipv4_ihl(buf);
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
    let inner_ihl = util::ipv4_ihl(body);
    // 内嵌报文须是 IPv4（与 TCP/tcpwin 路径一致）：畸形数据时 ipv4_ihl 返回 0，
    // 会把任意字节当 UDP 头读 dst_port 误配
    if (body[0] >> 4) != 4 {
        return None;
    }
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
    let icmp = util::ipv6_frame_skip(buf);
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
        let icmp = util::ipv6_frame_skip(buf);
        icmp.len() >= 2 && icmp[0] == 1 && icmp[1] == 4
    } else {
        // ICMP type 3 code 3
        let ihl = util::ipv4_ihl(buf);
        if buf.len() < ihl + 2 {
            return false;
        }
        let icmp = &buf[ihl..];
        icmp[0] == 3 && icmp[1] == 3
    }
}
