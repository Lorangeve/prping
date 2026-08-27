//! 原始套接字发送：Linux AF_PACKET / IPPROTO_RAW / raw ICMP 收包；Windows / macOS 走 pcap 兼容层（rawpcap.rs）。
//!
//! 忠实拆分自原 `engine/pkg.rs` 的 raw 段：`send_raw_bytes` 分发、
//! `wait_icmp_reply` 应答等待、AF_PACKET / IPPROTO_RAW 平台实现。

use std::net::SocketAddr;

use packet_dsl::ir::PacketSpec;

use super::SendOutcome;
use super::sniffer::SnifferMatcher;

// 以下仅 Linux/IPPROTO_RAW 路径使用（Windows/macOS/Linux+feature=pcap 走 rawpcap）
#[cfg(all(target_os = "linux", not(feature = "pcap")))]
use super::icmp_echo_ids;
#[cfg(target_os = "linux")]
use super::{Reply, match_reply};
#[cfg(not(any(windows, target_os = "macos", feature = "pcap")))]
use packet_dsl::ir::Layer;
#[cfg(not(windows))]
use std::io;
#[cfg(target_os = "linux")]
use std::time::Duration;

pub(crate) fn send_raw_bytes(
    bytes: &[u8],
    pkt: &PacketSpec,
    target: Option<&SocketAddr>,
    iface: Option<&str>,
    wait: Option<f64>,
    sniffer: Option<&SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<SendOutcome> {
    // Windows：Npcap；macOS：系统 libpcap；Linux feature=pcap：系统 libpcap（rawpcap.rs）
    #[cfg(any(windows, target_os = "macos", feature = "pcap"))]
    {
        crate::engine::rawpcap::send_raw_full(bytes, pkt, target, iface, wait, sniffer, sent_report)
    }
    #[cfg(not(any(windows, target_os = "macos", feature = "pcap")))]
    {
        // --wait：先开回包 socket 再发送。回环/近零延迟网络下内核在 send() 内就
        // 同步完成回包往返（loopback xmit 触发 NET_RX softirq，softirq 在
        // local_bh_enable 的进程上下文同步执行：icmp 回显 → 回包生成 → 再次投递），
        // 回包先于 socket 存在即被内核丢弃——发送后才开 socket 永远等不到
        // （与 rawpcap/Npcap 侧「先开抓包句柄再发送」同理）。
        #[cfg(target_os = "linux")]
        let reply_fd = if wait.is_some() && (sniffer.is_some() || icmp_echo_ids(pkt).is_some()) {
            Some(open_raw_icmp4()?)
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let reply_fd: Option<libc::c_int> = None;
        let result = (|| -> anyhow::Result<SendOutcome> {
            let (proto, sent) = match pkt.layers.last() {
                Some(Layer::Ethernet(_)) => ("ETH", send_af_packet(bytes, target, iface)?),
                Some(Layer::Ipv4(_)) => {
                    // 链路层帧可无目标；裸 IPv4 发送需要目标（sendto 路由/目标地址）
                    let t = target.ok_or_else(|| {
                        anyhow::anyhow!("raw IPv4 发送需要目标地址（HOST 或包内 IP 层 dst）")
                    })?;
                    ("IP4", send_raw_ip4(bytes, t)?)
                }
                Some(Layer::Ipv6(_)) => {
                    let t = target.ok_or_else(|| {
                        anyhow::anyhow!("raw IPv6 发送需要目标地址（HOST 或包内 IP 层 dst）")
                    })?;
                    ("IP6", send_raw_ip6(bytes, t)?)
                }
                _ => anyhow::bail!("raw 发送需要最外层为 eth / ipv4 / ipv6 层"),
            };
            let reply = match reply_fd {
                Some(fd) => {
                    let secs = wait.expect("reply_fd 仅在 --wait 时打开");
                    #[cfg(target_os = "linux")]
                    {
                        wait_icmp_reply(fd, pkt, secs, sniffer, sent_report)?
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = (fd, pkt, secs, sniffer, sent_report);
                        None
                    }
                }
                None => None,
            };
            Ok(SendOutcome {
                proto,
                sent,
                received: 0,
                reply,
            })
        })();
        #[cfg(target_os = "linux")]
        if let Some(fd) = reply_fd {
            unsafe { libc::close(fd) };
        }
        result
    }
}

/// raw 模式应答等待：sniffer 存在时按 sniffer 匹配；否则包是 ICMP echo → 等 echo reply
/// （按 id+seq 匹配）。socket 由调用方在**发送前**打开（见 `wait_icmp_reply` 注释）。
#[cfg(target_os = "linux")]
fn open_raw_icmp4() -> anyhow::Result<libc::c_int> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        anyhow::bail!(
            "raw ICMP socket 失败（需要 root/cap_net_raw）：{}",
            io::Error::last_os_error()
        );
    }
    Ok(fd)
}

/// 在已打开的 raw ICMP socket（v4）上等待回包（sniffer / ICMP echo id+seq 匹配）。
///
/// 调用方必须**先打开 socket 再发送**：回环/近零延迟网络下内核在 send() 内就同步
/// 完成回包往返——loopback xmit 触发 NET_RX softirq，softirq 在 local_bh_enable 的
/// 进程上下文同步执行（icmp 回显 → 回包生成 → 再次投递），回包先于 socket 存在即被
/// 内核丢弃，发送后才开 socket 永远等不到（与 rawpcap/Npcap「先开抓包句柄再发送」同理）。
#[cfg(target_os = "linux")]
fn wait_icmp_reply(
    fd: libc::c_int,
    pkt: &PacketSpec,
    secs: f64,
    sniffer: Option<&SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<Option<Reply>> {
    let t0 = std::time::Instant::now();
    let mut buf = [0u8; 65535];
    let deadline = Duration::from_secs_f64(secs);
    let mut rfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline.saturating_sub(t0.elapsed());
        if remaining.is_zero() {
            return Ok(None);
        }
        let rc = unsafe { libc::poll(&mut rfd, 1, remaining.as_millis() as libc::c_int) };
        if rc <= 0 {
            return Ok(None);
        }
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n <= 0 {
            continue;
        }
        let data = buf[..n as usize].to_vec();
        let rtt = t0.elapsed().as_secs_f64() * 1000.0;
        if let Some((bytes, matched)) = match_reply(&data, pkt, sniffer, sent_report)? {
            return Ok(Some(Reply {
                rtt,
                bytes,
                matched,
            }));
        }
    }
}

/// AF_PACKET 原始以太网帧（Linux；默认接口 lo，可用 --iface 指定）。
/// 链路层帧（如 ARP）不需要目标地址——帧内目的 MAC 即投递目标。
#[cfg(target_os = "linux")]
fn send_af_packet(
    bytes: &[u8],
    _target: Option<&SocketAddr>,
    iface: Option<&str>,
) -> anyhow::Result<usize> {
    use libc::{AF_PACKET, ETH_P_ALL, SOCK_RAW, htons, sockaddr, sockaddr_ll};
    use std::mem::size_of;

    if bytes.len() < 14 {
        anyhow::bail!("以太网帧过短（{} 字节）", bytes.len());
    }
    let iface = iface.unwrap_or("lo");
    let c_iface =
        std::ffi::CString::new(iface).map_err(|_| anyhow::anyhow!("接口名含 NUL：`{iface}`"))?;
    let ifindex = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("找不到网络接口 `{iface}`");
    }
    let fd = unsafe { libc::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16) as libc::c_int) };
    if fd < 0 {
        anyhow::bail!(
            "AF_PACKET socket 失败（需要 root/cap_net_raw）：{}",
            io::Error::last_os_error()
        );
    }
    let mut addr: sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = AF_PACKET as u16;
    addr.sll_protocol = htons(ETH_P_ALL as u16);
    addr.sll_ifindex = ifindex as libc::c_int;
    addr.sll_halen = 6;
    addr.sll_addr = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], 0, 0,
    ];
    let n = unsafe {
        libc::sendto(
            fd,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len(),
            0,
            &addr as *const sockaddr_ll as *const sockaddr,
            size_of::<sockaddr_ll>() as libc::socklen_t,
        )
    };
    unsafe { libc::close(fd) };
    if n < 0 {
        anyhow::bail!("AF_PACKET 发送失败：{}", io::Error::last_os_error());
    }
    Ok(n as usize)
}

// macOS 以太网帧现在走 pcap 路径（rawpcap.rs::send_raw_full），
// 不会再走到这个函数——保留兜底报错。
#[cfg(all(not(target_os = "linux"), not(windows), not(target_os = "macos")))]
fn send_af_packet(
    _bytes: &[u8],
    _target: Option<&SocketAddr>,
    _iface: Option<&str>,
) -> anyhow::Result<usize> {
    anyhow::bail!("AF_PACKET（以太网原始帧）仅支持 Linux")
}

/// IPPROTO_RAW + IP_HDRINCL 发送完整 IPv4 包（Unix；Windows/macOS 走 rawpcap）。
#[cfg(not(windows))]
fn send_raw_ip4(bytes: &[u8], target: &SocketAddr) -> anyhow::Result<usize> {
    if bytes.len() < 20 || (bytes[0] >> 4) != 4 {
        anyhow::bail!("包不是合法 IPv4 报文");
    }
    let ip = target.ip();
    let ip4 = match ip {
        std::net::IpAddr::V4(v4) => v4,
        _ => anyhow::bail!("目标不是 IPv4 地址：{ip}"),
    };
    #[cfg(unix)]
    {
        use libc::{AF_INET, IPPROTO_RAW, SOCK_RAW, sockaddr, sockaddr_in};
        use std::mem::size_of;

        let fd = unsafe { libc::socket(AF_INET, SOCK_RAW, IPPROTO_RAW) };
        if fd < 0 {
            anyhow::bail!(
                "raw socket 失败（需要 root/cap_net_raw）：{}",
                io::Error::last_os_error()
            );
        }
        #[cfg(target_os = "linux")]
        unsafe {
            let one: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const libc::c_int as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        let mut addr: sockaddr_in = unsafe { std::mem::zeroed() };
        #[cfg(target_os = "macos")]
        {
            addr.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
        }
        addr.sin_family = AF_INET as _;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from_ne_bytes(ip4.octets());
        let n = unsafe {
            libc::sendto(
                fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                0,
                &addr as *const sockaddr_in as *const sockaddr,
                size_of::<sockaddr_in>() as libc::socklen_t,
            )
        };
        unsafe { libc::close(fd) };
        if n < 0 {
            anyhow::bail!("raw IPv4 发送失败：{}", io::Error::last_os_error());
        }
        Ok(n as usize)
    }
    #[cfg(not(unix))]
    {
        let _ = (bytes, ip4);
        anyhow::bail!("raw 发送仅支持 Unix（Linux 推荐）")
    }
}

/// 原始 IPv6 发送（Linux：AF_INET6 + IPPROTO_RAW + IPV6_HDRINCL；Windows/macOS 走 rawpcap）。
#[cfg(not(windows))]
fn send_raw_ip6(bytes: &[u8], target: &SocketAddr) -> anyhow::Result<usize> {
    if bytes.len() < 40 || (bytes[0] >> 4) != 6 {
        anyhow::bail!("包不是合法 IPv6 报文");
    }
    let ip = target.ip();
    #[cfg(target_os = "linux")]
    {
        let ip6 = match ip {
            std::net::IpAddr::V6(v6) => v6,
            _ => anyhow::bail!("目标不是 IPv6 地址：{ip}"),
        };
        use libc::{AF_INET6, IPPROTO_RAW, SOCK_RAW, sockaddr, sockaddr_in6};
        use std::mem::size_of;

        let fd = unsafe { libc::socket(AF_INET6, SOCK_RAW, IPPROTO_RAW) };
        if fd < 0 {
            anyhow::bail!(
                "raw IPv6 socket 失败（需要 root/cap_net_raw）：{}",
                io::Error::last_os_error()
            );
        }
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_HDRINCL,
                &one as *const libc::c_int as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        let mut addr: sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = AF_INET6 as u16;
        addr.sin6_addr = libc::in6_addr {
            s6_addr: ip6.octets(),
        };
        let n = unsafe {
            libc::sendto(
                fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                0,
                &addr as *const sockaddr_in6 as *const sockaddr,
                size_of::<sockaddr_in6>() as libc::socklen_t,
            )
        };
        unsafe { libc::close(fd) };
        if n < 0 {
            anyhow::bail!("raw IPv6 发送失败：{}", io::Error::last_os_error());
        }
        Ok(n as usize)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (bytes, ip);
        anyhow::bail!("raw IPv6 发送仅支持 Linux")
    }
}
