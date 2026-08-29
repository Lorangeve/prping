//! 原始套接字发送：Linux AF_PACKET / IPPROTO_RAW / raw ICMP 收包；Windows / macOS 走 pcap 兼容层（rawpcap.rs）。
//!
//! 忠实拆分自原 `engine/pkg.rs` 的 raw 段：`send_raw_bytes` 分发、
//! `wait_icmp_reply` 应答等待、AF_PACKET / IPPROTO_RAW 平台实现。

use std::net::SocketAddr;

use packet_dsl::ir::PacketSpec;

use rust_i18n::t;

use super::SendOutcome;
use super::sniffer::SnifferMatcher;

// 仅 Linux（非 pcap）与 macOS 的内核 IP 栈/raw ICMP 路径使用（Windows 与 Linux+pcap 走 rawpcap）
#[cfg(any(all(target_os = "linux", not(feature = "pcap")), target_os = "macos"))]
use super::icmp_echo_ids;
#[cfg(any(all(target_os = "linux", not(feature = "pcap")), target_os = "macos"))]
use super::{Reply, match_reply};
#[cfg(any(all(target_os = "linux", not(feature = "pcap")), target_os = "macos"))]
use packet_dsl::ir::Layer;
#[cfg(any(all(target_os = "linux", not(feature = "pcap")), target_os = "macos"))]
use std::io;
#[cfg(any(all(target_os = "linux", not(feature = "pcap")), target_os = "macos"))]
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
    // macOS：裸 IPv4 外层 → 内核 IP 栈 raw socket（util::socket::inject_ip4——剥 IP 头
    // 按协议发载荷、内核建 IP 头，与 ping 的 raw ICMP 同一模型）。回环 lo0 是
    // DLT_NULL 裸 IP，pcap 链路层注入（需 EN10MB）发不了——裸 IP 走内核栈即可；
    // eth 外层仍走 rawpcap 链路层注入。
    #[cfg(target_os = "macos")]
    {
        if let Some(Layer::Ipv4(_)) = pkt.layers.last() {
            let t =
                target.ok_or_else(|| anyhow::anyhow!("{}", t!("engine.raw_ip4_need_target")))?;
            let v4 = match t.ip() {
                std::net::IpAddr::V4(v4) => v4,
                other => anyhow::bail!("{}", t!("engine.raw_ip4_not_v4", ip = other)),
            };
            // --wait：先开 raw ICMP socket 再发送（回包先于 socket 存在会被内核丢弃）
            let reply_fd = if wait.is_some() && (sniffer.is_some() || icmp_echo_ids(pkt).is_some())
            {
                Some(open_raw_icmp4()?)
            } else {
                None
            };
            let sent = crate::util::socket::inject_ip4(bytes, v4)
                .map_err(|e| anyhow::anyhow!("{}", t!("engine.raw_ip4_send_fail", err = e)))?;
            let reply = match reply_fd {
                Some(fd) => {
                    let secs = wait.expect("reply_fd 仅在 --wait 时打开");
                    wait_icmp_reply(fd, pkt, secs, sniffer, sent_report)?
                }
                None => None,
            };
            #[cfg(target_os = "macos")]
            if let Some(fd) = reply_fd {
                unsafe { libc::close(fd) };
            }
            return Ok(SendOutcome {
                proto: "IP4",
                sent,
                received: 0,
                reply,
            });
        }
    }
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
            // 按发包 IP 版本选回包 socket：v6（或 eth 内含 v6）→ AF_INET6 +
            // IPPROTO_ICMPV6（此前恒开 v4 ICMP socket，v6 echo 回包永远收不到、
            // 静默等满超时）；v4 → 原路径
            if reply_is_v6(pkt) {
                Some(open_raw_icmp6()?)
            } else {
                Some(open_raw_icmp4()?)
            }
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

/// 发包最外层 IP 版本（eth 帧向内找第一个 IP 层）：决定 raw `--wait` 的回包 socket。
#[cfg(target_os = "linux")]
fn reply_is_v6(pkt: &PacketSpec) -> bool {
    pkt.layers
        .iter()
        .rev()
        .find_map(|l| match l {
            Layer::Ipv6(_) => Some(true),
            Layer::Ipv4(_) => Some(false),
            _ => None,
        })
        .unwrap_or(false)
}

/// raw 模式应答等待：sniffer 存在时按 sniffer 匹配；否则包是 ICMP echo → 等 echo reply
/// （按 id+seq 匹配）。socket 由调用方在**发送前**打开（见 `wait_icmp_reply` 注释）。
#[cfg(any(all(target_os = "linux", not(feature = "pcap")), target_os = "macos"))]
fn open_raw_icmp4() -> anyhow::Result<libc::c_int> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        anyhow::bail!(
            "{}",
            rust_i18n::t!(
                "errors.raw_icmp_wait",
                hint = crate::util::privilege_hint(),
                error = io::Error::last_os_error().to_string()
            )
        );
    }
    Ok(fd)
}

/// Linux raw ICMPv6 socket（IPv6 包 `--wait` 的回包接收；raw v6 收包不含 IPv6 头，
/// 回包是裸 ICMPv6——匹配见 `wait_icmp_reply` 的 type 129 手工分支）。
#[cfg(target_os = "linux")]
fn open_raw_icmp6() -> anyhow::Result<libc::c_int> {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6) };
    if fd < 0 {
        anyhow::bail!(
            "{}",
            rust_i18n::t!(
                "errors.raw_icmp_wait",
                hint = crate::util::privilege_hint(),
                error = io::Error::last_os_error().to_string()
            )
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
#[cfg(any(all(target_os = "linux", not(feature = "pcap")), target_os = "macos"))]
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
        // Linux raw ICMPv6 收包不含 IPv6 头（裸 ICMPv6）：dissect 无法识别裸
        // ICMPv6，按 type 129 echo reply + id/seq 手工匹配（与 ping/icmp.rs
        // 的无头路径一致）。v4 回包 data[0] 是 IP version nibble，不会误中。
        if sniffer.is_none()
            && data.len() >= 8
            && data[0] == 129
            && let Some((id, seq)) = super::icmp_echo_ids(pkt)
            && id == u16::from_be_bytes([data[4], data[5]])
            && seq == u16::from_be_bytes([data[6], data[7]])
        {
            return Ok(Some(Reply {
                rtt,
                bytes: data.to_vec(),
                matched: None,
            }));
        }
    }
}

/// AF_PACKET 原始以太网帧（Linux；默认接口 lo，可用 --iface 指定）。
/// 链路层帧（如 ARP）不需要目标地址——帧内目的 MAC 即投递目标。
/// 仅 Linux 非 pcap 路径使用（Linux+feature=pcap 走 rawpcap 注入）。
#[cfg(all(target_os = "linux", not(feature = "pcap")))]
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
            "{}",
            rust_i18n::t!(
                "errors.af_packet_socket",
                hint = crate::util::privilege_hint(),
                error = io::Error::last_os_error().to_string()
            )
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

/// IPPROTO_RAW + IP_HDRINCL 发送完整 IPv4 包（仅 Linux 非 pcap 路径经 send_raw_bytes
/// 调用；Windows/macOS/Linux+feature=pcap 走 rawpcap）。
#[cfg(not(any(windows, target_os = "macos", feature = "pcap")))]
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

/// 原始 IPv6 发送（仅 Linux 非 pcap 路径经 send_raw_bytes 调用；
/// Windows/macOS/Linux+feature=pcap 走 rawpcap）。
#[cfg(not(any(windows, target_os = "macos", feature = "pcap")))]
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
