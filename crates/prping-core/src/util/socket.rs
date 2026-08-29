//! Raw socket 基础设施：创建、报错、TTL 设置、IP 头偏移解析。

use std::net::{IpAddr, SocketAddr};

/// 当前平台获取 raw socket / 抓包权限的方式（追加到权限类报错；随平台条件编译）。
pub fn privilege_hint() -> String {
    use rust_i18n::t;
    #[cfg(target_os = "linux")]
    {
        t!("errors.priv_hint_linux").to_string()
    }
    #[cfg(windows)]
    {
        t!("errors.priv_hint_windows").to_string()
    }
    #[cfg(target_os = "macos")]
    {
        t!("errors.priv_hint_macos").to_string()
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        t!("errors.priv_hint_other").to_string()
    }
}

/// raw socket 创建失败的统一报错：文案按平台区分（Windows 的 raw socket 需管理员
/// 且 Win7 RTM 有缺陷；macOS 需 root/ChmodBPF），并追加可操作的权限提示。
pub fn raw_socket_error(e: std::io::Error) -> anyhow::Error {
    use rust_i18n::t;
    let hint = privilege_hint();
    let error = e.to_string();
    #[cfg(windows)]
    {
        anyhow::anyhow!(t!("errors.raw_socket_windows", error = error, hint = hint))
    }
    #[cfg(target_os = "macos")]
    {
        anyhow::anyhow!(t!("errors.raw_socket_macos", error = error, hint = hint))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        anyhow::anyhow!(t!("errors.raw_socket", error = error, hint = hint))
    }
}

/// 创建 raw ICMP socket（v4: IPPROTO_ICMP / v6: IPPROTO_ICMPV6），可选源绑定。
pub fn create_icmp_socket(
    addr: IpAddr,
    source: Option<IpAddr>,
) -> anyhow::Result<(socket2::Socket, socket2::SockAddr)> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    match addr {
        IpAddr::V4(v4) => {
            let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                .map_err(raw_socket_error)?;
            if let Some(src) = source.filter(IpAddr::is_ipv4) {
                sock.bind(&SockAddr::from(SocketAddr::new(src, 0)))?;
            }
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V4(v4), 0))))
        }
        IpAddr::V6(v6) => {
            let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
                .map_err(raw_socket_error)?;
            if let Some(src) = source.filter(IpAddr::is_ipv6) {
                sock.bind(&SockAddr::from(SocketAddr::new(src, 0)))?;
            }
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V6(v6), 0))))
        }
    }
}

/// 创建 raw TCP socket（trace TCP SYN）。
#[cfg(unix)]
pub fn create_tcp_socket(
    addr: IpAddr,
    local: IpAddr,
) -> anyhow::Result<(socket2::Socket, socket2::SockAddr)> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    match addr {
        IpAddr::V4(v4) => {
            let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
                .map_err(raw_socket_error)?;
            sock.bind(&SockAddr::from(SocketAddr::new(local, 0)))?;
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V4(v4), 0))))
        }
        IpAddr::V6(v6) => {
            let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP))
                .map_err(raw_socket_error)?;
            sock.bind(&SockAddr::from(SocketAddr::new(local, 0)))?;
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V6(v6), 0))))
        }
    }
}

/// 创建普通 UDP socket（`trace --udp`）。
pub fn create_udp_socket(
    addr: IpAddr,
    source: Option<IpAddr>,
    sport: u16,
) -> anyhow::Result<socket2::Socket> {
    use socket2::{Domain, Socket, Type};
    let sock = match addr {
        IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::DGRAM, None)?,
        IpAddr::V6(_) => Socket::new(Domain::IPV6, Type::DGRAM, None)?,
    };
    let bind_addr = SocketAddr::new(
        source.unwrap_or(if addr.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        }),
        sport,
    );
    sock.bind(&socket2::SockAddr::from(bind_addr))?;
    Ok(sock)
}

/// 设置 TTL / Hop Limit。
pub fn set_ttl(sock: &socket2::Socket, ttl: u32, is_ipv6: bool) -> anyhow::Result<()> {
    if is_ipv6 {
        sock.set_unicast_hops_v6(ttl)?;
    } else {
        sock.set_ttl_v4(ttl)?;
    }
    Ok(())
}

/// IPv4 raw socket 收包的外层头偏移：Linux/BSD 恒含 IP 头；Windows 不含。
/// 仅 raw ICMP 收包路径用（Windows ping 走 ICMP.DLL，不在此列）。
#[cfg(not(windows))]
pub(crate) fn icmp_offset_v4(buf: &[u8]) -> usize {
    ipv4_ihl(buf)
}

/// 从 IPv4 报文首字节提取 IHL（Internet Header Length，字节数）。
///
/// `buf[0] >> 4 == 4` 确认为 IPv4，IHL = `(buf[0] & 0x0F) * 4`。
/// 非 IPv4 或 buf 过短时返回 0。
pub fn ipv4_ihl(buf: &[u8]) -> usize {
    if !buf.is_empty() && buf[0] >> 4 == 4 {
        ((buf[0] & 0x0F) as usize) * 4
    } else {
        0
    }
}

/// IPv6 帧探测：首字节 version nibble == 6 且含 40B 固定头时，跳过 IPv6 头返回载荷；
/// 否则原样返回（框架探测：Linux raw ICMPv6 不含 IPv6 头，部分平台含）。
pub fn ipv6_frame_skip(buf: &[u8]) -> &[u8] {
    if buf.len() >= 48 && buf[0] >> 4 == 6 {
        &buf[40..]
    } else {
        buf
    }
}

/// 裸 IPv4 应答注入（`packet --wait --raw` 监听应答用）：把完整 IPv4 报文交给
/// 内核 IP 栈路由（回环/局域网均可，无需 MAC 解析——绕开 pcap 链路层注入对
/// EN10MB 的依赖，macOS lo0 裸 IP 应答走此路径）。需 root/cap_net_raw。
/// - Linux：IPPROTO_RAW + IP_HDRINCL **整包**注入（校验和由序列化器算好）；
/// - macOS：不支持 IP_HDRINCL——按报文协议（byte 9）开 raw socket，**只发 IP 载荷**
///   （内核建 IP 头；与 ping 的 raw ICMP 同一模型）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn inject_ip4(bytes: &[u8], dst: std::net::Ipv4Addr) -> std::io::Result<usize> {
    use std::io;
    #[cfg(target_os = "linux")]
    {
        use std::mem::size_of;
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const libc::c_int as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as _;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());
        let n = unsafe {
            libc::sendto(
                fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        if n < 0 { Err(err) } else { Ok(n as usize) }
    }
    #[cfg(target_os = "macos")]
    {
        use std::mem::size_of;
        // 校验是完整 IPv4 报文，剥掉 IP 头只发载荷（内核建 IP 头）
        if bytes.len() < 20 || (bytes[0] >> 4) != 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "裸 IP 注入需要完整 IPv4 报文",
            ));
        }
        let proto = match bytes[9] {
            1 => libc::IPPROTO_ICMP,
            6 => libc::IPPROTO_TCP,
            17 => libc::IPPROTO_UDP,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("macOS 裸 IP 注入暂不支持协议 {other}（支持 ICMP/TCP/UDP）"),
                ));
            }
        };
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_len = size_of::<libc::sockaddr_in>() as u8;
        addr.sin_family = libc::AF_INET as _;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());
        let payload = &bytes[20..];
        let n = unsafe {
            libc::sendto(
                fd,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        if n < 0 { Err(err) } else { Ok(n as usize) }
    }
}

/// 打开 AF_PACKET raw socket 并绑定（`ifindex=0` = 全接口）。
/// 仅 Linux 默认后端（未启用 `pcap` feature）编译；serve 抓包与
/// `packet --listen --raw` 链路层监听共用。
#[cfg(all(target_os = "linux", not(feature = "pcap")))]
pub(crate) fn open_af_packet(ifindex: i32) -> std::io::Result<libc::c_int> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            libc::htons(libc::ETH_P_ALL as u16) as libc::c_int,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = libc::htons(libc::ETH_P_ALL as u16);
    sll.sll_ifindex = ifindex;
    let rc = unsafe {
        libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// 尽力开启 AF_PACKET 混杂模式（逐接口 PACKET_ADD_MEMBERSHIP，需 CAP_NET_ADMIN；
/// 回环跳过）。返回是否至少一个接口成功；全失败时不报错（仍能收到本机地址/
/// 广播/组播帧），调用方自行决定是否提示。
#[cfg(all(target_os = "linux", not(feature = "pcap")))]
pub(crate) fn af_packet_promisc_all(fd: libc::c_int) -> bool {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return false;
    }
    let mut promisc_ok = false;
    unsafe {
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name);
            if name != c"lo" {
                let ifidx = libc::if_nametoindex(ifa.ifa_name);
                if ifidx != 0 {
                    let mreq = libc::packet_mreq {
                        mr_ifindex: ifidx as libc::c_int,
                        mr_type: libc::PACKET_MR_PROMISC as libc::c_ushort,
                        mr_alen: 0,
                        mr_address: [0; 8],
                    };
                    let rc = libc::setsockopt(
                        fd,
                        libc::SOL_PACKET,
                        libc::PACKET_ADD_MEMBERSHIP,
                        &mreq as *const libc::packet_mreq as *const libc::c_void,
                        std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
                    );
                    if rc == 0 {
                        promisc_ok = true;
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    promisc_ok
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_offset_v4_header() {
        let mut b = vec![0u8; 20 + 8];
        b[0] = 0x45;
        assert_eq!(icmp_offset_v4(&b), 20);
        b[0] = 0x46;
        assert_eq!(icmp_offset_v4(&b), 24);
    }

    #[test]
    fn test_icmp_offset_v4_no_header() {
        assert_eq!(icmp_offset_v4(&[11u8, 0, 0, 0]), 0);
        assert_eq!(icmp_offset_v4(&[0u8, 0, 0, 0]), 0);
        assert_eq!(icmp_offset_v4(&[3u8, 3, 0, 0]), 0);
        assert_eq!(icmp_offset_v4(&[]), 0);
    }
}
