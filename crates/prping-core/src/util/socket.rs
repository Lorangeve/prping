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
