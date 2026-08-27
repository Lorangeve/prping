//! Raw socket 基础设施：创建、报错、TTL 设置、IP 头偏移解析。

use std::net::{IpAddr, SocketAddr};

/// raw socket 创建失败的统一报错：Windows 文案与 Unix 不同。
pub fn raw_socket_error(e: std::io::Error) -> anyhow::Error {
    use rust_i18n::t;
    if cfg!(windows) {
        anyhow::anyhow!(t!("errors.raw_socket_windows", error = e.to_string()))
    } else {
        anyhow::anyhow!(t!("errors.raw_socket", error = e.to_string()))
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

/// 创建 raw TCP socket（`trace --tcp`）。
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
pub(crate) fn icmp_offset_v4(buf: &[u8]) -> usize {
    if !buf.is_empty() && buf[0] >> 4 == 4 {
        ((buf[0] & 0x0F) as usize) * 4
    } else {
        0
    }
}

#[cfg(test)]
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
