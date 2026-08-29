//! DNS 解析与源地址解析。

use rust_i18n::t;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// 解析 `-s`（--source）参数：IP 地址，或 Linux 网卡名（取该网卡 IPv4 地址）。
pub fn resolve_source(s: &str) -> anyhow::Result<IpAddr> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(ip);
    }
    #[cfg(target_os = "linux")]
    if let Some(ip) = iface_to_ipv4(s)? {
        return Ok(IpAddr::V4(ip));
    }
    anyhow::bail!(
        "无法解析源地址 `{s}`：请用 IP 地址（如 192.168.1.10）；网卡名仅 Linux 支持（取 IPv4 地址）"
    )
}

/// Linux：`ioctl(SIOCGIFADDR)` 取网卡 IPv4 地址；网卡不存在/无 IPv4 → None。
#[cfg(target_os = "linux")]
fn iface_to_ipv4(name: &str) -> std::io::Result<Option<std::net::Ipv4Addr>> {
    use std::mem;
    if name.len() >= libc::IFNAMSIZ {
        return Ok(None);
    }
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    for (i, b) in name.bytes().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    // `as _`：请求码类型随 libc 平台差异（glibc ioctl 取 c_ulong，musl 取 c_int），
    // 由 ioctl 签名推断，避免 musl 下 `as c_ulong` 类型不符（Linux musl 构建修复）。
    let r = unsafe { libc::ioctl(fd, libc::SIOCGIFADDR as _, &mut ifr) };
    unsafe { libc::close(fd) };
    if r < 0 {
        return Ok(None);
    }
    let sin =
        unsafe { &*(&ifr.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in) };
    Ok(Some(std::net::Ipv4Addr::from(u32::from_be(
        sin.sin_addr.s_addr,
    ))))
}

/// 出口接口 MTU（尽力而为）：Linux 用 `IP_MTU` getsockopt（UDP connect 路由探测），
/// 其余平台暂返回 None（MTU 探测的 EMSGSIZE 分支靠二分继续收敛，报告缺 MTU 值）。
pub fn local_mtu_for(target: IpAddr) -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        let bind = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let s = std::net::UdpSocket::bind(bind).ok()?;
        s.connect(SocketAddr::new(target, 0)).ok()?;
        use std::os::fd::AsRawFd;
        let mut mtu: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let (level, opt) = if target.is_ipv4() {
            (libc::IPPROTO_IP, libc::IP_MTU)
        } else {
            (libc::IPPROTO_IPV6, libc::IPV6_MTU)
        };
        let rc = unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                level,
                opt,
                &mut mtu as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        (rc == 0).then_some(mtu as usize)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = target;
        None
    }
}

/// 源绑定用的本地地址（0 端口）；`-s` 未给时按目标族取通配地址。
pub fn local_bind(target_is_v4: bool, source: Option<IpAddr>) -> SocketAddr {
    match source {
        Some(s) => SocketAddr::new(s, 0),
        None if target_is_v4 => "0.0.0.0:0".parse().unwrap(),
        None => "[::]:0".parse().unwrap(),
    }
}

/// 解析主机名，返回全部匹配地址（按系统顺序，v4/v6 可选过滤）。
pub fn resolve_vec(
    host: &str,
    port: u16,
    force_v4: bool,
    force_v6: bool,
) -> anyhow::Result<Vec<SocketAddr>> {
    let raw = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = raw.parse::<IpAddr>() {
        // -4/-6 对 IP 字面量同样生效（此前字面量绕过族过滤被静默忽略）
        if (force_v4 && !ip.is_ipv4()) || (force_v6 && !ip.is_ipv6()) {
            anyhow::bail!(t!("errors.cannot_resolve", host = host));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let host = raw.to_string();
    Ok(smol::block_on(async {
        smol::unblock(move || {
            let mut addrs: Vec<SocketAddr> = (host.as_str(), port).to_socket_addrs()?.collect();
            if force_v4 {
                addrs.retain(|a| a.is_ipv4());
            } else if force_v6 {
                addrs.retain(|a| a.is_ipv6());
            } else {
                // v4 优先（与 eng/mod.rs ensure_dns_resolver 的注释一致）：
                // 双栈主机解析结果常 v6 在前，无 v6 路由时 connect_first 会
                // 每次先等满 5s 超时才回退 v4。稳定排序保留系统内顺序。
                addrs.sort_by_key(|a| a.is_ipv6());
            }
            Ok::<_, std::io::Error>(addrs)
        })
        .await
    })?)
}

/// 解析主机名，返回第一个匹配地址。
pub fn resolve(
    host: &str,
    port: u16,
    force_v4: bool,
    force_v6: bool,
) -> anyhow::Result<SocketAddr> {
    resolve_vec(host, port, force_v4, force_v6)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!(t!("errors.cannot_resolve", host = host)))
}

/// 主机名解析成功后的横幅：仅域名（非 IP 字面量）打印、`--json` 静默。
pub fn print_resolving(host: &str, ip: IpAddr) {
    if crate::stats::json() {
        return;
    }
    let stripped = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if stripped.parse::<IpAddr>().is_err() {
        println!(
            "{}",
            t!("common.resolving", host = host, ip = ip.to_string())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_ip_direct() {
        let a = resolve("127.0.0.1", 80, false, false).unwrap();
        assert_eq!(a.ip().to_string(), "127.0.0.1");
        assert_eq!(a.port(), 80);
    }
    #[test]
    fn test_resolve_ipv6() {
        let a = resolve("::1", 8080, false, false).unwrap();
        assert_eq!(a.ip().to_string(), "::1");
        assert_eq!(a.port(), 8080);
    }
    #[test]
    fn test_resolve_ipv6_brackets() {
        let a = resolve("[::1]", 9999, false, false).unwrap();
        assert_eq!(a.ip().to_string(), "::1");
        assert_eq!(a.port(), 9999);
    }
    #[test]
    fn test_resolve_all_ip_direct() {
        let a = resolve_vec("127.0.0.1", 0, false, false).unwrap();
        assert_eq!(a[0].ip().to_string(), "127.0.0.1");
    }
    #[test]
    fn test_resolve_all_ipv6() {
        let a = resolve_vec("::1", 0, false, false).unwrap();
        assert_eq!(a[0].ip().to_string(), "::1");
    }
    #[test]
    fn test_resolve_invalid_host() {
        let _ = resolve("invalid.host.name.xyzzy", 80, false, false);
    }
}
