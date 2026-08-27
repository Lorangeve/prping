//! 反向 DNS 查询（平台特定：Unix libc / Windows ws2_32 getnameinfo）。

use std::net::IpAddr;
use std::time::Duration;

/// 反向 DNS 查询（限时）：`-d` 之外每跳一次，超时/无 PTR 返回 None。
///
/// getnameinfo 是阻塞 DNS 查询，放在独立线程跑，主流程用 recv_timeout
/// 限时；超时后线程继续在后台等 DNS 完成（至多几秒）自然退出。
pub(super) fn reverse_dns_timeout(ip: IpAddr, timeout: Duration) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(reverse_dns(ip));
    });
    rx.recv_timeout(timeout).ok().flatten()
}

/// Unix（Linux/macOS/BSD）：libc getnameinfo。
#[cfg(unix)]
fn reverse_dns(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    use std::mem::MaybeUninit;

    let (addr, addrlen) = match ip {
        IpAddr::V4(v4) => {
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as _;
            addr.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
            (
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        IpAddr::V6(v6) => {
            let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            addr.sin6_family = libc::AF_INET6 as _;
            addr.sin6_addr.s6_addr = v6.octets();
            (
                &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    };
    let mut host: [MaybeUninit<u8>; 1024] = [MaybeUninit::uninit(); 1024];
    let mut serv: [MaybeUninit<u8>; 64] = [MaybeUninit::uninit(); 64];
    let rc = unsafe {
        libc::getnameinfo(
            addr,
            addrlen,
            host.as_mut_ptr() as *mut libc::c_char,
            1024,
            serv.as_mut_ptr() as *mut libc::c_char,
            64,
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let name = unsafe { CStr::from_ptr(host.as_ptr() as *const libc::c_char) };
    name.to_str().ok().map(|s| s.to_string())
}

/// Windows：getnameinfo（ws2_32）。
#[cfg(windows)]
fn reverse_dns(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    use std::mem::MaybeUninit;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, getnameinfo,
    };

    let (addr, addrlen) = match ip {
        IpAddr::V4(v4) => {
            let mut addr: SOCKADDR_IN = unsafe { std::mem::zeroed() };
            addr.sin_family = AF_INET;
            addr.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
            (
                &addr as *const _ as *const SOCKADDR,
                std::mem::size_of::<SOCKADDR_IN>() as i32,
            )
        }
        IpAddr::V6(v6) => {
            let mut addr: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
            addr.sin6_family = AF_INET6;
            // windows-sys 的 IN6_ADDR 是 union（字段 `u`），非 libc 的 `s6_addr`
            addr.sin6_addr.u.Byte = v6.octets();
            (
                &addr as *const _ as *const SOCKADDR,
                std::mem::size_of::<SOCKADDR_IN6>() as i32,
            )
        }
    };
    let mut host: [MaybeUninit<u8>; 1024] = [MaybeUninit::uninit(); 1024];
    let mut serv: [MaybeUninit<u8>; 64] = [MaybeUninit::uninit(); 64];
    let rc = unsafe {
        getnameinfo(
            addr,
            addrlen,
            host.as_mut_ptr() as *mut u8,
            1024,
            serv.as_mut_ptr() as *mut u8,
            64,
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let name = unsafe { CStr::from_ptr(host.as_ptr() as *const i8) };
    name.to_str().ok().map(|s| s.to_string())
}
