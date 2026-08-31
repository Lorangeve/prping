//! 反向 DNS 查询（平台特定：Unix libc / Windows ws2_32 getnameinfo）。

use std::net::IpAddr;

/// 后台启动反向 DNS 查询（不阻塞调用方）：返回接收端，查询线程完成时投递结果。
///
/// 调用方在合适时机 `recv_timeout` 取回（trace 用它实现跨跳并行：探测下一跳期间
/// 上一跳的查询在后台跑）。getnameinfo 是阻塞 DNS 查询，线程在后台等 DNS 完成
/// （至多几秒）自然退出。
pub(super) fn spawn_reverse_dns(ip: IpAddr) -> std::sync::mpsc::Receiver<Option<String>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(reverse_dns(ip));
    });
    rx
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
    // NI_NAMEREQD：无 PTR 记录时返回错误而非数字回退串（否则输出地址重复、
    // JSON hostname 恒非 null，与「无 PTR = None」的文档承诺矛盾）
    let rc = unsafe {
        libc::getnameinfo(
            addr,
            addrlen,
            host.as_mut_ptr() as *mut libc::c_char,
            1024,
            serv.as_mut_ptr() as *mut libc::c_char,
            64,
            libc::NI_NAMEREQD,
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
        AF_INET, AF_INET6, NI_NAMEREQD, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, getnameinfo,
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
    // NI_NAMEREQD：无 PTR 记录时返回错误而非数字回退串（与 Unix 路径一致）
    let rc = unsafe {
        getnameinfo(
            addr,
            addrlen,
            host.as_mut_ptr() as *mut u8,
            1024,
            serv.as_mut_ptr() as *mut u8,
            64,
            // windows-sys 0.59 常量是 u32，flags 参数是 i32
            NI_NAMEREQD as i32,
        )
    };
    if rc != 0 {
        return None;
    }
    let name = unsafe { CStr::from_ptr(host.as_ptr() as *const i8) };
    name.to_str().ok().map(|s| s.to_string())
}
