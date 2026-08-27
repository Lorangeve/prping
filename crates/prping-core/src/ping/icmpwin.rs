//! Windows ICMP 探测后端：Iphlpapi.dll 的 `IcmpSendEcho2` / `Icmp6SendEcho2`。
//!
//! 背景：Windows 的 raw socket（`socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`）从
//! Vista 起需要管理员权限（通常 WSAEACCES 10013），且 **Win7 RTM（SP0，
//! tcpip.sys 6.1.7600）有缺陷**——管理员权限下创建也返回 WSAEINVAL 10022
//! （Win10 正常）。系统 ping.exe 自 XP SP2 起就不用 raw socket，而是走
//! Iphlpapi.dll 的 `IcmpSendEcho`——不需要管理员、各 Windows 版本可用。本模块
//! 与之一致：Windows 上的 ICMP ping 全部经 Iphlpapi.dll，raw socket 只留给
//! MTU 探测 / 路由跟踪。
//!
//! windows-sys 0.59 的 `Win32_NetworkManagement_IpHelper` feature 提供了完整的
//! ICMP API 声明（`IcmpCreateFile`、`IcmpSendEcho2` 等），全部链接
//! `"iphlpapi.dll"`（非伞状 `windows.lib`），xwin SDK 自带 `Iphlpapi.lib`。

use crate::ping::icmp::IcmpErr;
#[cfg(windows)]
use std::net::IpAddr;
#[cfg(windows)]
use std::time::{Duration, Instant};

// IP_STATUS（iphlpapi.h；IcmpSendEcho2 回填在应答结构 Status 字段）
const IP_SUCCESS: u32 = 0;
const IP_DEST_NET_UNREACH: u32 = 11002;
const IP_DEST_HOST_UNREACH: u32 = 11003;
const IP_DEST_PROT_UNREACH: u32 = 11004;
const IP_DEST_PORT_UNREACH: u32 = 11005;
const IP_REQ_TIMED_OUT: u32 = 11010;
const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;
const IP_TTL_EXPIRED_REASSEM: u32 = 11014;
const IP_BAD_DESTINATION: u32 = 11018;
const IP_DEST_NO_ROUTE: u32 = 11019;
// IcmpSendEcho2 返回 0 时的 GetLastError 超时码
const ERROR_SEM_TIMEOUT: u32 = 121;
const ERROR_IO_PENDING: u32 = 997;

/// 状态码 → 探测失败原因（None = 成功）。纯函数，跨平台单测。
pub(crate) fn classify_status(code: u32) -> Option<IcmpErr> {
    match code {
        IP_SUCCESS => None,
        IP_REQ_TIMED_OUT => Some(IcmpErr::Timeout),
        IP_TTL_EXPIRED_TRANSIT | IP_TTL_EXPIRED_REASSEM => Some(IcmpErr::TtlExceeded),
        IP_DEST_NET_UNREACH | IP_DEST_HOST_UNREACH | IP_DEST_PROT_UNREACH
        | IP_DEST_PORT_UNREACH | IP_BAD_DESTINATION | IP_DEST_NO_ROUTE => {
            Some(IcmpErr::Unreachable)
        }
        _ => Some(IcmpErr::Timeout),
    }
}

#[cfg(windows)]
mod ws {
    use windows_sys::Win32::Foundation::{BOOL, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_OPTION_INFORMATION, Icmp6CreateFile,
        Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile, IcmpParseReplies, IcmpSendEcho2,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};

    use super::IcmpErr;

    /// ICMP 会话：持有 Iphlpapi.dll 句柄。
    ///
    /// 句柄是不透明值，仅经 Iphlpapi.dll 函数使用、Drop 时 IcmpCloseHandle——同一时刻
    /// 只有一个探测在用它（drive 循环串行），unblock 闭包里只复制句柄值。
    pub(crate) struct IcmpSession {
        handle: HANDLE,
    }

    // SAFETY: HANDLE 是不透明值；本类型不暴露任何可变共享状态，
    // 仅按值传给 API（探测串行 + unblock 闭包复制句柄值），Drop 只关一次。
    unsafe impl Send for IcmpSession {}
    unsafe impl Sync for IcmpSession {}

    impl IcmpSession {
        /// 按目标地址族打开 ICMP 句柄。
        pub(crate) fn new(dest: std::net::IpAddr) -> anyhow::Result<IcmpSession> {
            // SAFETY: IcmpCreateFile/Icmp6CreateFile 无参数、返回句柄或 INVALID_HANDLE。
            let handle = unsafe {
                match dest {
                    std::net::IpAddr::V4(_) => IcmpCreateFile(),
                    std::net::IpAddr::V6(_) => Icmp6CreateFile(),
                }
            };
            if handle == INVALID_HANDLE_VALUE {
                anyhow::bail!("IcmpCreateFile 失败：{}", std::io::Error::last_os_error());
            }
            Ok(IcmpSession { handle })
        }

        pub(crate) fn handle(&self) -> HANDLE {
            self.handle
        }
    }

    impl Drop for IcmpSession {
        fn drop(&mut self) {
            if self.handle != INVALID_HANDLE_VALUE {
                // SAFETY: 句柄仍有效（本 Drop 唯一释放点）。
                unsafe { IcmpCloseHandle(self.handle) };
            }
        }
    }

    /// 一次阻塞探测（调用方放 `smol::unblock`）：成功返回 (rtt, ttl, 应答总字节)。
    /// RTT 在 API 调用内测量（网络往返，不含线程调度）。
    pub(crate) fn probe_once(
        handle: HANDLE,
        dest: std::net::IpAddr,
        payload: &[u8],
        source6: Option<[u8; 16]>,
        timeout: std::time::Duration,
    ) -> Result<(std::time::Duration, u8, usize), IcmpErr> {
        use windows_sys::Win32::Foundation::BOOL;

        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        let t0 = std::time::Instant::now();
        let out = match dest {
            std::net::IpAddr::V4(v4) => {
                let dest = u32::from_le_bytes(v4.octets());
                let reply_size =
                    (std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 64) as u32;
                let mut reply = vec![0u8; reply_size as usize];
                // SAFETY: 参数类型与 Iphlpapi.dll 约定一致；reply 缓冲足够容纳应答。
                let rc = unsafe {
                    IcmpSendEcho2(
                        handle,
                        0,                // Event
                        None,             // ApcRoutine
                        std::ptr::null(), // ApcContext
                        dest,             // DestinationAddress
                        payload.as_ptr().cast(),
                        payload.len() as u16,
                        std::ptr::null(), // RequestOptions
                        reply.as_mut_ptr().cast(),
                        reply_size,
                        timeout_ms,
                    )
                };
                if rc == 0 {
                    return Err(super::last_error_to_icmp(
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32,
                    ));
                }
                // SAFETY: rc >= 1 时缓冲含至少一个 ICMP_ECHO_REPLY（+数据）。
                let n = unsafe { IcmpParseReplies(reply.as_mut_ptr().cast(), reply_size) };
                if n == 0 {
                    return Err(IcmpErr::Timeout);
                }
                // SAFETY: 首个应答结构按 C 布局读取；Vec 堆分配对齐 ≥ 8。
                let r = unsafe { &*(reply.as_ptr() as *const ICMP_ECHO_REPLY) };
                match super::classify_status(r.Status) {
                    Some(e) => Err(e),
                    None => Ok((r.Options.Ttl, 8 + r.DataSize as usize)),
                }
            }
            std::net::IpAddr::V6(v6) => {
                let mut dst: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
                dst.sin6_family = AF_INET6;
                dst.sin6_addr.u.Byte = v6.octets();
                let mut src_opt: Option<SOCKADDR_IN6> = source6.map(|addr| {
                    let mut s: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
                    s.sin6_family = AF_INET6;
                    s.sin6_addr.u.Byte = addr;
                    s
                });
                let src_ptr = src_opt
                    .as_ref()
                    .map_or(std::ptr::null(), |s| s as *const SOCKADDR_IN6);
                let reply_size =
                    (std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>() + payload.len() + 64) as u32;
                let mut reply = vec![0u8; reply_size as usize];
                // SAFETY: 同 v4；SourceAddress 可空（None → null）。
                let rc = unsafe {
                    Icmp6SendEcho2(
                        handle,
                        0,
                        None,
                        std::ptr::null(),
                        src_ptr,
                        &dst,
                        payload.as_ptr().cast(),
                        payload.len() as u16,
                        std::ptr::null(),
                        reply.as_mut_ptr().cast(),
                        reply_size,
                        timeout_ms,
                    )
                };
                if rc == 0 {
                    return Err(super::last_error_to_icmp(
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32,
                    ));
                }
                let n = unsafe { IcmpParseReplies(reply.as_mut_ptr().cast(), reply_size) };
                if n == 0 {
                    return Err(IcmpErr::Timeout);
                }
                let r = unsafe { &*(reply.as_ptr() as *const ICMPV6_ECHO_REPLY_LH) };
                match super::classify_status(r.Status) {
                    // ICMPV6_ECHO_REPLY 无 TTL 字段 → 0（与 Windows raw ICMPv6 收包一致）
                    Some(e) => Err(e),
                    None => Ok((0, 8 + r.DataSize as usize)),
                }
            }
        };
        out.map(|(ttl, size)| (t0.elapsed(), ttl, size))
    }
}

#[cfg(windows)]
fn last_error_to_icmp(err: u32) -> IcmpErr {
    match err {
        ERROR_SEM_TIMEOUT | ERROR_IO_PENDING => IcmpErr::Timeout,
        _ => IcmpErr::Timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_success_is_none() {
        assert_eq!(classify_status(IP_SUCCESS), None);
    }

    #[test]
    fn classify_timeout() {
        assert_eq!(classify_status(IP_REQ_TIMED_OUT), Some(IcmpErr::Timeout));
        assert_eq!(classify_status(9999), Some(IcmpErr::Timeout)); // 未知码保守归类
    }

    #[test]
    fn classify_ttl_expired() {
        assert_eq!(
            classify_status(IP_TTL_EXPIRED_TRANSIT),
            Some(IcmpErr::TtlExceeded)
        );
        assert_eq!(
            classify_status(IP_TTL_EXPIRED_REASSEM),
            Some(IcmpErr::TtlExceeded)
        );
    }

    #[test]
    fn classify_unreachable() {
        for code in [
            IP_DEST_NET_UNREACH,
            IP_DEST_HOST_UNREACH,
            IP_DEST_PROT_UNREACH,
            IP_DEST_PORT_UNREACH,
            IP_BAD_DESTINATION,
            IP_DEST_NO_ROUTE,
        ] {
            assert_eq!(
                classify_status(code),
                Some(IcmpErr::Unreachable),
                "code {code}"
            );
        }
    }

    /// windows-sys 官方类型布局与 Windows SDK 文档一致。
    #[cfg(windows)]
    #[test]
    fn reply_layout_sizes() {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_OPTION_INFORMATION,
        };
        if cfg!(target_pointer_width = "64") {
            assert_eq!(std::mem::size_of::<ICMP_ECHO_REPLY>(), 40);
            assert_eq!(std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>(), 48);
        } else {
            assert_eq!(std::mem::size_of::<ICMP_ECHO_REPLY>(), 28);
            assert_eq!(std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>(), 44);
        }
        assert_eq!(std::mem::size_of::<IP_OPTION_INFORMATION>(), 8);
        assert_eq!(std::mem::offset_of!(ICMP_ECHO_REPLY, Options), 24);
        assert_eq!(std::mem::offset_of!(IP_OPTION_INFORMATION, Ttl), 0);
    }
}
