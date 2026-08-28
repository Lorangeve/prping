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

// ---- Windows ICMP 诊断（排查 IcmpSendEcho2 被安全软件/防火墙拦截等环境问题）----

/// 非预期底层错误只警告一次（无限模式下避免刷屏）；正常超时不打印。
fn unexpected_warn(msg: &str) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "[icmp-win] warning: {msg} — currently treated as timeout; \
             set PRPING_ICMP_DEBUG=1 for per-probe details"
        );
    }
}

/// `PRPING_ICMP_DEBUG=1` 时打印每次 IcmpSendEcho2/Icmp6SendEcho2 探测的底层结果
/// （rc/GetLastError/应答数/Status/RTT）。零开销零输出，与 trace 的
/// `PRPING_TRACE_DUMP=1` 约定一致。
fn icmp_debug(msg: &str) {
    if std::env::var_os("PRPING_ICMP_DEBUG").is_none() {
        return;
    }
    eprintln!("[icmp-win] {msg}");
}

/// rc==0 时的 GetLastError 是否属于「正常超时」（无需警告）。
fn is_timeout_error(code: u32) -> bool {
    matches!(
        code,
        ERROR_SEM_TIMEOUT | ERROR_IO_PENDING | IP_REQ_TIMED_OUT
    )
}

/// 是否属于已分类的已知 IP_STATUS（决定非预期 Status 是否需要警告）。
fn is_known_status(code: u32) -> bool {
    matches!(
        code,
        IP_SUCCESS
            | IP_DEST_NET_UNREACH
            | IP_DEST_HOST_UNREACH
            | IP_DEST_PROT_UNREACH
            | IP_DEST_PORT_UNREACH
            | IP_REQ_TIMED_OUT
            | IP_TTL_EXPIRED_TRANSIT
            | IP_TTL_EXPIRED_REASSEM
            | IP_BAD_DESTINATION
            | IP_DEST_NO_ROUTE
    )
}

/// IP_STATUS 数值 → 名称（`PRPING_ICMP_DEBUG` 诊断输出用）。
fn icmp_status_name(code: u32) -> &'static str {
    match code {
        IP_SUCCESS => "IP_SUCCESS",
        IP_DEST_NET_UNREACH => "IP_DEST_NET_UNREACH",
        IP_DEST_HOST_UNREACH => "IP_DEST_HOST_UNREACH",
        IP_DEST_PROT_UNREACH => "IP_DEST_PROT_UNREACH",
        IP_DEST_PORT_UNREACH => "IP_DEST_PORT_UNREACH",
        IP_REQ_TIMED_OUT => "IP_REQ_TIMED_OUT",
        IP_TTL_EXPIRED_TRANSIT => "IP_TTL_EXPIRED_TRANSIT",
        IP_TTL_EXPIRED_REASSEM => "IP_TTL_EXPIRED_REASSEM",
        IP_BAD_DESTINATION => "IP_BAD_DESTINATION",
        IP_DEST_NO_ROUTE => "IP_DEST_NO_ROUTE",
        _ => "IP_STATUS_UNKNOWN",
    }
}

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
pub(crate) mod ws {
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle,
        IcmpCreateFile, IcmpSendEcho2,
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
        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        let t0 = std::time::Instant::now();
        let out = match dest {
            std::net::IpAddr::V4(v4) => {
                let dest = u32::from_le_bytes(v4.octets());
                let reply_size =
                    (std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 64) as u32;
                let mut reply = vec![0u8; reply_size as usize];
                // SAFETY: 参数类型与 Iphlpapi.dll 约定一致；reply 缓冲足够容纳应答。
                // windows-sys 0.59 的 HANDLE 是 `*mut c_void`：Event 传空指针。
                let rc = unsafe {
                    IcmpSendEcho2(
                        handle,
                        std::ptr::null_mut(), // Event
                        None,                 // ApcRoutine
                        std::ptr::null(),     // ApcContext
                        dest,                 // DestinationAddress
                        payload.as_ptr().cast(),
                        payload.len() as u16,
                        std::ptr::null(), // RequestOptions
                        reply.as_mut_ptr().cast(),
                        reply_size,
                        timeout_ms,
                    )
                };
                if rc == 0 {
                    let err = std::io::Error::last_os_error();
                    let code = err.raw_os_error().unwrap_or(0) as u32;
                    super::icmp_debug(&format!(
                        "IcmpSendEcho2 dest={v4} rc=0 last_error={code} timeout_ms={timeout_ms}"
                    ));
                    if !super::is_timeout_error(code) {
                        super::unexpected_warn(&format!(
                            "IcmpSendEcho2 failed: {err} (GetLastError={code})"
                        ));
                    }
                    return Err(super::last_error_to_icmp(code));
                }
                // rc >= 1：同步单请求直接读首个应答结构（经典 MSDN 用法，
                // `(PICMP_ECHO_REPLY)ReplyBuffer` 直读）。不能拿 IcmpParseReplies
                // 当判据——它对非 IP_SUCCESS 的应答（超时占位 / 错误回复）返回 0，
                // 会把真实 Status 掩成超时（实测 rc=1 而 replies=0 正是"快速失败"的根因）。
                // SAFETY: rc >= 1 保证缓冲开头有完整 ICMP_ECHO_REPLY；Vec 堆分配对齐 ≥ 8。
                let r = unsafe { &*(reply.as_ptr() as *const ICMP_ECHO_REPLY) };
                super::icmp_debug(&format!(
                    "IcmpSendEcho2 dest={v4} rc={rc} status={} ({}) rtt={:.1}ms",
                    r.Status,
                    super::icmp_status_name(r.Status),
                    t0.elapsed().as_secs_f64() * 1000.0
                ));
                match super::classify_status(r.Status) {
                    Some(e) => {
                        if !super::is_known_status(r.Status) {
                            super::unexpected_warn(&format!(
                                "unexpected IcmpSendEcho2 reply Status={}",
                                r.Status
                            ));
                        }
                        Err(e)
                    }
                    None => Ok((r.Options.Ttl, 8 + r.DataSize as usize)),
                }
            }
            std::net::IpAddr::V6(v6) => {
                let mut dst: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
                dst.sin6_family = AF_INET6;
                dst.sin6_addr.u.Byte = v6.octets();
                let src_opt: Option<SOCKADDR_IN6> = source6.map(|addr| {
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
                        std::ptr::null_mut(), // Event
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
                    let err = std::io::Error::last_os_error();
                    let code = err.raw_os_error().unwrap_or(0) as u32;
                    super::icmp_debug(&format!(
                        "Icmp6SendEcho2 dest={v6} rc=0 last_error={code} timeout_ms={timeout_ms}"
                    ));
                    if !super::is_timeout_error(code) {
                        super::unexpected_warn(&format!(
                            "Icmp6SendEcho2 failed: {err} (GetLastError={code})"
                        ));
                    }
                    return Err(super::last_error_to_icmp(code));
                }
                // 同 v4：直接读首个应答结构，不依赖 IcmpParseReplies。
                // SAFETY: rc >= 1 保证缓冲开头有完整 ICMPV6_ECHO_REPLY_LH。
                let r = unsafe { &*(reply.as_ptr() as *const ICMPV6_ECHO_REPLY_LH) };
                super::icmp_debug(&format!(
                    "Icmp6SendEcho2 dest={v6} rc={rc} status={} ({}) rtt={:.1}ms",
                    r.Status,
                    super::icmp_status_name(r.Status),
                    t0.elapsed().as_secs_f64() * 1000.0
                ));
                match super::classify_status(r.Status) {
                    Some(e) => {
                        if !super::is_known_status(r.Status) {
                            super::unexpected_warn(&format!(
                                "unexpected Icmp6SendEcho2 reply Status={}",
                                r.Status
                            ));
                        }
                        Err(e)
                    }
                    // ICMPV6_ECHO_REPLY 无 TTL 字段 → 0（与 Windows raw ICMPv6 收包一致）；
                    // 结构也无 DataSize 字段（仅 Address/Status/RoundTripTime），应答数据
                    // 回显请求载荷 → 总字节 = ICMPv6 头 8 + 载荷长度。
                    None => Ok((0, 8 + payload.len())),
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
    ///
    /// 数值按 windows-sys 0.59 结构体定义推算：
    /// - `IP_OPTION_INFORMATION`：4 标量字节 + 指针（x64 对齐 8 → 16B；x86 → 8B）
    /// - `ICMP_ECHO_REPLY`：16B 定长前缀 + Data 指针 + Options
    /// - `ICMPV6_ECHO_REPLY_LH`：`IPV6_ADDRESS_EX`（sin6_port + sin6_flowinfo +
    ///   sin6_addr[16] + sin6_scope_id = 28B）+ Status + RoundTripTime = 36B（两宽度一致）
    #[cfg(windows)]
    #[test]
    fn reply_layout_sizes() {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_OPTION_INFORMATION,
        };
        if cfg!(target_pointer_width = "64") {
            assert_eq!(std::mem::size_of::<ICMP_ECHO_REPLY>(), 40);
            assert_eq!(std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>(), 36);
            assert_eq!(std::mem::size_of::<IP_OPTION_INFORMATION>(), 16);
            assert_eq!(std::mem::offset_of!(ICMP_ECHO_REPLY, Options), 24);
        } else {
            assert_eq!(std::mem::size_of::<ICMP_ECHO_REPLY>(), 28);
            assert_eq!(std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>(), 36);
            assert_eq!(std::mem::size_of::<IP_OPTION_INFORMATION>(), 8);
            assert_eq!(std::mem::offset_of!(ICMP_ECHO_REPLY, Options), 20);
        }
        assert_eq!(std::mem::offset_of!(IP_OPTION_INFORMATION, Ttl), 0);
    }
}
