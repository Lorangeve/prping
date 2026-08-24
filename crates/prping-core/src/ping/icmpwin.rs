//! Windows ICMP 探测后端：ICMP.DLL 的 `IcmpSendEcho2` / `Icmp6SendEcho2`。
//!
//! 背景：Windows 的 raw socket（`socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`）从
//! Vista 起需要管理员权限（通常 WSAEACCES 10013），且 **Win7 RTM（SP0，
//! tcpip.sys 6.1.7600）有缺陷**——管理员权限下创建也返回 WSAEINVAL 10022
//! （Win10 正常）。系统 ping.exe 自 XP SP2 起就不用 raw socket，而是走
//! ICMP.DLL 的 `IcmpSendEcho`——不需要管理员、各 Windows 版本可用。本模块
//! 与之一致：Windows 上的 ICMP ping 全部经 ICMP.DLL，raw socket 只留给
//! MTU 探测 / 路由跟踪。
//!
//! xwin SDK 没有 icmp.lib（链接期导入库），且为保持零链接依赖、三 MSVC 目标
//! 通用——运行时 `LoadLibrary("icmp.dll")` + `GetProcAddress` 动态解析函数
//! （与 rawwin.rs 的 ensure_wpcap 同一哲学）。icmp.dll 是系统 DLL，Win7 SP0
//! 起一直存在。
//!
//! 纯逻辑（IP_STATUS 分类 / 应答结构布局）不依赖 Windows，可跨平台单测；
//! FFI 加载与探测仅 `cfg(windows)` 编译。

use crate::ping::icmp::IcmpErr;
use std::ffi::c_void;
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

/// ICMP_ECHO_REPLY 的 Options 部分（ip_option_information，含 TTL）。
#[repr(C)]
pub(crate) struct IpOptionInformation {
    ttl: u8,
    tos: u8,
    flags: u8,
    options_size: u8,
    options_data: *mut c_void,
}

/// ICMP_ECHO_REPLY（v4；指针字段随位数：x86 = 28B，x64 = 40B）。
#[repr(C)]
pub(crate) struct IcmpEchoReply {
    address: u32,
    status: u32,
    round_trip_time: u32,
    data_size: u16,
    reserved: u16,
    data: *mut c_void,
    options: IpOptionInformation,
}

/// SOCKADDR_IN6 最小布局（无指针，两架构同为 28B；sin6_family 主机序）。
#[repr(C)]
pub(crate) struct SockaddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

/// ICMPV6_ECHO_REPLY（x86 = 44B，x64 = 48B；无 TTL 字段 → 显示 0）。
#[repr(C)]
pub(crate) struct Icmpv6EchoReply {
    address: SockaddrIn6,
    status: u32,
    round_trip_time: u32,
    data_size: u16,
    reserved: u16,
    data: *mut c_void,
}

#[cfg(windows)]
mod ffi {
    use super::*;
    use std::sync::OnceLock;

    type CreateFileFn = unsafe extern "system" fn() -> *mut c_void;
    type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;
    type SendEcho2Fn = unsafe extern "system" fn(
        *mut c_void, // IcmpHandle
        *mut c_void, // Event
        *mut c_void, // ApcRoutine
        *mut c_void, // ApcContext
        *const u32,  // DestinationAddress（in_addr.s_addr，网络字节序）
        *const u8,   // RequestData
        u16,         // RequestSize
        *mut u8,     // ReplyBuffer
        u32,         // ReplySize
        u32,         // Timeout
    ) -> u32;
    type SendEcho2V6Fn = unsafe extern "system" fn(
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *const SockaddrIn6, // SourceAddress（可空）
        *const SockaddrIn6, // DestinationAddress
        *const u8,
        u16,
        *mut u8,
        u32,
        u32,
    ) -> u32;
    type ParseRepliesFn = unsafe extern "system" fn(*mut u8, u32) -> u32;

    /// icmp.dll 动态解析的函数集（进程内一次性加载）。
    pub(crate) struct IcmpApi {
        pub(crate) create_file: CreateFileFn,
        pub(crate) create_file6: CreateFileFn,
        pub(crate) send_echo2: SendEcho2Fn,
        pub(crate) send_echo2_6: SendEcho2V6Fn,
        pub(crate) parse_replies: ParseRepliesFn,
        pub(crate) close_handle: CloseHandleFn,
    }

    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const i8) -> *mut c_void;
        pub(crate) fn GetLastError() -> u32;
    }

    static API: OnceLock<Option<IcmpApi>> = OnceLock::new();

    pub(crate) fn api() -> Option<&'static IcmpApi> {
        API.get_or_init(load_api).as_ref()
    }

    fn load_api() -> Option<IcmpApi> {
        const WSTR: [u16; 9] = [
            b'i' as u16,
            b'c' as u16,
            b'm' as u16,
            b'p' as u16,
            b'.' as u16,
            b'd' as u16,
            b'l' as u16,
            b'l' as u16,
            0,
        ];
        // SAFETY: icmp.dll 是系统 DLL（Win7 SP0 起一直存在）；GetProcAddress 只读。
        unsafe {
            let h = LoadLibraryW(WSTR.as_ptr());
            if h.is_null() {
                return None;
            }
            let get = |name: &[u8]| GetProcAddress(h, name.as_ptr().cast());
            // 先取裸指针并检查齐全，再统一转成函数指针（usize/指针 → fn 需经
            // *const c_void 中转；任一符号缺失都视为不可用）
            let create_file = get(b"IcmpCreateFile\0");
            let create_file6 = get(b"Icmp6CreateFile\0");
            let send_echo2 = get(b"IcmpSendEcho2\0");
            let send_echo2_6 = get(b"Icmp6SendEcho2\0");
            let parse_replies = get(b"IcmpParseReplies\0");
            let close_handle = get(b"IcmpCloseHandle\0");
            let all = [
                create_file,
                create_file6,
                send_echo2,
                send_echo2_6,
                parse_replies,
                close_handle,
            ];
            if all.contains(&std::ptr::null_mut()) {
                return None;
            }
            // 指针 → 函数指针：`as` 不允许（E0605）；指针与 fn 指针同为指针宽，
            // transmute 是 libloading 同款做法（目标类型由字段声明推断；外层已是
            // unsafe 块）。
            Some(IcmpApi {
                create_file: std::mem::transmute(create_file),
                create_file6: std::mem::transmute(create_file6),
                send_echo2: std::mem::transmute(send_echo2),
                send_echo2_6: std::mem::transmute(send_echo2_6),
                parse_replies: std::mem::transmute(parse_replies),
                close_handle: std::mem::transmute(close_handle),
            })
        }
    }
}

/// ICMP 会话：持有 icmp.dll 句柄（v4 = IcmpCreateFile / v6 = Icmp6CreateFile）。
///
/// 句柄是不透明值，仅经 icmp.dll 函数使用、Drop 时 IcmpCloseHandle——同一时刻
/// 只有一个探测在用它（drive 循环串行），unblock 闭包里只复制句柄值。
#[cfg(windows)]
pub(crate) struct IcmpSession {
    handle: *mut c_void,
}

// SAFETY: 句柄是 icmp.dll 的不透明 HANDLE；本类型不暴露任何可变共享状态，
// 仅按值传给 API（探测串行 + unblock 闭包复制句柄值），Drop 只关一次。
#[cfg(windows)]
unsafe impl Send for IcmpSession {}
#[cfg(windows)]
unsafe impl Sync for IcmpSession {}

#[cfg(windows)]
impl IcmpSession {
    /// 按目标地址族打开 ICMP 句柄。icmp.dll 加载失败视为致命（系统级异常）。
    pub(crate) fn new(dest: IpAddr) -> anyhow::Result<IcmpSession> {
        let api = ffi::api().ok_or_else(|| anyhow::anyhow!("icmp.dll 加载失败"))?;
        // SAFETY: IcmpCreateFile/Icmp6CreateFile 无参数、返回句柄或 INVALID_HANDLE。
        let handle = unsafe {
            match dest {
                IpAddr::V4(_) => (api.create_file)(),
                IpAddr::V6(_) => (api.create_file6)(),
            }
        };
        if handle.is_null() {
            anyhow::bail!("IcmpCreateFile 失败：{}", std::io::Error::last_os_error());
        }
        Ok(IcmpSession { handle })
    }

    pub(crate) fn handle(&self) -> *mut c_void {
        self.handle
    }
}

#[cfg(windows)]
impl Drop for IcmpSession {
    fn drop(&mut self) {
        if let Some(api) = ffi::api()
            // SAFETY: 句柄仍有效（本 Drop 唯一释放点）。
            && !self.handle.is_null()
        {
            unsafe { (api.close_handle)(self.handle) };
        }
    }
}

/// 一次阻塞探测（调用方放 `smol::unblock`）：成功返回 (rtt, ttl, 应答总字节)。
/// RTT 在 API 调用内测量（网络往返，不含线程调度）。
#[cfg(windows)]
pub(crate) fn probe_once(
    handle: *mut c_void,
    dest: IpAddr,
    payload: &[u8],
    source6: Option<[u8; 16]>,
    timeout: Duration,
) -> Result<(Duration, u8, usize), IcmpErr> {
    let api = ffi::api().expect("会话创建时 icmp.dll 已加载");
    let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
    let t0 = Instant::now();
    let out = match dest {
        IpAddr::V4(v4) => {
            // in_addr.s_addr：网络字节序（x86/x64 为小端主机，取 LE 整数即得）
            let dest = u32::from_le_bytes(v4.octets());
            let reply_size = (std::mem::size_of::<IcmpEchoReply>() + payload.len() + 64) as u32;
            let mut reply = vec![0u8; reply_size as usize];
            // SAFETY: 参数类型与 icmp.dll 约定一致；reply 缓冲足够容纳应答。
            let rc = unsafe {
                (api.send_echo2)(
                    handle,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &dest,
                    payload.as_ptr(),
                    payload.len() as u16,
                    reply.as_mut_ptr(),
                    reply_size,
                    timeout_ms,
                )
            };
            if rc == 0 {
                // SAFETY: GetLastError 线程本地。
                return Err(last_error_to_icmp(unsafe { ffi::GetLastError() }));
            }
            // SAFETY: rc >= 1 时缓冲含至少一个 ICMP_ECHO_REPLY（+数据）。
            let n = unsafe { (api.parse_replies)(reply.as_mut_ptr(), reply_size) };
            if n == 0 {
                return Err(IcmpErr::Timeout);
            }
            // SAFETY: 首个应答结构按 C 布局读取；Vec 堆分配对齐 ≥ 8。
            let r = unsafe { &*(reply.as_ptr() as *const IcmpEchoReply) };
            match classify_status(r.status) {
                Some(e) => Err(e),
                None => Ok((r.options.ttl, 8 + r.data_size as usize)),
            }
        }
        IpAddr::V6(v6) => {
            let dst = SockaddrIn6 {
                family: 23, // AF_INET6
                port: 0,
                flowinfo: 0,
                addr: v6.octets(),
                scope_id: 0,
            };
            let src = source6.map(|addr| SockaddrIn6 {
                family: 23,
                port: 0,
                flowinfo: 0,
                addr,
                scope_id: 0,
            });
            let reply_size = (std::mem::size_of::<Icmpv6EchoReply>() + payload.len() + 64) as u32;
            let mut reply = vec![0u8; reply_size as usize];
            // SAFETY: 同 v4；SourceAddress 可空（None → null）。
            let rc = unsafe {
                (api.send_echo2_6)(
                    handle,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    src.as_ref().map_or(std::ptr::null(), |s| s),
                    &dst,
                    payload.as_ptr(),
                    payload.len() as u16,
                    reply.as_mut_ptr(),
                    reply_size,
                    timeout_ms,
                )
            };
            if rc == 0 {
                return Err(last_error_to_icmp(unsafe { ffi::GetLastError() }));
            }
            let n = unsafe { (api.parse_replies)(reply.as_mut_ptr(), reply_size) };
            if n == 0 {
                return Err(IcmpErr::Timeout);
            }
            let r = unsafe { &*(reply.as_ptr() as *const Icmpv6EchoReply) };
            match classify_status(r.status) {
                // ICMPV6_ECHO_REPLY 无 TTL 字段 → 0（与 Windows raw ICMPv6 收包一致）
                Some(e) => Err(e),
                None => Ok((0, 8 + r.data_size as usize)),
            }
        }
    };
    out.map(|(ttl, size)| (t0.elapsed(), ttl, size))
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

    /// 应答结构布局与 Windows SDK 文档一致（指针字段随位数自动变化）。
    #[test]
    fn reply_layout_sizes() {
        if cfg!(target_pointer_width = "64") {
            assert_eq!(std::mem::size_of::<IcmpEchoReply>(), 40);
            assert_eq!(std::mem::size_of::<Icmpv6EchoReply>(), 48);
        } else {
            assert_eq!(std::mem::size_of::<IcmpEchoReply>(), 28);
            assert_eq!(std::mem::size_of::<Icmpv6EchoReply>(), 44);
        }
        assert_eq!(std::mem::size_of::<SockaddrIn6>(), 28);
        // v4 TTL 字段偏移（options.ttl = 应答结构第 24 字节起）
        assert_eq!(std::mem::offset_of!(IcmpEchoReply, options), 24);
        assert_eq!(std::mem::offset_of!(IpOptionInformation, ttl), 0);
    }
}
