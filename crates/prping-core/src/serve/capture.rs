//! 服务端 verbose 完整帧抓包：普通 socket 只能看到载荷（TCP 流 / UDP 数据报），
//! eth/IP/TCP 头（含握手 SYN/SYN-ACK/ACK）在内核里被剥掉，要显示完整帧必须
//! raw 抓包。
//!
//! - **Linux**：AF_PACKET raw socket（`ETH_P_ALL`，全接口，需 root/cap_net_raw），
//!   按 `sll_pkttype == PACKET_HOST` 只收本机入向帧（服务端自己的出向回包
//!   PACKET_OUTGOING 天然不显示）。
//! - **Windows**：Npcap（复用 `rawpcap.rs` 的设备枚举与抓包句柄）；通配绑定开
//!   全部设备（多网卡机器不漏抓），指定绑定开拥有该 IP 的设备。
//! - **macOS**：libpcap（系统自带，底层 BPF /dev/bpf*）；lo0 为 DLT_NULL 裸 IP，
//!   网卡为完整 eth 帧，两条路径都反解。
//!
//! 抓包线程只打印**本服务收到的包**：目的端口 == 监听端口，且目的 IP 为本机地址
//! （通配绑定 0.0.0.0/:: 时用 getifaddrs / GetAdaptersAddresses 枚举本机全部 IP）。
//! v1 的 sport/dport 任一命中会把别的主机发往本机临时端口的包（如
//! `ping 别机:1234` 的 SYN-ACK）也当成本服务流量打印，v2 起不再打印。
//! 命中帧 `packet_dsl::dissect` 全栈反解（eth → ipv4/ipv6 → tcp/udp → 应用层规则
//! 分派）后打印。

use std::net::SocketAddr;

// IP 地址类型仅帧解析辅助使用（Linux/Windows/macOS 抓包路径 + 测试）
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 抓包启动结果。
pub(crate) enum CaptureStatus {
    /// 抓包已启动（实际抓包的设备名列表，供启动行显示）：serve 以帧级显示。
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "windows", target_os = "macos")),
        allow(dead_code)
    )]
    Active(Vec<String>),
    /// 不可用（原因）：serve 打印提示并回退载荷级 dissect。
    Unavailable(String),
}

/// 尝试启动服务端完整帧抓包线程。
pub(crate) fn spawn(addr: SocketAddr) -> CaptureStatus {
    #[cfg(target_os = "linux")]
    {
        spawn_linux(addr)
    }
    #[cfg(target_os = "windows")]
    {
        return spawn_windows(addr);
    }
    #[cfg(target_os = "macos")]
    {
        spawn_macos(addr)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = addr;
        CaptureStatus::Unavailable(rust_i18n::t!("server.capture_unsupported").to_string())
    }
}

/// 帧头部摘要（供 `[frame]` 行显示）。
///
/// 仅 Linux/Windows/macOS 抓包路径使用；其他平台不编译抓包循环，共享辅助只在
/// `test` 下保留（与 rawpcap 的 `#[cfg(any(windows, test))]` 模式一致）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
struct FrameMeta {
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
    proto: &'static str,
}

/// 从完整以太网帧提取 (src, sport, dst, dport, 传输协议)：eth → ipv4/ipv6 →
/// tcp/udp。非 IP / 非 TCP/UDP / 非首片分片 → None。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn frame_meta(frame: &[u8]) -> Option<FrameMeta> {
    if frame.len() < 14 {
        return None;
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0800 => ip_meta(&frame[14..], false),
        0x86DD => ip_meta(&frame[14..], true),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn ip_meta(ip: &[u8], v6: bool) -> Option<FrameMeta> {
    if v6 {
        if ip.len() < 40 || (ip[0] >> 4) != 6 {
            return None;
        }
        let next = ip[6];
        if !matches!(next, 6 | 17) {
            return None; // 扩展头（逐跳/路由/分片等）暂不追跳
        }
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?);
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?);
        let (sport, dport) = ports(&ip[40..])?;
        Some(FrameMeta {
            src: src.into(),
            sport,
            dst: dst.into(),
            dport,
            proto: if next == 6 { "TCP" } else { "UDP" },
        })
    } else {
        if ip.len() < 20 || (ip[0] >> 4) != 4 {
            return None;
        }
        let ihl = ((ip[0] & 0x0F) as usize) * 4;
        if ip.len() < ihl + 4 {
            return None;
        }
        // 非首片分片（offset>0）无端口，跳过
        let offset = (((ip[6] & 0x1F) as u16) << 8) | ip[7] as u16;
        if offset > 0 {
            return None;
        }
        let proto = ip[9];
        if !matches!(proto, 6 | 17) {
            return None;
        }
        let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
        let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
        let (sport, dport) = ports(&ip[ihl..])?;
        Some(FrameMeta {
            src: src.into(),
            sport,
            dst: dst.into(),
            dport,
            proto: if proto == 6 { "TCP" } else { "UDP" },
        })
    }
}

/// 传输层端口（tcp/udp 头前 4 字节）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn ports(p: &[u8]) -> Option<(u16, u16)> {
    if p.len() < 4 {
        return None;
    }
    Some((
        u16::from_be_bytes([p[0], p[1]]),
        u16::from_be_bytes([p[2], p[3]]),
    ))
}

/// 「只打印本服务收到的包」过滤器：目的端口 == 监听端口，且目的 IP 为本机地址。
///
/// 普通 socket 只会收到发给本服务监听地址的包，而 raw 抓包能看到网卡上的一切；
/// 若只按端口过滤（v1 的 sport/dport 任一命中），会把别的主机发往本机临时端口的
/// 包（比如 `ping 别机:1234` 时回给本机的 SYN-ACK）也打印出来——那不是本服务收
/// 到的包。v2 改为按「目的端口 + 目的 IP 本机」精确匹配。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq)]
struct ServiceFilter {
    port: u16,
    /// 允许的目的 IP；`None` = 任意（本机地址枚举失败时的兜底，仅剩端口条件）。
    dsts: Option<Vec<IpAddr>>,
}

impl ServiceFilter {
    /// 按监听地址构造：通配绑定（0.0.0.0/::）→ 枚举本机全部 IP；指定绑定 → 仅该 IP。
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    fn new(addr: SocketAddr) -> Self {
        let dsts = if addr.ip().is_unspecified() {
            local_addresses()
        } else {
            Some(vec![addr.ip()])
        };
        ServiceFilter {
            port: addr.port(),
            dsts,
        }
    }

    /// 完整以太网帧是否为「本服务收到的包」。
    fn matches_frame(&self, frame: &[u8]) -> bool {
        frame_meta(frame).is_some_and(|m| self.matches_meta(&m))
    }

    /// 裸 IP 包（macOS lo0 DLT_NULL 剥掉族头后）是否为「本服务收到的包」。
    #[cfg(any(target_os = "macos", test))]
    fn matches_bare(&self, ip: &[u8]) -> bool {
        bare_ip_meta(ip).is_some_and(|m| self.matches_meta(&m))
    }

    fn matches_meta(&self, m: &FrameMeta) -> bool {
        m.dport == self.port && self.dsts.as_ref().is_none_or(|dsts| dsts.contains(&m.dst))
    }
}

/// 本机全部 IP（IPv4 + IPv6，含回环）：`getifaddrs`。失败 → None（兜底不过滤 IP）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn local_addresses() -> Option<Vec<IpAddr>> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut cur = ifap;
    unsafe {
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                let sa = &*ifa.ifa_addr;
                if sa.sa_family == libc::AF_INET as libc::sa_family_t {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                        sin.sin_addr.s_addr,
                    ))));
                } else if sa.sa_family == libc::AF_INET6 as libc::sa_family_t {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    Some(out)
}

/// 本机全部 IP（IPv4 + IPv6，含回环）：`GetAdaptersAddresses`（XP+，Win7 兼容）。
#[cfg(target_os = "windows")]
fn local_addresses() -> Option<Vec<IpAddr>> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    // 第一遍：只取所需缓冲区大小（返回 ERROR_BUFFER_OVERFLOW）
    let mut size: u32 = 0;
    let rc = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_UNSPEC),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if rc != ERROR_BUFFER_OVERFLOW {
        return None;
    }
    // u64 缓冲保证 8 字节对齐（结构含 u64 字段；Vec<u8> 只对齐 1，直接 cast 会 UB）
    let mut buf = vec![0u64; size.div_ceil(8) as usize];
    let rc = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_UNSPEC),
            0,
            std::ptr::null(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if rc != NO_ERROR {
        return None;
    }
    let mut out = Vec::new();
    unsafe {
        let mut cur = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !cur.is_null() {
            let adapter = &*cur;
            let mut ua = adapter.FirstUnicastAddress;
            while !ua.is_null() {
                let entry = &*ua;
                let sa = entry.Address.lpSockaddr;
                if !sa.is_null() {
                    match (*sa).sa_family {
                        AF_INET => {
                            let sin = sa.cast::<SOCKADDR_IN>();
                            let b = (*sin).sin_addr.S_un.S_un_b;
                            out.push(IpAddr::V4(Ipv4Addr::new(b.s_b1, b.s_b2, b.s_b3, b.s_b4)));
                        }
                        AF_INET6 => {
                            let sin6 = sa.cast::<SOCKADDR_IN6>();
                            out.push(IpAddr::V6(Ipv6Addr::from((*sin6).sin6_addr.u.Byte)));
                        }
                        _ => {}
                    }
                }
                ua = entry.Next;
            }
            cur = adapter.Next;
        }
    }
    Some(out)
}

/// 打印一帧：`[frame] src:port → dst:port PROTO N B` + 全栈 dissect。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn show_frame(frame: &[u8]) {
    use std::io::Write;
    let report = packet_dsl::dissect(frame);
    let mut w = crate::output::stdout();
    let _ = crate::output::print_magenta(&mut w, "[frame] ");
    if let Some(m) = frame_meta(frame) {
        let _ = crate::output::print_cyan(
            &mut w,
            format!("{}:{} → {}:{} ", m.src, m.sport, m.dst, m.dport),
        );
        let _ = crate::output::print_yellow(&mut w, format!("{} ", m.proto));
    }
    let _ = writeln!(&mut w, "{} B", frame.len());
    let _ = crate::engine::eng::render_dissected(&mut w, &report, "  frame:", frame);
}

/// 裸 IP 包（无链路层头，如 macOS lo0 的 DLT_NULL 剥掉 4 字节族头后）→ 帧元数据。
/// 仅 macOS 回环抓包路径使用（Windows Npcap / Linux AF_PACKET 都是完整链路层帧）。
#[cfg(any(target_os = "macos", test))]
fn bare_ip_meta(ip: &[u8]) -> Option<FrameMeta> {
    match ip.first()? >> 4 {
        4 => ip_meta(ip, false),
        6 => ip_meta(ip, true),
        _ => None,
    }
}

/// 打印裸 IP 包（macOS lo0 回环帧；无 eth 层，dissect 走裸 IP 路径）。
/// 仅 macOS 抓包循环调用（无测试引用）。
#[cfg(target_os = "macos")]
fn show_bare_ip(ip: &[u8]) {
    use std::io::Write;
    let report = packet_dsl::dissect(ip);
    let mut w = crate::output::stdout();
    let _ = crate::output::print_magenta(&mut w, "[frame] ");
    if let Some(m) = bare_ip_meta(ip) {
        let _ = crate::output::print_cyan(
            &mut w,
            format!("{}:{} → {}:{} ", m.src, m.sport, m.dst, m.dport),
        );
        let _ = crate::output::print_yellow(&mut w, format!("{} ", m.proto));
    }
    let _ = writeln!(&mut w, "{} B", ip.len());
    let _ = crate::engine::eng::render_dissected(&mut w, &report, "  frame:", ip);
}

// ── Linux：AF_PACKET ──────────────────────────────────────────────────────

/// 打开 AF_PACKET raw socket 并绑定全接口，成功则启动抓包线程。
#[cfg(target_os = "linux")]
fn spawn_linux(addr: SocketAddr) -> CaptureStatus {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            libc::htons(libc::ETH_P_ALL as u16) as libc::c_int,
        )
    };
    if fd < 0 {
        return CaptureStatus::Unavailable(format!(
            "AF_PACKET socket failed (need root/cap_net_raw): {}",
            std::io::Error::last_os_error()
        ));
    }
    // 绑定全接口（sll_ifindex=0）
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = libc::htons(libc::ETH_P_ALL as u16);
    sll.sll_ifindex = 0;
    let rc = unsafe {
        libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let msg = std::io::Error::last_os_error().to_string();
        unsafe { libc::close(fd) };
        return CaptureStatus::Unavailable(format!("AF_PACKET bind failed: {msg}"));
    }
    let filter = ServiceFilter::new(addr);
    match std::thread::Builder::new()
        .name("server-capture".into())
        .spawn(move || linux_loop(fd, filter))
    {
        Ok(_) => CaptureStatus::Active(vec![rust_i18n::t!("server.capture_iface_all").to_string()]),
        Err(e) => {
            unsafe { libc::close(fd) };
            CaptureStatus::Unavailable(e.to_string())
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_loop(fd: libc::c_int, filter: ServiceFilter) {
    let mut buf = vec![0u8; 65536];
    loop {
        if crate::interrupted() {
            break;
        }
        // 200ms 轮询，以便及时响应中断
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, 200) };
        if rc <= 0 {
            continue;
        }
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut slen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut sll as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                &mut slen,
            )
        };
        if n <= 0 {
            continue;
        }
        // 只收本机入向（PACKET_HOST）：服务端自己的出向回包（PACKET_OUTGOING）不显示
        if sll.sll_pkttype != libc::PACKET_HOST {
            continue;
        }
        let frame = &buf[..n as usize];
        if !filter.matches_frame(frame) {
            continue;
        }
        show_frame(frame);
    }
    unsafe { libc::close(fd) };
}

// ── Windows：Npcap ────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn spawn_windows(addr: SocketAddr) -> CaptureStatus {
    use crate::engine::rawpcap;
    let devs = match rawpcap::list_devices() {
        Ok(d) => d,
        Err(e) => return CaptureStatus::Unavailable(e.to_string()),
    };
    // 通配绑定（0.0.0.0/::）→ 开全部设备；指定绑定 → 开拥有该 IP 的设备。
    // 不能只开 `pick_device` 的首个非回环：多网卡 Windows（Hyper-V vEthernet /
    // VPN / WiFi Direct 等虚拟适配器排在真网卡前面）上流量网卡不排第一时会把
    // 本服务收到的帧全部漏掉——Linux AF_PACKET 是全接口、macOS 也是多设备，
    // Windows 必须一致（每个设备一个抓包线程）。
    let wanted = rawpcap::capture_devices(&devs, addr);
    if wanted.is_empty() {
        let list = rawpcap::format_device_list(&devs);
        return CaptureStatus::Unavailable(format!("找不到可用的抓包设备；可用：\n{list}"));
    }
    // 每个设备一个抓包线程；至少一个成功才算 Active（失败原因留到全失败时返回）
    let filter = ServiceFilter::new(addr);
    let mut started: Vec<String> = Vec::new();
    let mut first_err: Option<String> = None;
    for idx in wanted {
        let dev = devs[idx].name.clone();
        match rawpcap::open_capture(&dev) {
            Ok(mut cap) => {
                let filter = filter.clone();
                match std::thread::Builder::new()
                    .name("server-capture".into())
                    .spawn(move || windows_loop(&mut cap, filter))
                {
                    Ok(_) => started.push(dev),
                    Err(e) => {
                        first_err.get_or_insert_with(|| e.to_string());
                    }
                }
            }
            Err(e) => {
                first_err.get_or_insert_with(|| e.to_string());
            }
        }
    }
    if started.is_empty() {
        CaptureStatus::Unavailable(
            first_err.unwrap_or_else(|| rust_i18n::t!("server.capture_iface_all").to_string()),
        )
    } else {
        CaptureStatus::Active(started)
    }
}

#[cfg(target_os = "windows")]
fn windows_loop(cap: &mut pcap::Capture<pcap::Active>, filter: ServiceFilter) {
    loop {
        if crate::interrupted() {
            break;
        }
        match cap.next_packet() {
            Ok(p) => {
                if filter.matches_frame(p.data) {
                    show_frame(p.data);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                // 抓包中断：打印一次原因后退出（连接回显不受影响）
                let mut w = crate::output::stderr();
                let _ = crate::output::writeln_orange(
                    &mut w,
                    format!("{}: {e}", rust_i18n::t!("server.capture_stopped")),
                );
                break;
            }
        }
    }
}

// ── macOS：libpcap（系统自带，底层 BPF /dev/bpf*）─────────────────────────

/// 打开 macOS 抓包句柄：libpcap 设备（系统自带，底层走 BPF）。
///
/// 与 Windows 的 Npcap 路径共用 `pcap::Capture` API；差异在设备枚举/选择
/// （复用 `rawpcap::list_devices` / `pick_device`）与链路类型：
/// - 普通网卡：Ethernet（EN10MB），帧带 14B eth 头（`show_frame` 全栈解析）
/// - lo0 回环：**DLT_NULL**（4 字节族头 + 裸 IP），抓包侧剥掉族头走裸 IP 路径
///
/// 权限：/dev/bpf* 默认 root:wheel 600——需 `sudo` 或 Wireshark 的 ChmodBPF 授权。
#[cfg(target_os = "macos")]
fn spawn_macos(addr: SocketAddr) -> CaptureStatus {
    let devs = match crate::engine::rawpcap::list_devices() {
        Ok(d) => d,
        Err(e) => return CaptureStatus::Unavailable(e.to_string()),
    };
    let iface_all = rust_i18n::t!("server.capture_iface_all").to_string();
    // 目标设备集合（libpcap 一次只能抓一个设备，按需开多个线程）：
    // 通配绑定（0.0.0.0/::）→ 全部设备（回环 + 所有非回环），本地客户端走回环、
    // 远程客户端走网卡，两者都能看到；指定绑定 → 拥有该 IP 的设备
    // （与 Windows 共用 capture_devices，Linux 的 AF_PACKET 是全接口）
    let wanted = crate::engine::rawpcap::capture_devices(&devs, addr);
    if wanted.is_empty() {
        let list = crate::engine::rawpcap::format_device_list(&devs);
        return CaptureStatus::Unavailable(format!("找不到可用的抓包设备；可用：\n{list}"));
    }
    // 每个设备一个抓包线程；至少一个成功才算 Active（失败原因留到全失败时返回）
    let filter = ServiceFilter::new(addr);
    let mut started: Vec<String> = Vec::new();
    let mut first_err: Option<String> = None;
    for idx in wanted {
        let dev = devs[idx].name.clone();
        match open_macos_capture(&dev) {
            Ok(mut cap) => {
                let dlt = cap.get_datalink();
                let filter = filter.clone();
                match std::thread::Builder::new()
                    .name("server-capture".into())
                    .spawn(move || macos_loop(&mut cap, filter, dlt))
                {
                    Ok(_) => started.push(dev),
                    Err(e) => {
                        first_err.get_or_insert_with(|| e.to_string());
                    }
                }
            }
            Err(e) => {
                first_err.get_or_insert_with(|| e.to_string());
            }
        }
    }
    if started.is_empty() {
        CaptureStatus::Unavailable(first_err.unwrap_or_else(|| iface_all.clone()))
    } else {
        CaptureStatus::Active(started)
    }
}

#[cfg(target_os = "macos")]
fn open_macos_capture(dev: &str) -> anyhow::Result<pcap::Capture<pcap::Active>> {
    let cap = pcap::Capture::from_device(dev)
        .map_err(|e| anyhow::anyhow!("打开 pcap 设备 `{dev}` 失败：{e}"))?
        .timeout(100)
        .promisc(true)
        .immediate_mode(true)
        .open()
        .map_err(|e| anyhow::anyhow!("打开 pcap 设备 `{dev}` 失败：{e}"))?;
    Ok(cap)
}

#[cfg(target_os = "macos")]
fn macos_loop(cap: &mut pcap::Capture<pcap::Active>, filter: ServiceFilter, dlt: pcap::Linktype) {
    loop {
        if crate::interrupted() {
            break;
        }
        match cap.next_packet() {
            Ok(p) => {
                // lo0 回环是 DLT_NULL：4 字节族头 + 裸 IP；普通网卡是 Ethernet 帧
                if dlt == pcap::Linktype::NULL || dlt == pcap::Linktype::LOOP {
                    let Some(ip) = strip_null(p.data) else {
                        continue;
                    };
                    if !filter.matches_bare(ip) {
                        continue;
                    }
                    show_bare_ip(ip);
                } else if filter.matches_frame(p.data) {
                    show_frame(p.data);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                // 抓包中断：打印一次原因后退出（连接回显不受影响）
                let mut w = crate::output::stderr();
                let _ = crate::output::writeln_orange(
                    &mut w,
                    format!("{}: {e}", rust_i18n::t!("server.capture_stopped")),
                );
                break;
            }
        }
    }
}

/// 剥 DLT_NULL/LOOP 的 4 字节族头（AF_INET=2 / AF_INET6=30），返回裸 IP 包；
/// 族头非法或不足 → None。族头字节序：DLT_NULL 是主机字节序，DLT_LOOP 是网络
/// 字节序——两种都接受（值都是 2/30，只是字节排列不同）。
#[cfg(target_os = "macos")]
fn strip_null(data: &[u8]) -> Option<&[u8]> {
    let head = data.get(..4)?;
    let le = u32::from_le_bytes(head.try_into().ok()?);
    let be = u32::from_be_bytes(head.try_into().ok()?);
    if (le != 2 && le != 30) && (be != 2 && be != 30) {
        return None;
    }
    Some(&data[4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造 eth + ipv4 + tcp 帧（端口 sport/dport，dst 由参数指定）。
    fn eth_ip4_tcp_to(sport: u16, dport: u16, dst: Ipv4Addr) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xaa; 6]); // dst MAC
        f.extend_from_slice(&[0xbb; 6]); // src MAC
        f.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 头：ihl=5, total=40, proto=6, src=127.0.0.1, dst 由参数指定
        let d = dst.octets();
        f.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 127, 0, 0, 1,
            d[0], d[1], d[2], d[3],
        ]);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&[0; 12]); // seq/ack/off+flags/win/checksum/urg
        f
    }

    /// 构造 eth + ipv4 + tcp 帧（端口 sport/dport，dst=127.0.0.1）。
    fn eth_ip4_tcp(sport: u16, dport: u16) -> Vec<u8> {
        eth_ip4_tcp_to(sport, dport, Ipv4Addr::LOCALHOST)
    }

    #[test]
    fn frame_meta_tcp_v4() {
        let f = eth_ip4_tcp(49320, 80);
        let m = frame_meta(&f).unwrap();
        assert_eq!(m.src, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(m.dst, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(m.sport, 49320);
        assert_eq!(m.dport, 80);
        assert_eq!(m.proto, "TCP");
    }

    #[test]
    fn service_filter_only_received() {
        // 帧：sport=49320 dport=80，dst=127.0.0.1（本机）
        let f = eth_ip4_tcp(49320, 80);
        // 服务监听 80：发往本服务监听端口的包 → 命中
        let sf80 = ServiceFilter {
            port: 80,
            dsts: Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        };
        assert!(sf80.matches_frame(&f));
        // 服务监听 49320：帧只是「从 49320 发出」（对端回包方向），不是本服务收到的 → 不命中
        let sf_ephemeral = ServiceFilter {
            port: 49320,
            dsts: Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        };
        assert!(!sf_ephemeral.matches_frame(&f));
        // 端口不对 → 不命中
        assert!(
            !ServiceFilter {
                port: 443,
                dsts: None
            }
            .matches_frame(&f)
        );
        // dst 不是本机地址（如 `ping 别机:1234` 回给本机临时端口的 SYN-ACK）→ 不命中
        let foreign = eth_ip4_tcp_to(49320, 80, Ipv4Addr::new(192, 168, 1, 99));
        assert!(!sf80.matches_frame(&foreign));
        // dsts=None（本机地址枚举失败兜底）：仅剩端口条件
        assert!(
            ServiceFilter {
                port: 80,
                dsts: None
            }
            .matches_frame(&f)
        );
    }

    #[test]
    fn captured_syn_frame_dissects_full_stack() {
        // 服务端 -v 抓包路径的回归：ensure_proto_registry 加载 eng_lib 后，
        // 完整帧应逐层识别 eth → ipv4 → tcp。此前 Windows 上出现「未能识别
        // 任何层、remaining 74 B」= 注册表为空（eng_lib 路径在构建机缺失），
        // 此测试守住这条链路至少能认出三层。
        crate::engine::eng::ensure_proto_registry();
        // 真实抓包帧：Windows Npcap 捕获的 TCP SYN（.114:45388 → .162:1234，74 B）
        let frame: Vec<u8> = vec![
            0x08, 0x00, 0x27, 0x5e, 0x76, 0xc6, 0x2c, 0xf0, 0x5d, 0xac, 0x20, 0x6a, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x3c, 0x15, 0x93, 0x40, 0x00, 0x40, 0x06, 0x00, 0xc4, 0xc0, 0xa8,
            0x51, 0x72, 0xc0, 0xa8, 0x51, 0xa2, 0xb1, 0x4c, 0x04, 0xd2, 0xa2, 0xf9, 0xe6, 0xfb,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xfa, 0xf0, 0xd9, 0x63, 0x00, 0x00, 0x02, 0x04,
            0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x82, 0x16, 0x8d, 0x18, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x03, 0x03, 0x0a,
        ];
        let report = packet_dsl::dissect(&frame);
        assert!(
            report.remaining.is_empty(),
            "整帧应被逐层消费，剩余 {} B",
            report.remaining.len()
        );
        assert!(
            report
                .layers
                .iter()
                .any(|l| matches!(l, packet_dsl::ir::Layer::Ethernet(_))),
            "应识别 eth 层：{report:?}"
        );
        assert!(
            report
                .layers
                .iter()
                .any(|l| matches!(l, packet_dsl::ir::Layer::Ipv4(_))),
            "应识别 ipv4 层：{report:?}"
        );
        assert!(
            report
                .layers
                .iter()
                .any(|l| matches!(l, packet_dsl::ir::Layer::Tcp(_))),
            "应识别 tcp 层：{report:?}"
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    fn service_filter_new_specific_bind() {
        // 指定绑定：只收该 IP 的包（不枚举本机地址）
        let sf = ServiceFilter::new("127.0.0.1:1234".parse().unwrap());
        assert_eq!(sf.port, 1234);
        assert_eq!(sf.dsts, Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]));
        // 通配绑定：枚举本机地址，getifaddrs 一定含回环 127.0.0.1
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let wild = ServiceFilter::new("0.0.0.0:1234".parse().unwrap());
            assert_eq!(wild.port, 1234);
            assert!(
                wild.dsts
                    .as_ref()
                    .is_some_and(|d| d.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)))
            );
        }
    }

    #[test]
    fn frame_meta_udp_v6() {
        // eth + ipv6（next=17 UDP）+ udp 头
        let mut f = Vec::new();
        f.extend_from_slice(&[0xaa; 6]);
        f.extend_from_slice(&[0xbb; 6]);
        f.extend_from_slice(&[0x86, 0xDD]);
        // IPv6：payload len=8, next=17, src/dst ::1
        f.extend_from_slice(&[
            0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40, //
        ]);
        let mut addr = [0u8; 16];
        addr[15] = 1; // ::1
        f.extend_from_slice(&addr);
        f.extend_from_slice(&addr);
        f.extend_from_slice(&12345u16.to_be_bytes());
        f.extend_from_slice(&53u16.to_be_bytes());
        f.extend_from_slice(&[0; 4]); // len/checksum
        let m = frame_meta(&f).unwrap();
        assert_eq!(m.src, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(m.dst, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(m.sport, 12345);
        assert_eq!(m.dport, 53);
        assert_eq!(m.proto, "UDP");
        // 只匹配「目的端口 == 监听端口」的入向包：53 命中，12345（sport 命中）不命中
        let sf53 = ServiceFilter {
            port: 53,
            dsts: Some(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]),
        };
        assert!(sf53.matches_frame(&f));
        assert!(
            !ServiceFilter {
                port: 12345,
                dsts: Some(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]),
            }
            .matches_frame(&f)
        );
    }

    #[test]
    fn frame_meta_rejects_non_ip_and_frag() {
        // ARP 帧（ethertype 0x0806）→ None
        let mut arp = vec![0u8; 14];
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert!(frame_meta(&arp).is_none());
        // 分片（offset>0）：ipv4 flags+offset 在帧内偏移 14+6/14+7；设 offset=1
        let mut frag = eth_ip4_tcp(100, 200);
        frag[14 + 6] = 0x00;
        frag[14 + 7] = 0x01;
        assert!(frame_meta(&frag).is_none());
        // 太短
        assert!(frame_meta(&[0u8; 4]).is_none());
        // 非 TCP/UDP（proto=1 ICMP）：ipv4 proto 在帧内偏移 14+9
        let mut icmp = eth_ip4_tcp(100, 200);
        icmp[14 + 9] = 1;
        assert!(frame_meta(&icmp).is_none());
    }

    /// 裸 IPv4 + TCP（不带 eth 头；与 eth_ip4_tcp 的 IPv4 头相同）。
    fn bare_ip4_tcp(sport: u16, dport: u16) -> Vec<u8> {
        let mut ip = Vec::new();
        ip.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 127, 0, 0, 1,
            127, 0, 0, 1,
        ]);
        ip.extend_from_slice(&sport.to_be_bytes());
        ip.extend_from_slice(&dport.to_be_bytes());
        ip.extend_from_slice(&[0; 12]);
        ip
    }

    #[test]
    fn bare_ip_meta_and_port_match() {
        let ip = bare_ip4_tcp(12345, 80);
        let m = bare_ip_meta(&ip).unwrap();
        assert_eq!(m.src, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(m.dst, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(m.sport, 12345);
        assert_eq!(m.dport, 80);
        assert_eq!(m.proto, "TCP");
        // 裸 IP 路径同样只匹配「目的端口 == 监听端口」：80 命中，12345/443 不命中
        let sf80 = ServiceFilter {
            port: 80,
            dsts: Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        };
        assert!(sf80.matches_bare(&ip));
        assert!(
            !ServiceFilter {
                port: 12345,
                dsts: Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            }
            .matches_bare(&ip)
        );
        assert!(
            !ServiceFilter {
                port: 443,
                dsts: Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            }
            .matches_bare(&ip)
        );
        // 非 IP（首字节 0x00）→ None
        assert!(bare_ip_meta(&[0x00; 20]).is_none());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn strip_null_header() {
        // DLT_NULL：4 字节族头 AF_INET=2（主机字节序）+ 裸 IPv4
        let mut data = vec![2u8, 0, 0, 0];
        data.extend_from_slice(&bare_ip4_tcp(100, 200));
        let ip = strip_null(&data).unwrap();
        assert_eq!(ip.len(), 36);
        assert_eq!(ip[0] >> 4, 4);
        assert!(
            ServiceFilter {
                port: 200,
                dsts: Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            }
            .matches_bare(ip)
        );
        // AF_INET6 = 30 → 剥掉后是 IPv6
        let mut v6 = vec![30u8, 0, 0, 0];
        v6.extend_from_slice(&[0x60u8; 40]);
        assert!(strip_null(&v6).is_some());
        // 非法族值 → None
        assert!(strip_null(&[0x99, 0, 0, 0, 0x45]).is_none());
        // 不足 4 字节 → None
        assert!(strip_null(&[2, 0]).is_none());
    }
}
