//! 服务端 verbose 完整帧抓包：普通 socket 只能看到载荷（TCP 流 / UDP 数据报），
//! eth/IP/TCP 头（含握手 SYN/SYN-ACK/ACK）在内核里被剥掉，要显示完整帧必须
//! raw 抓包。
//!
//! - **Linux**：AF_PACKET raw socket（`ETH_P_ALL`，全接口，需 root/cap_net_raw），
//!   按 `sll_pkttype == PACKET_HOST` 只收本机入向——回环上服务端回包也会以 HOST
//!   回环，完整会话可见且无重复；真实网卡上服务端出向（PACKET_OUTGOING）不显示
//!   （v1 入向聚焦）。
//! - **Windows**：Npcap（复用 `rawpcap.rs` 的设备选择与抓包句柄，`direction(In)`
//!   只收入向）。
//! - **其他平台**（macOS 等）：暂无 raw 抓包实现 → 不可用，`serve` 回退载荷级解析。
//!
//! 抓包线程按监听端口过滤帧（sport/dport 任一命中），命中帧 `packet_dsl::dissect`
//! 全栈反解（eth → ipv4/ipv6 → tcp/udp → 应用层规则分派）后打印。

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

/// 帧是否命中监听端口（src 或 dst 端口任一命中）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn frame_matches_port(frame: &[u8], port: u16) -> bool {
    frame_meta(frame).is_some_and(|m| m.sport == port || m.dport == port)
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
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn bare_ip_meta(ip: &[u8]) -> Option<FrameMeta> {
    match ip.first()? >> 4 {
        4 => ip_meta(ip, false),
        6 => ip_meta(ip, true),
        _ => None,
    }
}

/// 裸 IP 是否命中监听端口。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn bare_ip_matches_port(ip: &[u8], port: u16) -> bool {
    bare_ip_meta(ip).is_some_and(|m| m.sport == port || m.dport == port)
}

/// 打印裸 IP 包（macOS lo0 回环帧；无 eth 层，dissect 走裸 IP 路径）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
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
    let port = addr.port();
    match std::thread::Builder::new()
        .name("server-capture".into())
        .spawn(move || linux_loop(fd, port))
    {
        Ok(_) => CaptureStatus::Active(vec![rust_i18n::t!("server.capture_iface_all").to_string()]),
        Err(e) => {
            unsafe { libc::close(fd) };
            CaptureStatus::Unavailable(e.to_string())
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_loop(fd: libc::c_int, port: u16) {
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
        // 只收本机入向（PACKET_HOST）：回环上服务端回包也以 HOST 回环，完整会话可见
        if sll.sll_pkttype != libc::PACKET_HOST {
            continue;
        }
        let frame = &buf[..n as usize];
        if !frame_matches_port(frame, port) {
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
    let dev = match rawpcap::select_device_name(Some(&addr), None) {
        Ok(d) => d,
        Err(e) => return CaptureStatus::Unavailable(e.to_string()),
    };
    let mut cap = match rawpcap::open_capture(&dev) {
        Ok(c) => c,
        Err(e) => return CaptureStatus::Unavailable(e.to_string()),
    };
    let port = addr.port();
    match std::thread::Builder::new()
        .name("server-capture".into())
        .spawn(move || windows_loop(&mut cap, port))
    {
        Ok(_) => CaptureStatus::Active(vec![dev]),
        Err(e) => CaptureStatus::Unavailable(e.to_string()),
    }
}

#[cfg(target_os = "windows")]
fn windows_loop(cap: &mut pcap::Capture<pcap::Active>, port: u16) {
    loop {
        if crate::interrupted() {
            break;
        }
        match cap.next_packet() {
            Ok(p) => {
                if frame_matches_port(p.data, port) {
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
    // - 回环目标 → 仅回环设备（lo0）
    // - 指定非回环 → 首个非回环
    // - 未指定（0.0.0.0/::，如 `server 0.0.0.0:PORT`）→ lo0 + 首个非回环，
    //   本地客户端走回环、远程客户端走网卡，两者都能看到
    let mut wanted: Vec<usize> = Vec::new();
    let loop_idx = devs.iter().position(|d| d.loopback);
    let lan_idx = devs.iter().position(|d| !d.loopback);
    if addr.ip().is_unspecified() {
        if let Some(i) = loop_idx {
            wanted.push(i);
        }
        if let Some(i) = lan_idx {
            wanted.push(i);
        }
    } else if addr.ip().is_loopback() {
        if let Some(i) = loop_idx {
            wanted.push(i);
        }
    } else if let Some(i) = lan_idx {
        wanted.push(i);
    }
    if wanted.is_empty() {
        let list: Vec<String> = devs.iter().map(|d| d.name.clone()).collect();
        return CaptureStatus::Unavailable(format!(
            "找不到可用的抓包设备；可用：{}",
            list.join(", ")
        ));
    }
    // 每个设备一个抓包线程；至少一个成功才算 Active（失败原因留到全失败时返回）
    let port = addr.port();
    let mut started: Vec<String> = Vec::new();
    let mut first_err: Option<String> = None;
    for idx in wanted {
        let dev = devs[idx].name.clone();
        match open_macos_capture(&dev) {
            Ok(mut cap) => {
                let dlt = cap.get_datalink();
                match std::thread::Builder::new()
                    .name("server-capture".into())
                    .spawn(move || macos_loop(&mut cap, port, dlt))
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
fn macos_loop(cap: &mut pcap::Capture<pcap::Active>, port: u16, dlt: pcap::Linktype) {
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
                    if !bare_ip_matches_port(ip, port) {
                        continue;
                    }
                    show_bare_ip(ip);
                } else if frame_matches_port(p.data, port) {
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

    /// 构造 eth + ipv4 + tcp 帧（端口 sport/dport，flags 任意）。
    fn eth_ip4_tcp(sport: u16, dport: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xaa; 6]); // dst MAC
        f.extend_from_slice(&[0xbb; 6]); // src MAC
        f.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 头：ihl=5, total=40, proto=6, src/dst 127.0.0.1
        f.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 127, 0, 0, 1,
            127, 0, 0, 1,
        ]);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&[0; 12]); // seq/ack/off+flags/win/checksum/urg
        f
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
    fn frame_meta_port_match() {
        let f = eth_ip4_tcp(49320, 80);
        assert!(frame_matches_port(&f, 80)); // dport 命中
        assert!(frame_matches_port(&f, 49320)); // sport 命中
        assert!(!frame_matches_port(&f, 443));
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
        assert!(frame_matches_port(&f, 53));
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
        assert!(bare_ip_matches_port(&ip, 80));
        assert!(bare_ip_matches_port(&ip, 12345));
        assert!(!bare_ip_matches_port(&ip, 443));
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
        assert!(bare_ip_matches_port(ip, 200));
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
