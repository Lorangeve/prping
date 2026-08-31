//! 服务端 verbose 完整帧抓包：普通 socket 只能看到载荷（TCP 流 / UDP 数据报），
//! eth/IP/TCP 头（含握手 SYN/SYN-ACK/ACK）在内核里被剥掉，要显示完整帧必须
//! raw 抓包。
//!
//! - **Linux**（默认）：AF_PACKET raw socket（`ETH_P_ALL`，全接口，需
//!   root/cap_net_raw），按 `sll_pkttype == PACKET_HOST` 只收本机入向帧（服务端
//!   自己的出向回包 PACKET_OUTGOING 天然不显示）。
//! - **Linux**（`--features pcap`）：改走与 Windows/macOS 完全一致的 libpcap
//!   多设备路径——按设备列表逐设备开抓包线程，启动行显示真实接口名。
//! - **Windows**：Npcap（复用 `rawpcap.rs` 的设备枚举与抓包句柄）；通配绑定开
//!   全部设备（多网卡机器不漏抓），指定绑定开拥有该 IP 的设备。
//! - **macOS**：libpcap（系统自带，底层 BPF /dev/bpf*）；lo0 为 DLT_NULL 裸 IP，
//!   网卡为完整 eth 帧，两条路径都反解。
//!
//! 抓包线程默认只打印**本服务收到的包**：目的端口 == 监听端口，且目的 IP 为本机地址
//! （通配绑定 0.0.0.0/:: 时用 getifaddrs / GetAdaptersAddresses 枚举本机全部 IP）。
//! v1 的 sport/dport 任一命中会把别的主机发往本机临时端口的包（如
//! `ping 别机:1234` 的 SYN-ACK）也当成本服务流量打印，v2 起不再打印。
//! `-a`/`--capture-all` 全帧模式（`all_frames`）则不做端口/地址过滤，显示网卡上
//! 所有可见帧：ARP、ICMP、广播/组播、其他端口流量，以及本机出向回包
//! （Linux 默认只收 PACKET_HOST 入向；全帧模式放宽，并尽力开启混杂模式
//! PACKET_MR_PROMISC——需 CAP_NET_ADMIN，失败仍能收到本机地址/广播/组播帧）。
//! 命中帧 `packet_dsl::dissect` 全栈反解（eth → ipv4/ipv6 → tcp/udp → 应用层规则
//! 分派）后打印；`[frame]` 摘要行对 ARP/ICMP 等非 TCP-UDP 帧也给出地址级摘要。

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
///
/// `all_frames`（`-a`/`--capture-all`）：不做「目的端口 == 监听端口 + 目的 IP
/// 本机」过滤，显示网卡上所有可见帧（ARP/ICMP/广播/组播/出向回包）。
/// `filter`（`--filter`）：tcpdump 风格子集表达式，仅对全帧模式可见帧求值；
/// 解析失败返回错误（配置错误，不静默回退载荷级 dissect）。所有协议令牌按
/// 注册表（dissect）匹配，注册表为空（eng_lib 未加载）时报错。
pub(crate) fn spawn(
    addr: SocketAddr,
    all_frames: bool,
    filter: Option<&str>,
) -> Result<CaptureStatus, String> {
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        let expr = match filter {
            None => None,
            Some(s) => {
                if packet_dsl::proto_registry().is_empty() {
                    return Err(
                        "proto registry is empty (eng_lib not loaded) — --filter matches                          protocols via the registry/dissect and cannot run without it"
                            .into(),
                    );
                }
                Some(parse_filter(s)?)
            }
        };
        #[cfg(any(target_os = "macos", all(target_os = "linux", feature = "pcap")))]
        {
            // macOS（libpcap/BPF）与 Linux 开 `--features pcap` 时：pcap 多设备
            // 路径——按设备列表逐设备开抓包线程，启动行显示真实接口名（与
            // Windows Npcap 一致）
            Ok(spawn_pcap_devices(
                addr,
                all_frames,
                expr,
                open_pcap_capture,
            ))
        }
        #[cfg(all(target_os = "linux", not(feature = "pcap")))]
        {
            // Linux 默认：AF_PACKET 单 socket 绑全接口（sll_ifindex=0），
            // 启动行显示「全接口」
            Ok(spawn_linux(addr, all_frames, expr))
        }
        #[cfg(target_os = "windows")]
        {
            Ok(spawn_windows(addr, all_frames, expr))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = (addr, all_frames, filter);
        Ok(CaptureStatus::Unavailable(
            rust_i18n::t!("server.capture_unsupported").to_string(),
        ))
    }
}

/// 帧元数据（ServiceFilter 精确匹配用，只读 `dst`/`dport`；`src`/`sport`/`proto`
/// 保留供测试断言解析正确性——摘要显示已改用 `FrameSummary`）。
///
/// 仅 Linux/Windows/macOS 抓包路径使用；其他平台不编译抓包循环，共享辅助只在
/// `test` 下保留（与 rawpcap 的 `#[cfg(any(windows, test))]` 模式一致）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
#[cfg_attr(not(test), allow(dead_code))]
struct FrameMeta {
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
    proto: &'static str,
}

/// 帧摘要（`[frame]` 行显示）。比 `FrameMeta` 宽：ARP 与非 TCP/UDP 的 IP 协议
/// （ICMP/GRE 等）也给出摘要；`FrameMeta` 仍专供 `ServiceFilter` 精确匹配
/// （默认模式），摘要只影响显示。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
#[derive(Debug)]
enum FrameSummary {
    /// IP 传输层（TCP/UDP）：`src:port → dst:port PROTO`
    Transport {
        src: IpAddr,
        sport: u16,
        dst: IpAddr,
        dport: u16,
        proto: &'static str,
    },
    /// IP 非传输层（ICMP/GRE/…）：`src → dst PROTO`（无端口）
    Ip { src: IpAddr, dst: IpAddr, proto: u8 },
    /// ARP（Ethernet/IPv4 定长头）：`ARP request/reply spa → tpa`
    Arp {
        op: &'static str,
        spa: Ipv4Addr,
        tpa: Ipv4Addr,
    },
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

/// 从 IPv4/IPv6 报文提取共享头信息。
///
/// 返回 `(src, dst, proto/next_header, transport_offset, fragment_offset)`：
/// - `transport_offset`：到传输层载荷的偏移（IPv4 = ihl, IPv6 = 40，扩展头不追跳）
/// - `fragment_offset`：IPv4 分片偏移（IPv6 分片扩展头暂不处理，返回 0）。
///
/// 非 IPv4/IPv6 或版本检查失败 → None。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn parse_ip_base(ip: &[u8], v6: bool) -> Option<(IpAddr, IpAddr, u8, usize, u16)> {
    if v6 {
        if ip.len() < 40 || (ip[0] >> 4) != 6 {
            return None;
        }
        let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?));
        let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?));
        // RFC 8200 扩展头链式追跳（有界 8 层）：此前固定 t_offset=40 且 proto
        // 取 ip[6]——带扩展头的包（Hop-by-Hop/Fragment/路由等）被漏判为
        // 「非 TCP/UDP」或端口从扩展头字节误读
        let mut next = ip[6];
        let mut off = 40usize;
        let mut frag_offset = 0u16;
        for _ in 0..8 {
            match next {
                // 逐跳 0 / 路由 43 / 目的 60 / 移动 135 / HIP 139 / SHIM6 140：
                // 长度 = (hdr[1]+1)*8
                0 | 43 | 60 | 135 | 139 | 140 => {
                    if ip.len() < off + 2 {
                        return None;
                    }
                    next = ip[off];
                    off += ((ip[off + 1] as usize) + 1) * 8;
                }
                // 分片 44：定长 8 字节；偏移字段在 off+2（13 位）
                44 => {
                    if ip.len() < off + 8 {
                        return None;
                    }
                    let frag = u16::from_be_bytes([ip[off + 2], ip[off + 3]]);
                    frag_offset = frag & 0x1FFF;
                    next = ip[off];
                    off += 8;
                }
                // AH 51：长度 = (hdr[1]+2)*4
                51 => {
                    if ip.len() < off + 2 {
                        return None;
                    }
                    next = ip[off];
                    off += ((ip[off + 1] as usize) + 2) * 4;
                }
                _ => break,
            }
            if off > ip.len() {
                return None;
            }
        }
        Some((src, dst, next, off, frag_offset))
    } else {
        if ip.len() < 20 || (ip[0] >> 4) != 4 {
            return None;
        }
        let ihl = crate::util::ipv4_ihl(ip);
        // IHL 合法域 [20, 60]（RFC 791，4 位字段单位 4 字节）；并交叉校验
        // total_length >= IHL——畸形帧（IHL<5 或 total 小于头长）不再被当作
        // 有效 IP 头读取端口（此前 IHL=1 时 ports 从偏移 4 误读）
        if !(20..=60).contains(&ihl) {
            return None;
        }
        let total = ip
            .get(2..4)
            .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize);
        if total.is_some_and(|t| t < ihl) {
            return None;
        }
        if ip.len() < ihl + 4 {
            return None;
        }
        let offset = (((ip[6] & 0x1F) as u16) << 8) | ip[7] as u16;
        let proto = ip[9];
        let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
        let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
        Some((src, dst, proto, ihl, offset))
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn ip_meta(ip: &[u8], v6: bool) -> Option<FrameMeta> {
    let (src, dst, proto, t_offset, frag_offset) = parse_ip_base(ip, v6)?;
    if !matches!(proto, 6 | 17) {
        return None;
    }
    if frag_offset > 0 {
        return None; // 非首片分片无端口（IPv4 与 IPv6 Fragment 扩展头）
    }
    let (sport, dport) = ports(&ip[t_offset..])?;
    Some(FrameMeta {
        src,
        sport,
        dst,
        dport,
        proto: if proto == 6 { "TCP" } else { "UDP" },
    })
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

/// 从完整以太网帧提取摘要：eth → ipv4/ipv6 → tcp/udp（带端口）或非传输层协议
/// （仅地址）；ARP（Ethernet/IPv4）单独解析。非 IP / 非 ARP → None。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn frame_summary(frame: &[u8]) -> Option<FrameSummary> {
    if frame.len() < 14 {
        return None;
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0800 => ip_summary(&frame[14..], false),
        0x86DD => ip_summary(&frame[14..], true),
        0x0806 => arp_summary(&frame[14..]),
        _ => None,
    }
}

/// 裸 IP 包摘要：TCP/UDP 带端口；其余协议（ICMP/GRE/…）只给地址（分片非首片
/// 无端口，但地址仍在基本头内）。仅 IPv4/IPv6 基本头，扩展头不追跳。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn ip_summary(ip: &[u8], v6: bool) -> Option<FrameSummary> {
    let (src, dst, proto, t_offset, frag_offset) = parse_ip_base(ip, v6)?;
    if matches!(proto, 6 | 17) {
        // TCP/UDP
        if !v6 && frag_offset > 0 {
            return None; // IPv4 非首片分片无端口
        }
        let (sport, dport) = ports(&ip[t_offset..])?;
        Some(FrameSummary::Transport {
            src,
            sport,
            dst,
            dport,
            proto: if proto == 6 { "TCP" } else { "UDP" },
        })
    } else {
        Some(FrameSummary::Ip { src, dst, proto })
    }
}

/// ARP 帧摘要：仅 Ethernet/IPv4（htype=1, ptype=0x0800, hlen=6, plen=4）的
/// request/reply（28 字节定长头），显示 `spa → tpa`；其余 ARP 形态 → None。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn arp_summary(arp: &[u8]) -> Option<FrameSummary> {
    if arp.len() < 28 {
        return None;
    }
    if u16::from_be_bytes([arp[0], arp[1]]) != 1
        || u16::from_be_bytes([arp[2], arp[3]]) != 0x0800
        || arp[4] != 6
        || arp[5] != 4
    {
        return None;
    }
    let op = match u16::from_be_bytes([arp[6], arp[7]]) {
        1 => "request",
        2 => "reply",
        _ => return None,
    };
    Some(FrameSummary::Arp {
        op,
        spa: Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]),
        tpa: Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]),
    })
}

/// IP 协议号 → 短名（未知协议显示 `proto N`）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn proto_name(p: u8) -> String {
    match p {
        1 => "ICMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        47 => "GRE".into(),
        50 => "ESP".into(),
        51 => "AH".into(),
        58 => "ICMPv6".into(),
        89 => "OSPF".into(),
        132 => "SCTP".into(),
        _ => format!("proto {p}"),
    }
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

    /// 裸 IP 包（DLT_NULL/LOOP 剥掉族头后）是否为「本服务收到的包」。
    #[cfg(any(target_os = "macos", all(target_os = "linux", feature = "pcap"), test))]
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

/// 打印一帧/裸 IP 包：`[frame] <摘要> N B` + 全栈 dissect。
/// `summary_fn` 决定摘要提取方式（以太网帧用 `frame_summary`，裸 IP 用 `bare_ip_summary`）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn show_packet(data: &[u8], summary_fn: impl Fn(&[u8]) -> Option<FrameSummary>) {
    use std::io::Write;
    let report = packet_dsl::dissect(data);
    let mut w = crate::output::stdout();
    let _ = crate::output::print_magenta(&mut w, "[frame] ");
    if let Some(s) = summary_fn(data) {
        print_summary(&mut w, &s);
    }
    let _ = writeln!(&mut w, "{} B", data.len());
    let _ = crate::engine::eng::render_dissected(&mut w, &report, "", data);
}

/// 打印一帧（完整以太网帧）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn show_frame(frame: &[u8]) {
    show_packet(frame, frame_summary);
}

/// 摘要行：`src:sport → dst:dport PROTO` / `src → dst PROTO` / `ARP op spa → tpa`。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn print_summary<W: termcolor::WriteColor>(w: &mut W, s: &FrameSummary) {
    match s {
        FrameSummary::Transport {
            src,
            sport,
            dst,
            dport,
            proto,
        } => {
            let _ = crate::output::print_cyan(w, format!("{src}:{sport} → {dst}:{dport} "));
            let _ = crate::output::print_yellow(w, format!("{proto} "));
        }
        FrameSummary::Ip { src, dst, proto } => {
            let _ = crate::output::print_cyan(w, format!("{src} → {dst} "));
            let _ = crate::output::print_yellow(w, format!("{} ", proto_name(*proto)));
        }
        FrameSummary::Arp { op, spa, tpa } => {
            let _ = crate::output::print_cyan(w, format!("ARP {op} {spa} → {tpa} "));
        }
    }
}

/// 裸 IP 包（无链路层头，如 macOS lo0 的 DLT_NULL 剥掉 4 字节族头后）→ 帧元数据。
/// 仅 macOS 回环抓包路径实际触发（Windows Npcap / Linux AF_PACKET 与 pcap 路径
/// 的普通网卡都是完整链路层帧；Linux 上仅为 pcap_loop 的防御性分支编译）。
#[cfg(any(target_os = "macos", all(target_os = "linux", feature = "pcap"), test))]
fn bare_ip_meta(ip: &[u8]) -> Option<FrameMeta> {
    match ip.first()? >> 4 {
        4 => ip_meta(ip, false),
        6 => ip_meta(ip, true),
        _ => None,
    }
}

/// 裸 IP 包摘要（DLT_NULL/LOOP 回环帧剥掉族头后；无 eth 层，摘要直接走 IP 路径）。
#[cfg(any(target_os = "macos", all(target_os = "linux", feature = "pcap"), test))]
fn bare_ip_summary(ip: &[u8]) -> Option<FrameSummary> {
    match ip.first()? >> 4 {
        4 => ip_summary(ip, false),
        6 => ip_summary(ip, true),
        _ => None,
    }
}

/// 打印裸 IP 包（DLT_NULL/LOOP 回环帧剥掉族头后；无 eth 层，dissect 走裸 IP 路径）。
/// 仅 macOS 回环路径实际触发（Linux lo 是 EN10MB，该分支不会走到）。
#[cfg(any(target_os = "macos", all(target_os = "linux", feature = "pcap")))]
fn show_bare_ip(ip: &[u8]) {
    show_packet(ip, bare_ip_summary);
}

// ── --filter 表达式（tcpdump 风格子集）─────────────────────────────────────

/// `--filter` 表达式：tcpdump 风格子集，对抓包循环解析出的帧摘要（`FrameSummary`）
/// 求值。纯解析/匹配，不依赖平台，三平台共用。
///
/// 语法（关键字不区分大小写）：
/// - 协议：`arp` `icmp` `icmp6`(`icmpv6`) `tcp` `udp` `ip` `ip6`(`ipv6`)
/// - 端口：`port 53`（sport 或 dport 任一）、`src port 53`、`dst port 53`
/// - 地址：`host 1.2.3.4`（src 或 dst）、`src host …`、`dst host …`（ARP 按 spa/tpa）
/// - 协议限定：协议后可直接跟限定符（tcpdump 同款）——`tcp port 53`、`tcp src port 53`、
///   `arp host 1.2.3.4`、`ip6 host ::1`（展开为 `tcp and port 53` 等）
/// - 组合：`and` / `or` / `not` + 括号（`and` 优先于 `or`，`not` 最高）
///
/// 匹配对象是帧摘要；无法识别层（VLAN/未知 ethertype 等）的帧摘要为 None，只有
/// `not` / `or` 组合能匹配上（与 tcpdump 对不匹配帧的默认行为一致）。
///
/// **所有协议令牌都按注册表（dissect）匹配**：内置 7 个（`arp` `icmp` `icmp6`
/// `tcp` `udp` `ip` `ip6`）与 eng_lib 扩展协议走同一条反解管线，注册表是协议识别的
/// 唯一来源。令牌对应反解层名（`Layer`，如 tcp/udp/arp/ipv4/ipv6/http/dns/eth/raw）
/// 或 `ProtoHit` 命中名（eng_lib 里声明了 dissect 分派规则 `#[rule]` 的协议，如
/// `quic_initial`）；`ip`/`ip6` 归一化为层名 `ipv4`/`ipv6`，`icmp6` 需 Icmp 层 +
/// IPv6 层。其他 eng_lib 协议（tls/dhcp/ospf 等）未声明 `#[rule]`，dissect 不会
/// 分派到它们，不能用于过滤——给 eng_lib 协议加上 `#[rule]` 即可获得过滤能力。
/// 需要注册表已加载（serve 自动加载；缺失时报错）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq)]
enum FilterExpr {
    /// 注册表/dissect 协议令牌：按反解层名（`tcp`/`udp`/`arp`/`ipv4`/…）或
    /// `ProtoHit` 命中名（如 `quic_initial`）匹配，需要完整反解（`FrameCtx.dissect`）。
    Dissect(String),
    Port {
        dir: FilterDir,
        n: u16,
    },
    Host {
        dir: FilterDir,
        ip: IpAddr,
    },
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
}

/// 端口/地址的方向限定：`port N`/`host IP` 是 src 或 dst 任一命中。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
#[derive(Debug, Clone, Copy, PartialEq)]
enum FilterDir {
    Any,
    Src,
    Dst,
}

/// 令牌是否为可过滤的 eng_lib/dissect 协议：固定层名（Layer 枚举，内置协议
/// 之外的部分），或注册表里声明了 dissect 分派规则 `#[rule]` 的 kind
/// （如 quic_initial；eng_lib 里 tls/dhcp/ospf 等无规则，dissect 不会分派到它们）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn is_dissect_proto(name: &str) -> bool {
    if matches!(name, "eth" | "ipv4" | "ipv6" | "http" | "dns" | "raw") {
        return true;
    }
    packet_dsl::proto_registry()
        .iter()
        .any(|p| p.rule.is_some() && p.name == name)
}

/// 解析 `--filter` 表达式；失败返回英文错误信息（用户可见）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn parse_filter(s: &str) -> Result<FilterExpr, String> {
    let toks = lex_filter(s)?;
    let mut p = FilterParser { toks: &toks, i: 0 };
    let e = p.parse_or()?;
    if let Some(t) = p.toks.get(p.i) {
        return Err(format!("unexpected token `{t}` after expression"));
    }
    Ok(e)
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    LParen,
    RParen,
}

impl std::fmt::Display for Tok {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tok::Word(w) => write!(f, "{w}"),
            Tok::LParen => write!(f, "("),
            Tok::RParen => write!(f, ")"),
        }
    }
}

/// 词法切分：空白与括号分隔，单词统一小写（关键字不区分大小写）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn lex_filter(s: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' | ')' => {
                if !cur.is_empty() {
                    toks.push(Tok::Word(std::mem::take(&mut cur)));
                }
                toks.push(if c == '(' { Tok::LParen } else { Tok::RParen });
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    toks.push(Tok::Word(std::mem::take(&mut cur)));
                }
            }
            c => cur.push(c.to_ascii_lowercase()),
        }
    }
    if !cur.is_empty() {
        toks.push(Tok::Word(cur));
    }
    if toks.is_empty() {
        return Err("empty filter expression".into());
    }
    Ok(toks)
}

/// 递归下降解析器：`or` < `and` < `not`/括号 < 原语。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
struct FilterParser<'a> {
    toks: &'a [Tok],
    i: usize,
}

impl FilterParser<'_> {
    fn peek(&self) -> Option<&str> {
        match self.toks.get(self.i) {
            Some(Tok::Word(w)) => Some(w),
            Some(Tok::LParen) => Some("("),
            Some(Tok::RParen) => Some(")"),
            None => None,
        }
    }

    fn parse_or(&mut self) -> Result<FilterExpr, String> {
        let mut left = self.parse_and()?;
        while self.peek() == Some("or") {
            self.i += 1;
            let right = self.parse_and()?;
            left = FilterExpr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<FilterExpr, String> {
        let mut left = self.parse_unary()?;
        while self.peek() == Some("and") {
            self.i += 1;
            let right = self.parse_unary()?;
            left = FilterExpr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<FilterExpr, String> {
        if self.peek() == Some("not") {
            self.i += 1;
            Ok(FilterExpr::Not(Box::new(self.parse_unary()?)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<FilterExpr, String> {
        if self.peek() == Some("(") {
            self.i += 1;
            let e = self.parse_or()?;
            if self.peek() != Some(")") {
                return Err("missing closing parenthesis `)`".into());
            }
            self.i += 1;
            return Ok(e);
        }
        self.parse_primitive()
    }

    fn parse_primitive(&mut self) -> Result<FilterExpr, String> {
        let Some(tok) = self.toks.get(self.i) else {
            return Err("unexpected end of filter expression".into());
        };
        let Tok::Word(w) = tok else {
            return Err(format!("unexpected token `{tok}`"));
        };
        match w.as_str() {
            "arp" | "icmp" | "icmp6" | "icmpv6" | "tcp" | "udp" | "ip" | "ip6" | "ipv6" | "eth"
            | "ipv4" | "http" | "dns" | "raw" => {
                // 内置关键字归一化为层名（ip/ip6 → ipv4/ipv6，icmp6 保持特判）；
                // 其余按注册表 kind 原样匹配
                let proto = match w.as_str() {
                    "ip" => "ipv4",
                    "ip6" | "ipv6" => "ipv6",
                    other => other,
                };
                self.i += 1;
                // tcpdump 风格协议限定：`tcp port 53` / `tcp src port 53` / `arp host IP`
                // 展开为 And(Proto, 限定符)（等价于 `tcp and port 53`）
                match self.parse_optional_qualifier()? {
                    None => Ok(FilterExpr::Dissect(proto.to_string())),
                    Some(q) => Ok(FilterExpr::And(
                        Box::new(FilterExpr::Dissect(proto.to_string())),
                        Box::new(q),
                    )),
                }
            }
            "port" => {
                self.i += 1;
                let n = self.expect_port()?;
                Ok(FilterExpr::Port {
                    dir: FilterDir::Any,
                    n,
                })
            }
            "src" | "dst" => {
                let dir = if w == "src" {
                    FilterDir::Src
                } else {
                    FilterDir::Dst
                };
                self.i += 1;
                match self.peek() {
                    Some("port") => {
                        self.i += 1;
                        let n = self.expect_port()?;
                        Ok(FilterExpr::Port { dir, n })
                    }
                    Some("host") => {
                        self.i += 1;
                        let ip = self.expect_host()?;
                        Ok(FilterExpr::Host { dir, ip })
                    }
                    _ => Err(format!("`{w}` must be followed by `port N` or `host IP`")),
                }
            }
            "host" => {
                self.i += 1;
                let ip = self.expect_host()?;
                Ok(FilterExpr::Host {
                    dir: FilterDir::Any,
                    ip,
                })
            }
            other => {
                // eng_lib/dissect 协议：注册表里带 #[rule] 的 kind（层名已在上方覆盖）
                if !is_dissect_proto(other) {
                    return Err(format!(
                        "unknown protocol `{other}` (built-in: arp/icmp/icmp6/tcp/udp/ip/ip6; \
                         layers: eth/ipv4/ipv6/http/dns/raw; or eng_lib protocols with a \
                         dissect #[rule], e.g. dns/http/quic_initial)"
                    ));
                }
                self.i += 1;
                match self.parse_optional_qualifier()? {
                    None => Ok(FilterExpr::Dissect(other.to_string())),
                    Some(q) => Ok(FilterExpr::And(
                        Box::new(FilterExpr::Dissect(other.to_string())),
                        Box::new(q),
                    )),
                }
            }
        }
    }

    /// 协议后的可选限定符：`[src|dst] (port N | host IP)`。无 `src`/`dst` 且后随
    /// 非 port/host 时返回 None（不消费任何令牌）；有方向但缺限定时报错。
    fn parse_optional_qualifier(&mut self) -> Result<Option<FilterExpr>, String> {
        let dir = match self.peek() {
            Some("src") => {
                self.i += 1;
                FilterDir::Src
            }
            Some("dst") => {
                self.i += 1;
                FilterDir::Dst
            }
            _ => FilterDir::Any,
        };
        match self.peek() {
            Some("port") => {
                self.i += 1;
                let n = self.expect_port()?;
                Ok(Some(FilterExpr::Port { dir, n }))
            }
            Some("host") => {
                self.i += 1;
                let ip = self.expect_host()?;
                Ok(Some(FilterExpr::Host { dir, ip }))
            }
            _ if dir != FilterDir::Any => {
                Err("`src`/`dst` must be followed by `port N` or `host IP`".into())
            }
            _ => Ok(None),
        }
    }

    fn expect_port(&mut self) -> Result<u16, String> {
        let Some(Tok::Word(w)) = self.toks.get(self.i) else {
            return Err("expected a port number".into());
        };
        let n: u16 = w.parse().map_err(|_| format!("invalid port `{w}`"))?;
        self.i += 1;
        Ok(n)
    }

    fn expect_host(&mut self) -> Result<IpAddr, String> {
        let Some(Tok::Word(w)) = self.toks.get(self.i) else {
            return Err("expected an IP address".into());
        };
        let ip: IpAddr = w.parse().map_err(|_| format!("invalid IP address `{w}`"))?;
        self.i += 1;
        Ok(ip)
    }
}

impl FilterExpr {
    /// 对反解报告求值；`dissect=None`（无上下文）时只有 `not`/`or` 组合能命中。
    fn matches_ctx(&self, ctx: &FrameCtx) -> bool {
        match self {
            FilterExpr::Dissect(name) => ctx.dissect.is_some_and(|r| match name.as_str() {
                // icmp6 需 Icmp 层 + IPv6 层（IR 的 Icmp 层不分版本，用兄弟层区分）
                "icmp6" => has_layer(r, "icmp") && has_layer(r, "ipv6"),
                "icmp" => has_layer(r, "icmp") && has_layer(r, "ipv4"),
                _ => has_layer(r, name) || r.proto.iter().any(|p| p.name == *name),
            }),
            FilterExpr::Port { dir, n } => {
                ctx.dissect
                    .and_then(dissect_ports)
                    .is_some_and(|(sport, dport)| match dir {
                        FilterDir::Any => sport == *n || dport == *n,
                        FilterDir::Src => sport == *n,
                        FilterDir::Dst => dport == *n,
                    })
            }
            FilterExpr::Host { dir, ip } => {
                ctx.dissect
                    .and_then(dissect_addrs)
                    .is_some_and(|(src, dst)| match dir {
                        FilterDir::Any => src == *ip || dst == *ip,
                        FilterDir::Src => src == *ip,
                        FilterDir::Dst => dst == *ip,
                    })
            }
            FilterExpr::And(a, b) => a.matches_ctx(ctx) && b.matches_ctx(ctx),
            FilterExpr::Or(a, b) => a.matches_ctx(ctx) || b.matches_ctx(ctx),
            FilterExpr::Not(a) => !a.matches_ctx(ctx),
        }
    }
}

/// 抓包循环里过滤求值的上下文：帧的完整反解报告（所有协议令牌按注册表匹配）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
struct FrameCtx<'a> {
    dissect: Option<&'a packet_dsl::dissect::DissectReport>,
}

/// 帧的 keep 判定（默认 ServiceFilter / --filter 表达式 / 全帧 三态收敛）。
/// 三平台 4 个抓包循环此前各复制一份同样的 match 块。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn frame_keep(data: &[u8], filter: &Option<ServiceFilter>, expr: &Option<FilterExpr>) -> bool {
    match (filter, expr) {
        (Some(f), _) => f.matches_frame(data),
        (None, Some(e)) => {
            let report = packet_dsl::dissect(data);
            let ctx = FrameCtx {
                dissect: Some(&report),
            };
            e.matches_ctx(&ctx)
        }
        (None, None) => true,
    }
}

/// 裸 IP（macOS lo0 DLT_NULL 剥头后）的 keep 判定，同上。
/// 仅 pcap_loop（macOS / Linux pcap 多设备路径）调用——cfg 与其调用方一致；
/// 此前误用 frame_keep 的宽 cfg，在 Linux 无 pcap / Windows 下引用不到
/// matches_bare（其 cfg 窄于此），E0599 编译失败。
#[cfg(any(target_os = "macos", all(target_os = "linux", feature = "pcap")))]
fn bare_ip_keep(data: &[u8], filter: &Option<ServiceFilter>, expr: &Option<FilterExpr>) -> bool {
    match (filter, expr) {
        (Some(f), _) => f.matches_bare(data),
        (None, Some(e)) => {
            let report = packet_dsl::dissect(data);
            let ctx = FrameCtx {
                dissect: Some(&report),
            };
            e.matches_ctx(&ctx)
        }
        (None, None) => true,
    }
}

/// 反解层栈是否含指定层名。
fn has_layer(r: &packet_dsl::dissect::DissectReport, name: &str) -> bool {
    r.layers
        .iter()
        .any(|l| crate::engine::eng::layer_name(l) == name)
}

/// 从反解层取传输端口（首个 Tcp/Udp 层；无端口层 → None）。
fn dissect_ports(r: &packet_dsl::dissect::DissectReport) -> Option<(u16, u16)> {
    r.layers.iter().find_map(|l| match l {
        packet_dsl::ir::Layer::Tcp(f) => Some((f.src_port?, f.dst_port?)),
        packet_dsl::ir::Layer::Udp(f) => Some((f.src_port?, f.dst_port?)),
        _ => None,
    })
}

/// 从反解层取地址对（首个 Ipv4/Ipv6 层；ARP 帧取 spa/tpa）。
fn dissect_addrs(r: &packet_dsl::dissect::DissectReport) -> Option<(IpAddr, IpAddr)> {
    use packet_dsl::ir::{Field, Layer};
    r.layers.iter().find_map(|l| match l {
        Layer::Ipv4(f) => match (&f.src, &f.dst) {
            (Field::Value(s), Field::Value(d)) => Some(((*s).into(), (*d).into())),
            _ => None,
        },
        Layer::Ipv6(f) => match (&f.src, &f.dst) {
            (Field::Value(s), Field::Value(d)) => Some(((*s).into(), (*d).into())),
            _ => None,
        },
        Layer::Arp(f) => Some((f.spa?.into(), f.tpa?.into())),
        _ => None,
    })
}

// ── Linux（默认）：AF_PACKET ──────────────────────────────────────────────

/// 打开 AF_PACKET raw socket 并绑定全接口，成功则启动抓包线程。
/// 仅在未启用 `pcap` feature 时编译；启用后走 `spawn_pcap_devices`（libpcap
/// 多设备路径，与 Windows/macOS 一致）。
#[cfg(all(target_os = "linux", not(feature = "pcap")))]
fn spawn_linux(addr: SocketAddr, all_frames: bool, expr: Option<FilterExpr>) -> CaptureStatus {
    let fd = match crate::util::socket::open_af_packet(0) {
        Ok(fd) => fd,
        Err(e) => {
            return CaptureStatus::Unavailable(
                rust_i18n::t!(
                    "errors.af_packet_socket",
                    hint = crate::util::privilege_hint(),
                    error = e.to_string()
                )
                .to_string(),
            );
        }
    };
    // 全帧模式：尽力开启混杂模式（PACKET_MR_PROMISC，需 CAP_NET_ADMIN），与
    // Windows/macOS pcap 路径默认 promisc(true) 对齐。失败不报错——仍能收到
    // 本机地址/广播/组播帧（ARP 请求等）；要看到网卡上其他主机的流量才需要。
    // 全部失败时给一次性提示（缺 CAP_NET_ADMIN 的典型症状）。
    if all_frames && !crate::util::socket::af_packet_promisc_all(fd) {
        eprintln!("{}", rust_i18n::t!("errors.capture_promisc_failed"));
    }
    // 默认模式构造 ServiceFilter；全帧模式不过滤（None 同时作为「全帧」标记）
    let filter = (!all_frames).then(|| ServiceFilter::new(addr));
    match std::thread::Builder::new()
        .name("server-capture".into())
        .spawn(move || linux_loop(fd, filter, expr))
    {
        Ok(_) => CaptureStatus::Active(vec![rust_i18n::t!("server.capture_iface_all").to_string()]),
        Err(e) => {
            unsafe { libc::close(fd) };
            CaptureStatus::Unavailable(e.to_string())
        }
    }
}

#[cfg(all(target_os = "linux", not(feature = "pcap")))]
fn linux_loop(fd: libc::c_int, filter: Option<ServiceFilter>, expr: Option<FilterExpr>) {
    let mut buf = vec![0u8; crate::util::RECV_BUF_SIZE];
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
        let frame = &buf[..n as usize];
        // 默认模式：只收本机入向（PACKET_HOST）且目的端口 == 监听端口；全帧模式：
        // --filter 只显示匹配帧，无 filter 显示一切（含广播/组播/出向回包）
        let keep = if filter.is_some() && sll.sll_pkttype != libc::PACKET_HOST {
            false // 默认模式非本机入向直接丢弃
        } else {
            frame_keep(frame, &filter, &expr)
        };
        if keep {
            show_frame(frame);
        }
    }
    unsafe { libc::close(fd) };
}

// ── Windows：Npcap ────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn spawn_windows(addr: SocketAddr, all_frames: bool, expr: Option<FilterExpr>) -> CaptureStatus {
    use crate::engine::rawpcap;
    let devs = match rawpcap::list_devices() {
        Ok(d) => d,
        Err(e) => return CaptureStatus::Unavailable(e.to_string()),
    };
    // 通配绑定（0.0.0.0/::）→ 开全部设备；指定绑定 → 开拥有该 IP 的设备。
    // 不能只开 `pick_device` 的首个非回环：多网卡 Windows（Hyper-V vEthernet /
    // VPN / WiFi Direct 等虚拟适配器排在真网卡前面）上流量网卡不排第一时会把
    // 本服务收到的帧全部漏掉——Linux AF_PACKET（默认）是全接口、macOS 是
    // 多设备、Linux 开 `--features pcap` 也是多设备，Windows 必须一致
    // （每个设备一个抓包线程）。
    let wanted = rawpcap::capture_devices(&devs, addr);
    if wanted.is_empty() {
        let list = rawpcap::format_device_list(&devs);
        return CaptureStatus::Unavailable(format!("找不到可用的抓包设备；可用：\n{list}"));
    }
    // 每个设备一个抓包线程；至少一个成功才算 Active（失败原因留到全失败时返回）
    // 默认模式构造 ServiceFilter；全帧模式不过滤（None 同时作为「全帧」标记）
    let filter = (!all_frames).then(|| ServiceFilter::new(addr));
    let mut started: Vec<String> = Vec::new();
    let mut first_err: Option<String> = None;
    for idx in wanted {
        let dev = devs[idx].name.clone();
        // 默认模式（ServiceFilter）只要入向；-a/--filter 全帧模式须看本机出向帧
        match rawpcap::open_capture(&dev, !all_frames) {
            Ok(mut cap) => {
                let filter = filter.clone();
                let expr = expr.clone();
                match std::thread::Builder::new()
                    .name("server-capture".into())
                    .spawn(move || windows_loop(&mut cap, filter, expr))
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
fn windows_loop(
    cap: &mut pcap::Capture<pcap::Active>,
    filter: Option<ServiceFilter>,
    expr: Option<FilterExpr>,
) {
    loop {
        if crate::interrupted() {
            break;
        }
        match cap.next_packet() {
            Ok(p) => {
                // 默认模式：目的端口 == 监听端口；全帧模式：--filter 只显示匹配帧，
                // 无 filter 显示一切（Npcap 已开混杂）
                if frame_keep(p.data, &filter, &expr) {
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

// ── pcap 多设备路径（macOS libpcap/BPF；Linux 开 `--features pcap` 时同款）──

/// 打开 pcap 抓包句柄（macOS：系统 libpcap，底层走 BPF；Linux：`--features
/// pcap` 的 libpcap）。与 Windows 的 Npcap 路径共用 `pcap::Capture` API；
/// 差异在设备枚举/选择（复用 `rawpcap::list_devices` / `pick_device`）与链路类型：
/// - 普通网卡：Ethernet（EN10MB），帧带 14B eth 头（`show_frame` 全栈解析）
/// - macOS lo0 回环：**DLT_NULL**（4 字节族头 + 裸 IP），抓包侧剥掉族头走裸 IP
///   路径（Linux lo 经 libpcap 是 EN10MB，不会出现 NULL/LOOP，该分支仅防御性）
///
/// 权限：macOS /dev/bpf* 默认 root:wheel 600——需 `sudo` 或 Wireshark 的
/// ChmodBPF 授权；Linux 需 cap_net_raw（libpcap 底层是 AF_PACKET socket）。
#[cfg(any(target_os = "macos", all(target_os = "linux", feature = "pcap")))]
fn open_pcap_capture(dev: &str) -> anyhow::Result<pcap::Capture<pcap::Active>> {
    let cap = pcap::Capture::from_device(dev)
        .map_err(|e| anyhow::anyhow!("打开 pcap 设备 `{dev}` 失败：{e}"))?
        .timeout(100)
        .promisc(true)
        .immediate_mode(true)
        .open()
        .map_err(|e| anyhow::anyhow!("打开 pcap 设备 `{dev}` 失败：{e}"))?;
    Ok(cap)
}

/// 按绑定地址在目标设备集合上逐个开抓包线程（macOS 与 Linux `--features pcap`
/// 共用；Windows 因 Npcap 打开方式差异保留独立实现）：
/// 通配绑定（0.0.0.0/::）→ 全部设备（回环 + 所有非回环），本地客户端走回环、
/// 远程客户端走网卡，两者都能看到；指定绑定 → 拥有该 IP 的设备
/// （与 Windows 共用 capture_devices，等价 Linux AF_PACKET 的「全接口」语义）。
/// 每个设备一个抓包线程；至少一个成功才算 Active（失败原因留到全失败时返回）。
#[cfg(any(target_os = "macos", all(target_os = "linux", feature = "pcap")))]
fn spawn_pcap_devices(
    addr: SocketAddr,
    all_frames: bool,
    expr: Option<FilterExpr>,
    open: fn(&str) -> anyhow::Result<pcap::Capture<pcap::Active>>,
) -> CaptureStatus {
    let devs = match crate::engine::rawpcap::list_devices() {
        Ok(d) => d,
        Err(e) => return CaptureStatus::Unavailable(e.to_string()),
    };
    let iface_all = rust_i18n::t!("server.capture_iface_all").to_string();
    let wanted = crate::engine::rawpcap::capture_devices(&devs, addr);
    if wanted.is_empty() {
        let list = crate::engine::rawpcap::format_device_list(&devs);
        return CaptureStatus::Unavailable(format!("找不到可用的抓包设备；可用：\n{list}"));
    }
    // 默认模式构造 ServiceFilter；全帧模式不过滤（None 同时作为「全帧」标记）
    let filter = (!all_frames).then(|| ServiceFilter::new(addr));
    let mut started: Vec<String> = Vec::new();
    let mut first_err: Option<String> = None;
    for idx in wanted {
        let dev = devs[idx].name.clone();
        match open(&dev) {
            Ok(mut cap) => {
                let dlt = cap.get_datalink();
                let filter = filter.clone();
                let expr = expr.clone();
                match std::thread::Builder::new()
                    .name("server-capture".into())
                    .spawn(move || pcap_loop(&mut cap, filter, expr, dlt))
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

#[cfg(any(target_os = "macos", all(target_os = "linux", feature = "pcap")))]
fn pcap_loop(
    cap: &mut pcap::Capture<pcap::Active>,
    filter: Option<ServiceFilter>,
    expr: Option<FilterExpr>,
    dlt: pcap::Linktype,
) {
    loop {
        if crate::interrupted() {
            break;
        }
        match cap.next_packet() {
            Ok(p) => {
                // macOS lo0 回环是 DLT_NULL：4 字节族头 + 裸 IP；普通网卡（含
                // Linux lo）是 Ethernet 帧
                if dlt == pcap::Linktype::NULL || dlt == pcap::Linktype::LOOP {
                    let Some(ip) = strip_null(p.data) else {
                        continue;
                    };
                    if bare_ip_keep(ip, &filter, &expr) {
                        show_bare_ip(ip);
                    }
                } else {
                    // 默认模式：目的端口 == 监听端口；全帧模式：--filter 只显示匹配帧，
                    // 无 filter 显示一切（BPF 已开混杂）
                    if frame_keep(p.data, &filter, &expr) {
                        show_frame(p.data);
                    }
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
/// serve 抓包与 `packet --listen --raw`（pcap 路径）共用。cfg 与
/// serve/mod.rs 的 re-export 及 listen_raw 的 pcap 路径调用方一致
/// （此前误用 frame_keep 一侧的窄 cfg，Windows 下 re-export 悬空 E0432）。
#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
pub(crate) fn strip_null(data: &[u8]) -> Option<&[u8]> {
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
        // TCP 头 20B：seq(4) ack(4) off+flags(2)=0x5000 win(2) cksum(2) urg(2)，
        // data_offset=5 才能被注册表 tcp 声明反解（与 ipv4 total=0x28 一致）
        f.extend_from_slice(&[0; 8]); // seq/ack
        f.extend_from_slice(&[0x50, 0x00]); // off+flags（data_offset=5）
        f.extend_from_slice(&[0; 6]); // window/checksum/urg
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

    /// 构造 eth + ipv4 + icmp 帧（proto=1，ICMP echo 头 8 字节，src/dst=127.0.0.1）。
    fn eth_ip4_icmp() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xaa; 6]);
        f.extend_from_slice(&[0xbb; 6]);
        f.extend_from_slice(&[0x08, 0x00]);
        // IPv4 头：ihl=5, total=28, proto=1, src/dst=127.0.0.1
        f.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 127, 0, 0, 1,
            127, 0, 0, 1,
        ]);
        f.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]); // type/code/cksum/id/seq
        f
    }

    /// 构造 eth + ARP 帧（Ethernet/IPv4 定长头，op/spa/tpa 由参数指定）。
    fn eth_arp(op: u16, spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]); // dst MAC 广播
        f.extend_from_slice(&[0xbb; 6]); // src MAC
        f.extend_from_slice(&[0x08, 0x06]); // ethertype=ARP
        f.extend_from_slice(&[0x00, 0x01]); // htype=Ethernet
        f.extend_from_slice(&[0x08, 0x00]); // ptype=IPv4
        f.extend_from_slice(&[0x06, 0x04]); // hlen/plen
        f.extend_from_slice(&op.to_be_bytes());
        f.extend_from_slice(&[0xbb; 6]); // sha
        f.extend_from_slice(&spa);
        f.extend_from_slice(&[0x00; 6]); // tha
        f.extend_from_slice(&tpa);
        f
    }

    #[test]
    fn frame_summary_transport_matches_frame_meta() {
        // TCP 帧：摘要（Transport）与 frame_meta（ServiceFilter 用）字段一致
        let f = eth_ip4_tcp(49320, 80);
        let m = frame_meta(&f).unwrap();
        match frame_summary(&f).unwrap() {
            FrameSummary::Transport {
                src,
                sport,
                dst,
                dport,
                proto,
            } => {
                assert_eq!(src, m.src);
                assert_eq!(sport, m.sport);
                assert_eq!(dst, m.dst);
                assert_eq!(dport, m.dport);
                assert_eq!(proto, m.proto);
            }
            other => panic!("TCP 帧应得 Transport 摘要：{other:?}"),
        }
    }

    #[test]
    fn frame_summary_icmp_no_ports() {
        // ICMP（proto=1）：摘要只给地址，无端口
        let f = eth_ip4_icmp();
        match frame_summary(&f).unwrap() {
            FrameSummary::Ip { src, dst, proto } => {
                assert_eq!(src, IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(dst, IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(proto, 1);
                assert_eq!(proto_name(proto), "ICMP");
                assert_eq!(proto_name(17), "UDP");
                assert_eq!(proto_name(200), "proto 200");
            }
            other => panic!("ICMP 帧应得 Ip 摘要：{other:?}"),
        }
    }

    #[test]
    fn frame_summary_arp_request_and_reply() {
        // ARP request：spa → tpa
        let req = eth_arp(1, [192, 168, 1, 2], [192, 168, 1, 1]);
        match frame_summary(&req).unwrap() {
            FrameSummary::Arp { op, spa, tpa } => {
                assert_eq!(op, "request");
                assert_eq!(spa, Ipv4Addr::new(192, 168, 1, 2));
                assert_eq!(tpa, Ipv4Addr::new(192, 168, 1, 1));
            }
            other => panic!("ARP request 应得 Arp 摘要：{other:?}"),
        }
        // ARP reply：spa → tpa
        let rep = eth_arp(2, [192, 168, 1, 1], [192, 168, 1, 2]);
        match frame_summary(&rep).unwrap() {
            FrameSummary::Arp { op, spa, tpa } => {
                assert_eq!(op, "reply");
                assert_eq!(spa, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(tpa, Ipv4Addr::new(192, 168, 1, 2));
            }
            other => panic!("ARP reply 应得 Arp 摘要：{other:?}"),
        }
    }

    #[test]
    fn frame_summary_rejects_short_and_foreign_arp() {
        assert!(frame_summary(&[0u8; 4]).is_none());
        // 非 Ethernet/IPv4 的 ARP（htype≠1）→ None
        let mut arp = eth_arp(1, [1, 2, 3, 4], [5, 6, 7, 8]);
        arp[14] = 0x06; // htype 高字节改 6 → 0x0601 ≠ 1
        assert!(frame_summary(&arp).is_none());
        // ARP 头不足 28 字节 → None
        assert!(frame_summary(&arp[..30]).is_none());
    }

    #[test]
    fn bare_ip_summary_icmp() {
        // 裸 IPv4 + ICMP（无 eth 头）：摘要走 Ip 分支
        let mut ip = Vec::new();
        ip.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 127, 0, 0, 1,
            127, 0, 0, 1,
        ]);
        ip.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]);
        match bare_ip_summary(&ip).unwrap() {
            FrameSummary::Ip { proto, .. } => assert_eq!(proto, 1),
            other => panic!("裸 ICMP 应得 Ip 摘要：{other:?}"),
        }
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
    #[cfg(any(target_os = "macos", all(target_os = "linux", feature = "pcap")))]
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

    // ── --filter 解析与匹配（注册表/dissect 驱动）────────────────────────────

    /// 帧 → 完整反解报告（过滤器测试用）。
    fn dissect_of(frame: &[u8]) -> packet_dsl::dissect::DissectReport {
        packet_dsl::dissect(frame)
    }

    /// 报告 → 过滤器求值上下文（借用报告，借期由调用方保持）。
    fn ctx(r: &packet_dsl::dissect::DissectReport) -> FrameCtx<'_> {
        FrameCtx { dissect: Some(r) }
    }

    /// 构造 eth + ipv6 + udp 帧（next=17 UDP，src/dst=::1）。
    fn eth_ip6_udp(sport: u16, dport: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xaa; 6]);
        f.extend_from_slice(&[0xbb; 6]);
        f.extend_from_slice(&[0x86, 0xDD]);
        f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40]); // payload len=8, next=17
        let mut addr = [0u8; 16];
        addr[15] = 1; // ::1
        f.extend_from_slice(&addr);
        f.extend_from_slice(&addr);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x08, 0x00, 0x00]); // len=8（无载荷）, checksum=0
        f
    }

    #[test]
    fn filter_proto_matches() {
        // 内置协议令牌按注册表（dissect）层名匹配
        crate::engine::eng::ensure_proto_registry();
        let tcp_r = dissect_of(&eth_ip4_tcp(49320, 80));
        let tcp = ctx(&tcp_r);
        let udp6_r = dissect_of(&eth_ip6_udp(53, 49320));
        let udp6 = ctx(&udp6_r);
        let icmp_r = dissect_of(&eth_ip4_icmp());
        let icmp = ctx(&icmp_r);
        // ICMPv6：IPv6 next=58 的帧
        let mut icmp6f = eth_ip6_udp(0, 0);
        icmp6f[14 + 6] = 58;
        let icmp6_r = dissect_of(&icmp6f);
        let icmp6 = ctx(&icmp6_r);
        let arp_r = dissect_of(&eth_arp(1, [192, 168, 1, 2], [192, 168, 1, 1]));
        let arp = ctx(&arp_r);
        assert!(parse_filter("tcp").unwrap().matches_ctx(&tcp));
        assert!(!parse_filter("tcp").unwrap().matches_ctx(&udp6));
        assert!(parse_filter("udp").unwrap().matches_ctx(&udp6));
        assert!(parse_filter("icmp").unwrap().matches_ctx(&icmp));
        assert!(!parse_filter("icmp").unwrap().matches_ctx(&icmp6));
        assert!(parse_filter("icmp6").unwrap().matches_ctx(&icmp6));
        assert!(!parse_filter("icmp6").unwrap().matches_ctx(&icmp));
        assert!(parse_filter("arp").unwrap().matches_ctx(&arp));
        assert!(!parse_filter("arp").unwrap().matches_ctx(&tcp));
        assert!(parse_filter("ip").unwrap().matches_ctx(&tcp));
        assert!(parse_filter("ip6").unwrap().matches_ctx(&udp6));
        assert!(!parse_filter("ip6").unwrap().matches_ctx(&tcp));
        // 关键字大小写不敏感
        assert!(parse_filter("TCP").unwrap().matches_ctx(&tcp));
        assert!(parse_filter("Ipv6").unwrap().matches_ctx(&udp6));
    }

    #[test]
    fn filter_port_and_host() {
        // port/host 限定符从反解层取值（Tcp/Udp 端口、Ipv4/Ipv6 地址）
        crate::engine::eng::ensure_proto_registry();
        let tcp_r = dissect_of(&eth_ip4_tcp(49320, 80));
        let tcp = ctx(&tcp_r);
        let udp6_r = dissect_of(&eth_ip6_udp(53, 49320));
        let udp6 = ctx(&udp6_r);
        // port：sport 或 dport 任一命中
        assert!(parse_filter("port 80").unwrap().matches_ctx(&tcp));
        assert!(parse_filter("port 49320").unwrap().matches_ctx(&tcp));
        assert!(!parse_filter("port 443").unwrap().matches_ctx(&tcp));
        // src/dst port 定向
        assert!(parse_filter("src port 49320").unwrap().matches_ctx(&tcp));
        assert!(!parse_filter("src port 80").unwrap().matches_ctx(&tcp));
        assert!(parse_filter("dst port 80").unwrap().matches_ctx(&tcp));
        assert!(!parse_filter("dst port 49320").unwrap().matches_ctx(&tcp));
        // host：src 或 dst 任一
        assert!(parse_filter("host 127.0.0.1").unwrap().matches_ctx(&tcp));
        assert!(!parse_filter("host 192.168.1.99").unwrap().matches_ctx(&tcp));
        assert!(
            parse_filter("src host 127.0.0.1")
                .unwrap()
                .matches_ctx(&tcp)
        );
        assert!(!parse_filter("src host 10.0.0.1").unwrap().matches_ctx(&tcp));
        assert!(
            parse_filter("dst host 127.0.0.1")
                .unwrap()
                .matches_ctx(&tcp)
        );
        // IPv6 地址（::1）
        assert!(parse_filter("host ::1").unwrap().matches_ctx(&udp6));
        assert!(!parse_filter("host 127.0.0.1").unwrap().matches_ctx(&udp6));
        // 非传输层（ICMP）host 匹配地址
        let icmp_r = dissect_of(&eth_ip4_icmp());
        let icmp = ctx(&icmp_r);
        assert!(parse_filter("host 127.0.0.1").unwrap().matches_ctx(&icmp));
    }

    #[test]
    fn filter_arp_host_uses_spa_tpa() {
        // ARP 按反解层 spa/tpa 匹配 host（tcpdump 同款语义）
        crate::engine::eng::ensure_proto_registry();
        let arp_r = dissect_of(&eth_arp(1, [192, 168, 1, 2], [192, 168, 1, 1]));
        let arp = ctx(&arp_r);
        assert!(parse_filter("host 192.168.1.2").unwrap().matches_ctx(&arp));
        assert!(parse_filter("host 192.168.1.1").unwrap().matches_ctx(&arp));
        assert!(
            parse_filter("src host 192.168.1.2")
                .unwrap()
                .matches_ctx(&arp)
        );
        assert!(
            parse_filter("dst host 192.168.1.1")
                .unwrap()
                .matches_ctx(&arp)
        );
        assert!(!parse_filter("host 10.0.0.1").unwrap().matches_ctx(&arp));
        // 组合
        assert!(
            parse_filter("arp and host 192.168.1.2")
                .unwrap()
                .matches_ctx(&arp)
        );
        assert!(
            !parse_filter("tcp and host 192.168.1.2")
                .unwrap()
                .matches_ctx(&arp)
        );
    }

    #[test]
    fn filter_combinations_and_precedence() {
        crate::engine::eng::ensure_proto_registry();
        let tcp_r = dissect_of(&eth_ip4_tcp(49320, 80));
        let tcp = ctx(&tcp_r);
        let icmp_r = dissect_of(&eth_ip4_icmp());
        let icmp = ctx(&icmp_r);
        // not
        assert!(!parse_filter("not tcp").unwrap().matches_ctx(&tcp));
        assert!(parse_filter("not arp").unwrap().matches_ctx(&tcp));
        // 无反解上下文：not 命中（原始帧 only）
        let noctx = FrameCtx { dissect: None };
        assert!(parse_filter("not arp").unwrap().matches_ctx(&noctx));
        // or / and
        assert!(parse_filter("arp or icmp").unwrap().matches_ctx(&icmp));
        assert!(!parse_filter("arp or icmp").unwrap().matches_ctx(&tcp));
        assert!(
            parse_filter("tcp and not port 443")
                .unwrap()
                .matches_ctx(&tcp)
        );
        assert!(!parse_filter("tcp and port 443").unwrap().matches_ctx(&tcp));
        // and 优先于 or：arp or (icmp and tcp)
        let e = parse_filter("arp or icmp and tcp").unwrap();
        assert_eq!(
            e,
            FilterExpr::Or(
                Box::new(FilterExpr::Dissect("arp".into())),
                Box::new(FilterExpr::And(
                    Box::new(FilterExpr::Dissect("icmp".into())),
                    Box::new(FilterExpr::Dissect("tcp".into())),
                )),
            )
        );
        // 括号
        let e2 = parse_filter("(arp or icmp) and not host 10.0.0.1").unwrap();
        assert!(e2.matches_ctx(&icmp));
        assert!(!e2.matches_ctx(&tcp));
    }

    #[test]
    fn filter_proto_qualifier_chain() {
        // tcpdump 风格：`tcp port N` / `tcp src port N` / `arp host IP` 展开为 And
        crate::engine::eng::ensure_proto_registry();
        let tcp_r = dissect_of(&eth_ip4_tcp(49320, 80));
        let tcp = ctx(&tcp_r);
        let arp_r = dissect_of(&eth_arp(1, [192, 168, 1, 2], [192, 168, 1, 1]));
        let arp = ctx(&arp_r);
        // 结构展开：tcp port 80 == tcp and port 80
        assert_eq!(
            parse_filter("tcp port 80").unwrap(),
            FilterExpr::And(
                Box::new(FilterExpr::Dissect("tcp".into())),
                Box::new(FilterExpr::Port {
                    dir: FilterDir::Any,
                    n: 80
                }),
            )
        );
        // 匹配语义
        assert!(parse_filter("tcp port 80").unwrap().matches_ctx(&tcp));
        assert!(!parse_filter("tcp port 443").unwrap().matches_ctx(&tcp));
        assert!(
            parse_filter("tcp src port 49320")
                .unwrap()
                .matches_ctx(&tcp)
        );
        assert!(!parse_filter("tcp src port 80").unwrap().matches_ctx(&tcp));
        assert!(parse_filter("tcp dst port 80").unwrap().matches_ctx(&tcp));
        // 协议 + host：arp host（spa/tpa）
        assert!(
            parse_filter("arp host 192.168.1.2")
                .unwrap()
                .matches_ctx(&arp)
        );
        assert!(!parse_filter("arp host 10.0.0.1").unwrap().matches_ctx(&arp));
        // 组合继续可用：not tcp port 80
        assert!(!parse_filter("not tcp port 80").unwrap().matches_ctx(&tcp));
        // 缺限定报错：tcp src
        assert!(parse_filter("tcp src").is_err());
    }

    /// 构造 eth + ipv4 + udp + dns 查询帧（example.com A IN，qdcount=1）。
    fn eth_ip4_udp_dns(sport: u16, dport: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xaa; 6]);
        f.extend_from_slice(&[0xbb; 6]);
        f.extend_from_slice(&[0x08, 0x00]);
        // IPv4：ihl=5, total=20+8+29=57, proto=17, src/dst=127.0.0.1
        f.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 127, 0, 0, 1,
            127, 0, 0, 1,
        ]);
        // UDP：sport/dport + len=8+29=37 + checksum 0
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x25, 0x00, 0x00]);
        // DNS header：id=0x1234, flags=0x0100(RD), qdcount=1, an/ns/ar=0
        f.extend_from_slice(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        // question：example.com A IN
        f.extend_from_slice(&[0x07]);
        f.extend_from_slice(b"example");
        f.extend_from_slice(&[0x03]);
        f.extend_from_slice(b"com");
        f.extend_from_slice(&[0x00]);
        f.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        f
    }

    #[test]
    fn filter_dissect_proto_dns() {
        // eng_lib 扩展协议：`dns` 按反解层名 + ProtoHit 命中名匹配
        crate::engine::eng::ensure_proto_registry();
        let dns_r = dissect_of(&eth_ip4_udp_dns(54321, 53));
        let dns = ctx(&dns_r);
        // dns 层命中
        assert!(parse_filter("dns").unwrap().matches_ctx(&dns));
        // dns + 端口限定链（qualifier 走反解层端口）
        assert!(parse_filter("dns port 53").unwrap().matches_ctx(&dns));
        assert!(!parse_filter("dns port 5353").unwrap().matches_ctx(&dns));
        assert!(
            parse_filter("dns src port 54321")
                .unwrap()
                .matches_ctx(&dns)
        );
        // http 不命中 dns 帧
        assert!(!parse_filter("http").unwrap().matches_ctx(&dns));
        // 无反解上下文不命中
        let noctx = FrameCtx { dissect: None };
        assert!(!parse_filter("dns").unwrap().matches_ctx(&noctx));
        // 固定层名：ipv4/eth 命中
        assert!(parse_filter("ipv4").unwrap().matches_ctx(&dns));
        assert!(parse_filter("eth").unwrap().matches_ctx(&dns));
    }

    #[test]
    fn filter_dissect_proto_validation() {
        // 注册表协议校验：声明了 #[rule] 的（quic_initial）可过滤，无规则的（tls）报错
        crate::engine::eng::ensure_proto_registry();
        assert!(
            parse_filter("quic_initial").is_ok(),
            "quic_initial 声明了 #[rule(udp(dport=443))]"
        );
        let e = parse_filter("tls").unwrap_err();
        assert!(
            e.contains("unknown protocol"),
            "tls 无 dissect 规则应报错：{e}"
        );
        assert!(e.contains("quic_initial"), "错误信息应提示可用协议：{e}");
        // 层名令牌始终有效（不依赖注册表）
        assert!(parse_filter("http").is_ok());
        assert!(parse_filter("raw").is_ok());
        assert!(parse_filter("tcp").is_ok());
    }

    #[test]
    fn filter_parse_errors() {
        for bad in [
            "",           // 空表达式
            "foo",        // 未知令牌
            "port",       // 缺端口号
            "port abc",   // 非数字端口
            "port 99999", // 超出 u16
            "host",       // 缺地址
            "host bad",   // 非法地址
            "tcp port",   // 协议后跟 port 但缺数字
            "src",        // 方向后缺限定
            "src foo",    // 方向后非法限定
            "dst port",   // 方向 + port 缺数字
            "arp)",       // 多余右括号
            "(arp",       // 缺右括号
            "arp or",     // 悬空 or
            "and arp",    // 开头 and
        ] {
            assert!(parse_filter(bad).is_err(), "应拒绝 `{bad}`");
        }
    }
}
