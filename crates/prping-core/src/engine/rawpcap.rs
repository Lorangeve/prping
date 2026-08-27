//! pcap raw 发送兼容层（`--pkt --raw` 的 pcap 后端：Windows / macOS / Linux feature=pcap）。
//!
//! Windows 和 macOS 没有 AF_PACKET（Linux 专属），自造完整包（eth 帧 / 裸 IP，
//! 含 TCP/UDP）必须经 pcap 在链路层注入（`pcap_sendpacket`），语义等价于 Linux 的
//! AF_PACKET。Linux 也可通过 `--features pcap` 启用此路径（需安装 libpcap-dev）。
//! macOS 使用系统自带的 libpcap（底层 BPF），需 sudo 或 ChmodBPF 授权。
//!
//! 职责（与 `pkg.rs` 的 Linux 路径等价，pkg.rs 在 windows/macos 下委托本模块）：
//! - 设备选择：`--iface` 匹配 pcap 设备名（不区分大小写）或描述子串；回环目标 →
//!   回环设备（Npcap Loopback Adapter / lo0）；其余取首个非回环设备。
//! - eth 帧：直接 `pcap_sendpacket`（设备链路类型须为 Ethernet）。
//! - 裸 IPv4：以太网封装——src MAC = 接口 MAC，dst MAC = 下一跳 MAC（ARP 解析）。
//!   Windows 用 `GetBestRoute`/`GetIpNetTable`/`GetIfEntry`；macOS 用
//!   `getifaddrs` + `ioctl(SIOCGIFADDR)` + ARP 探测。
//! - 裸 IPv6：v1 仅支持回环（`::1`）；跨链路目标暂报错。
//! - `--wait`：**先开抓包句柄再发送**（局域网回包可能 <1ms，先发后开会漏抓），
//!   按 sniffer 或 ICMP echo id+seq 匹配（复用 `pkg.rs::match_reply`）。
//!
//! 纯函数（`wrap_eth` / 设备选择）全平台编译可单测；pcap / iphlpapi / getifaddrs
//! FFI 仅对应平台编译。

// 以下导入仅 pcap 后端使用（纯函数与测试不依赖它们）
#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
use crate::engine::pkg::{Reply, SendOutcome};
#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
use crate::output::indent;
#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
use packet_dsl::ir::{Layer, PacketSpec};
#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
use rust_i18n::t;
#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
use std::time::{Duration, Instant};

/// Npcap/libpcap 设备抽象（纯数据；windows/macOS 由 `pcap::Device` 填充，测试直接构造）。
#[cfg(any(windows, target_os = "macos", feature = "pcap", test))]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DeviceInfo {
    pub name: String,
    pub desc: Option<String>,
    pub loopback: bool,
}

/// 选择发送/抓包设备：`--iface` 按名字（不区分大小写）精确匹配，或描述子串匹配；
/// 否则回环目标优先回环设备，其余取首个非回环设备（全回环时兜底取第一个）。
/// （macOS server 抓包不用本函数：0.0.0.0 未指定绑定需同时开 lo0 + 非回环设备，
/// 设备集合选择内联在 `capture::spawn_macos`。）
#[cfg(any(windows, target_os = "macos", feature = "pcap", test))]
pub(crate) fn pick_device(
    devs: &[DeviceInfo],
    target_loopback: bool,
    iface: Option<&str>,
) -> Option<usize> {
    if let Some(pat) = iface {
        let p = pat.to_ascii_lowercase();
        return devs.iter().position(|d| {
            d.name.to_ascii_lowercase() == p
                || d.desc
                    .as_deref()
                    .map(|s| s.to_ascii_lowercase().contains(&p))
                    .unwrap_or(false)
        });
    }
    if target_loopback && let Some(i) = devs.iter().position(|d| d.loopback) {
        return Some(i);
    }
    devs.iter()
        .position(|d| !d.loopback)
        .or_else(|| (!devs.is_empty()).then_some(0))
}

/// IP 版本 → 以太网类型（IPv4 0x0800 / IPv6 0x86DD）。
#[cfg(any(windows, target_os = "macos", feature = "pcap", test))]
fn ethertype_of(ip: &[u8]) -> Option<u16> {
    match ip.first()? >> 4 {
        4 => Some(0x0800),
        6 => Some(0x86DD),
        _ => None,
    }
}

/// 裸 IP 包 → 以太网帧（14B 头 + payload；非法 IP 返回 None）。
#[cfg(any(windows, target_os = "macos", feature = "pcap", test))]
fn wrap_eth(ip: &[u8], src_mac: [u8; 6], dst_mac: [u8; 6]) -> Option<Vec<u8>> {
    let ethertype = ethertype_of(ip)?;
    let mut frame = Vec::with_capacity(14 + ip.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(ip);
    Some(frame)
}

// ── Windows 专属：iphlpapi FFI + MAC 解析 ─────────────────────

/// MIB_IPFORWARDROW（`GetBestRoute` 输出；14 × DWORD，无填充，x86/x64 同构）。
#[cfg(any(windows, test))]
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MibIpForwardRow {
    dest: u32,
    mask: u32,
    policy: u32,
    next_hop: u32,
    if_index: u32,
    fwd_type: u32,
    proto: u32,
    age: u32,
    next_hop_as: u32,
    metric1: u32,
    metric2: u32,
    metric3: u32,
    metric4: u32,
    metric5: u32,
}

/// MIB_IPNETROW（ARP 缓存行；24 字节）。
#[cfg(any(windows, test))]
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MibIpNetRow {
    if_index: u32,
    phys_addr_len: u32,
    phys_addr: [u8; 8],
    addr: u32,
    typ: u32,
}

/// MIB_IFROW（`GetIfEntry` 输入/输出；固定布局，无指针，x86/x64 同构）。
#[cfg(any(windows, test))]
#[repr(C)]
#[derive(Clone, Copy)]
struct MibIfRow {
    wsz_name: [u16; 256],
    dw_index: u32,
    dw_type: u32,
    dw_mtu: u32,
    dw_speed: u32,
    dw_phys_addr_len: u32,
    b_phys_addr: [u8; 8],
    dw_admin_status: u32,
    dw_oper_status: u32,
    dw_last_change: u32,
    dw_in_octets: u32,
    dw_in_ucast_pkts: u32,
    dw_in_nucast_pkts: u32,
    dw_in_discards: u32,
    dw_in_errors: u32,
    dw_in_unknown_protos: u32,
    dw_out_octets: u32,
    dw_out_ucast_pkts: u32,
    dw_out_nucast_pkts: u32,
    dw_out_discards: u32,
    dw_out_errors: u32,
    dw_out_qlen: u32,
    dw_descr_len: u32,
    b_descr: [u8; 256],
}

#[cfg(any(windows, test))]
impl Default for MibIfRow {
    /// 全零初始化（`[u8; 256]`/`[u16; 256]` 超过 std Default 的 32 上限，手写）。
    fn default() -> Self {
        // SAFETY: 全零是 FFI 输入结构的合法初始状态（纯整型/字节数组，无 bool/引用）。
        unsafe { std::mem::zeroed() }
    }
}

/// iphlpapi FFI（Win7 兼容：`GetBestRoute` / `GetIpNetTable` / `GetIfEntry` 均为 XP+ API）。
#[cfg(windows)]
mod iphlp {
    use super::{MibIfRow, MibIpForwardRow};
    use std::ffi::c_void;

    pub const NO_ERROR: u32 = 0;
    pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        /// 到目标的最优路由（入参/出参的 IP 均为网络字节序）。
        pub fn GetBestRoute(dest: u32, source: u32, route: *mut MibIpForwardRow) -> u32;
        /// ARP 缓存表（IPv4；变长，先查大小再取）。
        pub fn GetIpNetTable(table: *mut c_void, size: *mut u32, order: i32) -> u32;
        /// 按接口索引取接口信息（含物理地址）。
        pub fn GetIfEntry(row: *mut MibIfRow) -> u32;
    }
}

/// wpcap.dll 延迟加载前置检查（`packet --raw` 唯一需要 Npcap 的入口）。
///
/// 背景：pcap crate 对 wpcap.dll 是静态导入，若直接链接，Windows 加载器在进程
/// 启动时就要解析它——机器没装 Npcap 就连 `--help` 都起不来（"wpcap.dll is
/// missing"）。`.cargo/config.toml` 已给所有 MSVC 目标配 `/DELAYLOAD:wpcap.dll`
/// 把该导入降级为延迟加载；这里在真正使用 pcap 前手动 `LoadLibrary` 探测：
/// - 成功：wpcap.dll 已驻留进程，后续 pcap 调用经 delay-load thunk 直接命中；
/// - 失败：返回友好错误——绝不能让 delay-load 失败路径走到（那会抛 SEH 异常
///   0xC06D007E，Rust 默认不捕获，直接崩溃）。
#[cfg(windows)]
pub(crate) fn ensure_wpcap() -> anyhow::Result<()> {
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut std::ffi::c_void;
    }
    // "wpcap.dll"（UTF-16，含 NUL）；LoadLibrary 标准搜索序 = delay-load thunk 的搜索序
    const WPCAP: [u16; 10] = [
        b'w' as u16,
        b'p' as u16,
        b'c' as u16,
        b'a' as u16,
        b'p' as u16,
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0,
    ];
    let h = unsafe { LoadLibraryW(WPCAP.as_ptr()) };
    if h.is_null() {
        anyhow::bail!(t!("errors.no_npcap"));
    }
    Ok(())
}

// ── pcap 发送入口（Windows / macOS 共用逻辑）───────────────────

/// `--pkt --raw` 的 pcap 发送入口（pkg.rs::send_raw_bytes 在 windows/macos 下委托）。
///
/// 一次完成：设备选择 → （--wait 时）开抓包句柄 → 以太网封装/直发 → 等待匹配应答。
#[cfg(windows)]
pub(crate) fn send_raw_full(
    bytes: &[u8],
    pkt: &PacketSpec,
    target: Option<&SocketAddr>,
    iface: Option<&str>,
    wait: Option<f64>,
    sniffer: Option<&crate::engine::pkg::SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<SendOutcome> {
    ensure_wpcap()?; // 延迟加载前置：未装 Npcap 时给友好报错（见 .cargo/config.toml /DELAYLOAD）
    send_raw_pcap(bytes, pkt, target, iface, wait, sniffer, sent_report)
}

/// macOS / Linux（feature=pcap）入口：系统 libpcap，无需延迟加载检查。
#[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
pub(crate) fn send_raw_full(
    bytes: &[u8],
    pkt: &PacketSpec,
    target: Option<&SocketAddr>,
    iface: Option<&str>,
    wait: Option<f64>,
    sniffer: Option<&crate::engine::pkg::SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<SendOutcome> {
    send_raw_pcap(bytes, pkt, target, iface, wait, sniffer, sent_report)
}

/// Windows / macOS 共用的 pcap 发送逻辑。
#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
fn send_raw_pcap(
    bytes: &[u8],
    pkt: &PacketSpec,
    target: Option<&SocketAddr>,
    iface: Option<&str>,
    wait: Option<f64>,
    sniffer: Option<&crate::engine::pkg::SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<SendOutcome> {
    let dev = select_device_name(target, iface)?;
    let (proto, frame) = match pkt.layers.last() {
        Some(Layer::Ethernet(_)) => ("ETH", bytes.to_vec()),
        Some(Layer::Ipv4(_)) => {
            let t = target.ok_or_else(|| {
                anyhow::anyhow!("raw IPv4 发送需要目标地址（HOST 或包内 IP 层 dst）")
            })?;
            ("IP4", wrap_ip4(bytes, t)?)
        }
        Some(Layer::Ipv6(_)) => {
            let t = target.ok_or_else(|| {
                anyhow::anyhow!("raw IPv6 发送需要目标地址（HOST 或包内 IP 层 dst）")
            })?;
            ("IP6", wrap_ip6(bytes, t)?)
        }
        _ => anyhow::bail!("raw 发送需要最外层为 eth / ipv4 / ipv6 层"),
    };
    // 先开抓包句柄再发送：局域网回包可能 <1ms，先发后开（Linux 的做法）会漏抓
    let mut cap = open_capture(&dev)?;
    cap.sendpacket(frame.as_slice())
        .map_err(|e| anyhow::anyhow!("pcap 发送失败（{dev}）：{e}"))?;
    let reply = match wait {
        Some(secs) => wait_reply(&mut cap, secs, pkt, &frame, sniffer, sent_report)?,
        None => None,
    };
    Ok(SendOutcome {
        proto,
        sent: frame.len(),
        received: 0,
        reply,
    })
}

#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
pub(crate) fn select_device_name(
    target: Option<&SocketAddr>,
    iface: Option<&str>,
) -> anyhow::Result<String> {
    let devs = list_devices()?;
    // 链路层帧（None）无目标可判回环：走非回环优先的默认选择
    let loopback = target.is_some_and(|t| t.ip().is_loopback());
    let idx = pick_device(&devs, loopback, iface).ok_or_else(|| {
        let hint = iface.map(|i| format!("（匹配 `{i}`）")).unwrap_or_default();
        let list: Vec<String> = devs.iter().map(|d| d.name.clone()).collect();
        anyhow::anyhow!("找不到可用的 pcap 设备{hint}；可用：{}", list.join(", "))
    })?;
    Ok(devs[idx].name.clone())
}

/// pcap 设备枚举（windows = Npcap；macOS = 系统 libpcap）。两者结果同构。
#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
pub(crate) fn list_devices() -> anyhow::Result<Vec<DeviceInfo>> {
    let devs = pcap::Device::list().map_err(|e| anyhow::anyhow!("pcap 设备枚举失败：{e}"))?;
    Ok(devs
        .into_iter()
        .map(|d| DeviceInfo {
            name: d.name,
            desc: d.desc,
            loopback: d.flags.is_loopback(),
        })
        .collect())
}

#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
pub(crate) fn open_capture(dev: &str) -> anyhow::Result<pcap::Capture<pcap::Active>> {
    let platform = if cfg!(windows) { "Npcap" } else { "libpcap" };
    let cap = pcap::Capture::from_device(dev)
        .map_err(|e| anyhow::anyhow!("打开 {platform} 设备 `{dev}` 失败：{e}"))?
        .timeout(100)
        .promisc(true)
        .immediate_mode(true)
        .open()
        .map_err(|e| anyhow::anyhow!("打开 {platform} 设备 `{dev}` 失败：{e}"))?;
    // 发送的是完整以太网帧：只接受 Ethernet 链路类型（普通网卡均 EN10MB；
    // lo0 回环为 DLT_NULL，raw 发送不支持——回环目标自动选 lo0 时会在这里报错）
    if cap.get_datalink() != pcap::Linktype::ETHERNET {
        anyhow::bail!(
            "设备 `{dev}` 链路类型不是 Ethernet（{:?}）——raw 发送仅支持 EN10MB 设备",
            cap.get_datalink()
        );
    }
    // 只收"入向"包：pcap_sendpacket 注入的帧会被本句柄看到，direction=In 把刚发
    // 的帧过滤掉（否则 --wait 时可能把自己的发送帧误匹配成应答）。失败忽略：
    // 少数驱动不支持 direction 过滤，代价只是多收几帧杂包。
    let _ = cap.direction(pcap::Direction::In);
    Ok(cap)
}

// ── IPv4 以太网封装 ─────────────────────────────────────────────

#[cfg(windows)]
fn wrap_ip4(bytes: &[u8], target: &SocketAddr) -> anyhow::Result<Vec<u8>> {
    if bytes.len() < 20 || (bytes[0] >> 4) != 4 {
        anyhow::bail!("包不是合法 IPv4 报文");
    }
    let ip4 = match target.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => anyhow::bail!("目标不是 IPv4 地址：{}", target.ip()),
    };
    let (dst_mac, src_mac) = resolve_macs_win(ip4)?;
    wrap_eth(bytes, src_mac, dst_mac).ok_or_else(|| anyhow::anyhow!("包不是合法 IP 报文"))
}

/// Unix pcap（macOS / Linux feature=pcap）：用 `getifaddrs` 取接口 MAC，ARP 探测取下一跳 MAC。
#[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
fn wrap_ip4(bytes: &[u8], target: &SocketAddr) -> anyhow::Result<Vec<u8>> {
    if bytes.len() < 20 || (bytes[0] >> 4) != 4 {
        anyhow::bail!("包不是合法 IPv4 报文");
    }
    let ip4 = match target.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => anyhow::bail!("目标不是 IPv4 地址：{}", target.ip()),
    };
    // 找到通向目标的本地接口（UDP connect 路由探测）
    let local_ip = crate::engine::pkg::local_ip_for(target)
        .ok_or_else(|| anyhow::anyhow!("macOS: 无法确定到 {ip4} 的本地出口接口"))?;
    let iface_name = macos_find_iface_for_ip(local_ip)?;
    let src_mac = macos_iface_mac(&iface_name)?;
    let dst_mac = macos_resolve_dst_mac(ip4, &iface_name)?;
    wrap_eth(bytes, src_mac, dst_mac).ok_or_else(|| anyhow::anyhow!("包不是合法 IP 报文"))
}

// ── IPv6 以太网封装 ─────────────────────────────────────────────

/// Windows IPv6：v1 仅支持回环（`::1`，经 Npcap Loopback Adapter）。
#[cfg(windows)]
fn wrap_ip6(bytes: &[u8], target: &SocketAddr) -> anyhow::Result<Vec<u8>> {
    if bytes.len() < 40 || (bytes[0] >> 4) != 6 {
        anyhow::bail!("包不是合法 IPv6 报文");
    }
    match target.ip() {
        // Npcap Loopback Adapter：虚拟以太网，src/dst MAC 不检查
        std::net::IpAddr::V6(v6) if v6.is_loopback() => {
            wrap_eth(bytes, [0u8; 6], [0u8; 6]).ok_or_else(|| anyhow::anyhow!("包不是合法 IP 报文"))
        }
        ip => anyhow::bail!(
            "Windows raw IPv6 暂仅支持回环目标（::1，经 Npcap Loopback Adapter）；\
             目标 {ip} 需要 ND 邻居解析（Win7 无 GetIpNetTable2，v6 邻居表不可枚举）"
        ),
    }
}

/// Unix pcap（macOS / Linux feature=pcap）IPv6：v1 仅支持回环（`::1`）。
#[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
fn wrap_ip6(bytes: &[u8], target: &SocketAddr) -> anyhow::Result<Vec<u8>> {
    if bytes.len() < 40 || (bytes[0] >> 4) != 6 {
        anyhow::bail!("包不是合法 IPv6 报文");
    }
    match target.ip() {
        std::net::IpAddr::V6(v6) if v6.is_loopback() => {
            // lo0 回环为 DLT_NULL（macOS）或 EN10MB（Linux）——
            // macOS 的 lo0 非 Ethernet，pcap 发送会失败
            if cfg!(target_os = "macos") {
                anyhow::bail!(
                    "macOS raw IPv6 回环（::1）经 lo0 为 DLT_NULL 链路类型，不支持以太网帧发送；\
                     请用不带 eth 层的包（ipv6 外层可通过 IPPROTO_RAW 发送）"
                )
            } else {
                // Linux lo0 为 EN10MB，可以用 pcap 发送
                wrap_eth(bytes, [0u8; 6], [0u8; 6])
                    .ok_or_else(|| anyhow::anyhow!("包不是合法 IP 报文"))
            }
        }
        ip => anyhow::bail!(
            "raw IPv6 暂仅支持回环目标（::1）；\
             目标 {ip} 需要 ND 邻居解析，暂未支持"
        ),
    }
}

// ── Windows MAC 解析 ────────────────────────────────────────────

/// 解析 (dst MAC, src MAC)：下一跳（`GetBestRoute`，0.0.0.0 = 直连目标）→ ARP 缓存
/// （`GetIpNetTable`；未命中先发 1 字节 UDP 触发内核 ARP 再查）→ 本机接口 MAC
/// （`GetIfEntry`）。ARP/接口查询失败用广播/全零 MAC 兜底并警告。
#[cfg(windows)]
fn resolve_macs_win(target: Ipv4Addr) -> anyhow::Result<([u8; 6], [u8; 6])> {
    let (next_hop, if_index) = next_hop_v4(target)?;
    let mut dst = arp_lookup(next_hop);
    if dst.is_none() {
        poke_arp(next_hop);
        std::thread::sleep(Duration::from_millis(120));
        dst = arp_lookup(next_hop);
    }
    let dst_mac = match dst {
        Some(m) => m,
        None => {
            let _ = crate::output::writeln_orange(
                &mut crate::output::stderr(),
                format!("  {}", t!("engine.note_arp_miss", next_hop = next_hop)),
            );
            [0xff; 6]
        }
    };
    let src_mac = match local_mac(if_index) {
        Ok(m) => m,
        Err(e) => {
            let _ = crate::output::writeln_orange(
                &mut crate::output::stderr(),
                format!(
                    "  {}",
                    t!("engine.note_iface_mac", if_index = if_index, error = e)
                ),
            );
            [0u8; 6]
        }
    };
    Ok((dst_mac, src_mac))
}

#[cfg(windows)]
fn next_hop_v4(target: Ipv4Addr) -> anyhow::Result<(Ipv4Addr, u32)> {
    let mut row = MibIpForwardRow::default();
    // dwDestAddr 用网络字节序；返回行 dwForwardNextHop 也是网络字节序（0.0.0.0 = 直连）
    let rc = unsafe { iphlp::GetBestRoute(u32::from_ne_bytes(target.octets()), 0, &mut row) };
    if rc != iphlp::NO_ERROR {
        anyhow::bail!("GetBestRoute({target}) 失败：{rc}");
    }
    let nh = Ipv4Addr::from(u32::to_ne_bytes(row.next_hop));
    Ok((if nh.is_unspecified() { target } else { nh }, row.if_index))
}

#[cfg(windows)]
fn arp_lookup(ip: Ipv4Addr) -> Option<[u8; 6]> {
    let want = u32::from_ne_bytes(ip.octets());
    let mut size: u32 = 0;
    // 第一次调用只取所需大小（返回 ERROR_INSUFFICIENT_BUFFER = 122）
    if unsafe { iphlp::GetIpNetTable(std::ptr::null_mut(), &mut size, 0) }
        != iphlp::ERROR_INSUFFICIENT_BUFFER
    {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    if unsafe { iphlp::GetIpNetTable(buf.as_mut_ptr().cast(), &mut size, 0) } != iphlp::NO_ERROR {
        return None;
    }
    if buf.len() < 4 {
        return None;
    }
    // MIB_IPNETTABLE：dwNumEntries(4B) + MIB_IPNETROW[]（行偏移见 MibIpNetRow：
    // dwIndex 0 / dwPhysAddrLen 4 / bPhysAddr 8 / dwAddr 16 / dwType 20）
    let num = u32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
    for i in 0..num {
        let base = 4 + i * std::mem::size_of::<MibIpNetRow>();
        if base + std::mem::size_of::<MibIpNetRow>() > buf.len() {
            break;
        }
        let row = &buf[base..base + std::mem::size_of::<MibIpNetRow>()];
        let addr = u32::from_ne_bytes(row[16..20].try_into().unwrap());
        if addr == want {
            let len = u32::from_ne_bytes(row[4..8].try_into().unwrap()) as usize;
            if len >= 6 {
                return Some(row[8..14].try_into().unwrap());
            }
        }
    }
    None
}

#[cfg(windows)]
fn poke_arp(ip: Ipv4Addr) {
    // 向该地址发 1 字节 UDP（丢弃端口 9）：内核为发送数据报会先解析 ARP
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        let _ = s.send_to(&[0u8; 1], (ip, 9));
    }
}

#[cfg(windows)]
fn local_mac(if_index: u32) -> anyhow::Result<[u8; 6]> {
    let mut row = MibIfRow {
        dw_index: if_index,
        ..Default::default()
    };
    let rc = unsafe { iphlp::GetIfEntry(&mut row) };
    if rc != iphlp::NO_ERROR {
        anyhow::bail!("GetIfEntry({if_index}) 失败：{rc}");
    }
    if (row.dw_phys_addr_len as usize) < 6 {
        anyhow::bail!("接口 {if_index} 物理地址长度异常：{}", row.dw_phys_addr_len);
    }
    Ok(row.b_phys_addr[..6].try_into().unwrap())
}

// ── Unix pcap MAC 解析（getifaddrs / ARP）───────────────────────
// macOS 和 Linux（feature=pcap）共用。

/// Unix pcap：通过 `getifaddrs` 找到拥有指定 IP 的接口名（如 `en0` / `eth0`）。
#[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
fn macos_find_iface_for_ip(local_ip: std::net::IpAddr) -> anyhow::Result<String> {
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            anyhow::bail!("getifaddrs 失败：{}", std::io::Error::last_os_error());
        }
        let _guard = IfaddrsGuard(ifap);
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                let sa = &*ifa.ifa_addr;
                if sa.sa_family == libc::AF_INET as libc::sa_family_t && local_ip.is_ipv4() {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if std::net::IpAddr::V4(ip) == local_ip {
                        let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                            .to_string_lossy()
                            .into_owned();
                        return Ok(name);
                    }
                }
            }
            cur = ifa.ifa_next;
        }
    }
    anyhow::bail!("macOS: 找不到 IP {local_ip} 对应的网络接口")
}

/// Unix pcap：通过 `getifaddrs` + `AF_LINK` 取接口的 MAC 地址。
#[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
fn macos_iface_mac(iface_name: &str) -> anyhow::Result<[u8; 6]> {
    // getifaddrs + AF_LINK（macOS）/ AF_PACKET（Linux）取 MAC
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            anyhow::bail!("getifaddrs 失败：{}", std::io::Error::last_os_error());
        }
        let _guard = IfaddrsGuard(ifap);
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                .to_string_lossy()
                .into_owned();
            // macOS 用 AF_LINK + sockaddr_dl；Linux 用 AF_PACKET + sockaddr_ll
            #[cfg(target_os = "macos")]
            let is_link = !ifa.ifa_addr.is_null()
                && (*ifa.ifa_addr).sa_family == libc::AF_LINK as libc::sa_family_t;
            #[cfg(target_os = "linux")]
            let is_link = !ifa.ifa_addr.is_null()
                && (*ifa.ifa_addr).sa_family == libc::AF_PACKET as libc::sa_family_t;
            if name == iface_name && is_link {
                #[cfg(target_os = "macos")]
                {
                    // sockaddr_dl：sdl_data[sdl_nlen..sdl_nlen+6] 为 MAC
                    let sdl = ifa.ifa_addr as *const libc::sockaddr_dl;
                    let nlen = (*sdl).sdl_nlen as usize;
                    let data = (*sdl).sdl_data.as_ptr();
                    let mut mac = [0u8; 6];
                    for i in 0..6 {
                        mac[i] = *data.add(nlen + i) as u8;
                    }
                    return Ok(mac);
                }
                #[cfg(target_os = "linux")]
                {
                    // sockaddr_ll：sll_addr[0..6] 为 MAC
                    let sll = ifa.ifa_addr as *const libc::sockaddr_ll;
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&(&(*sll).sll_addr)[..6]);
                    return Ok(mac);
                }
            }
            cur = ifa.ifa_next;
        }
    }
    anyhow::bail!("接口 {iface_name} 无 MAC 地址（非物理以太网？）")
}

/// Unix pcap：解析目标 IPv4 的下一跳 MAC。
///
/// 策略：先发 UDP 触发内核 ARP 解析，然后查系统 ARP 表。
#[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
fn macos_resolve_dst_mac(target: Ipv4Addr, iface: &str) -> anyhow::Result<[u8; 6]> {
    // 1. 发 1 字节 UDP 触发内核 ARP 解析
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        let _ = s.send_to(&[0u8; 1], (target, 9));
    }
    std::thread::sleep(Duration::from_millis(100));

    // 2. 查系统 ARP 表
    if let Some(mac) = unix_arp_table_lookup(target) {
        return Ok(mac);
    }

    // 3. 再试一次（ARP 可能还在路上）
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        let _ = s.send_to(&[0u8; 1], (target, 9));
    }
    std::thread::sleep(Duration::from_millis(150));
    if let Some(mac) = unix_arp_table_lookup(target) {
        return Ok(mac);
    }

    // 4. 兜底：广播 MAC
    let _ = crate::output::writeln_orange(
        &mut crate::output::stderr(),
        format!("{}ARP 解析 {target} 失败（接口 {iface}），使用广播 MAC 兜底", indent(1)),
    );
    Ok([0xff; 6])
}

/// Unix pcap：查系统 ARP 表（Linux 用 /proc/net/arp，macOS 用 arp -an）。
#[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
fn unix_arp_table_lookup(target: Ipv4Addr) -> Option<[u8; 6]> {
    // Linux: /proc/net/arp 更快更可靠
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/net/arp").ok()?;
        let target_str = target.to_string();
        for line in content.lines().skip(1) {
            // 格式：IP HWType Flags HWAddress Mask Device
            // 192.168.1.1 0x2 0x2 aa:bb:cc:dd:ee:ff * eth0
            if !line.contains(&target_str) {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 && parts[0] == target_str {
                if let Some(mac) = parse_mac(parts[3]) {
                    return Some(mac);
                }
            }
        }
        None
    }
    // macOS: arp -an
    #[cfg(not(target_os = "linux"))]
    {
        let output = std::process::Command::new("arp")
            .args(["-an"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let target_str = target.to_string();
        for line in stdout.lines() {
            // 格式：? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
            if !line.contains(&target_str) {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            for (i, part) in parts.iter().enumerate() {
                if *part == "at" && i + 1 < parts.len() {
                    let mac_str = parts[i + 1];
                    if let Some(mac) = parse_mac(mac_str) {
                        return Some(mac);
                    }
                }
            }
        }
        None
    }
}

/// 解析 "aa:bb:cc:dd:ee:ff" 格式的 MAC 地址。
#[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

/// `getifaddrs` 结果的 RAII 守卫。
#[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
struct IfaddrsGuard(*mut libc::ifaddrs);

#[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
impl Drop for IfaddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

// ── 回包等待（Windows / macOS 共用）────────────────────────────

/// `--wait`：在已打开的抓包句柄上按 sniffer / ICMP echo id+seq 匹配应答，直到超时。
///
/// `sent_frame` 是刚注入的完整帧：pcap 会把发送帧回读给抓包句柄（`direction(In)`
/// 过滤在部分驱动/虚拟网卡上不生效），与发送帧相同的帧是"自己"，直接跳过——
/// 否则 `--wait` 可能把自己的 echo request 误匹配成应答（假阳性，RTT ~0.1ms）。
#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
fn wait_reply(
    cap: &mut pcap::Capture<pcap::Active>,
    secs: f64,
    pkt: &PacketSpec,
    sent_frame: &[u8],
    sniffer: Option<&crate::engine::pkg::SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<Option<Reply>> {
    // 非 ICMP 且无 sniffer：raw 模式下不等待（与 Linux 行为一致）
    if sniffer.is_none() && crate::engine::pkg::icmp_echo_ids(pkt).is_none() {
        return Ok(None);
    }
    let t0 = Instant::now();
    let deadline = Duration::from_secs_f64(secs);
    loop {
        let remaining = deadline.saturating_sub(t0.elapsed());
        if remaining.is_zero() {
            return Ok(None);
        }
        match cap.next_packet() {
            Ok(p) => {
                if p.data == sent_frame {
                    continue; // 自己刚发的帧（真回包不可能与请求逐字节相同）
                }
                let rtt = t0.elapsed().as_secs_f64() * 1000.0;
                if let Some((bytes, matched)) =
                    crate::engine::pkg::match_reply(p.data, pkt, sniffer, sent_report)?
                {
                    return Ok(Some(Reply {
                        rtt,
                        bytes,
                        matched,
                    }));
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(anyhow::anyhow!("pcap 捕获失败：{e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_eth_ipv4() {
        let ip = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 127, 0, 0, 1,
            127, 0, 0, 1,
        ];
        let f = wrap_eth(&ip, [1, 2, 3, 4, 5, 6], [0xff; 6]).unwrap();
        assert_eq!(f.len(), 14 + 20);
        assert_eq!(&f[0..6], &[0xff; 6]); // dst MAC 在前
        assert_eq!(&f[6..12], &[1, 2, 3, 4, 5, 6]); // src MAC 在后
        assert_eq!(&f[12..14], &[0x08, 0x00]); // IPv4 ethertype
        assert_eq!(&f[14..], &ip);
    }

    #[test]
    fn wrap_eth_ipv6() {
        let ip = [0x60u8; 40];
        let f = wrap_eth(&ip, [0u8; 6], [0u8; 6]).unwrap();
        assert_eq!(f.len(), 14 + 40);
        assert_eq!(&f[12..14], &[0x86, 0xDD]); // IPv6 ethertype
    }

    #[test]
    fn wrap_eth_rejects_non_ip() {
        assert!(wrap_eth(&[0x00; 20], [0u8; 6], [0u8; 6]).is_none());
        assert!(wrap_eth(&[], [0u8; 6], [0u8; 6]).is_none());
    }

    #[test]
    fn pick_device_by_name_and_desc() {
        let devs = vec![
            DeviceInfo {
                name: r"\Device\NPF_{AAA}".into(),
                desc: Some("Realtek PCIe Ethernet".into()),
                loopback: false,
            },
            DeviceInfo {
                name: r"\Device\NPF_{BBB}".into(),
                desc: Some("Npcap Loopback Adapter".into()),
                loopback: true,
            },
        ];
        // 名字精确匹配（不区分大小写）
        assert_eq!(
            pick_device(&devs, false, Some(r"\DEVICE\npf_{aaa}")),
            Some(0)
        );
        // 描述子串匹配
        assert_eq!(pick_device(&devs, false, Some("realtek")), Some(0));
        assert_eq!(pick_device(&devs, false, Some("loopback")), Some(1));
        assert_eq!(pick_device(&devs, false, Some("nope")), None);
    }

    #[test]
    fn pick_device_defaults() {
        let devs = vec![
            DeviceInfo {
                name: "loop".into(),
                desc: None,
                loopback: true,
            },
            DeviceInfo {
                name: "eth".into(),
                desc: None,
                loopback: false,
            },
        ];
        assert_eq!(pick_device(&devs, false, None), Some(1)); // 非回环目标 → 首个非回环
        assert_eq!(pick_device(&devs, true, None), Some(0)); // 回环目标 → 回环设备
        let only_loop = vec![DeviceInfo {
            name: "loop".into(),
            desc: None,
            loopback: true,
        }];
        assert_eq!(pick_device(&only_loop, false, None), Some(0)); // 全回环 → 兜底第一个
        assert_eq!(pick_device(&[], false, None), None);
    }

    #[test]
    fn mib_row_layouts() {
        // 与 Windows SDK 文档布局一致（全 DWORD/固定数组，无填充；x86/x64 同构）
        assert_eq!(std::mem::size_of::<MibIpForwardRow>(), 56);
        assert_eq!(std::mem::size_of::<MibIpNetRow>(), 24);
        assert_eq!(std::mem::size_of::<MibIfRow>(), 860);
    }

    #[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
    #[test]
    fn parse_mac_valid() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac("00:11:22:33:44:55"),
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[cfg(all(not(windows), any(target_os = "macos", feature = "pcap")))]
    #[test]
    fn parse_mac_invalid() {
        assert_eq!(parse_mac("invalid"), None);
        assert_eq!(parse_mac("aa:bb:cc"), None);
        assert_eq!(parse_mac("gg:hh:ii:jj:kk:ll"), None);
    }
}
