//! pcap 设备抽象：DeviceInfo / 设备选择 / 以太网封装辅助。

#[cfg(any(windows, target_os = "macos", feature = "pcap", test))]
use std::net::IpAddr;

/// Npcap/libpcap 设备抽象（纯数据；windows/macOS 由 `pcap::Device` 填充，测试直接构造）。
#[cfg(any(windows, target_os = "macos", feature = "pcap", test))]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DeviceInfo {
    pub name: String,
    pub desc: Option<String>,
    pub loopback: bool,
    /// 设备上配置的 IP 地址（服务端抓包按绑定 IP 匹配设备用；发送路径不依赖）。
    pub addrs: Vec<IpAddr>,
}

/// 格式化设备列表：每行一个设备，Windows 下同时显示显示名。
///
/// 格式示例：
/// - Windows: `  \Device\NPF_{...} (Intel Ethernet Connection I219-V)`
/// - 其它平台: `  \Device\NPF_{...}` 或 `  en0`
#[cfg(any(windows, target_os = "macos", feature = "pcap", test))]
pub(crate) fn format_device_list(devs: &[DeviceInfo]) -> String {
    devs.iter()
        .map(|d| {
            if let Some(desc) = &d.desc
                && !desc.is_empty()
            {
                return format!("  {} ({})", d.name, desc);
            }
            format!("  {}", d.name)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 选择发送/抓包设备：`--iface` 按名字（不区分大小写）精确匹配，或描述子串匹配；
/// 否则回环目标优先回环设备，其余取首个非回环设备（全回环时兜底取第一个）。
/// （服务端抓包不用本函数：0.0.0.0 未指定绑定需开全部设备，见 `capture_devices`。）
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

/// 服务端抓包目标设备索引集合（Windows/macOS 共用），等价 Linux AF_PACKET 的
/// 「全接口」语义：
/// - 通配绑定（0.0.0.0/::）→ **全部设备**（回环 + 所有非回环）。
/// - 回环绑定 → 回环设备（无则兜底第一个）。
/// - 指定非回环 IP → 拥有该 IP 的设备（IPv4/IPv6 均可）；找不到则首个非回环。
#[cfg(any(windows, target_os = "macos", feature = "pcap", test))]
pub(crate) fn capture_devices(devs: &[DeviceInfo], addr: std::net::SocketAddr) -> Vec<usize> {
    let ip = addr.ip();
    if ip.is_unspecified() {
        return (0..devs.len()).collect();
    }
    if ip.is_loopback() {
        if let Some(i) = devs.iter().position(|d| d.loopback) {
            return vec![i];
        }
        return if devs.is_empty() { Vec::new() } else { vec![0] };
    }
    if let Some(i) = devs.iter().position(|d| d.addrs.contains(&ip)) {
        return vec![i];
    }
    devs.iter()
        .position(|d| !d.loopback)
        .map(|i| vec![i])
        .unwrap_or_default()
}

/// IP 版本 → 以太网类型（IPv4 0x0800 / IPv6 0x86DD）。
#[cfg(any(windows, target_os = "macos", feature = "pcap", test))]
pub(crate) fn ethertype_of(ip: &[u8]) -> Option<u16> {
    match ip.first()? >> 4 {
        4 => Some(0x0800),
        6 => Some(0x86DD),
        _ => None,
    }
}

/// 裸 IP 包 → 以太网帧（14B 头 + payload；非法 IP 返回 None）。
#[cfg(any(windows, target_os = "macos", feature = "pcap", test))]
pub(crate) fn wrap_eth(ip: &[u8], src_mac: [u8; 6], dst_mac: [u8; 6]) -> Option<Vec<u8>> {
    let ethertype = ethertype_of(ip)?;
    let mut frame = Vec::with_capacity(14 + ip.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(ip);
    Some(frame)
}
