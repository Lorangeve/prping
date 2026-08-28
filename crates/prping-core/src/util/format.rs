//! 格式化与协议原语：随机数、载荷填充、时间戳、字节格式化、UDP 触发协议。

/// TCP 接收模式触发字节：客户端发送 `[0xFF]` 进入接收模式，服务端持续回送数据。
pub const TCP_RECEIVE_TRIGGER: u8 = 0xFF;

/// 随机 u16（用于 ICMP id / TCP 源端口等）。
pub fn rand_u16() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u16
}

/// 随机 u32（用于 TCP seq：Unix raw TCP 路径 + Windows Npcap 路径 tcpwin.rs）。
pub fn rand_u32() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u32
}

/// 载荷填充：`0..255` 循环（各模式统一的 echo 载荷格式）。
pub fn echo_fill(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }
}

/// Unix 时间戳（秒），用于 JSON 输出的 `ts` 字段。
pub fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 字节切片转为连续小写十六进制字符串（如 `0a1b2c`）。
pub fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 字节数格式化为人类可读字符串（B / KiB / MiB / GiB / TiB）。
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{:.2} {}", size, UNITS[unit])
    }
}

/// 解析逗号分隔的 `k=v` 参数对（核心逻辑，无错误信息包装）。
///
/// 跳过空项，trim 键值。调用方包装错误信息。
pub fn parse_kv_pairs(s: &str) -> impl Iterator<Item = (&str, &str)> {
    s.split(',').filter_map(|pair| {
        let pair = pair.trim();
        if pair.is_empty() {
            return None;
        }
        pair.split_once('=').map(|(k, v)| (k.trim(), v.trim()))
    })
}

/// 解析 UDP 接收模式触发包：`[0xFF, 0xFF, size(2B BE), count(4B BE)]`。
///
/// 返回 `Some((size, count))`，失败返回 `None`。
pub fn parse_udp_receive_trigger(data: &[u8]) -> Option<(usize, u32)> {
    if data.len() == 8 && data[0] == 0xFF && data[1] == 0xFF {
        let size = u16::from_be_bytes([data[2], data[3]]) as usize;
        let count = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        Some((size, count))
    } else {
        None
    }
}

/// 构造 UDP 接收模式触发包：`[0xFF, 0xFF, size(2B BE), count(4B BE)]`。
pub fn udp_receive_trigger(size: usize, count: u32) -> Vec<u8> {
    let size = size.clamp(1, crate::MAX_UDP) as u16;
    let mut b = vec![0u8; 8];
    b[0] = 0xFF;
    b[1] = 0xFF;
    b[2..4].copy_from_slice(&size.to_be_bytes());
    b[4..8].copy_from_slice(&count.to_be_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_receive_trigger() {
        let b = udp_receive_trigger(1024, 7);
        assert_eq!(b.len(), 8);
        assert_eq!(&b[..2], &[0xFF, 0xFF]);
        assert_eq!(u16::from_be_bytes([b[2], b[3]]), 1024);
        assert_eq!(u32::from_be_bytes([b[4], b[5], b[6], b[7]]), 7);
    }
    #[test]
    fn test_udp_receive_trigger_clamp() {
        let b = udp_receive_trigger(1_000_000, 1);
        assert_eq!(u16::from_be_bytes([b[2], b[3]]), 65507);
    }
}
