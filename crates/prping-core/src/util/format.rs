//! 格式化与协议原语：随机数、载荷填充、时间戳、字节格式化、UDP 触发协议。

/// 随机 u16（用于 ICMP id / TCP 源端口等）。
pub fn rand_u16() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u16
}

/// 随机 u32（用于 TCP seq 等）。
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

/// 构造 UDP 接收模式触发包：`[0xFF, 0xFF, size(2B BE), count(4B BE)]`。
pub fn udp_receive_trigger(size: usize, count: u32) -> Vec<u8> {
    let size = size.clamp(1, 65507) as u16;
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
