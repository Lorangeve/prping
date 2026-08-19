//! MTU 探测模式（`--mtu`）：ICMP echo + DF 位 + 变长载荷二分，找最大不分片尺寸。
//!
//! 对标 `ping -M do -s N` 的自动版本：探测每个载荷大小时带「不分片」位，
//! 收到 echo 回复 → 该尺寸可过；收到 ICMP Fragmentation Needed（type 3 code 4）
//! → 过大，且报文中携带下一跳 MTU。二分收敛到最大可通过载荷，MTU = 载荷 + 28
//! （IPv4：20 字节 IP 头 + 8 字节 ICMP 头）。
//!
//! 平台差异：DF 位通过 setsockopt 设置——Linux `IP_MTU_DISCOVER=IP_PMTUDISC_DO`、
//! Windows `IP_DONTFRAGMENT=1`、macOS/BSD `IP_DONTFRAG`。

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rust_i18n::t;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::output;
use crate::stats;
use crate::util::{self, PingConfig};

/// MTU 探测结果。
#[derive(Debug, Clone)]
pub struct MtuReport {
    /// 最大可通过的 ICMP 载荷字节数。
    pub payload_max: usize,
    /// 路径 MTU = payload_max + 28（IPv4）。
    pub mtu: usize,
    /// 探测途中 Fragmentation Needed 报文报回的 MTU（若有，取最小）。
    pub frag_needed_mtu: Option<usize>,
    /// 备注（如探测超时次数）。
    pub notes: Vec<String>,
}

#[derive(Debug)]
enum ProbeOutcome {
    /// echo 回复（该尺寸可过）。
    Ok,
    /// Fragmentation Needed，携带下一跳 MTU。
    FragNeeded(usize),
    Timeout,
    /// 不可达 / TTL 超时 / 其他错误。
    Fail(String),
}

/// 探测入口：打印过程行 + 汇总（文本 / JSON），返回报告。
pub fn probe_mtu(cfg: &PingConfig) -> anyhow::Result<MtuReport> {
    let addr = util::resolve(&cfg.host, 0, cfg.v4, cfg.v6)?;
    let target = match addr.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => anyhow::bail!(t!("errors.mtu_ipv4_only")),
    };
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .map_err(|e| anyhow::anyhow!(t!("errors.raw_socket", error = e.to_string())))?;
    set_df(&sock)?;
    if let Some(src) = cfg.source.filter(IpAddr::is_ipv4) {
        sock.bind(&SockAddr::from(SocketAddr::new(src, 0)))?;
    }
    let ident = rand_id();
    let target_sa = SocketAddr::new(addr.ip(), 0);
    let mut w = termcolor::StandardStream::stdout(termcolor::ColorChoice::Auto);

    // 基本连通性：小包必须有回显，否则 ICMP 多半被防火墙丢弃
    match probe(&sock, target_sa, ident, 0, 32, Duration::from_secs(2))? {
        ProbeOutcome::Ok => {}
        ProbeOutcome::FragNeeded(_) => {} // 理论不可能（32B 也要分片），继续
        ProbeOutcome::Timeout => {
            anyhow::bail!(t!("errors.mtu_no_reply", target = target.to_string()));
        }
        ProbeOutcome::Fail(e) => anyhow::bail!(e),
    }

    // 二分 [0, 65507]（IPv4 最大 ICMP 载荷）
    let mut lo = 0usize;
    let mut hi = 65507usize;
    let mut frag_mtu: Option<usize> = None;
    let mut notes: Vec<String> = Vec::new();
    let mut seq = 1u16;
    let probe_timeout = Duration::from_millis(800);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        let outcome = match probe(&sock, target_sa, ident, seq, mid, probe_timeout)? {
            ProbeOutcome::Ok => ProbeOutcome::Ok,
            ProbeOutcome::FragNeeded(m) => ProbeOutcome::FragNeeded(m),
            ProbeOutcome::Timeout => {
                // 超时重试一次（区分丢包与真正超限）
                match probe(&sock, target_sa, ident, seq, mid, probe_timeout)? {
                    ProbeOutcome::Ok => ProbeOutcome::Ok,
                    ProbeOutcome::FragNeeded(m) => ProbeOutcome::FragNeeded(m),
                    ProbeOutcome::Timeout => {
                        notes.push(
                            t!(
                                "mtu.timeout_note",
                                size = mid,
                                timeout = probe_timeout.as_secs_f64()
                            )
                            .to_string(),
                        );
                        ProbeOutcome::Timeout
                    }
                    ProbeOutcome::Fail(e) => ProbeOutcome::Fail(e),
                }
            }
            ProbeOutcome::Fail(e) => ProbeOutcome::Fail(e),
        };
        seq = seq.wrapping_add(1);
        let (fits, reported) = match outcome {
            ProbeOutcome::Ok => (true, None),
            ProbeOutcome::FragNeeded(m) => {
                frag_mtu = Some(frag_mtu.map_or(m, |x| x.min(m)));
                (false, Some(m))
            }
            ProbeOutcome::Timeout => (false, None),
            ProbeOutcome::Fail(e) => anyhow::bail!(e),
        };
        if !stats::json() {
            let line = if fits {
                format!("  payload={mid:>5} → {}", t!("mtu.ok"))
            } else {
                match reported {
                    Some(m) => format!("  payload={mid:>5} → {} (mtu={m})", t!("mtu.frag")),
                    None => format!("  payload={mid:>5} → {}", t!("mtu.fail")),
                }
            };
            if fits {
                output::print_green(&mut w, line)?;
            } else {
                output::print_red(&mut w, line)?;
            }
            writeln!(w)?;
        }
        if fits {
            lo = mid;
        } else {
            hi = mid.saturating_sub(1);
        }
    }

    let report = MtuReport {
        payload_max: lo,
        mtu: lo + 28,
        frag_needed_mtu: frag_mtu,
        notes,
    };
    if stats::json() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut line = format!(
            "{{\"type\":\"mtu\",\"target\":\"{}\",\"ts\":{ts},\"summary\":true,\"payload_max\":{},\"mtu\":{}",
            cfg.host.replace('"', "\\\""),
            report.payload_max,
            report.mtu
        );
        if let Some(m) = report.frag_needed_mtu {
            line += &format!(",\"frag_needed_mtu\":{m}");
        }
        line.push('}');
        println!("{line}");
    } else {
        println!(
            "\n{}",
            t!(
                "mtu.summary",
                host = cfg.host,
                mtu = report.mtu,
                payload = report.payload_max
            )
        );
        if let Some(m) = report.frag_needed_mtu {
            println!("  {}", t!("mtu.frag_needed_mtu", mtu = m));
        }
        for n in &report.notes {
            output::print_dim(&mut w, format!("  {n}"))?;
            writeln!(w)?;
        }
    }
    Ok(report)
}

/// 单次探测：发带 DF 的 echo，等待回复/分片需要/超时。
fn probe(
    sock: &Socket,
    target: SocketAddr,
    ident: u16,
    seq: u16,
    payload: usize,
    timeout: Duration,
) -> anyhow::Result<ProbeOutcome> {
    let pkt = build_echo(ident, seq, payload);
    sock.send_to(&pkt, &SockAddr::from(target))?;
    let deadline = Instant::now() + timeout;
    let mut buf: [std::mem::MaybeUninit<u8>; 8192] = [std::mem::MaybeUninit::new(0u8); 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(ProbeOutcome::Timeout);
        }
        sock.set_read_timeout(Some(remaining))?;
        match sock.recv_from(&mut buf) {
            Ok((n, _src)) => {
                let data = util::init_slice(&buf, n);
                if let Some(outcome) = classify(data, ident, seq) {
                    return Ok(outcome);
                }
                // 杂包（其他探测的回复/无关 ICMP），继续等
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(ProbeOutcome::Timeout);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// 分类收到的 IPv4 报文：echo 回复 / Fragmentation Needed / 其他。
fn classify(buf: &[u8], ident: u16, seq: u16) -> Option<ProbeOutcome> {
    if buf.len() < 28 {
        return None;
    }
    let ihl = ((buf[0] & 0x0F) as usize) * 4;
    let icmp = buf.get(ihl..)?;
    if icmp.len() < 8 {
        return None;
    }
    match icmp[0] {
        0 => {
            // echo reply：校验 id/seq
            if u16::from_be_bytes([icmp[4], icmp[5]]) == ident
                && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
            {
                Some(ProbeOutcome::Ok)
            } else {
                None
            }
        }
        3 if icmp[1] == 4 => {
            // Fragmentation Needed：MTU 在 ICMP 数据区第 6-7 字节；
            // 引用报文里的 id 在第 8+4 字节（ICMP 头 8B + 引用 IP 头偏移 4）
            if icmp.len() >= 14 && u16::from_be_bytes([icmp[12], icmp[13]]) == ident {
                let mtu = u16::from_be_bytes([icmp[6], icmp[7]]) as usize;
                Some(ProbeOutcome::FragNeeded(mtu))
            } else {
                None
            }
        }
        3 => Some(ProbeOutcome::Fail(t!("mtu.unreachable").to_string())),
        11 => Some(ProbeOutcome::Fail(t!("mtu.ttl_exceeded").to_string())),
        _ => None,
    }
}

/// 构建 ICMP echo 报文（type 8，id/seq，载荷填充 0..255 循环）。
fn build_echo(ident: u16, seq: u16, payload: usize) -> Vec<u8> {
    let mut b = vec![0u8; 8 + payload];
    b[0] = 8;
    b[1] = 0;
    b[4] = (ident >> 8) as u8;
    b[5] = ident as u8;
    b[6] = (seq >> 8) as u8;
    b[7] = seq as u8;
    for i in 0..payload {
        b[8 + i] = (i % 256) as u8;
    }
    let c = crate::icmp::icmp_cksum(&b);
    b[2] = (c >> 8) as u8;
    b[3] = c as u8;
    b
}

fn rand_id() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u16
}

/// 设置 DF（不分片）位。
#[cfg(target_os = "linux")]
fn set_df(sock: &Socket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let val: libc::c_int = libc::IP_PMTUDISC_DO;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Windows：`IP_DONTFRAGMENT = 21`（Winsock2 IPPROTO_IP 选项）。
#[cfg(target_os = "windows")]
fn set_df(sock: &Socket) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    const IPPROTO_IP: libc::c_int = 0; // Winsock IPPROTO_IP
    const IP_DONTFRAGMENT: libc::c_int = 21;
    let val: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_socket() as libc::SOCKET,
            IPPROTO_IP,
            IP_DONTFRAGMENT,
            &val as *const _ as *const libc::c_char,
            std::mem::size_of::<libc::c_int>() as libc::c_int,
        )
    };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// macOS/BSD：`IP_DONTFRAG = 0x18`。
#[cfg(target_os = "macos")]
fn set_df(sock: &Socket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    const IP_DONTFRAG: libc::c_int = 0x18;
    let val: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            IP_DONTFRAG,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_packet_layout() {
        let b = build_echo(0x1234, 7, 10);
        assert_eq!(b.len(), 18);
        assert_eq!(b[0], 8, "type echo");
        assert_eq!(b[1], 0, "code 0");
        assert_eq!(b[4], 0x12);
        assert_eq!(b[5], 0x34);
        assert_eq!(b[6], 0);
        assert_eq!(b[7], 7);
        assert_eq!(b[8], 0, "载荷填充");
        assert_eq!(b[17], 9);
        // checksum 校验
        let mut copy = b.clone();
        copy[2] = 0;
        copy[3] = 0;
        assert_eq!(
            u16::from_be_bytes([b[2], b[3]]),
            crate::icmp::icmp_cksum(&copy)
        );
    }

    fn with_ip_header(icmp: &[u8]) -> Vec<u8> {
        // 伪造 20 字节 IPv4 头 + icmp 负载；id 放在 IP 头偏移 4
        let mut b = vec![0u8; 20 + icmp.len()];
        b[0] = 0x45;
        b[4] = 0x12;
        b[5] = 0x34;
        b[9] = 1;
        b[20..].copy_from_slice(icmp);
        b
    }

    #[test]
    fn classify_echo_reply() {
        // echo reply：type 0，id/seq 匹配
        let mut icmp = vec![0u8; 8 + 4];
        icmp[4] = 0x12;
        icmp[5] = 0x34;
        icmp[6] = 0;
        icmp[7] = 7;
        let buf = with_ip_header(&icmp);
        assert!(matches!(classify(&buf, 0x1234, 7), Some(ProbeOutcome::Ok)));
        // seq 不匹配 → 杂包
        assert!(classify(&buf, 0x1234, 8).is_none());
    }

    #[test]
    fn classify_frag_needed() {
        // Fragmentation Needed：type 3 code 4，MTU 字段 + 引用报文 id
        let mut icmp = vec![0u8; 8 + 20 + 8];
        icmp[0] = 3;
        icmp[1] = 4;
        icmp[6] = 0x05;
        icmp[7] = 0xDC; // MTU 1500
        icmp[8 + 4] = 0x12;
        icmp[8 + 5] = 0x34; // 引用报文 id
        let buf = with_ip_header(&icmp);
        match classify(&buf, 0x1234, 0) {
            Some(ProbeOutcome::FragNeeded(m)) => assert_eq!(m, 1500),
            other => panic!("期望 FragNeeded，得到 {other:?}"),
        }
        // id 不匹配 → 杂包
        let buf2 = with_ip_header(&icmp);
        let _ = buf2;
        icmp[8 + 5] = 0x35;
        let buf3 = with_ip_header(&icmp);
        assert!(classify(&buf3, 0x1234, 0).is_none());
    }

    #[test]
    fn classify_unreachable_and_ttl() {
        let mut icmp = vec![0u8; 8];
        icmp[0] = 3;
        icmp[1] = 1;
        let buf = with_ip_header(&icmp);
        assert!(matches!(classify(&buf, 0, 0), Some(ProbeOutcome::Fail(_))));
        let mut icmp2 = vec![0u8; 8];
        icmp2[0] = 11;
        let buf2 = with_ip_header(&icmp2);
        assert!(matches!(classify(&buf2, 0, 0), Some(ProbeOutcome::Fail(_))));
    }

    #[test]
    fn classify_garbage() {
        assert!(classify(b"", 0, 0).is_none());
        assert!(classify(&[0u8; 10], 0, 0).is_none());
    }
}
