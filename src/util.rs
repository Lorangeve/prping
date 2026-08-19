//! 共享工具：DNS 解析、运行循环控制、Ctrl+C 中断、UDP 触发协议、测试参数。

use rust_i18n::t;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

/// 一次测试的全部参数（收敛各模块的长参数列表）。
#[derive(Debug, Clone)]
pub struct PingConfig {
    pub host: String,
    pub port: u16,
    pub count: u64,
    pub duration: Option<f64>,
    pub interval: f64,
    /// 负载大小（`-l`，None = 未指定）。
    pub size: Option<usize>,
    pub quiet: bool,
    pub histogram: Option<crate::stats::HistogramSpec>,
    pub warmup: u64,
    pub v4: bool,
    pub v6: bool,
    pub parallel: u32,
    pub udp: bool,
    pub receive: bool,
    /// 带宽测试模式（`-b`）。
    pub bandwidth: bool,
    /// MTU 探测模式（`--mtu`）。
    pub mtu: bool,
    /// 是否打印时间线图（`-g`）。
    pub graph: bool,
    /// 源地址/网卡绑定（`-I`，None = 内核自动选）。
    pub source: Option<IpAddr>,
}

/// 解析 `-I` 参数：IP 地址，或 Linux 网卡名（取该网卡 IPv4 地址）。
pub fn resolve_source(s: &str) -> anyhow::Result<IpAddr> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(ip);
    }
    #[cfg(target_os = "linux")]
    if let Some(ip) = iface_to_ipv4(s)? {
        return Ok(IpAddr::V4(ip));
    }
    anyhow::bail!(
        "无法解析源地址 `{s}`：请用 IP 地址（如 192.168.1.10）；网卡名仅 Linux 支持（取 IPv4 地址）"
    )
}

/// Linux：`ioctl(SIOCGIFADDR)` 取网卡 IPv4 地址；网卡不存在/无 IPv4 → None。
#[cfg(target_os = "linux")]
fn iface_to_ipv4(name: &str) -> std::io::Result<Option<std::net::Ipv4Addr>> {
    use std::mem;
    // 接口名最长 IFNAMSIZ-1
    if name.len() >= libc::IFNAMSIZ {
        return Ok(None);
    }
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    for (i, b) in name.bytes().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    let r = unsafe { libc::ioctl(fd, libc::SIOCGIFADDR as libc::c_ulong, &mut ifr) };
    unsafe { libc::close(fd) };
    if r < 0 {
        return Ok(None);
    }
    let sin =
        unsafe { &*(&ifr.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in) };
    Ok(Some(std::net::Ipv4Addr::from(u32::from_be(
        sin.sin_addr.s_addr,
    ))))
}

/// 源绑定用的本地地址（0 端口）；`-I` 未给时按目标族取通配地址。
pub fn local_bind(target_is_v4: bool, source: Option<IpAddr>) -> SocketAddr {
    match source {
        Some(s) => SocketAddr::new(s, 0),
        None if target_is_v4 => "0.0.0.0:0".parse().unwrap(),
        None => "[::]:0".parse().unwrap(),
    }
}

/// 创建带大收发缓冲的 UDP socket（socket2 设置后包成 smol::Async）。
///
/// 内核默认 UDP 缓冲（~212KB）在带宽测试突发下会溢出丢包，这里放大到 4MB。
pub fn bind_udp(bind: SocketAddr) -> anyhow::Result<smol::Async<socket2::Socket>> {
    let domain = if bind.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock.set_recv_buffer_size(4 * 1024 * 1024)?;
    sock.set_send_buffer_size(4 * 1024 * 1024)?;
    sock.bind(&socket2::SockAddr::from(bind))?;
    sock.set_nonblocking(true)?;
    Ok(smol::Async::new(sock)?)
}

/// 异步 UDP 发送。
pub async fn udp_send(
    sock: &smol::Async<socket2::Socket>,
    payload: &[u8],
    addr: &SocketAddr,
) -> std::io::Result<usize> {
    sock.write_with(|s| s.send_to(payload, &socket2::SockAddr::from(*addr)))
        .await
}

/// 异步 UDP 接收，返回（字节数, 来源地址）。
pub async fn udp_recv(
    sock: &smol::Async<socket2::Socket>,
    buf: &mut [MaybeUninit<u8>],
) -> std::io::Result<(usize, SocketAddr)> {
    sock.read_with(|s| s.recv_from(buf))
        .await
        .map(|(n, a)| (n, a.as_socket().expect("UDP socket 地址必为 INET")))
}

/// 把已初始化的接收前缀转成 `&[u8]`（配合 `udp_recv`/`recv_from` 的 MaybeUninit 缓冲）。
pub fn init_slice(buf: &[MaybeUninit<u8>], n: usize) -> &[u8] {
    // SAFETY: 所有字节均以 0 初始化（调用方用 MaybeUninit::new(0) 构造），
    // 且 MaybeUninit<u8> 与 u8 布局一致。
    unsafe { std::mem::transmute(&buf[..n]) }
}

/// 配置多线程 executor：smol 全局 executor 默认单线程，`-P` 并发与服务端连接
/// 无法真正并行。在首次 `smol::spawn` 之前设置 `SMOL_THREADS`（spawn 时才惰性初始化）。
pub fn configure_executor_threads() {
    if std::env::var_os("SMOL_THREADS").is_none() {
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .max(2);
        // SAFETY: 进程启动早期、无并发线程竞争时调用；edition 2024 要求显式 unsafe。
        unsafe { std::env::set_var("SMOL_THREADS", n.to_string()) };
    }
}

/// 解析主机名（支持 `[IPv6]` 括号格式与 -4/-6 强制），返回单个地址。
/// 解析主机名，返回全部匹配地址（按系统顺序，v4/v6 可选过滤）。
pub fn resolve_vec(
    host: &str,
    port: u16,
    force_v4: bool,
    force_v6: bool,
) -> anyhow::Result<Vec<SocketAddr>> {
    let raw = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let host = raw.to_string();
    Ok(smol::block_on(async {
        smol::unblock(move || {
            let mut addrs: Vec<SocketAddr> = (host.as_str(), port).to_socket_addrs()?.collect();
            if force_v4 {
                addrs.retain(|a| a.is_ipv4());
            } else if force_v6 {
                addrs.retain(|a| a.is_ipv6());
            }
            Ok::<_, std::io::Error>(addrs)
        })
        .await
    })?)
}

/// 解析主机名，返回第一个匹配地址。
pub fn resolve(
    host: &str,
    port: u16,
    force_v4: bool,
    force_v6: bool,
) -> anyhow::Result<SocketAddr> {
    resolve_vec(host, port, force_v4, force_v6)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!(t!("errors.cannot_resolve", host = host)))
}

/// 主机名解析成功后的横幅：仅域名（非 IP 字面量）打印、`--json` 静默。
///
/// 各模式（icmp/tcp/udp/latency/bandwidth）共用，收敛 strip-bracket + 判断的重复。
pub fn print_resolving(host: &str, ip: IpAddr) {
    if crate::stats::json() {
        return;
    }
    let stripped = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if stripped.parse::<IpAddr>().is_err() {
        println!(
            "{}",
            t!("common.resolving", host = host, ip = ip.to_string())
        );
    }
}

/// 运行循环控制：按次数、按时长或 Ctrl+C 中断决定何时停止。
///
/// 循环写法（seq 由 `advance()` 推进，禁止直接改字段）：
/// ```text
/// loop {
///     if run.seq() > 0 { /* 间隔 */ }
///     if run.done() { break; }
///     let seq = run.seq();
///     /* 测量主体 */
///     run.advance();
/// }
/// ```
pub struct Run {
    /// 有效测量次数（0 = 无限，除非给了时长）。
    count: u64,
    /// 预热次数（不计入统计）。
    warmup: u64,
    /// 时长模式截止时间。
    deadline: Option<Instant>,
    /// 当前迭代序号（含预热）。
    seq: u64,
}

impl Run {
    /// `count` 为有效测量次数，`duration` 为秒数（`-n 10s`）。
    pub fn new(count: u64, warmup: u64, duration: Option<f64>) -> Self {
        let deadline = duration.map(|d| Instant::now() + Duration::from_secs_f64(d));
        Self {
            count,
            warmup,
            deadline,
            seq: 0,
        }
    }

    /// 当前迭代序号（含预热）。
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// 推进到下一次迭代。
    pub fn advance(&mut self) {
        self.seq += 1;
    }

    /// 当前迭代是否为预热。
    pub fn is_warmup(&self) -> bool {
        self.seq < self.warmup
    }

    /// 是否应停止（Ctrl+C、时长到期、次数达到上限）。
    pub fn done(&self) -> bool {
        if interrupted() {
            return true;
        }
        if let Some(dl) = self.deadline {
            return Instant::now() >= dl;
        }
        self.count != 0 && self.seq >= self.warmup + self.count
    }
}

/// 带 5 秒超时的 TCP 连接（黑洞地址不会挂死 OS 超时）。
pub async fn connect_timeout(
    addr: SocketAddr,
    source: Option<IpAddr>,
) -> std::io::Result<smol::Async<std::net::TcpStream>> {
    // socket2 建 socket →（可选）绑定源地址 → 阻塞 connect_timeout（5s，unblock 线程），
    // 再转非阻塞 + smol::Async。smol::net::TcpStream 无法从已绑定的 socket 构造，统一走此路径。
    let std_stream: std::net::TcpStream =
        smol::unblock(move || -> std::io::Result<std::net::TcpStream> {
            let domain = if addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };
            let sock =
                socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
            if let Some(src) = source {
                sock.bind(&socket2::SockAddr::from(SocketAddr::new(src, 0)))?;
            }
            sock.connect_timeout(&socket2::SockAddr::from(addr), Duration::from_secs(5))?;
            Ok(sock.into())
        })
        .await?;
    std_stream.set_nonblocking(true)?;
    smol::Async::new(std_stream)
}

/// 逐个尝试连接（多地址回退），全部失败返回最后一个错误。
pub async fn connect_first(
    addrs: &[SocketAddr],
    source: Option<IpAddr>,
) -> std::io::Result<smol::Async<std::net::TcpStream>> {
    let mut last = None;
    for a in addrs {
        match connect_timeout(*a, source).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses to connect")
    }))
}
/// 优雅结束发送方向：shutdown(Write) 后排空残余数据至 EOF。
///
/// 带宽发送方向客户端不回读服务端回显，直接 drop 会因接收缓冲未读数据触发 RST，
/// 导致服务端统计的接收量偏小；shutdown + drain 让服务端完整处理后再关闭。
pub async fn drain_after_send(stream: &mut smol::Async<std::net::TcpStream>) {
    use smol::io::AsyncReadExt;
    let _ = stream.get_ref().shutdown(std::net::Shutdown::Write);
    let mut buf = [0u8; 65536];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static INTERRUPT_COUNT: AtomicU8 = AtomicU8::new(0);

/// 是否收到过 Ctrl+C（或被注入中断）。
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

/// 置位/清除中断标志（测试注入优雅退出时使用）。
pub fn set_interrupted(v: bool) {
    INTERRUPTED.store(v, Ordering::Relaxed);
}

/// 重置中断状态（测试隔离用）。
pub fn reset_interrupt() {
    INTERRUPTED.store(false, Ordering::Relaxed);
    INTERRUPT_COUNT.store(0, Ordering::Relaxed);
}

/// 构造 UDP 接收模式触发包：`[0xFF, 0xFF, size(2B BE), count(4B BE)]`。
///
/// 服务端收到后向来源地址回送 `count` 个 `size` 字节的数据报。
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
    fn test_resolve_ip_direct() {
        let a = resolve("127.0.0.1", 80, false, false).unwrap();
        assert_eq!(a.ip().to_string(), "127.0.0.1");
        assert_eq!(a.port(), 80);
    }
    #[test]
    fn test_resolve_ipv6() {
        let a = resolve("::1", 8080, false, false).unwrap();
        assert_eq!(a.ip().to_string(), "::1");
        assert_eq!(a.port(), 8080);
    }
    #[test]
    fn test_resolve_ipv6_brackets() {
        let a = resolve("[::1]", 9999, false, false).unwrap();
        assert_eq!(a.ip().to_string(), "::1");
        assert_eq!(a.port(), 9999);
    }
    #[test]
    fn test_resolve_all_ip_direct() {
        let a = resolve_vec("127.0.0.1", 0, false, false).unwrap();
        assert_eq!(a[0].ip().to_string(), "127.0.0.1");
    }
    #[test]
    fn test_resolve_all_ipv6() {
        let a = resolve_vec("::1", 0, false, false).unwrap();
        assert_eq!(a[0].ip().to_string(), "::1");
    }
    #[test]
    fn test_resolve_invalid_host() {
        let _ = resolve("invalid.host.name.xyzzy", 80, false, false);
    }
    #[test]
    fn test_run_count_limited() {
        let mut r = Run::new(3, 2, None);
        let mut n = 0;
        while !r.done() {
            r.advance();
            n += 1;
        }
        assert_eq!(n, 5); // 2 预热 + 3 有效
    }
    #[test]
    fn test_run_infinite() {
        let r = Run::new(0, 4, None);
        assert!(!r.done());
    }
    #[test]
    fn test_run_duration() {
        // 时长模式忽略 count，由截止时间驱动（1ms 内应能跑出若干次迭代并终止）
        let mut r = Run::new(0, 0, Some(0.001));
        let mut n = 0;
        while !r.done() && n < 1_000_000 {
            r.advance();
            n += 1;
        }
        assert!(n > 0, "should run at least once");
        assert!(r.done());
    }
    #[test]
    fn test_run_warmup_flag() {
        let mut r = Run::new(1, 2, None);
        assert!(r.is_warmup());
        r.advance();
        assert!(r.is_warmup());
        r.advance();
        assert!(!r.is_warmup());
    }
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
    #[test]
    fn test_init_slice() {
        let buf: [MaybeUninit<u8>; 4] = [MaybeUninit::new(0xAB); 4];
        let s = init_slice(&buf, 4);
        assert_eq!(s, &[0xAB, 0xAB, 0xAB, 0xAB]);
    }
    #[test]
    fn test_bind_udp() {
        smol::block_on(async {
            let sock = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
            let local: SocketAddr = sock.get_ref().local_addr().unwrap().as_socket().unwrap();
            assert!(local.port() != 0);
        });
    }
}
