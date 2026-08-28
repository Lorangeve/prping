//! 服务端：TCP 回显 + UDP 回显/触发协议（latency/bandwidth 共用）。

mod capture;

use crate::PrpingError;
use crate::output;
use crate::util::{self, TCP_RECEIVE_TRIGGER, RECV_BUF_SIZE, parse_udp_receive_trigger, interrupted};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::TcpListener;
use std::collections::HashMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// 服务端并发 TCP 连接上限。
const MAX_CONNECTIONS: usize = 1024;

/// verbose 帧 dissect+打印（三处 UDP/TCP 路径共用）。
fn verbose_dissect(tag: &str, addr: &str, data: &[u8], n: usize, verbose: bool, capture_active: bool) {
    if verbose && !capture_active {
        let report = packet_dsl::dissect(data);
        let mut w = output::stdout();
        let _ = output::print_green(&mut w, format!("{tag} "));
        let _ = output::print_cyan(&mut w, format!("{addr} "));
        let _ = writeln!(&mut w, "{n} B");
        let _ = crate::engine::eng::render_dissected(&mut w, &report, "  recv:", data);
    }
}

/// 服务端运行报告（中断退出后返回）。
#[derive(Debug, Default)]
pub struct ServerReport {
    pub connections: u64,
    /// 服务端接收的字节数（普通 echo / 上行方向）。
    pub bytes: u64,
    /// 服务端发送的字节数（-r 触发模式 / 下行方向）。
    pub sent: u64,
    pub secs: f64,
    pub mbps: f64,
}

struct ServerAgg {
    connections: AtomicU64,
    bytes: AtomicU64,
    sent: AtomicU64,
    micros: AtomicU64,
}

/// UDP 来源会话跟踪：按源地址聚合，空闲 2s 后打印汇总（与 TCP 连接日志对齐）。
struct UdpSession {
    bytes: u64,
    packets: u64,
    start: Instant,
    last_activity: Instant,
}

impl UdpSession {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            bytes: 0,
            packets: 0,
            start: now,
            last_activity: now,
        }
    }

    /// 打印会话汇总（格式对齐 TCP 的 `recv IP:PORT size in secs — Mbps`）。
    fn finish_print(&self, src: SocketAddr) {
        let elapsed = self.start.elapsed().as_secs_f64();
        if self.bytes == 0 || elapsed <= 0.0 {
            return;
        }
        let mbits = (self.bytes as f64 * 8.0) / (elapsed * 1_000_000.0);
        let size_str = crate::util::format_bytes(self.bytes);
        let mut w = output::stdout();
        let _ = output::print_green(&mut w, rust_i18n::t!("server.recv_tag"));
        let _ = output::print_cyan(&mut w, format!("{}:{} ", src.ip(), src.port()));
        let _ = output::print_yellow(
            &mut w,
            format!(
                "{size_str} ({} pkts) in {elapsed:.2}s — {mbits:.2} Mbps",
                self.packets,
            ),
        );
        let _ = writeln!(&mut w);
    }
}

/// 刷新空闲超时的 UDP 会话：打印汇总并从 map 中移除。
fn flush_idle_udp_sessions(
    sessions: &mut HashMap<SocketAddr, UdpSession>,
    idle_timeout: std::time::Duration,
) {
    let now = Instant::now();
    // 收集需要清除的 key（避免在迭代中修改 map）
    let expired: Vec<SocketAddr> = sessions
        .iter()
        .filter(|(_, s)| now.duration_since(s.last_activity) >= idle_timeout)
        .map(|(&k, _)| k)
        .collect();
    for key in expired {
        if let Some(sess) = sessions.remove(&key) {
            sess.finish_print(key);
        }
    }
}

/// 服务端：同时服务 latency/bandwidth 连接（TCP 回显 + UDP 回显/触发协议）。
///
/// 无限运行直到 `set_interrupted(true)`（Ctrl+C 或测试注入），返回聚合报告。
/// 连接日志直接打印到 stdout（语义化配色）。
/// `verbose` 为 true 时，每个收发数据包打印 dissect 反解层栈 + hexdump。
/// `capture_all`（`-a`/`--capture-all`）使抓包不过滤，显示所有可见帧
/// （ARP/ICMP/广播/组播/出向）。CLI 层校验要求显式配合 `-v`。
/// `filter`（`--filter`，tcpdump 风格子集）只显示匹配表达式的帧，CLI 层
/// 校验要求显式配合 `-a`；表达式非法返回错误。
/// （lib 层仍做防御性归一：capture_all/filter 存在时强制 verbose 与全帧，
/// 保证直接 API 调用方不会拿到「开了抓包却不反解」的无效组合。）
pub async fn serve(
    addr: SocketAddr,
    verbose: bool,
    capture_all: bool,
    filter: Option<&str>,
) -> Result<ServerReport, PrpingError> {
    let verbose = verbose || capture_all || filter.is_some();
    let capture_all = capture_all || filter.is_some();
    // verbose 模式需要 dissect 反解应用层（http/dns 等）：proto 注册表在
    // engine/packet 路径由 ensure_proto_registry 加载，服务端进程必须自己加载
    // （OnceLock 一次性；非 verbose 不加载，保持零开销）。
    if verbose {
        crate::engine::eng::ensure_proto_registry();
        // 注册表为空（eng_lib/lib 库目录都缺失，或全部解析失败）时，抓到的
        // 帧/载荷只能 hexdump、无法反解层栈（每帧都显示「未能识别任何层」）——
        // 提前警告并给出实际查找的库目录，避免看不出原因。
        if packet_dsl::proto_registry().is_empty() {
            let libs = crate::engine::eng::libs_display(&crate::engine::eng::registry_libs());
            let mut w = output::stderr();
            let _ = output::writeln_orange(
                &mut w,
                format!(
                    "{}（{}）",
                    rust_i18n::t!("server.verbose_dissect_unavailable"),
                    libs
                ),
            );
        }
    }
    // 完整帧抓包（verbose）：普通 socket 只见载荷，要显示 eth/IP/TCP 头（含握手）
    // 需 raw 抓包。成功 → 帧级显示（抑制下面 socket 载荷级打印）；失败 → 提示并
    // 回退载荷级 dissect（Linux 需 root/cap_net_raw，Windows 需装 Npcap）。
    let mut capture_active = false;
    if verbose {
        match capture::spawn(addr, capture_all, filter) {
            Ok(capture::CaptureStatus::Active(devs)) => {
                capture_active = true;
                println!(
                    "{}",
                    rust_i18n::t!("server.verbose_capture_active", devs = devs.join(", "))
                );
                if capture_all {
                    println!("{}", rust_i18n::t!("server.capture_all_active"));
                }
                if let Some(f) = filter {
                    println!(
                        "{}",
                        rust_i18n::t!("server.capture_filter_active", filter = f)
                    );
                }
            }
            Ok(capture::CaptureStatus::Unavailable(reason)) => {
                let mut w = output::stderr();
                let _ = output::writeln_orange(
                    &mut w,
                    rust_i18n::t!("server.verbose_capture_note", reason = reason),
                );
                // macOS 专用提示：BPF 抓包需 root（/dev/bpf* 默认 root:wheel 600）
                #[cfg(target_os = "macos")]
                let _ = output::writeln_orange(
                    &mut w,
                    rust_i18n::t!("server.verbose_capture_macos_hint"),
                );
            }
            Err(e) => {
                // --filter 表达式非法：配置错误，直接终止而不是回退
                return Err(anyhow::anyhow!("invalid capture filter: {e}").into());
            }
        }
    }

    let listener = TcpListener::bind(addr).await?;
    let agg = Arc::new(ServerAgg {
        connections: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        sent: AtomicU64::new(0),
        micros: AtomicU64::new(0),
    });

    // UDP：回显服务 + 接收模式触发协议（大缓冲 socket，避免突发丢包）
    let udp_socket = Arc::new(util::bind_udp(addr)?);
    let udp_agg = agg.clone();
    smol::spawn(async move {
        let mut buf: Vec<std::mem::MaybeUninit<u8>> = vec![std::mem::MaybeUninit::new(0u8); RECV_BUF_SIZE];
        // 按来源地址跟踪 UDP 会话：收到第一个包时记录，来源空闲 2s 后打印汇总并清除。
        // 与 TCP 的「连接结束打一行日志」对齐，避免逐包刷屏。
        let mut sessions: HashMap<SocketAddr, UdpSession> = HashMap::new();
        let idle_timeout = std::time::Duration::from_secs(2);
        loop {
            // 中断退出前：刷新所有活跃会话的汇总
            if interrupted() {
                for (src, sess) in sessions.drain() {
                    sess.finish_print(src);
                }
                break;
            }
            // 非阻塞轮询：先检查是否有来源已空闲超时需打印汇总
            flush_idle_udp_sessions(&mut sessions, idle_timeout);
            // 带超时的 recv：50ms 让出检查空闲会话
            let recv = smol::future::or(util::udp_recv(&udp_socket, &mut buf), async {
                smol::Timer::after(std::time::Duration::from_millis(50)).await;
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "poll"))
            })
            .await;
            let (n, src) = match recv {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(_) => continue,
            };
            let data = util::init_slice(&buf, n);
            // UDP 接收模式触发包：[0xFF, 0xFF, size(2B BE), count(4B BE)]
            if let Some((size, count)) = parse_udp_receive_trigger(data) {
                // verbose 且未抓包：dissect 触发包
                verbose_dissect("[udp-trigger]", &format!("{}:{}", src.ip(), src.port()), data, n, verbose, capture_active);
                // 接收模式开始：给服务端一个即时接收反馈（不逐包打印，带宽测试会刷屏）
                let mut w = output::stdout();
                let _ = output::print_green(&mut w, rust_i18n::t!("server.udp_trigger"));
                let _ = output::print_cyan(&mut w, format!("{}:{} ", src.ip(), src.port()));
                let _ = output::print_yellow(&mut w, format!("({count} × {size}B)"));
                let _ = writeln!(&mut w);
                // 触发模式：把已有会话刷新（如果有的话），避免混杂
                if let Some(sess) = sessions.remove(&src) {
                    sess.finish_print(src);
                }
                let sock = udp_socket.clone();
                let payload = vec![0x42u8; size.max(1usize)];
                let agg = udp_agg.clone();
                smol::spawn(async move {
                    let mut sent = 0u64;
                    while sent < count as u64 {
                        if interrupted() {
                            break;
                        }
                        match util::udp_send(&sock, &payload, &src).await {
                            Ok(_) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                // 发送缓冲区满：让出，等客户端排空后重试
                                smol::Timer::after(std::time::Duration::from_millis(1)).await;
                                continue;
                            }
                            Err(_) => break, // 端口不可达等致命错误
                        }
                        agg.sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
                        sent += 1;
                    }
                })
                .detach();
                continue;
            }
            // 普通回显：原样回送并统计接收字节（UDP ping/latency 的接收量进聚合报告）
            // verbose 且未抓包：打印接收数据报的 dissect 反解
            verbose_dissect("[udp-echo]", &format!("{}:{}", src.ip(), src.port()), data, n, verbose, capture_active);
            // 更新来源会话统计（首次出现时打一行 connect 日志）
            let sess = sessions.entry(src).or_insert_with(|| {
                let mut w = output::stdout();
                let _ = output::print_green(&mut w, rust_i18n::t!("server.connect_tag"));
                let _ = output::print_cyan(&mut w, format!("{}:{}", src.ip(), src.port()));
                let _ = writeln!(&mut w, " (udp)");
                UdpSession::new()
            });
            sess.bytes += n as u64;
            sess.packets += 1;
            sess.last_activity = Instant::now();
            if util::udp_send(&udp_socket, data, &src).await.is_ok() {
                udp_agg.bytes.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    })
    .detach();

    // 并发连接上限：防恶意/失控客户端无限堆任务
    let conn_sem = Arc::new(smol::lock::Semaphore::new(MAX_CONNECTIONS));

    loop {
        if interrupted() {
            break;
        }
        // 200ms 轮询 accept，以便及时响应中断
        let accept = smol::future::or(listener.accept(), async {
            smol::Timer::after(std::time::Duration::from_millis(200)).await;
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, ""))
        })
        .await;
        let (stream, peer) = match accept {
            Ok(v) => v,
            Err(_) => continue,
        };
        // 超出上限：直接拒绝新连接（信号量配额在任务结束时释放）
        let Some(perm) = conn_sem.clone().try_acquire_arc() else {
            drop(stream);
            continue;
        };
        let agg = agg.clone();

        smol::spawn(async move {
            let _perm = perm;
            let mut stream = stream;
            stream.set_nodelay(true).ok();
            let mut buf = vec![0u8; RECV_BUF_SIZE];
            let mut total: u64 = 0;
            let mut sent_total: u64 = 0;
            let mut echo_ok = true;
            let start = std::time::Instant::now();
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n as u64;
                        // verbose 且未抓包：打印接收数据的 dissect 反解
                        verbose_dissect("[recv]", &format!("{peer}"), &buf[..n], n, verbose, capture_active);
                        // 接收模式触发（0xFF 单字节）：持续回送数据并统计发送量
                        if n == 1 && buf[0] == TCP_RECEIVE_TRIGGER && total == 1 {
                            let dummy = vec![0u8; RECV_BUF_SIZE];
                            loop {
                                if stream.write_all(&dummy).await.is_err() {
                                    break;
                                }
                                sent_total += dummy.len() as u64;
                            }
                            break;
                        }
                        // 回显：100ms 写超时。带宽测试客户端不回读回显，
                        // 写窗口会迅速打满；超时后停止回显但继续排空数据，避免连接被 RST。
                        if echo_ok {
                            let echo = smol::future::or(stream.write_all(&buf[..n]), async {
                                smol::Timer::after(std::time::Duration::from_millis(100)).await;
                                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, ""))
                            })
                            .await;
                            if echo.is_err() {
                                echo_ok = false;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            let elapsed = start.elapsed().as_secs_f64();
            agg.connections.fetch_add(1, Ordering::Relaxed);
            agg.bytes.fetch_add(total, Ordering::Relaxed);
            agg.sent.fetch_add(sent_total, Ordering::Relaxed);
            agg.micros
                .fetch_add((elapsed * 1_000_000.0) as u64, Ordering::Relaxed);

            // 连接日志渲染收敛在 output.rs（着色统一）
            let mut w = output::stdout();
            let _ = output::print_server_log(&mut w, peer, total, sent_total, elapsed);
        })
        .detach();
    }

    // 聚合报告（打印由调用方渲染）
    let conns = agg.connections.load(Ordering::Relaxed);
    let bytes = agg.bytes.load(Ordering::Relaxed);
    let sent = agg.sent.load(Ordering::Relaxed);
    let micros = agg.micros.load(Ordering::Relaxed);
    let secs = micros as f64 / 1_000_000.0;
    let mbps = if secs > 0.0 {
        (bytes as f64 * 8.0) / (secs * 1_000_000.0)
    } else {
        0.0
    };
    Ok(ServerReport {
        connections: conns,
        bytes,
        sent,
        secs,
        mbps,
    })
}
