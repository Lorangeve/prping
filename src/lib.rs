//! prping —— 跨平台 psping 复刻（库）。
//!
//! # 架构
//!
//! 单 crate 双 target：本库提供协议实现与统一入口，`main.rs`（bin）只做
//! CLI 解析、输出渲染与退出码。
//!
//! ```text
//! prping crate
//! ├── lib.rs       pub: run / serve / PingConfig / Stats / 报告 / 错误 / 警告 / output 渲染辅助
//! ├── main.rs      bpaf 解析 → 互斥校验 → run()/serve() → t! 渲染 → 退出码；信号安装
//! └── util/stats/output/icmp/tcp/udp/latency/bandwidth   lib 内部实现
//! ```
//!
//! # 模式识别（`run`）
//!
//! | 条件 | 模式 |
//! |------|------|
//! | `bandwidth` + 端口 | 带宽测试 |
//! | `size`（-l）+ 端口 | 延迟测试 |
//! | 端口 | TCP ping（`udp` 则 UDP ping） |
//! | 无端口 | ICMP ping |
//!
//! # 服务端协议（`serve`）
//!
//! - **TCP**：回显全部数据；首个数据包为单字节 `0xFF` 时进入接收模式，
//!   持续回送 64KB 数据块；回显写超时 100ms 后停止回显但继续排空。
//! - **UDP**：回显全部数据报；8 字节触发包 `[0xFF, 0xFF, size(2B BE), count(4B BE)]`
//!   触发接收模式，回送 count 个 size 字节数据报。
//!
//! # 用法示例
//!
//! ```no_run
//! use prping::{PingConfig, run};
//!
//! let cfg = PingConfig {
//!     host: "127.0.0.1".into(),
//!     port: 80,
//!     count: 3,
//!     duration: None,
//!     interval: 1.0,
//!     size: None,
//!     quiet: true,
//!     histogram: None,
//!     warmup: 0,
//!     v4: false,
//!     v6: false,
//!     parallel: 1,
//!     udp: false,
//!     receive: false,
//!     bandwidth: false,
//!     graph: false,
//! };
//! let kind = run(&cfg, |_| {}).expect("run");
//! ```

rust_i18n::i18n!("locales");

mod bandwidth;
mod drive;
mod icmp;
mod latency;
mod output;
mod stats;
mod tcp;
mod udp;
mod util;

pub use stats::{HistogramSpec, Stats, parse_histogram, set_json, set_pretty};
pub use util::{
    PingConfig, configure_executor_threads, interrupted, reset_interrupt, set_interrupted,
};
// bin 侧错误/警告渲染用（颜色统一在 output.rs 管理）
pub use output::{stderr, writeln_orange, writeln_red};

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;

/// 测试分支结果（`run` 的返回）。
#[derive(Debug)]
pub enum OutcomeKind {
    /// ping 类（ICMP/TCP/UDP/latency）统计。
    Ping(Stats),
    /// 带宽测试报告。
    Bandwidth(BandwidthReport),
}

/// 带宽测试报告。
#[derive(Debug)]
pub struct BandwidthReport {
    /// 打印用标题（i18n，如 "TCP 带宽测试:"）。
    pub label: String,
    /// 实际发送/接收字节数。
    pub total_bytes: u64,
    /// 耗时（秒）。
    pub secs: f64,
    /// 吞吐（Mbps）。
    pub mbps: f64,
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

/// 测试警告（通过 `run` 的回调流出，bin 渲染为本地化文案）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PrpingWarning {
    /// `-i` 低于 1ms 下限，已截断。
    IntervalClamped { requested: f64 },
    /// `-b -u` 时 `-P` 无效。
    ParallelUdpIgnored,
    /// 非带宽模式 `-P` 无效。
    ParallelIgnored,
    /// 普通 ping 模式 `-r` 无效。
    ReceiveIgnoredPing,
    /// UDP 负载超 65507，已截断。
    UdpSizeClamped { requested: usize, max: usize },
}

/// 分派层错误；模式内部 IO/网络错误透传。
#[derive(Debug, thiserror::Error)]
pub enum PrpingError {
    #[error("UDP requires a port: HOST:PORT")]
    UdpRequiresPort,
    #[error("bandwidth requires HOST:PORT")]
    BandwidthRequiresPort,
    #[error("-4 and -6 cannot be used together")]
    ConflictV4V6,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// 统一入口：按配置自动识别模式并执行。
///
/// 警告（clamp/忽略提示）通过 `on_warning` 回调即时流出，保证在测试输出之前渲染。
pub fn run(
    cfg: &PingConfig,
    on_warning: impl FnMut(PrpingWarning),
) -> Result<OutcomeKind, PrpingError> {
    let mut on_warning = on_warning;
    let mut cfg = cfg.clone();

    // config 级不变式：-4/-6 冲突（bin 的 validate 只管 CLI 级冲突，这里兜底库调用方）
    if cfg.v4 && cfg.v6 {
        return Err(PrpingError::ConflictV4V6);
    }

    // -i 0 快速模式：clamp 到 1ms 下限
    if cfg.interval < 0.001 {
        on_warning(PrpingWarning::IntervalClamped {
            requested: cfg.interval,
        });
        cfg.interval = 0.001;
    }

    // 非带宽模式 -P 无效（-b -u 的 -P 警告在带宽分支）
    if cfg.parallel > 1 && !cfg.bandwidth {
        on_warning(PrpingWarning::ParallelIgnored);
    }

    if cfg.bandwidth {
        if cfg.port == 0 {
            return Err(PrpingError::BandwidthRequiresPort);
        }
        if cfg.udp && cfg.parallel > 1 {
            on_warning(PrpingWarning::ParallelUdpIgnored);
        }
        let size = clamp_udp_size(cfg.size.unwrap_or(8192), cfg.udp, &mut on_warning);
        cfg.size = Some(size);
        let report = bandwidth::run_client(&cfg)?;
        return Ok(OutcomeKind::Bandwidth(report));
    }

    if cfg.size.is_some() && cfg.port != 0 {
        // 延迟测试（-l + 端口）
        let size = clamp_udp_size(cfg.size.unwrap(), cfg.udp, &mut on_warning);
        cfg.size = Some(size);
        cfg.count = cfg.count.max(1);
        let stats = latency::run_client(&cfg)?;
        return Ok(OutcomeKind::Ping(stats));
    }

    if cfg.port != 0 {
        // TCP/UDP ping
        if cfg.receive {
            on_warning(PrpingWarning::ReceiveIgnoredPing);
        }
        let stats = if cfg.udp {
            udp::ping(&cfg)?
        } else {
            tcp::ping(&cfg)?
        };
        return Ok(OutcomeKind::Ping(stats));
    }

    // ICMP ping
    if cfg.udp {
        return Err(PrpingError::UdpRequiresPort);
    }
    if cfg.receive {
        on_warning(PrpingWarning::ReceiveIgnoredPing);
    }
    cfg.size = Some(cfg.size.unwrap_or(32));
    let stats = icmp::ping(&cfg)?;
    Ok(OutcomeKind::Ping(stats))
}

/// UDP 数据报负载上限（IPv4 65507 / IPv6 65527，取保守值），超限时截断并告警。
fn clamp_udp_size(size: usize, udp: bool, on_warning: &mut impl FnMut(PrpingWarning)) -> usize {
    const MAX_UDP: usize = 65507;
    if udp && size > MAX_UDP {
        on_warning(PrpingWarning::UdpSizeClamped {
            requested: size,
            max: MAX_UDP,
        });
        return MAX_UDP;
    }
    size
}

/// 服务端：同时服务 latency/bandwidth 连接（TCP 回显 + UDP 回显/触发协议）。
///
/// 无限运行直到 `set_interrupted(true)`（Ctrl+C 或测试注入），返回聚合报告。
/// 连接日志直接打印到 stdout（语义化配色）。
pub async fn serve(addr: SocketAddr) -> Result<ServerReport, PrpingError> {
    use smol::io::{AsyncReadExt, AsyncWriteExt};
    use smol::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

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
        let mut buf: Vec<std::mem::MaybeUninit<u8>> = vec![std::mem::MaybeUninit::new(0u8); 65536];
        loop {
            let Ok((n, src)) = util::udp_recv(&udp_socket, &mut buf).await else {
                continue;
            };
            let data = util::init_slice(&buf, n);
            // UDP 接收模式触发包：[0xFF, 0xFF, size(2B BE), count(4B BE)]
            if n == 8 && data[0] == 0xFF && data[1] == 0xFF {
                let size = u16::from_be_bytes([data[2], data[3]]) as usize;
                let count = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let sock = udp_socket.clone();
                let payload = vec![0x42u8; size.max(1)];
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
            let _ = util::udp_send(&udp_socket, data, &src).await;
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
            let mut buf = vec![0u8; 65536];
            let mut total: u64 = 0;
            let mut sent_total: u64 = 0;
            let mut echo_ok = true;
            let start = std::time::Instant::now();
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n as u64;
                        // 接收模式触发（0xFF 单字节）：持续回送数据并统计发送量
                        if n == 1 && buf[0] == 0xFF && total == 1 {
                            let dummy = vec![0u8; 65536];
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

/// 服务端并发 TCP 连接上限。
const MAX_CONNECTIONS: usize = 1024;

struct ServerAgg {
    connections: AtomicU64,
    bytes: AtomicU64,
    sent: AtomicU64,
    micros: AtomicU64,
}

fn format_bytes(bytes: u64) -> String {
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
