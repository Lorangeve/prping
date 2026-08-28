//! Bandwidth test — client/server TCP/UDP bandwidth measurement.

use crate::output;
use crate::stats::{self, HistogramSpec};
use crate::util::{self, PingConfig, TCP_RECEIVE_TRIGGER, RECV_BUF_SIZE};
use rust_i18n::t;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use std::io::{IsTerminal, Write};
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use termcolor::StandardStream;

/// 带宽测试实时进度条：同一行 `\r` 动态刷新（~100ms 限频）。
///
/// 仅当 stdout 为 tty 且非 `--json`/`-q` 时启用；非 tty（管道/文件）静默，
/// 避免污染流式输出。时长模式按时间推进，次数模式按包（发送）/字节（接收）推进。
struct Progress {
    w: StandardStream,
    enabled: bool,
    start: Instant,
    last: Instant,
    kind: ProgressKind,
    /// 次数模式里程碑步长：每 total/20 强制刷新一次（快速测试也能看到进度）
    milestone_step: u64,
    next_milestone: u64,
}

enum ProgressKind {
    /// 次数模式 + 发送方向：按包数推进
    Packets { total: u64, size: u64 },
    /// 次数模式 + 接收方向：按字节推进
    Bytes { total: u64 },
    /// 时长模式：按时间推进
    Time { duration: f64 },
}

const BAR_WIDTH: usize = 20;

/// 吞吐量采样器：每 ~100ms 记录一次窗口吞吐量 (elapsed_secs, mbps)。
struct ThroughputSampler {
    start: Instant,
    last_sample: Instant,
    last_bytes: u64,
    samples: Vec<(f64, f64)>,
}

impl ThroughputSampler {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            last_sample: now,
            last_bytes: 0,
            samples: Vec::new(),
        }
    }

    /// 每次写入/读取后调用，传入当前累计字节数。
    fn tick(&mut self, total_bytes: u64) {
        let now = Instant::now();
        if now.duration_since(self.last_sample) >= Duration::from_millis(100) {
            let elapsed = now.duration_since(self.start).as_secs_f64();
            let window_bytes = total_bytes.saturating_sub(self.last_bytes);
            let window_secs = now.duration_since(self.last_sample).as_secs_f64();
            if window_secs > 0.0 {
                let mbps = window_bytes as f64 * 8.0 / (window_secs * 1_000_000.0);
                self.samples.push((elapsed, mbps));
            }
            self.last_sample = now;
            self.last_bytes = total_bytes;
        }
    }

    fn finish(&mut self, total_bytes: u64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.start).as_secs_f64();
        let window_bytes = total_bytes.saturating_sub(self.last_bytes);
        let window_secs = now.duration_since(self.last_sample).as_secs_f64();
        if window_secs > 0.001 && window_bytes > 0 {
            let mbps = window_bytes as f64 * 8.0 / (window_secs * 1_000_000.0);
            self.samples.push((elapsed, mbps));
        }
    }

    fn samples(&self) -> &[(f64, f64)] {
        &self.samples
    }
}

/// 构造进度条：时长模式按时间；次数模式按包（发送）/字节（接收）。
fn make_progress(
    duration: Option<f64>,
    count: u64,
    size: u64,
    receive: bool,
    quiet: bool,
) -> Progress {
    let kind = match duration {
        Some(d) => ProgressKind::Time { duration: d },
        None if receive => ProgressKind::Bytes {
            total: count.saturating_mul(size),
        },
        None => ProgressKind::Packets { total: count, size },
    };
    Progress::new(kind, quiet)
}

impl Progress {
    fn new(kind: ProgressKind, quiet: bool) -> Self {
        let enabled = !quiet && !stats::json() && std::io::stdout().is_terminal();
        let now = Instant::now();
        // 次数模式每 5% 一个里程碑；时长模式只按时间刷新
        let (milestone_step, next_milestone) = match &kind {
            ProgressKind::Packets { total, .. } => {
                let s = (total / 20).max(1);
                (s, s)
            }
            ProgressKind::Bytes { total } => {
                let s = (total / 20).max(1);
                (s, s)
            }
            ProgressKind::Time { .. } => (0, u64::MAX),
        };
        Self {
            w: output::stdout(),
            enabled,
            start: now,
            last: now,
            kind,
            milestone_step,
            next_milestone,
        }
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    /// 刷新：100ms 时间限频 + 每 5% 里程碑强制刷新。
    fn update(&mut self, done: u64, bytes: u64) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let milestone = self.milestone_step > 0 && done >= self.next_milestone;
        let due = milestone || now.duration_since(self.last) >= Duration::from_millis(100);
        if !due {
            return;
        }
        if milestone {
            self.next_milestone = self.next_milestone.saturating_add(self.milestone_step);
        }
        self.last = now;
        self.render(done, bytes);
    }

    /// 打印最终进度行并换行（测试结束）。
    fn finish(&mut self, done: u64, bytes: u64) {
        if !self.enabled {
            return;
        }
        self.render(done, bytes);
        let _ = writeln!(&mut self.w);
    }

    fn render(&mut self, done: u64, bytes: u64) {
        let elapsed = self.start.elapsed().as_secs_f64().max(0.001);
        let mbits = bytes as f64 * 8.0 / elapsed / 1_000_000.0;
        let (pct, stats) = match &self.kind {
            ProgressKind::Packets { total, size } => {
                let pct = if *total > 0 {
                    done as f64 / *total as f64 * 100.0
                } else {
                    0.0
                };
                let stats = t!(
                    "bandwidth.progress.packets",
                    done = done,
                    total = total,
                    done_bytes = crate::util::format_bytes(bytes),
                    total_bytes = crate::util::format_bytes(total.saturating_mul(*size)),
                    mbps = format!("{mbits:.2}")
                );
                (pct, stats)
            }
            ProgressKind::Bytes { total } => {
                let pct = if *total > 0 {
                    bytes as f64 / *total as f64 * 100.0
                } else {
                    0.0
                };
                let stats = t!(
                    "bandwidth.progress.bytes",
                    done_bytes = crate::util::format_bytes(bytes),
                    total_bytes = crate::util::format_bytes(*total),
                    mbps = format!("{mbits:.2}")
                );
                (pct, stats)
            }
            ProgressKind::Time { duration } => {
                let pct = if *duration > 0.0 {
                    elapsed / *duration * 100.0
                } else {
                    0.0
                };
                let stats = t!(
                    "bandwidth.progress.time",
                    bytes = crate::util::format_bytes(bytes),
                    mbps = format!("{mbits:.2}")
                );
                (pct, stats)
            }
        };
        let pct = pct.min(100.0);
        let filled = ((pct / 100.0) * BAR_WIDTH as f64).round() as usize;
        let bar: String = "#".repeat(filled) + &"-".repeat(BAR_WIDTH - filled);
        let mut line = format!("\r[{bar}] {pct:>3.0}%  {stats}");
        // 补齐到固定宽度，覆盖上一行残留
        if line.len() < 80 {
            line.push_str(&" ".repeat(80 - line.len()));
        }
        let _ = write!(self.w, "{line}");
        let _ = self.w.flush();
    }
}

pub fn run_client(cfg: &PingConfig) -> anyhow::Result<crate::BandwidthReport> {
    let addr = util::resolve(&cfg.host, cfg.port, cfg.v4, cfg.v6)?;
    util::print_resolving(&cfg.host, addr.ip());
    let mut cfg = cfg.clone();
    cfg.size = Some(cfg.size.unwrap_or(8192));
    smol::block_on(run_client_async(addr, &cfg))
}

async fn run_client_async(
    addr: SocketAddr,
    cfg: &PingConfig,
) -> anyhow::Result<crate::BandwidthReport> {
    if cfg.udp {
        run_udp(addr, cfg).await
    } else {
        run_tcp(addr, cfg).await
    }
}

async fn run_tcp(addr: SocketAddr, cfg: &PingConfig) -> anyhow::Result<crate::BandwidthReport> {
    let (count, size, parallel, receive, warmup, duration) = (
        cfg.count,
        cfg.size.unwrap(),
        cfg.parallel,
        cfg.receive,
        cfg.warmup,
        cfg.duration,
    );

    if warmup > 0 && !receive {
        let mut stream = util::connect_timeout(addr, cfg.source).await?;
        stream.get_ref().set_nodelay(true)?;
        let payload = vec![0u8; size];
        for _ in 0..warmup {
            if util::interrupted() {
                break;
            }
            stream.write_all(&payload).await?;
        }
        if !stats::json() {
            println!("{}", t!("bandwidth.warmup_complete", count = warmup));
        }
    }

    if receive {
        let mut stream = util::connect_timeout(addr, cfg.source).await?;
        stream.get_ref().set_nodelay(true)?;
        stream.write_all(&[TCP_RECEIVE_TRIGGER]).await?;
        let deadline = duration.map(|d| Instant::now() + Duration::from_secs_f64(d));
        let target_bytes = deadline.map(|_| u64::MAX).unwrap_or(count * size as u64);
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        let mut total: u64 = 0;
        let start = Instant::now();
        let mut prog = make_progress(duration, count, size as u64, true, cfg.quiet);
        let mut times = Vec::new();
        let mut sampler = ThroughputSampler::new();
        while total < target_bytes {
            if util::interrupted() {
                break;
            }
            if deadline.is_some_and(|dl| Instant::now() >= dl) {
                break;
            }
            let t0 = Instant::now();
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if cfg.histogram.is_some() {
                times.push(t0.elapsed());
            }
            total += n as u64;
            // TCP 是字节流，读块可能越过目标：截断到目标字节数（时长模式无上限）
            if target_bytes != u64::MAX && total > target_bytes {
                total = target_bytes;
            }
            sampler.tick(total);
            prog.update(0, total);
        }
        sampler.finish(total);
        prog.finish(0, total);
        return report(ReportArgs {
            label: t!("bandwidth.tcp_test").to_string(),
            total_bytes: total,
            elapsed: start.elapsed(),
            histogram: cfg.histogram.as_ref(),
            times: &times,
            quiet: cfg.quiet,
            target: format!("{}:{}", cfg.host, cfg.port),
            received: cfg.receive,
            parallel: 1,
            throughput_timeline: sampler.samples(),
            graph: cfg.graph,
        });
    }

    if parallel <= 1 {
        let mut stream = util::connect_timeout(addr, cfg.source).await?;
        stream.get_ref().set_nodelay(true)?;
        let payload = vec![0u8; size];
        let mut times = Vec::new();
        let deadline = duration.map(|d| Instant::now() + Duration::from_secs_f64(d));
        let mut sent: u64 = 0;
        let start = Instant::now();
        let mut prog = make_progress(duration, count, size as u64, false, cfg.quiet);
        let mut sampler = ThroughputSampler::new();
        loop {
            if util::interrupted() {
                break;
            }
            if deadline.is_some_and(|dl| Instant::now() >= dl) {
                break;
            }
            if deadline.is_none() && sent >= count {
                break;
            }
            let t0 = Instant::now();
            stream.write_all(&payload).await?;
            if cfg.histogram.is_some() {
                times.push(t0.elapsed());
            }
            sent += 1;
            sampler.tick(sent * size as u64);
            prog.update(sent, sent * size as u64);
        }
        // 优雅结束发送方向：避免 RST 清队列导致服务端统计偏小
        util::drain_after_send(&mut stream).await;
        drop(stream);
        sampler.finish(sent * size as u64);
        prog.finish(sent, sent * size as u64);
        report(ReportArgs {
            label: t!("bandwidth.tcp_test").to_string(),
            total_bytes: sent * size as u64,
            elapsed: start.elapsed(),
            histogram: cfg.histogram.as_ref(),
            times: &times,
            quiet: cfg.quiet,
            target: format!("{}:{}", cfg.host, cfg.port),
            received: cfg.receive,
            parallel: 1,
            throughput_timeline: sampler.samples(),
            graph: cfg.graph,
        })
    } else {
        // 并行连接：全局配额保证总量精确等于 count（修复 count < parallel 时发 0 包）
        let per_conn = if duration.is_some() {
            u64::MAX
        } else {
            count.div_ceil(parallel as u64)
        };
        let remaining = Arc::new(AtomicU64::new(count));
        let done = Arc::new(AtomicU64::new(0));
        let deadline = duration.map(|d| Instant::now() + Duration::from_secs_f64(d));
        let want_times = cfg.histogram.is_some();
        let source = cfg.source;
        let mut tasks = Vec::new();
        for _ in 0..parallel {
            let a = addr;
            let rem = remaining.clone();
            let done = done.clone();
            tasks.push(smol::spawn(async move {
                let mut stream = util::connect_timeout(a, source).await?;
                stream.get_ref().set_nodelay(true)?;
                let payload = vec![0u8; size];
                let mut sent = 0u64;
                let mut times = Vec::new();
                loop {
                    if util::interrupted() {
                        break;
                    }
                    if deadline.is_some_and(|dl| Instant::now() >= dl) {
                        break;
                    }
                    if deadline.is_none() {
                        if sent >= per_conn {
                            break;
                        }
                        // 抢占全局配额，发完即停（总量截断为 count）
                        // nightly 1.93+ 将 fetch_update 更名 try_update（尚未稳定），显式 allow
                        #[allow(deprecated)]
                        if rem
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |r: u64| {
                                r.checked_sub(1)
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    let t0 = Instant::now();
                    stream.write_all(&payload).await?;
                    if want_times {
                        times.push(t0.elapsed());
                    }
                    sent += 1;
                    done.fetch_add(1, Ordering::Relaxed);
                }
                util::drain_after_send(&mut stream).await;
                Ok::<_, anyhow::Error>((sent, times))
            }));
        }
        // 进度条：并行发送期间主循环在等待，用独立 task 每 100ms 刷新
        let prog = Arc::new(std::sync::Mutex::new(make_progress(
            duration,
            count,
            size as u64,
            false,
            cfg.quiet,
        )));
        let stop = Arc::new(AtomicBool::new(false));
        let prog_task = if prog.lock().unwrap().enabled() {
            let prog = prog.clone();
            let done = done.clone();
            let stop = stop.clone();
            Some(smol::spawn(async move {
                loop {
                    smol::Timer::after(Duration::from_millis(100)).await;
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let d = done.load(Ordering::Relaxed);
                    prog.lock().unwrap().update(d, d * size as u64);
                }
            }))
        } else {
            None
        };
        let start = Instant::now();
        let mut total_sent: u64 = 0;
        let mut all_times: Vec<Duration> = Vec::new();
        for t in tasks {
            let (sent, times) = t.await?;
            total_sent += sent;
            all_times.extend(times);
        }
        stop.store(true, Ordering::Relaxed);
        if let Some(t) = prog_task {
            let _ = t.await;
        }
        prog.lock()
            .unwrap()
            .finish(total_sent, total_sent * size as u64);
        report(ReportArgs {
            label: t!("bandwidth.tcp_test").to_string(),
            total_bytes: total_sent * size as u64,
            elapsed: start.elapsed(),
            histogram: cfg.histogram.as_ref(),
            times: &all_times,
            quiet: cfg.quiet,
            target: format!("{}:{}", cfg.host, cfg.port),
            received: cfg.receive,
            parallel: parallel as u16,
            throughput_timeline: &[],
            graph: cfg.graph,
        })
    }
}

async fn run_udp(addr: SocketAddr, cfg: &PingConfig) -> anyhow::Result<crate::BandwidthReport> {
    let (count, size, receive, warmup, duration) = (
        cfg.count,
        cfg.size.unwrap(),
        cfg.receive,
        cfg.warmup,
        cfg.duration,
    );
    let sock = util::bind_udp(util::local_bind(addr.is_ipv4(), cfg.source))?;
    let deadline = duration.map(|d| Instant::now() + Duration::from_secs_f64(d));

    if warmup > 0 && !receive {
        let payload = vec![0u8; size];
        for _ in 0..warmup {
            if util::interrupted() {
                break;
            }
            util::udp_send(&sock, &payload, &addr).await?;
        }
        if !stats::json() {
            println!("{}", t!("bandwidth.warmup_complete", count = warmup));
        }
    }

    if receive {
        // UDP 接收模式：发送触发包，服务器持续回送数据报
        let trigger = util::udp_receive_trigger(
            size,
            if duration.is_some() {
                u32::MAX
            } else {
                count.min(u32::MAX as u64) as u32
            },
        );
        util::udp_send(&sock, &trigger, &addr).await?;
        let target = deadline.map(|_| u64::MAX).unwrap_or(count * size as u64);
        let mut buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::new(0u8); RECV_BUF_SIZE];
        let mut total: u64 = 0;
        let start = Instant::now();
        let mut prog = make_progress(duration, count, size as u64, true, cfg.quiet);
        let mut times = Vec::new();
        let mut sampler = ThroughputSampler::new();
        while total < target {
            if util::interrupted() {
                break;
            }
            if deadline.is_some_and(|dl| Instant::now() >= dl) {
                break;
            }
            let t0 = Instant::now();
            let recv = smol::future::or(async { util::udp_recv(&sock, &mut buf).await }, async {
                smol::Timer::after(Duration::from_secs(5)).await;
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
            })
            .await;
            match recv {
                Ok((n, _)) => {
                    if cfg.histogram.is_some() {
                        times.push(t0.elapsed());
                    }
                    total += n as u64;
                    sampler.tick(total);
                    prog.update(0, total);
                }
                Err(_) => break,
            }
        }
        prog.finish(0, total);
        return report(ReportArgs {
            label: t!("bandwidth.udp_test").to_string(),
            total_bytes: total,
            elapsed: start.elapsed(),
            histogram: cfg.histogram.as_ref(),
            times: &times,
            quiet: cfg.quiet,
            target: format!("{}:{}", cfg.host, cfg.port),
            received: cfg.receive,
            parallel: 1,
            throughput_timeline: sampler.samples(),
            graph: cfg.graph,
        });
    }

    let payload = vec![0u8; size];
    let mut times = Vec::new();
    let mut sent: u64 = 0;
    let start = Instant::now();
    let mut prog = make_progress(duration, count, size as u64, false, cfg.quiet);
    loop {
        if util::interrupted() {
            break;
        }
        if deadline.is_some_and(|dl| Instant::now() >= dl) {
            break;
        }
        if deadline.is_none() && sent >= count {
            break;
        }
        let t0 = Instant::now();
        util::udp_send(&sock, &payload, &addr).await?;
        if cfg.histogram.is_some() {
            times.push(t0.elapsed());
        }
        sent += 1;
        prog.update(sent, sent * size as u64);
    }
    prog.finish(sent, sent * size as u64);
    report(ReportArgs {
        label: t!("bandwidth.udp_test").to_string(),
        total_bytes: sent * size as u64,
        elapsed: start.elapsed(),
        histogram: cfg.histogram.as_ref(),
        times: &times,
        quiet: cfg.quiet,
        target: format!("{}:{}", cfg.host, cfg.port),
        received: cfg.receive,
        parallel: 1,
        throughput_timeline: &[],
        graph: cfg.graph,
    })
}

/// 带宽报告渲染参数（收敛 report 的 8 个位置参数，避免同类型传错）。
pub(crate) struct ReportArgs<'a> {
    pub label: String,
    pub total_bytes: u64,
    pub elapsed: Duration,
    pub histogram: Option<&'a HistogramSpec>,
    pub times: &'a [Duration],
    pub quiet: bool,
    pub target: String,
    pub received: bool,
    /// 并发连接数（仅并行 TCP 模式 >1 时有意义）。
    pub parallel: u16,
    /// 吞吐量时间线采样：(elapsed_secs, window_mbps)。
    pub throughput_timeline: &'a [(f64, f64)],
    /// 是否渲染时间线图（`-g`）。
    pub graph: bool,
}

fn report(args: ReportArgs<'_>) -> anyhow::Result<crate::BandwidthReport> {
    let ReportArgs {
        label,
        total_bytes,
        elapsed,
        histogram,
        times,
        quiet,
        target,
        received,
        parallel,
        throughput_timeline,
        graph,
    } = args;
    let secs = elapsed.as_secs_f64();
    let mbits = total_bytes as f64 * 8.0 / (secs * 1_000_000.0);
    let report = crate::BandwidthReport {
        label: label.clone(),
        total_bytes,
        secs,
        mbps: mbits,
    };

    let mut w = output::stdout();
    if stats::json() {
        // label 可能含引号/反斜杠，做最小转义保证 JSON 合法
        let escaped = label.replace('\\', "\\\\").replace('"', "\\\"");
        let target = target.replace('"', "\\\"");
        let ts = crate::util::unix_ts();
        writeln!(
            &mut w,
            "{{\"type\":\"bandwidth\",\"target\":\"{target}\",\"ts\":{ts},\"direction\":\"{}\",\"label\":\"{escaped}\",\"bytes\":{total_bytes},\"secs\":{secs:.2},\"mbps\":{mbits:.2}}}",
            if received { "recv" } else { "send" }
        )?;
        return Ok(report);
    }

    // quiet 模式只抑制进度条，不抑制汇总（与 latency/ping 的 -q 行为一致）
    println!();
    output::print_bold(&mut w, label)?;
    writeln!(&mut w)?;
    let verb = if received {
        t!(
            "bandwidth.received_bytes",
            bytes = total_bytes,
            secs = format!("{:.2}", secs)
        )
    } else {
        t!(
            "bandwidth.sent_bytes",
            bytes = total_bytes,
            secs = format!("{:.2}", secs)
        )
    };
    writeln!(&mut w, "  {verb}")?;
    // 人性化字节数（如 "800.00 KiB"），与原始字节数并列方便对比
    if !quiet {
        let human = crate::util::format_bytes(total_bytes);
        writeln!(&mut w, "  {}", t!("bandwidth.bytes_human", bytes = human))?;
    }
    if parallel > 1 {
        writeln!(
            &mut w,
            "  {}",
            t!("bandwidth.connections", count = parallel)
        )?;
    }
    output::print_green(
        &mut w,
        format!(
            "  {}\n",
            t!("bandwidth.bandwidth", mbps = format!("{:.2}", mbits))
        ),
    )?;
    if let Some(spec) = histogram {
        // 直方图直接消费耗时样本（不再临时构造 Stats）
        crate::stats::print_histogram(&mut w, times, spec)?;
    }
    if graph && !throughput_timeline.is_empty() {
        crate::stats::print_throughput_timeline(&mut w, throughput_timeline)?;
    }
    Ok(report)
}
