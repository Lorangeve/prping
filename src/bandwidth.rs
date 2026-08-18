//! Bandwidth test — client/server TCP/UDP bandwidth measurement.

use crate::output;
use crate::stats::{self, HistogramSpec};
use crate::util::{self, PingConfig};
use rust_i18n::t;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub fn run_client(cfg: &PingConfig) -> anyhow::Result<crate::BandwidthReport> {
    let addr = util::resolve(&cfg.host, cfg.port, cfg.v4, cfg.v6)?;
    if cfg.host.parse::<std::net::IpAddr>().is_err() {
        let stripped = cfg
            .host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(&cfg.host);
        if stripped.parse::<std::net::IpAddr>().is_err() && !stats::json() {
            let mut w = output::stdout();
            writeln!(
                &mut w,
                "{}",
                t!(
                    "common.resolving",
                    host = cfg.host,
                    ip = addr.ip().to_string()
                )
            )?;
        }
    }
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
        let mut stream = util::connect_timeout(addr).await?;
        stream.set_nodelay(true)?;
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
        let mut stream = util::connect_timeout(addr).await?;
        stream.set_nodelay(true)?;
        stream.write_all(&[0xFF]).await?;
        let deadline = duration.map(|d| Instant::now() + Duration::from_secs_f64(d));
        let target_bytes = deadline.map(|_| u64::MAX).unwrap_or(count * size as u64);
        let mut buf = vec![0u8; 65536];
        let mut total: u64 = 0;
        let start = Instant::now();
        while total < target_bytes {
            if util::interrupted() {
                break;
            }
            if deadline.is_some_and(|dl| Instant::now() >= dl) {
                break;
            }
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
            // TCP 是字节流，读块可能越过目标：截断到目标字节数（时长模式无上限）
            if target_bytes != u64::MAX && total > target_bytes {
                total = target_bytes;
            }
        }
        return report(
            t!("bandwidth.tcp_test"),
            total,
            start.elapsed(),
            cfg.histogram.as_ref(),
            &[],
            cfg.quiet,
            &format!("{}:{}", cfg.host, cfg.port),
        );
    }

    if parallel <= 1 {
        let mut stream = util::connect_timeout(addr).await?;
        stream.set_nodelay(true)?;
        let payload = vec![0u8; size];
        let mut times = Vec::new();
        let deadline = duration.map(|d| Instant::now() + Duration::from_secs_f64(d));
        let mut sent: u64 = 0;
        let start = Instant::now();
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
        }
        drop(stream);
        report(
            t!("bandwidth.tcp_test"),
            sent * size as u64,
            start.elapsed(),
            cfg.histogram.as_ref(),
            &times,
            cfg.quiet,
            &format!("{}:{}", cfg.host, cfg.port),
        )
    } else {
        // 并行连接：全局配额保证总量精确等于 count（修复 count < parallel 时发 0 包）
        let per_conn = if duration.is_some() {
            u64::MAX
        } else {
            count.div_ceil(parallel as u64)
        };
        let remaining = Arc::new(AtomicU64::new(count));
        let deadline = duration.map(|d| Instant::now() + Duration::from_secs_f64(d));
        let mut tasks = Vec::new();
        for _ in 0..parallel {
            let a = addr;
            let rem = remaining.clone();
            tasks.push(smol::spawn(async move {
                let mut stream = util::connect_timeout(a).await?;
                stream.set_nodelay(true)?;
                let payload = vec![0u8; size];
                let mut sent = 0u64;
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
                    stream.write_all(&payload).await?;
                    sent += 1;
                }
                Ok::<_, anyhow::Error>(sent)
            }));
        }
        let start = Instant::now();
        let mut total_sent: u64 = 0;
        for t in tasks {
            total_sent += t.await?;
        }
        report(
            t!("bandwidth.tcp_test"),
            total_sent * size as u64,
            start.elapsed(),
            cfg.histogram.as_ref(),
            &[],
            cfg.quiet,
            &format!("{}:{}", cfg.host, cfg.port),
        )
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
    let bind_addr: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let sock = util::bind_udp(bind_addr)?;
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
        let mut buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::new(0u8); 65536];
        let mut total: u64 = 0;
        let start = Instant::now();
        while total < target {
            if util::interrupted() {
                break;
            }
            if deadline.is_some_and(|dl| Instant::now() >= dl) {
                break;
            }
            let recv = smol::future::or(async { util::udp_recv(&sock, &mut buf).await }, async {
                smol::Timer::after(Duration::from_secs(5)).await;
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
            })
            .await;
            match recv {
                Ok((n, _)) => total += n as u64,
                Err(_) => break,
            }
        }
        return report(
            t!("bandwidth.udp_test"),
            total,
            start.elapsed(),
            cfg.histogram.as_ref(),
            &[],
            cfg.quiet,
            &format!("{}:{}", cfg.host, cfg.port),
        );
    }

    let payload = vec![0u8; size];
    let mut times = Vec::new();
    let mut sent: u64 = 0;
    let start = Instant::now();
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
    }
    report(
        t!("bandwidth.udp_test"),
        sent * size as u64,
        start.elapsed(),
        cfg.histogram.as_ref(),
        &times,
        cfg.quiet,
        &format!("{}:{}", cfg.host, cfg.port),
    )
}

fn report(
    label: impl AsRef<str>,
    total_bytes: u64,
    elapsed: Duration,
    histogram: Option<&HistogramSpec>,
    times: &[Duration],
    quiet: bool,
    target: &str,
) -> anyhow::Result<crate::BandwidthReport> {
    let label = label.as_ref();
    let secs = elapsed.as_secs_f64();
    let mbits = total_bytes as f64 * 8.0 / (secs * 1_000_000.0);
    let report = crate::BandwidthReport {
        label: label.to_string(),
        total_bytes,
        secs,
        mbps: mbits,
    };

    if quiet {
        return Ok(report);
    }

    let mut w = output::stdout();
    if stats::json() {
        // label 可能含引号/反斜杠，做最小转义保证 JSON 合法
        let escaped = label.replace('\\', "\\\\").replace('"', "\\\"");
        let target = target.replace('"', "\\\"");
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        writeln!(
            &mut w,
            "{{\"type\":\"bandwidth\",\"target\":\"{target}\",\"ts\":{ts},\"label\":\"{escaped}\",\"bytes\":{total_bytes},\"secs\":{secs:.2},\"mbps\":{mbits:.2}}}"
        )?;
        return Ok(report);
    }

    println!();
    output::print_bold(&mut w, label)?;
    writeln!(&mut w)?;
    writeln!(
        &mut w,
        "  {}",
        t!(
            "bandwidth.sent_bytes",
            bytes = total_bytes,
            secs = format!("{:.2}", secs)
        )
    )?;
    output::print_green(
        &mut w,
        format!(
            "  {}\n",
            t!("bandwidth.bandwidth", mbps = format!("{:.2}", mbits))
        ),
    )?;
    if let Some(spec) = histogram
        && !times.is_empty()
    {
        let mut s = crate::stats::Stats::default();
        for t in times {
            s.record(*t);
        }
        crate::stats::print_histogram(&mut w, &s, spec)?;
    }
    Ok(report)
}
