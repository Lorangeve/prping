//! Latency test — client/server TCP/UDP round-trip latency measurement.

use crate::output;
use crate::stats::{self, Stats};
use crate::util::{self, PingConfig, Run};
use rust_i18n::t;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use termcolor::StandardStream;

/// 返回 `Ok(true)` 表示有丢包（供退出码判断）。
pub fn run_client(cfg: &PingConfig) -> anyhow::Result<bool> {
    let addr = util::resolve(&cfg.host, cfg.port, cfg.v4, cfg.v6)?;
    if cfg.host.parse::<IpAddr>().is_err() {
        let stripped = cfg
            .host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(&cfg.host);
        if stripped.parse::<IpAddr>().is_err() && !stats::json() {
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
    smol::block_on(run_client_async(addr, cfg))
}

async fn run_client_async(addr: SocketAddr, cfg: &PingConfig) -> anyhow::Result<bool> {
    if cfg.udp {
        run_udp_client(addr, cfg).await
    } else {
        run_tcp_client(addr, cfg).await
    }
}

async fn run_tcp_client(addr: SocketAddr, cfg: &PingConfig) -> anyhow::Result<bool> {
    let mut stats = Stats::default();
    let mut w = output::stdout();
    let payload = vec![0x42u8; cfg.size];
    let mut buf = vec![0u8; cfg.size + 1];
    let mut run = Run::new(cfg.count, cfg.warmup, cfg.duration);

    loop {
        if run.seq() > 0 {
            smol::Timer::after(Duration::from_secs(1)).await;
        }
        if run.done() {
            break;
        }
        let is_warmup = run.is_warmup();
        let start = Instant::now();
        let mut stream = match util::connect_timeout(addr).await {
            Ok(s) => s,
            Err(e) => {
                if !is_warmup {
                    stats.record_loss();
                    if !stats::json() {
                        output::writeln_red(&mut w, &t!("common.connect_failed", error = e))?;
                    }
                }
                run.advance();
                continue;
            }
        };
        stream.set_nodelay(true)?;

        if cfg.receive {
            // 发送触发字节，服务器回送 size 字节
            stream.write_all(&[0xFF]).await?;
            match smol::future::or(
                async {
                    stream.read_exact(&mut buf[..1]).await?;
                    stream.read_exact(&mut buf[1..]).await.map(|_| cfg.size + 1)
                },
                async {
                    smol::Timer::after(Duration::from_secs(10)).await;
                    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
                },
            )
            .await
            {
                Ok(_) => {
                    let rtt = start.elapsed();
                    if !is_warmup {
                        stats.record(rtt);
                    }
                    if !stats::json() {
                        print_latency(&mut w, addr, rtt, cfg.size, is_warmup)?;
                    }
                }
                Err(_) => {
                    if !is_warmup {
                        stats.record_loss();
                    }
                    if !stats::json() {
                        output::writeln_red(&mut w, t!("common.timeout"))?;
                    }
                }
            }
            run.advance();
            continue;
        }

        if stream.write_all(&payload).await.is_err() {
            run.advance();
            continue;
        }
        match smol::future::or(
            async { stream.read_exact(&mut buf[..cfg.size]).await },
            async {
                smol::Timer::after(Duration::from_secs(10)).await;
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
            },
        )
        .await
        {
            Ok(_) => {
                let rtt = start.elapsed();
                if !is_warmup {
                    stats.record(rtt);
                }
                if !stats::json() {
                    print_latency(&mut w, addr, rtt, cfg.size, is_warmup)?;
                }
            }
            Err(_) => {
                if !is_warmup {
                    stats.record_loss();
                }
                if !stats::json() {
                    output::writeln_red(&mut w, t!("common.timeout"))?;
                }
            }
        }
        run.advance();
    }
    print_result(&mut w, &stats, cfg)?;
    Ok(stats.loss_pct() > 0.0)
}

async fn run_udp_client(addr: SocketAddr, cfg: &PingConfig) -> anyhow::Result<bool> {
    let bind_addr: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let sock = util::bind_udp(bind_addr)?;
    let mut stats = Stats::default();
    let mut w = output::stdout();
    let payload = vec![0x42u8; cfg.size];
    let trigger = util::udp_receive_trigger(cfg.size, 1);
    let mut buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::new(0u8); cfg.size + 512];
    let mut run = Run::new(cfg.count, cfg.warmup, cfg.duration);

    loop {
        if run.seq() > 0 {
            smol::Timer::after(Duration::from_secs(1)).await;
        }
        if run.done() {
            break;
        }
        let is_warmup = run.is_warmup();
        let start = Instant::now();
        // 接收模式：发送触发包，服务器回送 size 字节；否则发送 size 字节负载
        let sent = if cfg.receive {
            util::udp_send(&sock, &trigger, &addr).await
        } else {
            util::udp_send(&sock, &payload, &addr).await
        };
        if sent.is_err() {
            run.advance();
            continue;
        }

        match smol::future::or(
            async { Some(util::udp_recv(&sock, &mut buf).await) },
            async {
                smol::Timer::after(Duration::from_secs(10)).await;
                None
            },
        )
        .await
        {
            Some(Ok((n, _))) => {
                let rtt = start.elapsed();
                if !is_warmup {
                    stats.record(rtt);
                }
                if !stats::json() {
                    print_latency(&mut w, addr, rtt, n, is_warmup)?;
                }
            }
            _ => {
                if !is_warmup {
                    stats.record_loss();
                }
                if !stats::json() {
                    output::writeln_red(&mut w, t!("common.timeout"))?;
                }
            }
        }
        run.advance();
    }
    print_result(&mut w, &stats, cfg)?;
    Ok(stats.loss_pct() > 0.0)
}

fn print_latency(
    w: &mut StandardStream,
    addr: SocketAddr,
    rtt: Duration,
    size: usize,
    warmup: bool,
) -> anyhow::Result<()> {
    output::print_green(w, t!("common.reply_from"))?;
    output::print_cyan(w, addr.ip().to_string())?;
    write!(w, ":")?;
    output::print_magenta(w, addr.port().to_string())?;
    write!(w, ": {}{size} ", t!("common.bytes"))?;
    output::print_yellow(
        w,
        format!("{}{:.2}ms", t!("common.time"), rtt.as_secs_f64() * 1000.0),
    )?;
    if warmup {
        output::print_dim(w, format!(" {}", t!("common.warmup")))?;
    }
    writeln!(w)?;
    Ok(())
}

fn print_result(w: &mut StandardStream, stats: &Stats, cfg: &PingConfig) -> anyhow::Result<()> {
    if !stats::json() {
        println!();
    }
    stats::print_summary(w, stats, "latency")?;
    if !stats::json()
        && stats.received > 0
        && let Some(spec) = &cfg.histogram
    {
        stats::print_histogram(w, stats, spec)?;
    }
    if !stats::json() {
        stats::print_timeline(w, stats)?;
    }
    Ok(())
}
