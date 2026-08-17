//! UDP ping — test UDP port reachability and measure round-trip latency.

use crate::output;
use crate::stats::{self, Stats};
use crate::util::{self, PingConfig, Run};
use rust_i18n::t;
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use termcolor::StandardStream;

/// 返回 `Ok(true)` 表示有丢包（供退出码判断）。
pub fn ping(cfg: &PingConfig) -> anyhow::Result<bool> {
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
    smol::block_on(ping_async(addr, cfg))
}

async fn ping_async(target: SocketAddr, cfg: &PingConfig) -> anyhow::Result<bool> {
    let bind_addr: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let sock = util::bind_udp(bind_addr)?;
    let mut stats = Stats::default();
    let mut w = output::stdout();
    // 前 2 字节放 seq，用于回包校验（#3：过滤杂包）
    let mut payload = vec![0u8; cfg.size.max(2)];
    let mut buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::new(0u8); cfg.size + 512];
    let mut run = Run::new(cfg.count, cfg.warmup, cfg.duration);

    loop {
        if run.seq() > 0 {
            smol::Timer::after(Duration::from_secs_f64(cfg.interval)).await;
        }
        if run.done() {
            break;
        }
        let is_warmup = run.is_warmup();
        let seq_num = run.seq() as u16;
        payload[..2].copy_from_slice(&seq_num.to_be_bytes());
        let start = Instant::now();
        if util::udp_send(&sock, &payload, &target).await.is_err() {
            run.advance();
            continue;
        }

        // 等待回包：校验前 2 字节 seq，杂包忽略继续等，直到整体超时
        let deadline = Instant::now() + Duration::from_secs(4);
        let result = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break Err(());
            }
            let recv = smol::future::or(
                async { Some(util::udp_recv(&sock, &mut buf).await) },
                async {
                    smol::Timer::after(remaining).await;
                    None
                },
            )
            .await;
            match recv {
                Some(Ok((n, src))) => {
                    let init = util::init_slice(&buf, n);
                    if n >= 2 && init[..2] == seq_num.to_be_bytes() {
                        break Ok((start.elapsed(), src, n));
                    }
                    // 杂包：继续等待
                }
                _ => break Err(()),
            }
        };

        match result {
            Ok((rtt, src, n)) => {
                if !is_warmup {
                    stats.record(rtt);
                }
                if !cfg.quiet && !stats::json() {
                    print_reply(&mut w, src, n, rtt, is_warmup)?;
                }
            }
            Err(_) => {
                if !is_warmup {
                    stats.record_loss();
                }
                if !cfg.quiet && !stats::json() {
                    output::writeln_red(&mut w, t!("common.timeout"))?;
                }
            }
        }
        run.advance();
    }

    if !cfg.quiet && !stats::json() {
        println!();
    }
    stats::print_summary(&mut w, &stats, "udp")?;
    if !stats::json()
        && stats.received > 0
        && let Some(spec) = &cfg.histogram
    {
        stats::print_histogram(&mut w, &stats, spec)?;
    }
    if !stats::json() {
        stats::print_timeline(&mut w, &stats)?;
    }
    Ok(stats.loss_pct() > 0.0)
}

fn print_reply(
    w: &mut StandardStream,
    src: SocketAddr,
    size: usize,
    rtt: Duration,
    warmup: bool,
) -> anyhow::Result<()> {
    output::print_green(w, t!("common.reply_from"))?;
    output::print_cyan(w, src.ip().to_string())?;
    write!(w, ":")?;
    output::print_magenta(w, src.port().to_string())?;
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
