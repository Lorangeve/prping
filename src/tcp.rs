//! TCP ping — test TCP port connectivity and measure connection latency.

use crate::output;
use crate::stats::{self, Stats};
use crate::util::{self, PingConfig, Run};
use rust_i18n::t;
use std::io::Write;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use termcolor::StandardStream;

/// 返回 `Ok(true)` 表示有丢包（供退出码判断）。
pub fn ping(cfg: &PingConfig) -> anyhow::Result<Stats> {
    let addr = util::resolve(&cfg.host, cfg.port, cfg.v4, cfg.v6)?;
    if cfg.host.parse::<IpAddr>().is_err() {
        let stripped = cfg
            .host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(&cfg.host);
        if stripped.parse::<IpAddr>().is_err() && !stats::json() {
            println!(
                "{}",
                t!(
                    "common.resolving",
                    host = cfg.host,
                    ip = addr.ip().to_string()
                )
            );
        }
    }
    if !stats::json() {
        println!(
            "{}",
            t!(
                "tcp.connect_to",
                addr = addr.ip().to_string(),
                port = addr.port()
            )
        );
        if let Some(d) = cfg.duration {
            println!("{}", t!("tcp.duration", secs = d, warmup = cfg.warmup));
        } else {
            println!(
                "{}",
                t!(
                    "tcp.iterations",
                    total = cfg.warmup + cfg.count,
                    warmup = cfg.warmup
                )
            );
        }
    }
    smol::block_on(ping_async(addr, cfg))
}

async fn ping_async(addr: std::net::SocketAddr, cfg: &PingConfig) -> anyhow::Result<Stats> {
    let mut stats = Stats::default();
    let mut w = output::stdout();
    let mut run = Run::new(cfg.count, cfg.warmup, cfg.duration);

    loop {
        if run.seq() > 0 {
            smol::Timer::after(Duration::from_secs_f64(cfg.interval)).await;
        }
        if run.done() {
            break;
        }
        let is_warmup = run.is_warmup();
        let start = Instant::now();
        // 5 秒 connect 超时：黑洞地址（静默丢包）不会挂死 OS 超时
        match util::connect_timeout(addr).await {
            Ok(stream) => {
                let rtt = start.elapsed();
                let local = stream.local_addr().ok();
                if !is_warmup {
                    stats.record(rtt);
                }
                if !cfg.quiet && !stats::json() {
                    print_connected(&mut w, addr, local, rtt, is_warmup)?;
                }
            }
            Err(e) => {
                if !is_warmup {
                    stats.record_loss();
                }
                if !cfg.quiet && !stats::json() {
                    output::writeln_red(
                        &mut w,
                        &t!("common.connect_failed", error = e.to_string()),
                    )?;
                }
            }
        }
        run.advance();
    }

    if !cfg.quiet && !stats::json() {
        println!();
    }
    stats::print_summary(&mut w, &stats, "tcp")?;
    if !stats::json()
        && stats.received > 0
        && let Some(spec) = &cfg.histogram
    {
        stats::print_histogram(&mut w, &stats, spec)?;
    }
    if cfg.graph && !stats::json() {
        stats::print_timeline(&mut w, &stats)?;
    }
    Ok(stats)
}

fn print_connected(
    w: &mut StandardStream,
    addr: std::net::SocketAddr,
    local: Option<std::net::SocketAddr>,
    rtt: Duration,
    warmup: bool,
) -> anyhow::Result<()> {
    output::print_green(w, &t!("common.connecting_to"))?;
    output::print_cyan(w, addr.ip().to_string())?;
    write!(w, ":")?;
    output::print_magenta(w, addr.port().to_string())?;
    if warmup {
        output::print_dim(w, format!(" {}", t!("common.warmup")))?;
    }
    write!(w, ": ")?;
    if let Some(l) = local {
        output::print_dim(w, format!("{} {}:", t!("common.from"), l.ip()))?;
        output::print_dim(w, l.port().to_string())?;
        write!(w, ": ")?;
    }
    output::print_yellow(w, format!("{:.2}ms", rtt.as_secs_f64() * 1000.0))?;
    writeln!(w)?;
    Ok(())
}
