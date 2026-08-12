//! UDP ping — test UDP port reachability and measure round-trip latency.

use crate::output;
use crate::stats::{self, Stats};
use rust_i18n::t;
use smol::net::UdpSocket;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use termcolor::StandardStream;

#[allow(clippy::too_many_arguments)]
pub fn ping(host: &str, port: u16, count: u64, interval: f64, size: usize, quiet: bool, histogram: Option<usize>, warmup: u64, v4: bool, v6: bool) -> anyhow::Result<()> {
    let addr = resolve(host, port, v4, v6)?;
    if host.parse::<IpAddr>().is_err() {
        let stripped = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
        if stripped.parse::<IpAddr>().is_err() {
            let mut w = output::stdout();
            writeln!(&mut w, "{}", t!("common.resolving", host = host, ip = addr.ip().to_string()))?;
        }
    }
    smol::block_on(ping_async(addr, count, interval, size, quiet, histogram, warmup))
}

fn resolve(host: &str, port: u16, force_v4: bool, force_v6: bool) -> anyhow::Result<SocketAddr> {
    let raw = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = raw.parse::<IpAddr>() { return Ok(SocketAddr::new(ip, port)); }
    let host = raw.to_string();
    Ok(smol::block_on(async {
        smol::unblock(move || {
            let mut addrs: Vec<SocketAddr> = (host.as_str(), port).to_socket_addrs()?.collect();
            if force_v4 { addrs.retain(|a| a.is_ipv4()); }
            else if force_v6 { addrs.retain(|a| a.is_ipv6()); }
            addrs.into_iter().next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, t!("errors.cannot_resolve", host = host)))
        }).await
    })?)
}

async fn ping_async(target: SocketAddr, count: u64, interval: f64, size: usize, quiet: bool, histogram: Option<usize>, warmup: u64) -> anyhow::Result<()> {
    let bind_addr: SocketAddr = if target.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let sock = UdpSocket::bind(bind_addr).await?;
    let mut stats = Stats::default();
    let mut w = output::stdout();
    let total = if count == 0 { u64::MAX } else { warmup + count };
    let payload = vec![0u8; size];

    for seq in 0..total {
        if seq > 0 { smol::Timer::after(Duration::from_secs_f64(interval)).await; }
        let start = Instant::now();
        if sock.send_to(&payload, target).await.is_err() { continue; }

        let mut buf = vec![0u8; size + 512];
        let recv = smol::future::or(
            async { Some(sock.recv_from(&mut buf).await) },
            async { smol::Timer::after(Duration::from_secs(4)).await; None },
        ).await;

        match recv {
            Some(Ok((n, src))) => {
                let rtt = start.elapsed();
                let is_warmup = seq < warmup;
                if !is_warmup { stats.record(rtt); }
                if !quiet { print_reply(&mut w, src, n, rtt, is_warmup)?; }
            }
            _ => {
                let is_warmup = seq < warmup;
                if !is_warmup { stats.record_loss(); }
                if !quiet { output::writeln_red(&mut w, t!("common.timeout"))?; }
            }
        }
    }

    if !quiet { println!(); }
    stats::print_summary(&mut w, &stats)?;
    if histogram.is_some() && stats.received > 0 { stats::print_histogram(&mut w, &stats, histogram)?; }
    stats::print_timeline(&mut w, &stats)?;
    Ok(())
}

fn print_reply(w: &mut StandardStream, src: SocketAddr, size: usize, rtt: Duration, warmup: bool) -> anyhow::Result<()> {
    output::print_green(w, t!("common.reply_from"))?;
    output::print_cyan(w, format!("{}:{}", src.ip(), src.port()))?;
    write!(w, ": {}{size} ", t!("common.bytes"))?;
    output::print_yellow(w, format!("{}{:.2}ms", t!("common.time"), rtt.as_secs_f64() * 1000.0))?;
    if warmup { output::print_yellow(w, format!(" {}", t!("common.warmup")))?; }
    writeln!(w)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_resolve_ip_direct() { let a = resolve("127.0.0.1", 8080, false, false).unwrap(); assert_eq!(a.ip().to_string(), "127.0.0.1"); assert_eq!(a.port(), 8080); }
    #[test] fn test_resolve_invalid() { let _ = resolve("invalid.xyzzy", 80, false, false); }
}
