//! TCP ping — test TCP port connectivity and measure connection latency.

use crate::output;
use crate::stats::{self, Stats};
use rust_i18n::t;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use termcolor::StandardStream;

#[allow(clippy::too_many_arguments)]
pub fn ping(host: &str, port: u16, count: u64, interval: f64, quiet: bool, histogram: Option<usize>, warmup: u64, v4: bool, v6: bool) -> anyhow::Result<()> {
    let addr = resolve(host, port, v4, v6)?;
    if host.parse::<IpAddr>().is_err() {
        let stripped = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
        if stripped.parse::<IpAddr>().is_err() {
            println!("{}", t!("common.resolving", host = host, ip = addr.ip().to_string()));
        }
    }
    println!("{}", t!("tcp.connect_to", addr = addr.ip().to_string(), port = addr.port()));
    println!("{}", t!("tcp.iterations", total = warmup + count, warmup = warmup));
    smol::block_on(ping_async(addr, count, interval, quiet, histogram, warmup))
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
            addrs.into_iter().next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "cannot resolve host"))
        }).await
    })?)
}

async fn ping_async(addr: SocketAddr, count: u64, interval: f64, quiet: bool, histogram: Option<usize>, warmup: u64) -> anyhow::Result<()> {
    let mut stats = Stats::default();
    let mut w = output::stdout();
    let total = if count == 0 { u64::MAX } else { warmup + count };

    for seq in 0..total {
        if seq > 0 { smol::Timer::after(Duration::from_secs_f64(interval)).await; }
        let start = Instant::now();
        match smol::net::TcpStream::connect(addr).await {
            Ok(stream) => {
                let rtt = start.elapsed();
                let local = stream.local_addr().ok();
                let is_warmup = seq < warmup;
                if !is_warmup { stats.record(rtt); }
                if !quiet { print_connected(&mut w, addr, local, rtt, is_warmup)?; }
            }
            Err(e) => {
                let is_warmup = seq < warmup;
                if !is_warmup { stats.record_loss(); }
                if !quiet { output::writeln_red(&mut w, &t!("common.connect_failed", error = e.to_string()))?; }
            }
        }
    }

    if !quiet { println!(); }
    stats::print_summary(&mut w, &stats)?;
    if histogram.is_some() && stats.received > 0 { stats::print_histogram(&mut w, &stats, histogram)?; }
    stats::print_timeline(&mut w, &stats)?;
    Ok(())
}

fn print_connected(w: &mut StandardStream, addr: SocketAddr, local: Option<SocketAddr>, rtt: Duration, warmup: bool) -> anyhow::Result<()> {
    output::print_green(w, &t!("common.connecting_to"))?;
    output::print_cyan(w, addr.ip().to_string())?;
    write!(w, ":")?;
    output::print_magenta(w, addr.port().to_string())?;
    if warmup { output::print_dim(w, format!(" {}", t!("common.warmup")))?; }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_resolve_ip_direct() { let a = resolve("127.0.0.1", 80, false, false).unwrap(); assert_eq!(a.ip().to_string(), "127.0.0.1"); assert_eq!(a.port(), 80); }
    #[test] fn test_resolve_ipv6() { let a = resolve("::1", 8080, false, false).unwrap(); assert_eq!(a.ip().to_string(), "::1"); assert_eq!(a.port(), 8080); }
    #[test] fn test_resolve_invalid() { let _ = resolve("invalid.xyzzy", 80, false, false); }
}
