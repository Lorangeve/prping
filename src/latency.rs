//! Latency test — client/server TCP/UDP round-trip latency measurement.

use crate::output;
use crate::stats::{self, Stats};
use rust_i18n::t;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::{TcpStream, UdpSocket};
use std::io::Write;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use termcolor::StandardStream;

#[allow(clippy::too_many_arguments)]
pub fn run_client(host: &str, port: u16, count: u64, size: usize, udp: bool, receive: bool, histogram: Option<usize>, warmup: u64, v4: bool, v6: bool) -> anyhow::Result<()> {
    let addr = resolve(host, port, v4, v6)?;
    if host.parse::<IpAddr>().is_err() {
        let stripped = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
        if stripped.parse::<IpAddr>().is_err() {
            let mut w = output::stdout();
            writeln!(&mut w, "{}", t!("common.resolving", host = host, ip = addr.ip().to_string()))?;
        }
    }
    smol::block_on(run_client_async(addr, count, size, udp, receive, histogram, warmup))
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

async fn run_client_async(addr: SocketAddr, count: u64, size: usize, udp: bool, receive: bool, histogram: Option<usize>, warmup: u64) -> anyhow::Result<()> {
    if udp { run_udp_client(addr, count, size, receive, histogram, warmup).await }
    else { run_tcp_client(addr, count, size, receive, histogram, warmup).await }
}

async fn run_tcp_client(addr: SocketAddr, count: u64, size: usize, receive: bool, histogram: Option<usize>, warmup: u64) -> anyhow::Result<()> {
    let mut stats = Stats::default();
    let mut w = output::stdout();
    let total = warmup + count;

    for seq in 0..total {
        if seq > 0 { smol::Timer::after(Duration::from_secs(1)).await; }
        let start = Instant::now();
        let mut stream = match connect_timeout(addr).await {
            Ok(s) => s,
            Err(e) => { if seq >= warmup { stats.record_loss(); output::writeln_red(&mut w, &t!("common.connect_failed", error = e))?; } continue; }
        };
        stream.set_nodelay(true)?;

        if receive {
            // Send trigger byte, server responds with size bytes
            stream.write_all(&[0xFF]).await?;
            let mut buf = vec![0u8; size + 1];
            match smol::future::or(
                async { stream.read_exact(&mut buf[..1]).await?; stream.read_exact(&mut buf[1..]).await.map(|_| size + 1) },
                async { smol::Timer::after(Duration::from_secs(10)).await; Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")) },
            ).await {
                Ok(_) => { let rtt = start.elapsed(); let is_warmup = seq < warmup; if !is_warmup { stats.record(rtt); } print_latency(&mut w, addr, rtt, size, is_warmup)?; }
                Err(_) => { if seq >= warmup { stats.record_loss(); } output::writeln_red(&mut w, t!("common.timeout"))?; }
            }
            continue;
        }

        let payload = vec![0x42u8; size];
        if stream.write_all(&payload).await.is_err() { continue; }

        let mut buf = vec![0u8; size];
        match smol::future::or(
            async { stream.read_exact(&mut buf).await },
            async { smol::Timer::after(Duration::from_secs(10)).await; Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")) },
        ).await {
            Ok(_) => { let rtt = start.elapsed(); let is_warmup = seq < warmup; if !is_warmup { stats.record(rtt); } print_latency(&mut w, addr, rtt, size, is_warmup)?; }
            Err(_) => { let is_warmup = seq < warmup; if !is_warmup { stats.record_loss(); } output::writeln_red(&mut w, t!("common.timeout"))?; }
        }
    }
    print_result(&mut w, &stats, histogram)?;
    Ok(())
}

async fn run_udp_client(addr: SocketAddr, count: u64, size: usize, _receive: bool, histogram: Option<usize>, warmup: u64) -> anyhow::Result<()> {
    // UDP receive mode not implemented
    let _ = _receive;
    let bind_addr: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let sock = UdpSocket::bind(bind_addr).await?;
    let mut stats = Stats::default();
    let mut w = output::stdout();
    let total = warmup + count;
    let payload = vec![0x42u8; size];

    for seq in 0..total {
        if seq > 0 { smol::Timer::after(Duration::from_secs(1)).await; }
        let start = Instant::now();
        if sock.send_to(&payload, addr).await.is_err() { continue; }
        let mut buf = vec![0u8; size + 512];
        match smol::future::or(
            async { Some(sock.recv_from(&mut buf).await) },
            async { smol::Timer::after(Duration::from_secs(10)).await; None },
        ).await {
            Some(Ok((n, _))) => { let rtt = start.elapsed(); let is_warmup = seq < warmup; if !is_warmup { stats.record(rtt); } print_latency(&mut w, addr, rtt, n, is_warmup)?; }
            _ => { let is_warmup = seq < warmup; if !is_warmup { stats.record_loss(); } output::writeln_red(&mut w, t!("common.timeout"))?; }
        }
    }
    print_result(&mut w, &stats, histogram)?;
    Ok(())
}

fn print_latency(w: &mut StandardStream, addr: SocketAddr, rtt: Duration, size: usize, warmup: bool) -> anyhow::Result<()> {
    output::print_green(w, t!("common.reply_from"))?;
    output::print_cyan(w, format!("{}:{}", addr.ip(), addr.port()))?;
    write!(w, ": {}{size} ", t!("common.bytes"))?;
    output::print_yellow(w, format!("{}{:.2}ms", t!("common.time"), rtt.as_secs_f64() * 1000.0))?;
    if warmup { output::print_yellow(w, format!(" {}", t!("common.warmup")))?; }
    writeln!(w)?;
    Ok(())
}

async fn connect_timeout(addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
    smol::future::or(
        TcpStream::connect(addr),
        async {
            smol::Timer::after(Duration::from_secs(5)).await;
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))
        },
    ).await
}

fn print_result(w: &mut StandardStream, stats: &Stats, histogram: Option<usize>) -> anyhow::Result<()> { println!(); stats::print_summary(w, stats)?; if histogram.is_some() && stats.received > 0 { stats::print_histogram(w, stats, histogram)?; } stats::print_timeline(w, stats)?; Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_resolve_ipv6_brackets() { let a = resolve("[::1]", 9999, false, false).unwrap(); assert_eq!(a.ip().to_string(), "::1"); assert_eq!(a.port(), 9999); }
}
