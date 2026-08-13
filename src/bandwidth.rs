//! Bandwidth test — client/server TCP/UDP bandwidth measurement.

use crate::output;
use rust_i18n::t;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::{TcpStream, UdpSocket};
use std::io::Write;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

#[allow(clippy::too_many_arguments)]
pub fn run_client(host: &str, port: u16, count: u64, size: usize, parallel: u32, udp: bool, receive: bool, histogram: Option<usize>, warmup: u64, v4: bool, v6: bool) -> anyhow::Result<()> {
    let addr = resolve(host, port, v4, v6)?;
    if host.parse::<IpAddr>().is_err() {
        let stripped = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
        if stripped.parse::<IpAddr>().is_err() {
            let mut w = output::stdout();
            writeln!(&mut w, "{}", t!("common.resolving", host = host, ip = addr.ip().to_string()))?;
        }
    }
    smol::block_on(run_client_async(addr, count, size, parallel, udp, receive, histogram, warmup))
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

#[allow(clippy::too_many_arguments)]
async fn run_client_async(addr: SocketAddr, count: u64, size: usize, parallel: u32, udp: bool, receive: bool, histogram: Option<usize>, warmup: u64) -> anyhow::Result<()> {
    if udp { run_udp(addr, count, size, receive, histogram, warmup).await }
    else { run_tcp(addr, count, size, parallel, receive, histogram, warmup).await }
}

async fn run_tcp(addr: SocketAddr, count: u64, size: usize, parallel: u32, receive: bool, histogram: Option<usize>, warmup: u64) -> anyhow::Result<()> {
    if warmup > 0 && !receive {
        let mut stream = connect_timeout(addr).await?;
        stream.set_nodelay(true)?;
        let payload = vec![0u8; size];
        for _ in 0..warmup { stream.write_all(&payload).await?; }
        println!("{}", t!("bandwidth.warmup_complete", count = warmup));
    }

    if receive {
        let mut stream = connect_timeout(addr).await?;
        stream.set_nodelay(true)?;
        stream.write_all(&[0xFF]).await?;
        let target_bytes = count * size as u64;
        let mut buf = vec![0u8; 65536];
        let mut total: u64 = 0;
        let start = Instant::now();
        while total < target_bytes {
            let n = stream.read(&mut buf).await?;
            if n == 0 { break; }
            total += n as u64;
        }
        let times = vec![start.elapsed()];
        report(t!("bandwidth.tcp_test"), size, count, start.elapsed(), histogram, &times)?;
        return Ok(());
    }

    if parallel <= 1 {
        let mut stream = connect_timeout(addr).await?;
        stream.set_nodelay(true)?;
        let payload = vec![0u8; size];
        let mut times = Vec::new();
        let start = Instant::now();
        for _ in 0..count {
            let t0 = Instant::now();
            stream.write_all(&payload).await?;
            if histogram.is_some() { times.push(t0.elapsed()); }
        }
        drop(stream);
        report(t!("bandwidth.tcp_test"), size, count, start.elapsed(), histogram, &times)?;
    } else {
        let mut tasks = Vec::new();
        let per_conn = count / parallel as u64;
        for _ in 0..parallel {
            let a = addr;
            tasks.push(smol::spawn(async move {
                let mut stream = connect_timeout(a).await?;
                stream.set_nodelay(true)?;
                let payload = vec![0u8; size];
                for _ in 0..per_conn { stream.write_all(&payload).await?; }
                Ok::<_, anyhow::Error>(())
            }));
        }
        let start = Instant::now();
        for t in tasks { t.await?; }
        report(t!("bandwidth.tcp_test"), size, count, start.elapsed(), histogram, &[])?;
    }
    Ok(())
}

async fn connect_timeout(addr: SocketAddr) -> anyhow::Result<TcpStream> {
    smol::future::or(
        TcpStream::connect(addr),
        async {
            smol::Timer::after(Duration::from_secs(5)).await;
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))
        },
    ).await.map_err(Into::into)
}

async fn run_udp(addr: SocketAddr, count: u64, size: usize, _receive: bool, histogram: Option<usize>, warmup: u64) -> anyhow::Result<()> {
    // UDP receive mode not implemented; falls back to send
    let _ = _receive;
    let bind_addr: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let sock = UdpSocket::bind(bind_addr).await?;
    if warmup > 0 {
        let payload = vec![0u8; size];
        for _ in 0..warmup { sock.send_to(&payload, addr).await?; }
        println!("{}", t!("bandwidth.warmup_complete", count = warmup));
    }
    let payload = vec![0u8; size];
    let mut times = Vec::new();
    let start = Instant::now();
    for _ in 0..count {
        let t0 = Instant::now();
        sock.send_to(&payload, addr).await?;
        if histogram.is_some() { times.push(t0.elapsed()); }
    }
    report(t!("bandwidth.udp_test"), size, count, start.elapsed(), histogram, &times)?;
    Ok(())
}

fn report(label: impl AsRef<str>, size: usize, count: u64, elapsed: Duration, histogram: Option<usize>, times: &[Duration]) -> anyhow::Result<()> {
    let label = label.as_ref();
    let mut w = output::stdout();
    let secs = elapsed.as_secs_f64();
    let total_bytes = size as u64 * count;
    let mbits = total_bytes as f64 * 8.0 / (secs * 1_000_000.0);
    println!();
    output::print_bold(&mut w, label)?; writeln!(&mut w)?;
    writeln!(&mut w, "  {}", t!("bandwidth.sent_bytes", bytes = total_bytes, secs = format!("{:.2}", secs)))?;
    output::print_green(&mut w, format!("  {}\n", t!("bandwidth.bandwidth", mbps = format!("{:.2}", mbits))))?;
    if let Some(buckets) = histogram
        && !times.is_empty() {
            let mut s = crate::stats::Stats::default();
            for t in times { s.record(*t); }
            crate::stats::print_histogram(&mut w, &s, Some(buckets))?;
        }
    Ok(())
}

