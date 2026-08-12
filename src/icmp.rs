//! ICMP ping — send ICMP echo requests and measure round-trip latency.

use crate::output;
use crate::stats::{self, Stats};
use rust_i18n::t;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use termcolor::StandardStream;

#[allow(clippy::too_many_arguments)]
pub fn ping(host: &str, count: u64, interval: f64, size: usize, quiet: bool, histogram: Option<usize>, warmup: u64, v4: bool, v6: bool) -> anyhow::Result<()> {
    let addrs: Vec<SocketAddr> = resolve(host, v4, v6)?;
    if addrs.is_empty() { anyhow::bail!(t!("errors.cannot_resolve", host = host)); }

    let addr = addrs[0].ip();
    if host.parse::<IpAddr>().is_err() {
        let stripped = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
        if stripped.parse::<IpAddr>().is_err() {
            println!("{}", t!("common.resolving", host = host, ip = addr.to_string()));
        }
    }

    println!("{}", t!("icmp.pinging", addr = addr.to_string(), size = size));
    println!("{}", t!("icmp.iterations", total = warmup + count, warmup = warmup));

    smol::block_on(ping_async(addr, count, interval, size, quiet, histogram, warmup))
}

fn resolve(host: &str, force_v4: bool, force_v6: bool) -> anyhow::Result<Vec<SocketAddr>> {
    let raw = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = raw.parse::<IpAddr>() { return Ok(vec![SocketAddr::new(ip, 0)]); }
    let host = raw.to_string();
    Ok(smol::block_on(async {
        smol::unblock(move || {
            let mut addrs: Vec<SocketAddr> = (host.as_str(), 0).to_socket_addrs()?.collect();
            if force_v4 { addrs.retain(|a| a.is_ipv4()); }
            else if force_v6 { addrs.retain(|a| a.is_ipv6()); }
            Ok::<_, std::io::Error>(addrs)
        }).await
    })?)
}

async fn ping_async(addr: IpAddr, count: u64, interval: f64, size: usize, quiet: bool, histogram: Option<usize>, warmup: u64) -> anyhow::Result<()> {
    let (sock, target) = create_socket(addr)?;
    let async_sock = smol::Async::new(sock)?;
    let mut stats = Stats::default();
    let mut w = output::stdout();
    let ident = rand_id();
    let total = if count == 0 { u64::MAX } else { warmup + count };

    for seq in 0..total {
        if seq > 0 { smol::Timer::after(Duration::from_secs_f64(interval)).await; }
        let seq_num = seq as u16;
        match send_recv(&async_sock, &target, ident, seq_num, size, addr).await {
            Ok((rtt, ttl, reply_size)) => {
                let is_warmup = seq < warmup;
                if !is_warmup { stats.record(rtt); }
                if !quiet { print_reply(&mut w, addr, reply_size, rtt, ttl, is_warmup)?; }
            }
            Err(_) => {
                if seq >= warmup { stats.record_loss(); }
                if !quiet { output::writeln_red(&mut w, &t!("common.timeout"))?; }
            }
        }
    }

    if !quiet { println!(); }
    stats::print_summary(&mut w, &stats)?;
    if histogram.is_some() && stats.received > 0 { stats::print_histogram(&mut w, &stats, histogram)?; }
    stats::print_timeline(&mut w, &stats)?;
    Ok(())
}

fn create_socket(addr: IpAddr) -> anyhow::Result<(Socket, SockAddr)> {
    match addr {
        IpAddr::V4(v4) => {
            let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                .map_err(|e| anyhow::anyhow!(t!("errors.raw_socket", error = e.to_string())))?;
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V4(v4), 0))))
        }
        IpAddr::V6(v6) => {
            let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
                .map_err(|e| anyhow::anyhow!(t!("errors.raw_socket", error = e.to_string())))?;
            Ok((sock, SockAddr::from(SocketAddr::new(IpAddr::V6(v6), 0))))
        }
    }
}

fn print_reply(w: &mut StandardStream, addr: IpAddr, size: usize, rtt: Duration, ttl: u8, warmup: bool) -> anyhow::Result<()> {
    output::print_green(w, &t!("common.reply_from"))?;
    output::print_cyan(w, addr.to_string())?;
    write!(w, ": {}={size} ", t!("common.bytes"))?;
    output::print_yellow(w, format!("{}={:.2}ms", t!("common.time"), rtt.as_secs_f64() * 1000.0))?;
    write!(w, " {}={ttl}", t!("common.ttl"))?;
    if warmup { output::print_yellow(w, format!(" {}", t!("common.warmup")))?; }
    writeln!(w)?;
    Ok(())
}

async fn send_recv(async_sock: &smol::Async<Socket>, target: &SockAddr, ident: u16, seq: u16, payload_size: usize, addr: IpAddr) -> Result<(Duration, u8, usize), ()> {
    let request = build_icmp_echo(addr, ident, seq, payload_size);
    let send_time = Instant::now();
    async_sock.write_with(|sock| sock.send_to(&request, target)).await.map_err(|_| ())?;
    let mut buf: [MaybeUninit<u8>; 4096] = unsafe { MaybeUninit::uninit().assume_init() };
    let timeout = Duration::from_secs(4);
    let recv = smol::future::or(
        async { async_sock.read_with(|sock| sock.recv_from(&mut buf)).await.map(|(n, _)| n) },
        async { smol::Timer::after(timeout).await; Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")) },
    ).await;
    match recv { Ok(n) => parse_reply(&buf, n, ident, seq, send_time, addr), Err(_) => Err(()) }
}

fn parse_reply(buf: &[MaybeUninit<u8>], n: usize, ident: u16, seq: u16, send_time: Instant, expected_src: IpAddr) -> Result<(Duration, u8, usize), ()> {
    let rtt = send_time.elapsed();
    let buf_init: &[u8] = unsafe { std::mem::transmute(&buf[..n]) };
    match expected_src {
        IpAddr::V4(_) => {
            if buf_init.len() < 28 { return Err(()); }
            let ip_header_len = ((buf_init[0] & 0x0F) as usize) * 4;
            let icmp = &buf_init[ip_header_len..];
            if icmp.len() < 8 || icmp[0] != 0 { return Err(()); }
            if u16::from_be_bytes([icmp[4], icmp[5]]) != ident || u16::from_be_bytes([icmp[6], icmp[7]]) != seq { return Err(()); }
            Ok((rtt, buf_init[8], n - ip_header_len))
        }
        IpAddr::V6(_) => {
            if buf_init.len() < 48 { return Err(()); }
            let icmp = &buf_init[40..];
            if icmp.len() < 8 || icmp[0] != 129 { return Err(()); }
            if u16::from_be_bytes([icmp[4], icmp[5]]) != ident || u16::from_be_bytes([icmp[6], icmp[7]]) != seq { return Err(()); }
            Ok((rtt, buf_init[7], n - 40))
        }
    }
}

fn build_icmp_echo(addr: IpAddr, ident: u16, seq: u16, payload_size: usize) -> Vec<u8> {
    match addr { IpAddr::V4(_) => build_v4(ident, seq, payload_size), IpAddr::V6(_) => build_v6(ident, seq, payload_size) }
}
fn build_v4(ident: u16, seq: u16, payload_size: usize) -> Vec<u8> { let total=8+payload_size; let mut b=vec![0u8; total]; b[0]=8; b[1]=0; b[4]=(ident>>8)as u8; b[5]=ident as u8; b[6]=(seq>>8)as u8; b[7]=seq as u8; for i in 0..payload_size{b[8+i]=(i%256)as u8} let c=icmp_cksum(&b); b[2]=(c>>8)as u8; b[3]=c as u8; b }
fn build_v6(ident: u16, seq: u16, payload_size: usize) -> Vec<u8> { let total=8+payload_size; let mut b=vec![0u8; total]; b[0]=128; b[1]=0; b[4]=(ident>>8)as u8; b[5]=ident as u8; b[6]=(seq>>8)as u8; b[7]=seq as u8; for i in 0..payload_size{b[8+i]=(i%256)as u8} b }
fn icmp_cksum(data: &[u8]) -> u16 { let mut s=0u32; for c in data.chunks(2){s+=if c.len()==2{u16::from_be_bytes([c[0],c[1]])as u32}else{(c[0]as u32)<<8}} while s>>16!=0{s=(s&0xFFFF)+(s>>16)} !(s as u16) }
fn rand_id() -> u16 { use std::collections::hash_map::RandomState; use std::hash::{BuildHasher,Hasher}; RandomState::new().build_hasher().finish() as u16 }

#[cfg(test)]
mod tests {
    use super::*; use std::net::Ipv4Addr;
    #[test] fn test_icmpv4_echo_build() { let b=build_v4(0x1234,0x0001,32); assert_eq!(b.len(),40); assert_eq!(b[0],8); assert_eq!(b[4],0x12); }
    #[test] fn test_icmpv6_echo_build() { let b=build_v6(0xABCD,0x0005,16); assert_eq!(b.len(),24); assert_eq!(b[0],128); }
    #[test] fn test_icmp_cksum_known() { assert_ne!(icmp_cksum(&[8,0,0,0,0,1,0,1,0x41,0x42,0,0,0,0,0,0]),0); }
    #[test] fn test_icmp_cksum_zeros() { assert_eq!(icmp_cksum(&[0u8;8]),0xFFFF); }
    #[test] fn test_resolve_ip_direct() { let a=resolve("127.0.0.1",false,false).unwrap(); assert_eq!(a[0].ip().to_string(),"127.0.0.1"); }
    #[test] fn test_resolve_ipv6_direct() { let a=resolve("::1",false,false).unwrap(); assert_eq!(a[0].ip().to_string(),"::1"); }
    #[test] fn test_resolve_ipv6_brackets() { let a=resolve("[::1]",false,false).unwrap(); assert_eq!(a[0].ip().to_string(),"::1"); }
    #[test] fn test_resolve_invalid_host() { let _=resolve("invalid.host.name.xyzzy",false,false); }
    #[test] fn test_ipv4_reply_parse() { let ident=0x1234u16; let seq=0x0002u16; let mut p=Vec::new(); p.extend([0x45,0,0,40,0,0,0,0,64,1,0,0,127,0,0,1,127,0,0,1]); p.push(0); p.push(0); p.extend((0u16).to_be_bytes()); p.extend(ident.to_be_bytes()); p.extend(seq.to_be_bytes()); p.extend(vec![0u8;16]); let ttl=p[8]; let mut u: [MaybeUninit<u8>;256]=unsafe{MaybeUninit::uninit().assume_init()}; for(i,&b)in p.iter().enumerate(){u[i].write(b);} let r=parse_reply(&u,p.len(),ident,seq,Instant::now(),IpAddr::V4(Ipv4Addr::new(127,0,0,1))); assert!(r.is_ok()); assert_eq!(r.unwrap().1,ttl); }
    #[test] fn test_ipv4_reply_wrong_ident() { let mut p=Vec::new(); p.extend([0x45,0,0,40,0,0,0,0,64,1,0,0,127,0,0,1,127,0,0,1]); p.push(0);p.push(0);p.extend((0u16).to_be_bytes());p.extend(0xBBBBu16.to_be_bytes());p.extend(1u16.to_be_bytes());p.extend(vec![0u8;16]); let mut u:[MaybeUninit<u8>;256]=unsafe{MaybeUninit::uninit().assume_init()}; for(i,&b)in p.iter().enumerate(){u[i].write(b);} assert!(parse_reply(&u,p.len(),0xAAAA,1,Instant::now(),IpAddr::V4(Ipv4Addr::new(127,0,0,1))).is_err()); }
    #[test] fn test_parse_reply_too_short() { let u:[MaybeUninit<u8>;4]=unsafe{MaybeUninit::uninit().assume_init()}; assert!(parse_reply(&u,4,0,0,Instant::now(),IpAddr::V4(Ipv4Addr::new(127,0,0,1))).is_err()); }
}
