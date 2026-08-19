//! Latency test — client/server TCP/UDP round-trip latency measurement.

use crate::drive::{Probe, ProbeOutcome, drive};
use crate::output;
use crate::stats::{self, Stats};
use crate::util::{self, PingConfig};
use rust_i18n::t;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use termcolor::StandardStream;

/// 返回 `Ok(true)` 表示有丢包（供退出码判断）。
pub fn run_client(cfg: &PingConfig) -> anyhow::Result<Stats> {
    let addrs = util::resolve_vec(&cfg.host, cfg.port, cfg.v4, cfg.v6)?;
    util::print_resolving(&cfg.host, addrs[0].ip());
    smol::block_on(run_client_async(addrs, cfg))
}

async fn run_client_async(addrs: Vec<SocketAddr>, cfg: &PingConfig) -> anyhow::Result<Stats> {
    if cfg.udp {
        run_udp_client(addrs[0], cfg).await
    } else {
        run_tcp_client(addrs, cfg).await
    }
}

async fn run_tcp_client(addrs: Vec<SocketAddr>, cfg: &PingConfig) -> anyhow::Result<Stats> {
    let payload = vec![0x42u8; cfg.size.unwrap()];
    let buf = vec![0u8; cfg.size.unwrap() + 1];
    let mut probe = LatencyTcpProbe {
        addrs,
        payload,
        buf,
        cfg,
    };
    drive(
        cfg,
        "latency",
        &format!("{}:{}", cfg.host, cfg.port),
        &mut probe,
    )
    .await
}

/// TCP 延迟探测体：connect + echo 往返（或接收模式触发）+ 人读行。
struct LatencyTcpProbe<'a> {
    addrs: Vec<SocketAddr>,
    payload: Vec<u8>,
    buf: Vec<u8>,
    cfg: &'a PingConfig,
}

impl Probe for LatencyTcpProbe<'_> {
    async fn probe(
        &mut self,
        w: &mut StandardStream,
        _seq: u64,
        is_warmup: bool,
    ) -> anyhow::Result<ProbeOutcome> {
        let start = Instant::now();
        let mut stream = match util::connect_first(&self.addrs, self.cfg.source).await {
            Ok(s) => s,
            Err(e) => {
                if !self.cfg.quiet && !stats::json() {
                    output::writeln_red(w, &t!("common.connect_failed", error = e.to_string()))?;
                }
                return Ok(ProbeOutcome::Err {
                    json_err: "connect failed",
                });
            }
        };
        stream.get_ref().set_nodelay(true)?;

        if self.cfg.receive {
            // 发送触发字节，服务器回送 size 字节
            stream.write_all(&[0xFF]).await?;
            match smol::future::or(
                async {
                    stream.read_exact(&mut self.buf[..1]).await?;
                    stream
                        .read_exact(&mut self.buf[1..])
                        .await
                        .map(|_| self.cfg.size.unwrap() + 1)
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
                    if !self.cfg.quiet && !stats::json() {
                        print_latency(w, self.addrs[0], rtt, self.cfg.size.unwrap(), is_warmup)?;
                    }
                    Ok(ProbeOutcome::Ok { rtt })
                }
                Err(_) => {
                    if !self.cfg.quiet && !stats::json() {
                        output::writeln_red(w, t!("common.timeout"))?;
                    }
                    Ok(ProbeOutcome::Err {
                        json_err: "timeout",
                    })
                }
            }
        } else {
            if stream.write_all(&self.payload).await.is_err() {
                return Ok(ProbeOutcome::Skip);
            }
            match smol::future::or(
                async {
                    stream
                        .read_exact(&mut self.buf[..self.cfg.size.unwrap()])
                        .await
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
                    if !self.cfg.quiet && !stats::json() {
                        print_latency(w, self.addrs[0], rtt, self.cfg.size.unwrap(), is_warmup)?;
                    }
                    Ok(ProbeOutcome::Ok { rtt })
                }
                Err(_) => {
                    if !self.cfg.quiet && !stats::json() {
                        output::writeln_red(w, t!("common.timeout"))?;
                    }
                    Ok(ProbeOutcome::Err {
                        json_err: "timeout",
                    })
                }
            }
        }
    }
}

async fn run_udp_client(addr: SocketAddr, cfg: &PingConfig) -> anyhow::Result<Stats> {
    let sock = util::bind_udp(util::local_bind(addr.is_ipv4(), cfg.source))?;
    let payload = vec![0x42u8; cfg.size.unwrap()];
    let trigger = util::udp_receive_trigger(cfg.size.unwrap(), 1);
    let buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::new(0u8); cfg.size.unwrap() + 512];
    let mut probe = LatencyUdpProbe {
        sock: &sock,
        payload,
        trigger,
        buf,
        addr,
        cfg,
    };
    drive(
        cfg,
        "latency",
        &format!("{}:{}", cfg.host, cfg.port),
        &mut probe,
    )
    .await
}

/// UDP 延迟探测体：发负载/触发包 + 等回包 + 人读行。
struct LatencyUdpProbe<'a> {
    sock: &'a smol::Async<socket2::Socket>,
    payload: Vec<u8>,
    trigger: Vec<u8>,
    buf: Vec<MaybeUninit<u8>>,
    addr: SocketAddr,
    cfg: &'a PingConfig,
}

impl Probe for LatencyUdpProbe<'_> {
    async fn probe(
        &mut self,
        w: &mut StandardStream,
        _seq: u64,
        is_warmup: bool,
    ) -> anyhow::Result<ProbeOutcome> {
        let start = Instant::now();
        // 接收模式：发送触发包，服务器回送 size 字节；否则发送 size 字节负载
        let sent = if self.cfg.receive {
            util::udp_send(self.sock, &self.trigger, &self.addr).await
        } else {
            util::udp_send(self.sock, &self.payload, &self.addr).await
        };
        if sent.is_err() {
            return Ok(ProbeOutcome::Skip);
        }

        match smol::future::or(
            async { Some(util::udp_recv(self.sock, &mut self.buf).await) },
            async {
                smol::Timer::after(Duration::from_secs(10)).await;
                None
            },
        )
        .await
        {
            Some(Ok((n, _))) => {
                let rtt = start.elapsed();
                if !self.cfg.quiet && !stats::json() {
                    print_latency(w, self.addr, rtt, n, is_warmup)?;
                }
                Ok(ProbeOutcome::Ok { rtt })
            }
            _ => {
                if !self.cfg.quiet && !stats::json() {
                    output::writeln_red(w, t!("common.timeout"))?;
                }
                Ok(ProbeOutcome::Err {
                    json_err: "timeout",
                })
            }
        }
    }
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
