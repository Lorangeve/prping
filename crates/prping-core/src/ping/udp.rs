//! UDP ping — test UDP port reachability and measure round-trip latency.

use crate::drive::{Probe, ProbeOutcome, drive};
use crate::output;
use crate::stats::{self, Stats};
use crate::util::{self, PingConfig};
use rust_i18n::t;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use termcolor::StandardStream;

/// 返回 `Ok(true)` 表示有丢包（供退出码判断）。
pub fn ping(cfg: &PingConfig) -> anyhow::Result<Stats> {
    let addr = util::resolve(&cfg.host, cfg.port, cfg.v4, cfg.v6)?;
    util::print_resolving(&cfg.host, addr.ip());
    if !stats::json() {
        println!(
            "{}",
            t!(
                "udp.pinging",
                addr = addr.ip().to_string(),
                port = addr.port(),
                size = cfg.size.unwrap_or(32)
            )
        );
        if let Some(d) = cfg.duration {
            println!("{}", t!("udp.duration", secs = d, warmup = cfg.warmup));
        } else if cfg.count == 0 {
            // 默认（无 -n）为无限模式：明确显示，避免「N 次迭代」误导
            println!("{}", t!("common.iterations_infinite", warmup = cfg.warmup));
        } else {
            println!(
                "{}",
                t!(
                    "udp.iterations",
                    total = cfg.warmup + cfg.count,
                    warmup = cfg.warmup
                )
            );
        }
        println!("{}", t!("udp.echo_hint"));
    }
    smol::block_on(ping_async(addr, cfg))
}

async fn ping_async(target: SocketAddr, cfg: &PingConfig) -> anyhow::Result<Stats> {
    let sock = util::bind_udp(util::local_bind(target.is_ipv4(), cfg.source))?;
    // 前 4 字节放 u32 seq，用于回包校验（#3：过滤杂包）。用 4 字节而非 2 字节：
    // 2 字节 seq 在 >65535 次迭代后回绕，超长运行可能与陈旧回包撞号。
    let payload = vec![0u8; cfg.size.unwrap_or(32).max(4)];
    let buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::new(0u8); cfg.size.unwrap_or(32) + 512];
    let mut probe = UdpProbe {
        sock: &sock,
        payload,
        buf,
        target,
        cfg,
    };
    drive(
        cfg,
        "udp",
        &format!("{}:{}", cfg.host, cfg.port),
        &mut probe,
    )
    .await
}

/// UDP 探测体：发 seq 标记包 + 过滤杂包等回包 + 人读行（统计/JSONL 由 drive 处理）。
struct UdpProbe<'a> {
    sock: &'a smol::Async<socket2::Socket>,
    payload: Vec<u8>,
    buf: Vec<MaybeUninit<u8>>,
    target: SocketAddr,
    cfg: &'a PingConfig,
}

impl Probe for UdpProbe<'_> {
    async fn probe(
        &mut self,
        w: &mut StandardStream,
        seq: u64,
        is_warmup: bool,
    ) -> anyhow::Result<ProbeOutcome> {
        let seq_num = seq as u32;
        self.payload[..4].copy_from_slice(&seq_num.to_be_bytes());
        let start = Instant::now();
        if util::udp_send(self.sock, &self.payload, &self.target)
            .await
            .is_err()
        {
            return Ok(ProbeOutcome::Skip);
        }

        // 等待回包：校验前 2 字节 seq，杂包忽略继续等，直到整体超时
        let deadline = Instant::now() + Duration::from_secs(4);
        let result = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break Err(());
            }
            let recv = smol::future::or(
                async { Some(util::udp_recv(self.sock, &mut self.buf).await) },
                async {
                    smol::Timer::after(remaining).await;
                    None
                },
            )
            .await;
            match recv {
                Some(Ok((n, src))) => {
                    let init = util::init_slice(&self.buf, n);
                    if n >= 4 && init[..4] == seq_num.to_be_bytes() {
                        break Ok((start.elapsed(), src, n));
                    }
                    // 杂包：继续等待
                }
                _ => break Err(()),
            }
        };

        match result {
            Ok((rtt, src, n)) => {
                if !self.cfg.quiet && !stats::json() {
                    print_reply(w, src, n, rtt, is_warmup)?;
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

fn print_reply(
    w: &mut StandardStream,
    src: SocketAddr,
    size: usize,
    rtt: Duration,
    warmup: bool,
) -> anyhow::Result<()> {
    output::print_probe_result(
        w,
        &t!("common.reply_from"),
        src,
        Some(size),
        rtt,
        None,
        warmup,
        None,
    )?;
    Ok(())
}
