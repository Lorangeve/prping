//! TCP ping — test TCP port connectivity and measure connection latency.

use crate::drive::{Probe, ProbeOutcome, drive};
use crate::output;
use crate::stats::{self, Stats};
use crate::util::{self, PingConfig};
use rust_i18n::t;
use std::net::SocketAddr;
use std::time::Duration;
use termcolor::StandardStream;

/// 返回 `Ok(true)` 表示有丢包（供退出码判断）。
pub fn ping(cfg: &PingConfig) -> anyhow::Result<Stats> {
    let addrs = util::resolve_vec(&cfg.host, cfg.port, cfg.v4, cfg.v6)?;
    if let Some(first) = addrs.first() {
        util::print_resolving(&cfg.host, first.ip());
    }
    if !stats::json() {
        if let Some(first) = addrs.first() {
            println!(
                "{}",
                t!(
                    "tcp.connect_to",
                    addr = first.ip().to_string(),
                    port = first.port()
                )
            );
        }
        if let Some(d) = cfg.duration {
            println!("{}", t!("tcp.duration", secs = d, warmup = cfg.warmup));
        } else if cfg.count == 0 {
            // 默认（无 -n）为无限模式：明确显示，避免「N 次迭代」误导
            println!("{}", t!("common.iterations_infinite", warmup = cfg.warmup));
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
    smol::block_on(ping_async(addrs, cfg))
}

async fn ping_async(addrs: Vec<SocketAddr>, cfg: &PingConfig) -> anyhow::Result<Stats> {
    let mut probe = TcpProbe { addrs, cfg };
    drive(
        cfg,
        "tcp",
        &format!("{}:{}", cfg.host, cfg.port),
        &mut probe,
    )
    .await
}

/// TCP 探测体：connect + 人读行（统计/JSONL 由 drive 统一处理）。
struct TcpProbe<'a> {
    addrs: Vec<SocketAddr>,
    cfg: &'a PingConfig,
}

impl Probe for TcpProbe<'_> {
    async fn probe(
        &mut self,
        w: &mut StandardStream,
        _seq: u64,
        is_warmup: bool,
    ) -> anyhow::Result<ProbeOutcome> {
        match util::connect_timed(&self.addrs, self.cfg.source).await {
            Ok((stream, rtt)) => {
                let local = stream.get_ref().local_addr().ok();
                let peer = stream.get_ref().peer_addr().unwrap_or(self.addrs[0]);
                if !self.cfg.quiet && !stats::json() {
                    print_connected(w, peer, local, rtt, is_warmup)?;
                }
                Ok(ProbeOutcome::Ok { rtt })
            }
            Err(e) => {
                if !self.cfg.quiet && !stats::json() {
                    output::writeln_red(w, &t!("common.connect_failed", error = e.to_string()))?;
                }
                Ok(ProbeOutcome::Err {
                    json_err: "connect failed",
                })
            }
        }
    }
}

fn print_connected(
    w: &mut StandardStream,
    addr: std::net::SocketAddr,
    local: Option<std::net::SocketAddr>,
    rtt: Duration,
    warmup: bool,
) -> anyhow::Result<()> {
    output::print_probe_result(
        w,
        &t!("common.connecting_to"),
        addr,
        None,
        rtt,
        None,
        warmup,
        local,
    )?;
    Ok(())
}
