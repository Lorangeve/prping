//! 统一 ping 循环驱动器：icmp/tcp/udp/latency 共用的测量循环骨架。
//!
//! 循环、预热、统计记录、JSONL 逐行与收尾（汇总/直方图/时间线）收敛在这里；
//! 各模式只实现「一次探测」——网络 I/O 与人读输出行（`Probe` trait）。

use crate::output;
use crate::stats::{self, Stats};
use crate::util::{self, PingConfig, Run};
use std::time::Duration;
use termcolor::StandardStream;

/// 分片睡眠：每 100ms 检查一次 Ctrl+C 中断标志。
///
/// 返回 false 表示睡眠期间收到中断（调用方应停止循环）。
/// drive 的循环间隔因此对 Ctrl+C 的响应延迟从「一个完整 interval」
/// 降到 ~100ms；纯计时语义不变（累计时长精确到 100ms 以内）。
async fn interruptible_sleep(total: Duration) -> bool {
    let mut remaining = total;
    while remaining > Duration::ZERO {
        if util::interrupted() {
            return false;
        }
        let step = remaining.min(Duration::from_millis(100));
        smol::Timer::after(step).await;
        remaining -= step;
    }
    !util::interrupted()
}

/// 一次探测的结果：drive 统一处理统计记录与 JSONL 输出。
pub enum ProbeOutcome {
    /// 成功：记录一次 rtt。
    Ok { rtt: Duration },
    /// 失败：记录一次丢包；`json_err` 写入 JSONL 的 error 字段。
    Err { json_err: &'static str },
    /// 跳过：不记录不输出（发送失败等），仅推进循环。
    Skip,
}

/// 模式相关的一次探测：负责网络 I/O 与人读输出行。
///
/// drive 只负责循环骨架/统计/JSONL/收尾；探测体与每行渲染由各模式实现。
/// `w` 为人读输出流（json/quiet 时无输出需求），`seq` 为当前迭代序号
/// （含预热），`is_warmup` 为预热标记。
pub trait Probe {
    async fn probe(
        &mut self,
        w: &mut StandardStream,
        seq: u64,
        is_warmup: bool,
    ) -> anyhow::Result<ProbeOutcome>;
}

/// 统一 ping 循环：间隔、预热、统计、JSONL 逐行、收尾（汇总/直方图/时间线）。
///
/// `mode` 用于 JSONL 的 type 字段（"icmp"/"tcp"/"udp"/"latency"），
/// `target` 为被测目标串（如 "host:port"）。
pub async fn drive<P: Probe>(
    cfg: &PingConfig,
    mode: &str,
    target: &str,
    probe: &mut P,
) -> anyhow::Result<Stats> {
    let mut stats = Stats::default();
    let mut w = output::stdout();
    let mut run = Run::new(cfg.count, cfg.warmup, cfg.duration);
    // JSONL 的 seq 用「有效迭代计数」（跳过预热），保证从 1 连续
    let mut valid_seq: u64 = 0;

    loop {
        if run.done() {
            break;
        }
        let is_warmup = run.is_warmup();
        let seq = run.seq();
        match probe.probe(&mut w, seq, is_warmup).await? {
            ProbeOutcome::Ok { rtt } => {
                if !is_warmup {
                    stats.record(rtt);
                }
                if stats::json() && !is_warmup {
                    valid_seq += 1;
                    stats::json_sample(&mut w, mode, target, valid_seq, true, Some(rtt), None)?;
                }
            }
            ProbeOutcome::Err { json_err } => {
                if !is_warmup {
                    stats.record_loss();
                }
                if stats::json() && !is_warmup {
                    valid_seq += 1;
                    stats::json_sample(
                        &mut w,
                        mode,
                        target,
                        valid_seq,
                        false,
                        None,
                        Some(json_err),
                    )?;
                }
            }
            ProbeOutcome::Skip => {}
        }
        run.advance();
        // 间隔在「确认还有下一轮」之后等待：count 模式最后一轮不再多睡一个
        // 完整 interval（原实现在循环顶先睡再查 done，固定次数运行总会多等一次）。
        // 分片 sleep：每 100ms 检查一次 Ctrl+C，中断响应不再被长 interval 拖住。
        if !run.done() && !interruptible_sleep(Duration::from_secs_f64(cfg.interval)).await {
            break;
        }
    }

    if !cfg.quiet && !stats::json() {
        println!();
    }
    stats::print_summary(&mut w, &stats, mode, target)?;
    if !stats::json()
        && stats.received > 0
        && let Some(spec) = &cfg.histogram
    {
        // samples 现为 VecDeque：复制一份供直方图（每轮渲染一次）
        let samples: Vec<std::time::Duration> = stats.samples().iter().copied().collect();
        stats::print_histogram(&mut w, &samples, spec)?;
    }
    if cfg.graph && !stats::json() {
        stats::print_timeline(&mut w, &stats)?;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::PingConfig;

    /// 假探测：seq==1 失败、seq==2 跳过，其余成功。
    struct FakeProbe;

    impl Probe for FakeProbe {
        async fn probe(
            &mut self,
            _w: &mut StandardStream,
            seq: u64,
            _is_warmup: bool,
        ) -> anyhow::Result<ProbeOutcome> {
            match seq {
                1 => Ok(ProbeOutcome::Err {
                    json_err: "timeout",
                }),
                2 => Ok(ProbeOutcome::Skip),
                _ => Ok(ProbeOutcome::Ok {
                    rtt: Duration::from_millis(1),
                }),
            }
        }
    }

    fn cfg() -> PingConfig {
        PingConfig {
            host: "127.0.0.1".into(),
            port: 0,
            count: 4,
            duration: None,
            interval: 0.0,
            size: None,
            quiet: true,
            histogram: None,
            warmup: 0,
            v4: false,
            v6: false,
            parallel: 1,
            udp: false,
            receive: false,
            bandwidth: false,
            graph: false,
            mtu: false,
            traceroute: false,
            trace_tcp: false,
            trace_udp: false,
            max_hops: 30,
            no_dns: false,
            source: None,
        }
    }

    #[test]
    fn drive_records_stats() {
        let mut p = FakeProbe;
        let stats = smol::block_on(drive(&cfg(), "test", "127.0.0.1", &mut p)).unwrap();
        // seq 0→Ok, 1→Err, 2→Skip, 3→Ok：sent=3, received=2, 丢包 1/3
        assert_eq!(stats.sent, 3);
        assert_eq!(stats.received, 2); // Skip 不计数
        assert!((stats.loss_pct() - 33.33).abs() < 0.1);
        assert!(stats.has_loss());
    }

    #[test]
    fn drive_warmup_not_counted() {
        let mut c = cfg();
        c.count = 2;
        c.warmup = 2;
        let mut p = FakeProbe;
        let stats = smol::block_on(drive(&c, "test", "127.0.0.1", &mut p)).unwrap();
        // 2 预热 + 2 有效 = 4 次迭代；有效迭代 seq 2（Skip）不计数、seq 3（成功）计数
        assert_eq!(stats.sent, 1);
        assert_eq!(stats.received, 1);
    }
}
