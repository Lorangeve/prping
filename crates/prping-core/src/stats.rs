//! Statistics collection and terminal output.

use crate::output;
use rust_i18n::t;
use std::io::{IsTerminal, Result, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use termcolor::StandardStream;

static PRETTY: AtomicBool = AtomicBool::new(false);
static JSON: AtomicBool = AtomicBool::new(false);

/// Enable Unicode/Braille rendering.
pub fn set_pretty(v: bool) {
    PRETTY.store(v, Ordering::Relaxed);
}

/// Enable machine-readable JSON output.
pub fn set_json(v: bool) {
    JSON.store(v, Ordering::Relaxed);
}
pub fn json() -> bool {
    JSON.load(Ordering::Relaxed)
}

/// 直方图规格：固定桶数，或自定义阈值（ms）。
#[derive(Debug, Clone, PartialEq)]
pub enum HistogramSpec {
    Buckets(usize),
    Thresholds(Vec<f64>),
}

/// 解析 `-H` 参数："20" → Buckets(20)；"1,5,10,50" → Thresholds(\[1,5,10,50\])。
/// 非法/无意义输入返回 None（调用方报错）：桶数 0、空段（`1,` / `1,,5`）。
pub fn parse_histogram(s: &str) -> Option<HistogramSpec> {
    if s.contains(',') {
        let mut v: Vec<f64> = Vec::new();
        for p in s.split(',') {
            let t = p.trim();
            if t.is_empty() {
                return None; // `1,` / `1,,5`：空段是非法输入，不静默丢弃
            }
            v.push(t.parse().ok()?);
        }
        if v.is_empty() {
            return None;
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        v.dedup_by(|a, b| (*a - *b).abs() < f64::EPSILON);
        Some(HistogramSpec::Thresholds(v))
    } else {
        let n: usize = s.parse().ok()?;
        if n == 0 {
            return None; // 0 桶无意义
        }
        Some(HistogramSpec::Buckets(n))
    }
}

/// 直方图数据（桶计算与渲染解耦）：渲染器只消费桶，不重算分布。
#[derive(Debug)]
pub struct Histogram {
    /// 桶：(下界 ms, 上界 ms, 计数)；上界为 `f64::INFINITY` 表示无上界（末桶）。
    pub buckets: Vec<(f64, f64, usize)>,
    /// 最大桶计数（渲染缩放用）。
    pub max_count: usize,
}

impl Histogram {
    /// 从耗时样本构造直方图（内部排序；无样本或不可分桶返回 None）。
    pub fn from_times(times: &[Duration], spec: &HistogramSpec) -> Option<Histogram> {
        if times.is_empty() {
            return None;
        }
        let mut sorted: Vec<f64> = times.iter().map(|t| t.as_secs_f64() * 1000.0).collect();
        sorted.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        match spec {
            HistogramSpec::Buckets(n) => {
                let num = (*n).clamp(3, 50);
                let min = sorted[0];
                let max = *sorted.last().unwrap();
                if (max - min).abs() < f64::EPSILON {
                    return None;
                }
                let bw = (max - min) / num as f64;
                let mut counts = vec![0usize; num];
                for &ms in &sorted {
                    let idx = ((ms - min) / bw) as usize;
                    counts[idx.min(num - 1)] += 1;
                }
                let buckets = (0..num)
                    .map(|i| (min + i as f64 * bw, min + (i + 1) as f64 * bw, counts[i]))
                    .collect();
                Some(Histogram {
                    buckets,
                    max_count: *counts.iter().max().unwrap_or(&1),
                })
            }
            HistogramSpec::Thresholds(ts) => {
                let n = ts.len() + 1;
                let mut counts = vec![0usize; n];
                for &ms in &sorted {
                    let idx = ts.partition_point(|&th| ms > th);
                    counts[idx.min(n - 1)] += 1;
                }
                let buckets = (0..n)
                    .map(|i| {
                        let low = if i == 0 { 0.0 } else { ts[i - 1] };
                        let high = if i == n - 1 { f64::INFINITY } else { ts[i] };
                        (low, high, counts[i])
                    })
                    .collect();
                Some(Histogram {
                    buckets,
                    max_count: *counts.iter().max().unwrap_or(&1),
                })
            }
        }
    }
}

/// 保留的采样窗口上限（无限 ping 时内存有界）。
const MAX_SAMPLES: usize = 10000;

#[derive(Debug, Default)]
pub struct Stats {
    pub sent: u64,
    pub received: u64,
    pub min: Option<Duration>,
    pub max: Option<Duration>,
    pub total: Duration,
    pub sum_sq: f64,
    times: Vec<Duration>,
    timeline: Vec<(f64, f64)>, // (seconds from start, latency ms)
    t0: Option<Instant>,
    // 抖动：相邻接收样本 RTT 差的绝对值；丢包打断连续链（prev 重置）
    prev_rtt: Option<Duration>,
    jitter_sum: f64, // 秒
    jitter_max: Duration,
    jitter_pairs: u64,
}

impl Stats {
    pub fn record(&mut self, rtt: Duration) {
        if self.t0.is_none() {
            self.t0 = Some(Instant::now());
        }
        let t = self.t0.unwrap().elapsed().as_secs_f64();
        self.timeline.push((t, rtt.as_secs_f64() * 1000.0));
        self.sent += 1;
        self.received += 1;
        self.total += rtt;
        self.sum_sq += rtt.as_secs_f64().powi(2);
        self.min = Some(self.min.map_or(rtt, |m| m.min(rtt)));
        self.max = Some(self.max.map_or(rtt, |m| m.max(rtt)));
        self.times.push(rtt);
        if let Some(prev) = self.prev_rtt {
            let d = rtt.abs_diff(prev);
            self.jitter_sum += d.as_secs_f64();
            self.jitter_max = self.jitter_max.max(d);
            self.jitter_pairs += 1;
        }
        self.prev_rtt = Some(rtt);
        // 无限 ping 时内存有界：窗口上限 10000，超出丢弃最旧（min/max/loss 仍累计）
        if self.times.len() > MAX_SAMPLES {
            self.times.remove(0);
            self.timeline.remove(0);
        }
    }

    pub fn record_loss(&mut self) {
        self.sent += 1;
        self.prev_rtt = None; // 丢包打断相邻样本链
    }

    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        (self.sent - self.received) as f64 / self.sent as f64 * 100.0
    }

    /// 是否有丢包（供退出码判断）。
    pub fn has_loss(&self) -> bool {
        self.loss_pct() > 0.0
    }

    pub fn avg(&self) -> Option<Duration> {
        if self.received == 0 {
            return None;
        }
        Some(self.total / self.received as u32)
    }

    /// 抖动：相邻接收样本 RTT 差的平均绝对值（丢包链被重置）。
    pub fn jitter(&self) -> Option<Duration> {
        if self.jitter_pairs == 0 {
            return None;
        }
        Some(Duration::from_secs_f64(
            self.jitter_sum / self.jitter_pairs as f64,
        ))
    }

    /// 最大相邻 RTT 差。
    pub fn jitter_max(&self) -> Option<Duration> {
        (self.jitter_pairs > 0).then_some(self.jitter_max)
    }

    pub fn stddev(&self) -> Option<Duration> {
        if self.received < 2 {
            return None;
        }
        let avg_secs = self.avg()?.as_secs_f64();
        let variance = (self.sum_sq / self.received as f64) - avg_secs.powi(2);
        if variance <= 0.0 {
            return Some(Duration::ZERO);
        }
        Some(Duration::from_secs_f64(variance.sqrt()))
    }

    pub fn percentile(&self, p: f64) -> Option<Duration> {
        if self.times.is_empty() {
            return None;
        }
        let mut sorted = self.times.clone();
        sorted.sort_unstable();
        let idx = ((self.times.len() - 1) as f64 * p / 100.0).round() as usize;
        Some(sorted[idx])
    }

    pub fn sorted_times(&self) -> Vec<Duration> {
        let mut v = self.times.clone();
        v.sort_unstable();
        v
    }

    /// 原始采样（供直方图等只读消费，避免克隆）。
    pub(crate) fn samples(&self) -> &[Duration] {
        &self.times
    }
}

/// 输出 JSONL 逐次测量行：`{"type","target","ts","seq","ok","rtt_ms"|"error"}`。
///
/// `--json` 时每次 ping 实时输出一行，结束后另有汇总行（print_summary）。
pub fn json_sample(
    w: &mut StandardStream,
    mode: &str,
    target: &str,
    seq: u64,
    ok: bool,
    rtt: Option<Duration>,
    err: Option<&str>,
) -> Result<()> {
    let ts = crate::util::unix_ts();
    let target = target.replace('"', "\\\"");
    if ok {
        let ms = rtt.map(|r| r.as_secs_f64() * 1000.0).unwrap_or(0.0);
        writeln!(
            w,
            "{{\"type\":\"{mode}\",\"target\":\"{target}\",\"ts\":{ts},\"seq\":{seq},\"ok\":true,\"rtt_ms\":{ms:.2}}}"
        )
    } else {
        let err = err.unwrap_or("error").replace('"', "\\\"");
        writeln!(
            w,
            "{{\"type\":\"{mode}\",\"target\":\"{target}\",\"ts\":{ts},\"seq\":{seq},\"ok\":false,\"error\":\"{err}\"}}"
        )
    }
}

/// `mode` 用于 JSON 输出（如 "icmp"/"tcp"/"udp"/"latency"），`target` 为被测主机。
pub fn print_summary(
    w: &mut StandardStream,
    stats: &Stats,
    mode: &str,
    target: &str,
) -> Result<()> {
    if json() {
        let loss = stats.loss_pct();
        let ts = crate::util::unix_ts();
        let target = target.replace('"', "\\\"");
        let mut line = format!(
            "{{\"type\":\"{mode}\",\"target\":\"{target}\",\"ts\":{ts},\"summary\":true,\"sent\":{},\"received\":{},\"lost\":{},\"loss_pct\":{:.1}",
            stats.sent,
            stats.received,
            stats.sent - stats.received,
            loss
        );
        if stats.received > 0 {
            let min = stats.min.unwrap().as_secs_f64() * 1000.0;
            let max = stats.max.unwrap().as_secs_f64() * 1000.0;
            let avg = stats.avg().unwrap().as_secs_f64() * 1000.0;
            let stddev = stats
                .stddev()
                .map(|d| d.as_secs_f64() * 1000.0)
                .unwrap_or(0.0);
            line += &format!(
                ",\"min_ms\":{min:.2},\"max_ms\":{max:.2},\"avg_ms\":{avg:.2},\"stddev_ms\":{stddev:.2}"
            );
            if let Some(j) = stats.jitter() {
                let jitter = j.as_secs_f64() * 1000.0;
                let jitter_max = stats.jitter_max().unwrap().as_secs_f64() * 1000.0;
                line += &format!(",\"jitter_ms\":{jitter:.2},\"jitter_max_ms\":{jitter_max:.2}");
            }
            if stats.received >= 2 {
                let p50 = stats.percentile(50.0).unwrap().as_secs_f64() * 1000.0;
                let p95 = stats.percentile(95.0).unwrap().as_secs_f64() * 1000.0;
                let p99 = stats.percentile(99.0).unwrap().as_secs_f64() * 1000.0;
                line += &format!(",\"p50_ms\":{p50:.2},\"p95_ms\":{p95:.2},\"p99_ms\":{p99:.2}");
            }
        }
        line.push('}');
        writeln!(w, "{line}")?;
        return Ok(());
    }

    let loss = stats.loss_pct();
    let line = t!(
        "stats.sent_received",
        sent = stats.sent,
        received = stats.received,
        lost = stats.sent - stats.received,
        pct = format!("{:.0}", loss)
    );
    // 丢包率着色：0% 绿，<10% 黄，≥10% 红
    if loss == 0.0 {
        output::print_green(w, format!("{}{line}", output::indent(1)))?;
    } else if loss < 10.0 {
        output::print_yellow(w, format!("{}{line}", output::indent(1)))?;
    } else {
        output::print_red(w, format!("{}{line}", output::indent(1)))?;
    }
    writeln!(w)?;

    if stats.received > 0 {
        let min = stats.min.unwrap().as_secs_f64() * 1000.0;
        let max = stats.max.unwrap().as_secs_f64() * 1000.0;
        let avg = stats.avg().unwrap().as_secs_f64() * 1000.0;
        let stddev = stats
            .stddev()
            .map(|d| d.as_secs_f64() * 1000.0)
            .unwrap_or(0.0);

        writeln!(
            w,
            "{}{}",
            output::indent(1),
            t!(
                "stats.min_max_avg",
                min = format!("{:.2}", min),
                max = format!("{:.2}", max),
                avg = format!("{:.2}", avg),
                stddev = format!("{:.2}", stddev)
            )
        )?;

        if stats.received >= 2 {
            let p50 = format!(
                "{:.2}",
                stats.percentile(50.0).unwrap().as_secs_f64() * 1000.0
            );
            let p95 = format!(
                "{:.2}",
                stats.percentile(95.0).unwrap().as_secs_f64() * 1000.0
            );
            let p99 = format!(
                "{:.2}",
                stats.percentile(99.0).unwrap().as_secs_f64() * 1000.0
            );
            writeln!(
                w,
                "{}{}",
                output::indent(1),
                t!("stats.percentiles", p50 = p50, p95 = p95, p99 = p99)
            )?;
        }
        if let (Some(j), Some(jm)) = (stats.jitter(), stats.jitter_max()) {
            writeln!(
                w,
                "{}{}",
                output::indent(1),
                t!(
                    "stats.jitter",
                    avg = format!("{:.2}", j.as_secs_f64() * 1000.0),
                    max = format!("{:.2}", jm.as_secs_f64() * 1000.0)
                )
            )?;
        }
    }
    Ok(())
}

pub fn print_histogram(
    w: &mut StandardStream,
    times: &[Duration],
    spec: &HistogramSpec,
) -> Result<()> {
    let Some(h) = Histogram::from_times(times, spec) else {
        return Ok(());
    };
    // -p/--pretty：用 ploot 渲染 Unicode 柱状图
    if PRETTY.load(Ordering::Relaxed) {
        return print_ploot_histogram(w, &h);
    }
    match spec {
        HistogramSpec::Buckets(_) => print_bucket_histogram(w, &h),
        HistogramSpec::Thresholds(_) => print_threshold_histogram(w, &h),
    }
}

/// `-p` 直方图：ploot boxes（Unicode 柱状图）。
fn print_ploot_histogram(w: &mut StandardStream, h: &Histogram) -> Result<()> {
    let xs: Vec<f64> = h.buckets.iter().map(|&(low, _, _)| low).collect();
    let ys: Vec<f64> = h.buckets.iter().map(|&(_, _, c)| c as f64).collect();
    let mut fig = ploot::Figure::new();
    fig.set_terminal_size(80, 20);
    let ax = fig.axes2d();
    let title = t!("stats.latency_dist");
    ax.set_title(&title);
    ax.boxes(xs.iter().copied(), ys.iter().copied(), &[]);
    write!(w, "{}", strip_ansi(fig.render()))?;
    Ok(())
}

/// 非 tty 时剥离 ANSI 转义（ploot 恒输出颜色，管道下保持干净）。
fn strip_ansi(out: String) -> String {
    if std::io::stdout().is_terminal() {
        return out;
    }
    let mut s = String::with_capacity(out.len());
    let mut it = out.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            // \x1b[...m
            if it.next_if_eq(&'[').is_some() {
                for c in it.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
        }
        s.push(c);
    }
    s
}

fn print_bucket_histogram(w: &mut StandardStream, h: &Histogram) -> Result<()> {
    let bar_char = if PRETTY.load(Ordering::Relaxed) {
        "█"
    } else {
        "#"
    };
    let bar_width = 40usize;

    writeln!(w)?;
    writeln!(w, "{}", t!("stats.latency_dist"))?;
    for (low, high, count) in &h.buckets {
        let bar_len = count
            .checked_mul(bar_width)
            .and_then(|c| c.checked_div(h.max_count))
            .unwrap_or(0);
        write!(w, "{}{low:7.2} - {high:7.2} ms ", output::indent(1))?;
        output::print_yellow(w, bar_char.repeat(bar_len))?;
        writeln!(w, " ({count})")?;
    }
    Ok(())
}

/// 自定义阈值直方图：桶 i 覆盖 (th[i-1], th[i]]，最后一个桶为 (th[last], +∞)。
fn print_threshold_histogram(w: &mut StandardStream, h: &Histogram) -> Result<()> {
    let bar_char = if PRETTY.load(Ordering::Relaxed) {
        "█"
    } else {
        "#"
    };
    let bar_width = 40usize;

    writeln!(w)?;
    writeln!(w, "{}", t!("stats.latency_dist"))?;
    for (low, high, count) in &h.buckets {
        let range = if high.is_infinite() {
            format!("> {low:.2}")
        } else {
            format!("{low:.2} - {high:.2}")
        };
        let bar_len = count
            .checked_mul(bar_width)
            .and_then(|c| c.checked_div(h.max_count))
            .unwrap_or(0);
        write!(w, "{}{range:<14} ", output::indent(1))?;
        output::print_yellow(w, bar_char.repeat(bar_len))?;
        writeln!(w, " ({count})")?;
    }
    Ok(())
}

/// Print latency timeline (scatter: time vs latency).
pub fn print_timeline(w: &mut StandardStream, stats: &Stats) -> Result<()> {
    // -p/--pretty：用 ploot 渲染 Braille 散点图
    if PRETTY.load(Ordering::Relaxed) {
        return print_ploot_timeline(w, stats);
    }
    if stats.timeline.len() < 2 {
        return Ok(());
    }
    let pts = &stats.timeline;
    let max_y = pts.iter().map(|&(_, y)| y).fold(0.0f64, f64::max);
    let min_y = pts.iter().map(|&(_, y)| y).fold(f64::MAX, f64::min);
    let max_x = pts.last().unwrap().0;
    if max_y <= 0.0 {
        return Ok(());
    }

    let y_range = (max_y - min_y).max(0.001);
    let height = 16usize;
    let width = pts.len().clamp(20, 80);
    let step = (pts.len() / width).max(1);

    let mut sampled = Vec::new();
    let mut i = 0;
    while i < pts.len() {
        let end = (i + step).min(pts.len());
        let avg: f64 = pts[i..end].iter().map(|&(_, y)| y).sum::<f64>() / (end - i) as f64;
        sampled.push((pts[i].0, avg));
        i = end;
    }

    let bar_char = if PRETTY.load(Ordering::Relaxed) {
        [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
    } else {
        [" ", ".", ".", ":", ":", "|", "|", "#", "#"]
    };

    writeln!(w)?;
    writeln!(
        w,
        "Latency timeline (Y: {:.2}~{:.2}ms, X: 0~{:.1}s):",
        min_y, max_y, max_x
    )?;

    for row in (0..height).rev() {
        if row == height - 1 {
            // 5 宽标签 + 空格后 │ 落在位置 8，与中间行/└ 对齐
            write!(w, "  {max_y:5.1} │")?;
        } else if row == 0 {
            write!(w, "  {min_y:5.1} │")?;
        } else {
            write!(w, "        │")?;
        }
        for (_x, y) in &sampled {
            // 用 height-1 做乘数：max_y → norm=15（最顶行），min_y → 0，
            // 避免 norm=16 越界导致最高延迟点丢失
            let norm = ((*y - min_y) / y_range * (height - 1) as f64).round() as usize;
            // 柱状渲染：从底部（row 0）到延迟高度（norm）逐行填充，
            // 替代原来的单点散点，形态更直观
            let idx = if row <= norm { 7 } else { 0 };
            write!(w, "{}", bar_char[idx])?;
        }
        writeln!(w)?;
    }
    write!(w, "        └")?;
    for _ in 0..sampled.len() {
        write!(w, "─")?;
    }
    writeln!(w)?;
    // X 轴标签：右端对齐轴尾（"0s" 2 字符 + pad + label 顶到末个 "─"）
    write!(w, "       0s")?;
    let label = format!("{:.1}s", max_x);
    let pad = sampled.len().saturating_sub(label.len() + 1).max(1);
    for _ in 0..pad {
        write!(w, " ")?;
    }
    writeln!(w, "{label}")?;
    Ok(())
}

/// `-p` 时间线：ploot points（Braille 散点）。
fn print_ploot_timeline(w: &mut StandardStream, stats: &Stats) -> Result<()> {
    if stats.timeline.len() < 2 {
        return Ok(());
    }
    let xs: Vec<f64> = stats.timeline.iter().map(|&(t, _)| t).collect();
    let ys: Vec<f64> = stats.timeline.iter().map(|&(_, y)| y).collect();
    let mut fig = ploot::Figure::new();
    fig.set_terminal_size(80, 16);
    let ax = fig.axes2d();
    ax.set_title("Latency timeline");
    ax.points(
        xs.iter().copied(),
        ys.iter().copied(),
        &[ploot::PlotOption::Caption("latency (ms)".into())],
    );
    write!(w, "{}", strip_ansi(fig.render()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_record_and_basic_stats() {
        let mut s = Stats::default();
        s.record(Duration::from_millis(10));
        s.record(Duration::from_millis(20));
        s.record(Duration::from_millis(30));
        assert_eq!(s.sent, 3);
        assert_eq!(s.received, 3);
        assert_eq!(s.min, Some(Duration::from_millis(10)));
        assert_eq!(s.max, Some(Duration::from_millis(30)));
        assert_eq!(s.avg(), Some(Duration::from_millis(20)));
    }
    #[test]
    fn test_record_loss() {
        let mut s = Stats::default();
        s.record_loss();
        s.record_loss();
        assert_eq!(s.sent, 2);
        assert_eq!(s.received, 0);
        assert_eq!(s.loss_pct(), 100.0);
    }
    #[test]
    fn test_mixed_loss_and_success() {
        let mut s = Stats::default();
        s.record(Duration::from_millis(10));
        s.record_loss();
        s.record(Duration::from_millis(20));
        s.record_loss();
        assert_eq!(s.sent, 4);
        assert_eq!(s.received, 2);
        assert!((s.loss_pct() - 50.0).abs() < 0.01);
    }
    #[test]
    fn test_percentiles() {
        let mut s = Stats::default();
        for i in 1..=100 {
            s.record(Duration::from_millis(i));
        }
        assert!(
            s.percentile(50.0).unwrap().as_millis() >= 49
                && s.percentile(50.0).unwrap().as_millis() <= 51
        );
    }
    #[test]
    fn test_stddev() {
        let mut s = Stats::default();
        s.record(Duration::from_millis(10));
        s.record(Duration::from_millis(10));
        assert_eq!(s.stddev(), Some(Duration::ZERO));
        s.record(Duration::from_millis(20));
        assert!(s.stddev().unwrap().as_millis() > 0);
    }
    #[test]
    fn test_empty_stats() {
        let s = Stats::default();
        assert_eq!(s.avg(), None);
        assert_eq!(s.stddev(), None);
        assert_eq!(s.percentile(50.0), None);
        assert_eq!(s.loss_pct(), 0.0);
    }
    #[test]
    fn test_jitter() {
        let mut s = Stats::default();
        assert_eq!(s.jitter(), None, "无样本无抖动");
        s.record(Duration::from_millis(10));
        assert_eq!(s.jitter(), None, "单样本无抖动");
        s.record(Duration::from_millis(30)); // 差 20
        s.record(Duration::from_millis(35)); // 差 5
        assert_eq!(
            s.jitter(),
            Some(Duration::from_secs_f64(0.0125)),
            "平均差 (20+5)/2=12.5ms"
        );
        assert_eq!(s.jitter_max(), Some(Duration::from_millis(20)));
    }

    #[test]
    fn test_jitter_reset_on_loss() {
        let mut s = Stats::default();
        s.record(Duration::from_millis(10));
        s.record(Duration::from_millis(30)); // 差 20
        s.record_loss(); // 打断链
        s.record(Duration::from_millis(100)); // 与前一个接收样本不再比较
        assert_eq!(
            s.jitter(),
            Some(Duration::from_millis(20)),
            "丢包后不再累计"
        );
        assert_eq!(s.jitter_max(), Some(Duration::from_millis(20)));
    }

    #[test]
    fn test_sorted_times() {
        let mut s = Stats::default();
        s.record(Duration::from_millis(50));
        s.record(Duration::from_millis(10));
        s.record(Duration::from_millis(30));
        let v = s.sorted_times();
        assert_eq!(v[0], Duration::from_millis(10));
        assert_eq!(v[2], Duration::from_millis(50));
    }
    #[test]
    fn test_parse_histogram_buckets() {
        assert_eq!(parse_histogram("20"), Some(HistogramSpec::Buckets(20)));
    }
    #[test]
    fn test_parse_histogram_thresholds() {
        assert_eq!(
            parse_histogram("5,1,50"),
            Some(HistogramSpec::Thresholds(vec![1.0, 5.0, 50.0]))
        );
    }
    #[test]
    fn test_parse_histogram_invalid() {
        assert_eq!(parse_histogram("abc"), None);
        assert_eq!(parse_histogram("a,b"), None);
    }
    #[test]
    fn test_threshold_histogram_counts() {
        let mut s = Stats::default();
        for ms in [0.5, 1.0, 5.0, 10.0, 50.0] {
            s.record(Duration::from_secs_f64(ms / 1000.0));
        }
        let spec = HistogramSpec::Thresholds(vec![1.0, 5.0, 10.0]);
        // 桶: (0,1] (1,5] (5,10] (10,∞] → 0.5→0, 1.0→0, 5.0→1, 10.0→2, 50.0→3
        let mut w = termcolor::StandardStream::stdout(termcolor::ColorChoice::Never);
        print_histogram(&mut w, s.samples(), &spec).unwrap();
    }

    #[test]
    fn test_histogram_from_times_thresholds() {
        let times: Vec<Duration> = [0.5, 1.0, 5.0, 10.0, 50.0]
            .iter()
            .map(|&ms| Duration::from_secs_f64(ms / 1000.0))
            .collect();
        let h = Histogram::from_times(&times, &HistogramSpec::Thresholds(vec![1.0, 5.0, 10.0]))
            .unwrap();
        let counts: Vec<usize> = h.buckets.iter().map(|&(_, _, c)| c).collect();
        assert_eq!(counts, vec![2, 1, 1, 1]);
        assert_eq!(h.max_count, 2);
        // 末桶无上界
        assert!(h.buckets[3].1.is_infinite());
    }

    #[test]
    fn test_histogram_from_times_buckets() {
        let times: Vec<Duration> = (1..=10).map(Duration::from_millis).collect();
        let h = Histogram::from_times(&times, &HistogramSpec::Buckets(5)).unwrap();
        assert_eq!(h.buckets.len(), 5);
        let total: usize = h.buckets.iter().map(|&(_, _, c)| c).sum();
        assert_eq!(total, 10);
    }

    #[test]
    fn test_histogram_from_times_empty() {
        assert!(Histogram::from_times(&[], &HistogramSpec::Buckets(5)).is_none());
    }

    #[test]
    fn test_histogram_from_times_flat() {
        // 全部同值：不可分桶
        let times = vec![Duration::from_millis(3); 5];
        assert!(Histogram::from_times(&times, &HistogramSpec::Buckets(5)).is_none());
    }
}
