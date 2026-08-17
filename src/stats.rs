//! Statistics collection and terminal output.

use crate::output;
use rust_i18n::t;
use std::io::{Result, Write};
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

/// 解析 `-H` 参数："20" → Buckets(20)；"1,5,10,50" → Thresholds([1,5,10,50])。
pub fn parse_histogram(s: &str) -> Option<HistogramSpec> {
    if s.contains(',') {
        let mut v: Vec<f64> = s.split(',').filter_map(|p| p.trim().parse().ok()).collect();
        if v.is_empty() {
            return None;
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        v.dedup_by(|a, b| (*a - *b).abs() < f64::EPSILON);
        Some(HistogramSpec::Thresholds(v))
    } else {
        s.parse().ok().map(HistogramSpec::Buckets)
    }
}

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
    }

    pub fn record_loss(&mut self) {
        self.sent += 1;
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
}

/// `mode` 用于 JSON 输出（如 "icmp"/"tcp"/"udp"/"latency"）。
pub fn print_summary(w: &mut StandardStream, stats: &Stats, mode: &str) -> Result<()> {
    if json() {
        let loss = stats.loss_pct();
        let mut line = format!(
            "{{\"type\":\"{mode}\",\"sent\":{},\"received\":{},\"lost\":{},\"loss_pct\":{:.1}",
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
        output::print_green(w, format!("  {line}"))?;
    } else if loss < 10.0 {
        output::print_yellow(w, format!("  {line}"))?;
    } else {
        output::print_red(w, format!("  {line}"))?;
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
            "  {}",
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
                "  {}",
                t!("stats.percentiles", p50 = p50, p95 = p95, p99 = p99)
            )?;
        }
    }
    Ok(())
}

pub fn print_histogram(w: &mut StandardStream, stats: &Stats, spec: &HistogramSpec) -> Result<()> {
    match spec {
        HistogramSpec::Buckets(n) => print_bucket_histogram(w, stats, *n),
        HistogramSpec::Thresholds(ts) => print_threshold_histogram(w, stats, ts),
    }
}

fn print_bucket_histogram(w: &mut StandardStream, stats: &Stats, num_buckets: usize) -> Result<()> {
    let bar_char = if PRETTY.load(Ordering::Relaxed) {
        "█"
    } else {
        "#"
    };
    let times = stats.sorted_times();
    if times.is_empty() {
        return Ok(());
    }

    let num_buckets = num_buckets.clamp(3, 50);
    let min = times[0].as_secs_f64() * 1000.0;
    let max = times[times.len() - 1].as_secs_f64() * 1000.0;
    if (max - min).abs() < f64::EPSILON {
        return Ok(());
    }

    let bucket_width = (max - min) / num_buckets as f64;
    let mut buckets = vec![0usize; num_buckets];
    for t in &times {
        let ms = t.as_secs_f64() * 1000.0;
        let idx = ((ms - min) / bucket_width) as usize;
        buckets[idx.min(num_buckets - 1)] += 1;
    }

    let max_count = *buckets.iter().max().unwrap_or(&1);
    let bar_width = 40usize;

    writeln!(w)?;
    writeln!(w, "{}", t!("stats.latency_dist"))?;
    for (i, &count) in buckets.iter().enumerate() {
        let low = min + i as f64 * bucket_width;
        let high = low + bucket_width;
        let bar_len = if max_count > 0 {
            count * bar_width / max_count
        } else {
            0
        };
        write!(w, "  {low:7.2} - {high:7.2} ms ")?;
        output::print_yellow(w, bar_char.repeat(bar_len))?;
        writeln!(w, " ({count})")?;
    }
    Ok(())
}

/// 自定义阈值直方图：桶 i 覆盖 (th[i-1], th[i]]，最后一个桶为 (th[last], +∞)。
fn print_threshold_histogram(
    w: &mut StandardStream,
    stats: &Stats,
    thresholds: &[f64],
) -> Result<()> {
    let bar_char = if PRETTY.load(Ordering::Relaxed) {
        "█"
    } else {
        "#"
    };
    let times = stats.sorted_times();
    if times.is_empty() {
        return Ok(());
    }

    let n = thresholds.len() + 1;
    let mut buckets = vec![0usize; n];
    for t in &times {
        let ms = t.as_secs_f64() * 1000.0;
        let idx = thresholds.partition_point(|&th| ms > th);
        buckets[idx.min(n - 1)] += 1;
    }

    let max_count = *buckets.iter().max().unwrap_or(&1);
    let bar_width = 40usize;

    writeln!(w)?;
    writeln!(w, "{}", t!("stats.latency_dist"))?;
    for (i, &count) in buckets.iter().enumerate() {
        let low = if i == 0 { 0.0 } else { thresholds[i - 1] };
        let high = if i == n - 1 {
            f64::INFINITY
        } else {
            thresholds[i]
        };
        let range = if high.is_infinite() {
            format!("> {low:.2}")
        } else {
            format!("{low:.2} - {high:.2}")
        };
        let bar_len = if max_count > 0 {
            count * bar_width / max_count
        } else {
            0
        };
        write!(w, "  {range:<14} ")?;
        output::print_yellow(w, bar_char.repeat(bar_len))?;
        writeln!(w, " ({count})")?;
    }
    Ok(())
}

/// Print latency timeline (scatter: time vs latency).
pub fn print_timeline(w: &mut StandardStream, stats: &Stats) -> Result<()> {
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
            write!(w, "  {max_y:6.1} │")?;
        } else if row == 0 {
            write!(w, "  {min_y:6.1} │")?;
        } else {
            write!(w, "        │")?;
        }
        for (_x, y) in &sampled {
            let norm = ((*y - min_y) / y_range * height as f64) as usize;
            let idx = if (norm as isize - row as isize).abs() <= 0 {
                7
            } else {
                0
            };
            write!(w, "{}", bar_char[idx])?;
        }
        writeln!(w)?;
    }
    write!(w, "        └")?;
    for _ in 0..sampled.len() {
        write!(w, "─")?;
    }
    writeln!(w)?;
    // X 轴标签：从 "0s" 到末端，label 与 "0s" 之间至少一个空格
    write!(w, "       0s")?;
    let label = format!("{:.1}s", max_x);
    let pad = sampled.len().saturating_sub(label.len() + 3).max(1);
    for _ in 0..pad {
        write!(w, " ")?;
    }
    writeln!(w, "{label}")?;
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
        print_histogram(&mut w, &s, &spec).unwrap();
    }
}
