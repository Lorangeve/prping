//! 中断控制与运行循环。

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static INTERRUPT_COUNT: AtomicU8 = AtomicU8::new(0);

/// 是否收到过 Ctrl+C（或被注入中断）。
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

/// 置位/清除中断标志（测试注入优雅退出时使用）。
pub fn set_interrupted(v: bool) {
    INTERRUPTED.store(v, Ordering::Relaxed);
}

/// 重置中断状态（测试隔离用）。
pub fn reset_interrupt() {
    INTERRUPTED.store(false, Ordering::Relaxed);
    INTERRUPT_COUNT.store(0, Ordering::Relaxed);
}

/// 运行循环控制：按次数、按时长或 Ctrl+C 中断决定何时停止。
///
/// 循环写法（seq 由 `advance()` 推进，禁止直接改字段）：
/// ```text
/// loop {
///     if run.seq() > 0 { /* 间隔 */ }
///     if run.done() { break; }
///     let seq = run.seq();
///     /* 测量主体 */
///     run.advance();
/// }
/// ```
pub struct Run {
    count: u64,
    warmup: u64,
    deadline: Option<Instant>,
    seq: u64,
}

impl Run {
    pub fn new(count: u64, warmup: u64, duration: Option<f64>) -> Self {
        let deadline = duration.map(|d| Instant::now() + Duration::from_secs_f64(d));
        Self {
            count,
            warmup,
            deadline,
            seq: 0,
        }
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn advance(&mut self) {
        self.seq += 1;
    }

    pub fn is_warmup(&self) -> bool {
        self.seq < self.warmup
    }

    pub fn done(&self) -> bool {
        if interrupted() {
            return true;
        }
        if let Some(dl) = self.deadline {
            return Instant::now() >= dl;
        }
        self.count != 0 && self.seq >= self.warmup + self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_count_limited() {
        let mut r = Run::new(3, 2, None);
        let mut n = 0;
        while !r.done() {
            r.advance();
            n += 1;
        }
        assert_eq!(n, 5);
    }
    #[test]
    fn test_run_infinite() {
        let r = Run::new(0, 4, None);
        assert!(!r.done());
    }
    #[test]
    fn test_run_duration() {
        let mut r = Run::new(0, 0, Some(0.001));
        let mut n = 0;
        while !r.done() && n < 1_000_000 {
            r.advance();
            n += 1;
        }
        assert!(n > 0);
        assert!(r.done());
    }
    #[test]
    fn test_run_warmup_flag() {
        let mut r = Run::new(1, 2, None);
        assert!(r.is_warmup());
        r.advance();
        assert!(r.is_warmup());
        r.advance();
        assert!(!r.is_warmup());
    }
}
