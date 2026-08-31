//! prping-core —— 跨平台 psping 复刻（核心库）。
//!
//! # 架构
//!
//! workspace 拆分后本 crate 为协议实现与包构造引擎的核心库，
//! CLI 解析与渲染由 `prping-cli` crate 负责。
//!
//! ```text
//! workspace
//! ├── crates/prping-core/    本库：协议 + 引擎 + 工具
//! │   ├── lib.rs             pub: run / serve / PingConfig / Stats / 报告 / 错误 / 警告
//! │   ├── serve/             TCP/UDP 服务端 + capture（raw 抓包）
//! │   ├── ping/              ICMP / TCP / UDP / latency / bandwidth / MTU / traceroute
//! │   │   └── trace/         ICMP echo / TCP SYN / UDP 逐跳 + dns（反向 DNS）
//! │   ├── engine/            eng / pkg / recipe / pcap / rawpcap
//! │   └── util/              config / dns / net / socket / format / interrupt
//! │       stats / drive / output / manual   共享基础设施
//! └── crates/prping-cli/     CLI：bpaf 子命令解析 → run()/serve() → 渲染
//! ```
//!
//! # 模式识别（`run`）
//!
//! | 条件 | 模式 |
//! |------|------|
//! | `traceroute`（trace 子命令） | 路由跟踪（无端口 ICMP；**带端口自动 TCP SYN**；`trace_udp` 经典 UDP） |
//! | `mtu`（-M） | MTU 探测（无端口） |
//! | `bandwidth` + 端口 | 带宽测试 |
//! | `size`（-l）+ 端口 | 延迟测试 |
//! | 端口 | TCP ping（`udp` 则 UDP ping） |
//! | 无端口 | ICMP ping |
//!
//! # 服务端协议（`serve`）
//!
//! - **TCP**：回显全部数据；首个数据包为单字节 `0xFF` 时进入接收模式，
//!   持续回送 64KB 数据块；回显写超时 100ms 后停止回显但继续排空。
//! - **UDP**：回显全部数据报；8 字节触发包 `[0xFF, 0xFF, size(2B BE), count(4B BE)]`
//!   触发接收模式，回送 count 个 size 字节数据报。
//!
//! # 用法示例
//!
//! ```no_run
//! use prping_core::{PingConfig, run};
//!
//! let cfg = PingConfig {
//!     host: "127.0.0.1".into(),
//!     port: 80,
//!     count: 3,
//!     duration: None,
//!     interval: 1.0,
//!     size: None,
//!     quiet: true,
//!     histogram: None,
//!     warmup: 0,
//!     v4: false,
//!     v6: false,
//!     parallel: 1,
//!     udp: false,
//!     receive: false,
//!     bandwidth: false,
//!     graph: false,
//!     mtu: false,
//!     traceroute: false,
//!     trace_tcp: false,
//!     trace_udp: false,
//!     max_hops: 30,
//!     no_dns: false,
//!     source: None,
//! };
//! let kind = run(&cfg, |_| {}).expect("run");
//! ```

rust_i18n::i18n!("locales", fallback = "en-US");

mod drive;
pub(crate) mod engine;
pub(crate) mod manual;
mod output;
pub(crate) mod ping;
mod serve;
mod stats;
mod util;
pub mod web;

// ── 公开 API ─────────────────────────────────────────────────────────────
// 注意：engine/pkg 路径（分析/LSP/pcap 转码/发送/配方/listen）随 CLI 一起公开——
// prping-cli 的 engine/packet/document 子命令直接调用这些 API，属于事实上的稳定
// 公开面（早期「公开面最小化」声明已不适用；如需收紧需先把 CLI 调用收敛成高层
// 入口，属独立重构）。核心测量 API（run/serve/PingConfig/Stats）仍为第一优先保证。

// 基础设施
pub use manual::{Section, find_sections, manual_for, print_paged, sections, toc};
pub use output::{indent, pad_to, spaces, stderr, writeln_orange, writeln_red};
pub use serve::{ServerReport, serve};
pub use stats::{HistogramSpec, Stats, parse_histogram, set_json, set_pretty};
pub use util::{
    PingConfig, configure_executor_threads, interrupted, parse_kv_pairs, reset_interrupt, resolve,
    resolve_source, set_interrupted,
};

// 测量模块
pub use ping::mtu::{MtuReport, probe_mtu};
pub use ping::trace::{DEFAULT_MAX_HOPS, TraceReport, traceroute};

// 引擎模块
pub use engine::convert::{ConvertOptions, ConvertReport, convert_pcap};
pub use engine::eng::{
    analyze_file, analyze_recipe, analyze_text_json, decode_hex, decode_pcap, dns_type_name,
    effective_libs, ensure_proto_registry, layer_name, libs_display, ls_builtins, opt_bytes_len,
    render_dissected, render_hexdump, render_layers, render_packet, render_packet_fields, run_lsp,
    run_lsp_on, value_display,
};
pub use engine::pcap::{LinkType, PcapRecord, linktype_of, read_pcap, write_pcap};
pub use engine::pkg::{
    PkgOptions, Reply, SendMode, SendOutcome, SnifferMatcher, Transport, WaitMode, derive_target,
    extract_payload, listen_packets, listen_raw_packets, patch_zero_src, raw_only, send_packets,
    send_recipe, sniffer_match, sniffer_match_with, step_send_mode,
};
pub use engine::recipe::{
    Extract, ExtractAs, FromSpec, GlobalDecl, OnError, Recipe, Step, StepRaw, parse as parse_recipe,
};

// Web 编辑器服务器（`prping web`）
pub use web::{WebConfig, serve_web};

// ── 核心类型 ──────────────────────────────────────────────────────────────

/// 测试分支结果（`run` 的返回）。
#[derive(Debug)]
pub enum OutcomeKind {
    /// ping 类（ICMP/TCP/UDP/latency）统计。
    Ping(Stats),
    /// 带宽测试报告。
    Bandwidth(BandwidthReport),
    /// MTU 探测报告。
    Mtu(MtuReport),
    /// 路由跟踪报告。
    Traceroute(TraceReport),
}

/// 带宽测试报告。
#[derive(Debug)]
pub struct BandwidthReport {
    /// 打印用标题（i18n，如 "TCP 带宽测试:"）。
    pub label: String,
    /// 实际发送/接收字节数。
    pub total_bytes: u64,
    /// 耗时（秒）。
    pub secs: f64,
    /// 吞吐（Mbps）。
    pub mbps: f64,
}

/// 测试警告（通过 `run` 的回调流出，bin 渲染为本地化文案）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PrpingWarning {
    /// `-i` 低于 1ms 下限，已截断。
    IntervalClamped { requested: f64 },
    /// `-b -u` 时 `--parallel` 无效。
    ParallelUdpIgnored,
    /// 非带宽模式 `--parallel` 无效。
    ParallelIgnored,
    /// 普通 ping 模式 `-r` 无效。
    ReceiveIgnoredPing,
    /// UDP 负载超 65507，已截断。
    UdpSizeClamped { requested: usize, max: usize },
}

/// 分派层错误；模式内部 IO/网络错误透传。
#[derive(Debug, thiserror::Error)]
pub enum PrpingError {
    #[error("UDP requires a port: HOST:PORT")]
    UdpRequiresPort,
    #[error("bandwidth requires HOST:PORT")]
    BandwidthRequiresPort,
    #[error("-4 and -6 cannot be used together")]
    ConflictV4V6,
    #[error("interval must be a finite number of seconds (got {0})")]
    InvalidInterval(f64),
    #[error("duration must be a finite number of seconds (got {0})")]
    InvalidDuration(f64),
    #[error("MTU probe does not take a port: --mtu HOST")]
    MtuRequiresNoPort,
    #[error(
        "UDP traceroute does not take a port: trace --udp HOST (destination ports auto-increment from 33434)"
    )]
    TracerouteRequiresNoPort,
    #[error("TCP traceroute requires a port: trace HOST:PORT")]
    TcpTraceRequiresPort,
    #[error("TCP and UDP traceroute cannot be requested together")]
    TraceProtoConflict,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// 统一入口：按配置自动识别模式并执行。
///
/// 警告（clamp/忽略提示）通过 `on_warning` 回调即时流出，保证在测试输出之前渲染。
pub fn run(
    cfg: &PingConfig,
    on_warning: impl FnMut(PrpingWarning),
) -> Result<OutcomeKind, PrpingError> {
    let mut on_warning = on_warning;
    let mut cfg = cfg.clone();

    // config 级不变式：-4/-6 冲突（bin 的 validate 只管 CLI 级冲突，这里兜底库调用方）
    if cfg.v4 && cfg.v6 {
        return Err(PrpingError::ConflictV4V6);
    }

    // 数值不变式：NaN/±inf/过大值会使 Duration::from_secs_f64 panic
    // （drive/bandwidth/Run 处），在入口统一拒绝（CLI 侧同样兜底，这里保护库调用方）。
    // 负 interval 仍走既有 clamp（警告 + 1ms 下限）；负 duration 同样拒绝——
    // from_secs_f64 对负值 panic，「期限已过」语义并非有意设计。
    if !cfg.interval.is_finite() || cfg.interval > MAX_DURATION_SECS {
        return Err(PrpingError::InvalidInterval(cfg.interval));
    }
    if let Some(d) = cfg.duration
        && (!d.is_finite() || !(0.0..=MAX_DURATION_SECS).contains(&d))
    {
        return Err(PrpingError::InvalidDuration(d));
    }

    // -i 0 快速模式：clamp 到 1ms 下限
    if cfg.interval < 0.001 {
        on_warning(PrpingWarning::IntervalClamped {
            requested: cfg.interval,
        });
        cfg.interval = 0.001;
    }

    // 非带宽模式 --parallel 无效（-b -u 的 --parallel 警告在带宽分支）
    if cfg.parallel > 1 && !cfg.bandwidth {
        on_warning(PrpingWarning::ParallelIgnored);
    }

    // MTU 探测模式（--mtu）
    if cfg.mtu {
        if cfg.port != 0 {
            return Err(PrpingError::MtuRequiresNoPort);
        }
        let report = ping::mtu::probe_mtu(&cfg)?;
        return Ok(OutcomeKind::Mtu(report));
    }

    // 路由跟踪模式（trace）
    if cfg.traceroute {
        // 探测协议决策：显式 --tcp/--udp 各自校验；未指定时带端口自动 TCP
        // SYN（与 ping 的「带端口 → TCP」一致），无端口默认 ICMP echo。
        let probe = resolve_trace_probe(cfg.trace_tcp, cfg.trace_udp, cfg.port)?;
        cfg.trace_tcp = probe == TraceProbe::Tcp;
        cfg.trace_udp = probe == TraceProbe::Udp;
        let report = ping::trace::traceroute(&cfg)?;
        return Ok(OutcomeKind::Traceroute(report));
    }

    if cfg.bandwidth {
        if cfg.port == 0 {
            return Err(PrpingError::BandwidthRequiresPort);
        }
        if cfg.udp && cfg.parallel > 1 {
            on_warning(PrpingWarning::ParallelUdpIgnored);
        }
        let size = clamp_udp_size(cfg.size.unwrap_or(8192), cfg.udp, &mut on_warning);
        cfg.size = Some(size);
        let report = ping::bandwidth::run_client(&cfg)?;
        return Ok(OutcomeKind::Bandwidth(report));
    }

    if cfg.size.is_some() && cfg.port != 0 {
        // 延迟测试（-l + 端口）
        let size = clamp_udp_size(cfg.size.unwrap(), cfg.udp, &mut on_warning);
        cfg.size = Some(size);
        // count=0 = 无限（与 ping 一致；CLI 缺省给 10，显式 -n 0 进入无限）
        let stats = ping::latency::run_client(&cfg)?;
        return Ok(OutcomeKind::Ping(stats));
    }

    if cfg.port != 0 {
        // TCP/UDP ping
        if cfg.receive {
            on_warning(PrpingWarning::ReceiveIgnoredPing);
        }
        let stats = if cfg.udp {
            ping::udp::ping(&cfg)?
        } else {
            ping::tcp::ping(&cfg)?
        };
        return Ok(OutcomeKind::Ping(stats));
    }

    // ICMP ping
    if cfg.udp {
        return Err(PrpingError::UdpRequiresPort);
    }
    if cfg.receive {
        on_warning(PrpingWarning::ReceiveIgnoredPing);
    }
    // ICMP echo 载荷受协议硬上限约束（IPv4 最大 ICMP 报文 65507 字节）：
    // Unix 路径超限 send 报错、Windows 路径 u16 DataSize 截断——统一 clamp
    if let Some(sz) = cfg.size
        && sz > MAX_UDP
    {
        on_warning(PrpingWarning::UdpSizeClamped {
            requested: sz,
            max: MAX_UDP,
        });
        cfg.size = Some(MAX_UDP);
    }
    cfg.size = Some(cfg.size.unwrap_or(32));
    let stats = ping::icmp::ping(&cfg)?;
    Ok(OutcomeKind::Ping(stats))
}

/// UDP 数据报负载上限（IPv4 65507 / IPv6 65527，取保守值）。
pub const MAX_UDP: usize = 65507;

/// 秒数型参数（interval/duration/wait/delay）的合理上限：超过即拒绝。
///
/// Duration::from_secs_f64 对 NaN/负值/过大值（> ~1.8e19 秒）会 panic，
/// 此上限远低于溢出阈值（1e12 秒 ≈ 3.2 万年），同时挡住 1e300 这类
/// 有限但荒谬的输入。
pub const MAX_DURATION_SECS: f64 = 1e12;

/// UDP 数据报负载上限（IPv4 65507 / IPv6 65527，取保守值），超限时截断并告警。
fn clamp_udp_size(size: usize, udp: bool, on_warning: &mut impl FnMut(PrpingWarning)) -> usize {
    if udp && size > MAX_UDP {
        on_warning(PrpingWarning::UdpSizeClamped {
            requested: size,
            max: MAX_UDP,
        });
        return MAX_UDP;
    }
    size
}

/// 路由跟踪探测协议（`run` 分派层的最终决策结果）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceProbe {
    /// ICMP echo（`trace HOST`，默认）。
    Icmp,
    /// TCP SYN（`trace HOST:PORT` 带端口自动；库调用方可显式置 `trace_tcp`）。
    Tcp,
    /// 经典 UDP（`trace --udp HOST`，33434 起递增端口）。
    Udp,
}

/// trace 探测协议决策与校验：`--tcp` 需端口、`--udp` 不接受端口、两者互斥；
/// 未显式指定协议时**带端口自动启用 TCP SYN**（与 ping 的「带端口 → TCP」一致），
/// 无端口默认 ICMP echo。
fn resolve_trace_probe(
    trace_tcp: bool,
    trace_udp: bool,
    port: u16,
) -> Result<TraceProbe, PrpingError> {
    if trace_tcp && trace_udp {
        return Err(PrpingError::TraceProtoConflict);
    }
    if trace_tcp {
        if port == 0 {
            return Err(PrpingError::TcpTraceRequiresPort);
        }
        return Ok(TraceProbe::Tcp);
    }
    if trace_udp {
        if port != 0 {
            return Err(PrpingError::TracerouteRequiresNoPort);
        }
        return Ok(TraceProbe::Udp);
    }
    Ok(if port != 0 {
        TraceProbe::Tcp
    } else {
        TraceProbe::Icmp
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_probe_explicit_modes() {
        // --tcp 需端口
        assert!(matches!(
            resolve_trace_probe(true, false, 80),
            Ok(TraceProbe::Tcp)
        ));
        assert!(matches!(
            resolve_trace_probe(true, false, 0),
            Err(PrpingError::TcpTraceRequiresPort)
        ));
        // --udp 不接受端口（33434 起自动递增）
        assert!(matches!(
            resolve_trace_probe(false, true, 0),
            Ok(TraceProbe::Udp)
        ));
        assert!(matches!(
            resolve_trace_probe(false, true, 80),
            Err(PrpingError::TracerouteRequiresNoPort)
        ));
        // --tcp 与 --udp 互斥
        assert!(matches!(
            resolve_trace_probe(true, true, 80),
            Err(PrpingError::TraceProtoConflict)
        ));
    }

    #[test]
    fn trace_probe_auto_from_port() {
        // 带端口且未指定协议 → 自动 TCP SYN（与 ping 的「带端口 → TCP」一致）
        assert!(matches!(
            resolve_trace_probe(false, false, 443),
            Ok(TraceProbe::Tcp)
        ));
        // 无端口 → ICMP echo（默认）
        assert!(matches!(
            resolve_trace_probe(false, false, 0),
            Ok(TraceProbe::Icmp)
        ));
    }
}
