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
//! | `traceroute`（-t） | 路由跟踪（无端口） |
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

rust_i18n::i18n!("locales");

mod drive;
pub(crate) mod engine;
pub(crate) mod manual;
mod output;
pub(crate) mod ping;
mod serve;
mod stats;
mod util;

// ── 公开 API（lib 的 public surface 最小化）───────────────────────────────

// 基础设施
pub use manual::{Section, find_sections, manual_for, print_paged, sections, toc};
pub use output::{indent, pad_to, spaces, stderr, writeln_orange, writeln_red};
pub use serve::{ServerReport, serve};
pub use stats::{HistogramSpec, Stats, parse_histogram, set_json, set_pretty};
pub use util::{
    PingConfig, configure_executor_threads, interrupted, reset_interrupt, resolve_source,
    set_interrupted,
};

// 测量模块
pub use ping::mtu::{MtuReport, probe_mtu};
pub use ping::trace::{DEFAULT_MAX_HOPS, TraceReport, traceroute};

// 引擎模块
pub use engine::convert::{ConvertOptions, ConvertReport, convert_pcap};
pub use engine::eng::{
    analyze_file, analyze_recipe, decode_hex, decode_pcap, dns_type_name, effective_libs,
    ensure_proto_registry, layer_name, libs_display, ls_builtins, opt_bytes_len, render_dissected,
    render_hexdump, render_layers, render_packet, render_packet_fields, run_lsp, run_lsp_on,
    value_display,
};
pub use engine::pcap::{LinkType, PcapRecord, linktype_of, read_pcap, write_pcap};
pub use engine::pkg::{
    PkgOptions, Reply, SendMode, SendOutcome, SnifferMatcher, Transport, derive_target,
    extract_payload, patch_zero_src, send_packets, send_recipe, sniffer_match, sniffer_match_with,
    step_send_mode,
};
pub use engine::recipe::{
    Extract, ExtractAs, FromSpec, GlobalDecl, OnError, Recipe, Step, StepRaw, parse as parse_recipe,
};

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
    #[error("MTU probe does not take a port: --mtu HOST")]
    MtuRequiresNoPort,
    #[error("traceroute does not take a port: trace HOST")]
    TracerouteRequiresNoPort,
    #[error("TCP traceroute requires a port: trace --tcp HOST:PORT")]
    TcpTraceRequiresPort,
    #[error("--tcp and --udp cannot be used together")]
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
        if cfg.trace_tcp && cfg.trace_udp {
            return Err(PrpingError::TraceProtoConflict);
        }
        if cfg.trace_tcp {
            if cfg.port == 0 {
                return Err(PrpingError::TcpTraceRequiresPort);
            }
        } else if cfg.port != 0 {
            // ICMP / UDP 变体都不接受端口（UDP 端口自动从 33434 起递增）
            return Err(PrpingError::TracerouteRequiresNoPort);
        }
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
        cfg.count = cfg.count.max(1);
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
    cfg.size = Some(cfg.size.unwrap_or(32));
    let stats = ping::icmp::ping(&cfg)?;
    Ok(OutcomeKind::Ping(stats))
}

/// UDP 数据报负载上限（IPv4 65507 / IPv6 65527，取保守值），超限时截断并告警。
fn clamp_udp_size(size: usize, udp: bool, on_warning: &mut impl FnMut(PrpingWarning)) -> usize {
    const MAX_UDP: usize = 65507;
    if udp && size > MAX_UDP {
        on_warning(PrpingWarning::UdpSizeClamped {
            requested: size,
            max: MAX_UDP,
        });
        return MAX_UDP;
    }
    size
}
