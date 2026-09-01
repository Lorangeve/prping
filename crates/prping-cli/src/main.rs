rust_i18n::i18n!("locales", fallback = "en-US");

use bpaf::*;
use prping_core::{
    OutcomeKind, PingConfig, PrpingError, PrpingWarning, configure_executor_threads, find_sections,
    manual_for, parse_histogram, print_paged, resolve_source, run, serve, set_json, set_pretty,
    stderr, toc, writeln_orange, writeln_red,
};
use rust_i18n::t;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};

/// 全部子命令名（唯一前缀展开的匹配表；顺序不影响解析）。
const SUBCOMMANDS: &[&str] = &[
    "ping",
    "latency",
    "bandwidth",
    "server",
    "trace",
    "engine",
    "packet",
    "document",
    #[cfg(feature = "web")]
    "web",
];

/// Parse "host:port" string.
fn parse_target(input: &str) -> anyhow::Result<(String, Option<u16>)> {
    if let Some(rest) = input.strip_prefix('[') {
        if let Some((ip, port)) = rest.split_once("]:") {
            return Ok((format!("[{ip}]"), Some(port.parse()?)));
        }
        if let Some(ip) = rest.strip_suffix(']') {
            return Ok((format!("[{ip}]"), None));
        }
        anyhow::bail!(t!("errors.invalid_ipv6"));
    }
    if let Some((host, port)) = input.rsplit_once(':') {
        // host:port 形态（host 不再含 ':'，即非裸 IPv6）
        if !host.contains(':') {
            if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
                // 形似 host:badport：明确报错，而不是把整串当主机名给出迷惑的解析失败
                anyhow::bail!(t!("errors.invalid_port", value = port));
            }
            return Ok((host.to_string(), Some(port.parse()?)));
        }
    }
    Ok((input.to_string(), None))
}

// ── 共享选项构造（各子命令按需组合；字段名与 struct 字段对应）────────────────

fn opt_count() -> impl Parser<Option<String>> {
    long("count")
        .short('n')
        .argument::<String>("N|Ns")
        .help(t!("help.options.count").as_ref())
        .optional()
}

fn opt_interval() -> impl Parser<Option<f64>> {
    long("interval")
        .short('i')
        .argument::<f64>("S")
        .help(t!("help.options.interval").as_ref())
        .optional()
}

fn opt_quiet() -> impl Parser<bool> {
    long("quiet")
        .short('q')
        .switch()
        .help(t!("help.options.quiet").as_ref())
}

fn opt_histogram() -> impl Parser<Option<String>> {
    long("histogram")
        .short('H')
        .argument::<String>("N|t1,t2,...")
        .help(t!("help.options.histogram").as_ref())
        .optional()
}

fn opt_warmup() -> impl Parser<Option<u64>> {
    long("warmup")
        .short('w')
        .argument::<u64>("N")
        .help(t!("help.options.warmup").as_ref())
        .optional()
}

fn opt_json() -> impl Parser<bool> {
    long("json").switch().help(t!("help.options.json").as_ref())
}

fn opt_v4() -> impl Parser<bool> {
    short('4').switch().help(t!("help.options.v4").as_ref())
}

fn opt_v6() -> impl Parser<bool> {
    short('6').switch().help(t!("help.options.v6").as_ref())
}

fn opt_source() -> impl Parser<Option<String>> {
    long("source")
        .short('s')
        .argument::<String>("ADDR|IFACE")
        .help(t!("help.options.source").as_ref())
        .optional()
}

fn opt_lang() -> impl Parser<Option<String>> {
    long("lang")
        .argument::<String>("en|zh-CN")
        .help(t!("help.options.lang").as_ref())
        .optional()
}

fn opt_udp() -> impl Parser<bool> {
    long("udp")
        .short('u')
        .switch()
        .help(t!("help.options.udp").as_ref())
}

fn opt_size() -> impl Parser<Option<String>> {
    long("size")
        .short('l')
        .argument::<String>("64|8k|1m")
        .help(t!("help.options.size").as_ref())
        .optional()
}

// ── 各子命令参数与解析器 ──────────────────────────────────────────────────

/// ping 子命令（ICMP / TCP / UDP(-u) / MTU(-m)）
/// 三条测量子命令（ping/latency/bandwidth）共享的 CLI 选项。
struct MeasureArgs {
    udp: bool,
    size: Option<String>,
    graph: bool,
    pretty: bool,
    count: Option<String>,
    interval: Option<f64>,
    quiet: bool,
    histogram: Option<String>,
    warmup: Option<u64>,
    json: bool,
    v4: bool,
    v6: bool,
    source: Option<String>,
    lang: Option<String>,
    target: String,
}

/// 共享测量选项 parser（ping/latency/bandwidth 组合使用）。
fn measure_parser() -> impl Parser<MeasureArgs> {
    construct!(MeasureArgs {
        udp(opt_udp()),
        size(opt_size()),
        graph(long("graph")
            .short('g')
            .switch()
            .help(t!("help.options.graph").as_ref())),
        pretty(long("pretty")
            .short('p')
            .switch()
            .help(t!("help.options.pretty").as_ref())),
        count(opt_count()),
        interval(opt_interval()),
        quiet(opt_quiet()),
        histogram(opt_histogram()),
        warmup(opt_warmup()),
        json(opt_json()),
        v4(opt_v4()),
        v6(opt_v6()),
        source(opt_source()),
        lang(opt_lang()),
        target(positional::<String>("HOST")),
    })
}

/// ping 子命令（ICMP / TCP / UDP(-u) / MTU(-m)）
struct PingArgs {
    mtu: bool,
    measure: MeasureArgs,
}

/// latency 子命令（TCP/UDP 回显往返延迟）
struct LatencyArgs {
    receive: bool,
    measure: MeasureArgs,
}

/// bandwidth 子命令（TCP/UDP 吞吐）
struct BandwidthArgs {
    receive: bool,
    parallel: Option<u32>,
    measure: MeasureArgs,
}

/// server 子命令（同时服务 latency/bandwidth/接收模式）
struct ServerArgs {
    verbose: bool,
    /// 全帧抓包：显示所有可见帧（ARP/ICMP/广播/出向），需显式配合 -v
    capture_all: bool,
    /// --filter 表达式（tcpdump 风格子集），需显式配合 -a
    filter: Option<String>,
    lang: Option<String>,
    addr: String,
}

/// trace 子命令（ICMP echo / TCP SYN（带端口自动）/ UDP 逐跳路径发现）
struct TraceArgs {
    udp: bool,
    max_hops: Option<u32>,
    no_dns: bool,
    json: bool,
    v4: bool,
    v6: bool,
    source: Option<String>,
    lang: Option<String>,
    target: String,
}

/// engine 子命令（packet-dsl 宿主：分析/LSP/--ls/--hex/--pcap/转码）
#[derive(Clone)]
struct EngineArgs {
    file: Option<String>,
    lsp: bool,
    ls: bool,
    hex: Option<String>,
    pcap: Option<String>,
    /// pcap → .pkt/.pktl 转码输出目录（配合 --pcap；缺省无损字节级，--structured 语义化）。
    to_pkt: Option<String>,
    /// 转码用语义结构化（A2）；缺省无损字节级（A1）。
    structured: bool,
    /// 转码跳过前 N 条记录。
    skip: usize,
    /// 转码最多转换 N 条（缺省全部）。
    limit: Option<usize>,
    /// 转码解析/渲染并发线程数（0 = 自动：记录数 ≥ 阈值时按 CPU 并行；1 = 单线程）。
    threads: usize,
    lib: Vec<String>,
    params: Vec<String>,
    global: Vec<String>,
    json: bool,
    lang: Option<String>,
}

/// packet 子命令（构建 .pkt 并发送；.pktl 配方执行；--wait 无值 = 持续监听）
#[derive(Clone)]
struct PacketArgs {
    raw: bool,
    iface: Option<String>,
    wait: prping_core::WaitMode,
    count: usize,
    fuzz: bool,
    out: Option<String>,
    summary: bool,
    lib: Vec<String>,
    params: Vec<String>,
    global: Vec<String>,
    json: bool,
    lang: Option<String>,
    file: String,
    target: Option<String>,
}

/// document 子命令（使用手册：全文 / 章节跳转）
struct DocumentArgs {
    lang: Option<String>,
    section: Option<String>,
}

/// web 子命令（内嵌 Web 编辑器：SolidJS SPA + CodeMirror + LSP 桥）
#[cfg(feature = "web")]
#[derive(Clone)]
struct WebArgs {
    addr: Option<String>,
    port: Option<u16>,
    open: bool,
    lib: Vec<String>,
    lang: Option<String>,
}

/// 顶层命令枚举（子命令分发）。
enum Command {
    Ping(PingArgs),
    Latency(LatencyArgs),
    Bandwidth(BandwidthArgs),
    Server(ServerArgs),
    Trace(TraceArgs),
    Engine(EngineArgs),
    Packet(PacketArgs),
    Document(DocumentArgs),
    #[cfg(feature = "web")]
    Web(WebArgs),
}

fn ping_cmd() -> impl Parser<Command> {
    construct!(PingArgs {
        mtu(long("mtu")
            .short('m')
            .switch()
            .help(t!("help.options.mtu").as_ref())),
        measure(measure_parser()),
    })
    .to_options()
    .usage(t!("help.usage_ping").as_ref())
    .descr(t!("cmd.ping").as_ref())
    .footer(t!("help.footer_ping").as_ref())
    .command("ping")
    .map(Command::Ping)
}

fn latency_cmd() -> impl Parser<Command> {
    construct!(LatencyArgs {
        receive(long("receive")
            .short('r')
            .switch()
            .help(t!("help.options.receive").as_ref())),
        measure(measure_parser()),
    })
    .to_options()
    .usage(t!("help.usage_latency").as_ref())
    .descr(t!("cmd.latency").as_ref())
    .footer(t!("help.footer_latency").as_ref())
    .command("latency")
    .map(Command::Latency)
}

fn bandwidth_cmd() -> impl Parser<Command> {
    construct!(BandwidthArgs {
        receive(long("receive")
            .short('r')
            .switch()
            .help(t!("help.options.receive").as_ref())),
        parallel(long("parallel")
            .argument::<u32>("N")
            .help(t!("help.options.parallel").as_ref())
            .optional()),
        measure(measure_parser()),
    })
    .to_options()
    .usage(t!("help.usage_bandwidth").as_ref())
    .descr(t!("cmd.bandwidth").as_ref())
    .footer(t!("help.footer_bandwidth").as_ref())
    .command("bandwidth")
    .map(Command::Bandwidth)
}

fn server_cmd() -> impl Parser<Command> {
    construct!(ServerArgs {
        verbose(long("verbose")
            .short('v')
            .switch()
            .help(t!("help.options.verbose").as_ref())),
        capture_all(long("capture-all")
            .short('a')
            .switch()
            .help(t!("help.options.capture_all").as_ref())),
        filter(long("filter")
            .help(t!("help.options.capture_filter").as_ref())
            .argument::<String>("EXPR")
            .optional()),
        lang(opt_lang()),
        addr(positional::<String>("ADDR:PORT")),
    })
    .to_options()
    .usage(t!("help.usage_server").as_ref())
    .descr(t!("cmd.server").as_ref())
    .footer(t!("help.footer_server").as_ref())
    .command("server")
    .map(Command::Server)
}

fn trace_cmd() -> impl Parser<Command> {
    construct!(TraceArgs {
        udp(long("udp")
            .short('u')
            .switch()
            .help(t!("help.options.trace_udp").as_ref())),
        max_hops(long("max-hops")
            .short('m')
            .argument::<u32>("N")
            .help(t!("help.options.max_hops").as_ref())
            .optional()),
        no_dns(long("no-dns")
            .short('d')
            .switch()
            .help(t!("help.options.no_dns").as_ref())),
        json(opt_json()),
        v4(opt_v4()),
        v6(opt_v6()),
        source(opt_source()),
        lang(opt_lang()),
        target(positional::<String>("HOST[:PORT]")),
    })
    .to_options()
    .usage(t!("help.usage_trace").as_ref())
    .descr(t!("cmd.trace").as_ref())
    .footer(t!("help.footer_trace").as_ref())
    .command("trace")
    .map(Command::Trace)
}

fn engine_cmd() -> impl Parser<Command> {
    construct!(EngineArgs {
        lsp(long("lsp")
            .switch()
            .help(t!("help.options.lsp").as_ref())),
        ls(long("ls").switch().help(t!("help.options.ls").as_ref())),
        hex(long("hex")
            .argument::<String>("0102...")
            .help(t!("help.options.hex").as_ref())
            .optional()),
        pcap(long("pcap")
            .argument::<String>("FILE.pcap")
            .help(t!("help.options.pcap").as_ref())
            .optional()),
        to_pkt(long("to-pkt")
            .argument::<String>("DIR")
            .help(t!("help.options.to_pkt").as_ref())
            .optional()),
        structured(long("structured")
            .switch()
            .help(t!("help.options.structured").as_ref())),
        skip(long("skip")
            .argument::<usize>("N")
            .help(t!("help.options.skip").as_ref())
            .fallback(0)),
        limit(long("limit")
            .argument::<usize>("N")
            .help(t!("help.options.limit").as_ref())
            .optional()),
        threads(long("threads")
            .argument::<usize>("N")
            .help(t!("help.options.threads").as_ref())
            .fallback(0)),
        lib(long("lib")
            .argument::<String>("PATH")
            .help(t!("help.options.lib").as_ref())
            .many()),
        params(long("params")
            .short('p')
            .argument::<String>("k=v,...")
            .help(t!("help.options.params").as_ref())
            .many()),
        global(long("global")
            .short('g')
            .argument::<String>("k=v,...")
            .help(t!("help.options.global").as_ref())
            .many()),
        lang(opt_lang()),
        json(opt_json()),
        file(positional::<String>("FILE.pkt").optional()),
    })
    .to_options()
    .usage(t!("help.usage_engine").as_ref())
    .descr(t!("cmd.engine").as_ref())
    .footer(t!("help.footer_engine").as_ref())
    .command("engine")
    .map(Command::Engine)
}

fn packet_cmd() -> impl Parser<Command> {
    construct!(PacketArgs {
        raw(long("raw").switch().help(t!("help.options.raw").as_ref())),
        iface(long("iface")
            .argument::<String>("IFACE")
            .help(t!("help.options.iface").as_ref())
            .optional()),
        // --wait：无值 = 持续监听（服务端，纯监听：命中打印匹配详情）；
        // --wait SECS = 发送后等一个匹配应答（对标 scapy sr1）；负数 = 无限等待（= 无值）
        wait({
            let bare = long("wait")
                .help(t!("help.options.wait").as_ref())
                .req_flag(())
                .map(|_| Some(prping_core::WaitMode::Continuous));
            let with = long("wait")
                .help(t!("help.options.wait").as_ref())
                .argument::<f64>("SECS")
                // 负数 = 无限等待（等价裸 --wait）
                .optional()
                // NaN/±inf 会在 Duration::from_secs_f64 处 panic，解析期拒绝
                // bpaf guard 消息要求 &'static str（无法走 i18n）；NaN/±inf/过大值
                // 会在 Duration::from_secs_f64 处 panic，解析期直接拒绝
                // （注：守卫失败时 bpaf 会回溯到裸 --wait，把该值当文件报错——
                // 仍是优雅错误，优于 panic）
                .guard(
                    |o: &Option<f64>| {
                        o.is_none_or(|s| s.is_finite() && s <= prping_core::MAX_DURATION_SECS)
                    },
                    "--wait needs a finite number of seconds (not NaN/infinity)",
                )
                .map(|o: Option<f64>| {
                    o.map(|s| {
                        if s < 0.0 {
                            prping_core::WaitMode::Continuous
                        } else {
                            prping_core::WaitMode::OneShot(s)
                        }
                    })
                });
            construct!([bare, with])
                .map(|w: Option<prping_core::WaitMode>| w.unwrap_or(prping_core::WaitMode::Off))
        }),
        // --count N：每个包重复发送 N 次（配方步骤 `count:` 覆盖）
        count(long("count")
            .help(t!("help.options.pkt_count").as_ref())
            .argument::<usize>("N")
            .optional()
            .map(|c| c.unwrap_or(1))),
        fuzz(long("fuzz").switch().help(t!("help.options.fuzz").as_ref())),
        out(long("out")
            .argument::<String>("FILE.pcap")
            .help(t!("help.options.out").as_ref())
            .optional()),
        summary(long("summary").switch().help(t!("help.options.summary").as_ref())),
        json(opt_json()),
        lib(long("lib")
            .argument::<String>("PATH")
            .help(t!("help.options.lib").as_ref())
            .many()),
        params(long("params")
            .short('p')
            .argument::<String>("k=v,...")
            .help(t!("help.options.params").as_ref())
            .many()),
        global(long("global")
            .short('g')
            .argument::<String>("k=v,...")
            .help(t!("help.options.global").as_ref())
            .many()),
        lang(opt_lang()),
        file(positional::<String>("FILE.pkt")),
        target(positional::<String>("HOST[:PORT]").optional()),
    })
    .to_options()
    .usage(t!("help.usage_packet").as_ref())
    .descr(t!("cmd.packet").as_ref())
    .footer(t!("help.footer_packet").as_ref())
    .command("packet")
    .map(Command::Packet)
}

/// document 子命令（使用手册：全文 / 章节跳转）
fn document_cmd() -> impl Parser<Command> {
    construct!(DocumentArgs {
        lang(opt_lang()),
        section(positional::<String>("SECTION").optional()),
    })
    .to_options()
    .usage(t!("help.usage_document").as_ref())
    .descr(t!("cmd.document").as_ref())
    .footer(t!("help.footer_document").as_ref())
    .command("document")
    .map(Command::Document)
}

/// web 子命令（内嵌 Web 编辑器：单端口 HTTP + WebSocket，--open 打开浏览器）
#[cfg(feature = "web")]
fn web_cmd() -> impl Parser<Command> {
    construct!(WebArgs {
        addr(long("addr")
            .argument::<String>("ADDR")
            .help(t!("help.options.web_addr").as_ref())
            .optional()),
        port(long("port")
            .argument::<u16>("N")
            .help(t!("help.options.web_port").as_ref())
            .optional()),
        open(long("open").switch().help(t!("help.options.web_open").as_ref())),
        lib(long("lib")
            .argument::<String>("PATH")
            .help(t!("help.options.lib").as_ref())
            .many()),
        lang(opt_lang()),
    })
    .to_options()
    .usage(t!("help.usage_web").as_ref())
    .descr(t!("cmd.web").as_ref())
    .footer(t!("help.footer_web").as_ref())
    .command("web")
    .map(Command::Web)
}

/// 顶层解析器：9 个子命令平行组合（bpaf 要求子命令是首个 token）。
/// web 由 `web` feature 门控（默认不编译；justfile 统一以 --features prping/web 启用）。
fn cmd() -> impl Parser<Command> {
    #[cfg(feature = "web")]
    {
        construct!([
            ping_cmd(),
            latency_cmd(),
            bandwidth_cmd(),
            server_cmd(),
            trace_cmd(),
            engine_cmd(),
            packet_cmd(),
            document_cmd(),
            web_cmd(),
        ])
    }
    #[cfg(not(feature = "web"))]
    {
        construct!([
            ping_cmd(),
            latency_cmd(),
            bandwidth_cmd(),
            server_cmd(),
            trace_cmd(),
            engine_cmd(),
            packet_cmd(),
            document_cmd(),
        ])
    }
}

/// Parse size string like "64", "8k", "1m" to bytes.
fn parse_size(s: &str) -> anyhow::Result<usize> {
    let s = s.trim().to_lowercase();
    if let Some(n) = s.strip_suffix('k') {
        return Ok((n.parse::<f64>()? * 1024.0) as usize);
    }
    if let Some(n) = s.strip_suffix('m') {
        return Ok((n.parse::<f64>()? * 1024.0 * 1024.0) as usize);
    }
    Ok(s.parse()?)
}

/// Parse count string like "10" or "10s" to (count, is_duration).
fn parse_count(s: &str) -> anyhow::Result<(u64, Option<f64>)> {
    let parse = |v: &str| {
        v.parse::<f64>()
            .map_err(|_| anyhow::anyhow!(t!("errors.invalid_count", value = s)))
    };
    if let Some(n) = s.strip_suffix('s') {
        return Ok((0, Some(parse(n)?)));
    }
    Ok((
        s.parse::<u64>()
            .map_err(|_| anyhow::anyhow!(t!("errors.invalid_count", value = s)))?,
        None,
    ))
}

// ── 子命令级校验（结构性冲突已由子命令选项集天然消除，这里只留真校验）──────

fn json_conflicts(json: bool, pretty: bool, graph: bool, histogram: bool) -> Option<String> {
    if json && pretty {
        return Some(t!("errors.conflict_json_pretty").to_string());
    }
    if json && graph {
        return Some(t!("errors.conflict_json_graph").to_string());
    }
    if json && histogram {
        return Some(t!("errors.conflict_json_histogram").to_string());
    }
    None
}

/// ping：--json 与 -p/-g/-H；-m（MTU）与 -u/-l/-g/-p/-H/-n/-i/-w/-q 互斥。
fn validate_ping(a: &MeasureArgs) -> Option<String> {
    if let Some(msg) = json_conflicts(a.json, a.pretty, a.graph, a.histogram.is_some()) {
        return Some(msg);
    }
    // MTU 冲突校验已移至 run_ping（需要访问 PingArgs.mtu）。
    None
}

fn validate_latency(a: &MeasureArgs) -> Option<String> {
    json_conflicts(a.json, a.pretty, a.graph, a.histogram.is_some())
}

fn validate_bandwidth(a: &BandwidthArgs) -> Option<String> {
    if a.parallel == Some(0) {
        return Some(t!("errors.parallel_zero").to_string());
    }
    if a.measure.count.as_deref() == Some("0") {
        return Some(t!("errors.count_zero_bandwidth").to_string());
    }
    None
}

/// server 依赖链校验：--capture-all 需显式 --verbose；--filter 需显式
/// --capture-all（不隐含开启，缺前置标志直接报错）。
fn validate_server(a: &ServerArgs) -> Option<String> {
    if a.capture_all && !a.verbose {
        return Some(t!("errors.capture_all_requires_verbose").to_string());
    }
    if a.filter.is_some() && !a.capture_all {
        return Some(t!("errors.filter_requires_capture_all").to_string());
    }
    None
}

/// 非法 -H 解析（-n 的非法值在 parse_count 路径报错；-H 返回 None 时这里报错）。
fn bad_histogram(histogram: &Option<String>) -> Option<String> {
    let hist = histogram.as_deref().and_then(parse_histogram);
    if histogram.is_some() && hist.is_none() {
        Some(
            t!(
                "errors.invalid_histogram",
                value = histogram.as_deref().unwrap_or("")
            )
            .to_string(),
        )
    } else {
        None
    }
}

// ── 子命令执行 ──────────────────────────────────────────────────────────────

/// 子命令内 --lang：解析后设置 locale（--help 本地化由 detect_locale 预扫描保证）。
fn apply_lang(lang: &Option<String>) {
    if let Some(loc) = lang {
        rust_i18n::set_locale(&normalize_locale(loc));
    }
}

/// 统一收尾：lib run() + 退出码（丢包/未到达目标 → 1）。
fn dispatch_run(cfg: PingConfig, ctrl_echo: Option<CtrlCEchoGuard>) -> anyhow::Result<()> {
    match run(&cfg, |w| {
        if !cfg.quiet {
            let mut err = stderr();
            let _ = writeln_orange(&mut err, render_warning(w));
        }
    }) {
        Ok(kind) => {
            let has_loss = match &kind {
                OutcomeKind::Ping(stats) => stats.has_loss(),
                OutcomeKind::Bandwidth(_) | OutcomeKind::Mtu(_) => false,
                OutcomeKind::Traceroute(report) => !report.reached,
            };
            if has_loss {
                drop(ctrl_echo); // 先恢复终端设置再退出（process::exit 不跑析构）
                std::process::exit(1);
            }
        }
        Err(e) => {
            // 7 个模式级错误统一用红色报错退出；其它错误向上透传。
            if let Some(msg) = cli_error_message(&e) {
                fail(ctrl_echo, msg);
            } else {
                return Err(e.into());
            }
        }
    }
    Ok(())
}

/// PrpingError 对应的本地化 CLI 错误消息（None = 非用户错误，透传）。
fn cli_error_message(e: &PrpingError) -> Option<String> {
    match e {
        PrpingError::UdpRequiresPort => Some(t!("errors.udp_requires_port").to_string()),
        PrpingError::BandwidthRequiresPort => {
            Some(t!("errors.bandwidth_requires_port").to_string())
        }
        PrpingError::ConflictV4V6 => Some(t!("errors.conflict_v4_v6").to_string()),
        PrpingError::MtuRequiresNoPort => Some(t!("errors.mtu_requires_no_port").to_string()),
        PrpingError::TracerouteRequiresNoPort => {
            Some(t!("errors.trace_requires_no_port").to_string())
        }
        PrpingError::TcpTraceRequiresPort => Some(t!("errors.tcp_trace_requires_port").to_string()),
        PrpingError::TraceProtoConflict => Some(t!("errors.trace_udp_tcp_conflict").to_string()),
        _ => None,
    }
}

/// 红字报错并退出（恢复终端设置后退出码 1）。
fn fail(ctrl_echo: Option<CtrlCEchoGuard>, msg: impl AsRef<str>) -> ! {
    drop(ctrl_echo); // 恢复终端设置（Drop impl）
    let mut w = stderr();
    let _ = writeln_red(&mut w, msg);
    std::process::exit(1);
}

fn run_ping(a: PingArgs) -> anyhow::Result<()> {
    apply_lang(&a.measure.lang);
    if let Some(msg) = validate_ping(&a.measure) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }
    if let Some(msg) = bad_histogram(&a.measure.histogram) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }
    // MTU 冲突校验（需要访问 PingArgs.mtu）
    if a.mtu {
        let mut bad: Vec<&str> = Vec::new();
        if a.measure.udp {
            bad.push("-u");
        }
        if a.measure.size.is_some() {
            bad.push("-l");
        }
        if a.measure.graph {
            bad.push("-g");
        }
        if a.measure.pretty {
            bad.push("-p");
        }
        if a.measure.histogram.is_some() {
            bad.push("-H");
        }
        if a.measure.count.is_some() {
            bad.push("-n");
        }
        if a.measure.interval.is_some() {
            bad.push("-i");
        }
        if a.measure.warmup.is_some() {
            bad.push("-w");
        }
        if a.measure.quiet {
            bad.push("-q");
        }
        if !bad.is_empty() {
            let mut w = stderr();
            let _ = writeln_red(
                &mut w,
                format!(
                    "Error: {}",
                    t!("errors.conflict_mtu_mode", opts = bad.join(" "))
                ),
            );
            std::process::exit(1);
        }
    }

    let _ctrl_echo = suppress_ctrl_c_echo(a.measure.json);
    set_pretty(a.measure.pretty);
    set_json(a.measure.json);

    let (host, port) = parse_target(&a.measure.target)?;
    // 旧功能残留：ping HOST:PORT -l N 曾静默派发到 latency（echo 协议），目标不是
    // prping server 时全部超时、极难排查。现在明确报错：-l 只对 ICMP ping（无端口）
    // 有意义（TCP ping 无负载概念；UDP ping 的负载大小请用 latency 子命令）。
    if port.is_some() && a.measure.size.is_some() {
        let mut w = stderr();
        let _ = writeln_red(
            &mut w,
            format!(
                "Error: {}",
                t!(
                    "errors.ping_port_no_size",
                    target = a.measure.target.as_str()
                )
            ),
        );
        std::process::exit(1);
    }
    let (cnt, dur) = match a.measure.count.as_deref() {
        Some(s) => parse_count(s)?,
        None => (0, None),
    };
    let cfg = PingConfig {
        host,
        port: port.unwrap_or(0),
        count: cnt,
        duration: dur,
        size: a.measure.size.as_deref().map(parse_size).transpose()?,
        quiet: a.measure.quiet,
        histogram: a.measure.histogram.as_deref().and_then(parse_histogram),
        v4: a.measure.v4,
        v6: a.measure.v6,
        source: a
            .measure
            .source
            .as_deref()
            .map(resolve_source)
            .transpose()?,
        udp: a.measure.udp,
        mtu: a.mtu,
        graph: a.measure.graph,
        interval: a.measure.interval.unwrap_or(PingConfig::default().interval),
        warmup: a.measure.warmup.unwrap_or(PingConfig::default().warmup),
        ..PingConfig::default()
    };
    dispatch_run(cfg, _ctrl_echo)
}

fn run_latency(a: LatencyArgs) -> anyhow::Result<()> {
    apply_lang(&a.measure.lang);
    if let Some(msg) = validate_latency(&a.measure) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }
    if let Some(msg) = bad_histogram(&a.measure.histogram) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }

    let _ctrl_echo = suppress_ctrl_c_echo(a.measure.json);
    set_pretty(a.measure.pretty);
    set_json(a.measure.json);

    let (host, port) = parse_target(&a.measure.target)?;
    let port = port.ok_or_else(|| anyhow::anyhow!(t!("errors.latency_requires_port")))?;
    let (cnt, dur) = match a.measure.count.as_deref() {
        Some(s) => parse_count(s)?,
        // 缺省 10 次有效探测：此前 count=0 被 lib 的 max(1) 吞成 1 次，
        // 单样本的均值/百分位/jitter 统计毫无意义（-n 0 显式给出 = 无限）
        None => (10, None),
    };
    // 子命令已明确延迟模式：-l 缺省 64（与 psping 默认一致）
    let cfg = PingConfig {
        host,
        port,
        count: cnt,
        duration: dur,
        size: Some(parse_size(a.measure.size.as_deref().unwrap_or("64"))?),
        quiet: a.measure.quiet,
        histogram: a.measure.histogram.as_deref().and_then(parse_histogram),
        v4: a.measure.v4,
        v6: a.measure.v6,
        source: a
            .measure
            .source
            .as_deref()
            .map(resolve_source)
            .transpose()?,
        udp: a.measure.udp,
        receive: a.receive,
        graph: a.measure.graph,
        interval: a.measure.interval.unwrap_or(PingConfig::default().interval),
        warmup: a.measure.warmup.unwrap_or(PingConfig::default().warmup),
        ..PingConfig::default()
    };
    dispatch_run(cfg, _ctrl_echo)
}

fn run_bandwidth(a: BandwidthArgs) -> anyhow::Result<()> {
    apply_lang(&a.measure.lang);
    if let Some(msg) = validate_bandwidth(&a) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }
    if let Some(msg) = bad_histogram(&a.measure.histogram) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }

    let _ctrl_echo = suppress_ctrl_c_echo(a.measure.json);
    set_json(a.measure.json);
    set_pretty(a.measure.pretty);

    let (host, port) = parse_target(&a.measure.target)?;
    let port = port.ok_or_else(|| anyhow::anyhow!(t!("errors.bandwidth_requires_port")))?;
    // 缺省 1000 次（对齐 psping 的 -n 默认 1000）；count==0 在带宽循环里表示
    // 「立即停止」，与 ping 的「0=无限」语义不同，必须在 CLI 层给默认值。
    let (cnt, dur) = match a.measure.count.as_deref() {
        Some(s) => parse_count(s)?,
        None => (1000, None),
    };
    let cfg = PingConfig {
        host,
        port,
        count: cnt,
        duration: dur,
        size: a.measure.size.as_deref().map(parse_size).transpose()?, // None → lib 默认 8192
        quiet: a.measure.quiet,
        histogram: a.measure.histogram.as_deref().and_then(parse_histogram),
        v4: a.measure.v4,
        v6: a.measure.v6,
        source: a
            .measure
            .source
            .as_deref()
            .map(resolve_source)
            .transpose()?,
        parallel: a.parallel.unwrap_or(1),
        udp: a.measure.udp,
        receive: a.receive,
        bandwidth: true,
        graph: a.measure.graph,
        interval: a.measure.interval.unwrap_or(PingConfig::default().interval),
        warmup: a.measure.warmup.unwrap_or(PingConfig::default().warmup),
        ..PingConfig::default()
    };
    dispatch_run(cfg, _ctrl_echo)
}

fn run_server(a: ServerArgs) -> anyhow::Result<()> {
    apply_lang(&a.lang);
    if let Some(msg) = validate_server(&a) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }
    let addr: SocketAddr = a
        .addr
        .parse()
        .map_err(|_| anyhow::anyhow!(t!("errors.invalid_bind", addr = a.addr.as_str())))?;
    // 监听行由 serve() 在绑定后打印（显示实际地址，'ADDR:0' 时给出真实端口）
    // 依赖链由 validate_server 保证（-a 需 -v、--filter 需 -a），
    // 三个标志原样传给 serve，不再隐含开启。
    let report = smol::block_on(serve(addr, a.verbose, a.capture_all, a.filter.as_deref()))?;
    println!(
        "{}",
        t!(
            "server.summary",
            conns = report.connections,
            bytes = report.bytes,
            sent = report.sent,
            secs = format!("{:.2}", report.secs),
            mbps = format!("{:.2}", report.mbps)
        )
    );
    Ok(())
}

/// web 子命令分发（内嵌 Web 编辑器服务器；监听行由 serve_web 打印）。
#[cfg(feature = "web")]
fn run_web(a: WebArgs) -> anyhow::Result<()> {
    apply_lang(&a.lang);
    let addr = match &a.addr {
        Some(s) => s
            .parse::<std::net::IpAddr>()
            .map_err(|_| anyhow::anyhow!(t!("errors.invalid_bind", addr = s.as_str())))?,
        // 默认仅回环：页面可触发引擎能力（读库/分析），不默认暴露到网络
        None => std::net::IpAddr::from([127, 0, 0, 1]),
    };
    let cfg = prping_core::WebConfig {
        addr,
        port: a.port.unwrap_or(0),
        libs: resolve_libs(&a.lib),
        open_browser: a.open,
    };
    smol::block_on(prping_core::serve_web(cfg))
}

fn run_trace(a: TraceArgs) -> anyhow::Result<()> {
    apply_lang(&a.lang);
    let _ctrl_echo = suppress_ctrl_c_echo(a.json);
    set_json(a.json);

    let (host, port) = parse_target(&a.target)?;
    let cfg = PingConfig {
        host,
        port: port.unwrap_or(0),
        v4: a.v4,
        v6: a.v6,
        source: a.source.as_deref().map(resolve_source).transpose()?,
        traceroute: true,
        // TCP SYN 由 lib 按「带端口」自动启用（run 分派层 resolve_trace_probe）
        trace_udp: a.udp,
        max_hops: a.max_hops.unwrap_or(PingConfig::default().max_hops),
        no_dns: a.no_dns,
        ..PingConfig::default()
    };
    dispatch_run(cfg, _ctrl_echo)
}

// ── 引擎 / 包构建子命令（engine / packet）────────────────────────────────

/// engine 子命令校验：--ls/--hex/--pcap 互斥、不能与 --lsp 组合、子动作不带文件；
/// 转码选项（--to-pkt/--structured/--skip/--limit）须配合 --pcap。
fn validate_engine(a: &EngineArgs) -> anyhow::Result<()> {
    let sub = a.ls || a.hex.is_some() || a.pcap.is_some();
    if (a.ls as u8 + a.hex.is_some() as u8 + a.pcap.is_some() as u8) > 1 {
        anyhow::bail!(t!("errors.eng_sub_conflict"));
    }
    if sub && a.lsp {
        anyhow::bail!(t!("errors.eng_sub_conflict_lsp"));
    }
    // --json 仅对 FILE.pkt/.pktl 分析模式定义（--ls/--hex/--pcap/--lsp 走各自输出）
    if a.json && (sub || a.lsp) {
        anyhow::bail!(t!("errors.eng_json_sub_conflict"));
    }
    if sub && a.file.is_some() {
        anyhow::bail!(t!("errors.eng_sub_no_file"));
    }
    if a.lsp && a.file.is_some() {
        anyhow::bail!(t!("errors.eng_lsp_no_file"));
    }
    if a.to_pkt.is_some() && a.pcap.is_none() {
        anyhow::bail!(t!("errors.to_pkt_requires_pcap"));
    }
    if a.structured && a.to_pkt.is_none() {
        anyhow::bail!(t!("errors.structured_requires_to_pkt"));
    }
    if (a.skip > 0 || a.limit.is_some()) && a.to_pkt.is_none() {
        anyhow::bail!(t!("errors.skip_limit_requires_to_pkt"));
    }
    if a.threads > 0 && a.to_pkt.is_none() {
        anyhow::bail!(t!("errors.threads_requires_to_pkt"));
    }
    Ok(())
}

/// packet 子命令校验：--iface 仅配合 --raw；持续监听（--wait 无值）与发送类选项互斥。
fn validate_packet(a: &PacketArgs) -> anyhow::Result<()> {
    if a.iface.is_some() && !a.raw {
        anyhow::bail!(t!("errors.iface_requires_raw"));
    }
    if a.count == 0 {
        anyhow::bail!(t!("errors.pkt_count_zero"));
    }
    if a.wait == prping_core::WaitMode::Continuous && (a.fuzz || a.out.is_some()) {
        anyhow::bail!(t!("errors.listen_conflict"));
    }
    if a.wait == prping_core::WaitMode::Continuous && a.count > 1 {
        anyhow::bail!(t!("errors.listen_count_conflict"));
    }
    if a.json && a.wait == prping_core::WaitMode::Continuous {
        anyhow::bail!(t!("errors.pkt_json_listen_conflict"));
    }
    // --json 抑制人读输出，--summary 却强制打印紧凑层栈行 → 冲突（JSONL 契约）
    if a.json && a.summary {
        anyhow::bail!(t!("errors.pkt_json_summary_conflict"));
    }
    Ok(())
}

/// engine 子命令分发（分析 .pkt / 配方概览 / LSP / --ls / --hex / --pcap）。
fn run_engine(a: EngineArgs) -> anyhow::Result<()> {
    apply_lang(&a.lang);
    validate_engine(&a)?;
    let _ctrl_echo = suppress_ctrl_c_echo(a.json);
    set_json(a.json);
    let libs = resolve_libs(&a.lib);

    if a.lsp {
        return prping_core::run_lsp(&libs);
    }
    if a.ls {
        return prping_core::ls_builtins(&libs);
    }
    if let Some(hex) = &a.hex {
        return prping_core::decode_hex(hex);
    }
    if let Some(pcap) = &a.pcap {
        if let Some(dir) = &a.to_pkt {
            return prping_core::convert_pcap(
                std::path::Path::new(pcap),
                &prping_core::ConvertOptions {
                    out_dir: std::path::PathBuf::from(dir),
                    structured: a.structured,
                    skip: a.skip,
                    limit: a.limit,
                    threads: a.threads,
                },
            )
            .map(|_| ());
        }
        return prping_core::decode_pcap(std::path::Path::new(pcap));
    }

    let file = a
        .file
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!(t!("errors.eng_requires_file")))?;
    let path = resolve_pktl_arg(std::path::Path::new(file))?;
    let params = parse_params(&a.params)?;
    let globals = parse_globals(&a.global)?;
    if is_recipe(&path) {
        return prping_core::analyze_recipe(&path);
    }
    prping_core::analyze_file(&path, &params, &globals, &libs)
}

/// packet 子命令分发（构建发送 / 配方执行）。
fn run_packet(a: PacketArgs) -> anyhow::Result<()> {
    apply_lang(&a.lang);
    validate_packet(&a)?;
    let _ctrl_echo = suppress_ctrl_c_echo(a.json);
    set_json(a.json);

    // 先解析文件路径（后续预检和发送都需要）
    let path = resolve_pktl_arg(std::path::Path::new(&a.file))?;

    // --wait 无值 = 持续监听（服务端）——--raw 为链路层监听（帧内 MAC/IP 决定去向，
    // 不需要 ADDR:PORT）；否则 UDP 监听（目标 = 监听地址，显式或包内 dport 推导）
    if a.wait == prping_core::WaitMode::Continuous {
        if a.raw {
            if a.target.is_some() {
                return Err(anyhow::anyhow!(t!("errors.listen_raw_no_target")));
            }
            let opts = prping_core::PkgOptions {
                target: None,
                mode: prping_core::SendMode::Raw {
                    iface: a.iface.clone(),
                },
                params: parse_params(&a.params)?,
                globals: parse_globals(&a.global)?,
                wait: prping_core::WaitMode::Continuous,
                count: a.count,
                fuzz: false,
                out: None,
                summary: a.summary,
                libs: resolve_libs(&a.lib),
            };
            return prping_core::listen_raw_packets(&path, &opts);
        }
        let target = match a.target.as_deref() {
            Some(t) => {
                let (host, port) = parse_target(t)?;
                let port = match port {
                    Some(p) => p,
                    None => return Err(anyhow::anyhow!(t!("errors.pkg_requires_port"))),
                };
                Some(resolve_target(&host, port)?)
            }
            None => None,
        };
        let opts = prping_core::PkgOptions {
            target,
            mode: prping_core::SendMode::Payload,
            params: parse_params(&a.params)?,
            globals: parse_globals(&a.global)?,
            wait: prping_core::WaitMode::Continuous,
            count: a.count,
            fuzz: false,
            out: None,
            summary: a.summary,
            libs: resolve_libs(&a.lib),
        };
        return prping_core::listen_packets(&path, &opts);
    }

    // 预检只解析一次文件（此前 up to 3 次重复解析同一文件）；显式 --raw 时
    // 无需预检（结果只在 !raw 分支用到）
    let raw_only = !a.raw && all_exports_raw_only(&path, &a);
    let target = match a.target.as_deref() {
        Some(t) => {
            let (host, port) = parse_target(t)?;
            let port = match port {
                Some(p) => p,
                // raw 模式端口无意义（原始 socket 不带端口；链路层帧如 ARP 甚至不需要
                // 目标）——允许裸 HOST，端口按 0 处理
                None if a.raw => 0,
                None => {
                    // 预检：如果所有导出包都是 raw-only（无 TCP/UDP 传输层），自动升级
                    // 为 raw 模式并给提示，而不是报"需要端口"的误导性错误
                    if raw_only {
                        let mut w = prping_core::stderr();
                        let _ = writeln_orange(&mut w, t!("engine.auto_raw_upgrade"));
                        let _ = writeln!(&mut w);
                        0
                    } else {
                        return Err(anyhow::anyhow!(t!("errors.pkg_requires_port")));
                    }
                }
            };
            Some(resolve_target(&host, port)?)
        }
        None => {
            // 未给目标：如果所有导出包都是 raw-only，提前提示需要 root 权限
            if raw_only {
                let mut w = prping_core::stderr();
                let _ = writeln_orange(&mut w, t!("engine.auto_raw_upgrade"));
                let _ = writeln!(&mut w);
            }
            None
        }
    };
    let raw_mode = a.raw
        || (raw_only
            && target
                .as_ref()
                .is_none_or(|t: &std::net::SocketAddr| t.port() == 0));
    let opts = prping_core::PkgOptions {
        target,
        mode: if raw_mode {
            prping_core::SendMode::Raw {
                iface: a.iface.clone(),
            }
        } else {
            prping_core::SendMode::Payload
        },
        params: parse_params(&a.params)?,
        globals: parse_globals(&a.global)?,
        wait: a.wait,
        count: a.count,
        fuzz: a.fuzz,
        out: a.out.as_ref().map(std::path::PathBuf::from),
        summary: a.summary,
        libs: resolve_libs(&a.lib),
    };
    if is_recipe(&path) {
        return prping_core::send_recipe(&path, &opts);
    }
    prping_core::send_packets(&path, &opts)
}

/// document 子命令分发（使用手册：全文 / 章节跳转）。
fn run_document(a: DocumentArgs) -> anyhow::Result<()> {
    apply_lang(&a.lang);
    let section = a.section.unwrap_or_default();
    handle_help_pkg(&section)
}

// ── 唯一前缀展开 ──────────────────────────────────────────────────────────

/// 唯一前缀展开：首 token（子命令位置）是某子命令名的唯一前缀时替换为全名。
///
/// bpaf 的子命令匹配是精确的（`take_cmd` 做 `w == word`），这里在解析前
/// 展开 `prping e F.pkt` → `prping engine F.pkt` 这类写法；歧义（多个候选）
/// 与「形似旧语法目标」的情况返回错误文案由调用方红字打印退出。
fn expand_subcommand_prefix(args: &mut [String]) -> Result<(), String> {
    let Some(first) = args.first() else {
        return Ok(());
    };
    if first.starts_with('-') {
        return Ok(());
    }
    let matches: Vec<&str> = SUBCOMMANDS
        .iter()
        .copied()
        .filter(|c| c.starts_with(first.as_str()))
        .collect();
    match matches.len() {
        0 => {
            // 形似旧语法目标（IP 或 host:port）：提示迁移到 `ping`
            let looks_like_host =
                first.parse::<IpAddr>().is_ok() || (first.contains(':') && !first.starts_with('-'));
            if looks_like_host {
                return Err(t!("errors.legacy_host_hint", host = first.as_str()).to_string());
            }
            Ok(())
        }
        1 => {
            if matches[0] != first.as_str() {
                args[0] = matches[0].to_string();
            }
            Ok(())
        }
        _ => Err(t!(
            "errors.ambiguous_prefix",
            token = first.as_str(),
            candidates = matches.join(", ")
        )
        .to_string()),
    }
}

// ── 顶层流程 ──────────────────────────────────────────────────────────────

/// 把 BCP-47 语言标识（en-US / zh-CN / en_US / zh）规范化到 rust-i18n 实际 locale。
///
/// locales 目录为 `en-US.yml` 与 `zh-CN.yml`，所有输入统一映射：
/// 中文系 → `zh-CN`，其余（含 en-US/en/en_GB...）→ `en-US`。
fn normalize_locale(s: &str) -> String {
    let s = s.trim().to_lowercase().replace('_', "-");
    if s.starts_with("zh") {
        "zh-CN".to_string()
    } else {
        "en-US".to_string()
    }
}

/// macOS 系统 UI 语言（系统设置 → 语言与地区 的首选语言）。
///
/// 通过 CoreFoundation 的 `CFLocaleCopyCurrent` 查询，返回形如
/// `zh-Hans-CN` / `en_US` 的 locale 标识；查询失败返回 None（调用方兜底 LANG）。
#[cfg(target_os = "macos")]
fn macos_system_locale() -> Option<String> {
    use std::ffi::{CStr, c_char};
    use std::os::raw::c_void;

    /// kCFStringEncodingUTF8
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFLocaleCopyCurrent() -> *const c_void;
        fn CFLocaleGetIdentifier(locale: *const c_void) -> *const c_void;
        fn CFStringGetCString(
            the_string: *const c_void,
            buffer: *mut c_char,
            buffer_size: isize,
            encoding: u32,
        ) -> u8;
        fn CFRelease(cf: *const c_void);
    }

    // SAFETY: CFLocaleCopyCurrent 返回 retain 的对象，用完必须 CFRelease；
    // CFLocaleGetIdentifier 返回的 CFStringRef 由 locale 对象持有，不释放。
    unsafe {
        let locale = CFLocaleCopyCurrent();
        if locale.is_null() {
            return None;
        }
        let ident = CFLocaleGetIdentifier(locale);
        let mut buf = [0; 64];
        let ok = CFStringGetCString(
            ident,
            buf.as_mut_ptr(),
            buf.len() as isize,
            K_CF_STRING_ENCODING_UTF8,
        );
        CFRelease(locale);
        if ok == 0 {
            return None;
        }
        Some(CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned())
    }
}

/// Auto-detect locale from --lang / env vars / 系统 UI 语言（macOS/Windows）。
fn detect_locale() {
    // Check raw args for --lang before parser construction (for --help i18n)
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--lang")
        && let Some(loc) = args.get(pos + 1)
    {
        rust_i18n::set_locale(&normalize_locale(loc));
        return;
    }
    for a in &args {
        if let Some(loc) = a.strip_prefix("--lang=") {
            rust_i18n::set_locale(&normalize_locale(loc));
            return;
        }
    }
    if let Ok(loc) = std::env::var("RUST_I18N_LOCALE") {
        rust_i18n::set_locale(&normalize_locale(&loc));
    } else if let Some(loc) = std::env::var("LANG").ok().filter(|s| !s.trim().is_empty()) {
        // 所有平台（含 macOS）一致：LANG 优先（如 en_US.UTF-8 → en-US）；
        // macOS 终端不设 LANG 或 LANG 为空串时用系统 UI 语言兜底。
        let loc = loc.split('.').next().unwrap_or("en-US");
        rust_i18n::set_locale(&normalize_locale(loc));
    } else if cfg!(target_os = "macos") {
        // macOS：终端未设 LANG 时以系统 UI 语言为准（系统设置 → 语言与地区）。
        #[cfg(target_os = "macos")]
        {
            if let Some(loc) = macos_system_locale() {
                rust_i18n::set_locale(&normalize_locale(&loc));
            }
        }
    } else if cfg!(windows) {
        // Windows：无 LANG 环境变量，用系统 UI 语言
        #[cfg(windows)]
        {
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn GetUserDefaultUILanguage() -> u16;
            }
            // SAFETY: 无参数、无指针，纯查询 API，任何线程安全。
            let langid = unsafe { GetUserDefaultUILanguage() };
            let primary = langid & 0x3FF;
            let loc = match primary {
                0x04 => "zh-CN", // 中文（含繁体，项目无繁体 locale，归入 zh-CN）
                0x09 => "en-US", // 英语
                _ => "en-US",
            };
            rust_i18n::set_locale(&normalize_locale(loc));
        }
    }
    // 兜底：若检测结果不在项目实际 locale（en-US/zh-CN）内——rust-i18n 默认
    // locale 是 "en"，t! 会原样返回 key（如 "cmd.ping"）——强制回退英文。
    let cur: &str = &rust_i18n::locale();
    if !matches!(cur, "en-US" | "zh-CN") {
        rust_i18n::set_locale("en-US");
    }
}
/// document 子命令：手册全文（空 section）/ 章节跳转（编号 / 标题前缀 / 包含匹配）。
/// 顶层 `--help-pkg` 已废弃（与子命令解析互斥，直接报错）——手册统一走 document。
fn handle_help_pkg(section: &str) -> anyhow::Result<()> {
    let manual = manual_for(&rust_i18n::locale());
    match section {
        "" => {
            // 全文：tty 时 pager 自动分页
            print_paged(manual)?;
            Ok(())
        }
        q => {
            let hits = find_sections(manual, q);
            match hits.len() {
                0 => {
                    let mut w = stderr();
                    let _ = writeln_red(&mut w, t!("errors.help_pkg_not_found", section = q));
                    println!("{}", t!("errors.help_pkg_toc_hint"));
                    println!("{}", toc(manual));
                    std::process::exit(1);
                }
                1 => {
                    // 单章节：使用 print_paged 确保管道/文件场景完整输出
                    print_paged(&hits[0].body)?;
                    Ok(())
                }
                n => {
                    // 多章节候选：使用 write_all 确保一次性输出
                    let mut stdout = std::io::stdout();
                    let msg = t!("errors.help_pkg_ambiguous", count = n);
                    stdout.write_all(format!("{msg}\n").as_bytes())?;
                    for h in &hits {
                        stdout.write_all(format!("  {}. {}\n", h.number, h.title).as_bytes())?;
                    }
                    stdout.flush()?;
                    Ok(())
                }
            }
        }
    }
}

/// Web 执行桥子进程生命线（`PRPING_WEB_RUN=1`，由 `web/run.rs` spawn 时注入）：
/// 监视 stdin——父进程（web 服务器）死亡时管道写端被内核关闭，读到 EOF/错误立即
/// 退出，防止服务端被 SIGKILL/崩溃后子进程被 init 收养成为孤儿（尤其 `--wait`
/// 静默监听会一直占着端口）。数据字节忽略（引擎子命令无交互输入；预留将来把
/// 「优雅停机」也走 stdin 的扩展位）。
fn install_stdin_lifeline() {
    if std::env::var_os("PRPING_WEB_RUN").is_none_or(|v| v != "1") {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("stdin-lifeline".into())
        .spawn(|| {
            use std::io::Read;
            let stdin = std::io::stdin();
            let mut lock = stdin.lock();
            let mut buf = [0u8; 256];
            loop {
                match lock.read(&mut buf) {
                    Ok(0) | Err(_) => std::process::exit(0),
                    Ok(_) => {}
                }
            }
        });
}

fn main() -> anyhow::Result<()> {
    // 多线程 executor：smol 全局 executor 默认单线程，--parallel 并发无法真正并行
    configure_executor_threads();
    detect_locale();
    install_interrupt_handler()?;
    install_stdin_lifeline();

    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // 全局 --lang：任意位置提取并移除（子命令必须是首个 token，--lang 在子命令前
    // 时 bpaf 无法消费；detect_locale 已用它设置过一次 locale，这里对显式值再设置）。
    let mut lang = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--lang" {
            // 仅当下一 token 是合法 locale 形态才当作值消费：忘带值（如
            // engine --lang）时不再把文件名/子命令吞掉
            let next_is_value = args
                .get(i + 1)
                .is_some_and(|v| !v.starts_with('-') && !SUBCOMMANDS.contains(&v.as_str()));
            if next_is_value && let Some(v) = args.get(i + 1) {
                lang = Some(v.clone());
                args.remove(i + 1);
            }
            args.remove(i);
        } else if let Some(v) = args[i].strip_prefix("--lang=") {
            lang = Some(v.to_string());
            args.remove(i);
        } else {
            i += 1;
        }
    }
    if let Some(loc) = &lang {
        rust_i18n::set_locale(&normalize_locale(loc));
    }

    // 顶层 --version（不属任何子命令，pre-scan 处理）
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("prping {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // 无参数：摘要帮助
    if args.is_empty() {
        print_summary_help();
        return Ok(());
    }

    // 唯一前缀展开（bpaf 本身只做精确匹配）
    if let Err(msg) = expand_subcommand_prefix(&mut args) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(2);
    }

    let cmd = match cmd()
        .to_options()
        .usage(t!("help.usage").as_ref())
        .footer(t!("help.mode_guide").as_ref())
        .run_inner(args.as_slice())
    {
        Ok(c) => c,
        Err(f) => {
            // 帮助/错误打印与 .run() 一致（ParseFailure 自行选择 stdout/stderr）
            f.print_message(100);
            std::process::exit(f.exit_code());
        }
    };

    match cmd {
        Command::Ping(a) => run_ping(a),
        Command::Latency(a) => run_latency(a),
        Command::Bandwidth(a) => run_bandwidth(a),
        Command::Server(a) => run_server(a),
        Command::Trace(a) => run_trace(a),
        Command::Engine(a) => run_engine(a),
        Command::Packet(a) => run_packet(a),
        Command::Document(a) => run_document(a),
        #[cfg(feature = "web")]
        Command::Web(a) => run_web(a),
    }
}

/// 渲染测试警告为本地化文案。
fn render_warning(w: PrpingWarning) -> String {
    match w {
        PrpingWarning::IntervalClamped { requested } => {
            t!("errors.interval_min", value = requested).to_string()
        }
        PrpingWarning::ParallelUdpIgnored => t!("errors.parallel_udp_ignored").to_string(),
        PrpingWarning::ParallelIgnored => t!("errors.parallel_ignored").to_string(),
        PrpingWarning::ReceiveIgnoredPing => t!("errors.receive_ignored_ping").to_string(),
        PrpingWarning::UdpSizeClamped { requested, max } => {
            t!("errors.udp_size_clamped", size = requested, max = max).to_string()
        }
    }
}

/// 库目录列表：`--lib` 追加的路径。默认 `lib/` 目录（二进制同目录 + 当前目录，
/// 存在才收录）由 `packet_dsl::default_libs` 运行时发现并自动合并，这里不重复收录。
fn resolve_libs(extra: &[String]) -> Vec<std::path::PathBuf> {
    extra.iter().map(std::path::PathBuf::from).collect()
}

/// 解析 `packet` 子命令目标（DNS 解析，复用 lib 统一入口）。
fn resolve_target(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    prping_core::resolve(host, port, false, false)
}

/// 解析 `--params k=v,k2=v2`。
fn parse_params(list: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for s in list {
        // 校验所有 pair 都含 '='（parse_kv_pairs 会静默跳过无效项，这里需要报错）
        for pair in s.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if !pair.contains('=') {
                anyhow::bail!(t!("errors.params_format", value = pair));
            }
        }
        for (k, v) in prping_core::parse_kv_pairs(s) {
            out.push((k.to_string(), v.to_string()));
        }
    }
    Ok(out)
}

/// 解析 `--global k=v,k2=v2`（短 `-g`）→ 配方全局存储（值与 `params` 同形状解析：
/// 0x/十进制 → 数值，其余 → 字符串；`global("name")` 值原语读取）。
fn parse_globals(list: &[String]) -> anyhow::Result<packet_dsl::Globals> {
    let mut out = packet_dsl::Globals::new();
    for s in list {
        for pair in s.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!(t!("errors.global_format", value = pair)))?;
            out.insert(
                k.trim().to_string(),
                packet_dsl::parse_param_value(v.trim()),
            );
        }
    }
    Ok(out)
}

/// `.pktl` 配方文件判定（扩展名不区分大小写）。
fn is_recipe(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("pktl"))
        .unwrap_or(false)
}

/// 预检：加载 .pkt/.pktl 文件，检查所有导出包是否都是 raw-only（无 TCP/UDP 传输层，
/// 但有 eth/ipv4/ipv6 外层可 raw 发送）。用于 CLI 层在缺少端口时判断是否可以自动
/// 升级为 raw 模式，而不是报"需要端口"的误导性错误。
///
/// 失败时静默返回 false（让后续真正发送时报出更有意义的错误）。
fn all_exports_raw_only(path: &std::path::Path, a: &PacketArgs) -> bool {
    let libs = resolve_libs(&a.lib);
    let params_vec: Vec<(String, String)> = parse_params(&a.params).unwrap_or_default();
    let params: packet_dsl::Params = params_vec.into_iter().collect();
    let globals: packet_dsl::Globals = parse_globals(&a.global).unwrap_or_default();

    if is_recipe(path) {
        // 配方：解析 recipe，逐步骤检查每个 .pkt 文件
        let recipe = match prping_core::parse_recipe(path) {
            Ok(r) => r,
            Err(_) => return false,
        };
        if recipe.steps.is_empty() {
            return false;
        }
        // 收集所有步骤的 .pkt 文件路径
        let pkt_files: Vec<std::path::PathBuf> =
            recipe.steps.iter().map(|s| s.pkg.clone()).collect();
        // 逐个检查：只要有一步的包需要 TCP/UDP payload 模式，就返回 false
        for pkt_file in &pkt_files {
            let module = match packet_dsl::parse_file_with_libs(pkt_file, &libs) {
                Ok(m) => m,
                Err(_) => return false,
            };
            let sources = match packet_dsl::resolve_sources_with_globals(&module, &params, &globals)
            {
                Ok(s) => s,
                Err(_) => return false,
            };
            let pkts: Vec<_> = sources.iter().flat_map(|(_, pkts)| pkts).collect();
            if pkts.is_empty() {
                return false;
            }
            // 只要有任何一个包需要 TCP/UDP payload 模式（有传输层），就不是 all-raw-only
            if pkts.iter().any(|pkt| has_tcp_udp(pkt)) {
                return false;
            }
        }
        true
    } else {
        // 单文件：检查所有导出包
        let module = match packet_dsl::parse_file_with_libs(path, &libs) {
            Ok(m) => m,
            Err(_) => return false,
        };
        let sources = match packet_dsl::resolve_sources_with_globals(&module, &params, &globals) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let pkts: Vec<_> = sources.iter().flat_map(|(_, pkts)| pkts).collect();
        if pkts.is_empty() {
            return false;
        }
        // 没有任何包需要 TCP/UDP payload 模式
        !pkts.iter().any(|pkt| has_tcp_udp(pkt))
    }
}

/// 包是否包含 TCP/UDP 传输层（payload 模式可提取载荷发送）。
fn has_tcp_udp(pkt: &packet_dsl::PacketSpec) -> bool {
    pkt.layers.iter().any(|l| {
        matches!(
            l,
            packet_dsl::ir::Layer::Tcp(_) | packet_dsl::ir::Layer::Udp(_)
        )
    })
}

/// 无扩展名参数 → pktl 定位：先试 `<arg>.pktl`（当前目录/参数所在目录下的同名文件），
/// 该文件不存在时再试 `<arg>/<basename>.pktl`（同名文件夹里的同名 pktl）。
/// 带扩展名（`.pkt`/`.pktl`）的参数原样返回，交由调用方按扩展名分派。
fn resolve_pktl_arg(arg: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    if arg.extension().is_some() {
        return Ok(arg.to_path_buf());
    }
    let direct = std::path::PathBuf::from(format!("{}.pktl", arg.display()));
    if direct.is_file() {
        return Ok(direct);
    }
    let base = arg.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let in_dir = arg.join(format!("{base}.pktl"));
    if in_dir.is_file() {
        return Ok(in_dir);
    }
    anyhow::bail!(t!(
        "errors.pktl_not_found",
        arg = arg.display(),
        direct = direct.display(),
        folder = in_dir.display(),
    ));
}

/// 运行期间隐藏终端回显 `^C` 的 guard：构造时关闭 stdin tty 的 ECHOCTL，
/// Drop 时恢复原 termios。
///
/// `^C` 由终端行规程（ECHOCTL）回显到屏幕，**从不进入 stdout 管道**——
/// 这里只做显示层清理，避免 `--json` 流式输出时屏幕上混入 `^C`。
/// 仅在 stdin 为 tty（交互运行）时生效；stdin 被重定向时返回 None。
#[cfg(unix)]
struct CtrlCEchoGuard {
    original: libc::termios,
}

#[cfg(unix)]
impl Drop for CtrlCEchoGuard {
    fn drop(&mut self) {
        // SAFETY: 恢复我们修改前的 termios；tcsetattr 失败可忽略（终端已关闭等）。
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

#[cfg(not(unix))]
struct CtrlCEchoGuard;

// Windows 控制台不回显 `^C`，guard 是空操作；实现 Drop 让 `drop(_ctrl_echo)`
// 在 `process::exit` 前的调用保持类型一致（clippy drop_non_drop 门禁）。
#[cfg(not(unix))]
impl Drop for CtrlCEchoGuard {
    fn drop(&mut self) {}
}

/// `--json` 模式隐藏终端回显的 `^C`（Unix 且 stdin 为 tty 时；Windows 控制台不回显 `^C`）。
///
/// 第二次 Ctrl+C 走 `_exit` 不会恢复 termios——那是信号安全限制下的取舍，
/// 残留的只是 ECHOCTL 关闭（纯显示层，无害）。
#[cfg(unix)]
fn suppress_ctrl_c_echo(enable: bool) -> Option<CtrlCEchoGuard> {
    if !enable {
        return None;
    }
    // SAFETY: isatty 为纯查询调用。
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return None;
    }
    // SAFETY: tcgetattr/tcsetattr 为常规 termios 查询/设置；仅修改 ECHOCTL 一位。
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut t) } != 0 {
        return None;
    }
    let original = t;
    t.c_lflag &= !libc::ECHOCTL;
    if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) } != 0 {
        return None;
    }
    Some(CtrlCEchoGuard { original })
}

#[cfg(not(unix))]
fn suppress_ctrl_c_echo(_enable: bool) -> Option<CtrlCEchoGuard> {
    None
}

/// 安装 Ctrl+C 处理器：首次按下置位中断标志（优雅停止并输出统计），再次按下立即退出。
///
/// Unix 用 `libc::signal`，Windows 用 `kernel32::SetConsoleCtrlHandler`。
#[cfg(unix)]
fn install_interrupt_handler() -> anyhow::Result<()> {
    extern "C" fn on_sigint(_: libc::c_int) {
        if INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst) == 0 {
            prping_core::set_interrupted(true);
        } else {
            // 第二次 Ctrl+C：立即退出（_exit 为异步信号安全）
            unsafe { libc::_exit(130) };
        }
    }
    // SAFETY: 安装 SIGINT 处理器；处理器内只做原子操作与 _exit，均异步信号安全。
    unsafe { libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t) };
    Ok(())
}

#[cfg(windows)]
fn install_interrupt_handler() -> anyhow::Result<()> {
    use std::os::raw::{c_int, c_uint};

    // Windows 控制台事件处理器（BOOL CALLBACK HandlerRoutine(DWORD dwCtrlType)）。
    // 运行在专用线程而非信号上下文，可安全调用原子操作与 ExitProcess。
    unsafe extern "system" fn on_ctrl(_ctrl_type: c_uint) -> c_int {
        if INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst) == 0 {
            prping_core::set_interrupted(true);
        } else {
            // 第二次 Ctrl+C：立即退出（ExitProcess 不跑 atexit，处理器线程内安全）
            unsafe { ExitProcess(130) };
        }
        1 // TRUE：事件已处理，阻止默认终止
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(c_uint) -> c_int>,
            add: c_int,
        ) -> c_int;
        fn ExitProcess(code: c_uint) -> !;
    }

    // SAFETY: 注册控制台事件处理器；处理器内只做原子操作与 ExitProcess。
    let ok = unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    if ok == 0 {
        anyhow::bail!("SetConsoleCtrlHandler failed");
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn install_interrupt_handler() -> anyhow::Result<()> {
    Ok(())
}

use std::sync::atomic::{AtomicU8, Ordering};
static INTERRUPT_COUNT: AtomicU8 = AtomicU8::new(0);

fn print_summary_help() {
    println!("{}", t!("help.overview"));
    println!();
    println!("{}", t!("help.usage_line"));
    println!();
    println!("{}", t!("help.examples"));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// packet 校验：持续监听（--wait 无值）允许 --raw/--iface；拒绝 --fuzz/--out；
    /// --json 与持续监听互斥；--iface 需 --raw。
    #[test]
    fn validate_packet_wait_modes() {
        use prping_core::WaitMode;
        let base = PacketArgs {
            raw: false,
            iface: None,
            wait: WaitMode::Off,
            count: 1,
            fuzz: false,
            out: None,
            summary: false,
            lib: Vec::new(),
            params: Vec::new(),
            global: Vec::new(),
            json: false,
            lang: None,
            file: "a.pkt".into(),
            target: None,
        };
        // 普通发送 / 一次性 wait / 持续监听都合法
        assert!(validate_packet(&base).is_ok());
        let one_shot = PacketArgs {
            wait: WaitMode::OneShot(1.0),
            ..base.clone()
        };
        assert!(validate_packet(&one_shot).is_ok());
        let mut continuous = PacketArgs {
            wait: WaitMode::Continuous,
            ..base.clone()
        };
        assert!(
            validate_packet(&continuous).is_ok(),
            "--wait 无值（持续监听）合法"
        );
        // 持续监听 + --raw（链路层监听）合法；--raw --iface lo 合法
        continuous.raw = true;
        assert!(validate_packet(&continuous).is_ok(), "--wait --raw 合法");
        continuous.iface = Some("lo".into());
        assert!(
            validate_packet(&continuous).is_ok(),
            "--wait --raw --iface 合法"
        );
        // 持续监听 + --fuzz/--out 拒绝
        let bad = PacketArgs {
            wait: WaitMode::Continuous,
            fuzz: true,
            ..base.clone()
        };
        assert!(validate_packet(&bad).is_err(), "持续监听 + --fuzz 拒绝");
        let bad = PacketArgs {
            wait: WaitMode::Continuous,
            out: Some("x.pcap".into()),
            ..base.clone()
        };
        assert!(validate_packet(&bad).is_err(), "持续监听 + --out 拒绝");
        // --iface 无 --raw 拒绝
        let bad = PacketArgs {
            iface: Some("lo".into()),
            ..base.clone()
        };
        assert!(validate_packet(&bad).is_err(), "--iface 需 --raw");
        // --count：0 拒绝；>1 与持续监听拒绝
        let bad = PacketArgs {
            count: 0,
            ..base.clone()
        };
        assert!(validate_packet(&bad).is_err(), "--count 0 拒绝");
        let ok = PacketArgs {
            count: 3,
            ..base.clone()
        };
        assert!(validate_packet(&ok).is_ok(), "--count 3 合法");
        let bad = PacketArgs {
            count: 3,
            wait: WaitMode::Continuous,
            ..base.clone()
        };
        assert!(validate_packet(&bad).is_err(), "持续监听 + --count>1 拒绝");
    }

    /// normalize_locale 映射：BCP-47 全形态 → rust-i18n 实际 locale。
    #[test]
    fn normalize_locale_mapping() {
        for (input, expected) in [
            ("en-US", "en-US"),
            ("en_US", "en-US"),
            ("en", "en-US"),
            ("en_GB", "en-US"),
            ("fr-FR", "en-US"),
            ("C", "en-US"),
            ("zh-CN", "zh-CN"),
            ("zh_CN", "zh-CN"),
            ("zh", "zh-CN"),
            ("zh-Hans-CN", "zh-CN"),
            ("zh_TW", "zh-CN"),
            ("  zh-CN.UTF-8  ", "zh-CN"),
        ] {
            assert_eq!(normalize_locale(input), expected, "input: {input}");
        }
    }

    /// macOS：系统 UI 语言查询（仅 macOS 编译/运行；CI macOS job 上执行）。
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_system_locale_detects() {
        let loc = macos_system_locale();
        assert!(loc.is_some(), "CFLocaleCopyCurrent 应始终可用");
        let l = loc.unwrap();
        assert!(!l.is_empty());
        // 结果应能规范化为本项目支持的 locale 之一
        assert!(matches!(normalize_locale(&l).as_str(), "en-US" | "zh-CN"));
    }

    /// 唯一前缀展开表驱动测试。
    #[test]
    fn expand_prefix_exact() {
        let mut args = vec!["ping".to_string(), "8.8.8.8".to_string()];
        expand_subcommand_prefix(&mut args).unwrap();
        assert_eq!(args[0], "ping");
    }

    #[test]
    fn expand_prefix_unique_short() {
        for (short, full) in [
            ("pi", "ping"),
            ("pa", "packet"),
            ("ba", "bandwidth"),
            ("la", "latency"),
            ("se", "server"),
            ("tr", "trace"),
            ("en", "engine"),
            ("e", "engine"),
            ("t", "trace"),
            ("s", "server"),
            ("b", "bandwidth"),
            ("l", "latency"),
        ] {
            let mut args = vec![short.to_string(), "x".to_string()];
            expand_subcommand_prefix(&mut args).unwrap_or_else(|e| panic!("{short}: {e}"));
            assert_eq!(args[0], full, "prefix {short}");
        }
    }

    #[test]
    fn expand_prefix_ambiguous() {
        rust_i18n::set_locale("en-US");
        // "p" 匹配 ping 与 packet
        let mut args = vec!["p".to_string(), "8.8.8.8".to_string()];
        let err = expand_subcommand_prefix(&mut args).unwrap_err();
        assert!(err.contains("ping") && err.contains("packet"), "{err}");
        // "b" 匹配 bandwidth
        let mut args = vec!["b".to_string(), "h:1".to_string()];
        expand_subcommand_prefix(&mut args).unwrap();
        assert_eq!(args[0], "bandwidth");
    }

    #[test]
    fn expand_prefix_unknown_host_hints() {
        rust_i18n::set_locale("en-US");
        // 形似 IP：旧语法迁移提示
        let mut args = vec!["8.8.8.8".to_string()];
        let err = expand_subcommand_prefix(&mut args).unwrap_err();
        assert!(err.contains("ping"), "{err}");
        // host:port
        let mut args = vec!["1.2.3.4:53".to_string()];
        let err = expand_subcommand_prefix(&mut args).unwrap_err();
        assert!(err.contains("ping"), "{err}");
    }

    #[test]
    fn expand_prefix_ignores_flags_and_empty() {
        let mut args: Vec<String> = Vec::new();
        expand_subcommand_prefix(&mut args).unwrap();
        let mut args = vec!["-u".to_string(), "x".to_string()];
        expand_subcommand_prefix(&mut args).unwrap();
        assert_eq!(args[0], "-u");
    }

    /// engine 转码选项校验：--to-pkt/--structured/--skip/--limit 必须配合 --pcap。
    #[test]
    fn validate_engine_convert_flags() {
        rust_i18n::set_locale("en-US");
        let base = EngineArgs {
            file: None,
            lsp: false,
            ls: false,
            hex: None,
            pcap: Some("x.pcap".to_string()),
            to_pkt: None,
            structured: false,
            skip: 0,
            limit: None,
            threads: 0,
            lib: Vec::new(),
            params: Vec::new(),
            global: Vec::new(),
            json: false,
            lang: None,
        };
        // 合法组合：--pcap + --to-pkt（± structured/skip/limit）
        let mut ok = base.clone();
        ok.to_pkt = Some("dir".to_string());
        ok.structured = true;
        ok.skip = 2;
        ok.limit = Some(5);
        ok.threads = 4;
        validate_engine(&ok).unwrap();
        // --to-pkt 缺 --pcap
        let mut bad = base.clone();
        bad.pcap = None;
        bad.to_pkt = Some("dir".to_string());
        assert!(validate_engine(&bad).is_err());
        // --structured 缺 --to-pkt
        let mut bad = base.clone();
        bad.structured = true;
        assert!(validate_engine(&bad).is_err());
        // --skip/--limit/--threads 缺 --to-pkt
        let mut bad = base.clone();
        bad.skip = 1;
        assert!(validate_engine(&bad).is_err());
        let mut bad = base.clone();
        bad.limit = Some(1);
        assert!(validate_engine(&bad).is_err());
        let mut bad = base.clone();
        bad.threads = 2;
        assert!(validate_engine(&bad).is_err());
    }

    /// server 依赖链校验：--capture-all 需显式 --verbose；--filter 需显式
    /// --capture-all（不隐含开启）。
    #[test]
    fn validate_server_dependencies() {
        rust_i18n::set_locale("en-US");
        let args = |verbose, capture_all, filter: Option<&str>| ServerArgs {
            verbose,
            capture_all,
            filter: filter.map(String::from),
            lang: None,
            addr: "0.0.0.0:9000".to_string(),
        };
        // 合法组合：无标志 / 仅 -v / -v -a / -v -a --filter
        assert!(validate_server(&args(false, false, None)).is_none());
        assert!(validate_server(&args(true, false, None)).is_none());
        assert!(validate_server(&args(true, true, None)).is_none());
        assert!(validate_server(&args(true, true, Some("arp or icmp"))).is_none());
        // -a 缺 -v → 报错
        let msg = validate_server(&args(false, true, None)).unwrap();
        assert!(msg.contains("--capture-all"), "{msg}");
        // --filter 缺 -a（即使给了 -v）→ 报错
        let msg = validate_server(&args(true, false, Some("tcp"))).unwrap();
        assert!(msg.contains("--filter"), "{msg}");
        let msg = validate_server(&args(false, false, Some("tcp"))).unwrap();
        assert!(msg.contains("--filter"), "{msg}");
    }

    /// 无扩展名参数 → pktl 定位：先 `<arg>.pktl`，再 `<arg>/<basename>.pktl`；
    /// 带扩展名原样返回；两者都找不到报错。
    #[test]
    fn resolve_pktl_arg_lookup() {
        rust_i18n::set_locale("en-US");
        let dir = std::env::temp_dir().join(format!("prping-pktl-arg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // 1. 直接文件：<arg>.pktl 存在 → 命中
        std::fs::write(dir.join("direct.pktl"), "recipe:\n- packet: x.pkt\n").unwrap();
        let got = resolve_pktl_arg(&dir.join("direct")).unwrap();
        assert_eq!(got, dir.join("direct.pktl"));

        // 2. 同名文件夹：<arg>.pktl 不存在，<arg>/<basename>.pktl 存在 → 命中
        std::fs::create_dir_all(dir.join("folded")).unwrap();
        std::fs::write(dir.join("folded/folded.pktl"), "recipe:\n- packet: y.pkt\n").unwrap();
        let got = resolve_pktl_arg(&dir.join("folded")).unwrap();
        assert_eq!(got, dir.join("folded/folded.pktl"));

        // 3. 带扩展名：原样返回（.pktl 与 .pkt 都不做查找）
        let p = dir.join("named.pkt");
        assert_eq!(resolve_pktl_arg(&p).unwrap(), p);
        let p = dir.join("named.pktl");
        assert_eq!(resolve_pktl_arg(&p).unwrap(), p);

        // 4. 两者都不存在 → 报错，消息带两条候选路径（跨平台：用 Path 分隔符断言）
        let err = resolve_pktl_arg(&dir.join("missing")).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains(dir.join("missing.pktl").to_string_lossy().as_ref()),
            "{msg}"
        );
        assert!(
            msg.contains(
                dir.join("missing")
                    .join("missing.pktl")
                    .to_string_lossy()
                    .as_ref()
            ),
            "{msg}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
