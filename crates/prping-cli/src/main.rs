rust_i18n::i18n!("locales");

use bpaf::*;
use prping_core::{
    DEFAULT_MAX_HOPS, OutcomeKind, PingConfig, PrpingError, PrpingWarning,
    configure_executor_threads, find_sections, manual_for, parse_histogram, print_paged,
    resolve_source, run, serve, set_json, set_pretty, stderr, toc, writeln_orange, writeln_red,
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
    if let Some((host, port)) = input.rsplit_once(':')
        && port.chars().all(|c| c.is_ascii_digit())
        && !host.contains(':')
    {
        return Ok((host.to_string(), Some(port.parse()?)));
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
struct PingArgs {
    udp: bool,
    mtu: bool,
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

/// latency 子命令（TCP/UDP 回显往返延迟）
struct LatencyArgs {
    udp: bool,
    size: Option<String>,
    receive: bool,
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

/// bandwidth 子命令（TCP/UDP 吞吐）
struct BandwidthArgs {
    udp: bool,
    size: Option<String>,
    receive: bool,
    parallel: Option<u32>,
    count: Option<String>,
    interval: Option<f64>,
    quiet: bool,
    warmup: Option<u64>,
    json: bool,
    v4: bool,
    v6: bool,
    source: Option<String>,
    lang: Option<String>,
    target: String,
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

/// trace 子命令（ICMP echo / TCP SYN / UDP 逐跳路径发现）
struct TraceArgs {
    tcp: bool,
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
    lang: Option<String>,
}

/// packet 子命令（构建 .pkt 并发送；.pktl 配方执行）
struct PacketArgs {
    raw: bool,
    iface: Option<String>,
    wait: Option<f64>,
    fuzz: bool,
    out: Option<String>,
    summary: bool,
    lib: Vec<String>,
    params: Vec<String>,
    global: Vec<String>,
    lang: Option<String>,
    file: String,
    target: Option<String>,
}

/// document 子命令（使用手册：全文 / 章节跳转）
struct DocumentArgs {
    lang: Option<String>,
    section: Option<String>,
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
}

fn ping_cmd() -> impl Parser<Command> {
    construct!(PingArgs {
        udp(opt_udp()),
        mtu(long("mtu")
            .short('m')
            .switch()
            .help(t!("help.options.mtu").as_ref())),
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
        target(positional::<String>("HOST[:PORT]")),
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
        udp(opt_udp()),
        size(opt_size()),
        receive(long("receive")
            .short('r')
            .switch()
            .help(t!("help.options.receive").as_ref())),
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
        target(positional::<String>("HOST:PORT")),
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
        udp(opt_udp()),
        size(opt_size()),
        receive(long("receive")
            .short('r')
            .switch()
            .help(t!("help.options.receive").as_ref())),
        parallel(long("parallel")
            .argument::<u32>("N")
            .help(t!("help.options.parallel").as_ref())
            .optional()),
        count(opt_count()),
        interval(opt_interval()),
        quiet(opt_quiet()),
        warmup(opt_warmup()),
        json(opt_json()),
        v4(opt_v4()),
        v6(opt_v6()),
        source(opt_source()),
        lang(opt_lang()),
        target(positional::<String>("HOST:PORT")),
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
        tcp(long("tcp")
            .short('t')
            .switch()
            .help(t!("help.options.tcp").as_ref())),
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
        wait(long("wait")
            .argument::<f64>("SECS")
            .help(t!("help.options.wait").as_ref())
            .optional()),
        fuzz(long("fuzz").switch().help(t!("help.options.fuzz").as_ref())),
        out(long("out")
            .argument::<String>("FILE.pcap")
            .help(t!("help.options.out").as_ref())
            .optional()),
        summary(long("summary").switch().help(t!("help.options.summary").as_ref())),
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

/// 顶层解析器：8 个子命令平行组合（bpaf 要求子命令是首个 token）。
fn cmd() -> impl Parser<Command> {
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
fn validate_ping(a: &PingArgs) -> Option<String> {
    if let Some(msg) = json_conflicts(a.json, a.pretty, a.graph, a.histogram.is_some()) {
        return Some(msg);
    }
    if a.mtu {
        let mut bad: Vec<&str> = Vec::new();
        if a.udp {
            bad.push("-u");
        }
        if a.size.is_some() {
            bad.push("-l");
        }
        if a.graph {
            bad.push("-g");
        }
        if a.pretty {
            bad.push("-p");
        }
        if a.histogram.is_some() {
            bad.push("-H");
        }
        if a.count.is_some() {
            bad.push("-n");
        }
        if a.interval.is_some() {
            bad.push("-i");
        }
        if a.warmup.is_some() {
            bad.push("-w");
        }
        if a.quiet {
            bad.push("-q");
        }
        if !bad.is_empty() {
            return Some(t!("errors.conflict_mtu_mode", opts = bad.join(" ")).to_string());
        }
    }
    None
}

fn validate_latency(a: &LatencyArgs) -> Option<String> {
    json_conflicts(a.json, a.pretty, a.graph, a.histogram.is_some())
}

fn validate_bandwidth(_a: &BandwidthArgs) -> Option<String> {
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
        let mut err = stderr();
        let _ = writeln_orange(&mut err, render_warning(w));
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
        Err(PrpingError::UdpRequiresPort) => {
            drop(ctrl_echo);
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.udp_requires_port"));
            std::process::exit(1);
        }
        Err(PrpingError::BandwidthRequiresPort) => {
            drop(ctrl_echo);
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.bandwidth_requires_port"));
            std::process::exit(1);
        }
        Err(PrpingError::ConflictV4V6) => {
            drop(ctrl_echo);
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.conflict_v4_v6"));
            std::process::exit(1);
        }
        Err(PrpingError::MtuRequiresNoPort) => {
            drop(ctrl_echo);
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.mtu_requires_no_port"));
            std::process::exit(1);
        }
        Err(PrpingError::TracerouteRequiresNoPort) => {
            drop(ctrl_echo);
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.trace_requires_no_port"));
            std::process::exit(1);
        }
        Err(PrpingError::TcpTraceRequiresPort) => {
            drop(ctrl_echo);
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.tcp_trace_requires_port"));
            std::process::exit(1);
        }
        Err(PrpingError::TraceProtoConflict) => {
            drop(ctrl_echo);
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.trace_udp_tcp_conflict"));
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn run_ping(a: PingArgs) -> anyhow::Result<()> {
    apply_lang(&a.lang);
    if let Some(msg) = validate_ping(&a) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }
    if let Some(msg) = bad_histogram(&a.histogram) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }

    let _ctrl_echo = suppress_ctrl_c_echo(a.json);
    set_pretty(a.pretty);
    set_json(a.json);

    let (host, port) = parse_target(&a.target)?;
    let (cnt, dur) = match a.count.as_deref() {
        Some(s) => parse_count(s)?,
        None => (0, None),
    };
    let cfg = PingConfig {
        host,
        port: port.unwrap_or(0),
        count: cnt,
        duration: dur,
        interval: a.interval.unwrap_or(1.0),
        size: a.size.as_deref().map(parse_size).transpose()?,
        quiet: a.quiet,
        histogram: a.histogram.as_deref().and_then(parse_histogram),
        warmup: a.warmup.unwrap_or(4),
        v4: a.v4,
        v6: a.v6,
        source: a.source.as_deref().map(resolve_source).transpose()?,
        parallel: 1,
        udp: a.udp,
        receive: false,
        bandwidth: false,
        mtu: a.mtu,
        traceroute: false,
        trace_tcp: false,
        trace_udp: false,
        max_hops: DEFAULT_MAX_HOPS,
        no_dns: false,
        graph: a.graph,
    };
    dispatch_run(cfg, _ctrl_echo)
}

fn run_latency(a: LatencyArgs) -> anyhow::Result<()> {
    apply_lang(&a.lang);
    if let Some(msg) = validate_latency(&a) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }
    if let Some(msg) = bad_histogram(&a.histogram) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }

    let _ctrl_echo = suppress_ctrl_c_echo(a.json);
    set_pretty(a.pretty);
    set_json(a.json);

    let (host, port) = parse_target(&a.target)?;
    let port = port.ok_or_else(|| anyhow::anyhow!(t!("errors.latency_requires_port")))?;
    let (cnt, dur) = match a.count.as_deref() {
        Some(s) => parse_count(s)?,
        None => (0, None),
    };
    // 子命令已明确延迟模式：-l 缺省 64（与 psping 默认一致）
    let cfg = PingConfig {
        host,
        port,
        count: cnt,
        duration: dur,
        interval: a.interval.unwrap_or(1.0),
        size: Some(parse_size(a.size.as_deref().unwrap_or("64"))?),
        quiet: a.quiet,
        histogram: a.histogram.as_deref().and_then(parse_histogram),
        warmup: a.warmup.unwrap_or(4),
        v4: a.v4,
        v6: a.v6,
        source: a.source.as_deref().map(resolve_source).transpose()?,
        parallel: 1,
        udp: a.udp,
        receive: a.receive,
        bandwidth: false,
        mtu: false,
        traceroute: false,
        trace_tcp: false,
        trace_udp: false,
        max_hops: DEFAULT_MAX_HOPS,
        no_dns: false,
        graph: a.graph,
    };
    dispatch_run(cfg, _ctrl_echo)
}

fn run_bandwidth(a: BandwidthArgs) -> anyhow::Result<()> {
    apply_lang(&a.lang);
    if let Some(msg) = validate_bandwidth(&a) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }

    let _ctrl_echo = suppress_ctrl_c_echo(a.json);
    set_json(a.json);

    let (host, port) = parse_target(&a.target)?;
    let port = port.ok_or_else(|| anyhow::anyhow!(t!("errors.bandwidth_requires_port")))?;
    let (cnt, dur) = match a.count.as_deref() {
        Some(s) => parse_count(s)?,
        None => (0, None),
    };
    let cfg = PingConfig {
        host,
        port,
        count: cnt,
        duration: dur,
        interval: a.interval.unwrap_or(1.0),
        size: a.size.as_deref().map(parse_size).transpose()?, // None → lib 默认 8192
        quiet: a.quiet,
        histogram: None,
        warmup: a.warmup.unwrap_or(4),
        v4: a.v4,
        v6: a.v6,
        source: a.source.as_deref().map(resolve_source).transpose()?,
        parallel: a.parallel.unwrap_or(1),
        udp: a.udp,
        receive: a.receive,
        bandwidth: true,
        mtu: false,
        traceroute: false,
        trace_tcp: false,
        trace_udp: false,
        max_hops: DEFAULT_MAX_HOPS,
        no_dns: false,
        graph: false,
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
    println!("{}", t!("server.bandwidth_listening", addr = addr));
    // 依赖链由 validate_server 保证（-a 需 -v、--filter 需 -a），
    // 三个标志原样传给 serve，不再隐含开启。
    if a.verbose {
        println!("{}", t!("server.verbose_hint"));
    }
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

fn run_trace(a: TraceArgs) -> anyhow::Result<()> {
    apply_lang(&a.lang);
    let _ctrl_echo = suppress_ctrl_c_echo(a.json);
    set_json(a.json);

    let (host, port) = parse_target(&a.target)?;
    let cfg = PingConfig {
        host,
        port: port.unwrap_or(0),
        count: 0,
        duration: None,
        interval: 1.0,
        size: None,
        quiet: false,
        histogram: None,
        warmup: 4,
        v4: a.v4,
        v6: a.v6,
        source: a.source.as_deref().map(resolve_source).transpose()?,
        parallel: 1,
        udp: false,
        receive: false,
        bandwidth: false,
        mtu: false,
        traceroute: true,
        trace_tcp: a.tcp,
        trace_udp: a.udp,
        max_hops: a.max_hops.unwrap_or(DEFAULT_MAX_HOPS),
        no_dns: a.no_dns,
        graph: false,
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

/// packet 子命令校验：--iface 仅配合 --raw。
fn validate_packet(a: &PacketArgs) -> anyhow::Result<()> {
    if a.iface.is_some() && !a.raw {
        anyhow::bail!(t!("errors.iface_requires_raw"));
    }
    Ok(())
}

/// engine 子命令分发（分析 .pkt / 配方概览 / LSP / --ls / --hex / --pcap）。
fn run_engine(a: EngineArgs) -> anyhow::Result<()> {
    apply_lang(&a.lang);
    validate_engine(&a)?;
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

    let target = match a.target.as_deref() {
        Some(t) => {
            let (host, port) = parse_target(t)?;
            let port = match port {
                Some(p) => p,
                // raw 模式端口无意义（原始 socket 不带端口；链路层帧如 ARP 甚至不需要
                // 目标）——允许裸 HOST，端口按 0 处理
                None if a.raw => 0,
                None => return Err(anyhow::anyhow!(t!("errors.pkg_requires_port"))),
            };
            Some(resolve_target(&host, port)?)
        }
        None => None,
    };
    let opts = prping_core::PkgOptions {
        target,
        mode: if a.raw {
            prping_core::SendMode::Raw {
                iface: a.iface.clone(),
            }
        } else {
            prping_core::SendMode::Payload
        },
        params: parse_params(&a.params)?,
        globals: parse_globals(&a.global)?,
        wait: a.wait,
        fuzz: a.fuzz,
        out: a.out.as_ref().map(std::path::PathBuf::from),
        summary: a.summary,
        libs: resolve_libs(&a.lib),
    };
    let path = resolve_pktl_arg(std::path::Path::new(&a.file))?;
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

/// Auto-detect locale from --lang / env vars / 系统 UI 语言（Windows）。
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
    } else if let Ok(loc) = std::env::var("LANG") {
        let loc = loc.split('.').next().unwrap_or("en-US");
        rust_i18n::set_locale(&normalize_locale(loc));
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
}
/// 预处理裸 `--help-pkg`（不带值）→ `--help-pkg=`（空标题 = 全文）；
/// 顶层 `--help-pkg` 处理（全文分页 / 章节跳转），与子命令解析互斥。
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

fn main() -> anyhow::Result<()> {
    // 多线程 executor：smol 全局 executor 默认单线程，--parallel 并发无法真正并行
    configure_executor_threads();
    detect_locale();
    install_interrupt_handler()?;

    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // 全局 --lang：任意位置提取并移除（子命令必须是首个 token，--lang 在子命令前
    // 时 bpaf 无法消费；detect_locale 已用它设置过一次 locale，这里对显式值再设置）。
    let mut lang = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--lang" {
            if let Some(v) = args.get(i + 1) {
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

/// 库目录列表：默认当前目录 `lib/`（存在时）+ `--lib` 追加的路径。
fn resolve_libs(extra: &[String]) -> Vec<std::path::PathBuf> {
    let mut libs = Vec::new();
    let default = std::path::Path::new("lib");
    if default.is_dir() {
        libs.push(default.to_path_buf());
    }
    for l in extra {
        libs.push(std::path::PathBuf::from(l));
    }
    libs
}

/// 解析 `packet` 子命令目标（DNS 解析）。
fn resolve_target(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    let mut addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .ok()
        .map(|it| it.collect())
        .ok_or_else(|| anyhow::anyhow!(t!("errors.resolve_failed", host = host)))?;
    if addrs.is_empty() {
        anyhow::bail!(t!("errors.resolve_failed", host = host));
    }
    addrs.sort_by_key(|a| u8::from(a.is_ipv6()));
    Ok(addrs[0])
}

/// 解析 `--params k=v,k2=v2`。
fn parse_params(list: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for s in list {
        for pair in s.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!(t!("errors.params_format", value = pair)))?;
            out.push((k.trim().to_string(), v.trim().to_string()));
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
        std::fs::write(dir.join("direct.pktl"), "recipe:\n- pkg: x.pkt\n").unwrap();
        let got = resolve_pktl_arg(&dir.join("direct")).unwrap();
        assert_eq!(got, dir.join("direct.pktl"));

        // 2. 同名文件夹：<arg>.pktl 不存在，<arg>/<basename>.pktl 存在 → 命中
        std::fs::create_dir_all(dir.join("folded")).unwrap();
        std::fs::write(dir.join("folded/folded.pktl"), "recipe:\n- pkg: y.pkt\n").unwrap();
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
