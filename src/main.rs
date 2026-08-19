rust_i18n::i18n!("locales");

use bpaf::*;
use prping::{
    OutcomeKind, PingConfig, PrpingError, PrpingWarning, configure_executor_threads, find_sections,
    manual_for, parse_histogram, print_paged, resolve_source, run, serve, set_json, set_pretty,
    stderr, toc, writeln_orange, writeln_red,
};
use rust_i18n::t;
use std::net::SocketAddr;

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

fn cmd() -> impl Parser<Command> {
    let help_icmp = long("help-icmp")
        .switch()
        .help(t!("help.options.help_icmp").as_ref())
        .hide();
    let help_tcp = long("help-tcp")
        .switch()
        .help(t!("help.options.help_tcp").as_ref())
        .hide();
    let help_latency = long("help-latency")
        .switch()
        .help(t!("help.options.help_latency").as_ref())
        .hide();
    let help_bandwidth = long("help-bandwidth")
        .switch()
        .help(t!("help.options.help_bandwidth").as_ref())
        .hide();
    let help_udp = long("help-udp")
        .switch()
        .help(t!("help.options.help_udp").as_ref())
        .hide();
    let help_server = long("help-server")
        .switch()
        .help(t!("help.options.help_server").as_ref())
        .hide();
    let help_pkg = long("help-pkg")
        .argument::<String>("[SECTION]")
        .help(t!("help.options.help_pkg").as_ref())
        .hide()
        .optional();

    let server = long("server")
        .short('s')
        .argument::<String>("ADDR:PORT")
        .help(t!("help.options.server").as_ref())
        .optional();

    let bandwidth = long("bandwidth")
        .short('b')
        .switch()
        .help(t!("help.options.bandwidth").as_ref());

    let count = long("count")
        .short('n')
        .argument::<String>("N|Ns")
        .help(t!("help.options.count").as_ref())
        .optional();

    let interval = long("interval")
        .short('i')
        .argument::<f64>("S")
        .help(t!("help.options.interval").as_ref())
        .optional();

    let req_size = long("size")
        .short('l')
        .argument::<String>("64|8k|1m")
        .help(t!("help.options.size").as_ref())
        .optional();

    let lang = long("lang")
        .argument::<String>("en|zh-CN")
        .help(t!("help.options.lang").as_ref())
        .optional();

    let receive = long("receive")
        .short('r')
        .switch()
        .help(t!("help.options.receive").as_ref());
    let udp = long("udp")
        .short('u')
        .switch()
        .help(t!("help.options.udp").as_ref());
    let mtu = long("mtu")
        .short('M')
        .switch()
        .help(t!("help.options.mtu").as_ref());
    let quiet = long("quiet")
        .short('q')
        .switch()
        .help(t!("help.options.quiet").as_ref());
    let histogram = long("histogram")
        .short('H')
        .argument::<String>("N|t1,t2,...")
        .help(t!("help.options.histogram").as_ref())
        .optional();
    let warmup = long("warmup")
        .short('w')
        .help(t!("help.options.warmup").as_ref())
        .argument::<u64>("N")
        .optional();
    let parallel = long("parallel")
        .short('P')
        .help(t!("help.options.parallel").as_ref())
        .argument::<u32>("N")
        .optional();
    let v4 = short('4').switch().help(t!("help.options.v4").as_ref());
    let v6 = short('6').switch().help(t!("help.options.v6").as_ref());
    let source = long("source")
        .short('I')
        .help(t!("help.options.source").as_ref())
        .argument::<String>("ADDR|IFACE")
        .optional();
    let pretty = long("pretty")
        .short('p')
        .switch()
        .help(t!("help.options.pretty").as_ref());
    let graph = long("graph")
        .short('g')
        .switch()
        .help(t!("help.options.graph").as_ref());
    let json = long("json")
        .flag(true, false)
        .help(t!("help.options.json").as_ref());
    let version = long("version")
        .short('V')
        .flag(true, false)
        .help(t!("help.options.version").as_ref());

    // 引擎 / 包构建组（--eng / --pkg 与常规测试模式互斥）
    let eng = long("eng").switch().help(t!("help.options.eng").as_ref());
    let lsp = long("lsp").switch().help(t!("help.options.lsp").as_ref());
    let pkg = long("pkg")
        .argument::<String>("FILE")
        .help(t!("help.options.pkg").as_ref())
        .optional();
    let raw = long("raw").switch().help(t!("help.options.raw").as_ref());
    let iface = long("iface")
        .argument::<String>("IFACE")
        .help(t!("help.options.iface").as_ref())
        .optional();
    let params = long("params")
        .argument::<String>("k=v,...")
        .help(t!("help.options.params").as_ref())
        .many();
    let wait = long("wait")
        .argument::<f64>("SECS")
        .help(t!("help.options.wait").as_ref())
        .optional();
    let fuzz = long("fuzz").switch().help(t!("help.options.fuzz").as_ref());
    let out = long("out")
        .argument::<String>("FILE.pcap")
        .help(t!("help.options.out").as_ref())
        .optional();
    let ls = long("ls").switch().help(t!("help.options.ls").as_ref());
    let hex = long("hex")
        .argument::<String>("0102...")
        .help(t!("help.options.hex").as_ref())
        .optional();
    let pcap = long("pcap")
        .argument::<String>("FILE.pcap")
        .help(t!("help.options.pcap").as_ref())
        .optional();
    let lib = long("lib")
        .argument::<String>("PATH")
        .help(t!("help.options.lib").as_ref())
        .many();

    // 位置参数：HOST[:PORT]（测量模式）或 FILE.pkt [HOST:PORT]（--pkg）
    let target = positional::<String>("HOST[:PORT]").optional();

    // 按语义分组，帮助中分组展示（group_help 应用于内层组合）
    let mode = construct!(ModeGroup {
        bandwidth,
        req_size,
        receive,
        udp,
        mtu
    })
    .group_help(t!("help.group.mode").as_ref());
    let test = construct!(TestGroup {
        count,
        interval,
        quiet,
        histogram,
        warmup,
        parallel
    })
    .group_help(t!("help.group.test").as_ref());
    let output = construct!(OutputGroup {
        lang,
        pretty,
        graph,
        json
    })
    .group_help(t!("help.group.output").as_ref());
    let network =
        construct!(NetworkGroup { v4, v6, source }).group_help(t!("help.group.network").as_ref());
    let server_grp =
        construct!(ServerGroup { server }).group_help(t!("help.group.server").as_ref());
    let other = construct!(OtherGroup { version }).group_help(t!("help.group.other").as_ref());
    let engine = construct!(EngineGroup {
        eng,
        lsp,
        pkg,
        raw,
        iface,
        params,
        wait,
        fuzz,
        out,
        ls,
        hex,
        pcap,
        lib
    })
    .group_help(t!("help.group.engine").as_ref());

    construct!(Command {
        help_icmp,
        help_tcp,
        help_latency,
        help_bandwidth,
        help_udp,
        help_server,
        help_pkg,
        mode,
        test,
        output,
        network,
        server_grp,
        other,
        engine,
        target,
    })
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

/// UDP 数据报负载上限（IPv4 65507 / IPv6 65527，取保守值），超限时 clamp 并提示。
/// 模式组（自动识别）：-b 带宽 / -l 延迟 / -r 接收 / -u UDP
struct ModeGroup {
    bandwidth: bool,
    req_size: Option<String>,
    receive: bool,
    udp: bool,
    mtu: bool,
}

/// 校验互斥参数组合，返回本地化错误文案（None = 通过）。
///
/// `port_present`：目标是否带端口（None = 无目标或目标非法，跳过 `-r` 校验，
/// 交由后续目标解析路径报错）。互斥规则（CLI 级；config 级不变式在 lib `run`：
/// v4∧v6、UDP/带宽缺端口、`-P` 非带宽警告、`-i` clamp）：
///
/// - `-s`（服务端模式）不能与目标 `HOST[:PORT]` 同时使用
/// - `-s` 不能与任何客户端测试参数同时使用（-b/-l/-u/-r/-n/-i/-H/-w/-P/-q/-p/-g/--json）
/// - `--json` 与 `-p`/`-g`/`-H` 冲突（JSON 输出替代全部人读渲染）
/// - `-r` 仅在与 `-b`（带宽）或 `-l`+端口（延迟）搭配时有效
fn validate(cmd: &Command, port_present: Option<bool>) -> Option<String> {
    if cmd.server_grp.server.is_some() {
        if cmd.target.is_some() {
            return Some(t!("errors.conflict_server_target").to_string());
        }
        let mut opts: Vec<&str> = Vec::new();
        let m = &cmd.mode;
        if m.mtu {
            opts.push("--mtu");
        }
        if m.bandwidth {
            opts.push("-b");
        }
        if m.req_size.is_some() {
            opts.push("-l");
        }
        if m.receive {
            opts.push("-r");
        }
        if m.udp {
            opts.push("-u");
        }
        let g = &cmd.test;
        if g.count.is_some() {
            opts.push("-n");
        }
        if g.interval.is_some() {
            opts.push("-i");
        }
        if g.histogram.is_some() {
            opts.push("-H");
        }
        if g.warmup.is_some() {
            opts.push("-w");
        }
        if g.parallel.is_some() {
            opts.push("-P");
        }
        if g.quiet {
            opts.push("-q");
        }
        let o = &cmd.output;
        if o.pretty {
            opts.push("-p");
        }
        if o.graph {
            opts.push("-g");
        }
        if o.json {
            opts.push("--json");
        }
        if !opts.is_empty() {
            return Some(t!("errors.conflict_server_mode", opts = opts.join(" ")).to_string());
        }
    }

    if cmd.output.json {
        if cmd.output.pretty {
            return Some(t!("errors.conflict_json_pretty").to_string());
        }
        if cmd.output.graph {
            return Some(t!("errors.conflict_json_graph").to_string());
        }
        if cmd.test.histogram.is_some() {
            return Some(t!("errors.conflict_json_histogram").to_string());
        }
    }

    if cmd.mode.receive && !cmd.mode.bandwidth {
        // -r 合法条件：-b（带宽），或 -l 且目标带端口（延迟测试）
        let latency_ok = match port_present {
            Some(true) => cmd.mode.req_size.is_some(),
            Some(false) => false,
            None => true, // 无目标/目标非法：跳过，交给后续路径报错
        };
        if !latency_ok {
            return Some(t!("errors.receive_requires_latency_bandwidth").to_string());
        }
    }

    // --mtu 与其他模式参数互斥（ICMP 基础模式；-4/-6 可用）
    if cmd.mode.mtu {
        let m = &cmd.mode;
        let bad: Vec<&str> = [
            ("bandwidth", m.bandwidth),
            ("req_size", m.req_size.is_some()),
            ("receive", m.receive),
            ("udp", m.udp),
        ]
        .iter()
        .filter(|(_, on)| *on)
        .map(|(n, _)| match *n {
            "bandwidth" => "-b",
            "req_size" => "-l",
            "receive" => "-r",
            _ => "-u",
        })
        .collect();
        if !bad.is_empty() {
            return Some(t!("errors.conflict_mtu_mode", opts = bad.join(" ")).to_string());
        }
        if cmd.test.histogram.is_some() {
            return Some(t!("errors.conflict_mtu_histogram").to_string());
        }
    }

    // 源绑定 -I：与服务端模式互斥；引擎/包模式不接受（无意义）
    if let Some(src) = &cmd.network.source {
        if cmd.server_grp.server.is_some() {
            return Some(t!("errors.conflict_source_server").to_string());
        }
        let _ = src;
    }

    None
}

/// 测试控制组（`-i`/`-w`/`-P` 用 Option 记录是否显式给出，供互斥校验使用；
/// 缺省值在构造 `PingConfig` 时补全）。
struct TestGroup {
    count: Option<String>,
    interval: Option<f64>,
    quiet: bool,
    histogram: Option<String>,
    warmup: Option<u64>,
    parallel: Option<u32>,
}

/// 输出组
struct OutputGroup {
    lang: Option<String>,
    pretty: bool,
    graph: bool,
    json: bool,
}

/// 网络组
struct NetworkGroup {
    v4: bool,
    v6: bool,
    source: Option<String>,
}

/// 服务端组
struct ServerGroup {
    server: Option<String>,
}

/// 其他组
struct OtherGroup {
    version: bool,
}

/// 引擎 / 包构建组（--eng / --pkg：packet-dsl 的宿主 CLI）。
struct EngineGroup {
    eng: bool,
    lsp: bool,
    pkg: Option<String>,
    raw: bool,
    iface: Option<String>,
    params: Vec<String>,
    wait: Option<f64>,
    fuzz: bool,
    out: Option<String>,
    ls: bool,
    hex: Option<String>,
    pcap: Option<String>,
    lib: Vec<String>,
}

struct Command {
    help_icmp: bool,
    help_tcp: bool,
    help_latency: bool,
    help_bandwidth: bool,
    help_udp: bool,
    help_server: bool,
    help_pkg: Option<String>,
    mode: ModeGroup,
    test: TestGroup,
    output: OutputGroup,
    network: NetworkGroup,
    server_grp: ServerGroup,
    other: OtherGroup,
    engine: EngineGroup,
    target: Option<String>,
}

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
/// 带值（`--help-pkg 安装` 或 `--help-pkg=安装`）原样保留。
/// 返回的列表不含 argv[0]（与 bpaf `Args::current_args` 一致）。
fn normalize_help_pkg_args() -> Vec<String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut out = Vec::with_capacity(raw.len());
    let mut it = raw.iter().peekable();
    while let Some(a) = it.next() {
        if a == "--help-pkg" {
            let next_is_value = it.peek().map(|n| !n.starts_with('-')).unwrap_or(false);
            if next_is_value {
                out.push(a.clone());
            } else {
                out.push("--help-pkg=".to_string());
            }
        } else {
            out.push(a.clone());
        }
    }
    out
}

fn main() -> anyhow::Result<()> {
    // 多线程 executor：smol 全局 executor 默认单线程，-P 并发无法真正并行
    configure_executor_threads();
    detect_locale();
    install_interrupt_handler()?;

    let args = normalize_help_pkg_args();
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

    // --lang 参数（--help 的本地化已由 detect_locale 预扫描保证）
    if let Some(loc) = &cmd.output.lang {
        rust_i18n::set_locale(&normalize_locale(loc));
    }

    // 引擎 / 包构建模式（--eng / --pkg / --ls / --hex / --pcap）
    let engine_used = cmd.engine.eng
        || cmd.engine.pkg.is_some()
        || cmd.engine.ls
        || cmd.engine.hex.is_some()
        || cmd.engine.pcap.is_some();
    if engine_used {
        return run_engine(&cmd);
    }

    if cmd.other.version {
        println!("prping {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Mode-specific help (check first)
    if cmd.help_icmp {
        println!("{}", t!("help.icmp"));
        return Ok(());
    }
    if cmd.help_tcp {
        println!("{}", t!("help.tcp"));
        return Ok(());
    }
    if cmd.help_latency {
        println!("{}", t!("help.latency"));
        return Ok(());
    }
    if cmd.help_bandwidth {
        println!("{}", t!("help.bandwidth"));
        return Ok(());
    }
    if cmd.help_udp {
        println!("{}", t!("help.udp"));
        return Ok(());
    }
    if cmd.help_server {
        println!("{}", t!("help.server"));
        return Ok(());
    }

    // 使用手册（--help-pkg [SECTION]）：全文分页 / 章节跳转
    if let Some(section) = &cmd.help_pkg {
        let manual = manual_for(&rust_i18n::locale());
        match section.as_str() {
            "" => {
                // 全文：tty 时 pager 自动分页
                print_paged(manual)?;
                return Ok(());
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
                        println!("{}", hits[0].body);
                        return Ok(());
                    }
                    n => {
                        println!("{}", t!("errors.help_pkg_ambiguous", count = n));
                        for h in &hits {
                            println!("  {}. {}", h.number, h.title);
                        }
                        return Ok(());
                    }
                }
            }
        }
    }

    // 互斥参数校验：-r 的合法性依赖目标端口，先轻量解析（失败则跳过该项检查）
    let port_present = cmd
        .target
        .as_deref()
        .and_then(|t| parse_target(t).ok())
        .map(|(_, p)| p.is_some());
    if let Some(msg) = validate(&cmd, port_present) {
        let mut w = stderr();
        let _ = writeln_red(&mut w, format!("Error: {msg}"));
        std::process::exit(1);
    }

    // 非法 -H 参数直接报错（与 -n abc 一致；parse_histogram 对非法值返回 None）
    let hist = cmd.test.histogram.as_deref().and_then(parse_histogram);
    if cmd.test.histogram.is_some() && hist.is_none() {
        let mut w = stderr();
        let _ = writeln_red(
            &mut w,
            format!(
                "Error: {}",
                t!(
                    "errors.invalid_histogram",
                    value = cmd.test.histogram.as_deref().unwrap_or("")
                )
            ),
        );
        std::process::exit(1);
    }

    // --json 模式：隐藏终端回显的 ^C（Unix 且 stdin 为 tty 时；Drop 时恢复原设置）。
    // ^C 是终端行规程回显、从不进入 stdout 管道，这里只做显示层清理。
    let _ctrl_echo = suppress_ctrl_c_echo(cmd.output.json);

    // Set output modes before any output
    set_pretty(cmd.output.pretty);
    set_json(cmd.output.json);

    // No args: show summary (bpaf handles -h/--help with i18n descriptions)
    if cmd.target.is_none()
        && cmd.server_grp.server.is_none()
        && !cmd.help_icmp
        && !cmd.help_tcp
        && !cmd.help_latency
        && !cmd.help_bandwidth
        && !cmd.help_udp
        && !cmd.help_server
    {
        print_summary_help();
        return Ok(());
    }

    if let Some(addr) = &cmd.server_grp.server {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|_| anyhow::anyhow!(t!("errors.invalid_bind", addr = addr.as_str())))?;
        println!("{}", t!("server.bandwidth_listening", addr = addr));
        let report = smol::block_on(serve(addr))?;
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
        return Ok(());
    }

    let target = cmd
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!(t!("errors.host_port_required")))?;

    let (host, port) = parse_target(target)?;

    // 次数/时长解析（-n 10 或 -n 10s），非法值直接报错
    let (cnt, dur) = match cmd.test.count.as_deref() {
        Some(s) => parse_count(s)?,
        None => (0, None),
    };

    let cfg = PingConfig {
        host,
        port: port.unwrap_or(0),
        count: cnt,
        duration: dur,
        interval: cmd.test.interval.unwrap_or(1.0),
        size: cmd.mode.req_size.as_deref().map(parse_size).transpose()?,
        quiet: cmd.test.quiet,
        histogram: hist,
        warmup: cmd.test.warmup.unwrap_or(4),
        v4: cmd.network.v4,
        v6: cmd.network.v6,
        source: cmd
            .network
            .source
            .as_deref()
            .map(resolve_source)
            .transpose()?,
        parallel: cmd.test.parallel.unwrap_or(1),
        udp: cmd.mode.udp,
        receive: cmd.mode.receive,
        bandwidth: cmd.mode.bandwidth,
        mtu: cmd.mode.mtu,
        graph: cmd.output.graph,
    };

    // 统一入口：模式识别、clamp、忽略提示都在 lib 的 run() 内
    // 警告（clamp/忽略）以橙色输出
    match run(&cfg, |w| {
        let mut err = stderr();
        let _ = writeln_orange(&mut err, render_warning(w));
    }) {
        Ok(kind) => {
            let has_loss = match &kind {
                OutcomeKind::Ping(stats) => stats.has_loss(),
                OutcomeKind::Bandwidth(_) | OutcomeKind::Mtu(_) => false,
            };
            // 有丢包时以非零退出码结束（脚本友好）
            if has_loss {
                drop(_ctrl_echo); // 先恢复终端设置再退出（process::exit 不跑析构）
                std::process::exit(1);
            }
        }
        Err(PrpingError::UdpRequiresPort) => {
            drop(_ctrl_echo);
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.udp_requires_port"));
            std::process::exit(1);
        }
        Err(PrpingError::BandwidthRequiresPort) => {
            drop(_ctrl_echo);
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.bandwidth_requires_port"));
            std::process::exit(1);
        }
        Err(PrpingError::ConflictV4V6) => {
            drop(_ctrl_echo);
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.conflict_v4_v6"));
            std::process::exit(1);
        }
        Err(PrpingError::MtuRequiresNoPort) => {
            drop(_ctrl_echo);
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.mtu_requires_no_port"));
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
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

// ── 引擎 / 包构建模式（--eng / --pkg / --ls / --hex / --pcap）────────────────

/// 引擎互斥校验（与测量参数无关，只在引擎模式启用时调用）。
fn validate_engine(cmd: &Command) -> anyhow::Result<()> {
    let e = &cmd.engine;
    if e.eng && e.pkg.is_some() {
        anyhow::bail!(t!("errors.conflict_eng_pkg"));
    }
    if e.lsp && !e.eng {
        anyhow::bail!(t!("errors.lsp_requires_eng"));
    }
    if e.raw && e.pkg.is_none() {
        anyhow::bail!(t!("errors.raw_requires_pkg"));
    }
    if e.iface.is_some() && !(e.pkg.is_some() && e.raw) {
        anyhow::bail!(t!("errors.iface_requires_raw"));
    }
    if !e.params.is_empty() && !e.eng && e.pkg.is_none() {
        anyhow::bail!(t!("errors.params_requires_eng_pkg"));
    }
    if e.wait.is_some() && e.pkg.is_none() {
        anyhow::bail!(t!("errors.wait_requires_pkg"));
    }
    if e.fuzz && e.pkg.is_none() {
        anyhow::bail!(t!("errors.fuzz_requires_pkg"));
    }
    if e.out.is_some() && e.pkg.is_none() {
        anyhow::bail!(t!("errors.out_requires_pkg"));
    }
    if !e.lib.is_empty() && !e.eng && e.pkg.is_none() {
        anyhow::bail!(t!("errors.lib_requires_eng_pkg"));
    }
    let eng_sub = e.ls || e.hex.is_some() || e.pcap.is_some();
    if (e.ls as u8 + e.hex.is_some() as u8 + e.pcap.is_some() as u8) > 1 {
        anyhow::bail!(t!("errors.eng_sub_conflict"));
    }
    if eng_sub && !e.eng {
        anyhow::bail!(t!("errors.eng_sub_requires_eng"));
    }
    if eng_sub && e.lsp {
        anyhow::bail!(t!("errors.eng_sub_conflict_lsp"));
    }
    if eng_sub && cmd.target.is_some() {
        anyhow::bail!(t!("errors.eng_sub_no_file"));
    }
    if e.eng && e.lsp && cmd.target.is_some() {
        anyhow::bail!(t!("errors.eng_lsp_no_file"));
    }
    // -I 与引擎模式冲突（引擎/包模式不接受源绑定）
    if cmd.network.source.is_some() {
        anyhow::bail!(t!("errors.conflict_source_engine"));
    }
    Ok(())
}

/// 引擎 / 包构建模式分发（--eng 分析/LSP/--ls/--hex/--pcap；--pkg 构建发送）。
fn run_engine(cmd: &Command) -> anyhow::Result<()> {
    validate_engine(cmd)?;
    let e = &cmd.engine;

    // 引擎模式（--eng）：.pkt 分析（精美输出）或 LSP 服务器
    if e.eng {
        if e.lsp {
            return prping::run_lsp(&resolve_libs(&e.lib));
        }
        if e.ls {
            return prping::ls_builtins(&resolve_libs(&e.lib));
        }
        if let Some(hex) = &e.hex {
            return prping::decode_hex(hex);
        }
        if let Some(pcap) = &e.pcap {
            return prping::decode_pcap(std::path::Path::new(pcap));
        }
        let file = cmd
            .target
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!(t!("errors.eng_requires_file")))?;
        let params = parse_params(&e.params)?;
        return prping::analyze_file(std::path::Path::new(file), &params, &resolve_libs(&e.lib));
    }

    // 包发送（--pkg FILE [HOST:PORT]；目标省略时逐包从包内推导）
    if let Some(file) = &e.pkg {
        let target = match cmd.target.as_deref() {
            Some(t) => {
                let (host, port) = parse_target(t)?;
                let port = port.ok_or_else(|| anyhow::anyhow!(t!("errors.pkg_requires_port")))?;
                Some(resolve_target(&host, port)?)
            }
            None => None,
        };
        let opts = prping::PkgOptions {
            target,
            mode: if e.raw {
                prping::SendMode::Raw {
                    iface: e.iface.clone(),
                }
            } else {
                prping::SendMode::Payload
            },
            params: parse_params(&e.params)?,
            wait: e.wait,
            fuzz: e.fuzz,
            out: e.out.as_ref().map(std::path::PathBuf::from),
            libs: resolve_libs(&e.lib),
        };
        return prping::send_packets(std::path::Path::new(file), &opts);
    }

    // 没有 --eng / --pkg / 子模式：打印用法并报错
    let mut w = stderr();
    let _ = writeln_orange(&mut w, t!("errors.engine_mode_required"));
    let _ = writeln_red(
        &mut w,
        "--eng FILE.pkt | --eng --lsp | --pkg FILE.pkt [HOST:PORT]",
    );
    std::process::exit(2);
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

/// 解析 `--pkg` 目标（DNS 解析）。
fn resolve_target(host: &str, port: u16) -> anyhow::Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    let mut addrs: Vec<std::net::SocketAddr> = (host, port)
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
            prping::set_interrupted(true);
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
            prping::set_interrupted(true);
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
