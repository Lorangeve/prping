rust_i18n::i18n!("locales");

use bpaf::*;
use prping::{
    OutcomeKind, PingConfig, PrpingError, PrpingWarning, configure_executor_threads,
    parse_histogram, run, serve, set_json, set_pretty, stderr, writeln_orange, writeln_red,
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
    let target = positional::<String>("HOST[:PORT]").optional();

    // 按语义分组，帮助中分组展示（group_help 应用于内层组合）
    let mode = construct!(ModeGroup {
        bandwidth,
        req_size,
        receive,
        udp
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
    let network = construct!(NetworkGroup { v4, v6 }).group_help(t!("help.group.network").as_ref());
    let server_grp =
        construct!(ServerGroup { server }).group_help(t!("help.group.server").as_ref());
    let other = construct!(OtherGroup { version }).group_help(t!("help.group.other").as_ref());

    construct!(Command {
        help_icmp,
        help_tcp,
        help_latency,
        help_bandwidth,
        help_udp,
        help_server,
        mode,
        test,
        output,
        network,
        server_grp,
        other,
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
}

/// 校验互斥参数组合，返回本地化错误文案（None = 通过）。
///
/// `port_present`：目标是否带端口（None = 无目标或目标非法，跳过 `-r` 校验，
/// 交由后续目标解析路径报错）。互斥规则：
///
/// - `-4` 与 `-6` 不能同时使用（地址族矛盾）
/// - `-s`（服务端模式）不能与目标 `HOST[:PORT]` 同时使用
/// - `-s` 不能与任何客户端测试参数同时使用（-b/-l/-u/-r/-n/-i/-H/-w/-P/-q/-p/-g/--json）
/// - `--json` 与 `-p`/`-g`/`-H` 冲突（JSON 输出替代全部人读渲染）
/// - `-r` 仅在与 `-b`（带宽）或 `-l`+端口（延迟）搭配时有效
fn validate(cmd: &Command, port_present: Option<bool>) -> Option<String> {
    if cmd.network.v4 && cmd.network.v6 {
        return Some(t!("errors.conflict_v4_v6").to_string());
    }

    if cmd.server_grp.server.is_some() {
        if cmd.target.is_some() {
            return Some(t!("errors.conflict_server_target").to_string());
        }
        let mut opts: Vec<&str> = Vec::new();
        let m = &cmd.mode;
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
}

/// 服务端组
struct ServerGroup {
    server: Option<String>,
}

/// 其他组
struct OtherGroup {
    version: bool,
}

struct Command {
    help_icmp: bool,
    help_tcp: bool,
    help_latency: bool,
    help_bandwidth: bool,
    help_udp: bool,
    help_server: bool,
    mode: ModeGroup,
    test: TestGroup,
    output: OutputGroup,
    network: NetworkGroup,
    server_grp: ServerGroup,
    other: OtherGroup,
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
fn main() -> anyhow::Result<()> {
    // 多线程 executor：smol 全局 executor 默认单线程，-P 并发无法真正并行
    configure_executor_threads();
    detect_locale();
    install_interrupt_handler()?;

    let cmd = cmd()
        .to_options()
        .usage(t!("help.usage").as_ref())
        .footer(t!("help.mode_guide").as_ref())
        .run();

    // --lang 参数（--help 的本地化已由 detect_locale 预扫描保证）
    if let Some(loc) = &cmd.output.lang {
        rust_i18n::set_locale(&normalize_locale(loc));
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
    let hist = cmd.test.histogram.as_deref().and_then(parse_histogram);

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
        parallel: cmd.test.parallel.unwrap_or(1),
        udp: cmd.mode.udp,
        receive: cmd.mode.receive,
        bandwidth: cmd.mode.bandwidth,
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
                OutcomeKind::Bandwidth(_) => false,
            };
            // 有丢包时以非零退出码结束（脚本友好）
            if has_loss {
                std::process::exit(1);
            }
        }
        Err(PrpingError::UdpRequiresPort) => {
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.udp_requires_port"));
            std::process::exit(1);
        }
        Err(PrpingError::BandwidthRequiresPort) => {
            let mut w = stderr();
            let _ = writeln_red(&mut w, t!("errors.bandwidth_requires_port"));
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
        PrpingWarning::ReceiveIgnoredPing => t!("errors.receive_ignored_ping").to_string(),
        PrpingWarning::UdpSizeClamped { requested, max } => {
            t!("errors.udp_size_clamped", size = requested, max = max).to_string()
        }
    }
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
