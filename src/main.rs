rust_i18n::i18n!("locales");

use bpaf::*;
use prping::{
    OutcomeKind, PingConfig, PrpingError, PrpingWarning, configure_executor_threads,
    parse_histogram, run, serve, set_json, set_pretty,
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
        .fallback(1.0);

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
        .help("Receive from server instead of sending");
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
        .fallback(4);
    let parallel = long("parallel")
        .short('P')
        .help(t!("help.options.parallel").as_ref())
        .argument::<u32>("N")
        .fallback(1);
    let v4 = short('4').switch().help(t!("help.options.v4").as_ref());
    let v6 = short('6').switch().help(t!("help.options.v6").as_ref());
    let pretty = long("pretty")
        .short('p')
        .switch()
        .help("Use Unicode/Braille histogram rendering");
    let graph = long("graph")
        .short('g')
        .switch()
        .help("Print latency timeline graph (with -p: ploot rendering)");
    let json = long("json")
        .flag(true, false)
        .help(t!("help.options.json").as_ref());
    let version = long("version")
        .short('V')
        .flag(true, false)
        .help("Show version");
    let target = positional::<String>("HOST[:PORT]").optional();

    construct!(Command {
        help_icmp,
        help_tcp,
        help_latency,
        help_bandwidth,
        help_udp,
        help_server,
        server,
        bandwidth,
        count,
        interval,
        req_size,
        lang,
        receive,
        udp,
        quiet,
        histogram,
        warmup,
        parallel,
        v4,
        v6,
        pretty,
        graph,
        json,
        version,
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
struct Command {
    help_icmp: bool,
    help_tcp: bool,
    help_latency: bool,
    help_bandwidth: bool,
    help_udp: bool,
    help_server: bool,
    server: Option<String>,
    bandwidth: bool,
    count: Option<String>,
    interval: f64,
    req_size: Option<String>,
    lang: Option<String>,
    udp: bool,
    quiet: bool,
    histogram: Option<String>,
    warmup: u64,
    parallel: u32,
    v4: bool,
    v6: bool,
    pretty: bool,
    graph: bool,
    json: bool,
    version: bool,
    receive: bool,
    target: Option<String>,
}

/// 把 BCP-47 语言标识（en-US / zh-CN / en_US / zh）规范化到 rust-i18n 实际 locale。
///
/// locales 目录只有 `en.yml` 与 `zh-CN.yml`，所有输入统一映射：
/// 中文系 → `zh-CN`，其余（含 en-US/en/en_GB...）→ `en`。
fn normalize_locale(s: &str) -> String {
    let s = s.trim().to_lowercase().replace('_', "-");
    if s.starts_with("zh") {
        "zh-CN".to_string()
    } else {
        "en".to_string()
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
        let loc = loc.split('.').next().unwrap_or("en");
        rust_i18n::set_locale(&normalize_locale(loc));
    } else {
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

    let cmd = cmd().run();

    // --lang 参数（--help 的本地化已由 detect_locale 预扫描保证）
    if let Some(loc) = &cmd.lang {
        rust_i18n::set_locale(&normalize_locale(loc));
    }

    if cmd.version {
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

    // Set output modes before any output
    set_pretty(cmd.pretty);
    set_json(cmd.json);

    // No args: show summary (bpaf handles -h/--help with i18n descriptions)
    if cmd.target.is_none()
        && cmd.server.is_none()
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

    if let Some(addr) = &cmd.server {
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
    let hist = cmd.histogram.as_deref().and_then(parse_histogram);

    // 次数/时长解析（-n 10 或 -n 10s），非法值直接报错
    let (cnt, dur) = match cmd.count.as_deref() {
        Some(s) => parse_count(s)?,
        None => (0, None),
    };

    let cfg = PingConfig {
        host,
        port: port.unwrap_or(0),
        count: cnt,
        duration: dur,
        interval: cmd.interval,
        size: cmd.req_size.as_deref().map(parse_size).transpose()?,
        quiet: cmd.quiet,
        histogram: hist,
        warmup: cmd.warmup,
        v4: cmd.v4,
        v6: cmd.v6,
        parallel: cmd.parallel,
        udp: cmd.udp,
        receive: cmd.receive,
        bandwidth: cmd.bandwidth,
        graph: cmd.graph,
    };

    // 统一入口：模式识别、clamp、忽略提示都在 lib 的 run() 内
    match run(&cfg, |w| eprintln!("{}", render_warning(w))) {
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
            eprintln!("{}", t!("errors.udp_requires_port"));
            std::process::exit(1);
        }
        Err(PrpingError::BandwidthRequiresPort) => {
            eprintln!("{}", t!("errors.bandwidth_requires_port"));
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
