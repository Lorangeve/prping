mod bandwidth;
mod icmp;
mod latency;
mod output;
mod stats;
mod tcp;
mod udp;
mod util;

rust_i18n::i18n!("locales");

use bpaf::*;
use rust_i18n::t;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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
fn clamp_udp_size(size: usize, udp: bool) -> usize {
    const MAX_UDP: usize = 65507;
    if udp && size > MAX_UDP {
        eprintln!(
            "{}",
            t!("errors.udp_size_clamped", size = size, max = MAX_UDP)
        );
        return MAX_UDP;
    }
    size
}

#[derive(Debug, Clone)]
struct Command {
    help_icmp: bool,
    help_tcp: bool,
    help_latency: bool,
    help_bandwidth: bool,
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
    json: bool,
    version: bool,
    receive: bool,
    target: Option<String>,
}

/// Auto-detect locale from env vars or --lang arg.
fn detect_locale() {
    // Check raw args for --lang before parser construction (for --help i18n)
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--lang")
        && let Some(loc) = args.get(pos + 1)
    {
        rust_i18n::set_locale(loc);
        return;
    }
    for a in &args {
        if let Some(loc) = a.strip_prefix("--lang=") {
            rust_i18n::set_locale(loc);
            return;
        }
    }
    if let Ok(loc) = std::env::var("RUST_I18N_LOCALE") {
        rust_i18n::set_locale(&loc);
    } else if let Ok(loc) = std::env::var("LANG") {
        let loc = loc.split('.').next().unwrap_or("en").replace('_', "-");
        rust_i18n::set_locale(&loc);
    }
}

fn main() -> anyhow::Result<()> {
    // 多线程 executor：smol 全局 executor 默认单线程，-P 并发无法真正并行
    util::configure_executor_threads();
    detect_locale();
    util::install_interrupt_handler()?;

    let cmd = cmd().run();

    // --lang 参数（--help 的本地化已由 detect_locale 预扫描保证）
    if let Some(loc) = &cmd.lang {
        rust_i18n::set_locale(loc);
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

    // Set output modes before any output
    crate::stats::set_pretty(cmd.pretty);
    crate::stats::set_json(cmd.json);

    // No args: show summary (bpaf handles -h/--help with i18n descriptions)
    if cmd.target.is_none()
        && cmd.server.is_none()
        && !cmd.help_icmp
        && !cmd.help_tcp
        && !cmd.help_latency
        && !cmd.help_bandwidth
    {
        print_summary_help();
        return Ok(());
    }

    if let Some(addr) = &cmd.server {
        return smol::block_on(serve_both(addr.clone()));
    }

    let target = cmd
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!(t!("errors.host_port_required")))?;

    let (host, port) = parse_target(target)?;
    let hist = cmd.histogram.as_deref().and_then(stats::parse_histogram);

    // 次数/时长解析（-n 10 或 -n 10s），非法值直接报错
    let (cnt, dur) = match cmd.count.as_deref() {
        Some(s) => parse_count(s)?,
        None => (0, None),
    };

    // -i 0 快速模式：clamp 到 1ms 下限，避免无意中以最大速率打爆网络
    let interval = if cmd.interval < 0.001 {
        eprintln!("{}", t!("errors.interval_min", value = cmd.interval));
        0.001
    } else {
        cmd.interval
    };

    let mut cfg = util::PingConfig {
        host,
        port: port.unwrap_or(0),
        count: cnt,
        duration: dur,
        interval,
        size: 32,
        quiet: cmd.quiet,
        histogram: hist,
        warmup: cmd.warmup,
        v4: cmd.v4,
        v6: cmd.v6,
        parallel: cmd.parallel,
        udp: cmd.udp,
        receive: cmd.receive,
    };

    let has_loss = if cmd.bandwidth {
        let p = port.ok_or_else(|| anyhow::anyhow!(t!("errors.bandwidth_requires_port")))?;
        cfg.port = p;
        let size = parse_size(cmd.req_size.as_deref().unwrap_or("8192"))?;
        cfg.size = clamp_udp_size(size, cmd.udp);
        // UDP 带宽无并发，-P 静默忽略 → 提示
        if cmd.udp && cmd.parallel > 1 {
            eprintln!("{}", t!("errors.parallel_udp_ignored"));
        }
        bandwidth::run_client(&cfg)?;
        false
    } else if cmd.req_size.is_some()
        && let Some(p) = port
    {
        cfg.port = p;
        let size = parse_size(cmd.req_size.as_deref().unwrap())?;
        cfg.size = clamp_udp_size(size, cmd.udp);
        cfg.count = cnt.max(1);
        latency::run_client(&cfg)?
    } else if let Some(p) = port {
        cfg.port = p;
        // 普通 ping 模式不使用 -r，提示避免误以为生效
        if cmd.receive {
            eprintln!("{}", t!("errors.receive_ignored_ping"));
        }
        if cmd.udp {
            udp::ping(&cfg)?
        } else {
            tcp::ping(&cfg)?
        }
    } else {
        if cmd.udp {
            anyhow::bail!(t!("errors.udp_requires_port"));
        }
        if cmd.receive {
            eprintln!("{}", t!("errors.receive_ignored_ping"));
        }
        // ICMP 负载大小（-l，默认 32）
        let size = cmd
            .req_size
            .as_deref()
            .map(parse_size)
            .transpose()?
            .unwrap_or(32);
        cfg.size = size;
        icmp::ping(&cfg)?
    };

    // 有丢包时以非零退出码结束（脚本友好）
    if has_loss {
        std::process::exit(1);
    }
    Ok(())
}

/// Summary help: overview + tips + examples (shown when no args).
fn print_summary_help() {
    println!("{}", t!("help.overview"));
    println!();
    println!("{}", t!("help.usage_line"));
    println!();
    println!("{}", t!("help.examples"));
}

/// 服务端聚合统计（Ctrl+C 退出时打印）。
struct ServerAgg {
    connections: AtomicU64,
    bytes: AtomicU64,
    micros: AtomicU64,
}

/// 服务端并发 TCP 连接上限。
const MAX_CONNECTIONS: usize = 1024;

/// Server handles both latency and bandwidth client connections (TCP + UDP).
async fn serve_both(addr: String) -> anyhow::Result<()> {
    use smol::io::{AsyncReadExt, AsyncWriteExt};
    use smol::net::TcpListener;
    let addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!(t!("errors.invalid_bind", addr = addr)))?;
    println!("{}", t!("server.bandwidth_listening", addr = addr));
    let listener = TcpListener::bind(addr).await?;
    let agg = Arc::new(ServerAgg {
        connections: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        micros: AtomicU64::new(0),
    });

    // UDP：回显服务 + 接收模式触发协议（大缓冲 socket，避免突发丢包）
    let udp_socket = Arc::new(util::bind_udp(addr)?);
    smol::spawn(async move {
        let mut buf: Vec<std::mem::MaybeUninit<u8>> = vec![std::mem::MaybeUninit::new(0u8); 65536];
        loop {
            let Ok((n, src)) = util::udp_recv(&udp_socket, &mut buf).await else {
                continue;
            };
            let data = util::init_slice(&buf, n);
            // UDP 接收模式触发包：[0xFF, 0xFF, size(2B BE), count(4B BE)]
            if n == 8 && data[0] == 0xFF && data[1] == 0xFF {
                let size = u16::from_be_bytes([data[2], data[3]]) as usize;
                let count = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let sock = udp_socket.clone();
                let payload = vec![0x42u8; size.max(1)];
                smol::spawn(async move {
                    let mut sent = 0u64;
                    while sent < count as u64 {
                        if util::interrupted() {
                            break;
                        }
                        match util::udp_send(&sock, &payload, &src).await {
                            Ok(_) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                // 发送缓冲区满：让出，等客户端排空后重试
                                smol::Timer::after(Duration::from_millis(1)).await;
                                continue;
                            }
                            Err(_) => break, // 端口不可达等致命错误
                        }
                        sent += 1;
                    }
                })
                .detach();
                continue;
            }
            let _ = util::udp_send(&udp_socket, data, &src).await;
        }
    })
    .detach();

    // 并发连接上限：防恶意/失控客户端无限堆任务
    let conn_sem = Arc::new(smol::lock::Semaphore::new(MAX_CONNECTIONS));

    loop {
        if util::interrupted() {
            break;
        }
        // 200ms 轮询 accept，以便及时响应 Ctrl+C
        let accept = smol::future::or(listener.accept(), async {
            smol::Timer::after(Duration::from_millis(200)).await;
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, ""))
        })
        .await;
        let (stream, peer) = match accept {
            Ok(v) => v,
            Err(_) => continue,
        };
        // 超出上限：直接拒绝新连接（信号量配额在任务结束时释放）
        let Some(perm) = conn_sem.clone().try_acquire_arc() else {
            drop(stream);
            continue;
        };
        let agg = agg.clone();

        smol::spawn(async move {
            use std::io::Write as _;
            let _perm = perm;
            let mut stream = stream;
            stream.set_nodelay(true).ok();
            let mut buf = vec![0u8; 65536];
            let mut total: u64 = 0;
            let mut echo_ok = true;
            let start = std::time::Instant::now();
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n as u64;
                        // 接收模式触发（0xFF 单字节）：持续回送数据
                        if n == 1 && buf[0] == 0xFF && total == 1 {
                            let dummy = vec![0u8; 65536];
                            loop {
                                if stream.write_all(&dummy).await.is_err() {
                                    break;
                                }
                            }
                            break;
                        }
                        // 回显：100ms 写超时。带宽测试客户端不回读回显，
                        // 写窗口会迅速打满；超时后停止回显但继续排空数据，避免连接被 RST。
                        if echo_ok {
                            let echo = smol::future::or(stream.write_all(&buf[..n]), async {
                                smol::Timer::after(Duration::from_millis(100)).await;
                                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, ""))
                            })
                            .await;
                            if echo.is_err() {
                                echo_ok = false;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            let elapsed = start.elapsed().as_secs_f64();
            agg.connections.fetch_add(1, Ordering::Relaxed);
            agg.bytes.fetch_add(total, Ordering::Relaxed);
            agg.micros
                .fetch_add((elapsed * 1_000_000.0) as u64, Ordering::Relaxed);

            let ip = peer.ip().to_string();
            let port = peer.port();
            let mut w = output::stdout();
            if total > 0 && elapsed > 0.0 {
                let mbits = (total as f64 * 8.0) / (elapsed * 1_000_000.0);
                let size_str = format_bytes(total);
                let _ = output::print_green(&mut w, t!("server.recv_tag"));
                let _ = output::print_cyan(&mut w, format!("{ip}:{port} "));
                let _ = output::print_yellow(
                    &mut w,
                    format!("{size_str} ({total}) in {elapsed:.2}s — {mbits:.2} Mbps"),
                );
                let _ = writeln!(&mut w);
            } else {
                let _ = output::print_green(&mut w, t!("server.connect_tag"));
                let _ = output::print_cyan(&mut w, format!("{ip}:{port} "));
                let _ = output::print_yellow(&mut w, format!("{:.2}ms", elapsed * 1000.0));
                let _ = writeln!(&mut w);
            }
        })
        .detach();
    }

    // 聚合统计
    let conns = agg.connections.load(Ordering::Relaxed);
    let bytes = agg.bytes.load(Ordering::Relaxed);
    let micros = agg.micros.load(Ordering::Relaxed);
    let secs = micros as f64 / 1_000_000.0;
    let mbps = if secs > 0.0 {
        (bytes as f64 * 8.0) / (secs * 1_000_000.0)
    } else {
        0.0
    };
    println!(
        "{}",
        t!(
            "server.summary",
            conns = conns,
            bytes = bytes,
            secs = format!("{secs:.2}"),
            mbps = format!("{mbps:.2}")
        )
    );
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{:.2} {}", size, UNITS[unit])
    }
}
