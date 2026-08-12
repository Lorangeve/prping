mod bandwidth;
mod icmp;
mod latency;
mod output;
mod stats;
mod tcp;
mod udp;

rust_i18n::i18n!("locales");

use bpaf::*;
use rust_i18n::t;

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
    let help_icmp = long("help-icmp").switch().help(t!("help.options.help_icmp").as_ref()).hide();
    let help_tcp = long("help-tcp").switch().help(t!("help.options.help_tcp").as_ref()).hide();
    let help_latency = long("help-latency").switch().help(t!("help.options.help_latency").as_ref()).hide();
    let help_bandwidth = long("help-bandwidth").switch().help(t!("help.options.help_bandwidth").as_ref()).hide();

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

    let udp = long("udp").short('u').switch().help(t!("help.options.udp").as_ref());
    let quiet = long("quiet").short('q').switch().help(t!("help.options.quiet").as_ref());
    let histogram = long("histogram").short('H').argument::<String>("N").help(t!("help.options.histogram").as_ref()).optional();
    let warmup = long("warmup").short('w').help(t!("help.options.warmup").as_ref()).argument::<u64>("N").fallback(4);
    let parallel = long("parallel").short('P').help(t!("help.options.parallel").as_ref()).argument::<u32>("N").fallback(1);
    let v4 = short('4').switch().help(t!("help.options.v4").as_ref());
    let v6 = short('6').switch().help(t!("help.options.v6").as_ref());
    let pretty = long("pretty").short('p').switch().help("Use Unicode/Braille histogram rendering");
    let target = positional::<String>("HOST[:PORT]").optional();

    construct!(Command {
        help_icmp, help_tcp, help_latency, help_bandwidth,
        server, bandwidth, count, interval, req_size, lang, udp, quiet, histogram,
        warmup, parallel, v4, v6, pretty, target,
    })
}

/// Parse size string like "64", "8k", "1m" to bytes.
fn parse_size(s: &str) -> anyhow::Result<usize> {
    let s = s.trim().to_lowercase();
    if let Some(n) = s.strip_suffix('k') { return Ok((n.parse::<f64>()? * 1024.0) as usize); }
    if let Some(n) = s.strip_suffix('m') { return Ok((n.parse::<f64>()? * 1024.0 * 1024.0) as usize); }
    Ok(s.parse()?)
}

/// Parse count string like "10" or "10s" to (count, is_duration).
fn parse_count(s: &str) -> anyhow::Result<(u64, Option<f64>)> {
    if let Some(n) = s.strip_suffix('s') {
        return Ok((0, Some(n.parse()?)));
    }
    Ok((s.parse()?, None))
}

/// Parse histogram string to bucket count.
fn parse_histogram(s: &str) -> Option<usize> {
    s.parse().ok()
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
    #[allow(dead_code)]
    lang: Option<String>,
    udp: bool,
    quiet: bool,
    histogram: Option<String>,
    warmup: u64,
    parallel: u32,
    v4: bool,
    v6: bool,
    pretty: bool,
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
    detect_locale();

    let cmd = cmd().run();

    // Mode-specific help (check first)
    if cmd.help_icmp { println!("{}", t!("help.icmp")); return Ok(()); }
    if cmd.help_tcp { println!("{}", t!("help.tcp")); return Ok(()); }
    if cmd.help_latency { println!("{}", t!("help.latency")); return Ok(()); }
    if cmd.help_bandwidth { println!("{}", t!("help.bandwidth")); return Ok(()); }

    // Set pretty mode before any output
    crate::stats::set_pretty(cmd.pretty);

    // No args: show summary (bpaf handles -h/--help with i18n descriptions)
    if cmd.target.is_none() && cmd.server.is_none() && !cmd.help_icmp && !cmd.help_tcp && !cmd.help_latency && !cmd.help_bandwidth {
        print_summary_help();
        return Ok(());
    }

    if let Some(addr) = &cmd.server {
        return smol::block_on(serve_both(addr.clone()));
    }

    let target = cmd.target.as_deref()
        .ok_or_else(|| anyhow::anyhow!(t!("errors.host_port_required")))?;

    let (host, port) = parse_target(target)?;
    let hist = cmd.histogram.as_deref().and_then(parse_histogram);

    if cmd.bandwidth {
        let p = port.ok_or_else(|| anyhow::anyhow!("bandwidth requires HOST:PORT"))?;
        let size = parse_size(cmd.req_size.as_deref().unwrap_or("8192"))?;
        let cnt_str = cmd.count.as_deref().unwrap_or("10000");
        let (cnt, _) = parse_count(cnt_str)?;
        bandwidth::run_client(&host, p, cnt.max(1000), size, cmd.parallel, cmd.udp, hist, cmd.warmup, cmd.v4, cmd.v6)
    } else if cmd.req_size.is_some() {
        let p = port.ok_or_else(|| anyhow::anyhow!("latency requires HOST:PORT"))?;
        let size = parse_size(cmd.req_size.as_deref().unwrap())?;
        let cnt_str = cmd.count.as_deref().unwrap_or("100");
        let (cnt, _) = parse_count(cnt_str)?;
        latency::run_client(&host, p, cnt.max(1), size, cmd.udp, hist, cmd.warmup, cmd.v4, cmd.v6)
    } else if let Some(p) = port {
        let cnt = cmd.count.as_deref().map(|s| s.parse().unwrap_or(0)).unwrap_or(0);
        if cmd.udp {
            udp::ping(&host, p, cnt, cmd.interval, 32, cmd.quiet, hist, cmd.warmup, cmd.v4, cmd.v6)
        } else {
            tcp::ping(&host, p, cnt, cmd.interval, cmd.quiet, hist, cmd.warmup, cmd.v4, cmd.v6)
        }
    } else {
        let cnt = cmd.count.as_deref().map(|s| s.parse().unwrap_or(0)).unwrap_or(0);
        if cmd.udp { anyhow::bail!(t!("errors.udp_requires_port")); }
        icmp::ping(&host, cnt, cmd.interval, 32, cmd.quiet, hist, cmd.warmup, cmd.v4, cmd.v6)
    }
}

/// Summary help: overview + tips + examples (shown when no args).
fn print_summary_help() {
    println!("{}", t!("help.overview"));
    println!();
    println!("{}", t!("help.usage_line"));
    println!();
    println!("{}", t!("help.examples"));
}

/// Server handles both latency and bandwidth client connections.
async fn serve_both(addr: String) -> anyhow::Result<()> {
    use smol::io::{AsyncReadExt, AsyncWriteExt};
    use smol::net::TcpListener;
    let addr: std::net::SocketAddr = addr.parse()
        .map_err(|_| anyhow::anyhow!(t!("errors.invalid_bind", addr = addr)))?;
    println!("{}", t!("server.bandwidth_listening", addr = addr));
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (mut stream, peer) = listener.accept().await?;
        smol::spawn(async move {
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
                        if echo_ok {
                            let echo = smol::future::or(
                                stream.write_all(&buf[..n]),
                                async {
                                    smol::Timer::after(std::time::Duration::from_millis(1)).await;
                                    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, ""))
                                },
                            ).await;
                            if echo.is_err() { echo_ok = false; }
                        }
                    }
                    Err(_) => break,
                }
            }
            let elapsed = start.elapsed().as_secs_f64();
            let ip = peer.ip().to_string();
            let port = peer.port();
            if total > 0 && elapsed > 0.0 {
                let mbits = (total as f64 * 8.0) / (elapsed * 1_000_000.0);
                let size_str = format_bytes(total);
                println!("\x1b[32mrecv\x1b[0m \x1b[36m{ip}:{port}\x1b[0m \x1b[33m{size_str} ({total})\x1b[0m in \x1b[33m{:.2}s\x1b[0m — \x1b[33m{:.2} Mbps\x1b[0m", elapsed, mbits);
            } else {
                println!("\x1b[32mconnect\x1b[0m \x1b[36m{ip}:{port}\x1b[0m \x1b[33m{:.2}ms\x1b[0m", elapsed * 1000.0);
            }
        }).detach();
    }
    #[allow(unreachable_code)]
    Ok(())
}

#[allow(dead_code)]
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") }
    else { format!("{:.2} {}", size, UNITS[unit]) }
}
