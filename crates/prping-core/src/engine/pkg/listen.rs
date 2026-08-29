//! 持续监听（裸 `--wait`，即原 `--listen`）：pktlang 对话的服务端。
//!
//! 绑定 UDP 地址，持续接收数据报；每个数据报反解后按 .pkt 的 `sniffer:` 规则
//! 匹配——命中则**回显**给发送方并打印匹配详情（字段=值 + 反解展示），未命中
//! 忽略。与客户端的 `packet --wait`（发送 + 按同一规则匹配应答）配对，即可让
//! 两个进程用 export + sniffer 模拟通信（见 `examples/sniffer_chat/`）。
//!
//! - 监听地址：CLI `HOST:PORT` 或按包内最外层 udp/tcp `dport` 推导
//!   （IPv6 包 → `[::]:port`，否则 `0.0.0.0:port`）。
//! - 匹配规则构建用 `allow_sent: false`：监听没有发包可引用，`id=id` 这类裸
//!   Ident 发包字段引用在构建期直接报错（监听规则请用字面量/`and`/`or`/`not`/
//!   字节谓词）。
//! - 回显 = 把收到的数据报原样送回发送方（字节保真，客户端的 sniffer 可按
//!   `id=id` 等引用发包字段匹配回显）。
//! - Ctrl+C 优雅退出（读超时轮询中断标志），结束时打印匹配统计。

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::Duration;

use packet_dsl::ir::{Layer, PacketSpec};
use rust_i18n::t;
use termcolor::{ColorChoice, StandardStream};

use super::PkgOptions;
use crate::output::{indent, print_cyan, print_dim, print_green, print_magenta, writeln_red};

/// 监听入口：绑定 `opts.target`（或包内 dport 推导的地址），循环接收/匹配/回显。
///
/// **发送段先行**（"只要包含发送段就会发送"）：文件有可发送的导出（普通包定义；
/// 含 `reply()` 叶子的应答模板只在监听上下文可求值 → 不可发送，跳过）就先发送
/// 一遍，再进入持续监听。
pub fn listen_packets(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    crate::engine::eng::ensure_dns_resolver();
    crate::engine::eng::ensure_proto_registry();
    let module =
        packet_dsl::parse_file_with_libs(file, &opts.libs).map_err(|d| anyhow::anyhow!("{d}"))?;
    let params: packet_dsl::Params = opts.params.iter().cloned().collect();
    let spec = module
        .sniffer
        .clone()
        .ok_or_else(|| anyhow::anyhow!("{}", t!("engine.listen_requires_sniffer")))?;
    // allow_sent=false：监听没有发包可引用（裸 Ident 引用发包字段 → 构建期报错）
    let matcher = packet_dsl::Matcher::build(&spec, Some(&module), &params, &opts.globals, false)
        .map_err(|d| anyhow::anyhow!("{d}"))?;
    // 发送段先行（"只要包含发送段就会发送"）：文件有可发送的导出（普通包定义；
    // 含 `reply()` 叶子的应答模板只在监听上下文可求值 → 不可发送，跳过）先发送，
    // 再进入持续监听
    if packet_dsl::resolve_sources_with_globals(&module, &params, &opts.globals)
        .is_ok_and(|s| s.iter().any(|(_, ps)| !ps.is_empty()))
    {
        // OneShot(0)：纯发送不读回显（wait 0 = 立即超时），避免绑定前阻塞 1s
        let send_opts = PkgOptions {
            wait: super::WaitMode::OneShot(0.0),
            ..opts.clone()
        };
        if let Err(e) = super::send::send_packets(file, &send_opts) {
            // 发送段先行失败：降级为警告并继续监听——纯监听场景（等待对端发包）
            // 不应被「本机暂无可发送对端」阻断（send_packets 内部已打印具体红字错误）。
            let mut w = crate::output::stderr();
            let _ = crate::output::writeln_orange(
                &mut w,
                rust_i18n::t!("engine.listen_send_phase_failed", error = e.to_string()),
            );
        }
    }
    let addr = listen_addr(&module, &params, &opts.globals, opts)?;
    let sock = UdpSocket::bind(addr)
        .map_err(|e| anyhow::anyhow!(t!("engine.listen_bind_fail", addr = addr, err = e)))?;
    // 读超时轮询 Ctrl+C：200ms 内无数据报 → 检查中断标志后继续
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;

    let mut w = StandardStream::stdout(ColorChoice::Auto);
    print_magenta(&mut w, "prping packet --wait (listen mode)")?;
    writeln!(&mut w)?;
    print_cyan(&mut w, t!("engine.listen_binding", addr = addr))?;
    writeln!(&mut w)?;

    let mut buf = [0u8; 65535];
    let mut total = 0usize;
    let mut matched = 0usize;
    loop {
        if crate::util::interrupted() {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                total += 1;
                let data = buf[..n].to_vec();
                match matcher.matches(&data, None) {
                    Some(fields) => {
                        matched += 1;
                        // 回显：原样送回发送方
                        if let Err(e) = sock.send_to(&data, peer) {
                            writeln_red(
                                &mut w,
                                format!(
                                    "{}✗ {}",
                                    indent(1),
                                    t!("engine.listen_echo_fail", peer = peer, err = e)
                                ),
                            )?;
                        } else {
                            print_green(
                                &mut w,
                                t!("engine.listen_matched", bytes = data.len(), peer = peer),
                            )?;
                            writeln!(&mut w)?;
                            if !opts.summary {
                                if !fields.is_empty() {
                                    let pairs: Vec<String> =
                                        fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
                                    print_green(
                                        &mut w,
                                        format!("{}{}", indent(1), pairs.join(" ")),
                                    )?;
                                    writeln!(&mut w)?;
                                }
                                let report = packet_dsl::dissect(&data);
                                crate::engine::eng::render_dissected(
                                    &mut w,
                                    &report,
                                    "  datagram:",
                                    &data,
                                )?;
                            }
                        }
                    }
                    None => {
                        // 未命中：忽略（摘要模式静默）
                        if !opts.summary {
                            print_dim(
                                &mut w,
                                t!("engine.listen_ignored", bytes = data.len(), peer = peer),
                            )?;
                            writeln!(&mut w)?;
                        }
                    }
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    print_cyan(
        &mut w,
        t!("engine.listen_done", matched = matched, total = total),
    )?;
    writeln!(&mut w)?;
    Ok(())
}

/// UDP 监听命中：匹配数据报字节 + sniffer 命中字段 + 对端地址。
pub(crate) type UdpListenHit = (Vec<u8>, Vec<(String, String)>, SocketAddr);

/// 配方 `wait:` 无值（持续监听）步骤（UDP）：绑定地址监听数据报，sniffer 匹配
/// **第一个命中**即返回（不做回显——命中后由配方后续步骤发包）。返回
/// (匹配字节, 命中字段, 对端)；`None` = Ctrl+C 中断。
pub(crate) fn listen_udp_once(
    module: &packet_dsl::Module,
    params: &packet_dsl::Params,
    globals: &packet_dsl::Globals,
    matcher: &packet_dsl::Matcher,
    opts: &PkgOptions,
    timeout: Option<Duration>,
) -> anyhow::Result<Option<UdpListenHit>> {
    let addr = listen_addr(module, params, globals, opts)?;
    let sock = UdpSocket::bind(addr)
        .map_err(|e| anyhow::anyhow!(t!("engine.listen_bind_fail", addr = addr, err = e)))?;
    // 读超时轮询 Ctrl+C / 限时：200ms 内无数据报 → 检查中断与 deadline 后继续
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;
    let deadline = timeout.map(|d| std::time::Instant::now() + d);
    let mut buf = [0u8; 65535];
    loop {
        if crate::util::interrupted() || deadline.is_some_and(|dl| std::time::Instant::now() >= dl)
        {
            return Ok(None);
        }
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let data = buf[..n].to_vec();
                if let Some(fields) = matcher.matches(&data, None) {
                    return Ok(Some((data, fields, peer)));
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// 监听地址：CLI 显式 HOST:PORT 优先；否则按包内最外层 udp/tcp dport 推导
/// （IPv6 包 → `[::]:port`，其余 → `0.0.0.0:port`）。配方监听简报也用。
pub(crate) fn listen_addr(
    module: &packet_dsl::Module,
    params: &packet_dsl::Params,
    globals: &packet_dsl::Globals,
    opts: &PkgOptions,
) -> anyhow::Result<SocketAddr> {
    if let Some(t) = opts.target {
        return Ok(t);
    }
    let sources = packet_dsl::resolve_sources_with_globals(module, params, globals)
        .map_err(|d| anyhow::anyhow!("{d}"))?;
    let pkts: Vec<&PacketSpec> = sources.iter().flat_map(|(_, ps)| ps).collect();
    if pkts.is_empty() {
        anyhow::bail!("{}", t!("engine.err_no_packets"));
    }
    // 收集全部导出包的 dst 端口：多个不同端口时单 socket 无法同时监听，
    // 明确报错提示显式指定 HOST:PORT（而不是静默只监听第一个包的端口）。
    let mut ports: Vec<u16> = Vec::new();
    for pkt in &pkts {
        if let Some(port) = pkt.layers.iter().rev().find_map(|l| match l {
            Layer::Udp(f) => f.dst_port,
            Layer::Tcp(f) => f.dst_port,
            _ => None,
        }) && !ports.contains(&port)
        {
            ports.push(port);
        }
    }
    if ports.is_empty() {
        anyhow::bail!("{}", t!("engine.listen_no_port"));
    }
    if ports.len() > 1 {
        let list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        anyhow::bail!(
            "{}",
            t!("engine.listen_multi_dport", ports = list.join(", "))
        );
    }
    let port = ports[0];
    let has_v6 = pkts
        .iter()
        .any(|pkt| pkt.layers.iter().any(|l| matches!(l, Layer::Ipv6(_))));
    let ip: IpAddr = if has_v6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    Ok(SocketAddr::new(ip, port))
}
