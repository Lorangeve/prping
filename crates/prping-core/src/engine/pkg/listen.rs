//! 持续监听（裸 `--wait`，即原 `--listen`）：纯监听（匹配 + 报告 + 统计）。
//!
//! 绑定 UDP 地址，持续接收数据报；每个数据报反解后按 .pkt 的 `sniffer:` 规则
//! 匹配——命中打印匹配详情（字段=值 + 反解展示），未命中忽略，**不发包回应**
//! （回应包的构造属编排，由 .pktl 配方的 `wait:` 无值步骤 + extract + 后续
//! 发包步骤完成，见 `examples/sniffer_chat/`、`examples/dns_trigger/`）。
//!
//! - 监听地址：CLI `HOST:PORT` 或按包内最外层 udp/tcp `dport` 推导
//!   （IPv6 包 → `[::]:port`，否则 `0.0.0.0:port`）。
//! - 匹配规则构建用 `allow_sent: false`：监听没有发包可引用，`id=id` 这类裸
//!   Ident 发包字段引用在构建期直接报错（监听规则请用字面量/`and`/`or`/`not`/
//!   字节谓词）。
//! - **发送段先行**：文件有可发送的导出先发送一遍再进入监听（发请求触发对端）。
//! - Ctrl+C 优雅退出（读超时轮询中断标志），结束时打印匹配统计。

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::Duration;

use packet_dsl::ir::{Layer, PacketSpec};
use rust_i18n::t;
use termcolor::{ColorChoice, StandardStream};

use super::PkgOptions;
use crate::output::{indent, print_cyan, print_dim, print_green, print_magenta};

/// 监听入口：绑定 `opts.target`（或包内 dport 推导的地址），循环接收/匹配/报告。
///
/// **发送段先行**（"只要包含发送段就会发送"）：文件有可发送的导出（普通包定义；
/// 含 `reply()` 叶子的包求值失败 → 无可发送包，跳过）就先发送一遍，再进入持续监听。
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
    // 含 reply() 叶子的包求值失败 → 无可发送包，跳过）先发送，再进入持续监听
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
                        // 纯监听：命中只打印匹配详情（不发包回应——回应由 .pktl 配方编排）
                        print_green(
                            &mut w,
                            t!("engine.listen_matched", bytes = data.len(), peer = peer),
                        )?;
                        writeln!(&mut w)?;
                        if !opts.summary {
                            if !fields.is_empty() {
                                let pairs: Vec<String> =
                                    fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
                                print_green(&mut w, format!("{}{}", indent(1), pairs.join(" ")))?;
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

/// 配方监听步骤（UDP）的单次收包结果。
pub(crate) enum UdpListen {
    /// sniffer 命中：匹配字节 + 命中字段 + 对端；`until_matched` = 该包同时满足
    /// loop 块的 `until:` 谓词（本轮结束后循环收工）。
    Hit {
        data: Vec<u8>,
        fields: Vec<(String, String)>,
        peer: SocketAddr,
        until_matched: bool,
    },
    /// `until:` 命中但 sniffer 未命中：循环立即收工（非本步命中，不 extract/不回应）。
    Until,
}

/// 配方 `wait:` 无值（持续监听）步骤（UDP）：绑定地址监听数据报，sniffer 匹配
/// **第一个命中**即返回（不发包——命中后由配方 extract 取值、后续步骤回应）。返回
/// [`UdpListen`]；`None` = Ctrl+C 中断。`until` 非 None 时（loop 块上下文）额外
/// 检查每包：sniffer 命中时附带 `until_matched`；仅 until 命中 → [`UdpListen::Until`]。
pub(crate) fn listen_udp_once(
    module: &packet_dsl::Module,
    params: &packet_dsl::Params,
    globals: &packet_dsl::Globals,
    matcher: &packet_dsl::Matcher,
    opts: &PkgOptions,
    timeout: Option<Duration>,
    until: Option<&packet_dsl::Matcher>,
) -> anyhow::Result<Option<UdpListen>> {
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
                    // sniffer 命中：附带 until 是否同时命中（loop 块收工判定）
                    let until_matched = until.is_some_and(|m| m.matches(&data, None).is_some());
                    return Ok(Some(UdpListen::Hit {
                        data,
                        fields,
                        peer,
                        until_matched,
                    }));
                }
                // 非命中包也参与 until 检查（如"收到停服包即收工"）
                if let Some(m) = until
                    && m.matches(&data, None).is_some()
                {
                    return Ok(Some(UdpListen::Until));
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
