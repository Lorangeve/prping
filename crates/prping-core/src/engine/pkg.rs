//! `--pkt`：构建 .pkt 并一次性发送全部变体包到目标。
//!
//! - 默认：提取最外层 TCP/UDP 的应用层载荷，经普通 socket 发送（TCP 建连 / UDP 数据报），
//!   并读取回显（超时）。本地监听的服务能直接收到应用数据。
//! - `--raw`：原始发送完整序列化字节——Linux（需要 root/cap_net_raw）：
//!   eth → AF_PACKET；ipv4 → IPPROTO_RAW + IP_HDRINCL；ipv6 → 原始 IPv6。
//!   Windows：Npcap 链路层注入（`rawwin.rs` 兼容层，设备选择 + 以太网封装 + 抓包等待）。
//! - `--wait N`（对标 scapy `sr1`）：发送后等待匹配应答并打印 RTT + 反解展示。
//! - `--fuzz`（对标 scapy `fuzz()`）：未填字段全部随机化。
//! - `--out FILE.pcap`（对标 scapy `wrpcap`）：构建的包另存为 pcap。

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use packet_dsl::ast::{SnifferSpec, SnifferValue};
use packet_dsl::ir::{ArpOp, Field, Layer, MacAddr, PacketSpec};
use packet_dsl::{DefaultSerializer, PacketSource, Serializer};
use rust_i18n::t;
use termcolor::{ColorChoice, StandardStream, WriteColor};

use crate::engine::eng::render_hexdump;
use crate::engine::recipe::{ExtractAs, OnError};
use crate::output::{print_cyan, print_dim, print_green, print_magenta, writeln_red};

/// 发送方式。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SendMode {
    /// 提取传输层载荷，经普通 TCP/UDP socket 发送。
    #[default]
    Payload,
    /// 原始套接字发送完整字节。
    Raw { iface: Option<String> },
}

/// 传输层。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// 收到的应答。
#[derive(Debug, Clone)]
pub struct Reply {
    /// 往返耗时（毫秒）。
    pub rtt: f64,
    pub bytes: Vec<u8>,
    /// sniffer 匹配结果（字段名, 值）；None = 非 sniffer 匹配的应答。
    pub matched: Option<Vec<(String, String)>>,
}

/// 发送结果。
pub struct SendOutcome {
    pub proto: &'static str,
    pub sent: usize,
    pub received: usize,
    /// 等待到的应答（`--wait`）。
    pub reply: Option<Reply>,
}

/// `--pkt` 的完整选项。
#[derive(Debug, Clone, Default)]
pub struct PkgOptions {
    /// 显式目标（None = 逐包从包内推导）。
    pub target: Option<SocketAddr>,
    pub mode: SendMode,
    /// 运行时参数（`params("name")` 值引用）。
    pub params: Vec<(String, String)>,
    /// 配方全局存储（`-g name=value`（--global）注入；`global("name")` 值原语读取——
    /// 普通 `--pkt` 也生效，配方执行时步骤间由 extract 更新）。
    pub globals: packet_dsl::Globals,
    /// 发送后等待应答的秒数（对标 scapy `sr1`；None = 不等待）。
    pub wait: Option<f64>,
    /// fuzz 模式：未填字段全部随机化（对标 scapy `fuzz()`）。
    pub fuzz: bool,
    /// 构建的包另存为 pcap（对标 scapy `wrpcap`）。
    pub out: Option<PathBuf>,
    /// pkglang 库目录（import 解析，如发布目录的 `lib/`）。
    pub libs: Vec<PathBuf>,
}

/// 构建并发送。`file` 为 .pkt 路径，其余行为由 `opts` 控制。
///
/// 目标推导：取最外层 IP 层的 `dst` 为目标地址；载荷模式还需要传输层 `dport`。
/// 无 TCP/UDP 传输层的包（如 ICMP/ARP）自动改用 raw 发送完整包。
/// `wait` 时：UDP/TCP 载荷模式等匹配应答（DNS 按 id）、raw 模式下 ICMP echo 等回显，
/// 打印 RTT 并反解展示应答。`.pktl` 配方文件请用 [`send_recipe`]。
pub fn send_packets(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    crate::engine::eng::ensure_dns_resolver();
    crate::engine::eng::ensure_proto_registry();
    let module =
        packet_dsl::parse_file_with_libs(file, &opts.libs).map_err(|d| anyhow::anyhow!("{d}"))?;
    let p: packet_dsl::Params = opts.params.iter().cloned().collect();
    let sources = packet_dsl::resolve_sources_with_globals(&module, &p, &opts.globals)
        .map_err(|d| anyhow::anyhow!("{d}"))?;
    let total: usize = sources.iter().map(|(_, p)| p.len()).sum();
    if total == 0 {
        anyhow::bail!("没有可发送的包：文件既无默认导出，也无命名导出");
    }

    // --out：先存档（按最外层推断链路类型）。raw 模式下与发送循环一致：
    // src=0.0.0.0/:: 的包先做零源填充（否则 pcap 记录的字节 ≠ 实际发送字节）。
    if let Some(out) = &opts.out {
        let ser = if opts.fuzz {
            DefaultSerializer::new_fuzz()
        } else {
            DefaultSerializer::new()
        };
        let all: Vec<Vec<u8>> = sources
            .iter()
            .flat_map(|(_, pkts)| pkts)
            .filter_map(|pkt| {
                let mut b = ser.serialize_parts(pkt).ok()?;
                if matches!(opts.mode, SendMode::Raw { .. }) && ip_src_zero(&pkt.layers) {
                    let target = opts.target.or_else(|| derive_target(pkt, false).ok());
                    if let Some(t) = target
                        && let Some(local) = local_ip_for(&t)
                    {
                        let _ = patch_zero_src(&mut b.0, &b.1, &pkt.layers, local);
                    }
                }
                Some(b.0)
            })
            .collect();
        let lt = sources
            .iter()
            .flat_map(|(_, pkts)| pkts)
            .next()
            .map(|pkt| crate::engine::pcap::linktype_of(&pkt.layers))
            .unwrap_or(crate::engine::pcap::LinkType::Raw);
        crate::engine::pcap::write_pcap(out, lt, &all)?;
    }

    let mut w = StandardStream::stdout(ColorChoice::Auto);
    print_magenta(&mut w, "packet-dsl pkg")?;
    writeln!(&mut w)?;
    print_cyan(
        &mut w,
        format!(
            "sending {total} packets from {} ({}){}",
            file.display(),
            match &opts.mode {
                SendMode::Payload => "payload over TCP/UDP, raw fallback".to_string(),
                SendMode::Raw { .. } => "raw sockets".to_string(),
            },
            match opts.target {
                Some(t) => format!(" to {}", fmt_target(Some(t))),
                None => " — target derived from each packet".to_string(),
            }
        ),
    )?;
    writeln!(&mut w)?;
    if opts.fuzz {
        crate::output::print_yellow(&mut w, t!("engine.note_fuzz"))?;
        writeln!(&mut w)?;
    }
    if let Some(secs) = opts.wait {
        crate::output::print_yellow(&mut w, t!("engine.note_wait_reply", secs = secs))?;
        writeln!(&mut w)?;
    }
    writeln!(&mut w)?;
    // 实际生效的库目录（默认 eng_lib + --lib；与解析器合并顺序一致）
    let libs = crate::engine::eng::effective_libs(&opts.libs);
    print_dim(
        &mut w,
        format!("libs: {}", crate::engine::eng::libs_display(&libs)),
    )?;
    writeln!(&mut w)?;
    writeln!(&mut w)?;
    let stats = send_module(
        &mut w,
        None,
        SendCtx {
            module: &module,
            sources: &sources,
            params: &p,
            globals: &opts.globals,
            on_reply: None,
        },
        opts,
    )?;
    if stats.failed > 0 {
        anyhow::bail!("{} of {} packets failed to send", stats.failed, stats.total);
    }
    if stats.skipped == stats.total && stats.total > 0 {
        anyhow::bail!(
            "没有可发送的包：{} 个导出均为纯裸层（无 TCP/UDP 传输、也无 eth/ipv4/ipv6 外层）",
            stats.total
        );
    }
    Ok(())
}
/// 每个文件/步骤的发送统计。
#[derive(Debug, Default)]
pub(crate) struct SendStats {
    pub total: usize,
    pub failed: usize,
    /// 纯裸层导出（无传输、无 raw 外层）——payload 模式下跳过不发送。
    pub skipped: usize,
}

/// 回包回调（配方 extract 用）：收到匹配回包时回调回包字节。
type ReplyCb<'a> = Option<&'a mut dyn FnMut(&[u8])>;

/// 发送一个已解析模块的全部来源包（`--pkt` 与配方步骤共用的发送/渲染循环）。
///
/// `params`/`globals` 是求值期快照（须与 `sources` 一致）；`header` 非 None 时在
/// 逐包输出前打印一行（配方步骤标题）；`on_reply` 在收到匹配回包时回调回包字节
/// （配方 extract 用）。
struct SendCtx<'a> {
    module: &'a packet_dsl::Module,
    sources: &'a [(PacketSource, Vec<PacketSpec>)],
    params: &'a packet_dsl::Params,
    globals: &'a packet_dsl::Globals,
    on_reply: ReplyCb<'a>,
}

fn send_module(
    w: &mut StandardStream,
    header: Option<String>,
    ctx: SendCtx<'_>,
    opts: &PkgOptions,
) -> anyhow::Result<SendStats> {
    let SendCtx {
        module,
        sources,
        params,
        globals,
        mut on_reply,
    } = ctx;
    let ser = if opts.fuzz {
        DefaultSerializer::new_fuzz()
    } else {
        DefaultSerializer::new()
    };
    // sniffer：--wait 时按 .pkt 的 sniffer 段校验应答（构建期静态校验 + 值表达式
    // 求值——可引用 `global(...)`，错误即报出）
    let sniffer = if opts.wait.is_some() {
        module
            .sniffer
            .as_ref()
            .map(|s| SnifferMatcher::build(s, Some(module), params, globals))
            .transpose()?
    } else {
        None
    };
    if let Some(h) = header {
        print_magenta(w, &h)?;
        writeln!(w)?;
    }
    let total: usize = sources.iter().map(|(_, p)| p.len()).sum();
    let mut idx = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    for (source, pkts) in sources {
        for pkt in pkts {
            idx += 1;
            // 层字段展示（与 --eng 一致；用实际发送的 ser，fuzz 一致）
            let header = format!(
                "packet {idx}/{total}  [{}]",
                match source {
                    PacketSource::Default => "default export".to_string(),
                    PacketSource::Export(name) => format!("export \"{name}\""),
                }
            );
            if crate::engine::eng::render_packet_fields(w, pkt, &header, &ser).is_err() {
                // 序列化失败：退回简版 stack 行（发送环节会再报错）
                let stack: Vec<&str> = pkt
                    .layers
                    .iter()
                    .map(crate::engine::eng::layer_name)
                    .collect();
                print_dim(w, format!("  stack: {}", stack.join(" -> ")))?;
                writeln!(w)?;
            }
            // 层序咨询性警告（只提示不阻断）：如 tcp 是 udp 的载荷、缺网络层等
            crate::engine::eng::print_stack_warnings(w, pkt)?;

            let extracted = extract_payload_with(pkt, &ser);
            // 无 TCP/UDP 传输且最外层也不是可 raw 发送的 eth/ipv4/ipv6 → 纯裸层导出
            // （如 `dns_query = dns(...)`、裸 `req = arp(...)` 之类仅作 --eng 展示/组合
            // 的元件），payload 与 raw 模式一致跳过并黄字提示，不视为发送失败。
            let raw_sendable_outer = raw_sendable_outer(pkt);
            if extracted.is_none() && !raw_sendable_outer {
                skipped += 1;
                crate::output::print_yellow(w, format!("  {}", t!("engine.note_bare_export")))?;
                writeln!(w)?;
                writeln!(w)?;
                continue;
            }
            let is_raw = matches!(opts.mode, SendMode::Raw { .. }) || extracted.is_none();
            if extracted.is_none() && !matches!(opts.mode, SendMode::Raw { .. }) {
                crate::output::print_yellow(w, format!("  {}", t!("engine.note_raw_fallback")))?;
                writeln!(w)?;
            }
            // 目标：显式指定 > 包内 IP 层 dst 推导；raw 链路层帧（eth 外层、无 IP 层可
            // 推导目标，如 ARP）放行 None——AF_PACKET 按帧内目的 MAC 直发，目标仅用于
            // IP 源地址填充/代理诊断等旁路逻辑。其余失败（ipv4/ipv6 dst 缺失或 random、
            // 外层不是 eth/ipv4/ipv6）逐包报错。
            let target: Option<SocketAddr> = match resolve_send_target(pkt, is_raw, opts.target) {
                Ok((t, Some(note))) => {
                    print_dim(w, format!("  target: {note}"))?;
                    writeln!(w)?;
                    t
                }
                Ok((t, None)) => t,
                Err(e) => {
                    failed += 1;
                    crate::output::writeln_red(w, format!("  ✗ {e}"))?;
                    continue;
                }
            };
            // 代理 fake-ip 诊断：目标在 198.18.0.0/15（Clash 等 fake-ip 段）时，
            // eth 原始帧绕过代理直发物理网卡，公网不可达（bare-ip 走内核路由/代理可达）。
            let is_eth_frame = matches!(pkt.layers.last(), Some(Layer::Ethernet(_)));
            if is_raw
                && is_eth_frame
                && let Some(t) = target
                && is_fake_ip(t.ip())
            {
                crate::output::print_yellow(
                    w,
                    format!("  {}", t!("engine.note_fakeip_target", ip = t.ip())),
                )?;
                writeln!(w)?;
            }
            // 序列化：raw 模式一次序列化 + 源地址填充（src=0.0.0.0/:: → 本机路由地址），
            // 展示与发送用同一份字节（fuzz 也一致）；payload 模式展示载荷。
            let shown: Vec<u8>;
            let mut raw_bytes: Option<Vec<u8>> = None;
            let mut src_note: Option<std::net::IpAddr> = None;
            let mut src_warn = false;
            if is_raw {
                let (mut bytes, parts) = ser.serialize_parts(pkt).map_err(anyhow::Error::from)?;
                if ip_src_zero(&pkt.layers) {
                    // 链路层帧无目标（None）时无法路由探测本地源地址 → src_warn
                    match target.as_ref().and_then(local_ip_for) {
                        Some(local) if patch_zero_src(&mut bytes, &parts, &pkt.layers, local) => {
                            src_note = Some(local);
                        }
                        _ => src_warn = true,
                    }
                }
                shown = bytes.clone();
                raw_bytes = Some(bytes);
            } else {
                let (_, payload) = extracted.as_ref().expect("已判定非 raw → 必有传输层");
                shown = payload.clone();
            }
            // sniffer：发包字节反解（SentField 引用来源；raw = 完整包，payload = 载荷）
            let sent_report = sniffer.as_ref().map(|_| packet_dsl::dissect(&shown));
            let result = if is_raw {
                let iface = match &opts.mode {
                    SendMode::Raw { iface } => iface.as_deref(),
                    SendMode::Payload => None,
                };
                send_raw_bytes(
                    raw_bytes.as_deref().expect("raw 分支必有序列化字节"),
                    pkt,
                    target.as_ref(),
                    iface,
                    opts.wait,
                    sniffer.as_ref(),
                    sent_report.as_ref(),
                )
            } else {
                let (transport, payload) = extracted.expect("已判定非 raw → 必有传输层");
                // payload 模式必有目标（非 raw 时 derive_target need_port=true 强制）
                let t = target.expect("payload 模式必有目标");
                send_payload(
                    transport,
                    &payload,
                    &t,
                    opts.wait,
                    sniffer.as_ref(),
                    sent_report.as_ref(),
                )
            };
            if let Some(ip) = src_note {
                if is_eth_frame && is_fake_ip(ip) {
                    // 路由探测拿到的是代理 fake-ip 网关地址：eth 原始帧绕过代理直发，
                    // 真实网关 ingress 过滤会丢弃该源地址
                    crate::output::print_yellow(
                        w,
                        format!("  {}", t!("engine.note_fakeip_src", ip = ip)),
                    )?;
                    writeln!(w)?;
                } else {
                    print_dim(w, format!("  {}", t!("engine.note_src_filled", ip = ip)))?;
                    writeln!(w)?;
                }
            } else if src_warn {
                crate::output::print_yellow(w, format!("  {}", t!("engine.note_src_unfillable")))?;
                writeln!(w)?;
            }
            match result {
                Ok(outcome) => {
                    print_green(
                        w,
                        format!(
                            "  {} → {} sent {} B{}",
                            outcome.proto,
                            fmt_target(target),
                            outcome.sent,
                            if outcome.received > 0 {
                                format!(", received {} B", outcome.received)
                            } else {
                                String::new()
                            }
                        ),
                    )?;
                    writeln!(w)?;
                    match &outcome.reply {
                        Some(Reply {
                            rtt,
                            bytes,
                            matched,
                        }) => {
                            if let Some(cb) = on_reply.as_mut() {
                                cb(bytes);
                            }
                            if let Some(fields) = matched {
                                let pairs: Vec<String> =
                                    fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
                                print_green(
                                    w,
                                    format!("  ✓ reply matched: {} ({rtt:.3} ms)", pairs.join(" ")),
                                )?;
                                writeln!(w)?;
                            } else {
                                print_cyan(w, format!("  reply after {rtt:.3} ms"))?;
                                writeln!(w)?;
                            }
                            if !bytes.is_empty() {
                                let report = packet_dsl::dissect(bytes);
                                crate::engine::eng::render_dissected(
                                    w, &report, "  reply:", bytes,
                                )?;
                            }
                        }
                        None => {
                            if let Some(secs) = opts.wait {
                                let what = if sniffer.is_some() {
                                    "matching reply"
                                } else {
                                    "reply"
                                };
                                writeln_red(w, format!("  ✗ no {what} within {secs}s"))?;
                            }
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    crate::output::writeln_red(w, format!("  ✗ {e}"))?;
                }
            }
            if !shown.is_empty() {
                render_hexdump(w, &shown)?;
            }
            writeln!(w)?;
        }
    }
    Ok(SendStats {
        total: idx,
        failed,
        skipped,
    })
}

/// 发送配方（`.pktl`）：按顺序执行每个步骤（一个 .pkt 文件），维护 global 存储。
///
/// - `global:` 段声明共享变量（`- 名=值` 一行内联或缩进 `init:` 初始值；CLI -G（--global）
///   覆盖 init；裸 `- 名` = 未初始化，值来自 extract）。
/// - 每步 `--wait` 等回包后按 `extract:` 从回包反解字段取值写入 global
///   （多个回包依次应用，后写覆盖先写）；后续步骤的 .pkt 用 `global("name")` 读取。
/// - 每步 `raw:` 覆盖发送方式（`true`/网卡名 = 强制原始发送、`false` = 强制载荷发送，
///   覆盖 CLI `--raw`；见 [`step_send_mode`]）。
/// - 步骤失败（发送失败 / extract 无回包或字段缺失）默认 stop 整个配方，
///   `on_error: continue` 记录失败继续（退出码仍非零）。
pub fn send_recipe(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    crate::engine::eng::ensure_dns_resolver();
    crate::engine::eng::ensure_proto_registry();
    let recipe = crate::engine::recipe::parse(file)?;
    // 全局存储：配方 init → CLI -G（--global）覆盖（CLI 优先，与 params 语义一致）
    let mut globals: packet_dsl::Globals = packet_dsl::Globals::new();
    for g in &recipe.globals {
        if let Some(init) = &g.init {
            globals.insert(g.name.clone(), init.clone());
        }
    }
    for (k, v) in &opts.globals {
        globals.insert(k.clone(), v.clone());
    }

    // 步骤 .pkt 用到的 params（词法收集；失败静默——exec 循环会报真正的解析错误）
    let per_step: Vec<Vec<(String, Option<packet_dsl::ast::Value>)>> = recipe
        .steps
        .iter()
        .map(|s| crate::engine::eng::collect_pkt_params(&s.pkg).unwrap_or_default())
        .collect();
    let mut param_names: Vec<String> = Vec::new();
    for used in &per_step {
        for (n, _) in used {
            if !param_names.contains(n) {
                param_names.push(n.clone());
            }
        }
    }

    let mut w = StandardStream::stdout(ColorChoice::Auto);
    print_magenta(&mut w, "packet-dsl recipe")?;
    writeln!(&mut w)?;
    print_cyan(
        &mut w,
        format!(
            "{} — {} step(s), {} global(s), {} param(s){}",
            file.display(),
            recipe.steps.len(),
            recipe.globals.len(),
            param_names.len(),
            match opts.target {
                Some(t) => format!(" to {}", fmt_target(Some(t))),
                None => " — target derived from each packet".to_string(),
            }
        ),
    )?;
    writeln!(&mut w)?;
    if !param_names.is_empty() {
        print_dim(&mut w, format!("params: {}", param_names.join(", ")))?;
        writeln!(&mut w)?;
    }
    if let Some(secs) = opts.wait {
        crate::output::print_yellow(&mut w, t!("engine.note_wait_recipe", secs = secs))?;
        writeln!(&mut w)?;
    }
    writeln!(&mut w)?;
    let libs = crate::engine::eng::effective_libs(&opts.libs);
    print_dim(
        &mut w,
        format!("libs: {}", crate::engine::eng::libs_display(&libs)),
    )?;
    writeln!(&mut w)?;

    // --out：配方模式收集全部步骤的包，结束后写一个 pcap（链路类型取首个包）
    let mut out_all: Vec<Vec<u8>> = Vec::new();
    let mut out_lt: Option<crate::engine::pcap::LinkType> = None;
    let mut total_failed = 0usize;

    for (i, step) in recipe.steps.iter().enumerate() {
        writeln!(&mut w)?;
        // 步骤间延迟（delay: 秒；pcap 转码配方携带捕获间隔）：非首步在发送前等待。
        // 分片 sleep 检查 Ctrl+C（首次中断提前结束配方，与测量模式一致的优雅退出）。
        if i > 0
            && let Some(secs) = step.delay
            && secs > 0.0
        {
            print_dim(
                &mut w,
                format!(
                    "  delay {secs}s before step {}/{} ...",
                    i + 1,
                    recipe.steps.len()
                ),
            )?;
            writeln!(&mut w)?;
            if !sleep_interruptible(secs) {
                crate::output::print_yellow(
                    &mut w,
                    "  interrupted during delay — stopping recipe",
                )?;
                writeln!(&mut w)?;
                return Ok(());
            }
        }
        // 步骤失败处理：stop（默认）→ 中止返回 Err；continue → 记录继续
        let fail_step = |w: &mut StandardStream, msg: &str| -> anyhow::Result<()> {
            let _ = crate::output::writeln_red(w, format!("  ✗ {msg}"));
            if step.on_error == OnError::Stop {
                anyhow::bail!(
                    "配方 {}：第 {}/{} 步失败（on_error: stop）",
                    file.display(),
                    i + 1,
                    recipe.steps.len()
                );
            }
            Ok(())
        };

        // 步骤参数：CLI --params + 步骤 params（同名覆盖）
        let mut step_params: packet_dsl::Params = opts.params.iter().cloned().collect();
        for (k, v) in &step.params {
            step_params.insert(k.clone(), v.clone());
        }
        // 步骤级选项：wait 覆盖 CLI；raw 覆盖发送方式（true/网卡 = 强制 raw，
        // false = 强制 payload——覆盖 CLI --raw）
        let step_opts = PkgOptions {
            wait: step.wait.or(opts.wait),
            mode: step_send_mode(&step.raw, &opts.mode),
            ..opts.clone()
        };
        if !step.extract.is_empty() && step_opts.wait.is_none() {
            fail_step(
                &mut w,
                "步骤声明了 extract 但没有 wait（extract 需要回包：本步 `wait:` 或 `--wait`）",
            )?;
            total_failed += 1;
            continue;
        }
        // 解析 + 求值（注入当前 global 快照）
        let module = match packet_dsl::parse_file_with_libs(&step.pkg, &opts.libs) {
            Ok(m) => m,
            Err(d) => {
                fail_step(&mut w, &format!("解析 {} 失败：{d}", step.pkg.display()))?;
                total_failed += 1;
                continue;
            }
        };
        let sources =
            match packet_dsl::resolve_sources_with_globals(&module, &step_params, &globals) {
                Ok(s) => s,
                Err(d) => {
                    fail_step(&mut w, &format!("求值 {} 失败：{d}", step.pkg.display()))?;
                    total_failed += 1;
                    continue;
                }
            };
        if sources.iter().map(|(_, p)| p.len()).sum::<usize>() == 0 {
            fail_step(
                &mut w,
                &format!(
                    "{} 没有可发送的包（无默认导出/命名导出）",
                    step.pkg.display()
                ),
            )?;
            total_failed += 1;
            continue;
        }
        // --out 合并收集
        if opts.out.is_some() {
            let ser = if opts.fuzz {
                DefaultSerializer::new_fuzz()
            } else {
                DefaultSerializer::new()
            };
            for (_, pkts) in &sources {
                for pkt in pkts {
                    if let Ok(b) = ser.serialize(pkt) {
                        if out_lt.is_none() {
                            out_lt = Some(crate::engine::pcap::linktype_of(&pkt.layers));
                        }
                        out_all.push(b);
                    }
                }
            }
        }
        // 发送 + 收集回包字节（extract 用）
        let mut replies: Vec<Vec<u8>> = Vec::new();
        let header = format!(
            "step {}/{}  {}",
            i + 1,
            recipe.steps.len(),
            step.pkg.display()
        );
        let stats = match send_module(
            &mut w,
            Some(header),
            SendCtx {
                module: &module,
                sources: &sources,
                params: &step_params,
                globals: &globals,
                on_reply: Some(&mut |b: &[u8]| replies.push(b.to_vec())),
            },
            &step_opts,
        ) {
            Ok(s) => s,
            Err(e) => {
                fail_step(&mut w, &format!("{} 发送中断：{e}", step.pkg.display()))?;
                total_failed += 1;
                continue;
            }
        };
        let mut step_failed = stats.failed;
        if stats.skipped == stats.total && stats.total > 0 {
            step_failed += 1;
            fail_step(
                &mut w,
                &format!(
                    "步骤 {} 的包均为纯裸层（无传输/无 raw 外层），无法发送",
                    step.pkg.display()
                ),
            )?;
        }
        // extract：回包 → global（多个回包依次应用，后写覆盖先写）
        if !step.extract.is_empty() {
            if replies.is_empty() {
                step_failed += 1;
                fail_step(
                    &mut w,
                    &format!(
                        "步骤没有收到回包，无法提取 {} 条 extract（sniffer/回显未匹配）",
                        step.extract.len()
                    ),
                )?;
            } else {
                for rb in &replies {
                    match apply_extract(
                        Some(&module),
                        &mut globals,
                        &step.extract,
                        &step_params,
                        rb,
                    ) {
                        Ok(pairs) => {
                            for (n, v) in pairs {
                                print_green(
                                    &mut w,
                                    format!(
                                        "  ✓ global.{n} = {}",
                                        crate::engine::eng::value_display(&v)
                                    ),
                                )?;
                                writeln!(&mut w)?;
                            }
                        }
                        Err(e) => {
                            step_failed += 1;
                            let _ = crate::output::writeln_red(&mut w, format!("  ✗ {e}"));
                            break;
                        }
                    }
                }
                if step_failed > stats.failed {
                    fail_step(&mut w, "extract 失败（见上）")?;
                }
            }
        }
        total_failed += step_failed;
        if step_failed > 0 {
            let _ = crate::output::writeln_red(
                &mut w,
                format!(
                    "  ✗ 步骤 {}/{} 失败（{step_failed} 个问题）",
                    i + 1,
                    recipe.steps.len()
                ),
            );
            if step.on_error == OnError::Stop {
                return Err(anyhow::anyhow!(
                    "配方 {}：第 {}/{} 步失败（on_error: stop）",
                    file.display(),
                    i + 1,
                    recipe.steps.len()
                ));
            }
        }
    }

    if let Some(out) = &opts.out {
        crate::engine::pcap::write_pcap(
            out,
            out_lt.unwrap_or(crate::engine::pcap::LinkType::Raw),
            &out_all,
        )?;
    }
    if total_failed > 0 {
        anyhow::bail!("配方 {}：{} 个步骤有失败", file.display(), total_failed);
    }
    Ok(())
}

/// 步骤级 `raw:` 覆盖 → 本步发送方式（CLI 模式为基准）。
///
/// - `raw: true`：强制 raw 发送；未指定网卡时继承 CLI `--iface`（CLI 也未给则平台默认）。
/// - `raw: 网卡名`：强制 raw 发送并指定网卡（覆盖 CLI `--iface`）。
/// - `raw: false`：强制载荷发送（覆盖 CLI `--raw`）。
/// - 未声明：继承 CLI 模式。
pub fn step_send_mode(raw: &Option<crate::engine::recipe::StepRaw>, cli: &SendMode) -> SendMode {
    match raw {
        Some(crate::engine::recipe::StepRaw::On { iface }) => {
            let iface = iface.clone().or_else(|| match cli {
                SendMode::Raw { iface } => iface.clone(),
                SendMode::Payload => None,
            });
            SendMode::Raw { iface }
        }
        Some(crate::engine::recipe::StepRaw::Off) => SendMode::Payload,
        None => cli.clone(),
    }
}

/// 分片等待 `secs` 秒（100ms 步进），期间可响应 Ctrl+C（`interrupted()`）。
/// 返回 false = 已被中断提前结束。
fn sleep_interruptible(secs: f64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(secs);
    loop {
        if crate::util::interrupted() {
            return false;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return true;
        }
        let remaining = deadline - now;
        let step = remaining.min(std::time::Duration::from_millis(100));
        std::thread::sleep(step);
    }
}

/// 从回包字节按 `extract:` 子句提取字段写入 global（复用 sniffer 的层/字段机制）。
/// 返回实际写入的 (名字, 值) 列表供调用方打印。任一子句失败 → 整体报错（已写入的
/// 前序值保留——后写覆盖先写的语义由调用方逐回包调用保证）。
fn apply_extract(
    module: Option<&packet_dsl::Module>,
    globals: &mut packet_dsl::Globals,
    extracts: &[crate::engine::recipe::Extract],
    params: &packet_dsl::Params,
    reply_bytes: &[u8],
) -> anyhow::Result<Vec<(String, packet_dsl::ast::Value)>> {
    use packet_dsl::ast::Value;
    let report = packet_dsl::dissect(reply_bytes);
    let mut out = Vec::new();
    for e in extracts {
        let val = match &e.from {
            crate::engine::recipe::FromSpec::Field { layer, field } => {
                let Some(rl) = report.layers.iter().find(|l| layer_kind(l) == *layer) else {
                    return Err(anyhow::anyhow!(
                        "配方 {} 行：回包没有 {} 层（无法提取 {}）",
                        e.line,
                        layer,
                        e.name
                    ));
                };
                match e.as_ {
                    ExtractAs::Bytes => {
                        let bytes = field_bytes(rl, field).ok_or_else(|| {
                            anyhow::anyhow!("配方 {} 行：层 {} 没有字段 {}", e.line, layer, field)
                        })?;
                        Value::List(bytes.into_iter().map(|b| Value::Int(b as i64)).collect())
                    }
                    ExtractAs::Str => {
                        let s = sniffer_extract(rl, field).ok_or_else(|| {
                            anyhow::anyhow!("配方 {} 行：层 {} 没有字段 {}", e.line, layer, field)
                        })?;
                        Value::Str(s.display())
                    }
                    ExtractAs::Int | ExtractAs::Hex => {
                        let f = sniffer_extract(rl, field).ok_or_else(|| {
                            anyhow::anyhow!("配方 {} 行：层 {} 没有字段 {}", e.line, layer, field)
                        })?;
                        match f {
                            FVal::U(u) => {
                                if e.as_ == ExtractAs::Int {
                                    Value::Int(u as i64)
                                } else {
                                    Value::Hex(u)
                                }
                            }
                            other => {
                                return Err(anyhow::anyhow!(
                                    "配方 {} 行：字段 {}.{} 不是数值（{}），请用 as: str / bytes",
                                    e.line,
                                    layer,
                                    field,
                                    other.display()
                                ));
                            }
                        }
                    }
                }
            }
            crate::engine::recipe::FromSpec::Expr(expr) => {
                // 值表达式：求值（可调用户值函数/params/global/reply 叶子），
                // 结果按 `as:` 转换（缺省 = 自然类型值）
                let reply_access =
                    |layer: &str, field: &str| reply_field_value(&report, layer, field);
                let v =
                    packet_dsl::eval_extract_value(module, params, globals, &reply_access, expr)
                        .map_err(|d| {
                            anyhow::anyhow!("配方 {} 行：`from` 表达式求值失败：{d}", e.line)
                        })?;
                if e.as_given {
                    convert_expr_value(e.as_, v, e.line, &e.name)?
                } else {
                    v
                }
            }
        };
        globals.insert(e.name.clone(), val.clone());
        out.push((e.name.clone(), val));
    }
    Ok(out)
}

/// `from:` 表达式形态的 `as:` 转换（缺省 = 自然值，见调用方）。
fn convert_expr_value(
    as_: ExtractAs,
    v: packet_dsl::ast::Value,
    line: usize,
    name: &str,
) -> anyhow::Result<packet_dsl::ast::Value> {
    use packet_dsl::ast::Value;
    fn err_msg(line: usize, name: &str, msg: &str, v: &Value) -> anyhow::Error {
        anyhow::anyhow!(
            "配方 {line} 行：提取 `{name}` 的 as 转换失败：{msg}（表达式结果是 {}）",
            crate::engine::eng::value_display(v)
        )
    }
    match as_ {
        ExtractAs::Int => match v {
            Value::Int(_) => Ok(v),
            Value::Hex(h) => Ok(Value::Int(h as i64)),
            other => Err(err_msg(line, name, "需要整数（Int/Hex）", &other)),
        },
        ExtractAs::Hex => match v {
            Value::Hex(_) => Ok(v),
            Value::Int(i) if i >= 0 => Ok(Value::Hex(i as u64)),
            other => Err(err_msg(line, name, "需要非负整数（Int/Hex）", &other)),
        },
        ExtractAs::Str => match v {
            Value::Str(_) => Ok(v),
            Value::Int(i) => Ok(Value::Str(i.to_string())),
            Value::Hex(h) => Ok(Value::Str(h.to_string())),
            other => Err(err_msg(line, name, "需要字符串或整数", &other)),
        },
        ExtractAs::Bytes => match v {
            Value::List(_) => Ok(v),
            Value::Str(s) => Ok(Value::List(
                s.bytes().map(|b| Value::Int(b as i64)).collect(),
            )),
            other => Err(err_msg(
                line,
                name,
                "数值转字节请在表达式里用 be16()/u8() 等原语包一层",
                &other,
            )),
        },
    }
}

/// `reply("层","字段")` 取值：sniffer 字段集 + 扩展字节字段（icmp.payload /
/// http.body / raw.bytes；raw.bytes 无 Raw 层时兜底 remaining——裸应用层回显）。
fn reply_field_value(
    report: &packet_dsl::DissectReport,
    layer: &str,
    field: &str,
) -> Option<packet_dsl::ast::Value> {
    use packet_dsl::ast::Value;
    // 1) 语义 IR 层（eth/arp/ipv4/.../dns/http）优先
    if let Some(rl) = report.layers.iter().find(|l| layer_kind(l) == layer) {
        if let Some(f) = sniffer_extract(rl, field) {
            return Some(match f {
                FVal::U(u) => Value::Int(u as i64),
                other => Value::Str(other.display()),
            });
        }
        match (layer, field) {
            ("icmp", "payload") => match rl {
                Layer::Icmp(f) => f.payload.clone().map(bytes_value),
                _ => None,
            },
            ("http", "body") => match rl {
                Layer::Http(f) => f.body.clone().map(bytes_value),
                _ => None,
            },
            ("raw", "bytes") => match rl {
                Layer::Raw(d) => Some(bytes_value(d.bytes.clone())),
                _ => None,
            },
            _ => None,
        }
    } else {
        // 2) proto 注册表命中（协议走 pkt 声明反解，如 dns）——字段表取值
        let v = report.proto.iter().find(|h| h.name == layer).and_then(|h| {
            h.fields
                .iter()
                .find(|(n, _)| n == field)
                .map(|(_, v)| match v {
                    packet_dsl::ProtoVal::Int(i) => Value::Int(*i),
                    packet_dsl::ProtoVal::Str(s) => Value::Str(s.clone()),
                    packet_dsl::ProtoVal::Bytes(b) => bytes_value(b.clone()),
                })
        });
        if v.is_some() {
            return v;
        }
        // 3) raw 兜底
        if layer == "raw" && field == "bytes" && !report.remaining.is_empty() {
            return Some(bytes_value(report.remaining.clone()));
        }
        None
    }
}

/// 字节列表 → Value（每个字节为 Int 值；与 packet-dsl 的 bytes_value 等价）。
fn bytes_value(bytes: Vec<u8>) -> packet_dsl::ast::Value {
    use packet_dsl::ast::Value;
    Value::List(bytes.into_iter().map(|b| Value::Int(b as i64)).collect())
}

/// 反解层字段的可比规范值（sniffer 匹配用）。
#[derive(Debug, Clone, PartialEq)]
enum FVal {
    U(u64),
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
    Mac(MacAddr),
    S(String),
}

impl FVal {
    fn display(&self) -> String {
        match self {
            FVal::U(u) => u.to_string(),
            FVal::Ip4(a) => a.to_string(),
            FVal::Ip6(a) => a.to_string(),
            FVal::Mac(m) => m.to_string(),
            FVal::S(s) => s.clone(),
        }
    }
}

/// 每层支持的匹配字段名（与 `--eng` 展示名一致；`sport`/`dport`/`type` 为 IR 字段别名）。
/// 配方 `extract` 的 `from: reply.<层>.<字段>` 与 `--eng` 概览校验共用。
pub(crate) fn sniffer_field_names(layer: &str) -> Option<&'static [&'static str]> {
    Some(match layer {
        "eth" => &["dst", "src", "ethertype"][..],
        "arp" => &["op", "sha", "spa", "tha", "tpa"][..],
        "ipv4" => &["src", "dst", "ttl", "proto", "tos", "id", "flags"][..],
        "ipv6" => &["src", "dst", "hop_limit", "next_header"][..],
        "icmp" => &["type", "code", "id", "seq"][..],
        "tcp" => &["sport", "dport", "seq", "ack", "flags", "window"][..],
        "udp" => &["sport", "dport"][..],
        "dns" => &["id", "flags", "opcode"][..],
        "http" => &["method", "path", "version"][..],
        _ => return None,
    })
}

/// `reply("层","字段")` 可用的字段集：sniffer 字段集 + 扩展字节字段
/// （icmp.payload / http.body / raw.bytes）——`from:` 表达式形态的 `--eng` 校验与
/// 求值共用（求值侧见 `reply_field_value`）。
pub(crate) fn reply_field_names(layer: &str) -> Option<Vec<&'static str>> {
    let mut names = match layer {
        "raw" => vec!["bytes"],
        _ => sniffer_field_names(layer)?.to_vec(),
    };
    match layer {
        "icmp" => names.push("payload"),
        "http" => names.push("body"),
        _ => {}
    }
    Some(names)
}

/// 从反解层提取字段（别名映射到 IR 字段名）。
fn sniffer_extract(l: &Layer, name: &str) -> Option<FVal> {
    match l {
        Layer::Ethernet(f) => match name {
            "dst" => mac_field(&f.dst_mac),
            "src" => mac_field(&f.src_mac),
            "ethertype" => f.ethertype.map(|v| FVal::U(v as u64)),
            _ => None,
        },
        Layer::Arp(f) => match name {
            "op" => f.op.map(|o| FVal::S(o.to_string())),
            "sha" => f.sha.map(FVal::Mac),
            "spa" => f.spa.map(FVal::Ip4),
            "tha" => f.tha.map(FVal::Mac),
            "tpa" => f.tpa.map(FVal::Ip4),
            _ => None,
        },
        Layer::Ipv4(f) => match name {
            "src" => ip4_field(&f.src),
            "dst" => ip4_field(&f.dst),
            "ttl" => u8_field(&f.ttl),
            "proto" => f.proto.map(|v| FVal::U(v as u64)),
            "tos" => f.tos.map(|v| FVal::U(v as u64)),
            "id" => f.id.map(|v| FVal::U(v as u64)),
            "flags" => f.flags.map(|fl| {
                FVal::S(format!(
                    "df={},mf={},frag={}",
                    u8::from(fl.df),
                    u8::from(fl.mf),
                    fl.frag_offset
                ))
            }),
            _ => None,
        },
        Layer::Ipv6(f) => match name {
            "src" => ip6_field(&f.src),
            "dst" => ip6_field(&f.dst),
            "hop_limit" => u8_field(&f.hop_limit),
            "next_header" => f.next_header.map(|v| FVal::U(v as u64)),
            _ => None,
        },
        Layer::Icmp(f) => match name {
            "type" => f.icmp_type.map(|v| FVal::U(v as u64)),
            "code" => f.code.map(|v| FVal::U(v as u64)),
            "id" => f.id.map(|v| FVal::U(v as u64)),
            "seq" => f.seq.map(|v| FVal::U(v as u64)),
            _ => None,
        },
        Layer::Tcp(f) => match name {
            "sport" => f.src_port.map(|v| FVal::U(v as u64)),
            "dport" => f.dst_port.map(|v| FVal::U(v as u64)),
            "seq" => f.seq.map(|v| FVal::U(v as u64)),
            "ack" => f.ack.map(|v| FVal::U(v as u64)),
            "flags" => f.flags.map(|fl| FVal::S(fl.to_string())),
            "window" => f.window.map(|v| FVal::U(v as u64)),
            _ => None,
        },
        Layer::Udp(f) => match name {
            "sport" => f.src_port.map(|v| FVal::U(v as u64)),
            "dport" => f.dst_port.map(|v| FVal::U(v as u64)),
            _ => None,
        },
        Layer::Dns(f) => match name {
            "id" => f.id.map(|v| FVal::U(v as u64)),
            "flags" => f.flags.map(|v| FVal::U(v as u64)),
            "opcode" => f.opcode.map(|v| FVal::U(v as u64)),
            _ => None,
        },
        Layer::Http(f) => match name {
            "method" => f.method.clone().map(FVal::S),
            "path" => f.path.clone().map(FVal::S),
            "version" => f.version.clone().map(FVal::S),
            _ => None,
        },
        Layer::Raw(_) => None,
    }
}

fn mac_field(f: &packet_dsl::ir::Field<MacAddr>) -> Option<FVal> {
    match f {
        packet_dsl::ir::Field::Value(m) => Some(FVal::Mac(*m)),
        _ => None,
    }
}

fn ip4_field(f: &packet_dsl::ir::Field<Ipv4Addr>) -> Option<FVal> {
    match f {
        packet_dsl::ir::Field::Value(a) => Some(FVal::Ip4(*a)),
        _ => None,
    }
}

fn ip6_field(f: &packet_dsl::ir::Field<Ipv6Addr>) -> Option<FVal> {
    match f {
        packet_dsl::ir::Field::Value(a) => Some(FVal::Ip6(*a)),
        _ => None,
    }
}

fn u8_field(f: &packet_dsl::ir::Field<u8>) -> Option<FVal> {
    match f {
        packet_dsl::ir::Field::Value(v) => Some(FVal::U(*v as u64)),
        _ => None,
    }
}

/// sniffer 匹配值。
#[derive(Debug, Clone)]
enum MatchVal {
    /// 常量比较。
    Literal(FVal),
    /// 引用发包同层同名字段。
    SentField(String),
    /// 值表达式（原语/值函数/params）：构建期求值为字节，与回包字段**字节**比较。
    Expr(Vec<u8>),
}

/// 由 `.pkt` 的 `sniffer:` 段构建的回包匹配器（多子句，任一命中即匹配）。
pub(crate) struct SnifferMatcher {
    clauses: Vec<ClauseMatcher>,
}

/// 单个匹配子句：`match 层(字段=值, ...)`。
struct ClauseMatcher {
    layer: String,
    fields: Vec<(String, MatchVal)>,
}

impl SnifferMatcher {
    /// 构建并校验：每个子句的层类型/字段名/字面量类型都静态检查；值表达式在
    /// 构建期求值为字节（错误在发送前报出）。`module` 提供值函数作用域
    /// （同文件 `func ... -> bytes`；None = 仅内置原语，宿主 `sniffer_match` 用）；
    /// `globals` 供 `global("name")` 值原语取值（配方执行时注入）。
    fn build(
        spec: &SnifferSpec,
        module: Option<&packet_dsl::Module>,
        params: &packet_dsl::Params,
        globals: &packet_dsl::Globals,
    ) -> anyhow::Result<Self> {
        let mut clauses = Vec::new();
        for clause in &spec.clauses {
            if sniffer_field_names(&clause.layer).is_none() {
                anyhow::bail!(
                    "sniffer: 未知层类型 `{}`（可用：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns）",
                    clause.layer
                );
            }
            let mut fields = Vec::new();
            for (name, v) in &clause.fields {
                if !sniffer_field_names(&clause.layer)
                    .unwrap()
                    .contains(&name.as_str())
                {
                    anyhow::bail!(
                        "sniffer: 层 `{}` 没有字段 `{name}`（可用：{}）",
                        clause.layer,
                        sniffer_field_names(&clause.layer).unwrap().join("/")
                    );
                }
                fields.push((
                    name.clone(),
                    match v {
                        SnifferValue::SentField(f) => MatchVal::SentField(f.clone()),
                        SnifferValue::Literal(lit) => MatchVal::Literal(
                            SnifferMatcher::coerce_literal(&clause.layer, name, lit)?,
                        ),
                        SnifferValue::Expr(expr) => MatchVal::Expr(
                            packet_dsl::eval_sniffer_value_with_globals(
                                module, params, globals, expr,
                            )
                            .map_err(|d| anyhow::anyhow!("sniffer: 匹配值表达式求值失败：{d}"))?,
                        ),
                    },
                ));
            }
            clauses.push(ClauseMatcher {
                layer: clause.layer.clone(),
                fields,
            });
        }
        Ok(SnifferMatcher { clauses })
    }

    /// 字面量 → 规范值（按字段类型；类型不符即报错）。
    fn coerce_literal(
        layer: &str,
        field: &str,
        v: &packet_dsl::ast::Value,
    ) -> anyhow::Result<FVal> {
        let is_ip4 = matches!(
            (layer, field),
            ("ipv4", "src" | "dst") | ("arp", "spa" | "tpa")
        );
        let is_ip6 = matches!((layer, field), ("ipv6", "src" | "dst"));
        let is_mac = matches!(
            (layer, field),
            ("eth", "dst" | "src") | ("arp", "sha" | "tha")
        );
        let is_str = matches!(
            (layer, field),
            ("arp", "op") | ("tcp", "flags") | ("http", "method" | "path" | "version")
        );
        match v {
            packet_dsl::ast::Value::Int(i)
                if *i >= 0 && !is_ip4 && !is_ip6 && !is_mac && !is_str =>
            {
                Ok(FVal::U(*i as u64))
            }
            packet_dsl::ast::Value::Hex(h) if !is_ip4 && !is_ip6 && !is_mac && !is_str => {
                Ok(FVal::U(*h))
            }
            packet_dsl::ast::Value::Str(s) => {
                if is_ip4 {
                    s.parse::<Ipv4Addr>().map(FVal::Ip4).map_err(|_| {
                        anyhow::anyhow!("sniffer: 字段 `{field}` 需要 IPv4 地址，得到 `{s}`")
                    })
                } else if is_ip6 {
                    s.parse::<Ipv6Addr>().map(FVal::Ip6).map_err(|_| {
                        anyhow::anyhow!("sniffer: 字段 `{field}` 需要 IPv6 地址，得到 `{s}`")
                    })
                } else if is_mac {
                    MacAddr::from_str_loose(s).map(FVal::Mac).ok_or_else(|| {
                        anyhow::anyhow!("sniffer: 字段 `{field}` 需要 MAC 地址，得到 `{s}`")
                    })
                } else if is_str {
                    Ok(FVal::S(s.clone()))
                } else {
                    anyhow::bail!("sniffer: 字段 `{field}` 需要数值，得到字符串 `{s}`")
                }
            }
            other => anyhow::bail!(
                "sniffer: 字段 `{field}` 的字面量类型不支持（{}）",
                crate::engine::eng::value_display(other)
            ),
        }
    }

    /// 回包是否匹配任一子句；匹配时返回命中子句的 (字段名, 回包实际值) 列表。
    pub(crate) fn matches(
        &self,
        reply: &[u8],
        sent: &packet_dsl::DissectReport,
    ) -> Option<Vec<(String, String)>> {
        let report = packet_dsl::dissect(reply);
        for clause in &self.clauses {
            // 回包没有该子句的层（语义 IR 或 proto 命中）→ 子句不可能满足
            let Some(rl) = report.layers.iter().find(|l| layer_kind(l) == clause.layer) else {
                // 协议走 pkt 声明反解（proto 命中，如 dns）：无语义 IR 层时
                // 用 proto 字段表匹配（字段名与 --eng 展示一致；SentField 从
                // 发包的 proto hit / IR 层取，与下方 IR 分支等价）
                let hit = report.proto.iter().find(|h| h.name == clause.layer);
                let mut out = Vec::new();
                let mut ok_all = true;
                if let Some(hit) = hit {
                    for (name, val) in &clause.fields {
                        let Some(rv) =
                            hit.fields
                                .iter()
                                .find(|(n, _)| n == name)
                                .map(|(_, v)| match v {
                                    packet_dsl::ProtoVal::Int(i) => FVal::U(*i as u64),
                                    packet_dsl::ProtoVal::Str(s) => FVal::S(s.clone()),
                                    packet_dsl::ProtoVal::Bytes(b) => {
                                        FVal::S(b.iter().map(|x| format!("{x:02x}")).collect())
                                    }
                                })
                        else {
                            ok_all = false;
                            break;
                        };
                        let ok = match val {
                            MatchVal::Literal(lit) => &rv == lit,
                            MatchVal::SentField(f) => {
                                let sv = sent
                                    .proto
                                    .iter()
                                    .find(|h| h.name == clause.layer)
                                    .and_then(|h| {
                                        h.fields.iter().find(|(n, _)| n == f).map(
                                            |(_, v)| match v {
                                                packet_dsl::ProtoVal::Int(i) => FVal::U(*i as u64),
                                                packet_dsl::ProtoVal::Str(s) => FVal::S(s.clone()),
                                                packet_dsl::ProtoVal::Bytes(b) => FVal::S(
                                                    b.iter().map(|x| format!("{x:02x}")).collect(),
                                                ),
                                            },
                                        )
                                    })
                                    .or_else(|| {
                                        sent.layers
                                            .iter()
                                            .find(|l| layer_kind(l) == clause.layer)
                                            .and_then(|l| sniffer_extract(l, f))
                                    });
                                sv.is_some_and(|sv| rv == sv)
                            }
                            MatchVal::Expr(expected) => {
                                proto_field_bytes(&rv).as_deref() == Some(expected.as_slice())
                            }
                        };
                        if !ok {
                            ok_all = false;
                            break;
                        }
                        out.push((name.clone(), rv.display()));
                    }
                } else {
                    ok_all = false;
                }
                if ok_all {
                    return Some(out);
                }
                continue;
            };
            let sl = sent.layers.iter().find(|l| layer_kind(l) == clause.layer);
            let mut out = Vec::new();
            let mut ok_all = true;
            for (name, val) in &clause.fields {
                let Some(rv) = sniffer_extract(rl, name) else {
                    ok_all = false;
                    break;
                };
                let ok = match val {
                    MatchVal::Literal(lit) => &rv == lit,
                    MatchVal::SentField(f) => match sl.and_then(|l| sniffer_extract(l, f)) {
                        Some(sv) => rv == sv,
                        None => false,
                    },
                    MatchVal::Expr(expected) => {
                        field_bytes(rl, name).as_deref() == Some(expected.as_slice())
                    }
                };
                if !ok {
                    ok_all = false;
                    break;
                }
                out.push((name.clone(), rv.display()));
            }
            if ok_all {
                return Some(out);
            }
        }
        None
    }
}

/// 回包反解层某字段的**原始字节**（`Expr` 值表达式字节级比较用；字段集与
/// `sniffer_extract` 一致）。数值按大端（u8 单字节 / u16 两字节 / u32 四字节），
/// 地址/MAC 按网络序，字符串为 UTF-8。
/// proto 字段值的线格式字节（sniffer Expr 匹配用；与 `field_bytes` 的 IR 层
/// 字节形态一致：数值大端、字节原样、字符串 UTF-8）。
fn proto_field_bytes(v: &FVal) -> Option<Vec<u8>> {
    Some(match v {
        FVal::U(u) => {
            // 按值大小取最小大端宽度（与字段类型宽度一致；sniffer Expr 的
            // 期望值通常是 2/4 字节，取高 2/4 字节）
            let b = u.to_be_bytes();
            if *u <= 0xFFFF {
                b[6..].to_vec()
            } else if *u <= 0xFFFF_FFFF {
                b[4..].to_vec()
            } else {
                b.to_vec()
            }
        }
        FVal::Ip4(a) => a.octets().to_vec(),
        FVal::Ip6(a) => a.octets().to_vec(),
        FVal::Mac(m) => m.0.to_vec(),
        FVal::S(s) => s.as_bytes().to_vec(),
    })
}

fn field_bytes(l: &Layer, name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let ok = match l {
        Layer::Ethernet(f) => match name {
            "dst" => mac_field_bytes(&f.dst_mac, &mut out),
            "src" => mac_field_bytes(&f.src_mac, &mut out),
            "ethertype" => u16_bytes(f.ethertype, &mut out),
            _ => false,
        },
        Layer::Arp(f) => match name {
            "op" => match f.op {
                Some(ArpOp::Request) => {
                    out.extend_from_slice(&1u16.to_be_bytes());
                    true
                }
                Some(ArpOp::Reply) => {
                    out.extend_from_slice(&2u16.to_be_bytes());
                    true
                }
                None => false,
            },
            "sha" => mac_opt_bytes(f.sha, &mut out),
            "spa" => ip4_opt_bytes(f.spa, &mut out),
            "tha" => mac_opt_bytes(f.tha, &mut out),
            "tpa" => ip4_opt_bytes(f.tpa, &mut out),
            _ => false,
        },
        Layer::Ipv4(f) => match name {
            "src" => ip4_field_bytes(&f.src, &mut out),
            "dst" => ip4_field_bytes(&f.dst, &mut out),
            "ttl" => u8_field_bytes(&f.ttl, &mut out),
            "proto" => u8_bytes(f.proto, &mut out),
            "tos" => u8_bytes(f.tos, &mut out),
            "id" => u16_bytes(f.id, &mut out),
            "flags" => match f.flags {
                Some(fl) => {
                    let v = (u16::from(fl.df) << 14) | (u16::from(fl.mf) << 13) | fl.frag_offset;
                    out.extend_from_slice(&v.to_be_bytes());
                    true
                }
                None => false,
            },
            _ => false,
        },
        Layer::Ipv6(f) => match name {
            "src" => ip6_field_bytes(&f.src, &mut out),
            "dst" => ip6_field_bytes(&f.dst, &mut out),
            "hop_limit" => u8_field_bytes(&f.hop_limit, &mut out),
            "next_header" => u8_bytes(f.next_header, &mut out),
            _ => false,
        },
        Layer::Icmp(f) => match name {
            "type" => u8_bytes(f.icmp_type, &mut out),
            "code" => u8_bytes(f.code, &mut out),
            "id" => u16_bytes(f.id, &mut out),
            "seq" => u16_bytes(f.seq, &mut out),
            _ => false,
        },
        Layer::Tcp(f) => match name {
            "sport" => u16_bytes(f.src_port, &mut out),
            "dport" => u16_bytes(f.dst_port, &mut out),
            "seq" => u32_bytes(f.seq, &mut out),
            "ack" => u32_bytes(f.ack, &mut out),
            "flags" => match f.flags {
                Some(fl) => {
                    out.push(fl.to_byte());
                    true
                }
                None => false,
            },
            "window" => u16_bytes(f.window, &mut out),
            _ => false,
        },
        Layer::Udp(f) => match name {
            "sport" => u16_bytes(f.src_port, &mut out),
            "dport" => u16_bytes(f.dst_port, &mut out),
            _ => false,
        },
        Layer::Dns(f) => match name {
            "id" => u16_bytes(f.id, &mut out),
            "flags" => u16_bytes(f.flags, &mut out),
            "opcode" => u8_bytes(f.opcode, &mut out),
            _ => false,
        },
        Layer::Http(f) => match name {
            "method" => str_bytes(f.method.as_deref(), &mut out),
            "path" => str_bytes(f.path.as_deref(), &mut out),
            "version" => str_bytes(f.version.as_deref(), &mut out),
            _ => false,
        },
        Layer::Raw(_) => false,
    };
    ok.then_some(out)
}

fn mac_field_bytes(f: &Field<MacAddr>, out: &mut Vec<u8>) -> bool {
    match f {
        Field::Value(m) => {
            out.extend_from_slice(&m.0);
            true
        }
        _ => false,
    }
}

fn mac_opt_bytes(v: Option<MacAddr>, out: &mut Vec<u8>) -> bool {
    match v {
        Some(m) => {
            out.extend_from_slice(&m.0);
            true
        }
        None => false,
    }
}

fn ip4_field_bytes(f: &Field<std::net::Ipv4Addr>, out: &mut Vec<u8>) -> bool {
    match f {
        Field::Value(a) => {
            out.extend_from_slice(&a.octets());
            true
        }
        _ => false,
    }
}

fn ip4_opt_bytes(v: Option<std::net::Ipv4Addr>, out: &mut Vec<u8>) -> bool {
    match v {
        Some(a) => {
            out.extend_from_slice(&a.octets());
            true
        }
        None => false,
    }
}

fn ip6_field_bytes(f: &Field<std::net::Ipv6Addr>, out: &mut Vec<u8>) -> bool {
    match f {
        Field::Value(a) => {
            out.extend_from_slice(&a.octets());
            true
        }
        _ => false,
    }
}

fn u8_field_bytes(f: &Field<u8>, out: &mut Vec<u8>) -> bool {
    match f {
        Field::Value(v) => {
            out.push(*v);
            true
        }
        _ => false,
    }
}

fn u8_bytes(v: Option<u8>, out: &mut Vec<u8>) -> bool {
    match v {
        Some(v) => {
            out.push(v);
            true
        }
        None => false,
    }
}

fn u16_bytes(v: Option<u16>, out: &mut Vec<u8>) -> bool {
    match v {
        Some(v) => {
            out.extend_from_slice(&v.to_be_bytes());
            true
        }
        None => false,
    }
}

fn u32_bytes(v: Option<u32>, out: &mut Vec<u8>) -> bool {
    match v {
        Some(v) => {
            out.extend_from_slice(&v.to_be_bytes());
            true
        }
        None => false,
    }
}

fn str_bytes(v: Option<&str>, out: &mut Vec<u8>) -> bool {
    match v {
        Some(s) => {
            out.extend_from_slice(s.as_bytes());
            true
        }
        None => false,
    }
}

/// 层的展示名（与 `--eng` 一致）。
fn layer_kind(l: &Layer) -> String {
    match l {
        Layer::Ethernet(_) => "eth".into(),
        Layer::Arp(_) => "arp".into(),
        Layer::Ipv4(_) => "ipv4".into(),
        Layer::Ipv6(_) => "ipv6".into(),
        Layer::Icmp(_) => "icmp".into(),
        Layer::Tcp(_) => "tcp".into(),
        Layer::Udp(_) => "udp".into(),
        Layer::Http(_) => "http".into(),
        Layer::Dns(_) => "dns".into(),
        Layer::Raw(_) => "raw".into(),
    }
}

/// 按 sniffer 声明校验回包（宿主/测试用）：`spec` 取自 `Module.sniffer`。
///
/// 无模块上下文：`Expr` 值表达式仅支持内置原语（`be16`/`concat`/`u8`/`mac`/`ip4`…），
/// 引用用户值函数请用 [`sniffer_match_with`]。
pub fn sniffer_match(
    spec: &SnifferSpec,
    reply: &[u8],
    sent: &[u8],
) -> anyhow::Result<Option<Vec<(String, String)>>> {
    sniffer_match_with(spec, None, &packet_dsl::Params::new(), reply, sent)
}

/// 按 sniffer 声明校验回包（带模块 + 运行时参数）：`Expr` 值表达式可引用同文件
/// 值函数（`func ... -> bytes`）与 `params(...)`，求值为字节后与回包字段字节比较。
pub fn sniffer_match_with(
    spec: &SnifferSpec,
    module: Option<&packet_dsl::Module>,
    params: &packet_dsl::Params,
    reply: &[u8],
    sent: &[u8],
) -> anyhow::Result<Option<Vec<(String, String)>>> {
    let m = SnifferMatcher::build(spec, module, params, &packet_dsl::Globals::new())?;
    let sent_report = packet_dsl::dissect(sent);
    Ok(m.matches(reply, &sent_report))
}

/// 从包推导目标地址：最外层 IP 层的 `dst`；有 TCP/UDP 传输层时带上 `dport`，
/// 无传输层（ICMP 等）端口为 0；`need_port` 时缺 dport 直接报错。
pub fn derive_target(pkt: &PacketSpec, need_port: bool) -> anyhow::Result<SocketAddr> {
    let ip = pkt
        .layers
        .iter()
        .rev()
        .find_map(|l| match l {
            Layer::Ipv4(f) => match f.dst {
                packet_dsl::ir::Field::Value(a) => Some(std::net::IpAddr::from(a)),
                _ => None,
            },
            Layer::Ipv6(f) => match f.dst {
                packet_dsl::ir::Field::Value(a) => Some(std::net::IpAddr::from(a)),
                _ => None,
            },
            _ => None,
        })
        .ok_or_else(|| {
            anyhow::anyhow!("包没有定义目标地址（IP 层 dst 缺失或为 random），请显式指定 HOST:PORT")
        })?;
    let port = match pkt_dport(pkt) {
        // raw 模式也带真实 dport（有传输层时展示更有信息量；无则 0 = 无端口）
        Some(p) => p,
        None if need_port => {
            anyhow::bail!("包没有定义目标端口（传输层 dport 缺失），请显式指定 HOST:PORT")
        }
        None => 0,
    };
    Ok(SocketAddr::new(ip, port))
}

/// 最外层 TCP/UDP 的目标端口：语义字段优先；字节直喂层（库函数构建，raw 有值）
/// 从头部字节解析——TCP/UDP 头 dport 都在 offset 2-3（sport 2B + dport 2B）。
fn pkt_dport(pkt: &PacketSpec) -> Option<u16> {
    pkt.layers.iter().rev().find_map(|l| match l {
        Layer::Tcp(f) => f.dst_port.or_else(|| raw_dport(&f.raw)),
        Layer::Udp(f) => f.dst_port.or_else(|| raw_dport(&f.raw)),
        _ => None,
    })
}

/// 展示用目标字符串：None = 链路层帧（无 IP 目标）；端口 0（无 TCP/UDP 传输层的包，
/// 如 ICMP）时只显示 IP——端口是传输层概念，IP 层没有端口，`127.0.0.1:0` 会误导。
fn fmt_target(t: Option<SocketAddr>) -> String {
    match t {
        Some(t) if t.port() == 0 => t.ip().to_string(),
        Some(t) => t.to_string(),
        None => t!("engine.target_none").to_string(),
    }
}

/// 最外层可 raw 发送（Linux：eth → AF_PACKET、ipv4 → IPPROTO_RAW、ipv6 → IPV6_HDRINCL；
/// Windows：Npcap 链路层注入）。
fn raw_sendable_outer(pkt: &PacketSpec) -> bool {
    matches!(
        pkt.layers.last(),
        Some(Layer::Ethernet(_) | Layer::Ipv4(_) | Layer::Ipv6(_))
    )
}

/// 包是否「只能经 raw 模式发送」：无 TCP/UDP 传输层（payload 模式提取不到载荷，
/// [`send_module`] 自动回退 raw 发送完整包），但最外层可 raw 发送（eth/ipv4/ipv6，
/// 如 ICMP over IP、ARP over eth）。纯裸层导出（无传输也无 raw 外层）不在此列——
/// payload 与 raw 两种模式都发不了（`engine.note_bare_export` 跳过）。
pub(crate) fn raw_only(pkt: &PacketSpec) -> bool {
    !pkt.layers
        .iter()
        .any(|l| matches!(l, Layer::Tcp(_) | Layer::Udp(_)))
        && raw_sendable_outer(pkt)
}

/// `--eng` 逐包展示的发送方式提示（只提示不阻断）：无 TCP/UDP 传输层的包只能经
/// raw 模式发送完整字节（`--raw` / 配方 `raw: true`），payload 模式无法提取载荷。
/// 与 `eng::print_stack_warnings` 同风格（橙色 `note:`），构建期提前告知发送约束；
/// 发送期自动回退的 `engine.note_raw_fallback` 提示不变。
pub(crate) fn print_raw_only_hint<W: WriteColor>(w: &mut W, pkt: &PacketSpec) -> io::Result<()> {
    if raw_only(pkt) {
        crate::output::writeln_orange(w, format!("  {}", t!("engine.note_raw_only")))?;
    }
    Ok(())
}

/// 解析发送目标：(目标, 展示文案；None = 显式指定，无需逐包提示)。规则：
///
/// - 显式指定 > 包内 IP 层 `dst` 推导（`derive_target`）；
/// - raw 链路层帧（最外层 eth、无 IP 层可推导目标，如 ARP）→ `None` 放行——
///   AF_PACKET 按帧内目的 MAC 直发，目标仅用于源地址填充/代理诊断等旁路逻辑；
/// - raw 且最外层不是 eth/ipv4/ipv6（裸 arp/http 等导出）→ 报「外层不可 raw 发送」；
/// - 其余（ipv4/ipv6 `dst` 缺失或 random）→ 原推导错误。
///
/// 返回 `Err` 表示该包不可发送（调用方逐包报错跳过）。
fn resolve_send_target(
    pkt: &PacketSpec,
    is_raw: bool,
    explicit: Option<SocketAddr>,
) -> Result<(Option<SocketAddr>, Option<String>), String> {
    if let Some(t) = explicit {
        return Ok((Some(t), None));
    }
    match derive_target(pkt, !is_raw) {
        Ok(t) => Ok((
            Some(t),
            Some(format!("{} (derived from packet)", fmt_target(Some(t)))),
        )),
        Err(_e) if is_raw && matches!(pkt.layers.last(), Some(Layer::Ethernet(_))) => Ok((
            None,
            Some(format!("none — {}", t!("engine.note_linklayer_no_target"))),
        )),
        Err(_e) if is_raw && !raw_sendable_outer(pkt) => {
            Err("raw 发送需要最外层为 eth / ipv4 / ipv6 层".to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// 从字节直喂的传输层头解析 dport（TCP/UDP 头 offset 2-3 的 be16）。
fn raw_dport(raw: &Option<Vec<u8>>) -> Option<u16> {
    let b = raw.as_ref()?;
    if b.len() < 4 {
        return None;
    }
    Some(u16::from_be_bytes([b[2], b[3]]))
}

/// 提取最外层 TCP/UDP 的应用层载荷（内层序列化字节，使用给定序列化器）。
pub fn extract_payload_with(
    pkt: &PacketSpec,
    ser: &DefaultSerializer,
) -> Option<(Transport, Vec<u8>)> {
    let idx = pkt
        .layers
        .iter()
        .rposition(|l| matches!(l, Layer::Tcp(_) | Layer::Udp(_)))?;
    let inner = PacketSpec {
        layers: pkt.layers[..idx].to_vec(),
    };
    let payload = ser.serialize(&inner).ok()?;
    match &pkt.layers[idx] {
        Layer::Tcp(_) => Some((Transport::Tcp, payload)),
        Layer::Udp(_) => Some((Transport::Udp, payload)),
        _ => unreachable!("已匹配 TCP/UDP"),
    }
}

/// 提取最外层 TCP/UDP 的应用层载荷（默认序列化器）。
pub fn extract_payload(pkt: &PacketSpec) -> Option<(Transport, Vec<u8>)> {
    extract_payload_with(pkt, &DefaultSerializer::with_seed(0))
}

/// 普通 socket 发送：TCP 建连写载荷并读回显；UDP 发数据报并读回显。
/// `wait` 时等待匹配应答（sniffer 存在按 sniffer，否则 DNS 按 id），返回 RTT 与应答字节。
fn send_payload(
    transport: Transport,
    payload: &[u8],
    target: &SocketAddr,
    wait: Option<f64>,
    sniffer: Option<&SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<SendOutcome> {
    // timeout 转换：wait=0 → None（用默认 2s）；wait>0 → Some(秒)
    let timeout = wait.and_then(|s| {
        if s > 0.0 {
            Some(Duration::from_secs_f64(s))
        } else {
            None // wait=0 不设 timeout，用默认值
        }
    });
    match transport {
        Transport::Tcp => {
            let t0 = std::time::Instant::now();
            let mut conn = TcpStream::connect(target)?;
            conn.set_read_timeout(timeout.or(Some(Duration::from_secs(2))))?;
            conn.write_all(payload)?;
            let _ = conn.shutdown(Shutdown::Write);
            let t_conn = t0.elapsed();
            // 回显字节保留在 Reply.bytes（配方 extract 需要）；`received` 为其长度
            let body = read_all(&mut conn)?;
            let received = body.len();
            let reply = if wait.is_some() && received > 0 {
                // 应答 body 已在 read_all 里读完；继续排空余量（原 read_echo 语义）
                let _ = read_all(&mut conn);
                Some(Reply {
                    rtt: t_conn.as_secs_f64() * 1000.0,
                    bytes: body,
                    matched: None, // TCP 回显无独立字节，sniffer 不适用
                })
            } else {
                None
            };
            Ok(SendOutcome {
                proto: "TCP",
                sent: payload.len(),
                received,
                reply,
            })
        }
        Transport::Udp => {
            let sock = UdpSocket::bind("0.0.0.0:0")?;
            sock.send_to(payload, target)?;
            let (received, reply) = match wait {
                Some(secs) => {
                    sock.set_read_timeout(Some(Duration::from_secs_f64(secs)))?;
                    match wait_udp_reply(&sock, payload, sniffer, sent_report)? {
                        Some((rtt, bytes, matched)) => {
                            let _ = secs;
                            (
                                bytes.len(),
                                Some(Reply {
                                    rtt,
                                    bytes,
                                    matched,
                                }),
                            )
                        }
                        None => (0, None),
                    }
                }
                None => {
                    sock.set_read_timeout(Some(Duration::from_secs(1)))?;
                    (recv_echo(&sock)?, None)
                }
            };
            Ok(SendOutcome {
                proto: "UDP",
                sent: payload.len(),
                received,
                reply,
            })
        }
    }
}

/// UDP 等待应答：sniffer 存在时按 sniffer 匹配；否则按 DNS id 匹配（发送与应答都是
/// DNS 时），否则取第一个数据报。返回 (rtt, 应答字节, sniffer 匹配字段)。
type UdpReply = (f64, Vec<u8>, Option<Vec<(String, String)>>);
fn wait_udp_reply(
    sock: &UdpSocket,
    sent: &[u8],
    sniffer: Option<&SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> io::Result<Option<UdpReply>> {
    let sent_id = packet_dsl::dissect::dns_message_id(sent);
    let t0 = std::time::Instant::now();
    let mut buf = [0u8; 65535];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let data = buf[..n].to_vec();
                let rtt = t0.elapsed().as_secs_f64() * 1000.0;
                if let Some(sn) = sniffer {
                    // sniffer 存在：只接受匹配的应答（杂包跳过）
                    if let Some(fields) = sn.matches(
                        &data,
                        sent_report.ok_or(io::Error::other("内部错误：sniffer 缺发包反解"))?,
                    ) {
                        return Ok(Some((rtt, data, Some(fields))));
                    }
                    continue;
                }
                if sent_id.is_some() {
                    // 发送的是 DNS：只接受同 id 的 DNS 应答（杂包/非 DNS 都跳过）
                    if packet_dsl::dissect::dns_message_id(&data) != sent_id {
                        continue;
                    }
                }
                return Ok(Some((rtt, data, None)));
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    }
}

/// UDP：读取回显直到超时。
fn recv_echo(sock: &UdpSocket) -> io::Result<usize> {
    let mut got = 0usize;
    let mut buf = [0u8; 8192];
    loop {
        match sock.recv(&mut buf) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// 读满输入直到 EOF/超时，返回字节数与内容。
fn read_all(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// 原始套接字发送完整字节（已由调用方序列化 + 源地址填充）；
/// `wait` 时按 sniffer（存在）或 ICMP echo 匹配回显。
fn send_raw_bytes(
    bytes: &[u8],
    pkt: &PacketSpec,
    target: Option<&SocketAddr>,
    iface: Option<&str>,
    wait: Option<f64>,
    sniffer: Option<&SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<SendOutcome> {
    // Windows：Npcap 兼容层一次完成设备选择 + 以太网封装 + 抓包等待（rawwin.rs）
    #[cfg(windows)]
    {
        crate::engine::rawwin::send_raw_full(bytes, pkt, target, iface, wait, sniffer, sent_report)
    }
    #[cfg(not(windows))]
    {
        // --wait：先开回包 socket 再发送。回环/近零延迟网络下内核在 send() 内就
        // 同步完成回包往返（loopback xmit 触发 NET_RX softirq，softirq 在
        // local_bh_enable 的进程上下文同步执行：icmp 回显 → 回包生成 → 再次投递），
        // 回包先于 socket 存在即被内核丢弃——发送后才开 socket 永远等不到
        // （与 rawwin/Npcap 侧「先开抓包句柄再发送」同理）。
        #[cfg(target_os = "linux")]
        let reply_fd = if wait.is_some() && (sniffer.is_some() || icmp_echo_ids(pkt).is_some()) {
            Some(open_raw_icmp4()?)
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let reply_fd: Option<libc::c_int> = None;
        let result = (|| -> anyhow::Result<SendOutcome> {
            let (proto, sent) = match pkt.layers.last() {
                Some(Layer::Ethernet(_)) => ("ETH", send_af_packet(bytes, target, iface)?),
                Some(Layer::Ipv4(_)) => {
                    // 链路层帧可无目标；裸 IPv4 发送需要目标（sendto 路由/目标地址）
                    let t = target.ok_or_else(|| {
                        anyhow::anyhow!("raw IPv4 发送需要目标地址（HOST 或包内 IP 层 dst）")
                    })?;
                    ("IP4", send_raw_ip4(bytes, t)?)
                }
                Some(Layer::Ipv6(_)) => {
                    let t = target.ok_or_else(|| {
                        anyhow::anyhow!("raw IPv6 发送需要目标地址（HOST 或包内 IP 层 dst）")
                    })?;
                    ("IP6", send_raw_ip6(bytes, t)?)
                }
                _ => anyhow::bail!("raw 发送需要最外层为 eth / ipv4 / ipv6 层"),
            };
            let reply = match reply_fd {
                Some(fd) => {
                    let secs = wait.expect("reply_fd 仅在 --wait 时打开");
                    wait_icmp_reply(fd, pkt, secs, sniffer, sent_report)?
                }
                None => None,
            };
            Ok(SendOutcome {
                proto,
                sent,
                received: 0,
                reply,
            })
        })();
        #[cfg(target_os = "linux")]
        if let Some(fd) = reply_fd {
            unsafe { libc::close(fd) };
        }
        result
    }
}

/// 到达 `target` 的本地源地址（UDP connect 路由探测，不发数据）。
/// `trace --tcp` 的 TCP 伪头部校验和也用它取源 IP。
pub(crate) fn local_ip_for(target: &SocketAddr) -> Option<std::net::IpAddr> {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let s = UdpSocket::bind(bind).ok()?;
    s.connect(*target).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

/// 包内是否有 IP 层且源地址为零（0.0.0.0 / ::）——需要发送前填充。
fn ip_src_zero(layers: &[Layer]) -> bool {
    layers.iter().any(|l| match l {
        Layer::Ipv4(f) => matches!(
            &f.src,
            packet_dsl::ir::Field::Value(a) if a.is_unspecified()
        ),
        Layer::Ipv6(f) => matches!(
            &f.src,
            packet_dsl::ir::Field::Value(a) if a.is_unspecified()
        ),
        _ => false,
    })
}

/// 198.18.0.0/15（RFC 2544 基准段）——Clash 等代理 fake-ip 模式的常用地址段。
fn is_fake_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0], o[1]) == (198, 18) || (o[0], o[1]) == (198, 19)
        }
        _ => false,
    }
}

/// 把 IP 层为零的源地址（0.0.0.0 / ::）填充为 `local`（宿主 raw 发送用）。
///
/// `parts` 来自 `Serializer::serialize_parts`（每层头字节区间，内→外）。
/// IPv4 填充后重算 header checksum（offset 10-11）；返回是否实际填充。
pub fn patch_zero_src(
    bytes: &mut [u8],
    parts: &[(usize, usize)],
    layers: &[Layer],
    local: std::net::IpAddr,
) -> bool {
    for (i, l) in layers.iter().enumerate() {
        let Some(&(s, e)) = parts.get(i) else {
            continue;
        };
        match l {
            Layer::Ipv4(_) => {
                let seg = &mut bytes[s..e];
                if seg.len() >= 20
                    && seg[12..16] == [0, 0, 0, 0]
                    && let std::net::IpAddr::V4(ip) = local
                {
                    seg[12..16].copy_from_slice(&ip.octets());
                    seg[10] = 0;
                    seg[11] = 0;
                    let c = packet_dsl::serialize::checksum(&seg[..20]);
                    seg[10] = (c >> 8) as u8;
                    seg[11] = (c & 0xFF) as u8;
                    return true;
                }
                return false;
            }
            Layer::Ipv6(_) => {
                let seg = &mut bytes[s..e];
                if seg.len() >= 40
                    && seg[8..24].iter().all(|&b| b == 0)
                    && let std::net::IpAddr::V6(ip) = local
                {
                    seg[8..24].copy_from_slice(&ip.octets());
                    return true;
                }
                return false;
            }
            _ => {}
        }
    }
    false
}

/// 包内 ICMP echo 的 id/seq（无 sniffer 时 raw `--wait` 按此匹配 echo reply）。
pub(crate) fn icmp_echo_ids(pkt: &PacketSpec) -> Option<(u16, u16)> {
    let Some(Layer::Icmp(icmp)) = pkt.layers.iter().find(|l| matches!(l, Layer::Icmp(_))) else {
        return None;
    };
    let (Some(id), Some(seq)) = (icmp.id, icmp.seq) else {
        return None;
    };
    Some((id, seq))
}

/// 回包匹配结果：(应答字节, sniffer 命中字段)。
pub(crate) type ReplyMatch = Option<(Vec<u8>, Option<Vec<(String, String)>>)>;

/// 用 sniffer（存在）或 ICMP echo id+seq 匹配收到的回包数据。
///
/// 返回 `(应答字节, sniffer 命中字段)`；RTT 由调用方测量后填入 `Reply`。
/// Linux raw ICMP socket（`wait_icmp_reply`）与 Windows Npcap 捕获（`rawwin`）共用。
pub(crate) fn match_reply(
    data: &[u8],
    pkt: &PacketSpec,
    sniffer: Option<&SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<ReplyMatch> {
    if let Some(sn) = sniffer {
        let report = sent_report.ok_or_else(|| anyhow::anyhow!("内部错误：sniffer 缺发包反解"))?;
        return Ok(sn
            .matches(data, report)
            .map(|fields| (data.to_vec(), Some(fields))));
    }
    let Some((id, seq)) = icmp_echo_ids(pkt) else {
        return Ok(None);
    };
    let report = packet_dsl::dissect(data);
    let reply_icmp = report.layers.iter().find_map(|l| match l {
        Layer::Icmp(f) => Some(f),
        _ => None,
    });
    let Some(icmp) = reply_icmp else {
        return Ok(None);
    };
    // ICMPv6 echo reply 是 type=129（v4 是 0）：按发包 ICMP 类型取期望回包类型，
    // 避免把 v4 语义的 type=0 硬套到 v6 回包上（v6 --wait 永远匹配不到）。
    let expect_reply_type = match pkt.layers.iter().find_map(|l| match l {
        Layer::Icmp(f) => f.icmp_type,
        _ => None,
    }) {
        Some(128) => 129,
        _ => 0,
    };
    if icmp.icmp_type == Some(expect_reply_type) && icmp.id == Some(id) && icmp.seq == Some(seq) {
        Ok(Some((data.to_vec(), None)))
    } else {
        Ok(None)
    }
}

/// raw 模式应答等待：sniffer 存在时按 sniffer 匹配；否则包是 ICMP echo → 等 echo reply
/// （按 id+seq 匹配）。socket 由调用方在**发送前**打开（见 `wait_icmp_reply` 注释）。
#[cfg(target_os = "linux")]
fn open_raw_icmp4() -> anyhow::Result<libc::c_int> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        anyhow::bail!(
            "raw ICMP socket 失败（需要 root/cap_net_raw）：{}",
            io::Error::last_os_error()
        );
    }
    Ok(fd)
}

/// 在已打开的 raw ICMP socket（v4）上等待回包（sniffer / ICMP echo id+seq 匹配）。
///
/// 调用方必须**先打开 socket 再发送**：回环/近零延迟网络下内核在 send() 内就同步
/// 完成回包往返——loopback xmit 触发 NET_RX softirq，softirq 在 local_bh_enable 的
/// 进程上下文同步执行（icmp 回显 → 回包生成 → 再次投递），回包先于 socket 存在即被
/// 内核丢弃，发送后才开 socket 永远等不到（与 rawwin/Npcap「先开抓包句柄再发送」同理）。
#[cfg(target_os = "linux")]
fn wait_icmp_reply(
    fd: libc::c_int,
    pkt: &PacketSpec,
    secs: f64,
    sniffer: Option<&SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<Option<Reply>> {
    let t0 = std::time::Instant::now();
    let mut buf = [0u8; 65535];
    let deadline = Duration::from_secs_f64(secs);
    let mut rfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline.saturating_sub(t0.elapsed());
        if remaining.is_zero() {
            return Ok(None);
        }
        let rc = unsafe { libc::poll(&mut rfd, 1, remaining.as_millis() as libc::c_int) };
        if rc <= 0 {
            return Ok(None);
        }
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n <= 0 {
            continue;
        }
        let data = buf[..n as usize].to_vec();
        let rtt = t0.elapsed().as_secs_f64() * 1000.0;
        if let Some((bytes, matched)) = match_reply(&data, pkt, sniffer, sent_report)? {
            return Ok(Some(Reply {
                rtt,
                bytes,
                matched,
            }));
        }
    }
}

/// AF_PACKET 原始以太网帧（Linux；默认接口 lo，可用 --iface 指定）。
/// 链路层帧（如 ARP）不需要目标地址——帧内目的 MAC 即投递目标。
#[cfg(target_os = "linux")]
fn send_af_packet(
    bytes: &[u8],
    _target: Option<&SocketAddr>,
    iface: Option<&str>,
) -> anyhow::Result<usize> {
    use libc::{AF_PACKET, ETH_P_ALL, SOCK_RAW, htons, sockaddr, sockaddr_ll};
    use std::mem::size_of;

    if bytes.len() < 14 {
        anyhow::bail!("以太网帧过短（{} 字节）", bytes.len());
    }
    let iface = iface.unwrap_or("lo");
    let c_iface =
        std::ffi::CString::new(iface).map_err(|_| anyhow::anyhow!("接口名含 NUL：`{iface}`"))?;
    let ifindex = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("找不到网络接口 `{iface}`");
    }
    let fd = unsafe { libc::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16) as libc::c_int) };
    if fd < 0 {
        anyhow::bail!(
            "AF_PACKET socket 失败（需要 root/cap_net_raw）：{}",
            io::Error::last_os_error()
        );
    }
    let mut addr: sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = AF_PACKET as u16;
    addr.sll_protocol = htons(ETH_P_ALL as u16);
    addr.sll_ifindex = ifindex as libc::c_int;
    addr.sll_halen = 6;
    addr.sll_addr = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], 0, 0,
    ];
    let n = unsafe {
        libc::sendto(
            fd,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len(),
            0,
            &addr as *const sockaddr_ll as *const sockaddr,
            size_of::<sockaddr_ll>() as libc::socklen_t,
        )
    };
    unsafe { libc::close(fd) };
    if n < 0 {
        anyhow::bail!("AF_PACKET 发送失败：{}", io::Error::last_os_error());
    }
    Ok(n as usize)
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn send_af_packet(
    _bytes: &[u8],
    _target: Option<&SocketAddr>,
    _iface: Option<&str>,
) -> anyhow::Result<usize> {
    anyhow::bail!("AF_PACKET（以太网原始帧）仅支持 Linux")
}

/// IPPROTO_RAW + IP_HDRINCL 发送完整 IPv4 包（Unix；Windows 走 rawwin::send_raw_full）。
#[cfg(not(windows))]
fn send_raw_ip4(bytes: &[u8], target: &SocketAddr) -> anyhow::Result<usize> {
    if bytes.len() < 20 || (bytes[0] >> 4) != 4 {
        anyhow::bail!("包不是合法 IPv4 报文");
    }
    let ip = target.ip();
    let ip4 = match ip {
        std::net::IpAddr::V4(v4) => v4,
        _ => anyhow::bail!("目标不是 IPv4 地址：{ip}"),
    };
    #[cfg(unix)]
    {
        use libc::{AF_INET, IPPROTO_RAW, SOCK_RAW, sockaddr, sockaddr_in};
        use std::mem::size_of;

        let fd = unsafe { libc::socket(AF_INET, SOCK_RAW, IPPROTO_RAW) };
        if fd < 0 {
            anyhow::bail!(
                "raw socket 失败（需要 root/cap_net_raw）：{}",
                io::Error::last_os_error()
            );
        }
        #[cfg(target_os = "linux")]
        unsafe {
            let one: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const libc::c_int as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        let mut addr: sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = AF_INET as u16;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from_ne_bytes(ip4.octets());
        let n = unsafe {
            libc::sendto(
                fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                0,
                &addr as *const sockaddr_in as *const sockaddr,
                size_of::<sockaddr_in>() as libc::socklen_t,
            )
        };
        unsafe { libc::close(fd) };
        if n < 0 {
            anyhow::bail!("raw IPv4 发送失败：{}", io::Error::last_os_error());
        }
        Ok(n as usize)
    }
    #[cfg(not(unix))]
    {
        let _ = (bytes, ip4);
        anyhow::bail!("raw 发送仅支持 Unix（Linux 推荐）")
    }
}

/// 原始 IPv6 发送（Linux：AF_INET6 + IPPROTO_RAW + IPV6_HDRINCL；Windows 走 rawwin）。
#[cfg(not(windows))]
fn send_raw_ip6(bytes: &[u8], target: &SocketAddr) -> anyhow::Result<usize> {
    if bytes.len() < 40 || (bytes[0] >> 4) != 6 {
        anyhow::bail!("包不是合法 IPv6 报文");
    }
    let ip = target.ip();
    #[cfg(target_os = "linux")]
    {
        let ip6 = match ip {
            std::net::IpAddr::V6(v6) => v6,
            _ => anyhow::bail!("目标不是 IPv6 地址：{ip}"),
        };
        use libc::{AF_INET6, IPPROTO_RAW, SOCK_RAW, sockaddr, sockaddr_in6};
        use std::mem::size_of;

        let fd = unsafe { libc::socket(AF_INET6, SOCK_RAW, IPPROTO_RAW) };
        if fd < 0 {
            anyhow::bail!(
                "raw IPv6 socket 失败（需要 root/cap_net_raw）：{}",
                io::Error::last_os_error()
            );
        }
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_HDRINCL,
                &one as *const libc::c_int as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        let mut addr: sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = AF_INET6 as u16;
        addr.sin6_addr = libc::in6_addr {
            s6_addr: ip6.octets(),
        };
        let n = unsafe {
            libc::sendto(
                fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                0,
                &addr as *const sockaddr_in6 as *const sockaddr,
                size_of::<sockaddr_in6>() as libc::socklen_t,
            )
        };
        unsafe { libc::close(fd) };
        if n < 0 {
            anyhow::bail!("raw IPv6 发送失败：{}", io::Error::last_os_error());
        }
        Ok(n as usize)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (bytes, ip);
        anyhow::bail!("raw IPv6 发送仅支持 Linux")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dsl::ir::{
        ArpFields, EthernetFields, Field, IcmpFields, Ipv4Fields, Ipv6Fields, TcpFields,
    };

    /// eth + ipv6 + ICMPv6 帧（checksum 随意——dissect 只进 notes 不校验）。
    fn icmp_frame_v6(icmp_type: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0u8; 12]); // eth dst/src
        b.extend_from_slice(&0x86dd_u16.to_be_bytes());
        b.extend_from_slice(&0x6000_0000u32.to_be_bytes());
        b.extend_from_slice(&8u16.to_be_bytes()); // payload len（仅 ICMPv6 头）
        b.push(58); // next header = ICMPv6
        b.push(64); // hop limit
        b.extend_from_slice(&[0u8; 16]); // src ::
        b.extend_from_slice(&[0u8; 16]); // dst ::
        b.push(icmp_type);
        b.push(0);
        b.extend_from_slice(&[0, 0]); // checksum
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&seq.to_be_bytes());
        b
    }

    /// eth + ipv4 + ICMP 帧。
    fn icmp_frame_v4(icmp_type: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0u8; 12]); // eth dst/src
        b.extend_from_slice(&0x0800_u16.to_be_bytes());
        b.extend_from_slice(&0x4500_u16.to_be_bytes());
        b.extend_from_slice(&28u16.to_be_bytes()); // total len = 20 头 + 8 icmp
        b.extend_from_slice(&[0, 0, 0, 0, 0x40, 1]); // id, flags/frag, ttl, proto
        b.extend_from_slice(&[0, 0]); // checksum
        b.extend_from_slice(&[1, 2, 3, 4]); // src
        b.extend_from_slice(&[8, 8, 8, 8]); // dst
        b.push(icmp_type);
        b.push(0);
        b.extend_from_slice(&[0, 0]); // checksum
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&seq.to_be_bytes());
        b
    }

    fn v6_echo_request_pkt() -> PacketSpec {
        PacketSpec {
            layers: vec![
                Layer::Icmp(IcmpFields {
                    icmp_type: Some(128),
                    code: Some(0),
                    id: Some(7),
                    seq: Some(3),
                    ..Default::default()
                }),
                Layer::Ipv6(Ipv6Fields {
                    src: Field::Value("::1".parse().unwrap()),
                    dst: Field::Value("2400:da00::6666".parse().unwrap()),
                    ..Default::default()
                }),
            ],
        }
    }

    /// 默认 ICMP 匹配：v6 发包期望 echo reply type=129（v4 是 0）。
    /// （层头解析走 proto 注册表——须先注册 eng_lib，见 dissect 契约。）
    #[test]
    fn match_reply_v6_expects_type_129() {
        crate::engine::eng::ensure_proto_registry();
        let pkt = v6_echo_request_pkt();
        // ICMPv6 echo reply（type=129，id/seq 一致）→ 匹配
        let r = match_reply(&icmp_frame_v6(129, 7, 3), &pkt, None, None).unwrap();
        assert!(r.is_some(), "v6 echo reply (type=129) 应匹配");
        // type=0（v4 语义）→ 不匹配
        assert_eq!(
            match_reply(&icmp_frame_v6(0, 7, 3), &pkt, None, None).unwrap(),
            None,
            "v6 回包 type=0 不应匹配"
        );
        // id 不符 → 不匹配
        assert_eq!(
            match_reply(&icmp_frame_v6(129, 8, 3), &pkt, None, None).unwrap(),
            None
        );
        // 自己发的 echo request（type=128）→ 不匹配（防自帧假阳性）
        assert_eq!(
            match_reply(&icmp_frame_v6(128, 7, 3), &pkt, None, None).unwrap(),
            None,
            "echo request 自身不应被当作回包"
        );
    }

    /// 默认 ICMP 匹配：v4 仍期望 type=0。
    #[test]
    fn match_reply_v4_still_expects_type_0() {
        crate::engine::eng::ensure_proto_registry();
        let pkt = PacketSpec {
            layers: vec![
                Layer::Icmp(IcmpFields {
                    icmp_type: Some(8),
                    code: Some(0),
                    id: Some(7),
                    seq: Some(3),
                    ..Default::default()
                }),
                Layer::Ipv4(Ipv4Fields {
                    src: Field::Value("1.2.3.4".parse().unwrap()),
                    dst: Field::Value("8.8.8.8".parse().unwrap()),
                    ..Default::default()
                }),
            ],
        };
        assert!(
            match_reply(&icmp_frame_v4(0, 7, 3), &pkt, None, None)
                .unwrap()
                .is_some(),
            "v4 echo reply (type=0) 应匹配"
        );
        assert_eq!(
            match_reply(&icmp_frame_v4(8, 7, 3), &pkt, None, None).unwrap(),
            None,
            "v4 echo request 自身不应匹配"
        );
    }

    /// 值表达式字节比较：回包字段字节 == 表达式求值字节。
    #[test]
    fn field_bytes_expr_match() {
        // icmp id=0x1234 → 字节 [0x12, 0x34]
        let l = Layer::Icmp(IcmpFields {
            icmp_type: Some(8),
            id: Some(0x1234),
            seq: Some(1),
            ..Default::default()
        });
        assert_eq!(field_bytes(&l, "id"), Some(vec![0x12, 0x34]));
        assert_eq!(field_bytes(&l, "type"), Some(vec![8]));
        assert_eq!(field_bytes(&l, "seq"), Some(vec![0x00, 0x01]));
        assert_eq!(field_bytes(&l, "code"), None, "未填字段 → None");
        assert_eq!(field_bytes(&l, "nope"), None, "未知字段 → None");
        // eth src MAC → 6 字节网络序
        let eth = Layer::Ethernet(packet_dsl::ir::EthernetFields {
            src_mac: Field::Value(MacAddr::from_str_loose("aa:bb:cc:dd:ee:ff").unwrap()),
            ..Default::default()
        });
        assert_eq!(
            field_bytes(&eth, "src"),
            Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    /// extract 表达式形态：reply 叶子取值 + 运算 + as 转换（apply_extract 直测）。
    #[test]
    fn apply_extract_expr_form() {
        crate::engine::eng::ensure_proto_registry();
        use crate::engine::recipe::FromSpec;
        use packet_dsl::ast::Value;

        // 回包：eth + ipv4 + ICMP echo reply（type=0，id=0x1234，seq=7，带 4 字节载荷）
        // ——total_len 须含载荷，dissect 才能把载荷归入 icmp.payload
        let mut reply = icmp_frame_v4(0, 0x1234, 7);
        reply[17] = 32; // IPv4 total_len 低字节 = 20 头 + 8 icmp + 4 载荷
        reply.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let mk_extract =
            |from: FromSpec, as_: ExtractAs, as_given: bool| crate::engine::recipe::Extract {
                name: "x".to_string(),
                from,
                as_,
                as_given,
                line: 1,
            };
        let mut globals = packet_dsl::Globals::new();
        let params = packet_dsl::Params::new();

        // 1) `reply.icmp.seq + 1`（表达式，缺省 as）→ Int(8)
        let expr = packet_dsl::parser::parse_value_expr(r#"reply("icmp", "seq") + 1"#).unwrap();
        let e = mk_extract(FromSpec::Expr(expr), ExtractAs::Int, false);
        let out = apply_extract(None, &mut globals, &[e], &params, &reply).unwrap();
        assert_eq!(out[0].1, Value::Int(8), "seq=7 + 1");

        // 2) `cksum(reply.icmp.payload)`（表达式，as: bytes）→ 2 字节
        let expr =
            packet_dsl::parser::parse_value_expr(r#"cksum(reply("icmp", "payload"))"#).unwrap();
        let e = mk_extract(FromSpec::Expr(expr), ExtractAs::Bytes, true);
        let out = apply_extract(None, &mut globals, &[e], &params, &reply).unwrap();
        let Value::List(bytes) = &out[0].1 else {
            panic!("cksum 应为字节列表，得到 {:?}", out[0].1);
        };
        assert_eq!(bytes.len(), 2, "cksum → 2 字节：{bytes:?}");

        // 3) `reply.icmp.id` 表达式形态（as: hex）→ Value::Hex
        let expr = packet_dsl::parser::parse_value_expr(r#"reply("icmp", "id")"#).unwrap();
        let e = mk_extract(FromSpec::Expr(expr), ExtractAs::Hex, true);
        let out = apply_extract(None, &mut globals, &[e], &params, &reply).unwrap();
        assert_eq!(out[0].1, Value::Hex(0x1234));

        // 4) 字节列表原样（缺省 as）→ List
        let expr = packet_dsl::parser::parse_value_expr(r#"reply("icmp", "payload")"#).unwrap();
        let e = mk_extract(FromSpec::Expr(expr), ExtractAs::Bytes, false);
        let out = apply_extract(None, &mut globals, &[e], &params, &reply).unwrap();
        assert_eq!(
            out[0].1,
            Value::List(vec![
                Value::Int(0xDE),
                Value::Int(0xAD),
                Value::Int(0xBE),
                Value::Int(0xEF)
            ])
        );

        // 5) 字段不存在 → 报错
        let expr = packet_dsl::parser::parse_value_expr(r#"reply("icmp", "nope")"#).unwrap();
        let e = mk_extract(FromSpec::Expr(expr), ExtractAs::Int, false);
        let err = apply_extract(None, &mut globals, &[e], &params, &reply)
            .unwrap_err()
            .to_string();
        assert!(err.contains("回包没有 `icmp.nope` 字段"), "{err}");

        // 6) 直取形态（Field）仍走原逻辑：reply.icmp.id as: hex
        let e = mk_extract(
            FromSpec::Field {
                layer: "icmp".into(),
                field: "id".into(),
            },
            ExtractAs::Hex,
            true,
        );
        let out = apply_extract(None, &mut globals, &[e], &params, &reply).unwrap();
        assert_eq!(out[0].1, Value::Hex(0x1234));
    }

    /// reply_field_names：扩展字段集（payload/body/raw.bytes）。
    #[test]
    fn reply_field_names_extended() {
        assert_eq!(
            reply_field_names("icmp"),
            Some(vec!["type", "code", "id", "seq", "payload"])
        );
        assert_eq!(
            reply_field_names("http"),
            Some(vec!["method", "path", "version", "body"])
        );
        assert_eq!(reply_field_names("raw"), Some(vec!["bytes"]));
        assert!(reply_field_names("bogus").is_none());
    }

    /// fmt_target：端口 0（无 TCP/UDP 传输层的包）只显示 IP，避免 `127.0.0.1:0` 误导；
    /// None（链路层帧）显示占位文案。
    #[test]
    fn fmt_target_hides_port_zero() {
        let no_port: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert_eq!(fmt_target(Some(no_port)), "127.0.0.1");
        let with_port: SocketAddr = "127.0.0.1:53".parse().unwrap();
        assert_eq!(fmt_target(Some(with_port)), "127.0.0.1:53");
        let v6_no_port: SocketAddr = "[::1]:0".parse().unwrap();
        assert_eq!(fmt_target(Some(v6_no_port)), "::1");
        let v6_with_port: SocketAddr = "[::1]:8080".parse().unwrap();
        assert_eq!(fmt_target(Some(v6_with_port)), "[::1]:8080");
        assert!(!fmt_target(None).is_empty(), "None 应显示占位文案");
    }

    /// resolve_send_target：链路层帧（eth 外层、无 IP 层）raw 模式放行 None 目标；
    /// 非 raw 仍报推导错误；裸 arp 导出（非 eth 外层）报外层不可发送。
    #[test]
    fn resolve_target_link_layer_frame() {
        // 层序内→外：eth 在最外层（last）
        let arp = PacketSpec {
            layers: vec![
                Layer::Arp(ArpFields::default()),
                Layer::Ethernet(EthernetFields {
                    dst_mac: Field::Value(MacAddr([0xff; 6])),
                    ..Default::default()
                }),
            ],
        };
        // raw 链路层帧：无目标放行
        let (t, note) = resolve_send_target(&arp, true, None).expect("链路层帧应放行");
        assert!(t.is_none());
        let note = note.expect("应有展示文案");
        assert!(note.contains("none"), "{note}");
        // 显式目标优先
        let explicit: SocketAddr = "192.168.1.5:0".parse().unwrap();
        let (t2, note2) = resolve_send_target(&arp, true, Some(explicit)).unwrap();
        assert_eq!(t2, Some(explicit));
        assert!(note2.is_none(), "显式目标不打印逐包提示");
        // 非 raw（payload 模式回退判定）仍报推导错误
        let err = resolve_send_target(&arp, false, None).unwrap_err();
        assert!(err.contains("目标地址"), "{err}");
    }

    /// resolve_send_target：裸 arp 导出（最外层不是 eth/ipv4/ipv6）raw 模式报外层不可发送。
    #[test]
    fn resolve_target_bare_arp_outer_is_error() {
        let bare = PacketSpec {
            layers: vec![Layer::Arp(ArpFields::default())],
        };
        let err = resolve_send_target(&bare, true, None).unwrap_err();
        assert!(err.contains("eth / ipv4 / ipv6"), "{err}");
    }

    /// resolve_send_target：外层 ipv4 但 dst 缺失 → 原推导错误（非外层错误）。
    #[test]
    fn resolve_target_ipv4_without_dst_is_derivation_error() {
        let ip = PacketSpec {
            layers: vec![Layer::Ipv4(Ipv4Fields::default())],
        };
        let err = resolve_send_target(&ip, true, None).unwrap_err();
        assert!(err.contains("目标地址"), "{err}");
    }

    /// derive_target：raw 模式无传输层 → 端口 0；有 TCP dport → 保留真实端口
    /// （raw 发送也带上，展示更有信息量）；need_port 且缺 dport → 报错。
    #[test]
    fn derive_target_raw_keeps_real_port() {
        // 无传输层（如 ICMP）→ 端口 0
        let icmp = PacketSpec {
            layers: vec![Layer::Ipv4(Ipv4Fields {
                src: Field::Value("0.0.0.0".parse().unwrap()),
                dst: Field::Value("127.0.0.1".parse().unwrap()),
                ..Default::default()
            })],
        };
        assert_eq!(derive_target(&icmp, false).unwrap().port(), 0);
        // 有 TCP dport → 保留真实端口
        let tcp = PacketSpec {
            layers: vec![
                Layer::Tcp(TcpFields {
                    dst_port: Some(8080),
                    ..Default::default()
                }),
                Layer::Ipv4(Ipv4Fields {
                    src: Field::Value("0.0.0.0".parse().unwrap()),
                    dst: Field::Value("127.0.0.1".parse().unwrap()),
                    ..Default::default()
                }),
            ],
        };
        assert_eq!(derive_target(&tcp, false).unwrap().port(), 8080);
        // need_port=true 且缺 dport → 报错
        assert!(derive_target(&icmp, true).is_err());
    }

    /// raw-only 判定：无 TCP/UDP 传输层 + 最外层可 raw 发送（eth/ipv4/ipv6）→ true；
    /// 有传输层 / 纯裸层导出（无传输也无 raw 外层）/ 空栈 → false。
    #[test]
    fn raw_only_predicate() {
        use packet_dsl::ir::{DnsFields, HttpFields, RawData, UdpFields};
        let mk = |layers: Vec<Layer>| PacketSpec { layers };
        // ICMP over IPv4（examples/network_icmp_bare/）→ raw-only
        assert!(raw_only(&mk(vec![
            Layer::Icmp(IcmpFields::default()),
            Layer::Ipv4(Ipv4Fields::default()),
        ])));
        // ARP over eth（examples/link_arp/）→ raw-only
        assert!(raw_only(&mk(vec![
            Layer::Arp(ArpFields::default()),
            Layer::Ethernet(EthernetFields::default()),
        ])));
        // 有传输层：http |> tcp |> ipv4 → payload 可提取，非 raw-only
        assert!(!raw_only(&mk(vec![
            Layer::Http(HttpFields::default()),
            Layer::Tcp(TcpFields::default()),
            Layer::Ipv4(Ipv4Fields::default()),
        ])));
        // quic_initial |> udp（examples/quic_initial/）→ 非 raw-only
        assert!(!raw_only(&mk(vec![
            Layer::Raw(RawData {
                bytes: vec![0xc0],
                proto: Some("quic_initial".into()),
            }),
            Layer::Udp(UdpFields::default()),
        ])));
        // 纯裸层导出（dns 单层，无传输也无 raw 外层）→ 非 raw-only（两种模式都发不了）
        assert!(!raw_only(&mk(vec![Layer::Dns(DnsFields::default())])));
        // 空栈 → 非 raw-only
        assert!(!raw_only(&mk(vec![])));
    }
}
