//! 发送逻辑：`--pkt` 入口、逐包发送/渲染循环、载荷模式 socket 发送、目标推导、
//! 源地址填充（含 IPv4 header checksum 重算）。
//!
//! 忠实拆分自原 `engine/pkg.rs`：send_packets（92-226）、send_module（227-545）、
//! stack_summary（547-630）、目标推导/载荷提取（1859-2007）、socket 发送（2009-2171）、
//! 源地址填充（2266-2337）。

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::time::Duration;

use packet_dsl::ir::{Layer, PacketSpec};
use packet_dsl::{DefaultSerializer, PacketSource, Serializer};
use rust_i18n::t;
use serde_json::{Map, Value, json};
use termcolor::{ColorChoice, StandardStream, WriteColor};

use super::raw::send_raw_bytes;
use super::sniffer::{SnifferMatcher, sniffer_extract};
use super::{PkgOptions, Reply, SendMode, SendOutcome, Transport, is_fake_ip, local_ip_for};
use crate::engine::eng::render_hexdump;
use crate::output::{
    indent, print_cyan, print_dim, print_green, print_magenta, print_orange, writeln_red,
};
use crate::util::hex_str;

pub fn send_packets(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    crate::engine::eng::ensure_dns_resolver();
    crate::engine::eng::ensure_proto_registry();
    let module =
        packet_dsl::parse_file_with_libs(file, &opts.libs).map_err(|d| anyhow::anyhow!("{d}"))?;
    if opts.wait == crate::engine::pkg::WaitMode::Continuous {
        anyhow::bail!("持续监听（--wait 无值）请用 listen_packets / listen_raw_packets");
    }
    let wait_secs = opts.wait.one_shot_secs();
    let p: packet_dsl::Params = opts.params.iter().cloned().collect();
    let sources = packet_dsl::resolve_sources_with_globals(&module, &p, &opts.globals)
        .map_err(|d| anyhow::anyhow!("{d}"))?;
    let total: usize = sources.iter().map(|(_, p)| p.len()).sum();
    if total == 0 {
        anyhow::bail!("{}", t!("engine.err_no_packets"));
    }

    // 单个序列化器贯穿 --out 存档与发送循环：随机字段（IP ID / sport）只消费
    // 一次，存档字节与实发字节一致（此前 --out 块与 send_module 各建一个
    // 时间种子实例，IP ID/sport 必然漂移）。raw 模式下零源填充在发送循环内
    // 完成，收集的字节即为实发字节。
    let mut ser = if opts.fuzz {
        DefaultSerializer::new_fuzz()
    } else {
        DefaultSerializer::new()
    };
    let mut archive = SendArchive::default();

    let mut w = StandardStream::stdout(ColorChoice::Auto);
    let json = crate::stats::json();
    // 模式/目标说明（摘要与完整模式共用）
    let mode_str = match &opts.mode {
        SendMode::Payload => "payload over TCP/UDP, raw fallback".to_string(),
        SendMode::Raw { .. } => "raw sockets".to_string(),
    };
    let target_str = match opts.target {
        Some(t) => format!(" to {}", fmt_target(Some(t))),
        None => " — target derived from each packet".to_string(),
    };
    if !json && !opts.summary {
        print_magenta(&mut w, "prping packet")?;
        writeln!(&mut w)?;
        print_cyan(
            &mut w,
            format!(
                "sending {total} packets from {file} ({mode_str}){target_str}",
                file = file.display()
            ),
        )?;
        writeln!(&mut w)?;
        if opts.fuzz {
            print_orange(&mut w, t!("engine.note_fuzz"))?;
            writeln!(&mut w)?;
        }
        if let Some(secs) = wait_secs.filter(|s| *s > 0.0) {
            print_orange(&mut w, t!("engine.note_wait_reply", secs = secs))?;
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
    }
    let stats = send_module(
        &mut w,
        None,
        SendCtx {
            module: &module,
            sources: &sources,
            params: &p,
            globals: &opts.globals,
            on_reply: None,
            on_sent: None,
        },
        opts,
        &mut ser,
        Some(&mut archive),
    )?;
    // --out：发送循环收集的实发字节写 pcap（raw 模式与线上一致；payload 模式为完整包）
    if let Some(out) = &opts.out {
        crate::engine::pcap::write_pcap(
            out,
            archive
                .linktype
                .unwrap_or(crate::engine::pcap::LinkType::Raw),
            &archive.bytes,
        )?;
    }
    if json {
        // --json：汇总行（packet JSONL 的最后一行）
        let sent = stats.total - stats.failed - stats.skipped;
        let mut m = Map::new();
        m.insert("type".into(), json!("summary"));
        m.insert("file".into(), json!(file.display().to_string()));
        m.insert("total".into(), json!(stats.total));
        m.insert("sent".into(), json!(sent));
        m.insert("failed".into(), json!(stats.failed));
        m.insert("skipped".into(), json!(stats.skipped));
        serde_json::to_writer(&mut w, &Value::Object(m))?;
        writeln!(&mut w)?;
    }
    if opts.summary {
        // 摘要模式：单行结果（错误已在发送循环里红字打印）
        let sent = stats.total - stats.failed - stats.skipped;
        let skip_str = if stats.skipped > 0 {
            format!(", skipped {}", stats.skipped)
        } else {
            String::new()
        };
        let target_phrase = match opts.target {
            Some(t) => format!(" to {}", fmt_target(Some(t))),
            None => String::new(),
        };
        print_cyan(
            &mut w,
            format!(
                "prping packet: {total} packets from {file}{target} — sent {sent}, failed {failed}{skip}",
                file = file.display(),
                target = target_phrase,
                sent = sent,
                failed = stats.failed,
                skip = skip_str,
            ),
        )?;
        writeln!(&mut w)?;
    }
    if stats.failed > 0 {
        anyhow::bail!(
            "{}",
            t!(
                "engine.err_send_failed",
                failed = stats.failed,
                total = stats.total
            )
        );
    }
    if stats.skipped == stats.total && stats.total > 0 {
        anyhow::bail!("{}", t!("engine.err_all_bare", total = stats.total));
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

/// `--out` 存档收集：发送循环内每包序列化一次后的实发/存档字节 + 首包链路类型。
///
/// 与发送共用**同一个序列化器**：随机字段（IP ID / sport）只消费一次，存档字节与
/// 实发字节一致（此前 `--out` 块与 send_module 各建一个时间种子实例、sent_full/
/// 摘要二次序列化，各自产出不同随机值）。
#[derive(Debug, Default)]
pub(crate) struct SendArchive {
    pub bytes: Vec<Vec<u8>>,
    pub linktype: Option<crate::engine::pcap::LinkType>,
}

/// `--json` 逐包行的公共字段（type/idx/total/source/layers）。
fn pkt_json_base(
    idx: usize,
    total: usize,
    source: &PacketSource,
    pkt: &PacketSpec,
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".into(), json!("packet"));
    m.insert("idx".into(), json!(idx));
    m.insert("total".into(), json!(total));
    let src = match source {
        PacketSource::Default => "default export".to_string(),
        PacketSource::Export(name) => format!("export \"{name}\""),
    };
    m.insert("source".into(), json!(src));
    let layers: Vec<&str> = pkt
        .layers
        .iter()
        .map(crate::engine::eng::layer_name)
        .collect();
    m.insert("layers".into(), json!(layers));
    m
}

/// `--json`：输出一行 JSONL 到 stdout。
fn json_line(w: &mut StandardStream, m: Map<String, Value>) -> io::Result<()> {
    serde_json::to_writer(&mut *w, &Value::Object(m))?;
    writeln!(w)
}

/// 回包回调（配方 extract 用）：收到匹配回包时回调回包字节。
/// 发包回调：每包发送时回调**完整序列化包字节**（配方 `extract from: sent.<层>.<字段>` 用）。
type ReplyCb<'a> = Option<&'a mut dyn FnMut(&[u8])>;

/// 发送一个已解析模块的全部来源包（`--pkt` 与配方步骤共用的发送/渲染循环）。
///
/// `params`/`globals` 是求值期快照（须与 `sources` 一致）；`header` 非 None 时在
/// 逐包输出前打印一行（配方步骤标题）；`on_reply` 在收到匹配回包时回调回包字节
/// （配方 extract 用）；`on_sent` 在每包发送时回调完整序列化包字节（配方
/// `extract from: sent.<层>.<字段>` 用）。
pub(crate) struct SendCtx<'a> {
    pub(crate) module: &'a packet_dsl::Module,
    pub(crate) sources: &'a [(PacketSource, Vec<PacketSpec>)],
    pub(crate) params: &'a packet_dsl::Params,
    pub(crate) globals: &'a packet_dsl::Globals,
    pub(crate) on_reply: ReplyCb<'a>,
    pub(crate) on_sent: ReplyCb<'a>,
}

pub(crate) fn send_module(
    w: &mut StandardStream,
    header: Option<String>,
    ctx: SendCtx<'_>,
    opts: &PkgOptions,
    ser: &mut DefaultSerializer,
    mut out_archive: Option<&mut SendArchive>,
) -> anyhow::Result<SendStats> {
    let SendCtx {
        module,
        sources,
        params,
        globals,
        mut on_reply,
        mut on_sent,
    } = ctx;
    // 一次性等待的秒数（Continuous 是服务端模式，不进 send_module）
    let wait_secs = opts.wait.one_shot_secs();
    // sniffer：--wait 时按 .pkt 的 sniffer 段校验应答（构建期静态校验 + 值表达式
    // 求值——可引用 `global(...)`，错误即报出）
    let sniffer = if wait_secs.is_some() {
        module
            .sniffer
            .as_ref()
            .map(|s| SnifferMatcher::build(s, Some(module), params, globals, true))
            .transpose()?
    } else {
        None
    };
    let json = crate::stats::json();
    if !json && let Some(h) = header {
        print_magenta(w, &h)?;
        writeln!(w)?;
    }
    // count = 每个包重复发送次数（--count / 配方步骤 count:），总显示数 = 包数 × count
    let count = opts.count.max(1);
    let total: usize = sources.iter().map(|(_, p)| p.len()).sum::<usize>() * count;
    let mut idx = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    // note 去重计数器：首次完整打印，后续简短（避免 headers.pkt 等多裸层文件刷屏）
    let mut bare_export_seen = 0usize;
    let mut raw_fallback_seen = 0usize;
    for (source, pkts) in sources {
        for pkt in pkts {
            for _rep in 0..count {
                idx += 1;
                // 摘要模式/--json：跳过层字段展示/警告/hexdump，只发送并统计（错误仍打印）
                if !json && !opts.summary {
                    // 层字段展示（与 --eng 一致；用实际发送的 ser，fuzz 一致）
                    let header = format!(
                        "packet {idx}/{total}  [{}]",
                        match source {
                            PacketSource::Default => "default export".to_string(),
                            PacketSource::Export(name) => format!("export \"{name}\""),
                        }
                    );
                    if crate::engine::eng::render_packet_fields(w, pkt, &header, ser).is_err() {
                        // 序列化失败：退回简版 stack 行（发送环节会再报错）
                        let stack: Vec<&str> = pkt
                            .layers
                            .iter()
                            .map(crate::engine::eng::layer_name)
                            .collect();
                        print_dim(w, format!("{}stack: {}", indent(1), stack.join(" -> ")))?;
                        writeln!(w)?;
                    }
                    // 层序咨询性警告（只提示不阻断）：如 tcp 是 udp 的载荷、缺网络层等
                    crate::engine::eng::print_stack_warnings(w, pkt)?;
                }

                let extracted = extract_payload_with(pkt, ser);
                // 无 TCP/UDP 传输且最外层也不是可 raw 发送的 eth/ipv4/ipv6 → 纯裸层导出
                // （如 `dns_query = dns(...)`、裸 `req = arp(...)` 之类仅作 --eng 展示/组合
                // 的元件），payload 与 raw 模式一致跳过并黄字提示，不视为发送失败。
                let raw_sendable_outer = raw_sendable_outer(pkt);
                if extracted.is_none() && !raw_sendable_outer {
                    skipped += 1;
                    if json {
                        let mut m = pkt_json_base(idx, total, source, pkt);
                        m.insert("status".into(), json!("skipped"));
                        m.insert("error".into(), Value::Null);
                        json_line(w, m)?;
                    } else if !opts.summary {
                        bare_export_seen += 1;
                        if bare_export_seen == 1 {
                            print_orange(
                                w,
                                format!("{}{}", indent(1), t!("engine.note_bare_export")),
                            )?;
                        } else {
                            print_orange(
                                w,
                                format!("{}{}", indent(1), t!("engine.note_bare_export_short")),
                            )?;
                        }
                        writeln!(w)?;
                        writeln!(w)?;
                    }
                    continue;
                }
                let is_raw = matches!(opts.mode, SendMode::Raw { .. }) || extracted.is_none();
                if !json
                    && !opts.summary
                    && extracted.is_none()
                    && !matches!(opts.mode, SendMode::Raw { .. })
                {
                    raw_fallback_seen += 1;
                    if raw_fallback_seen == 1 {
                        print_orange(
                            w,
                            format!(
                                "{}{}",
                                indent(1),
                                t!(
                                    "engine.note_raw_fallback",
                                    hint = crate::util::privilege_hint()
                                )
                            ),
                        )?;
                    } else {
                        print_orange(
                            w,
                            format!("{}{}", indent(1), t!("engine.note_raw_fallback_short")),
                        )?;
                    }
                    writeln!(w)?;
                }
                // 目标：显式指定 > 包内 IP 层 dst 推导；raw 链路层帧（eth 外层、无 IP 层可
                // 推导目标，如 ARP）放行 None——AF_PACKET 按帧内目的 MAC 直发，目标仅用于
                // IP 源地址填充/代理诊断等旁路逻辑。其余失败（ipv4/ipv6 dst 缺失或 random、
                // 外层不是 eth/ipv4/ipv6）逐包报错。
                let target: Option<SocketAddr> = match resolve_send_target(pkt, is_raw, opts.target)
                {
                    Ok((t, Some(note))) => {
                        if !json && !opts.summary {
                            print_dim(w, format!("{}target: {note}", indent(1)))?;
                            writeln!(w)?;
                        }
                        t
                    }
                    Ok((t, None)) => t,
                    Err(e) => {
                        failed += 1;
                        if json {
                            let mut m = pkt_json_base(idx, total, source, pkt);
                            m.insert("status".into(), json!("failed"));
                            m.insert("target".into(), Value::Null);
                            m.insert("error".into(), json!(e));
                            json_line(w, m)?;
                        } else {
                            crate::output::writeln_red(w, format!("{}✗ {e}", indent(1)))?;
                        }
                        continue;
                    }
                };
                // 代理 fake-ip 诊断：目标在 198.18.0.0/15（Clash 等 fake-ip 段）时，
                // eth 原始帧绕过代理直发物理网卡，公网不可达（bare-ip 走内核路由/代理可达）。
                let is_eth_frame = matches!(pkt.layers.last(), Some(Layer::Ethernet(_)));
                if !json
                    && !opts.summary
                    && is_raw
                    && is_eth_frame
                    && let Some(t) = target
                    && is_fake_ip(t.ip())
                {
                    print_orange(
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
                    let (mut bytes, parts) =
                        ser.serialize_parts(pkt).map_err(anyhow::Error::from)?;
                    if ip_src_zero(&pkt.layers) {
                        // 链路层帧无目标（None）时无法路由探测本地源地址 → src_warn
                        match target.as_ref().and_then(local_ip_for) {
                            Some(local)
                                if patch_zero_src(&mut bytes, &parts, &pkt.layers, local) =>
                            {
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
                // 完整包字节：--out 存档 / sent.extract / 摘要层栈共用同一份——
                // 每包只序列化一次，随机字段（IP ID / sport）不重复消费，三者与
                // 实发字节一致（此前 --out 用独立序列化器、sent_full/摘要二次
                // 序列化，各自产出不同随机值，配方 extract sent.* 取到假字段）
                let full_bytes = if is_raw {
                    Some(shown.clone()) // raw：实发字节（已含零源填充）
                } else if on_sent.is_some() || opts.summary || out_archive.is_some() {
                    ser.serialize(pkt).ok() // payload：完整序列化（内核建头，仅存档/展示用）
                } else {
                    None
                };
                if let Some(a) = out_archive.as_deref_mut()
                    && let Some(fb) = &full_bytes
                {
                    if a.linktype.is_none() {
                        a.linktype = Some(crate::engine::pcap::linktype_of(&pkt.layers));
                    }
                    a.bytes.push(fb.clone());
                }
                // sniffer：发包字节反解（SentField 引用来源；raw = 完整包，payload = 载荷）
                let sent_report = sniffer.as_ref().map(|_| packet_dsl::dissect(&shown));
                // 发包完整字节：`extract from: sent.<层>.<字段>` 的来源（payload 模式
                // 实际只发载荷，但 .pkt 定义的完整包字节才携带传输层头字段）
                if let (Some(cb), Some(full)) = (on_sent.as_mut(), full_bytes.as_deref()) {
                    cb(full);
                }
                if opts.summary {
                    // 摘要模式：每包一行紧凑层栈（内→外，与 DSL `|>` 管道一致）；
                    // payload 模式的 `shown` 只是载荷，栈描述需完整包字节
                    let full = full_bytes.as_deref().unwrap_or(&shown);
                    print_cyan(w, format!("{}{}", indent(1), stack_summary(pkt, full)))?;
                    writeln!(w)?;
                }
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
                        wait_secs,
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
                        wait_secs,
                        sniffer.as_ref(),
                        sent_report.as_ref(),
                    )
                };
                if !json && !opts.summary {
                    if let Some(ip) = src_note {
                        if is_eth_frame && is_fake_ip(ip) {
                            // 路由探测拿到的是代理 fake-ip 网关地址：eth 原始帧绕过代理直发，
                            // 真实网关 ingress 过滤会丢弃该源地址
                            print_orange(
                                w,
                                format!("{}{}", indent(1), t!("engine.note_fakeip_src", ip = ip)),
                            )?;
                            writeln!(w)?;
                        } else {
                            print_orange(
                                w,
                                format!("{}{}", indent(1), t!("engine.note_src_filled", ip = ip)),
                            )?;
                            writeln!(w)?;
                        }
                    } else if src_warn {
                        print_orange(
                            w,
                            format!("{}{}", indent(1), t!("engine.note_src_unfillable")),
                        )?;
                        writeln!(w)?;
                    }
                }
                match result {
                    Ok(outcome) => {
                        // 回包回调（配方 extract 依赖）先统一执行，json/文本两路共用
                        if let Some(Reply { bytes, .. }) = &outcome.reply
                            && let Some(cb) = on_reply.as_mut()
                        {
                            cb(bytes);
                        }
                        if json {
                            let mut m = pkt_json_base(idx, total, source, pkt);
                            m.insert("status".into(), json!("sent"));
                            m.insert("proto".into(), json!(outcome.proto));
                            m.insert("bytes".into(), json!(outcome.sent));
                            m.insert("received".into(), json!(outcome.received));
                            m.insert("target".into(), json!(fmt_target(target)));
                            m.insert(
                                "rtt_ms".into(),
                                json!(outcome.reply.as_ref().map(|r| r.rtt)),
                            );
                            m.insert("reply".into(), match &outcome.reply {
                            Some(Reply { rtt: _, bytes, matched }) => json!({
                                "bytes": bytes.len(),
                                "hex": hex_str(bytes),
                                "matched": matched.as_ref().map(|pairs| {
                                    pairs.iter().map(|(k, v)| (k.clone(), json!(v))).collect::<Map<String, Value>>()
                                }),
                            }),
                            None => Value::Null,
                        });
                            json_line(w, m)?;
                        } else {
                            // 发送结果行：摘要与完整模式都显示
                            print_green(
                                w,
                                format!(
                                    "{}{} → {} sent {} B{}",
                                    indent(1),
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
                            if !opts.summary && !shown.is_empty() {
                                print_cyan(w, format!("{}sent:", indent(1)))?;
                                writeln!(w)?;
                                render_hexdump(w, &shown)?;
                            }
                            match &outcome.reply {
                                Some(Reply {
                                    rtt,
                                    bytes,
                                    matched,
                                }) => {
                                    if opts.summary {
                                        // 摘要模式：只显示 RTT，跳过字段匹配详情与回包反解
                                        if matched.is_some() {
                                            print_green(
                                                w,
                                                format!("{}✓ reply ({rtt:.3} ms)", indent(1)),
                                            )?;
                                        } else {
                                            print_cyan(
                                                w,
                                                format!("{}reply ({rtt:.3} ms)", indent(1)),
                                            )?;
                                        }
                                        writeln!(w)?;
                                    } else {
                                        if let Some(fields) = matched {
                                            let pairs: Vec<String> = fields
                                                .iter()
                                                .map(|(k, v)| format!("{k}={v}"))
                                                .collect();
                                            print_green(
                                                w,
                                                format!(
                                                    "  ✓ reply matched: {} ({rtt:.3} ms)",
                                                    pairs.join(" ")
                                                ),
                                            )?;
                                            writeln!(w)?;
                                        } else {
                                            print_cyan(
                                                w,
                                                format!("{}reply after {rtt:.3} ms", indent(1)),
                                            )?;
                                            writeln!(w)?;
                                        }
                                        if !bytes.is_empty() {
                                            let report = packet_dsl::dissect(bytes);
                                            crate::engine::eng::render_dissected(
                                                w, &report, "  reply:", bytes,
                                            )?;
                                        }
                                    }
                                }
                                None => {
                                    // wait=0 是「发送后不读」语义，不是 0 秒等待——
                                    // 不打印误导性的「no reply within 0s」
                                    if let Some(secs) = wait_secs.filter(|s| *s > 0.0) {
                                        let what = if sniffer.is_some() {
                                            "matching reply"
                                        } else {
                                            "reply"
                                        };
                                        writeln_red(
                                            w,
                                            format!("{}✗ no {what} within {secs}s", indent(1)),
                                        )?;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        failed += 1;
                        if json {
                            let mut m = pkt_json_base(idx, total, source, pkt);
                            m.insert("status".into(), json!("failed"));
                            m.insert("target".into(), json!(fmt_target(target)));
                            m.insert("error".into(), json!(e.to_string()));
                            json_line(w, m)?;
                        } else {
                            crate::output::writeln_red(w, format!("{}✗ {e}", indent(1)))?;
                        }
                    }
                }
                if !json && !opts.summary {
                    writeln!(w)?;
                }
            }
        }
    }
    Ok(SendStats {
        total: idx,
        failed,
        skipped,
    })
}

/// 摘要模式：紧凑层栈描述（内 → 外，与 DSL `|>` 管道一致），如
/// `<dns id=0x1234 q=example.com(A) |> / <udp sport=12345 dport=53 |> / <ipv4 src=... dst=... |>`。
///
/// 层身份来自构造的 `PacketSpec`（DSL 声明即真相：http/dns 等应用层不会因反解
/// 的端口规则未命中而退化 raw）；头层字段值从实际序列化字节反解（auto 填充/
/// 源地址补齐后的真实值，如 ttl/proto/随机端口）。反解层栈为外 → 内。
fn stack_summary(pkt: &PacketSpec, bytes: &[u8]) -> String {
    let report = packet_dsl::dissect(bytes);
    // 反解层栈外 → 内，反转成内 → 外；按 kind 逐层取真实值（头层）
    let mut d_iter = report.layers.iter().rev();
    pkt.layers
        .iter()
        .map(|spec| {
            // 语义应用层（http/dns）与 raw：身份以 spec 为准（反解按端口规则分派，
            // 认不出 http 挂在 1234 等非标准端口、裸 proto 也只剩 raw）；
            // 头层：取同 kind 的反解层（真实序列化值），无则回退 spec。
            let l = match spec {
                Layer::Http(_) | Layer::Dns(_) | Layer::Raw(_) => spec,
                _ => d_iter
                    .find(|d| {
                        crate::engine::eng::layer_name(d) == crate::engine::eng::layer_name(spec)
                    })
                    .unwrap_or(spec),
            };
            layer_summary(l)
        })
        .collect::<Vec<_>>()
        .join(" / ")
}

/// 一层 → `<层名 字段=值 ... |>`。
fn layer_summary(l: &Layer) -> String {
    let name = crate::engine::eng::layer_name(l);
    let mut parts: Vec<String> = Vec::new();
    match l {
        Layer::Ethernet(_) => push_fields(l, &mut parts, &["dst", "src"]),
        Layer::Arp(_) => push_fields(l, &mut parts, &["op", "spa", "tpa"]),
        Layer::Ipv4(_) => push_fields(l, &mut parts, &["src", "dst", "ttl", "proto"]),
        Layer::Ipv6(_) => push_fields(l, &mut parts, &["src", "dst", "hop_limit"]),
        Layer::Icmp(_) => push_fields(l, &mut parts, &["type", "code", "id", "seq"]),
        Layer::Tcp(_) => push_fields(l, &mut parts, &["sport", "dport", "flags"]),
        Layer::Udp(_) => push_fields(l, &mut parts, &["sport", "dport"]),
        Layer::Http(f) => {
            // 与 `--eng`/非摘要视图一致：method/path/version + headers/body 计数
            push_fields(l, &mut parts, &["method", "path", "version"]);
            parts.push(format!("headers={}", f.headers.len()));
            parts.push(format!(
                "body={} B",
                crate::engine::eng::opt_bytes_len(&f.body)
            ));
        }
        Layer::Dns(f) => {
            // id/flags 用十六进制（与 --eng 展示一致）；sniffer_extract 给十进制
            if let Some(id) = f.id {
                parts.push(format!("id=0x{id:04x}"));
            }
            if let Some(fl) = f.flags {
                parts.push(format!("flags=0x{fl:04x}"));
            }
            for q in &f.questions {
                let qt = q
                    .qtype
                    .map(|t| format!("({})", crate::engine::eng::dns_type_name(Some(t))))
                    .unwrap_or_default();
                parts.push(format!("q={}{qt}", q.name));
            }
            if !f.answers.is_empty() {
                parts.push(format!("ans={}", f.answers.len()));
            }
        }
        Layer::Raw(d) => parts.push(format!("bytes={} B", d.bytes.len())),
    }
    format!("<{name} {} |>", parts.join(" "))
}

/// 按字段名从反解层取值（`sniffer_extract` 的字段集）追加 `字段=值`。
fn push_fields(l: &Layer, out: &mut Vec<String>, names: &[&str]) {
    for n in names {
        if let Some(v) = sniffer_extract(l, n) {
            out.push(format!("{n}={}", v.display()));
        }
    }
}

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
pub(crate) fn fmt_target(t: Option<SocketAddr>) -> String {
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
pub fn raw_only(pkt: &PacketSpec) -> bool {
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
    match transport {
        Transport::Tcp => {
            let t0 = std::time::Instant::now();
            let mut conn = TcpStream::connect(target)?;
            // wait=0（--wait 0 / 监听发送段先行）：纯发送不读回显（此前仍读满
            // 默认 2s，与 listen 注释「立即超时」相悖）；wait>0 用请求秒数；
            // wait=None 用默认 2s
            conn.set_read_timeout(match wait {
                Some(secs) if secs > 0.0 => Some(Duration::from_secs_f64(secs)),
                Some(_) => None, // wait=0：不读，无需超时
                None => Some(Duration::from_secs(2)),
            })?;
            conn.write_all(payload)?;
            let _ = conn.shutdown(Shutdown::Write);
            let (received, reply) = match wait {
                Some(secs) if secs > 0.0 => {
                    // RTT 含回显接收耗时（此前在 write 后、read_all 前采样，与
                    // UDP/raw 路径的「收到匹配回包才计时」口径不一致）
                    let body = read_all(&mut conn)?;
                    let t_conn = t0.elapsed();
                    let received = body.len();
                    // 应答 body 已在 read_all 里读完；继续排空余量（原 read_echo 语义）
                    let _ = read_all(&mut conn);
                    let reply = if received > 0 {
                        // 回显字节保留在 Reply.bytes（配方 extract 需要）
                        Some(Reply {
                            rtt: t_conn.as_secs_f64() * 1000.0,
                            bytes: body,
                            matched: None, // TCP 回显无独立字节，sniffer 不适用
                        })
                    } else {
                        None
                    };
                    (received, reply)
                }
                // wait=0：发送后不读（与 UDP 分支一致）
                Some(_) => (0, None),
                None => {
                    // 无 --wait：读回显（默认 2s 超时）但不设 reply（原语义）
                    let body = read_all(&mut conn)?;
                    let received = body.len();
                    if received > 0 {
                        let _ = read_all(&mut conn);
                    }
                    (received, None)
                }
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
                Some(secs) if secs > 0.0 => {
                    sock.set_read_timeout(Some(Duration::from_secs_f64(secs)))?;
                    match wait_udp_reply(&sock, payload, sniffer, sent_report)? {
                        Some((rtt, bytes, matched)) => (
                            bytes.len(),
                            Some(Reply {
                                rtt,
                                bytes,
                                matched,
                            }),
                        ),
                        None => (0, None),
                    }
                }
                // wait=0（`--wait 0` / 监听发送段先行）：发送后不读
                Some(_) => (0, None),
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
                    if let Some(fields) = sn.matches(&data, sent_report) {
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
                    // 按实际 IHL 重算校验和（此前固定 20 字节头——带 IP 选项
                    // 的包（IHL>5）重算结果错误、接收方丢弃）
                    let ihl = ((seg[0] & 0x0F) * 4) as usize;
                    if seg.len() < ihl {
                        return false;
                    }
                    let c = packet_dsl::serialize::checksum(&seg[..ihl]);
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
