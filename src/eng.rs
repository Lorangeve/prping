//! 引擎模式（`--eng`）：.pkt 分析的精美输出 + LSP 语言服务器（`--eng --lsp`）。
//!
//! - 精美输出：模块概览 → 逐来源逐包展示层栈（字段 + auto 标注）→ 字节 hexdump（带 ASCII）。
//! - LSP：JSON-RPC over stdio（Content-Length 分帧），提供诊断 / 补全 / 悬停 / 文档符号。

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use packet_dsl::diag::Diagnostic;
use packet_dsl::ir::{Layer, MacAddr, PacketSpec};
use packet_dsl::registry::builtin_doc;
use packet_dsl::semantic::Module;
use packet_dsl::{DefaultSerializer, PacketSource};
use serde_json::{Value, json};
use termcolor::{ColorChoice, StandardStream, WriteColor};

use crate::output::{print_cyan, print_dim, print_green, print_magenta, print_yellow};

/// DSL 值 → 展示字符串（函数参数默认值渲染 / sniffer 字面量用）。
pub fn value_display(v: &packet_dsl::ast::Value) -> String {
    match v {
        packet_dsl::ast::Value::Str(s) => format!("\"{s}\""),
        packet_dsl::ast::Value::Int(i) => i.to_string(),
        packet_dsl::ast::Value::Hex(h) => format!("0x{h:X}"),
        packet_dsl::ast::Value::Bool(b) => b.to_string(),
        packet_dsl::ast::Value::List(items) => {
            let inner: Vec<String> = items.iter().map(value_display).collect();
            format!("[{}]", inner.join(", "))
        }
        packet_dsl::ast::Value::Param { name, default } => match default {
            Some(d) => format!("params(\"{name}\", \"{d}\")"),
            None => format!("params(\"{name}\")"),
        },
        packet_dsl::ast::Value::Ident { name, .. } => name.clone(),
        packet_dsl::ast::Value::Call { name, args, .. } => {
            let inner: Vec<String> = args.iter().map(value_display).collect();
            format!("{name}({})", inner.join(", "))
        }
        packet_dsl::ast::Value::Add { left, right, .. } => {
            format!("{} + {}", value_display(left), value_display(right))
        }
    }
}

// ══════════════════════════════════════════════════════════════
// 精美输出
// ══════════════════════════════════════════════════════════════

/// `FuncDoc` → markdown 正文（摘要段落 + auto 说明；供 LSP 悬停）。
fn doc_markdown(doc: &packet_dsl::ast::FuncDoc) -> String {
    let mut md = String::new();
    if !doc.summary.is_empty() {
        md.push_str(&format!("{}\n\n", doc.summary));
    }
    if let Some(auto) = &doc.auto {
        md.push_str(&format!("**auto**：{auto}\n\n"));
    }
    md
}

/// `--eng --ls`：列出全部内置原语与库层头函数的字段表（对标 scapy `ls()`）。
pub fn ls_builtins(libs: &[std::path::PathBuf]) -> anyhow::Result<()> {
    let libs = effective_libs(libs);
    let mut w = StandardStream::stdout(ColorChoice::Auto);
    print_magenta(&mut w, "packet-dsl builtins")?;
    writeln!(&mut w)?;
    print_dim(&mut w, format!("libs: {}", libs_display(&libs)))?;
    writeln!(&mut w)?;
    writeln!(&mut w)?;
    for doc in packet_dsl::builtin_docs() {
        let params: Vec<String> = doc
            .params
            .iter()
            .map(|(n, t)| format!("{n}: {t}"))
            .collect();
        print_cyan(&mut w, format!("{}({})", doc.name, params.join(", ")))?;
        writeln!(&mut w)?;
        for (n, t) in &doc.params {
            print_dim(&mut w, format!("    {n}: {t}"))?;
            writeln!(&mut w)?;
        }
        print_yellow(&mut w, format!("    auto: {}", doc.auto))?;
        writeln!(&mut w)?;
    }
    // 库层头函数（eng_lib，隐式可见）：列签名
    let funcs = packet_dsl::lib_exports(&libs)
        .into_iter()
        .filter(|e| e.params.is_some())
        .collect::<Vec<_>>();
    if !funcs.is_empty() {
        print_magenta(&mut w, "\neng_lib layer functions")?;
        writeln!(&mut w)?;
        for e in funcs {
            let ps: Vec<String> = e
                .params
                .as_ref()
                .unwrap()
                .iter()
                .map(|p| match &p.default {
                    Some(d) => format!("{}={}", p.name, value_display(d)),
                    None => p.name.clone(),
                })
                .collect();
            print_cyan(&mut w, format!("{}({})", e.name, ps.join(", ")))?;
            writeln!(&mut w)?;
            if let Some(doc) = &e.doc {
                // doc 摘要：签名下第一行，"""...""" 文档字符串（多行摘要整体包裹）
                if !doc.summary.is_empty() {
                    print_dim(&mut w, "    \"\"\"")?;
                    writeln!(&mut w)?;
                    for line in doc.summary.lines() {
                        print_dim(&mut w, format!("    {line}"))?;
                        writeln!(&mut w)?;
                    }
                    print_dim(&mut w, "    \"\"\"")?;
                    writeln!(&mut w)?;
                }
                // 逐参数说明：按声明顺序，只列有 @param 说明的参数
                for p in e.params.as_ref().unwrap() {
                    if let Some((_, desc)) = doc.params.iter().find(|(n, _)| n == &p.name) {
                        print_dim(&mut w, format!("    {}: {desc}", p.name))?;
                        writeln!(&mut w)?;
                    }
                }
                if let Some(auto) = &doc.auto {
                    print_yellow(&mut w, format!("    auto: {auto}"))?;
                    writeln!(&mut w)?;
                }
            }
            print_dim(&mut w, format!("    [{}] 库函数（隐式可见）", e.module))?;
            writeln!(&mut w)?;
        }
    }
    Ok(())
}

/// `--eng --hex <hex>`：反解并展示十六进制字节（对标 scapy `Ether(bytes)` + `show()`）。
pub fn decode_hex(hex: &str) -> anyhow::Result<()> {
    let hex_str: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if !hex_str.len().is_multiple_of(2) || !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("--hex 需要偶数长度的十六进制字符串");
    }
    let bytes = (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).expect("已校验 hex"))
        .collect::<Vec<_>>();
    let report = packet_dsl::dissect(&bytes);
    let mut w = StandardStream::stdout(ColorChoice::Auto);
    print_magenta(&mut w, "packet-dsl dissect")?;
    writeln!(&mut w)?;
    render_dissected(&mut w, &report, &format!("{} bytes", bytes.len()), &bytes)
        .map_err(anyhow::Error::from)
}

/// `--eng --pcap <file>`：读 pcap 并逐条反解展示。
pub fn decode_pcap(path: &Path) -> anyhow::Result<()> {
    let (network, nano, records) = crate::pcap::read_pcap(path)?;
    let mut w = StandardStream::stdout(ColorChoice::Auto);
    print_magenta(&mut w, "packet-dsl pcap")?;
    writeln!(&mut w)?;
    print_dim(
        &mut w,
        format!(
            "file: {}  linktype: {}  records: {}",
            path.display(),
            network,
            records.len()
        ),
    )?;
    writeln!(&mut w)?;
    writeln!(&mut w)?;
    for (i, rec) in records.iter().enumerate() {
        let ts = if nano {
            format!("{}.{:09}", rec.ts_sec, rec.ts_frac)
        } else {
            format!("{}.{:06}", rec.ts_sec, rec.ts_frac)
        };
        let report = packet_dsl::dissect(&rec.data);
        render_dissected(
            &mut w,
            &report,
            &format!("record {}/{}  [t={ts}]", i + 1, records.len()),
            &rec.data,
        )?;
    }
    Ok(())
}

/// 分析一个 .pkt 文件并输出完整可视化（`--eng FILE`）。
pub fn analyze_file(
    path: &Path,
    params: &[(String, String)],
    libs: &[std::path::PathBuf],
) -> anyhow::Result<()> {
    ensure_dns_resolver();
    let module =
        packet_dsl::parse_file_with_libs(path, libs).map_err(|d| anyhow::anyhow!("{d}"))?;
    let p: packet_dsl::Params = params.iter().cloned().collect();
    let sources =
        packet_dsl::resolve_sources_with_params(&module, &p).map_err(|d| anyhow::anyhow!("{d}"))?;
    let total: usize = sources.iter().map(|(_, p)| p.len()).sum();
    if total == 0 {
        anyhow::bail!("没有可求值的包：文件既无默认导出，也无命名导出");
    }

    let mut w = StandardStream::stdout(ColorChoice::Auto);
    let libs = effective_libs(libs);
    render_module_header(&mut w, &module, total, &libs)?;
    let mut idx = 0usize;
    for (source, pkts) in &sources {
        for pkt in pkts {
            idx += 1;
            render_packet(
                &mut w,
                pkt,
                &format!(
                    "packet {idx}/{total}  [{}]",
                    match source {
                        PacketSource::Default => "default export".to_string(),
                        PacketSource::Export(name) => format!("export \"{name}\""),
                    }
                ),
            )?;
        }
    }
    Ok(())
}

/// 注入默认 DNS 解析器（ToSocketAddrs，v4 优先）；进程级，首个生效。
/// `dns("host")` 原语与地址字段的域名解析依赖它（packet-dsl 本身不发网络请求）。
pub fn ensure_dns_resolver() {
    packet_dsl::set_dns_resolver(|host| {
        use std::net::ToSocketAddrs;
        let mut addrs: Vec<std::net::SocketAddr> = (host, 0)
            .to_socket_addrs()
            .ok()
            .map(|it| it.collect())
            .unwrap_or_default();
        addrs.sort_by_key(|a| u8::from(a.is_ipv6())); // v4 优先
        addrs.into_iter().map(|a| a.ip()).collect()
    });
}

/// 实际生效的库目录 = 默认 eng_lib（编译期路径，发布态可能为空）+ 显式 libs。
/// 与 `parse_file_with_libs` 内部合并顺序一致（默认在前、显式追加）。
pub fn effective_libs(libs: &[PathBuf]) -> Vec<PathBuf> {
    let mut all = packet_dsl::default_libs();
    all.extend_from_slice(libs);
    all
}

/// 库目录列表的展示字符串（空 → `(none)`；路径做 canonicalize）。
pub fn libs_display(libs: &[PathBuf]) -> String {
    if libs.is_empty() {
        "(none)".to_string()
    } else {
        libs.iter()
            .map(|p| {
                std::fs::canonicalize(p)
                    .unwrap_or_else(|_| p.clone())
                    .display()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// 渲染模块概览：module/exports/defs/funcs/packets + 实际生效的库目录。
fn render_module_header<W: WriteColor>(
    w: &mut W,
    module: &Module,
    total: usize,
    libs: &[PathBuf],
) -> io::Result<()> {
    print_magenta(w, "packet-dsl engine")?;
    writeln!(w)?;
    print_cyan(w, "module: ")?;
    print_bold_plain(w, &module.name)?;
    if let Some(path) = &module.path {
        print_dim(w, format!("  (file: {})", path.display()))?;
    }
    writeln!(w)?;
    if !module.imports.is_empty() {
        let imps: Vec<String> = module
            .imports
            .iter()
            .map(|i| match &i.names {
                Some(names) => format!(
                    "{} {{ {} }}",
                    i.module,
                    names
                        .iter()
                        .map(|(n, alias, _)| match alias {
                            Some(a) => format!("{n} as {a}"),
                            None => n.clone(),
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => i.module.clone(),
            })
            .collect();
        print_dim(w, format!("imports: {}   ", imps.join(", ")))?;
    }
    if !module.exports.is_empty() {
        let exps: Vec<&str> = module.exports.iter().map(|(n, _)| n.as_str()).collect();
        print_dim(w, format!("exports: {}   ", exps.join(", ")))?;
    }
    if module.default.is_some() {
        print_dim(w, "default: yes")?;
    }
    writeln!(w)?;
    if !module.defs.is_empty() {
        let defs: Vec<&str> = module.defs.iter().map(|d| d.name.as_str()).collect();
        print_dim(w, format!("defs: {}", defs.join(", ")))?;
        writeln!(w)?;
    }
    if !module.funcs.is_empty() {
        for f in &module.funcs {
            let params: Vec<String> = f
                .params
                .iter()
                .map(|p| match &p.default {
                    Some(d) => format!("{}={}", p.name, value_display(d)),
                    None => p.name.clone(),
                })
                .collect();
            print_dim(w, format!("func {}({})", f.name, params.join(", ")))?;
            writeln!(w)?;
        }
    }
    print_dim(w, format!("packets: {total}"))?;
    writeln!(w)?;
    if let Some(sn) = &module.sniffer {
        print_dim(w, "sniffer:")?;
        writeln!(w)?;
        for clause in &sn.clauses {
            let fields: Vec<String> = clause
                .fields
                .iter()
                .map(|(name, v)| match v {
                    packet_dsl::SnifferValue::Literal(l) => {
                        format!("{name}={}", value_display(l))
                    }
                    packet_dsl::SnifferValue::SentField(f) => format!("{name}={f}"),
                })
                .collect();
            print_dim(
                w,
                format!("  - match {}({})", clause.layer, fields.join(", ")),
            )?;
            writeln!(w)?;
        }
    }
    print_dim(w, format!("libs: {}", libs_display(libs)))?;
    writeln!(w)?;
    writeln!(w)?;
    Ok(())
}

/// 渲染层栈（字段 + auto/random 标注）。
pub fn render_layers<W: WriteColor>(w: &mut W, layers: &[Layer], header: &str) -> io::Result<()> {
    print_cyan(w, header)?;
    writeln!(w)?;
    for (i, layer) in layers.iter().enumerate() {
        print_dim(w, format!("  [{i}] "))?;
        print_green(w, layer_name(layer))?;
        let desc = describe_layer(layer);
        if !desc.is_empty() {
            print_yellow(w, format!("  {desc}"))?;
        }
        writeln!(w)?;
    }
    Ok(())
}

/// 层字段渲染（无 hexdump）：`--eng` 与 `--pkg` 复用。
///
/// 每层字段：字节直喂层从「该层序列化后的字节」解析（len/checksum/proto 真实值，
/// 对标 scapy `Ether(bytes)`）；语义层（无 raw）用 IR 字段 + auto 标注。
/// `ser` 由调用方传入（`--pkg` 传实际发送用的序列化器，fuzz 与发送一致）。
/// 返回完整包字节（供调用方决定是否 hexdump）。
pub fn render_packet_fields<W: WriteColor>(
    w: &mut W,
    pkt: &PacketSpec,
    header: &str,
    ser: &DefaultSerializer,
) -> io::Result<Vec<u8>> {
    let (bytes, parts) = ser.serialize_parts(pkt).map_err(io::Error::other)?;
    print_cyan(w, header)?;
    writeln!(w)?;
    for (i, layer) in pkt.layers.iter().enumerate() {
        print_dim(w, format!("  [{i}] "))?;
        print_green(w, layer_name(layer))?;
        let desc = if layer_raw(layer).is_some() {
            // 该层在序列化结果中的区间（内→外）；外层包含内层，取自身头部分
            let seg = parts.get(i).map(|&(s, e)| &bytes[s..e]);
            match seg {
                Some(seg) => describe_raw_bytes(layer, seg),
                None => describe_layer(layer),
            }
        } else {
            describe_layer(layer)
        };
        if !desc.is_empty() {
            print_yellow(w, format!("  {desc}"))?;
        }
        writeln!(w)?;
    }
    print_dim(w, format!("  bytes: {} B", bytes.len()))?;
    writeln!(w)?;
    Ok(bytes)
}

/// 渲染一个包：层栈字段（从序列化后的真实字节解析）+ 字节 hexdump。
pub fn render_packet<W: WriteColor>(w: &mut W, pkt: &PacketSpec, header: &str) -> io::Result<()> {
    let ser = DefaultSerializer::new();
    let bytes = render_packet_fields(w, pkt, header, &ser)?;
    render_hexdump(w, &bytes)?;
    writeln!(w)?;
    Ok(())
}

/// 渲染反解报告（层栈 + 注记 + hexdump）。
pub fn render_dissected<W: WriteColor>(
    w: &mut W,
    report: &packet_dsl::dissect::DissectReport,
    header: &str,
    bytes: &[u8],
) -> io::Result<()> {
    if report.layers.is_empty() {
        print_red_plain(w, &format!("{header} — 未能识别任何层"))?;
        writeln!(w)?;
    } else {
        render_layers(w, &report.layers, header)?;
    }
    for n in &report.notes {
        print_yellow(w, format!("  note: {n}"))?;
        writeln!(w)?;
    }
    if !report.remaining.is_empty() {
        print_dim(w, format!("  remaining: {} B", report.remaining.len()))?;
        writeln!(w)?;
    }
    if !bytes.is_empty() {
        render_hexdump(w, bytes)?;
    }
    writeln!(w)?;
    Ok(())
}

fn print_red_plain<W: WriteColor>(w: &mut W, text: &str) -> io::Result<()> {
    w.set_color(termcolor::ColorSpec::new().set_fg(Some(termcolor::Color::Red)))?;
    write!(w, "{text}")?;
    w.reset()
}

fn print_bold_plain<W: WriteColor>(w: &mut W, text: &str) -> io::Result<()> {
    w.set_color(termcolor::ColorSpec::new().set_bold(true))?;
    write!(w, "{text}")?;
    w.reset()
}

/// 16 字节一行的 hexdump：偏移 + hex + ASCII。
pub fn render_hexdump<W: WriteColor>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    for (off, chunk) in bytes.chunks(16).enumerate() {
        print_dim(w, format!("  {off:04x}  "))?;
        let mut hex = String::new();
        let mut ascii = String::new();
        for b in chunk {
            hex.push_str(&format!("{b:02x} "));
            ascii.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        for _ in chunk.len()..16 {
            hex.push_str("   ");
        }
        write!(w, "{hex} ")?;
        print_green(w, format!("|{ascii}|"))?;
        writeln!(w)?;
    }
    Ok(())
}

pub(crate) fn layer_name(l: &Layer) -> &'static str {
    match l {
        Layer::Ethernet(_) => "eth",
        Layer::Arp(_) => "arp",
        Layer::Ipv4(_) => "ipv4",
        Layer::Ipv6(_) => "ipv6",
        Layer::Icmp(_) => "icmp",
        Layer::Tcp(_) => "tcp",
        Layer::Udp(_) => "udp",
        Layer::Http(_) => "http",
        Layer::Dns(_) => "dns",
        Layer::Raw(_) => "raw",
    }
}

/// 层字段描述：用户填的值直接显示，未填字段标 `auto`。
/// 层头 bytes= 直喂的原始字节（无则 None）。
fn layer_raw(l: &Layer) -> Option<&[u8]> {
    match l {
        Layer::Ethernet(f) => f.raw.as_deref(),
        Layer::Arp(f) => f.raw.as_deref(),
        Layer::Ipv4(f) => f.raw.as_deref(),
        Layer::Ipv6(f) => f.raw.as_deref(),
        Layer::Icmp(f) => f.raw.as_deref(),
        Layer::Tcp(f) => f.raw.as_deref(),
        Layer::Udp(f) => f.raw.as_deref(),
        Layer::Http(f) => f.raw.as_deref(),
        Layer::Dns(f) => f.raw.as_deref(),
        Layer::Raw(_) => None,
    }
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 地址展示：域名解析来源时显示 `dns(host->ip)`，否则显示 IP。
fn addr_disp(host: &Option<String>, ip: String) -> String {
    match host {
        Some(h) => format!("dns({h}->{ip})"),
        None => ip,
    }
}

/// 从层头字节解析字段描述（scapy 风格：`<IP version=4 ihl=5 ...>`）。
/// 用于 bytes 直喂 / 反解层——字节是唯一真相，字段值从头部字节读。
fn describe_raw_bytes(l: &Layer, raw: &[u8]) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};
    match l {
        Layer::Ethernet(_) if raw.len() >= 14 => {
            let mac = |b: &[u8]| {
                b.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            };
            format!(
                "dst={} src={} ethertype=0x{:04x}",
                mac(&raw[0..6]),
                mac(&raw[6..12]),
                u16::from_be_bytes([raw[12], raw[13]])
            )
        }
        Layer::Arp(_) if raw.len() >= 28 => {
            let mac = |b: &[u8]| {
                b.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            };
            let ip = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string();
            format!(
                "op={} sha={} spa={} tha={} tpa={}",
                u16::from_be_bytes([raw[6], raw[7]]),
                mac(&raw[8..14]),
                ip(&raw[14..18]),
                mac(&raw[18..24]),
                ip(&raw[24..28])
            )
        }
        Layer::Ipv4(f) if raw.len() >= 20 => {
            let frag = u16::from_be_bytes([raw[6], raw[7]]);
            let proto = raw[9];
            let proto_name = match proto {
                1 => "ICMP".to_string(),
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                other => format!("{other}"),
            };
            let src = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]).to_string();
            let dst = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]).to_string();
            format!(
                "version={} ihl={} tos=0x{:02x} len={} id={} flags={} frag={} ttl={} proto={} chksum=0x{:04x} src={} dst={}",
                raw[0] >> 4,
                raw[0] & 0x0F,
                raw[1],
                u16::from_be_bytes([raw[2], raw[3]]),
                u16::from_be_bytes([raw[4], raw[5]]),
                if frag & 0x4000 != 0 { "DF" } else { "-" },
                frag & 0x1FFF,
                raw[8],
                proto_name,
                u16::from_be_bytes([raw[10], raw[11]]),
                addr_disp(&f.src_host, src),
                addr_disp(&f.dst_host, dst),
            )
        }
        Layer::Ipv6(f) if raw.len() >= 40 => {
            let nh = raw[6];
            let nh_name = match nh {
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                58 => "ICMPv6".to_string(),
                other => format!("{other}"),
            };
            let ip6 = |b: &[u8]| {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                Ipv6Addr::from(a).to_string()
            };
            let src = ip6(&raw[8..24]);
            let dst = ip6(&raw[24..40]);
            format!(
                "version={} traffic_class=0x{:02x} flow_label=0x{:05x} payload_len={} next_header={} hop_limit={} src={} dst={}",
                raw[0] >> 4,
                ((raw[0] & 0x0F) << 4) | (raw[1] >> 4),
                (((raw[1] & 0x0F) as u32) << 16) | ((raw[2] as u32) << 8) | raw[3] as u32,
                u16::from_be_bytes([raw[4], raw[5]]),
                nh_name,
                raw[7],
                addr_disp(&f.src_host, src),
                addr_disp(&f.dst_host, dst),
            )
        }
        Layer::Icmp(_) if raw.len() >= 8 => {
            // payload 长度从语义字段取（反解层载荷在 payload，非头部字节）
            let payload = match l {
                Layer::Icmp(f) => f
                    .payload
                    .as_ref()
                    .map(|p| format!(" payload={} B", p.len()))
                    .unwrap_or_default(),
                _ => String::new(),
            };
            format!(
                "type={} code={} chksum=0x{:04x} id={} seq={}{}",
                raw[0],
                raw[1],
                u16::from_be_bytes([raw[2], raw[3]]),
                u16::from_be_bytes([raw[4], raw[5]]),
                u16::from_be_bytes([raw[6], raw[7]]),
                payload
            )
        }
        Layer::Tcp(_) if raw.len() >= 20 => {
            let flags = raw[13];
            let mut fs = String::new();
            for (bit, name) in [
                (0x01, "FIN"),
                (0x02, "SYN"),
                (0x04, "RST"),
                (0x08, "PSH"),
                (0x10, "ACK"),
                (0x20, "URG"),
                (0x40, "ECE"),
                (0x80, "CWR"),
            ] {
                if flags & bit != 0 {
                    if !fs.is_empty() {
                        fs.push(',');
                    }
                    fs.push_str(name);
                }
            }
            format!(
                "sport={} dport={} seq={} ack={} dataofs={} flags={} window={} chksum=0x{:04x} urgptr={}",
                u16::from_be_bytes([raw[0], raw[1]]),
                u16::from_be_bytes([raw[2], raw[3]]),
                u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
                u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]),
                raw[12] >> 4,
                if fs.is_empty() { "-".to_string() } else { fs },
                u16::from_be_bytes([raw[14], raw[15]]),
                u16::from_be_bytes([raw[16], raw[17]]),
                u16::from_be_bytes([raw[18], raw[19]])
            )
        }
        Layer::Udp(_) if raw.len() >= 8 => format!(
            "sport={} dport={} len={} chksum=0x{:04x}",
            u16::from_be_bytes([raw[0], raw[1]]),
            u16::from_be_bytes([raw[2], raw[3]]),
            u16::from_be_bytes([raw[4], raw[5]]),
            u16::from_be_bytes([raw[6], raw[7]])
        ),
        _ => {
            // http/dns 或头部不足：回退 bytes=0x… 摘要
            let n = raw.len().min(12);
            format!("bytes=0x{}…", hex_str(&raw[..n]))
        }
    }
}

fn describe_layer(l: &Layer) -> String {
    // bytes= 直喂 / 反解层：从头部字节解析字段（scapy 风格）
    if let Some(raw) = layer_raw(l) {
        return describe_raw_bytes(l, raw);
    }
    match l {
        Layer::Ethernet(f) => format!(
            "src={} dst={} ethertype={}",
            field_mac(f.src_mac, "auto"),
            field_mac(f.dst_mac, "auto"),
            opt_hex(f.ethertype, "auto")
        ),
        Layer::Arp(f) => format!(
            "op={} sha={} spa={} tha={} tpa={}",
            opt(&f.op, "auto"),
            opt_mac(f.sha, "auto"),
            opt_ip4(f.spa, "auto"),
            opt_mac(f.tha, "auto"),
            opt_ip4(f.tpa, "auto")
        ),
        Layer::Ipv4(f) => format!(
            "src={} dst={} ttl={} proto={} tos={} id={} flags={}",
            field_ip4(f.src, "auto"),
            field_ip4(f.dst, "auto"),
            field_u8(f.ttl, "auto"),
            opt(&f.proto, "auto"),
            opt(&f.tos, "auto"),
            opt(&f.id, "auto"),
            opt_flags4(f.flags)
        ),
        Layer::Ipv6(f) => format!(
            "src={} dst={} hop_limit={} next_header={}",
            field_ip6(f.src, "auto"),
            field_ip6(f.dst, "auto"),
            field_u8(f.hop_limit, "auto"),
            opt(&f.next_header, "auto")
        ),
        Layer::Icmp(f) => format!(
            "type={} code={} id={} seq={} payload={} B",
            opt(&f.icmp_type, "auto"),
            opt(&f.code, "auto"),
            opt(&f.id, "auto"),
            opt(&f.seq, "auto"),
            opt_bytes_len(&f.payload)
        ),
        Layer::Tcp(f) => format!(
            "sport={} dport={} seq={} ack={} flags={} window={} mss={}",
            opt(&f.src_port, "auto"),
            opt(&f.dst_port, "auto"),
            opt(&f.seq, "auto"),
            opt(&f.ack, "auto"),
            opt_tcp_flags(f.flags),
            opt(&f.window, "auto"),
            match f.options.first() {
                Some(packet_dsl::ir::TcpOption::Mss(m)) => m.to_string(),
                None => "-".to_string(),
            }
        ),
        Layer::Udp(f) => format!(
            "sport={} dport={}",
            opt(&f.src_port, "auto"),
            opt(&f.dst_port, "auto")
        ),
        Layer::Http(f) => format!(
            "{} {} {} headers={} body={} B",
            f.method.clone().unwrap_or_else(|| "auto".to_string()),
            f.path.clone().unwrap_or_else(|| "auto".to_string()),
            f.version.clone().unwrap_or_else(|| "auto".to_string()),
            f.headers.len(),
            opt_bytes_len(&f.body)
        ),
        Layer::Dns(f) => format!(
            "id={} flags={} questions={} answers={}",
            opt(&f.id, "auto"),
            opt(&f.flags, "auto"),
            f.questions.len(),
            f.answers.len()
        ),
        Layer::Raw(r) => format!("{} bytes", r.bytes.len()),
    }
}

fn field_show<T: std::fmt::Display>(f: &packet_dsl::ir::Field<T>, auto: &str) -> String {
    use packet_dsl::ir::Field;
    match f {
        Field::Auto => auto.to_string(),
        Field::Random => "random".to_string(),
        Field::Value(v) => v.to_string(),
    }
}

fn field_mac(f: packet_dsl::ir::Field<packet_dsl::ir::MacAddr>, auto: &str) -> String {
    field_show(&f, auto)
}

fn field_ip4(f: packet_dsl::ir::Field<std::net::Ipv4Addr>, auto: &str) -> String {
    field_show(&f, auto)
}

fn field_ip6(f: packet_dsl::ir::Field<std::net::Ipv6Addr>, auto: &str) -> String {
    field_show(&f, auto)
}

fn field_u8(f: packet_dsl::ir::Field<u8>, auto: &str) -> String {
    field_show(&f, auto)
}

fn opt<T: std::fmt::Display>(o: &Option<T>, auto: &str) -> String {
    o.as_ref()
        .map(|v| v.to_string())
        .unwrap_or_else(|| auto.to_string())
}

fn opt_mac(o: Option<MacAddr>, auto: &str) -> String {
    o.map(|m| m.to_string()).unwrap_or_else(|| auto.to_string())
}

fn opt_ip4(o: Option<std::net::Ipv4Addr>, auto: &str) -> String {
    o.map(|v| v.to_string()).unwrap_or_else(|| auto.to_string())
}

fn opt_hex(o: Option<u16>, auto: &str) -> String {
    o.map(|v| format!("0x{v:04x}"))
        .unwrap_or_else(|| auto.to_string())
}

fn opt_bytes_len(o: &Option<Vec<u8>>) -> String {
    o.as_ref()
        .map(|v| v.len().to_string())
        .unwrap_or_else(|| "auto".to_string())
}

fn opt_flags4(f: Option<packet_dsl::ir::Ipv4Flags>) -> String {
    match f {
        Some(fl) => {
            let mut parts: Vec<String> = Vec::new();
            if fl.df {
                parts.push("df".to_string());
            }
            if fl.mf {
                parts.push("mf".to_string());
            }
            if fl.frag_offset != 0 {
                parts.push(format!("off={}", fl.frag_offset));
            }
            if parts.is_empty() {
                "0".to_string()
            } else {
                parts.join(",")
            }
        }
        None => "auto".to_string(),
    }
}

fn opt_tcp_flags(f: Option<packet_dsl::ir::TcpFlags>) -> String {
    f.map(|fl| fl.to_string())
        .unwrap_or_else(|| "auto".to_string())
}

// ══════════════════════════════════════════════════════════════
// LSP（--eng --lsp）
// ══════════════════════════════════════════════════════════════

/// LSP 服务器入口（stdio）；`libs` 为 pkglang 库目录（import 解析用）。
pub fn run_lsp(libs: &[std::path::PathBuf]) -> anyhow::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_lsp_on(stdin.lock(), stdout.lock(), libs)
}

/// 可测试的 LSP 循环：读写任意 `Read + Write`。
pub fn run_lsp_on<R: Read, W: Write>(
    reader: R,
    writer: W,
    libs: &[std::path::PathBuf],
) -> anyhow::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    let mut server = LspServer {
        libs: libs.to_vec(),
        ..LspServer::default()
    };
    loop {
        match read_message(&mut reader) {
            Ok(Some(msg)) => {
                let cont = server.handle(&msg, &mut writer)?;
                writer.flush()?;
                if !cont {
                    break;
                }
            }
            Ok(None) => break, // EOF
            Err(e) => {
                let resp = error_response(Value::Null, -32700, format!("parse error: {e}"));
                write_message(&mut writer, &resp)?;
            }
        }
    }
    Ok(())
}

/// 读取一条 Content-Length 分帧的 JSON-RPC 消息。
fn read_message<R: BufRead>(reader: &mut R) -> io::Result<Option<Value>> {
    let mut len: Option<usize> = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None); // EOF
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Content-Length:") {
            len = rest.trim().parse::<usize>().ok();
        }
    }
    let len =
        len.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length"))?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    let msg =
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}

/// 写一条 Content-Length 分帧的 JSON-RPC 消息。
fn write_message<W: Write>(writer: &mut W, msg: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(msg)?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(&body)?;
    Ok(())
}

fn response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

fn notify(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "method": method, "params": params })
}

/// LSP 服务器状态。
#[derive(Default)]
struct LspServer {
    /// uri → 文档文本（full sync）。
    docs: HashMap<String, String>,
    shutdown: bool,
    /// pkglang 库目录（import 解析）。
    libs: Vec<PathBuf>,
}

impl LspServer {
    /// 处理一条消息；返回 false = 退出循环（exit 通知 / shutdown 后）。
    fn handle<W: Write>(&mut self, msg: &Value, w: &mut W) -> io::Result<bool> {
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let id = msg.get("id").cloned();
        let is_request = id.is_some();

        match method {
            "initialize" => {
                if let Some(id) = id {
                    let caps = json!({
                        "capabilities": {
                            "textDocumentSync": 1,
                            "completionProvider": { "triggerCharacters": [">", "(", ",", " "] },
                            "hoverProvider": true,
                            "documentSymbolProvider": true
                        },
                        "serverInfo": {
                            "name": "prping packet-dsl",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    });
                    write_message(w, &response(id, caps))?;
                }
            }
            "initialized" => {}
            "shutdown" => {
                self.shutdown = true;
                if let Some(id) = id {
                    write_message(w, &response(id, Value::Null))?;
                }
            }
            "exit" => return Ok(false),
            "textDocument/didOpen" => {
                self.on_did_open(msg);
                self.publish_diagnostics_for(msg, w)?;
            }
            "textDocument/didChange" => {
                self.on_did_change(msg);
                self.publish_diagnostics_for(msg, w)?;
            }
            "textDocument/completion" => {
                if let Some(id) = id {
                    let items = self.completion(msg);
                    write_message(
                        w,
                        &response(id, json!({ "isIncomplete": false, "items": items })),
                    )?;
                }
            }
            "textDocument/hover" => {
                if let Some(id) = id {
                    let hover = self.hover(msg);
                    write_message(w, &response(id, hover))?;
                }
            }
            "textDocument/documentSymbol" => {
                if let Some(id) = id {
                    let symbols = self.document_symbol(msg);
                    write_message(w, &response(id, symbols))?;
                }
            }
            "$/cancelRequest" | "workspace/didChangeConfiguration" => {}
            _ => {
                if is_request {
                    write_message(
                        w,
                        &error_response(id.unwrap_or(Value::Null), -32601, "method not found"),
                    )?;
                }
            }
        }
        Ok(true)
    }

    fn on_did_open(&mut self, msg: &Value) {
        let params = &msg["params"];
        if let (Some(uri), Some(text)) = (
            params["textDocument"]["uri"].as_str(),
            params["textDocument"]["text"].as_str(),
        ) {
            self.docs.insert(uri.to_string(), text.to_string());
        }
    }

    fn on_did_change(&mut self, msg: &Value) {
        let params = &msg["params"];
        let uri = params["textDocument"]["uri"].as_str().unwrap_or("");
        // full sync：取最后一条 contentChanges 的 text
        if let Some(changes) = params["contentChanges"].as_array()
            && let Some(last) = changes.last()
            && let Some(text) = last["text"].as_str()
        {
            self.docs.insert(uri.to_string(), text.to_string());
        }
    }

    /// 解析文档并推送诊断（didOpen / didChange 后）。
    fn publish_diagnostics_for<W: Write>(&self, msg: &Value, w: &mut W) -> io::Result<()> {
        let params = &msg["params"];
        let uri = params["textDocument"]["uri"].as_str().unwrap_or("");
        let version = params["textDocument"]["version"].as_i64();
        let diags = self.diagnostics(uri);
        let mut p = json!({ "uri": uri, "diagnostics": diags });
        if let Some(v) = version {
            p["version"] = json!(v);
        }
        write_message(w, &notify("textDocument/publishDiagnostics", p))
    }

    fn text_of(&self, uri: &str) -> Option<&str> {
        self.docs.get(uri).map(String::as_str)
    }

    /// 诊断：解析 → 首个错误（带行/列）。
    fn diagnostics(&self, uri: &str) -> Vec<Value> {
        let Some(text) = self.text_of(uri) else {
            return vec![];
        };
        analyze(text, uri, &self.libs)
    }

    fn completion(&self, msg: &Value) -> Vec<Value> {
        let uri = msg["params"]["textDocument"]["uri"].as_str().unwrap_or("");
        let mut items = Vec::new();
        for kw in ["export", "import", "use", "true", "false"] {
            items.push(json!({
                "label": kw,
                "kind": 14, // Keyword
                "insertText": kw,
            }));
        }
        // 运行时参数引用函数
        items.push(json!({
            "label": "params",
            "kind": 3, // Function
            "detail": "params(\"name\"[, \"default\"])",
            "documentation": {
                "kind": "markdown",
                "value": "读取运行时参数：`--params name=value` 注入，`params(\"name\")` 取值。\n\n可带默认值：`params(\"port\", \"443\")`。"
            },
            "insertText": "params(\"\")",
        }));
        for doc in packet_dsl::registry::builtin_docs() {
            let params: Vec<String> = doc
                .params
                .iter()
                .map(|(n, t)| format!("{n}: {t}"))
                .collect();
            items.push(json!({
                "label": doc.name,
                "kind": 3, // Function
                "detail": format!("{}({})", doc.name, params.join(", ")),
                "documentation": {
                    "kind": "markdown",
                    "value": format!("**自动行为**：{}", doc.auto)
                },
                "insertText": format!("{}()", doc.name),
            }));
        }
        // 元件名（若文档可解析）
        if let Some(text) = self.text_of(uri)
            && let Ok(module) = try_parse(text, uri, &self.libs)
        {
            for def in &module.defs {
                items.push(json!({
                    "label": def.name,
                    "kind": 6, // Variable
                    "detail": "component",
                }));
            }
            for f in &module.funcs {
                let params: Vec<String> = f
                    .params
                    .iter()
                    .map(|p| match &p.default {
                        Some(d) => format!("{}={}", p.name, value_display(d)),
                        None => p.name.clone(),
                    })
                    .collect();
                items.push(json!({
                    "label": f.name,
                    "kind": 3, // Function
                    "detail": format!("func {}({})", f.name, params.join(", ")),
                    "insertText": format!("{}()", f.name),
                }));
            }
            for (name, _) in &module.exports {
                items.push(json!({
                    "label": name,
                    "kind": 6,
                    "detail": "export",
                }));
            }
            if module.default.is_some() {
                items.push(json!({
                    "label": module.name,
                    "kind": 9, // Module
                    "detail": "default export",
                }));
            }
        }
        // 库导出（隐式可见，无需 import）：函数签名与元件。
        // 放在本地定义之后——本地同名定义优先（遮蔽库导出）。
        let mut labels: std::collections::HashSet<String> = items
            .iter()
            .filter_map(|i| i["label"].as_str().map(str::to_string))
            .collect();
        for exp in packet_dsl::lib_exports(&self.libs) {
            if labels.contains(&exp.name) {
                continue;
            }
            if let Some(params) = &exp.params {
                let ps: Vec<String> = params
                    .iter()
                    .map(|p| match &p.default {
                        Some(d) => format!("{}={}", p.name, value_display(d)),
                        None => p.name.clone(),
                    })
                    .collect();
                items.push(json!({
                    "label": exp.name,
                    "kind": 3, // Function
                    "detail": format!("func {}({})  [{}]", exp.name, ps.join(", "), exp.module),
                    "insertText": format!("{}()", exp.name),
                }));
            } else {
                items.push(json!({
                    "label": exp.name,
                    "kind": 6, // Variable
                    "detail": format!("export [{}]", exp.module),
                }));
            }
            labels.insert(exp.name.clone());
        }
        items
    }

    fn hover(&self, msg: &Value) -> Value {
        let uri = msg["params"]["textDocument"]["uri"].as_str().unwrap_or("");
        let pos = &msg["params"]["position"];
        let (line, character) = (
            pos["line"].as_i64().unwrap_or(0) as usize,
            pos["character"].as_i64().unwrap_or(0) as usize,
        );
        let Some(text) = self.text_of(uri) else {
            return Value::Null;
        };
        let Some(word) = word_at(text, line, character) else {
            return Value::Null;
        };
        if let Some(doc) = builtin_doc(&word) {
            let mut md = format!("### `{}()`\n\n", doc.name);
            if !doc.params.is_empty() {
                md.push_str("**参数**\n\n");
                for (n, t) in &doc.params {
                    md.push_str(&format!("- `{n}`: {t}\n"));
                }
                md.push('\n');
            }
            md.push_str(&format!("**自动行为**：{}\n", doc.auto));
            return json!({ "contents": { "kind": "markdown", "value": md } });
        }
        if word == "params" {
            return json!({ "contents": { "kind": "markdown", "value":
                "### `params(\"name\"[, \"default\"])`\n\n读取运行时参数（`--params name=value` 注入）。\n\n例：`tcp(dport=params(\"port\", \"443\"))`" } });
        }
        if matches!(word.as_str(), "export" | "import" | "use") {
            let help = match word.as_str() {
                "export" => "声明导出元件：`export:` 后跟 `- 名字` 列表。",
                "import" => "引入其他模块的元件：`import a { a, b }` 或 `import a`（全部导出）。",
                _ => "开始一条流水线：`use(a, b) |> tcp(dport=443) |> ipv4()`。",
            };
            return json!({ "contents": { "kind": "markdown", "value": format!("### `{word}`\n\n{help}") } });
        }
        if word == "func" {
            return json!({ "contents": { "kind": "markdown", "value":
                "### `func name(p1, p2=默认) { pipeline }`\n\n具名参数化函数：参数全部可选——无默认值的参数未传时为「未设」（在层参数位置省略 → 自动值），有默认值则用默认。函数体无 `use` 时以空包种子逐层包裹（层片段语义）。\n\n例：\n\n```\nfunc net4(dst, src=\"random\", ttl=64) {\n    ipv4(src=src, dst=dst, ttl=ttl) |> eth()\n}\n```" } });
        }
        // 用户函数悬停（若文档可解析）
        if let Some(text) = self.text_of(uri)
            && let Ok(module) = try_parse(text, uri, &self.libs)
            && let Some(f) = module.funcs.iter().find(|f| f.name == word)
        {
            let params: Vec<String> = f
                .params
                .iter()
                .map(|p| match &p.default {
                    Some(d) => format!("`{}={}`", p.name, value_display(d)),
                    None => format!("`{}`", p.name),
                })
                .collect();
            let mut md = format!("### `func {}({})`\n\n", f.name, params.join(", "));
            if let Some(doc) = &f.doc {
                md.push_str(&doc_markdown(doc));
            }
            md.push_str("**参数**（全部可选）：\n\n");
            for p in &f.params {
                let default = match &p.default {
                    Some(d) => format!("默认 `{}`", value_display(d)),
                    None => "未设（省略 → 自动值）".to_string(),
                };
                let desc = f
                    .doc
                    .as_ref()
                    .and_then(|d| d.params.iter().find(|(n, _)| n == &p.name))
                    .map(|(_, t)| format!("——{t}"))
                    .unwrap_or_default();
                md.push_str(&format!("- `{}`：{default}{desc}\n", p.name));
            }
            return json!({ "contents": { "kind": "markdown", "value": md } });
        }
        // 库导出函数（隐式可见）：与用户函数同格式，标注来源模块
        if let Some(exp) = packet_dsl::lib_exports(&self.libs)
            .into_iter()
            .find(|e| e.name == word && e.params.is_some())
        {
            let params: Vec<String> = exp
                .params
                .as_ref()
                .unwrap()
                .iter()
                .map(|p| match &p.default {
                    Some(d) => format!("`{}={}`", p.name, value_display(d)),
                    None => format!("`{}`", p.name),
                })
                .collect();
            let mut md = format!("### `func {}({})`\n\n", exp.name, params.join(", "));
            if let Some(doc) = &exp.doc {
                md.push_str(&doc_markdown(doc));
            }
            md.push_str(&format!("库模块：`{}`（隐式可见）\n\n", exp.module));
            md.push_str("**参数**（全部可选）：\n\n");
            for p in exp.params.as_ref().unwrap() {
                let default = match &p.default {
                    Some(d) => format!("默认 `{}`", value_display(d)),
                    None => "未设（省略 → 自动值）".to_string(),
                };
                let desc = exp
                    .doc
                    .as_ref()
                    .and_then(|d| d.params.iter().find(|(n, _)| n == &p.name))
                    .map(|(_, t)| format!("——{t}"))
                    .unwrap_or_default();
                md.push_str(&format!("- `{}`：{default}{desc}\n", p.name));
            }
            return json!({ "contents": { "kind": "markdown", "value": md } });
        }
        Value::Null
    }

    fn document_symbol(&self, msg: &Value) -> Value {
        let uri = msg["params"]["textDocument"]["uri"].as_str().unwrap_or("");
        let Some(text) = self.text_of(uri) else {
            return json!([]);
        };
        let Ok(module) = try_parse(text, uri, &self.libs) else {
            return json!([]);
        };
        let mut symbols = Vec::new();
        for def in &module.defs {
            symbols.push(json!({
                "name": def.name,
                "kind": 13, // Variable
                "detail": "component",
                "range": lsp_range(def.span),
                "selectionRange": lsp_range(def.name_span),
            }));
        }
        for f in &module.funcs {
            let params: Vec<String> = f.params.iter().map(|p| p.name.clone()).collect();
            symbols.push(json!({
                "name": f.name,
                "kind": 12, // Function
                "detail": format!("func {}({})", f.name, params.join(", ")),
                "range": lsp_range(f.span),
                "selectionRange": lsp_range(f.name_span),
            }));
        }
        for (name, span) in &module.exports {
            symbols.push(json!({
                "name": name,
                "kind": 14, // Constant
                "detail": "export",
                "range": lsp_range(*span),
                "selectionRange": lsp_range(*span),
            }));
        }
        if let Some((_, span)) = &module.default {
            symbols.push(json!({
                "name": module.name,
                "kind": 2, // Module
                "detail": "default export",
                "range": lsp_range(*span),
                "selectionRange": lsp_range(*span),
            }));
        }
        json!(symbols)
    }
}

/// 解析文档（带 import 根）；URI 无法定位文件时退化为纯单文件解析。
fn try_parse(text: &str, uri: &str, libs: &[PathBuf]) -> Result<Module, Diagnostic> {
    match uri_info(uri) {
        Some((name, dir)) => packet_dsl::parse_source_at_with_libs(&name, &dir, text, libs),
        None => packet_dsl::parse_str("untitled", text),
    }
}

/// 文档诊断列表（首个错误；无错误时为空）。
fn analyze(text: &str, uri: &str, libs: &[PathBuf]) -> Vec<Value> {
    match try_parse(text, uri, libs) {
        Ok(_) => vec![],
        Err(d) => vec![lsp_diag(&d)],
    }
}

fn lsp_diag(d: &Diagnostic) -> Value {
    let (sl, sc, el, ec) = match &d.span {
        Some(s) => (
            s.start.line.saturating_sub(1),
            s.start.col.saturating_sub(1),
            s.end.line.saturating_sub(1),
            s.end.col.saturating_sub(1),
        ),
        None => (0, 0, 0, 0),
    };
    json!({
        "range": {
            "start": { "line": sl, "character": sc },
            "end": { "line": el, "character": ec }
        },
        "severity": 1,
        "source": "packet-dsl",
        "message": d.message,
    })
}

fn lsp_range(span: packet_dsl::ast::Span) -> Value {
    json!({
        "start": { "line": span.start.line.saturating_sub(1), "character": span.start.col.saturating_sub(1) },
        "end": { "line": span.end.line.saturating_sub(1), "character": span.end.col.saturating_sub(1) }
    })
}

/// 取 (行, 列) 处的标识符（0 基行/列）。
fn word_at(text: &str, line: usize, character: usize) -> Option<String> {
    let line_text = text.lines().nth(line)?;
    let bytes = line_text.as_bytes();
    let mut start = character.min(bytes.len());
    let mut end = start;
    while start > 0 && is_ident_char(bytes[start - 1]) {
        start -= 1;
    }
    while end < bytes.len() && is_ident_char(bytes[end]) {
        end += 1;
    }
    if start == end {
        return None;
    }
    Some(line_text[start..end].to_string())
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `file:///path/to/demo.pkt` → (名字 "demo", 目录)。非 file:// 返回 None。
fn uri_info(uri: &str) -> Option<(String, PathBuf)> {
    let rest = uri.strip_prefix("file://")?;
    let path_str = percent_decode(rest);
    let path = PathBuf::from(&path_str);
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "untitled".to_string());
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    Some((name, dir))
}

/// 简化百分号解码（%20 等）。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}
