//! `--pkg`：构建 .pkt 并一次性发送全部变体包到目标。
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
use packet_dsl::ir::{Layer, MacAddr, PacketSpec};
use packet_dsl::{DefaultSerializer, PacketSource, Serializer};
use termcolor::{ColorChoice, StandardStream};

use crate::eng::render_hexdump;
use crate::output::{print_cyan, print_dim, print_green, print_magenta, writeln_red};

/// 发送方式。
#[derive(Debug, Clone, Default)]
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

/// `--pkg` 的完整选项。
#[derive(Debug, Clone, Default)]
pub struct PkgOptions {
    /// 显式目标（None = 逐包从包内推导）。
    pub target: Option<SocketAddr>,
    pub mode: SendMode,
    /// 运行时参数（`params("name")` 值引用）。
    pub params: Vec<(String, String)>,
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
/// 打印 RTT 并反解展示应答。
pub fn send_packets(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    crate::eng::ensure_dns_resolver();
    let module =
        packet_dsl::parse_file_with_libs(file, &opts.libs).map_err(|d| anyhow::anyhow!("{d}"))?;
    let p: packet_dsl::Params = opts.params.iter().cloned().collect();
    let sources =
        packet_dsl::resolve_sources_with_params(&module, &p).map_err(|d| anyhow::anyhow!("{d}"))?;
    let total: usize = sources.iter().map(|(_, p)| p.len()).sum();
    if total == 0 {
        anyhow::bail!("没有可发送的包：文件既无默认导出，也无命名导出");
    }
    let ser = if opts.fuzz {
        DefaultSerializer::new_fuzz()
    } else {
        DefaultSerializer::new()
    };
    // sniffer：--wait 时按 .pkt 的 sniffer 段校验应答（构建期静态校验，错误即报出）
    let sniffer = if opts.wait.is_some() {
        module
            .sniffer
            .as_ref()
            .map(SnifferMatcher::build)
            .transpose()?
    } else {
        None
    };

    // --out：先存档（按最外层推断链路类型）
    if let Some(out) = &opts.out {
        let all: Vec<Vec<u8>> = sources
            .iter()
            .flat_map(|(_, pkts)| pkts)
            .filter_map(|pkt| ser.serialize(pkt).ok())
            .collect();
        let lt = sources
            .iter()
            .flat_map(|(_, pkts)| pkts)
            .next()
            .map(|pkt| crate::pcap::linktype_of(&pkt.layers))
            .unwrap_or(crate::pcap::LinkType::Raw);
        crate::pcap::write_pcap(out, lt, &all)?;
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
                Some(t) => format!(" to {t}"),
                None => " — target derived from each packet".to_string(),
            }
        ),
    )?;
    writeln!(&mut w)?;
    if opts.fuzz {
        crate::output::print_yellow(&mut w, "note: fuzz mode — unset fields randomized")?;
        writeln!(&mut w)?;
    }
    if let Some(secs) = opts.wait {
        crate::output::print_yellow(
            &mut w,
            format!("note: waiting up to {secs}s for a matching reply"),
        )?;
        writeln!(&mut w)?;
    }
    writeln!(&mut w)?;
    // 实际生效的库目录（默认 eng_lib + --lib；与解析器合并顺序一致）
    let libs = crate::eng::effective_libs(&opts.libs);
    print_dim(&mut w, format!("libs: {}", crate::eng::libs_display(&libs)))?;
    writeln!(&mut w)?;
    writeln!(&mut w)?;
    let mut idx = 0usize;
    let mut failed = 0usize;
    for (source, pkts) in &sources {
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
            if crate::eng::render_packet_fields(&mut w, pkt, &header, &ser).is_err() {
                // 序列化失败：退回简版 stack 行（发送环节会再报错）
                let stack: Vec<&str> = pkt.layers.iter().map(crate::eng::layer_name).collect();
                print_dim(&mut w, format!("  stack: {}", stack.join(" -> ")))?;
                writeln!(&mut w)?;
            }

            let extracted = extract_payload_with(pkt, &ser);
            let is_raw = matches!(opts.mode, SendMode::Raw { .. }) || extracted.is_none();
            if extracted.is_none() && !matches!(opts.mode, SendMode::Raw { .. }) {
                crate::output::print_yellow(
                    &mut w,
                    "  note: no TCP/UDP transport — sending full packet via raw sockets",
                )?;
                writeln!(&mut w)?;
            }
            let target = match opts.target {
                Some(t) => t,
                None => match derive_target(pkt, !is_raw) {
                    Ok(t) => {
                        print_dim(&mut w, format!("  target: {t} (derived from packet)"))?;
                        writeln!(&mut w)?;
                        t
                    }
                    Err(e) => {
                        failed += 1;
                        crate::output::writeln_red(&mut w, format!("  ✗ {e}"))?;
                        continue;
                    }
                },
            };
            // 代理 fake-ip 诊断：目标在 198.18.0.0/15（Clash 等 fake-ip 段）时，
            // eth 原始帧绕过代理直发物理网卡，公网不可达（bare-ip 走内核路由/代理可达）。
            let is_eth_frame = matches!(pkt.layers.last(), Some(Layer::Ethernet(_)));
            if is_raw && is_eth_frame && is_fake_ip(target.ip()) {
                crate::output::print_yellow(
                    &mut w,
                    format!(
                        "  note: 目标 {} 是代理 fake-ip（198.18.0.0/15）——eth 原始帧绕过代理直发不可达；用 examples/network_icmp_bare.pkt（走内核路由/代理）或关代理直连",
                        target.ip()
                    ),
                )?;
                writeln!(&mut w)?;
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
                    match local_ip_for(&target) {
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
                    &target,
                    iface,
                    opts.wait,
                    sniffer.as_ref(),
                    sent_report.as_ref(),
                )
            } else {
                let (transport, payload) = extracted.expect("已判定非 raw → 必有传输层");
                send_payload(
                    transport,
                    &payload,
                    &target,
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
                        &mut w,
                        format!(
                            "  note: src 自动填充为 {ip}（疑似代理 fake-ip 网关）——eth 原始帧绕过代理直发，真实网关会丢弃；用 examples/network_icmp_bare.pkt（走内核路由/代理）"
                        ),
                    )?;
                    writeln!(&mut w)?;
                } else {
                    print_dim(&mut w, format!("  note: src auto-filled → {ip}"))?;
                    writeln!(&mut w)?;
                }
            } else if src_warn {
                crate::output::print_yellow(
                    &mut w,
                    "  note: src=0.0.0.0/:: 且无法自动填充本地地址——回包可能路由不回来；用 --params src=<本机 IP>",
                )?;
                writeln!(&mut w)?;
            }
            match result {
                Ok(outcome) => {
                    print_green(
                        &mut w,
                        format!(
                            "  {} → {target}: sent {} B{}",
                            outcome.proto,
                            outcome.sent,
                            if outcome.received > 0 {
                                format!(", received {} B", outcome.received)
                            } else {
                                String::new()
                            }
                        ),
                    )?;
                    writeln!(&mut w)?;
                    match &outcome.reply {
                        Some(Reply {
                            rtt,
                            bytes,
                            matched,
                        }) => {
                            if let Some(fields) = matched {
                                let pairs: Vec<String> =
                                    fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
                                print_green(
                                    &mut w,
                                    format!("  ✓ reply matched: {} ({rtt:.3} ms)", pairs.join(" ")),
                                )?;
                                writeln!(&mut w)?;
                            } else {
                                print_cyan(&mut w, format!("  reply after {rtt:.3} ms"))?;
                                writeln!(&mut w)?;
                            }
                            if !bytes.is_empty() {
                                let report = packet_dsl::dissect(bytes);
                                crate::eng::render_dissected(&mut w, &report, "  reply:", bytes)?;
                            }
                        }
                        None => {
                            if let Some(secs) = opts.wait {
                                let what = if sniffer.is_some() {
                                    "matching reply"
                                } else {
                                    "reply"
                                };
                                writeln_red(&mut w, format!("  ✗ no {what} within {secs}s"))?;
                            }
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    crate::output::writeln_red(&mut w, format!("  ✗ {e}"))?;
                }
            }
            if !shown.is_empty() {
                render_hexdump(&mut w, &shown)?;
            }
            writeln!(&mut w)?;
        }
    }
    if failed > 0 {
        anyhow::bail!("{failed} of {total} packets failed to send");
    }
    Ok(())
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
fn sniffer_field_names(layer: &str) -> Option<&'static [&'static str]> {
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
    /// 构建并校验：每个子句的层类型/字段名/字面量类型都静态检查（错误在发送前报出）。
    fn build(spec: &SnifferSpec) -> anyhow::Result<Self> {
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
                crate::eng::value_display(other)
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
            // 回包没有该子句的层 → 子句不可能满足，试下一个
            let Some(rl) = report.layers.iter().find(|l| layer_kind(l) == clause.layer) else {
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
/// 返回 `Some(字段对)` = 匹配成功（字段名, 回包实际值）；`None` = 不匹配。
pub fn sniffer_match(
    spec: &SnifferSpec,
    reply: &[u8],
    sent: &[u8],
) -> anyhow::Result<Option<Vec<(String, String)>>> {
    let m = SnifferMatcher::build(spec)?;
    let sent_report = packet_dsl::dissect(sent);
    Ok(m.matches(reply, &sent_report))
}

/// 从包推导目标地址：最外层 IP 层的 `dst`；`need_port` 时取最外层 TCP/UDP 的 `dport`。
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
    let port = if need_port {
        pkt.layers
            .iter()
            .rev()
            .find_map(|l| match l {
                // 语义字段优先；字节直喂层（库函数构建，raw 有值）从头部字节解析：
                // TCP/UDP 头 dport 都在 offset 2-3（sport 2B + dport 2B）。
                Layer::Tcp(f) => f.dst_port.or_else(|| raw_dport(&f.raw)),
                Layer::Udp(f) => f.dst_port.or_else(|| raw_dport(&f.raw)),
                _ => None,
            })
            .ok_or_else(|| {
                anyhow::anyhow!("包没有定义目标端口（传输层 dport 缺失），请显式指定 HOST:PORT")
            })?
    } else {
        0
    };
    Ok(SocketAddr::new(ip, port))
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
    let timeout = wait.map(Duration::from_secs_f64);
    match transport {
        Transport::Tcp => {
            let t0 = std::time::Instant::now();
            let mut conn = TcpStream::connect(target)?;
            conn.set_read_timeout(timeout.or(Some(Duration::from_secs(2))))?;
            conn.write_all(payload)?;
            let _ = conn.shutdown(Shutdown::Write);
            let t_conn = t0.elapsed();
            let received = read_echo(&mut conn)?;
            let reply = if wait.is_some() && received > 0 {
                // 应答 body 已在 read_echo 里读完；RTT = 连接 + 首字节耗时
                let _ = read_all(&mut conn);
                Some(Reply {
                    rtt: t_conn.as_secs_f64() * 1000.0,
                    bytes: Vec::new(), // body 已在 read_echo 中计数
                    matched: None,     // TCP 回显无独立字节，sniffer 不适用
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

/// TCP：读取回显直到 EOF/超时（超时不算错误）。
fn read_echo(r: &mut impl Read) -> io::Result<usize> {
    Ok(read_all(r)?.len())
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
    target: &SocketAddr,
    iface: Option<&str>,
    wait: Option<f64>,
    sniffer: Option<&SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<SendOutcome> {
    // Windows：Npcap 兼容层一次完成设备选择 + 以太网封装 + 抓包等待（rawwin.rs）
    #[cfg(windows)]
    {
        crate::rawwin::send_raw_full(bytes, pkt, target, iface, wait, sniffer, sent_report)
    }
    #[cfg(not(windows))]
    {
        let (proto, sent) = match pkt.layers.last() {
            Some(Layer::Ethernet(_)) => ("ETH", send_af_packet(bytes, target, iface)?),
            Some(Layer::Ipv4(_)) => ("IP4", send_raw_ip4(bytes, target)?),
            Some(Layer::Ipv6(_)) => ("IP6", send_raw_ip6(bytes, target)?),
            _ => anyhow::bail!("raw 发送需要最外层为 eth / ipv4 / ipv6 层"),
        };
        let reply = if let Some(secs) = wait {
            raw_reply_for(pkt, secs, sniffer, sent_report)?
        } else {
            None
        };
        Ok(SendOutcome {
            proto,
            sent,
            received: 0,
            reply,
        })
    }
}

/// 到达 `target` 的本地源地址（UDP connect 路由探测，不发数据）。
fn local_ip_for(target: &SocketAddr) -> Option<std::net::IpAddr> {
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
/// Linux raw ICMP socket（`raw_reply_for`）与 Windows Npcap 捕获（`rawwin`）共用。
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
    if icmp.icmp_type == Some(0) && icmp.id == Some(id) && icmp.seq == Some(seq) {
        Ok(Some((data.to_vec(), None)))
    } else {
        Ok(None)
    }
}

/// raw 模式应答等待：sniffer 存在时按 sniffer 匹配；否则包是 ICMP echo → 等 echo reply
/// （按 id+seq 匹配）。
#[cfg(target_os = "linux")]
fn raw_reply_for(
    pkt: &PacketSpec,
    secs: f64,
    sniffer: Option<&SnifferMatcher>,
    sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<Option<Reply>> {
    use libc::{AF_INET, IPPROTO_ICMP, SOCK_RAW, socket};

    // 无 sniffer 且非 ICMP echo：raw 模式下暂不等待
    if sniffer.is_none() && icmp_echo_ids(pkt).is_none() {
        return Ok(None);
    }
    let fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
    if fd < 0 {
        anyhow::bail!(
            "raw ICMP socket 失败（需要 root/cap_net_raw）：{}",
            io::Error::last_os_error()
        );
    }
    let result = (|| {
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
    })();
    unsafe { libc::close(fd) };
    result
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn raw_reply_for(
    _pkt: &PacketSpec,
    _secs: f64,
    _sniffer: Option<&SnifferMatcher>,
    _sent_report: Option<&packet_dsl::DissectReport>,
) -> anyhow::Result<Option<Reply>> {
    Ok(None)
}

/// AF_PACKET 原始以太网帧（Linux；默认接口 lo，可用 --iface 指定）。
#[cfg(target_os = "linux")]
fn send_af_packet(
    bytes: &[u8],
    _target: &SocketAddr,
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
    _target: &SocketAddr,
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
