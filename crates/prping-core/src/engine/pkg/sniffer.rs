//! Sniffer 匹配：由 `.pkt` 的 `sniffer:` 段构建回包匹配器（多子句，任一命中即匹配）。
//!
//! 忠实拆分自原 `engine/pkg.rs` 的 sniffer 相关段：FVal 规范值 / 字段提取 /
//! SnifferMatcher 构建与匹配 / 字节级比较（Expr 值表达式）。

use std::net::{Ipv4Addr, Ipv6Addr};

use packet_dsl::ast::{SnifferSpec, SnifferValue};
use packet_dsl::ir::{ArpOp, Field, Layer, MacAddr};

/// 反解层字段的可比规范值（sniffer 匹配用）。
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FVal {
    U(u64),
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
    Mac(MacAddr),
    S(String),
}

impl FVal {
    pub(crate) fn display(&self) -> String {
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
pub(crate) fn sniffer_extract(l: &Layer, name: &str) -> Option<FVal> {
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
pub struct SnifferMatcher {
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
    pub fn build(
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

pub(crate) fn field_bytes(l: &Layer, name: &str) -> Option<Vec<u8>> {
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
pub(crate) fn layer_kind(l: &Layer) -> String {
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
