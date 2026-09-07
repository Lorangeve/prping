//! 统一匹配谓词：由 `.pkt` 的 `sniffer:` 段构建的匹配器（回包校验 / 监听规则）。
//!
//! - 与 `#[rule]` 共享字段取值内核：反解层字段 → 类型化规范值（[`FVal`]）或
//!   原始字节（[`layer_field_bytes`]），字段名表（[`field_names`]）一处维护，
//!   宿主（`--eng` 展示 / 配方 `extract` / `reply()` 表达式）与 proto 校验共用。
//! - 谓词语法（`and`/`or`/`not` + 字段等式 `ne` + 字节模式 `mask`/`startswith`/
//!   `endswith`/`contains`）与 `#[rule]` 的 `and`/`or`/匹配函数同构；`#[rule]`
//!   在**解析期**按层单点分派（无法跨层 AND），sniffer 在**反解后**对整包判定
//!   （支持跨层 AND / `not`），故共享 AST 与取值器、保留各自求值入口。
//! - `SentField`（裸 Ident 引用发包同层同名字段）是 sniffer 独有能力：监听模式
//!   无发包可引用，构建期（`allow_sent: false`）直接报错。

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ast::{SnifferClause, SnifferItem, SnifferPred, SnifferSpec, SnifferValue, Value};
use crate::diag::{Diagnostic, PktResult};
use crate::ir::{Field, Layer, MacAddr};
use crate::proto::{ProtoHit, ProtoVal};
use crate::{DissectReport, Globals, Module, Params};

/// 反解层字段的可比规范值（sniffer 匹配 / 配方 extract 用）。
#[derive(Debug, Clone, PartialEq)]
pub enum FVal {
    U(u64),
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
    Mac(MacAddr),
    S(String),
}

impl FVal {
    pub fn display(&self) -> String {
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
/// 配方 `extract` 的 `from: reply.<层>.<字段>`、`reply()` 表达式与 `--eng` 概览校验共用。
///
/// **同步修改点**：新增协议字段时需同步修改以下位置：
/// 1. 本函数 `field_names` — 字段名列表
/// 2. `layer_field` — 按名提取 FVal 的 match arm
/// 3. `layer_field_bytes` — 按名取原始字节的 match arm
/// 4. `reply_field_names` — 如有扩展字节字段（如 `payload`/`body`）
pub fn field_names(layer: &str) -> Option<&'static [&'static str]> {
    Some(match layer {
        "eth" => &["dst", "src", "ethertype"][..],
        "arp" => &["op", "sha", "spa", "tha", "tpa"][..],
        "ipv4" => &["src", "dst", "ttl", "proto", "tos", "id", "flags"][..],
        "ipv6" => &["src", "dst", "hop_limit", "next_header"][..],
        "icmp" => &["type", "code", "id", "seq"][..],
        "tcp" => &["sport", "dport", "seq", "ack", "flags", "window"][..],
        "udp" => &["sport", "dport"][..],
        "dns" => &["id", "flags"][..],
        "http" => &["method", "path", "version"][..],
        // raw 载荷层：字节谓词（startswith/contains/endswith）的主要目标；
        // `bytes` 字段 = 载荷整体（hex 展示；`layer_field_bytes` 给原始字节）。
        "raw" => &["bytes"][..],
        _ => return None,
    })
}

/// `reply("层","字段")` 可用的字段集：sniffer 字段集 + 扩展字节字段
/// （icmp.payload / http.body / raw.bytes）——`from:` 表达式形态的 `--eng` 校验与
/// 求值共用。
pub fn reply_field_names(layer: &str) -> Option<Vec<&'static str>> {
    let mut names = match layer {
        "raw" => vec!["bytes"],
        _ => field_names(layer)?.to_vec(),
    };
    match layer {
        "icmp" => names.push("payload"),
        "http" => names.push("body"),
        _ => {}
    }
    Some(names)
}

/// 层名（与 `--eng` 展示一致）。
pub fn layer_name(l: &Layer) -> &'static str {
    crate::stack::name(l)
}

/// 取 IR 层的原始字节（字节谓词/`--eng` hex 展示用；反解时回填）。
pub fn layer_raw_bytes(l: &Layer) -> Option<&[u8]> {
    match l {
        Layer::Ethernet(f) => f.raw.as_deref(),
        Layer::Arp(f) => f.raw.as_deref(),
        Layer::Ipv4(f) => f.raw.as_deref(),
        Layer::Ipv6(f) => f.raw.as_deref(),
        Layer::Icmp(f) => f.raw.as_deref(),
        Layer::Tcp(f) => f.raw.as_deref(),
        Layer::Udp(f) => f.raw.as_deref(),
        Layer::Dns(f) => f.raw.as_deref(),
        Layer::Http(f) => f.raw.as_deref(),
        Layer::Raw(d) => Some(&d.bytes),
    }
}

/// 从反解层提取字段（别名映射到 IR 字段名）→ 类型化规范值。
///
/// **同步修改点**：新增协议字段时需同步修改 `field_names`（字段名列表）。
pub fn layer_field(l: &Layer, name: &str) -> Option<FVal> {
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
            _ => None,
        },
        Layer::Http(f) => match name {
            "method" => f.method.clone().map(FVal::S),
            "path" => f.path.clone().map(FVal::S),
            "version" => f.version.clone().map(FVal::S),
            _ => None,
        },
        Layer::Raw(d) => match name {
            "bytes" => Some(FVal::S(
                d.bytes.iter().map(|x| format!("{x:02x}")).collect(),
            )),
            _ => None,
        },
    }
}

fn mac_field(f: &Field<MacAddr>) -> Option<FVal> {
    match f {
        Field::Value(m) => Some(FVal::Mac(*m)),
        _ => None,
    }
}

fn ip4_field(f: &Field<Ipv4Addr>) -> Option<FVal> {
    match f {
        Field::Value(a) => Some(FVal::Ip4(*a)),
        _ => None,
    }
}

fn ip6_field(f: &Field<Ipv6Addr>) -> Option<FVal> {
    match f {
        Field::Value(a) => Some(FVal::Ip6(*a)),
        _ => None,
    }
}

fn u8_field(f: &Field<u8>) -> Option<FVal> {
    match f {
        Field::Value(v) => Some(FVal::U(*v as u64)),
        _ => None,
    }
}

/// 回包反解层某字段的**原始字节**（`Expr` 值表达式字节级比较用；字段集与
/// [`layer_field`] 一致）。数值按大端（u8 单字节 / u16 两字节 / u32 四字节），
/// 地址/MAC 按网络序，字符串为 UTF-8。
pub fn layer_field_bytes(l: &Layer, name: &str) -> Option<Vec<u8>> {
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
                Some(crate::ir::ArpOp::Request) => {
                    out.extend_from_slice(&1u16.to_be_bytes());
                    true
                }
                Some(crate::ir::ArpOp::Reply) => {
                    out.extend_from_slice(&2u16.to_be_bytes());
                    true
                }
                Some(crate::ir::ArpOp::Other(n)) => {
                    out.extend_from_slice(&n.to_be_bytes());
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
            _ => false,
        },
        Layer::Http(f) => match name {
            "method" => str_bytes(f.method.as_deref(), &mut out),
            "path" => str_bytes(f.path.as_deref(), &mut out),
            "version" => str_bytes(f.version.as_deref(), &mut out),
            _ => false,
        },
        Layer::Raw(d) => match name {
            "bytes" => {
                out.extend_from_slice(&d.bytes);
                true
            }
            _ => false,
        },
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

fn ip4_field_bytes(f: &Field<Ipv4Addr>, out: &mut Vec<u8>) -> bool {
    match f {
        Field::Value(a) => {
            out.extend_from_slice(&a.octets());
            true
        }
        _ => false,
    }
}

fn ip4_opt_bytes(v: Option<Ipv4Addr>, out: &mut Vec<u8>) -> bool {
    match v {
        Some(a) => {
            out.extend_from_slice(&a.octets());
            true
        }
        None => false,
    }
}

fn ip6_field_bytes(f: &Field<Ipv6Addr>, out: &mut Vec<u8>) -> bool {
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

// ── 匹配器 ──────────────────────────────────────────────────

/// 匹配值（字段等式的右值，构建期解析为可比较形态）。
#[derive(Debug, Clone)]
enum MatchVal {
    /// 常量比较。
    Literal(FVal),
    /// 引用发包同层同名字段。
    SentField(String),
    /// 值表达式（原语/值函数/params）：构建期求值为字节，与回包字段**字节**比较。
    Expr(Vec<u8>),
}

/// 层内匹配条件（构建后形态）。
#[derive(Debug, Clone)]
enum ItemMatcher {
    FieldEq { name: String, val: MatchVal },
    FieldNe { name: String, val: MatchVal },
    Mask(u8),
    StartsWith(Vec<u8>),
    EndsWith(Vec<u8>),
    Contains(Vec<u8>),
}

/// 单个匹配子句（构建后形态）。
#[derive(Debug, Clone)]
struct ClauseMatcher {
    layer: String,
    items: Vec<ItemMatcher>,
}

/// 匹配谓词（构建后形态）。
#[derive(Debug, Clone)]
enum PredMatcher {
    Clause(ClauseMatcher),
    And(Vec<PredMatcher>),
    Or(Vec<PredMatcher>),
    Not(Box<PredMatcher>),
}

/// 由 `.pkt` 的 `sniffer:` 段构建的匹配器（多谓词，任一命中即匹配 = 隐式 OR）。
pub struct Matcher {
    preds: Vec<PredMatcher>,
}

impl Matcher {
    /// 构建并校验：每个子句的层类型/字段名/字面量类型都静态检查；值表达式在
    /// 构建期求值为字节（错误在发送前报出）。`module` 提供值函数作用域
    /// （同文件 `func ... -> bytes`；None = 仅内置原语）；`globals` 供
    /// `global("name")` 值原语取值（配方执行时注入）。
    ///
    /// `allow_sent: false`（监听模式）时，`SentField`（裸 Ident 引用发包字段）
    /// 直接报错——监听没有发包可引用。
    pub fn build(
        spec: &SnifferSpec,
        module: Option<&Module>,
        params: &Params,
        globals: &Globals,
        allow_sent: bool,
    ) -> PktResult<Self> {
        Self::build_ctx(spec, module, params, globals, allow_sent, None)
    }

    /// 同 [`Matcher::build`]，并注入 serve 轮次上下文（serve 阶段监听 matcher
    /// 构建：`round()`/`hits()` 值原语在匹配值表达式中取当前轮次/已命中次数）。
    pub fn build_ctx(
        spec: &SnifferSpec,
        module: Option<&Module>,
        params: &Params,
        globals: &Globals,
        allow_sent: bool,
        serve: Option<crate::eval::ServeCtx>,
    ) -> PktResult<Self> {
        let mut preds = Vec::new();
        for p in &spec.clauses {
            preds.push(build_pred(p, module, params, globals, allow_sent, serve)?);
        }
        Ok(Matcher { preds })
    }

    /// 回包是否匹配任一谓词；匹配时返回命中谓词报告的 (字段名, 回包实际值) 列表
    /// （仅字段等式 `FieldEq` 报告；`ne`/字节模式/`not` 内的字段不报告）。
    ///
    /// `sent` 为发包反解（`SentField` 引用来源；监听模式传 None——构建期已拒绝
    /// `SentField`，求值不会触达）。
    pub fn matches(
        &self,
        reply: &[u8],
        sent: Option<&DissectReport>,
    ) -> Option<Vec<(String, String)>> {
        let report = crate::dissect::dissect(reply);
        for p in &self.preds {
            if let Some(fields) = eval_pred(p, reply, &report, sent) {
                return Some(fields);
            }
        }
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn build_pred(
    p: &SnifferPred,
    module: Option<&Module>,
    params: &Params,
    globals: &Globals,
    allow_sent: bool,
    serve: Option<crate::eval::ServeCtx>,
) -> PktResult<PredMatcher> {
    match p {
        SnifferPred::Clause(c) => Ok(PredMatcher::Clause(build_clause(
            c, module, params, globals, allow_sent, serve,
        )?)),
        SnifferPred::And(ps) => Ok(PredMatcher::And(
            ps.iter()
                .map(|p| build_pred(p, module, params, globals, allow_sent, serve))
                .collect::<PktResult<_>>()?,
        )),
        SnifferPred::Or(ps) => Ok(PredMatcher::Or(
            ps.iter()
                .map(|p| build_pred(p, module, params, globals, allow_sent, serve))
                .collect::<PktResult<_>>()?,
        )),
        SnifferPred::Not(p) => Ok(PredMatcher::Not(Box::new(build_pred(
            p, module, params, globals, allow_sent, serve,
        )?))),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_clause(
    c: &SnifferClause,
    module: Option<&Module>,
    params: &Params,
    globals: &Globals,
    allow_sent: bool,
    serve: Option<crate::eval::ServeCtx>,
) -> PktResult<ClauseMatcher> {
    if field_names(&c.layer).is_none() {
        return Err(Diagnostic::new(format!(
            "sniffer: 未知层类型 `{}`（可用：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns）",
            c.layer
        )));
    }
    let mut items = Vec::new();
    for item in &c.items {
        items.push(match item {
            SnifferItem::FieldEq { name, val } => ItemMatcher::FieldEq {
                name: name.clone(),
                val: build_value(
                    &c.layer, name, val, module, params, globals, allow_sent, serve,
                )?,
            },
            SnifferItem::FieldNe { name, val } => ItemMatcher::FieldNe {
                name: name.clone(),
                val: build_value(
                    &c.layer, name, val, module, params, globals, allow_sent, serve,
                )?,
            },
            SnifferItem::Mask(v) => ItemMatcher::Mask(coerce_mask(v)?),
            // 空模式：starts_with/ends_with 恒真（无意义），contains 空串在
            // windows(0) 处 panic——构建期统一拒绝（与 #[rule] 路径对齐）
            SnifferItem::StartsWith(s) => {
                if s.is_empty() {
                    return Err(Diagnostic::new("sniffer: starts_with 模式不能为空"));
                }
                ItemMatcher::StartsWith(s.as_bytes().to_vec())
            }
            SnifferItem::EndsWith(s) => {
                if s.is_empty() {
                    return Err(Diagnostic::new("sniffer: ends_with 模式不能为空"));
                }
                ItemMatcher::EndsWith(s.as_bytes().to_vec())
            }
            SnifferItem::Contains(s) => {
                if s.is_empty() {
                    return Err(Diagnostic::new("sniffer: contains 模式不能为空"));
                }
                ItemMatcher::Contains(s.as_bytes().to_vec())
            }
        });
    }
    Ok(ClauseMatcher {
        layer: c.layer.clone(),
        items,
    })
}

/// 构建字段等式/不等式的匹配值（字段名校验 + 字面量类型强转 + 值表达式求值）。
#[allow(clippy::too_many_arguments)]
fn build_value(
    layer: &str,
    name: &str,
    v: &SnifferValue,
    module: Option<&Module>,
    params: &Params,
    globals: &Globals,
    allow_sent: bool,
    serve: Option<crate::eval::ServeCtx>,
) -> PktResult<MatchVal> {
    if !field_names(layer)
        .expect("层已校验存在")
        .contains(&name.to_string().as_str())
    {
        return Err(Diagnostic::new(format!(
            "sniffer: 层 `{layer}` 没有字段 `{name}`（可用：{}）",
            field_names(layer).unwrap().join("/")
        )));
    }
    match v {
        SnifferValue::SentField(f) => {
            if !allow_sent {
                return Err(Diagnostic::new(format!(
                    "sniffer: 字段 `{name}` 引用发包字段 `{f}`，但监听模式没有发包可引用（请用字面量/值表达式）"
                )));
            }
            Ok(MatchVal::SentField(f.clone()))
        }
        SnifferValue::Literal(lit) => Ok(MatchVal::Literal(coerce_literal(layer, name, lit)?)),
        SnifferValue::Expr(expr) => {
            let bytes =
                crate::eval::eval_sniffer_value_ctx(module, params, globals, serve, expr)
                    .map_err(|d| Diagnostic::new(format!("sniffer: 匹配值表达式求值失败：{d}")))?;
            Ok(MatchVal::Expr(bytes))
        }
    }
}

/// 字面量 → 规范值（按字段类型；类型不符即报错）。
fn coerce_literal(layer: &str, field: &str, v: &Value) -> PktResult<FVal> {
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
        Value::Int(i) if *i >= 0 && !is_ip4 && !is_ip6 && !is_mac && !is_str => {
            Ok(FVal::U(*i as u64))
        }
        Value::Hex(h) if !is_ip4 && !is_ip6 && !is_mac && !is_str => Ok(FVal::U(*h)),
        Value::Str(s) => {
            if is_ip4 {
                s.parse::<Ipv4Addr>().map(FVal::Ip4).map_err(|_| {
                    Diagnostic::new(format!(
                        "sniffer: 字段 `{field}` 需要 IPv4 地址，得到 `{s}`"
                    ))
                })
            } else if is_ip6 {
                s.parse::<Ipv6Addr>().map(FVal::Ip6).map_err(|_| {
                    Diagnostic::new(format!(
                        "sniffer: 字段 `{field}` 需要 IPv6 地址，得到 `{s}`"
                    ))
                })
            } else if is_mac {
                MacAddr::from_str_loose(s).map(FVal::Mac).ok_or_else(|| {
                    Diagnostic::new(format!("sniffer: 字段 `{field}` 需要 MAC 地址，得到 `{s}`"))
                })
            } else if is_str {
                Ok(FVal::S(s.clone()))
            } else {
                Err(Diagnostic::new(format!(
                    "sniffer: 字段 `{field}` 需要数值，得到字符串 `{s}`"
                )))
            }
        }
        other => Err(Diagnostic::new(format!(
            "sniffer: 字段 `{field}` 的字面量类型不支持（{}）",
            value_repr(other)
        ))),
    }
}

/// `mask(值)` → 掩码字节（0..=255）。
fn coerce_mask(v: &Value) -> PktResult<u8> {
    match v {
        Value::Int(i) if *i >= 0 && *i <= 255 => Ok(*i as u8),
        Value::Hex(h) if *h <= 255 => Ok(*h as u8),
        other => Err(Diagnostic::new(format!(
            "sniffer: mask 需要 0..=255，得到 {}",
            value_repr(other)
        ))),
    }
}

/// Value 的紧凑展示（错误消息用）。
fn value_repr(v: &Value) -> String {
    match v {
        Value::Str(s) => format!("\"{s}\""),
        Value::Int(i) => i.to_string(),
        Value::Hex(h) => format!("0x{h:X}"),
        Value::List(items) => format!(
            "[{}]",
            items.iter().map(value_repr).collect::<Vec<_>>().join(", ")
        ),
        other => format!("{other:?}"),
    }
}

/// 谓词求值：命中返回报告的 (字段名, 值)；未命中返回 None。
fn eval_pred(
    p: &PredMatcher,
    reply: &[u8],
    report: &DissectReport,
    sent: Option<&DissectReport>,
) -> Option<Vec<(String, String)>> {
    match p {
        PredMatcher::Clause(c) => clause_matches(c, reply, report, sent),
        PredMatcher::And(ps) => {
            let mut out = Vec::new();
            for p in ps {
                out.extend(eval_pred(p, reply, report, sent)?);
            }
            Some(out)
        }
        PredMatcher::Or(ps) => {
            for p in ps {
                if let Some(f) = eval_pred(p, reply, report, sent) {
                    return Some(f);
                }
            }
            None
        }
        PredMatcher::Not(p) => {
            if eval_pred(p, reply, report, sent).is_some() {
                None
            } else {
                Some(Vec::new())
            }
        }
    }
}

/// 单个子句匹配：回包反解后必须满足全部条件（IR 层或 proto 命中两分支）。
fn clause_matches(
    c: &ClauseMatcher,
    reply: &[u8],
    report: &DissectReport,
    sent: Option<&DissectReport>,
) -> Option<Vec<(String, String)>> {
    // 1) 语义 IR 层分支
    if let Some(rl) = report.layers.iter().find(|l| layer_name(l) == c.layer) {
        let sl = sent.and_then(|s| s.layers.iter().find(|l| layer_name(l) == c.layer));
        let mut out = Vec::new();
        for item in &c.items {
            match item {
                ItemMatcher::FieldEq { name, val } => {
                    let rv = layer_field(rl, name)?;
                    let ok = match val {
                        MatchVal::Literal(lit) => &rv == lit,
                        MatchVal::SentField(f) => match sl.and_then(|l| layer_field(l, f)) {
                            Some(sv) => rv == sv,
                            None => false,
                        },
                        MatchVal::Expr(expected) => {
                            layer_field_bytes(rl, name).as_deref() == Some(expected.as_slice())
                        }
                    };
                    if !ok {
                        return None;
                    }
                    out.push((name.clone(), rv.display()));
                }
                ItemMatcher::FieldNe { name, val } => {
                    // 字段缺失 → ne 成立（缺失 ≠ 任何值；与 SentField 分支一致）。
                    // 此前回包缺字段时整个子句 ? 失败、发包缺字段时 ne 却成立——
                    // 同一 ne 条件对「字段缺失」的判定相反，行为不可预期
                    let ok = match layer_field(rl, name) {
                        None => true,
                        Some(rv) => match val {
                            MatchVal::Literal(lit) => &rv != lit,
                            MatchVal::SentField(f) => match sl.and_then(|l| layer_field(l, f)) {
                                Some(sv) => rv != sv,
                                None => true,
                            },
                            MatchVal::Expr(expected) => {
                                layer_field_bytes(rl, name).as_deref() != Some(expected.as_slice())
                            }
                        },
                    };
                    if !ok {
                        return None;
                    }
                    // ne 不报告命中字段
                }
                ItemMatcher::Mask(m) => {
                    let b = layer_raw_bytes(rl)?;
                    if b.first().is_none_or(|x| x & m != *m) {
                        return None;
                    }
                }
                ItemMatcher::StartsWith(p) => {
                    let b = layer_raw_bytes(rl)?;
                    if !b.starts_with(p) {
                        return None;
                    }
                }
                ItemMatcher::EndsWith(p) => {
                    let b = layer_raw_bytes(rl)?;
                    if !b.ends_with(p) {
                        return None;
                    }
                }
                ItemMatcher::Contains(p) => {
                    let b = layer_raw_bytes(rl)?;
                    if !b.windows(p.len()).any(|w| w == p.as_slice()) {
                        return None;
                    }
                }
            }
        }
        return Some(out);
    }
    // 2) proto 命中分支（协议走 pkt 声明反解，如 dns）：字段表匹配；字节模式
    //    作用于整个报文（proto 命中无独立层 raw）。
    let hit = report.proto.iter().find(|h| h.name == c.layer)?;
    let mut out = Vec::new();
    for item in &c.items {
        match item {
            ItemMatcher::FieldEq { name, val } => {
                let rv = proto_field(hit, name)?;
                let ok = match val {
                    MatchVal::Literal(lit) => &rv == lit,
                    MatchVal::SentField(f) => {
                        let sv = sent.and_then(|s| {
                            s.proto
                                .iter()
                                .find(|h| h.name == c.layer)
                                .and_then(|h| proto_field(h, f))
                                .or_else(|| {
                                    s.layers
                                        .iter()
                                        .find(|l| layer_name(l) == c.layer)
                                        .and_then(|l| layer_field(l, f))
                                })
                        });
                        sv.is_some_and(|sv| rv == sv)
                    }
                    MatchVal::Expr(expected) => {
                        proto_field_bytes(hit, name, &rv).as_deref() == Some(expected.as_slice())
                    }
                };
                if !ok {
                    return None;
                }
                out.push((name.clone(), rv.display()));
            }
            ItemMatcher::FieldNe { name, val } => {
                // 字段缺失 → ne 成立（与 IR 分支一致）
                let ok = match proto_field(hit, name) {
                    None => true,
                    Some(rv) => match val {
                        MatchVal::Literal(lit) => &rv != lit,
                        MatchVal::SentField(f) => {
                            let sv = sent.and_then(|s| {
                                s.proto
                                    .iter()
                                    .find(|h| h.name == c.layer)
                                    .and_then(|h| proto_field(h, f))
                                    .or_else(|| {
                                        s.layers
                                            .iter()
                                            .find(|l| layer_name(l) == c.layer)
                                            .and_then(|l| layer_field(l, f))
                                    })
                            });
                            !sv.is_some_and(|sv| rv == sv)
                        }
                        MatchVal::Expr(expected) => {
                            proto_field_bytes(hit, name, &rv).as_deref()
                                != Some(expected.as_slice())
                        }
                    },
                };
                if !ok {
                    return None;
                }
            }
            ItemMatcher::Mask(m) => {
                if reply.first().is_none_or(|x| x & m != *m) {
                    return None;
                }
            }
            ItemMatcher::StartsWith(p) => {
                if !reply.starts_with(p) {
                    return None;
                }
            }
            ItemMatcher::EndsWith(p) => {
                if !reply.ends_with(p) {
                    return None;
                }
            }
            ItemMatcher::Contains(p) => {
                if !reply.windows(p.len()).any(|w| w == p.as_slice()) {
                    return None;
                }
            }
        }
    }
    Some(out)
}

/// proto 命中字段表 → 规范值（字段名与 `--eng` 展示一致）。
fn proto_field(hit: &ProtoHit, name: &str) -> Option<FVal> {
    hit.fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| match v {
            ProtoVal::Int(i) => FVal::U(*i as u64),
            ProtoVal::Str(s) => FVal::S(s.clone()),
            ProtoVal::Bytes(b) => FVal::S(b.iter().map(|x| format!("{x:02x}")).collect()),
        })
}

/// proto 字段值的线格式字节（sniffer Expr 匹配用；与 `layer_field_bytes` 的 IR 层
/// 字节形态一致：数值大端、字节原样、字符串 UTF-8）。
///
/// 数值字段按**声明类型定宽**编码（u8→1B / u16→2B / u32→4B / u64→8B）：此前按
/// 值大小取最小宽度——u8 字段值 1 编码成 2B [00 01]，与 `u8(1)`（1B）恒不匹配，
/// 而 `be16(1)` 反而误匹配；注册表查不到（用户自建裸 proto 未注册）时回退最小宽度。
fn proto_field_bytes(hit: &ProtoHit, name: &str, v: &FVal) -> Option<Vec<u8>> {
    Some(match v {
        FVal::U(u) => {
            use crate::ast::FieldType;
            let width = crate::proto::proto_registry()
                .iter()
                .find(|p| p.name == hit.name)
                .and_then(|p| p.fields.iter().find(|f| f.name == name))
                .and_then(|f| match f.ty {
                    FieldType::U8 => Some(1),
                    FieldType::Be16 | FieldType::Le16 => Some(2),
                    FieldType::Be32 | FieldType::Le32 => Some(4),
                    FieldType::Be64 | FieldType::Le64 => Some(8),
                    _ => None,
                });
            match width {
                Some(w) => {
                    let b = u.to_be_bytes();
                    b[8 - w..].to_vec()
                }
                None => {
                    // 回退：按值大小取最小大端宽度
                    let b = u.to_be_bytes();
                    if *u <= 0xFFFF {
                        b[6..].to_vec()
                    } else if *u <= 0xFFFF_FFFF {
                        b[4..].to_vec()
                    } else {
                        b.to_vec()
                    }
                }
            }
        }
        FVal::Ip4(a) => a.octets().to_vec(),
        FVal::Ip6(a) => a.octets().to_vec(),
        FVal::Mac(m) => m.0.to_vec(),
        FVal::S(s) => s.as_bytes().to_vec(),
    })
}

/// 按 sniffer 声明校验回包（宿主/测试用）：`spec` 取自 `Module.sniffer`。
///
/// 无模块上下文：`Expr` 值表达式仅支持内置原语（`be16`/`concat`/`u8`/`mac`/`ip4`…），
/// 引用用户值函数请用 [`sniffer_match_with`]。
pub fn sniffer_match(
    spec: &SnifferSpec,
    reply: &[u8],
    sent: &[u8],
) -> PktResult<Option<Vec<(String, String)>>> {
    sniffer_match_with(spec, None, &Params::new(), reply, sent)
}

/// 按 sniffer 声明校验回包（带模块 + 运行时参数）：`Expr` 值表达式可引用同文件
/// 值函数（`func ... -> bytes`）与 `params(...)`，求值为字节后与回包字段字节比较。
pub fn sniffer_match_with(
    spec: &SnifferSpec,
    module: Option<&Module>,
    params: &Params,
    reply: &[u8],
    sent: &[u8],
) -> PktResult<Option<Vec<(String, String)>>> {
    let m = Matcher::build(spec, module, params, &Globals::new(), true)?;
    let sent_report = crate::dissect::dissect(sent);
    Ok(m.matches(reply, Some(&sent_report)))
}
