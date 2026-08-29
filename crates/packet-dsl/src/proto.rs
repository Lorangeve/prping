//! proto 解析侧（M2）：同一声明反向读字节 + 规则分派 + 全局注册表。
//!
//! - [`ResolvedProto`]：语义阶段产出的可解析 proto（分派规则 + 字段表）。
//! - [`set_proto_registry`]：宿主（prping）在入口加载 eng_lib 的 proto 注册一次
//!   （`OnceLock` 只读，dissect 并发安全）。
//! - [`parse_proto`]：按字段声明顺序从字节解码（`bytes(宽度)` 引用前序字段；
//!   `@auto`/`@len` 在线格式上正常读；`rest` 消费到末尾；规则掩码先验首字节）。
//! - [`ProtoHit`]：解析结果（通用字段表，供 `DissectReport.proto` / 展示 / 转码）。

use std::sync::OnceLock;

use crate::ast::{BinOp, Value};

/// 分派原子条件（`#[rule(udp(dport=443))]` 的上下文子条件；规则侧声明与
/// dissect 侧观测值共用同一结构）。
#[derive(Debug, Clone, PartialEq)]
pub enum RuleCond {
    Eth {
        ethertype: Option<u16>,
    },
    Ipv4 {
        proto: Option<u8>,
    },
    Ipv6 {
        next_header: Option<u8>,
    },
    Tcp {
        dport: Option<u16>,
        sport: Option<u16>,
    },
    Udp {
        dport: Option<u16>,
        sport: Option<u16>,
    },
}

/// 上下文子条件所在层（eth/ipv4/ipv6/tcp/udp；语义阶段保证同一 proto 的
/// 上下文子条件全部同层——dissect 按层分派，跨层条件无法在单点判定）。
pub(crate) fn cond_layer(b: &RuleCond) -> &'static str {
    match b {
        RuleCond::Eth { .. } => "eth",
        RuleCond::Ipv4 { .. } => "ipv4",
        RuleCond::Ipv6 { .. } => "ipv6",
        RuleCond::Tcp { .. } => "tcp",
        RuleCond::Udp { .. } => "udp",
    }
}

/// 单个上下文子条件与分派点观测值是否匹配（未指定的键 = 通配）。
fn cond_matches(rule: &RuleCond, kind: &RuleCond) -> bool {
    match (rule, kind) {
        (
            RuleCond::Udp {
                dport: pd,
                sport: ps,
            },
            RuleCond::Udp { dport, sport },
        ) => (pd.is_none() || *pd == *dport) && (ps.is_none() || *ps == *sport),
        (
            RuleCond::Tcp {
                dport: pd,
                sport: ps,
            },
            RuleCond::Tcp { dport, sport },
        ) => (pd.is_none() || *pd == *dport) && (ps.is_none() || *ps == *sport),
        (RuleCond::Ipv4 { proto: pp }, RuleCond::Ipv4 { proto }) => pp.is_none() || *pp == *proto,
        (RuleCond::Ipv6 { next_header: pp }, RuleCond::Ipv6 { next_header }) => {
            pp.is_none() || *pp == *next_header
        }
        (RuleCond::Eth { ethertype: pe }, RuleCond::Eth { ethertype }) => {
            pe.is_none() || *pe == *ethertype
        }
        _ => false,
    }
}

/// 一个 proto 的分派规则：上下文条件（端口/协议号）+ 匹配函数列表（AND 组合）。
///
/// - `ctxs`：上下文条件表达式（`#[rule(udp(dport=443))]` 等，按层分派候选）
/// - `matches`：匹配函数列表（`#[rule(startswith("HTTP/"))]` 等，解析期校验）
///
/// 匹配函数通过 [`MatchTarget`] 定位到报文/字段的字节内容，或通过字段名提取
/// 解析值做比较（`ne`/`eq`）。全部 AND 组合；`or(...)` 内只允许上下文条件。
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub ctxs: Vec<CtxCond>,
    pub matches: Vec<MatchFn>,
}

/// rule 匹配函数，隐式返回 bool（proto 上下文里使用）。
///
/// 分两类：
/// - **字节模式**（`StartsWith`/`EndsWith`/`Contains`）：从 [`MatchTarget`] 取
///   字节切片，做前缀/后缀/子串匹配。
/// - **值约束**（`Eq`/`Ne`）：从 proto 解析结果提取字段值，与字面量比较。
#[derive(Debug, Clone, PartialEq)]
pub enum MatchFn {
    /// 首字节位掩码（`#[rule(bytes(0xc0))]`）：`(首字节 & mask) == mask`。
    /// 保留兼容，后续由 `mask` 原语替代。
    Mask(u8),
    /// 前缀匹配：`#[rule(startswith("HTTP/"))]`。
    StartsWith {
        pattern: Vec<u8>,
        target: MatchTarget,
    },
    /// 后缀匹配：`#[rule(endswith("\r\n\r\n"))]`。
    EndsWith {
        pattern: Vec<u8>,
        target: MatchTarget,
    },
    /// 子串包含：`#[rule(contains("HTTP/"))]`。
    Contains {
        pattern: Vec<u8>,
        target: MatchTarget,
    },
    /// 字段值相等：`#[rule(eq(qdcount, 0))]`。
    Eq { field: String, value: MatchVal },
    /// 字段值不等：`#[rule(ne(qdcount, 0))]`。
    Ne { field: String, value: MatchVal },
    /// 任一子条件满足（`#[rule(or(...))]` 内的字段值约束）。
    Or(Vec<MatchFn>),
    /// 全部子条件满足（`#[rule(and(...))]` 内的字段值约束，通常隐式 AND）。
    And(Vec<MatchFn>),
}

/// 匹配目标：匹配函数作用的字节范围。
#[derive(Debug, Clone, PartialEq)]
pub enum MatchTarget {
    /// 整个报文（默认，无 `at`/`in` 时）。
    Whole,
    /// 从报文偏移开始（`#[rule(startswith("HTTP/", at=6))]`）。
    Offset(usize),
    /// 字段的字节范围（`#[rule(startswith("HTTP/", in=start_line))]`，
    /// 字段名 = `#[meta(name=...)]` 或参数名）。
    Field(String),
}

/// 匹配值：`eq`/`ne` 的字面量比较值。
#[derive(Debug, Clone, PartialEq)]
pub enum MatchVal {
    Int(i64),
    Bytes(Vec<u8>),
    Str(String),
}

/// rule 校验上下文：proto 解析的完整结果，供匹配函数提取数据。
pub struct RuleContext<'a> {
    pub bytes: &'a [u8],
    pub hit: &'a ProtoHit,
    pub field_ranges: &'a [(String, usize, usize)],
}

impl Rule {
    pub fn is_empty(&self) -> bool {
        self.ctxs.is_empty() && self.matches.is_empty()
    }

    /// 在分派点 `kind`（某层实际观测值）是否命中：任一上下文条件表达式求值为真
    /// （每个条件内部全部原子同层，语义阶段已校验；无 ctx 则永不命中）。
    pub fn matches_cond(&self, kind: &RuleCond) -> bool {
        self.ctxs.iter().any(|c| c.matches(kind))
    }

    /// 全部匹配函数是否通过（AND 组合）。从 `RuleContext` 提取数据，逐条校验。
    pub fn matches_proto(&self, ctx: &RuleContext) -> bool {
        self.matches.iter().all(|m| m.eval(ctx))
    }

    /// 便捷方法：对单字节做 Whole 模式匹配（测试用）。
    pub fn matches_bytes(&self, bytes: &[u8]) -> bool {
        let empty = ProtoHit {
            name: String::new(),
            fields: Vec::new(),
            subs: Vec::new(),
        };
        let ctx = RuleContext {
            bytes,
            hit: &empty,
            field_ranges: &[],
        };
        self.matches_proto(&ctx)
    }
}

impl MatchFn {
    /// 在 rule 上下文里求值，隐式返回 bool。
    fn eval(&self, ctx: &RuleContext) -> bool {
        match self {
            MatchFn::Mask(m) => ctx.bytes.first().is_some_and(|b| b & m == *m),
            MatchFn::StartsWith { pattern, target } => {
                target_bytes(ctx, target).is_some_and(|b| b.starts_with(pattern))
            }
            MatchFn::EndsWith { pattern, target } => {
                target_bytes(ctx, target).is_some_and(|b| b.ends_with(pattern))
            }
            MatchFn::Contains { pattern, target } => target_bytes(ctx, target)
                .is_some_and(|b| b.windows(pattern.len()).any(|w| w == pattern.as_slice())),
            MatchFn::Eq { field, value } => {
                field_val(ctx, field).is_some_and(|v| match_val_eq(v, value))
            }
            MatchFn::Ne { field, value } => {
                field_val(ctx, field).is_some_and(|v| !match_val_eq(v, value))
            }
            MatchFn::Or(fns) => fns.iter().any(|f| f.eval(ctx)),
            MatchFn::And(fns) => fns.iter().all(|f| f.eval(ctx)),
        }
    }

    /// 匹配目标是否需要解析后校验（需要字段范围或非 Whole）。
    pub fn needs_parse_result(&self) -> bool {
        match self {
            MatchFn::Mask(_) => false, // 掩码检查首字节，不依赖 parse 结果
            MatchFn::Eq { .. } | MatchFn::Ne { .. } => true,
            MatchFn::Or(fns) | MatchFn::And(fns) => fns.iter().any(|f| f.needs_parse_result()),
            MatchFn::StartsWith { target, .. }
            | MatchFn::EndsWith { target, .. }
            | MatchFn::Contains { target, .. } => !matches!(target, MatchTarget::Whole),
        }
    }

    /// 是否为字节内容匹配（掩码/前缀/后缀/子串），区别于字段值约束（eq/ne/or/and）。
    /// `or(...)` 分支只禁止字节内容匹配（无层可挂），允许字段值约束。
    pub fn is_byte_pattern(&self) -> bool {
        matches!(
            self,
            MatchFn::Mask(_)
                | MatchFn::StartsWith { .. }
                | MatchFn::EndsWith { .. }
                | MatchFn::Contains { .. }
        )
    }
}

/// 从上下文提取字节切片。
fn target_bytes<'a>(ctx: &'a RuleContext, target: &MatchTarget) -> Option<&'a [u8]> {
    match target {
        MatchTarget::Whole => Some(ctx.bytes),
        MatchTarget::Offset(n) => ctx.bytes.get(*n..),
        MatchTarget::Field(name) => {
            let (_, start, end) = ctx.field_ranges.iter().find(|(n, _, _)| n == name)?;
            ctx.bytes.get(*start..*end)
        }
    }
}

/// 从上下文提取字段解析值。
fn field_val<'a>(ctx: &'a RuleContext, field: &str) -> Option<&'a ProtoVal> {
    ctx.hit
        .fields
        .iter()
        .find(|(n, _)| n == field)
        .map(|(_, v)| v)
}

/// MatchVal 与 ProtoVal 的等值比较。
fn match_val_eq(proto_val: &ProtoVal, match_val: &MatchVal) -> bool {
    match match_val {
        MatchVal::Int(i) => proto_val.as_int() == Some(*i),
        MatchVal::Bytes(b) => match proto_val {
            ProtoVal::Bytes(pb) => pb == b,
            ProtoVal::Str(s) => s.as_bytes() == b.as_slice(),
            ProtoVal::Int(_) => false,
        },
        MatchVal::Str(s) => match proto_val {
            ProtoVal::Str(ps) => ps == s,
            ProtoVal::Bytes(pb) => pb == s.as_bytes(),
            ProtoVal::Int(_) => false,
        },
    }
}

/// 上下文条件表达式（`#[rule(...)]` 的 ctx 部分）：原子条件 / and / or 树。
#[derive(Debug, Clone, PartialEq)]
pub enum CtxCond {
    /// 原子上下文子条件（`udp(dport=443)` 等）。
    Atom(RuleCond),
    /// 全部子条件满足（`and(...)`）。
    And(Vec<CtxCond>),
    /// 任一子条件满足（`or(...)`）。
    Or(Vec<CtxCond>),
}

impl CtxCond {
    /// 与分派点观测值求值（`kind` 为当前层实际值；所有原子条件同层）。
    pub fn matches(&self, kind: &RuleCond) -> bool {
        match self {
            CtxCond::Atom(b) => cond_matches(b, kind),
            CtxCond::And(v) => v.iter().all(|c| c.matches(kind)),
            CtxCond::Or(v) => v.iter().any(|c| c.matches(kind)),
        }
    }

    /// 构造 `and(...)`：折叠嵌套 And、单子条件退化为原子（`and(a)` ≡ `a`）。
    pub(crate) fn and(children: Vec<CtxCond>) -> CtxCond {
        let mut flat = Vec::new();
        for c in children {
            match c {
                CtxCond::And(inner) => flat.extend(inner),
                other => flat.push(other),
            }
        }
        if flat.len() == 1 {
            flat.pop().expect("len==1")
        } else {
            CtxCond::And(flat)
        }
    }

    /// 构造 `or(...)`：折叠嵌套 Or、单子条件退化为原子（`or(a)` ≡ `a`）。
    pub(crate) fn or(children: Vec<CtxCond>) -> CtxCond {
        let mut flat = Vec::new();
        for c in children {
            match c {
                CtxCond::Or(inner) => flat.extend(inner),
                other => flat.push(other),
            }
        }
        if flat.len() == 1 {
            flat.pop().expect("len==1")
        } else {
            CtxCond::Or(flat)
        }
    }
}

/// 收集表达式里全部原子条件的层（语义阶段校验同层用）。
pub(crate) fn ctx_cond_layers(c: &CtxCond, out: &mut Vec<&'static str>) {
    match c {
        CtxCond::Atom(b) => out.push(cond_layer(b)),
        CtxCond::And(v) | CtxCond::Or(v) => {
            for x in v {
                ctx_cond_layers(x, out);
            }
        }
    }
}

/// 从 (分派层, 键值对) 构建上下文规则（`#[rule(layer=..., dport=...) ]` 的语义）。
pub fn build_cond(layer: &str, vals: &[(String, String)]) -> crate::diag::PktResult<RuleCond> {
    let num = |v: &str| -> crate::diag::PktResult<u64> {
        if let Some(h) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
            u64::from_str_radix(h, 16).map_err(|_| {
                crate::diag::Diagnostic::new(format!("`#[rule]` 参数值 `{v}` 不是十六进制数"))
            })
        } else {
            v.parse().map_err(|_| {
                crate::diag::Diagnostic::new(format!("`#[rule]` 参数值 `{v}` 不是数字"))
            })
        }
    };
    let take = |name: &str| -> crate::diag::PktResult<Option<u64>> {
        for (k, v) in vals {
            if k == name {
                return num(v).map(Some);
            }
        }
        Ok(None)
    };
    for (k, _) in vals {
        if !matches!(
            k.as_str(),
            "dport" | "sport" | "proto" | "next_header" | "ethertype"
        ) {
            return Err(crate::diag::Diagnostic::new(format!(
                "`#[rule]` 未知参数 `{k}`（支持 dport/sport/proto/next_header/ethertype）"
            )));
        }
    }
    let u16v = |v: Option<u64>| v.map(|n| n as u16);
    let u8v = |v: Option<u64>| v.map(|n| n as u8);

    match layer {
        "eth" => Ok(RuleCond::Eth {
            ethertype: u16v(take("ethertype")?),
        }),
        "ipv4" => Ok(RuleCond::Ipv4 {
            proto: u8v(take("proto")?),
        }),
        "ipv6" => Ok(RuleCond::Ipv6 {
            next_header: u8v(take("next_header")?),
        }),
        "tcp" => Ok(RuleCond::Tcp {
            dport: u16v(take("dport")?),
            sport: u16v(take("sport")?),
        }),
        "udp" => Ok(RuleCond::Udp {
            dport: u16v(take("dport")?),
            sport: u16v(take("sport")?),
        }),
        other => Err(crate::diag::Diagnostic::new(format!(
            "`#[rule]` 层 `{other}` 无效（支持 eth/ipv4/ipv6/tcp/udp）"
        ))),
    }
}

pub fn parse_cond(s: &str) -> crate::diag::PktResult<RuleCond> {
    // 旧字符串形式（`udp(dport=443)`）——`#[rule]` 已改为键值对，保留供外部 API 使用
    let (head, inner) = s.split_once('(').ok_or_else(|| {
        crate::diag::Diagnostic::new(format!(
            "分派条件语法错误：`{s}`（应为 `udp(dport=443)` 等）"
        ))
    })?;
    let inner = inner.strip_suffix(')').ok_or_else(|| {
        crate::diag::Diagnostic::new(format!("分派条件语法错误：`{s}` 缺少结尾 `)`"))
    })?;
    let mut vals: Vec<(String, String)> = Vec::new();
    for kv in inner.split(',') {
        let kv = kv.trim();
        if kv.is_empty() {
            continue;
        }
        let Some((k, v)) = kv.split_once('=') else {
            return Err(crate::diag::Diagnostic::new(format!(
                "分派条件参数 `{kv}` 需要 `k=v` 形式"
            )));
        };
        vals.push((k.trim().to_string(), v.trim().to_string()));
    }
    build_cond(head.trim(), &vals)
}

/// 可解析的 proto（注册表条目）。
#[derive(Debug, Clone)]
pub struct ResolvedProto {
    pub name: String,
    /// IR 层类型（`#[proto(kind=...)]`；None = 仅构造/解析的裸协议，如 QUIC）。
    pub layer: Option<String>,
    /// 分派规则（`#[rule]` 注解；None = 不参与 dissect 自动分派，可作
    /// `rest(子proto)` 解析目标）。
    pub rule: Option<Rule>,
    /// 值参数（只参与构造）。
    pub params: Vec<crate::ast::FuncParam>,
    pub fields: Vec<crate::ast::FieldDecl>,
}

/// 全局 proto 注册表（`OnceLock`：首次注册后只读，dissect 并发安全）。
static PROTO_REGISTRY: OnceLock<Vec<ResolvedProto>> = OnceLock::new();

/// 注册全局 proto 表（宿主入口调用一次；重复注册忽略）。
pub fn set_proto_registry(protos: Vec<ResolvedProto>) {
    let _ = PROTO_REGISTRY.set(protos);
}

/// 已注册的 proto（空表 = 未加载，dissect 行为与无 proto 时一致）。
pub fn proto_registry() -> &'static [ResolvedProto] {
    PROTO_REGISTRY.get().map(|v| v.as_slice()).unwrap_or(&[])
}

/// 按分派点（传输层端口/网络层协议/链路 ethertype）找规则命中的 proto。
pub(crate) fn find_rule<'a>(
    registry: &'a [ResolvedProto],
    kind: &RuleCond,
) -> Vec<&'a ResolvedProto> {
    registry
        .iter()
        .filter(|p| p.rule.as_ref().is_some_and(|r| r.matches_cond(kind)))
        .collect()
}

/// 按 IR 层类型找 proto（`#[proto(kind="eth")]` 等层头声明，无 rule 分派——
/// dissect 层头解析用它：固定层序 + 注册表字段表反解，失败 → None（按 raw 保留））。
pub(crate) fn find_by_kind<'a>(
    registry: &'a [ResolvedProto],
    kind: &str,
) -> Option<&'a ResolvedProto> {
    registry.iter().find(|p| p.layer.as_deref() == Some(kind))
}

/// 内容识别候选：端口/协议规则未命中时，回退按内容反解的 proto。
///
/// 协议识别应以内容为准（格式/魔数/结构），端口只是可选提示。候选集合：
/// - 应用层 IR 协议（`kind="http"` / `kind="dns"`）：靠声明结构 + 匹配函数
///   （`startswith`/`contains` 等魔数、`ne` 区计数）识别，不依赖端口；
/// - 带匹配函数的裸 proto（如 QUIC `startswith(...)` ）：靠魔数先验。
///
/// 排除层头（eth/arp/ipv4/ipv6/icmp/tcp/udp）与无内容判别力的裸 proto
/// （如 dns_question/dns_answer 子 proto，无匹配函数会误报任意字节）。
pub(crate) fn find_content_candidates(registry: &[ResolvedProto]) -> Vec<&ResolvedProto> {
    registry
        .iter()
        .filter(|p| match p.layer.as_deref() {
            Some("http") | Some("dns") => true,
            None => p.rule.as_ref().is_some_and(|r| !r.matches.is_empty()),
            _ => false,
        })
        .collect()
}

/// 解析结果字段值（展示/转码用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoVal {
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
}

impl ProtoVal {
    /// 展示字符串（与 dissect 层字段风格一致）。
    pub fn display(&self) -> String {
        match self {
            ProtoVal::Int(i) => i.to_string(),
            ProtoVal::Str(s) => s.clone(),
            ProtoVal::Bytes(b) => {
                if b.len() <= 8 {
                    b.iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<Vec<_>>()
                        .join("")
                } else {
                    format!("{} bytes", b.len())
                }
            }
        }
    }

    /// 数值（宽度引用用）。
    pub fn as_int(&self) -> Option<i64> {
        match self {
            ProtoVal::Int(i) => Some(*i),
            _ => None,
        }
    }
}

/// 一条 proto 解析命中。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoHit {
    pub name: String,
    pub fields: Vec<(String, ProtoVal)>,
    /// `rest(子proto)` 递归解析出的嵌套命中（如 QUIC 的 CRYPTO 帧序列）。
    pub subs: Vec<ProtoHit>,
}

/// 按字段声明从字节解码（M2 解析解释器）。
///
/// 失败（掩码不匹配 / 字段越界 / 宽度不可求值 / 常量字段不符）→ None（调用方回退 raw）。
pub fn parse_proto(resolved: &ResolvedProto, bytes: &[u8]) -> Option<ProtoHit> {
    parse_until(resolved, bytes, bytes, 0, None).map(|(hit, _)| hit)
}

/// 子 proto 递归解析（rest/list 元素）：`bytes` 是完整报文 `full[base..]` 的切片，
/// `base` = 切片在完整报文中的起始偏移（DNS 压缩指针追跳用绝对偏移）。
fn parse_consumed_at(
    resolved: &ResolvedProto,
    bytes: &[u8],
    full: &[u8],
    base: usize,
) -> Option<(ProtoHit, usize)> {
    parse_until(resolved, bytes, full, base, None)
}

/// 层头反解：同 [`parse_consumed`]，但**遇 rest 字段即停**（rest = 载荷区，
/// 不属于层头——如 ICMP 的 payload 字段；层头字节 = rest 之前的定长/变长字段）。
/// 返回 (ProtoHit, 层头字节数)；ProtoHit 不含 rest 字段（载荷留待调用方）。
/// dissect 层头按 proto 注册表反解用（`find_by_kind` + 本函数）。
pub fn parse_header(resolved: &ResolvedProto, bytes: &[u8]) -> Option<(ProtoHit, usize)> {
    parse_until(resolved, bytes, bytes, 0, Some(true))
}

fn parse_until(
    resolved: &ResolvedProto,
    bytes: &[u8],
    full: &[u8],
    base: usize,
    stop_at_rest: Option<bool>,
) -> Option<(ProtoHit, usize)> {
    // 匹配函数先验：Whole 模式的字节匹配（不依赖 parse 结果，可提前快速失败）
    if let Some(rule) = &resolved.rule {
        for m in &rule.matches {
            if !m.needs_parse_result()
                && !m.eval(&RuleContext {
                    bytes,
                    hit: &ProtoHit {
                        name: String::new(),
                        fields: Vec::new(),
                        subs: Vec::new(),
                    },
                    field_ranges: &[],
                })
            {
                return None;
            }
        }
    }
    let mut pos = 0usize; // 字节游标（普通字段按字节推进）
    let mut bitpos = 0usize; // 当前字节内位偏移（bits 字段；普通字段处须为 0）
    let mut fields: Vec<(String, ProtoVal)> = Vec::with_capacity(resolved.fields.len());
    let mut vals: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    let mut subs: Vec<ProtoHit> = Vec::new();
    let mut field_ranges: Vec<(String, usize, usize)> = Vec::new();
    for f in &resolved.fields {
        if stop_at_rest == Some(true) && f.ty == crate::ast::FieldType::Rest {
            break; // 层头边界：rest 字段 = 载荷区，不消费
        }
        let pos_before = pos + bitpos / 8;
        // decode_field 返回消费**位数**（bits 字段 < 8，普通字段为 8 的倍数）
        let (v, n) = decode_field(f, bytes, full, base, pos, bitpos, &vals, &mut subs)?;
        pos += (bitpos + n) / 8;
        bitpos = (bitpos + n) % 8;
        let pos_after = pos + bitpos / 8;
        if let Some(i) = v.as_int() {
            vals.insert(f.name.clone(), i);
        }
        fields.push((f.name.clone(), v));
        field_ranges.push((f.name.clone(), pos_before, pos_after));
    }
    let hit = ProtoHit {
        name: resolved.name.clone(),
        fields,
        subs,
    };
    // 匹配函数解析后校验：需要 parse 结果的 MatchFn（offset/字段目标、值约束）
    if let Some(rule) = &resolved.rule {
        let ctx = RuleContext {
            bytes,
            hit: &hit,
            field_ranges: &field_ranges,
        };
        if !rule.matches_proto(&ctx) {
            return None;
        }
    }
    Some((hit, pos))
}

/// 重复解析子协议直到字节耗尽或失败（`rest(子proto)` 字段 = 原哨兵 list 语义）。
/// 返回消费的字节数（到第一个失败的子 proto 为止；失败帧本身不消费——
/// 剩余留在后续字段/载荷区，如 HTTP headers 到空行即停、body 由下一字段接）。
fn parse_sub_sequence(
    name: &str,
    bytes: &[u8],
    full: &[u8],
    base: usize,
    subs: &mut Vec<ProtoHit>,
) -> usize {
    let Some(sub) = proto_registry().iter().find(|p| p.name == name) else {
        return 0;
    };
    let mut rest = bytes;
    let mut consumed = 0usize;
    while !rest.is_empty() {
        match parse_consumed_at(sub, rest, full, base) {
            // 零消费匹配（如 bytes=0 字段）：rest 不推进 → 死循环，直接停止
            Some((hit, n)) if n > 0 => {
                subs.push(hit);
                consumed += n;
                rest = &rest[n.min(rest.len())..];
            }
            _ => break, // 帧不匹配或零消费 → 停止，剩余不消费
        }
    }
    consumed
}

/// 按计数重复解析子协议（list 字段：`count` 次，每元素一个 `ProtoHit` 进 `subs`）。
/// 返回消费的字节数（全部元素解析成功）；任一元素解析失败 → 整体失败（回退 raw）。
fn parse_list_sequence(
    name: &str,
    bytes: &[u8],
    count: usize,
    full: &[u8],
    base: usize,
    subs: &mut Vec<ProtoHit>,
) -> Option<usize> {
    let sub = proto_registry().iter().find(|p| p.name == name)?;
    let mut rest = bytes;
    let mut consumed = 0usize;
    for _ in 0..count {
        let (hit, n) = parse_consumed_at(sub, rest, full, base)?;
        subs.push(hit);
        consumed += n;
        rest = &rest[n.min(rest.len())..];
    }
    Some(consumed)
}

/// 解码一个字段：返回 (值, 消费**位数**——bits 字段 < 8，普通字段为 8 的倍数)；
/// `rest(子proto)` 时递归填充 `subs`。
///
/// 常量校验：字段类型为定宽（数值/MAC/IP）且默认值是**字面量**（Int/Hex/Str）时，
/// 解码值与常量不符 → None（协议判别位；表达式默认值如 `bor(0xc0, pnl)` 跳过，
/// 由 `#[rule(bytes(...))]` 掩码承担判别）。
#[allow(clippy::too_many_arguments)]
fn decode_field(
    f: &crate::ast::FieldDecl,
    bytes: &[u8],
    full: &[u8],
    base: usize,
    pos: usize,
    bitpos: usize,
    vals: &std::collections::HashMap<String, i64>,
    subs: &mut Vec<ProtoHit>,
) -> Option<(ProtoVal, usize)> {
    use crate::ast::FieldType::*;
    let take = |n: usize| -> Option<&[u8]> {
        let end = pos.checked_add(n)?;
        bytes.get(pos..end)
    };
    // bits（位字段）：字节内取 N 位（大端：按声明顺序高位在前），不跨字节。
    // 与普通字段一样走下方的常量校验（字面量默认 = 判别位）。
    let decoded: Option<(ProtoVal, usize)> = if let Some(n) = f.bits {
        let n = n as usize;
        if f.ty != U8 || bitpos + n > 8 {
            None
        } else {
            let b = *bytes.get(pos)?;
            let shift = (8 - bitpos - n) as u32;
            let v = ((b >> shift) as i64) & ((1i64 << n) - 1);
            Some((ProtoVal::Int(v), n))
        }
    } else {
        // 普通字段：字节对齐（位组须凑满整字节，语义阶段已保证）
        if bitpos != 0 {
            return None;
        }
        match f.ty {
            U8 => Some((ProtoVal::Int(*take(1)?.first()? as i64), 8)),
            Be16 | Le16 => {
                let b = take(2)?;
                let v = if matches!(f.ty, Be16) {
                    u16::from_be_bytes([b[0], b[1]])
                } else {
                    u16::from_le_bytes([b[0], b[1]])
                };
                Some((ProtoVal::Int(v as i64), 16))
            }
            Be32 | Le32 => {
                let b = take(4)?;
                let v = if matches!(f.ty, Be32) {
                    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
                } else {
                    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
                };
                Some((ProtoVal::Int(v as i64), 32))
            }
            Be64 | Le64 => {
                let b = take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                let v = if matches!(f.ty, Be64) {
                    u64::from_be_bytes(a)
                } else {
                    u64::from_le_bytes(a)
                };
                Some((ProtoVal::Int(v as i64), 64))
            }
            Vint => {
                // 变长整数：方案数据化（codec 在字段上，构造侧 encode_field_type
                // 同一声明反向解码）——le128（续延位）/ prefix（前缀宽度表）/
                // table（内联 + 哨兵表）；编解码实现收敛在 codec.rs
                // （`VintCodec::encode`/`decode`），构造/解析共用同一份代码。
                let codec = f.vint.as_ref()?;
                let (v, n) = codec.decode(&bytes[pos..])?;
                Some((ProtoVal::Int(v), n * 8))
            }
            Mac => {
                let b = take(6)?;
                Some((
                    ProtoVal::Str(
                        b.iter()
                            .map(|x| format!("{x:02x}"))
                            .collect::<Vec<_>>()
                            .join(":"),
                    ),
                    6 * 8,
                ))
            }
            Ip4 => {
                let b = take(4)?;
                Some((
                    ProtoVal::Str(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])),
                    4 * 8,
                ))
            }
            Ip6 => {
                let b = take(16)?;
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                Some((
                    ProtoVal::Str(std::net::Ipv6Addr::from(a).to_string()),
                    16 * 8,
                ))
            }
            Bytes => {
                let w = eval_width(f.width.as_ref()?, vals)?;
                if w < 0 {
                    return None;
                }
                let n = w as usize;
                Some((ProtoVal::Bytes(take(n)?.to_vec()), n * 8))
            }
            DnsName => {
                // DNS 名字（标签序列 + 0 终止；压缩指针**追跳还原**）：
                // 在**完整报文**（full）上用绝对偏移（base + pos）读标签——压缩
                // 指针目标偏移是整报文的偏移（可能指向前面的 question 区，当前
                // 切片不含），追跳有界（防循环），值 = 还原的点分名字字符串。
                // **消费字节 = 原始位置的标签 + 终止**（0 或 2B 指针，切片内相对）
                // ——追跳段只参与值还原，不影响顺序消费。
                let mut labels: Vec<String> = Vec::new();
                let mut p = base + pos; // 绝对位置（完整报文中）
                let mut consumed = 0usize; // 原始位置消费（字节）
                let mut at_origin = true; // 是否还在原始位置（追跳后只读不消费）
                let mut jumps = 0usize;
                loop {
                    let &b = full.get(p)?;
                    match b & 0xC0 {
                        0x00 => {
                            if at_origin {
                                consumed += 1;
                            }
                            if b == 0 {
                                break;
                            }
                            let l = b as usize;
                            full.get(p + 1..p + 1 + l)?; // 标签内容越界检查
                            let label =
                                String::from_utf8_lossy(&full[p + 1..p + 1 + l]).to_string();
                            labels.push(label);
                            // 消费 = 长度字节(已加) + 标签内容 l 字节（不含长度字节）
                            if at_origin {
                                consumed += l;
                            }
                            p += 1 + l;
                        }
                        0xC0 => {
                            // 压缩指针：原始位置消费 2B；追跳到目标偏移继续读标签
                            full.get(p + 1)?;
                            if at_origin {
                                consumed += 2;
                            }
                            let target = (((b & 0x3F) as usize) << 8) | full[p + 1] as usize;
                            if target >= full.len() {
                                return None;
                            }
                            p = target;
                            at_origin = false;
                            jumps += 1;
                            if jumps > 32 {
                                return None; // 防循环
                            }
                        }
                        _ => return None, // 0x40/0x80 保留位
                    }
                }
                Some((ProtoVal::Str(labels.join(".")), consumed * 8))
            }
            Line => {
                // 文本行：读到 `\r\n`（或末尾容忍）；**空行（首字节 `\r`）→ 失败**
                // （list 哨兵终止判定：HTTP headers 读到空行即停止）。
                // 消费 = 行字节 + `\r\n`（2B）；值 = 行字符串（不含终止符）。
                let rest = &bytes[pos..];
                if rest.first() == Some(&b'\r') {
                    return None; // 空行
                }
                match rest.windows(2).position(|w| w == b"\r\n") {
                    Some(i) => {
                        let line = String::from_utf8_lossy(&rest[..i]).to_string();
                        Some((ProtoVal::Str(line), (i + 2) * 8))
                    }
                    None => {
                        // 无终止符（截断/末尾）：整段作一行
                        let line = String::from_utf8_lossy(rest).to_string();
                        Some((ProtoVal::Str(line), rest.len() * 8))
                    }
                }
            }
            Rest => {
                let rest = bytes[pos..].to_vec();
                // 重复区（rest 子 proto）：`#[meta(list="计数", item=...)]` 按 count
                // 表达式循环（任一元素失败 → 整体失败回退 raw）；`#[meta(rest="子proto")]`
                // 循环解析到失败（空行/不匹配即停——HTTP headers 以空行结束）。
                // 两者都只消费解析成功的字节，剩余留给后续字段（HTTP body 接在 headers 后）。
                if let Some(item) = &f.rest_proto {
                    let n = match &f.list_count {
                        Some(count) => {
                            let c = eval_width(count, vals)?;
                            if !(0..=0xFFFF).contains(&c) {
                                return None;
                            }
                            parse_list_sequence(item, &rest, c as usize, full, base + pos, subs)?
                        }
                        None => parse_sub_sequence(item, &rest, full, base + pos, subs),
                    };
                    return Some((ProtoVal::Bytes(rest[..n].to_vec()), n * 8));
                }
                Some((
                    ProtoVal::Bytes(rest),
                    (bytes.len() - pos) * 8, // 纯 rest：消费到末尾
                ))
            }
        }
    };
    // 常量校验（定宽字段 + 字面量默认）：协议判别位（如 quic_crypto 的 frame_type）
    let (v, n) = decoded?;
    let ok = match (&f.default, f.ty) {
        (Some(crate::ast::Value::Int(i)), U8 | Be16 | Be32 | Be64 | Le16 | Le32 | Le64 | Vint) => {
            v.as_int() == Some(*i)
        }
        (Some(crate::ast::Value::Hex(h)), U8 | Be16 | Be32 | Be64 | Le16 | Le32 | Le64 | Vint) => {
            v.as_int() == Some(*h as i64)
        }
        (Some(crate::ast::Value::Str(sv)), Mac | Ip4 | Ip6) => {
            matches!(&v, ProtoVal::Str(got) if got == sv)
        }
        _ => true, // 表达式默认/数据字段：不校验
    };
    if ok { Some((v, n)) } else { None }
}

/// 宽度/计数表达式求值（字面量 / 前序字段名 / `+` / 算术与位运算函数）。
pub(crate) fn eval_width(v: &Value, vals: &std::collections::HashMap<String, i64>) -> Option<i64> {
    match v {
        Value::Int(i) => Some(*i),
        Value::Hex(h) => Some(*h as i64),
        Value::Ident { name, .. } => vals.get(name).copied(),
        Value::BinOp {
            op: BinOp::Add,
            left,
            right,
            ..
        } => Some(eval_width(left, vals)?.checked_add(eval_width(right, vals)?)?),
        Value::Call { name, args, .. } => {
            let a = args
                .iter()
                .map(|x| eval_width(x, vals))
                .collect::<Option<Vec<i64>>>()?;
            match name.as_str() {
                "band" => a.into_iter().reduce(|x, y| x & y),
                "bor" => a.into_iter().reduce(|x, y| x | y),
                "bxor" => a.into_iter().reduce(|x, y| x ^ y),
                // checked 算术：溢出/非法移位量 → None（调用方回退 raw，不 panic）
                "shl" | "shr" | "mul" | "sub" | "div" => {
                    let mut it = a.into_iter();
                    let mut acc = it.next()?;
                    for y in it {
                        acc = match name.as_str() {
                            "shl" => u32::try_from(y).ok().and_then(|s| acc.checked_shl(s))?,
                            "shr" => u32::try_from(y).ok().and_then(|s| acc.checked_shr(s))?,
                            "mul" => acc.checked_mul(y)?,
                            "sub" => acc.checked_sub(y)?,
                            _ => {
                                if y == 0 {
                                    return None;
                                }
                                acc.checked_div(y)?
                            }
                        };
                    }
                    Some(acc)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一个最小可解析 proto：`first: u8` + `payload: rest`（消费到末尾）。
    fn min_proto(name: &str, rule: Rule) -> ResolvedProto {
        let span = crate::ast::Span::new(1, 1, 1, 1);
        ResolvedProto {
            name: name.to_string(),
            layer: None,
            rule: Some(rule),
            params: Vec::new(),
            fields: vec![
                crate::ast::FieldDecl {
                    name: "first".to_string(),
                    name_span: span,
                    ty: crate::ast::FieldType::U8,
                    width: None,
                    bits: None,
                    default: None,
                    len_of: None,
                    len_expr: None,
                    rest_proto: None,
                    list_count: None,
                    vint: None,
                    span,
                },
                crate::ast::FieldDecl {
                    name: "payload".to_string(),
                    name_span: span,
                    ty: crate::ast::FieldType::Rest,
                    width: None,
                    bits: None,
                    default: None,
                    len_of: None,
                    len_expr: None,
                    rest_proto: None,
                    list_count: None,
                    vint: None,
                    span,
                },
            ],
        }
    }

    /// `and(udp(dport=443), bytes(0xc0))` 端到端：分派（find_rule）+ 解析
    /// （掩码先验）全链路——只有端口 443 且首字节过掩码才命中。
    #[test]
    fn rule_and_dispatch_end_to_end() {
        let p = min_proto(
            "quic_and",
            Rule {
                ctxs: vec![CtxCond::Atom(RuleCond::Udp {
                    dport: Some(443),
                    sport: None,
                })],
                matches: vec![MatchFn::Mask(0xc0)],
            },
        );
        let reg = vec![p];
        // 命中：udp 443 + 首字节过掩码 → 反解出字段
        let kind = RuleCond::Udp {
            dport: Some(443),
            sport: Some(9),
        };
        let cands = find_rule(&reg, &kind);
        assert_eq!(cands.len(), 1, "udp 443 应命中候选");
        let hit = parse_proto(cands[0], &[0xc1, 0x00, 0x01]).expect("首字节过掩码应解析成功");
        assert_eq!(hit.name, "quic_and");
        assert_eq!(hit.fields.len(), 2);
        // 端口不符 → 不参与分派
        let other = RuleCond::Udp {
            dport: Some(53),
            sport: Some(9),
        };
        assert!(find_rule(&reg, &other).is_empty(), "非 443 端口不命中");
        // 端口对但首字节不过掩码 → 解析失败（回退 raw）
        let cands = find_rule(&reg, &kind);
        assert!(
            parse_proto(cands[0], &[0x40, 0x00, 0x01]).is_none(),
            "掩码不符应解析失败"
        );
        // tcp 层不命中 udp 规则
        let tcp = RuleCond::Tcp {
            dport: Some(443),
            sport: Some(9),
        };
        assert!(
            find_rule(&reg, &tcp).is_empty(),
            "tcp 分派点不命中 udp 规则"
        );
    }

    /// `or(udp(dport=443), udp(dport=4433))` + 独立掩码：多端口选一分派 +
    /// 掩码 AND 先验——任一端口命中、首字节仍须过掩码。
    #[test]
    fn rule_or_multi_port_with_mask() {
        let p = min_proto(
            "quic_or",
            Rule {
                ctxs: vec![CtxCond::Or(vec![
                    CtxCond::Atom(RuleCond::Udp {
                        dport: Some(443),
                        sport: None,
                    }),
                    CtxCond::Atom(RuleCond::Udp {
                        dport: Some(4433),
                        sport: None,
                    }),
                ])],
                matches: vec![MatchFn::Mask(0xc0)],
            },
        );
        let reg = vec![p];
        // 任一端口命中
        for dport in [443u16, 4433] {
            let kind = RuleCond::Udp {
                dport: Some(dport),
                sport: Some(9),
            };
            let cands = find_rule(&reg, &kind);
            assert_eq!(cands.len(), 1, "udp {dport} 应命中 or 规则");
            assert!(
                parse_proto(cands[0], &[0xc1, 0x00]).is_some(),
                "udp {dport} + 掩码过应解析成功"
            );
        }
        // 两端口之外不命中
        let other = RuleCond::Udp {
            dport: Some(8443),
            sport: Some(9),
        };
        assert!(find_rule(&reg, &other).is_empty(), "非 or 端口不命中");
        // 端口命中但掩码不过 → 解析失败
        let kind = RuleCond::Udp {
            dport: Some(443),
            sport: Some(9),
        };
        let cands = find_rule(&reg, &kind);
        assert!(
            parse_proto(cands[0], &[0x40, 0x00]).is_none(),
            "掩码不符应解析失败"
        );
    }

    /// 混合 and/or：`and(udp(dport=443), udp(sport=53))` 嵌套进 or 分支——
    /// or(and(...), udp(dport=4433))：443+sport53 或 4433 任一命中。
    #[test]
    fn rule_or_with_and_nested() {
        let p = min_proto(
            "quic_mix",
            Rule {
                ctxs: vec![CtxCond::Or(vec![
                    CtxCond::And(vec![
                        CtxCond::Atom(RuleCond::Udp {
                            dport: Some(443),
                            sport: Some(53),
                        }),
                        CtxCond::Atom(RuleCond::Udp {
                            dport: Some(443),
                            sport: None,
                        }),
                    ]),
                    CtxCond::Atom(RuleCond::Udp {
                        dport: Some(4433),
                        sport: None,
                    }),
                ])],
                matches: Vec::new(),
            },
        );
        let reg = vec![p];
        // and 分支：443 + sport 53
        let a = RuleCond::Udp {
            dport: Some(443),
            sport: Some(53),
        };
        assert!(
            find_rule(&reg, &a).len() == 1,
            "and 分支（443+sport53）应命中"
        );
        // and 分支里第一个原子满足但第二个不满足（sport 不符）→ 整体不命中
        let b = RuleCond::Udp {
            dport: Some(443),
            sport: Some(12345),
        };
        assert!(
            find_rule(&reg, &b).is_empty(),
            "and 分支须全部满足（sport 不符不命中）"
        );
        // or 第二分支：4433
        let c = RuleCond::Udp {
            dport: Some(4433),
            sport: Some(9999),
        };
        assert!(find_rule(&reg, &c).len() == 1, "or 第二分支 4433 应命中");
        // 都不满足
        let d = RuleCond::Udp {
            dport: Some(8443),
            sport: Some(9),
        };
        assert!(find_rule(&reg, &d).is_empty(), "两分支都不满足不命中");
    }

    /// `contains("HTTP/")` 内容子串判别：报文字节包含子串才解析，不含则失败
    /// （协议识别以内容为准——HTTP 的魔数 `HTTP/`，端口无关）。
    #[test]
    fn rule_contains_substring_dispatch() {
        let p = min_proto(
            "http_like",
            Rule {
                ctxs: Vec::new(),
                matches: vec![MatchFn::Contains {
                    pattern: b"HTTP/".to_vec(),
                    target: MatchTarget::Whole,
                }],
            },
        );
        let reg = [p];
        // 含子串 → 解析成功
        let hit = parse_proto(&reg[0], b"GET / HTTP/1.1\r\n").expect("含 HTTP/ 应解析成功");
        assert_eq!(hit.name, "http_like");
        // 不含子串 → 解析失败（内容魔数不符）
        assert!(
            parse_proto(&reg[0], b"hello world\r\n").is_none(),
            "不含 HTTP/ 应解析失败"
        );
    }
}
