//! 求值：`use` 展开、层位变体笛卡尔积、包组逐包包裹、组件循环检测、函数调用。
//!
//! 规则（设计 §4.4 / §5.2）：
//! - 每个 `use` 元件独立成包；多个 `use` 元件 → 多个包。
//! - 每层一个 `|>` 正常包裹，内 → 外依次嵌套。
//! - 包组（命名流水线展开出多个包）被 `use` 时逐包包裹。
//! - 组件引用（`|>` 层调用或 def expr 中的调用）解析为内置函数或用户元件。
//! - 函数（`func name(args) { body }`）：调用时绑定参数（未传 → 默认值或未设），
//!   函数体以「空包种子」求值——无 `use` 时从一个空包开始逐层包裹（层片段语义）。

use crate::ast::{Arg, BinOp, Call, Expr, FieldType, LenTarget, Pipeline, Value};
use crate::diag::{Diagnostic, PktResult};
use crate::ir::{BuildResult, Layer, PacketSpec, RawData};
use crate::registry::{FnEnv, Params, build_layers, is_builtin};
use crate::semantic::{LookupKind, Module, ModuleData, ModuleGraph};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// 配方全局存储（`.pktl` 的 `global:` 段 / 步骤 `extract` / 宿主 -G（--global）注入）：
/// 名字 → **类型化值**（`global("name")` 值原语读取；与 `params` 的字符串形状解析不同，
/// 全局值保持字面量类型——Int/Hex/Str/字节列表，可直接参与 `+`/`be16`/位运算）。
///
/// 宿主在配方每步求值前注入当前快照（extract 在步骤间更新），值在构建期内联进 IR。
pub type Globals = HashMap<String, Value>;

/// 回包字段访问器（`reply("层","字段")` 值原语；配方 extract 的 from 表达式求值时
/// 宿主注入——回包反解报告 + 字段提取都在宿主侧）。层/字段名 → 类型化值。
pub type ReplyAccess<'a> = &'a dyn Fn(&str, &str) -> Option<Value>;

/// 求值入口：默认导出 + 全部命名导出的包（export 顺序，默认导出在前），无运行时参数。
pub fn resolve(module: &Module) -> PktResult<BuildResult> {
    resolve_with_params(module, &Params::new())
}

/// 求值入口（带运行时参数）：脚本内 `params("name")` 从 `params` 取值。
pub fn resolve_with_params(module: &Module, params: &Params) -> PktResult<BuildResult> {
    resolve_with_globals(module, params, &Globals::new())
}

/// 求值入口（带运行时参数 + 配方全局存储）：`params("name")` 从 `params`、
/// `global("name")` 从 `globals` 取值（配方 `.pktl` 执行时注入）。
pub fn resolve_with_globals(
    module: &Module,
    params: &Params,
    globals: &Globals,
) -> PktResult<BuildResult> {
    let sources = resolve_sources_with_globals(module, params, globals)?;
    let packets = sources.into_iter().flat_map(|(_, pkts)| pkts).collect();
    Ok(BuildResult { packets })
}

/// 字节列表 → Value（每个字节为 Int 值）。
pub(crate) fn bytes_value(bytes: Vec<u8>) -> Value {
    Value::List(bytes.into_iter().map(|b| Value::Int(b as i64)).collect())
}

/// 层 → 头原始字节（proto 值位置调用取构建字节用；raw 分支层直接取 raw 字段）。
fn layer_raw_bytes(l: &Layer) -> Option<Vec<u8>> {
    Some(match l {
        Layer::Raw(r) => r.bytes.clone(),
        Layer::Ethernet(f) => f.raw.clone()?,
        Layer::Arp(f) => f.raw.clone()?,
        Layer::Ipv4(f) => f.raw.clone()?,
        Layer::Ipv6(f) => f.raw.clone()?,
        Layer::Icmp(f) => f.raw.clone()?,
        Layer::Tcp(f) => f.raw.clone()?,
        Layer::Udp(f) => f.raw.clone()?,
        Layer::Http(f) => f.raw.clone()?,
        Layer::Dns(f) => f.raw.clone()?,
    })
}

/// 值表达式：取位置 span（用于报错）。
fn v_span(v: &Value) -> crate::ast::Span {
    match v {
        Value::Call { span, .. }
        | Value::BinOp { span, .. }
        | Value::Ident { span, .. }
        | Value::Param { span, .. } => *span,
        _ => crate::ast::Span::new(0, 0, 0, 0),
    }
}

/// 值 → 字节列表（元素分类走 `shape` 表；报错文案属地在此——与 registry
/// 层参数路径的措辞不同，但"什么算字节"必须一致）。
fn bytes_of(v: &Value, span: crate::ast::Span) -> PktResult<Vec<u8>> {
    match v {
        Value::List(items) => match crate::shape::flat_bytes_checked(items) {
            Ok(bytes) => Ok(bytes),
            Err(bad) => Err(Diagnostic::at(
                format!(
                    "期望字节列表（0..255 整数），得到 {}",
                    crate::registry::describe(bad)
                ),
                span,
            )),
        },
        Value::Str(s) => Ok(s.as_bytes().to_vec()),
        other => Err(Diagnostic::at(
            format!(
                "期望字节列表或字符串，得到 {}",
                crate::registry::describe(other)
            ),
            span,
        )),
    }
}

/// 值 → 整数。
fn int_of(v: Option<&Value>, what: &str, span: crate::ast::Span) -> PktResult<i64> {
    match v {
        Some(Value::Int(i)) => Ok(*i),
        Some(Value::Hex(h)) => Ok(*h as i64),
        // 字符串不隐式转数值：显式用 `int("...")`（0x 前缀=十六进制，否则十进制）。
        // 裸字符串字面量进数字位置（如 `be16("0x4242")`）一律报错，写 0x/十进制字面量
        Some(Value::Str(s)) => Err(Diagnostic::at(
            format!(
                "`{what}` 需要整数，得到字符串 `{s}`——字符串不隐式转数值，写 0x/十进制字面量，或经 params(\"...\") 按形状解析"
            ),
            span,
        )),
        Some(other) => Err(Diagnostic::at(
            format!(
                "`{what}` 需要整数，得到 {}",
                crate::registry::describe(other)
            ),
            span,
        )),
        None => Err(Diagnostic::at(format!("`{what}` 缺少参数"), span)),
    }
}

/// 值 → 字符串。
fn str_of(v: Option<&Value>, what: &str, span: crate::ast::Span) -> PktResult<String> {
    match v {
        Some(Value::Str(s)) => Ok(s.clone()),
        Some(other) => Err(Diagnostic::at(
            format!(
                "`{what}` 需要字符串，得到 {}",
                crate::registry::describe(other)
            ),
            span,
        )),
        None => Err(Diagnostic::at(format!("`{what}` 缺少参数"), span)),
    }
}

// ── proto 字段编码辅助（mac/ip4/ip6）─────────────────────────────

/// 值 → 6 字节 MAC（字符串 `aa:bb:cc:dd:ee:ff`（分隔符 : - . 容忍）或 6 字节列表）。
fn mac_bytes(v: &Value, name: &str, span: crate::ast::Span) -> PktResult<Vec<u8>> {
    if let Value::List(_) = v {
        let b = bytes_of(v, span)?;
        if b.len() != 6 {
            return Err(Diagnostic::at(
                format!("字段 `{name}`：mac 需要 6 字节，得到 {} 字节列表", b.len()),
                span,
            ));
        }
        return Ok(b);
    }
    let s = str_of(Some(v), name, span)?;
    let parts: Vec<&str> = s.split([':', '-', '.']).collect();
    if parts.len() != 6 {
        return Err(Diagnostic::at(
            format!("字段 `{name}`：mac 需要 `aa:bb:cc:dd:ee:ff` 形式，得到 `{s}`"),
            span,
        ));
    }
    let mut out = Vec::with_capacity(6);
    for p in parts {
        let b = u8::from_str_radix(p, 16).map_err(|_| {
            Diagnostic::at(format!("字段 `{name}`：mac 段 `{p}` 不是十六进制"), span)
        })?;
        out.push(b);
    }
    Ok(out)
}

/// 值 → 4 字节 IPv4（点分字符串或 4 字节列表）。
fn ip4_bytes(v: &Value, name: &str, span: crate::ast::Span) -> PktResult<Vec<u8>> {
    if let Value::List(_) = v {
        let b = bytes_of(v, span)?;
        if b.len() != 4 {
            return Err(Diagnostic::at(
                format!("字段 `{name}`：ip4 需要 4 字节，得到 {} 字节列表", b.len()),
                span,
            ));
        }
        return Ok(b);
    }
    let s = str_of(Some(v), name, span)?;
    // `random` 关键字已随内置层函数移除（随机值改用 rand16/rand8 等字节原语），
    // 字面量 "random" 不应再被当域名解析——直接拒绝。
    if s.eq_ignore_ascii_case("random") {
        return Err(Diagnostic::at(
            format!("字段 `{name}`：`random` 关键字已移除，请用 rand16/rand8 等字节原语"),
            span,
        ));
    }
    match s.parse::<std::net::Ipv4Addr>() {
        Ok(a) => Ok(a.octets().to_vec()),
        Err(_) => {
            // 域名回退（与 `ip4(dns(host))` 一致；v4 优先）
            let addrs = crate::dns_lookup(&s);
            match addrs.iter().find(|a| a.is_ipv4()).or_else(|| addrs.first()) {
                Some(std::net::IpAddr::V4(a)) => Ok(a.octets().to_vec()),
                _ => Err(Diagnostic::at(
                    format!("字段 `{name}`：非法 IPv4 地址或无法解析的域名 `{s}`"),
                    span,
                )),
            }
        }
    }
}

/// 值 → 16 字节 IPv6（冒号字符串或 16 字节列表）。
fn ip6_bytes(v: &Value, name: &str, span: crate::ast::Span) -> PktResult<Vec<u8>> {
    if let Value::List(_) = v {
        let b = bytes_of(v, span)?;
        if b.len() != 16 {
            return Err(Diagnostic::at(
                format!("字段 `{name}`：ip6 需要 16 字节，得到 {} 字节列表", b.len()),
                span,
            ));
        }
        return Ok(b);
    }
    let s = str_of(Some(v), name, span)?;
    // 同 ip4_bytes：字面量 "random" 直接拒绝，不走域名解析。
    if s.eq_ignore_ascii_case("random") {
        return Err(Diagnostic::at(
            format!("字段 `{name}`：`random` 关键字已移除，请用 rand16/rand8 等字节原语"),
            span,
        ));
    }
    match s.parse::<std::net::Ipv6Addr>() {
        Ok(a) => Ok(a.octets().to_vec()),
        Err(_) => {
            // 域名回退（v6 优先）
            let addrs = crate::dns_lookup(&s);
            match addrs.iter().find(|a| a.is_ipv6()).or_else(|| addrs.first()) {
                Some(std::net::IpAddr::V6(a)) => Ok(a.octets().to_vec()),
                _ => Err(Diagnostic::at(
                    format!("字段 `{name}`：非法 IPv6 地址或无法解析的域名 `{s}`"),
                    span,
                )),
            }
        }
    }
}

/// 值 → IPv4 地址（src/dst 元数据用）。
fn ip4_of(v: &Value, span: crate::ast::Span) -> PktResult<std::net::Ipv4Addr> {
    let b = ip4_bytes(v, "src/dst", span)?;
    Ok(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

/// 值 → IPv6 地址（src/dst 元数据用）。
fn ip6_of(v: &Value, span: crate::ast::Span) -> PktResult<std::net::Ipv6Addr> {
    let b = ip6_bytes(v, "src/dst", span)?;
    Ok(std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(b).expect("ip6_bytes 已校验 16 字节"),
    ))
}

/// 定宽整数编码（值原语 u8/be16/be32/le16/le32 与字段类型 U8/Be16/.../Le64 共用）：
/// 数值（0..max-1）或恰好同宽字节列表（le 反转）→ 字节。`what` 为错误文案主语
/// （值原语传 `` `u8` `` 等，字段传 `字段 `x` 的 u8`）。
fn encode_int_bytes(
    v: Option<&Value>,
    width: usize,
    little: bool,
    max: u64,
    what: &str,
    span: crate::ast::Span,
) -> PktResult<Vec<u8>> {
    // 同宽字节直通（与 tpl/raw 的字节列表直通同一哲学）；le 变体反转
    if let Some(Value::List(_)) = v {
        let mut b = bytes_of(v.expect("已匹配 List"), span)?;
        if b.len() != width {
            return Err(Diagnostic::at(
                format!(
                    "{what} 需要恰好 {width} 字节（数值 0..={} 或同宽字节列表），得到 {} 字节",
                    max - 1,
                    b.len()
                ),
                span,
            ));
        }
        if little {
            b.reverse();
        }
        return Ok(b);
    }
    let n = int_of(v, what, span)?;
    if n < 0 || n as u64 >= max {
        return Err(Diagnostic::at(
            format!("{what} 参数超出范围 0..={}：{n}", max - 1),
            span,
        ));
    }
    // 先按低字节在前编码，大端再反转（高字节在前）
    let mut bytes: Vec<u8> = (0..width)
        .map(|i| ((n as u64 >> (i * 8)) & 0xFF) as u8)
        .collect();
    if !little {
        bytes.reverse();
    }
    Ok(bytes)
}

// vint 编解码实现已收敛到 codec.rs（`VintCodec::encode`/`decode`），构造（本文件
// `encode_field_type`）与解析（proto.rs `decode_field`）共用同一份代码防漂移。

// DNS 域名长度前缀编码已下沉为 tpl 的 `%L` 说明符（eng_lib/bytes.pkt 的
// `func dns_name(s) -> bytes { tpl("%L", s) }`），见 packet-dsl/src/tpl.rs。

/// 每字段的**打包后**字节数：`bits` 位组（连续位字段）的字节 = 组内总位宽/8，
/// 记在组内最后一个字段上（其余组内字段为 0）；普通字段 = 编码字节数。
/// `@auto`/`@len` 的字节数计算必须用此——位组压缩后字节数减少
/// （如 IPv4 version+ihl 两字段各 4 位 = 1 字节）。
fn packed_sizes(enc: &[Vec<u8>], bits: &[Option<u8>]) -> Vec<usize> {
    let mut out = vec![0usize; enc.len()];
    let mut i = 0;
    while i < enc.len() {
        if bits[i].is_some() {
            let mut total = 0usize;
            let mut j = i;
            while j < enc.len() && bits[j].is_some() {
                total += bits[j].expect("Some") as usize;
                j += 1;
            }
            debug_assert_eq!(total % 8, 0, "位组对齐在语义阶段已校验");
            out[j - 1] = total / 8;
            i = j;
        } else {
            out[i] = enc[i].len();
            i += 1;
        }
    }
    out
}

/// 把各字段编码片段按 `bits` 信息打包成最终字节流：位组内按声明顺序
/// 从高位到低位填充（大端位序），凑满 8 位即输出一字节；普通字段要求
/// 字节对齐（语义阶段已保证）。`bits` 字段的编码片段取低 N 位。
fn pack_fields(enc: &[Vec<u8>], bits: &[Option<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(enc.iter().map(|b| b.len()).sum());
    let mut acc: u128 = 0;
    let mut bitpos = 0usize;
    for (i, b) in enc.iter().enumerate() {
        match bits[i] {
            Some(n) => {
                let n = n as usize;
                // 位段值 = 编码字节的低 N 位（u8 位字段 = 单字节掩码；be32/be64
                // 多字节位字段 = 整值低 N 位，如 20 位 flow ⊂ be32 编码）
                let mut val: u128 = 0;
                for x in b {
                    val = (val << 8) | *x as u128;
                }
                val &= (1u128 << n) - 1;
                acc = (acc << n) | val;
                bitpos += n;
                while bitpos >= 8 {
                    out.push((acc >> (bitpos - 8)) as u8);
                    bitpos -= 8;
                }
                acc &= (1u128 << bitpos) - 1; // 清掉已刷新位（acc 只保留未刷位）
            }
            None => {
                debug_assert_eq!(bitpos, 0, "普通字段前位组未对齐（语义应已拦截）");
                out.extend_from_slice(b);
            }
        }
    }
    debug_assert_eq!(bitpos, 0, "结尾位组未对齐（语义应已拦截）");
    out
}

/// 包的来源（供宿主展示 / 归因）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketSource {
    /// 顶层匿名流水线（默认导出）。
    Default,
    /// 某个命名导出。
    Export(String),
}

/// 按来源分组求值（无运行时参数）：默认导出在前，命名导出按 export 顺序。
pub fn resolve_sources(module: &Module) -> PktResult<Vec<(PacketSource, Vec<PacketSpec>)>> {
    resolve_sources_with_params(module, &Params::new())
}

/// 按来源分组求值（带运行时参数）。
pub fn resolve_sources_with_params(
    module: &Module,
    params: &Params,
) -> PktResult<Vec<(PacketSource, Vec<PacketSpec>)>> {
    resolve_sources_with_globals(module, params, &Globals::new())
}

/// 按来源分组求值（带运行时参数 + 配方全局存储）：`global("name")` 值原语
/// 从 `globals` 取类型化值（`.pktl` 配方的 `global:`/`extract`/`-G`（--global）注入）。
pub fn resolve_sources_with_globals(
    module: &Module,
    params: &Params,
    globals: &Globals,
) -> PktResult<Vec<(PacketSource, Vec<PacketSpec>)>> {
    resolve_sources_ctx(module, params, globals, None)
}

/// 按来源分组求值（带运行时参数 + 全局存储 + **回包访问器**）：`reply("层","字段")`
/// 值原语从 `reply` 取收到的帧反解字段（配方 extract 求值专用入口；
/// 无访问器时 `reply` 回退用户函数）。
pub fn resolve_sources_with_reply<'a>(
    module: &Module,
    params: &Params,
    globals: &Globals,
    reply: ReplyAccess<'a>,
) -> PktResult<Vec<(PacketSource, Vec<PacketSpec>)>> {
    resolve_sources_ctx(module, params, globals, Some(reply))
}

/// 求值上下文共用体：`reply: Option` 控制 `reply("层","字段")` 是否可用。
fn resolve_sources_ctx(
    module: &Module,
    params: &Params,
    globals: &Globals,
    reply: Option<ReplyAccess<'_>>,
) -> PktResult<Vec<(PacketSource, Vec<PacketSpec>)>> {
    let entry = entry_index(module)?;
    let mut ctx = EvalCtx {
        graph: &module.graph,
        stack: Vec::new(),
        params,
        globals,
        reply,
        env_stack: vec![FnEnv::new()],
        value_depth: 0,
    };
    let mut out = Vec::new();
    if let Some((p, _)) = &module.default {
        let pkts = ctx.eval_pipeline(entry, p)?;
        if !pkts.is_empty() {
            out.push((PacketSource::Default, pkts));
        }
    }
    for (name, _span) in &module.exports {
        let pkts = ctx.eval_component(entry, name, &[])?;
        if !pkts.is_empty() {
            out.push((PacketSource::Export(name.clone()), pkts));
        }
    }
    Ok(out)
}

/// 求值 sniffer 匹配值表达式 → 字节列表（字节原语 / 用户值函数 / `params(...)` /
/// `global(...)` / 数字加法 / 字节列表字面量）。`module` 提供用户函数作用域
/// （同文件 `func ... -> bytes`）；`None` 时仅内置原语可用（宿主侧 `sniffer_match`
/// 无模块上下文时用）。
///
/// 与普通值表达式同一求值路径：函数最终算出的是**字节**，sniffer 的 match 值
/// 也按字节比较（`id=be16(0x1234)` ↔ 回包 id 的两字节）。
pub fn eval_sniffer_value(
    module: Option<&Module>,
    params: &Params,
    v: &Value,
) -> PktResult<Vec<u8>> {
    eval_sniffer_value_with_globals(module, params, &Globals::new(), v)
}

/// 同 [`eval_sniffer_value`]，但带配方全局存储（`global("name")` 值原语可引用
/// 配方 `global:`/`extract` 注入的值，如 `match icmp(id=global("tid"))`）。
pub fn eval_sniffer_value_with_globals(
    module: Option<&Module>,
    params: &Params,
    globals: &Globals,
    v: &Value,
) -> PktResult<Vec<u8>> {
    let module = match module {
        Some(m) => m,
        None => &builtin_only_module(),
    };
    let entry = entry_index(module)?;
    let mut ctx = EvalCtx {
        graph: &module.graph,
        stack: Vec::new(),
        params,
        globals,
        reply: None,
        env_stack: vec![FnEnv::new()],
        value_depth: 0,
    };
    let val = ctx.eval_value(entry, v)?;
    bytes_of(&val, v_span(v))
}

/// 求值配方 extract 的 `from:` 值表达式（带配方全局存储 + 回包字段访问器）：
/// 表达式可引用用户值函数 / `params(...)` / `global(...)` / `reply("层","字段")`，
/// 结果为**类型化值**（Int/Hex/Str/字节列表，按 `as:` 转换前的自然形态）。
/// `reply` 回调由宿主提供（回包反解 + 字段提取）；`module` 为 None 时仅内置原语。
pub fn eval_extract_value(
    module: Option<&Module>,
    params: &Params,
    globals: &Globals,
    reply: ReplyAccess<'_>,
    v: &Value,
) -> PktResult<Value> {
    let module = match module {
        Some(m) => m,
        None => &builtin_only_module(),
    };
    let entry = entry_index(module)?;
    let mut ctx = EvalCtx {
        graph: &module.graph,
        stack: Vec::new(),
        params,
        globals,
        reply: Some(reply),
        env_stack: vec![FnEnv::new()],
        value_depth: 0,
    };
    ctx.eval_value(entry, v)
}

/// 仅内置原语可用的空模块（无用户函数/元件/导出；供无模块上下文的表达式求值）。
fn builtin_only_module() -> Module {
    let path = PathBuf::from("<sniffer>");
    let mut graph = ModuleGraph::default();
    graph.by_path.insert(path.clone(), 0);
    graph.modules.push(Arc::new(ModuleData {
        name: "<sniffer>".into(),
        path: path.clone(),
        ast: Arc::new(crate::ast::AstFile { stmts: Vec::new() }),
        is_lib: false,
    }));
    graph.module_imports.push(Vec::new());
    graph.scopes.push(HashMap::new());
    Module {
        name: "<sniffer>".into(),
        path: Some(path),
        exports: Vec::new(),
        default: None,
        defs: Vec::new(),
        funcs: Vec::new(),
        protos: Vec::new(),
        sniffer: None,
        imports: Vec::new(),
        graph: Arc::new(graph),
        entry: 0,
    }
}

fn entry_index(module: &Module) -> PktResult<usize> {
    let path = module
        .path
        .as_ref()
        .ok_or_else(|| Diagnostic::new("模块缺少路径，无法定位"))?;
    module
        .graph
        .by_path
        .get(path)
        .copied()
        .ok_or_else(|| Diagnostic::new("模块不在已解析的图中"))
}

/// 用户值函数最大调用深度（防自递归/互递归栈溢出；正常 .pkt 函数嵌套远低于此）。
const MAX_VALUE_FUNC_DEPTH: usize = 64;

struct EvalCtx<'a> {
    graph: &'a ModuleGraph,
    /// 组件求值栈（循环检测）：(定义模块下标, 名字)。
    stack: Vec<(usize, String)>,
    /// 运行时参数表（`params("name")` 值引用）。
    params: &'a Params,
    /// 配方全局存储（`global("name")` 值原语；`.pktl` 配方注入）。
    globals: &'a Globals,
    /// 回包字段访问器（`reply("层","字段")` 值原语；配方 extract 的 from 表达式
    /// 求值时由宿主注入——回包反解报告 + 字段提取都在宿主侧）。
    reply: Option<ReplyAccess<'a>>,
    /// 函数参数环境栈（内层函数在最上）。
    env_stack: Vec<FnEnv>,
    /// 用户值函数当前调用深度（`eval_user_value_func` 入口 +1、出口 -1）。
    value_depth: usize,
}

impl EvalCtx<'_> {
    fn current_env(&self) -> &FnEnv {
        self.env_stack
            .last()
            .expect("env 栈至少有一层（构造时压入空环境）")
    }

    /// 求值一个元件（本模块作用域中的名字，`args` 为调用参数）→ 包组。
    fn eval_component(
        &mut self,
        module: usize,
        name: &str,
        args: &[Arg],
    ) -> PktResult<Vec<PacketSpec>> {
        let (def_module, kind) = self
            .graph
            .lookup(module, name)
            .ok_or_else(|| Diagnostic::new(format!("内部错误：元件 `{name}` 未解析")))?;
        let key = (def_module, name.to_string());
        if self.stack.contains(&key) {
            let mut chain: Vec<String> = self
                .stack
                .iter()
                .map(|(m, n)| format!("{}::{}", self.graph.modules[*m].name, n))
                .collect();
            chain.push(format!("{}::{}", self.graph.modules[def_module].name, name));
            return Err(Diagnostic::new(format!(
                "检测到循环元件引用：{}",
                chain.join(" → ")
            )));
        }
        self.stack.push(key);
        let result = match kind {
            LookupKind::Def(def_idx) => {
                if !args.is_empty() {
                    return Err(Diagnostic::at(
                        format!("元件 `{name}` 不接受参数（非函数）"),
                        args[0].span,
                    ));
                }
                self.graph
                    .def_expr(def_module, def_idx)
                    .ok_or_else(|| Diagnostic::new(format!("内部错误：元件 `{name}` 无定义体")))
                    .and_then(|expr| self.eval_expr(def_module, expr))
            }
            LookupKind::Func(func_idx) => {
                // proto 函数 = 带 schema 的 FuncStmt：层位置调用走 proto 构造
                // （字段即参数，产出 IR 层/Raw 层）；普通函数走流水线求值。
                if self
                    .graph
                    .func_def(def_module, func_idx)
                    .is_some_and(|f| f.schema.is_some())
                {
                    self.eval_proto(def_module, func_idx, args)
                } else {
                    self.eval_func(def_module, func_idx, args)
                }
            }
            LookupKind::Default => {
                if !args.is_empty() {
                    return Err(Diagnostic::at(
                        format!("默认导出 `{name}` 不接受参数（非函数）"),
                        args[0].span,
                    ));
                }
                self.graph
                    .default_pipeline(def_module)
                    .ok_or_else(|| {
                        Diagnostic::new(format!("内部错误：模块 `{}` 无默认导出", def_module))
                    })
                    .and_then(|p| self.eval_pipeline(def_module, p))
            }
        };
        self.stack.pop();
        result
    }

    /// 函数调用：校验参数 → 绑定环境（未传 → 默认值或未设）→ 求值函数体。
    fn eval_func(
        &mut self,
        module: usize,
        func_idx: usize,
        args: &[Arg],
    ) -> PktResult<Vec<PacketSpec>> {
        let func = self
            .graph
            .func_def(module, func_idx)
            .cloned()
            .ok_or_else(|| Diagnostic::new("内部错误：函数定义丢失"))?;
        // 命名参数后不允许位置参数（与层函数一致）
        if let Some(first_named) = args.iter().position(|a| a.name.is_some())
            && let Some(first_pos) = args.iter().position(|a| a.name.is_none())
            && first_pos > first_named
        {
            return Err(Diagnostic::at(
                format!("函数 `{}`：命名参数后不能使用位置参数", func.name),
                args[first_pos].span,
            ));
        }
        // 未知参数 / 重复参数
        let mut seen: Vec<&str> = Vec::new();
        let mut positional: Vec<&Arg> = Vec::new();
        for a in args {
            match &a.name {
                Some((n, _)) => {
                    if !func.params.iter().any(|p| &p.name == n) {
                        return Err(Diagnostic::at(
                            format!("函数 `{}` 没有参数 `{n}`", func.name),
                            a.span,
                        ));
                    }
                    if seen.contains(&n.as_str()) {
                        return Err(Diagnostic::at(
                            format!("函数 `{}`：参数 `{n}` 重复指定", func.name),
                            a.span,
                        ));
                    }
                    seen.push(n);
                }
                None => positional.push(a),
            }
        }
        // 位置参数按声明顺序填充；命名参数任意顺序。
        // 实参值先按「调用处环境」解析（Ident 链 → 具体值/未设），避免跨层滞留的
        // 参数引用在子函数里形成循环；默认值保持原样（在子函数环境里惰性解析）。
        let caller_env = self.current_env().clone();
        let mut env: FnEnv = FnEnv::new();
        for p in &func.params {
            // 默认值是值表达式（concat/bytes(...) 等）→ 立即求值
            let v = match &p.default {
                Some(d) if matches!(d, Value::Call { .. } | Value::BinOp { .. }) => {
                    Some(self.eval_value(module, d)?)
                }
                other => other.clone(),
            };
            env.insert(p.name.clone(), v);
        }
        for (i, a) in positional.iter().enumerate() {
            let Some(p) = func.params.get(i) else {
                return Err(Diagnostic::at(
                    format!("函数 `{}`：位置参数过多", func.name),
                    a.span,
                ));
            };
            let resolved = crate::registry::deref_opt(&a.value, &caller_env, &p.name)?.cloned();
            // 未设（None）→ 保留默认值（回退默认），不覆盖
            if resolved.is_some() {
                env.insert(p.name.clone(), resolved);
            }
        }
        for a in args {
            if let Some((n, _)) = &a.name {
                let resolved = crate::registry::deref_opt(&a.value, &caller_env, n)?.cloned();
                if resolved.is_some() {
                    env.insert(n.clone(), resolved);
                }
            }
        }
        self.env_stack.push(env);
        let result = self.eval_pipeline(module, &func.body);
        self.env_stack.pop();
        result
    }

    /// proto 构造解释器（M1 构造侧）：按字段声明顺序把参数/默认值编码为字节，包成 IR 层。
    ///
    /// - 字段即参数：位置参数按字段序、命名参数按名绑定（命名覆盖位置）；未传 →
    ///   `= 默认值`（在字段环境求值，可引用前序字段）；既未传也无默认 → 报错
    ///   （`len` 计算字段除外，值由引擎计算）。
    /// - `bytes` 字段（`#[meta(bytes=...)]`）：宽度表达式引用前序字段值；实参字节长度
    ///   须与宽度一致（构造校验）。
    /// - `len`：值 = 基准字节数（`len="auto"` = 后续全部字段 / `len="目标"` = 目标字段），
    ///   用字段自身类型编码（如 `#[meta(len="auto", codec="prefix", ...)]`）。
    /// - `src`/`dst` 字段（ip4/ip6 类型）：兼作 ipv4/ipv6 层的伪头部地址元数据。
    /// - `func_idx` 是带 schema 的 FuncStmt 下标（proto = 值函数 + 字段标注）。
    fn eval_proto(
        &mut self,
        module: usize,
        func_idx: usize,
        args: &[Arg],
    ) -> PktResult<Vec<PacketSpec>> {
        let f = self
            .graph
            .func_def(module, func_idx)
            .cloned()
            .ok_or_else(|| Diagnostic::new("内部错误：proto 定义丢失"))?;
        let schema = f
            .schema
            .as_ref()
            .ok_or_else(|| Diagnostic::new("内部错误：func 无 schema 却走 eval_proto"))?;
        let layer_kind = crate::semantic::proto_layer_kind(&f).map(str::to_string);
        // 命名参数后不允许位置参数（与函数一致）
        if let Some(first_named) = args.iter().position(|a| a.name.is_some())
            && let Some(first_pos) = args.iter().position(|a| a.name.is_none())
            && first_pos > first_named
        {
            return Err(Diagnostic::at(
                format!("proto `{}`：命名参数后不能使用位置参数", f.name),
                args[first_pos].span,
            ));
        }
        // 可绑定名字 = 字段 ∪ 值参数（重名冲突在语义阶段已报）
        let bindable = |n: &str| -> bool {
            schema.fields.iter().any(|f| f.name == n) || f.params.iter().any(|p| p.name == n)
        };
        // 未知参数 / 重复参数
        let mut seen: Vec<&str> = Vec::new();
        for a in args {
            if let Some((n, _)) = &a.name {
                if !bindable(n) {
                    return Err(Diagnostic::at(
                        format!("proto `{}` 没有参数（字段）`{n}`", f.name),
                        a.span,
                    ));
                }
                if seen.contains(&n.as_str()) {
                    return Err(Diagnostic::at(
                        format!("proto `{}`：字段 `{n}` 重复指定", f.name),
                        a.span,
                    ));
                }
                seen.push(n);
            }
        }
        let caller_env = self.current_env().clone();
        // 字段/参数环境：先绑定值参数（字段默认值/宽度可引用），再逐字段绑定
        self.env_stack.push(FnEnv::new());
        let result = (|| -> PktResult<Vec<PacketSpec>> {
            // 值参数默认值进环境（Call/BinOp 立即求值，与 eval_func 一致）
            for p in &f.params {
                let v = match &p.default {
                    Some(d) if matches!(d, Value::Call { .. } | Value::BinOp { .. }) => {
                        Some(self.eval_value(module, d)?)
                    }
                    other => other.clone(),
                };
                self.env_stack
                    .last_mut()
                    .expect("proto 环境已压栈")
                    .insert(p.name.clone(), v);
            }
            // 实参（调用处环境解析）：命名按名覆盖（参数/字段），位置按声明序填充
            // 「无默认值」的数据字段（跳过 len 计算与有默认的常量/自动字段）——
            // quic_crypto(0, "CHLO") → offset, data；eth/udp 等全默认字段请用命名参数
            let positional: Vec<&Arg> = args.iter().filter(|a| a.name.is_none()).collect();
            let mut pos_iter = positional.iter();
            let mut arg_map: std::collections::HashMap<&str, Value> =
                std::collections::HashMap::new();
            for f in &schema.fields {
                if f.len_of.is_some() || f.default.is_some() {
                    continue;
                }
                if let Some(a) = pos_iter.next()
                    && let Some(v) =
                        crate::registry::deref_opt(&a.value, &caller_env, &f.name)?.cloned()
                {
                    arg_map.insert(f.name.as_str(), v);
                }
            }
            for p in &f.params {
                if let Some(a) = pos_iter.next()
                    && let Some(v) =
                        crate::registry::deref_opt(&a.value, &caller_env, &p.name)?.cloned()
                {
                    arg_map.insert(p.name.as_str(), v);
                }
            }
            if pos_iter.next().is_some() {
                return Err(Diagnostic::at(
                    format!("proto `{}`：位置参数过多", f.name),
                    args.last().expect("有位置参数").span,
                ));
            }
            for a in args {
                if let Some((n, _)) = &a.name
                    && let Some(v) = crate::registry::deref_opt(&a.value, &caller_env, n)?.cloned()
                {
                    arg_map.insert(n.as_str(), self.eval_value(module, &v)?);
                }
            }
            // 参数的实参覆盖默认（字段默认值/宽度引用参数时取实参值）
            for p in &f.params {
                if let Some(v) = arg_map.get(p.name.as_str()) {
                    self.env_stack
                        .last_mut()
                        .expect("proto 环境已压栈")
                        .insert(p.name.clone(), Some(v.clone()));
                }
            }

            // 第一遍：编码普通字段的数据（len 计算字段占位 0 编码）
            let mut enc: Vec<Vec<u8>> = Vec::with_capacity(schema.fields.len());
            let bits: Vec<Option<u8>> = schema.fields.iter().map(|f| f.bits).collect();
            let mut len_idx: Vec<(usize, LenTarget)> = Vec::new();
            let mut field_vals: std::collections::HashMap<String, Value> =
                std::collections::HashMap::new();
            for (i, f) in schema.fields.iter().enumerate() {
                if let Some(target) = &f.len_of {
                    if let Some(a) = args.iter().find(|a| match &a.name {
                        Some((n, _)) => n == &f.name,
                        None => false,
                    }) {
                        return Err(Diagnostic::at(
                            format!(
                                "proto `{}`：字段 `{}` 是 len 计算字段（`len=\"auto\"`/`len=\"目标\"`，引擎计算），不接受参数",
                                f.name, f.name
                            ),
                            a.span,
                        ));
                    }
                    // 占位 0 编码（Field 目标随后续目标回填；Auto 反向填）
                    enc.push(self.encode_field_type(f, Value::Int(0))?);
                    len_idx.push((i, target.clone()));
                    continue;
                }
                // if 条件在场守卫：整型表达式非零 = 字段存在；条件为假 → 不编码
                //（enc 压空占位保持与 schema 下标对齐；实参可省略，已给则忽略）
                if let Some(cond) = &f.if_cond {
                    let cv = self.eval_value(module, cond)?;
                    let ci = int_of(Some(&cv), "if 条件", f.span)?;
                    if ci == 0 {
                        enc.push(Vec::new());
                        continue;
                    }
                }
                // 值 = 实参 > 默认值（字段环境求值，可引用前序字段与值参数）
                let v: Value = match arg_map.get(f.name.as_str()) {
                    Some(v) => v.clone(),
                    None => match &f.default {
                        Some(d) => self.eval_value(module, d)?,
                        None => {
                            return Err(Diagnostic::at(
                                format!("proto `{}`：字段 `{}` 未提供且无默认值", f.name, f.name),
                                f.span,
                            ));
                        }
                    },
                };
                // 重复区（rest 子 proto）：值 = 列表 → 逐项调用子 proto 编码拼接
                // （list="计数" 与 rest="子proto" 构造同形；**字节列表直喂**——如
                // quic_initial 的 payload = concat(quic_crypto(), pad(...)) 求值为
                // 全 Int/Hex 的字节列表，须按原样直喂，不能逐项当参数调子 proto；
                // 含 Str/List 元素才是元素列表（HTTP headers / DNS questions））
                // 类型档分类（不管 0..255 范围；范围由下方 coercer 报）——
                // 规则唯一化到 shape 表（is_flat_numeric）
                let is_bytes_list =
                    matches!(&v, Value::List(items) if crate::shape::is_flat_numeric(items));
                if f.list_count.is_some()
                    || (f.rest_proto.is_some() && matches!(v, Value::List(_)) && !is_bytes_list)
                {
                    let items = match &v {
                        Value::List(items) => items.clone(),
                        other => {
                            return Err(Diagnostic::at(
                                format!(
                                    "proto `{}`：重复区字段 `{}` 的值必须是列表（如 `[\"a.com\", \"b.com\"]`；`rest=\"子proto\"` 也可直喂字节），得到 {}",
                                    f.name,
                                    f.name,
                                    crate::registry::describe(other)
                                ),
                                f.span,
                            ));
                        }
                    };
                    let mut b = Vec::new();
                    for item in items {
                        b.extend(self.eval_repeat_item(module, f, &item)?);
                    }
                    enc.push(b);
                    self.env_stack
                        .last_mut()
                        .expect("proto 环境已压栈")
                        .insert(f.name.clone(), Some(v.clone()));
                    field_vals.insert(f.name.clone(), v);
                    continue;
                }
                // bytes 宽度校验（尽力而为：宽度表达式引用未算的 @len/@auto 字段时跳过）
                let mut validated = false;
                if f.ty == FieldType::Bytes
                    && let Some(width) = &f.width
                {
                    let w = self
                        .eval_value(module, width)
                        .ok()
                        .and_then(|v| int_of(Some(&v), "bytes 宽度", f.span).ok());
                    if let Some(w) = w {
                        if w < 0 {
                            return Err(Diagnostic::at(
                                format!("proto `{}`：`bytes` 宽度不能为负（{w}）", f.name),
                                f.span,
                            ));
                        }
                        let b = bytes_of(&v, f.span)?;
                        if b.len() as i64 != w {
                            return Err(Diagnostic::at(
                                format!(
                                    "proto `{}`：字段 `{}` 的字节长度 {} ≠ 声明的 `bytes({w})` 宽度",
                                    f.name,
                                    f.name,
                                    b.len()
                                ),
                                f.span,
                            ));
                        }
                        validated = true;
                    }
                }
                // bits（位字段）：值必须在 0..=2^bits-1（编码取低 N 位；
                // bits=64 时上限即 i64 本身）
                if let Some(b) = f.bits {
                    let n = int_of(Some(&v), "位字段", f.span)?;
                    let max = if b >= 64 { i64::MAX } else { (1i64 << b) - 1 };
                    if !(0..=max).contains(&n) {
                        return Err(Diagnostic::at(
                            format!(
                                "proto `{}`：位字段 `{}` 的值 {n} 超出 {b} 位（0..={max}）",
                                f.name, f.name
                            ),
                            f.span,
                        ));
                    }
                }
                let b = if f.ty == FieldType::Bytes && !validated {
                    bytes_of(&v, f.span)?
                } else {
                    self.encode_field_type(f, v.clone())?
                };
                enc.push(b);
                // 记录字段值（供后续默认/宽度引用、typed_layer 语义回填）
                self.env_stack
                    .last_mut()
                    .expect("proto 环境已压栈")
                    .insert(f.name.clone(), Some(v.clone()));
                field_vals.insert(f.name.clone(), v);
            }
            // len 回填：值 = 基准字节数（Field 目标 = 目标字段编码字节数；Auto =
            // 后续全部字段字节数）；`expr` 变换存在时先求基准值再变换（expr 里
            // `len` = 基准字节数）。字节数用**打包后**长度（bits 位组压缩，
            // 如 version+ihl = 1 字节）。Field 目标先填（其值为普通字段，第一遍
            // 已编码），Auto 后填（须看后续全部字段的最终编码）。
            for (i, target) in &len_idx {
                let LenTarget::Field(name) = target else {
                    continue; // Auto 在下方统一反向填（须看后续全部字段最终编码）
                };
                let sizes = packed_sizes(&enc, &bits);
                let tlen = sizes
                    .iter()
                    .enumerate()
                    .find(|(j, _)| *j > *i && schema.fields[*j].name == *name)
                    .map(|(_, s)| *s)
                    .ok_or_else(|| {
                        Diagnostic::at(
                            format!("proto `{}`：`len=\"{name}\"` 目标未找到", f.name),
                            schema.fields[*i].span,
                        )
                    })?;
                let f = &schema.fields[*i];
                let v = self.eval_len_value(module, f, tlen as i64)?;
                enc[*i] = self.encode_field_type(f, v)?;
            }
            // len="auto" 反向填：值 = 后续字段最终编码总长（后填先算）；expr 变换同 Field
            for (i, _) in len_idx
                .iter()
                .filter(|(_, t)| matches!(t, LenTarget::Auto))
                .rev()
            {
                let f = &schema.fields[*i];
                let sizes = packed_sizes(&enc, &bits);
                let after: usize = sizes[*i + 1..].iter().sum();
                let v = self.eval_len_value(module, f, after as i64)?;
                enc[*i] = self.encode_field_type(f, v)?;
            }
            // bits 位组打包成最终字节流（普通字段字节对齐，语义阶段已保证）
            let bytes: Vec<u8> = pack_fields(&enc, &bits);
            // 无 #[layer] 的裸协议（如 QUIC）→ Raw 载荷层；有 layer → IR 层（raw 分支）
            // 有 #[layer] → typed_layer 按字段名回填语义字段（raw 分支保留头字节）；
            // 无 #[layer] 裸协议 → Raw 载荷层
            let layer = match &layer_kind {
                Some(kind) => self.typed_layer(kind, bytes, &field_vals, f.name_span)?,
                // 裸协议（无 kind）→ Raw 载荷层，记下 proto 名供层序检查
                // （查注册表 `#[rule]` 载体集，如 quic_initial 只能包在 udp 里）
                None => Layer::Raw(RawData {
                    bytes,
                    proto: Some(f.name.clone()),
                }),
            };
            Ok(vec![PacketSpec {
                layers: vec![layer],
            }])
        })();
        self.env_stack.pop();
        result
    }

    /// `len` 字段的值：基准值（后续字节数 / 目标字段字节数）→ `expr` 变换
    /// （expr 里 `len` = 基准值；缺省 = 原值）。
    fn eval_len_value(
        &mut self,
        module: usize,
        f: &crate::ast::FieldDecl,
        base: i64,
    ) -> PktResult<Value> {
        let Some(expr) = &f.len_expr else {
            return Ok(Value::Int(base));
        };
        // 在字段环境求值（expr 可引用前序字段与值参数），`len` 特殊变量 = 基准值
        self.env_stack
            .last_mut()
            .expect("proto 环境已压栈")
            .insert("len".to_string(), Some(Value::Int(base)));
        self.eval_value(module, expr)
    }

    /// 重复区字段的元素编码：列表项 → 子 proto 调用（项为列表 = 位置参数序列；
    /// 单值 = 第一个位置参数），取构建字节。
    fn eval_repeat_item(
        &mut self,
        module: usize,
        f: &crate::ast::FieldDecl,
        item: &Value,
    ) -> PktResult<Vec<u8>> {
        let item_proto = f.rest_proto.as_deref().expect("重复区字段必有子 proto");
        let (def_module, idx) = self.graph.lookup(module, item_proto).ok_or_else(|| {
            Diagnostic::at(
                format!(
                    "proto 字段 `{}`：重复区子 proto `{item_proto}` 未找到",
                    f.name
                ),
                f.span,
            )
        })?;
        let LookupKind::Func(idx) = idx else {
            return Err(Diagnostic::at(
                format!(
                    "proto 字段 `{}`：重复区子 proto `{item_proto}` 不是 proto",
                    f.name
                ),
                f.span,
            ));
        };
        // 元素须是带 schema 的 proto 函数（proto = 值函数 + 字段标注）
        if self
            .graph
            .func_def(def_module, idx)
            .is_none_or(|f| f.schema.is_none())
        {
            return Err(Diagnostic::at(
                format!(
                    "proto 字段 `{}`：重复区子 proto `{item_proto}` 不是 proto（需要 `#[proto] func ... -> bytes`）",
                    f.name
                ),
                f.span,
            ));
        }
        // 项 = 列表 → 位置参数序列；单值 → 单个位置参数
        let vals: Vec<Value> = match item {
            Value::List(items) => items.clone(),
            other => vec![other.clone()],
        };
        let args: Vec<Arg> = vals
            .iter()
            .map(|v| Arg {
                name: None,
                value: v.clone(),
                span: f.span,
            })
            .collect();
        let pkts = self.eval_proto(def_module, idx, &args)?;
        pkts.first()
            .and_then(|p| p.layers.first())
            .and_then(layer_raw_bytes)
            .ok_or_else(|| {
                Diagnostic::at(
                    format!(
                        "proto 字段 `{}`：list 元素 `{item_proto}` 构建无字节",
                        f.name
                    ),
                    f.span,
                )
            })
    }

    /// 把 `#[layer]` proto 的字段值回填为 IR 语义字段（按字段名约定）——
    /// 让既有消费者（payload 发送的 sport/dport、ICMP --wait 的 id/seq、
    /// `patch_zero_src`/`derive_target` 的 src/dst 等）在 headers.pkt 迁移后继续工作。
    /// 头字节仍走 `raw` 分支（serializer 自动补 checksum/length）。
    fn typed_layer(
        &self,
        kind: &str,
        bytes: Vec<u8>,
        vals: &std::collections::HashMap<String, Value>,
        span: crate::ast::Span,
    ) -> PktResult<Layer> {
        use crate::ir::*;
        use std::net::{Ipv4Addr, Ipv6Addr};
        let num = |name: &str| -> Option<i64> {
            vals.get(name)
                .and_then(|v| int_of(Some(v), name, span).ok())
        };
        let macv = |name: &str| -> Option<MacAddr> {
            vals.get(name)
                .and_then(|v| mac_bytes(v, name, span).ok())
                .map(|b| MacAddr([b[0], b[1], b[2], b[3], b[4], b[5]]))
        };
        let ip4v =
            |name: &str| -> Option<Ipv4Addr> { vals.get(name).and_then(|v| ip4_of(v, span).ok()) };
        let ip6v =
            |name: &str| -> Option<Ipv6Addr> { vals.get(name).and_then(|v| ip6_of(v, span).ok()) };
        // 域名来源（展示用，与 `layer` 原语的 ip4_or_dns 标注一致）：字符串且非
        // IP 字面量/random → 视为域名（编码时已解析成功才会走到这里）。
        let hostv = |name: &str| -> Option<String> {
            match vals.get(name) {
                Some(Value::Str(s))
                    if !s.eq_ignore_ascii_case("random")
                        && s.parse::<std::net::IpAddr>().is_err() =>
                {
                    Some(s.clone())
                }
                _ => None,
            }
        };
        Ok(match kind {
            "eth" => Layer::Ethernet(EthernetFields {
                src_mac: macv("src_mac").map(Field::Value).unwrap_or(Field::Auto),
                dst_mac: macv("dst_mac").map(Field::Value).unwrap_or(Field::Auto),
                ethertype: num("ethertype").map(|n| n as u16),
                raw: Some(bytes),
            }),
            "arp" => Layer::Arp(ArpFields {
                op: num("op").map(|n| match n {
                    1 => ArpOp::Request,
                    2 => ArpOp::Reply,
                    // RARP(3) 等未知 opcode：保留原始值
                    other => ArpOp::Other(u16::try_from(other).unwrap_or(0)),
                }),
                sha: macv("sha"),
                spa: ip4v("spa"),
                tha: macv("tha"),
                tpa: ip4v("tpa"),
                raw: Some(bytes),
            }),
            "ipv4" => {
                let flags = num("flags").map(|n| Ipv4Flags {
                    df: n & 0x4000 != 0,
                    mf: n & 0x2000 != 0,
                    frag_offset: (n & 0x1fff) as u16,
                });
                Layer::Ipv4(Ipv4Fields {
                    src: ip4v("src").map(Field::Value).unwrap_or(Field::Auto),
                    dst: ip4v("dst").map(Field::Value).unwrap_or(Field::Auto),
                    src_host: hostv("src"),
                    dst_host: hostv("dst"),
                    ttl: num("ttl")
                        .map(|n| Field::Value(n as u8))
                        .unwrap_or(Field::Auto),
                    proto: num("proto").map(|n| n as u8),
                    tos: num("tos").map(|n| n as u8),
                    id: num("id").map(|n| n as u16),
                    flags,
                    raw: Some(bytes),
                    ..Default::default()
                })
            }
            "ipv6" => Layer::Ipv6(Ipv6Fields {
                src: ip6v("src").map(Field::Value).unwrap_or(Field::Auto),
                dst: ip6v("dst").map(Field::Value).unwrap_or(Field::Auto),
                src_host: hostv("src"),
                dst_host: hostv("dst"),
                hop_limit: num("hop_limit")
                    .map(|n| Field::Value(n as u8))
                    .unwrap_or(Field::Auto),
                next_header: num("next_header").map(|n| n as u8),
                raw: Some(bytes),
            }),
            "icmp" => Layer::Icmp(IcmpFields {
                icmp_type: num("type").map(|n| n as u8),
                code: num("code").map(|n| n as u8),
                id: num("id").map(|n| n as u16),
                seq: num("seq").map(|n| n as u16),
                // payload 已在头字节内（rest 字段），不重复设置（raw 分支 hdr + 内层）
                payload: None,
                raw: Some(bytes),
            }),
            "udp" => Layer::Udp(UdpFields {
                src_port: num("sport").map(|n| n as u16),
                dst_port: num("dport").map(|n| n as u16),
                raw: Some(bytes),
                ..Default::default()
            }),
            "dns" => {
                // 构造侧回填（展示用；raw 保留整段字节，roundtrip 依赖）：questions
                // = 名字列表；answers = 位置参数序列列表（[name, rtype, class, ttl,
                // rdata]）。qtype/qclass 缺省按 1（构造时子 proto 参数未暴露）。
                use crate::ir::{DnsAnswer, DnsQuestion};
                let mut questions = Vec::new();
                if let Some(Value::List(items)) = vals.get("questions") {
                    for it in items {
                        questions.push(DnsQuestion {
                            name: match it {
                                Value::Str(s) => s.clone(),
                                other => {
                                    str_of(Some(other), "dns questions", span).unwrap_or_default()
                                }
                            },
                            qtype: Some(1),
                            qclass: Some(1),
                        });
                    }
                }
                let mut answers = Vec::new();
                if let Some(Value::List(items)) = vals.get("answers") {
                    for it in items {
                        if let Value::List(seq) = it {
                            let intv = |i: usize| -> Option<i64> {
                                seq.get(i)
                                    .and_then(|v| int_of(Some(v), "dns answer", span).ok())
                            };
                            answers.push(DnsAnswer {
                                name: match seq.first() {
                                    Some(Value::Str(s)) => s.clone(),
                                    _ => String::new(),
                                },
                                rtype: intv(1).map(|n| n as u16),
                                class: intv(2).map(|n| n as u16),
                                ttl: intv(3).map(|n| n as u32),
                                rdata: seq
                                    .get(4)
                                    .and_then(|v| bytes_of(v, span).ok())
                                    .unwrap_or_default(),
                            });
                        }
                    }
                }
                Layer::Dns(DnsFields {
                    id: num("id").map(|n| n as u16),
                    flags: num("flags").map(|n| n as u16),
                    opcode: None,
                    questions,
                    answers,
                    raw: Some(bytes),
                })
            }
            "http" => {
                // 构造侧回填（展示用；raw 保留整段字节）：start_line 拆 method/path/
                // version；headers = 字符串列表拆 key:value；body 原样。
                use crate::ir::HttpFields;
                let start_line = match vals.get("start_line") {
                    Some(Value::Str(s)) => s.clone(),
                    other => str_of(other, "http start_line", span).unwrap_or_default(),
                };
                let (method, path, version) = if let Some(rest) = start_line.strip_prefix("HTTP/") {
                    (None, None, Some(format!("HTTP/{rest}")))
                } else {
                    let mut parts = start_line.splitn(3, ' ');
                    (
                        parts.next().filter(|s| !s.is_empty()).map(str::to_string),
                        parts.next().map(str::to_string),
                        parts.next().map(str::to_string),
                    )
                };
                let mut headers = Vec::new();
                if let Some(Value::List(items)) = vals.get("headers") {
                    for it in items {
                        let line = match it {
                            Value::Str(s) => s.clone(),
                            other => str_of(Some(other), "http headers", span).unwrap_or_default(),
                        };
                        if let Some((k, v)) = line.split_once(':') {
                            headers.push((k.trim().to_string(), v.trim().to_string()));
                        }
                    }
                }
                let body = vals
                    .get("body")
                    .and_then(|v| bytes_of(v, span).ok())
                    .filter(|b| !b.is_empty());
                Layer::Http(HttpFields {
                    method,
                    path,
                    version,
                    headers,
                    body,
                    raw: Some(bytes),
                })
            }
            // tcp 未迁移（选项/复杂布局），proto 声明时仅 raw 字节
            other => crate::registry::raw_layer(other, bytes, None)?,
        })
    }

    /// 按字段类型把值编码为字节（可逆原语：构造侧编码；解析侧解码见 DESIGN 草案）。
    /// `f` 提供类型与 vint 方案（codec 在字段上，`FieldType::Vint` 必须携带）。
    fn encode_field_type(&mut self, f: &crate::ast::FieldDecl, v: Value) -> PktResult<Vec<u8>> {
        let ty = f.ty;
        let name = f.name.as_str();
        let span = f.span;
        match ty {
            FieldType::U8 => encode_int_bytes(
                Some(&v),
                1,
                false,
                1 << 8,
                &format!("字段 `{name}` 的 u8"),
                span,
            ),
            FieldType::Be16
            | FieldType::Be32
            | FieldType::Be64
            | FieldType::Le16
            | FieldType::Le32
            | FieldType::Le64 => {
                let (width, little) = match ty {
                    FieldType::Be16 | FieldType::Le16 => (2usize, matches!(ty, FieldType::Le16)),
                    FieldType::Be32 | FieldType::Le32 => (4usize, matches!(ty, FieldType::Le32)),
                    FieldType::Be64 => (8usize, false),
                    FieldType::Le64 => (8usize, true),
                    _ => unreachable!("已在分支排除"),
                };
                // 8 字节按 i64::MAX 封顶（无符号 2^64 超出 i64 表示）
                let max = if width == 8 {
                    1u64 << 63
                } else {
                    1u64 << (width * 8)
                };
                let label = if width == 8 {
                    if little { "le64" } else { "be64" }
                } else if width == 4 {
                    if little { "le32" } else { "be32" }
                } else if little {
                    "le16"
                } else {
                    "be16"
                };
                encode_int_bytes(
                    Some(&v),
                    width,
                    little,
                    max,
                    &format!("字段 `{name}` 的 {label}"),
                    span,
                )
            }
            FieldType::Vint => {
                // 变长整数：方案数据化（codec 在字段上）——le128（续延位）/
                // prefix（前缀宽度表）/ table（内联 + 哨兵表）；编解码实现收敛在
                // codec.rs（`VintCodec::encode`/`decode`），构造/解析共用同一份
                // 代码（eng_lib/vint.pkt 库 proto varint/qvarint 走同路径）。
                let codec = f.vint.as_ref().ok_or_else(|| {
                    Diagnostic::at(format!("字段 `{name}`：vint 缺少 codec 方案"), span)
                })?;
                let n = int_of(Some(&v), name, span)?;
                let what = format!("字段 `{name}` 的 vint");
                codec
                    .encode(n)
                    .map_err(|e| Diagnostic::at(format!("{what} {}", e.message()), span))
            }
            FieldType::Mac => mac_bytes(&v, name, span),
            FieldType::Ip4 => ip4_bytes(&v, name, span),
            FieldType::Ip6 => ip6_bytes(&v, name, span),
            FieldType::Bytes | FieldType::Rest => bytes_of(&v, span),
            FieldType::DnsName => {
                // DNS 名字编码（标签 + 0 终止）；复用 tpl `%L`（与 eng_lib dns_name 值函数一致）
                let args = vec![Value::Str("%L".to_string()), v.clone()];
                let out = crate::tpl::eval_tpl(&args, span)?;
                bytes_of(&out, span)
            }
            FieldType::Line => {
                // 文本行：值（字符串/字节）→ 字节 + `\r\n`（解析侧空行失败对称：
                // 解析读到 `\r\n` 开头即失败，构造侧 line("") 产空行供手动编码）
                let mut b = bytes_of(&v, span)?;
                b.extend_from_slice(b"\r\n");
                Ok(b)
            }
        }
    }

    fn eval_expr(&mut self, module: usize, expr: &Expr) -> PktResult<Vec<PacketSpec>> {
        match expr {
            Expr::Call(c) => self.eval_call(module, c),
            Expr::Pipeline(p) => self.eval_pipeline(module, p),
        }
    }

    /// 层函数调用：用户定义/库导出优先，否则内置原语。
    fn eval_call(&mut self, module: usize, call: &Call) -> PktResult<Vec<PacketSpec>> {
        // 层调用参数里的值表达式（concat/be16/... 原语与值函数）先求值，得到字面量/
        // 字节列表后再交给函数绑定或 registry 构造层；顶层 Ident（函数参数引用，含
        // 未设省略）与 params() 保留原样。用户函数与内置调用统一在此预求值，
        // module 是调用处模块（函数体内引用的回调/元件按调用处解析）。
        let mut c = call.clone();
        for a in &mut c.args {
            if matches!(a.value, Value::Call { .. } | Value::BinOp { .. }) {
                a.value = self.eval_value(module, &a.value)?;
            }
        }
        if self.graph.lookup(module, &c.name).is_some() {
            return self.eval_component(module, &c.name, &c.args);
        }
        if is_builtin(&c.name) {
            let layers = build_layers(&c, self.params, self.current_env())?;
            return Ok(vec![PacketSpec { layers }]);
        }
        Err(Diagnostic::at(
            format!("未知层函数或元件：`{}`", c.name),
            c.name_span,
        ))
    }

    /// 值表达式求值（值函数体 / 值位置调用）：字面量 / 参数 / 加法 / 值调用。
    fn eval_value(&mut self, module: usize, v: &Value) -> PktResult<Value> {
        match v {
            Value::Str(_) | Value::Int(_) | Value::Hex(_) => Ok(v.clone()),
            Value::List(items) => {
                let items = items
                    .iter()
                    .map(|it| self.eval_value(module, it))
                    .collect::<PktResult<Vec<_>>>()?;
                Ok(Value::List(items))
            }
            Value::Ident { name, span } => {
                // 沿 env_stack 自顶向下查找（闭包捕获：lambda/higher-order 回调体内
                // 引用外层函数参数）；最近绑定优先（顶层遮蔽下层），绑定为未设 → 未提供
                let v = self
                    .env_stack
                    .iter()
                    .rev()
                    .find_map(|env| env.get(name))
                    .and_then(|x| x.clone())
                    .ok_or_else(|| Diagnostic::at(format!("参数 `{name}` 未提供"), *span))?;
                // 环境值可能是 Param/嵌套值表达式 → 递归解析
                self.eval_value(module, &v)
            }
            Value::Param { name, default, .. } => {
                // 宿主注入值：按形状解析（0x 前缀/纯数字 → 数值，否则字符串）；
                // 未注入：求值**默认值表达式**（可为 be16(...)/hex(...)/字面量/字节列表）；
                // 两者都无：报错。
                match self.params.get(name) {
                    Some(v) => Ok(crate::registry::parse_param_value(v)),
                    None => match default {
                        Some(d) => {
                            let v = self.eval_value(module, d)?;
                            // 字符串默认值保持形状解析（"0x4242" → 数值，与宿主值一致）；
                            // 非字符串默认（be16(...)/hex(...)/字面量/字节列表）直接返回
                            match v {
                                Value::Str(s) => Ok(crate::registry::parse_param_value(&s)),
                                other => Ok(other),
                            }
                        }
                        None => Err(Diagnostic::at(
                            format!(
                                "参数 `{name}` 未提供（可用 --params {name}=... 传入，或写 params(\"{name}\", \"默认值\")）"
                            ),
                            v_span(v),
                        )),
                    },
                }
            }
            Value::BinOp {
                op,
                left,
                right,
                span,
            } => {
                // 唯一运算符 `+`：整数相加（Int/Hex 同进数值上下文）
                let l = self.eval_value(module, left)?;
                let r = self.eval_value(module, right)?;
                match op {
                    BinOp::Add => {
                        let to_i = |v: &Value| match v {
                            Value::Int(i) => Some(*i),
                            Value::Hex(h) => Some(*h as i64),
                            _ => None,
                        };
                        let (Some(a), Some(b)) = (to_i(&l), to_i(&r)) else {
                            return Err(Diagnostic::at(
                                format!(
                                    "`+` 只支持整数相加，得到 {} 与 {}",
                                    crate::registry::describe(&l),
                                    crate::registry::describe(&r)
                                ),
                                *span,
                            ));
                        };
                        // checked 加法：debug/release 均不 panic/回绕，溢出报诊断
                        a.checked_add(b).map(Value::Int).ok_or_else(|| {
                            Diagnostic::at(format!("`+` 整数溢出：{a} + {b}"), *span)
                        })
                    }
                }
            }
            Value::Call {
                name,
                name_span,
                args,
                span,
            } => {
                // global("名"[, 默认])：配方全局存储读取——**延迟求值默认值**
                // （与 params 一致：全局已设置时不求值默认表达式，避免
                // `global("x", be16(params("p")))` 在 x 已设置时因 p 未注入而报错）。
                // 与 params 的差异：全局值是**类型化**字面量（Int/Hex/Str/字节列表），
                // 不经过字符串形状解析，可直接参与 +/be16/位运算。
                if name == "global" {
                    return self.eval_global(module, args, *span);
                }
                let arg_vals: Vec<Value> = args
                    .iter()
                    .map(|a| self.eval_value(module, a))
                    .collect::<PktResult<_>>()?;
                self.eval_value_call(module, name, &arg_vals, *span, *name_span)
            }
        }
    }

    /// `global("名"[, 默认值])`：读取配方全局存储（`.pktl` 的 `global:` 段 /
    /// 步骤 `extract` / 宿主 -G（--global）注入）。与 `params` 的差异：全局值是**类型化**
    /// 字面量（Int/Hex/Str/字节列表），原样返回，不经过字符串形状解析。
    /// 未设置：延迟求值默认值表达式（与 `params` 一致）；两者都无 → 报错。
    fn eval_global(
        &mut self,
        module: usize,
        args: &[Value],
        span: crate::ast::Span,
    ) -> PktResult<Value> {
        if args.len() > 2 {
            return Err(Diagnostic::at(
                format!(
                    "`global` 需要 1-2 个参数（全局名[, 默认值]），得到 {}",
                    args.len()
                ),
                span,
            ));
        }
        let Some(Value::Str(name)) = args.first() else {
            return Err(Diagnostic::at(
                "`global` 需要字符串参数（全局名），如 global(\"tid\")",
                span,
            ));
        };
        if let Some(v) = self.globals.get(name) {
            return Ok(v.clone());
        }
        match args.get(1) {
            Some(d) => self.eval_value(module, d),
            None => Err(Diagnostic::at(
                format!(
                    "全局 `{name}` 未设置（可用配方 global: 段 init / 步骤 extract / -g {name}=... 注入，或写 global(\"{name}\", \"默认值\")）"
                ),
                span,
            )),
        }
    }

    /// 值调用分派：引擎字节原语 / 用户值函数（-> bytes）。
    fn eval_value_call(
        &mut self,
        module: usize,
        name: &str,
        args: &[Value],
        span: crate::ast::Span,
        _name_span: crate::ast::Span,
    ) -> PktResult<Value> {
        match name {
            // `reply("层", "字段")`：读取当前回包的反解字段（配方 extract 的
            // `from:` 表达式专用，宿主注入访问器）。仅在注入回包访问器（extract
            // 求值上下文）时按内置处理；其余上下文回退用户函数——eng_lib/bytes.pkt
            // 的 ARP 位常量 `func reply() -> bytes` 等撞名场景保持原语义。
            // 数值字段 → Int，地址/字符串字段 → Str（display），
            // payload/body/raw 字节字段 → 字节列表（宿主侧决定）。
            "reply" => {
                if let Some(f) = self.reply {
                    if args.len() != 2 {
                        return Err(Diagnostic::at(
                            format!("`reply` 需要 2 个参数（层, 字段），得到 {}", args.len()),
                            span,
                        ));
                    }
                    let layer = str_of(args.first(), "reply", span)?;
                    let field = str_of(args.get(1), "reply", span)?;
                    f(&layer, &field).ok_or_else(|| {
                        Diagnostic::at(format!("回包没有 `{layer}.{field}` 字段"), span)
                    })
                } else if args.len() == 2 {
                    // 无回包访问器（普通解析/`engine` 分析）但按 2 参调用：
                    // 这是配方 extract 的专用原语，给出可操作的报错而不是
                    // 「参数过多」（eng_lib 的 0 参 `func reply()` 撞名仍走用户
                    // 函数分支）。
                    Err(Diagnostic {
                        kind: crate::diag::DiagnosticKind::ReplyOutsideRecipe,
                        ..Diagnostic::at(
                            "`reply(层, 字段)` 只能在配方 extract 的 `from:` 表达式中 \
                             使用（本上下文没有回包可读取；回应包请用 .pktl 配方编排）"
                                .to_string(),
                            span,
                        )
                    })
                } else {
                    self.eval_user_value_func(module, name, args, span)
                }
            }
            "concat" => {
                let mut out = Vec::new();
                for a in args {
                    out.extend(bytes_of(a, span)?);
                }
                Ok(bytes_value(out))
            }
            "u8" | "be16" | "be32" | "le16" | "le32" | "be64" | "le64" => {
                // 宽度/上限/端序取自 shape 表（与字段类型编码、静态检查同一权威；
                // 8 字节按 i64::MAX 封顶——无符号 2^64 超出 i64 表示）
                let (width, max, little) =
                    crate::shape::int_width(name).expect("已匹配定宽整数原语");
                // 同宽字节直通 + 范围检查 + 编码与字段类型共用（encode_int_bytes）
                Ok(bytes_value(encode_int_bytes(
                    args.first(),
                    width,
                    little,
                    max,
                    &format!("`{name}`"),
                    span,
                )?))
            }
            // varint/qvarint 值原语已移除（下沉为 eng_lib/vint.pkt 的库 proto 声明，
            // 值位置调用走下方 `_` 分支的 proto 值位置调用）——变长整数编码统一
            // 收敛到 vint codec（codec.rs `VintCodec::encode`，字段与库 proto 同实现）。
            // `raw` 是双位置原语（与 hex 对称）：层位置 = Raw 载荷层（registry），
            // 值位置 = 字符串按 UTF-8 编码（`raw("abc")` ≡ Python `b"abc"`），
            // 字节列表原样直通。
            "raw" => {
                if let Some(v) = args.first()
                    && let Value::List(_) = v
                {
                    return Ok(v.clone());
                }
                let s = str_of(args.first(), name, span)?;
                Ok(bytes_value(s.as_bytes().to_vec()))
            }
            // tpl(template, input)：字符串模板匹配 → 字节（%c/%d/%x + 宽度 + 重复/
            // 填充 + 分隔符字符类；ip4/ip6/mac 值原语的字面量解析已下沉为 eng_lib
            // 值函数基于 tpl 实现，见 eng_lib/bytes.pkt 与 packet-dsl/src/tpl.rs）
            "tpl" => crate::tpl::eval_tpl(args, span),
            // dns("host")：域名 → IP（v4 优先，返回字符串，可流入 ip4/ip6 与字段元数据）
            "dns" => {
                let host = str_of(args.first(), name, span)?;
                // IP 字面量短路：无需解析器直接返回（headers.pkt 的 ip4(dns(src))
                // 在无解析器的纯 DSL 测试环境也可用；域名才走宿主解析器）
                if host.parse::<std::net::IpAddr>().is_ok() {
                    return Ok(Value::Str(host));
                }
                // 可选第二参 dns("host", 6) = IPv6 优先（ipv6() 值函数用；
                // 默认 v4 优先与历史行为一致）
                let want_v6 = matches!(args.get(1), Some(Value::Int(6)));
                let addrs = crate::dns_lookup(&host);
                let pick = if want_v6 {
                    addrs.iter().find(|a| a.is_ipv6()).or_else(|| addrs.first())
                } else {
                    addrs.iter().find(|a| a.is_ipv4()).or_else(|| addrs.first())
                };
                match pick {
                    Some(a) => Ok(Value::Str(a.to_string())),
                    None => Err(Diagnostic::at(
                        format!("`dns` 无法解析域名：`{host}`（宿主未注入解析器或解析失败）"),
                        span,
                    )),
                }
            }
            // cksum(data)：互联网校验和（RFC 1071，one's complement）→ 2 字节大端。
            // 与自动校验和共用 serialize::checksum。原 words16/fold16（校验和的
            // 切分/折叠内部机制）已回退移除——DSL 不再暴露中间步骤，校验和是一步
            // 原语（sum 仍是通用整数求和，见下）。
            "cksum" => {
                let v = args
                    .first()
                    .ok_or_else(|| Diagnostic::at("`cksum` 缺少参数", span))?;
                let data = bytes_of(v, span)?;
                Ok(bytes_value(
                    crate::serialize::checksum(&data).to_be_bytes().to_vec(),
                ))
            }
            // md5/sha1/sha256(data)：常见摘要算法（闭合算法原语化，与 sum 同哲学）——
            // 输入字节列表或字符串（UTF-8），输出定长摘要字节（16/20/32）。
            "md5" | "sha1" | "sha256" => {
                let v = args
                    .first()
                    .ok_or_else(|| Diagnostic::at(format!("`{name}` 缺少参数"), span))?;
                let data = bytes_of(v, span)?;
                let digest = match name {
                    "md5" => {
                        use md5::{Digest, Md5};
                        let mut h = Md5::new();
                        h.update(&data);
                        h.finalize().to_vec()
                    }
                    "sha1" => {
                        use sha1::{Digest, Sha1};
                        let mut h = Sha1::new();
                        h.update(&data);
                        h.finalize().to_vec()
                    }
                    _ => {
                        use sha2::{Digest, Sha256};
                        let mut h = Sha256::new();
                        h.update(&data);
                        h.finalize().to_vec()
                    }
                };
                Ok(bytes_value(digest))
            }
            // count(list)：列表元素个数（原 eng_lib 值函数下沉回引擎原语）。
            "count" => {
                let v = args
                    .first()
                    .ok_or_else(|| Diagnostic::at("`count` 缺少参数", span))?;
                let Value::List(items) = v else {
                    return Err(Diagnostic::at(
                        format!("`count` 需要列表，得到 {}", crate::registry::describe(v)),
                        span,
                    ));
                };
                Ok(Value::Int(items.len() as i64))
            }
            // len 已下沉为 eng_lib/bytes.pkt 库值函数（`func len(x) -> int { count(raw(x)) }`）——
            // 可组合（count∘raw），无需引擎实现（qvarint(len(data)) 等长度前缀直接用）
            // ── 位运算（函数形态）──
            // bor(a, b, ...) 变参左折叠；band/bxor 二元；bnot 一元；shl/shr 移位。
            // 输入双形态（与 be16/tpl 同哲学）：全部 Int/Hex → 整数位运算（结果整数）；
            // 全部同宽字节列表 → 元素级位运算（结果字节列表）。协议标志位已下沉为
            // eng_lib/bytes.pkt 的位常量值函数（syn()/df()/request() 等），组合用
            // bor：如 tcp(flags=bor(syn(), ack()))。shl/shr 仅整数（字节列表无移位语义）。
            // 算术 mul/div/sub 为宽度/expr 表达式专用（`bytes="sub(mul(shr(x,4),4),20)"`）。
            "bor" | "band" | "bxor" | "bnot" | "shl" | "shr" | "mul" | "div" | "sub" => {
                match name {
                    "bnot" => {
                        // 一元：整数按位取反 / 字节列表元素级取反
                        if args.len() != 1 {
                            return Err(Diagnostic::at("`bnot` 需要 1 个参数", span));
                        }
                        let v = &args[0];
                        match v {
                            Value::List(_) => {
                                let b = bytes_of(v, span)?;
                                Ok(bytes_value(b.into_iter().map(|x| !x).collect()))
                            }
                            _ => Ok(Value::Int(!int_of(Some(v), name, span)?)),
                        }
                    }
                    "shl" | "shr" => {
                        // 移位：仅整数；移位量限 0..64（wrapping_* 对越界移位会 panic）
                        if args.len() != 2 {
                            return Err(Diagnostic::at(format!("`{name}` 需要 2 个参数"), span));
                        }
                        let a = int_of(args.first(), name, span)?;
                        let n = int_of(args.get(1), name, span)?;
                        if !(0..64).contains(&n) {
                            return Err(Diagnostic::at(
                                format!("`{name}` 移位量超出 0..64：{n}"),
                                span,
                            ));
                        }
                        let out = if name == "shl" {
                            a.wrapping_shl(n as u32)
                        } else {
                            a.wrapping_shr(n as u32)
                        };
                        Ok(Value::Int(out))
                    }
                    _ => {
                        // bor 至少 2 参；band/bxor 恰 2 参；mul/div/sub 恰 2 参（仅整数）
                        let is_arith = matches!(name, "mul" | "div" | "sub");
                        let ok = if name == "bor" {
                            args.len() >= 2
                        } else {
                            args.len() == 2
                        };
                        if !ok {
                            return Err(Diagnostic::at(
                                format!(
                                    "`{name}` 需要{}",
                                    if name == "bor" {
                                        "至少 2 个参数"
                                    } else {
                                        " 2 个参数"
                                    }
                                ),
                                span,
                            ));
                        }
                        // checked 算术：debug/release 均不 panic/回绕，溢出返回 None
                        // （div 的 b==0 由 checked_div 返回 None，调用方先判除零再报溢出）
                        let op = match name {
                            "bor" => |a: i64, b: i64| Some(a | b),
                            "band" => |a: i64, b: i64| Some(a & b),
                            "bxor" => |a: i64, b: i64| Some(a ^ b),
                            "mul" => |a: i64, b: i64| a.checked_mul(b),
                            "div" => |a: i64, b: i64| a.checked_div(b),
                            "sub" => |a: i64, b: i64| a.checked_sub(b),
                            _ => unreachable!("已在分支排除"),
                        };
                        // 双形态：全部 Int/Hex → 整数；全部同宽字节列表 → 元素级
                        // （算术 mul/div/sub 仅整数形态——字节列表无乘除/减法语义）
                        if args
                            .iter()
                            .all(|a| matches!(a, Value::Int(_) | Value::Hex(_)))
                        {
                            let mut acc = int_of(args.first(), name, span)?;
                            for v in &args[1..] {
                                let b = int_of(Some(v), name, span)?;
                                // 除零先报（checked_div 对 b==0 返回 None，混淆为溢出）
                                if name == "div" && b == 0 {
                                    return Err(Diagnostic::at("`div` 除数为 0", span));
                                }
                                acc = op(acc, b).ok_or_else(|| {
                                    Diagnostic::at(format!("`{name}` 整数溢出"), span)
                                })?;
                            }
                            Ok(Value::Int(acc))
                        } else if !is_arith && args.iter().all(|a| matches!(a, Value::List(_))) {
                            let lists: Vec<Vec<u8>> = args
                                .iter()
                                .map(|a| bytes_of(a, span))
                                .collect::<PktResult<_>>()?;
                            let w = lists[0].len();
                            for l in &lists {
                                if l.len() != w {
                                    return Err(Diagnostic::at(
                                        format!(
                                            "`{name}` 字节列表宽度不一致（{} vs {w}）",
                                            l.len()
                                        ),
                                        span,
                                    ));
                                }
                            }
                            let mut out = Vec::with_capacity(w);
                            for i in 0..w {
                                let mut acc = lists[0][i];
                                for l in &lists[1..] {
                                    // 位运算（本路径仅 bor/band/bxor）不可能溢出
                                    acc = op(acc as i64, l[i] as i64).expect("位运算不溢出") as u8;
                                }
                                out.push(acc);
                            }
                            Ok(bytes_value(out))
                        } else {
                            Err(Diagnostic::at(
                                format!("`{name}` 需要全部整数或全部同宽字节列表"),
                                span,
                            ))
                        }
                    }
                }
            }
            "rand16" | "rand8" => {
                // 随机整数（0..65535 / 0..255）；需要字节时用 be16(rand16()) 等
                use std::collections::hash_map::RandomState;
                use std::hash::{BuildHasher, Hasher};
                let h = RandomState::new().build_hasher().finish();
                let n = match name {
                    "rand16" => (h as u16) as i64,
                    _ => (h as u8) as i64,
                };
                Ok(Value::Int(n))
            }
            // rand_bytes(n)：构建期随机 n 字节（0..255，每字节独立随机）——字节方向的
            // 随机（与 rand16/rand8 的整数方向互补）：随机 MAC/payload/nonce 直接产出
            // 字节列表，无需 u8(rand8()) 逐个拼。上限 = 包长上限 65535（IPv4 total
            // length 16 位封顶，超过无意义）。与 rand16/rand8 同一随机来源（每次构建
            // 独立，与序列化 seed 无关——确定性由调用方固定随机字段保证）。
            "rand_bytes" => {
                use std::collections::hash_map::RandomState;
                use std::hash::{BuildHasher, Hasher};
                let n = int_of(args.first(), "rand_bytes", span)?;
                if n < 0 {
                    return Err(Diagnostic::at(
                        format!("`rand_bytes` 需要非负字节数，得到 {n}"),
                        span,
                    ));
                }
                if n > 65535 {
                    return Err(Diagnostic::at(
                        format!("`rand_bytes` 字节数超出包长上限 0..65535：{n}"),
                        span,
                    ));
                }
                let mut out: Vec<u8> = Vec::with_capacity(n as usize);
                while out.len() < n as usize {
                    let h = RandomState::new().build_hasher().finish();
                    for b in h.to_le_bytes() {
                        if out.len() < n as usize {
                            out.push(b);
                        }
                    }
                }
                Ok(bytes_value(out))
            }
            // pad(n)：n 个零字节（确定性填充）——与 rand_bytes 对称（随机 vs 零）。
            // 真实缺口：以太网最小帧 46B 填充、IP 选项对齐、DNS OPT padding 等；
            // 无此原语时只能 hex("0000...") 或 concat 一串 be16(0)。上限同包长
            // 上限 0..65535（与 rand_bytes 一致）。
            "pad" => {
                let n = int_of(args.first(), "pad", span)?;
                if n < 0 {
                    return Err(Diagnostic::at(
                        format!("`pad` 需要非负字节数，得到 {n}"),
                        span,
                    ));
                }
                if n > 65535 {
                    return Err(Diagnostic::at(
                        format!("`pad` 字节数超出包长上限 0..65535：{n}"),
                        span,
                    ));
                }
                Ok(bytes_value(vec![0; n as usize]))
            }
            // `dns_name` 已下沉为 eng_lib 值函数（tpl `%L` 说明符实现，见
            // eng_lib/bytes.pkt 与 packet-dsl/src/tpl.rs）
            // 值位置 hex：合法输入在解析期已是字节列表，这里只处理非法输入的标记调用
            //（`hex("abc")` 等），统一校验并清晰报错
            "hex" => {
                let s = str_of(args.first(), name, span)?;
                let bytes = crate::registry::hex_string_bytes(&s)
                    .map_err(|msg| Diagnostic::at(format!("`hex` {msg}：`{s}`"), span))?;
                Ok(bytes_value(bytes))
            }
            _ => {
                // proto 值位置调用（自表示协议双位置）：构建字节返回（concat/raw 组合用）
                // proto = 带 schema 的 FuncStmt（`#[proto] func ... -> bytes`）
                if let Some((def_module, LookupKind::Func(idx))) = self.graph.lookup(module, name)
                    && self
                        .graph
                        .func_def(def_module, idx)
                        .is_some_and(|f| f.schema.is_some())
                {
                    let proto_args: Vec<Arg> = args
                        .iter()
                        .map(|v| Arg {
                            name: None,
                            value: v.clone(),
                            span,
                        })
                        .collect();
                    let pkts = self.eval_proto(def_module, idx, &proto_args)?;
                    if let Some(bytes) = pkts
                        .first()
                        .and_then(|p| p.layers.first())
                        .and_then(layer_raw_bytes)
                    {
                        return Ok(bytes_value(bytes));
                    }
                }
                // 用户值函数（-> bytes / -> int）
                self.eval_user_value_func(module, name, args, span)
            }
        }
    }

    /// 调用用户值函数（-> bytes）。名字经**模块作用域**解析（本地函数 + import +
    /// eng_lib 库导出 prelude），函数体在**定义模块**作用域内求值——库值函数体内可
    /// 调用其他库值函数（headers.pkt 的 http/dns 内部值函数同理）。
    fn eval_user_value_func(
        &mut self,
        module: usize,
        name: &str,
        args: &[Value],
        span: crate::ast::Span,
    ) -> PktResult<Value> {
        let (def_module, kind) = self
            .graph
            .lookup(module, name)
            .ok_or_else(|| Diagnostic::at(format!("未知值函数或原语：`{name}`"), span))?;
        let LookupKind::Func(idx) = kind else {
            return Err(Diagnostic::at(
                format!("`{name}` 不是值函数（缺 `-> bytes` / `-> int`）"),
                span,
            ));
        };
        let func = self
            .graph
            .func_def(def_module, idx)
            .cloned()
            .ok_or_else(|| Diagnostic::new("内部错误：值函数丢失"))?;
        let (ret, body) = func.value_body.clone().ok_or_else(|| {
            Diagnostic::at(
                format!("`{name}` 不是值函数（缺 `-> bytes` / `-> int`）"),
                span,
            )
        })?;
        if args.len() > func.params.len() {
            return Err(Diagnostic::at(format!("值函数 `{name}`：参数过多"), span));
        }
        // 防自递归/互递归栈溢出：进入函数体（含默认值求值——默认值里可调值函数）
        // 前检查深度，超限报错而不是耗尽栈崩溃（组件循环检测不覆盖值函数路径）
        if self.value_depth >= MAX_VALUE_FUNC_DEPTH {
            return Err(Diagnostic::at(
                format!("值函数调用深度超过 {MAX_VALUE_FUNC_DEPTH} 层（疑似递归调用：`{name}`）"),
                span,
            ));
        }
        self.value_depth += 1;
        // 闭包收尾：无论函数体求值成功与否都递减深度（错误路径不泄漏计数）
        let mut run = || -> PktResult<Value> {
            let mut env: FnEnv = FnEnv::new();
            for p in &func.params {
                let v = match &p.default {
                    Some(d) if matches!(d, Value::Call { .. } | Value::BinOp { .. }) => {
                        // 默认值里的值调用（含库值函数）/运算在定义模块作用域求值
                        Some(self.eval_value(def_module, d)?)
                    }
                    other => other.clone(),
                };
                env.insert(p.name.clone(), v);
            }
            for (i, a) in args.iter().enumerate() {
                env.insert(func.params[i].name.clone(), Some(a.clone()));
            }
            self.env_stack.push(env);
            let result = self.eval_value(def_module, &body);
            self.env_stack.pop();
            match ret {
                // `-> bytes`：结果由调用方在字节上下文校验（bytes_of）
                crate::ast::ValueRet::Bytes => result,
                // `-> int`：结果必须是整数（运行时校验，与 `-> bytes` 的声明+校验一致）
                crate::ast::ValueRet::Int => {
                    let v = result?;
                    Ok(Value::Int(int_of(Some(&v), name, span)?))
                }
            }
        };
        let result = run();
        self.value_depth -= 1;
        result
    }

    /// 流水线求值：use 元件展开为包组，然后逐层包裹（内 → 外）。
    /// 无 `use` 时以一个空包种子开始（函数体层片段语义；顶层裸层流水线同样成立）。
    fn eval_pipeline(&mut self, module: usize, p: &Pipeline) -> PktResult<Vec<PacketSpec>> {
        let mut packets = Vec::new();
        for (name, _span) in &p.use_names {
            packets.extend(self.eval_component(module, name, &[])?);
        }
        if packets.is_empty() {
            // 空包种子：无 use 的流水线从空包开始逐层包裹
            packets.push(PacketSpec { layers: Vec::new() });
        }
        for call in &p.layers {
            let form_packets = self.eval_call(module, call)?;
            let mut wrapped = Vec::new();
            for bp in &packets {
                for fp in &form_packets {
                    let mut layers = bp.layers.clone();
                    layers.extend(fp.layers.iter().cloned());
                    wrapped.push(PacketSpec { layers });
                }
            }
            packets = wrapped;
        }
        Ok(packets)
    }
}
