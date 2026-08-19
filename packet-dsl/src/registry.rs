//! 内置函数注册表：把层函数调用（`tcp(dport=80)` 等）构造成 IR `Layer`。
//!
//! - 位置参数按参数表顺序填充；命名参数任意顺序；命名参数后不允许位置参数。
//! - 未知参数 / 重复参数 / 类型错误带 span 报错。
//! - 未填字段保持 `None`（自动值），由宿主序列化阶段补齐。

use std::net::{Ipv4Addr, Ipv6Addr};

use std::borrow::Cow;

use crate::ast::{Arg, Call, Span, Value};
use crate::diag::{Diagnostic, PktResult};
use crate::ir::*;

/// 运行时参数表：`--params k=v` 注入，脚本用 `params("k")` 读取。
pub type Params = std::collections::HashMap<String, String>;

/// 函数参数环境：参数名 → 值（None = 未设/省略）。非函数上下文传空表。
pub type FnEnv = std::collections::HashMap<String, Option<Value>>;

/// 内置层函数名（供语义阶段的 call 名字解析使用）。
///
/// 引擎只保留数据原语与唯一的「字节 → 层标注」原语 `layer`：eth/arp/ipv4/... 等
/// 层头由 eng_lib 的库函数提供（headers.pkt 构建头字节，bytes.pkt 用 `layer`
/// 做具名包装；库导出隐式可见，作用域优先于内置）。
pub const BUILTINS: &[&str] = &[
    "raw", "hex",
    // 通用层标注原语：bytes + 层类型字面量 → 该层（序列化时按层类型自动补
    // length/checksum/proto 推导；eng_lib/bytes.pkt 的 *_bytes 具名包装基于它）
    "layer",
];

pub fn is_builtin(name: &str) -> bool {
    BUILTINS.contains(&name)
}

/// 内置函数文档（LSP 悬停 / 补全详情用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltinDoc {
    pub name: &'static str,
    /// 参数：名字 → 类型说明。
    pub params: Vec<(&'static str, &'static str)>,
    /// 自动行为说明。
    pub auto: &'static str,
}

/// 全部内置函数文档。
pub fn builtin_docs() -> Vec<BuiltinDoc> {
    vec![
        BuiltinDoc {
            name: "raw",
            params: vec![("bytes", "str | 字节列表")],
            auto: "原样字节载荷",
        },
        BuiltinDoc {
            name: "hex",
            params: vec![("str", "hex 字符串，如 \"deadbeef\"")],
            auto: "hex 解码为原始字节载荷",
        },
        // 通用层标注原语（eng_lib/bytes.pkt 的 *_bytes 具名包装基于它）
        BuiltinDoc {
            name: "layer",
            params: vec![
                (
                    "kind",
                    "层类型字面量：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns",
                ),
                ("bytes", "该层头字节"),
                ("src", "可选源地址（仅 ipv4/ipv6，伪头部校验和）"),
                ("dst", "可选目标地址（仅 ipv4/ipv6，伪头部校验和）"),
            ],
            auto: "序列化时按层类型自动补 length/checksum 并按内层推导 proto/ethertype/next_header",
        },
    ]
}

/// 单个内置函数文档。
pub fn builtin_doc(name: &str) -> Option<BuiltinDoc> {
    builtin_docs().into_iter().find(|d| d.name == name)
}

/// 把层调用解析为一个或多个 IR Layer（`params` 供 `params("name")` 值引用取值，
/// `env` 供函数体内的参数引用 `Value::Ident` 取值）。
pub fn build_layers(call: &Call, params: &Params, env: &FnEnv) -> PktResult<Vec<Layer>> {
    match call.name.as_str() {
        "raw" => build_raw(call, params, env).map(|f| vec![Layer::Raw(f)]),
        "hex" => build_hex(call, params, env).map(|f| vec![Layer::Raw(f)]),
        // 通用层标注：kind（闭集字面量）+ 头字节 → 对应层；ipv4/ipv6 可选 src/dst
        // （伪头部校验和元数据）。eng_lib/bytes.pkt 的 *_bytes 具名包装基于它。
        "layer" => build_layer(call, params, env),
        other => Err(Diagnostic::at(
            format!(
                "未知层函数 `{other}`（内置原语：{}；层头函数见 eng_lib 库导出）",
                BUILTINS.join(" / ")
            ),
            call.name_span,
        )),
    }
}

// ── 参数解析骨架 ──────────────────────────────────────────────

/// 参数读取器：命名参数 + 按表顺序的位置参数。
struct Args<'a> {
    call: &'a Call,
    params: &'a Params,
    env: &'a FnEnv,
    param_order: &'static [&'static str],
    pos_args: Vec<&'a Arg>,
    positional: usize,
    taken: Vec<&'static str>,
}

impl<'a> Args<'a> {
    fn new(
        call: &'a Call,
        params: &'a Params,
        env: &'a FnEnv,
        param_order: &'static [&'static str],
    ) -> PktResult<Self> {
        let pos_args: Vec<&Arg> = call.args.iter().filter(|a| a.name.is_none()).collect();
        // 命名参数后不允许位置参数
        if let Some(first_named) = call.args.iter().position(|a| a.name.is_some())
            && pos_args
                .iter()
                .any(|a| call.args.iter().position(|x| std::ptr::eq(x, *a)).unwrap() > first_named)
        {
            return Err(Diagnostic::at(
                format!("`{}`：命名参数后不能使用位置参数", call.name),
                call.span,
            ));
        }
        // 命名参数重复
        for (i, a) in call.args.iter().enumerate() {
            if let Some((n, _)) = &a.name {
                for b in call.args.iter().skip(i + 1) {
                    if let Some((m, _)) = &b.name
                        && n == m
                    {
                        return Err(Diagnostic::at(
                            format!("`{}`：参数 `{n}` 重复指定", call.name),
                            b.span,
                        ));
                    }
                }
            }
        }
        Ok(Self {
            call,
            params,
            env,
            param_order,
            pos_args,
            positional: 0,
            taken: Vec::new(),
        })
    }

    fn take(&mut self, name: &'static str) -> PktResult<Option<&'a Arg>> {
        // 命名参数
        if let Some(arg) = self
            .call
            .args
            .iter()
            .find(|a| a.name.as_ref().map(|(n, _)| n.as_str()) == Some(name))
        {
            if self.taken.contains(&name) {
                return Err(Diagnostic::at(
                    format!("`{}`：参数 `{name}` 重复指定", self.call.name),
                    arg.span,
                ));
            }
            self.taken.push(name);
            // 参数引用未设 → 视为未提供（省略 → 自动值）
            if arg_unset(arg, self.env, name)? {
                return Ok(None);
            }
            return Ok(Some(arg));
        }
        // 位置参数：填参数表顺序
        if self.positional < self.pos_args.len() && self.param_order[self.positional] == name {
            let arg = self.pos_args[self.positional];
            self.positional += 1;
            self.taken.push(name);
            if arg_unset(arg, self.env, name)? {
                return Ok(None);
            }
            return Ok(Some(arg));
        }
        Ok(None)
    }

    /// 校验没有未知参数 / 多余位置参数。
    fn finish(&self) -> PktResult<()> {
        for a in &self.call.args {
            if let Some((n, span)) = &a.name
                && !self.param_order.contains(&n.as_str())
            {
                return Err(Diagnostic::at(
                    format!("`{}`：未知参数 `{n}`", self.call.name),
                    *span,
                ));
            }
        }
        if self.positional < self.pos_args.len() {
            let extra = &self.pos_args[self.positional];
            return Err(Diagnostic::at(
                format!("`{}`：位置参数过多", self.call.name),
                extra.span,
            ));
        }
        Ok(())
    }

    // 便捷取值

    // 字段取值（支持 `"random"` 关键字）：未写 → Auto；"random" → Random；值 → Value

    /// 返回 (字段, 域名来源)：地址由域名解析得到时 second 为 Some(host)（展示用）。
    fn opt_field_ip4(
        &mut self,
        name: &'static str,
    ) -> PktResult<(Field<Ipv4Addr>, Option<String>)> {
        match self.take(name)? {
            Some(a) => field_coerce_ip4(&a.value, a.span, name, self.params, self.env),
            None => Ok((Field::Auto, None)),
        }
    }
    fn opt_field_ip6(
        &mut self,
        name: &'static str,
    ) -> PktResult<(Field<Ipv6Addr>, Option<String>)> {
        match self.take(name)? {
            Some(a) => field_coerce_ip6(&a.value, a.span, name, self.params, self.env),
            None => Ok((Field::Auto, None)),
        }
    }
}

/// 解析参数引用链：`Value::Ident` → 环境里的最终值；返回 None 表示「未设」（省略 → 自动）。
pub(crate) fn deref_opt<'a>(
    v: &'a Value,
    env: &'a FnEnv,
    what: &str,
) -> PktResult<Option<&'a Value>> {
    let mut cur = v;
    let mut depth = 0;
    loop {
        match cur {
            Value::Ident { name, span: ispan } => {
                if depth > 32 {
                    return Err(Diagnostic::at(format!("参数引用循环：`{name}`"), *ispan));
                }
                match env.get(name) {
                    Some(Some(inner)) => {
                        cur = inner;
                        depth += 1;
                    }
                    Some(None) => return Ok(None),
                    None => {
                        return Err(Diagnostic::at(
                            format!("参数 `{name}` 未定义（函数未声明该参数；用于 `{what}`）"),
                            *ispan,
                        ));
                    }
                }
            }
            _ => return Ok(Some(cur)),
        }
    }
}

/// 通用层标注原语：`layer(kind, bytes[, src, dst])`。
///
/// `kind` 为闭集字面量（eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns），`bytes` 为该层头
/// 字节直喂；`src`/`dst` 仅 ipv4/ipv6 接受（供传输层伪头部校验和）。
fn build_layer(call: &Call, params: &Params, env: &FnEnv) -> PktResult<Vec<Layer>> {
    const LAYER_PARAMS: &[&str] = &["kind", "bytes", "src", "dst"];
    let mut a = Args::new(call, params, env, LAYER_PARAMS)?;
    let kind = match a.take("kind")? {
        Some(arg) => val_str(&arg.value, arg.span, "kind", params, env)?,
        None => {
            return Err(Diagnostic::at(
                "`layer` 需要 `kind` 参数（eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns）",
                call.span,
            ));
        }
    };
    let b = match a.take("bytes")? {
        Some(arg) => val_bytes(&arg.value, arg.span, "bytes", params, env)?,
        None => {
            return Err(Diagnostic::at(
                format!("`layer` 需要 `bytes` 参数（层类型 `{kind}`）"),
                call.span,
            ));
        }
    };
    a.finish()?;
    // 非 IP 层不接受 src/dst（与旧 *_bytes 一致：未知参数报错）
    if !matches!(kind.as_str(), "ipv4" | "ipv6") {
        if let Some(arg) = a.take("src")? {
            return Err(Diagnostic::at(
                format!("层类型 `{kind}` 不接受 `src` 参数（仅 ipv4/ipv6）"),
                arg.span,
            ));
        }
        if let Some(arg) = a.take("dst")? {
            return Err(Diagnostic::at(
                format!("层类型 `{kind}` 不接受 `dst` 参数（仅 ipv4/ipv6）"),
                arg.span,
            ));
        }
    }
    match kind.as_str() {
        "eth" => Ok(vec![Layer::Ethernet(EthernetFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "arp" => Ok(vec![Layer::Arp(ArpFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "ipv4" => {
            let (src, src_host) = a.opt_field_ip4("src")?;
            let (dst, dst_host) = a.opt_field_ip4("dst")?;
            Ok(vec![Layer::Ipv4(Ipv4Fields {
                src,
                dst,
                src_host,
                dst_host,
                raw: Some(b),
                ..Default::default()
            })])
        }
        "ipv6" => {
            let (src, src_host) = a.opt_field_ip6("src")?;
            let (dst, dst_host) = a.opt_field_ip6("dst")?;
            Ok(vec![Layer::Ipv6(Ipv6Fields {
                src,
                dst,
                src_host,
                dst_host,
                raw: Some(b),
                ..Default::default()
            })])
        }
        "icmp" => Ok(vec![Layer::Icmp(IcmpFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "tcp" => Ok(vec![Layer::Tcp(TcpFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "udp" => Ok(vec![Layer::Udp(UdpFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "http" => Ok(vec![Layer::Http(HttpFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "dns" => Ok(vec![Layer::Dns(DnsFields {
            raw: Some(b),
            ..Default::default()
        })]),
        other => Err(Diagnostic::at(
            format!("未知层类型 `{other}`（可用：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns）"),
            call.span,
        )),
    }
}

/// 必须提供的值：参数引用未设 → 报错。
fn deref<'a>(v: &'a Value, env: &'a FnEnv, span: Span, what: &str) -> PktResult<&'a Value> {
    deref_opt(v, env, what)?
        .ok_or_else(|| Diagnostic::at(format!("参数 `{what}` 未提供（参数未设）"), span))
}

/// 参数值是否为「未设」的参数引用（链式解析到 None）。
fn arg_unset(arg: &Arg, env: &FnEnv, what: &str) -> PktResult<bool> {
    Ok(matches!(arg.value, Value::Ident { .. }) && deref_opt(&arg.value, env, what)?.is_none())
}

/// 值 → Field：字符串 `"random"` → Random；其余走原 coercer → Value。未设参数 → Auto。
fn field_coerce_ip4(
    v: &Value,
    span: Span,
    what: &str,
    params: &Params,
    env: &FnEnv,
) -> PktResult<(Field<Ipv4Addr>, Option<String>)> {
    let Some(v) = deref_opt(v, env, what)? else {
        return Ok((Field::Auto, None));
    };
    match v {
        Value::Str(s) if s.eq_ignore_ascii_case("random") => Ok((Field::Random, None)),
        _ => {
            let (a, host) = val_ip4(v, span, what, params, env)?;
            Ok((Field::Value(a), host))
        }
    }
}

fn field_coerce_ip6(
    v: &Value,
    span: Span,
    what: &str,
    params: &Params,
    env: &FnEnv,
) -> PktResult<(Field<Ipv6Addr>, Option<String>)> {
    let Some(v) = deref_opt(v, env, what)? else {
        return Ok((Field::Auto, None));
    };
    match v {
        Value::Str(s) if s.eq_ignore_ascii_case("random") => Ok((Field::Random, None)),
        _ => {
            let (a, host) = val_ip6(v, span, what, params, env)?;
            Ok((Field::Value(a), host))
        }
    }
}

// ── 值 → 类型 ─────────────────────────────────────────────────

fn val_str(v: &Value, span: Span, what: &str, params: &Params, env: &FnEnv) -> PktResult<String> {
    let v = deref(v, env, span, what)?;
    match v {
        Value::Str(s) => Ok(s.clone()),
        other => match as_param(other, params, span, what)? {
            Some(s) => Ok(s.into_owned()),
            None => Err(Diagnostic::at(
                format!("参数 `{what}` 需要字符串，得到 {}", describe(other)),
                span,
            )),
        },
    }
}

fn val_bytes(
    v: &Value,
    span: Span,
    what: &str,
    params: &Params,
    env: &FnEnv,
) -> PktResult<Vec<u8>> {
    let v = deref(v, env, span, what)?;
    match v {
        Value::Str(s) => Ok(s.as_bytes().to_vec()),
        Value::Param { .. } => Ok(as_param(v, params, span, what)?
            .unwrap_or_default()
            .as_bytes()
            .to_vec()),
        Value::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                let b = match it {
                    Value::Int(i) if (0..=255).contains(i) => *i as u8,
                    Value::Hex(h) if *h <= 255 => *h as u8,
                    Value::Int(i) => {
                        return Err(Diagnostic::at(
                            format!("参数 `{what}` 的字节超出范围 0..255：{i}"),
                            span,
                        ));
                    }
                    Value::Hex(h) => {
                        return Err(Diagnostic::at(
                            format!("参数 `{what}` 的字节超出范围 0..255：0x{h:X}"),
                            span,
                        ));
                    }
                    other => {
                        return Err(Diagnostic::at(
                            format!("参数 `{what}` 需要字节列表，得到 {}", describe(other)),
                            span,
                        ));
                    }
                };
                out.push(b);
            }
            Ok(out)
        }
        other => Err(Diagnostic::at(
            format!(
                "参数 `{what}` 需要字符串或字节列表（如 [0x48, 0x69]），得到 {}",
                describe(other)
            ),
            span,
        )),
    }
}

/// 返回 (地址, 域名来源)：字符串是域名且经解析器解析时 second 为 Some(host)。
fn val_ip4(
    v: &Value,
    span: Span,
    what: &str,
    params: &Params,
    env: &FnEnv,
) -> PktResult<(Ipv4Addr, Option<String>)> {
    let v = deref(v, env, span, what)?;
    match v {
        Value::Str(s) => ip4_or_dns(s, what, span),
        other => match as_param(other, params, span, what)? {
            Some(s) => ip4_or_dns(&s, what, span),
            None => Err(Diagnostic::at(
                format!(
                    "参数 `{what}` 需要 IPv4 地址字符串，得到 {}",
                    describe(other)
                ),
                span,
            )),
        },
    }
}

/// IPv4 字符串解析；非 IP 时尝试域名解析（宿主 `dns` 解析器，取首个 IPv4）。
fn ip4_or_dns(s: &str, what: &str, span: Span) -> PktResult<(Ipv4Addr, Option<String>)> {
    match s.parse::<Ipv4Addr>() {
        Ok(a) => Ok((a, None)),
        Err(_) => match crate::dns_lookup(s).into_iter().find(|a| a.is_ipv4()) {
            Some(a) => match a {
                std::net::IpAddr::V4(v4) => Ok((v4, Some(s.to_string()))),
                _ => unreachable!("已按 is_ipv4 过滤"),
            },
            None => Err(Diagnostic::at(
                format!("参数 `{what}` 不是合法 IPv4 且无法解析：`{s}`"),
                span,
            )),
        },
    }
}

/// 返回 (地址, 域名来源)：字符串是域名且经解析器解析时 second 为 Some(host)。
fn val_ip6(
    v: &Value,
    span: Span,
    what: &str,
    params: &Params,
    env: &FnEnv,
) -> PktResult<(Ipv6Addr, Option<String>)> {
    let v = deref(v, env, span, what)?;
    match v {
        Value::Str(s) => ip6_or_dns(s, what, span),
        other => match as_param(other, params, span, what)? {
            Some(s) => ip6_or_dns(&s, what, span),
            None => Err(Diagnostic::at(
                format!(
                    "参数 `{what}` 需要 IPv6 地址字符串，得到 {}",
                    describe(other)
                ),
                span,
            )),
        },
    }
}

/// IPv6 字符串解析；非 IP 时尝试域名解析（宿主 `dns` 解析器，取首个 IPv6）。
fn ip6_or_dns(s: &str, what: &str, span: Span) -> PktResult<(Ipv6Addr, Option<String>)> {
    match s.parse::<Ipv6Addr>() {
        Ok(a) => Ok((a, None)),
        Err(_) => match crate::dns_lookup(s).into_iter().find(|a| a.is_ipv6()) {
            Some(a) => match a {
                std::net::IpAddr::V6(v6) => Ok((v6, Some(s.to_string()))),
                _ => unreachable!("已按 is_ipv6 过滤"),
            },
            None => Err(Diagnostic::at(
                format!("参数 `{what}` 不是合法 IPv6 且无法解析：`{s}`"),
                span,
            )),
        },
    }
}

pub(crate) fn describe(v: &Value) -> String {
    match v {
        Value::Str(s) => format!("字符串 `{s}`"),
        Value::Int(i) => format!("整数 `{i}`"),
        Value::Hex(h) => format!("十六进制 `0x{h:X}`"),
        Value::Bool(b) => format!("布尔 `{b}`"),
        Value::List(_) => "列表".to_string(),
        Value::Param { name, .. } => format!("参数引用 `params(\"{name}\")`"),
        Value::Ident { name, .. } => format!("参数引用 `{name}`"),
        Value::Call { name, .. } => format!("值调用 `{name}(...)`"),
        Value::Add { .. } => "加法表达式".to_string(),
    }
}

/// 取参数值：`params("name", "默认值")` → 宿主注入值或默认值；缺失报错。
pub(crate) fn param_value(
    params: &Params,
    name: &str,
    default: &Option<String>,
    span: Span,
    what: &str,
) -> PktResult<String> {
    match params.get(name) {
        Some(v) => Ok(v.clone()),
        None => match default {
            Some(d) => Ok(d.clone()),
            None => Err(Diagnostic::at(
                format!(
                    "参数 `{name}` 未提供（用于 `{what}`；可用 --params {name}=... 传入，或写 params(\"{name}\", \"默认值\")）"
                ),
                span,
            )),
        },
    }
}

/// 若值是参数引用，解析为字符串；否则返回 None。
fn as_param<'a>(
    v: &'a Value,
    params: &Params,
    span: Span,
    what: &str,
) -> PktResult<Option<Cow<'a, str>>> {
    match v {
        Value::Param { name, default } => Ok(Some(Cow::Owned(param_value(
            params, name, default, span, what,
        )?))),
        _ => Ok(None),
    }
}

// ── 各层构造函数 ─────────────────────────────────────────────

const RAW_PARAMS: &[&str] = &["bytes"];
fn build_raw(call: &Call, params: &Params, env: &FnEnv) -> PktResult<RawData> {
    let mut a = Args::new(call, params, env, RAW_PARAMS)?;
    let bytes = match a.take("bytes")? {
        Some(arg) => val_bytes(&arg.value, arg.span, "bytes", params, env)?,
        None => Vec::new(),
    };
    a.finish()?;
    Ok(RawData { bytes })
}

const HEX_PARAMS: &[&str] = &["str"];
fn build_hex(call: &Call, params: &Params, env: &FnEnv) -> PktResult<RawData> {
    let mut a = Args::new(call, params, env, HEX_PARAMS)?;
    let s = match a.take("str")? {
        Some(arg) => val_str(&arg.value, arg.span, "str", params, env)?,
        None => {
            return Err(Diagnostic::at(
                "`hex` 需要字符串参数，如 hex(\"deadbeef\")",
                call.span,
            ));
        }
    };
    a.finish()?;
    let hex: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !hex.len().is_multiple_of(2) || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Diagnostic::at(
            format!("`hex` 需要偶数长度的十六进制字符串：`{s}`"),
            call.span,
        ));
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("已校验 hex"))
        .collect();
    Ok(RawData { bytes })
}
