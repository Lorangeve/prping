//! 求值：`use` 展开、层位变体笛卡尔积、包组逐包包裹、组件循环检测、函数调用。
//!
//! 规则（设计 §4.4 / §5.2）：
//! - 每个 `use` 元件独立成包；多个 `use` 元件 → 多个包。
//! - 每层一个 `|>` 正常包裹，内 → 外依次嵌套。
//! - 包组（命名流水线展开出多个包）被 `use` 时逐包包裹。
//! - 组件引用（`|>` 层调用或 def expr 中的调用）解析为内置函数或用户元件。
//! - 函数（`func name(args) { body }`）：调用时绑定参数（未传 → 默认值或未设），
//!   函数体以「空包种子」求值——无 `use` 时从一个空包开始逐层包裹（层片段语义）。

use crate::ast::{Arg, Call, Expr, Pipeline, Value};
use crate::diag::{Diagnostic, PktResult};
use crate::ir::{BuildResult, PacketSpec};
use crate::registry::{FnEnv, Params, build_layers, is_builtin};
use crate::semantic::{LookupKind, Module, ModuleGraph};

/// 求值入口：默认导出 + 全部命名导出的包（export 顺序，默认导出在前），无运行时参数。
pub fn resolve(module: &Module) -> PktResult<BuildResult> {
    resolve_with_params(module, &Params::new())
}

/// 求值入口（带运行时参数）：脚本内 `params("name")` 从 `params` 取值。
pub fn resolve_with_params(module: &Module, params: &Params) -> PktResult<BuildResult> {
    let sources = resolve_sources_with_params(module, params)?;
    let packets = sources.into_iter().flat_map(|(_, pkts)| pkts).collect();
    Ok(BuildResult { packets })
}

/// 字节列表 → Value（每个字节为 Int 值）。
fn bytes_value(bytes: Vec<u8>) -> Value {
    Value::List(bytes.into_iter().map(|b| Value::Int(b as i64)).collect())
}

/// 值表达式：取位置 span（用于报错）。
fn v_span(v: &Value) -> crate::ast::Span {
    match v {
        Value::Call { span, .. } | Value::Add { span, .. } | Value::Ident { span, .. } => *span,
        _ => crate::ast::Span::new(0, 0, 0, 0),
    }
}

/// 值 → 字节列表。
fn bytes_of(v: &Value, span: crate::ast::Span) -> PktResult<Vec<u8>> {
    match v {
        Value::List(items) => {
            let mut out = Vec::new();
            for it in items {
                match it {
                    Value::Int(i) if (0..=255).contains(i) => out.push(*i as u8),
                    Value::Hex(h) if *h <= 255 => out.push(*h as u8),
                    other => {
                        return Err(Diagnostic::at(
                            format!(
                                "期望字节列表（0..255 整数），得到 {}",
                                crate::registry::describe(other)
                            ),
                            span,
                        ));
                    }
                }
            }
            Ok(out)
        }
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
        Some(Value::Str(s)) => s
            .trim()
            .parse::<i64>()
            .map_err(|_| Diagnostic::at(format!("`{what}` 需要整数，得到字符串 `{s}`"), span)),
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

/// 模块内函数下标（按名）。
fn func_index(graph: &crate::semantic::ModuleGraph, module: usize, name: &str) -> Option<usize> {
    graph.func_index(module, name)
}

/// DNS 域名长度前缀编码：`example.com` → `07 65 78 ... 00`。
fn dns_name_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in s.split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
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
    let entry = entry_index(module)?;
    let mut ctx = EvalCtx {
        graph: &module.graph,
        stack: Vec::new(),
        params,
        env_stack: vec![FnEnv::new()],
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

struct EvalCtx<'a> {
    graph: &'a ModuleGraph,
    /// 组件求值栈（循环检测）：(定义模块下标, 名字)。
    stack: Vec<(usize, String)>,
    /// 运行时参数表（`params("name")` 值引用）。
    params: &'a Params,
    /// 函数参数环境栈（内层函数在最上）。
    env_stack: Vec<FnEnv>,
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
            LookupKind::Func(func_idx) => self.eval_func(def_module, func_idx, args),
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
                Some(d) if matches!(d, Value::Call { .. } | Value::Add { .. }) => {
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
            if matches!(a.value, Value::Call { .. } | Value::Add { .. }) {
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
            Value::Str(_) | Value::Int(_) | Value::Hex(_) | Value::Bool(_) => Ok(v.clone()),
            Value::List(items) => {
                let items = items
                    .iter()
                    .map(|it| self.eval_value(module, it))
                    .collect::<PktResult<Vec<_>>>()?;
                Ok(Value::List(items))
            }
            Value::Ident { name, span } => {
                let env = self.current_env();
                let v = env
                    .get(name)
                    .and_then(|x| x.clone())
                    .ok_or_else(|| Diagnostic::at(format!("参数 `{name}` 未提供"), *span))?;
                // 环境值可能是 Param/嵌套值表达式 → 递归解析
                self.eval_value(module, &v)
            }
            Value::Param { name, default } => {
                let s = crate::registry::param_value(
                    self.params,
                    name,
                    default,
                    v_span(v),
                    "值表达式",
                )?;
                Ok(Value::Str(s))
            }
            Value::Add { left, right, span } => {
                let l = self.eval_value(module, left)?;
                let r = self.eval_value(module, right)?;
                let to_i = |v: &Value| match v {
                    Value::Int(i) => Some(*i),
                    Value::Hex(h) => Some(*h as i64),
                    _ => None,
                };
                let (Some(a), Some(b)) = (to_i(&l), to_i(&r)) else {
                    return Err(Diagnostic::at("`+` 只支持整数相加", *span));
                };
                Ok(Value::Int(a + b))
            }
            Value::Call {
                name,
                name_span,
                args,
                span,
            } => {
                if name == "reduce" {
                    // reduce 的第三参是函数名（Ident），不能预求值
                    return self.eval_reduce(module, args, *span, *name_span);
                }
                let arg_vals: Vec<Value> = args
                    .iter()
                    .map(|a| self.eval_value(module, a))
                    .collect::<PktResult<_>>()?;
                self.eval_value_call(module, name, &arg_vals, *span, *name_span)
            }
        }
    }

    /// 值调用分派：引擎字节原语 / reduce / 用户值函数（-> bytes）。
    fn eval_value_call(
        &mut self,
        module: usize,
        name: &str,
        args: &[Value],
        span: crate::ast::Span,
        _name_span: crate::ast::Span,
    ) -> PktResult<Value> {
        match name {
            "concat" => {
                let mut out = Vec::new();
                for a in args {
                    out.extend(bytes_of(a, span)?);
                }
                Ok(bytes_value(out))
            }
            "u8" | "be16" | "be32" => {
                let n = int_of(args.first(), name, span)?;
                let width = match name {
                    "u8" => 1,
                    "be16" => 2,
                    _ => 4,
                };
                let max = 1u64 << (width * 8);
                if n < 0 || n as u64 >= max {
                    return Err(Diagnostic::at(
                        format!("`{name}` 参数超出范围 0..{}：{n}", max - 1),
                        span,
                    ));
                }
                let bytes: Vec<u8> = (0..width)
                    .rev()
                    .map(|i| ((n as u64 >> (i * 8)) & 0xFF) as u8)
                    .collect();
                Ok(bytes_value(bytes))
            }
            "ip4" | "ip6" | "mac" | "bytes" => {
                // 字节列表直通：`mac(rand_mac())` / 预编码地址——长度与值域符合即原样
                // 返回（与值位置 hex → 字节列表同一哲学，支持随机/字节值构造地址）；
                // 字符串仍按类型解析（ip4/ip6/mac 文本 → 字节）。
                let want = match name {
                    "ip4" => Some(4),
                    "ip6" => Some(16),
                    "mac" => Some(6),
                    _ => None,
                };
                if let Some(w) = want
                    && let Some(v) = args.first()
                    && let Value::List(items) = v
                    && items.len() == w
                    && items
                        .iter()
                        .all(|it| matches!(it, Value::Int(i) if (0..=255).contains(i)))
                {
                    return Ok(v.clone());
                }
                let s = str_of(args.first(), name, span)?;
                let bytes: Vec<u8> = match name {
                    "ip4" => match s.parse::<std::net::Ipv4Addr>() {
                        Ok(a) => a.octets().to_vec(),
                        // 域名回退：经宿主解析器取首个 IPv4（如 params("dst", "www.baidu.com")）
                        Err(_) => match crate::dns_lookup(&s).into_iter().find(|a| a.is_ipv4()) {
                            Some(a) => match a {
                                std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                                _ => unreachable!("已按 is_ipv4 过滤"),
                            },
                            None => {
                                return Err(Diagnostic::at(
                                    format!("`{name}` 不是合法 IPv4 且无法解析：`{s}`"),
                                    span,
                                ));
                            }
                        },
                    },
                    "ip6" => match s.parse::<std::net::Ipv6Addr>() {
                        Ok(a) => a.octets().to_vec(),
                        Err(_) => match crate::dns_lookup(&s).into_iter().find(|a| a.is_ipv6()) {
                            Some(a) => match a {
                                std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                                _ => unreachable!("已按 is_ipv6 过滤"),
                            },
                            None => {
                                return Err(Diagnostic::at(
                                    format!("`{name}` 不是合法 IPv6 且无法解析：`{s}`"),
                                    span,
                                ));
                            }
                        },
                    },
                    "mac" => crate::ir::MacAddr::from_str_loose(&s)
                        .ok_or_else(|| {
                            Diagnostic::at(format!("`{name}` 不是合法 MAC：`{s}`"), span)
                        })?
                        .0
                        .to_vec(),
                    _ => s.as_bytes().to_vec(),
                };
                Ok(bytes_value(bytes))
            }
            // dns("host")：域名 → IP（v4 优先，返回字符串，可流入 ip4/ip6 与字段元数据）
            "dns" => {
                let host = str_of(args.first(), name, span)?;
                let addrs = crate::dns_lookup(&host);
                let pick = addrs.iter().find(|a| a.is_ipv4()).or_else(|| addrs.first());
                match pick {
                    Some(a) => Ok(Value::Str(a.to_string())),
                    None => Err(Diagnostic::at(
                        format!("`dns` 无法解析域名：`{host}`（宿主未注入解析器或解析失败）"),
                        span,
                    )),
                }
            }
            "cksum" => {
                let v = args
                    .first()
                    .ok_or_else(|| Diagnostic::at("`cksum` 缺少参数", span))?;
                let data = bytes_of(v, span)?;
                let c = crate::serialize::checksum(&data);
                Ok(bytes_value(vec![(c >> 8) as u8, (c & 0xFF) as u8]))
            }
            "len" => {
                let v = args
                    .first()
                    .ok_or_else(|| Diagnostic::at("`len` 缺少参数", span))?;
                let b = bytes_of(v, span)?;
                Ok(Value::Int(b.len() as i64))
            }
            "arpop" => {
                // ARP op 快捷：字符串 request/reply → 1/2；数字透传
                let v = args
                    .first()
                    .ok_or_else(|| Diagnostic::at("`arpop` 缺少参数", span))?;
                match v {
                    Value::Str(s) => {
                        let n = match s.to_ascii_lowercase().as_str() {
                            "request" => 1,
                            "reply" => 2,
                            _ => {
                                return Err(Diagnostic::at(
                                    format!("`arpop` 无法识别：`{s}`（request/reply）"),
                                    span,
                                ));
                            }
                        };
                        Ok(Value::Int(n))
                    }
                    other => int_of(Some(other), "arpop", span).map(Value::Int),
                }
            }
            "tcpflags" | "ip4flags" => {
                // TCP/IPv4 flags 快捷："syn,ack" → 0x12；"df,mf" → 0x6000；数字透传
                let v = args
                    .first()
                    .ok_or_else(|| Diagnostic::at(format!("`{name}` 缺少参数"), span))?;
                if let Value::Int(_) | Value::Hex(_) = v {
                    return int_of(Some(v), name, span).map(Value::Int);
                }
                let s = str_of(Some(v), name, span)?;
                let mut out: i64 = 0;
                for tok in s.split([',', '|']) {
                    match tok.trim().to_ascii_lowercase().as_str() {
                        "syn" => out |= 0x02,
                        "ack" => out |= 0x10,
                        "psh" => out |= 0x08,
                        "rst" => out |= 0x04,
                        "fin" => out |= 0x01,
                        "urg" => out |= 0x20,
                        "ece" => out |= 0x40,
                        "cwr" => out |= 0x80,
                        "df" => out |= 0x4000,
                        "mf" => out |= 0x2000,
                        "" => {}
                        other => {
                            return Err(Diagnostic::at(
                                format!("`{name}` 无法识别：`{other}`"),
                                span,
                            ));
                        }
                    }
                }
                Ok(Value::Int(out))
            }
            "count" => {
                // 列表元素计数（DNS qdcount 等）
                let v = args
                    .first()
                    .ok_or_else(|| Diagnostic::at("`count` 缺少参数", span))?;
                match v {
                    Value::List(items) => Ok(Value::Int(items.len() as i64)),
                    other => Err(Diagnostic::at(
                        format!(
                            "`count` 需要列表，得到 {}",
                            crate::registry::describe(other)
                        ),
                        span,
                    )),
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
            "dns_name" => {
                let s = str_of(args.first(), name, span)?;
                Ok(bytes_value(dns_name_bytes(&s)))
            }
            "reduce" => self.eval_reduce(module, args, span, _name_span),
            _ => {
                // 用户值函数（-> bytes）
                self.eval_user_value_func(module, name, args, span)
            }
        }
    }

    /// `reduce(列表, 初始字节, 函数名)`：逐项折叠，f(acc, item) -> bytes。
    fn eval_reduce(
        &mut self,
        module: usize,
        args: &[Value],
        span: crate::ast::Span,
        _name_span: crate::ast::Span,
    ) -> PktResult<Value> {
        if args.len() != 3 {
            return Err(Diagnostic::at(
                "`reduce` 需要 3 个参数：列表, 初始字节, 函数名",
                span,
            ));
        }
        let list_val = self.eval_value(module, &args[0])?;
        let Value::List(items) = list_val else {
            return Err(Diagnostic::at("`reduce` 的第一个参数需要是列表", span));
        };
        let init_val = self.eval_value(module, &args[1])?;
        let init = bytes_of(&init_val, span)?;
        let Value::Ident {
            name: fname,
            span: fspan,
        } = &args[2]
        else {
            return Err(Diagnostic::at("`reduce` 的第三个参数需要是函数名", span));
        };
        let func = self
            .graph
            .func_def(
                module,
                func_index(self.graph, module, fname).ok_or_else(|| {
                    Diagnostic::at(format!("`reduce` 找不到值函数 `{fname}`"), *fspan)
                })?,
            )
            .cloned()
            .ok_or_else(|| Diagnostic::new("内部错误：reduce 函数丢失"))?;
        if func.value_body.is_none() {
            return Err(Diagnostic::at(
                format!("`reduce` 的回调 `{fname}` 必须是值函数（-> bytes）"),
                *fspan,
            ));
        }
        let mut acc: Vec<u8> = init;
        for item in items {
            // 绑定 (acc, item) 并调用回调
            let mut env: FnEnv = FnEnv::new();
            env.insert("acc".to_string(), Some(bytes_value(acc)));
            env.insert("item".to_string(), Some(item.clone()));
            self.env_stack.push(env);
            let result = self.eval_value(module, func.value_body.as_ref().unwrap());
            self.env_stack.pop();
            acc = bytes_of(&result?, span)?;
        }
        Ok(bytes_value(acc))
    }

    /// 调用用户值函数（-> bytes）。
    fn eval_user_value_func(
        &mut self,
        module: usize,
        name: &str,
        args: &[Value],
        span: crate::ast::Span,
    ) -> PktResult<Value> {
        let idx = func_index(self.graph, module, name)
            .ok_or_else(|| Diagnostic::at(format!("未知值函数或原语：`{name}`"), span))?;
        let func = self
            .graph
            .func_def(module, idx)
            .cloned()
            .ok_or_else(|| Diagnostic::new("内部错误：值函数丢失"))?;
        let body = func
            .value_body
            .clone()
            .ok_or_else(|| Diagnostic::at(format!("`{name}` 不是值函数（缺 `-> bytes`）"), span))?;
        if args.len() > func.params.len() {
            return Err(Diagnostic::at(format!("值函数 `{name}`：参数过多"), span));
        }
        let mut env: FnEnv = FnEnv::new();
        for p in &func.params {
            let v = match &p.default {
                Some(d) if matches!(d, Value::Call { .. } | Value::Add { .. }) => {
                    Some(self.eval_value(module, d)?)
                }
                other => other.clone(),
            };
            env.insert(p.name.clone(), v);
        }
        for (i, a) in args.iter().enumerate() {
            env.insert(func.params[i].name.clone(), Some(a.clone()));
        }
        self.env_stack.push(env);
        let result = self.eval_value(module, &body);
        self.env_stack.pop();
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
