//! 静态形状检查（求值前类型检查）：封闭 coercer 规则中**语法可判定**的子集。
//!
//! 设计边界（与 `DESIGN.md` §6 的字节本位模型一致）：
//! - 值层只有「数值 / 字节」两类语义类型 + 字符串的上下文消费；本检查不引入
//!   第三种类型，只把求值期 coercer **必然报错**的形态提前到编辑器——文案与
//!   求值期报错对齐（`int_of` / `encode_int_bytes` / `bytes_of` / `tpl`），
//!   保证「编辑器看到的就是运行时会发生的」。
//! - **零误报优先**：`params(...)`（按形状解析，运行时才定型）、裸 `ident`
//!   （函数参数/前序字段引用）、未知名字的值调用一律跳过。`hex("...")` 合法
//!   形态在解析期已转成字节列表（parser 值位置特判），残留的 `hex` 调用标记
//!   即非法输入（奇数长度/非 hex 字符），可静态判定。
//! - 覆盖面：def/流水线/层函数体与参数默认值、值函数体（`-> bytes`/`-> int`）、
//!   proto 字段默认值（按字段类型 + bits 判别位）、sniffer 值表达式。库值函数
//!   （eng_lib 的 `ip4`/`mac` 等）体不跨模块展开，但 `ip4`/`ip6`/`mac` 作为
//!   标准库地址值函数收录在宽度表（与 GRAMMAR.md §4.6 / DESIGN.md §6.3 清单一致）。
//! - 宿主接入：LSP `analyze` 在解析成功后运行本检查，产出多条诊断（按位置
//!   排序去重）；CLI 求值路径不变——本检查只提前报错时机，不改语义。

use crate::ast::{
    BinOp, Expr, FieldDecl, FieldType, Pipeline, SnifferItem, SnifferPred, SnifferSpec,
    SnifferValue, Span, Value,
};
use crate::diag::Diagnostic;
use crate::registry::{describe, hex_string_bytes};
use crate::semantic::Module;

// 宽度/字节分类规则表在 `shape.rs`（唯一权威，与 eval coercer / registry 共用）；
// 下面四个函数是 check 侧薄别名（签名与全部调用点不变，报错文案属地不变）。

/// 定宽整数原语 → (字节数, 上限 2^n)。
fn int_prim(name: &str) -> Option<(usize, u64)> {
    crate::shape::int_width(name).map(|(w, max, _little)| (w, max))
}

/// 标准库地址值函数 → 字节宽度（eng_lib 值函数基于 tpl，等宽直通）。
fn std_addr_width(name: &str) -> Option<usize> {
    crate::shape::std_addr_width(name)
}

/// 整数字面量（Int/Hex 同进数值上下文）→ i64。
fn literal_int(v: &Value) -> Option<i64> {
    crate::shape::literal_int(v)
}

/// 静态可算的产字节宽度：字面量/封闭原语 → Some(n)，含未知成分 → None
/// （None = 静态侧跳过，零误报；求值期 coercer 接管）。
fn width_of(v: &Value) -> Option<usize> {
    crate::shape::fixed_width(v)
}

/// 对模块做静态形状检查，返回全部诊断（按源码位置排序、去重）。
pub fn check_module(module: &Module) -> Vec<Diagnostic> {
    let mut c = Checker { out: Vec::new() };
    if let Some((p, _)) = &module.default {
        c.pipeline(p);
    }
    for d in &module.defs {
        c.expr(&d.expr);
    }
    for f in &module.funcs {
        for p in &f.params {
            if let Some(d) = &p.default {
                c.value(d);
            }
        }
        c.pipeline(&f.body);
        // 值函数体（-> bytes / -> int）：体是值表达式，同样可静态检查
        if let Some((_, body)) = &f.value_body {
            c.value(body);
        }
    }
    for p in &module.protos {
        for pp in &p.params {
            if let Some(d) = &pp.default {
                c.value(d);
            }
        }
        c.proto_fields(&p.fields);
    }
    if let Some(spec) = &module.sniffer {
        c.sniffer(spec);
    }
    // 按位置排序（无 span 兜底 0:0）+ 相邻去重（同位置同文案只留一条）
    c.out.sort_by_key(|d| {
        (
            d.span.as_ref().map(|s| (s.start.line, s.start.col)),
            d.message.clone(),
        )
    });
    c.out.dedup_by(|a, b| {
        a.message == b.message
            && a.span.as_ref().map(|s| (s.start, s.end))
                == b.span.as_ref().map(|s| (s.start, s.end))
    });
    c.out
}

struct Checker {
    out: Vec<Diagnostic>,
}

impl Checker {
    fn err(&mut self, msg: impl Into<String>, span: Span) {
        self.out.push(Diagnostic::at(msg, span));
    }

    fn expr(&mut self, e: &Expr) {
        match e {
            Expr::Call(c) => {
                // 层位置的调用名不是值原语（raw/hex/layer 双位置、层头函数另查），
                // 只检查实参里的值表达式
                for a in &c.args {
                    self.value(&a.value);
                }
            }
            Expr::Pipeline(p) => self.pipeline(p),
        }
    }

    fn pipeline(&mut self, p: &Pipeline) {
        for call in &p.layers {
            for a in &call.args {
                self.value(&a.value);
            }
        }
    }

    fn value(&mut self, v: &Value) {
        match v {
            Value::Str(_) | Value::Int(_) | Value::Hex(_) | Value::Ident { .. } => {}
            Value::List(items) => {
                for it in items {
                    self.value(it);
                }
            }
            Value::Param { default, .. } => {
                if let Some(d) = default {
                    self.value(d);
                }
            }
            Value::BinOp {
                op: BinOp::Add,
                left,
                right,
                span,
            } => {
                self.value(left);
                self.value(right);
                // 加法只支持整数相加（eval 对求值后的两侧做 Int/Hex 判定）；
                // 字符串/列表字面量是必然失败形态，ident/call 未知形状跳过
                if matches!(left.as_ref(), Value::Str(_) | Value::List(_))
                    || matches!(right.as_ref(), Value::Str(_) | Value::List(_))
                {
                    self.err(
                        format!(
                            "`+` 只支持整数相加，得到 {} 与 {}",
                            describe(left),
                            describe(right)
                        ),
                        *span,
                    );
                }
            }
            Value::Call {
                name, args, span, ..
            } => self.call(name, args, *span),
        }
    }

    fn call(&mut self, name: &str, args: &[Value], span: Span) {
        // 无论被调名字是否已知，先递归检查实参（内层值调用都要查）
        for a in args {
            self.value(a);
        }
        if let Some((width, max)) = int_prim(name) {
            self.int_call(name, width, max, args, span);
            return;
        }
        match name {
            // 值位置 hex：合法输入解析期已转字节列表，此标记即非法输入
            "hex" => self.hex_marker(args, span),
            "raw" => {
                let Some(a0) = args.first() else {
                    self.err("`raw` 缺少参数", span);
                    return;
                };
                if matches!(a0, Value::Int(_) | Value::Hex(_)) {
                    self.err(format!("`raw` 需要字符串，得到 {}", describe(a0)), span);
                }
            }
            "concat" => {
                for a in args {
                    if matches!(a, Value::Int(_) | Value::Hex(_)) {
                        self.err(format!("期望字节列表或字符串，得到 {}", describe(a)), span);
                    } else if let Value::List(items) = a {
                        self.byte_list(items, span);
                    }
                }
            }
            "count" => {
                let Some(a0) = args.first() else {
                    self.err("`count` 缺少参数", span);
                    return;
                };
                if matches!(a0, Value::Int(_) | Value::Hex(_) | Value::Str(_)) {
                    self.err(format!("`count` 需要列表，得到 {}", describe(a0)), span);
                }
            }
            "cksum" | "md5" | "sha1" | "sha256" => {
                let Some(a0) = args.first() else {
                    self.err(format!("`{name}` 缺少参数"), span);
                    return;
                };
                if matches!(a0, Value::Int(_) | Value::Hex(_)) {
                    self.err(format!("期望字节列表或字符串，得到 {}", describe(a0)), span);
                } else if let Value::List(items) = a0 {
                    self.byte_list(items, span);
                }
            }
            "bor" | "band" | "bxor" | "bnot" | "shl" | "shr" | "mul" | "div" | "sub" => {
                self.bitop(name, args, span);
            }
            "rand_bytes" | "pad" => {
                let Some(a0) = args.first() else {
                    self.err(format!("`{name}` 缺少参数"), span);
                    return;
                };
                match a0 {
                    Value::Int(n) if *n < 0 => {
                        self.err(format!("`{name}` 需要非负字节数，得到 {n}"), span);
                    }
                    Value::Int(n) if *n > 65535 => {
                        self.err(format!("`{name}` 字节数超出包长上限 0..65535：{n}"), span);
                    }
                    Value::Hex(h) if *h > 65535 => {
                        self.err(format!("`{name}` 字节数超出包长上限 0..65535：{h}"), span);
                    }
                    Value::Str(s) => self.err(
                        format!(
                            "`{name}` 需要整数，得到字符串 `{s}`——字符串不隐式转数值，写 0x/十进制字面量，或经 params(\"...\") 按形状解析"
                        ),
                        span,
                    ),
                    _ => {}
                }
            }
            "tpl" => {
                let Some(t) = args.first() else {
                    self.err("`tpl` 缺少模板参数", span);
                    return;
                };
                if matches!(t, Value::Int(_) | Value::Hex(_) | Value::List(_)) {
                    self.err(
                        format!("`tpl` 模板参数需要字符串字面量，得到 {}", describe(t)),
                        span,
                    );
                    return;
                }
                if args.len() < 2 {
                    self.err("`tpl` 缺少输入参数", span);
                    return;
                }
                if let Some(a1) = args.get(1)
                    && matches!(a1, Value::Int(_) | Value::Hex(_))
                {
                    self.err(
                        format!("`tpl` 输入参数需要字符串或字节列表，得到 {}", describe(a1)),
                        span,
                    );
                }
            }
            "dns" => {
                let Some(a0) = args.first() else {
                    self.err("`dns` 缺少参数", span);
                    return;
                };
                if matches!(a0, Value::Int(_) | Value::Hex(_) | Value::List(_)) {
                    self.err(format!("`dns` 需要字符串，得到 {}", describe(a0)), span);
                }
            }
            "global" => {
                let bad = match args.first() {
                    None => true,
                    Some(a0) => matches!(a0, Value::Int(_) | Value::Hex(_) | Value::List(_)),
                };
                if bad {
                    self.err(
                        "`global` 需要字符串参数（全局名），如 global(\"tid\")",
                        span,
                    );
                }
            }
            other => {
                if let Some(w) = std_addr_width(other) {
                    self.std_addr(w, args, span);
                }
                // 未知/库/用户值函数：体不跨模块展开，不检查
            }
        }
    }

    /// 定宽整数原语（u8/be16/...）：字符串误入数值位、范围溢出、同宽直通宽度。
    fn int_call(&mut self, name: &str, width: usize, max: u64, args: &[Value], span: Span) {
        let Some(a0) = args.first() else {
            self.err(format!("`{name}` 缺少参数"), span);
            return;
        };
        match a0 {
            // 字符串不隐式转数值（int_of 文案）；params 按形状解析是唯一豁免
            Value::Str(s) => self.err(
                format!(
                    "`{name}` 需要整数，得到字符串 `{s}`——字符串不隐式转数值，写 0x/十进制字面量，或经 params(\"...\") 按形状解析"
                ),
                span,
            ),
            Value::Int(n) if *n < 0 || (*n as u64) >= max => {
                self.err(format!("`{name}` 参数超出范围 0..={}：{n}", max - 1), span);
            }
            Value::Hex(h) if *h >= max => {
                self.err(format!("`{name}` 参数超出范围 0..={}：{h}", max - 1), span);
            }
            Value::List(items) => {
                if let Some(n) = self.byte_list(items, span)
                    && n != width
                {
                    self.width_err(name, width, max, n, span);
                }
            }
            // hex 非法标记由通用走查报；其余封闭原语按静态宽度判同宽直通
            Value::Call { name: inner, .. } if inner == "hex" => {}
            other => {
                if let Some(n) = width_of(other)
                    && n != width
                {
                    self.width_err(name, width, max, n, span);
                }
            }
        }
    }

    fn width_err(&mut self, name: &str, width: usize, max: u64, got: usize, span: Span) {
        self.err(
            format!(
                "`{name}` 需要恰好 {width} 字节（数值 0..={} 或同宽字节列表），得到 {got} 字节",
                max - 1
            ),
            span,
        );
    }

    /// 字节列表元素检查（bytes_of 规则）：字面量元素须 0..=255。
    /// 返回 Some(len) = 全部元素为合法字面量字节（宽度可静态判定），否则 None。
    fn byte_list(&mut self, items: &[Value], span: Span) -> Option<usize> {
        let mut len = 0;
        let mut all = true;
        for it in items {
            match it {
                Value::Int(i) if (0..=255).contains(i) => len += 1,
                Value::Hex(h) if *h <= 255 => len += 1,
                Value::Int(_) | Value::Hex(_) => {
                    self.err(
                        format!("期望字节列表（0..255 整数），得到 {}", describe(it)),
                        span,
                    );
                    all = false;
                }
                _ => all = false,
            }
        }
        all.then_some(len)
    }

    /// 值位置 hex 非法标记：与 eval 共用 hex_string_bytes 的校验文案。
    fn hex_marker(&mut self, args: &[Value], span: Span) {
        let Some(a0) = args.first() else {
            self.err("`hex` 缺少参数", span);
            return;
        };
        match a0 {
            Value::Str(s) => {
                if let Err(msg) = hex_string_bytes(s) {
                    self.err(format!("`hex` {msg}：`{s}`"), span);
                }
            }
            other => self.err(format!("`hex` 需要字符串，得到 {}", describe(other)), span),
        }
    }

    /// 位运算/算术原语：严格元数（eval 校验）+ 双形态一致性 + 移位量/除零。
    /// 文案分层与 eval 对齐：shl/shr/bnot 走 int_of（需要整数），mul/div/sub 与
    /// bor/band/bxor 的混合形态走「需要全部整数或全部同宽字节列表」。
    fn bitop(&mut self, name: &str, args: &[Value], span: Span) {
        let need_ok = match name {
            "bnot" => args.len() == 1,
            "bor" => args.len() >= 2,
            _ => args.len() == 2,
        };
        if !need_ok {
            let msg = match name {
                "bnot" => "`bnot` 需要 1 个参数".to_string(),
                "bor" => "`bor` 需要至少 2 个参数".to_string(),
                _ => format!("`{name}` 需要 2 个参数"),
            };
            self.err(msg, span);
            return;
        }
        match name {
            "bnot" => {
                // 一元：整数按位取反 / 字节列表元素级；字符串误入 → int_of 文案
                if let Some(Value::Str(s)) = args.first() {
                    self.err(
                        format!(
                            "`bnot` 需要整数，得到字符串 `{s}`——字符串不隐式转数值，写 0x/十进制字面量，或经 params(\"...\") 按形状解析"
                        ),
                        span,
                    );
                }
            }
            "shl" | "shr" => {
                // 移位仅整数（int_of 直接判定）：字符串/列表字面量必然失败
                for a in args {
                    match a {
                        Value::Str(s) => self.err(
                            format!(
                                "`{name}` 需要整数，得到字符串 `{s}`——字符串不隐式转数值，写 0x/十进制字面量，或经 params(\"...\") 按形状解析"
                            ),
                            span,
                        ),
                        Value::List(_) => {
                            self.err(format!("`{name}` 需要整数，得到 列表"), span);
                        }
                        _ => {}
                    }
                }
                if let Some(n) = args.get(1).and_then(literal_int)
                    && !(0..64).contains(&n)
                {
                    self.err(format!("`{name}` 移位量超出 0..64：{n}"), span);
                }
            }
            "mul" | "div" | "sub" => {
                // 算术仅整数形态：列表/字符串字面量必然失败
                if args
                    .iter()
                    .any(|a| matches!(a, Value::Str(_) | Value::List(_)))
                {
                    self.err(format!("`{name}` 需要全部整数或全部同宽字节列表"), span);
                    return;
                }
                // 除零（eval 在运算前先判；仅两个整数字面量时可静态判定）
                if name == "div"
                    && args.len() == 2
                    && args
                        .iter()
                        .all(|a| matches!(a, Value::Int(_) | Value::Hex(_)))
                    && args.get(1).and_then(literal_int) == Some(0)
                {
                    self.err("`div` 除数为 0", span);
                }
            }
            _ => {
                // bor/band/bxor 双形态：全部整数 或 全部同宽字节列表
                let any_str = args.iter().any(|a| matches!(a, Value::Str(_)));
                let any_list = args.iter().any(|a| matches!(a, Value::List(_)));
                let any_int = args
                    .iter()
                    .any(|a| matches!(a, Value::Int(_) | Value::Hex(_)));
                if any_str || (any_list && any_int) {
                    self.err(format!("`{name}` 需要全部整数或全部同宽字节列表"), span);
                    return;
                }
                if any_list {
                    // 全列表：元素检查 + 同宽检查（eval 逐列表报宽度）
                    let mut widths: Vec<usize> = Vec::new();
                    for a in args {
                        if let Value::List(items) = a
                            && let Some(w) = self.byte_list(items, span)
                        {
                            widths.push(w);
                        }
                    }
                    if let Some(&w0) = widths.first() {
                        for w in &widths[1..] {
                            if w != &w0 {
                                self.err(
                                    format!("`{name}` 字节列表宽度不一致（{w} vs {w0}）"),
                                    span,
                                );
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    /// 标准库地址值函数（eng_lib，体为 tpl）：字符串按模板解析、字节列表等宽直通。
    fn std_addr(&mut self, width: usize, args: &[Value], span: Span) {
        let Some(a0) = args.first() else { return };
        let width_err_msg = |width: usize, got: usize| {
            format!(
                "`tpl` 参数是字节列表但长度与模板输出不符：模板输出 {width} 字节，实际 {got} 字节（字符串按模板解析）"
            )
        };
        match a0 {
            // 字符串是正常路径（模板解析；具体格式错误求值期才判定）
            Value::Str(_) => {}
            Value::Int(_) | Value::Hex(_) => {
                self.err(
                    format!("`tpl` 输入参数需要字符串或字节列表，得到 {}", describe(a0)),
                    span,
                );
            }
            Value::List(items) => {
                if let Some(n) = self.byte_list(items, span)
                    && n != width
                {
                    self.err(width_err_msg(width, n), span);
                }
            }
            other => {
                if let Some(n) = width_of(other)
                    && n != width
                {
                    self.err(width_err_msg(width, n), span);
                }
            }
        }
    }

    fn sniffer(&mut self, spec: &SnifferSpec) {
        fn walk(c: &mut Checker, p: &SnifferPred) {
            match p {
                SnifferPred::Clause(clause) => {
                    for item in &clause.items {
                        match item {
                            // 值表达式（求值为字节后比较）可静态检查；
                            // 字面量是常量比较语义、SentField 是字段引用，均不查
                            SnifferItem::FieldEq {
                                val: SnifferValue::Expr(v),
                                ..
                            }
                            | SnifferItem::FieldNe {
                                val: SnifferValue::Expr(v),
                                ..
                            } => c.value(v),
                            SnifferItem::Mask(v) => c.value(v),
                            _ => {}
                        }
                    }
                }
                SnifferPred::And(ps) | SnifferPred::Or(ps) => {
                    for x in ps {
                        walk(c, x);
                    }
                }
                SnifferPred::Not(inner) => walk(c, inner),
            }
        }
        for clause in &spec.clauses {
            walk(self, clause);
        }
    }

    /// proto 字段：默认值按字段类型检查（镜像 encode_field_type），
    /// 宽度/len 表达式/if 条件/list 计数做通用值走查。
    fn proto_fields(&mut self, fields: &[FieldDecl]) {
        for f in fields {
            if let Some(d) = &f.default {
                self.value(d);
                let before = self.out.len();
                self.field_typed(f, d);
                // bits 判别位检查（eval 在类型编码后做；类型本身已报错则跳过）
                if self.out.len() == before
                    && let Some(b) = f.bits
                    && let Some(n) = literal_int(d)
                {
                    let max = if b >= 64 { i64::MAX } else { (1i64 << b) - 1 };
                    if !(0..=max).contains(&n) {
                        self.err(
                            format!(
                                "proto `{}`：位字段 `{}` 的值 {n} 超出 {b} 位（0..={max}）",
                                f.name, f.name
                            ),
                            f.span,
                        );
                    }
                }
            }
            for sv in [&f.width, &f.len_expr, &f.if_cond, &f.list_count]
                .into_iter()
                .flatten()
            {
                self.value(sv);
            }
            // switch_field 是「前序字段名」字符串（非字节值），不检查
        }
    }

    /// 字段类型自身的形状检查（encode_field_type 镜像）。
    fn field_typed(&mut self, f: &FieldDecl, d: &Value) {
        let name = f.name.as_str();
        let span = f.span;
        match f.ty {
            FieldType::U8 => self.field_int(f, d, 1, false),
            FieldType::Be16 => self.field_int(f, d, 2, false),
            FieldType::Le16 => self.field_int(f, d, 2, true),
            FieldType::Be32 => self.field_int(f, d, 4, false),
            FieldType::Le32 => self.field_int(f, d, 4, true),
            FieldType::Be64 => self.field_int(f, d, 8, false),
            FieldType::Le64 => self.field_int(f, d, 8, true),
            FieldType::Vint => {
                // 值域依 codec 方案而异，只查字符串误入数值位（int_of what = 字段名）
                if let Value::Str(s) = d {
                    self.err(
                        format!(
                            "`{name}` 需要整数，得到字符串 `{s}`——字符串不隐式转数值，写 0x/十进制字面量，或经 params(\"...\") 按形状解析"
                        ),
                        span,
                    );
                }
            }
            FieldType::Mac => self.field_addr(f, d, 6, "mac"),
            FieldType::Ip4 => self.field_addr(f, d, 4, "ip4"),
            FieldType::Ip6 => self.field_addr(f, d, 16, "ip6"),
            FieldType::Bytes | FieldType::Rest => {
                match d {
                    Value::List(items) => {
                        self.byte_list(items, span);
                    }
                    Value::Int(_) | Value::Hex(_) => {
                        self.err(format!("期望字节列表或字符串，得到 {}", describe(d)), span);
                    }
                    _ => {}
                }
                // bytes=宽度声明（宽度表达式为字面量且默认宽度可算时校验）
                if f.ty == FieldType::Bytes
                    && let Some(wv) = &f.width
                    && let Some(w) = literal_int(wv)
                    && let Some(n) = width_of(d)
                    && n as i64 != w
                {
                    self.err(
                        format!(
                            "proto `{name}`：字段 `{name}` 的字节长度 {n} ≠ 声明的 `bytes({w})` 宽度"
                        ),
                        span,
                    );
                }
            }
            FieldType::DnsName => match d {
                Value::Int(_) | Value::Hex(_) => {
                    self.err(
                        format!("`tpl` 输入参数需要字符串或字节列表，得到 {}", describe(d)),
                        span,
                    );
                }
                Value::List(_) => {
                    // %L 输出宽动态不可算，不接受字节列表输入（eval 同文案）
                    self.err(
                        "`tpl` 模板含动态宽度说明符 `%L`，不接受字节列表输入（字符串按模板解析）"
                            .to_string(),
                        span,
                    );
                }
                _ => {}
            },
            FieldType::Line => {
                if matches!(d, Value::Int(_) | Value::Hex(_)) {
                    self.err(format!("期望字节列表或字符串，得到 {}", describe(d)), span);
                }
            }
        }
    }

    /// 定宽整数字段（encode_int_bytes 共用路径，what = "字段 x 的 u8" 形态）。
    fn field_int(&mut self, f: &FieldDecl, d: &Value, width: usize, little: bool) {
        let max = if width == 8 {
            1u64 << 63
        } else {
            1u64 << (width * 8)
        };
        let label = match (width, little) {
            (1, _) => "u8",
            (2, false) => "be16",
            (2, true) => "le16",
            (4, false) => "be32",
            (4, true) => "le32",
            (8, false) => "be64",
            _ => "le64",
        };
        let what = format!("字段 `{}` 的 {label}", f.name);
        match d {
            Value::Str(s) => self.err(
                format!(
                    "`{what}` 需要整数，得到字符串 `{s}`——字符串不隐式转数值，写 0x/十进制字面量，或经 params(\"...\") 按形状解析"
                ),
                f.span,
            ),
            Value::Int(n) if *n < 0 || (*n as u64) >= max => {
                self.err(format!("`{what}` 参数超出范围 0..={}：{n}", max - 1), f.span);
            }
            Value::Hex(h) if *h >= max => {
                self.err(format!("`{what}` 参数超出范围 0..={}：{h}", max - 1), f.span);
            }
            Value::List(items) => {
                if let Some(n) = self.byte_list(items, f.span)
                    && n != width
                {
                    self.err(
                        format!(
                            "`{what}` 需要恰好 {width} 字节（数值 0..={} 或同宽字节列表），得到 {n} 字节",
                            max - 1
                        ),
                        f.span,
                    );
                }
            }
            _ => {}
        }
    }

    /// 地址字段（mac_bytes/ip4_bytes/ip6_bytes 共用路径：字符串或定宽字节列表）。
    fn field_addr(&mut self, f: &FieldDecl, d: &Value, width: usize, ty: &str) {
        match d {
            Value::List(items) => {
                if let Some(n) = self.byte_list(items, f.span)
                    && n != width
                {
                    self.err(
                        format!(
                            "字段 `{}`：{ty} 需要 {width} 字节，得到 {n} 字节列表",
                            f.name
                        ),
                        f.span,
                    );
                }
            }
            Value::Int(_) | Value::Hex(_) => {
                self.err(
                    format!("`{}` 需要字符串，得到 {}", f.name, describe(d)),
                    f.span,
                );
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::parse_str;

    /// 解析并静态检查测试源码，返回诊断文案列表。
    fn check_src(src: &str) -> Vec<String> {
        let module = parse_str("t", src).expect("测试源码应可解析");
        check_module(&module)
            .into_iter()
            .map(|d| d.message)
            .collect()
    }

    #[test]
    fn string_in_numeric_position() {
        let msgs = check_src("a = raw(bytes=be16(\"4242\"))\n");
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(msgs[0].contains("需要整数，得到字符串"), "{msgs:?}");
        assert!(
            msgs[0].contains("params"),
            "应提示 params 形状解析: {msgs:?}"
        );
    }

    #[test]
    fn range_overflow() {
        let msgs = check_src("a = raw(bytes=be16(70000))\nb = raw(bytes=u8(300))\n");
        assert_eq!(msgs.len(), 2, "{msgs:?}");
        assert!(
            msgs[0].contains("参数超出范围 0..=65535：70000"),
            "{msgs:?}"
        );
        assert!(msgs[1].contains("参数超出范围 0..=255：300"), "{msgs:?}");
    }

    #[test]
    fn range_boundary_ok() {
        let msgs = check_src(concat!(
            "a = raw(bytes=u8(255))\n",
            "b = raw(bytes=be16(65535))\n",
            "c = raw(bytes=be32(0xFFFFFFFF))\n",
            "d = raw(bytes=be64(0x7FFFFFFFFFFFFFFF))\n",
        ));
        assert!(msgs.is_empty(), "{msgs:?}");
    }

    #[test]
    fn byte_list_width_mismatch() {
        // hex 合法形态解析期已转字节列表 → 宽度可静态判定
        let msgs = check_src("a = raw(bytes=be16(hex(\"123456\")))\n");
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(msgs[0].contains("需要恰好 2 字节"), "{msgs:?}");
        assert!(msgs[0].contains("得到 3 字节"), "{msgs:?}");
        assert!(check_src("a = raw(bytes=be16(hex(\"1234\")))\n").is_empty());
    }

    #[test]
    fn invalid_hex_flagged() {
        // 非法 hex 解析期残留调用标记 → 静态判定（与 eval 共用 hex_string_bytes）
        let msgs = check_src("a = raw(bytes=u8(hex(\"abc\")))\n");
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(msgs[0].contains("偶数长度"), "{msgs:?}");
    }

    #[test]
    fn composition_width() {
        assert!(check_src("a = raw(bytes=be16(concat(hex(\"12\"), hex(\"34\"))))\n").is_empty());
        let msgs = check_src("a = raw(bytes=u8(concat(hex(\"12\"), hex(\"34\"))))\n");
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(msgs[0].contains("需要恰好 1 字节"), "{msgs:?}");
    }

    #[test]
    fn raw_string_width() {
        assert!(check_src("a = raw(bytes=be16(raw(\"ab\")))\n").is_empty());
        let msgs = check_src("a = raw(bytes=be16(raw(\"abc\")))\n");
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(msgs[0].contains("需要恰好 2 字节"), "{msgs:?}");
    }

    #[test]
    fn count_needs_list() {
        let msgs = check_src("a = raw(bytes=count(\"abc\"))\n");
        assert!(
            msgs.iter().any(|m| m.contains("需要列表，得到 字符串")),
            "{msgs:?}"
        );
        assert!(check_src("a = raw(bytes=hex(\"00\"))\n").is_empty());
    }

    #[test]
    fn add_only_integers() {
        let msgs = check_src("a = raw(bytes=u8(1 + \"x\"))\n");
        assert!(
            msgs.iter().any(|m| m.contains("只支持整数相加")),
            "{msgs:?}"
        );
    }

    #[test]
    fn shift_range_and_div_zero() {
        let msgs = check_src("a = raw(bytes=u8(shl(1, 64)))\nb = raw(bytes=u8(div(10, 0)))\n");
        assert_eq!(msgs.len(), 2, "{msgs:?}");
        assert!(msgs[0].contains("移位量超出 0..64：64"), "{msgs:?}");
        assert!(msgs[1].contains("除数为 0"), "{msgs:?}");
    }

    #[test]
    fn rand_bytes_limit() {
        let msgs = check_src("a = raw(bytes=rand_bytes(70000))\n");
        assert!(
            msgs.iter()
                .any(|m| m.contains("超出包长上限 0..65535：70000")),
            "{msgs:?}"
        );
    }

    #[test]
    fn missing_argument() {
        let msgs = check_src("a = raw(bytes=u8())\n");
        assert!(msgs.iter().any(|m| m.contains("`u8` 缺少参数")), "{msgs:?}");
    }

    #[test]
    fn params_and_idents_skipped() {
        // params 形状运行时才定、ident 是参数引用 → 零误报
        let msgs = check_src(concat!(
            "func net(ttl) {\n",
            "    raw(bytes=be16(params(\"port\", \"53\")))\n",
            "}\n",
            "a = net(ttl=64)\n",
            "use(a) |> raw(hex(\"00\"))\n",
        ));
        assert!(msgs.is_empty(), "{msgs:?}");
    }

    #[test]
    fn value_func_body_checked() {
        let msgs = check_src("func g() -> bytes { be16(\"x\") }\n");
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(msgs[0].contains("需要整数"), "{msgs:?}");
    }

    #[test]
    fn proto_field_literal_range() {
        let msgs = check_src("#[proto]\nfunc p(x) -> bytes { concat(u8(x), u8(300)) }\n");
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(msgs[0].contains("参数超出范围 0..=255：300"), "{msgs:?}");
    }

    #[test]
    fn proto_field_bits_overflow() {
        let msgs = check_src(concat!(
            "#[proto]\n",
            "func q() -> bytes { concat(#[meta(bits=4)] u8(4), #[meta(bits=4)] u8(200)) }\n",
        ));
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(msgs[0].contains("超出 4 位（0..=15）"), "{msgs:?}");
    }

    #[test]
    fn proto_field_mac_width() {
        let msgs = check_src("#[proto]\nfunc m() -> bytes { concat(mac([1, 2, 3])) }\n");
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(
            msgs[0].contains("mac 需要 6 字节，得到 3 字节列表"),
            "{msgs:?}"
        );
    }

    #[test]
    fn std_addr_width_checks() {
        // mac(ip4(...))：ip4 产 4 字节 → mac 需要 6 字节（真实笔误类）
        let msgs = check_src("a = raw(bytes=mac(ip4(\"1.2.3.4\")))\n");
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(msgs[0].contains("模板输出 6 字节，实际 4 字节"), "{msgs:?}");
        // 整数进地址值函数（求值期走 tpl 输入类型错误）
        let msgs = check_src("a = raw(bytes=concat(ip4(300)))\n");
        assert!(
            msgs.iter()
                .any(|m| m.contains("输入参数需要字符串或字节列表")),
            "{msgs:?}"
        );
        // 字符串是正常路径
        assert!(check_src("a = raw(bytes=concat(ip4(\"1.2.3.4\")))\n").is_empty());
    }

    #[test]
    fn tpl_input_int() {
        let msgs = check_src("a = raw(bytes=tpl(\"%c\", 300))\n");
        assert!(
            msgs.iter()
                .any(|m| m.contains("输入参数需要字符串或字节列表")),
            "{msgs:?}"
        );
    }
}
