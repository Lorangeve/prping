//! chumsky 解析器：token 流 → AST。
//!
//! 语法要点：
//! - 语句按换行分隔；流水线内允许换行（续行以 `|>` 开头）。
//! - 流水线层包裹只支持 `|>`（`||>` 或分支已移除，多包用多条流水线）。
//! - 值：字符串 / 整数 / 十六进制（`0x..`）/ 列表（`[...]`）。
//! - 错误带 span（行/列）：解析器输入是 `Tok`，位置表（`Vec<Token>`）放在 parser state 中，
//!   由 `map_with` 把 token 下标区间换算成行/列。
//!
//! 注意：chumsky 1.0.0-alpha.8 中 `(A, B)` 元组语法 + `map_with` 存在类型推断缺陷，
//! 一律使用显式 `.then()` 链。

use std::fmt;

use chumsky::error::RichReason;
use chumsky::input::{MapExtra, Stream};
use chumsky::inspector::SimpleState;
use chumsky::prelude::*;
use chumsky::span::SimpleSpan;

use crate::ast;
use crate::ast::*;
use crate::diag::{Diagnostic, PktResult};
use crate::lexer::{Tok, Token, span_from_tokens};

/// 解析器使用的 span：token 下标区间。
pub type SpanT = SimpleSpan<usize>;
/// 解析器 extra：Rich 错误 + token 位置表（state，供 span 换算）。
pub type Extra<'a> = chumsky::extra::Full<Rich<'a, Tok, SpanT>, SimpleState<Vec<Token>>, ()>;
/// 解析器输入：token 流。
pub type ParserInput = Stream<std::vec::IntoIter<Tok>>;

impl fmt::Display for Tok {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tok::Ident(s) => write!(f, "标识符 `{s}`"),
            Tok::Str(s) => write!(f, "字符串 `{s}`"),
            Tok::Int(i) => write!(f, "整数 `{i}`"),
            Tok::Hex(h) => write!(f, "十六进制 `0x{h:X}`"),
            Tok::PipeGt => write!(f, "`|>`"),
            Tok::PipePipeGt => write!(f, "`||>`"),
            Tok::LParen => write!(f, "`(`"),
            Tok::RParen => write!(f, "`)`"),
            Tok::LBrace => write!(f, "`{{`"),
            Tok::RBrace => write!(f, "`}}`"),
            Tok::LBracket => write!(f, "`[`"),
            Tok::RBracket => write!(f, "`]`"),
            Tok::Comma => write!(f, "`,`"),
            Tok::Colon => write!(f, "`:`"),
            Tok::Dash => write!(f, "`-`"),
            Tok::Arrow => write!(f, "`->`"),
            Tok::Plus => write!(f, "`+`"),
            Tok::Equals => write!(f, "`=`"),
            Tok::Hash => write!(f, "`#`"),
            Tok::At => write!(f, "`@`"),
            Tok::Newline => write!(f, "换行"),
        }
    }
}

/// 把 chumsky 的 token 下标 span 换算成行/列 span。
fn conv<'src>(extra: &mut MapExtra<'src, '_, ParserInput, Extra<'src>>) -> Span {
    let s = extra.span();
    let toks = &**extra.state();
    span_from_tokens(toks, s.start(), s.end())
}

/// 标识符（带自身 span）。
fn ident<'src>() -> impl Parser<'src, ParserInput, (String, Span), Extra<'src>> + Clone {
    any::<ParserInput, Extra<'src>>()
        .filter(|t: &Tok| matches!(t, Tok::Ident(_)))
        .map_with(|t, e| {
            let Tok::Ident(s) = t else {
                unreachable!("filter 已保证为 Ident")
            };
            (s, conv(e))
        })
}

/// 关键字匹配（不消费以外的 token）。
fn kw<'src>(s: &'static str) -> impl Parser<'src, ParserInput, Tok, Extra<'src>> + Clone {
    any::<ParserInput, Extra<'src>>().filter(move |t: &Tok| matches!(t, Tok::Ident(i) if i == s))
}

/// 换行 token。
fn newline<'src>() -> impl Parser<'src, ParserInput, (), Extra<'src>> + Clone {
    just(Tok::Newline).ignored()
}

/// 零个或多个换行。
fn nl0<'src>() -> impl Parser<'src, ParserInput, (), Extra<'src>> + Clone {
    newline().repeated().ignored()
}

/// 一个或多个换行。
fn nl1<'src>() -> impl Parser<'src, ParserInput, (), Extra<'src>> + Clone {
    newline().repeated().at_least(1).ignored()
}

/// 逗号分隔符：容忍前后换行（多行调用 / 列表 / use）。
fn comma_nl<'src>() -> impl Parser<'src, ParserInput, Tok, Extra<'src>> + Clone {
    nl0().ignore_then(just(Tok::Comma)).then_ignore(nl0())
}

/// 值表达式解析器（与 `parser()` 内 `value` 同一实现，抽出供
/// [`parse_value_expr`] 独立解析配方 `from:` 表达式等单值输入）。
/// 注意：`impl Parser` 返回类型下方法解析不再走具体类型的自动引用捕获，
/// 内部所有共享解析器一律显式 `.clone()`（chumsky 组合子均为 Clone）。
fn value_parser<'src>() -> impl Parser<'src, ParserInput, Value, Extra<'src>> + Clone {
    let ident = ident();
    let kw = kw;
    let nl0 = nl0();
    let comma_nl = comma_nl();
    recursive::<ParserInput, Value, Extra<'src>, _, _>(|value| {
        let str_ = any::<ParserInput, Extra<'src>>()
            .filter(|t: &Tok| matches!(t, Tok::Str(_)))
            .map_with(|t, _| match t {
                Tok::Str(s) => Value::Str(s),
                _ => unreachable!("filter 已保证为 Str"),
            });
        let int_ = any::<ParserInput, Extra<'src>>()
            .filter(|t: &Tok| matches!(t, Tok::Int(_)))
            .map_with(|t, _| match t {
                Tok::Int(i) => Value::Int(i),
                _ => unreachable!("filter 已保证为 Int"),
            });
        let hex_ = any::<ParserInput, Extra<'src>>()
            .filter(|t: &Tok| matches!(t, Tok::Hex(_)))
            .map_with(|t, _| match t {
                Tok::Hex(h) => Value::Hex(h),
                _ => unreachable!("filter 已保证为 Hex"),
            });
        let list_ = value
            .clone()
            .separated_by(comma_nl.clone())
            .allow_trailing()
            .collect::<Vec<_>>()
            .map(Value::List)
            .delimited_by(
                just(Tok::LBracket).then_ignore(nl0.clone()),
                nl0.clone().ignore_then(just(Tok::RBracket)),
            );
        // 运行时参数引用：`params("name"[, "默认值"])`
        let str_tok = any::<ParserInput, Extra<'src>>()
            .filter(|t: &Tok| matches!(t, Tok::Str(_)))
            .map_with(|t, _| match t {
                Tok::Str(s) => s,
                _ => unreachable!("filter 已保证为 Str"),
            });
        let params_call = kw("params")
            .then(just(Tok::LParen))
            .then_ignore(nl0.clone())
            .ignore_then(str_tok)
            .then(comma_nl.clone().ignore_then(value.clone()).or_not())
            .then_ignore(nl0.clone())
            .then_ignore(just(Tok::RParen))
            .map_with(|(name, default), _| Value::Param {
                name,
                default: default.map(Box::new),
            });
        // 值位置 hex 调用：`hex("deadbeef")` / `hex("0x4242")` → 字节列表值（底层数据
        // 构建，如 `eth_frame(payload=hex("..."))`）；与层位置 `hex(...)`（Raw 载荷层）
        // 并存。合法输入解析期产出字节列表（`raw(bytes=hex(...))` 等直接消费方依赖）；
        // 非法/奇数长度 → 解析为 `hex` 调用标记，由求值/`val_bytes` 统一校验报错
        // （不能在这里直接报解析错误：choice 会回溯到通用 value_call，吞掉诊断）。
        let hex_call = kw("hex")
            .then(just(Tok::LParen))
            .then_ignore(nl0.clone())
            .ignore_then(str_tok)
            .then_ignore(nl0.clone())
            .then_ignore(just(Tok::RParen))
            .map_with(|s, e| {
                let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
                let hex = cleaned
                    .strip_prefix("0x")
                    .or_else(|| cleaned.strip_prefix("0X"))
                    .unwrap_or(&cleaned);
                let ok = hex.len().is_multiple_of(2) && hex.chars().all(|c| c.is_ascii_hexdigit());
                if !ok {
                    let sp = conv(e);
                    return Value::Call {
                        name: "hex".to_string(),
                        name_span: sp,
                        args: vec![Value::Str(s)],
                        span: sp,
                    };
                }
                let bytes: Vec<Value> = (0..hex.len())
                    .step_by(2)
                    .map(|i| {
                        Value::Int(
                            u8::from_str_radix(&hex[i..i + 2], 16).expect("已校验 hex") as i64
                        )
                    })
                    .collect();
                Value::List(bytes)
            });
        // 函数参数引用：`dst=dst` 右侧的裸标识符（须在 `params(...)` 之后尝试，避免抢占）
        let ident_value = ident
            .clone()
            .map_with(|(name, span), _| Value::Ident { name, span });
        // 通用值调用：`concat(...)` / `be16(...)` / 用户值函数
        let value_call = ident
            .clone()
            .then(
                just(Tok::LParen)
                    .ignore_then(nl0.clone())
                    .ignore_then(
                        value
                            .clone()
                            .separated_by(comma_nl.clone())
                            .allow_trailing()
                            .collect::<Vec<_>>(),
                    )
                    .then_ignore(nl0.clone())
                    .then_ignore(just(Tok::RParen)),
            )
            .map_with(|((name, name_span), args), e| Value::Call {
                name,
                name_span,
                args,
                span: conv(e),
            });
        let atom = choice((
            str_,
            int_,
            hex_,
            list_,
            params_call,
            hex_call,
            value_call,
            ident_value,
        ));
        // 数字加法：`20 + len(payload)`（左结合）；操作数都是 atom 或 `+` 链，无括号
        // 分组语法——列表/调用括号内可再含 `+`（如 concat(u8(1 + 1))）。
        // 比较/逻辑运算符已随 lambda/map/filter 移除，`+` 是唯一运算符。
        let add = atom
            .clone()
            .then(
                just(Tok::Plus)
                    .ignore_then(atom.clone())
                    .repeated()
                    .collect::<Vec<_>>(),
            )
            .map_with(|(first, rest), e| {
                rest.into_iter().fold(first, |acc, r| Value::BinOp {
                    op: BinOp::Add,
                    left: Box::new(acc),
                    right: Box::new(r),
                    span: conv(e),
                })
            });
        add.boxed()
    })
}

pub fn parser<'src>() -> impl Parser<'src, ParserInput, AstFile, Extra<'src>> {
    // 注意：先取 value_parser()（内部自带 ident/kw/nl0/comma_nl 副本），再绑定本
    // 函数作用域的 ident/kw/... ——否则后者会遮蔽函数名（RHS 解析到前者）。
    // 所有共享解析器后续使用一律 `.clone()`（impl Parser 返回类型下方法解析
    // 不再自动引用捕获，显式克隆等价且安全）。
    let value = value_parser();
    let ident = ident();
    let kw = kw;
    let nl0 = nl0();
    let nl1 = nl1();
    let comma_nl = comma_nl();

    // 参数：`IDENT = value`（命名）或 `value`（位置参数）
    let named_arg = ident
        .clone()
        .then(just(Tok::Equals).ignore_then(value.clone()))
        .map_with(|((name, name_span), v), e| Arg {
            name: Some((name, name_span)),
            value: v,
            span: conv(e),
        });
    let positional_arg = value.clone().map_with(|v, e| Arg {
        name: None,
        value: v,
        span: conv(e),
    });
    let arg = choice((named_arg, positional_arg));
    let arg_list = arg
        .separated_by(comma_nl.clone())
        .allow_trailing()
        .collect::<Vec<_>>();

    // 层函数调用：`name(args)`；容忍无参裸调用 `tcp`（等价于 `tcp()`，见设计 §4.2 示例）
    let call = ident
        .clone()
        .then(
            just(Tok::LParen)
                .ignore_then(nl0.clone())
                .ignore_then(arg_list.clone())
                .then_ignore(nl0.clone())
                .then_ignore(just(Tok::RParen))
                .or_not(),
        )
        .map_with(|((name, name_span), args), e| Call {
            name,
            name_span,
            args: args.unwrap_or_default(),
            span: conv(e),
        });

    // 层包裹：nl0 |> call（原 `||>` 或分支已移除，多包用多条流水线）
    let layer = nl0
        .clone()
        .then(just(Tok::PipeGt).ignore_then(call.clone()))
        .map_with(|(_, c), _| c);

    // 标识符列表：`a, b, c`
    let ident_list = ident
        .clone()
        .separated_by(comma_nl.clone())
        .allow_trailing()
        .at_least(1)
        .collect::<Vec<_>>();

    // import 括号列表：`a, x as ax, c`（`as` 别名可省略）→ (原名, 别名, span)
    let import_ident_list = ident
        .clone()
        .then(kw("as").ignore_then(ident.clone()).or_not())
        .map_with(|((name, name_span), alias), _| (name, alias.map(|(a, _)| a), name_span))
        .separated_by(comma_nl.clone())
        .allow_trailing()
        .at_least(1)
        .collect::<Vec<_>>();

    // `use(a, b)` 引入段（可独立用于函数体）
    let use_part = kw("use")
        .then(just(Tok::LParen))
        .then(ident_list.clone())
        .then(just(Tok::RParen))
        .map_with(|(((_, _), use_names), _), _| use_names);

    // 流水线：`use(a, b) |> ... |> ...`
    let layer_seq = layer.repeated().collect::<Vec<_>>();
    let pipeline = use_part
        .clone()
        .then(layer_seq.clone())
        .map_with(|(use_names, layers), e| Pipeline {
            use_names,
            layers,
            span: conv(e),
        });

    // 函数体：`use(...)` 可选（无 use 时视为层片段，首个调用裸写，后续 `|>` 包裹）
    let func_body_with_use =
        use_part
            .clone()
            .then(layer_seq.clone())
            .map_with(|(use_names, layers), e| Pipeline {
                use_names,
                layers,
                span: conv(e),
            });
    let func_body_bare = call
        .clone()
        .then(layer_seq.clone())
        .map(|(c, rest)| {
            let mut v = vec![c];
            v.extend(rest);
            v
        })
        .map_with(|layers, e| Pipeline {
            use_names: Vec::new(),
            layers,
            span: conv(e),
        });
    let func_body = choice((func_body_with_use, func_body_bare));

    // 表达式：流水线或单层调用
    let expr = choice((
        pipeline.clone().map(Expr::Pipeline),
        call.clone().map(Expr::Call),
    ));

    // export 块：`export:` 后跟 `- IDENT` 列表（容忍 `-c` 无空格写法）
    let export_block = kw("export")
        .then(just(Tok::Colon))
        .then(nl0.clone())
        .ignore_then(
            (just(Tok::Dash).ignore_then(ident.clone()))
                .separated_by(nl1.clone().or_not())
                .allow_trailing()
                .at_least(1)
                .collect::<Vec<_>>(),
        )
        .map_with(|names, e| ExportStmt {
            names,
            span: conv(e),
        });

    // import：`import a { a, b }`（括号列表支持 `x as ax` 别名）
    let import_stmt = kw("import")
        .then(ident.clone())
        .then(
            just(Tok::LBrace)
                .ignore_then(import_ident_list.clone())
                .then_ignore(just(Tok::RBrace))
                .or_not(),
        )
        .map_with(|((_, (module, _)), names), e| ImportStmt {
            module,
            names,
            span: conv(e),
        });

    // 定义：`IDENT = expr`（expr 可以是流水线或单层调用）
    let def_stmt = ident
        .clone()
        .then(just(Tok::Equals).ignore_then(expr.clone()))
        .map_with(|((name, name_span), e), extra| DefStmt {
            name,
            name_span,
            span: conv(extra),
            expr: e,
        });

    // ── sniffer 段：`sniffer:` + `- match 层(条件, ...)`（顶层列表 = 隐式 OR）──
    // 条件项：`字段=值`（Ident → 发包同层同名字段引用）/ `ne(字段, 值)` /
    // `mask(0xc0)` / `startswith("...")` / `endswith("...")` / `contains("...")`；
    // 谓词组合：`and(...)` / `or(...)` / `not(...)`（与 `#[rule]` 同构）。
    let field_item = ident
        .clone()
        .then(
            just(Tok::Equals)
                .then_ignore(nl0.clone())
                .ignore_then(value.clone()),
        )
        .map_with(|((name, _), v), _| {
            let val = match v {
                Value::Ident { name: f, .. } => SnifferValue::SentField(f),
                // 字面量按字段类型强转（常量比较）；其余（原语/值函数调用、
                // params、数字加法、字节列表）是值表达式 → 求值为字节后
                // 与回包字段字节比较（与「值函数最终算出字节」一致）
                Value::Str(_) | Value::Int(_) | Value::Hex(_) => SnifferValue::Literal(v),
                other => SnifferValue::Expr(other),
            };
            SnifferItem::FieldEq { name, val }
        });
    let ne_item = kw("ne")
        .then_ignore(nl0.clone())
        .ignore_then(
            just(Tok::LParen)
                .then_ignore(nl0.clone())
                .ignore_then(ident.clone())
                .then(
                    just(Tok::Comma)
                        .then_ignore(nl0.clone())
                        .ignore_then(value.clone()),
                )
                .then_ignore(nl0.clone())
                .then_ignore(just(Tok::RParen)),
        )
        .map_with(|((name, _), v), _| {
            let val = match v {
                Value::Ident { name: f, .. } => SnifferValue::SentField(f),
                Value::Str(_) | Value::Int(_) | Value::Hex(_) => SnifferValue::Literal(v),
                other => SnifferValue::Expr(other),
            };
            SnifferItem::FieldNe { name, val }
        });
    let mask_item = kw("mask")
        .then_ignore(nl0.clone())
        .ignore_then(
            just(Tok::LParen)
                .then_ignore(nl0.clone())
                .ignore_then(value.clone())
                .then_ignore(nl0.clone())
                .then_ignore(just(Tok::RParen)),
        )
        .map_with(|v, _| SnifferItem::Mask(v));
    // 字节模式：`startswith/endswith/contains("...")`（字符串参数）
    let str_tok = any::<ParserInput, Extra<'src>>()
        .filter(|t: &Tok| matches!(t, Tok::Str(_)))
        .map_with(|t, _| match t {
            Tok::Str(s) => s,
            _ => unreachable!("filter 已保证为 Str"),
        });
    let pat_item = |kw_name: &'static str| {
        kw(kw_name).then_ignore(nl0.clone()).ignore_then(
            just(Tok::LParen)
                .then_ignore(nl0.clone())
                .ignore_then(str_tok)
                .then_ignore(nl0.clone())
                .then_ignore(just(Tok::RParen)),
        )
    };
    let startswith_item = pat_item("startswith").map(SnifferItem::StartsWith);
    let endswith_item = pat_item("endswith").map(SnifferItem::EndsWith);
    let contains_item = pat_item("contains").map(SnifferItem::Contains);
    let sniffer_items = choice((
        ne_item,
        mask_item,
        startswith_item,
        endswith_item,
        contains_item,
        field_item,
    ))
    .separated_by(comma_nl.clone())
    .allow_trailing()
    .collect::<Vec<_>>();
    // 单个匹配子句：`match 层(条件, ...)`
    let sniffer_clause = kw("match")
        .then_ignore(nl0.clone())
        .ignore_then(ident.clone())
        .then(
            just(Tok::LParen)
                .then_ignore(nl0.clone())
                .ignore_then(sniffer_items)
                .then_ignore(nl0.clone())
                .then_ignore(just(Tok::RParen)),
        )
        .map_with(|((layer, _), items), e| {
            SnifferPred::Clause(SnifferClause {
                layer,
                items,
                span: conv(e),
            })
        });
    // 谓词：match 子句 / and / or / not（递归）
    let sniffer_pred = recursive::<ParserInput, SnifferPred, Extra<'src>, _, _>(|pred| {
        let and_pred = kw("and")
            .then_ignore(nl0.clone())
            .ignore_then(
                just(Tok::LParen)
                    .then_ignore(nl0.clone())
                    .ignore_then(
                        pred.clone()
                            .separated_by(comma_nl.clone())
                            .allow_trailing()
                            .collect::<Vec<_>>(),
                    )
                    .then_ignore(nl0.clone())
                    .then_ignore(just(Tok::RParen)),
            )
            .map_with(|v, _| SnifferPred::And(v));
        let or_pred = kw("or")
            .then_ignore(nl0.clone())
            .ignore_then(
                just(Tok::LParen)
                    .then_ignore(nl0.clone())
                    .ignore_then(
                        pred.clone()
                            .separated_by(comma_nl.clone())
                            .allow_trailing()
                            .collect::<Vec<_>>(),
                    )
                    .then_ignore(nl0.clone())
                    .then_ignore(just(Tok::RParen)),
            )
            .map_with(|v, _| SnifferPred::Or(v));
        let not_pred = kw("not")
            .then_ignore(nl0.clone())
            .ignore_then(
                just(Tok::LParen)
                    .then_ignore(nl0.clone())
                    .ignore_then(pred.clone())
                    .then_ignore(nl0.clone())
                    .then_ignore(just(Tok::RParen)),
            )
            .map_with(|p, _| SnifferPred::Not(Box::new(p)));
        choice((sniffer_clause.clone(), and_pred, or_pred, not_pred))
    });
    // sniffer 块：`sniffer:` 后跟 `- 谓词` 列表（与 export: 同风格；顶层隐式 OR）
    let sniffer_stmt = kw("sniffer")
        .then(just(Tok::Colon))
        .then_ignore(nl0.clone())
        .ignore_then(
            (just(Tok::Dash)
                .ignore_then(nl0.clone())
                .ignore_then(sniffer_pred))
            .separated_by(nl1.clone().or_not())
            .allow_trailing()
            .at_least(1)
            .collect::<Vec<_>>(),
        )
        .map_with(|clauses, e| SnifferSpec {
            clauses,
            span: conv(e),
        });

    // 函数参数：`IDENT`（未设）或 `IDENT = 默认值`
    let func_param = ident
        .clone()
        .then(just(Tok::Equals).ignore_then(value.clone()).or_not())
        .map_with(|((name, span), default), _| FuncParam {
            name,
            span,
            default,
        });
    let func_param_list = func_param
        .separated_by(comma_nl.clone())
        .allow_trailing()
        .collect::<Vec<_>>();

    // 函数：`func name(p1, p2=默认) { pipeline }`
    // （先扁平化头部为三元组，避免 chumsky 对深层嵌套元组的推断缺陷）
    let func_head = kw("func")
        .then_ignore(nl0.clone())
        .ignore_then(ident.clone())
        .then(
            just(Tok::LParen)
                .ignore_then(nl0.clone())
                .ignore_then(func_param_list.clone())
                .then_ignore(nl0.clone())
                .then_ignore(just(Tok::RParen)),
        )
        .map(|((name, name_span), params)| (name, name_span, params));

    // ── 统一注解语法：`#[注解( key=value, ... )]`（flag 无值；裸值为旧形式）。
    //    所有注解（proto/rule/meta 及旧名 bind/feature/layer）同一语法，语义阶段按名解释。
    // 参数项：`key = value` / `fn(args)`（rule 的 `udp(dport=443)`，参数复用本生产）/
    // 裸值（meta 的 `auto`/`rest` flag、旧位置形式）——解释时按注解名区分
    let attr_arg = recursive::<ParserInput, AttrArg, Extra<'src>, _, _>(|attr_arg| {
        choice((
            // `key = value`
            ident
                .clone()
                .then(
                    just(Tok::Equals)
                        .then_ignore(nl0.clone())
                        .ignore_then(value.clone()),
                )
                .map_with(|((key, _), v), e| AttrArg::Kv {
                    key,
                    value: v,
                    span: conv(e),
                }),
            // `fn(args)`：rule 的 `udp(dport=443)` / `bytes(0xc0)`
            ident
                .clone()
                .then(
                    just(Tok::LParen)
                        .then_ignore(nl0.clone())
                        .ignore_then(
                            attr_arg
                                .clone()
                                .separated_by(comma_nl.clone())
                                .allow_trailing()
                                .collect::<Vec<_>>(),
                        )
                        .then_ignore(nl0.clone())
                        .then_ignore(just(Tok::RParen)),
                )
                .map_with(|((name, _), args), e| AttrArg::Call {
                    name,
                    args,
                    span: conv(e),
                }),
            // 裸值（meta flag / 旧位置形式）
            value.clone().map_with(|v, e| AttrArg::Bare {
                value: v,
                span: conv(e),
            }),
        ))
        .boxed()
    });
    let attr_args = attr_arg
        .clone()
        .separated_by(comma_nl.clone())
        .allow_trailing()
        .collect::<Vec<_>>();
    let attr = just(Tok::Hash)
        .then_ignore(just(Tok::LBracket))
        .then_ignore(nl0.clone())
        .ignore_then(ident.clone())
        .then(
            just(Tok::LParen)
                .then_ignore(nl0.clone())
                .ignore_then(attr_args)
                .then_ignore(nl0.clone())
                .then_ignore(just(Tok::RParen))
                .or_not(),
        )
        .then_ignore(nl0.clone())
        .then_ignore(just(Tok::RBracket))
        .map_with(|((name, _), args), e| Attr {
            name,
            args: args.unwrap_or_default(),
            span: conv(e),
        });
    // 注解可多行，每行注解后容忍换行
    let attr_line = attr.then_ignore(nl0.clone());

    // ── `#[proto] func` 的 body：扁平 `concat(...)`（可带 `#[meta(...)]` 标注）──
    // 该 body 形态也兼容普通 `layer(kind, bytes)` 层片段（无注解时按普通函数求值）。
    // concat 参数前缀注解：`#[meta(...)]`（统一语法，一个参数可多个标注，项合并）；
    // 其它 `#[...]` 注解（旧调用形式 / `#[layer]` 等）也能解析，在降糖时给出明确报错
    let proto_func_arg = attr_line
        .clone()
        .repeated()
        .collect::<Vec<_>>()
        .then(value.clone())
        .map_with(|(attrs, v), e| ProtoFuncArg {
            attrs,
            value: v,
            span: conv(e),
        });

    let proto_func_args = proto_func_arg
        .separated_by(comma_nl.clone())
        .allow_trailing()
        .collect::<Vec<_>>();
    let proto_concat_body = kw("concat")
        .then_ignore(nl0.clone())
        .then_ignore(just(Tok::LParen))
        .then_ignore(nl0.clone())
        .ignore_then(proto_func_args.clone())
        .then_ignore(nl0.clone())
        .then_ignore(just(Tok::RParen));
    let proto_concat = proto_concat_body.clone().map(|args| ProtoFuncBody { args });
    // body 只有扁平 `concat(...)`；`layer("kind", concat(...))` 形态已移除
    // （层身份一律用 `#[proto(kind=...)]` 注解，避免同一信息两种写法）。
    let proto_func_body_call = proto_concat;
    // proto body：`-> bytes { concat(...) }`——`-> bytes` 必填（proto = 值函数 +
    // 字段标注，返回类型标注声明值函数本性；缺省走层/值函数 body，降糖阶段报迁移错）
    let proto_func_body = just(Tok::Arrow)
        .then_ignore(nl0.clone())
        .ignore_then(kw("bytes"))
        .then_ignore(nl0.clone())
        .ignore_then(just(Tok::LBrace))
        .then_ignore(nl0.clone())
        .ignore_then(proto_func_body_call)
        .then_ignore(nl0.clone())
        .then_ignore(just(Tok::RBrace));
    // 函数体：值函数 `-> bytes`/`-> int` { 值表达式 } 或层函数 `{ 流水线 }`
    let value_func_body = just(Tok::Arrow)
        .then_ignore(nl0.clone())
        .ignore_then(choice((
            kw("bytes").map(|_| ValueRet::Bytes),
            kw("int").map(|_| ValueRet::Int),
        )))
        .then_ignore(nl0.clone())
        .then_ignore(just(Tok::LBrace))
        .then_ignore(nl0.clone())
        .then(value.clone())
        .then_ignore(nl0.clone())
        .then_ignore(just(Tok::RBrace))
        .map_with(|(ret, v), e| {
            (
                Some((ret, v)),
                Pipeline {
                    use_names: Vec::new(),
                    layers: Vec::new(),
                    span: conv(e),
                },
            )
        });
    let layer_func_body = just(Tok::LBrace)
        .then_ignore(nl0.clone())
        .ignore_then(func_body)
        .then_ignore(nl0.clone())
        .then_ignore(just(Tok::RBrace))
        .map(|b| (None, b));
    // 普通函数（无注解）：`func name(...) { pipeline }` / `-> bytes { expr }`
    let func_stmt = func_head
        .clone()
        .then_ignore(nl0.clone())
        .then(choice((value_func_body.clone(), layer_func_body.clone())))
        .map_with(
            |((name, name_span, params), (value_body, body)), e| FuncStmt {
                name,
                name_span,
                params,
                body: Box::new(body),
                value_body,
                attrs: Vec::new(),
                proto_body: None,
                schema: None,
                span: conv(e),
                doc: None,
            },
        );
    // `#[proto] func`（带注解的函数）：body 三选一（proto 形态优先，降糖在
    // `desugar_proto_funcs` 校验/翻译）；无 `#[proto]` 的注解函数在此解析、
    // 在降糖阶段报「注解需要 #[proto]」
    let proto_func_stmt = attr_line
        .clone()
        .repeated()
        .at_least(1)
        .collect::<Vec<_>>()
        .then(func_head.clone())
        .then_ignore(nl0.clone())
        .then(choice((
            proto_func_body.map_with(|b, e| {
                (
                    None::<(ValueRet, Value)>,
                    Pipeline {
                        use_names: Vec::new(),
                        layers: Vec::new(),
                        span: conv(e),
                    },
                    Some(Box::new(b)),
                )
            }),
            value_func_body.clone().map(|(vb, b)| (vb, b, None)),
            layer_func_body.clone().map(|(vb, b)| (vb, b, None)),
        )))
        .map_with(
            |((attrs, (name, name_span, params)), (value_body, body, proto_body)), e| FuncStmt {
                name,
                name_span,
                params,
                body: Box::new(body),
                value_body,
                attrs,
                proto_body,
                schema: None,
                span: conv(e),
                doc: None,
            },
        );

    // 顶层匿名流水线（默认导出）
    let pipeline_stmt = pipeline.clone().map_with(|p, e| PipelineStmt {
        span: conv(e),
        pipeline: p,
    });

    let stmt = choice((
        export_block.map(Stmt::Export),
        import_stmt.map(Stmt::Import),
        proto_func_stmt.map(Stmt::Func),
        func_stmt.map(Stmt::Func),
        sniffer_stmt.map(Stmt::Sniffer),
        def_stmt.map(Stmt::Def),
        pipeline_stmt.map(Stmt::Pipeline),
    ));

    nl0.clone()
        .ignore_then(stmt)
        .repeated()
        .collect::<Vec<_>>()
        .then_ignore(nl0)
        .then_ignore(end::<ParserInput, Extra<'src>>())
        .map(|stmts| AstFile { stmts })
}

/// 解析入口：`src` → AST（词法 + 语法错误合并为 [`Diagnostic`]）。
pub fn parse_ast(src: &str) -> crate::diag::PktResult<AstFile> {
    let (tokens, lex_errors) = crate::lexer::lex(src);
    if let Some(e) = lex_errors.first() {
        return Err(crate::diag::Diagnostic {
            message: e.message.clone(),
            file: None,
            span: Some(crate::diag::SourceSpan::from_ast(e.span, e.offset, 1)),
            kind: crate::diag::DiagnosticKind::General,
        });
    }
    // 旧 `proto 关键字` 语法的迁移诊断：语句起始的裸 `proto IDENT {`（proto 已不再是
    // 关键字——是普通标识符），给出明确的改写指引
    if let Some((_, tok)) = tokens.iter().enumerate().find(|(i, t)| {
        let i = *i;
        matches!(&t.tok, Tok::Ident(s) if s == "proto")
            && (i == 0 || matches!(tokens.get(i - 1).map(|p| &p.tok), Some(Tok::Newline)))
            && matches!(tokens.get(i + 1).map(|p| &p.tok), Some(Tok::Ident(_)))
    }) {
        return Err(crate::diag::Diagnostic {
            message: "`proto` 关键字语法已移除：请改用 `#[proto] func name(params) { concat(...) }`（字段 = concat 参数，可带 `#[meta]` 标注，如 `#[meta(auto)] be16(checksum)`；`#[proto(\"族\")]` 带协议族标签）"
                .to_string(),
            file: None,
            span: Some(crate::diag::SourceSpan::from_ast(
                crate::ast::Span {
                    start: crate::ast::Pos {
                        line: tok.line,
                        col: tok.col,
                    },
                    end: crate::ast::Pos {
                        line: tok.line,
                        col: tok.col + tok.len,
                    },
                },
                tok.offset,
                tok.len,
            )),
            kind: crate::diag::DiagnosticKind::General,
        });
    }
    let mut state = SimpleState(tokens.clone());
    let input = tokens.iter().map(|t| t.tok.clone()).collect::<Vec<_>>();
    let result = parser().parse_with_state(Stream::from_iter(input), &mut state);
    let result = render_parse_err(&tokens, result.into_result())?;
    let mut ast = result.map_err(|_| crate::diag::Diagnostic::new("解析失败：未知错误"))?;
    desugar_proto_funcs(&mut ast)?;
    attach_doc_comments(&mut ast, src);
    Ok(ast)
}

// ── `#[proto] func` 降糖（解析后立即执行，下游只见 FuncStmt + schema）───────

/// 把带注解的函数统一为 proto 声明：
///
/// - `#[proto] func name(params) -> bytes { concat(...) }`（`-> bytes` 必填）：
///   body 的 concat 参数 = 字段（`#[meta(...)]` 标注 auto/name/len/bytes/rest），
///   降糖为 `FuncStmt.schema` 字段表；函数参数 → proto 值参数，
///   `#[proto(kind="eth")]` → 层类型。proto = 值函数 + 字段标注（可逆 schema）。
/// - 带注解但无 `#[proto]` 的函数 → 报错（注解只用于 `#[proto]` 函数）。
fn desugar_proto_funcs(ast: &mut AstFile) -> PktResult<()> {
    let mut out = Vec::with_capacity(ast.stmts.len());
    for stmt in std::mem::take(&mut ast.stmts) {
        match stmt {
            Stmt::Func(f) if f.attrs.iter().any(|a| a.name == "proto") => {
                out.push(Stmt::Func(desugar_proto_func(f)?));
            }
            Stmt::Func(f) if !f.attrs.is_empty() || f.proto_body.is_some() => {
                return Err(Diagnostic::at(
                    format!(
                        "函数 `{}` 的注解需要 `#[proto]`（`#[...]` 只用于 `#[proto]` 函数）",
                        f.name
                    ),
                    f.attrs.first().map(|a| a.span).unwrap_or(f.name_span),
                ));
            }
            other => out.push(other),
        }
    }
    ast.stmts = out;
    Ok(())
}

/// `#[proto] func -> bytes` → `FuncStmt`（校验 body 形态 + 逐参数翻译为 schema 字段表）。
fn desugar_proto_func(mut f: ast::FuncStmt) -> PktResult<ast::FuncStmt> {
    // proto = 值函数 + 字段标注：`-> bytes` 必填（语法层只接受 `-> bytes { concat }`，
    // 缺省（旧语法 `{ concat }` / `-> int`）走层/值函数 body，在此给迁移报错）
    let Some(pb) = f.proto_body.take() else {
        return Err(match &f.value_body {
            // `-> bytes` 已声明但 body 不是扁平 concat（如 `layer("kind", ...)` 旧形态）
            Some(_) => Diagnostic::at(
                format!(
                    "`#[proto]` 函数 `{}` 的函数体必须是扁平 `concat(...)`（`-> bytes` 已声明；concat 参数 = 字段，可带 `#[meta]` 标注；body 的 `layer(\"kind\", ...)` 形态已移除，层身份用 `#[proto(kind=...)]` 注解）",
                    f.name
                ),
                f.name_span,
            ),
            // 旧语法（无 `-> bytes`）或 `-> int`
            None => Diagnostic::at(
                format!(
                    "`#[proto]` 函数 `{}` 需要 `-> bytes` 返回类型标注（proto = 值函数 + 字段标注，如 `#[proto] func eth(...) -> bytes {{ concat(...) }}`；`-> int` 不可逆）",
                    f.name
                ),
                f.name_span,
            ),
        });
    };
    let attrs = normalize_proto_attr(f.attrs, &f.name)?;
    f.attrs = attrs;

    // body 参数（解析时已由 proto_concat_body 收）
    let args = pb.args;
    let param_names: std::collections::HashSet<&str> =
        f.params.iter().map(|p| p.name.as_str()).collect();
    let mut fields = Vec::with_capacity(args.len());
    for (i, arg) in args.into_iter().enumerate() {
        fields.push(desugar_proto_arg(&f.name, arg, i, &param_names)?);
    }
    f.schema = Some(Box::new(ast::ProtoSchema { fields }));
    Ok(f)
}

/// 校验 `#[proto(kind=...)]` 注解并原样返回（层类型由语义阶段读取/校验）：
/// - `#[proto(kind="eth")]` → 保留（kind 值 = IR 层类型，语义校验闭集）；
/// - 裸 `#[proto]` → 保留（无 IR 层 = Raw 层，如 quic_initial / quic_crypto）；
/// - 旧位置形式 `#[proto("eth")]` / `#[proto(eth)]` → 迁移报错；
/// - 重复 `#[proto]` / 未知项 → 报错。
fn normalize_proto_attr(attrs: Vec<ast::Attr>, name: &str) -> PktResult<Vec<ast::Attr>> {
    let mut out = Vec::with_capacity(attrs.len());
    let mut seen = false;
    for a in attrs {
        if a.name == "proto" {
            if seen {
                return Err(Diagnostic::at(
                    format!("`#[proto]` 注解重复（`{name}`）"),
                    a.span,
                ));
            }
            seen = true;
            for arg in &a.args {
                match arg {
                    ast::AttrArg::Kv { key, span, .. } if key == "kind" => {}
                    ast::AttrArg::Kv { key, span, .. } => {
                        return Err(Diagnostic::at(
                            format!("`#[proto]` 未知项 `{key}`（支持 kind）"),
                            *span,
                        ));
                    }
                    ast::AttrArg::Bare { span, .. } => {
                        // 旧位置形式 `#[proto("eth")]` / `#[proto(eth)]`
                        return Err(Diagnostic::at(
                            "`#[proto]` 参数已改为键值对：`#[proto(kind=\"eth\")]`（裸 `#[proto]` = Raw 层）"
                                .to_string(),
                            *span,
                        ));
                    }
                    ast::AttrArg::Call { span, .. } => {
                        return Err(Diagnostic::at(
                            "`#[proto]` 不支持调用形式（层身份用 `#[proto(kind=\"eth\")]`）"
                                .to_string(),
                            *span,
                        ));
                    }
                }
            }
            out.push(a);
        } else {
            out.push(a);
        }
    }
    Ok(out)
}

/// concat 一个参数 → 字段声明（`#[proto] func` 降糖）。
///
/// 参数形态（见 GRAMMAR.md §3 proto_func_arg）：
/// - `u8(tos)` / `be16(id)`（类型化调用 + 标识符）：字段名 = 标识符；签名参数同名 →
///   默认值 = 参数引用（构造用参数值）；非签名参数 → 必填字段（无默认）。
/// - `u8(0x45)` / `be32(0x00000001)`（类型化调用 + 字面量/表达式）：匿名常量字段
///   `f{i}`，默认值 = 字面量/表达式（解析侧按常量校验，如 quic frame_type）。
/// - `#[meta(name="first")] u8(bor(0xc0, pnl))`：显式字段名 + 默认值表达式。
/// - `#[meta(bytes="dcid_len")] dcid` / `#[meta(rest="quic_crypto")] payload`：
///   裸标识符，类型来自 meta（宽度/子 proto 为字符串时按值表达式子解析）。
/// - `#[meta(len="auto")]` / `#[meta(len="dcid")]`：计算长度字段（后续全部 /
///   目标字段字节数，引擎反向填充）。
fn desugar_proto_arg(
    proto_name: &str,
    arg: ast::ProtoFuncArg,
    idx: usize,
    params: &std::collections::HashSet<&str>,
) -> PktResult<ast::FieldDecl> {
    use ast::{FieldType, LenTarget, Value};
    let span = arg.span;
    // ── #[meta(...)] 键值对标注（name / len / bytes / rest / expr / list / bits / codec）──
    let mut len_of: Option<LenTarget> = None;
    let mut len_expr: Option<Value> = None;
    let mut rest_proto: Option<String> = None;
    let mut list_count: Option<Value> = None;
    let mut bits: Option<u8> = None;
    let mut meta_ty: Option<FieldType> = None;
    let mut width: Option<Value> = None;
    let mut name_override: Option<String> = None;
    // vint 方案参数（`#[meta(codec=...)]`；`varint`/`qvarint` 糖走 call 侧）
    let mut codec_name: Option<String> = None;
    let mut prefix_bits: Option<u8> = None;
    let mut widths: Option<Vec<u8>> = None;
    let mut inline_max: Option<u8> = None;
    let mut sentinels: Option<Vec<u8>> = None;
    let mut endian: Option<String> = None;
    for a in &arg.attrs {
        if a.name != "meta" {
            return Err(Diagnostic::at(
                format!(
                    "`#[proto]` 函数 `{proto_name}`：concat 参数前的注解只支持 `#[meta(...)]`（支持项 name / len / bytes / rest / expr / list / item / bits / codec / prefix_bits / widths / inline_max / sentinels / endian；得到 `#[{}]`）",
                    a.name
                ),
                a.span,
            ));
        }
        for item in &a.args {
            match item {
                ast::AttrArg::Kv { key, value, span } => match key.as_str() {
                    "auto" => {
                        // @auto 已并入 len：同一"计算长度"机制的两种目标
                        return Err(Diagnostic::at(
                            format!(
                                "`#[proto]` 函数 `{proto_name}`：`#[meta(auto)]` 已并入 `#[meta(len=\"auto\")]`（@auto/@len 统一为 len 目标，取值 \"auto\" = 后续全部字段字节数）"
                            ),
                            *span,
                        ));
                    }
                    "name" => name_override = Some(meta_name(proto_name, value, *span)?),
                    "len" => {
                        // len 目标：`"auto"` = 后续全部字段字节数（原 @auto）；字段名 = 目标字段字节数（原 @len）
                        let t = meta_name(proto_name, value, *span)?;
                        len_of = Some(if t == "auto" {
                            LenTarget::Auto
                        } else {
                            LenTarget::Field(t)
                        });
                    }
                    "expr" => len_expr = Some(meta_expr(proto_name, value, *span)?),
                    "bytes" => {
                        meta_ty = Some(FieldType::Bytes);
                        width = Some(meta_width(proto_name, value, *span)?);
                    }
                    "rest" => {
                        meta_ty = Some(FieldType::Rest);
                        rest_proto = Some(meta_name(proto_name, value, *span)?);
                    }
                    "list" => {
                        meta_ty = Some(FieldType::Rest);
                        list_count = Some(meta_width(proto_name, value, *span)?);
                    }
                    "item" => {
                        // list 元素子 proto（须配合 `#[meta(list="计数", ...)]`）；
                        // 重复到失败的哨兵形态已并入 rest(子proto)
                        rest_proto = Some(meta_name(proto_name, value, *span)?);
                    }
                    "bits" => bits = Some(meta_bits(proto_name, value, *span)?),
                    // vint codec：`codec` = 模型名（le128/prefix/table），类型 = Vint；
                    // 模型参数 prefix_bits/widths/inline_max/sentinels/endian 按模型消费
                    "codec" => {
                        meta_ty = Some(FieldType::Vint);
                        codec_name = Some(meta_name(proto_name, value, *span)?);
                    }
                    "prefix_bits" => prefix_bits = Some(meta_bits(proto_name, value, *span)?),
                    "widths" => widths = Some(meta_u8_list(proto_name, value, *span)?),
                    "inline_max" => inline_max = Some(meta_u8(proto_name, value, *span)?),
                    "sentinels" => sentinels = Some(meta_u8_list(proto_name, value, *span)?),
                    "endian" => endian = Some(meta_name(proto_name, value, *span)?),
                    k => {
                        return Err(Diagnostic::at(
                            format!(
                                "`#[proto]` 函数 `{proto_name}`：未知 `#[meta({k}=...)]` 项（支持 name / len / bytes / rest / expr / list / item / bits / codec / prefix_bits / widths / inline_max / sentinels / endian）"
                            ),
                            *span,
                        ));
                    }
                },
                ast::AttrArg::Bare { value, span } => match value {
                    // 无值 flag：`#[meta(rest)]`
                    ast::Value::Ident { name, .. } if name == "auto" => {
                        return Err(Diagnostic::at(
                            format!(
                                "`#[proto]` 函数 `{proto_name}`：`#[meta(auto)]` 已并入 `#[meta(len=\"auto\")]`（@auto/@len 统一为 len 目标）"
                            ),
                            *span,
                        ));
                    }
                    ast::Value::Ident { name, .. } if name == "rest" => {
                        meta_ty = Some(FieldType::Rest);
                    }
                    // `#[meta(list, item="...")]` 哨兵形态已移除：rest(子proto) 即
                    // 重复解析到失败（HTTP headers 以空行结束）
                    ast::Value::Ident { name, .. } if name == "list" => {
                        return Err(Diagnostic::at(
                            format!(
                                "`#[proto]` 函数 `{proto_name}`：哨兵 list（`#[meta(list, item=...)]` 无计数）已并入 `#[meta(rest=\"子proto\")]`（重复解析到失败）"
                            ),
                            *span,
                        ));
                    }
                    _ => {
                        // 旧位置形式 / 未知裸项
                        return Err(Diagnostic::at(
                            format!(
                                "`#[proto]` 函数 `{proto_name}`：`#[meta(...)]` 参数已改为键值对：`#[meta(len=\"dcid\")]` / `#[meta(bytes=4)]` / `#[meta(name=\"xx\")]`"
                            ),
                            *span,
                        ));
                    }
                },
                ast::AttrArg::Call { name, span, .. } => {
                    // 旧调用形式 `#[meta(len("x"))]`
                    return Err(Diagnostic::at(
                        format!(
                            "`#[proto]` 函数 `{proto_name}`：`#[meta({name}(...))]` 已改为键值对：`#[meta(len=\"dcid\")]` / `#[meta(bytes=4)]` / `#[meta(name=\"xx\")]`"
                        ),
                        *span,
                    ));
                }
            }
        }
    }
    // ── 值 → (类型, 内部表达式) ──
    // 类型化调用名表：u8/be16/.../line 有独立编码形态，可作 concat 参数调用；
    // bytes/rest 是声明性 meta 类型（无编码函数），调用形态已移除（上面拦截报错）
    let type_of = |name: &str| -> Option<FieldType> {
        match name {
            "u8" => Some(FieldType::U8),
            "be16" => Some(FieldType::Be16),
            "be32" => Some(FieldType::Be32),
            "be64" => Some(FieldType::Be64),
            "le16" => Some(FieldType::Le16),
            "le32" => Some(FieldType::Le32),
            "le64" => Some(FieldType::Le64),
            "mac" => Some(FieldType::Mac),
            "ip4" => Some(FieldType::Ip4),
            "ip6" => Some(FieldType::Ip6),
            "dns_name" => Some(FieldType::DnsName),
            "line" => Some(FieldType::Line),
            _ => None,
        }
    };
    let (call_ty, inner): (Option<FieldType>, Option<Value>) = match arg.value {
        Value::Call {
            name,
            args,
            span: cspan,
            ..
        } => {
            // `bytes(宽度)` / `rest(子proto)` 调用形态已移除——宽度/消费末尾是
            // 声明性 `#[meta]` 项，不是函数：写 `#[meta(bytes=...)]` /
            // `#[meta(rest=...)]`（裸标识符字段），定宽字面量自动推导
            if name == "bytes" || name == "rest" {
                return Err(Diagnostic::at(
                    format!(
                        "`#[proto]` 函数 `{proto_name}`：`{name}(...)` 调用形态已移除（不是函数）——宽度/消费末尾是声明性 `#[meta]` 项：写 `#[meta({name}=...)] 字段名`（裸标识符字段），定宽字面量自动推导"
                    ),
                    cspan,
                ));
            }
            let t = type_of(&name).ok_or_else(|| {
                Diagnostic::at(
                    format!(
                        "`#[proto]` 函数 `{proto_name}`：`{name}(...)` 不是字段类型（可用 u8/be16/be32/be64/le16/le32/le64/mac/ip4/ip6/dns_name/line；变长整数用 `#[meta(codec=...)]`）"
                    ),
                    cspan,
                )
            })?;
            if args.len() > 1 {
                return Err(Diagnostic::at(
                    format!("字段类型 `{name}` 只接受一个参数"),
                    cspan,
                ));
            }
            (Some(t), args.into_iter().next())
        }
        Value::Ident { name, span: ispan } => {
            // 裸标识符：类型必须来自 meta（bytes/rest/codec）
            (None, Some(Value::Ident { name, span: ispan }))
        }
        other => {
            // 字面量值：宽度从值自动推导（`hex("60000000")` = 4 字节 → bytes(4)，
            // 如 IPv6 头 first4）——内置类型化调用（u8/be16/mac/ip4/...）自带宽度，
            // 无需 bytes 标注；`bytes` 宽度机制只留给变长场合
            // （引用前序字段/计算表达式，`#[meta(bytes="dcid_len")]`）
            if meta_ty.is_none() {
                match &other {
                    Value::List(items) => {
                        meta_ty = Some(FieldType::Bytes);
                        width = Some(Value::Int(items.len() as i64));
                    }
                    Value::Str(s) => {
                        meta_ty = Some(FieldType::Bytes);
                        width = Some(Value::Int(s.len() as i64));
                    }
                    _ => {
                        return Err(Diagnostic::at(
                            format!(
                                "`#[proto]` 函数 `{proto_name}`：concat 参数必须是类型化调用（u8/be16/...）、标识符、字节列表/字符串字面量，或带 `#[meta(bytes/rest)]` 类型的值，得到 {}",
                                crate::registry::describe(&other)
                            ),
                            span,
                        ));
                    }
                }
            }
            (None, Some(other))
        }
    };
    let ty = call_ty.or(meta_ty).ok_or_else(|| {
        Diagnostic::at(
            format!(
                "`#[proto]` 函数 `{proto_name}`：裸标识符字段需要 `#[meta(bytes=...)]` / `#[meta(rest=...)]` / `#[meta(codec=...)]` 标注类型"
            ),
            span,
        )
    })?;
    if let Some(mt) = meta_ty
        && mt != ty
    {
        return Err(Diagnostic::at(
            format!(
                "`#[proto]` 函数 `{proto_name}`：字段类型冲突（外层调用 vs `#[meta(...)]` 标注）"
            ),
            span,
        ));
    }
    // ── vint 方案：meta codec 参数 → 方案（`FieldType::Vint` 唯一来源）──
    let vint = build_vint_codec(
        proto_name,
        VintMetaArgs {
            codec_name,
            prefix_bits,
            widths,
            inline_max,
            sentinels,
            endian,
        },
        ty,
        span,
    )?;
    // ── 名字与默认值 ──
    let (name, name_span) = match name_override {
        Some(n) => (n, span),
        None => match &inner {
            Some(Value::Ident { name, span }) => (name.clone(), *span),
            _ => (format!("f{idx}"), span),
        },
    };
    let default = match &inner {
        Some(Value::Ident { name, .. }) if params.contains(name.as_str()) => Some(Value::Ident {
            name: name.clone(),
            span,
        }),
        Some(Value::Ident { .. }) => None, // 非签名参数标识符：必填字段（或 len 计算字段）
        Some(other) => Some(other.clone()),
        None => None, // 裸 `rest`（无参数）：匿名 rest 字段
    };
    Ok(ast::FieldDecl {
        name,
        name_span,
        ty,
        width,
        bits,
        default,
        len_of,
        len_expr,
        rest_proto,
        list_count,
        vint,
        span,
    })
}

/// meta 的 `bits`：位宽 1..=8 整数（字符串或数字字面量）。
fn meta_bits(proto_name: &str, v: &ast::Value, span: Span) -> PktResult<u8> {
    let n = match v {
        ast::Value::Int(i) => *i,
        ast::Value::Str(s) => s.parse::<i64>().map_err(|_| {
            Diagnostic::at(
                format!(
                    "`#[proto]` 函数 `{proto_name}`：`#[meta(bits=...)]` 需要 1..=8 的整数，得到 `{s}`"
                ),
                span,
            )
        })?,
        other => {
            return Err(Diagnostic::at(
                format!(
                    "`#[proto]` 函数 `{proto_name}`：`#[meta(bits=...)]` 需要 1..=8 的整数，得到 {}",
                    crate::registry::describe(other)
                ),
                span,
            ))
        }
    };
    if !(1..=8).contains(&n) {
        return Err(Diagnostic::at(
            format!(
                "`#[proto]` 函数 `{proto_name}`：`#[meta(bits=...)]` 需要 1..=8（每字节最多 8 位），得到 {n}"
            ),
            span,
        ));
    }
    Ok(n as u8)
}

/// `#[meta(codec=...)]` 收集的 vint 方案参数（parser 组装后交 [`build_vint_codec`]）。
struct VintMetaArgs {
    codec_name: Option<String>,
    prefix_bits: Option<u8>,
    widths: Option<Vec<u8>>,
    inline_max: Option<u8>,
    sentinels: Option<Vec<u8>>,
    endian: Option<String>,
}

/// 组装 vint 方案（`FieldType::Vint` 字段的 codec，**唯一来源是 `#[meta(codec=...)]`**）：
/// `meta` 的 `codec_name` + 模型参数显式声明（类型 = Vint 已在解析时设入 meta_ty，
/// 此处只组装/校验参数）；Vint 字段无 codec → 报错；非 Vint 字段返回 None。
fn build_vint_codec(
    proto_name: &str,
    meta: VintMetaArgs,
    ty: crate::ast::FieldType,
    span: Span,
) -> PktResult<Option<crate::ast::VintCodec>> {
    use crate::ast::{VintCodec, VintEndian};
    let VintMetaArgs {
        codec_name,
        prefix_bits,
        widths,
        inline_max,
        sentinels,
        endian,
    } = meta;
    // 无 codec 名时的游离模型参数 → 误用报错（须在消费参数前检查）
    if codec_name.is_none()
        && (prefix_bits.is_some()
            || widths.is_some()
            || inline_max.is_some()
            || sentinels.is_some()
            || endian.is_some())
    {
        return Err(Diagnostic::at(
            format!(
                "`#[proto]` 函数 `{proto_name}`：codec 参数（prefix_bits/widths/inline_max/sentinels/endian）需要配合 `#[meta(codec=...)]`"
            ),
            span,
        ));
    }
    let meta_codec: Option<VintCodec> = match codec_name {
        None => None,
        Some(n) => match n.as_str() {
            "le128" => {
                if prefix_bits.is_some()
                    || widths.is_some()
                    || inline_max.is_some()
                    || sentinels.is_some()
                    || endian.is_some()
                {
                    return Err(Diagnostic::at(
                        format!(
                            "`#[proto]` 函数 `{proto_name}`：codec `le128` 不接受 prefix_bits/widths/inline_max/sentinels/endian 参数"
                        ),
                        span,
                    ));
                }
                Some(VintCodec::Le128)
            }
            "prefix" => {
                let pb = prefix_bits.ok_or_else(|| {
                    Diagnostic::at(
                        format!(
                            "`#[proto]` 函数 `{proto_name}`：codec `prefix` 需要 `#[meta(prefix_bits=...)]`（1..=8）"
                        ),
                        span,
                    )
                })?;
                let ws = widths.ok_or_else(|| {
                    Diagnostic::at(
                        format!(
                            "`#[proto]` 函数 `{proto_name}`：codec `prefix` 需要 `#[meta(widths=[...])]`（2^prefix_bits 个宽度）"
                        ),
                        span,
                    )
                })?;
                if inline_max.is_some() || sentinels.is_some() || endian.is_some() {
                    return Err(Diagnostic::at(
                        format!(
                            "`#[proto]` 函数 `{proto_name}`：codec `prefix` 不接受 inline_max/sentinels/endian 参数"
                        ),
                        span,
                    ));
                }
                Some(VintCodec::Prefix {
                    prefix_bits: pb,
                    widths: ws,
                })
            }
            "table" => {
                let im = inline_max.ok_or_else(|| {
                    Diagnostic::at(
                        format!(
                            "`#[proto]` 函数 `{proto_name}`：codec `table` 需要 `#[meta(inline_max=...)]`（0..=255）"
                        ),
                        span,
                    )
                })?;
                let ss = sentinels.ok_or_else(|| {
                    Diagnostic::at(
                        format!(
                            "`#[proto]` 函数 `{proto_name}`：codec `table` 需要 `#[meta(sentinels=[...])]`（哨兵字节表）"
                        ),
                        span,
                    )
                })?;
                let ws = widths.ok_or_else(|| {
                    Diagnostic::at(
                        format!(
                            "`#[proto]` 函数 `{proto_name}`：codec `table` 需要 `#[meta(widths=[...])]`（与 sentinels 对齐的宽度表）"
                        ),
                        span,
                    )
                })?;
                if ss.len() != ws.len() {
                    return Err(Diagnostic::at(
                        format!(
                            "`#[proto]` 函数 `{proto_name}`：codec `table` 的 sentinels 与 widths 长度不一致（{} vs {}）",
                            ss.len(),
                            ws.len()
                        ),
                        span,
                    ));
                }
                if prefix_bits.is_some() {
                    return Err(Diagnostic::at(
                        format!(
                            "`#[proto]` 函数 `{proto_name}`：codec `table` 不接受 prefix_bits 参数"
                        ),
                        span,
                    ));
                }
                let endian = match endian.as_deref() {
                    None | Some("be") => VintEndian::Be,
                    Some("le") => VintEndian::Le,
                    Some(o) => {
                        return Err(Diagnostic::at(
                            format!(
                                "`#[proto]` 函数 `{proto_name}`：`#[meta(endian=...)]` 需要 \"be\" 或 \"le\"，得到 `{o}`"
                            ),
                            span,
                        ));
                    }
                };
                Some(VintCodec::Table {
                    inline_max: im,
                    table: ss.into_iter().zip(ws).collect(),
                    endian,
                })
            }
            other => {
                return Err(Diagnostic::at(
                    format!(
                        "`#[proto]` 函数 `{proto_name}`：未知 codec `{other}`（可用 le128 / prefix / table）"
                    ),
                    span,
                ));
            }
        },
    };
    match (meta_codec, ty) {
        (Some(m), crate::ast::FieldType::Vint) => Ok(Some(m)),
        (None, crate::ast::FieldType::Vint) => Err(Diagnostic::at(
            format!(
                "`#[proto]` 函数 `{proto_name}`：vint 字段需要 codec 方案（`#[meta(codec=\"le128\"|\"prefix\"|\"table\", ...)]`）"
            ),
            span,
        )),
        // 非 Vint 字段：无 codec → None（游离参数已在函数开头拦截）
        _ => Ok(None),
    }
}

/// meta 的 u8 参数（`inline_max` 等）：Int/Hex/字符串 → 0..=255。
fn meta_u8(proto_name: &str, v: &ast::Value, span: Span) -> PktResult<u8> {
    let n = match v {
        ast::Value::Int(i) => *i,
        ast::Value::Hex(h) => *h as i64,
        ast::Value::Str(s) => s.parse::<i64>().map_err(|_| {
            Diagnostic::at(
                format!(
                    "`#[proto]` 函数 `{proto_name}`：`#[meta(...)]` 需要 0..=255 的整数，得到 `{s}`"
                ),
                span,
            )
        })?,
        other => {
            return Err(Diagnostic::at(
                format!(
                    "`#[proto]` 函数 `{proto_name}`：`#[meta(...)]` 需要 0..=255 的整数，得到 {}",
                    crate::registry::describe(other)
                ),
                span,
            ));
        }
    };
    if !(0..=255).contains(&n) {
        return Err(Diagnostic::at(
            format!("`#[proto]` 函数 `{proto_name}`：`#[meta(...)]` 需要 0..=255，得到 {n}"),
            span,
        ));
    }
    Ok(n as u8)
}

/// meta 的 u8 列表参数（`widths`/`sentinels`）：`[1, 2, 4, 8]` 整数列表 → Vec<u8>。
fn meta_u8_list(proto_name: &str, v: &ast::Value, span: Span) -> PktResult<Vec<u8>> {
    let ast::Value::List(items) = v else {
        return Err(Diagnostic::at(
            format!(
                "`#[proto]` 函数 `{proto_name}`：`#[meta(...)]` 需要整数列表（如 [1, 2, 4, 8]），得到 {}",
                crate::registry::describe(v)
            ),
            span,
        ));
    };
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        let n = match it {
            ast::Value::Int(i) => *i,
            ast::Value::Hex(h) => *h as i64,
            ast::Value::Str(s) => s.parse::<i64>().map_err(|_| {
                Diagnostic::at(
                    format!(
                        "`#[proto]` 函数 `{proto_name}`：宽度/哨兵列表元素需要 0..=255 的整数，得到 `{s}`"
                    ),
                    span,
                )
            })?,
            other => {
                return Err(Diagnostic::at(
                    format!(
                        "`#[proto]` 函数 `{proto_name}`：宽度/哨兵列表元素需要 0..=255 的整数，得到 {}",
                        crate::registry::describe(other)
                    ),
                    span,
                ));
            }
        };
        if !(0..=255).contains(&n) {
            return Err(Diagnostic::at(
                format!("`#[proto]` 函数 `{proto_name}`：宽度/哨兵列表元素需要 0..=255，得到 {n}"),
                span,
            ));
        }
        out.push(n as u8);
    }
    Ok(out)
}

/// meta 的名字参数：字符串或标识符 → 名字。
fn meta_name(proto_name: &str, v: &ast::Value, span: Span) -> PktResult<String> {
    match v {
        ast::Value::Str(s) => Ok(s.clone()),
        ast::Value::Ident { name, .. } => Ok(name.clone()),
        other => Err(Diagnostic::at(
            format!(
                "`#[proto]` 函数 `{proto_name}`：需要字段/目标名（字符串或标识符），得到 {}",
                crate::registry::describe(other)
            ),
            span,
        )),
    }
}

/// meta 的宽度/计数表达式：字符串按值表达式子解析（`bytes("band(first, 3) + 1")`），
/// 其余原样（`bytes(band(first, 3) + 1)`）。
fn meta_width(proto_name: &str, v: &ast::Value, span: Span) -> PktResult<ast::Value> {
    match v {
        ast::Value::Str(s) => {
            parse_value_expr(s).map_err(|e| {
                Diagnostic::at(
                    format!(
                        "`#[proto]` 函数 `{proto_name}`：`#[meta(bytes(...))]` 的宽度表达式解析失败：{e}"
                    ),
                    span,
                )
            })
        }
        other => Ok(other.clone()),
    }
}

/// meta 的 `expr`（`@auto`/`@len` 的表达式变换）：字符串按值表达式子解析，
/// 其余原样（`#[meta(auto, expr="shl(len, 4)")]`）。
fn meta_expr(proto_name: &str, v: &ast::Value, span: Span) -> PktResult<ast::Value> {
    match v {
        ast::Value::Str(s) => parse_value_expr(s).map_err(|e| {
            Diagnostic::at(
                format!("`#[proto]` 函数 `{proto_name}`：`#[meta(expr=...)]` 表达式解析失败：{e}"),
                span,
            )
        }),
        other => Ok(other.clone()),
    }
}

/// 解析单个**值表达式**（配方 `extract` 的 `from:` 表达式等单值输入）：
/// `src` → [`Value`]。与 `parse_ast` 同一词法/错误渲染；输入须为完整表达式
/// （如 `reply.icmp.seq + 1`），调用方负责剥注释与 `key: ` 前缀。
pub fn parse_value_expr<'src>(src: &'src str) -> crate::diag::PktResult<Value> {
    let (tokens, lex_errors) = crate::lexer::lex(src);
    if let Some(e) = lex_errors.first() {
        return Err(crate::diag::Diagnostic {
            message: e.message.clone(),
            file: None,
            span: Some(crate::diag::SourceSpan::from_ast(e.span, e.offset, 1)),
            kind: crate::diag::DiagnosticKind::General,
        });
    }
    let mut state = SimpleState(tokens.clone());
    let input = tokens.iter().map(|t| t.tok.clone()).collect::<Vec<_>>();
    let result = value_parser()
        .then_ignore(end::<ParserInput, Extra<'src>>())
        .parse_with_state(Stream::from_iter(input), &mut state);
    match render_parse_err(&tokens, result.into_result()) {
        Ok(r) => r.map_err(|_| crate::diag::Diagnostic::new("解析失败：未知错误")),
        Err(d) => Err(d),
    }
}

/// 把 chumsky 的错误结果渲染为 `Diagnostic`（`parse_ast`/`parse_value_expr` 共用）。
fn render_parse_err<'a, T>(
    tokens: &[Token],
    result: Result<T, Vec<chumsky::error::Rich<'a, Tok, SpanT>>>,
) -> Result<Result<T, Vec<chumsky::error::Rich<'a, Tok, SpanT>>>, crate::diag::Diagnostic> {
    use crate::diag::{Diagnostic, SourceSpan};

    if let Err(errs) = &result {
        let e = errs.first().expect("非空错误列表");
        let s = e.span();
        let span = span_from_tokens(tokens, s.start(), s.end());
        let message = match e.reason() {
            RichReason::Custom(msg) => msg.clone(),
            RichReason::ExpectedFound { expected, found } => {
                let exp: Vec<String> = expected.iter().map(|p| pattern_text(p)).collect();
                match found {
                    Some(f) => format!("期望 {}，发现 {}", exp.join(" 或 "), **f),
                    None => format!("期望 {}，但输入已结束", exp.join(" 或 ")),
                }
            }
        };
        return Err(Diagnostic {
            message,
            file: None,
            span: Some(SourceSpan::from_ast(span, 0, 0)),
            kind: crate::diag::DiagnosticKind::General,
        });
    }
    Ok(result)
}

/// 把紧贴每个 `func` 上方的连续 `#` 注释行解析成该函数的结构化 doc（`FuncDoc`）。
///
/// 注释在词法层被丢弃，故在解析成功后按 `FuncStmt.span` 起始行回扫源码。
/// 规则：与 `func` 之间无空行/非注释行的连续注释块才算 doc（保守，不跨空行）。
/// 行格式：`@param 名: 说明` / `@auto: 说明` 为标签，其余为摘要。
fn attach_doc_comments(ast: &mut AstFile, src: &str) {
    let lines: Vec<&str> = src.lines().collect();
    for stmt in &mut ast.stmts {
        let Stmt::Func(f) = stmt else {
            continue;
        };
        // f.span.start.line 为 1 基；lines 为 0 基 → 上方注释行 = start.line - 2
        let mut idx = f.span.start.line.checked_sub(2);
        let mut raw: Vec<&str> = Vec::new();
        while let Some(i) = idx {
            let prev = lines.get(i).map(|l| l.trim_start()).unwrap_or("");
            if let Some(rest) = prev.strip_prefix('#') {
                // 去 `#` 后的一个空格（`# 注释` → `注释`；`#注释` → `注释`）
                raw.push(rest.strip_prefix(' ').unwrap_or(rest));
                idx = i.checked_sub(1);
            } else {
                break;
            }
        }
        if raw.is_empty() {
            continue;
        }
        raw.reverse();
        let mut doc = crate::ast::FuncDoc::default();
        let mut summary: Vec<&str> = Vec::new();
        for line in raw {
            if let Some(rest) = line.strip_prefix("@param ") {
                // `@param 名: 说明`：名 = 第一个冒号前，说明 = 冒号后（trim）
                let (name, desc) = match rest.split_once(':') {
                    Some((n, d)) => (n.trim().to_string(), d.trim().to_string()),
                    None => (rest.trim().to_string(), String::new()),
                };
                if !name.is_empty() {
                    doc.params.push((name, desc));
                }
            } else if let Some(rest) = line.strip_prefix("@auto") {
                doc.auto = Some(
                    rest.strip_prefix(':')
                        .map(str::trim)
                        .unwrap_or("")
                        .to_string(),
                );
            } else {
                summary.push(line);
            }
        }
        if !summary.is_empty() {
            doc.summary = summary.join("\n");
        }
        f.doc = Some(doc);
    }
}

/// 渲染期望 token 列表。
fn pattern_text(p: &chumsky::error::RichPattern<'_, Tok>) -> String {
    use chumsky::error::RichPattern;
    match p {
        RichPattern::Token(t) => t.to_string(),
        RichPattern::Label(l) => l.to_string(),
        RichPattern::Identifier(i) => i.clone(),
        RichPattern::Any => "任意 token".to_string(),
        RichPattern::SomethingElse => "其他内容".to_string(),
        RichPattern::EndOfInput => "输入结束".to_string(),
    }
}
