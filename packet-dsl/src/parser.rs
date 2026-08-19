//! chumsky 解析器：token 流 → AST。
//!
//! 语法要点：
//! - 语句按换行分隔；流水线内允许换行（续行以 `|>` 开头）。
//! - 流水线层包裹只支持 `|>`（`||>` 或分支已移除，多包用多条流水线）。
//! - 值：字符串 / 整数 / 十六进制（`0x..`）/ 布尔 / 列表（`[...]`）。
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

use crate::ast::*;
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
            Tok::Bool(b) => write!(f, "布尔 `{b}`"),
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

pub fn parser<'src>() -> impl Parser<'src, ParserInput, AstFile, Extra<'src>> {
    // 标识符（带自身 span）
    let ident = any::<ParserInput, Extra<'src>>()
        .filter(|t: &Tok| matches!(t, Tok::Ident(_)))
        .map_with(|t, e| {
            let Tok::Ident(s) = t else {
                unreachable!("filter 已保证为 Ident")
            };
            (s, conv(e))
        });

    // 关键字匹配（不消费以外的 token）
    let kw = |s: &'static str| {
        any::<ParserInput, Extra<'src>>()
            .filter(move |t: &Tok| matches!(t, Tok::Ident(i) if i == s))
    };

    // 换行
    let newline = just(Tok::Newline).ignored();
    let nl0 = newline.clone().repeated().ignored();
    let nl1 = newline.repeated().at_least(1).ignored();
    // 逗号分隔符：容忍前后换行（多行调用 / 列表 / use）
    let comma_nl = nl0
        .clone()
        .ignore_then(just(Tok::Comma))
        .then_ignore(nl0.clone());

    // 值
    let value = recursive::<ParserInput, Value, Extra<'src>, _, _>(|value| {
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
        let bool_ = any::<ParserInput, Extra<'src>>()
            .filter(|t: &Tok| matches!(t, Tok::Bool(_)))
            .map_with(|t, _| match t {
                Tok::Bool(b) => Value::Bool(b),
                _ => unreachable!("filter 已保证为 Bool"),
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
            .then(comma_nl.clone().ignore_then(str_tok).or_not())
            .then_ignore(nl0.clone())
            .then_ignore(just(Tok::RParen))
            .map_with(|(name, default), _| Value::Param { name, default });
        // 值位置 hex 调用：`hex("deadbeef")` → 字节列表值（底层数据构建，如
        // `eth_frame(payload=hex("..."))`）；与层位置 `hex(...)`（Raw 载荷层）并存
        let hex_call = kw("hex")
            .then(just(Tok::LParen))
            .then_ignore(nl0.clone())
            .ignore_then(str_tok)
            .then_ignore(nl0.clone())
            .then_ignore(just(Tok::RParen))
            .map_with(|s, _| {
                let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
                let bytes: Vec<Value> = (0..cleaned.len())
                    .step_by(2)
                    .map(|i| {
                        Value::Int(u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap_or(0) as i64)
                    })
                    .collect();
                Value::List(bytes)
            });
        // 函数参数引用：`dst=dst` 右侧的裸标识符（须在 `params(...)` 之后尝试，避免抢占）
        let ident_value = ident.map_with(|(name, span), _| Value::Ident { name, span });
        // 通用值调用：`concat(...)` / `be16(...)` / 用户值函数
        let value_call = ident
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
            bool_,
            list_,
            params_call,
            hex_call,
            value_call,
            ident_value,
        ));
        // 数字加法：`20 + len(payload)`（左结合）
        atom.clone()
            .then(
                just(Tok::Plus)
                    .ignore_then(atom.clone())
                    .repeated()
                    .collect::<Vec<_>>(),
            )
            .map_with(|(first, rest), e| {
                rest.into_iter().fold(first, |acc, r| Value::Add {
                    left: Box::new(acc),
                    right: Box::new(r),
                    span: conv(e),
                })
            })
            .boxed()
    });

    // 参数：`IDENT = value`（命名）或 `value`（位置参数）
    let named_arg = ident
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
        .separated_by(comma_nl.clone())
        .allow_trailing()
        .at_least(1)
        .collect::<Vec<_>>();

    // import 括号列表：`a, x as ax, c`（`as` 别名可省略）→ (原名, 别名, span)
    let import_ident_list = ident
        .then(kw("as").ignore_then(ident).or_not())
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
            (just(Tok::Dash).ignore_then(ident))
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
        .then(ident)
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
        .then(just(Tok::Equals).ignore_then(expr.clone()))
        .map_with(|((name, name_span), e), extra| DefStmt {
            name,
            name_span,
            span: conv(extra),
            expr: e,
        });

    // sniffer 字段：`IDENT = 值`（值须给出；Ident → 发包同层同名字段引用）
    let sniffer_field = ident
        .then(just(Tok::Equals).ignore_then(value.clone()))
        .map_with(|((name, _), v), _| (name, v));
    let sniffer_fields = sniffer_field
        .separated_by(comma_nl.clone())
        .allow_trailing()
        .collect::<Vec<_>>();
    // 单个匹配子句：`match 层(字段=值, ...)`
    let sniffer_match = kw("match")
        .then_ignore(nl0.clone())
        .ignore_then(ident)
        .then(
            just(Tok::LParen)
                .then_ignore(nl0.clone())
                .ignore_then(sniffer_fields)
                .then_ignore(nl0.clone())
                .then_ignore(just(Tok::RParen)),
        )
        .map_with(|((layer, _), fields), e| SnifferClause {
            layer,
            fields: fields
                .into_iter()
                .map(|(name, v)| {
                    let val = match v {
                        Value::Ident { name: f, .. } => SnifferValue::SentField(f),
                        other => SnifferValue::Literal(other),
                    };
                    (name, val)
                })
                .collect(),
            span: conv(e),
        });
    // sniffer 块：`sniffer:` 后跟 `- match 层(...)` 列表（与 export: 同风格）
    let sniffer_stmt = kw("sniffer")
        .then(just(Tok::Colon))
        .then_ignore(nl0.clone())
        .ignore_then(
            (just(Tok::Dash)
                .ignore_then(nl0.clone())
                .ignore_then(sniffer_match))
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
        .ignore_then(ident)
        .then(
            just(Tok::LParen)
                .ignore_then(nl0.clone())
                .ignore_then(func_param_list)
                .then_ignore(nl0.clone())
                .then_ignore(just(Tok::RParen)),
        )
        .map(|((name, name_span), params)| (name, name_span, params));
    // 函数体：值函数 `-> bytes { 值表达式 }` 或层函数 `{ 流水线 }`
    let value_func_body = just(Tok::Arrow)
        .then_ignore(nl0.clone())
        .ignore_then(kw("bytes"))
        .then_ignore(nl0.clone())
        .then_ignore(just(Tok::LBrace))
        .then_ignore(nl0.clone())
        .ignore_then(value.clone())
        .then_ignore(nl0.clone())
        .then_ignore(just(Tok::RBrace))
        .map(|v| {
            (
                Some(v),
                Pipeline {
                    use_names: Vec::new(),
                    layers: Vec::new(),
                    span: Span::new(0, 0, 0, 0),
                },
            )
        });
    let layer_func_body = just(Tok::LBrace)
        .then_ignore(nl0.clone())
        .ignore_then(func_body)
        .then_ignore(nl0.clone())
        .then_ignore(just(Tok::RBrace))
        .map(|b| (None, b));
    let func_stmt = func_head
        .then_ignore(nl0.clone())
        .then(choice((value_func_body, layer_func_body)))
        .map_with(
            |((name, name_span, params), (value_body, body)), e| FuncStmt {
                name,
                name_span,
                params,
                body,
                value_body,
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
    use crate::diag::{Diagnostic, SourceSpan};

    let (tokens, lex_errors) = crate::lexer::lex(src);
    if let Some(e) = lex_errors.first() {
        return Err(Diagnostic {
            message: e.message.clone(),
            file: None,
            span: Some(SourceSpan::from_ast(e.span, e.offset, 1)),
        });
    }
    let mut state = SimpleState(tokens.clone());
    let input = tokens.iter().map(|t| t.tok.clone()).collect::<Vec<_>>();
    let result = parser().parse_with_state(Stream::from_iter(input), &mut state);
    let result = result.into_result();
    if let Err(errs) = &result {
        let e = errs.first().expect("非空错误列表");
        let s = e.span();
        let span = span_from_tokens(&tokens, s.start(), s.end());
        let message = match e.reason() {
            RichReason::Custom(msg) => msg.clone(),
            RichReason::ExpectedFound { expected, found } => {
                let exp: Vec<String> = expected.iter().map(|p| pattern_text(p)).collect();
                match found {
                    Some(f) => format!("期望 {}，发现 {}", exp.join(" 或 "), &**f),
                    None => format!("期望 {}，但输入已结束", exp.join(" 或 ")),
                }
            }
        };
        return Err(Diagnostic {
            message,
            file: None,
            span: Some(SourceSpan::from_ast(span, 0, 0)),
        });
    }
    let mut ast = result.map_err(|_| Diagnostic::new("解析失败：未知错误"))?;
    attach_doc_comments(&mut ast, src);
    Ok(ast)
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
