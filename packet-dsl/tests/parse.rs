//! 解析器测试：语法、边界规则、span、错误定位。

use packet_dsl::ast::{Expr, Stmt, Value};
use packet_dsl::parser::parse_ast;

fn parse(src: &str) -> packet_dsl::ast::AstFile {
    parse_ast(src).unwrap_or_else(|e| panic!("解析失败：{e}"))
}

fn parse_err(src: &str) -> packet_dsl::diag::Diagnostic {
    parse_ast(src).expect_err("应当解析失败")
}

#[test]
fn def_with_named_args() {
    let ast = parse(r#"a = http(method="GET", path="/")"#);
    assert_eq!(ast.stmts.len(), 1);
    let Stmt::Def(d) = &ast.stmts[0] else {
        panic!("期望 Def")
    };
    assert_eq!(d.name, "a");
    let Expr::Call(c) = &d.expr else {
        panic!("期望 Call")
    };
    assert_eq!(c.name, "http");
    assert_eq!(c.args.len(), 2);
    assert_eq!(c.args[0].name.as_ref().unwrap().0, "method");
    assert!(matches!(c.args[0].value, Value::Str(ref s) if s == "GET"));
}

#[test]
fn def_with_positional_args() {
    let ast = parse(r#"a = tcp(12345, 80)"#);
    let Stmt::Def(d) = &ast.stmts[0] else {
        panic!()
    };
    let Expr::Call(c) = &d.expr else { panic!() };
    assert_eq!(c.args.len(), 2);
    assert!(c.args[0].name.is_none());
    assert!(matches!(c.args[0].value, Value::Int(12345)));
}

#[test]
fn pipeline_layers_inner_to_outer() {
    let ast = parse(r#"use(a, b) |> tcp(dport=80) |> ipv4 |> eth"#);
    let Stmt::Pipeline(p) = &ast.stmts[0] else {
        panic!("期望 Pipeline")
    };
    assert_eq!(p.pipeline.use_names.len(), 2);
    assert_eq!(p.pipeline.layers.len(), 3);
    assert_eq!(p.pipeline.layers[0].name, "tcp");
    assert_eq!(p.pipeline.layers[1].name, "ipv4");
    assert_eq!(p.pipeline.layers[2].name, "eth");
}

#[test]
fn multiline_pipeline_continuation() {
    let ast = parse("use(a) |> tcp(dport=80)\n          |> udp(dport=80)\n");
    let Stmt::Pipeline(p) = &ast.stmts[0] else {
        panic!()
    };
    assert_eq!(p.pipeline.layers.len(), 2);
}

#[test]
fn statements_separated_by_newlines() {
    let ast = parse("a = http()\nb = tcp()\nuse(a) |> tcp()\n");
    assert_eq!(ast.stmts.len(), 3);
}

#[test]
fn export_block_no_space() {
    let ast = parse("export:\n-a\n-b\n");
    let Stmt::Export(e) = &ast.stmts[0] else {
        panic!()
    };
    assert_eq!(e.names.len(), 2);
    assert_eq!(e.names[0].0, "a");
}

#[test]
fn export_same_line_items() {
    let ast = parse("export: -a -b\n");
    let Stmt::Export(e) = &ast.stmts[0] else {
        panic!()
    };
    assert_eq!(e.names.len(), 2);
}

#[test]
fn import_with_and_without_braces() {
    let ast = parse("import a { a, b }\nimport c\n");
    assert_eq!(ast.stmts.len(), 2);
    let Stmt::Import(i1) = &ast.stmts[0] else {
        panic!()
    };
    assert_eq!(i1.module, "a");
    assert_eq!(i1.names.as_ref().unwrap().len(), 2);
    let Stmt::Import(i2) = &ast.stmts[1] else {
        panic!()
    };
    assert!(i2.names.is_none());
}

#[test]
fn import_alias_syntax() {
    // `x as ax`：别名可省略；`as` 不是保留字，可作普通导出名
    let ast = parse("import a { x as ax, y }\n");
    let Stmt::Import(i) = &ast.stmts[0] else {
        panic!()
    };
    let names = i.names.as_ref().unwrap();
    assert_eq!(names.len(), 2);
    assert_eq!(names[0].0, "x");
    assert_eq!(names[0].1.as_deref(), Some("ax"));
    assert_eq!(names[1].0, "y");
    assert!(names[1].1.is_none());
    let ast2 = parse("import a { as }\n");
    let Stmt::Import(i2) = &ast2.stmts[0] else {
        panic!()
    };
    assert_eq!(i2.names.as_ref().unwrap()[0].0, "as");
    assert!(i2.names.as_ref().unwrap()[0].1.is_none());
}

#[test]
fn comments_and_shebang() {
    let ast = parse("#!/usr/bin/env packet-dsl\n# 注释\n\na = http() # 行尾注释\n");
    assert_eq!(ast.stmts.len(), 1);
}

#[test]
fn func_doc_comment_attaches() {
    let ast = parse(
        "# net6(dst, ...)：一次生成 [ipv6, eth] 两层\n# 第二行说明\nfunc net6(dst) { ipv6(dst=dst) |> eth() }\n",
    );
    let Stmt::Func(f) = &ast.stmts[0] else {
        panic!()
    };
    let doc = f.doc.as_ref().expect("应有 doc");
    assert_eq!(
        doc.summary,
        "net6(dst, ...)：一次生成 [ipv6, eth] 两层\n第二行说明"
    );
    assert!(doc.params.is_empty());
    assert!(doc.auto.is_none());
}

#[test]
fn func_doc_requires_adjacent_comment() {
    // 空行隔开 → 不算 doc
    let ast = parse("# 普通注释\n\nfunc f() { ipv4() }\n");
    let Stmt::Func(f) = &ast.stmts[0] else {
        panic!()
    };
    assert!(f.doc.is_none(), "空行隔开的注释不算 doc");
    // 无注释 → None
    let ast2 = parse("func f() { ipv4() }\n");
    let Stmt::Func(f2) = &ast2.stmts[0] else {
        panic!()
    };
    assert!(f2.doc.is_none());
    // 缩进注释 + 无空格前缀都去掉
    let ast3 = parse("    #带缩进无空格\nfunc f() { ipv4() }\n");
    let Stmt::Func(f3) = &ast3.stmts[0] else {
        panic!()
    };
    assert_eq!(f3.doc.as_ref().unwrap().summary, "带缩进无空格");
}

#[test]
fn func_doc_tags_parse() {
    let ast = parse(
        "# 一次生成 [ipv4, eth] 两层\n# @param dst: 目标 IPv4 地址（必填；可域名）\n# @param src: 源地址\n# @auto: 自动补 length/checksum\nfunc net4(dst, src=\"0.0.0.0\") { ipv4(dst=dst) |> eth() }\n",
    );
    let Stmt::Func(f) = &ast.stmts[0] else {
        panic!()
    };
    let doc = f.doc.as_ref().expect("应有 doc");
    assert_eq!(doc.summary, "一次生成 [ipv4, eth] 两层");
    assert_eq!(
        doc.params,
        vec![
            (
                "dst".to_string(),
                "目标 IPv4 地址（必填；可域名）".to_string()
            ),
            ("src".to_string(), "源地址".to_string()),
        ]
    );
    assert_eq!(doc.auto.as_deref(), Some("自动补 length/checksum"));
}

#[test]
fn func_doc_tag_variants() {
    // 无冒号 @param / 空 @auto / 冒号后多余空格
    let ast = parse("# @param a\n# @auto:\n# @param b:  多空格\nfunc f(a, b) { ipv4() }\n");
    let Stmt::Func(f) = &ast.stmts[0] else {
        panic!()
    };
    let doc = f.doc.as_ref().expect("应有 doc");
    assert_eq!(doc.summary, "", "全标签行 → 空摘要");
    assert_eq!(
        doc.params,
        vec![
            ("a".to_string(), String::new()),
            ("b".to_string(), "多空格".to_string())
        ]
    );
    assert_eq!(doc.auto.as_deref(), Some(""));
}

#[test]
fn func_doc_multi_stmt_only_attaches_own() {
    // 注释只贴给自己的函数；第二个函数无注释
    let ast = parse(
        "# 只给第一个\nfunc a() { ipv4() }\nfunc b() { ipv6() }\n# 只给第三个\nfunc c() { udp() }\n",
    );
    let docs: Vec<Option<String>> = ast
        .stmts
        .iter()
        .filter_map(|s| match s {
            Stmt::Func(f) => Some(f.doc.as_ref().map(|d| d.summary.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        docs,
        vec![
            Some("只给第一个".to_string()),
            None,
            Some("只给第三个".to_string())
        ]
    );
}

#[test]
fn string_escapes() {
    let ast = parse(r#"a = http(method="G\"ET", body="a\nb")"#);
    let Stmt::Def(d) = &ast.stmts[0] else {
        panic!()
    };
    let Expr::Call(c) = &d.expr else { panic!() };
    let method = c
        .args
        .iter()
        .find(|a| a.name.as_ref().unwrap().0 == "method")
        .unwrap();
    assert!(matches!(&method.value, Value::Str(s) if s == "G\"ET"));
    let body = c
        .args
        .iter()
        .find(|a| a.name.as_ref().unwrap().0 == "body")
        .unwrap();
    assert!(matches!(&body.value, Value::Str(s) if s == "a\nb"));
}

#[test]
fn hex_and_list_values() {
    let ast = parse(r#"a = raw(bytes=[0x48, 0x69])"#);
    let Stmt::Def(d) = &ast.stmts[0] else {
        panic!()
    };
    let Expr::Call(c) = &d.expr else { panic!() };
    assert!(matches!(&c.args[0].value, Value::List(items) if items.len() == 2));
}

#[test]
fn multiline_call_and_list() {
    let ast = parse(
        r#"post = http(method="POST",
            path="/login",
            headers=[
                "Content-Type: application/json",
                "User-Agent: prping",
            ],
            body="{}")
"#,
    );
    let Stmt::Def(d) = &ast.stmts[0] else {
        panic!()
    };
    let Expr::Call(c) = &d.expr else { panic!() };
    assert_eq!(c.name, "http");
    assert_eq!(c.args.len(), 4);
    let headers = c
        .args
        .iter()
        .find(|a| a.name.as_ref().unwrap().0 == "headers")
        .unwrap();
    assert!(matches!(&headers.value, Value::List(items) if items.len() == 2));
}

#[test]
fn multiline_use_list() {
    let ast = parse("use(a,\n     b) |> tcp()\n");
    let Stmt::Pipeline(p) = &ast.stmts[0] else {
        panic!()
    };
    assert_eq!(p.pipeline.use_names.len(), 2);
}

#[test]
fn def_expr_can_be_pipeline() {
    let ast = parse(r#"full = use(a) |> tcp(dport=443) |> ipv4()"#);
    let Stmt::Def(d) = &ast.stmts[0] else {
        panic!()
    };
    assert!(matches!(d.expr, Expr::Pipeline(_)));
}

// ── 边界规则 ─────────────────────────────────────────────────

/// `||>` 已移除：出现即报语法错误。
#[test]
fn or_branch_is_error() {
    let err = parse_err("use(a) ||> udp");
    assert!(
        err.message.contains("期望") || err.message.contains("||>"),
        "{}",
        err.message
    );
    let err2 = parse_err("use(a) |> tcp ||> udp");
    assert!(
        err2.message.contains("期望") || err2.message.contains("||>"),
        "{}",
        err2.message
    );
}

#[test]
fn unterminated_string_is_error() {
    let err = parse_err(r#"a = http(method="GET)"#);
    assert!(err.message.contains("未闭合"));
}

#[test]
fn trailing_garbage_is_error() {
    let err = parse_err("a = http() @@@");
    assert!(
        err.message.contains("无法识别") || err.message.contains("期望"),
        "{}",
        err.message
    );
}

#[test]
fn bare_call_without_parens_means_no_args() {
    // 容忍无参裸调用（`tcp` == `tcp()`）
    let ast = parse("a = http");
    let Stmt::Def(d) = &ast.stmts[0] else {
        panic!()
    };
    let Expr::Call(c) = &d.expr else { panic!() };
    assert_eq!(c.name, "http");
    assert!(c.args.is_empty());
}

#[test]
fn empty_export_block_is_error() {
    let err = parse_err("export:\n");
    assert!(err.message.contains("期望"));
}

#[test]
fn error_span_points_at_fault() {
    let err = parse_err("a = http()\nb = tcp(80, 443) ||| udp\n");
    // 错误在第二行；span 行号应为 2
    let span = err.span.expect("应有 span");
    assert_eq!(span.start.line, 2, "span: {:?}", span);
}

#[test]
fn error_carries_file_name() {
    let d = parse_ast("a = http(").unwrap_err();
    let d2 = d.with_file("x.pkt".to_string());
    assert!(d2.to_string().starts_with("x.pkt:"));
}

// ── 函数语法 ─────────────────────────────────────────────────

#[test]
fn func_stmt_parses() {
    let ast = parse("func f(a, b=64, c=\"random\") {\n    ipv4(src=a, dst=b) |> eth(src_mac=c)\n}");
    let Stmt::Func(f) = &ast.stmts[0] else {
        panic!("期望 Func，得到 {:?}", ast.stmts[0])
    };
    assert_eq!(f.name, "f");
    assert_eq!(f.params.len(), 3);
    assert_eq!(f.params[0].name, "a");
    assert!(f.params[0].default.is_none(), "无默认值");
    assert!(matches!(f.params[1].default, Some(Value::Int(64))));
    assert!(matches!(f.params[2].default, Some(Value::Str(ref s)) if s == "random"));
    assert_eq!(f.body.layers.len(), 2, "函数体两个调用");
    assert!(f.body.use_names.is_empty(), "函数体无 use");
    // 参数引用：dst=b 右侧是 Value::Ident
    let ipv4_call = &f.body.layers[0];
    assert_eq!(ipv4_call.name, "ipv4");
    assert!(matches!(&ipv4_call.args[0].value, Value::Ident { name, .. } if name == "a"));
    assert!(matches!(&ipv4_call.args[1].value, Value::Ident { name, .. } if name == "b"));
}

#[test]
fn func_body_with_use() {
    let ast = parse("func f(p) { use(p) |> tcp(dport=80) }");
    let Stmt::Func(f) = &ast.stmts[0] else {
        panic!()
    };
    assert_eq!(f.body.use_names.len(), 1);
    assert_eq!(f.body.use_names[0].0, "p");
    assert_eq!(f.body.layers.len(), 1);
}

#[test]
fn func_param_ident_value() {
    // 位置参数也允许标识符（转发参数）
    let ast = parse("func f(a) { tcp(a) }");
    let Stmt::Func(f) = &ast.stmts[0] else {
        panic!()
    };
    assert!(matches!(&f.body.layers[0].args[0].value, Value::Ident { name, .. } if name == "a"));
}

#[test]
fn func_errors() {
    // 缺右括号
    let d = parse_err("func f(a { tcp() }");
    assert!(d.to_string().contains("期望"), "{}", d);
    // 缺函数体花括号
    let d2 = parse_err("func f() ipv4()");
    assert!(d2.to_string().contains("期望"), "{}", d2);
}
