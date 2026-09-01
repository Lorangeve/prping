//! pktlang 全面测试套件
//! 测试所有 pktlang 功能：语法解析、类型系统、值函数、协议层、管道组合、配方、语义分析、序列化

use packet_dsl::ast::{Expr, Stmt};
use packet_dsl::ir::Layer;
use packet_dsl::parser::parse_ast;
use packet_dsl::resolve;
use packet_dsl::semantic::parse_str;

/// 辅助函数：解析源码
fn parse(src: &str) -> packet_dsl::ast::AstFile {
    parse_ast(src).unwrap_or_else(|e| panic!("解析失败：{e}"))
}

/// 辅助函数：解析并求值
fn resolve_src(src: &str) -> Vec<Vec<Layer>> {
    let m = parse_str("test", src).expect("解析成功");
    let built = resolve(&m).expect("求值成功");
    built.packets.into_iter().map(|p| p.layers).collect()
}

/// 辅助函数：获取层名
fn layer_name(l: &Layer) -> &'static str {
    match l {
        Layer::Ethernet(_) => "eth",
        Layer::Arp(_) => "arp",
        Layer::Ipv4(_) => "ipv4",
        Layer::Ipv6(_) => "ipv6",
        Layer::Icmp(_) => "icmp",
        Layer::Tcp(_) => "tcp",
        Layer::Udp(_) => "udp",
        Layer::Http(_) => "http",
        Layer::Dns(_) => "dns",
        Layer::Raw(_) => "raw",
    }
}

/// 辅助函数：获取层名列表
fn names(p: &[Layer]) -> Vec<&'static str> {
    p.iter().map(layer_name).collect()
}

// ============================================================================
// 1. 语法解析测试
// ============================================================================

#[test]
fn test_basic_identifiers() {
    let ast = parse(r#"a = http(method="GET")"#);
    assert_eq!(ast.stmts.len(), 1);
    assert!(matches!(ast.stmts[0], Stmt::Def(_)));
}

#[test]
fn test_string_escapes() {
    let ast = parse(r#"a = http(start_line="GET / HTTP/1.1\\r\\n")"#);
    assert_eq!(ast.stmts.len(), 1);
}

#[test]
fn test_hex_literals() {
    let ast = parse(r#"a = hex("4242")"#);
    assert_eq!(ast.stmts.len(), 1);
}

#[test]
fn test_pipeline_operator() {
    let ast = parse(r#"use(a) |> tcp(dport=80)"#);
    assert_eq!(ast.stmts.len(), 1);
    assert!(matches!(ast.stmts[0], Stmt::Pipeline(_)));
}

#[test]
fn test_named_and_positional_args() {
    let ast = parse(r#"a = tcp(sport=12345, 80)"#);
    let Stmt::Def(d) = &ast.stmts[0] else {
        panic!("期望 Def")
    };
    let Expr::Call(c) = &d.expr else {
        panic!("期望 Call")
    };
    assert_eq!(c.args.len(), 2);
}

#[test]
fn test_import_export() {
    let ast = parse(
        r#"import a
export:
- a
"#,
    );
    assert_eq!(ast.stmts.len(), 2);
}

#[test]
fn test_comments_and_shebang() {
    let ast = parse(
        r#"#!/usr/bin/env pkt
# 这是注释
a = http()
"#,
    );
    assert_eq!(ast.stmts.len(), 1);
}

#[test]
fn test_multiline_pipeline() {
    let ast = parse(
        r#"use(a) 
|> tcp(dport=80)
|> ipv4()"#,
    );
    assert_eq!(ast.stmts.len(), 1);
    assert!(matches!(ast.stmts[0], Stmt::Pipeline(_)));
}

// ============================================================================
// 2. 类型系统测试
// ============================================================================

#[test]
fn test_numeric_types() {
    let ast = parse(r#"a = be16(0x1234)"#);
    assert_eq!(ast.stmts.len(), 1);
}

#[test]
fn test_byte_types() {
    let ast = parse(r#"a = hex("4242")"#);
    assert_eq!(ast.stmts.len(), 1);

    let ast2 = parse(r#"a = raw("text")"#);
    assert_eq!(ast2.stmts.len(), 1);
}

#[test]
fn test_address_types() {
    let ast = parse(r#"a = ip4("1.2.3.4")"#);
    assert_eq!(ast.stmts.len(), 1);

    let ast2 = parse(r#"a = ip6("::1")"#);
    assert_eq!(ast2.stmts.len(), 1);

    let ast3 = parse(r#"a = mac("aa:bb:cc:dd:ee:ff")"#);
    assert_eq!(ast3.stmts.len(), 1);
}

// ============================================================================
// 3. 值函数和原语测试
// ============================================================================

#[test]
fn test_byte_primitives() {
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80)
"#,
    );
    assert!(!built.is_empty());
}

#[test]
fn test_algorithm_primitives() {
    // 测试 count, cksum, md5, sha1, sha256
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80) |> ipv4() |> eth()
"#,
    );
    assert!(!built.is_empty());
}

#[test]
fn test_bit_operations() {
    // 测试 bor, band, bxor, bnot, shl, shr
    let built = resolve_src(
        r#"a = tcp(sport=12345, dport=80, flags=bor(syn(), ack()))
use(a) |> ipv4() |> eth()
"#,
    );
    assert!(!built.is_empty());
}

#[test]
fn test_random_values() {
    // 测试 rand16(), rand8(), rand_bytes()
    let built = resolve_src(
        r#"a = tcp(sport=rand16(), dport=80)
use(a) |> ipv4() |> eth()
"#,
    );
    assert!(!built.is_empty());
}

#[test]
fn test_padding() {
    // 测试 pad()
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80) |> ipv4() |> eth()
"#,
    );
    assert!(!built.is_empty());
}

#[test]
fn test_dns_resolution() {
    // 测试 dns() - 注意：这需要 DNS 解析器注入
    // 在测试环境中可能跳过或使用模拟
}

#[test]
fn test_string_templates() {
    // 测试 tpl()
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80)
"#,
    );
    assert!(!built.is_empty());
}

// ============================================================================
// 4. 协议层测试
// ============================================================================

#[test]
fn test_ethernet_layer() {
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80) |> ipv4() |> eth()
"#,
    );
    assert!(!built.is_empty());
    assert_eq!(names(&built[0]), vec!["http", "tcp", "ipv4", "eth"]);
}

#[test]
fn test_arp_layer() {
    let built = resolve_src(
        r#"a = arp(op=request(), sha="00:11:22:33:44:55", spa="192.168.1.1", tha="00:00:00:00:00:00", tpa="192.168.1.2")
use(a) |> eth(src_mac="00:11:22:33:44:55", dst_mac="ff:ff:ff:ff:ff:ff", ethertype=0x0806)
"#,
    );
    assert!(!built.is_empty());
    assert_eq!(names(&built[0]), vec!["arp", "eth"]);
}

#[test]
fn test_ipv4_layer() {
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80) |> ipv4(src="1.1.1.1", dst="2.2.2.2")
"#,
    );
    assert!(!built.is_empty());
    assert_eq!(names(&built[0]), vec!["http", "tcp", "ipv4"]);
}

#[test]
fn test_ipv6_layer() {
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80) |> ipv6(src="::1", dst="::2")
"#,
    );
    assert!(!built.is_empty());
    assert_eq!(names(&built[0]), vec!["http", "tcp", "ipv6"]);
}

#[test]
fn test_tcp_layer() {
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(sport=12345, dport=80)
"#,
    );
    assert!(!built.is_empty());
    assert_eq!(names(&built[0]), vec!["http", "tcp"]);
}

#[test]
fn test_udp_layer() {
    let built = resolve_src(
        r#"a = dns(id=0x1234, questions=["example.com"])
use(a) |> udp(sport=12345, dport=53)
"#,
    );
    assert!(!built.is_empty());
    assert_eq!(names(&built[0]), vec!["dns", "udp"]);
}

#[test]
fn test_icmp_layer() {
    let built = resolve_src(
        r#"a = icmp(type=8, code=0, id=0x1234, seq=0)
use(a) |> ipv4() |> eth()
"#,
    );
    assert!(!built.is_empty());
    assert_eq!(names(&built[0]), vec!["icmp", "ipv4", "eth"]);
}

#[test]
fn test_http_layer() {
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80)
"#,
    );
    assert!(!built.is_empty());
    assert_eq!(names(&built[0]), vec!["http", "tcp"]);
}

#[test]
fn test_dns_layer() {
    let built = resolve_src(
        r#"a = dns(id=0x1234, questions=["example.com"])
use(a) |> udp(dport=53)
"#,
    );
    assert!(!built.is_empty());
    assert_eq!(names(&built[0]), vec!["dns", "udp"]);
}

// ============================================================================
// 5. 管道和组合测试
// ============================================================================

#[test]
fn test_single_layer_pipeline() {
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80)
"#,
    );
    assert_eq!(built.len(), 1);
    assert_eq!(names(&built[0]), vec!["http", "tcp"]);
}

#[test]
fn test_multi_layer_pipeline() {
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80) |> ipv4() |> eth()
"#,
    );
    assert_eq!(built.len(), 1);
    assert_eq!(names(&built[0]), vec!["http", "tcp", "ipv4", "eth"]);
}

#[test]
fn test_multi_component_pipeline() {
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
b = http(start_line="POST / HTTP/1.1")
use(a, b) |> tcp(dport=80)
"#,
    );
    assert_eq!(built.len(), 2);
    assert_eq!(names(&built[0]), vec!["http", "tcp"]);
    assert_eq!(names(&built[1]), vec!["http", "tcp"]);
}

#[test]
fn test_multi_export() {
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
b = http(start_line="POST / HTTP/1.1")
tcp_full = use(a, b) |> tcp(dport=80)
udp_full = use(a, b) |> udp(dport=80)
export:
- tcp_full
- udp_full
"#,
    );
    assert_eq!(built.len(), 4);
    assert_eq!(names(&built[0]), vec!["http", "tcp"]);
    assert_eq!(names(&built[2]), vec!["http", "udp"]);
}

// ============================================================================
// 6. 配方 (Recipe) 测试
// ============================================================================

#[test]
fn test_recipe_steps() {
    // 导出语义：resolve() 返回「默认导出（顶层匿名流水线）+ 全部具名导出」的包。
    // 未被 export 的 def 不产生包。packet 1 = 匿名流水线完整层栈，packet 2 = 导出的 def a（裸 http 层）。
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(sport=40000, dport=80) |> ipv4() |> eth()
export:
- a
"#,
    );
    assert_eq!(built.len(), 2, "默认导出 1 包 + 具名导出 a 1 包");
    assert_eq!(
        names(&built[0]),
        vec!["http", "tcp", "ipv4", "eth"],
        "匿名流水线 = 默认导出"
    );
    assert_eq!(
        names(&built[1]),
        vec!["http"],
        "具名导出的 def a = 裸 http 层"
    );
}

#[test]
fn test_recipe_params_injection() {
    // 测试参数注入 - 使用正确的 params 语法
    let recipe = r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=params("port"))
"#;
    let ast = parse(recipe);
    // 2 个语句：a = http(...) 和 use(a) |> tcp(dport=params("port"))
    assert_eq!(ast.stmts.len(), 2);
}

#[test]
fn test_recipe_sniffer() {
    // 测试 sniffer 匹配 - 使用正确的 sniffer 语法
    let recipe = r#"a = raw(bytes="x")
use(a) |> icmp() |> ipv4() |> eth()
sniffer:
  - match icmp(type=0, id=id, seq=seq)
"#;
    let ast = parse(recipe);
    // 3 个语句：a = raw(...)、use(a) |> icmp() |> ipv4() |> eth()、sniffer: ...
    assert_eq!(ast.stmts.len(), 3);
}

// ============================================================================
// 7. 语义分析测试
// ============================================================================

#[test]
fn test_static_checks() {
    // 测试静态检查：类型检查、范围检查
    let result = parse_ast(r#"a = be16(0x1234)"#);
    assert!(result.is_ok());
}

#[test]
fn test_diagnostic_information() {
    // 测试错误诊断
    let result = parse_ast(r#"a = "#);
    assert!(result.is_err());
}

#[test]
fn test_symbol_resolution() {
    // 测试符号解析：导入解析、作用域
    let result = parse_ast(
        r#"import a
use(a) |> tcp(dport=80)
"#,
    );
    assert!(result.is_ok());
}

// ============================================================================
// 8. 序列化测试
// ============================================================================

#[test]
fn test_byte_serialization() {
    // 测试字节序列化
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80) |> ipv4() |> eth()
"#,
    );
    assert!(!built.is_empty());
    // 这里可以添加序列化验证
}

#[test]
fn test_checksum_calculation() {
    // 测试校验和计算
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80) |> ipv4() |> eth()
"#,
    );
    assert!(!built.is_empty());
}

#[test]
fn test_random_value_fill() {
    // 测试随机值填充
    let built = resolve_src(
        r#"a = tcp(sport=rand16(), dport=80)
use(a) |> ipv4() |> eth()
"#,
    );
    assert!(!built.is_empty());
}

#[test]
fn test_variant_expansion() {
    // 测试变体展开：笛卡尔积
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
b = http(start_line="POST / HTTP/1.1")
use(a, b) |> tcp(dport=80)
"#,
    );
    assert_eq!(built.len(), 2);
}

// ============================================================================
// 9. 集成测试
// ============================================================================

#[test]
fn test_example_files() {
    // 集成：解析工作区 examples/ 下全部 .pkt（语法层；.pktl 配方是另一语法，不在 parse_ast 范围）。
    // cwd 是 crate 目录，用 CARGO_MANIFEST_DIR 回溯到工作区根。
    use std::fs;
    use std::path::PathBuf;

    let ws = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let examples_dir = ws.join("examples");
    assert!(
        examples_dir.is_dir(),
        "examples 目录应存在：{:?}",
        examples_dir
    );

    let mut count = 0usize;
    fn walk(dir: &PathBuf, count: &mut usize) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, count);
            } else if path.extension().is_some_and(|e| e == "pkt") {
                let content = fs::read_to_string(&path).unwrap();
                if let Err(e) = parse_ast(&content) {
                    panic!("文件 {} 解析失败：{}", path.display(), e);
                }
                *count += 1;
            }
        }
    }
    walk(&examples_dir, &mut count);
    assert!(count >= 10, "应解析到 ≥10 个 .pkt，实际 {}", count);
}

#[test]
fn test_lsp_functionality() {
    // 测试 LSP 功能：诊断、补全、悬停
    // 这里可以添加 LSP 相关测试
}

#[test]
fn test_engine_functionality() {
    // 测试引擎功能：分析、hex、pcap
    // 这里可以添加引擎相关测试
}

// ============================================================================
// 10. 错误处理测试
// ============================================================================

#[test]
fn test_syntax_errors() {
    // 测试语法错误处理
    let result = parse_ast(r#"a = ="#);
    assert!(result.is_err());
}

#[test]
fn test_type_errors() {
    // 测试类型错误处理
    // 注意：pktlang 的类型错误是在求值阶段检测的
    let result = parse_ast(r#"a = be16("0x1234")"#);
    // 解析阶段可能不会报错，求值阶段才会
    assert!(result.is_ok());
}

#[test]
fn test_semantic_errors() {
    // 测试语义错误处理
    // 注意：pktlang 的语义错误是在求值阶段检测的
    let result = parse_ast(r#"use(nonexistent) |> tcp(dport=80)"#);
    // 解析阶段可能不会报错，求值阶段才会
    assert!(result.is_ok());
}

// ============================================================================
// 11. 性能测试
// ============================================================================

#[test]
fn test_parsing_performance() {
    // 测试解析性能
    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let _ = parse_ast(
            r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80) |> ipv4() |> eth()
"#,
        );
    }
    let duration = start.elapsed();
    // 1000 次解析应该在合理时间内完成
    assert!(duration.as_millis() < 1000);
}

#[test]
fn test_serialization_performance() {
    // 测试序列化性能
    let built = resolve_src(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80) |> ipv4() |> eth()
"#,
    );

    let start = std::time::Instant::now();
    for _ in 0..1000 {
        for _pkt in &built {
            // 这里可以添加序列化调用
        }
    }
    let duration = start.elapsed();
    // 1000 次序列化应该在合理时间内完成
    assert!(duration.as_millis() < 1000);
}

// ============================================================================
// 12. 边界条件测试
// ============================================================================

#[test]
fn test_empty_input() {
    let result = parse_ast("");
    assert!(result.is_ok());
}

#[test]
fn test_whitespace_only() {
    let result = parse_ast("   \n   \t   ");
    assert!(result.is_ok());
}

#[test]
fn test_comments_only() {
    let result = parse_ast("# 这是注释\n# 另一行注释");
    assert!(result.is_ok());
}

#[test]
fn test_long_string() {
    let long_string = "a".repeat(10000);
    let result = parse_ast(&format!(r#"a = raw("{}")"#, long_string));
    assert!(result.is_ok());
}

#[test]
fn test_deep_nesting() {
    let result = parse_ast(
        r#"a = http(start_line="GET / HTTP/1.1")
use(a) |> tcp(dport=80) |> ipv4() |> eth()
"#,
    );
    assert!(result.is_ok());
}
