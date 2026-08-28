//! 解析 .pkt 源码并打印 AST（调试用）
use packet_dsl::parser::parse_ast;

fn main() {
    let src = match std::env::args().nth(1) {
        Some(path) => std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读取 {path} 失败：{e}")),
        None => r#"# 包名 = b
import a { a, b }
export:
- full
full = use(a, b) |> tcp(dport=80) |> ipv4(src="1.1.1.1") |> eth()
req = arp(op="request", spa="192.168.1.1", tpa="192.168.1.2")
"#
        .to_string(),
    };
    match parse_ast(&src) {
        Ok(ast) => println!("{:#?}", ast.stmts),
        Err(e) => eprintln!("错误: {e}"),
    }
}
