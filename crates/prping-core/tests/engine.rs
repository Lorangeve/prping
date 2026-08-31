//! 引擎模式测试：LSP JSON-RPC 会话（诊断 / 补全 / 悬停 / 文档符号）。
//!
//! 通过 `run_lsp_on` 把会话跑在内存读写对里，验证协议层行为。

use std::io::{Cursor, Read, Write};

use prping_core::run_lsp_on;
use serde_json::{Value, json};

/// 构造一条分帧消息写入 writer。
fn write_frame(w: &mut impl Write, msg: &Value) {
    let body = serde_json::to_vec(msg).unwrap();
    write!(w, "Content-Length: {}\r\n\r\n", body.len()).unwrap();
    w.write_all(&body).unwrap();
}

/// 从 reader 读一条分帧消息（读到 EOF 返回 None）。
fn read_frame(r: &mut impl Read) -> Option<Value> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return None,
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length:"))
        .and_then(|v| v.trim().parse().ok())?;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).ok()?;
    serde_json::from_slice(&body).ok()
}

/// 运行一次完整会话，返回 (诊断通知, 各请求响应)。
fn run_session(frames: Vec<Value>) -> Vec<Value> {
    let mut input: Vec<u8> = Vec::new();
    for f in &frames {
        write_frame(&mut input, f);
    }
    let mut output = Cursor::new(Vec::new());
    run_lsp_on(&mut Cursor::new(input), &mut output, &[]).expect("LSP 会话不应崩溃");
    let mut r = Cursor::new(output.into_inner());
    let mut out = Vec::new();
    while let Some(m) = read_frame(&mut r) {
        out.push(m);
    }
    out
}

fn req(id: i64, method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

fn notif(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "method": method, "params": params })
}

const URI: &str = "file:///tmp/probe.pkt";

#[test]
fn initialize_returns_capabilities() {
    let msgs = run_session(vec![req(1, "initialize", json!({"capabilities": {}}))]);
    assert_eq!(msgs.len(), 1);
    let caps = &msgs[0]["result"]["capabilities"];
    assert_eq!(caps["textDocumentSync"], 1);
    assert_eq!(caps["hoverProvider"], true);
    assert_eq!(caps["documentSymbolProvider"], true);
    assert!(caps["completionProvider"]["triggerCharacters"].is_array());
    assert_eq!(msgs[0]["result"]["serverInfo"]["name"], "prping packet-dsl");
}

#[test]
fn did_open_publishes_diagnostics_for_broken_doc() {
    let msgs = run_session(vec![notif(
        "textDocument/didOpen",
        json!({
            "textDocument": { "uri": URI, "languageId": "pkt", "version": 1,
                              "text": "a = tcp(dport=80)\nuse(a) |> udp( dport=53\n" }
        }),
    )]);
    let diag = &msgs[0]["params"]["diagnostics"];
    assert_eq!(
        diag.as_array().map(|a| a.len()),
        Some(1),
        "应有 1 条诊断：{msgs:?}"
    );
    let d = &diag[0];
    assert_eq!(d["severity"], 1);
    assert_eq!(d["source"], "packet-dsl");
    assert!(d["message"].as_str().unwrap().contains("期望"));
    // span 落在第二行（0 基 line=1）
    assert_eq!(d["range"]["start"]["line"], 1);
}

#[test]
fn did_change_updates_diagnostics() {
    let msgs = run_session(vec![
        notif(
            "textDocument/didOpen",
            json!({
                "textDocument": { "uri": URI, "languageId": "pkt", "version": 1, "text": "a = tcp()\n" }
            }),
        ),
        notif(
            "textDocument/didChange",
            json!({
                "textDocument": { "uri": URI, "version": 2 },
                "contentChanges": [{ "text": "a = tcp((\n" }]
            }),
        ),
    ]);
    // didOpen：无诊断（合法文件）；didChange：有诊断
    assert_eq!(
        msgs[0]["params"]["diagnostics"].as_array().unwrap().len(),
        0
    );
    assert_eq!(
        msgs[1]["params"]["diagnostics"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn completion_offers_keywords_and_builtins() {
    let msgs = run_session(vec![
        notif(
            "textDocument/didOpen",
            json!({
                "textDocument": { "uri": URI, "languageId": "pkt", "version": 1, "text": "a = tcp()\n" }
            }),
        ),
        req(
            2,
            "textDocument/completion",
            json!({
                // 语句关键字位（光标前无部分词；服务端按部分词前缀过滤候选）
                "textDocument": { "uri": URI }, "position": { "line": 0, "character": 0 }
            }),
        ),
    ]);
    let items = &msgs[1]["result"]["items"];
    let items = items.as_array().unwrap();
    let labels: Vec<&str> = items.iter().map(|i| i["label"].as_str().unwrap()).collect();
    // 顶层语句位：只给语句关键字与注解（该位不接受调用/原语）
    for kw in ["use", "func", "export:", "import", "#[proto]"] {
        assert!(labels.contains(&kw), "缺少语句关键字 {kw}: {labels:?}");
    }
    assert!(
        !labels.contains(&"tcp") && !labels.contains(&"u8"),
        "顶层语句位不应混入调用名: {labels:?}"
    );

    // 层位（|> 之后）：层头/内置层原语/库导出都在
    let msgs = run_session(vec![
        notif(
            "textDocument/didOpen",
            json!({
                "textDocument": { "uri": URI, "languageId": "pkt", "version": 1,
                                  "text": "a = tcp()\nfull = use(a) |>\n" }
            }),
        ),
        req(
            2,
            "textDocument/completion",
            json!({
                "textDocument": { "uri": URI }, "position": { "line": 1, "character": 16 }
            }),
        ),
    ]);
    let items = &msgs[1]["result"]["items"];
    let items = items.as_array().unwrap();
    let labels: Vec<&str> = items.iter().map(|i| i["label"].as_str().unwrap()).collect();
    // 引擎原语（raw/hex/layer）
    for b in ["raw", "hex", "layer"] {
        assert!(labels.contains(&b), "层位缺少内置原语 {b}: {labels:?}");
    }
    // 层头函数与 *_bytes 具名包装来自 eng_lib 库导出（隐式可见，无需 import）
    for b in [
        "eth",
        "arp",
        "ipv4",
        "ipv6",
        "icmp",
        "tcp",
        "udp",
        "http",
        "dns",
        "eth_bytes",
        "ipv4_bytes",
        "tcp_bytes",
        "dns_bytes",
    ] {
        assert!(labels.contains(&b), "层位缺少库导出 {b}: {labels:?}");
    }
    // tcp 是库函数：detail 带 func 签名
    let tcp = items.iter().find(|i| i["label"] == "tcp").unwrap();
    assert!(
        tcp["detail"].as_str().unwrap().contains("-> bytes tcp("),
        "tcp detail: {:?}",
        tcp["detail"]
    );

    // 值位（dport= 之后，光标在值前）：值原语与本地元件在列，层头不出现
    let msgs = run_session(vec![
        notif(
            "textDocument/didOpen",
            json!({
                "textDocument": { "uri": URI, "languageId": "pkt", "version": 1,
                                  "text": "a = tcp()\nfull = use(a) |> udp(dport=53)\n" }
            }),
        ),
        req(
            2,
            "textDocument/completion",
            json!({
                "textDocument": { "uri": URI }, "position": { "line": 1, "character": 27 }
            }),
        ),
    ]);
    let items = &msgs[1]["result"]["items"];
    let items = items.as_array().unwrap();
    let labels: Vec<&str> = items.iter().map(|i| i["label"].as_str().unwrap()).collect();
    for b in ["hex", "raw", "u8", "params", "concat"] {
        assert!(labels.contains(&b), "值位缺少值原语 {b}: {labels:?}");
    }
    assert!(labels.contains(&"a"), "值位应可引用本地元件 a: {labels:?}");
    assert!(
        !labels.contains(&"eth") && !labels.contains(&"ipv4"),
        "值位不应有层头: {labels:?}"
    );
}

#[test]
fn hover_shows_lib_func_docs() {
    let msgs = run_session(vec![
        notif(
            "textDocument/didOpen",
            json!({
                "textDocument": { "uri": URI, "languageId": "pkt", "version": 1, "text": "use(a) |> udp(dport=53)\n" }
            }),
        ),
        req(
            3,
            "textDocument/hover",
            json!({
                "textDocument": { "uri": URI }, "position": { "line": 0, "character": 11 }
            }),
        ),
    ]);
    let contents = &msgs[1]["result"]["contents"]["value"];
    let md = contents.as_str().unwrap();
    // udp 现在是 eng_lib 库 proto（自表示协议，隐式可见）：显示 `#[proto] func` 签名与字段
    assert!(md.contains("### `#[proto] func ... -> bytes udp("), "{md}");
    assert!(md.contains("库模块"), "{md}");
    assert!(md.contains("sport"), "{md}");
}

#[test]
fn hover_on_unknown_word_is_null() {
    let msgs = run_session(vec![
        notif(
            "textDocument/didOpen",
            json!({
                "textDocument": { "uri": URI, "languageId": "pkt", "version": 1,
                                  "text": "a = tcp()\nbogus_thing()\n" }
            }),
        ),
        req(
            4,
            "textDocument/hover",
            json!({
                "textDocument": { "uri": URI }, "position": { "line": 1, "character": 3 }
            }),
        ),
    ]);
    // 未知名字（非内置/本地/库/元件/参数）仍为无提示
    assert_eq!(msgs[1]["result"], Value::Null);
}

#[test]
fn hover_on_local_def_shows_component() {
    // 本地元件悬停：定义 + 片段（此前恒为无提示）
    let msgs = run_session(vec![
        notif(
            "textDocument/didOpen",
            json!({
                "textDocument": { "uri": URI, "languageId": "pkt", "version": 1, "text": "a = tcp()\n" }
            }),
        ),
        req(
            4,
            "textDocument/hover",
            json!({
                "textDocument": { "uri": URI }, "position": { "line": 0, "character": 1 }
            }),
        ),
    ]);
    let md = msgs[1]["result"]["contents"]["value"].as_str().unwrap();
    assert!(md.contains("`a`") && md.contains("元件"), "{md}");
    assert!(md.contains("a = tcp()"), "{md}");
}

#[test]
fn document_symbol_lists_defs_and_exports() {
    let msgs = run_session(vec![
        notif(
            "textDocument/didOpen",
            json!({
                "textDocument": { "uri": URI, "languageId": "pkt", "version": 1,
                                  "text": "export:\n- full\na = http()\nfull = use(a) |> tcp(dport=80)\n" }
            }),
        ),
        req(
            5,
            "textDocument/documentSymbol",
            json!({
                "textDocument": { "uri": URI }
            }),
        ),
    ]);
    let syms = msgs[1]["result"].as_array().unwrap();
    let names: Vec<&str> = syms.iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"a"), "{names:?}");
    assert!(names.contains(&"full"), "{names:?}");
    assert!(names.contains(&"full"), "export 引用同一元件");
    // selectionRange 应指向名字
    let a = syms.iter().find(|s| s["name"] == "a").unwrap();
    assert_eq!(a["selectionRange"]["start"]["line"], 2);
}

#[test]
fn unknown_method_returns_error() {
    let msgs = run_session(vec![req(9, "bogus/method", json!({}))]);
    assert_eq!(msgs[0]["error"]["code"], -32601);
    assert_eq!(msgs[0]["id"], 9);
}

#[test]
fn shutdown_then_exit_terminates() {
    let msgs = run_session(vec![
        req(7, "shutdown", json!({})),
        notif("exit", json!({})),
    ]);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["id"], 7);
    assert_eq!(msgs[0]["result"], Value::Null);
}

#[test]
fn malformed_body_gets_parse_error() {
    // 直接喂非法 JSON
    let input = b"Content-Length: 5\r\n\r\n{}{}{";
    let mut output = Cursor::new(Vec::new());
    run_lsp_on(&mut Cursor::new(input.to_vec()), &mut output, &[]).expect("不应崩溃");
    let mut r = Cursor::new(output.into_inner());
    let m = read_frame(&mut r).expect("应有响应");
    assert_eq!(m["error"]["code"], -32700);
}

// ── 函数：补全 / 文档符号 / 悬停 ─────────────────────────────

#[test]
fn completion_includes_funcs() {
    let msgs = run_session(vec![
        notif(
            "textDocument/didOpen",
            json!({
                "textDocument": { "uri": URI, "languageId": "pkt", "version": 1,
                    "text": "func net4(dst, src=\"random\") { ipv4(src=src, dst=dst) |> eth() }\nuse(a) |> net4(dst=\"1.2.3.4\")\na = http()\n" }
            }),
        ),
        req(
            3,
            "textDocument/completion",
            json!({ "textDocument": { "uri": URI }, "position": { "line": 1, "character": 10 } }),
        ),
    ]);
    let items = msgs[1]["result"]["items"].as_array().unwrap();
    let f = items.iter().find(|i| i["label"] == "net4").unwrap();
    assert_eq!(f["kind"], 3, "函数 kind=Function");
    assert!(
        f["detail"]
            .as_str()
            .unwrap()
            .contains("func net4(dst, src=\"random\")")
    );
}

#[test]
fn document_symbol_includes_funcs() {
    let msgs = run_session(vec![
        notif(
            "textDocument/didOpen",
            json!({
                "textDocument": { "uri": URI, "languageId": "pkt", "version": 1,
                    "text": "func wrap(dport) { tcp(dport=dport) }\nuse(wrap)\n" }
            }),
        ),
        req(
            3,
            "textDocument/documentSymbol",
            json!({ "textDocument": { "uri": URI } }),
        ),
    ]);
    let syms = msgs[1]["result"].as_array().unwrap();
    let f = syms.iter().find(|s| s["name"] == "wrap").unwrap();
    assert_eq!(f["kind"], 12, "函数 kind=Function");
    assert!(f["detail"].as_str().unwrap().contains("func wrap(dport)"));
}

#[test]
fn hover_shows_func_signature() {
    let msgs = run_session(vec![
        notif(
            "textDocument/didOpen",
            json!({
                "textDocument": { "uri": URI, "languageId": "pkt", "version": 1,
                    "text": "func wrap(dport, flags=\"syn\") { tcp(dport=dport, flags=flags) }\nuse(wrap)\n" }
            }),
        ),
        req(
            3,
            "textDocument/hover",
            json!({ "textDocument": { "uri": URI }, "position": { "line": 0, "character": 6 } }),
        ),
    ]);
    let md = msgs[1]["result"]["contents"]["value"].as_str().unwrap();
    assert!(md.contains("### `func wrap("), "{md}");
    assert!(md.contains("`dport`"), "{md}");
    assert!(md.contains("`flags=\"syn\"`"), "{md}");
    assert!(md.contains("未设（省略 → 自动值）"), "{md}");
}

// ── --lib 库目录：analyze_file 携带 libs 解析 import ─────────

/// 入口文件 import util；库目录在入口目录之外，只有显式 libs 才能解析。
/// 注意：模块名不能与默认 eng_lib 撞名（net/data/headers 已在 eng_lib 中）。
#[test]
fn analyze_file_with_libs_resolves_imports() {
    let entry = std::env::temp_dir().join(format!("pkt-lib-entry-{}", std::process::id()));
    let lib = std::env::temp_dir().join(format!("pkt-lib-lib-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&entry);
    let _ = std::fs::remove_dir_all(&lib);
    std::fs::create_dir_all(&entry).unwrap();
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::write(
        lib.join("util.pkt"),
        "func net4(dst) { ipv4(dst=dst) |> eth() }\nexport:\n- net4\n",
    )
    .unwrap();
    let main = entry.join("main.pkt");
    std::fs::write(
        &main,
        "import util { net4 }\np = raw(bytes=\"x\")\nuse(p) |> net4(dst=\"1.2.3.4\")\n",
    )
    .unwrap();

    // 无 libs → 找不到模块
    let out = prping_core::analyze_file(&main, &[], &packet_dsl::Globals::new(), &[]).unwrap_err();
    assert!(out.to_string().contains("找不到模块"), "{out}");

    // 带 libs → 成功
    prping_core::analyze_file(
        &main,
        &[],
        &packet_dsl::Globals::new(),
        std::slice::from_ref(&lib),
    )
    .expect("带 libs 应成功");

    let _ = std::fs::remove_dir_all(&entry);
    let _ = std::fs::remove_dir_all(&lib);
}
