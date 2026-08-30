//! LSP 语言服务器（`engine --lsp`）：JSON-RPC over stdio，提供诊断 / 补全 / 悬停 / 文档符号。

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use packet_dsl::diag::Diagnostic;
use packet_dsl::registry::builtin_doc;
use packet_dsl::semantic::Module;
use serde_json::{Value, json};

use super::{doc_markdown, value_display};

/// LSP 服务器入口（stdio）；`libs` 为 pkglang 库目录（import 解析用）。
pub fn run_lsp(libs: &[std::path::PathBuf]) -> anyhow::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_lsp_on(stdin.lock(), stdout.lock(), libs)
}

/// 可测试的 LSP 循环：读写任意 `Read + Write`。
pub fn run_lsp_on<R: Read, W: Write>(
    reader: R,
    writer: W,
    libs: &[std::path::PathBuf],
) -> anyhow::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    let mut server = LspServer {
        libs: libs.to_vec(),
        ..LspServer::default()
    };
    loop {
        match read_message(&mut reader) {
            Ok(Some(msg)) => {
                let cont = server.handle(&msg, &mut writer)?;
                writer.flush()?;
                if !cont {
                    break;
                }
            }
            Ok(None) => break, // EOF
            Err(e) => {
                let resp = error_response(Value::Null, -32700, format!("parse error: {e}"));
                write_message(&mut writer, &resp)?;
            }
        }
    }
    Ok(())
}

/// 读取一条 Content-Length 分帧的 JSON-RPC 消息。
fn read_message<R: BufRead>(reader: &mut R) -> io::Result<Option<Value>> {
    let mut len: Option<usize> = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None); // EOF
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Content-Length:") {
            len = rest.trim().parse::<usize>().ok();
        }
    }
    // Content-Length 无上限校验时，恶意/异常客户端可触发数 GB 分配（OOM）
    const MAX_LSP_MSG: usize = 16 * 1024 * 1024;
    let len =
        len.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length"))?;
    if len > MAX_LSP_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Content-Length {len} exceeds {MAX_LSP_MSG}"),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    let msg =
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}

/// 写一条 Content-Length 分帧的 JSON-RPC 消息。
fn write_message<W: Write>(writer: &mut W, msg: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(msg)?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(&body)?;
    Ok(())
}

fn response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

fn notify(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "method": method, "params": params })
}

/// LSP 服务器状态。
#[derive(Default)]
struct LspServer {
    /// uri → 文档文本（full sync）。
    docs: HashMap<String, String>,
    shutdown: bool,
    /// pkglang 库目录（import 解析）。
    libs: Vec<PathBuf>,
    /// 库导出缓存：LSP 进程内 libs 固定，悬停/补全高频调用避免每次全量重读重解析库文件。
    lib_exports_cache: OnceLock<Vec<packet_dsl::LibExport>>,
}

impl LspServer {
    /// 库导出（进程内只解析一次；libs 构造后不变）。
    fn lib_exports_cached(&self) -> &[packet_dsl::LibExport] {
        self.lib_exports_cache
            .get_or_init(|| packet_dsl::lib_exports(&self.libs))
    }
    /// 处理一条消息；返回 false = 退出循环（exit 通知 / shutdown 后）。
    fn handle<W: Write>(&mut self, msg: &Value, w: &mut W) -> io::Result<bool> {
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let id = msg.get("id").cloned();
        let is_request = id.is_some();

        match method {
            "initialize" => {
                if let Some(id) = id {
                    let caps = json!({
                        "capabilities": {
                            "textDocumentSync": 1,
                            "completionProvider": { "triggerCharacters": [">", "(", ",", " "] },
                            "hoverProvider": true,
                            "documentSymbolProvider": true,
                            "definitionProvider": true
                        },
                        "serverInfo": {
                            "name": "prping packet-dsl",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    });
                    write_message(w, &response(id, caps))?;
                }
            }
            "initialized" => {}
            "shutdown" => {
                self.shutdown = true;
                if let Some(id) = id {
                    write_message(w, &response(id, Value::Null))?;
                }
            }
            "exit" => return Ok(false),
            "textDocument/didOpen" => {
                self.on_did_open(msg);
                self.publish_diagnostics_for(msg, w)?;
            }
            "textDocument/didChange" => {
                self.on_did_change(msg);
                self.publish_diagnostics_for(msg, w)?;
            }
            "textDocument/completion" => {
                if let Some(id) = id {
                    let items = self.completion(msg);
                    write_message(
                        w,
                        &response(id, json!({ "isIncomplete": false, "items": items })),
                    )?;
                }
            }
            "textDocument/hover" => {
                if let Some(id) = id {
                    let hover = self.hover(msg);
                    write_message(w, &response(id, hover))?;
                }
            }
            "textDocument/documentSymbol" => {
                if let Some(id) = id {
                    let symbols = self.document_symbol(msg);
                    write_message(w, &response(id, symbols))?;
                }
            }
            "textDocument/definition" => {
                if let Some(id) = id {
                    let defs = self.definition(msg);
                    write_message(w, &response(id, defs))?;
                }
            }
            "$/cancelRequest" | "workspace/didChangeConfiguration" => {}
            _ => {
                if is_request {
                    write_message(
                        w,
                        &error_response(id.unwrap_or(Value::Null), -32601, "method not found"),
                    )?;
                }
            }
        }
        Ok(true)
    }

    fn on_did_open(&mut self, msg: &Value) {
        let params = &msg["params"];
        if let (Some(uri), Some(text)) = (
            params["textDocument"]["uri"].as_str(),
            params["textDocument"]["text"].as_str(),
        ) {
            self.docs.insert(uri.to_string(), text.to_string());
        }
    }

    fn on_did_change(&mut self, msg: &Value) {
        let params = &msg["params"];
        let uri = params["textDocument"]["uri"].as_str().unwrap_or("");
        // full sync：取最后一条 contentChanges 的 text
        if let Some(changes) = params["contentChanges"].as_array()
            && let Some(last) = changes.last()
            && let Some(text) = last["text"].as_str()
        {
            self.docs.insert(uri.to_string(), text.to_string());
        }
    }

    /// 解析文档并推送诊断（didOpen / didChange 后）。
    fn publish_diagnostics_for<W: Write>(&self, msg: &Value, w: &mut W) -> io::Result<()> {
        let params = &msg["params"];
        let uri = params["textDocument"]["uri"].as_str().unwrap_or("");
        let version = params["textDocument"]["version"].as_i64();
        let diags = self.diagnostics(uri);
        let mut p = json!({ "uri": uri, "diagnostics": diags });
        if let Some(v) = version {
            p["version"] = json!(v);
        }
        write_message(w, &notify("textDocument/publishDiagnostics", p))
    }

    fn text_of(&self, uri: &str) -> Option<&str> {
        self.docs.get(uri).map(String::as_str)
    }

    /// 诊断：解析 → 首个错误（带行/列）。
    fn diagnostics(&self, uri: &str) -> Vec<Value> {
        let Some(text) = self.text_of(uri) else {
            return vec![];
        };
        analyze(text, uri, &self.libs)
    }

    fn completion(&self, msg: &Value) -> Vec<Value> {
        let uri = msg["params"]["textDocument"]["uri"].as_str().unwrap_or("");
        let mut items = Vec::new();
        for kw in ["export", "import", "use", "true", "false"] {
            items.push(json!({
                "label": kw,
                "kind": 14, // Keyword
                "insertText": kw,
            }));
        }
        // 引擎原语（builtin_docs 全量：层位置 raw/hex/layer + 值位置字节原语/flags/
        // params）。名字同时是库/本地函数（如 dns：值原语与层函数同名）时
        // 跳过——函数条目在后面按作用域加入，避免重复补全项。
        let func_names: std::collections::HashSet<&str> = self
            .lib_exports_cached()
            .iter()
            .filter(|e| e.params.is_some())
            .map(|e| e.name.as_str())
            .collect();
        for doc in packet_dsl::registry::builtin_docs() {
            if func_names.contains(doc.name) {
                continue;
            }
            let params: Vec<String> = doc.params.iter().map(|(n, _)| n.to_string()).collect();
            let insert = if doc.name == "params" {
                "params(\"\")".to_string()
            } else {
                format!("{}()", doc.name)
            };
            items.push(json!({
                "label": doc.name,
                "kind": 3, // Function
                "detail": format!("{}({})", doc.name, params.join(", ")),
                "documentation": {
                    "kind": "markdown",
                    "value": format!("{}\n\n**行为**：{}", doc.summary, doc.auto)
                },
                "insertText": insert,
            }));
        }
        // 元件名（若文档可解析）
        if let Some(text) = self.text_of(uri)
            && let Ok(module) = try_parse(text, uri, &self.libs)
        {
            for def in &module.defs {
                items.push(json!({
                    "label": def.name,
                    "kind": 6, // Variable
                    "detail": "component",
                }));
            }
            for f in &module.funcs {
                let params: Vec<String> = f
                    .params
                    .iter()
                    .map(|p| match &p.default {
                        Some(d) => format!("{}={}", p.name, value_display(d)),
                        None => p.name.clone(),
                    })
                    .collect();
                items.push(json!({
                    "label": f.name,
                    "kind": 3, // Function
                    "detail": format!("func {}({})", f.name, params.join(", ")),
                    "insertText": format!("{}()", f.name),
                }));
            }
            for (name, _) in &module.exports {
                items.push(json!({
                    "label": name,
                    "kind": 6,
                    "detail": "export",
                }));
            }
            if module.default.is_some() {
                items.push(json!({
                    "label": module.name,
                    "kind": 9, // Module
                    "detail": "default export",
                }));
            }
        }
        // 库导出（隐式可见，无需 import）：函数签名与元件。
        // 放在本地定义之后——本地同名定义优先（遮蔽库导出）。
        let mut labels: std::collections::HashSet<String> = items
            .iter()
            .filter_map(|i| i["label"].as_str().map(str::to_string))
            .collect();
        for exp in self.lib_exports_cached() {
            if labels.contains(&exp.name) {
                continue;
            }
            if let Some(params) = &exp.params {
                let ps: Vec<String> = params
                    .iter()
                    .map(|p| match &p.default {
                        Some(d) => format!("{}={}", p.name, value_display(d)),
                        None => p.name.clone(),
                    })
                    .collect();
                items.push(json!({
                    "label": exp.name,
                    "kind": 3, // Function
                    "detail": format!(
                        "{}{}({})  [{}]",
                        if exp.is_proto { "#[proto] func ... -> bytes " } else { "func " },
                        exp.name,
                        ps.join(", "),
                        exp.module
                    ),
                    "insertText": format!("{}()", exp.name),
                }));
            } else {
                items.push(json!({
                    "label": exp.name,
                    "kind": 6, // Variable
                    "detail": format!("export [{}]", exp.module),
                }));
            }
            labels.insert(exp.name.clone());
        }
        items
    }

    fn hover(&self, msg: &Value) -> Value {
        let uri = msg["params"]["textDocument"]["uri"].as_str().unwrap_or("");
        let pos = &msg["params"]["position"];
        let (line, character) = (
            pos["line"].as_i64().unwrap_or(0) as usize,
            pos["character"].as_i64().unwrap_or(0) as usize,
        );
        let Some(text) = self.text_of(uri) else {
            return Value::Null;
        };
        let Some(word) = word_at(text, line, character) else {
            return Value::Null;
        };
        // 内置原语文档。名字同时是库导出函数（如 dns：值原语与 eng_lib 层函数同名）
        // 时跳过——层位置函数更常用，交给下面的库函数悬停分支展示完整签名。
        let is_lib_func = self
            .lib_exports_cached()
            .iter()
            .any(|e| e.name == word && e.params.is_some());
        if !is_lib_func && let Some(doc) = builtin_doc(&word) {
            // 与库函数悬停同构：签名（参数名）+ 摘要 + 行为 + 参数说明
            let sig: Vec<String> = doc.params.iter().map(|(n, _)| n.to_string()).collect();
            let mut md = format!("### `{}({})`\n\n", doc.name, sig.join(", "));
            if !doc.summary.is_empty() {
                md.push_str(&format!("{}\n\n", doc.summary));
            }
            md.push_str(&format!("**行为**：{}\n", doc.auto));
            if !doc.params.is_empty() {
                md.push_str("\n**参数**\n\n");
                for (n, t) in &doc.params {
                    md.push_str(&format!("- `{n}`: {t}\n"));
                }
            }
            return json!({ "contents": { "kind": "markdown", "value": md } });
        }
        if matches!(word.as_str(), "export" | "import" | "use") {
            let help = match word.as_str() {
                "export" => "声明导出元件：`export:` 后跟 `- 名字` 列表。",
                "import" => "引入其他模块的元件：`import a { a, b }` 或 `import a`（全部导出）。",
                _ => "开始一条流水线：`use(a, b) |> tcp(dport=443) |> ipv4()`。",
            };
            return json!({ "contents": { "kind": "markdown", "value": format!("### `{word}`\n\n{help}") } });
        }
        if word == "func" {
            return json!({ "contents": { "kind": "markdown", "value":
                "### `func name(p1, p2=默认) { pipeline }`\n\n具名参数化函数：参数全部可选——无默认值的参数未传时为「未设」（在层参数位置省略 → 自动值），有默认值则用默认。函数体无 `use` 时以空包种子逐层包裹（层片段语义）。\n\n例：\n\n```\nfunc net4(dst, src=\"random\", ttl=64) {\n    ipv4(src=src, dst=dst, ttl=ttl) |> eth()\n}\n```" } });
        }
        // 用户函数悬停（若文档可解析）
        if let Some(text) = self.text_of(uri)
            && let Ok(module) = try_parse(text, uri, &self.libs)
            && let Some(f) = module.funcs.iter().find(|f| f.name == word)
        {
            let params: Vec<String> = f
                .params
                .iter()
                .map(|p| match &p.default {
                    Some(d) => format!("`{}={}`", p.name, value_display(d)),
                    None => format!("`{}`", p.name),
                })
                .collect();
            let mut md = format!("### `func {}({})`\n\n", f.name, params.join(", "));
            if let Some(doc) = &f.doc {
                md.push_str(&doc_markdown(doc));
            }
            md.push_str("**参数**（全部可选）：\n\n");
            for p in &f.params {
                let default = match &p.default {
                    Some(d) => format!("默认 `{}`", value_display(d)),
                    None => "未设（省略 → 自动值）".to_string(),
                };
                let desc = f
                    .doc
                    .as_ref()
                    .and_then(|d| d.params.iter().find(|(n, _)| n == &p.name))
                    .map(|(_, t)| format!("——{t}"))
                    .unwrap_or_default();
                md.push_str(&format!("- `{}`：{default}{desc}\n", p.name));
            }
            return json!({ "contents": { "kind": "markdown", "value": md } });
        }
        // 库导出函数（隐式可见）：与用户函数同格式，标注来源模块
        if let Some(exp) = self
            .lib_exports_cached()
            .iter()
            .find(|e| e.name == word && e.params.is_some())
        {
            let params: Vec<String> = exp
                .params
                .as_ref()
                .unwrap()
                .iter()
                .map(|p| match &p.default {
                    Some(d) => format!("`{}={}`", p.name, value_display(d)),
                    None => format!("`{}`", p.name),
                })
                .collect();
            let mut md = format!(
                "### `{}{}({})`\n\n",
                if exp.is_proto {
                    "#[proto] func ... -> bytes "
                } else {
                    "func "
                },
                exp.name,
                params.join(", ")
            );
            if let Some(doc) = &exp.doc {
                md.push_str(&doc_markdown(doc));
            }
            if exp.is_proto {
                md.push_str("声明式自表示协议（字段即参数，可构造 + 解析）\n\n");
            }
            md.push_str(&format!("库模块：`{}`（隐式可见）\n\n", exp.module));
            md.push_str("**参数**（全部可选）：\n\n");
            for p in exp.params.as_ref().unwrap() {
                let default = match &p.default {
                    Some(d) => format!("默认 `{}`", value_display(d)),
                    None => "未设（省略 → 自动值）".to_string(),
                };
                let desc = exp
                    .doc
                    .as_ref()
                    .and_then(|d| d.params.iter().find(|(n, _)| n == &p.name))
                    .map(|(_, t)| format!("——{t}"))
                    .unwrap_or_default();
                md.push_str(&format!("- `{}`：{default}{desc}\n", p.name));
            }
            return json!({ "contents": { "kind": "markdown", "value": md } });
        }
        Value::Null
    }

    /// `textDocument/definition`：定位光标处标识符的定义位置（元件/函数/proto/导出）。
    fn definition(&self, msg: &Value) -> Value {
        let uri = msg["params"]["textDocument"]["uri"].as_str().unwrap_or("");
        let pos = &msg["params"]["position"];
        let (line, character) = (
            pos["line"].as_i64().unwrap_or(0) as usize,
            pos["character"].as_i64().unwrap_or(0) as usize,
        );
        let Some(text) = self.text_of(uri) else {
            return Value::Null;
        };
        let Some(word) = word_at(text, line, character) else {
            return Value::Null;
        };
        let Ok(module) = try_parse(text, uri, &self.libs) else {
            return Value::Null;
        };
        // 定义位置：元件 / 函数 / proto / 导出（name_span 覆盖标识符）
        let span = module
            .defs
            .iter()
            .find(|d| d.name == word)
            .map(|d| d.name_span)
            .or_else(|| {
                module
                    .funcs
                    .iter()
                    .find(|f| f.name == word)
                    .map(|f| f.name_span)
            })
            .or_else(|| {
                module
                    .protos
                    .iter()
                    .find(|p| p.name == word)
                    .map(|p| p.name_span)
            })
            .or_else(|| {
                module
                    .exports
                    .iter()
                    .find(|(n, _)| *n == word)
                    .map(|(_, s)| *s)
            });
        let Some(span) = span else {
            return Value::Null;
        };
        // LSP 坐标 0 基；DSL span 1 基
        json!([{
            "uri": uri,
            "range": {
                "start": { "line": span.start.line - 1, "character": span.start.col - 1 },
                "end": { "line": span.end.line - 1, "character": span.end.col - 1 }
            }
        }])
    }

    fn document_symbol(&self, msg: &Value) -> Value {
        let uri = msg["params"]["textDocument"]["uri"].as_str().unwrap_or("");
        let Some(text) = self.text_of(uri) else {
            return json!([]);
        };
        let Ok(module) = try_parse(text, uri, &self.libs) else {
            return json!([]);
        };
        let mut symbols = Vec::new();
        for def in &module.defs {
            symbols.push(json!({
                "name": def.name,
                "kind": 13, // Variable
                "detail": "component",
                "range": lsp_range(def.span),
                "selectionRange": lsp_range(def.name_span),
            }));
        }
        for f in &module.funcs {
            let params: Vec<String> = f.params.iter().map(|p| p.name.clone()).collect();
            symbols.push(json!({
                "name": f.name,
                "kind": 12, // Function
                "detail": format!("func {}({})", f.name, params.join(", ")),
                "range": lsp_range(f.span),
                "selectionRange": lsp_range(f.name_span),
            }));
        }
        for (name, span) in &module.exports {
            symbols.push(json!({
                "name": name,
                "kind": 14, // Constant
                "detail": "export",
                "range": lsp_range(*span),
                "selectionRange": lsp_range(*span),
            }));
        }
        if let Some((_, span)) = &module.default {
            symbols.push(json!({
                "name": module.name,
                "kind": 2, // Module
                "detail": "default export",
                "range": lsp_range(*span),
                "selectionRange": lsp_range(*span),
            }));
        }
        json!(symbols)
    }
}

/// 解析文档（带 import 根）；URI 无法定位文件时退化为纯单文件解析。
/// 解析内存文本（web analyze 复用；`file://` URI → 模块名/目录，其余按 untitled）。
pub(crate) fn try_parse(text: &str, uri: &str, libs: &[PathBuf]) -> Result<Module, Diagnostic> {
    match uri_info(uri) {
        Some((name, dir)) => packet_dsl::parse_source_at_with_libs(&name, &dir, text, libs),
        None => packet_dsl::parse_str("untitled", text),
    }
}

/// 文档诊断列表（首个错误；无错误时为空）。
fn analyze(text: &str, uri: &str, libs: &[PathBuf]) -> Vec<Value> {
    match try_parse(text, uri, libs) {
        Ok(_) => vec![],
        Err(d) => vec![lsp_diag(&d)],
    }
}

fn lsp_diag(d: &Diagnostic) -> Value {
    let (sl, sc, el, ec) = match &d.span {
        Some(s) => (
            s.start.line.saturating_sub(1),
            s.start.col.saturating_sub(1),
            s.end.line.saturating_sub(1),
            s.end.col.saturating_sub(1),
        ),
        None => (0, 0, 0, 0),
    };
    json!({
        "range": {
            "start": { "line": sl, "character": sc },
            "end": { "line": el, "character": ec }
        },
        "severity": 1,
        "source": "packet-dsl",
        "message": d.message,
    })
}

fn lsp_range(span: packet_dsl::ast::Span) -> Value {
    json!({
        "start": { "line": span.start.line.saturating_sub(1), "character": span.start.col.saturating_sub(1) },
        "end": { "line": span.end.line.saturating_sub(1), "character": span.end.col.saturating_sub(1) }
    })
}

/// 取 (行, 列) 处的标识符（0 基行/列）。
fn word_at(text: &str, line: usize, character: usize) -> Option<String> {
    let line_text = text.lines().nth(line)?;
    let bytes = line_text.as_bytes();
    let mut start = character.min(bytes.len());
    let mut end = start;
    while start > 0 && is_ident_char(bytes[start - 1]) {
        start -= 1;
    }
    while end < bytes.len() && is_ident_char(bytes[end]) {
        end += 1;
    }
    if start == end {
        return None;
    }
    Some(line_text[start..end].to_string())
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `file:///path/to/demo.pkt` → (名字 "demo", 目录)。非 file:// 返回 None。
fn uri_info(uri: &str) -> Option<(String, PathBuf)> {
    let rest = uri.strip_prefix("file://")?;
    let path_str = percent_decode(rest);
    let path = PathBuf::from(&path_str);
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "untitled".to_string());
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    Some((name, dir))
}

/// 简化百分号解码（%20 等）。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}
