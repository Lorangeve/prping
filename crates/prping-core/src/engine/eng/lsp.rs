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
    /// 库内全部声明函数（含未导出）缓存：未导出函数可经 `import 模块 { 名字 }`
    /// 引入作用域，补全同样提供（标注来源模块）。
    lib_functions_cache: OnceLock<Vec<packet_dsl::LibExport>>,
}

impl LspServer {
    /// 库导出（进程内只解析一次；libs 构造后不变）。
    fn lib_exports_cached(&self) -> &[packet_dsl::LibExport] {
        self.lib_exports_cache
            .get_or_init(|| packet_dsl::lib_exports(&self.libs))
    }
    /// 库内全部声明函数（进程内只解析一次；与 lib_exports 同构，含未导出项）。
    fn lib_functions_cached(&self) -> &[packet_dsl::LibExport] {
        self.lib_functions_cache
            .get_or_init(|| packet_dsl::lib_functions(&self.libs))
    }

    /// `import ` 位：可导入模块名（lib_exports + lib_functions 出现过的全部模块）。
    fn import_module_items(&self) -> Vec<Value> {
        let mut modules: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for e in self
            .lib_exports_cached()
            .iter()
            .chain(self.lib_functions_cached())
        {
            if seen.insert(e.module.clone()) {
                modules.push(e.module.clone());
            }
        }
        modules.sort();
        modules
            .into_iter()
            .map(|m| json!({ "label": m, "kind": 9, "detail": "module", "insertText": m }))
            .collect()
    }

    /// `import 模块 {` 位：该模块可导入成员（函数全量 + 导出元件——语义层按目标
    /// 模块本地定义解析，未导出函数同样可导入）。插入裸名字，import 位不接受调用。
    fn import_member_items(&self, module: &str) -> Vec<Value> {
        let mut items: Vec<Value> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for e in self
            .lib_exports_cached()
            .iter()
            .chain(self.lib_functions_cached())
            .filter(|e| e.module == module)
        {
            if !seen.insert(e.name.clone()) {
                continue;
            }
            match &e.params {
                Some(params) => {
                    let ps: Vec<String> = params
                        .iter()
                        .map(|p| match &p.default {
                            Some(d) => format!("{}={}", p.name, value_display(d)),
                            None => p.name.clone(),
                        })
                        .collect();
                    items.push(json!({
                        "label": e.name,
                        "kind": 3, // Function
                        "detail": format!(
                            "{} {}({})",
                            if e.is_proto { "#[proto] func" } else { "func" },
                            e.name,
                            ps.join(", ")
                        ),
                        "insertText": e.name,
                    }));
                }
                None => {
                    items.push(json!({
                        "label": e.name,
                        "kind": 6, // Variable
                        "detail": "component",
                        "insertText": e.name,
                    }));
                }
            }
        }
        items.sort_by(|a, b| a["label"].as_str().cmp(&b["label"].as_str()));
        items
    }

    /// .pktl 配方文档补全：段头 / 项形态 / 步骤选项键 / 提取键 / 枚举值 / packet 文件名。
    /// 结构（清单风格）：`global:`（`- name:`/`init:`）与 `recipe:`（列 0 步骤项
    /// `- packet:` + 缩进选项 `wait:/raw:/extract:`…，提取子项 `- name:` + `from:/as:`）。
    fn recipe_completion(&self, text: &str, uri: &str, line_no: usize, col: usize) -> Vec<Value> {
        let lines: Vec<&str> = text.lines().collect();
        let cur = lines.get(line_no).copied().unwrap_or("");
        let before = cur.get(..col.min(cur.len())).unwrap_or("");
        let trimmed = before.trim_start();
        let indent = before.len() - before.trim_start().len();

        // 值位：`key:` 之后——有枚举的键给枚举值；packet 给同目录 .pkt 文件名；
        // 自由值键（wait/delay/count/params/init/name）不弹
        if let Some((raw_key, _)) = trimmed.split_once(':') {
            let key = raw_key.trim().trim_start_matches('-').trim();
            match key {
                "as" => return str_items(&["int", "hex", "str", "bytes"], "as 值"),
                "on_error" => return str_items(&["stop", "continue"], "on_error 值"),
                "raw" => return str_items(&["true", "false", "<网卡名>"], "raw 值"),
                "packet" => return self.recipe_packet_items(uri),
                "from" => {
                    return vec![json!({
                        "label": "reply.",
                        "kind": 5, // Field
                        "detail": "回包反解字段（层.字段，与 sniffer 字段集一致）",
                        "insertText": "reply.",
                    })];
                }
                "wait" | "delay" | "count" | "params" | "init" | "name" => return vec![],
                _ => {}
            }
        }

        // 段落与提取上下文：最近段头定 section；段内出现过整行 extract: 且其后
        // 未回到列 0 顶层 → 提取子列表
        let mut section = "";
        let mut in_extract = false;
        for i in (0..line_no).rev() {
            let raw = lines.get(i).copied().unwrap_or("");
            let t = raw.trim();
            if t == "global:" {
                section = "global";
                break;
            }
            if t == "recipe:" {
                section = "recipe";
                break;
            }
            if t == "extract:" {
                in_extract = true;
                break;
            }
            if t.starts_with('#') || t.is_empty() {
                continue;
            }
            let indent_i = raw.len() - raw.trim_start().len();
            if indent_i == 0 {
                break; // 回到列 0 顶层——段外
            }
        }

        // 项形态（`- ` 起头）：提取子项 → name:；配方顶层步骤 → packet:；global 项 → name:
        if let Some(item) = trimmed.strip_prefix("- ") {
            let _ = item;
            if in_extract {
                return str_items(&["name: "], "提取项（from: 取回包字段）");
            }
            if section == "recipe" && indent == 0 {
                return str_items(&["packet: "], "步骤 .pkt 文件");
            }
            if section == "global" {
                return str_items(&["name: "], "全局变量（init: 可选初始化）");
            }
            return str_items(&["packet: ", "name: "], "项");
        }

        // 缩进行：选项键（提取续行 from:/as:，global 的 init:，步骤选项组）
        if indent > 0 {
            if in_extract {
                return str_items(&["from: ", "as: "], "提取键");
            }
            if section == "global" {
                return str_items(&["init: "], "global 选项");
            }
            if section == "recipe" {
                return str_items(
                    &[
                        "wait: ",
                        "on_timeout: ",
                        "count: ",
                        "delay: ",
                        "params: ",
                        "raw: ",
                        "extract:",
                        "on_error: ",
                    ],
                    "步骤选项",
                );
            }
        }

        // 顶层（空行 / 部分词）→ 段头
        str_items(&["global:", "recipe:"], "段头")
    }

    /// `packet:` 值位：同目录 .pkt 文件名（配方相对 .pktl 所在目录解析）。
    fn recipe_packet_items(&self, uri: &str) -> Vec<Value> {
        let Some((_, dir)) = uri_info(uri) else {
            return vec![];
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return vec![];
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x == "pkt")
            })
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        names
            .iter()
            .map(|n| {
                json!({
                    "label": n,
                    "kind": 7, // File
                    "detail": "packet 步骤",
                    "insertText": n,
                })
            })
            .collect()
    }

    /// `export:` 列表位：作用域内裸名字，顺序即 tier——本地元件 → 本地函数 →
    /// 模块默认导出 → 库导出（可转出口）。文档不可解析时本地名走兜底扫描。
    /// insertText 一律裸名——export 列表不接受调用。
    fn export_name_items(&self, text: &str, uri: &str) -> Vec<Value> {
        let mut items: Vec<Value> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut push = |name: &str, kind: i32, detail: &str| {
            if seen.insert(name.to_string()) {
                items.push(json!({
                    "label": name,
                    "kind": kind,
                    "detail": detail,
                    "insertText": name,
                }));
            }
        };
        match try_parse(text, uri, &self.libs) {
            Ok(module) => {
                for def in &module.defs {
                    push(&def.name, 6, "component");
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
                    push(
                        &f.name,
                        3,
                        &format!("func {}({})", f.name, params.join(", ")),
                    );
                }
                if module.default.is_some() {
                    push(&module.name, 9, "default export");
                }
            }
            // 输入中途不可解析：兜底扫描顶层名字，本地名不缺席
            Err(_) => {
                let (defs, funcs) = scan_top_level_names(text);
                for d in &defs {
                    push(d, 6, "component");
                }
                for f in &funcs {
                    push(f, 3, &format!("func {f}()"));
                }
            }
        }
        for exp in self.lib_exports_cached() {
            match &exp.params {
                Some(params) => {
                    let ps: Vec<String> = params
                        .iter()
                        .map(|p| match &p.default {
                            Some(d) => format!("{}={}", p.name, value_display(d)),
                            None => p.name.clone(),
                        })
                        .collect();
                    push(
                        &exp.name,
                        3,
                        &format!(
                            "{} {}({})  [{}]",
                            if exp.is_proto {
                                "#[proto] func"
                            } else {
                                "func"
                            },
                            exp.name,
                            ps.join(", "),
                            exp.module
                        ),
                    );
                }
                None => push(&exp.name, 6, &format!("component [{}]", exp.module)),
            }
        }
        items
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
        // Markdown 等非 DSL 文档：无 LSP 诊断
        if is_markdown_doc(uri) {
            return vec![];
        }
        // .pktl 配方文档：配方解析（.pkt 解析器不认配方语法）
        if is_recipe_doc(uri) {
            return recipe_diagnostics(text, uri);
        }
        analyze(text, uri, &self.libs)
    }

    fn completion(&self, msg: &Value) -> Vec<Value> {
        let uri = msg["params"]["textDocument"]["uri"].as_str().unwrap_or("");
        let pos = &msg["params"]["position"];
        let line_no = pos["line"].as_i64().unwrap_or(0) as usize;
        let col = pos["character"].as_i64().unwrap_or(0) as usize;
        if let Some(text) = self.text_of(uri) {
            // Markdown 等非 DSL 文档：引擎 LSP 不适用（渲染/编辑切换由宿主负责）
            if is_markdown_doc(uri) {
                return vec![];
            }
            // .pktl 配方文档：段头 / 项形态 / 步骤选项键 / 枚举值 / packet 文件名
            if is_recipe_doc(uri) {
                return self.recipe_completion(text, uri, line_no, col);
            }
            let line_text = text.lines().nth(line_no).unwrap_or("");
            let before = line_text.get(..col.min(line_text.len())).unwrap_or("");
            // import 上下文：`import ` 后补可导入模块名；`import 模块 {` 内补该模块
            // 成员名（语义层按目标模块本地定义解析，未导出也可导入——与 lib_functions
            // 同一口径）。插入裸名字——import 位置不接受调用。
            if let Some(ctx) = import_context(before) {
                return match ctx {
                    ImportCtx::Module => self.import_module_items(),
                    ImportCtx::Members(module) => self.import_member_items(&module),
                };
            }
            // export: 列表位：作用域内裸名字（本地元件/函数 → 库导出），可转出口
            if export_list_context(text, line_no, col) {
                return self.export_name_items(text, uri);
            }
            // sniffer: 块：- 项起点补谓词；match 后补层名；match 层( 内补字段 name=
            if let Some(ctx) = sniffer_context(text, line_no, col) {
                return match ctx {
                    SnifferCtx::Pred => sniffer_pred_items(),
                    SnifferCtx::Layer => sniffer_layer_items(),
                    SnifferCtx::Field(fields) => sniffer_field_items(fields),
                };
            }
            // 注解上下文：`#[proto(kind="…")]` 值位补层类型、`#[meta(…)` 补键/标志、
            // 注解名位补注解名——注解行不落全局函数表
            if let Some(ctx) = attr_context(before) {
                return match ctx {
                    AttrCtx::Name => attr_name_items(),
                    AttrCtx::ProtoKind { quoted } => proto_kind_items(quoted),
                    AttrCtx::MetaKey => meta_key_items(),
                    AttrCtx::Empty => vec![],
                };
            }
        }
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
        // 函数名集合含未导出库函数（同样走后面按作用域加入的条目）。
        let func_names: std::collections::HashSet<&str> = self
            .lib_functions_cached()
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
        // 元件名（文档可解析时取完整信息；输入中途不可解析则轻量扫描顶层名字兜底
        // ——export: 列表位尤其依赖本地名，而此时文档必然尚未可解析）
        if let Some(text) = self.text_of(uri) {
            match try_parse(text, uri, &self.libs) {
                Ok(module) => {
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
                Err(_) => {
                    let (defs, funcs) = scan_top_level_names(text);
                    for name in defs {
                        items.push(json!({
                            "label": name,
                            "kind": 6, // Variable
                            "detail": "component",
                        }));
                    }
                    for name in funcs {
                        items.push(json!({
                            "label": name,
                            "kind": 3, // Function
                            "detail": format!("func {name}()"),
                            "insertText": format!("{name}()"),
                        }));
                    }
                }
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
        // 库内未导出函数（`import 模块 { 名字 }` 按目标模块本地定义引入作用域）：
        // 同样能解析出来，补全提供并标注需 import 的模块；与导出项按名去重。
        for f in self.lib_functions_cached() {
            if labels.contains(&f.name) {
                continue;
            }
            labels.insert(f.name.clone());
            let Some(params) = &f.params else {
                continue;
            };
            let ps: Vec<String> = params
                .iter()
                .map(|p| match &p.default {
                    Some(d) => format!("{}={}", p.name, value_display(d)),
                    None => p.name.clone(),
                })
                .collect();
            items.push(json!({
                "label": f.name,
                "kind": 3, // Function
                "detail": format!(
                    "{}{}({})  [需 import {}]",
                    if f.is_proto { "#[proto] func ... -> bytes " } else { "func " },
                    f.name,
                    ps.join(", "),
                    f.module
                ),
                "insertText": format!("{}()", f.name),
            }));
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
        if is_markdown_doc(uri) {
            return Value::Null;
        }
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

/// import 补全上下文（见 [`import_context`]）。
enum ImportCtx {
    /// `import ` 关键字之后：补模块名。
    Module,
    /// `import 模块 {` 之后：补该模块成员名。
    Members(String),
}

/// export: 列表位判定：光标行含未写完的 export: 项（冒号后允许已有 - 项），
/// 或本身是 - 项且向上连续 - 行后紧跟 export: 行。与语法一致——export 是顶层
/// 语句，项以 `-` 起头（允许换行）。
fn export_list_context(text: &str, line_no: usize, col: usize) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    let last = lines.len().saturating_sub(1);
    for i in (0..=line_no.min(last)).rev() {
        let raw = if i == line_no {
            let end = col.min(lines[i].len());
            lines[i].get(..end).unwrap_or("")
        } else {
            lines[i]
        };
        let t = raw.trim();
        if has_keyword_colon(t, "export") {
            return true;
        }
        if t.starts_with('-') {
            continue;
        }
        return false;
    }
    false
}

/// 行内是否出现「关键字 + 冒号」（容忍关键字与冒号之间的空白）。
fn has_keyword_colon(t: &str, keyword: &str) -> bool {
    let Some(i) = t.find(keyword) else {
        return false;
    };
    for c in t[i + keyword.len()..].chars() {
        if c == ':' {
            return true;
        }
        if !c.is_whitespace() {
            return false;
        }
    }
    false
}

/// Markdown 文档判定（file:// 路径后缀）：引擎 LSP 不适用。
fn is_markdown_doc(uri: &str) -> bool {
    uri.strip_prefix("file://")
        .is_some_and(|p| p.ends_with(".md") || p.ends_with(".markdown"))
}

/// .pktl 配方文档判定（file:// 路径后缀）。
fn is_recipe_doc(uri: &str) -> bool {
    uri.strip_prefix("file://")
        .is_some_and(|p| p.ends_with(".pktl"))
}

/// .pktl 诊断：配方解析（内存文本）→ 行号化错误诊断（无错误则空）。
fn recipe_diagnostics(text: &str, uri: &str) -> Vec<Value> {
    let display = uri_info(uri)
        .map(|(_, dir)| dir.join("recipe.pktl"))
        .unwrap_or_else(|| PathBuf::from("recipe.pktl"));
    match crate::engine::recipe::parse_text(text, &display) {
        Ok(_) => vec![],
        Err(e) => {
            let msg = e.to_string();
            let line = recipe_error_line(&msg).unwrap_or(1);
            let line0 = line.saturating_sub(1);
            vec![json!({
                "range": {
                    "start": { "line": line0, "character": 0 },
                    "end": { "line": line0, "character": 0 }
                },
                "severity": 1,
                "source": "packet-dsl",
                "message": msg,
            })]
        }
    }
}

/// 从本地化错误串提取行号（err() 前缀置顶：en `recipe line N:` / zh `配方 N 行：`）。
fn recipe_error_line(msg: &str) -> Option<usize> {
    let rest = if let Some(r) = msg.strip_prefix("recipe line ") {
        r
    } else if let Some(r) = msg.strip_prefix("配方 ") {
        r
    } else {
        return None;
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// 关键字/枚举字符串项（kind 14，insertText 原样，可带尾随空格）。
fn str_items(values: &[&str], detail: &str) -> Vec<Value> {
    values
        .iter()
        .map(|v| {
            json!({
                "label": v,
                "kind": 14, // Keyword
                "detail": detail,
                "insertText": v,
            })
        })
        .collect()
}

/// sniffer 补全上下文（见 [`sniffer_context`]）。
enum SnifferCtx {
    /// `- ` 项起点 / and(or(not( 内：补谓词 match/and/or/not。
    Pred,
    /// `match ` 之后：补层名（IR 层闭集）。
    Layer,
    /// `match 层(` 括号内：补该层字段 `name=`（matchpred 字段表）。
    Field(&'static [&'static str]),
}

/// sniffer: 块补全位判定：块内（光标行向上连续 `-` 行后紧跟 sniffer: 行）时按
/// 光标前片段细分——`match ` 后为层名位；`match 层(` 括号内且当前字段段未写 `=`
/// 时为字段位（值位交回全局列表，那里本就该补 ack()/reply() 等值函数）。
fn sniffer_context(text: &str, line_no: usize, col: usize) -> Option<SnifferCtx> {
    let lines: Vec<&str> = text.lines().collect();
    let last = lines.len().saturating_sub(1);
    let mut in_block = false;
    for i in (0..=line_no.min(last)).rev() {
        let t = lines[i].trim_start();
        if t.starts_with('#') {
            continue; // 块内注释行
        }
        if t.starts_with('-') {
            continue;
        }
        if has_keyword_colon(t, "sniffer") {
            in_block = true;
        }
        break;
    }
    if !in_block {
        return None;
    }
    let cur = lines.get(line_no)?;
    let before = cur.get(..col.min(cur.len())).unwrap_or("");
    let tb = before.trim_start();
    if has_keyword_colon(tb, "sniffer") {
        return Some(SnifferCtx::Pred); // sniffer: 冒号后
    }
    let item = tb.strip_prefix('-')?.trim_start();
    if let Some(after) = item.strip_prefix("match") {
        if !after.is_empty() && !after.starts_with(char::is_whitespace) {
            return Some(SnifferCtx::Pred); // `ma` 之类部分词，按谓词过滤
        }
        let body = after.trim_start();
        let Some(paren) = body.find('(') else {
            return Some(SnifferCtx::Layer); // match 后未到括号 → 层名
        };
        let layer = body[..paren].trim();
        // 括号深度：光标在该层调用的括号内才是字段位
        let depth = body[paren + 1..].chars().fold(1i32, |d, c| match c {
            '(' => d + 1,
            ')' => d - 1,
            _ => d,
        });
        if depth <= 0 {
            return Some(SnifferCtx::Pred); // 层调用已闭合（项尾）
        }
        // 值位（当前字段段已含 `=`）→ 全局列表补值函数 ack()/reply() 等
        let seg = body[paren + 1..].rsplit(',').next().unwrap_or("");
        if seg.contains('=') {
            return None;
        }
        return packet_dsl::field_names(layer).map(SnifferCtx::Field);
    }
    // and(/or(/not( 内与任意部分词 → 谓词位
    Some(SnifferCtx::Pred)
}

/// sniffer 谓词关键字项。
fn sniffer_pred_items() -> Vec<Value> {
    ["match", "and", "or", "not"]
        .iter()
        .map(|k| json!({ "label": k, "kind": 14, "detail": "sniffer 谓词", "insertText": k }))
        .collect()
}

/// sniffer 层名项（IR 层闭集，见 registry::LAYER_KINDS）。
fn sniffer_layer_items() -> Vec<Value> {
    packet_dsl::registry::LAYER_KINDS
        .iter()
        .map(|l| json!({ "label": l, "kind": 5, "detail": "layer", "insertText": l }))
        .collect()
}

/// sniffer 层字段项（`name=`，字段表一处维护于 matchpred::field_names）。
fn sniffer_field_items(fields: &'static [&'static str]) -> Vec<Value> {
    fields
        .iter()
        .map(|f| {
            json!({
                "label": format!("{f}="),
                "kind": 5, // Field
                "detail": "match 字段",
                "insertText": format!("{f}="),
            })
        })
        .collect()
}

/// 光标行（光标前片段）是否处于 import 补全位。import 是单行语句，行内启发即可：
/// `import` 关键字之后未到 `{` → 模块名位；`import 模块 {` 之后 → 成员位。
/// 注解（`#[...]`，恒为单行）内的补全上下文。
enum AttrCtx {
    /// 注解名位（`#[` 后，含部分词）
    Name,
    /// `#[proto(kind=…)]` 值位；quoted = 光标在 kind 字符串引号内（插裸名，
    /// 否则连引号一起补）
    ProtoKind { quoted: bool },
    /// `#[meta(…)` 键/标志位（auto / len= / bits= / …）
    MetaKey,
    /// 注解内暂无候选的位（如 meta 值位）——宁空勿错，不落全局函数表
    Empty,
}

/// 行内 `#[` 起未闭合的注解 → 注解上下文（注解行的补全不落全局函数表）。
fn attr_context(before: &str) -> Option<AttrCtx> {
    let body = &before[before.rfind("#[")? + 2..];
    if body.contains(']') {
        return None; // 注解已闭合
    }
    let name_end = body
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(body.len());
    let name = &body[..name_end];
    if !matches!(name, "proto" | "rule" | "meta") {
        return Some(AttrCtx::Name); // 正在打注解名（含部分词）
    }
    if name == "proto" {
        // kind= 值位：`kind=` 之后光标前引号数为奇 → 在字符串引号内；
        // 尚无 kind=（`#[proto` / `#[proto(`）→ 注解名位（按前缀过滤不出函数）
        return Some(match body.find("kind=") {
            Some(eq) => AttrCtx::ProtoKind {
                quoted: body[eq + 5..].matches('"').count() % 2 == 1,
            },
            None => AttrCtx::Name,
        });
    }
    // meta：键/标志位 = 最后一个 `(` 或 `,` 之后、光标前没有 `=` 的段；
    // 值位（字段名/数字）不出全局函数表 → 空列表
    let seg_start = body.rfind(['(', ',']).map_or(0, |i| i + 1);
    if !body[seg_start..].contains('=') {
        return Some(AttrCtx::MetaKey);
    }
    Some(AttrCtx::Empty)
}

/// 注解名项（parser 语义注解：proto/rule/meta）。
fn attr_name_items() -> Vec<Value> {
    [("proto", "层协议注解"), ("rule", "规则注解"), ("meta", "字段元数据注解")]
        .iter()
        .map(|(n, d)| json!({ "label": n, "kind": 14, "detail": d, "insertText": n }))
        .collect()
}

/// `#[proto(kind=…)]` 值位：IR 层类型闭集（registry::LAYER_KINDS，与语义
/// 校验同一集合，见 semantic 的 kind 检查）。
fn proto_kind_items(quoted: bool) -> Vec<Value> {
    packet_dsl::registry::LAYER_KINDS
        .iter()
        .map(|l| {
            let insert = if quoted {
                l.to_string()
            } else {
                let q = '"';
                format!("{q}{l}{q}")
            };
            json!({ "label": l, "kind": 5, "detail": "proto kind", "insertText": insert })
        })
        .collect()
}

/// `#[meta(…)` 键/标志项（与语义阶段接受的 meta 键一致）。
fn meta_key_items() -> Vec<Value> {
    ["auto", "len=", "bits=", "bytes=", "list=", "item=", "rest=", "cases=", "switch="]
        .iter()
        .map(|m| json!({ "label": m, "kind": 14, "detail": "meta", "insertText": m }))
        .collect()
}

fn import_context(line_before_cursor: &str) -> Option<ImportCtx> {
    let t = line_before_cursor.trim_start();
    let rest = t.strip_prefix("import")?;
    if rest.is_empty() {
        return Some(ImportCtx::Module); // 刚敲完 import
    }
    if !rest.starts_with(|c: char| c.is_whitespace()) {
        return None; // `importx` 之类——不是 import 语句
    }
    match rest.find('{') {
        None => Some(ImportCtx::Module),
        Some(brace) => {
            let module = rest[..brace].split_whitespace().last()?;
            Some(ImportCtx::Members(module.to_string()))
        }
    }
}

/// 文档未可解析时的顶层名字兜底扫描（补全用）：顶层 def（列 0 起 `name =`，非
/// `==`/比较）与顶层 `func name(` 声明。正则启发，只供补全命名——不求完整语法；
/// 注释 / export 项 / 缩进（函数体）一律跳过。
fn scan_top_level_names(text: &str) -> (Vec<String>, Vec<String>) {
    let mut defs: Vec<String> = Vec::new();
    let mut funcs: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in text.lines() {
        let Some(first) = line.chars().next() else {
            continue;
        };
        if first == '#' || first == '-' || first.is_whitespace() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("func ") {
            let name: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() && seen.insert(name.clone()) {
                funcs.push(name);
            }
            continue;
        }
        if let Some(eq) = line.find('=') {
            // `==` 比较（非赋值）跳过
            if line.as_bytes().get(eq + 1) == Some(&b'=') {
                continue;
            }
            let name = line[..eq].trim_end();
            // 名字段须为纯 ident（排除管道行里 `dst=` 之类实参）
            let is_ident = !name.is_empty()
                && name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if is_ident && seen.insert(name.to_string()) {
                defs.push(name.to_string());
            }
        }
    }
    (defs, funcs)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_top_level_names_picks_defs_and_funcs() {
        let text = concat!(
            "# 注释行\n",
            "req = icmp(type=8)\n",
            "\n",
            "#[proto]\n",
            "func hdr_line(text=\"\") -> bytes {\n",
            "    concat(line(text))\n",
            "}\n",
            "export:\n",
            "- req\n",
            "use(req) |> ipv4(dst=\"1.2.3.4\")\n",
        );
        let (defs, funcs) = scan_top_level_names(text);
        assert_eq!(defs, vec!["req".to_string()], "只收顶层 def，实参/比较不算");
        assert_eq!(funcs, vec!["hdr_line".to_string()]);
    }

    #[test]
    fn scan_top_level_names_skips_noise() {
        // 缩进（函数体）、注释、export 项、无等号行、`==` 比较都不产生名字
        let text = concat!(
            "    let_like = 1\n",
            "# comment = 1\n",
            "- item\n",
            "plain_line()\n",
            "match_x == y\n",
        );
        let (defs, funcs) = scan_top_level_names(text);
        assert!(defs.is_empty(), "不应有 defs: {defs:?}");
        assert!(funcs.is_empty());
    }

    #[test]
    fn completion_after_import_lists_modules() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server
            .docs
            .insert("file:///scratch.pkt".to_string(), "import ".to_string());
        let items = server.completion(&json!({
            "params": {
                "textDocument": { "uri": "file:///scratch.pkt" },
                "position": { "line": 0, "character": 7 },
            }
        }));
        assert!(!items.is_empty());
        let labels: Vec<&str> = items.iter().filter_map(|i| i["label"].as_str()).collect();
        assert!(labels.contains(&"headers"), "应有 headers 模块: {labels:?}");
        assert!(labels.contains(&"wireguard"), "应有 wireguard 模块");
        assert!(
            items.iter().all(|i| i["kind"] == 9),
            "import 位应全是模块项: {labels:?}"
        );
    }

    #[test]
    fn completion_in_import_braces_lists_members() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server.docs.insert(
            "file:///scratch.pkt".to_string(),
            "import headers { ".to_string(),
        );
        let items = server.completion(&json!({
            "params": {
                "textDocument": { "uri": "file:///scratch.pkt" },
                "position": { "line": 0, "character": 17 },
            }
        }));
        let labels: Vec<&str> = items.iter().filter_map(|i| i["label"].as_str()).collect();
        assert!(labels.contains(&"eth"), "headers 成员 eth 应在: {labels:?}");
        assert!(
            labels.contains(&"hdr_line"),
            "未导出的 hdr_line 也可导入（按本地定义解析）"
        );
        // 裸名字插入——import 位置不接受调用
        assert!(
            items
                .iter()
                .all(|i| !i["insertText"].as_str().unwrap_or("").ends_with("()"))
        );
    }

    #[test]
    #[test]
    fn completion_in_proto_attr_positions() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server
            .docs
            .insert(
                "file:///p.pkt".to_string(),
                "#[proto(kind=\"\")] func arp2() -> bytes { concat() }\n".to_string(),
            );
        let ask = |line: i32, ch: i32| {
            server
                .completion(&json!({
                    "params": {
                        "textDocument": { "uri": "file:///p.pkt" },
                        "position": { "line": line, "character": ch },
                    }
                }))
                .iter()
                .map(|i| {
                    (
                        i["label"].as_str().unwrap_or("?").to_string(),
                        i["kind"].as_i64().unwrap_or(0),
                        i["insertText"].as_str().unwrap_or("?").to_string(),
                    )
                })
                .collect::<Vec<_>>()
        };
        // kind 字符串引号内 → 层类型裸名（eth/arp/…），绝无函数项
        let inside = ask(0, 14);
        assert!(
            inside.iter().any(|(l, _, _)| l == "eth"),
            "应有 eth 层类型: {inside:?}"
        );
        assert!(
            inside.iter().all(|(_, k, _)| *k == 5),
            "kind 值位应全为层类型: {inside:?}"
        );
        let (_, _, ins) = inside.iter().find(|(l, _, _)| l == "eth").unwrap();
        assert_eq!(ins, "eth", "引号内插裸名");
        // 引号前（kind= 之后）→ 同集合，insertText 带引号
        let before_quote = ask(0, 13);
        let (_, _, ins2) = before_quote
            .iter()
            .find(|(l, _, _)| l == "eth")
            .expect("应有 eth");
        assert_eq!(ins2, "\"eth\"", "引号外连引号补");

        // 注解名位（部分词 pro）→ proto/rule/meta，无函数
        server
            .docs
            .insert("file:///n.pkt".to_string(), "#[pro\n".to_string());
        let names = (0..1)
            .flat_map(|_| {
                server.completion(&json!({
                    "params": {
                        "textDocument": { "uri": "file:///n.pkt" },
                        "position": { "line": 0, "character": 5 },
                    }
                }))
            })
            .map(|i| i["label"].as_str().unwrap_or("?").to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["proto".to_string(), "rule".to_string(), "meta".to_string()]
        );

        // meta 键位 → auto/len=/bits=/… 键集，无函数
        server
            .docs
            .insert("file:///m.pkt".to_string(), "#[meta(\n".to_string());
        let keys = server
            .completion(&json!({
                "params": {
                    "textDocument": { "uri": "file:///m.pkt" },
                    "position": { "line": 0, "character": 7 },
                }
            }))
            .iter()
            .map(|i| i["label"].as_str().unwrap_or("?").to_string())
            .collect::<Vec<_>>();
        assert!(keys.contains(&"auto".to_string()), "应有 auto: {keys:?}");
        assert!(keys.contains(&"len=".to_string()), "应有 len=: {keys:?}");
        assert!(!keys.iter().any(|k| k.contains("(")), "meta 键位不应有函数: {keys:?}");
    }
    fn completion_in_sniffer_positions() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        let text = concat!(
            "get = http(start_line=\"GET /\")\n",
            "full = use(get) |> tcp(sport=40000) |> eth()\n",
            "\n",
            "sniffer:\n",
            "  - match tcp(sport=dport, flags=ack())\n",
            "\n",
            "export:\n",
            "- full\n",
        );
        server
            .docs
            .insert("file:///s.pkt".to_string(), text.to_string());
        let ask = |line: i32, ch: i32| {
            let items = server.completion(&json!({
                "params": {
                    "textDocument": { "uri": "file:///s.pkt" },
                    "position": { "line": line, "character": ch },
                }
            }));
            items
                .iter()
                .map(|i| {
                    (
                        i["label"].as_str().unwrap_or("?").to_string(),
                        i["kind"].as_i64().unwrap_or(0),
                    )
                })
                .collect::<Vec<_>>()
        };
        // sniffer: 冒号后 → 谓词
        let items = ask(3, 8);
        assert_eq!(
            items,
            vec![
                ("match".to_string(), 14),
                ("and".to_string(), 14),
                ("or".to_string(), 14),
                ("not".to_string(), 14)
            ]
        );
        // - 项起点 → 谓词
        assert_eq!(ask(4, 4), items);
        // match 空格后 → 层名（含 tcp，无函数）
        let layers = ask(4, 12);
        assert!(
            layers.iter().any(|(l, _)| l == "tcp"),
            "应有 tcp 层: {layers:?}"
        );
        assert!(layers.iter().all(|(_, k)| *k == 5), "层名位应全为字段类");
        // match tcp( 括号内 → tcp 字段 name=
        let fields = ask(4, 16);
        assert!(
            fields.iter().any(|(l, _)| l == "sport="),
            "应有 sport=: {fields:?}"
        );
        assert!(
            fields.iter().all(|(l, _)| !l.contains("()")),
            "字段位无调用"
        );
        // 值位（ack( 括号内）→ 交回全局（含值函数 ack）
        let value = ask(4, 37);
        assert!(
            value.iter().any(|(l, _)| l == "ack"),
            "值位应有值函数 ack: {:?}",
            value
                .iter()
                .map(|(l, _)| l.clone())
                .take(8)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn completion_in_export_lists_locals_first() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        let text = concat!(
            "get = http(start_line=\"GET /\")\n",
            "full = use(get) |> tcp(sport=40000) |> eth()\n",
            "\n",
            "export:\n",
            "- full\n",
        );
        server
            .docs
            .insert("file:///s.pkt".to_string(), text.to_string());
        let items = server.completion(&json!({
            "params": {
                "textDocument": { "uri": "file:///s.pkt" },
                "position": { "line": 3, "character": 7 },
            }
        }));
        let labels: Vec<&str> = items.iter().filter_map(|i| i["label"].as_str()).collect();
        assert!(
            labels.first() == Some(&"get") && labels.get(1) == Some(&"full"),
            "本地元件应置顶: {labels:?}"
        );
        assert!(labels.contains(&"eth"), "库导出 eth 应在后段");
        // insertText 全为裸名
        assert!(
            items
                .iter()
                .all(|i| !i["insertText"].as_str().unwrap_or("").ends_with("()"))
        );
    }

    #[test]
    fn markdown_docs_get_no_lsp() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server.docs.insert(
            "file:///r.md".to_string(),
            "# 标题\n\n- 列表项\n".to_string(),
        );
        // 诊断 / 补全 / 悬停全部静默
        assert!(server.diagnostics("file:///r.md").is_empty());
        assert!(
            server
                .completion(&json!({
                    "params": {
                        "textDocument": { "uri": "file:///r.md" },
                        "position": { "line": 0, "character": 2 },
                    }
                }))
                .is_empty()
        );
        assert_eq!(
            server.hover(&json!({
                "params": {
                    "textDocument": { "uri": "file:///r.md" },
                    "position": { "line": 0, "character": 2 },
                }
            })),
            Value::Null
        );
    }

    #[test]
    fn completion_in_recipe_positions() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        let text = concat!(
            "global:\n",
            "- tid=0x4321\n",
            "\n",
            "recipe:\n",
            "- packet: recipe_query.pkt\n",
            "  wait: 1\n",
            "  extract:\n",
            "  - name: tid\n",
            "    from: reply.dns.id\n",
            "    as: hex\n",
            "- packet: ",
        );
        server
            .docs
            .insert("file:///s.pktl".to_string(), text.to_string());
        let ask = |line: i32, ch: i32| -> Vec<String> {
            server
                .completion(&json!({
                    "params": {
                        "textDocument": { "uri": "file:///s.pktl" },
                        "position": { "line": line, "character": ch },
                    }
                }))
                .iter()
                .map(|i| i["label"].as_str().unwrap_or("?").to_string())
                .collect()
        };
        // 顶层空行 → 段头
        assert_eq!(
            ask(2, 0),
            vec!["global:".to_string(), "recipe:".to_string()]
        );
        // global 项 → name:
        assert_eq!(ask(1, 2), vec!["name: ".to_string()]);
        // 步骤项 → packet:
        assert_eq!(ask(4, 2), vec!["packet: ".to_string()]);
        // 提取子项 → name:；提取续行 → from:/as:
        assert_eq!(ask(7, 4), vec!["name: ".to_string()]);
        assert_eq!(ask(9, 4), vec!["from: ".to_string(), "as: ".to_string()]);
        // as: 值位 → 枚举
        assert_eq!(
            ask(9, 10),
            vec![
                "int".to_string(),
                "hex".to_string(),
                "str".to_string(),
                "bytes".to_string()
            ]
        );
        // packet: 值位（无真实目录）→ 空（不弹全局函数）
        assert!(ask(10, 10).is_empty());
        // wait: 自由值 → 不弹
        assert!(ask(5, 9).is_empty());
    }

    #[test]
    fn recipe_diagnostics_reports_line() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        // `- packet:` 无路径 → 第 1 行错误
        server
            .docs
            .insert("file:///s.pktl".to_string(), "- packet:\n".to_string());
        let diags = server.diagnostics("file:///s.pktl");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0]["range"]["start"]["line"], 0);
        assert!(!diags[0]["message"].as_str().unwrap_or("").is_empty());
        // 合法配方 → 零诊断
        server.docs.insert(
            "file:///s.pktl".to_string(),
            "recipe:\n- packet: x.pkt\n".to_string(),
        );
        assert!(server.diagnostics("file:///s.pktl").is_empty());
    }

    #[test]
    fn completion_on_unparseable_doc_still_lists_locals() {
        // 输入中途（export: 未写完、文档不可解析）：本地名经兜底扫描仍在补全里
        let text = "req = icmp(type=8)\n\nexport:";
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server
            .docs
            .insert("file:///scratch.pkt".to_string(), text.to_string());
        let items = server.completion(&json!({
            "params": {
                "textDocument": { "uri": "file:///scratch.pkt" },
                "position": { "line": 2, "character": 7 },
            }
        }));
        let labels: Vec<&str> = items.iter().filter_map(|i| i["label"].as_str()).collect();
        assert!(
            labels.contains(&"req"),
            "本地 def req 应在补全里: {labels:?}"
        );
        assert!(!items.is_empty());
    }
}
