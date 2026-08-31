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
                        .map(|p| param_sig(&p.name, p.default.as_ref()))
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
                    // 二级路径补全：reply. → 层名；reply.层. → 该层字段
                    //（CM 锚定词起点不含点，label 带全路径以吃住已敲前缀的过滤）
                    let val = trimmed.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
                    let Some(rest) = val.strip_prefix("reply.") else {
                        return vec![json!({
                            "label": "reply.",
                            "kind": 5, // Field
                            "detail": "回包反解字段（层.字段，与 sniffer 字段集一致）",
                            "insertText": "reply.",
                        })];
                    };
                    if rest.contains('.') {
                        // reply.层. → 该层字段
                        let layer = rest.split('.').next().unwrap_or("");
                        return packet_dsl::field_names(layer)
                            .map(|fields| {
                                fields
                                    .iter()
                                    .map(|f| {
                                        json!({
                                            "label": format!("reply.{layer}.{f}"),
                                            "kind": 5,
                                            "detail": "回包反解字段",
                                            "insertText": format!("reply.{layer}.{f}"),
                                        })
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                    }
                    // reply.（或部分层名）→ 层名，插入带尾点顺势下一级
                    return packet_dsl::registry::LAYER_KINDS
                        .iter()
                        .map(|l| {
                            json!({
                                "label": format!("reply.{l}"),
                                "kind": 5,
                                "detail": "回包反解层",
                                "insertText": format!("reply.{l}."),
                            })
                        })
                        .collect();
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
                        .map(|p| param_sig(&p.name, p.default.as_ref()))
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
                        .map(|p| param_sig(&p.name, p.default.as_ref()))
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
                            "completionProvider": {
                                // = : 值位/键位即弹；[ 注解位；. 配方 from 二级路径
                                "triggerCharacters": [">", "(", ",", " ", "=", ":", "[", "."]
                            },
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
        // 打词中间态豁免（D2/D3）：诊断说某名字「未知/未定义」，而该名字是任意
        // 已知名字的严格前缀 → 多半是用户正在输入，本步不报。仅 LSP 路径——
        // CLI 诊断保持严格（打错成真名字的前缀照样报）。
        analyze(text, uri, &self.libs)
            .into_iter()
            .filter(|d| !self.typing_transient_error(d, text))
            .collect()
    }

    /// 「未知/未定义名字」诊断且名字是已知名字的严格前缀 → 打词中间态。
    /// 例外：`use` 关键字本身等值（`full = use` 是打向 `use(q)` 的必经中间态，
    /// 解析器把裸 `use` 当层函数名报未知）。
    fn typing_transient_error(&self, d: &Value, text: &str) -> bool {
        let msg = d["message"].as_str().unwrap_or("");
        if !(msg.contains("未知") || msg.contains("未定义")) {
            return false;
        }
        let known = self.known_names(text);
        backtick_idents(msg).iter().any(|i| {
            !i.is_empty()
                && known.iter().any(|k| {
                    k.starts_with(i.as_str()) && (k.len() > i.len() || (k == i && i == "use"))
                })
        })
    }

    /// 已知名字全集（打词豁免与未完调用名判定共用）：本地 def/func（兜底扫描，
    /// 文档不可解析也拿得到）+ 库导出/库函数 + 内置原语 + 层类型 + 语句关键字。
    fn known_names(&self, text: &str) -> std::collections::HashSet<String> {
        let mut names: std::collections::HashSet<String> = std::collections::HashSet::new();
        let (defs, funcs) = scan_top_level_names(text);
        names.extend(defs);
        names.extend(funcs);
        for e in self
            .lib_exports_cached()
            .iter()
            .chain(self.lib_functions_cached())
        {
            names.insert(e.name.clone());
        }
        for d in packet_dsl::registry::builtin_docs() {
            names.insert(d.name.to_string());
        }
        names.extend(
            packet_dsl::registry::LAYER_KINDS
                .iter()
                .map(|s| (*s).to_string()),
        );
        names.extend(
            ["use", "func", "export", "import", "true", "false"]
                .iter()
                .map(|s| (*s).to_string()),
        );
        names
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
            // 通用位置上下文：层位 / use( 元件位 / 实参名位 / 值位 / 语句位 / 字符串注释
            // ——按位返回该处语法合法且已排序的候选，替代过去「处处同一张全量混合表」
            self.pkt_ctx_items(text, uri, line_no, col)
        } else {
            vec![]
        }
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
        // 参数名悬停优先：`name=` 形态给所属函数的参数说明（此前该位恒为无提示）
        if let Some(md) = self.param_hover(text, uri, line, character, &word) {
            return json!({ "contents": { "kind": "markdown", "value": md } });
        }
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
                    // proto 式自指占位（默认值 ≡ 参数名）显示「自动」
                    Some(d) if value_display(d) != p.name => format!("默认 `{}`", value_display(d)),
                    Some(_) => "自动（字段占位）".to_string(),
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
        // 本地元件悬停：定义行 + 片段（此前该位恒为无提示）
        if let Some(text) = self.text_of(uri)
            && let Ok(module) = try_parse(text, uri, &self.libs)
            && let Some(d) = module.defs.iter().find(|d| d.name == word)
        {
            let lines: Vec<&str> = text.lines().collect();
            let sl = d.span.start.line.saturating_sub(1);
            let el = (d.span.end.line.saturating_sub(1)).min(lines.len().saturating_sub(1));
            let mut md = format!("### `{}`\n\n元件（component）——命名流水线。\n\n```", d.name);
            for l in lines.iter().take(el + 1).skip(sl) {
                md.push('\n');
                md.push_str(l);
            }
            md.push_str("\n```");
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
                    // proto 字段自指占位（默认值 ≡ 参数名，如 sport=sport）显示「自动」
                    Some(d) if value_display(d) != p.name => format!("默认 `{}`", value_display(d)),
                    Some(_) => "自动（proto 字段占位）".to_string(),
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
    let rest = msg
        .strip_prefix("recipe line ")
        .or_else(|| msg.strip_prefix("配方 "))?;
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
    [
        ("proto", "层协议注解"),
        ("rule", "规则注解"),
        ("meta", "字段元数据注解"),
    ]
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
    [
        "auto", "len=", "bits=", "bytes=", "list=", "item=", "rest=", "cases=", "switch=",
    ]
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

// ── .pkt 通用位置上下文补全 ─────────────────────────────────────────────
// import/export/sniffer/attr 四个特判之外的一切位置：先判定光标所处语法位
//（层位 / use( 元件位 / 实参名位 / 值位 / 语句位 / 字符串注释），再只给该位
// 语法合法且排好序的候选。排序用 sortText 分层（00 最优先），数组序与
// sortText 一致——前端保序渲染，外部 LSP 编辑器按 sortText 排。

/// 函数参数信息（补全与悬停共用的规范化形态）。
struct ParamInfo {
    name: String,
    /// 默认值渲染串（None = 未设）。
    default: Option<String>,
    /// 参数说明（doc `@param` / 内置参数类型说明）。
    desc: Option<String>,
}

/// .pkt 通用位置上下文。
enum PktCtx {
    /// 字符串字面量 / 注释内：不出候选。
    Quiet,
    /// 层位：`|>` 之后、管道中段、函数体语句起头。
    Layer,
    /// `layer("…` 的 kind 值位：层类型闭集（quoted = 光标在引号内，插裸名）。
    LayerKind { quoted: bool },
    /// `use(` 括号内：元件裸名。
    Use,
    /// 实参名位：内层未闭合调用的参数 `name=`（used = 已填参数名）。
    Args { func: String, used: Vec<String> },
    /// 值位：`name=` 之后（scope = 所在函数体可见的参数名，裸名引用）。
    Value {
        func: String,
        arg: Option<String>,
        scope: Vec<String>,
    },
    /// 顶层语句起头：use / func / export: / import / 注解。
    TopLevel,
}

/// 常用层函数（层位置顶；同时也是值位排除集——层头不作值候选）。
const LAYER_COMMON: &[&str] = &[
    "eth", "arp", "ipv4", "ipv6", "icmp", "tcp", "udp", "http", "dns",
];

/// 值位核心原语（t1，常用序；其余值原语 t2 按字母序）。
const VALUE_CORE: &[&str] = &[
    "hex", "raw", "concat", "params", "global", "reply", "u8", "be16", "be32", "tpl",
];

/// (层函数, 参数名) → 值位置顶候选。覆盖高频书写：flags 位组合、地址、端口、载荷。
fn arg_value_boost(func: &str, arg: &str) -> &'static [&'static str] {
    match (func, arg) {
        (_, "flags") => &[
            "syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr", "df", "mf", "bor",
        ],
        ("eth", "src" | "dst") => &["mac", "rand_mac", "params"],
        ("ipv4", "src" | "dst") => &["ip4", "params"],
        ("ipv6", "src" | "dst") => &["ip6", "params"],
        ("tcp" | "udp", "sport" | "dport") => &["params", "rand16"],
        (_, "payload" | "data" | "bytes" | "options") => &["hex", "raw", "concat", "tpl"],
        (_, "id") => &["rand16"],
        _ => &[],
    }
}

/// 判定光标所处的 .pkt 语法位。纯文本启发（容错输入中途的半成品）：行内注释、
/// 字符串奇偶先行排除，再看 `|>` 尾随/续行、内层未闭合调用、管道中段、花括号深度。
/// 扫描范围为光标前全文（文档 KB 量级，逐键成本可忽略）。
fn pkt_context(text: &str, line_no: usize, col: usize) -> PktCtx {
    let lines: Vec<&str> = text.lines().collect();
    let cur = lines.get(line_no).copied().unwrap_or("");
    // 列号可能落在多字节字符中间（CJK 注释/字符串逐字输入的常态）：
    // 回退到最近的字符边界，避免 before 退化为空串导致误判语句位
    let mut cend = col.min(cur.len());
    while cend > 0 && !cur.is_char_boundary(cend) {
        cend -= 1;
    }
    let before_cur = &cur[..cend];
    // 光标绝对偏移（lines 与 text 的行切分一致）
    let mut off = 0usize;
    for l in lines.iter().take(line_no) {
        off += l.len() + 1;
    }
    off += before_cur.len();
    let up_to = &text[..off.min(text.len())];
    // 注释内容以空格占位（保偏移）——括号/花括号配对不受注释里杂字符干扰
    let cleaned = blank_comments(up_to);

    // 行内注释（引号外 # 到行尾）
    let mut in_q = false;
    for c in before_cur.chars() {
        if c == '"' {
            in_q = !in_q;
        } else if c == '#' && !in_q {
            return PktCtx::Quiet;
        }
    }
    // 字符串字面量内（引号奇偶；DSL 无跨行字符串）。layer(" 的 kind 值位例外：
    // 引号内补层类型裸名（与 #[proto(kind="…")] 同一套 quoted 语义）。
    if cleaned.matches('"').count() % 2 == 1 {
        if let Some(q) = cleaned.rfind('"') {
            let head = cleaned[..q].trim_end();
            let kind_eq = head.ends_with('=') && ident_tail(head.trim_end_matches('=')) == "kind";
            if (kind_eq || head.ends_with('('))
                && enclosing_call(&cleaned[..q]).is_some_and(|(f, _, _)| f == "layer")
            {
                return PktCtx::LayerKind { quoted: true };
            }
        }
        return PktCtx::Quiet;
    }
    // `|>` 尾随（容忍中间空白）→ 层位
    if cleaned.trim_end().ends_with("|>") {
        return PktCtx::Layer;
    }
    // `|` 已打、`>` 未打：正在补管道符 → 层位（DSL 无 `|` 运算符，孤立 | 只会出现在这里）
    if cleaned.trim_end().ends_with('|') {
        return PktCtx::Layer;
    }
    // 续行：上一行以 |> 结尾、本行光标前为空 → 层位
    if before_cur.trim().is_empty()
        && line_no > 0
        && lines
            .get(line_no - 1)
            .is_some_and(|p| blank_comments(p).trim_end().ends_with("|>"))
    {
        return PktCtx::Layer;
    }
    // 内层未闭合调用：实参名位 / 值位
    if let Some((func, used, seg_start)) = enclosing_call(&cleaned) {
        if func == "use" {
            return PktCtx::Use;
        }
        let seg = &cleaned[seg_start..];
        if let Some(eq) = seg.find('=') {
            let arg = ident_tail(seg[..eq].trim_end());
            return PktCtx::Value {
                func,
                arg: (!arg.is_empty()).then_some(arg),
                scope: enclosing_func_params(&cleaned),
            };
        }
        return PktCtx::Args { func, used };
    }
    // 管道中段（当前行光标前已有 |>，且不在调用括号内）→ 层位
    //（只看本行——全文检查会把后续语句行误判成层位）
    if blank_comments(before_cur).contains("|>") {
        return PktCtx::Layer;
    }
    // def 值位：`name = ` 之后（语句的流水线头，语法上就是层调用位）→ 层位。
    // 此前误归语句关键字位——`x = ` 后打函数名不出候选。要求 `=` 前是纯
    // ident 头（排除 `#[meta(len=…)]` 已闭合注解行等），`==` 不算赋值。
    let line_clean = blank_comments(before_cur);
    if let Some(eq) = line_clean.rfind('=') {
        let head = line_clean[..eq].trim_end();
        let value_side = &line_clean[eq + 1..];
        let valid_head = !head.is_empty()
            && !value_side.starts_with('=')
            && head
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c.is_whitespace());
        if valid_head {
            return PktCtx::Layer;
        }
    }
    // 语句位：函数体内（花括号未闭合）= 层调用；顶层 = 语句关键字
    if brace_depth(&cleaned) > 0 {
        return PktCtx::Layer;
    }
    PktCtx::TopLevel
}

/// 注释内容以空格占位（字符串外 `#` 到行尾；换行保留，偏移不变）。
fn blank_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_q = false;
    let mut in_comment = false;
    for c in s.chars() {
        if in_comment {
            if c == '\n' {
                in_comment = false;
                out.push('\n');
            } else {
                out.push(' ');
            }
        } else if c == '"' {
            in_q = !in_q;
            out.push(c);
        } else if c == '#' && !in_q {
            in_comment = true;
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

/// 串尾 ident 段（字母数字下划线后缀）。
fn ident_tail(s: &str) -> String {
    s.trim_end()
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

/// 光标前的部分词（ident 后缀；列号可能落在多字节字符中间，回退字符边界）。
/// 服务端前缀过滤（C3）用——与 pkt_context 的边界规则一致。
fn cursor_word_prefix(text: &str, line_no: usize, col: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let cur = lines.get(line_no).copied().unwrap_or("");
    let mut cend = col.min(cur.len());
    while cend > 0 && !cur.is_char_boundary(cend) {
        cend -= 1;
    }
    ident_tail(&cur[..cend])
}

/// 串头 ident 段。
fn ident_head(s: &str) -> String {
    s.trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// 提取消息中反引号包裹的标识符（`u`、`ful` …；诊断消息里的说明文字不带反引号）。
fn backtick_idents(msg: &str) -> Vec<String> {
    let mut out = Vec::new();
    for seg in msg.split('`').skip(1).step_by(2) {
        let ident = ident_head(seg);
        if !ident.is_empty() {
            out.push(ident);
        }
    }
    out
}

/// 光标前文本的内层未闭合调用：Some((函数名, 已填参数名, 当前实参段起点偏移))。
/// 引号内字符不参与括号配对；段起点 = 调用开括号后或其内最后一个顶层逗号之后。
fn enclosing_call(s: &str) -> Option<(String, Vec<String>, usize)> {
    let b = s.as_bytes();
    // 每个位置的前缀引号奇偶（1 = 处于字符串内）
    let mut par = Vec::with_capacity(b.len() + 1);
    par.push(0u8);
    let mut parity = 0u8;
    for &c in b {
        parity ^= u8::from(c == b'"');
        par.push(parity);
    }
    let mut depth = 0i32;
    let mut i = b.len();
    while i > 0 {
        i -= 1;
        if par[i] == 1 {
            continue; // 字符串内
        }
        match b[i] {
            b')' => depth += 1,
            b'(' => {
                if depth > 0 {
                    depth -= 1;
                    continue;
                }
                // 函数名：'(' 之前容许空白的 ident
                let mut e = i;
                while e > 0 && (b[e - 1] as char).is_whitespace() {
                    e -= 1;
                }
                let mut st = e;
                while st > 0 && (b[st - 1].is_ascii_alphanumeric() || b[st - 1] == b'_') {
                    st -= 1;
                }
                if st == e {
                    return None; // 非调用括号
                }
                // 当前实参段起点与已填参数名（调用内顶层逗号 / name=）
                let mut d2 = 0i32;
                let mut seg = i + 1;
                let mut used: Vec<String> = Vec::new();
                let mut j = i + 1;
                while j < b.len() {
                    if par[j] == 1 {
                        j += 1;
                        continue;
                    }
                    match b[j] {
                        b'(' => d2 += 1,
                        b')' => d2 -= 1,
                        b',' if d2 == 0 => seg = j + 1,
                        b'=' if d2 == 0 && b.get(j + 1) != Some(&b'=') => {
                            let mut e2 = j;
                            while e2 > 0 && (b[e2 - 1] as char).is_whitespace() {
                                e2 -= 1;
                            }
                            let mut s2 = e2;
                            while s2 > 0 && (b[s2 - 1].is_ascii_alphanumeric() || b[s2 - 1] == b'_')
                            {
                                s2 -= 1;
                            }
                            if s2 < e2 {
                                used.push(s[s2..e2].to_string());
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                return Some((s[st..e].to_string(), used, seg));
            }
            _ => {}
        }
    }
    None
}

/// 花括号深度（字符串/注释外）：>0 = 处于函数体内。
fn brace_depth(s: &str) -> i32 {
    let mut depth = 0i32;
    let mut in_q = false;
    for c in blank_comments(s).chars() {
        if c == '"' {
            in_q = !in_q;
        } else if !in_q {
            if c == '{' {
                depth += 1;
            } else if c == '}' {
                depth -= 1;
            }
        }
    }
    depth
}

/// 光标前最近一个「已开未闭」函数头的参数名列表（函数体内值位的作用域名）。
fn enclosing_func_params(cleaned: &str) -> Vec<String> {
    let b = cleaned.as_bytes();
    let mut end = cleaned.len();
    while let Some(idx) = cleaned[..end].rfind("func ") {
        // 词边界：func 前不能是 ident 字符（排除 myfunc）
        if idx > 0 && (b[idx - 1].is_ascii_alphanumeric() || b[idx - 1] == b'_') {
            end = idx;
            continue;
        }
        let head = &cleaned[idx + 5..];
        let Some(open) = head.find('{') else {
            return vec![];
        };
        // 函数体已在光标前闭合 → 继续向外找更早的 func
        if head[open..].contains('}') {
            end = idx;
            continue;
        }
        let Some(popen) = head.find('(') else {
            return vec![];
        };
        let Some(pclose) = head[popen..].find(')') else {
            return vec![];
        };
        return split_top_commas(&head[popen + 1..popen + pclose])
            .iter()
            .map(|s| ident_head(s))
            .filter(|s| !s.is_empty())
            .collect();
    }
    vec![]
}

/// 顶层逗号切分（括号/引号内的逗号不算——默认值可能是 bor(0x50, 0) 这类）。
fn split_top_commas(s: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut depth = 0i32;
    let mut in_q = false;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '"' => {
                in_q = !in_q;
                cur.push(c);
            }
            '(' if !in_q => {
                depth += 1;
                cur.push(c);
            }
            ')' if !in_q => {
                depth -= 1;
                cur.push(c);
            }
            ',' if !in_q && depth == 0 => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

/// 参数签名段：`名` / `名=默认`；默认值与参数名相同（proto 字段自指占位）时只显示名。
fn param_sig(name: &str, default: Option<&packet_dsl::ast::Value>) -> String {
    match default {
        Some(d) if value_display(d) != name => format!("{name}={}", value_display(d)),
        _ => name.to_string(),
    }
}

/// 库函数候选项（detail 带签名与来源模块标签；sort 为 sortText 分级前缀）。
fn lib_func_item(exp: &packet_dsl::LibExport, sort: String) -> Value {
    let ps = exp
        .params
        .as_ref()
        .map(|ps| {
            ps.iter()
                .map(|p| param_sig(&p.name, p.default.as_ref()))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    json!({
        "label": exp.name,
        "kind": 3,
        "detail": format!(
            "{}{}({})  [{}]",
            if exp.is_proto { "#[proto] func ... -> bytes " } else { "func " },
            exp.name,
            ps,
            exp.module
        ),
        "insertText": format!("{}()", exp.name),
        "sortText": sort,
    })
}

/// 本地函数候选项。
fn local_func_item(name: &str, params: &[packet_dsl::semantic::FuncParam], sort: String) -> Value {
    let ps = params
        .iter()
        .map(|p| param_sig(&p.name, p.default.as_ref()))
        .collect::<Vec<_>>()
        .join(", ");
    json!({
        "label": name,
        "kind": 3,
        "detail": format!("func {name}({ps})"),
        "insertText": format!("{name}()"),
        "sortText": sort,
    })
}

/// 内置原语候选项（detail/documentation 复用 builtin_docs 渲染）。
fn builtin_value_item(doc: &packet_dsl::registry::BuiltinDoc, sort: String) -> Value {
    let params: Vec<String> = doc.params.iter().map(|(n, _)| n.to_string()).collect();
    let insert = if doc.name == "params" {
        "params(\"\")".to_string()
    } else {
        format!("{}()", doc.name)
    };
    json!({
        "label": doc.name,
        "kind": 3,
        "detail": format!("{}({})", doc.name, params.join(", ")),
        "documentation": {
            "kind": "markdown",
            "value": format!("{}\n\n**行为**：{}", doc.summary, doc.auto)
        },
        "insertText": insert,
        "sortText": sort,
    })
}

/// 实参名位候选：函数已声明参数的 `name=`（跳过已填），按声明顺序置顶。
fn arg_name_items(func: &str, params: &[ParamInfo], used: &[String]) -> Vec<Value> {
    params
        .iter()
        .enumerate()
        .filter(|(_, p)| !used.iter().any(|u| u == &p.name))
        .map(|(i, p)| {
            json!({
                "label": format!("{}=", p.name),
                "kind": 5, // Field
                "detail": match &p.desc {
                    Some(d) => format!("{func} 参数——{d}"),
                    None => format!("{func} 参数"),
                },
                "insertText": format!("{}=", p.name),
                "sortText": format!("00{i:02}{}", p.name),
            })
        })
        .collect()
}

/// 顶层语句位候选：语句关键字（t0）+ 注解（t1）。
fn toplevel_items() -> Vec<Value> {
    let kw = [
        ("use", "顶层默认流水线 use(元件) |> 层(…)"),
        ("func", "具名函数 func name(p=默认) { pipeline }"),
        ("export:", "导出元件列表（- 名字）"),
        ("import", "引入库模块 import headers { eth }"),
    ];
    let attr = [
        ("#[proto]", "proto 协议函数注解（字段即参数）"),
        ("#[meta]", "字段元数据注解 auto/len/bits/…"),
        ("#[rule]", "解析规则注解"),
    ];
    let mut items: Vec<Value> = kw
        .iter()
        .enumerate()
        .map(|(i, (k, d))| {
            json!({ "label": k, "kind": 14, "detail": d, "insertText": k, "sortText": format!("00{i:02}{k}") })
        })
        .collect();
    items.extend(attr.iter().enumerate().map(|(i, (k, d))| {
        json!({ "label": k, "kind": 14, "detail": d, "insertText": k, "sortText": format!("01{i:02}{k}") })
    }));
    items
}

impl LspServer {
    /// 特判上下文（import/export/sniffer/attr）未命中后的通用位置分派。
    /// 出口统一做服务端前缀过滤（C3）：按光标前部分词过滤候选——前端 CM 过滤
    /// 行为不变，外部 LSP 编辑器直接受益（不再整表下发）。
    fn pkt_ctx_items(&self, text: &str, uri: &str, line_no: usize, col: usize) -> Vec<Value> {
        let items = match pkt_context(text, line_no, col) {
            PktCtx::Quiet => Vec::new(),
            PktCtx::Layer => self.layer_items(text, uri),
            PktCtx::LayerKind { quoted } => proto_kind_items(quoted),
            PktCtx::Use => self.use_items(text, uri),
            PktCtx::TopLevel => toplevel_items(),
            PktCtx::Args { func, used } => {
                if func == "use" {
                    self.use_items(text, uri)
                } else {
                    match self.func_params(&func, text, uri) {
                        // 有参数表：只补未填的 name=（部分词过滤交给出口统一做）
                        Some(params) if !params.is_empty() => arg_name_items(&func, &params, &used),
                        // 零参 / 位置实参函数（eth 参数表来自 proto 字段、u8( 数字位）：
                        Some(_) => vec![],
                        // 名字未知：是已知名字的严格前缀或本地已扫描到的名字（文档
                        // 不可解析时签名拿不到）→ 用户还在打名，宁空勿噪（C2）；
                        // 完全未知名 → 值候选（位置实参合法）
                        None => {
                            if self.unfinished_call_name(&func, text) {
                                vec![]
                            } else {
                                self.value_items(text, uri, None, None, Vec::new())
                            }
                        }
                    }
                }
            }
            PktCtx::Value { func, arg, scope } => {
                if func == "use" {
                    return self.use_items(text, uri);
                }
                let mut items = self.value_items(text, uri, Some(&func), arg.as_deref(), scope);
                // sniffer 块内的值位：同层其余字段引用置顶（sport=dport 匹配写法）
                if in_sniffer_block(text, line_no)
                    && let Some(fields) = packet_dsl::field_names(&func)
                {
                    let arg_ref = arg.as_deref();
                    let refs: Vec<Value> = fields
                        .iter()
                        .filter(|f| Some(**f) != arg_ref)
                        .enumerate()
                        .map(|(i, f)| {
                            json!({
                                "label": f,
                                "kind": 5,
                                "detail": "match 字段引用",
                                "insertText": f,
                                "sortText": format!("00{i:02}{f}"),
                            })
                        })
                        .collect();
                    items.splice(..0, refs);
                }
                items
            }
        };
        // 出口前缀过滤（C3）：部分词为空（`=`、`(`、`|>` 之后等）不过滤
        let prefix = cursor_word_prefix(text, line_no, col);
        if prefix.is_empty() {
            return items;
        }
        items
            .into_iter()
            .filter(|i| {
                i["label"]
                    .as_str()
                    .is_some_and(|l| l.starts_with(prefix.as_str()))
            })
            .collect()
    }

    /// 实参名位遇到解析不到的调用名：该名是否「已在输入中」——是已知名字的严格
    /// 前缀，或与本地兜底扫描到的名字相同（文档不可解析时签名拿不到但名字存在）。
    fn unfinished_call_name(&self, name: &str, text: &str) -> bool {
        let known = self.known_names(text);
        known.contains(name)
            || known
                .iter()
                .any(|k| k.starts_with(name) && k.len() > name.len())
    }

    /// 层位候选：t0 use + 常用层头 → t1 内置层原语 → t2 其余本地/库函数（字母序）。
    /// 不含元件 def（裸元件不能作管道步）与值专用原语（该位非法）。
    fn layer_items(&self, text: &str, uri: &str) -> Vec<Value> {
        let mut items: Vec<Value> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        // t0：use + 常用层头（层头须确为库函数才给——外部 lib 覆盖时自适应；
        // detail 复用库函数项带完整签名与来源模块，sortText 仍居 t0）
        let mut common: Vec<&str> = vec!["use"];
        common.extend(
            LAYER_COMMON
                .iter()
                .copied()
                .filter(|n| self.lib_has_func(n)),
        );
        for (i, name) in common.iter().enumerate() {
            seen.insert(name.to_string());
            if *name == "use" {
                items.push(json!({
                    "label": name,
                    "kind": 3,
                    "detail": "流水线组合 use(元件, …)",
                    "insertText": "use()",
                    "sortText": format!("00{i:02}{name}"),
                }));
            } else if let Some(exp) = self
                .lib_exports_cached()
                .iter()
                .chain(self.lib_functions_cached())
                .find(|e| &e.name == name)
            {
                items.push(lib_func_item(exp, format!("00{i:02}{name}")));
            }
        }
        // t1：内置层原语 raw/hex/layer
        for name in packet_dsl::registry::BUILTINS {
            seen.insert(name.to_string());
            if let Some(doc) = packet_dsl::registry::builtin_doc(name) {
                items.push(builtin_value_item(&doc, format!("01{name}")));
            }
        }
        // t2：其余本地函数（含本地 proto）+ 库函数（字母序；本地优先遮蔽）
        let mut t2: Vec<(String, Value)> = Vec::new();
        if let Ok(module) = try_parse(text, uri, &self.libs) {
            for f in &module.funcs {
                if seen.insert(f.name.clone()) {
                    t2.push((
                        f.name.clone(),
                        local_func_item(&f.name, &f.params, format!("02{}", f.name)),
                    ));
                }
            }
            for p in &module.protos {
                if seen.insert(p.name.clone()) {
                    t2.push((
                        p.name.clone(),
                        json!({
                            "label": p.name,
                            "kind": 3,
                            "detail": format!("#[proto] func {}(…)", p.name),
                            "insertText": format!("{}()", p.name),
                            "sortText": format!("02{}", p.name),
                        }),
                    ));
                }
            }
        }
        for exp in self
            .lib_functions_cached()
            .iter()
            .chain(self.lib_exports_cached())
        {
            if seen.insert(exp.name.clone()) {
                t2.push((
                    exp.name.clone(),
                    lib_func_item(exp, format!("02{}", exp.name)),
                ));
            }
        }
        t2.sort_by(|a, b| a.0.cmp(&b.0));
        items.extend(t2.into_iter().map(|(_, v)| v));
        items
    }

    /// use( 元件位：t0 本地元件 → t1 库元件导出。裸名插入（use 不接受调用实参）。
    fn use_items(&self, text: &str, uri: &str) -> Vec<Value> {
        let mut items: Vec<Value> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        match try_parse(text, uri, &self.libs) {
            Ok(module) => {
                for d in &module.defs {
                    if seen.insert(d.name.clone()) {
                        items.push(json!({
                            "label": d.name, "kind": 6, "detail": "本地元件",
                            "insertText": d.name, "sortText": format!("00{}", d.name),
                        }));
                    }
                }
            }
            // 输入中途不可解析：兜底扫描顶层 def 名
            Err(_) => {
                let (defs, _) = scan_top_level_names(text);
                for d in defs {
                    if seen.insert(d.clone()) {
                        items.push(json!({
                            "label": d, "kind": 6, "detail": "本地元件",
                            "insertText": d, "sortText": format!("00{d}"),
                        }));
                    }
                }
            }
        }
        for exp in self
            .lib_exports_cached()
            .iter()
            .chain(self.lib_functions_cached())
        {
            if exp.params.is_none() && seen.insert(exp.name.clone()) {
                items.push(json!({
                    "label": exp.name, "kind": 6,
                    "detail": format!("元件 [{}]", exp.module),
                    "insertText": exp.name, "sortText": format!("01{}", exp.name),
                }));
            }
        }
        items
    }

    /// 值位候选：t0 函数体作用域参数名 + (func, arg) 加权 → t1 值核心原语 →
    /// t2 其余值原语/本地函数/库值函数（字母序）→ t3 元件（载荷位引用）。
    /// 排除层头（LAYER_COMMON）与 proto 协议构建器——该位要的是值不是层。
    fn value_items(
        &self,
        text: &str,
        uri: &str,
        func: Option<&str>,
        arg: Option<&str>,
        scope: Vec<String>,
    ) -> Vec<Value> {
        if func == Some("layer") && arg == Some("kind") {
            return proto_kind_items(false);
        }
        let mut items: Vec<Value> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        // t0a：函数体作用域参数名（裸名引用——dport=port 是最常敲的形态）
        for (i, name) in scope.iter().enumerate() {
            if seen.insert(name.clone()) {
                items.push(json!({
                    "label": name, "kind": 6, "detail": "函数参数",
                    "insertText": name, "sortText": format!("00{i:02}{name}"),
                }));
            }
        }
        let builtin_docs = packet_dsl::registry::builtin_docs();
        // 值原语 = 内置文档全集去掉 layer（raw/hex 层值双位，保留）
        let builtin_value: std::collections::HashMap<&str, &packet_dsl::registry::BuiltinDoc> =
            builtin_docs
                .iter()
                .filter(|d| d.name != "layer")
                .map(|d| (d.name, d))
                .collect();
        let local = try_parse(text, uri, &self.libs).ok();
        // 库值函数 = 非 proto 函数（flags 助手/地址构造/net 工具…）
        let mut lib_plain: Vec<&packet_dsl::LibExport> = self
            .lib_functions_cached()
            .iter()
            .chain(self.lib_exports_cached())
            .filter(|e| e.params.is_some() && !e.is_proto)
            .collect();
        lib_plain.sort_by(|a, b| a.name.cmp(&b.name));
        lib_plain.dedup_by(|a, b| a.name == b.name);
        // 可用名集合（加权表只提升确实存在的候选）
        let available: std::collections::HashSet<&str> = builtin_value
            .keys()
            .copied()
            .chain(
                local
                    .as_ref()
                    .map(|m| m.funcs.iter().map(|f| f.name.as_str()))
                    .into_iter()
                    .flatten(),
            )
            .chain(lib_plain.iter().map(|e| e.name.as_str()))
            .collect();
        // t0b：(func, arg) 加权（flags= → syn/ack/…；dst= → ip4/mac…）
        let boost: &[&str] = match (func, arg) {
            (Some(f), Some(a)) => arg_value_boost(f, a),
            _ => &[],
        };
        let mut idx = scope.len();
        for &name in boost {
            if !available.contains(name) || !seen.insert(name.to_string()) {
                continue;
            }
            let item = match builtin_value.get(name) {
                Some(doc) => builtin_value_item(doc, format!("00{idx:02}")),
                None => match lib_plain.iter().find(|e| e.name == name) {
                    Some(e) => lib_func_item(e, format!("00{idx:02}")),
                    None => {
                        match local
                            .as_ref()
                            .and_then(|m| m.funcs.iter().find(|f| f.name == name))
                        {
                            Some(f) => local_func_item(&f.name, &f.params, format!("00{idx:02}")),
                            None => continue,
                        }
                    }
                },
            };
            items.push(item);
            idx += 1;
        }
        // t1：值核心原语（常用序）
        for name in VALUE_CORE {
            if let Some(doc) = builtin_value.get(name)
                && seen.insert(name.to_string())
            {
                items.push(builtin_value_item(doc, format!("01{name}")));
            }
        }
        // t2：其余值原语（字母序）→ 本地函数 → 库值函数（本地优先遮蔽）
        let mut rest: Vec<&packet_dsl::registry::BuiltinDoc> = builtin_value
            .values()
            .copied()
            .filter(|d| !VALUE_CORE.contains(&d.name) && !seen.contains(d.name))
            .collect();
        rest.sort_by_key(|d| d.name);
        for d in rest {
            if seen.insert(d.name.to_string()) {
                items.push(builtin_value_item(d, format!("02{}", d.name)));
            }
        }
        if let Some(m) = &local {
            for f in &m.funcs {
                if seen.insert(f.name.clone()) {
                    items.push(local_func_item(&f.name, &f.params, format!("02{}", f.name)));
                }
            }
        }
        for e in &lib_plain {
            if seen.insert(e.name.clone()) {
                items.push(lib_func_item(e, format!("02{}", e.name)));
            }
        }
        // t3：元件（载荷位引用 def 名，如 payload=q）
        if let Some(m) = &local {
            for d in &m.defs {
                if seen.insert(d.name.clone()) {
                    items.push(json!({
                        "label": d.name, "kind": 6, "detail": "本地元件",
                        "insertText": d.name, "sortText": format!("03{}", d.name),
                    }));
                }
            }
        }
        for e in self
            .lib_exports_cached()
            .iter()
            .chain(self.lib_functions_cached())
        {
            if e.params.is_none() && seen.insert(e.name.clone()) {
                items.push(json!({
                    "label": e.name, "kind": 6,
                    "detail": format!("元件 [{}]", e.module),
                    "insertText": e.name, "sortText": format!("03{}", e.name),
                }));
            }
        }
        items
    }

    /// 函数参数表（本地 → 库函数/导出 → 内置）：None = 名字无法解析。
    /// 值专用原语（u8/hex/params/…）只收位置实参 → 空表（实参名位不弹）。
    fn func_params(&self, name: &str, text: &str, uri: &str) -> Option<Vec<ParamInfo>> {
        if let Ok(module) = try_parse(text, uri, &self.libs)
            && let Some(f) = module.funcs.iter().find(|f| f.name == name)
        {
            return Some(
                f.params
                    .iter()
                    .map(|p| ParamInfo {
                        name: p.name.clone(),
                        default: p.default.as_ref().map(value_display),
                        desc: f
                            .doc
                            .as_ref()
                            .and_then(|d| d.params.iter().find(|(n, _)| n == &p.name))
                            .map(|(_, t)| t.clone()),
                    })
                    .collect(),
            );
        }
        for exp in self
            .lib_functions_cached()
            .iter()
            .chain(self.lib_exports_cached())
        {
            if exp.name == name {
                return Some(
                    exp.params
                        .as_ref()
                        .map(|ps| {
                            ps.iter()
                                .map(|p| ParamInfo {
                                    name: p.name.clone(),
                                    default: p.default.as_ref().map(value_display),
                                    desc: exp
                                        .doc
                                        .as_ref()
                                        .and_then(|d| d.params.iter().find(|(n, _)| n == &p.name))
                                        .map(|(_, t)| t.clone()),
                                })
                                .collect()
                        })
                        .unwrap_or_default(), // 元件：无实参名
                );
            }
        }
        match packet_dsl::registry::builtin_doc(name) {
            // 层位置原语接受命名实参（hex 层位同样只收位置串：hex("…")）
            Some(doc) if name == "raw" || name == "layer" => Some(
                doc.params
                    .iter()
                    .map(|(n, t)| ParamInfo {
                        name: n.to_string(),
                        default: None,
                        desc: Some(t.to_string()),
                    })
                    .collect(),
            ),
            // 其余原语只收位置实参（hex("…")/u8(n)/params("k") 等），不给 name=
            Some(_) => Some(vec![]),
            None => None,
        }
    }

    /// 名字是否为库内函数（导出与否均可）。
    fn lib_has_func(&self, name: &str) -> bool {
        self.lib_exports_cached()
            .iter()
            .chain(self.lib_functions_cached())
            .any(|e| e.name == name && e.params.is_some())
    }

    /// 参数名悬停：光标处 `name=` 的 name → 行内最近未闭合调用函数的参数说明
    ///（本地 doc → 库 doc → 内置参数表）。非参数位返回 None 落回原悬停逻辑。
    fn param_hover(
        &self,
        text: &str,
        uri: &str,
        line: usize,
        character: usize,
        word: &str,
    ) -> Option<String> {
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
        if !line_text[start..end].eq(word) {
            return None;
        }
        // 词后必须紧跟 `=`（参数名形态；`==` 不是）
        let after = line_text[end..].trim_start();
        if !after.starts_with('=') || after.starts_with("==") {
            return None;
        }
        let func = line_enclosing_func(&line_text[..start])?;
        let params = self.func_params(&func, text, uri)?;
        let p = params.iter().find(|p| p.name == word)?;
        let mut md = format!("### `{func}` 参数 `{}`\n\n", p.name);
        if let Some(d) = &p.desc {
            md.push_str(d);
            md.push('\n');
        }
        match &p.default {
            // proto 字段自指占位（默认值 ≡ 参数名）→ 显示「自动」
            Some(d) if *d != p.name => md.push_str(&format!("\n默认 `{d}`")),
            Some(_) => md.push_str("\n自动（proto 字段占位）"),
            None => md.push_str("\n未设（省略 → 自动值）"),
        }
        Some(md)
    }
}

/// 行内光标前最近一个未闭合调用的函数名（参数悬停定位所属函数用）。
fn line_enclosing_func(head: &str) -> Option<String> {
    let b = head.as_bytes();
    let mut in_q = false;
    let mut depth = 0i32;
    let mut i = b.len();
    while i > 0 {
        i -= 1;
        let c = b[i];
        if c == b'"' {
            in_q = !in_q;
            continue;
        }
        if in_q {
            continue;
        }
        match c {
            b')' => depth += 1,
            b'(' => {
                if depth > 0 {
                    depth -= 1;
                    continue;
                }
                let mut e = i;
                while e > 0 && (b[e - 1] as char).is_whitespace() {
                    e -= 1;
                }
                let mut st = e;
                while st > 0 && (b[st - 1].is_ascii_alphanumeric() || b[st - 1] == b'_') {
                    st -= 1;
                }
                if st == e {
                    return None;
                }
                return Some(head[st..e].to_string());
            }
            _ => {}
        }
    }
    None
}

/// 光标行向上是否处于 sniffer: 块内（块判定从 sniffer_context 拆出复用）。
fn in_sniffer_block(text: &str, line_no: usize) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    let last = lines.len().saturating_sub(1);
    for i in (0..=line_no.min(last)).rev() {
        let t = lines[i].trim_start();
        if t.starts_with('#') || t.starts_with('-') {
            continue;
        }
        return has_keyword_colon(t, "sniffer");
    }
    false
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
pub(crate) fn uri_info(uri: &str) -> Option<(String, PathBuf)> {
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
    fn completion_in_proto_attr_positions() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server.docs.insert(
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
        assert!(
            !keys.iter().any(|k| k.contains("(")),
            "meta 键位不应有函数: {keys:?}"
        );
    }
    #[test]
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
        // 值位（flags= 与 ack 之间）→ 值位加权（syn/ack 置顶）+ 同层字段引用
        let value = ask(4, 33);
        assert!(
            value.iter().any(|(l, _)| l == "ack"),
            "值位应有值函数 ack: {:?}",
            value
                .iter()
                .map(|(l, _)| l.clone())
                .take(8)
                .collect::<Vec<_>>()
        );
        assert!(
            value.iter().any(|(l, _)| l == "dport"),
            "sniffer 值位应有同层字段引用 dport: {:?}",
            value
                .iter()
                .map(|(l, _)| l.clone())
                .take(10)
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

    // ── 通用位置上下文（层位/实参名位/值位/语句位/字符串注释）──────────

    /// 各位置共享的探针：取 labels（按返回序）。
    fn labels_at(server: &LspServer, uri: &str, line: i32, ch: i32) -> Vec<String> {
        server
            .completion(&json!({
                "params": {
                    "textDocument": { "uri": uri },
                    "position": { "line": line, "character": ch },
                }
            }))
            .iter()
            .filter_map(|i| i["label"].as_str().map(str::to_string))
            .collect()
    }

    #[test]
    fn completion_after_pipe_lists_layers_only() {
        // 截图场景：`d = use(q) |>` 层位——只给 use/层函数，不再混入值原语与关键字，
        // 且常用层头排在协议构建器之前
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        let text = "q = icmp(type=8)\nd = use(q) |>\nexport:\n- full\n";
        server
            .docs
            .insert("file:///s.pkt".to_string(), text.to_string());
        let labels = labels_at(&server, "file:///s.pkt", 1, 14);
        assert_eq!(
            labels.first().map(String::as_str),
            Some("use"),
            "use 置顶: {labels:?}"
        );
        for want in ["eth", "ipv4", "udp", "tcp", "hex", "layer"] {
            assert!(
                labels.contains(&want.to_string()),
                "层位应有 {want}: {labels:?}"
            );
        }
        for noise in ["be16", "u8", "md5", "true", "false", "export", "q"] {
            assert!(
                !labels.contains(&noise.to_string()),
                "层位不应有 {noise}（值原语/关键字/裸元件非法）: {labels:?}"
            );
        }
        let pos = |n: &str| labels.iter().position(|l| l == n).unwrap();
        assert!(
            pos("udp") < pos("tls_record"),
            "常用层头应在协议构建器前: {labels:?}"
        );
    }

    #[test]
    fn completion_in_call_args_lists_param_names() {
        // tcp( 实参名位：服务端结构化参数表给未填的 name=（替代前端 detail 正则）
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        let text = "full = use(q) |> tcp(sport=1, \n";
        server
            .docs
            .insert("file:///s.pkt".to_string(), text.to_string());
        let labels = labels_at(&server, "file:///s.pkt", 0, 30);
        assert!(
            labels.iter().all(|l| l.ends_with('=')),
            "实参名位应全是 name=: {labels:?}"
        );
        assert!(
            labels.contains(&"dport=".to_string()),
            "应有 dport=: {labels:?}"
        );
        assert!(
            !labels.contains(&"sport=".to_string()),
            "已填参数不重复: {labels:?}"
        );
        // 部分词 dp 过滤交给前端；这里验证声明序（tcp 前段参数在前）
        assert_eq!(
            labels.first().map(String::as_str),
            Some("dport="),
            "{labels:?}"
        );
    }

    #[test]
    fn completion_zero_arg_call_is_quiet() {
        // u8( / hex( 等值原语只收位置实参：实参位不弹（宁空勿噪）
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "x = use(q) |> hex(\n".to_string(),
        );
        assert!(
            labels_at(&server, "file:///s.pkt", 0, 19).is_empty(),
            "hex( 括号内不应弹全量表"
        );
    }

    #[test]
    fn completion_value_position_boosts_by_arg() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        // flags= → TCP 标志助手置顶
        server.docs.insert(
            "file:///f.pkt".to_string(),
            "x = use(q) |> tcp(flags=\n".to_string(),
        );
        let flags = labels_at(&server, "file:///f.pkt", 0, 25);
        assert!(
            flags
                .iter()
                .take(4)
                .all(|l| ["syn", "ack", "fin", "rst"].contains(&l.as_str())),
            "flags= 前几位应是标志助手: {flags:?}"
        );
        assert!(
            !flags.contains(&"eth".to_string()) && !flags.contains(&"ipv4".to_string()),
            "值位不应有层头: {flags:?}"
        );
        // dport= → params/rand16 置顶
        server.docs.insert(
            "file:///d.pkt".to_string(),
            "x = use(q) |> udp(dport=\n".to_string(),
        );
        let dport = labels_at(&server, "file:///d.pkt", 0, 25);
        assert_eq!(
            dport.first().map(String::as_str),
            Some("params"),
            "dport= 应置顶 params: {dport:?}"
        );
        // ipv4 dst= → ip4
        server.docs.insert(
            "file:///i.pkt".to_string(),
            "x = use(q) |> ipv4(dst=\n".to_string(),
        );
        let dst = labels_at(&server, "file:///i.pkt", 0, 25);
        assert!(
            dst.iter().take(3).any(|l| l == "ip4"),
            "ipv4 dst= 前排应有 ip4: {dst:?}"
        );
    }

    #[test]
    fn completion_quiet_in_string_and_comment() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "x = use(q) |> tcp(dst=\"1\n".to_string(),
        );
        assert!(
            labels_at(&server, "file:///s.pkt", 0, 24).is_empty(),
            "字符串内不应弹候选"
        );
        server.docs.insert(
            "file:///c.pkt".to_string(),
            "# 注释 ( 里有括号\n".to_string(),
        );
        assert!(
            labels_at(&server, "file:///c.pkt", 0, 12).is_empty(),
            "注释内不应弹候选"
        );
    }

    #[test]
    fn completion_toplevel_lists_statements_only() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server
            .docs
            .insert("file:///s.pkt".to_string(), "\n".to_string());
        let labels = labels_at(&server, "file:///s.pkt", 0, 0);
        assert_eq!(
            labels.first().map(String::as_str),
            Some("use"),
            "顶层语句位 use 置顶: {labels:?}"
        );
        for want in ["func", "export:", "import", "#[proto]"] {
            assert!(
                labels.contains(&want.to_string()),
                "顶层应有 {want}: {labels:?}"
            );
        }
        assert!(
            !labels.contains(&"be16".to_string()) && !labels.contains(&"tcp".to_string()),
            "顶层语句位不给调用名: {labels:?}"
        );
    }

    #[test]
    fn completion_in_func_body_lists_layers_and_scope_params() {
        // 函数体语句起头 = 层位；值位额外给作用域参数名（dport=port 最常敲）
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        let text = "func f(port) {\n  udp(dport=\n}\n";
        server
            .docs
            .insert("file:///s.pkt".to_string(), text.to_string());
        // 语句起头（第 1 行缩进后）→ 层位
        let stmt = labels_at(&server, "file:///s.pkt", 1, 2);
        assert!(
            stmt.contains(&"udp".to_string()) && stmt.contains(&"use".to_string()),
            "函数体语句位应是层位: {stmt:?}"
        );
        // dport= 值位 → 作用域参数 port 置顶
        let value = labels_at(&server, "file:///s.pkt", 1, 12);
        assert_eq!(
            value.first().map(String::as_str),
            Some("port"),
            "函数体内值位应置顶参数引用 port: {value:?}"
        );
    }

    #[test]
    fn completion_use_lists_components() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        let text = "q = icmp(type=8)\nx = use(\n";
        server
            .docs
            .insert("file:///s.pkt".to_string(), text.to_string());
        let labels = labels_at(&server, "file:///s.pkt", 1, 9);
        assert!(
            labels.contains(&"q".to_string()),
            "use( 内应有本地元件 q: {labels:?}"
        );
        assert!(
            !labels.iter().any(|l| l.ends_with("()")),
            "use( 内是裸名插入，不接受调用: {labels:?}"
        );
    }

    #[test]
    fn completion_layer_kind_value() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        // layer(" 引号内 → 层类型裸名
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "x = use(q) |> layer(\"\n".to_string(),
        );
        let inside = labels_at(&server, "file:///s.pkt", 0, 22);
        assert!(
            inside.contains(&"tcp".to_string()) && inside.contains(&"eth".to_string()),
            "layer(\" 应给层类型: {inside:?}"
        );
        // layer(kind= 引号外 → 同集合（连引号插入）
        server.docs.insert(
            "file:///t.pkt".to_string(),
            "x = use(q) |> layer(kind=\n".to_string(),
        );
        let outside = labels_at(&server, "file:///t.pkt", 0, 26);
        assert!(
            outside.contains(&"tcp".to_string()),
            "layer(kind= 应给层类型: {outside:?}"
        );
    }

    #[test]
    fn completion_param_hover_and_component_hover() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        // 参数名悬停：icmp(type=8) 的 type → 参数说明（此前恒为无提示）
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "q = icmp(type=8)\n".to_string(),
        );
        let hov = server.hover(&json!({
            "params": {
                "textDocument": { "uri": "file:///s.pkt" },
                "position": { "line": 0, "character": 12 },
            }
        }));
        let md = hov["contents"]["value"].as_str().unwrap_or("");
        assert!(md.contains("`icmp` 参数 `type`"), "参数悬停应有说明: {md}");
        // 本地元件悬停：定义 + 片段（此前恒为无提示）
        server.docs.insert(
            "file:///d.pkt".to_string(),
            "q = icmp(type=8)\n".to_string(),
        );
        let hov2 = server.hover(&json!({
            "params": {
                "textDocument": { "uri": "file:///d.pkt" },
                "position": { "line": 0, "character": 1 },
            }
        }));
        let md2 = hov2["contents"]["value"].as_str().unwrap_or("");
        assert!(
            md2.contains("元件") && md2.contains("q = icmp"),
            "元件悬停应有定义: {md2}"
        );
    }

    #[test]
    fn completion_in_sniffer_value_lists_field_refs() {
        // sniffer 块内值位：同层其余字段引用置顶（sport=dport 匹配写法）
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        let text = "sniffer:\n  - match tcp(sport=\n";
        server
            .docs
            .insert("file:///s.pkt".to_string(), text.to_string());
        let labels = labels_at(&server, "file:///s.pkt", 1, 28);
        assert!(
            labels.contains(&"dport".to_string()),
            "sniffer 值位应有同层字段引用: {labels:?}"
        );
        assert!(
            !labels.contains(&"sport".to_string()),
            "当前字段自身不重复给: {labels:?}"
        );
    }

    #[test]
    fn diagnostics_skip_typing_transient_unknown_names() {
        // D2：函数名打到一半（名字是已知名字的严格前缀）→ 不报；
        // 真错误（完全未知名）照报。仅 LSP 路径豁免。
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "q = icmp(type=8)\nfull = u\n".to_string(),
        );
        assert!(
            server.diagnostics("file:///s.pkt").is_empty(),
            "`u` 是 use 的前缀（正在打词），不应报未知: {:?}",
            server.diagnostics("file:///s.pkt")
        );
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "q = icmp(type=8)\nfull = xyzzy()\n".to_string(),
        );
        let diags = server.diagnostics("file:///s.pkt");
        assert_eq!(diags.len(), 1, "完全未知名照报");
        assert!(diags[0]["message"].as_str().unwrap_or("").contains("未知"));
        // D3：export 项名字打到一半豁免
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "q = icmp(type=8)\nfull = use(q)\nexport:\n- ful\n".to_string(),
        );
        assert!(
            server.diagnostics("file:///s.pkt").is_empty(),
            "`ful` 是 full 的前缀（正在打词），不应报未定义: {:?}",
            server.diagnostics("file:///s.pkt")
        );
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "q = icmp(type=8)\nfull = use(q)\nexport:\n- zz\n".to_string(),
        );
        assert_eq!(server.diagnostics("file:///s.pkt").len(), 1, "真未定义照报");
        // `use` 关键字本身等值：`full = use` 是打向 use(q) 的必经中间态
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "q = icmp(type=8)\nfull = use\n".to_string(),
        );
        assert!(server.diagnostics("file:///s.pkt").is_empty());
    }

    #[test]
    fn completion_after_lone_pipe_lists_layers() {
        // C1：`|` 打了、`>` 还没打 → 层位（DSL 无 | 运算符，孤立 | 只出现在管道）
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        let text = "q = icmp(type=8)\nx = use(q) |";
        server
            .docs
            .insert("file:///s.pkt".to_string(), text.to_string());
        let labels = labels_at(&server, "file:///s.pkt", 1, 13);
        assert!(
            labels.contains(&"udp".to_string()) && labels.contains(&"eth".to_string()),
            "孤立 | 后应给层位候选: {labels:?}"
        );
        assert!(
            !labels.contains(&"func".to_string()) && !labels.contains(&"export:".to_string()),
            "孤立 | 后不应给语句关键字: {labels:?}"
        );
    }

    #[test]
    fn completion_unfinished_call_name_is_quiet() {
        // C2：实参位函数名打到一半（tc → tcp）→ 空；完全未知名 → 值候选回落保留
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "q = icmp(type=8)\nx = use(q) |> tc(".to_string(),
        );
        assert!(
            labels_at(&server, "file:///s.pkt", 1, 17).is_empty(),
            "tc( 是 tcp 的前缀（正在打名），不应弹值全表"
        );
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "q = icmp(type=8)\nx = use(q) |> zzz(".to_string(),
        );
        assert!(
            !labels_at(&server, "file:///s.pkt", 1, 19).is_empty(),
            "完全未知调用名仍回落值候选"
        );
    }

    #[test]
    fn completion_prefix_filter_on_server() {
        // C3：服务端按光标前部分词前缀过滤（空词不过滤；= ( 之后词为空）
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "q = icmp(type=8)\nx = use(q) |> ud".to_string(),
        );
        assert_eq!(
            labels_at(&server, "file:///s.pkt", 1, 16),
            vec!["udp".to_string(), "udp_bytes".to_string()],
            "部分词 ud 只剩 udp 系候选"
        );
        server.docs.insert(
            "file:///s.pkt".to_string(),
            "q = icmp(type=8)\nx = use(q) |> udp(dport=pa".to_string(),
        );
        let labels = labels_at(&server, "file:///s.pkt", 1, 28);
        assert!(
            !labels.is_empty() && labels.iter().all(|l| l.starts_with("pa")),
            "值位部分词 pa 只留 pa 前缀候选: {labels:?}"
        );
        assert!(labels.contains(&"params".to_string()), "{labels:?}");
    }

    #[test]
    fn completion_def_value_position_lists_layers() {
        // `x = ` 后打函数名：def 值位 = 层调用位（此前误归语句关键字位，不出候选）
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        // `x = ` 空值：整张层位表，use 置顶
        server
            .docs
            .insert("file:///s.pkt".to_string(), "x = ".to_string());
        let labels = labels_at(&server, "file:///s.pkt", 0, 4);
        assert_eq!(
            labels.first().map(String::as_str),
            Some("use"),
            "def 值位应给层调用候选: {labels:?}"
        );
        assert!(
            !labels.contains(&"func".to_string()) && !labels.contains(&"export:".to_string()),
            "def 值位不应给语句关键字: {labels:?}"
        );
        // 部分词 tc → 前缀过滤到 tcp 系
        server
            .docs
            .insert("file:///s.pkt".to_string(), "x = tc".to_string());
        let labels = labels_at(&server, "file:///s.pkt", 0, 6);
        assert!(
            labels.contains(&"tcp".to_string()),
            "def 值位打 tc 应补出 tcp: {labels:?}"
        );
        // 值内实参位不被影响：x = icmp( → 参数名
        server
            .docs
            .insert("file:///s.pkt".to_string(), "x = icmp(".to_string());
        let labels = labels_at(&server, "file:///s.pkt", 0, 9);
        assert!(
            labels.iter().all(|l| l.ends_with('=')),
            "def 值内实参名位仍应是参数名: {labels:?}"
        );
    }

    #[test]
    fn recipe_from_second_level_paths() {
        let mut server = LspServer {
            libs: Vec::new(),
            ..LspServer::default()
        };
        let text = "recipe:\n- packet: x.pkt\n  extract:\n  - name: t\n    from: reply.\n";
        server
            .docs
            .insert("file:///s.pktl".to_string(), text.to_string());
        // reply. → 层名（插入带尾点）
        let layers = labels_at(&server, "file:///s.pktl", 4, 16);
        assert!(
            layers.contains(&"reply.tcp".to_string()) && layers.contains(&"reply.dns".to_string()),
            "reply. 后应有层名: {layers:?}"
        );
        // reply.tcp. → 该层字段
        let text2 = "recipe:\n- packet: x.pkt\n  extract:\n  - name: t\n    from: reply.tcp.\n";
        server
            .docs
            .insert("file:///s.pktl".to_string(), text2.to_string());
        let fields = labels_at(&server, "file:///s.pktl", 4, 20);
        assert!(
            fields.contains(&"reply.tcp.sport".to_string()),
            "reply.tcp. 后应有字段: {fields:?}"
        );
    }
}
