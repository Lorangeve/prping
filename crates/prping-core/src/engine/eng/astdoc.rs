//! 块视图（低代码）信封数据：AST 结构化导出（`ast` 信封）+ 原语/库层 schema（`schema` 信封）。
//!
//! 为什么不复用 analyze 的 fields（docs/design-web-editor.md §10）：analyze 的字段
//! 是**渲染后的展示串**——len/checksum 已求值、raw 层从字节反解、auto 标注混入，
//! 且无位置信息，只够只读层栈面板，做不了块视图的 IR。这里直接序列化 AST：
//!
//! - **原文保真**：调用实参按 span 从源码切片（保留 0x 前缀/引号/表达式原样），
//!   求值结果永远是 analyze 的职责，块视图只管结构；
//! - **span 全量携带**（1 基行/列，端点排他——与 lexer 的 `col + len` 构造一致）：
//!   前端按 span 排序还原源码顺序（Module 按类别分组，顺序信息只在 span 里），
//!   为阶段 2（块 → 文本回写）预留定位；
//! - 解析入口与 analyze 同一 [`parse_editor_source`]（URI → 模块名/目录规则一致，
//!   相对 import 行为统一）；解析/语义失败 → Err（前端降级只读提示）。

use std::path::PathBuf;

use anyhow::anyhow;
use packet_dsl::ast::{Call, Expr, FieldType, Pipeline, Span};
use packet_dsl::semantic::Module;
use serde_json::{Value as Json, json};

use super::{effective_libs, parse_editor_source, value_display};

// ── 源码切片 ─────────────────────────────────────────────────

/// 源码切片器：按 1 基行/列 span 取原文。
struct Slicer {
    text: String,
    /// 每行（0 基）的起始字节偏移。
    line_starts: Vec<usize>,
}

impl Slicer {
    fn new(text: &str) -> Self {
        let mut line_starts = vec![0usize];
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i + 1);
            }
        }
        Self {
            text: text.to_string(),
            line_starts,
        }
    }

    /// 1 基 (line, col) → 字节偏移。col 按字符计（与 lexer 一致）；越界取行尾/文尾。
    fn offset(&self, line: usize, col: usize) -> usize {
        let li = line.saturating_sub(1).min(self.line_starts.len() - 1);
        let start = self.line_starts[li];
        let line_end = self
            .line_starts
            .get(li + 1)
            .map(|&n| n.saturating_sub(1)) // 去掉换行符本身
            .unwrap_or(self.text.len());
        let line_text = &self.text[start..line_end];
        // 第 col-1 个字符后的字节偏移；col 超行宽 → 行尾
        match line_text.char_indices().nth(col.saturating_sub(1)) {
            Some((off, _)) => start + off,
            None => start + line_text.len(),
        }
    }

    /// 切 span 原文（端点排他），首尾去空白。畸形 span（end < start）→ 空串。
    fn slice(&self, span: &Span) -> String {
        let a = self.offset(span.start.line, span.start.col);
        let b = self.offset(span.end.line, span.end.col);
        if b <= a {
            return String::new();
        }
        self.text[a..b.min(self.text.len())].trim().to_string()
    }
}

/// Span → 紧凑 JSON（1 基行/列；键缩写减小载荷：start line/col、end line/col）。
fn span_json(s: Span) -> Json {
    json!({ "sl": s.start.line, "sc": s.start.col, "el": s.end.line, "ec": s.end.col })
}

fn span_key(it: &Json) -> (u64, u64) {
    let sp = it.get("span");
    (
        sp.and_then(|s| s.get("sl"))
            .and_then(Json::as_u64)
            .unwrap_or(0),
        sp.and_then(|s| s.get("sc"))
            .and_then(Json::as_u64)
            .unwrap_or(0),
    )
}

// ── AST 序列化 ───────────────────────────────────────────────

fn pipeline_json(p: &Pipeline, s: &Slicer) -> Json {
    json!({
        // use(...) 引入的元件（源码顺序）
        "use": p
            .use_names
            .iter()
            .map(|(n, sp)| json!({ "name": n, "span": span_json(*sp) }))
            .collect::<Vec<_>>(),
        // 层调用序列（内 → 外，与 DSL 语义一致）
        "layers": p.layers.iter().map(|c| call_json(c, s)).collect::<Vec<_>>(),
    })
}

fn call_json(c: &Call, s: &Slicer) -> Json {
    json!({
        "name": c.name,
        "span": span_json(c.span),
        // 实参原文切片：0x/引号/表达式原样（值保真的关键）。命名实参的 span
        // 覆盖整个 `name = value`——剥掉前导 `name`、`=` 与空白只留值原文
        "args": c
            .args
            .iter()
            .map(|a| {
                let full = s.slice(&a.span);
                let value = match &a.name {
                    Some((n, _)) => full
                        .strip_prefix(n.as_str())
                        .map(|rest| {
                            let rest = rest.trim_start();
                            rest.strip_prefix('=')
                                .map(str::trim_start)
                                .unwrap_or(rest)
                        })
                        .unwrap_or(full.as_str())
                        .to_string(),
                    None => full,
                };
                json!({
                    "name": a.name.as_ref().map(|(n, _)| n.clone()),
                    "value": value,
                    "span": span_json(a.span),
                })
            })
            .collect::<Vec<_>>(),
    })
}

/// 字段线格式类型 → 短名（块视图字段提示用）。
fn field_type_str(ty: FieldType) -> &'static str {
    match ty {
        FieldType::U8 => "u8",
        FieldType::Be16 => "be16",
        FieldType::Be32 => "be32",
        FieldType::Be64 => "be64",
        FieldType::Le16 => "le16",
        FieldType::Le32 => "le32",
        FieldType::Le64 => "le64",
        FieldType::Vint => "vint",
        FieldType::Mac => "mac",
        FieldType::Ip4 => "ip4",
        FieldType::Ip6 => "ip6",
        FieldType::Bytes => "bytes",
        FieldType::Rest => "rest",
        FieldType::DnsName => "dns_name",
        FieldType::Line => "line",
    }
}

/// AST 结构化导出（`ast` 信封）：语句项按源码顺序（span 升序）。
///
/// 项类别：pipeline（顶层匿名流水线）/ def（命名元件）/ func / proto / import /
/// sniffer。每项携带 span；call 实参为原文切片。
pub fn ast_text_json(uri: &str, text: &str, libs: &[PathBuf]) -> anyhow::Result<Json> {
    let libs = effective_libs(libs);
    let module: Module = parse_editor_source(uri, text, &libs).map_err(|d| anyhow!("{d}"))?;
    let slicer = Slicer::new(text);
    let mut items: Vec<Json> = Vec::new();

    if let Some((p, span)) = &module.default {
        items.push(json!({
            "kind": "pipeline",
            "pipeline": pipeline_json(p, &slicer),
            "span": span_json(*span),
        }));
    }
    for d in &module.defs {
        let mut expr = match &d.expr {
            Expr::Call(c) => call_json(c, &slicer),
            Expr::Pipeline(p) => pipeline_json(p, &slicer),
        };
        expr["kind"] = json!(match &d.expr {
            Expr::Call(_) => "call",
            Expr::Pipeline(_) => "pipeline",
        });
        items.push(json!({
            "kind": "def",
            "name": d.name,
            "expr": expr,
            "span": span_json(d.span),
        }));
    }
    for f in &module.funcs {
        items.push(json!({
            "kind": "func",
            "name": f.name,
            "params": f
                .params
                .iter()
                .map(|p| json!({
                    "name": p.name,
                    "default": p.default.as_ref().map(value_display),
                }))
                .collect::<Vec<_>>(),
            "doc": f.doc.as_ref().map(|d| d.summary.clone()),
            "body": pipeline_json(&f.body, &slicer),
            "span": span_json(f.span),
        }));
    }
    for p in &module.protos {
        items.push(json!({
            "kind": "proto",
            "name": p.name,
            "layer": p.layer,
            "fields": p
                .fields
                .iter()
                .map(|fd| {
                    let mut f = json!({ "name": fd.name, "ty": field_type_str(fd.ty) });
                    if let Some(w) = &fd.width {
                        f["width"] = json!(value_display(w));
                    }
                    if let Some(d) = &fd.default {
                        f["default"] = json!(value_display(d));
                    }
                    if let Some(b) = fd.bits {
                        f["bits"] = json!(b);
                    }
                    f
                })
                .collect::<Vec<_>>(),
            "span": span_json(p.span),
        }));
    }
    for i in &module.imports {
        items.push(json!({
            "kind": "import",
            "module": i.module,
            "span": span_json(i.span),
        }));
    }
    if let Some(s) = &module.sniffer {
        items.push(json!({ "kind": "sniffer", "span": span_json(s.span) }));
    }
    // 源码顺序（Module 按类别分组返回，顺序信息只在 span 里）
    items.sort_by_key(span_key);
    Ok(json!({
        "mode": "packet",
        "file": uri,
        "module": module.name,
        "items": items,
    }))
}

// ── 配方（.pktl）导出 ────────────────────────────────────────

/// uri → 本地路径（file:// 前缀剥离；其余原样）。
fn uri_path(uri: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(uri.strip_prefix("file://").unwrap_or(uri))
}

/// 配方（.pktl）结构化导出（ast 信封 recipe 形态）：global 项 + 步骤（一块一步骤）。
/// 每步骤带行区间（sl..el 含，供删行/插行）与文件 token 的 fileSpan（改名拼接用）。
pub fn recipe_text_json(uri: &str, text: &str) -> anyhow::Result<Json> {
    let recipe =
        crate::engine::recipe::parse_text(text, &uri_path(uri)).map_err(|e| anyhow!("{e}"))?;
    let lines: Vec<&str> = text.lines().collect();

    // 步骤块行区间：起始行起，最后一个「缩进选项行」；空行跳过、行首新项/段头终止
    let step_end = |start: usize| -> usize {
        let mut end = start;
        for (i, raw) in lines.iter().enumerate().skip(start) {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            if raw.starts_with(' ') || raw.starts_with('\u{9}') {
                end = i + 1;
                continue;
            }
            break;
        }
        end
    };

    let globals: Vec<Json> = recipe
        .globals
        .iter()
        .map(|g| {
            json!({
                "name": g.name,
                "init": g.init.as_ref().map(value_display),
                "line": g.line,
            })
        })
        .collect();

    let steps: Vec<Json> = recipe
        .steps
        .iter()
        .map(|s| {
            let end = step_end(s.line);
            let raw = lines.get(s.line - 1).copied().unwrap_or("");
            // 文件 token：剥行内注释后，"- packet: 文件" / 裸 "- 文件" 的文件段
            // （1 基列，端点排他——与 ast 切片语义一致）
            let no_comment = raw.split('#').next().unwrap_or("").trim_end();
            let trimmed = no_comment.trim_start();
            let indent = no_comment.len() - trimmed.len();
            let (fsc, fec) = if let Some(rest) = trimmed.strip_prefix("- packet:") {
                let lead = rest.len() - rest.trim_start().len();
                let start = indent + "- packet:".len() + lead;
                (start + 1, no_comment.len() + 1)
            } else if let Some(rest) = trimmed.strip_prefix("- ") {
                let lead = rest.len() - rest.trim_start().len();
                let start = indent + 2 + lead;
                (start + 1, no_comment.len() + 1)
            } else {
                (1, 1)
            };
            // 文件取书写原文（Step.pkg 是解析期相对配方目录解析后的路径——
            // 块视图改名/round-trip 需要与配方文本逐字对应）
            let file_token = no_comment
                .get(fsc.saturating_sub(1)..fec.saturating_sub(1))
                .unwrap_or("")
                .to_string();
            let mut flags: Vec<Json> = Vec::new();
            if s.wait.is_some() {
                flags.push(json!("wait"));
            }
            if s.on_timeout.is_some() {
                flags.push(json!("on_timeout"));
            }
            if let Some(n) = s.count {
                flags.push(json!(format!("count={n}")));
            }
            if let Some(sec) = s.delay {
                flags.push(json!(format!("delay={sec}")));
            }
            if s.raw.is_some() {
                flags.push(json!("raw"));
            }
            if !s.params.is_empty() {
                flags.push(json!(format!("params×{}", s.params.len())));
            }
            if !s.extract.is_empty() {
                flags.push(json!(format!("extract×{}", s.extract.len())));
            }
            if matches!(s.on_error, crate::engine::recipe::OnError::Continue) {
                flags.push(json!("on_error=continue"));
            }
            json!({
                "file": file_token,
                "line": s.line,
                "endLine": end,
                "fileSpan": { "sl": s.line, "sc": fsc, "el": s.line, "ec": fec },
                "span": { "sl": s.line, "sc": 1, "el": end, "ec": 1 },
                "flags": flags,
            })
        })
        .collect();

    Ok(json!({
        "mode": "recipe",
        "file": uri,
        "globals": globals,
        "steps": steps,
    }))
}

/// 块视图数据路由（ast 信封统一入口）：.pktl → 配方导出，其余 → packet AST。
pub fn blocks_json(uri: &str, text: &str, libs: &[PathBuf]) -> anyhow::Result<Json> {
    if uri.ends_with(".pktl") {
        recipe_text_json(uri, text)
    } else {
        ast_text_json(uri, text, libs)
    }
}

/// 原语/库层 schema（`schema` 信封）：块定义的字段提示与悬停文档数据源。
///
/// builtins = 引擎内建原语（层位置 raw/hex/layer + 值位置字节原语，`--ls`/LSP
/// 补全同源）；libLayers = eng_lib 层头函数/协议（字段名 + 默认值 + 摘要）。
pub fn schema_json(libs: &[PathBuf]) -> Json {
    let libs = effective_libs(libs);
    let builtins: Vec<Json> = packet_dsl::registry::builtin_docs()
        .iter()
        .map(|d| {
            json!({
                "name": d.name,
                "params": d
                    .params
                    .iter()
                    .map(|(n, t)| json!([n, t]))
                    .collect::<Vec<_>>(),
                "summary": d.summary,
                "auto": d.auto,
            })
        })
        .collect();
    let lib_funcs: Vec<Json> = packet_dsl::lib_exports(&libs)
        .iter()
        .filter(|e| e.params.is_some())
        .map(|e| {
            json!({
                "name": e.name,
                "module": e.module,
                "isProto": e.is_proto,
                "params": e.params.as_ref().map(|ps| {
                    ps.iter()
                        .map(|p| json!({
                            "name": p.name,
                            "default": p.default.as_ref().map(value_display),
                        }))
                        .collect::<Vec<_>>()
                }),
                "summary": e.doc.as_ref().map(|d| d.summary.clone()),
            })
        })
        .collect();
    json!({ "builtins": builtins, "libLayers": lib_funcs })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "req = icmp(type=8, id=0x1234, seq=1)\n\
                          \n\
                          use(req) |> ipv4(dst=\"127.0.0.1\", ttl=64) |> eth()\n";

    #[test]
    fn ast_items_sorted_with_source_order() {
        let doc = ast_text_json("file:///scratch.pkt", SAMPLE, &[]).unwrap();
        let items = doc["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        // 源码顺序：def（第 1 行）在前、顶层 pipeline（第 3 行）在后
        assert_eq!(items[0]["kind"], "def");
        assert_eq!(items[0]["name"], "req");
        assert_eq!(items[1]["kind"], "pipeline");
        // def 的 expr：call icmp，实参原文保真（0x 前缀原样）
        assert_eq!(items[0]["expr"]["kind"], "call");
        assert_eq!(items[0]["expr"]["name"], "icmp");
        let args = items[0]["expr"]["args"].as_array().unwrap();
        assert_eq!(args[0]["name"], "type");
        assert_eq!(args[0]["value"], "8");
        assert_eq!(args[1]["value"], "0x1234");
        // 顶层 pipeline：use 名单 + 层序（内 → 外）
        let pl = &items[1]["pipeline"];
        assert_eq!(pl["use"][0]["name"], "req");
        assert_eq!(pl["layers"][0]["name"], "ipv4");
        assert_eq!(pl["layers"][1]["name"], "eth");
        let ipargs = pl["layers"][0]["args"].as_array().unwrap();
        assert_eq!(ipargs[0]["name"], "dst");
        assert_eq!(ipargs[0]["value"], "\"127.0.0.1\""); // 引号原样
    }

    #[test]
    fn ast_multiline_slice_and_empty_doc() {
        // 空文档 → 0 项；跨行实参切片正确
        let empty = ast_text_json("file:///e.pkt", "", &[]).unwrap();
        assert_eq!(empty["items"].as_array().unwrap().len(), 0);

        let doc = ast_text_json("file:///m.pkt", "x = hex(\n    \"deadbeef\",\n)\n", &[]).unwrap();
        let items = doc["items"].as_array().unwrap();
        let args = items[0]["expr"]["args"].as_array().unwrap();
        assert_eq!(args[0]["value"], "\"deadbeef\"");
    }

    #[test]
    fn ast_semantic_error_is_err() {
        // 未知名（解析可过、语义不可过）→ Err，块视图降级
        assert!(ast_text_json("file:///x.pkt", "x = nosuchlayer(a=1)\n", &[]).is_err());
    }

    #[test]
    fn recipe_steps_spans_and_globals() {
        let text = "global:\n- tid=0x1234\nrecipe:\n- packet: a.pkt\n  wait: 1\n- packet: b.pkt\n";
        let doc = recipe_text_json("file:///r.pktl", text).unwrap();
        assert_eq!(doc["mode"], "recipe");
        let globals = doc["globals"].as_array().unwrap();
        assert_eq!(globals.len(), 1);
        assert_eq!(globals[0]["name"], "tid");
        assert_eq!(globals[0]["init"], "0x1234");
        assert_eq!(globals[0]["line"], 2);
        let steps = doc["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["file"], "a.pkt");
        // 步骤 1 块含缩进选项行（wait: 1）；步骤 2 到 EOF
        assert_eq!(steps[0]["line"], 4);
        assert_eq!(steps[0]["endLine"], 5);
        assert_eq!(steps[1]["line"], 6);
        assert_eq!(steps[1]["endLine"], 6);
        // 文件 token span："- packet: a.pkt" 列 11..16（排他）→ 切片 = "a.pkt"
        let fs = &steps[0]["fileSpan"];
        assert_eq!(fs["sl"], 4);
        assert_eq!(fs["sc"], 11);
        assert_eq!(fs["el"], 4);
        assert_eq!(fs["ec"], 16);
        assert_eq!(
            &text.lines().nth(3).unwrap()
                [fs["sc"].as_i64().unwrap() as usize - 1..fs["ec"].as_i64().unwrap() as usize - 1],
            "a.pkt"
        );
        // 步骤 1 带选项 → wait 旗标
        assert!(
            steps[0]["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f == "wait")
        );
    }

    #[test]
    fn schema_has_builtins_and_lib_layers() {
        let doc = schema_json(&[]);
        let builtins = doc["builtins"].as_array().unwrap();
        assert!(builtins.iter().any(|b| b["name"] == "raw"));
        assert!(builtins.iter().any(|b| b["name"] == "layer"));
        let libs = doc["libLayers"].as_array().unwrap();
        let icmp = libs
            .iter()
            .find(|l| l["name"] == "icmp" && l["isProto"] == true)
            .expect("eng_lib icmp proto in schema");
        let params = icmp["params"].as_array().unwrap();
        assert!(params.iter().any(|p| p["name"] == "type"));
    }
}
