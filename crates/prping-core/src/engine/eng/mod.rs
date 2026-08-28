//! 引擎模式（`--eng`）：.pkt 分析的精美输出 + LSP 语言服务器（`--eng --lsp`）。
//!
//! - 精美输出：模块概览 → 逐来源逐包展示层栈（字段 + auto 标注）→ 字节 hexdump（带 ASCII）。
//! - LSP：JSON-RPC over stdio（Content-Length 分帧），提供诊断 / 补全 / 悬停 / 文档符号。

mod display;
mod lsp;

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use packet_dsl::PacketSource;
use termcolor::{Ansi, ColorChoice, StandardStream};

use crate::output::{indent, print_cyan, print_dim, print_green, print_magenta, print_orange, print_yellow};

use display::render_module_header;

/// DSL 值 → 展示字符串（函数参数默认值渲染 / sniffer 字面量用）。
pub fn value_display(v: &packet_dsl::ast::Value) -> String {
    match v {
        packet_dsl::ast::Value::Str(s) => format!("\"{s}\""),
        packet_dsl::ast::Value::Int(i) => i.to_string(),
        packet_dsl::ast::Value::Hex(h) => {
            // 字节对齐（偶数位）小写：0x0800/0x86dd/0x00/0x0100，与协议字段展示
            // （eth ethertype `0x{:04x}`）及 eng_lib 文档中的写法一致。
            let digits = ((64 - h.leading_zeros()) as usize).div_ceil(4);
            let width = if digits <= 2 {
                2
            } else {
                digits + (digits % 2)
            };
            format!("0x{h:0width$x}")
        }
        packet_dsl::ast::Value::List(items) => {
            let inner: Vec<String> = items.iter().map(value_display).collect();
            format!("[{}]", inner.join(", "))
        }
        packet_dsl::ast::Value::Param { name, default } => match default {
            Some(d) => format!("params(\"{name}\", {})", value_display(d)),
            None => format!("params(\"{name}\")"),
        },
        packet_dsl::ast::Value::Ident { name, .. } => name.clone(),
        packet_dsl::ast::Value::Call { name, args, .. } => {
            let inner: Vec<String> = args.iter().map(value_display).collect();
            format!("{name}({})", inner.join(", "))
        }
        packet_dsl::ast::Value::BinOp {
            op, left, right, ..
        } => {
            format!(
                "{} {} {}",
                value_display(left),
                packet_dsl::registry::binop_str(*op),
                value_display(right)
            )
        }
    }
}

// ══════════════════════════════════════════════════════════════
// 配方参数面收集（步骤 .pkt 的 params 词法收集）
// ══════════════════════════════════════════════════════════════

/// 步骤 .pkt 用到的运行时参数（`params("name", default)`），词法收集。
///
/// 遍历文件 AST 的 def / func（层函数 body + 值函数 `value_body`）/ 顶层匿名流水线 /
/// sniffer 匹配值表达式里的 [`packet_dsl::ast::Value::Param`] 节点，返回 (参数名, 默认值)
/// 列表（不排序不去重，按出现顺序）。
///
/// 两点保证使词法收集即完整：
/// - `params(...)` 首参必为字符串字面量（parser 只产出字面量名），名字静态可知；
/// - eng_lib（headers.pkt 等）不引用 `params`，无需沿 import 边追进库模块。
///
/// 供 `engine FILE.pktl` 概览展示配方参数面、`send_recipe` 运行时 header 汇总。
pub(crate) fn collect_pkt_params(
    path: &Path,
) -> anyhow::Result<Vec<(String, Option<packet_dsl::ast::Value>)>> {
    let src = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("读取失败：{e}"))?;
    let ast = packet_dsl::parser::parse_ast(&src).map_err(|d| anyhow::anyhow!("解析失败：{d}"))?;
    let mut out: Vec<(String, Option<packet_dsl::ast::Value>)> = Vec::new();
    for stmt in &ast.stmts {
        match stmt {
            packet_dsl::ast::Stmt::Def(d) => match &d.expr {
                packet_dsl::ast::Expr::Call(c) => walk_call_args(&c.args, &mut out),
                packet_dsl::ast::Expr::Pipeline(p) => walk_pipeline(p, &mut out),
            },
            packet_dsl::ast::Stmt::Pipeline(p) => {
                walk_pipeline(&p.pipeline, &mut out);
            }
            packet_dsl::ast::Stmt::Func(f) if f.schema.is_some() => {
                // proto 函数 = 带 schema 的 FuncStmt：字段的 width（bytes 宽度
                // 表达式）与默认值可能是值表达式
                let schema = f.schema.as_ref().expect("guard: schema.is_some()");
                for fd in &schema.fields {
                    if let Some(v) = &fd.width {
                        walk_value(v, &mut out);
                    }
                    if let Some(v) = &fd.default {
                        walk_value(v, &mut out);
                    }
                }
            }
            packet_dsl::ast::Stmt::Func(f) => {
                // 值函数：body 可能引用 params
                if let Some((_ret, body)) = &f.value_body {
                    walk_value(body, &mut out);
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// 遍历 pipeline 里的 params 节点。
fn walk_pipeline(
    p: &packet_dsl::ast::Pipeline,
    out: &mut Vec<(String, Option<packet_dsl::ast::Value>)>,
) {
    for c in &p.layers {
        walk_call_args(&c.args, out);
    }
}

/// 遍历调用参数里的 params 节点。
fn walk_call_args(
    args: &[packet_dsl::ast::Arg],
    out: &mut Vec<(String, Option<packet_dsl::ast::Value>)>,
) {
    for a in args {
        walk_value(&a.value, out);
    }
}

/// 遍历值表达式里的 params 节点。
fn walk_value(v: &packet_dsl::ast::Value, out: &mut Vec<(String, Option<packet_dsl::ast::Value>)>) {
    match v {
        packet_dsl::ast::Value::Param { name, default } => {
            out.push((name.clone(), default.as_deref().cloned()));
        }
        packet_dsl::ast::Value::Call { args, .. } => {
            for a in args {
                walk_value(a, out);
            }
        }
        packet_dsl::ast::Value::List(items) => {
            for i in items {
                walk_value(i, out);
            }
        }
        packet_dsl::ast::Value::BinOp { left, right, .. } => {
            walk_value(left, out);
            walk_value(right, out);
        }
        _ => {}
    }
}

/// 聚合配方参数面：按名字排序去重，合并默认值列表与步骤索引。
pub fn aggregate_pkt_params(
    per_step: &[Vec<(String, Option<packet_dsl::ast::Value>)>],
) -> Vec<(String, Vec<packet_dsl::ast::Value>, Vec<usize>)> {
    let mut map: HashMap<String, (Vec<packet_dsl::ast::Value>, Vec<usize>)> = HashMap::new();
    for (step_idx, params) in per_step.iter().enumerate() {
        for (name, default) in params {
            let entry = map.entry(name.clone()).or_default();
            if let Some(d) = default
                && !entry.0.contains(d)
            {
                entry.0.push(d.clone());
            }
            if !entry.1.contains(&(step_idx + 1)) {
                entry.1.push(step_idx + 1);
            }
        }
    }
    let mut out: Vec<_> = map.into_iter().map(|(k, (v1, v2))| (k, v1, v2)).collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// 遍历 `from:` 表达式 AST 里的 `reply("层","字段")` 叶子并校验层/字段名
/// （字面量参数才静态校验；`reply(global("l"), "f")` 等动态参数留给执行期报错）。
pub(crate) fn validate_expr_reply_leaves(
    v: &packet_dsl::ast::Value,
    line: usize,
) -> anyhow::Result<()> {
    use packet_dsl::ast::Value;
    match v {
        Value::Call { name, args, .. } => {
            if name == "reply"
                && let [Value::Str(layer), Value::Str(field)] = &args[..]
            {
                let names = crate::engine::pkg::reply_field_names(layer).ok_or_else(|| {
                    anyhow::anyhow!(
                        "配方 {line} 行：未知回包层 `{layer}`（可用：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns/raw）"
                    )
                })?;
                if !names.contains(&field.as_str()) {
                    anyhow::bail!(
                        "配方 {line} 行：层 {layer} 没有字段 `{field}`（可用：{}）",
                        names.join("/")
                    );
                }
            }
            for a in args {
                validate_expr_reply_leaves(a, line)?;
            }
        }
        Value::List(items) => {
            for it in items {
                validate_expr_reply_leaves(it, line)?;
            }
        }
        Value::BinOp { left, right, .. } => {
            validate_expr_reply_leaves(left, line)?;
            validate_expr_reply_leaves(right, line)?;
        }
        _ => {}
    }
    Ok(())
}

/// 注入默认 DNS 解析器（ToSocketAddrs，v4 优先）；进程级，首个生效。
/// `dns("host")` 原语与地址字段的域名解析依赖它（packet-dsl 本身不发网络请求）。
pub fn ensure_dns_resolver() {
    packet_dsl::set_dns_resolver(|host| {
        crate::util::resolve_vec(host, 0, false, false)
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.ip())
            .collect()
    });
}

/// 注册表加载用库目录：编译期烘焙的 `eng_lib` 优先；缺失（发布版布局，只有
/// `lib/` 没有 `eng_lib/`）时回退运行时 `lib/`——先找可执行文件同目录，再找
/// 当前工作目录（与 CLI `resolve_libs` 的 CWD `lib/` 语义一致；serve 在部署
/// 目录运行、engine/packet 在仓库运行都能加载到协议声明）。
pub(crate) fn registry_libs() -> Vec<PathBuf> {
    let baked = packet_dsl::default_libs();
    if !baked.is_empty() {
        return baked;
    }
    let mut runtime = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
        && dir.join("lib").is_dir()
    {
        runtime.push(dir.join("lib"));
    }
    let cwd = Path::new("lib");
    if cwd.is_dir() {
        runtime.push(cwd.to_path_buf());
    }
    runtime
}

/// 从默认 eng_lib 目录加载 proto 声明进注册表（进程级，首个生效）。
pub fn ensure_proto_registry() {
    if !packet_dsl::proto_registry().is_empty() {
        return;
    }
    let libs = registry_libs();
    let mut protos = Vec::new();
    for dir in libs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().is_none_or(|x| x != "pkt") {
                continue;
            }
            let Ok(m) = packet_dsl::parse_file_with_libs(&path, &[]) else {
                continue;
            };
            for p in m.protos {
                protos.push(packet_dsl::ResolvedProto {
                    name: p.name.clone(),
                    layer: p.layer.clone(),
                    rule: p.rule.clone(),
                    params: p
                        .params
                        .iter()
                        .map(|x| packet_dsl::ast::FuncParam {
                            name: x.name.clone(),
                            span: x.span,
                            default: x.default.clone(),
                        })
                        .collect(),
                    fields: p.fields.clone(),
                });
            }
        }
    }
    packet_dsl::set_proto_registry(protos);
}

/// 实际生效的库目录 = 默认 eng_lib（编译期路径，发布态可能为空）+ 显式 libs。
/// 与 `parse_file_with_libs` 内部合并顺序一致（默认在前、显式追加）。
pub fn effective_libs(libs: &[PathBuf]) -> Vec<PathBuf> {
    let mut all = packet_dsl::default_libs();
    all.extend_from_slice(libs);
    all
}

/// 库目录列表的展示字符串（空 → `(none)`；路径做 canonicalize）。
pub fn libs_display(libs: &[PathBuf]) -> String {
    if libs.is_empty() {
        "(none)".to_string()
    } else {
        libs.iter()
            .map(|p| {
                std::fs::canonicalize(p)
                    .unwrap_or_else(|_| p.clone())
                    .display()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

// ── 渲染（忠实拆分自原 `engine/eng.rs` 的渲染段，见 `display.rs`）──────────

pub use display::{
    dns_type_name, layer_name, opt_bytes_len, print_stack_warnings, render_dissected,
    render_hexdump, render_layers, render_packet, render_packet_fields,
};

/// 文档 → Markdown（LSP 悬停用）。
pub(crate) fn doc_markdown(doc: &packet_dsl::ast::FuncDoc) -> String {
    let mut md = String::new();
    if !doc.summary.is_empty() {
        md.push_str(&format!("{}\n\n", doc.summary));
    }
    if let Some(auto) = &doc.auto {
        md.push_str(&format!("**auto**：{auto}\n\n"));
    }
    md
}

/// LSP 语言服务器入口。
pub fn run_lsp(libs: &[PathBuf]) -> anyhow::Result<()> {
    lsp::run_lsp(libs)
}

/// LSP 语言服务器入口（指定输入输出）。
pub fn run_lsp_on<R: io::Read, W: io::Write>(
    reader: R,
    writer: W,
    libs: &[PathBuf],
) -> anyhow::Result<()> {
    lsp::run_lsp_on(reader, writer, libs)
}

/// 列出全部内置原语与库层头函数的字段表（对标 scapy `ls()`）。
/// 输出自动分页（tty 时使用 $PAGER，非 tty 时确保完整输出）。
pub fn ls_builtins(libs: &[PathBuf]) -> anyhow::Result<()> {
    let libs = effective_libs(libs);
    let mut buf = Vec::new();
    {
        let mut w = Ansi::new(&mut buf);
        print_magenta(&mut w, "packet-dsl builtins")?;
        writeln!(&mut w)?;
        print_dim(&mut w, format!("libs: {}", libs_display(&libs)))?;
        writeln!(&mut w)?;
        writeln!(&mut w)?;
        for doc in packet_dsl::builtin_docs() {
            // 签名只列参数名（与库函数一致；类型/说明在参数行）
            let params: Vec<String> = doc.params.iter().map(|(n, _)| n.to_string()).collect();
            print_cyan(&mut w, format!("{}({})", doc.name, params.join(", ")))?;
            writeln!(&mut w)?;
            // 摘要：签名下第一行，"""...""" 文档字符串（与库函数同构）
            if !doc.summary.is_empty() {
                print_green(&mut w, format!("{}\"\"\"", indent(2)))?;
                writeln!(&mut w)?;
                for line in doc.summary.lines() {
                    print_green(&mut w, format!("{}{line}", indent(2)))?;
                    writeln!(&mut w)?;
                }
                print_green(&mut w, format!("{}\"\"\"", indent(2)))?;
                writeln!(&mut w)?;
            }
            for (n, t) in &doc.params {
                print_dim(&mut w, format!("{}{}: {t}", indent(2), n))?;
                writeln!(&mut w)?;
            }
            print_yellow(&mut w, format!("{}auto: {}", indent(2), doc.auto))?;
            writeln!(&mut w)?;
        }
        // 库层头函数（eng_lib，隐式可见）：列签名
        let funcs = packet_dsl::lib_exports(&libs)
            .into_iter()
            .filter(|e| e.params.is_some())
            .collect::<Vec<_>>();
        if !funcs.is_empty() {
            print_magenta(&mut w, "\neng_lib layer functions")?;
            writeln!(&mut w)?;
            for e in funcs {
                let ps: Vec<String> = e
                    .params
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|p| match &p.default {
                        Some(d) => format!("{}={}", p.name, value_display(d)),
                        None => p.name.clone(),
                    })
                    .collect();
                print_cyan(&mut w, format!("{}({})", e.name, ps.join(", ")))?;
                writeln!(&mut w)?;
                if let Some(doc) = &e.doc {
                    // doc 摘要：签名下第一行，"""...""" 文档字符串（多行摘要整体包裹，绿色）
                    if !doc.summary.is_empty() {
                        print_green(&mut w, format!("{}\"\"\"", indent(2)))?;
                        writeln!(&mut w)?;
                        for line in doc.summary.lines() {
                            print_green(&mut w, format!("{}{line}", indent(2)))?;
                            writeln!(&mut w)?;
                        }
                        print_green(&mut w, format!("{}\"\"\"", indent(2)))?;
                        writeln!(&mut w)?;
                    }
                    // 逐参数说明：按声明顺序，只列有 @param 说明的参数
                    for p in e.params.as_ref().unwrap() {
                        if let Some((_, desc)) = doc.params.iter().find(|(n, _)| n == &p.name) {
                            print_dim(&mut w, format!("{}{}: {desc}", indent(2), p.name))?;
                            writeln!(&mut w)?;
                        }
                    }
                    if let Some(auto) = &doc.auto {
                        print_yellow(&mut w, format!("{}auto: {auto}", indent(2)))?;
                        writeln!(&mut w)?;
                    }
                }
                print_dim(
                    &mut w,
                    format!("{}[{}] 库函数（隐式可见）", indent(2), e.module),
                )?;
                writeln!(&mut w)?;
            }
        }
    }
    let output = String::from_utf8_lossy(&buf);
    crate::manual::print_paged(&output)?;
    Ok(())
}

/// 解析 hex 字符串并展示反解结果。
pub fn decode_hex(hex: &str) -> anyhow::Result<()> {
    ensure_proto_registry();
    let hex = hex.replace([' ', '\n'], "");
    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| anyhow::anyhow!("hex 解析失败：{e}"))?;
        bytes.push(byte);
    }
    let mut w = StandardStream::stdout(ColorChoice::Auto);
    let report = packet_dsl::dissect(&bytes);
    render_dissected(&mut w, &report, "hex:", &bytes)?;
    Ok(())
}

/// 解析 pcap 文件并展示反解结果。
pub fn decode_pcap(path: &Path) -> anyhow::Result<()> {
    ensure_proto_registry();
    let (_version, _nano, records) = crate::engine::pcap::read_pcap(path)?;
    let mut w = StandardStream::stdout(ColorChoice::Auto);
    print_magenta(&mut w, "packet-dsl pcap")?;
    writeln!(&mut w)?;
    print_cyan(&mut w, format!("file: {}", path.display()))?;
    writeln!(&mut w)?;
    print_dim(&mut w, format!("records: {}", records.len()))?;
    writeln!(&mut w)?;
    writeln!(&mut w)?;
    for (i, record) in records.iter().enumerate() {
        let report = packet_dsl::dissect(&record.data);
        let header = format!("frame {}:", i + 1);
        render_dissected(&mut w, &report, &header, &record.data)?;
    }
    Ok(())
}

pub fn analyze_file(
    path: &Path,
    params: &[(String, String)],
    globals: &packet_dsl::Globals,
    libs: &[std::path::PathBuf],
) -> anyhow::Result<()> {
    ensure_dns_resolver();
    ensure_proto_registry();
    let module =
        packet_dsl::parse_file_with_libs(path, libs).map_err(|d| anyhow::anyhow!("{d}"))?;
    let p: packet_dsl::Params = params.iter().cloned().collect();
    let sources = packet_dsl::resolve_sources_with_globals(&module, &p, globals)
        .map_err(|d| anyhow::anyhow!("{d}"))?;
    let total: usize = sources.iter().map(|(_, p)| p.len()).sum();
    if total == 0 {
        anyhow::bail!("没有可求值的包：文件既无默认导出，也无命名导出");
    }

    let mut w = StandardStream::stdout(ColorChoice::Auto);
    let libs = effective_libs(libs);
    render_module_header(&mut w, &module, total, &libs, params)?;
    let mut idx = 0usize;
    for (source, pkts) in &sources {
        for pkt in pkts {
            idx += 1;
            render_packet(
                &mut w,
                pkt,
                &format!(
                    "packet {idx}/{total}  [{}]",
                    match source {
                        PacketSource::Default => "default export".to_string(),
                        PacketSource::Export(name) => format!("export \"{name}\""),
                    }
                ),
            )?;
            print_stack_warnings(&mut w, pkt)?;
            // 发送方式提示：无 TCP/UDP 传输层的包只能经 raw 模式发送（--raw / 配方 raw: true）
            crate::engine::pkg::print_raw_only_hint(&mut w, pkt)?;
        }
    }
    Ok(())
}

pub fn analyze_recipe(path: &Path) -> anyhow::Result<()> {
    use crate::engine::recipe::{ExtractAs, FromSpec, OnError};

    let recipe = crate::engine::recipe::parse(path)?;
    // 校验 extract 的层/字段名（执行期同样报错，这里提前暴露笔误）：
    // - 直取形态 `reply.<层>.<字段>`：sniffer 字段集；
    // - 表达式形态：遍历 AST 里的 `reply("层","字段")` 叶子（字面量参数才校验）
    for step in &recipe.steps {
        for e in &step.extract {
            match &e.from {
                FromSpec::Field { layer, field } => {
                    let names = crate::engine::pkg::sniffer_field_names(layer).ok_or_else(|| {
                        anyhow::anyhow!(
                            "配方 {} 行：未知回包层 `{}`（可用：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns）",
                            e.line,
                            layer
                        )
                    })?;
                    if !names.contains(&field.as_str()) {
                        anyhow::bail!(
                            "配方 {} 行：层 {} 没有字段 `{}`（可用：{}）",
                            e.line,
                            layer,
                            field,
                            names.join("/")
                        );
                    }
                }
                FromSpec::Expr(v) => {
                    validate_expr_reply_leaves(v, e.line)?;
                }
            }
        }
    }
    // 步骤 .pkt 用到的 params（词法收集 `params("名", 默认)`）。解析失败 = 配方在
    // 执行期同样失败，概览提前暴露（与 extract 字段校验同一「提前报错」哲学）。
    let mut per_step: Vec<Vec<(String, Option<packet_dsl::ast::Value>)>> = Vec::new();
    for (i, step) in recipe.steps.iter().enumerate() {
        let used = collect_pkt_params(&step.pkg).map_err(|e| {
            anyhow::anyhow!(
                "配方 {}：第 {}/{} 步 {}：{e}",
                path.display(),
                i + 1,
                recipe.steps.len(),
                step.pkg.display()
            )
        })?;
        per_step.push(used);
    }
    let params_agg = aggregate_pkt_params(&per_step);
    let mut w = StandardStream::stdout(ColorChoice::Auto);
    print_magenta(&mut w, "prping engine recipe")?;
    writeln!(&mut w)?;
    print_cyan(
        &mut w,
        format!(
            "{} — {} step(s), {} global(s), {} param(s)",
            path.display(),
            recipe.steps.len(),
            recipe.globals.len(),
            params_agg.len()
        ),
    )?;
    writeln!(&mut w)?;
    writeln!(&mut w)?;
    if !recipe.globals.is_empty() {
        print_green(&mut w, "globals:")?;
        writeln!(&mut w)?;
        for g in &recipe.globals {
            let init = match &g.init {
                Some(v) => format!("  (init = {})", value_display(v)),
                None => "  (unset until extract)".to_string(),
            };
            print_dim(&mut w, format!("  - {}{}", g.name, init))?;
            writeln!(&mut w)?;
        }
        writeln!(&mut w)?;
    }
    if !params_agg.is_empty() {
        print_green(&mut w, "params (inject via -p k=v):")?;
        writeln!(&mut w)?;
        for (name, defaults, _) in &params_agg {
            let has_default = !defaults.is_empty();
            let def = match defaults.len() {
                0 => "required".to_string(),
                1 => format!("default: {}", value_display(&defaults[0])),
                _ => format!(
                    "default: {}",
                    defaults
                        .iter()
                        .map(value_display)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            // 无默认值（必需参数）用橙色警告，有默认值用灰色
            if has_default {
                print_dim(
                    &mut w,
                    format!("{}- {name} ({def})", indent(1)),
                )?;
            } else {
                print_orange(
                    &mut w,
                    format!("{}- {name} ({def})", indent(1)),
                )?;
            }
            writeln!(&mut w)?;
        }
        writeln!(&mut w)?;
    }
    for (i, step) in recipe.steps.iter().enumerate() {
        print_green(&mut w, format!("step {}: {}", i + 1, step.pkg.display()))?;
        writeln!(&mut w)?;
        if let Some(secs) = step.wait {
            print_dim(&mut w, format!("{}wait: {secs}s", indent(1)))?;
            writeln!(&mut w)?;
        }
        if let Some(secs) = step.delay {
            print_dim(&mut w, format!("{}delay: {secs}s", indent(1)))?;
            writeln!(&mut w)?;
        }
        if let Some(raw) = &step.raw {
            let desc = match raw {
                crate::engine::recipe::StepRaw::On { iface } => match iface {
                    Some(i) => format!("raw: {i}"),
                    None => "raw: true".to_string(),
                },
                crate::engine::recipe::StepRaw::Off => "raw: false".to_string(),
            };
            print_dim(&mut w, format!("{}{desc}", indent(1)))?;
            writeln!(&mut w)?;
        }
        if !step.params.is_empty() {
            let ps: Vec<String> = step
                .params
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            print_dim(&mut w, format!("{}params: {}", indent(1), ps.join(", ")))?;
            writeln!(&mut w)?;
        }
        for e in &step.extract {
            let as_name = match e.as_ {
                ExtractAs::Int => "int",
                ExtractAs::Hex => "hex",
                ExtractAs::Str => "str",
                ExtractAs::Bytes => "bytes",
            };
            let from_desc = match &e.from {
                FromSpec::Field { layer, field } => format!("reply.{layer}.{field}"),
                FromSpec::Expr(v) => value_display(v),
            };
            let as_desc = if e.as_given {
                format!(" ({as_name})")
            } else {
                String::new()
            };
            print_dim(
                &mut w,
                format!("{}extract: {} ← {from_desc}{as_desc}", indent(1), e.name),
            )?;
            writeln!(&mut w)?;
        }
        let on_error = match step.on_error {
            OnError::Stop => "stop",
            OnError::Continue => "continue",
        };
        print_dim(&mut w, format!("{}on_error: {on_error}", indent(1)))?;
        writeln!(&mut w)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("prping-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn collect_pkt_params_errors() {
        let dir = temp_dir("errors");
        let missing = dir.join("missing.pkt");
        let err = collect_pkt_params(&missing).unwrap_err();
        assert!(err.to_string().contains("读取失败"), "{err}");

        let bad = dir.join("bad.pkt");
        std::fs::write(&bad, "this is not a valid pkt !!").unwrap();
        let err = collect_pkt_params(&bad).unwrap_err();
        assert!(err.to_string().contains("解析失败"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_pkt_params_with_and_without_default() {
        let dir = temp_dir("params");
        let pkt = dir.join("test.pkt");
        std::fs::write(
            &pkt,
            r#"req = icmp(type=8, seq=params("seq", 1))
use(req) |> ipv4(dst=params("ip"), ttl=64)
"#,
        )
        .unwrap();
        let params = collect_pkt_params(&pkt).unwrap();
        assert_eq!(params.len(), 2, "应收集到 seq 和 ip 两个参数");
        // seq 有默认值 1
        let seq = params.iter().find(|(n, _)| n == "seq").unwrap();
        assert!(seq.1.is_some(), "seq 应有默认值");
        // ip 无默认值
        let ip = params.iter().find(|(n, _)| n == "ip").unwrap();
        assert!(ip.1.is_none(), "ip 应无默认值");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 按空格折行：短文本一行、贪心打包、超宽词硬切、空文本。
    #[test]
    fn wrap_words_break_at_spaces() {
        assert_eq!(display::wrap_words("", 10), Vec::<String>::new());
        assert_eq!(display::wrap_words("a b c", 10), vec!["a b c"]);
        // 贪心打包到宽度
        assert_eq!(
            display::wrap_words("aa bb cc dd", 5),
            vec!["aa bb", "cc dd"]
        );
        // 超宽词硬切
        assert_eq!(display::wrap_words("abcdefgh", 4), vec!["abcd", "efgh"]);
        // 混合：词超宽时先硬切，剩余部分续到下一行
        assert_eq!(
            display::wrap_words("aa xxxxxx bb", 4),
            vec!["aa", "xxxx", "xx", "bb"]
        );
        // 宽度 1：逐字符
        assert_eq!(display::wrap_words("ab cd", 1), vec!["a", "b", "c", "d"]);
    }

    /// 层行折行后逐行长度不超宽（按字符计，UTF-8 安全）。
    #[test]
    fn wrap_words_respects_width() {
        for width in [1usize, 8, 20, 40] {
            let text = "version=4 ihl=5 tos=0x00 len=35 id=7982 flags=- frag=0 \
                        ttl=64 proto=ICMP chksum=0x5daa src=127.0.0.1 dst=127.0.0.1";
            for line in display::wrap_words(text, width) {
                assert!(line.chars().count() <= width, "{line:?} 超宽 {width}");
            }
        }
        // 超长连续词（如 dns(域名->ip)）不 panic、不丢字
        let long = "dst=dns(very.long.hostname.example.com->198.18.0.5) src=127.0.0.1";
        let joined = display::wrap_words(long, 10).join("");
        assert_eq!(joined.replace(' ', ""), long.replace(' ', ""));
    }

    /// 聚合：同名同默认值去重、同名不同默认值全保留、无默认参数、步骤列表合并。
    #[test]
    fn aggregate_pkt_params_dedup() {
        let per_step = vec![
            vec![
                (
                    "dst".to_string(),
                    Some(packet_dsl::ast::Value::Str("127.0.0.1".into())),
                ),
                ("id".to_string(), Some(packet_dsl::ast::Value::Hex(0x1234))),
                ("nodelay".to_string(), None),
            ],
            vec![
                (
                    "dst".to_string(),
                    Some(packet_dsl::ast::Value::Str("127.0.0.1".into())),
                ),
                ("id".to_string(), Some(packet_dsl::ast::Value::Hex(0x5678))),
            ],
            vec![("dst".to_string(), None)],
        ];
        let agg = aggregate_pkt_params(&per_step);
        assert_eq!(agg.len(), 3, "按名字排序去重：dst / id / nodelay");
        assert_eq!(agg[0].0, "dst");
        assert_eq!(
            agg[0].1,
            vec![packet_dsl::ast::Value::Str("127.0.0.1".into())],
            "同默认值去重"
        );
        assert_eq!(agg[0].2, vec![1, 2, 3], "含无默认的步骤 3");
        assert_eq!(agg[1].0, "id");
        assert_eq!(
            agg[1].1,
            vec![
                packet_dsl::ast::Value::Hex(0x1234),
                packet_dsl::ast::Value::Hex(0x5678)
            ]
        );
        assert_eq!(agg[1].2, vec![1, 2]);
        assert_eq!(agg[2].0, "nodelay");
        assert!(agg[2].1.is_empty(), "无默认");
        assert_eq!(agg[2].2, vec![1]);
    }
}
