//! 引擎模式（`--eng`）：.pkt 分析的精美输出 + LSP 语言服务器（`--eng --lsp`）。
//!
//! - 精美输出：模块概览 → 逐来源逐包展示层栈（字段 + auto 标注）→ 字节 hexdump（带 ASCII）。
//! - LSP：JSON-RPC over stdio（Content-Length 分帧），提供诊断 / 补全 / 悬停 / 文档符号。

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use packet_dsl::ir::{Layer, MacAddr, PacketSpec};
use packet_dsl::semantic::Module;
use packet_dsl::{DefaultSerializer, PacketSource};
use rust_i18n::t;
use termcolor::{ColorChoice, StandardStream, WriteColor};

use crate::output::{
    print_cyan, print_dim, print_green, print_magenta, print_yellow, writeln_orange,
};

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
                walk_pipeline(&f.body, &mut out);
                if let Some((_, v)) = &f.value_body {
                    walk_value(v, &mut out);
                }
            }
            packet_dsl::ast::Stmt::Pipeline(p) => walk_pipeline(&p.pipeline, &mut out),
            packet_dsl::ast::Stmt::Sniffer(s) => {
                for cl in &s.clauses {
                    for (_, sv) in &cl.fields {
                        match sv {
                            packet_dsl::ast::SnifferValue::Literal(v)
                            | packet_dsl::ast::SnifferValue::Expr(v) => walk_value(v, &mut out),
                            packet_dsl::ast::SnifferValue::SentField(_) => {}
                        }
                    }
                }
            }
            packet_dsl::ast::Stmt::Export(_) | packet_dsl::ast::Stmt::Import(_) => {}
        }
    }
    Ok(out)
}

fn walk_pipeline(
    p: &packet_dsl::ast::Pipeline,
    out: &mut Vec<(String, Option<packet_dsl::ast::Value>)>,
) {
    for c in &p.layers {
        walk_call_args(&c.args, out);
    }
}

fn walk_call_args(
    args: &[packet_dsl::ast::Arg],
    out: &mut Vec<(String, Option<packet_dsl::ast::Value>)>,
) {
    for a in args {
        walk_value(&a.value, out);
    }
}

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

/// 跨步骤聚合参数面：参数名（排序）→ (去重默认值[首个出现序], 使用步骤[1-based])。
/// 同名默认值在不同步骤不同时全部保留（展示 `= a, b`；步骤列表可辅助对应）。
pub(crate) fn aggregate_pkt_params(
    per_step: &[Vec<(String, Option<packet_dsl::ast::Value>)>],
) -> Vec<(String, Vec<packet_dsl::ast::Value>, Vec<usize>)> {
    let mut agg: HashMap<String, (Vec<packet_dsl::ast::Value>, Vec<usize>)> = HashMap::new();
    for (i, used) in per_step.iter().enumerate() {
        for (name, default) in used {
            let e = agg.entry(name.clone()).or_default();
            if let Some(d) = default
                && !e.0.iter().any(|x| x == d)
            {
                e.0.push(d.clone());
            }
            if !e.1.contains(&(i + 1)) {
                e.1.push(i + 1);
            }
        }
    }
    let mut out: Vec<_> = agg
        .into_iter()
        .map(|(n, (defaults, steps))| (n, defaults, steps))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

// ══════════════════════════════════════════════════════════════
// 精美输出
// ══════════════════════════════════════════════════════════════

/// `FuncDoc` → markdown 正文（摘要段落 + auto 说明；供 LSP 悬停）。
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

/// `--eng --ls`：列出全部内置原语与库层头函数的字段表（对标 scapy `ls()`）。
pub fn ls_builtins(libs: &[std::path::PathBuf]) -> anyhow::Result<()> {
    let libs = effective_libs(libs);
    let mut w = StandardStream::stdout(ColorChoice::Auto);
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
            print_green(&mut w, "    \"\"\"")?;
            writeln!(&mut w)?;
            for line in doc.summary.lines() {
                print_green(&mut w, format!("    {line}"))?;
                writeln!(&mut w)?;
            }
            print_green(&mut w, "    \"\"\"")?;
            writeln!(&mut w)?;
        }
        for (n, t) in &doc.params {
            print_dim(&mut w, format!("    {n}: {t}"))?;
            writeln!(&mut w)?;
        }
        print_yellow(&mut w, format!("    auto: {}", doc.auto))?;
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
                    print_green(&mut w, "    \"\"\"")?;
                    writeln!(&mut w)?;
                    for line in doc.summary.lines() {
                        print_green(&mut w, format!("    {line}"))?;
                        writeln!(&mut w)?;
                    }
                    print_green(&mut w, "    \"\"\"")?;
                    writeln!(&mut w)?;
                }
                // 逐参数说明：按声明顺序，只列有 @param 说明的参数
                for p in e.params.as_ref().unwrap() {
                    if let Some((_, desc)) = doc.params.iter().find(|(n, _)| n == &p.name) {
                        print_dim(&mut w, format!("    {}: {desc}", p.name))?;
                        writeln!(&mut w)?;
                    }
                }
                if let Some(auto) = &doc.auto {
                    print_yellow(&mut w, format!("    auto: {auto}"))?;
                    writeln!(&mut w)?;
                }
            }
            print_dim(&mut w, format!("    [{}] 库函数（隐式可见）", e.module))?;
            writeln!(&mut w)?;
        }
    }
    Ok(())
}

/// `--eng --hex <hex>`：反解并展示十六进制字节（对标 scapy `Ether(bytes)` + `show()`）。
pub fn decode_hex(hex: &str) -> anyhow::Result<()> {
    ensure_proto_registry();
    let hex_str: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if !hex_str.len().is_multiple_of(2) || !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("--hex 需要偶数长度的十六进制字符串");
    }
    let bytes = (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).expect("已校验 hex"))
        .collect::<Vec<_>>();
    let report = packet_dsl::dissect(&bytes);
    let mut w = StandardStream::stdout(ColorChoice::Auto);
    print_magenta(&mut w, "packet-dsl dissect")?;
    writeln!(&mut w)?;
    render_dissected(&mut w, &report, &format!("{} bytes", bytes.len()), &bytes)
        .map_err(anyhow::Error::from)
}

/// `--eng --pcap <file>`：读 pcap 并逐条反解展示。
pub fn decode_pcap(path: &Path) -> anyhow::Result<()> {
    ensure_proto_registry();
    let (network, nano, records) = crate::engine::pcap::read_pcap(path)?;
    let mut w = StandardStream::stdout(ColorChoice::Auto);
    print_magenta(&mut w, "packet-dsl pcap")?;
    writeln!(&mut w)?;
    print_dim(
        &mut w,
        format!(
            "file: {}  linktype: {}  records: {}",
            path.display(),
            network,
            records.len()
        ),
    )?;
    writeln!(&mut w)?;
    writeln!(&mut w)?;
    for (i, rec) in records.iter().enumerate() {
        let ts = if nano {
            format!("{}.{:09}", rec.ts_sec, rec.ts_frac)
        } else {
            format!("{}.{:06}", rec.ts_sec, rec.ts_frac)
        };
        let report = packet_dsl::dissect(&rec.data);
        render_dissected(
            &mut w,
            &report,
            &format!("record {}/{}  [t={ts}]", i + 1, records.len()),
            &rec.data,
        )?;
    }
    Ok(())
}

/// 分析一个 .pkt 文件并输出完整可视化（`--eng FILE`）。
///
/// `globals` 注入配方全局存储（`-g k=v`，`global("名"[, 默认])` 值原语读取）——
/// 与 `--pkt` 一致：`--eng` 也接受 `-g`，缺省为空。
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
    render_module_header(&mut w, &module, total, &libs)?;
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

/// `--eng FILE.pktl`：配方结构概览（global 声明 + 步骤及选项），并校验
/// `extract` 的 `from:` 层/字段名（与 sniffer 字段集一致）。
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
    print_magenta(&mut w, "packet-dsl recipe")?;
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
        print_green(&mut w, "params (from step pkts; inject via -p k=v):")?;
        writeln!(&mut w)?;
        for (name, defaults, steps) in &params_agg {
            let def = match defaults.len() {
                0 => "no default".to_string(),
                1 => format!("= {}", value_display(&defaults[0])),
                _ => format!(
                    "= {}",
                    defaults
                        .iter()
                        .map(value_display)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            let step_desc = if steps.len() == 1 {
                format!("step {}", steps[0])
            } else {
                format!(
                    "steps {}",
                    steps
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            print_dim(&mut w, format!("  - {name} ({def}; {step_desc})"))?;
            writeln!(&mut w)?;
        }
        writeln!(&mut w)?;
    }
    for (i, step) in recipe.steps.iter().enumerate() {
        print_green(&mut w, format!("step {}: {}", i + 1, step.pkg.display()))?;
        writeln!(&mut w)?;
        if let Some(secs) = step.wait {
            print_dim(&mut w, format!("  wait: {secs}s"))?;
            writeln!(&mut w)?;
        }
        if let Some(secs) = step.delay {
            print_dim(&mut w, format!("  delay: {secs}s"))?;
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
            print_dim(&mut w, format!("  {desc}"))?;
            writeln!(&mut w)?;
        }
        if !step.params.is_empty() {
            let ps: Vec<String> = step
                .params
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            print_dim(&mut w, format!("  params: {}", ps.join(", ")))?;
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
                format!("  extract: {} ← {from_desc}{as_desc}", e.name),
            )?;
            writeln!(&mut w)?;
        }
        let on_error = match step.on_error {
            OnError::Stop => "stop",
            OnError::Continue => "continue",
        };
        print_dim(&mut w, format!("  on_error: {on_error}"))?;
        writeln!(&mut w)?;
    }
    Ok(())
}

/// 遍历 `from:` 表达式 AST 里的 `reply("层","字段")` 叶子并校验层/字段名
/// （字面量参数才静态校验；`reply(global("l"), "f")` 等动态参数留给执行期报错）。
fn validate_expr_reply_leaves(v: &packet_dsl::ast::Value, line: usize) -> anyhow::Result<()> {
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
        Value::Param {
            default: Some(d), ..
        } => validate_expr_reply_leaves(d, line)?,
        Value::Param { .. } => {}
        Value::BinOp { left, right, .. } => {
            validate_expr_reply_leaves(left, line)?;
            validate_expr_reply_leaves(right, line)?;
        }
        _ => {}
    }
    Ok(())
}

/// 加载 eng_lib 的 proto 定义进全局注册表（`packet_dsl::proto_registry`，
/// OnceLock 一次性；重复调用无操作）。dissect 的 `#[bind]` 分派依赖它——
/// 不加载则 proto 相关的包（如 QUIC）回落 raw，行为与未注册时一致。
pub fn ensure_proto_registry() {
    if !packet_dsl::proto_registry().is_empty() {
        return;
    }
    let libs = packet_dsl::default_libs();
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

/// 注入默认 DNS 解析器（ToSocketAddrs，v4 优先）；进程级，首个生效。
/// `dns("host")` 原语与地址字段的域名解析依赖它（packet-dsl 本身不发网络请求）。
pub fn ensure_dns_resolver() {
    packet_dsl::set_dns_resolver(|host| {
        use std::net::ToSocketAddrs;
        let mut addrs: Vec<std::net::SocketAddr> = (host, 0)
            .to_socket_addrs()
            .ok()
            .map(|it| it.collect())
            .unwrap_or_default();
        addrs.sort_by_key(|a| u8::from(a.is_ipv6())); // v4 优先
        addrs.into_iter().map(|a| a.ip()).collect()
    });
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

/// 渲染模块概览：module/exports/defs/funcs/packets + 实际生效的库目录。
fn render_module_header<W: WriteColor>(
    w: &mut W,
    module: &Module,
    total: usize,
    libs: &[PathBuf],
) -> io::Result<()> {
    print_magenta(w, "packet-dsl engine")?;
    writeln!(w)?;
    print_cyan(w, "module: ")?;
    print_bold_plain(w, &module.name)?;
    if let Some(path) = &module.path {
        print_dim(w, format!("  (file: {})", path.display()))?;
    }
    writeln!(w)?;
    if !module.imports.is_empty() {
        let imps: Vec<String> = module
            .imports
            .iter()
            .map(|i| match &i.names {
                Some(names) => format!(
                    "{} {{ {} }}",
                    i.module,
                    names
                        .iter()
                        .map(|(n, alias, _)| match alias {
                            Some(a) => format!("{n} as {a}"),
                            None => n.clone(),
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => i.module.clone(),
            })
            .collect();
        print_dim(w, format!("imports: {}   ", imps.join(", ")))?;
    }
    if !module.exports.is_empty() {
        let exps: Vec<&str> = module.exports.iter().map(|(n, _)| n.as_str()).collect();
        print_dim(w, format!("exports: {}   ", exps.join(", ")))?;
    }
    if module.default.is_some() {
        print_dim(w, "default: yes")?;
    }
    writeln!(w)?;
    if !module.defs.is_empty() {
        let defs: Vec<&str> = module.defs.iter().map(|d| d.name.as_str()).collect();
        print_dim(w, format!("defs: {}", defs.join(", ")))?;
        writeln!(w)?;
    }
    if !module.funcs.is_empty() {
        for f in &module.funcs {
            let params: Vec<String> = f
                .params
                .iter()
                .map(|p| match &p.default {
                    Some(d) => format!("{}={}", p.name, value_display(d)),
                    None => p.name.clone(),
                })
                .collect();
            print_dim(w, format!("func {}({})", f.name, params.join(", ")))?;
            writeln!(w)?;
        }
    }
    print_dim(w, format!("packets: {total}"))?;
    writeln!(w)?;
    if let Some(sn) = &module.sniffer {
        print_dim(w, "sniffer:")?;
        writeln!(w)?;
        for clause in &sn.clauses {
            let fields: Vec<String> = clause
                .fields
                .iter()
                .map(|(name, v)| match v {
                    packet_dsl::SnifferValue::Literal(l) => {
                        format!("{name}={}", value_display(l))
                    }
                    packet_dsl::SnifferValue::SentField(f) => format!("{name}={f}"),
                    packet_dsl::SnifferValue::Expr(e) => {
                        format!("{name}={}", value_display(e))
                    }
                })
                .collect();
            print_dim(
                w,
                format!("  - match {}({})", clause.layer, fields.join(", ")),
            )?;
            writeln!(w)?;
        }
    }
    print_dim(w, format!("libs: {}", libs_display(libs)))?;
    writeln!(w)?;
    writeln!(w)?;
    Ok(())
}

/// 折行宽度回退值（stdout 非 tty 或探测失败时）。
const WRAP_DEFAULT: usize = 100;

/// 终端列宽：stdout 为 tty 时查询实际宽度，失败/非 tty 回退 [`WRAP_DEFAULT`]。
fn term_width() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: TIOCGWINSZ 是纯查询 ioctl；非 tty 返回 -1 走回退。
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0
            && ws.ws_col > 0
        {
            return ws.ws_col as usize;
        }
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        struct Coord {
            x: i16,
            y: i16,
        }
        #[repr(C)]
        struct SmallRect {
            left: i16,
            top: i16,
            right: i16,
            bottom: i16,
        }
        #[repr(C)]
        struct ConsoleScreenBufferInfo {
            size: Coord,
            cursor_pos: Coord,
            attrs: u16,
            window: SmallRect,
            max_size: Coord,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetStdHandle(n: u32) -> *mut std::ffi::c_void;
            fn GetConsoleScreenBufferInfo(
                h: *mut std::ffi::c_void,
                info: *mut ConsoleScreenBufferInfo,
            ) -> i32;
        }
        // SAFETY: 控制台缓冲区信息为只读查询；非控制台/失败走回退。
        unsafe {
            let h = GetStdHandle(0xFFFF_FFF5); // STD_OUTPUT_HANDLE = (DWORD)-11
            let mut info: ConsoleScreenBufferInfo = std::mem::zeroed();
            if !h.is_null() && GetConsoleScreenBufferInfo(h, &mut info) != 0 {
                let w = i32::from(info.window.right) - i32::from(info.window.left) + 1;
                if w > 0 {
                    return w as usize;
                }
            }
        }
    }
    WRAP_DEFAULT
}

/// 按空格把文本折成不超过 `width` 的多行（贪心打包；词本身超宽时硬切，
/// 硬切点保证在 UTF-8 字符边界）。返回行不含尾随空格。
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for tok in text.split_whitespace() {
        // 超宽词：先收掉当前行，再按 width 硬切，余下部分作为下一行开头
        if tok.len() > width {
            if !cur.is_empty() {
                lines.push(std::mem::take(&mut cur));
            }
            let mut rest = tok;
            while rest.len() > width {
                let mut cut = width;
                while !rest.is_char_boundary(cut) {
                    cut -= 1;
                }
                if cut == 0 {
                    // width 装不下首个字符：按单个字符切
                    cut = rest.chars().next().expect("rest 非空").len_utf8();
                }
                lines.push(rest[..cut].to_string());
                rest = &rest[cut..];
            }
            cur.push_str(rest);
            continue;
        }
        if cur.is_empty() {
            cur.push_str(tok);
        } else if cur.len() + 1 + tok.len() <= width {
            cur.push(' ');
            cur.push_str(tok);
        } else {
            lines.push(std::mem::take(&mut cur));
            cur.push_str(tok);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// 打印一层：`  [i] name  desc`，desc 过长按空格折行（续行对齐 desc 起始列）。
fn render_layer_line<W: WriteColor>(
    w: &mut W,
    i: usize,
    name: &str,
    desc: &str,
    width: usize,
) -> io::Result<()> {
    let prefix = format!("  [{i}] {name}");
    print_dim(w, &prefix)?;
    if desc.is_empty() {
        writeln!(w)?;
        return Ok(());
    }
    let indent = prefix.chars().count() + 2;
    let avail = width.saturating_sub(indent).max(1);
    let pad = " ".repeat(indent);
    for (k, seg) in wrap_words(desc, avail).iter().enumerate() {
        if k == 0 {
            print_yellow(w, format!("  {seg}"))?;
        } else {
            print_yellow(w, format!("{pad}{seg}"))?;
        }
        writeln!(w)?;
    }
    Ok(())
}

/// 渲染层栈（字段 + auto/random 标注）。
pub fn render_layers<W: WriteColor>(w: &mut W, layers: &[Layer], header: &str) -> io::Result<()> {
    print_cyan(w, header)?;
    writeln!(w)?;
    let width = term_width();
    for (i, layer) in layers.iter().enumerate() {
        render_layer_line(w, i, layer_name(layer), &describe_layer(layer), width)?;
    }
    Ok(())
}

/// 层字段渲染（无 hexdump）：`--eng` 与 `--pkt` 复用。
///
/// 每层字段：字节直喂层从「该层序列化后的字节」解析（len/checksum/proto 真实值，
/// 对标 scapy `Ether(bytes)`）；语义层（无 raw）用 IR 字段 + auto 标注。
/// `ser` 由调用方传入（`--pkt` 传实际发送用的序列化器，fuzz 与发送一致）。
/// 返回完整包字节（供调用方决定是否 hexdump）。
pub fn render_packet_fields<W: WriteColor>(
    w: &mut W,
    pkt: &PacketSpec,
    header: &str,
    ser: &DefaultSerializer,
) -> io::Result<Vec<u8>> {
    let (bytes, parts) = ser.serialize_parts(pkt).map_err(io::Error::other)?;
    print_cyan(w, header)?;
    writeln!(w)?;
    let width = term_width();
    for (i, layer) in pkt.layers.iter().enumerate() {
        let desc = if layer_raw(layer).is_some() {
            // 该层在序列化结果中的区间（内→外）；外层包含内层，取自身头部分
            let seg = parts.get(i).map(|&(s, e)| &bytes[s..e]);
            match seg {
                Some(seg) => describe_raw_bytes(layer, seg),
                None => describe_layer(layer),
            }
        } else {
            describe_layer(layer)
        };
        render_layer_line(w, i, layer_name(layer), &desc, width)?;
    }
    print_dim(w, format!("  bytes: {} B", bytes.len()))?;
    writeln!(w)?;
    Ok(bytes)
}

/// 渲染一个包：层栈字段（从序列化后的真实字节解析）+ 字节 hexdump。
pub fn render_packet<W: WriteColor>(w: &mut W, pkt: &PacketSpec, header: &str) -> io::Result<()> {
    let ser = DefaultSerializer::new();
    let bytes = render_packet_fields(w, pkt, header, &ser)?;
    render_hexdump(w, &bytes)?;
    writeln!(w)?;
    Ok(())
}

/// 层序咨询性警告（只提示不阻断）：`--eng` 展示与 `--pkt` 发送共用。
/// 无警告时静默；每条一行橙色 `note:`，风格与 fake-ip 等运行期提示一致。
pub fn print_stack_warnings<W: WriteColor>(w: &mut W, pkt: &PacketSpec) -> io::Result<()> {
    for warn in packet_dsl::stack_warnings(pkt) {
        let msg = match warn.kind {
            packet_dsl::StackWarningKind::ReversedOrder => {
                t!(
                    "engine.note_stack_reversed",
                    inner = warn.inner,
                    outer = warn.outer
                )
            }
            packet_dsl::StackWarningKind::TransportInTransport => t!(
                "engine.note_stack_transport_in_transport",
                inner = warn.inner,
                outer = warn.outer
            ),
            packet_dsl::StackWarningKind::MissingNetwork => t!(
                "engine.note_stack_missing_network",
                inner = warn.inner,
                outer = warn.outer
            ),
            packet_dsl::StackWarningKind::PayloadOnly => {
                t!(
                    "engine.note_stack_payload_only",
                    inner = warn.inner,
                    outer = warn.outer
                )
            }
            packet_dsl::StackWarningKind::UninferrableProto => t!(
                "engine.note_stack_uninferrable_proto",
                inner = warn.inner,
                outer = warn.outer
            ),
            packet_dsl::StackWarningKind::WrongCarrier => t!(
                "engine.note_stack_wrong_carrier",
                inner = warn.inner,
                outer = warn.outer,
                carriers = warn.carriers.join("/")
            ),
        };
        writeln_orange(w, format!("  {msg}"))?;
    }
    Ok(())
}

/// 渲染反解报告（层栈 + 注记 + hexdump）。
pub fn render_dissected<W: WriteColor>(
    w: &mut W,
    report: &packet_dsl::dissect::DissectReport,
    header: &str,
    bytes: &[u8],
) -> io::Result<()> {
    if report.layers.is_empty() {
        print_red_plain(w, &format!("{header} — 未能识别任何层"))?;
        writeln!(w)?;
    } else {
        render_layers(w, &report.layers, header)?;
    }
    // proto（自表示协议）解析命中，如 QUIC（含 rest(子proto) 嵌套）
    for hit in &report.proto {
        render_proto_hit(w, hit, 2)?;
    }
    for n in &report.notes {
        print_yellow(w, format!("  note: {n}"))?;
        writeln!(w)?;
    }
    if !report.remaining.is_empty() {
        print_dim(w, format!("  remaining: {} B", report.remaining.len()))?;
        writeln!(w)?;
    }
    if !bytes.is_empty() {
        render_hexdump(w, bytes)?;
    }
    writeln!(w)?;
    Ok(())
}

/// 递归渲染一条 proto 命中（子命中缩进）。
fn render_proto_hit<W: WriteColor>(
    w: &mut W,
    hit: &packet_dsl::ProtoHit,
    indent: usize,
) -> io::Result<()> {
    let pad = " ".repeat(indent);
    print_cyan(w, format!("{pad}proto: {}", hit.name))?;
    writeln!(w)?;
    for (name, val) in &hit.fields {
        print_dim(w, format!("{pad}  {name} = {}", val.display()))?;
        writeln!(w)?;
    }
    for sub in &hit.subs {
        render_proto_hit(w, sub, indent + 2)?;
    }
    Ok(())
}

fn print_red_plain<W: WriteColor>(w: &mut W, text: &str) -> io::Result<()> {
    w.set_color(termcolor::ColorSpec::new().set_fg(Some(termcolor::Color::Red)))?;
    write!(w, "{text}")?;
    w.reset()
}

fn print_bold_plain<W: WriteColor>(w: &mut W, text: &str) -> io::Result<()> {
    w.set_color(termcolor::ColorSpec::new().set_bold(true))?;
    write!(w, "{text}")?;
    w.reset()
}

/// 16 字节一行的 hexdump：偏移 + hex + ASCII。
pub fn render_hexdump<W: WriteColor>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    for (off, chunk) in bytes.chunks(16).enumerate() {
        print_dim(w, format!("  {off:04x}  "))?;
        let mut hex = String::new();
        let mut ascii = String::new();
        for b in chunk {
            hex.push_str(&format!("{b:02x} "));
            ascii.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        for _ in chunk.len()..16 {
            hex.push_str("   ");
        }
        write!(w, "{hex} ")?;
        print_green(w, format!("|{ascii}|"))?;
        writeln!(w)?;
    }
    Ok(())
}

pub(crate) fn layer_name(l: &Layer) -> &'static str {
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

/// 层字段描述：用户填的值直接显示，未填字段标 `auto`。
/// 层头 bytes= 直喂的原始字节（无则 None）。
fn layer_raw(l: &Layer) -> Option<&[u8]> {
    match l {
        Layer::Ethernet(f) => f.raw.as_deref(),
        Layer::Arp(f) => f.raw.as_deref(),
        Layer::Ipv4(f) => f.raw.as_deref(),
        Layer::Ipv6(f) => f.raw.as_deref(),
        Layer::Icmp(f) => f.raw.as_deref(),
        Layer::Tcp(f) => f.raw.as_deref(),
        Layer::Udp(f) => f.raw.as_deref(),
        Layer::Http(f) => f.raw.as_deref(),
        Layer::Dns(f) => f.raw.as_deref(),
        Layer::Raw(_) => None,
    }
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 地址展示：域名解析来源时显示 `dns(host->ip)`，否则显示 IP。
fn addr_disp(host: &Option<String>, ip: String) -> String {
    match host {
        Some(h) => format!("dns({h}->{ip})"),
        None => ip,
    }
}

/// 从层头字节解析字段描述（scapy 风格：`<IP version=4 ihl=5 ...>`）。
/// 用于 bytes 直喂 / 反解层——字节是唯一真相，字段值从头部字节读。
fn describe_raw_bytes(l: &Layer, raw: &[u8]) -> String {
    match l {
        Layer::Ethernet(_) if raw.len() >= 14 => {
            let mac = |b: &[u8]| {
                b.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            };
            format!(
                "dst={} src={} ethertype=0x{:04x}",
                mac(&raw[0..6]),
                mac(&raw[6..12]),
                u16::from_be_bytes([raw[12], raw[13]])
            )
        }
        Layer::Arp(_) if raw.len() >= 28 => {
            let mac = |b: &[u8]| {
                b.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            };
            let ip = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string();
            format!(
                "op={} sha={} spa={} tha={} tpa={}",
                u16::from_be_bytes([raw[6], raw[7]]),
                mac(&raw[8..14]),
                ip(&raw[14..18]),
                mac(&raw[18..24]),
                ip(&raw[24..28])
            )
        }
        Layer::Ipv4(f) if raw.len() >= 20 => {
            let frag = u16::from_be_bytes([raw[6], raw[7]]);
            let proto = raw[9];
            let proto_name = match proto {
                1 => "ICMP".to_string(),
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                other => format!("{other}"),
            };
            let src = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]).to_string();
            let dst = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]).to_string();
            format!(
                "version={} ihl={} tos=0x{:02x} len={} id={} flags={} frag={} ttl={} proto={} chksum=0x{:04x} src={} dst={}",
                raw[0] >> 4,
                raw[0] & 0x0F,
                raw[1],
                u16::from_be_bytes([raw[2], raw[3]]),
                u16::from_be_bytes([raw[4], raw[5]]),
                if frag & 0x4000 != 0 { "DF" } else { "-" },
                frag & 0x1FFF,
                raw[8],
                proto_name,
                u16::from_be_bytes([raw[10], raw[11]]),
                addr_disp(&f.src_host, src),
                addr_disp(&f.dst_host, dst),
            )
        }
        Layer::Ipv6(f) if raw.len() >= 40 => {
            let nh = raw[6];
            let nh_name = match nh {
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                58 => "ICMPv6".to_string(),
                other => format!("{other}"),
            };
            let ip6 = |b: &[u8]| {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                Ipv6Addr::from(a).to_string()
            };
            let src = ip6(&raw[8..24]);
            let dst = ip6(&raw[24..40]);
            format!(
                "version={} traffic_class=0x{:02x} flow_label=0x{:05x} payload_len={} next_header={} hop_limit={} src={} dst={}",
                raw[0] >> 4,
                ((raw[0] & 0x0F) << 4) | (raw[1] >> 4),
                (((raw[1] & 0x0F) as u32) << 16) | ((raw[2] as u32) << 8) | raw[3] as u32,
                u16::from_be_bytes([raw[4], raw[5]]),
                nh_name,
                raw[7],
                addr_disp(&f.src_host, src),
                addr_disp(&f.dst_host, dst),
            )
        }
        Layer::Icmp(_) if raw.len() >= 8 => {
            // payload 长度从语义字段取（反解层载荷在 payload，非头部字节）
            let payload = match l {
                Layer::Icmp(f) => f
                    .payload
                    .as_ref()
                    .map(|p| format!(" payload={} B", p.len()))
                    .unwrap_or_default(),
                _ => String::new(),
            };
            format!(
                "type={} code={} chksum=0x{:04x} id={} seq={}{}",
                raw[0],
                raw[1],
                u16::from_be_bytes([raw[2], raw[3]]),
                u16::from_be_bytes([raw[4], raw[5]]),
                u16::from_be_bytes([raw[6], raw[7]]),
                payload
            )
        }
        Layer::Tcp(_) if raw.len() >= 20 => {
            let flags = raw[13];
            let mut fs = String::new();
            for (bit, name) in [
                (0x01, "FIN"),
                (0x02, "SYN"),
                (0x04, "RST"),
                (0x08, "PSH"),
                (0x10, "ACK"),
                (0x20, "URG"),
                (0x40, "ECE"),
                (0x80, "CWR"),
            ] {
                if flags & bit != 0 {
                    if !fs.is_empty() {
                        fs.push(',');
                    }
                    fs.push_str(name);
                }
            }
            format!(
                "sport={} dport={} seq={} ack={} dataofs={} flags={} window={} chksum=0x{:04x} urgptr={}",
                u16::from_be_bytes([raw[0], raw[1]]),
                u16::from_be_bytes([raw[2], raw[3]]),
                u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
                u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]),
                raw[12] >> 4,
                if fs.is_empty() { "-".to_string() } else { fs },
                u16::from_be_bytes([raw[14], raw[15]]),
                u16::from_be_bytes([raw[16], raw[17]]),
                u16::from_be_bytes([raw[18], raw[19]])
            )
        }
        Layer::Udp(_) if raw.len() >= 8 => format!(
            "sport={} dport={} len={} chksum=0x{:04x}",
            u16::from_be_bytes([raw[0], raw[1]]),
            u16::from_be_bytes([raw[2], raw[3]]),
            u16::from_be_bytes([raw[4], raw[5]]),
            u16::from_be_bytes([raw[6], raw[7]])
        ),
        // DNS 已 proto 化：反解/构造侧都回填 questions/answers（压缩指针追跳还原），
        // 直接显示字段；头部不足时回退 bytes=0x… 摘要
        Layer::Dns(f) => {
            let mut parts = vec![
                format!("id=0x{:04x}", f.id.unwrap_or(0)),
                format!("flags=0x{:04x}", f.flags.unwrap_or(0)),
            ];
            for q in &f.questions {
                parts.push(format!("q={}({})", q.name, dns_type_name(q.qtype)));
            }
            for a in &f.answers {
                parts.push(format!(
                    "a={}:{}",
                    a.name,
                    dns_rdata_disp(a.rtype, &a.rdata)
                ));
            }
            if parts.len() > 2 {
                parts.join(" ")
            } else {
                let n = raw.len().min(12);
                format!("bytes=0x{}…", hex_str(&raw[..n]))
            }
        }
        // HTTP 已 proto 化：反解/构造侧都回填 method/path/version/headers/body
        Layer::Http(f) => format!(
            "{} {} {} headers={} body={} B",
            f.method.clone().unwrap_or_else(|| "auto".to_string()),
            f.path.clone().unwrap_or_else(|| "auto".to_string()),
            f.version.clone().unwrap_or_else(|| "auto".to_string()),
            f.headers.len(),
            opt_bytes_len(&f.body)
        ),
        _ => {
            // 头部不足：回退 bytes=0x… 摘要
            let n = raw.len().min(12);
            format!("bytes=0x{}…", hex_str(&raw[..n]))
        }
    }
}

/// DNS 类型名（未知类型显示数字）。
fn dns_type_name(t: Option<u16>) -> String {
    match t {
        Some(1) => "A".into(),
        Some(2) => "NS".into(),
        Some(5) => "CNAME".into(),
        Some(6) => "SOA".into(),
        Some(12) => "PTR".into(),
        Some(15) => "MX".into(),
        Some(16) => "TXT".into(),
        Some(28) => "AAAA".into(),
        Some(33) => "SRV".into(),
        Some(41) => "OPT".into(),
        Some(255) => "ANY".into(),
        Some(n) => format!("{n}"),
        None => "?".into(),
    }
}

/// DNS rdata 展示：A/AAAA 解为 IP，其余十六进制。
fn dns_rdata_disp(t: Option<u16>, rdata: &[u8]) -> String {
    match (t, rdata.len()) {
        (Some(1), 4) => Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
        (Some(28), 16) => {
            let mut a = [0u8; 16];
            a.copy_from_slice(rdata);
            Ipv6Addr::from(a).to_string()
        }
        _ => format!("0x{}", hex_str(rdata)),
    }
}

fn describe_layer(l: &Layer) -> String {
    // bytes= 直喂 / 反解层：从头部字节解析字段（scapy 风格）
    if let Some(raw) = layer_raw(l) {
        return describe_raw_bytes(l, raw);
    }
    match l {
        Layer::Ethernet(f) => format!(
            "src={} dst={} ethertype={}",
            field_mac(f.src_mac, "auto"),
            field_mac(f.dst_mac, "auto"),
            opt_hex(f.ethertype, "auto")
        ),
        Layer::Arp(f) => format!(
            "op={} sha={} spa={} tha={} tpa={}",
            opt(&f.op, "auto"),
            opt_mac(f.sha, "auto"),
            opt_ip4(f.spa, "auto"),
            opt_mac(f.tha, "auto"),
            opt_ip4(f.tpa, "auto")
        ),
        Layer::Ipv4(f) => format!(
            "src={} dst={} ttl={} proto={} tos={} id={} flags={}",
            field_ip4(f.src, "auto"),
            field_ip4(f.dst, "auto"),
            field_u8(f.ttl, "auto"),
            opt(&f.proto, "auto"),
            opt(&f.tos, "auto"),
            opt(&f.id, "auto"),
            opt_flags4(f.flags)
        ),
        Layer::Ipv6(f) => format!(
            "src={} dst={} hop_limit={} next_header={}",
            field_ip6(f.src, "auto"),
            field_ip6(f.dst, "auto"),
            field_u8(f.hop_limit, "auto"),
            opt(&f.next_header, "auto")
        ),
        Layer::Icmp(f) => format!(
            "type={} code={} id={} seq={} payload={} B",
            opt(&f.icmp_type, "auto"),
            opt(&f.code, "auto"),
            opt(&f.id, "auto"),
            opt(&f.seq, "auto"),
            opt_bytes_len(&f.payload)
        ),
        Layer::Tcp(f) => format!(
            "sport={} dport={} seq={} ack={} flags={} window={} mss={}",
            opt(&f.src_port, "auto"),
            opt(&f.dst_port, "auto"),
            opt(&f.seq, "auto"),
            opt(&f.ack, "auto"),
            opt_tcp_flags(f.flags),
            opt(&f.window, "auto"),
            match f.options.first() {
                Some(packet_dsl::ir::TcpOption::Mss(m)) => m.to_string(),
                None => "-".to_string(),
            }
        ),
        Layer::Udp(f) => format!(
            "sport={} dport={}",
            opt(&f.src_port, "auto"),
            opt(&f.dst_port, "auto")
        ),
        Layer::Http(f) => format!(
            "{} {} {} headers={} body={} B",
            f.method.clone().unwrap_or_else(|| "auto".to_string()),
            f.path.clone().unwrap_or_else(|| "auto".to_string()),
            f.version.clone().unwrap_or_else(|| "auto".to_string()),
            f.headers.len(),
            opt_bytes_len(&f.body)
        ),
        Layer::Dns(f) => {
            let mut parts = vec![
                format!("id={}", opt(&f.id, "auto")),
                format!("flags={}", opt(&f.flags, "auto")),
            ];
            for q in &f.questions {
                parts.push(format!("q={}({})", q.name, dns_type_name(q.qtype)));
            }
            parts.push(format!("answers={}", f.answers.len()));
            parts.join(" ")
        }
        Layer::Raw(r) => format!("{} bytes", r.bytes.len()),
    }
}

fn field_show<T: std::fmt::Display>(f: &packet_dsl::ir::Field<T>, auto: &str) -> String {
    use packet_dsl::ir::Field;
    match f {
        Field::Auto => auto.to_string(),
        Field::Random => "random".to_string(),
        Field::Value(v) => v.to_string(),
    }
}

fn field_mac(f: packet_dsl::ir::Field<packet_dsl::ir::MacAddr>, auto: &str) -> String {
    field_show(&f, auto)
}

fn field_ip4(f: packet_dsl::ir::Field<std::net::Ipv4Addr>, auto: &str) -> String {
    field_show(&f, auto)
}

fn field_ip6(f: packet_dsl::ir::Field<std::net::Ipv6Addr>, auto: &str) -> String {
    field_show(&f, auto)
}

fn field_u8(f: packet_dsl::ir::Field<u8>, auto: &str) -> String {
    field_show(&f, auto)
}

fn opt<T: std::fmt::Display>(o: &Option<T>, auto: &str) -> String {
    o.as_ref()
        .map(|v| v.to_string())
        .unwrap_or_else(|| auto.to_string())
}

fn opt_mac(o: Option<MacAddr>, auto: &str) -> String {
    o.map(|m| m.to_string()).unwrap_or_else(|| auto.to_string())
}

fn opt_ip4(o: Option<std::net::Ipv4Addr>, auto: &str) -> String {
    o.map(|v| v.to_string()).unwrap_or_else(|| auto.to_string())
}

fn opt_hex(o: Option<u16>, auto: &str) -> String {
    o.map(|v| format!("0x{v:04x}"))
        .unwrap_or_else(|| auto.to_string())
}

fn opt_bytes_len(o: &Option<Vec<u8>>) -> String {
    o.as_ref()
        .map(|v| v.len().to_string())
        .unwrap_or_else(|| "auto".to_string())
}

fn opt_flags4(f: Option<packet_dsl::ir::Ipv4Flags>) -> String {
    match f {
        Some(fl) => {
            let mut parts: Vec<String> = Vec::new();
            if fl.df {
                parts.push("df".to_string());
            }
            if fl.mf {
                parts.push("mf".to_string());
            }
            if fl.frag_offset != 0 {
                parts.push(format!("off={}", fl.frag_offset));
            }
            if parts.is_empty() {
                "0".to_string()
            } else {
                parts.join(",")
            }
        }
        None => "auto".to_string(),
    }
}

fn opt_tcp_flags(f: Option<packet_dsl::ir::TcpFlags>) -> String {
    f.map(|fl| fl.to_string())
        .unwrap_or_else(|| "auto".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dsl::ast::Value;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("prping-eng-params-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 词法收集 params：def（Call / Pipeline）、层函数、值函数 value_body、
    /// 顶层匿名流水线、sniffer 匹配值表达式——按出现顺序全部收集。
    #[test]
    fn collect_pkt_params_lexical() {
        let dir = temp_dir("lexical");
        let pkt = dir.join("probe.pkt");
        std::fs::write(
            &pkt,
            r#"p = raw(bytes="probe")
full = use(p) |> icmp(type=8, id=params("id", 0x1234), seq=params("seq", 1)) |> ipv4(dst=params("dst", "127.0.0.1"))
hdr = tcp(dport=params("dport2", 80))
func myid() -> bytes { be16(params("myid", 0x99)) }
use(p) |> tcp(dport=params("dport", 443))
sniffer:
  - match icmp(type=0, id=params("myid"), seq=[0x00, 0x01])
export:
- full
"#,
        )
        .unwrap();
        let got = collect_pkt_params(&pkt).unwrap();
        assert_eq!(
            got,
            vec![
                ("id".to_string(), Some(Value::Hex(0x1234))),
                ("seq".to_string(), Some(Value::Int(1))),
                ("dst".to_string(), Some(Value::Str("127.0.0.1".into()))),
                ("dport2".to_string(), Some(Value::Int(80))),
                ("myid".to_string(), Some(Value::Hex(0x99))),
                ("dport".to_string(), Some(Value::Int(443))),
                // sniffer 值表达式里的 params（无默认）
                ("myid".to_string(), None),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 文件缺失 / 语法错误 → 报错（带上下文前缀）。
    #[test]
    fn collect_pkt_params_errors() {
        let err = collect_pkt_params(Path::new("/nonexistent/no-such-file.pkt")).unwrap_err();
        assert!(err.to_string().contains("读取失败"), "{err}");

        let dir = temp_dir("syntax");
        let bad = dir.join("bad.pkt");
        std::fs::write(&bad, "this is not a valid pkt !!").unwrap();
        let err = collect_pkt_params(&bad).unwrap_err();
        assert!(err.to_string().contains("解析失败"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 按空格折行：短文本一行、贪心打包、超宽词硬切、空文本。
    #[test]
    fn wrap_words_break_at_spaces() {
        assert_eq!(wrap_words("", 10), Vec::<String>::new());
        assert_eq!(wrap_words("a b c", 10), vec!["a b c"]);
        // 贪心打包到宽度
        assert_eq!(wrap_words("aa bb cc dd", 5), vec!["aa bb", "cc dd"]);
        // 超宽词硬切
        assert_eq!(wrap_words("abcdefgh", 4), vec!["abcd", "efgh"]);
        // 混合：词超宽时先硬切，剩余部分续到下一行
        assert_eq!(
            wrap_words("aa xxxxxx bb", 4),
            vec!["aa", "xxxx", "xx", "bb"]
        );
        // 宽度 1：逐字符
        assert_eq!(wrap_words("ab cd", 1), vec!["a", "b", "c", "d"]);
    }

    /// 层行折行后逐行长度不超宽（按字符计，UTF-8 安全）。
    #[test]
    fn wrap_words_respects_width() {
        for width in [1usize, 8, 20, 40] {
            let text = "version=4 ihl=5 tos=0x00 len=35 id=7982 flags=- frag=0 \
                        ttl=64 proto=ICMP chksum=0x5daa src=127.0.0.1 dst=127.0.0.1";
            for line in wrap_words(text, width) {
                assert!(line.chars().count() <= width, "{line:?} 超宽 {width}");
            }
        }
        // 超长连续词（如 dns(域名->ip)）不 panic、不丢字
        let long = "dst=dns(very.long.hostname.example.com->198.18.0.5) src=127.0.0.1";
        let joined = wrap_words(long, 10).join("");
        assert_eq!(joined.replace(' ', ""), long.replace(' ', ""));
    }

    /// 聚合：同名同默认值去重、同名不同默认值全保留、无默认参数、步骤列表合并。
    #[test]
    fn aggregate_pkt_params_dedup() {
        let per_step = vec![
            vec![
                ("dst".to_string(), Some(Value::Str("127.0.0.1".into()))),
                ("id".to_string(), Some(Value::Hex(0x1234))),
                ("nodelay".to_string(), None),
            ],
            vec![
                ("dst".to_string(), Some(Value::Str("127.0.0.1".into()))),
                ("id".to_string(), Some(Value::Hex(0x5678))),
            ],
            vec![("dst".to_string(), None)],
        ];
        let agg = aggregate_pkt_params(&per_step);
        assert_eq!(agg.len(), 3, "按名字排序去重：dst / id / nodelay");
        assert_eq!(agg[0].0, "dst");
        assert_eq!(
            agg[0].1,
            vec![Value::Str("127.0.0.1".into())],
            "同默认值去重"
        );
        assert_eq!(agg[0].2, vec![1, 2, 3], "含无默认的步骤 3");
        assert_eq!(agg[1].0, "id");
        assert_eq!(agg[1].1, vec![Value::Hex(0x1234), Value::Hex(0x5678)]);
        assert_eq!(agg[1].2, vec![1, 2]);
        assert_eq!(agg[2].0, "nodelay");
        assert!(agg[2].1.is_empty(), "无默认");
        assert_eq!(agg[2].2, vec![1]);
    }
}
