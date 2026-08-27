//! 配方执行（`.pktl`）：按顺序执行每个步骤（一个 .pkt 文件），维护 global 存储。
//!
//! 忠实拆分自原 `engine/pkg.rs` 的配方段：`send_recipe` 步骤循环、`extract`
//! 回包字段提取、`as:` 值转换、`reply(...)` 取值。

use std::io::Write;
use std::path::Path;

use packet_dsl::ir::Layer;
use packet_dsl::{DefaultSerializer, Serializer};
use rust_i18n::t;
use termcolor::{ColorChoice, StandardStream};

use super::send::{SendCtx, fmt_target, send_module};
use super::sniffer::{FVal, field_bytes, layer_kind, sniffer_extract};
use super::{PkgOptions, SendMode};
use crate::engine::recipe::{ExtractAs, OnError};
use crate::output::{indent, print_cyan, print_dim, print_green, print_magenta};

pub fn send_recipe(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    crate::engine::eng::ensure_dns_resolver();
    crate::engine::eng::ensure_proto_registry();
    let recipe = crate::engine::recipe::parse(file)?;
    // 全局存储：配方 init → CLI -G（--global）覆盖（CLI 优先，与 params 语义一致）
    let mut globals: packet_dsl::Globals = packet_dsl::Globals::new();
    for g in &recipe.globals {
        if let Some(init) = &g.init {
            globals.insert(g.name.clone(), init.clone());
        }
    }
    for (k, v) in &opts.globals {
        globals.insert(k.clone(), v.clone());
    }

    // 步骤 .pkt 用到的 params（词法收集；失败静默——exec 循环会报真正的解析错误）
    let per_step: Vec<Vec<(String, Option<packet_dsl::ast::Value>)>> = recipe
        .steps
        .iter()
        .map(|s| crate::engine::eng::collect_pkt_params(&s.pkg).unwrap_or_default())
        .collect();
    let mut param_names: Vec<String> = Vec::new();
    for used in &per_step {
        for (n, _) in used {
            if !param_names.contains(n) {
                param_names.push(n.clone());
            }
        }
    }

    let mut w = StandardStream::stdout(ColorChoice::Auto);
    let target_str = match opts.target {
        Some(t) => format!(" to {}", fmt_target(Some(t))),
        None => " — target derived from each packet".to_string(),
    };
    if opts.summary {
        // 摘要模式：不发头部，执行完只打一行结果
    } else {
        print_magenta(&mut w, "packet-dsl recipe")?;
        writeln!(&mut w)?;
        print_cyan(
            &mut w,
            format!(
                "{} — {} step(s), {} global(s), {} param(s){}",
                file.display(),
                recipe.steps.len(),
                recipe.globals.len(),
                param_names.len(),
                target_str,
            ),
        )?;
        writeln!(&mut w)?;
        if !param_names.is_empty() {
            print_dim(&mut w, format!("params: {}", param_names.join(", ")))?;
            writeln!(&mut w)?;
        }
        if let Some(secs) = opts.wait {
            crate::output::print_yellow(&mut w, t!("engine.note_wait_recipe", secs = secs))?;
            writeln!(&mut w)?;
        }
        writeln!(&mut w)?;
        let libs = crate::engine::eng::effective_libs(&opts.libs);
        print_dim(
            &mut w,
            format!("libs: {}", crate::engine::eng::libs_display(&libs)),
        )?;
        writeln!(&mut w)?;
    }

    // --out：配方模式收集全部步骤的包，结束后写一个 pcap（链路类型取首个包）
    let mut out_all: Vec<Vec<u8>> = Vec::new();
    let mut out_lt: Option<crate::engine::pcap::LinkType> = None;
    let mut total_failed = 0usize;
    let mut packets_sent = 0usize;

    for (i, step) in recipe.steps.iter().enumerate() {
        if !opts.summary {
            writeln!(&mut w)?;
        }
        // 步骤间延迟（delay: 秒；pcap 转码配方携带捕获间隔）：非首步在发送前等待。
        // 分片 sleep 检查 Ctrl+C（首次中断提前结束配方，与测量模式一致的优雅退出）。
        if i > 0
            && let Some(secs) = step.delay
            && secs > 0.0
        {
            if !opts.summary {
                print_dim(
                    &mut w,
                    format!(
                        "{}delay {secs}s before step {}/{} ...",
                        indent(1),
                        i + 1,
                        recipe.steps.len()
                    ),
                )?;
                writeln!(&mut w)?;
            }
            if !sleep_interruptible(secs) {
                crate::output::print_yellow(
                    &mut w,
                    format!("{}interrupted during delay — stopping recipe", indent(1)),
                )?;
                writeln!(&mut w)?;
                return Ok(());
            }
        }
        // 步骤失败处理：stop（默认）→ 中止返回 Err；continue → 记录继续
        let fail_step = |w: &mut StandardStream, msg: &str| -> anyhow::Result<()> {
            let _ = crate::output::writeln_red(w, format!("{}✗ {msg}", indent(1)));
            if step.on_error == OnError::Stop {
                anyhow::bail!(
                    "配方 {}：第 {}/{} 步失败（on_error: stop）",
                    file.display(),
                    i + 1,
                    recipe.steps.len()
                );
            }
            Ok(())
        };

        // 步骤参数：CLI --params + 步骤 params（同名覆盖）
        let mut step_params: packet_dsl::Params = opts.params.iter().cloned().collect();
        for (k, v) in &step.params {
            step_params.insert(k.clone(), v.clone());
        }
        // 步骤级选项：wait 覆盖 CLI；raw 覆盖发送方式（true/网卡 = 强制 raw，
        // false = 强制 payload——覆盖 CLI --raw）
        let step_opts = PkgOptions {
            wait: step.wait.or(opts.wait),
            mode: step_send_mode(&step.raw, &opts.mode),
            ..opts.clone()
        };
        if !step.extract.is_empty() && step_opts.wait.is_none() {
            fail_step(
                &mut w,
                "步骤声明了 extract 但没有 wait（extract 需要回包：本步 `wait:` 或 `--wait`）",
            )?;
            total_failed += 1;
            continue;
        }
        // 解析 + 求值（注入当前 global 快照）
        let module = match packet_dsl::parse_file_with_libs(&step.pkg, &opts.libs) {
            Ok(m) => m,
            Err(d) => {
                fail_step(&mut w, &format!("解析 {} 失败：{d}", step.pkg.display()))?;
                total_failed += 1;
                continue;
            }
        };
        let sources =
            match packet_dsl::resolve_sources_with_globals(&module, &step_params, &globals) {
                Ok(s) => s,
                Err(d) => {
                    fail_step(&mut w, &format!("求值 {} 失败：{d}", step.pkg.display()))?;
                    total_failed += 1;
                    continue;
                }
            };
        if sources.iter().map(|(_, p)| p.len()).sum::<usize>() == 0 {
            fail_step(
                &mut w,
                &format!(
                    "{} 没有可发送的包（无默认导出/命名导出）",
                    step.pkg.display()
                ),
            )?;
            total_failed += 1;
            continue;
        }
        // --out 合并收集
        if opts.out.is_some() {
            let ser = if opts.fuzz {
                DefaultSerializer::new_fuzz()
            } else {
                DefaultSerializer::new()
            };
            for (_, pkts) in &sources {
                for pkt in pkts {
                    if let Ok(b) = ser.serialize(pkt) {
                        if out_lt.is_none() {
                            out_lt = Some(crate::engine::pcap::linktype_of(&pkt.layers));
                        }
                        out_all.push(b);
                    }
                }
            }
        }
        // 发送 + 收集回包字节（extract 用）
        let mut replies: Vec<Vec<u8>> = Vec::new();
        let header = format!(
            "step {}/{}  {}",
            i + 1,
            recipe.steps.len(),
            step.pkg.display()
        );
        let stats = match send_module(
            &mut w,
            Some(header),
            SendCtx {
                module: &module,
                sources: &sources,
                params: &step_params,
                globals: &globals,
                on_reply: Some(&mut |b: &[u8]| replies.push(b.to_vec())),
            },
            &step_opts,
        ) {
            Ok(s) => s,
            Err(e) => {
                fail_step(&mut w, &format!("{} 发送中断：{e}", step.pkg.display()))?;
                total_failed += 1;
                continue;
            }
        };
        let mut step_failed = stats.failed;
        packets_sent += stats.total - stats.failed - stats.skipped;
        if stats.skipped == stats.total && stats.total > 0 {
            step_failed += 1;
            fail_step(
                &mut w,
                &format!(
                    "步骤 {} 的包均为纯裸层（无传输/无 raw 外层），无法发送",
                    step.pkg.display()
                ),
            )?;
        }
        // extract：回包 → global（多个回包依次应用，后写覆盖先写）
        if !step.extract.is_empty() {
            if replies.is_empty() {
                step_failed += 1;
                fail_step(
                    &mut w,
                    &format!(
                        "步骤没有收到回包，无法提取 {} 条 extract（sniffer/回显未匹配）",
                        step.extract.len()
                    ),
                )?;
            } else {
                for rb in &replies {
                    match apply_extract(
                        Some(&module),
                        &mut globals,
                        &step.extract,
                        &step_params,
                        rb,
                    ) {
                        Ok(pairs) => {
                            // 摘要模式：提取仍写入 global，但不逐条打印
                            if !opts.summary {
                                for (n, v) in pairs {
                                    print_green(
                                        &mut w,
                                        format!(
                                            "  ✓ global.{n} = {}",
                                            crate::engine::eng::value_display(&v)
                                        ),
                                    )?;
                                    writeln!(&mut w)?;
                                }
                            }
                        }
                        Err(e) => {
                            step_failed += 1;
                            let _ = crate::output::writeln_red(&mut w, format!("  ✗ {e}"));
                            break;
                        }
                    }
                }
                if step_failed > stats.failed {
                    fail_step(&mut w, "extract 失败（见上）")?;
                }
            }
        }
        total_failed += step_failed;
        if step_failed > 0 {
            let _ = crate::output::writeln_red(
                &mut w,
                format!(
                    "  ✗ 步骤 {}/{} 失败（{step_failed} 个问题）",
                    i + 1,
                    recipe.steps.len()
                ),
            );
            if step.on_error == OnError::Stop {
                return Err(anyhow::anyhow!(
                    "配方 {}：第 {}/{} 步失败（on_error: stop）",
                    file.display(),
                    i + 1,
                    recipe.steps.len()
                ));
            }
        }
    }

    if let Some(out) = &opts.out {
        crate::engine::pcap::write_pcap(
            out,
            out_lt.unwrap_or(crate::engine::pcap::LinkType::Raw),
            &out_all,
        )?;
    }
    if opts.summary {
        // 摘要模式：单行结果（错误已在循环里红字打印）
        let target_phrase = match opts.target {
            Some(t) => format!(" to {}", fmt_target(Some(t))),
            None => String::new(),
        };
        print_cyan(
            &mut w,
            format!(
                "packet-dsl recipe: {file} — {steps} step(s){target}, {packets_sent} packet(s) sent, {total_failed} failed",
                file = file.display(),
                steps = recipe.steps.len(),
                target = target_phrase,
            ),
        )?;
        writeln!(&mut w)?;
    }
    if total_failed > 0 {
        anyhow::bail!("配方 {}：{} 个步骤有失败", file.display(), total_failed);
    }
    Ok(())
}

/// 步骤级 `raw:` 覆盖 → 本步发送方式（CLI 模式为基准）。
///
/// - `raw: true`：强制 raw 发送；未指定网卡时继承 CLI `--iface`（CLI 也未给则平台默认）。
/// - `raw: 网卡名`：强制 raw 发送并指定网卡（覆盖 CLI `--iface`）。
/// - `raw: false`：强制载荷发送（覆盖 CLI `--raw`）。
/// - 未声明：继承 CLI 模式。
pub fn step_send_mode(raw: &Option<crate::engine::recipe::StepRaw>, cli: &SendMode) -> SendMode {
    match raw {
        Some(crate::engine::recipe::StepRaw::On { iface }) => {
            let iface = iface.clone().or_else(|| match cli {
                SendMode::Raw { iface } => iface.clone(),
                SendMode::Payload => None,
            });
            SendMode::Raw { iface }
        }
        Some(crate::engine::recipe::StepRaw::Off) => SendMode::Payload,
        None => cli.clone(),
    }
}

/// 分片等待 `secs` 秒（100ms 步进），期间可响应 Ctrl+C（`interrupted()`）。
/// 返回 false = 已被中断提前结束。
fn sleep_interruptible(secs: f64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(secs);
    loop {
        if crate::util::interrupted() {
            return false;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return true;
        }
        let remaining = deadline - now;
        let step = remaining.min(std::time::Duration::from_millis(100));
        std::thread::sleep(step);
    }
}

/// 从回包字节按 `extract:` 子句提取字段写入 global（复用 sniffer 的层/字段机制）。
/// 返回实际写入的 (名字, 值) 列表供调用方打印。任一子句失败 → 整体报错（已写入的
/// 前序值保留——后写覆盖先写的语义由调用方逐回包调用保证）。
fn apply_extract(
    module: Option<&packet_dsl::Module>,
    globals: &mut packet_dsl::Globals,
    extracts: &[crate::engine::recipe::Extract],
    params: &packet_dsl::Params,
    reply_bytes: &[u8],
) -> anyhow::Result<Vec<(String, packet_dsl::ast::Value)>> {
    use packet_dsl::ast::Value;
    let report = packet_dsl::dissect(reply_bytes);
    let mut out = Vec::new();
    for e in extracts {
        let val = match &e.from {
            crate::engine::recipe::FromSpec::Field { layer, field } => {
                let Some(rl) = report.layers.iter().find(|l| layer_kind(l) == *layer) else {
                    return Err(anyhow::anyhow!(
                        "配方 {} 行：回包没有 {} 层（无法提取 {}）",
                        e.line,
                        layer,
                        e.name
                    ));
                };
                match e.as_ {
                    ExtractAs::Bytes => {
                        let bytes = field_bytes(rl, field).ok_or_else(|| {
                            anyhow::anyhow!("配方 {} 行：层 {} 没有字段 {}", e.line, layer, field)
                        })?;
                        Value::List(bytes.into_iter().map(|b| Value::Int(b as i64)).collect())
                    }
                    ExtractAs::Str => {
                        let s = sniffer_extract(rl, field).ok_or_else(|| {
                            anyhow::anyhow!("配方 {} 行：层 {} 没有字段 {}", e.line, layer, field)
                        })?;
                        Value::Str(s.display())
                    }
                    ExtractAs::Int | ExtractAs::Hex => {
                        let f = sniffer_extract(rl, field).ok_or_else(|| {
                            anyhow::anyhow!("配方 {} 行：层 {} 没有字段 {}", e.line, layer, field)
                        })?;
                        match f {
                            FVal::U(u) => {
                                if e.as_ == ExtractAs::Int {
                                    Value::Int(u as i64)
                                } else {
                                    Value::Hex(u)
                                }
                            }
                            other => {
                                return Err(anyhow::anyhow!(
                                    "配方 {} 行：字段 {}.{} 不是数值（{}），请用 as: str / bytes",
                                    e.line,
                                    layer,
                                    field,
                                    other.display()
                                ));
                            }
                        }
                    }
                }
            }
            crate::engine::recipe::FromSpec::Expr(expr) => {
                // 值表达式：求值（可调用户值函数/params/global/reply 叶子），
                // 结果按 `as:` 转换（缺省 = 自然类型值）
                let reply_access =
                    |layer: &str, field: &str| reply_field_value(&report, layer, field);
                let v =
                    packet_dsl::eval_extract_value(module, params, globals, &reply_access, expr)
                        .map_err(|d| {
                            anyhow::anyhow!("配方 {} 行：`from` 表达式求值失败：{d}", e.line)
                        })?;
                if e.as_given {
                    convert_expr_value(e.as_, v, e.line, &e.name)?
                } else {
                    v
                }
            }
        };
        globals.insert(e.name.clone(), val.clone());
        out.push((e.name.clone(), val));
    }
    Ok(out)
}

/// `from:` 表达式形态的 `as:` 转换（缺省 = 自然值，见调用方）。
fn convert_expr_value(
    as_: ExtractAs,
    v: packet_dsl::ast::Value,
    line: usize,
    name: &str,
) -> anyhow::Result<packet_dsl::ast::Value> {
    use packet_dsl::ast::Value;
    fn err_msg(line: usize, name: &str, msg: &str, v: &Value) -> anyhow::Error {
        anyhow::anyhow!(
            "配方 {line} 行：提取 `{name}` 的 as 转换失败：{msg}（表达式结果是 {}）",
            crate::engine::eng::value_display(v)
        )
    }
    match as_ {
        ExtractAs::Int => match v {
            Value::Int(_) => Ok(v),
            Value::Hex(h) => Ok(Value::Int(h as i64)),
            other => Err(err_msg(line, name, "需要整数（Int/Hex）", &other)),
        },
        ExtractAs::Hex => match v {
            Value::Hex(_) => Ok(v),
            Value::Int(i) if i >= 0 => Ok(Value::Hex(i as u64)),
            other => Err(err_msg(line, name, "需要非负整数（Int/Hex）", &other)),
        },
        ExtractAs::Str => match v {
            Value::Str(_) => Ok(v),
            Value::Int(i) => Ok(Value::Str(i.to_string())),
            Value::Hex(h) => Ok(Value::Str(h.to_string())),
            other => Err(err_msg(line, name, "需要字符串或整数", &other)),
        },
        ExtractAs::Bytes => match v {
            Value::List(_) => Ok(v),
            Value::Str(s) => Ok(Value::List(
                s.bytes().map(|b| Value::Int(b as i64)).collect(),
            )),
            other => Err(err_msg(
                line,
                name,
                "数值转字节请在表达式里用 be16()/u8() 等原语包一层",
                &other,
            )),
        },
    }
}

/// `reply("层","字段")` 取值：sniffer 字段集 + 扩展字节字段（icmp.payload /
/// http.body / raw.bytes；raw.bytes 无 Raw 层时兜底 remaining——裸应用层回显）。
fn reply_field_value(
    report: &packet_dsl::DissectReport,
    layer: &str,
    field: &str,
) -> Option<packet_dsl::ast::Value> {
    use packet_dsl::ast::Value;
    // 1) 语义 IR 层（eth/arp/ipv4/.../dns/http）优先
    if let Some(rl) = report.layers.iter().find(|l| layer_kind(l) == layer) {
        if let Some(f) = sniffer_extract(rl, field) {
            return Some(match f {
                FVal::U(u) => Value::Int(u as i64),
                other => Value::Str(other.display()),
            });
        }
        match (layer, field) {
            ("icmp", "payload") => match rl {
                Layer::Icmp(f) => f.payload.clone().map(bytes_value),
                _ => None,
            },
            ("http", "body") => match rl {
                Layer::Http(f) => f.body.clone().map(bytes_value),
                _ => None,
            },
            ("raw", "bytes") => match rl {
                Layer::Raw(d) => Some(bytes_value(d.bytes.clone())),
                _ => None,
            },
            _ => None,
        }
    } else {
        // 2) proto 注册表命中（协议走 pkt 声明反解，如 dns）——字段表取值
        let v = report.proto.iter().find(|h| h.name == layer).and_then(|h| {
            h.fields
                .iter()
                .find(|(n, _)| n == field)
                .map(|(_, v)| match v {
                    packet_dsl::ProtoVal::Int(i) => Value::Int(*i),
                    packet_dsl::ProtoVal::Str(s) => Value::Str(s.clone()),
                    packet_dsl::ProtoVal::Bytes(b) => bytes_value(b.clone()),
                })
        });
        if v.is_some() {
            return v;
        }
        // 3) raw 兜底
        if layer == "raw" && field == "bytes" && !report.remaining.is_empty() {
            return Some(bytes_value(report.remaining.clone()));
        }
        None
    }
}

/// 字节列表 → Value（每个字节为 Int 值；与 packet-dsl 的 bytes_value 等价）。
pub(crate) fn bytes_value(bytes: Vec<u8>) -> packet_dsl::ast::Value {
    use packet_dsl::ast::Value;
    Value::List(bytes.into_iter().map(|b| Value::Int(b as i64)).collect())
}
