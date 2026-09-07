//! 配方执行（`.pktl`）：按顺序执行每个步骤（一个 .pkt 文件），维护 global 存储。
//!
//! 忠实拆分自原 `engine/pkg.rs` 的配方段：`send_recipe` 步骤循环、`extract`
//! 回包字段提取、`as:` 值转换、`reply(...)` 取值。

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use packet_dsl::DefaultSerializer;
use packet_dsl::ir::Layer;
use rust_i18n::t;
use serde_json::{Map, Value, json};
use termcolor::{ColorChoice, StandardStream};

use super::send::{SendCtx, fmt_target, send_module};
use super::sniffer::{FVal, field_bytes, layer_kind, sniffer_extract};
use super::{PkgOptions, SendMode};
use crate::engine::eng::{aggregate_pkt_params, collect_pkt_params, value_display};
use crate::engine::recipe::{ExtractAs, OnError, StepRaw};
use crate::output::{indent, print_cyan, print_dim, print_green, print_magenta, print_orange};

pub fn send_recipe(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    if opts.wait == crate::engine::pkg::WaitMode::Continuous {
        anyhow::bail!("{}", t!("engine.recipe_no_cli_wait"));
    }
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

    // 步骤 .pkt 用到的 params（词法收集；失败静默——exec 循环会报真正的解析错误）。
    // 遍历 items 递归收集所有 packet：顶层步骤、serve 规则监听源、handler/嵌套
    // on_recv 步骤（与下方脱糖产出的步骤序列一一对应）
    let per_step: Vec<Vec<(String, Option<packet_dsl::ast::Value>)>> =
        collect_recipe_pkt_params(&recipe);
    let params_agg = aggregate_pkt_params(&per_step);

    // ── serve 阶段脱糖（执行器内部；解析器不产生 LoopCtx）──
    // items（Step | Serve）→ 扁平步骤序列，复用下方 loop 块机制驱动轮次：
    // - Step 条目原样保留（loop_ctx = None）；
    // - Serve 条目展开：每条规则先产出监听步骤（wait = -1.0 负数哨兵 = 监听，
    //   raw/params/extract 取规则、on_error Stop），再按序产出其 handler 条目
    //   （Step 克隆；OnRecv 递归展开——嵌套 packet 同样产出监听步骤）。
    //   阶段全部产出步骤附加同一 LoopCtx（id = 阶段序号、count = serve.max、
    //   until = serve.until、delay = serve.delay），first/last 标记产出序列首/末。
    let mut steps: Vec<crate::engine::recipe::Step> = Vec::new();
    let mut serve_stage = 0usize;
    // 阶段 id → 执行期信息（规则表 + on_mismatch 有无）：分派监听按需取用
    let mut stage_info: std::collections::HashMap<usize, StageInfo> =
        std::collections::HashMap::new();
    for item in &recipe.items {
        match item {
            crate::engine::recipe::RecipeItem::Step(s) => steps.push(s.clone()),
            crate::engine::recipe::RecipeItem::Serve(serve) => {
                let base = crate::engine::recipe::LoopCtx {
                    id: serve_stage,
                    count: serve.max,
                    until: serve.until.clone(),
                    delay: serve.delay,
                    first: false,
                    last: false,
                    rule: None,
                    line: serve.line,
                };
                let mut block: Vec<crate::engine::recipe::Step> = Vec::new();
                let n_rules = serve.rules.len();
                let is_dispatch = n_rules > 1 || serve.on_mismatch.is_some();
                stage_info.insert(
                    serve_stage,
                    StageInfo {
                        rules: serve.rules.clone(),
                        mismatch: serve.on_mismatch.is_some(),
                    },
                );
                for (k, rule) in serve.rules.iter().enumerate() {
                    if is_dispatch {
                        // 分派阶段：仅规则 0 产出监听步骤（= 分派监听，rule 段
                        // 标记 None 不受守卫）；规则 k>0 只产出 handler 段
                        expand_serve_rule(rule, &base, Some(k), None, k == 0, &mut block);
                    } else {
                        expand_serve_rule(rule, &base, None, None, true, &mut block);
                    }
                }
                if let Some(items) = &serve.on_mismatch {
                    // on_mismatch 段：段标记 = 规则数（守卫键），执行完回监听
                    for it in items {
                        expand_segment_item(it, &base, Some(n_rules), &mut block);
                    }
                }
                // 阶段边界：产出序列首/末步（首步 = 闸门所在、末步 = 回跳点）
                if let Some(first) = block.first_mut()
                    && let Some(ctx) = first.loop_ctx.as_mut()
                {
                    ctx.first = true;
                }
                if let Some(last) = block.last_mut()
                    && let Some(ctx) = last.loop_ctx.as_mut()
                {
                    ctx.last = true;
                }
                steps.extend(block);
                serve_stage += 1;
            }
        }
    }
    let step_total = steps.len();

    let mut w = StandardStream::stdout(ColorChoice::Auto);
    let json = crate::stats::json();
    let target_str = match opts.target {
        Some(t) => format!(" to {}", fmt_target(Some(t))),
        None => " — target derived from each packet".to_string(),
    };
    if !json && !opts.summary {
        print_magenta(&mut w, "prping packet recipe")?;
        writeln!(&mut w)?;
        print_cyan(
            &mut w,
            format!(
                "{} — {} step(s), {} global(s), {} param(s){}",
                file.display(),
                step_total,
                recipe.globals.len(),
                params_agg.len(),
                target_str,
            ),
        )?;
        writeln!(&mut w)?;
        if !params_agg.is_empty() {
            print_dim(&mut w, "params:")?;
            writeln!(&mut w)?;
            for (name, defaults, _) in &params_agg {
                let has_default = !defaults.is_empty();
                let def = match defaults.len() {
                    0 => "required".to_string(),
                    1 => format!(
                        "default: {}",
                        crate::engine::eng::value_display(&defaults[0])
                    ),
                    _ => format!(
                        "default: {}",
                        defaults
                            .iter()
                            .map(crate::engine::eng::value_display)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                };
                // 无默认值（必需参数）用橙色警告，有默认值用灰色
                if has_default {
                    print_dim(&mut w, format!("{}- {name} ({def})", indent(1)))?;
                } else {
                    print_orange(&mut w, format!("{}- {name} ({def})", indent(1)))?;
                }
                writeln!(&mut w)?;
            }
        }
        if let Some(secs) = opts.wait.one_shot_secs() {
            crate::output::print_orange(&mut w, t!("engine.note_wait_recipe", secs = secs))?;
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

    // --out：配方模式收集全部步骤的包，结束后写一个 pcap（链路类型取首个包）；
    // 与发送共用同一序列化器（随机字段只消费一次，存档字节 == 实发字节）
    let mut ser = if opts.fuzz {
        DefaultSerializer::new_fuzz()
    } else {
        DefaultSerializer::new()
    };
    let mut out_archive = super::send::SendArchive::default();
    let mut total_failed = 0usize;
    let mut packets_sent = 0usize;
    // ── loop 块运行态（`- loop:` 块，块内步骤已平铺且连续）──
    // 块边界索引：LoopCtx.id → (块首下标, 块尾下标 = 末步 + 1)
    // （闸门收工时跳到块尾；末步执行完回跳块首重新判定）
    let mut loop_bounds: std::collections::HashMap<usize, (usize, usize)> =
        std::collections::HashMap::new();
    for (idx, s) in steps.iter().enumerate() {
        if let Some(ctx) = &s.loop_ctx {
            let e = loop_bounds.entry(ctx.id).or_insert((idx, idx + 1));
            e.1 = idx + 1; // 末次写入 = 块尾
        }
    }
    // 块 id → 运行态（iter = 已开始的轮数（1 起）；until_hit = until 谓词已命中）
    let mut loop_runs: std::collections::HashMap<usize, LoopRun> = std::collections::HashMap::new();
    // on_mismatch 触发包（分派监听 Mismatch 返回；未命中段步骤 reply.* 的来源）
    let mut mismatch_reply: Option<(Vec<u8>, std::net::SocketAddr)> = None;
    // 步骤下标显式推进（loop 闸门可整块跳过 → while 而非 for）
    let mut i = 0usize;
    while i < step_total {
        let step = &steps[i];
        // ── loop 块首：迭代闸门（until / Ctrl+C / 次数，先到先退）──
        if let Some(ctx) = step.loop_ctx.as_ref().filter(|c| c.first) {
            let run = loop_runs.entry(ctx.id).or_default();
            if run.resume_gate {
                // on_mismatch 段执行完回分派监听：不收工判定/不计数/不延迟，
                // 直接重新进入监听等待（不消耗服务轮次）
                run.resume_gate = false;
            } else {
                let end_reason = if run.until_hit {
                    Some("until")
                } else if crate::util::interrupted() {
                    Some("interrupted")
                } else if ctx.count.is_some_and(|n| run.iter >= n) {
                    Some("count")
                } else {
                    None
                };
                if let Some(reason) = end_reason {
                    print_loop_end(&mut w, opts, ctx.id, run.iter, reason)?;
                    i = loop_bounds[&ctx.id].1;
                    continue;
                }
                // 轮间延迟（第 2 轮起）：响应 Ctrl+C 提前优雅收工
                if run.iter > 0
                    && let Some(secs) = ctx.delay
                    && secs > 0.0
                {
                    if !json && !opts.summary {
                        print_dim(
                            &mut w,
                            format!(
                                "{}delay {secs}s before serve {} round {} ...",
                                indent(1),
                                ctx.id + 1,
                                run.iter + 1
                            ),
                        )?;
                        writeln!(&mut w)?;
                    }
                    if !sleep_interruptible(secs) {
                        print_loop_end(&mut w, opts, ctx.id, run.iter, "interrupted")?;
                        i = loop_bounds[&ctx.id].1;
                        continue;
                    }
                }
                run.selected = None;
                mismatch_reply = None; // 新一轮：清除上一轮的未命中触发包
                run.iter += 1;
            }
        }
        // 分派段守卫：多规则/on_mismatch 阶段仅执行被选中段的步骤
        if let Some(ctx) = &step.loop_ctx
            && let Some(want) = ctx.rule
        {
            let sel = loop_runs.get(&ctx.id).and_then(|r| r.selected);
            if sel != Some(want) {
                i += 1;
                continue;
            }
        }
        if !json && !opts.summary {
            writeln!(&mut w)?;
        }
        // 步骤间延迟（delay: 秒；pcap 转码配方携带捕获间隔）：非首步在发送前等待。
        // 分片 sleep 检查 Ctrl+C（首次中断提前结束配方，与测量模式一致的优雅退出）。
        if i > 0
            && let Some(secs) = step.delay
            && secs > 0.0
        {
            if !json && !opts.summary {
                print_dim(
                    &mut w,
                    format!(
                        "{}delay {secs}s before step {}/{} ...",
                        indent(1),
                        i + 1,
                        step_total
                    ),
                )?;
                writeln!(&mut w)?;
            }
            if !sleep_interruptible(secs) {
                if json {
                    let mut m = Map::new();
                    m.insert("type".into(), json!("error"));
                    m.insert(
                        "message".into(),
                        json!("interrupted during delay — stopping recipe"),
                    );
                    serde_json::to_writer(&mut w, &Value::Object(m))?;
                    writeln!(&mut w)?;
                } else {
                    crate::output::print_orange(
                        &mut w,
                        format!("{}interrupted during delay — stopping recipe", indent(1)),
                    )?;
                    writeln!(&mut w)?;
                }
                return Ok(());
            }
        }
        // 步骤失败处理：stop（默认）→ 中止返回 Err；continue → 记录继续
        let fail_step = |w: &mut StandardStream, msg: &str| -> anyhow::Result<()> {
            if json {
                let mut m = Map::new();
                m.insert("type".into(), json!("error"));
                m.insert("step".into(), json!(i + 1));
                m.insert("message".into(), json!(msg));
                serde_json::to_writer(&mut *w, &Value::Object(m))?;
                writeln!(w)?;
            } else {
                let _ = crate::output::writeln_red(w, format!("{}✗ {msg}", indent(1)));
            }
            if step.on_error == OnError::Stop {
                anyhow::bail!(
                    "{}",
                    t!(
                        "engine.recipe_step_failed_stop",
                        file = file.display(),
                        step = i + 1,
                        total = step_total
                    )
                );
            }
            Ok(())
        };

        // 步骤参数：CLI --params + 步骤 params（同名覆盖）
        let mut step_params: packet_dsl::Params = opts.params.iter().cloned().collect();
        for (k, v) in &step.params {
            step_params.insert(k.clone(), v.clone());
        }
        // serve 轮次上下文（serve 阶段内步骤/matcher/extract 求值时 round()/
        // hits() 可用；round = 当前轮、hits = 已命中次数——命中后的步骤含本次）
        let step_serve = step.loop_ctx.as_ref().map(|c| {
            let run = loop_runs.get(&c.id);
            packet_dsl::ServeCtx {
                round: run.map(|r| r.iter).unwrap_or(0),
                hits: run.map(|r| r.hits).unwrap_or(0),
            }
        });
        // 步骤级选项：wait（非负秒数；None = 继承 CLI `--wait SECS`）覆盖 CLI；
        // raw 覆盖发送方式（true/网卡 = 强制 raw，false = 强制 payload——覆盖
        // CLI --raw）；监听步骤（serve 脱糖产出，wait = 负数哨兵）不发送 →
        // 内部 wait 强制 Off（监听由 listen_once 驱动）
        let is_listen = matches!(step.wait, Some(s) if s < 0.0);
        let step_opts = PkgOptions {
            wait: if is_listen {
                crate::engine::pkg::WaitMode::Off
            } else {
                match (step.wait, opts.wait.one_shot_secs()) {
                    // 步骤显式 wait 秒数覆盖 CLI；CLI `--wait SECS` 作步骤默认
                    (Some(secs), _) => crate::engine::pkg::WaitMode::OneShot(secs),
                    (None, Some(s)) => crate::engine::pkg::WaitMode::OneShot(s),
                    _ => crate::engine::pkg::WaitMode::Off,
                }
            },
            // 监听方式：显式 `raw:` 覆盖；否则按包内有无 udp/tcp 传输层自动选择
            // （有 → UDP 数据报监听；无（ICMP/ARP 等）→ 链路层监听）
            mode: if is_listen && step.raw.is_none() {
                super::SendMode::Payload // 占位，listen 分支里按包自动重选
            } else {
                step_send_mode(&step.raw, &opts.mode)
            },
            count: step.count.unwrap_or(opts.count),
            ..opts.clone()
        };
        // 提取来源分区：`sent.` 来源取本步发包（无需 wait）；其余（reply./表达式）取回包
        let has_reply_extract = step
            .extract
            .iter()
            .any(|e| !matches!(e.from, crate::engine::recipe::FromSpec::SentField { .. }));
        let can_reply = matches!(step_opts.wait, crate::engine::pkg::WaitMode::OneShot(_));
        // on_mismatch 段步骤：reply.*/reply.peer.* 取触发未命中的包与对端
        // （无需本步 wait；预注入见下方 replies 声明处）
        let in_mismatch_seg = step.loop_ctx.as_ref().is_some_and(|c| {
            c.rule
                .is_some_and(|k| stage_info.get(&c.id).is_some_and(|s| k == s.rules.len()))
        });
        if has_reply_extract && !can_reply && !is_listen && !in_mismatch_seg {
            fail_step(&mut w, &t!("engine.recipe_extract_needs_wait"))?;
            total_failed += 1;
            i += 1;
            continue;
        }
        // 解析 + 求值（注入当前 global 快照）
        let module = match packet_dsl::parse_file_with_libs(&step.pkg, &opts.libs) {
            Ok(m) => m,
            Err(d) => {
                fail_step(
                    &mut w,
                    &t!(
                        "engine.recipe_parse_fail",
                        file = step.pkg.display(),
                        err = d
                    ),
                )?;
                total_failed += 1;
                i += 1;
                continue;
            }
        };
        // 发送/监听共用的收集容器与标题
        let mut replies: Vec<Vec<u8>> = Vec::new();
        let mut sent_bytes: Vec<Vec<u8>> = Vec::new();
        // listen 步骤的对端（UDP 监听；`reply.peer.*` extract 用）
        let mut listen_peer: Option<std::net::SocketAddr> = None;
        // on_mismatch 段步骤：预注入触发未命中的包（本段 reply.* 的取值来源；
        // 仅当步骤声明了 reply 来源 extract 时注入，不影响 on_timeout 语义）
        if in_mismatch_seg
            && has_reply_extract
            && let Some((mp, _)) = &mismatch_reply
        {
            replies.push(mp.clone());
        }
        // loop 块内步骤：标题附 loop 序号与当前轮次（如 [loop 1 r2/10]）
        let loop_tag = match &step.loop_ctx {
            Some(ctx) => {
                let iter = loop_runs.get(&ctx.id).map(|r| r.iter).unwrap_or(0);
                let bound = ctx.count.map(|n| format!("/{n}")).unwrap_or_default();
                format!("  [serve {} r{iter}{bound}]", ctx.id + 1)
            }
            None => String::new(),
        };
        let header = format!(
            "step {}/{}  {}{}",
            i + 1,
            step_total,
            step.pkg.display(),
            loop_tag
        );
        if json {
            let raw = step.raw.as_ref().map(|r| match r {
                StepRaw::On { iface } => match iface {
                    Some(i) => json!(i),
                    None => json!("true"),
                },
                StepRaw::Off => json!("false"),
            });
            let sp: Map<String, Value> = step
                .params
                .iter()
                .map(|(k, v)| (k.clone(), json!(v.clone())))
                .collect();
            let mut m = Map::new();
            m.insert("type".into(), json!("step"));
            m.insert("step".into(), json!(i + 1));
            m.insert("total".into(), json!(step_total));
            m.insert("pkt".into(), json!(step.pkg.display().to_string()));
            m.insert(
                "wait".into(),
                if is_listen {
                    // 监听步骤（serve 脱糖产出）：json 标记 listen
                    json!("listen")
                } else {
                    match step_opts.wait {
                        crate::engine::pkg::WaitMode::OneShot(s) => json!(s),
                        _ => json!(null),
                    }
                },
            );
            m.insert("raw".into(), raw.unwrap_or(Value::Null));
            m.insert("params".into(), json!(sp));
            m.insert(
                "on_timeout".into(),
                match &step.on_timeout {
                    Some(crate::engine::recipe::OnTimeout::Retry(n)) => json!(format!("retry {n}")),
                    Some(crate::engine::recipe::OnTimeout::Packet(f)) => {
                        json!(f.display().to_string())
                    }
                    None => json!(null),
                },
            );
            m.insert(
                "count".into(),
                match step.count {
                    Some(n) => json!(n),
                    None => json!(null),
                },
            );
            if let Some(ctx) = &step.loop_ctx {
                let iter = loop_runs.get(&ctx.id).map(|r| r.iter).unwrap_or(0);
                m.insert(
                    "serve".into(),
                    json!({
                        "id": ctx.id + 1,
                        "iter": iter,
                        "count": ctx.count,
                        "until": ctx.until,
                    }),
                );
            }
            serde_json::to_writer(&mut w, &Value::Object(m))?;
            writeln!(&mut w)?;
        }
        // listen 步骤：监听触发——不发送，用 .pkt 的 sniffer 匹配外部到达的包，
        // 命中后配方继续（触发后续步骤发包）；匹配包供 reply extract 取值。
        if is_listen {
            let spec = module
                .sniffer
                .clone()
                .ok_or_else(|| anyhow::anyhow!("{}", t!("engine.listen_requires_sniffer")))?;
            // 监听无发包可引用（allow_sent=false；裸 Ident 引用发包字段 → 构建期报错）
            let matcher = packet_dsl::Matcher::build_ctx(
                &spec,
                Some(&module),
                &step_params,
                &globals,
                false,
                step_serve,
            )
            .map_err(|d| anyhow::anyhow!("{d}"))?;
            // until 谓词匹配器（loop 块内）：每轮重建——global 取上一轮 extract 最新值
            let until_matcher = match step.loop_ctx.as_ref().and_then(|c| c.until.as_ref()) {
                Some(preds) => {
                    match build_until_matcher(
                        preds,
                        Some(&module),
                        &step_params,
                        &globals,
                        step_serve,
                    ) {
                        Ok(m) => Some(m),
                        Err(e) => {
                            fail_step(&mut w, &e.to_string())?;
                            total_failed += 1;
                            i += 1;
                            continue;
                        }
                    }
                }
                None => None,
            };
            if !json && !opts.summary {
                print_magenta(&mut w, &header)?;
                writeln!(&mut w)?;
            }
            // 监听方式：显式 raw 覆盖；否则按包内有无 udp/tcp 传输层自动选择
            // （有 → UDP 数据报监听；无（ICMP/ARP 等）→ 链路层监听）
            let mode = if step.raw.is_some() {
                step_send_mode(&step.raw, &opts.mode)
            } else {
                auto_listen_mode(&module, &step_params, &globals)?
            };
            // 分派监听判定（多规则/带 on_mismatch 阶段的首个监听步骤）
            let is_dispatch_listen = step
                .loop_ctx
                .as_ref()
                .is_some_and(|c| c.first && c.rule.is_none())
                && step
                    .loop_ctx
                    .as_ref()
                    .and_then(|c| stage_info.get(&c.id))
                    .is_some_and(|s| s.dispatch());
            let dispatch_rules = step
                .loop_ctx
                .as_ref()
                .and_then(|c| stage_info.get(&c.id))
                .map(|s| s.rules.len())
                .unwrap_or(0);
            // 监听简报：在监听什么（地址/接口）+ 匹配规则（sniffer 摘要）——文案走 i18n
            if !json && !opts.summary && is_dispatch_listen {
                let where_str = match &mode {
                    super::SendMode::Payload => {
                        let addr =
                            super::listen::listen_addr(&module, &step_params, &globals, &step_opts)
                                .map_err(|e| anyhow::anyhow!("{e}"))?;
                        t!("engine.listen_recipe_udp", addr = addr.to_string()).to_string()
                    }
                    super::SendMode::Raw { iface } => t!(
                        "engine.listen_recipe_raw",
                        iface = iface.as_deref().unwrap_or("*")
                    )
                    .to_string(),
                };
                print_cyan(
                    &mut w,
                    format!(
                        "  {}",
                        t!(
                            "engine.serve_dispatch_banner",
                            where_str = where_str,
                            rules = dispatch_rules,
                        )
                    ),
                )?;
                writeln!(&mut w)?;
            } else if !json && !opts.summary {
                let where_str = match &mode {
                    super::SendMode::Payload => {
                        let addr =
                            super::listen::listen_addr(&module, &step_params, &globals, &step_opts)
                                .map_err(|e| anyhow::anyhow!("{e}"))?;
                        t!("engine.listen_recipe_udp", addr = addr.to_string())
                    }
                    super::SendMode::Raw { iface } => t!(
                        "engine.listen_recipe_raw",
                        iface = iface.as_deref().unwrap_or("*")
                    ),
                };
                let rule = sniffer_summary(&spec);
                print_cyan(
                    &mut w,
                    format!(
                        "  {}",
                        t!(
                            "engine.listen_recipe_banner",
                            where_str = where_str,
                            rule = rule
                        )
                    ),
                )?;
                writeln!(&mut w)?;
            }
            // 持续监听（`wait: -1`）无超时；`listen_once` 内部轮询 Ctrl+C
            let timeout: Option<Duration> = None;
            // 命中第一个匹配包即返回（replies 供 extract）；对端供 reply.peer.* 取值。
            // loop 块内：until 命中 / Ctrl+C → 优雅收工（loop_abort = 块尾下标）
            let mut loop_abort: Option<usize> = None;
            let mut listen_reply: Option<Vec<u8>> = None;
            if is_dispatch_listen {
                // ── 分派监听：单一 socket 按序匹配全部规则 matcher（先命中先
                // 服务）；on_mismatch 段在未命中包上执行（不消耗轮次）──
                let ctx_id = step.loop_ctx.as_ref().expect("分派步骤必有 ctx").id;
                let info = &stage_info[&ctx_id];
                let n_rules = info.rules.len();
                // 规则监听方式必须一致（混合 payload/raw 不支持）
                let raw_count = info.rules.iter().filter(|r| r.raw.is_some()).count();
                if raw_count > 0 && raw_count < n_rules {
                    fail_step(&mut w, &t!("engine.serve_mixed_raw"))?;
                    total_failed += 1;
                    i += 1;
                    continue;
                }
                // 每轮重建：各规则模块 + params + matcher（round()/hits() 注入）
                let mut rule_modules: Vec<packet_dsl::Module> = Vec::new();
                let mut rule_matchers: Vec<packet_dsl::Matcher> = Vec::new();
                let mut rule_params: Vec<packet_dsl::Params> = Vec::new();
                let mut prep_err: Option<String> = None;
                for rule in &info.rules {
                    let m = match packet_dsl::parse_file_with_libs(&rule.packet, &opts.libs) {
                        Ok(m) => m,
                        Err(d) => {
                            prep_err = Some(format!("{d}"));
                            break;
                        }
                    };
                    let Some(spec) = m.sniffer.clone() else {
                        prep_err = Some(t!("engine.listen_requires_sniffer").to_string());
                        break;
                    };
                    let mut rp = step_params.clone();
                    for (k, v) in &rule.params {
                        rp.insert(k.clone(), v.clone());
                    }
                    match packet_dsl::Matcher::build_ctx(
                        &spec,
                        Some(&m),
                        &rp,
                        &globals,
                        false,
                        step_serve,
                    ) {
                        Ok(mt) => {
                            rule_modules.push(m);
                            rule_matchers.push(mt);
                            rule_params.push(rp);
                        }
                        Err(d) => {
                            prep_err = Some(format!("{d}"));
                            break;
                        }
                    }
                }
                if let Some(msg) = prep_err {
                    fail_step(
                        &mut w,
                        &t!(
                            "engine.recipe_listen_error",
                            file = info.rules[0].packet.display(),
                            err = msg,
                        ),
                    )?;
                    total_failed += 1;
                    i += 1;
                    continue;
                }
                match mode {
                    super::SendMode::Payload => {
                        match super::listen::listen_udp_dispatch(
                            &globals,
                            &rule_modules,
                            &rule_matchers,
                            &rule_params,
                            &step_opts,
                            timeout,
                            until_matcher.as_ref(),
                            info.mismatch,
                        ) {
                            Ok(Some(super::listen::UdpDispatch::Hit {
                                rule,
                                data,
                                fields,
                                peer,
                                until_matched,
                            })) => {
                                {
                                    let run =
                                        loop_runs.get_mut(&ctx_id).expect("分派阶段运行态已建");
                                    run.selected = Some(rule);
                                    run.hits += 1;
                                }
                                mismatch_reply = None; // 新命中使旧的未命中触发包失效
                                listen_matched(&mut w, opts, &data, &fields, Some(&peer))?;
                                listen_peer = Some(peer);
                                listen_reply = Some(data.clone());
                                // 命中规则 extract 内联应用（分派监听步骤自身无
                                // extract；reply./reply.peer. 取命中包与对端）
                                let extracts: Vec<&crate::engine::recipe::Extract> =
                                    info.rules[rule].extract.iter().collect();
                                if !extracts.is_empty() {
                                    let serve_hit = packet_dsl::ServeCtx {
                                        round: loop_runs.get(&ctx_id).map(|r| r.iter).unwrap_or(0),
                                        hits: loop_runs.get(&ctx_id).map(|r| r.hits).unwrap_or(0),
                                    };
                                    match apply_extract(
                                        Some(&rule_modules[rule]),
                                        &mut globals,
                                        &extracts,
                                        &rule_params[rule],
                                        None,
                                        Some(&data),
                                        Some(peer),
                                        Some(serve_hit),
                                    ) {
                                        Ok(pairs) => print_extract_pairs(&mut w, opts, &pairs)?,
                                        Err(e) => {
                                            if json {
                                                let mut m = Map::new();
                                                m.insert("type".into(), json!("error"));
                                                m.insert("step".into(), json!(i + 1));
                                                m.insert("message".into(), json!(e.to_string()));
                                                serde_json::to_writer(&mut w, &Value::Object(m))?;
                                                writeln!(&mut w)?;
                                            } else {
                                                let _ = crate::output::writeln_red(
                                                    &mut w,
                                                    format!("  ✗ {e}"),
                                                );
                                            }
                                            total_failed += 1;
                                        }
                                    }
                                }
                                if until_matched && let Some(run) = loop_runs.get_mut(&ctx_id) {
                                    run.until_hit = true; // 本轮结束后收工
                                }
                            }
                            Ok(Some(super::listen::UdpDispatch::Until)) => {
                                let run = loop_runs.entry(ctx_id).or_default();
                                print_loop_end(&mut w, opts, ctx_id, run.iter, "until")?;
                                loop_abort = loop_bounds.get(&ctx_id).map(|b| b.1);
                            }
                            Ok(Some(super::listen::UdpDispatch::Mismatch { data, peer })) => {
                                // 未命中包 → on_mismatch 段（不消耗轮次，执行完回监听）
                                if !json && !opts.summary {
                                    print_dim(
                                        &mut w,
                                        format!(
                                            "  {}",
                                            t!(
                                                "engine.serve_mismatch_hit",
                                                peer = peer.to_string()
                                            ),
                                        ),
                                    )?;
                                    writeln!(&mut w)?;
                                }
                                let run = loop_runs.get_mut(&ctx_id).expect("分派阶段运行态已建");
                                run.selected = Some(n_rules);
                                // 触发未命中的包 + 对端：本段步骤 reply.*/reply.peer.* 的取值来源
                                mismatch_reply = Some((data.clone(), peer));
                                listen_peer = Some(peer);
                                listen_reply = Some(data);
                            }
                            Ok(None) => {
                                let run = loop_runs.entry(ctx_id).or_default();
                                print_loop_end(&mut w, opts, ctx_id, run.iter, "interrupted")?;
                                loop_abort = loop_bounds.get(&ctx_id).map(|b| b.1);
                            }
                            Err(e) => {
                                fail_step(
                                    &mut w,
                                    &t!(
                                        "engine.recipe_listen_error",
                                        file = step.pkg.display(),
                                        err = e,
                                    ),
                                )?;
                                total_failed += 1;
                                i += 1;
                                continue;
                            }
                        }
                    }
                    super::SendMode::Raw { iface } => {
                        let arcs: Vec<Arc<packet_dsl::Matcher>> =
                            rule_matchers.into_iter().map(Arc::new).collect();
                        match super::listen_raw::listen_raw_dispatch(
                            arcs,
                            until_matcher.map(Arc::new),
                            iface.as_deref(),
                            timeout,
                            info.mismatch,
                        ) {
                            Ok(Some(super::listen_raw::RawDispatch::Hit {
                                rule,
                                data,
                                until_matched,
                            })) => {
                                {
                                    let run =
                                        loop_runs.get_mut(&ctx_id).expect("分派阶段运行态已建");
                                    run.selected = Some(rule);
                                    run.hits += 1;
                                }
                                mismatch_reply = None; // 新命中使旧的未命中触发包失效
                                listen_matched(&mut w, opts, &data, &[], None)?;
                                listen_reply = Some(data.clone());
                                let extracts: Vec<&crate::engine::recipe::Extract> =
                                    info.rules[rule].extract.iter().collect();
                                if !extracts.is_empty() {
                                    let serve_hit = packet_dsl::ServeCtx {
                                        round: loop_runs.get(&ctx_id).map(|r| r.iter).unwrap_or(0),
                                        hits: loop_runs.get(&ctx_id).map(|r| r.hits).unwrap_or(0),
                                    };
                                    match apply_extract(
                                        Some(&rule_modules[rule]),
                                        &mut globals,
                                        &extracts,
                                        &rule_params[rule],
                                        None,
                                        Some(&data),
                                        None,
                                        Some(serve_hit),
                                    ) {
                                        Ok(pairs) => print_extract_pairs(&mut w, opts, &pairs)?,
                                        Err(e) => {
                                            if json {
                                                let mut m = Map::new();
                                                m.insert("type".into(), json!("error"));
                                                m.insert("step".into(), json!(i + 1));
                                                m.insert("message".into(), json!(e.to_string()));
                                                serde_json::to_writer(&mut w, &Value::Object(m))?;
                                                writeln!(&mut w)?;
                                            } else {
                                                let _ = crate::output::writeln_red(
                                                    &mut w,
                                                    format!("  ✗ {e}"),
                                                );
                                            }
                                            total_failed += 1;
                                        }
                                    }
                                }
                                if until_matched && let Some(run) = loop_runs.get_mut(&ctx_id) {
                                    run.until_hit = true; // 本轮结束后收工
                                }
                            }
                            Ok(Some(super::listen_raw::RawDispatch::Until)) => {
                                let run = loop_runs.entry(ctx_id).or_default();
                                print_loop_end(&mut w, opts, ctx_id, run.iter, "until")?;
                                loop_abort = loop_bounds.get(&ctx_id).map(|b| b.1);
                            }
                            Ok(Some(super::listen_raw::RawDispatch::Mismatch { data })) => {
                                if !json && !opts.summary {
                                    print_dim(
                                        &mut w,
                                        format!("  {}", t!("engine.serve_mismatch_hit_raw")),
                                    )?;
                                    writeln!(&mut w)?;
                                }
                                let run = loop_runs.get_mut(&ctx_id).expect("分派阶段运行态已建");
                                run.selected = Some(n_rules);
                                listen_reply = Some(data);
                            }
                            Ok(None) => {
                                let run = loop_runs.entry(ctx_id).or_default();
                                print_loop_end(&mut w, opts, ctx_id, run.iter, "interrupted")?;
                                loop_abort = loop_bounds.get(&ctx_id).map(|b| b.1);
                            }
                            Err(e) => {
                                fail_step(
                                    &mut w,
                                    &t!(
                                        "engine.recipe_listen_error",
                                        file = step.pkg.display(),
                                        err = e,
                                    ),
                                )?;
                                total_failed += 1;
                                i += 1;
                                continue;
                            }
                        }
                    }
                }
            } else {
                match mode {
                    super::SendMode::Payload => {
                        match super::listen::listen_udp_once(
                            &module,
                            &step_params,
                            &globals,
                            &matcher,
                            &step_opts,
                            timeout,
                            until_matcher.as_ref(),
                        ) {
                            Ok(Some(super::listen::UdpListen::Hit {
                                data,
                                fields,
                                peer,
                                until_matched,
                            })) => {
                                listen_matched(&mut w, opts, &data, &fields, Some(&peer))?;
                                listen_peer = Some(peer);
                                listen_reply = Some(data);
                                // hits() 计数：单规则直听命中也计入阶段命中累计
                                if let Some(ctx) = &step.loop_ctx
                                    && let Some(run) = loop_runs.get_mut(&ctx.id)
                                {
                                    run.hits += 1;
                                }
                                if until_matched
                                    && let Some(ctx) = &step.loop_ctx
                                    && let Some(run) = loop_runs.get_mut(&ctx.id)
                                {
                                    run.until_hit = true; // 本轮结束后收工
                                }
                            }
                            Ok(Some(super::listen::UdpListen::Until)) => {
                                // until 命中（非本步 sniffer 命中）：跳过本轮后续步骤，整块收工
                                if let Some(ctx) = &step.loop_ctx {
                                    let run = loop_runs.entry(ctx.id).or_default();
                                    print_loop_end(&mut w, opts, ctx.id, run.iter, "until")?;
                                    loop_abort = loop_bounds.get(&ctx.id).map(|b| b.1);
                                }
                            }
                            Ok(None) => {
                                // Ctrl+C：loop 块内优雅收工；非 loop 维持旧行为（步骤失败）
                                if let Some(ctx) = &step.loop_ctx {
                                    let run = loop_runs.entry(ctx.id).or_default();
                                    print_loop_end(&mut w, opts, ctx.id, run.iter, "interrupted")?;
                                    loop_abort = loop_bounds.get(&ctx.id).map(|b| b.1);
                                }
                            }
                            Err(e) => {
                                fail_step(
                                    &mut w,
                                    &t!(
                                        "engine.recipe_listen_error",
                                        file = step.pkg.display(),
                                        err = e
                                    ),
                                )?;
                                total_failed += 1;
                                i += 1;
                                continue;
                            }
                        }
                    }
                    super::SendMode::Raw { iface } => {
                        match super::listen_raw::listen_raw_once(
                            Arc::new(matcher),
                            until_matcher.map(Arc::new),
                            iface.as_deref(),
                            timeout,
                        ) {
                            Ok(Some(super::listen_raw::RawListen::Hit {
                                data,
                                until_matched,
                            })) => {
                                listen_matched(&mut w, opts, &data, &[], None)?;
                                listen_reply = Some(data);
                                // hits() 计数：单规则直听命中也计入阶段命中累计
                                if let Some(ctx) = &step.loop_ctx
                                    && let Some(run) = loop_runs.get_mut(&ctx.id)
                                {
                                    run.hits += 1;
                                }
                                if until_matched
                                    && let Some(ctx) = &step.loop_ctx
                                    && let Some(run) = loop_runs.get_mut(&ctx.id)
                                {
                                    run.until_hit = true;
                                }
                            }
                            Ok(Some(super::listen_raw::RawListen::Until)) => {
                                if let Some(ctx) = &step.loop_ctx {
                                    let run = loop_runs.entry(ctx.id).or_default();
                                    print_loop_end(&mut w, opts, ctx.id, run.iter, "until")?;
                                    loop_abort = loop_bounds.get(&ctx.id).map(|b| b.1);
                                }
                            }
                            Ok(None) => {
                                if let Some(ctx) = &step.loop_ctx {
                                    let run = loop_runs.entry(ctx.id).or_default();
                                    print_loop_end(&mut w, opts, ctx.id, run.iter, "interrupted")?;
                                    loop_abort = loop_bounds.get(&ctx.id).map(|b| b.1);
                                }
                            }
                            Err(e) => {
                                fail_step(
                                    &mut w,
                                    &t!(
                                        "engine.recipe_listen_error",
                                        file = step.pkg.display(),
                                        err = e
                                    ),
                                )?;
                                total_failed += 1;
                                i += 1;
                                continue;
                            }
                        }
                    }
                }
            }
            if let Some(end) = loop_abort {
                i = end;
                continue;
            }
            let Some(hit) = listen_reply else {
                fail_step(&mut w, &t!("engine.recipe_listen_interrupted"))?;
                total_failed += 1;
                i += 1;
                continue;
            };
            replies.push(hit);
        }
        // 非 listen：解析来源（send_module 与 on_timeout retry 重发共用）
        let sources = if is_listen {
            Vec::new()
        } else {
            let resolved = match step_serve {
                Some(sc) => {
                    packet_dsl::resolve_sources_with_serve(&module, &step_params, &globals, sc)
                }
                None => packet_dsl::resolve_sources_with_globals(&module, &step_params, &globals),
            };
            match resolved {
                Ok(s) => s,
                Err(d) => {
                    fail_step(
                        &mut w,
                        &t!(
                            "engine.recipe_eval_fail",
                            file = step.pkg.display(),
                            err = d
                        ),
                    )?;
                    total_failed += 1;
                    i += 1;
                    continue;
                }
            }
        };
        if !is_listen && sources.iter().map(|(_, p)| p.len()).sum::<usize>() == 0 {
            fail_step(
                &mut w,
                &format!("{}: {}", step.pkg.display(), t!("engine.err_no_packets")),
            )?;
            total_failed += 1;
            i += 1;
            continue;
        }
        // --out 收集已下沉到 send_module（与发送共用同一序列化器）；listen 步骤
        // 不发送、不收集
        let stats = if is_listen {
            super::send::SendStats::default()
        } else {
            match send_module(
                &mut w,
                Some(header.clone()),
                SendCtx {
                    module: &module,
                    sources: &sources,
                    params: &step_params,
                    globals: &globals,
                    on_reply: Some(&mut |b: &[u8]| replies.push(b.to_vec())),
                    on_sent: Some(&mut |b: &[u8]| sent_bytes.push(b.to_vec())),
                },
                &step_opts,
                &mut ser,
                Some(&mut out_archive),
            ) {
                Ok(s) => s,
                Err(e) => {
                    fail_step(
                        &mut w,
                        &t!(
                            "engine.recipe_send_error",
                            file = step.pkg.display(),
                            err = e
                        ),
                    )?;
                    total_failed += 1;
                    i += 1;
                    continue;
                }
            }
        };
        let mut step_failed = stats.failed;
        packets_sent += stats.total - stats.failed - stats.skipped;
        if !is_listen && stats.skipped == stats.total && stats.total > 0 {
            step_failed += 1;
            fail_step(
                &mut w,
                &t!("engine.recipe_bare_only", file = step.pkg.display()),
            )?;
        }
        // wait 超时处理（on_timeout）：发送成功但等待超时未收到匹配应答 →
        // `retry [N]` 重发当前步骤的包（每次重新 wait，任一次等到回包即成功）；
        // `文件` 发送备选 .pkt（发其它包）；步骤继续
        if !is_listen
            && stats.failed == 0
            && step_opts.wait.one_shot_secs().is_some()
            && replies.is_empty()
            && let Some(on_timeout) = &step.on_timeout
        {
            let secs = step_opts.wait.one_shot_secs().expect("已判 OneShot");
            match on_timeout {
                crate::engine::recipe::OnTimeout::Retry(n) => {
                    for attempt in 1..=*n {
                        if json {
                            let mut m = Map::new();
                            m.insert("type".into(), json!("retry"));
                            m.insert("step".into(), json!(i + 1));
                            m.insert("attempt".into(), json!(attempt));
                            m.insert("total".into(), json!(n));
                            serde_json::to_writer(&mut w, &Value::Object(m))?;
                            writeln!(&mut w)?;
                        } else if !opts.summary {
                            print_orange(
                                &mut w,
                                format!(
                                    "  {}",
                                    t!(
                                        "engine.recipe_timeout_retry",
                                        secs = secs,
                                        attempt = attempt,
                                        total = n
                                    )
                                ),
                            )?;
                            writeln!(&mut w)?;
                        }
                        // 重发当前步骤的包（wait 保留：每次重新等应答）
                        let rstats = match send_module(
                            &mut w,
                            Some(header.clone()),
                            SendCtx {
                                module: &module,
                                sources: &sources,
                                params: &step_params,
                                globals: &globals,
                                on_reply: Some(&mut |b: &[u8]| replies.push(b.to_vec())),
                                on_sent: Some(&mut |b: &[u8]| sent_bytes.push(b.to_vec())),
                            },
                            &step_opts,
                            &mut ser,
                            Some(&mut out_archive),
                        ) {
                            Ok(s) => s,
                            Err(e) => {
                                fail_step(
                                    &mut w,
                                    &t!(
                                        "engine.recipe_send_error",
                                        file = step.pkg.display(),
                                        err = e
                                    ),
                                )?;
                                total_failed += 1;
                                break;
                            }
                        };
                        packets_sent += rstats.total - rstats.failed - rstats.skipped;
                        if !replies.is_empty() {
                            break; // 重试等到回包 → 步骤成功（replies 供 extract）
                        }
                    }
                }
                crate::engine::recipe::OnTimeout::Packet(fallback) => {
                    if json {
                        let mut m = Map::new();
                        m.insert("type".into(), json!("timeout"));
                        m.insert("step".into(), json!(i + 1));
                        m.insert("secs".into(), json!(secs));
                        m.insert("send".into(), json!(fallback.display().to_string()));
                        serde_json::to_writer(&mut w, &Value::Object(m))?;
                        writeln!(&mut w)?;
                    } else if !opts.summary {
                        print_orange(
                            &mut w,
                            format!(
                                "  {}",
                                t!(
                                    "engine.recipe_timeout_send",
                                    secs = secs,
                                    file = fallback.display()
                                )
                            ),
                        )?;
                        writeln!(&mut w)?;
                    }
                    match send_on_timeout_packet(
                        fallback,
                        &module,
                        &step_params,
                        &globals,
                        &step_opts,
                        &mut w,
                    ) {
                        Ok(sent) => packets_sent += sent,
                        Err(e) => {
                            fail_step(&mut w, &t!("engine.recipe_on_timeout_fail", err = e))?;
                            total_failed += 1;
                        }
                    }
                }
            }
        }
        // extract：回包 → global（多个回包依次应用，后写覆盖先写）
        // extract：sent 来源 → 本步发包字段；reply 来源 → 回包字段
        // （多包/多回包依次应用，后写覆盖先写）
        if !step.extract.is_empty() {
            let sent_extracts: Vec<&crate::engine::recipe::Extract> = step
                .extract
                .iter()
                .filter(|e| matches!(e.from, crate::engine::recipe::FromSpec::SentField { .. }))
                .collect();
            let reply_extracts: Vec<&crate::engine::recipe::Extract> = step
                .extract
                .iter()
                .filter(|e| !matches!(e.from, crate::engine::recipe::FromSpec::SentField { .. }))
                .collect();
            let mut extract_failed = false;
            // sent 来源：不需要回包
            if !sent_extracts.is_empty() {
                if sent_bytes.is_empty() {
                    step_failed += 1;
                    extract_failed = true;
                    fail_step(&mut w, &t!("engine.recipe_extract_no_sent"))?;
                } else {
                    for sb in &sent_bytes {
                        match apply_extract(
                            Some(&module),
                            &mut globals,
                            &sent_extracts,
                            &step_params,
                            Some(sb),
                            None,
                            None,
                            step_serve,
                        ) {
                            Ok(pairs) => print_extract_pairs(&mut w, opts, &pairs)?,
                            Err(e) => {
                                step_failed += 1;
                                extract_failed = true;
                                if json {
                                    let mut m = Map::new();
                                    m.insert("type".into(), json!("error"));
                                    m.insert("step".into(), json!(i + 1));
                                    m.insert("message".into(), json!(e.to_string()));
                                    serde_json::to_writer(&mut w, &Value::Object(m))?;
                                    writeln!(&mut w)?;
                                } else {
                                    let _ = crate::output::writeln_red(&mut w, format!("  ✗ {e}"));
                                }
                                break;
                            }
                        }
                    }
                }
            }
            // reply 来源：需要回包
            if !reply_extracts.is_empty() {
                if replies.is_empty() {
                    step_failed += 1;
                    extract_failed = true;
                    fail_step(
                        &mut w,
                        &t!("engine.recipe_extract_no_reply", n = reply_extracts.len()),
                    )?;
                } else {
                    // on_mismatch 段：reply.peer.* 取触发未命中的包的对端
                    let extract_peer = if in_mismatch_seg {
                        mismatch_reply.as_ref().map(|(_, p)| *p)
                    } else {
                        listen_peer
                    };
                    for rb in &replies {
                        match apply_extract(
                            Some(&module),
                            &mut globals,
                            &reply_extracts,
                            &step_params,
                            None,
                            Some(rb),
                            extract_peer,
                            step_serve,
                        ) {
                            Ok(pairs) => print_extract_pairs(&mut w, opts, &pairs)?,
                            Err(e) => {
                                step_failed += 1;
                                extract_failed = true;
                                if json {
                                    let mut m = Map::new();
                                    m.insert("type".into(), json!("error"));
                                    m.insert("step".into(), json!(i + 1));
                                    m.insert("message".into(), json!(e.to_string()));
                                    serde_json::to_writer(&mut w, &Value::Object(m))?;
                                    writeln!(&mut w)?;
                                } else {
                                    let _ = crate::output::writeln_red(&mut w, format!("  ✗ {e}"));
                                }
                                break;
                            }
                        }
                    }
                }
            }
            if extract_failed && step_failed > stats.failed {
                fail_step(&mut w, &t!("engine.recipe_extract_failed"))?;
            }
        }
        total_failed += step_failed;
        if !json && step_failed > 0 {
            let _ = crate::output::writeln_red(
                &mut w,
                format!(
                    "  {}",
                    t!(
                        "engine.recipe_step_failed_summary",
                        step = i + 1,
                        total = step_total,
                        n = step_failed
                    )
                ),
            );
            if step.on_error == OnError::Stop {
                return Err(anyhow::anyhow!(
                    "{}",
                    t!(
                        "engine.recipe_step_failed_stop",
                        file = file.display(),
                        step = i + 1,
                        total = step_total
                    )
                ));
            }
        }
        // 常规路径：块内末步 → 回跳块首（闸门重新判定收工条件）；否则下一步骤。
        // （失败路径与 loop 闸门跳转各自显式改 i，不走这里）
        if let Some(ctx) = &step.loop_ctx
            && ctx.last
        {
            // on_mismatch 段末（段标记 = 规则数）：回分派监听不消耗轮次
            // （闸门遇 resume_gate 跳过一次计数/收工判定）
            let n_rules = stage_info.get(&ctx.id).map(|s| s.rules.len()).unwrap_or(0);
            if ctx.rule.is_some_and(|k| k == n_rules)
                && let Some(run) = loop_runs.get_mut(&ctx.id)
            {
                run.resume_gate = true;
            }
            i = loop_bounds[&ctx.id].0;
            continue;
        }
        i += 1;
    }

    if let Some(out) = &opts.out {
        crate::engine::pcap::write_pcap(
            out,
            out_archive
                .linktype
                .unwrap_or(crate::engine::pcap::LinkType::Raw),
            &out_archive.bytes,
        )?;
    }
    if json {
        // --json：配方汇总行（JSONL 最后一行）
        let mut m = Map::new();
        m.insert("type".into(), json!("summary"));
        m.insert("file".into(), json!(file.display().to_string()));
        m.insert("steps".into(), json!(step_total));
        m.insert("packets_sent".into(), json!(packets_sent));
        m.insert("steps_failed".into(), json!(total_failed));
        serde_json::to_writer(&mut w, &Value::Object(m))?;
        writeln!(&mut w)?;
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
                "prping packet recipe: {file} — {steps} step(s){target}, {packets_sent} packet(s) sent, {total_failed} failed",
                file = file.display(),
                steps = step_total,
                target = target_phrase,
            ),
        )?;
        writeln!(&mut w)?;
    }
    if total_failed > 0 {
        anyhow::bail!(
            "{}",
            t!(
                "engine.recipe_failed_total",
                file = file.display(),
                n = total_failed
            )
        );
    }
    Ok(())
}

/// 遍历配方 items 递归收集全部 packet 的词法 params：顶层步骤 + serve 规则
/// 监听源 + handler/嵌套 on_recv 步骤（顺序与 send_recipe 脱糖产出的步骤序列
/// 一致；单包收集失败静默返回空——exec 循环会报真正的解析错误）。
fn collect_recipe_pkt_params(
    recipe: &crate::engine::recipe::Recipe,
) -> Vec<Vec<(String, Option<packet_dsl::ast::Value>)>> {
    use crate::engine::recipe::{RecipeItem, ServeItem, ServeRule};
    fn push(pkg: &Path, out: &mut Vec<Vec<(String, Option<packet_dsl::ast::Value>)>>) {
        out.push(collect_pkt_params(pkg).unwrap_or_default());
    }
    fn walk_rule(rule: &ServeRule, out: &mut Vec<Vec<(String, Option<packet_dsl::ast::Value>)>>) {
        push(&rule.packet, out);
        for item in &rule.handler {
            match item {
                ServeItem::Step(s) => push(&s.pkg, out),
                ServeItem::OnRecv(nested) => walk_rule(nested, out),
            }
        }
    }
    let mut out = Vec::new();
    for item in &recipe.items {
        match item {
            RecipeItem::Step(s) => push(&s.pkg, &mut out),
            RecipeItem::Serve(serve) => {
                for rule in &serve.rules {
                    walk_rule(rule, &mut out);
                }
                if let Some(items) = &serve.on_mismatch {
                    for item in items {
                        match item {
                            ServeItem::Step(s) => push(&s.pkg, &mut out),
                            ServeItem::OnRecv(nested) => walk_rule(nested, &mut out),
                        }
                    }
                }
            }
        }
    }
    out
}

/// serve 规则 → 扁平步骤（监听步骤 + handler 递归展开；全部附加同一 LoopCtx）。
///
/// - `seg`：本规则段标记（分派阶段 = Some(规则下标)；非分派阶段 = None）。
/// - `listen_tag`：本规则监听步骤的段标记（分派监听 = None 不受守卫；嵌套
///   on_recv = Some(所属规则)——受守卫）。
/// - `emit_listen`：false = 不产出监听步骤（分派阶段规则 k>0：分派监听已
///   按序匹配全部规则，不重复监听）。
fn expand_serve_rule(
    rule: &crate::engine::recipe::ServeRule,
    base: &crate::engine::recipe::LoopCtx,
    seg: Option<usize>,
    listen_tag: Option<usize>,
    emit_listen: bool,
    out: &mut Vec<crate::engine::recipe::Step>,
) {
    use crate::engine::recipe::ServeItem;
    // 监听步骤：wait 负数哨兵（-1.0）= 监听（执行器 `is_listen` 判定）——不发送，
    // 用规则监听源的 sniffer 匹配命中包，规则 extract 命中取值写 global。
    // 分派监听步骤（分派阶段规则 0）自身不挂 extract——命中规则的 extract 由
    // 执行器内联应用（步骤级 extract 只认步骤自身模块）。
    if emit_listen {
        let mut ctx = base.clone();
        ctx.rule = listen_tag;
        let dispatch_listener = seg.is_some() && listen_tag.is_none();
        out.push(crate::engine::recipe::Step {
            pkg: rule.packet.clone(),
            wait: Some(-1.0),
            on_timeout: None,
            count: None,
            delay: None,
            raw: rule.raw.clone(),
            params: rule.params.clone(),
            extract: if dispatch_listener {
                Vec::new()
            } else {
                rule.extract.clone()
            },
            on_error: OnError::Stop,
            line: rule.line,
            loop_ctx: Some(ctx),
        });
    }
    for item in &rule.handler {
        match item {
            ServeItem::Step(s) => {
                let mut s = s.clone();
                let mut ctx = base.clone();
                ctx.rule = seg;
                s.loop_ctx = Some(ctx);
                out.push(s);
            }
            // 嵌套 on_recv：监听步骤 + 其 handler 递归展开（同阶段同一 LoopCtx；
            // 分派阶段下监听步骤与 handler 同属本规则段）
            ServeItem::OnRecv(nested) => {
                expand_serve_rule(nested, base, seg, seg, true, out);
            }
        }
    }
}

/// on_mismatch 段条目 → 扁平步骤（段标记 = 规则数；条目语法与 handler 一致）。
fn expand_segment_item(
    item: &crate::engine::recipe::ServeItem,
    base: &crate::engine::recipe::LoopCtx,
    seg: Option<usize>,
    out: &mut Vec<crate::engine::recipe::Step>,
) {
    use crate::engine::recipe::ServeItem;
    match item {
        ServeItem::Step(s) => {
            let mut s = s.clone();
            let mut ctx = base.clone();
            ctx.rule = seg;
            s.loop_ctx = Some(ctx);
            out.push(s);
        }
        ServeItem::OnRecv(nested) => expand_serve_rule(nested, base, seg, seg, true, out),
    }
}

/// serve 阶段执行期信息（阶段 id → 规则表 + on_mismatch 有无；脱糖收集）。
struct StageInfo {
    rules: Vec<crate::engine::recipe::ServeRule>,
    mismatch: bool,
}

impl StageInfo {
    /// 多规则或带 on_mismatch → 分派监听（单一 socket 按序匹配全部规则）。
    fn dispatch(&self) -> bool {
        self.rules.len() > 1 || self.mismatch
    }
}

/// loop 块运行态（块 id → 迭代计数 / until 命中标记）。
#[derive(Default)]
struct LoopRun {
    /// 已开始的轮数（1 起：闸门放行时 +1）。
    iter: usize,
    /// until 谓词已命中（本轮结束后收工）。
    until_hit: bool,
    /// 分派阶段当前轮选中的段（Some(k) = 规则 k 命中；Some(n) = on_mismatch
    /// 段；None = 尚未命中/非分派阶段）。段守卫据此跳过未选中段的步骤。
    selected: Option<usize>,
    /// on_mismatch 段执行完回分派监听：跳过一次闸门（不消耗轮次）。
    resume_gate: bool,
    /// 本阶段累计命中次数（`hits()` 值原语取值源；命中后含本次）。
    hits: usize,
}

/// serve 阶段收工打印（`--json`：`{"type":"serve_end",...}` 行；人读：青色一行，
/// 摘要模式静默）。`reason`：until / count / interrupted。
fn print_loop_end(
    w: &mut StandardStream,
    opts: &PkgOptions,
    id: usize,
    iterations: usize,
    reason: &str,
) -> anyhow::Result<()> {
    if crate::stats::json() {
        let mut m = Map::new();
        m.insert("type".into(), json!("serve_end"));
        m.insert("serve".into(), json!(id + 1));
        m.insert("iterations".into(), json!(iterations));
        m.insert("reason".into(), json!(reason));
        serde_json::to_writer(&mut *w, &Value::Object(m))?;
        writeln!(w)?;
        return Ok(());
    }
    if opts.summary {
        return Ok(());
    }
    let reason_str = match reason {
        "until" => t!("engine.recipe_loop_reason_until").to_string(),
        "count" => t!("engine.recipe_loop_reason_count").to_string(),
        _ => t!("engine.recipe_loop_reason_interrupted").to_string(),
    };
    print_cyan(
        w,
        t!(
            "engine.serve_end",
            id = id + 1,
            iters = iterations,
            reason = reason_str
        ),
    )?;
    writeln!(w)?;
    Ok(())
}

/// `until:` 谓词列表 → Matcher：合成只含 `sniffer:` 段的源文本复用 packet-dsl
/// 解析器（语法已在解析期预检），再按 sniffer 同一构建路径做层/字段名与值语义
/// 检查（`allow_sent=false`——监听无发包可引用）。`module` 提供值函数作用域、
/// `globals` 供 `global(...)` 取值（loop 每轮重建 → 取上一轮 extract 最新值）。
fn build_until_matcher(
    preds: &[String],
    module: Option<&packet_dsl::Module>,
    params: &packet_dsl::Params,
    globals: &packet_dsl::Globals,
    serve: Option<packet_dsl::ServeCtx>,
) -> anyhow::Result<packet_dsl::Matcher> {
    let mut text = String::from("sniffer:\n");
    for p in preds {
        text.push_str("- ");
        text.push_str(p);
        text.push('\n');
    }
    let ast = packet_dsl::parser::parse_ast(&text)
        .map_err(|d| anyhow::anyhow!("{}", t!("engine.recipe_until_pred_fail", err = d)))?;
    let spec = ast
        .stmts
        .into_iter()
        .find_map(|s| match s {
            packet_dsl::ast::Stmt::Sniffer(spec) => Some(spec),
            _ => None,
        })
        .expect("sniffer 段已在解析期预检");
    packet_dsl::Matcher::build_ctx(&spec, module, params, globals, false, serve)
        .map_err(|d| anyhow::anyhow!("{}", t!("engine.recipe_until_pred_fail", err = d)))
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

/// 监听步骤的自动方式：包内有 udp/tcp 传输层 → UDP 数据报监听；否则
/// （ICMP/ARP/裸 IP 等）→ 链路层监听（`raw: true` 可显式覆盖）。
fn auto_listen_mode(
    module: &packet_dsl::Module,
    params: &packet_dsl::Params,
    globals: &packet_dsl::Globals,
) -> anyhow::Result<super::SendMode> {
    let sources = packet_dsl::resolve_sources_with_globals(module, params, globals)
        .map_err(|d| anyhow::anyhow!("{d}"))?;
    let has_transport = sources.iter().flat_map(|(_, ps)| ps).any(|pkt| {
        pkt.layers.iter().any(|l| {
            matches!(
                l,
                packet_dsl::ir::Layer::Udp(_) | packet_dsl::ir::Layer::Tcp(_)
            )
        })
    });
    Ok(if has_transport {
        super::SendMode::Payload
    } else {
        super::SendMode::Raw { iface: None }
    })
}

/// sniffer 规则单行摘要（监听简报）：`match icmp(type=8)`、
/// `or(match a(...), match b(...))`；顶层多条 = 隐式 OR。
fn sniffer_summary(spec: &packet_dsl::SnifferSpec) -> String {
    use packet_dsl::ast::{SnifferItem, SnifferPred};
    fn item(v: &SnifferItem) -> String {
        match v {
            SnifferItem::FieldEq { name, val } => {
                format!("{name}={}", crate::engine::eng::sniffer_value_display(val))
            }
            SnifferItem::FieldNe { name, val } => format!(
                "ne({name}, {})",
                crate::engine::eng::sniffer_value_display(val)
            ),
            SnifferItem::Mask(v) => format!("mask({})", value_display(v)),
            SnifferItem::StartsWith(s) => format!("startswith({s:?})"),
            SnifferItem::EndsWith(s) => format!("endswith({s:?})"),
            SnifferItem::Contains(s) => format!("contains({s:?})"),
        }
    }
    fn pred(p: &SnifferPred) -> String {
        match p {
            SnifferPred::Clause(c) => format!(
                "match {}({})",
                c.layer,
                c.items.iter().map(item).collect::<Vec<_>>().join(", ")
            ),
            SnifferPred::And(ps) => format!(
                "and({})",
                ps.iter().map(pred).collect::<Vec<_>>().join(", ")
            ),
            SnifferPred::Or(ps) => {
                format!("or({})", ps.iter().map(pred).collect::<Vec<_>>().join(", "))
            }
            SnifferPred::Not(p) => format!("not({})", pred(p)),
        }
    }
    spec.clauses
        .iter()
        .map(pred)
        .collect::<Vec<_>>()
        .join(" or ")
}

/// 发送 `on_timeout` 备选包（wait 超时时）：解析 + 求值（注入当前 global/params）+
/// send_module（wait=Off 纯发送）。返回实际发送的包数。
fn send_on_timeout_packet(
    file: &std::path::Path,
    _cur_module: &packet_dsl::Module,
    params: &packet_dsl::Params,
    globals: &packet_dsl::Globals,
    opts: &PkgOptions,
    w: &mut StandardStream,
) -> anyhow::Result<usize> {
    let module =
        packet_dsl::parse_file_with_libs(file, &opts.libs).map_err(|d| anyhow::anyhow!("{d}"))?;
    let sources = packet_dsl::resolve_sources_with_globals(&module, params, globals)
        .map_err(|d| anyhow::anyhow!("{d}"))?;
    if sources.iter().map(|(_, p)| p.len()).sum::<usize>() == 0 {
        anyhow::bail!("{}", t!("engine.err_no_packets"));
    }
    let send_opts = PkgOptions {
        wait: crate::engine::pkg::WaitMode::Off,
        ..opts.clone()
    };
    // on_timeout 兜底包不参与 --out 存档（配方主步骤已收集）
    let mut ser = if opts.fuzz {
        DefaultSerializer::new_fuzz()
    } else {
        DefaultSerializer::new()
    };
    let stats = send_module(
        w,
        Some(format!("on_timeout  {}", file.display())),
        SendCtx {
            module: &module,
            sources: &sources,
            params,
            globals,
            on_reply: None,
            on_sent: None,
        },
        &send_opts,
        &mut ser,
        None,
    )?;
    Ok(stats.total - stats.failed - stats.skipped)
}

/// listen 步骤命中打印：`✓ matched N B（from peer）` + sniffer 命中字段 + 反解展示。
/// `--json`：输出 `{"type":"matched", ...}` 行；摘要模式静默。
fn listen_matched(
    w: &mut StandardStream,
    opts: &PkgOptions,
    bytes: &[u8],
    fields: &[(String, String)],
    peer: Option<&std::net::SocketAddr>,
) -> anyhow::Result<()> {
    if crate::stats::json() {
        let mut m = Map::new();
        m.insert("type".into(), json!("matched"));
        m.insert("bytes".into(), json!(bytes.len()));
        if let Some(p) = peer {
            m.insert("peer".into(), json!(p.to_string()));
        }
        if !fields.is_empty() {
            let f: Map<String, Value> = fields.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            m.insert("fields".into(), json!(f));
        }
        serde_json::to_writer(&mut *w, &Value::Object(m))?;
        writeln!(w)?;
    } else if !opts.summary {
        match peer {
            Some(p) => {
                print_green(w, format!("  ✓ matched {} B from {p}", bytes.len()))?;
                writeln!(w)?;
            }
            None => {
                print_green(w, format!("  ✓ matched {} B", bytes.len()))?;
                writeln!(w)?;
            }
        }
        if !fields.is_empty() {
            let pairs: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
            print_green(w, format!("{}{}", indent(1), pairs.join(" ")))?;
            writeln!(w)?;
        }
        let report = packet_dsl::dissect(bytes);
        crate::engine::eng::render_dissected(w, &report, "  datagram:", bytes)?;
    }
    Ok(())
}

/// 打印提取结果（摘要模式：仍写入 global 但不逐条打印）。
fn print_extract_pairs(
    w: &mut StandardStream,
    opts: &PkgOptions,
    pairs: &[(String, packet_dsl::ast::Value)],
) -> anyhow::Result<()> {
    if crate::stats::json() {
        // --json：逐条 extract 结果行
        for (n, v) in pairs {
            let mut m = Map::new();
            m.insert("type".into(), json!("extract"));
            m.insert("name".into(), json!(n));
            m.insert("value".into(), json!(value_display(v)));
            serde_json::to_writer(&mut *w, &Value::Object(m))?;
            writeln!(w)?;
        }
    } else if !opts.summary {
        for (n, v) in pairs {
            print_green(w, format!("  ✓ global.{n} = {}", value_display(v)))?;
            writeln!(w)?;
        }
    }
    Ok(())
}

/// 从发包/回包字节按 `extract:` 子句提取字段写入 global（复用 matchpred 的
/// 层/字段机制）。`sent_bytes` 非 None = 发包来源；`reply_bytes` 非 None = 回包来源
/// （二者恰有一个）。返回实际写入的 (名字, 值) 列表供调用方打印。任一子句失败 →
/// 整体报错（已写入的前序值保留——后写覆盖先写的语义由调用方逐包调用保证）。
#[allow(clippy::too_many_arguments)]
fn apply_extract(
    module: Option<&packet_dsl::Module>,
    globals: &mut packet_dsl::Globals,
    extracts: &[&crate::engine::recipe::Extract],
    params: &packet_dsl::Params,
    sent_bytes: Option<&[u8]>,
    reply_bytes: Option<&[u8]>,
    // listen 步骤的对端地址（`reply.peer.*` 来源用；非 listen 步骤为 None）。
    peer: Option<std::net::SocketAddr>,
    // serve 轮次上下文（serve 阶段 extract 的 round()/hits() 取值源）。
    serve: Option<packet_dsl::ServeCtx>,
) -> anyhow::Result<Vec<(String, packet_dsl::ast::Value)>> {
    use crate::engine::recipe::FromSpec;
    use packet_dsl::ast::Value;
    let src_bytes = sent_bytes.or(reply_bytes).expect("恰有一个来源");
    let report = packet_dsl::dissect(src_bytes);
    let mut out = Vec::new();
    for e in extracts {
        let val = match &e.from {
            // 监听对端（listen 步骤 UDP 监听）：reply.peer.ip / reply.peer.port
            FromSpec::PeerField { field } => {
                let p = peer.ok_or_else(|| {
                    anyhow::anyhow!(
                        "{}",
                        t!(
                            "engine.recipe_peer_only_listen",
                            line = e.line,
                            field = field
                        )
                    )
                })?;
                match (field.as_str(), e.as_) {
                    ("ip", ExtractAs::Str) => Value::Str(p.ip().to_string()),
                    ("ip", ExtractAs::Bytes) => Value::List(
                        match p.ip() {
                            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                        }
                        .into_iter()
                        .map(|b| Value::Int(b as i64))
                        .collect(),
                    ),
                    ("ip", _) => Value::Str(p.ip().to_string()),
                    ("port", ExtractAs::Hex) => Value::Hex(p.port() as u64),
                    ("port", _) => Value::Int(p.port() as i64),
                    _ => unreachable!("parse_from 已校验 peer 字段"),
                }
            }
            FromSpec::Field { layer, field } | FromSpec::SentField { layer, field } => {
                let Some(rl) = report.layers.iter().find(|l| layer_kind(l) == *layer) else {
                    return Err(anyhow::anyhow!(
                        "{}",
                        t!(
                            "engine.recipe_no_layer",
                            line = e.line,
                            src = src_label(sent_bytes.is_some()),
                            layer = layer,
                            name = e.name
                        )
                    ));
                };
                // 字段 → 自然 Value（Bytes 用原始字节；其余用 sniffer 字段值），
                // 再经统一的 `as:` 转换（ExtractAs::apply，与表达式形态共用）
                let natural = match e.as_ {
                    ExtractAs::Bytes => {
                        let bytes = field_bytes(rl, field).ok_or_else(|| {
                            anyhow::anyhow!(
                                "{}",
                                t!(
                                    "engine.recipe_no_field",
                                    line = e.line,
                                    layer = layer,
                                    field = field
                                )
                            )
                        })?;
                        Value::List(bytes.into_iter().map(|b| Value::Int(b as i64)).collect())
                    }
                    _ => {
                        let f = sniffer_extract(rl, field).ok_or_else(|| {
                            anyhow::anyhow!(
                                "{}",
                                t!(
                                    "engine.recipe_no_field",
                                    line = e.line,
                                    layer = layer,
                                    field = field
                                )
                            )
                        })?;
                        match f {
                            FVal::U(u) => Value::Int(u as i64),
                            other => Value::Str(other.display()),
                        }
                    }
                };
                e.as_.apply(natural, e.line, &e.name)?
            }
            FromSpec::Expr(expr) => {
                // 值表达式：求值（可调用户值函数/params/global/reply 叶子），
                // 结果按 `as:` 转换（缺省 = 自然类型值）
                let reply_access =
                    |layer: &str, field: &str| reply_field_value(&report, layer, field);
                let v = packet_dsl::eval_extract_value_ctx(
                    module,
                    params,
                    globals,
                    &reply_access,
                    serve,
                    expr,
                )
                .map_err(|d| {
                    anyhow::anyhow!("{}", t!("engine.recipe_expr_fail", line = e.line, err = d))
                })?;
                if e.as_given {
                    e.as_.apply(v, e.line, &e.name)?
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

/// 提取来源的标签（错误消息用；走 i18n）。
fn src_label(sent: bool) -> String {
    if sent {
        t!("engine.recipe_src_label_sent").to_string()
    } else {
        t!("engine.recipe_src_label_reply").to_string()
    }
}

/// `reply("层","字段")` 取值：sniffer 字段集 + 扩展字节字段（icmp.payload /
/// http.body / raw.bytes；raw.bytes 无 Raw 层时兜底 remaining——裸应用层回显）。
/// 供配方 `extract` 的 `from:` 表达式专用（唯一注入回包访问器的上下文）。
pub(crate) fn reply_field_value(
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

#[cfg(test)]
mod tests {
    use super::*;
    // 测试里直接调用 DefaultSerializer 的 trait 方法
    use packet_dsl::Serializer as _;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

    /// 配方 items 里的普通步骤（按序；serve 阶段不计入——解析测试只断言顶层
    /// Step 条目，serve 阶段的结构由专门的测试覆盖）。
    fn steps(r: &crate::engine::recipe::Recipe) -> Vec<&crate::engine::recipe::Step> {
        r.items
            .iter()
            .filter_map(|it| match it {
                crate::engine::recipe::RecipeItem::Step(s) => Some(s),
                crate::engine::recipe::RecipeItem::Serve(_) => None,
            })
            .collect()
    }

    /// 解析：`packet:` 键 + `wait:`（非负秒数 = 发后等一个应答 / 不写 = 纯发送；
    /// 负数旧持续监听写法已移除——报错测试见 recipe_parse_wait_errors_and_renamed_key）。
    #[test]
    fn recipe_parse_packet_and_wait() {
        let dir = std::env::temp_dir().join(format!("prping-parse-wait-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pktl = dir.join("r.pktl");
        std::fs::write(&pktl, "recipe:\n- packet: a.pkt\n  wait: 5\n- b.pkt\n").unwrap();
        let r = crate::engine::recipe::parse(&pktl).unwrap();
        assert_eq!(r.items.len(), 2);
        let crate::engine::recipe::RecipeItem::Step(s0) = &r.items[0] else {
            panic!("条目 0 应为 Step");
        };
        assert_eq!(s0.pkg.file_name().unwrap(), "a.pkt");
        assert_eq!(s0.wait, Some(5.0));
        let crate::engine::recipe::RecipeItem::Step(s1) = &r.items[1] else {
            panic!("条目 1 应为 Step");
        };
        assert_eq!(s1.pkg.file_name().unwrap(), "b.pkt");
        assert!(s1.wait.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 解析：`on_timeout: 文件`；`wait:` 负数（旧持续监听写法）报错。
    #[test]
    fn recipe_parse_on_timeout_and_wait_negative() {
        let dir = std::env::temp_dir().join(format!("prping-parse-timeout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pktl = dir.join("r.pktl");
        std::fs::write(
            &pktl,
            "recipe:\n- packet: a.pkt\n  wait: 2\n  on_timeout: fb.pkt\n",
        )
        .unwrap();
        let r = crate::engine::recipe::parse(&pktl).unwrap();
        let crate::engine::recipe::RecipeItem::Step(s0) = &r.items[0] else {
            panic!("条目 0 应为 Step");
        };
        match &s0.on_timeout {
            Some(crate::engine::recipe::OnTimeout::Packet(p)) => {
                assert_eq!(p.file_name().unwrap().to_string_lossy(), "fb.pkt")
            }
            other => panic!("应解析为 Packet，得到 {other:?}"),
        }
        assert_eq!(s0.wait, Some(2.0));
        // 负数 = 旧持续监听写法 → 明确报错（监听循环由 serve: 阶段接管）
        std::fs::write(&pktl, "recipe:\n- packet: a.pkt\n  wait: -2\n").unwrap();
        let err = crate::engine::recipe::parse(&pktl).unwrap_err().to_string();
        assert!(err.contains("wait"), "{err}");
    }

    /// 解析：`wait:` 非法值/空值/负数报错；serve 键不能写在普通步骤上；
    /// `pkg:` 旧键明确报错。
    #[test]
    fn recipe_parse_wait_errors_and_renamed_key() {
        let dir = std::env::temp_dir().join(format!("prping-parse-wait2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pktl = dir.join("r.pktl");
        // 非法 wait 值
        std::fs::write(&pktl, "recipe:\n- packet: a.pkt\n  wait: abc\n").unwrap();
        let err = crate::engine::recipe::parse(&pktl).unwrap_err().to_string();
        assert!(err.contains("`wait`"), "{err}");
        // 空值非法（要么不写、要么写值）
        std::fs::write(&pktl, "recipe:\n- packet: a.pkt\n  wait:\n").unwrap();
        let err = crate::engine::recipe::parse(&pktl).unwrap_err().to_string();
        assert!(err.contains("`wait`"), "{err}");
        // 负数 = 旧持续监听写法 → 报错提示改用 serve: 阶段
        std::fs::write(&pktl, "recipe:\n- packet: a.pkt\n  wait: -1\n").unwrap();
        let err = crate::engine::recipe::parse(&pktl).unwrap_err().to_string();
        assert!(err.contains("wait") && err.contains("serve"), "{err}");
        // serve 专用键不能写在普通步骤上
        std::fs::write(&pktl, "recipe:\n- packet: a.pkt\n  until:\n").unwrap();
        let err = crate::engine::recipe::parse(&pktl).unwrap_err().to_string();
        assert!(err.contains("serve"), "{err}");
        // 空值非法：params（原静默无操作）/ extract 内联值（原被静默忽略）
        std::fs::write(&pktl, "recipe:\n- packet: a.pkt\n  params:\n").unwrap();
        let err = crate::engine::recipe::parse(&pktl).unwrap_err().to_string();
        assert!(err.contains("`params`"), "{err}");
        std::fs::write(&pktl, "recipe:\n- packet: a.pkt\n  extract: 3\n").unwrap();
        let err = crate::engine::recipe::parse(&pktl).unwrap_err().to_string();
        assert!(err.contains("`extract`"), "{err}");
        // 旧键 pkg: → 明确报错提示改名
        std::fs::write(&pktl, "recipe:\n- pkg: a.pkt\n").unwrap();
        let err = crate::engine::recipe::parse(&pktl).unwrap_err().to_string();
        assert!(err.contains("packet:"), "{err}");
    }

    /// ICMP mock 配方（examples/icmp_mock/）字节级验证：server 配方
    /// listen 匹配 request → extract 字段写 global → reply.pkt 构造 echo reply
    /// （type=0/id/payload 回显、seq=请求 seq+1000 配方标记、IP 互换）；client 配方两步 request：
    /// sniffer 校验 reply + extract cid 复用。读真实 demo 文件，不依赖 root/socket。
    #[test]
    fn icmp_mock_recipe_simulation() {
        crate::engine::eng::ensure_proto_registry();
        let ex = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/icmp_mock");
        // 1) server / client 配方解析：server = serve 阶段（max: 2 + 单规则），
        //    client = 两个普通步骤
        let server = crate::engine::recipe::parse(&ex.join("server.pktl")).unwrap();
        assert_eq!(server.items.len(), 1);
        let crate::engine::recipe::RecipeItem::Serve(serve) = &server.items[0] else {
            panic!("server 配方应为 serve 阶段");
        };
        assert_eq!(
            serve.max,
            Some(2),
            "serve.max = 服务轮数（对应 client 两步请求）"
        );
        assert_eq!(serve.rules.len(), 1);
        let rule = &serve.rules[0];
        let client = crate::engine::recipe::parse(&ex.join("client.pktl")).unwrap();
        assert_eq!(client.items.len(), 2);
        // 2) client req1.pkt 构造 echo request 帧（id=0x1234, seq=1, payload "hello"）
        let req1_src = std::fs::read_to_string(ex.join("req1.pkt")).unwrap();
        let rm = packet_dsl::semantic::parse_str("t", &req1_src).unwrap();
        let built = packet_dsl::resolve(&rm).unwrap();
        let frame = packet_dsl::DefaultSerializer::new()
            .serialize(&built.packets[0])
            .unwrap();
        // 3) 规则 extract 应用到匹配帧 → global
        let mut globals = packet_dsl::Globals::new();
        let extract_refs: Vec<&crate::engine::recipe::Extract> = rule.extract.iter().collect();
        apply_extract(
            Some(&rm),
            &mut globals,
            &extract_refs,
            &packet_dsl::Params::new(),
            None,
            Some(&frame),
            None,
            None,
        )
        .expect("server extract 应从 request 帧取值");
        use packet_dsl::ast::Value;
        assert_eq!(globals.get("r_id"), Some(&Value::Int(0x1234)));
        assert_eq!(globals.get("r_seq"), Some(&Value::Int(1)));
        // demo 用回环 127.0.0.1（可运行）；r_src_ip 取自 reply.ipv4.src、r_dst_ip 取自
        // reply.ipv4.dst（来源字段不同，值同为回环）
        assert_eq!(
            globals.get("r_src_ip"),
            Some(&Value::Str("127.0.0.1".into()))
        );
        assert_eq!(
            globals.get("r_dst_ip"),
            Some(&Value::Str("127.0.0.1".into()))
        );
        assert!(matches!(globals.get("r_payload"), Some(Value::List(v)) if v.len() == 5));
        // 4) 规则 handler 的 reply.pkt 用 global 求值 → echo reply
        let reply_src = std::fs::read_to_string(ex.join("reply.pkt")).unwrap();
        let rrm = packet_dsl::semantic::parse_str("t", &reply_src).unwrap();
        let rbuilt =
            packet_dsl::resolve_sources_with_globals(&rrm, &packet_dsl::Params::new(), &globals)
                .unwrap();
        let reply = packet_dsl::DefaultSerializer::new()
            .serialize(&rbuilt[0].1[0])
            .unwrap();
        // 5) 校验 reply：type=0、id/payload 回显、seq=请求 seq+1000（配方标记）、IP 互换
        let rep = packet_dsl::dissect(&reply);
        let icmp = rep
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Icmp(f) => Some(f),
                _ => None,
            })
            .expect("reply 有 icmp 层");
        assert_eq!(icmp.icmp_type, Some(0), "echo reply type=0");
        assert_eq!(icmp.id, Some(0x1234), "id 回显");
        assert_eq!(
            icmp.seq,
            Some(1 + 1000),
            "seq = 请求 seq + 1000（配方标记，排除内核替答）"
        );
        assert_eq!(icmp.payload.as_deref(), Some(&b"hello"[..]), "载荷回显");
        let ip4 = rep
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Ipv4(f) => Some(f),
                _ => None,
            })
            .expect("reply 有 ipv4 层");
        let ipv = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
        // 回环场景 src/dst 同为 127.0.0.1；互换方向由 r_src_ip/r_dst_ip 的来源字段保证
        assert_eq!(ip4.src, packet_dsl::ir::Field::Value(ipv("127.0.0.1")));
        assert_eq!(ip4.dst, packet_dsl::ir::Field::Value(ipv("127.0.0.1")));
        // 6) client req1 的 sniffer 校验 reply
        let matcher = packet_dsl::Matcher::build(
            &rm.sniffer.clone().unwrap(),
            Some(&rm),
            &packet_dsl::Params::new(),
            &packet_dsl::Globals::new(),
            true,
        )
        .unwrap();
        let got = matcher
            .matches(&reply, Some(&packet_dsl::dissect(&frame)))
            .expect("client 应匹配 echo reply");
        assert!(got.iter().any(|(k, v)| k == "id" && v == "4660"), "{got:?}");
        // 7) client 步骤 1 extract cid → req2.pkt 复用 global
        let crate::engine::recipe::RecipeItem::Step(client_step1) = &client.items[0] else {
            panic!("client 条目 0 应为 Step");
        };
        let mut cglobals = packet_dsl::Globals::new();
        let cid_refs: Vec<&crate::engine::recipe::Extract> = client_step1.extract.iter().collect();
        apply_extract(
            Some(&rm),
            &mut cglobals,
            &cid_refs,
            &packet_dsl::Params::new(),
            None,
            Some(&reply),
            None,
            None,
        )
        .expect("client extract 应从 reply 取 cid");
        assert_eq!(cglobals.get("cid"), Some(&Value::Int(0x1234)));
        let req2_src = std::fs::read_to_string(ex.join("req2.pkt")).unwrap();
        let r2m = packet_dsl::semantic::parse_str("t", &req2_src).unwrap();
        let r2built =
            packet_dsl::resolve_sources_with_globals(&r2m, &packet_dsl::Params::new(), &cglobals)
                .unwrap();
        let req2 = packet_dsl::DefaultSerializer::new()
            .serialize(&r2built[0].1[0])
            .unwrap();
        let rep2 = packet_dsl::dissect(&req2);
        let icmp2 = rep2
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Icmp(f) => Some(f),
                _ => None,
            })
            .unwrap();
        assert_eq!(icmp2.id, Some(0x1234), "req2 复用 extract 的 cid");
        assert_eq!(icmp2.seq, Some(2));
        // 8) server 对 req2 回第二个 reply（id=0x1234 seq=2，回包 seq=1002）→ client req2 sniffer 校验
        let mut globals2 = packet_dsl::Globals::new();
        let extract_refs2: Vec<&crate::engine::recipe::Extract> = rule.extract.iter().collect();
        apply_extract(
            Some(&r2m),
            &mut globals2,
            &extract_refs2,
            &packet_dsl::Params::new(),
            None,
            Some(&req2),
            None,
            None,
        )
        .expect("server extract 二次取值");
        let r2reply =
            packet_dsl::resolve_sources_with_globals(&rrm, &packet_dsl::Params::new(), &globals2)
                .unwrap();
        let reply2 = packet_dsl::DefaultSerializer::new()
            .serialize(&r2reply[0].1[0])
            .unwrap();
        let matcher2 = packet_dsl::Matcher::build(
            &r2m.sniffer.clone().unwrap(),
            Some(&r2m),
            &packet_dsl::Params::new(),
            &cglobals,
            true,
        )
        .unwrap();
        let got2 = matcher2
            .matches(&reply2, Some(&packet_dsl::dissect(&req2)))
            .expect("client req2 应匹配第二个 echo reply");
        assert!(
            got2.iter().any(|(k, v)| k == "id" && v == "4660"),
            "{got2:?}"
        );
    }

    /// 统一的 `as:` 转换函数（ExtractAs::apply）：自然值 → 目标形态。
    #[test]
    fn extract_as_apply() {
        use packet_dsl::ast::Value;
        let line = 1;
        // int：Int 原样 / Hex 转 Int / Str 报错
        assert_eq!(
            crate::engine::recipe::ExtractAs::Int
                .apply(Value::Int(4660), line, "x")
                .unwrap(),
            Value::Int(4660)
        );
        assert_eq!(
            crate::engine::recipe::ExtractAs::Int
                .apply(Value::Hex(0x1234), line, "x")
                .unwrap(),
            Value::Int(4660)
        );
        assert!(
            crate::engine::recipe::ExtractAs::Int
                .apply(Value::Str("127.0.0.1".into()), line, "x")
                .is_err()
        );
        // hex：Int → Hex / 负数报错
        assert_eq!(
            crate::engine::recipe::ExtractAs::Hex
                .apply(Value::Int(4660), line, "x")
                .unwrap(),
            Value::Hex(0x1234)
        );
        // str：Int → 数字字符串 / Str 原样
        assert_eq!(
            crate::engine::recipe::ExtractAs::Str
                .apply(Value::Int(4660), line, "x")
                .unwrap(),
            Value::Str("4660".into())
        );
        assert_eq!(
            crate::engine::recipe::ExtractAs::Str
                .apply(Value::Str("127.0.0.1".into()), line, "x")
                .unwrap(),
            Value::Str("127.0.0.1".into())
        );
        // bytes：List 原样 / Str → 字节 / Int 报错（提示 be16）
        assert_eq!(
            crate::engine::recipe::ExtractAs::Bytes
                .apply(
                    Value::List(vec![Value::Int(104), Value::Int(105)]),
                    line,
                    "x"
                )
                .unwrap(),
            Value::List(vec![Value::Int(104), Value::Int(105)])
        );
        assert_eq!(
            crate::engine::recipe::ExtractAs::Bytes
                .apply(Value::Str("hi".into()), line, "x")
                .unwrap(),
            Value::List(vec![Value::Int(104), Value::Int(105)])
        );
        assert!(
            crate::engine::recipe::ExtractAs::Bytes
                .apply(Value::Int(4660), line, "x")
                .is_err()
        );
    }

    /// 解析：`count: N` 步骤字段（每个包重复发送次数）。
    #[test]
    fn recipe_parse_count() {
        let dir = std::env::temp_dir().join(format!("prping-parse-count-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pktl = dir.join("r.pktl");
        std::fs::write(&pktl, "recipe:\n- packet: a.pkt\n  count: 3\n- b.pkt\n").unwrap();
        let r = crate::engine::recipe::parse(&pktl).unwrap();
        let s = steps(&r);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].count, Some(3));
        assert!(s[1].count.is_none());
        // count: 0 → 报错
        std::fs::write(&pktl, "recipe:\n- packet: a.pkt\n  count: 0\n").unwrap();
        let err = crate::engine::recipe::parse(&pktl).unwrap_err().to_string();
        assert!(err.contains("count"), "{err}");
    }

    /// 集成：`count: N` 一次发多个包——UDP 回环收包端应收到 N 个数据报。
    #[test]
    fn recipe_count_sends_multiple() {
        crate::engine::eng::ensure_proto_registry();
        let dir = std::env::temp_dir().join(format!("prping-count-recipe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("pkt.pkt"),
            "q = dns(id=0x1111, questions=[\"example.com\"])\nfull = use(q) |> udp(dport=params(\"port\")) |> ipv4(dst=\"127.0.0.1\") |> eth()\nexport:\n- full\n",
        )
        .unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let pktl = dir.join("recipe.pktl");
        std::fs::write(
            &pktl,
            format!("recipe:\n- packet: pkt.pkt\n  count: 4\n  params: port={port}\n"),
        )
        .unwrap();
        // 收包端 = 发包目标端口
        let rx = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)).unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let pktl2 = pktl.clone();
        let handle = std::thread::spawn(move || {
            let opts = PkgOptions {
                summary: true,
                ..Default::default()
            };
            send_recipe(&pktl2, &opts)
        });
        // 收 count=4 个数据报
        let mut got = 0usize;
        for _ in 0..10 {
            if let Ok((n, _)) = rx.recv_from(&mut [0u8; 512]) {
                got += usize::from(n > 0);
                if got >= 4 {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(got, 4, "count: 4 应一次发出 4 个数据报");
        let res = handle.join().expect("配方线程不应 panic");
        res.expect("配方应成功完成");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 解析：`on_timeout: retry` / `on_timeout: retry N`。
    #[test]
    fn recipe_parse_on_timeout_retry() {
        let dir = std::env::temp_dir().join(format!("prping-parse-otretry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pktl = dir.join("r.pktl");
        std::fs::write(
            &pktl,
            "recipe:\n- packet: a.pkt\n  wait: 2\n  on_timeout: retry\n",
        )
        .unwrap();
        let r = crate::engine::recipe::parse(&pktl).unwrap();
        assert!(
            matches!(
                steps(&r)[0].on_timeout,
                Some(crate::engine::recipe::OnTimeout::Retry(1))
            ),
            "on_timeout: retry = 重试 1 次"
        );
        std::fs::write(
            &pktl,
            "recipe:\n- packet: a.pkt\n  wait: 2\n  on_timeout: retry 3\n",
        )
        .unwrap();
        let r = crate::engine::recipe::parse(&pktl).unwrap();
        assert!(
            matches!(
                steps(&r)[0].on_timeout,
                Some(crate::engine::recipe::OnTimeout::Retry(3))
            ),
            "on_timeout: retry 3 = 重试 3 次"
        );
        // retry 0 → 报错
        std::fs::write(
            &pktl,
            "recipe:\n- packet: a.pkt\n  wait: 2\n  on_timeout: retry 0\n",
        )
        .unwrap();
        let err = crate::engine::recipe::parse(&pktl).unwrap_err().to_string();
        assert!(err.contains("retry"), "{err}");
    }

    /// 集成：`on_timeout: retry`——超时后重发原包，第二次（重试）等到回包 →
    /// 步骤成功、extract 可用。UDP 回环：先不发应答让首次超时，重试时再应答。
    #[test]
    fn recipe_on_timeout_retry_succeeds_on_resend() {
        crate::engine::eng::ensure_proto_registry();
        let dir = std::env::temp_dir().join(format!("prping-otretry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("pkt.pkt"),
            "q = dns(id=0x3333, questions=[\"example.com\"])\nfull = use(q) |> udp(dport=params(\"port\")) |> ipv4(dst=\"127.0.0.1\") |> eth()\nexport:\n- full\nsniffer:\n  - match dns(id=id, flags=0x8180)\n",
        )
        .unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let pktl = dir.join("recipe.pktl");
        std::fs::write(
            &pktl,
            format!(
                "global:\n- rid\nrecipe:\n- packet: pkt.pkt\n  wait: 1\n  on_timeout: retry 3\n  params: port={port}\n  extract:\n  - name: rid\n    from: reply.dns.id\n    as: int\n"
            ),
        )
        .unwrap();
        // 服务端：第一次收到不回应（逼首次超时），第二次收到回 DNS 应答
        let pktl2 = pktl.clone();
        let handle = std::thread::spawn(move || {
            let opts = PkgOptions {
                summary: true,
                ..Default::default()
            };
            send_recipe(&pktl2, &opts)
        });
        let server =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut first = true;
        let mut replies = 0usize;
        let mut buf = [0u8; 512];
        for _ in 0..30 {
            match server.recv_from(&mut buf) {
                Ok((n, peer)) if n > 0 => {
                    if first {
                        first = false; // 第一次：不回应 → 触发 retry
                    } else {
                        // 第二次起：回 DNS 应答（id 回显 + flags=0x8180）
                        let mut resp = buf[..n].to_vec();
                        resp[2..4].copy_from_slice(&[0x81, 0x80]);
                        resp[7] = 0; // ancount 0（sniffer 只看 id/flags）
                        let _ = server.send_to(&resp, peer);
                        replies += 1;
                        if replies >= 1 {
                            break;
                        }
                    }
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
        assert_eq!(replies, 1, "重试应等到一次回包");
        let res = handle.join().expect("配方线程不应 panic");
        if let Err(e) = &res {
            eprintln!("配方执行失败：{e:#}");
        }
        res.expect("on_timeout retry 等到回包后应成功");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 集成：`wait: 秒数` 超时（无人应答）→ `on_timeout` 发送备选包并继续。
    /// 字节级回环，无 root 依赖。
    #[test]
    fn recipe_wait_timeout_sends_on_timeout_packet() {
        crate::engine::eng::ensure_proto_registry();
        let dir =
            std::env::temp_dir().join(format!("prping-timeout-recipe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 主步骤包：发到无人监听的端口（必然超时）
        std::fs::write(
            dir.join("query.pkt"),
            "p = raw(bytes=\"ping\")\nuse(p) |> udp(dport=params(\"qport\")) |> ipv4(dst=\"127.0.0.1\") |> eth()\n",
        )
        .unwrap();
        // 备选包：发到客户端监听端口
        std::fs::write(
            dir.join("fb.pkt"),
            "p = raw(bytes=\"fallback\")\nuse(p) |> udp(dport=params(\"port\")) |> ipv4(dst=\"127.0.0.1\") |> eth()\n",
        )
        .unwrap();
        // 客户端端口（收 on_timeout 备选包）
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cport = client.local_addr().unwrap().port();
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        // 无人端口（主步骤目标，保证超时）
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let qport = probe.local_addr().unwrap().port();
        drop(probe);
        let pktl = dir.join("recipe.pktl");
        std::fs::write(
            &pktl,
            format!(
                "recipe:\n- packet: query.pkt\n  wait: 1\n  on_timeout: fb.pkt\n  params: qport={qport},port={cport}\n"
            ),
        )
        .unwrap();
        // 配方线程（summary 静音）
        let pktl2 = pktl.clone();
        let handle = std::thread::spawn(move || {
            let opts = PkgOptions {
                summary: true,
                ..Default::default()
            };
            send_recipe(&pktl2, &opts)
        });
        // 客户端应收到 on_timeout 备选包（fallback 载荷）
        let mut got_fb = false;
        let mut buf = [0u8; 64];
        for _ in 0..30 {
            if let Ok((n, _)) = client.recv_from(&mut buf) {
                got_fb = n > 0 && buf[..n].windows(8).any(|w| w == b"fallback");
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(got_fb, "客户端应收到 on_timeout 备选包（fallback 载荷）");
        let res = handle.join().expect("配方线程不应 panic");
        res.expect("配方应成功完成（超时 → on_timeout 发包 → 继续）");
    }

    /// 集成：serve 阶段（max: 1）单规则——监听匹配 DNS 查询 → 规则 extract
    /// 匹配包字段 → handler **触发发包**（应答回客户端）。字节级回环，无 root 依赖。
    #[test]
    fn recipe_listen_triggers_next_step() {
        crate::engine::eng::ensure_proto_registry();
        let dir = std::env::temp_dir().join(format!("prping-listen-recipe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 监听步骤 .pkt：sniffer 匹配 DNS 查询 id=0x4242；dport 用 params（随机端口）
        std::fs::write(
            dir.join("listen.pkt"),
            "p = raw(bytes=\"\")\nuse(p) |> udp(dport=params(\"port\")) |> ipv4() |> eth()\nsniffer:\n  - match dns(id=0x4242)\n",
        )
        .unwrap();
        // 触发步骤 .pkt：用 extract 的 global（匹配包的 dns.id / udp.sport）构造应答发回客户端
        std::fs::write(
            dir.join("trigger.pkt"),
            "q = dns(id=global(\"tid\"), flags=0x8180, questions=[\"example.com\"])\nfull = use(q) |> udp(sport=53, dport=global(\"cport\")) |> ipv4(dst=\"127.0.0.1\") |> eth()\nexport:\n- full\n",
        )
        .unwrap();
        // 空闲端口
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let pktl = dir.join("recipe.pktl");
        std::fs::write(
            &pktl,
            format!(
                "global:\n- tid\n- cport\nrecipe:\n- serve:\n  max: 1\n  rules:\n  - packet: listen.pkt\n    params: port={port}\n    extract:\n    - name: tid\n      from: reply.dns.id\n      as: int\n    - name: cport\n      from: reply.peer.port\n      as: int\n    handler:\n    - packet: trigger.pkt\n"
            ),
        )
        .unwrap();
        // 配方线程（summary 静音输出）
        let pktl2 = pktl.clone();
        let handle = std::thread::spawn(move || {
            let opts = PkgOptions {
                summary: true,
                ..Default::default()
            };
            send_recipe(&pktl2, &opts)
        });
        // 客户端：轮询发 DNS 查询（id=0x4242）直到命中；再收触发步骤发回的应答
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        // DNS 查询字节：id=0x4242, flags=0x0100, qdcount=1, question example.com A IN
        let query: Vec<u8> = vec![
            0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        // 收到应答 = 触发发包成功（应答 id=0x4242 回显，flags=0x8180）
        let mut got_reply = false;
        for _ in 0..60 {
            let _ = client.send_to(&query, server_addr);
            if let Ok((n, _)) = client.recv_from(&mut [0u8; 4096]) {
                got_reply = n > 0;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(got_reply, "客户端应收到 listen 触发步骤发回的应答");
        let res = handle.join().expect("配方线程不应 panic");
        if let Err(e) = &res {
            eprintln!("配方执行失败：{e:#}");
        }
        res.expect("配方应成功完成（serve 命中 → extract → handler 触发发包）");
    }
}
