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

    // 步骤 .pkt 用到的 params（词法收集；失败静默——exec 循环会报真正的解析错误）
    let per_step: Vec<Vec<(String, Option<packet_dsl::ast::Value>)>> = recipe
        .steps
        .iter()
        .map(|s| collect_pkt_params(&s.pkg).unwrap_or_default())
        .collect();
    let params_agg = aggregate_pkt_params(&per_step);

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
                recipe.steps.len(),
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
    for (i, step) in recipe.steps.iter().enumerate() {
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
                        recipe.steps.len()
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
                        total = recipe.steps.len()
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
        // 步骤级选项：wait（三态，与 CLI --wait 同语义）覆盖 CLI；raw 覆盖发送方式
        // （true/网卡 = 强制 raw，false = 强制 payload——覆盖 CLI --raw）；
        // 持续监听步骤（wait 无值）不发送 → 内部 wait 强制 Off（监听由 listen_once 驱动）
        let is_listen = matches!(step.wait, Some(crate::engine::pkg::WaitMode::Continuous));
        let step_opts = PkgOptions {
            wait: if is_listen {
                crate::engine::pkg::WaitMode::Off
            } else {
                match (step.wait, opts.wait) {
                    // 步骤显式 wait（OneShot）覆盖 CLI；CLI `--wait SECS` 作步骤默认
                    (Some(mode), _) => mode,
                    (None, crate::engine::pkg::WaitMode::OneShot(secs)) => {
                        crate::engine::pkg::WaitMode::OneShot(secs)
                    }
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
        let can_reply =
            matches!(step_opts.wait, crate::engine::pkg::WaitMode::OneShot(_)) || is_listen;
        if has_reply_extract && !can_reply {
            fail_step(&mut w, &t!("engine.recipe_extract_needs_wait"))?;
            total_failed += 1;
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
                continue;
            }
        };
        // 发送/监听共用的收集容器与标题
        let mut replies: Vec<Vec<u8>> = Vec::new();
        let mut sent_bytes: Vec<Vec<u8>> = Vec::new();
        // listen 步骤的对端（UDP 监听；`reply.peer.*` extract 用）
        let mut listen_peer: Option<std::net::SocketAddr> = None;
        let header = format!(
            "step {}/{}  {}",
            i + 1,
            recipe.steps.len(),
            step.pkg.display()
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
            m.insert("total".into(), json!(recipe.steps.len()));
            m.insert("pkt".into(), json!(step.pkg.display().to_string()));
            m.insert(
                "wait".into(),
                match step_opts.wait {
                    crate::engine::pkg::WaitMode::OneShot(s) => json!(s),
                    crate::engine::pkg::WaitMode::Continuous => json!("continuous"),
                    crate::engine::pkg::WaitMode::Off => json!(null),
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
            let matcher =
                packet_dsl::Matcher::build(&spec, Some(&module), &step_params, &globals, false)
                    .map_err(|d| anyhow::anyhow!("{d}"))?;
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
            // 监听简报：在监听什么（地址/接口）+ 匹配规则（sniffer 摘要）——文案走 i18n
            if !json && !opts.summary {
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
            // 持续监听（wait 无值）无超时；`listen_once` 内部轮询 Ctrl+C
            let timeout: Option<Duration> = None;
            // 命中第一个匹配包即返回（replies 供 extract）；对端供 reply.peer.* 取值
            let mut listen_reply: Option<Vec<u8>> = None;
            match mode {
                super::SendMode::Payload => {
                    match super::listen::listen_udp_once(
                        &module,
                        &step_params,
                        &globals,
                        &matcher,
                        &step_opts,
                        timeout,
                    ) {
                        Ok(Some((b, fields, peer))) => {
                            listen_matched(&mut w, opts, &b, &fields, Some(&peer))?;
                            listen_peer = Some(peer);
                            listen_reply = Some(b);
                        }
                        Ok(None) => {}
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
                            continue;
                        }
                    }
                }
                super::SendMode::Raw { iface } => {
                    match super::listen_raw::listen_raw_once(
                        Arc::new(module.clone()),
                        Arc::new(step_params.clone()),
                        Arc::new(globals.clone()),
                        Arc::new(matcher),
                        iface.as_deref(),
                        timeout,
                    ) {
                        Ok(Some(b)) => {
                            listen_matched(&mut w, opts, &b, &[], None)?;
                            listen_reply = Some(b);
                        }
                        Ok(None) => {}
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
                            continue;
                        }
                    }
                }
            }
            let Some(hit) = listen_reply else {
                fail_step(&mut w, &t!("engine.recipe_listen_interrupted"))?;
                total_failed += 1;
                continue;
            };
            replies.push(hit);
        }
        // 非 listen：解析来源（send_module 与 on_timeout retry 重发共用）
        let sources = if is_listen {
            Vec::new()
        } else {
            match packet_dsl::resolve_sources_with_globals(&module, &step_params, &globals) {
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
                    for rb in &replies {
                        match apply_extract(
                            Some(&module),
                            &mut globals,
                            &reply_extracts,
                            &step_params,
                            None,
                            Some(rb),
                            listen_peer,
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
                        total = recipe.steps.len(),
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
                        total = recipe.steps.len()
                    )
                ));
            }
        }
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
        m.insert("steps".into(), json!(recipe.steps.len()));
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
                steps = recipe.steps.len(),
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
fn apply_extract(
    module: Option<&packet_dsl::Module>,
    globals: &mut packet_dsl::Globals,
    extracts: &[&crate::engine::recipe::Extract],
    params: &packet_dsl::Params,
    sent_bytes: Option<&[u8]>,
    reply_bytes: Option<&[u8]>,
    // listen 步骤的对端地址（`reply.peer.*` 来源用；非 listen 步骤为 None）。
    peer: Option<std::net::SocketAddr>,
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
                let v =
                    packet_dsl::eval_extract_value(module, params, globals, &reply_access, expr)
                        .map_err(|d| {
                            anyhow::anyhow!(
                                "{}",
                                t!("engine.recipe_expr_fail", line = e.line, err = d)
                            )
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
/// 供配方 `extract` 的 `from:` 表达式与 `packet --listen --raw` 的应答模板共用。
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

    /// 解析：`packet:` 键 + `wait:` 三态（无值 = 持续监听 / 秒数 = 发后等一个应答 /
    /// 不写 = 纯发送，与 CLI `--wait` 同语义）。
    #[test]
    fn recipe_parse_packet_and_wait_three_state() {
        let dir = std::env::temp_dir().join(format!("prping-parse-wait-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pktl = dir.join("r.pktl");
        std::fs::write(
            &pktl,
            "recipe:\n- packet: a.pkt\n  wait: 5\n- packet: b.pkt\n  wait:\n- c.pkt\n",
        )
        .unwrap();
        let r = crate::engine::recipe::parse(&pktl).unwrap();
        assert_eq!(r.steps.len(), 3);
        assert_eq!(r.steps[0].pkg.file_name().unwrap(), "a.pkt");
        assert_eq!(
            r.steps[0].wait,
            Some(crate::engine::pkg::WaitMode::OneShot(5.0))
        );
        assert_eq!(r.steps[1].pkg.file_name().unwrap(), "b.pkt");
        assert_eq!(
            r.steps[1].wait,
            Some(crate::engine::pkg::WaitMode::Continuous)
        );
        assert_eq!(r.steps[2].pkg.file_name().unwrap(), "c.pkt");
        assert!(r.steps[2].wait.is_none());
    }

    /// 解析：`on_timeout: 文件`；`wait:` 其他负数报错。
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
        match &r.steps[0].on_timeout {
            Some(crate::engine::recipe::OnTimeout::Packet(p)) => {
                assert_eq!(p.file_name().unwrap().to_string_lossy(), "fb.pkt")
            }
            other => panic!("应解析为 Packet，得到 {other:?}"),
        }
        assert_eq!(
            r.steps[0].wait,
            Some(crate::engine::pkg::WaitMode::OneShot(2.0))
        );
        // 任意负数 = 无限等待（wait < 0 即可）
        std::fs::write(&pktl, "recipe:\n- packet: a.pkt\n  wait: -2\n").unwrap();
        let r = crate::engine::recipe::parse(&pktl).unwrap();
        assert_eq!(
            r.steps[0].wait,
            Some(crate::engine::pkg::WaitMode::Continuous),
            "wait: -2（任意负数）= 无限等待"
        );
    }

    /// 解析：`wait:` 非法值报错；`pkg:` 旧键明确报错。
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
        // 1) server / client 配方解析
        let server = crate::engine::recipe::parse(&ex.join("server.pktl")).unwrap();
        // 显式两组 listen+reply（pktl 可含任意多包）：4 步
        assert_eq!(server.steps.len(), 4);
        assert_eq!(
            server.steps[0].wait,
            Some(crate::engine::pkg::WaitMode::Continuous),
            "server 步骤 1 = wait 无值（持续监听）"
        );
        let client = crate::engine::recipe::parse(&ex.join("client.pktl")).unwrap();
        assert_eq!(client.steps.len(), 2);
        // 2) client req1.pkt 构造 echo request 帧（id=0x1234, seq=1, payload "hello"）
        let req1_src = std::fs::read_to_string(ex.join("req1.pkt")).unwrap();
        let rm = packet_dsl::semantic::parse_str("t", &req1_src).unwrap();
        let built = packet_dsl::resolve(&rm).unwrap();
        let frame = packet_dsl::DefaultSerializer::new()
            .serialize(&built.packets[0])
            .unwrap();
        // 3) server 步骤 1 的 extract 应用到匹配帧 → global
        let mut globals = packet_dsl::Globals::new();
        let extract_refs: Vec<&crate::engine::recipe::Extract> =
            server.steps[0].extract.iter().collect();
        apply_extract(
            Some(&rm),
            &mut globals,
            &extract_refs,
            &packet_dsl::Params::new(),
            None,
            Some(&frame),
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
        // 4) server 步骤 2 reply.pkt 用 global 求值 → echo reply
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
        let mut cglobals = packet_dsl::Globals::new();
        let cid_refs: Vec<&crate::engine::recipe::Extract> =
            client.steps[0].extract.iter().collect();
        apply_extract(
            Some(&rm),
            &mut cglobals,
            &cid_refs,
            &packet_dsl::Params::new(),
            None,
            Some(&reply),
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
        let extract_refs2: Vec<&crate::engine::recipe::Extract> =
            server.steps[0].extract.iter().collect();
        apply_extract(
            Some(&r2m),
            &mut globals2,
            &extract_refs2,
            &packet_dsl::Params::new(),
            None,
            Some(&req2),
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
        assert_eq!(r.steps[0].count, Some(3));
        assert!(r.steps[1].count.is_none());
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
                r.steps[0].on_timeout,
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
                r.steps[0].on_timeout,
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

    /// 集成：配方步骤 `wait:`（无值 = 持续监听，与 CLI 裸 `--wait` 同语义）匹配 DNS
    /// 查询 → extract 匹配包字段 → 后续步骤**触发发包**（应答回客户端）。
    /// 字节级回环，无 root 依赖。
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
                "global:\n- tid\n- cport\nrecipe:\n- packet: listen.pkt\n  wait:\n  params: port={port}\n  extract:\n  - name: tid\n    from: reply.dns.id\n    as: int\n  - name: cport\n    from: reply.peer.port\n    as: int\n- packet: trigger.pkt\n"
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
        res.expect("配方应成功完成（listen 命中 → extract → 触发发包）");
    }
}
