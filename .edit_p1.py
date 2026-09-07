from pathlib import Path

def sub(path, old, new, tag, expect=1):
    p = Path(path)
    s = p.read_text(encoding="utf-8")
    assert s.count(old) == expect, tag + " count=" + str(s.count(old))
    p.write_text(s.replace(old, new), encoding="utf-8")

PK = "crates/prping-core/src/engine/pkg/recipe.rs"

# A) desugar: stage_info + rule tags + mismatch segment
sub(PK, """    let mut steps: Vec<crate::engine::recipe::Step> = Vec::new();
    let mut serve_stage = 0usize;""", """    let mut steps: Vec<crate::engine::recipe::Step> = Vec::new();
    let mut serve_stage = 0usize;
    // 阶段 id → 执行期信息（规则表 + on_mismatch 有无）：分派监听按需取用
    let mut stage_info: std::collections::HashMap<usize, StageInfo> =
        std::collections::HashMap::new();""", "desugar-head")
sub(PK, """                    first: false,
                    last: false,
                    line: serve.line,
                };""", """                    first: false,
                    last: false,
                    rule: None,
                    line: serve.line,
                };""", "base-ctx")
sub(PK, """                let mut block: Vec<crate::engine::recipe::Step> = Vec::new();
                for rule in &serve.rules {
                    expand_serve_rule(rule, &base, &mut block);
                }""", """                let mut block: Vec<crate::engine::recipe::Step> = Vec::new();
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
                }""", "desugar-rules")

# B) expand_serve_rule rework
sub(PK, """/// serve 规则 → 扁平步骤（监听步骤 + handler 递归展开；全部附加同一 LoopCtx）。
fn expand_serve_rule(
    rule: &crate::engine::recipe::ServeRule,
    base: &crate::engine::recipe::LoopCtx,
    out: &mut Vec<crate::engine::recipe::Step>,
) {
    use crate::engine::recipe::ServeItem;""", """/// serve 规则 → 扁平步骤（监听步骤 + handler 递归展开；全部附加同一 LoopCtx）。
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
    use crate::engine::recipe::ServeItem;""", "expand-sig")
sub(PK, """    // 监听步骤：wait 负数哨兵（-1.0）= 监听（执行器 `is_listen` 判定）——不发送，
    // 用规则监听源的 sniffer 匹配命中包，规则 extract 命中取值写 global
    out.push(crate::engine::recipe::Step {
        pkg: rule.packet.clone(),
        wait: Some(-1.0),
        on_timeout: None,
        count: None,
        delay: None,
        raw: rule.raw.clone(),
        params: rule.params.clone(),
        extract: rule.extract.clone(),
        on_error: OnError::Stop,
        line: rule.line,
        loop_ctx: Some(base.clone()),
    });""", """    // 监听步骤：wait 负数哨兵（-1.0）= 监听（执行器 `is_listen` 判定）——不发送，
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
    }""", "expand-listen")
sub(PK, """            ServeItem::Step(s) => {
                let mut s = s.clone();
                s.loop_ctx = Some(base.clone());
                out.push(s);
            }
            // 嵌套 on_recv：监听步骤 + 其 handler 递归展开（同阶段同一 LoopCtx）
            ServeItem::OnRecv(nested) => expand_serve_rule(nested, base, out),
        }
    }
}""", """            ServeItem::Step(s) => {
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
}""", "expand-body")

# C) StageInfo + LoopRun
sub(PK, """/// loop 块运行态（块 id → 迭代计数 / until 命中标记）。
#[derive(Default)]
struct LoopRun {
    /// 已开始的轮数（1 起：闸门放行时 +1）。
    iter: usize,
    /// until 谓词已命中（本轮结束后收工）。
    until_hit: bool,
}""", """/// serve 阶段执行期信息（阶段 id → 规则表 + on_mismatch 有无；脱糖收集）。
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
}""", "stageinfo-looprun")

# D) label + delay text + JSON renames (item 5)
sub(PK, "format!(\"  [loop {} r{iter}{bound}]\", ctx.id + 1)", "format!(\"  [serve {} r{iter}{bound}]\", ctx.id + 1)", "loop-tag")
sub(PK, "\"{}delay {secs}s before loop {} round {} ...\"", "\"{}delay {secs}s before serve {} round {} ...\"", "delay-text")
sub(PK, """            m.insert(
                "loop".into(),
                json!({""", """            m.insert(
                "serve".into(),
                json!({""", "step-json")
sub(PK, """        m.insert("type".into(), json!("loop_end"));
        m.insert("loop".into(), json!(id + 1));""", """        m.insert("type".into(), json!("serve_end"));
        m.insert("serve".into(), json!(id + 1));""", "end-json")
sub(PK, "/// loop 块收工打印（`--json`：`{\"type\":\"loop_end\",...}` 行；人读：青色一行，", "/// serve 阶段收工打印（`--json`：`{\"type\":\"serve_end\",...}` 行；人读：青色一行，", "end-doc")

# E) collect_recipe_pkt_params: mismatch segment
sub(PK, """            crate::engine::recipe::RecipeItem::Serve(serve) => {
                for rule in &serve.rules {
                    walk_rule(rule, &mut out);
                }
            }""", """            crate::engine::recipe::RecipeItem::Serve(serve) => {
                for rule in &serve.rules {
                    walk_rule(rule, &mut out);
                }
                if let Some(items) = &serve.on_mismatch {
                    for item in items {
                        match item {
                            crate::engine::recipe::ServeItem::Step(s) => push(&s.pkg, &mut out),
                            crate::engine::recipe::ServeItem::OnRecv(nested) => walk_rule(nested, &mut out),
                        }
                    }
                }
            }""", "collect-mismatch")
print("pkg/recipe.rs script1 OK")