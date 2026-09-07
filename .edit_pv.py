from pathlib import Path

def sub(path, old, new, tag, expect=1):
    p = Path(path)
    s = p.read_text(encoding="utf-8")
    assert s.count(old) == expect, tag + " count=" + str(s.count(old))
    p.write_text(s.replace(old, new), encoding="utf-8")

RC = "crates/prping-core/src/engine/recipe.rs"

# 1) mismatch var + in_mismatch flag
sub(RC, """    let mut mismatch: Option<Vec<ServeItem>> = None;""", """    let mut mismatch: Option<Vec<ServeItem>> = None;
    let mut in_mismatch = false;""", "in-mismatch")

# 2) opts-mode "- " handling: mismatch items before until predicates
sub(RC, """            if let Some(pred) = trimmed.strip_prefix("- ") {
                if !in_until {
                    return Err(err(ln, t!("engine.parse_serve_item_no_until")));
                }""", """            if let Some(pred) = trimmed.strip_prefix("- ") {
                if in_mismatch {
                    // on_mismatch 段条目：步骤 / 嵌套 on_recv（语法与 handler
                    // 一致；条目缩进 = 各条目自身缩进，键行（rules: 等）自然
                    // 退出段——parse_step_block/on_recv_body 消费条目整块）
                    let item_indent = indent;
                    if let Some(onrecv_rest) = pred.strip_prefix("on_recv:") {
                        if !onrecv_rest.trim().is_empty() {
                            return Err(err(ln, t!("engine.parse_on_recv_inline")));
                        }
                        *i += 1;
                        let onrecv = parse_on_recv_body(lines, i, path, ln, item_indent, 1)?;
                        mismatch
                            .get_or_insert_with(Vec::new)
                            .push(ServeItem::OnRecv(Box::new(onrecv)));
                    } else {
                        let step = parse_step_block(lines, i, path, pred.trim(), ln, item_indent)?;
                        mismatch
                            .get_or_insert_with(Vec::new)
                            .push(ServeItem::Step(step));
                    }
                    continue;
                }
                if !in_until {
                    return Err(err(ln, t!("engine.parse_serve_item_no_until")));
                }""", "mismatch-items")

# 3) on_mismatch arm: defer item consumption
sub(RC, """                "on_mismatch" => {
                    // 未命中处理段：条目写在后续 `- ` 行（handler 同款语法）；
                    // 不接受内联值；只允许出现一次
                    if !val.is_empty() {
                        return Err(err(ln, t!("engine.parse_mismatch_inline")));
                    }
                    if mismatch.is_some() {
                        return Err(err(ln, t!("engine.parse_mismatch_dup")));
                    }
                    *i += 1;
                    mismatch = Some(parse_handler_items(lines, i, path, serve_indent, 1)?);
                }""", """                "on_mismatch" => {
                    // 未命中处理段：条目写在后续 `- ` 行（handler 同款语法，
                    // 由上方 opts 模式的 "- " 分支消费）；不接受内联值；
                    // 只允许出现一次
                    if !val.is_empty() {
                        return Err(err(ln, t!("engine.parse_mismatch_inline")));
                    }
                    if in_mismatch {
                        return Err(err(ln, t!("engine.parse_mismatch_dup")));
                    }
                    in_mismatch = true;
                }""", "mismatch-arm-v2")

# 4) empty-segment checks (rules: entry + serve body end)
sub(RC, """                "rules" => {
                    if !val.is_empty() {
                        return Err(err(ln, t!("engine.parse_rules_inline")));
                    }
                    in_rules = true;
                }""", """                "rules" => {
                    if !val.is_empty() {
                        return Err(err(ln, t!("engine.parse_rules_inline")));
                    }
                    if in_mismatch && mismatch.is_none() {
                        return Err(err(ln, t!("engine.parse_mismatch_empty")));
                    }
                    in_rules = true;
                }""", "empty-check-rules")
sub(RC, """    if in_mismatch && mismatch.is_none() {
        return Err(err(line_no, t!("engine.parse_mismatch_empty")));
    }
    Ok(Serve {""", """    Ok(Serve {""", "noop")
sub(RC, """    Ok(Serve {
        max,""", """    if in_mismatch && mismatch.is_none() {
        return Err(err(line_no, t!("engine.parse_mismatch_empty")));
    }
    Ok(Serve {
        max,""", "empty-check-end")
print("parser v2 OK")