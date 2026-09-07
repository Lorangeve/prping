from pathlib import Path

def sub(path, old, new, tag):
    p = Path(path)
    s = p.read_text(encoding="utf-8")
    assert s.count(old) == 1, tag + " count=" + str(s.count(old))
    p.write_text(s.replace(old, new), encoding="utf-8")

EV = "crates/packet-dsl/src/eval.rs"

// ---- round()/hits() dispatch in eval_value_call ----
sub(EV, """        match name {
            // `reply("层", "字段")`：读取当前回包的反解字段（配方 extract 的""".replace("@", chr(39)), """        match name {
            // `round()` / `hits()`：serve 阶段轮次原语（宿主注入当前轮次上下文）。
            // 仅配方 serve 阶段的 matcher/until/extract/阶段内步骤表达式求值可用；
            // 其余上下文按 0 参调用给出可操作报错（与 reply 同策略：用户函数
            // 撞名时非 0 参调用仍走用户函数分支）。
            "round" | "hits" => {
                if let Some(sc) = self.serve {
                    if !args.is_empty() {
                        return Err(Diagnostic::at(
                            format!("`{name}` 不接受参数（serve 轮次原语无参调用）"),
                            span,
                        ));
                    }
                    return Ok(Value::Int(if name == "round" {
                        sc.round as i64
                    } else {
                        sc.hits as i64
                    }));
                }
                if args.is_empty() {
                    return Err(Diagnostic {
                        kind: crate::diag::DiagnosticKind::ReplyOutsideRecipe,
                        ..Diagnostic::at(
                            "`round()`/`hits()` 只能在配方 serve 阶段的 matcher/until/extract/阶段内步骤表达式中使用（本上下文没有 serve 轮次）".to_string(),
                            span,
                        )
                    });
                }
                self.eval_user_value_func(module, name, args, span)
            }
            // `reply("层", "字段")`：读取当前回包的反解字段（配方 extract 的""".replace("@", chr(39)), "dispatch")

// ---- lib.rs exports ----
LB = "crates/packet-dsl/src/lib.rs"
sub(LB, "Globals, PacketSource, ReplyAccess, eval_extract_value,", "Globals, PacketSource, ReplyAccess, ServeCtx, eval_extract_value, eval_extract_value_ctx,", "lib-1")
sub(LB, "eval_sniffer_value_with_globals, resolve,", "eval_sniffer_value_ctx, eval_sniffer_value_with_globals, resolve,", "lib-2")
sub(LB, "resolve_sources_with_params, resolve_sources_with_reply, resolve_with_globals,", "resolve_sources_with_params, resolve_sources_with_reply, resolve_sources_with_serve, resolve_with_globals,", "lib-3")
print("eval.rs dispatch + lib.rs exports OK")