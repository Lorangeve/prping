from pathlib import Path

def sub(path, old, new, tag, expect=1):
    p = Path(path)
    s = p.read_text(encoding="utf-8")
    assert s.count(old) == expect, tag + " count=" + str(s.count(old))
    p.write_text(s.replace(old, new), encoding="utf-8")

PK = "crates/prping-core/src/engine/pkg/recipe.rs"

sub(PK, "                    \"loop\".into(),", "                    \"serve\".into(),", "step-json")
sub(PK, """        m.insert("type".into(), json!("loop_end"));
        m.insert("loop".into(), json!(id + 1));""", """        m.insert("type".into(), json!("serve_end"));
        m.insert("serve".into(), json!(id + 1));""", "end-json")
sub(PK, "/// loop 块收工打印（`--json`：`{\"type\":\"loop_end\",...}` 行；人读：青色一行，", "/// serve 阶段收工打印（`--json`：`{\"type\":\"serve_end\",...}` 行；人读：青色一行，", "end-doc")
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
print("pkg/recipe.rs script1-remainder OK")