from pathlib import Path

def sub(path, old, new, tag, expect=1):
    p = Path(path)
    s = p.read_text(encoding="utf-8")
    assert s.count(old) == expect, tag + " count=" + str(s.count(old))
    p.write_text(s.replace(old, new), encoding="utf-8")

OLD_EM = """  `on_mismatch:`（未命中处理段，条目写在后续 `- ` 行，语法与 handler 一致；
  收到的包不匹配任何规则且不匹配 until 时执行——**不消耗服务轮次**，执行完
  重新监听；空段/内联值/重复段非法）/
"""
NEW_EM = """  `on_mismatch:`（未命中处理段，条目写在后续 `- ` 行，语法与 handler 一致；
  收到的包不匹配任何规则且不匹配 until 时执行——**不消耗服务轮次**，执行完
  重新监听；段内步骤的 `reply.*`/`reply.peer.*` 取**触发未命中的包**与其对端
  （extract 无需本步 wait）；空段/内联值/重复段非法）/
"""
sub("docs/claude-rules/engine.md", OLD_EM, NEW_EM, "em")

OLD_ZH = """  **`on_mismatch:` 段**在未命中包上触发且**不消耗服务轮次**（max 只数真实命中）。
"""
NEW_ZH = """  **`on_mismatch:` 段**在未命中包上触发且**不消耗服务轮次**（max 只数真实命中）——
  段内步骤的 `reply.*`/`reply.peer.*` 取**触发未命中的包**与其对端（可据此把
  协议错误应答发回发起方；extract 无需本步 `wait:`）。
"""
sub("docs/manual-zh.md", OLD_ZH, NEW_ZH, "zh")

OLD_EN = """  segment fires on unmatched packets and **consumes no service round** (max
  counts real hits only).
"""
NEW_EN = """  segment fires on unmatched packets and **consumes no service round** (max
  counts real hits only); its steps read **the packet that triggered the
  mismatch** via `reply.*`/`reply.peer.*` (e.g. to answer the sender with a
  protocol-error response; the extract needs no `wait:` on the step).
"""
sub("docs/manual-en.md", OLD_EN, NEW_EN, "en")
print("docs OK")