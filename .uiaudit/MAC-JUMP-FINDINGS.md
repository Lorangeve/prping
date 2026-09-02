# 「点 mac 跳到 random_mac」调查记录

## 结论（当前构建 @16:40 重建后）

**未能复现。** 以下全部路径实测均正确跳到 `bytes.pkt L91 func mac(s)`：

| 场景 | 结果 |
|------|------|
| headers.pkt L53 `concat(mac(dst_mac), …)` 点 `mac` | ✓ bytes.pkt L91 |
| headers.pkt L95 arp `mac(sha)` 点 `mac` | ✓ bytes.pkt L91 |
| 自建文件（无 import）`mac("aa:bb:…")` 调用处 | ✓ bytes.pkt L91 |
| bytes.pkt L73 注释 `mac(rand_mac())` 点 `mac`（真实 UI 精确 span） | ✓ L91 |
| bytes.pkt L73 点 `rand_mac` | ✓ L74 `func rand_mac`（正确） |
| ssh.pkt L34 `@param mac` 注释 | ✓ bytes.pkt L91 |
| emoji（UTF-16 代理对）+ 中文在同一行 `mac` 前面 | ✓ bytes.pkt L91 |
| bytes.pkt Outline 面板点 mac / rand_mac | ✓ L91 / L74 |
| hover `mac` | ✓ 显示 `func mac(s)` 文档 |

## 链路核查（全部精确匹配，无模糊/子串逻辑）

- `lsp.rs definition()`：`word_at`（[A-Za-z0-9_]）→ `Module::definition_of`（名字全等）→ 库兜底 `lib_functions_cached().find(name == word)`（全等）+ `file_name_span`（AST 语句名全等）
- `semantic.rs definition_of`：defs/funcs/protos 全等 → scope（构建期全等插入）→ export 行兜底
- `utf16_col_to_byte`：代理对按 2 units 计，实测无漂移

## 已知的「像跳错」情形

1. **`mac(rand_mac())` 相邻 token**（bytes.pkt L73 注释）：`mac` 与 `rand_mac` 只隔一个 `(`，`mac` 仅 3 字符宽——点偏到 `rand_` 就会跳 L74 `func rand_mac`。这是正确行为但极易误读。
2. **旧会话/旧构建**：本次会话中服务端/前端多次重建重启；若页面是旧前端（WS 会 403 断开）或旧二进制（QA 期 LSP 线程可能已死），跳转行为不可信。
3. **dst_mac / src_mac 点了不跳**（返回 null）是正确的——它们是 proto 参数，无定义体。

## 探针留存

- `.uiaudit/macdef.mjs` / `macdef2.mjs` / `macdef3.mjs` / `sshmac.mjs` / `utf16probe.mjs`（原始 LSP 复测）
- `.uiaudit/macui2.py` / `macui3.py`（真实 UI 点击 / Outline / hover）
- 截图：`mac-click-final.png`（headers mac → bytes L91 正确落点）
