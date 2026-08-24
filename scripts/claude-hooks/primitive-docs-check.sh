#!/usr/bin/env bash
# 原语文档同步检查（Claude Code hook / 手动门禁）
#
# 校验链：eval.rs/registry.rs 分派原语 ⊆ registry.rs builtin_docs()（--eng --ls 与
# LSP 悬停/补全的展示源）⊆ GRAMMAR.md §4.6（语法可见面清单）。
# 缺 BuiltinDoc → `--eng --ls` / LSP 不显示该原语；缺 GRAMMAR.md → 规范缺条目。
#
# 用法：
#   hook 模式（默认）：stdin 收 Claude Code PostToolUse JSON——编辑原语源码
#     （registry/eval/tpl/parser/lexer/ast）时提醒同步清单并报告实际缺失；
#     编辑文档（GRAMMAR/DESIGN/README/CLAUDE/eng_lib）时只报告缺失。
#     stdout 输出 {"systemMessage": "..."}（空 = 无关文件，不打扰）。
#   --check 模式：无条件校验（CI / `just doc-sync-check`），违规退出码 1。
#
# 文件路径可用环境变量覆盖（测试用）：REG / EVAL / GRAMMAR。
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
REG="${REG:-$REPO/crates/packet-dsl/src/registry.rs}"
EVAL="${EVAL:-$REPO/crates/packet-dsl/src/eval.rs}"
GRAMMAR="${GRAMMAR:-$REPO/crates/packet-dsl/GRAMMAR.md}"

# ── 名称提取 ────────────────────────────────────────────────
# builtin_docs：registry.rs 的 `name: "X"`（--ls/LSP 展示源）
docs() {
  grep -oE 'name: "[a-z0-9_]+"' "$REG" | sed 's/name: "//;s/"//'
}
# 值分派：eval.rs eval_value_call 顶层 match 分支（12 空格缩进；嵌套 match 更深，排除）
value_dispatch() {
  awk '/fn eval_value_call/,/^    }$/' "$EVAL" \
    | grep -oE '^ {12}"[a-z0-9_]+"(\s*\|\s*"[a-z0-9_]+")*\s*=>' \
    | grep -oE '"[a-z0-9_]+"' | tr -d '"'
}
# 层分派：registry.rs build_layers 分支
layer_dispatch() {
  awk '/pub fn build_layers/,/^}/' "$REG" \
    | grep -oE '^\s*"[a-z0-9_]+"\s*=>' | grep -oE '"[a-z0-9_]+"' | tr -d '"'
}

# ── 校验 ────────────────────────────────────────────────────
check() {
  local dispatch docs_sorted missing_docs stale_docs missing_grammar n
  # global 与 params 同属 eval_value Call 臂的特判原语（不经 eval_value_call match），
  # 与 params 一样在脚本里显式并入分派集合
  dispatch="$( { value_dispatch; layer_dispatch; printf '%s\n' params global; } | sort -u)"
  docs_sorted="$(docs | sort -u)"
  # 1) --ls 完整性：分派原语必须有 BuiltinDoc
  missing_docs="$(comm -23 <(printf '%s\n' "$dispatch") <(printf '%s\n' "$docs_sorted"))"
  # 2) 文档残留：BuiltinDoc 但已无分派
  stale_docs="$(comm -13 <(printf '%s\n' "$dispatch") <(printf '%s\n' "$docs_sorted"))"
  # 3) GRAMMAR.md §4.6：builtin_docs 全部列出
  missing_grammar=""
  while IFS= read -r n; do
    [ -z "$n" ] && continue
    grep -qw -- "$n" "$GRAMMAR" || missing_grammar="$missing_grammar $n"
  done <<< "$docs_sorted"

  MISSING_DOCS="$missing_docs"
  STALE_DOCS="$stale_docs"
  MISSING_GRAMMAR="${missing_grammar# }"
}

report() {
  local m="原语文档同步"
  if [ -z "$MISSING_DOCS" ] && [ -z "$STALE_DOCS" ] && [ -z "$MISSING_GRAMMAR" ]; then
    m="$m：✓ 全部一致（builtin_docs ↔ 分派 ↔ GRAMMAR.md §4.6）"
  else
    m="$m：✗ 有缺口"
    [ -n "$MISSING_DOCS" ] && m="$m\n- 分派但缺 BuiltinDoc（--eng --ls / LSP 不显示）：$MISSING_DOCS"
    [ -n "$MISSING_GRAMMAR" ] && m="$m\n- 有 BuiltinDoc 但 GRAMMAR.md §4.6 未列出：$MISSING_GRAMMAR"
    [ -n "$STALE_DOCS" ] && m="$m\n- BuiltinDoc 已无分派（可能已移除原语）：$STALE_DOCS"
    m="$m\n改动原语必同步：registry.rs builtin_docs()（--eng --ls/LSP 源）、@packet-dsl/GRAMMAR.md §4.6、@packet-dsl/DESIGN.md §5/§6、docs/claude-rules/engine.md 原语清单"
  fi
  printf '%b' "$m"
}

check

if [ "${1:-}" = "--check" ]; then
  report
  echo
  if [ -n "$MISSING_DOCS$STALE_DOCS$MISSING_GRAMMAR" ]; then
    exit 1
  fi
  exit 0
fi

# ── Claude Code PostToolUse 模式 ─────────────────────────────
input="$(cat)"
fp="$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty' 2>/dev/null || true)"
[ -n "$fp" ] || exit 0
case "$fp" in
  *packet-dsl/src/registry.rs|*packet-dsl/src/eval.rs|*packet-dsl/src/tpl.rs|*packet-dsl/src/parser.rs|*packet-dsl/src/lexer.rs|*packet-dsl/src/ast.rs)
    m="$(report)"$'\n'"修改了原语源码：改动原语必同步 @packet-dsl/GRAMMAR.md §4.6、registry.rs builtin_docs()（--eng --ls/LSP 源）、@packet-dsl/DESIGN.md §5/§6、docs/claude-rules/engine.md 原语清单"
    ;;
  *packet-dsl/GRAMMAR.md|*packet-dsl/DESIGN.md|*packet-dsl/README.md|*CLAUDE.md|*docs/claude-rules/*.md|*eng_lib/bytes.pkt|*eng_lib/headers.pkt)
    m="$(report)"
    ;;
  *)
    exit 0
    ;;
esac
jq -n --arg m "$m" '{systemMessage: $m}'
