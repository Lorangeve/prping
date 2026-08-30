// CodeMirror 6 编辑器组装：pktlang 高亮 + LSP 三件套（lint / 补全 / 悬停）。

import { autocompletion, closeBrackets } from "@codemirror/autocomplete";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { bracketMatching, foldGutter, indentOnInput, syntaxHighlighting, defaultHighlightStyle } from "@codemirror/language";
import { setDiagnostics, type Diagnostic } from "@codemirror/lint";
import { highlightSelectionMatches, search } from "@codemirror/search";
import { EditorState, type Extension } from "@codemirror/state";
import {
  EditorView,
  drawSelection,
  dropCursor,
  highlightActiveLine,
  highlightActiveLineGutter,
  highlightSpecialChars,
  hoverTooltip,
  keymap,
  lineNumbers,
  tooltips,
} from "@codemirror/view";
import { pktlangLanguage } from "./pktlang";

/** 深色主题（与面板配色一致，不引外部主题依赖）。 */
const theme = EditorView.theme(
  {
    "&": { color: "#d4d4d4", backgroundColor: "#14161a", height: "100%" },
    ".cm-content": { caretColor: "#61afef", fontFamily: "'SF Mono', Menlo, Consolas, monospace" },
    ".cm-scroller": { fontFamily: "'SF Mono', Menlo, Consolas, monospace", lineHeight: "1.6" },
    ".cm-gutters": { backgroundColor: "#14161a", color: "#5c6370", border: "none" },
    ".cm-activeLineGutter": { backgroundColor: "#1d2026" },
    ".cm-activeLine": { backgroundColor: "#1d2026" },
    ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "#2c313c" },
    ".cm-cursor": { borderLeftColor: "#61afef" },
    ".cm-tooltip": {
      backgroundColor: "#1d2026",
      border: "1px solid #333842",
      borderRadius: "6px",
      overflow: "hidden",
      maxWidth: "460px",
    },
    ".cm-tooltip-autocomplete ul li[aria-selected]": { backgroundColor: "#2c313c" },
    ".hover-doc": { padding: "6px 10px", whiteSpace: "pre-wrap", fontSize: "12px" },
  },
  { dark: true },
);

const highlight = syntaxHighlighting(defaultHighlightStyle, { fallback: true });

export interface EditorOpts {
  doc: string;
  /** 文档变更（防抖由调用方处理）。 */
  onUpdate: (text: string) => void;
  /** LSP 补全源（返回 CompletionList 或 null）。 */
  completion: (pos: { line: number; character: number }) => Promise<any>;
  /** LSP 悬停源（返回 {contents} 或 null）。 */
  hover: (pos: { line: number; character: number }) => Promise<any>;
}

export function createEditor(parent: HTMLElement, opts: EditorOpts): EditorView {
  const cmCompletion = autocompletion({
    override: [
      async (ctx) => {
        const line = ctx.state.doc.lineAt(ctx.pos);
        const result = await opts.completion({
          line: line.number - 1,
          character: ctx.pos - line.from,
        });
        if (!result) return null;
        // LSP CompletionList → CM CompletionResult（insertText 如 `tcp()` 原样展开）
        return {
          from: ctx.matchBefore(/[A-Za-z0-9_]/)?.from ?? ctx.pos,
          options: (result.items ?? []).map((item: any) => ({
            label: item.label,
            detail: item.detail ?? "",
            info: item.documentation?.value ?? item.documentation ?? undefined,
            type: item.kind === 3 ? "function" : item.kind === 14 ? "keyword" : "variable",
            apply: item.insertText ?? item.label,
          })),
        };
      },
    ],
  });

  const cmHover = hoverTooltip(
    async (view, pos) => {
      const line = view.state.doc.lineAt(pos);
      const result = await opts.hover({
        line: line.number - 1,
        character: pos - line.from,
      });
      if (!result || result.contents == null) return null;
      const value =
        typeof result.contents === "string" ? result.contents : (result.contents.value ?? "");
      if (!value) return null;
      // 极简展示：按文本渲染（保留换行），Markdown 修饰丢弃
      return {
        pos,
        create: () => {
          const dom = document.createElement("div");
          dom.className = "hover-doc";
          dom.textContent = value;
          return { dom };
        },
      };
    },
    { hoverTime: 400 },
  );

  const updateListener = EditorView.updateListener.of((u) => {
    if (u.docChanged) opts.onUpdate(u.state.doc.toString());
  });

  const extensions: Extension[] = [
    lineNumbers(),
    highlightActiveLineGutter(),
    highlightSpecialChars(),
    history(),
    foldGutter(),
    drawSelection(),
    dropCursor(),
    EditorState.allowMultipleSelections.of(true),
    indentOnInput(),
    bracketMatching(),
    closeBrackets(),
    highlightActiveLine(),
    highlightSelectionMatches(),
    search({ top: true }),
    keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
    pktlangLanguage,
    highlight,
    theme,
    tooltips({ position: "absolute" }),
    cmCompletion,
    cmHover,
    updateListener,
  ];

  return new EditorView({
    state: EditorState.create({ doc: opts.doc, extensions }),
    parent,
  });
}

/** LSP 诊断（0-based 行列）→ CM lint 诊断并推送。 */
export function applyDiagnostics(
  view: EditorView,
  diags: { line: number; character: number; message: string; severity: number }[],
): void {
  const cmDiags: Diagnostic[] = diags
    .map((d) => {
      const doc = view.state.doc;
      const lineInfo = doc.line(Math.min(Math.max(d.line + 1, 1), doc.lines));
      const from = Math.min(lineInfo.from + d.character, lineInfo.to);
      const to = Math.min(from + 1, lineInfo.to);
      return {
        from,
        to,
        message: d.message,
        severity: d.severity <= 1 ? ("error" as const) : ("warning" as const),
      };
    })
    .filter((d) => d.to > d.from || d.from < view.state.doc.length);
  view.dispatch(setDiagnostics(view.state, cmDiags));
}

/** 替换整个文档（打开库文件时）。 */
export function setDoc(view: EditorView, text: string): void {
  view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: text } });
}
