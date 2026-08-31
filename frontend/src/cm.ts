// CodeMirror 6 编辑器组装：pktlang 高亮 + LSP 三件套（lint / 补全 / 悬停）。
// 补全手感：validFor 本地过滤（免每键 LSP 往返）、( , = > [ 空格 - : . 输入即弹、
// 选中 name() / params("") 光标落点顺势弹下一级。上下文判定与候选排序由服务端
// 完成（层位/实参名位/值位/语句位各给该位合法且排好序的列表），前端只做渲染。

import { autocompletion, closeBrackets, startCompletion, type CompletionResult } from "@codemirror/autocomplete";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { bracketMatching, foldGutter, indentOnInput, syntaxHighlighting, defaultHighlightStyle } from "@codemirror/language";
import { setDiagnostics, type Diagnostic } from "@codemirror/lint";
import { highlightSelectionMatches, search } from "@codemirror/search";
import { Compartment, EditorState, type Text, type Extension } from "@codemirror/state";
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
import { renderMarkdown } from "./markdown";
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
    ".hover-doc": {
      padding: "8px 12px",
      fontSize: "12px",
      lineHeight: "1.55",
      maxHeight: "400px",
      overflowY: "auto",
      overscrollBehavior: "contain",
    },
    ".hover-doc::-webkit-scrollbar": { width: "8px" },
    ".hover-doc::-webkit-scrollbar-thumb": { backgroundColor: "#333842", borderRadius: "4px" },
    ".hover-doc::-webkit-scrollbar-track": { backgroundColor: "transparent" },
    ".hover-doc p": { margin: "0 0 6px", whiteSpace: "pre-wrap" },
    ".hover-doc :last-child": { marginBottom: "0" },
    ".hover-doc h1, .hover-doc h2, .hover-doc h3, .hover-doc h4, .hover-doc h5, .hover-doc h6": {
      margin: "2px 0 6px",
      fontSize: "12.5px",
      color: "#e8e8e8",
    },
    ".hover-doc ul": { margin: "0 0 6px", paddingLeft: "18px" },
    ".hover-doc li": { margin: "1px 0" },
    ".hover-doc code": {
      backgroundColor: "#2a2e37",
      borderRadius: "3px",
      padding: "1px 4px",
      fontFamily: "inherit",
      fontSize: "11.5px",
    },
    ".hover-doc pre": {
      backgroundColor: "#101216",
      border: "1px solid #333842",
      borderRadius: "4px",
      padding: "6px 8px",
      overflowX: "auto",
      margin: "0 0 6px",
    },
    ".hover-doc pre code": { backgroundColor: "transparent", padding: "0", fontSize: "11.5px" },
    ".hover-doc strong": { color: "#e8e8e8" },
    ".cm-completionInfo": {
      backgroundColor: "#1d2026",
      border: "1px solid #333842",
      borderRadius: "6px",
    },
  },
  { dark: true },
);

const highlight = syntaxHighlighting(defaultHighlightStyle, { fallback: true });

/** 可编辑开关（Compartment：库文件只读 / 工作区文件可写，切换不重建编辑器）。 */
const editableCompartment = new Compartment();

function editableExt(on: boolean): Extension {
  return [EditorView.editable.of(on), EditorState.readOnly.of(!on)];
}

/** 切换编辑器可编辑态（打开库文件 → false，工作区文件 → true）。 */
export function setEditable(view: EditorView, editable: boolean): void {
  view.dispatch({ effects: editableCompartment.reconfigure(editableExt(editable)) });
}

/** LSP documentation（MarkupContent | MarkedString | 数组）→ markdown 文本。 */
function docMarkdown(d: any): string {
  if (d == null) return "";
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map(docMarkdown).join("\n\n");
  return d.value ?? "";
}

/** 补全项 info：懒渲染——info 气泡出现时才把 markdown 转 HTML（renderMarkdown
 *  先整体转义，innerHTML 注入安全）。无文档返回 null 不弹气泡。 */
function infoRenderer(item: any): (() => Node) | null {
  const md = docMarkdown(item.documentation);
  if (!md) return null;
  return () => {
    const dom = document.createElement("div");
    dom.className = "hover-doc";
    dom.innerHTML = renderMarkdown(md);
    return dom;
  };
}

/** 光标是否在字符串字面量内（引号奇偶启发）：触发字符不弹窗防打扰。 */
function insideString(doc: Text, pos: number): boolean {
  const text = doc.sliceString(0, pos);
  return (text.match(/"/g)?.length ?? 0) % 2 === 1;
}

/** 光标是否处于 export: 列表位（export: 行冒号之后，或其 - 项续行）——该处语法上
 *  只接受裸名字（元件/函数），补全不应给 name() 调用。启发式：光标行含未写完的
 *  export: 项，或本身是 - 项且向上连续 - 行后紧跟 export: 行。 */
function inExportList(doc: Text, pos: number): boolean {
  const lines = doc.sliceString(0, pos).split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const t = lines[i].trim();
    if (i === lines.length - 1) {
      // 光标行：export: 之后（冒号后允许已有 - 项内容）
      if (/export\s*:/.test(t)) return true;
      if (t.startsWith("-")) continue;
      return false;
    }
    if (t.startsWith("-")) continue;
    if (/^export\s*:/.test(t)) return true;
    return false;
  }
  return false;
}

/** 光标前词起点（锚定行尾取尾部词段，行内任意位置的词都正确）。 */
function wordStart(doc: Text, lineFrom: number, pos: number): number {
  const before = doc.sliceString(lineFrom, pos);
  return pos - (/[A-Za-z0-9_]*$/.exec(before)?.[0].length ?? 0);
}

/** 光标是否处于 sniffer: 块内（sniffer: 行，或其 - 项续行）。服务端已做上下文
 *  补全（谓词/层名/字段），前端只负责空格触发与结果排序。 */
/** 光标是否处于 .pktl 配方列表位（global:/recipe: 段头之下）。服务端按位置返回
 *  段头/项形态/选项键/枚举值专属列表，前端只负责 `-` 与空格触发。 */
function inRecipeList(doc: Text, pos: number): boolean {
  const lines = doc.sliceString(0, pos).split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const t = lines[i].trim();
    if (t === "global:" || t === "recipe:") return true;
    if (t.startsWith("-")) continue;
    return false;
  }
  return false;
}

function inSnifferList(doc: Text, pos: number): boolean {
  const lines = doc.sliceString(0, pos).split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const t = lines[i].trim();
    if (/^sniffer\s*:/.test(t)) return true;
    if (t.startsWith("-")) continue;
    return false;
  }
  return false;
}

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
      async (ctx): Promise<CompletionResult | null> => {
        const line = ctx.state.doc.lineAt(ctx.pos);
        const result = await opts.completion({
          line: line.number - 1,
          character: ctx.pos - line.from,
        });
        if (!result) return null;
        // export: 列表位：只补作用域内裸名字（本地元件/函数优先）——该处不接受
        // name() 调用，带括号的 insertText 反而会写出非法语法
        if (inExportList(ctx.state.doc, ctx.pos)) {
          const tier = (it: any): number => {
            const d = it.detail ?? "";
            if (it.kind === 6 || it.kind === 9) return 1; // 本地元件/导出/模块默认
            if (it.kind === 3 && d.startsWith("func ") && !d.includes(" [")) return 2; // 本地函数
            if (d.includes(" [")) return 3; // 库导出（隐式在作用域，可转出口）
            return 4; // 其余（原语等——导出多半无效，沉底）
          };
          const nameOpts = (result.items ?? [])
            .filter((it: any) => it.kind === 3 || it.kind === 6 || it.kind === 9)
            .sort((a: any, b: any) => tier(a) - tier(b))
            .map((it: any) => ({
              label: it.label,
              detail: it.detail ?? "",
              info: infoRenderer(it),
              type: it.kind === 3 ? "function" : it.kind === 9 ? "namespace" : "variable",
              apply: it.label, // 裸名字——export 列表不接受调用
              boost: 40 - tier(it) * 10, // 保持 tier 顺序（CM 同分按字母重排）
            }));
          return {
            from: wordStart(ctx.state.doc, line.from, ctx.pos),
            options: nameOpts,
            validFor: /^[A-Za-z0-9_]*$/,
          };
        }
        // LSP CompletionList → CM CompletionResult。服务端已按位置给该位合法且
        // 排好序的候选（数组序 = sortText 分级），前端按数组序轻衰减 boost 保序
        //（CM 过滤同分按原序稳定）；该位无候选 → null 不弹窗
        const options = (result.items ?? []).map((item: any, i: number) => {
          const insert = item.insertText ?? item.label;
          // name() 形式：整体插入、光标落括号内，顺势弹参数补全；
          // params("") 形式：光标落引号内
          const fn = /^\s*([A-Za-z_][A-Za-z0-9_]*)\(\)$/.exec(insert);
          const fnStr = /^\s*([A-Za-z_][A-Za-z0-9_]*)\(""\)$/.exec(insert);
          return {
            label: item.label,
            detail: item.detail ?? "",
            info: infoRenderer(item),
            type:
              item.kind === 3
                ? "function"
                : item.kind === 14
                  ? "keyword"
                  : item.kind === 5
                    ? "property"
                    : item.kind === 9
                      ? "namespace"
                      : "variable",
            boost: Math.max(0, 20 - i * 0.2),
            apply: fn
              ? (view: EditorView, _c: unknown, from: number, to: number) => {
                  view.dispatch({
                    changes: { from, to, insert: `${fn[1]}()` },
                    selection: { anchor: from + fn[1].length + 1 },
                  });
                  startCompletion(view);
                }
              : fnStr
                ? (view: EditorView, _c: unknown, from: number, to: number) => {
                    view.dispatch({
                      changes: { from, to, insert: `${fnStr[1]}("")` },
                      selection: { anchor: from + fnStr[1].length + 2 },
                    });
                    startCompletion(view);
                  }
                : insert,
          };
        });
        if (options.length === 0) return null;
        // sniffer: 块内：服务端按位置返回谓词/层名/字段位专属列表（值位交回全局）
        // ——仅当整份结果都是 sniffer 条目时才走此分支，避免误伤值位的全局列表
        const snifferItems = result.items ?? [];
        if (
          inSnifferList(ctx.state.doc, ctx.pos) &&
          snifferItems.length > 0 &&
          snifferItems.every((it: any) => it.kind === 14 || it.kind === 5)
        ) {
          return {
            from: wordStart(ctx.state.doc, line.from, ctx.pos),
            options: snifferItems.map((it: any) => ({
              label: it.label,
              detail: it.detail ?? "",
              type: it.kind === 14 ? "keyword" : "property",
              apply: it.insertText ?? it.label,
              // match 最常用置顶，and/or/not 次之，层名/字段再次
              boost: it.kind === 14 ? (it.label === "match" ? 30 : 25) : 20,
            })),
            validFor: /^[A-Za-z0-9_=]*$/,
          };
        }
        // 光标前的词起点（锚定行尾取尾部词段，行内任意位置的词都正确）
        const from = wordStart(ctx.state.doc, line.from, ctx.pos);
        return {
          from,
          options,
          // 词字符/=续敲时 CM 本地过滤复用本结果，不重查 LSP（括号/逗号等会触发重查）
          validFor: /^[A-Za-z0-9_=]*$/,
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
      // Markdown 渲染（renderMarkdown 先整体转义 HTML，注入安全）
      return {
        pos,
        create: () => {
          const dom = document.createElement("div");
          dom.className = "hover-doc";
          dom.innerHTML = renderMarkdown(value);
          return { dom };
        },
      };
    },
    { hoverTime: 400 },
  );

  const updateListener = EditorView.updateListener.of((u) => {
    if (!u.docChanged) return;
    opts.onUpdate(u.state.doc.toString());
    // 触发字符：输入 ( , = > 立即弹补全（ipv4( 直达参数列表、|> 后直达层函数、
    // dport= 后直达值候选）；import 行的空格直达模块名；export:/sniffer: 列表位敲
    // - / 空格即弹名字或谓词；#[ 敲 [ 弹注解名；配方键位敲 : 弹枚举值、from: 敲
    // . 弹 reply. 层.字段 二级；字符串字面量内不打扰
    let inserted = "";
    u.changes.iterChanges((_a, _b, _c, _d, text) => {
      inserted += text.toString();
    });
    if (
      inserted.length > 0 &&
      inserted.length <= 3 &&
      !insideString(u.state.doc, u.state.selection.main.head)
    ) {
      const head = u.state.selection.main.head;
      const line = u.state.doc.lineAt(head);
      const before = u.state.doc.sliceString(line.from, head);
      const inExport = inExportList(u.state.doc, head);
      const inSniff = inSnifferList(u.state.doc, head);
      // export:/sniffer:/配方 列表位敲 `-`（项起点）即弹，无需先敲字母；空格同样触发
      const inRecipe = inRecipeList(u.state.doc, head);
      const dashCtx = inserted.trim() === "-" && (inExport || inSniff || inRecipe);
      const spaceCtx =
        inserted.trim() === "" &&
        (inExport || inSniff || inRecipe || /^\s*import\s/.test(before));
      // 配方键位：`:` 弹该键枚举值；`from:` 值内 `.` 弹 reply. 层.字段
      const colonCtx = inserted.trim() === ":" && inRecipe;
      const dotCtx = inserted.trim() === "." && inRecipe;
      // 注解位：`#[`（closeBrackets 会补出 []）弹注解名
      const bracketCtx = inserted.includes("[");
      // 自动格式化：列表位项起点的 `-` 补随行空格（规范形态 `- full` / `- match`）
      if (dashCtx && inserted.trim() === "-") {
        const dashHead = u.state.selection.main.head;
        const dashLine = u.state.doc.lineAt(dashHead);
        const beforeDash = u.state.doc.sliceString(dashLine.from, dashHead - 1);
        if (beforeDash.trim() === "") {
          u.view.dispatch({
            changes: { from: dashHead, insert: " " },
            selection: { anchor: dashHead + 1 },
          });
        }
      }
      if (!/[(,=>]\s*$/.test(inserted) && !dashCtx && !spaceCtx && !colonCtx && !dotCtx && !bracketCtx) return;
      startCompletion(u.view);
    }
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
    editableCompartment.of(editableExt(true)),
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
  // 输入中间态降噪：「输入已结束」类 parse 错误的 span 恒在文档末尾（EOF），
  // 打字过程中必然存在——落在最后一行时不展示（「字符串未闭合」「非法 token」
  // 等精准的中间态提示保留；非末行的真错误不受影响）
  const lastLine = view.state.doc.lines - 1;
  const shown = diags.filter(
    (d) => !(d.message.includes("输入已结束") && d.line >= lastLine),
  );
  const cmDiags: Diagnostic[] = shown
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

/** 跳到指定行（0-based）：移动光标、滚动到视区中间并聚焦——大纲点击用。 */
export function revealLine(view: EditorView, line0: number): void {
  const doc = view.state.doc;
  const l = doc.line(Math.min(Math.max(line0 + 1, 1), doc.lines));
  view.dispatch({
    selection: { anchor: l.from },
    effects: EditorView.scrollIntoView(l.from, { y: "center" }),
  });
  view.focus();
}
