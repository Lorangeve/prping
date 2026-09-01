// 极简 Markdown → HTML 渲染（LSP hover / 补全文档展示用）。
//
// 引擎 LSP（eng/lsp.rs）的文档只产出固定子集，这里不引第三方渲染器，
// 仅支持该子集（与 doc_markdown / hover 输出对齐，另为 .md 文件预览加了表格）：
//   - 围栏代码块 ```…```（容许 ≤3 空格缩进——README 列表/段内嵌的围栏）
//   - 标题 # ~ ######
//   - 无序列表（连续 "- " 行聚合为一个 <ul>）
//   - GFM 表格（| 表头 | + | --- | 分隔行；单元格走行内标记；: 对齐）——
//     hover/补全文档目前不产出表格，多支持无害
//   - 段落（空行分隔；段内单换行经 CSS pre-wrap 保留）
//   - 行内 `code` 与 **粗体**（code 内的 ** 不展开）
//
// 安全：先整体转义 HTML 实体，再套标记——渲染结果 innerHTML 注入，
// 任何输入（含 <script>、属性、占位符字符）都只会显示为文本。

const PLACE_HOLDER = "\uE000"; // 私有区字符作 code 段占位（输入已转义，不会误触）

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/\u0000/g, "");
}

/** 行内标记：转义后处理 `code`（占位保护）与 **粗体**。 */
function inline(s: string): string {
  const codes: string[] = [];
  let t = esc(s).replace(/`([^`]+)`/g, (_m, c: string) => {
    codes.push(`<code>${c}</code>`);
    return PLACE_HOLDER + (codes.length - 1) + PLACE_HOLDER;
  });
  t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  return t.replace(new RegExp(PLACE_HOLDER + "(\\d+)" + PLACE_HOLDER, "g"), (_m, i: string) =>
    codes[Number(i)] ?? "",
  );
}

/** 表格行拆列：去首尾管道后按 | 分列；\| 转义经私有区占位保护（输入已转义，不会误触）。 */
function splitRow(line: string): string[] {
  let t = line.trim();
  if (t.startsWith("|")) t = t.slice(1);
  if (t.endsWith("|") && !t.endsWith("\\|")) t = t.slice(0, -1);
  const PIPE = "\uE001";
  return t
    .replace(/\\\|/g, PIPE)
    .split("|")
    .map((c) => c.trim().replaceAll(PIPE, "|"));
}

/** 分隔行：仅由 |、-、: 与空白组成（如 `| --- | :---: |`）。 */
function isDelimRow(line: string): boolean {
  const t = line.trim();
  if (!t.includes("|") || !t.includes("-") || /[^\s|:-]/.test(t)) return false;
  const cells = splitRow(t);
  return cells.length > 0 && cells.every((c) => /^:?-+:?$/.test(c));
}

/** 分隔行单元格的前导/尾随 : → 对齐（无则空串 = 默认左对齐）。 */
function cellAlign(d: string): string {
  const l = d.startsWith(":");
  const r = d.endsWith(":");
  return l && r ? "center" : r ? "right" : l ? "left" : "";
}

export function renderMarkdown(src: string): string {
  const lines = src.split("\n");
  const out: string[] = [];
  let para: string[] = [];
  let i = 0;

  const flushPara = () => {
    if (para.length) {
      out.push(`<p>${inline(para.join("\n"))}</p>`);
      para = [];
    }
  };

  while (i < lines.length) {
    const line = lines[i];
    if (/^\s*```/.test(line)) {
      flushPara();
      const buf: string[] = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) {
        buf.push(lines[i]);
        i++;
      }
      i++; // 跳过闭合围栏（缺失也安全）
      out.push(`<pre><code>${esc(buf.join("\n"))}</code></pre>`);
      continue;
    }
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      flushPara();
      const n = h[1].length;
      out.push(`<h${n}>${inline(h[2])}</h${n}>`);
      i++;
      continue;
    }
    if (/^- /.test(line)) {
      flushPara();
      const items: string[] = [];
      while (i < lines.length && /^- /.test(lines[i])) {
        items.push(`<li>${inline(lines[i].slice(2))}</li>`);
        i++;
      }
      out.push(`<ul>${items.join("")}</ul>`);
      continue;
    }
    // GFM 表格：表头行（含 |）+ 次行分隔行（| --- |）；其后含 | 的非空行都是数据行
    if (line.includes("|") && i + 1 < lines.length && isDelimRow(lines[i + 1])) {
      flushPara();
      const head = splitRow(line);
      const aligns = splitRow(lines[i + 1]).map(cellAlign);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].trim() !== "" && lines[i].includes("|")) {
        rows.push(splitRow(lines[i]));
        i++;
      }
      // 列数以表头为准：缺格补空，对齐按分隔行（缺省左）
      const tr = (cells: string[], tag: "th" | "td") =>
        `<tr>${head
          .map((_c, j) => {
            const align = aligns[j] ?? "";
            const attr = align ? ` style="text-align:${align}"` : "";
            return `<${tag}${attr}>${inline(cells[j] ?? "")}</${tag}>`;
          })
          .join("")}</tr>`;
      out.push(
        `<table><thead>${tr(head, "th")}</thead><tbody>${rows
          .map((r) => tr(r, "td"))
          .join("")}</tbody></table>`,
      );
      continue;
    }
    if (line.trim() === "") {
      flushPara();
      i++;
      continue;
    }
    para.push(line);
    i++;
  }
  flushPara();
  return out.join("");
}
