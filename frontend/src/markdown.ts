// 极简 Markdown → HTML 渲染（LSP hover / 补全文档展示用）。
//
// 引擎 LSP（eng/lsp.rs）的文档只产出固定子集，这里不引第三方渲染器，
// 仅支持该子集（与 doc_markdown / hover 输出对齐）：
//   - 围栏代码块 ```…```
//   - 标题 # ~ ######
//   - 无序列表（连续 "- " 行聚合为一个 <ul>）
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
    if (line.startsWith("```")) {
      flushPara();
      const buf: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
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
