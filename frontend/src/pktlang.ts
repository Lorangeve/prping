// pkt DSL 的 CodeMirror 语法高亮（StreamLanguage 简易分词，与 packet-dsl 词法对齐）：
// - `#` 到行尾是注释；`#[` 是协议注解（lexer 特例，标为 meta）
// - 关键字 use/import/export/func/true/false/params，`export:` 列表项以 `- ` 开头
// - 0x 十六进制与十进制数字、"…" 字符串、|> 管道操作符
// 函数调用名（后跟 `(`）标为 functionName，字段名（`=` 前）标为 propertyName。

import { StreamLanguage } from "@codemirror/language";
import type { StreamParser } from "@codemirror/language";

const KEYWORDS = new Set(["use", "import", "export", "func", "true", "false", "params"]);

export const pktlang: StreamParser<{}> = {
  name: "pktlang",
  token(stream) {
    if (stream.eatSpace()) return null;

    // `#[` 协议注解（非注释），其余 # 注释到行尾
    if (stream.match("#[", false)) {
      stream.match(/#\[[^\]]*\]?/);
      return "meta";
    }
    if (stream.peek() === "#") {
      stream.skipToEnd();
      return "comment";
    }
    // 字符串（未闭合也算，吃满行尾）
    if (stream.match(/^"(?:[^"\\]|\\.)*"/)) return "string";
    if (stream.peek() === '"') {
      stream.skipToEnd();
      return "string";
    }
    // 数字
    if (stream.match(/^0[xX][0-9a-fA-F]+/)) return "number";
    if (stream.match(/^\d+(\.\d+)?/)) return "number";
    // 管道操作符
    if (stream.match("|>")) return "operator";
    // 标识符 / 调用 / 字段
    if (stream.match(/^[A-Za-z_][A-Za-z0-9_-]*/)) {
      const word = stream.current();
      if (KEYWORDS.has(word)) return "keyword";
      // 后面紧跟 `(` → 函数调用；紧跟 `=` → 字段名
      if (stream.peek() === "(") return "variableName.function";
      if (stream.peek() === "=") return "propertyName";
      return "variableName";
    }
    if (stream.match(/^[=-]/)) return "operator";
    stream.next();
    return null;
  },
};

export const pktlangLanguage = StreamLanguage.define(pktlang);
