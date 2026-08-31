// 块视图（阶段 2+3：可编辑 + 回写 + 配方）——ast/recipe 信封 → Blockly(Zelos) 工作区。
//
// packet 模型（.pkt，一个 layer 一个概念块）：
// - **pkt_def 父块**：\`name =\` 可命名（FieldTextInput）+ EXPR 值插座——语句容器；
// - **pkt_fn_<层名> 表达式块**：schema 信封动态注册（参数行 + 默认值），带 OUTPUT
//   插座与 CONTENT 内层插座——管线 = 嵌套（外层 CONTENT ← 内层 OUTPUT，
//   文本顺序 = 内 → 外，与 DSL \`|>\` 语义一致）；最内层是 pkt_use 表达式块；
// - proto/func/import/sniffer = 信息卡（不可编辑）。
// 回写：字段提交按 call span 拼接；结构操作（包裹/解包/删语句/改名）按 item span
// 重生成整句（表达式树走链）——App 侧 span 拼接 → setDoc → 既有刷新闭环。
//
// 配方模型（.pktl，一个 .pkt 一个块）：global 信息卡 + recipe 头 + 步骤链，
// 步骤改名按 fileSpan、加/删步按行区间拼接。
//
// Blockly ~1MB：动态 import 懒加载成独立 chunk；eng_lib 只读文档注入 readOnly。

import { createEffect, createSignal, onCleanup, onMount, Show } from "solid-js";

type SpanJson = { sl: number; sc: number; el: number; ec: number };

export interface AstArg {
  name: string | null;
  value: string;
  span: SpanJson;
}
export interface AstCall {
  name: string;
  span: SpanJson;
  args: AstArg[];
}
export interface AstPipeline {
  use: { name: string; span: SpanJson }[];
  layers: AstCall[];
}
export interface AstItem {
  kind: "pipeline" | "def" | "func" | "proto" | "import" | "sniffer";
  name?: string;
  expr?: ({ kind: "call" } & AstCall) | ({ kind: "pipeline" } & AstPipeline);
  pipeline?: AstPipeline;
  params?: { name: string; default?: string | null }[];
  fields?: { name: string; ty: string; width?: string; default?: string; bits?: number }[];
  layer?: string | null;
  module?: string;
  doc?: string;
  span: SpanJson;
}
export interface AstDoc {
  mode: "packet";
  file: string;
  module: string;
  items: AstItem[];
}
export interface RecipeStep {
  file: string;
  line: number;
  endLine: number;
  fileSpan: SpanJson;
  span: SpanJson;
  flags: string[];
}
export interface RecipeDoc {
  mode: "recipe";
  file: string;
  globals: { name: string; init: string | null; line: number }[];
  steps: RecipeStep[];
}
export type BlockDoc = AstDoc | RecipeDoc;
export interface SchemaDoc {
  builtins: { name: string; params: [string, string][]; summary: string; auto: string }[];
  libLayers: {
    name: string;
    module: string;
    isProto: boolean;
    params?: { name: string; default?: string | null }[] | null;
    summary?: string | null;
  }[];
}

// ── Blockly 懒加载与块注册 ───────────────────────────────────

let blocklyPromise: Promise<any> | null = null;
function loadBlockly(): Promise<any> {
  blocklyPromise ??= import("blockly");
  return blocklyPromise;
}

let registered = false;
/** 基础块：pkt_card（通用卡片/信息卡）、pkt_def（可命名父块）、pkt_use（元件引用）。 */
function registerBlocks(B: any) {
  if (registered) return;
  registered = true;
  B.Blocks["pkt_card"] = {
    init: function (this: any) {
      this.appendDummyInput("HEAD").appendField(new B.FieldLabel(""), "TEXT");
      this.setColour(210);
    },
  };
  // def 父块：可命名 + 表达式插座（语句容器）
  B.Blocks["pkt_def"] = {
    init: function (this: any) {
      this.appendDummyInput("HEAD")
        .appendField(new B.FieldTextInput("name"), "NAME")
        .appendField("=");
      this.appendValueInput("EXPR").setCheck(null);
      this.setColour(150);
    },
  };
  // 元件引用表达式：use(get)
  B.Blocks["pkt_use"] = {
    init: function (this: any) {
      this.appendDummyInput("HEAD")
        .appendField("use(")
        .appendField(new B.FieldLabel(""), "NAME")
        .appendField(")");
      this.setOutput(true, null);
      this.setColour(150);
    },
  };
}

/** schema 驱动的函数块类型表：pkt_fn_<层名> → 参数（名 + 默认值展示）。
 *  一个函数一个块：参数行由块定义给出（schema 顺序 + 默认值），带 OUTPUT
 *  插座（表达式块）+ CONTENT 内层插座（管线包裹）。 */
const fnParams = new Map<string, { n: string; def: string }[]>();

function registerSchemaBlocks(B: any, schema: SchemaDoc | null) {
  if (!schema) return;
  fnParams.clear();
  const add = (name: string, params: { n: string; def: string }[]) => {
    if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(name)) return;
    fnParams.set(name, params);
    B.Blocks["pkt_fn_" + name] = {
      init: function (this: any) {
        this.appendDummyInput("HEAD").appendField(name);
        params.forEach((p, i) => {
          const input = this.appendDummyInput("ARG" + i);
          if (p.n) input.appendField(p.n + " =");
          input.appendField(new B.FieldTextInput(p.def), "F" + i);
        });
        // 内层插座：管线包裹（最内层留空）
        this.appendValueInput("CONTENT").setCheck(null);
        this.setOutput(true, null);
        this.setColour(230);
      },
    };
  };
  for (const l of schema.libLayers ?? []) {
    // proto 参数的 schema 默认是自引用 Ident（default = 参数名 = 引擎自动值）——
    // 显示为空（省略 = 自动），否则回写会生成顶层无作用域的 ident（语义非法）
    add(
      l.name,
      (l.params ?? []).map((p) => ({
        n: p.name,
        def: p.default && p.default !== p.name ? p.default : "",
      })),
    );
  }
  for (const b of schema.builtins ?? []) {
    if (!["raw", "hex", "layer"].includes(b.name)) continue;
    add(b.name, b.params.map(([n]) => ({ n, def: "" })));
  }
}

const TRUNCATE = 56;
function clip(s: string): string {
  return s.length > TRUNCATE ? s.slice(0, TRUNCATE - 1) + "…" : s;
}

// ── ast 文档 → 块规格 ────────────────────────────────────────

function argText(a: AstArg): string {
  return a.name ? a.name + " = " + a.value : a.value;
}

/** 回写范围 = 源实参的参数名（保源顺序；位置实参按序映射 schema 参数名）。 */
function writtenNames(call: AstCall | null, params: { n: string }[]): string[] {
  if (!call) return [];
  return call.args
    .map((a) => (a.name ? a.name : (params[call.args.indexOf(a)]?.n ?? null)))
    .filter((n): n is string => !!n);
}

// ── 组件 ────────────────────────────────────────────────────

export function BlocksView(props: {
  ast: BlockDoc | null;
  error: string | null;
  editable: boolean;
  schema: SchemaDoc | null;
  onEdit: (span: SpanJson, replacement: string | null) => void;
  onAppend: (stmt: string) => void;
  onInsertLine: (afterLine: number, text: string) => void;
}) {
  let host!: HTMLDivElement;
  const [ready, setReady] = createSignal(false);
  const [failed, setFailed] = createSignal<string | null>(null);
  let ws: any = null;
  let Bmod: any = null;
  let building = false;
  let editableShown = props.editable;
  let newSeq = 100;
  // def 父块/信息卡的手动纵排游标（表达式块由渲染器随父块内联定位）
  let cardY = 24;
  const CARD_X = 24;

  function packetItems(): AstItem[] | null {
    return props.ast && props.ast.mode === "packet" ? props.ast.items : null;
  }

  /** schema 驱动的函数块类型已注册？ */
  function fnTypeReady(name: string): boolean {
    return !!Bmod?.Blocks["pkt_fn_" + name];
  }

  /** initSvg + render 后取渲染高度（不含嵌套子块——子块由渲染器内联定位）。 */
  function cardHeight(b: any): number {
    b.initSvg();
    b.render();
    const hw = b.getHeightWidth();
    return hw?.height ?? 40;
  }

  function fnBlock(name: string, itemIdx: number, call: AstCall | null, ins: boolean): any {
    const fnType = "pkt_fn_" + name;
    const typed = fnTypeReady(name);
    const b = ws.newBlock(typed ? fnType : "pkt_card");
    b.setColour(230);
    if (props.editable) {
      b.setMovable(false);
      b.setDeletable(false);
    }
    if (typed) {
      // 参数行已由块定义给出（schema 顺序 + 默认值）——按源实参回填：
      // 具名优先、位置实参按序、缺失用 schema 默认
      const params = fnParams.get(name)!;
      const byName = new Map<string, string>();
      const positional: string[] = [];
      for (const a of call?.args ?? []) {
        if (a.name) byName.set(a.name, a.value);
        else positional.push(a.value);
      }
      // written = 源实参的参数名（保源顺序；位置实参按序映射 schema 参数名）——
      // 回写只写这个集合，未写过的参数继续走默认值（避免全参数显式撑爆源文件）
      const written = writtenNames(call, params);
      b.data = JSON.stringify({
        k: "layer",
        type: fnType,
        item: itemIdx,
        ins,
        args: params.map((p) => ({ n: p.n })),
        written,
        span: call?.span ?? null,
      });
      params.forEach((p, i) => {
        const v = byName.get(p.n) ?? positional[i] ?? p.def;
        b.getField("F" + i)?.setValue(v.includes("\n") ? clip(v) : v);
      });
    } else {
      // 未知层/schema 未到：通用卡片（TEXT 层名 + 行实参）
      b.setFieldValue(name, "TEXT");
      b.data = JSON.stringify({
        k: "layer",
        item: itemIdx,
        ins,
        args: (call?.args ?? []).map((a) => ({ n: a.name })),
        span: call?.span ?? null,
      });
      for (const a of call?.args ?? []) {
        const input = b.appendDummyInput();
        if (a.name) input.appendField(new Bmod.FieldLabel(a.name + " ="));
        input.appendField(new Bmod.FieldLabel(clip(a.value)));
      }
      if (!props.editable && call?.span) {
        b.setTooltip(call.args.map(argText).join("\n"));
      }
    }
    if (call?.args.length) b.setTooltip(call.args.map(argText).join("\n"));
    attachMenu(b);
    return b;
  }

  function useBlock(name: string, itemIdx: number): any {
    const b = ws.newBlock("pkt_use");
    b.getField("NAME").setValue(name);
    b.setColour(150);
    if (props.editable) {
      b.setMovable(false);
      b.setDeletable(false);
    }
    b.data = JSON.stringify({ k: "use", item: itemIdx, name });
    b.initSvg();
    return b;
  }

  /** 表达式树 → 文本（内 → 外：use(get) |> tcp(...) |> ...）。 */
  function exprText(b: any): string {
    const d = JSON.parse(b.data);
    if (d.k === "use") return "use(" + d.name + ")";
    const name = d.type
      ? d.type.slice("pkt_fn_".length)
      : (b.getField("TEXT")?.getValue() ?? "");
    const inner = b.getInput("CONTENT")?.connection?.targetBlock() ?? null;
    // 只写「源实参 ∪ 显式加入的」（written，与 callTextFromBlock 同一判据）——
    // 结构操作的重生成同样不做 schema 全参数展开
    const written: string[] = Array.isArray(d.written)
      ? d.written
      : (d.args ?? []).map((a: any) => a.n);
    const parts = written.map((n: string) => {
      const i = (d.args ?? []).findIndex((a: any) => a.n === n);
      const v = i >= 0 ? (b.getField("F" + i)?.getValue() ?? "") : "";
      return n ? n + "=" + v : v;
    });
    const call = name + "(" + parts.join(", ") + ")";
    return inner ? exprText(inner) + " |> " + call : call;
  }

  /** 结构提交：按 item 下标找 def 父块，重生成整句（表达式树当前状态）。 */
  function commitItemByIdx(idx: number) {
    const top = ws
      .getTopBlocks(false)
      .find((tb: any) => {
        let d: any = null;
        try { d = JSON.parse(tb.data ?? "null"); } catch {}
        return d?.k === "head" && d.item === idx;
      });
    console.log("[ci] idx=", idx, " found=", !!top);
    if (top) commitDef(top);
  }
  function commitDef(defBlock: any) {
    const d = JSON.parse(defBlock.data);
    const item = packetItems()?.[d.item];
    if (!item) return;
    const expr = defBlock.getInput("EXPR")?.connection?.targetBlock() ?? null;
    if (!expr) {
      props.onEdit(item.span, null); // 表达式被清空 → 整句删除
      return;
    }
    const name = defBlock.getField("NAME")?.getValue() ?? d.name;
    props.onEdit(item.span, name + " = " + exprText(expr));
  }

  // ── packet 渲染 ─────────────────────────────────────────────

  function renderPacket(ast: AstDoc) {
    ast.items.forEach((item, idx) => {
      if (item.kind === "def" && item.name) {
        const b = ws.newBlock("pkt_def");
        b.getField("NAME").setValue(item.name);
        if (props.editable) {
          b.setMovable(false);
          b.setDeletable(false);
        }
        b.data = JSON.stringify({ k: "head", kind: "def", name: item.name, item: idx, span: item.span });
        attachDefMenu(b);
        // 表达式树
        let innerMost: any = null;
        let holder: any = null; // 待包裹层块的有序列表（内 → 外）
        if (item.expr?.kind === "call") {
          holder = [fnBlock(item.expr.name, idx, item.expr, false)];
        } else if (item.expr?.kind === "pipeline") {
          if (item.expr.use.length === 1) innerMost = useBlock(item.expr.use[0].name, idx);
          // 多载荷 use(a, b)：MVP 取首名（多载荷嵌套待做）
          else if (item.expr.use.length > 0) innerMost = useBlock(item.expr.use[0].name, idx);
          holder = item.expr.layers.map((c) => fnBlock(c.name, idx, c, true));
        }
        // 组嵌套：外层 CONTENT ← 内层 OUTPUT
        for (let i = 0; i < holder.length; i++) {
          if (i > 0) {
            holder[i].getInput("CONTENT")?.connection.connect(holder[i - 1].outputConnection);
          }
        }
        const outermost = holder.length > 0 ? holder[holder.length - 1] : innerMost;
        b.initSvg();
        if (outermost) {
          b.getInput("EXPR").connection.connect(outermost.outputConnection);
        } else if (innerMost) {
          b.getInput("EXPR").connection.connect(innerMost.outputConnection);
        }
        const h = cardHeight(b);
        b.moveBy(CARD_X, cardY);
        cardY += h + 26;
        return;
      }
      if (item.kind === "pipeline") {
        // 顶层匿名流水线：同 def 但无名字——用一张 def 卡（名字占位 "(pipeline)"）
        const b = ws.newBlock("pkt_def");
        b.getField("NAME").setValue("(pipeline)");
        if (props.editable) {
          b.setMovable(false);
          b.setDeletable(false);
        }
        b.data = JSON.stringify({ k: "head", kind: "pipeline", name: "(pipeline)", item: idx, span: item.span });
        attachDefMenu(b);
        let innerMost: any = null;
        const holder: any[] = [];
        if (item.pipeline) {
          if (item.pipeline.use.length > 0) innerMost = useBlock(item.pipeline.use[0].name, idx);
          holder.push(...item.pipeline.layers.map((c) => fnBlock(c.name, idx, c, true)));
        }
        for (let i = 1; i < holder.length; i++) {
          holder[i].getInput("CONTENT")?.connection.connect(holder[i - 1].outputConnection);
        }
        const outermost = holder.length > 0 ? holder[holder.length - 1] : innerMost;
        b.initSvg();
        if (outermost) b.getInput("EXPR").connection.connect(outermost.outputConnection);
        else if (innerMost) b.getInput("EXPR").connection.connect(innerMost.outputConnection);
        const h = cardHeight(b);
        b.moveBy(CARD_X, cardY);
        cardY += h + 26;
        return;
      }
      // 信息卡：proto / func / import / sniffer
      const card = infoCard(item);
      if (card) {
        const h = cardHeight(card);
        card.moveBy(CARD_X, cardY);
        cardY += h + 26;
      }
    });
  }

  function infoCard(item: AstItem): any | null {
    const b = ws.newBlock("pkt_card");
    b.setPreviousStatement(false, null);
    b.setNextStatement(false, null);
    b.setColour(290);
    b.data = JSON.stringify({ k: "info" });
    if (item.kind === "proto") {
      b.setFieldValue(clip("#[proto] " + item.name + (item.layer ? " → " + item.layer : "")), "TEXT");
      for (const f of item.fields ?? []) {
        b.appendDummyInput().appendField(
          new Bmod.FieldLabel(
            clip(f.name + ": " + f.ty + (f.width ? "[" + f.width + "]" : "") + (f.default != null ? " = " + f.default : "")),
          ),
        );
      }
      b.setTooltip("#[proto] " + item.name);
    } else if (item.kind === "func") {
      const ps = (item.params ?? []).map((p) => p.name + (p.default ? "=" + p.default : "")).join(", ");
      b.setFieldValue(clip("func " + item.name + "(" + ps + ")"), "TEXT");
      b.setTooltip(item.doc ?? "func " + item.name);
    } else if (item.kind === "import") {
      b.setFieldValue(clip("import " + (item.module ?? "")), "TEXT");
    } else if (item.kind === "sniffer") {
      b.setFieldValue("sniffer { … }", "TEXT");
      b.setTooltip("回包/监听匹配声明");
    } else {
      return null;
    }
    b.initSvg();
    return b;
  }

  // ── 配方渲染（一个 .pkt 一个块）─────────────────────────────

  function renderRecipe(doc: RecipeDoc) {
    for (const g of doc.globals) {
      const b = ws.newBlock("pkt_card");
      b.setFieldValue(
        clip(g.init != null ? "global " + g.name + " = " + g.init : "global " + g.name),
        "TEXT",
      );
      b.setColour(120);
      b.setPreviousStatement(false, null);
      b.setNextStatement(false, null);
      b.data = JSON.stringify({ k: "info" });
      b.setTooltip("跨步骤共享变量（global 段）");
      b.initSvg();
      const h = cardHeight(b);
      b.moveBy(CARD_X, cardY);
      cardY += h + 6;
    }
    const head = ws.newBlock("pkt_card");
    head.setFieldValue(clip("recipe · " + doc.steps.length + " steps"), "TEXT");
    head.setColour(290);
    head.setPreviousStatement(false, null);
    head.data = JSON.stringify({ k: "info" });
    const hh = cardHeight(head);
    head.moveBy(CARD_X, cardY);
    cardY += hh + 6;
    let prev: any = head;
    doc.steps.forEach((s) => {
      const b = ws.newBlock("pkt_card");
      b.setColour(230);
      if (props.editable) {
        b.setMovable(false);
        b.setDeletable(false);
      }
      b.data = JSON.stringify({ k: "step", endLine: s.endLine, fileSpan: s.fileSpan, span: s.span });
      if (props.editable) {
        b.getInput("HEAD").removeField("TEXT");
        b.getInput("HEAD").appendField(new Bmod.FieldTextInput(s.file), "TEXT");
      } else {
        b.getField("TEXT").setValue(s.file);
      }
      for (const f of s.flags) {
        b.appendDummyInput().appendField(new Bmod.FieldLabel(f));
      }
      b.setTooltip("- packet: " + s.file);
      attachStepMenu(b);
      b.initSvg();
      const h = cardHeight(b);
      b.moveBy(CARD_X, cardY);
      cardY += h + 6;
      prev.nextConnection.connect(b.previousConnection);
      prev = b;
    });
  }

  // ── 菜单 ────────────────────────────────────────────────────

  function attachDefMenu(b: any) {
    if (!props.editable) return;
    b.customContextMenu = function (options: any[]) {
      let d: any = null;
      try { d = JSON.parse(b.data ?? "null"); } catch { d = null; }
      if (!d || d.k !== "head") return;
      options.push({
        text: "Delete statement",
        callback: () => {
          const item = packetItems()?.[d.item];
          if (item) props.onEdit(item.span, null);
        },
      });
    };
  }

  /** 找到持有 target 输出插座的输入（沿 def 父块的表达式树）。 */
  function findHolderOf(target: any): { holder: any; input: any } | null {
    const walk = (block: any): { holder: any; input: any } | null => {
      for (const input of block.inputList ?? []) {
        const t = input.connection?.targetBlock() ?? null;
        if (t === target) return { holder: block, input };
        if (t) {
          const r = walk(t);
          if (r) return r;
        }
      }
      return null;
    };
    for (const top of ws.getTopBlocks(false)) {
      let d: any = null;
      try { d = JSON.parse(top.data ?? "null"); } catch {}
      if (d?.k !== "head") continue;
      const r = walk(top);
      if (r) return r;
    }
    return null;
  }

  function attachMenu(b: any) {
    if (!props.editable) return;
    b.customContextMenu = function (options: any[]) {
      let d: any = null;
      try { d = JSON.parse(b.data ?? "null"); } catch { d = null; }
      if (!d || d.k !== "layer") return;
      if (d.ins) {
        // 包裹（外插层）：新块 CONTENT ← 当前表达式，原持有者改插新块
        options.push({
          text: "Wrap with layer…",
          callback: () => {
            const nm = window.prompt("Layer name:", "icmp");
            if (!nm) return;
            // 持有者必须先查（在 nb.CONTENT ← b 之前）：连接后 b 的持有者会变成 nb 自己
            const holder = findHolderOf(b);
            console.log("[wrap] holder=", holder?.holder?.getField("NAME")?.getValue() ?? holder?.holder?.type ?? "null");
            const nb = fnBlock(nm, d.item, null, true);
            nb.getInput("CONTENT")?.connection.connect(b.outputConnection);
            if (holder) holder.input.connection.connect(nb.outputConnection);
            console.log("[wrap] connected, commitItemByIdx next");
            commitItemByIdx(d.item);
          },
        });
      } else {
        // def = call（纯内容）：管线必须以 use(...) 开头——提供语法正确的整句包裹
        options.push({
          text: "Wrap in new statement…",
          callback: () => {
            const item = packetItems()?.[d.item];
            if (!item || item.kind !== "def" || !item.name) return;
            const nm = window.prompt("Wrapping layer name:", "udp");
            if (!nm) return;
            props.onAppend(item.name + "_wrapped = use(" + item.name + ") |> " + nm.trim() + "()");
          },
        });
      }
      // 解包（删本层）：持有者插座改接本层的 CONTENT 内层；孤儿块不 dispose——
      // ast 刷新后 renderDoc 的 ws.clear() 统一清除（v13 dispose 会连带子树）
      options.push({
        text: "Delete this layer",
        callback: () => {
          const inner = b.getInput("CONTENT")?.connection?.targetBlock() ?? null;
          const holder = findHolderOf(b);
          if (holder && inner) holder.input.connection.connect(inner.outputConnection);
          else if (holder) holder.input.connection.disconnect();
          commitItemByIdx(d.item);
        },
      });
      // 字段集控制：written = 源实参 ∪ 显式加入的参数（回写范围）；
      // typed 块的全部 schema 参数始终可见，未 written 的显示默认值但不回写
      const fnName = d.type ? d.type.slice("pkt_fn_".length) : null;
      const all = fnName ? (fnParams.get(fnName) ?? []).map((p) => p.n) : [];
      const writtenNow: string[] = d.written?.length ? d.written : all;
      options.push({ separator: true } as any);
      options.push({
        text: "Add field…",
        callback: () => {
          const avail = fnName ? all.filter((n) => !writtenNow.includes(n)) : [];
          const nm = window.prompt(
            avail.length ? "Field (of: " + avail.join(", ") + "):" : "Field name:",
            avail[0] ?? "",
          );
          if (!nm) return;
          if (fnName && !avail.includes(nm)) return; // 未知/已写参数
          const dd = JSON.parse(b.data);
          dd.written = [...(dd.written?.length ? dd.written : all), nm];
          b.data = JSON.stringify(dd);
          commitCall(b);
        },
      });
      options.push({
        text: "Remove field…",
        callback: () => {
          const nm = window.prompt("Field name to remove:", writtenNow[0] ?? "");
          if (!nm) return;
          const dd = JSON.parse(b.data);
          dd.written = writtenNow.filter((n) => n !== nm);
          b.data = JSON.stringify(dd);
          commitCall(b);
        },
      });
      options.push({ separator: true } as any);
      options.push({
        text: "Delete statement",
        callback: () => {
          const item = packetItems()?.[d.item];
          if (item) props.onEdit(item.span, null);
        },
      });
    };
  }

  function attachStepMenu(b: any) {
    if (!props.editable) return;
    b.customContextMenu = function (options: any[]) {
      let d: any = null;
      try { d = JSON.parse(b.data ?? "null"); } catch { d = null; }
      if (!d || d.k !== "step") return;
      options.push({
        text: "Add step after…",
        callback: () => {
          const nm = window.prompt("Packet file (.pkt):", "untitled.pkt");
          if (!nm) return;
          props.onInsertLine(d.endLine, "- packet: " + nm.trim());
        },
      });
      options.push({ separator: true } as any);
      options.push({
        text: "Delete step",
        callback: () => props.onEdit(d.span, null),
      });
    };
  }

  // ── 提交 ────────────────────────────────────────────────────

  /** 字段提交：按 call span 重生成调用文本（未编辑参数保留字段现值）。 */
  function commitCall(b: any) {
    const d = JSON.parse(b.data);
    if (!d.span) { commitItemByIdx(d.item); return; }
    props.onEdit(d.span, callTextFromBlock(b, d));
  }

  function callTextFromBlock(b: any, d: any): string {
    // 函数块的层名由块类型携带（pkt_fn_<name>，无 TEXT 字段）；通用卡片从 TEXT 取
    const name = d.type
      ? d.type.slice("pkt_fn_".length)
      : (b.getField("TEXT")?.getValue() ?? "");
    const inner = b.getInput("CONTENT")?.connection?.targetBlock() ?? null;
    const innerText = inner ? " |> " + callTextFromBlock(inner, JSON.parse(inner.data)) : "";
    // 只写「源实参 ∪ 用户显式加的」（d.written，保源顺序）——schema 全参数仅供
    // 字段显示，未写过的参数继续走默认值，避免整句被撑成全参数显式形式。
    // 注意 Array.isArray 判据：新插层的 written 是空数组（全默认）而非未设置
    const written: string[] = Array.isArray(d.written)
      ? d.written
      : (d.args ?? []).map((a: any) => a.n);
    const parts = written.map((n: string) => {
      const i = (d.args ?? []).findIndex((a: any) => a.n === n);
      const v = i >= 0 ? (b.getField("F" + i)?.getValue() ?? "") : "";
      return n ? n + "=" + v : v;
    });
    return name + "(" + parts.join(", ") + ")" + innerText;
  }

  /** 结构提交：回溯到 def 父块，按表达式树重生成整句。 */


  // ── 渲染 ────────────────────────────────────────────────────

  function renderDoc(ast: BlockDoc | null) {
    if (!ws || !Bmod) return;
    building = true;
    try {
      ws.clear();
      cardY = 24;
      if (ast) {
        if (ast.mode === "recipe") renderRecipe(ast);
        else renderPacket(ast);
        ws.render();
        ws.scrollCenter();
      }
    } catch (e) {
      ws.clear();
      setFailed(e instanceof Error ? e.message : String(e));
    } finally {
      building = false;
    }
  }

  function injectWs() {
    ws = Bmod.inject(host, {
      renderer: "zelos",
      readOnly: !props.editable,
      scrollbars: true,
      trashcan: false,
      sounds: false,
      zoom: { controls: true, wheel: true, startScale: 0.85 },
      grid: { spacing: 24, length: 1, colour: "#23232e", snap: false },
    });
    ws.addChangeListener((e: any) => {
      if (building || !props.editable) return;
      if (e.type !== Bmod.Events.BLOCK_CHANGE) return;
      const b = ws.getBlockById(e.blockId);
      if (!b?.data) return;
      let d: any = null;
      try { d = JSON.parse(b.data); } catch { return; }
      if (d.k === "step") {
        if (e.element === "TEXT") props.onEdit(d.fileSpan, String(e.newValue ?? ""));
        return;
      }
      if (d.k === "head") {
        // def 改名：整句重生成（名字 + 表达式树）
        if (e.element === "NAME") commitDef(b);
        return;
      }
      if (d.k === "layer") {
        if (e.element === "TEXT" || (typeof e.element === "string" && e.element.startsWith("F"))) {
          commitCall(b);
        }
      }
    });
    ws.configureContextMenu = (options: any[]) => {
      if (!props.editable) return;
      options.push({ separator: true } as any);
      options.push({
        text: "New statement (def = icmp())",
        callback: () => {
          const nm = window.prompt("def name:", "pkt" + newSeq++);
          if (nm && nm.trim()) props.onAppend(nm.trim() + " = icmp()");
        },
      });
    };
    // e2e 观测钩子（只读调试用）
    (window as any).__prpingBlocks = ws;
    (window as any).__prpingBlockly = Bmod;
  }

  onMount(async () => {
    try {
      Bmod = await loadBlockly();
      registerBlocks(Bmod);
      injectWs();
      setReady(true);
    } catch (e) {
      setFailed(e instanceof Error ? e.message : String(e));
    }
  });

  // editable 切换（ws 文件 ↔ eng_lib 只读）→ 重建工作区
  createEffect(() => {
    const ed = props.editable;
    if (!ready() || !Bmod || !ws) return;
    if (ed === editableShown) return;
    editableShown = ed;
    ws.dispose();
    injectWs();
    renderDoc(props.ast);
  });

  // schema 到达 → 注册「一个函数一个块」类型并重建
  createEffect(() => {
    const s = props.schema;
    if (!ready() || !Bmod || !ws || !s) return;
    registerSchemaBlocks(Bmod, s);
    renderDoc(props.ast);
  });

  createEffect(() => {
    if (ready()) renderDoc(props.ast);
  });

  onCleanup(() => ws?.dispose());

  return (
    <section class="blocks-pane" ref={host} data-testid="blocks">
      <Show when={ready() && props.editable}>
        <div class="blocks-hint">editable — right-click a block for structure ops</div>
      </Show>
      <Show when={!ready()}>
        <div class="blocks-overlay">
          {failed() ? "Blockly load failed: " + failed() : "loading blocks…"}
        </div>
      </Show>
      <Show when={ready() && props.error}>
        <div class="blocks-overlay blocks-error" title={props.error ?? ""}>
          blocks unavailable — {props.error}
        </div>
      </Show>
      <Show
        when={ready() && !props.error && props.ast && props.ast.mode === "packet" && props.ast.items.length === 0}
      >
        <div class="blocks-overlay">empty document — nothing to show</div>
      </Show>
    </section>
  );
}
