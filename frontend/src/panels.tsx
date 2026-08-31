// 右侧面板：诊断 / 层栈 / HEX 预览（数据来自 LSP publishDiagnostics 与 analyze 信封）。

import { For, Show, createMemo } from "solid-js";

export interface LspDiag {
  line: number;
  character: number;
  message: string;
  severity: number;
}

export interface AnalyzeDoc {
  sources: {
    kind: string;
    name: string | null;
    packets: {
      idx: number;
      total: number;
      layers: { name: string; fields: string; raw: boolean }[];
      bytes: number;
      hex: string;
      warnings: string[];
      raw_only: boolean;
    }[];
  }[];
  total: number;
  /** `sniffer:` 段的匹配子句展示文本（顶层子句间 = 隐式 OR）；无段则缺省 */
  sniffer?: string[];
  /** 文件声明的运行参数（params("名", 默认) 词法收集；default null = 必填）。
   *  构建失败的应答也带，供面板渲染参数输入行 */
  params?: { name: string; default: string | null }[];
}

/** analyze 的 fields 是渲染后的展示串（如 `type=8, code=0`）——按 `, ` 拆行
 *  拆出键值；无 `=` 的段整段进值列。（此前 Object.entries 直接迭代字符串，
  * 每个字符一行——层栈面板全是单字符行。） */
function fieldsRows(fields: string): { k: string; v: string }[] {
  if (!fields) return [];
  return fields.split(", ").map((part) => {
    const i = part.indexOf("=");
    return i > 0 ? { k: part.slice(0, i), v: part.slice(i + 1) } : { k: "", v: part };
  });
}

export type Panel = "diagnostics" | "layers" | "hex" | "recipe" | "globals";

/** .pktl 配方概览（服务端 parse_text 同构 JSON）。 */
export interface RecipeDoc {
  globals: { name: string; init: string | null; line: number }[];
  params: { key: string; value: string; step: number }[];
  steps: {
    idx: number;
    pkg: string;
    /** 服务端按配方目录解析出的包文件完整路径——点击跳转用 */
    pkgPath: string;
    line: number;
    wait: string | null;
    onTimeout: string | null;
    raw: string | null;
    onError: string;
    extract: { name: string; from: string; as: string }[];
  }[];
}

/** 诊断列表（空态给一行提示）。 */
export function DiagnosticsPanel(props: { diags: LspDiag[] }) {
  return (
    <div class="panel-body">
      <Show
        when={props.diags.length > 0}
        fallback={<div class="empty-hint">No diagnostics — document parses clean.</div>}
      >
        <For each={props.diags}>
          {(d) => (
            <div class={`diag ${d.severity <= 1 ? "diag-error" : "diag-warn"}`}>
              <span class="diag-pos">
                {d.line + 1}:{d.character + 1}
              </span>
              <span class="diag-msg">{d.message}</span>
            </div>
          )}
        </For>
      </Show>
    </div>
  );
}

/** sources → 扁平包列表（带来源标签）：层栈/HEX 面板按「显示全部」迭代渲染。 */
interface FlatPacket {
  idx: number;
  total: number;
  bytes: number;
  hex: string;
  warnings: string[];
  raw_only: boolean;
  layers: AnalyzeDoc["sources"][number]["packets"][number]["layers"];
  srcKind: string;
  srcName: string | null;
}

function allPackets(doc: AnalyzeDoc | null): FlatPacket[] {
  const out: FlatPacket[] = [];
  for (const src of doc?.sources ?? []) {
    for (const p of src.packets) {
      out.push({ ...p, srcKind: src.kind, srcName: src.name });
    }
  }
  return out;
}

/** 包头：来源（export 名）/序号/字节数/raw 标注。 */
function PacketMeta(props: { p: FlatPacket }) {
  return (
    <div class="pkt-meta">
      <Show when={props.p.srcKind === "default"}>
        <span class="badge">default export</span>
      </Show>
      <Show when={props.p.srcKind === "export"}>
        <span class="badge">export {props.p.srcName}</span>
      </Show>
      packet {props.p.idx}/{props.p.total} · {props.p.bytes} bytes
      <Show when={props.p.raw_only}>
        <span class="badge badge-raw">raw only</span>
      </Show>
    </div>
  );
}

/** 层栈视图：全部 sources → 全部 packets 逐个渲染（层字段键值 + raw 标注）；
 *  文件带 `sniffer:` 段时附匹配子句列表（顶层子句间隐式 OR）。解析/构建失败
 *  不在此展示——分析错误由面板顶部横幅承载（LSP 诊断不含运行期参数错误）。 */
export function LayersPanel(props: { doc: AnalyzeDoc | null }) {
  const packets = createMemo(() => allPackets(props.doc));
  return (
    <div class="panel-body">
      <Show
        when={packets().length > 0 || (props.doc?.sniffer?.length ?? 0) > 0}
        fallback={<div class="empty-hint">No packets yet — start typing a pipeline.</div>}
      >
        <For each={packets()}>
          {(p) => (
            <div class="pkt-block">
              <PacketMeta p={p} />
              <For each={p.warnings}>
                {(w) => <div class="diag diag-warn"><span class="diag-msg">{w}</span></div>}
              </For>
              <For each={p.layers}>
                {(layer, i) => (
                  <div class="layer">
                    <div class="layer-head">
                      <span class="layer-idx">{i() + 1}</span>
                      <span class="layer-name">{layer.name}</span>
                      <Show when={layer.raw}>
                        <span class="badge">raw bytes</span>
                      </Show>
                    </div>
                    <table class="fields">
                      <tbody>
                        <For each={fieldsRows(layer.fields)}>
                          {({ k, v }) => (
                            <tr>
                              <td class="fk">{k}</td>
                              <td class="fv">{v}</td>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </div>
                )}
              </For>
            </div>
          )}
        </For>
        <Show when={(props.doc?.sniffer?.length ?? 0) > 0}>
          <div class="pkt-meta">sniffer</div>
          <For each={props.doc?.sniffer}>
            {(c, i) => (
              <div class="sniff-clause">
                <Show when={i() > 0}>
                  <span class="badge badge-raw">OR</span>
                </Show>
                <span class="sniff-text">{c}</span>
              </div>
            )}
          </For>
        </Show>
      </Show>
    </div>
  );
}

/** .pktl 配方步骤视图：每步 packet/wait/extract/on_error。
 *  包文件名可点击——onOpenPkg 打开对应包文件（跳转到该包）。 */
export function RecipePanel(props: {
  doc: RecipeDoc | null;
  onOpenPkg?: (pkgPath: string) => void;
}) {
  return (
    <div class="panel-body">
      <Show
        when={(props.doc?.steps.length ?? 0) > 0}
        fallback={
          <div class="empty-hint">No steps yet — add `- packet: file.pkt`.</div>
        }
      >
        <For each={props.doc?.steps}>
          {(s) => (
            <div class="layer">
              <div class="layer-head">
                <span class="layer-idx">{s.idx}</span>
                <span
                  class="layer-name pkg-link"
                  title="Open this packet file"
                  onClick={() => props.onOpenPkg?.(s.pkgPath)}
                >
                  {s.pkg}
                </span>
                <Show when={s.wait}>
                  <span class="badge">wait {s.wait}</span>
                </Show>
                <Show when={s.raw}>
                  <span class="badge badge-raw">raw {s.raw}</span>
                </Show>
                <Show when={s.onTimeout}>
                  <span class="badge">on_timeout {s.onTimeout}</span>
                </Show>
                <Show when={s.onError === "continue"}>
                  <span class="badge">on_error continue</span>
                </Show>
              </div>
              <Show when={s.extract.length > 0}>
                <table class="fields">
                  <tbody>
                    <For each={s.extract}>
                      {(e) => (
                        <tr>
                          <td class="fk">{e.name}</td>
                          <td class="fv">
                            ← {e.from}
                            <Show when={e.as}> · as {e.as}</Show>
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </Show>
            </div>
          )}
        </For>
      </Show>
    </div>
  );
}

/** .pktl Globals 视图：global 声明（name = init）+ 步骤 params 键值。 */
export function GlobalsPanel(props: { doc: RecipeDoc | null }) {
  const globals = () => props.doc?.globals ?? [];
  const params = () => props.doc?.params ?? [];
  return (
    <div class="panel-body">
      <Show
        when={globals().length + params().length > 0}
        fallback={
          <div class="empty-hint">No globals / params — declare under `global:`.</div>
        }
      >
        <Show when={globals().length > 0}>
          <div class="pkt-meta">global</div>
          <table class="fields">
            <tbody>
              <For each={globals()}>
                {(g) => (
                  <tr>
                    <td class="fk">{g.name}</td>
                    <td class="fv">{g.init ?? "—"}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Show>
        <Show when={params().length > 0}>
          <div class="pkt-meta">params</div>
          <table class="fields">
            <tbody>
              <For each={params()}>
                {(p) => (
                  <tr>
                    <td class="fk">
                      {p.key} <span class="badge">step {p.step}</span>
                    </td>
                    <td class="fv">{p.value}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Show>
      </Show>
    </div>
  );
}

/** HEX 视图：全部包依次渲染（16 字节/行：offset + hex + ascii）。 */
export function HexPanel(props: { doc: AnalyzeDoc | null }) {
  const packets = createMemo(() => allPackets(props.doc));
  return (
    <div class="panel-body">
      <Show when={packets().length > 0} fallback={<div class="empty-hint">No packet bytes.</div>}>
        <For each={packets()}>
          {(p) => (
            <div class="pkt-block">
              <PacketMeta p={p} />
              <HexView hex={p.hex} />
            </div>
          )}
        </For>
      </Show>
    </div>
  );
}

function HexView(props: { hex: string }) {
  const rows = createMemo(() => {
    const hex = props.hex.replace(/\s+/g, "");
    const out: { off: string; hexes: string[]; ascii: string }[] = [];
    for (let i = 0; i < hex.length; i += 32) {
      const slice = hex.slice(i, i + 32);
      const bytes: number[] = [];
      for (let j = 0; j < slice.length; j += 2) {
        bytes.push(parseInt(slice.slice(j, j + 2), 16));
      }
      out.push({
        off: (i / 2).toString(16).padStart(4, "0"),
        hexes: bytes.map((b) => b.toString(16).padStart(2, "0")),
        ascii: bytes.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join(""),
      });
    }
    return out;
  });
  return (
    <div class="hexview">
      <For each={rows()}>
        {(r) => (
          <div class="hex-row">
            <span class="hex-off">{r.off}</span>
            <span class="hex-bytes">
              {r.hexes.map((h) => (
                <span class="hex-byte">{h}</span>
              ))}
            </span>
            <span class="hex-ascii">{r.ascii}</span>
          </div>
        )}
      </For>
    </div>
  );
}

/** 面板页签（.pktl 配方文档切换为 Recipe/Globals 组）。 */
export function PanelTabs(props: {
  panel: Panel;
  setPanel: (p: Panel) => void;
  diagCount: number;
  recipe?: boolean;
}) {
  // 派生而非一次性 signal：props.recipe 随打开文件类型变化，页签须跟随
  const tabs = () =>
    props.recipe
      ? [
          { id: "diagnostics" as Panel, label: "Diagnostics" },
          { id: "recipe" as Panel, label: "Recipe" },
          { id: "globals" as Panel, label: "Globals" },
        ]
      : [
          { id: "diagnostics" as Panel, label: "Diagnostics" },
          { id: "layers" as Panel, label: "Layers" },
          { id: "hex" as Panel, label: "Hex" },
        ];
  return (
    <div class="tabs">
      <For each={tabs()}>
        {(t) => (
          <button
            class="tab"
            classList={{ active: props.panel === t.id }}
            onClick={() => props.setPanel(t.id)}
          >
            {t.label}
            <Show when={t.id === "diagnostics" && props.diagCount > 0}>
              <span class="tab-badge">{props.diagCount}</span>
            </Show>
          </button>
        )}
      </For>
    </div>
  );
}
