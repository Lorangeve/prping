// 右侧面板：诊断 / 层栈 / HEX 预览（数据来自 LSP publishDiagnostics 与 analyze 信封）。

import { For, Index, Show, createEffect, createMemo, createSignal, onCleanup } from "solid-js";

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

export type Panel =
  | "diagnostics"
  | "layers"
  | "hex"
  | "recipe"
  | "globals"
  | "outline"
  | "run";

/** Run 面板的选项快照（kv 持久化；count/wait 以字符串承载输入框原文）。 */
export interface RunSettings {
  target: string;
  count: string;
  wait: string;
  /** 裸 --wait：持续监听（覆盖 wait 数值） */
  listen: boolean;
  fuzz: boolean;
  raw: boolean;
  iface: string;
  /** --json：JSONL 结构化渲染（listen 时自动失效——CLI 禁 --json × 持续监听） */
  json: boolean;
}

/** run_out 行 + run_exit 终态（App 聚合后传入）。 */
export interface RunLine {
  stream: string;
  text: string;
  /** ingestion 时一次解析出的 JSONL 展示视图（null = 非 JSON 行，原样渲染）。
   *  行对象就此定型：控制台 <For> 按对象身份复用 DOM，新行只追加不重建。 */
  view?: RunLineView | null;
}
/** JSONL 行的渲染视图（cls/text/title 在 ingestion 一次算好）。 */
export interface RunLineView {
  cls: string;
  text: string;
  title?: string;
}
/** 一次运行的任务卡（Run 面板多标签；App 聚合 run_out/run_exit）。
 *  fileKey = 发起运行的文档标签（Run 面板按它过滤——每个文件 tab 独立的任务列表）。 */
export interface RunTask {
  id: string;
  fileKey: string;
  /** 运行的文件（工作区相对路径） */
  file: string;
  lines: RunLine[];
  exit: RunExitState | null;
  running: boolean;
  /** 计时段（客户端侧）：run 受理时刻 / 终态落地时刻——chip 显示耗时 */
  startedAt: number;
  endedAt: number | null;
  /** run 已受理但还没有任何输出：控制台给一条 transient 'starting…' 行 */
  starting?: boolean;
}

export interface RunExitState {
  code: number | null;
  stopped: boolean;
  truncated: boolean;
}

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

/** 诊断列表：LSP 诊断 + analyze 构建错误（运行期参数缺失等——LSP 诊断不覆盖）
 *  一并列在本页签；空态给一行提示。 */
export function DiagnosticsPanel(props: { diags: LspDiag[]; buildError?: string | null }) {
  return (
    <div class="panel-body">
      <Show when={props.buildError}>
        <div class="diag diag-error">
          <span class="diag-pos">analyze</span>
          <span class="diag-msg">{props.buildError}</span>
        </div>
      </Show>
      <Show when={props.diags.length > 0}>
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
      <Show when={!props.buildError && props.diags.length === 0}>
        <div class="empty-hint">No diagnostics — document parses clean.</div>
      </Show>
    </div>
  );
}

/** 文档大纲（LSP documentSymbol：component def / func / export / 默认导出）。
 *  点击行号跳转（编辑器滚动到该行）。.pktl 配方无符号——页签不出现。 */
export interface OutlineSym {
  name: string;
  kind: number; // 12=Function 13=Variable(def) 14=Constant(export) 2=Module(default)
  detail: string;
  line: number; // 0-based
}

const KIND_TAG: Record<number, string> = {
  2: "default",
  12: "func",
  13: "def",
  14: "export",
};

export function OutlinePanel(props: { symbols: OutlineSym[]; onJump: (line: number) => void }) {
  return (
    <div class="panel-body">
      <Show
        when={props.symbols.length > 0}
        fallback={<div class="empty-hint">No definitions yet.</div>}
      >
        <For each={props.symbols}>
          {(s) => (
            <div
              class="outline-item"
              title={s.detail || s.name}
              onClick={() => props.onJump(s.line)}
            >
              <span class="badge">{KIND_TAG[s.kind] ?? "sym"}</span>
              <span class="outline-name">{s.name}</span>
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
 *  不在此展示——分析错误归 Diagnostics 页签（空态给指向提示）。 */
export function LayersPanel(props: { doc: AnalyzeDoc | null; buildError?: string | null }) {
  const packets = createMemo(() => allPackets(props.doc));
  return (
    <div class="panel-body">
      <Show
        when={packets().length > 0 || (props.doc?.sniffer?.length ?? 0) > 0}
        fallback={
          <div class="empty-hint">
            {props.buildError
              ? "Build failed — see the Diagnostics tab."
              : "No packets yet — start typing a pipeline."}
          </div>
        }
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
export function HexPanel(props: { doc: AnalyzeDoc | null; buildError?: string | null }) {
  const packets = createMemo(() => allPackets(props.doc));
  return (
    <div class="panel-body">
      <Show
        when={packets().length > 0}
        fallback={
          <div class="empty-hint">
            {props.buildError
              ? "Build failed — see the Diagnostics tab."
              : "No packet bytes."}
          </div>
        }
      >
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

/** HEX 视图渲染封顶：超大包只画前 4096 字节（数据本身仍在，后续复制等
 *  不受限——只裁 DOM）。 */
const HEX_RENDER_CAP_BYTES = 4096;

function HexView(props: { hex: string }) {
  const totalBytes = createMemo(() => props.hex.replace(/\s+/g, "").length / 2);
  const rows = createMemo(() => {
    const hex = props.hex.replace(/\s+/g, "").slice(0, HEX_RENDER_CAP_BYTES * 2);
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
      <Show when={totalBytes() > HEX_RENDER_CAP_BYTES}>
        <div class="hex-row hex-cap-hint">
          +{totalBytes() - HEX_RENDER_CAP_BYTES} bytes not shown
        </div>
      </Show>
    </div>
  );
}

/** 面板页签（.pktl 配方文档切换为 Recipe/Globals 组；Run 页签两种文档都有）。 */
export function PanelTabs(props: {
  panel: Panel;
  setPanel: (p: Panel) => void;
  diagCount: number;
  recipe?: boolean;
  running?: boolean;
}) {
  // 派生而非一次性 signal：props.recipe 随打开文件类型变化，页签须跟随
  const tabs = () => [
    ...(props.recipe
      ? [
          { id: "diagnostics" as Panel, label: "Diagnostics" },
          { id: "recipe" as Panel, label: "Recipe" },
          { id: "globals" as Panel, label: "Globals" },
        ]
      : [
          { id: "diagnostics" as Panel, label: "Diagnostics" },
          { id: "layers" as Panel, label: "Layers" },
          { id: "hex" as Panel, label: "Hex" },
          { id: "outline" as Panel, label: "Outline" },
        ]),
    { id: "run" as Panel, label: "Run" },
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
            <Show when={t.id === "run" && props.running}>
              <span class="tab-badge run-badge" title="process running">
                ●
              </span>
            </Show>
          </button>
        )}
      </For>
    </div>
  );
}

/** JSONL 行 → 渲染视图（ingestion 时调用一次，控制台不再逐帧整表重解析）。
 *  非 JSON 行返回 null（原样文本）。stripRoot 给出工作区根时，step 行的包路径
 *  若带该绝对前缀则剥掉（服务端会逐步 relativize，这里做渲染端兜底）。 */
export function parseRunLine(text: string, stripRoot?: string | null): RunLineView | null {
  let o: any;
  try {
    o = JSON.parse(text);
  } catch {
    return null;
  }
  if (o.type === "packet") {
    const ok = o.status === "sent";
    const layers = Array.isArray(o.layers) ? o.layers.join("·") : "";
    const t = o.target ? " → " + o.target : "";
    const err = o.error ? "  ✗ " + o.error : "";
    const rtt = o.rtt_ms != null ? "  " + o.rtt_ms + "ms" : "";
    // 失败包无 bytes 字段（raw 等失败场景）——有值才显示字节数
    const size = o.bytes != null ? o.bytes + " B " : "";
    return {
      cls: ok ? "run-line-ok" : "run-line-err",
      text: (ok ? "✓ " : "✗ ") + o.idx + "/" + o.total + "  " + (o.proto ?? "") + " " +
        size + layers + t + rtt + err,
      title: text,
    };
  }
  if (o.type === "step") {
    let pkt = String(o.pkt ?? "");
    if (stripRoot) {
      const norm = stripRoot.replace(/\\/g, "/").replace(/\/+$/, "");
      const p = pkt.replace(/\\/g, "/");
      if (norm && p.startsWith(`${norm}/`)) pkt = p.slice(norm.length + 1);
    }
    return {
      cls: "run-line-step",
      text: "step " + o.step + "/" + o.total + ":  " + pkt,
      title: text,
    };
  }
  if (o.type === "summary") {
    const ok = (o.failed ?? o.steps_failed ?? 0) === 0;
    const parts: string[] = [];
    if (o.sent != null) parts.push("sent " + o.sent);
    if (o.failed != null) parts.push("failed " + o.failed);
    if (o.skipped != null) parts.push("skipped " + o.skipped);
    if (o.packets_sent != null) parts.push("packets sent " + o.packets_sent);
    if (o.steps != null) parts.push("steps " + o.steps);
    if (o.steps_failed != null) parts.push("failed " + o.steps_failed);
    return {
      cls: ok ? "run-line-summary" : "run-line-err",
      text: "summary: " + parts.join(" · "),
      title: text,
    };
  }
  return null; // 其它 JSONL 类型：原样文本
}

/** 耗时格式（chip 用）：62s → 1m02s。 */
function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m${String(s % 60).padStart(2, "0")}s`;
}

/** Run 面板：packet 选项 + 执行控制台（服务端 spawn 自身 CLI，见 web/run.rs）。 */
export function RunPanel(props: {
  /** 全部任务卡（运行中 + 已结束）；chip 即任务管理 */
  tasks: RunTask[];
  /** 当前查看的任务 id */
  activeId: string | null;
  setActive: (id: string) => void;
  settings: RunSettings;
  setSettings: (s: RunSettings) => void;
  /** 文件声明的运行参数（params("名", 默认)）；与 Layers 页签共用同一份输入值 */
  declParams: { name: string; default: string | null }[];
  runValues: Record<string, string>;
  setRunValues: (v: Record<string, string>) => void;
  canRun: boolean;
  onRun: () => void;
  onStopTask: (id: string) => void;
  onCloseTask: (id: string) => void;
  /** 停止全部运行中任务（run_stop 不带 id——服务端停本连接全部） */
  onStopAll: () => void;
}) {
  let consoleHost: HTMLDivElement | undefined;
  const active = () => props.tasks.find((t) => t.id === props.activeId) ?? null;
  // 跟随滚动只在「用户本就在底部附近（≤40px）」时进行——上翻阅读历史输出时不拽走
  let stickBottom = true;
  let lastActiveId: string | null | undefined;
  const onConsoleScroll = () => {
    if (!consoleHost) return;
    stickBottom =
      consoleHost.scrollHeight - consoleHost.scrollTop - consoleHost.clientHeight <= 40;
  };
  createEffect(() => {
    const id = props.activeId;
    active()?.lines.length;
    if (id !== lastActiveId) {
      lastActiveId = id;
      stickBottom = true; // 切换任务：从头跟随
    }
    if (consoleHost && stickBottom) consoleHost.scrollTop = consoleHost.scrollHeight;
  });
  // 运行中任务的耗时秒级跳动（只在有运行中任务时开 interval）
  const [nowTick, setNowTick] = createSignal(0);
  createEffect(() => {
    if (!props.tasks.some((tk) => tk.running)) return;
    const iv = setInterval(() => setNowTick((n) => n + 1), 1000);
    onCleanup(() => clearInterval(iv));
  });
  const now = () => {
    nowTick(); // 依赖 tick：运行中任务每秒重算
    return Date.now();
  };
  const taskDuration = (t: RunTask) => fmtDuration((t.endedAt ?? now()) - t.startedAt);
  const set = (patch: Partial<RunSettings>) =>
    props.setSettings({ ...props.settings, ...patch });
  const exitText = () => {
    const e = active()?.exit;
    if (!e) return "";
    if (e.stopped) return "stopped";
    if (e.code == null) return "exit ?"; // unix 被 kill 等无退出码情形
    return "exit " + e.code;
  };
  // 任务卡状态图标（chip 即任务管理：● 运行中 / ✓✗ 终态 / ■ 已停止）
  const taskIcon = (t: RunTask) => {
    if (t.running) return "●";
    if (t.exit?.stopped) return "■";
    if (t.exit?.code == null) return "?";
    return t.exit.code === 0 ? "✓" : "✗";
  };
  // JSONL 模式（settings.json && !listen）：渲染 ingestion 算好的结构化视图；
  // 非 JSON 行（stderr 的 raw 升级提示等）原样回退文本
  const jsonMode = () => props.settings.json && !props.settings.listen;
  return (
    <div class="panel-body run-panel">
      <div class="run-controls">
        <Show
          when={!active()?.running}
          fallback={
            <button
              class="run-stop-btn"
              onClick={() => active() && props.onStopTask(active()!.id)}
              title="stop the active run"
            >
              ■ Stop
            </button>
          }
        >
          <button
            class="run-go-btn"
            disabled={!props.canRun}
            onClick={props.onRun}
            title={
              props.canRun
                ? "run with prping packet — a new task tab is created; runs run in parallel"
                : "open a workspace .pkt/.pktl file to run"
            }
          >
            ▶ Run
          </button>
        </Show>
        <Show when={props.tasks.some((tk) => tk.running)}>
          <button
            class="run-stop-btn"
            onClick={() => props.onStopAll()}
            title="stop all running tasks (run_stop without id stops every task on this connection)"
          >
            ■ Stop all
          </button>
        </Show>
        <span class="run-status" classList={{ running: !!active()?.running }}>
          <Show when={active()} fallback={null}>
            <span>#{active()!.id.replace("run-", "")} </span>
          </Show>
          <Show when={active()?.running} fallback={exitText()}>
            running…
          </Show>
          <Show when={active()?.exit?.truncated}>
            <span
              class="run-truncated"
              title="output line limit reached — process kept running"
            >
              {" "}· truncated
            </span>
          </Show>
        </span>
        <Show when={props.tasks.length > 0}>
          <span class="run-tasks-hint">
            {props.tasks.filter((t) => t.running).length}/{props.tasks.length} tasks
          </span>
        </Show>
      </div>
      {/* 控制台图例（一行）：✓/✗/exit 语义 + 步骤路径基准 */}
      <div class="run-legend">
        ✓ sent · ✗ send/wait failed · exit N — paths are relative to workspace root
      </div>
      {/* 任务列表（任务管理）：有任务即常驻；点行切控制台，■ 停止，✕ 移除 */}
      <Show when={props.tasks.length > 0}>
        <div class="run-task-list">
          <For each={props.tasks}>
            {(t) => {
              const failed = !t.running && !t.exit?.stopped && t.exit?.code != null && t.exit.code !== 0;
              const ok = !t.running && t.exit?.code === 0;
              return (
                <div
                  class="run-task-row"
                  classList={{ active: props.activeId === t.id }}
                  onClick={() => props.setActive(t.id)}
                  title={t.file + "  (" + t.id + ")"}
                >
                  <span
                    class="run-task-state"
                    classList={{ running: t.running, ok, fail: failed }}
                  >
                    {taskIcon(t)}
                  </span>
                  <span class="run-task-id">#{t.id.replace("run-", "")}</span>
                  <span class="run-task-file" title={t.file}>
                    {t.file.split("/").pop()}
                  </span>
                  <span class="run-task-dur">{taskDuration(t)}</span>
                  <span class="run-task-status">
                    {t.running
                      ? "running…"
                      : t.exit?.stopped
                        ? "stopped"
                        : t.exit?.code != null
                          ? "exit " + t.exit.code
                          : "?"}
                  </span>
                  <Show when={t.running}>
                    <button
                      class="run-task-act"
                      title="stop this task"
                      onClick={(e) => {
                        e.stopPropagation();
                        props.onStopTask(t.id);
                      }}
                    >
                      ■ stop
                    </button>
                  </Show>
                  <button
                    class="run-task-act"
                    title="remove from list"
                    onClick={(e) => {
                      e.stopPropagation();
                      props.onCloseTask(t.id);
                    }}
                  >
                    ✕
                  </button>
                </div>
              );
            }}
          </For>
        </div>
      </Show>
      <label class="run-field">
        <span>target</span>
        <input
          value={props.settings.target}
          placeholder="HOST[:PORT]"
          onInput={(e) => set({ target: e.currentTarget.value })}
        />
      </label>
      <div class="run-row">
        <label class="run-mini">
          count
          <input
            class="run-num"
            value={props.settings.count}
            placeholder="1"
            onInput={(e) => set({ count: e.currentTarget.value })}
          />
        </label>
        <label class="run-mini">
          wait s
          <input
            class="run-num"
            value={props.settings.wait}
            placeholder="off"
            onInput={(e) => set({ wait: e.currentTarget.value })}
          />
        </label>
        <label class="run-check" title="bare --wait: keep listening for matched packets">
          <input
            type="checkbox"
            checked={props.settings.listen}
            onInput={(e) => set({ listen: e.currentTarget.checked })}
          />
          listen
        </label>
        <label
          class="run-check"
          title="--json: structured JSONL output (auto-off with listen — CLI forbids the pair)"
        >
          <input
            type="checkbox"
            checked={props.settings.json && !props.settings.listen}
            disabled={props.settings.listen}
            onInput={(e) => set({ json: e.currentTarget.checked })}
          />
          json
        </label>
        <label class="run-check" title="--fuzz">
          <input
            type="checkbox"
            checked={props.settings.fuzz}
            onInput={(e) => set({ fuzz: e.currentTarget.checked })}
          />
          fuzz
        </label>
        <label class="run-check" title="--raw (link-layer send / listen)">
          <input
            type="checkbox"
            checked={props.settings.raw}
            onInput={(e) => set({ raw: e.currentTarget.checked })}
          />
          raw
        </label>
        <Show when={props.settings.raw}>
          <input
            class="run-iface"
            value={props.settings.iface}
            placeholder="--iface"
            onInput={(e) => set({ iface: e.currentTarget.value })}
          />
        </Show>
      </div>
      <Show when={props.declParams.length > 0}>
        <div class="run-params">
          <Index each={props.declParams}>
            {(p) => (
              <label
                class="param-item"
                title={
                  p().default == null
                    ? "required — no default"
                    : "default " + (p().default ?? "")
                }
              >
                <span class="badge">param</span>
                <span
                  class="param-name"
                  classList={{
                    "param-missing": p().default == null && !props.runValues[p().name],
                  }}
                >
                  {p().name}
                </span>
                <input
                  class="param-input"
                  placeholder={p().default ?? "required"}
                  value={props.runValues[p().name] ?? ""}
                  onInput={(e) =>
                    props.setRunValues({ ...props.runValues, [p().name]: e.currentTarget.value })
                  }
                />
              </label>
            )}
          </Index>
        </div>
      </Show>
      <div class="run-console" ref={consoleHost} onScroll={onConsoleScroll}>
        {/* 行对象 ingestion 时定型（raw+view 稳定引用）：<For> 按身份对账，
            新输出只追加 DOM，不再整表重建/重解析 */}
        <For each={active()?.lines ?? []}>
          {(l) => {
            const n = jsonMode() ? l.view : null;
            return n ? (
              <div class={n.cls} title={n.title}>
                {n.text}
              </div>
            ) : (
              <div
                class="run-line"
                classList={{ err: l.stream === "err" }}
                title={jsonMode() ? "raw output line" : undefined}
              >
                {l.text}
              </div>
            );
          }}
        </For>
        {/* run 受理后的过渡行：首条真实输出到达（starting 复位）即消失 */}
        <Show when={active()?.starting}>
          <div class="run-line run-line-step">starting…</div>
        </Show>
        <Show when={(active()?.lines ?? []).length === 0 && !active()?.starting}>
          <div class="empty-hint">
            <Show
              when={active()}
              fallback={
                <>
                  Run starts a task (multiple runs run in parallel — switch via
                  the task chips); set target/count/wait above.
                </>
              }
            >
              <Show when={active()?.running} fallback="no output yet">
                waiting for output…
              </Show>
            </Show>
          </div>
        </Show>
      </div>
    </div>
  );
}
