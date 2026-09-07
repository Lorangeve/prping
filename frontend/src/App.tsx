// prping web —— 应用骨架：顶栏（状态/当前文件/保存）+ 左栏文件管理 + 编辑器 + 右面板。
// 数据流：编辑 →（防抖）→ LSP didChange + analyze 请求 → 诊断/层栈/HEX 更新。
// 文件面：工作区（examples / 自定义文件夹）可编辑保存（Ctrl+S），eng_lib 只读。

import { For, Index, createEffect, createMemo, onCleanup, onMount, createSignal, Show } from "solid-js";

/** analyze 应答带的运行参数声明（params("名", 默认)）；.pktl 聚合声明带
 *  overridden = 任一步骤 params: 覆盖同名（Run 面板输入对它无效，行上标注）。 */
interface DeclParam {
  name: string;
  default: string | null;
  overridden?: boolean;
}

/** 导航历史条目：文件 + 落点行（null = 文件级打开，离开时回填光标行）。 */
interface NavEntry {
  root: "ws" | "lib";
  path: string;
  line0: number | null;
}
import type { EditorView } from "@codemirror/view";
import {
  applyDiagnostics,
  createEditor,
  restoreEditorState,
  revealLine,
  revealPos,
  saveEditorState,
  setDoc,
  setEditable,
  setLinkMode,
  setLinkScope,
  type EditorSnapshot,
} from "./cm";
import { FileSidebar, FolderDialog, type CurrentFile, type TreeEntry } from "./files";
import { draftKey, Keys, kvDel, kvGet, kvKeys, kvSet } from "./store";
import { LspClient, type LspDiagnostic } from "./lsp";
import type { AnalyzeDoc, Panel, RunLine, RunSettings, RunTask } from "./panels";
import {
  DiagnosticsPanel,
  GlobalsPanel,
  HexPanel,
  LayersPanel,
  OutlinePanel,
  PanelTabs,
  ParamRow,
  RecipePanel,
  RunPanel,
  TaskManager,
  parseRunLine,
  stripAnsiEscapes,
  type OutlineSym,
  type RecipeDoc,
} from "./panels";
import { SAMPLE_DOC } from "./sample";
import { renderMarkdown } from "./markdown";
import { PrpingClient, type Status } from "./ws";

// analyze/大纲应答序号（模块级）：快速连续编辑时请求乱序到达，只认最新一次——
// 与 files.tsx FolderDialog 的 browseSeq 同构（uri + seq 双重匹配才落账）
let analyzeSeq = 0;

export function App() {
  const [status, setStatus] = createSignal<Status>("connecting");
  // 侧栏显隐：默认按视口宽度（>940 显示），窗口 resize 重新按宽度判定；
  // 切换按钮在顶栏（side-head 的 actions 行在 files.tsx，此处不动那个文件）
  const [sideVisible, setSideVisible] = createSignal(
    typeof window === "undefined" ? true : window.innerWidth > 940,
  );
  const onResize = () => setSideVisible(window.innerWidth > 940);
  const toggleSide = () => setSideVisible((v) => !v);
  const [libs, setLibs] = createSignal<string[]>([]);
  const [libDirs, setLibDirs] = createSignal<string[]>([]);
  const [diags, setDiags] = createSignal<LspDiagnostic[]>([]);
  const [doc, setAnalyzeDoc] = createSignal<AnalyzeDoc | null>(null);
  // .pktl 配方概览（analyze 信封对配方文档返回配方结构而非层栈）
  const [recipeDoc, setRecipeDoc] = createSignal<RecipeDoc | null>(null);
  // analyze 失败错误（运行期参数缺失/构建错误——LSP 诊断不覆盖这类语义错误）。
  // 不再作横幅盖在 Layers/Hex 上：统一进 Diagnostics 页签（诊断行 + 页签计数），
  // Layers/Hex 空态给指向提示
  const [analyzeErr, setAnalyzeErr] = createSignal<string | null>(null);
  // 去重后的构建错误：解析/语义错误 LSP 与 analyze 都报（analyze 文案含文件路径，
  // 通常包住 LSP 消息）——消息互相包含视为同源，只显示 LSP 行
  const buildErrShown = () => {
    const err = analyzeErr();
    if (!err) return null;
    return diags().some((d) => err.includes(d.message) || d.message.includes(err))
      ? null
      : err;
  };
  // 文档大纲（LSP documentSymbol；.pkt 编辑器 Outline 页签）
  const [symbols, setSymbols] = createSignal<OutlineSym[]>([]);
  // 内置原语名单（config.json 一次性下发）：跳转高亮据此排除「无定义可跳」的调用名
  const [builtins, setBuiltins] = createSignal<Set<string>>(new Set());
  // Layers 页签顶的运行参数：文件声明过（params("名", 默认)）则渲染结构化输入行，
  // 否则退回自由文本 k=v；值随每次 analyze 传给服务端构建
  const [runParams, setRunParams] = createSignal("");
  const [runValues, setRunValues] = createSignal<Record<string, string>>({});
  const [declParams, setDeclParams] = createSignal<DeclParam[]>([]);

  // 右侧面板页签是全局的用户选择：切/开任何文件都不重置——a.pktl 停在 Run，
  // 打开 b.pktl 右栏仍是 Run。仅当所选页签在当前文件类型不存在时读侧就地
  // 矫正（配方无 Layers/Hex/Outline → Recipe；普通文件无 Recipe/Globals →
  // Layers；md 无侧栏）。
  const [panelSel, setPanelSel] = createSignal<Panel>("layers");
  function coercePanel(p: Panel): Panel {
    if (isPktl()) return p === "layers" || p === "hex" || p === "outline" ? "recipe" : p;
    if (isMd()) return p === "recipe" || p === "globals" ? "diagnostics" : p;
    return p === "recipe" || p === "globals" ? "layers" : p;
  }
  const panel = () => coercePanel(panelSel());
  function setPanel(p: Panel) {
    setPanelSel(p);
  }
  const [version, setVersion] = createSignal("");

  // ── 执行（Run 页签）────────────────────────────────────
  // 服务端 spawn 自身 CLI 的 packet 子命令（web/run.rs）；run_id 关联流式输出。
  // 多标签并行运行：每个 run 一个任务卡（任务管理），chip 切换控制台。
  const [runSettings, setRunSettings] = createSignal<RunSettings>({
    count: "1",
    wait: "",
    listen: false,
    fuzz: false,
    raw: false,
    iface: "",
    json: true, // 默认 JSONL 结构化渲染（listen 时自动失效）
  });
  const [runTasks, setRunTasks] = createSignal<RunTask[]>([]);
  // 每文件（fileKey = root:path）的会话内运行计数：任务卡展示号 #n 的取号器。
  // 单调不复用（移除任务卡不清号——「第几次运行」语义）；重连 = 新会话，与
  // 任务卡一起清零（onStatus "connected"）。id 本身仍是服务端传输层句柄 run-N。
  const runSeqPerFile = new Map<string, number>();
  const [activeRunId, setActiveRunId] = createSignal<string | null>(null);
  // 控制台行数上限（与 MAX_RUN_LINES 转发上限独立；超限从头丢弃）
  const MAX_UI_RUN_LINES = 4000;
  // 任务卡数量上限：超出丢弃最旧（服务端并发另有全局 8 上限）
  const MAX_UI_RUN_TASKS = 24;
  // 当前视图的任务：手动选中的任务若属于其它文件标签，则自动落到本文件最新任务
  const activeTask = () => {
    const k = activeKey();
    const inFile = runTasks().filter((t) => t.fileKey === k);
    const picked = inFile.find((t) => t.id === activeRunId());
    return picked ?? inFile[inFile.length - 1] ?? null;
  };
  const fileHasRunning = (key: string | null) =>
    runTasks().some((t) => t.running && t.fileKey === key);

  // Markdown 视图：渲染（renderMarkdown HTML）/ 编辑（源码）——仅 .md 文件用
  const [mdMode, setMdMode] = createSignal<"render" | "edit">("render");

  // 文件管理：工作区树 / 文档标签页（每打开一个文件一个 tab）/ 已保存文本
  const [wsRoot, setWsRoot] = createSignal<string | null>(null);
  const [entries, setEntries] = createSignal<TreeEntry[]>([]);
  // 文档标签：打开过的文件都保留一个 tab（内容驻内存，切回即还原）；key = root:path
  interface DocTab {
    file: CurrentFile;
    /** 离开该 tab 时的编辑器内容快照（含未保存修改） */
    text: string;
    savedText: string;
    /** 该文件的运行参数输入（与其它 tab 相互独立——右栏数据随 tab 隔离） */
    runValues: Record<string, string>;
    runParams: string;
    /** 离开时的编辑器整档快照（undo 历史/选区/滚动）——切回整体还原，
     *  Ctrl+Z 绝不串到别的文件（cm.saveEditorState / restoreEditorState） */
    editor?: EditorSnapshot;
  }
  const [tabs, setTabs] = createSignal<DocTab[]>([]);
  const [activeKey, setActiveKey] = createSignal<string | null>(null);
  const tabKey = (f: { root: string; path: string }) => `${f.root}:${f.path}`;
  /** 当前文件 = 活跃 tab 的文件（tab 未开时 null） */
  const current = () => {
    const k = activeKey();
    return k ? (tabs().find((tb) => tabKey(tb.file) === k)?.file ?? null) : null;
  };
  /** 离开当前 tab 前把编辑器实时内容与运行参数写回标签（切走/关闭前的落账）；
   *  编辑器整档快照一并存入（undo 历史/选区/滚动随标签走）。 */
  function syncActiveTab() {
    const k = activeKey();
    if (!k) return;
    const t = text();
    const s = savedText() ?? "";
    const rv = runValues();
    const rp = runParams();
    const ed = view ? saveEditorState(view) : undefined;
    setTabs((ts) =>
      ts.map((tb) => (tabKey(tb.file) === k ? { ...tb, text: t, savedText: s, runValues: rv, runParams: rp, editor: ed } : tb)),
    );
  }
  const [text, setText] = createSignal(SAMPLE_DOC);
  const [savedText, setSavedText] = createSignal<string | null>(SAMPLE_DOC);
  const [fileMsg, setFileMsg] = createSignal<string | null>(null);
  // 与磁盘不同的本地草稿：**默认不恢复**（磁盘为准），显式点击才载入——
  // 此前草稿静默压过磁盘，被历史 bug 污染的草稿会让每次打开都错
  const [pendingDraft, setPendingDraft] = createSignal<{ path: string; text: string } | null>(
    null,
  );

  // ── 导航历史（返回/前进）────────────────────────────────
  // 落点条目 = 文件 + 打开/跳转时的行。离开某条目时把其行号刷新为光标行，
  // 「返回」因此能回到离开时的位置（含同文件内的定义跳转）。
  const [navList, setNavList] = createSignal<NavEntry[]>([]);
  const [navIdx, setNavIdx] = createSignal(-1);
  let navigating = false; // 返回/前进触发的文件打开不再入栈

  let editorHost!: HTMLDivElement;
  let view: EditorView;
  let autoOpened = false; // 首次连接后自动打开一个工作区文件（重连不重复触发）

  let analyzeTimer: ReturnType<typeof setTimeout> | null = null;
  let changeTimer: ReturnType<typeof setTimeout> | null = null;
  let draftTimer: ReturnType<typeof setTimeout> | null = null;

  const client = new PrpingClient();
  const lsp = new LspClient(client);

  // 服务端 → 客户端的 LSP 消息（initialize 应答 / publishDiagnostics / 补全悬停
  // 应答）全部经此回调进入 LspClient——漏接则诊断与补全全哑
  client.onLsp = (m) => lsp.handle(m);

  // packet 运行输出/终态（run 信封启动后按 run_id 归入对应任务卡；断线重连后
  // 旧会话的 run 已被服务端收杀，未知 id 的输出直接忽略）。
  // 输出走「缓冲 + rAF 合帧」：高频 run_out 不再逐封 setRunTasks；行对象在
  // ingestion 一次成形（多行拆分 + JSONL 预解析），控制台 <For> 按对象身份复用
  const runLineBuf: { run: string; stream: string; text: string }[] = [];
  let runFlushScheduled = false;
  const flushRunLines = () => {
    runFlushScheduled = false;
    if (runLineBuf.length === 0) return;
    const batch = runLineBuf.splice(0, runLineBuf.length);
    setRunTasks((ts) => {
      // 按任务归并追加；任务已被移除（用户关卡）的输出直接丢弃
      const byRun = new Map<string, RunLine[]>();
      for (const b of batch) {
        const arr = byRun.get(b.run) ?? [];
        const view = parseRunLine(b.text, wsRoot());
        // 非 JSON 行原样回退，但剥 ANSI 转义兜底（服务端已注入 NO_COLOR，此为
        // 二道防线）；JSON 行的 text 保留原始载荷（转义可能是包数据的一部分）
        arr.push({ stream: b.stream, text: view ? b.text : stripAnsiEscapes(b.text), view });
        byRun.set(b.run, arr);
      }
      let touched = false;
      const next = ts.map((t) => {
        const add = byRun.get(t.id);
        if (!add) return t;
        touched = true;
        byRun.delete(t.id);
        const lines = [...t.lines, ...add];
        return {
          ...t,
          starting: false, // 首条真实输出到达：'starting…' 过渡行退场
          lines: lines.length > MAX_UI_RUN_LINES ? lines.slice(lines.length - MAX_UI_RUN_LINES) : lines,
        };
      });
      return touched ? next : ts;
    });
  };
  client.onRunOut = (run, stream, text) => {
    // 服务端开始合并多行：同一 payload 可能带多条 \n 分隔行（单行向后兼容）；
    // 行内不产生空行——行边界即换行符
    for (const ln of text.split("\n")) {
      if (ln.length > 0) runLineBuf.push({ run, stream, text: ln });
    }
    if (runLineBuf.length === 0 || runFlushScheduled) return;
    runFlushScheduled = true;
    if (typeof requestAnimationFrame === "function") requestAnimationFrame(flushRunLines);
    else setTimeout(flushRunLines, 16); // 无 rAF 环境兜底
  };
  client.onRunExit = (run, exit) => {
    setRunTasks((ts) =>
      ts.map((t) =>
        t.id === run
          ? { ...t, exit, running: false, endedAt: Date.now(), starting: false }
          : t,
      ),
    );
  };

  // 非致命提示（item 1）：fileMsg 区域展示，几秒后自动消失（文案未被覆盖才清）
  let fileMsgClearTimer: ReturnType<typeof setTimeout> | null = null;
  function notify(msg: string) {
    setFileMsg(msg);
    if (fileMsgClearTimer) clearTimeout(fileMsgClearTimer);
    fileMsgClearTimer = setTimeout(() => {
      setFileMsg((cur) => (cur === msg ? null : cur));
    }, 5000);
  }
  // 服务端拒绝（error 信封）与非正常断线：非致命提示（自动消失，不挡编辑）
  client.onServerError = (m) => notify(`server: ${m}`);

  // 诊断推送 → 编辑器 squiggle + 右侧面板（Markdown 打开时忽略旧文档残留推送）
  lsp.onDiagnostics = (d) => {
    if (isMd()) return;
    setDiags(d);
    if (view) applyDiagnostics(view, d);
  };

  const dirty = () => current()?.root === "ws" && text() !== savedText();

  // Markdown 文档：引擎 LSP 不适用（诊断/补全/悬停停用），顶栏切渲染/编辑
  const isMd = () => (current()?.path ?? "").toLowerCase().endsWith(".md");
  // .pktl 配方文档：侧栏切 Recipe/Globals 页签，analyze 返回配方概览
  const isPktl = () => (current()?.path ?? "").toLowerCase().endsWith(".pktl");
  // 文档是否引用运行参数（params(...)）：完全没用就不渲染 params 输入区
  const usesRunParams = () => /\bparams\s*\(/.test(text());

  // 可跳名字集（Ctrl 高亮/候选判定用）：本地符号（defs/funcs/exports/默认导出
  // 名，来自 documentSymbol）+ import 行引入的名字（含 as 别名）与模块名。
  // 注意放 text/view 声明之后——Solid 的 memo 创建即求值。
  const linkNames = createMemo(() => {
    const names = new Set<string>();
    for (const s of symbols()) names.add(s.name);
    for (const line of text().split("\n")) {
      const m = /^\s*import\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*\{([^}]*)\})?/.exec(line);
      if (!m) continue;
      names.add(m[1]!);
      if (m[2]) {
        for (const item of m[2].split(",")) {
          const name = item.trim().split(/\s+as\s+/i)[0]?.trim();
          if (name) names.add(name);
        }
      }
    }
    return names;
  });

  createEffect(() => {
    // 先读依赖再判 view：guard 放前面会让 Solid 首次运行不跟踪任何依赖，
    // effect 永不重跑，scope 恒为空集（高亮/点击脱节）。
    const names = linkNames();
    const b = builtins();
    if (!view) return;
    setLinkScope(view, { names, builtins: b });
  });

  client.onStatus = (s) => {
    setStatus(s);
    if (s === "connected") {
      // 重连 = 新 WS 会话：旧会话的运行已被服务端收杀，任务卡随之清空；
      // 取号器一并归零（新会话每文件从 #1 重新起号）
      setRunTasks([]);
      runSeqPerFile.clear();
      setActiveRunId(null);
      // 首连与重连统一在此初始化（WS OPEN 后才可发送）：重建 LSP 会话并
      // 重放当前文档、刷新分析/库列表/工作区树（重连后服务端工作区回到默认）
      if (!isMd()) {
        lsp.start(lsp.documentUri, text());
        refreshAnalyze();
      }
      refreshLibs();
      refreshTree();
    }
  };

  function refreshAnalyze() {
    // Markdown：不进 analyze 管线（引擎 LSP/analyze 不适用）
    if (isMd()) return;
    if (analyzeTimer) clearTimeout(analyzeTimer);
    analyzeTimer = setTimeout(async () => {
      // 请求序号：应答往返期间再编辑/再切换会发出更新的请求，过期应答整体丢弃
      const seq = ++analyzeSeq;
      void refreshSymbols(seq); // 大纲与 analyze 同节奏刷新（共享同一序号）
      // 请求时刻的文档：应答往返期间文件可能已切换，过期应答直接丢弃；
      // 配方判定也按请求时 URI（isPktl() 是应答到达时的状态，快速切换会灌错面板）
      const uri = lsp.documentUri;
      const res = await client.analyze(uri, text(), buildRunParams());
      if (seq !== analyzeSeq || uri !== lsp.documentUri) return; // 过期应答：文件已切换或有新请求
      if (isMd()) return; // 已切到 Markdown：面板已停用，不接收 analyze 结果
      // 声明的运行参数成功/失败应答都带：结构化输入行的数据源。按请求时文件
      // 类型分流：.pkt 用 analyze 带回的 params("名",默认) 声明；.pktl 用配方
      // 概览聚合的 decl（步骤 .pkt 声明 + 步骤 params: 覆盖标记）——概览的
      // params 是步骤键值表，形状不同，灌进输入行会渲染成空名行（历史 bug）。
      // 声明未变（打参数值时最常见的情形）不替换——新数组会触发下游重建。
      const data = res.data as { params?: DeclParam[]; decl?: DeclParam[] } | undefined;
      if (uri.toLowerCase().endsWith(".pktl")) {
        const decl = res.ok ? (data?.decl ?? []) : []; // 配方解析失败：步骤文件不可知，清空
        const prev = declParams();
        const same =
          prev.length === decl.length &&
          prev.every(
            (p, i) =>
              p.name === decl[i].name &&
              p.default === decl[i].default &&
              p.overridden === decl[i].overridden,
          );
        if (!same) setDeclParams(decl);
      } else {
        const decl = data?.params;
        if (decl) {
          const prev = declParams();
          const same =
            prev.length === decl.length &&
            prev.every((p, i) => p.name === decl[i].name && p.default === decl[i].default);
          if (!same) setDeclParams(decl);
        }
      }
      if (!res.ok) {
        // 构建失败（如 params('ip') 未提供）：LSP 不报这类错误——进 Diagnostics 页签。
        // 上一次的成功结果同时清掉：Layers/Hex 空态显示「Build failed」指向提示，
        // 不无声展示陈旧层栈
        setAnalyzeErr(res.error as string);
        setAnalyzeDoc(null);
        setRecipeDoc(null);
        return;
      }
      setAnalyzeErr(null);
      if (uri.toLowerCase().endsWith(".pktl")) {
        // 配方文档：数据是 globals/params/steps 概览，层栈/HEX 置空
        setRecipeDoc(res.data as RecipeDoc);
        setAnalyzeDoc(null);
      } else {
        setAnalyzeDoc(res.data as AnalyzeDoc);
        setRecipeDoc(null);
      }
    }, 250);
  }

  /** 文档符号（Outline 页签）：md/配方无符号——清空即可。应答过期丢弃
   *  （seq 由 refreshAnalyze 发放：大纲与 analyze 同批次、同生命周期）。 */
  async function refreshSymbols(seq: number) {
    if (isMd() || isPktl()) {
      setSymbols([]);
      return;
    }
    const uri = lsp.documentUri;
    const res = await lsp.documentSymbol();
    if (seq !== analyzeSeq || uri !== lsp.documentUri || isMd() || isPktl()) return;
    const arr = Array.isArray(res) ? res : [];
    setSymbols(
      arr.map((s: any) => ({
        name: s.name ?? "",
        kind: s.kind ?? 0,
        detail: s.detail ?? "",
        line: s.range?.start?.line ?? 0,
      })),
    );
  }

  /** Markdown 标题大纲：与渲染器同规则（围栏内 # 不算标题），index 对应渲染后
   *  DOM 里 h1..h6 的出现序，点击滚动定位；编辑模式走编辑器行跳转。 */
  const mdOutlineItems = createMemo(() => {
    const out: { level: number; text: string; index: number; line: number }[] = [];
    let inFence = false;
    text().split("\n").forEach((line, ln) => {
      if (line.startsWith("```")) inFence = !inFence;
      if (inFence) return;
      const m = /^(#{1,6})\s+(.*)$/.exec(line);
      if (m) out.push({ level: m[1].length, text: m[2].trim(), index: out.length, line: ln });
    });
    return out;
  });

  let mdRenderHost!: HTMLElement;
  function jumpMdHeading(h: { index: number; line: number }) {
    if (mdMode() === "render") {
      const heads = mdRenderHost?.querySelectorAll("h1,h2,h3,h4,h5,h6");
      heads[h.index]?.scrollIntoView({ behavior: "smooth", block: "start" });
    } else if (view) {
      revealLine(view, h.line);
    }
  }

  async function refreshLibs() {
    const list = await client.listLibs();
    if (list.ok) {
      setLibs(list.data.files as string[]);
      setLibDirs(list.data.dirs as string[]);
    }
  }

  async function refreshTree() {
    const res = await client.tree();
    if (!res.ok) return;
    let list = (res.data.entries as TreeEntry[]) ?? [];
    setWsRoot((res.data.root as string | null) ?? null);
    setEntries(list);
    // 草稿 GC（best effort）：树里已不存在的 draft:ws:* 一并清掉（文件被外部
    // 删除/改名后，残留草稿不再随「恢复草稿」反复复活）
    void kvKeys("draft:ws:").then((keys) => {
      for (const k of keys) {
        const p = k.slice("draft:ws:".length);
        if (!list.some((e) => !e.dir && e.path === p)) void kvDel(k);
      }
    });
    if (!autoOpened) {
      autoOpened = true;
      // 恢复持久化的自定义工作区根（服务端会话随重连/重载重置；目录已不存在
      // 则清除持久化记录，落回默认 examples）
      const savedRoot = await kvGet<string>(Keys.workspaceRoot);
      if (savedRoot && savedRoot !== (res.data.root as string | null)) {
        const r = await client.openFolder(savedRoot);
        if (r.ok) {
          setWsRoot((r.data as { root: string | null }).root ?? null);
          const res2 = await client.tree();
          if (res2.ok) {
            list = (res2.data.entries as TreeEntry[]) ?? [];
            setEntries(list);
          }
        } else {
          void kvDel(Keys.workspaceRoot);
        }
      }
      // 恢复上次打开的文件（不在树里也尝试读，服务端报错即走兜底）；
      // 无记录则自动打开第一个工作区文件（空工作区保持内置示例文档）
      const last = await kvGet<CurrentFile>(Keys.lastFile);
      if (last?.root === "ws" && last.path) void openWsFile(last.path);
      else if (last?.root === "lib" && last.path) void openLib(last.path);
      else {
        const first = list.find((e) => !e.dir);
        if (first) void openWsFile(first.path);
      }
    }
  }

  /** 草稿防抖落库：调度时刻即抓取 {key, text} 快照——回调里用的是调度瞬间的
   *  内容与路径，防抖期间切文件不会把新文件内容写进旧文件的草稿键（竞态修复）。
   *  仅工作区文件（eng_lib 只读不产生差异）。 */
  function scheduleDraft() {
    const cur = current();
    if (!cur || cur.root !== "ws") return;
    if (draftTimer) clearTimeout(draftTimer);
    const snapshot = { key: draftKey("ws", cur.path), text: text() };
    draftTimer = setTimeout(() => void kvSet(snapshot.key, snapshot.text), 1000);
  }

  /** 把所有「内容 ≠ 已保存文本」的工作区标签刷进草稿库（后台标签也保住）。
   *  关标签 / 切文件 / 根组件卸载三个时机调用。 */
  function flushAllDrafts() {
    for (const tb of tabs()) {
      if (tb.file.root === "ws" && tb.text !== tb.savedText) {
        void kvSet(draftKey("ws", tb.file.path), tb.text);
      }
    }
  }

  function onEditorUpdate(t: string) {
    setText(t);
    // Markdown：无 LSP 全文同步 / 分析——只走草稿持久化
    if (isMd()) {
      scheduleDraft();
      return;
    }
    // LSP 全文同步 + 分析共用一个防抖节奏
    if (changeTimer) clearTimeout(changeTimer);
    changeTimer = setTimeout(() => lsp.change(t), 250);
    refreshAnalyze();
    // 草稿持久化（防抖 1s）
    scheduleDraft();
  }

  /** 自由文本运行参数 → {ip:…, seq:…}：一行一个 k=v（首个 = 分隔；空行/无 = 跳过） */
  function parseRunParams(s: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const line of s.split("\n")) {
      const tok = line.trim();
      if (!tok) continue;
      const i = tok.indexOf("=");
      if (i > 0) out[tok.slice(0, i).trim()] = tok.slice(i + 1).trim();
    }
    return out;
  }

  /** analyze 运行参数：声明过的文件用结构化输入值，否则退回自由文本解析 */
  function buildRunParams(): Record<string, string> {
    if (declParams().length > 0) return { ...runValues() };
    return parseRunParams(runParams());
  }

  // ── 执行（Run 页签 / 顶栏 ▶）────────────────────────────

  const isPktFile = () => {
    const p = (current()?.path ?? "").toLowerCase();
    return p.endsWith(".pkt") || p.endsWith(".pktl");
  };
  // 只运行工作区文件（库文件只读；服务端同样按工作区根解析校验）
  const canRun = () => current()?.root === "ws" && isPktFile();

  /** 选项快照 → run 信封字段（空值字段不发，服务端按 CLI 缺省）。 */
  function buildRunOpts(name: string) {
    const s = runSettings();
    const wait: number | true | undefined = s.listen
      ? true
      : s.wait.trim() === ""
        ? undefined
        : Number(s.wait);
    const count =
      s.count.trim() === "" || Number(s.count) === 1 ? undefined : Number(s.count);
    return {
      name,
      // 不发 target：发包地址属于包字段（params 注入），引擎从包内推导 socket
      // 目标；CLI 位置 HOST:PORT 的显式覆盖旁路不进 webui。
      params: buildRunParams(),
      count: Number.isFinite(count) ? count : undefined,
      wait: typeof wait === "number" && !Number.isFinite(wait) ? undefined : wait,
      fuzz: s.fuzz || undefined,
      raw: s.raw || undefined,
      iface: s.raw && s.iface.trim() ? s.iface.trim() : undefined,
      // listen（裸 --wait）与 --json 冲突：CLI 校验会拒绝，前端直接不发
      json: s.json && !s.listen || undefined,
    };
  }

  async function doRun() {
    const cur = current();
    if (!cur) return;
    if (!canRun()) {
      setFileMsg("run: open a workspace .pkt/.pktl file first");
      return;
    }
    // 选项快速校验（服务端只兜底，这里给即时反馈）
    const s = runSettings();
    if (!s.listen && s.wait.trim() !== "" && (!Number.isFinite(Number(s.wait)) || Number(s.wait) < 0)) {
      setFileMsg("run: wait must be a non-negative number of seconds");
      return;
    }
    if (s.count.trim() !== "" && (!Number.isInteger(Number(s.count)) || Number(s.count) < 1)) {
      setFileMsg("run: count must be a positive integer");
      return;
    }
    // Run = 执行所见：未保存修改先落盘（失败即中止——运行的必须是磁盘内容）
    if (dirty()) {
      await saveCurrent();
      if (text() !== savedText()) {
        setFileMsg("run: save failed — fix the file and retry");
        return;
      }
    }
    const res = await client.run(buildRunOpts(cur.path));
    if (!res.ok) {
      setFileMsg("run: " + res.error);
      return;
    }
    // 新任务卡入列（归属当前文档标签；超上限丢最旧）；视图切到新任务。
    // startedAt/endedAt 客户端计时；starting = 受理未出输出（控制台 'starting…' 行）。
    // n = 本文件的会话内运行序号（展示 #n；移除不复用，重连随 Map 清零）
    const fkey = tabKey(cur);
    const n = (runSeqPerFile.get(fkey) ?? 0) + 1;
    runSeqPerFile.set(fkey, n);
    const task: RunTask = {
      id: (res.data as { run: string }).run,
      n,
      fileKey: fkey,
      file: cur.path,
      lines: [],
      exit: null,
      running: true,
      startedAt: Date.now(),
      endedAt: null,
      starting: true,
    };
    setRunTasks((ts) => {
      const next = [...ts, task];
      return next.length > MAX_UI_RUN_TASKS ? next.slice(next.length - MAX_UI_RUN_TASKS) : next;
    });
    // 新任务即最新执行项：控制台总是跟随它（任务列表里仍可点回旧任务）
    setActiveRunId(task.id);
    setPanelPersist("run");
  }

  async function doStop() {
    const id = activeTask()?.id;
    if (!id) return;
    await client.runStop(id); // 终态经 run_exit 回调落地
  }

  /** 停全部：run_stop 不带 id——服务端停本连接所有运行（终态逐个 run_exit 推回）。 */
  function doStopAll() {
    void client.runStop();
  }

  /** 任务管理器点行导航：控制台切到该任务；任务属其它文件标签时经 applyOpen
   *  reopen 激活该标签（沿用标签内存内容，未保存修改不丢），最后右栏切 Run。
   *  关闭文件标签会移除其任务卡，导航目标必然是已开标签（找不到即静默忽略）。 */
  function openTask(id: string) {
    const t = runTasks().find((tk) => tk.id === id);
    if (!t) return;
    setActiveRunId(id);
    if (activeKey() !== t.fileKey) {
      const tab = tabs().find((tb) => tabKey(tb.file) === t.fileKey);
      if (tab) {
        applyOpen(tab.file, "", fileUri(
          tab.file.root === "ws" ? (wsRoot() ?? "") : "",
          tab.file.path,
        ));
      }
    }
    setPanelPersist("run");
  }

  /** 任务管理：停止单个任务（chip ✕ / 列表操作）；终态经 run_exit 落地后由 onCloseTask 移除 */
  async function onStopTask(id: string) {
    await client.runStop(id);
  }

  /** 从任务列表移除一个任务（运行中的先停）；若是当前视图则切到相邻任务 */
  function onCloseTask(id: string) {
    setRunTasks((ts) => {
      const idx = ts.findIndex((t) => t.id === id);
      if (idx < 0) return ts;
      if (ts[idx].running) void client.runStop(id);
      const next = ts.filter((t) => t.id !== id);
      setActiveRunId((cur) =>
        cur === id ? (next[idx]?.id ?? next[next.length - 1]?.id ?? null) : cur,
      );
      return next;
    });
  }

  function updateRunSettings(s: RunSettings) {
    setRunSettings(s);
    void kvSet(Keys.runSettings, s);
  }

  /** 工作区文件 → file:// URI（Windows 盘符路径折叠为 /C:/ 形式；LSP/analyze
   *  据此把 import 解析到文件所在目录，模块名取文件名）。 */
  function fileUri(root: string, rel: string): string {
    let p = `${root}/${rel}`.replace(/\\/g, "/");
    if (!p.startsWith("/")) p = `/${p}`;
    return `file://${p}`;
  }

  /** 打开文件的统一落点：创建/激活文档标签 + 替换编辑器文档 + LSP 会话重放 +
   *  立即分析。`saved` 为磁盘文本（草稿恢复时与编辑器文本不同 → 呈现未保存状态）；
   *  `opts.reload` = 显式磁盘重载（↺），覆盖标签里未保存的内容。已开的标签默认
   *  **激活既有内容**（含未保存修改），不用请求带来的磁盘版本覆盖。 */
  function applyOpen(
    file: CurrentFile,
    content: string,
    uri: string,
    saved?: string,
    opts?: { reload?: boolean },
  ) {
    // 离开位置要在换文档前抓（此后光标随 setDoc 落回新文档开头）
    const depart = navDeparture();
    syncActiveTab(); // 旧 tab 内容落账
    flushAllDrafts(); // 切档时机：所有脏标签（含刚落账的）草稿入库
    const key = tabKey(file);
    const idx = tabs().findIndex((tb) => tabKey(tb.file) === key);
    const reopen = idx >= 0 && !opts?.reload;
    // 已开标签且非重载：沿用标签内存内容（可能含未保存修改），丢弃请求的磁盘版本。
    // 运行参数输入（runValues/runParams）同样随标签隔离：恢复旧标签的、新标签从空开始
    const useContent = reopen ? tabs()[idx].text : content;
    const useSaved = reopen ? tabs()[idx].savedText : (saved ?? content);
    const useRunValues = reopen ? tabs()[idx].runValues : {};
    const useRunParams = reopen ? tabs()[idx].runParams : "";
    if (idx >= 0) {
      setTabs((ts) =>
        ts.map((tb, i) =>
          i === idx ? { ...tb, text: useContent, savedText: useSaved, runValues: useRunValues, runParams: useRunParams } : tb,
        ),
      );
    } else {
      setTabs((ts) => [...ts, { file, text: useContent, savedText: useSaved, runValues: useRunValues, runParams: useRunParams }]);
    }
    setActiveKey(key);
    setRunValues(useRunValues);
    setRunParams(useRunParams);
    if (reopen && tabs()[idx].editor) {
      // 切回已开标签：整档快照还原（undo 历史/选区/滚动随该文件走，绝不串档）
      restoreEditorState(view, tabs()[idx].editor!);
    } else {
      // 首次打开 / 显式重载：整档重建（history 从零开始，Ctrl+Z 不跨文件）
      setDoc(view, useContent);
    }
    setText(useContent);
    setSavedText(useSaved);
    // 整档重建/还原后链接 scope 需与新档对齐；名字集恰好未变时下游 effect 不重跑，
    // 这里强制补发一次（cm.setLinkScope 内部有浅比较挡重复重配）
    setLinkScope(view, { names: linkNames(), builtins: builtins() });
    setFileMsg(null);
    setAnalyzeErr(null);
    setDeclParams([]); // 新文件的参数声明待首次 analyze 返回
    setPendingDraft(null);
    setEditable(view, file.root === "ws");
    // 跳转链接模式随文件类型切换（md 无跳转目标）
    setLinkMode(view, isMd() ? "md" : isPktl() ? "pktl" : "pkt");
    // 入导航栈（返回/前进的落点）；返回/前进自身的打开经 navigating 跳过
    pushNav({ root: file.root, path: file.path, line0: null }, depart);
    if (isMd()) {
      // Markdown：不进 LSP 会话（诊断/补全/悬停停用）；清残留诊断与面板
      setDiags([]);
      setAnalyzeDoc(null);
      setRecipeDoc(null);
      setSymbols([]);
      setMdMode("render");
      if (view) applyDiagnostics(view, []);
      return;
    }
    lsp.openDoc(uri, useContent);
    refreshAnalyze();
  }

  async function openWsFile(path: string, opts?: { reload?: boolean }) {
    // 已开标签：直接激活（保留未保存内容），不重读磁盘（↺ 显式重载除外）
    const key = tabKey({ root: "ws", path });
    if (!opts?.reload && tabs().some((tb) => tabKey(tb.file) === key)) {
      applyOpen({ root: "ws", path }, "", fileUri(wsRoot() ?? "", path));
      void kvSet(Keys.lastFile, { root: "ws", path });
      return;
    }
    const res = await client.readWs(path);
    if (!res.ok) {
      setFileMsg(res.error as string);
      return;
    }
    const root = wsRoot();
    const disk = (res.data as { text: string }).text;
    // 草稿恢复：浏览器库里存有未落盘文本（≠ 磁盘）则给出恢复入口（磁盘已加载）。
    // 注意必须放在 applyOpen 之后——applyOpen 会清 pendingDraft/fileMsg
    const draft = await kvGet<string>(draftKey("ws", path));
    applyOpen(
      { root: "ws", path },
      disk,
      root ? fileUri(root, path) : `file:///${path}`,
      disk,
      opts,
    );
    if (draft != null && draft !== disk) {
      setPendingDraft({ path, text: draft });
      setFileMsg("draft from last session differs from disk — disk loaded; restore draft to switch");
    }
    void kvSet(Keys.lastFile, { root: "ws", path });
  }

  async function openLib(name: string) {
    // 库文件只读、内容不变：已开标签直接激活
    const key = tabKey({ root: "lib", path: name });
    if (tabs().some((tb) => tabKey(tb.file) === key)) {
      applyOpen({ root: "lib", path: name }, "", `file:///${name}`);
      void kvSet(Keys.lastFile, { root: "lib", path: name });
      return;
    }
    const res = await client.readLib(name);
    if (!res.ok) {
      setFileMsg(res.error as string);
      return;
    }
    applyOpen({ root: "lib", path: name }, (res.data as { text: string }).text, `file:///${name}`);
    void kvSet(Keys.lastFile, { root: "lib", path: name });
  }

  /** Recipe 面板步骤的包文件名点击 → 打开对应包。pkgPath 是服务端按配方所在
   *  目录解析出的绝对路径，剪掉工作区根即得树内相对路径（resolve_rel 不折叠
   *  ./..，这里顺带规整）。 */
  function openRecipePkg(pkgPath: string) {
    const root = wsRoot();
    if (!pkgPath) return;
    if (!root || current()?.root !== "ws") {
      setFileMsg("packet file lives outside the current workspace");
      return;
    }
    let rel = pkgPath.replace(/\\/g, "/");
    const rootNorm = root.replace(/\\/g, "/").replace(/\/+$/, "");
    if (rel.startsWith(`${rootNorm}/`)) {
      rel = rel.slice(rootNorm.length + 1);
    } else {
      rel = rel.split("/").pop() ?? rel; // 前缀不匹配（挂载差异）兜底按文件名在工作区找
    }
    const parts: string[] = [];
    for (const seg of rel.split("/")) {
      if (!seg || seg === ".") continue;
      if (seg === "..") parts.pop();
      else parts.push(seg);
    }
    void openWsFile(parts.join("/"));
  }

  // ── 跳转（go-to-definition）与导航历史 ────────────────────

  /** 光标当前行（0 基）；编辑器未就绪时 null。 */
  function cursorLine0(): number | null {
    if (!view) return null;
    try {
      return view.state.doc.lineAt(view.state.selection.main.head).number - 1;
    } catch {
      return null;
    }
  }

  /** 离开位置快照（当前文件 + 光标行）。跨文件打开要在 setDoc/切标签之前
   *  抓取——那时编辑器仍是旧文档，光标还在离开处。 */
  function navDeparture(): { root: "ws" | "lib" | null; path: string | null; line0: number | null } | null {
    const cur = current();
    return cur ? { root: cur.root, path: cur.path, line0: cursorLine0() } : null;
  }

  /** 记录一次导航落点：先把离开条目的行号刷新为离开时的光标行（返回时回到
   *  离开处），再截断前进分支并追加。同文件同行去重；上限 200 条。 */
  function pushNav(
    entry: NavEntry,
    depart: ReturnType<typeof navDeparture> | null = navDeparture(),
  ) {
    if (navigating) return;
    const list = navList();
    const idx = navIdx();
    if (
      idx >= 0 &&
      idx < list.length &&
      depart?.root != null &&
      depart?.path != null &&
      list[idx].root === depart.root &&
      list[idx].path === depart.path
    ) {
      list[idx] = { ...list[idx], line0: depart.line0 ?? list[idx].line0 };
    }
    const merged = list.slice(0, idx + 1);
    const top = merged[merged.length - 1];
    if (top && top.root === entry.root && top.path === entry.path && top.line0 === entry.line0) {
      return;
    }
    merged.push(entry);
    if (merged.length > 200) merged.splice(0, merged.length - 200);
    setNavList(merged);
    setNavIdx(merged.length - 1);
  }

  /** 返回/前进：打开目标文件或在本文件定位到落点行。 */
  async function navTo(target: number) {
    const entry = navList()[target];
    if (!entry || target === navIdx()) return;
    navigating = true;
    try {
      setNavIdx(target);
      const cur = current();
      if (cur?.root === entry.root && cur?.path === entry.path) {
        if (view && entry.line0 != null) revealPos(view, entry.line0);
        return;
      }
      await (entry.root === "ws" ? openWsFile(entry.path) : openLib(entry.path));
      const landed = current();
      if (
        landed?.root === entry.root &&
        landed?.path === entry.path &&
        view &&
        entry.line0 != null
      ) {
        revealPos(view, entry.line0);
      }
    } finally {
      navigating = false;
    }
  }

  const navBack = () => void navTo(navIdx() - 1);
  const navForward = () => void navTo(navIdx() + 1);

  /** 打开文件并定位到目标行（定义跳转的统一落点；入导航栈）。 */
  async function openAndReveal(
    root: "ws" | "lib",
    path: string,
    line0 = 0,
    char0?: number,
    charEnd?: number,
  ) {
    const same = current()?.root === root && current()?.path === path;
    if (same) {
      pushNav({ root, path, line0 });
    } else {
      await (root === "ws" ? openWsFile(path) : openLib(path));
      const cur = current();
      if (cur?.root !== root || cur?.path !== path) return; // 打开失败（fileMsg 已提示）
      // applyOpen 已按文件级落点入栈（line0=null）：补上实际定位行
      const idx = navIdx();
      const list = navList();
      if (idx >= 0 && list[idx] && list[idx].root === root && list[idx].path === path) {
        setNavList(list.map((e, i) => (i === idx ? { ...e, line0 } : e)));
      }
    }
    if (view) revealPos(view, line0, char0, charEnd);
  }

  /** file:// URI → 本地路径（解码 %XX；Windows 盘符折算 /C:/ → C:/）。 */
  function uriToPath(uri: string): string {
    let p = uri.startsWith("file://") ? uri.slice("file://".length) : uri;
    try {
      p = decodeURIComponent(p);
    } catch {
      /* 保留原样 */
    }
    p = p.replace(/\\/g, "/");
    if (/^\/[A-Za-z]:\//.test(p)) p = p.slice(1);
    return p;
  }

  /** 路径段后缀匹配长度（定义目标与工作区树/库清单的符号链接兜底比较用）。 */
  function commonSuffixK(a: string[], b: string[]): number {
    let k = 0;
    while (k < a.length && k < b.length && a[a.length - 1 - k] === b[b.length - 1 - k]) k++;
    return k;
  }

  /** 定义目标绝对路径 → 可打开条目：工作区/库目录前缀优先（服务端 canonicalize
   *  过，这里同样规整），前缀不匹配（符号链接/挂载差异）按路径后缀在工作区树
   *  与库清单里找最长命中。 */
  function matchOpenable(p: string): { root: "ws" | "lib"; path: string } | null {
    const norm = (s: string) => s.replace(/\\/g, "/").replace(/\/+$/, "");
    const root = wsRoot();
    if (root) {
      const r = norm(root);
      if (p === r || p.startsWith(`${r}/`)) return { root: "ws", path: p.slice(r.length + 1) };
    }
    for (const dir of libDirs()) {
      const d = norm(dir);
      if (p === d || p.startsWith(`${d}/`)) {
        const rel = p === d ? p.split("/").pop()! : p.slice(d.length + 1);
        // 库读取只收文件名（read_lib_file 限单段）；子目录文件回退按名匹配
        const path = rel.includes("/") ? (rel.split("/").pop() ?? rel) : rel;
        return { root: "lib", path };
      }
    }
    const segs = p.split("/");
    let best: { root: "ws" | "lib"; path: string; k: number } | null = null;
    for (const e of entries()) {
      if (e.dir) continue;
      const k = commonSuffixK(segs, e.path.split("/"));
      if (k > 0 && (!best || k > best.k)) best = { root: "ws", path: e.path, k };
    }
    for (const f of libs()) {
      const k = commonSuffixK(segs, f.split("/"));
      if (k > 0 && (!best || k > best.k)) best = { root: "lib", path: f, k };
    }
    return best ? { root: best.root, path: best.path } : null;
  }

  /** go-to-definition：LSP definition → 打开目标文件（跨文件）或本文件跳行。
   *  目标是定义名的 span，落点选中名字整体。 */
  async function gotoDefinition(pos: { line: number; character: number }) {
    if (isMd() || isPktl()) return;
    // 先同步全文（didChange 有 250ms 防抖，直接查会打在旧文本上——与补全/悬停同法）
    lsp.change(text());
    const res = await lsp.definition(pos.line, pos.character);
    const loc = Array.isArray(res) ? res[0] : res;
    if (!loc?.uri) {
      if (lsp.lastTimedOut) {
        // 超时 ≠ 无定义：会话忙/已死时给可行动的提示（区别于真空结果）
        setFileMsg("definition lookup timed out — LSP session busy or gone, retry");
        return;
      }
      const word = wordAround(pos);
      setFileMsg(word ? `no definition found for “${word}”` : "no definition found");
      return;
    }
    const line0 = loc.range?.start?.line ?? 0;
    const char0 = loc.range?.start?.character;
    const charEnd = loc.range?.end?.character;
    const target = matchOpenable(uriToPath(String(loc.uri)));
    if (!target) {
      setFileMsg(`definition target is outside the workspace and libraries: ${uriToPath(String(loc.uri))}`);
      return;
    }
    await openAndReveal(target.root, target.path, line0, char0, charEnd);
  }

  /** 点击位置所在标识符（无定义提示文案用）。 */
  function wordAround(pos: { line: number; character: number }): string {
    const lineText = text().split("\n")[pos.line] ?? "";
    const w = (c: string) => /[A-Za-z0-9_]/.test(c);
    let s = Math.min(pos.character, lineText.length);
    let e = s;
    while (s > 0 && w(lineText[s - 1]!)) s--;
    while (e < lineText.length && w(lineText[e]!)) e++;
    return lineText.slice(s, e);
  }

  /** .pktl 步骤文件 token 单击：按配方所在目录解析相对路径并打开。
   *  与 Recipe 面板的 openRecipePkg 不同：token 是编辑器里写的相对引用。 */
  function openRecipePkgToken(token: string) {
    const cur = current();
    if (!cur || cur.root !== "ws") {
      setFileMsg("packet file lives outside the current workspace");
      return;
    }
    const dir = cur.path.includes("/") ? cur.path.slice(0, cur.path.lastIndexOf("/") + 1) : "";
    const parts: string[] = [];
    for (const seg of `${dir}${token}`.replace(/\\/g, "/").split("/")) {
      if (!seg || seg === ".") continue;
      if (seg === "..") parts.pop();
      else parts.push(seg);
    }
    void openAndReveal("ws", parts.join("/"), 0);
  }

  /** 丢弃编辑器内容与本地草稿，回到磁盘版本（草稿被污染时的逃生门）。 */
  async function reloadFromDisk() {
    const cur = current();
    if (!cur || cur.root !== "ws") return;
    void kvDel(draftKey("ws", cur.path));
    setPendingDraft(null);
    // 显式磁盘重载：跳过「已开标签直接激活」，覆盖标签里的未保存内容
    await openWsFile(cur.path, { reload: true });
  }

  /** 载入挂起的本地草稿（覆盖编辑器内容；保存后草稿清除）。 */
  function restoreDraft() {
    const pd = pendingDraft();
    const cur = current();
    if (!pd || !cur || cur.root !== "ws" || cur.path !== pd.path) return;
    setDoc(view, pd.text);
    setText(pd.text);
    setFileMsg("draft restored — Save keeps it");
  }

  async function saveCurrent() {
    const cur = current();
    if (!cur || cur.root !== "ws") return;
    const res = await client.saveFile(cur.path, text());
    if (res.ok) {
      setSavedText(text());
      setFileMsg(null);
      void kvDel(draftKey("ws", cur.path)); // 已落盘，草稿不再需要
      setPendingDraft(null);
      void refreshTree();
    } else {
      setFileMsg(`save failed: ${res.error}`);
    }
  }

  function newFile() {
    if (!wsRoot()) {
      setFileMsg("no workspace — open a folder first (📂)");
      return;
    }
    const name = window.prompt("New file (relative path, .pkt/.pktl):", "untitled.pkt");
    if (!name) return;
    // 轻量规整：反斜杠 → '/'，去前导 '/'、折叠重复 '/'（服务端仍会全量校验）
    const clean = name.trim().replace(/\\/g, "/").replace(/^\//, "").replace(/\/{2,}/g, "/");
    if (!/\.(pkt|pktl)$/.test(clean)) {
      setFileMsg("only .pkt/.pktl files are supported");
      return;
    }
    applyOpen({ root: "ws", path: clean }, "", fileUri(wsRoot()!, clean));
    setSavedText(null); // 未落盘：处于待保存状态
    // applyOpen 会清 fileMsg，提示放它后面（Ctrl+S 走 saveCurrent 落盘）
    setFileMsg("Unsaved buffer — press Ctrl+S to create the file in the workspace");
  }

  async function deleteFile(path: string, isDir = false) {
    // 目录删除是递归的（服务端 remove_dir_all），确认文案必须说明后果
    const msg = isDir ? `Delete folder ${path} and ALL its contents?` : `Delete ${path}?`;
    if (!window.confirm(msg)) return;
    const res = await client.deleteFile(path);
    if (res.ok) {
      void kvDel(draftKey("ws", path));
      // 命中该路径（目录含子路径）的草稿一并清掉，防止重开后「恢复草稿」复活
      const draftPaths = [path];
      if (isDir) {
        for (const e of entries()) {
          if (!e.dir && e.path.startsWith(`${path}/`)) draftPaths.push(e.path);
        }
      }
      for (const dp of draftPaths) void kvDel(draftKey("ws", dp));
      // 该文件的编辑器标签全部关闭（keepDraft：草稿已清，不回写），
      // closeTab 内会停掉其运行中任务并从任务列表移除
      const doomed = tabs()
        .filter(
          (tb) =>
            tb.file.root === "ws" &&
            (tb.file.path === path || (isDir && tb.file.path.startsWith(`${path}/`))),
        )
        .map((tb) => tabKey(tb.file));
      for (const k of doomed) closeTab(k, { keepDraft: true });
      // 删除目录：目录内文件的“上次文件”记录一并清掉（草稿留在库里无害）
      if (isDir) {
        const last = await kvGet<CurrentFile>(Keys.lastFile);
        if (last?.root === "ws" && (last.path === path || last.path.startsWith(`${path}/`))) {
          void kvDel(Keys.lastFile);
        }
      }
      // 导航历史剔除被删条目（目录删除连子路径一起），游标收拢到相邻条目
      const idx = navIdx();
      let nextIdx = idx;
      const kept = navList().filter((e, i) => {
        const hit =
          e.root === "ws" && (e.path === path || (isDir && e.path.startsWith(`${path}/`)));
        if (hit && i <= idx) nextIdx -= 1;
        return !hit;
      });
      setNavList(kept);
      setNavIdx(kept.length ? Math.min(Math.max(nextIdx, 0), kept.length - 1) : -1);
      void refreshTree();
    } else {
      setFileMsg(`delete failed: ${res.error}`);
    }
  }

  /** 重命名/移动（左栏 ✎；草稿随路径迁移，打开中的文件同步更新当前路径）。 */
  async function renameFile(path: string) {
    const next = window.prompt(`Rename/move ${path} to:`, path);
    if (next == null) return;
    const to = next.trim().replace(/\\/g, "/").replace(/^\//, "").replace(/\/{2,}/g, "/");
    if (!to || to === path) return;
    const res = await client.renameFile(path, to);
    if (res.ok) {
      // 草稿迁移 + 打开中文件路径更新 + 上次文件记录更新
      const draft = await kvGet<string>(draftKey("ws", path));
      if (draft != null) {
        void kvDel(draftKey("ws", path));
        void kvSet(draftKey("ws", to), draft);
      }
      if (current()?.root === "ws" && current()?.path === path) {
        const root = wsRoot();
        // 标签页文件路径改写（保留内容与 dirty 状态）+ LSP 会话以新 URI 重放
        setTabs((ts) =>
          ts.map((tb) =>
            tabKey(tb.file) === tabKey({ root: "ws", path }) ? { ...tb, file: { root: "ws", path: to } } : tb,
          ),
        );
        setActiveKey(tabKey({ root: "ws", path: to }));
        lsp.openDoc(root ? fileUri(root, to) : `file:///${to}`, text());
        refreshAnalyze();
      } else if (tabs().some((tb) => tabKey(tb.file) === tabKey({ root: "ws", path }))) {
        // 非活跃标签里的文件被改名：同步改写标签路径（内容不变）
        setTabs((ts) =>
          ts.map((tb) =>
            tabKey(tb.file) === tabKey({ root: "ws", path }) ? { ...tb, file: { root: "ws", path: to } } : tb,
          ),
        );
      }
      const last = await kvGet<CurrentFile>(Keys.lastFile);
      if (last?.root === "ws" && last.path === path) {
        void kvSet(Keys.lastFile, { root: "ws", path: to });
      }
      // 导航历史里的旧路径一并改写（返回/前进不落空）
      setNavList(navList().map((e) => (e.root === "ws" && e.path === path ? { ...e, path: to } : e)));
      void refreshTree();
    } else {
      setFileMsg(`rename failed: ${res.error}`);
    }
  }

  /** 关闭文档标签：所有脏的工作区标签（含被关的与后台的）先把未保存内容写入
   *  IndexedDB 草稿（1s 防抖可能未触发）；关闭当前标签时激活相邻标签（右优先，
   *  无则左），全部关闭回到示例文档空态。keepDraft 跳过写草稿（删除文件时用：
   *  草稿要清掉而不是写入）。 */
  function closeTab(key: string, opts?: { keepDraft?: boolean }) {
    const idx = tabs().findIndex((tb) => tabKey(tb.file) === key);
    if (idx < 0) return;
    if (!opts?.keepDraft) {
      syncActiveTab(); // 被关的是当前标签时，编辑器实时内容先落账进标签
      flushAllDrafts();
    }
    // 该文件的运行中任务一并停止并移除（任务数据随文档标签走）
    for (const t of runTasks()) {
      if (t.fileKey === key && t.running) void client.runStop(t.id);
    }
    setRunTasks((ts) => ts.filter((t) => t.fileKey !== key));
    const next = tabs().filter((_, i) => i !== idx);
    setTabs(next);
    if (activeKey() !== key) return;
    const neighbor = next[idx] ?? next[idx - 1] ?? null;
    if (neighbor) {
      const uri =
        neighbor.file.root === "ws"
          ? fileUri(wsRoot() ?? "", neighbor.file.path)
          : `file:///${neighbor.file.path}`;
      applyOpen(neighbor.file, "", uri);
      return;
    }
    // 全部关闭：回到示例文档空态（与初始挂载一致）
    setActiveKey(null);
    setDoc(view, SAMPLE_DOC);
    setText(SAMPLE_DOC);
    setSavedText(SAMPLE_DOC);
    setFileMsg(null);
    setAnalyzeErr(null);
    setDeclParams([]);
    setPendingDraft(null);
    setDiags([]);
    setAnalyzeDoc(null);
    setRecipeDoc(null);
    setSymbols([]);
    if (view) applyDiagnostics(view, []);
  }

  /** 新建目录：父目录链自动创建，已存在报错。 */
  async function mkdirFolder() {
    if (!wsRoot()) {
      setFileMsg("no workspace — open a folder first (📂)");
      return;
    }
    const name = window.prompt("New folder (relative path):", "new_folder");
    if (!name) return;
    const clean = name.trim().replace(/\\/g, "/").replace(/^\//, "").replace(/\/{2,}/g, "/");
    if (!clean) return;
    const res = await client.mkdir(clean);
    if (res.ok) {
      void refreshTree();
    } else {
      setFileMsg(`mkdir failed: ${res.error}`);
    }
  }

  // ── 文件夹选择对话框（web dialog）────────────────────────
  const [folderDlg, setFolderDlg] = createSignal(false);

  async function dlgBrowse(path?: string) {
    const res = await client.browse(path);
    if (res.ok) {
      return {
        ok: true,
        path: (res.data as { path: string }).path,
        parent: (res.data as { parent: string | null }).parent ?? null,
        dirs: (res.data as { dirs: string[] }).dirs,
      };
    }
    return { ok: false, error: res.error as string };
  }

  /** 确认选择：null = 成功（对话框关闭），否则返回错误文案就地展示。 */
  async function dlgConfirm(path: string): Promise<string | null> {
    if (!path) return "path is empty";
    const res = await client.openFolder(path);
    if (res.ok) {
      const root = (res.data as { root: string | null }).root ?? null;
      setWsRoot(root);
      void kvSet(Keys.workspaceRoot, root); // 重载后恢复该工作区
      void refreshTree();
      return null;
    }
    return res.error as string;
  }

  function onKeydown(e: KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
      e.preventDefault();
      void saveCurrent();
    }
    // 导航历史（VS Code 惯例键位；浏览器自身历史导航被 preventDefault 拦下）
    if (e.altKey && e.key === "ArrowLeft") {
      e.preventDefault();
      navBack();
    }
    if (e.altKey && e.key === "ArrowRight") {
      e.preventDefault();
      navForward();
    }
    // Alt+W 关闭当前文档标签（Ctrl+W 是浏览器级关闭，拦截不了）
    if (e.altKey && e.key.toLowerCase() === "w") {
      e.preventDefault();
      const k = activeKey();
      if (k) closeTab(k);
    }
  }

  function setPanelPersist(p: Panel) {
    setPanel(p);
    void kvSet(Keys.panel, p);
  }

  onMount(async () => {
    view = createEditor(editorHost, {
      doc: SAMPLE_DOC,
      onUpdate: onEditorUpdate,
      // 补全/悬停前先同步当前全文——didChange 走 250ms 防抖，直接查会打在
      // 服务端的旧文本上（本地名缺失、参数缓存过期）。didChange 是小消息，随查随发
      completion: (pos) => {
        if (isMd()) return Promise.resolve(null); // markdown 无 LSP
        lsp.change(text());
        return lsp.completion(pos.line, pos.character);
      },
      hover: (pos) => {
        if (isMd()) return Promise.resolve(null);
        lsp.change(text());
        return lsp.hover(pos.line, pos.character);
      },
      // 跳转：Ctrl/Cmd/Alt+单击标识符 / 单击 import 模块名；.pktl 步骤文件名单击
      onGoto: (pos) => void gotoDefinition(pos),
      onGotoPktlFile: (t) => openRecipePkgToken(t),
    });

    // 配置（版本号 + WS 路径 + 内置原语名单 + WS 鉴权 token）
    try {
      const cfg = await fetch("/config.json").then((r) => r.json());
      setVersion(cfg.version ?? "");
      if (Array.isArray(cfg.builtins)) setBuiltins(new Set(cfg.builtins as string[]));
      // token 契约（服务端并行新增）：connect 前注入，连接与断线重连统一携带；
      // 缺失/为空则不带 token 连接（服务端拒绝时经 onServerError 呈现）
      if (typeof cfg.token === "string" && cfg.token) client.setAuthToken(cfg.token);
    } catch {
      /* dev 代理未起时忽略 */
    }

    window.addEventListener("keydown", onKeydown);
    window.addEventListener("resize", onResize);

    // 恢复持久化的面板页签（IndexedDB 不可用时静默跳过）；非法值忽略。
    // 上一版曾存按标签的 map（对象）——无法还原单值语义，直接忽略
    const PANELS_ALL: Panel[] = [
      "diagnostics", "layers", "hex", "outline", "run", "recipe", "globals",
    ];
    void kvGet<Panel | Record<string, Panel>>(Keys.panel).then((p) => {
      if (typeof p === "string" && PANELS_ALL.includes(p)) setPanelSel(p);
    });
    // 恢复 Run 选项快照（旧条目缺字段时并入当前默认，避免半快照）
    void kvGet<RunSettings>(Keys.runSettings).then((s) => {
      if (s) setRunSettings({ ...runSettings(), ...s });
    });

    // 连接成功后的 LSP 会话重建 / 分析刷新 / 库列表 / 目录树统一走
    // onStatus("connected") 钩子——此处立即发送会在 CONNECTING 状态撞异常
    client.connect();
  });

  onCleanup(() => {
    window.removeEventListener("keydown", onKeydown);
    window.removeEventListener("resize", onResize);
    // 卸载前 flush 所有脏标签的草稿（编辑中途刷新不丢；后台标签一并保住）
    if (draftTimer) clearTimeout(draftTimer);
    if (fileMsgClearTimer) clearTimeout(fileMsgClearTimer);
    syncActiveTab();
    flushAllDrafts();
    client.close();
  });

  const statusLabel = () =>
    ({ connected: "connected", connecting: "connecting…", closed: "reconnecting…" })[status()];

  return (
    <div class="app">
      <header class="topbar">
        {/* 侧栏显隐切换（CSS 契约见 .main.side-hidden；side-head 行动区在 files.tsx，
            按钮放顶栏保证侧栏隐藏后仍可恢复） */}
        <button
          class="icon-btn side-toggle"
          onClick={toggleSide}
          title="toggle sidebar"
        >
          {sideVisible() ? "◧" : "▢"}
        </button>
        <span class="brand">prping web</span>
        <span class="version">{version() && `v${version()}`}</span>
        <span class={`status status-${status()}`} title="WebSocket status">
          {statusLabel()}
        </span>
        {/* 导航历史：定义跳转/文件打开的返回与前进（Alt+← / Alt+→） */}
        <span class="nav-btns">
          <button
            class="nav-btn"
            disabled={navIdx() <= 0}
            onClick={navBack}
            title="Back (Alt+←)"
          >
            ←
          </button>
          <button
            class="nav-btn"
            disabled={navIdx() >= navList().length - 1}
            onClick={navForward}
            title="Forward (Alt+→)"
          >
            →
          </button>
        </span>
        <Show when={current()} keyed>
          {(c) => (
            <span
              class="current-file"
              title={c.root === "lib" ? "read-only library file" : "workspace file"}
            >
              {c.path}
              <Show when={c.root === "lib"}>
                <span class="ro-badge">read-only</span>
              </Show>
              <Show when={dirty()}>
                <span class="dirty-dot" title="unsaved changes" />
              </Show>
            </span>
          )}
        </Show>
        <Show when={dirty()}>
          <button
            class="reload-btn"
            onClick={() => void reloadFromDisk()}
            title="discard editor content and draft, reload from disk"
          >
            ↺
          </button>
          <button class="save-btn" onClick={() => void saveCurrent()} title="Ctrl+S">
            Save
          </button>
          <Show when={isPktFile()}>
            <Show
              when={!activeTask()?.running}
              fallback={
                <button
                  class="run-stop-btn header"
                  onClick={() => void doStop()}
                  title="stop the active run (Run tab manages all tasks)"
                >
                  ■ Stop
                </button>
              }
            >
              <button
                class="run-go-btn header"
                disabled={!canRun()}
                onClick={() => void doRun()}
                title={
                  canRun()
                    ? "run this file with prping packet (Run tab for options)"
                    : "workspace .pkt/.pktl files only"
                }
              >
                ▶ Run
              </button>
            </Show>
          </Show>
        </Show>
        <Show
          when={pendingDraft() && current()?.root === "ws" && current()?.path === pendingDraft()!.path}
          keyed
        >
          <button class="draft-btn" onClick={restoreDraft} title="load the draft saved last session">
            restore draft
          </button>
        </Show>
        <Show when={fileMsg()}>
          <span class="file-msg">{fileMsg()}</span>
        </Show>
        <Show when={isMd()}>
          <span class="view-toggle" role="tablist" title="markdown view">
            <button
              classList={{ active: mdMode() === "render" }}
              onClick={() => setMdMode("render")}
            >
              render
            </button>
            <button
              classList={{ active: mdMode() === "edit" }}
              onClick={() => setMdMode("edit")}
            >
              edit
            </button>
          </span>
        </Show>
        {/* 右上角全局任务管理器：全连接唯一任务管理面（有任务才出现，
            徽标 = 运行中计数；面板内点行导航 / ■ 停 / ✕ 移除 / Stop all） */}
        <Show when={runTasks().length > 0}>
          <TaskManager
            tasks={runTasks()}
            activeId={activeTask()?.id ?? null}
            onSelect={openTask}
            onStopTask={(id) => void onStopTask(id)}
            onCloseTask={onCloseTask}
            onStopAll={doStopAll}
          />
        </Show>
      </header>
      <main class="main" classList={{ "main-md": isMd(), "side-hidden": !sideVisible() }}>
        <FileSidebar
          wsRoot={wsRoot()}
          entries={entries()}
          libs={libs()}
          libDirs={libDirs()}
          current={current()}
          onOpenWs={(p) => void openWsFile(p)}
          onOpenLib={(n) => void openLib(n)}
          onDelete={(p, isDir) => void deleteFile(p, isDir)}
          onRename={(p) => void renameFile(p)}
          onMkdir={() => void mkdirFolder()}
          onRefresh={() => void refreshTree()}
          onOpenFolder={() => setFolderDlg(true)}
          onNewFile={() => newFile()}
        />
        <FolderDialog
          open={folderDlg()}
          initial={wsRoot() ?? ""}
          onBrowse={dlgBrowse}
          onConfirm={dlgConfirm}
          onClose={() => setFolderDlg(false)}
        />
        <div class="editor-col">
          {/* 文档标签条：每打开一个文件一个 tab（✕ 关闭；● 为未保存修改） */}
          <Show when={tabs().length > 0}>
            <div class="doc-tabs" role="tablist">
              <For each={tabs()}>
                {(tb) => {
                  const key = tabKey(tb.file);
                  const tabDirty = () =>
                    tb.file.root === "ws" &&
                    (activeKey() === key ? text() !== savedText() : tb.text !== tb.savedText);
                  return (
                    <div
                      class="doc-tab"
                      classList={{ active: activeKey() === key }}
                      title={tb.file.root + ":" + tb.file.path}
                      onClick={() => {
                        if (activeKey() === key) return;
                        applyOpen(tb.file, "", fileUri(
                          tb.file.root === "ws" ? (wsRoot() ?? "") : "",
                          tb.file.path,
                        ));
                      }}
                    >
                      <span class="doc-tab-name">{tb.file.path.split("/").pop()}</span>
                      <Show when={fileHasRunning(key)}>
                        <span class="doc-tab-run" title="task running">●</span>
                      </Show>
                      <Show when={tabDirty()}>
                        <span class="dirty-dot" title="unsaved changes" />
                      </Show>
                      <button
                        class="doc-tab-close"
                        title="close tab (Alt+W)"
                        onClick={(e) => {
                          e.stopPropagation();
                          closeTab(key);
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
          <section
            class="editor-pane"
            classList={{ hidden: isMd() && mdMode() === "render" }}
            ref={editorHost}
          />
          <Show when={isMd() && mdMode() === "render"}>
            <section
              class="editor-pane md-render"
              // renderMarkdown 先整体转义 HTML 再套标记——文件内容注入安全
              innerHTML={renderMarkdown(text())}
              ref={mdRenderHost}
            />
          </Show>
        </div>
        {/* Markdown 大纲栏：标题层级树，点击滚动定位（渲染）/行跳转（编辑） */}
        <Show when={isMd()}>
          <aside class="md-outline">
            <div class="md-outline-head">Outline</div>
            <For each={mdOutlineItems()}>
              {(h) => (
                <div
                  class={`md-outline-item lv-${h.level}`}
                  title={h.text}
                  onClick={() => jumpMdHeading(h)}
                >
                  {h.text}
                </div>
              )}
            </For>
            <Show when={mdOutlineItems().length === 0}>
              <div class="empty-hint">No headings.</div>
            </Show>
          </aside>
        </Show>
        {/* Markdown 文档：引擎 LSP/analyze 不适用——三个页签（诊断/层栈/HEX）
            整个侧栏不存在，编辑/渲染占满其余宽度 */}
        <Show when={!isMd()}>
          <aside class="side-pane">
          <PanelTabs
            panel={panel()}
            setPanel={setPanelPersist}
            diagCount={diags().length + (buildErrShown() ? 1 : 0)}
            recipe={isPktl()}
            running={fileHasRunning(activeKey())}
          />
          {/* 构建错误不再作横幅盖在 Layers/Hex 上——统一进 Diagnostics 页签
              （诊断行 + 页签计数），Layers/Hex 空态给指向提示 */}
          {/* 运行参数输入行只在 Layers 页签出现，且文档引用了 params(...) 才显示
              （没用的文件不给一个永远无效的输入框）；Hex 只看字节 */}
          <Show when={!isMd() && !isPktl() && panel() === "layers" && usesRunParams()}>
            <div class="params-box">
              <Show
                when={declParams().length > 0}
                fallback={
                  <>
                    <div class="params-label" title="run params for analyze">params</div>
                    <textarea
                      class="params-input"
                      rows={3}
                      placeholder={"ip=127.0.0.1\nseq=2"}
                      value={runParams()}
                      onInput={(e) => {
                        setRunParams(e.currentTarget.value);
                        refreshAnalyze();
                      }}
                    />
                  </>
                }
              >
                {/* Index（按位置复用 DOM）而非 For（按引用对账）：analyze 应答每次
                    都带新数组的参数声明，For 会整表销毁重建 → 每键失焦 */}
                <Index each={declParams()}>
                  {(p) => (
                    <ParamRow
                      decl={p()}
                      value={runValues()[p().name] ?? ""}
                      onInput={(v) => {
                        setRunValues({ ...runValues(), [p().name]: v });
                        refreshAnalyze();
                      }}
                    />
                  )}
                </Index>
              </Show>
            </div>
          </Show>
          <Show when={panel() === "diagnostics"}>
            <DiagnosticsPanel diags={diags()} buildError={buildErrShown()} />
          </Show>
          <Show when={panel() === "recipe" && isPktl()}>
            <RecipePanel doc={recipeDoc()} onOpenPkg={openRecipePkg} />
          </Show>
          <Show when={panel() === "globals" && isPktl()}>
            <GlobalsPanel doc={recipeDoc()} />
          </Show>
          <Show when={panel() === "layers" && !isPktl()}>
            <LayersPanel doc={doc()} buildError={analyzeErr()} />
          </Show>
          <Show when={panel() === "hex" && !isPktl()}>
            <HexPanel doc={doc()} buildError={analyzeErr()} />
          </Show>
          <Show when={panel() === "outline" && !isPktl()}>
            <OutlinePanel
              symbols={symbols()}
              onJump={(l) => {
                const cur = current();
                if (cur) pushNav({ root: cur.root, path: cur.path, line0: l });
                if (view) revealLine(view, l);
              }}
            />
          </Show>
          <Show when={panel() === "run"}>
            <RunPanel
              tasks={runTasks().filter((t) => t.fileKey === activeKey())}
              activeId={activeTask()?.id ?? null}
              settings={runSettings()}
              setSettings={updateRunSettings}
              declParams={declParams()}
              runValues={runValues()}
              setRunValues={setRunValues}
              canRun={canRun()}
              onRun={() => void doRun()}
              onStopTask={(id) => void onStopTask(id)}
            />
          </Show>
          </aside>
        </Show>
      </main>
    </div>
  );
}
