// prping web —— 应用骨架：顶栏（状态/当前文件/保存）+ 左栏文件管理 + 编辑器 + 右面板。
// 数据流：编辑 →（防抖）→ LSP didChange + analyze 请求 → 诊断/层栈/HEX 更新。
// 文件面：工作区（examples / 自定义文件夹）可编辑保存（Ctrl+S），eng_lib 只读。

import { For, Index, createMemo, onCleanup, onMount, createSignal, Show } from "solid-js";

/** analyze 应答带的运行参数声明（params("名", 默认)）。 */
interface DeclParam {
  name: string;
  default: string | null;
}
import type { EditorView } from "@codemirror/view";
import { applyDiagnostics, createEditor, revealLine, setDoc, setEditable } from "./cm";
import { FileSidebar, FolderDialog, type CurrentFile, type TreeEntry } from "./files";
import { draftKey, Keys, kvDel, kvGet, kvSet } from "./store";
import { LspClient, type LspDiagnostic } from "./lsp";
import type { AnalyzeDoc, Panel } from "./panels";
import {
  DiagnosticsPanel,
  GlobalsPanel,
  HexPanel,
  LayersPanel,
  OutlinePanel,
  PanelTabs,
  RecipePanel,
  type OutlineSym,
  type RecipeDoc,
} from "./panels";
import { SAMPLE_DOC } from "./sample";
import { renderMarkdown } from "./markdown";
import { PrpingClient, type Status } from "./ws";

export function App() {
  const [status, setStatus] = createSignal<Status>("connecting");
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
  // Layers 页签顶的运行参数：文件声明过（params("名", 默认)）则渲染结构化输入行，
  // 否则退回自由文本 k=v；值随每次 analyze 传给服务端构建
  const [runParams, setRunParams] = createSignal("");
  const [runValues, setRunValues] = createSignal<Record<string, string>>({});
  const [declParams, setDeclParams] = createSignal<DeclParam[]>([]);

  const [panel, setPanel] = createSignal<Panel>("layers");
  const [version, setVersion] = createSignal("");

  // Markdown 视图：渲染（renderMarkdown HTML）/ 编辑（源码）——仅 .md 文件用
  const [mdMode, setMdMode] = createSignal<"render" | "edit">("render");

  // 文件管理：工作区树 / 当前文件 / 已保存文本（与编辑器文本比较得 dirty）
  const [wsRoot, setWsRoot] = createSignal<string | null>(null);
  const [entries, setEntries] = createSignal<TreeEntry[]>([]);
  const [current, setCurrent] = createSignal<CurrentFile | null>(null);
  const [text, setText] = createSignal(SAMPLE_DOC);
  const [savedText, setSavedText] = createSignal<string | null>(SAMPLE_DOC);
  const [fileMsg, setFileMsg] = createSignal<string | null>(null);
  // 与磁盘不同的本地草稿：**默认不恢复**（磁盘为准），显式点击才载入——
  // 此前草稿静默压过磁盘，被历史 bug 污染的草稿会让每次打开都错
  const [pendingDraft, setPendingDraft] = createSignal<{ path: string; text: string } | null>(
    null,
  );

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

  client.onStatus = (s) => {
    setStatus(s);
    if (s === "connected") {
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
      void refreshSymbols(); // 大纲与 analyze 同节奏刷新（md/pktl 内部自清）
      // 请求时刻的文档：应答往返期间文件可能已切换，过期应答直接丢弃；
      // 配方判定也按请求时 URI（isPktl() 是应答到达时的状态，快速切换会灌错面板）
      const uri = lsp.documentUri;
      const res = await client.analyze(uri, text(), buildRunParams());
      if (uri !== lsp.documentUri) return; // 过期应答：文件已切换
      if (isMd()) return; // 已切到 Markdown：面板已停用，不接收 analyze 结果
      // 声明的运行参数成功/失败应答都带：结构化输入行的数据源。
      // 声明未变（打参数值时最常见的情形）不替换——新数组会触发下游重建
      const decl = (res.data as { params?: DeclParam[] } | undefined)?.params;
      if (decl) {
        const prev = declParams();
        const same =
          prev.length === decl.length &&
          prev.every((p, i) => p.name === decl[i].name && p.default === decl[i].default);
        if (!same) setDeclParams(decl);
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

  /** 文档符号（Outline 页签）：md/配方无符号——清空即可。应答过期丢弃。 */
  async function refreshSymbols() {
    if (isMd() || isPktl()) {
      setSymbols([]);
      return;
    }
    const uri = lsp.documentUri;
    const res = await lsp.documentSymbol();
    if (uri !== lsp.documentUri || isMd() || isPktl()) return;
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

  function onEditorUpdate(t: string) {
    setText(t);
    // Markdown：无 LSP 全文同步 / 分析——只走草稿持久化
    if (isMd()) {
      if (draftTimer) clearTimeout(draftTimer);
      draftTimer = setTimeout(() => {
        const cur = current();
        if (cur?.root === "ws") void kvSet(draftKey("ws", cur.path), text());
      }, 1000);
      return;
    }
    // LSP 全文同步 + 分析共用一个防抖节奏
    if (changeTimer) clearTimeout(changeTimer);
    changeTimer = setTimeout(() => lsp.change(t), 250);
    refreshAnalyze();
    // 草稿持久化（防抖 1s；仅工作区文件——eng_lib 只读不产生差异）
    if (current()?.root === "ws") {
      if (draftTimer) clearTimeout(draftTimer);
      draftTimer = setTimeout(() => {
        const cur = current();
        if (cur?.root === "ws") void kvSet(draftKey("ws", cur.path), text());
      }, 1000);
    }
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

  /** 工作区文件 → file:// URI（Windows 盘符路径折叠为 /C:/ 形式；LSP/analyze
   *  据此把 import 解析到文件所在目录，模块名取文件名）。 */
  function fileUri(root: string, rel: string): string {
    let p = `${root}/${rel}`.replace(/\\/g, "/");
    if (!p.startsWith("/")) p = `/${p}`;
    return `file://${p}`;
  }

  /** 打开文件的统一落点：替换编辑器文档 + LSP 会话重放 + 立即分析。
   *  `saved` 为磁盘文本（草稿恢复时与编辑器文本不同 → 呈现未保存状态）。 */
  function applyOpen(file: CurrentFile, content: string, uri: string, saved?: string) {
    setDoc(view, content);
    setText(content);
    setSavedText(saved ?? content);
    setCurrent(file);
    setFileMsg(null);
    setAnalyzeErr(null);
    setDeclParams([]); // 新文件的参数声明待首次 analyze 返回
    setPendingDraft(null);
    setEditable(view, file.root === "ws");
    if (isMd()) {
      // Markdown：不进 LSP 会话（诊断/补全/悬停停用）；清残留诊断与面板
      setDiags([]);
      setAnalyzeDoc(null);
      setRecipeDoc(null);
      setSymbols([]);
      setMdMode("render");
      // 从配方切来时页签组没有 recipe/globals，落回诊断
      if (panel() === "recipe" || panel() === "globals") setPanel("diagnostics");
      if (view) applyDiagnostics(view, []);
      return;
    }
    if (isPktl()) {
      // 配方文档：侧栏切 Recipe 页签，清层栈残留
      setAnalyzeDoc(null);
      setRecipeDoc(null);
      setPanel("recipe");
    } else if (panel() === "recipe" || panel() === "globals") {
      // 配方 → 普通文档：页签组已换回 Layers/Hex，面板停在 recipe/globals
      // 会落在无内容页签上（侧栏空白），回 Layers 立即显示层栈
      setPanel("layers");
    }
    lsp.openDoc(uri, content);
    refreshAnalyze();
  }

  async function openWsFile(path: string) {
    const res = await client.readWs(path);
    if (!res.ok) {
      setFileMsg(res.error as string);
      return;
    }
    const root = wsRoot();
    const disk = (res.data as { text: string }).text;
    // 草稿恢复：浏览器库里存有未落盘文本（≠ 磁盘）则恢复并标记未保存
    const draft = await kvGet<string>(draftKey("ws", path));
    if (draft != null && draft !== disk) {
      setPendingDraft({ path, text: draft });
      setFileMsg("draft from last session differs from disk — disk loaded; restore draft to switch");
    } else {
      setPendingDraft(null);
    }
    applyOpen(
      { root: "ws", path },
      disk,
      root ? fileUri(root, path) : `file:///${path}`,
      disk,
    );
    void kvSet(Keys.lastFile, { root: "ws", path });
  }

  async function openLib(name: string) {
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

  /** 丢弃编辑器内容与本地草稿，回到磁盘版本（草稿被污染时的逃生门）。 */
  async function reloadFromDisk() {
    const cur = current();
    if (!cur || cur.root !== "ws") return;
    void kvDel(draftKey("ws", cur.path));
    setPendingDraft(null);
    await openWsFile(cur.path); // 草稿已清 → 恢复磁盘内容
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
  }

  async function deleteFile(path: string, isDir = false) {
    // 目录删除是递归的（服务端 remove_dir_all），确认文案必须说明后果
    const msg = isDir ? `Delete folder ${path} and ALL its contents?` : `Delete ${path}?`;
    if (!window.confirm(msg)) return;
    const res = await client.deleteFile(path);
    if (res.ok) {
      void kvDel(draftKey("ws", path));
      // 删除目录：目录内文件的“上次文件”记录一并清掉（草稿留在库里无害）
      if (isDir) {
        const last = await kvGet<CurrentFile>(Keys.lastFile);
        if (last?.root === "ws" && (last.path === path || last.path.startsWith(`${path}/`))) {
          void kvDel(Keys.lastFile);
        }
      }
      // 删除打开中的文件：缓冲保留（保存即重建）
      if (current()?.root === "ws" && current()?.path === path) setSavedText(text());
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
        setCurrent({ root: "ws", path: to });
        lsp.openDoc(root ? fileUri(root, to) : `file:///${to}`, text());
        refreshAnalyze();
      }
      const last = await kvGet<CurrentFile>(Keys.lastFile);
      if (last?.root === "ws" && last.path === path) {
        void kvSet(Keys.lastFile, { root: "ws", path: to });
      }
      void refreshTree();
    } else {
      setFileMsg(`rename failed: ${res.error}`);
    }
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
    });

    // 配置（版本号 + WS 路径）
    try {
      const cfg = await fetch("/config.json").then((r) => r.json());
      setVersion(cfg.version ?? "");
    } catch {
      /* dev 代理未起时忽略 */
    }

    window.addEventListener("keydown", onKeydown);

    // 恢复持久化的面板选择（IndexedDB 不可用时静默跳过）
    void kvGet<Panel>(Keys.panel).then((p) => {
      if (p === "diagnostics" || p === "layers" || p === "hex") setPanel(p);
    });

    // 连接成功后的 LSP 会话重建 / 分析刷新 / 库列表 / 目录树统一走
    // onStatus("connected") 钩子——此处立即发送会在 CONNECTING 状态撞异常
    client.connect();
  });

  onCleanup(() => {
    window.removeEventListener("keydown", onKeydown);
    // 卸载前 flush 未落库的草稿（编辑中途刷新不丢）
    if (draftTimer) {
      clearTimeout(draftTimer);
      const cur = current();
      if (cur?.root === "ws" && text() !== savedText()) {
        void kvSet(draftKey("ws", cur.path), text());
      }
    }
    client.close();
  });

  const statusLabel = () =>
    ({ connected: "connected", connecting: "connecting…", closed: "reconnecting…" })[status()];

  return (
    <div class="app">
      <header class="topbar">
        <span class="brand">prping web</span>
        <span class="version">{version() && `v${version()}`}</span>
        <span class={`status status-${status()}`} title="WebSocket status">
          {statusLabel()}
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
      </header>
      <main class="main" classList={{ "main-md": isMd() }}>
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
                    <label
                      class="param-item"
                      title={p().default == null ? "required — no default" : `default ${p().default}`}
                    >
                      <span class="badge">param</span>
                      <span
                        class="param-name"
                        classList={{
                          "param-missing": p().default == null && !runValues()[p().name],
                        }}
                      >
                        {p().name}
                      </span>
                      <input
                        class="param-input"
                        placeholder={p().default ?? "required"}
                        value={runValues()[p().name] ?? ""}
                        onInput={(e) => {
                          setRunValues({ ...runValues(), [p().name]: e.currentTarget.value });
                          refreshAnalyze();
                        }}
                      />
                    </label>
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
                if (view) revealLine(view, l);
              }}
            />
          </Show>
          </aside>
        </Show>
      </main>
    </div>
  );
}
