// prping web —— 应用骨架：顶栏（状态/当前文件/保存）+ 左栏文件管理 + 编辑器 + 右面板。
// 数据流：编辑 →（防抖）→ LSP didChange + analyze 请求 → 诊断/层栈/HEX 更新。
// 文件面：工作区（examples / 自定义文件夹）可编辑保存（Ctrl+S），eng_lib 只读。

import { For, createEffect, onCleanup, onMount, createSignal, Show } from "solid-js";

/** analyze 应答带的运行参数声明（params("名", 默认)）。 */
interface DeclParam {
  name: string;
  default: string | null;
}
import type { EditorView } from "@codemirror/view";
import { applyDiagnostics, createEditor, setDoc, setEditable } from "./cm";
import { FileSidebar, FolderDialog, type CurrentFile, type TreeEntry } from "./files";
import { draftKey, Keys, kvDel, kvGet, kvSet } from "./store";
import { LspClient, type LspDiagnostic } from "./lsp";
import type { AnalyzeDoc, Panel } from "./panels";
import {
  DiagnosticsPanel,
  GlobalsPanel,
  HexPanel,
  LayersPanel,
  PanelTabs,
  RecipePanel,
  type RecipeDoc,
} from "./panels";
import { SAMPLE_DOC } from "./sample";
import { BlocksView, type BlockDoc } from "./blocks";
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
  // analyze 失败横幅（运行期参数缺失/构建错误——LSP 诊断不覆盖这类语义错误）
  const [analyzeErr, setAnalyzeErr] = createSignal<string | null>(null);
  // 面板顶的运行参数：文件声明过（params("名", 默认)）则渲染结构化输入行，
  // 否则退回自由文本 k=v；值随每次 analyze 传给服务端构建
  const [runParams, setRunParams] = createSignal("");
  const [runValues, setRunValues] = createSignal<Record<string, string>>({});
  const [declParams, setDeclParams] = createSignal<DeclParam[]>([]);

  const [panel, setPanel] = createSignal<Panel>("layers");
  const [version, setVersion] = createSignal("");

  // 块视图（阶段 1：只读预览）：ast IR + text/blocks 视图切换
  const [viewMode, setViewMode] = createSignal<"text" | "blocks">("text");
  // Markdown 视图：渲染（renderMarkdown HTML）/ 编辑（源码）——仅 .md 文件用
  const [mdMode, setMdMode] = createSignal<"render" | "edit">("render");
  const [astDoc, setAstDoc] = createSignal<BlockDoc | null>(null);
  const [astErr, setAstErr] = createSignal<string | null>(null);
  const [schema, setSchema] = createSignal<any>(null);
  // ast 构建时的文本快照：块编辑回写前比对，过期（文本已变）则丢弃本次编辑
  const [astText, setAstText] = createSignal<string | null>(null);

  // 文件管理：工作区树 / 当前文件 / 已保存文本（与编辑器文本比较得 dirty）
  const [wsRoot, setWsRoot] = createSignal<string | null>(null);
  const [entries, setEntries] = createSignal<TreeEntry[]>([]);
  const [current, setCurrent] = createSignal<CurrentFile | null>(null);
  const [text, setText] = createSignal(SAMPLE_DOC);
  const [savedText, setSavedText] = createSignal<string | null>(SAMPLE_DOC);
  const [fileMsg, setFileMsg] = createSignal<string | null>(null);

  let editorHost!: HTMLDivElement;
  let view: EditorView;
  let autoOpened = false; // 首次连接后自动打开一个工作区文件（重连不重复触发）

  let analyzeTimer: ReturnType<typeof setTimeout> | null = null;
  let changeTimer: ReturnType<typeof setTimeout> | null = null;
  let draftTimer: ReturnType<typeof setTimeout> | null = null;
  let astTimer: ReturnType<typeof setTimeout> | null = null;

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

  client.onStatus = (s) => {
    setStatus(s);
    if (s === "connected") {
      // 首连与重连统一在此初始化（WS OPEN 后才可发送）：重建 LSP 会话并
      // 重放当前文档、刷新分析/库列表/工作区树（重连后服务端工作区回到默认）
      if (!isMd()) {
        lsp.start(lsp.documentUri, text());
        refreshAnalyze();
        refreshAst();
      }
      refreshLibs();
      refreshTree();
      // schema（块编辑的层名/字段候选）：每连接取一次
      void client.schema().then((s) => {
        if (s.ok) setSchema(s.data);
      });
    }
  };

  function refreshAnalyze() {
    if (analyzeTimer) clearTimeout(analyzeTimer);
    analyzeTimer = setTimeout(async () => {
      // 请求时刻的文档：应答往返期间文件可能已切换，过期应答直接丢弃；
      // 配方判定也按请求时 URI（isPktl() 是应答到达时的状态，快速切换会灌错面板）
      const uri = lsp.documentUri;
      const res = await client.analyze(uri, text(), buildRunParams());
      if (uri !== lsp.documentUri) return; // 过期应答：文件已切换
      // 声明的运行参数成功/失败应答都带：结构化输入行的数据源
      const decl = (res.data as { params?: DeclParam[] } | undefined)?.params;
      if (decl) setDeclParams(decl);
      if (!res.ok) {
        // 构建失败（如 params('ip') 未提供）：LSP 不报这类错误，横幅就地呈现
        setAnalyzeErr(res.error as string);
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

  function refreshAst() {
    // .pktl 也走 ast 信封（blocks_json 的 recipe 形态）——块视图按步骤渲染
    if (astTimer) clearTimeout(astTimer);
    astTimer = setTimeout(async () => {
      const uri = lsp.documentUri; // 应答期间文件可能已切换，过期应答丢弃
      const snapshot = text();
      setAstText(snapshot);
      const res = await client.ast(uri, snapshot);
      if (uri !== lsp.documentUri) return;
      if (res.ok) {
        setAstDoc(res.data as BlockDoc);
        setAstErr(null);
      } else {
        // 解析/语义失败：块视图降级为提示（保留上次成功结果不动）
        setAstErr(res.error as string);
      }
    }, 250);
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
    // Markdown：无 LSP 全文同步 / 分析 / 块视图——只走草稿持久化
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
    refreshAst();
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
    setEditable(view, file.root === "ws");
    if (isMd()) {
      // Markdown：不进 LSP 会话（诊断/补全/悬停停用）；清残留诊断与面板
      setDiags([]);
      setAnalyzeDoc(null);
      setAstDoc(null);
      setRecipeDoc(null);
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
      setAstDoc(null);
      setPanel("recipe");
    } else if (panel() === "recipe" || panel() === "globals") {
      // 配方 → 普通文档：页签组已换回 Layers/Hex，面板停在 recipe/globals
      // 会落在无内容页签上（侧栏空白），回 Layers 立即显示层栈
      setPanel("layers");
    }
    lsp.openDoc(uri, content);
    refreshAnalyze();
    refreshAst();
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
    const content = draft != null && draft !== disk ? draft : disk;
    applyOpen(
      { root: "ws", path },
      content,
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

  async function saveCurrent() {
    const cur = current();
    if (!cur || cur.root !== "ws") return;
    const res = await client.saveFile(cur.path, text());
    if (res.ok) {
      setSavedText(text());
      setFileMsg(null);
      void kvDel(draftKey("ws", cur.path)); // 已落盘，草稿不再需要
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

  // 切回文本视图时让 CodeMirror 重新测量（blocks 视图期间容器 display:none）
  createEffect(() => {
    if (viewMode() === "text" && view) view.requestMeasure();
  });

  // ── 块视图回写（阶段 2）────────────────────────────────

  /** 1 基 (line, col) → 字节偏移；col 按字符计，越界取行尾（与 astdoc 切片一致）。 */
  function spanOffset(text: string, line: number, col: number): number {
    const lines = text.split("\n");
    const li = Math.min(Math.max(line - 1, 0), lines.length - 1);
    let off = 0;
    for (let i = 0; i < li; i++) off += lines[i].length + 1;
    const lineText = lines[li];
    let cnt = 0;
    for (const ch of lineText) {
      if (cnt >= col - 1) break;
      cnt++;
      off += ch.length;
    }
    return off;
  }

  /** 块编辑回写：span 处替换 replacement（null = 删整行）；过期守卫（文本已变
   *  则丢弃并刷新 ast）。写入走 setDoc → 既有 onEditorUpdate → LSP/analyze/ast
   *  防抖刷新闭环（草稿/脏标记照常）。 */
  function applyBlockEdit(span: { sl: number; sc: number; el: number; ec: number }, replacement: string | null) {
    const cur = text();
    if (astText() != null && cur !== astText()) {
      (window as any).__lastBlockEdit = { discarded: true };
      refreshAst(); // ast 过期：丢弃本次（界面随即重建为最新块）
      return;
    }
    let a = spanOffset(cur, span.sl, span.sc);
    let b = spanOffset(cur, span.el, span.ec);
    if (b < a) return;
    if (replacement === null) {
      // 删语句：扩到整行（含换行），避免残留空行
      const ls = spanOffset(cur, span.sl, 1);
      const lineText = cur.slice(ls, b);
      if (!lineText.trim()) {
        // 理论不可达（span 非空），兜底直接删行
      }
      a = ls;
      let eol = cur.indexOf("\n", b);
      b = eol === -1 ? cur.length : eol + 1;
    }
    const next = cur.slice(0, a) + (replacement ?? "") + cur.slice(b);
    (window as any).__lastBlockEdit = { a, b, discarded: false, len: next.length };
    setDoc(view, next);
    setText(next);
  }

  /** 新建语句：追加到文档末尾（ast 刷新后块视图重建出现新链）。 */
  function appendBlockStmt(stmt: string) {
    const cur = text();
    const next = cur + (cur.endsWith("\n") || cur === "" ? "" : "\n") + stmt + "\n";
    setDoc(view, next);
    setText(next);
  }

  /** 配方加步骤：在第 line 行后插入一行文本（块视图右键 Add step after）。 */
  function insertLineAfter(line: number, lineText: string) {
    const lines = text().split("\n");
    const idx = Math.min(Math.max(line, 0), lines.length); // 行号 1 基；EOF 追加
    lines.splice(idx, 0, lineText);
    const next = lines.join("\n");
    setDoc(view, next);
    setText(next);
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
          <button class="save-btn" onClick={() => void saveCurrent()} title="Ctrl+S">
            Save
          </button>
        </Show>
        <Show when={fileMsg()}>
          <span class="file-msg">{fileMsg()}</span>
        </Show>
        <span class="view-toggle" role="tablist" title="editor view">
          <Show
            when={isMd()}
            fallback={
              <>
                <button
                  classList={{ active: viewMode() === "text" }}
                  onClick={() => setViewMode("text")}
                >
                  text
                </button>
                <button
                  classList={{ active: viewMode() === "blocks" }}
                  onClick={() => setViewMode("blocks")}
                >
                  blocks
                </button>
              </>
            }
          >
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
          </Show>
        </span>
      </header>
      <main class="main">
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
          classList={{
            hidden: viewMode() !== "text" || (isMd() && mdMode() === "render"),
          }}
          ref={editorHost}
        />
        <Show when={isMd() && mdMode() === "render"}>
          <section
            class="editor-pane md-render"
            // renderMarkdown 先整体转义 HTML 再套标记——文件内容注入安全
            innerHTML={renderMarkdown(text())}
          />
        </Show>
        <Show when={viewMode() === "blocks" && !isMd()}>
          <BlocksView
            ast={astDoc()}
            error={astErr()}
            editable={current()?.root === "ws"}
            schema={schema()}
            onEdit={applyBlockEdit}
            onAppend={appendBlockStmt}
            onInsertLine={insertLineAfter}
          />
        </Show>
        <aside class="side-pane">
          <PanelTabs
            panel={panel()}
            setPanel={setPanelPersist}
            diagCount={diags().length}
            recipe={isPktl()}
          />
          <Show when={analyzeErr()}>
            <div class="analyze-error">{analyzeErr()}</div>
          </Show>
          <Show when={!isMd() && !isPktl() && (panel() === "layers" || panel() === "hex")}>
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
                <For each={declParams()}>
                  {(p) => (
                    <label
                      class="param-item"
                      title={p.default == null ? "required — no default" : `default ${p.default}`}
                    >
                      <span class="badge">param</span>
                      <span
                        class="param-name"
                        classList={{
                          "param-missing": p.default == null && !runValues()[p.name],
                        }}
                      >
                        {p.name}
                      </span>
                      <input
                        class="param-input"
                        placeholder={p.default ?? "required"}
                        value={runValues()[p.name] ?? ""}
                        onInput={(e) => {
                          setRunValues({ ...runValues(), [p.name]: e.currentTarget.value });
                          refreshAnalyze();
                        }}
                      />
                    </label>
                  )}
                </For>
              </Show>
            </div>
          </Show>
          <Show when={panel() === "diagnostics"}>
            <DiagnosticsPanel diags={diags()} />
          </Show>
          <Show when={panel() === "recipe" && isPktl()}>
            <RecipePanel doc={recipeDoc()} onOpenPkg={openRecipePkg} />
          </Show>
          <Show when={panel() === "globals" && isPktl()}>
            <GlobalsPanel doc={recipeDoc()} />
          </Show>
          <Show when={panel() === "layers" && !isPktl()}>
            <LayersPanel doc={doc()} />
          </Show>
          <Show when={panel() === "hex" && !isPktl()}>
            <HexPanel doc={doc()} />
          </Show>
        </aside>
      </main>
    </div>
  );
}
