// prping web —— 应用骨架：头部（状态/库文件）+ 左编辑器 + 右面板。
// 数据流：编辑 →（防抖）→ LSP didChange + analyze 请求 → 诊断/层栈/HEX 更新。

import { onCleanup, onMount, createSignal, For, Show } from "solid-js";
import type { EditorView } from "@codemirror/view";
import { applyDiagnostics, createEditor, setDoc } from "./cm";
import { LspClient, type LspDiagnostic } from "./lsp";
import type { AnalyzeDoc, Panel } from "./panels";
import { DiagnosticsPanel, HexPanel, LayersPanel, PanelTabs } from "./panels";
import { SAMPLE_DOC } from "./sample";
import { PrpingClient, type Status } from "./ws";

export function App() {
  const [status, setStatus] = createSignal<Status>("connecting");
  const [libs, setLibs] = createSignal<string[]>([]);
  const [libDirs, setLibDirs] = createSignal<string[]>([]);
  const [activeLib, setActiveLib] = createSignal<string | null>(null);
  const [diags, setDiags] = createSignal<LspDiagnostic[]>([]);
  const [doc, setAnalyzeDoc] = createSignal<AnalyzeDoc | null>(null);
  const [analyzeError, setAnalyzeError] = createSignal<string | null>(null);
  const [panel, setPanel] = createSignal<Panel>("layers");
  const [version, setVersion] = createSignal("");

  let editorHost!: HTMLDivElement;
  let view: EditorView;
  let lastText = SAMPLE_DOC;

  const client = new PrpingClient();
  const lsp = new LspClient(client);

  // 服务端 → 客户端的 LSP 消息（initialize 应答 / publishDiagnostics / 补全悬停
  // 应答）全部经此回调进入 LspClient——漏接则诊断与补全全哑
  client.onLsp = (m) => lsp.handle(m);

  // 诊断推送 → 编辑器 squiggle + 右侧面板
  lsp.onDiagnostics = (d) => {
    setDiags(d);
    if (view) applyDiagnostics(view, d);
  };

  client.onStatus = (s) => {
    setStatus(s);
    if (s === "connected") {
      // 首连与重连统一在此初始化（WS OPEN 后才可发送）：重建 LSP 会话并
      // 重放当前文档、刷新分析与库列表
      lsp.start(lsp.documentUri, lastText);
      refreshAnalyze();
      refreshLibs();
    }
  };

  let analyzeTimer: ReturnType<typeof setTimeout> | null = null;
  let changeTimer: ReturnType<typeof setTimeout> | null = null;

  function refreshAnalyze() {
    if (analyzeTimer) clearTimeout(analyzeTimer);
    analyzeTimer = setTimeout(async () => {
      const res = await client.analyze(lsp.documentUri, lastText);
      if (res.ok) {
        setAnalyzeError(null);
        setAnalyzeDoc(res.data as AnalyzeDoc);
      } else {
        // 解析错误已在 LSP 诊断展示；这里记录服务端错误文案（如内部异常）
        setAnalyzeError(res.error as string);
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

  function onEditorUpdate(text: string) {
    lastText = text;
    setActiveLib(null);
    // LSP 全文同步 + 分析共用一个防抖节奏
    if (changeTimer) clearTimeout(changeTimer);
    changeTimer = setTimeout(() => lsp.change(text), 250);
    refreshAnalyze();
  }

  async function openLib(name: string) {
    const res = await client.readLib(name);
    if (!res.ok) {
      setAnalyzeError(res.error as string);
      return;
    }
    const text = (res.data as { text: string }).text;
    setDoc(view, text);
    lastText = text;
    setActiveLib(name);
    setAnalyzeError(null);
    lsp.openDoc(`file:///${name}`, text);
    refreshAnalyze();
  }

  onMount(async () => {
    view = createEditor(editorHost, {
      doc: SAMPLE_DOC,
      onUpdate: onEditorUpdate,
      completion: (pos) => lsp.completion(pos.line, pos.character),
      hover: (pos) => lsp.hover(pos.line, pos.character),
    });

    // 配置（版本号 + WS 路径）
    try {
      const cfg = await fetch("/config.json").then((r) => r.json());
      setVersion(cfg.version ?? "");
    } catch {
      /* dev 代理未起时忽略 */
    }

    // 连接成功后的 LSP 会话重建 / 分析刷新 / 库列表统一走 onStatus("connected")
    // 钩子——此处立即发送会在 CONNECTING 状态撞 WebSocket DOMException
    client.connect();
  });

  onCleanup(() => client.close());

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
        <span class="libs-label">eng_lib:</span>
        <div class="libs">
          <For each={libs()}>
            {(name) => (
              <button
                class="lib-chip"
                classList={{ active: activeLib() === name }}
                onClick={() => openLib(name)}
                title={`open ${name} (read-only)`}
              >
                {name}
              </button>
            )}
          </For>
        </div>
      </header>
      <main class="main">
        <section class="editor-pane" ref={editorHost} />
        <aside class="side-pane">
          <PanelTabs panel={panel()} setPanel={setPanel} diagCount={diags().length} />
          <Show when={panel() === "diagnostics"}>
            <DiagnosticsPanel diags={diags()} />
          </Show>
          <Show when={panel() === "layers"}>
            <LayersPanel doc={doc()} error={analyzeError()} />
          </Show>
          <Show when={panel() === "hex"}>
            <HexPanel doc={doc()} />
          </Show>
          <footer class="libs-dirs" title="effective library directories">
            {libDirs().join(" · ")}
          </footer>
        </aside>
      </main>
    </div>
  );
}
