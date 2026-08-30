// 右侧面板：诊断 / 层栈 / HEX 预览（数据来自 LSP publishDiagnostics 与 analyze 信封）。

import { For, Show, createMemo, createSignal } from "solid-js";

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
      layers: { name: string; fields: Record<string, string>; raw: boolean }[];
      bytes: number;
      hex: string;
      warnings: string[];
      raw_only: boolean;
    }[];
  }[];
  total: number;
}

export type Panel = "diagnostics" | "layers" | "hex";

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

/** 层栈视图：sources → packets → layers（字段键值 + auto/raw 标注）。 */
export function LayersPanel(props: { doc: AnalyzeDoc | null; error: string | null }) {
  return (
    <div class="panel-body">
      <Show when={props.error} fallback={<LayersTable doc={props.doc} />}>
        <div class="diag diag-error">
          <span class="diag-msg">{props.error}</span>
        </div>
      </Show>
    </div>
  );
}

function LayersTable(props: { doc: AnalyzeDoc | null }) {
  const packet = createMemo(() => {
    const sources = props.doc?.sources ?? [];
    for (const src of sources) {
      if (src.packets.length > 0) return src.packets[0];
    }
    return null;
  });
  const packetCount = createMemo(() => props.doc?.total ?? 0);
  return (
    <Show
      when={packet()}
      fallback={
        <div class="empty-hint">
          {packetCount() === 0 ? "No packets yet — start typing a pipeline." : "Loading…"}
        </div>
      }
    >
      {(p) => (
        <div>
          <div class="pkt-meta">
            packet {p().idx}/{p().total} · {p().bytes} bytes
            <Show when={p().raw_only}>
              <span class="badge badge-raw">raw only</span>
            </Show>
          </div>
          <For each={p().warnings}>
            {(w) => <div class="diag diag-warn"><span class="diag-msg">{w}</span></div>}
          </For>
          <For each={p().layers}>
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
                    <For each={Object.entries(layer.fields)}>
                      {([k, v]) => (
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
    </Show>
  );
}

/** HEX 视图：16 字节/行（offset + hex + ascii）。 */
export function HexPanel(props: { doc: AnalyzeDoc | null }) {
  const packet = createMemo(() => {
    const sources = props.doc?.sources ?? [];
    for (const src of sources) {
      if (src.packets.length > 0) return src.packets[0];
    }
    return null;
  });
  return (
    <div class="panel-body">
      <Show when={packet()} fallback={<div class="empty-hint">No packet bytes.</div>}>
        {(p) => <HexView hex={p().hex} />}
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

/** 面板页签。 */
export function PanelTabs(props: {
  panel: Panel;
  setPanel: (p: Panel) => void;
  diagCount: number;
}) {
  const [tabs] = createSignal<{ id: Panel; label: string }[]>([
    { id: "diagnostics", label: "Diagnostics" },
    { id: "layers", label: "Layers" },
    { id: "hex", label: "Hex" },
  ]);
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
