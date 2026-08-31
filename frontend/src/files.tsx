// 左栏文件管理：工作区（examples / 自定义文件夹，可编辑）+ eng_lib 库（只读）。
// 工作区目录树来自 tree 信封（目录在前、已排序、深度缩进、目录行点击折叠/展开、
// **默认全收起**——跟踪展开集，不在集内的目录一律折叠）；
// eng_lib 来自 list 信封。文件/目录行悬停出现改名/删除按钮，右键菜单同功能。
// 图标统一为内联 SVG（Feather 风格描边、currentColor 单色）——不用 emoji，跨平台
// 渲染一致、按钮风格统一。

import { For, Show, createEffect, createMemo, createSignal, onCleanup } from "solid-js";
import { Portal } from "solid-js/web";

export interface TreeEntry {
  path: string; // 工作区相对路径（'/' 分隔）
  dir: boolean;
  pkt: boolean; // .pkt/.pktl（false = 其他文件，暗色展示，同样可改名/删除）
}

export interface CurrentFile {
  root: "ws" | "lib";
  path: string;
}

function depth(path: string): number {
  return path.split("/").length - 1;
}

function basename(path: string): string {
  return path.split("/").pop() ?? path;
}

/** 统一图标：描边风格内联 SVG（子路径可合并进单个 d）。 */
function Icon(props: { d: string; size?: number }) {
  return (
    <svg
      width={props.size ?? 14}
      height={props.size ?? 14}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d={props.d} />
    </svg>
  );
}

/** 图标路径（Feather 风格）。 */
const I = {
  file: "M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM13 2v6h6",
  refresh:
    "M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15",
  folder:
    "M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z",
  folderPlus:
    "M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2zM12 11v6M9 14h6",
  filePlus:
    "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M12 18v-6M9 15h6",
  chevronDown: "M6 9l6 6 6-6",
  chevronsUp: "M17 11l-5-5-5 5M17 18l-5-5-5 5",
  chevronsDown: "M7 13l5 5 5-5M7 6l5 5 5-5",
  pencil: "M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z",
  x: "M18 6L6 18M6 6l12 12",
};

export function FileSidebar(props: {
  wsRoot: string | null;
  entries: TreeEntry[];
  libs: string[];
  libDirs: string[];
  current: CurrentFile | null;
  onOpenWs: (path: string) => void;
  onOpenLib: (name: string) => void;
  onDelete: (path: string, isDir: boolean) => void;
  onRename: (path: string) => void;
  onMkdir: () => void;
  onRefresh: () => void;
  onOpenFolder: () => void;
  onNewFile: () => void;
}) {
  // 展开的目录集合：**默认全收起**——不在集合内的目录一律折叠（新建目录、
  // 切换工作区后的新树均自然收起，无需按工作区重置状态）
  const [expanded, setExpanded] = createSignal<Set<string>>(new Set());
  function toggleDir(path: string) {
    const next = new Set(expanded());
    if (next.has(path)) next.delete(path);
    else next.add(path);
    setExpanded(next);
  }
  // 折叠过滤：任一祖先目录未展开则整行隐藏（目录行自身只受祖先影响）
  const visibleEntries = createMemo(() => {
    const set = expanded();
    return props.entries.filter((e) => {
      const parts = e.path.split("/");
      parts.pop();
      let acc = "";
      for (const seg of parts) {
        acc = acc ? acc + "/" + seg : seg;
        if (!set.has(acc)) return false;
      }
      return true;
    });
  });
  // 全部折叠/全部展开 toggle：所有目录都不在展开集内 = 已全折叠
  const allDirs = createMemo(() => props.entries.filter((e) => e.dir).map((e) => e.path));
  const allCollapsed = createMemo(() => {
    const dirs = allDirs();
    return dirs.length > 0 && dirs.every((d) => !expanded().has(d));
  });
  function toggleAll() {
    setExpanded(allCollapsed() ? new Set(allDirs()) : new Set<string>());
  }

  // ── 右键菜单（行内悬停按钮之外的第二入口；空白区 = 新建/刷新）──────
  type MenuState = { x: number; y: number; entry: TreeEntry | null };
  const [menu, setMenu] = createSignal<MenuState | null>(null);

  function openEntryMenu(ev: MouseEvent, e: TreeEntry) {
    ev.preventDefault();
    ev.stopPropagation(); // 不落到空白区菜单
    setMenu({ x: ev.clientX, y: ev.clientY, entry: e });
  }

  function openBlankMenu(ev: MouseEvent) {
    ev.preventDefault();
    setMenu({ x: ev.clientX, y: ev.clientY, entry: null });
  }

  function closeMenu() {
    setMenu(null);
  }

  /** 视口夹取：菜单整体保持在窗口内（估算高度按条目数）。 */
  const menuPos = createMemo(() => {
    const m = menu();
    if (!m) return null;
    const items = m.entry ? (m.entry.dir ? 2 : 3) : props.wsRoot ? 3 : 2;
    return {
      left: `${Math.max(4, Math.min(m.x, window.innerWidth - 176 - 6))}px`,
      top: `${Math.max(4, Math.min(m.y, window.innerHeight - items * 27 - 12))}px`,
    };
  });

  // 菜单打开期间挂全局关闭监听（点外部/Escape/滚动/失焦/改窗口）
  createEffect(() => {
    if (!menu()) return;
    const onDown = (ev: PointerEvent) => {
      const t = ev.target;
      if (t instanceof Element && t.closest(".ctx-menu")) return; // 菜单内点击交给 onClick
      setMenu(null);
    };
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") setMenu(null);
    };
    const close = () => setMenu(null);
    document.addEventListener("pointerdown", onDown, true);
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("scroll", close, true);
    window.addEventListener("blur", close);
    window.addEventListener("resize", close);
    onCleanup(() => {
      document.removeEventListener("pointerdown", onDown, true);
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("scroll", close, true);
      window.removeEventListener("blur", close);
      window.removeEventListener("resize", close);
    });
  });

  /** 执行菜单动作：先关菜单再分发（prompt 类阻塞对话框无碍）。 */
  function menuAction(
    action: "open" | "rename" | "delete" | "newfile" | "newdir" | "openfolder" | "refresh",
  ) {
    const m = menu();
    closeMenu();
    if (!m) return;
    switch (action) {
      case "open":
        if (m.entry && !m.entry.dir) props.onOpenWs(m.entry.path);
        break;
      case "rename":
        if (m.entry) props.onRename(m.entry.path);
        break;
      case "delete":
        if (m.entry) props.onDelete(m.entry.path, m.entry.dir);
        break;
      case "newfile":
        props.onNewFile();
        break;
      case "newdir":
        props.onMkdir();
        break;
      case "openfolder":
        props.onOpenFolder();
        break;
      case "refresh":
        props.onRefresh();
        break;
    }
  }
  return (
    <nav class="sidebar">
      <div class="side-section">
        <div class="side-head">
          <span class="side-title" title={props.wsRoot ?? ""}>
            workspace{props.wsRoot ? "" : " (none)"}
          </span>
          <span class="side-actions">
            <button class="icon-btn" title="refresh tree" onClick={() => props.onRefresh()}>
              <Icon d={I.refresh} />
            </button>
            <button
              class="icon-btn"
              title={allCollapsed() ? "expand all" : "collapse all"}
              disabled={allDirs().length === 0}
              onClick={() => toggleAll()}
            >
              <Icon d={allCollapsed() ? I.chevronsDown : I.chevronsUp} />
            </button>
            <button class="icon-btn" title="open a custom folder" onClick={() => props.onOpenFolder()}>
              <Icon d={I.folder} />
            </button>
            <button class="icon-btn" title="new folder" onClick={() => props.onMkdir()}>
              <Icon d={I.folderPlus} />
            </button>
            <button class="icon-btn" title="new file" onClick={() => props.onNewFile()}>
              <Icon d={I.filePlus} />
            </button>
          </span>
        </div>
        <Show
          when={props.wsRoot}
          fallback={<div class="empty-hint">No workspace — open a folder.</div>}
        >
          <div class="tree" onContextMenu={openBlankMenu}>
            <For each={visibleEntries()}>
              {(e) => (
                <Show
                  when={!e.dir}
                  fallback={
                    <div
                      class="tree-dir"
                      style={{ "padding-left": `${8 + depth(e.path) * 12}px` }}
                      onClick={() => toggleDir(e.path)}
                      onContextMenu={(ev) => openEntryMenu(ev, e)}
                      title={
                        (expanded().has(e.path) ? "collapse " : "expand ") + basename(e.path)
                      }
                    >
                      <span class="chev" classList={{ collapsed: !expanded().has(e.path) }}>
                        <Icon d={I.chevronDown} size={11} />
                      </span>
                      <Icon d={I.folder} size={12} />
                      <span class="tree-name">{basename(e.path)}</span>
                      <span class="tree-ops">
                        <button
                          class="tree-del"
                          title={`rename/move ${e.path}`}
                          onClick={(ev) => {
                            ev.stopPropagation();
                            props.onRename(e.path);
                          }}
                        >
                          <Icon d={I.pencil} size={12} />
                        </button>
                        <button
                          class="tree-del"
                          title={`delete folder ${e.path} (recursive)`}
                          onClick={(ev) => {
                            ev.stopPropagation();
                            props.onDelete(e.path, true);
                          }}
                        >
                          <Icon d={I.x} size={12} />
                        </button>
                      </span>
                    </div>
                  }
                >
                  <div
                    class="tree-file"
                    classList={{
                      active: props.current?.root === "ws" && props.current?.path === e.path,
                      "tree-other": !e.pkt,
                    }}
                    style={{ "padding-left": `${8 + depth(e.path) * 12}px` }}
                    onClick={() => props.onOpenWs(e.path)}
                    onContextMenu={(ev) => openEntryMenu(ev, e)}
                    title={e.path}
                  >
                    <span class="tree-name">{basename(e.path)}</span>
                    <span class="tree-ops">
                      <button
                        class="tree-del"
                        title={`rename/move ${e.path}`}
                        onClick={(ev) => {
                          ev.stopPropagation();
                          props.onRename(e.path);
                        }}
                      >
                        <Icon d={I.pencil} size={12} />
                      </button>
                      <button
                        class="tree-del"
                        title={`delete ${e.path}`}
                        onClick={(ev) => {
                          ev.stopPropagation();
                          props.onDelete(e.path, false);
                        }}
                      >
                        <Icon d={I.x} size={12} />
                      </button>
                    </span>
                  </div>
                </Show>
              )}
            </For>
          </div>
        </Show>
      </div>
      <div class="side-section libs-section">
        <div class="side-head">
          <span class="side-title">
            eng_lib<span class="ro-badge">read-only</span>
          </span>
        </div>
        <div class="tree">
          <For each={props.libs}>
            {(name) => (
              <div
                class="tree-file lib-file"
                classList={{
                  active: props.current?.root === "lib" && props.current?.path === name,
                }}
                onClick={() => props.onOpenLib(name)}
                title={`open ${name} (read-only)`}
              >
                <span class="tree-name">{name}</span>
              </div>
            )}
          </For>
        </div>
        <footer class="libs-dirs" title="effective library directories">
          {props.libDirs.join(" · ")}
        </footer>
      </div>
      <Portal>
        <Show when={menuPos()}>
          {(pos) => (
            <div class="ctx-menu" role="menu" style={{ left: pos().left, top: pos().top }}>
              <Show when={menu()?.entry} fallback={<BlankMenuItems onAction={menuAction} hasWs={!!props.wsRoot} />}>
                {(e) => (
                  <>
                    <Show when={!e().dir}>
                      <button type="button" class="ctx-item" role="menuitem" onClick={() => menuAction("open")}>
                        <Icon d={I.file} size={13} /> open
                      </button>
                    </Show>
                    <button type="button" class="ctx-item" role="menuitem" onClick={() => menuAction("rename")}>
                      <Icon d={I.pencil} size={13} /> rename/move
                    </button>
                    <button type="button" class="ctx-item ctx-danger" role="menuitem" onClick={() => menuAction("delete")}>
                      <Icon d={I.x} size={13} /> {e().dir ? "delete folder" : "delete"}
                    </button>
                  </>
                )}
              </Show>
            </div>
          )}
        </Show>
      </Portal>
    </nav>
  );
}

/** 空白区右键菜单项：有工作区 = 新建文件/新建文件夹/刷新；无 = 打开文件夹/刷新。 */
function BlankMenuItems(props: {
  hasWs: boolean;
  onAction: (action: "newfile" | "newdir" | "openfolder" | "refresh") => void;
}) {
  return (
    <Show
      when={props.hasWs}
      fallback={
        <>
          <button type="button" class="ctx-item" role="menuitem" onClick={() => props.onAction("openfolder")}>
            <Icon d={I.folder} size={13} /> open a custom folder
          </button>
          <button type="button" class="ctx-item" role="menuitem" onClick={() => props.onAction("refresh")}>
            <Icon d={I.refresh} size={13} /> refresh
          </button>
        </>
      }
    >
      <>
        <button type="button" class="ctx-item" role="menuitem" onClick={() => props.onAction("newfile")}>
          <Icon d={I.filePlus} size={13} /> new file
        </button>
        <button type="button" class="ctx-item" role="menuitem" onClick={() => props.onAction("newdir")}>
          <Icon d={I.folderPlus} size={13} /> new folder
        </button>
        <button type="button" class="ctx-item" role="menuitem" onClick={() => props.onAction("refresh")}>
          <Icon d={I.refresh} size={13} /> refresh
        </button>
      </>
    </Show>
  );
}

// ── 文件夹选择对话框（web dialog；打开文件夹的唯一入口）──────
//
// 服务端 browse 信封驱动目录导航（子目录进出 + 路径直输），确定后由上层走
// workspace path 信封校验并设为工作区。

export interface BrowseResult {
  ok: boolean;
  path?: string;
  parent?: string | null;
  dirs?: string[];
  error?: string;
}

export function FolderDialog(props: {
  open: boolean;
  /** 初始浏览目录（当前工作区根，缺省服务端主目录）。 */
  initial: string;
  /** 浏览目录（App 侧转调 client.browse）。 */
  onBrowse: (path?: string) => Promise<BrowseResult>;
  /** 确认选择；返回 null 表示成功（上层关框），否则返回错误文案就地展示。 */
  onConfirm: (path: string) => Promise<string | null>;
  onClose: () => void;
}) {
  const [cur, setCur] = createSignal("");
  const [parent, setParent] = createSignal<string | null>(null);
  const [input, setInput] = createSignal("");
  const [dirs, setDirs] = createSignal<string[]>([]);
  const [err, setErr] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  // 浏览序号：连续快速点击时响应乱序到达，只应用最后一次请求的结果
  let browseSeq = 0;

  async function go(p?: string) {
    const seq = ++browseSeq;
    setLoading(true);
    setErr(null);
    const r = await props.onBrowse(p);
    if (seq !== browseSeq) return; // 过期响应丢弃
    setLoading(false);
    if (r.ok) {
      setCur(r.path ?? "");
      setInput(r.path ?? "");
      setParent(r.parent ?? null);
      setDirs(r.dirs ?? []);
    } else {
      setErr(r.error ?? "browse failed");
    }
  }

  // 每次打开都从初始目录重新浏览（当前工作区根 = examples；状态可预期，
  // 不残留上次导航位置与上次错误；initial 为空时服务端兜底主目录）
  createEffect(() => {
    if (props.open) {
      setErr(null);
      void go(props.initial.trim() || undefined);
    }
  });

  function join(cur: string, name: string): string {
    return cur.endsWith("/") ? cur + name : cur + "/" + name;
  }

  async function confirm() {
    const e = await props.onConfirm(input().trim());
    if (e) setErr(e);
    else props.onClose();
  }

  return (
    <Show when={props.open}>
      <div class="dlg-backdrop" onClick={props.onClose}>
        <div class="dlg" onClick={(e) => e.stopPropagation()}>
          <div class="dlg-title">Open folder</div>
          <div class="dlg-path">
            <input
              class="dlg-input"
              value={input()}
              placeholder="/absolute/path (Enter to jump)"
              autofocus
              onInput={(e) => setInput(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void go(input().trim());
                if (e.key === "Escape") props.onClose();
              }}
            />
            <button class="icon-btn" title="jump to path" onClick={() => void go(input().trim())}>
              →
            </button>
          </div>
          <div class="dlg-list">
            <Show when={parent()}>
              {(p) => (
                <div class="dlg-row dlg-up" onClick={() => void go(p())}>
                  ../
                </div>
              )}
            </Show>
            <For each={dirs()}>
              {(d) => (
                <div class="dlg-row" onClick={() => void go(join(cur(), d))}>
                  {d}/
                </div>
              )}
            </For>
            <Show when={dirs().length === 0 && !loading()}>
              <div class="empty-hint">no subdirectories</div>
            </Show>
          </div>
          <Show when={err()}>
            <div class="dlg-err">{err()}</div>
          </Show>
          <div class="dlg-actions">
            <span class="dlg-spacer" />
            <button class="dlg-btn" onClick={props.onClose}>
              Cancel
            </button>
            <button class="dlg-btn dlg-primary" onClick={() => void confirm()}>
              Open
            </button>
          </div>
        </div>
      </div>
    </Show>
  );
}
