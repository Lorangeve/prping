# 设计文档：`prping web` Web 编辑器

> 状态：已实现（MVP：骨架 + LSP 桥 + CodeMirror 闭环 + 实时预览 + 库浏览；资源分发默认 `UI/` 目录 + 可选 `web-embed` 内嵌；左栏文件管理——工作区 examples 可编辑、eng_lib 只读；执行——Run 页签/顶栏 ▶ spawn 自身 `packet` 子命令，输出流式回传）
> 范围：`prping web [--addr ADDR] [--port N] [--open] [--lib PATH]`
> 关联模块：`crates/prping-core/src/web/`、`frontend/`、`crates/prping-core/build.rs`

---

## 1. 背景与目标

为 prping 的包构造引擎（packet DSL：`.pkt` / `.pktl`）提供一个**实时可编辑**的图形界面，
作为 `engine` / `packet` 子命令的可视化补充：

- **文本编辑**：CodeMirror 6 + 引擎现有 LSP（诊断 / 补全 / 悬停 / 文档符号）；
- **实时反馈**：编辑即分析——层栈字段、字节数、hexdump、层序警告实时刷新；
- **协议学习**：eng_lib 协议库（headers.pkt 等 21 个文件）只读浏览；
- **执行**：Run 页签 / 顶栏 ▶ 运行工作区 `.pkt/.pktl`（target/count/wait/listen/fuzz/raw/
  iface/params）——服务端 spawn 自身 `packet` 子命令（§4.9），输出与退出码流式回显；
- **文件管理**：左栏文件树——默认打开**启动目录**的 `examples/` 文件夹（发现方法与
  `UI/`、`lib` 一致：二进制目录优先、其次启动目录），可编辑/保存（Ctrl+S）/新建/删除；
  也可从页面打开任意本地文件夹作工作区；eng_lib 库文件始终只读；
- **零安装体验**：`prping web --open` 一条命令打开浏览器即用——默认读二进制目录/`启动目录`的 `UI/` 文件夹（`just dist` 产物布局自带）；`--features web-embed` 时前端内嵌二进制（单文件分发）。

### 非目标（本期）

- 不做用户系统 / 远程部署形态（默认仅回环，单用户本地工具）；
- eng_lib 库文件不做写入接口（只读；工作区写入限根内 `.pkt/.pktl`，见 §4.8）；
- 不引入 tokio（与项目 smol 栈保持一致）。

---

## 2. 总体架构

```text
浏览器（SolidJS SPA；默认读 UI/ 目录，--features web-embed 时内嵌二进制）
 ├─ CodeMirror 6 编辑器 ── LSP JSON-RPC（WS 信封透传 → 内存管道 → run_lsp_on）
 ├─ 层栈 / HEX / 诊断面板 ── analyze 信封（内存文本 → engine --json 同构文档）
 ├─ 左栏文件管理 ── tree / read(root=ws) / save / delete / workspace / browse 信封（可写工作区；
 │                   📂 = web 文件夹选择对话框，原生系统选择框为同机次选）
 ├─ Run 面板 / 顶栏 ▶ ── run / run_stop 信封（服务端 spawn 自身 CLI 的 packet 子命令，
 │                       输出/退出经 run_out / run_exit 流式回传）
 └─ eng_lib 库浏览 ── list / read 信封（服务端只读）
           │  HTTP（静态资源 + /config.json）＋ WebSocket（/ws）同端口
 ──────────┴──────────────────────────────────────────────
 prping web（crates/prping-core/src/web/，smol 异步）
 ├─ http.rs      极简 HTTP/1.1 GET/HEAD 响应（Content-Length、keep-alive）
 ├─ ws.rs        WS 会话：信封分派 + Content-Length 分帧解包 + LSP 桥 + 会话工作区状态
 ├─ workspace.rs 可写工作区：默认 examples 发现（同 UI/ 方法）+ 路径校验/读写删/目录树
 ├─ run.rs       执行桥：run 信封 → spawn 自身二进制 packet 子命令（输出/退出流式回传）
 ├─ pipe.rs      异步↔阻塞字节桥（smol::channel 实现 io::Read/Write）
 └─ assets.rs    静态资源双模式：默认读 UI/ 目录；web-embed feature 时 rust-embed
                 （debug 直读 dist / release 编译期内嵌）
                     │
        ──── 进程内（无需 IPC）────
        ├─ engine LSP（engine/eng/lsp.rs::run_lsp_on，阻塞线程）
        ├─ analyze_text_json（engine/eng/mod.rs，进程内直接调用）
        ├─ packet 子进程（web/run.rs：current_exe + packet 子命令，输出逐行回传）
        └─ eng_lib 只读文件访问（effective_libs 目录扫描）
```

核心思路：

1. **特权留在服务端进程**。raw socket（cap_net_raw）与文件系统访问都发生在 `prping`
   进程内，浏览器零特权——这是把引擎搬进 web 的天然优点；后续「发送/监听」按钮直接复用
   `packet` 子命令的发送路径，无需额外授权体系。
2. **LSP 零改动复用**。现有 `run_lsp_on<R: Read, W: Write>` 本就与 IO 解耦
   （stdio 只是默认形态，测试早已用内存 `Cursor` 跑通），web 侧只需两根内存管道。
3. **单一端口单进程**。HTTP 静态与 WebSocket 共用同一 `TcpListener`，按请求头
   `Upgrade: websocket` 分流；无跨端口配置、无 CORS 问题。

---

## 3. 技术选型与理由

### 3.1 后端（Rust）

| 关注点 | 选型 | 理由 / 落选者 |
|---|---|---|
| HTTP 服务 | 手写极简 HTTP/1.1（`web/http.rs`，~200 行） | 只需 GET/HEAD + Content-Length + keep-alive。hyper+smol-hyper 引入三套 IO trait 适配（hyper rt / futures-io / std）只为几条静态路由，得不偿失；axum 拖 tokio 违背 smol 栈；trillium 全家桶依赖面大 |
| WebSocket | `async-tungstenite`（默认 feature：`handshake` + `futures-03-sink`，**无 tokio**） | `smol::Async<TcpStream>`（async-io 2.6）原生实现 futures-io `AsyncRead/Write`，可直接作传输层；升级握手手工完成（101 + `derive_accept_key`），再用 `WebSocketStream::from_raw_socket` 包裸流 |
| 资源分发 | **默认读盘**：运行期从二进制所在目录（优先）或启动目录的 `UI/` 文件夹读前端产物——前端与 Rust 编译零耦合，产物体积小、构建无需 node；**可选 `web-embed` feature**：`rust-embed` 8，debug 直读 `frontend/dist`（改前端重跑构建即生效），release 编译期内嵌（单文件分发） |
| MIME | `mime_guess` | rust-embed 传递依赖，提升为直接依赖零成本 |
| 打开浏览器 | `open` 5 | 跨平台 open/xdg-open/start，`that_detached` 不阻塞服务启动 |
| 异步运行时 | 复用 `smol` 2 | 与全项目一致；`smol::spawn` / `smol::unblock` / `smol::channel` / `smol::Timer` |

### 3.2 前端（`frontend/`）

| 关注点 | 选型 | 理由 / 落选者 |
|---|---|---|
| 框架 | SolidJS 1.9 + Vite 6（`vite-plugin-solid`） | 纯本地单页应用，不需要 SSR/文件路由——**不用 SolidStart**（Nitro 输出形态嵌二进制别扭，纯 Vite 的 `dist/` 一个目录即可 rust-embed） |
| 编辑器 | CodeMirror 6（state/view/language/lint/autocomplete/search/commands） | Lezer 生态可后续换正式语法；本期用 `StreamLanguage` 简易分词 |
| LSP 客户端 | 自写薄封装（`src/lsp.ts`，~150 行） | 服务端仅 5 个能力（diagnostics/completion/hover/documentSymbol/definition），`codemirror-languageserver` 泛用封装反而重 |
| Markdown 渲染 | 自写极简渲染器（`src/markdown.ts`） | LSP 文档只产出固定子集（标题/粗体/行内代码/列表/围栏代码块/段落）；先整体转义 HTML 实体再套标记，innerHTML 注入安全。落选 marked/markdown-it（为一个 tooltip 引整库不值） |
| UI | 手写 CSS（深色，~300 行） | 单页三面板布局，引入 Tailwind/Kobalte 收益低 |
| 包管理 | bun（build.rs/justfile 自动降级 npm） | bun 自带锁文件与脚本运行器、install 快；npm 随 node 附带兜底 |

### 3.3 依赖增量

Rust 侧 +5 crate（async-tungstenite / rust-embed（可选，随 `web-embed`）/ open /
futures-util / mime_guess），npm 侧 solid-js + codemirror 6 件套 + vite 全家（dev）。
产物体积 +~2MB（仅 `web-embed` 内嵌时进二进制；默认分发为 `prping` + `UI/` 目录）。

---

## 4. 服务端设计

### 4.1 模块结构

```text
crates/prping-core/src/web/
├── mod.rs     serve_web(WebConfig) 入口：bind → 横幅（libs/ui/workspace 行）→ --open → accept
│              handle_conn：读请求头 → WS 升级（仅 /ws）或 HTTP 分发（keep-alive 循环）
├── http.rs    请求头解析（CRLFCRLF 截断，MAX_HEAD=64KB）+ 响应 + 路由
├── ws.rs      accept（手工 101）+ session（三分任务 + 会话工作区状态）+ 信封分派 + FrameDecoder
├── workspace.rs 工作区（可写）：default_workspace（examples 发现）+ validate_rel/resolve_in_root
│              （逐段校验 + canonicalize 根内断言）+ tree/read_file/save_file/delete_entry（目录递归）/open_folder
├── pipe.rs    ChanReader/ChanWriter（smol::channel ↔ io::Read/Write，EOF=发送端 drop）
└── assets.rs  静态资源双模式：默认 UI/ 目录（二进制目录→启动目录）；
                web-embed 时 rust-embed Assets（folder=../../frontend/dist）
                lookup / index_missing / source_label / missing_hint
```

公开 API（lib.rs，`#[cfg(feature = "web")]` 门控）：`serve_web(WebConfig) -> anyhow::Result<()>`
（async，CLI 侧 `smol::block_on` 驱动）、`WebConfig { addr, port, libs, open_browser }`、
`analyze_text_json(uri, text, params, libs)`。`web` feature **默认不启用**——纯 `cargo build`
不编译 web 模块、CLI 无 `web` 子命令（产物体积更小）；justfile 的 build/check/test
配方统一以 `--features prping/web` 启用（`web-embed` 隐含 `web`）。

### 4.2 连接生命周期

```text
accept ──→ handle_conn（每连接一个 smol task）
             │ read_head（CRLFCRLF，≤64KB）
             ├─ Upgrade: websocket 且 path=/ws 且有 Sec-WebSocket-Key
             │    → ws::accept：写 101（derive_accept_key）→ from_raw_socket
             │    → ws::session（流所有权移交，连接不再有 HTTP）
             └─ 其余 → GET/HEAD 分发 → keep-alive 循环 / Connection: close 退出
```

- 方法非 GET/HEAD → 405 后断开；WS 请求路径非 `/ws` 或缺 key → 404 后断开。
- Ctrl+C：accept 循环放独立 task，主循环 `Timer(300ms)` 轮询 `interrupted()`（与
  `serve` 的中断语义一致：首次优雅退出，再次由信号处理器强制退出）。

### 4.3 WS 会话（三分任务 + 通道）

```text
            in_tx/in_rx (Vec<u8>)            out_tx/out_rx (Vec<u8>)
 WS 读任务 ──────────────────────→ LSP 线程 ─────────────────→ 帧转发任务
 (source.next)    信封里 lsp 消息     run_lsp_on               out_rx.recv
     │            按 Content-Length   (ChanReader /            → FrameDecoder
     │            分帧入队             ChanWriter)             → 解出 JSON
     │                                                                │
     └── analyze/list/read：smol::unblock 执行 ──→ 结果信封 ──┐       │
                                                             ▼       ▼
                              reply_rx (serde_json::Value) ← 回推主循环
                                                               │ sink.send
                                                               ▼
                                                          WebSocket 客户端
```

**EOF 传导链**（无泄漏的关键）：客户端断开 → WS 读任务结束 → `in_tx` drop →
LSP `ChanReader` 读到 EOF → `run_lsp_on` 返回 → `out_tx`（ChanWriter）drop →
帧转发任务结束 → `reply_rx` 关闭 → 回推主循环退出 → session 返回。
每条 WS 连接一个独立 LSP 会话（浏览器多标签互不干扰）。

### 4.4 HTTP 路由

| 路径 | 行为 |
|---|---|
| `/`（及 `/index.html`） | `index.html`（内嵌 / UI 目录），`Cache-Control: no-cache` |
| `/assets/*` | 产物（vite 文件名带内容 hash），`public, max-age=31536000, immutable` |
| `/config.json` | `{"version": "0.1.0", "wsPath": "/ws"}`，no-cache |
| 其余 | 404 |
| `/` 且前端资源缺失 | **503** + 按模式给提示（i18n）：内嵌 = `web.frontend_missing`（构建方式）；UI 目录 = `web.ui_missing`（放置位置：<二进制目录>/UI 或启动目录/UI） |

资源键两种模式共用同一校验（`sanitize_key`）：`/` → `index.html`，其余剥前导
`/` 后**逐段校验**——空段、点开头（`.`/`..`/隐藏文件）、反斜杠、冒号一律拒绝，
余下必为单一路径组件，内嵌键精确匹配 / UI 目录拼接均不可能穿越。请求头超 64KB →
连接关闭；HEAD 只回头部。

### 4.5 信封协议（WS 文本帧，一帧一信封 JSON）

客户端 → 服务端：

```jsonc
{ "type": "lsp", "message": { …JSON-RPC 消息原样… } }
{ "type": "analyze", "id": 1, "uri": "file:///scratch.pkt",
  "text": "…编辑器全文…", "params": { "k": "v" } }
{ "type": "list", "id": 2 }                       // 列库文件（.pkt/.pktl 文件名 + 目录）
{ "type": "read", "id": 3, "name": "net.pkt" }    // 读库文件（仅纯文件名）；带 root:"ws" 读工作区
{ "type": "tree", "id": 4 }                       // 工作区目录树（默认 examples/）
{ "type": "save", "id": 5, "name": "a/b.pkt", "text": "…" }  // 保存工作区文件（可写）
{ "type": "delete", "id": 6, "name": "a/b.pkt" }  // 删除工作区条目（目录 = 递归删除）
{ "type": "rename", "id": 6, "from": "a.pkt", "to": "b/c.pkt" }  // 重命名/移动（目标存在则拒绝）
{ "type": "mkdir",  "id": 6, "name": "sub/dir" }  // 新建目录（父链自动创建）
{ "type": "workspace", "id": 7, "path": "…" }     // 打开/重置/查询工作区根（path 省略=查询）
{ "type": "browse", "id": 8, "path": "/dir" }     // 列子目录（文件夹选择对话框数据源；缺省=主目录）
{ "type": "run", "id": 9, "name": "a/b.pktl",     // 运行工作区 .pkt/.pktl：spawn 自身二进制
  "target": "h:p", "params": {"k":"v"},           // packet 子命令；wait=数字秒 或 true（裸
  "count": N, "wait": SECS|true, "raw": bool,     // --wait 持续监听）；未给字段按 CLI 缺省
  "iface": "eth0", "out": "run.pcap", "globals": {"k":"v"},
  "json": bool }                                  // --json：JSONL 结构化输出（前端按行渲染
                                                  // 包/步骤/汇总；与 listen 冲突——前端禁用）
{ "type": "run_stop", "id": 10, "run": "run-0" }  // 停止运行：带 run id 精确停单个
                                                  // （任务管理）；缺省停本连接全部
```

服务端 → 客户端：

```jsonc
{ "type": "lsp", "message": { …publishDiagnostics / 请求应答… } }
{ "type": "result", "id": 1, "ok": true,  "data": … }   // run 的 data = { "run": "run-N" } 启动 ack
                                                  // run_stop 的 data = { "stopped": N } 停止数
{ "type": "result", "id": 1, "ok": false, "error": "…" }
{ "type": "run_out", "run": "run-0", "stream": "out"|"err", "text": "…" }  // 运行输出（逐行流式）
{ "type": "run_exit", "run": "run-0", "code": 0|null,    // 运行结束；code null = 被 kill
                      "stopped": bool, "truncated": bool }
{ "type": "error",  "message": "invalid envelope" }
```

要点：

- **lsp 消息重分帧**：服务端不信任客户端的 Content-Length，取 `message` 重新序列化
  成标准 JSON-RPC 帧（`Content-Length: N\r\n\r\n{body}`）再喂给 LSP；
- **FrameDecoder**（服务端 LSP 输出 → 信封）：增量解析 Content-Length 分帧；无
  Content-Length 的畸形头丢弃已缓冲部分防卡死；单帧上限 16MB（与 LSP 侧
  `MAX_LSP_MSG` 同量级），超限清空缓冲；
- `analyze`/`read`/`tree`/`save`/`delete` 在 `smol::unblock` 执行（CPU/IO 不阻塞
  异步循环），结果按请求 `id` 关联，乱序到达无碍；
- **会话工作区状态**：每条 WS 连接独立持有工作区根（`Mutex<Option<PathBuf>>`，初值 =
  服务端启动时发现的 examples）——`workspace` 信封切换只影响本连接，浏览器多标签
  互不干扰；重连后服务端侧重置回默认。
- **run 生命周期事件不占请求 id**：`run` 信封的 `id` 仅用于启动 ack（成功 = 活跃，
  失败 = `{ok:false}`）；后续输出/退出按 `run` id 字符串（`run-N`，每连接自增）
  关联，与请求-应答配对机制解耦。**同连接可并行多个运行**（多标签任务管理——
  前端每个 run 一个任务卡，chip 切换控制台 / ✕ 停止移除），全服并发由
  MAX_CONCURRENT_RUNS（8）封顶；`run_stop` 带 `run` id 停单个、缺省停本连接全部。

### 4.6 analyze：内存文本 → `engine --json` 同构文档

`eng/mod.rs` 重构：`analyze_file_json` 的文档构建逻辑提取为
`analyze_sources_doc(file_label, sources, total, libs, params)`，两个调用方共用：

- CLI：`engine FILE.pkt --json`（路径文件）；
- Web：新增 `analyze_text_json(uri, text, params, libs)`（内存文本）。
  解析复用 LSP 的 `try_parse`（提升为 `pub(crate)`）：`file://` URI →
  (模块名, 目录) 规则与 CLI/LSP 完全一致，相对 import 行为统一。

返回文档与 `engine --json` 同构：`sources → packets → layers(name/fields/raw) /
bytes / hex / warnings / raw_only`，前端三面板直接消费。

### 4.7 库浏览（只读）

- `list`：`effective_libs`（运行时 lib/ 发现 + `--lib` 附加）逐目录扫描 `*.pkt|*.pktl`，
  跨目录按文件名去重（先到先得，与解析器库搜索顺序一致），目录列表一并返回供前端展示；
- `read`：**仅接受纯文件名**（`Path::file_name() == Path` 校验，拒绝分隔符与 `..`），
  按库目录顺序查找读取——库文件无写接口。

### 4.8 工作区（可写，`web/workspace.rs`）

与只读库浏览相对，工作区内的 `.pkt/.pktl` **可写**（保存/删除/新建）。默认工作区
发现顺序与 UI/ 同构：**二进制目录/examples → 启动目录/examples**（`just dist` 布局
就地可用）；`workspace` 信封可为本连接打开任意本地目录（canonicalize 校验存在）。
写操作安全边界：

- 相对路径逐段校验（与 `assets.rs` 的 `sanitize_key` 同风格）：空段、点段、反斜杠、
  冒号（盘符/ADS）、Windows 保留设备名（`CON.pkt` 等）一律拒绝；扩展名按操作区分：
  **读/删/改名/建目录接受任意文件**（文件管理基本语义，`tree` 条目带 `pkt` 标记供
  前端样式区分），仅 `save` 保留 DSL 提示语义（服务端实际不限扩展名）；
- `read`：二进制/非 UTF-8 文件明确报错（不显示乱码）；
- 解析后 canonicalize + 根内断言（防符号链接把工作区条目指向根外）；
- `save`：新建/覆盖，缺失父目录自动创建（validate_rel 已保证相对路径无点段/反斜杠/
  冒号，create_dir_all 后重走 canonicalize + 根内断言）；4MB 内容上限；同目录隐藏
  临时文件 + rename 原子落盘（无半截文件）；
- `rename`：改名/跨目录移动，目标不存在才执行（覆盖需显式删除），目标父目录须已
  存在；目录同样支持；
- `mkdir`：父目录链自动创建，已存在报错；
- `tree`：目录在前、字典序；隐藏项/符号链接跳过，条目 ≤4096、递归深度 ≤8 截断；
- **开自定义文件夹唯一入口**（📂 按钮 → web 文件夹选择对话框）：`browse` 信封列
  子目录（仅目录、跳隐藏、≤500 条、目录符号链接可跟随——用户逐级驱动无递归风险），
  对话框内点击进出、`..` 上级、路径输入框直达（Enter 跳转），确定走
  `workspace path` 信封校验生效；浏览起点 = 当前工作区根（缺省 examples），initial
  为空时服务端兜底用户主目录（HOME/USERPROFILE，兜底 `/`）。曾实现过的服务端
  原生选择框与浏览器 webkitdirectory 导入已移除：前者与 browse 目标重复（都为设
  工作区根），后者受浏览器安全模型限制拿不到绝对路径（fakepath），语义只能做导入，
  与「打开文件夹」混淆——打开文件夹收敛为 web 对话框一条路。

### 4.9 执行桥（`web/run.rs`）

页面可运行当前工作区的 `.pkt/.pktl`（「Run」页签 / 顶栏 ▶）：`run` 信封 → 服务端
**spawn 自身二进制**（`current_exe()`）跑 `prping packet …` 子命令，stdout/stderr
逐行打包成 `run_out` 信封回推，退出以 `run_exit` 收尾（`code`/`stopped`/`truncated`）。

- **为什么是子进程桥而非进程内调用**（ADR #8）：`send_packets` 等入口直接写进程
  stdout，注入输出捕获需全链路改造；子进程零改动复用 CLI 全部语义（构建发送/配方
  执行/raw/监听、`validate_*` 校验与本地化报错——非法组合的错误文案直接落在执行
  控制台），且天然获得崩溃隔离与 kill 取消；
- **参数映射**：信封字段 → argv（`--lib` 透传生效库目录、`--params k=v` 逐对传递、
  `--count/--wait/--fuzz/--raw/--iface/--out/--json`）；`wait: true` = 裸 `--wait`
  （持续监听）；`json: true` = `--json`（JSONL 结构化输出——前端按行解析渲染包
  ✓/✗、步骤、汇总，非 JSON 行如 raw 升级提示原样回退；与 listen 冲突由前端禁用、
  CLI 校验兜底）。`--lib` 跳过子进程默认发现（exe 目录/`cwd lib/`，canonicalize
  等价）的目录避免重复；相对路径按服务端 cwd 绝对化（子进程 cwd 已换成工作区根）；
- **安全边界**：文件限工作区内 `.pkt/.pktl`（`resolve_in_root(require_pkt)` +
  canonicalize 根内断言）；子进程 `cwd = 工作区根`（`--out` 相对路径落根内，
  值经 `validate_rel` 词法校验防逃逸）；同连接可并行多个子进程（多标签任务管理），
  全服并发 ≤8（`web.run_too_many`）；
- **资源上限**：转发行数（20k）/单行长度（8KB）封顶，超限后继续排水（防子进程管道
  写阻塞）但不再转发，`run_exit.truncated` 标记；全服并发运行上限 8
  （`web.run_too_many`），与每连接单运行槽双重封顶；
- **生命周期**：`run_stop` → kill 活跃子进程（waiter 轮询 `try_wait` 收尸并回报
  `stopped`）；WS 断开 → 读任务与会话收尾双路径显式 `run::stop`（run 的读流任务
  持有回推通道克隆，通道关闭探测不可依赖）——不留孤儿进程。**父进程死亡保险**：
  子进程 stdin 管道化 + 注入 `PRPING_WEB_RUN=1`（CLI 侧 `install_stdin_lifeline`
  监视线程）——服务端被 SIGKILL/崩溃时内核关闭写端 → 子进程读到 EOF 自行退出
  （跨平台、无 unsafe；Linux PDEATHSIG 会因 blocking 池线程退出误杀子进程，不采用）。
  实现注意：move 闭包只捕获 body 引用到的值——生命线写端必须显式移入 waiter 闭包体，
  否则 spawn_waiter 返回即关闭（曾致子进程秒退）。

---

## 5. 前端设计

### 5.1 目录结构

```text
frontend/
├── index.html / vite.config.ts / tsconfig.json / package.json
└── src/
    ├── index.tsx      入口 render
    ├── App.tsx        布局（顶栏——含返回/前进导航钮/左栏文件管理/编辑器/右面板）
    │                 + 数据流编排 + 打开/保存 + 跳转目标映射（URI → 工作区/库文件）
    │                 + 导航历史栈（落点带行、离开回填，§5.4）
    │                 + 执行编排（顶栏 ▶ / Run 页签：run 信封 + run_out/run_exit 流聚合）
    ├── files.tsx      左栏文件管理：工作区树（缩进/悬停改名删除钮）+ eng_lib 只读列表 + 新建/刷新
│                     + 右键菜单（文件：打开/改名/删除；目录：改名/删除（递归）；
│                     空白区：新建文件/新建文件夹/刷新，无工作区 = 打开文件夹/刷新）
│                     + FolderDialog（web 文件夹选择对话框：browse 导航/路径直输/确定取消，
│                     「system dialog…」调服务端原生选择框）
    ├── ws.ts          PrpingClient：信封传输 + request id 关联 + 指数退避重连 + 工作区信封方法
    │                 + run/runStop/run_out/run_exit（执行流式事件回调）
    ├── lsp.ts         LspClient：initialize/didOpen/didChange/补全/悬停/definition + 诊断回调
    ├── cm.ts          CodeMirror 组装：高亮 + lint + 补全 + 悬停 + 深色主题 + 可编辑开关（Compartment）
    │                 + 跳转链接（可跳目标标记/单击·Ctrl 单击检测/linkMode 切换/revealPos）
    ├── markdown.ts    极简 Markdown → HTML（hover / 补全文档渲染；先转义后套标记）
    ├── pktlang.ts     StreamLanguage 分词（# 注释 / #[ 注解 / 关键字 / 0x 十六进制 / |> / 字段名）
    ├── panels.tsx     诊断 / 层栈 / HEX / 大纲 / Run 五面板（Markdown 文档侧栏不渲染——
                       LSP/analyze 管线不适用，改为「内容 + 标题大纲栏」双栏；
                       analyze 应答对 md 一律丢弃，`refreshAnalyze` 对 md 不调度；
                       Run 面板：packet 选项 + 执行控制台，.pkt/.pktl 两种页签组都有）
    ├── sample.ts      空态兜底示例文档（无工作区/无可开文件时出现）
    └── index.css      深色样式（三栏：文件树 220px + 编辑器 + 面板）
```

### 5.2 数据流（编辑 → 反馈）

```text
编辑器变更 ──┬─ 250ms 防抖 → didChange（全文同步，version++）──→ publishDiagnostics
             │                                                    → applyDiagnostics（squiggle + 诊断面板）
             └─ 250ms 防抖 → analyze 信封 ──────────────────────→ 层栈 / HEX 面板刷新
```

- LSP 全文同步（`textDocumentSync: 1`）与 analyze 共用防抖节奏，一次编辑两组请求；
- 重连成功后自动重放 `initialize + didOpen + analyze`（`onStatus("connected")` 钩子）；
- 断线期间挂起的 request 以 `{ok:false, error:"disconnected"}` 快速失败，不悬挂 UI。

文件流（打开 → 编辑 → 保存）：

- 连接后首个 `tree` 自动打开工作区第一个文件（无工作区/空树 → 保持内置示例文档）；
  重连不重复自动打开（重放当前文档）；
- 打开文件 → `read(root)` → `setDoc` + LSP 会话重放（`didOpen`）+ 立即 analyze。
  **工作区文件传真实 `file://` 绝对路径 URI**（`fileUri(root, rel)`，Windows 盘符折叠
  为 `/C:/` 形式）——LSP/analyze 的 import 据此解析到文件所在目录，模块名取文件名；
  库文件沿用 `file:///<name>`；
- 可编辑态经 CodeMirror `Compartment` 切换（`setEditable`）：工作区文件可写，
  eng_lib 文件 `EditorView.editable(false) + readOnly`；
- 保存：`Ctrl+S`（`metaKey` 同）或 Save 按钮（dirty 时出现）→ `save` 信封 → 成功后
  刷新目录树；dirty = 编辑器文本 ≠ 已保存文本（新建文件未落盘恒 dirty）；
- 删除打开中的文件：缓冲保留（保存即重建）；删除目录 = 递归（确认文案说明后果），
  目录内文件的 lastFile 记录一并清除；
- 开自定义目录（📂）：web 文件夹选择对话框（browse 导航 + 路径直输，详见 §4.8），
  确定后刷新目录树；「system dialog…」走服务端原生选择框（不可用时错误就地展示）；
- 执行（Run）：顶栏 ▶ 或 Run 页签 → dirty 先保存（执行所见 = 磁盘内容）→ `run` 信封
  → 启动 ack 后聚合 `run_out` 行（上限 4000 行，超出丢头部）到控制台，`run_exit`
  落终态（exit code / stopped / truncated）；`run_stop` 停止活跃运行；选项快照
  （target/count/wait/listen/fuzz/raw/iface/json）经 IndexedDB 持久化，参数输入与
  Layers 页签共用同一份 `runValues`。**json 默认开**：控制台按 JSONL 解析渲染
  （✓/✗ 包行 + 层栈/字节/目标/错误、步骤行、汇总行，悬停看原始 JSON），非 JSON
  行（stderr 提示）原样回退；listen 勾选时 json 自动失效（CLI 禁 `--json` × 持续监听）。

**前端持久化（IndexedDB，浏览器端数据库）**——项目相关状态跨刷新/重连保留，
生成的产物不落库：

| 键 | 内容 | 恢复时机 |
|---|---|---|
| `workspaceRoot` | 自定义工作区根 | 连接后首个 `tree` 若与服务端默认（examples）不同 → `workspace path` 重开（目录已不存在则清除记录，落回默认） |
| `lastFile` | 上次打开的文件 `{root, path}` | 目录树就绪后重开（服务端报错走兜底：自动打开第一个工作区文件） |
| `draft:<root>:<path>` | 未落盘草稿（编辑器文本 ≠ 磁盘文本时才存在） | 打开该文件时恢复草稿并呈未保存状态（savedText = 磁盘文本）；保存/删除即清除 |
| `panel` | 右侧面板页签选择 | 启动时恢复 |

实现：`src/store.ts` 裸 IndexedDB kv（无依赖，~90 行；隐私模式退化内存 Map）；
草稿写入防抖 1s、卸载前 flush。**不存**：层栈/HEX/诊断等生成物（打开即重算）。

### 5.3 LSP ↔ CodeMirror 映射

| LSP 能力 | CodeMirror 呈现 |
|---|---|
| `publishDiagnostics` | `@codemirror/lint` `setDiagnostics`（severity 1→error，其余→warning；行/列 0 基 → doc offset）。末行「输入已结束」类 parse 错误不展示——span 恒在 EOF，打字中间态必然存在；「字符串未闭合」「非法 token」等精准中间态提示保留。诊断统一归 Diagnostics 页签：LSP 诊断 + analyze 构建错误（运行期参数缺失等，作 `analyze` 来源的诊断行）同列表，页签计数含构建错误；Layers/Hex 空态给「Build failed — see the Diagnostics tab.」指向提示，不再用横幅盖在面板上 |
| `textDocument/completion` | `autocompletion.override` 异步源；服务端按位置上下文（层位/实参名位/值位/语句位/import/export/sniffer/attr/配方/字符串注释）返回该位语法合法且 `sortText` 分级的候选，前端保序渲染（数组序轻衰减 boost）；`name()` 光标落括号内、`params("")` 光标落引号内并顺势弹下一级；kind 映射 function/keyword/property/namespace；documentation（markdown）经 `renderMarkdown` 懒渲染为 info 气泡（选中项才转 HTML） |
| `textDocument/hover` | `hoverTooltip`（hoverTime 400ms），markdown `contents.value` 经 `markdown.ts` 渲染为 HTML（标题/粗体/行内代码/列表/围栏代码块；先整体转义，注入安全）。**查询前同步全文必须去重**（`LspClient.lastSent`）：补全/悬停源内的 `lsp.change` 若在内容未变时仍发 didChange，服务端必回 publishDiagnostics → `applyDiagnostics` 视图更新 → CM hover 的 `update()` 重启 hover（20ms），异步源 pending 被顶掉、应答永远过期——tooltip 永不出现（headless Chrome + CDP 帧捕获定位） |
| `textDocument/documentSymbol` | Outline 页签（.pkt：component def / func / export / 默认导出，点击 `revealLine` 跳行）；Markdown 文档侧栏为标题大纲栏（与渲染器同规则解析 `#`，围栏内不算；渲染模式滚动定位、编辑模式行跳转） |
| `textDocument/definition` | **点击跳转 + 返回/前进**（§5.4）：服务端解析跨文件定义位置（packet-dsl `Module::definition_of` / `import_module_site`），返回目标文件 `file://` URI + 名字 span；前端解码 URI 并映射回可打开目标（工作区相对路径 / 库文件名——前缀匹配 + 路径后缀兜底），`revealPos` 选中定义名并入导航栈 |

补全/悬停均为「编辑器位置 → LSP 0 基行列」的轻适配；超时 3s 兜底返回 null 不卡 UI。

### 5.4 跳转与导航历史（go-to-definition / back-forward）

交互（`cm.ts` 链接标记 + `App.tsx` 导航栈）：

- **跳转候选**标记——**点亮集合 = 确定可跳集合**（字符串/注释行除外）：`.pkt` 里 ①名字在作用域集（本地 defs/funcs/exports，来自 LSP documentSymbol；import 引入名含 as 别名与模块名，从文本解析）；②调用名且**非内置原语**（语义分析保证非内置调用必有定义；内置 concat/global/params… 无定义可跳，`config.json` 的 `builtins` 名单一次性下发）。字段名（`x=`）/参数名/裸关键字不在集里，不亮。`.pktl` 只有步骤文件 token；Markdown 无候选。候选平时无样式，**按住 Ctrl/Cmd 统一点亮**。状态类 `cm-mod-goto` 挂 **body**（CM6 会在焦点变化时整写 `.cm-editor` 的 class，挂编辑器上会被抹掉），由 `modGotoTracking` 插件维护：**窗口级** keydown/keyup 捕获（焦点在任何元素都收得到——只听编辑器会漏「焦点在外按键」）+ 编辑器 mousemove（指针携带按键状态移入）+ 窗口失焦清理；标记随模式/作用域数据/文档/视口变化重建。Playwright 回归覆盖：聚焦按键、焦点在外按键、悬停移入、静止悬停后按键、焦点在外点击跳转、点亮集合精确性（内置/字段/关键字不亮）。
- **跳转触发**：一律 **Ctrl/Cmd+单击**（Alt 让给多光标/块选，见下）；无修饰键单击保持光标定位，绝不跳转（import 模块名/.pktl 文件名一视同仁）。解析不到定义（原语/未知名）提示 `no definition found`。
- **多光标/块选（Alt）**：**Alt+单击**在该处加一个光标、**Alt+拖拽**做矩形（块）选区，按住 Alt 指针变十字作提示——全部为 CodeMirror 原生机制（`clickAddsSelectionRange` 覆盖默认修饰键 + `rectangularSelection` + `crosshairCursor`，需 `allowMultipleSelections`，已开启）。修饰键分区：Alt = 多光标/块选，Ctrl/Cmd = 跳转。
- **定义解析**（服务端 `definition`）：本文件 defs/funcs/protos → 作用域（import 别名/转出口/库 prelude 隐式可见，如 `ipv4()` 直接跳 `eng_lib/headers.pkt`）→ import 行模块名（跳目标文件头/默认导出）→ 库内未导出函数（`lib_module_paths` 按来源模块映射）。跨文件目标返回规范路径的 `file://` URI（路径百分号编码，Windows 反斜杠折算 `/`）。
- **导航历史**：顶栏 ←/→ 按钮（Alt+← / Alt+→，`preventDefault` 拦下浏览器历史导航）。落点 = 文件 + 行；离开条目时回填光标行（跨文件在 `setDoc` 前抓快照），「返回」因此回到离开时的位置；Outline 点击同入栈；重命名/删除同步改写/剔除条目。栈上限 200，同文件同行去重；返回/前进自身的打开以 `navigating` 标志跳过入栈。历史仅在会话内存（IndexedDB 只存工作区根/上次文件/草稿，刷新后从上次文件重新起步）。

---

## 6. 安全模型

| 面 | 措施 |
|---|---|
| 网络暴露 | 默认绑定 `127.0.0.1`（`--addr` 显式才改）；WS 端点仅 `/ws` |
| 浏览器特权 | 零特权：raw socket / 文件访问全在服务端进程 |
| 文件读 | 库浏览只读 + 纯文件名白名单式校验（拒绝分隔符/`..`） |
| 文件写（工作区） | 仅限工作区根内：路径逐段校验（`..`/反斜杠/盘符/隐藏段/Windows 保留名拒绝）+ canonicalize 根内断言（防符号链接逃逸）+ 仅 `.pkt/.pktl` + 4MB 上限；缺失父目录自动创建（仅校验后的相对路径）；工作区根可为任意本地目录（`workspace` 信封 / 对话框选择）——单用户本地工具的信任模型，随 token 鉴权（§10）收紧 |
| 资源服务 | 内嵌：rust-embed 键精确匹配；UI 目录：逐段校验（空段/点段/反斜杠/冒号拒绝）+ 仅普通文件可读 |
| 执行（run） | 仅工作区内 `.pkt/.pktl`（`resolve_in_root` + canonicalize 根内断言）；子进程 `cwd = 工作区根`（`--out` 经 `validate_rel` 防逃逸）；argv 由信封字段构造、不经过 shell；每连接单运行槽；输出行数/行长度封顶；断开/停止即 kill（无孤儿） |
| 协议滥用 | 请求头 ≤64KB、单帧 ≤16MB、畸形帧丢弃；信封 type 白名单 |
| 同源滥用 | 本机其它页面可连 `/ws`（无 token）——MVP 接受；规划：URL 随机 token（§10） |

> 发送/监听能力已接入（§4.9，raw 发包可由页面触发）——URL 随机 token 校验（§10）
> 升级为**必做项**，见路线图「鉴权」行。

---

## 7. 构建与发布

### 7.1 构建链（`crates/prping-core/build.rs`）

```text
cargo build/check/test（默认：无 web-embed）
  └─ prping-core/build.rs：检测 CARGO_FEATURE_WEB_EMBED 缺失 → 整个前端链条跳过
     （默认产物运行期读 UI/ 目录，无需 node 工具链，改前端不触发重编）

cargo build/check/test --features web-embed
  └─ prping-core/build.rs
       ├─ rerun-if-changed: frontend/{src,index.html,package.json,vite.config.ts,tsconfig.json}
       └─ build_frontend(): bun install（node_modules 缺失时）→ bun run build
            ├─ 无 bun → npm 降级；无 node → cargo:warning 跳过（离线/交叉可编译）
            ├─ 有工具链但构建失败 → panic（构建失败，杜绝静默内嵌过期资源）
            └─ 跳过开关：PRPING_SKIP_WEB_BUILD=1
  └─ rust-embed（web/assets.rs）：release 编译期内嵌 dist；debug 运行期直读
```

**为什么放在 prping-core 而不是 prping-cli**：rust-embed 在 **core 编译期**读
`frontend/dist`，core 先于 cli 编译——构建逻辑必须在 core 的 build.rs 才能保证
「先建前端、后读资源」的顺序。

**为何 rerun-if-changed 而非监视 dist 产物**：dist 内容变化经前端源码变化传导；
用户手删 dist 且无源码变更时 cargo 缓存不会重跑——可接受（`just build-web` 兜底）。

### 7.2 justfile

- `just build` / `just build-release`：依赖 **`web-dist`** 保障配方（`frontend/dist`
  缺失或前端源码比产物新时自动执行 `just build-web`，新鲜则零开销跳过；
  `PRPING_SKIP_WEB_BUILD=1` 跳过，与 build.rs 一致；无 node 降级为警告），cargo
  构建后调用 `just dist` 把 **`target/{debug,release}` 同步为完整可运行布局**
  `{prping, UI/, lib/, examples/}`——默认构建的 `prping web` 运行期从**二进制同
  目录**读取（直接 `cargo run` 也命中 exe 目录候选），`--eng` 库搜索命中同目录
  `lib/`；dist 缺失（无 node）时打提示不阻塞；
- `just build-web`：bun/npm 构建 `frontend/dist`（强制刷新 / CI 预热；npm 为
  bun 缺失时的兜底；不落 UI 副本，源码树不留生成物）；
- `just dist DIR`：资源打包——`lib/`（← eng_lib）、`examples/`、`UI/`
  （← frontend/dist）同步到 DIR，发布布局开箱即用；web-embed 构建的二进制不依赖
  UI/；dist 缺失时打警告不阻塞跨平台产物；
- `just check-web-embed`：`cargo check` + clippy `-D warnings`（`--features
  prping/web-embed`；CI ubuntu 执行，与 `check-pcap` 并列）；
- 开发模式：`prping web --port 8788` 起后端，`cd frontend && bun dev` 起 Vite
  热更新（`/ws`、`/config.json` 已配代理指向 8788）。

### 7.3 发布形态

| 形态 | 内容 | 构建 |
|---|---|---|
| 单文件 | `prping` 二进制（前端内嵌，`--open` 即用） | `cargo build --release -p prping --features web-embed` |
| 目录（默认） | `target/release/{prping, UI/, lib/, examples/}`（`just publish`/`just dist`）——运行期读同目录 `UI/` | 默认（构建 UI 副本需 node，无则降级为 503 提示页） |

---

## 8. i18n

服务端横幅/错误走 rust-i18n（core `locales/{en-US,zh-CN}.yml` 的 `web.*` 段：
listening / opening / open_failed / frontend_missing / ui_embedded(_debug) /
ui_dir / ui_dir_missing / ui_missing / read_* / ws_*（工作区：ws_dir / ws_dir_missing /
ws_not_found / ws_bad_path / ws_escape / ws_bad_ext / ws_too_large / ws_read_failed /
ws_save_failed / ws_delete_failed / ws_open_failed））；横幅 `ui:` 行标明资源来源
（内嵌 / UI 目录路径 / 未找到提示），`workspace:` 行标明工作区（路径 / 未找到提示）；
Ctrl+C 提示只在 listening 行尾出现一次，`--open` 的 opening 行不重复 URL
（`open_failed` 例外——手动访问需要完整地址）；
CLI 帮助走 cli locale（`cmd.web` / `usage_web` / `footer_web` / `options.web_*`，
`help.usage_line` 摘要与 `build-web` 输出同步双语）。前端 UI 文案当前为英文
（MVP；面板文案少）。

---

## 9. 测试

### 9.1 单元测试（随代码，`cargo test` 门禁）

| 模块 | 覆盖 |
|---|---|
| `assets.rs` | 键映射（`/`→index.html）、穿越/特殊段拒绝（`..`/点段/反斜杠/冒号/空段）、UI 目录读盘往返（临时根注入） |
| `pipe.rs` | 字节往返 + 跨块 EOF、零长读、对端断开 BrokenPipe |
| `http.rs` | 请求头解析（query 剥离/HTTP/1.0/Connection: close）、WS 升级判定、畸形拒绝、CRLFCRLF 定位 |
| `ws.rs` | FrameDecoder（整帧/单字节碎帧/畸形头不卡死/超限丢弃）、params 形状、`read` 路径穿越拒绝 |
| `run.rs` | argv 构造（缺省/全量/裸 --wait/--lib 去重与子进程默认发现跳过）、行块读取（碎块/超长截断/EOF 残留）、信封校验（工作区内 .pkt 限定/穿越拒绝/count·wait 数值/--out 逃逸/params 含逗号拒绝） |
| `workspace.rs` | 路径校验（穿越/特殊段/Windows 保留名；扩展名开/关两模式）、符号链接逃逸拒绝、save（父目录自动创建/覆盖写/临时文件清理）/read/delete（目录递归删除）/rename（改名+跨目录移动+目标存在拒绝）/mkdir（嵌套+已存在拒绝）往返、二进制文件读拒绝、目录树排序/全部普通文件/隐藏跳过/深度截断、browse（排序/隐藏跳过/父链/缺失路径报错）、open_folder 存在性校验、选择器输出三态解析（unix） |
| `eng/mod.rs` | `analyze_text_json` 与 CLI `--json` 同构（随 engine 既有测试回归） |

### 9.2 端到端验证记录（Node `WebSocket` 客户端，对真实服务端）

1. `initialize` → serverInfo 正常；
2. `didOpen` 合法文档 → `publishDiagnostics`（0 错误）；
3. 补全 → 165 项，含内置原语与 eng_lib 导出（icmp/net4/eth）；
4. 悬停 `ipv4` → `#[proto] func …` markdown 文档；
5. `analyze` 示例文档 → ok，52 字节，hex 头 `ffffffffffff…0800 4500`（eth+ipv4+icmp 帧）；
6. `analyze` 非法文本 → ok:false，错误行号+文案与 CLI 一致；
7. `list` → 21 个库文件；`read net.pkt` → 全文；
8. `read ../../Cargo.toml` → 拒绝。

另验证：`--open` 弹出浏览器；release 二进制删除磁盘 dist 后仍 200（内嵌生效）；
前端未构建时 `/` 返回 503 构建提示；`prping w` 前缀展开正常。

工作区文件管理端到端（Node `WebSocket` 客户端对真实服务端，22/22 通过）：

1. `tree` → root 为二进制同目录 `examples/`，107 条目、目录在前、含 .pkt、无非
   `.pkt(l)` 文件、`writable: true`；
2. `read root:"ws" app_http/http_get.pkt` → ok + `writable: true`；`read net.pkt`
   （库）→ ok + `writable: false`；
3. `save zz_e2e_test.pkt` → 读回一致、目录树出现；`delete` → 再读报错；
4. `save ../evil.pkt` / `x.txt` / `a//b.pkt` / `read C:/win.pkt` → 全部拒绝（i18n 文案）；
5. `workspace path:<自定义目录>` → root 切换、tree 跟随、可保存；`workspace path:""`
   → 重置回 examples；`workspace`（无 path）→ 查询；
6. analyze 以真实 `file://` URI（examples 子目录文件）→ ok，import 解析正常；
7. HTTP：`/` 200 text/html、`/config.json` 200、未知路径 404。

资源分发双模式端到端（curl 对真实服务端）：

1. 默认构建 + 启动目录 `UI/`：`/` 200 text/html、`/assets/*.js` 200、`/config.json` 200、
   `/../Cargo.toml` 与 `/.git/config`（--path-as-is）404、横幅 `ui: <UI 目录路径>`；
2. 默认构建 + 无 UI 目录（/tmp 启动）：`/` 503 + `web.ui_missing` 指引，横幅 `ui: 未找到 UI 目录…`；
3. exe 目录优先：`target/debug/UI` 存在时从任意 cwd 启动均命中 exe 目录（横幅验证）；
4. `--features web-embed` 构建：无任何 UI 目录时 `/` 与 `/assets/*` 仍 200（内嵌生效），
   横幅 `ui: 内嵌（web-embed feature）`。

执行端到端（Node `WebSocket` 客户端对真实服务端，全部通过）：

1. `run` 配方（`transport_udp`，target 127.0.0.1:9、`--wait 1`）→ ack `{run}` →
   `run_out` 逐行（构建层栈/发送/hexdump/无应答提示）→ `run_exit` code 0；
2. 持续监听（`wait: true`，sniffer `.pkt` 高位端口）→ 监听横幅流出；期间再次
   `run` → `ok:false`（`web.run_busy`）；
3. `run_stop` → ack `{stopped:true}` → `run_exit` `{code:null, stopped:true}`；
   槽位释放后再 `run` 正常；
4. `run name:"../etc/passwd"` → 拒绝（`web.ws_bad_path`）；`run name:"a.txt"` →
   拒绝（扩展名）；
5. 断开连接（无 `run_stop` 直接 close）→ 服务端收杀子进程，`ps` 无孤儿。

---

## 10. 已知限制与路线图

| 项 | 现状 | 计划 |
|---|---|---|
| 发送/监听 | 已实现：Run 页签 / 顶栏 ▶ → `run`/`run_stop`/`run_out`/`run_exit` 信封（§4.9 子进程桥：spawn 自身二进制 `packet`，零改动复用 CLI 全语义；工作区限定 + 单运行槽 + 输出封顶 + 断开收杀） | raw 发包权限提示页（无 cap_net_raw 时的引导）；运行历史/重放 |
| 文件保存 | 已实现：左栏文件管理（工作区 = 默认 examples/ 或自定义目录）tree/save/read/delete（目录递归）/rename/mkdir 信封 + 路径逐段校验 + 根内断言 + Ctrl+S 保存/新建/删除/改名/移动 + 目录树折叠（默认全收起，展开集跟踪）+ 右键菜单（打开/改名/删除/新建/刷新） | URL 随机 token 鉴权（与下方「鉴权」行合并推进，发送能力上线时必做） |
| 跳转导航 | 已实现：点击跳转 + 返回/前进（§5.4）——`.pkt` Ctrl/Cmd/Alt+单击标识符、import 模块名与 `.pktl` 步骤文件名单击；定义解析跨文件（import/转出口/库 prelude → 目标 .pkt 源文件，未导出库函数按模块映射）；顶栏 ←/→ + Alt+方向键导航历史（会话内存栈，落点带行、离开回填） | 跳转处悬停 tooltip 显示定义预览（需服务端按位置缓存定义文本）；「查找引用」 |
| 库文件读取 | `read` 信封限**单段文件名**（`read_lib_file` 简单名白名单）——eng_lib 平铺目录下无感；跳转到子目录库文件时前端回退按文件名匹配顶层 | 若引入嵌套库目录：`read` 支持相对子路径（校验随现有键名规则） |
| 鉴权 | 无（仅回环）。**发送能力（§4.9）已上线——本项升级为必做** | URL 随机 token（`prping web` 打印带 token 的 URL），发信封校验 |
| TLS/远程 | 无 | 非目标；远程用 SSH 隧道或反向代理 |
| 手册章节 | 未加入 `document` | `manual-zh/en` 增补 web 章节（双语编号一致性测试约束） |
| check-all | Windows 交叉目标 2 个**预先存在**错误（父提交 69310e25 已有）：`serve/capture.rs` 的 `strip_null` import/定义 cfg 错配、`ping/trace/dns.rs` getnameinfo 参数 |`matches_bare` cfg 缺失（`bare_ip_keep` cfg 对齐其唯一调用方 `pcap_loop`）、linux+pcap 的 `Layer`/`io` cfg 错配（`reply_is_v6`/`open_raw_icmp6` cfg 收紧）、Linux 主机 4 条 engine `raw/listen_raw` 死代码警告及全部 clippy 残留已顺手修复——现为默认/pcap/web-embed 全组合 clippy 零警告；剩余 2 项 Windows 交叉错误独立修复，不阻塞本特性 |

---

## 11. 关键决策记录（ADR 摘要)

1. **手写极简 HTTP 而非 hyper/axum**——静态路由 + 单 WS 端点不足以引入框架与
   tokio；HTTP 子集（GET/HEAD、Content-Length、keep-alive）~200 行且单测覆盖。
2. **WS 握手手工完成**——请求头已由 HTTP 层消费，`from_raw_socket` 跳过
   tungstenite 握手，避免双读；`derive_accept_key`（tungstenite 公开 API）算验收键。
3. **LSP 桥用内存管道而非子进程**——`run_lsp_on` 泛型 IO 是现成缝隙（测试已用
   `Cursor` 验证）；smol::channel 的 `send_blocking`/`recv_blocking` 两侧同源，
   EOF 语义 = 发送端 drop，全链路无 OS 管道、无平台差异。
4. **前端构建挂 core 的 build.rs**——rust-embed 读盘时机在 core 编译期，构建逻辑
   必须先行（详见 §7.1）；bun→npm 降级保证 CI/裸环境可编译。
5. **移除低代码积木视图（原 Blockly 块编辑器，2026-09）**——曾以 `ast`/`schema` 信封 +
   `eng/astdoc.rs`（AST 结构化导出：节点 span + 实参原文切片）+ `frontend/blocks.tsx`
   实现积木编辑/回写（阶段 0+1+2+3），最终整体移除：DSL 语法面极小，拼包的难点在
   协议语义而非语法，积木消除的成本有限；而块视图要求每个 DSL 特性在第二表示里
   再实现一遍（span 回写、过期守卫、语法门控、降级路径），维护税随 DSL 演进永久
   累积。受众上，需要积木的新手往往没有 raw socket 权限，会拼包的用户已有 Scapy/hping。
   移除后文本编辑器 + analyze 层栈/HEX 实时预览是唯一编辑面——求值结果
   （checksum/len/auto）永远由 analyze 呈现，不引入平行存储。
6. **资源默认不内嵌，`UI/` 目录兜底**——内嵌改成可选 `web-embed` feature（默认关）：
   前端产物与 Rust 编译零耦合（改前端不触发重编）、默认构建无需 node 工具链（离线/
   交叉/CI 零负担）、二进制小 ~2MB；分发形态 = 二进制 + `UI/` 目录（`just dist` 自带，
   替换目录即换 UI）。需要单文件分发时 `--features web-embed` 一键内嵌（rust-embed
   debug 仍直读 dist，开发热更新路径不变）。UI 目录查找：二进制所在目录优先（`just
   dist` 布局与 cwd 无关），其次启动目录；每请求即时解析，目录可后补、文件改动即生效。
7. **工作区写边界收在路径层而非鉴权层**——examples 默认工作区沿用 `UI/`/`lib` 的
   就近发现（二进制目录 → 启动目录），写操作全部经同一 `validate_rel + resolve_in_root`
   缝隙（词法逐段校验 + canonicalize 根内断言 + 扩展名白名单 + 4MB 上限；缺失父目录
   自动创建但仅限校验后的相对路径），服务端无「任意路径写」原语；自定义目录打开依赖
   回环单用户的本地信任模型，与 §6 同源滥用条目一致，token 上线后再整体收紧。库文件
   只读由「无写信封」结构保证，不做运行时开关。
8. **执行用子进程桥而非进程内调用（2026-09）**——`run` 信封 spawn 自身二进制跑
   `packet` 子命令：进程内路线（`SendMode/PkgOptions` 直调）需给 `send_packets`/
   `send_recipe` 全链路注入输出 writer、复制 `validate_*` 校验、处理 raw 特权与
   取消；子进程路线零改动复用 CLI 全语义（含本地化报错直接落在控制台），天然获得
   崩溃隔离与 kill 取消。代价是进程/管道开销（发包场景可忽略）。安全边界收在
   spawn 之前：工作区路径解析、`--out` 词法校验、`cwd = 工作区根`、argv 直构造
   不过 shell、单运行槽、断开收杀。**重评触发条件**（任一出现再考虑进程内）：
   ① 高频自动运行（>10 runs/s，spawn 开销显著）；② 需要进程内富类型结果做深度
   交互（per-layer hex 等超出现有 JSONL 字段）；③ 需要进程内流式进度回调且 JSONL
   逐行不再够用。