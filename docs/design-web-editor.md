# 设计文档：`prping web` Web 编辑器

> 状态：已实现（MVP：骨架 + LSP 桥 + CodeMirror 闭环 + 实时预览 + 库浏览；资源分发改为默认 `UI/` 目录 + 可选 `web-embed` 内嵌）
> 范围：`prping web [--addr ADDR] [--port N] [--open] [--lib PATH]`
> 关联模块：`crates/prping-core/src/web/`、`frontend/`、`crates/prping-core/build.rs`

---

## 1. 背景与目标

为 prping 的包构造引擎（packet DSL：`.pkt` / `.pktl`）提供一个**实时可编辑**的图形界面，
作为 `engine` / `packet` 子命令的可视化补充：

- **文本编辑**：CodeMirror 6 + 引擎现有 LSP（诊断 / 补全 / 悬停 / 文档符号）；
- **低代码编辑**（规划中）：Blockly 积木视图，Scratch 风格（Zelos 渲染器）；
- **实时反馈**：编辑即分析——层栈字段、字节数、hexdump、层序警告实时刷新；
- **协议学习**：eng_lib 协议库（headers.pkt 等 21 个文件）只读浏览；
- **零安装体验**：`prping web --open` 一条命令打开浏览器即用——默认读二进制目录/`启动目录`的 `UI/` 文件夹（`just dist` 产物布局自带）；`--features web-embed` 时前端内嵌二进制（单文件分发）。

### 非目标（本期）

- 不做用户系统 / 远程部署形态（默认仅回环，单用户本地工具）；
- 不做 `.pkt` 文件写入（库浏览只读；编辑器内容仅存于浏览器）；
- 不引入 tokio（与项目 smol 栈保持一致）。

---

## 2. 总体架构

```text
浏览器（SolidJS SPA；默认读 UI/ 目录，--features web-embed 时内嵌二进制）
 ├─ CodeMirror 6 编辑器 ── LSP JSON-RPC（WS 信封透传 → 内存管道 → run_lsp_on）
 ├─ 层栈 / HEX / 诊断面板 ── analyze 信封（内存文本 → engine --json 同构文档）
 └─ eng_lib 库浏览 ── list / read 信封（服务端只读）
           │  HTTP（静态资源 + /config.json）＋ WebSocket（/ws）同端口
 ──────────┴──────────────────────────────────────────────
 prping web（crates/prping-core/src/web/，smol 异步）
 ├─ http.rs   极简 HTTP/1.1 GET/HEAD 响应（Content-Length、keep-alive）
 ├─ ws.rs     WS 会话：信封分派 + Content-Length 分帧解包 + LSP 桥
 ├─ pipe.rs   异步↔阻塞字节桥（smol::channel 实现 io::Read/Write）
 └─ assets.rs 静态资源双模式：默认读 UI/ 目录；web-embed feature 时 rust-embed
                 （debug 直读 dist / release 编译期内嵌）
                     │
        ──── 进程内（无需 IPC）────
        ├─ engine LSP（engine/eng/lsp.rs::run_lsp_on，阻塞线程）
        ├─ analyze_text_json（engine/eng/mod.rs，进程内直接调用）
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
| 低代码 | **规划：Blockly + Zelos 渲染器**（§10） | Zelos 即 Scratch 积木外观；Blockly vanilla JS 可包进 Solid。落选 scratch-blocks（停更）、Rete.js/Drawflow（节点画布适合拓扑图，pkt DSL 是层栈+步骤序列，嵌套块更贴合） |
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
├── mod.rs     serve_web(WebConfig) 入口：bind → 横幅 → --open → accept 循环
│              handle_conn：读请求头 → WS 升级（仅 /ws）或 HTTP 分发（keep-alive 循环）
├── http.rs    请求头解析（CRLFCRLF 截断，MAX_HEAD=64KB）+ 响应 + 路由
├── ws.rs      accept（手工 101）+ session（三分任务）+ 信封分派 + FrameDecoder
├── pipe.rs    ChanReader/ChanWriter（smol::channel ↔ io::Read/Write，EOF=发送端 drop）
└── assets.rs  静态资源双模式：默认 UI/ 目录（二进制目录→启动目录）；
                web-embed 时 rust-embed Assets（folder=../../frontend/dist）
                lookup / index_missing / source_label / missing_hint
```

公开 API（lib.rs）：`serve_web(WebConfig) -> anyhow::Result<()>`（async，CLI 侧
`smol::block_on` 驱动）、`WebConfig { addr, port, libs, open_browser }`、
`analyze_text_json(uri, text, params, libs)`。

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
{ "type": "read", "id": 3, "name": "net.pkt" }    // 读库文件（仅纯文件名）
```

服务端 → 客户端：

```jsonc
{ "type": "lsp", "message": { …publishDiagnostics / 请求应答… } }
{ "type": "result", "id": 1, "ok": true,  "data": … }
{ "type": "result", "id": 1, "ok": false, "error": "…" }
{ "type": "error",  "message": "invalid envelope" }
```

要点：

- **lsp 消息重分帧**：服务端不信任客户端的 Content-Length，取 `message` 重新序列化
  成标准 JSON-RPC 帧（`Content-Length: N\r\n\r\n{body}`）再喂给 LSP；
- **FrameDecoder**（服务端 LSP 输出 → 信封）：增量解析 Content-Length 分帧；无
  Content-Length 的畸形头丢弃已缓冲部分防卡死；单帧上限 16MB（与 LSP 侧
  `MAX_LSP_MSG` 同量级），超限清空缓冲；
- `analyze`/`read` 在 `smol::unblock` 执行（CPU/IO 不阻塞异步循环），结果按请求
  `id` 关联，乱序到达无碍。

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

- `list`：`effective_libs`（烘焙 eng_lib + `--lib` 附加）逐目录扫描 `*.pkt|*.pktl`，
  跨目录按文件名去重（先到先得，与解析器库搜索顺序一致），目录列表一并返回供前端展示；
- `read`：**仅接受纯文件名**（`Path::file_name() == Path` 校验，拒绝分隔符与 `..`），
  按库目录顺序查找读取——服务端无写接口。

---

## 5. 前端设计

### 5.1 目录结构

```text
frontend/
├── index.html / vite.config.ts / tsconfig.json / package.json
└── src/
    ├── index.tsx      入口 render
    ├── App.tsx        布局（顶栏/编辑器/右面板）+ 数据流编排
    ├── ws.ts          PrpingClient：信封传输 + request id 关联 + 指数退避重连
    ├── lsp.ts         LspClient：initialize/didOpen/didChange/补全/悬停 + 诊断回调
    ├── cm.ts          CodeMirror 组装：高亮 + lint + 补全 + 悬停 + 深色主题
    ├── pktlang.ts     StreamLanguage 分词（# 注释 / #[ 注解 / 关键字 / 0x 十六进制 / |> / 字段名）
    ├── panels.tsx     诊断 / 层栈 / HEX 三面板
    ├── sample.ts      首开示例文档（合法 DSL，开箱即有预览）
    └── index.css      深色样式
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

### 5.3 LSP ↔ CodeMirror 映射

| LSP 能力 | CodeMirror 呈现 |
|---|---|
| `publishDiagnostics` | `@codemirror/lint` `setDiagnostics`（severity 1→error，其余→warning；行/列 0 基 → doc offset） |
| `textDocument/completion` | `autocompletion.override` 异步源；`insertText`（如 `tcp()`）原样展开；kind 3→function |
| `textDocument/hover` | `hoverTooltip`，markdown `contents.value` 按纯文本渲染（保留换行） |

补全/悬停均为「编辑器位置 → LSP 0 基行列」的轻适配；超时 3s 兜底返回 null 不卡 UI。

### 5.4 与未来块编辑器的边界

**文本是单一事实源**：块编辑器（规划）将 parse 文本成块、改动后生成文本回写；
解析失败时块视图降级为只读+报错。前端当前所有状态（`lastText` / LSP 会话）都围绕
文本组织，为双向同步预留了同一条数据通道（`analyze` 信封即块视图的 IR 来源）。

---

## 6. 安全模型

| 面 | 措施 |
|---|---|
| 网络暴露 | 默认绑定 `127.0.0.1`（`--addr` 显式才改）；WS 端点仅 `/ws` |
| 浏览器特权 | 零特权：raw socket / 文件访问全在服务端进程 |
| 文件访问 | 库浏览只读 + 纯文件名白名单式校验（拒绝分隔符/`..`） |
| 资源服务 | 内嵌：rust-embed 键精确匹配；UI 目录：逐段校验（空段/点段/反斜杠/冒号拒绝）+ 仅普通文件可读 |
| 协议滥用 | 请求头 ≤64KB、单帧 ≤16MB、畸形帧丢弃；信封 type 白名单 |
| 同源滥用 | 本机其它页面可连 `/ws`（无 token）——MVP 接受；规划：URL 随机 token（§10） |

> 发送/监听能力接入后（§10），raw 发包将可由页面触发，届时 token 校验升级为必做项。

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
ui_dir / ui_dir_missing / ui_missing / read_*）；横幅新增 `ui:` 行标明资源来源
（内嵌 / UI 目录路径 / 未找到提示）；Ctrl+C 提示只在 listening 行尾出现一次，
`--open` 的 opening 行不重复 URL（`open_failed` 例外——手动访问需要完整地址）；
CLI 帮助走 cli locale（`cmd.web` / `usage_web` / `footer_web` / `options.web_*`，
`help.usage_line` 摘要与 `build-web` 输出同步双语）。前端 UI 文案当前为英文
（MVP；面板文案少，随块编辑器一并接前端 i18n）。

---

## 9. 测试

### 9.1 单元测试（随代码，`cargo test` 门禁）

| 模块 | 覆盖 |
|---|---|
| `assets.rs` | 键映射（`/`→index.html）、穿越/特殊段拒绝（`..`/点段/反斜杠/冒号/空段）、UI 目录读盘往返（临时根注入） |
| `pipe.rs` | 字节往返 + 跨块 EOF、零长读、对端断开 BrokenPipe |
| `http.rs` | 请求头解析（query 剥离/HTTP/1.0/Connection: close）、WS 升级判定、畸形拒绝、CRLFCRLF 定位 |
| `ws.rs` | FrameDecoder（整帧/单字节碎帧/畸形头不卡死/超限丢弃）、params 形状、`read` 路径穿越拒绝 |
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

资源分发双模式端到端（curl 对真实服务端）：

1. 默认构建 + 启动目录 `UI/`：`/` 200 text/html、`/assets/*.js` 200、`/config.json` 200、
   `/../Cargo.toml` 与 `/.git/config`（--path-as-is）404、横幅 `ui: <UI 目录路径>`；
2. 默认构建 + 无 UI 目录（/tmp 启动）：`/` 503 + `web.ui_missing` 指引，横幅 `ui: 未找到 UI 目录…`；
3. exe 目录优先：`target/debug/UI` 存在时从任意 cwd 启动均命中 exe 目录（横幅验证）；
4. `--features web-embed` 构建：无任何 UI 目录时 `/` 与 `/assets/*` 仍 200（内嵌生效），
   横幅 `ui: 内嵌（web-embed feature）`。

---

## 10. 已知限制与路线图

| 项 | 现状 | 计划 |
|---|---|---|
| 低代码编辑 | 未实现（仅文本） | Blockly(Zelos) 积木视图：层=块、字段=输入、配方=步骤序列；文本为单一事实源，块↔文本双向（解析失败降级只读） |
| 发送/监听 | 无 | 「Run」按钮 → 服务端复用 `packet` 发送路径（SendMode/PkgOptions 现成），进度/结果走新信封类型回传 |
| 文件保存 | 编辑器内容不落盘 | 工作区文件读写 + 路径校验（需 token 先行） |
| 鉴权 | 无（仅回环） | URL 随机 token（`prping web` 打印带 token 的 URL），发信封校验——发送能力上线时必做 |
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
5. **文本为单一事实源**——块编辑器是视图而非平行存储；`analyze_text_json` 的
   结构化输出即块视图 IR，避免引入第二套模型。
6. **资源默认不内嵌，`UI/` 目录兜底**——内嵌改成可选 `web-embed` feature（默认关）：
   前端产物与 Rust 编译零耦合（改前端不触发重编）、默认构建无需 node 工具链（离线/
   交叉/CI 零负担）、二进制小 ~2MB；分发形态 = 二进制 + `UI/` 目录（`just dist` 自带，
   替换目录即换 UI）。需要单文件分发时 `--features web-embed` 一键内嵌（rust-embed
   debug 仍直读 dist，开发热更新路径不变）。UI 目录查找：二进制所在目录优先（`just
   dist` 布局与 cwd 无关），其次启动目录；每请求即时解析，目录可后补、文件改动即生效。
