# prping webui 冒烟测试（Playwright）

对 `prping web` Web 编辑器（SolidJS SPA + WS 信封 + 执行桥）的端到端冒烟测试。
**被测对象是真实产物**：真实二进制、真实 HTTP/WS 服务端、真实 `packet` 子命令执行桥——
不 mock 前后端任何一层。

## 范围（冒烟 = 快速广覆盖，不做深验收）

| 用例文件 | 覆盖 | 冒烟断言点 |
|---|---|---|
| `tests/load.spec.ts` | 服务与外壳 | `/config.json` 契约（version/wsPath/token/builtins）；页面加载；WS connected；工作区树与 eng_lib 只读树 |
| `tests/editor.spec.ts` | 编辑器核心 | 打开文件 → CodeMirror 渲染；Layers/Hex 实时预览（analyze 通路）；语法错误 → Diagnostics；新建文件 → 输入 → Ctrl+S 持久化（刷新后读回） |
| `tests/files.spec.ts` | 文件管理 | 新建/改名/删除文件（prompt/confirm 对话框）；新建/删除目录；📂 文件夹对话框 browse + 取消不改工作区 |
| `tests/run.spec.ts` | 执行桥 | run 信封 → packet 子命令 → 控制台 JSONL（✓ 包行/推导 target/summary）→ 任务卡 exit 0；listen 持续运行 → ■ Stop → stopped |

有意不覆盖（留给功能测试）：LSP 补全/悬停/跳转细节、.pktl 配方多步编排、多标签脏内容
还原、--fuzz/--raw/iface 选项矩阵、跨连接任务管理器、重连恢复。

## 架构

```
playwright test
  ├─ global-setup.ts
  │    ├─ killStale()           收上一轮残留进程（state.json 记 pid）
  │    └─ buildSandbox()        搭沙箱 + 起两个进程 + 就绪等待
  │         沙箱布局（同 just dist 产物形态，二进制拷贝、UI/lib 为目录符号链接）：
  │           <sandbox>/prping | UI/ → frontend/dist | lib/ → eng_lib | examples/ ← fixtures/workspace | logs/
  │         进程①  prping web  --addr 127.0.0.1 --port <free>   （被测服务端）
  │         进程②  prping server 127.0.0.1:<free>               （UDP echo，run 冒烟回包源）
  │         就绪    轮询 GET /config.json 200；UDP 探针等原样回显
  ├─ tests/*.spec.ts            baseURL = 沙箱 web 端口（PRPING_WEB_URL 注入）
  └─ global-teardown.ts         按进程组收尸（web 派生的 packet 子命令随组回收，无孤儿）
```

设计要点：

- **拷贝二进制而非 symlink**：服务端按 `current_exe` 就近发现 `UI/`/`lib/`/`examples/`，
  符号链接会被解析回 `target/`，沙箱就近查找失效；目录符号链接则不受影响（读盘穿透）。
- **每轮全新沙箱**：工作区随便改不碰仓库 `examples/`；根默认 `e2e/.local/sandbox`
  （gitignored），失败现场保留待查，下一轮 setup 重建。
- **免 root**：冒烟 fixture 全走 UDP 载荷模式（有 TCP/UDP 传输层 → 普通 socket），
  不碰 raw socket/链路层。
- **串行单 worker**：全部用例共享一个服务端沙箱，避免文件操作竞态；冒烟总量小，
  串行足够快（全程约半分钟）。

## 运行

```sh
just test-webui                 # 全套（自动构建前端 dist；二进制缺失时 cargo build）
just test-webui --grep run      # 参数透传给 playwright test
```

手动等价（CI 可参考）：

```sh
just web-dist && cargo build --features prping/web
cd e2e && bun install && bunx playwright install chromium
bunx playwright test
```

## 环境变量

| 变量 | 缺省 | 作用 |
|---|---|---|
| `PRPING_BIN` | `target/debug/prping` | 被测二进制（可指向 `just build-release` 产物做发布冒烟）；setup 会做 **web 子命令能力探测**，无 web feature 的旧产物快速报错而非启动超时 |
| `PRPING_WEBUI_SANDBOX` | `e2e/.local/sandbox` | 沙箱根（本轮现场产物落这里） |
| `PRPING_ECHO_PORT` / `PRPING_LISTEN_PORT` | 自动分配 | 用例注入 fixture 参数用（setup 生成，用例经 `process.env` 读取） |

## 选择器契约与维护

前端未埋 `data-testid`，用例依赖现有稳定 class/aria（`.topbar .brand`、
`.tree-file .tree-name`、`.doc-tab.active`、`.run-line-ok`、`.param-item`、
`button[title="new file"]` 等），集中在 `helpers/ui.ts` + 各用例文件头部。前端改版
时：先改 `helpers/ui.ts`（公共操作），再按用例文件头部注释定位受影响断言。

已知前端契约假设（若变更需同步用例）：

- `window.prompt/confirm` 承载新建/改名/删除交互（Playwright 需预挂 dialog 监听）；
- CodeMirror 开启 closeBrackets——键盘输入避开括号/引号配对字符；
- 文件打开即激活文档页签，右侧面板页签文案为 Diagnostics/Layers/Hex/Outline/Run；
- 参数框（`.params-box`）只在 **Layers 页签**渲染（Run 面板另有一份共用 runValues 的
  `.run-params`）；运行入口是 **Run 页签内的 ▶ Run**（顶栏 ▶ Run/■ Stop 仅在脏缓冲时出现）；
- 任务行（`.run-task-row`）在**顶栏任务管理器弹层**（`.taskmgr-btn` → `.taskmgr-pop`），
  Run 面板本身用状态行 `.run-status`（`#1 exit 0` / `running…` / `stopped`）呈现当前任务终态。

已知测试发现（修复记录）：

- **Layers 字段表坍缩**（本套件首轮发现并修复）：引擎 analyze 的层 fields 为空格分隔的
  `k=v` 串，前端 `fieldsRows` 曾按 `", "` 切分——整层字段坍缩成一行（键=首键、值=剩余
  全文）。修复：在「下一个 `k=` token 前的空白」处切分，值内空格（如 http start_line）保留。

## fixture 说明（fixtures/workspace/）

| 文件 | 用途 |
|---|---|
| `udp_echo_smoke.pkt` | UDP 载荷发包 → echo 往返；`port`/`ip` 经 `params()` 注入（顺带冒烟参数输入行） |
| `udp_listen_smoke.pkt` | 裸 `--wait` 持续监听（sniffer 永不命中）→ 进程常驻，供 ■ Stop 冒烟 |
| `syntax_error.pkt` | 括号未闭合 → Diagnostics 冒烟 |
