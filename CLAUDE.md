# prping

跨平台 psping 复刻（Rust）。**同时作为网络协议学习资源**：`eng_lib/` 内含带详细注释的协议头定义库。

## 技术选型

- **异步运行时**: [smol](https://github.com/smol-rs/smol)（**不引入 tokio**）；ICMP 手写 raw socket（socket2）+ smol::Async，无第三方 ICMP 依赖
- **CLI**: [bpaf](https://github.com/pacak/bpaf)（编译快）；**错误**: lib 层 thiserror（`PrpingError`），bin 层 anyhow
- **代码结构**: workspace 双 crate —— `crates/prping-core/`（协议实现 + 引擎 + 工具）+ `crates/prping-cli/`（bpaf 子命令解析 → run()/serve() → 渲染）。lib.rs 公开面最小化：只 re-export `run`/`serve`/`PingConfig`/`Stats`/报告/错误/警告
- **模块地图**（逐文件细节看代码注释与 docs/claude-rules/，此处只列职责）：
  - `lib.rs` — `run()` 模式分派（ICMP/TCP/UDP/latency/bandwidth/MTU/traceroute）+ 核心类型（`OutcomeKind`/`BandwidthReport`/`PrpingWarning`/`PrpingError`）
  - `serve/` — TCP/UDP 回显/触发服务端；`capture.rs` verbose 完整帧抓包（AF_PACKET/Npcap/BPF，`--features pcap` 走 libpcap 多设备路径）+ `-a` 全帧 + `--filter` tcpdump 风格表达式（三平台一致）
  - `ping/` — icmp（导出 `build_v4`/`build_v6`/`icmp_cksum` 供 MTU/trace 复用）/tcp/udp、latency、bandwidth（独立循环+进度条）、mtu（DF+变长二分）、`trace/`（icmp / tcp / udp / tcpwin[Win+Npcap] / dns 反解）
  - `util/` — config、dns、net（`bind_udp` 4MB 缓冲、`connect_timeout` 含 Win7 workaround）、socket（raw 基础设施）、format、interrupt（`Run`：按次数或 `-n 10s` 按时长）
  - `engine/` — 包构造引擎：`eng/`（display/lsp）、`pkg/`（send/recipe/sniffer/raw/listen/listen_raw）、`rawpcap/`（pcap feature 兼容层）
  - `web/` — Web 编辑器服务器（`prping web`，单端口 HTTP+WS，smol）：`http.rs` 极简 GET/HEAD、`ws.rs` 信封协议（lsp 透传/analyze/list/read）+ FrameDecoder 防御、`pipe.rs` 异步↔阻塞桥（零改动复用 `run_lsp_on`）、`assets.rs` 静态资源双模式——**默认运行期读 `UI/` 目录（二进制所在目录优先，其次启动目录）**；`--features web-embed` 时 rust-embed（debug 直读 dist / release 编译期内嵌）；键名逐段校验（空段/点段/反斜杠/冒号拒绝）
  - `stats.rs` 统计/直方图/JSON 输出；`drive.rs` `Probe` trait 统一 ping 循环（间隔/预热/统计/JSONL）；`output.rs` 终端颜色 + 服务端日志 + 缩进工具；`manual.rs` 手册分页
- **直方图**: 默认 ASCII `#`；`-p`/`--pretty` 用 [ploot](https://github.com/ploot-rs/ploot)（非 tty 剥 ANSI）；`-H` 桶数或逗号阈值（ms）
- **i18n**: rust-i18n（`locales/{en-US,zh-CN}.yml`）；`--lang` > `$LANG` > macOS/Windows 系统 UI 语言兜底 > 英文
- **信号**: Ctrl+C 优雅退出（首次停并出统计，再次强杀）；`--json` 下 Unix 隐藏 tty 的 `^C` 回显（退出恢复）
- **JSON/退出码**: `--json` 抑制人读输出；`run()` 返回 `OutcomeKind`，bin 依丢包/`TraceReport::reached` 返回 1
- **其他**: IPv6 全支持；TCP_NODELAY 默认关 Nagle；UDP 触发协议 `[FF FF size(2B) count(4B)]`；带宽并发 `--parallel`（Task 池+全局配额）；`util::configure_executor_threads` 按 CPU 设 `SMOL_THREADS`
- **Windows 7 构建 / Npcap / ICMP.DLL 等平台细节** → `docs/claude-rules/windows-build.md`

## 平台支持

| 平台 | 目标（Rust target） | 产物 | 构建命令 |
|------|-------------------|------|----------|
| **Windows**（Win10+） | `x86_64-pc-windows-msvc` | `prping.exe` | `just build-windows-msvc` |
| **Windows 7 x64** | `x86_64-win7-windows-msvc` | `prping.exe` | `just build-win7` |
| **Windows 7 x86** | `i686-win7-windows-msvc` | `prping.exe` | `just build-win7-32` |
| **macOS x86_64** | `x86_64-apple-darwin` | `prping` | `just build-release`（Intel Mac 本机） |
| **macOS ARM** | `aarch64-apple-darwin` | `prping` | `just build-release`（M 系列本机） |
| **Linux x86_64** | `x86_64-unknown-linux-gnu` | `prping` | `just build-release`（本机） |
| **Linux x86 (32-bit)** | `i686-unknown-linux-gnu` | `prping` | `just build-linux-32` |
| **Linux ARM (32-bit)** | `armv7-unknown-linux-gnueabihf` | `prping` | `just build-linux-arm` |
| **Linux ARM64** | `aarch64-unknown-linux-gnu` | `prping` | `just build-linux-arm64` |

> 全部产物：`just artifacts`；全平台检查：`just check-all`

### 可选 feature

- **`pcap`**（Linux，`--features pcap`，默认关）：默认 raw 后端是原生 socket（AF_PACKET/IPPROTO_RAW/raw ICMP），零额外依赖。开启后**仅两处**改走 libpcap（与 Windows/macOS 同路径语义、可交叉验证）：`packet --raw` 发送（`engine/pkg/raw.rs` 分派：`--iface` 匹配设备名/描述子串、裸 IPv4 自动以太网封装、裸 IPv6 仅回环）与 `server -v` 抓包（`serve/capture.rs`：多设备多线程、恒开混杂）。其余功能不变；pcap **文件读写**（`--pcap/--out/--to-pkt`）与 feature 无关。
- **`web-embed`**（`--features web-embed`，默认关）：rust-embed 编译期内嵌前端进二进制（单文件分发）。默认不内嵌：运行期读二进制同目录 `UI/`。前端构建两条路径：① web-embed 下由 `crates/prping-core/build.rs` 执行（rust-embed 读盘在 core 编译期，构建逻辑必须先行）；② 默认模式下由 justfile 的 `web-dist` 保障配方按需自动构建（dist 缺失或前端源码更新时，`just build`/`just build-release` 的依赖；产物新鲜零开销）。两条路径同为 bun 优先、npm 降级、`PRPING_SKIP_WEB_BUILD=1` 跳过、无 node 仅警告。

## CLI 设计

子命令组织全部功能（bpaf `command()` 平行组合），可用任意**唯一前缀**缩写
（`src/main.rs::expand_subcommand_prefix`；歧义如 `p` → ping/packet 报错列候选）：
```
prping ping HOST[:PORT]     ICMP ping（无端口）/ TCP ping（有端口）/ UDP（-u）/ MTU 探测（-m）
prping latency [OPTIONS] HOST:PORT   Latency test（-l 缺省 64；-u UDP；-r 接收）
prping bandwidth [OPTIONS] HOST:PORT Bandwidth test（-l 缺省 8k；--parallel 并发；-u/-r）
prping server ADDR:PORT     Server（同时服务 latency/bandwidth；-v 抓包 dissect；-a 全帧抓包，需显式 -v；--filter 表达式，需显式 -a）
prping trace [OPTIONS] HOST[:PORT] Traceroute（ICMP 默认；带端口自动 TCP SYN；-u/--udp 经典 UDP 33434 起递增；-m 最大跳数 / -d 免 DNS / --json）
prping engine [OPTIONS] FILE.pkt|.pktl  引擎：分析/LSP/--ls/--hex/--pcap/配方概览（无扩展名自动定位 pktl；--ls 自动分页）
prping packet [OPTIONS] FILE.pkt|.pktl [HOST:PORT]  构建发送/配方执行（--raw/--wait[SECS]/--fuzz/--out；裸 --wait = 持续监听回显，--wait --raw = 链路层监听按应答模板应答）
prping document [SECTION]   使用手册（全文 / 章节跳转）
prping web [--addr ADDR] [--port N] [--open] [--lib PATH]  Web 编辑器（SolidJS SPA + CodeMirror + LSP；默认 127.0.0.1、端口自动分配；--open 打开浏览器；--lib 附加包库目录）
prping -s ADDR|IFACE ...    指定源地址/网卡（测量子命令内）
顶层 --version / --lang（任意位置）由 main() pre-scan 处理，不占子命令位
```
每个子命令的选项集只含该模式生效的选项（结构性互斥）；`validate_*` 只留真校验：
`--json`×`-p/-g/-H`、engine `--json`×`--ls/--hex/--pcap/--lsp`、packet `--json`×裸 `--wait`、`-m`×其他 ping 选项、非法 `-H`/`-n`、server 依赖链（`-a` 需 `-v`、`--filter` 需 `-a`，不隐含开启）。

## 功能完成度

1. **测量** — ICMP/TCP/UDP ping、latency、bandwidth（`--parallel` 并发 + `-b` 实时进度条，仅 tty）、MTU 探测（`-m`，解析 Fragmentation Needed）、traceroute（ICMP 默认/带端口 TCP SYN/`--udp` 经典变体）、jitter（文本 + `--json`）、`-s` 源绑定（Linux 网卡名 → IPv4）、`-R` 反向 DNS、`-n 10s` 时长模式（细节 → `docs/claude-rules/measure.md`）
2. **输出** — 彩色人读 + `--json`/JSONL 机器可读、直方图（`-H` 自定义阈值，psping `-h` 对齐）、服务端聚合统计、退出码反映丢包/未达
3. **引擎** — `engine` 分析/LSP/`--ls`/`--hex`/`--pcap`；`packet` 发送/配方；`.pktl` 配方（global / extract / wait / raw 步骤开关 / on_error）；engine/packet `--json` 结构化输出（细节 → `docs/claude-rules/engine.md`）
4. **Web 编辑器** — SolidJS SPA（CodeMirror 6）+ engine LSP（WS 信封桥接 `run_lsp_on`：诊断/补全/悬停）+ 实时层栈/HEX 预览（`analyze_text_json` 与 CLI `--json` 同构）+ eng_lib 只读浏览；`--open` 开浏览器；前端**默认不内嵌**（运行期读**二进制同目录** `UI/`：`just build`/`just build-release` 经 `web-dist` 按需自动构建前端、经 `just dist` 同步 `target/<profile>/{UI,lib,examples}` 完整可运行布局；源码树不留生成物），`--features web-embed` 才内嵌（单文件分发）
5. `document` 使用手册（双语、章节跳转、$PAGER 分页）

## 协议学习资源（eng_lib/）

- 25+ 协议 `.pkt` 库文件：headers（eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns）、quic、tls、ssh、ftp、smtp、dhcp、ntp、igmp、ospf、bgp、ipsec、wireguard、gre、mqtt、coap、rtp/rtcp、vnc、rdp、smb，及 bytes/net/vint/data 原语库。**完整清单以 `prping engine --ls` 与 `PROTOCOL_SUPPORT.md` 为准**
- **注释规范**：每个 proto 函数包含 ①RFC 标准引用 ②协议概述 ③字段详解（含义/类型/默认值/常见取值）④引擎自动计算字段说明 ⑤字节布局与字段顺序
- 查看：`prping engine --ls/--hex`、`prping document`、`docs/protocol-learning.md`

## 编码约定

- Rust edition 2024；`cargo clippy` 零警告、`cargo fmt` 通过、`cargo test --workspace --all-targets` 全通过
- 用户可见输出英文，注释中文
- 颜色统一 `output.rs`（客户端与服务端一致，连接日志 `output::print_server_log`）；bin 侧错误红/警告橙（lib re-export `output::{stderr, writeln_red, writeln_orange}`）
- 缩进用 `output.rs` 工具（`indent(level)`/`spaces(n)`/`pad_to`），不硬编码空格
- 参数校验分层：子命令选项集结构性互斥 + `validate_*` 只留真校验 + lib `run` 管 config 级不变式
- 共享逻辑收敛一处，不重复实现；不引入不必要的抽象；**JSON-RPC/LSP 管道与 WS 信封为手写实现（serde_json ~50 行），不引入 jsonrpc/lsp-server/jsonrpsee/gRPC 框架**（重评触发条件 → `docs/design-web-editor.md`）
- 构建：build.rs 自动配置 `.cargo/run-with-cap.sh` runner（cap_net_raw，仅 `cargo run`/`test` 生效）；直跑产物用 `just cap`（rebuild 后失效需重跑）；平台配方在 `justfile`
- **原语文档同步门禁**：改动原语须同步 `engine --ls` 展示与 GRAMMAR.md §4.6；`scripts/claude-hooks/primitive-docs-check.sh` 自动校验（`just doc-sync-check`）——原语清单在 `docs/claude-rules/engine.md`
- **门禁**：平台相关改动 → `just check-all`（7 个交叉目标）；pcap 路径 → `just check-pcap`；web 前端/嵌入 → `just check-web-embed`（CI ubuntu 执行）。建议流程：`cargo check` → `just check-all` → `cargo test` → 提交
- **跨平台依赖**：平台 API 统一 `windows-sys`（微软官方）；`t!` 宏导入用 `use rust_i18n::t;`；避免在 `#[cfg(unix)]` 块内定义通用函数。Windows 类型细节 → `docs/claude-rules/windows-build.md`
- CI: `.github/workflows/ci.yml` — fmt/clippy/doc/全部测试 × Linux/macOS/Windows + 非门禁基准 job

## 版本控制

使用 [jujutsu](https://github.com/jj-vcs/jj) (jj) 进行版本控制。

## 详细规则（docs/claude-rules/，按需阅读）

- `docs/claude-rules/engine.md` — 包构造引擎（engine/packet/LSP/pcap/转码/配方）、packet-dsl、hex/raw 字节体系、eng_lib 与库搜索、运行时参数。**改动原语或协议声明、新增协议支持前必读**
- `docs/claude-rules/measure.md` — jitter、源绑定、MTU、路由跟踪各变体、子命令前缀展开
- `docs/claude-rules/windows-build.md` — Win7 基线构建（xwin/XWIN_ARCH/windows.lib）、cap 配方、Npcap 与 wpcap 延迟加载、WSAPoll/ICMP.DLL/raw 收包框架
- `docs/design-web-editor.md` — Web 编辑器设计（架构/信封协议/安全模型/ADR/路线图）

## 使用手册（document 子命令）

- 手册源：`docs/manual-zh.md` / `docs/manual-en.md`（超长双语，`## N. 标题` 编号 + 头部目录），经 `src/manual.rs` include_str! 内嵌，单一来源（不建 mdbook）
- `prping document` 全文（unix tty 经 `$PAGER`，默认 `less -R`）；`prping document 章节` 编号/标题/包含匹配（多命中列候选、无命中列目录）；随 locale 切换，双语章节编号一致性有测试
- 各子命令独立 `--help`（bpaf 生成，`cmd.*` descr + `help.footer_*` 示例）
