# prping

跨平台 psping 复刻，使用 Rust 实现。

## 技术选型

- **异步运行时**: [smol](https://github.com/smol-rs/smol) — 轻量级，组件化
- **ICMP**: 手写 raw socket (socket2) + smol::Async，无第三方 ICMP 依赖
- **CLI**: [bpaf](https://github.com/pacak/bpaf) — 轻量级，编译快
- **错误处理**: lib 层 thiserror（`PrpingError` 分派层枚举 + IO/anyhow 透传），bin 层 anyhow 做胶水
- **代码结构**: 单 crate 双 target — `src/lib.rs`（协议/统一入口 `run`/`serve`，公开面最小化）+ `src/main.rs`（CLI 解析/渲染/退出码/信号安装）+ `src/{util,drive,stats,output,icmp,tcp,udp,latency,bandwidth,trace}.rs`（lib 内部）。超大模块按 rust mod 目录化拆分（`a.rs` → `a/` 目录 + `a/mod.rs` 入口，忠实搬移原实现，行为不变）：
  - `engine/pkg/`（原 `pkg.rs` 3119 行）— `send.rs`（`--pkt` 发送/渲染循环 + 目标推导 + 源地址填充）、`recipe.rs`（`.pktl` 配方执行 + extract）、`sniffer.rs`（回包匹配器 + 字段提取 + 字节级 Expr 比较）、`raw.rs`（AF_PACKET / IPPROTO_RAW / raw ICMP 收包）
  - `engine/eng/`（原 `eng.rs` 1672 行）— `display.rs`（层字段展示/hexdump/反解渲染/模块概览头 + 终端宽度/折行）、`lsp.rs`（LSP 语言服务器，原 `engine/lsp.rs` 移入）
  - `ping/trace/`（原 `trace.rs` 2072 行）— `icmp.rs`（echo 逐跳）、`tcp.rs`（SYN 逐跳）、`udp.rs`（经典 UDP 逐跳）；共享常量/类型/工具在 `mod.rs`
- **终端颜色**: [termcolor](https://github.com/BurntSushi/termcolor)，颜色函数统一在 `output.rs`（客户端与服务端一致）
- **直方图**: 默认 ASCII `#`（内置）；`-p`/`--pretty` 用 [ploot](https://github.com/ploot-rs/ploot) 渲染 Unicode 柱状图与 Braille 散点时间线（非 tty 自动剥离 ANSI）；`-H` 支持桶数或逗号分隔阈值（ms）
- **i18n**: [rust-i18n](https://github.com/longfangsong/rust-i18n) — `locales/en-US.yml` + `locales/zh-CN.yml`，自动检测 `$LANG` 或 `--lang`
- **信号处理**: Ctrl+C 优雅退出 — Unix `libc::signal` / Windows `kernel32::SetConsoleCtrlHandler`（首次停止输出统计、再次强制退出）；`--json` 模式在 Unix 运行期关 stdin tty 的 `ECHOCTL` 隐藏终端回显的 `^C`（退出时恢复）
- **DNS 解析**: `smol::unblock` + `std::net::ToSocketAddrs`，统一在 `util.rs`（`resolve_vec` 返回全部、`resolve` 取首个；解析横幅 `util::print_resolving`）
- **ping 循环驱动器**: icmp/tcp/udp/latency 共用 `drive.rs::drive`（间隔/预热/统计/JSONL/收尾），各模式实现 `Probe` trait 只做「一次探测」与人读行
- **次数/时长**: `-n 10` 固定次数，`-n 10s` 按秒运行（`util::Run` 统一控制循环）
- **带宽测试并发**: 多连接 `--parallel`，smol::Task 池 + 全局配额（总量精确等于 count）
- **多线程**: `util::configure_executor_threads` 按 CPU 核数设置 `SMOL_THREADS`（smol 全局 executor 默认单线程）
- **UDP**: socket2 大收发缓冲（4MB）+ smol::Async（`util::bind_udp`），避免突发丢包；客户端打印头部提示（目标/负载/迭代数）与回显要求说明（目标需 `prping server` 回显才回包）
- **UDP 接收模式**: 触发包协议 `[0xFF, 0xFF, size(2B), count(4B)]`，服务端回送 count 个 size 字节数据报；回显计入聚合统计、触发包打印即时接收日志（不逐包打印）
- **JSON/退出码**: `--json` 机器可读统计（`stats::set_json`）抑制人读输出；`run()` 返回 `OutcomeKind`（Ping(Stats)/Bandwidth(report)/Mtu(report)/Traceroute(report)），bin 依 `Stats::has_loss()` 或 `TraceReport::reached` 返回 1
- **IPv6**: `-4`/`-6` 全支持；**TCP_NODELAY**: 默认关闭 Nagle
- **Windows 7 构建 / Npcap / ICMP.DLL 等平台细节** → `docs/claude-rules/windows-build.md`

## CLI 设计

子命令组织全部功能（bpaf `command()` 平行组合），子命令可用任意**唯一前缀**缩写
（`src/main.rs::expand_subcommand_prefix` 在解析前展开；歧义如 `p` → ping/packet 报错列候选）：
```
prping ping HOST[:PORT]     ICMP ping（无端口）/ TCP ping（有端口）/ UDP（-u）/ MTU 探测（-m）
prping latency [OPTIONS] HOST:PORT   Latency test（-l 缺省 64；-u UDP；-r 接收）
prping bandwidth [OPTIONS] HOST:PORT Bandwidth test（-l 缺省 8k；--parallel 并发；-u/-r）
prping server ADDR:PORT     Server（同时服务 latency/bandwidth）
prping trace [OPTIONS] HOST[:PORT] Traceroute（ICMP echo 默认；-t/--tcp 用 TCP SYN 需端口；-u/--udp 经典 UDP 33434 起递增；-m 最大跳数 / -d 免 DNS / --json）
prping engine [OPTIONS] FILE.pkt|.pktl  引擎：分析/LSP/--ls/--hex/--pcap/配方概览（无扩展名参数自动定位 pktl：先 `<arg>.pktl`，再同名文件夹 `<arg>/<arg>.pktl`）
prping packet [OPTIONS] FILE.pkt|.pktl [HOST:PORT]  构建发送/配方执行（--raw/--wait/--fuzz/--out）
prping -s ADDR|IFACE ...    指定源地址/网卡（测量子命令内）
顶层 --version / --help-pkg [SECTION] / --lang（任意位置）由 main() pre-scan 处理，不占子命令位
```
每个子命令的选项集只含该模式生效的选项（结构性互斥）：ping 含 `-u/-l/-g/-p/-m`，
latency 含 `-u/-l/-r/-g/-p`，bandwidth 含 `-u/-l/-r/--parallel`，trace 含 `-m/-d`，
engine/packet 含引擎选项（`--lsp/--ls/--hex/--pcap` 互斥且不带文件；`--to-pkt/--structured/--skip/--limit` 需 `--pcap`；`--iface` 需 `--raw`）。
`validate_*` 只留真校验：`--json`×`-p/-g/-H`、`-m`×其他 ping 选项、非法 `-H`/`-n`。

## 功能完成度

1. ICMP Ping — IPv4/IPv6, raw socket, 直方图, 时间线, 统计（`-l` 控制负载大小；区分不可达/TTL 超时）
2. TCP Ping — connect 延迟, 彩色输出, 统计
3. UDP Ping — 可达性, 延迟, 统计（回包 seq 校验过滤杂包）
4. Latency Test — TCP/UDP client/server, echo 协议, `-r` 接收模式
5. Bandwidth Test — TCP/UDP client/server, 多连接并发, `-r` 接收模式
6. 时长模式 — `-n 10s` 按秒运行（ICMP/TCP/UDP/latency/bandwidth 全支持）
7. Ctrl+C 优雅退出 — 首次停止并输出统计，再次强制退出（Unix libc::signal / Windows SetConsoleCtrlHandler）
8. `--json` 机器可读输出、`--version`、退出码反映丢包
9. `-H` 自定义阈值直方图（psping `-h` 对齐）
10. 服务端聚合统计（Ctrl+C 退出时打印）
11. 带宽测试实时进度条（`-b`）——`\r` 同行动态刷新；时长模式按时间、次数模式按包（每 5% 里程碑 + 100ms 限频）；仅 tty 显示，管道/`--json`/`-q` 静默（`bandwidth.rs::Progress`）
12. 抖动 jitter — 相邻 RTT 差均值/最大（文本 + `--json` 的 `jitter_ms`/`jitter_max_ms`）
13. 路径 MTU 探测 — `-m`/`--mtu`（ICMP DF + 变长载荷二分，解析 Fragmentation Needed）
14. 源绑定 — `-s ADDR|IFACE`（全模式；Linux 网卡名 → IPv4）
15. 路由跟踪 — `-t`/`--traceroute`（ICMP echo + 递增 TTL 逐跳）及 `--tcp` SYN / `--udp` 经典变体（细节 → `docs/claude-rules/measure.md`）
16. 配方 `.pktl` — 多个 `.pkt` 按顺序发出，global 跨步骤存储 / extract / wait / raw 步骤开关 / on_error（细节 → `docs/claude-rules/engine.md`）

## 编码约定

- Rust edition 2024
- `cargo clippy` 零警告，`cargo fmt` 通过，`cargo test --workspace --all-targets` 全通过（464 tests）
- 用户可见输出英文，注释中文
- 颜色由 `output.rs` 统一管理（客户端与服务端一致，服务端连接日志用 `output::print_server_log`）；bin 侧错误用红色、警告用橙色（lib re-export `output::{stderr, writeln_red, writeln_orange}` 给 bin 用）
- 参数校验分层：子命令选项集结构性互斥（server/trace/mtu/模式互斥、`-r` 依赖等已消除）+ `validate_ping`/`validate_latency`/`validate_engine`/`validate_packet` 只留真校验 + lib `run` 管 config 级不变式（`-4`/`-6` 冲突、UDP/带宽缺端口、`-i` clamp、`-m`/trace 不接受端口）；非法 `-H`（如 `-H abc`）与非法 `-n` 在 bin 红色报错退出码 1
- 共享逻辑（DNS 解析、运行循环、直方图桶计算、UDP socket、测试参数 `PingConfig`）收敛一处，不重复实现：直方图数据与渲染解耦（`stats::Histogram::from_times`），带宽报告用 `ReportArgs` 结构传参
- lib 公开面最小化：只 re-export `run`/`serve`/`PingConfig`/`Stats`/报告/错误/警告/`output::{stderr, writeln_red, writeln_orange}`，其余 `pub(crate)`
- 不引入不必要的抽象
- 构建: `build.rs` 自动配置 `.cargo/run-with-cap.sh` runner（cap_net_raw，仅 `cargo run`/`cargo test` 生效）；直接跑产物用 `just cap`（rebuild 后失效需重跑）；各平台配方在 `justfile`——细节 → `docs/claude-rules/windows-build.md`
- CI: `.github/workflows/ci.yml` — fmt/clippy/doc/全部测试 × Linux/macOS/Windows + 非门禁基准 job
- **原语文档同步门禁**：改动原语（registry.rs builtin_docs / eval.rs 分派 / tpl 等）须同步 `engine --ls` 展示与 GRAMMAR.md §4.6；`scripts/claude-hooks/primitive-docs-check.sh` 自动校验分派 ⊆ builtin_docs ⊆ GRAMMAR.md §4.6（`.claude/settings.json` PostToolUse hook 提醒 + `just doc-sync-check`，违规退出码 1）——原语清单在 `docs/claude-rules/engine.md`

## 版本控制

使用 [jujutsu](https://github.com/jj-vcs/jj) (jj) 进行版本控制。

## 详细规则（docs/claude-rules/，按需阅读）

- `docs/claude-rules/engine.md` — 包构造引擎（engine/packet/LSP/pcap/转码/配方）、packet-dsl 子 crate、hex/raw 字节体系、自表示协议 proto、值函数/字节原语、eng_lib 标准库与库搜索、运行时参数。**改动原语或协议声明、新增协议支持前必读**。
- `docs/claude-rules/measure.md` — 测量功能细节：jitter、源绑定、MTU 探测、路由跟踪（ICMP / TCP SYN / UDP 变体）、子命令前缀展开。
- `docs/claude-rules/windows-build.md` — Win7 基线构建（xwin / XWIN_ARCH / windows.lib）、cap 与平台配方、Npcap 绑定与 wpcap 延迟加载、WSAPoll / ICMP.DLL / raw 收包框架等 Windows 细节。

## 使用手册（--help-pkg）

- 手册源：`docs/manual-zh.md` / `docs/manual-en.md`（超长双语，`## N. 标题` 编号章节 + 头部目录），经 `src/manual.rs` include_str! 内嵌，单一来源（不建 mdbook 站点）。
- `--help-pkg`（无参数）→ 全文，unix tty 经 `$PAGER`（默认 `less -R`）自动分页，非 tty / Windows 直接输出（`src/manual.rs::print_paged`）。
- `--help-pkg 章节` → `find_sections` 编号 / 标题前缀 / 包含匹配（忽略大小写），单命中打印该章节、多命中列候选、无命中列目录；裸 `--help-pkg` 由 `normalize_help_pkg_args` 预处理。
- 手册随 locale 切换（`manual_for`，`rust_i18n::locale()`）；双语章节编号一致性有测试。
- 各子命令独立 `--help`（bpaf 生成，`cmd.*` descr + `help.footer_*` 示例）；`--help-*` 旧 flag 已移除，详细内容见 `--help-pkg` 手册。
