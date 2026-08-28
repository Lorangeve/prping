# 跨平台兼容性与功能统一性分析

> 分析日期：基于当前代码库（`crates/prping-core` / `crates/prping-cli` 全部 97 处 `#[cfg]` 平台分支、
> `justfile` 构建配方、`.github/workflows/ci.yml`、`docs/claude-rules/windows-build.md`）。

## 一、平台矩阵与构建/CI 覆盖

| 目标平台 | 目标（Rust target） | 构建方式 | CI 覆盖 |
|---|---|---|---|
| **Linux x86_64** | `x86_64-unknown-linux-gnu` | 本机 `cargo build` | ✅ 原生测试（ubuntu-latest） |
| **Linux x86 (32-bit)** | `i686-unknown-linux-gnu` | 交叉编译 | ⚠️ 仅本地 `just check-all` 语法检查 |
| **Linux ARM (32-bit)** | `armv7-unknown-linux-gnueabihf` | 交叉编译 | ⚠️ 仅本地 `just check-all` 语法检查 |
| **Linux ARM64** | `aarch64-unknown-linux-gnu` | 交叉编译 | ⚠️ 仅本地 `just check-all` 语法检查 |
| **macOS x86_64 / ARM** | `x86_64-apple-darwin` / `aarch64-apple-darwin` | **仅本机构建**（依赖系统 SDK，无法交叉） | ✅ 原生测试（macos-latest） |
| **Windows 10+ x86_64** | `x86_64-pc-windows-msvc` | `cargo xwin` 交叉 / 本机 | ✅ 原生测试（windows-latest） |
| **Windows 7 x64** | `x86_64-win7-windows-msvc` | nightly + `-Z build-std`（Tier 3 目标） | ⚠️ 仅交叉**构建**（win7-build job），无真机测试 |
| **Windows 7 x86** | `i686-win7-windows-msvc` | nightly + `-Z build-std`（Tier 3 目标） | ⚠️ 仅交叉**构建**（win7-build job），无真机测试 |

要点：

- 质量门禁：CI 三平台原生跑 fmt / clippy（零警告）/ doc / 全部测试（464 tests，`--workspace --all-targets`）；bench 非门禁。
- `just check-all` 覆盖 7 个交叉目标做语法检查；**不含 macOS**（macOS 只能本机编译）。
- 依赖策略：平台相关代码统一用 `windows-sys`（微软官方）/ `libc` / `socket2`；pcap crate 在 Windows/macOS 强制、Linux 可选（`--features pcap`）。
- Win7 为 Tier 3 目标：构建通过 ≠ 运行正确，Win7 特有缺陷（WSAPoll、raw socket）只能靠代码规避，无回归测试。

## 二、功能分层：三类平台形态

### 1. 完全跨平台（零 `#[cfg]`，行为一致）

TCP ping、UDP ping、Latency、Bandwidth、server（TCP/UDP 回显 + 触发协议）、engine 分析 / LSP / pcap 转码解析、统计 / 直方图 / JSON / 退出码、i18n、`-n 10s` 时长模式。

这些功能只走普通 socket / 纯 Rust 解析，三平台代码完全相同，无任何平台分支。

### 2. 统一 API + 平台后端（每平台一套实现，语义对齐）

| 功能 | Linux | Windows | macOS |
|---|---|---|---|
| ICMP ping | raw socket（需 root / cap_net_raw） | **ICMP.DLL**（`IcmpSendEcho2`/`Icmp6SendEcho2`，无需管理员，规避 Win7 RTM raw 缺陷） | raw socket |
| MTU 探测 DF 位 | `IP_MTU_DISCOVER = IP_PMTUDISC_DO` | `IP_DONTFRAGMENT = 21` | `IP_DONTFRAG = 0x18` |
| 服务端全帧抓包（`-v -a`） | AF_PACKET（cap_net_raw；`-a` 混杂还需 CAP_NET_ADMIN）；`--features pcap` 时改走 libpcap 多设备路径（与 macOS 同款，启动行显示接口列表而非「全接口」） | Npcap（通配绑定开全部设备，多网卡不漏抓） | 系统 libpcap / BPF（需 root 或 ChmodBPF） |
| 引擎 `--raw` 发送 | AF_PACKET / IPPROTO_RAW | Npcap（wpcap.dll **延迟加载**，未装只影响该功能） | 系统 libpcap |
| 反向 DNS | libc `getnameinfo` | ws2_32 `getnameinfo` | libc `getnameinfo` |
| Ctrl+C 优雅退出 | `libc::signal`（SIGINT） | `SetConsoleCtrlHandler` | `libc::signal` |
| connect 超时 | `socket2::connect_timeout`（poll） | **自写 `select()` + `SO_ERROR`**（规避 WSAPoll 在 Win7 SP0 的缺陷） | socket2 |
| 终端宽度 / 手册分页 | TIOCGWINSZ / `$PAGER`（默认 less -R） | GetConsoleScreenBufferInfo / 直接输出 | 同 Linux |
| i18n 语言检测 | `$LANG` | `GetUserDefaultUILanguage`（系统 UI 语言） | `$LANG` |
| `-s` 源绑定 | 支持（含 Linux 网卡名 → ioctl `SIOCGIFADDR`） | ICMPv4 **不支持**（见下），其余支持 | 支持（仅 IP） |

### 3. 功能缺口（平台不支持，明确报错或降级）

| 缺口 | 平台 | 现状 |
|---|---|---|
| **`trace HOST:PORT`（TCP SYN 逐跳，带端口自动）** | Windows | ✅ **已补齐（Npcap 路径）**：pcap 注入完整帧（SYN，TTL 递增）+ 抓包收 SYN-ACK/RST 与 ICMP Time Exceeded。需安装 Npcap（未装时 banner 前提示安装）；**仅 IPv4**（IPv6 跨链路需 ND 邻居解析） |
| **ICMP ping `-s` 源绑定（v4）** | Windows | 被静默忽略（`IcmpSendEcho2` 无源地址参数），打印橙色提示后继续；v6 支持（经 `SourceAddress` 传入） |
| **MTU 探测 / ICMP 路由跟踪** | Windows | 需要 raw socket → **管理员权限**；Win7 RTM（SP0）下即使管理员也创建失败（WSAEINVAL 10022），错误文案专门说明。ICMP ping 不受影响（走 ICMP.DLL） |
| **裸 IPv6 发送** | Windows / macOS（pcap 路径） | **仅回环**（`::1`）；跨链路目标报错（Win7 无 `GetIpNetTable2`，v6 邻居表不可枚举）。Linux `IPPROTO_RAW` 全支持 |
| **`-s` 网卡名** | 非 Linux | 仅 Linux 支持网卡名解析；其余平台要求 IP 字面量 |
| **全帧抓包** | 非 Linux/Windows/macOS（如 FreeBSD） | `Unavailable`，回退载荷级 dissect，其余功能照常 |

## 三、统一性设计亮点

1. **收包格式差异透明吸收**：IPv4 raw socket 收包 Linux 恒含 IP 头、Windows 不含（`icmp_offset_v4`/`icmp_offset_v6` 用 version-nibble 框架探测，两种惯例都兼容），上层代码完全不感知平台。
2. **Linux 可选 pcap feature**：`--features pcap` 后 `packet --raw` 走与 Windows/macOS 完全相同的 pcap 链路层注入路径，`server -v` 抓包同样改走 pcap 多设备路径（启动行显示接口列表而非「全接口」），语义对齐、可交叉验证。
3. **错误文案统一分层**：raw socket 失败在 `util::raw_socket_error` 一处按平台给不同文案（root/cap vs 管理员/Win7 缺陷），i18n 双语都有。
4. **探测循环统一**：`Probe` trait + `drive.rs` 骨架让 icmp/tcp/udp/latency 的间隔/预热/统计/JSONL/收尾完全一致，平台差异只藏在 `Probe::probe` 内部。
5. **诊断工具**：`PRPING_TRACE_DUMP=1` 环境变量可 dump 各平台原始收包字节，专门用于排查平台格式差异。
6. **运行时降级而非崩溃**：Npcap 延迟加载 + `ensure_wpcap()` 入口探测；抓包失败回退载荷级 dissect（配置错误如 `--filter` 非法除外）；macOS 抓包失败附 ChmodBPF 提示。

## 四、风险与不对称点

| 问题 | 影响 |
|---|---|
| TCP traceroute 的 Windows 路径依赖 Npcap 且仅 IPv4 | 需安装 Npcap（未装时 banner 前友好报错）；IPv6 目标回退 ICMP trace；Windows 上 IPv6 TCP SYN 探测暂不可用（ND 邻居解析不可枚举） |
| Windows `trace HOST:PORT`（TCP SYN）的 Npcap 路径无 Windows 真机回归 | 三平台 CI 只编译不运行该路径；依赖 Npcap 抓包行为（帧回读、方向过滤），需手工验证 |
| Win7 是 Tier 3 目标，CI 只构建不运行 | 构建通过 ≠ 运行正确；Win7 特有缺陷（WSAPoll、raw socket）只能靠代码规避，无回归测试 |
| `check-all` 不含 macOS 交叉 | macOS 平台分支（BPF 抓包、`IP_DONTFRAG`、libpcap 发送）仅靠 CI 原生 job 覆盖 |
| 权限模型三平台各异 | Linux root/cap、Windows 管理员 + Npcap、macOS root/ChmodBPF——同一命令在不同平台成功率不同 |
| Windows ICMPv4 `-s` 静默忽略 | 语义不一致（其他模式支持），虽有提示但脚本场景易误解 |
| Windows/macOS 裸 IPv6 发送仅回环 | 引擎 raw 功能在非 Linux 平台受限 |

## 五、结论

**兼容性**：9 个发布目标全部可持续构建（CI 三平台原生测试 + Win7 交叉构建），平台分支都有明确文档和错误文案兜底，属于成熟状态。

**功能统一性**：核心测量功能（ping / latency / bandwidth / server / MTU / trace）在三平台**完全统一**（`trace HOST:PORT`（TCP SYN）的 Windows Npcap 路径已补齐），差异集中在「必须碰内核/链路层」的实现后端：ICMP 探测后端、抓包、raw 发送。剩余的语义缺口只有半个——Windows ICMPv4 源绑定被忽略。

**后续收敛方向**（按优先级）：

1. CI 增加 Win7 / Windows Npcap 真机（或虚拟机）冒烟测试，把 Tier 3 目标与 Npcap 路径从"只编译"提升到"可运行验证"；
2. 评估 Windows ICMPv4 `-s` 从"忽略"改为"硬报错"（`validate_*` 层拦截），消除静默语义不一致；
3. Windows `trace HOST:PORT`（TCP SYN）的 IPv6 支持（需 ND 邻居解析，Win10 的 `GetIpNetTable2` 可枚举邻居表，可先支持 Win10+）。
