# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式。

## [Unreleased]

### 新增

- 非带宽模式使用 `-P` 现在输出橙色警告（此前静默忽略；UDP 带宽的 `-P` 警告沿用）
- 非法 `-H` 参数（如 `-H abc`）现在红色报错并退出码 1（此前静默忽略，与 `-n abc` 一致）
- 带宽测试实时进度条（`-b`）：`\r` 同行动态刷新，时长模式按时间、次数模式按包推进（每 5% 里程碑 + 100ms 限频）；仅 stdout 为 tty 时显示，管道/文件/`--json`/`-q` 静默
- `--json` 模式运行期间隐藏终端回显的 `^C`（Unix 且 stdin 为 tty 时；`^C` 为终端行规程回显、本就不进入 stdout 管道，退出时恢复终端设置）
- 互斥参数校验：冲突组合输出红色错误并退出码 1（`-4`/`-6`、`-s` 与目标或客户端参数、`--json` 与 `-p`/`-g`/`-H`、无 `-b`/`-l` 时使用 `-r`）；clamp/忽略类提示改为橙色输出
- Windows 7 兼容构建：`x86_64-win7-windows-gnu` 目标 + nightly `build-std`（MSVCRT 链接，见 README）
- `-g`/`--graph`：显式显示时间线图（默认不再自动打印；`-gp` 用 ploot 渲染）
- `-p`/`--pretty` 改用 [ploot](https://github.com/ploot-rs/ploot) 渲染：Unicode 柱状图直方图 + Braille 散点时间线（管道下自动剥离 ANSI）
- `--json` 改为 JSONL：每次测量一行（含 seq/rtt_ms 或 error），末尾汇总行带 `summary:true`；带宽带 `direction` 字段
- `--version` / `-V`
- `-H` 自定义阈值直方图（逗号分隔毫秒阈值，如 `-H "1,5,10,50"`）
- 服务端聚合统计（Ctrl+C 退出时打印连接数/字节/平均吞吐）
- 服务端并发连接上限（1024），超限直接拒绝
- `-n 10s` 时长模式全模式支持
- UDP 接收模式（`-r`）触发协议 `[0xFF, 0xFF, size, count]`
- ICMP 不可达/TTL 超时错误区分显示
- 丢包时退出码 1（脚本友好）
- Windows Ctrl+C 优雅退出（`SetConsoleCtrlHandler`）
- 架构重构：拆分为 lib（协议/统一入口）+ bin（CLI），进程内协议测试
- 性能基准脚本 `scripts/bench.sh`（CI 非门禁 job）
- CI：fmt/clippy/测试/doc × Linux/macOS/Windows

### 修复

- 带宽测试并行模式（`-b -P N -H`）直方图此前为空（只统计串行耗时）→ 各连接分别收集每包写入耗时并汇总
- 延迟测试（`-l`）此前固定 1 秒间隔、忽略 `-i` → 与其他模式一致遵循 `-i`
- 带宽测试接收模式（`-b -r`）`-H` 直方图此前无数据（只统计发送耗时）→ 接收方向也记录每块读取耗时
- ICMP 模式 `--json` 缺少逐行输出（只有末尾 summary）→ 补上 `json_sample`，与 tcp/udp/latency 一致（修复 `prping HOST --json -i 0.3` 终端无输出、看似卡死）
- `-n 10s` 此前静默失效（TCP/UDP/ICMP 会变无限 ping）
- UDP `-r` 接收模式此前为空壳（静默回退为发送）
- ICMP `-l` 尺寸参数此前被忽略
- TCP ping 无 connect 超时（黑洞地址挂死 OS 超时）→ 统一 5s 超时
- `-i 0` 无限快速模式无速率保护 → clamp 到 1ms
- `-b -n 4 -P 8`（count < parallel）此前发送 0 字节
- UDP `-l 64k+` 负载超限静默失败 → 截断到 65507 并提示
- UDP ping 回包不校验（杂包污染统计）→ 负载内嵌 seq 校验
- 服务端 1ms echo 超时导致跨网络延迟测试失真 → 100ms + 排空模式
- 静默忽略的参数（`-r` 普通 ping、`-b -u -P`）现在明确提示
- 本地快测时服务端聚合吞吐显示 0.00 → 微秒精度

### 重构

- 统一 ping 循环驱动器（`drive.rs`）：icmp/tcp/udp/latency 的间隔/预热/统计/JSONL/收尾收敛为一处，各模式只实现「一次探测」（`Probe` trait）
- 直方图数据与渲染解耦（`Histogram::from_times`）：ASCII 与 ploot 共用桶计算，带宽报告不再临时构造 `Stats`
- DNS 解析收敛：`resolve`/`resolve_all` 合并进 `resolve_vec`，5 处重复的 resolving 横幅并入 `util::print_resolving`
- 带宽报告 `report()` 8 个位置参数改为 `ReportArgs` 结构（消除同类型参数传错风险）
- 模式合法性单一事实来源：`-4`/`-6` 冲突、UDP/带宽缺端口、`-P` 非带宽警告等 config 级不变式收敛到 lib `run`；bin `validate` 只管 CLI 级冲突（`-s`/`--json`/`-r`）
- 服务端连接日志渲染收敛到 `output::print_server_log`（着色统一，协议代码不再内联渲染）
