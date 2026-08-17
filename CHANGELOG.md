# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式。

## [Unreleased]

### 新增

- Windows 7 兼容构建：`x86_64-win7-windows-gnu` 目标 + nightly `build-std`（MSVCRT 链接，见 README）
- `-g`/`--graph`：显式显示时间线图（默认不再自动打印；`-gp` 用 ploot 渲染）
- `-p`/`--pretty` 改用 [ploot](https://github.com/ploot-rs/ploot) 渲染：Unicode 柱状图直方图 + Braille 散点时间线（管道下自动剥离 ANSI）
- `--json` 机器可读统计输出（ping 带 `type` 字段，带宽带 `bytes`/`mbps`）
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
