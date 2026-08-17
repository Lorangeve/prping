# prping

跨平台 psping 复刻，使用 Rust 实现。

## 技术选型

- **异步运行时**: [smol](https://github.com/smol-rs/smol) — 轻量级，组件化
- **ICMP**: 手写 raw socket (socket2) + smol::Async，无第三方 ICMP 依赖
- **CLI**: [bpaf](https://github.com/pacak/bpaf) — 轻量级，编译快
- **错误处理**: lib 层用 thiserror（`PrpingError` 分派层枚举 + IO/anyhow 透传），bin 层用 anyhow 做胶水
- **代码结构**: 单 crate 双 target — `src/lib.rs`（协议/统一入口 `run`/`serve`，公开面最小化）+ `src/main.rs`（CLI 解析/渲染/退出码/信号安装）+ `src/{util,stats,output,icmp,tcp,udp,latency,bandwidth}.rs`（lib 内部）
- **终端颜色**: [termcolor](https://github.com/BurntSushi/termcolor)，颜色函数统一在 `output.rs`（客户端与服务端一致）
- **直方图**: 默认 ASCII `#`，`-p`/`--pretty` 用 Unicode `█`（内置实现，无外部依赖）；`-H` 支持桶数或逗号分隔阈值（ms）
- **i18n**: [rust-i18n](https://github.com/longfangsong/rust-i18n) — `locales/en.yml` + `locales/zh-CN.yml`，自动检测 `$LANG` 或 `--lang`
- **信号处理**: Ctrl+C 优雅退出 — Unix 用 `libc::signal`，Windows 用 `kernel32::SetConsoleCtrlHandler`（首次停止并输出统计，再次强制退出）
- **DNS 解析**: `smol::unblock` + `std::net::ToSocketAddrs`，统一在 `util.rs`
- **次数/时长**: `-n 10` 固定次数，`-n 10s` 按秒运行（`util::Run` 统一控制循环）
- **带宽测试并发**: 多连接 `-P`，smol::Task 池 + 全局配额（总量精确等于 count）
- **多线程**: `util::configure_executor_threads` 按 CPU 核数设置 `SMOL_THREADS`（smol 全局 executor 默认单线程）
- **UDP**: socket2 大收发缓冲（4MB）+ smol::Async 包装（`util::bind_udp`），避免突发丢包
- **UDP 接收模式**: 触发包协议 `[0xFF, 0xFF, size(2B), count(4B)]`，服务端回送 count 个 size 字节数据报
- **JSON 输出**: `--json` 输出机器可读统计（`stats::set_json`），抑制人读输出
- **退出码**: `run()` 返回 `OutcomeKind`（Ping(Stats)/Bandwidth(report)），bin 依据 `Stats::has_loss()` 返回 1
- **IPv6**: `-4`/`-6` 全支持
- **TCP_NODELAY**: 默认关闭 Nagle

## CLI 设计

```
prping HOST                 ICMP ping（无限，Ctrl+C 停止）
prping HOST:PORT            TCP ping
prping -u HOST:PORT         UDP ping
prping -l SIZE HOST:PORT    Latency test
prping -b -l SIZE HOST:PORT Bandwidth test
prping -s ADDR:PORT         Server（同时服务 latency/bandwidth）
```

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

## 编码约定

- Rust edition 2024
- `cargo clippy` 零警告，`cargo fmt` 通过，`cargo test --all-targets` 全通过（单元 34 + 协议 9 + CLI 5 + doc = 49 tests）
- 用户可见输出英文，注释中文
- 颜色由 `output.rs` 统一管理（客户端与服务端一致，服务端不使用内联 ANSI）
- 共享逻辑（DNS 解析、运行循环、UDP socket、测试参数 `PingConfig`）收敛在 `util.rs`，不重复实现
- lib 公开面最小化：只 re-export `run`/`serve`/`PingConfig`/`Stats`/报告/错误/警告，其余 `pub(crate)`
- 不引入不必要的抽象
- 构建: `build.rs` 自动配置 `.cargo/run-with-cap.sh` runner 设置 cap_net_raw
- CI: `.github/workflows/ci.yml` — fmt/clippy/doc/全部测试 × Linux/macOS/Windows + 非门禁基准 job
- 跨平台编译检查: `cargo check --target x86_64-pc-windows-msvc`（Windows 路径需本机验证时用临时 CARGO_HOME）

## 版本控制

使用 [jujutsu](https://github.com/jj-vcs/jj) (jj) 进行版本控制。
