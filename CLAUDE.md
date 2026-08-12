# prping

跨平台 psping 复刻，使用 Rust 实现。

## 技术选型

- **异步运行时**: [smol](https://github.com/smol-rs/smol) — 轻量级，组件化
- **ICMP**: 手写 raw socket (socket2) + smol::Async，无第三方 ICMP 依赖
- **CLI**: [bpaf](https://github.com/pacak/bpaf) — 轻量级，编译快
- **错误处理**: lib 层用 thiserror，bin 层用 anyhow 做胶水
- **代码结构**: 单 crate — `main.rs`, `icmp.rs`, `tcp.rs`, `udp.rs`, `latency.rs`, `bandwidth.rs`, `stats.rs`, `output.rs`
- **终端颜色**: ANSI 转义码 (`println!` 内联)，颜色函数统一在 `output.rs`
- **直方图**: 默认 ASCII `#`，`-p`/`--pretty` 用 Unicode `█`，可选 [ploot](https://github.com/ploot-rs/ploot) (feature flag)
- **i18n**: [rust-i18n](https://github.com/longfangsong/rust-i18n) — `locales/en.yml` + `locales/zh-CN.yml`，自动检测 `$LANG` 或 `--lang`
- **信号处理**: Ctrl+C 待实现
- **DNS 解析**: `smol::unblock` + `std::net::ToSocketAddrs`
- **带宽测试并发**: 多连接 `-P`，smol::Task 池
- **UDP**: `-u` 参数支持
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

1. ICMP Ping — IPv4/IPv6, raw socket, 直方图, 时间线, 统计
2. TCP Ping — connect 延迟, 彩色输出, 统计
3. UDP Ping — 可达性, 延迟, 统计
4. Latency Test — TCP/UDP client/server, echo 协议
5. Bandwidth Test — TCP/UDP client/server, 多连接并发

## 编码约定

- Rust edition 2024
- `cargo clippy` 零警告，`cargo test` 全通过（24 tests）
- 用户可见输出英文，注释中文
- 颜色由 `output.rs` 统一管理，服务端用 ANSI 转义码内联 `println!`
- 不引入不必要的抽象
- 构建: `build.rs` 自动配置 `.cargo/run-with-cap.sh` runner 设置 cap_net_raw

## 版本控制

使用 [jujutsu](https://github.com/jj-vcs/jj) (jj) 进行版本控制。
