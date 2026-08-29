# 重构计划：CLI 分派与校验分层（问题修复后的结构性收尾）

> 背景：本轮已修复 21 个具体逻辑问题（见 CHANGELOG）。以下计划针对分析中发现的
> **结构性问题**——它们跨子命令、影响可维护性，需要一次有意的重构而非点状修补。
> 每个条目给出动机、方案、影响面与验收标准。

---

## P1. 模式分派从「配置嗅探」改为「显式模式」——消除 `ping HOST:PORT -l N` 这类陷阱

**现状**（`crates/prping-core/src/lib.rs:246-277`）：`run()` 按配置组合猜模式：

```text
mtu → traceroute → bandwidth → size+port→latency → port→TCP/UDP ping → ICMP
```

`size+port` 命中 latency、`port` 命中 TCP ping——「看起来合法」的参数组合会静默落入
别的协议（本轮已用 CLI 校验堵住 ping 的 `-l`+端口，但库 API 调用方仍会踩中）。

**方案**：给 `PingConfig` 增加显式 `mode` 字段（枚举 `ProbeMode { Auto, Icmp, Tcp,
Udp, Latency, Bandwidth, Mtu, Traceroute }`，默认 `Auto` 保持现有嗅探作兜底）：

- CLI 各子命令在构造 `PingConfig` 时设置对应 `mode`（ping 无端口=ICMP、有端口=TCP/
  UDP、`-m`=Mtu、latency=Latency、bandwidth=Bandwidth、trace=Traceroute）。
- `run()` 优先按 `mode` 分派；`Auto` 才走现有嗅探链（兼容库调用方）。
- `validate_*` 与 lib 不变式合并成一张「模式 × 选项」合法性表。

**验收**：`ping host:port -l N` 从「CLI 报错」升级为「无论谁调用都按 TCP ping 或报错」；
`run()` 无嗅探歧义分支；现有 494 测试全绿。

**影响面**：lib.rs 分派 + cli main.rs 5 个 run_* + config.rs。

---

## P2. count 语义三套合一

**现状**：

| 模式 | count=0 语义 | 位置 |
|------|-------------|------|
| drive 系（icmp/tcp/udp/latency） | 无限 | `util::Run` |
| latency | 0→1 | `lib.rs:250` |
| bandwidth | 立即停止（0 包） | `bandwidth.rs::should_stop` |

本轮已把 bandwidth 缺省改为 1000（对齐 psping `-n` 默认；先前的 100 已修正）并拒绝 `-n 0`，但语义仍分裂。

**方案**：在 `PingConfig` 上定义唯一语义——`count=0` = **无限**（与 psping 的
「-n 缺省无限」一致）：

- `should_stop` 改为 `count != 0 && sent >= count`（与 `Run::done` 对齐）；
- latency 的 `count.max(1)` 移除（`-n 0` 显式 = 无限，与 ping 一致）；
- CLI 不再需要「-n 0 报错」特判（0 有明确含义）。

**验收**：三处 count 判断收敛到一处；`-n 0` 在全部模式 = 无限。

---

## P3. 校验分层统一：一张表取代分散的 validate

**现状**：校验分散在 4 层且不齐：

- bpaf 结构性互斥（选项集）；
- `validate_*`（真校验）：bandwidth 之前是空壳、ping 的 `-m` 冲突在 run_ping 运行时
  才报、`-H` 校验 ping/latency 有而 bandwidth 曾缺失；
- lib `run()` 的 config 级不变式（`-4/-6`、缺端口、警告）；
- 运行时检查（MTU 冲突、`--parallel 0` 等散落各处）。

**方案**：建一张「模式 × 选项合法性」表（数据结构或匹配函数），`validate_*` 与
lib 不变式共用；规则包括：`-l` 仅 ICMP/无端口、`-m` 互斥集、`-r` 仅 latency/
bandwidth、`-H` 全测量模式统一校验、`--parallel` 范围、`-n 0` 语义等。
CLI 只做解析与渲染，合法性判定全部下沉 lib（lib 提供 `validate_config(&PingConfig)`）。

**验收**：任何非法组合在解析期或 run() 入口报错，无「静默忽略」；`validate_*` 只剩
「解析依赖 CLI 上下文」的项。

---

## P4. 后续候选（低优先，记录不承诺）

- **UDP ping 负载大小**：`ping -u HOST:PORT -l N` 目前随 `-l`+端口一并被拒；若要
  恢复 psping 语义，需 P1 之后在显式模式下允许（UDP ping 本就使用 size）。
- **trace 反向 DNS 的进一步并行**：本轮实现「延迟一跳渲染 + 后台查询」；若需即时
  首跳显示，可把渲染与 DNS 解耦为两遍（先 addr+rtt，后补 hostname 列）。
- **带宽 UDP 发送方向**：drain 方案保留「服务端回显需配对」的协议约束；文档建议
  补充「-u 发送方向含服务端回显负载」的说明。
- **`listen_raw.rs` 跨目标警告**：check-all 在部分 Linux 目标上报 `params/globals`
  字段未使用（cfg 差异），可并入 P3 的 cfg 清理。
- **server 报告口径**：聚合 Mbps 按「TCP 连接时长 + UDP 会话时长」累计，语义近似；
  可改为墙钟时间 + 独立字节计数。

---

## 建议执行顺序

1. P2（count 语义）——最小、独立、低风险；
2. P3（校验表）——依赖 P2 的 count 语义；
3. P1（显式 mode）——最大改动，最后做，做完跑 `just check-all` + 全测试。

每次提交保持 `cargo fmt` / `cargo clippy -D warnings` / `cargo test --workspace`
全绿。
