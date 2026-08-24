# prping 使用手册

> 跨平台网络「万用表」——psping 复刻，用 Rust 实现。
> 测量：ICMP / TCP / UDP ping、延迟测试、带宽测试、路径 MTU 探测、路由跟踪、抖动统计。
> 包构造引擎集成在同一 binary（`engine`/`packet` 子命令，见第 26 章）。

## 目录

1. [简介与特性](#1-简介与特性)
2. [安装](#2-安装)
3. [快速开始](#3-快速开始)
4. [模式总览（自动识别）](#4-模式总览自动识别)
5. [ICMP Ping](#5-icmp-ping)
6. [TCP Ping](#6-tcp-ping)
7. [UDP Ping](#7-udp-ping)
8. [延迟测试（Latency Test）](#8-延迟测试latency-test)
9. [带宽测试（Bandwidth Test）](#9-带宽测试bandwidth-test)
10. [服务端模式（Server Mode）](#10-服务端模式server-mode)
11. [接收模式（Receive Mode）](#11-接收模式receive-mode)
12. [测试控制选项（次数/间隔/预热/静默/并发）](#12-测试控制选项次数间隔预热静默并发)
13. [直方图与时间线（-H / -g / -p）](#13-直方图与时间线-h--g--p)
14. [统计指标（含抖动 jitter）](#14-统计指标含抖动-jitter)
15. [JSON 输出](#15-json-输出)
16. [MTU 探测（-m / --mtu）](#16-mtu-探测-m---mtu)
17. [路由跟踪（-t / --traceroute）](#17-路由跟踪--t--traceroute)
18. [源地址绑定（-s）](#18-源地址绑定-s)
19. [IPv4 / IPv6 双栈](#19-ipv4-ipv6-双栈)
20. [退出码与脚本化](#20-退出码与脚本化)
21. [信号与中断（Ctrl+C）](#21-信号与中断ctrlc)
22. [语言与国际化](#22-语言与国际化)
23. [完整示例合集](#23-完整示例合集)
24. [常见问题（FAQ）](#24-常见问题faq)
25. [与 psping 的对比](#25-与-psping-的对比)
26. [包构造引擎（engine / packet / packet-dsl）](#26-包构造引擎engine--packet--packet-dsl)

> 提示：`prping --help-pkg 章节标题` 可直接跳转到对应章节学习；
> `prping --help-pkg 1`（编号）、`prping --help-pkg 安装`（标题前缀）均可。

---

## 1. 简介与特性

prping 是一个跨平台（Linux / macOS / Windows）的命令行网络测量工具，对标微软
[psping](https://learn.microsoft.com/en-us/sysinternals/downloads/psping)，
定位是网络工程师的「万用表」：快速回答「能不能通、延迟多少、丢不丢包、抖不抖、
带宽多大、MTU 多少」。

### 特性一览

- **四种 ping**：ICMP（IPv4/IPv6）、TCP、UDP，端口自动识别
- **延迟测试**：client/server 架构，TCP/UDP 双模式，可测反向（接收模式）
- **带宽测试**：多连接并发（`--parallel`），实时进度条
- **路径 MTU 探测**（`-m`）：ICMP DF + 变长载荷二分，自动解析
- **路由跟踪**（`-t`）：ICMP echo + 递增 TTL，逐跳路径 + 反向 DNS
- **抖动 jitter**：相邻 RTT 差的均值/最大，实时流排障指标
- **统计**：min/max/avg/stddev + P50/P95/P99 + 丢包率 + 直方图 + 时间线
- **JSON 输出**：逐次采样 + 汇总，机器可读，适合脚本/监控
- **源地址绑定**（`-s`）：多网卡 / 策略路由场景
- **次数或时长**：`-n 10` 固定次数，`-n 10s` 按秒运行
- **IPv4/IPv6 双栈**、Ctrl+C 优雅退出、中英双语、退出码反映丢包

### 命令行总览

```
prping ping [选项] <HOST[:PORT]>
```

功能按子命令组织（见 3.1/4 章），模式由「子命令 + 目标形式」决定：

| 子命令 + 目标形式 | 模式 |
|---|---|
| `ping HOST`（无端口） | ICMP ping |
| `ping HOST:PORT` | TCP ping |
| `ping -u HOST:PORT` | UDP ping |
| `latency -l SIZE HOST:PORT` | 延迟测试 |
| `bandwidth -l SIZE HOST:PORT` | 带宽测试 |
| `ping -m HOST` | MTU 探测 |
| `trace HOST` | 路由跟踪 |
| `server ADDR:PORT` | 服务端 |

---

## 2. 安装

### 源码编译

```bash
git clone <仓库地址> && cd prping
cargo build --release
```

Linux 上 ICMP ping / MTU 探测 / 原始套接字需要 root 或 `cap_net_raw`：

```bash
sudo setcap cap_net_raw+ep target/release/prping
```

### 一键配方（justfile）

```bash
just build-release        # release 构建
just build-windows        # 全部 Windows 产物（含 Win7 兼容版）
just test                 # 全部测试
just lint                 # clippy 零警告
```

### 依赖

- Rust 2024 edition（stable 即可）
- 无运行时依赖；Windows 7 兼容版需 nightly + xwin 工具链（见项目 README）

---

## 3. 快速开始

```bash
# 通不通
prping ping 8.8.8.8                    # ICMP，无限测，Ctrl+C 停
prping ping example.com                # 域名自动解析

# 端口通不通 / 建连延迟
prping ping 192.168.1.1:80
prping ping 8.8.8.8:53 -n 10           # 固定 10 次

# 延迟测试（需要服务端，见第 10 章）
prping latency -l 64 -n 100 server:8080

# 带宽测试
prping bandwidth -l 8k -n 10000 --parallel 4 server:8080

# 快速看一轮统计（含抖动）
prping ping -n 20 -w 0 -H 10 192.168.1.1

# 路径 MTU
prping ping -m 8.8.8.8

# 路由跟踪
prping trace 8.8.8.8

# 指定源地址
prping ping -s 192.168.1.10 8.8.8.8

# 包引擎 / 发包（第 26 章）
prping engine file.pkt
prping packet file.pkt 192.168.1.1:9000
```

---

## 3.1 子命令与迁移指南

prping 使用**子命令**组织全部功能，子命令可用任意**唯一前缀**缩写（如 `prping e file.pkt`
等价 `prping engine file.pkt`；`p` 有歧义会报错）：

| 子命令 | 功能 | 旧写法（已移除） |
|---|---|---|
| `ping` | ICMP / TCP / UDP / MTU 探测 | `prping HOST`、`prping -u`、`prping -m` |
| `latency` | 延迟测试（TCP/UDP，`-r` 接收模式） | `prping -l SIZE HOST:PORT` |
| `bandwidth` | 带宽测试（`--parallel` 并发） | `prping -b -l SIZE HOST:PORT` |
| `server` | 服务端（latency/bandwidth 共用） | `prping -s ADDR:PORT` |
| `trace` | 路由跟踪（`-m` 跳数 / `-d` 免 DNS） | `prping -t HOST` |
| `engine` | 包引擎：分析 .pkt/.pktl、LSP、`--ls/--hex/--pcap`、pcap→.pkt/.pktl 转码（`--to-pkt`） | `prping --eng ...` |
| `packet` | 构建 .pkt/.pktl 并发送（`--raw/--wait/--fuzz/--out`） | `prping --pkt ...` |

顶层 `--version`、`--help-pkg [章节]`、`--lang` 不占子命令位置，可出现在任意位置
（如 `prping --lang zh-CN ping 8.8.8.8`）。

---

## 4. 子命令总览

功能按子命令组织；每个子命令的选项集只包含该模式生效的选项（结构性互斥，
不再需要参数冲突校验）：

| 子命令 | 目标 | 主要选项 | 说明 |
|---|---|---|---|
| `ping` | `HOST`（ICMP）/ `HOST:PORT`（TCP）/ `-u HOST:PORT`（UDP） | `-n/-i/-w/-q/-H/-g/-p/-s/-4/-6/--json`；`-m` MTU 探测 | `-m` 无端口、仅 IPv4，与 `-u/-l/-g/-p/-H/-n/-i/-w/-q` 互斥 |
| `latency` | `HOST:PORT`（必填） | `-l SIZE`（缺省 64）、`-u/-r/-g/-p/-H` + 测试/网络选项 | 需对端 `prping server` |
| `bandwidth` | `HOST:PORT`（必填） | `-l SIZE`（缺省 8k）、`-u/-r/--parallel N` + 测试/网络选项 | 需对端 `prping server` |
| `server` | `ADDR:PORT`（必填） | 无客户端选项 | 同时服务延迟/带宽/接收模式 |
| `trace` | `HOST`（无端口） | `-m N/-d/-s/-4/-6/--json` | ICMP echo + 递增 TTL |
| `engine` | `FILE.pkt/.pktl`（可选） | `--lsp/--ls/--hex/--pcap`（互斥、不带文件）、`--to-pkt DIR/--structured/--skip/--limit`（配合 `--pcap`）、`--lib/-p/-g` | 分析/LSP/概览/转码 |
| `packet` | `FILE.pkt/.pktl`（必填）+ `[HOST:PORT]`（可选） | `--raw/--iface/--wait/--fuzz/--out/--lib/-p/-g` | 构建发送/配方执行 |

测量子命令共用「测试控制」「输出」「网络」选项组（第 12/13/15/19 章）。

---

## 5. ICMP Ping

**用途**：最基础的连通性 + 延迟测量；区分网络故障（不可达/TTL 超时）。

```bash
prping ping 8.8.8.8                  # 无限（Ctrl+C 停）
prping ping -n 10 -i 0.2 8.8.8.8     # 10 次，200ms 间隔
prping ping -l 1400 8.8.8.8          # 大载荷（探测链路限制）
prping ping -m 8.8.8.8               # 见第 16 章：自动 MTU
prping trace 8.8.8.8               # 见第 17 章：路由跟踪
```

### 输出示例

```
正在 Ping 8.8.8.8，数据大小 32 字节:
10 次迭代 (预热 0) ping 测试:
来自 8.8.8.8: 字节=32 时间=1.23ms TTL=57
...
  发送 = 10，接收 = 10，丢失 = 0 (0% 丢失),
  最小 = 1.11ms，最大 = 1.87ms，平均 = 1.34ms，标准差 = 0.21ms
  P50 = 1.32ms, P95 = 1.87ms, P99 = 1.87ms
  抖动 = 0.18ms（最大 0.44ms）
```

### 说明

- 原始 ICMP socket：Linux/macOS 需 root 或 `cap_net_raw`；**Windows 上 ICMP ping 走 ICMP.DLL（`IcmpSendEcho2`，同系统 ping.exe）**——不需要管理员权限，且不受 Win7 RTM（SP0）的 raw socket 缺陷影响（该版本 `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` 管理员下也返回 WSAEINVAL 10022，SP1 修复）；Win7 SP0 上 v4 的 `-s` 源绑定不支持（ICMP.DLL 无源参数，提示后忽略，v6 支持）
- `-l` 控制 ICMP 载荷字节数（不含 ICMP/IP 头）
- 区分三类回复：echo reply（正常）、不可达（type 3）、TTL 超时（type 11）

---

## 6. TCP Ping

**用途**：端口连通性 + 建连（connect）延迟；等价于「telnet 端口 + 计时」。

```bash
prping ping 192.168.1.1:22           # SSH 端口
prping ping -n 30 -i 0.1 -H 10 server:443
prping ping -s 10.0.0.2 server:443   # 指定源地址（第 18 章）
```

### 输出示例

```
TCP 连接到 192.168.1.1:22:
30 次迭代 (预热 0) ping 测试:
连接到 192.168.1.1:22: 从 192.168.1.100:54321: 0.32ms
...
  发送 = 30，接收 = 30，丢失 = 0 (0% 丢失),
  最小 = 0.25ms，最大 = 0.60ms，平均 = 0.33ms，标准差 = 0.08ms
```

### 说明

- 每次探测新建 TCP 连接并立即关闭（不发送应用数据）
- 连接超时 5 秒；多地址（域名多 IP）自动逐个回退
- 丢包 = 连接失败次数；防火墙 drop 会表现为超时丢包
- `--parallel` 并发在此模式无意义（每次只连一次）

---

## 7. UDP Ping

**用途**：UDP 可达性测试（如 DNS 53 端口、游戏服务器），psping 之外 prping 独有。

```bash
prping ping -u 8.8.8.8:53
prping ping -u -n 10 192.168.1.1:5000
```

### 说明

- 发送带序号标记的 UDP 数据报；回包校验 seq，过滤杂包
- **目标需有 UDP 回显服务**（如 `prping server` 服务端、DNS 应答）才会回包，
  无回显时全部超时——这是 UDP ping 的固有特性
- UDP 通常会被防火墙静默丢弃，丢包率 = 100% 不代表主机不可达，
  请用 ICMP/TCP 交叉验证

---

## 8. 延迟测试（Latency Test）

**用途**：端到端应用延迟（TCP 建连 + 数据往返），比 ping 更接近真实用户体验。
需要两端都装 prping：客户端 `-l` 触发，服务端 `-s`。

```bash
# 服务端（先起）
prping server 0.0.0.0:8080

# 客户端
prping latency -l 64 -n 100 server:8080          # TCP 延迟测试（默认）
prping latency -l 64 -n 100 -u server:8080       # UDP 延迟测试
prping latency -l 64 -n 100 -r server:8080       # 反向：测下载方向（第 11 章）
```

### 工作原理

1. 客户端连接服务端（TCP 或 UDP）
2. 发送 `size` 字节请求，服务端原样回显
3. 客户端测量往返时间（RTT）
4. 服务端 Ctrl+C 退出时打印聚合统计

### 说明

- `-l` 是触发延迟测试的必要条件（有端口时）
- 服务端并发上限 1024 连接
- UDP 延迟测试回显字节计入服务端聚合统计

---

## 9. 带宽测试（Bandwidth Test）

**用途**：吞吐量测量（Mbps），`--parallel` 多连接并发压测。

```bash
# 服务端
prping server 0.0.0.0:8080

# 客户端：8KB 包，1 万次，4 并发
prping bandwidth -l 8k -n 10000 --parallel 4 server:8080

# 时长模式
prping bandwidth -l 1m -n 10s --parallel 8 server:8080
```

### 输出示例

```
TCP Bandwidth test:
  Sent = 81920000 bytes in 0.42s
  Bandwidth = 1566.49 Mbps
```

### 说明

- 真实吞吐测量建议用 iperf3；prping 的带宽模式偏「够用」的便捷压测
- `--parallel` 并发数：多连接并行，总量精确等于 `count`
- `-r` 测下载方向（接收模式，见第 11 章）
- 进度条仅 tty 显示；管道/`--json`/`-q` 静默
- UDP 带宽模式内核缓冲自动放大到 4MB，避免突发丢包

---

## 10. 服务端模式（Server Mode）

**用途**：延迟/带宽测试的服务端；同时服务 TCP/UDP、延迟/带宽/接收模式。

```bash
prping server 0.0.0.0:8080
prping server [::]:8080             # IPv6
```

### 说明

- 一个服务端同时支持所有客户端模式（TCP/UDP × 延迟/带宽 × 收发方向）
- Ctrl+C 退出时打印聚合统计（连接数、收发字节等）
- 不能与任何客户端参数（`-n/-i/-l/-b/-u/--parallel/-s/-m` 等）混用
- Windows 上为 Win7 兼容保留

---

## 11. 接收模式（Receive Mode）

**用途**：测「下载方向」——客户端只收、服务端只发。

```bash
# 服务端
prping server 0.0.0.0:8080

# 客户端：反向延迟测试
prping latency -l 64 -n 100 -r server:8080

# 客户端：反向带宽测试
prping bandwidth -l 8k -n 10000 --parallel 4 -r server:8080
```

### 说明

- `-r` 合法条件：`-b`（带宽），或 `-l` + 端口（延迟）
- UDP 接收模式触发协议：客户端发 `[0xFF, 0xFF, size(2B), count(4B)]` 触发包，
  服务端回送 count 个 size 字节数据报
- 服务端 UDP 回显字节计入聚合统计

---

## 12. 测试控制选项（次数/间隔/预热/静默/并发）

所有 ping/延迟/带宽模式通用。

| 选项 | 说明 |
|---|---|
| `-n N` | 固定次数（默认无限） |
| `-n 10s` | 按秒运行（10 秒） |
| `-i S` | 间隔秒数（0 = 快速，下限 1ms） |
| `-w N` | 预热次数（默认 4，不计入统计） |
| `-q` | 静默：不输出每次结果，只出汇总 |
| `--parallel N` | 并发连接数（仅带宽测试有效；其他模式忽略并警告） |
| `-l SIZE` | 载荷大小，支持 `64` / `8k` / `1m` 后缀 |

### 示例

```bash
prping ping -n 1000 -i 0.01 8.8.8.8      # 1000 次快速 ping（10ms 间隔）
prping ping -n 30s -w 5 server:8080      # 测 30 秒，5 次预热
prping ping -q -n 100 192.168.1.1        # 只输出汇总
prping ping -n 1000000 -i 0 -q 8.8.8.8   # 100 万次快速 ping（0 间隔 = 最快）
```

> 注意：`-n` 只支持 `s` 后缀（秒，如 `-n 10s`）；`-n 1m` 会报错，
> 固定次数写纯数字。`-l` 的 `m` 后缀才是兆字节（`-l 1m` = 1MB 载荷）。

---

## 13. 直方图与时间线（-H / -g / -p）

### 直方图 `-H`

两种形式：

```bash
prping ping -n 100 -H 10 8.8.8.8          # 10 个桶
prping ping -n 100 -H "1,5,10,50" 8.8.8.8 # 自定义毫秒阈值：1/5/10/50ms 分档
```

默认 ASCII `#` 渲染；`-p`（pretty）用
[ploot](https://github.com/ploot-rs/ploot) 渲染 Unicode 柱状图
（非 tty 自动剥离 ANSI 颜色）。

### 时间线 `-g`

```bash
prping ping -n 20 -i 0.1 -gp 127.0.0.1:22  # 时间线图（-p 用 ploot Braille 散点）
```

`-g` 显示每轮延迟的时间线，适合观察抖动趋势。

### 说明

- `-H` 非法值（如 `-H abc`）红色报错退出码 1
- `--json` 与 `-p/-g/-H` 互斥（JSON 是机器格式，不需要图表）

---

## 14. 统计指标（含抖动 jitter）

每次测试结束输出汇总统计：

| 指标 | 含义 |
|---|---|
| 发送 / 接收 / 丢失 | 包计数与丢包率 |
| 最小 / 最大 / 平均 | min / max / avg（ms） |
| 标准差 stddev | 延迟离散程度 |
| **抖动 jitter** | **相邻两次 RTT 差的平均绝对值**（丢包打断链） |
| 抖动最大 | 相邻 RTT 差的最大值 |
| P50 / P95 / P99 | 百分位延迟（样本 ≥ 2 时输出） |

### 输出示例

```
  发送 = 8，接收 = 8，丢失 = 0 (0% 丢失),
  最小 = 0.24ms，最大 = 2.18ms，平均 = 0.66ms，标准差 = 0.60ms
  P50 = 0.48ms, P95 = 2.18ms, P99 = 2.18ms
  抖动 = 0.40ms（最大 1.52ms）
```

### 抖动说明

- 抖动 = 连续两次成功 RTT 之差的平均值（`|RTT[i] - RTT[i-1]|` 的均值）
- 丢包会打断「连续」链：丢包后的第一个样本不与丢包前的样本比较
- 高抖动 = 网络不稳定（实时音视频/游戏掉帧的常见根因）；
  低延迟 + 高抖动比高延迟更影响实时体验

---

## 15. JSON 输出

`--json` 输出 JSONL（每行一条记录，实时可 `tail -f`；最后一行是汇总）。

### 逐次采样行

```json
{"type":"tcp","target":"127.0.0.1:22","ts":1787031710,"seq":0,"ok":true,"rtt_ms":0.26}
{"type":"tcp","target":"127.0.0.1:22","ts":1787031711,"seq":1,"ok":true,"rtt_ms":0.31}
{"type":"tcp","target":"127.0.0.1:22","ts":1787031712,"seq":2,"ok":false,"error":"timeout"}
```

### 汇总行（summary:true）

```json
{"type":"tcp","target":"127.0.0.1:22","ts":1787031713,"summary":true,"sent":3,"received":2,
 "lost":1,"loss_pct":33.3,"min_ms":0.26,"max_ms":0.31,"avg_ms":0.28,"stddev_ms":0.02,
 "jitter_ms":0.05,"jitter_max_ms":0.05,"p50_ms":0.26,"p95_ms":0.31,"p99_ms":0.31}
```

- `type`：`icmp` / `tcp` / `udp` / `latency` / `mtu`
- 汇总行字段：`sent/received/lost/loss_pct`、`min_ms/max_ms/avg_ms/stddev_ms`、
  `jitter_ms/jitter_max_ms`（样本 ≥ 2 时）、`p50_ms/p95_ms/p99_ms`（样本 ≥ 2 时）
- MTU 模式汇总：`payload_max`、`mtu`、`frag_needed_mtu`（若有）

### 脚本示例

```bash
prping ping -n 10 --json 8.8.8.8 | tail -1 | jq .jitter_ms
prping ping -n 30s --json server:8080 | jq -r 'select(.ok) | .rtt_ms' | awk '{s+=$1} END {print s/NR}'
```

> `--json` 在 Unix 上运行期间关闭终端回显的 `^C`（退出时恢复）。

---

## 16. MTU 探测（-m / --mtu）

**用途**：找出路径最大可传输单元（path MTU）——两端之间不产生分片的最大包尺寸。
链路 MTU 不匹配是「小包通、大包不通」的经典根因。

```bash
prping ping -m 8.8.8.8
prping ping -m 192.168.1.1 -s eth0     # 指定源
prping ping -m --json 8.8.8.8          # 机器可读
```

### 输出示例

```
  payload=32769 → ok（可过）
  payload=49153 → ok（可过）
  payload=57345 → 分片需要
  payload=53249 → 分片需要
  payload=51199 → ok（可过）
  ...

路径 MTU = 1500 字节（最大不分片载荷 1472 字节，目标 8.8.8.8）
  途中 Fragmentation Needed 报回 MTU = 1500
```

### 工作原理

1. 发送带 DF（不分片）位的 ICMP echo，载荷大小二分试探 `[0, 65507]`
2. 收到 echo 回复 → 该尺寸可过；收到 Fragmentation Needed（type 3 code 4）
   → 过大，且报文中携带下一跳 MTU
3. 收敛后：**路径 MTU = 最大可过载荷 + 28**（IPv4：20 字节 IP 头 + 8 字节 ICMP 头）
4. 途中路由器报回的 MTU 一并展示（取最小值）

### 限制

- **仅 IPv4**（IPv6 路径 MTU 需要 ICMPv6 Packet Too Big，暂未支持）
- 需要 raw socket（root / `cap_net_raw`）
- 防火墙丢弃 ICMP 时报「无回显」错误——此时无法探测
- 探测超时按「超限」处理并备注（最多 2 次重试/尺寸）

---

## 17. 路由跟踪（trace / -t / --traceroute）

**用途**：逐跳查看数据包到目标的转发路径——定位丢包/高延迟发生在哪一跳、
发现不对称路由、验证多线出口。默认对标 Windows `tracert`（ICMP echo）；
`--tcp` 用 TCP SYN 变体（对标 `tcptraceroute`/`tracetcp`）、`--udp` 用经典
UDP 变体（对标 Unix `traceroute`）——ICMP 被防火墙过滤时依然可用。

```bash
prping trace www.baidu.com          # ICMP echo，默认最多 30 跳
prping trace -m 20 8.8.8.8          # 最多 20 跳
prping trace -d 8.8.8.8             # 不解析主机名（只显示 IP）
prping trace --json 8.8.8.8         # 机器可读（每跳一行 + 汇总行）
prping trace -6 ::1                 # IPv6（Hop Limit 递增）
prping trace --tcp 8.8.8.8:443      # TCP SYN（需 HOST:PORT；目标回 SYN-ACK/RST 即到达）
prping trace --udp 8.8.8.8          # UDP（经典 traceroute，33434 起递增端口）
```

### 输出示例

```
正在跟踪到 www.baidu.com (110.242.68.66) 的路由，最多 30 跳:
  1    0.35 ms   0.28 ms   0.31 ms  192.168.1.1
  2    2.10 ms   1.98 ms   2.05 ms  100.64.0.1
  3        *        *        *        *
  4   25.12 ms  24.80 ms  25.33 ms  dg-xxx.bj.baidubce.com (110.242.68.66)

到达目标 www.baidu.com，共 4 跳。
```

### 工作原理

**ICMP echo（默认）**：

1. 向目标发 ICMP echo request，TTL 从 1 起逐跳递增（IPv6 用 Hop Limit）
2. TTL 耗尽的中间路由器回 ICMP Time Exceeded（type 11 / ICMPv6 type 3），
   其源地址即该跳地址——Time Exceeded 内嵌原始报文（IP 头 + 前 8 字节 ICMP），
   按 id/seq 匹配确认归属（与 `tracert` 同款校验）
3. 目标本身回 ICMP echo reply → 到达，停止跟踪

**TCP SYN（`--tcp HOST:PORT`）**：

1. 发 TCP SYN，TTL 逐跳递增；每个探测用独立源端口，按内嵌 TCP 头的
   (sport, dport) 匹配归属（无需 seq）
2. 中间路由器回 Time Exceeded（内嵌原始 TCP 头）；目标回 **SYN-ACK**
   （端口开）或 **RST**（端口关）即到达——两种都算到达目标
3. 收包用两个 socket：raw ICMP（Time Exceeded）+ raw TCP（SYN-ACK/RST），
   `poll` 同时等待；TCP 伪头部校验和按 UDP 路由探测得到的本地源地址计算
4. **Windows 不支持**（raw TCP socket 受限），`trace --tcp` 报错提示

**UDP（`--udp HOST`，经典 Unix traceroute）**：

1. 普通 UDP socket 发载荷到递增目标端口（33434 起，每探测 +1，尽量避开
   被监听的端口），TTL 逐跳递增；UDP 头由内核构造（校验和内核算）
2. 中间路由回 Time Exceeded（内嵌原始 UDP 头，按 (sport, dport) 匹配归属）；
   目标回 **Port Unreachable**（type 3 code 3 / ICMPv6 type 1 code 4）即到达
3. 只需一个 raw ICMP socket 收包；**跨平台可用**（Windows 支持普通 UDP +
   raw ICMP，不像 `--tcp` 被禁止）
4. 目标 UDP 端口恰好开放（如 DNS 53）时回的是数据而非 ICMP——该探测显示 `*`
   （经典 traceroute 同样如此，选高段端口正是为避开）

### 说明

- 超时跳打印红色 `*`（路由器屏蔽 ICMP/UDP 或路径丢包），不中断跟踪
- 每跳 3 次探测（背靠背发送，单跳收集窗口 1 秒）；反向 DNS 解析每跳主机名
- `-m N` 上限 255（TTL 字段上限），默认 30；`-d` 跳过反向 DNS
  （避免慢 DNS 拖慢整条路径）
- 目标不回显/不答 SYN/不回端口不可达时跑满 `-m` 跳仍标记未到达 → 非零退出码
- 需要 raw socket（root / `cap_net_raw`）；`--tcp` 的端口建议选常用开放端口
  （如 80/443），被过滤时退化为 `*`；`--tcp` 与 `--udp` 互斥

---

## 18. 源地址绑定（-s）

**用途**：指定探测源地址/网卡——多网卡主机、策略路由、双链路排障。

```bash
prping ping -s 192.168.1.10 8.8.8.8        # 指定源 IP（TCP/ICMP/UDP 均可）
prping ping -s 10.0.0.2 server:8080 -l 64  # 延迟测试指定源
prping ping -s eth0 8.8.8.8                # Linux：网卡名自动取 IPv4
prping ping -m -s eth1 8.8.8.8             # MTU 探测指定源
```

### 说明

- 参数可以是 IP 地址，或 **Linux 网卡名**（经 `SIOCGIFADDR` 取该网卡 IPv4；
  IPv6 请直接写地址）
- 全模式生效：ICMP / TCP / UDP ping、延迟、带宽、MTU 探测
- 服务端模式不接受 `-s`（`--source`）
- 源族不匹配时报错（如 `-s` 给 IPv6 地址而目标是 IPv4）

---

## 19. IPv4 / IPv6 双栈

```bash
prping ping 8.8.8.8                # IPv4
prping ping 2001:4860:4860::8888   # IPv6（无需括号）
prping ping [::1]:80               # IPv6 带端口需方括号
prping ping -6 example.com         # 强制 IPv6（域名多记录时）
prping ping -4 example.com         # 强制 IPv4
```

### 规则

- 无 `-4/-6` 时按目标形式自动判断；域名解析出多条记录时取首个
- `-4` 与 `-6` 互斥（同时给出报错）
- MTU 探测仅 IPv4（第 16 章）

---

## 20. 退出码与脚本化

| 退出码 | 含义 |
|---|---|
| 0 | 无丢包（含 MTU 探测成功）；traceroute 到达目标 |
| 1 | 有丢包 / 未到达目标 / 连接失败 / 参数错误 |
| 2 | 其他运行错误 |

```bash
prping ping -n 10 8.8.8.8 || echo "网络有问题"
prping ping -n 10 --json 8.8.8.8 >/dev/null && echo OK

# 监控脚本：丢包阈值告警
loss=$(prping ping -n 5 --json 8.8.8.8 | tail -1 | jq -r .loss_pct)
[ "$(echo "$loss > 10" | bc)" = 1 ] && alert
```

---

## 21. 信号与中断（Ctrl+C）

- **首次 Ctrl+C**：停止测试，输出完整统计后退出
- **再次 Ctrl+C**：强制退出（不等统计）
- `--json` 模式在 Unix 上运行期间关闭终端回显的 `^C`
  （`^C` 是终端回显、从不进入 stdout 管道；退出时恢复）

---

## 22. 语言与国际化

自动检测：`$LANG`（Unix）/ 系统 UI 语言（Windows）；`--lang` 手动指定。

```bash
prping ping --lang en-US 8.8.8.8    # 英文
prping ping --lang zh-CN 8.8.8.8    # 中文（默认按系统）
LANG=zh_CN.UTF-8 prping ping 8.8.8.8
```

### 手册语言

`--help-pkg` 的手册随语言切换：

```bash
prping --lang zh-CN --help-pkg 16     # 中文手册第 16 章（MTU）
prping --lang en-US --help-pkg MTU    # 英文手册
```

---

## 23. 完整示例合集

### 日常排障

```bash
# 1. 通不通？
prping ping 8.8.8.8 -n 4

# 2. 延迟/抖动/丢包全景（20 次，阈值直方图）
prping ping -n 20 -w 0 -H "1,5,10,50" 8.8.8.8

# 3. 特定端口
prping ping 8.8.8.8:53 -n 10
prping ping 192.168.1.1:443 -n 10 -i 0.5

# 4. 大包通不通（MTU 问题）
prping ping -l 1400 8.8.8.8
prping ping -m 8.8.8.8

# 5. 路由路径 / 卡在哪一跳
prping trace 8.8.8.8

# 6. 多网卡指定源
prping ping -s eth1 10.0.0.1:80 -n 20
```

### 延迟/带宽（对端需 `prping server`）

```bash
prping server 0.0.0.0:8080                       # 服务端
prping latency -l 64 -n 1000 server:8080             # TCP 延迟
prping latency -l 64 -n 1000 -u server:8080          # UDP 延迟
prping latency -l 64 -n 1000 -r server:8080          # 反向（下载方向）
prping bandwidth -l 8k -n 10000 --parallel 4 server:8080    # 带宽
prping bandwidth -l 1m -n 10s --parallel 8 server:8080      # 时长模式带宽
prping bandwidth -l 8k -n 10000 --parallel 4 -r server:8080 # 反向带宽
```

### 脚本/监控

```bash
# 每 30 秒测一次延迟并记录
while true; do
  echo "$(date +%s) $(prping ping -n 3 --json 8.8.8.8 | tail -1 | jq -r .avg_ms)"
  sleep 30
done >> latency.log

# 丢包率变化
prping ping -n 60 -i 1 --json 8.8.8.8 | jq -c 'select(.summary)'
```

---

## 24. 常见问题（FAQ）

### Q1: ICMP ping 报「无法创建 raw socket」
需要 root 或 `cap_net_raw`：
```bash
sudo setcap cap_net_raw+ep $(which prping)
```
Windows 需以管理员运行。

### Q2: UDP ping 全部超时
UDP 无回显服务（或防火墙丢弃）。用 TCP/ICMP 交叉验证；
DNS 服务器可用 `prping ping -u 8.8.8.8:53` 试试（DNS 会回包）。

### Q3: 小包通、大包不通
大概率是 MTU 问题：`prping ping -m <host>` 探测路径 MTU，
检查两端 MTU 配置与隧道开销（如 PPPoE 减 8 字节）。

### Q4: 延迟低但视频/语音卡
看**抖动 jitter**（第 14 章）——高抖动比高延迟更伤实时流。
`prping ping -n 100 -H 1,5,10,50 <host>` 看分布。

### Q5: `-n 1m` 是 100 万次吗？
会报错。`-n` 只支持 `s` 后缀（秒，`-n 10s` = 10 秒）；
固定次数写纯数字（`-n 1000000`）。`-l` 的 `m` 后缀才是兆字节（`-l 1m` = 1MB 载荷）。

### Q6: `--parallel` 对 TCP ping 无效？
`--parallel` 只对带宽测试有效；其他模式忽略并给出警告。

### Q7: 带宽测试数字和 iperf3 不一样？
正常。prping 带宽模式是便捷压测，未做窗口/拥塞调优；
精确吞吐请用 iperf3。

### Q8: 如何测下载方向？
`-r` 接收模式（第 11 章），对端 `prping server`。

### Q9: `--json` 和 `-p/-g/-H` 能一起用吗？
不能，互斥。JSON 是机器格式。

### Q10: 支持 Win7 吗？
支持（Win7 兼容版构建配方见第 2 章与项目 README）。

### Q11: 想构造/发送自定义数据包？
那是包构造引擎（第 26 章）：`prping packet examples/network_icmp_bare ...`。

---

## 25. 与 psping 的对比

| 功能 | psping | prping | 说明 |
|---|---|---|---|
| ICMP ping | ✓ | ✓ | raw socket |
| TCP ping | ✓ | ✓ | 建连延迟 |
| UDP ping | ✗ | ✓ | prping 独有 |
| 延迟测试 | ✓ | ✓ | TCP/UDP |
| 带宽测试 | ✓ | ✓ | TCP/UDP，`--parallel` 并发 |
| 接收模式 `-r` | ✓ | ✓ | 测下载方向 |
| MTU 探测 | ✗ | ✓ | prping 独有（自动二分） |
| 抖动 jitter | ✗ | ✓ | prping 独有 |
| 直方图 | `-h` | `-H` | 桶数或自定义阈值（ms） |
| 时间线 | ✓ | `-g` | `-p` 用 ploot 渲染 |
| JSON 输出 | ✗ | ✓ | 脚本友好 |
| 退出码 | 部分 | ✓ | 有丢包返回 1 |
| i18n | ✗ | ✓ | 中英自动切换 |
| 跨平台 | Windows | Linux/macOS/Windows | 含 Win7 兼容版 |
| 防火墙 `-f` | ✓ | — | Windows only，跨平台无此需求 |

---

## 26. 包构造引擎（engine / packet / packet-dsl）

### packet-dsl（workspace 子 crate）

`.pkt` 网络包构建 DSL：解析 + 语义分析 → 结构化 IR → 序列化字节。
支持 import/export 模块系统、运行时参数（`params("name")`）、字节原语
（`concat`/`be16`/`rand16`/...，随机值在构建期生成，如 `sport=rand16()`）、
用户函数（`func name(args) { ... }`）、
包反解（`dissect(bytes)`）、pcap 读写。设计文档见 `crates/packet-dsl/DESIGN.md`。

### 引擎模式（同一 binary）

包构造引擎 CLI，与 prping 本体完全分离：

```bash
prping engine FILE.pkt            # 分析：层栈 + hexdump
prping engine --lsp               # .pkt 语言服务器
prping packet FILE.pkt [HOST:PORT] # 构建并发送（目标可省略，按包内推导）
prping packet FILE.pkt --wait 3   # 应答匹配 + RTT
prping packet FILE.pkt --fuzz     # 全字段随机化
prping packet FILE.pkt --out x.pcap  # 存 pcap
prping engine --ls / --hex ... / --pcap x.pcap
prping engine --pcap x.pcap --to-pkt dir/          # pcap → 每记录一个 .pkt + 一个 .pktl 配方
prping engine --pcap x.pcap --to-pkt dir/ --structured  # 语义结构化转码
```

**无扩展名参数自动定位 pktl**：`engine`/`packet` 的文件参数不带扩展名时，
先找 `<arg>.pktl`（当前目录/参数所在目录），找不到该文件再找同名文件夹里的
`<arg>/<basename>.pktl`。examples 即按此组织——每示例一个文件夹
（`examples/<name>/<name>.pktl` + 其 .pkt），如：

```bash
prping engine examples/tcp_handshake    # = examples/tcp_handshake/tcp_handshake.pktl
prping packet tcp_handshake 127.0.0.1:80 --wait 1   # （在 examples/ 目录下）
```

### pcap → .pkt/.pktl 转码（`engine --pcap --to-pkt`）

`--out` 的逆操作：把 pcap 逐条转成 `.pkt`（每记录一个 `record_%05d.pkt`，按原始序号
命名）+ 一个 `.pktl` 配方（按序引用全部 `.pkt`，步骤 `delay:` 携带捕获帧间隔——
间隔 <1μs 不写；首步无 delay），可直接 `packet dir/x.pktl [HOST:PORT] --raw` 还原
发送或 `--out` 合并写回 pcap：

```bash
prping engine --pcap x.pcap --to-pkt dir/            # 无损字节级（缺省）
prping engine --pcap x.pcap --to-pkt dir/ --structured   # 语义结构化
prping engine --pcap x.pcap --to-pkt dir/ --skip 10 --limit 100  # 只转第 11..110 条
prping engine --pcap x.pcap --to-pkt dir/ --threads 8       # 8 线程并行解析
```

两种路线：

- **无损字节级（A1，缺省）**：整帧/整包 `layer("eth"/"ipv4"/"ipv6", hex(...))` 或
  `raw(bytes=hex(...))` 直喂——字节 100% 保真（不经语义字段层，checksum 不会被重算），
  且最外层为 eth/ipv4/ipv6 时可 `--raw` 发送还原捕获字节。未知链路类型（非
  1=Ethernet/101=Raw）只能 `raw` 存档，头注释会提示。
- **语义结构化（A2，`--structured`）**：`dissect` 反解层栈 → 可读可编辑的 DSL 源码
  （`eth`/`arp`/`ipv4`/`ipv6`/`icmp`/`tcp`/`udp` 语义字段 + `bor(syn(), ack())` 等
  位常量；`dns`/`http` 及语义无法表达的层——IPv4/TCP 选项头、TCP URG 指针、IPv6
  traffic class/flow label——整段 `*_bytes(hex(...))` 字节直喂）。合法捕获经
  层序反转 + 每层 raw 头字节，重序列化**字节级一致**（roundtrip 保真）；有
  `remaining`（以太网填充/未知协议载荷）或无法反解时整条退回 A1（`fallback`）。
  头注释带层栈与 dissect 注记（如 checksum 错）。

**并行解析（`--threads N`）**：逐记录 dissect/渲染是纯函数、完全独立，可多线程
（`std::thread::scope` 零新依赖；worker 各自渲染+写文件，结果按序号归位，与单线程
产出逐字节一致）。`0` = 自动（记录数 ≥ 1024 时按 CPU 核数并行，小文件保持单线程
避免线程池开销）；`1` = 强制单线程；`N` = 精确 N 线程（≤ 记录数）。无损 A1 模式
几乎不耗 CPU（I/O 是瓶颈），多线程收益主要在 `--structured` 的大 pcap 上。

**配方 `delay:` 步骤选项**：步骤开始前等待（非首步生效，分片 sleep 响应 Ctrl+C 提前
结束）——转码配方用它复现捕获节奏；手写配方也可用（如模拟思考间隔）。

**sniffer 段**（回包校验）：`--wait` 时按 `.pkt` 里的 sniffer 声明匹配应答，
匹配成功显示 `✓ reply matched: 字段=值 (rtt)`，超时显示 `✗ no matching reply`：

```pkt
sniffer:
  - match icmp(type=0, id=id, seq=seq)   # 回包必须是 echo reply，id/seq 与发包一致
  # - match dns(id=id)                    # DNS 应答 id 与查询一致（替代默认 DNS id 匹配）
  # 右值字面量 = 常量比较（type=0）；裸 Ident = 引用发包同层同名字段（id=id）
  # 多子句 = 任一命中即匹配（与 export: 同风格列表）
```

示例：

```
# net.pkt —— 组合函数：一次生成 ipv4+eth 两层
import net { net4 }
use(p) |> net4(dst="1.1.1.1")
```

### 字节原语关系表（raw / hex / u8 / be16 / be32 / []）

DSL 的字节最终形态是「字节列表」——`[0x12, 0x34]` 这种 `[]` 字面量。下面六个写法
都是字节的构造/消费入口（`raw` 是**双位置**原语：层 = Raw 载荷层，值 = UTF-8 字节）：

| 原语 | 位置 | 输入 | 输出 | 等价关系 |
| --- | --- | --- | --- | --- |
| `[]` 字面量 | 值 | — | 字节列表 | 一切字节原语的共同产物形态 |
| `raw("abc")` | **层 / 值** | 字符串（UTF-8）或字节列表 | Raw 载荷层 / 字节列表 | `raw("abc")` = `[0x61, 0x62, 0x63]` ≡ Python `b"abc"` |
| `hex("1234")` | 值 / 层 | hex 文本（可选 `0x` 前缀、偶数长度） | 字节列表 / Raw 层 | `hex("1234")` = `[0x12, 0x34]` |
| `u8(x)` | 值 | 数值 0..255 或 1 字节 | 1 字节 | `u8(0x61)` = `u8([0x61])` = `[0x61]` |
| `be16(x)` | 值 | 数值 0..65535 或 2 字节 | 2 字节大端 | `be16(0x1234)` = `be16(hex("1234"))` = `[0x12, 0x34]` |
| `be32(x)` | 值 | 数值 0..2³²-1 或 4 字节 | 4 字节大端 | 同上，宽度 4 |

流向速览：

```
"abc" ──bytes()/raw()──► [61 62 63]         字符串 = UTF-8 字节（≡ Python b"abc"）
"1234" ──hex()──► [12 34]                    hex 文本 = 字节
0x1234 ──be16()──► [12 34]  ──le16()──► [34 12]   数值按宽度大端/小端编码
[12 34] ──be16()──► [12 34]  ──int()──► 0x1234     同宽直通 / 大端解码
```

互转规则（**宽度即类型**——字节数相同即可直接互转，无需再包函数）：

- `be16(hex("1234"))` = `be16([0x12, 0x34])` = `u8(raw("a"))` —— 同宽字节直通；
  宽度不符才报错（`be16(hex("123456"))` → 需要 2 字节）
- `le16`/`le32` 小端编码（`le16(0x1234)` = `[0x34, 0x12]`），字节输入做反转
  （`le16([0x01, 0x02])` = `[0x02, 0x01]`）
- 字符串字面量不隐式转数值：`be16("0x4242")` 报错，写 `be16(0x4242)` 或 `be16(hex("0x4242"))`
- `raw` 是双位置原语（层 = 载荷层，值 = UTF-8 字节）。**params 按形状解析**
  （`0x` 前缀 = 十六进制数值、纯数字 = 十进制数值、其余 = 字符串）：
  `be16(params("port", "53"))` / `icmp(id=params("id", "0x1234"))` 直接可用；
  **默认值可为值表达式**（`params("port", be16(0x1235))` = `[0x12,0x35]`）

### raw 发送的平台差异（packet --raw）

`packet --raw` 发送完整序列化字节，各平台底层实现不同：

| 平台 | eth 层（以太网帧） | ipv4 层（裸 IP） | ipv6 层（裸 IPv6） |
|---|---|---|---|
| Linux | AF_PACKET（需 root/cap_net_raw；`--iface` 指定网卡，默认 lo） | IPPROTO_RAW + IP_HDRINCL | AF_INET6 + IPPROTO_RAW + IPV6_HDRINCL |
| Windows | Npcap `pcap_sendpacket` 链路层注入（需安装 Npcap；`--iface` 匹配 Npcap 设备名/描述） | Npcap 注入 + 自动以太网封装（src MAC = 接口 MAC，dst MAC = 下一跳 ARP） | 仅支持回环 `::1`（经 Npcap Loopback Adapter） |
| macOS/BSD | 不支持 | IPPROTO_RAW 可用（无 IP_HDRINCL，IP 头由内核生成，语义与 Linux 不同） | 不支持 |

Windows 补充说明：

- **安装要求**：仅 `packet --raw`（Npcap 链路层注入）需要安装 Npcap（[npcap.com](https://npcap.com/)）。wpcap.dll 已改为延迟加载（`/DELAYLOAD`）——未安装 Npcap 的机器上 prping 其余功能（ping/latency/bandwidth/trace/engine 等）照常运行，只有执行 `packet --raw` 会报「需要 Npcap」。安装选项「Allow non-admin applications to capture packets」未勾选时，抓包/注入需要管理员权限。
- **Win7**：Npcap 仍支持 Windows 7；驱动为 SHA-2 签名，需安装 KB4474419 + KB4490628，否则驱动加载失败。
- **回环**：目标为 `127.0.0.1`/`::1` 时自动选用 Npcap Loopback Adapter（安装时勾选「Install Npcap Loopback Adapter」）。
- **MAC 解析**：裸 IPv4 发送前自动解析下一跳（`GetBestRoute`）与 ARP 缓存（`GetIpNetTable`）；未命中会先发 1 字节 UDP 触发内核 ARP 再查，仍失败用广播地址并警告。
- **IPv6 限制**：非回环的裸 IPv6 暂不支持（Win7 无 `GetIpNetTable2`，v6 邻居表不可枚举）。
- **`--wait`**：先开抓包句柄再发送（避免漏抓快速回包），并按方向过滤掉自己刚发的帧。

### 目标推导与链路层帧

`packet FILE.pkt [HOST:PORT]` 的目标优先级：**显式 `HOST:PORT` > 包内最外层 IP 层
`dst` 推导 > 省略**。raw 模式端口无意义（原始 socket 不带端口），可只写 `HOST`
（如 `packet foo.pkt --raw 192.168.1.5`）。

**链路层帧（最外层 eth、无 IP 层，如 ARP）raw 发送不需要目标**——AF_PACKET 按帧内
目的 MAC 直发（`--iface` 指定网卡，默认 lo），目标仅用于 IP 源地址填充等旁路逻辑：

```bash
prping packet examples/link_arp/arp_request.pkt --raw   # ARP 请求（广播帧）直接发出
#   target: none — 链路层帧，无需 IP 目标（AF_PACKET 按帧内目的 MAC 直发）
```

无 TCP/UDP 传输且最外层也不是 eth/ipv4/ipv6 的**纯裸层导出**（如 `req = arp(...)`
这类仅作 --eng 展示/组合的元件）payload 与 raw 模式一致跳过并黄字提示，不视为发送
失败；全部跳过时汇总报「没有可发送的包」。裸 IPv4/IPv6 发送仍需要目标（sendto 路由）。

**发送方式提示（`--eng`）**：无 TCP/UDP 传输但最外层可 raw 发送的包（如 ICMP
over IP、ARP over eth）在 `engine FILE.pkt` 逐包展示时橙色提示「本包只能经 raw
模式发送」——发送完整包需 `--raw`（或配方步骤 `raw: true`），payload 模式提取
不到载荷（不带 `--raw` 发送时会自动回退 raw socket）。

详见 `crates/packet-dsl/README.md`。

### 配方（.pktl，多个包按顺序发出）

`.pktl`（package list）把多个 `.pkt` 按顺序组成一次会话（握手/多包流程），
并用 **global 存储**跨步骤共享数据——不只是上一步，任意步骤都能读：

```text
# examples/dns_recipe/dns_recipe.pktl
global:
- name: tid             # 跨步骤共享变量（init 可选；-g 键值覆盖 init）
  init: 0x4321

recipe:
- pkg: recipe_query.pkt   # 发 recipe_query.pkt，等回包，提取 dns.id → global.tid
  wait: 1
  extract:
  - name: tid
    from: reply.dns.id    # 回包反解字段（层.字段，与 sniffer 字段集一致）
    as: hex               # 默认 int；可选 hex / str / bytes
- pkg: recipe_query.pkt   # 裸文件名 = 无额外选项
```

- **语法**：`global:` / `recipe:` 段头与步骤项（`- `）在行首；步骤选项行缩进。
  步骤项 `- pkg: 文件`（后可跟 `wait:` / `raw:` / `delay:` / `params:` / `extract:` /
  `on_error:`）
  或裸文件名 `- 文件`；`#` 注释；路径相对 .pktl 所在目录。global 项三种形态：
  `- name: 名`（可后跟缩进 `init:`）、`- 名`（裸声明，未初始化）、
  `- 名=值`（一行内联 init，值与 `init:` 同字面量语法）。
- **global 存储**：`.pkt` 内用新值原语 **`global("名"[, 默认值])`** 读取
  （与 `params` 对称，但值是**类型化**的——Int/Hex/Str/字节列表，不经过字符串
  形状解析，可直接参与 `+`/`be16`/位运算，如 `tcp(ack=global("seq") + 1)`）；
  未设置且无默认 → 报错。写入途径：`init` 初始值（global 项可 `- 名=值` 一行内联）、
  步骤 `extract`（回包取值，多个回包依次应用后写覆盖先写）、CLI `-g k=v`（覆盖 init）。
- **extract**：需要该步骤有回包（`wait:` 或 `--wait`）。`from:` 两种取值形态：
  - `reply.<层>.<字段>` 直取回包反解字段（层/字段名与 sniffer 一致），`as:` 控制
    形态——`int`（数值字段，默认）/ `hex` / `str`（IP/MAC 格式化字符串）/
    `bytes`（字段原始字节，网络序）；
  - **值表达式**（可调函数/原语/`+` 运算，内嵌 `reply.<层>.<字段>` 叶子）：
    `from: reply.tcp.seq + 1`、`from: be16(reply.dns.id)`、
    `from: cksum(reply.icmp.payload)`——表达式求值为类型化值（数值字段 → 整数、
    地址/字符串字段 → 字符串、`icmp.payload`/`http.body`/`raw.bytes` 载荷字段 →
    字节列表），可引用同步骤 .pkt 的 `func` 值函数、`params(...)`、`global(...)`；
    `as:` 可选（缺省 = 表达式的自然类型；显式 `as:` 按 int/hex/str/bytes 转换）。
    TCP 载荷回显的应答字节也保留（配方 extract 可用）。
- **容错**：步骤失败（发送失败 / extract 无回包或字段缺失）默认 **stop** 整个
  配方（退出码 1）；`on_error: continue` 记录失败继续，最后仍汇总报错。
- **raw 开关**：步骤 `raw: true` 强制本步用原始套接字发送完整序列化字节（等价
  单步 `--raw`，网卡继承 CLI `--iface`）；`raw: 网卡名`（如 `raw: eth0`）同时指定
  网卡；`raw: false` 强制本步走普通 TCP/UDP 载荷发送（覆盖 CLI `--raw`）——
  一个配方里可混合 raw 与载荷步骤，如先 `raw: eth0` 发 ARP/以太网帧、再 `raw: false`
  发 TCP 载荷。
- **CLI**：`packet FILE.pktl [HOST:PORT]` 执行；`--wait`/`--raw`/`-p`（`--params`）/
  `--fuzz`/`--out`/`--lib` 为全局默认，步骤内 `wait:`/`raw:`/`params:` 覆盖；
  `--out` 在配方模式收集全部步骤的包写一个 pcap；`-g k=v`（`--global`）注入全局。
  步骤 `delay: 秒数` 在**开始前**等待（非首步生效，分片 sleep 响应 Ctrl+C）——pcap 转码生成的配方用它携带捕获帧间隔（`engine --pcap x.pcap --to-pkt dir/`）。
  `engine FILE.pktl` 展示配方概览（global 声明 + **步骤 .pkt 用到的参数面**——
  `params("名", 默认)` 词法收集，含默认值与使用步骤，提示 `-p k=v` 注入；解析失败
  提前报错，与 extract 字段校验同一哲学）+ 步骤选项，并校验 extract 的
  层/字段名——表达式形态同样校验 `reply(...)` 叶子）；`packet FILE.pktl` 执行时
  header 同样汇总打印参数名。
- **示例**（每协议一个文件夹，内含同名 `.pktl` 与其 `.pkt`，均为可实际发送的
  **多包流程**）：
  `examples/tcp_handshake/`（TCP 三次握手：SYN → ACK → HTTP GET，seq/ack 经
  `global("cseq") + 1` 算术链）、
  `examples/transport_udp/`（UDP 发包：DNS 查询 + VNC 横幅两种载荷）、
  `examples/dns_recipe/`（DNS 查询：提取应答 dns.id 复用）、
  `examples/network_icmp_bare/`（ICMP echo：sniffer + extract id/seq 复用，裸 IP
  走内核路由，`--raw` 需 root）、
  `examples/app_http/`（HTTP GET/POST over TCP，`-p port=` 注入端口）、
  `examples/link_arp/`（ARP 请求/应答）、
  `examples/quic_initial/`（QUIC Initial/Short 长/短头）。
  运行如 `prping packet examples/dns_recipe 127.0.0.1:5353 --wait 1`。
