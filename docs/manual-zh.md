# prping 使用手册

> 跨平台网络「万用表」——psping 复刻，用 Rust 实现。
> 测量：ICMP / TCP / UDP ping、延迟测试、带宽测试、路径 MTU 探测、抖动统计。
> 包构造引擎集成在同一 binary（`--eng`/`--pkg` 模式，见第 25 章）。

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
16. [MTU 探测（-M / --mtu）](#16-mtu-探测-m---mtu)
17. [源地址绑定（-I）](#17-源地址绑定-i)
18. [IPv4 / IPv6 双栈](#18-ipv4-ipv6-双栈)
19. [退出码与脚本化](#19-退出码与脚本化)
20. [信号与中断（Ctrl+C）](#20-信号与中断ctrlc)
21. [语言与国际化](#21-语言与国际化)
22. [完整示例合集](#22-完整示例合集)
23. [常见问题（FAQ）](#23-常见问题faq)
24. [与 psping 的对比](#24-与-psping-的对比)
25. [包构造引擎（--eng / --pkg / packet-dsl）](#25-包构造引擎--eng--pkg--packet-dsl)

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
- **带宽测试**：多连接并发（`-P`），实时进度条
- **路径 MTU 探测**（`-M`）：ICMP DF + 变长载荷二分，自动解析
- **抖动 jitter**：相邻 RTT 差的均值/最大，实时流排障指标
- **统计**：min/max/avg/stddev + P50/P95/P99 + 丢包率 + 直方图 + 时间线
- **JSON 输出**：逐次采样 + 汇总，机器可读，适合脚本/监控
- **源地址绑定**（`-I`）：多网卡 / 策略路由场景
- **次数或时长**：`-n 10` 固定次数，`-n 10s` 按秒运行
- **IPv4/IPv6 双栈**、Ctrl+C 优雅退出、中英双语、退出码反映丢包

### 命令行总览

```
prping [选项] <HOST[:PORT]>
```

没有选项时按目标自动识别模式：

| 目标形式 | 模式 |
|---|---|
| `HOST`（无端口） | ICMP ping |
| `HOST:PORT` | TCP ping |
| `-u HOST:PORT` | UDP ping |
| `-l SIZE HOST:PORT` | 延迟测试 |
| `-b -l SIZE HOST:PORT` | 带宽测试 |
| `-M HOST` | MTU 探测 |
| `-s ADDR:PORT` | 服务端 |

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
prping 8.8.8.8                    # ICMP，无限测，Ctrl+C 停
prping example.com                # 域名自动解析

# 端口通不通 / 建连延迟
prping 192.168.1.1:80
prping 8.8.8.8:53 -n 10           # 固定 10 次

# 延迟测试（需要服务端，见第 10 章）
prping -l 64 -n 100 server:8080

# 带宽测试
prping -b -l 8k -n 10000 -P 4 server:8080

# 快速看一轮统计（含抖动）
prping -n 20 -w 0 -H 10 192.168.1.1

# 路径 MTU
prping -M 8.8.8.8

# 指定源地址
prping -I 192.168.1.10 8.8.8.8
```

---

## 4. 模式总览（自动识别）

模式由「选项 + 目标端口」自动判定，无需显式模式参数：

| 触发条件 | 模式 | 说明 |
|---|---|---|
| 无端口、无 `-u/-l/-b/-M` | ICMP | 默认；`-4/-6` 选协议 |
| 有端口、无 `-u/-l/-b` | TCP | 建连延迟 + 可达性 |
| `-u` + 端口 | UDP | 发 UDP 数据报，校验回包 seq |
| `-l SIZE` + 端口 | 延迟测试 | 需对端 `prping -s` |
| `-b` + `-l SIZE` + 端口 | 带宽测试 | 需对端 `prping -s` |
| `-M` | MTU 探测 | 无端口；仅 IPv4 |
| `-s ADDR:PORT` | 服务端 | 不能与客户端参数混用 |

所有模式共用「测试控制」「输出」「网络」选项组（第 12/13/15/18 章）。

---

## 5. ICMP Ping

**用途**：最基础的连通性 + 延迟测量；区分网络故障（不可达/TTL 超时）。

```bash
prping 8.8.8.8                  # 无限（Ctrl+C 停）
prping -n 10 -i 0.2 8.8.8.8     # 10 次，200ms 间隔
prping -l 1400 8.8.8.8          # 大载荷（探测链路限制）
prping -M 8.8.8.8               # 见第 16 章：自动 MTU
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

- 原始 ICMP socket：Linux/macOS 需 root 或 `cap_net_raw`；Windows 需管理员
- `-l` 控制 ICMP 载荷字节数（不含 ICMP/IP 头）
- 区分三类回复：echo reply（正常）、不可达（type 3）、TTL 超时（type 11）

---

## 6. TCP Ping

**用途**：端口连通性 + 建连（connect）延迟；等价于「telnet 端口 + 计时」。

```bash
prping 192.168.1.1:22           # SSH 端口
prping -n 30 -i 0.1 -H 10 server:443
prping -I 10.0.0.2 server:443   # 指定源地址（第 17 章）
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
- `-P` 并发在此模式无意义（每次只连一次）

---

## 7. UDP Ping

**用途**：UDP 可达性测试（如 DNS 53 端口、游戏服务器），psping 之外 prping 独有。

```bash
prping -u 8.8.8.8:53
prping -u -n 10 192.168.1.1:5000
```

### 说明

- 发送带序号标记的 UDP 数据报；回包校验 seq，过滤杂包
- **目标需有 UDP 回显服务**（如 `prping -s` 服务端、DNS 应答）才会回包，
  无回显时全部超时——这是 UDP ping 的固有特性
- UDP 通常会被防火墙静默丢弃，丢包率 = 100% 不代表主机不可达，
  请用 ICMP/TCP 交叉验证

---

## 8. 延迟测试（Latency Test）

**用途**：端到端应用延迟（TCP 建连 + 数据往返），比 ping 更接近真实用户体验。
需要两端都装 prping：客户端 `-l` 触发，服务端 `-s`。

```bash
# 服务端（先起）
prping -s 0.0.0.0:8080

# 客户端
prping -l 64 -n 100 server:8080          # TCP 延迟测试（默认）
prping -l 64 -n 100 -u server:8080       # UDP 延迟测试
prping -l 64 -n 100 -r server:8080       # 反向：测下载方向（第 11 章）
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

**用途**：吞吐量测量（Mbps），`-P` 多连接并发压测。

```bash
# 服务端
prping -s 0.0.0.0:8080

# 客户端：8KB 包，1 万次，4 并发
prping -b -l 8k -n 10000 -P 4 server:8080

# 时长模式
prping -b -l 1m -n 10s -P 8 server:8080
```

### 输出示例

```
TCP Bandwidth test:
  Sent = 81920000 bytes in 0.42s
  Bandwidth = 1566.49 Mbps
```

### 说明

- 真实吞吐测量建议用 iperf3；prping 的带宽模式偏「够用」的便捷压测
- `-P` 并发数：多连接并行，总量精确等于 `count`
- `-r` 测下载方向（接收模式，见第 11 章）
- 进度条仅 tty 显示；管道/`--json`/`-q` 静默
- UDP 带宽模式内核缓冲自动放大到 4MB，避免突发丢包

---

## 10. 服务端模式（Server Mode）

**用途**：延迟/带宽测试的服务端；同时服务 TCP/UDP、延迟/带宽/接收模式。

```bash
prping -s 0.0.0.0:8080
prping -s [::]:8080             # IPv6
```

### 说明

- 一个服务端同时支持所有客户端模式（TCP/UDP × 延迟/带宽 × 收发方向）
- Ctrl+C 退出时打印聚合统计（连接数、收发字节等）
- 不能与任何客户端参数（`-n/-i/-l/-b/-u/-P/-I/-M` 等）混用
- Windows 上为 Win7 兼容保留

---

## 11. 接收模式（Receive Mode）

**用途**：测「下载方向」——客户端只收、服务端只发。

```bash
# 服务端
prping -s 0.0.0.0:8080

# 客户端：反向延迟测试
prping -l 64 -n 100 -r server:8080

# 客户端：反向带宽测试
prping -b -l 8k -n 10000 -P 4 -r server:8080
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
| `-P N` | 并发连接数（仅带宽测试有效；其他模式忽略并警告） |
| `-l SIZE` | 载荷大小，支持 `64` / `8k` / `1m` 后缀 |

### 示例

```bash
prping -n 1000 -i 0.01 8.8.8.8      # 1000 次快速 ping（10ms 间隔）
prping -n 30s -w 5 server:8080      # 测 30 秒，5 次预热
prping -q -n 100 192.168.1.1        # 只输出汇总
prping -n 1000000 -i 0 -q 8.8.8.8   # 100 万次快速 ping（0 间隔 = 最快）
```

> 注意：`-n` 只支持 `s` 后缀（秒，如 `-n 10s`）；`-n 1m` 会报错，
> 固定次数写纯数字。`-l` 的 `m` 后缀才是兆字节（`-l 1m` = 1MB 载荷）。

---

## 13. 直方图与时间线（-H / -g / -p）

### 直方图 `-H`

两种形式：

```bash
prping -n 100 -H 10 8.8.8.8          # 10 个桶
prping -n 100 -H "1,5,10,50" 8.8.8.8 # 自定义毫秒阈值：1/5/10/50ms 分档
```

默认 ASCII `#` 渲染；`-p`（pretty）用
[ploot](https://github.com/ploot-rs/ploot) 渲染 Unicode 柱状图
（非 tty 自动剥离 ANSI 颜色）。

### 时间线 `-g`

```bash
prping -n 20 -i 0.1 -gp 127.0.0.1:22  # 时间线图（-p 用 ploot Braille 散点）
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
prping -n 10 --json 8.8.8.8 | tail -1 | jq .jitter_ms
prping -n 30s --json server:8080 | jq -r 'select(.ok) | .rtt_ms' | awk '{s+=$1} END {print s/NR}'
```

> `--json` 在 Unix 上运行期间关闭终端回显的 `^C`（退出时恢复）。

---

## 16. MTU 探测（-M / --mtu）

**用途**：找出路径最大可传输单元（path MTU）——两端之间不产生分片的最大包尺寸。
链路 MTU 不匹配是「小包通、大包不通」的经典根因。

```bash
prping -M 8.8.8.8
prping -M 192.168.1.1 -I eth0     # 指定源
prping -M --json 8.8.8.8          # 机器可读
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

## 17. 源地址绑定（-I）

**用途**：指定探测源地址/网卡——多网卡主机、策略路由、双链路排障。

```bash
prping -I 192.168.1.10 8.8.8.8        # 指定源 IP（TCP/ICMP/UDP 均可）
prping -I 10.0.0.2 server:8080 -l 64  # 延迟测试指定源
prping -I eth0 8.8.8.8                # Linux：网卡名自动取 IPv4
prping -M -I eth1 8.8.8.8             # MTU 探测指定源
```

### 说明

- 参数可以是 IP 地址，或 **Linux 网卡名**（经 `SIOCGIFADDR` 取该网卡 IPv4；
  IPv6 请直接写地址）
- 全模式生效：ICMP / TCP / UDP ping、延迟、带宽、MTU 探测
- 服务端模式（`-s`）不接受 `-I`
- 源族不匹配时报错（如 `-I` 给 IPv6 地址而目标是 IPv4）

---

## 18. IPv4 / IPv6 双栈

```bash
prping 8.8.8.8                # IPv4
prping 2001:4860:4860::8888   # IPv6（无需括号）
prping [::1]:80               # IPv6 带端口需方括号
prping -6 example.com         # 强制 IPv6（域名多记录时）
prping -4 example.com         # 强制 IPv4
```

### 规则

- 无 `-4/-6` 时按目标形式自动判断；域名解析出多条记录时取首个
- `-4` 与 `-6` 互斥（同时给出报错）
- MTU 探测仅 IPv4（第 16 章）

---

## 19. 退出码与脚本化

| 退出码 | 含义 |
|---|---|
| 0 | 无丢包（含 MTU 探测成功） |
| 1 | 有丢包 / 连接失败 / 参数错误 |
| 2 | 其他运行错误 |

```bash
prping -n 10 8.8.8.8 || echo "网络有问题"
prping -n 10 --json 8.8.8.8 >/dev/null && echo OK

# 监控脚本：丢包阈值告警
loss=$(prping -n 5 --json 8.8.8.8 | tail -1 | jq -r .loss_pct)
[ "$(echo "$loss > 10" | bc)" = 1 ] && alert
```

---

## 20. 信号与中断（Ctrl+C）

- **首次 Ctrl+C**：停止测试，输出完整统计后退出
- **再次 Ctrl+C**：强制退出（不等统计）
- `--json` 模式在 Unix 上运行期间关闭终端回显的 `^C`
  （`^C` 是终端回显、从不进入 stdout 管道；退出时恢复）

---

## 21. 语言与国际化

自动检测：`$LANG`（Unix）/ 系统 UI 语言（Windows）；`--lang` 手动指定。

```bash
prping --lang en-US 8.8.8.8    # 英文
prping --lang zh-CN 8.8.8.8    # 中文（默认按系统）
LANG=zh_CN.UTF-8 prping 8.8.8.8
```

### 手册语言

`--help-pkg` 的手册随语言切换：

```bash
prping --lang zh-CN --help-pkg 16     # 中文手册第 16 章（MTU）
prping --lang en-US --help-pkg MTU    # 英文手册
```

---

## 22. 完整示例合集

### 日常排障

```bash
# 1. 通不通？
prping 8.8.8.8 -n 4

# 2. 延迟/抖动/丢包全景（20 次，阈值直方图）
prping -n 20 -w 0 -H "1,5,10,50" 8.8.8.8

# 3. 特定端口
prping 8.8.8.8:53 -n 10
prping 192.168.1.1:443 -n 10 -i 0.5

# 4. 大包通不通（MTU 问题）
prping -l 1400 8.8.8.8
prping -M 8.8.8.8

# 5. 多网卡指定源
prping -I eth1 10.0.0.1:80 -n 20
```

### 延迟/带宽（对端需 `prping -s`）

```bash
prping -s 0.0.0.0:8080                       # 服务端
prping -l 64 -n 1000 server:8080             # TCP 延迟
prping -l 64 -n 1000 -u server:8080          # UDP 延迟
prping -l 64 -n 1000 -r server:8080          # 反向（下载方向）
prping -b -l 8k -n 10000 -P 4 server:8080    # 带宽
prping -b -l 1m -n 10s -P 8 server:8080      # 时长模式带宽
prping -b -l 8k -n 10000 -P 4 -r server:8080 # 反向带宽
```

### 脚本/监控

```bash
# 每 30 秒测一次延迟并记录
while true; do
  echo "$(date +%s) $(prping -n 3 --json 8.8.8.8 | tail -1 | jq -r .avg_ms)"
  sleep 30
done >> latency.log

# 丢包率变化
prping -n 60 -i 1 --json 8.8.8.8 | jq -c 'select(.summary)'
```

---

## 23. 常见问题（FAQ）

### Q1: ICMP ping 报「无法创建 raw socket」
需要 root 或 `cap_net_raw`：
```bash
sudo setcap cap_net_raw+ep $(which prping)
```
Windows 需以管理员运行。

### Q2: UDP ping 全部超时
UDP 无回显服务（或防火墙丢弃）。用 TCP/ICMP 交叉验证；
DNS 服务器可用 `prping -u 8.8.8.8:53` 试试（DNS 会回包）。

### Q3: 小包通、大包不通
大概率是 MTU 问题：`prping -M <host>` 探测路径 MTU，
检查两端 MTU 配置与隧道开销（如 PPPoE 减 8 字节）。

### Q4: 延迟低但视频/语音卡
看**抖动 jitter**（第 14 章）——高抖动比高延迟更伤实时流。
`prping -n 100 -H 1,5,10,50 <host>` 看分布。

### Q5: `-n 1m` 是 100 万次吗？
会报错。`-n` 只支持 `s` 后缀（秒，`-n 10s` = 10 秒）；
固定次数写纯数字（`-n 1000000`）。`-l` 的 `m` 后缀才是兆字节（`-l 1m` = 1MB 载荷）。

### Q6: `-P` 对 TCP ping 无效？
`-P` 只对带宽测试有效；其他模式忽略并给出警告。

### Q7: 带宽测试数字和 iperf3 不一样？
正常。prping 带宽模式是便捷压测，未做窗口/拥塞调优；
精确吞吐请用 iperf3。

### Q8: 如何测下载方向？
`-r` 接收模式（第 11 章），对端 `prping -s`。

### Q9: `--json` 和 `-p/-g/-H` 能一起用吗？
不能，互斥。JSON 是机器格式。

### Q10: 支持 Win7 吗？
支持（Win7 兼容版构建配方见第 2 章与项目 README）。

### Q11: 想构造/发送自定义数据包？
那是包构造引擎（第 25 章）：`prping --pkg demo.pkt ...`。

---

## 24. 与 psping 的对比

| 功能 | psping | prping | 说明 |
|---|---|---|---|
| ICMP ping | ✓ | ✓ | raw socket |
| TCP ping | ✓ | ✓ | 建连延迟 |
| UDP ping | ✗ | ✓ | prping 独有 |
| 延迟测试 | ✓ | ✓ | TCP/UDP |
| 带宽测试 | ✓ | ✓ | TCP/UDP，`-P` 并发 |
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

## 25. 包构造引擎（--eng / --pkg / packet-dsl）

### packet-dsl（workspace 子 crate）

`.pkt` 网络包构建 DSL：解析 + 语义分析 → 结构化 IR → 序列化字节。
支持 import/export 模块系统、运行时参数（`params("name")`）、字节原语
（`concat`/`be16`/`rand16`/...，随机值在构建期生成，如 `sport=rand16()`）、
用户函数（`func name(args) { ... }`）、
包反解（`dissect(bytes)`）、pcap 读写。设计文档见 `packet-dsl/DESIGN.md`。

### 引擎模式（同一 binary）

包构造引擎 CLI，与 prping 本体完全分离：

```bash
prping --eng FILE.pkt            # 分析：层栈 + hexdump
prping --eng --lsp               # .pkt 语言服务器
prping --pkg FILE.pkt [HOST:PORT] # 构建并发送（目标可省略，按包内推导）
prping --pkg FILE.pkt --wait 3   # 应答匹配 + RTT
prping --pkg FILE.pkt --fuzz     # 全字段随机化
prping --pkg FILE.pkt --out x.pcap  # 存 pcap
prping --eng --ls / --hex ... / --pcap x.pcap
```

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

### raw 发送的平台差异（--pkg --raw）

`--pkg --raw` 发送完整序列化字节，各平台底层实现不同：

| 平台 | eth 层（以太网帧） | ipv4 层（裸 IP） | ipv6 层（裸 IPv6） |
|---|---|---|---|
| Linux | AF_PACKET（需 root/cap_net_raw；`--iface` 指定网卡，默认 lo） | IPPROTO_RAW + IP_HDRINCL | AF_INET6 + IPPROTO_RAW + IPV6_HDRINCL |
| Windows | Npcap `pcap_sendpacket` 链路层注入（需安装 Npcap；`--iface` 匹配 Npcap 设备名/描述） | Npcap 注入 + 自动以太网封装（src MAC = 接口 MAC，dst MAC = 下一跳 ARP） | 仅支持回环 `::1`（经 Npcap Loopback Adapter） |
| macOS/BSD | 不支持 | IPPROTO_RAW 可用（无 IP_HDRINCL，IP 头由内核生成，语义与 Linux 不同） | 不支持 |

Windows 补充说明：

- **安装要求**：Npcap（[npcap.com](https://npcap.com/)）。安装选项「Allow non-admin applications to capture packets」未勾选时，抓包/注入需要管理员权限。
- **Win7**：Npcap 仍支持 Windows 7；驱动为 SHA-2 签名，需安装 KB4474419 + KB4490628，否则驱动加载失败。
- **回环**：目标为 `127.0.0.1`/`::1` 时自动选用 Npcap Loopback Adapter（安装时勾选「Install Npcap Loopback Adapter」）。
- **MAC 解析**：裸 IPv4 发送前自动解析下一跳（`GetBestRoute`）与 ARP 缓存（`GetIpNetTable`）；未命中会先发 1 字节 UDP 触发内核 ARP 再查，仍失败用广播地址并警告。
- **IPv6 限制**：非回环的裸 IPv6 暂不支持（Win7 无 `GetIpNetTable2`，v6 邻居表不可枚举）。
- **`--wait`**：先开抓包句柄再发送（避免漏抓快速回包），并按方向过滤掉自己刚发的帧。

详见 `packet-dsl/README.md`。
