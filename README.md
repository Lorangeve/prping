# prping

跨平台 psping 复刻，使用 Rust 实现。支持 ICMP ping、TCP ping、UDP ping、延迟测试、
带宽测试、路径 MTU 探测与路由跟踪。

## 特性

- **四种 ping 模式**：ICMP / TCP / UDP，自动识别（有端口=TCP，`-u`=UDP，无端口=ICMP）
- **次数或时长**：`-n 10` 固定次数，`-n 10s` 按秒运行
- **延迟测试**：client/server 架构，TCP/UDP 双模式，`-r` 接收模式测反向
- **带宽测试**：多连接并发（`--parallel`），直方图，`-r` 测下载方向
- **路径 MTU 探测**：`-m` 自动二分最大不分片载荷
- **路由跟踪**：`-t` 逐跳探测转发路径（递增 TTL + 反向 DNS）
- **IPv4/IPv6 双栈**：`[::1]:80` 括号格式自动识别
- **统计输出**：min/max/avg/stddev + P50/P95/P99 + 丢包率
- **可视化**：直方图（`-H`，支持自定义阈值）、延迟时间线；`-p` 用 [ploot](https://github.com/ploot-rs/ploot) 渲染 Unicode 柱状图/Braille 散点
- **JSON 输出**：`--json` 机器可读统计，适合脚本/监控
- **退出码**：有丢包时返回 1，脚本可据此判断成败
- **i18n**：英文/中文自动检测（`--lang` 切换）
- **彩色输出**：语义化配色（IP 青、端口品红、延迟黄、错误红）
- **Ctrl+C 优雅退出**：首次按下停止并输出统计，再次按下强制退出

## 安装

```bash
# 基本构建（Linux/macOS/Windows）
cargo build --release
sudo setcap cap_net_raw+ep target/release/prping  # ICMP 需要（Linux）

# Linux 可选：启用 pcap（需 libpcap-dev）
cargo build --release --features pcap
```

### 编译参数

| 参数 | 说明 |
|------|------|
| `--release` | Release 构建（推荐） |
| `--features pcap` | Linux 启用 pcap（macOS/Windows 默认启用） |
| `--features web` | 启用 `prping web` Web 编辑器子命令（默认不编译；`just build`/`just check`/`just test` 等统一启用） |

> **pcap 说明**：`packet --raw` 在 Windows/macOS 始终走 pcap 链路层注入；Linux 默认走原生 raw socket（AF_PACKET/IPPROTO_RAW），无需 pcap。启用 `--features pcap` 后 Linux 也走 pcap，与 Windows/macOS 行为一致。

> **web 说明**：`prping web` 子命令由 `--features web` 门控（默认不编译，产物体积更小）。workspace 需包名限定：`cargo build --features prping/web`。justfile 的 build/check/test 配方统一启用，产物默认具备完整功能。

## Windows 7

Rust 1.78 起官方将 `*-pc-windows-*` 目标最低支持提升到 **Windows 10**；Win7 需用官方的 Win7 基线目标（Tier 3）构建，**MSVC 版为首选**。详细构建说明 → `docs/claude-rules/windows-build.md`。

```bash
rustup toolchain install nightly --profile minimal
rustup component add rust-src --toolchain nightly
cargo install cargo-xwin
XWIN_ARCH=x86,x86_64 cargo +nightly xwin build -Z build-std --target x86_64-win7-windows-msvc --release
```

## 用法

子命令组织全部功能；可用任意**唯一前缀**缩写（`prping e file.pkt` ≡ `prping engine file.pkt`）。

```
prping ping HOST                # ICMP ping（无限，Ctrl+C 停止）
prping ping HOST:PORT           # TCP ping
prping ping -u HOST:PORT        # UDP ping
prping ping -m HOST             # 路径 MTU 探测（ICMP DF + 变长载荷二分）
prping latency -l SIZE HOST:PORT   # 延迟测试（-l 缺省 64）
prping bandwidth -l SIZE HOST:PORT # 带宽测试（-l 缺省 8k；--parallel 并发）
prping server ADDR:PORT         # 服务端（同时支持延迟/带宽/接收模式）
prping trace HOST               # 路由跟踪（ICMP echo + 递增 TTL，逐跳路径）
prping trace HOST:PORT          # TCP SYN 路由跟踪（带端口自动启用，ICMP 被过滤时可用）
prping trace --udp HOST         # UDP 路由跟踪（经典 traceroute，33434 起递增端口）
prping ping -s 192.168.1.10 HOST  # 指定源地址/网卡（Linux 网卡名 → IPv4）
prping --version                # 版本号
prping document                 # 完整使用手册（tty 自动分页）
prping document 17              # 跳转手册第 17 章（路由跟踪）
# 包构造引擎（子命令，与测量模式互斥）：
prping engine FILE.pkt          # .pkt 分析（层栈 + hexdump）
prping engine --lsp             # .pkt 语言服务器（JSON-RPC over stdio）
prping packet FILE.pkt [HOST:PORT]  # 构建并发送（目标可省略）
prping engine --pcap x.pcap --to-pkt dir/  # pcap → 每记录一个 .pkt + .pktl 配方（--structured 语义化）
# Web 编辑器（子命令由 --features web 启用；前端默认随产物 UI/ 目录分发，--features web-embed 内嵌二进制）：
prping web --open               # 启动并自动打开浏览器（左栏文件管理：examples 可编辑保存/Ctrl+S、eng_lib 只读；CodeMirror + LSP + 实时层栈/HEX 预览）
```

### 选项（按子命令分组）

**通用（任意位置）**

| 选项 | 说明 |
|------|------|
| `-s ADDR\|IFACE` | 指定源地址/网卡 |
| `-4` / `-6` | 强制 IPv4/IPv6 |
| `--json` | 输出 JSON 统计 |
| `--lang en\|zh-CN` | 语言（任意位置） |
| `document [章节]` | 完整使用手册（`document 17` 跳转第 17 章） |

**ping**

| 选项 | 说明 |
|------|------|
| `-n N` / `-n 10s` | 次数（默认无限）或时长 |
| `-i S` | 间隔秒数（0=快速，下限 1ms） |
| `-l SIZE` | 请求大小，`k`/`m` 后缀 |
| `-H N` 或 `-H t1,t2,...` | 直方图桶数，或逗号分隔的毫秒阈值（如 `1,5,10,50`） |
| `-w N` | 预热次数（默认 4） |
| `-q` | 静默模式 |
| `-u` | UDP 模式 |
| `-p` | Unicode 渲染（直方图/时间线用 ploot） |
| `-g` | 显示时间线图（配合 `-p` 用 ploot 渲染） |
| `-m` / `--mtu` | 路径 MTU 探测（ICMP DF + 变长载荷二分） |

**latency**

| 选项 | 说明 |
|------|------|
| `-l SIZE` | 请求大小（缺省 64） |
| `-u` | UDP 模式 |
| `-r` | 接收模式（测下载） |
| `-p` | Unicode 渲染 |

**bandwidth**

| 选项 | 说明 |
|------|------|
| `-l SIZE` | 请求大小（缺省 8k） |
| `-u` | UDP 模式 |
| `-r` | 接收模式（测下载） |
| `--parallel N` | 并发连接数 |

**trace**

| 选项 | 说明 |
|------|------|
| `-m N` | 最大跳数 |
| `-d` | 免 DNS 解析 |
| `--udp` | 经典 UDP 逐跳（33434 起递增端口） |

> 带端口的 `trace HOST:PORT` 自动走 TCP SYN 逐跳（Windows 走 Npcap 注入，需安装
> Npcap、仅 IPv4）；无端口为 ICMP echo。

### hex/raw 为基 + 层 bytes 直喂

`hex`/`raw` 是唯一字节原语；`eth`/`ipv4`/... 层头函数基于 hex 字节模板 + 字节原语
构建（引擎自动补 checksum/length）。任何层还支持 **`bytes=hex("...")` 直喂**——
整层头字节完全由你指定（绕过语义字段与自动校验和），载荷仍可语义组合：

```
use(payload) |> ipv4(bytes=hex("4500001c0001000040010000...")) |> eth(bytes=hex("ffff..."))
```

### pkglang 标准库（eng_lib → 发布为 `lib/`）

packet-dsl 引擎内置只保留字节原语（`hex`/`raw` + `concat`/`be16`/`count`/`cksum`/... 与
`layer(kind, bytes)` 层标注原语）；层头自表示协议（`eth`/`arp`/`ipv4`/`ipv6`/`icmp`/`tcp`/`udp`/`http`/
`dns`，`#[proto]` 字段表双端驱动：构造编码 + 反解）与组合/数据组装函数统一放标准库
[eng_lib/](eng_lib/)（`headers.pkt`：层头 proto（可反解）；
`bytes.pkt`：`*_bytes` 层标注包装；`net.pkt`：net4/net6 一次生成 IP+Eth 层；`data.pkt`：
`eth_frame`/`ip4_packet`/`net4_packet`/`net6_packet` 把 raw/hex 字节载荷直接组装成包）。
`hex("...")` 也可在参数值位置使用（hex 字符串 → 字节列表）。

- 库搜索：import 先查入口文件目录递归，再从库目录兜底。**默认 eng_lib 自动加载**——
  路径在编译期烘焙（packet-dsl 的 `CARGO_MANIFEST_DIR/../eng_lib`），源码构建时指向
  仓库标准库；运行时 `is_dir()` 校验，不存在则返回空。显式库 = 默认「当前目录/lib」
  （发布时 `just publish` 把 eng_lib 复制为 `target/release/lib/`）+ `--lib PATH`
  （可多次，`engine`/`packet` 子命令），排在默认 eng_lib 之后（`effective_libs` 合并，
  `engine` 头部的 `libs: ...` 行即展示这一列表）。发布机上默认路径失效，由运行时
  `./lib` + `--lib` 顶替。
- **库导出隐式可见**：eng_lib 模块的 `export:` 无需 `import` 直接可用
  （如直接写 `net4(dst=...)`、`eth_frame(payload=hex("..."))`）；
  显式 `import` 仍支持，本地定义优先遮蔽。
- 示例：`prping engine examples/network_icmp_bare`（无扩展名自动定位到
  `examples/network_icmp_bare/network_icmp_bare.pktl`）。

### 包构造引擎（同一 binary 的 `engine` / `packet` 子命令）

packet-dsl（`.pkt` 网络包构建 DSL）是独立子项目；引擎侧 CLI（`engine` / `packet` /
LSP / pcap）集成在 prping 同一 binary 中（与测量模式互斥）。

> pkglang 的完整语法规范（词法 token + 语句/表达式 EBNF，含值表达式 `+` 加法优先级
> 与 `hex()`/`params()`/裸 ident 的二义性消解规则）见
> [packet-dsl/GRAMMAR.md](crates/packet-dsl/GRAMMAR.md)；设计文档为
> `crates/packet-dsl/DESIGN.md`，快速上手见 `crates/packet-dsl/README.md`。

- `prping engine FILE.pkt`：模块概览 + 逐包层栈（字段 + `auto` 标注）+ 字节 hexdump。
  文件参数不带扩展名时自动定位 pktl：先找 `<arg>.pktl`，再找同名文件夹里的
  `<arg>/<basename>.pktl`（examples 即按「每 pktl 一个文件夹」组织，
  `examples/<name>/<name>.pktl` + 其 .pkt）。
- `prping engine --lsp`：.pkt 语言服务器——诊断 / 补全 / 悬停 / 文档符号。
- `prping packet FILE.pkt [HOST:PORT]`：求值展开全部变体包并发送（默认提取 TCP/UDP
  载荷，`--raw` 原始套接字；`--wait` 应答匹配 + RTT，`--fuzz` 全字段随机，
  `--out` 写 pcap；`--ls`/`--hex`/`--pcap` 反解展示；`engine --pcap x.pcap --to-pkt dir/`
  把 pcap 逐条转成 `.pkt` + `.pktl` 配方（缺省无损字节级，`--structured` 语义结构化，
  `--skip/--limit` 选范围、`--threads` 并行解析；配方步骤 `delay:` 携带捕获帧间隔）。详见 [packet-dsl](crates/packet-dsl/)。
  list）——`global:` 段声明跨步骤共享变量，`recipe:` 段列出步骤；每步可 `wait:`
  （等回包）/ `delay:`（开始前等待，非首步）/ `params:` / `extract:`（回包反解取值写 global，如 `from:
  reply.dns.id`）/ `on_error: stop|continue`；`.pkt` 内用 `global("名"[, 默认])`
  值原语读取，`-g k=v`（`--global`）注入覆盖 init、`-p k=v`（`--params` 短选项）注入
  普通参数；`engine FILE.pktl` 展示概览。示例统一为 **mock server/client 形式**
  （服务端配方 server.pktl：`wait:` 无值监听 + extract + 触发发包；客户端配方
  client.pktl：发包 + `wait: N` + sniffer 校验 + extract——形态标杆见
  `examples/icmp_mock/`，完整清单见 `examples/README.md`）：
  `examples/icmp_mock/`（ICMP echo：seq+1000 配方标记排除内核替答）、
  `examples/http_mock/`（HTTP GET/POST → 200 OK，链路层监听）、
  `examples/dhcp_mock/`（DORA 四步：:67 监听 → Offer/Ack 单播回包）、
  `examples/tcp_data_mock/`（数据段 → 纯 ACK，ack=seq+len）、
  `examples/tcp_http_mock/`（三次握手 + HTTP GET，客户端 extract 动态 seq/ack）、
  `examples/arp_mock/`（who-has → is-at + gratuitous ARP）、
  `examples/udp_mock/`（同一服务端按端口分派 DNS 应答与 VNC 横幅）、
  `examples/dns_echo_listen/`（DNS 查询 → A 记录应答，客户端两步 extract 复用 tid）、
  `examples/dns_trigger/`、`examples/icmp_echo_server/`、
  `examples/tcp_handshake_listen/`、`examples/sniffer_chat/`（同构 server/client 变体）；
  机制/素材类保留原样：`network_icmp_bare/`（真实 ICMP echo，裸 IP 走内核路由——
  内核即应答方）、`wait_timeout/`（on_timeout）、`bad_network/`（重传/RST 时序）、
  `quic_initial/`（QUIC 构造）、`icmp_ping/`（真实目标 ping 配方）、`pcaps/`。
  运行如 `prping packet examples/dns_echo_listen/client.pktl 127.0.0.1:53`。

### 测量功能（万用表）

- **统计**：min/max/avg/stddev、**抖动 jitter（相邻 RTT 差均值/最大）**、P50/P95/P99、
  直方图（`-H`）、时间线（`-g/-p`）；`--json` 输出含 `jitter_ms`/`jitter_max_ms`。
- **路径 MTU**：`-m`（`--mtu`）用 ICMP DF + 变长载荷二分，报告最大不分片载荷与路径 MTU
  （IPv4；途中 Fragmentation Needed 报回的 MTU 一并展示）。
- **路由跟踪**：`-t`（`--traceroute`）ICMP echo + 递增 TTL 逐跳探测路径（每跳 3 次、
  反向 DNS、超时 `*`；`-m` 最大跳数默认 30、`-d` 跳过 DNS；目标回显即停止，
  未到达返回非零退出码；IPv4/IPv6）。**带端口自动启用 TCP SYN 变体**
  （`trace HOST:PORT`：每探测独立源端口按 (sport,dport) 匹配；目标回 SYN-ACK/RST
  即到达）——ICMP 被过滤时仍可用；Unix 走 raw socket，
  Windows 走 Npcap 注入（需安装 Npcap，仅 IPv4）。
  `trace --udp HOST` 用经典 **UDP** 变体（33434 起递增目标端口，内核构 UDP 头；
  目标回 ICMP Port Unreachable 即到达）——跨平台可用。
- **源绑定**：`-s ADDR|IFACE` 指定探测源地址（TCP/UDP/ICMP/延迟/带宽全模式；
  Linux 网卡名自动取 IPv4）。
- 用户函数 / net4 模块等 DSL 能力见 [packet-dsl](crates/packet-dsl/) 与 `eng_lib/net.pkt`。

## 使用手册

`prping document` 输出完整双语使用手册（[docs/manual-zh.md](docs/manual-zh.md) /
[docs/manual-en.md](docs/manual-en.md)，随 `--lang` 选择）：26 章覆盖全部模式/选项/
统计（含 jitter）/JSON/MTU/`-s`/退出码/FAQ/示例。长文在 tty 下经 `less` 自动分页，
文档头部有目录，`prping document <编号或标题>` 直接跳转章节学习。

## 设计文档

- [docs/design-web-editor.md](docs/design-web-editor.md) — `prping web` 内嵌 Web 编辑器
  （总体架构、WS 信封协议、LSP 桥、构建链、安全模型与路线图）

## 示例

```bash
# TCP ping，30 次，0.1s 间隔，直方图 + 时间线图（ploot 渲染）
prping ping -n 30 -i 0.1 -H 10 -gp 192.168.1.1:80

# 延迟测试（客户端发送 64B）
prping latency -l 64 -n 100 server:8080

# 接收模式延迟测试（客户端接收，测下载方向）
prping latency -l 64 -n 100 -r server:8080

# 带宽测试，8KB 包，4 并发
prping bandwidth -l 8k -n 10000 --parallel 4 server:8080

# 自定义阈值直方图（1/5/10/50ms 分档）
prping ping -n 100 -H "1,5,10,50" server:8080

# JSON 输出（脚本/监控）
prping ping -n 100 --json server:8080

# 服务端（Ctrl+C 退出时打印聚合统计）
prping server 0.0.0.0:8080
```

> 说明：测试出现丢包时进程以退出码 1 结束（可用于脚本判断）；
> 带宽/延迟并发场景可通过 `SMOL_THREADS=N` 环境变量启用多线程执行器（默认按 CPU 核数）。
> 服务端并发 TCP 连接上限 1024，超出直接拒绝；`-i` 下限 1ms 防误打网络。

## 输出示例

TCP ping + 统计 + 直方图：

```
$ prping ping -n 3 -w 0 127.0.0.1:22
TCP 连接到 127.0.0.1:22:
3 次迭代 (预热 0) ping 测试:
连接到 127.0.0.1:22: 从 127.0.0.1:55940: 0.32ms

  发送 = 3，接收 = 3，丢失 = 0 (0% 丢失),
  最小 = 0.12ms，最大 = 0.17ms，平均 = 0.15ms，标准差 = 0.02ms
  P50 = 0.15ms, P95 = 0.17ms, P99 = 0.17ms
```

加 `-g` 显示时间线图（`-gp` 用 ploot 渲染 Unicode 柱状/Braille 散点）：

```
$ prping ping -n 20 -i 0.1 -gp 127.0.0.1:22
...
延迟分布:（-p 时 ploot 柱状图）
Latency timeline:（-gp 时 ploot Braille 散点 + 图例）
```

`--json` 输出 JSONL（每行一条记录，实时可 tail -f；最后一行是汇总）：

```
$ prping ping -n 3 -w 0 --json 127.0.0.1:22
{"type":"tcp","target":"127.0.0.1:22","ts":1787031710,"seq":0,"ok":true,"rtt_ms":0.26}
{"type":"tcp","target":"127.0.0.1:22","ts":1787031711,"seq":1,"ok":true,"rtt_ms":0.31}
{"type":"tcp","target":"127.0.0.1:22","ts":1787031711,"seq":2,"ok":true,"rtt_ms":0.28}
{"type":"tcp","target":"127.0.0.1:22","ts":1787031712,"summary":true,"sent":3,"received":3,
 "lost":0,"loss_pct":0.0,"min_ms":0.12,"max_ms":0.17,"avg_ms":0.15,"stddev_ms":0.02,
 "p50_ms":0.15,"p95_ms":0.17,"p99_ms":0.17}
```

带宽：

```
$ prping bandwidth -l 8k -n 10000 --parallel 4 server:8080
TCP Bandwidth test:
  Sent = 81920000 bytes in 0.42s
  Bandwidth = 1566.49 Mbps
```

## 与 psping 对比

| 功能 | psping | prping | 说明 |
|------|--------|--------|------|
| ICMP ping | ✓ | ✓ | raw socket，需 root/cap_net_raw |
| TCP ping | ✓ | ✓ | |
| UDP ping | ✓ | ✓ | psping 无独立 UDP ping，prping 有 |
| 延迟测试 | ✓ | ✓ | TCP/UDP |
| 带宽测试 | ✓ | ✓ | TCP/UDP |
| 接收模式 `-r` | ✓ | ✓ | TCP：0xFF 触发；UDP：`[0xFF,0xFF,size,cnt]` 触发协议 |
| 直方图 | `-h` | `-H` | 桶数或自定义阈值（ms） |
| 0.01ms 精度 | ✓ | ✓ | |
| IPv4/IPv6 | ✓ | ✓ | |
| `-n 10s` 时长模式 | ✓ | ✓ | |
| Ctrl+C 优雅退出 | ✓ | ✓ | 首次停止并输出统计，再次强制退出 |
| JSON 输出 | ✗ | ✓ | prping 独有 |
| 退出码 | 部分 | ✓ | 有丢包时返回 1 |
| `-t` 持续 ping | ✓ | 默认 | prping 默认即无限 |
| 默认次数 | 4 | 无限 | |
| 预热默认 | ICMP/TCP=1, 延迟=5, 带宽=2×CPU | 全部=4 | |
| 并发 IO `-i`（带宽） | ✓ | `--parallel` | 参数名不同 |
| 防火墙 `-f` | ✓ | — | Windows only，跨平台不需要 |
| i18n | ✗ | ✓ | 中英文自动切换 |
| 时间线图 | ✗ | ✓ | prping 独有 |
| P50/P95/P99 | ✗ | ✓ | prping 独有 |
| 跨平台 | Windows | Linux/macOS/Windows | |
| 二进制体积 | ~500KB | ~1.9MB（debug 48MB） | |

## 技术栈

- [smol](https://github.com/smol-rs/smol) — 轻量异步运行时
- [bpaf](https://github.com/pacak/bpaf) — CLI 解析
- [rust-i18n](https://github.com/longfangsong/rust-i18n) — 国际化
- [termcolor](https://github.com/BurntSushi/termcolor) — 跨平台终端颜色
- [socket2](https://github.com/rust-lang/socket2) — raw socket
- libc — Unix Ctrl+C 信号处理
- [ploot](https://github.com/ploot-rs/ploot) — `-p` Unicode 终端绘图
- [pcap](https://github.com/rust-pcap/rust-pcap) — 包抓取（Npcap/libpcap，`packet --raw` 和 `--wait`）

## 开发

```bash
just test                  # 全部测试（476）
just lint                  # clippy 零警告
just fmt-check             # 格式检查
just bench                 # 本地回环基准（阈值断言）
just build-win7            # Windows 7 x64 兼容版
just build-win7-32         # Windows 7 x86（32 位）兼容版
just build-windows         # 全部 Windows 产物
```

> 各平台产物构建配方统一在 `justfile`（需安装 [just](https://github.com/casey/just)）；不用 just 时等价命令见上。

变更记录见 [CHANGELOG.md](CHANGELOG.md)。

## License

MIT