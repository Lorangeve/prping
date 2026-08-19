# prping

跨平台 psping 复刻，使用 Rust 实现。支持 ICMP ping、TCP ping、UDP ping、延迟测试和带宽测试。

## 特性

- **四种 ping 模式**：ICMP / TCP / UDP，自动识别（有端口=TCP，`-u`=UDP，无端口=ICMP）
- **次数或时长**：`-n 10` 固定次数，`-n 10s` 按秒运行
- **延迟测试**：client/server 架构，TCP/UDP 双模式，`-r` 接收模式测反向
- **带宽测试**：多连接并发（`-P`），直方图，`-r` 测下载方向
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
cargo build --release
sudo setcap cap_net_raw+ep target/release/prping  # ICMP 需要（Linux）
```

## Windows 7

Rust 1.78 起官方将 `*-pc-windows-*` 目标最低支持提升到 **Windows 10**；Win7 需用官方的
Win7 基线目标（Tier 3）构建，**MSVC 版为首选**：

```bash
rustup toolchain install nightly --profile minimal
rustup component add rust-src --toolchain nightly
cargo install cargo-xwin                        # 自动下载 Windows SDK
XWIN_ARCH=x86,x86_64 cargo +nightly xwin build -Z build-std --target x86_64-win7-windows-msvc --release
# → target/x86_64-win7-windows-msvc/release/prping.exe   （x64 版）
XWIN_ARCH=x86,x86_64 cargo +nightly xwin build -Z build-std --target i686-win7-windows-msvc --release
# → target/i686-win7-windows-msvc/release/prping.exe     （x86/32 位版）
```

> `XWIN_ARCH=x86,x86_64` 必须统一指定：cargo-xwin 默认只下载 x86_64+aarch64 库，
> 且其 DONE 标记只记录最近一次架构，不统一会导致换架构构建时反复重下载 SDK。

> MSVC 构建**静态链接 CRT 与 C++ 运行库**（`.cargo/config.toml` 的 `crt-static`）：
> 产物不依赖 `vcruntime140.dll`/`msvcp140.dll`/`ucrtbase.dll`，目标机器无需安装
> VC++ Redistributable。实测 Win7 目标产物仅依赖 `ADVAPI32`/`KERNEL32`/`ntdll`
> 三个 Win7 自带系统库。`x86_64-pc-windows-msvc`（普通 MSVC 目标）同样静态链接。
> 链接器已加 `/ignore:4099` 抑制 xwin 静态库缺 PDB 的无害噪音警告。

无 xwin 的环境（如 CI 用 mingw）可退而求其次构建 GNU 备选版（MSVCRT 链接）：

```bash
cargo +nightly build -Z build-std --target x86_64-win7-windows-gnu --release
```

> 说明：Win7 基线目标为 Tier 3（官方不自动构建测试）；GNU 备选版已验证主流程
> （TCP/UDP ping、接收模式）可用，MSVC 版由 CI `win7-build` job 产出。

## 用法

```
prping HOST                    # ICMP ping（无限，Ctrl+C 停止）
prping HOST:PORT               # TCP ping
prping -u HOST:PORT            # UDP ping
prping -l SIZE HOST:PORT       # 延迟测试（触发条件：-l + 端口）
prping -b -l SIZE HOST:PORT    # 带宽测试
prping -s ADDR:PORT            # 服务端（同时支持延迟/带宽/接收模式）
prping --mtu HOST              # 路径 MTU 探测（ICMP DF + 变长载荷二分）
prping -I 192.168.1.10 HOST    # 指定源地址/网卡（Linux 网卡名 → IPv4）
prping --help-pkg              # 完整使用手册（tty 自动分页）
prping --help-pkg 16           # 跳转手册第 16 章（MTU 探测）
# 包构造引擎（同一 binary，--eng/--pkg 与测量模式互斥）：
prping --eng FILE.pkt          # .pkt 分析（层栈 + hexdump）
prping --eng --lsp             # .pkt 语言服务器（JSON-RPC over stdio）
prping --pkg FILE.pkt [HOST:PORT]  # 构建并发送（目标可省略）
```

### 常用选项

| 选项 | 说明 |
|------|------|
| `-n N` / `-n 10s` | 次数（默认无限）或时长 |
| `-i S` | 间隔秒数（0=快速，下限 1ms） |
| `-l SIZE` | 请求大小，`k`/`m` 后缀 |
| `-H N` 或 `-H t1,t2,...` | 直方图桶数，或逗号分隔的毫秒阈值（如 `1,5,10,50`） |
| `-w N` | 预热次数（默认 4） |
| `-q` | 静默模式 |
| `-r` | 接收模式（测下载） |
| `-u` | UDP 模式 |
| `-P N` | 并发连接数 |
| `-p` | Unicode 渲染（直方图/时间线用 ploot） |
| `-g` | 显示时间线图（配合 `-p` 用 ploot 渲染） |
| `-4` / `-6` | 强制 IPv4/IPv6 |
| `--json` | 输出 JSON 统计 |
| `-V` / `--version` | 版本号 |
| `--lang en\|zh-CN` | 语言 |
| `--help-icmp` 等 | 各模式详细帮助 |
| `-I ADDR\|IFACE` | 指定源地址/网卡（Linux 网卡名取 IPv4；多网卡/策略路由场景） |
| `-M, --mtu` | 路径 MTU 探测：ICMP DF + 变长载荷二分（仅 IPv4，raw socket） |
| `--help-pkg [章节]` | 完整使用手册（tty 自动分页，`## N. 标题` 章节）；`--help-pkg 编号\|标题` 跳转章节（双语随 `--lang`） |

### hex/raw 为基 + 层 bytes 直喂

`hex`/`raw` 是唯一字节原语；`eth`/`ipv4`/... 层头函数基于 hex 字节模板 + 字节原语
构建（引擎自动补 checksum/length）。任何层还支持 **`bytes=hex("...")` 直喂**——
整层头字节完全由你指定（绕过语义字段与自动校验和），载荷仍可语义组合：

```
use(payload) |> ipv4(bytes=hex("4500001c0001000040010000...")) |> eth(bytes=hex("ffff..."))
```

### pkglang 标准库（eng_lib → 发布为 `lib/`）

packet-dsl 引擎内置只保留字节原语（`hex`/`raw` + `concat`/`be16`/`cksum`/`ip4`/... 与
`layer(kind, bytes)` 层标注原语）；层头函数（`eth`/`arp`/`ipv4`/`ipv6`/`icmp`/`tcp`/`udp`/`http`/
`dns`）与组合/数据组装函数统一放标准库 [eng_lib/](eng_lib/)（`headers.pkt`：层头函数；
`bytes.pkt`：`*_bytes` 层标注包装；`net.pkt`：net4/net6 一次生成 IP+Eth 层；`data.pkt`：
`eth_frame`/`ip4_packet`/`net4_packet`/`net6_packet` 把 raw/hex 字节载荷直接组装成包）。
`hex("...")` 也可在参数值位置使用（hex 字符串 → 字节列表）。

- 库搜索：import 先查入口文件目录递归，再从库目录兜底。**默认 eng_lib 自动加载**——
  路径在编译期烘焙（packet-dsl 的 `CARGO_MANIFEST_DIR/../eng_lib`），源码构建时指向
  仓库标准库；运行时 `is_dir()` 校验，不存在则返回空。显式库 = 默认「当前目录/lib」
  （发布时 `just publish` 把 eng_lib 复制为 `target/release/lib/`）+ `--lib PATH`
  （可多次，需 `--eng` 或 `--pkg`），排在默认 eng_lib 之后（`effective_libs` 合并，
  `--eng` 头部的 `libs: ...` 行即展示这一列表）。发布机上默认路径失效，由运行时
  `./lib` + `--lib` 顶替。
- **库导出隐式可见**：eng_lib 模块的 `export:` 无需 `import` 直接可用
  （如直接写 `net4(dst=...)`、`eth_frame(payload=hex("..."))`）；
  显式 `import` 仍支持，本地定义优先遮蔽。
- 示例：`prping --eng examples/data_demo.pkt`。

### 包构造引擎（同一 binary 的 `--eng` / `--pkg` 模式）

packet-dsl（`.pkt` 网络包构建 DSL）是独立子项目；引擎侧 CLI（`--eng` / `--pkg` /
LSP / pcap）集成在 prping 同一 binary 中（与测量模式互斥）：

- `prping --eng FILE.pkt`：模块概览 + 逐包层栈（字段 + `auto` 标注）+ 字节 hexdump。
- `prping --eng --lsp`：.pkt 语言服务器——诊断 / 补全 / 悬停 / 文档符号。
- `prping --pkg FILE.pkt [HOST:PORT]`：求值展开全部变体包并发送（默认提取 TCP/UDP
  载荷，`--raw` 原始套接字；`--wait` 应答匹配 + RTT，`--fuzz` 全字段随机，
  `--out` 写 pcap；`--ls`/`--hex`/`--pcap` 反解展示）。详见 [packet-dsl](packet-dsl/)。

### 测量功能（万用表）

- **统计**：min/max/avg/stddev、**抖动 jitter（相邻 RTT 差均值/最大）**、P50/P95/P99、
  直方图（`-H`）、时间线（`-g/-p`）；`--json` 输出含 `jitter_ms`/`jitter_max_ms`。
- **路径 MTU**：`-M`（`--mtu`）用 ICMP DF + 变长载荷二分，报告最大不分片载荷与路径 MTU
  （IPv4；途中 Fragmentation Needed 报回的 MTU 一并展示）。
- **源绑定**：`-I ADDR|IFACE` 指定探测源地址（TCP/UDP/ICMP/延迟/带宽全模式；
  Linux 网卡名自动取 IPv4）。
- 用户函数 / net4 模块等 DSL 能力见 [packet-dsl](packet-dsl/) 与 `examples/net.pkt`。

## 使用手册

`prping --help-pkg` 输出完整双语使用手册（[docs/manual-zh.md](docs/manual-zh.md) /
[docs/manual-en.md](docs/manual-en.md)，随 `--lang` 选择）：25 章覆盖全部模式/选项/
统计（含 jitter）/JSON/MTU/`-I`/退出码/FAQ/示例。长文在 tty 下经 `less` 自动分页，
文档头部有目录，`prping --help-pkg <编号或标题>` 直接跳转章节学习。

## 示例

```bash
# TCP ping，30 次，0.1s 间隔，直方图 + 时间线图（ploot 渲染）
prping -n 30 -i 0.1 -H 10 -gp 192.168.1.1:80

# 延迟测试（客户端发送 64B）
prping -l 64 -n 100 server:8080

# 接收模式延迟测试（客户端接收，测下载方向）
prping -l 64 -n 100 -r server:8080

# 带宽测试，8KB 包，4 并发
prping -b -l 8k -n 10000 -P 4 server:8080

# 自定义阈值直方图（1/5/10/50ms 分档）
prping -n 100 -H "1,5,10,50" server:8080

# JSON 输出（脚本/监控）
prping -n 100 --json server:8080

# 服务端（Ctrl+C 退出时打印聚合统计）
prping -s 0.0.0.0:8080
```

> 说明：测试出现丢包时进程以退出码 1 结束（可用于脚本判断）；
> 带宽/延迟并发场景可通过 `SMOL_THREADS=N` 环境变量启用多线程执行器（默认按 CPU 核数）。
> 服务端并发 TCP 连接上限 1024，超出直接拒绝；`-i` 下限 1ms 防误打网络。

## 输出示例

TCP ping + 统计 + 直方图：

```
$ prping -n 3 -w 0 127.0.0.1:22
TCP 连接到 127.0.0.1:22:
3 次迭代 (预热 0) ping 测试:
连接到 127.0.0.1:22: 从 127.0.0.1:55940: 0.32ms

  发送 = 3，接收 = 3，丢失 = 0 (0% 丢失),
  最小 = 0.12ms，最大 = 0.17ms，平均 = 0.15ms，标准差 = 0.02ms
  P50 = 0.15ms, P95 = 0.17ms, P99 = 0.17ms
```

加 `-g` 显示时间线图（`-gp` 用 ploot 渲染 Unicode 柱状/Braille 散点）：

```
$ prping -n 20 -i 0.1 -gp 127.0.0.1:22
...
延迟分布:（-p 时 ploot 柱状图）
Latency timeline:（-gp 时 ploot Braille 散点 + 图例）
```

`--json` 输出 JSONL（每行一条记录，实时可 tail -f；最后一行是汇总）：

```
$ prping -n 3 -w 0 --json 127.0.0.1:22
{"type":"tcp","target":"127.0.0.1:22","ts":1787031710,"seq":0,"ok":true,"rtt_ms":0.26}
{"type":"tcp","target":"127.0.0.1:22","ts":1787031711,"seq":1,"ok":true,"rtt_ms":0.31}
{"type":"tcp","target":"127.0.0.1:22","ts":1787031711,"seq":2,"ok":true,"rtt_ms":0.28}
{"type":"tcp","target":"127.0.0.1:22","ts":1787031712,"summary":true,"sent":3,"received":3,
 "lost":0,"loss_pct":0.0,"min_ms":0.12,"max_ms":0.17,"avg_ms":0.15,"stddev_ms":0.02,
 "p50_ms":0.15,"p95_ms":0.17,"p99_ms":0.17}
```

带宽：

```
$ prping -b -l 8k -n 10000 -P 4 server:8080
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
| 并发 IO `-i`（带宽） | ✓ | `-P` | 参数名不同 |
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

## 开发

```bash
just test                  # 全部测试（67）
just lint                  # clippy 零警告
just fmt-check             # 格式检查
just bench                 # 本地回环基准（阈值断言）
just build-win7            # Windows 7 x64 兼容版
just build-win7-32         # Windows 7 x86（32 位）兼容版
just build-windows         # 全部 Windows 产物
```

> 各平台产物构建配方统一在 `justfile`（需安装 [just](https://github.com/casey/just)）；不用 just 时等价命令见上。

贡献指南见 [CONTRIBUTING.md](CONTRIBUTING.md)，变更记录见 [CHANGELOG.md](CHANGELOG.md)。

## License

MIT
