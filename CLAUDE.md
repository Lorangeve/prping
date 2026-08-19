# prping

跨平台 psping 复刻，使用 Rust 实现。

## 技术选型

- **异步运行时**: [smol](https://github.com/smol-rs/smol) — 轻量级，组件化
- **ICMP**: 手写 raw socket (socket2) + smol::Async，无第三方 ICMP 依赖
- **CLI**: [bpaf](https://github.com/pacak/bpaf) — 轻量级，编译快
- **错误处理**: lib 层用 thiserror（`PrpingError` 分派层枚举 + IO/anyhow 透传），bin 层用 anyhow 做胶水
- **代码结构**: 单 crate 双 target — `src/lib.rs`（协议/统一入口 `run`/`serve`，公开面最小化）+ `src/main.rs`（CLI 解析/渲染/退出码/信号安装）+ `src/{util,drive,stats,output,icmp,tcp,udp,latency,bandwidth}.rs`（lib 内部）
- **终端颜色**: [termcolor](https://github.com/BurntSushi/termcolor)，颜色函数统一在 `output.rs`（客户端与服务端一致）
- **直方图**: 默认 ASCII `#`（内置）；`-p`/`--pretty` 用 [ploot](https://github.com/ploot-rs/ploot) 渲染 Unicode 柱状图与 Braille 散点时间线（非 tty 自动剥离 ANSI 颜色）；`-H` 支持桶数或逗号分隔阈值（ms）
- **i18n**: [rust-i18n](https://github.com/longfangsong/rust-i18n) — `locales/en-US.yml` + `locales/zh-CN.yml`，自动检测 `$LANG` 或 `--lang`
- **信号处理**: Ctrl+C 优雅退出 — Unix 用 `libc::signal`，Windows 用 `kernel32::SetConsoleCtrlHandler`（首次停止并输出统计，再次强制退出）；`--json` 模式在 Unix 上运行期间关闭 stdin tty 的 `ECHOCTL` 以隐藏终端回显的 `^C`（`^C` 是终端回显、从不进入 stdout 管道；退出时恢复）
- **Windows 7**: 官方 Win7 基线目标（Tier 3）+ nightly `-Z build-std`；首选 `x86_64-win7-windows-msvc`（x64）与 `i686-win7-windows-msvc`（x86/32 位）双产物（xwin 链接），GNU 版 `x86_64-win7-windows-gnu`（MSVCRT）为无 xwin 备选。MSVC 目标统一静态链接 CRT/C++ 运行库（`.cargo/config.toml` 配 `crt-static`）：产物不依赖 `vcruntime140.dll`/`msvcp140.dll`/`ucrtbase.dll`，Win7 实测仅依赖 `ADVAPI32`/`KERNEL32`/`ntdll`；链接器加 `/ignore:4099` 抑制 xwin 静态库缺 PDB 的 LNK4099 噪音（链接本身成功）。所有 xwin 配方必须统一 `XWIN_ARCH=x86,x86_64`（cargo-xwin 默认只下载 x86_64+aarch64 库、DONE 标记只记最近一次架构，不统一会反复重下载）
- **DNS 解析**: `smol::unblock` + `std::net::ToSocketAddrs`，统一在 `util.rs`（`resolve_vec` 返回全部、`resolve` 取首个；解析横幅统一 `util::print_resolving`）
- **ping 循环驱动器**: icmp/tcp/udp/latency 共用 `drive.rs::drive`（间隔/预热/统计/JSONL/收尾），各模式实现 `Probe` trait 只做「一次探测」与人读行
- **次数/时长**: `-n 10` 固定次数，`-n 10s` 按秒运行（`util::Run` 统一控制循环）
- **带宽测试并发**: 多连接 `-P`，smol::Task 池 + 全局配额（总量精确等于 count）
- **多线程**: `util::configure_executor_threads` 按 CPU 核数设置 `SMOL_THREADS`（smol 全局 executor 默认单线程）
- **UDP**: socket2 大收发缓冲（4MB）+ smol::Async 包装（`util::bind_udp`），避免突发丢包；客户端打印头部提示（目标/负载/迭代数）与回显要求说明（目标需 `prping -s` 回显才回包）
- **UDP 接收模式**: 触发包协议 `[0xFF, 0xFF, size(2B), count(4B)]`，服务端回送 count 个 size 字节数据报；服务端 UDP 回显字节计入聚合统计、触发包打印即时接收日志（不逐包打印）
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
prping -g HOST:PORT        TCP ping + 时间线图（-gp 用 ploot 渲染）
prping -M HOST             MTU 探测（ICMP DF + 变长载荷二分）
prping -I ADDR|IFACE HOST  指定源地址/网卡
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
11. 带宽测试实时进度条（`-b`）——`\r` 同行动态刷新；时长模式按时间、次数模式按包（每 5% 里程碑 + 100ms 限频）；仅 tty 显示，管道/`--json`/`-q` 静默（`bandwidth.rs::Progress`）
12. 抖动 jitter — 相邻 RTT 差均值/最大（文本 + `--json` 的 `jitter_ms`/`jitter_max_ms`）
13. 路径 MTU 探测 — `-M`/`--mtu`（ICMP DF + 变长载荷二分，解析 Fragmentation Needed）
14. 源绑定 — `-I ADDR|IFACE`（全模式；Linux 网卡名 → IPv4）

## 编码约定

- Rust edition 2024
- `cargo clippy` 零警告，`cargo fmt` 通过，`cargo test --all-targets` 全通过（单元 40 + 协议 15 + CLI 12 = 67 tests）
- 用户可见输出英文，注释中文
- 颜色由 `output.rs` 统一管理（客户端与服务端一致，服务端连接日志用 `output::print_server_log`）；bin 侧错误用红色、警告用橙色（lib re-export `output::{stderr, writeln_red, writeln_orange}` 给 bin 用）
- 互斥/非法参数校验：`main.rs::validate` 管 CLI 级冲突（`-s` 与目标或客户端参数、`--json` 与 `-p`/`-g`/`-H`、无 `-b`/`-l` 时 `-r`），lib `run` 管 config 级不变式（`-4`/`-6` 冲突、UDP/带宽缺端口、`-P` 非带宽警告、`-i` clamp）；非法 `-H`（如 `-H abc`）与非法 `-n` 一样在 bin 红色报错退出码 1（`-i`/`-w`/`-P` 用 Option 记录是否显式给出）
- 共享逻辑（DNS 解析、运行循环、直方图桶计算、UDP socket、测试参数 `PingConfig`）收敛一处，不重复实现：直方图数据与渲染解耦（`stats::Histogram::from_times`），带宽报告用 `ReportArgs` 结构传参
- lib 公开面最小化：只 re-export `run`/`serve`/`PingConfig`/`Stats`/报告/错误/警告/`output::{stderr, writeln_red, writeln_orange}`，其余 `pub(crate)`
- 不引入不必要的抽象
- 构建: `build.rs` 自动配置 `.cargo/run-with-cap.sh` runner 设置 cap_net_raw；各平台产物配方在 `justfile`（`just build-release` / `build-win7` / `build-win7-32` / `build-windows` / `test` / `lint` 等）
- CI: `.github/workflows/ci.yml` — fmt/clippy/doc/全部测试 × Linux/macOS/Windows + 非门禁基准 job
- 跨平台编译检查: `cargo check --target x86_64-pc-windows-msvc`（Windows 路径需本机验证时用临时 CARGO_HOME）

## 版本控制

使用 [jujutsu](https://github.com/jj-vcs/jj) (jj) 进行版本控制。

## packet-dsl（workspace 子 crate）

- 独立 crate `packet-dsl/`（.pkt 网络包构建 DSL，解析 + 语义 → 结构化 IR，宿主序列化/发送）。
  设计文档：`packet-dsl/DESIGN.md`；用法：`packet-dsl/README.md`。
- 技术：chumsky 1.0.0-alpha.8（token 流解析，span 用 `SimpleState<Vec<Token>>` 位置表换算行/列）、
  serde（IR 跨进程）、thiserror（序列化错误）。DSL 本身不发包。
- 管道语义：`|>` 包裹一层（内 → 外嵌套）；`use(a, b)` 多载荷各自成包、包组逐包包裹；
  多包用多条流水线 + `export:` 具名导出（`||>` 或分支已移除）；顶层匿名流水线 = 默认导出
  （以模块名被 `import`）。`call` 容忍无参裸调用（`tcp` == `tcp()`）。
- chumsky 1.0.0-alpha.8 两个已知坑：`(A, B)` 元组 + `map_with` 有类型推断缺陷（一律用显式
  `.then()` 链）；`repeated()`/`separated_by()` 输出 `()`（必须 `.collect()`）。`select!` 闭包
  在早期绑定生命周期下会让 `impl Parser` 推断失败（用 `filter` + `map_with` 替代）。
- 求值：层位变体笛卡尔积（外层层位变化在外、内层在内）；包组逐包包裹；组件循环检测（求值栈）。
- 序列化：`DefaultSerializer`（seed 可注入，测试确定性）；自动值 = 随机端口/id、TTL 64、
  广播 dst、自动 checksum/length/ethertype；无外层 IP 时 TCP/UDP 伪头部用零地址。
- 随机字段：IR 的 `Field::{Auto, Random, Value}` 保留（fuzz/`layer(..., src="random")`
  伪头部辅助字段）；`"random"` 关键字已随内置层函数移出 DSL——随机值用 `rand16()`/
  `rand8()` 构建期原语（`sport=rand16()`）。`serialize` 前 `resolve_random` 预解析
  （一次消费 RNG，保证传输层伪头部与 IP 头随机地址一致）。
- 用户函数（func）：`func name(p1, p2=默认, ...) { pipeline }`——具名参数化函数，把组合
  逻辑（原内置 `net4`/`net6`，现迁移为 `eng_lib/net.pkt` 模块，库导出隐式可见）下沉到
  pkglang。参数全部可选：无默认值 = 未设（层参数位置省略 → 自动值）；函数体无 `use` 时以
  空包种子逐层包裹（层片段语义，可直接出现在 `|>`）；实参按调用处环境解析后绑定（防跨层
  Ident 循环）；标识符值 `Value::Ident` 只能出现在函数体内且必须是已声明参数。求值入口
  `eval.rs::EvalCtx` 维护 `env_stack`（函数参数环境栈）。
- 质量门禁（workspace 级）：`just test` / `just lint` / `just fmt-check` 已覆盖 packet-dsl。

## 包构造引擎（--eng / --pkg，同一 binary）

引擎侧（`--eng`/`--pkg`/LSP/pcap）集成在 prping 同一 binary 中（与测量模式互斥），
共享 packet-dsl crate；不再有独立 prping-pkt binary。

- `prping --eng FILE.pkt`：模块概览 + 逐包层栈（字段 + `auto` 标注）+ 字节 hexdump
  （`src/eng.rs`）；`--eng --lsp`：.pkt LSP 服务器
  （JSON-RPC over stdio，`run_lsp_on` 可测；诊断/补全/悬停/documentSymbol）。
- `prping --pkg FILE.pkt HOST:PORT`：构建并一次性发送全部变体包（`src/pkg.rs`）。
  默认提取最外层 TCP/UDP 的应用层载荷经普通 socket 发送并读回显；`--raw` 原始发送
  完整序列化字节，按平台分派：Linux：eth → AF_PACKET + if_nametoindex（注意 CString
  结尾 NUL）、ipv4 → IPPROTO_RAW + IP_HDRINCL、ipv6 → IPV6_HDRINCL；
  Windows：Npcap 链路层注入（`src/rawwin.rs` 兼容层，`send_raw_bytes` 在
  `#[cfg(windows)]` 下整体委托 `rawwin::send_raw_full`）——设备选择（`--iface` 匹配
  Npcap 设备名/描述；回环目标自动选 Npcap Loopback Adapter）、裸 IPv4 自动以太网
  封装（src MAC = GetIfEntry 接口 MAC；dst MAC = GetBestRoute 下一跳 + GetIpNetTable
  ARP 缓存，未命中先发 1 字节 UDP 触发 ARP，再失败广播兜底警告）、裸 IPv6 仅回环
  （非回环需 ND 邻居解析，Win7 无 GetIpNetTable2，报错）、`--wait` 先开抓包句柄再
  发送（避免漏抓快速回包）并按方向过滤自己刚发的帧。绑定：pcap crate 2.x 仅
  `[target.'cfg(windows)'.dependencies]`；链接需 Npcap SDK 的 wpcap.lib
  （`just fetch-npcap-sdk` + 配方内置 LIBPCAP_LIBDIR）；运行时目标机装 Npcap
  （Win7 需 KB4474419 + KB4490628，SHA-2 驱动签名）。回包匹配（sniffer / ICMP echo
  id+seq）抽为 `pkg.rs::match_reply`，Linux raw ICMP 与 Windows Npcap 捕获共用；
  非 ICMP 且无 sniffer 时不等待（两平台一致）。逐包容错：失败红字提示、最后汇总退出码。
  **raw 源地址自动填充**：IP 层 src=0.0.0.0/::（DSL 未指定）时，发送前用
  UDP-connect 路由探测的本地地址填进字节并重算 IPv4 header checksum
  （`pkg.rs::patch_zero_src`，AF_PACKET 原始帧内核不会替我们填，回包要靠它路由回来）；
  显式 src 不覆盖。**域名即地址**：`dns("host")` 值原语（v4 优先）与
  `ip4`/`ip6`/地址字段（src/dst/spa/tpa...）直接接受域名（按族取首个），
  如 `dst=params("dst", "www.baidu.com")` 或 `--params dst=www.baidu.com`——
  解析经 `packet_dsl::set_dns_resolver` 注入（prping 入口 `ensure_dns_resolver`）。
  域名来源记录在 IR（Ipv4Fields/Ipv6Fields 的 src_host/dst_host），`--eng` 展示
  `dst=dns(www.baidu.com->198.18.0.5)`（字面量 IP 不标注）。
  代理诊断：目标或填充的 src 落在 198.18.0.0/15（Clash 等 fake-ip 段）时黄色警告——
  eth 原始帧绕过代理直发不可达，提示用 `examples/network_icmp_bare.pkt`
  （无 eth 层，IPPROTO_RAW 走内核路由/代理 TUN，源地址内核按路由填，代理环境可用）。
- scapy 衍生特性（A 解剖 / B 应答 / C pcap / D ls / E fuzz）：
  - **解剖**：packet-dsl `dissect(bytes) -> DissectReport`（`packet-dsl/src/dissect.rs`）——
    双路径（eth vs bare-IP）取更深解析，bare-app 兜底（DNS/HTTP 载荷），DNS 压缩指针，
    IPv4/ICMP 校验和错进 `notes` 不报错；`dns_message_id(bytes)` 供应答匹配。渲染在
    `eng.rs::render_dissected`；CLI：`--eng --hex` / `--eng --pcap` / `--pkg --wait` 应答解剖。
  - **应答 + RTT（--wait）**：`pkg.rs::send_payload`/`raw_reply_for`——DNS 只收 id 匹配
    应答（`dns_message_id`，跳过杂包），TCP 首字节时间，Linux raw ICMP 匹配 echo id+seq；
    UDP 回读有 1s、TCP 有 2s 超时（无 wait 分支同样要有默认超时，否则测试挂起）。
  - **sniffer 段（.pkt 回包校验）**：`sniffer:` + `- match icmp(type=0, id=id, seq=seq)`
    列表（与 `export:` 同风格，多子句 = 任一命中）——`--wait` 时按声明匹配应答
    （`pkg.rs::SnifferMatcher`：回包反解层字段 == 字面量常量或发包同层同名字段
    `SentField`；匹配成功 `✓ reply matched: k=v ... (rtt)`，超时 `✗ no matching reply`）；
    替代默认 DNS/ICMP 硬编码匹配。字段名与 `--eng` 展示一致
    （`sport`/`dport`/`type` 为 IR 字段 `src_port`/`dst_port`/`icmp_type` 别名；
    每层支持字段静态校验，字面量按字段类型强转，`sniffer_match` 为公开测试/宿主 API；
    仅配合 `--wait`，TCP 回显无独立字节故不适用）。
  - **pcap**：`src/pcap.rs` 手写格式（magic 0xa1b2c3d4 LE/BE + nano 变体；24B 全局 + 16B
    记录头；`LinkType{Ethernet=1, Raw=101}`）。`--pkg --out` 写入、`--eng --pcap` 读取。
  - **--ls**：`eng.rs::ls_builtins` 内置原语 + 库函数字段表——与内置同构的展示
    （函数上方紧贴的 `#` doc 注释：摘要行 + `@param 名: 说明` 逐参数 + `@auto: 说明`，
    解析为 `FuncDoc`（ast.rs），见 `FuncStmt.doc`/`Func.doc`/`LibExport.doc`；
    `--ls` 展示时摘要以 `"""..."""` 文档字符串置于签名下第一行）；
    **--hex**：`decode_hex` 十六进制转字节。
  - **--fuzz**：`DefaultSerializer::new_fuzz`（`with_seed_fuzz` 测试确定性）——Auto 视作
    Random（MAC/地址/TTL/端口/id/flags），协议类型/length/校验和保持自动保证栈合法。
- packet-dsl 增量 API：`parse_source_at`（编辑器未落盘文件的 import 根解析）、
  `resolve_sources`（按 默认导出/命名导出 归因）、`builtin_docs`（LSP 悬停/补全文档，
  含 raw/hex 与 `layer`）、`lib_exports`（库模块命名导出枚举——LSP 补全/悬停提供
  eng_lib 层头函数签名，本地定义优先遮蔽）。
- 引擎 CLI 冲突校验在 `src/main.rs`（`validate_engine`）：`--eng`/`--pkg` 互斥、
  `--raw`/`--iface`/`--params`/`--wait`/`--fuzz`/`--out` 需 `--pkg`、`--lsp` 需 `--eng`、
  `--ls`/`--hex`/`--pcap` 互斥且需 `--eng`、`-I` 与引擎模式互斥。i18n 键与测量侧共用
  `locales/`（引擎键并入同一 yml）。

## hex/raw 为基 + 层 bytes 直喂

- **hex/raw 是唯一字节原语**：eth/ipv4/... 层头函数（eng_lib/headers.pkt）基于
  hex 字节模板 + 字节原语拼出（引擎只算字段编码之外的自动 checksum/length/伪头部）。
- **层 bytes= 直喂**：任何层（eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns）支持
  `bytes=hex("...")`（值位置 hex → 字节列表）——该层序列化时整层头直接用给定字节
  （绕过语义字段与自动校验和/length，调用方全权负责）；载荷仍可语义组合：
  `use(payload) |> ipv4(bytes=hex("4500...")) |> eth(bytes=hex("ffff..."))`。
- 实现：IR 各 Fields 加 `#[serde(default)] pub raw: Option<Vec<u8>>`；引擎层标注原语
  `layer(kind, bytes[, src, dst])` 取头字节（复用 hex 值位置）；serialize 各层开头
  raw 分支（头字节 + payload）；eng `layer_raw`/describe 显示 `bytes=0x…`。
- dissect：bytes 直喂的层反解回语义字段（roundtrip 不保真，不报错）。

## 值函数 / 字节原语 / reduce（hex/raw 之上的构建体系）

- **值函数**：`func name(args) -> bytes { 值表达式 }`——函数体是值表达式（返回字节列表），
  与层函数（体是流水线）以 `-> bytes` 标注区分。
- **字节原语**（值位置，引擎实现；DSL 无字节运算，这些是 hex/raw 之上"一步"）：
  `concat` / `u8` / `be16` / `be32` / `ip4` / `ip6` / `mac` / `bytes` / `cksum` / `len` /
  `count` / `rand16` / `rand8` / `dns_name` / `dns`。`mac`/`ip4`/`ip6` 接受**字节列表直通**
  （长度符合即原样返回，如 `mac(rand_mac())` 随机 MAC；字符串仍按类型解析）。
  **域名解析**：`dns("host")` 值原语返回 v4 优先 IP 字符串；`ip4`/`ip6` 与地址字段
  （src/dst/spa/tpa...）接受域名回退（按族取首个）。解析经宿主注入的
  `packet_dsl::set_dns_resolver`（prping 在 analyze_file/send_packets 入口
  `ensure_dns_resolver` 注入 ToSocketAddrs 默认解析器）；packet-dsl 本身不发网络请求，
  无解析器时域名报错。默认值也可写域名：`dst=params("dst", "www.baidu.com")`。
- **reduce**：`reduce(列表, 初始字节, 函数名)`——具名值函数引用（回调 `func f(acc, item) -> bytes`），
  无 lambda 语法；http headers / dns questions 等可变长列表逐项折叠。
- **值表达式**：字面量 / 参数引用 / params() / 值调用（原语或值函数）/ `+` 数字加法（Hex 兼容）。
  层调用参数里出现值表达式时 `eval_call` 先 `eval_value`（顶层 Ident 保留给 registry 的省略语义）。
- **`layer` 层标注原语**：`layer(kind, bytes[, src, dst])`——字节 + 层类型字面量 → 该层；
  `src`/`dst` 仅 ipv4/ipv6（供传输层伪头部校验和）。eng_lib/bytes.pkt 为每种层提供
  具名包装（`eth_bytes`/`ipv4_bytes`/...，即 `func eth_bytes(bytes) { layer("eth", bytes) }`）。
  序列化时按层类型自动补 total_length/header checksum/ICMP·TCP·UDP checksum
  （依赖载荷长度/伪头部，函数内无法算）。
- **eng_lib/headers.pkt**：由 hex/raw + 原语定义 `eth`/`arp`/`ipv4`/`ipv6`/`icmp`/`tcp`/`udp`/
  `http`/`dns` 层函数（引擎已无同名内置，库导出即唯一来源；eval_call 作用域优先）；
  层函数内部经 bytes.pkt 的 `*_bytes` 包装调用 `layer`。字节与旧内置版完全一致
  （golden 对比测试 `eng_lib_headers_match_builtin_bytes`）。

## pkglang 标准库（eng_lib / lib/）与库搜索

- 引擎内置只留字节原语（hex/raw + `layer` 层标注）；层头函数（headers.pkt）与组合/
  数据组装函数放 `eng_lib/`（`headers.pkt`：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns；
  `bytes.pkt`：`*_bytes` 层标注包装；`net.pkt`：net4/net6；`data.pkt`：
  eth_frame/ip4_packet/net4_packet/net6_packet——raw/hex 载荷 → IP/Eth 层）。
  `just publish` 把 eng_lib 复制为 `target/release/lib/`（与二进制同目录分发）。
- 库搜索：`packet-dsl` 的 `find_module(dir, libs, name)`——入口目录（直接+递归）优先，
  库目录**从后往前**逐个搜索（显式 lib 优先于默认 eng_lib）；公共 API
  `parse_file_with_libs` / `parse_source_at_with_libs`。
- **import 按模块解析**：同名文件在不同目录可共存，每个 import 绑定到**自身模块目录**
  找到的模块实例（`ModuleGraph.module_imports` 存每模块 import 边，无全局名字表）——
  入口目录的本地文件（如自己的 headers.pkt）遮蔽库同名模块；结果不依赖 import 顺序。
- **import 别名**：`import a { x as ax }`——`ax` 以别名进入作用域，解析目标仍是 `x`
  （`ScopeEntry::Imported(module, orig)` 携带原名，`lookup`/`resolve_final` 用原名定位），
  同名导出冲突可消解；`as` 非保留字。`--eng` 的 `imports:` 行显示 `x as ax`。
- **库导出隐式可见**：libs 下所有模块的命名导出（export:）自动进入每个模块作用域，
  脚本无需 `import` 直接调用（prelude 语义）。实现：`build_graph` 先把库模块
  （`ModuleData.is_lib`）入图（先入队库种子、最后入队入口，保证入口下标 0）、
  `resolve_names` 最后注入库导出（已占用名不覆盖）——显式 import / 本地定义优先遮蔽。
  **prelude 转出口**：`export: tcp`（tcp 来自 prelude）可再被 `import b { tcp }` 引入——
  作用域查不到时 `find_lib_export` 回退到库模块集合（须「导出且本地定义」才可作求值目标）。
  **库目录诊断**：库目录不可读 / 库模块语法错 / 同一库目录内导出名重复 → 报错（带文件+span）；
  跨目录同名导出允许（显式 lib 覆盖标准库）。
- prping `--lib PATH`（可多次，需 --eng/--pkg）：`resolve_libs` = 默认「当前目录/lib」
  （存在时）+ --lib 追加；analyze_file/send_packets/LSP（LspServer.libs）全链路携带。
- 值位置 hex：`hex("...")` 在参数值位置解析为字节列表 Value（parser `hex_call`），
  与层位置 `hex(...)`（Raw 载荷层）并存。

## 使用手册（--help-pkg）

- 手册源：`docs/manual-zh.md` / `docs/manual-en.md`（超长双语，`## N. 标题` 编号章节 + 头部目录），
  经 `src/manual.rs` include_str! 内嵌，单一来源（不建 mdbook 站点）。
- `--help-pkg`（无参数）→ 全文，unix tty 经 `$PAGER`（默认 `less -R`）自动分页，
  非 tty / Windows 直接输出（`src/manual.rs::print_paged`）。
- `--help-pkg 章节` → `find_sections` 编号 / 标题前缀 / 包含匹配（忽略大小写），
  单命中打印该章节、多命中列候选、无命中列目录。裸 `--help-pkg` 由
  `normalize_help_pkg_args` 预处理为 `--help-pkg=`（空标题 = 全文）。
- 手册随 locale 切换（`manual_for`，`rust_i18n::locale()`）；双语章节编号一致性有测试。
- 现有 `--help-icmp/--help-tcp/.../--help-server` 详细帮助（locales `help.*`）已补
  `-I`/`-M` 说明并指向 `--help-pkg`。

## 测量功能（万用表）

- **抖动 jitter**：`Stats` 累计相邻接收样本 RTT 差（丢包打断链），
  `jitter()`/`jitter_max()` 输出均值/最大；文本汇总行 + `--json` 的 `jitter_ms`/`jitter_max_ms`。
- **源绑定 `-I`**：`util::resolve_source`（IP 或 Linux 网卡名 → SIOCGIFADDR 取 IPv4）；
  `util::connect_timeout/connect_first` 改走 socket2 → bind → `connect_timeout` → `smol::Async`
  （`smol::net::TcpStream` 无法从已绑定 socket 构造）；`local_bind` 统一 UDP/ICMP 源绑定。
- **MTU 探测 `-M`/`--mtu`**：`src/mtu.rs`——ICMP echo + DF（setsockopt：Linux
  `IP_MTU_DISCOVER=IP_PMTUDISC_DO` / Windows `IP_DONTFRAGMENT=21` / macOS `IP_DONTFRAG`）+
  载荷二分 [0,65507]；解析 Fragmentation Needed（type 3 code 4）的 MTU 字段；
  仅 IPv4（IPv6 需 ICMPv6 PTB）。`OutcomeKind::Mtu` 不触发丢包退出码。
- 运行时参数：`--params k=v,k2=v2`（可重复）注入；packet-dsl 的 `Value::Param`（`params("name"[, "默认值"])`
  值引用）在求值时从 `Params` 表取值，各类型 coercer（端口/地址/flags/MAC/字符串/载荷）统一经
  `as_param` 解析；`resolve_with_params` / `resolve_sources_with_params` 为带参数求值入口。
- prping CLI（`src/main.rs`）测量侧：ping/延迟/带宽/服务端/`-M` MTU/`-I` 源绑定；
  引擎侧 `--eng`/`--pkg`/`--lsp`/`--ls`/`--hex`/`--pcap`/`--lib`/`--params` 与测量互斥，
  见「包构造引擎」章节。
