# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式。

## [Unreleased]

### 新增

- 服务端 `server -a`/`--capture-all` 全帧抓包：不做「目的端口 == 监听端口」过滤，显示网卡上所有可见帧
  （ARP/ICMP/广播/组播/其他端口流量/出向回包，隐含 `-v`）；`[frame]` 摘要行对 ARP/ICMP 等非
  TCP-UDP 帧也给出地址级摘要（`serve/capture.rs` 新增 `FrameSummary`，Linux/Windows/macOS 三平台
  一致）；Linux 尽力开启混杂模式（需 CAP_NET_ADMIN，仅 cap_net_raw 时仍收本机地址/广播/组播帧）
- 服务端 `server --filter "表达式"`：tcpdump 风格子集过滤器（隐含 `-a`），只显示匹配帧——协议
  `arp`/`icmp`/`icmp6`/`tcp`/`udp`/`ip`/`ip6`、`port N`/`src port`/`dst port`、`host IP`/`src host`/
  `dst host`（ARP 按 spa/tpa）、`and`/`or`/`not` + 括号（`and` 优先）；表达式非法报错退出，
  三平台一致（`serve/capture.rs` 纯解析/匹配，不依赖 BPF 编译）；**所有协议令牌按注册表
  （dissect）匹配**——内置 arp/icmp/icmp6/tcp/udp/ip/ip6 归一化为反解层名，加固定层
  eth/ipv4/ipv6/http/dns/raw 与声明了 `#[rule]` 的 eng_lib 协议（如 dns/http/quic_initial），
  port/host 限定取自反解层（`--filter "dns"` 只显示 DNS 帧）；注册表缺失时报错
- pcap → .pkt/.pktl 转码（`engine --pcap FILE.pcap --to-pkt DIR`，`--out` 的逆操作）：每条记录生成
  一个 `record_%05d.pkt`（按原始序号命名）+ 一个 `.pktl` 配方按序引用全部 `.pkt`；缺省**无损字节级**
  （整帧/整包 `layer("eth"/"ipv4"/"ipv6", hex(...))` 或 `raw(bytes=hex(...))` 直喂，字节 100%
  保真且可 `--raw` 还原发送），`--structured` 切**语义结构化**（dissect 反解 → DSL 语义字段 +
  `*_bytes(hex(...))` 字节直喂兜底，合法捕获 roundtrip 字节一致；有 remaining/无法反解整条退回无损）；
  `--skip N` / `--limit N` 选转换范围、`--threads N` 并行解析（逐记录 dissect/渲染纯函数
  可并发，`std::thread::scope` 零新依赖；0 = 自动阈值 1024 条按 CPU 核数并行，1 = 单线程，
  结果按序号归位与单线程逐字节一致）；配方步骤 `delay:` 携带捕获帧间隔
- 配方 `.pktl` 新增步骤选项 `delay: 秒数`：步骤开始前等待（非首步生效，分片 sleep 响应 Ctrl+C 提前
  结束）——`engine FILE.pktl` 概览同步展示
- 配方 `.pktl` 新增步骤选项 `raw: true|false|网卡名`（`--raw` 的按步开关）：`raw: true` 强制本步
  原始发送完整序列化字节（网卡继承 CLI `--iface`）、`raw: eth0` 同时指定网卡、`raw: false` 强制
  本步走普通 TCP/UDP 载荷发送（覆盖 CLI `--raw`）——同一配方可混合 raw 与载荷步骤；
  `engine FILE.pktl` 概览同步展示；覆盖逻辑公开为 `pkg.rs::step_send_mode`
- packet-dsl 反解 fidelity 修复（roundtrip 字节级保真的公共地基）：`serialize_icmp` raw 分支补
  `f.payload`（icmp body 在最内层时不再丢失）；`parse_dns`/`parse_http` 填 `raw` 整段载荷（重序列化
  不再丢 DNS 压缩指针/附加段与 HTTP 头格式）；dissect 层序约定（展示序 外→内 vs 序列化 内→外）
  写入模块文档——新增字节级 roundtrip 测试覆盖

- 配方 `.pktl`（package list）：`--pkt FILE.pktl [HOST:PORT]` 按顺序发送多个 `.pkt`（`recipe:` 清单段；`--eng FILE.pktl` 概览并校验 extract 字段名）——`global:` 段声明跨步骤共享变量，步骤选项 `wait:`（覆盖 `--wait`）/`params:`/`extract:`（回包反解取值写 global，`from: reply.<层>.<字段>` + `as: int|hex|str|bytes`，复用 sniffer 字段机制）/`on_error: stop|continue`（默认 stop，失败中止配方）；`.pkt` 侧新值原语 `global("名"[, 默认])` 读取（类型化值，与 `params` 对称但可直接参与 `+`/`be16`/位运算）；`-p k=v`（`--params` 短选项）注入普通参数、`-g k=v`（`--global`）注入覆盖 init；`--out` 配方模式合并全部步骤写一个 pcap；sniffer 匹配值表达式也可引用 `global(...)`；TCP 载荷回显的应答字节保留（extract 可用）；示例 `examples/dns_recipe.pktl`（两步 DNS）/ `examples/udp_flow.pktl`（三步 UDP：extract as: int/bytes、be16 同宽直通、`global("tid") + 1` 运算）/ `examples/icmp_echo_flow.pktl`（两步 ICMP raw：sniffer + extract id/seq 复用，需 root）
- `engine FILE.pktl` 配方概览新增**参数面展示**：词法收集各步骤 .pkt 用到的 `params("名", 默认)`（含默认值与使用步骤，header 计入 param 计数；步骤 .pkt 解析失败提前报错，与 extract 字段校验同一哲学）；`packet FILE.pktl` 执行时 header 同样汇总打印参数名——`-p k=v` 注入前可先看清配方暴露哪些参数
- 路由跟踪 `-t`/`--traceroute`：ICMP echo + 递增 TTL 逐跳探测路径（对标 Windows `tracert`）——每跳 3 次探测、Time Exceeded 内嵌报文按 id/seq 匹配归属、反向 DNS 解析跳主机名、超时打印 `*`；`-m`/`--max-hops` 限跳数（默认 30）、`-d`/`--no-dns` 跳过解析；`--json` 每跳一行 + 汇总行；目标回显即停止，`-m` 内未到达返回退出码 1；IPv4/IPv6 双栈、`-s` 源绑定可用
- 路由跟踪 **TCP SYN 变体**：`trace --tcp HOST:PORT`（对标 `tcptraceroute`/`tracetcp`）——发 TCP SYN 递增 TTL，中间路由回 Time Exceeded，目标回 **SYN-ACK**（端口开）或 **RST**（端口关）即到达，ICMP 被防火墙过滤时仍可用；每个探测独立源端口，按内嵌 TCP 头 (sport, dport) 匹配（无需 seq）；raw ICMP（Time Exceeded）+ raw TCP（SYN-ACK/RST）双 socket `poll` 同时等待，TCP 伪头部校验和用 UDP 路由探测得到的本地源地址；SYN-ACK 带选项时 IPv6 框架判断用「无头优先」解析兜底；探测源端口限制 0x4000..=0x5FFF 防带头包误判；Windows 禁止 raw TCP socket → `trace --tcp` 报错提示（ICMP trace 不受影响）
- 路由跟踪 **UDP 变体**：`trace --udp HOST`（经典 Unix traceroute）——普通 UDP socket 发载荷到递增目标端口（33434 起每探测 +1，避开被监听端口），TTL 逐跳递增，UDP 头由内核构造（校验和内核算）；中间路由回 Time Exceeded、目标回 **Port Unreachable**（type 3 code 3 / ICMPv6 type 1 code 4）即到达；回复按内嵌 UDP 头 (sport, dport) 匹配归属（固定源端口 + 递增目标端口）；只需一个 raw ICMP socket 收包，**跨平台可用**（Windows 支持普通 UDP + raw ICMP）；`--tcp` 与 `--udp` 互斥（`TraceProtoConflict`）
- Windows 7 x86（32 位）MSVC 产物：`i686-win7-windows-msvc`（`just build-win7-32`，CI 随 x64 一起产出），同样静态链接 CRT/C++ 运行库，实测仅依赖 `ADVAPI32`/`KERNEL32`/`ntdll`；所有 xwin 配方统一 `XWIN_ARCH=x86,x86_64` 避免 SDK 反复重下载
- MSVC 构建静态链接 CRT 与 C++ 运行库（`.cargo/config.toml` 配 `crt-static`）：产物不依赖 `vcruntime140.dll`/`msvcp140.dll`/`ucrtbase.dll`，目标机器无需 VC++ Redistributable；实测 `x86_64-win7-windows-msvc` 产物仅依赖 `ADVAPI32`/`KERNEL32`/`ntdll` 三个 Win7 自带系统库；链接器加 `/ignore:4099` 抑制 xwin 静态库缺 PDB 的 LNK4099 噪音警告
- UDP ping 头部提示（与 ICMP/TCP 一致：目标/负载/迭代数或时长），并提示回显要求——目标端口需有回显服务（`prping -s ADDR:PORT`）才会回包
- 服务端 UDP 接收模式触发即时日志（触发来源与 `count × size`，不逐包打印避免带宽测试刷屏）
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

- **`packet --raw` 无法发送链路层协议（ARP/CDP/LLDP 等）**——目标推导 `derive_target` 只认 IP 层
  `dst`，纯链路层帧（最外层 eth、无 IP 层）一律报「包没有定义目标地址，请显式指定 HOST:PORT」，
  而 AF_PACKET 本就按帧内目的 MAC 直发、不需要目标 → 链路层帧 raw 发送放行无目标
  （`pkg.rs::resolve_send_target` 返回 `None`，展示 `target: none — 链路层帧，无需 IP 目标`；
  目标仅用于 IP 源地址填充/代理诊断等旁路逻辑）；raw 模式端口无意义，允许裸 `HOST`（端口按 0）；
  无 TCP/UDP 传输且最外层也不是 eth/ipv4/ipv6 的**纯裸层导出**（如 `req = arp(...)` 组合元件）
  payload 与 raw 模式一致跳过黄字提示（不视为发送失败，全部跳过汇总报「没有可发送的包」），
  裸 IPv4/IPv6 发送仍要求目标——示例 `prping packet examples/link_arp/arp_request.pkt --raw` 直接可用
- **Win7 RTM（SP0）两个 Winsock 缺陷导致 ping 全挂**（Win10 正常）——① raw ICMP socket 创建：`socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` 在 6.1.7600 上**管理员权限下也返回 WSAEINVAL 10022**（SP1 修复）→ `ping` 子命令 Windows 侧改走 **ICMP.DLL**（新 `ping/icmpwin.rs`，`IcmpSendEcho2`/`Icmp6SendEcho2`，与系统 ping.exe 同实现：无需管理员、各版本可用；运行时 `LoadLibrary("icmp.dll")` + `GetProcAddress` 动态解析——xwin SDK 无 icmp.lib 且保持零链接依赖；IP_STATUS 映射：11010→超时、11013/11014→TTL 超时、11002..11005/11018/11019→不可达；v4 TTL 取 ICMP_ECHO_REPLY.Options（`#[repr(C)]` 布局 + x86=28B/x64=40B 单测）、v6 无 TTL 显示 0；阻塞调用 `smol::unblock`；v4 `-s` 源绑定不支持（一次性橙色提示，v6 经 SourceAddress 支持））；② **WSAPoll 缺陷**：socket2 的 `connect_timeout` 在 Windows 内部用 WSAPoll，而 WSAPoll 对**非阻塞 socket** 在 Win7 RTM 返回 WSAEINVAL 10022（SP1 修复；curl 也因此禁用 WSAPoll）→ `util.rs::win_connect_select` 用经典 `select()` 等待可写 + `SO_ERROR` 取连接结果（TCP ping/latency/bandwidth 的 connect 10022 一并修复，Unix 仍走 socket2 原实现）
- **raw socket 报错文案平台区分**：`errors.raw_socket` 是 Linux 语境（"root or cap_net_raw"），Windows 上误导 → 新增 `errors.raw_socket_windows`（说明需管理员 + Win7 RTM 缺陷，ICMP ping 已走 ICMP API），`mtu.rs`/`trace.rs` 经 `icmp::raw_socket_error` 统一分平台（MTU 探测 / ICMP 路由跟踪在 Win7 SP0 上仍受 raw socket 限制）
- **Windows 上未装 Npcap 时程序无法启动（双击报「the program can't start because wpcap.dll is missing」）**——pcap crate 对 wpcap.dll 是静态导入，Windows 加载器在进程启动时解析全部导入表，即使只用 ping/trace 等与 Npcap 无关的功能也会因缺 DLL 直接起不来 → wpcap.dll 改为**延迟加载**（`.cargo/config.toml` 三 MSVC 目标统一 `/DELAYLOAD:wpcap.dll` + `delayimp.lib`——delay-load helper `__delayLoadHelper2` 由 MSVC 工具链的 delayimp.lib 提供，lld-link 不像 link.exe 会自动拉取，须显式链接）：未装 Npcap 的机器上其余功能全部照常运行，只有 `packet --raw` 会报 `errors.no_npcap`（`rawwin.rs::ensure_wpcap` 入口先 LoadLibrary 探测，成功则 DLL 驻留、后续经 delay-load thunk 命中；失败给友好报错，不会走到 delay-load 的 SEH 异常 0xC06D007E 崩溃路径）
- **Windows 上 traceroute/ping 收不到中间路由的 ICMP 错误报文**（实测：ICMP trace 到公网目标只有最后一跳 echo reply，Time Exceeded 全丢；Linux 正常）——Windows 的 raw ICMP socket 收包**不含外层 IP 头**（与 Linux 不同，同 ICMPv6 缺头问题；echo reply 因 type 0 被误读为 IHL=0 而"碰巧"能匹配，Time Exceeded 的 type 11 被误读为 IHL=44 必失败）→ 新增 `util::icmp_offset_v4` 首字节 version-nibble==4 框架探测（与 IPv6 的 `icmp_offset_v6` 对称），trace 的 v4 解析（ICMP/TCP/UDP 三变体）与 ICMP ping 的 `parse_reply`（v4/v6 双分支）全部适配；不含头平台 TTL/hop limit 不可得时显示 0
- **traceroute 中间跳全 `*` 只剩最后一跳 echo reply**（实测：Windows/Linux 都复现，系统 tracert/traceroute 正常显示中间跳）——**根因是 Time Exceeded 内嵌报文布局读错**：RFC 792 的 ICMP 头 8 字节**本身含 4B unused**，内嵌原始 IP 头从 ICMP 第 8 字节起（`body[0]`）；旧代码（与配套测试）误当成「8B 头 + 额外 4B unused + 内嵌 IP」，从 `body[4]` 读 IHL → 把内嵌 IP 的 id 高字节当版本 → IHL 40、内嵌 ICMP 读进载荷 → 所有中间跳匹配失败（`PRPING_TRACE_DUMP=1` 转储实锤：内嵌头完整、id=0xea05、seq 全对，只是读错位置）；→ ICMP/TCP/UDP 三变体的 v4（`body[0]`/`eihl` 从 0 起）与 v6（`body[24..40]` 读 dst、内嵌从 `body[40]` 起）解析全部按真实布局修正，测试构造同步改为真实格式
- **traceroute 内嵌传输头被路由器截断（<8B）的兜底归属**：内嵌 IP 头必完整（RFC 1812 至少整个 IP 头）、dst 恒可读，传输头截断时按「内嵌 dst == 目标」归属（全量 id/seq 不匹配仍丢弃防误认；系统 traceroute 根本不校验内嵌内容，dst 校验已比基线更严）——`parse_reply_v4/v6`、`match_time_exceeded_tcp`、`parse_udp_icmp` 三处适配；`PRPING_TRACE_DUMP=1` 环境变量打印收到的原始包（`[trace-dump]` 前缀）便于排查
- `packet`/`engine` 发包输出中无 TCP/UDP 传输层的包（如 ICMP）目标显示为 `127.0.0.1:0`（端口是传输层概念，IP 层没有端口）→ 端口 0 时只显示 IP；发送成功行 `IP4 → 127.0.0.1:0: sent 35 B` 去掉误导性端口与多余的冒号，raw 模式有真实 dport（TCP/UDP 层）时仍保留
- 引擎/发包侧（`packet`/`engine` 子命令）的 `note:` 提示此前硬编码且中英混杂（`--lang` 无效）→ 全部迁入 i18n（`engine.note_*` 键，en-US 默认英文，随 `--lang`/`$LANG` 切换）
- 服务端 UDP 回显此前不计入聚合统计（Ctrl+C 报告缺 UDP 接收量）→ 回显字节计入 `bytes`
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

### 变更

- 服务端抓包选项改为**显式依赖链**（不再隐含开启）：`-a`/`--capture-all` 必须配合 `-v`/`--verbose`，
  `--filter` 必须配合 `-a`——缺前置标志直接报错退出（`-a` 单独用报
  「`--capture-all` 需要配合 `--verbose` 使用」，`--filter` 单独用报
  「`--filter` 需要配合 `--capture-all` 使用」）；三个标志原样传给 `serve`，lib 层保留防御性归一

### 重构

- 统一 ping 循环驱动器（`drive.rs`）：icmp/tcp/udp/latency 的间隔/预热/统计/JSONL/收尾收敛为一处，各模式只实现「一次探测」（`Probe` trait）
- 直方图数据与渲染解耦（`Histogram::from_times`）：ASCII 与 ploot 共用桶计算，带宽报告不再临时构造 `Stats`
- DNS 解析收敛：`resolve`/`resolve_all` 合并进 `resolve_vec`，5 处重复的 resolving 横幅并入 `util::print_resolving`
- 带宽报告 `report()` 8 个位置参数改为 `ReportArgs` 结构（消除同类型参数传错风险）
- 模式合法性单一事实来源：`-4`/`-6` 冲突、UDP/带宽缺端口、`-P` 非带宽警告等 config 级不变式收敛到 lib `run`；bin `validate` 只管 CLI 级冲突（`-s`/`--json`/`-r`）
- 服务端连接日志渲染收敛到 `output::print_server_log`（着色统一，协议代码不再内联渲染）
