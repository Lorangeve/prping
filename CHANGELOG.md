# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式。

## [Unreleased]

### 新增

- **WebUI 执行功能**（`prping web` 编辑器可运行包/配方）：Run 页签 + 顶栏 ▶ 运行当前
  工作区 `.pkt/.pktl`——`run`/`run_stop` 信封 → 服务端 spawn 自身二进制的 `packet`
  子命令（ADR #8，零改动复用 CLI 全语义与本地化报错），stdout/stderr 逐行流式回传
  （`run_out`/`run_exit`），输出行数/单行长度封顶（超限继续排水并标记 `truncated`）；
  params/count/wait/listen（裸 `--wait`）/fuzz/raw/--iface/--out/json（`--json` JSONL
  结构化输出）选项（**无 target**：地址由包字段 params 承载、引擎从包内推导；
  显式 HOST:PORT 只留在 CLI 位置参数），`--out` 落工作区根内（`validate_rel` 防逃逸）；**json 默认开**——
  控制台按 JSONL 解析渲染（✓/✗ 包行+层栈/字节/目标/错误、步骤行、汇总行，悬停看
  原始 JSON），非 JSON 行（stderr 提示）原样回退，listen 与 json 互斥（CLI 校验）；
  **多标签并行运行 + 任务管理**：每次 Run 新建任务（控制台跟随最新任务），
  任务列表有任务即常驻（● 运行中 / ✓✗■ 终态；点行切控制台、■ 停止、✕ 移除）；
  `run_stop` 带 `run` id 停单个、缺省停本连接全部；全服
  并发上限 8；run_stop、连接断开与服务端进程死亡（stdin 生命线：子进程监视 stdin
  EOF 自行退出）三条路径均不留孤儿；未保存修改先落盘再执行；选项快照与运行参数
  输入（与 Layers 页签共用 `runValues`）经 IndexedDB 持久化。
- **WebUI 文档标签页**（多文件并行编辑）：每打开一个文件一个编辑器 tab——切走时
  编辑器内容落账进标签（未保存修改驻内存），切回即还原（不重读磁盘）；已开文件
  的再次打开 = 激活既有标签；✕ / Alt+W 关闭，脏文件先写 IndexedDB 草稿防丢、
  重开走恢复提示；关闭当前标签激活相邻（右优先），全部关闭回示例文档空态；
  **右栏数据随标签隔离**：运行任务卡按发起文件归属（Run 面板只显示当前文件的
  任务，文档标签 ● 指示后台运行），运行参数输入每标签独立，关闭文件标签即停止
  其运行中任务。
- **`web` feature 门控 `prping web` 子命令**（默认不启用）：core `web/` 模块与 CLI web
  子命令整体由 `--features web` 门控——纯 `cargo build` 不编译 web 模块、CLI 无 `web`
  子命令（产物体积更小）。justfile 的 build/check/test 配方统一以 `--features prping/web`
  启用，产物默认具备完整功能；`web-embed` 隐含 `web`（内嵌只对 web 子命令有意义）。

- **sniffer 统一谓词引擎**（packet-dsl `matchpred`，与 `#[rule]` 共享字段取值内核）：
  `.pkt` 的 `sniffer:` 段支持 `and(...)`/`or(...)`/`not(...)` 组合（跨层 AND、取反）、
  层内 `ne(字段, 值)` 不等、`mask(0xc0)`/`startswith`/`endswith`/`contains("...")`
  字节谓词（层原始字节；proto 命中时作用于整个报文）；字段取值器
  （`layer_field`/`layer_field_bytes`/`field_names`）下沉 packet-dsl，sniffer 匹配、
  配方 `extract`、`reply()` 表达式、`--eng` 展示共用一套字段表（`opcode` 等不实际
  解析的字段从表移除，改为构建期报错而非静默不匹配）
- **配方 `extract` 支持 `sent.<层>.<字段>`**：从**本步发包**反解字段取值写 global
  （无需 `wait`；`send_module` 新增 `on_sent` 回调收集完整序列化包字节），与
  `reply.<层>.<字段>`（需 wait）并存
- **裸 `--wait` 持续监听**（pktlang 对话的服务端，`--listen` 已并入）：**发送段先行**——文件有
  可发送的导出先发送再监听（含 `reply()` 的应答模板自动跳过）；绑定 UDP 地址（显式
  `HOST:PORT` 或按包内最外层 udp/tcp dport 推导），按 `.pkt` 的 sniffer 规则匹配
  收到的数据报——命中**原样回显**（`✓ matched ... from peer` + 反解展示），未命中
  忽略，Ctrl+C 优雅退出并打印匹配统计；监听规则不能引用发包字段（构建期报错）；
  与客户端 `--wait` 配对可让两个进程用 export + sniffer 模拟通信
- **`--wait --raw` 链路层监听完整版**：持续接收完整帧（Linux AF_PACKET /
  macOS·Windows libpcap·Npcap，需 root/管理员），按 sniffer 统一谓词匹配，命中后按
  **应答模板**（.pkt 默认导出，`reply("层","字段")` 取收到的帧字段）构造应答帧并
  raw 注入；自注入/lo 双投递防护；`--iface` 选网卡；`resolve_sources_with_reply`
  在 packet-dsl 支持带 reply 访问器求值；`open_af_packet`/混杂抽取到
  `util::socket`（serve 抓包与监听共用）
- **demo：`examples/icmp_echo_server/`**——纯 pktlang 的 ICMP echo 服务端
  （`sudo prping packet --wait --raw server.pkt` 后 `prping ping` 即被应答），
  附 README 说明三层监听对比
- **配方 `wait:` 与 CLI `--wait` 同语义（监听触发并入，负数 = 无限等待）**：`.pktl`
  步骤选项 `wait:` 无值或负数 = **无限等待**（无值 = 持续监听，等价 CLI 裸 `--wait`/
  负数 `--wait`，如 `--wait=-2`）——本步不发送，用该 `.pkt` 的 sniffer 匹配外部到达的包，**命中后配方
  继续**（触发后续步骤发包）；匹配包供 `extract` 取值，新增 **`reply.peer.ip`/
  `reply.peer.port`** 对端来源（UDP 监听载荷无 udp 头，对端来自 socket peer）；
  `raw: true|网卡` 走链路层监听。demo → `examples/dns_trigger/`（配方服务端：wait
  监听匹配查询 → extract → 触发发包应答）
- **`--count N` / 配方步骤 `count: N`（一次发多个包）**：`packet` 的 `--count N`
  让每个包重复发送 N 次（`send_module` 循环层实现，输出/统计/--json 按 ×N）；
  配方步骤 `count:` 覆盖 CLI（默认 1）；持续监听（裸 `--wait`）不支持 `--count > 1`；
  `--count 0` 拒绝
- **配方 `on_timeout` wait 超时处理**：步骤 `wait: 秒数` 超时未收到匹配应答 →
  `on_timeout: retry [N]` **重发当前步骤的包 N 次**（每次重新 wait，任一次等到
  回包即成功，默认 1；`recipe::OnTimeout::Retry`）或 `on_timeout: 文件` 打印
  超时信息并**发送备选 .pkt**（发其它包），步骤继续；备选包注入当前
  global/params（`pkg.rs::send_on_timeout_packet`）。demo →
  `examples/wait_timeout/`（超时 → 发 fallback 包）
- **配方步骤键改名 `pkg:` → `packet:`**（纯改名，旧键写 `pkg:` 报错提示改名；
  裸文件名 `- 文件` 保留；convert.rs 转码配方与全部 examples/docs 同步）
- **裸 IP 应答注入（macOS lo0 修复）**：`--wait --raw` 应答模板为裸 IPv4 外层
  （无 eth 层）时，注入改走**内核 IP 栈路由**（`util::socket::inject_ip4`：Linux
  IPPROTO_RAW+IP_HDRINCL 整包 / macOS 按报文协议开 raw socket 只发 IP 载荷），
  回环与局域网均无需 MAC 解析——macOS lo0 的 DLT_NULL 裸 IP 帧也能被应答
  （此前 eth 模板取不到 `reply("eth","src")` 逐帧报错跳过）；eth 外层应答仍走
  链路层注入；三个监听 demo（icmp/dns/tcp）的应答模板统一改为裸 IP 外层
- **demo：`examples/sniffer_chat/`**——双进程通信模拟（裸 `--wait` 服务端回显 +
  客户端配方 `sent.`/`reply.` extract 全链路），附独立 README.md 说明
- **demo 修正：`examples/icmp_mock/` 回环内核替答**——回环（macOS/Linux）上内核会替答
  ICMP echo（纯回显的 reply 与内核替答逐字节相同，client 命中的是内核回包）：`reply.pkt`
  把回包 seq 偏移 +1000 作配方标记，client sniffer 只匹配 1001/1002 排除内核替答；
  client 步骤 2 加 `delay: 0.5` 给 server 重开下一轮抓包留时间（否则错过 req2 只命中 3 条）；
  同步更新 README 与 `icmp_mock_recipe_simulation` 测试

- **`trace` 带端口自动启用 TCP SYN，移除 `--tcp`/`-t` 标志**（`prping trace HOST:PORT`）：
  与 `ping` 的「带端口 → TCP」一致，分派层决策收敛为纯函数 `lib.rs::resolve_trace_probe`
  （`trace HOST` 仍是 ICMP echo 默认；`--udp` 不变、仍不接受端口）；`--tcp` 在 CLI 层
  移除（未知参数即解析报错），库层 `PingConfig.trace_tcp` 与 `TcpTraceRequiresPort` /
  `TraceProtoConflict` 校验保留供库调用方使用
- **`trace --tcp` 支持 Windows（Npcap 路径）**：raw TCP socket 在 Windows 被禁止，改用与
  `packet --raw` 相同的 pcap 兼容层——Npcap 注入完整以太网帧（eth + IPv4 + TCP SYN，TTL 递增
  写在 IP 头里，IP/TCP 校验和手算；MAC 经 `GetBestRoute`/ARP 缓存/`GetIfEntry` 解析，复用
  `rawpcap.rs`），同一抓包句柄收 SYN-ACK/RST（目标到达）与 ICMP Time Exceeded（中间路由），
  回复按内嵌 TCP 头 (sport, dport) 匹配归属（`ping/trace/tcpwin.rs`）；抓包句柄先于发送打开、
  与发送帧逐字节相同者跳过（Npcap 回读注入帧）；**未装 Npcap** 时 banner 前经
  `ensure_wpcap()`（LoadLibrary 探测）报友好错误（`errors.tcp_trace_npcap`），不触发 wpcap.dll
  delay-load 异常；**仅 IPv4**（IPv6 跨链路需 ND 邻居解析，Win7 不可枚举，`errors.tcp_trace_ipv6`）；
  `-s` 源绑定（v4）与 `--json`/反向 DNS 等选项语义与 Unix 一致
- **修复 Unix `trace --tcp` 两处缺陷**（`ping/trace/tcp.rs`）：① 回包端口匹配逻辑反了
  （SYN-ACK/RST 回复的 (src port, dst port) = (目标端口, 我们的源端口)，旧代码按同向匹配，
  真实回复全部被当杂包丢弃、目标永远"未到达"；回环下误把自己的 SYN 回声当回复）——改为
  源端口=目标端口 + 目的端口∈探测源端口 + 源 IP=目标，并新增单测；② 恢复双 socket 收包
  （raw TCP 只收 TCP 包，收不到中间路由的 ICMP Time Exceeded——旧实现中间跳恒超时）：raw
  ICMP + raw TCP 双 socket `libc::poll` 同时等待，Time Exceeded 按内嵌 TCP 端口匹配
  （`parse_ttl_exceeded_v4/v6`）；TCP flags 判定位置从 IP 头修正到 TCP 头偏移
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

- **WebUI hover 悬浮框被编辑器面板拦腰裁掉**（tooltip 以 `position: absolute` 渲染在
  `.editor-pane`（`overflow: hidden`）内部，面板下方空间不足时下半截被边界截断，
  小窗口必现）→ tooltip 改 `position: "fixed"`（相对视口定位逃离裁切容器，放不下时
  CM 自动上下翻转；CM6 新版默认值正是为此），`.hover-doc` 高度上限改
  `min(400px, 100vh - 90px)` 随小视口收缩（内容内部滚动）
- **`bandwidth` 不带 `-n` 时发送 0 包**（`count=0` 在带宽循环里语义是「立即停止」，与 ping 的「0=无限」/latency 的「0→1」不一致；`--help` 示例本身就不带 `-n`）→ 缺省 `-n 1000`（对齐 psping 的 `-n` 默认），显式 `-n 0` 报错
- **`ping HOST:PORT -l N` 静默派发到 latency（echo 协议）**（旧功能残留：`-l` + 端口组合被 lib `run()` 的模式嗅探误判；目标不是 prping server 时全部超时且输出上下文仍是 ping）→ CLI 层明确报错（`-l` 仅对无端口 ICMP ping 有效）
- **MTU 探测：DF 位下载荷超过本机接口 MTU 时 `send_to` 报 EMSGSIZE 直接中止整个探测**（Linux `IP_PMTUDISC_DO`/BSD `IP_DONTFRAG` 下发送超 MTU 立即返回 EMSGSIZE，「路径 MTU < 本机 MTU」正是探测目标场景）→ 视为 FragNeeded 继续二分（`mtu=本地 MTU`，Linux 经 `IP_MTU` getsockopt 查询，其余平台记 None 不污染聚合；`ProbeOutcome::FragNeeded` 改携带 `Option<usize>`）
- **服务端聚合报告忽略 UDP 会话时长**（`micros` 只由 TCP 连接累加，纯 UDP 流量时摘要恒 `in 0.00s (avg 0.00 Mbps)`）→ UDP 会话汇总时把会话耗时计入 `micros`
- **drive 循环固定次数/时长模式末尾多睡一个完整 interval**（循环顶先睡再查 `done()`，`-n 2 -i 0.5` 实测 3.04s vs 理论 2.5s）→ 间隔改在 `advance()` 后、确认还有下一轮再睡；睡眠分片（100ms 检查 Ctrl+C），中断响应不再被长 interval 拖住
- **Unix raw ICMP ping 单次收包、杂包即误判超时**（raw ICMP socket 收到本机所有 ICMP 流量，其他进程的回显/错误报文会让本次探测立刻记丢包；UDP ping 有循环过滤而 ICMP 没有）→ 循环收包直到 deadline，按 ident/seq 过滤；type 3/11 校验内嵌原始报文 id/seq 才归属
- **`bandwidth -u` 发送方向从不排空服务端回显**（4MB 接收缓冲打满后服务端回显阻塞、本端发送被本地缓冲排空速率拖住，测的是本机速率而非链路吞吐）→ 并行 drain 任务持续丢弃回包（发送完成后停止）
- **`bandwidth -H` 非法值静默忽略**（与 ping/latency 的 `bad_histogram` 校验不一致）→ 统一校验
- **trace ICMP v4 截断归属与 v6 不一致**（v4 在 id/seq 不匹配但内嵌 dst 对时一律归 `want[0]`，v6 只在内嵌头缺失时兜底）→ 统一：仅内嵌 ICMP 头截断（<8B）时按 dst 归属，id/seq 不匹配不再误归属
- **trace TCP SYN v6 目标端口 0x6000-0x6FFF（24576-28671）回包解析错位**（无头 TCP 数据的首字节=回复源端口高位，被 version-nibble 启发误判为带头）→ `tcp_frame_v6` 追加 next header=TCP 与 src==target 双校验再判定带头
- **UDP ping 2 字节 seq 回绕**（>65535 次迭代后与陈旧回包撞号）→ 改 4 字节 u32 seq（负载最小 4 字节）
- **JSONL seq 从预热数起且不连续**（warmup 不输出行但 seq 含预热偏移）→ 用有效迭代计数（跳过预热）从 1 连续编号
- **`ping host:badport` 报迷惑的 DNS 解析错误** → `parse_target` 对 host 含冒号且端口非数字明确报「invalid port」
- **`server 0.0.0.0:0` 打印「监听在 :0」** → 监听行移到 `serve()` 绑定后，打印实际端口
- **`packet --wait`（持续监听）发送段先行失败会杀死监听**（纯监听场景被「本机暂无可发送对端」阻断）→ 降级为橙色警告并继续监听
- **`listen_addr` 只取第一个包的 dport**（多 export 不同端口时静默只监听一个）→ 收集全部 dport，多个不同端口明确报错提示显式指定 ADDR:PORT
- **trace 硬编码中文错误「无法获取本机路由地址」** → 改用 i18n `errors.trace_no_local_addr`（tcpwin 已在用）
- **超长 ping 的 percentile/直方图口径**：采样窗口 10000 → 100000，窗口满后文本摘要/JSON 标注「基于最近 N 个样本」（min/max/avg/stddev 仍按全历史）
- 顶层 `--help-pkg` 已失效但文档/提示仍引导使用 → 全部迁移到 `document` 子命令（README/CLAUDE.md/手册提示/manual.rs 模块注释）

### 变更

- **引擎不再默认读取 eng_lib**：编译期烘焙的仓库 `eng_lib` 路径已移除，默认库目录
  一律运行时发现（二进制同目录 `lib/` + 当前目录 `lib/`，存在才收录、canonical
  去重；`just dist` 同步 eng_lib → lib/）——部署与开发统一 `lib/` 布局，显式
  `--lib` 优先级不变。测试构建经 packet-dsl 新增的 `test-stdlib` feature（由
  packet-dsl / prping-core 的 dev-dependencies 激活，产物永不启用）在运行时发现落空时
  回退仓库 eng_lib，测试共享真实标准库 prelude；`resolve_libs` 随之只归集 `--lib`
  （默认目录不再重复收录）
- **`bandwidth` 缺省次数改为 1000**（对齐 psping 的 `-n` 默认；原为「不带 `-n` 发 0 包」的静默空跑）
- **`ping HOST:PORT -l N` 从「静默变 latency」改为报错**（负载大小仅限无端口 ICMP ping；带端口负载请用 latency/bandwidth）
- **`packet --wait` 发送段先行失败从「中止」改为「警告并继续监听」**
- **`server` 的监听地址行改由 `serve()` 在绑定后打印**（显示真实端口）
- **顶层 `--help-pkg` 正式废弃**（解析直接报错），手册统一走 `prping document`
- **Windows ICMP ping 全部显示「请求超时」**（实测：系统 ping.exe 正常、prping 100% 超时且失败是
  即时的）——根因：同步单请求在 `rc>=1`（IcmpSendEcho2 已写入应答）后用 `IcmpParseReplies` 当判据，
  而该函数对非 `IP_SUCCESS` 的应答（超时占位/错误回复）返回 0，**实测对真实成功应答也返回 0**
  （`PRPING_ICMP_DEBUG=1` 转储 `rc=1 replies=0`，直接读 Status 为 `IP_SUCCESS`）→ `n==0 → 超时`
  短路把成功/不可达/无路由全部掩成「请求超时」→ 改为经典用法：`rc>=1` 时直接读缓冲区内首个
  `ICMP_ECHO_REPLY`/`ICMPV6_ECHO_REPLY_LH` 按 `Status` 分类（`ping/icmpwin.rs`，v4/v6 同步改）；
  新增 `PRPING_ICMP_DEBUG=1` 逐探测转储（rc/GetLastError/Status 名称/RTT，`[icmp-win]` 前缀，
  与 `PRPING_TRACE_DUMP` 同约定）+ 非预期失败一次性 `[icmp-win] warning`（不再静默掩码）
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