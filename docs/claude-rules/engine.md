# 包构造引擎（engine / packet）与 packet-dsl 详细规则

> 从 CLAUDE.md 拆出的详细规则，覆盖：packet-dsl 子 crate、engine/packet 子命令
> （LSP/pcap/配方）、hex/raw 字节体系、自表示协议 proto、值函数/字节原语、
> eng_lib 标准库与库搜索、运行时参数。
> **改动原语（registry.rs builtin_docs / eval.rs 分派 / tpl 等）、协议声明或这些
> 规则本身时，必须同步 GRAMMAR.md / DESIGN.md / CLAUDE.md 相关条目（见「原语文档
> 同步门禁」）。** Windows 专属（Npcap/wpcap/ICMP.DLL）见 `docs/claude-rules/windows-build.md`。

## packet-dsl（workspace 子 crate）

- 独立 crate `packet-dsl/`（.pkt 网络包构建 DSL，解析 + 语义 → 结构化 IR，宿主序列化/发送）。
  设计文档：`packet-dsl/DESIGN.md`；用法：`packet-dsl/README.md`；
  pkglang 语法规范（词法 + 语句/表达式 EBNF，解析表达式语法的权威描述，与 lexer.rs/parser.rs
  一一对应）：`packet-dsl/GRAMMAR.md`。
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
- 质量门禁（workspace 级）：`just test` / `just lint`（clippy + 原语文档同步 `doc-sync-check`）/ `just fmt-check` 已覆盖 packet-dsl。

## 包构造引擎（engine / packet 子命令）

引擎侧（`engine`/`packet` 子命令/LSP/pcap）集成在 prping 同一 binary 中（与测量子命令互斥），
共享 packet-dsl crate；不再有独立 prping-pkt binary。

- `prping engine FILE.pkt`：模块概览 + 逐包层栈（字段 + `auto` 标注）+ 字节 hexdump
  （`src/eng.rs`）；`engine --lsp`：.pkt LSP 服务器
  （JSON-RPC over stdio，`run_lsp_on` 可测；诊断/补全/悬停/documentSymbol）。
  诊断 = 解析错误（单条）+ **静态形状检查**（`packet_dsl::check::check_module`，
  DESIGN.md §6.6：解析成功后对求值期 coercer 必然失败的封闭形态出多条诊断——
  字符串进数值位/越界/同宽宽度不符/移位移位量/除零/proto 字段默认值（含 bits）等，
  按 (行,列) 排序去重；`params`/裸 ident/未知值调用零误报跳过；库值函数体不展开，
  `ip4`/`ip6`/`mac` 按 tpl 宽度表检查）。
  补全按光标位置上下文出候选（`eng/lsp.rs::pkt_context`）：层位（`|>` 后/`|>` 续行/
  def 值位 `name = ` 之后/函数体语句）只给 use+层函数+库函数、实参名位给所属函数未填的 `name=`（本地/库/内置参数表，hex/params
  等位置实参原语不弹）、值位给值原语+作用域参数名+值函数并按 (函数,参数) 加权
  （flags=→syn/ack…、dst=→ip4/mac…）、顶层语句位给语句关键字+注解、字符串/注释内不弹；
  .pktl 配方与 import/export/sniffer/attr 各有专属分支。候选 `sortText` 分级且数组序一致，
  前端（UI cm.ts）保序渲染，不重复实现位置判定；出口按光标部分词前缀过滤（`ud`→udp 系，
  空词不过滤），孤立 `|`（`>` 未打）按层位出候选，未完调用名（已知名字的严格前缀）宁空勿噪。
  诊断打词豁免（仅 LSP 路径，CLI 保持严格）：「未知/未定义名字」且名字是已知名字（本地
  def/func 兜底扫描 + 库 + 内置 + 层类型 + 关键字，`use` 关键字等值例外）的严格前缀 → 本步不报；
  前端另过滤末行「输入已结束」类 parse 错误（span 恒在 EOF，打字中间态必然存在），
  「字符串未闭合」「非法 token」等精准中间态提示保留。
- `prping packet FILE.pkt [HOST:PORT]`：构建并一次性发送全部变体包（`src/pkg.rs`）。
  目标优先级：显式 `HOST:PORT` > 包内最外层 IP 层 `dst` 推导（`derive_target`，
  payload 模式还需传输层 `dport`）> 省略。raw 模式端口无意义，允许裸 `HOST`
  （端口按 0）；**链路层帧（最外层 eth、无 IP 层，如 ARP）raw 发送不需要目标**——
  AF_PACKET 按帧内目的 MAC 直发（`pkg.rs::resolve_send_target` 放行 `None`），
  目标仅用于源地址填充/代理诊断等旁路逻辑，展示
  `target: none — 链路层帧，无需 IP 目标（AF_PACKET 按帧内目的 MAC 直发）`。
  无 TCP/UDP 传输且最外层也不是 eth/ipv4/ipv6 的**纯裸层导出** payload 与 raw
  模式一致跳过黄字提示（`engine.note_bare_export`，不视为失败；全部跳过汇总报
  「没有可发送的包」）；裸 IPv4/IPv6 发送仍要求目标（sendto 路由）。
  **发送方式提示（`--eng`）**：无 TCP/UDP 传输但最外层可 raw 发送的包（ICMP
  over IP、ARP over eth）在 `--eng` 逐包展示时橙色提示 `engine.note_raw_only`——
  只能经 `--raw`/配方 `raw: true` 发送完整包，payload 模式提取不到载荷
  （`pkg.rs::raw_only` 判定，与发送期自动回退的 `engine.note_raw_fallback` 提示
  互补：后者描述发送时的实际动作）。
  默认提取最外层 TCP/UDP 的应用层载荷经普通 socket 发送并读回显；`--raw` 原始发送
  完整序列化字节，按平台分派：Linux：eth → AF_PACKET + if_nametoindex（注意 CString
  结尾 NUL）、ipv4 → IPPROTO_RAW + IP_HDRINCL、ipv6 → IPV6_HDRINCL；
  **Windows：Npcap 链路层注入（`src/rawwin.rs`）——设备选择/ARP/延迟加载 wpcap.dll/
  `--wait` 帧回读等细节见 `docs/claude-rules/windows-build.md`**。回包匹配（sniffer /
  ICMP echo id+seq）抽为 `pkg.rs::match_reply`，Linux raw ICMP 与 Windows Npcap 捕获
  共用；非 ICMP 且无 sniffer 时不等待（两平台一致）。逐包容错：失败红字提示、最后汇总退出码。
  **raw 源地址自动填充**：IP 层 src=0.0.0.0/::（DSL 未指定）时，发送前用
  UDP-connect 路由探测的本地地址填进字节并重算 IPv4 header checksum
  （`pkg.rs::patch_zero_src`，AF_PACKET 原始帧内核不会替我们填，回包要靠它路由回来）；
  显式 src 不覆盖。**域名即地址**：`dns("host")` 值原语（v4 优先，`dns(host, 6)` v6 优先，
  IP 字面量短路）与地址字段（src/dst/spa/tpa...、layer src/dst）直接接受域名（按族取首个）；
  值位置的 `ip4`/`ip6`/`mac` 值函数（tpl 实现）不解析域名——需显式 `dns()` 包装
  （headers.pkt 内部已做），
  如 `dst=params("dst", "www.baidu.com")` 或 `--params dst=www.baidu.com`——
  解析经 `packet_dsl::set_dns_resolver` 注入（prping 入口 `ensure_dns_resolver`）。
  域名来源记录在 IR（Ipv4Fields/Ipv6Fields 的 src_host/dst_host），`engine` 展示
  `dst=dns(www.baidu.com->198.18.0.5)`（字面量 IP 不标注）。
  代理诊断：目标或填充的 src 落在 198.18.0.0/15（Clash 等 fake-ip 段）时黄色警告——
  eth 原始帧绕过代理直发不可达，提示用 `examples/network_icmp_bare/`（裸 IP 走内核
  路由/代理 TUN，源地址内核按路由填，代理环境可用）。
  **层序咨询性警告**（`packet_dsl::stack_warnings`，`stack.rs`）：`--eng`/`--pkt` 对
  构造包的层栈相邻对做规范承载检查（与序列化器自动字段推断表一致）——只橙色提示
  `note:`、不阻断（隧道/封装合法：WireGuard `ipv4 |> udp`、VXLAN `eth |> udp`、
  IPIP `ipv4 |> ipv4` 不警告）；警告类别：层序颠倒（http 承载 tcp）、传输层互叠
  （tcp 是 udp 的载荷）、缺网络层（eth 直挂 tcp/http/icmp）、ICMP/ARP 承载语义层、
  网络层无法推断内层协议号（http/dns 直挂 ipv4/ipv6 → proto=0/59 静默兜底）、
  裸协议违反 `#[rule]` 载体（`quic_initial |> tcp` → WrongCarrier——eval 把裸协议
  名记进 IR `RawData.proto`，检查器查注册表 rule 的载体层集合 `ctx_cond_layers`，
  纯 `bytes(...)` 掩码/未注册协议不校验）；
  渲染共用 `eng::print_stack_warnings`（i18n 键 `engine.note_stack_*`，
  locales 根目录 + `crates/prping-core/locales/` 双份须同步——rust-i18n 编译期读
  crate 侧副本）。
- scapy 衍生特性（A 解剖 / B 应答 / C pcap / D ls / E fuzz）：
  - **解剖**：packet-dsl `dissect(bytes) -> DissectReport`（`packet-dsl/src/dissect.rs`）——
    双路径（eth vs bare-IP）取更深解析；应用层先按 `#[rule]` 分派、未命中回退内容
    识别（协议识别以内容为准、端口只是可选提示——http 靠 `#[rule(contains("HTTP/", in=start_line))]`
    字段字节魔数、dns 靠 `#[rule(or(ne(qdcount,0), ...))]` 字段值约束、裸 proto 靠
    `#[rule(mask(0xc0))]` 首字节掩码，防任意字节误报）；**硬编码已清零**（content_valid /
    dns_all_zero 已删除，全部由 rule 匹配函数承载）；
    DNS 压缩指针追跳还原、IPv4/ICMP 校验和错进 `notes` 不报错；
    `dns_message_id(bytes)` 供应答匹配（读前 2B）。渲染在
    `eng.rs::render_dissected`；CLI：`engine --hex` / `engine --pcap` / `packet --wait` 应答解剖。
  - **应答 + RTT（--wait）**：`pkg.rs::send_payload`/`wait_icmp_reply`——DNS 只收 id 匹配
    应答（`dns_message_id`，跳过杂包），TCP 首字节时间，Linux raw ICMP 匹配 echo id+seq
    （回包 socket 须**先于发送打开**——回环/近零延迟下内核在 send() 内同步完成回包往返，
    发送后再开 socket 会把回包永久漏掉；`send_raw_bytes` 先 `open_raw_icmp4` 再发再等）；
    UDP 回读有 1s、TCP 有 2s 超时（无 wait 分支同样要有默认超时，否则测试挂起）。
  - **sniffer 段（.pkt 回包校验 / 监听规则）**：`sniffer:` + `- 谓词` 列表（与
    `export:` 同风格，**顶层列表 = 隐式 OR**）——`--wait` 时按声明匹配应答、
    裸 `--wait` 时作监听规则（服务端）。匹配器为 **packet-dsl `matchpred::Matcher`**（与
    `#[rule]` 共享字段取值内核）：回包反解层字段 == 字面量常量、发包同层同名字段
    `SentField`（`id=id`；**监听模式无发包，`allow_sent: false` 构建期报错**），
    或**值表达式**——原语/值函数/`params(...)`/字节列表，构建期
    `eval_sniffer_value` 求值为字节后与回包字段**字节**比较，如
    `match icmp(id=myid(), seq=[0x00, 0x01])`，可复用同文件 `func ... -> bytes`；
    匹配成功 `✓ reply matched: k=v ... (rtt)`，超时 `✗ no matching reply`）。
    **统一谓词**（与 `#[rule]` 同构）：`and(...)`/`or(...)`/`not(...)` 组合
    （支持跨层 AND、取反）、层内 `ne(字段, 值)` 不等、`mask(0xc0)`/`startswith`/
    `endswith`/`contains("...")` 字节谓词（层原始字节；proto 命中时作用于整个
    报文）——见 `matchpred.rs`。字段名 = `matchpred::field_names`（与 `engine`
    展示/配方 `extract` 共用；`sport`/`dport`/`type` 为 IR 字段
    `src_port`/`dst_port`/`icmp_type` 别名；**字段集 = 反解层实际解析字段**，
    如 dns 只有 `id`/`flags`——`opcode` 不独立解析不要列）；每层支持字段静态
    校验，字面量按字段类型强转，`sniffer_match` 为公开测试/宿主 API（仅内置
    原语），`sniffer_match_with` 带模块 + 参数（支持值函数/`params`）；
    替代默认 DNS/ICMP 硬编码匹配（默认 ICMP 匹配按发包 IP 族取期望回包类型
    v4 type=0 / v6 type=129，防把 echo request 自身当回包）；
    仅配合 `--wait`，TCP 回显无独立字节故不适用。
  - **裸 `--wait` 纯持续监听**：`pkg/listen.rs::listen_packets`——**发送段先行**
    （文件有可发送的导出先发送再监听；含 `reply()` 叶子的包求值失败 → 无可发送包跳过），绑定
    CLI `HOST:PORT`（或按包内最外层 udp/tcp dport 推导，IPv6 包 → `[::]`），
    循环接收 UDP 数据报，反解后按 .pkt 的 sniffer 规则匹配（`allow_sent:
    false`）；命中只打印 `✓ matched ... from peer` +
    反解展示（**不发包回应**——回应包的构造属编排，由 .pktl 配方的 `wait: -1`
    步骤 + extract + 触发发包完成），未命中忽略；Ctrl+C 优雅退出（读超时 200ms
    轮询中断标志）并打印匹配统计（demo → `examples/sniffer_chat/README.md`）。
  - **`--wait --raw` 链路层纯监听**：`pkg/listen_raw.rs::listen_raw_packets`（同样发送段先行）
    ——持续接收**完整帧**（Linux 默认 AF_PACKET 单 socket 全接口/指定 `--iface`，
    复用 `util::socket::open_af_packet`/`af_packet_promisc_all`；macOS/Windows/
    Linux+pcap 走 `rawpcap::open_capture_listen` 多设备多线程——**接收导向打开**：
    不做 EN10MB 限制（macOS lo0 的 DLT_NULL 也能收，剥头复用 `serve::strip_null`）、
    混杂尽力而为（BIOCPROMISC 不支持的设备如 macOS anpi* 降级不混杂）；
    按 sniffer 统一谓词匹配（`allow_sent: false`），命中只打印匹配详情与反解展示
    （**无应答模板注入**——历史单文件应答模板已移除，`reply("层","字段")` 现为
    配方 extract 专用原语，.pkt 内出现即 `ReplyOutsideRecipe` 诊断错误）；
    lo 双投递防护（DEDUP_WINDOW 去重）；Ctrl+C 优雅退出 + 匹配统计。需要 root/Npcap。
    配方服务端 demo → `examples/icmp_echo_server/`（ICMP echo）、
    `examples/tcp_handshake_listen/`（TCP SYN-ACK）、`examples/dns_echo_listen/`（DNS）。
  - **pcap**：`src/pcap.rs` 手写格式（magic 0xa1b2c3d4 LE/BE + nano 变体；24B 全局 + 16B
    记录头；`LinkType{Ethernet=1, Raw=101}`）。`packet --out` 写入、`engine --pcap` 读取、
    **`engine --pcap x.pcap --to-pkt DIR` 转码**（`src/engine/convert.rs`，`--out` 逆操作）：每记录一个
    `record_%05d.pkt` + 一个 `.pktl` 配方（步骤 `delay:` 携带捕获帧间隔）；缺省**无损字节级**
    （整帧 `layer("eth"/"ipv4"/"ipv6", hex(...))`/`raw(bytes=hex(...))` 直喂，可 `--raw` 还原发送），
    `--structured` **语义结构化**（dissect 反解 → DSL 语义字段，dns/http/选项头等语义无法表达
    的层整段 `*_bytes(hex(...))` 直喂；层序 dissect 展示序 外→内 需 rev 后序列化；有 remaining/
    无法反解整条退回无损；合法捕获 roundtrip 字节一致），`--skip N`/`--limit N` 选范围、
    `--threads N` 并行（逐记录 dissect/渲染纯函数可并发，`std::thread::scope` 零新依赖，
    结果按序号归位与单线程逐字节一致；0 = 自动阈值 1024 条按 CPU 核数并行）。
  - **--ls**：`eng.rs::ls_builtins` 内置原语 + 库函数字段表——两节**同构展示**：
    签名（只列参数名，内置不内联类型，类型说明在参数行）→ 摘要以 `"""..."""` 文档字符串
    置于签名下第一行（库函数来自紧贴的 `#` doc 注释摘要行，解析为 `FuncDoc`（ast.rs），
    见 `FuncStmt.doc`/`Func.doc`/`LibExport.doc`；内置来自 `BuiltinDoc.summary`）→
    逐参数说明（库函数 `@param 名: 说明`）→ `auto:` 说明（库函数 `@auto: 说明`）→
    库函数尾注 `[模块] 库函数（隐式可见）`（内置无尾注，节标题即来源）；
    **--hex**：`decode_hex` 十六进制转字节。
  - **--fuzz**：`DefaultSerializer::new_fuzz`（`with_seed_fuzz` 测试确定性）——Auto 视作
    Random（MAC/地址/TTL/端口/id/flags），协议类型/length/校验和保持自动保证栈合法。
- packet-dsl 增量 API：`parse_source_at`（编辑器未落盘文件的 import 根解析）、
  `resolve_sources`（按 默认导出/命名导出 归因）、`builtin_docs`（**全部引擎原语**的文档：
  层位置 raw/hex/layer + 值位置字节原语/位运算/params/global/reply——`--ls` 与 LSP 悬停/补全共用，
  改动原语必须同步；`reply` 为配方 extract 的 from 表达式专用，见「配方」条）、`lib_exports`（库模块命名导出枚举——LSP 补全/悬停提供
  eng_lib 层头函数签名，本地定义优先遮蔽；LSP 侧 `LspServer.lib_exports_cache`
  OnceLock 进程内缓存一次，避免每次悬停/补全全量重读重解析库文件）。
- **默认导出与同名命名元件**：模块同时有默认流水线与名为模块名的命名元件时，
  `import a`（无大括号）报明确诊断（提示显式 `import a { a }` 或改名），非含糊冲突。
- 引擎 CLI 冲突校验在 `src/main.rs`（`validate_engine`/`validate_packet`）：`--ls`/`--hex`/`--pcap`
  互斥且不与 `--lsp` 组合、子动作不带文件（engine）；`--iface` 需 `--raw`（packet）。
  结构性约束由子命令选项集保证（engine/packet 各自定义自己的选项，`-s` 与引擎无关）。
  i18n 键与测量侧共用 `locales/`（引擎键并入同一 yml）。`packet FILE.pktl [HOST:PORT]`
  与 `engine FILE.pktl` 按扩展名分派到**配方**（见下条）。
   **无扩展名参数自动定位 pktl**：`engine`/`packet` 收到不带扩展名的文件参数时，
   先试 `<arg>.pktl`（当前目录/参数所在目录下的同名文件），找不到该文件再试
   `<arg>/<basename>.pktl`（同名文件夹里的同名 pktl）——examples 里带同名 .pktl
   的目录按此组织（`examples/<name>/<name>.pktl` + 其 .pkt，如 network_icmp_bare/
   quic_initial/bad_network），因此在 `examples/` 下 `prping engine quic_initial`
   与仓库根下 `prping engine examples/quic_initial` 都直接可用
   （`main.rs::resolve_pktl_arg`）；*_mock 系列是 server.pktl + client.pktl
   双配方（无同名 pktl），按路径运行 `prping packet examples/icmp_mock/server.pktl`。
- **配方（.pktl = package list）**：`src/recipe.rs` 解析清单（`global:` 段声明跨步骤
  共享变量 + `recipe:` 段按顺序列出步骤）；`pkg.rs::send_recipe` 执行——每步 = 一个
  `.pkt`（解析/求值注入当前 global 快照），步骤项键 `- packet: 文件`（旧键 `pkg:`
  已改名，写 `pkg:` 报错提示改名），步骤选项 `wait:`（**与 CLI `--wait` 同语义**：
  `wait: -1`（任意负数）= **无限等待**（持续监听，等价 CLI 裸 `--wait`/负数 `--wait`——
  本步不发送，用 .pkt 的 sniffer 匹配外部到达的包，命中后配方继续（触发后续步骤
  发包），匹配包供 `extract` 的 `reply.` 来源取值；**监听方式自动选择**：包内有
  udp/tcp 传输层 → UDP 数据报监听（`pkg/listen.rs::listen_udp_once`，绑定 CLI
  `HOST:PORT` 或包内 dport 推导），无（ICMP/ARP 等）→ 链路层监听
  （`pkg/listen_raw.rs::listen_raw_once`）；`raw: true|网卡` 可显式覆盖）、
  `wait: 秒数` = 发送后等一个匹配应答（覆盖 CLI `--wait SECS`）、
  `on_timeout: retry [N]|文件`（**wait 超时处理**：超时未收到匹配应答 →
  `retry [N]` **重发当前步骤的包 N 次**（每次重新 wait，任一次等到回包即成功，
  默认 1；`recipe::OnTimeout::Retry`）或**发送备选 .pkt**（发其它包，步骤继续；
  `pkg.rs::send_on_timeout_packet`））、
  `count: N`（**每个包重复发送 N 次**，覆盖 CLI `--count`；`send_module` 循环层
  实现，`--count`/`count:` 均按 `opts.count` 逐包 ×N 发送）/
  `raw:`（覆盖 `--raw`：`true` 开原始发送且网卡继承 CLI `--iface`、网卡名 = 开原始
  发送并指定网卡、`false` 强制载荷发送；`pkg.rs::step_send_mode` 实现）/`delay:`
  （步骤开始前等待）/`params:`（追加覆盖 `-p`/`--params`）/`extract:`（取值写
  global，`from:` 四种
  形态：`reply.<层>.<字段>` 直取**回包**反解字段复用 sniffer 字段机制
  （需 `wait:`（OneShot 或 `wait: -1` 持续监听））、`sent.<层>.<字段>` 直取**本步发包**反解字段（**无需 wait**，
  经 `SendCtx.on_sent` 回调收集完整序列化包字节）、**`reply.peer.ip`/`reply.peer.port`**
  （持续监听步骤 UDP 监听的**对端地址**——载荷无 udp 头，对端来自 socket peer，
  供后续步骤回包；`FromSpec::PeerField`），`as: int|hex|str|bytes`，或
  **值表达式**（`reply.<层>.<字段>` 叶子改写为 `reply("层","字段")` 原语调用后按 DSL
  值表达式解析求值——可调函数/原语/`+`，可引用同步骤 .pkt 值函数/`params`/`global`，
  `as:` 可选，缺省 = 自然类型值；`reply` 原语仅在 extract 求值上下文生效，其余回退
  用户函数，eng_lib 的 ARP 位常量 `reply()` 撞名不受影响），多回包依次应用后写覆盖
  先写）/`on_error: stop|continue`（默认 stop，失败中止配方退出码 1）；
  **loop 块**（`- loop: N`，N 为负数 = 无限（空值非法——字段要么不写、要么写值，无限写 `loop: -1`），
  与 CLI 负数 `--wait` 同语义；`recipe::LoopCtx`）：
  包裹嵌套步骤组（`steps:` 后缩进 `- ` 项；`until:` 谓词列表须在 `steps:` 前，
  sniffer 同款语法、可 `global(...)`，`pkg.rs::build_until_matcher` 每轮重建），
  每轮完整执行块内步骤；解析后**平铺**进 `Recipe.steps`（块内每步带同一 `LoopCtx`，
  `first`/`last` 定位块边界），执行器 while 回跳（`pkg.rs::send_recipe`：块首迭代
  闸门 = until 命中 / Ctrl+C 优雅收工（打印统计、退出码 0）/ 次数，先到先退；
  `delay:` 轮间延迟第 2 轮起；`listen_*_once` 带 until 匹配器，until 命中非
  sniffer 包 → 不回应整块立即收工）；
  写入 global 的途径：`init` 初始值（global 项三形态：`- name: X` + 缩进 `init:` /
  裸 `- X` / `- X=v` 一行内联；值 = 字符串/十进制/0x/字节列表字面量）→ CLI
  `-g k=v`（`--global`，覆盖 init）→ 步骤 `extract`（覆盖前两者）；`.pkt` 侧读取用
  packet-dsl 值原语 `global("名"[, 默认])`（类型化值）。`--out` 配方模式收集全部步骤
  包合并写一个 pcap；`engine FILE.pktl` 展示结构概览并校验 extract 字段名
  （表达式形态遍历 `reply(...)` 叶子校验）。
  `send_packets`/`send_recipe` 共用发送循环 `pkg.rs::send_module`（`SendCtx` 携带
  module/sources/params/globals + 回包回调 `on_reply` + 发包回调 `on_sent`，
  均 `ReplyCb`）。示例统一为 **mock server/client 形式**（形态标杆 `examples/icmp_mock/`：
  server.pktl = `wait: -1` 监听 + extract + 触发发包，client.pktl = 发包 +
  `wait: N` + sniffer 校验 + extract 复用；完整清单见 `examples/README.md`）：
  `examples/icmp_mock/`（**ICMP mock**：链路层监听触发发包 + 两步 request，回包 seq
    偏移 +1000 作配方标记，排除回环内核替答）
  / `examples/http_mock/`（**HTTP mock**：链路层监听 GET/POST → 200 OK，客户端 raw
    TCP；http 反解分派要求 dport=80/8080）
  / `examples/dhcp_mock/`（**DHCP mock**：UDP :67 监听 Discover/Request → Offer/Ack
    单播回包，DORA 四步；裸字节数组 + 固定 xid）
  / `examples/tcp_data_mock/`（**TCP 数据 mock**：监听 PSH|ACK 数据段 → 纯 ACK
    （ack=seq+载荷长度），两轮 seq/ack 推进）
  / `examples/tcp_http_mock/`（**TCP 握手+HTTP mock**：listen SYN → SYN-ACK →
    listen GET → 200 OK；客户端 extract 服务端 ISN 动态构造 ACK/GET）
  / `examples/arp_mock/`（**ARP mock**：链路层监听 who-has → is-at 单播应答 +
    gratuitous ARP 演示）
  / `examples/udp_mock/`（**UDP mock**：同一服务端按端口分派 DNS 应答与 VNC 横幅）
  / `examples/dns_echo_listen/`（**DNS mock**：UDP :53 监听查询 → A 记录应答；客户端
  / `examples/dns_loop_server/`（**循环监听服务**：`loop: -1` 无限包 listen+reply，
    `until:` 停服包收工——loop 块样例）
    两步 extract 复用 tid——原 dns_recipe 的 extract 教学点并入）
  / `examples/dns_trigger/`（**配方监听触发最小样例**：`wait: -1` 步骤匹配 DNS 查询
    → extract id/`reply.peer.port` 对端 → 触发步骤发包应答）
  / `examples/icmp_echo_server/`（**配方服务端入门样板**：单组 listen+reply 的 ICMP
    echo 服务端）
  / `examples/tcp_handshake_listen/`（**TCP 握手 mock**：listen 纯 SYN → SYN-ACK
    （ack=seq+1/地址互换），客户端 extract 服务端 ISN）
  / `examples/sniffer_chat/`（**双进程对话模拟**：sent/reply 两种 extract 来源 +
    and/not sniffer 组合——见该目录 README.md）。
  机制/素材类保留原样（mock 形态不适用）：`examples/network_icmp_bare/`（真实 ICMP
  echo，裸 IP 走内核路由——内核即应答方，mock 配方会与内核替答冲突）/
  `examples/wait_timeout/`（**wait 超时处理**：`on_timeout` 发备选包——机制演示）/
  `examples/bad_network/`（重传/RST 时序重放，`--out` 生成 pcap 供 tcpdump 分析）/
  `examples/quic_initial/`（QUIC Initial/Short 构造展示，保护前裸结构、无应答语义）/
  `examples/icmp_ping/`（对真实目标的 1-10 次 ping 配方）/ `examples/pcaps/`（pcap 素材）。

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

## 自表示协议（proto，`#[proto] func` 唯一语法）

- `#[proto(kind="eth")] func name(params) -> bytes { concat(...) }`（**proto = 值函数 + 字段标注**，`-> bytes` 必填）：
  声明式字段布局（`FuncStmt.schema`），**字段即调用参数**，层位置调用时按声明顺序编码字节、包成 IR 层
  ——`#[proto(kind="eth")]` 合并层类型（kind = IR 层类型，语义阶段校验闭集），裸
  `#[proto]` = Raw 层（如 quic_initial / quic_crypto）——与命令式 func 构建逐字节
  一致（`tests/proto_func.rs` 以 eth/arp/icmp/ipv4/ipv6 与命令式 `*_bytes(concat(...))`
  对照）。proto 关键字语法已移除；解析期 `parser.rs::desugar_proto_funcs` 把
  函数体降糖为字段表（`FuncStmt.schema`），下游（构造/解析/注册表/LSP）只见字段表。**proto 关键字语法已移除**；解析期 `parser.rs::desugar_proto_funcs` 把函数体
  降糖为字段表（`ProtoStmt`），下游（构造/解析/注册表/LSP）只见字段表。
- 可逆字段原语：`u8/be16/be32/be64/le16/le32/le64/mac/ip4/ip6/
  dns_name/line`（文本行：到 `\r\n`，值 = 字符串；
  解析侧**空行（首字节 `\r`）→ 失败**——重复区停止判定用）；
  `bytes`/`rest` 是**声明性 meta 类型**（无编码函数，`bytes(宽度)`/`rest(子proto)`
  调用形态已移除）：宽度经 `#[meta(bytes=...)]`、消费语义经 `#[meta(rest)]` /
  `#[meta(rest="子proto")]`（末尾递归/重复到失败），定宽字面量自动推导；
  **vint 变长整数**（`FieldType::Vint`，**唯一声明形态** `#[meta(codec=...)]`——无
  varint/qvarint 字段关键字糖；值位置的 `varint()`/`qvarint()` 由 eng_lib/vint.pkt
  库 proto 声明提供，引擎无变长整数内置原语）：`#[meta(codec="le128")] n` / `#[meta(codec="prefix", prefix_bits=2,
  widths=[1,2,4,8])] len` / `#[meta(codec="table", inline_max=0xFC,
  sentinels=[0xFD,0xFE,0xFF], widths=[2,4,8], endian="le")] n`
  ——三模型：le128 续延位（protobuf）、prefix 前缀宽度表（QUIC）、table 内联+哨兵表
  （Bitcoin LE / CBOR BE）；新增编码 = 声明数据不动引擎；构造/解析共用同一方案
  **与同一实现**（`ast.rs::VintCodec` + `FieldDecl.vint` 承载声明、`codec.rs`
  `VintCodec::encode`/`decode` 双向编解码；语义校验：prefix 表长 = 2^prefix_bits 且
  宽度严格递增、table 哨兵 > inline_max 且互异、两表等长、endian ∈ be/le）；
  vint 可作 `len` 计算字段（QUIC `#[meta(len="auto", codec="prefix", ...)] length` 即此）；
  **`bits` 位字段**（`#[meta(bits=N)]`，
  整型字段容量内：u8 ≤8 / be16 ≤16 / be32 ≤32 / be64 ≤64：同一位组按声明顺序
  高位→低位填充，连续位字段凑满 8 的倍数位成整字节组——IPv4 version/ihl 各 4 位
  拆分、IPv6 version+TC+flow = 4+8+20 位跨 4 字节组；字面量默认 = 常量校验判别位、
  参数引用 = 可变字段）；
  **`switch` 判别式分派**（`#[meta(switch="前序字段", cases=[[值, "子proto"], ...])]`，
  类型固定 Bytes：解析时按前序字段值选子 proto 反解字节窗口（子命中恰好消费整窗 →
  进嵌套 `subs`），有界窗口 `bytes=宽度` 未命中/失败 → 整窗不透明字节优雅降级
  （如 DNS rdata 按 rdlen、未知 rtype 与升级前行为一致），无界窗口 → 整体回退；
  构造侧值 = 字节直喂）；
  **`if` 条件在场守卫**（`#[meta(if="整型表达式")]`——`band`/`shr` 等现有运算组合
  引用前序字段/参数，**非零 = 在场**、不引入布尔运算：为假时解析消费 0 位、构造不编码、
  实参可省略——GRE 可选字段；与 bits/len/rest 互斥）；默认值/宽度可引用前序字段与**值参数**
  （`func name(pnl=0, ...)`，只参与构造）；`bytes` 宽度构造侧校验实参长度
  （引用未算自动字段时跳过）；`len` 计算字段统一为单一目标：`len="auto"` = 后续全部
  字段字节数、`len="目标"` = 目标字段（后序）字节数（反向填充），都可配 **`expr` 表达式变换**
  （`#[meta(len="auto", expr="shl(div(len, 4) + 5, 4)")]`，expr 里 `len` = 基准字节数，
  支持 `+`/mul/div/sub/shl/shr——TCP data_offset 联动）；`src`/`dst` 字段兼作
  ipv4/ipv6 伪头部地址元数据；
  `#[proto(kind="eth")]`（IR 层类型闭集；裸 `#[proto]` = Raw 层）/
  `#[rule(udp(dport=443))]`（上下文分派）/ `#[rule(mask(0xc0))]`（首字节掩码）/
  `#[rule(startswith("HTTP/"))]` / `#[rule(contains("HTTP/", in=start_line))]`（字节模式匹配，
  可选 `at=N` 偏移 / `in=字段名` 字段字节内容定位）/ `#[rule(ne(qdcount, 0))]`（字段值约束，
  `eq`/`ne`，`or(...)` 内合并为 OR 语义）/ `#[rule(and(...))]` AND / `#[rule(or(...))]` OR
  ——**同层**条件 AND 合并、**跨层**条件独立任一命中；字节模式匹配只允许 AND 组合（不能
  出现在 or 分支），字段值约束允许在 or 内；`not` 不支持。注解——注解参数
  统一语法（`key=value` 项 / 调用形式 / 裸值 flag，见 GRAMMAR.md §3 attr）；
  注解可全缺（裸 proto 合法：构造产 Raw 层、可作
  `rest(子proto)` 解析目标）；proto 可导出（eng_lib prelude 依赖）。
- **M2 解析侧**：`src/proto.rs`——`parse_proto` 同一声明反向解码（`bytes` 宽度（`#[meta(bytes=...)]`）引用
  前序字段、`len` 计算字段正常读、`rest` 到末尾（与 `bytes= 窗口` 同设 = 窗口内重复，
  见 §12.5 窗口内重复条目 / GRAMMAR §3）、规则掩码先验），产出通用字段表
  `ProtoHit`；`#[rule]` 分派注册表（`set_proto_registry`，OnceLock）接入 dissect
  （tcp/udp 端口、ipv4 proto、ipv6 next_header、eth ethertype 各层查表，命中即解析、
  未命中/失败回退内容识别——协议识别以内容为准、端口只是可选提示），
  `DissectReport.proto` 承载命中，`engine --pcap/--hex` 展示。
  **dissect 注册表化（协议走 pkt 声明、硬编码 parse_* 已删除）**：应用层
  `try_app_layer` 先查 proto 注册表（`#[rule]` 分派 + 匹配函数：dns `udp/tcp(dport=53)` +
  `or(ne(qdcount,0), ...)` 字段值约束、http `or(tcp(80), tcp(8080))` +
  `contains("HTTP/", in=start_line)` 字段字节魔数，命中即
  `proto_hit_to_layer` 转 IR 层、载荷保留 raw）；规则未命中时回退
  `find_content_candidates`（http/dns + 带匹配函数的裸 proto，如 QUIC `mask(0xc0)`）按内容反解；
  层头 `try_proto_layer` 按
  kind 查注册表（`find_by_kind`
  + `parse_header`——**遇 rest 字段即停**，层头字节 = rest 之前的定长/变长字段，
  `proto_hit_to_layer` 回填语义 IR 层 + `set_layer_raw` 保留头字节）。**硬编码
  parse_*（含 parse_dns/parse_http）已全部退役**：未注册/字节不符时该层不产生（eth/arp/ipv4/ipv6 字节留
  remaining，icmp/tcp/udp 段按 raw 保留并记 note）——层头解析**只**走注册表，
  调用方须先 `set_proto_registry`（宿主 `ensure_proto_registry`）。**`ensure_proto_registry`
  修入口-as-库**：入口文件本身在库
  目录中（headers.pkt 被逐个解析注册时）以 is_lib=true 入图（export 参与 prelude
  注入，供 bytes/data 等依赖它的库模块引用——否则层头 proto 从未真正注册）。sniffer/recipe 的 `reply.<层>.<字段>` 与 sniffer 匹配
  在语义 IR 层缺失时回退查 `report.proto` 字段表（proto 命中即字段来源）。
- **M3 实证**：`eng_lib/quic.pkt` 的 `quic_initial` 迁为 proto（rule udp 443 +
  bytes 0xc0 + len="目标" 长度前缀 + len="auto" Length），构造字节与旧 func 一致（golden），
  捕获的 QUIC 包可被 `engine --pcap` 反解成字段——首个"eng_lib 可造即可解析"。
  完整草案见 `docs/design-proto-self-describing.md`。
- **M4 层头全量 proto 化 + 语义回填**：`eng_lib/headers.pkt` 的 9 层全部迁为 proto
  （eth/arp/ipv4/ipv6/icmp/udp + tcp/dns + http——http 用 `line` 文本行 + rest(hdr_line) 重复到空行
   + rest body，见「变长标记」条；dns 用 `dns_answer` + 四区 list，响应也走
  注册表）；构造字节与旧 func 逐字节一致（`tests/proto_func.rs` 对照）；
  层头注册表接入完成：eth/arp/ipv4/ipv6/icmp/tcp/udp 全按 `find_by_kind` +
  `parse_header` 反解（arp/ipv6 亦已接入；ipv4 用 bits 拆分 version/ihl 后带选项的
  头也走注册表）；**硬编码 parse_* 全量退役（不再兜底，层头只走注册表）**。
  `typed_layer` 按字段名把值回填 IR 语义字段：src/dst（含 src_host/dst_host 域名
  标注）、sport/dport、type/code/id/seq、ttl/proto/flags、src_mac/dst_mac/
  ethertype 等——既有消费者（payload 发送、ICMP --wait、patch_zero_src/
  derive_target、sniffer 字段校验）迁移后继续工作；头字节仍走 raw 分支
  （自动 checksum/length）。
- **新增协议支持流程（务必遵守）**：协议一律走 pkt 声明（构造 + 解析共用同一份
  `#[proto]`），引擎不保留/不新写任何协议解析魔法。给新协议写声明时若现有可逆字段
  原语（u8/be16/.../dns_name/bytes/rest/bits/list/vint codec/len·expr）表达
  不了线格式（如新的变长编码、位域、指针跳转等），**不要自己发明引擎魔法或临时
  硬编码**——停下来向用户询问是否增加新原语（及如何设计），得到确认后再实现，
  并同步 GRAMMAR.md/DESIGN.md/CLAUDE.md（含本文件）。引擎侧不再保留任何协议解析兜底
  （DNS 压缩指针 chase、HTTP 文本行均已原语化下沉）。
- **变长标记（list / DnsName / vint codec / len expr / 算术宽度 / bits 位字段 / line+重复区）**——
  tcp/dns/ipv4/http/quic 能 proto 化的机制：
  - **vint codec（变长整数数据化）**：唯一声明形态 `#[meta(codec="le128")]`（续延位，
    protobuf）/ `#[meta(codec="prefix", prefix_bits=2, widths=[1,2,4,8])]`（前缀宽度表，
    QUIC RFC 9000 §16）/ `#[meta(codec="table", inline_max=0xFC, sentinels=[0xFD,0xFE,
    0xFF], widths=[2,4,8], endian="le")]`（内联+哨兵表，Bitcoin LE / CBOR BE）——
    编码宽度由值决定（DSL 无比较/分支，闭式算法原语化）；**字段位置无 varint/qvarint
    关键字糖**，值位置的 `varint()`/`qvarint()` 同由 vint.pkt 库 proto 提供；构造（`eval.rs::encode_field_type`）
    与解析（`proto.rs::decode_field`）共用同一方案**与同一实现**（`codec.rs`
`VintCodec::encode`/`decode`，双向一份代码防漂移），`FieldDecl.vint` 承载；
    **可作 `len` 计算字段**（QUIC `#[meta(len="auto", codec="prefix", ...)] length`、
    `#[meta(len="data", codec="prefix", ...)] length`——长度前缀本身变长编码）；
    解析侧常量校验同定宽字段（字面量默认 = 判别位）；
    新增编码 = 声明数据不动引擎（见 docs/design-proto-self-describing.md §4.5）。
  - **list 重复字段**：`#[meta(list="计数表达式", item="子proto")]`（rest 类型）——
    元素 = 子 proto，构造侧值 = 列表逐项调子 proto 编码（如 DNS questions =
    `["www.baidu.com"]` → dns_question(name) 逐条），解析侧按 count 表达式（引用
    前序字段，如 qdcount）循环解析子 proto、每元素一个嵌套 `ProtoHit.subs`；
    `parse_list_sequence` 复用 rest(子proto) 的递归解析、按计数而非解析到失败。
    **重复到失败的哨兵形态（`#[meta(list, item=...)]` 无计数）已并入 `rest(子proto)`**
    ——rest(子proto) 即重复解析到失败（HTTP headers 到空行），构造侧值 = 列表逐项编码
    或字节直喂（如 QUIC payload），解析侧只消费解析成功的字节、剩余留给后续字段。
  - **`dns_name` 字段类型**：DNS 名字（标签序列 + 0 终止；压缩指针**追跳还原**）——
    构造侧编码复用 tpl `%L`（eng_lib `dns_name()` 值函数同源）；解析侧在**完整报文**
    上用绝对偏移读标签，遇指针跳转到报文内目标偏移继续读（有界 ≤32 防循环），
    值 = 还原的点分名字 `ProtoVal::Str`；**消费字节 = 原始位置的标签 + 终止**（指针
    按 2B 计），追跳段只参与值还原不影响顺序消费——解析链传播 `full`/`base`
    （`parse_consumed_at`），子 proto（answers list 等）的指针也能追到前面的
    question 区。DNS question/answer 即裸 proto 范例。
  - **`#[meta(len=..., expr="...")]` 表达式变换**：len 的基准值（后续/目标
    字节数）先求 `expr` 再编码——expr 里 `len` = 基准值，支持 `+`/mul/div/sub/shl/shr
    （`eval_width` 与构造侧 `eval_value` 同语义）；TCP data_offset 即用
    `expr="shl(div(len + 13, 4), 4)"`（len = 后续字段字节数，含 options）。宽度表达式
    `bytes=...` 相应支持算术：`bytes="sub(mul(shr(data_offset, 4), 4), 20)"`（options
    宽度回算）。**`u8` 字段编码支持恰好 1 字节列表直通**（`flags=bor(syn(), ack())`
    位常量组合是字节列表，与值原语 `u8` 一致）。
  - **`bits` 位字段（`#[meta(bits=N)]`，整型容量内）**：半字节/位级布局声明——IPv4 首字节
    version(4)+ihl(4) 用 `#[meta(bits=4)] u8(4)`（字面量 = 常量校验判别 version==4）+
    `#[meta(bits=4)] u8(ihl)`（参数引用 = 可变读出）；ihl 因此成为可引用字段，options
    宽度 `bytes="sub(mul(ihl, 4), 20)"` 按它回算——**带选项的 IPv4 头也走注册表**。
    容量随类型放宽：u8 ≤8 / be16 ≤16 / be32 ≤32 / be64 ≤64（IPv6 version+TC+flow-label
    = 4+8+20 位跨 4 字节组即此）。构造侧位打包（`pack_fields`：位组压缩后字节数参与
    len 计算）与解析侧位读取（`decode_field` 位游标，可跨字节）对称；位组总位宽
    %8==0（语义阶段校验，普通字段从字节边界开始；`len="目标"` 目标不能是位字段）。
- **② 递归解析（rest 子 proto + 常量判别）**：`rest(子proto)` 末尾递归——剩余字节
  按子 proto 解码成嵌套 `ProtoHit.subs`（quic_initial.data: rest(quic_crypto)）；
  子 proto 用常量默认值字段作线格式判别（`frame_type: u8 = 0x06`）——解析侧校验
  线上值与常量一致，不一致即停止该子序列（QUIC PADDING 帧 frame_type=0x00 据此
  截断）；`quic_crypto` 即裸 proto 范例。`engine --pcap` 展示嵌套
  `proto: quic_initial → proto: quic_crypto`。
- **字段表达（`#[meta]` 键值对标注，一个注解可多项）**：concat 参数 = 字段——
  `u8(tos)`（类型化调用 + 标识符，签名参数同名 = 默认值引用，非签名标识符 = 必填
  字段）、`be32(0x00000001)`（匿名常量 `f{i}`）、`#[meta(name="first")] u8(bor(0xc0, pnl))`
  （显式名 + 默认表达式）、`#[meta(name="first4")] hex("60000000")`（**字面量宽度
  自动推导** = 4 字节）、`#[meta(bytes="dcid_len")] dcid` / `#[meta(rest="quic_crypto")] payload`
  （裸标识符类型来自 meta）、`dns_name(name)`（DNS 名字字段）；
  项：`name` / `len`（计算长度目标：`"auto"` = 后续全部 / 字段名 = 目标字段字节数，
  按值表达式子解析，如 `bytes="band(first, 3) + 1"`）/ `rest`（可带子 proto；
  与 `bytes=宽度` 同设 = **窗口内重复**——Bytes 类型窗口里循环单发反解子 proto
  到耗尽，恰好耗尽 → 子命中进 subs，未耗尽/未注册 → 整窗不透明字节降级；
  TCP options 等 data_offset 界定的中部重复区；与 `list=` 计数互斥）/
   `expr`（len 表达式变换，`expr="shl(div(len, 4) + 5, 4)"`，`len` = 基准值）/
   `list`+`item`（重复字段：计数表达式 + 元素子 proto）/
   `codec`+`prefix_bits`+`widths`+`inline_max`+`sentinels`+`endian`（vint 方案）/
   `switch`+`cases`（判别式分派：`switch="前序字段"` + `cases=[[1, "rdata_a"], [28, "rdata_aaaa"]]`——
   类型固定 Bytes，解析按前序字段值选子 proto 反解字节窗口（有界 `bytes=宽度`
   未命中/失败 → 整窗不透明字节降级），构造侧值 = 字节直喂）/
   `if`（条件在场守卫：`if="band(shr(flags, 1), 1)"` 等现有运算组合，非零 = 在场——
   为假解析 0 位 / 构造不编码 / 实参可省）/
  `bits`（位字段
  位宽，整型字段容量内：u8 ≤8 / be16 ≤16 / be32 ≤32 / be64 ≤64）；`line("...")` 文本行字段（到 `\r\n`，HTTP 头行）。
  内置类型化调用（u8/be16/mac/ip4/ip6/dns_name/line；变长整数 = vint codec）宽度自带，`bytes` 宽度机制只
  留给变长场合；body 必须扁平 concat（嵌套/hex 等不可逆片段报错）；body 的 `layer("kind", ...)`
   形态已移除——层身份一律用 `#[proto(kind=...)]` 注解。
  `tests/proto_func.rs`（含与命令式 `*_bytes` 的 golden 对照 + dissect 注册表 +
  list/DnsName/expr 机制）+ `tests/proto_headers.rs`（真实 eng_lib 注册表端到端）。

## 值函数 / 字节原语（hex/raw 之上的构建体系）

- **值函数**：`func name(args) -> bytes|int { 值表达式 }`——函数体是值表达式
  （`-> bytes` 字节列表 / `-> int` 整数，**返回类型是声明+运行时校验**，
  非静态检查），与层函数（体是流水线）以返回类型标注区分。**值调用按模块作用域解析**
  （本地函数 / import / eng_lib 库导出 prelude，函数体在定义模块内求值）——库值函数
  脚本无需 import 直接调用（如 `eng_lib/bytes.pkt` 的 `dns_name()`/`line()`/`rand_mac()`）。
- **中间形态：无 lambda / map / filter / reduce / 多态折叠 / 比较逻辑 / Bool**——
  算法（count/cksum）由引擎原语提供，语言保持最小、求值保证终止；`+` 是唯一
  运算符。已移除运算符（`=>`/`==`/`&&`/`!` 等）在词法层报清晰错误，`true`/`false`
  退化为普通 IDENT。
- **原语三族边界判定**（放新原语前先分类；详细论证 → packet-dsl `DESIGN.md` §5.5）：
  - **生成式（值函数）** = "字节从哪来"：纯值计算、无字节流游标、只有正向（可逆性归
    meta）——不关心"我在哪/我前面是谁"的需求落这里；eng_lib func 声明即可扩展（开放集）；
  - **proto-meta** = "字节怎么排"：本字段的宽度/在场性/位布局/重复/分派，构造与解析
    双端同表驱动（`FieldDecl`）——需要"字段身份 + 双端行为"的需求落这里（引擎闭集）；
  - **proto-rule** = "字节是谁的"：跨层分派判据（上下文原子/字节模式/字段约束），
    解析侧识别门、构造侧层序合法性（引擎闭集）。
  - 接触点：meta 借值表达式当标量词汇（`bytes=`/`if=`/`switch` 判别子都经 `eval_width`）；
    rule 站在解码产物之上；`switch(cases)` = 字段内的 rule（表驱动开放数据），
    rule = 层间的 switch（谓词闭集）。
  - 判别测试：需要字节游标或字段身份 → 当不了值函数；天生要逆向（校验字读回比对）→
    是 meta/字段级不是值函数；只在双端搬运信息（回填/校验注记）→ 引擎骨架，不做成原语。
- **字节原语**（值位置，引擎实现；DSL 无字节运算，这些是 hex/raw 之上"一步"）：
  `concat` / `u8` / `be16` / `be32` / `be64` / `le16` / `le32` / `le64` /
  `tpl` / `count` / `cksum` / `md5` / `sha1` / `sha256` /
  `rand16` / `rand8` / `rand_bytes` / `pad` / `dns`；
  `raw` 是**双位置**原语（层 = Raw 载荷层，值 = UTF-8 字节，≡ Python `b"..."`，与 hex 对称）。
  **变长整数**（已下沉，非内置原语）：`varint(n)` = protobuf base-128/LEB128（≤9B）、
  `qvarint(n)` = QUIC 2 位长度前缀 1/2/4/8B（RFC 9000 §16）——由 eng_lib/vint.pkt
  的库 proto 声明提供（proto 双位置，值位置调用返回字节），与 `#[meta(codec=...)]`
  字段方案共用同一编解码实现（`codec.rs` `VintCodec::encode`/`decode`）。
  **随机分两方向**：整数方向 `rand16()`/`rand8()`（端口/ID/seq 数值字段）；
  字节方向 `rand_bytes(n)`（0..255、n ≤ 65535，随机 MAC/payload/nonce——
  `rand_mac()` 即 `rand_bytes(6)`）。两者都是构建期随机（每次构建独立，
  与序列化 seed 无关——确定性由调用方固定随机字段保证）。
  **`pad(n)` 确定性填充**：n 个零字节（0..65535，与 rand_bytes 对称）——
  以太网最小帧 46B 填充、IP 选项对齐、DNS OPT padding 等，免去
  `hex("0000...")`/`concat(be16(0), ...)` 手拼。
  **`count`/`cksum` 为引擎原语**（中间形态移回）：列表长度 / 2B 反码校验和——
  DNS qdcount 用 `count(questions)`；`cksum` = RFC 1071 反码校验和（2B 大端，
  与自动校验和一致，`cksum(hex("..."))` 一步）。**`len` 是可组合的库值函数**
  （eng_lib/bytes.pkt `func len(x) -> int { count(raw(x)) }`，字符串 UTF-8、
  字节列表原样——可组合算法住库、闭合算法住引擎，与 ip4/ip6/mac 下沉同理由）。
  原 `words16`/`fold16`（校验和的切分/折叠中间机制）、`sum`（无真实用户的整数
  求和）与 `reduce`（高阶回调，已被 proto list/rest 取代）已移除，DSL 不再暴露
  中间步骤（循环/迭代本就是引擎机制）。
  **摘要 `md5`/`sha1`/`sha256` 为引擎原语**（输入字节列表或字符串 → 16/20/32B）。
  **位运算** `bor`/`band`/`bxor`/`bnot`/`shl`/`shr`（值原语，函数形态）：整数
  （Int/Hex）或同宽字节列表（元素级）；bor 变参左折叠。协议标志位（TCP/IPv4 flags、
  ARP op）原引擎原语 `tcpflags`/`ip4flags`/`arpop` 已下沉为 eng_lib/bytes.pkt 位常量
  值函数（`syn()`/`ack()`/`df()`/`mf()`/`request()`/`reply()`…）+ 位运算组合：
  `tcp(flags=bor(syn(), ack()))`（headers.pkt 的 tcp/ipv4/arp 已改；flag 字符串
  写法移除，数字直写仍可用）。**撞名注意**：位常量是 prelude 短名，`syn`/`ack`/
  `df`/`request` 等为常见词——本地定义（元件/函数同名）优先遮蔽，遮蔽后常量不可用
  （如元件命名 `syn` 会让 `syn()` 解析失败），脚本内勿与位常量同名。
  **tpl 等宽直通**：`tpl` 的输入是字节列表且长度 = 模板总输出宽时原样返回
  （`mac(rand_mac())` 随机 MAC 仍可用；字符串按模板解析）。
  **params 按形状解析（取代已移除的 int()）**：`0x`/`0X` 前缀 = 十六进制数值、纯十进制
  数字 = 数值、其余 = 字符串——`be16(params("port", "53"))` = `[0x00,0x35]`、
  `icmp(id=params("id", "0x1234"))` 直接可用（`--params port=5353` 可用）。
  **默认值可为任意值表达式**：未注入时求值为默认（`params("port", be16(0x1235))` =
  `[0x12,0x35]`、`params("payload", hex("deadbeef"))`），字符串默认值仍按形状解析；
  值表达式默认仅在值表达式位置可用（层参数位置默认需字符串字面量）。
  **字符串字面量不隐式转数值**：`be16("0x4242")` 报错（写 `be16(0x4242)` 或
  `be16(hex("0x4242"))`）；数值形文本载荷在值表达式里会变数值，层参数路径
  （`raw(bytes=...)`/地址字段）保持字符串。`raw("abc")` ≡ Python
  `b"abc"`（UTF-8 字节）。**同宽字节直通**：`u8`/`be16`/`be32` 接受恰好同宽的字节
  （`be16(hex("1234"))` = `be16(0x1234)`；宽度不符报错带字节数）；小端变体 `le16`/`le32`
  数值低字节在前（`le16(0x1234)` = `[0x34,0x12]`）、字节输入反转（`le16([0x01,0x02])` =
  `[0x02,0x01]`，按大端解读后重编码为小端）。
  `hex()`（值位置 parser 解析期、层位置 `build_hex`）接受可选
  `0x` 前缀、要求偶数长度纯 hex，非法/奇数长度报错（值位置早期切片越界 panic 已修）。
  **完整「值类型与转换」表见 `packet-dsl/DESIGN.md` §6**（类型清单/表示/产生原语/
  转换规则/歧义点——`int_of`、`hex_string_bytes`、`val_ip4/6`、`val_bytes` 等 coercer
  与之对应，改动须同步）。
  **tpl 模板子语法**（`packet-dsl/src/tpl.rs`，权威定义 `DESIGN.md` §5.3，EBNF 见
  `packet-dsl/GRAMMAR.md` §4.7）：模板串 =
  字面字符与说明符交替，**锚定全匹配**、字面/分隔符匹配但不产出（scanf 式）；`%c` 通配
  1 字节；`%d1/%d2/%d4` 十进制、`%x1/%x2/%x4` 十六进制（宽度缺省 1，大端）；
  `%L` DNS 名字序列（**动态宽度，tpl 唯一例外**：点分标签 → 长度前缀 + 尾 0，
  不吃宽度/重复参数，标签 ≤63B/总长 ≤255B；含 %L 的模板不接受字节列表输入）；
  `{n}` 重复、`{n:sep}` 带分隔符（`{n:}` 缺省 `:`，冒号分隔时输入 `::` = 零填充压缩，
  ip6 `%x2{8:}` 一个模板通吃全 8 组/`::1`/`fe80::1`/`fe80::`）、`{n:[chars]}` 分隔符
  字符类（mac `%x{6:[-.:]}` 容忍 `:`/`-`/`.`）；`%%` 转义。旧内置 `ip4`/`ip6`/`mac`/
  `dns_name` 值原语已下沉为 eng_lib 值函数（`func ip4(s) -> bytes { tpl("%d{4:.}", s) }`、
  `func dns_name(s) -> bytes { tpl("%L", s) }` 等）。
  **域名解析**：`dns("host")` 值原语返回 v4 优先 IP 字符串（`dns(host, 6)` = v6 优先；
  IP 字面量短路无需解析器）；地址**字段**（src/dst/spa/tpa...、layer src/dst）直接接受
  域名回退（按族取首个），值位置的 `ip4`/`ip6` 值函数则需显式 `dns()` 包装
  （headers.pkt 内部 `ip4(dns(src))`/`ip6(dns(dst, 6))` 已处理）。解析经宿主注入的
  `packet_dsl::set_dns_resolver`（prping 在 analyze_file/send_packets 入口
  `ensure_dns_resolver` 注入 ToSocketAddrs 默认解析器）；packet-dsl 本身不发网络请求，
  无解析器时域名报错。默认值也可写域名：`dst=params("dst", "www.baidu.com")`。
- **可变长列表走 proto 机制**（无 reduce/高阶回调——reduce 已移除）：DNS
  questions/answers 用计数 list（`#[meta(list="qdcount", item=...)]`）、HTTP
  headers 用 rest(hdr_line) 重复到空行（`line` + 空行失败终止）——headers.pkt
  的 `hdr_line` 是 proto 子声明。
- **值表达式**：字面量 / 参数引用 / params() / 值调用（原语或值函数）/
  运算链（仅 `+` 数字加法——比较/逻辑已移除）。
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
  `bytes.pkt`：`*_bytes` 层标注包装 + `rand_mac`/`ip4`/`ip6`/`mac`/`dns_name`/`line`
  字节构建值函数（地址值函数 = tpl 模板实现；line = concat∘raw + hex 换行，域名需显式 `dns()`）+ 协议标志位常量
  （`fin`/`syn`/`ack`/`df`/`mf`/`request`/`reply`…，组合用 `bor`，见「值函数/字节原语」）；`net.pkt`：net4/net6；`data.pkt`：
  eth_frame/ip4_packet/net4_packet/net6_packet——raw/hex 载荷 → IP/Eth 层；
  `quic.pkt`：quic_initial/quic_short/quic_crypto——RFC 9000 长/短头 + CRYPTO 帧
  （UDP 封装；长度/token 字段用 vint codec 声明（`#[meta(codec="prefix", ...)]`），`pad` 作 PADDING 帧；保护前
  裸结构，AEAD/头部保护不在 DSL 范围，示例 `examples/quic_initial/`）。
  分发（publish/dist 配方）见 `docs/claude-rules/windows-build.md`。
- 库搜索：`packet-dsl` 的 `find_module(dir, libs, name)`——入口目录（直接+递归）优先，
  库目录**从后往前**逐个搜索（显式 lib 优先于默认 lib/ 目录）；公共 API
  `parse_file_with_libs` / `parse_source_at_with_libs`。
- **默认库目录 = 运行时发现，不再烘焙 eng_lib**：`packet_dsl::default_libs` 找
  二进制同目录 `lib/` + 当前目录 `lib/`（存在才收录，canonical 去重）——二进制
  一律走 `lib/` 布局（`just dist` 产出/同步），仓库 `eng_lib/` 只是同步源。
  测试构建经 `test-stdlib` feature（packet-dsl/prping-core 的 dev-dependencies
  激活，自引用 dev-dep 手法）在发现落空时回退仓库 `eng_lib/`——测试与产物行为分离，
  产物永不读 eng_lib。
- **import 按模块解析**：同名文件在不同目录可共存，每个 import 绑定到**自身模块目录**
  找到的模块实例（`ModuleGraph.module_imports` 存每模块 import 边，无全局名字表）——
  入口目录的本地文件（如自己的 headers.pkt）遮蔽库同名模块；结果不依赖 import 顺序。
- **import 别名**：`import a { x as ax }`——`ax` 以别名进入作用域，解析目标仍是 `x`
  （`ScopeEntry::Imported(module, orig)` 携带原名，`lookup`/`resolve_final` 用原名定位），
  同名导出冲突可消解；`as` 非保留字。`engine` 的 `imports:` 行显示 `x as ax`。
- **库导出隐式可见**：libs 下所有模块的命名导出（export:）自动进入每个模块作用域，
  脚本无需 `import` 直接调用（prelude 语义）。实现：`build_graph` 先把库模块
  （`ModuleData.is_lib`）入图（先入队库种子、最后入队入口，保证入口下标 0）、
  `resolve_names` 最后注入库导出（已占用名不覆盖）——显式 import / 本地定义优先遮蔽。
  **prelude 转出口**：`export: tcp`（tcp 来自 prelude）可再被 `import b { tcp }` 引入——
  作用域查不到时 `find_lib_export` 回退到库模块集合（须「导出且本地定义」才可作求值目标）。
  **库目录诊断**：库目录不可读 / 库模块语法错 / 同一库目录内导出名重复 → 报错（带文件+span）；
  跨目录同名导出允许（显式 lib 覆盖标准库）。
- prping `--lib PATH`（可多次，engine/packet 子命令）：`resolve_libs` 只归集 --lib
  （默认 lib/ 由 `default_libs` 运行时发现合并）；analyze_file/send_packets/LSP
  （LspServer.libs）全链路携带。
- 值位置 hex：`hex("...")` 在参数值位置解析为字节列表 Value（parser `hex_call`），
  与层位置 `hex(...)`（Raw 载荷层）并存。

## 运行时参数（--params / 配方全局 Globals）

- `--params k=v,k2=v2`（可重复）注入；packet-dsl 的 `Value::Param`（`params("name"[, "默认值"])`
  值引用）在求值时从 `Params` 表取值，各类型 coercer（端口/地址/flags/MAC/字符串/载荷）统一经
  `as_param` 解析；`resolve_with_params` / `resolve_sources_with_params` 为带参数求值入口。
- 配方全局：`Globals`（`HashMap<String, Value>`，类型化）+ `global("名"[, 默认])` 值原语
  （eval_value Call 臂特判、延迟求值默认，与 params 对称——doc-sync 脚本把 global 并入
  分派集合）；入口 `resolve_with_globals` / `resolve_sources_with_globals` /
  `eval_sniffer_value_with_globals`（sniffer 匹配值可引用全局）/
  `eval_extract_value`（extract 的 from 表达式求值，宿主注入回包访问器——`reply` 原语
  读取回包反解字段；`parse_value_expr` 解析单个值表达式）。
