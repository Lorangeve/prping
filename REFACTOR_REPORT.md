# prping 代码重合分析与重构建议报告

> 生成方式：分 9 个分析 agent（8 条子命令各一个 + 1 个全库交叉扫描），
> 主控对关键发现逐条 grep/read 交叉验证后汇总。

---

## 1. 概述

prping 是一个跨平台 psping 复刻（Rust，workspace 双 crate：`prping-core` 核心库 + `prping-cli` CLI 胶水）。

**总体结论**：代码结构整体良好，共享逻辑已经过一轮收敛（`drive.rs` 统一 ping 循环骨架、`stats.rs` 统一统计、`util/*` 统一 socket/DNS/格式原语、`output.rs` 统一颜色、`rawpcap.rs` 统一 Npcap/libpcap 抓包基础设施）。剩余重复集中在 **4 类**：

1. **CLI 胶水层（main.rs）**：4 个 `run_*` 重复构造 22 字段 `PingConfig` 字面量、3 个 Args struct 重复 12 个字段、`dispatch_run` 7 个 Err 分支复制粘贴 —— 全部是机械重复，风险低收益高。
2. **测量模式渲染层**：ICMP/TCP/UDP/latency 四个模式各有几乎相同的 `print_reply` 式逐行渲染、入口头部打印模板、ICMP 应答解析、TCP connect 失败处理、UDP 收发超时循环。
3. **serve 抓包层（capture.rs 内部）**：三平台 4 处过滤逻辑、`ip_meta`/`ip_summary` 双份 IP 头解析、`show_frame`/`show_bare_ip` 双份展示。
4. **引擎层（engine/ 双模块）**：`layer_name`/`layer_kind` 双份层名映射、`hex_str` 双份、k=v 参数解析双份、--out pcap 序列化双份、DNS 解析三套、配方初始化双份、analyze/send 入口模式重复。

> 注意：`serve/capture.rs` 与 `engine/pkg/sniffer.rs` 之间**不存在**复制粘贴级重复（前者手工解析字节、后者操作 IR 层，见 §4.5）；
> `capture.rs` 复用 `rawpcap.rs` 是健康的消费关系，不是重复。

**统计**：9 个 agent 共报告 80 余条候选发现，合并跨 agent 重复（如 layer_kind/layer_name 被 3 个 agent 独立发现）后约 **42 处独立重复点**：
`high`（复制粘贴级）21 处 / `medium`（结构相似）18 处 / `low`（概念重合）3 处，详见 §4 清单（以清单为准）。
其中**最值得优先处理**的 6 组：CLI 四份 PingConfig 字面量（C-1）、四份逐行渲染（M-1）、trace 三变体逐跳骨架 + ICMP 错误解析（M-9/M-10/M-11）、bandwidth 绕过 drive（M-6）、capture 内部双份（S-2/S-3/S-4）、IHL 解析 20+ 处内联（M-16）。

---

## 2. 分析方法

- **分 agent 逐子命令**：ping / latency / bandwidth / server / trace / engine / packet / document+CLI 胶水，各一个独立 agent 分析其完整代码路径；另加一个全库交叉扫描 agent。
- **三档分类**：
  - `high` = 复制粘贴级（几乎相同代码，可直接合并）
  - `medium` = 结构相似（同一逻辑的变体，可收敛到共享函数/泛型/宏）
  - `low` = 概念重合（抽象类似但实现差异大，收敛收益低）
- **人工交叉验证**：主控对 high 置信发现逐条 grep/read 复核（例如 `layer_kind`/`layer_name`、4 份 `print_reply`、4 处 `PingConfig {` 字面量、`0xFF` 魔数散布、`bandwidth.rs` 循环 vs `Run::done()`）。

---

## 3. 子命令代码地图

| 子命令 | CLI 入口（main.rs） | lib 分派 | 核心模块 |
|---|---|---|---|
| ping | `PingArgs`(131) / `ping_cmd`(271) / `validate_ping`(606) / `run_ping`(755) | `run()`: mtu → tcp/udp ping → icmp ping | `ping/icmp.rs` `ping/icmpwin.rs` `ping/tcp.rs` `ping/udp.rs` `ping/mtu.rs` |
| latency | `LatencyArgs`(151) / `latency_cmd`(307) / `run_latency`(805) | `run()`: size+port 分支 | `ping/latency.rs`（Probe 实现） |
| bandwidth | `BandwidthArgs`(171) / `bandwidth_cmd`(343) / `run_bandwidth`(857) | `run()`: bandwidth 分支 | `ping/bandwidth.rs`（独立循环，不用 drive） |
| server | `ServerArgs`(189) / `server_cmd`(374) / `run_server`(902) | `serve()` | `serve/mod.rs` `serve/capture.rs` |
| trace | `TraceArgs`(200) / `trace_cmd`(399) / `run_trace`(934) | `run()`: traceroute 分支 | `ping/trace/{mod,icmp,tcp,udp,tcpwin,dns}.rs` |
| engine | `EngineArgs`(214) / `engine_cmd`(433) / `run_engine`(1010) | 直接调 lib engine API | `engine/eng/*` `engine/recipe.rs` `engine/convert.rs` `engine/pcap.rs` `engine/rawpcap.rs` |
| packet | `PacketArgs`(238) / `packet_cmd`(491) / `run_packet`(1055) | 直接调 lib pkg API | `engine/pkg/*` `engine/rawpcap.rs` |
| document | `DocumentArgs`(254) / `document_cmd`(535) / `run_document`(1098) | `manual.rs` | `manual.rs`（`print_paged`/`find_sections`/`toc`） |

共享基础设施：`drive.rs`（循环骨架）、`stats.rs`（统计+渲染）、`output.rs`（颜色）、`util/{config,dns,net,socket,format,interrupt}.rs`、`engine/rawpcap.rs`（抓包底层）。

---

## 4. 代码重合清单

### 4.1 CLI 胶水层（main.rs）—— 机械重复，优先重构

| # | 位置 A | 位置 B | 内容 | 档 |
|---|---|---|---|---|
| C-1 | `main.rs:777-801` (run_ping) | `main.rs:829-853` / `874-898` / `940-964` | **`PingConfig` 22 字段字面量构造重复 4 次**，其中 14 个字段值完全相同（`parallel:1, bandwidth:false, mtu:false, traceroute:false, trace_tcp:false, trace_udp:false, max_hops, no_dns:false` 等）；实测 grep `PingConfig {` 在 main.rs 命中 4 处 | high |
| C-2 | `main.rs:131-148` (PingArgs) | `main.rs:151-168` (LatencyArgs) / `171-186` (BandwidthArgs) | 三个 struct **12 个字段完全相同**（udp/size/count/interval/quiet/histogram/warmup/json/v4/v6/source/lang/target），三个 `cmd()` 构造同步重复 | high |
| C-3 | `main.rs:708-749` (dispatch_run) | 同函数其余分支 | **7 个 `PrpingError` 分支全部是** `drop(ctrl_echo) + writeln_red + exit(1)` 三行复制粘贴，仅错误消息不同（第 8 个 `Err(e) => return Err(e.into())` 透传除外） | high |
| C-4 | `main.rs:606-644` (validate_ping) | `646-648`/`650-652`/`656-664` (validate_*) + `667-680` (bad_histogram) + `592-603` (json_conflicts) | 校验函数模式重复（bad_histogram 的 `Option` 判定、json_conflicts 三连 if），但各校验真逻辑不同，收敛收益中等 | medium |
| C-5 | `main.rs:1164-1203` (detect_locale) | `main.rs:685-689` (apply_lang) / `1255-1273` (main 里 --lang pre-scan) | **locale 设置逻辑分散 3 处**，都调 `rust_i18n::set_locale(&normalize_locale(...))` | medium |
| C-6 | `main.rs:1554` (`static INTERRUPT_COUNT`) | `util/interrupt.rs:7`（同名 static） | **两个 crate 各有一个同名 `INTERRUPT_COUNT`**（main 的计数 Ctrl+C 次数，util 的仅被 `reset_interrupt` 使用），同名异义易混淆；bin 侧信号处理器调 `set_interrupted(true)`，计数/职责边界模糊 | medium |

### 4.2 测量模式层（ping / trace / latency / bandwidth）

| # | 位置 A | 位置 B | 内容 | 档 |
|---|---|---|---|---|
| M-1 | `ping/udp.rs:141-162` (print_reply) | `ping/latency.rs:226-247` (print_latency) | **函数体逐行一致**：`print_green(reply_from) → print_cyan(ip) → ":" → print_magenta(port) → bytes → print_yellow(rtt) → warmup 后缀`，仅变量名不同；`ping/icmp.rs:203-224` 同结构多 TTL 字段；`ping/tcp.rs:97-120` (print_connected) 同结构 | high |
| M-2 | `ping/icmp.rs:39-63` | `ping/tcp.rs:19-45` / `ping/udp.rs:18-44` | 入口头部打印模板重复：`resolve → print_resolving → 标题 → duration/infinite/iterations 三分支` | high |
| M-3 | `ping/icmp.rs:265-320` (parse_reply) | `ping/trace/icmp.rs:138-251` (parse_reply_v4/v6) | ICMP 应答解析重复：外层 IP 头偏移判断（`buf[0]>>4==4/6`）、type 分派（0/3/11）、id/seq 匹配（`u16::from_be_bytes([icmp[4],icmp[5]])`）；trace 版额外处理 Time Exceeded 内嵌报文；`ping/mtu.rs:196-260` (classify) 是第三处（额外处理 Frag Needed type3/code4） | high |
| M-4 | `ping/tcp.rs:75-94` (TcpProbe::probe) | `ping/latency.rs:64-74` (LatencyTcpProbe::probe) | TCP connect 失败处理完全相同：`connect_first → Err → if !quiet && !json → writeln_red(connect_failed) → ProbeOutcome::Err{json_err:"connect failed"}` | high |
| M-5 | `ping/udp.rs:87-137` (UdpProbe::probe) | `ping/latency.rs:189-222` (LatencyUdpProbe::probe) / `ping/bandwidth.rs:471-474` | UDP 发送+超时接收模式重复：`udp_send → smol::future::or(udp_recv, Timer)`，差异仅超时常量（4s/10s/5s）与是否 seq 校验 | medium |
| M-6 | `ping/bandwidth.rs:234-255, 278-295, 322-367`（4 个循环） | `drive.rs:50-79` + `util/interrupt.rs:37-76` (Run) | **bandwidth 独立循环内联重写了 `Run::done()` 的控制逻辑**（`interrupted()` + deadline + count 三条件 break，实测每个循环都有 `if util::interrupted() { break }` + `deadline.is_some_and(...)` + count 检查）——drive 骨架唯一的漏网模式 | high |
| M-7 | `ping/bandwidth.rs:210,225,271,329` | `ping/latency.rs:75` / `serve/mod.rs:226` | `connect + set_nodelay(true)` 组合出现 6 次 | medium |
| M-8 | `ping/latency.rs:79` / `ping/bandwidth.rs:226`（客户端 0xFF） | `serve/mod.rs:138,250`（服务端 0xFF 校验） | **TCP 接收模式触发魔数 `0xFF` 硬编码 3 处**，未定义常量（UDP 侧有 `util/format.rs::udp_receive_trigger` 收敛，TCP 侧没有）；`65507` 字面量在 `lib.rs:286` / `util/format.rs:50` / `ping/mtu.rs:75` 三处；`33434` 仅在 `trace/udp.rs:13` 有常量、`lib.rs:230` 注释重复 | medium |
| M-9 | trace 三变体的逐跳循环 | `trace/icmp.rs:26-128` vs `trace/udp.rs:29-132`（tcp.rs:60-228 同构） | **逐跳循环骨架几乎逐行相同**：`for hop_no → interrupted → set_ttl → 发送探测 → 收集回复（deadline/rtts/recv_from/parse）→ finish_hop → dest_hit break`；三变体仅发送/解析协议不同，可用泛型骨架+闭包收敛（约 300 行） | high |
| M-10 | IPv4 ICMP 错误报文解析（type 11 Time Exceeded → 内嵌 IP 头 → inner_dst） | `trace/icmp.rs:163-192` / `trace/tcp.rs:366-399` / `trace/udp.rs:138-175` / `trace/tcpwin.rs:219-248` | **同一逻辑写 4 遍**：inner_ihl 计算、内嵌 dst 提取、内嵌传输层头读取 | high |
| M-11 | IPv6 回复「框架探测」（`buf[0]>>4==6 → &buf[40..]`） | `trace/icmp.rs:211-215` / `trace/tcp.rs:404-408` / `trace/udp.rs:180-184` | 三处 3 行代码完全相同；Time Exceeded 内嵌 dst=body[24..40] 同样三处重复 | high |
| M-12 | 校验和折叠逻辑（`while sum>0xFFFF { sum=(sum&0xFFFF)+(sum>>16) } !(sum)`） | `trace/tcp.rs:272-305` (tcp_checksum) vs `ping/icmp.rs:360-373` (icmp_cksum) | tcp_checksum 额外加伪头部，核心 fold-and-negate 与 icmp_cksum 相同；tcpwin.rs 直接复用 icmp_cksum 反证可合并 | medium |
| M-13 | recv_from 超时/错误 match 分支 | `trace/icmp.rs:112-118` vs `trace/udp.rs:116-122` | `Err(e) if WouldBlock||TimedOut => break; Err(_) => break` 完全相同 | high |
| M-14 | TCP 回包匹配（IP 头→src 校验→sport/dport 镜像→flags） | `trace/tcp.rs:307-332` (Unix raw) vs `trace/tcpwin.rs:176-251` (Windows Npcap) | 核心相同，仅差 14B 以太网帧偏移；ICMP Time Exceeded 分支同理 | medium |
| M-15 | 反向 DNS 平台封装（sockaddr 构造→getnameinfo→CStr） | `trace/dns.rs:18-62` (Unix) vs `trace/dns.rs:64-112` (Windows) | 结构对称的平台抽象，已有 cfg 拆分；合并需 trait 抽象，收益有限 | low |
| M-16 | IPv4 IHL 解析（`(buf[0]&0x0F)*4` + 长度检查 + `&buf[ihl..]`） | 散布于 `trace/icmp.rs:147` / `trace/udp.rs:142` / `trace/tcp.rs:317,370` / `trace/tcpwin.rs:194` / `ping/icmp.rs:278` / `ping/mtu.rs:230` / `serve/capture.rs:167,251` | **同一表达式内联 20+ 处**（含内嵌 inner_ihl 4 处），应提取 `ipv4_ihl(buf)` 等工具函数（cross-cutting X1） | high |
| M-17 | 65536 字节接收缓冲区字面量 | `ping/bandwidth.rs:229,458` / `serve/mod.rs:131,227,251` / `serve/capture.rs:1043` / `util/net.rs:199` | **`vec![0u8; 65536]` 硬编码 6+ 处**，应收敛为 `const RECV_BUF_SIZE`（cross-cutting X7） | medium |
| M-18 | TCP SYN 头填充（sport/dport/seq/ack/offset+flags/window=65535/checksum） | `trace/tcp.rs:246-267` (build_tcp_syn, Unix raw 20B) vs `trace/tcpwin.rs:257-305` (build_syn_frame, Windows Npcap 14+20+20B) | TCP 头字段填充逐字段对应，tcpwin 仅多以太网头 + IPv4 头（cross-cutting X4） | medium |

### 4.3 serve / 抓包层

| # | 位置 A | 位置 B | 内容 | 档 |
|---|---|---|---|---|
| S-1 | `serve/mod.rs:142-150` ([udp-trigger]) | `serve/mod.rs:184-191` ([udp-echo]) / `238-248` ([recv]) | **verbose dissect+打印 3 处几乎相同**：`guard(verbose && !capture_active) → dissect → print_green 标签 → print_cyan 地址 → 字节数 → render_dissected`，仅标签/地址格式/header 参数不同 | high |
| S-2 | `capture.rs:1076-1088` (linux_loop) | `capture.rs:1162-1174` (windows_loop) / `1281-1293` / `1298-1310` (macos 两分支) | **三平台 4 处抓包过滤逻辑相同**：`match (&filter,&expr) { ServiceFilter → matches_frame / FilterExpr → dissect+FrameCtx+matches_ctx / None → true } → show_frame` | high |
| S-3 | `capture.rs:144-191` (ip_meta) | `capture.rs:223-280` (ip_summary) | **双份手动 IPv4/IPv6 头解析**（约 80 行复制）：版本检查、ihl 计算、分片检测、src/dst 提取、端口提取；差异仅 ip_meta 限 TCP/UDP、ip_summary 支持全部协议 | high |
| S-4 | `capture.rs:474-485` (show_frame) | `capture.rs:535-546` (show_bare_ip) | 函数体几乎相同，唯一差异是摘要函数（frame_summary vs bare_ip_summary） | high |
| S-5 | `capture.rs:310-322` (proto_name，9 协议) | `engine/eng/display.rs:454-458`（describe_raw_bytes 内联 3 协议版） | 协议号→名称映射功能等价、覆盖不同 | medium |
| S-6 | `engine/pkg/sniffer.rs:634-647` (layer_kind → String) | `engine/eng/display.rs:372-385` (layer_name → &'static str) | **10 个 Layer 变体映射完全相同**，仅返回类型不同（实测两函数都存在）；与 §4.4 E-1 同一处，重复级别为复制粘贴级 | high |

### 4.4 引擎层（engine / packet）

| # | 位置 A | 位置 B | 内容 | 档 |
|---|---|---|---|---|
| E-1 | `engine/pkg/sniffer.rs:634-647` (layer_kind) | `engine/eng/display.rs:372-385` (layer_name) | 10 个 Layer 变体映射完全相同，仅返回类型不同（String vs &'static str）——与 §4.3 S-6 同一处 | high |
| E-2 | `main.rs:1364-1379` (parse_params) | `engine/recipe.rs:674-687` (parse_params_list) | **k=v 逗号分割解析逻辑几乎相同**（split(',') → trim → split_once('=')），仅输入类型与错误信息不同 | high |
| E-3 | `engine/pkg/send.rs:37-68` | `engine/pkg/recipe.rs:189-206` | **--out pcap 序列化逻辑重复**：fuzz 判断 + DefaultSerializer 构造 + linktype_of 推断 + write_pcap | high |
| E-4 | `engine/pkg/sniffer.rs:66-142` (sniffer_extract) | `engine/eng/display.rs:638-722` (describe_layer) | 逐层枚举字段名做字段提取/描述，字段集高度重叠（一个返回 FVal 供匹配、一个返回 String 供展示） | medium |
| E-5 | `main.rs:1348-1361` (resolve_target) | `engine/eng/mod.rs:225-236` (ensure_dns_resolver) / `util/dns.rs:56-83` (resolve_vec) | **三套 DNS 解析**：ToSocketAddrs + v4 优先排序逻辑重复（util/dns.rs 有 smol::unblock 包装） | medium |
| E-6 | `engine/pkg/recipe.rs:20-87` (send_recipe) | `engine/eng/mod.rs:531-705` (analyze_recipe) | 配方公共初始化重复：ensure_dns_resolver + ensure_proto_registry + parse + collect_pkt_params + 头部打印（标题/步数/globals/params/libs） | medium |
| E-7 | `engine/pkg/send.rs:728-809` (send_payload) | `engine/pkg/raw.rs:25-100` (send_raw_bytes) | Reply{rtt,bytes,matched} 构建模式类似，但数据来源（TCP/UDP/raw ICMP）与平台差异大 | low |
| E-8 | `engine/eng/display.rs:404-406` (hex_str) | `engine/convert.rs:619-621` (hex_str) | **`hex_str` 函数体逐字节相同**（实测确认）：`b.iter().map(|x| format!("{x:02x}")).collect()` | high |
| E-9 | `engine/eng/mod.rs:487-528` (analyze_file) | `engine/pkg/send.rs:24-35` (send_packets) | 共享入口模式：ensure_dns → ensure_proto → parse_file_with_libs → resolve_sources_with_globals → total==0 检查 | medium |
| E-10 | `engine/eng/mod.rs:534-564` (analyze_recipe 校验) | `engine/pkg/recipe.rs:396-442` (apply_extract) | 同一 extract 列表：分析侧校验（sniffer_field_names）、执行侧提取（sniffer_extract）各写一遍遍历 | medium |
| E-11 | `engine/eng/display.rs:416-603` (describe_raw_bytes) | `engine/pkg/sniffer.rs:67-141` (sniffer_extract) | 同一层字段集合的两种消费（raw 字节解析→展示串 vs IR 字段→FVal 规范值），字段名集合高度重合（与 E-4 同源） | medium |
| E-12 | `engine/eng/lsp.rs:231-236` (diagnostics) | `engine/eng/mod.rs:487-528` (analyze_file) | LSP 从内存文本解析、engine 从文件解析，parse+resolve 流程等价但入口不同，收敛收益低 | low |
| E-13 | `engine/eng/display.rs:333-343` (print_red_plain/print_bold_plain) | `output.rs:40-44, 47-52` (print_red/print_bold) | **display.rs 内两个去泛型副本**（直接用 &str 而非 impl AsRef<str>），逻辑与 output.rs 完全相同（cross-cutting X9） | medium |

> **已排除的嫌疑**：`engine/recipe.rs`（配方类型定义+解析）与 `engine/pkg/recipe.rs`（配方执行）**不是重复**——pkg/recipe.rs 是消费者（`use crate::engine::recipe::{ExtractAs,OnError}` + `parse(file)`），类型单点定义，职责清晰。`engine/pcap.rs`（文件读写）与 `engine/rawpcap.rs`（实时抓包）职责不同。

### 4.5 跨模块核实结论（重要）

- **`serve/capture.rs` ↔ `engine/pkg/sniffer.rs`：无复制粘贴级重复**。capture 手工解析字节帧（`frame_meta`/`ip_meta`，在 dissect 前做快速过滤），sniffer 操作 `packet_dsl::ir::Layer` 语义 IR 做回包匹配。输入、用途、实现都不同（`low`）。
- **`serve/capture.rs` ↔ `engine/rawpcap.rs`：健康的消费关系**。capture 的 Windows/macOS 路径复用 `rawpcap::list_devices/capture_devices/open_capture/format_device_list`（实测 grep 确认），Linux AF_PACKET 循环内联在 capture（平台差异使然）。`ping/trace/tcpwin.rs`、`engine/pkg/raw.rs` 同样复用 rawpcap —— 这是**已收敛的好架构**。
- **`engine/pcap.rs` ↔ `engine/rawpcap.rs`：职责不同**（pcap 文件格式读写 vs 实时抓包设备），无代码重复、仅概念重合（`low`，engine agent E-7 确认）。
- **`engine/recipe.rs` ↔ `engine/pkg/recipe.rs`：职责互补而非重复**（解析 vs 执行，pkg 侧 `use crate::engine::recipe::{ExtractAs,OnError}` 是消费者，cross-cutting X12 确认）。
- **`serve/capture.rs:946-981` ↔ `engine/pkg/raw.rs:179-231`：AF_PACKET 打开代码重复**（cross-cutting X8，medium）——两处都做 `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)` + sockaddr_ll 填充 + bind，差异仅 ifindex（全接口 vs 指定接口），可收敛到 `util::socket::open_af_packet(ifindex)`。

---

## 5. 共享基础设施现状

已收敛良好（无需动作）：

| 共享件 | 职责 | 消费方 |
|---|---|---|
| `drive.rs::drive` + `Probe` trait | 循环骨架（间隔/预热/统计/JSONL/收尾） | icmp/tcp/udp/latency（bandwidth 例外，见 M-6） |
| `stats.rs::Stats` | min/max/avg/stddev/jitter/percentile/直方图/时间线 + 汇总渲染 | 所有测量模式 + bandwidth 报告 |
| `output.rs` | termcolor 颜色封装 + indent/spaces/pad_to + print_server_log | 全 crate |
| `util/net.rs` | bind_udp / connect_timeout / connect_first / init_slice / configure_executor_threads / drain_after_send | 所有测量 + serve |
| `util/socket.rs` | create_icmp/tcp/udp_socket / set_ttl / icmp_offset_v4 / raw_socket_error | icmp/trace/mtu |
| `util/format.rs` | rand / echo_fill / unix_ts / format_bytes / udp_receive_trigger | 所有测量 + serve |
| `util/dns.rs` | resolve / resolve_vec / resolve_source / local_bind / print_resolving | 所有测量 + packet |
| `util/interrupt.rs` | interrupted / set_interrupted / reset_interrupt + Run | drive + bandwidth + serve |
| `engine/rawpcap.rs` | Npcap/libpcap 设备枚举/抓包/注入 + MAC 解析 | capture.rs / tcpwin.rs / pkg/raw.rs |

---

## 6. 重构建议（按优先级）

### P0 —— 机械提取，低风险高收益（有测试覆盖，行为不变）

- [x] 1. **合并 4 份逐行渲染函数（M-1）**：在 `output.rs` 提取
   `print_probe_result(w, addr, port_opt, size_opt, rtt, ttl_opt, warmup)`，
   `udp.rs::print_reply` / `latency.rs::print_latency` / `icmp.rs::print_reply` / `tcp.rs::print_connected` 统一调用。
   涉及：`ping/{icmp,tcp,udp,latency}.rs`、`output.rs`。
- [x] 2. **PingConfig 构造收敛（C-1）**：实现 `PingConfig::builder()` 或 `PingConfig { ..Default }` 覆盖差异字段，
   消除 main.rs 4 处 22 字段字面量（约 80 行）。涉及：`util/config.rs`、`main.rs`。
- [ ] 3. **CLI 共享选项块（C-2）**：提取 `struct MeasureCommon { udp,size,count,interval,quiet,histogram,warmup,json,v4,v6,source,lang,target }` +
   `fn measure_common() -> impl Parser<...>`，三个 cmd() 组合它。涉及：`main.rs`。
- [x] 4. **dispatch_run 错误分支 helper（C-3）**：`fn fail(ctrl_echo, msg)` 收敛 7 个分支。涉及：`main.rs`。
- [x] 5. **合并 verbose dissect（S-1）**：`serve/mod.rs` 提取 `fn verbose_dissect(tag, addr, header, data, n, verbose, capture_active)`。涉及：`serve/mod.rs`。
- [x] 6. **TCP 触发魔数常量（M-8）**：`const TCP_RECEIVE_TRIGGER: u8 = 0xFF` 放 `util/format.rs`，客户端/服务端共用；
   `MAX_UDP` 提升为 pub 常量消除三处 65507 字面量。涉及：`util/format.rs`、`ping/{latency,bandwidth,mtu}.rs`、`serve/mod.rs`、`lib.rs`。

### P1 —— 结构收敛，中等风险（需对齐行为语义）

7. **ICMP 应答解析统一（M-3）**：提取共享类型
   `enum IcmpReply { EchoReply{id,seq,ttl,size}, TimeExceeded{...}, Unreachable, FragNeeded{...}, Unknown }`
   到 `util/`（或 `ping/icmp.rs` 公开），`parse_reply` / `trace::icmp::parse_reply_v4/v6` / `mtu::classify` 三个实现
   统一调用，各自只做语义映射。涉及：`ping/{icmp,mtu}.rs`、`ping/trace/icmp.rs`。
- [x] 8. **TCP connect 收敛（M-4 / M-7）**：`util/net.rs` 提取 `connect_timed(addrs, source) -> Result<(TcpStream, Duration)>`
   （connect_first + elapsed + set_nodelay），tcp/latency Probe 共用；bandwidth 的 4 处
   `connect_timeout + set_nodelay` 用一个包装函数收敛。
9. **UDP 超时收包收敛（M-5）**：`util/net.rs` 提取 `udp_recv_timeout(sock, buf, timeout, seq_filter: Option<u16>)`，
   udp/latency/bandwidth 三处共用（seq_filter 控制是否过滤杂包）。
- [x] 10. **capture 内部收敛（S-2/S-3/S-4）**：提取 `fn should_show(data, filter, expr) -> bool`（4 处）、
    `fn parse_ip_header<T>(buf, v6: bool, mode) -> Option<T>`（合并 ip_meta/ip_summary）、
    `fn show_frame_inner(data, summary_fn)`（合并 show_frame/show_bare_ip）。涉及：`serve/capture.rs`（单文件内部，收益大）。
- [x] 11. **layer_kind 收敛（S-6 / E-1）**：`sniffer.rs::layer_kind` 改为 `&'static str` 或直接调 `display.rs::layer_name`。
    `proto_name`（S-5）提升到共享位置，display.rs 复用。
- [x] 12. **trace 逐跳骨架泛型化（M-9/M-10/M-11/M-13）**：提取
    `hop_loop<F,G>(cfg, target_ip, max_hops, send_probes: F, recv_reply: G) -> (Vec<Hop>, bool)`，
    三变体注入各自的发送/解析闭包；同时把 IPv4 ICMP 错误解析（4 处）、IPv6 框架探测（3 处）收敛为
    `parse_icmp_error_v4/v6(buf, target)` 共享函数。涉及：`ping/trace/{icmp,tcp,udp,tcpwin}.rs`。**收益最大的一组**（约 400 行）。
- [x] 13. **k=v 参数解析统一（E-2/P-2）**：`main.rs::parse_params` 与 `engine/recipe.rs::parse_params_list` 合并为
    `fn parse_kv_pairs(s: &str)` 单点实现。涉及：`main.rs`、`engine/recipe.rs`。
14. **--out pcap 序列化收敛（E-3）**：`fn collect_out_pcap(opts, sources)` 收敛 send.rs 与 recipe.rs 的
    fuzz/serializer/linktype/write_pcap 链。涉及：`engine/pkg/{send,recipe}.rs`。
- [x] 15. **DNS 解析三套收敛（E-5）**：`main.rs::resolve_target` 与 `eng/mod.rs::ensure_dns_resolver` 改用
    `util/dns.rs::resolve`（统一 smol::unblock + v4 优先）。涉及：`main.rs`、`engine/eng/mod.rs`、`util/dns.rs`。
16. **配方公共初始化（E-6/P-6）**：`fn prepare_recipe(path, libs, params, globals)` 收敛 send_recipe/analyze_recipe
    的 ensure→parse→collect_pkt_params→头部打印链。涉及：`engine/pkg/recipe.rs`、`engine/eng/mod.rs`。
- [x] 17. **hex_str 去重（E-8）**：提取到共享位置（`engine/mod.rs` 或 `util/format.rs`），display.rs 与 convert.rs 共用。
- [x] 18. **TCP 回包匹配合并（M-14）**：`match_tcp_syn_reply(ip_payload, target, dport, want)` 供 trace/tcp.rs 与 tcpwin.rs
    共用（tcpwin 调用前跳过 14B eth 头）。
- [x] 19. **IHL/框架探测工具函数（M-16，cross-cutting R1）**：`util/socket.rs` 增加 `ipv4_ihl(buf)` / `ipv6_frame_skip(buf)` /
    `inner_ipv4_ihl(buf)`，替换 20+ 处内联 `(buf[0]&0x0F)*4` 与 7 处 `buf[0]>>4==6 → &buf[40..]`。涉及：`util/socket.rs`、`ping/{icmp,mtu}.rs`、`ping/trace/*.rs`、`serve/capture.rs`。
- [x] 20. **缓冲/协议常量收敛（M-17 / M-8，cross-cutting R4/R7）**：`const RECV_BUF_SIZE: usize = 65536` 消除 6 处字面量；
    对称提取 `parse_udp_receive_trigger(data) -> Option<(usize,u32)>` 与现有 `udp_receive_trigger` 配套（serve/mod.rs 与 bandwidth 解析侧复用）。
21. **AF_PACKET 打开收敛（cross-cutting R6）**：`util::socket::open_af_packet(ifindex)` 供 capture.rs（全接口）与 pkg/raw.rs（指定接口）共用。
- [x] 22. **display.rs 颜色副本删除（cross-cutting R8）**：`print_red_plain`/`print_bold_plain` 直接改调 `output::print_red`/`print_bold`（Rust 自动解引用兼容 &str）。
23. **TCP SYN 构建 + 校验和收敛（M-18 / M-12，cross-cutting R9）**：TCP 头字段填充提取 `fn fill_tcp_header(buf, sport, dport, seq, flags, window)` 供 Unix/Windows 两条路径共用；校验和提取 `inet_checksum(data)` + `pseudo_checksum(proto, src, dst, payload)`，icmp_cksum / tcp_checksum / IP 头校验和统一调用。涉及：`ping/icmp.rs`、`ping/trace/{tcp,tcpwin}.rs`。

### P2 —— 架构级调整，高风险（需设计讨论）

25. **bandwidth 收编进 drive 骨架（M-6）**：将 `Probe` 泛化为更通用的测量 trait（如返回
    `Measurement::Rtt(Duration) | Measurement::Bytes(u64)`），drive 统一管理循环控制+warmup+JSONL+收尾，
    bandwidth 只实现「一次发送批次」与进度条。收益：消除约 200 行循环重复，统一 -n/-n s 语义。
    风险：bandwidth 的进度条、`--parallel` 并发、报告形态与 ping 不同，需仔细设计 trait 边界。
26. **CLI 选项体系重构（C-1+C-2 深度版）**：考虑把「测量选项」下沉为 lib 的 `MeasureOptions` 由 `PingConfig::from_opts(...)` 转换，
    CLI 只声明差异。
27. **Layer 字段遍历统一（E-4/E-6/E-11）**：设计 `LayerFields` trait 或按层字段表驱动
    `sniffer_extract` 与 `describe_raw_bytes`/`describe_layer`，新增协议时只改一处。短期收益中等。
28. **rawpcap.rs 拆分（E-12 附带建议）**：1068 行混合设备选择/MAC 解析（Windows iphlpapi / Unix getifaddrs）/pcap 发送/回包等待，
    可拆 `rawpcap/{device,mac,send}.rs` 降低单文件复杂度。

---

## 7. 建议实施顺序

1. 先做 P0（CLI + 渲染层机械提取：合并 print_probe_result、PingConfig 构造收敛、共享选项块、dispatch_run helper、verbose_dissect、魔数常量），测试覆盖下安全，一次提交可完成。
2. 再做 E-8/P-2/P-3（hex_str、k=v 解析、--out pcap 序列化）等小文件级去重。
3. P1-7/8/9（测量层行为对齐，需跑 `cargo test --workspace --all-targets` + 实际 ping 验证）。
4. P1-12/19（trace 逐跳骨架 + IHL 工具函数，收益最大，改动集中在 trace/ 目录，先出骨架设计再动工）。
5. P1-10/11（capture 单文件重构，改动集中，需 `just check-all` 验证三平台编译）。
6. P1-20/21/22（常量与平台收敛，独立小提交）。
7. P2-23（drive 泛化）与 P2-25/26 单独排期，先出设计再动工。
8. 全程遵守：`cargo clippy` 零警告 + `cargo fmt` + `cargo test --workspace --all-targets`（494 tests）+ 平台相关改动跑 `just check-all`。

---

## 8. 附录：各子命令 agent 原始发现

- ping：8 处中高置信（含 4 处 print_reply 级渲染、ICMP 解析、PingConfig 字面量）→ 已并入 §4.1/§4.2（C-1..C-6、M-1..M-8）。
- latency：10 处（print_latency=print_reply、TCP connect 模式、UDP 超时模式、0xFF 魔数、CLI 三 struct/run_* 重复）→ 已并入。
- bandwidth：13 条（drive 骨架缺失、run_tcp/run_udp 内部对称重复、进度条、set_nodelay×4、CLI 构造重复）→ 已并入 §4.2。
- server：9 条（verbose 3 处、capture 过滤 4 处、ip_meta/ip_summary、show_frame/show_bare_ip、proto_name/layer_kind）→ 已并入 §4.3。
- trace：7 处（逐跳骨架三变体同构、IPv4 ICMP 错误解析 4 处、IPv6 框架探测 3 处、校验和折叠、TCP 回包匹配双份、recv 超时分支）→ 已并入 §4.2（M-9..M-15）。
- engine：8 处（layer_kind/layer_name、hex_str 双份、parse_params_list、analyze/send 入口模式、配方校验/提取双遍历、字段枚举、LSP 入口）→ 已并入 §4.4（E-1..E-12）。
- packet：7 处（layer_name/layer_kind、k=v 解析、--out 序列化、字段枚举、DNS 三套、配方初始化、Reply 构建）→ 已并入 §4.4。
- document-cli：6 处（三 Args struct、四 run_* PingConfig 字面量、dispatch_run 7 分支、校验退出模式、locale 4 处分散、INTERRUPT_COUNT 双源）→ 已并入 §4.1。
- cross-cutting：14 条全库扫描发现（IHL 解析 20+ 处、IPv6 框架探测 7 处、65536 缓冲区常量、AF_PACKET 双份、SYN 构建双份、校验和、resolve_target 重复等），6 条为全新（X1/X4/X7/X8/X9/X14），其余与 M/E 条目合并 → §4.2（M-16/M-17/M-18）、§4.4（E-13）、§4.5、§5。
