# 测量功能（万用表）

> 从 CLAUDE.md 拆出的详细规则。CLAUDE.md 只保留功能清单摘要；Windows 平台相关
> （WSAPoll / ICMP.DLL / raw 收包无外层头 / trace TCP SYN 限制）见
> `docs/claude-rules/windows-build.md`。

## 抖动 jitter

`Stats` 累计相邻接收样本 RTT 差（丢包打断链），`jitter()`/`jitter_max()` 输出均值/最大；
文本汇总行 + `--json` 的 `jitter_ms`/`jitter_max_ms`。

## 源绑定 `-s`

`util::resolve_source`（IP 或 Linux 网卡名 → SIOCGIFADDR 取 IPv4）；
`util::connect_timeout/connect_first` 改走 socket2 → bind → `connect_timeout` → smol::Async
（`smol::net::TcpStream` 无法从已绑定 socket 构造）；`local_bind` 统一 UDP/ICMP 源绑定。
Windows connect 路径见 `windows-build.md`（`win_connect_select`）。

## MTU 探测 `-m`/`--mtu`

`src/mtu.rs`——ICMP echo + DF（setsockopt：Linux `IP_MTU_DISCOVER=IP_PMTUDISC_DO` /
Windows `IP_DONTFRAGMENT=21` / macOS `IP_DONTFRAG`）+ 载荷二分 [0,65507]；解析
Fragmentation Needed（type 3 code 4）的 MTU 字段；仅 IPv4（IPv6 需 ICMPv6 PTB）。
`OutcomeKind::Mtu` 不触发丢包退出码。

## 路由跟踪 `-t`/`--traceroute`

`src/trace.rs`——ICMP echo + 递增 TTL（IPv6 用 `set_unicast_hops_v6`），每跳 3 次背靠背
探测、1s 收集窗口；Time Exceeded（v4 type 11 / v6 type 3）内嵌报文按 id/seq 匹配归属，
echo reply 即到达。

模式选择在 `run` 分派层（`lib.rs::resolve_trace_probe`）：无端口 → ICMP；**带端口且未
显式指定协议 → 自动 TCP SYN**（与 ping 的「带端口 → TCP」一致；CLI 无 `--tcp` 标志）；
`--udp` 不接受端口（33434 起自动递增）；库调用方可显式置 `cfg.trace_tcp` 指定 TCP
（需端口）。

- **内嵌布局按 RFC 792：8B ICMP 头本身含 4B unused，内嵌原始 IP 头从 `icmp[8]`
  （`body[0]`）起**（曾误当「8B 头 + 额外 4B unused」从 `body[4]` 读 IHL → 中间跳全
  `*`，转储实锤后修正：v4 `eihl` 从 `body[0]`、v6 dst 在 `body[24..40]`、内嵌传输从
  `body[40]` 起）。
- **内嵌传输头被路由器截断（<8B，常见实现）时按「内嵌 dst == 目标」兜底归属**（内嵌
  IP 头恒完整、dst 恒可读；全量 id/seq 不匹配仍丢弃防误认；系统 traceroute 根本不校验
  内嵌内容，dst 校验已更严）——`parse_reply_v4/v6`、`match_time_exceeded_tcp`、
  `parse_udp_icmp` 三处适配；`PRPING_TRACE_DUMP=1` 时 `trace_dump` 打印收到的原始包
  （`[trace-dump]` 前缀）供排查。
- 反向 DNS 用 getnameinfo（unix libc / Windows ws2_32 自行声明）+ 线程限时（`-d` 跳过）；
  收包框架（raw socket 是否含外层头）见 `windows-build.md`。
- `OutcomeKind::Traceroute` 按 `reached` 决定退出码。

### TCP SYN 变体（`trace HOST:PORT` 带端口自动，`cfg.trace_tcp`）

对标 tcptraceroute/tracetcp。**Unix（`trace/tcp.rs`）**——raw TCP socket
（`IPPROTO_TCP`）发 SYN（内核构 IP 头）、伪头部校验和用 `engine::pkg::local_ip_for` 的
本地源 IP 并 bind 到该地址；每探测独立源端口 0x4000..=0x5FFF（防 IPv6 无头缓冲被
version-nibble 误判为带头）；raw ICMP（Time Exceeded，`parse_ttl_exceeded_v4/v6` 按内嵌
TCP (sport,dport) 匹配）+ raw TCP（SYN-ACK/RST，`match_tcp_reply_v4/v6`：源端口=目标
端口、目的端口∈探测源端口、源 IP=目标；先无头解析兜底再按带头）双 socket `libc::poll`
等待，两个 socket 先于发送打开（回环下回包可能在 send 内完成往返）；SYN-ACK 与 RST
都算到达。中间路由回 Time Exceeded，目标回 SYN-ACK（端口开）/RST（端口关）即到达
（ICMP 被过滤时仍可用）。

**Windows（`trace/tcpwin.rs`）**——raw TCP socket 被禁止（SOCK_RAW + IPPROTO_TCP 创建
失败），改用与 `packet --raw` 相同的 Npcap 兼容层（`engine/rawpcap.rs`）：pcap 注入完整
以太网帧（eth + IPv4 + TCP SYN，TTL 递增写在 IP 头里，IP/TCP 校验和手算；MAC 经
`resolve_macs_win` 解析），同一抓包句柄收 SYN-ACK/RST（`parse_reply_frame`，语义与
Unix 一致）与 ICMP Time Exceeded；先开抓包句柄再发送（局域网回包 <1ms）；抓包句柄会
回读刚注入的帧——与发送帧逐字节相同者跳过。**仅 IPv4**（IPv6 跨链路需 ND 邻居解析，
Win7 无 GetIpNetTable2；`errors.tcp_trace_ipv6`）；**未装 Npcap** 在 banner 前经
`ensure_wpcap()`（LoadLibrary 探测）报 `errors.tcp_trace_npcap`，绝不走到 wpcap.dll 的
delay-load 异常。

### UDP 变体（`trace --udp HOST`，`cfg.trace_udp`）

经典 Unix traceroute。`trace_udp`（全平台，无 cfg gate）——普通 UDP socket
（`create_udp_socket`：bind 固定随机源端口，内核构 UDP 头/校验和）发 1B 载荷到递增
目标端口（33434 起每探测 +1），每跳 set_ttl；只需一个 raw ICMP socket 收包
（`parse_udp_icmp`：Time Exceeded 中间跳 / Port Unreachable（v4 type 3 code 3、
ICMPv6 type 1 code 4）到达，按内嵌 UDP 头 (sport, dport) 匹配归属）；TCP 与 UDP 互斥
（`TraceProtoConflict`，库层校验——CLI 无 `--tcp` 标志）。

## 子命令解析

`expand_subcommand_prefix` 唯一前缀展开（bpaf `take_cmd` 精确匹配，前缀展开在
run_inner 前做；歧义/旧语法 host 提示红字退出 2）；顶层 `--version`/`--lang`
由 main() pre-scan 提取处理（`--lang` 任意位置移除，子命令解析后 `apply_lang` 幂等重设）。
