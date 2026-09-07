# udp_mock：用两个 pktl 配方模拟「按端口分派」的 UDP 服务端（DNS + VNC 横幅）

`examples/udp_mock/`（取代旧 `transport_udp/`，后者只是两步发包演示）是两个
**配方**（`.pktl`）——服务端配方 + 客户端配方，纯 pktlang 模拟一台主机上
**同一个 UDP 服务端按端口分派两种应用协议**：:5533 应答 DNS 查询（A 记录），
:5900 应答 VNC RFB 版本横幅：

| 文件 | 角色 | 配方步骤 |
| --- | --- | --- |
| `server.pktl` | 服务端（按端口分派） | **两个 serve 阶段**顺序排列（各 `max: 1`）：第 1 阶段 **UDP 数据报监听** :5533 匹配 DNS 查询（flags=0x0100）→ extract id/对端地址写 global → handler 触发发包 A 记录应答；第 2 阶段 `raw: true` **链路层监听** 匹配 RFB 横幅（跨层 AND：udp dport=5900 + raw 前缀）→ extract 帧内对端 → handler 回横幅。不分派成一条多规则 serve 是因为两条规则监听方式不同（数据报 vs 链路层，同阶段混用报错）且端口不同（单 socket 无法同时绑定），故顺序两阶段 |
| `client.pktl` | 客户端（多包流程） | 1. 发 DNS 查询（id=0x1234）→ `wait: 2` sniffer 校验应答（id 一致 + flags=0x8180）；2. `delay: 0.5` 后发 RFB 横幅 → `wait: 2` 等回横幅（无 sniffer，见下） |

## 运行（服务端需 root；客户端全程免 root）

```bash
# 终端 1 —— 服务端配方（需 root：第 2 阶段是链路层监听，抓帧要 cap_net_raw）
sudo prping packet examples/udp_mock/server.pktl

# 终端 2 —— 客户端配方（普通 UDP socket，无需 root）
prping packet examples/udp_mock/client.pktl
```

预期：客户端步骤 1 `✓ reply matched: id=4660 flags=33152`（应答 A 记录
example.com → 93.184.216.34），步骤 2 `sent 12 B, received 12 B`；服务端两个
serve 阶段各命中一次并回包。跨机实验给客户端加 `-p ip=<对端 IP>`（回包按 socket 对端
地址原路返回，天然支持）。

## 「端口即服务分派」：同一主机，端口决定协议

真实主机上没有「端口 53 的机器」——是**进程**各自绑定端口，内核按目的端口把
数据报分给对应 socket。本 mock 用配方复刻这一层：

- 服务端配方的每条 serve 规则按**其监听源 .pkt 的最外层 udp dport**（或链路层
  规则里的 dport 条件）绑定/过滤各自的端口——两个阶段独立监听 :5533 与 :5900；
- 客户端两个步骤只换 dport（5533 → 5900），协议栈不变（udp → ipv4 → eth）；
- 应答一律发回 socket/帧里看到的**对端真实地址**，与请求同端口同服务。

固定值（id=0x1234、sport=12345/12346、MAC）是 mock 的正常手段，便于教学
对照；真实场景 id 应随机（rand16()）、端口由内核分配、MAC 由 ARP 决定。

## 为什么 DNS 在 :5533 而不是 :53（root 说明）

DNS 的 proto 分派规则（`eng_lib/headers.pkt`）是三段：

```pkt
#[rule(udp(dport=53))]    # 上下文：UDP 目的端口 53（快路径）
#[rule(tcp(dport=53))]    # 上下文：TCP 目的端口 53（快路径）
#[rule(or(ne(qdcount,0), ne(ancount,0), ne(nscount,0), ne(arcount,0)))]
                          # 内容特征：任一区计数非零（查询 qdcount=1 必满足）
```

端口规则未命中时引擎还有**内容识别回退**（协议识别以内容为准，端口只是可选
提示）：按 dns 声明结构直接试解析，区计数非零即接受。UDP 数据报监听拿到的是
纯载荷（没有端口上下文），反解本来就只看内容——**DNS 载荷在任意端口都能反解
出 dns 层**。因此选 **5533 高位端口**：绑定 <1024 特权端口需要 root/管理员，
5533 全程免 root，把 root 的需求留给真正绕不开的第 2 阶段（见下）。代价是与
真实 DNS 端口不同——教学演示取舍，真实解析器仍固定用 :53。

## 为什么第 2 阶段（VNC）必须走链路层监听

引擎对裸 UDP 载荷只尝试 **dns/http** 两种声明反解；RFB 横幅是纯文本，两者都
解析失败 → **一个层都产不出**，任何 sniffer 规则（包括 raw(...) 字节谓词）
都无从匹配（实测：横幅数据报被监听 ignored）。链路层监听收完整帧：解析不到
应用层时载荷保留为 **raw 层**，于是 udp 层（带 dport）与 raw 层（带横幅
字节）都齐全，跨层 AND 即可「端口 + 内容」双确认：

```pkt
- and(match udp(dport=5900), match raw(startswith("RFB ")))
```

链路层监听没有 `reply.peer.*`（peer 来自 UDP 数据报监听的 socket；帧里没有
socket）——对端地址从**帧内**取：`reply.ipv4.src` / `reply.udp.sport`。
这也是本目录的一个教学点：两种监听方式的对端取值途径不同（`dns_echo_listen/`
用 reply.peer.*，本目录第 2 阶段用帧字段）。

客户端步骤 2 的 `wait` 因此**不配 sniffer**：回包是裸横幅数据报（无 IP/UDP
头），反解不出可匹配的层。引擎对无 sniffer 的 wait 语义是「收到的第一个
数据报即应答」（发送与应答字节相同时，内置 DNS-id 门——首 2 字节相同——
天然通过），命中即打印 ✓ reply 与字节数/RTT。

## DNS 报文结构（RFC 1035，eng_lib/headers.pkt）

头部 12B：事务 ID + 标志 + 四区计数；后随问题区/应答区/授权区/附加区。

| 字段 | 长度 | 含义 |
| --- | --- | --- |
| id | 2B | 事务 ID：客户端随机生成，应答回显同一 id 用于配对（本 mock 固定 0x1234） |
| flags | 2B | 位域：QR(1)=查询/应答、Opcode(4)、AA(1) 权威、TC(1) 截断、RD(1) 期望递归、RA(1) 递归可用、Z(3)、RCODE(4) 错误码 |
| qdcount | 2B | 问题区条目数（查询 = 1） |
| ancount | 2B | 应答区条目数（查询 = 0，应答 = 命中数） |
| nscount / arcount | 2B | 授权/附加区条目数 |

本 mock 用到的两个 flags 值：查询 `0x0100`（QR=0 + RD=1，递归查询的标准
默认）、应答 `0x8180`（QR=1 + RD=1 + RA=1，成功递归应答）。

问题区条目 = QNAME + QTYPE(2B) + QCLASS(2B)；QNAME 是**长度前缀标签**序列
（每段前 1B 长度，\0 结尾）：`example.com` → \x07example\x03com\x00——
构造时直接给字符串，序列化器自动转线格式。QCLASS 几乎恒为 IN(1)；常用
QTYPE：A(1) IPv4、NS(2)、CNAME(5)、MX(15)、TXT(16)、AAAA(28)。

应答区条目（A 记录）= 名字 + 类型 + 类 + TTL(4B) + RDLENGTH(2B) + RDATA。
配方里用**列表元组**构造（`dns_reply.pkt`）：
`answers=[["example.com", 1, 1, 300, ip4("93.184.216.34")]]`——名字/类型
A(1)/类 IN(1)/TTL 300/4B 地址，rdlength 自动计算。回环应答 TTL 300 只是
演示值；真实权威服务器按域名策略设置（通常 60~86400）。

## VNC RFB 握手横幅（RFC 6143，eng_lib/vnc.pkt）

VNC（Remote Frame Buffer）握手第一步是**协议版本协商**：双方交换 12B 定长
文本横幅 `RFB xxx.yyy\n`——RFB 魔数 + 主版本 3 位 + 点 + 次版本 3 位 +
换行。`RFB 003.008` = RFB 协议 3.8（最常用的经典版本；3.3/3.7/3.8 的差异
在安全协商流程）。真实 VNC **服务端先发**横幅，客户端回自己支持的最高版本；
本 mock 反过来（客户端先发、服务端回显）——为的是复用「监听触发 → 回包」的
配方形态与第 1 阶段同构，教学重点是横幅格式与端口分派，不是真实时序。横幅之后
依次是安全类型协商 → 认证 → 初始化（帧缓冲参数）→ 交互阶段（见
`eng_lib/vnc.pkt` 的 vnc_security_types / vnc_client_init / vnc_server_init）。
5900 是 VNC 的注册端口（RFB over TCP 的常态；本 mock 用 UDP 承载做教学简化，
横幅本身与传输层无关）。

## 配方引擎能力对照（本目录覆盖的点）

- **UDP 数据报监听**：listen .pkt 有 udp 传输层 → 自动绑 udp dport 端口，
  载荷反解后按 sniffer 匹配；对端地址 `reply.peer.ip/port`（来自 socket）；
- **链路层监听**：serve 规则 `raw: true` → 抓完整帧（需 root）；帧内
  ipv4/udp/raw 字段齐全；对端从帧内取；
- **触发发包**：规则命中 → extract 写 global → handler 步骤用
  `global("...")` 构造应答（payload 模式普通 UDP socket 发送）；
- **wait 校验**：`wait: 2` 发后等应答（sniffer 匹配 / 无 sniffer 收首包）；
- **extract 复用**：`from: reply.dns.id`（匹配包字段）/ `reply.peer.*`
  （socket 对端）/ `reply.ipv4.src`、`reply.udp.sport`（帧内字段）；
- **跨层 AND**：`and(match udp(...), match raw(startswith(...)))`——端口 +
  内容双确认；
- **params 注入**：客户端 .pkt 的 `dst=params("ip", "127.0.0.1")`，
  `-p ip=` 可改目标。

## 为什么 client 步骤 2 要 delay 0.5

服务端配方的两个 serve 阶段是**串行**的：第 1 阶段命中 → handler 发应答 → 阶段
收工 → 第 2 阶段打开 :5900 监听（链路层抓包初始化更慢）。回环上 client 全程 <1ms 就
跑完，不加 delay 会把横幅发在 :5900 监听就绪之前——服务端永远等不到（表现为
第 2 阶段 2s 超时）。这与 `examples/icmp_mock/`「为什么 seq 是 1001/1002」
一节是同一条回环经验。

## 验证（本目录开发时的实测记录，Linux 回环）

- 8 个文件 `prping engine` 全部通过（reply 两个文件引用配方运行时才有的
  global，与 `icmp_mock/reply.pkt` 同款：裸跑报「全局未设置」，用
  `-g tid=... ` 注入即过——语法解析均成功）；
- DNS 阶段免 root 端到端闭环：服务端命中查询 → extract tid/cip/cport → 回
  A 记录应答；客户端 `✓ reply matched: id=4660 flags=33152`，应答反解出
  rdata=5db8d822（93.184.216.34）；
- 第 2 阶段链路层规则经 `--pcap` 逐帧反解验证：横幅完整帧反解出
  udp(dport=5900) + raw(12B "RFB 003.008\n") 两层——规则可命中；客户端
  步骤 2 无 sniffer wait 经回显实测 `sent 12 B, received 12 B`；
  链路层抓帧本身需要 root，免 root 环境按预期报
  `Operation not permitted`（即上文 root 说明的边界）。
