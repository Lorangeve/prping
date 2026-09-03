# dhcp_mock：用两个 pktl 配方模拟 DHCP DORA 四步（服务端/客户端）

`examples/dhcp_mock/` 下是两个**配方**（`.pktl`）——服务端配方 + 客户端配方，
各自可包含**任意多步、多包**，纯 pktlang 模拟一次完整的 DHCP DORA 会话
（Discover → Offer → Request → Ack）：

| 文件 | 角色 | 配方步骤 |
| --- | --- | --- |
| `server.pktl` | 服务端（DHCP 服务器） | **显式两组** listen+reply：每组 = `wait:` 无值链路层监听匹配 BOOTREQUEST → extract 客户端 IP/端口、本机 IP 写 global → 触发发包应答（第 1 组回 Offer、第 2 组回 Ack）。两组对应 client 两步；要服务更多次就多写几组 |
| `client.pktl` | 客户端（两步发包流程） | 1. 发 Discover → `wait: 2` 校验 Offer（sniffer）→ extract 服务端 IP 写 `global.sip`；2. `delay: 0.5` 后发 Request（dst 复用 `global.sip`）→ `wait: 2` 校验 Ack |
| `listen.pkt` | 服务端监听规则 | 三重跨层 AND：`ipv4(proto=17)` + `udp(68→67)` + `raw 首字节 mask(0x01)`（op=1） |
| `dhcp_discover.pkt` / `dhcp_request.pkt` | 客户端两个请求包 | 旧 `dhcp_flow/` 的裸字节数组逐字段注释全保留，封装改单播回环；各带 wait 校验用的 sniffer |
| `dhcp_offer.pkt` / `dhcp_ack.pkt` | 服务端两个应答包 | 同上；封装用 `global(...)` 回包（`global` 第二参 = 单跑本文件时的回环缺省） |

## 运行（需 root；链路层抓帧 AF_PACKET / raw 发送 IPPROTO_RAW）

```bash
# 终端 1 —— 服务端配方（两组监听+应答，Ctrl+C 结束）
sudo prping packet examples/dhcp_mock/server.pktl

# 终端 2 —— 客户端配方（两步发包 + wait 校验 + extract 复用）
sudo prping packet examples/dhcp_mock/client.pktl
# 目标默认 127.0.0.1；换目标：--params ip=<地址>（需与网络拓扑自洽）
```

回环 `lo` 即可完整闭环（无需真实网卡/广播域）；macOS 同理（裸 IP 走内核栈）。

## 关键设计取舍（本轮改造的验证结论，注释里均有展开）

- **为什么链路层监听（`raw: true`），不是 UDP 数据报监听**：引擎按「listen 包
  内有无 udp/tcp」自动选监听方式——本包有 udp，会自动选 UDP 数据报监听
  （bind :67，收到的只是 DHCP 载荷）。但**裸 DHCP 载荷反解不出任何层**：
  eth 路径被 ciaddr 前缀 0x0000（ethertype < 0x0600）拒绝、裸 IP 路径被首
  nibble 0x0 拒绝、应用层回退只认 dns/http——层栈为空，任何 sniffer 谓词都
  匹配不到。实测：数据报监听收到 58 B Discover 打印 `- ignored 58 B`。链路层
  监听抓完整帧，帧内 ipv4+udp 反解成功、DHCP 载荷成为 raw 层（首字节 = op），
  字节谓词才能命中，extract 还能取 `reply.ipv4.*`/`reply.udp.sport`。
- **为什么 sniffer 是三重 AND**（`and(match ..., match ..., match ...)`——
  and 的子项是完整 match 子句，写成 `match and(...)` 会把 and 当层名报错）：
  ① `ipv4(proto=17)` 排除内核 ICMP port-unreachable 等杂帧（回环上没人 bind
  :67/:68，每个 DHCP 数据报都会触发一个 ICMP 差错；ICMP 分支不递归反解嵌入
  原包，无 udp/raw 层，这里按 proto 再挡一次兼作教学）；② `udp(68→67)` 锁
  BOOTREQUEST 的端口方向；③ `raw 首字节 mask(0x01)`——mask 语义是
  `(首字节 & mask) == mask`（matchpred.rs），0x01 命中 op=1、排除 op=2。
- **为什么两组监听用同一规则、按组配对**（不区分 Discover/Request）：两者
  op 都是 1，严格区分要匹配 option 53 字节模式 `35 01 01`/`35 01 03`，但
  sniffer 字节谓词 `startswith/contains` 只接受**字符串**参数，而 DSL 字符串
  转义只有 `\n \r \t \\ \"`（无 `\xNN`），表达不了控制字节——现有谓词无法
  表达。同款位置配对思路见 icmp_mock 两组 listen 共用一条规则。
- **为什么 xid/chaddr/yiaddr 全是固定值**：引擎没有 dhcp proto 层（反解时
  DHCP 载荷只能整体落在 raw 层），配方 extract 取不到 xid 等字段，没法像
  icmp_mock 提取回显。固定值便于教学对照（四个报文逐字节看差异）；真实场景
  客户端应随机化 xid、用真实 MAC，服务端按 xid+chaddr 配对会话。
- **为什么单播替代广播**：真实 DHCP 的 Discover/Request 是广播、Offer/Ack
  视广播位回包；回环没有广播域，mock 单播（dst=params/ip、回包 global.cip）
  简化且无需 SO_BROADCAST/raw 广播权限。载荷里的 192.168.1.x 是"模拟局域网"
  的假地址，与外层回环封装各管各的（学习点：DHCP 载荷地址 vs 传输封装地址）。
- **UDP 校验和注记**：客户端 Discover/Request 的 IP 源按 DHCP 语义写
  0.0.0.0；raw 发送前引擎补本机地址并只重算 **IP 头**校验和，UDP 校验和仍是
  按 0.0.0.0 伪头部算的——Wireshark 会标红。可接受：服务端走 AF_PACKET 抓帧，
  不经过内核 UDP socket，无人校验（服务端回包源地址来自 extract，校验和正确）。
- **为什么 client 步骤 2 带 `delay: 0.5`**：server 每命中一次都要重开下一轮
  抓包，回环上 client 全程 <1ms，不加 delay 会错过第二个请求（经验同
  icmp_mock「为什么 seq 是 1001/1002」）。

## 学习材料：DHCP 报文结构与选项（承自旧 examples/dhcp_flow/）

- **固定部分（236 字节）**：`op(1) htype(1) hlen(1) hops(1) xid(4) secs(2)
  flags(2) ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64)
  file(128)`——逐字段注释见四个 .pkt 文件的字节数组。
- **Magic Cookie**：`0x63825363`——标识选项区从第 240 字节开始。
- **选项区（TLV：type 1B + len 1B + value）**：

  | Option | Name | 描述 |
  | --- | --- | --- |
  | 1 | Subnet Mask | 子网掩码 |
  | 3 | Router | 默认网关 |
  | 6 | DNS Server | DNS 服务器地址 |
  | 50 | Requested IP | Request 中请求的 IP |
  | 51 | Lease Time | IP 地址租约时间（秒） |
  | 53 | Message Type | DHCP 消息类型（1=Discover 2=Offer 3=Request 5=Ack） |
  | 54 | Server Identifier | DHCP 服务器标识 |
  | 55 | Parameter List | 客户端请求的参数列表 |
  | 61 | Client Identifier | 客户端标识 |

- **DORA 四步**：Discover（客户端广播"谁能给我 IP"）→ Offer（服务端"我可以
  给你 IP X"）→ Request（客户端广播"我要 IP X"，让所有服务器知道它的选择）
  → Ack（服务端"IP X 已分配给你"）。xid 与 chaddr 在四个报文中保持一致。

## 与其它 mock 服务端写法的对照

| 目录 | 监听方式 | 对端地址来源 | 备注 |
| --- | --- | --- | --- |
| `examples/icmp_mock/` | 链路层（raw，ICMP 无传输层自动 raw） | `reply.ipv4.src/dst` | 内核替答回避：seq 偏移 +1000 |
| `examples/dns_echo_listen/` | UDP 数据报（bind :53） | `reply.peer.ip/port`（socket 对端） | 载荷有 dns proto 规则可匹配 |
| 本目录 `dhcp_mock/` | 链路层（**必须显式** `raw: true`） | `reply.ipv4.src/dst` + `reply.udp.sport` | 裸载荷无 proto 层：反解不出层，数据报监听不可行（见上） |

## 验证

- 语法：`prping engine examples/dhcp_mock/<file>` 七个文件全部退出码 0。
- 字节级（不依赖 root）：`packet --out` 落 pcap + `engine --pcap` 反解——完整
  Discover 帧反解出 `raw(58B) + udp(68→67) + ipv4`，raw 首字节 = op；Offer 帧
  `raw(274B) + udp(67→68) + ipv4(127.0.0.1)`。
- 端到端：需 root 双终端跑 server.pktl / client.pktl（见「运行」）。
