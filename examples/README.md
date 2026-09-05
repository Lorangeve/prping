# 协议学习用 Examples

本目录的协议流程示例统一为 **mock server/client 形式**：每个协议一个 `*_mock`
目录，内含**两个配方**——`server.pktl`（服务端：`wait: -1` 持续监听 +
sniffer 匹配 + `extract` 写 global + 触发发包步骤）与 `client.pktl`（客户端：
发包 + `wait: N` + sniffer 校验回包 + extract 复用），两个终端各跑一个即可在
本机闭环模拟一次完整协议会话。形态标杆是 `icmp_mock/`。

每个 `.pktl` 和 `.pkt` 都包含详细中文注释，解释协议结构、字段含义与工作原理。

## Mock server/client 系列（双配方闭环）

| 目录 | 协议/场景 | 监听方式 | 备注 |
| --- | --- | --- | --- |
| `icmp_mock/` | ICMP echo 会话 | 链路层（root） | **形态标杆**：回包 seq 偏移 +1000 作配方标记，排除回环内核替答 |
| `http_mock/` | HTTP GET/POST → 200 OK | 链路层（root） | http 反解分派要求 TCP dport=80/8080；客户端用 tcp 字段匹配应答 |
| `dhcp_mock/` | DHCP DORA 四步 | UDP :67（root） | 裸字节数组构造；固定 xid；Offer/Ack 单播回包 |
| `tcp_data_mock/` | TCP 数据传输/确认 | 链路层（root） | 数据段 → 纯 ACK（ack=seq+载荷长度），两轮 seq/ack 推进 |
| `tcp_http_mock/` | TCP 三次握手 + HTTP GET | 链路层（root） | 客户端 extract 服务端 ISN，动态构造 ACK/GET（Scapy 手动握手对照） |
| `arp_mock/` | ARP 请求/应答 | 链路层（root） | who-has → is-at 单播应答；含 gratuitous ARP 演示 |
| `udp_mock/` | 同一服务端分派 DNS + VNC | UDP（按端口） | 「端口即服务」分派：DNS 应答与 VNC 横幅两种协议 |

## 同构 server/client 变体（机制针对性演示）

| 目录 | 演示点 | 监听方式 |
| --- | --- | --- |
| `icmp_echo_server/` | **配方服务端入门样板**：单组 listen+reply 的 ICMP echo | 链路层（root） |
| `dns_echo_listen/` | **DNS mock**：查询 → 带 A 记录应答；客户端两步 extract 复用 tid | UDP :53（root 绑定） |
| `dns_trigger/` | **配方监听触发最小样例**：`wait: -1` 命中后触发发包 | UDP 55353（免 root） |
| `dns_loop_server/` | **循环监听服务**：`loop:` 无限包 listen+reply 连续服务多请求，`until:` 停服包收工（Ctrl+C 亦优雅） | UDP 55354（免 root） |
| `tcp_handshake_listen/` | **TCP 握手 mock**：listen 纯 SYN → SYN-ACK（ack=seq+1），客户端 extract 服务端 ISN | 链路层（root） |
| `sniffer_chat/` | **双进程对话模拟**：`sent.`/`reply.` 两种 extract 来源 + and/not sniffer 组合 | UDP 55353（免 root） |

## 机制/素材类（保留原样，mock 形态不适用）

- `network_icmp_bare/` — 真实 ICMP echo，裸 IP 走内核路由（代理/Clash fake-ip 环境
  可用）。**内核即应答方**，mock 配方会与内核替答冲突，故保留真实探测形态。
- `wait_timeout/` — 配方 `on_timeout` 超时处理机制演示（发备选包），非协议流程。
- `bad_network/` — 重传/RST 时序重放（`--out` 生成 pcap 供 tcpdump 分析），
  LSP 诊断测试引用其文件。
- `quic_initial/` — QUIC Initial/Short 构造展示（保护前裸结构，AEAD/头部保护不在
  DSL 范围），无应答语义可模拟。
- `icmp_ping/` — 对**真实目标**发 1～10 次 ICMP ping 的实用配方（`icmp_ping_real_N`）。
- `pcaps/` — pcap 素材文件。

## 爆破演示（仅限授权环境 / 本机靶场）

在线口令爆破的教学示例：看清爆破流量的报文形态、服务端「口令校验点」与响应侧
信道（✗/✓、401/403 vs 200），以及为什么真实服务需要限速/锁定/告警。
**全部默认打本机回环，请勿对未授权目标使用。**

| 目录 | 场景 | 形态 | 监听方式 |
| --- | --- | --- | --- |
| `brute_pin/` | DNS 门禁 PIN 爆破（候选藏 qname，字节谓词校验） | mock server/client 闭环（免 root） | UDP 55353 |
| `brute_http/` | HTTP 表单 / Basic 认证爆破 | 配方 + Python 本机靶场 `lab_server.py`（免 root） | TCP 8000（payload 模式） |

## 使用方法

### 查看协议结构（engine 概览）

```bash
prping engine examples/icmp_mock/server.pktl    # 配方概览（global + 步骤）
prping engine examples/icmp_mock/reply.pkt      # 单包层栈 + 字节 hexdump
prping engine examples/network_icmp_bare        # 带同名 .pktl 的目录可省略文件名
```

### 运行 mock 会话（两个终端）

```bash
# 终端 1 —— 服务端配方（多数 mock 需 root：链路层监听 / 绑定低位端口）
sudo prping packet examples/icmp_mock/server.pktl

# 终端 2 —— 客户端配方
sudo prping packet examples/icmp_mock/client.pktl 127.0.0.1
```

免 root 的组合：`dns_trigger/`、`dns_loop_server/`（UDP 55353/55354）、`sniffer_chat/`（UDP 55353）、
`udp_mock/` 的 VNC 步骤（高位端口）、`dns_echo_listen/` 的客户端（payload 模式）。

### 参数注入

```bash
# 目标 IP/端口注入（-p）；global 覆盖注入（-g）
sudo prping packet examples/icmp_ping/icmp_ping_real_4.pktl --raw --wait 1 -p ip=192.168.1.1
prping packet examples/dns_trigger/client.pktl 127.0.0.1:55353 -p port=55353
```

## 协议学习建议

1. **从形态标杆开始**：`icmp_mock/` 理解 mock server/client 的双向配方结构；
2. **理解监听方式自动选择**：包内有 udp → 数据报监听；无传输层 → 链路层监听
   （对照 `dns_trigger/` 与 `icmp_mock/` 的 listen.pkt）；
3. **掌握 extract 数据流**：`reply.`/`sent.`/`reply.peer.*` 三种来源，
   对照 `sniffer_chat/` 与 `dns_echo_listen/`；
4. **进阶动态协议**：`tcp_http_mock/` 的 seq/ack 全链 extract 推导。

## 相关资源

- `eng_lib/` — 25+ 协议 .pkt 库文件（headers/dhcp/quic/tls/…，带 RFC 引用注释）
- `docs/protocol-learning.md` — 协议学习指南
- `docs/claude-rules/engine.md` — 配方/extract/sniffer 语义权威文档
- `PROTOCOL_SUPPORT.md` — 协议支持清单
