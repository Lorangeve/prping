# http_mock：用两个 pktl 配方模拟 HTTP over TCP 的服务端/客户端

`examples/http_mock/` 是两个**配方**（`.pktl`）——服务端配方 + 客户端配方，
纯 pktlang 模拟一次「GET → 200 OK → POST → 200 OK」的 HTTP 会话
（合并改造自 `examples/http_flow/` 与 `examples/app_http/`，形态标杆 `examples/icmp_mock/`）：

| 文件 | 角色 | 配方步骤 |
| --- | --- | --- |
| `server.pktl` | 服务端（HTTP 80 端口） | **单一 serve 阶段双规则分派**（`max: 2`）：两条链路层监听规则匹配 `http(method="GET"/"POST")` 共用一条抓包会话（按声明顺序逐个匹配、先命中先服务）→ 命中规则的 extract 写客户端端口/序列号/双向 IP → 该规则 handler 触发发包 200 OK（`ack = r_seq + 请求字节数`，见下） |
| `client.pktl` | 客户端（多包流程） | 1. 发 GET（`raw: true`）→ `wait: 2` 校验 200 OK（sniffer TCP 层 + http 内容双判据）；2. `delay: 0.5` 后发 POST（JSON body + Content-Length）→ `wait: 2` 校验（分派监听无重绑间隙，delay 仅为可读性保留） |

## HTTP 协议速览（RFC 2616/7230）

无状态的应用层文本协议，请求/响应模式，基于 TCP 传输：

- 请求格式：`方法 路径 HTTP版本\r\n` + 头部行 + `\r\n` + 体
- 响应格式：`HTTP版本 状态码 原因\r\n` + 头部行 + `\r\n` + 体

**常见方法**：

| 方法 | 用途 |
| --- | --- |
| GET | 获取资源（最常用，无体） |
| POST | 提交数据（本示例 JSON 登录） |
| PUT | 更新资源 |
| DELETE | 删除资源 |
| HEAD | 获取头部信息（无体） |

**常见状态码**：

| 状态码 | 含义 |
| --- | --- |
| 200 OK | 请求成功（本示例应答） |
| 301 Moved Permanently | 永久重定向 |
| 302 Found | 临时重定向 |
| 404 Not Found | 资源不存在 |
| 500 Internal Server Error | 服务器内部错误 |

**常见 Content-Type**：

| 值 | 内容 |
| --- | --- |
| text/html | HTML 文本（本示例应答） |
| application/json | JSON 数据（本示例 POST 体） |
| application/xml | XML 数据 |
| image/png | PNG 图片 |
| application/octet-stream | 二进制流 |

## 运行（需 root；链路层 AF_PACKET/Npcap）

```bash
# 终端 1 —— 服务端配方（链路层监听 + 触发应答）
sudo prping packet examples/http_mock/server.pktl

# 终端 2 —— 客户端配方（两步发包 + wait 校验）
sudo prping packet examples/http_mock/client.pktl
```

端口/地址注入（两端要一致）：`-p port=8080 -p ip=192.168.1.10 -p sip=192.168.1.5`
（resp_*.pkt 的 `sport=params("port", 80)` 与 client 的 `dport=params("port", 80)`
共用同一个键；`sip` 是客户端源 IP，回环实验不用管）。

## ack 计算表（TCP 确认号语义的教学点）

TCP 确认号 = 对方已连续收到的最后一字节序号 + 1 = 请求 seq + 请求字节数。
本 mock 固定 `seq=0x1000`，所以应答 ack 可预知：

| 请求 | 请求行 | 头部行 | 空行 | 体 | 载荷合计 | 应答 ack |
| --- | --- | --- | --- | --- | --- | --- |
| GET（http_get.pkt） | 26 | 19+24+19 | 2 | 0 | **90** | `0x1000+90 = 0x105A` |
| POST（http_post.pkt） | 22 | 32+24+20 | 2 | 32 | **132** | `0x1000+132 = 0x1084` |

（均已用引擎逐字节核验：`engine http_get.pkt` 整帧 144 B = eth14+ip20+tcp20+载荷90；
`engine http_post.pkt` 整帧 186 B = …+载荷132。）

应答 200 OK 的 `Content-Length: 31`：`<html>`6+`<body>`6+`Hello`5+`</body>`7+`</html>`7 = 31。
引擎 `http(...)` 是**纯拼接**（start_line + 头行 + \r\n + body），不自动补 Content-Length——
手动声明并保持一致是 HTTP 最经典的实验点（写错时客户端按声明长度截断/挂起）。

## 为什么必须 80/8080（http 反解分派）

http proto 的分派规则（eng_lib/headers.pkt）：

```
#[rule(or(tcp(dport=80), tcp(dport=8080)))]      ← 端口快速路径
#[rule(contains("HTTP/", in=start_line))]        ← 内容识别兜底
```

- **请求方向**：client 发往 `dport=80`（或注入的 8080）→ 快速路径命中 → 载荷反解出
  http 层，请求行按空格拆成 `method="GET"` / `path="/index.html"` / `version="HTTP/1.1"`
  —— server 的 listen sniffer 直接 `match http(method="GET")`（已在 matchpred.rs
  field_names 确认 http 层三字段可这样匹配）。
- **响应方向**：200 OK 帧 `dport=40000`，端口快速路径**未命中**——但引擎的
  **内容识别兜底**（"HTTP/" 魔数，协议识别以内容为准、端口只是提示）仍会反解出
  http 层，且响应行 `"HTTP/1.1 200 OK"` **整体落在 version 字段**（method/path 为
  None，所以响应方向永远不能匹配 `http(method=...)`）。client sniffer 的第二条
  规则 `match http(version="HTTP/1.1 200 OK")` 就是在演示这个兜底。

## 为什么服务端用链路层监听（需 root）

listen_*.pkt 不含 udp/tcp 传输层 → 引擎自动选**链路层监听**完整帧（AF_PACKET /
Npcap，需 root 抓包权限），帧内 eth/ipv4/tcp/http 层字段齐全，extract 直接取
`reply.tcp.sport` / `reply.ipv4.src`。对比 `examples/dns_echo_listen/` 的 UDP
数据报监听（绑定端口、载荷反解、`reply.peer.*` 取对端）：HTTP 挂在 TCP 上，而
引擎没有"TCP 数据报监听"，链路层是唯一能看到完整 TCP 段的方式。

⚠ listen_*.pkt 的包定义里**不能加 tcp 层**：监听方式按"包内有无 udp/tcp"自动判定，
加了会被当成 UDP 数据报监听（`recipe.rs::auto_listen_mode`）——包体只留
ipv4/eth 外壳做占位/文档，实际匹配完全由 sniffer 规则决定（同 icmp_mock/listen.pkt）。

## 客户端为什么用 tcp 字段匹配应答（主判据）

client sniffer 每步两条规则（隐式 OR）：

1. `match tcp(dport=40000, seq=0x2000, ack=0x105A/0x1084, flags="psh,ack")`
   —— **主判据，跨平台最稳**：四元组反向 + 服务端固定 ISN + 确认号推进 +
   旗标组合，四个字段一起把 200 OK 钉死。flags 字面量是反解展示的小写逗号串
   （`"psh,ack"`，见 matchpred.rs 对 tcp.flags 的字符串化）。
2. `match http(version="HTTP/1.1 200 OK")` —— 内容判据（见上一节；依赖引擎
   内容兜底，留作演示）。

客户端**不用** `http(method=...)` 匹配：响应帧里 method/path 是 None，等式恒不成立。

## 内核对无监听端口的 RST 副作用（无碍）

mock 不是真 TCP 栈：不握手、不维护连接状态，所以本机内核看到"发往无监听端口"
的帧会回 RST——client 的 GET 发往 80（无监听）内核回 RST，server 的 200 OK 到达
client 的 40000（无监听）内核也回 RST。这些 RST：

- 载荷为空 → 反解不出 http 层 → server 的 `http(method=...)` 永不误触发；
- flags 是 `rst` ≠ `"psh,ack"`、ack/seq 对不上 → client 的主判据永不误命中；
- 不影响 raw 收发本身（AF_PACKET 收发不过内核 TCP 栈的 connect/accept 状态机）。

同理，两条 200 OK 的 `seq=0x2000` 固定不变（真 TCP 会话服务端会推进序列号）。

## 平台差异（客户端 wait 校验的注意点）

- **macOS / Windows / Linux+pcap feature**：client 发送是 eth 外层 raw（libpcap/
  Npcap 路径，`rawpcap.rs::send_raw_full`——**先开抓包句柄再发送**），wait 能看到
  TCP 应答，sniffer 校验完整闭环。
- **Linux 默认构建（无 pcap feature）**：raw 发送路径的回包 socket 是**raw ICMP**
  （`engine/pkg/raw.rs`——只收 ICMP），收不到 TCP 应答 → client 的 `wait: 2`
  超时但**步骤不失败**（client 不从应答 extract 任何值），server 侧监听+应答照常
  工作。要完整看到 `✓ reply matched` 需 `cargo build --features prping/pcap`
  （需系统 libpcap-dev）后重跑，或换 macOS/Windows。
- 因此 client 步骤**不写 extract**（icmp_mock 的"extract 复用"教学点见该目录与
  dns_echo_listen）——extract 依赖回包，在收不到 TCP 应答的平台上会把示例变成
  必失败步骤。

## 固定值即 mock（教学对照，真实场景应动态提取/随机化）

sport=40000、seq=0x1000/0x2000、MAC 全零、端口 80 都是**固定值**：它们让应答的
ack/端口可预知，sniffer 才能用字面量校验。真实场景里内核随机选源端口与 ISN、
MAC 由 ARP 解析——应像 `examples/tcp_http_mock/` 那样 extract 后动态构造。

## 验证（解析级，不依赖 root/网络）

`server.pktl`/`client.pktl` 经 `prping engine` 校验步骤结构与 extract 字段名
（`reply.tcp.sport`/`reply.ipv4.src` 走 matchpred.rs 的字段表）；各 .pkt 单独
`engine` 校验构造与 sniffer 规则（resp_*.pkt 引用 extract 来的 global，单文件
分析用 `-g r_sport=40000 ...` 注入即可，配方运行时由监听步骤自动提取）。
