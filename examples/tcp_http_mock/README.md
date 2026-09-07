# tcp_http_mock：用两个 pktl 配方模拟 TCP 三次握手 + HTTP GET/200 OK

`examples/tcp_http_mock/` 下是两个**配方**（`.pktl`）——服务端配方 + 客户端配方，
纯 pktlang 在**一台 Linux 机器（root）上闭环**模拟一次「TCP 三次握手 → HTTP GET →
200 OK」完整会话，每一帧的 seq/ack 都看得见、算得清：

| 文件 | 角色 | 配方步骤 |
| --- | --- | --- |
| `server.pktl` | 服务端（TCP :80 + HTTP 静态页） | `serve:` 单规则 + **嵌套 on_recv**：规则链路层监听匹配纯 SYN → extract 端口/seq/双向 IP → handler 先发 SYN-ACK（`ack=请求 seq+1`，固定服务端 ISN=0x2000），再 `on_recv:` 等 GET → extract GET 的 seq/ack → 嵌套 handler 发包 200 OK（`seq=GET 的 ack`，`ack=GET 的 seq+38`） |
| `client.pktl` | 客户端（三步流程） | 1. 发 SYN（seq=0x1000）→ `wait: 2` 校验 SYN-ACK → **extract 服务端 ISN**（`reply.tcp.seq` 写 `global.sseq`，真实握手核心动作）；2. `delay: 0.5` 发第三次握手 ACK（`wait: 0` 无应答）；3. `delay: 0.5` 发 HTTP GET（PSH\|ACK）→ `wait: 2` 校验 200 OK（tcp 字段 + http 状态行） |

发包用**裸 IP 外层**（无 eth 层）+ `raw: true`：有 tcp 传输层的发送必须显式 raw
（否则走 TCP 载荷建连），裸 IP 经内核 IP 栈路由注入（Linux IPPROTO_RAW+IP_HDRINCL），
回环与局域网都无需 MAC 解析；监听为**链路层**收完整帧（AF_PACKET/libpcap）。

## 运行（需 root；两个终端）

```bash
# 终端 1 —— 服务端配方
sudo prping packet examples/tcp_http_mock/server.pktl

# 终端 2 —— 客户端配方
sudo prping packet examples/tcp_http_mock/client.pktl 127.0.0.1
```

- **Linux**：回环完整闭环（AF_PACKET 抓帧 + raw socket 注入，双端都要 root/cap_net_raw）；
- 实验前**停掉本机 80 端口的真实服务**（否则内核会抢答 SYN-ACK，时序表对不上，
  见「内核 RST 副作用」）；`-p ip= / -p sip= / -p port=` 可注入地址/端口做变体实验。

## seq/ack 全程时序表（数字逐项可对账）

客户端 ISN 固定 0x1000、服务端 ISN 固定 0x2000（固定值便于教学对照；真实场景
应随机化——服务端 ISN 的**动态提取**见 client 步骤 1）：

| 段 | 方向 | seq | ack | flags | 载荷 | 来源 |
| --- | --- | --- | --- | --- | --- | --- |
| ① SYN | C→S | 0x1000 | — | `syn` | — | client 步骤 1 `syn.pkt` |
| ② SYN-ACK | S→C | 0x2000（固定 ISN） | **0x1001 = ①.seq+1**（extract `r_seq+1`） | `syn,ack` | — | server 规则 handler `synack.pkt` |
| ③ ACK | C→S | 0x1001 = cseq+1 | **0x2001 = ②.seq+1**（sseq 动态提取后 +1） | `ack` | — | client 步骤 2 `tcp_ack.pkt`（`wait: 0`） |
| ④ GET | C→S | 0x1001（③ 无载荷不占号） | 0x2001（服务端无新数据，不变） | `psh,ack` | 38 B：`GET / HTTP/1.1\r\n`(16)+`Host: mock.example\r\n`(20)+空行(2) | client 步骤 3 `http_get.pkt` |
| ⑤ 200 OK | S→C | **0x2001 = ④.ack**（extract `r2_ack`） | **0x1027 = ④.seq+38**（extract `r2_seq+38`） | `psh,ack` | 89 B：状态行(17)+两头部(26+20)+空行(2)+body(24) | server 嵌套 on_recv handler `http_resp.pkt` |

三条**动态链**（旧目录做不到/做不全的部分）：

- **server 侧**：`ack = r_seq + 1`（SYN-ACK）、`seq = r2_ack`、`ack = r2_seq + 38`
  ——全部来自 serve 规则/嵌套 on_recv extract 的匹配帧字段，服务端对客户端 ISN/端口一无所知也能应答；
- **client 侧**：`ack = sseq + 1`（③⑤）——`sseq` 是从 SYN-ACK **动态提取**的服务端
  ISN。对比 `examples/tcp_handshake/`：那边 cseq/sseq 双双 init 硬编码（0x1000/0x2000），
  只能对着已知 ISN 的对端演；本目录把"提取对端 ISN 再构造 ACK"这一真实握手核心动作补齐；
- **对端 ack 即自己 seq**：⑤ 的 seq 直接取 ④ 的 ack（客户端已确认到 0x2001，服务端
  数据正好从这发）——TCP 两条方向各推一条数轴、ack 互为对方 seq 游标的自然结果。

对 Scapy：`sr1(IP(dst)/TCP(dport=80)/"GET / HTTP/1.1\r\n\r\n")` 自动替你完成握手，
prping 把每一段手动拆开——教学价值正在于每个 seq/ack 都亲手算过。

## http 层反解分派（为什么端口必须是 80）

http proto 的反解分派（`eng_lib/headers.pkt`）：

```text
#[rule(or(tcp(dport=80), tcp(dport=8080)))]   # 端口分派
#[rule(contains("HTTP/", in=start_line))]      # 内容分派兜底
```

| 帧 | dport | 端口分派 | 内容兜底 | 反解出的 http 字段 |
| --- | --- | --- | --- | --- |
| ④ GET 请求 | 80 | ✓ | ✓ | `method=GET path=/ version=HTTP/1.1`（请求行按空格拆三段） |
| ⑤ 200 OK 响应 | 40000 | ✗ | ✓（start_line 含 `HTTP/`） | `method=None path=None version="HTTP/1.1 200 OK"`（**响应行整体落在 version**） |
| ①②③ 与内核噪声 RST | — | ✗ | ✗（无 HTTP 载荷） | 无 http 层 |

- 本 mock 全程用 **80** 端口：server 的应答 sport 固定 80，与端口分派白名单配套；
  客户端 GET 打 8080 也能被 server 匹配（白名单含 8080），但应答仍从 80 发，教学上
  不要混用；
- server 的 listen_get 只写 `match http(method="GET")` 就够：GET 帧 dport=80 必然
  反解出 http 层，而噪声帧没有 HTTP 载荷、根本不会有 http 层；
- client 校验响应**不能**用 `raw(contains("200 OK"))`：⑤ 的载荷已被内容兜底反解成
  http 层，不再是 Raw 层（`packet --out` + `engine --pcap` 实测）；改用
  `http(version="HTTP/1.1 200 OK")` 钉住状态行——这就是响应行整体落在 version 字段
  的用法。

## sniffer 技术取舍（实测验证）

- **listen 侧只用字面量**：监听模式没有发包可引用（裸 Ident/SentField 构建期报错，
  `matchpred.rs` `allow_sent: false`）；
- **`flags="syn"` 精确串比较**：tcp.flags 反解为小写逗号串（`"syn"` / `"syn,ack"` /
  `"rst,ack"`）。listen_syn 只匹配 `"syn"`——自己刚回的 SYN-ACK 是 `"syn,ack"` 不命中，
  回环上 AF_PACKET 对出向帧同样投递，精确匹配是防自环的关键。client 侧 sniffer 用
  **字节形态** `flags=bor(syn(), ack())`（与 flags 字段 2 字节大端 0x00,0x12 比较），
  两种形态对照读；
- **跨层 and**：`and(match tcp(...), match http(...))`（client 步骤 3）——sniffer 反解
  后对整包判定，支持跨层 AND/or/not；`#[rule]` 是解析期单点分派反而做不到；
- **最小校验变体**：client 步骤 3 删掉 http 子句只留 tcp 子句也能匹配
  （`examples/tcp_handshake_listen/` 客户端同款）；想收窄 server 的广谱监听可写
  `and(match tcp(dport=80), match tcp(flags="syn"))`。

## 内核 RST 副作用（噪音正常，不会误触发）

raw 注入的包**同样会被内核 TCP 栈看到**，而 mock 的连接对内核不存在：

- client 的 SYN 打到 :80（无监听）→ 内核替答 **RST**（sport=80, flags=`rst,ack`）；
- mock 的 SYN-ACK/GET 响应被 client 内核看到（本机没有对应 socket）→ 内核对 :80 回 RST；
- 于是两个终端的监听输出里会混进 RST 噪声帧——**这是预期现象**。所有 sniffer 都靠
  flags 精确匹配/字节比较/http 层存在性把它们挡在外面（`rst,ack` 的 flags 字节 0x14
  ≠ `syn,ack` 的 0x12 / `psh,ack` 的 0x18；RST 无载荷不出 http 层）；
- 若本机 80 端口跑着**真实服务**，内核会抢在 mock 之前回真 SYN-ACK（同样通过 client
  的 sniffer 校验，但 ISN 不是 0x2000，时序表对不上）——实验前停掉它，或换一台
  没有 80 服务的机器/容器。

## 与旧示例的关系（本目录同时取代两者，旧目录保留未动）

- `examples/tcp_handshake/`：静态 seq/ack 演示（cseq/sseq 双硬编码、需真实 TCP 服务
  且 Linux raw 收不到回包）——其 **global 算术链**教学点（`seq+1`/`ack+1`）已并入
  本目录注释与时序表，且在闭环里真实跑通；
- `examples/tcp_http_handshake/`：SYN→ACK→GET 三步配方（需**真实** HTTP 服务器；
  Linux raw 回包 socket 只收 ICMP，extract 动态链实际走不通，Windows 需 Npcap）——
  其 **extract 动态 seq/ack** 教学点与 Scapy 对比并入本目录，现在 Linux 单机 root
  即可完整闭环。

## 为什么 client 步骤 2/3 要 delay: 0.5

server 的 handler 是串行的：SYN 命中 → 回 SYN-ACK → `on_recv:` 重新打开 GET 监听
（pcap 设备枚举 + BPF 编译），回环上 client 全程亚毫秒——不 delay 会在下一个监听
就绪前发包而错过（表现为监听侧"少命中一条"）。经验来自
`examples/icmp_mock/README`「为什么 seq 是 1001/1002」一节。

## 验证（不依赖 root/网络的部分）

- 全部 `.pkt`/`.pktl` 经 `prping engine examples/tcp_http_mock/<file>` 解析退出码 0；
- 关键字节事实用 `prping packet --out x.pcap f.pkt` + `prping engine --pcap x.pcap`
  实测：GET 载荷 38 B（ipv4 total 78=20+20+38）、200 OK 载荷 89 B（total 129）、
  flags 反解串、响应帧经内容兜底反解出 http 层（version=整行状态行）。
