# tcp_handshake_listen：用 .pktl 配方模拟 TCP 三次握手

服务端**配方**：`wait:`（无值）链路层监听完整帧，按 sniffer 规则匹配纯 SYN，
`extract` 取请求的端口/序列号/双向 IP 写 global，**触发后续步骤**构造 SYN-ACK
（`ack = 请求 seq + 1`）发回；客户端 `--raw --wait SECS` 发 SYN、校验 SYN-ACK、
再发最终 ACK——三个握手段齐全。

> 单文件 `--wait --raw` 应答模板（`reply("层","字段")` 内联取值）已移除；
> 回应编排一律走配方（`raw: true` 显式指定链路层/原始发送）。

## 运行（需 root；Linux AF_PACKET / macOS·Win libpcap）

```bash
# 终端 1 —— 服务端配方：命中纯 SYN 就回 SYN-ACK
sudo prping packet examples/tcp_handshake_listen/server.pktl

# 终端 2 —— 客户端：发 SYN + ACK，--wait 2 等并校验 SYN-ACK
sudo prping packet --raw --wait 2 examples/tcp_handshake_listen/client.pkt 127.0.0.1
```

客户端输出（节选）：`✓ reply matched: flags=syn,ack ack=4097`——服务端回的 SYN-ACK
ack=0x1001 = 客户端 SYN seq+1，证明配方 extract → global → 触发发包的推导正确。

## 三个握手段

| 段 | 方向 | 内容 | 来源 |
| --- | --- | --- | --- |
| SYN | 客户端→服务端 | seq=0x1000, flags=SYN | `client.pkt` 的 `syn_pkt` |
| SYN-ACK | 服务端→客户端 | seq=0x2000, **ack=请求 seq+1**, flags=SYN+ACK | `synack.pkt`（`global("r_seq") + 1`） |
| ACK | 客户端→服务端 | seq=0x1001, ack=0x2001, flags=ACK | `client.pkt` 的 `ack_pkt` |

## 服务端配方拆解（server.pktl）

```text
recipe:
- packet: listen.pkt        # 步骤 1：持续监听（不发送）
  wait:                     # 无值 = 持续监听直到命中（与 CLI 裸 --wait 同语义）
  extract:
  - name: r_sport
    from: reply.tcp.sport   # 请求的客户端端口
  - name: r_seq
    from: reply.tcp.seq     # 请求的 seq（ack 推导用）
  - name: r_src_ip
    from: reply.ipv4.src    # 请求方 IP（回包 dst）
  - name: r_dst_ip
    from: reply.ipv4.dst    # 本机 IP（回包 src）
- packet: synack.pkt        # 步骤 2：触发发包
  raw: true                 # 有 tcp 传输层 → 必须显式 raw（否则走 TCP 载荷建连）
```

- `listen.pkt` 只有 ipv4（无 udp/tcp 传输层）→ 自动选**链路层监听**完整帧；
  监听规则 `match tcp(flags="syn")` **精确匹配纯 SYN**（SYN-ACK 反解为
  "syn,ack" 不命中，不会把自己刚回的 SYN-ACK 当新请求）；
- `synack.pkt`：`ack=global("r_seq") + 1`——确认号 = 请求 seq + 1（`+` 算术直接
  作用在 extract 出的整数值上）；端口/IP 全互换（**裸 IP 外层**，raw: true 走内核
  IP 栈路由注入，回环与局域网均无需 MAC 解析）；校验和由序列化器自动重算；
- 一个 `wait:` 步骤服务一次握手；连续服务就多写几组 listen+synack 步骤。

## 注意

- **固定 seq/ack**：为直观展示数值关系，服务端 ISN 固定 0x2000、客户端固定
  0x1000/0x1001。真实三次握手应由客户端**提取**服务端 seq 后动态构造 ACK——
  配方变体见 `examples/tcp_handshake/`（`extract: from: reply.tcp.seq` 存
  `global.sseq` 后再发 ACK）。
- **位常量遮蔽**：元件/变量名勿用 `syn`/`ack`/`fin` 等（会遮蔽 eng_lib/bytes.pkt
  的位常量值函数，见 `client.pkt` 里 `syn_pkt`/`ack_pkt` 的命名）。
- 客户端 ACK 在 `--wait` 前随 SYN 一起发出（两个 export 先发送）；服务端只响应
  SYN，ACK 不匹配规则——握手段完整但 ACK 无回应（真实场景用配方变体保证顺序）。
