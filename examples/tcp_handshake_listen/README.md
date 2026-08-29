# tcp_handshake_listen：用两个 .pkt 模拟 TCP 三次握手

服务端用 **`--wait --raw` 链路层监听**（裸 `--wait` = 持续），按 sniffer 规则匹配
SYN，用**应答模板**（`reply("层","字段")` 取请求字段）构造 SYN-ACK 注入；客户端
`--raw --wait SECS` 发 SYN、校验 SYN-ACK、再发最终 ACK——三个握手段齐全。

## 运行（需 root；Linux AF_PACKET / macOS·Win libpcap）

```bash
# 终端 1 —— 服务端：持续监听，命中纯 SYN 就回 SYN-ACK
sudo prping packet --wait --raw examples/tcp_handshake_listen/server.pkt

# 终端 2 —— 客户端：发 SYN + ACK，--wait 2 等并校验 SYN-ACK
sudo prping packet --raw --wait 2 examples/tcp_handshake_listen/client.pkt 127.0.0.1
```

客户端输出（节选）：`✓ reply matched: flags=syn,ack ack=4097` ——服务端回的 SYN-ACK
ack=0x1001 = 客户端 SYN seq+1，证明模板推导正确。

## 三个握手段

| 段 | 方向 | 内容 | 来源 |
| --- | --- | --- | --- |
| SYN | 客户端→服务端 | seq=0x1000, flags=SYN | `client.pkt` 的 `syn_pkt` |
| SYN-ACK | 服务端→客户端 | seq=0x2000, **ack=请求 seq+1**, flags=SYN+ACK | `server.pkt` 的**应答模板** |
| ACK | 客户端→服务端 | seq=0x1001, ack=0x2001, flags=ACK | `client.pkt` 的 `ack_pkt` |

服务端模板的关键行：

```pkt
use(payload) |> tcp(sport=80, dport=reply("tcp", "sport"), seq=0x2000,
    ack=reply("tcp", "seq") + 1, flags=bor(syn(), ack()), window=65535)
  |> ipv4(dst=reply("ipv4", "src"), src=reply("ipv4", "dst"))
```

- `ack=reply("tcp","seq") + 1`：确认号 = 请求 seq + 1（`+` 算术直接作用在
  `reply()` 返回的整数值上）；
- 端口/IP 全互换（**裸 IP 外层**，无 eth 层——应答经内核 IP 栈路由注入，回环与
  局域网均无需 MAC 解析，macOS lo0 也能工作）；SYN-ACK 的校验和由序列化器自动重算；
- 监听规则 `match tcp(flags="syn")` **精确匹配纯 SYN**（SYN-ACK 反解为
  "syn,ack" 不命中），不会把自己的 SYN-ACK 当新请求循环应答（另有自注入去重兜底）。

## 注意

- **固定 seq/ack**：为直观展示数值关系，服务端 ISN 固定 0x2000、客户端固定
  0x1000/0x1001。真实三次握手应由客户端**提取**服务端 seq 后动态构造 ACK——
  配方变体（3 个文件）：`client.pktl` 步骤 1 发 SYN、`extract: from:
  reply.tcp.seq` 存 `global.sseq`，步骤 2 发
  `tcp(seq=global("cseq")+1, ack=global("sseq")+1, flags=ack())`（模式与
  `examples/tcp_handshake/` 相同）。
- **位常量遮蔽**：元件/变量名勿用 `syn`/`ack`/`fin` 等（会遮蔽 eng_lib/bytes.pkt
  的位常量值函数，见 `client.pkt` 里 `syn_pkt`/`ack_pkt` 的命名）。
- 客户端 ACK 在 `--wait` 前随 SYN 一起发出（两个 export 先发送）；服务端只响应
  SYN，ACK 不匹配规则——握手段完整但 ACK 不做回显（真实场景用配方变体保证顺序）。
