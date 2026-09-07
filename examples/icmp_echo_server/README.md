# icmp_echo_server：用 .pktl 配方实现一个 ICMP echo 服务端

展示**配方服务端**：`serve:` 阶段链路层监听完整帧，按 sniffer 统一谓词匹配
ICMP echo request，命中后 `extract` 把请求字段写进 global，`handler` 步骤构造
echo reply（`reply.pkt`）并发回——回应包的构造属编排，一律由配方完成。

> 单文件 `packet --wait --raw` 的应答模板（`reply("层","字段")` 内联取值）已移除：
> `.pkt` + `--wait` 现在是**纯监听**（匹配 + 打印 + 统计），任何"回应"都走配方。

## 运行

```bash
# 终端 1 —— 服务端配方（需 root / 管理员；Linux AF_PACKET / macOS·Windows libpcap·Npcap）
sudo prping packet examples/icmp_echo_server/server.pktl

# 终端 2 —— 客户端配方（client.pktl：发包 + wait 校验 + extract；等价旧 CLI 裸 --wait）
sudo prping packet examples/icmp_echo_server/client.pktl 127.0.0.1
prping ping 127.0.0.1          # 或本机局域网 IP；-n 3 限制次数
```

> **回环注意**：发往 `127.0.0.1` 的 ICMP echo request 会被**内核自动替答**（比配方
> 回包更快），客户端 `--wait` 大概率命中的是内核回包。要在回环上**可验证**配方
> 链路，用 `examples/icmp_mock/`（回包 seq 偏移 +1000 作配方标记）；本示例适合
> 对**另一台机器**的请求做应答，或作为配方服务端的入门样板。

## 服务端配方拆解（server.pktl）

```text
recipe:
- serve:                 # serve 阶段：监听分派 + 命中处理，阻塞至收工
  max: 1                 # 服务一轮即收工（调大 = 多轮；-1 = 无限）
  rules:
  - packet: listen.pkt   # 监听源：其 sniffer 即本规则的分派谓词
    extract:             # 命中后从匹配帧取值写 global
    - name: r_id
      from: reply.icmp.id  # 请求的 icmp.id（回显用）
    - name: r_seq
      from: reply.icmp.seq
    - name: r_payload
      from: reply.icmp.payload
    - name: r_src_ip     # 请求方 IP（帧内 ipv4.src）
      from: reply.ipv4.src
    - name: r_dst_ip     # 本机 IP（帧内 ipv4.dst）
      from: reply.ipv4.dst
    handler:             # 命中后步骤（每个命中包执行一次）
    - packet: reply.pkt  # 用 global 构造 echo reply
      raw: true          # 裸 IP 外层走内核 IP 栈路由（无需 MAC 解析）
```

- `listen.pkt` 的 sniffer 即监听规则（`allow_sent: false`：用字面量，不能引用发包字段）；
  包内无 udp/tcp 传输层 → 自动选**链路层监听**（完整帧，icmp/ipv4 字段齐全）；
- `reply.pkt` 全部字段来自 `global("...")`：type=0、id/seq/载荷回显、IP 互换，
  正好构成 echo reply（校验和由序列化器自动重算）；
- `serve:` 阶段阻塞至收工：`max: 1` 服务一轮；调大 `max:` 逐轮服务更多请求
  （`max: -1` = 无限，Ctrl+C 优雅收工），`until:` 谓词命中亦可提前收工。

## 客户端配方（client.pktl）

```pktl
recipe:
- packet: client.pkt   # client.pkt 构造 echo request + sniffer 校验（内容未变）
  raw: true            # 有 ipv4 外层（裸 IP）走内核 IP 栈 raw socket，等价旧 --raw
  wait: 2              # 等匹配应答并打印 `✓ reply matched` + RTT
  extract:
  - name: cid
    from: reply.icmp.id
    as: int            # 从回包提取 icmp.id 存 global.cid（多步可复用，本单步示例存而不用）
```

统一为配方形态后与 icmp_mock/client.pktl 同构——区别仅在本示例是**单步**且 reply
为纯回显（无 seq+1000 配方标记）。

## 模式对照

| 模式 | 命令 | 看到什么 | 能回应 |
| --- | --- | --- | --- |
| 纯监听（UDP 载荷） | `packet --wait FILE [ADDR:PORT]`（无值） | UDP 数据报载荷 | 否（只打印匹配） |
| 纯监听（链路层全帧） | `packet --wait --raw FILE`（无值） | eth/IP/ICMP/ARP 任意完整帧 | 否（只打印匹配） |
| 配方服务端（本示例） | `packet server.pktl` | 同上（listen 步骤） | **是**（触发后续步骤发包） |
| 抓包展示 | `server -v [-a] [--filter]` | 同上（dissect 展示） | 否 |
