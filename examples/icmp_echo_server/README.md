# icmp_echo_server：用 .pktl 配方实现一个 ICMP echo 服务端

展示**配方服务端**：步骤 `wait:`（无值）链路层监听完整帧，按 sniffer 统一谓词匹配
ICMP echo request，命中后 `extract` 把请求字段写进 global，**触发后续步骤**构造
echo reply（`reply.pkt`）并发回——回应包的构造属编排，一律由配方完成。

> 单文件 `packet --wait --raw` 的应答模板（`reply("层","字段")` 内联取值）已移除：
> `.pkt` + `--wait` 现在是**纯监听**（匹配 + 打印 + 统计），任何"回应"都走配方。

## 运行

```bash
# 终端 1 —— 服务端配方（需 root / 管理员；Linux AF_PACKET / macOS·Windows libpcap·Npcap）
sudo prping packet examples/icmp_echo_server/server.pktl

# 终端 2 —— 客户端（任选其一）
sudo prping packet --raw --wait 2 examples/icmp_echo_server/client.pkt 127.0.0.1
prping ping 127.0.0.1          # 或本机局域网 IP；-n 3 限制次数
```

> **回环注意**：发往 `127.0.0.1` 的 ICMP echo request 会被**内核自动替答**（比配方
> 回包更快），客户端 `--wait` 大概率命中的是内核回包。要在回环上**可验证**配方
> 链路，用 `examples/icmp_mock/`（回包 seq 偏移 +1000 作配方标记）；本示例适合
> 对**另一台机器**的请求做应答，或作为配方服务端的入门样板。

## 服务端配方拆解（server.pktl）

```text
recipe:
- packet: listen.pkt     # 步骤 1：持续监听（不发送）
  wait:                  # 无值 = 持续监听直到命中（与 CLI 裸 --wait 同语义）
  extract:               # 命中后从匹配帧取值写 global
  - name: r_id
    from: reply.icmp.id  # 请求的 icmp.id（回显用）
  - name: r_seq
    from: reply.icmp.seq
  - name: r_payload
    from: reply.icmp.payload
  - name: r_src_ip       # 请求方 IP（帧内 ipv4.src）
    from: reply.ipv4.src
  - name: r_dst_ip       # 本机 IP（帧内 ipv4.dst）
    from: reply.ipv4.dst
- packet: reply.pkt      # 步骤 2：触发发包——用 global 构造 echo reply
  raw: true              # 裸 IP 外层走内核 IP 栈路由（无需 MAC 解析）
```

- `listen.pkt` 的 sniffer 即监听规则（`allow_sent: false`：用字面量，不能引用发包字段）；
  包内无 udp/tcp 传输层 → 自动选**链路层监听**（完整帧，icmp/ipv4 字段齐全）；
- `reply.pkt` 全部字段来自 `global("...")`：type=0、id/seq/载荷回显、IP 互换，
  正好构成 echo reply（校验和由序列化器自动重算）；
- 一个 `wait:` 步骤服务一个请求；连续服务就多写几组 listen+reply 步骤
  （见 `examples/icmp_mock/server.pktl`）。

## 客户端（client.pkt，未变）

```pkt
p = raw(bytes="hello ping")
use(p) |> icmp(type=8, id=0x1234, seq=1) |> ipv4(dst=params("ip", "127.0.0.1"))

sniffer:
  - match icmp(type=0, id=id, seq=seq)   # 回包必须是 echo reply，id/seq 与发包一致
```

`--raw --wait 2`：raw 发送 echo request，等匹配应答并打印 `✓ reply matched` + RTT。

## 模式对照

| 模式 | 命令 | 看到什么 | 能回应 |
| --- | --- | --- | --- |
| 纯监听（UDP 载荷） | `packet --wait FILE [ADDR:PORT]`（无值） | UDP 数据报载荷 | 否（只打印匹配） |
| 纯监听（链路层全帧） | `packet --wait --raw FILE`（无值） | eth/IP/ICMP/ARP 任意完整帧 | 否（只打印匹配） |
| 配方服务端（本示例） | `packet server.pktl` | 同上（listen 步骤） | **是**（触发后续步骤发包） |
| 抓包展示 | `server -v [-a] [--filter]` | 同上（dissect 展示） | 否 |
