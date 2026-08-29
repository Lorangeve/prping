# icmp_echo_server：用 `packet --wait --raw` 实现一个 ICMP echo 服务端

展示 **链路层监听完整版**：持续接收**完整帧**（不是 UDP 载荷），按 sniffer 统一谓词
匹配，命中后按 **应答模板**（.pkt 默认导出，经 `reply("层","字段")` 取收到的帧字段）
构造应答帧并 raw 注入。

## 运行

```bash
# 终端 1 —— 服务端（需 root / 管理员；Linux AF_PACKET / macOS·Windows libpcap·Npcap）
sudo prping packet --wait --raw examples/icmp_echo_server/server.pkt

# 终端 2 —— 客户端（任选其一）
prping packet --raw --wait 2 client.pkt 127.0.0.1   # 发 echo request，sniffer 校验 echo reply
prping ping 127.0.0.1          # 或本机局域网 IP；-n 3 限制次数
# 系统 ping 也可：ping -c 3 127.0.0.1
```

> **实测（Linux 容器，arm64）**：`packet --wait --raw` 起服务端后，
> `packet --raw --wait` 客户端 → `✓ reply matched: type=0 id=4660 seq=1 (0.016 ms)`；
> 系统 `ping -c 3 127.0.0.1` → 3/3 回复 0% 丢失。服务端日志：`✓ matched N B — replied N B`。

> **macOS 说明**：`--wait --raw` 用 libpcap 抓包（需 sudo 或 ChmodBPF 授权
> /dev/bpf*）。监听打开**接受 DLT_NULL 回环**（lo0 可收可匹配）、混杂尽力而为
> （anpi* 等设备自动降级）。应答模板为**裸 IP 外层**（无 eth 层），注入走**内核
> IP 栈路由**（macOS 按报文协议开 raw socket 发 IP 载荷）——**回环 127.0.0.1 直接
> 可用**，无需局域网网卡。

服务端输出（节选）：

```
prping packet --wait --raw
raw listen on * — 按 sniffer 规则匹配完整帧，命中后按应答模板注入（Ctrl+C 停止；需 root/Npcap）
✓ matched 74 B — replied 74 B (default export)
  type=8
  frame:
  [0] icmp  type=8 code=0 id=0x1f42 seq=1 ...
  ...
```

客户端 `prping ping 127.0.0.1` 会收到回复（如果本机系统 ping 也可验证：
`ping -c 3 127.0.0.1`）。

## server.pkt 拆解

```pkt
sniffer:
  - match icmp(type=8)                    # 监听规则：ICMP echo request
                                          # （监听无发包，用字面量；支持 and/or/not/字节谓词）

payload = raw(bytes=reply("icmp", "payload"))   # 载荷原样回显
use(payload) |> icmp(type=0, id=reply("icmp", "id"), seq=reply("icmp", "seq"))
  |> ipv4(dst=reply("ipv4", "src"), src=reply("ipv4", "dst"))
```

- `sniffer:` = 匹配规则（与 `--wait SECS` 回包校验、裸 `--wait` UDP 监听同一引擎）；
- **默认导出**（匿名顶层流水线）= **应答模板**：`reply("层","字段")` 在求值时从
  收到的帧反解取值——`id`/`seq`/`payload` 回显、IPv4 地址互换，正好构成
  echo reply（type=0，校验和由序列化器自动重算）；
- 应答为**裸 IP 外层**（无 eth 层），注入走内核 IP 栈路由（Linux
  IPPROTO_RAW+IP_HDRINCL / macOS 按协议 raw socket）——回环与局域网均无需 MAC 解析，
  去重 + 自注入防护防回环。

## 对比三层监听

| 模式 | 命令 | 看到什么 | 能应答 |
| --- | --- | --- | --- |
| UDP 载荷 | `packet --wait FILE [ADDR:PORT]`（无值） | UDP 数据报载荷 | 原样回显 |
| 链路层全帧 | `packet --wait --raw FILE`（无值） | eth/IP/ICMP/ARP 任意完整帧 | 按模板构造应答注入 |
| 抓包展示 | `server -v [-a] [--filter]` | 同上（dissect 展示） | 否 |
