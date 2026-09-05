# icmp_mock：用两个 pktl 配方模拟 ICMP 发包/回包

`examples/icmp_mock/` 下是两个**配方**（`.pktl`）——服务端配方 + 客户端配方，
各自可包含**任意多步、多包**，纯 pktlang 模拟一次 ICMP echo 会话：

| 文件 | 角色 | 配方步骤 |
| --- | --- | --- |
| `server.pktl` | 服务端（ICMP echo 服务） | **显式多组** listen+reply（pktl 可含任意多包）：每组 = `wait: -1` 链路层监听匹配 echo request → extract id/载荷/双向 IP 写 global → 触发发包 echo reply（**seq 偏移 +1000 作配方标记**，见下）。两组对应 client 两步；要服务更多次就多写几组 |
| `client.pktl` | 客户端（多包流程） | 1. 发 echo request（id=0x1234, seq=1）→ `wait: 2` 校验 echo reply（sniffer 期望 seq=1001）→ extract 回包 icmp.id 写 global.cid；2. `delay: 0.5` 后**复用** cid 再发一个 request（seq=2，期望 1002）→ `wait: 2` 校验 |

发包用**裸 IP 外层**（无 eth 层）：ICMP 发送走**内核 IP 栈 raw socket**——
Linux IPPROTO_RAW+IP_HDRINCL 整包 / macOS 剥 IP 头按协议发载荷（内核建 IP 头，
与 ping 的 raw ICMP 同一模型）——**回环 lo0 无需 MAC/EN10MB**。

## 运行（需 root；raw ICMP socket）

```bash
# 终端 1 —— 服务端配方
sudo prping packet examples/icmp_mock/server.pktl

# 终端 2 —— 客户端配方（两步发包 + wait 校验 + extract 复用）
sudo prping packet examples/icmp_mock/client.pktl
#   （目标 127.0.0.1 已内建在 req1/req2 的 ipv4 dst——配方 + 裸 HOST 无端口
#     会触发「需要目标端口」校验；跨机用 -p ip=<对端 IP>）
```

- **macOS**：回环 127.0.0.1 直接可用（裸 IP 走内核栈，lo0 的 DLT_NULL 不再是障碍）；
- **Linux**：同样回环完整闭环（`ping -c 3 127.0.0.1` 也会被服务端配方应答）。

## 为什么 seq 是 1001/1002（回环内核替答）

发往 `127.0.0.1` 的 ICMP echo request 会被**内核自动应答**（macOS/Linux 都回 type=0
且原样回显 id/seq/载荷——`ping 127.0.0.1` 不需要任何服务端）。如果配方回包是纯回显，
它与内核替答**逐字节相同**，client 的 `wait` 命中的是内核回包（RTT 0.03ms 量级），
根本没法验证"配方回包"这条链路。因此：

- `reply.pkt` 把回包 `seq` 偏移为 `请求 seq + 1000`（配方标记）；
- client 的 sniffer 只匹配 `seq=1001` / `seq=1002`——内核替答永远回显原 seq，
  匹配不到，命中的必然是配方回包；
- client 步骤 2 带 `delay: 0.5`：server 每命中一次都要重新打开下一轮抓包（pcap
  设备枚举 + BPF），回环上 client 全程 <1ms 就跑完，不加 delay 会错过第二个请求
  （表现为只命中 3 条：server 1 次 + client 2 次）。

> 换 `en0 + 本机局域网 IP` 也躲不开内核替答——目标仍是本机地址。要彻底绕开，
> 目标得是另一台机器；或改用非 ICMP 的 mock（如 DNS/UDP，内核不会替答）。

## 配方引擎已覆盖的能力（即"全部功能都支持"）

- **监听触发**：`wait: -1`（= CLI 裸 `--wait`）= 持续监听，sniffer 匹配外部包，
  命中后配方继续（触发后续步骤发包）；
- **链路层监听**：`raw: true` 让监听步骤走完整帧匹配（`icmp` 层字段齐全，无需
  `reply.peer.*`——帧内 ipv4 src/dst 直接可取）；
- **extract 跨步骤**：匹配帧字段 → global（`reply.icmp.id` / `reply.icmp.payload` /
  `reply.ipv4.src|dst`），`as: int|bytes|str`；后续步骤用 `global("...")` 构造发包；
- **多包流程**：客户端两个 request 步骤，步骤 2 复用步骤 1 从回包提取的 `cid`；
- **wait 校验**：`wait: 2` 发送后等匹配应答（sniffer `match icmp(type=0, id=..., seq=...)`）；
- **raw 发送**：ICMP 无传输层 → 自动回退 raw socket（无需每步 `raw: true`，
  显式写更清晰）；`on_timeout`/`on_error` 异常处理同样可用。

## 验证（字节级，不依赖 root/网络）

`recipe.rs::icmp_mock_recipe_simulation`：读真实 demo 文件——构造 echo request →
server 配方 extract → reply.pkt 用 global 构造 echo reply → 断言 type=0/id/payload
回显、seq=请求 seq+1000（配方标记）、IP 互换 → client 配方 sniffer 校验（1001）+
extract cid → req2 复用 cid → server 二次回包（seq=1002）→ client req2 sniffer 校验。
