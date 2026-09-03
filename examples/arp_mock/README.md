# arp_mock：用两个 pktl 配方模拟 ARP 请求/应答（取代 link_arp）

`examples/arp_mock/` 是 `examples/link_arp/` 的 **mock 同构改造版**。旧目录只是
两步串发（request → reply，应答 MAC 靠 `-p tmac` 参数人工注入、无任何校验）；
本目录改成 icmp_mock 的「`*_mock` server/client」形态：**服务端配方**持续监听
ARP 请求并触发应答，**客户端配方**发包 + `wait` 校验 + `extract` 复用，
真正走一遍「广播问 → 单播答」的问答闭环：

| 文件 | 角色 | 配方步骤 |
| --- | --- | --- |
| `server.pktl` | 服务端（ARP 应答机，模拟「持有该 IP 的主机」） | **一组 listen+reply**：`wait:` 无值链路层监听匹配 ARP 请求（`op="request"`）→ extract 请求方 sha/spa/被询问的 tpa 写 global → 触发发包 `arp_reply.pkt`（**谁问的 IP 我来答**：spa=请求的 tpa、tha 回填请求方 MAC，单播发回）。要服务更多次就照 icmp_mock 再写几组 listen+reply |
| `client.pktl` | 客户端（两步流程） | 1. 发 ARP 请求（广播，`tpa=params("ip","127.0.0.1")`）→ `wait: 2` 校验应答（sniffer 匹配 `op="reply"` + 服务端固定 MAC）→ extract `reply.arp.sha` 写 global.rmac（教学点：**从应答学习对方 MAC**——单步用不到，演示复用入口）；2. `delay: 0.5` 后发 gratuitous ARP（`free_arp.pkt`，纯发送无 wait） |

支撑包：`listen.pkt`（服务端监听占位 + sniffer 规则）、`arp_reply.pkt`（应答
模板）、`arp_request.pkt`（请求 + 期望应答的 sniffer）、`free_arp.pkt`
（gratuitous ARP，原样搬自旧目录 `free_arp_81_1.pkt`）。

## ARP 报文结构（RFC 826，28B 定长，无校验和）

ARP 把网络层地址（IPv4）解析成链路层地址（MAC）。报文是 28 字节定长头，
字段含义与请求/应答两种取值：

| 字段 | 宽度 | 含义 | 请求（client 步骤 1） | 应答（server 步骤 2） |
| --- | --- | --- | --- | --- |
| `htype` | 2B | 硬件类型：1 = 以太网 | 1 | 1 |
| `ptype` | 2B | 协议类型：0x0800 = IPv4 | 0x0800 | 0x0800 |
| `hlen` | 1B | 硬件地址长度：6 = MAC 48bit | 6 | 6 |
| `plen` | 1B | 协议地址长度：4 = IPv4 32bit | 4 | 4 |
| `op` | 2B | 操作码：`request()` = 1 询问 / `reply()` = 2 告知 | 1 | 2 |
| `sha` | 6B | 发送方硬件地址（源 MAC） | 请求方 MAC（mock 固定 `00:11:22:33:44:55`） | 应答者 MAC（mock 固定 `66:77:88:99:aa:bb`） |
| `spa` | 4B | 发送方协议地址（源 IPv4） | 请求方 IP | **被询问的 IP**（= 请求的 tpa） |
| `tha` | 6B | 目标硬件地址 | 全零（未知——正是要问的） | 请求方 MAC（回填请求的 sha） |
| `tpa` | 4B | 目标协议地址 | 要解析的 IP（`-p ip=` 可注入） | 请求方 IP（回填请求的 spa） |

htype/hlen 与 ptype/plen 成对出现，是为兼容非以太网/非 IPv4 的解析场景设计的
（Chaosnet、PUP 等历史网络；现代流量里几乎恒为 1/6/0x0800/4）。ARP **没有
校验和字段**——完整性靠局域网内明文广播、全员可验，这也是 gratuitous ARP 能
刷别人缓存的结构性原因。eth 层的 ethertype 由 arp 层自动推导 0x0806，无需手写。

## 请求广播、应答单播：RFC 826 的完整流程

1. 发送方**广播** ARP Request（eth dst=`ff:ff:ff:ff:ff:ff`）：「谁拥有 IP X？
   请告诉 Y」——广播是因为不知道问谁，本地网段全员可闻；
2. 收到请求的每台主机做两件事：① 顺带把请求方的 `spa -> sha` 记进自己的
   ARP 缓存（**即使自己不是被问者**——下次回话就用得上）；② **只有 tpa 是
   自己 IP 的那台**才单播 ARP Reply：「我是 X，我的 MAC 是 Z」，dst=请求方 MAC。
3. 请求方收到应答，把 `tpa -> tha` 写进缓存，后续报文直接单播。

本 mock 的 server 是流程 2 的简化：sniffer 只匹配 `op="request"`，**不检查
tpa 归属**（真实主机会先判断 tpa 是否归自己）——教学上更直白，代价是真实网段
上会把你没问过的请求也答了（想更真实可给 listen.pkt 的 sniffer 追加 tpa 字面量
过滤，作为练习）。client 的 extract（`reply.arp.sha` 写 global.rmac）对应流程 3
的「从应答学习对方 MAC」。

## gratuitous ARP（免费 ARP）：client 步骤 2

普通 ARP 请求问「**别人**的 IP」；gratuitous ARP 问「**自己**的 IP」
（`spa == tpa`），纯广播通告、无应答期待。两大用途：

- **IP 冲突探测**：若真有别的设备占着这个 IP，它会应答/抗议（IPv4 的重复地址
  检测，RFC 5227 标准化）；
- **宣告 MAC<->IP 绑定变化**：开机/换网卡/HA 主备切换后广播一句，其他主机收到
  后把 `spa -> sha` 覆盖进 ARP 缓存，流量切到新位置。

报文特征：op=request（也存在 op=reply 的变体，两者都刷缓存；request 版还能
顺带探冲突）、目的地址广播、tha 全零。本目录把旧 `link_arp/free_arp_81_1.pkt`
原样搬入（`spa=tpa=192.168.81.1`、真实抓包网卡 MAC `2c:f0:5d:ac:20:6a`），
包定义不变，注释补齐了讲解。

## 为什么 mock 里内核不会抢答

ICMP mock（`../icmp_mock/`）要靠「seq 偏移 +1000」区分配方回包与内核替答——
ARP mock 没有这个问题：本 mock 缺省跑在 **Linux 回环 lo** 上（raw 发送缺省
iface=lo），而 **lo 带 IFF_NOARP、不跑 ARP**——内核即使看到 tpa=127.0.0.1 归
本机也不会替答（对照：真实以太网卡上内核 ARP 模块会应答指向本机 IP 的请求）。
AF_PACKET 注入的帧也不经过内核 ARP 处理路径。因此 ARP mock 无需「配方标记」
技巧，问答一一对应。

若改到**真实网段**运行（`-p ip=<邻居 IP>` + `--iface eth0`）：广播出去的请求
可能收到真实设备的应答——client 的 sniffer 用 **op="reply" + 服务端固定 MAC
`66:77:88:99:aa:bb` 双重过滤**，真主机应答的 sha 不等于 mock 约定值，不会
误命中。这与 icmp_mock 给回包造「内核不会产生的特征」是同一思路：固定值既是
mock 的正常手段，也是排除干扰的标记（真实场景应答者 MAC 是本机网卡 MAC，
应动态取得，不应写死）。

## sniffer 写 ARP 规则：op 的字面量形式（验证结论）

在 matchpred.rs / ir.rs 里核实过的语法事实，写规则前先看：

- arp 层可匹配字段：`op / sha / spa / tha / tpa`（`matchpred.rs::field_names`）；
- **op 必须写带引号的字符串字面量**：`op="request"` / `op="reply"`——反解出的
  op 值是 `ArpOp` 的 Display 字符串（`"request"` / `"reply"`，其它 opcode 显示
  为 `op=N`），匹配按字符串相等比较；
- **数值字面量 `op=1` / `op=2` 直接报错**：`("arp","op")` 在 `coerce_literal`
  的字符串位名单里，整数进不了；
- `request()` / `reply()` 是 eng_lib 位常量（`bytes.pkt`：`be16(1)` /
  `be16(2)`），只用于**构造**包（`arp(op=request(), ...)`）；与 sniffer 的
  字符串形式分工不同，别混用；
- MAC/IP 字段（`sha`/`tha`/`spa`/`tpa`）写字符串字面量，按类型强转后比较
  （如 `sha="66:77:88:99:aa:bb"`）；多条 `k=v` 同一 `match` 内是 AND。

## 运行（需 root；链路层 AF_PACKET 收发）

```bash
# 终端 1 —— 服务端配方（持续监听 ARP 请求并应答）
sudo prping packet examples/arp_mock/server.pktl

# 终端 2 —— 客户端配方（两步：请求+wait 校验 → delay 0.5 → gratuitous ARP）
sudo prping packet examples/arp_mock/client.pktl
```

- 链路层监听/发送需要 raw socket 权限（Linux AF_PACKET 需 root 或
  `cap_net_raw`；macOS/Windows 走 libpcap/Npcap 路径）；
- 缺省在 lo 上闭环（内核不抢答，见上）；`-p ip=` 换询问目标、`--iface` 换网卡；
- server 每命中一次要重开下一轮抓包，client 步骤 2 的 `delay: 0.5` 就是给它
  留就绪时间——icmp_mock「为什么 seq 是 1001/1002」一节同一经验，删 delay 的
  话回环上可能在 server 未就绪时发包、错过服务。

## 验证（解析级，不依赖 root/网络）

```bash
./target/debug/prping engine examples/arp_mock/listen.pkt
./target/debug/prping engine examples/arp_mock/arp_reply.pkt
./target/debug/prping engine examples/arp_mock/arp_request.pkt
./target/debug/prping engine examples/arp_mock/free_arp.pkt
./target/debug/prping engine examples/arp_mock/server.pktl
./target/debug/prping engine examples/arp_mock/client.pktl
```

`engine` 会解析并展示层栈（arp 字段 op/sha/spa/tha/tpa、ethertype=0x0806）与
字节 hexdump，配方则展示步骤结构并校验 extract 字段名——ARP 28B 定长、无校验和，
hexdump 可逐字节对照上面的字段表。
