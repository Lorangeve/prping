# dns_echo_listen：用 .pktl 配方模拟 DNS 发包/回包

客户端发 DNS 查询，服务端**配方** `wait:` 持续监听（UDP 数据报）匹配查询，
`extract` 取查询 id 与对端地址写 global，**触发后续步骤**构造**带 A 记录的 DNS
应答**发回；客户端 `--wait` 校验应答——一次完整的 DNS 请求/响应模拟。

> 单文件 `--wait --raw` 应答模板（`reply("层","字段")` 内联取值）已移除；
> 回应编排一律走配方（同款触发模式见 `examples/dns_trigger/`——那里演示
> 多步编排，本示例是标准 :53 端口 + A 记录应答的最小服务端）。

## 运行（服务端绑定 :53 需 root；客户端 payload 模式无需 root）

```bash
# 终端 1 —— 服务端配方
sudo prping packet examples/dns_echo_listen/server.pktl

# 终端 2 —— 客户端配方（两步：查询 + 校验提取 → 复用 tid 再查询）
prping packet examples/dns_echo_listen/client.pktl 127.0.0.1:53
```

客户端输出（节选）：`✓ reply matched: id=16962 flags=33280`——服务端配方回的应答
id=0x4242（与查询一致）、flags=0x8180（应答位）。

## 服务端配方拆解（server.pktl）

```text
recipe:
- packet: listen.pkt      # 步骤 1：持续监听（不发送）
  wait:                   # 无值 = 持续监听直到命中（与 CLI 裸 --wait 同语义）
  extract:                # 命中后从匹配包取值写 global
  - name: tid
    from: reply.dns.id    # 查询的 dns.id
  - name: cip
    from: reply.peer.ip   # 查询方 IP（对端地址来自 socket）
  - name: cport
    from: reply.peer.port # 查询方 UDP 源端口
- packet: reply.pkt       # 步骤 2：触发发包——用 global 构造应答发回查询方
```

- `listen.pkt` 有 udp 传输层 → 自动选 **UDP 数据报监听**（无需 root 抓包，
  只需绑定 :53 的权限）；监听规则 `match dns(flags=0x0100)` 匹配 DNS 查询（QR=0）；
- **`reply.peer.ip` / `reply.peer.port`**：UDP 监听到的是数据报载荷（没有 udp 头），
  对端地址来自 socket（`peer`），供后续步骤回包（`udp(dport=global("cport"))`）；
- `reply.pkt`：id 回显请求 id、flags=0x8180（QR=1+RD+RA）、questions 回显 +
  `answers=[["example.com", 1, 1, 300, ip4("93.184.216.34")]]`（**列表元组**形式
  的 A 记录，`ip4(...)` 生成记录字节）。

## 客户端配方（client.pktl，两步）

```pktl
global:
- tid=0x1111

recipe:
- packet: client.pkt   # 发查询（id=0x4242）+ sniffer 校验应答（内容未变）
  wait: 2
  extract:
  - name: tid
    from: reply.dns.id
    as: hex            # 提取应答 dns.id → global.tid
- packet: client_reuse.pkt   # 复用 global("tid") 再发查询（第二步校验同款）
  wait: 2
  delay: 0.5           # 给服务端配方重开下一轮监听留时间（回环客户端太快会错过）
```

payload 模式（UDP 载荷经内核送达，无需 root）；`id=id` 是发包字段引用（SentField），
要求回包 dns.id 与发包一致。第二步复用提取的 tid——原 `dns_recipe/` 的「extract 回包
字段 → global → 跨步骤复用」教学点已并入本目录。

## 验证（字节级，不依赖 root/网络）

`recipe_listen_triggers_next_step`（`pkg/recipe.rs` 测试）：UDP 回环——配方线程
`wait:` 持续监听匹配 DNS 查询 → extract `reply.dns.id`/`reply.peer.port` → 后续
步骤构造应答发回客户端 → 客户端收到应答。

## 与其它服务端写法的对照

| 写法 | 文件 | 应答方式 |
| --- | --- | --- |
| 配方服务端（本示例） | `server.pktl` | extract → 触发步骤发包（标准 :53 + A 记录） |
| 配方服务端（多步编排演示） | `examples/dns_trigger/` | 同款触发模式，端口 55353 |
| 纯监听 | `packet --wait listen.pkt` | 无（只打印匹配详情） |

## DNS 协议学习速查（原 dns_flow/ 的学习注释并入）

**报文结构**（头部 12 字节）：ID(2B) 事务标识符 + Flags(2B)（QR/Opcode/AA/TC/RD/RA/
RCODE）+ 四区计数 QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT（各 2B）+ 问题区（QNAME+QTYPE+
QCLASS）+ 应答区（NAME+TYPE+CLASS+TTL+RDLENGTH+RDATA）。本示例的应答走
`answers=[["example.com", 1, 1, 300, ip4("93.184.216.34")]]` **列表元组**形式
（A 记录，`ip4()` 生成记录字节）；DNS 为省空间使用压缩指针（0xC0xx 指向报文前部域名）。

**记录类型**：1=A（IPv4）、28=AAAA（IPv6）、5=CNAME（别名）、15=MX（邮件交换）、
2=NS（权威服务器）、6=SOA（起始授权）、16=TXT（文本）。

**响应码 RCODE**：0=NoError、1=FormatError、2=ServerFailure、3=NXDOMAIN（域名不存在）、
4=NotImplemented、5=Refused。

**查询方式**：RD=1（flags=0x0100）递归查询——客户端要求服务端完成完整解析；RD=0 迭代
查询——客户端自行逐级查询。应答 flags=0x8180 = QR(应答)+RD+RA（支持递归）。
