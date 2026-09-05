# tcp_data_mock：用两个 pktl 配方模拟 TCP 数据传输/确认

`examples/tcp_data_mock/` 下是两个**配方**（`.pktl`）——服务端配方 + 客户端配方，
纯 pktlang 模拟一段 **TCP 数据传输/确认** 会话（数据段 PSH|ACK ↔ 纯 ACK 确认段，
两轮）——由 `examples/tcp_data_flow/`（静态发送 demo，无监听/无校验）改造为
icmp_mock 同构的 mock 服务端/客户端形态：

| 文件 | 角色 | 配方步骤 |
| --- | --- | --- |
| `server.pktl` | 服务端（数据确认服务） | **显式两组** listen+reply：每组 = `wait: -1` 链路层监听匹配 PSH|ACK 数据段 → extract 端口/seq/双向 IP 写 global → 触发发包纯 ACK（ack = 本轮 r_seq + 45）。两组对应 client 两步；要服务更多次就多写几组 |
| `client.pktl` | 客户端（两步数据发送） | 1. 发数据段（seq=0x1000，载荷 45 字节）→ `wait: 2` 校验纯 ACK（ack=0x102D）→ extract reply.tcp.seq 写 global.sseq；2. `delay: 0.5` 后发第二个数据段（seq=0x102D，ack=sseq+1——**用第一轮 ACK 提取的服务端 seq 动态构造确认号**）→ `wait: 2` 校验（ack=0x105A） |
| `listen.pkt` | server 步骤 1 | 链路层监听包体（仅 ipv4，无传输层）+ sniffer：`match tcp(flags=bor(psh(), ack()))` |
| `tcp_ack.pkt` | server 步骤 2 | 纯 ACK 确认段（seq=0x2000，ack=global("r_seq") + 45，window=65535） |
| `tcp_data.pkt` | client 步骤 1 | 数据段 PSH|ACK（seq=0x1000，ack=0x2001）+ wait sniffer |
| `tcp_data2.pkt` | client 步骤 2 | 数据段 PSH|ACK（seq=0x102D，ack=global("sseq") + 1）+ wait sniffer |

## 运行（需 root；链路层抓帧 + raw 注入）

```bash
# 终端 1 —— 服务端配方：命中 PSH|ACK 数据段就回纯 ACK
sudo prping packet examples/tcp_data_mock/server.pktl

# 终端 2 —— 客户端配方：两步数据发送 + wait 校验 + extract 复用
sudo prping packet examples/tcp_data_mock/client.pktl
```

发包用**裸 IP 外层**（无 eth 层）：raw 发送走**内核 IP 栈**注入——Linux
IPPROTO_RAW+IP_HDRINCL 整包 / macOS 剥 IP 头按协议发载荷 / Windows·Linux+pcap
经 libpcap 封以太网帧注入——回环无需 MAC 解析；监听/回包校验走**链路层完整帧**
（帧内 ipv4/tcp 字段齐全，sniffer 直接匹配 `tcp.*`）。

## 四个段的数值对照（载荷均为 45 字节，逐字计算见 tcp_ack.pkt）

| 段 | 方向 | 关键字段 | 来源 |
| --- | --- | --- | --- |
| 数据段 1 | 客户端→服务端 | seq=0x1000, ack=0x2001, flags=PSH\|ACK | `tcp_data.pkt` |
| 确认段 1 | 服务端→客户端 | seq=0x2000, **ack=0x102D**(=0x1000+45), flags=ACK | `tcp_ack.pkt`（ack=global("r_seq")+45） |
| 数据段 2 | 客户端→服务端 | **seq=0x102D**(=0x1000+45), **ack=sseq+1**, flags=PSH\|ACK | `tcp_data2.pkt`（ack=global("sseq")+1） |
| 确认段 2 | 服务端→客户端 | seq=0x2000, **ack=0x105A**(=0x102D+45), flags=ACK | `tcp_ack.pkt` 复用 |

载荷字节精确数（`prping engine examples/tcp_data_mock/tcp_data.pkt` 的层栈输出
核实：ipv4 len=85 = 20 IP + 20 TCP + **45 载荷**）：

```text
"Hello, TCP! This is a data transmission test."
 7("Hello, ") + 4("TCP!") + 5(" This") + 3(" is") + 2(" a")
 + 5(" data") + 13(" transmission") + 6(" test.") = 45 字节
```

改载荷必须同步改三处字面量：`tcp_ack.pkt` 的 `+ 45`、`tcp_data.pkt` 的
`ack=0x102D`、`tcp_data2.pkt` 的 `seq=0x102D` 与 `ack=0x105A`（mock 用固定
字面量便于教学对照数值关系；真实 TCP 的确认号从收到的段头动态读取，不存在
手工同步问题）。

## seq/ack 语义（本 mock 的三个教学点）

1. **确认号 = 期望的下一个字节序号**：服务端收到 seq=0x1000、45 字节的数据段后，
   回 ack = 0x1000 + 45 = 0x102D——「0x102D 之前的都收到了，下一个给我 0x102D」。
2. **发送方 seq 随数据推进**：第二个数据段 seq = 0x102D = 上一段 seq + 载荷长度
   （数据段 2 的 ack 教学点同上）。
3. **累积确认 + 确认号要动态推导**：ack=0x105A 一笔确认两段共 90 字节（0x105A
   之前全部收齐），无需逐段 ACK；client 步骤 1 用固定 ack 建立数值直觉，步骤 2
   的 ack 改用 **extract 出来的服务端 seq** 推导——接收方状态必须来自对端，不能
   拍脑袋固定。教学取舍说明：真实 TCP 中**纯 ACK 不消耗序号**（SYN/FIN 各占 1、
   数据按载荷长度计），本 mock 服务端只发纯 ACK，client 的 ack=sseq+1 里的 +1
   是 mock 简化，重点是「从收到的段头提取/推导」这个动作本身。

**滑动窗口**：两端每段都带 `window=65535`（接收方通告「我还能收 65535 字节」，
发送方未收到新 ACK 前在途数据不得超过它——流量控制的全部基础）。窗口缩放选项
（Window Scale）可把 16 位窗口乘出大窗口，本 mock 不带选项（dataofs=5，20 字节
头无选项区）。**SACK**（选择性确认）：允许 ACK 携带「已收到的不连续块」列表，
丢包时免重传已收段——本 mock 数据连续到达用不上，其价值在乱序/丢包场景。

## TCP 标志位组合速查

| 标志 | 含义 | 常见组合 |
| --- | --- | --- |
| SYN | 同步序列号（建连） | SYN（握手第一步） |
| ACK | 确认号有效 | ACK（确认段）/ SYN\|ACK（第二步）/ PSH\|ACK（数据段）/ FIN\|ACK（挥手） |
| FIN | 结束连接（四次挥手） | FIN\|ACK |
| RST | 重置连接 | RST（内核对未监听端口的反应，见下） |
| PSH | 推送数据（接收方立即交付应用层，不缓冲） | PSH\|ACK（数据传输段） |
| URG/ECE/CWR | 紧急指针/拥塞通告 | 少见 |

位常量来自 `eng_lib/bytes.pkt`：fin()=0x01/syn()=0x02/rst()=0x04/psh()=0x08/
ack()=0x10/urg()=0x20/...——**勿用同名变量遮蔽**；tcp 的 `ack=` 确认号参数与
`ack()` 位常量同名，带括号是位常量调用、裸 `ack=` 是参数，语法可区分。

## 为什么监听匹配 PSH|ACK、校验匹配 flags=ack()

- server 的 `listen.pkt` 用 `match tcp(flags=bor(psh(), ack()))`：sniffer 对
  flags 做**字节级**比较（bor(psh(),ack()) 求值为 0x18 与帧内 flags 字节相等），
  只有数据段命中——本配方刚回的纯 ACK（0x10）、内核 RST（0x04）都不会被当成
  新数据（避免「互相确认」死循环）；若写 flags=ack() 会把纯 ACK 也匹配进来。
- client 两步的 wait sniffer 用 `flags=ack()`（0x10 字节比较）：只认纯 ACK，
  **排除内核 RST**——9090 没有真实 TCP 服务监听，内核收到数据段会立刻回 RST
  （flags=0x04，回环 RTT 亚毫秒），RST 不满足 flags=ack() → 命中的必然是
  server 配方的确认段。这是理解「真实栈对未监听端口的反应」的活教材。
- sniffer 规则只能用字面量/值表达式：server 的**监听**模式没有发包可引用
  （引用发包字段的裸 Ident 构建期直接报错）；client 的 wait 校验写死期望值
  才能逐字段核对 mock 的数值关系。若用 `-p port=` 覆盖端口，sniffer 的
  `sport=9090` 字面量需同步改。

## 为什么端口是 9090（避开 80/8080）

http 层的反解分派规则（`eng_lib/headers.pkt`）：

```text
#[rule(or(tcp(dport=80), tcp(dport=8080)))]
#[rule(contains("HTTP/", in=start_line))]
```

TCP 目标端口 80/8080 的帧载荷会被反解出 http 层（method/path/version）——本
mock 的载荷是普通文本，多出一层 http 只会干扰教学（且易让人误以为 HTTP 在起
作用）；9090 不在分派规则内，帧内只有 tcp/ipv4 干干净净。第二个规则
`contains("HTTP/")` 对本 mock 的载荷也不命中（无 "HTTP/" 子串）。端口可注入
覆盖（`-p port=`），但注意 sniffer 字面量同步（见上节）。

## 为什么 client 第 2 步 delay: 0.5（回环抓包重开的经验）

server 每命中一次都要重新打开下一轮抓包（pcap/AF_PACKET 设备枚举 + 过滤），回环
上 client 全程亚毫秒就跑完两步，不加 delay 会在 server 下一轮监听就绪前就错过
第二个数据段（表现为只命中 server 第 1 组）。经验来源：icmp_mock README
「为什么 seq 是 1001/1002」——同样的配方结构，同样的处方。

## 固定值的说明（mock 的正常手段）

seq（0x1000/0x102D/0x2000）、端口（40000/9090）、确认号字面量（0x102D/0x105A）
都是**固定值便于教学对照**——两终端并排跑，肉眼即可核对每个数值的来龙去脉。
真实场景应动态提取/随机化：ISN 随机（防序号预测攻击）、客户端端口临时分配、
确认号一律从收到的段头读取——本 mock 已示范后者的配方形态（extract → global →
下一步构造），ISN/端口的随机化留给读者改造（`rand()` 类原语 + `global` 注入）。

## 平台/引擎说明（运行前必读）

- **服务端**配方（链路层监听 + 触发发包）在 Linux **默认构建**即可完整运行
  （AF_PACKET 抓帧 + 内核栈 raw 注入，需 root）。
- **客户端**的 `wait` 校验依赖抓包路径收 TCP 段：Linux 默认构建的 raw 发送等待
  走 raw ICMP socket（只有 ICMP 回包能到达——icmp_mock 正是靠它闭环），**TCP 段
  到不了该 socket**，wait 会打印 `✗ no matching reply`，随后 extract 因无回包
  报错中止。跑完整客户端闭环请用 `--features pcap` 构建（Linux/macOS/Windows
  通用抓包路径：先开抓包句柄再发送，任意协议的段都能匹配）。macOS 上裸 IP 的
  raw 等待同样只收 ICMP；服务端不受影响。
- 内核副作用：回环上 raw 注入的 TCP 段会被内核协议栈处理（未监听端口 → RST），
  RST 与本 mock 的所有 sniffer 规则都不匹配，不影响闭环，但抓包时能看到它——
  这本身就是一个学习点。

## 验证（解析级，不依赖 root/网络）

```bash
prping engine examples/tcp_data_mock/listen.pkt     # sniffer 规则解析
prping engine examples/tcp_data_mock/tcp_ack.pkt    # 层栈 tcp|ipv4 + global 表达式
prping engine examples/tcp_data_mock/tcp_data.pkt   # 载荷 45 字节核对（ipv4 len=85）
prping engine examples/tcp_data_mock/tcp_data2.pkt  # seq/ack 表达式 + sniffer
prping engine examples/tcp_data_mock/server.pktl    # 配方：两组 listen+reply
prping engine examples/tcp_data_mock/client.pktl    # 配方：两步 wait+extract
```

`tcp_ack.pkt`/`tcp_data2.pkt` 里的 `global("名", 默认值)` 带**第一轮示例值**：
裸 `engine` 分析没有配方上下文，未设置的 global 会在求值期报错（引擎固有行为，
icmp_mock/dns_echo_listen 的 reply.pkt 同样如此）——默认值让裸分析能展示一份
具体的第一轮包；配方运行时 extract 先写 global，默认值不生效（延迟求值：全局已
设置时默认表达式根本不求值）。

逐字节闭环（构造 → extract → 用 global 构造确认段 → sniffer 校验）还有配方
模拟测试覆盖（参照 `recipe.rs` 的 icmp_mock 仿真测试形态）。
