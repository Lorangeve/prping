# sniffer_chat：用 export + sniffer + 配方编排让两个进程模拟通信

本 demo 演示 pktlang 的三大能力如何配合，让**两个独立进程**像真实网络程序一样
对话：

1. **从发包提取值**——配方 `extract: from: sent.<层>.<字段>` 取本步**发出的包**
   的字段值（无需等回包）；
2. **监听触发**——服务端配方 `wait:`（无值）按 `.pkt` 的 `sniffer:` 规则匹配
   收到的 UDP 数据报，命中后 `extract` 取值写 global，**触发后续步骤**把查询
   重建后发回查询方（服务端 = 一个配方，见 `server.pktl`）；
3. **按规则校验回包**——客户端的 `wait: 2` + `sniffer:` 声明匹配服务端回显，
   从回包提取值（`from: reply.<层>.<字段>`）。

> 裸 `--wait` 已改为**纯监听**（匹配 + 打印 + 统计，不发包回应）；"回应"一律由
> 配方编排——本 demo 的服务端因此从单文件 `server.pkt` 换成了 `server.pktl`。

## 文件

| 文件 | 角色 |
| --- | --- |
| `server.pktl` | 服务端配方：**两组** listen 步骤（`wait:` 无值）→ extract → echo 步骤回显（对应 client 两步查询——每步发包用独立 socket，只有一组的话第二步的查询无人应答） |
| `listen.pkt` | 服务端步骤 1：`sniffer:` 即监听规则（`and`/`not` 组合 + 字段等式） |
| `echo.pkt` | 服务端步骤 2：用 global 重建查询（同 id）发回查询方 |
| `step1.pkt` | 客户端步骤 1：发固定 id 的 DNS 查询（sent extract 的取值来源） |
| `step2.pkt` | 客户端步骤 2：复用 tid 发查询 + `sniffer:` 校验回显 |
| `client.pktl` | 客户端配方：两步对话（sent extract → 再发 → 校验回包 → reply extract） |

## 运行

两个终端，先起服务端：

```bash
# 终端 1 —— 服务端配方：监听 127.0.0.1:55353（按 listen.pkt 包内 udp dport 推导）
prping packet examples/sniffer_chat/server.pktl
# 终端 2 —— 客户端：跑配方
prping packet examples/sniffer_chat/client.pktl 127.0.0.1:55353
```

## 发生了什么（逐行拆解）

**终端 1（服务端配方）**：

```
step 1/2  listen.pkt
    listening on 0.0.0.0:55353 — 规则: and(match dns(flags=0x0100), not(match dns(flags=0x8180)))
  ✓ matched 29 B from 127.0.0.1:xxxxx
    flags=256
    datagram:
    [0] dns  id=0x4242 flags=0x0100 q=example.com(A)
step 2/2  echo.pkt
  UDP → 127.0.0.1:xxxxx sent 29 B
```

- 每个数据报反解后按 `listen.pkt` 的规则匹配：

  ```pkt
  sniffer:
    - and(match dns(flags=0x0100), not(match dns(flags=0x8180)))
  ```

  `and` = 两个子句同时满足：是 DNS **查询**（flags=0x0100，RD 位），且
  `not(match dns(flags=0x8180))` 不是应答（flags=0x8180 是响应标志）——
  演示了统一谓词的组合能力；
- 命中 → `extract` 取 `reply.dns.id` / `reply.peer.ip` / `reply.peer.port` 写 global
  （UDP 监听载荷没有 udp 头，对端地址来自 socket peer）→ 触发 `echo.pkt` 重建
  查询（同 id 同 flags）发回查询方。

**终端 2（客户端配方）**：

```
step 1/2  examples/sniffer_chat/step1.pkt
  ...
  UDP → 127.0.0.1:55353 sent 29 B
  ✓ global.tid = 16962          ← sent extract：从**发包**提取 dns.id
step 2/2  examples/sniffer_chat/step2.pkt
  ...
  ✓ reply matched: id=16962 flags=256 (0.206 ms)   ← sniffer 匹配服务端回显
  ✓ global.echoed_id = 16962    ← reply extract：从回包提取 dns.id
```

1. **步骤 1**：发出 `dns(id=0x4242)` 查询（0x4242 = 16962），配方用
   `extract: from: sent.dns.id` 把**本步发包**实际携带的 id 存入 `global.tid`。
   这是 `sent.<层>.<字段>` 来源——**不需要 wait**（不用等回包）：

   ```pktl
   - packet: step1.pkt
     extract:
     - name: tid
       from: sent.dns.id
       as: int
   ```

2. **步骤 2**：`dns(id=global("tid"))` 复用提取的 id 再发查询；`wait: 2` 等服务端
   回显；`step2.pkt` 的 sniffer 声明校验回包：

   ```pkt
   sniffer:
     - match dns(id=id, flags=0x0100)
   ```

   `id=id` 是**发包字段引用**（SentField）：要求回包 dns.id == 发包 dns.id——
   服务端按 id 重建回显所以必然一致。命中打印 `✓ reply matched: id=16962 flags=256`。
3. 最后 `extract: from: reply.dns.id` 把回包 id 存入 `global.echoed_id`。

## 核心概念对照

| 机制 | 语法/命令 | 作用 |
| --- | --- | --- |
| `export:` | .pkt 的导出段 | 声明要**发出**的包 |
| `sniffer:` | .pkt 的匹配声明 | 客户端：`wait:` 校验回包；服务端：listen 步骤的监听规则 |
| `sent.<层>.<字段>` | 配方 `extract from:` | 取**发包**反解字段（无需 wait） |
| `reply.<层>.<字段>` | 配方 `extract from:` | 取**回包/匹配包**反解字段（需 wait） |
| `reply.peer.ip/port` | 配方 `extract from:` | UDP 监听步骤的**对端地址**（来自 socket） |
| 配方 `wait:` 无值 | `.pktl` 步骤选项 | 服务端：监听触发（命中后配方继续） |

## 谓词速查（统一谓词引擎）

sniffer 规则 = 子句列表（隐式 OR），子句内条件 AND；支持组合与字节谓词：

```pkt
sniffer:
  - match dns(id=id, flags=0x0100)                    # 字段等式（值=常量/发包引用/表达式）
  - match icmp(ne(type, 8))                           # 不等
  - match raw(startswith("GET "), contains("HTTP/1.1")) # 字节谓词（层原始字节）
  - and(match udp(dport=53), not(match dns(flags=0x8180)))  # 跨层 AND / 取反
  - or(match icmp(type=0), match dns(id=id))          # OR
```

字段集与 proto 实际解析一致（如 dns: `id`/`flags`；`opcode` 不独立解析，
请用 flags 位）；监听规则不能引用发包字段（无发包可引用，构建期报错）。
