# sniffer_chat：用 export + sniffer 让两个配方模拟通信

本 demo 演示 pktlang 的三大能力如何配合，让**两个独立进程**像真实网络程序一样
对话：

1. **从发包提取值**——配方 `extract: from: sent.<层>.<字段>` 取本步**发出的包**
   的字段值（无需等回包）；
2. **监听 + 回显**——`prping packet --wait`（无值）按 `.pkt` 的 `sniffer:` 规则匹配
   收到的 UDP 数据报，命中即**原样回显**给发送方（pktlang 对话的服务端）；
3. **按规则校验回包**——客户端的 `--wait` + `sniffer:` 声明匹配服务端回显，
   从回包提取值（`from: reply.<层>.<字段>`）。

## 文件

| 文件 | 角色 |
| --- | --- |
| `server.pkt` | 服务端：`sniffer:` 即监听规则（`and`/`not` 组合 + 字段等式） |
| `step1.pkt` | 客户端步骤 1：发固定 id 的 DNS 查询（sent extract 的取值来源） |
| `step2.pkt` | 客户端步骤 2：复用 tid 发查询 + `sniffer:` 校验回显 |
| `client.pktl` | 客户端配方：两步对话（sent extract → 再发 → 校验回包 → reply extract） |

## 运行

两个终端，先起服务端：

```bash
# 终端 1 —— 服务端：监听 127.0.0.1:55353，回显匹配 sniffer 规则的数据报
prping packet --wait examples/sniffer_chat/server.pkt 127.0.0.1:55353
# 终端 2 —— 客户端：跑配方
prping packet examples/sniffer_chat/client.pktl 127.0.0.1:55353
```

> 服务端省略地址时按 `server.pkt` 包内最外层 udp `dport` 推导监听端口
> （这里是 55353），无需在命令行重复指定。

## 发生了什么（逐行拆解）

**终端 1（服务端）**：

```
prping packet --wait
listening on 127.0.0.1:55353 — echo datagrams matching the sniffer rule (Ctrl+C to stop)
✓ matched 29 B from 127.0.0.1:xxxxx
  flags=256
  datagram:
  [0] dns  id=0x4242 flags=0x0100 q=example.com(A)
  ...
```

- 每个数据报反解后按 `server.pkt` 的规则匹配：
  ```pkt
  sniffer:
    - and(match dns(flags=0x0100), not(match dns(flags=0x8180)))
  ```
  `and` = 两个子句同时满足：是 DNS **查询**（flags=0x0100，RD 位），且
  `not(match dns(flags=0x8180))` 不是应答（flags=0x8180 是响应标志）——
  演示了统一谓词的组合能力。
- 命中 → `✓ matched` 并把收到的 29 字节**原样回显**给发送方。

**终端 2（客户端）**：

```
step 1/2  examples/sniffer_chat/step1.pkt
  ...
  UDP → 127.0.0.1:55353 sent 29 B
  ✓ global.tid = 16962          ← sent extract：从**发包**提取 dns.id
step 2/2  examples/sniffer_chat/step2.pkt
  ...
  ✓ reply matched: id=16962 flags=256 (0.206 ms)   ← sniffer 匹配回显
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
2. **步骤 2**：`dns(id=global("tid"))` 复用提取的 id 再发查询；`wait: 2` 等回显；
   `step2.pkt` 的 sniffer 声明校验回包：
   ```pkt
   sniffer:
     - match dns(id=id, flags=0x0100)
   ```
   `id=id` 是**发包字段引用**（SentField）：要求回包 dns.id == 发包 dns.id——
   服务端原样回显所以必然一致。命中打印 `✓ reply matched: id=16962 flags=256`。
3. 最后 `extract: from: reply.dns.id` 把回包 id 存入 `global.echoed_id`。

## 核心概念对照

| 机制 | 语法/命令 | 作用 |
| --- | --- | --- |
| `export:` | .pkt 的导出段 | 声明要**发出**的包 |
| `sniffer:` | .pkt 的匹配声明 | 客户端：`--wait SECS` 校验回包；服务端：裸 `--wait` 的监听规则 |
| `sent.<层>.<字段>` | 配方 `extract from:` | 取**发包**反解字段（无需 wait） |
| `reply.<层>.<字段>` | 配方 `extract from:` | 取**回包**反解字段（需 wait） |
| 裸 `--wait` | `packet --wait FILE [ADDR:PORT]` | 服务端：匹配 + 回显，Ctrl+C 停止 |

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
