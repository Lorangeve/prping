# dns_trigger：配方 `serve:` 监听触发——sniffer 匹配结果触发发包

展示 `.pktl` 配方的**监听触发**能力：`serve:` 阶段让配方阻塞监听，用规则监听源
`.pkt`（`listen.pkt`）的 sniffer 规则匹配外部到达的包，命中后执行 `handler`
步骤（触发发包）——一个配方就能做服务端（`--wait --raw` 是纯监听、不发包回应，
这里由 **handler 步骤**负责发包，可编排任意多步逻辑）。

## 运行

```bash
# 终端 1 —— 服务端（配方：serve 监听匹配查询 → 触发发包应答）
prping packet examples/dns_trigger/server.pktl

# 终端 2 —— 客户端配方：发查询 + wait 校验应答
prping packet examples/dns_trigger/client.pktl 127.0.0.1:55353
```

客户端输出（节选）：`✓ reply matched: id=16962 flags=33280`——服务端配方触发的
应答 id=0x4242（与查询一致）、flags=0x8180（应答位）。

## 服务端配方拆解（server.pktl）

```yaml
recipe:
- serve:                  # serve 阶段：监听分派 + 命中处理，阻塞至收工
  max: 1                  # 服务一轮即收工（-1 = 无限）
  rules:
  - packet: listen.pkt    # 监听源：其 sniffer 即本规则的分派谓词（不发送）
    extract:              # 命中后从**匹配包**取值写 global
    - name: tid
      from: reply.dns.id    # 匹配包的 dns.id
    - name: cport
      from: reply.peer.port # 查询方的 UDP 源端口（见下）
    handler:              # 命中后步骤——用 global 构造应答发回查询方
    - packet: reply.pkt
```

- `serve:` 阶段阻塞至收工：`max: 1` 服务一轮；`max: -1`（负数）= 无限服务，
  `until:` 谓词命中提前收工，Ctrl+C 优雅收工。普通步骤 `wait: 秒数` = 发送后等
  一个匹配应答（负数已非法——持续监听由 `serve:` 接管）。**字段空值非法**——
  要么不写、要么写值；
- **`reply.peer.ip` / `reply.peer.port`**：UDP 监听到的是**数据报载荷**（没有
  udp 头），`reply.udp.sport` 取不到——对端地址来自 socket（`peer`），供后续
  步骤回包（`udp(dport=global("cport"))`）；
- `raw: true` / `raw: 网卡` 时走**链路层监听**（匹配完整帧，帧内 ipv4/udp 字段
  齐全，无需 peer 来源）。

## 与两种既有监听模式对照

| 模式 | 谁应答 | 匹配后 |
| --- | --- | --- |
| 裸 `--wait`（UDP 监听，纯监听） | 无人应答 | 只打印匹配详情 |
| `--wait --raw`（链路层监听，纯监听） | 无人应答 | 只打印匹配详情 |
| 配方 `serve:`（本 demo） | **handler 步骤** | extract → 触发任意步骤发包 |

## 验证（字节级，不依赖 root/网络）

`recipe_listen_triggers_next_step`（`pkg/recipe.rs` 测试）：UDP 回环——配方
`serve:` 阶段监听匹配 DNS 查询 → extract `reply.dns.id`/`reply.peer.port` →
handler 构造应答发回客户端 → 客户端收到应答。
