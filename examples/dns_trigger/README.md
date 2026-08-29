# dns_trigger：配方 `wait:` 持续监听——sniffer 匹配结果触发发包

展示 `.pktl` 配方的**监听触发**能力：步骤选项 `wait:`（**无值**，与 CLI 裸 `--wait`
同语义）让该步骤不发送，用该 `.pkt` 的 sniffer 规则匹配外部到达的包，**命中后配方
继续**（触发后续步骤发包）——一个配方就能做服务端（与 `--wait --raw` 的应答模板
注入不同，这里由**配方后续步骤**负责发包，可编排任意多步逻辑）。

## 运行

```bash
# 终端 1 —— 服务端（配方：wait 监听匹配查询 → 触发发包应答）
prping packet examples/dns_trigger/server.pktl

# 终端 2 —— 客户端：发查询 + --wait 校验应答
prping packet --wait 2 examples/dns_trigger/client.pkt 127.0.0.1:55353
```

客户端输出（节选）：`✓ reply matched: id=16962 flags=33280`——服务端配方触发的
应答 id=0x4242（与查询一致）、flags=0x8180（应答位）。

## 服务端配方拆解（server.pktl）

```yaml
recipe:
- packet: listen.pkt      # 步骤 1：持续监听（不发送）
  wait:                   # 无值 = 持续监听直到命中（与 CLI 裸 --wait 同语义）
  extract:                # 命中后从**匹配包**取值写 global
  - name: tid
    from: reply.dns.id    # 匹配包的 dns.id
  - name: cport
    from: reply.peer.port # 查询方的 UDP 源端口（见下）
- packet: reply.pkt       # 步骤 2：触发发包——用 global 构造应答发回查询方
```

- `wait:` 与 CLI `--wait` **同语义**：无值或负数 = 无限等待（无值 = 持续监听，本步
  不发送，匹配外部包，命中后配方继续）；`wait: 秒数` = 发送后等一个匹配应答；
  不写 = 纯发送；
- **`reply.peer.ip` / `reply.peer.port`**：UDP 监听到的是**数据报载荷**（没有
  udp 头），`reply.udp.sport` 取不到——对端地址来自 socket（`peer`），供后续
  步骤回包（`udp(dport=global("cport"))`）；
- `raw: true` / `raw: 网卡` 时走**链路层监听**（匹配完整帧，帧内 ipv4/udp 字段
  齐全，无需 peer 来源）。

## 与两种既有监听模式对照

| 模式 | 谁应答 | 匹配后 |
| --- | --- | --- |
| 裸 `--wait`（UDP 监听） | 监听进程原样回显 | 回显 |
| `--wait --raw`（链路层监听） | 监听进程按应答模板注入 | 模板构造应答 |
| 配方 `wait:` 无值（本 demo） | **配方后续步骤** | extract → 触发任意步骤发包 |

## 验证（字节级，不依赖 root/网络）

`recipe_listen_triggers_next_step`（`pkg/recipe.rs` 测试）：UDP 回环——配方线程
`wait:` 持续监听匹配 DNS 查询 → extract `reply.dns.id`/`reply.peer.port` → 后续步骤
构造应答发回客户端 → 客户端收到应答。
