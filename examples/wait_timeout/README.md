# wait_timeout：pktl 的 wait 超时处理（on_timeout）

展示 `.pktl` 配方的**异常处理**：步骤 `wait: 秒数` 超时（未收到匹配应答）时，
`on_timeout: 文件` 打印超时信息并**发送另一个 .pkt**（发其它包），配方继续——
用于超时回退、重试提示、降级通知等场景。

## 运行

```bash
# 终端 1 —— 收 on_timeout 备选包（任意 UDP 收包端，如 python）
python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',59999)); print(s.recvfrom(64))"

# 终端 2 —— 配方：probe 发到无人端口 58888 → wait 2s 超时 → 发 fallback 到 59999
prping packet examples/wait_timeout/recipe.pktl
```

配方输出（节选）：

```
step 1/1  examples/wait_timeout/probe.pkt
  UDP → 127.0.0.1:58888 sent 29 B
  ⚠ wait 超时（2s）——发送 on_timeout 包 examples/wait_timeout/fallback.pkt
on_timeout  examples/wait_timeout/fallback.pkt
  UDP → 127.0.0.1:59999 sent 8 B
prping packet recipe: ... — 1 step(s), 2 packet(s) sent, 0 failed
```

## recipe.pktl 拆解

```yaml
recipe:
- packet: probe.pkt      # 主步骤：发 DNS 查询（到无人端口，必然超时）
  wait: 2                # 发送后等 2s 匹配应答
  on_timeout: fallback.pkt  # 超时 → 打印信息 + 发送 fallback.pkt，步骤继续
  params: qport=58888,fport=59999
```

- `on_timeout` 仅对 `wait: 秒数`（有限等待）生效；`wait: -1` / 负数（无限等待）
  没有超时概念；
- 超时判定：发送成功但 `wait: 秒数` 内未收到匹配应答（replies 为空）；
- 备选包注入当前 global/params（可用 `global("...")` / `params("...")` 构造）；
- 备选包发送失败 → 走 `on_error` 处理；超时后步骤若有 `extract` 的 `reply.` 来源
  仍会因无回包而失败（`on_error: continue` 可跳过继续）。

## 验证（字节级，不依赖 root/网络）

`recipe_wait_timeout_sends_on_timeout_packet`（`pkg/recipe.rs` 测试）：UDP 回环——
步骤 `wait: 1` 发到无人端口 → 超时 → `on_timeout` 发送 fallback 包 → 客户端收到
`fallback` 载荷。

## 相关：`wait` 与 CLI `--wait` 同语义

| pktl | CLI | 语义 |
| --- | --- | --- |
| `wait: -1` 或负数 | `--wait`（无值）或负数（如 `--wait=-2`） | 无限等待（无值 = 持续监听，命中后配方继续） |
| `wait: 秒数` | `--wait SECS` | 发送后等一个匹配应答（超时触发 `on_timeout`） |
| 不写 | 无 | 纯发送 |
