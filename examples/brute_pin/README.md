# brute_pin — UDP 门禁爆破（DNS 载荷，mock 闭环，免 root）

用两个配方模拟一次完整的**在线口令爆破**：`server.pktl` 是只认固定 PIN 的
DNS 门禁，`client.pktl` 是逐个试候选的爆破方。全部流量走 127.0.0.1:55353，
载荷模式发包，**不需要 root**。

> ⚠️ **仅限授权环境与本机靶场。** 本示例的价值是让你在报文层面看清爆破流量
> 长什么样、服务端的「口令校验点」在哪里，以及**为什么真实服务要有限速/锁定/
> 告警**——请勿对任何未授权目标使用。

## 运行

```bash
# 终端 1 —— 门禁（阻塞监听，命中一次后配方结束）
prping packet examples/brute_pin/server.pktl

# 终端 2 —— 爆破客户端（4 个错误候选 + 1 个正确候选）
prping packet examples/brute_pin/client.pktl 127.0.0.1:55353
```

客户端输出：前 4 步 `✗ no matching reply`（门禁对错误候选**静默丢弃**），
最后一步 `✓ reply matched: id=4919 flags=33152`（收到 qname 为
`GRANT.pin.lab` 的应答）。门禁侧命中后打印命中报文反解、extract 三项
global（tid/cip/cport）并回包即退出。

## 协议形态（为什么是 DNS）

- 候选查询：DNS 查询，事务 ID 固定 0x1337、flags=0x0100（标准查询位），
  **候选 PIN 藏在 qname 标签里**：`PIN-XXXX.lab`——线上格式中
  `"PIN-XXXX"` 是连续字节原样出现的。
- 命中回执：同 id 的 DNS 应答，flags=0x8180（QR|RD|RA），qname 改写为
  `GRANT.pin.lab`。
- **载体必须是可反解的协议**：裸 UDP 数据报若反解不出任何注册协议，层栈为空
  （`dissect_bare_app` 只留 remaining，见 packet-dsl
  `src/dissect.rs`），sniffer 无层可匹配——纯文本 "PIN-XXXX" 载荷就是
  这种情况，所以示例用 DNS 作载体，字节谓词打在 dns 层的原始字节上。

## 机制拆解（对着文件看）

| 文件 | 角色 | 关键点 |
| --- | --- | --- |
| `listen.pkt` | 门禁监听 | serve 规则监听源（UDP 数据报监听 :55353，阻塞至命中）；口令校验 = sniffer 一行 `match dns(contains("PIN-4242"))`——字节谓词打在 dns 层原始字节上，**改口令就是改这一行** |
| `grant.pkt` | 触发回包 | extract 到的 tid + 对端地址（`reply.peer.ip/port`）重建应答：`dns(id=global("tid"), flags=0x8180, questions=["GRANT.pin.lab"])` |
| `attempt.pkt` | 爆破尝试 | 候选经 `params("code")` 注入 qname；sniffer 只认 `dns(id=0x1337, flags=0x8180)` 的应答 |
| `server.pktl` | 门禁编排 | `serve:`（`max: 1`）监听 → extract（tid/cip/cport）→ handler 触发发包，单轮闭环 |
| `client.pktl` | 爆破编排 | 同一 attempt.pkt × 5 步，`params:` 逐步覆盖候选；`on_error: continue` 兜住超时 |

教学点：

- **成功判定在服务端匹配规则里**：错误候选在服务端侧「不存在」（不回包），
  爆破方只能靠超时感知——真实服务常如此（或回统一拒绝报文），攻击方靠响应
  差异侧信道猜测；本 mock 连侧信道都没有。
- **配方没有循环**：5 个候选就是显式 5 步（.pktl 的设计取向是每步可读）。
  候选多时用单步配方 + shell 循环：

  ```bash
  for c in 0000 1111 4242; do
    prping packet examples/brute_pin/attempt.pkt 127.0.0.1:55353 -p code=PIN-$c --wait 1 || true
  done
  ```

- **防御视角**：门禁 mock 故意不设防。真实系统在连续失败后应限速（本示例
  客户端每步 `delay: 0.3` 模拟「有礼貌的低速」）、临时锁定、告警——翻成规则
  就是「单位时间同源失败 ≥ N 即阻断」，在 pcap 里表现为一串同四元组的
  请求 + 稀疏响应。

## 参数注入

- `-p ip=` / `-p port=`：改门禁地址/端口（server 与 client 两边要一致）。
- 门禁口令：`listen.pkt` sniffer 里的字面量 `PIN-4242`；客户端候选：
  `client.pktl` 各步 `params: code=PIN-XXXX`（纯数字会被 params 自动转成
  整数，务必带 `PIN-` 前缀保持字符串——见 attempt.pkt 注释）。
