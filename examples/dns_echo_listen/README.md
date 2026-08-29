# dns_echo_listen：用两个 .pkt 模拟 DNS 发包/回包

客户端发 DNS 查询，服务端用 `--wait --raw` 链路层监听匹配查询，按**应答模板**
（`reply("dns","id")` 回显 id）构造**带 A 记录的 DNS 应答**注入，客户端 `--wait`
校验应答——一次完整的 DNS 请求/响应模拟。

## 运行（服务端需 root；客户端 payload 模式无需 root）

```bash
# 终端 1 —— 服务端：匹配 DNS 查询（flags=0x0100），按模板回应答
sudo prping packet --wait --raw examples/dns_echo_listen/server.pkt

# 终端 2 —— 客户端：payload 模式发查询，--wait 2 等并校验应答
prping packet --wait 2 examples/dns_echo_listen/client.pkt 127.0.0.1:53
```

客户端输出（节选）：`✓ reply matched: id=16962 flags=33280` ——服务端回的应答
id=0x4242（与查询一致）、flags=0x8180（应答位）。

## 两个文件

**server.pkt**——监听规则 + 应答模板：

```pkt
sniffer:
  - match dns(flags=0x0100)     # 匹配 DNS 查询（QR=0）

resp = dns(id=reply("dns", "id"), flags=0x8180,
    questions=["example.com"],
    answers=[["example.com", 1, 1, 300, ip4("93.184.216.34")]])
use(resp) |> udp(sport=53, dport=reply("udp", "sport"))
  |> ipv4(dst=reply("ipv4", "src"), src=reply("ipv4", "dst"))
```

- `id=reply("dns","id")`：应答 id = 请求 id（查询-应答配对）；
- `flags=0x8180`：QR=1（应答）+ RD + RA；
- `answers=[[...]]`：**列表元组**形式（`["name", rtype, class, ttl, rdata]`），
  `ip4("93.184.216.34")` 生成 A 记录字节；
- UDP 端口/IP 全互换。应答模板是**裸 IP 外层**（无 eth 层）：应答经内核 IP 栈
  路由注入（Linux IPPROTO_RAW+IP_HDRINCL / macOS 按协议 raw socket），回环与
  局域网均无需 MAC 解析。

**client.pkt**——查询 + 校验：

```pkt
q = dns(id=0x4242, questions=["example.com"])
use(q) |> udp(dport=53) |> ipv4(dst=params("ip", "127.0.0.1")) |> eth()
sniffer:
  - match dns(id=id, flags=0x8180)   # id 与发包一致（SentField），应答位
```

## macOS 说明（lo0 是裸 IP，现在也能工作）

macOS 回环 lo0 链路类型是 DLT_NULL（剥头后是**裸 IP，没有 eth 层**）。早期版本
的 eth 外层应答模板取不到 `reply("eth","src")` 会失败；现在的应答模板为裸 IP
外层，注入走**内核 IP 栈路由**（macOS 按报文协议开 raw socket 发 IP 载荷），
**回环 127.0.0.1 直接可用**：

```bash
# macOS：sudo prping packet --wait --raw server.pkt   （监听全接口）
# Linux：sudo prping packet --wait --raw server.pkt   （AF_PACKET 全接口）
# 客户端都指 127.0.0.1:53
```

监听全接口时会捕获网卡上的**真实 DNS 流量**（`match dns(flags=0x0100)` 匹配所有
RD 查询）；用 `--iface` 限定网卡 + 受控环境可避免噪音。

## 验证（字节级，不依赖 root/网络）

`listen_raw.rs::dns_query_response_simulation`：查询帧 → 模板构造应答（断言外层为
裸 ipv4，无 eth）→ 断言 id 回显、flags=0x8180、A 记录存在、UDP 端口互换 → 客户端
sniffer `match dns(id=id, flags=0x8180)` 校验通过。

## 与 ICMP echo 的对照

| | 客户端 | 服务端模板关键行 |
| --- | --- | --- |
| DNS | `--wait 2 client.pkt HOST:53`（payload） | `dns(id=reply("dns","id"), flags=0x8180, answers=[[...]])` |
| ICMP | `--raw --wait 2 client.pkt HOST`（见 `examples/icmp_echo_server/`） | `icmp(type=0, id=reply("icmp","id"), seq=reply("icmp","seq"))` |
