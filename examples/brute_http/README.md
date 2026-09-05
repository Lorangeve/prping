# brute_http — HTTP 登录爆破（表单 / Basic 认证，免 root）

两个配方对本机靶场 `lab_server.py`（一个「故意不设防」的登录服务）做在线
口令爆破：`form.pktl` 打查询串表单登录，`basic.pktl` 打 Basic 认证。
载荷模式（普通 socket 建连发 HTTP），**不需要 root**。

> ⚠️ **仅限授权环境与本机靶场。** 对未授权目标使用属违法行为。本示例的价值
> 是看清「凭据藏在哪、爆破流量长什么样、命中如何判定」，以及为什么服务端要
> 限速/锁定/监控。

## 运行

```bash
# 终端 1 —— 本机靶场（admin / secret123，监听 127.0.0.1:8000，命中才应答）
python3 examples/brute_http/lab_server.py

# 终端 2 —— 表单登录爆破（4 错 + 1 对）
prping packet examples/brute_http/form.pktl 127.0.0.1:8000

# 或 Basic 认证爆破
prping packet examples/brute_http/basic.pktl 127.0.0.1:8000
```

输出形态：错误候选 → `✗ no reply within 2s`（靶场静默断开），最后一步 →
`reply after 0.x ms`，回包 hexdump 里可见完整的 `HTTP/1.1 200 OK`。

## 靶场行为与「为什么静默失败」

靶场对**正确凭据**回完整 `HTTP/1.1 200 OK`；对错误凭据**不回包直接断开**。

真实系统的爆破面在响应侧信道上更丰富：401/403 vs 200（状态码差异）、响应时间
差（限速/黑名单延迟）。prping 的 TCP 载荷模式读回的是裸响应字节，而裸 HTTP
响应会被裸字节反解误认成以太网帧（ASCII 响应的第 13-14 字节恰为 `"\r\n"` =
0x0d0a ≥ 0x0600，落在 ethertype 位置），http 层反解不出来；TCP 载荷模式又没有
sniffer 匹配路径（UDP 才有，见 `src/engine/pkg/send.rs`）——extract 取不到
状态行，所以靶场用「命中才有响应」的形态，命中判定退化为**有无响应**
（✗ 超时 vs ✓ + 回包 hexdump 里可见的 200 OK）。

## 文件

| 文件 | 角色 | 关键点 |
| --- | --- | --- |
| `lab_server.py` | 本机靶场 | ~/login` 查询串表单 + ~/admin` Basic 认证；命中 200 OK，错误静默断开；**无任何限速/锁定** |
| `form_attempt.pkt` | 表单尝试包 | `http()` 拼 GET 查询串；候选 `params("q")` 整段注入；无 sniffer（见上） |
| `basic_attempt.pkt` | Basic 尝试包 | `Authorization: Basic <base64>` 头；候选 `params("auth")` 整行注入 |
| `form.pktl` | 表单爆破编排 | 5 步 × `params: q=user=admin&password=XXXX` |
| `basic.pktl` | Basic 爆破编排 | 5 步 × 预计算 base64；「明文对 → base64」对照写在注释里 |

## 机制拆解

- **凭据藏在哪，爆破就构造哪**：表单在请求行查询串（`user=admin&password=...`），
  Basic 在 Authorization 头（`Basic base64(user:pass)`，RFC 7617）。两种载体的
  尝试包只有一处不同，编排配方结构完全一致。
- **候选要整段/整行注入**（保持字符串类型）：步骤 params 的纯数字串会被自动
  转成整数（`pass=123456` → Int），`concat` 不收整数——注入完整查询段/完整
  Authorization 头（字母开头）保持字符串。这是引擎类型规则的一个真实坑，
  借本示例演示。
- **Basic 的 base64 是离线预计算的**：DSL 无 base64 原语，
  `printf 'admin:secret123' | base64` 算好写进每步 params——候选表即
  「明文对 → base64」对照表。
- **低速与防御**：每步 `delay: 0.5` 刻意低速。真实服务对这种流量该有的反应：
  同源连续失败 → 限速/验证码/临时锁定/告警；靶场故意全没有，正是「不设防
  登录端点」的反面教材。

## 变体：POST 表单（Content-Length 教学点）

POST 登录需 `Content-Length: <body 字节数>`。DSL 算不出长度，变通做法是
**固定长度 body**（候选口令右侧补空格到定长，服务端 strip 后比对）：

```bash
line = concat("POST /login HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: 24\r\n\r\n",
              "user=admin&password=", params("pass", "123456"), "        ")
```

（`password=` 后接 8 字节定长候选区，Content-Length 恒为 24；注意
`pass` 默认值别用纯数字串——会被 params 转成整数。）

## 参数注入

- `-p ip=` / `-p port=`：改靶场地址/端口（与 lab_server.py 监听一致）。
- 候选口令：`form.pktl` 各步 `params: q=...`；Basic：`params: auth=...`。
- 候选多时：单步配方 + shell 循环（同 brute_pin/README）。
