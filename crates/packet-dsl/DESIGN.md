# Packet DSL 设计文档（网络包构建 DSL）

> 状态：设计定稿（已实现，见 `packet-dsl/` crate）
> 实现语言：Rust（独立 crate，不依赖 yak 引擎 / Yakit）
> 解析器：chumsky
> 文件扩展名：`.pkt`
> 产物：结构化 IR（包描述），由宿主消费后序列化/发送

## 1. 背景与目标

一个**独立**的声明式、模块化网络包构建 DSL（Rust crate：`packet-dsl`）：

- 从任意网络层开始构建（链路层 / 网络层 / 传输层 / 应用层）
- 层头函数（`eth`/`ipv4`/`tcp`/...）由标准库 eng_lib 用字节原语构建；
  引擎内置只保留字节原语（hex/raw + `layer` 层标注），未填字段自动补齐
  （随机值 / 默认值 / 自动 checksum）
- 文件即模块（包名 = 文件名），支持 `import` / `export` 双向复用任意层元件
- `use(...) |> 层(...)` 管道式包裹（内 → 外嵌套）
- **DSL 本身不发包**：解析 + 语义分析后产出结构化 IR，宿主负责序列化与发送

## 2. 关键设计决策（ADR 摘要）

| 决策点 | 结论 | 理由 |
| --- | --- | --- |
| 解析器 | chumsky | spans + 错误恢复对带 import 的模块 DSL 体验最好；本场景解析不是性能热点 |
| 文件扩展名 | `.pkt` | 语义直观，与「包名」一致 |
| DSL 产物 | 结构化 IR（字段化描述） | 与宿主解耦，IR 可跨进程传递（适合 yak 引擎 gRPC 通道） |
| 管道语义 | `|>` = 正常包裹一层（内→外嵌套） | 「同栈多层」；多载荷用 `use(a, b)`，多包用多条流水线 + `export:` 具名导出 |
| import/export | 双向，可导出任意层元件 | 任意层文件都能作为上层载荷被引用 |
| 层序校验 | **咨询性警告，不阻断**（`stack_warnings`，见 §9） | 隧道/封装合法（WireGuard 的 `ipv4 |> udp`、VXLAN 的 `eth |> udp`、IPIP 的 `ipv4 |> ipv4` 都是真实协议），硬性分层门禁会误杀；但明显无意义的组合（应用层承载语义层、传输层叠传输层、链路层缺网络层、ICMP/ARP 承载语义层、网络层无法推断内层协议号、裸协议违反 `#[rule]` 声明的载体）值得橙色提示——序列化器对它们要么静默产出误导头字段（proto=0/next_header=59），要么报难以理解的 `UnknownEthertype` |
| 运行环境 | 嵌入 yak 引擎 / Yakit | 通过 IR + 序列化边界与引擎集成 |

## 3. 术语

- **元件（component）**：任意一层或几层的包描述，可命名、可导出、可被 import。
- **最小元件（minimal element）**：层头函数生成的最小合法头部，未填字段走自动值。
- **流水线（pipeline）**：`use(元件...) |> 层(...)` 的包裹链（内 → 外）。
- **包组（packet group）**：命名流水线展开出的多个包（多载荷 `use(a, b)` 时）。

## 4. 语法规范

### 4.1 BNF 草案

> 本节为早期 BNF 草案（不含 `func` / 值函数 `-> bytes` / `params()` / 值位置 `hex()` /
> `+` 数字加法 / import 别名等后续演进）。**现行权威语法（词法 + 语句 + 表达式 EBNF）
> 见 [`GRAMMAR.md`](GRAMMAR.md)**，与 `lexer.rs`/`parser.rs` 实现一一对应；冲突处以
> `GRAMMAR.md` 为准。

```
file          := shebang? (comment | stmt)*
stmt          := export_block | import_stmt | def_stmt | pipeline | sniffer_stmt

export_block  := "export" ":" export_item+
export_item   := "-" IDENT            # 容忍 "-c" 无空格写法
import_stmt   := "import" IDENT ("{" ident_list "}")?
def_stmt      := IDENT "=" expr
pipeline      := use_expr layers
use_expr      := "use" "(" ident_list ")"
layers        := layer (layer)*
layer         := "|>" call            # 包裹一层（内 → 外嵌套）
call          := IDENT "(" arg_list? ")"
arg           := IDENT "=" value | value
value         := STRING | INT | HEX | BOOL | value_list
ident_list    := IDENT ("," IDENT)*
comment       := "#" ... EOL

# 回包/监听匹配（--pkt --wait 校验应答、--listen 监听规则；求值期语义，宿主
# 负责匹配；顶层列表任一命中 = 隐式 OR；谓词组合与 #[rule] 同构）
sniffer_stmt  := "sniffer" ":" sniffer_pred+
sniffer_pred  := "-" sniffer_match | "-" "and" "(" sniffer_pred_list ")"
               | "-" "or" "(" sniffer_pred_list ")" | "-" "not" "(" sniffer_pred ")"
sniffer_match := "match" IDENT "(" sniffer_item_list? ")"
sniffer_item  := sniffer_field | "ne" "(" IDENT "," value ")"
               | "mask" "(" num ")" | "startswith" "(" STRING ")"
               | "endswith" "(" STRING ")" | "contains" "(" STRING ")"
sniffer_field := IDENT "=" value      # 值 = 字面量（常量）| 裸 IDENT（发包同层同名字段，
                                      #     监听模式无发包报错）| 值表达式（原语/值函数/
                                      #     params → 字节级比较）
```

> 实现注记：
> - `call` 同时容忍无参裸调用 `tcp`（等价于 `tcp()`），与 §4.2 示例一致。
> - 括号/方括号内容忍换行：多行调用 `http(method="GET",\n  path="/")`、多行列表
>   `headers=[...]`、多行 `use(a, b)` 均合法（仅流水线续行 + 参数换行，不改语句边界）。
> - 运行时参数（求值期扩展，非 BNF 语法）：`--params k=v` 注入，值位置写
>   `params("name"[, "默认值"])`（如 `tcp(dport=params("port", "443"))`），
>   求值时从宿主参数表取值并按字段类型解析；宿主入口为 `resolve_with_params`。

### 4.2 管道语义

- **`|>` = 正常包裹**：把当前内容作为载荷，包上该层，内 → 外依次嵌套。
- **`use(a, b)` = 多载荷**：每个 use 元件独立成包（a-tcp、b-tcp 两个包）。
- **多包 = 多条流水线**：需要同载荷多协议（如 TCP 与 UDP 各一发）时写多条流水线，
  用 `export:` 具名导出（`||>` 或分支语法已移除）。

```
# 同载荷、两种传输 → 两条流水线（原 `||>` 展开）
a = http(method="GET")
tcp_full = use(a) |> tcp(dport=443) |> ipv4()
udp_full = use(a) |> udp(dport=53)  |> ipv4()
export:
- tcp_full
- udp_full
```

同一行内多个 `|>` 为嵌套包裹：

```
use(a) |> tcp(dport=443) |> ipv4(src="1.1.1.1", dst="2.2.2.2") |> eth()
# 产出一个完整协议栈包
```

### 4.3 注释

`#` 到行尾为注释，支持 `#!` shebang 首行（可选）。

### 4.4 边界规则（决策）

| # | 边界问题 | 决策 |
| --- | --- | --- |
| 1 | `use(a,b) |> tcp` 是 a、b 各自成包 | 每个 use 元件**独立成包**（a-tcp、b-tcp 两个包）。「a、b 作为一组同时塞进一个 tcp 包」第一版**不支持**，留作扩展（可后续加 `group(a,b)` 语法） |
| 2 | 命名流水线 `full = use(a) |> tcp` 展开出多个包（`use(a,b)` 时） | `full` 是**一组包**（包组）。import 别处 `use(full)` 时：展开组内所有包、逐包再应用外层包裹 |
| 3 | 顶层匿名流水线的导出名 | 顶层 `use(...) |> ...`（未赋值）是**该文件的默认导出**；`import b`（不带大括号）引入默认导出 + 全部命名导出。命名流水线用 `export:` 列出名字。一个文件只能有一个默认导出（多条流水线请用 `export:`） |

> 决策 #2 的求值规则：`use(full) |> tcp` 中 `full` 若展开为 `[tcp-a, udp-a]`，
> 则结果为 `[tcp(tcp-a), tcp(udp-a)]`——组内逐包包裹。

## 5. 内置原语表（字节原语 + 层标注）

引擎内置只保留**字节原语**（`hex`/`raw` + 值位置原语）与唯一的 **`layer` 层标注原语**
（`layer(kind, bytes[, src, dst])`，字节 + 层类型字面量 → 该层，序列化时引擎按层类型
自动补 length/checksum）。层头函数（`eth`/`arp`/`ipv4`/`ipv6`/`icmp`/`tcp`/`udp`/`http`/
`dns`）全部由标准库 [eng_lib/headers.pkt](../eng_lib/headers.pkt) 用字节原语拼出，
`*_bytes` 具名包装（`eth_bytes`/`ipv4_bytes`/...）由 [eng_lib/bytes.pkt](../eng_lib/bytes.pkt)
定义为 `func eth_bytes(bytes) { layer("eth", bytes) }`（库导出隐式可见）。

| 类别 | 函数 | 说明 |
| --- | --- | --- |
| 数据 | `raw(bytes)` / `hex("...")` | 原始字节载荷 |
| 值 | `concat`/`u8`/`be16`/`be32`/`be64`/`le16`/`le32`/`le64`/`tpl`/`raw`（值位置）/`count`/`cksum`/`md5`/`sha1`/`sha256`/`rand16`/`rand8`/`rand_bytes`/`pad` | 字节构建/整数/校验和/摘要/填充原语（值位置；count/cksum/md5/sha1/sha256 为引擎原语，见 §5.2；`len` 是可组合的库值函数 `count∘raw`（bytes.pkt），非引擎原语；rand_bytes 随机 / pad 确定性填充对称；**变长整数 varint/qvarint 已下沉为 eng_lib/vint.pkt 库 proto**（非内置原语），与 `#[meta(codec=...)]` 字段方案共用编码实现） |
| 值 | `bor`/`band`/`bxor`/`bnot`/`shl`/`shr` | 位运算（整数或同宽字节列表元素级；bor 变参）——协议标志位（TCP/IPv4 flags、ARP op）原为引擎原语 `tcpflags`/`ip4flags`/`arpop`，已下沉为 eng_lib/bytes.pkt 位常量值函数（`syn()`/`df()`/`request()`…）组合：`tcp(flags=bor(syn(), ack()))` |
| 值 | `global("名"[, 默认])`（值位置特判） | 配方全局存储读取——`.pktl` 的 `global:` 段 / 步骤 `extract` / 宿主 `-g k=v`（--global）注入；与 `params` 对称但值为**类型化**字面量（Int/Hex/Str/字节列表原样返回，不经过字符串形状解析），可直接参与 `+`/`be16`/位运算（`tcp(ack=global("seq") + 1)`）；未设置时**延迟求值**默认值，两者都无则报错（同 `params`） |
| 值 | `reply("层", "字段")` | 读取当前回包的反解字段——配方 `extract` 的 `from:` 表达式专用（求值期宿主注入回包访问器，其余上下文回退用户函数——eng_lib 的 ARP 位常量 `reply()` 撞名保持原语义）；`from: reply.<层>.<字段>` 直取形态在配方解析期改写为本调用。数值字段 → Int、地址/字符串字段 → Str（display）、payload/body/raw 字节 → 字节列表 |
| 层标注 | `layer(kind, bytes, src?, dst?)` | 字节 → 对应层；`kind` 为闭集字面量，`src`/`dst` 仅 `ipv4`/`ipv6`（伪头部校验和） |

> 自动行为（checksum / length / ethertype / 伪头部）留在 Rust 序列化层，见 §8。
> `layer(..., src="random")`（`ipv4`/`ipv6` 包装透传）仍支持 `"random"`；层头函数
> 不暴露该关键字——随机值用构建期原语：整数方向 `rand16()`/`rand8()`（端口/ID/seq），
> 字节方向 `rand_bytes(n)`（随机 MAC/payload/nonce，`rand_mac()` 即 `rand_bytes(6)`）；
> 确定性填充用 `pad(n)`（n 零字节，与 rand_bytes 对称）。

> **地址值函数已下沉**：旧内置 `ip4`/`ip6`/`mac` 值原语由通用模板原语 `tpl`
> 取代（见 §5.3）——`eng_lib/bytes.pkt` 定义 `func ip4(s) -> bytes { tpl("%d{4:.}", s) }`、
> `func ip6(s) -> bytes { tpl("%x2{8:}", s) }`、`func mac(s) -> bytes { tpl("%x{6:[-.:]}", s) }`
> （库导出隐式可见）。**值位置的域名需显式 `dns()`**（`ip4(dns("host"))`；ipv6 用
> `dns(host, 6)` 取 v6）；地址**字段**位置（`layer` 的 src/dst、ipv4/ipv6 字段）仍由
> 引擎校验解析 + 域名回退（见 §6.3）。

> 组合函数（旧内置 `net4`/`net6`）已迁移为 **pkglang 用户函数模块**
> （`eng_lib/net.pkt`，库导出隐式可见，无需 import 直接使用），见 §5.2。

### 5.2 用户函数（func）

组合逻辑（如 `net4`/`net6` 一次生成 IP+以太网两层）可以写成**具名参数化函数**，
从 Rust 内置下沉为 pkglang 模块；**值函数**（`-> bytes`/`-> int`）返回
值表达式（字节列表 / 整数），与层函数（体是流水线）以返回类型标注区分：

```
# net.pkt（层函数：体是流水线）
func net4(dst, src="0.0.0.0", ttl=64, id=0, proto, tos, flags,
          src_mac="00:00:00:00:00:00", dst_mac="ff:ff:ff:ff:ff:ff", ethertype) {
    ipv4(src=src, dst=dst, ttl=ttl, proto=proto, tos=tos, id=id, flags=flags)
        |> eth(src_mac=src_mac, dst_mac=dst_mac, ethertype=ethertype)
}
export:
- net4
```

```
# bytes.pkt（值函数：体是值表达式）
func dns_name(s) -> bytes { tpl("%L", s) }             # -> bytes：字节返回
func mac(s) -> bytes { tpl("%x{6:[-.:]}", s) }         # -> bytes：tpl 模板解析
```
> 校验和/摘要不再需要库层组合：`cksum`（RFC 1071 反码）与 `md5`/`sha1`/`sha256`
> 是引擎原语（值位置，输入字节列表或字符串）——原 `words16`/`fold16`（校验和的
> 切分/折叠中间机制）与 `sum`（无真实用户的整数求和）已回退移除，DSL 不暴露
> 中间步骤。

语法与语义：

- `func name(p1, p2=默认, ...) { pipeline }`；函数体是流水线，`use(...)` 可选。
- **值函数**：`func name(...) -> bytes|int { 值表达式 }`——返回类型是**声明 +
  运行时校验**（`bytes` → 调用方字节上下文校验；`int` → 结果须为整数），非静态检查。
  值函数可出现在值表达式中（`be16(double(0x1234))`）、作库导出。
- **无高阶原语**：lambda / map / filter / 多态折叠 / **reduce** 均已移除（中间形态：
  算法原语化、语言最小化、求值保证终止）——整数聚合由引擎原语 `count` 提供
  （`len` = `count∘raw` 是可组合的库值函数，bytes.pkt），
  可变长列表（DNS questions/answers、HTTP headers）走 proto list/rest 机制。
- **参数全部可选**：无默认值 = 「未设」——在层参数位置**省略**（走自动值）；
  有默认值 = 未传时用默认。实参值可为任意 `Value`（含 `params("x")`、列表、参数转发）。
- **层片段语义**：函数体无 `use` 时以「空包种子」求值（从一个空包开始逐层包裹），
  因此函数返回的是多层片段，可直接出现在 `|>` 里：
  `use(p) |> net4(dst="1.1.1.1")` → `[raw, ipv4, eth]`。
- **嵌套与循环**：函数体内可调用其他函数（参数按调用处环境解析后绑定，
  避免跨层 `Value::Ident` 滞留成循环）；循环引用由求值栈检测报错。
- 函数名与 def 共用同一作用域（重名即冲突）；函数可被 `export`/`import`，
  也可出现在 `use(...)` 中（零参调用，全部走默认值）。
- **doc 注释**：紧贴 `func` 上方的连续 `#` 注释行（去掉 `# ` 前缀）作为该函数的说明，
  空行/非注释行隔开则不算（注释在词法层被丢弃，解析成功后按函数起始行回扫源码抓取）。
  行格式：普通行为摘要，`@param 名: 说明` 逐参数说明，`@auto: 说明` 描述序列化自动行为；
  解析为结构化 `ast::FuncDoc`（summary/params/auto），`--eng --ls` 与 LSP 悬停按
  「签名 + `"""..."""` 摘要文档字符串 + 逐参数 + auto」同构展示（对齐内置原语
  raw/hex/layer 的字段表风格；摘要置于签名下第一行）。
  展示链路：`FuncStmt.doc` → `Func.doc` / `LibExport.doc`。
- 校验：函数体里的标识符值必须是已声明参数（防拼写错误）；非函数定义里出现
  参数引用直接报错。

### 5.3 字符串模板原语 `tpl(template, input)`

> 通用「文本 → 字节」解析器（取代旧 `ip4`/`ip6`/`mac`/`dns_name` 值原语的字面量
> 解析；实现见 `packet-dsl/src/tpl.rs`；模板子语法 EBNF 见 `GRAMMAR.md` §4.7）。
> 模板串 = 字面字符与说明符交替，**锚定全匹配**
> （输入全部消费）；字面字符/分隔符**匹配但不产出**（scanf 式解析器），说明符
> 按序产出字节拼接。

| 语法 | 语义 |
| --- | --- |
| `%c` | 恰好 1 字节任意值（通配） |
| `%d1`/`%d2`/`%d4`（`%d` ≡ `%d1`） | 十进制，输出 1/2/4 字节大端；贪心最多 3/5/10 位数字，值域 0..256^w−1 越界报错 |
| `%x1`/`%x2`/`%x4`（`%x` ≡ `%x1`） | 十六进制，同上（贪心最多 2w 位 hex） |
| `%L` | **DNS 名字序列（动态宽度，tpl 唯一例外）**：消费剩余全部输入为点分标签，每个标签输出（u8 标签字节长 + 原文），末尾 0x00；空标签跳过（尾点/连续点容忍）；标签 ≤63B、总长 ≤255B。不吃宽度/重复参数。`dns_name("example.com")` ≡ `tpl("%L", "example.com")`——旧 `dns_name` 值原语下沉至此 |
| `{n}` | 重复 n 次（无分隔符） |
| `{n:sep}` | 重复 n 次，分隔符为单字符 sep；`{n:}` 缺省 sep = `:` |
| `{n:[chars]}` | 重复 n 次，分隔符为字符类中任一字符（如 mac 的 `{6:[-.:]}`） |
| `::`（仅 sep=`:` 的重复） | 输入 `::` = 零填充压缩：缺位补零组（ip6 的 `fe80::1`/`::1`/`fe80::` 一个模板通吃；多个 `::` 报错） |
| `%%` | 转义字面 `%`；其余字面字符仅支持 ASCII |

输入为**字节列表**时**等宽直通**（长度 = 模板总输出宽且逐字节 0..255 即原样返回，
与旧 `mac(rand_mac())` 一致；**含 `%L` 的模板输出宽动态不可算 → 不接受字节列表
输入**）；否则按字符串解析。典型用法：

```
ip4("1.2.3.4")   ≡ tpl("%d{4:.}",  "1.2.3.4")     # 4×u8 点分
mac("aa:bb:..")  ≡ tpl("%x{6:[-.:]}", "aa:bb..")  # 6×u8 分隔符容忍
ip6("fe80::1")   ≡ tpl("%x2{8:}",   "fe80::1")    # 8×be16 含 :: 压缩
dns_name("example.com") ≡ tpl("%L", "example.com")  # 长度前缀 + 尾 0
tpl("%d2:%d2", "5353:80")                          # 端口对 → 4 字节
```

## 6. 值类型与转换（类型表）

> 权威定义。DSL 是**字节本位**设计："类型"是**值 → 字节编码边界的转换规则**，不是值
> 自带的属性。值域上只有两类：**数值**（hex/十进制字面量）与**字节**（raw/hex 产物、
> 字符串）；地址/MAC/flags 不是独立类型，而是字符串在边界的**校验性解析**——值位置
> 经 `tpl` 模板（§5.3，ip4/ip6/mac 值函数），字段位置经引擎 coercer。
> 本文档是这些规则唯一权威；`hex_string_bytes` / `val_ip4`/`ip6` /
> `val_bytes` 等 coercer 与之一一对应（改动须同步此处）。

### 6.1 值层形态（`ast::Value`，句法形态，非类型）

| 形态 | 说明 |
| --- | --- |
| `Str` / `Int` / `Hex` | 字面量（字符串 / 十进制整数 / 十六进制；布尔已随高阶原语移除） |
| `List` | 列表字面量；字节原语的产物也是它（**值层不区分「字节列表」与其他列表**） |
| `Param` | `params("name"[, 默认])` 运行时参数引用，求值恒产出 `Str` |
| `Ident` / `Call` / `Add` | 函数参数引用 / 值调用（原语或值函数）/ 数字加法 |

### 6.2 语义类型（两类值）

| 类型 | `Value` 表示 | 产生 | 到字节编码 |
| --- | --- | --- | --- |
| 数值 | `Hex` / `Int` | `0x4242`（hex 字面量）、`80`（十进制字面量）、`+`、`count`（引擎原语）与 `len`（库值函数 `count∘raw`）、`rand16`/`rand8`、`bor`/`band`/`bxor`/`bnot`/`shl`/`shr`（整数形态）、`params(...)`（按形状解析，见 6.3） | `u8` 1B / `be16`/`le16` 2B / `be32`/`le32` 4B / `be64`/`le64` 8B（大端/小端；范围 0..2^n-1，越界报错） |
| 字节 | `List(Int 0..255)` | `hex("...")`、`raw("...")`（值位置）、**字符串**（UTF-8，同 Python `b"..."`）、`concat`/`u8`/`be16`/`be32`/`be64`/`le16`/`le32`/`le64`/`tpl`、`varint`/`qvarint`（变长整数，宽度取决于值——eng_lib/vint.pkt 库 proto 值位置调用）、`cksum`（2B 反码校验和）、`md5`/`sha1`/`sha256`（16/20/32B 摘要）、`rand_bytes(n)`（n 随机字节）、`pad(n)`（n 零字节）、值函数（`-> bytes`） | 原样 |

**字符串的消费**（不是类型）：
- 字节上下文 → UTF-8 编码（`raw("abc")` ≡ Python `b"abc"`）；
- 地址/MAC 上下文 → `tpl` 模板解析（值位置：`ip4`/`ip6`/`mac` 值函数，见 §5.3）
  或引擎 coercer（字段位置：`layer` src/dst、ipv4/ipv6 字段；含域名回退）；
- flags 上下文 → **不接受字符串**：协议标志位用位常量值函数组合
  （`tcp(flags=bor(syn(), ack()))`，位常量见 eng_lib/bytes.pkt；原引擎
  `tcpflags`/`ip4flags`/`arpop` 已下沉）；
- 数值上下文 → **禁止**（`be16("4242")` 报错）；唯一例外是 `params(...)` 按形状解析（见 6.3）。

### 6.3 转换规则（唯一权威）

| 源 → 目标 | 规则 |
| --- | --- |
| 数值 → u8/be16/be32/le16/le32 | 直接取值，范围检查（`int_of`）；`be16`/`be32` 大端、`le16`/`le32` 小端（低字节在前） |
| 字符串 → 数值 | **仅 `params(...)` 按形状解析**：`0x`/`0X` 前缀 = 十六进制数值、纯十进制数字 = 数值、其余 = 字符串（`be16(params("port","53"))` = `[0x00,0x35]`、`be16(params("id","0x4242"))` = `[0x42,0x42]`）；**默认值可为任意值表达式**（`params("port", be16(0x1235))` 未注入时 = `[0x12,0x35]`，字符串默认仍形状解析）。**裸字符串字面量进数字位置（`be16("0x4242")`）仍报错**——hex 形式写 `be16(hex("0x4242"))`，十进制写 `be16(0x4242)` 字面量 |
| 字符串 → 字节 | UTF-8 编码（`raw` 值位置 / `val_bytes`；`raw("abc")` ≡ `b"abc"`） |
| 字符串 → 地址/MAC | **值位置经 `tpl` 模板**：`ip4`/`ip6`/`mac` 值函数（`%d{4:.}` / `%x2{8:}` / `%x{6:[-.:]}`，含 ip6 `::` 压缩）；**字段位置经引擎 coercer**：ip 文本/域名回退（`val_ip4`/`ip6` + `dns_lookup`）；**域名在值位置需显式 `dns()`**（`ip4(dns("host"))`，v6 用 `dns(host, 6)`） |
| 字节 → u8/be16/be32/le16/le32 | **同宽直通**（`u8` 1B / `be16` 2B / `be32` 4B 原样；`be16(hex("1234"))` = `be16(0x1234)` = `[0x12,0x34]`）。**小端变体反转**：字节输入按大端解读后重编码为小端（`le16([0x01,0x02])` = `[0x02,0x01]`，`le16(0x1234)` = `[0x34,0x12]`）；长度不符报错带字节数 |
| 字节 → 地址/MAC | **tpl 等宽直通**：字节列表长度 = 模板总输出宽且逐字节 0..255 即原样（`mac(rand_mac())` 随机 MAC）；长度不符报错 |
| hex 字符串 → 字节 | `hex()`：去空白、可选 `0x`/`0X` 前缀、须偶数长度纯 hex，否则报错 |
| 值函数体 → 字节 | `-> bytes` 是**声明 + 运行时校验**（`bytes_of`），非静态检查 |

### 6.4 歧义点与既定规则

- **字符串不隐式转数值**：`be16("0x4242")` / `u8("80")` 一律报错——hex 形式写
  `be16(hex("0x4242"))`，十进制写 `be16(0x4242)` 字面量；字符串进数值位置的唯一入口是
  `params(...)` 按形状解析（见 6.3）。
- **`params` 按形状解析**（取代已移除的 `int()`）：`0x`/十进制 → 数值，其余 → 字符串；
  要字节写 `hex(params("id", "4242"))` 或直接用字符串。数值形文本载荷在值表达式里会变
  数值，层参数路径（`raw(bytes=...)`/地址字段）保持字符串。
- **`List` 恒为字节**：值层不另设「字节类型」；数字上下文收到 `List` 即类型错误——但
  **同宽直通**例外：`be16(hex("1234"))` 合法（2 字节直通，**恒等**——字节进字节出，
  不产生数值），宽度不符才报错。**字节不隐式解码回数值**（`int(字节)` 解码原语已随
  `int()` 移除）：构造方向只需值 → 字节，反向解码需求不存在；数值随机用
  `rand16()`/`rand8()`（整数方向），字节随机用 `rand_bytes(n)`（字节方向）。
- **`Int` vs `Hex`**：求值后等价（都进数值上下文；`0x4242` 与 `16962` 是同一数值的两种拼写）。
- **字节长度**：字段宽度由消费方决定（`be16` 2B、地址 4/16B、MAC 6B），不在值上携带。

### 6.5 类型错误

所有 coercer 报错即类型错误（`be16` 需要整数，得到 字符串），词汇统一为
`describe()` 的形态名（字符串/整数/十六进制/列表/参数引用/值调用/加法表达式）；
字符串误入数值位置的报错附 `int()` 提示。

## 7. 模块系统（import / export）

- **文件名 = 包名**。`import a { a, b }` → 以当前文件目录为根，**递归搜索** `a.pkt`，
  只引入其中导出的 `a`、`b` 两个元件。
- **import 按模块解析**：同名文件在不同目录可共存——每个 import 绑定到**自身模块目录**
  找到的模块实例（图内无全局名字表，`ModuleGraph.module_imports` 存每模块 import 边）；
  入口目录的本地文件（如自己的 headers.pkt）遮蔽库同名模块，结果不依赖 import 顺序。
  库搜索**从后往前**（显式 lib 优先于默认 eng_lib，与 prelude 注入胜者一致）。
- `import a`（不写大括号）= 引入全部导出（含默认导出，默认导出以模块名进入作用域）。
- **双向**：任何文件可 export 任意层元件（包括组合产物），
  如应用层文件导出 http 元件、传输层文件导出「http+udp」组合元件。
- **库模块（eng_lib / lib/）**：`parse_file_with_libs` 把库目录下所有模块载入图，
  其命名导出（`export:`）对全体模块**隐式可见**（无需 `import`，prelude 语义）；
  显式 `import` 仍支持，本地定义/显式 import 优先遮蔽库导出。
- **转出口含 prelude**：`export: tcp`（tcp 未显式 import、仅库 prelude 可见）合法，
  `import b { tcp }` 解析时回退到库模块集合定位最终定义（多级转出口链同样成立）。
- **库目录诊断**（不静默丢弃）：库目录不可读 / 库模块语法错误 / **同一库目录内
  导出名重复**（如两个库文件都 `export: dup`）→ 报错并带文件与 span；
  跨库目录同名导出仍允许（显式 `lib/` 覆盖标准库的既有语义）。
- 语义阶段：
  1. **import 图构建**：以入口文件为根，递归解析所有 import。
  2. **循环依赖检测**：DFS 染色，检测环并报错（带文件与 span）。
  3. **名字解析**：`use` 的名字必须来自本文件定义或已 import，否则报错并带 span 定位。
- **别名**：`import a { x as ax }`——括号列表每项 `IDENT (as IDENT)?`，`ax` 以别名进入
  作用域（解析目标仍是 `x`），两个模块导出同名时可用别名消解冲突；`as` 不是保留字，
  可作普通元件名。无别名的名字与本地定义冲突即报错。
- **默认导出与同名命名元件**：模块同时有默认流水线和名为模块名的命名元件时，
  `import a`（无大括号）无法无歧义引入——报明确诊断（提示 `import a { a }`
  显式引入命名元件或改名），不再抛含糊的「名字冲突」。

## 8. IR 设计（Rust 类型草图）

```rust
// 一个文件求值后的产物：多个包
pub struct BuildResult {
    pub packets: Vec<PacketSpec>,
}

// 结构化包描述：内 → 外 扁平层列表（use 元件展开后拼入）
pub struct PacketSpec {
    pub layers: Vec<Layer>,
}

pub enum Layer {
    Ethernet(EthernetFields),
    Arp(ArpFields),
    Ipv4(Ipv4Fields),
    Ipv6(Ipv6Fields),
    Icmp(IcmpFields),
    Tcp(TcpFields),
    Udp(UdpFields),
    Http(HttpFields),
    Dns(DnsFields),
    Raw(RawData),
}

// 字段用 Option 表示「自动」；宿主序列化时填随机值/checksum/length
pub struct TcpFields {
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub seq: Option<u32>,
    pub ack: Option<u32>,
    pub flags: Option<TcpFlags>,
    pub window: Option<u16>,
    pub options: Vec<TcpOption>,
    pub auto_checksum: bool,
}
```

## 9. 求值流程与序列化边界

```
文本 .pkt → chumsky 解析 → AST
          → import 图 + 循环检测 + 名字解析
          → IR（BuildResult，字段 Option = 自动）
          → [宿主] 序列化：填 checksum / length / 随机值 → 字节 → 发送
```

- 求值阶段把每个流水线：`use` 元件各自展开为包，再逐层包裹（内 → 外）。
- checksum / length / 随机值**不进 IR**，留 `None` 由宿主序列化阶段填。
- IR 纯净、可复用、可跨进程传递（适合 yak 引擎 gRPC 通道）。

### 9.1 层序咨询性检查（`stack.rs`）

`stack_warnings(&PacketSpec) -> Vec<StackWarning>` 走层栈相邻对（`layers[i]` 为内层、
`layers[i+1]` 为外层），报告违反**规范承载关系**的组合，只提示不阻断（不影响序列化/
发送/退出码）。规范承载关系与序列化器的自动字段推断表一致：

- eth 可承载 arp/ipv4/ipv6（及 raw 载荷）；eth 直挂 tcp/udp/http/dns/icmp → `MissingNetwork`；
- ipv4/ipv6 可承载 icmp/tcp/udp（及 raw）；直挂 http/dns → `UninferrableProto`
  （序列化静默兜底 proto=0 / next_header=59）；
- tcp/udp 可承载 http/dns/raw 与整栈封装（隧道）；tcp/udp 互叠 → `TransportInTransport`；
- icmp/arp 只应承载 raw → `PayloadOnly`；http/dns 只应承载 raw → `ReversedOrder`；
- 裸协议（`#[proto]` 无 kind，构造产 Raw 层并带 `RawData.proto` 名）查注册表其
  `#[rule]` 声明的载体层集合（`ctx_cond_layers` 提取，纯 `bytes(...)` 掩码无载体层
  不校验）——外层不在集合内 → `WrongCarrier`（如 `quic_initial |> tcp`：QUIC 声明
  载体 `udp(dport=443)`）；协议未注册（用户文件自建裸协议）→ 静默，与 dissect
  分派同源同限（放 lib 目录即被注册）；
- raw 作为内层任意合法（`raw |> eth` 手工帧等）；网络层/传输层承载另一套完整栈的
  隧道（`ipv4 |> udp`、`eth |> udp`、`ipv4 |> ipv4`）不警告。

宿主把 `StackWarningKind` 映射到 i18n 键渲染为橙色 `note:` 行（`--eng` 逐包展示与
`--pkt` 发送前共用 `eng::print_stack_warnings`）。

## 10. 解析器架构（chumsky）

```
lexer  （轻量）  关键字 export/import/use、IDENT、|>、-、字符串/数字/hex
parser           组合子 → AST（use 表达式、链、变体、def、export/import 块）
semantic         模块解析、循环检测、名字解析 → IR
```

- `|>` 链用 `separated_by` / 递归组合子实现；
- 续行：流水线内允许换行（续行以 `|>` 开头）；括号/方括号内容忍换行（多行调用与列表）；
- 每个 token/span 携带文件位置，供 import 报错与名字解析报错。

## 11. 集成边界（嵌入 yak 引擎 / Yakit）

- DSL crate 只负责：解析 + 语义分析 → 产出 `BuildResult`（纯数据结构，可 serde）。
- 引擎侧：把 IR 序列化为 protobuf/JSON 传过 gRPC，或在引擎内直接消费 IR 调底层
  序列化（对标 `pcapx` 的字节产出）。
- 预留接口：
  - `parse_file(path) -> Result<Module, Diagnostic>`（含 import 解析）
  - `resolve(module) -> Result<BuildResult, Diagnostic>`
  - 序列化器 trait：`fn serialize(&self, spec: &PacketSpec) -> Vec<u8>`（引擎实现）

## 12. 路线图

1. [x] Rust crate 骨架（`packet-dsl`）：AST + chumsky 解析器（单文件、无 import）
2. [x] 语义分析：import 图、循环检测、名字解析
3. [x] IR 定义 + 求值（use 展开、逐层包裹）
4. [x] 内置原语注册表（hex/raw + `layer` 层标注；层头函数与 `*_bytes` 包装迁移至 eng_lib）
5. [x] 序列化器（默认实现：TCP/UDP/IP checksum、length、随机值）
6. [x] 测试：golden 用例（ARP 请求、DNS over UDP、HTTP over TCP、VNC 原始载荷）
7. [ ] yak 引擎集成边界（IR serde + 序列化 trait）

## 12.5 自表示协议（proto，`#[proto] func` 唯一语法）

> 详见 `docs/design-proto-self-describing.md`（路线 A 完整草案）。proto 关键字语法已
> 移除：声明式协议一律写 `#[proto] func name(params) -> bytes { concat(...) }`
> （**proto = 值函数 + 字段标注**，`-> bytes` 必填），解析期降糖为字段表
> （`FuncStmt.schema`，`parser.rs::desugar_proto_funcs`）。body 的
> `layer("kind", concat(...))` 形态已移除（层身份一律用 `#[proto(kind=...)]` 注解）。
> 字段即调用参数，层位置调用按声明顺序编码字节、包成 IR 层——与命令式 `func` 构建
> **逐字节一致**（测试 `tests/proto_func.rs` 以 eth/arp/icmp/ipv4/ipv6 与命令式
> `*_bytes(concat(...))` 对照）。

```pkt
#[proto(kind="eth")]
func eth(dst_mac="ff:ff:ff:ff:ff:ff", src_mac="00:00:00:00:00:00", ethertype=0x0800) -> bytes {
    concat(mac(dst_mac), mac(src_mac), be16(ethertype))
}
#[proto(kind="arp")]
func arp(htype=1, ptype=0x0800, hlen=6, plen=4, op=request(), sha="00:00:00:00:00:00", spa="0.0.0.0", tha="00:00:00:00:00:00", tpa="0.0.0.0") -> bytes {
    concat(
        be16(htype), be16(ptype), u8(hlen), u8(plen), be16(op),  # 常量字段：构造写常量，解析照样从线上读
        mac(sha), ip4(spa), mac(tha), ip4(tpa)
    )
}
```

- **字段类型（可逆原语）**：`u8`/`be16`/`be32`/`be64`/`le16`/`le32`/`le64`/
  `Vint`（变长整数，方案数据化：`#[meta(codec="le128"|"prefix"|"table", ...)]`，
  原 varint/qvarint 字段关键字糖已移除）/`mac`/`ip4`/`ip6`/`dns_name`/`line`
  /`bytes`/`rest`——`bytes`/`rest` 是**声明性 meta 类型**（无编码函数，
  `bytes(宽度)`/`rest(子proto)` 调用形态已移除）：宽度经 `#[meta(bytes=...)]`、
  消费语义经 `#[meta(rest)]` / `#[meta(rest="子proto")]`（末尾递归解析：剩余字节
  按子 proto 的字段声明继续解码，构造侧 = 原样编码或列表逐项，解析侧 = 递归字段表，
  见 M4 ②；重复到失败的哨兵 list 已并入 `#[meta(rest="子proto")]`）。
- **字段即参数**：位置参数按字段序、命名参数按名（命名覆盖位置）；未传 → `= 默认值`
  （在字段环境求值，可引用前序字段）；既未传也无默认 → 报错（`len` 计算字段除外）。
- **`bytes` 字段（`#[meta(bytes=宽度)]`）**：宽度表达式引用前序字段；构造侧校验实参长度 == 宽度。
- **`len` 计算字段**：`len="auto"` = 后续字段编码字节数、`len="目标"` = 目标字段字节数
  （原 @auto/@len 统一为 len 目标），用字段自身类型编码（如
  `#[meta(len="auto", codec="prefix", ...)] length`）；反向填充（后填先算，前面的可依赖后面的宽度）。
- **`src`/`dst` 字段**（ip4/ip6 类型）：兼作 ipv4/ipv6 层的伪头部地址元数据
  （内层 TCP/UDP 校验和正确性，与 headers.pkt 的 layer src/dst 一致）。
- **注解**：`#[proto(kind="eth")]`（kind 为 IR 层闭集 eth/arp/ipv4/ipv6/icmp/tcp/udp/
  http/dns，省略 = Raw 层）/ `#[rule(udp(dport=443))]`（上下文分派，见 M2）/
  `#[rule(bytes(0xc0))]`（首字节掩码）/ `#[rule(and(...))]`（AND 分组）/
  `#[rule(or(...))]`（选一，如多端口）——多个 `#[rule]` 注解与 and(...) 等价：
  全部子条件 AND（and/or 树内所有上下文原子须同一层）；掩码只允许 AND 组合；
  `not` 不支持。
  注解可全缺——**裸 proto 合法**：构造产 Raw 层、可作 `rest(子proto)` 的解析目标
  （如 `quic_crypto` 帧，只有字段表、不落 IR 层）；proto 可导出（eng_lib prelude）。
- **`#[meta(len="auto")]` 注意**：线格式里的校验和/长度字段须声明为 `len="auto"`
  （`#[meta(len="auto")] be16(checksum)`），由序列化器 raw 分支重算——与命令式
  `be16(0)` 占位一致（len 计算字段不接受实参）。注解参数统一 `key=value`
  语法（proto/rule/meta 同构，见 GRAMMAR.md §3 attr）。
- **M2 解析侧**：同一份字段声明反向读取字节（`src/proto.rs`）——`parse_proto` 按
  声明顺序解码（`bytes` 宽度（`#[meta(bytes=...)]`）引用前序字段、`len` 计算字段在线格式上正常读、`rest`
  消费到末尾、规则掩码先验首字节），产出通用字段表 `ProtoHit`；
  `#[rule(udp(dport=443))]` 分派注册表（`set_proto_registry`，OnceLock）接入
  `dissect`——`try_app_layer`（tcp/udp 端口）/ `parse_ipv4`（proto）/ `parse_ipv6`
  （next_header）/ `parse_eth`（ethertype）各层查表，命中即解析、失败回退 raw；
  `DissectReport.proto` 承载命中，`engine --pcap/--hex` 展示。
- **M3 实证**：`eng_lib/quic.pkt` 的 `quic_initial` 迁为 proto
  （`#[rule(udp(dport=443))]` + `#[rule(bytes(0xc0))]` + `len="目标"` 长度前缀 + `len="auto"`
  Length）——构造字节与旧 func 完全一致（golden 测试），捕获的 QUIC 包可被
  `engine --pcap` 反解成字段（第一个"eng_lib 可造即可解析"的协议）；
  proto 可导出（eng_lib prelude 依赖）。
- **M4 层头全量 proto 化 + 语义回填**：`eng_lib/headers.pkt` 的 **6 层头迁为 proto**
  （eth/arp/ipv4/ipv6/icmp/udp，`#[layer(...)]` 注解），tcp/http/dns 保持 func
  （tcp 选项布局、dns/http 可变结构不适配字段表）；构造字节与旧 func 逐字节一致
  （`tests/proto_func.rs` 对比测试）。`typed_layer` 按字段名把值回填 IR 语义字段：
  src/dst（含 `src_host`/`dst_host` 域名标注，`dst=dns(example.com->ip)` 展示）、
  sport/dport、type/code/id/seq、ttl/proto/flags、src_mac/dst_mac/ethertype 等——
  既有消费者（payload 发送、ICMP `--wait` 匹配、`patch_zero_src`/`derive_target`、
  sniffer 字段校验）在迁移后继续工作；头字节仍走 `raw` 分支（自动 checksum/length）。
- **② 递归解析（rest 子 proto + 常量判别）**：`rest(子proto)` 末尾递归——剩余字节按
  子 proto 解码成嵌套 `ProtoHit.subs`（如 `quic_initial.data: rest(quic_crypto)`）；
  子 proto 用**常量默认值字段**作线格式判别（`frame_type: u8 = 0x06`）——解析侧校验
  线上值与常量一致，不一致即停止该子序列（QUIC PADDING 帧 `frame_type=0x00` 据此
  截断，不会错吃后续帧）；`quic_crypto` 即裸 proto（无 layer/rule）范例。
  `engine --pcap` 展示嵌套：`proto: quic_initial → proto: quic_crypto`。
- **字段表达（`#[meta]` 标注，见 GRAMMAR.md §3 proto_arg）**：
  - concat 参数 = 字段：`u8(tos)`（类型化调用 + 标识符）→ 字段名 = 标识符，签名参数
    同名 → 默认值 = 参数引用（否则必填）；`be32(0x00000001)`（字面量）→ 匿名常量
    字段 `f{i}`；`#[meta(name("first"))] u8(bor(0xc0, pnl))` → 显式字段名 + 默认表达式；
  - `#[meta]` 逐字段标注（**一个注解可多个键值对**）：`#[meta(len="auto")]` /
    `#[meta(name="first", len="dcid", bytes="dcid_len")]`——项：`name`（字段名）/
    `len`（计算长度目标：`"auto"` = 后续全部 / 字段名 = 目标字段，原 @auto/@len 统一）/
    `bytes`（宽度，字符串按值表达式子解析，如 `bytes="band(first, 3) + 1"`）/ `rest`（可带子 proto）；
  - **字面量宽度自动推导**：`#[meta(name="first4")] hex("60000000")` = 固定 4 字节
    （值长度即宽度）——内置类型化调用（u8/be16/mac/ip4/ip6/dns_name/line；变长整数 =
    vint codec）宽度自带，无需 `bytes` 标注；`bytes` 宽度机制只留给变长
    场合（引用前序字段 / 计算表达式，如 `#[meta(bytes="dcid_len")] dcid`）；
  - body 必须扁平（禁止嵌套 concat / hex 模板——不可逆片段报错）；
  - `#[proto(kind="eth")]` 合并层类型：kind = IR 层类型（eth/arp/...，语义阶段校验闭集），
    裸 `#[proto]` = Raw 层（如 quic_initial / quic_crypto）；位置形 `#[proto("eth")]` 是
    已移除的旧形式（迁移报错）——`#[proto(kind="eth")]` 即原 `#[proto]` + `#[layer("eth")]` 合并；
  - body 的 `layer("kind", ...)` 形态已移除——层身份一律用 `#[proto(kind=...)]` 注解。

## 13. 示例

### 12.1 应用层文件 `a.pkt`

```
# 包名 = a
export:
- a
- b
- c

a = http(method="GET", path="/")
b = http(method="POST", path="/login", body="{}")
c = http(method="PUT", path="/api/items")
```

### 12.2 传输层文件 `b.pkt`

```
# 包名 = b；import 从当前目录递归找 a.pkt
import a { a, b }

tcp_full = use(a, b) |> tcp(dport=80)
udp_full = use(a, b) |> udp(dport=80)

export:
- tcp_full
- udp_full
```

求值产物 = 4 个 `PacketSpec`（a、b × tcp/udp，原 `||>` 展开改为两条流水线）：

```
[http, tcp(dport=80)]   [http, tcp(dport=80)]   # a、b 各自
[http, udp(dport=80)]   [http, udp(dport=80)]   # a、b 各自
```

### 12.3 命名组合元件 `c.pkt`

```
# 包名 = c；组合元件可再被导出
full = use(a) |> tcp(dport=443) |> ipv4(src="1.1.1.1", dst="2.2.2.2") |> eth()

export:
- full
```

### 12.4 从链路层起步（ARP）

```
# arp.pkt —— 直接构造链路层包，无上层载荷
req = arp(op="request", spa="192.168.1.1", tpa="192.168.1.2")
full = use(req) |> eth(dst_mac="ff:ff:ff:ff:ff:ff")

export:
- full
```
