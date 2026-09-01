# packet-dsl

声明式网络包构建 DSL（`.pkt`）：解析 + 语义分析 → 结构化 IR，由宿主序列化/发送。

- **独立 crate**，不依赖 yak 引擎 / Yakit；解析器 [chumsky](https://github.com/zesterer/chumsky)。
- **DSL 本身不发包**：产物是纯数据结构（`BuildResult`，可 serde），跨进程传递安全。
- 设计文档：[`DESIGN.md`](DESIGN.md)。

## 快速开始

```rust
use packet_dsl::{parse_file, resolve, DefaultSerializer, Serializer};

let module = parse_file("probe.pkt")?;            // 解析 + import 图 + 名字解析
let built = resolve(&module)?;                    // 求值：变体笛卡尔积展开
for pkt in &built.packets {
    let bytes = DefaultSerializer::new().serialize(pkt)?;  // 填 checksum/随机值 → 字节
    // 交给宿主发送……
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## DSL 速览

```pkt
# 应用层元件（文件即模块，包名 = 文件名）
export:
- a
- b
a = http(method="GET", path="/")
b = http(method="POST", path="/login", body="{}")

# 传输层：a、b × tcp/udp → 4 个包（多协议用两条流水线 + 具名导出）
import a { a, b }
tcp_full = use(a, b) |> tcp(dport=80)
udp_full = use(a, b) |> udp(dport=80)
export:
- tcp_full
- udp_full

# 完整协议栈（可命名再导出）
full = use(a) |> tcp(dport=443) |> ipv4(src="1.1.1.1", dst="2.2.2.2") |> eth()
export:
- full

# 链路层起步（ARP）
req = arp(op="request", spa="192.168.1.1", tpa="192.168.1.2")
use(req) |> eth(dst_mac="ff:ff:ff:ff:ff:ff")
```

## 核心概念

| 概念 | 说明 |
| --- | --- |
| `use(a, b)` | 引入元件（本文件定义或 import），每个元件独立成包 |
| `|>` | 正常包裹一层（内 → 外嵌套） |
| 多包 | 多载荷用 `use(a, b)`；同载荷多协议用多条流水线 + `export:` 具名导出 |
| 元件 / 包组 | 命名流水线展开出多个包；`use(包组)` 时逐包包裹 |
| 默认导出 | 顶层匿名流水线；`import b`（不带大括号）引入默认导出 + 全部命名导出 |
| import 别名 | `import a { x as ax }`——`ax` 以别名进入作用域（解析目标仍是 `x`），
  两个模块导出同名时用别名消解冲突 |

## 内置函数

引擎内置只保留字节原语：`hex("...")` / `raw(bytes=...)` 与唯一的层标注原语
`layer(kind, bytes[, src, dst])`（字节 + 层类型字面量 → 该层，序列化时自动补
length/checksum）。标准库 [eng_lib/bytes.pkt](../eng_lib/bytes.pkt) 为每种层提供
具名包装 `eth_bytes`/`ipv4_bytes`/`tcp_bytes`/...（`func eth_bytes(bytes) { layer("eth", bytes) }`）。

层头协议（`eth` / `arp` / `ipv4` / `ipv6` / `icmp` / `tcp` / `udp` / `http` / `dns`）
由标准库 [eng_lib/headers.pkt](../eng_lib/headers.pkt) 以 `#[proto]` 自表示声明
（proto = 值函数 + 字段标注：字段表双端驱动——构造按声明编码、反解按声明读字节；
层身份经 `#[proto(kind=...)]`、应用层分派经 `#[rule(...)]`），
默认库自动加载、导出隐式可见，无需 import 直接调用。

随机值用构建期字节原语：整数方向 `sport=rand16()`（随机端口）、`id=rand16()` 等；
字节方向 `rand_bytes(n)`（随机 MAC/payload/nonce，`rand_mac()` 即 `rand_bytes(6)`）；
确定性填充用 `pad(n)`（n 零字节，与 rand_bytes 对称）；
`"random"` 关键字与 Field::Auto/Random 已随内置层函数移除。
**域名解析**：`dns("host")` 值原语（v4 优先，`dns(host, 6)` v6 优先；IP 字面量短路）
与地址字段（src/dst/spa/tpa...、layer src/dst）的域名回退（如 `dst=params("dst",
"www.baidu.com")`），经宿主注入的 `set_dns_resolver` 解析；值位置的 `ip4`/`ip6`/`mac`
值函数（tpl 模板实现，见下）不解析域名——需显式 `dns()` 包装（`ip4(dns("host"))`）。
**字符串模板 `tpl("模板", 输入)`**：通用「文本 → 字节」解析（取代旧 ip4/ip6/mac/
dns_name 值原语的字面量解析）：`%c` 通配 1 字节；`%d1/%d2/%d4` 十进制、`%x1/%x2/%x4`
十六进制（宽度缺省 1，大端）；`%L` DNS 名字序列（动态宽度：点分标签 → 长度前缀 +
尾 0，`dns_name("example.com")` ≡ `tpl("%L", "example.com")`）；`{n}` 重复、
`{n:sep}` 带分隔符（`{n:}` 缺省 `:`，冒号分隔时输入 `::` = 零填充压缩，ip6 用
`%x2{8:}`）、`{n:[chars]}` 分隔符字符类（mac 用 `%x{6:[-.:]}`）；`%%` 转义；锚定
全匹配，字节列表等宽直通（含 `%L` 的模板不接受字节列表）。ip4/ip6/mac/dns_name
值函数即其特例：`ip4(s)` ≡ `tpl("%d{4:.}", s)`。
**位运算 `bor`/`band`/`bxor`/`bnot`/`shl`/`shr`**：整数（Int/Hex）或同宽字节列表
（元素级）位运算——协议标志位常量（`syn()`/`df()`/`request()`…，eng_lib/bytes.pkt）
组合用：`tcp(flags=bor(syn(), ack()))`（取代旧引擎原语 `tcpflags`/`ip4flags`/`arpop`）。
**算法原语 `count`/`cksum`/`md5`/`sha1`/`sha256`**（引擎原语，输入字节列表或字符串）：
列表长度 / 2B 反码校验和（RFC 1071，与自动校验和一致）/ 16·20·32B 摘要——DNS
qdcount 用 `count(questions)`，`cksum(hex("..."))` 一步；`sum`（整数求和）与
`reduce`（字节折叠）已按「无消费者不下沉」移除。逐项拼接由 **proto 字段表的重复区**
承担：`#[meta(list="计数", item="子proto")]`（按计数重复）与 `#[meta(rest="子proto")]`
（到失败/末尾；与 `bytes=窗口` 同设 = 窗口内重复）——http headers / dns questions 即此。
**eng_lib 库值函数**（非引擎原语，导出隐式可见）：`len`/`line`（`bytes.pkt`）、
`varint`/`qvarint`（`vint.pkt`）。lambda / map / filter / 多态折叠 /
比较逻辑（`==`/`&&`/`!`…）已移除：算法由原语提供，语言保持最小、求值保证终止。
值函数返回类型 `-> bytes` / `-> int`（`-> bool` 已移除）；`+` 是唯一运算符。
`hex("...")` 也可在参数值位置使用（hex 字符串 → 字节列表值），如
`eth_frame(payload=hex("deadbeef"))`、`ipv4(bytes=hex("4500..."))`。
**层 bytes= 直喂**：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns 均可 `bytes=hex("...")`
指定整层头字节（绕过语义字段与自动 checksum/length，载荷仍可语义组合）。
全部字段表见 [`DESIGN.md`](DESIGN.md) §5。

## 值类型与转换

DSL 是**字节本位**设计："类型"是值 → 字节编码边界的转换规则，不是值自带的属性。
完整权威定义（含歧义点与既定规则）见 [`DESIGN.md`](DESIGN.md) §6，速查：

| 类型 | 写法/产生 | 到字节编码 |
| --- | --- | --- |
| 数字 u8/u16/u32 | `0x4242`（十六进制字面量）、`16962`（十进制）、`len`/`count`/`sum`（引擎原语）、`params("port", "53")` / `params("id", "0x4242")` / `params("port", be16(0x1235))`（按形状解析，默认值可为值表达式） | `u8` 1B / `be16` 2B / `be32` 4B 大端；`le16`/`le32` 小端（`le16(0x1234)` = `[0x34,0x12]`，字节输入反转 `le16([0x01,0x02])` = `[0x02,0x01]`） |
| 字符串 | `"text"`、`params("k", "默认")`（恒为字符串） | UTF-8（`raw("text")`，值位置） |
| 字节 | `hex("0x4242")` / `hex("4242")`（可选 `0x` 前缀）、`[0x42, 0x42]`、`concat(...)`、`pad(n)`（n 零字节）、`rand_bytes(n)`（n 随机字节）、`varint(n)`（protobuf base-128）/`qvarint(n)`（QUIC 2 位前缀）、`cksum(...)`/`md5(...)`/`sha1(...)`/`sha256(...)` | 原样 |
| 地址 | `ip4("1.2.3.4")` / `ip6("::1")` / `mac("aa:bb:cc:dd:ee:ff")`（eng_lib 值函数，tpl 实现；域名需 `ip4(dns("host"))`）/ 地址字段（可域名） | 4B / 16B / 6B 网络序 |
| flags | `bor(syn(), ack())` / `df()` / `request()`（eng_lib 位常量值函数 + 位运算原语；数字直写也可） | 位图 1-2B |
| 校验和/摘要 | `cksum(data)` / `md5(data)` / `sha1(data)` / `sha256(data)`（引擎原语；输入字节列表或字符串） | 2B 反码校验和 / 16B / 20B / 32B 摘要 |

- **字符串字面量不隐式转数值**：`be16("0x4242")` 报错——写 `be16(0x4242)` 或
  `be16(hex("0x4242"))`。**params 例外**：按形状解析（`0x` 前缀 = 十六进制数值、
  纯数字 = 十进制数值、其余 = 字符串），`be16(params("port","53"))` 直接可用。
- `hex()` 的字符串须为偶数长度纯十六进制（可带 `0x` 前缀），否则报错。
- `raw("text")` ≡ Python `b"text"`：字符串在字节上下文按 UTF-8 编码。
- **同宽字节直通**：`u8`/`be16`/`be32` 接受恰好同宽的字节（`be16(hex("1234"))` =
  `be16(0x1234)` = `[0x12, 0x34]`，宽度不符才报错）。

- 字节不能当"不同宽"的数字（`be16([0x12])` 宽度不符报错）；字符串仍不隐式转数值。

### 字节原语关系表（raw / hex / u8 / be16 / be32 / []）

字节的最终形态是「字节列表」（`[0x12, 0x34]` 这种 `[]` 字面量）；下面六个写法都是
字节的构造/消费入口（`raw` 是**双位置**原语：层 = Raw 载荷层，值 = UTF-8 字节）：

| 原语 | 位置 | 输入 | 输出 | 等价关系 |
| --- | --- | --- | --- | --- |
| `[]` 字面量 | 值 | — | 字节列表 | 一切字节原语的共同产物形态 |
| `raw("abc")` | **层 / 值** | 字符串（UTF-8）/ 字节列表 | Raw 载荷层 / 字节列表 | `raw("abc")` = `[0x61, 0x62, 0x63]` ≡ Python `b"abc"` |
| `hex("1234")` | 值 / 层 | hex 文本（可选 `0x` 前缀） | 字节列表 / Raw 层 | `hex("1234")` = `[0x12, 0x34]` |
| `u8(x)` | 值 | 数值 0..255 或 1 字节 | 1 字节 | `u8(0x61)` = `u8([0x61])` = `[0x61]` |
| `be16(x)` | 值 | 数值 0..65535 或 2 字节 | 2 字节大端 | `be16(0x1234)` = `be16(hex("1234"))` = `[0x12, 0x34]` |
| `be32(x)` | 值 | 数值 0..2³²-1 或 4 字节 | 4 字节大端 | 同上，宽度 4 |

**互转规则（宽度即类型）**：字节数相同即可直接互转——
`be16(hex("1234"))` = `be16([0x12, 0x34])` = `u8(raw("a"))`（宽度不符才报错）；
`le16`/`le32` 小端编码
（`le16(0x1234)` = `[0x34, 0x12]`）、字节输入反转（`le16([0x01, 0x02])` = `[0x02, 0x01]`）；
字符串不隐式转数值（`be16("0x4242")` 报错）；`raw` 是双位置原语（层 = 载荷层，值 = UTF-8 字节）。

> 组合函数（旧内置 `net4`/`net6`）已迁移为 **pkglang 用户函数模块**
> [eng_lib/net.pkt](../eng_lib/net.pkt)：`import net { net4, net6 }` 后
> `net4(dst="1.1.1.1")` 一次生成 `[ipv4, eth]` 两层（默认 src=0.0.0.0、TTL 64、
> 广播 dst_mac；库导出隐式可见，也可不 import 直接调用）。

> **QUIC 构建**：[eng_lib/quic.pkt](../eng_lib/quic.pkt)（`quic_initial`/`quic_short`/
> `quic_crypto`，RFC 9000 长/短头 + CRYPTO 帧，UDP 封装）——长度/token 字段用
> 引擎原语 `qvarint`（QUIC 2 位前缀变长整数），`pad` 作 PADDING 帧；示例见
> `examples/quic_initial/`（文件夹内含同名 `.pktl` 与其 `.pkt`）。注：构造的是保护前的裸结构（AEAD/头部保护需
> initial secrets，RFC 9001 §5.2，不在 DSL 范围）。

## 库搜索（eng_lib 如何被找到）

标准库目录的查找分两层，宿主（prping）与解析器用同一套合并逻辑：

- **默认 eng_lib（编译期烘焙）**：`default_libs()` 返回
  `CARGO_MANIFEST_DIR/../eng_lib`（`CARGO_MANIFEST_DIR` 是编译 packet-dsl 时注入的
  环境变量 = 本 crate 所在目录），运行时 `is_dir()` 校验——路径不存在（如二进制
  拷到别的机器）就返回空列表，不再报错。
- **显式 libs（运行时追加）**：prping 侧 `resolve_libs` = 默认「当前目录 `lib/`」
  （存在时）+ `--lib PATH`（可多次）；这些路径排在默认 eng_lib 之后。
- **合并顺序**：`effective_libs` = 默认 eng_lib 在前 + 显式 libs 追加，
  与 `parse_file_with_libs` 内部合并一致；`--eng` 输出头部的 `libs: ...` 行
  就是这一列表的展示（canonicalize 后的绝对路径）。
- **import 解析顺序**：入口文件所在目录（直接 + 递归）优先，随后**从后往前**
  搜索库目录——显式 lib（`./lib`、`--lib`）优先于默认 eng_lib；同名文件在不同
  目录可共存，每个 import 按自身模块目录绑定到对应模块实例（本地文件遮蔽库）。
- **发布分发**：`just publish` 把 eng_lib 复制为 `target/release/lib/`
  （与二进制同目录）；发布机上 `default_libs()` 返回空，由运行时
  `./lib` + `--lib` 顶替，行为一致。

## 用户函数（func）

把组合逻辑写成可复用、可 import 的模块函数：

```
func net4(dst, src="0.0.0.0", ttl=64, id=0) {
    ipv4(src=src, dst=dst, ttl=ttl, id=id) |> eth()
}
use(p) |> net4(dst="1.1.1.1")        # 一条调用给出 ipv4+eth 两层
```

- 语法：`func name(p1, p2=默认, ...) { pipeline }`；函数体可用 `use`，也可裸层。
- 参数全部可选：无默认值 = 「未设」（层参数位置省略 → 自动值）；有默认值未传时用默认。
- **库导出隐式可见**：`parse_file_with_libs` 传入的库目录（如发布 `lib/`）下所有模块的
  命名导出自动进入作用域，脚本无需 `import` 直接调用；显式 import 仍支持，本地定义优先。
- 函数体无 `use` 时以空包种子逐层包裹（层片段语义），可直接出现在 `|>` 里；
  函数体内可调用其他函数；函数名与 def 共用作用域，可 export/import。
- **doc 注释**：紧贴 `func` 上方的连续 `#` 注释行视为该函数的说明（空行隔开则不算）。
  行格式：普通行为摘要；`# @param 名: 说明` 逐参数说明；`# @auto: 说明` 描述序列化
  自动行为。`--eng --ls` 按内置原语同构展示（签名 + `"""..."""` 摘要文档字符串 + 逐参数
  + auto），LSP 悬停同样展示。
- 详情与设计取舍见 [`DESIGN.md`](DESIGN.md) §5.2。

## sniffer（回包校验 / 监听规则）

`--pkt --wait` 时按声明匹配应答（替代默认 DNS/ICMP 硬编码匹配）；
`--listen`（或配方 `wait:` 无值）时同一声明即**监听规则**（匹配收到的数据报并打印详情）：

```
sniffer:
  - match icmp(type=0, id=id, seq=seq)   # 回包必须是 echo reply，id/seq 与发包一致
  - and(match udp(dport=53), not(match dns(flags=0x8180)))  # and/or/not 组合
```

- `sniffer:` + `- 谓词` 列表（与 `export:` 同风格；**顶层列表 = 隐式 OR**）；谓词：
  - `match 层(条件, ...)`：反解后必须满足全部条件（层内 AND）；
  - `and(...)`/`or(...)`/`not(...)`：组合（支持跨层 AND、取反——与 `#[rule]` 同构）；
  - 层内条件：`字段=值`、`ne(字段, 值)`（不等）、`mask(0xc0)`（层原始字节首字节
    位掩码）、`startswith/endswith/contains("...")`（层原始字节前缀/后缀/子串）。
- `字段=值` 右值有三种：
  - 字面量 = 常量（`type=0`：回包 icmp.type == 0）；
  - 裸 Ident = 引用**发包同层同名字段**（`id=id` = 回包 id 等于发出去的 id；
    **监听模式无发包，构建期报错**）；
  - 值表达式 = **字节级比较**（`id=be16(0x1234)` / `seq=[0x00, 0x01]` / 用户值函数
    `myid()` / `be16(params("id", "0x4242"))`）——与「值函数最终算出的是字节」一致，
    求值为字节后与回包字段字节比较；可在同文件定义 `func ... -> bytes` 复用。
- 字段集 = 反解层实际解析字段（`matchpred::field_names`，与 `--eng` 展示 / 配方
  `extract` 的 `reply.<层>.<字段>` 共用）。
- 匹配成功宿主显示 `✓ reply matched: 字段=值 (rtt)`，超时 `✗ no matching reply`。
- 只携带声明（`Module.sniffer` / AST `SnifferSpec`），匹配由 `matchpred::Matcher`
  实现（`build(spec, module, params, globals, allow_sent)` + `matches(reply, sent)`；
  公开 API `sniffer_match(spec, reply, sent)` 仅内置原语；
  `sniffer_match_with(spec, module, params, reply, sent)` 支持用户值函数与
  `params(...)`）。

## 库结构

| 模块 | 职责 |
| --- | --- |
| `lexer` / `parser` | chumsky 解析（token 流 → AST，带行/列 span） |
| `ast` | AST 定义（`FieldDecl` 字段表 = 构造/反解双端共享的数据载体） |
| `semantic` | import 图、递归搜索、循环检测、名字解析（`parse_file` / `parse_str`） |
| `eval` | 求值（`resolve`）：use 展开、变体笛卡尔积、组件循环检测 |
| `registry` | 内置原语文档 + proto 注册表（dissect 分派）+ 参数解析 |
| `ir` | 结构化 IR（`BuildResult` / `PacketSpec` / `Layer`，serde） |
| `serialize` | 默认序列化器：字节产出（checksum / length / 随机值，seed 可注入） |
| `proto` | proto 解析侧：同一字段表反向读字节 + `#[rule]` 判别 + 全局注册表 |
| `dissect` | 载荷逐层反解调度（`dissect(bytes)` → `DissectReport`） |
| `codec` | vint 方案双向编解码（le128 / prefix / table） |
| `tpl` | 字符串模板（`ip4`/`ip6`/`mac`/`dns_name` 值函数的通用实现） |
| `matchpred` | sniffer 匹配器（回包校验 / 监听规则） |
| `stack` | 层栈咨询性检查（只警告不阻断） |
| `diag` | 统一诊断类型（解析 / 语义 / 求值共用） |

## 测试

```sh
cargo test -p packet-dsl        # 解析器边界 / 语义 / 求值 / golden 字节 / 反解 / sniffer
```

Golden 用例覆盖：ARP 请求、DNS over UDP、HTTP over TCP、VNC 原始载荷；
期望字节由独立 Python 实现手工计算，并复核 IPv4/TCP/UDP checksum。
