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

层头函数（`eth` / `arp` / `ipv4` / `ipv6` / `icmp` / `tcp` / `udp` / `http` / `dns`）
由标准库 [eng_lib/headers.pkt](../eng_lib/headers.pkt) 用 `hex`/`raw` + 字节原语定义，
默认库自动加载、导出隐式可见，无需 import 直接调用。

随机值用构建期字节原语：`sport=rand16()`（随机端口）、`id=rand16()` 等；
`"random"` 关键字与 Field::Auto/Random 已随内置层函数移除。
**域名解析**：`dns("host")` 值原语（v4 优先）与 `ip4`/`ip6`/地址字段的域名回退
（如 `dst=params("dst", "www.baidu.com")`），经宿主注入的 `set_dns_resolver` 解析。
`hex("...")` 也可在参数值位置使用（hex 字符串 → 字节列表值），如
`eth_frame(payload=hex("deadbeef"))`、`ipv4(bytes=hex("4500..."))`。
**层 bytes= 直喂**：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns 均可 `bytes=hex("...")`
指定整层头字节（绕过语义字段与自动 checksum/length，载荷仍可语义组合）。
全部字段表见 [`DESIGN.md`](DESIGN.md) §5。

> 组合函数（旧内置 `net4`/`net6`）已迁移为 **pkglang 用户函数模块**
> [eng_lib/net.pkt](../eng_lib/net.pkt)：`import net { net4, net6 }` 后
> `net4(dst="1.1.1.1")` 一次生成 `[ipv4, eth]` 两层（默认 src=0.0.0.0、TTL 64、
> 广播 dst_mac；库导出隐式可见，也可不 import 直接调用）。

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

## sniffer（回包校验）

`--pkg --wait` 时按声明匹配应答（替代默认 DNS/ICMP 硬编码匹配）：

```
sniffer:
  - match icmp(type=0, id=id, seq=seq)   # 回包必须是 echo reply，id/seq 与发包一致
```

- `sniffer:` + `- match 层(字段=值, ...)` 列表（与 `export:` 同风格）：回包反解后
  必须满足某子句全部等式（多子句 = 任一命中）；右值字面量 = 常量，裸 Ident = 引用
  **发包同层同名字段**（`id=id` = 回包 id 等于发出去的 id）。
- 匹配成功宿主显示 `✓ reply matched: 字段=值 (rtt)`，超时 `✗ no matching reply`。
- 只携带声明（`Module.sniffer` / AST `SnifferSpec`），匹配由宿主实现
  （prping 的 `pkg.rs::SnifferMatcher`，公开 API `sniffer_match(spec, reply, sent)`）。

## 库结构

| 模块 | 职责 |
| --- | --- |
| `lexer` / `parser` | chumsky 解析（token 流 → AST，带行/列 span） |
| `semantic` | import 图、递归搜索、循环检测、名字解析（`parse_file` / `parse_str`） |
| `eval` | 求值（`resolve`）：use 展开、变体笛卡尔积、组件循环检测 |
| `registry` | 内置层函数注册表 + 参数解析 |
| `ir` | 结构化 IR（`BuildResult` / `PacketSpec` / `Layer`，serde） |
| `serialize` | 默认序列化器：字节产出（checksum / length / 随机值，seed 可注入） |

## 测试

```sh
cargo test -p packet-dsl        # 67 个测试：解析器边界 / 语义 / 求值 / golden 字节
```

Golden 用例覆盖：ARP 请求、DNS over UDP、HTTP over TCP、VNC 原始载荷；
期望字节由独立 Python 实现手工计算，并复核 IPv4/TCP/UDP checksum。
