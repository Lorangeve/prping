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
| 运行环境 | 嵌入 yak 引擎 / Yakit | 通过 IR + 序列化边界与引擎集成 |

## 3. 术语

- **元件（component）**：任意一层或几层的包描述，可命名、可导出、可被 import。
- **最小元件（minimal element）**：层头函数生成的最小合法头部，未填字段走自动值。
- **流水线（pipeline）**：`use(元件...) |> 层(...)` 的包裹链（内 → 外）。
- **包组（packet group）**：命名流水线展开出的多个包（多载荷 `use(a, b)` 时）。

## 4. 语法规范

### 4.1 BNF 草案

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

# 回包校验（--pkg --wait 用；求值期语义，宿主负责匹配；多子句任一命中）
sniffer_stmt  := "sniffer" ":" sniffer_match+
sniffer_match := "-" "match" IDENT "(" sniffer_field_list? ")"
sniffer_field := IDENT "=" value      # 值 = 字面量（常量）或裸 IDENT（发包同层同名字段）
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
| 值 | `concat`/`u8`/`be16`/`be32`/`ip4`/`ip6`/`mac`/`bytes`/`cksum`/`len`/`count`/`rand16`/`rand8`/`dns_name` | 字节构建原语（值位置） |
| 值 | `arpop`/`tcpflags`/`ip4flags` | 标志/操作码文本 → 数值 |
| 层标注 | `layer(kind, bytes, src?, dst?)` | 字节 → 对应层；`kind` 为闭集字面量，`src`/`dst` 仅 `ipv4`/`ipv6`（伪头部校验和） |

> 自动行为（checksum / length / ethertype / 伪头部）留在 Rust 序列化层，见 §7。
> `layer(..., src="random")`（`ipv4`/`ipv6` 包装透传）仍支持 `"random"`；层头函数
> 不暴露该关键字——随机值用 `rand16()` 等构建期原语。

> 组合函数（旧内置 `net4`/`net6`）已迁移为 **pkglang 用户函数模块**
> （`eng_lib/net.pkt`，库导出隐式可见，无需 import 直接使用），见 §5.2。

### 5.2 用户函数（func）

组合逻辑（如 `net4`/`net6` 一次生成 IP+以太网两层）可以写成**具名参数化函数**，
从 Rust 内置下沉为 pkglang 模块：

```
# net.pkt
func net4(dst, src="0.0.0.0", ttl=64, id=0, proto, tos, flags,
          src_mac="00:00:00:00:00:00", dst_mac="ff:ff:ff:ff:ff:ff", ethertype) {
    ipv4(src=src, dst=dst, ttl=ttl, proto=proto, tos=tos, id=id, flags=flags)
        |> eth(src_mac=src_mac, dst_mac=dst_mac, ethertype=ethertype)
}
export:
- net4
```

语法与语义：

- `func name(p1, p2=默认, ...) { pipeline }`；函数体是流水线，`use(...)` 可选。
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

## 6. 模块系统（import / export）

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

## 7. IR 设计（Rust 类型草图）

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

## 8. 求值流程与序列化边界

```
文本 .pkt → chumsky 解析 → AST
          → import 图 + 循环检测 + 名字解析
          → IR（BuildResult，字段 Option = 自动）
          → [宿主] 序列化：填 checksum / length / 随机值 → 字节 → 发送
```

- 求值阶段把每个流水线：`use` 元件各自展开为包，再逐层包裹（内 → 外）。
- checksum / length / 随机值**不进 IR**，留 `None` 由宿主序列化阶段填。
- IR 纯净、可复用、可跨进程传递（适合 yak 引擎 gRPC 通道）。

## 9. 解析器架构（chumsky）

```
lexer  （轻量）  关键字 export/import/use、IDENT、|>、-、字符串/数字/hex
parser           组合子 → AST（use 表达式、链、变体、def、export/import 块）
semantic         模块解析、循环检测、名字解析 → IR
```

- `|>` 链用 `separated_by` / 递归组合子实现；
- 续行：流水线内允许换行（续行以 `|>` 开头）；括号/方括号内容忍换行（多行调用与列表）；
- 每个 token/span 携带文件位置，供 import 报错与名字解析报错。

## 10. 集成边界（嵌入 yak 引擎 / Yakit）

- DSL crate 只负责：解析 + 语义分析 → 产出 `BuildResult`（纯数据结构，可 serde）。
- 引擎侧：把 IR 序列化为 protobuf/JSON 传过 gRPC，或在引擎内直接消费 IR 调底层
  序列化（对标 `pcapx` 的字节产出）。
- 预留接口：
  - `parse_file(path) -> Result<Module, Diagnostic>`（含 import 解析）
  - `resolve(module) -> Result<BuildResult, Diagnostic>`
  - 序列化器 trait：`fn serialize(&self, spec: &PacketSpec) -> Vec<u8>`（引擎实现）

## 11. 路线图

1. [x] Rust crate 骨架（`packet-dsl`）：AST + chumsky 解析器（单文件、无 import）
2. [x] 语义分析：import 图、循环检测、名字解析
3. [x] IR 定义 + 求值（use 展开、逐层包裹）
4. [x] 内置原语注册表（hex/raw + `layer` 层标注；层头函数与 `*_bytes` 包装迁移至 eng_lib）
5. [x] 序列化器（默认实现：TCP/UDP/IP checksum、length、随机值）
6. [x] 测试：golden 用例（ARP 请求、DNS over UDP、HTTP over TCP、VNC 原始载荷）
7. [ ] yak 引擎集成边界（IR serde + 序列化 trait）

## 12. 示例

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
