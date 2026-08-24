# pkglang 自表示协议（#[proto] 声明式 schema）设计草案

> 状态：草案（路线 A 设计文档；部分章节已落地，语法随实现收敛——正文早期
> 章节保留历史写法：`@auto` 现为 `#[meta(len="auto")]`、`@len(目标)` 现为
> `#[meta(len="目标")]`（统一为 len 目标）、哨兵 list 现为 `#[meta(rest="子proto")]`、
> body 的 `layer("kind", ...)` 形态已移除（层身份用 `#[proto(kind=...)]`）、
> 字段位置无 varint/qvarint 关键字（vint codec 数据化，见 §4.5 定稿））。
> 目标：让 pkt 层函数**自表示**——一份协议定义同时用于构造、解析、转码结构化。
> 触发点：eng_lib 已能构造 QUIC（`quic.pkt`），但捕获的 QUIC 只能反解到 `udp + raw`
> （dissect 硬编码 9 层，`Layer` 枚举无 Quic）。用户直觉：pkt 本身是字节构建的规格，
> 加 `#[proto]`/`#[layer]` 标注即可自表示、可解析——本草案验证并落实这个直觉。

## 1. 目标与边界

### 1.1 目标

> **凡是 eng_lib / 用户脚本里「用声明式字段描述的协议」，捕获到的字节都能反解成
> 同样的语义字段**（构造、解析、A2 结构化转码共用同一份定义）。

### 1.2 边界（信息论边界，必须明说）

pkt 的表达力 = `hex()`/`raw()`/`rand_bytes()` 可拼出**任意字节**。"pkt 能表达的都
可解析"在严格意义上等于"任意字节可解析"，不可能。本设计只承诺：

- ✅ 声明式字段描述的协议 → 可解析成结构；
- ❌ `hex`/`raw`/`rand_bytes` 直喂的部分、变宽 `tpl`（`%L`）、加密/压缩载荷 →
  保持 `raw`（与现有设计一致：这些本来就该是 raw，字节保真但不结构化）。

## 2. 核心机制：注解是开关，字段描述才是实质

`#[proto]` 只解决两件事：

1. **标记**：这个 func 是"自表示协议"，参与解析注册；
2. **携带 bind 元数据**：告诉 dissect 在什么条件下路由到它。

解析器真正需要的是**可逆的字段描述**。现在的层函数体是命令式字节拼接，解析器读不出
字段布局——这是核心缺口。以 `quic_initial` 为例：

```pkt
# 现在（命令式构造，仅可构造）：
func quic_initial(dcid, scid, version=0x00000001, pnl=0, pn=u8(0), token="", payload="") -> bytes {
    concat(
        u8(bor(0xc0, pnl)),
        be32(version),
        u8(len(dcid)), dcid,
        u8(len(scid)), scid,
        qvarint(len(token)), token,
        qvarint(len(pn) + len(payload)),
        pn,
        payload
    )
}
```

从这段 `concat` 里，解析器**无法可靠反向**得到字段表：

- 宽度函数交织（`be32`/`u8`/`qvarint` 混在 concat 里），没有"字段名 → 偏移/宽度"表；
- `u8(len(dcid)), dcid` 是"长度前缀 + 载荷"联动，构造时手写，解析时需要把它识别成
  一个**字段对**（先读 1 字节长度，再读这么长的字节）——concat 里看不出这种结构；
- `qvarint(len(pn) + len(payload))` 是**反向依赖**（Length 取决于后面的字段），解析时
  需要知道"这个字段是自动计算值，不是独立可读字段"；
- `pn` 的宽度依赖首字节的 `pnl` 位——**字段宽度依赖前字段的位**。

所以：**注释/标注解决不了解析，必须把命令式拼接换成声明式字段描述**（Kaitai Struct /
scapy `Field` 列表同款思路），构造与解析由同一份声明生成。

## 3. 语法草案

### 3.1 `#[proto] func`（最终语法，取代早期字段块草案）

> **实现修正**：本节早先的 `proto name { 字段 }` 字段块语法与 `switch`/`list`
> 机制（§3.2）是设计期草案；落地时简化为一律 `#[proto] func name(params) -> bytes {
> concat(...) }` + 逐字段 `#[meta]` 标注（见 §9），字段即调用参数，`switch`/`list`
> 不引入（`rest(子proto)` 递归 + 常量判别覆盖帧序列场景）。下面保留早期字段块
> 作为语义示意。

```pkt
# QUIC Initial 长头（RFC 9000 §17.2.2）——自表示协议
# bind: 上层分派条件（UDP dport 443 且首字节高位特征）
#[proto(
    name = "quic_initial",
    bind = udp(dport = 443),
    feature = 0xc0,           # 可选：首字节特征位（长头 0xc0）
)]
proto quic_initial {
    first: u8 = bor(0xc0, pnl)   # 构造：bor(0xc0, pnl)；解析：读 1 字节
    version: be32
    dcid_len: u8
    dcid: bytes(dcid_len)        # 长度联动：宽度 = 前字段值
    scid_len: u8
    scid: bytes(scid_len)
    token_len: qvarint
    token: bytes(token_len)
    length: qvarint @auto        # 自动字段：构造 = pn+payload 长度，解析读出但不参与布局
    pn: bytes((first & 0x03) + 1)  # 宽度依赖前字段位（受限于 1..=4，声明期校验）
    payload: rest                # 消费剩余字节
}
```

要点：

- **字段即规格**：每个字段 = 名字 + 编码原语（可逆）+ 宽度/联动。构造侧顺序编码追加；
  解析侧按偏移顺序读取、绑定同名变量。**同一份声明双向使用**。
- **可逆编码原语**（构造/解析对称）：`u8` / `be16` / `be32` / `be64` / `le16` / `le32` /
  `le64` / `varint` / `qvarint` / `bytes(n)` / `rest` / `mac` / `ip4` / `ip6` / `bits` /
  `dns_name` / `line`。这些是**新原语**，与现有值原语并存（现有 `be16(x)` 是纯编码器，
  声明式字段是"具名 + 可逆"的字段操作）。`dns_name` = DNS 名字（标签序列 + 0 终止；
  解析侧压缩指针**追跳还原**为点分名字，有界防循环）；`line` = 文本行（到 `\r\n`；
  空行 = 解析失败——list 哨兵终止判定用）。
- **宽度联动**：`bytes(字段名)`、`bytes(表达式)`——宽度引用前序字段；声明期做
  终止性/范围校验（宽度必须可静态求值或引用已声明字段）。
- **自动字段 `@auto`**：checksum/length 类。构造时引擎计算（沿用现有自动补
  checksum/length 逻辑）；解析时读出存字段、**重序列化时重算**（语义 = 现有 raw
  分支的"重算"行为，保证 roundtrip）。
- **`rest`**：消费到输入末尾——payload/帧区。
- **位依赖**：`(first & 0x03)` 这类**只读位表达式**允许出现在宽度位置（声明期静态
  求值 + 范围校验），但不引入通用比较/Bool——语言最小化哲学保留。

### 3.2 列表与分派（有界迭代、无通用分支）

变长列表与按内容分叉用**声明式**表达，避免把比较/循环塞回语言。实现定版用
`#[proto] func` + `#[meta]`（见 §9 与 GRAMMAR.md §3），本文的 `list()`/`switch`
字段块语法是设计草案，等价能力已按最终语法落地：

```pkt
# list 重复字段：`#[meta(list="计数", item="子proto")]`——元素 = 子 proto，
# 构造侧值 = 列表逐项调子 proto 编码；解析侧按 count 表达式循环子 proto。
#[proto]
func dns_question(name="", qtype=1, qclass=1) {
    concat(dns_name(name), be16(qtype), be16(qclass))
}
#[proto(kind="dns")]
#[rule(udp(dport=53))]
#[rule(tcp(dport=53))]
func dns(id=0, flags=0x0100, questions=[]) {
    concat(
        be16(id), be16(flags),
        #[meta(name="qdcount")] be16(count(questions)),
        be16(0), be16(0), be16(0),
        #[meta(list="qdcount", item="dns_question")] questions
    )
}

# TCP：data_offset @auto + expr 变换（`len` = 后续字节数）联动 options 宽度
#[proto(kind="tcp")]
func tcp(sport=rand16(), dport=0, seq=0, ack=0, flags=syn(), window=65535, urg=0, options="") {
    concat(
        be16(sport), be16(dport), be32(seq), be32(ack),
        #[meta(name="data_offset", auto, expr="shl(div(len + 13, 4), 4)")] u8(bor(0x50, 0)),
        u8(flags), be16(window),
        #[meta(auto)] be16(checksum),
        #[meta(name="urg")] be16(urg),
        #[meta(bytes="sub(mul(shr(data_offset, 4), 4), 20)")] options
    )
}
```

- **`list(count, item)`**：有界迭代，count 引用前序字段（终止性由声明保证）；
  元素 = 子 proto（复用 `rest(子proto)` 的递归解析，按计数而非解析到失败）；
- **`#[meta(auto/len, expr=...)]`**：@auto/@len 的表达式变换（expr 里 `len` =
  基准字节数）——TCP data_offset 的 `5 + options/4 << 4` 联动；宽度表达式
  `bytes=...` 支持 `+`/`mul`/`div`/`sub`/`shl`/`shr`（`(data_offset>>4)*4-20`）；
- **`dns_name` 字段类型**：DNS 名字（标签序列 + 0 终止；压缩指针**追跳还原**——
  解析侧在完整报文上用绝对偏移读标签，指针跳转到目标偏移继续读（有界 ≤32 防循环），
  值 = 点分名字字符串；消费 = 原始位置标签 + 终止，追跳段只参与值还原）；
- **`line` 文本行字段**：到 `\r\n`（构造 = 值 + `\r\n`；解析侧**空行 → 失败**）；
- **list 哨兵终止**：`#[meta(list, item="子proto")]`（无 count）循环解析子 proto 直到
  失败（空行/不匹配即停）——HTTP headers 以空行结束即用此表达；
- **`bits` 位字段**（`#[meta(bits=N)] u8(值)`，1..=8 位）：同一字节内按声明顺序
  高位→低位填充（大端位序），连续位字段凑满 8 位成一字节——IPv4 首字节
  version(4)+ihl(4) 即用此拆分（`#[meta(bits=4)] u8(4)` 字面量 = 常量校验判别位、
  `u8(ihl)` 参数引用 = 可变字段，options 宽度 `bytes="sub(mul(ihl, 4), 20)"` 按 ihl
  回算）；位组总位宽必须 %8==0（语义阶段校验，普通字段从字节边界开始）；
- **`switch`**：按内容分叉仍未落地（无声明式用例）；**长度联动 + `@auto` +
  `list` + `rest` + `expr` 变换**覆盖绝大多数协议头；特殊布局（DNS 压缩指针、
  QUIC 头部保护、IP 选项交错）标记 `@opaque` 整段直喂（见 §6），不追求声明式
  表达一切。

### 3.3 `#[layer]` 与现有 func 的关系

- `#[layer(kind)]` 是 `#[proto]` 的特例：表示"这个 proto 对应 IR 的一个层类型"，
  进入现有 `Layer` 枚举/序列化/转码 A2 的语义路径（如 `#[layer("icmp")]`）；
- 不迁移的现有 func（headers.pkt 命令式）继续可用，只是只构造不解析——**增量兼容**；
- bind 冲突（端口 443 既是 QUIC 也是 TLS）→ 按声明顺序尝试 + 失败回退 raw
  （复用现有 dissect 的 try/notes 哲学）。

## 4. 双向语义（构造/解析共用同一份声明）

| 阶段 | 引擎做什么 |
|---|---|
| 构造 | 按字段声明顺序编码：每个字段 = 编码原语(值) → 追加字节；`@auto` 字段由引擎计算（checksum/length，可带 `expr` 变换如 data_offset）；`bytes(联动)` 先求宽度再编码；`list` 字段值 = 列表逐项调子 proto 编码 |
| 解析 | 按同一字段声明顺序 take：每个字段 = 读 N 字节 → 按原语解码 → 绑定名字；`rest` 消费剩余（层头解析遇 rest 即停，载荷留调用方）；`list` 按 count 循环子 proto（哨兵 = 循环到失败）；`bits` 按位取（字节内高位在前）；`@auto` 读出存字段、重序列化时重算；`dns_name` 标签读取 + **压缩指针追跳还原**（完整报文上绝对偏移）；`line` 读到 `\r\n`（空行失败） |
| roundtrip | 解析产物（字段值）+ 同一声明重序列化 == 原字节（`@auto` 重算、opaque 原样）——**一致性由 schema 本身保证**，不再依赖两边手写代码对齐（P0 修的就是这类漂移） |

实现上就是**一份声明两个解释器**（构造解释器 + 解析解释器），都在 packet-dsl 求值器
侧（沿用 chumsky 解析 + AST + 现有 `layer`/序列化器的结构），不引入新依赖。

## 4.5 vint codec 模型（变长整数数据化，定稿）

### 4.5.1 动机

`varint`/`qvarint` 是**值依赖宽度的变长编码**（编码长度由值大小决定）——DSL 无比较/
分支/循环，无法下沉为库函数，只能收口在引擎。但把每个编码硬编码成一个字段类型
（`FieldType::Varint`/`Qvarint`）意味着：新增一个变长编码（Bitcoin/CBOR/BER…）就要
改引擎。**形态 B**：统一为**一个字段类型 + 数据化方案**——`FieldType::Vint` 携带
`VintCodec` 方案，构造/解析共用（可逆），新增编码 = 声明数据，不动引擎。

变长整数线格式只有三种结构模型，现实协议几乎都是它们的实例：

| 模型 | 机制 | 实例 |
|---|---|---|
| 续延位（LEB128） | 每字节低 7 位值 + 最高位续延，值越大字节越多 | protobuf varint、Thrift、MIDI VLQ |
| 前缀宽度表 | 首字节高 `prefix_bits` 位 = 宽度索引，查表得字节数 | QUIC qvarint |
| 内联 + 哨兵表 | 值 ≤ 阈值直接 1 字节内联；否则首字节 = 哨兵，查表得后续字节数 | Bitcoin varint（LE）、CBOR/msgpack 长度（BE）、DER Length |

### 4.5.2 方案定义（引擎侧，`VintCodec`）

```rust
pub enum VintCodec {
    /// 续延位（LEB128）：范围 0..=2^63-1（≤9B）；负数报错。
    /// 与值原语 `varint()` 同编码。
    Le128,
    /// 前缀宽度表：首字节高 prefix_bits 位 = 宽度索引（大端序），查 widths 表
    /// 得字段字节数；值 = 余下位（大端）。范围 0..=2^(8·max(widths)−prefix_bits)−1。
    /// 与值原语 `qvarint()` 同编码（Prefix{2, [1,2,4,8]}）。
    Prefix { prefix_bits: u8, widths: Vec<u8> },
    /// 内联 + 哨兵表：值 ≤ inline_max 直接 1 字节内联；否则首字节 = 哨兵
    /// （> inline_max），查 table（哨兵 → 后续字节数）读余下字节，值 = 大端或小端。
    /// 范围 0..=min(i64::MAX, 2^(8·max(width))−1)。
    Table { inline_max: u8, table: Vec<(u8, u8)>, endian: VintEndian },
}
pub enum VintEndian { Be, Le }   // Table 值字节端序；Prefix 按规范恒大端
```

### 4.5.3 DSL 语法（声明数据，`#[meta]` 键值对；**无字段关键字糖**）

```
#[meta(codec="le128")] n
#[meta(codec="prefix", prefix_bits=2, widths=[1,2,4,8])] len
#[meta(codec="table", inline_max=0xFC,
        sentinels=[0xFD,0xFE,0xFF], widths=[2,4,8], endian="le")] n
```

- 键：`codec`（le128/prefix/table，必填——Vint 类型唯一来源）、`prefix_bits`（1..=8）、
  `widths`（整数列表，各 1..=8）、`inline_max`（0..=255）、`sentinels`（整数列表）、
  `endian`（"be" 缺省 / "le"）；
- **字段位置无 `varint`/`qvarint` 关键字**（已移除的糖）——所有 vint 声明都是
  数据；值位置的 `varint()`/`qvarint()` 由 **eng_lib/vint.pkt 库 proto 声明**提供
  （proto 双位置：`#[proto] func varint(n=0) { #[meta(codec="le128")] n }` 声明后，
  concat 里 `varint(x)` 值位置调用返回字节；引擎无变长整数内置原语）；字段位置写
  `varint(x)` 报"不是字段类型"并提示 codec meta；
- `len` 计算字段（`len="auto"` = 后续全部 / `len="目标"` = 目标字段字节数，原
  @auto/@len 统一为 len 目标）的 vint 字段：值 = 引擎算出的字节数，用自身方案编码
  （QUIC `#[meta(len="auto", codec="prefix", prefix_bits=2, widths=[1,2,4,8])] length`、
  `#[meta(len="data", codec="prefix", prefix_bits=2, widths=[1,2,4,8])] length` 即此）。

### 4.5.4 语义校验（semantic.rs）

- Vint 字段必须有方案（裸标识符 + codec meta 必须给；`vint` 不是关键字）；
- le128：不接受 prefix_bits/widths/inline_max/sentinels/endian 附加参数；
- prefix：prefix_bits ∈ 1..=8；`widths.len() == 2^prefix_bits`；各宽度 ∈ 1..=8；严格递增
  （构造按列表序取第一个装得下的 = 最小宽度，确定性）；
- table：非空；sentinels 互异；每个哨兵 > inline_max（否则解码歧义：首字节既可能
  是内联值又可能是哨兵）；widths 各 ∈ 1..=8 且严格递增；sentinels/widths 等长
  （构造期 zip）；endian ∈ be/le；
- bits 位字段仍只配 u8（Vint 不能是位字段，既有检查覆盖）。

### 4.5.5 构造 / 解析（对称）

| 阶段 | le128 | prefix | table |
|---|---|---|---|
| 构造 | n≥0；`while n≥128 { 低7位\|0x80 }` 尾字节 | 按 widths 序找第一个 `n < 2^(8w−pb)`：`full = (idx << (8w−pb)) \| n` 大端 w 字节 | n ≤ inline_max → `[n]`；否则按表找第一个装得下的：哨兵 + n 大端/小端 w 字节 |
| 解析 | 续延位循环（移位 ≥64 溢出拒绝） | 首字节 `>> (8−pb)` = 索引 → 宽度 → 读 w 字节 → 掩掉前缀位 | 首字节 ≤ inline_max → 内联值；否则查表（未命中 → 失败回退 raw）→ 读 w 字节 |
| 常量校验 | 字面量默认值 = 判别位（与定宽字段同规则，`frame_type: u8 = 0x06` 模式） | 同左 | 同左 |

范围检查构造侧做（le128 ≤ i64::MAX；prefix ≤ 2^(8·max(w)−pb)−1；table ≤
min(i64::MAX, 2^(8·max(w))−1)——w=8 时 2^64 溢出，钳到 i64::MAX）。

**实现收敛（M4 后）**：构造（`eval.rs::encode_field_type`）与解析
（`proto.rs::decode_field`）共用 `codec.rs` 同一份编解码（`VintCodec::encode`/
`decode`），不再各写一份——历史上 LEB128 解码游标不推进的 bug 即双实现漂移所致；
新增第 4 个结构模型只需改 codec.rs 一处。

### 4.5.6 边界（诚实清单）

- **不做**：DER Length 的 `0x80+n` 公式哨兵表（需表字面量/公式语法，用例稀少）——
  显式哨兵表可表达 Bitcoin/CBOR/msgpack；DER 长格式待有真实用例再扩展；
- **不做**：非 2 幂基数的续延位（base-100 等）——le128 覆盖全部现实续延位编码；
- 端序：Prefix 恒大端（规范如此）；Table 可配（Bitcoin LE / CBOR BE）；
- 值位置的 `varint()`/`qvarint()` 已下沉为 eng_lib/vint.pkt 库 proto（builtin_docs
  与引擎分派已移除）——与字段方案共用 `codec.rs` 同一编解码实现（`VintCodec::encode`/`decode`），
  新增任意变长编码 = 声明一个 proto 即可在值位置使用（如 `func bitcoin_len(n=0) {
  #[meta(codec="table", ...)] n }`）。

## 5. rule 分派（dissect 路由注册）

`#[rule(...)]` 收集进**协议注册表**（进程内，编译期从 eng_lib/用户 lib 扫描），
dissect 的分派链从硬编码 match 改为：注册表按 rule 匹配优先，失败回退硬编码
parse_*（引擎魔法兜底，逐步退役）：

```
udp(dport=443) ──► quic_initial / quic_short（按首字节特征位二次分派）
tcp(dport=53) / udp(dport=53) ──► dns（headers.pkt 已 proto 化；多 rule 注解跨层——
                                    同层条件 AND 合并、跨层条件独立任一命中）
ipv4(proto=47) ──► gre（若有人声明）
```

- rule 条件支持：`udp/tcp(dport=..)`、`ipv4(proto=..)`、`ipv6(next_header=..)`、
  `eth(ethertype=..)`、`bytes(首字节特征)`；**多 `#[rule]` 注解可跨层**（如 DNS 的
  udp 53 + tcp 53——同层 AND、跨层任一命中即候选，语义阶段按层分组）；
- **层头也按 proto 注册表反解**：`find_by_kind`（`#[proto(kind="eth")]` 等）+ 
  `parse_header`（遇 rest 即停），产出语义 IR 层（`proto_hit_to_layer` 回填）+ 
  ProtoHit 附加；失败回退硬编码；
- 不冲突时完全增量：注册表为空 = 行为与现状一致。

## 6. 边界与限制（诚实清单）

1. **opaque 字段**：`@opaque` 标记（hex/raw/rand/tpl 变宽/加密/压缩）整段直喂，
   字节保真不结构化——QUIC 的 AEAD 保护部分、TCP 选项混合体都属于此列（保护后/
   压缩后的载荷语义上无法解，信息论边界）。DNS 压缩指针已**追跳还原**（不再是 opaque）
2. **歧义**：同端口多协议 → 声明顺序 + 特征位 + 失败回退 raw。
3. **终止性**：`list` 计数有界、`switch` 分支有限、宽度联动必须静态/已声明字段——
   声明期校验拒绝未绑定宽度（保持"求值保证终止"的既有承诺）。
4. **性能**：声明式解析每字段一次边界检查，与手写 dissect 同级；`rest`/`list` 不回溯。
5. **自动字段**：`@auto` 只重算 checksum/length 类；非此类的"派生值"（如 DNS
   nscount 计数）要求显式声明，否则进 remaining——与现状字段粒度一致。

## 7. 与现有体系的集成路径

```
proto 声明 ──► packet-dsl 解析器（chumsky，新增 proto 语法）──► ProtoDef（AST）
                  │
                  ├─► 构造解释器 ──► 现有 IR Layer / 序列化器（raw 分支不冲突）
                  ├─► 解析解释器 ──► 产出与 Layer 同构的 Fields（或通用 FieldMap）
                  │                       └─► dissect 分派（内置 9 层优先 + bind 注册表）
                  └─► 转码 A2：proto 化层直接生成语义 DSL 字段（替代 *_bytes hex 兜底）
```

- **里程碑**：
  - M1（引擎）：可逆字段原语 + 声明式构造解释器（不动解析侧，纯增量）；
  - M2（解析侧）：`#[proto]` 语法 + 解析解释器 + bind 注册表 + dissect 路由；
  - M3（试点）：`quic_initial`/`quic_short`/`quic_crypto` 迁为 proto 声明，
    roundtrip + 转码 A2 结构化测试（首个"eng_lib 可造即可解析"的协议）；
  - M4（已落地）：headers.pkt 9 层全部 proto 化（eth/arp/ipv4/ipv6/icmp/udp +
    tcp/dns + http），Rust 手写 parse_*（含 parse_dns/parse_http）全部删除——
    应用层/层头按注册表唯一反解（`proto_hit_to_layer` 回填 IR 层）；
    tcp 用 `@auto + expr` 联动 data_offset、dns 用四区 `list` + `dns_name`（压缩指针
    追跳还原，响应也走注册表）、ipv4 用 `bits` 位字段拆分 version/ihl + options
    宽度按 ihl 回算、http 用 `line` 文本行 + list 哨兵终止 + rest body。
- **兼容**：全程增量，命令式 func 不废弃；`#[proto]` 是并行的新路径。
- **门禁**：新增语法需同步 GRAMMAR.md（§4.x 语法可见面）+ DESIGN.md + 原语文档
  同步脚本（proto/bind 原语并入 doc-sync 分派集合）。

## 8. 与既有先例的对比

| | scapy | Kaitai Struct | 本设计 |
|---|---|---|---|
| 协议定义 | Python 类（fields + dissect 手写） | .ksy 声明式 schema | pkt `#[proto]` 声明式 |
| 构造/解析 | 两份代码 | 一份 schema 生成解析器（构造弱） | 一份声明双解释器 |
| 与现有 DSL 关系 | 无关 | 无关 | 同一语言增量（命令式兼容） |
| 解析器生成 | 无（手写） | 代码生成 | 解释器（无代码生成，免构建步骤） |

优势：不引入第二门语言、不引入代码生成步骤（解释器直接消费 AST）、命令式构造保留。
代价：需要新增"可逆字段原语 + 声明式语法"，属中等偏大的语言扩展。

## 9. 最终语法：`#[proto] func` + `#[meta]`（proto 关键字已移除）

实现定版：**proto 关键字语法已删除**，声明式协议唯一写法是 `#[proto] func ... -> bytes`
（proto = 值函数 + 字段标注，`-> bytes` 必填）——解析期
降糖为字段表（`parser.rs::desugar_proto_funcs`），构造/解析/注册表/LSP 全部走既有
proto 机制，零新解析器：

```pkt
#[proto]
#[rule(udp(dport=443))]
#[rule(bytes(0xc0))]
func quic_initial(pnl=0, pn=u8(0), payload="") {
    concat(
        #[meta(name="first")] u8(bor(0xc0, pnl)),
        #[meta(name="version")] be32(0x00000001),
        #[meta(len="dcid")] u8(dcid_len),
        #[meta(bytes="dcid_len")] dcid,
        #[meta(len="auto", codec="prefix", prefix_bits=2, widths=[1,2,4,8])] length,
        #[meta(bytes="band(first, 3) + 1")] pn,
        #[meta(rest="quic_crypto")] payload
    )
}
```

降糖规则（逐字段，见 GRAMMAR.md §3 proto_arg）：

| concat 参数形态 | 降糖为 |
|---|---|
| `u8(tos)`（类型化调用 + 标识符） | `tos: u8`；签名参数同名 → 默认值 = 参数引用，否则必填 |
| `be32(0x00000001)`（字面量） | 匿名常量字段 `f{i}`（默认值 = 字面量，解析侧按常量校验） |
| `dns_name(name)` | `name: dns_name`（DNS 名字；标签序列 + 0 终止，压缩指针直喂） |
| `#[meta(name="first")] u8(bor(0xc0, pnl))` | `first: u8 = bor(0xc0, pnl)`（显式字段名 + 默认表达式） |
| `#[meta(bytes="dcid_len")] dcid` | `dcid: bytes(dcid_len)`（裸标识符，类型来自 meta） |
| `#[meta(bytes=4)] hex("60000000")` | `first4: bytes(4) = hex("60000000")`（固定宽 + 常量默认值，IPv6） |
| `#[meta(auto)] qvarint(length)` | `length: qvarint @auto` |
| `#[meta(auto, expr="shl(div(len, 4) + 5, 4)")] u8(0x50)` | `data_offset: u8 @auto` + expr 变换（`len` = 后续字节数；TCP） |
| `#[meta(bits=4)] u8(4)` | `version: u8 bits=4 = 4`（位字段：字节内 4 位；字面量默认 = 常量校验；IPv4 version+ihl 拆分） |
| `#[meta(len="dcid")] u8(dcid_len)` | `dcid_len: u8 @len(dcid)` |
| `#[meta(rest="quic_crypto")] payload` | `payload: rest(quic_crypto) = payload` |
| `#[meta(list="qdcount", item="dns_question")] questions` | `questions: rest(重复 qdcount 次 dns_question)`（list 字段） |

要点：

- `#[meta]` 键值对（一个注解可多项）：`#[meta(auto)]` / `#[meta(name="xx", bytes=4)]` /
  `#[meta(len="dcid")]` / `#[meta(rest="quic_crypto")]` / `#[meta(auto, expr="...")]` /
  `#[meta(list="计数", item="子proto")]`——字符串参数按值表达式子解析
  （`bytes="band(first, 3) + 1"` 复用 `parse_value_expr`）。**字面量宽度自动推导**
  （`hex("60000000")` = 4 字节，无需 bytes 标注）；`bytes` 宽度机制只留给变长场合
  （引用前序字段 / 计算表达式）；`expr` 变换配 @auto/@len（`len` = 基准字节数，
  支持 `+`/mul/div/sub/shl/shr）；`list` 需 `list`+`item` 两项齐全（重复字段）。
- body 必须**扁平 concat**（或 `layer("kind", concat(...))`，与 `#[proto(kind=...)]`
  等价、冲突报错）：嵌套 concat / hex 模板 / reduce 等不可逆片段在降糖时清晰报错。
- `#[proto(kind="eth")]` 合并层类型：kind = IR 层类型（eth/arp/ipv4/ipv6/icmp/tcp/
  udp/http/dns，语义阶段校验闭集），裸 `#[proto]` = Raw 层（如 quic_initial /
  quic_crypto）。协议族标签已随合并删除。
- 分派规则：`#[rule(udp(dport=443))]`（上下文）/ `#[rule(bytes(0xc0))]`（首字节
  掩码）/ `#[rule(and(udp(dport=443), bytes(0xc0)))]`（AND 分组）/
  `#[rule(or(udp(dport=443), udp(dport=4433)))]`（选一，如多端口）——**同层**
  条件 AND 合并、**跨层**条件独立任一命中（如 DNS 的 `#[rule(udp(dport=53))]` +
  `#[rule(tcp(dport=53))]`）；and/or 树内所有上下文原子须同一层；掩码只允许 AND，
  不能进 or 分支；dissect 命中即尝试解析、失败回退 raw/硬编码。
- 与命令式 func 构建**逐字节等价**（`tests/proto_func.rs` golden：eth/arp/icmp/ipv4/
  ipv6/tcp/dns/quic_initial），解析侧同源（rest(quic_crypto) 嵌套命中、
  list(dns_question) 按计数循环一致）。

取舍（实现时权衡）：关系型布局（@len/@auto/宽度表达式/rest 递归）在 func 形式下
标注密度高、字段表直接表达更短——这是保留 proto 关键字时的样子；删掉后所有协议
统一穿 `#[meta]` 外套，换来单一语法（无第二个声明关键字）。用户偏好函数形态 →
定为唯一语法，字段块草案（§3.1）废弃。
