# pkglang 语法规范（Grammar Reference）

> pkglang = packet-dsl 的 `.pkt` 网络包构建语言。本文档给出**完整语法**：
> 词法（token 层）+ 语句 + 表达式，全部以 EBNF 形式给出，与实现
> [`packet-dsl/src/lexer.rs`](src/lexer.rs) / [`packet-dsl/src/parser.rs`](src/parser.rs)
> 一一对应（实现即权威；本文档如有出入，以实现为准）。
>
> 设计取舍见 [`DESIGN.md`](DESIGN.md)，快速上手见 [`README.md`](README.md)。
> `DESIGN.md` §4.1 的 BNF 草案为早期版本，本文档为现行权威语法（含 `func` /
> 值函数 `-> bytes` / `params()` / 值位置 `hex()` / `+` 数字加法 / import 别名等演进）。

## 1. 概览

- **文件即模块**：一个 `.pkt` 文件 = 一组语句，模块名 = 文件名。
- **语句按换行分隔**；括号/方括号/花括号内与流水线续行允许换行（见 §5）。
- **表达式分三层**：
  - 语句表达式 `expr`：`pipeline`（`use(...) |> ...`）或单层 `call`；
  - 调用 `call`：`名字(参数...)`，参数可命名（`k=v`）可位置（`v`）；
  - 值表达式 `value`：字面量 / 列表 / 特殊调用 / 裸标识符，运算符仅 `+`
    （数字加法）。lambda / 比较（`==`/`!=`/`<`/`<=`/`>`/`>=`）/ 逻辑
    （`&&`/`||`/`!`）已随高阶原语移除（中间形态：算法原语化，语言最小化）。
- **`|>` 管道**：把当前内容作为载荷包一层（内 → 外嵌套）；多载荷用 `use(a, b)`，
  多包用多条流水线 + `export:`（`||>` 分支语法已移除）。

## 2. 词法（Lexical Grammar）

### 2.1 字符级规则

```
input      = shebang? { whitespace | comment | token | newline }
shebang    = "#!" ... EOL            # 仅限文件首行，整行跳过
whitespace = " " | "\t" | "\r"       # 跳过，不产 token
comment    = "#" ... EOL             # 到行尾；换行本身仍产 token
newline    = "\n"                    # 语句分隔 token
```

### 2.2 Token 表

| Token | 词法 | 说明 |
| --- | --- | --- |
| `IDENT` | `[A-Za-z_][A-Za-z0-9_]*` | 关键字（`export`/`import`/`use`/`func`/`sniffer`/`match`/`params`/`hex`/`as`）**不是保留字**——parser 按上下文匹配，`as` 可作普通元件名；`true`/`false` 现在是普通 IDENT（布尔类型已移除） |
| `STRING` | `"..."` | 转义 `\\` `\"` `\n` `\r` `\t`；未知转义保留反斜杠 + 字符原文 |
| `INT` | `[0-9]+` | i64；溢出 = 词法错误 |
| `HEX` | `0x[0-9a-fA-F]+`（`0X` 亦可） | u64；`0x` 后无数字 = 词法错误 |
| `\|>` | 管道运算符 | 单独 `\|` / `\|\|` 不跟 `>` = 词法错误 |
| `\|\|>` | 已移除的分支运算符 | 仍产出 token，解析时给出明确报错（提示改用多条流水线） |
| `->` | 值函数返回标注 | `func f(...) -> bytes { ... }`（`-> int` 亦可；`-> bool` 已移除） |
| `+` | 数字加法 | 仅值表达式内（唯一运算符） |
| `=` | 赋值 / 命名参数 / 参数默认值 | `=>`（lambda）与 `==`（比较）已移除 = 词法错误 |
| `-` | export/sniffer 列表项 | 容忍 `-c` 无空格写法 |
| `(` `)` `{` `}` `[` `]` `,` `:` | 标点 | |

### 2.3 词法注记

- 已移除运算符的清晰报错：`=>`（lambda）/`==`/`!=`/`<`/`<=`/`>`/`>=`/`&&`/`||`/`!`
  在词法层直接报「已移除」错误（提示见消息文本），`true`/`false` 退化为普通 IDENT。
- 字符串中 `\` 后跟非转义字符：保留 `\` 与字符原文（如 `"\q"` → `\q`）。
- 未识别字符（如 `;`、`@`）→ 词法错误「无法识别的字符」。

## 3. 语法（EBNF 全集）

```ebnf
(* 文件 = 语句序列：每条语句前允许任意数量换行（惯例 ≥1 分隔） *)
file           = { nl stmt } ;
nl             = { newline } ;                          (* 零或多个换行（容忍换行处） *)

stmt           = export_stmt | import_stmt | func_stmt | sniffer_stmt
               | def_stmt | pipeline_stmt ;

export_stmt    = "export" ":" nl { "-" ident } ;          (* ≥1 项；项间允许换行（也可无） *)
import_stmt    = "import" ident [ "{" import_item { "," import_item } [ "," ] "}" ] ;
import_item    = ident [ "as" ident ] ;
func_stmt      = "func" ident "(" [ func_param { "," func_param } [ "," ] ] ")"
proto_func_stmt_body
               = "{" proto_concat "}" ;
                    (* `#[proto] func ... -> bytes` 的 body：扁平 `concat(...)`
                       （降糖为 `FuncStmt.schema` 字段表）；body 的 `layer("kind", concat(...))`
                       形态已移除——层身份一律用 `#[proto(kind=...)]` 注解（同一信息
                       两种写法是历史遗留，已收敛）。无 `#[proto]` 注解时按普通 layer
                       函数求值（如 eng_lib 的 `*_bytes`） *)
proto_concat   = "concat" "(" [ proto_arg { "," proto_arg } [ "," ] ] ")" ;
proto_arg      = { meta_attr nl } value ;
                   (* concat 参数 = 字段（类型化调用 / 裸标识符 / 字面量/表达式）：
                      - `u8(tos)` / `be16(id)`：字段名 = 标识符，签名参数同名 → 默认值 =
                        参数引用（否则必填字段）；
                      - `u8(0x45)` / `be32(0x00000001)`：匿名常量字段 `f{i}`（默认值 =
                        字面量/表达式，解析侧按常量校验）；
                      - `dns_name(name)`：DNS 名字字段（DnsName 类型，标签序列 + 0 终止；
                        解析侧**压缩指针追跳还原**——在完整报文上用绝对偏移读标签，
                        指针跳转到目标偏移继续读（有界防循环），值 = 点分名字字符串；
                        消费 = 原始位置标签 + 终止，追跳段只参与值还原）；
                      - `line("...")` / `line(text)`：**文本行字段**（到 `\r\n`，值 =
                        字符串；构造 = 值 + `\r\n`；解析侧**空行（首字节 `\r`）→ 失败**）；
                      - `#[meta(name="first")] u8(bor(0xc0, pnl))`：显式字段名；
                      - `#[meta(bytes="dcid_len")] dcid` / `#[meta(rest="quic_crypto")] payload` /
                        `#[meta(list="qdcount", item="dns_question")] questions`：
                        裸标识符，类型来自 meta；宽度/子 proto 字符串按值表达式子解析；
                        list = **重复字段**（元素子 proto 按 count 表达式循环，如 DNS
                        questions 逐条 qdcount 次；构造值 = 列表，逐项调子 proto 编码）；
                         `#[meta(rest="子proto")]`：**重复解析到失败**（原哨兵 list——循环
                        解析子 proto 直到失败，空行/不匹配即停，如 HTTP headers）；
                      - `#[meta(len="auto", expr="shl(div(len, 4) + 5, 4)")] u8(0x50)`：
                        `len` 的**表达式变换**（expr 里 `len` = 基准值——后续/
                        目标字节数；TCP data_offset 联动；`+`/mul/div/sub/shl/shr 可用）；
                      - `hex("60000000")` 等字面量：宽度自动推导（= 字节数），无需 bytes *)
                       - `#[meta(bits=4)] u8(4)`：**位字段**（整型字段容量内：u8 ≤8 /
                         be16 ≤16 / be32 ≤32 / be64 ≤64 位）——
                         同一位组内按声明顺序从高位到低位填充（大端位序），连续位字段
                         凑满 8 的倍数位即成整字节组（IPv4 version+ihl 各 4 位 = 0x45；
                         IPv6 version+TC+flow = 4+8+20 位跨 4 字节组）；字面量
                         默认值 = 常量校验（判别位），参数引用默认值 = 可变字段；
                       - `#[meta(codec="le128")] n` /
                         `#[meta(codec="prefix", prefix_bits=2, widths=[1,2,4,8])] len` /
                         `#[meta(codec="table", inline_max=0xFC, sentinels=[0xFD,0xFE,0xFF],
                         widths=[2,4,8], endian="le")] n`：**vint 变长整数字段**（Vint 类型，
                         **唯一声明形态**——无 varint/qvarint 字段关键字糖）——
                         le128 = 续延位（protobuf base-128）、prefix = 前缀宽度表
                         （QUIC RFC 9000 §16）、table = 内联+哨兵表（Bitcoin LE / CBOR BE）；
                         构造/解析共用，新增编码 = 声明数据不动引擎；裸标识符类型来自 meta；
                         table 的 `endian` 缺省 "be"；vint 可作 `len` 计算字段
                         （值 = 引擎算出的字节数，用自身方案编码）；模型与参数约束见
                         DESIGN.md §4.5；值位置的 `varint()`/`qvarint()` 由 eng_lib/vint.pkt 库 proto
                         声明提供（proto 双位置，concat 一步拼字节用）——引擎无变长整数
                         内置原语；*)
meta_attr      = "#" "[" "meta" "(" [ meta_item { "," meta_item } [ "," ] ] ")" "]" ;
meta_item      = "rest" | "list" | ident "=" value ;
                   (* 一个注解可带多个键值对（`#[meta(name="xx", bytes=4)]`）；
                      `rest` 为无值 flag（plain rest，消费到末尾）；`name` = 字段名、
                       `len` = 计算长度目标（`"auto"` = 后续全部字段字节数，原 @auto；
                       字段名 = 目标字段字节数，原 @len——两者统一为 len 目标）、
                      `bytes` = 宽度（字符串按值表达式子解析：`bytes="band(first, 3) + 1"`）、
                      `rest` = rest 类型（可带子 proto：`rest="quic_crypto"`；
                       与 `bytes=宽度` 同设 = **窗口内重复**——类型 = Bytes，
                       窗口里循环单发反解子 proto 到耗尽（每次 ≥1 字节），
                       恰好耗尽 → 子命中进 subs，未耗尽/未注册 → 整窗不透明
                       字节降级——TCP options 等 data_offset 界定的中部重复区）、
                      `expr` = len 表达式变换（`expr="shl(div(len, 4) + 5, 4)"`，
                      `len` = 基准值）、`list` = 重复计数表达式 + `item` = 元素子 proto
                      （`#[meta(list="qdcount", item="dns_question")]`，两项须齐全；
                       重复到失败的哨兵形态已并入 `rest="子proto"`）、
                      
                      `bits` = 位字段位宽（整型字段容量内：u8 ≤8 / be16 ≤16 /
                      be32 ≤32 / be64 ≤64；连续位字段须凑满整字节——
                      位组总位宽 %8==0 才可接普通字段/结尾）、
                      `switch` = 判别式分派（`switch="前序字段"`，类型固定 Bytes：
                      解析时读前序字段值按 `cases` 表选子 proto 反解字节窗口，
                      构造侧值 = 字节直喂）+ `cases` = 判别表
                      （`cases=[[1, "rdata_a"], [28, "rdata_aaaa"]]`，值互异；
                      有界窗口 `bytes=宽度` 下未命中/反解失败 → 整窗不透明字节
                      降级，无界窗口 → 整体回退）+
                      `if` = 条件在场守卫（`if="整型表达式"`——`band`/`shr` 组合
                      引用前序字段，非零 = 字段存在：解析消费 0 位、构造不编码、
                      实参可省略；与 bits/len/rest 互斥）、
                       `codec` = vint 方案名（le128/prefix/table，类型 = Vint）+
                       `prefix_bits`（1..=8）+ `widths`（整数列表，各 1..=8）+
                       `inline_max`（0..=255）+ `sentinels`（整数列表）+ `endian`（"be"/"le"）：
                       按模型消费（le128 不带参数；prefix 需 prefix_bits+widths 且
                       widths.len()==2^prefix_bits 严格递增；table 需 inline_max+sentinels+
                       widths，哨兵 > inline_max 且互异、宽度严格递增、两表等长）。
                      字面量值宽度自动推导（`hex("60000000")` → 4 字节）——
                      `#[meta(bytes=...)]` 标注只用于变长宽度（引用前序字段/计算表达式） *)
proto_func_stmt= { proto_attr nl } "func" ident "(" [ func_param { "," func_param } [ "," ] ] ")"
                  "->" "bytes" proto_func_stmt_body ;
                    (* 自表示协议（`#[proto] func ... -> bytes`，唯一声明语法）：
                       **proto = 值函数 + 字段标注**——`-> bytes` 必填（返回类型标注
                       声明值函数本性；旧语法无 `-> bytes` 的 `{ concat }` 已移除，迁移报错）；
                       注解至少含一个 `#[proto]`；body 的 concat 参数按 proto_arg 规则
                       组成字段表（`FuncStmt.schema`）——字段即调用参数，层位置调用按
                       声明顺序编码字节，包成 IR 层；`#[proto(kind="arp")]` 合并层类型
                       （kind = IR 层类型，语义阶段校验闭集；位置形 `#[proto("arp")]` 是
                       已移除的旧形式，迁移报错）；无默认值的字段 = 必填参数，值参数
                       只参与构造；注解可全缺（裸 proto 合法）：构造产 Raw 层、可作
                       rest(子proto) 解析目标 *)
attr           = "#" "[" ident [ "(" [ attr_item { "," attr_item } [ "," ] ] ")" ] "]" ;
attr_item      = ident "=" value | value ;
                    (* 统一注解参数语法：`key=value` 列表（裸 `value` 为 flag/旧位置形式，
                       按注解名解释）——
                       `#[proto(kind="eth")]`（层身份，省略 = Raw 层）/
                       `#[rule(udp(dport=443))]`（上下文分派）/
                       `#[rule(mask(0xc0))]`（首字节掩码）/
                       `#[rule(startswith("HTTP/"))]` / `#[rule(contains("HTTP/", in=start_line))]`（字节模式匹配）/
                       `#[rule(or(ne(qdcount, 0), ne(ancount, 0)))]`（字段值约束 OR）/
                       `#[meta(name="x", bytes=4)]`（字段标注）*)
proto_field    = ident ":" proto_type [ "=" value ] [ "@" "auto" | "@" "len" "(" ident ")" ] ;
                    (* 降糖产物（`#[meta]` 标注翻译而来）：`name: type [= 默认值]
                       [@auto|@len(目标)]`——IR 展示形态（`@auto` = `len="auto"`、
                       `@len(目标)` = `len="目标"`）；默认值/宽度可引用前序字段与值参数；
                       `len` = 后续全部/目标字段字节数，都可用 `expr` 变换
                       （`#[meta(len=..., expr="...")]`） *)
proto_type     = "u8" | "be16" | "be32" | "be64" | "le16" | "le32" | "le64"
                | "mac" | "ip4" | "ip6" | "dns_name" | "line"
                | "bytes" | "rest" ;
                    (* bytes/rest 是**声明性 meta 类型**（无编码函数，`bytes(...)`/
                       `rest(...)` 调用形态已移除）：宽度/消费语义一律经 `#[meta]`
                       标注——`#[meta(bytes=宽度)]`（宽度引用前序字段或字面量；
                       定宽字面量自动推导，如 `hex("60000000")` → 4 字节）、
                       `#[meta(rest)]`（消费到末尾）、`#[meta(rest="子proto")]`
                       （末尾递归：剩余字节按子 proto 解析，构造侧 = 原样编码或
                       列表逐项，如 HTTP headers / QUIC CRYPTO 帧）；子 proto 可
                       是任意 proto（含无 `#[proto(kind=...)]` 的裸 proto：构造时产
                       Raw 层、解析时只作字段表，如 quic_crypto 帧）；rest 是
                       字段表的结构性终结指令（解析侧），bytes 的宽度是声明性
                       约束（引用前序字段的表达式），都不是字节变换函数；
                       dns_name = DNS 名字（标签序列 + 0 终止；压缩指针**追跳还原**
                       为点分名字字符串，有界防循环）；line = 文本行（到 `\r\n`；
                       空行 = 解析失败——哨兵终止判定）；
                       list 重复字段 = rest 类型 + `#[meta(list="计数", item="子proto")]`
                       （按计数循环）或 `#[meta(list, item="子proto")]`（哨兵：循环到失败，
                       HTTP headers）；
                       变长整数 = **vint 类型**，唯一声明形态 `#[meta(codec=...)]`
                       （无 varint/qvarint 字段关键字），见 proto_arg；vint 可作
                       @auto/@len 字段（QUIC `#[meta(auto, codec="prefix", ...)] length`） *)
rule_call      = "and" "(" rule_call { "," rule_call } ")"
               | "or" "(" rule_call { "," rule_call } ")"
               | layer_ident "(" [ rule_kv { "," rule_kv } ] ")"
               | "mask" "(" num ")"
               | "startswith" "(" STRING [ "," match_loc ] ")"
               | "endswith" "(" STRING [ "," match_loc ] ")"
               | "contains" "(" STRING [ "," match_loc ] ")"
               | ( "ne" | "eq" ) "(" ident "," value ")" ;
                    (* `#[rule(...)]` 调用形式——上下文条件 + 匹配函数（隐式 bool，AND 组合）：
                       上下文条件：`#[rule(udp(dport=443))]` 按层分派候选；
                       字节模式匹配：`mask(0xc0)` 首字节位掩码、`startswith`/`endswith`/
                       `contains` 子串匹配（可选 `at=N` 偏移定位 / `in=字段名` 字段字节内容
                       定位，字段名 = `#[meta(name=...)]` 或参数名）；
                       字段值约束：`ne(字段, 值)` / `eq(字段, 值)`（解析后校验，`or(...)` 内
                       合并为 OR 语义）；
                       组合：`and(...)` AND / `or(...)` OR（`or` 内禁止字节模式匹配，
                       允许字段值约束）；`not` 不支持。多个 `#[rule]` 注解与 and(...) 等价。 *)
match_loc      = "at" "=" num | "in" "=" ident ;
rule_kv        = ( "dport" | "sport" | "proto" | "next_header" | "ethertype" ) "=" num ;
sniffer_stmt   = "sniffer" ":" nl { "-" nl sniffer_pred } ;  (* ≥1 项；顶层列表 = 隐式 OR *)
sniffer_pred   = "match" ident "(" [ sniffer_item { "," sniffer_item } [ "," ] ] ")"
               | "and" "(" sniffer_pred { "," sniffer_pred } [ "," ] ")"
               | "or" "(" sniffer_pred { "," sniffer_pred } [ "," ] ")"
               | "not" "(" sniffer_pred ")" ;
sniffer_item   = sniffer_field | "ne" "(" ident "," value ")"
               | "mask" "(" num ")" | "startswith" "(" STRING ")"
               | "endswith" "(" STRING ")" | "contains" "(" STRING ")" ;
sniffer_field  = ident "=" value ;
def_stmt       = ident "=" expr ;
pipeline_stmt  = pipeline ;                                (* 顶层匿名流水线 = 默认导出 *)

expr           = pipeline | call ;
pipeline       = use_part layer* ;
use_part       = "use" "(" ident_list ")" ;               (* 至少 1 个名字 *)
layer          = nl "|>" call ;                           (* 内 → 外包裹一层 *)
call           = ident [ "(" [ arg { "," arg } [ "," ] ] ")" ] ;  (* 无参裸调用 ≡ call() *)
arg            = [ ident "=" ] value ;                    (* 命名参数先于位置参数尝试 *)

value          = add ;                                    (* 唯一运算符：`+` 数字加法 *)
add            = atom { "+" atom } ;                      (* 左结合；比较/逻辑已移除 *)
atom           = STRING | INT | HEX | list
               | params_call | hex_call | value_call | ident ;
list           = "[" [ value { "," value } [ "," ] ] "]" ;
params_call    = "params" "(" STRING [ "," value ] ")" ; (* 运行时参数引用（默认值可为任意值表达式：字符串/数值/be16(...)/字节列表） *)
hex_call       = "hex" "(" STRING ")" ;                   (* 值位置 hex → 字节列表值；可带可选 0x/0X 前缀 *)
value_call     = ident "(" [ value { "," value } [ "," ] ] ")" ;  (* 值调用，仅位置参数 *)
ident_list     = ident { "," ident } [ "," ] ;
ident          = IDENT ;
```

> 说明：
> - `nl` 表示「该处容忍换行」：语句前任意数量（惯例 ≥1 分隔）；`|>` 前、逗号两侧、
>   括号/方括号/花括号内均容忍换行（细则见 §5）。
> - `expr` vs `call`：`expr` 用于 `def_stmt` 右侧（流水线或单调用）；
>   `call` 是流水线中的一层。二者最终都解析为层调用序列，语义等价。
> - `call` 与 `value_call` 的差别：前者参数可命名/位置（`arg`），后者只收位置
>   值列表——值函数（字节原语 / 用户值函数）**没有命名参数**。
> - `sniffer_field` 的右值有三种语义：字面量（常量比较）、裸 `ident`（引用发包
>   同层同名字段；监听模式无发包，构建期报错）、其余 `value`（值表达式——原语/
>   值函数/`params`/字节列表，求值为字节后与回包字段**字节**比较；语法仍是上面的
>   `value`，语义在求值期区分）。
> - **sniffer 谓词组合**（与 `#[rule]` 同构）：`and(...)` 全部子谓词满足（支持跨层
>   AND）、`or(...)` 任一满足、`not(...)` 取反（监听/回包反解后整包判定；`#[rule]`
>   侧不支持 `not`）；层内条件：`ne(字段, 值)` 不等、`mask(0xc0)` 层原始字节首字节
>   位掩码、`startswith/endswith/contains("...")` 层原始字节前缀/后缀/子串
>   （proto 命中时作用于整个报文）。字段集 = 反解层实际解析字段
>   （`matchpred::field_names`，与 `--eng` 展示/配方 `extract` 共用）。
> - **`params(...)` 按形状解析**（取代已移除的 `int()`）：`0x`/`0X` 前缀 = 十六进制数值、
>   纯十进制数字 = 数值、其余 = 字符串——`be16(params("port", "53"))` 直接可用
>   （`--params port=5353`）。**默认值可为任意值表达式**：未注入时求值为默认
>   （`params("port", be16(0x1235))` = `[0x12,0x35]`），字符串默认值仍按形状解析。裸字符串字面量进数字位置（`be16("0x4242")`）仍报错，
>   写 `be16(0x4242)` 或 `be16(hex("0x4242"))`。`hex()` 的字符串须为**偶数长度纯
>   十六进制**（可带可选 `0x` 前缀），否则报错。要字节写 `hex(params("id", "4242"))`
>   或直接用字符串（`raw("abc")` ≡ Python `b"abc"`）。
> - **同宽字节直通**：`u8`/`be16`/`be32`/`le16`/`le32` 接受恰好同宽的字节列表（`be16(hex("1234"))`
>   = `be16(0x1234)`，宽度不符报错；同宽直通是**恒等**——字节进字节出，不产生数值）；
>   小端变体 `le16`/`le32` 对字节输入做反转（`le16([0x01,0x02])` = `[0x02,0x01]`）。
>   字节列表**不**隐式解码回数值（`int(字节)` 解码原语已随 `int()` 移除；构造方向
>   只需值→字节，反向解码需求不存在）。
> - 完整「值类型与转换」表（类型清单、表示、产生原语、转换规则、歧义点）见
>   [`DESIGN.md`](DESIGN.md) §6——本文件只约束语法（`value` 的 EBNF），
>   语义类型由消费方 coercer 按该表解释。

## 4. 表达式语法（重点）

### 4.1 语句表达式 `expr`

`def_stmt` 右侧只能是两种形状：

```
a = http(method="GET")                              # expr = call（单层调用/元件引用）
full = use(a) |> tcp(dport=443) |> ipv4() |> eth()  # expr = pipeline
```

`expr` 内不允许裸值（`x = 42` 不合法——定义右侧必须是包构造表达式）。

### 4.2 调用 `call` 与参数 `arg`

- 调用 = `IDENT (参数列表?)`；**无参裸调用**合法：`tcp` ≡ `tcp()`（语义期解析为函数）。
- 参数两种形态，**命名参数先尝试**（parser 的 `choice` 顺序）：
  - 命名：`IDENT = value`，如 `tcp(dport=80, flags="syn")`；
  - 位置：裸 `value`，如 `layer("eth", bytes)`。
- 参数间逗号分隔，容忍尾逗号与前后换行（多行调用）。
- 命名/位置混用、参数个数与类型由**求值期**按函数签名解析（parser 不校验）。

### 4.3 值表达式 `value`

值表达式是语法树的叶子层，出现在参数值位置、列表元素、`func` 参数默认值、
值函数体（`-> bytes`/`-> int` `{ ... }`）：

```
value = add ;                     # 唯一运算符：`+` 数字加法
add   = atom { "+" atom } ;       # 左结合
atom  = STRING | INT | HEX | list
      | params_call | hex_call | value_call | ident
```

atom 的解析顺序（决定二义性消解）：

| 序 | 形态 | 结果 |
| --- | --- | --- |
| 1 | `STRING` / `INT` / `HEX` | 字面量 |
| 2 | `[ ... ]` | 值列表 |
| 3 | `params("名"[, "默认"])` | 运行时参数引用（`Value::Param`） |
| 4 | `hex("...")` | 字节列表值（值位置特判） |
| 5 | `ident(...)` | 值调用（`Value::Call`；字节原语或用户值函数，仅位置参数） |
| 6 | 裸 `ident` | 函数参数引用（`Value::Ident`，仅函数体内合法） |

`+` 加法：`a + b + c` = `BinOp(Add(a, b), c)`（左结合）；操作数都是 atom 或 `+` 链，
无括号分组语法——列表/调用括号内可再含 `+`（如 `concat(u8(1 + 1))`）。lambda /
比较 / 逻辑运算符已随高阶原语（map/filter）移除；算法（count/len/cksum）由
引擎原语提供。

### 4.4 上下文相关二义性消解

1. **`hex(...)` 双义**：值位置（参数值）→ 字节列表 `Value`；语句位置（裸调用
   `hex("...")`）→ Raw 载荷层。parser 中值位置 `hex_call` 特判在通用 `value_call` 之前。
2. **`params(...)` 特判**：先于通用值调用尝试，避免被当作函数调用；实参必须是字符串。
3. **裸 ident 最后尝试**：`ident_value` 在 `choice` 末尾——`dst=dst` 右侧的 `dst`
   才是参数引用；其它位置裸 ident 作值的合法性由**语义期**校验（必须在函数体内，
   且必须是已声明的参数）。
4. **关键字非保留字**：`export`/`import`/`use`/`func`/`sniffer`/`match`/`as`/`params`/
   `hex` 是按上下文匹配的 IDENT；`as` 可作普通元件名（import 别名的右操作数
   之后不再特殊）。
5. **`-> bytes`/`-> int` 判定函数种类**：`func` 头部括号后出现 `-> 返回类型`
   = 值函数（体是值表达式，返回类型运行时校验）；否则 = 层函数（体是流水线）。
   两种函数体形态由 `choice` 区分。

### 4.5 特殊语法形态

| 形态 | 含义 |
| --- | --- |
| `func f(p1, p2="默认") { ... }` | 层函数：具名参数化流水线（体可用 `use`，也可裸层） |
| `func f(p1) -> bytes { 值表达式 }` | 值函数：返回字节列表（`-> int` 返回整数） |
| `count(列表)` / `cksum(数据)` | 引擎算法原语：列表长度 / 2B 反码校验和（`len(数据)` = 库值函数 `count∘raw`，bytes.pkt） |
| `md5(数据)` / `sha1(数据)` / `sha256(数据)` | 引擎摘要原语：→ 16/20/32 字节（输入字节列表或字符串） |
| `params("name"[, "默认值"])` | 运行时参数注入（`--params k=v`） |
| `import a { x as ax }` | import 别名：`ax` 进作用域，解析目标仍是 `x` |
| `sniffer: - match icmp(type=0, id=id)` | 回包匹配声明（`--pkt --wait` 用） |
| `tpl("模板串", 输入)` | 字符串模板 → 字节（值原语）。模板串是**普通字符串字面量**（非语法层构造），其内部**模板子语法**（`%c`/`%d`/`%x` + 宽度 + `{n:sep}` 重复/`::` 压缩 + 字符类 + `%%` 转义）EBNF 见 §4.7，权威语义定义见 `DESIGN.md` §5.3 |

### 4.6 内置原语清单（语法可见面）

> 与 `DESIGN.md` §5 同源；**改动原语必须同步本节 + `registry.rs` 的
> `builtin_docs()`（`--eng --ls` 与 LSP 悬停/补全的展示源，改动原语必须同步）**。
> 层头函数（eth/arp/ipv4/...）与地址值函数（ip4/ip6/mac）在 eng_lib 库
> （库导出隐式可见），不属引擎原语。校验：`scripts/claude-hooks/primitive-docs-check.sh`
> （Claude Code hook + `just doc-sync-check`）。

| 原语 | 语法形态 | 说明 |
| --- | --- | --- |
| `raw` | 层位置裸调用 / 值位置 `raw("...")` | 层 = Raw 载荷层；值 = UTF-8 字节（≡ Python `b"..."`） |
| `hex` | 层位置裸调用 / 值位置 `hex("...")` | hex 字符串 → 字节（可选 `0x` 前缀，须偶数长度） |
| `layer` | 层位置 `layer(kind, bytes[, src, dst])` | 字节 + 层类型字面量 → 该层（序列化自动补 length/checksum） |
| `concat` | 值调用 | 字节列表拼接 |
| `u8`/`be16`/`be32`/`be64`/`le16`/`le32`/`le64` | 值调用 | 数值/同宽字节 → 1/2/4/8 字节（大端；le 小端低字节在前；8 字节按 i64::MAX 封顶） |
| `tpl` | 值调用 `tpl("模板", 输入)` | 字符串模板 → 字节（模板子语法 EBNF 见 §4.7；字节列表等宽直通） |
| `cksum` | 值调用 | 互联网校验和（RFC 1071 反码）→ 2 字节大端（与自动校验和一致；words16/fold16 中间机制已移除） |
| `md5`/`sha1`/`sha256` | 值调用 | 摘要 → 16/20/32 字节（输入字节列表或字符串 UTF-8） |
| `count` | 值调用 | 列表元素个数 → 整数（DNS qdcount 用 count(questions)） |
| `len` | eng_lib 库值函数（bytes.pkt，隐式可见） | 字节数 → 整数：`func len(x) -> int { count(raw(x)) }`（字符串 UTF-8、字节列表原样）——可组合算法下沉，非引擎原语 |
| `line` | eng_lib 库值函数（bytes.pkt，隐式可见） | 文本行 → 字节：`func line(s="") -> bytes { concat(raw(s), hex("0d0a")) }`（值 + `\r\n`）——proto `line` 字段（§4.2）的构造侧编码双位置；非引擎原语 |
| `rand16`/`rand8` | 值调用 | 构建期随机整数（0..65535 / 0..255）——整数方向随机（端口/ID/seq） |
| `rand_bytes` | 值调用 `rand_bytes(n)` | 构建期随机 n 字节（0..255，n ≤ 65535）——字节方向随机（随机 MAC/payload/nonce；rand_mac 即 rand_bytes(6)） |
| `pad` | 值调用 `pad(n)` | n 个零字节（0..65535）——确定性填充（与 rand_bytes 对称：以太网最小帧 46B 填充、选项对齐、DNS OPT padding） |
| `dns` | 值调用 | 域名 → IP 字符串（`dns(host, 6)` = v6 优先；IP 字面量短路） |
| `bor`/`band`/`bxor`/`bnot`/`shl`/`shr` | 值调用 | 位运算（整数或同宽字节列表元素级；bor 变参左折叠，协议标志位常量见 eng_lib/bytes.pkt） |
| `mul`/`div`/`sub` | 值调用 | 算术（**仅整数**，变参左折叠；除 0 报错）——宽度/`expr` 表达式专用：`bytes="sub(mul(shr(x, 4), 4), 20)"`（TCP options 宽度）、`#[meta(auto, expr="shl(div(len, 4) + 5, 4)")]`（TCP data_offset） |
| `params` | 值位置特判 `params("名"[, 默认])` | 运行时参数注入（`--params k=v`） |
| `global` | 值位置特判 `global("名"[, 默认])` | 配方全局存储读取（`.pktl` `global:` 段 / 步骤 `extract` / `-g k=v`（--global）注入）；与 `params` 对称但值为**类型化**字面量（Int/Hex/Str/字节列表原样返回，不经过字符串形状解析），可直接参与 `+`/`be16`/位运算；未设置时延迟求值默认值，两者都无则报错 |
| `reply` | 值调用 `reply("层", "字段")` | 读取当前回包的反解字段（配方 `extract` 的 `from:` 表达式专用；求值期注入回包，其余上下文回退用户函数——eng_lib 的 ARP 位常量 `reply()` 撞名保持原语义）——`from: reply.icmp.id` 直取形态经构建期改写为本调用；数值字段 → Int、地址/字符串字段 → Str、payload/body/raw 字节 → 字节列表 |
| `round` | 值调用 `round()` | serve 阶段当前轮次（闸门放行后 1 起）——仅配方 `serve:` 阶段的监听 matcher / `until:` 谓词 / `extract` / 阶段内步骤表达式求值时按内置处理（宿主注入当前轮次），其余上下文报错（用户函数撞名时非 0 参调用仍走用户函数） |
| `hits` | 值调用 `hits()` | serve 阶段已命中次数（监听 matcher 构建时 = 之前轮次累计；命中后 extract/handler 求值时含本次；`on_mismatch` 不计数）——上下文约束同 `round` |

### 4.7 tpl 模板子语法（EBNF）

`tpl("模板串", 输入)` 的模板串在 pkglang 外层语法里只是**普通字符串字面量**
（值调用 `tpl`，见 §4.5）；模板串的**内部子语言**（模板匹配语法）在求值期由
`packet-dsl/src/tpl.rs` 解析——不经过 lexer.rs/parser.rs 的 chumsky 管线
（§6 的唯一例外），权威语义定义见 `DESIGN.md` §5.3。

```
template = element* ;                        (* 锚定全匹配：输入必须全部消费 *)
element  = literal | spec | dnsname ;
literal  = ( ascii - "%" ) | "%%" ;          (* "%%" 转义：匹配字面 '%' *)
spec     = "%" kind [ width ] [ repeat ] ;
kind     = "c" | "d" | "x" ;
width    = "1" | "2" | "4" ;                 (* 仅 d/x；缺省 = "1"（1 字节） *)
repeat   = "{" count [ ":" sep ] "}" ;
count    = [0-9]+ ;                    (* 解析后值须 >= 1（"{0}" 报错）；前导零合法，"{01}" = 1 *)
sep      = "" | ascii_char | "[" charset "]" ;
           (* "" = "{n:}" 冒号后空 → 缺省分隔符 ':'；单字符（":" 显式写 "{n::}"）；
              字符类：非空、不含 ']'、仅 ASCII *)
charset  = ascii - "]" ;
dnsname  = "%L" ;                        (* DNS 名字序列：动态宽度，不吃 width/repeat；
                                            紧跟数字或 "{" 报错 *)
```

匹配语义（字面字符/分隔符**匹配但不产出**——scanf 式解析器，说明符按序产出字节拼接）：

| 形态 | 语义 |
| --- | --- |
| `%c` | 恰好 1 字节任意值（通配），原样产出 |
| `%d w` | 贪心十进制（w=1/2/4 → 最多 3/5/10 位），值域 0..256^w−1（越界报错），大端 w 字节 |
| `%x w` | 贪心十六进制（最多 2w 位），同上 |
| `%L` | **DNS 名字序列（动态宽度，tpl 唯一例外）**：消费剩余全部输入为点分标签，每个标签产出（u8 标签字节长 + 原文），末尾 `0x00`；空标签跳过（尾点/连续点容忍）；标签 ≤63 字节、总长 ≤255（越界报错）。`dns_name("example.com")` ≡ `tpl("%L", "example.com")` |
| `{n}` | 重复 n 组（无分隔符） |
| `{n:sep}` | 重复 n 组，组间消费分隔符 sep（不产出）；`{n:}` 缺省 sep = `:` |
| `::`（sep = `:` 的重复内） | 输入 `::` = 零填充压缩：缺位补零组（`%x2{8:}` 通吃 ip6 全 8 组 / `::1` / `fe80::1` / `fe80::`；多个 `::` 报错） |
| 字节列表输入 | **等宽直通**：长度 = 模板总输出宽且逐字节 0..255 即原样返回（`mac(rand_mac())`）；**含 `%L` 的模板输出宽动态不可算 → 不接受字节列表输入** |

非法形态（`%` 后非 c/d/x/L/`%`、宽度非 1/2/4、`%L` 后跟数字或 `{`、`{` 未闭合、
`{0}`、非 ASCII 字面字符/分隔符/字符类）→ 求值期报错带位置。示例：

```
ip4("1.2.3.4")  ≡ tpl("%d{4:.}",  "1.2.3.4")     # 4×u8 点分
ip6("fe80::1")  ≡ tpl("%x2{8:}",  "fe80::1")     # 8×be16 含 :: 压缩
mac("aa:bb:..") ≡ tpl("%x{6:[-.:]}", "aa:bb..")  # 6×u8 分隔符容忍
dns_name("example.com") ≡ tpl("%L", "example.com")  # 长度前缀 + 尾 0
tpl("%d2:%d2", "5353:80")                        # 端口对 → 4 字节
```

## 5. 换行与续行规则

- **语句分隔**：每条语句前允许任意数量换行（惯例 ≥1 换行分隔；文件开头任意）。
- **续行**：流水线下一层以 `|>` 开头即续行（`layer := nl "|>" call`，`|>` 前容忍换行）。
- **括号内换行**：`(`/`[`/`{` 之后与 `)`/`]`/`}` 之前容忍换行；逗号两侧容忍换行
  （多行调用、多行列表、多行 `use(a, b)` 均合法）。
- **export/sniffer 列表项**：项间允许换行，也可无空格同排（`-a -b`）。
- **注释**：`#` 到行尾；不跨行。

## 6. 实现注记（parser 对应）

- 解析管线：词法（`lexer.rs`，token 流带行/列 span）→ chumsky 组合子（`parser.rs`）
  → AST（`ast.rs`）。span 用 `SimpleState<Vec<Token>>` 位置表换算行/列。
- 本 EBNF 的每个非终结符都能在 `parser.rs` 找到同名组合子
  （`value` / `call` / `arg_list` / `pipeline` / `use_part` / `func_stmt` /
  `sniffer_stmt` / `export_block` / ...），命名与本文档一一对应。
- **唯一例外：tpl 模板子语法（§4.7）**——模板串是字符串字面量，其内部模板语言
  不在 chumsky 管线内，由求值期 `tpl.rs` 解析（与 `DESIGN.md` §5.3 双权威互指）；
  其中 `%L` 是 tpl 内部的**动态宽度例外**（其余说明符输出宽度均由模板静态决定）。
- **语法层不含名字语义**：哪个 ident 是内置原语、参数类型强转、命名/位置参数
  对齐、`layer` 的 `kind` 闭集——都在 `registry.rs`（内置原语表）与 `eval.rs`
  （求值）处理。
- 改 parser 时注意 chumsky 1.0.0-alpha.8 的已知坑：`(A, B)` 元组 + `map_with`
  类型推断缺陷（用显式 `.then()` 链）；`repeated()` / `separated_by()` 输出 `()`
  （必须 `.collect()`）。

## 7. 示例（标注语法要点）

```pkt
# 值表达式：字面量、列表、params、+ 加法
a = http(method="GET", path="/", headers=[("Host", "example.com")])

# 调用：命名参数 + 无参裸调用（tcp ≡ tcp()）
b = use(a) |> tcp(dport=params("port", "443")) |> ipv4(dst=dst) |> eth

# 层函数：use 可选（层片段语义），参数可设默认值
func net4(dst, src="0.0.0.0", ttl=64) {
    ipv4(src=src, dst=dst, ttl=ttl) |> eth()
}

# 值函数：-> bytes { 值表达式 }
func wrap(acc, item) -> bytes { concat(acc, be16(item)) }

# import 别名 + export
import a { x as ax }
full = use(ax) |> tcp(dport=80)
export:
- full

# sniffer 回包/监听匹配（值 = 字面量常量 / 裸 Ident 发包字段引用 / 值表达式；
# and/or/not 组合 + ne/mask/startswith/endswith/contains 条件）
sniffer:
  - match icmp(type=0, id=id, seq=seq)
  - and(match udp(dport=53), not(match dns(flags=0x8180)))
```
