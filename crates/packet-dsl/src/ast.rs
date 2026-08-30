//! AST（抽象语法树）：chumsky 解析器的输出。
//!
//! 每个节点携带源码位置（1 基的行/列），供 import 报错与名字解析报错定位。

/// 源码位置：1 基行/列。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pos {
    pub line: usize,
    pub col: usize,
}

/// 一段源码区间（1 基行/列，含端点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: Pos,
    pub end: Pos,
}

impl Span {
    pub fn new(start_line: usize, start_col: usize, end_line: usize, end_col: usize) -> Self {
        Self {
            start: Pos {
                line: start_line,
                col: start_col,
            },
            end: Pos {
                line: end_line,
                col: end_col,
            },
        }
    }

    /// 合并两个 span（取并集）。
    pub fn union(self, other: Span) -> Span {
        Span {
            start: self.start,
            end: other.end,
        }
    }
}

/// 一个 `.pkt` 文件的解析结果：语句列表。
#[derive(Debug, Clone)]
pub struct AstFile {
    pub stmts: Vec<Stmt>,
}

/// 语句：export 块 / import / 定义 / 函数（含 proto schema）/ sniffer / 顶层匿名流水线。
#[derive(Debug, Clone)]
pub enum Stmt {
    Export(ExportStmt),
    Import(ImportStmt),
    Def(DefStmt),
    Func(FuncStmt),
    Sniffer(SnifferSpec),
    Pipeline(PipelineStmt),
}

/// `export:` 块。
#[derive(Debug, Clone)]
pub struct ExportStmt {
    pub names: Vec<(String, Span)>,
    pub span: Span,
}

/// `import a { a, b }`：names = None 表示「不带大括号 = 引入全部导出」。
/// 带大括号时每项为 (原名, 别名, span)——`x as y` 以 `y` 进入作用域，别名 None = 原名。
#[derive(Debug, Clone)]
pub struct ImportStmt {
    pub module: String,
    pub names: Option<Vec<(String, Option<String>, Span)>>,
    pub span: Span,
}

/// `IDENT = expr`
#[derive(Debug, Clone)]
pub struct DefStmt {
    pub name: String,
    pub name_span: Span,
    pub expr: Expr,
    pub span: Span,
}

/// 函数 doc 注释（紧贴 `func` 上方的连续 `#` 行）解析后的结构化内容。
///
/// 约定（与 `--eng --ls` 展示一致）：非标签行为摘要；`@param 名: 说明` 逐参数；
/// `@auto: 说明` 描述序列化自动行为。
#[derive(Debug, Clone, Default)]
pub struct FuncDoc {
    /// 摘要行（非 `@param`/`@auto` 标签行，按源码顺序拼接）。
    pub summary: String,
    /// `@param 名: 说明` 列表（保持声明顺序）。
    pub params: Vec<(String, String)>,
    /// `@auto: 说明`（后写覆盖先写）。
    pub auto: Option<String>,
}

/// `func name(p1, p2="默认") { pipeline }`：具名参数化函数。
///
/// 值函数返回类型（`-> bytes` / `-> int`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueRet {
    /// `-> bytes`：函数体求值为字节列表（原语义）。
    Bytes,
    /// `-> int`：函数体求值为整数（`sum`/`count`/`len`/位运算等整数原语的结果）。
    Int,
}

/// 函数体是流水线（`use` 可选）；无 `use` 时视为层片段，求值以一个空包种子逐层包裹。
/// 参数全部可选：无默认值 = 未设（在层参数位置省略 → 自动值）；有默认值 = 未传时用默认。
#[derive(Debug, Clone)]
pub struct FuncStmt {
    pub name: String,
    pub name_span: Span,
    pub params: Vec<FuncParam>,
    /// 层函数体（流水线）；`value_body`/`schema` 存在时忽略。Box 控制 Stmt 枚举尺寸。
    pub body: Box<Pipeline>,
    /// 值函数（`-> bytes` / `-> int`）：函数体是值表达式；None = 层函数。
    pub value_body: Option<(ValueRet, Value)>,
    /// `#[proto]` / `#[rule]` 注解（仅 proto 函数，`#[proto]` 必有；普通函数为空）。
    /// 带 `#[proto]` 时 `proto_body` 承载降糖前的 body，`schema` 承载降糖后的字段表。
    pub attrs: Vec<Attr>,
    /// `#[proto] func` 的 body（`concat(...)`，参数可带 `#[meta(...)]` 标注）；
    /// None = 普通函数。解析后由 [`desugar_proto_func`] 降糖为 `schema`（本字段即被
    /// 消费清空）。Box 控制 Stmt 枚举尺寸。
    pub proto_body: Option<Box<ProtoFuncBody>>,
    /// proto schema（`#[proto] func ... -> bytes`）：字段表——proto = 值函数 +
    /// 字段标注（`-> bytes` 必填，schema 使其**可逆**：构造编码、解析解码共用）。
    /// None = 普通函数/值函数。Box 控制 Stmt 枚举尺寸。
    pub schema: Option<Box<ProtoSchema>>,
    pub span: Span,
    /// 紧贴函数上方的 `#` doc 注释（`--ls`/LSP 悬停展示用；无则 None）。
    pub doc: Option<FuncDoc>,
}

/// proto 的降糖字段表（`#[proto] func` 的 concat 参数 → 字段声明）。
#[derive(Debug, Clone)]
pub struct ProtoSchema {
    /// 字段声明，按线格式顺序（构造/解析共用）。
    pub fields: Vec<FieldDecl>,
}

/// `#[proto] func` 的 body（降糖前）：扁平 `concat(...)`，参数可带 `#[meta(...)]` 标注。
/// （body 的 `layer("kind", concat(...))` 形态已移除——层身份一律用
/// `#[proto(kind=...)]` 注解，避免同一信息两种写法。）
#[derive(Debug, Clone)]
pub struct ProtoFuncBody {
    /// concat 的参数（含 `#[meta(...)]` 标注），按线格式顺序。
    pub args: Vec<ProtoFuncArg>,
}

/// `concat` 的一个参数：值（类型化调用 / 裸标识符 / 表达式）+ 前置 `#[meta(...)]` 标注。
#[derive(Debug, Clone)]
pub struct ProtoFuncArg {
    pub attrs: Vec<Attr>,
    pub value: Value,
    pub span: Span,
}

/// 函数参数：`IDENT`（未设）或 `IDENT = 默认值`。
#[derive(Debug, Clone)]
pub struct FuncParam {
    pub name: String,
    pub span: Span,
    pub default: Option<Value>,
}

// ── proto（自表示协议：声明式字段布局，构造与解析共用）────────────

/// 变长整数值字节的端序（Table 模型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VintEndian {
    Be,
    Le,
}

/// 变长整数编解码方案（`FieldType::Vint` 字段携带，构造/解析共用——可逆）。
///
/// 变长整数线格式只有三种结构模型，现实协议几乎都是它们的实例；方案数据化后
/// 新增编码 = 声明数据，不动引擎（见 docs/design-proto-self-describing.md §4.5）。
/// 编解码实现收敛在 `codec.rs`（`encode`/`decode` 方法），构造/解析同一份代码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VintCodec {
    /// 续延位模型（LEB128）：每字节低 7 位值 + 最高位续延，值越大字节越多，
    /// 最小字节数。范围 0..=2^63-1（≤9B）。`varint(x)` 即此方案。
    Le128,
    /// 前缀宽度表模型：首字节高 `prefix_bits` 位 = 宽度索引（大端序），查
    /// `widths` 表得字段字节数；值 = 余下位（大端）。范围 0..=2^(8·max(widths)−
    /// prefix_bits)−1。`qvarint(x)` 即 Prefix{2, [1,2,4,8]}（RFC 9000 §16）。
    Prefix { prefix_bits: u8, widths: Vec<u8> },
    /// 内联 + 哨兵表模型：值 ≤ `inline_max` 直接 1 字节内联；否则首字节 = 哨兵
    /// （> inline_max），查 `table`（哨兵 → 后续字节数）读余下字节，值按 `endian`
    /// 解读。范围 0..=min(i64::MAX, 2^(8·max(width))−1)。
    /// Bitcoin varint 即 Table{0xFC, [(0xFD,2),(0xFE,4),(0xFF,8)], Le}。
    Table {
        inline_max: u8,
        table: Vec<(u8, u8)>,
        endian: VintEndian,
    },
}

/// 声明式字段的线格式编码类型（可逆原语：构造编码、解析解码共用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    U8,
    Be16,
    Be32,
    Be64,
    Le16,
    Le32,
    Le64,
    /// 变长整数（方案见 [`FieldDecl::vint`]；`varint`/`qvarint` 为预置方案的糖）。
    Vint,
    /// 6 字节 MAC。
    Mac,
    /// 4 字节 IPv4。
    Ip4,
    /// 16 字节 IPv6。
    Ip6,
    /// 定宽/联动宽度字节（宽度来自 `#[meta(bytes=...)]`，字面量自动推导）。
    Bytes,
    /// 消费到载荷末尾（payload；`#[meta(rest)]`，可带子 proto `#[meta(rest="子proto")]`）。
    Rest,
    /// DNS 名字（标签序列 + 0 终止；解析侧压缩指针追跳还原，构造侧字符串编码）。
    DnsName,
    /// 文本行（到 `\r\n`；值 = 字符串，不含终止符）——HTTP 头行等。
    /// 解析侧**空行（首字节 `\r`）→ 失败**（供 list 哨兵终止判定）。
    Line,
}

/// 计算长度字段的目标：`#[meta(len="auto")]` = 后续全部字段字节数（原 `@auto`）；
/// `#[meta(len="字段名")]` = 目标字段（后序）编码字节数（原 `@len`）。
/// 两者同一机制（构造侧引擎计算、可配 `expr` 变换、解析侧正常读），合并为一个概念。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LenTarget {
    /// 后续全部字段字节数（原 `@auto`/`#[meta(auto)]`）。
    Auto,
    /// 目标字段（后序）字节数（原 `@len(目标)`/`#[meta(len="目标")]`）。
    Field(String),
}

/// proto 的一个字段：`name: type [= 默认值] [len 标注]`。
#[derive(Debug, Clone)]
pub struct FieldDecl {
    pub name: String,
    pub name_span: Span,
    pub ty: FieldType,
    /// `#[meta(bytes=...)]` 的宽度表达式（引用前序字段名或字面量；其余类型为 None）。
    pub width: Option<Value>,
    /// `#[meta(bits=N)]` 位宽（整型字段：u8 ≤8 / be16 ≤16 / be32 ≤32 / be64 ≤64）：
    /// 字段只占位组内 N 位——同一组内按声明顺序从高位到低位填充（大端位序），
    /// 连续 bits 字段凑满 8 的倍数位即成整字节组（如 IPv4 version+ihl 各 4 位
    /// = 0x45；IPv6 version+TC+flow = 4+8+20 位跨 4 字节组）。
    pub bits: Option<u8>,
    /// `= 默认值`（未传参数时求值；可引用前序字段与参数）。
    pub default: Option<Value>,
    /// 计算长度字段：`len="auto"` = 后续全部字段字节数；`len="目标"` = 目标字段
    /// （后序）字节数——构造时引擎计算、反向填充，解析时正常读、重序列化重算。
    pub len_of: Option<LenTarget>,
    /// `len` 的表达式变换（`#[meta(len=..., expr="...")]`）：构造时先算基准值
    /// （后续字节数 / 目标字段字节数），再经表达式变换后编码（expr 里 `len` 特殊
    /// 变量 = 基准值；缺省 = 原值）——TCP data_offset 的 `/4 + 5 << 4` 联动即用此
    /// 表达。解析时正常读、不重算。
    pub len_expr: Option<Value>,
    /// 重复区的子协议名：`#[meta(list="计数", item="子proto")]`（按计数重复）或
    /// `#[meta(rest="子proto")]`（重复解析到失败，原哨兵 list）——元素子 proto；
    /// 构造侧值 = 列表逐项编码，解析侧按计数/到失败循环产出嵌套 [`ProtoHit`]。
    pub rest_proto: Option<String>,
    /// 重复字段的计数表达式（`#[meta(list="计数", item="子proto")]`，引用前序字段
    /// 如 DNS qdcount）；None + `rest_proto` = 重复到失败（原哨兵 list，如 HTTP
    /// headers 以空行结束）。
    pub list_count: Option<Value>,
    /// 变长整数方案（`ty == Vint` 时必填；`#[meta(codec=...)]` 声明，无调用糖）。
    pub vint: Option<VintCodec>,
    /// `#[meta(switch="字段")]` 判别式分派：解析时读前序字段值，按 `cases` 表
    /// 选子 proto 反解本字段的字节窗口；构造侧值 = 字节直喂（同 rest 字段先例）。
    /// 类型固定 [`FieldType::Bytes`]（值 = 窗口字节）。
    pub switch_field: Option<Value>,
    /// `#[meta(cases=[[值, "子proto"], ...])]` 判别表（`switch` 必配；值须互异）。
    pub cases: Option<Vec<(i64, String)>>,
    /// `#[meta(if="表达式")]` 条件在场守卫：整型表达式非零 = 字段存在——
    /// 解析消费 0 位、构造不编码、实参可省略；表达式引用前序整型字段/参数
    /// （`band`/`shr` 组合，非零语义，不引入布尔运算）。
    pub if_cond: Option<Value>,
    pub span: Span,
}

/// 注解：`#[proto(kind="eth")]` / `#[rule(layer="udp", dport=443)]` /
/// `#[meta(name="x", bytes=4)]`——统一参数语法：`key=value` 项列表（flag 无值；
/// 裸值/裸标识符为旧形式，语义阶段给迁移报错）。
#[derive(Debug, Clone)]
pub struct Attr {
    pub name: String,
    pub args: Vec<AttrArg>,
    pub span: Span,
}

/// 注解的一个参数项（统一语法，按注解名解释）：
/// - `Kv`：`key = value`（proto 的 `kind`、meta 的 `name`/`len`/`bytes`/`rest`）；
/// - `Call`：`fn(args)` 调用形式（rule 的 `udp(dport=443)` / `bytes(0xc0)`，
///   具名/位置参数复用 [`AttrArg`]）；
/// - `Bare`：裸值（meta 的 `auto`/`rest` flag，或旧位置形式——迁移报错用）。
#[derive(Debug, Clone)]
pub enum AttrArg {
    Kv {
        key: String,
        value: Value,
        span: Span,
    },
    Call {
        name: String,
        args: Vec<AttrArg>,
        span: Span,
    },
    Bare {
        value: Value,
        span: Span,
    },
}

/// `sniffer:` 回包/监听匹配声明（`--pkt --wait` 校验应答、`--listen` 监听规则），
/// 与 `export:` 同风格的列表；**顶层列表 = 隐式 OR**（向后兼容）。
///
/// ```pkt
/// sniffer:
///   - match icmp(type=0, id=id, seq=seq)
///   - and(match udp(dport=53), match http(method="GET"))
/// ```
///
/// 每个 `match 层(条件, ...)` 是一个匹配子句：反解后必须满足该子句全部条件。
/// 匹配值（字段等式右值）：
/// - 字面量（Int/Hex/Str）= 常量比较（如 `type=0`：回包 icmp.type == 0）；
/// - 裸 Ident = 引用**发包同层同名字段**（如 `id=id`：回包 icmp.id == 发包 icmp.id；
///   监听模式无发包，构建期报错）；
/// - 值表达式（字节原语 / 值函数 / `params(...)` / 字节列表）= **字节级比较**
///   （如 `id=be16(0x1234)`：求值为字节后与回包字段字节比较——函数最终算出的
///   也是字节，可直接复用已写好的值函数）。
#[derive(Debug, Clone)]
pub struct SnifferSpec {
    /// 顶层匹配谓词列表（任一命中即匹配 = 隐式 OR）。
    pub clauses: Vec<SnifferPred>,
    pub span: Span,
}

/// 匹配谓词：单个 match 子句或 `and`/`or`/`not` 组合（与 `#[rule]` 同构）。
#[derive(Debug, Clone)]
pub enum SnifferPred {
    /// `match 层(条件, ...)`：层内全部条件 AND。
    Clause(SnifferClause),
    /// `and(...)`：全部子谓词满足。
    And(Vec<SnifferPred>),
    /// `or(...)`：任一子谓词满足。
    Or(Vec<SnifferPred>),
    /// `not(...)`：子谓词不满足（监听/回包反解后整包判定；`#[rule]` 侧不支持）。
    Not(Box<SnifferPred>),
}

/// 单个匹配子句：`match 层(条件, ...)`。
#[derive(Debug, Clone)]
pub struct SnifferClause {
    /// 期望的层类型（eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns 或 proto 命中名）。
    pub layer: String,
    /// 层内匹配条件列表（全部 AND）。
    pub items: Vec<SnifferItem>,
    pub span: Span,
}

/// 层内匹配条件。
#[derive(Debug, Clone)]
pub enum SnifferItem {
    /// `字段=值` 等式（值语义见 [`SnifferValue`]）。
    FieldEq { name: String, val: SnifferValue },
    /// `ne(字段, 值)` 不等比较（值语义同等式；匹配时不报告命中字段）。
    FieldNe { name: String, val: SnifferValue },
    /// `mask(0xc0)`：层原始字节首字节位掩码 `(首字节 & mask) == mask`。
    Mask(Value),
    /// `startswith("...")`：层原始字节前缀匹配。
    StartsWith(String),
    /// `endswith("...")`：层原始字节后缀匹配。
    EndsWith(String),
    /// `contains("...")`：层原始字节子串匹配。
    Contains(String),
}

/// sniffer 匹配值（字段等式右值）。
#[derive(Debug, Clone)]
pub enum SnifferValue {
    /// 常量比较。
    Literal(Value),
    /// 引用发包同层同名字段。
    SentField(String),
    /// 值表达式（原语/值函数/params 等）：求值为字节后与回包字段**字节**比较。
    Expr(Value),
}

/// 定义右侧的表达式：单层调用（含元件引用）或流水线。
#[derive(Debug, Clone)]
pub enum Expr {
    Call(Call),
    Pipeline(Pipeline),
}

/// 层函数调用：`tcp(dport=80)` / `my_layer(...)`（语义阶段解析为内置函数或用户元件）。
#[derive(Debug, Clone)]
pub struct Call {
    pub name: String,
    pub name_span: Span,
    pub args: Vec<Arg>,
    pub span: Span,
}

/// 参数：`IDENT = value`（命名）或 `value`（位置参数）。
#[derive(Debug, Clone)]
pub struct Arg {
    pub name: Option<(String, Span)>,
    pub value: Value,
    pub span: Span,
}

/// 值表达式的二元运算符（目前仅 `+` 数字加法；比较/逻辑已随高阶原语移除）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    /// `+`（整数加法）
    Add,
}

/// 值。
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Hex(u64),
    List(Vec<Value>),
    /// 运行时参数引用：`params("name", 默认值)`，求值时从宿主注入的参数表取值
    /// （宿主值按形状解析：`0x` 前缀/纯数字 → 数值，否则字符串）；未注入时用
    /// **默认值表达式**（可为任意值表达式，如 `be16(0x1235)` / `"text"` / `[0x12]`）。
    Param {
        name: String,
        default: Option<Box<Value>>,
    },
    /// 函数参数引用：`dst=dst` 右侧的裸标识符，求值时从当前函数的参数环境取值。
    /// 未提供的参数（未设）在层参数位置表示省略（自动值），由求值阶段处理。
    Ident {
        name: String,
        span: Span,
    },
    /// 值位置函数调用：`concat(...)` / `be16(...)` 等——原语或用户值函数（`-> bytes`/`-> int`）。
    Call {
        name: String,
        name_span: Span,
        args: Vec<Value>,
        span: Span,
    },
    /// 数字加法：`20 + len(payload)`（值表达式）。
    BinOp {
        op: BinOp,
        left: Box<Value>,
        right: Box<Value>,
        span: Span,
    },
}

/// 流水线：`use(a, b) |> tcp(...) |> ipv4(...)`。
#[derive(Debug, Clone)]
pub struct Pipeline {
    /// `use(...)` 引入的元件名（必须是本文件定义或已 import 的元件）。
    pub use_names: Vec<(String, Span)>,
    /// 层调用序列：内 → 外（每个调用把当前内容包一层）。
    pub layers: Vec<Call>,
    pub span: Span,
}

/// 顶层匿名流水线（默认导出）。
#[derive(Debug, Clone)]
pub struct PipelineStmt {
    pub pipeline: Pipeline,
    pub span: Span,
}
