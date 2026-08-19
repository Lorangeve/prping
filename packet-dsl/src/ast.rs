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

/// 语句：export 块 / import / 定义 / 函数 / sniffer / 顶层匿名流水线。
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
/// 函数体是流水线（`use` 可选）；无 `use` 时视为层片段，求值以一个空包种子逐层包裹。
/// 参数全部可选：无默认值 = 未设（在层参数位置省略 → 自动值）；有默认值 = 未传时用默认。
#[derive(Debug, Clone)]
pub struct FuncStmt {
    pub name: String,
    pub name_span: Span,
    pub params: Vec<FuncParam>,
    /// 层函数体（流水线）；`value_body` 存在时忽略。
    pub body: Pipeline,
    /// 值函数（`-> bytes`）：函数体是值表达式，返回字节列表；None = 层函数。
    pub value_body: Option<Value>,
    pub span: Span,
    /// 紧贴函数上方的 `#` doc 注释（`--ls`/LSP 悬停展示用；无则 None）。
    pub doc: Option<FuncDoc>,
}

/// 函数参数：`IDENT`（未设）或 `IDENT = 默认值`。
#[derive(Debug, Clone)]
pub struct FuncParam {
    pub name: String,
    pub span: Span,
    pub default: Option<Value>,
}

/// `sniffer:` 回包匹配声明（`--pkg --wait` 校验应答），与 `export:` 同风格的列表：
///
/// ```pkt
/// sniffer:
///   - match icmp(type=0, id=id, seq=seq)
/// ```
///
/// 每个 `match 层(字段=值, ...)` 是一个匹配子句：回包反解后必须满足该子句全部等式；
/// 多子句时**任一命中**即匹配成功。匹配值：
/// - 字面量（Int/Hex/Str/Bool）= 常量比较（如 `type=0`：回包 icmp.type == 0）；
/// - 裸 Ident = 引用**发包同层同名字段**（如 `id=id`：回包 icmp.id == 发包 icmp.id）。
#[derive(Debug, Clone)]
pub struct SnifferSpec {
    /// 匹配子句列表（任一命中即匹配）。
    pub clauses: Vec<SnifferClause>,
    pub span: Span,
}

/// 单个匹配子句：`match 层(字段=值, ...)`。
#[derive(Debug, Clone)]
pub struct SnifferClause {
    /// 期望的回包层类型（eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns）。
    pub layer: String,
    /// (字段名, 匹配值)。
    pub fields: Vec<(String, SnifferValue)>,
    pub span: Span,
}

/// sniffer 匹配值。
#[derive(Debug, Clone)]
pub enum SnifferValue {
    /// 常量比较。
    Literal(Value),
    /// 引用发包同层同名字段。
    SentField(String),
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

/// 值。
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Hex(u64),
    Bool(bool),
    List(Vec<Value>),
    /// 运行时参数引用：`params("name", "默认值")`，求值时从宿主注入的参数表取值。
    /// 值在宿主侧都是字符串，在具体字段处按类型解析（端口/地址/flags 等）。
    Param {
        name: String,
        default: Option<String>,
    },
    /// 函数参数引用：`dst=dst` 右侧的裸标识符，求值时从当前函数的参数环境取值。
    /// 未提供的参数（未设）在层参数位置表示省略（自动值），由求值阶段处理。
    Ident {
        name: String,
        span: Span,
    },
    /// 值位置函数调用：`concat(...)` / `be16(...)` 等——原语或用户值函数（`-> bytes`）。
    Call {
        name: String,
        name_span: Span,
        args: Vec<Value>,
        span: Span,
    },
    /// 数字加法：`20 + len(payload)`（值表达式）。
    Add {
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
