//! 配方（`.pktl` = package list）：按顺序发送多个 `.pkt` 文件，跨步骤共享 global 状态。
//!
//! 格式（清单风格，与 .pkt 的 `export:`/`sniffer:` 一致）：
//!
//! ```text
//! # handshake.pktl
//! global:
//! - name: tid             # 跨步骤共享变量（可选 init）
//!   init: 0x1234
//! - server_seq            # 裸声明 = 未初始化，值来自后续 extract / CLI -g
//! - next_seq=0x100        # 一行内联 init（与 init: 同字面量语法）
//!
//! recipe:
//! - packet: examples/step1.pkt  # 发 step1，等回包，把回包 tcp.seq 提取进 global
//!   wait: 1
//!   extract:
//!   - name: server_seq
//!     from: reply.tcp.seq      # 回包反解字段（层.字段，与 sniffer 字段集一致）
//!     as: int                  # 默认 int；可选 hex / str / bytes
//!   - name: next_seq
//!     from: reply.tcp.seq + 1  # 值表达式（可调函数/原语；缺省 = 自然类型值）
//!   on_error: stop             # stop（默认）/ continue
//! - examples/step2.pkt         # 裸文件名 = 无额外选项
//! ```
//!
//! 语法规则：
//! - `global:` / `recipe:` 段头与步骤项（`- `）在行首（列 0）；段内选项行缩进（≥1 空格）。
//! - global 项三种形态：`- name: X`（可后跟缩进 `init:`）、`- X`（裸声明，未初始化）、
//!   `- X=v`（一行内联 init；v 与 `init:` 同字面量语法，见下）。
//! - 步骤项：`- packet: 文件`（后可跟选项行）或裸文件名 `- 文件`。
//! - 步骤选项：`wait: 秒数`（**非负秒数** = 发送后等一个匹配应答，等价 CLI
//!   `--wait SECS`；不写 = 纯发送；负数/空值非法——持续监听已由 `serve:` 接管）、
//!   `on_timeout: retry [N]|文件`（**wait 超时处理**：`wait: 秒数` 超时未收到匹配
//!   应答时，打印超时信息并重发或发送备选 .pkt，步骤继续）、`delay: 秒数`（步骤
//!   开始前等待，pcap 转码配方用；响应 Ctrl+C 提前结束）、
//!   `params: k=v,k2=v2`（静态字符串，追加到 `--params` 同名覆盖）、
//!   `raw: true|false|网卡名`（覆盖 `--raw`：`true` 开原始发送、网卡名 = 开原始发送并
//!   指定网卡、`false` 强制载荷发送）、`extract:`（子列表 `- name:` + `from:` + `as:`）、
//!   `on_error: stop|continue`。
//! - **serve 阶段**（`- serve:`，容器项无内联值）：多规则监听分派 + 命中处理，
//!   阻塞至收工——`max: N`（最多服务轮数，负数 = 无限）、`until:` 谓词列表
//!   （sniffer 同款 `match 层(条件, ...)` / and/or/not；收到的包命中即在本轮结束
//!   后收工）、`delay: 秒` 轮间延迟、`rules:` 规则表（至少一条）。阶段内 Ctrl+C
//!   优雅收工（打印统计、退出码 0）。谓词可用 `global(...)`（每轮重建 Matcher，
//!   取上一轮 extract 最新值）。
//! - **serve 规则**（`rules:` 下 `- packet: 文件` 项）：监听源——包内有 udp/tcp
//!   传输层 → UDP 数据报监听，否则链路层监听（`raw: true|网卡名` 显式覆盖）；
//!   其 `sniffer:` 段 = 本规则的分派谓词；`extract:` 命中取值写 global（`reply.*`
//!   取命中包、`reply.peer.*` 取 socket 对端）；`handler:` = 命中后步骤列表
//!   （每个命中包执行一次）。多规则 = 分派：不同 dport 天然分流，同一监听地址
//!   的规则按声明顺序逐个匹配。
//! - **嵌套 on_recv**（handler 内 `- on_recv:` 项）：handler 执行中等待**下一个**
//!   匹配包（单轮），命中后执行其 handler——多步握手/状态机按嵌套深度编排。
//! - `from:` 取值：`reply.<层>.<字段>` 直取回包反解字段（层/字段名与 sniffer 一致）；
//!   或**值表达式**（可调函数/原语/`+`，内嵌 `reply.<层>.<字段>` 叶子），如
//!   `from: reply.icmp.seq + 1` / `from: cksum(reply.icmp.payload)`。
//! - `init` 值：字符串 `"..."` / 十进制 / `0x` 十六进制 / `[0x01, 0x02]` 字节列表。
//! - `#` 行注释，空行忽略；路径相对 .pktl 所在目录解析。
//!
//! 执行在 `pkg.rs::send_recipe`（维护 global 存储 + extract + on_error 容错）；
//! `--eng FILE.pktl` 只做结构概览（`eng.rs::analyze_recipe`）。

use rust_i18n::t;

use std::path::{Path, PathBuf};

use packet_dsl::ast::Value;

/// 全局声明（`global:` 段一项）。
#[derive(Debug, Clone)]
pub struct GlobalDecl {
    pub name: String,
    /// 初始值（字符串 / 数字 / hex / 字节列表字面量）；None = 未初始化。
    pub init: Option<Value>,
    pub line: usize,
}

/// 回包字段提取的取值形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExtractAs {
    /// 数值字段 → 整数（默认）。
    #[default]
    Int,
    /// 数值字段 → 十六进制值。
    Hex,
    /// 字段展示字符串（IP/MAC 格式化、数值十进制）。
    Str,
    /// 字段原始字节（网络序 / UTF-8）。
    Bytes,
}

impl ExtractAs {
    /// 统一的 `as:` 形态转换：自然值 → 目标形态（Int/Hex/Str/Bytes）。
    /// 字段形态（`apply_extract` 先把 FVal 归一到自然 Value）与表达式形态共用，
    /// 消除重复转换逻辑；错误消息统一走 i18n。
    pub fn apply(self, v: Value, line: usize, name: &str) -> anyhow::Result<Value> {
        fn err_msg(line: usize, name: &str, msg: &str, v: &Value) -> anyhow::Error {
            anyhow::anyhow!(
                "{}",
                t!(
                    "engine.recipe_as_convert_fail",
                    line = line,
                    name = name,
                    msg = msg,
                    val = crate::engine::eng::value_display(v)
                )
            )
        }
        match self {
            ExtractAs::Int => match v {
                Value::Int(_) => Ok(v),
                Value::Hex(h) => Ok(Value::Int(h as i64)),
                other => Err(err_msg(line, name, &t!("engine.recipe_as_int"), &other)),
            },
            ExtractAs::Hex => match v {
                Value::Hex(_) => Ok(v),
                Value::Int(i) if i >= 0 => Ok(Value::Hex(i as u64)),
                other => Err(err_msg(line, name, &t!("engine.recipe_as_hex"), &other)),
            },
            ExtractAs::Str => match v {
                Value::Str(_) => Ok(v),
                Value::Int(i) => Ok(Value::Str(i.to_string())),
                Value::Hex(h) => Ok(Value::Str(h.to_string())),
                other => Err(err_msg(line, name, &t!("engine.recipe_as_str"), &other)),
            },
            ExtractAs::Bytes => match v {
                Value::List(_) => Ok(v),
                Value::Str(s) => Ok(Value::List(
                    s.bytes().map(|b| Value::Int(b as i64)).collect(),
                )),
                other => Err(err_msg(line, name, &t!("engine.recipe_as_bytes"), &other)),
            },
        }
    }

    fn parse(s: &str, line: usize) -> anyhow::Result<Self> {
        if s.trim().is_empty() {
            return Err(err(line, t!("engine.parse_as_empty")));
        }
        match s {
            "int" => Ok(ExtractAs::Int),
            "hex" => Ok(ExtractAs::Hex),
            "str" => Ok(ExtractAs::Str),
            "bytes" => Ok(ExtractAs::Bytes),
            other => Err(anyhow::anyhow!(
                "{}",
                t!("engine.parse_as_only", line = line, other = other)
            )),
        }
    }
}

/// `from:` 取值来源：回包/发包反解字段（直取形态）或值表达式（可调用函数/原语）。
#[derive(Debug, Clone, PartialEq)]
pub enum FromSpec {
    /// `reply.<层>.<字段>`——直接取**回包**反解字段（`as:` 控制形态，默认 int）。
    Field { layer: String, field: String },
    /// `sent.<层>.<字段>`——直接取**本步发包**反解字段（`as:` 控制形态，默认 int；
    /// 无需 `wait`）。
    SentField { layer: String, field: String },
    /// `reply.peer.ip` / `reply.peer.port`——**listen 步骤** UDP 监听的**对端地址**
    /// （载荷里没有 udp 头，对端来自 socket；供后续步骤回包）。
    PeerField { field: String },
    /// 值表达式（可含 `reply.<层>.<字段>` 叶子，解析期改写为 `reply("层","字段")`
    /// 原语调用）：如 `reply.icmp.seq + 1` / `cksum(reply.icmp.payload)`。
    /// `as:` 可选（缺省 = 表达式的自然类型值）。
    Expr(packet_dsl::ast::Value),
}

impl FromSpec {
    /// 表达式形态的 DSL 值（字段/发包字段形态返回 None）。
    pub fn as_expr(&self) -> Option<&packet_dsl::ast::Value> {
        match self {
            FromSpec::Expr(v) => Some(v),
            FromSpec::Field { .. } | FromSpec::SentField { .. } | FromSpec::PeerField { .. } => {
                None
            }
        }
    }
}

/// 提取子句（步骤 `extract:` 一项）：从回包反解取值写入 global。
#[derive(Debug, Clone)]
pub struct Extract {
    pub name: String,
    pub from: FromSpec,
    pub as_: ExtractAs,
    /// 是否显式写了 `as:`（`from:` 表达式形态缺省 = 自然值；字段形态缺省 = int）。
    pub as_given: bool,
    pub line: usize,
}

/// 步骤失败处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    /// 任一步骤失败即停整个配方（默认）。
    Stop,
    /// 记录失败继续下一步骤（最后退出码仍非零）。
    Continue,
}

/// 步骤级 `raw:` 覆盖（`--raw` 的按步开关）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepRaw {
    /// 强制原始发送完整序列化字节。`iface` 非 None = `raw: 网卡名`（指定网卡）；
    /// None = `raw: true`（网卡继承 CLI `--iface`，未给则用平台默认）。
    On { iface: Option<String> },
    /// `raw: false`：强制载荷发送（覆盖 CLI `--raw`）。
    Off,
}

/// 步骤 `on_timeout`（wait 超时处理）：重发原包（retry）或发送备选 .pkt。
#[derive(Debug, Clone)]
pub enum OnTimeout {
    /// `on_timeout: retry [N]`：重发当前步骤的包 N 次（每次重新 wait；默认 1）。
    /// 任一次等到回包 → 步骤成功；全失败 → 按超时处理。
    Retry(usize),
    /// `on_timeout: 文件`：超时后发送备选 .pkt（发其它包）。
    Packet(PathBuf),
}

/// serve 规则：监听源 + 命中取值 + 命中后步骤（serve 阶段与嵌套 on_recv 共用）。
#[derive(Debug, Clone)]
pub struct ServeRule {
    /// 监听源 .pkt（其 `sniffer:` 段 = 本规则的分派谓词；udp/tcp dport 推导绑定）。
    pub packet: PathBuf,
    /// 监听方式覆盖（None = 按包内传输层自动选择；`raw: true|网卡名` = 链路层监听）。
    pub raw: Option<StepRaw>,
    /// 规则级静态参数（追加到 `--params`，同名覆盖）。
    pub params: Vec<(String, String)>,
    /// 命中包字段提取（`reply.*` 取命中包反解；`reply.peer.*` 取 socket 对端）。
    pub extract: Vec<Extract>,
    /// 命中后步骤（每个命中包执行一次；可含嵌套 `on_recv:` 项）。
    pub handler: Vec<ServeItem>,
    pub line: usize,
}

/// serve handler 条目：普通步骤或嵌套 on_recv（等下一个包）。
/// （allow：Step 为 handler 里的高频常用变体，按值携带字段更顺手；Box 化只为压
/// lint，会波及解析器/执行器/eng 概览的模式匹配，不值得。）
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum ServeItem {
    Step(Step),
    OnRecv(Box<ServeRule>),
}

/// serve 阶段：多规则监听分派 + 命中处理，阻塞至收工。
#[derive(Debug, Clone)]
pub struct Serve {
    /// 最多服务轮数；None = 无限（`max: 负数`）。与 until/Ctrl+C 先到先退。
    pub max: Option<usize>,
    /// `until:` 谓词文本列表（sniffer 同款语法；顶层多条 = 隐式 OR）。收到的包
    /// 命中任一谓词 → 本轮结束后收工；执行期每轮重建 Matcher（`global(...)`
    /// 取上一轮 extract 最新值）。
    pub until: Option<Vec<String>>,
    /// 轮间延迟秒数（第 2 轮起生效；响应 Ctrl+C 提前收工）。
    pub delay: Option<f64>,
    /// 规则表（至少一条）。
    pub rules: Vec<ServeRule>,
    /// 未命中处理段（`on_mismatch:` 选项，写在 rules: 之前）：收到的包不匹配
    /// 任何规则且不匹配 until 时执行；执行完继续监听，**不消耗服务轮次**。
    /// 条目语法与 handler 一致（步骤 / 嵌套 on_recv）。
    pub on_mismatch: Option<Vec<ServeItem>>,
    pub line: usize,
}

/// 配方条目：步骤或 serve 阶段。
#[derive(Debug, Clone)]
pub enum RecipeItem {
    Step(Step),
    Serve(Serve),
}

/// serve 阶段脱糖后的循环上下文（执行器内部：serve: 阶段展开为带同一 [`LoopCtx`]
/// 的扁平步骤序列，执行器按 first/last 定位块边界循环回跳；解析器不产生此类型）。
#[derive(Debug, Clone, PartialEq)]
pub struct LoopCtx {
    /// 阶段序号（0 起；同阶段步骤相同）。
    pub id: usize,
    /// 服务轮数上限；None = 无限（max 负数）。
    pub count: Option<usize>,
    /// `until:` 谓词文本列表（每个监听步骤收包时检查；任一命中 → 本轮结束后收工）。
    pub until: Option<Vec<String>>,
    /// 轮间延迟秒数（第 2 轮起生效）。
    pub delay: Option<f64>,
    /// 阶段内首步（迭代闸门所在）。
    pub first: bool,
    /// 阶段内末步（块边界 = 末步下标 + 1）。
    pub last: bool,
    /// 分派阶段的段标记（多规则/带 on_mismatch 阶段）：Some(k) = 本步属于
    /// 规则 k 段（k = 规则数 = on_mismatch 段），执行器只执行选中段的步骤；
    /// None = 非分派阶段步骤或分派监听步骤本身（不受段守卫）。
    pub rule: Option<usize>,
    pub line: usize,
}

/// 配方步骤：发送一个 .pkt（可选等一个应答 + 超时补偿 + 字段提取）。
#[derive(Debug, Clone)]
pub struct Step {
    /// .pkt 文件（相对 .pktl 所在目录解析）。
    pub pkg: PathBuf,
    /// 发送后等待匹配应答的秒数（非负；None = 纯发送，继承 CLI `--wait SECS`
    /// 作默认）。负数/空值非法——持续监听已由 `serve:` 阶段接管。
    pub wait: Option<f64>,
    /// **wait 超时处理**：`wait: 秒数` 超时未收到匹配应答时——`retry [N]` 重发
    /// 当前步骤的包（每次重新 wait），或发送备选 .pkt（发其它包）；步骤继续。
    pub on_timeout: Option<OnTimeout>,
    /// **每个包重复发送次数**（`count: N`，覆盖 CLI `--count`；默认继承）。
    pub count: Option<usize>,
    /// 步骤开始前的延迟秒数（pcap 转码配方携带捕获间隔；响应 Ctrl+C 提前结束）。
    pub delay: Option<f64>,
    /// 覆盖发送方式（None = 继承 CLI `--raw`）。
    pub raw: Option<StepRaw>,
    /// 静态字符串参数（追加到 `--params`，同名覆盖）。
    pub params: Vec<(String, String)>,
    pub extract: Vec<Extract>,
    pub on_error: OnError,
    pub line: usize,
    /// 执行器内部脱糖标记（**解析器不产生**）：`serve:` 阶段由执行器
    /// （`pkg/recipe.rs::send_recipe`）展开为扁平步骤序列时附加——同一阶段的
    /// 全部步骤共享同一 [`LoopCtx`]，`first`/`last` 标记块边界（闸门/回跳点）；
    /// 普通步骤（含 serve handler 内的步骤条目原样克隆）为 None。
    pub loop_ctx: Option<LoopCtx>,
}

/// 解析后的配方。
#[derive(Debug, Clone)]
pub struct Recipe {
    pub path: PathBuf,
    pub globals: Vec<GlobalDecl>,
    pub items: Vec<RecipeItem>,
}

/// 解析 .pktl 配方文件。`validate_fields`：是否在解析期校验 `from:` 的层/字段名
/// （执行器复用 pkg.rs 的 sniffer 字段集；`--eng` 概览同样校验）。
pub fn parse(path: &Path) -> anyhow::Result<Recipe> {
    let src = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            t!("engine.parse_read_fail", path = path.display(), err = e)
        )
    })?;
    parse_text(&src, path)
}

/// 解析配方文本（LSP 内存文档用）：`path` 供相对 packet 路径解析、Recipe.path
/// 与错误展示（行号化错误由 parse_text 内部统一生成）。
pub fn parse_text(src: &str, path: &Path) -> anyhow::Result<Recipe> {
    let mut recipe = Recipe {
        path: path.to_path_buf(),
        globals: Vec::new(),
        items: Vec::new(),
    };
    let lines: Vec<&str> = src.lines().collect();
    let mut i = 0usize;
    let mut in_global = false;
    let mut in_recipe = false;
    let mut cur_global: Option<GlobalBuf> = None;

    while i < lines.len() {
        let line_no = i + 1;
        let raw = strip_comment(lines[i]);
        i += 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent == 0 {
            if trimmed == "global:" || trimmed == "recipe:" {
                cur_global = None;
                in_global = trimmed == "global:";
                in_recipe = trimmed == "recipe:";
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("- ") {
                let rest = rest.trim();
                if in_global {
                    // `- name: X` / `- X` / `- X=v` 三种形态（见 parse_global_item）
                    let (name, inline_init) = parse_global_item(rest, line_no)?;
                    if recipe.globals.iter().any(|g| g.name == name) {
                        return Err(err(line_no, t!("engine.parse_global_dup", name = name)));
                    }
                    cur_global = Some(GlobalBuf {
                        name: name.clone(),
                        line: line_no,
                        has_inline_init: inline_init.is_some(),
                    });
                    recipe.globals.push(GlobalDecl {
                        name,
                        init: inline_init,
                        line: line_no,
                    });
                    continue;
                }
                if in_recipe {
                    // 配方条目：serve 阶段项或步骤项（各自消费自己的缩进块）
                    if let Some(serve_rest) = rest.strip_prefix("serve:") {
                        if !serve_rest.trim().is_empty() {
                            return Err(err(line_no, t!("engine.parse_serve_inline")));
                        }
                        let serve = parse_serve_body(&lines, &mut i, path, line_no, indent)?;
                        recipe.items.push(RecipeItem::Serve(serve));
                        continue;
                    }
                    if rest.starts_with("on_recv:") {
                        return Err(err(line_no, t!("engine.parse_on_recv_top")));
                    }
                    let step = parse_step_block(&lines, &mut i, path, rest, line_no, 0)?;
                    recipe.items.push(RecipeItem::Step(step));
                    continue;
                }
                return Err(err(line_no, t!("engine.parse_list_outside")));
            }
            return Err(err(
                line_no,
                t!("engine.parse_expect_section", trimmed = trimmed),
            ));
        }
        // ── 缩进行 ──
        if in_global {
            let (key, val) = split_kv(trimmed, line_no)?;
            if key != "init" {
                return Err(err(line_no, t!("engine.parse_global_only_init", key = key)));
            }
            let Some(gb) = cur_global.as_ref() else {
                return Err(err(line_no, t!("engine.parse_init_after_name")));
            };
            if gb.has_inline_init {
                return Err(err(
                    line_no,
                    t!("engine.parse_init_inline_conflict", name = gb.name),
                ));
            }
            if val.trim().is_empty() {
                return Err(err(line_no, t!("engine.parse_init_empty")));
            }
            let v = parse_init_value(val, line_no)?;
            let g = recipe
                .globals
                .iter_mut()
                .find(|g| g.name == gb.name && g.line == gb.line)
                .expect("已压入 global 项");
            g.init = Some(v);
            continue;
        }
        return Err(err(line_no, t!("engine.parse_indent_outside")));
    }
    if recipe.items.is_empty() {
        return Err(anyhow::anyhow!(
            "{}",
            t!("engine.parse_no_steps", path = path.display())
        ));
    }
    Ok(recipe)
}

/// 步骤项块：`- ` 条目行 + 后续缩进选项/提取行（缩进 > item_indent 归本条目，
/// indent <= item_indent 结束）。顶层（item_indent=0）与 serve handler 内共用。
fn parse_step_block(
    lines: &[&str],
    i: &mut usize,
    path: &Path,
    first_rest: &str,
    first_line_no: usize,
    item_indent: usize,
) -> anyhow::Result<Step> {
    let pkg = parse_step_item(first_rest, first_line_no, path)?;
    let mut buf = StepBuf {
        pkg,
        wait: None,
        on_timeout: None,
        count: None,
        delay: None,
        raw: None,
        params: Vec::new(),
        extract: Vec::new(),
        on_error: OnError::Stop,
        line: first_line_no,
    };
    let mut in_extract = false;
    let mut extract_buf: Option<ExtractBuf> = None;
    while *i < lines.len() {
        let line_no = *i + 1;
        let raw = strip_comment(lines[*i]);
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            *i += 1;
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent <= item_indent {
            break;
        }
        *i += 1;
        step_line(
            &mut buf,
            trimmed,
            line_no,
            path,
            &mut in_extract,
            &mut extract_buf,
        )?;
    }
    if let Some(b) = extract_buf {
        buf.extract.push(b.finish()?);
    }
    buf.finish()
}

/// serve 阶段块：`- serve:` 行已消费。选项 max/until/delay/rules；`- ` 行在
/// until: 之后 = 谓词；rules: 之后进入规则列表。缩进 <= serve_indent 结束阶段。
fn parse_serve_body(
    lines: &[&str],
    i: &mut usize,
    path: &Path,
    line_no: usize,
    serve_indent: usize,
) -> anyhow::Result<Serve> {
    let mut max: Option<usize> = None;
    let mut delay: Option<f64> = None;
    let mut until: Vec<(String, usize)> = Vec::new();
    let mut in_until = false;
    let mut rules: Vec<ServeRule> = Vec::new();
    let mut in_rules = false;
    let mut mismatch: Option<Vec<ServeItem>> = None;
    let mut in_mismatch = false;
    let mut rule_item_indent = 0usize;
    let mut cur_rule: Option<RuleBuf> = None;
    let mut rule_in_extract = false;
    let mut rule_extract_buf: Option<ExtractBuf> = None;
    let mut handler_seen = false;
    while *i < lines.len() {
        let ln = *i + 1;
        let raw = strip_comment(lines[*i]);
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            *i += 1;
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent <= serve_indent {
            break;
        }
        if !in_rules {
            // ── 阶段选项模式 ──
            *i += 1;
            if let Some(pred) = trimmed.strip_prefix("- ") {
                if in_mismatch {
                    // on_mismatch 段条目：步骤 / 嵌套 on_recv（语法与 handler
                    // 一致；条目缩进 = 各条目自身缩进，键行（rules: 等）自然
                    // 退出段——parse_step_block/on_recv_body 消费条目整块）
                    let item_indent = indent;
                    if let Some(onrecv_rest) = pred.strip_prefix("on_recv:") {
                        if !onrecv_rest.trim().is_empty() {
                            return Err(err(ln, t!("engine.parse_on_recv_inline")));
                        }
                        *i += 1;
                        let onrecv = parse_on_recv_body(lines, i, path, ln, item_indent, 1)?;
                        mismatch
                            .get_or_insert_with(Vec::new)
                            .push(ServeItem::OnRecv(Box::new(onrecv)));
                    } else {
                        let step = parse_step_block(lines, i, path, pred.trim(), ln, item_indent)?;
                        mismatch
                            .get_or_insert_with(Vec::new)
                            .push(ServeItem::Step(step));
                    }
                    continue;
                }
                if !in_until {
                    return Err(err(ln, t!("engine.parse_serve_item_no_until")));
                }
                let pred = pred.trim();
                if pred.is_empty() {
                    return Err(err(ln, t!("engine.parse_until_empty")));
                }
                until.push((pred.to_string(), ln));
                continue;
            }
            let (key, val) = split_kv(trimmed, ln)?;
            match key.as_str() {
                "max" => {
                    // 最多服务轮数：负数 = 无限（与 wait/loop 的显式化约定一致）
                    if val.trim().is_empty() {
                        return Err(err(ln, t!("engine.parse_max_empty")));
                    }
                    let n: i64 = val
                        .trim()
                        .parse()
                        .map_err(|_| err(ln, t!("engine.parse_max_value", val = val)))?;
                    if n == 0 {
                        return Err(err(ln, t!("engine.parse_max_zero")));
                    }
                    max = if n < 0 { None } else { Some(n as usize) };
                }
                "delay" => {
                    if val.trim().is_empty() {
                        return Err(err(ln, t!("engine.parse_delay_empty")));
                    }
                    let secs: f64 = val
                        .parse()
                        .map_err(|_| err(ln, t!("engine.parse_delay_value", val = val)))?;
                    if !secs.is_finite() || secs > crate::MAX_DURATION_SECS {
                        return Err(err(ln, t!("engine.parse_delay_finite", val = val)));
                    }
                    if secs < 0.0 {
                        return Err(err(ln, t!("engine.parse_delay_negative")));
                    }
                    delay = Some(secs);
                }
                "until" => {
                    // 谓词写在后续 `- ` 行（与 sniffer: 同风格）；不接受内联值
                    if !val.is_empty() {
                        return Err(err(ln, t!("engine.parse_until_inline")));
                    }
                    in_until = true;
                }
                "rules" => {
                    if !val.is_empty() {
                        return Err(err(ln, t!("engine.parse_rules_inline")));
                    }
                    if in_mismatch && mismatch.is_none() {
                        return Err(err(ln, t!("engine.parse_mismatch_empty")));
                    }
                    in_rules = true;
                }
                "on_mismatch" => {
                    // 未命中处理段：条目写在后续 `- ` 行（handler 同款语法，
                    // 由上方 opts 模式的 "- " 分支消费）；不接受内联值；
                    // 只允许出现一次
                    if !val.is_empty() {
                        return Err(err(ln, t!("engine.parse_mismatch_inline")));
                    }
                    if in_mismatch {
                        return Err(err(ln, t!("engine.parse_mismatch_dup")));
                    }
                    in_mismatch = true;
                }
                "serve" => return Err(err(ln, t!("engine.parse_serve_nested"))),
                other => {
                    return Err(err(ln, t!("engine.parse_serve_only_opts", other = other)));
                }
            }
            continue;
        }
        // ── rules 模式 ──
        if rule_item_indent == 0 || indent == rule_item_indent {
            // 规则条目行（首个条目确定条目缩进）
            let Some(rest) = trimmed.strip_prefix("- ") else {
                return Err(err(ln, t!("engine.parse_rules_expect_item")));
            };
            if rule_item_indent == 0 {
                rule_item_indent = indent;
            }
            if let Some(rule) = cur_rule.take() {
                rules.push(rule.finish()?);
            }
            *i += 1;
            let pkg = parse_step_item(rest.trim(), ln, path)?;
            cur_rule = Some(RuleBuf {
                packet: pkg,
                raw: None,
                params: Vec::new(),
                extract: Vec::new(),
                handler: Vec::new(),
                line: ln,
            });
            rule_in_extract = false;
            rule_extract_buf = None;
            handler_seen = false;
            continue;
        }
        if indent < rule_item_indent {
            // 退到阶段选项层级——serve 选项必须写在 rules: 之前
            return Err(err(ln, t!("engine.parse_serve_opts_before_rules")));
        }
        // 规则内容行（选项/提取/handler）
        let Some(rule) = cur_rule.as_mut() else {
            return Err(err(ln, t!("engine.parse_rules_expect_item")));
        };
        if trimmed == "handler:" || trimmed.starts_with("handler:") {
            let (key, val) = split_kv(trimmed, ln)?;
            if key != "handler" {
                return Err(err(
                    ln,
                    t!("engine.parse_unknown_option", other = "handler"),
                ));
            }
            if !val.is_empty() {
                return Err(err(ln, t!("engine.parse_handler_inline")));
            }
            if handler_seen {
                return Err(err(ln, t!("engine.parse_handler_dup")));
            }
            handler_seen = true;
            *i += 1;
            // 提交挂起的提取项后进入 handler 条目列表
            if let Some(b) = rule_extract_buf.take() {
                rule.extract.push(b.finish()?);
            }
            rule_in_extract = false;
            rule.handler = parse_handler_items(lines, i, path, rule_item_indent, 1)?;
            continue;
        }
        if handler_seen {
            return Err(err(ln, t!("engine.parse_handler_last")));
        }
        *i += 1;
        rule_line(
            rule,
            trimmed,
            ln,
            &mut rule_in_extract,
            &mut rule_extract_buf,
        )?;
    }
    if let Some(rule) = cur_rule.take() {
        rules.push(rule.finish()?);
    }
    if rules.is_empty() {
        return Err(err(line_no, t!("engine.parse_rules_empty")));
    }
    for (pred, ln) in &until {
        parse_until_pred(pred).map_err(|e| {
            err(
                *ln,
                t!("engine.parse_until_pred_fail", pred = pred, err = e),
            )
        })?;
    }
    if in_mismatch && mismatch.is_none() {
        return Err(err(line_no, t!("engine.parse_mismatch_empty")));
    }
    Ok(Serve {
        max,
        until: if until.is_empty() {
            None
        } else {
            Some(until.iter().map(|(p, _)| p.clone()).collect())
        },
        delay,
        rules,
        on_mismatch: mismatch,
        line: line_no,
    })
}

/// serve 规则解析中间态。
struct RuleBuf {
    packet: PathBuf,
    raw: Option<StepRaw>,
    params: Vec<(String, String)>,
    extract: Vec<Extract>,
    handler: Vec<ServeItem>,
    line: usize,
}

impl RuleBuf {
    fn finish(self) -> anyhow::Result<ServeRule> {
        Ok(ServeRule {
            packet: self.packet,
            raw: self.raw,
            params: self.params,
            extract: self.extract,
            handler: self.handler,
            line: self.line,
        })
    }
}

/// 提取行处理（`extract:` 子列表项 `- name:`/`- from:`/`- as:`、from:/as: 续行、
/// 退出提取）。返回 true = 该行已被提取状态机消费；false = 非提取行（挂起项已
/// 提交进 sink，由调用方继续自己的选项匹配）。
fn extract_line(
    trimmed: &str,
    line_no: usize,
    in_extract: &mut bool,
    extract_buf: &mut Option<ExtractBuf>,
    sink: &mut Vec<Extract>,
) -> anyhow::Result<bool> {
    if let Some(rest) = trimmed.strip_prefix("- ") {
        *in_extract = true;
        if let Some(b) = extract_buf.take() {
            sink.push(b.finish()?);
        }
        let (key, val) = split_kv(rest.trim(), line_no)?;
        let mut b = ExtractBuf {
            line: line_no,
            ..Default::default()
        };
        match key.as_str() {
            "name" => b.name = Some(nonempty(val, "name", line_no)?),
            "from" => b.from = Some(parse_from(val, line_no)?),
            "as" => {
                b.as_ = ExtractAs::parse(val, line_no)?;
                b.as_given = true;
            }
            other => {
                return Err(err(line_no, t!("engine.parse_extract_only", other = other)));
            }
        }
        *extract_buf = Some(b);
        return Ok(true);
    }
    if *in_extract {
        // 提取项的续行（from: / as:），或退出提取回到选项模式
        if let Some(b) = extract_buf.as_mut() {
            let (key, val) = split_kv(trimmed, line_no)?;
            match key.as_str() {
                "from" => {
                    b.from = Some(parse_from(val, line_no)?);
                    return Ok(true);
                }
                "as" => {
                    b.as_ = ExtractAs::parse(val, line_no)?;
                    b.as_given = true;
                    return Ok(true);
                }
                _ => {}
            }
        }
        *in_extract = false;
        if let Some(b) = extract_buf.take() {
            sink.push(b.finish()?);
        }
    }
    Ok(false)
}

/// 嵌套 on_recv 最大嵌套层数（规则 handler 内的 on_recv = 第 1 层，超过即
/// 解析报错——深嵌套无实际场景，防解析器/执行器递归失控）。
const MAX_ON_RECV_DEPTH: usize = 8;

/// handler 条目列表（serve 规则 / 嵌套 on_recv 共用）：`handler:` 行之后、缩进
/// 大于 min_indent 的 `- ` 项序列；条目 = 步骤项（整块消费）或嵌套 on_recv 项。
/// 首个条目确定条目缩进，后续条目须一致；选项行更深；缩进 <= min_indent 结束。
fn parse_handler_items(
    lines: &[&str],
    i: &mut usize,
    path: &Path,
    min_indent: usize,
    depth: usize,
) -> anyhow::Result<Vec<ServeItem>> {
    let mut items: Vec<ServeItem> = Vec::new();
    let mut item_indent = 0usize;
    while *i < lines.len() {
        let ln = *i + 1;
        let raw = strip_comment(lines[*i]);
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            *i += 1;
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent <= min_indent {
            break;
        }
        if !(trimmed.starts_with("- ") && (item_indent == 0 || indent == item_indent)) {
            return Err(err(ln, t!("engine.parse_handler_expect_item")));
        }
        if item_indent == 0 {
            item_indent = indent;
        }
        let rest = trimmed["- ".len()..].trim();
        if let Some(onrecv_rest) = rest.strip_prefix("on_recv:") {
            if !onrecv_rest.trim().is_empty() {
                return Err(err(ln, t!("engine.parse_on_recv_inline")));
            }
            if depth > MAX_ON_RECV_DEPTH {
                return Err(err(
                    ln,
                    t!("engine.parse_on_recv_depth", max = MAX_ON_RECV_DEPTH),
                ));
            }
            *i += 1;
            let onrecv = parse_on_recv_body(lines, i, path, ln, item_indent, depth)?;
            items.push(ServeItem::OnRecv(Box::new(onrecv)));
        } else {
            *i += 1;
            let step = parse_step_block(lines, i, path, rest, ln, item_indent)?;
            items.push(ServeItem::Step(step));
        }
    }
    Ok(items)
}

/// 嵌套 on_recv 块：`- on_recv:` 行已消费。选项 packet/raw/params/extract；
/// `handler:` 递归；缩进 <= onrecv_indent 结束（packet 必填、handler: 之后的
/// 选项行非法）。
fn parse_on_recv_body(
    lines: &[&str],
    i: &mut usize,
    path: &Path,
    line_no: usize,
    onrecv_indent: usize,
    level: usize,
) -> anyhow::Result<ServeRule> {
    let mut rule = RuleBuf {
        packet: PathBuf::new(),
        raw: None,
        params: Vec::new(),
        extract: Vec::new(),
        handler: Vec::new(),
        line: line_no,
    };
    let mut in_extract = false;
    let mut extract_buf: Option<ExtractBuf> = None;
    let mut has_packet = false;
    let mut handler_seen = false;
    while *i < lines.len() {
        let ln = *i + 1;
        let raw = strip_comment(lines[*i]);
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            *i += 1;
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent <= onrecv_indent {
            break;
        }
        if trimmed == "handler:" || trimmed.starts_with("handler:") {
            let (key, val) = split_kv(trimmed, ln)?;
            if key != "handler" {
                return Err(err(
                    ln,
                    t!("engine.parse_unknown_option", other = "handler"),
                ));
            }
            if !val.is_empty() {
                return Err(err(ln, t!("engine.parse_handler_inline")));
            }
            if handler_seen {
                return Err(err(ln, t!("engine.parse_handler_dup")));
            }
            handler_seen = true;
            *i += 1;
            if let Some(b) = extract_buf.take() {
                rule.extract.push(b.finish()?);
            }
            in_extract = false;
            rule.handler = parse_handler_items(lines, i, path, onrecv_indent, level + 1)?;
            continue;
        }
        if handler_seen {
            return Err(err(ln, t!("engine.parse_handler_last")));
        }
        *i += 1;
        if let Some(rest) = trimmed.strip_prefix("packet:") {
            let pkg_str = rest.trim();
            if pkg_str.is_empty() {
                return Err(err(ln, t!("engine.parse_step_no_path")));
            }
            rule.packet = resolve_rel(path, pkg_str);
            has_packet = true;
            continue;
        }
        onrecv_line(&mut rule, trimmed, ln, &mut in_extract, &mut extract_buf)?;
    }
    if let Some(b) = extract_buf {
        rule.extract.push(b.finish()?);
    }
    if !has_packet {
        return Err(err(line_no, t!("engine.parse_on_recv_no_packet")));
    }
    rule.finish()
}

/// serve 规则的选项行（raw/params/extract；handler 由调用方拦截处理）。
fn rule_line(
    rule: &mut RuleBuf,
    trimmed: &str,
    line_no: usize,
    in_extract: &mut bool,
    extract_buf: &mut Option<ExtractBuf>,
) -> anyhow::Result<()> {
    if extract_line(trimmed, line_no, in_extract, extract_buf, &mut rule.extract)? {
        return Ok(());
    }
    let (key, val) = split_kv(trimmed, line_no)?;
    match key.as_str() {
        "raw" => rule.raw = Some(parse_step_raw(val, line_no)?),
        "params" => {
            if val.trim().is_empty() {
                return Err(err(line_no, t!("engine.parse_params_empty")));
            }
            for (k, v) in parse_params_list(val, line_no)? {
                if let Some(existing) = rule.params.iter_mut().find(|(ek, _)| *ek == k) {
                    existing.1 = v;
                } else {
                    rule.params.push((k, v));
                }
            }
        }
        "extract" => {
            // 进入提取子列表（extract: 独占一行，后跟 - 项）；内联值非法——
            // 与普通步骤同规则（命中取值写 global，reply./reply.peer. 来源）
            if !val.is_empty() {
                return Err(err(line_no, t!("engine.parse_extract_inline")));
            }
            *in_extract = true;
        }
        "wait" | "on_timeout" | "count" | "delay" | "on_error" => {
            return Err(err(line_no, t!("engine.parse_rule_step_only", key = key)));
        }
        other => {
            return Err(err(
                line_no,
                t!("engine.parse_rule_unknown_option", other = other),
            ));
        }
    }
    Ok(())
}

/// 嵌套 on_recv 的选项行（raw/params/extract；packet 由调用方处理、handler
/// 由调用方拦截）。
fn onrecv_line(
    rule: &mut RuleBuf,
    trimmed: &str,
    line_no: usize,
    in_extract: &mut bool,
    extract_buf: &mut Option<ExtractBuf>,
) -> anyhow::Result<()> {
    if extract_line(trimmed, line_no, in_extract, extract_buf, &mut rule.extract)? {
        return Ok(());
    }
    let (key, val) = split_kv(trimmed, line_no)?;
    match key.as_str() {
        "raw" => rule.raw = Some(parse_step_raw(val, line_no)?),
        "params" => {
            if val.trim().is_empty() {
                return Err(err(line_no, t!("engine.parse_params_empty")));
            }
            for (k, v) in parse_params_list(val, line_no)? {
                if let Some(existing) = rule.params.iter_mut().find(|(ek, _)| *ek == k) {
                    existing.1 = v;
                } else {
                    rule.params.push((k, v));
                }
            }
        }
        "extract" => {
            // 进入提取子列表（extract: 独占一行，后跟 - 项）；内联值非法——
            // 与普通步骤同规则（命中取值写 global，reply./reply.peer. 来源）
            if !val.is_empty() {
                return Err(err(line_no, t!("engine.parse_extract_inline")));
            }
            *in_extract = true;
        }
        "wait" | "on_timeout" | "count" | "delay" | "on_error" => {
            return Err(err(line_no, t!("engine.parse_rule_step_only", key = key)));
        }
        other => {
            return Err(err(
                line_no,
                t!("engine.parse_rule_unknown_option", other = other),
            ));
        }
    }
    Ok(())
}
// ── 解析辅助 ────────────────────────────────────────────────

/// 剥离行内注释：`#` 到行尾截断（双引号字符串内的 `#` 保留，如 `init: "a#b"`）。
/// 整行注释（行首 `#`）剥离后为空行，由调用方跳过。
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

struct StepBuf {
    pkg: PathBuf,
    /// 非负秒数（None = 纯发送）。
    wait: Option<f64>,
    on_timeout: Option<OnTimeout>,
    count: Option<usize>,
    delay: Option<f64>,
    raw: Option<StepRaw>,
    params: Vec<(String, String)>,
    extract: Vec<Extract>,
    on_error: OnError,
    line: usize,
}

impl StepBuf {
    fn finish(self) -> anyhow::Result<Step> {
        Ok(Step {
            pkg: self.pkg,
            wait: self.wait,
            on_timeout: self.on_timeout,
            count: self.count,
            delay: self.delay,
            raw: self.raw,
            params: self.params,
            extract: self.extract,
            on_error: self.on_error,
            line: self.line,
            loop_ctx: None,
        })
    }
}

#[derive(Default)]
struct ExtractBuf {
    name: Option<String>,
    from: Option<FromSpec>,
    as_: ExtractAs,
    as_given: bool,
    line: usize,
}

/// 当前 global 项解析中间态（缩进 `init:` 行的归属与内联标记）。
struct GlobalBuf {
    name: String,
    line: usize,
    /// 已通过 `- 名=值` 内联给出 init（后续 `init:` 行报错，防双写）。
    has_inline_init: bool,
}

impl ExtractBuf {
    fn finish(self) -> anyhow::Result<Extract> {
        let name = self
            .name
            .ok_or_else(|| err(self.line, t!("engine.parse_extract_no_name")))?;
        let from = self
            .from
            .ok_or_else(|| err(self.line, t!("engine.parse_extract_no_from", name = name)))?;
        Ok(Extract {
            name,
            from,
            as_: self.as_,
            as_given: self.as_given,
            line: self.line,
        })
    }
}

/// `key: value` 拆分（value 可含冒号，如 `from: reply.tcp.seq`）。
fn split_kv(s: &str, line: usize) -> anyhow::Result<(String, &str)> {
    let (k, v) = s
        .split_once(':')
        .ok_or_else(|| err(line, t!("engine.parse_kv_syntax", s = s)))?;
    let k = k.trim();
    if k.is_empty() {
        return Err(err(line, t!("engine.parse_kv_empty_key")));
    }
    Ok((k.to_string(), v.trim()))
}

fn nonempty(v: &str, what: &str, line: usize) -> anyhow::Result<String> {
    if v.is_empty() {
        Err(err(line, t!("engine.parse_nonempty", what = what)))
    } else {
        Ok(v.to_string())
    }
}

/// 解析 global 段一项（`- ` 后的内容）→ (名字, 内联 init)。三种形态：
/// - `name: X`——显式名字（init 可选，由缩进 `init:` 行给出）；
/// - `X`——裸声明（无 init）；
/// - `X=v`——一行内联 init（v 与 `init:` 同字面量语法，`parse_init_value`）。
fn parse_global_item(rest: &str, line: usize) -> anyhow::Result<(String, Option<Value>)> {
    if let Some(n) = rest.strip_prefix("name:") {
        let n = n.trim();
        if n.is_empty() {
            return Err(err(line, t!("engine.parse_global_name_missing")));
        }
        return Ok((n.to_string(), None));
    }
    if let Some(eq) = rest.find('=') {
        let name = rest[..eq].trim();
        if name.is_empty() {
            return Err(err(
                line,
                t!("engine.parse_global_bare_missing", rest = rest),
            ));
        }
        let val = rest[eq + 1..].trim();
        if val.is_empty() {
            return Err(err(line, t!("engine.parse_global_init_empty", name = name)));
        }
        return Ok((name.to_string(), Some(parse_init_value(val, line)?)));
    }
    if rest.contains(':') {
        return Err(err(
            line,
            t!("engine.parse_global_item_syntax", rest = rest),
        ));
    }
    if rest.is_empty() {
        return Err(err(line, t!("engine.parse_global_name_missing2")));
    }
    Ok((rest.to_string(), None))
}

/// `from:` 取值来源解析：
/// 1. `reply.<层>.<字段>` 且字段在 sniffer 字段集内 → [`FromSpec::Field`]（直取形态，
///    `as:` 控制形态；保持旧行为）。payload/body/raw 等扩展字段不在 sniffer 集内，
///    走表达式形态（`reply.<层>.<字段>` 叶子在求值时同样可取）。
/// 2. `sent.<层>.<字段>` 同上 → [`FromSpec::SentField`]（取本步发包字段，无需 wait）。
/// 3. 其余 → [`FromSpec::Expr`] 值表达式：`reply.<层>.<字段>` 叶子改写为
///    `reply("层", "字段")` 调用后按 DSL 值表达式解析（可调函数/原语/`+` 运算）。
fn parse_from(v: &str, line: usize) -> anyhow::Result<FromSpec> {
    if v.trim().is_empty() {
        return Err(err(line, t!("engine.parse_from_empty")));
    }
    if let Some((layer, field)) = parse_field_ref(v, "reply.") {
        // 监听对端（listen 步骤的 UDP 监听）：`reply.peer.ip` / `reply.peer.port`——
        // 载荷里没有 udp 头，对端地址来自 socket（peer），供后续步骤回包
        if layer == "peer" {
            if matches!(field.as_str(), "ip" | "port") {
                return Ok(FromSpec::PeerField { field });
            }
            return Err(err(line, t!("engine.parse_peer_field_only", field = field)));
        }
        if let Some(names) = crate::engine::pkg::sniffer_field_names(&layer)
            && names.contains(&field.as_str())
        {
            return Ok(FromSpec::Field { layer, field });
        }
    }
    if let Some((layer, field)) = parse_field_ref(v, "sent.")
        && let Some(names) = crate::engine::pkg::sniffer_field_names(&layer)
        && names.contains(&field.as_str())
    {
        return Ok(FromSpec::SentField { layer, field });
    }
    let rewritten = rewrite_reply_leaves(v);
    let expr = packet_dsl::parser::parse_value_expr(&rewritten)
        .map_err(|d| err(line, t!("engine.parse_expr_fail", err = d)))?;
    Ok(FromSpec::Expr(expr))
}

/// `<prefix><层>.<字段>`（严格两段，层/字段非空且字段不含 `.`）→ Some((层, 字段))。
fn parse_field_ref(v: &str, prefix: &str) -> Option<(String, String)> {
    let rest = v.strip_prefix(prefix)?;
    let (layer, field) = rest.split_once('.')?;
    if layer.is_empty() || field.is_empty() || field.contains('.') {
        return None;
    }
    Some((layer.to_string(), field.to_string()))
}

/// 把表达式里的 `reply.<层>.<字段>` 叶子改写为 `reply("层", "字段")` 调用
/// （字符串字面量内原样保留；`reply(...)` 函数形态原样保留）。
fn rewrite_reply_leaves(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'"' => {
                // 字符串字面量：原样复制到收尾引号（含 \" 转义）
                let start = i;
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        i += 1;
                    }
                    i += 1;
                }
                if i < b.len() {
                    i += 1; // 收尾引号
                }
                out.push_str(&s[start..i]);
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                if &s[start..i] == "reply" && i < b.len() && b[i] == b'.' {
                    // `reply.<层>.<字段>`：层后须紧跟 `.` + 标识符字段
                    if let Some((layer, end1)) = read_ident_at(s, b, i + 1)
                        && end1 < b.len()
                        && b[end1] == b'.'
                        && let Some((field, end2)) = read_ident_at(s, b, end1 + 1)
                    {
                        out.push_str(&format!("reply(\"{layer}\", \"{field}\")"));
                        i = end2;
                        continue;
                    }
                }
                out.push_str(&s[start..i]);
            }
            _ => {
                let ch = s[i..].chars().next().expect("有效 UTF-8");
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    out
}

/// 从字节下标 pos 读一个标识符（`[A-Za-z_][A-Za-z0-9_]*`）→ (标识符, 结束下标)。
/// pos 必须在字符边界（调用方保证：仅在 ASCII 标识符/`.`/`"` 之后调用）。
fn read_ident_at(s: &str, b: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos >= b.len() || !(b[pos].is_ascii_alphabetic() || b[pos] == b'_') {
        return None;
    }
    let mut end = pos + 1;
    while end < b.len() && (b[end].is_ascii_alphanumeric() || b[end] == b'_') {
        end += 1;
    }
    Some((s[pos..end].to_string(), end))
}

/// `params: k=v,k2=v2`（与 `--params` 同格式）。
fn parse_params_list(v: &str, line: usize) -> anyhow::Result<Vec<(String, String)>> {
    let out: Vec<_> = crate::util::parse_kv_pairs(v)
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    if out.is_empty() && !v.trim().is_empty() {
        return Err(err(line, t!("engine.parse_params_value", v = v)));
    }
    Ok(out)
}

/// `raw:` 步骤选项：`true`（开原始发送，网卡继承 CLI `--iface`）/
/// `false`（强制载荷发送，覆盖 CLI `--raw`）/ 网卡名（如 `eth0`，开原始发送并指定网卡；
/// 带引号 `"eth0"` 等价，网卡名里的空格/`#` 用引号包裹）。
fn parse_step_raw(v: &str, line: usize) -> anyhow::Result<StepRaw> {
    let v = v.trim();
    match v {
        "true" | "on" | "yes" => Ok(StepRaw::On { iface: None }),
        "false" | "off" | "no" => Ok(StepRaw::Off),
        "" => Err(err(line, t!("engine.parse_raw_value"))),
        other => {
            let iface = other.trim_matches('"');
            if iface.is_empty() {
                return Err(err(line, t!("engine.parse_raw_iface_empty")));
            }
            Ok(StepRaw::On {
                iface: Some(iface.to_string()),
            })
        }
    }
}

/// `init` 值字面量：字符串 / 十进制 / 0x 十六进制 / 字节列表。
pub fn parse_init_value(s: &str, line: usize) -> anyhow::Result<Value> {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('"') {
        let rest = inner
            .strip_suffix('"')
            .ok_or_else(|| err(line, t!("engine.parse_str_no_quote", s = s)))?;
        return Ok(Value::Str(rest.to_string()));
    }
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len() - 1];
        let mut items = Vec::new();
        for part in inner.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                let v = u64::from_str_radix(hex, 16)
                    .map_err(|_| err(line, t!("engine.parse_hex_byte_bad", part = part)))?;
                if v > 0xFF {
                    return Err(err(line, t!("engine.parse_byte_out_of_range", part = part)));
                }
                items.push(Value::Hex(v));
            } else {
                let v: i64 = part
                    .parse()
                    .map_err(|_| err(line, t!("engine.parse_byte_list_bad", part = part)))?;
                if !(0..=255).contains(&v) {
                    return Err(err(line, t!("engine.parse_byte_out_of_range", part = part)));
                }
                items.push(Value::Int(v));
            }
        }
        return Ok(Value::List(items));
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let v = u64::from_str_radix(hex, 16)
            .map_err(|_| err(line, t!("engine.parse_hex_bad", s = s)))?;
        return Ok(Value::Hex(v));
    }
    if let Ok(v) = s.parse::<i64>() {
        return Ok(Value::Int(v));
    }
    Err(err(line, t!("engine.parse_init_value_bad", s = s)))
}

/// 步骤行处理（顶层步骤与 loop 嵌套步骤共用同一状态机）：提取子列表项
/// （`- name:`/`- from:`/`- as:`）、提取续行、步骤选项键。
fn step_line(
    step: &mut StepBuf,
    trimmed: &str,
    line_no: usize,
    path: &Path,
    in_extract: &mut bool,
    extract_buf: &mut Option<ExtractBuf>,
) -> anyhow::Result<()> {
    // 提取子列表：`- name:` / `- from:` / `- as:` 或以 `- ` 开头的续项
    if let Some(rest) = trimmed.strip_prefix("- ") {
        *in_extract = true;
        // 完成上一个提取项
        if let Some(b) = extract_buf.take() {
            step.extract.push(b.finish()?);
        }
        let (key, val) = split_kv(rest.trim(), line_no)?;
        let mut b = ExtractBuf {
            line: line_no,
            ..Default::default()
        };
        match key.as_str() {
            "name" => b.name = Some(nonempty(val, "name", line_no)?),
            "from" => b.from = Some(parse_from(val, line_no)?),
            "as" => {
                b.as_ = ExtractAs::parse(val, line_no)?;
                b.as_given = true;
            }
            other => {
                return Err(err(line_no, t!("engine.parse_extract_only", other = other)));
            }
        }
        *extract_buf = Some(b);
        return Ok(());
    }
    if *in_extract {
        // 提取项的续行（from: / as:），或退出提取回到步骤选项
        if let Some(b) = extract_buf.as_mut() {
            let (key, val) = split_kv(trimmed, line_no)?;
            match key.as_str() {
                "from" => {
                    b.from = Some(parse_from(val, line_no)?);
                    return Ok(());
                }
                "as" => {
                    b.as_ = ExtractAs::parse(val, line_no)?;
                    b.as_given = true;
                    return Ok(());
                }
                _ => {}
            }
        }
        // 非提取续行 → 提交当前提取项，回到步骤选项处理
        *in_extract = false;
        if let Some(b) = extract_buf.take() {
            step.extract.push(b.finish()?);
        }
    }
    // 步骤选项行
    let (key, val) = split_kv(trimmed, line_no)?;
    match key.as_str() {
        "wait" => {
            // 非负秒数 = 发送后等一个匹配应答；不写 = 纯发送。负数/空值非法——
            // 持续监听已由 serve: 阶段接管（负数原为持续监听写法）
            if val.trim().is_empty() {
                return Err(err(line_no, t!("engine.parse_wait_empty")));
            }
            let secs: f64 = val
                .trim()
                .parse()
                .map_err(|_| err(line_no, t!("engine.parse_wait_value", val = val)))?;
            // NaN/±inf/过大值会使 Duration::from_secs_f64 panic，先拒绝
            if !secs.is_finite() || secs > crate::MAX_DURATION_SECS {
                return Err(err(line_no, t!("engine.parse_wait_finite", val = val)));
            }
            if secs < 0.0 {
                return Err(err(line_no, t!("engine.parse_wait_listen_removed")));
            }
            step.wait = Some(secs);
        }
        "delay" => {
            if val.trim().is_empty() {
                return Err(err(line_no, t!("engine.parse_delay_empty")));
            }
            let secs: f64 = val
                .parse()
                .map_err(|_| err(line_no, t!("engine.parse_delay_value", val = val)))?;
            // NaN/±inf/过大值会使 Duration::from_secs_f64 panic，先拒绝
            if !secs.is_finite() || secs > crate::MAX_DURATION_SECS {
                return Err(err(line_no, t!("engine.parse_delay_finite", val = val)));
            }
            if secs < 0.0 {
                return Err(err(line_no, t!("engine.parse_delay_negative")));
            }
            step.delay = Some(secs);
        }
        "params" => {
            if val.trim().is_empty() {
                return Err(err(line_no, t!("engine.parse_params_empty")));
            }
            let pairs = parse_params_list(val, line_no)?;
            for (k, v) in pairs {
                if let Some(existing) = step.params.iter_mut().find(|(ek, _)| *ek == k) {
                    existing.1 = v;
                } else {
                    step.params.push((k, v));
                }
            }
        }
        "raw" => {
            step.raw = Some(parse_step_raw(val, line_no)?);
        }
        "on_timeout" => {
            let v = val.trim();
            let on_timeout = if let Some(rest) = v.strip_prefix("retry") {
                // `retry` / `retry N`：重发当前步骤的包（次数默认 1）
                let rest = rest.trim();
                let n = if rest.is_empty() {
                    1
                } else {
                    rest.parse::<usize>()
                        .map_err(|_| err(line_no, t!("engine.parse_retry_count", n = rest)))?
                };
                if n == 0 {
                    return Err(err(line_no, t!("engine.parse_retry_zero")));
                }
                OnTimeout::Retry(n)
            } else {
                if v.is_empty() {
                    return Err(err(line_no, t!("engine.parse_on_timeout_path")));
                }
                OnTimeout::Packet(resolve_rel(path, v))
            };
            step.on_timeout = Some(on_timeout);
        }
        "count" => {
            if val.trim().is_empty() {
                return Err(err(line_no, t!("engine.parse_count_empty")));
            }
            let n: usize = val
                .trim()
                .parse()
                .map_err(|_| err(line_no, t!("engine.parse_count_value", val = val)))?;
            if n == 0 {
                return Err(err(line_no, t!("engine.parse_count_zero")));
            }
            step.count = Some(n);
        }
        "on_error" => {
            if val.trim().is_empty() {
                return Err(err(line_no, t!("engine.parse_on_error_empty")));
            }
            step.on_error = match val {
                "stop" => OnError::Stop,
                "continue" => OnError::Continue,
                other => {
                    return Err(err(
                        line_no,
                        t!("engine.parse_on_error_value", other = other),
                    ));
                }
            };
        }
        "extract" => {
            // 进入提取子列表（extract: 独占一行，后跟 - 项）；内联值非法——
            // 列表容器的条目只能写在后续 `- ` 行（与 until:/steps: 同规则）
            if !val.is_empty() {
                return Err(err(line_no, t!("engine.parse_extract_inline")));
            }
            *in_extract = true;
        }
        // serve 语法键不得出现在普通步骤上
        "until" | "steps" | "loop" | "serve" | "on_recv" | "rules" | "max" | "handler" => {
            return Err(err(line_no, t!("engine.parse_serve_only_key", key = key)));
        }
        other => {
            return Err(err(
                line_no,
                t!("engine.parse_unknown_option", other = other),
            ));
        }
    }
    Ok(())
}

/// 步骤项（`- ` 后内容）→ .pkt 路径：`packet: 文件` 或裸文件名（相对 .pktl 所在
/// 目录解析）；`pkg:` 报改名提示，含冒号的裸名报语法错误。顶层与 loop 嵌套共用。
fn parse_step_item(rest: &str, line_no: usize, path: &Path) -> anyhow::Result<PathBuf> {
    let pkg_str = match rest.strip_prefix("packet:") {
        Some(p) => p.trim().to_string(),
        None => {
            if rest.starts_with("pkg:") {
                return Err(err(line_no, t!("engine.parse_pkg_renamed")));
            }
            if rest.contains(':') {
                return Err(err(line_no, t!("engine.parse_step_syntax", rest = rest)));
            }
            rest.to_string()
        }
    };
    if pkg_str.is_empty() {
        return Err(err(line_no, t!("engine.parse_step_no_path")));
    }
    Ok(resolve_rel(path, &pkg_str))
}

/// `until:` 单条谓词语法解析（sniffer 同款：`match 层(条件, ...)` / and/or/not）。
/// 合成只含 `sniffer:` 段的源文本复用 packet-dsl 解析器——仅语法校验；执行期
/// `Matcher::build`（pkg/recipe.rs）做层/字段名与值语义检查。
pub fn parse_until_pred(pred: &str) -> Result<packet_dsl::ast::SnifferPred, String> {
    let text = format!("sniffer:\n- {pred}\n");
    let ast = packet_dsl::parser::parse_ast(&text).map_err(|d| d.to_string())?;
    ast.stmts
        .into_iter()
        .find_map(|s| match s {
            packet_dsl::ast::Stmt::Sniffer(spec) => Some(spec),
            _ => None,
        })
        .and_then(|spec| spec.clauses.into_iter().next())
        .ok_or_else(|| "no predicate parsed".to_string())
}
/// 相对 .pktl 所在目录解析路径（绝对路径原样）。
fn resolve_rel(recipe: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        recipe.parent().unwrap_or_else(|| Path::new(".")).join(p)
    }
}

/// 行号化错误。
fn err(line: usize, msg: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{}", t!("engine.parse_err_prefix", line = line, msg = msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `until:` 谓词独立语法解析（合成 `sniffer:` 源文本复用 packet-dsl 解析器）。
    #[test]
    fn until_pred_parses_standalone() {
        // 单条 match 子句
        let p = parse_until_pred("match icmp(type=8)").expect("match 子句可解析");
        assert!(matches!(p, packet_dsl::ast::SnifferPred::Clause(_)));
        // 组合谓词 and/not
        let p = parse_until_pred("and(match icmp(type=0), not(match udp(dport=9)))")
            .expect("组合谓词可解析");
        assert!(matches!(p, packet_dsl::ast::SnifferPred::And(_)));
        // 语法错误报错
        assert!(parse_until_pred("match icmp(== 8)").is_err());
        assert!(parse_until_pred("icmp.type == 0").is_err());
    }

    /// serve 阶段解析：max/delay/until 谓词 + 规则（extract/handler 步骤选项完整）
    /// 与阶段后的普通步骤条目（条目级 items 结构；LoopCtx 由执行器脱糖附加，
    /// 解析器不产生）。
    #[test]
    fn recipe_parse_serve_block() {
        let src = r#"
global:
- tid

recipe:
- serve:
  max: 3
  delay: 0.5
  until:
  - match icmp(type=0)
  - match udp(dport=9)
  rules:
  - packet: listen.pkt
    extract:
    - name: tid
      from: reply.icmp.id
    handler:
    - packet: reply.pkt
      raw: true
- packet: tail.pkt
"#;
        let dir = std::env::temp_dir().join(format!("prping-serve-parse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("flow.pktl");
        std::fs::write(&path, src).unwrap();
        let r = parse(&path).expect("serve 配方解析成功");
        assert_eq!(r.items.len(), 2, "serve 阶段 + 阶段后 1 步");
        let RecipeItem::Serve(serve) = &r.items[0] else {
            panic!("条目 0 应为 serve 阶段");
        };
        assert_eq!(serve.max, Some(3), "max = 服务轮数上限");
        assert_eq!(serve.delay, Some(0.5));
        assert_eq!(
            serve.until.as_deref(),
            Some(
                &[
                    "match icmp(type=0)".to_string(),
                    "match udp(dport=9)".to_string()
                ][..]
            )
        );
        assert_eq!(serve.rules.len(), 1);
        let rule = &serve.rules[0];
        assert_eq!(rule.packet.file_name().unwrap(), "listen.pkt");
        assert_eq!(rule.extract.len(), 1, "规则 extract 完整解析");
        assert_eq!(rule.extract[0].name, "tid");
        assert_eq!(rule.handler.len(), 1, "handler 条目完整解析");
        let ServeItem::Step(reply) = &rule.handler[0] else {
            panic!("handler 条目应为步骤");
        };
        assert_eq!(reply.pkg.file_name().unwrap(), "reply.pkt");
        assert_eq!(
            reply.raw,
            Some(StepRaw::On { iface: None }),
            "handler 步骤选项完整解析"
        );
        let RecipeItem::Step(tail) = &r.items[1] else {
            panic!("条目 1 应为普通步骤");
        };
        assert_eq!(tail.pkg.file_name().unwrap(), "tail.pkt");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 嵌套 on_recv 解析：handler 内 `- on_recv:` 项（packet/raw/extract/handler
    /// 递归完整解析）。
    #[test]
    fn recipe_parse_serve_on_recv() {
        let src = r#"
recipe:
- serve:
  rules:
  - packet: listen.pkt
    handler:
    - packet: hello.pkt
    - on_recv:
      packet: again.pkt
      raw: true
      extract:
      - name: x
        from: reply.dns.id
      handler:
      - packet: final.pkt
"#;
        let dir = std::env::temp_dir().join(format!("prping-onrecv-parse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("flow.pktl");
        std::fs::write(&path, src).unwrap();
        let r = parse(&path).expect("嵌套 on_recv 解析成功");
        let RecipeItem::Serve(serve) = &r.items[0] else {
            panic!("条目 0 应为 serve 阶段");
        };
        assert_eq!(serve.rules.len(), 1);
        let rule = &serve.rules[0];
        assert_eq!(rule.handler.len(), 2, "普通步骤 + on_recv 条目");
        let ServeItem::Step(hello) = &rule.handler[0] else {
            panic!("handler[0] 应为步骤");
        };
        assert_eq!(hello.pkg.file_name().unwrap(), "hello.pkt");
        let ServeItem::OnRecv(nested) = &rule.handler[1] else {
            panic!("handler[1] 应为嵌套 on_recv");
        };
        assert_eq!(nested.packet.file_name().unwrap(), "again.pkt");
        assert_eq!(nested.raw, Some(StepRaw::On { iface: None }));
        assert_eq!(nested.extract.len(), 1, "on_recv extract 完整解析");
        assert_eq!(nested.extract[0].name, "x");
        assert_eq!(nested.handler.len(), 1);
        let ServeItem::Step(final_step) = &nested.handler[0] else {
            panic!("on_recv handler 条目应为步骤");
        };
        assert_eq!(final_step.pkg.file_name().unwrap(), "final.pkt");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `max:` 负数 = 无限服务（Serve.max = None；空值非法——报错见
    /// recipe_parse_serve_errors）。
    #[test]
    fn recipe_parse_serve_max_negative() {
        for (tag, body) in [
            (
                "neg1",
                "recipe:\n- serve:\n  max: -1\n  rules:\n  - a.pkt\n",
            ),
            (
                "neg5",
                "recipe:\n- serve:\n  max: -5\n  rules:\n  - a.pkt\n",
            ),
        ] {
            let dir =
                std::env::temp_dir().join(format!("prping-serve-inf-{}-{tag}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("flow.pktl");
            std::fs::write(&path, body).unwrap();
            let r = parse(&path).unwrap_or_else(|e| panic!("{tag}: 无限 serve 解析成功: {e}"));
            assert_eq!(r.items.len(), 1);
            let RecipeItem::Serve(serve) = &r.items[0] else {
                panic!("{tag}: 应为 serve 阶段");
            };
            assert_eq!(serve.max, None, "{tag}: 负数 = 无限");
            assert_eq!(serve.rules.len(), 1, "{tag}: 裸文件名规则项");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// serve 阶段解析错误路径：max 0/非法/空、缺 rules、until 内联、until 前置
    /// `- ` 行、普通步骤写 serve 选项、未知 serve 选项、规则未知选项、规则写
    /// 步骤专属选项、until 谓词语法错误、顶层 on_recv、嵌套 serve。
    #[test]
    fn recipe_parse_serve_errors() {
        let dir = std::env::temp_dir().join(format!("prping-serve-err-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let parse = |name: &str, body: &str| {
            let path = dir.join(name);
            std::fs::write(&path, body).unwrap();
            parse(&path).expect_err("预期解析失败").to_string()
        };
        // max 0 / 非法 / 空
        let e = parse(
            "zero.pktl",
            "recipe:\n- serve:\n  max: 0\n  rules:\n  - a.pkt\n",
        );
        assert!(e.contains("max"), "{e}");
        let e = parse(
            "bad.pktl",
            "recipe:\n- serve:\n  max: abc\n  rules:\n  - a.pkt\n",
        );
        assert!(e.contains("max"), "{e}");
        let e = parse(
            "maxempty.pktl",
            "recipe:\n- serve:\n  max:\n  rules:\n  - a.pkt\n",
        );
        assert!(e.contains("max"), "{e}");
        // 缺 rules（下一个顶层项直接收尾 serve 阶段）
        let e = parse("norules.pktl", "recipe:\n- serve:\n- packet: a.pkt\n");
        assert!(e.contains("rules"), "{e}");
        // until 内联值不接受
        let e = parse(
            "untilinline.pktl",
            "recipe:\n- serve:\n  until: match icmp(type=0)\n  rules:\n  - a.pkt\n",
        );
        assert!(e.contains("until"), "{e}");
        // until: 之前的 `- ` 行（未声明 until 就出现谓词项）
        let e = parse(
            "itemfirst.pktl",
            "recipe:\n- serve:\n  - match icmp(type=0)\n  rules:\n  - a.pkt\n",
        );
        assert!(e.contains("until"), "{e}");
        // 普通步骤写 until / rules（serve 专用键）
        let e = parse("untiltop.pktl", "recipe:\n- packet: a.pkt\n  until:\n");
        assert!(e.contains("serve"), "{e}");
        let e = parse("rulestop.pktl", "recipe:\n- packet: a.pkt\n  rules:\n");
        assert!(e.contains("serve"), "{e}");
        // 未知 serve 选项
        let e = parse(
            "serveopt.pktl",
            "recipe:\n- serve:\n  wait: 1\n  rules:\n  - a.pkt\n",
        );
        assert!(e.contains("serve"), "{e}");
        // 规则未知选项 / 规则写步骤专属选项（wait/on_timeout/count/delay/on_error）
        let e = parse(
            "ruleopt.pktl",
            "recipe:\n- serve:\n  rules:\n  - a.pkt\n    foo: 1\n",
        );
        assert!(e.contains("serve"), "{e}");
        let e = parse(
            "rulewait.pktl",
            "recipe:\n- serve:\n  rules:\n  - a.pkt\n    wait: 1\n",
        );
        assert!(e.contains("serve"), "{e}");
        // until 谓词语法错误（解析期预检）
        let e = parse(
            "badpred.pktl",
            "recipe:\n- serve:\n  until:\n  - icmp.type == 0\n  rules:\n  - a.pkt\n",
        );
        assert!(e.contains("until") || e.contains("match"), "{e}");
        // 顶层 on_recv
        let e = parse("onrecvtop.pktl", "recipe:\n- on_recv:\n  packet: a.pkt\n");
        assert!(e.contains("on_recv"), "{e}");
        // 嵌套 serve 阶段
        let e = parse(
            "nested.pktl",
            "recipe:\n- serve:\n  serve:\n  rules:\n  - a.pkt\n",
        );
        assert!(e.contains("serve"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// serve on_mismatch 段解析：条目语法与 handler 一致（步骤/嵌套 on_recv）；
    /// 内联值 / 重复段非法。
    #[test]
    fn recipe_parse_serve_mismatch() {
        let src = r#"
recipe:
- serve:
  max: 2
  on_mismatch:
  - packet: warn.pkt
    params: code=44
  rules:
  - packet: listen.pkt
    handler:
    - packet: reply.pkt
"#;
        let dir =
            std::env::temp_dir().join(format!("prping-mismatch-parse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("flow.pktl");
        std::fs::write(&path, src).unwrap();
        let r = parse(&path).expect("on_mismatch 解析成功");
        let RecipeItem::Serve(serve) = &r.items[0] else {
            panic!("条目 0 应为 serve 阶段");
        };
        let Some(m) = &serve.on_mismatch else {
            panic!("on_mismatch 段应解析");
        };
        assert_eq!(m.len(), 1);
        let ServeItem::Step(warn) = &m[0] else {
            panic!("on_mismatch 条目应为步骤");
        };
        assert_eq!(warn.pkg.file_name().unwrap(), "warn.pkt");
        assert_eq!(warn.params, vec![("code".to_string(), "44".to_string())]);
        // 内联值非法
        let bad = "recipe:\n- serve:\n  on_mismatch: warn.pkt\n  rules:\n  - packet: a.pkt\n";
        let path = dir.join("bad1.pktl");
        std::fs::write(&path, bad).unwrap();
        let e = parse(&path).unwrap_err().to_string();
        assert!(e.contains("on_mismatch"), "{e}");
        // 重复段非法
        let dup = "recipe:\n- serve:\n  on_mismatch:\n  - packet: w.pkt\n  on_mismatch:\n  - packet: w2.pkt\n  rules:\n  - packet: a.pkt\n";
        let path = dir.join("bad2.pktl");
        std::fs::write(&path, dup).unwrap();
        let e = parse(&path).unwrap_err().to_string();
        assert!(e.contains("on_mismatch"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 嵌套 on_recv 深度限制：第 8 层允许、第 9 层解析报错。
    #[test]
    fn recipe_parse_on_recv_depth() {
        let nested = |levels: usize| -> String {
            let mut src =
                String::from("recipe:\n- serve:\n  rules:\n  - packet: l0.pkt\n    handler:\n");
            let mut ind = "    ".to_string();
            for l in 1..=levels {
                src.push_str(&format!("{ind}- on_recv:\n{ind}  packet: l{l}.pkt\n"));
                if l < levels {
                    src.push_str(&format!("{ind}  handler:\n"));
                    ind.push_str("  ");
                }
            }
            src
        };
        let dir = std::env::temp_dir().join(format!("prping-onrecv-depth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 8 层：通过（逐层校验 packet 名）
        let path = dir.join("ok.pktl");
        std::fs::write(&path, nested(8)).unwrap();
        let r = parse(&path).expect("8 层嵌套应解析成功");
        let RecipeItem::Serve(serve) = &r.items[0] else {
            panic!("条目 0 应为 serve 阶段");
        };
        let mut rule = &serve.rules[0];
        for l in 1..=8usize {
            assert_eq!(rule.handler.len(), 1, "第 {l} 层 handler 只有 on_recv 条目");
            let ServeItem::OnRecv(nested) = &rule.handler[0] else {
                panic!("第 {l} 层应为 on_recv");
            };
            assert_eq!(
                nested.packet.file_name().unwrap().to_string_lossy(),
                format!("l{l}.pkt"),
                "第 {l} 层 packet"
            );
            rule = nested;
        }
        // 9 层：报错
        let path = dir.join("deep.pktl");
        std::fs::write(&path, nested(9)).unwrap();
        let e = parse(&path).unwrap_err().to_string();
        assert!(e.contains("on_recv"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
