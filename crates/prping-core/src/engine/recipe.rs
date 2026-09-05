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
//! - 步骤选项：`wait:`（**与 CLI `--wait` 同语义**——`wait: -1`（任意负数）= 无限等待
//!   （等价 CLI 裸 `--wait` / 负数 `--wait`）：本步不发送、用 .pkt 的 sniffer 匹配
//!   外部到达的包，命中后配方继续（触发后续步骤发包），匹配包供 `extract` 的 `reply.`
//!   来源取值（`raw: true|网卡名` 走链路层监听，否则 UDP 数据报监听）；`wait: 秒数` =
//!   发送后等一个匹配应答（等价 CLI `--wait SECS`）；不写 = 纯发送。**空值非法**：
//!   字段要么不写、要么写值（空值易误读语义，解析期报错并提示 `wait: -1`），
//!   `on_timeout: 文件`（**wait 超时处理**：`wait: 秒数` 超时未收到匹配应答时，
//!   打印超时信息并**发送该 .pkt**（发其它包），步骤继续）、`delay: 秒数`（步骤开始前
//!   等待——非首步生效，pcap 转码配方用；响应 Ctrl+C 提前结束）、
//!   `params: k=v,k2=v2`（静态字符串，追加到 `--params` 同名覆盖）、
//!   `raw: true|false|网卡名`（覆盖 `--raw`：`true` 开原始发送、网卡名 = 开原始发送并
//!   指定网卡、`false` 强制载荷发送）、`extract:`（子列表 `- name:` + `from:` + `as:`）、
//!   `on_error: stop|continue`。
//! - **loop 块**（`- loop: N`，N 为负数 = 无限，与 CLI 负数 `--wait` 同语义；空值
//!   非法，无限循环写 `loop: -1`）：包裹
//!   一组嵌套步骤（`steps:` 后跟缩进 `- ` 步骤项），每轮完整执行块内步骤——服务端
//!   "监听→extract→回应"循环编排。
//!   `until:` 谓词列表（sniffer 同款 `match 层(条件, ...)` / and/or/not，顶层多条
//!   = 隐式 OR）任一命中 → 本轮结束后收工；`delay: 秒` 轮间延迟（第 2 轮起）；
//!   `loop: N` 计次（与 until 先到先退）。块内 Ctrl+C 优雅收工（打印统计、退出码
//!   0）。谓词可用 `global(...)`（每轮重建 Matcher，取上一轮 extract 最新值）。
//!   解析后块内步骤**平铺**进 `Recipe.steps`（每步携带 [`LoopCtx`]，执行器按
//!   `first`/`last` 定位块边界循环回跳）。
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

/// 步骤所属 loop 块的上下文（解析期附加到块内**每个**步骤）。
///
/// `Recipe.steps` 保持**扁平**（消费方无需感知嵌套）：loop 块解析时展开为连续的
/// 步骤序列，每步携带同一 [`LoopCtx`]，执行器按 `first`/`last` 定位块边界、
/// 循环回跳（见 `pkg/recipe.rs::send_recipe`）。
#[derive(Debug, Clone, PartialEq)]
pub struct LoopCtx {
    /// loop 块序号（解析顺序，0 起；同块内步骤相同）。
    pub id: usize,
    /// 循环次数；None = 无限（`loop: 负数`，与 CLI 负数 `--wait` 同语义——直到
    /// `until` 命中或 Ctrl+C 优雅收工；空值非法，无限写 `loop: -1`）。
    pub count: Option<usize>,
    /// `until:` 谓词文本列表（sniffer 同款语法：`match 层(条件, ...)` / and/or/not，
    /// 顶层多条 = 隐式 OR）。任一谓词命中即满足；执行期每轮构建 Matcher
    /// （`global(...)` 取上一轮 extract 的最新值）。
    pub until: Option<Vec<String>>,
    /// 轮间延迟秒数（第 2 轮起、块首步执行前生效；响应 Ctrl+C 提前收工）。
    pub delay: Option<f64>,
    /// 块内首步（执行器在此做迭代闸门：次数 / until / Ctrl+C）。
    pub first: bool,
    /// 块内末步（块边界 = 末步下标 + 1）。
    pub last: bool,
    /// loop 项行号（1 基，报错定位）。
    pub line: usize,
}

/// 配方步骤。
#[derive(Debug, Clone)]
pub struct Step {
    /// .pkt 文件（相对 .pktl 所在目录解析）。
    pub pkg: PathBuf,
    /// 与 CLI `--wait` 同语义：`wait: -1`（任意负数）= 无限等待（本步不发送，
    /// 用 .pkt 的 sniffer 匹配外部到达的包，命中后配方继续触发后续步骤发包）；
    /// `wait: 秒数` = 发送后等一个匹配应答；None = 纯发送（继承 CLI `--wait SECS` 作默认）。
    /// 空值非法（字段要么不写、要么写值；解析期报错提示 `wait: -1`）。
    pub wait: Option<crate::engine::pkg::WaitMode>,
    /// **wait 超时处理**：`wait: 秒数` 超时未收到匹配应答时——`retry [N]` 重发
    /// 当前步骤的包（每次重新 wait），或发送备选 .pkt（发其它包）；步骤继续。
    pub on_timeout: Option<OnTimeout>,
    /// **每个包重复发送次数**（`count: N`，覆盖 CLI `--count`；默认继承）。
    pub count: Option<usize>,
    /// 步骤开始前的延迟秒数（第 1 步忽略；pcap 转码配方携带捕获间隔）。
    pub delay: Option<f64>,
    /// 覆盖发送方式（None = 继承 CLI `--raw`；持续监听步骤 = 链路层监听开关）。
    pub raw: Option<StepRaw>,
    /// 静态字符串参数（追加到 `--params`，同名覆盖）。
    pub params: Vec<(String, String)>,
    pub extract: Vec<Extract>,
    pub on_error: OnError,
    /// 所属 loop 块上下文（None = 不在任何 loop 块内）。
    pub loop_ctx: Option<LoopCtx>,
    pub line: usize,
}

/// 解析后的配方。
#[derive(Debug, Clone)]
pub struct Recipe {
    pub path: PathBuf,
    pub globals: Vec<GlobalDecl>,
    pub steps: Vec<Step>,
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
        steps: Vec::new(),
    };
    let lines: Vec<&str> = src.lines().collect();
    let mut i = 0usize;
    // 解析状态
    let mut in_global = false; // global: 段内
    let mut in_recipe = false; // recipe: 段内
    let mut cur_global: Option<GlobalBuf> = None; // 当前 global 项（缩进 init: 行归属）
    let mut step: Option<StepBuf> = None; // 当前步骤
    let mut in_extract = false; // 步骤 extract: 子列表内
    let mut extract_buf: Option<ExtractBuf> = None; // 当前提取项（顶层/嵌套步骤共用同一状态机）
    // ── loop 块（`- loop:` 项）解析状态 ──
    let mut cur_loop: Option<LoopBuf> = None; // 当前 loop 块
    let mut in_until = false; // until: 谓词列表收集中（`- ` 行 = 谓词）
    let mut in_loop_steps = false; // 已进入 steps: 嵌套步骤模式
    let mut nested_item_indent = 0usize; // 嵌套步骤项缩进列（首个嵌套项确定）
    let mut nested_step: Option<StepBuf> = None; // 当前嵌套步骤
    let mut loop_id = 0usize; // loop 块计数（LoopCtx.id 分配）

    while i < lines.len() {
        let line_no = i + 1;
        // 行内注释：剥离 `#` 到行尾（双引号内的 `#` 保留，如 init: "a#b"）
        let raw = strip_comment(lines[i]);
        i += 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent == 0 {
            // ── 行首：段头 / 步骤项 ──
            if trimmed == "global:" || trimmed == "recipe:" {
                // 先收尾开着的 loop 块（`- loop:` 未写 steps: 在此报错）
                finish_loop(
                    &mut cur_loop,
                    &mut nested_step,
                    &mut extract_buf,
                    &mut in_until,
                    &mut in_loop_steps,
                    &mut loop_id,
                    &mut recipe.steps,
                )?;
                // 结束上一个步骤（若有）——先把未完成的提取项并入其 extract
                flush_extract(&mut step, &mut extract_buf)?;
                if let Some(s) = step.take() {
                    recipe.steps.push(s.finish()?);
                }
                in_extract = false;
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
                    // loop 块项：`- loop: N`（N 可省或负数 = 无限，直到 until/Ctrl+C）。
                    // 须在 `packet:`/裸文件名 之前判别（裸文件名步骤不允许含冒号）
                    if let Some(val) = rest.strip_prefix("loop:") {
                        // 先收尾上一个顶层步骤（loop 项也是顶层项）
                        flush_extract(&mut step, &mut extract_buf)?;
                        if let Some(s) = step.take() {
                            recipe.steps.push(s.finish()?);
                        }
                        in_extract = false;
                        // 收尾已开的 loop 块（缺 steps: 在此报错）
                        finish_loop(
                            &mut cur_loop,
                            &mut nested_step,
                            &mut extract_buf,
                            &mut in_until,
                            &mut in_loop_steps,
                            &mut loop_id,
                            &mut recipe.steps,
                        )?;
                        // 与 CLI 负数 `--wait` 同语义：负数 = 无限；正整数 = 循环次数。
                        // 空值非法（字段要么不写、要么写值）——无限循环显式写 `loop: -1`
                        let count = match val.trim() {
                            "" => {
                                return Err(err(line_no, t!("engine.parse_loop_empty")));
                            }
                            other => {
                                let n: i64 = other.parse().map_err(|_| {
                                    err(line_no, t!("engine.parse_loop_value", val = other))
                                })?;
                                if n == 0 {
                                    return Err(err(line_no, t!("engine.parse_loop_zero")));
                                }
                                if n < 0 { None } else { Some(n as usize) }
                            }
                        };
                        cur_loop = Some(LoopBuf {
                            count,
                            delay: None,
                            until: Vec::new(),
                            steps: Vec::new(),
                            line: line_no,
                        });
                        in_until = false;
                        in_loop_steps = false;
                        nested_item_indent = 0;
                        continue;
                    }
                    // 非 loop 顶层项：先收尾开着的 loop 块（缺 steps: 在此报错）
                    finish_loop(
                        &mut cur_loop,
                        &mut nested_step,
                        &mut extract_buf,
                        &mut in_until,
                        &mut in_loop_steps,
                        &mut loop_id,
                        &mut recipe.steps,
                    )?;
                    // 新步骤：`- packet: 文件` 或裸 `- 文件`（先收尾上一步的提取项）
                    flush_extract(&mut step, &mut extract_buf)?;
                    if let Some(s) = step.take() {
                        recipe.steps.push(s.finish()?);
                    }
                    in_extract = false;
                    let pkg = parse_step_item(rest, line_no, path)?;
                    step = Some(StepBuf {
                        pkg,
                        wait: None,
                        on_timeout: None,
                        count: None,
                        delay: None,
                        raw: None,
                        params: Vec::new(),
                        extract: Vec::new(),
                        on_error: OnError::Stop,
                        line: line_no,
                    });
                    continue;
                }
                return Err(err(line_no, t!("engine.parse_list_outside")));
            }
            return Err(err(
                line_no,
                t!("engine.parse_expect_section", trimmed = trimmed),
            ));
        }
        // ── 缩进行：段内选项 / 提取项 ──
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
        if in_recipe {
            // ── loop 块上下文（`- loop:` 项内）──
            if let Some(lb) = cur_loop.as_mut() {
                if !in_loop_steps {
                    // loop 选项模式：until: / delay: / steps:（`- ` 行 = until 谓词项）
                    if let Some(pred) = trimmed.strip_prefix("- ") {
                        if !in_until {
                            return Err(err(line_no, t!("engine.parse_loop_item_no_until")));
                        }
                        let pred = pred.trim();
                        if pred.is_empty() {
                            return Err(err(line_no, t!("engine.parse_until_empty")));
                        }
                        lb.until.push((pred.to_string(), line_no));
                        continue;
                    }
                    let (key, val) = split_kv(trimmed, line_no)?;
                    match key.as_str() {
                        "until" => {
                            // 谓词写在后续 `- ` 行（与 sniffer: 同风格）；不接受内联值
                            if !val.is_empty() {
                                return Err(err(line_no, t!("engine.parse_until_inline")));
                            }
                            in_until = true;
                        }
                        "delay" => {
                            // 轮间延迟（第 2 轮起、块首步执行前生效）
                            let secs: f64 = val.parse().map_err(|_| {
                                err(line_no, t!("engine.parse_delay_value", val = val))
                            })?;
                            // NaN/±inf/过大值会使 Duration::from_secs_f64 panic，先拒绝
                            if !secs.is_finite() || secs > crate::MAX_DURATION_SECS {
                                return Err(err(
                                    line_no,
                                    t!("engine.parse_delay_finite", val = val),
                                ));
                            }
                            if secs < 0.0 {
                                return Err(err(line_no, t!("engine.parse_delay_negative")));
                            }
                            lb.delay = Some(secs);
                        }
                        "steps" => {
                            // 进入嵌套步骤模式（此后直到块尾都是步骤内容）
                            if !val.is_empty() {
                                return Err(err(line_no, t!("engine.parse_steps_inline")));
                            }
                            in_until = false;
                            in_loop_steps = true;
                            nested_item_indent = 0;
                        }
                        "loop" => return Err(err(line_no, t!("engine.parse_loop_nested"))),
                        other => {
                            return Err(err(
                                line_no,
                                t!("engine.parse_loop_only_opts", other = other),
                            ));
                        }
                    }
                    continue;
                }
                // ── 嵌套步骤模式 ──
                if indent < nested_item_indent {
                    // loop 选项（until:/delay:）必须写在 steps: 之前
                    return Err(err(line_no, t!("engine.parse_loop_opts_before_steps")));
                }
                let is_item = trimmed.starts_with("- ");
                if is_item && (nested_item_indent == 0 || indent == nested_item_indent) {
                    if nested_item_indent == 0 {
                        nested_item_indent = indent;
                    }
                    // 新嵌套步骤：冲刷上一个（提取项 + 步骤本体）
                    flush_extract(&mut nested_step, &mut extract_buf)?;
                    if let Some(s) = nested_step.take() {
                        lb.steps.push(s);
                    }
                    in_extract = false;
                    let rest = trimmed.strip_prefix("- ").expect("已判 - ");
                    let pkg = parse_step_item(rest.trim(), line_no, path)?;
                    nested_step = Some(StepBuf {
                        pkg,
                        wait: None,
                        on_timeout: None,
                        count: None,
                        delay: None,
                        raw: None,
                        params: Vec::new(),
                        extract: Vec::new(),
                        on_error: OnError::Stop,
                        line: line_no,
                    });
                    continue;
                }
                // 嵌套步骤的选项/提取行：与顶层步骤共用同一状态机（step_line）
                let Some(step_ref) = nested_step.as_mut() else {
                    return Err(err(line_no, t!("engine.parse_steps_expect_item")));
                };
                step_line(
                    step_ref,
                    trimmed,
                    line_no,
                    path,
                    &mut in_extract,
                    &mut extract_buf,
                )?;
                continue;
            }
            // ── 顶层步骤上下文（与嵌套步骤共用 step_line 状态机）──
            let Some(step_ref) = step.as_mut() else {
                return Err(err(line_no, t!("engine.parse_option_after_step")));
            };
            step_line(
                step_ref,
                trimmed,
                line_no,
                path,
                &mut in_extract,
                &mut extract_buf,
            )?;
            continue;
        }
        return Err(err(line_no, t!("engine.parse_indent_outside")));
    }
    // 收尾：开着的 loop 块（缺 steps: 在此报错）→ 最后一个步骤 / 提取项
    finish_loop(
        &mut cur_loop,
        &mut nested_step,
        &mut extract_buf,
        &mut in_until,
        &mut in_loop_steps,
        &mut loop_id,
        &mut recipe.steps,
    )?;
    flush_extract(&mut step, &mut extract_buf)?;
    if let Some(s) = step.take() {
        recipe.steps.push(s.finish()?);
    }
    if recipe.steps.is_empty() {
        return Err(anyhow::anyhow!(
            "{}",
            t!("engine.parse_no_steps", path = path.display())
        ));
    }
    Ok(recipe)
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

/// 把未完成的提取项并入当前步骤的 extract 列表（新步骤 / 段头 / 收尾时调用）。
fn flush_extract(
    step: &mut Option<StepBuf>,
    extract_buf: &mut Option<ExtractBuf>,
) -> anyhow::Result<()> {
    if let Some(b) = extract_buf.take()
        && let Some(s) = step.as_mut()
    {
        s.extract.push(b.finish()?);
    }
    Ok(())
}

struct StepBuf {
    pkg: PathBuf,
    wait: Option<crate::engine::pkg::WaitMode>,
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
            loop_ctx: None, // loop 块由 LoopBuf::finish 统一附加
            line: self.line,
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
            // 与 CLI `--wait` 同语义：负数 = 无限等待（本步不发送，用 .pkt 的
            // sniffer 匹配外部到达的包，命中后配方继续触发后续步骤发包）；
            // 非负秒数 = 发送后等一个匹配应答；空值非法（要么不写、要么写值）
            let mode = match val.trim() {
                "" => {
                    return Err(err(line_no, t!("engine.parse_wait_empty")));
                }
                other => {
                    let secs: f64 = other
                        .parse()
                        .map_err(|_| err(line_no, t!("engine.parse_wait_value", val = val)))?;
                    // NaN/±inf/过大值会使 Duration::from_secs_f64 panic，先拒绝
                    if !secs.is_finite() || secs > crate::MAX_DURATION_SECS {
                        return Err(err(line_no, t!("engine.parse_wait_finite", val = val)));
                    }
                    if secs < 0.0 {
                        crate::engine::pkg::WaitMode::Continuous
                    } else {
                        crate::engine::pkg::WaitMode::OneShot(secs)
                    }
                }
            };
            step.wait = Some(mode);
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
        // until/steps 仅属于 loop 块（`- loop:` 项的选项），普通步骤报专门错误
        "until" | "steps" => {
            return Err(err(line_no, t!("engine.parse_loop_only_key", key = key)));
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

/// 收尾当前 loop 块：冲刷嵌套步骤 → 附加 [`LoopCtx`]（块内步骤平铺）→ 并入
/// `steps_out`。loop 项后未写 `steps:`（无嵌套步骤）在此报错；非 loop 上下文
/// 调用为空操作。
fn finish_loop(
    cur_loop: &mut Option<LoopBuf>,
    nested_step: &mut Option<StepBuf>,
    extract_buf: &mut Option<ExtractBuf>,
    in_until: &mut bool,
    in_loop_steps: &mut bool,
    loop_id: &mut usize,
    steps_out: &mut Vec<Step>,
) -> anyhow::Result<()> {
    if let Some(lb) = cur_loop.take() {
        flush_extract(nested_step, extract_buf)?;
        let mut buf = lb;
        if let Some(s) = nested_step.take() {
            buf.steps.push(s);
        }
        steps_out.extend(buf.finish(*loop_id)?);
        *loop_id += 1;
    }
    *in_until = false;
    *in_loop_steps = false;
    Ok(())
}

/// loop 块解析中间态（`- loop:` 项）。
struct LoopBuf {
    /// `loop: N` 次数（None = 无限，直到 until/Ctrl+C）。
    count: Option<usize>,
    /// 轮间延迟秒数（第 2 轮起生效）。
    delay: Option<f64>,
    /// `until:` 谓词文本 + 行号（执行期构建 Matcher）。
    until: Vec<(String, usize)>,
    /// 嵌套步骤（`steps:` 模式下收集）。
    steps: Vec<StepBuf>,
    /// loop 项行号（报错定位）。
    line: usize,
}

impl LoopBuf {
    /// 块收尾：校验（非空 steps、until 谓词语法预检——层/字段名语义在执行期
    /// `Matcher::build`，允许引用步骤 .pkt 的值函数）+ 附加 [`LoopCtx`] 平铺。
    fn finish(self, id: usize) -> anyhow::Result<Vec<Step>> {
        if self.steps.is_empty() {
            return Err(err(self.line, t!("engine.parse_loop_no_steps")));
        }
        for (pred, line) in &self.until {
            crate::engine::recipe::parse_until_pred(pred).map_err(|e| {
                err(
                    *line,
                    t!("engine.parse_until_pred_fail", pred = pred, err = e),
                )
            })?;
        }
        let n = self.steps.len();
        let until = if self.until.is_empty() {
            None
        } else {
            Some(
                self.until
                    .iter()
                    .map(|(p, _)| p.clone())
                    .collect::<Vec<_>>(),
            )
        };
        let mut out = Vec::with_capacity(n);
        for (i, s) in self.steps.into_iter().enumerate() {
            let mut step = s.finish()?;
            step.loop_ctx = Some(LoopCtx {
                id,
                count: self.count,
                until: until.clone(),
                delay: self.delay,
                first: i == 0,
                last: i == n - 1,
                line: self.line,
            });
            out.push(step);
        }
        Ok(out)
    }
}

/// 步骤项（`- ` 后内容）→ .pkt 路径：`packet: 文件` 或裸文件名（相对 .pktl 所在
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

    /// loop 块解析：`loop: N` + `delay:` + `until:` 谓词 + 嵌套步骤 → 平铺 steps
    /// 并附加 LoopCtx（块内共享 id/count/until/delay，first/last 标记边界）。
    #[test]
    fn recipe_parse_loop_block() {
        let src = r#"
global:
- tid

recipe:
- loop: 3
  delay: 0.5
  until:
  - match icmp(type=0)
  - match udp(dport=9)
  steps:
  - packet: listen.pkt
    wait: -1
    extract:
    - name: tid
      from: reply.icmp.id
  - packet: reply.pkt
    raw: true
- packet: tail.pkt
"#;
        let dir = std::env::temp_dir().join(format!("prping-loop-parse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("flow.pktl");
        std::fs::write(&path, src).unwrap();
        let r = parse(&path).expect("loop 配方解析成功");
        assert_eq!(r.steps.len(), 3, "块内 2 步平铺 + 块后 1 步");
        let ctx0 = r.steps[0].loop_ctx.as_ref().expect("首步带 LoopCtx");
        assert_eq!(ctx0.id, 0);
        assert_eq!(ctx0.count, Some(3));
        assert_eq!(
            ctx0.until.as_deref(),
            Some(
                &[
                    "match icmp(type=0)".to_string(),
                    "match udp(dport=9)".to_string()
                ][..]
            )
        );
        assert_eq!(ctx0.delay, Some(0.5));
        assert!(ctx0.first, "块首步");
        assert!(!ctx0.last);
        let ctx1 = r.steps[1].loop_ctx.as_ref().expect("次步带 LoopCtx");
        assert!(!ctx1.first);
        assert!(ctx1.last, "块末步");
        assert_eq!(ctx1.id, 0, "同块同 id");
        assert!(r.steps[2].loop_ctx.is_none(), "块外步骤无 LoopCtx");
        assert_eq!(
            r.steps[0].wait,
            Some(crate::engine::pkg::WaitMode::Continuous)
        );
        assert_eq!(
            r.steps[1].raw,
            Some(StepRaw::On { iface: None }),
            "嵌套步骤选项完整解析"
        );
        assert_eq!(r.steps[0].extract.len(), 1, "嵌套步骤 extract 完整解析");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `loop:` 负数 = 无限循环（count None；与 CLI 负数 `--wait` 同语义；空值非法，
    /// 报错见 recipe_parse_loop_errors）。
    #[test]
    fn recipe_parse_loop_infinite() {
        for (tag, body) in [
            ("neg1", "recipe:\n- loop: -1\n  steps:\n  - a.pkt\n"),
            ("neg5", "recipe:\n- loop: -5\n  steps:\n  - a.pkt\n"),
        ] {
            let dir =
                std::env::temp_dir().join(format!("prping-loop-inf-{}-{tag}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("flow.pktl");
            std::fs::write(&path, body).unwrap();
            let r = parse(&path).unwrap_or_else(|e| panic!("{tag}: 无限 loop 解析成功: {e}"));
            assert_eq!(r.steps.len(), 1);
            assert_eq!(
                r.steps[0].loop_ctx.as_ref().unwrap().count,
                None,
                "{tag}: 负数 = 无限"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// loop 块解析错误路径：次数 0/非法、缺 steps、until 内联、until 后置、
    /// 普通步骤写 until/steps、未知 loop 选项、until 谓词语法错误。
    #[test]
    fn recipe_parse_loop_errors() {
        let dir = std::env::temp_dir().join(format!("prping-loop-err-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let parse = |name: &str, body: &str| {
            let path = dir.join(name);
            std::fs::write(&path, body).unwrap();
            parse(&path).expect_err("预期解析失败").to_string()
        };
        // 次数 0 / 非法
        let e = parse("zero.pktl", "recipe:\n- loop: 0\n  steps:\n  - a.pkt\n");
        assert!(e.contains("loop"), "{e}");
        let e = parse("bad.pktl", "recipe:\n- loop: abc\n  steps:\n  - a.pkt\n");
        assert!(e.contains("loop"), "{e}");
        // 缺 steps（下一个顶层项直接收尾 loop）
        let e = parse("nosteps.pktl", "recipe:\n- loop: 2\n- packet: a.pkt\n");
        assert!(e.contains("steps"), "{e}");
        // until 内联值不接受
        let e = parse(
            "untilinline.pktl",
            "recipe:\n- loop: -1\n  until: match icmp(type=0)\n  steps:\n  - a.pkt\n",
        );
        assert!(e.contains("until"), "{e}");
        // until 写在 steps: 之后（进入嵌套步骤模式后报 loop 选项专用错误）
        let e = parse(
            "untillate.pktl",
            "recipe:\n- loop: -1\n  steps:\n  - a.pkt\n  until:\n",
        );
        assert!(e.contains("loop") && e.contains("steps"), "{e}");
        // 普通步骤写 until / steps
        let e = parse("untiltop.pktl", "recipe:\n- packet: a.pkt\n  until:\n");
        assert!(e.contains("loop"), "{e}");
        let e = parse("stepstop.pktl", "recipe:\n- packet: a.pkt\n  steps:\n");
        assert!(e.contains("loop"), "{e}");
        // 未知 loop 选项
        let e = parse(
            "loopopt.pktl",
            "recipe:\n- loop: -1\n  wait: 1\n  steps:\n  - a.pkt\n",
        );
        assert!(e.contains("loop"), "{e}");
        // until 谓词语法错误（解析期预检）
        let e = parse(
            "badpred.pktl",
            "recipe:\n- loop: -1\n  until:\n  - icmp.type == 0\n  steps:\n  - a.pkt\n",
        );
        assert!(e.contains("until") || e.contains("match"), "{e}");
        // loop 空值非法（原「无值 = 无限」）——无限循环显式写 `loop: -1`
        let e = parse("loopempty.pktl", "recipe:\n- loop:\n  steps:\n  - a.pkt\n");
        assert!(e.contains("loop") && e.contains("loop: -1"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
