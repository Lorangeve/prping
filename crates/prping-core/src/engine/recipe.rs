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
//! - pkg: examples/step1.pkt   # 发 step1，等回包，把回包 tcp.seq 提取进 global
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
//! - 步骤项：`- pkg: 文件`（后可跟选项行）或裸文件名 `- 文件`。
//! - 步骤选项：`wait: 秒数`（覆盖 `--wait`）、`delay: 秒数`（步骤开始前等待——
//!   非首步生效，pcap 转码配方用；响应 Ctrl+C 提前结束）、`params: k=v,k2=v2`（静态字符串，
//!   追加到 `--params` 同名覆盖）、`raw: true|false|网卡名`（覆盖 `--raw`：`true` 开原始
//!   发送、网卡名 = 开原始发送并指定网卡、`false` 强制载荷发送）、`extract:`（子列表
//!   `- name:` + `from:` + `as:`）、`on_error: stop|continue`。
//! - `from:` 取值：`reply.<层>.<字段>` 直取回包反解字段（层/字段名与 sniffer 一致）；
//!   或**值表达式**（可调函数/原语/`+`，内嵌 `reply.<层>.<字段>` 叶子），如
//!   `from: reply.icmp.seq + 1` / `from: cksum(reply.icmp.payload)`。
//! - `init` 值：字符串 `"..."` / 十进制 / `0x` 十六进制 / `[0x01, 0x02]` 字节列表。
//! - `#` 行注释，空行忽略；路径相对 .pktl 所在目录解析。
//!
//! 执行在 `pkg.rs::send_recipe`（维护 global 存储 + extract + on_error 容错）；
//! `--eng FILE.pktl` 只做结构概览（`eng.rs::analyze_recipe`）。

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
    fn parse(s: &str, line: usize) -> anyhow::Result<Self> {
        match s {
            "int" => Ok(ExtractAs::Int),
            "hex" => Ok(ExtractAs::Hex),
            "str" => Ok(ExtractAs::Str),
            "bytes" => Ok(ExtractAs::Bytes),
            other => Err(anyhow::anyhow!(
                "配方 {line} 行：`as` 只支持 int / hex / str / bytes，得到 `{other}`"
            )),
        }
    }
}

/// `from:` 取值来源：回包反解字段（直取形态）或值表达式（可调用函数/原语）。
#[derive(Debug, Clone, PartialEq)]
pub enum FromSpec {
    /// `reply.<层>.<字段>`——直接取回包反解字段（`as:` 控制形态，默认 int）。
    Field { layer: String, field: String },
    /// 值表达式（可含 `reply.<层>.<字段>` 叶子，解析期改写为 `reply("层","字段")`
    /// 原语调用）：如 `reply.icmp.seq + 1` / `cksum(reply.icmp.payload)`。
    /// `as:` 可选（缺省 = 表达式的自然类型值）。
    Expr(packet_dsl::ast::Value),
}

impl FromSpec {
    /// 表达式形态的 DSL 值（字段形态返回 None）。
    pub fn as_expr(&self) -> Option<&packet_dsl::ast::Value> {
        match self {
            FromSpec::Expr(v) => Some(v),
            FromSpec::Field { .. } => None,
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

/// 配方步骤。
#[derive(Debug, Clone)]
pub struct Step {
    /// .pkt 文件（相对 .pktl 所在目录解析）。
    pub pkg: PathBuf,
    /// 覆盖 `--wait`（None = 继承 CLI）。
    pub wait: Option<f64>,
    /// 步骤开始前的延迟秒数（第 1 步忽略；pcap 转码配方携带捕获间隔）。
    pub delay: Option<f64>,
    /// 覆盖发送方式（None = 继承 CLI `--raw`）。
    pub raw: Option<StepRaw>,
    /// 静态字符串参数（追加到 `--params`，同名覆盖）。
    pub params: Vec<(String, String)>,
    pub extract: Vec<Extract>,
    pub on_error: OnError,
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
    let src = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("读取配方失败（{}）：{e}", path.display()))?;
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
    let mut extract_buf: Option<ExtractBuf> = None; // 当前提取项

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
                        return Err(err(line_no, format!("全局 `{name}` 重复声明")));
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
                    // 新步骤：`- pkg: 文件` 或裸 `- 文件`（先收尾上一步的提取项）
                    flush_extract(&mut step, &mut extract_buf)?;
                    if let Some(s) = step.take() {
                        recipe.steps.push(s.finish()?);
                    }
                    in_extract = false;
                    let (pkg_str, line) = match rest.strip_prefix("pkg:") {
                        Some(p) => (p.trim().to_string(), line_no),
                        None => {
                            if rest.contains(':') {
                                return Err(err(
                                    line_no,
                                    format!(
                                        "步骤项语法错误：`{rest}`（应为 `- pkg: 文件` 或裸文件名）"
                                    ),
                                ));
                            }
                            (rest.to_string(), line_no)
                        }
                    };
                    if pkg_str.is_empty() {
                        return Err(err(line_no, "步骤缺少 .pkt 文件路径"));
                    }
                    let pkg = resolve_rel(path, &pkg_str);
                    step = Some(StepBuf {
                        pkg,
                        wait: None,
                        delay: None,
                        raw: None,
                        params: Vec::new(),
                        extract: Vec::new(),
                        on_error: OnError::Stop,
                        line,
                    });
                    continue;
                }
                return Err(err(line_no, "列表项出现在 global:/recipe: 段之外"));
            }
            return Err(err(
                line_no,
                format!("期望段头 `global:`/`recipe:` 或 `- ` 列表项，得到 `{trimmed}`"),
            ));
        }
        // ── 缩进行：段内选项 / 提取项 ──
        if in_global {
            let (key, val) = split_kv(trimmed, line_no)?;
            if key != "init" {
                return Err(err(
                    line_no,
                    format!("global 项只支持 `init:`，得到 `{key}:`"),
                ));
            }
            let Some(gb) = cur_global.as_ref() else {
                return Err(err(line_no, "`init:` 必须跟在 `- name: <名字>` 之后"));
            };
            if gb.has_inline_init {
                return Err(err(
                    line_no,
                    format!(
                        "全局 `{}` 已在一行内给出 init（`- {}=...`），不能再跟 `init:` 行",
                        gb.name, gb.name
                    ),
                ));
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
            let Some(step_ref) = step.as_mut() else {
                return Err(err(line_no, "选项行必须跟在 `- pkg:` 步骤之后"));
            };
            // 提取子列表：`- name:` / `- from:` / `- as:` 或以 `- ` 开头的续项
            if let Some(rest) = trimmed.strip_prefix("- ") {
                in_extract = true;
                // 完成上一个提取项
                if let Some(b) = extract_buf.take() {
                    step_ref.extract.push(b.finish()?);
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
                        return Err(err(
                            line_no,
                            format!("extract 项只支持 name/from/as，得到 `{other}`"),
                        ));
                    }
                }
                extract_buf = Some(b);
                continue;
            }
            if in_extract {
                // 提取项的续行（from: / as:），或退出提取回到步骤选项
                if let Some(b) = extract_buf.as_mut() {
                    let (key, val) = split_kv(trimmed, line_no)?;
                    match key.as_str() {
                        "from" => {
                            b.from = Some(parse_from(val, line_no)?);
                            continue;
                        }
                        "as" => {
                            b.as_ = ExtractAs::parse(val, line_no)?;
                            b.as_given = true;
                            continue;
                        }
                        _ => {}
                    }
                }
                // 非提取续行 → 提交当前提取项，回到步骤选项处理
                in_extract = false;
                if let Some(b) = extract_buf.take() {
                    step_ref.extract.push(b.finish()?);
                }
            }
            // 步骤选项行
            let (key, val) = split_kv(trimmed, line_no)?;
            match key.as_str() {
                "wait" => {
                    let secs: f64 = val.parse().map_err(|_| {
                        err(line_no, format!("`wait` 需要秒数（数字），得到 `{val}`"))
                    })?;
                    step_ref.wait = Some(secs);
                }
                "delay" => {
                    let secs: f64 = val.parse().map_err(|_| {
                        err(line_no, format!("`delay` 需要秒数（数字），得到 `{val}`"))
                    })?;
                    if secs < 0.0 {
                        return Err(err(line_no, "`delay` 不能为负数"));
                    }
                    step_ref.delay = Some(secs);
                }
                "params" => {
                    let pairs = parse_params_list(val, line_no)?;
                    for (k, v) in pairs {
                        if let Some(existing) = step_ref.params.iter_mut().find(|(ek, _)| *ek == k)
                        {
                            existing.1 = v;
                        } else {
                            step_ref.params.push((k, v));
                        }
                    }
                }
                "raw" => {
                    step_ref.raw = Some(parse_step_raw(val, line_no)?);
                }
                "on_error" => {
                    step_ref.on_error = match val {
                        "stop" => OnError::Stop,
                        "continue" => OnError::Continue,
                        other => {
                            return Err(err(
                                line_no,
                                format!("`on_error` 只支持 stop / continue，得到 `{other}`"),
                            ));
                        }
                    };
                }
                "extract" => {
                    // 进入提取子列表（extract: 独占一行，后跟 - 项）
                    in_extract = true;
                }
                other => {
                    return Err(err(
                        line_no,
                        format!(
                            "未知步骤选项 `{other}:`（支持 pkg/wait/delay/raw/params/extract/on_error）"
                        ),
                    ));
                }
            }
            continue;
        }
        return Err(err(line_no, "缩进行出现在 global:/recipe: 段之外"));
    }
    // 收尾：最后一个步骤 / 提取项
    flush_extract(&mut step, &mut extract_buf)?;
    if let Some(s) = step.take() {
        recipe.steps.push(s.finish()?);
    }
    if recipe.steps.is_empty() {
        return Err(anyhow::anyhow!(
            "配方 {}：`recipe:` 段至少需要一个步骤",
            path.display()
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
    wait: Option<f64>,
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
            delay: self.delay,
            raw: self.raw,
            params: self.params,
            extract: self.extract,
            on_error: self.on_error,
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
            .ok_or_else(|| err(self.line, "extract 项缺少 `name:`"))?;
        let from = self
            .from
            .ok_or_else(|| err(self.line, format!("extract 项 `{name}` 缺少 `from:`")))?;
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
        .ok_or_else(|| err(line, format!("期望 `键: 值`，得到 `{s}`")))?;
    let k = k.trim();
    if k.is_empty() {
        return Err(err(line, "键不能为空"));
    }
    Ok((k.to_string(), v.trim()))
}

fn nonempty(v: &str, what: &str, line: usize) -> anyhow::Result<String> {
    if v.is_empty() {
        Err(err(line, format!("`{what}` 不能为空")))
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
            return Err(err(line, "global 项 `name:` 缺少名字"));
        }
        return Ok((n.to_string(), None));
    }
    if let Some(eq) = rest.find('=') {
        let name = rest[..eq].trim();
        if name.is_empty() {
            return Err(err(line, format!("global 项缺少名字：`{rest}`")));
        }
        let val = rest[eq + 1..].trim();
        if val.is_empty() {
            return Err(err(line, format!("global 项 `{name}` 的 init 值不能为空")));
        }
        return Ok((name.to_string(), Some(parse_init_value(val, line)?)));
    }
    if rest.contains(':') {
        return Err(err(
            line,
            format!(
                "global 项语法错误：`{rest}`（应为 `- name: <名字>` / `- <名字>` / `- <名字>=<值>`）"
            ),
        ));
    }
    if rest.is_empty() {
        return Err(err(line, "global 项缺少名字"));
    }
    Ok((rest.to_string(), None))
}

/// `from:` 取值来源解析：
/// 1. `reply.<层>.<字段>` 且字段在 sniffer 字段集内 → [`FromSpec::Field`]（直取形态，
///    `as:` 控制形态；保持旧行为）。payload/body/raw 等扩展字段不在 sniffer 集内，
///    走表达式形态（`reply.<层>.<字段>` 叶子在求值时同样可取）。
/// 2. 其余 → [`FromSpec::Expr`] 值表达式：`reply.<层>.<字段>` 叶子改写为
///    `reply("层", "字段")` 调用后按 DSL 值表达式解析（可调函数/原语/`+` 运算）。
fn parse_from(v: &str, line: usize) -> anyhow::Result<FromSpec> {
    if let Some((layer, field)) = parse_field_ref(v)
        && let Some(names) = crate::engine::pkg::sniffer_field_names(&layer)
        && names.contains(&field.as_str())
    {
        return Ok(FromSpec::Field { layer, field });
    }
    let rewritten = rewrite_reply_leaves(v);
    let expr = packet_dsl::parser::parse_value_expr(&rewritten)
        .map_err(|d| err(line, format!("`from` 表达式解析失败：{d}")))?;
    Ok(FromSpec::Expr(expr))
}

/// `reply.<层>.<字段>`（严格两段，层/字段非空且字段不含 `.`）→ Some((层, 字段))。
fn parse_field_ref(v: &str) -> Option<(String, String)> {
    let rest = v.strip_prefix("reply.")?;
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
    let mut out = Vec::new();
    for pair in v.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (k, val) = pair
            .split_once('=')
            .ok_or_else(|| err(line, format!("`params` 需要 `k=v,k2=v2`，得到 `{v}`")))?;
        out.push((k.trim().to_string(), val.trim().to_string()));
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
        "" => Err(err(line, "`raw` 需要 true / false 或网卡名")),
        other => {
            let iface = other.trim_matches('"');
            if iface.is_empty() {
                return Err(err(line, "`raw` 的网卡名不能为空"));
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
            .ok_or_else(|| err(line, format!("字符串缺少结尾引号：`{s}`")))?;
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
                    .map_err(|_| err(line, format!("非法十六进制字节 `{part}`")))?;
                if v > 0xFF {
                    return Err(err(line, format!("字节列表元素超出 0..255：`{part}`")));
                }
                items.push(Value::Hex(v));
            } else {
                let v: i64 = part
                    .parse()
                    .map_err(|_| err(line, format!("非法字节列表元素 `{part}`")))?;
                if !(0..=255).contains(&v) {
                    return Err(err(line, format!("字节列表元素超出 0..255：`{part}`")));
                }
                items.push(Value::Int(v));
            }
        }
        return Ok(Value::List(items));
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let v =
            u64::from_str_radix(hex, 16).map_err(|_| err(line, format!("非法十六进制 `{s}`")))?;
        return Ok(Value::Hex(v));
    }
    if let Ok(v) = s.parse::<i64>() {
        return Ok(Value::Int(v));
    }
    Err(err(
        line,
        format!(
            "无法解析 `init` 值 `{s}`（支持：\"字符串\" / 十进制 / 0x 十六进制 / [0x01, 0x02] 字节列表）"
        ),
    ))
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
    anyhow::anyhow!("配方 {line} 行：{msg}")
}
