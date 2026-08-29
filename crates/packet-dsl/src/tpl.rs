//! `tpl(template, input)` 字符串模板匹配原语：文本 → 字节 的通用解析器。
//!
//! 取代 `ip4`/`ip6`/`mac` 值原语的字面量文本解析部分（域名回退仍由 `dns` 原语
//! 与地址字段 coercer 负责，见 registry.rs / eval.rs）。
//!
//! 模板子语法（模板串 = 字面字符与说明符交替；锚定全匹配，字面字符匹配但不产出）：
//! - `%c`        恰好 1 字节任意值（通配）
//! - `%d1|%d2|%d4` 十进制，输出 1/2/4 字节大端（值域 0..256^w−1；贪心最多
//!   3/5/10 位数字；宽度缺省 = 1，即 `%d` ≡ `%d1`）
//! - `%x1|%x2|%x4` 十六进制，同上（贪心最多 2w 位 hex；`%x` ≡ `%x1`）
//! - `%L`        DNS 名字序列（**动态宽度**，tpl 唯一例外）：消费剩余输入为
//!   点分标签，每个标签输出（u8 标签字节长 + 原文），末尾 0x00；空标签跳过
//!   （尾点/连续点容忍）；标签 ≤63 字节、总长 ≤255。不吃宽度/重复参数。
//!   ——旧 `dns_name` 值原语下沉至此（eng_lib/bytes.pkt 的
//!   `func dns_name(s) -> bytes { tpl("%L", s) }`）
//! - `{n}`       重复 n 次（无分隔符）
//! - `{n:sep}`   重复 n 次，分隔符为单字符 sep；`{n:}` 缺省 sep = `:`；
//!   冒号分隔时输入出现 `::` = 零填充压缩（ip6 形态：`fe80::1`/`::1`/`fe80::`）
//! - `{n:[chars]}` 重复 n 次，分隔符为字符类中任一字符（如 mac 的 `[-.:]`）
//! - `%%` 转义字面 `%`；其余非 ASCII 字面字符报错
//!
//! 输入为字节列表时**等宽直通**（长度 = 模板总输出宽且逐字节合法即原样返回，
//! 与旧 `mac(rand_mac())` 行为一致；含 `%L` 的模板输出宽动态不可算 → 不接受
//! 字节列表输入）；字符串按模板解析。

use crate::ast::{Span, Value};
use crate::diag::{Diagnostic, PktResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Char,
    Dec,
    Hex,
}

/// 重复分组间的分隔符。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Sep {
    /// `{n}`：无分隔符
    None,
    /// `{n:c}` / `{n:}`（缺省 `:`）
    Char(char),
    /// `{n:[chars]}`：任一字符
    Set(Vec<char>),
}

#[derive(Debug, Clone)]
struct Spec {
    kind: Kind,
    width: usize,
    count: usize,
    sep: Sep,
}

#[derive(Debug, Clone)]
enum Item {
    Lit(char),
    Spec(Spec),
    /// `%L`：DNS 名字序列（动态宽度，无参数）。
    DnsName,
}

#[derive(Debug, Clone)]
struct Tpl {
    items: Vec<Item>,
}

impl Tpl {
    fn parse(template: &str) -> Result<Tpl, String> {
        let chars: Vec<char> = template.chars().collect();
        let mut items = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '%' {
                if i + 1 < chars.len() && chars[i + 1] == '%' {
                    items.push(Item::Lit('%'));
                    i += 2;
                    continue;
                }
                let kind = match chars.get(i + 1) {
                    Some('c') => Kind::Char,
                    Some('d') => Kind::Dec,
                    Some('x') => Kind::Hex,
                    Some('L') => {
                        // %L：DNS 名字序列（动态宽度，tpl 唯一例外）。消费剩余
                        // 输入为点分标签，每个标签输出 (u8 长度 + 原文)，末尾 0x00。
                        // 不吃宽度/重复参数（紧跟数字或 `{` 报错，避免误写）。
                        i += 2;
                        if chars
                            .get(i)
                            .is_some_and(|c| c.is_ascii_digit() || *c == '{')
                        {
                            return Err(format!(
                                "`tpl` 模板：`%L` 不接受宽度或重复参数（位置 {i}）：{template}"
                            ));
                        }
                        items.push(Item::DnsName);
                        continue;
                    }
                    _ => {
                        return Err(format!(
                            "`tpl` 模板：`%` 后需要 c/d/x/L（位置 {i}）：{template}"
                        ));
                    }
                };
                i += 2;
                let mut width = 1;
                if kind != Kind::Char
                    && let Some(w) = chars.get(i).and_then(|c| c.to_digit(10))
                {
                    if matches!(w, 1 | 2 | 4) {
                        width = w as usize;
                        i += 1;
                    } else {
                        return Err(format!(
                            "`tpl` 模板：宽度只能是 1/2/4（位置 {i}）：{template}"
                        ));
                    }
                }
                // 重复：{n} / {n:sep} / {n:[chars]}
                let mut count = 1;
                let mut sep = Sep::None;
                if chars.get(i) == Some(&'{') {
                    i += 1;
                    let start = i;
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        i += 1;
                    }
                    if i == start {
                        return Err(format!(
                            "`tpl` 模板：`{{` 后需要重复次数（位置 {start}）：{template}"
                        ));
                    }
                    count = chars[start..i]
                        .iter()
                        .collect::<String>()
                        .parse::<usize>()
                        .map_err(|_| format!("`tpl` 模板：重复次数过大：{template}"))?;
                    if count == 0 {
                        return Err(format!("`tpl` 模板：重复次数须 > 0：{template}"));
                    }
                    if chars.get(i) == Some(&':') {
                        i += 1;
                        if chars.get(i) == Some(&'[') {
                            i += 1;
                            let mut set = Vec::new();
                            while i < chars.len() && chars[i] != ']' {
                                if !chars[i].is_ascii() {
                                    return Err(format!(
                                        "`tpl` 模板：分隔符字符类仅支持 ASCII：{template}"
                                    ));
                                }
                                set.push(chars[i]);
                                i += 1;
                            }
                            if chars.get(i) != Some(&']') {
                                return Err(format!("`tpl` 模板：字符类缺少 `]`：{template}"));
                            }
                            i += 1;
                            if set.is_empty() {
                                return Err(format!("`tpl` 模板：字符类不能为空：{template}"));
                            }
                            sep = Sep::Set(set);
                        } else if chars.get(i) == Some(&'}') {
                            // {n:}：缺省分隔符 = ':'
                            sep = Sep::Char(':');
                        } else {
                            match chars.get(i) {
                                Some(c) if c.is_ascii() => {
                                    sep = Sep::Char(*c);
                                    i += 1;
                                }
                                _ => {
                                    return Err(format!(
                                        "`tpl` 模板：分隔符须为单个 ASCII 字符：{template}"
                                    ));
                                }
                            }
                        }
                    }
                    if chars.get(i) != Some(&'}') {
                        return Err(format!("`tpl` 模板：`{{` 未闭合（位置 {i}）：{template}"));
                    }
                    i += 1;
                }
                items.push(Item::Spec(Spec {
                    kind,
                    width,
                    count,
                    sep,
                }));
            } else {
                if !chars[i].is_ascii() {
                    return Err(format!(
                        "`tpl` 模板：字面字符仅支持 ASCII（位置 {i}）：{template}"
                    ));
                }
                items.push(Item::Lit(chars[i]));
                i += 1;
            }
        }
        Ok(Tpl { items })
    }

    /// 模板总输出字节宽（List 直通的长度校验用）；含 `%L`（动态宽度）→ None。
    fn total_width(&self) -> Option<usize> {
        let mut sum = 0usize;
        for it in &self.items {
            match it {
                Item::Lit(_) => {}
                Item::Spec(s) => sum += s.width * s.count,
                Item::DnsName => return None,
            }
        }
        Some(sum)
    }

    /// 锚定全匹配：输入全部消费；产出按模板顺序拼接。
    fn match_bytes(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        let mut pos = 0;
        for item in &self.items {
            match item {
                Item::Lit(c) => {
                    if pos >= input.len() || input[pos] != *c as u8 {
                        return Err(mismatch_err(input, pos, &format!("期望字面量 `{c}`")));
                    }
                    pos += 1;
                }
                Item::Spec(s) => out.extend(self.match_repeat(s, input, &mut pos)?),
                Item::DnsName => out.extend(self.match_dns_name(input, &mut pos)?),
            }
        }
        if pos != input.len() {
            return Err(format!(
                "`tpl` 匹配失败：模板结束后仍有 {} 字节未消费（位置 {pos}）",
                input.len() - pos
            ));
        }
        Ok(out)
    }

    /// `%L`：DNS 名字序列——消费**剩余全部**输入为点分标签，每个标签输出
    /// （u8 标签字节长 + 原文），末尾 0x00。空标签跳过（尾点/连续点容忍，
    /// 与旧 dns_name 行为一致）；标签 ≤63 字节、总长 ≤255（旧实现 as u8 截断）。
    fn match_dns_name(&self, input: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
        let rest = &input[*pos..];
        let mut out = Vec::new();
        let mut total = 1usize; // 末尾 0x00
        for label in rest.split(|b| *b == b'.') {
            if label.is_empty() {
                continue;
            }
            if label.len() > 63 {
                return Err(format!(
                    "`tpl` 匹配失败：DNS 标签超过 63 字节（{} 字节）",
                    label.len()
                ));
            }
            total += 1 + label.len();
            if total > 255 {
                return Err("`tpl` 匹配失败：DNS 名字超过 255 字节".to_string());
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        *pos = input.len();
        Ok(out)
    }

    /// 匹配一个重复组（{count} 组，组间分隔符 sep，冒号分隔支持 `::` 零填充压缩）。
    fn match_repeat(&self, s: &Spec, input: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
        let sep_is_colon = matches!(s.sep, Sep::Char(':'));
        let mut groups: Vec<Vec<u8>> = Vec::new(); // 实际匹配到的组
        let mut fill_pos: Option<usize> = None; // 零填充插入位置（组下标）
        let mut compressed = false;

        for g in 0..s.count {
            // 组前分隔符（压缩后紧随的那一组不再需要分隔符）
            let need_sep = g > 0 && !(compressed && g == fill_pos.unwrap_or(0) + 1);
            if need_sep {
                match &s.sep {
                    Sep::None => {}
                    Sep::Char(c) => {
                        if *pos >= input.len() || input[*pos] != *c as u8 {
                            if compressed {
                                break; // 压缩后输入耗尽：余下组为填充
                            }
                            return Err(mismatch_err(input, *pos, &format!("期望分隔符 `{c}`")));
                        }
                        *pos += 1;
                        // 冒号分隔且分隔符后紧跟另一个 `:`（输入 `::`）→ 压缩标记：
                        // 第一个 `:` 已作为分隔符消费，这里再消费第二个
                        if sep_is_colon && *pos < input.len() && input[*pos] == b':' {
                            if compressed {
                                return Err(format!(
                                    "`tpl` 匹配失败：多个 `::` 零填充压缩（模板 {} 组）",
                                    s.count
                                ));
                            }
                            fill_pos = Some(g);
                            compressed = true;
                            *pos += 1;
                            continue;
                        }
                    }
                    Sep::Set(set) => {
                        let hit = *pos < input.len() && set.contains(&(input[*pos] as char));
                        if !hit {
                            if compressed {
                                break;
                            }
                            return Err(mismatch_err(
                                input,
                                *pos,
                                &format!("期望分隔符字符类 [{}]", set.iter().collect::<String>()),
                            ));
                        }
                        *pos += 1;
                    }
                }
            } else if g == 0
                && sep_is_colon
                && *pos + 1 < input.len()
                && input[*pos] == b':'
                && input[*pos + 1] == b':'
            {
                // 输入（当前游标处）`::` → 压缩（组 0 为填充）。此前误用
                // 绝对 input[0]/input[1]：模板在重复组前有字面项/说明符时
                // （如 `ip={3:%x:}` 配 `ip=::1`）压缩失效或误触发。
                fill_pos = Some(0);
                compressed = true;
                *pos += 2;
                continue;
            }

            match self.match_group(s, input, pos) {
                Ok(bytes) => groups.push(bytes),
                Err(e) => {
                    if compressed {
                        break; // 压缩后组不足：余下为填充
                    }
                    return Err(e);
                }
            }
        }

        if compressed {
            if groups.len() >= s.count {
                return Err(format!(
                    "`tpl` 匹配失败：`::` 压缩但组数已满（{} 组）",
                    s.count
                ));
            }
            let fill = s.count - groups.len();
            let fp = fill_pos.expect("compressed 必有 fill_pos");
            let mut out = Vec::new();
            for grp in groups.iter().take(fp) {
                out.extend_from_slice(grp);
            }
            for _ in 0..fill {
                out.extend(std::iter::repeat_n(0, s.width));
            }
            for grp in groups.iter().skip(fp) {
                out.extend_from_slice(grp);
            }
            Ok(out)
        } else {
            // 无压缩：组数必须恰好 count（中途失败已报错，这里只兜底）
            if groups.len() != s.count {
                return Err(format!(
                    "`tpl` 匹配失败：模板需要 {} 组，只匹配到 {} 组",
                    s.count,
                    groups.len()
                ));
            }
            Ok(groups.into_iter().flatten().collect())
        }
    }

    /// 匹配单个组（`%c` 1 字节 / `%d` 十进制 / `%x` 十六进制，大端编码）。
    fn match_group(&self, s: &Spec, input: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
        match s.kind {
            Kind::Char => {
                if *pos >= input.len() {
                    return Err(format!(
                        "`tpl` 匹配失败：位置 {pos} 需要 1 个字符，输入已结束"
                    ));
                }
                let b = input[*pos];
                *pos += 1;
                Ok(vec![b])
            }
            Kind::Dec | Kind::Hex => {
                let max_digits = match (s.kind, s.width) {
                    (Kind::Dec, 1) => 3,
                    (Kind::Dec, 2) => 5,
                    (Kind::Dec, _) => 10,
                    (_, 1) => 2,
                    (_, 2) => 4,
                    _ => 8,
                };
                let radix = if s.kind == Kind::Dec { 10 } else { 16 };
                let is_digit = |b: u8| {
                    if s.kind == Kind::Dec {
                        b.is_ascii_digit()
                    } else {
                        b.is_ascii_hexdigit()
                    }
                };
                let mut end = *pos;
                while end < input.len() && is_digit(input[end]) && end - *pos < max_digits {
                    end += 1;
                }
                if end == *pos {
                    return Err(mismatch_err(
                        input,
                        *pos,
                        &format!(
                            "期望{}数字",
                            if s.kind == Kind::Dec {
                                "十进制"
                            } else {
                                "十六进制"
                            }
                        ),
                    ));
                }
                let text = std::str::from_utf8(&input[*pos..end])
                    .map_err(|_| "`tpl` 匹配失败：非法 UTF-8 输入".to_string())?;
                let n = u64::from_str_radix(text, radix)
                    .map_err(|_| format!("`tpl` 匹配失败：`{text}` 不是合法数值"))?;
                let max = 1u64 << (s.width * 8);
                if n >= max {
                    return Err(format!(
                        "`tpl` 匹配失败：数值 {n} 超出 {} 位范围 0..{}",
                        s.width * 8,
                        max - 1
                    ));
                }
                *pos = end;
                // 大端编码（低字节在后）
                Ok((0..s.width)
                    .rev()
                    .map(|i| ((n >> (i * 8)) & 0xFF) as u8)
                    .collect())
            }
        }
    }
}

/// 报错：显示输入中失败位置附近的片段。
fn mismatch_err(input: &[u8], pos: usize, expect: &str) -> String {
    let around: String = input
        .iter()
        .skip(pos.saturating_sub(8))
        .take(16)
        .map(|b| *b as char)
        .collect();
    format!("`tpl` 匹配失败：位置 {pos} {expect}，输入附近 `{around}`")
}

/// `tpl(template, input)` 求值入口（eval.rs 值调用分派）。
pub(crate) fn eval_tpl(args: &[Value], span: Span) -> PktResult<Value> {
    let template = match args.first() {
        Some(Value::Str(s)) => s.clone(),
        Some(other) => {
            return Err(Diagnostic::at(
                format!(
                    "`tpl` 模板参数需要字符串字面量，得到 {}",
                    crate::registry::describe(other)
                ),
                span,
            ));
        }
        None => return Err(Diagnostic::at("`tpl` 缺少模板参数", span)),
    };
    let input = args
        .get(1)
        .ok_or_else(|| Diagnostic::at("`tpl` 缺少输入参数", span))?;
    let tpl = Tpl::parse(&template).map_err(|e| Diagnostic::at(e, span))?;
    match input {
        Value::Str(s) => {
            let bytes = tpl
                .match_bytes(s.as_bytes())
                .map_err(|e| Diagnostic::at(e, span))?;
            Ok(crate::eval::bytes_value(bytes))
        }
        Value::List(items) => {
            // 等宽直通：mac(rand_mac()) / 预编码字节（与旧 ip4/ip6/mac 一致）；
            // 含 `%L` 的模板输出宽动态不可算 → 不接受字节列表输入
            let Some(width) = tpl.total_width() else {
                return Err(Diagnostic::at(
                    "`tpl` 模板含动态宽度说明符 `%L`，不接受字节列表输入（字符串按模板解析）",
                    span,
                ));
            };
            let ok = items.len() == width
                && items
                    .iter()
                    .all(|it| matches!(it, Value::Int(i) if (0..=255).contains(i)));
            if ok {
                return Ok(input.clone());
            }
            Err(Diagnostic::at(
                format!(
                    "`tpl` 参数是字节列表但长度与模板输出不符：模板输出 {width} 字节，实际 {} 字节（字符串按模板解析）",
                    items.len()
                ),
                span,
            ))
        }
        other => Err(Diagnostic::at(
            format!(
                "`tpl` 输入参数需要字符串或字节列表，得到 {}",
                crate::registry::describe(other)
            ),
            span,
        )),
    }
}
