//! 使用手册（`--help-pkg`）：内嵌双语 markdown、章节解析与跳转匹配、pager 自动分页。
//!
//! - 手册源：`docs/manual-zh.md` / `docs/manual-en.md`（`#` 文档标题 + `## N. 标题` 章节）。
//! - `--help-pkg`（无参数）→ 全文，tty 时经 pager（`$PAGER`，默认 `less -R`）自动分页；
//!   `--help-pkg 目录标题` → 按编号 / 标题前缀 / 标题包含匹配章节，单命中打印、多命中列候选。

#[cfg(unix)]
use std::io::{IsTerminal, Write};

/// 中文手册（内嵌）。
pub const MANUAL_ZH: &str = include_str!("../../../docs/manual-zh.md");
/// 英文手册（内嵌）。
pub const MANUAL_EN: &str = include_str!("../../../docs/manual-en.md");

/// 按 locale 选择手册（`zh*` → 中文，否则英文）。
pub fn manual_for(locale: &str) -> &'static str {
    if locale.starts_with("zh") {
        MANUAL_ZH
    } else {
        MANUAL_EN
    }
}

/// 手册里的一个章节（`## N. 标题`，正文到下一个同级标题前）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub number: String,
    pub title: String,
    pub body: String,
}

/// 解析手册的全部章节（编号按 `## N. ` 形式；非编号标题如 `## 目录` 忽略）。
pub fn sections(manual: &str) -> Vec<Section> {
    let mut out = Vec::new();
    let mut cur: Option<(String, String, Vec<String>)> = None;
    for line in manual.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            let (num, title) = match rest.split_once(". ") {
                Some((n, t)) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => {
                    (n.to_string(), t.trim().to_string())
                }
                _ => {
                    // 非编号标题（如 `## 目录`）：若在章节内则当正文行
                    if let Some((_, _, lines)) = &mut cur {
                        lines.push(line.to_string());
                    }
                    continue;
                }
            };
            if let Some((num, title, lines)) = cur.take() {
                out.push(Section {
                    number: num,
                    title,
                    body: lines.join("\n"),
                });
            }
            cur = Some((num, title, vec![line.to_string()]));
        } else if let Some((_, _, lines)) = &mut cur {
            lines.push(line.to_string());
        }
    }
    if let Some((num, title, lines)) = cur {
        out.push(Section {
            number: num,
            title,
            body: lines.join("\n"),
        });
    }
    out
}

/// 目录：`N. 标题` 列表（供 `--help-pkg` 空查询提示 / 跳转无命中时展示）。
pub fn toc(manual: &str) -> String {
    sections(manual)
        .iter()
        .map(|s| format!("{:>2}. {}", s.number, s.title))
        .collect::<Vec<_>>()
        .join("\n")
}

/// 按查询匹配章节：编号（`16` / `16.`）或标题（前缀 / 包含，忽略大小写）。
/// 返回全部命中（由调用方决定单命中打印 / 多命中列候选）。
pub fn find_sections(manual: &str, query: &str) -> Vec<Section> {
    let q = query.trim();
    let q_lower = q.to_lowercase();
    let q_num = q.trim_end_matches('.').trim();
    sections(manual)
        .into_iter()
        .filter(|s| {
            if !s.number.is_empty() && (s.number == q_num || s.number == q) {
                return true;
            }
            let t = s.title.to_lowercase();
            if !q_lower.is_empty() && (t.starts_with(&q_lower) || t.contains(&q_lower)) {
                return true;
            }
            false
        })
        .collect()
}

/// pager 自动分页：unix + tty → `$PAGER`（默认 `less -R`），否则直接输出全文。
pub fn print_paged(text: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    if std::io::stdout().is_terminal() {
        let pager = std::env::var("PAGER").unwrap_or_else(|_| "less -R".to_string());
        let mut parts = pager.split_whitespace();
        let prog = parts.next().unwrap_or("less");
        let args: Vec<&str> = parts.collect();
        if let Ok(mut child) = std::process::Command::new(prog)
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(text.as_bytes())?;
            }
            let _ = child.wait();
            return Ok(());
        }
        // pager 启动失败 → 落到直接输出
    }
    #[cfg(not(unix))]
    let _ = text; // Windows：无 less，直接输出（PAGER 可另行配置，见手册 FAQ）
    print!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zh_has_25_sections_and_toc() {
        let secs = sections(MANUAL_ZH);
        assert!(secs.len() >= 25, "zh 章节数：{}", secs.len());
        assert_eq!(secs[0].number, "1");
        assert_eq!(secs[0].title, "简介与特性");
        assert!(secs[0].body.contains("psping"), "正文应含内容");
        assert!(MANUAL_ZH.contains("## 目录"));
        // 编号连续 1..=N
        for (i, s) in secs.iter().enumerate() {
            assert_eq!(s.number, (i + 1).to_string(), "编号应连续");
        }
    }

    #[test]
    fn zh_en_numbering_identical() {
        let zh: Vec<String> = sections(MANUAL_ZH)
            .iter()
            .map(|s| s.number.clone())
            .collect();
        let en: Vec<String> = sections(MANUAL_EN)
            .iter()
            .map(|s| s.number.clone())
            .collect();
        assert_eq!(zh, en, "双语章节编号必须一致");
        assert!(!zh.is_empty());
    }

    #[test]
    fn find_by_number() {
        let hits = find_sections(MANUAL_ZH, "16");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].title.contains("MTU"), "{}", hits[0].title);
        // "16." 也可
        assert_eq!(find_sections(MANUAL_ZH, "16.").len(), 1);
    }

    #[test]
    fn find_by_title_prefix_and_substring() {
        assert_eq!(find_sections(MANUAL_ZH, "安装").len(), 1);
        assert_eq!(
            find_sections(MANUAL_ZH, "安装与").len(),
            0,
            "标题是「安装」，前缀不匹配则无命中"
        );
        // 包含匹配（忽略大小写）
        let en_hits = find_sections(MANUAL_EN, "mtu");
        assert!(
            en_hits.iter().any(|s| s.title.contains("MTU")),
            "en 应命中 MTU 章：{:?}",
            en_hits.iter().map(|s| &s.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn find_multiple_and_none() {
        // "Ping" 命中 ICMP/TCP/UDP Ping 三章
        let hits = find_sections(MANUAL_ZH, "ping");
        assert!(hits.len() >= 3, "ping 应多命中：{}", hits.len());
        // 无命中
        assert!(find_sections(MANUAL_ZH, "不存在的章节").is_empty());
    }

    #[test]
    fn toc_lists_all() {
        let t = toc(MANUAL_ZH);
        assert!(t.starts_with(" 1. 简介与特性"), "{t}");
        assert!(t.lines().count() >= 25);
    }

    #[test]
    fn manual_for_locale() {
        assert_eq!(manual_for("zh-CN"), MANUAL_ZH);
        assert_eq!(manual_for("zh_CN"), MANUAL_ZH);
        assert_eq!(manual_for("en-US"), MANUAL_EN);
        assert_eq!(manual_for("fr-FR"), MANUAL_EN);
    }
}
