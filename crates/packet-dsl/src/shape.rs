//! 字节形状表（唯一权威）：值层"什么算字节、多宽"的分类规则。
//!
//! 收敛背景：此前"同宽直通/字节直喂"规则散落多处——`check.rs` 的静态宽度表、
//! `eval.rs` 的定宽整数分派与 `is_bytes_list` 启发式、`registry.rs`/`eval.rs`
//! 各自的字节列表校验循环。本模块把它们收敛为一张表，两个消费方共用：
//! - **求值期 coercer**（`eval.rs`/`registry.rs`）：分类 → 字节或报错；
//! - **静态形状检查**（`check.rs`）：同一分类 → 提前诊断（None = 跳过，零误报）。
//!
//! 两档分类刻意分开（语义不同，合并会悄悄改变行为）：
//! - [`is_flat_numeric`]：**类型档**，只看元素是不是 Int/Hex，不管范围——
//!   供 proto 重复区"字节直喂 vs 元素列表"的分档决策（范围违规随后由 coercer 报）；
//! - [`flat_bytes_checked`]：**coercer 档**，全部元素 0..255 才算字节，
//!   返回首个违规元素（报错文案属地归调用方）。
//!
//! 宽度权威仍是 `DESIGN.md` §6.3（语义）与 `GRAMMAR.md` §4.6（可见面）；
//! 本模块是它们的执行权威，改动须同步（doc-sync 门禁）。

use crate::ast::Value;

/// 定宽整数原语 → (字节数, 数值上限, 是否小端)。
///
/// 与 `eval.rs::encode_int_bytes`（值原语/字段编码共用）和 `check.rs` 范围检查
/// 同一张表；8 字节按 i64::MAX 封顶（无符号 2^64 超出 i64 表示）。
pub(crate) fn int_width(name: &str) -> Option<(usize, u64, bool)> {
    let (width, little) = match name {
        "u8" => (1, false),
        "be16" | "le16" => (2, name == "le16"),
        "be32" | "le32" => (4, name == "le32"),
        "be64" | "le64" => (8, name == "le64"),
        _ => return None,
    };
    let max = if width == 8 {
        1u64 << 63
    } else {
        1u64 << (width * 8)
    };
    Some((width, max, little))
}

/// 标准库地址值函数（eng_lib，体为 tpl）→ 字节宽度（等宽直通）。
pub(crate) fn std_addr_width(name: &str) -> Option<usize> {
    match name {
        "ip4" => Some(4),
        "ip6" => Some(16),
        "mac" => Some(6),
        _ => None,
    }
}

/// 类型档：列表元素全部为 Int/Hex（**不管 0..255 范围**）。
/// 仅用于"字节直喂 vs 元素列表"决策（proto rest/list 重复区等）；
/// 范围校验属 coercer 档（[`flat_bytes_checked`]）。
pub(crate) fn is_flat_numeric(items: &[Value]) -> bool {
    items
        .iter()
        .all(|x| matches!(x, Value::Int(_) | Value::Hex(_)))
}

/// 单个值的字节形态：合法字节（0..255 的 Int/Hex）→ Some(u8)。
fn byte_item(v: &Value) -> Option<u8> {
    match v {
        Value::Int(i) if (0..=255).contains(i) => Some(*i as u8),
        Value::Hex(h) if *h <= 255 => Some(*h as u8),
        _ => None,
    }
}

/// coercer 档：全部元素为合法字节 → `Ok(字节列表)`；否则 `Err(首个违规元素)`。
/// 报错文案属地归调用方（eval 值上下文与 registry 层参数路径措辞不同，
/// 但"什么算字节"必须一致——即本函数）。
pub(crate) fn flat_bytes_checked(items: &[Value]) -> Result<Vec<u8>, &Value> {
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match byte_item(it) {
            Some(b) => out.push(b),
            None => return Err(it),
        }
    }
    Ok(out)
}

/// 静态可算的产字节宽度：字面量/封闭原语 → `Some(n)`，含未知成分 → `None`
/// （求值期 coercer 接管；静态检查侧 None = 跳过，零误报）。
/// 字符串 = 字节上下文的 UTF-8 编码（`raw("abc")` ≡ `b"abc"`）。
pub(crate) fn fixed_width(v: &Value) -> Option<usize> {
    match v {
        Value::Str(s) => Some(s.len()),
        Value::List(items) => {
            let mut n = 0usize;
            for it in items {
                // 语义 = 元素个数（不是字节值之和）；非法元素 → None
                byte_item(it)?;
                n += 1;
            }
            Some(n)
        }
        Value::Call { name, args, .. } => match name.as_str() {
            "u8" => Some(1),
            "be16" | "le16" => Some(2),
            "be32" | "le32" => Some(4),
            "be64" | "le64" => Some(8),
            "cksum" => Some(2),
            "md5" => Some(16),
            "sha1" => Some(20),
            "sha256" => Some(32),
            "rand_bytes" | "pad" => match args.first().and_then(literal_int) {
                Some(n) if (0..=65535).contains(&n) => Some(n as usize),
                _ => None,
            },
            "raw" => match args.first() {
                Some(Value::Str(s)) => Some(s.len()),
                _ => None,
            },
            "concat" => {
                let mut n = 0;
                for a in args {
                    n += fixed_width(a)?;
                }
                Some(n)
            }
            other => std_addr_width(other),
        },
        _ => None,
    }
}

/// 整数字面量（Int/Hex 同进数值上下文）→ i64。
pub(crate) fn literal_int(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => Some(*i),
        Value::Hex(h) => Some(*h as i64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{fixed_width, flat_bytes_checked, int_width, is_flat_numeric};
    use crate::ast::Value;
    use crate::parser::parse_value_expr;

    fn v(src: &str) -> Value {
        parse_value_expr(src).expect("测试表达式应可解析")
    }

    #[test]
    fn int_width_table() {
        assert_eq!(int_width("u8"), Some((1, 1 << 8, false)));
        assert_eq!(int_width("be16"), Some((2, 1 << 16, false)));
        assert_eq!(int_width("le16"), Some((2, 1 << 16, true)));
        assert_eq!(int_width("be32"), Some((4, 1u64 << 32, false)));
        assert_eq!(int_width("le64"), Some((8, 1u64 << 63, true)));
        assert_eq!(int_width("ip4"), None, "地址值函数不是定宽整数原语");
    }

    #[test]
    fn flat_numeric_vs_flat_bytes_two_tiers() {
        assert!(is_flat_numeric(&[Value::Int(1), Value::Hex(0x1FF)]));
        assert!(matches!(
            flat_bytes_checked(&[Value::Int(1), Value::Hex(0x1FF)]),
            Err(Value::Hex(0x1FF))
        ));
        assert_eq!(
            flat_bytes_checked(&[Value::Int(1), Value::Hex(0xFE)]),
            Ok(vec![1, 0xFE])
        );
    }

    #[test]
    fn fixed_width_closed_primitives() {
        assert_eq!(fixed_width(&v("u8(0)")), Some(1));
        assert_eq!(fixed_width(&v("cksum(raw(\"ab\"))")), Some(2));
        assert_eq!(fixed_width(&v("md5(raw(\"x\"))")), Some(16));
        assert_eq!(fixed_width(&v("sha1(raw(\"x\"))")), Some(20));
        assert_eq!(fixed_width(&v("sha256(raw(\"x\"))")), Some(32));
        assert_eq!(fixed_width(&v("rand_bytes(100)")), Some(100));
        assert_eq!(fixed_width(&v("pad(0)")), Some(0));
        assert_eq!(fixed_width(&v("hex(\"deadbeef\")")), Some(4));
        assert_eq!(fixed_width(&v("concat(raw(\"abc\"), u8(0))")), Some(4));
        assert_eq!(fixed_width(&v("ip4(\"1.2.3.4\")")), Some(4));
        assert_eq!(fixed_width(&v("mac(\"aa:bb:cc:dd:ee:ff\")")), Some(6));
    }

    #[test]
    fn fixed_width_unknown_is_none() {
        assert_eq!(fixed_width(&v("params(\"x\")")), None);
        assert_eq!(fixed_width(&v("some_func(1)")), None);
        assert_eq!(fixed_width(&v("rand_bytes(params(\"n\"))")), None);
        assert_eq!(fixed_width(&v("1")), None, "数值不是字节");
    }
}
