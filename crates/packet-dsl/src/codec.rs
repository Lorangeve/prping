//! vint codec 双向编解码共享实现。
//!
//! 构造（`eval.rs::encode_field_type`）与解析（`proto.rs::decode_field`）共用
//! **同一份实现**（[`VintCodec::encode`] / [`VintCodec::decode`]）——声明数据
//! （[`crate::ast::VintCodec`]）之外，编解码算法也只有一份，杜绝双实现漂移
//! （历史上 LEB128 解码游标不推进的 bug 即漂移所致）。

use crate::ast::{VintCodec, VintEndian};

/// 编码错误（无 span——调用方在错误处拼 `{what}` 标签与 span）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CodecError {
    /// 负数（三个模型都拒绝）。
    Negative(i64),
    /// 超出模型上限（prefix 附带方案说明，table 无）。
    TooBig { max: u64, detail: Option<String> },
}

impl CodecError {
    /// 渲染为错误文案尾部（调用方拼 `{what} {tail}`，如 `字段 `x` 的 vint 参数超出…`）。
    pub(crate) fn message(&self) -> String {
        match self {
            CodecError::Negative(n) => format!("需要非负整数，得到 {n}"),
            CodecError::TooBig { max, detail } => match detail {
                Some(d) => format!("参数超出变长整数上限 0..={max}（{d}）"),
                None => format!("参数超出变长整数上限 0..={max}"),
            },
        }
    }
}

impl VintCodec {
    /// 编码：值 → 字节（最小宽度，确定性；负数/超界 → [`CodecError`]）。
    /// 与解析侧 [`Self::decode`] 共用本实现（构造/解析同一份代码，防漂移）。
    pub(crate) fn encode(&self, n: i64) -> Result<Vec<u8>, CodecError> {
        match self {
            VintCodec::Le128 => {
                // LEB128（base-128 续延位，最小字节数 ≤9B）；负数报错
                if n < 0 {
                    return Err(CodecError::Negative(n));
                }
                let mut out = Vec::new();
                let mut v = n as u64;
                while v >= 0x80 {
                    out.push(((v & 0x7f) as u8) | 0x80);
                    v >>= 7;
                }
                out.push(v as u8);
                Ok(out)
            }
            VintCodec::Prefix {
                prefix_bits,
                widths,
            } => {
                // 前缀宽度表：首字节高 prefix_bits 位 = 宽度索引（大端序），查
                // widths 表得字节数；值 = 余下位（大端）。按列表序取第一个装得
                // 下的（语义保证严格递增 = 最小宽度，确定性）。
                let pb = *prefix_bits as u32;
                let max_w = *widths.iter().max().expect("语义已校验非空");
                let value_bits = 8 * max_w as u32 - pb;
                let max = if value_bits >= 63 {
                    i64::MAX
                } else {
                    (1i64 << value_bits) - 1
                };
                if n < 0 {
                    return Err(CodecError::Negative(n));
                }
                if n > max {
                    return Err(CodecError::TooBig {
                        max: max as u64,
                        detail: Some(format!("{pb} 位前缀，最大宽度 {max_w}B")),
                    });
                }
                for (idx, w) in widths.iter().enumerate() {
                    let vb = 8 * *w as u32 - pb;
                    if (n as u64) < (1u64 << vb) {
                        let full = ((idx as u64) << vb) | (n as u64);
                        let bytes = full.to_be_bytes();
                        return Ok(bytes[8 - *w as usize..].to_vec());
                    }
                }
                unreachable!("范围校验已保证至少一个宽度装得下")
            }
            VintCodec::Table {
                inline_max,
                table,
                endian,
            } => {
                // 内联 + 哨兵表：值 ≤ inline_max 直接 1 字节；否则首字节 = 哨兵
                // （> inline_max），查表得后续字节数，值按 endian 解读。按表序取
                // 第一个装得下的（语义保证宽度严格递增 = 最小宽度）。
                let max_w = *table.iter().map(|(_, w)| w).max().expect("语义已校验非空");
                let max = if max_w >= 8 {
                    i64::MAX
                } else {
                    (1i64 << (8 * max_w as u32)) - 1
                };
                if n < 0 {
                    return Err(CodecError::Negative(n));
                }
                if n > max {
                    return Err(CodecError::TooBig {
                        max: max as u64,
                        detail: None,
                    });
                }
                if n <= *inline_max as i64 {
                    return Ok(vec![n as u8]);
                }
                for (sentinel, w) in table {
                    let cap = if *w == 8 {
                        u64::MAX
                    } else {
                        1u64 << (8 * *w as u32)
                    };
                    if (n as u64) < cap {
                        let mut out = vec![*sentinel];
                        let vb = (n as u64).to_be_bytes();
                        let keep = &vb[8 - *w as usize..];
                        if matches!(endian, VintEndian::Le) {
                            out.extend(keep.iter().rev());
                        } else {
                            out.extend_from_slice(keep);
                        }
                        return Ok(out);
                    }
                }
                unreachable!("范围校验已保证至少一个哨兵宽度装得下")
            }
        }
    }

    /// 解码：字节 → (值, 消费字节数)；非法/越界 → None（调用方回退 raw）。
    /// `bytes` 是当前字段起点起的切片（调用方已按游标切好）。
    pub(crate) fn decode(&self, bytes: &[u8]) -> Option<(i64, usize)> {
        match self {
            VintCodec::Le128 => {
                // LEB128（游标推进——原 Varint 实现循环内不推进 pos，
                // 多字节 varint 必失败，本重构顺带修复）；移位 ≥64 溢出拒绝
                let mut p = 0usize;
                let mut shift = 0u32;
                let mut v = 0u64;
                let mut n = 0usize;
                loop {
                    let b = *bytes.get(p)?;
                    p += 1;
                    n += 1;
                    v |= ((b & 0x7f) as u64) << shift;
                    if b & 0x80 == 0 {
                        break;
                    }
                    shift += 7;
                    if shift >= 64 {
                        return None;
                    }
                }
                Some((v as i64, n))
            }
            VintCodec::Prefix {
                prefix_bits,
                widths,
            } => {
                // 前缀宽度表：首字节高 prefix_bits 位 = 宽度索引（大端序），
                // 查 widths 表得字段字节数；值 = 余下位（大端）。
                let first = *bytes.first()?;
                let pb = *prefix_bits as usize;
                let idx = (first >> (8 - pb)) as usize;
                let w = *widths.get(idx)? as usize;
                let b = bytes.get(..w)?;
                let mut a = [0u8; 8];
                a[8 - w..].copy_from_slice(b);
                let raw = u64::from_be_bytes(a);
                let value_bits = 8 * w - pb;
                let v = raw & ((1u64 << value_bits) - 1);
                Some((v as i64, w))
            }
            VintCodec::Table {
                inline_max,
                table,
                endian,
            } => {
                // 内联 + 哨兵表：首字节 ≤ inline_max = 内联值；否则查表
                // （哨兵 → 后续字节数），值按 endian 解读。
                let first = *bytes.first()?;
                if first <= *inline_max {
                    return Some((first as i64, 1));
                }
                let (_, w) = table.iter().find(|(s, _)| *s == first)?;
                let w = *w as usize;
                // 哨兵占首字节，值字节从第 2 字节起
                let b = bytes.get(..1 + w)?;
                let vb = &b[1..];
                let v = if matches!(endian, VintEndian::Le) {
                    let mut a = [0u8; 8];
                    a[..w].copy_from_slice(vb);
                    u64::from_le_bytes(a)
                } else {
                    let mut a = [0u8; 8];
                    a[8 - w..].copy_from_slice(vb);
                    u64::from_be_bytes(a)
                };
                Some((v as i64, 1 + w))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 三模型双向 roundtrip + 编码最小宽度（decode∘encode = id，构造/解析同实现）。
    #[test]
    fn codec_roundtrip() {
        let quic = VintCodec::Prefix {
            prefix_bits: 2,
            widths: vec![1, 2, 4, 8],
        };
        let bitcoin = VintCodec::Table {
            inline_max: 0xFC,
            table: vec![(0xFD, 2), (0xFE, 4), (0xFF, 8)],
            endian: VintEndian::Le,
        };
        let cbor = VintCodec::Table {
            inline_max: 0x17,
            table: vec![(0x18, 1), (0x19, 2), (0x1A, 4), (0x1B, 8)],
            endian: VintEndian::Be,
        };
        let cases: Vec<(VintCodec, i64)> = vec![
            // le128：0/1/127/128/16383/16384/i64::MAX
            (VintCodec::Le128, 0),
            (VintCodec::Le128, 1),
            (VintCodec::Le128, 127),
            (VintCodec::Le128, 128),
            (VintCodec::Le128, 16383),
            (VintCodec::Le128, 16384),
            (VintCodec::Le128, i64::MAX),
            // prefix：QUIC 标准表各档 + 自定义表
            (quic.clone(), 0),
            (quic.clone(), 63),
            (quic.clone(), 64),
            (quic.clone(), 16383),
            (quic.clone(), 16384),
            (quic.clone(), (1i64 << 62) - 1),
            (
                VintCodec::Prefix {
                    prefix_bits: 1,
                    widths: vec![1, 2],
                },
                127,
            ),
            (
                VintCodec::Prefix {
                    prefix_bits: 1,
                    widths: vec![1, 2],
                },
                128,
            ),
            // table：Bitcoin LE（inline 0xFC + 哨兵 FD/FE/FF → 2/4/8 字节小端）
            (bitcoin.clone(), 0),
            (bitcoin.clone(), 0xFC),
            (bitcoin.clone(), 0x100),
            (bitcoin.clone(), 0x10000),
            (bitcoin.clone(), i64::MAX), // 8 字节档
            // table：CBOR BE（inline 0x17 + 哨兵 18/19/1A/1B → 1/2/4/8 字节大端）
            (cbor.clone(), 0x18),
            (cbor.clone(), 0x100),
            (cbor.clone(), i64::MAX),
        ];
        for (codec, n) in cases {
            let enc = codec
                .encode(n)
                .unwrap_or_else(|e| panic!("encode({n}): {}", e.message()));
            let (v, consumed) = codec.decode(&enc).expect("应能解码");
            assert_eq!(v, n, "decode(encode({n})) 应还原");
            assert_eq!(consumed, enc.len(), "解码消费应等于编码长度");
        }
    }

    /// 编码错误：负数 / 超界（文案尾部与既有字段报错一致）。
    #[test]
    fn codec_errors() {
        assert_eq!(
            VintCodec::Le128.encode(-1).unwrap_err().message(),
            "需要非负整数，得到 -1"
        );
        // prefix 超界：2^62 > 2^62-1（带方案说明）
        let err = VintCodec::Prefix {
            prefix_bits: 2,
            widths: vec![1, 2, 4, 8],
        }
        .encode(1i64 << 62)
        .unwrap_err();
        assert_eq!(
            err.message(),
            "参数超出变长整数上限 0..=4611686018427387903（2 位前缀，最大宽度 8B）"
        );
        // table 负数
        let err = VintCodec::Table {
            inline_max: 0xFC,
            table: vec![(0xFD, 2), (0xFE, 4), (0xFF, 8)],
            endian: VintEndian::Le,
        }
        .encode(-5)
        .unwrap_err();
        assert_eq!(err.message(), "需要非负整数，得到 -5");
        // table 超界：最大宽度 4 字节 → 上限 2^32-1
        let err = VintCodec::Table {
            inline_max: 0xFC,
            table: vec![(0xFD, 2), (0xFE, 4)],
            endian: VintEndian::Le,
        }
        .encode(4_294_967_296i64)
        .unwrap_err();
        assert_eq!(err.message(), "参数超出变长整数上限 0..=4294967295");
    }
}
