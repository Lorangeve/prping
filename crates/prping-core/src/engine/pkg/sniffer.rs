//! Sniffer 匹配：由 `.pkt` 的 `sniffer:` 段构建回包/监听匹配器。
//!
//! 匹配器本体已下沉 packet-dsl `matchpred`（与 `#[rule]` 共享字段取值内核；
//! 支持 `and`/`or`/`not` 组合、`ne` 不等、`mask`/`startswith`/`endswith`/`contains`
//! 字节谓词、跨层 AND、`SentField` 发包字段引用）。本模块保留旧公开名与宿主
//! API 形态（`SnifferMatcher`/`sniffer_match`/`sniffer_match_with`），内部
//! 直接转发 packet-dsl，避免历史调用点全部改名。

pub use packet_dsl::matchpred::{
    FVal, Matcher as SnifferMatcher, field_names as sniffer_field_names,
    layer_field as sniffer_extract, layer_field_bytes as field_bytes, layer_name as layer_kind,
    reply_field_names, sniffer_match, sniffer_match_with,
};
