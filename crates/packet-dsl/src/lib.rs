//! # packet-dsl — 声明式网络包构建 DSL（`.pkt`）
//!
//! 独立 crate，不依赖 yak 引擎 / Yakit。职责：解析 + 语义分析 → 产出结构化 IR
//! （[`BuildResult`]），由宿主负责序列化与发送。DSL 本身不发包。
//!
//! 快速开始：
//!
//! ```no_run
//! use packet_dsl::semantic::parse_file;
//! use packet_dsl::eval::resolve;
//! use packet_dsl::serialize::{DefaultSerializer, Serializer};
//!
//! let module = parse_file("arp.pkt")?;
//! let built = resolve(&module)?;
//! for pkt in &built.packets {
//!     let bytes = DefaultSerializer::new().serialize(pkt)?;
//!     // 交给宿主发送……
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! 设计文档见仓库内 `DESIGN.md`。

pub mod ast;
pub mod check;
mod codec;
pub mod diag;
pub mod dissect;
pub mod eval;
pub mod ir;
pub mod lexer;
pub mod matchpred;
pub mod parser;
pub mod proto;
pub mod registry;
pub mod semantic;
pub mod serialize;
pub mod stack;
mod tpl;
pub use ast::{SnifferSpec, SnifferValue};
pub use check::check_module;
pub use proto::{
    CtxCond, MatchFn, MatchTarget, MatchVal, ProtoHit, ProtoVal, ResolvedProto, Rule, RuleCond,
    parse_cond, parse_header, parse_proto, proto_registry, set_proto_registry,
};
pub use registry::{Params, builtin_doc, builtin_docs, is_builtin, parse_param_value};

pub use dissect::{DissectReport, dissect};
pub use eval::{
    Globals, PacketSource, ReplyAccess, eval_extract_value, eval_sniffer_value,
    eval_sniffer_value_with_globals, resolve, resolve_sources, resolve_sources_with_globals,
    resolve_sources_with_params, resolve_sources_with_reply, resolve_with_globals,
    resolve_with_params,
};
pub use ir::{BuildResult, Layer, PacketSpec};
pub use matchpred::{
    FVal, Matcher, field_names, layer_field, layer_field_bytes, layer_name, layer_raw_bytes,
    reply_field_names, sniffer_match, sniffer_match_with,
};
pub use semantic::{
    Def, DefinitionSite, LibExport, Module, ResolvedImport, default_libs, lib_exports,
    lib_functions, lib_module_paths, parse_file, parse_file_with_libs, parse_source_at,
    parse_source_at_with_libs, parse_str,
};
pub use serialize::{DefaultSerializer, SerializeError, Serializer};
pub use stack::{StackWarning, StackWarningKind, stack_warnings};

/// DNS 解析器（宿主注入）：域名 → 全部地址。packet-dsl 本身不发网络请求，
/// `dns("host")` 值原语与地址字段（layer src/dst、ipv4/ipv6 字段）的域名回退
/// 经此回调解析；未设置时域名报错（IP 字面量不经过解析器）。
type DnsResolver = Box<dyn Fn(&str) -> Vec<std::net::IpAddr> + Send + Sync>;
static DNS_RESOLVER: std::sync::OnceLock<DnsResolver> = std::sync::OnceLock::new();

/// 注入 DNS 解析器（进程级；重复调用忽略——首个生效）。
pub fn set_dns_resolver(f: impl Fn(&str) -> Vec<std::net::IpAddr> + Send + Sync + 'static) {
    let _ = DNS_RESOLVER.set(Box::new(f));
}

/// 是否已注入解析器（宿主展示/诊断用）。
pub fn dns_resolver_is_set() -> bool {
    DNS_RESOLVER.get().is_some()
}

/// 解析域名（未设置解析器或解析失败 → 空）。
pub(crate) fn dns_lookup(host: &str) -> Vec<std::net::IpAddr> {
    DNS_RESOLVER.get().map(|f| f(host)).unwrap_or_default()
}
