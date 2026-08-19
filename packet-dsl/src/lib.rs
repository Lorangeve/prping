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
pub mod diag;
pub mod dissect;
pub mod eval;
pub mod ir;
pub mod lexer;
pub mod parser;
pub mod registry;
pub mod semantic;
pub mod serialize;
pub use ast::{SnifferSpec, SnifferValue};
pub use registry::{Params, builtin_doc, builtin_docs, is_builtin};

pub use dissect::{DissectReport, dissect};
pub use eval::{
    PacketSource, resolve, resolve_sources, resolve_sources_with_params, resolve_with_params,
};
pub use ir::{BuildResult, Layer, PacketSpec};
pub use semantic::{
    Def, LibExport, Module, ResolvedImport, default_libs, lib_exports, parse_file,
    parse_file_with_libs, parse_source_at, parse_source_at_with_libs, parse_str,
};
pub use serialize::{DefaultSerializer, SerializeError, Serializer};

/// DNS 解析器（宿主注入）：域名 → 全部地址。packet-dsl 本身不发网络请求，
/// `dns("host")` 值原语与 `ip4/ip6("host")` 域名回退经此回调解析；未设置时报错。
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
