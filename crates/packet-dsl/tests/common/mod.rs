//! 测试公共工具：临时目录（import 测试用）。
#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "packet-dsl-test-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn write(&self, rel: &str, content: &str) -> PathBuf {
        let p = self.0.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 收集真实 eng_lib 的 proto（**不注册**；调用方合并自定义 proto 后一次
/// `set_proto_registry`——OnceLock 首次生效，须保证同一测试文件内注册内容一致）。
pub fn collect_eng_lib_protos() -> Vec<packet_dsl::ResolvedProto> {
    let mut protos = Vec::new();
    for dir in packet_dsl::default_libs() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().is_none_or(|x| x != "pkt") {
                continue;
            }
            let Ok(m) = packet_dsl::parse_file_with_libs(&path, &[]) else {
                continue;
            };
            for p in m.protos {
                protos.push(packet_dsl::ResolvedProto {
                    name: p.name.clone(),
                    layer: p.layer.clone(),
                    rule: p.rule.clone(),
                    params: p
                        .params
                        .iter()
                        .map(|x| packet_dsl::ast::FuncParam {
                            name: x.name.clone(),
                            span: x.span,
                            default: x.default.clone(),
                        })
                        .collect(),
                    fields: p.fields.clone(),
                });
            }
        }
    }
    protos
}

/// 注册真实 eng_lib 的 proto 表（OnceLock 幂等）。
///
/// dissect 契约：层头解析只走 proto 注册表（`#[proto(kind=...)]` pkt 声明即解析，
/// Rust 手写 parse_* 已退役），任何依赖 dissect 的测试必须先调用本函数注册
///（与宿主 `ensure_proto_registry` 一致：文件模式解析，自动带 eng_lib）。
pub fn register_eng_lib() {
    let protos = collect_eng_lib_protos();
    assert!(
        protos.iter().any(|p| p.name == "eth"),
        "eng_lib headers.pkt 应注册 eth proto（注册了 {} 个 proto）",
        protos.len()
    );
    packet_dsl::set_proto_registry(protos);
}
