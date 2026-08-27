//! 让 cargo 追踪 locale 文件变更。
//!
//! rust-i18n 的 `i18n!("locales")` 宏在**展开期**读取 `locales/*.yml` 并把文案
//! 内嵌进二进制，但 cargo 不感知宏读过的文件——增量构建时改 yml 不会触发
//! 重编译，产物里一直是旧文案。用 `rerun-if-changed` 声明依赖，yml 一改就
//! 重编译本 crate，文案修改即时生效。

fn main() {
    println!("cargo:rerun-if-changed=locales/zh-CN.yml");
    println!("cargo:rerun-if-changed=locales/en-US.yml");
}
