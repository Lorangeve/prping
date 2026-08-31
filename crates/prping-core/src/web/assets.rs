//! 前端静态资源来源：两种模式，按 `web-embed` feature 二选一编译。
//!
//! - **UI 目录**（默认）：运行期从 **prping 二进制所在目录**或**启动目录**下的
//!   `UI/` 文件夹读盘（`just dist` 产物布局自带；`just build-web` 同步 workspace
//!   根 `./UI`）。替换文件夹即换 UI，前端与 Rust 编译零耦合，产物体积小、
//!   构建不依赖 node 工具链。
//! - **内嵌**（`--features web-embed`）：rust-embed，debug 构建从磁盘直读
//!   `frontend/dist`（改完前端重跑构建即生效，无需重编），release 构建编译期
//!   内嵌进二进制（单文件分发）。
//!
//! `frontend/dist` 只提交 `.gitkeep` 占位，未构建前端时 `cargo check/build`
//! （含 web-embed）仍可用（运行期 404/503 给构建提示）。
//!
//! 路径安全（两种模式共用同一校验）：`/` → `index.html`，其余剥前导 `/` 后
//! **逐段校验**——空段（`//`）、点开头（`.`/`..`/`.gitkeep` 等隐藏文件）、
//! 反斜杠与冒号（Windows 分隔符/盘符/ADS）一律拒绝，余下必为单一路径组件，
//! 拼接后不可能逃出资源根目录。

/// `/` 与 `/index.html` → `index.html`；其余剥前导 `/` 并逐段校验。
fn sanitize_key(path: &str) -> Option<&str> {
    let key = match path {
        "/" | "/index.html" => "index.html",
        p => p.strip_prefix('/')?,
    };
    if key.is_empty() {
        return None;
    }
    for seg in key.split('/') {
        if seg.is_empty() || seg.starts_with('.') || seg.contains(['\\', ':']) {
            return None;
        }
    }
    Some(key)
}

fn mime_of(key: &str) -> String {
    mime_guess::from_path(key)
        .first_raw()
        .unwrap_or("application/octet-stream")
        .to_string()
}

/// 按路径取资源。返回 (内容, MIME)。
pub(crate) fn lookup(path: &str) -> Option<(Vec<u8>, String)> {
    imp::lookup(sanitize_key(path)?)
}

/// 前端资源是否缺失：UI 目录模式 = 找不到 UI 目录；内嵌模式 = dist 无 index.html。
pub(crate) fn index_missing() -> bool {
    imp::index_missing()
}

/// 资源来源描述（启动横幅 `ui:` 行，已本地化）。
pub(crate) fn source_label() -> String {
    imp::source_label()
}

/// 静态资源缺失时的 503 提示文案（按模式给对应的构建/放置指引）。
pub(crate) fn missing_hint() -> String {
    imp::missing_hint()
}

// ── UI 目录模式（默认）───────────────────────────────────────
#[cfg(not(feature = "web-embed"))]
mod imp {
    use std::path::{Path, PathBuf};

    use super::mime_of;

    /// UI 目录名（位于二进制所在目录或启动目录下）。
    pub(super) const UI_DIR: &str = "UI";

    /// 候选 UI 目录（按优先级）：1) prping 二进制所在目录/UI（`just dist` 发布
    /// 布局，与 cwd 无关）；2) 启动目录/UI（源码树开发：`just build-web` 同步）。
    fn candidates() -> Vec<PathBuf> {
        let mut dirs = Vec::with_capacity(2);
        // current_exe → 其所在目录/UI（链式写法：避免嵌套 if-let 触发 collapsible_if）
        let exe_dir = std::env::current_exe()
            .ok()
            .as_deref()
            .and_then(Path::parent)
            .map(|d| d.join(UI_DIR));
        dirs.extend(exe_dir);
        if let Ok(cwd) = std::env::current_dir() {
            dirs.push(cwd.join(UI_DIR));
        }
        dirs
    }

    /// 首个含 index.html 的候选目录。每请求即时解析（不缓存）：目录可后补、
    /// 文件改动即生效——回环工具，每请求两三次 stat 无所谓。
    fn root() -> Option<PathBuf> {
        candidates()
            .into_iter()
            .find(|d| d.join("index.html").is_file())
    }

    pub(super) fn lookup(key: &str) -> Option<(Vec<u8>, String)> {
        let root = root()?;
        Some((load_from(&root, Path::new(key))?, mime_of(key)))
    }

    pub(super) fn index_missing() -> bool {
        root().is_none()
    }

    pub(super) fn source_label() -> String {
        match root() {
            Some(dir) => rust_i18n::t!("web.ui_dir", dir = dir.display().to_string()).to_string(),
            None => rust_i18n::t!("web.ui_dir_missing").to_string(),
        }
    }

    pub(super) fn missing_hint() -> String {
        rust_i18n::t!("web.ui_missing").to_string()
    }

    /// 从指定根读盘：`root/rel` 仅接受普通文件（目录/缺失 → None）。
    /// 独立成函数供测试注入临时根，不依赖进程 cwd。
    pub(super) fn load_from(root: &Path, rel: &Path) -> Option<Vec<u8>> {
        let path = root.join(rel);
        if !path.is_file() {
            return None;
        }
        std::fs::read(path).ok()
    }
}

// ── 内嵌模式（web-embed feature）──────────────────────────────
#[cfg(feature = "web-embed")]
mod imp {
    use rust_embed::RustEmbed;

    use super::mime_of;

    #[derive(RustEmbed)]
    // 相对 CARGO_MANIFEST_DIR（crates/prping-core）→ workspace 根的 frontend/dist。
    // 目录里只提交 .gitkeep 占位：未构建前端时 cargo check/build 仍可用
    // （运行期 404/503 给构建提示）。
    #[folder = "../../frontend/dist"]
    struct Assets;

    pub(super) fn lookup(key: &str) -> Option<(Vec<u8>, String)> {
        let file = Assets::get(key)?;
        Some((file.data.to_vec(), mime_of(key)))
    }

    pub(super) fn index_missing() -> bool {
        Assets::get("index.html").is_none()
    }

    pub(super) fn source_label() -> String {
        if cfg!(debug_assertions) {
            rust_i18n::t!("web.ui_embedded_debug").to_string()
        } else {
            rust_i18n::t!("web.ui_embedded").to_string()
        }
    }

    pub(super) fn missing_hint() -> String {
        rust_i18n::t!("web.frontend_missing").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_mapping() {
        assert_eq!(sanitize_key("/"), Some("index.html"));
        assert_eq!(sanitize_key("/index.html"), Some("index.html"));
        assert_eq!(
            sanitize_key("/assets/app.a1b2c3.js"),
            Some("assets/app.a1b2c3.js")
        );
        // 缺前导 /
        assert_eq!(sanitize_key("assets/app.js"), None);
        assert_eq!(sanitize_key(""), None);
    }

    #[test]
    fn key_rejects_traversal_and_specials() {
        // 目录穿越
        assert_eq!(sanitize_key("/../etc/passwd"), None);
        assert_eq!(sanitize_key("/a/../../b"), None);
        // 当前段
        assert_eq!(sanitize_key("/a/./b"), None);
        // 隐藏文件（.gitkeep / .git 内部文件）
        assert_eq!(sanitize_key("/.gitkeep"), None);
        assert_eq!(sanitize_key("/.git/config"), None);
        // Windows 反斜杠分隔符（UI 目录模式下 join 可能被当分隔符解释）
        assert_eq!(sanitize_key("/a\\..\\..\\x"), None);
        // 盘符 / NTFS 备用数据流
        assert_eq!(sanitize_key("/C:/boot.ini"), None);
        assert_eq!(sanitize_key("/file.txt:hidden"), None);
        // 空段（//x、尾部 /）
        assert_eq!(sanitize_key("//x"), None);
        assert_eq!(sanitize_key("/x/"), None);
    }

    // 读盘路径：注入临时根验证往返，不依赖进程 cwd
    #[cfg(not(feature = "web-embed"))]
    #[test]
    fn disk_read_roundtrip_and_misses() {
        use std::path::Path;

        let root = std::env::temp_dir().join(format!("prping-ui-test-{}", std::process::id()));
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::write(root.join("index.html"), b"<html>ok</html>").unwrap();
        std::fs::write(root.join("assets/app.js"), b"1").unwrap();

        assert_eq!(
            imp::load_from(&root, Path::new("index.html")).as_deref(),
            Some(&b"<html>ok</html>"[..])
        );
        assert_eq!(
            imp::load_from(&root, Path::new("assets/app.js")).as_deref(),
            Some(&b"1"[..])
        );
        // 目录不可当文件读；点段键在 sanitize_key 已拒绝
        assert_eq!(imp::load_from(&root, Path::new("assets")), None);
        assert_eq!(imp::load_from(&root, Path::new("missing.js")), None);

        let _ = std::fs::remove_dir_all(&root);
    }
}
