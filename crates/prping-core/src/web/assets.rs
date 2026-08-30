//! 内嵌前端静态资源（rust-embed）。
//!
//! debug 构建从磁盘直读 `frontend/dist`（改完前端重跑构建即生效，无需重编）；
//! release 构建编译期内嵌进二进制（单文件分发）。目录里只提交 `.gitkeep` 占位，
//! 未构建前端时 `cargo check/build` 仍可用（运行期 404/503 给构建提示）。

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
// 相对 CARGO_MANIFEST_DIR（crates/prping-core）→ workspace 根的 frontend/dist
#[folder = "../../frontend/dist"]
struct Assets;

/// 按路径取资源：`/` → `index.html`；其余剥掉前导 `/` 精确匹配键名。
/// 点段（`.gitkeep`、隐藏文件）一律拒绝。返回 (内容, MIME)。
pub(crate) fn lookup(path: &str) -> Option<(Vec<u8>, String)> {
    let key = match path {
        "/" | "/index.html" => "index.html",
        p => p.strip_prefix('/')?,
    };
    if key.split('/').any(|seg| seg.starts_with('.')) {
        return None;
    }
    let file = Assets::get(key)?;
    let mime = mime_guess::from_path(key)
        .first_raw()
        .unwrap_or("application/octet-stream")
        .to_string();
    Some((file.data.to_vec(), mime))
}

/// 前端是否尚未构建（无 index.html）。
pub(crate) fn index_missing() -> bool {
    Assets::get("index.html").is_none()
}
