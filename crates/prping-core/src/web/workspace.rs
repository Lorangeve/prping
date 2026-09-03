//! 工作区目录：默认 examples（发现方法与 UI/ 一致），可从页面打开自定义文件夹。
//!
//! 与库浏览（只读）相对，工作区内的 .pkt/.pktl 文件**可写**（保存/删除/新建）。
//! 写操作的安全边界：
//!
//! - 相对路径逐段校验（与 assets.rs 的 sanitize_key 同一风格）：空段、点段
//!   （./../隐藏文件）、反斜杠、冒号（盘符/ADS）一律拒绝；
//! - 拼接后 canonicalize 并断言仍位于工作区根内（防符号链接逃逸）；
//! - 只接受 .pkt/.pktl 文件（Windows 保留设备名一并拒绝）；
//! - 删除：文件直接删，目录递归删（remove_dir_all）——路径仍走同一条校验链；
//! - 单文件内容上限 MAX_SAVE_TEXT。
//!
//! 发现顺序（default_workspace）：**二进制所在目录/examples → 启动目录/examples**，
//! 与 UI 目录（assets.rs）和 lib 目录（packet_dsl::default_libs）的就近查找一致——
//! just dist 的产物布局 {prping, lib/, examples/, UI/} 就地可用。

use std::path::{Path, PathBuf};

use rust_i18n::t;

use super::code;
use super::coded;

/// 默认工作区目录名（位于二进制所在目录或启动目录下）。
const WORKSPACE_DIR: &str = "examples";

/// 保存文本上限（编辑器内存文本；与 LSP 单帧上限同量级的小值）。
pub(crate) const MAX_SAVE_TEXT: usize = 4 * 1024 * 1024;

/// 目录树条目与递归深度上限（防异常目录树耗内存/卡顿）。
const MAX_TREE_ENTRIES: usize = 4096;
/// 条目路径最大段数（更深层不列出；walk 递归参数 = 段数 - 1，故 >= 截断）。
const MAX_TREE_DEPTH: usize = 8;

/// 相对路径总长上限。
const MAX_REL_LEN: usize = 512;

/// 默认工作区：首个存在的候选目录（二进制目录/examples → 启动目录/examples）。
pub(crate) fn default_workspace() -> Option<PathBuf> {
    candidates().into_iter().find(|d| d.is_dir())
}

/// 候选工作区目录（按优先级），与 assets.rs 的 UI 目录候选同构。
fn candidates() -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(2);
    let exe_dir = std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(Path::parent)
        .map(|d| d.join(WORKSPACE_DIR));
    dirs.extend(exe_dir);
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join(WORKSPACE_DIR));
    }
    dirs
}

/// 目录树条目（path 为工作区相对路径，'/' 分隔；dir = 目录项；pkt = .pkt/.pktl）。
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TreeEntry {
    pub(crate) path: String,
    pub(crate) dir: bool,
    pub(crate) pkt: bool,
}

/// 递归列目录树（目录在前、字典序；跳过隐藏项与符号链接；条目/深度有上限）。
pub(crate) fn tree(root: &Path) -> Vec<TreeEntry> {
    let mut out = Vec::new();
    walk(root, "", 0, &mut out);
    out
}

fn walk(dir: &Path, prefix: &str, depth: usize, out: &mut Vec<TreeEntry>) {
    if depth >= MAX_TREE_DEPTH || out.len() >= MAX_TREE_ENTRIES {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for e in entries.flatten() {
        // 不跟随符号链接：链接项一律跳过（读写最终仍有 canonicalize 根内断言兜底）
        let Ok(ft) = e.file_type() else { continue };
        let Ok(name) = e.file_name().into_string() else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let path = e.path();
        if ft.is_dir() {
            dirs.push((name, path));
        } else if ft.is_file() {
            files.push((name, path));
        }
    }
    dirs.sort_by(|a, b| a.0.cmp(&b.0));
    files.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, path) in dirs {
        if out.len() >= MAX_TREE_ENTRIES {
            return;
        }
        let rel = join_rel(prefix, &name);
        out.push(TreeEntry {
            path: rel.clone(),
            dir: true,
            pkt: false,
        });
        walk(&path, &rel, depth + 1, out);
    }
    for (name, _) in files {
        if out.len() >= MAX_TREE_ENTRIES {
            return;
        }
        out.push(TreeEntry {
            path: join_rel(prefix, &name),
            dir: false,
            pkt: is_pkt_file(&name),
        });
    }
}

fn join_rel(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

/// 读工作区文件大小上限：误点大文件（pcap/日志）先拒绝，不整读进内存后才判二进制
/// （save 上限 MAX_SAVE_TEXT 的读侧对称约束）。
const MAX_READ_BYTES: u64 = 8 * 1024 * 1024;
/// 二进制探测窗口：前 8KB 含 NUL 即按二进制拒绝（UTF-8 文本不含 NUL）。
const BINARY_PROBE: u64 = 8 * 1024;

/// 读工作区文件（任意扩展名；二进制/非 UTF-8 → 明确报错而非乱码）。
pub(crate) fn read_file(root: &Path, rel: &str) -> anyhow::Result<String> {
    let path = resolve_in_root(root, rel, false)?;
    let meta = std::fs::metadata(&path)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_read_failed", err = e.to_string())))?;
    if !meta.is_file() {
        anyhow::bail!(coded(code::NOT_FOUND, t!("web.ws_not_file").to_string()));
    }
    if meta.len() > MAX_READ_BYTES {
        anyhow::bail!(coded(
            code::TOO_LARGE,
            t!("web.ws_read_too_large", max = MAX_READ_BYTES).to_string()
        ));
    }
    // 前 8KB 探 NUL：二进制提前拒绝，避免整读后才发现不可显示
    let probe_len = meta.len().min(BINARY_PROBE) as usize;
    let mut f = std::fs::File::open(&path)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_read_failed", err = e.to_string())))?;
    use std::io::Read;
    let mut probe = vec![0u8; probe_len];
    f.read_exact(&mut probe)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_read_failed", err = e.to_string())))?;
    if probe.contains(&0) {
        anyhow::bail!(coded(code::BINARY, t!("web.ws_binary").to_string()));
    }
    drop(f);
    let bytes = std::fs::read(&path)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_read_failed", err = e.to_string())))?;
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("{}", t!("web.ws_binary")))
}

/// 保存工作区文件（任意扩展名；新建或覆盖；临时文件 + rename 保证不落半个文件）。
pub(crate) fn save_file(root: &Path, rel: &str, text: &str) -> anyhow::Result<()> {
    if text.len() > MAX_SAVE_TEXT {
        anyhow::bail!(coded(
            code::TOO_LARGE,
            t!("web.ws_too_large", max = MAX_SAVE_TEXT).to_string()
        ));
    }
    let path = resolve_in_root(root, rel, false).or_else(|_| {
        // 新建语义：父目录缺失时创建目录链后重走常规解析。validate_rel 已保证
        // 相对路径词法安全（无点段/反斜杠/冒号）；重解析的 canonicalize + 根内
        // 断言兜底符号链接逃逸。
        let root_canon = std::fs::canonicalize(root)
            .map_err(|e| anyhow::anyhow!(t!("web.ws_save_failed", err = e.to_string())))?;
        let dir = validate_rel(rel, false)
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf));
        if let Some(d) = dir {
            std::fs::create_dir_all(root_canon.join(d))
                .map_err(|e| anyhow::anyhow!(t!("web.ws_save_failed", err = e.to_string())))?;
        }
        resolve_in_root(root, rel, false)
    })?;
    // 同目录隐藏临时文件 + 改名（两平台 rename 均为替换语义）
    let tmp = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("prping")
    ));
    std::fs::write(&tmp, text)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_save_failed", err = e.to_string())))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_save_failed", err = e.to_string())))?;
    Ok(())
}

/// 删除工作区条目：目录递归删除（remove_dir_all，含全部内容），文件直接删除。
pub(crate) fn delete_entry(root: &Path, rel: &str) -> anyhow::Result<()> {
    let path = resolve_in_root(root, rel, false)?;
    if path.is_dir() {
        std::fs::remove_dir_all(&path)
    } else {
        std::fs::remove_file(&path)
    }
    .map_err(|e| anyhow::anyhow!(t!("web.ws_delete_failed", err = e.to_string())))
}

/// 重命名/移动（工作区根内）：目标不存在才执行（覆盖请显式删除或保存覆盖）；
/// 目标父目录必须已存在。目录同样支持（fs::rename 对目录即移动）。
pub(crate) fn rename_entry(root: &Path, from: &str, to: &str) -> anyhow::Result<()> {
    let src = resolve_in_root(root, from, false)?;
    let dst_rel = validate_rel(to, false)?;
    let root_canon = std::fs::canonicalize(root)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_rename_failed", err = e.to_string())))?;
    let dst = root_canon.join(&dst_rel);
    if dst.exists() {
        anyhow::bail!(coded(
            code::CONFLICT,
            t!("web.ws_target_exists").to_string()
        ));
    }
    let parent = dst.parent().unwrap_or(root_canon.as_path());
    let parent_canon = std::fs::canonicalize(parent)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_rename_failed", err = e.to_string())))?;
    if !parent_canon.starts_with(&root_canon) {
        anyhow::bail!(coded(code::ESCAPE, t!("web.ws_escape").to_string()));
    }
    let dst = parent_canon.join(
        dst_rel
            .file_name()
            .ok_or_else(|| coded(code::ESCAPE, t!("web.ws_bad_path").to_string()))?,
    );
    std::fs::rename(&src, &dst)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_rename_failed", err = e.to_string())))
}

/// 新建目录（父目录链一并创建；已存在 → 报错，避免静默嵌套误解）。
pub(crate) fn mkdirs(root: &Path, rel: &str) -> anyhow::Result<PathBuf> {
    let rel_path = validate_rel(rel, false)?;
    let root_canon = std::fs::canonicalize(root)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_mkdir_failed", err = e.to_string())))?;
    let path = root_canon.join(&rel_path);
    if path.exists() {
        anyhow::bail!(coded(
            code::CONFLICT,
            t!("web.ws_target_exists").to_string()
        ));
    }
    std::fs::create_dir_all(&path)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_mkdir_failed", err = e.to_string())))?;
    let canon = std::fs::canonicalize(&path)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_mkdir_failed", err = e.to_string())))?;
    if !canon.starts_with(&root_canon) {
        anyhow::bail!(coded(code::ESCAPE, t!("web.ws_escape").to_string()));
    }
    Ok(canon)
}

/// 打开自定义工作区文件夹：必须是已存在的目录，返回 canonicalize 后的路径。
pub(crate) fn open_folder(path: &str) -> anyhow::Result<PathBuf> {
    let p = PathBuf::from(path);
    std::fs::canonicalize(&p)
        .ok()
        .filter(|c| c.is_dir())
        .ok_or_else(|| anyhow::anyhow!(t!("web.ws_open_failed", err = path)))
}

// ── 目录浏览（web 文件夹选择对话框数据源）────────────────────

/// 浏览条目上限（防异常目录卡顿）。
const MAX_BROWSE_ENTRIES: usize = 500;

/// 浏览目录：返回 (当前目录 canonical, 父目录或 None, 子目录名列表)。
///
/// 仅列子目录（目录符号链接可跟随进入——浏览由用户逐级驱动，无递归爆栈风险）；
/// 跳过隐藏项；条目上限 MAX_BROWSE_ENTRIES。path 缺省/空 → 用户主目录
/// （HOME/USERPROFILE），再退回根目录。路径必须是已存在的目录。
pub(crate) fn browse(
    path: Option<&str>,
) -> anyhow::Result<(PathBuf, Option<PathBuf>, Vec<String>)> {
    let start = match path.filter(|p| !p.is_empty()) {
        Some(p) => PathBuf::from(p),
        None => home_dir().unwrap_or_else(|| PathBuf::from("/")),
    };
    let cur = std::fs::canonicalize(&start)
        .ok()
        .filter(|c| c.is_dir())
        .ok_or_else(|| {
            anyhow::anyhow!(t!("web.ws_open_failed", err = start.display().to_string()))
        })?;
    let parent = cur.parent().map(Path::to_path_buf);
    let mut dirs: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&cur) {
        for e in entries.flatten() {
            if dirs.len() >= MAX_BROWSE_ENTRIES {
                break;
            }
            let Ok(name) = e.file_name().into_string() else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            // is_dir 跟随符号链接：目录链接可点进去浏览
            if e.path().is_dir() {
                dirs.push(name);
            }
        }
    }
    dirs.sort();
    Ok((cur, parent, dirs))
}

/// 用户主目录（环境变量，无外部 home 依赖）。
fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// 相对路径词法校验 → 路径（'/' 分隔各段）。规则见模块注释；
/// `require_pkt` = 是否要求 .pkt/.pktl 扩展名（保存/新建 DSL 文件为 true，
/// 任意文件读/删/改名/建目录为 false）。
pub(crate) fn validate_rel(rel: &str, require_pkt: bool) -> anyhow::Result<PathBuf> {
    if rel.is_empty() || rel.len() > MAX_REL_LEN {
        anyhow::bail!(coded(code::ESCAPE, t!("web.ws_bad_path").to_string()));
    }
    if rel.contains('\\') || rel.contains(':') || rel.starts_with('/') || rel.ends_with('/') {
        anyhow::bail!(coded(code::ESCAPE, t!("web.ws_bad_path").to_string()));
    }
    for seg in rel.split('/') {
        if seg.is_empty() || seg.starts_with('.') || is_windows_reserved(seg) {
            anyhow::bail!(coded(code::ESCAPE, t!("web.ws_bad_path").to_string()));
        }
    }
    if require_pkt && !is_pkt_file(rel) {
        anyhow::bail!(coded(code::ESCAPE, t!("web.ws_bad_ext").to_string()));
    }
    Ok(PathBuf::from(rel))
}

/// 是否 .pkt/.pktl 文件（按最后一段的扩展名判断；工作区可写标志用）。
pub(crate) fn is_pkt_file(name: &str) -> bool {
    let last = name.rsplit('/').next().unwrap_or(name);
    matches!(
        Path::new(last).extension().and_then(|x| x.to_str()),
        Some("pkt") | Some("pktl")
    )
}

/// Windows 保留设备名（任意扩展名组合下都拒绝，防 CON.pkt 之类写入异常）。
fn is_windows_reserved(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or(seg);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// 校验相对路径并解析到工作区根内的绝对路径。
///
/// 已存在的文件 canonicalize 后断言仍在根内（防符号链接把工作区条目指向根外）；
/// 新文件要求父目录已存在（同样断言根内）。
pub(crate) fn resolve_in_root(
    root: &Path,
    rel: &str,
    require_pkt: bool,
) -> anyhow::Result<PathBuf> {
    let rel_path = validate_rel(rel, require_pkt)?;
    let root_canon = std::fs::canonicalize(root)
        .map_err(|e| anyhow::anyhow!(t!("web.ws_read_failed", err = e.to_string())))?;
    let path = root_canon.join(&rel_path);
    if path.exists() {
        let canon = std::fs::canonicalize(&path)
            .map_err(|e| anyhow::anyhow!(t!("web.ws_read_failed", err = e.to_string())))?;
        if !canon.starts_with(&root_canon) {
            anyhow::bail!(coded(code::ESCAPE, t!("web.ws_escape").to_string()));
        }
        Ok(canon)
    } else {
        let parent = path.parent().unwrap_or(root_canon.as_path());
        let parent_canon = std::fs::canonicalize(parent)
            .map_err(|e| anyhow::anyhow!(t!("web.ws_save_failed", err = e.to_string())))?;
        if !parent_canon.starts_with(&root_canon) {
            anyhow::bail!(coded(code::ESCAPE, t!("web.ws_escape").to_string()));
        }
        let name = rel_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("{}", t!("web.ws_bad_path")))?;
        Ok(parent_canon.join(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("prping-ws-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn validate_rel_accepts_relative_pkt_paths() {
        assert!(validate_rel("icmp.pkt", true).is_ok());
        assert!(validate_rel("http_mock/http_get.pkt", true).is_ok());
        assert!(validate_rel("a/b/c.pktl", true).is_ok());
        // 任意扩展名模式（读/删/改名/建目录）
        assert!(validate_rel("plain.txt", false).is_ok());
        assert!(validate_rel("notes", false).is_ok());
        // 扩展开关只影响扩展名检查，词法规则一致
        assert!(validate_rel("plain.txt", true).is_err());
    }

    #[test]
    fn validate_rel_rejects_escape_and_specials() {
        for bad in [
            "",
            "../x.pkt",
            "a/../../x.pkt",
            "/abs.pkt",
            "a//b.pkt",
            "a/./b.pkt",
            ".hidden/x.pkt",
            "a\\b.pkt",
            "C:/x.pkt",
            "file.txt:hidden",
            "a/",
            "CON.pkt",
            "a/NUL.pktl",
        ] {
            assert!(validate_rel(bad, true).is_err(), "{bad}");
            assert!(validate_rel(bad, false).is_err(), "{bad}");
        }
    }

    #[test]
    fn resolve_rejects_escape_and_missing_parent() {
        let root = temp_root("resolve");
        std::fs::write(root.join("ok.pkt"), b"x").unwrap();
        // 存在的文件正常解析
        assert!(resolve_in_root(&root, "ok.pkt", true).is_ok());
        assert!(resolve_in_root(&root, "ok.pkt", false).is_ok());
        // 不存在的文件但父目录存在 → OK（新建）
        assert!(resolve_in_root(&root, "ok2.pkt", true).is_ok());
        // 父目录不存在 → 拒绝
        assert!(resolve_in_root(&root, "no/such/dir/x.pkt", true).is_err());
        // 词法非法在 resolve 层同样拒绝
        assert!(resolve_in_root(&root, "../ok.pkt", true).is_err());

        // 符号链接逃逸（unix）：工作区内的链接指向根外文件
        #[cfg(unix)]
        {
            let outside = temp_root("outside");
            let target = outside.join("secret.pkt");
            std::fs::write(&target, b"s").unwrap();
            std::os::unix::fs::symlink(&target, root.join("link.pkt")).unwrap();
            assert!(resolve_in_root(&root, "link.pkt", true).is_err());
            let _ = std::fs::remove_dir_all(&outside);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn save_read_delete_roundtrip() {
        let root = temp_root("roundtrip");
        save_file(&root, "sub/a.pkt", "hello").unwrap();
        assert_eq!(read_file(&root, "sub/a.pkt").unwrap(), "hello");
        // 覆盖写
        save_file(&root, "sub/a.pkt", "world").unwrap();
        assert_eq!(read_file(&root, "sub/a.pkt").unwrap(), "world");
        // 无残留临时文件
        assert!(!root.join("sub/.a.pkt.tmp").exists());
        delete_entry(&root, "sub/a.pkt").unwrap();
        assert!(read_file(&root, "sub/a.pkt").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn delete_entry_removes_directory_recursively() {
        let root = temp_root("deldir");
        save_file(&root, "top/a.pkt", "x").unwrap();
        save_file(&root, "top/deep/b.pktl", "y").unwrap();
        save_file(&root, "top/keep.txt", "z").unwrap(); // 目录内任意扩展名一并删除
        // 目录递归删除（含子目录与非 pkt 文件）
        delete_entry(&root, "top").unwrap();
        assert!(!root.join("top").exists());
        // 根外路径仍被拒绝；根自身不可删（相对路径语义不含根）
        assert!(delete_entry(&root, "../escape").is_err());
        assert!(delete_entry(&root, "missing").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn save_rejects_oversize_allows_any_ext() {
        let root = temp_root("limits");
        assert!(save_file(&root, "big.pkt", &" ".repeat(MAX_SAVE_TEXT + 1)).is_err());
        // 任意扩展名可写（文件管理基本语义）；DSL 与否由前端提示
        assert!(save_file(&root, "big.txt", "x").is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_rejects_binary_file() {
        let root = temp_root("binary");
        std::fs::write(root.join("bin.pkt"), [0x00, 0xff, 0xfe, 0x01]).unwrap();
        assert!(read_file(&root, "bin.pkt").is_err());
        std::fs::write(root.join("ok.txt"), "hello").unwrap();
        assert_eq!(read_file(&root, "ok.txt").unwrap(), "hello");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rename_moves_and_rejects_existing_target() {
        let root = temp_root("rename");
        save_file(&root, "a/old.pkt", "x").unwrap();
        save_file(&root, "b/keep.pkt", "y").unwrap();
        // 同目录改名
        rename_entry(&root, "a/old.pkt", "a/new.pkt").unwrap();
        assert!(read_file(&root, "a/new.pkt").is_ok());
        assert!(read_file(&root, "a/old.pkt").is_err());
        // 跨目录移动
        rename_entry(&root, "a/new.pkt", "b/new.pkt").unwrap();
        assert!(read_file(&root, "b/new.pkt").is_ok());
        // 目标已存在 → 拒绝（不静默覆盖）
        assert!(rename_entry(&root, "b/new.pkt", "b/keep.pkt").is_err());
        // 目标父目录不存在 → 拒绝
        assert!(rename_entry(&root, "b/new.pkt", "no/dir/x.pkt").is_err());
        // 词法非法同样拒绝
        assert!(rename_entry(&root, "b/new.pkt", "../escape.pkt").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mkdirs_creates_nested_and_rejects_existing() {
        let root = temp_root("mkdir");
        mkdirs(&root, "x/y/z").unwrap();
        assert!(root.join("x/y/z").is_dir());
        assert!(mkdirs(&root, "x/y/z").is_err()); // 已存在
        assert!(mkdirs(&root, "../out").is_err()); // 越界
        assert!(mkdirs(&root, "a//b").is_err()); // 词法非法
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tree_lists_dirs_first_sorted_hidden_skipped() {
        let root = temp_root("tree");
        std::fs::create_dir_all(root.join("b_dir")).unwrap();
        std::fs::create_dir_all(root.join("a_dir/deep")).unwrap();
        std::fs::write(root.join("z.pkt"), b"").unwrap();
        std::fs::write(root.join(".hidden.pkt"), b"").unwrap();
        std::fs::write(root.join("note.txt"), b"").unwrap();
        std::fs::write(root.join("a_dir/one.pkt"), b"").unwrap();
        std::fs::write(root.join("a_dir/deep/two.pktl"), b"").unwrap();
        std::fs::write(root.join("b_dir/skip.txt"), b"").unwrap();

        let got = tree(&root);
        let paths: Vec<&str> = got.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "a_dir",
                "a_dir/deep",
                "a_dir/deep/two.pktl",
                "a_dir/one.pkt",
                "b_dir",
                "b_dir/skip.txt",
                "note.txt",
                "z.pkt",
            ]
        );
        assert!(got[0].dir);
        assert!(!got[2].dir);
        // pkt 标记：DSL 文件 true，其他文件 false
        assert!(got[2].pkt);
        assert!(!got[5].pkt);
        assert!(got[7].pkt);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tree_depth_capped() {
        let root = temp_root("cap");
        // 超深嵌套：深度截断，最深层文件不出现
        let mut deep = root.join("d");
        for _ in 0..MAX_TREE_DEPTH + 3 {
            deep = deep.join("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("x.pkt"), b"").unwrap();
        let got = tree(&root);
        let max_depth = got
            .iter()
            .map(|e| e.path.split('/').count())
            .max()
            .unwrap_or(0);
        assert!(max_depth <= MAX_TREE_DEPTH);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_folder_requires_existing_dir() {
        let root = temp_root("open");
        assert!(open_folder(&root.display().to_string()).is_ok());
        assert!(open_folder(&root.join("nope").display().to_string()).is_err());
        assert!(open_folder("").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn browse_lists_dirs_sorted_skips_hidden_and_files() {
        let root = temp_root("browse");
        // macOS 下 $TMPDIR 经 /var → /private/var 符号链接：先 canonicalize，
        // 与 browse 返回的已解析路径同基（Linux /tmp 无链接，行为不变）
        let root = std::fs::canonicalize(&root).unwrap();
        std::fs::create_dir_all(root.join("b_dir")).unwrap();
        std::fs::create_dir_all(root.join("a_dir")).unwrap();
        std::fs::create_dir_all(root.join(".hidden_dir")).unwrap();
        std::fs::write(root.join("file.pkt"), b"").unwrap();

        let (cur, parent, dirs) = browse(Some(&root.display().to_string())).unwrap();
        assert_eq!(std::fs::canonicalize(&root).unwrap(), cur);
        assert_eq!(parent.as_deref(), Some(root.parent().unwrap()));
        assert_eq!(dirs, vec!["a_dir", "b_dir"], "隐藏目录与文件不出现、字典序");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn browse_rejects_missing_and_uses_default_for_empty() {
        // 不存在的路径报错
        assert!(browse(Some("/definitely/not/exist-prping")).is_err());
        // 空串与 None 等价：走主目录/根兜底（只要求成功，不假设环境）
        assert!(browse(Some("")).is_ok());
        assert!(browse(None).is_ok());
    }
}
