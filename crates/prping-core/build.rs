//! 编译期依赖追踪 + 前端构建。
//!
//! 1. locale 追踪：rust-i18n 的 `i18n!("locales")` 宏在**展开期**读取
//!    `locales/*.yml` 并把文案内嵌进二进制，但 cargo 不感知宏读过的文件——
//!    增量构建时改 yml 不会触发重编译，产物里一直是旧文案。用
//!    `rerun-if-changed` 声明依赖，yml 一改就重编译本 crate。
//! 2. 前端构建（仅 `web-embed` feature）：web 模块的 rust-embed 在**本 crate
//!    编译期**读取 `frontend/dist`（release 内嵌二进制），因此前端必须在本
//!    crate 编译前就绪——构建逻辑必须放在本 crate 的 build.rs（放 prping-cli
//!    会晚于 rust-embed 读盘）。默认构建不启用该 feature：运行期读 UI/ 目录，
//!    无需 node 工具链。

fn main() {
    println!("cargo:rerun-if-changed=locales/zh-CN.yml");
    println!("cargo:rerun-if-changed=locales/en-US.yml");

    // 前端源码/配置变更 → 重建 dist；node 工具链缺失时仅警告跳过（离线/交叉
    // 环境可编译，运行期 web 页面 503 提示构建方式）。跳过开关：PRPING_SKIP_WEB_BUILD=1。
    // 仅 web-embed（rust-embed 内嵌）需要 dist：默认构建读 UI/ 目录，整个前端
    // 构建链条（含 rerun-if-changed）一并跳过，改前端不触发无谓重编。
    if std::env::var_os("CARGO_FEATURE_WEB_EMBED").is_none() {
        return;
    }
    println!("cargo:rerun-if-changed=../../frontend/src");
    println!("cargo:rerun-if-changed=../../frontend/index.html");
    // public/ 静态资源（favicon 等）经 vite 拷入 dist 根，变更也需重建
    println!("cargo:rerun-if-changed=../../frontend/public");
    println!("cargo:rerun-if-changed=../../frontend/package.json");
    println!("cargo:rerun-if-changed=../../frontend/vite.config.ts");
    println!("cargo:rerun-if-changed=../../frontend/tsconfig.json");
    let skip = matches!(
        std::env::var("PRPING_SKIP_WEB_BUILD").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    );
    if !skip {
        build_frontend();
    }
}

/// 前端构建（仅 web-embed feature 调用）：bun 优先、npm 兜底（npm 随 node
/// 附带）；node_modules 缺失时先装依赖。有工具链但构建失败 → panic（cargo
/// 构建失败，避免静默内嵌过期资源）；无工具链 → cargo:warning 后跳过。
fn build_frontend() {
    let root = std::path::Path::new("../../frontend");
    if !root.join("package.json").exists() {
        return;
    }
    // 工具链探测：--version 退出码即可（不解析输出）
    let has = |cmd: &str| {
        std::process::Command::new(cmd)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    let (pm, install_args, build_args): (&str, &[&str], &[&str]) = if has("bun") {
        // bun：自带包管理器与脚本运行器；build 走 package.json 的 vite script
        ("bun", &["install"], &["run", "build"])
    } else if has("npm") {
        (
            "npm",
            &["install", "--no-audit", "--no-fund", "--silent"],
            &["run", "build"],
        )
    } else {
        println!(
            "cargo:warning=prping web: node/bun/npm not found — skipping frontend build \
             (web UI falls back to a build-hint page); set PRPING_SKIP_WEB_BUILD=1 to silence"
        );
        return;
    };

    // 依赖安装：node_modules 缺失（或刚清理）时执行
    if !root.join("node_modules").is_dir() {
        let status = std::process::Command::new(pm)
            .args(install_args)
            .current_dir(root)
            .status()
            .unwrap_or_else(|e| panic!("failed to spawn {pm}: {e}"));
        if !status.success() {
            panic!(
                "frontend dependency install failed ({pm} install) — run `just build-web` manually for details"
            );
        }
    }

    let status = std::process::Command::new(pm)
        .args(build_args)
        .current_dir(root)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {pm}: {e}"));
    if !status.success() {
        panic!(
            "frontend build failed ({pm} build in frontend/) — fix the error above, \
             or set PRPING_SKIP_WEB_BUILD=1 to build without web assets"
        );
    }
}
