//! 编译时配置 cargo runner，自动在二进制上设置 cap_net_raw。
//!
//! 运行 `sudo cargo run -- icmp 8.8.8.8` 一次授权后，后续 `cargo run` 即可直接使用 ICMP。

fn main() {
    // locale 文案变更需重编译：rust-i18n 的 i18n! 宏展开期读 locales/*.yml，
    // cargo 不追踪该文件依赖，改 yml 后不重编译会一直显示旧文案。
    // 放在平台分支前：所有平台（含 Windows/macOS）都要追踪。
    println!("cargo:rerun-if-changed=locales/zh-CN.yml");
    println!("cargo:rerun-if-changed=locales/en-US.yml");

    if !cfg!(target_os = "linux") {
        return;
    }

    let config_dir = std::path::Path::new(".cargo");
    let _ = std::fs::create_dir_all(config_dir);

    // runner 脚本：用 sudo setcap 设权限，失败则直接运行二进制。
    // 仅在内容变化时重写——此前每次构建都覆盖，用户对脚本的自定义会被冲掉
    let runner = config_dir.join("run-with-cap.sh");
    let script = "#!/bin/sh\nBIN=\"$1\"; shift\nsudo -n setcap cap_net_raw+ep \"$BIN\" 2>/dev/null\nexec \"$BIN\" \"$@\"\n";
    if std::fs::read_to_string(&runner).ok().as_deref() != Some(script) {
        let _ = std::fs::write(&runner, script);
        let _ = std::process::Command::new("chmod")
            .arg("+x")
            .arg(&runner)
            .status();
    }

    // .cargo/config.toml
    let config = config_dir.join("config.toml");
    if !config.exists() {
        let content =
            "[target.'cfg(target_os = \"linux\")']\nrunner = \".cargo/run-with-cap.sh\"\n";
        let _ = std::fs::write(&config, content);
    }

    // 预授权提示
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    let Ok(profile) = std::env::var("PROFILE") else {
        return;
    };
    // 从 OUT_DIR 向上找 target/<profile>：此前固定 nth(3).unwrap() 依赖 OUT_DIR
    // 层数，目录结构变化即构建 panic——改为扫描含 profile 目录的祖先层
    let Some(target_dir) = std::path::Path::new(&out_dir)
        .ancestors()
        .find(|p| p.join(&profile).is_dir())
    else {
        return;
    };
    let binary = target_dir.join(&profile).join("prping");

    if binary.exists() {
        // 尝试直接 setcap（当前用户有 sudo 权限且无密码时生效）
        let _ = std::process::Command::new("sudo")
            .args(["-n", "setcap", "cap_net_raw+ep"])
            .arg(&binary)
            .status();
    }
}
