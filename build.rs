//! 编译时配置 cargo runner，自动在二进制上设置 cap_net_raw。
//!
//! 运行 `sudo cargo run -- icmp 8.8.8.8` 一次授权后，后续 `cargo run` 即可直接使用 ICMP。

fn main() {
    if !cfg!(target_os = "linux") {
        return;
    }

    let config_dir = std::path::Path::new(".cargo");
    let _ = std::fs::create_dir_all(config_dir);

    // runner 脚本：用 sudo setcap 设权限，失败则直接运行二进制
    let runner = config_dir.join("run-with-cap.sh");
    let script = "#!/bin/sh\nBIN=\"$1\"; shift\nsudo -n setcap cap_net_raw+ep \"$BIN\" 2>/dev/null\nexec \"$BIN\" \"$@\"\n";
    let _ = std::fs::write(&runner, script);
    let _ = std::process::Command::new("chmod").arg("+x").arg(&runner).status();

    // .cargo/config.toml
    let config = config_dir.join("config.toml");
    if !config.exists() {
        let content = "[target.'cfg(target_os = \"linux\")']\nrunner = \".cargo/run-with-cap.sh\"\n";
        let _ = std::fs::write(&config, content);
    }

    // 预授权提示
    let Ok(out_dir) = std::env::var("OUT_DIR") else { return };
    let Ok(profile) = std::env::var("PROFILE") else { return };
    let target_dir = std::path::Path::new(&out_dir).ancestors().nth(3).unwrap();
    let binary = target_dir.join(&profile).join("prping");

    if binary.exists() {
        // 尝试直接 setcap（当前用户有 sudo 权限且无密码时生效）
        let _ = std::process::Command::new("sudo")
            .args(["-n", "setcap", "cap_net_raw+ep"])
            .arg(&binary)
            .status();
    }
}
