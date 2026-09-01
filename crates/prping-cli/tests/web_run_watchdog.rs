//! Web 执行桥子进程生命线：`PRPING_WEB_RUN=1` 时 stdin 关闭（父进程死亡）→
//! 子进程自行退出，防孤儿。见 crates/prping-core/src/web/run.rs 与 main.rs 的
//! `install_stdin_lifeline`。
#![cfg(feature = "web")]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// 启动 `prping web --port 0`（常驻子命令，无需引擎库/工作区）。
fn spawn_child(web_run: bool) -> std::process::Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_prping"));
    cmd.args(["web", "--addr", "127.0.0.1", "--port", "0"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if web_run {
        cmd.env("PRPING_WEB_RUN", "1").stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.spawn().expect("spawn prping web")
}

/// 轮询等待子进程退出（含收尸）。
fn wait_exit(child: &mut std::process::Child, ms: u64) -> bool {
    let deadline = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < deadline {
        if child.try_wait().expect("try_wait").is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn stdin_close_ends_web_run_child() {
    let (mut child, stdin) = {
        let mut c = spawn_child(true);
        let stdin = c.stdin.take();
        (c, stdin)
    };
    // stdin 保持打开：子进程应持续存活
    std::thread::sleep(Duration::from_millis(600));
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "child exited while stdin still open"
    );
    // 关闭写端（= 父进程死亡）：子进程应读到 EOF 自行退出
    drop(stdin);
    assert!(
        wait_exit(&mut child, 5000),
        "child must exit after stdin EOF (lifeline)"
    );
    let _ = child.wait();
}

#[test]
fn without_env_stdin_close_is_ignored() {
    // 对照组：未打 PRPING_WEB_RUN 标记的子进程不受 stdin 影响（手动场景不变）
    let mut child = spawn_child(false);
    std::thread::sleep(Duration::from_millis(600));
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "control child should stay alive"
    );
    child.kill().expect("kill control child");
    let _ = child.wait();
}
