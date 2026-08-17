//! 子进程 CLI 行为测试：验证 bin 的解析、输出、退出码。
//!
//! 协议路径（echo/trigger/聚合/优雅退出）由 `tests/protocol.rs` 进程内覆盖。

use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_PORT: AtomicU16 = AtomicU16::new(22000);

fn alloc_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

/// 服务端句柄：Drop 时兜底杀掉子进程（panic 时也能清理）。
struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn prping() -> Command {
    Command::new(env!("CARGO_BIN_EXE_prping"))
}

/// 启动服务端并等待端口就绪。
fn start_server() -> (ServerGuard, u16) {
    let port = alloc_port();
    let child = prping()
        .args(["-s", &format!("127.0.0.1:{port}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    wait_port(port);
    (ServerGuard(child), port)
}

fn wait_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("server on {port} did not become ready");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn run_client(port: u16, args: &[&str]) -> std::process::Output {
    let mut cmd = prping();
    cmd.arg("127.0.0.1:".to_string() + &port.to_string());
    cmd.args(args);
    cmd.output().expect("run client")
}

fn stdout_str(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn tcp_ping_json_stats() {
    let (_srv, port) = start_server();
    let out = run_client(port, &["-n", "3", "-w", "0", "--json"]);
    assert!(out.status.success(), "exit={:?}", out.status);
    let s = stdout_str(&out);
    assert!(
        s.contains("\"type\":\"tcp\"") && s.contains("\"sent\":3") && s.contains("\"received\":3"),
        "got: {s}"
    );
}

#[test]
fn tcp_ping_exit_code_ok() {
    let (_srv, port) = start_server();
    let out = run_client(port, &["-n", "2", "-w", "0"]);
    assert!(out.status.success());
}

#[test]
fn tcp_ping_exit_code_loss() {
    // 无服务端口 → 100% 丢包 → 非零退出码
    let port = alloc_port();
    let out = run_client(port, &["-n", "1", "-w", "0"]);
    assert!(
        !out.status.success(),
        "expected non-zero exit, got {:?}",
        out.status.code()
    );
}

#[test]
fn version_flag() {
    let out = prping().arg("--version").output().expect("run --version");
    assert!(out.status.success());
    assert!(stdout_str(&out).starts_with("prping "));
}

#[test]
fn invalid_count_errors() {
    let out = prping()
        .args(["-n", "abc", "127.0.0.1:9"])
        .output()
        .expect("run");
    assert!(!out.status.success());
}
