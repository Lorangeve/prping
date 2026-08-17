//! 集成测试：真实起服务端 + 客户端子进程，回环验证各协议路径。
//!
//! 断言基于 `--json` 输出（与 locale 无关）和字节数，避免本地化文本耦合。

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
        .stdout(Stdio::piped())
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
fn tcp_ping_duration_mode() {
    let (_srv, port) = start_server();
    let out = run_client(port, &["-n", "1s", "-i", "0.2", "-w", "0", "--json"]);
    assert!(out.status.success());
    let s = stdout_str(&out);
    // 1s / 0.2s 间隔 ≈ 5 次
    assert!(
        s.contains("\"sent\":5") || s.contains("\"sent\":6"),
        "got: {s}"
    );
}

#[test]
fn latency_tcp_send() {
    let (_srv, port) = start_server();
    let out = run_client(port, &["-l", "64", "-n", "5", "-w", "0", "--json"]);
    assert!(out.status.success());
    let s = stdout_str(&out);
    assert!(
        s.contains("\"sent\":5") && s.contains("\"received\":5"),
        "got: {s}"
    );
}

#[test]
fn latency_tcp_receive() {
    let (_srv, port) = start_server();
    let out = run_client(port, &["-l", "64", "-n", "5", "-w", "0", "-r", "--json"]);
    assert!(out.status.success());
    let s = stdout_str(&out);
    assert!(
        s.contains("\"sent\":5") && s.contains("\"received\":5"),
        "got: {s}"
    );
}

#[test]
fn latency_udp_send() {
    let (_srv, port) = start_server();
    let out = run_client(port, &["-l", "64", "-n", "5", "-w", "0", "-u", "--json"]);
    assert!(out.status.success());
    let s = stdout_str(&out);
    assert!(
        s.contains("\"sent\":5") && s.contains("\"received\":5"),
        "got: {s}"
    );
}

#[test]
fn latency_udp_receive() {
    let (_srv, port) = start_server();
    let out = run_client(
        port,
        &["-l", "64", "-n", "5", "-w", "0", "-u", "-r", "--json"],
    );
    assert!(out.status.success());
    let s = stdout_str(&out);
    assert!(
        s.contains("\"sent\":5") && s.contains("\"received\":5"),
        "got: {s}"
    );
}

#[test]
fn bandwidth_tcp_send_bytes() {
    let (_srv, port) = start_server();
    let out = run_client(port, &["-b", "-l", "8k", "-n", "100", "-w", "0", "--json"]);
    assert!(out.status.success());
    let s = stdout_str(&out);
    assert!(s.contains("\"bytes\":819200"), "got: {s}");
}

#[test]
fn bandwidth_tcp_receive_bytes() {
    let (_srv, port) = start_server();
    let out = run_client(
        port,
        &["-b", "-l", "8k", "-n", "100", "-w", "0", "-r", "--json"],
    );
    assert!(out.status.success());
    let s = stdout_str(&out);
    assert!(s.contains("\"bytes\":819200"), "got: {s}");
}

#[test]
fn bandwidth_udp_send_bytes() {
    let (_srv, port) = start_server();
    let out = run_client(
        port,
        &["-b", "-l", "8k", "-n", "100", "-w", "0", "-u", "--json"],
    );
    assert!(out.status.success());
    let s = stdout_str(&out);
    assert!(s.contains("\"bytes\":819200"), "got: {s}");
}

#[test]
fn bandwidth_udp_receive_bytes() {
    let (_srv, port) = start_server();
    let out = run_client(
        port,
        &[
            "-b", "-l", "8k", "-n", "100", "-w", "0", "-u", "-r", "--json",
        ],
    );
    assert!(out.status.success());
    let s = stdout_str(&out);
    assert!(s.contains("\"bytes\":819200"), "got: {s}");
}

#[test]
fn bandwidth_parallel_exact_quota() {
    // count < parallel 时也必须发满 count 包（4 × 8k = 32768 字节）
    let (_srv, port) = start_server();
    let out = run_client(
        port,
        &["-b", "-l", "8k", "-n", "4", "-w", "0", "-P", "8", "--json"],
    );
    assert!(out.status.success());
    let s = stdout_str(&out);
    assert!(s.contains("\"bytes\":32768"), "got: {s}");
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

#[cfg(unix)]
#[test]
fn server_graceful_shutdown_summary() {
    use std::io::Read;
    let port = alloc_port();
    let mut guard = ServerGuard(
        prping()
            .args(["-s", &format!("127.0.0.1:{port}")])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server"),
    );
    wait_port(port);
    // 跑一个客户端制造连接
    let out = run_client(port, &["-n", "2", "-w", "0"]);
    assert!(out.status.success());
    // SIGINT 优雅退出，输出聚合统计
    unsafe { libc::kill(guard.0.id() as i32, libc::SIGINT) };
    let mut buf = String::new();
    guard
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut buf)
        .expect("read server stdout");
    let status = guard.0.wait().expect("wait server");
    assert!(
        status.success(),
        "server should exit 0 after SIGINT, got {status:?}"
    );
    assert!(
        buf.contains("server summary") || buf.contains("服务端汇总"),
        "got: {buf}"
    );
}
