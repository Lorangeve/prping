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

fn stderr_str(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// 互斥参数校验测试：固定 --lang en-US 保证错误文案可断言；
/// 冲突在连接/建 socket 之前触发，无需网络与 root。
fn run_conflict(args: &[&str]) -> std::process::Output {
    prping()
        .args(["--lang", "en-US"])
        .args(args)
        .output()
        .expect("run conflict check")
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

#[test]
fn invalid_histogram_errors() {
    // 非法 -H（非数字非阈值列表）应报错退出，而非静默忽略
    let out = prping()
        .args(["--lang", "en-US", "-H", "abc", "127.0.0.1:9"])
        .output()
        .expect("run");
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("invalid histogram value"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn parallel_warning_non_bandwidth() {
    // 非带宽模式 -P 警告（橙色，stderr）——不阻止运行
    let (_srv, port) = start_server();
    let out = run_client(port, &["--lang", "en-US", "-n", "1", "-w", "0", "-P", "4"]);
    assert!(out.status.success());
    assert!(
        stderr_str(&out).contains("-P ignored in this mode"),
        "stderr: {}",
        stderr_str(&out)
    );
}

// ---------- 互斥参数校验 ----------

#[test]
fn conflict_v4_v6_errors() {
    let out = run_conflict(&["-4", "-6", "127.0.0.1"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("-4 and -6 cannot be used together"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn conflict_server_target_errors() {
    let out = run_conflict(&["-s", "127.0.0.1:9000", "127.0.0.1:9001"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("cannot be combined with a target"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn conflict_server_mode_errors() {
    // 服务端模式不能带客户端测试参数（-b/-l/-u/-r/-n/-i/-H/-w/-P/-q/-p/-g/--json）
    let out = run_conflict(&["-s", "127.0.0.1:9000", "-b"]);
    assert!(!out.status.success());
    let s = stderr_str(&out);
    assert!(s.contains("client test options"), "stderr: {s}");
    assert!(s.contains("-b"), "stderr: {s}");

    let out = run_conflict(&["-s", "127.0.0.1:9000", "--json", "-n", "5"]);
    assert!(!out.status.success());
    let s = stderr_str(&out);
    assert!(s.contains("--json") && s.contains("-n"), "stderr: {s}");
}

#[test]
fn conflict_json_output_errors() {
    // --json 与 -p/-g/-H 冲突（JSON 输出替代全部人读渲染）
    for args in [
        &["--json", "-p", "127.0.0.1:9"][..],
        &["--json", "-g", "127.0.0.1:9"][..],
        &["--json", "-H", "20", "127.0.0.1:9"][..],
    ] {
        let out = run_conflict(args);
        assert!(!out.status.success(), "args: {args:?}");
        let s = stderr_str(&out);
        assert!(
            s.contains("--json and ") && s.contains("cannot be used together"),
            "args: {args:?} stderr: {s}"
        );
    }
}

#[test]
fn conflict_receive_without_latency_bandwidth_errors() {
    // -r 无 -b/-l：无端口（ICMP）与有端口（TCP/UDP ping）都应报错
    let out = run_conflict(&["-r", "127.0.0.1"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("-r requires -b (bandwidth) or -l (latency)"),
        "stderr: {}",
        stderr_str(&out)
    );

    let out = run_conflict(&["-r", "127.0.0.1:9"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("-r requires -b (bandwidth) or -l (latency)"),
        "stderr: {}",
        stderr_str(&out)
    );
}
