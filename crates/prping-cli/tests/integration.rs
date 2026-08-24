//! 子进程 CLI 行为测试：验证 bin 的子命令解析、输出、退出码。
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
        .args(["server", &format!("127.0.0.1:{port}")])
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

/// TCP ping 客户端：`prping ping 127.0.0.1:PORT [args]`。
fn run_client(port: u16, args: &[&str]) -> std::process::Output {
    let mut cmd = prping();
    cmd.arg("ping");
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

/// 校验类测试：固定 --lang en-US 保证错误文案可断言；
/// 冲突在连接/建 socket 之前触发，无需网络与 root。
fn run_check(args: &[&str]) -> std::process::Output {
    prping()
        .args(["--lang", "en-US"])
        .args(args)
        .output()
        .expect("run check")
}

// ---------- 真实 TCP ping（子进程 + 服务端） ----------

#[test]
fn tcp_ping_json_stats() {
    let (_srv, port) = start_server();
    let out = run_client(port, &["-n", "3", "-w", "0", "--json"]);
    assert!(out.status.success(), "exit={:?}", out.status);
    let s = stdout_str(&out);
    assert!(
        s.contains("\"target\"") && s.contains("\"loss_pct\""),
        "stdout: {s}"
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
    // 连接失败（无监听）：TCP ping 视为丢包 → 退出码 1
    let out = run_client(alloc_port(), &["-n", "2", "-w", "0"]);
    assert!(!out.status.success());
}

// ---------- 顶层行为 ----------

#[test]
fn version_flag() {
    let out = run_check(&["--version"]);
    assert!(out.status.success());
    assert!(stdout_str(&out).starts_with("prping "));
}

#[test]
fn top_help_lists_subcommands() {
    let out = run_check(&["--help"]);
    assert!(out.status.success());
    let s = stdout_str(&out);
    for cmd in [
        "ping",
        "latency",
        "bandwidth",
        "server",
        "trace",
        "engine",
        "packet",
    ] {
        assert!(s.contains(cmd), "help missing {cmd}: {s}");
    }
}

#[test]
fn subcommand_help() {
    let out = run_check(&["ping", "--help"]);
    assert!(out.status.success());
    let s = stdout_str(&out);
    assert!(s.contains("prping ping"), "usage line: {s}");
    assert!(s.contains("--mtu"), "ping help should list -M/--mtu: {s}");

    let out = run_check(&["trace", "--help"]);
    assert!(out.status.success());
    let s = stdout_str(&out);
    assert!(
        s.contains("--max-hops") && s.contains("--no-dns"),
        "trace help: {s}"
    );
}

// ---------- 唯一前缀展开 ----------

#[test]
fn unique_prefix_expands() {
    // e → engine；--ls 不需要文件/root
    let out = run_check(&["e", "--ls"]);
    assert!(out.status.success(), "stderr: {}", stderr_str(&out));
    let s = stdout_str(&out);
    assert!(
        s.contains("raw") && s.contains("hex"),
        "engine --ls output: {s}"
    );
}

#[test]
fn ambiguous_prefix_errors() {
    // p → ping / packet 歧义
    let out = run_check(&["p", "127.0.0.1:9"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("ambiguous"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn unknown_subcommand_errors() {
    let out = run_check(&["frobnicate", "127.0.0.1:9"]);
    assert!(!out.status.success());
}

#[test]
fn legacy_flat_syntax_hints_ping() {
    // 旧写法 `prping 8.8.8.8`：报错并提示迁移到 ping
    let out = run_check(&["8.8.8.8"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("try: prping ping"),
        "stderr: {}",
        stderr_str(&out)
    );
}

// ---------- 校验路径（子命令选项级） ----------

#[test]
fn invalid_count_errors() {
    let out = run_check(&["ping", "-n", "abc", "127.0.0.1:9"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("invalid count"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn invalid_histogram_errors() {
    let out = run_check(&["ping", "-H", "abc", "127.0.0.1:9"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("invalid histogram"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn conflict_v4_v6_errors() {
    let out = run_check(&["ping", "-4", "-6", "127.0.0.1:9"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("-4 and -6"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn conflict_json_output_errors() {
    // --json 与 -p/-g/-H 冲突（JSON 输出替代全部人读渲染）
    for args in [
        &["ping", "--json", "-p", "127.0.0.1:9"][..],
        &["ping", "--json", "-g", "127.0.0.1:9"][..],
        &["ping", "--json", "-H", "20", "127.0.0.1:9"][..],
    ] {
        let out = run_check(args);
        assert!(!out.status.success(), "args: {args:?}");
        let s = stderr_str(&out);
        assert!(
            s.contains("--json and ") && s.contains("cannot be used together"),
            "args: {args:?} stderr: {s}"
        );
    }
}

#[test]
fn mtu_conflict_errors() {
    // -m 与 -u/-n 互斥（在连接/建 socket 前校验）
    let out = run_check(&["ping", "-m", "-u", "-n", "3", "127.0.0.1"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("cannot be combined"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn latency_requires_port() {
    let out = run_check(&["latency", "127.0.0.1"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("latency requires"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn bandwidth_requires_port() {
    let out = run_check(&["bandwidth", "127.0.0.1"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("bandwidth requires"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn udp_ping_requires_port() {
    // ping -u 无端口：lib 报 UDP 需要端口（解析在 socket 创建前）
    let out = run_check(&["ping", "-u", "127.0.0.1"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("UDP requires a port"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn traceroute_requires_no_port() {
    // trace 带端口目标：lib run 分派层报错（先于 resolve/socket）
    let out = run_check(&["trace", "127.0.0.1:9"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("does not take a port"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn tcp_trace_requires_port() {
    // trace --tcp 缺端口：lib run 分派层报错（先于 resolve/socket）
    let out = run_check(&["trace", "--tcp", "127.0.0.1"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("requires a port"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn udp_trace_conflicts_with_tcp() {
    // trace --tcp --udp 互斥：lib run 分派层报错
    let out = run_check(&["trace", "--tcp", "--udp", "127.0.0.1:80"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("cannot be used together"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn udp_trace_requires_no_port() {
    // trace --udp 不带端口（33434 起自动递增）：带端口报错
    let out = run_check(&["trace", "--udp", "127.0.0.1:80"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("does not take a port"),
        "stderr: {}",
        stderr_str(&out)
    );
}

// ---------- 引擎 / 包构建子命令校验 ----------

#[test]
fn engine_sub_actions_conflict() {
    let out = run_check(&["engine", "--ls", "--hex", "ab"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("mutually exclusive"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn engine_requires_file() {
    let out = run_check(&["engine"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("needs a .pkt file"),
        "stderr: {}",
        stderr_str(&out)
    );
}

#[test]
fn packet_iface_requires_raw() {
    let out = run_check(&["packet", "--iface", "eth0", "x.pkt"]);
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("--iface"),
        "stderr: {}",
        stderr_str(&out)
    );
}
