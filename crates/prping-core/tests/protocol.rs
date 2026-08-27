//! 进程内协议测试：直接调用 lib 的 `serve`/`run`，无子进程、无真实信号。
//!
//! `serve` 通过 `smol::spawn` 跑在全局 executor 线程上，测试在 `block_on`
//! 内用 std 阻塞 socket 与其交互，最后 `set_interrupted(true)` 注入优雅退出。

use prping_core::{
    OutcomeKind, PingConfig, PrpingError, PrpingWarning, reset_interrupt, run, serve,
    set_interrupted,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

static NEXT_PORT: AtomicU16 = AtomicU16::new(23000);

fn alloc_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

fn wait_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("server on {port} did not become ready");
}

/// smol 全局 executor 默认单线程，多个测试并行 `serve` 会互相干扰，
/// 用互斥锁串行化进程内服务端测试。
static SERVER_LOCK: Mutex<()> = Mutex::new(());

/// 在 block_on 中启动 serve，执行 `f`，注入中断退出并返回报告。
fn with_server(f: impl Fn(u16) + Send + 'static) -> prping_core::ServerReport {
    let _guard = SERVER_LOCK.lock().unwrap();
    reset_interrupt();
    smol::block_on(async {
        let port = alloc_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let handle =
            smol::spawn(async move { serve(addr, false, false, None).await.expect("serve") });
        wait_port(port);
        f(port);
        // 给连接任务一点收尾时间，确保聚合计数完成
        smol::Timer::after(Duration::from_millis(80)).await;
        set_interrupted(true);
        let report = handle.await;
        reset_interrupt();
        report
    })
}

#[test]
fn server_tcp_echo_and_report() {
    let report = with_server(|port| {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.write_all(b"hello").expect("write");
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).expect("echo");
        assert_eq!(&buf, b"hello");
    });
    // connections = 1（wait_port 探测连接）+ 1（echo 连接）
    assert_eq!(report.connections, 2);
    assert_eq!(report.bytes, 5);
}

#[test]
fn server_tcp_receive_mode_trigger() {
    let report = with_server(|port| {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        // 0xFF 单字节触发接收模式：服务端持续回送 64KB 块
        stream.write_all(&[0xFF]).expect("trigger");
        let mut buf = vec![0u8; 65536];
        let n = stream.read(&mut buf).expect("recv");
        assert!(n > 0, "should receive data");
    });
    assert_eq!(report.connections, 2);
    // bytes 只统计客户端发来的数据（触发字节 1 个）
    assert_eq!(report.bytes, 1);
    // sent 统计服务端触发模式发送的数据量
    assert!(report.sent > 0, "sent={}", report.sent);
}

#[test]
fn server_udp_trigger_protocol() {
    let report = with_server(|port| {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        // 触发包：[0xFF, 0xFF, size=64(2B BE), count=5(4B BE)]
        let mut trigger = vec![0u8; 8];
        trigger[0] = 0xFF;
        trigger[1] = 0xFF;
        trigger[2..4].copy_from_slice(&64u16.to_be_bytes());
        trigger[4..8].copy_from_slice(&5u32.to_be_bytes());
        sock.send_to(&trigger, ("127.0.0.1", port))
            .expect("send trigger");
        let mut buf = vec![0u8; 64];
        let mut got = 0;
        for _ in 0..5 {
            let (n, _) = sock.recv_from(&mut buf).expect("recv");
            assert_eq!(n, 64);
            got += 1;
        }
        assert_eq!(got, 5);
    });
    // UDP 路径不计数；connections 来自 wait_port 的探测连接
    assert_eq!(report.connections, 1);
    assert_eq!(report.bytes, 0);
}

#[test]
fn server_udp_echo() {
    let report = with_server(|port| {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        sock.send_to(b"ping", ("127.0.0.1", port)).expect("send");
        let mut buf = [0u8; 4];
        let (n, _) = sock.recv_from(&mut buf).expect("echo");
        assert_eq!(&buf[..n], b"ping");
    });
    assert_eq!(report.connections, 1);
    // UDP 回显字节计入聚合统计（此前 bytes 只统计 TCP）
    assert_eq!(report.bytes, 4);
}

#[test]
fn run_udp_requires_port() {
    let cfg = PingConfig {
        host: "127.0.0.1".into(),
        port: 0,
        count: 1,
        duration: None,
        interval: 1.0,
        size: None,
        quiet: true,
        histogram: None,
        warmup: 0,
        v4: false,
        v6: false,
        parallel: 1,
        udp: true,
        receive: false,
        bandwidth: false,
        graph: false,
        mtu: false,
        traceroute: false,
        trace_tcp: false,
        trace_udp: false,
        max_hops: 30,
        no_dns: false,
        source: None,
    };
    let err = run(&cfg, |_| {}).expect_err("should fail");
    assert!(matches!(err, PrpingError::UdpRequiresPort));
}

#[test]
fn run_bandwidth_requires_port() {
    let mut cfg = ping_config();
    cfg.bandwidth = true;
    cfg.port = 0;
    let err = run(&cfg, |_| {}).expect_err("should fail");
    assert!(matches!(err, PrpingError::BandwidthRequiresPort));
}

#[test]
fn run_collects_warnings() {
    let mut cfg = ping_config();
    cfg.bandwidth = true;
    cfg.udp = true;
    cfg.parallel = 4;
    cfg.interval = 0.0;
    cfg.port = 1; // 无服务，run 会返回 Err，但警告先流出
    let mut warnings = Vec::new();
    let _ = run(&cfg, |w| warnings.push(w));
    assert!(warnings.contains(&PrpingWarning::IntervalClamped { requested: 0.0 }));
    assert!(warnings.contains(&PrpingWarning::ParallelUdpIgnored));
}

#[test]
fn run_parallel_ignored_warning() {
    // 非带宽模式 --parallel 无效 → 橙色警告（config 级不变式在 lib run 内）
    let mut cfg = ping_config();
    cfg.port = 1; // TCP ping（无服务，先看警告）
    cfg.parallel = 4;
    let mut warnings = Vec::new();
    let _ = run(&cfg, |w| warnings.push(w));
    assert!(warnings.contains(&PrpingWarning::ParallelIgnored));
}

#[test]
fn run_conflict_v4_v6_error() {
    // -4 与 -6 冲突：config 级不变式收敛在 lib run（bin validate 只查 CLI 级）
    let mut cfg = ping_config();
    cfg.port = 1;
    cfg.v4 = true;
    cfg.v6 = true;
    let err = run(&cfg, |_| {}).expect_err("should fail");
    assert!(matches!(err, PrpingError::ConflictV4V6));
}

#[test]
fn run_receive_ignored_for_ping() {
    let mut cfg = ping_config();
    cfg.port = 1; // TCP ping（无服务，先看警告）
    cfg.receive = true;
    let mut warnings = Vec::new();
    let _ = run(&cfg, |w| warnings.push(w));
    assert!(warnings.contains(&PrpingWarning::ReceiveIgnoredPing));
}

#[test]
fn run_udp_size_clamped_warning() {
    let mut cfg = ping_config();
    cfg.bandwidth = true;
    cfg.udp = true;
    cfg.size = Some(100_000);
    cfg.port = 1;
    let mut warnings = Vec::new();
    let _ = run(&cfg, |w| warnings.push(w));
    assert!(warnings.contains(&PrpingWarning::UdpSizeClamped {
        requested: 100_000,
        max: 65507
    }));
}

fn ping_config() -> PingConfig {
    PingConfig {
        host: "127.0.0.1".into(),
        port: 0,
        count: 1,
        duration: None,
        interval: 1.0,
        size: None,
        quiet: true,
        histogram: None,
        warmup: 0,
        v4: false,
        v6: false,
        parallel: 1,
        udp: false,
        receive: false,
        bandwidth: false,
        graph: false,
        mtu: false,
        traceroute: false,
        trace_tcp: false,
        trace_udp: false,
        max_hops: 30,
        no_dns: false,
        source: None,
    }
}

#[test]
fn run_traceroute_requires_no_port() {
    // 默认 ICMP trace 不接受端口：分派层错误（先于 socket 创建，离线可测）
    let mut cfg = ping_config();
    cfg.traceroute = true;
    cfg.port = 80;
    let err = run(&cfg, |_| {}).expect_err("should fail");
    assert!(matches!(err, PrpingError::TracerouteRequiresNoPort));
}

#[test]
fn run_tcp_trace_requires_port() {
    // --tcp 必须带端口（HOST:PORT）：分派层错误（先于 socket 创建，离线可测）
    let mut cfg = ping_config();
    cfg.traceroute = true;
    cfg.trace_tcp = true;
    cfg.port = 0;
    let err = run(&cfg, |_| {}).expect_err("should fail");
    assert!(matches!(err, PrpingError::TcpTraceRequiresPort));
}

#[test]
fn run_udp_trace_conflicts_with_tcp() {
    // --tcp 与 --udp 互斥：分派层错误
    let mut cfg = ping_config();
    cfg.traceroute = true;
    cfg.trace_tcp = true;
    cfg.trace_udp = true;
    cfg.port = 80;
    let err = run(&cfg, |_| {}).expect_err("should fail");
    assert!(matches!(err, PrpingError::TraceProtoConflict));
}

#[test]
fn run_udp_trace_requires_no_port() {
    // --udp 不带端口（33434 起自动递增）：带端口报错
    let mut cfg = ping_config();
    cfg.traceroute = true;
    cfg.trace_udp = true;
    cfg.port = 80;
    let err = run(&cfg, |_| {}).expect_err("should fail");
    assert!(matches!(err, PrpingError::TracerouteRequiresNoPort));
}

// ---------- 源绑定 -s ----------

/// TCP ping 指定源地址：本地监听 + 源绑定 127.0.0.1，连接来自该地址。
#[test]
fn tcp_ping_with_source_bind() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, peer) = listener.accept().unwrap();
        assert_eq!(peer.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        let mut buf = [0u8; 16];
        let _ = s.read(&mut buf);
    });
    reset_interrupt();
    let mut cfg = ping_config();
    cfg.host = "127.0.0.1".into();
    cfg.port = port;
    cfg.count = 1;
    cfg.source = Some("127.0.0.1".parse().unwrap());
    let outcome = run(&cfg, |_| {}).expect("run");
    let prping_core::OutcomeKind::Ping(stats) = outcome else {
        panic!("期望 Ping 统计");
    };
    assert_eq!(stats.received, 1, "应收到 1 次成功");
    server.join().unwrap();
}

// ---------- 带宽客户端四方向（进程内，run() 同步 + serve 全局 executor） ----------

/// 起 serve（全局 executor）+ 客户端 run() 带宽模式，返回（客户端报告, 服务端报告）。
fn bw_client(
    count: u64,
    size: usize,
    udp: bool,
    receive: bool,
) -> (prping_core::BandwidthReport, prping_core::ServerReport) {
    let _guard = SERVER_LOCK.lock().unwrap();
    reset_interrupt();
    let port = alloc_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let handle = smol::spawn(async move { serve(addr, false, false, None).await.expect("serve") });
    wait_port(port);
    let cfg = PingConfig {
        host: "127.0.0.1".into(),
        port,
        count,
        duration: None,
        interval: 1.0,
        size: Some(size),
        quiet: true,
        histogram: None,
        warmup: 0,
        v4: false,
        v6: false,
        parallel: 1,
        udp,
        receive,
        bandwidth: true,
        source: None,
        graph: false,
        mtu: false,
        traceroute: false,
        trace_tcp: false,
        trace_udp: false,
        max_hops: 30,
        no_dns: false,
    };
    let kind = run(&cfg, |_| {}).expect("run");
    let report = match kind {
        OutcomeKind::Bandwidth(r) => r,
        _ => panic!("expected bandwidth outcome"),
    };
    set_interrupted(true);
    let server_report = smol::block_on(handle);
    reset_interrupt();
    (report, server_report)
}

#[test]
fn bandwidth_tcp_send_client() {
    let (r, srv) = bw_client(100, 8192, false, false);
    assert_eq!(r.total_bytes, 819200);
    assert!(srv.connections >= 1);
}

#[test]
fn bandwidth_tcp_receive_client() {
    let (r, srv) = bw_client(100, 8192, false, true);
    assert_eq!(r.total_bytes, 819200);
    assert!(srv.sent > 0, "server should send data in receive mode");
}

#[test]
fn bandwidth_udp_send_client() {
    let (r, _srv) = bw_client(100, 8192, true, false);
    assert_eq!(r.total_bytes, 819200);
}

#[test]
fn bandwidth_udp_receive_client() {
    let (r, srv) = bw_client(100, 8192, true, true);
    assert_eq!(r.total_bytes, 819200);
    assert!(srv.sent > 0);
}
