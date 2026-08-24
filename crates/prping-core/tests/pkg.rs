//! `--pkt` 测试：载荷提取 + 真实本地监听发送（TCP/UDP 回显）+ 错误路径。

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;

use packet_dsl::Serializer;
use packet_dsl::ast::BinOp;
use packet_dsl::semantic::parse_str;
use prping_core::{
    ExtractAs, OnError, PkgOptions, SendMode, StepRaw, Transport, extract_payload, parse_recipe,
    send_packets, send_recipe, step_send_mode,
};

fn build_packets(src: &str) -> Vec<packet_dsl::ir::PacketSpec> {
    let m = parse_str("t", src).expect("解析成功");
    packet_dsl::resolve(&m).expect("求值成功").packets
}

/// dissect 契约：层头解析只走 proto 注册表（Rust 手写 parse_* 已退役）——
/// 直接调 `packet_dsl::dissect`/`render_dissected`/`sniffer_match` 的测试须先注册。
fn ensure_registry() {
    prping_core::ensure_proto_registry();
}

/// 写临时 .pkt 文件，返回路径（进程结束由系统清理）。
fn temp_pkt(name: &str, src: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("prping-pkg-{name}-{}.pkt", std::process::id()));
    std::fs::write(&p, src).expect("写临时文件");
    p
}

// ── 载荷提取 ─────────────────────────────────────────────────

#[test]
fn extract_tcp_payload() {
    ensure_registry();
    let pkts = build_packets(
        "a = http(start_line=\"GET / HTTP/1.1\")\nuse(a) |> tcp(dport=80) |> ipv4() |> eth()\n",
    );
    let (transport, payload) = extract_payload(&pkts[0]).expect("应有载荷");
    assert_eq!(transport, Transport::Tcp);
    assert_eq!(payload, b"GET / HTTP/1.1\r\n\r\n");
}

#[test]
fn extract_udp_payload() {
    let pkts = build_packets(
        "a = dns(questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n",
    );
    let (transport, payload) = extract_payload(&pkts[0]).expect("应有载荷");
    assert_eq!(transport, Transport::Udp);
    assert!(payload.len() >= 12);
    assert_eq!(&payload[2..4], &[0x01, 0x00], "默认 flags = RD");
}

#[test]
fn extract_none_without_transport() {
    let pkts = build_packets("a = raw(bytes=\"x\")\nexport:\n- a\n");
    assert!(extract_payload(&pkts[0]).is_none());
}

#[test]
fn extract_uses_outermost_transport() {
    // 内层 udp 被外层 tcp 包裹 → 取 tcp，载荷 = 内层 udp 的序列化
    let pkts = build_packets(
        "a = dns(questions=[\"x\"])\nuse(a) |> udp(dport=53) |> tcp(dport=80) |> ipv4()\n",
    );
    let (transport, payload) = extract_payload(&pkts[0]).expect("应有载荷");
    assert_eq!(transport, Transport::Tcp);
    assert!(
        payload.len() > 12,
        "载荷应含内层 UDP 序列化：{} B",
        payload.len()
    );
}

// ── 真实发送（本地监听）─────────────────────────────────────

#[test]
fn send_udp_payload_reaches_listener() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let target = sock.local_addr().unwrap();
    let sock2 = Arc::clone(&sock);
    let (got_tx, got_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let (n, peer) = sock2.recv_from(&mut buf).unwrap();
        let data = buf[..n].to_vec();
        got_tx.send(data.clone()).unwrap();
        let _ = sock2.send_to(&data, peer); // 回显
    });

    let file = temp_pkt(
        "udp",
        "a = dns(questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n",
    );
    send_packets(
        &file,
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .expect("发送成功");
    server.join().unwrap();

    let got = got_rx.recv().unwrap();
    // 载荷 = DNS 查询（id 随机，检查问题段 "example" + 0x03 + "com"）
    assert!(
        got.windows(8).any(|w| w == b"\x07example"),
        "监听端收到的载荷：{}",
        got.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
}

#[test]
fn send_tcp_payload_reaches_listener() {
    ensure_registry();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap();
    let (got_tx, got_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut data = Vec::new();
        conn.read_to_end(&mut data).unwrap(); // 等 EOF（prping shutdown(Write)）
        got_tx.send(data).unwrap();
        let _ = conn.write_all(b"HTTP/1.1 200 OK\r\n\r\n"); // 回显响应
    });

    let file = temp_pkt(
        "tcp",
        "a = http(start_line=\"GET / HTTP/1.1\")\nuse(a) |> tcp(dport=80) |> ipv4() |> eth()\n",
    );
    send_packets(
        &file,
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .expect("发送成功");
    server.join().unwrap();

    let got = got_rx.recv().unwrap();
    assert_eq!(got, b"GET / HTTP/1.1\r\n\r\n");
}

// ── 错误路径 ─────────────────────────────────────────────────

#[test]
fn no_transport_layer_fails_with_hint() {
    let file = temp_pkt("no-transport", "a = raw(bytes=\"x\")\nexport:\n- a\n");
    let target = "127.0.0.1:9".parse().unwrap();
    let err = send_packets(
        &file,
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("没有可发送的包"), "{msg}");
}

#[test]
fn missing_file_is_error() {
    let target = "127.0.0.1:9".parse().unwrap();
    let err = send_packets(
        &PathBuf::from("/nonexistent/x.pkt"),
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(!err.to_string().is_empty());
}

/// 裸导出（最外层不是 eth/ipv4/ipv6，如裸 http/arp）raw 模式与 payload 模式一致：
/// 跳过不发送（全部跳过时汇总报「没有可发送的包」）。
#[test]
fn raw_bare_export_is_skipped() {
    for src in [
        "a = http()\nexport:\n- a\n",
        "req = arp(op=request())\nexport:\n- req\n",
    ] {
        let file = temp_pkt("raw-bare", src);
        let err = send_packets(
            &file,
            &PkgOptions {
                mode: SendMode::Raw { iface: None },
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("没有可发送的包"),
            "裸导出应跳过并汇总报错：{err}"
        );
    }
}

/// 有传输层但最外层不是 eth/ipv4/ipv6（如裸 tcp 无外层）raw 模式仍报错——不是
/// 组合元件，是缺外层封装的真错误。
#[test]
fn raw_transport_without_outer_layer_is_error() {
    let file = temp_pkt("raw-tcp-bare", "a = http()\nuse(a) |> tcp(dport=80)\n");
    let err = send_packets(
        &file,
        &PkgOptions {
            mode: SendMode::Raw { iface: None },
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("failed to send"),
        "裸传输层应逐包报错：{err}"
    );
}

/// 链路层帧（ARP：eth 外层、无 IP 层）raw 模式省略目标不再报「没有定义目标地址」——
/// AF_PACKET 按帧内目的 MAC 直发。有 cap_net_raw 时发送成功；无权限时失败也应是
/// raw socket 权限错误（而非目标缺失）。
#[test]
fn raw_link_layer_frame_without_target_is_sendable() {
    let file = temp_pkt(
        "link-arp",
        "req = arp(op=request(), sha=\"00:11:22:33:44:55\", spa=\"127.0.0.1\", \
         tha=\"00:00:00:00:00:00\", tpa=\"127.0.0.1\")\n\
         use(req) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"ff:ff:ff:ff:ff:ff\")\n",
    );
    match send_packets(
        &file,
        &PkgOptions {
            mode: SendMode::Raw { iface: None },
            ..Default::default()
        },
    ) {
        Ok(()) => {} // cap_net_raw 就绪：发送成功
        Err(e) => {
            let msg = e.to_string();
            assert!(!msg.contains("目标地址"), "链路层帧不应报目标缺失：{msg}");
            assert!(
                msg.contains("failed to send"),
                "无权限时也应走发送失败路径而非目标解析失败：{msg}"
            );
        }
    }
}

#[test]
fn empty_file_is_error() {
    let file = temp_pkt("empty", "# 只有注释\n");
    let target = "127.0.0.1:9".parse().unwrap();
    let err = send_packets(
        &file,
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("没有可发送的包"), "{err}");
}

#[test]
fn tcp_listener_close_without_response_still_ok() {
    // 服务端只收不发：prping 应超时收尾而非报错
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut data = Vec::new();
        conn.read_to_end(&mut data).unwrap();
        data.len()
    });
    let file = temp_pkt(
        "tcp-noreply",
        "a = http()\nuse(a) |> tcp(dport=80) |> ipv4() |> eth()\n",
    );
    send_packets(
        &file,
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .expect("无回显也应成功");
    assert_eq!(server.join().unwrap(), 18);
}

// ── 目标推导（--pkt FILE 省略 HOST:PORT）────────────────────

#[test]
fn derive_target_ipv4_with_port() {
    let pkts = build_packets(
        "a = dns(questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4(dst=\"8.8.8.8\") |> eth()\n",
    );
    let addr = prping_core::derive_target(&pkts[0], true).expect("应推导出目标");
    assert_eq!(addr, "8.8.8.8:53".parse().unwrap());
}

#[test]
fn derive_target_ipv6_raw_no_port() {
    let pkts = build_packets(
        "a = raw(bytes=\"x\")\nuse(a) |> icmp() |> ipv6(dst=\"2001:4860:4860::8888\") |> eth()\n",
    );
    let addr = prping_core::derive_target(&pkts[0], false).expect("应推导出目标");
    assert_eq!(addr.ip().to_string(), "2001:4860:4860::8888");
    assert_eq!(addr.port(), 0);
}

#[test]
fn derive_target_without_ip_is_error() {
    let pkts = build_packets("a = http()\nuse(a) |> tcp(dport=443)\n");
    let err = prping_core::derive_target(&pkts[0], true).unwrap_err();
    assert!(err.to_string().contains("目标地址"), "{err}");
}

#[test]
fn derive_target_missing_dport_is_error() {
    // 库版 tcp()/udp() 默认 dport=0 已写进头字节；用不足 4B 的字节直喂层构造缺失
    let pkts = build_packets(
        "a = http()\nuse(a) |> tcp_bytes(bytes=\"ab\") |> ipv4(dst=\"1.2.3.4\") |> eth()\n",
    );
    let err = prping_core::derive_target(&pkts[0], true).unwrap_err();
    assert!(err.to_string().contains("dport"), "{err}");
}

/// 省略目标的端到端发送：包内 ipv4 dst + udp dport 指向监听 socket。
#[test]
fn send_without_explicit_target_derives_from_packet() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let listener_port = sock.local_addr().unwrap().port();
    let sock2 = Arc::clone(&sock);
    let (got_tx, got_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let (n, _peer) = sock2.recv_from(&mut buf).unwrap();
        let _ = got_tx.send(buf[..n].to_vec());
    });

    // dst/dport 写死在包内：dst=127.0.0.1，dport=监听端口
    let src = format!(
        "a = dns(questions=[\"example.com\"])\nuse(a) |> udp(dport={listener_port}) |> ipv4(src=\"127.0.0.1\", dst=\"127.0.0.1\") |> eth()\n"
    );
    let file = temp_pkt("derive-udp", &src);
    send_packets(
        &file,
        &PkgOptions {
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .expect("推导目标发送成功");
    server.join().unwrap();
    let got = got_rx.recv().unwrap();
    assert!(
        got.windows(8).any(|w| w == b"\x07example"),
        "监听端应收到 DNS 载荷"
    );
}

// ── 运行时参数（--params / params("name")）───────────────────

/// 参数化发送：dport/dst 都由 params 提供 → 推导目标 = 127.0.0.1:监听端口。
#[test]
fn send_with_params_end_to_end() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let listener_port = sock.local_addr().unwrap().port();
    let sock2 = Arc::clone(&sock);
    let (got_tx, got_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let (n, _peer) = sock2.recv_from(&mut buf).unwrap();
        let _ = got_tx.send(buf[..n].to_vec());
    });

    // 包内 dport/dst 全部来自 params(...)
    let src = "a = dns(questions=[\"example.com\"])\nuse(a) |> udp(dport=params(\"port\")) |> ipv4(dst=params(\"dst\")) |> eth()\n";
    let file = temp_pkt("params-udp", src);
    let params = vec![
        ("port".to_string(), listener_port.to_string()),
        ("dst".to_string(), "127.0.0.1".to_string()),
    ];
    send_packets(
        &file,
        &PkgOptions {
            mode: SendMode::Payload,
            params,
            ..Default::default()
        },
    )
    .expect("参数化发送成功");
    server.join().unwrap();
    let got = got_rx.recv().unwrap();
    assert!(
        got.windows(8).any(|w| w == b"\x07example"),
        "监听端应收到 DNS 载荷"
    );
}

/// 缺失参数（无默认值）→ 报错且逐包失败汇总。
#[test]
fn send_with_missing_param_fails() {
    let file = temp_pkt(
        "params-missing",
        "a = http()\nuse(a) |> udp(dport=params(\"port\")) |> ipv4(dst=\"127.0.0.1\") |> eth()\n",
    );
    let target = "127.0.0.1:9".parse().unwrap();
    let err = send_packets(
        &file,
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("未提供"), "{err}");
}

/// random 关键字已随内置层函数移除：`ipv4(dst="random")` 在求值阶段即被
/// ip4 原语拒绝（随机值改用 rand16/rand8 等字节原语在构建期生成）。
#[test]
fn random_dst_keyword_is_rejected() {
    let m = parse_str(
        "t",
        "a = http()\nuse(a) |> tcp(dport=443) |> ipv4(dst=\"random\") |> eth()\n",
    )
    .expect("解析成功");
    let err = packet_dsl::resolve(&m).expect_err("random 应被拒绝");
    assert!(err.to_string().contains("random"), "{err}");
}

/// pkglang 组合函数（net4 式）：默认 src 随机但 dst 显式 → 可推导目标。
#[test]
fn derive_target_through_func() {
    let pkts = build_packets(
        "func net4(dst) { ipv4(dst=dst) |> eth() }\na = http()\nuse(a) |> tcp(dport=443) |> net4(dst=\"8.8.8.8\")\n",
    );
    let addr = prping_core::derive_target(&pkts[0], true).expect("应推导出目标");
    assert_eq!(addr, "8.8.8.8:443".parse().unwrap());
}

/// --pkt --wait：UDP 回显应答（DNS id 匹配），等待路径不挂起且能收到回显。
#[test]
fn send_with_wait_gets_udp_echo() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let target = sock.local_addr().unwrap();
    let sock2 = Arc::clone(&sock);
    let (got_tx, got_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let (n, peer) = sock2.recv_from(&mut buf).unwrap();
        let data = buf[..n].to_vec();
        got_tx.send(data.clone()).unwrap();
        // 先发一个错误 id 的杂包，再回显正确 id —— wait 应跳过杂包
        let _ = sock2.send_to(&buf[..2].iter().map(|_| 0u8).collect::<Vec<_>>(), peer);
        let _ = sock2.send_to(&data, peer);
    });
    let file = temp_pkt(
        "wait-udp",
        "a = dns(id=0x4242, questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4(dst=\"127.0.0.1\") |> eth()\n",
    );
    let opts = prping_core::PkgOptions {
        target: Some(target),
        mode: SendMode::Payload,
        wait: Some(2.0),
        ..Default::default()
    };
    send_packets(&file, &opts).expect("wait 发送应成功");
    server.join().unwrap();
    let got = got_rx.recv().unwrap();
    assert!(
        got.windows(8).any(|w| w == b"\x07example"),
        "监听端应收到 DNS 查询"
    );
}

// ── sniffer（回包匹配）─────────────────────────────────────

/// sniffer_match：DNS 同 id 应答匹配；杂包/异 id 不匹配；字面量常量比较。
#[test]
fn sniffer_match_dns_id() {
    ensure_registry();
    let m = parse_str(
        "t",
        "a = dns(id=0x4242, questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n\
sniffer:\n  - match dns(id=id)\n",
    )
    .unwrap();
    let spec = m.sniffer.clone().expect("应有 sniffer");
    // 发包序列化字节（载荷 = 裸 DNS 查询，id=0x4242）
    let built = packet_dsl::resolve(&m).unwrap();
    let sent = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    let payload = prping_core::extract_payload(&built.packets[0]).unwrap().1;
    // 同 id 应答 → 匹配
    let reply = {
        let mut b = payload.clone();
        b[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // 标记为应答
        b
    };
    let got = prping_core::sniffer_match(&spec, &reply, &payload).unwrap();
    let got = got.expect("同 id 应答应匹配");
    assert_eq!(
        got,
        vec![("id".to_string(), "16962".to_string())],
        "{got:?}"
    );
    // 异 id 应答 → 不匹配
    let bad = {
        let mut b = payload.clone();
        b[0..2].copy_from_slice(&0x9999u16.to_be_bytes());
        b
    };
    assert_eq!(
        prping_core::sniffer_match(&spec, &bad, &payload).unwrap(),
        None,
        "异 id 不应匹配"
    );
    // 纯杂包（无法反解出 dns）→ 不匹配
    assert_eq!(
        prping_core::sniffer_match(&spec, b"junkjunkjunk", &payload).unwrap(),
        None
    );
    let _ = sent;
}

/// sniffer_match：常量 + sent 引用组合（icmp type=0, id=id, seq=seq）。
#[test]
fn sniffer_match_icmp_echo_reply() {
    let m = parse_str(
        "t",
        "p = raw(bytes=\"x\")\nuse(p) |> icmp(id=7, seq=3) |> ipv4(src=\"1.2.3.4\", dst=\"8.8.8.8\") |> eth()\n\
sniffer:\n  - match icmp(type=0, id=id, seq=seq)\n",
    )
    .unwrap();
    let spec = m.sniffer.clone().unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let sent = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    // echo reply：type=0，id/seq 与发包一致
    let mut reply = sent.clone();
    reply[34] = 0; // icmp type 偏移（eth14+ipv4 20）= 34 → echo reply
    reply[35] = 0; // code
    let got = prping_core::sniffer_match(&spec, &reply, &sent).unwrap();
    let got = got.expect("echo reply 应匹配");
    assert_eq!(got.len(), 3, "{got:?}");
    assert_eq!(got[0], ("type".to_string(), "0".to_string()));
    assert_eq!(got[1], ("id".to_string(), "7".to_string()));
    assert_eq!(got[2], ("seq".to_string(), "3".to_string()));
    // type=8（还是 echo request）→ 不匹配
    let mut req = sent.clone();
    req[34] = 8;
    assert_eq!(
        prping_core::sniffer_match(&spec, &req, &sent).unwrap(),
        None
    );
}

/// sniffer 字段名非法 → 发送前报错。
#[test]
fn sniffer_unknown_field_errors() {
    let file = temp_pkt(
        "sn-bad-field",
        "a = dns()\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n\
sniffer:\n  - match dns(nonexistent=1)\n",
    );
    let err = send_packets(
        &file,
        &PkgOptions {
            wait: Some(1.0),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("没有字段"),
        "应有字段校验错误：{err}"
    );
}

/// --pkt --wait + sniffer：跳过杂包，同 id 应答匹配（回环 UDP）。
#[test]
fn send_with_sniffer_skips_junk_and_matches() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let target = sock.local_addr().unwrap();
    let sock2 = Arc::clone(&sock);
    let (got_tx, got_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let (n, peer) = sock2.recv_from(&mut buf).unwrap();
        let data = buf[..n].to_vec();
        got_tx.send(data.clone()).unwrap();
        // 先回杂包（id 错），再回同 id 应答
        let _ = sock2.send_to(&[0x12, 0x34, 0x01, 0x00, b'j', b'u'], peer);
        let _ = sock2.send_to(&data, peer);
    });
    let file = temp_pkt(
        "sn-wait-udp",
        "a = dns(id=0x4242, questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4(dst=\"127.0.0.1\") |> eth()\n\
sniffer:\n  - match dns(id=id)\n",
    );
    let opts = prping_core::PkgOptions {
        target: Some(target),
        mode: SendMode::Payload,
        wait: Some(2.0),
        ..Default::default()
    };
    send_packets(&file, &opts).expect("wait + sniffer 发送应成功");
    server.join().unwrap();
    let got = got_rx.recv().unwrap();
    assert!(
        got.windows(8).any(|w| w == b"\x07example"),
        "监听端应收到 DNS 查询"
    );
}

/// --pkt --wait + sniffer：值表达式（用户值函数）经完整发送路径匹配应答。
#[test]
fn send_with_sniffer_expr_matches() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let target = sock.local_addr().unwrap();
    let sock2 = Arc::clone(&sock);
    let (got_tx, got_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let (n, peer) = sock2.recv_from(&mut buf).unwrap();
        let data = buf[..n].to_vec();
        got_tx.send(data.clone()).unwrap();
        // 先回杂包（id 错），再回同 id 应答
        let _ = sock2.send_to(&[0x12, 0x34, 0x01, 0x00, b'j', b'u'], peer);
        let _ = sock2.send_to(&data, peer);
    });
    let file = temp_pkt(
        "sn-wait-udp-expr",
        "func myid() -> bytes { be16(params(\"id\", \"0x4242\")) }\n\
a = dns(id=0x4242, questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4(dst=\"127.0.0.1\") |> eth()\n\
sniffer:\n  - match dns(id=myid())\n",
    );
    let opts = prping_core::PkgOptions {
        target: Some(target),
        mode: SendMode::Payload,
        wait: Some(2.0),
        params: vec![("id".to_string(), "0x4242".to_string())],
        ..Default::default()
    };
    send_packets(&file, &opts).expect("wait + 值函数表达式 sniffer 发送应成功");
    server.join().unwrap();
    let got = got_rx.recv().unwrap();
    assert!(
        got.windows(8).any(|w| w == b"\x07example"),
        "监听端应收到 DNS 查询"
    );
}

// ── 源地址自动填充（raw 发送）───────────────────────────────

/// patch_zero_src：src=0.0.0.0 填充为本地地址并重算 IPv4 header checksum。
#[test]
fn patch_zero_src_fills_and_rechecksums() {
    let m = parse_str(
        "t",
        "p = raw(bytes=\"x\")\nuse(p) |> icmp(id=7, seq=3) |> ipv4(src=\"0.0.0.0\", dst=\"8.8.8.8\") |> eth()\n",
    )
    .unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let pkt = &built.packets[0];
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    let (mut bytes, parts) = ser.serialize_parts(pkt).unwrap();
    let src_off = 14 + 12; // eth 14B + ipv4 src 偏移 12
    assert_eq!(
        &bytes[src_off..src_off + 4],
        &[0, 0, 0, 0],
        "填充前 src=0.0.0.0"
    );
    prping_core::patch_zero_src(
        &mut bytes,
        &parts,
        &pkt.layers,
        "192.168.1.10".parse().unwrap(),
    );
    assert_eq!(
        &bytes[src_off..src_off + 4],
        &[192, 168, 1, 10],
        "src 应填充为本地地址"
    );
    // header checksum 验证：清零 checksum 字段后求和，应为 !sum
    let mut hdr = bytes[14..14 + 20].to_vec();
    hdr[10] = 0;
    hdr[11] = 0;
    let mut sum = 0u32;
    for ch in hdr.chunks_exact(2) {
        sum += u16::from_be_bytes([ch[0], ch[1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    assert_eq!(
        u16::from_be_bytes([bytes[14 + 10], bytes[14 + 11]]),
        !(sum as u16),
        "checksum 应重算有效"
    );
}

/// patch_zero_src：用户显式指定的非零 src 不被覆盖。
#[test]
fn patch_zero_src_keeps_explicit() {
    let m = parse_str(
        "t",
        "p = raw(bytes=\"x\")\nuse(p) |> icmp(id=7, seq=3) |> ipv4(src=\"1.2.3.4\", dst=\"8.8.8.8\") |> eth()\n",
    )
    .unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let pkt = &built.packets[0];
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    let (mut bytes, parts) = ser.serialize_parts(pkt).unwrap();
    prping_core::patch_zero_src(
        &mut bytes,
        &parts,
        &pkt.layers,
        "192.168.1.10".parse().unwrap(),
    );
    let src_off = 14 + 12;
    assert_eq!(
        &bytes[src_off..src_off + 4],
        &[1, 2, 3, 4],
        "显式 src 不应被覆盖"
    );
}

/// 域名解析来源在层字段展示中标注 dns(host->ip)。
#[test]
fn render_shows_dns_source() {
    let m = parse_str(
        "t",
        "p = raw(bytes=\"x\")\nuse(p) |> icmp() |> ipv4(src=\"1.1.1.1\", dst=\"example.com\") |> eth()\n",
    )
    .unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    let mut out = termcolor::NoColor::new(Vec::new());
    prping_core::render_packet_fields(&mut out, &built.packets[0], "hdr", &ser).unwrap();
    let text = String::from_utf8(out.into_inner()).unwrap();
    // 标注格式（实际解析 IP 取决于进程里哪个解析器先注册——格式是稳定的）
    assert!(text.contains("dst=dns(example.com->"), "{text}");
    // 字面量 IP 不标注
    let m2 = parse_str(
        "t",
        "p = raw(bytes=\"x\")\nuse(p) |> icmp() |> ipv4(src=\"1.1.1.1\", dst=\"5.6.7.8\") |> eth()\n",
    )
    .unwrap();
    let built2 = packet_dsl::resolve(&m2).unwrap();
    let mut out2 = termcolor::NoColor::new(Vec::new());
    prping_core::render_packet_fields(&mut out2, &built2.packets[0], "hdr", &ser).unwrap();
    let text2 = String::from_utf8(out2.into_inner()).unwrap();
    assert!(
        text2.contains("dst=5.6.7.8") && !text2.contains("dns("),
        "{text2}"
    );
}

/// DNS 层展示：字节直喂/反解路径显示问题域名与回答（不再只显示 bytes=0x…）。
#[test]
fn render_dns_shows_question_names() {
    ensure_registry();
    let m = parse_str(
        "t",
        "q = dns(id=0xabcd, questions=[\"example.com\", \"www.example.com\"])\nuse(q) |> udp(dport=53) |> ipv4() |> eth()\n",
    )
    .unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    let mut out = termcolor::NoColor::new(Vec::new());
    prping_core::render_packet_fields(&mut out, &built.packets[0], "hdr", &ser).unwrap();
    let text = String::from_utf8(out.into_inner()).unwrap();
    assert!(text.contains("q=example.com(A)"), "{text}");
    assert!(text.contains("q=www.example.com(A)"), "{text}");
    assert!(
        !text.contains("bytes=0x"),
        "DNS 层应解析字段而非字节摘要: {text}"
    );
    // 反解路径（含回答 + 压缩指针）：answer 名与 rdata 一并展示
    let reply_hex = concat!(
        "abcd8180",
        "0001",
        "0001",
        "0000",
        "0000", // id + flags + qd=1 an=1 ns=0 ar=0
        "076578616d706c6503636f6d00",
        "0001",
        "0001", // 问题 example.com A IN
        "c00c",
        "0001",
        "0001",
        "0000012c",
        "0004",
        "5db8d822", // 回答：压缩指针 + A 93.184.216.34
    );
    let reply = build_packets(&format!(
        "a = hex(\"{reply_hex}\")\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n"
    ));
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&reply[0])
        .unwrap();
    let report = packet_dsl::dissect(&bytes);
    let mut out2 = termcolor::NoColor::new(Vec::new());
    prping_core::render_dissected(&mut out2, &report, "reply", &bytes).unwrap();
    let text2 = String::from_utf8(out2.into_inner()).unwrap();
    assert!(text2.contains("q=example.com(A)"), "{text2}");
    assert!(text2.contains("a=example.com:93.184.216.34"), "{text2}");
}

/// 多子句 sniffer：任一子句命中即匹配（回包是 icmp 或 dns 都算）。
#[test]
fn sniffer_multiple_clauses_or() {
    ensure_registry();
    let m = parse_str(
        "t",
        "a = dns(id=0x4242, questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n\
sniffer:\n  - match icmp(id=id, seq=seq)\n  - match dns(id=id)\n",
    )
    .unwrap();
    let spec = m.sniffer.clone().expect("应有 sniffer");
    let built = packet_dsl::resolve(&m).unwrap();
    let payload = prping_core::extract_payload(&built.packets[0]).unwrap().1;
    // 回包是 DNS 且 id 一致 → 第二个子句命中
    let reply = {
        let mut b = payload.clone();
        b[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        b
    };
    let got = prping_core::sniffer_match(&spec, &reply, &payload)
        .unwrap()
        .expect("DNS 子句应命中");
    assert_eq!(
        got,
        vec![("id".to_string(), "16962".to_string())],
        "{got:?}"
    );
    // 回包是 ICMP（echo reply 语义）但 id 不匹配 → 两个子句都不命中
    let bad = {
        let mut b = payload.clone();
        b[0..2].copy_from_slice(&0x9999u16.to_be_bytes());
        b
    };
    assert_eq!(
        prping_core::sniffer_match(&spec, &bad, &payload).unwrap(),
        None
    );
}

/// sniffer：值表达式（字节原语/字节列表）按**字节**级比较。
#[test]
fn sniffer_match_expr_primitives() {
    let m = parse_str(
        "t",
        "p = raw(bytes=\"x\")\nuse(p) |> icmp(id=7, seq=3) |> ipv4(src=\"1.2.3.4\", dst=\"8.8.8.8\") |> eth()\n\
sniffer:\n  - match icmp(type=u8(0), id=be16(7), seq=[0x00, 0x03])\n",
    )
    .unwrap();
    let spec = m.sniffer.clone().unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let sent = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    // echo reply：type=0，id/seq 与发包一致 → 表达式全部命中
    let mut reply = sent.clone();
    reply[34] = 0; // eth14 + ipv4 20 → icmp type
    reply[35] = 0; // code
    let got = prping_core::sniffer_match(&spec, &reply, &sent)
        .unwrap()
        .expect("字节级表达式应匹配");
    assert_eq!(
        got,
        vec![
            ("type".to_string(), "0".to_string()),
            ("id".to_string(), "7".to_string()),
            ("seq".to_string(), "3".to_string()),
        ],
        "{got:?}"
    );
    // id 不符（be16(7) 字节 [0x00,0x07]）→ 不匹配
    let mut bad = reply.clone();
    bad[38..40].copy_from_slice(&0x99u16.to_be_bytes());
    assert_eq!(
        prping_core::sniffer_match(&spec, &bad, &sent).unwrap(),
        None
    );
    // type=8（还是 echo request）→ u8(0) 不命中
    let mut req = sent.clone();
    req[35] = 0;
    assert_eq!(
        prping_core::sniffer_match(&spec, &req, &sent).unwrap(),
        None
    );
}

/// sniffer：值表达式可引用同文件值函数与 `params(...)`（需模块上下文）。
#[test]
fn sniffer_match_expr_user_func_and_params() {
    ensure_registry();
    let m = parse_str(
        "t",
        "func myid() -> bytes { be16(params(\"id\", \"7\")) }\n\
a = dns(id=0x1234, questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n\
sniffer:\n  - match dns(id=myid())\n",
    )
    .unwrap();
    let spec = m.sniffer.clone().unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let payload = prping_core::extract_payload(&built.packets[0]).unwrap().1;
    let mut params = std::collections::HashMap::new();
    params.insert("id".to_string(), "4660".to_string()); // 0x1234
    // 同 id 应答 → 匹配（表达式 = be16(params("id")) = [0x12, 0x34]）
    let reply = {
        let mut b = payload.clone();
        b[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        b
    };
    let got = prping_core::sniffer_match_with(&spec, Some(&m), &params, &reply, &payload)
        .unwrap()
        .expect("值函数表达式应匹配");
    assert_eq!(got, vec![("id".to_string(), "4660".to_string())], "{got:?}");
    // 异 id → 不匹配
    let bad = {
        let mut b = payload.clone();
        b[0..2].copy_from_slice(&0x9999u16.to_be_bytes());
        b
    };
    assert_eq!(
        prping_core::sniffer_match_with(&spec, Some(&m), &params, &bad, &payload).unwrap(),
        None
    );
}

/// sniffer 值表达式求值失败（未知函数）→ 发送前报错。
#[test]
fn sniffer_bad_expr_errors() {
    let file = temp_pkt(
        "sn-bad-expr",
        "a = dns()\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n\
sniffer:\n  - match dns(id=nonexistent_func())\n",
    );
    let err = send_packets(
        &file,
        &PkgOptions {
            wait: Some(1.0),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("匹配值表达式求值失败"),
        "应有表达式求值错误：{err}"
    );
}

// ── 配方（.pktl）──────────────────────────────────────────────

/// 建一组临时配方文件目录（每测试独立 tag；测试结束由 remove_dir_all 清理）。
fn temp_recipe_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("prping-recipe-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 配方解析：global 段 + 步骤选项（wait/params/extract/on_error）+ 裸文件名步骤。
#[test]
fn recipe_parse_full() {
    let dir = temp_recipe_dir("parse-full");
    let pktl = dir.join("flow.pktl");
    std::fs::write(
        &pktl,
        r#"global:
- name: tid
  init: 0x1234
- name: seq

recipe:
- pkg: a.pkt
  wait: 1.5
  params: k=1,k2=0x2
  extract:
  - name: seq
    from: reply.tcp.seq
    as: hex
  on_error: continue
- b.pkt
"#,
    )
    .unwrap();
    let r = parse_recipe(&pktl).expect("解析成功");
    assert_eq!(r.globals.len(), 2);
    assert_eq!(r.globals[0].name, "tid");
    assert_eq!(r.globals[0].init, Some(packet_dsl::ast::Value::Hex(0x1234)));
    assert_eq!(r.globals[1].init, None, "无 init = 未初始化");
    assert_eq!(r.steps.len(), 2);
    assert_eq!(r.steps[0].pkg, dir.join("a.pkt"));
    assert_eq!(r.steps[0].wait, Some(1.5));
    assert_eq!(
        r.steps[0].params,
        vec![("k".into(), "1".into()), ("k2".into(), "0x2".into())]
    );
    assert_eq!(r.steps[0].extract.len(), 1);
    assert_eq!(r.steps[0].extract[0].name, "seq");
    assert_eq!(
        r.steps[0].extract[0].from,
        prping_core::FromSpec::Field {
            layer: "tcp".into(),
            field: "seq".into()
        }
    );
    assert_eq!(r.steps[0].extract[0].as_, ExtractAs::Hex);
    assert!(r.steps[0].extract[0].as_given);
    assert_eq!(r.steps[0].on_error, OnError::Continue);
    assert_eq!(r.steps[1].pkg, dir.join("b.pkt"), "裸文件名 = 无选项步骤");
    assert!(r.steps[1].extract.is_empty());
    assert_eq!(r.steps[1].on_error, OnError::Stop, "默认 stop");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 配方解析：init 的字符串 / 字节列表 / 十进制形态。
#[test]
fn recipe_parse_init_values() {
    let dir = temp_recipe_dir("parse-init");
    let pktl = dir.join("init.pktl");
    std::fs::write(
        &pktl,
        r#"global:
- name: s
  init: "hello"
- name: n
  init: 42
- name: b
  init: [0xde, 0xad, 0xbe, 0xef]
recipe:
- a.pkt
"#,
    )
    .unwrap();
    let r = parse_recipe(&pktl).expect("解析成功");
    assert_eq!(
        r.globals[0].init,
        Some(packet_dsl::ast::Value::Str("hello".into()))
    );
    assert_eq!(r.globals[1].init, Some(packet_dsl::ast::Value::Int(42)));
    assert_eq!(
        r.globals[2].init,
        Some(packet_dsl::ast::Value::List(vec![
            packet_dsl::ast::Value::Hex(0xDE),
            packet_dsl::ast::Value::Hex(0xAD),
            packet_dsl::ast::Value::Hex(0xBE),
            packet_dsl::ast::Value::Hex(0xEF),
        ]))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 配方解析：global 项紧凑形态——`- X=v`（一行内联 init，与 `init:` 同字面量语法）
/// 与裸 `- X`（未初始化），并与 `- name: X` 形态混用。
#[test]
fn recipe_parse_global_compact() {
    let dir = temp_recipe_dir("parse-global-compact");
    let pktl = dir.join("compact.pktl");
    std::fs::write(
        &pktl,
        r#"global:
- tid=0x1234
- s="hello"
- n=42
- b=[0xde, 0xad]
- bare
- name: old
  init: 0x1
recipe:
- a.pkt
"#,
    )
    .unwrap();
    let r = parse_recipe(&pktl).expect("解析成功");
    assert_eq!(r.globals.len(), 6);
    assert_eq!(r.globals[0].name, "tid");
    assert_eq!(
        r.globals[0].init,
        Some(packet_dsl::ast::Value::Hex(0x1234)),
        "`- tid=0x1234` = name + 内联 init"
    );
    assert_eq!(
        r.globals[1].init,
        Some(packet_dsl::ast::Value::Str("hello".into()))
    );
    assert_eq!(r.globals[2].init, Some(packet_dsl::ast::Value::Int(42)));
    assert_eq!(
        r.globals[3].init,
        Some(packet_dsl::ast::Value::List(vec![
            packet_dsl::ast::Value::Hex(0xDE),
            packet_dsl::ast::Value::Hex(0xAD),
        ]))
    );
    assert_eq!(r.globals[4].name, "bare");
    assert_eq!(r.globals[4].init, None, "裸声明 = 未初始化");
    assert_eq!(r.globals[5].name, "old");
    assert_eq!(r.globals[5].init, Some(packet_dsl::ast::Value::Hex(0x1)));
    let _ = std::fs::remove_dir_all(&dir);
}

/// 配方解析：`from:` 表达式形态（`reply.<层>.<字段>` 叶子改写 + DSL 值表达式解析）
/// 与 `as:` 显式标记。
#[test]
fn recipe_parse_from_expr() {
    use packet_dsl::ast::Value;
    let dir = temp_recipe_dir("parse-expr");
    let pktl = dir.join("expr.pktl");
    std::fs::write(
        &pktl,
        r#"recipe:
- pkg: a.pkt
  wait: 1
  extract:
  - name: next_seq
    from: reply.tcp.seq + 1
  - name: ck
    from: cksum(reply.icmp.payload)
    as: bytes
  - name: tid
    from: reply.dns.id
"#,
    )
    .unwrap();
    let r = parse_recipe(&pktl).expect("解析成功");
    assert_eq!(r.steps[0].extract.len(), 3);

    // `reply.tcp.seq + 1` → BinOp(Add, Call(reply), Int(1))
    let e0 = &r.steps[0].extract[0];
    assert_eq!(e0.name, "next_seq");
    assert!(!e0.as_given, "未写 as: → as_given=false");
    let Some(Value::BinOp {
        op, left, right, ..
    }) = e0.from.as_expr()
    else {
        panic!("应为 BinOp(Add)，得到 {:?}", e0.from);
    };
    assert_eq!(*op, BinOp::Add);
    let Value::Call { name, args, .. } = &**left else {
        panic!("左操作数应为 reply 调用，得到 {left:?}");
    };
    assert_eq!(name, "reply");
    assert_eq!(args, &[Value::Str("tcp".into()), Value::Str("seq".into())]);
    assert!(matches!(**right, Value::Int(1)));

    // `cksum(reply.icmp.payload)` + as: bytes → as_given=true
    let e1 = &r.steps[0].extract[1];
    assert_eq!(e1.as_, ExtractAs::Bytes);
    assert!(e1.as_given);
    let Some(Value::Call { name, .. }) = e1.from.as_expr() else {
        panic!("应为 cksum 调用，得到 {:?}", e1.from);
    };
    assert_eq!(name, "cksum");

    // `reply.dns.id` 直取形态（字段在 sniffer 集内）→ Field
    let e2 = &r.steps[0].extract[2];
    assert_eq!(
        e2.from,
        prping_core::FromSpec::Field {
            layer: "dns".into(),
            field: "id".into()
        }
    );
    assert!(!e2.as_given, "直取形态缺省 as:int，as_given=false");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 配方端到端：`from:` 表达式提取——步骤 1 回包 dns.id=0x4321，表达式
/// `reply.dns.id + 1` → global.tid=0x4322，步骤 2 的 `global("tid")` 复用该值。
#[test]
fn recipe_extract_expr_feeds_next_step() {
    ensure_registry();
    let dir = temp_recipe_dir("extract-expr");
    std::fs::write(
        dir.join("step1.pkt"),
        "a = dns(id=0x4321, questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("step2.pkt"),
        "a = dns(id=global(\"tid\"), questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("flow.pktl"),
        "global:\n- name: tid\n  init: 0x1111\n\nrecipe:\n- pkg: step1.pkt\n  wait: 1\n  extract:\n  - name: tid\n    from: reply.dns.id + 1\n    as: int\n- step2.pkt\n",
    )
    .unwrap();

    // UDP 回显服务器：收两个数据报并回显，校验第二个的 DNS id = 0x4322（表达式结果）
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let target = sock.local_addr().unwrap();
    let sock2 = Arc::clone(&sock);
    let (got_tx, got_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut datagrams = Vec::new();
        for _ in 0..2 {
            let (n, peer) = sock2.recv_from(&mut buf).unwrap();
            let data = buf[..n].to_vec();
            datagrams.push(data.clone());
            let _ = sock2.send_to(&data, peer); // 回显
        }
        got_tx.send(datagrams).unwrap();
    });

    send_recipe(
        &dir.join("flow.pktl"),
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .expect("配方发送成功");
    server.join().unwrap();

    let datagrams = got_rx.recv().unwrap();
    assert_eq!(datagrams.len(), 2, "两个步骤各发一个数据报");
    let dns_id = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    assert_eq!(dns_id(&datagrams[0]), 0x4321, "步骤 1 DNS id");
    assert_eq!(
        dns_id(&datagrams[1]),
        0x4322,
        "步骤 2 应复用表达式提取的 tid（0x4321+1，而非 init 0x1111）：{:02x?}",
        &datagrams[1]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 配方解析错误路径：未知选项 / extract 缺 name / from 缺 reply. / 非法 init /
/// 重复 global / 空 recipe / 未知 on_error。
#[test]
fn recipe_parse_errors() {
    let cases: Vec<(&str, &str, &str)> = vec![
        (
            "unknown-opt.pktl",
            "recipe:\n- pkg: a.pkt\n  foo: 1\n",
            "未知步骤选项",
        ),
        (
            "extract-no-name.pktl",
            "recipe:\n- pkg: a.pkt\n  wait: 1\n  extract:\n  - from: reply.dns.id\n",
            "缺少 `name:`",
        ),
        (
            "from-no-reply.pktl",
            "recipe:\n- pkg: a.pkt\n  wait: 1\n  extract:\n  - name: x\n    from: dns.id\n",
            "`from` 表达式解析失败",
        ),
        (
            "from-bad-expr.pktl",
            "recipe:\n- pkg: a.pkt\n  wait: 1\n  extract:\n  - name: x\n    from: reply.tcp.seq +\n",
            "`from` 表达式解析失败",
        ),
        (
            "bad-init.pktl",
            "global:\n- name: x\n  init: not-a-value!\nrecipe:\n- a.pkt\n",
            "无法解析 `init` 值",
        ),
        (
            "inline-init-empty.pktl",
            "global:\n- tid=\nrecipe:\n- a.pkt\n",
            "init 值不能为空",
        ),
        (
            "colon-form.pktl",
            "global:\n- tid: 0x1234\nrecipe:\n- a.pkt\n",
            "global 项语法错误",
        ),
        (
            "dup-inline.pktl",
            "global:\n- tid=1\n- name: tid\nrecipe:\n- a.pkt\n",
            "重复声明",
        ),
        (
            "double-init.pktl",
            "global:\n- tid=1\n  init: 2\nrecipe:\n- a.pkt\n",
            "不能再跟 `init:` 行",
        ),
        (
            "dup-global.pktl",
            "global:\n- name: x\n- name: x\nrecipe:\n- a.pkt\n",
            "重复声明",
        ),
        (
            "empty-recipe.pktl",
            "global:\n- name: x\n",
            "`recipe:` 段至少需要一个步骤",
        ),
        (
            "bad-onerror.pktl",
            "recipe:\n- pkg: a.pkt\n  on_error: maybe\n",
            "`on_error` 只支持 stop / continue",
        ),
        (
            "raw-empty.pktl",
            "recipe:\n- pkg: a.pkt\n  raw:\n",
            "`raw` 需要 true / false 或网卡名",
        ),
    ];
    let dir = temp_recipe_dir("parse-errors");
    for (name, src, expect) in cases {
        let pktl = dir.join(name);
        std::fs::write(&pktl, src).unwrap();
        let err = parse_recipe(&pktl).unwrap_err();
        assert!(
            err.to_string().contains(expect),
            "{name} 应报 `{expect}`，得到：{err}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// 配方端到端：步骤 1 发 DNS 查询（id=0x4321）等回显，extract 应答的 dns.id →
/// global.tid；步骤 2 的 `global("tid")` 应复用 extract 值（而非 init 0x1111）。
#[test]
fn recipe_extract_feeds_next_step() {
    ensure_registry();
    let dir = temp_recipe_dir("extract");
    std::fs::write(
        dir.join("step1.pkt"),
        "a = dns(id=0x4321, questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("step2.pkt"),
        "a = dns(id=global(\"tid\"), questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("flow.pktl"),
        "global:\n- name: tid\n  init: 0x1111\n\nrecipe:\n- pkg: step1.pkt\n  wait: 1\n  extract:\n  - name: tid\n    from: reply.dns.id\n    as: int\n- step2.pkt\n",
    )
    .unwrap();

    // UDP 回显服务器：收两个数据报并回显，校验第二个的 DNS id 来自 extract
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let target = sock.local_addr().unwrap();
    let sock2 = Arc::clone(&sock);
    let (got_tx, got_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut datagrams = Vec::new();
        for _ in 0..2 {
            let (n, peer) = sock2.recv_from(&mut buf).unwrap();
            let data = buf[..n].to_vec();
            datagrams.push(data.clone());
            let _ = sock2.send_to(&data, peer); // 回显
        }
        got_tx.send(datagrams).unwrap();
    });

    send_recipe(
        &dir.join("flow.pktl"),
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .expect("配方发送成功");
    server.join().unwrap();

    let datagrams = got_rx.recv().unwrap();
    assert_eq!(datagrams.len(), 2, "两个步骤各发一个数据报");
    let dns_id = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    assert_eq!(dns_id(&datagrams[0]), 0x4321, "步骤 1 DNS id");
    assert_eq!(
        dns_id(&datagrams[1]),
        0x4321,
        "步骤 2 应复用 extract 的 tid（而非 init 0x1111）：{:02x?}",
        &datagrams[1]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 配方解析：步骤 `raw:` 开关——`true`（开 raw，网卡继承 CLI）/ `false`（强制载荷）/
/// 网卡名（`eth0` 或带引号 `"eth1"`）/ 未声明（继承 CLI）。
#[test]
fn recipe_parse_raw_option() {
    let dir = temp_recipe_dir("parse-raw");
    let pktl = dir.join("raw.pktl");
    std::fs::write(
        &pktl,
        r#"recipe:
- pkg: a.pkt
  raw: true
- pkg: b.pkt
  raw: false
- pkg: c.pkt
  raw: eth0
- pkg: d.pkt
  raw: "eth1"
- e.pkt
"#,
    )
    .unwrap();
    let r = parse_recipe(&pktl).expect("解析成功");
    assert_eq!(r.steps.len(), 5);
    assert_eq!(
        r.steps[0].raw,
        Some(StepRaw::On { iface: None }),
        "raw: true = 开 raw、网卡继承 CLI"
    );
    assert_eq!(r.steps[1].raw, Some(StepRaw::Off), "raw: false = 强制载荷");
    assert_eq!(
        r.steps[2].raw,
        Some(StepRaw::On {
            iface: Some("eth0".into())
        }),
        "raw: eth0 = 开 raw 并指定网卡"
    );
    assert_eq!(
        r.steps[3].raw,
        Some(StepRaw::On {
            iface: Some("eth1".into())
        }),
        "raw: \"eth1\" 剥引号后等价于 raw: eth1"
    );
    assert_eq!(r.steps[4].raw, None, "未声明 raw = 继承 CLI");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 步骤 `raw:` 覆盖 → 发送方式（`step_send_mode`）：未声明继承 CLI；
/// `raw: true` 强制 raw 且网卡继承 CLI `--iface`；`raw: 网卡` 覆盖网卡；
/// `raw: false` 强制载荷（覆盖 CLI `--raw`）。
#[test]
fn step_raw_mode_override() {
    let payload = SendMode::Payload;
    let cli_raw = SendMode::Raw {
        iface: Some("eth0".into()),
    };
    // 未声明 raw → 继承 CLI 模式
    assert_eq!(step_send_mode(&None, &payload), payload);
    assert_eq!(step_send_mode(&None, &cli_raw), cli_raw);
    // raw: true → 强制 raw；CLI 未给网卡则不填网卡
    assert_eq!(
        step_send_mode(&Some(StepRaw::On { iface: None }), &payload),
        SendMode::Raw { iface: None }
    );
    // raw: true + CLI --raw --iface eth0 → 网卡继承 eth0
    assert_eq!(
        step_send_mode(&Some(StepRaw::On { iface: None }), &cli_raw),
        cli_raw
    );
    // raw: eth1 → 强制 raw 并覆盖 CLI 网卡
    assert_eq!(
        step_send_mode(
            &Some(StepRaw::On {
                iface: Some("eth1".into())
            }),
            &cli_raw
        ),
        SendMode::Raw {
            iface: Some("eth1".into())
        }
    );
    // raw: false → 强制载荷（覆盖 CLI --raw）
    assert_eq!(step_send_mode(&Some(StepRaw::Off), &cli_raw), payload);
    assert_eq!(step_send_mode(&Some(StepRaw::Off), &payload), payload);
}

/// 配方端到端：CLI 以 `--raw` 运行，步骤声明 `raw: false` → 本步改走载荷发送
/// （UDP 数据报到达监听者，而非原始帧）。两个步骤都强制载荷，校验收到两个
/// 以 DNS id 开头的载荷数据报。
#[test]
fn recipe_raw_false_overrides_cli_raw() {
    ensure_registry();
    let dir = temp_recipe_dir("raw-false");
    std::fs::write(
        dir.join("step1.pkt"),
        "a = dns(id=0x4321, questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("step2.pkt"),
        "a = dns(id=0x4242, questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("flow.pktl"),
        "recipe:\n- pkg: step1.pkt\n  raw: false\n- pkg: step2.pkt\n  raw: false\n",
    )
    .unwrap();

    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let target = sock.local_addr().unwrap();
    let sock2 = Arc::clone(&sock);
    let (got_tx, got_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut datagrams = Vec::new();
        for _ in 0..2 {
            let (n, _) = sock2.recv_from(&mut buf).unwrap();
            datagrams.push(buf[..n].to_vec());
        }
        got_tx.send(datagrams).unwrap();
    });

    send_recipe(
        &dir.join("flow.pktl"),
        &PkgOptions {
            target: Some(target),
            // CLI 全局 raw：步骤 raw: false 必须覆盖它（否则走原始帧，监听者收不到载荷）
            mode: SendMode::Raw { iface: None },
            ..Default::default()
        },
    )
    .expect("配方发送成功");
    server.join().unwrap();

    let datagrams = got_rx.recv().unwrap();
    assert_eq!(datagrams.len(), 2, "两个步骤各发一个载荷数据报");
    let dns_id = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    assert_eq!(
        dns_id(&datagrams[0]),
        0x4321,
        "步骤 1 走载荷发送（DNS 头开头）"
    );
    assert_eq!(
        dns_id(&datagrams[1]),
        0x4242,
        "步骤 2 走载荷发送（DNS 头开头）"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
#[test]
fn recipe_on_error_stop_aborts() {
    let dir = temp_recipe_dir("onerr-stop");
    std::fs::write(dir.join("bad.pkt"), "this is not a valid pkt !!").unwrap();
    std::fs::write(
        dir.join("ok.pkt"),
        "a = raw(bytes=\"x\")\nuse(a) |> udp(dport=9) |> ipv4() |> eth()\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("flow.pktl"),
        "recipe:\n- pkg: bad.pkt\n- pkg: ok.pkt\n",
    )
    .unwrap();

    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let target = sock.local_addr().unwrap();
    let err = send_recipe(
        &dir.join("flow.pktl"),
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("on_error: stop"),
        "默认 stop 应中止配方：{err}"
    );
    drop(sock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// on_error: continue——步骤 1 解析失败仍继续步骤 2（发出数据报），最后退出码非零。
#[test]
fn recipe_on_error_continue_sends_rest() {
    let dir = temp_recipe_dir("onerr-cont");
    std::fs::write(dir.join("bad.pkt"), "this is not a valid pkt !!").unwrap();
    std::fs::write(
        dir.join("ok.pkt"),
        "a = raw(bytes=\"hello\")\nuse(a) |> udp(dport=9) |> ipv4() |> eth()\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("flow.pktl"),
        "recipe:\n- pkg: bad.pkt\n  on_error: continue\n- pkg: ok.pkt\n",
    )
    .unwrap();

    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let target = sock.local_addr().unwrap();
    let sock2 = Arc::clone(&sock);
    let (got_tx, got_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let (n, _) = sock2.recv_from(&mut buf).unwrap();
        got_tx.send(buf[..n].to_vec()).unwrap();
    });

    let err = send_recipe(
        &dir.join("flow.pktl"),
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Payload,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("有失败"),
        "continue 后汇总报错：{err}"
    );
    server.join().unwrap();
    let got = got_rx.recv().unwrap();
    assert!(
        got.windows(5).any(|w| w == b"hello"),
        "步骤 2 应已发送：{:02x?}",
        &got
    );
    let _ = std::fs::remove_dir_all(&dir);
}
