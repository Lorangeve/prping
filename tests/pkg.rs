//! `--pkg` 测试：载荷提取 + 真实本地监听发送（TCP/UDP 回显）+ 错误路径。

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;

use packet_dsl::Serializer;
use packet_dsl::semantic::parse_str;
use prping::{PkgOptions, SendMode, Transport, extract_payload, send_packets};

fn build_packets(src: &str) -> Vec<packet_dsl::ir::PacketSpec> {
    let m = parse_str("t", src).expect("解析成功");
    packet_dsl::resolve(&m).expect("求值成功").packets
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
    let pkts = build_packets(
        "a = http(method=\"GET\", path=\"/\")\nuse(a) |> tcp(dport=80) |> ipv4() |> eth()\n",
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
        "a = http(method=\"GET\", path=\"/\")\nuse(a) |> tcp(dport=80) |> ipv4() |> eth()\n",
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
    assert!(msg.contains("failed to send"), "{msg}");
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

#[test]
fn raw_without_ip_or_eth_layer_is_error() {
    let file = temp_pkt("raw-bad", "a = http()\nexport:\n- a\n");
    let target = "127.0.0.1:9".parse().unwrap();
    let err = send_packets(
        &file,
        &PkgOptions {
            target: Some(target),
            mode: SendMode::Raw { iface: None },
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("failed to send"), "{err}");
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

// ── 目标推导（--pkg FILE 省略 HOST:PORT）────────────────────

#[test]
fn derive_target_ipv4_with_port() {
    let pkts = build_packets(
        "a = dns(questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4(dst=\"8.8.8.8\") |> eth()\n",
    );
    let addr = prping::derive_target(&pkts[0], true).expect("应推导出目标");
    assert_eq!(addr, "8.8.8.8:53".parse().unwrap());
}

#[test]
fn derive_target_ipv6_raw_no_port() {
    let pkts = build_packets(
        "a = raw(bytes=\"x\")\nuse(a) |> icmp() |> ipv6(dst=\"2001:4860:4860::8888\") |> eth()\n",
    );
    let addr = prping::derive_target(&pkts[0], false).expect("应推导出目标");
    assert_eq!(addr.ip().to_string(), "2001:4860:4860::8888");
    assert_eq!(addr.port(), 0);
}

#[test]
fn derive_target_without_ip_is_error() {
    let pkts = build_packets("a = http()\nuse(a) |> tcp(dport=443)\n");
    let err = prping::derive_target(&pkts[0], true).unwrap_err();
    assert!(err.to_string().contains("目标地址"), "{err}");
}

#[test]
fn derive_target_missing_dport_is_error() {
    // 库版 tcp()/udp() 默认 dport=0 已写进头字节；用不足 4B 的字节直喂层构造缺失
    let pkts = build_packets(
        "a = http()\nuse(a) |> tcp_bytes(bytes=\"ab\") |> ipv4(dst=\"1.2.3.4\") |> eth()\n",
    );
    let err = prping::derive_target(&pkts[0], true).unwrap_err();
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
    let addr = prping::derive_target(&pkts[0], true).expect("应推导出目标");
    assert_eq!(addr, "8.8.8.8:443".parse().unwrap());
}

/// --pkg --wait：UDP 回显应答（DNS id 匹配），等待路径不挂起且能收到回显。
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
    let opts = prping::PkgOptions {
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
    let payload = prping::extract_payload(&built.packets[0]).unwrap().1;
    // 同 id 应答 → 匹配
    let reply = {
        let mut b = payload.clone();
        b[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // 标记为应答
        b
    };
    let got = prping::sniffer_match(&spec, &reply, &payload).unwrap();
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
        prping::sniffer_match(&spec, &bad, &payload).unwrap(),
        None,
        "异 id 不应匹配"
    );
    // 纯杂包（无法反解出 dns）→ 不匹配
    assert_eq!(
        prping::sniffer_match(&spec, b"junkjunkjunk", &payload).unwrap(),
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
    let got = prping::sniffer_match(&spec, &reply, &sent).unwrap();
    let got = got.expect("echo reply 应匹配");
    assert_eq!(got.len(), 3, "{got:?}");
    assert_eq!(got[0], ("type".to_string(), "0".to_string()));
    assert_eq!(got[1], ("id".to_string(), "7".to_string()));
    assert_eq!(got[2], ("seq".to_string(), "3".to_string()));
    // type=8（还是 echo request）→ 不匹配
    let mut req = sent.clone();
    req[34] = 8;
    assert_eq!(prping::sniffer_match(&spec, &req, &sent).unwrap(), None);
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

/// --pkg --wait + sniffer：跳过杂包，同 id 应答匹配（回环 UDP）。
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
    let opts = prping::PkgOptions {
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
    prping::patch_zero_src(
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
    prping::patch_zero_src(
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
    prping::render_packet_fields(&mut out, &built.packets[0], "hdr", &ser).unwrap();
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
    prping::render_packet_fields(&mut out2, &built2.packets[0], "hdr", &ser).unwrap();
    let text2 = String::from_utf8(out2.into_inner()).unwrap();
    assert!(
        text2.contains("dst=5.6.7.8") && !text2.contains("dns("),
        "{text2}"
    );
}

/// 多子句 sniffer：任一子句命中即匹配（回包是 icmp 或 dns 都算）。
#[test]
fn sniffer_multiple_clauses_or() {
    let m = parse_str(
        "t",
        "a = dns(id=0x4242, questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4() |> eth()\n\
sniffer:\n  - match icmp(id=id, seq=seq)\n  - match dns(id=id)\n",
    )
    .unwrap();
    let spec = m.sniffer.clone().expect("应有 sniffer");
    let built = packet_dsl::resolve(&m).unwrap();
    let payload = prping::extract_payload(&built.packets[0]).unwrap().1;
    // 回包是 DNS 且 id 一致 → 第二个子句命中
    let reply = {
        let mut b = payload.clone();
        b[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        b
    };
    let got = prping::sniffer_match(&spec, &reply, &payload)
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
    assert_eq!(prping::sniffer_match(&spec, &bad, &payload).unwrap(), None);
}
