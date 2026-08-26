//! Golden 字节测试：ARP 请求 / DNS over UDP / HTTP over TCP / VNC 原始载荷。
//!
//! 期望字节由独立 Python 实现手工计算（非复用本 crate 序列化器），
//! 同时用独立实现复核 IPv4/TCP/UDP checksum。

use packet_dsl::ir::Layer;
use packet_dsl::semantic::{parse_file, parse_str};
use packet_dsl::serialize::{DefaultSerializer, SerializeError, Serializer};

fn build_bytes(src: &str) -> Vec<Vec<u8>> {
    let m = parse_str("t", src).expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    let ser = DefaultSerializer::with_seed(42);
    built
        .packets
        .iter()
        .map(|p| ser.serialize(p).expect("序列化成功"))
        .collect()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ── Golden 用例 ─────────────────────────────────────────────

/// 设计 §12.4 的 ARP 请求（链路层起步，无上层载荷）。
#[test]
fn golden_arp_request() {
    let src = r#"
req = arp(op=request(), sha="00:11:22:33:44:55", spa="192.168.1.1", tpa="192.168.1.2")
full = use(req) |> eth(src_mac="00:11:22:33:44:55", dst_mac="ff:ff:ff:ff:ff:ff", ethertype=0x0806)
export:
- full
"#;
    let bytes = build_bytes(src);
    assert_eq!(bytes.len(), 1);
    assert_eq!(
        bytes[0],
        hex("ffffffffffff00112233445508060001080006040001001122334455c0a80101000000000000c0a80102")
    );
}

/// DNS over UDP：id/端口/地址全部显式 → 字节完全确定。
#[test]
fn golden_dns_over_udp() {
    let src = r#"
q = dns(id=0x1234, questions=["example.com"])
full = use(q) |> udp(sport=12345, dport=53)
      |> ipv4(src="1.1.1.1", dst="8.8.8.8", id=0, proto=17)
      |> eth(src_mac="00:11:22:33:44:55", dst_mac="66:77:88:99:aa:bb")
export:
- full
"#;
    let bytes = build_bytes(src);
    assert_eq!(bytes.len(), 1);
    assert_eq!(
        bytes[0],
        hex(
            "66778899aabb00112233445508004500003900000000401168a30101010108080808303900350025db82123401000001000000000000076578616d706c6503636f6d0000010001"
        )
    );
}

/// HTTP over TCP：GET 请求 + 显式 seq/flags → 字节确定。
#[test]
fn golden_http_over_tcp() {
    let src = r#"
h = http(start_line="GET / HTTP/1.1")
full = use(h) |> tcp(sport=40000, dport=80, seq=1, flags=bor(syn(), ack()))
      |> ipv4(src="10.0.0.1", dst="10.0.0.2", id=0, proto=6)
      |> eth(src_mac="00:11:22:33:44:55", dst_mac="66:77:88:99:aa:bb")
export:
- full
"#;
    let bytes = build_bytes(src);
    assert_eq!(bytes.len(), 1);
    assert_eq!(
        bytes[0],
        hex(
            "66778899aabb00112233445508004500003a00000000400666bc0a0000010a0000029c40005000000001000000005012ffff208c0000474554202f20485454502f312e310d0a0d0a"
        )
    );
}

/// VNC 原始载荷（"RFB 003.008\n"）。
#[test]
fn golden_vnc_raw() {
    let src = r#"
p = raw(bytes="RFB 003.008\n")
full = use(p) |> tcp(sport=40001, dport=5900, seq=2)
      |> ipv4(src="10.0.0.1", dst="10.0.0.2", id=0, proto=6)
      |> eth(src_mac="00:11:22:33:44:55", dst_mac="66:77:88:99:aa:bb")
export:
- full
"#;
    let bytes = build_bytes(src);
    assert_eq!(bytes.len(), 1);
    assert_eq!(
        bytes[0],
        hex(
            "66778899aabb00112233445508004500003400000000400666c20a0000010a0000029c41170c00000002000000005002ffff88850000524642203030332e3030380a"
        )
    );
}

// ── checksum 复核（独立实现）────────────────────────────────

/// 独立 one's complement checksum（RFC 1071）。
fn ref_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in data.as_chunks::<2>().0 {
        sum += u16::from_be_bytes(*c) as u32;
    }
    if data.len() & 1 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn verify_ipv4_checksum(pkt: &[u8]) -> Option<u16> {
    // 找 IPv4 头：以太网 14 字节后（或包首）version=4
    let start = if pkt.len() >= 14 && pkt[12] == 0x08 && pkt[13] == 0x00 {
        14
    } else {
        0
    };
    if pkt.len() >= start + 20 && (pkt[start] >> 4) == 4 {
        let mut header = pkt[start..start + 20].to_vec();
        header[10] = 0;
        header[11] = 0;
        Some(ref_checksum(&header))
    } else {
        None
    }
}

fn verify_transport_checksum(pkt: &[u8]) -> Option<u16> {
    // 以太网 + IPv4 + TCP/UDP：解析伪头部
    if pkt.len() < 14 + 20 || pkt[12] != 0x08 || pkt[13] != 0x00 {
        return None;
    }
    let proto = pkt[14 + 9];
    let (src, dst) = (&pkt[14 + 12..14 + 16], &pkt[14 + 16..14 + 20]);
    let total_len = u16::from_be_bytes([pkt[14 + 2], pkt[14 + 3]]) as usize;
    let seg = &pkt[14 + 20..14 + total_len];
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(dst);
    pseudo.push(0);
    pseudo.push(proto);
    pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    let mut all = pseudo;
    let mut seg2 = seg.to_vec();
    // 清掉 checksum 字段（TCP 偏移 16，UDP 偏移 6）
    let cs_off = if proto == 6 { 16 } else { 6 };
    seg2[cs_off] = 0;
    seg2[cs_off + 1] = 0;
    all.extend_from_slice(&seg2);
    Some(ref_checksum(&all))
}

#[test]
fn checksums_match_independent_implementation() {
    let pkt = &build_bytes(
        "h = http(start_line=\"GET / HTTP/1.1\")\nuse(h) |> tcp(sport=40000, dport=80, seq=1) |> ipv4(src=\"10.0.0.1\", dst=\"10.0.0.2\", proto=6) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\")",
    )[0];
    let ip_cs = verify_ipv4_checksum(pkt).expect("应有 IPv4");
    let tcp_cs = verify_transport_checksum(pkt).expect("应有 TCP");
    assert_eq!(
        u16::from_be_bytes([pkt[14 + 10], pkt[14 + 11]]),
        ip_cs,
        "IPv4 checksum"
    );
    assert_eq!(
        u16::from_be_bytes([pkt[14 + 20 + 16], pkt[14 + 20 + 17]]),
        tcp_cs,
        "TCP checksum"
    );
}

#[test]
fn udp_checksum_matches_independent_implementation() {
    let pkt = &build_bytes(
        "q = dns(questions=[\"example.com\"])\nuse(q) |> udp(sport=12345, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=17) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\")",
    )[0];
    let udp_cs = verify_transport_checksum(pkt).expect("应有 UDP");
    assert_eq!(
        u16::from_be_bytes([pkt[14 + 20 + 6], pkt[14 + 20 + 7]]),
        udp_cs,
        "UDP checksum"
    );
}

// ── 自动值 / 确定性 ─────────────────────────────────────────

#[test]
fn defaults_broadcast_dst_and_ttl() {
    let src = "a = raw(bytes=\"x\")\nuse(a) |> tcp(dport=80) |> ipv4(src=\"1.2.3.4\", dst=\"5.6.7.8\") |> eth()\n";
    let m = parse_str("t", src).expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    let ser = DefaultSerializer::with_seed(1);
    let pkt = ser.serialize(&built.packets[0]).expect("序列化成功");
    // 目的 MAC = 广播
    assert_eq!(&pkt[0..6], &[0xFF; 6]);
    // ethertype 由 ipv4 推导 = 0x0800
    assert_eq!(&pkt[12..14], &[0x08, 0x00]);
    // IPv4 TTL = 64
    assert_eq!(pkt[14 + 8], 64);
    // TCP flags 默认 SYN（offset 13 in TCP header）
    let tcp_off = 14 + 20;
    assert_eq!(pkt[tcp_off + 13], 0x02);
}

#[test]
fn same_seed_same_bytes() {
    let src = "a = raw(bytes=\"x\")\nuse(a) |> tcp(dport=80) |> ipv4() |> eth()\n";
    let m = parse_str("t", src).expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    let s1 = DefaultSerializer::with_seed(7);
    let s2 = DefaultSerializer::with_seed(7);
    let b1 = s1.serialize(&built.packets[0]).unwrap();
    let b2 = s2.serialize(&built.packets[0]).unwrap();
    assert_eq!(b1, b2);
}

#[test]
fn different_seed_different_sport() {
    // headers.tcp sport 默认 rand16()：构建期随机（resolve 时），非序列化期
    let src = "a = raw(bytes=\"x\")\nuse(a) |> tcp(dport=80) |> ipv4() |> eth()\n";
    let m1 = parse_str("t", src).expect("解析成功");
    let m2 = parse_str("t", src).expect("解析成功");
    let b1 = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&packet_dsl::resolve(&m1).unwrap().packets[0])
        .unwrap();
    let b2 = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&packet_dsl::resolve(&m2).unwrap().packets[0])
        .unwrap();
    assert_ne!(b1, b2, "两次 resolve 应产生不同随机 sport");
}

#[test]
fn random_sport_in_valid_range() {
    let src = "a = raw(bytes=\"x\")\nuse(a) |> tcp(dport=80) |> ipv4() |> eth()\n";
    let m = parse_str("t", src).expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    let ser = DefaultSerializer::new();
    for _ in 0..64 {
        let pkt = ser.serialize(&built.packets[0]).unwrap();
        let tcp_off = 14 + 20;
        let sport = u16::from_be_bytes([pkt[tcp_off], pkt[tcp_off + 1]]);
        assert!(sport >= 1, "源端口不应为 0");
    }
}

#[test]
fn empty_packet_is_error() {
    let ser = DefaultSerializer::new();
    let err = ser
        .serialize(&packet_dsl::ir::PacketSpec { layers: vec![] })
        .unwrap_err();
    assert_eq!(err, SerializeError::EmptyPacket);
}

#[test]
fn ipv6_stack_serializes() {
    let src = "a = raw(bytes=\"x\")\nuse(a) |> udp(dport=53) |> ipv6(src=\"::1\", dst=\"::2\", next_header=17) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\", ethertype=0x86dd)\n";
    let bytes = build_bytes(src);
    let pkt = &bytes[0];
    // 以太网 ethertype = 0x86dd
    assert_eq!(&pkt[12..14], &[0x86, 0xdd]);
    // IPv6 版本 + next header = 17 (UDP)
    assert_eq!(pkt[14] >> 4, 6);
    assert_eq!(pkt[14 + 6], 17);
    assert_eq!(pkt[14 + 7], 64, "hop limit 默认 64");
}

#[test]
fn icmp_echo_defaults() {
    let src = "a = raw(bytes=\"hi\")\nuse(a) |> icmp(id=0x1234) |> ipv4(src=\"1.2.3.4\", dst=\"5.6.7.8\") |> eth()\n";
    let bytes = build_bytes(src);
    let pkt = &bytes[0];
    let icmp_off = 14 + 20;
    assert_eq!(pkt[icmp_off], 8, "默认 echo request");
    assert_eq!(pkt[icmp_off + 1], 0);
    assert_eq!(&pkt[icmp_off + 4..icmp_off + 6], &[0x12, 0x34], "id");
    // checksum 校验（ICMP 自身）
    let msg = &pkt[icmp_off..];
    assert_eq!(
        ref_checksum(msg),
        0,
        "ICMP checksum 应使整个报文和为 0x0000（含校验和字段）"
    );
}

#[test]
fn hex_builtin_parses() {
    let src = "p = hex(\"deadbeef\")\nuse(p) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\", ethertype=0x1234)\n";
    let bytes = build_bytes(src);
    assert_eq!(&bytes[0][14..], &hex("deadbeef"));
    assert_eq!(&bytes[0][12..14], &[0x12, 0x34]);
}

#[test]
fn http_auto_content_length() {
    let src = "h = http(start_line=\"POST /login HTTP/1.1\", headers=[\"Content-Length: 2\"], body=\"{}\")\nuse(h) |> tcp(dport=80) |> ipv4() |> eth()\n";
    let bytes = build_bytes(src);
    let pkt = &bytes[0];
    let s = String::from_utf8_lossy(pkt);
    assert!(s.contains("POST /login HTTP/1.1\r\n"), "{s}");
    assert!(s.contains("Content-Length: 2\r\n"), "{s}");
}

#[test]
fn dns_answers_serialize() {
    let src = r#"q = dns(id=1, questions=["example.com"])
use(q) |> udp(dport=53) |> ipv4() |> eth()
"#;
    let bytes = build_bytes(src);
    let pkt = &bytes[0];
    // DNS 头 qdcount = 1（offset 14+20+8+4）
    let dns_off = 14 + 20 + 8;
    assert_eq!(u16::from_be_bytes([pkt[dns_off + 4], pkt[dns_off + 5]]), 1);
    // question name 编码 example.com
    // DNS name 长度前缀编码：0x07 example 0x03 com 0x00
    assert!(
        pkt.windows(7).any(|w| w == b"example"),
        "question 编码应含 example：{:02x?}",
        pkt
    );
}

#[test]
fn serde_roundtrip() {
    let m = parse_str(
        "t",
        "a = http(start_line=\"GET / HTTP/1.1\")\nuse(a) |> tcp(dport=80)\n",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    let json = serde_json::to_string(&built).expect("序列化为 JSON");
    let back: packet_dsl::ir::BuildResult = serde_json::from_str(&json).expect("反序列化");
    assert_eq!(back, built);
}

#[test]
fn parse_file_with_import_end_to_end() {
    use common::TempDir;
    let dir = TempDir::new("e2e");
    dir.write(
        "a.pkt",
        "export:\n- h\nh = http(start_line=\"GET / HTTP/1.1\")\n",
    );
    let b = dir.write("b.pkt", "import a { h }\nuse(h) |> tcp(dport=80) |> ipv4(src=\"1.2.3.4\", dst=\"5.6.7.8\") |> eth()\n");
    let m = parse_file(b).expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    let ser = DefaultSerializer::with_seed(3);
    let pkt = ser.serialize(&built.packets[0]).expect("序列化成功");
    assert!(pkt.len() > 60);
    // 全链路：eth → ipv4 → tcp → http
    assert!(matches!(built.packets[0].layers[0], Layer::Http(_)));
    assert!(matches!(built.packets[0].layers[1], Layer::Tcp(_)));
    assert!(matches!(built.packets[0].layers[2], Layer::Ipv4(_)));
    assert!(matches!(built.packets[0].layers[3], Layer::Ethernet(_)));
}

mod common;
