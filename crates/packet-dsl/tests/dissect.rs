//! 反解测试：序列化 roundtrip、DNS 压缩指针、截断/checksum 注记；fuzz 模式。

use packet_dsl::ir::{Field, Layer};
use packet_dsl::{DefaultSerializer, Serializer, dissect};

mod common;

fn build_packet(src: &str) -> packet_dsl::ir::PacketSpec {
    let m = packet_dsl::semantic::parse_str("t", src).unwrap();
    packet_dsl::resolve(&m)
        .unwrap()
        .packets
        .into_iter()
        .next()
        .unwrap()
}

/// DNS over UDP over IPv4 over eth：序列化 → 反解 → 字段一致。
#[test]
fn roundtrip_dns_udp_ipv4_eth() {
    common::register_eng_lib();
    let pkt = build_packet(
        "q = dns(id=0x1234, questions=[\"example.com\"])\nuse(q) |> udp(sport=12345, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", id=0, proto=17) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\")\n",
    );
    let bytes = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "notes: {:?}", r.notes);
    assert_eq!(r.layers.len(), 4, "eth+ipv4+udp+dns: {:#?}", r.layers);
    let Layer::Ethernet(eth) = &r.layers[0] else {
        panic!()
    };
    assert_eq!(
        eth.dst_mac,
        Field::Value("66:77:88:99:aa:bb".parse().unwrap())
    );
    assert_eq!(
        eth.src_mac,
        Field::Value("00:11:22:33:44:55".parse().unwrap())
    );
    let Layer::Ipv4(ip) = &r.layers[1] else {
        panic!()
    };
    assert_eq!(ip.src, Field::Value("1.1.1.1".parse().unwrap()));
    assert_eq!(ip.dst, Field::Value("8.8.8.8".parse().unwrap()));
    assert_eq!(ip.ttl, Field::Value(64));
    assert_eq!(ip.proto, Some(17));
    let Layer::Udp(udp) = &r.layers[2] else {
        panic!()
    };
    assert_eq!(udp.dst_port, Some(53));
    // 应用层：注册表 dns rule（udp 53）命中 → proto_hit_to_layer 转 Layer::Dns
    let Layer::Dns(dns) = &r.layers[3] else {
        panic!("dns 应转 IR 层: {:#?}", r.layers)
    };
    assert_eq!(dns.id, Some(0x1234));
    assert_eq!(dns.questions.len(), 1);
    assert_eq!(dns.questions[0].name, "example.com");
    assert_eq!(dns.questions[0].qtype, Some(1));
    // 载荷字节保留在 raw 分支（roundtrip/转码依赖）
    assert_eq!(dns.raw.as_deref().map(|b| b.len()), Some(29));
}

/// 裸 IPv4 + ICMP echo（无以太网）roundtrip。
#[test]
fn roundtrip_icmp_bare_ipv4() {
    common::register_eng_lib();
    let pkt = build_packet(
        "p = raw(bytes=\"ping\")\nuse(p) |> icmp(type=8, id=7, seq=3) |> ipv4(src=\"192.168.1.1\", dst=\"8.8.8.8\", proto=1)\n",
    );
    let bytes = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "{:?}", r.notes);
    assert_eq!(
        r.layers.len(),
        2,
        "ipv4+icmp（icmp body 在 payload 字段）: {:#?}",
        r.layers
    );
    let Layer::Ipv4(ip) = &r.layers[0] else {
        panic!()
    };
    assert_eq!(ip.src, Field::Value("192.168.1.1".parse().unwrap()));
    assert_eq!(ip.proto, Some(1));
    let Layer::Icmp(icmp) = &r.layers[1] else {
        panic!()
    };
    assert_eq!(icmp.icmp_type, Some(8));
    assert_eq!(icmp.id, Some(7));
    assert_eq!(icmp.seq, Some(3));
    assert_eq!(icmp.payload.as_deref(), Some(b"ping".as_slice()));
}

/// ARP over eth roundtrip。
#[test]
fn roundtrip_arp() {
    common::register_eng_lib();
    let pkt = build_packet(
        "r = arp(op=request(), sha=\"00:11:22:33:44:55\", spa=\"192.168.1.1\", tha=\"00:00:00:00:00:00\", tpa=\"192.168.1.2\")\nuse(r) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"ff:ff:ff:ff:ff:ff\", ethertype=0x0806)\n",
    );
    let bytes = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "{:?}", r.notes);
    let Layer::Arp(arp) = &r.layers[1] else {
        panic!()
    };
    assert_eq!(arp.spa, Some("192.168.1.1".parse().unwrap()));
    assert_eq!(arp.tpa, Some("192.168.1.2".parse().unwrap()));
}

/// IPv6 roundtrip（next header 17 → udp）。
#[test]
fn roundtrip_ipv6_udp() {
    common::register_eng_lib();
    let pkt = build_packet(
        "p = raw(bytes=\"x\")\nuse(p) |> udp(sport=12345, dport=5353) |> ipv6(src=\"::1\", dst=\"2001:db8::1\", next_header=17)\n",
    );
    let bytes = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "{:?}", r.notes);
    assert_eq!(r.layers.len(), 3);
    let Layer::Ipv6(ip) = &r.layers[0] else {
        panic!()
    };
    assert_eq!(ip.dst, Field::Value("2001:db8::1".parse().unwrap()));
    assert_eq!(ip.next_header, Some(17));
    let Layer::Udp(_) = &r.layers[1] else {
        panic!()
    };
}

/// **字节级** roundtrip：dissect → 反转层序 → 重序列化 == 原字节。
/// （dissect 产出展示序 外→内，serialize 期望 内→外；每层 raw 保留头字节，
/// checksum/length 确定性重算 = 原值。）
fn byte_roundtrip(src: &str, label: &str) {
    let pkt = build_packet(src);
    let bytes = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    let r = dissect(&bytes);
    let re = DefaultSerializer::with_seed(1)
        .serialize(&packet_dsl::ir::PacketSpec {
            layers: r.layers.into_iter().rev().collect(),
        })
        .unwrap();
    assert_eq!(re, bytes, "{label}: 字节级 roundtrip 应一致");
}

#[test]
fn byte_roundtrip_icmp_body() {
    common::register_eng_lib();
    // 回归：icmp 载荷存 f.payload（非内层），serialize raw 分支曾丢弃它
    byte_roundtrip(
        "p = raw(bytes=\"ping\")\nuse(p) |> icmp(type=8, id=7, seq=3) |> ipv4(src=\"192.168.1.1\", dst=\"8.8.8.8\", proto=1)\n",
        "icmp body",
    );
}

#[test]
fn byte_roundtrip_tcp_options() {
    common::register_eng_lib();
    // TCP 选项（doff>5）在 raw 头字节里，语义渲染会丢——raw 保留即可字节级还原
    // （用 IR 直接构造带选项头字节的 tcp 层）
    use packet_dsl::ir::{EthernetFields, Ipv4Fields, RawData, TcpFields, TcpFlags};
    let mut tcp_hdr = vec![0u8; 24]; // doff=6（20 + 4B 选项）
    tcp_hdr[0] = 0x30;
    tcp_hdr[1] = 0x39; // sport 12345
    tcp_hdr[2] = 0x23;
    tcp_hdr[3] = 0x28; // dport 9000
    tcp_hdr[12] = 0x60; // doff=6
    tcp_hdr[13] = 0x02; // SYN
    tcp_hdr[14] = 0xff;
    tcp_hdr[15] = 0xff; // window 65535
    tcp_hdr[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]); // MSS 1460
    let pkt = packet_dsl::ir::PacketSpec {
        layers: vec![
            Layer::Raw(RawData {
                bytes: b"x".to_vec(),
                proto: None,
            }),
            Layer::Tcp(TcpFields {
                src_port: Some(12345),
                dst_port: Some(53),
                flags: Some(TcpFlags {
                    syn: true,
                    ..Default::default()
                }),
                raw: Some(tcp_hdr),
                ..Default::default()
            }),
            Layer::Ipv4(Ipv4Fields {
                src: Field::Value("1.1.1.1".parse().unwrap()),
                dst: Field::Value("8.8.8.8".parse().unwrap()),
                proto: Some(6),
                ..Default::default()
            }),
            Layer::Ethernet(EthernetFields {
                ..Default::default()
            }),
        ],
    };
    let bytes = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "notes: {:?}", r.notes);
    let re = DefaultSerializer::with_seed(1)
        .serialize(&packet_dsl::ir::PacketSpec {
            layers: r.layers.into_iter().rev().collect(),
        })
        .unwrap();
    assert_eq!(re, bytes, "tcp options: 字节级 roundtrip 应一致");
}

#[test]
fn byte_roundtrip_dns_with_answers() {
    common::register_eng_lib();
    // 回归：dns raw=None 时重序列化丢 nscount/arcount/压缩指针/附加段——
    // 现 raw 保留整段载荷，字节级还原
    let msg_hex = concat!(
        "1234", // id
        "8180", // flags
        "0001",
        "0001",
        "0000",
        "0001", // qd=1 an=1 ns=0 ar=1（附加段 OPT）
        "07",
        "6578616d706c65",
        "03",
        "636f6d",
        "00", // 问题名 example.com
        "0001",
        "0001", // A IN
        "c00c", // 压缩指针 → 偏移 12
        "0001",
        "0001",
        "0000012c", // A IN TTL=300
        "0004",
        "5db8d822", // rdlen=4, 93.184.216.34
        "00",       // 附加：根域
        "0029",
        "0400",
        "0000000000000000", // OPT：udp size 1024, ext rcode 0, version 0, z 0
    );
    let src = format!(
        "q = hex(\"{msg_hex}\")\nuse(q) |> udp(sport=12345, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=17) |> eth()\n"
    );
    byte_roundtrip(&src, "dns with answers + OPT");
}

#[test]
fn byte_roundtrip_http() {
    common::register_eng_lib();
    // 回归：http raw=None 时重序列化规范化头部（trim/Content-Length）——
    // 现 raw 保留整段载荷
    let src = concat!(
        "h = raw(bytes=\"GET /index.html HTTP/1.1\\r\\nHost:  example.com\\r\\nX-Test: 1\\r\\n\\r\\nbody\\r\\n\")\n",
        "use(h) |> tcp(sport=40000, dport=80, flags=bor(psh(), ack()), seq=1, ack=1) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=6) |> eth()\n",
    );
    byte_roundtrip(src, "http");
}

#[test]
fn byte_roundtrip_padding() {
    common::register_eng_lib();
    // 以太网填充（total_len 之外的字节）在 remaining 里，不属任何层——
    // 结构化 roundtrip 不覆盖 padding（转码器对 remaining 非空会退无损 raw 路线）
    let pkt = build_packet(
        "p = raw(bytes=\"x\")\nuse(p) |> udp(sport=12345, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=17) |> eth()\n",
    );
    let mut bytes = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    // eth 帧最小 60B，凑足 46B 填充
    while bytes.len() < 60 {
        bytes.push(0x00);
    }
    let r = dissect(&bytes);
    assert!(
        !r.remaining.is_empty(),
        "填充字节应留在 remaining（60B 最小帧）"
    );
}

/// DNS 压缩指针解码。
#[test]
fn dns_compression_pointer() {
    common::register_eng_lib();
    // 手工构造 DNS 报文：查询 example.com，回答用压缩指针 0xC00C 指向查询名
    let msg_hex = concat!(
        "1234", // id
        "8180", // flags
        "0001",
        "0001",
        "0000",
        "0000", // qd=1 an=1 ns=0 ar=0
        "07",
        "6578616d706c65",
        "03",
        "636f6d",
        "00", // 问题名 example.com
        "0001",
        "0001", // A IN
        "c00c", // 压缩指针 → 偏移 12
        "0001",
        "0001",
        "0000012c", // A IN TTL=300
        "0004",
        "5db8d822", // rdlen=4, 93.184.216.34
    );
    // 用 DSL 构造 eth+ipv4+udp+dns 完整包（payload 用 hex）
    let src = format!(
        "q = hex(\"{msg_hex}\")\nuse(q) |> udp(sport=12345, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=17) |> eth()\n"
    );
    let pkt = build_packet(&src);
    let bytes = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    let r = dissect(&bytes);
    let Layer::Dns(dns) = &r.layers[3] else {
        panic!("期望 dns: {:#?}", r.layers)
    };
    assert_eq!(
        dns.questions[0].name, "example.com",
        "压缩指针应解出 example.com"
    );
    assert_eq!(dns.answers.len(), 1);
    assert_eq!(dns.answers[0].name, "example.com");
    assert_eq!(dns.answers[0].rdata, vec![93, 184, 216, 34]);
}

/// 截断输入 → 不崩溃；层头解析失败时字节留 remaining（注册表契约，
/// 不再有硬编码"截断"注记）。
#[test]
fn truncated_input_notes() {
    common::register_eng_lib();
    let r = dissect(&[0x45, 0x00, 0x00, 0x28]); // 不完整的 IPv4 头
    assert!(r.layers.is_empty());
    assert_eq!(
        r.remaining,
        vec![0x45, 0x00, 0x00, 0x28],
        "字节留 remaining"
    );
    // 完整 eth 头 + 截断 IP：eth 层照常（注册表），ipv4 反解失败 → remaining
    let mut bytes = vec![0u8; 14];
    bytes[12] = 0x08;
    bytes[13] = 0x00;
    bytes.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);
    let r = dissect(&bytes);
    assert_eq!(r.layers.len(), 1, "只有 eth 层: {:#?}", r.layers);
    assert!(!r.remaining.is_empty(), "截断 IP 字节应留 remaining");
}

/// 篡改字节 → IPv4 checksum 注记。
#[test]
fn checksum_mismatch_note() {
    common::register_eng_lib();
    let pkt = build_packet(
        "p = raw(bytes=\"x\")\nuse(p) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=17)\n",
    );
    let mut bytes = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    bytes[10] ^= 0xFF; // 破坏 checksum
    let r = dissect(&bytes);
    assert!(
        r.notes.iter().any(|n| n.contains("checksum")),
        "{:?}",
        r.notes
    );
}

// ── fuzz 模式 ───────────────────────────────────────────────

/// fuzz：未填字段全部随机；同种子确定性；协议栈仍合法。
#[test]
fn fuzz_randomizes_unset_fields() {
    // fuzz 作用于语义字段层（Auto 字段随机化）；bytes 直喂层字节已定不受 fuzz 影响。
    // 用 Rust IR 直接构造语义层验证序列化器 fuzz 行为。
    use packet_dsl::ir::{EthernetFields, Ipv4Fields, RawData};
    let pkt = packet_dsl::ir::PacketSpec {
        layers: vec![
            Layer::Raw(RawData {
                bytes: b"x".to_vec(),
                proto: None,
            }),
            Layer::Ipv4(Ipv4Fields {
                src: Field::Auto,
                dst: Field::Value("8.8.8.8".parse().unwrap()),
                proto: Some(6),
                ..Default::default()
            }),
            Layer::Ethernet(EthernetFields {
                src_mac: Field::Auto,
                dst_mac: Field::Value("ff:ff:ff:ff:ff:ff".parse().unwrap()),
                ..Default::default()
            }),
        ],
    };
    let normal = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    let f1 = DefaultSerializer::with_seed_fuzz(1)
        .serialize(&pkt)
        .unwrap();
    let f2 = DefaultSerializer::with_seed_fuzz(1)
        .serialize(&pkt)
        .unwrap();
    assert_eq!(f1, f2, "fuzz 同种子应确定性");
    assert_ne!(normal, f1, "fuzz 应改变字节");
    // 显式 dst（8.8.8.8）保留在 IPv4 头 offset 16-19；Auto src 被 fuzz 随机
    let eth_len = 14;
    assert_eq!(
        &f1[eth_len + 16..eth_len + 20],
        &[8, 8, 8, 8],
        "显式 dst 不应被 fuzz"
    );
    assert_ne!(
        &f1[eth_len + 12..eth_len + 16],
        &[0, 0, 0, 0],
        "Auto src 应被 fuzz 随机"
    );
    assert_eq!(f1[eth_len + 9], 6, "显式 proto 不应被 fuzz");
}
