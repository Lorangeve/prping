//! eng_lib/headers.pkt 层头 proto 的**解析侧**验证：注册真实 headers.pkt 的
//! proto（eth/arp/ipv4/ipv6/icmp/tcp/udp/dns）后，dissect 层头按 proto 注册表
//! 反解（`find_by_kind` + `parse_header`），产出语义 IR 层与硬编码路径一致。
//!
//! 这是「构造+解析全下沉」的端到端验证：同一份 pkt 声明，构造侧（golden 对照）
//! 与解析侧（本文件）共用。

use packet_dsl::ir::Layer;
use packet_dsl::{DefaultSerializer, Serializer, dissect};

/// 用真实 eng_lib 注册 proto 表（OnceLock 幂等；本文件测试共享同一注册内容）。
fn register_eng_lib() {
    let libs = packet_dsl::default_libs();
    let mut protos = Vec::new();
    for dir in libs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().is_none_or(|x| x != "pkt") {
                continue;
            }
            // 与 prping ensure_proto_registry 一致：文件模式解析（自动带 eng_lib）
            let Ok(m) = packet_dsl::parse_file_with_libs(&path, &[]) else {
                continue;
            };
            for p in m.protos {
                protos.push(packet_dsl::ResolvedProto {
                    name: p.name.clone(),
                    layer: p.layer.clone(),
                    rule: p.rule.clone(),
                    params: p
                        .params
                        .iter()
                        .map(|x| packet_dsl::ast::FuncParam {
                            name: x.name.clone(),
                            span: x.span,
                            default: x.default.clone(),
                        })
                        .collect(),
                    fields: p.fields.clone(),
                });
            }
        }
    }
    assert!(
        protos.iter().any(|p| p.name == "eth"),
        "eng_lib headers.pkt 应注册 eth proto（注册了 {} 个 proto）",
        protos.len()
    );
    packet_dsl::set_proto_registry(protos);
}

fn build_full_pkt(src: &str) -> Vec<u8> {
    let m = packet_dsl::semantic::parse_str("t", src).unwrap();
    let pkt = packet_dsl::resolve(&m)
        .unwrap()
        .packets
        .into_iter()
        .next()
        .unwrap();
    DefaultSerializer::with_seed(1).serialize(&pkt).unwrap()
}

/// eth/ipv4/tcp 层头走 proto 注册表反解：字段与硬编码路径一致。
#[test]
fn proto_headers_layer_dissect_tcp() {
    register_eng_lib();
    let bytes = build_full_pkt(
        "p = raw(bytes=\"x\")\nuse(p) |> tcp(sport=40000, dport=9000, seq=1, ack=2, flags=bor(psh(), ack()), window=1000) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", ttl=63, proto=6, tos=0x10, id=7) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\")\n",
    );
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "notes: {:?}", r.notes);
    assert_eq!(r.layers.len(), 4, "eth+ipv4+tcp+raw: {:#?}", r.layers);
    let Layer::Ethernet(eth) = &r.layers[0] else {
        panic!("eth 层");
    };
    assert_eq!(
        eth.src_mac,
        packet_dsl::ir::Field::Value("00:11:22:33:44:55".parse().unwrap())
    );
    assert_eq!(
        eth.dst_mac,
        packet_dsl::ir::Field::Value("66:77:88:99:aa:bb".parse().unwrap())
    );
    let Layer::Ipv4(ip) = &r.layers[1] else {
        panic!("ipv4 层");
    };
    assert_eq!(
        ip.src,
        packet_dsl::ir::Field::Value("1.1.1.1".parse().unwrap())
    );
    assert_eq!(
        ip.dst,
        packet_dsl::ir::Field::Value("8.8.8.8".parse().unwrap())
    );
    assert_eq!(ip.ttl, packet_dsl::ir::Field::Value(63));
    assert_eq!(ip.proto, Some(6));
    let Layer::Tcp(tcp) = &r.layers[2] else {
        panic!("tcp 层");
    };
    assert_eq!(tcp.src_port, Some(40000));
    assert_eq!(tcp.dst_port, Some(9000));
    assert_eq!(tcp.seq, Some(1));
    assert_eq!(tcp.ack, Some(2));
    let Layer::Raw(raw) = &r.layers[3] else {
        panic!("raw 载荷");
    };
    assert_eq!(raw.bytes, b"x");
    // roundtrip：proto 反解出的层（raw 分支）重序列化字节一致
    let mut layers = r.layers.clone();
    layers.reverse();
    let spec = packet_dsl::ir::PacketSpec { layers };
    let again = DefaultSerializer::with_seed(1).serialize(&spec).unwrap();
    assert_eq!(bytes, again, "proto 反解层重序列化应字节一致");
}

/// ICMP 层头：payload 是 rest 字段，层头反解遇 rest 即停（只消费 8B 头）。
#[test]
fn proto_headers_layer_dissect_icmp() {
    register_eng_lib();
    let bytes = build_full_pkt(
        "p = raw(bytes=\"pingdata\")\nuse(p) |> icmp(type=8, code=0, id=0x1234, seq=7) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=1) |> eth()\n",
    );
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "notes: {:?}", r.notes);
    let Layer::Icmp(icmp) = &r.layers[2] else {
        panic!("icmp 层: {:#?}", r.layers);
    };
    assert_eq!(icmp.icmp_type, Some(8));
    assert_eq!(icmp.code, Some(0));
    assert_eq!(icmp.id, Some(0x1234));
    assert_eq!(icmp.seq, Some(7));
    // 载荷回填 IcmpFields.payload（与硬编码路径一致）；头字节在 raw 分支
    assert_eq!(icmp.payload.as_deref(), Some(b"pingdata".as_slice()));
    // raw 分支保留完整头字节（checksum 为自动字段，序列化器已算好）
    let raw = icmp.raw.as_ref().expect("proto 反解应填 raw");
    assert_eq!(raw[0], 8);
    assert_eq!(raw[4], 0x12);
    assert_eq!(raw[5], 0x34);
    assert_eq!(raw[6], 0);
    assert_eq!(raw[7], 7);
}

/// DNS proto（rule udp 53）经注册表应用层分派命中（构造+解析对称）。
#[test]
fn proto_headers_dns_dispatch() {
    register_eng_lib();
    let bytes = build_full_pkt(
        "q = dns(id=0xabcd, questions=[\"example.com\"])\nuse(q) |> udp(sport=12345, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=17) |> eth()\n",
    );
    let r = dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "dns");
    assert!(hit.is_some(), "udp 53 应命中 dns proto（规则分派）：{r:?}");
    let hit = hit.unwrap();
    assert_eq!(hit.subs.len(), 1, "1 个 question 子命中");
    assert_eq!(hit.subs[0].name, "dns_question");
}

/// TCP 带 options：data_offset 自动联动（@auto expr）构造，解析侧回算宽度。
#[test]
fn proto_headers_tcp_options() {
    register_eng_lib();
    // MSS option：kind=2 len=4 value=1460 → 4 字节，data offset = 6
    let bytes = build_full_pkt(
        "p = raw(bytes=\"x\")\nuse(p) |> tcp(sport=40000, dport=9000, options=hex(\"0204045c\")) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=6) |> eth()\n",
    );
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "notes: {:?}", r.notes);
    let Layer::Tcp(tcp) = &r.layers[2] else {
        panic!("tcp 层");
    };
    assert_eq!(tcp.src_port, Some(40000));
    // 头 24 字节（20 + 4 options）：raw 分支保留完整头字节
    let raw = tcp.raw.as_ref().expect("proto 反解应填 raw");
    assert_eq!(raw.len(), 24, "TCP 头应含 options");
    assert_eq!(raw[12] >> 4, 6, "data_offset 应为 6");
}

/// IPv4 带 options：version/ihl 是 bit 字段（version 字面量常量校验、ihl 可变），
/// options 宽度 `bytes="sub(mul(ihl, 4), 20)"` 按 ihl 回算——带选项的头也能
/// 完整走注册表（此前 ihl 半字节无法声明，只能硬编码）。
#[test]
fn proto_headers_ipv4_options() {
    register_eng_lib();
    // 4 字节 options（如 router alert 等），ihl=6 → 头 24B
    let bytes = build_full_pkt(
        "p = raw(bytes=\"xy\")\nuse(p) |> udp(sport=12345, dport=5353) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=17, ihl=6, options=hex(\"01020304\")) |> eth()\n",
    );
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "notes: {:?}", r.notes);
    // 注册表命中 ipv4（含 options 的完整头）
    let hit = r.proto.iter().find(|h| h.name == "ipv4");
    assert!(hit.is_some(), "ipv4 头应命中注册表：{r:?}");
    let hit = hit.unwrap();
    let get = |n: &str| {
        hit.fields
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(get("version"), Some(packet_dsl::ProtoVal::Int(4)));
    assert_eq!(get("ihl"), Some(packet_dsl::ProtoVal::Int(6)));
    assert_eq!(
        get("options"),
        Some(packet_dsl::ProtoVal::Bytes(vec![1, 2, 3, 4])),
        "options 宽度按 ihl 回算读出"
    );
    // IR 语义层照常（src/dst 回填）；raw 分支保留完整头字节（含 options）
    let Layer::Ipv4(ip) = &r.layers[1] else {
        panic!("ipv4 层: {:#?}", r.layers);
    };
    assert_eq!(
        ip.src,
        packet_dsl::ir::Field::Value("1.1.1.1".parse().unwrap())
    );
    let raw = ip.raw.as_ref().expect("proto 反解应填 raw");
    assert_eq!(raw.len(), 24, "IPv4 头应含 options");
    assert_eq!(raw[0], 0x46, "首字节 = version 4 | ihl 6");
    assert_eq!(&raw[20..24], &[1, 2, 3, 4], "options 字节在头尾部");
    // 载荷完整（UDP 层照常解析，payload 为 raw）
    let Layer::Udp(udp) = &r.layers[2] else {
        panic!("udp 层: {:#?}", r.layers);
    };
    assert_eq!(udp.src_port, Some(12345));
    assert_eq!(udp.dst_port, Some(5353));
    let Layer::Raw(raw_pl) = &r.layers[3] else {
        panic!("raw 载荷: {:#?}", r.layers);
    };
    assert_eq!(raw_pl.bytes, b"xy");
    // roundtrip：反解层重序列化字节一致
    let mut layers = r.layers.clone();
    layers.reverse();
    let spec = packet_dsl::ir::PacketSpec { layers };
    let again = DefaultSerializer::with_seed(1).serialize(&spec).unwrap();
    assert_eq!(bytes, again, "带 options 的 ipv4 反解重序列化应字节一致");
}

/// ARP 层头走注册表反解（28B 定宽；htype/ptype 常量校验 ≡ 硬编码参数校验）。
#[test]
fn proto_headers_arp_via_registry() {
    register_eng_lib();
    let bytes = build_full_pkt(
        "a = arp(op=request(), sha=\"00:11:22:33:44:55\", spa=\"192.168.1.1\", tha=\"00:00:00:00:00:00\", tpa=\"192.168.1.2\")\nuse(a) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"ff:ff:ff:ff:ff:ff\", ethertype=0x0806)\n",
    );
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "notes: {:?}", r.notes);
    let hit = r.proto.iter().find(|h| h.name == "arp");
    assert!(hit.is_some(), "arp 头应命中注册表：{r:?}");
    let Layer::Arp(arp) = &r.layers[1] else {
        panic!("arp 层: {:#?}", r.layers);
    };
    assert_eq!(arp.op, Some(packet_dsl::ir::ArpOp::Request));
    assert_eq!(arp.spa, Some("192.168.1.1".parse().unwrap()));
    assert_eq!(arp.tpa, Some("192.168.1.2".parse().unwrap()));
    assert_eq!(arp.sha, Some("00:11:22:33:44:55".parse().unwrap()));
}

/// IPv6 层头走注册表反解（40B 定长；first4 常量校验挡 TC/flow label≠0 的包）。
#[test]
fn proto_headers_ipv6_via_registry() {
    register_eng_lib();
    let bytes = build_full_pkt(
        "p = raw(bytes=\"x\")\nuse(p) |> udp(sport=12345, dport=5353) |> ipv6(src=\"2001:db8::1\", dst=\"2001:db8::2\", hop_limit=32, next_header=17) |> eth()\n",
    );
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "notes: {:?}", r.notes);
    let hit = r.proto.iter().find(|h| h.name == "ipv6");
    assert!(hit.is_some(), "ipv6 头应命中注册表：{r:?}");
    let Layer::Ipv6(ip6) = &r.layers[1] else {
        panic!("ipv6 层: {:#?}", r.layers);
    };
    assert_eq!(
        ip6.src,
        packet_dsl::ir::Field::Value("2001:db8::1".parse().unwrap())
    );
    assert_eq!(ip6.hop_limit, packet_dsl::ir::Field::Value(32));
    assert_eq!(ip6.next_header, Some(17));
    // 内层 UDP 仍解析
    let Layer::Udp(udp) = &r.layers[2] else {
        panic!("udp 层: {:#?}", r.layers);
    };
    assert_eq!(udp.src_port, Some(12345));
    assert_eq!(udp.dst_port, Some(5353));
}

/// HTTP proto（rule tcp 80/8080）：哨兵 list（headers 到空行）+ line + rest body
/// 构造/解析对称；proto_hit_to_layer 回填 method/path/version/headers/body。
#[test]
fn proto_headers_http_via_registry() {
    register_eng_lib();
    let src = concat!(
        "h = http(start_line=\"POST /login HTTP/1.1\", headers=[\"Host: example.com\", \"Content-Length: 2\"], body=\"{}\")\n",
        "use(h) |> tcp(sport=40000, dport=8080, flags=bor(psh(), ack()), seq=1, ack=1) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=6) |> eth()\n",
    );
    let bytes = build_full_pkt(src);
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "notes: {:?}", r.notes);
    // 注册表命中 http → proto_hit_to_layer 转 Layer::Http
    let hit = r.proto.iter().find(|h| h.name == "http");
    assert!(hit.is_some(), "tcp 8080 应命中 http proto：{r:?}");
    let hit = hit.unwrap();
    assert_eq!(hit.subs.len(), 2, "2 个 hdr_line 子命中");
    assert!(hit.subs.iter().all(|s| s.name == "hdr_line"));
    let Layer::Http(f) = &r.layers[3] else {
        panic!("http 应转 IR 层: {:#?}", r.layers);
    };
    assert_eq!(f.method.as_deref(), Some("POST"));
    assert_eq!(f.path.as_deref(), Some("/login"));
    assert_eq!(f.version.as_deref(), Some("HTTP/1.1"));
    assert_eq!(f.headers.len(), 2);
    assert_eq!(
        f.headers[0],
        ("Host".to_string(), "example.com".to_string())
    );
    assert_eq!(f.body.as_deref(), Some(b"{}".as_slice()));
    // raw 保留整段载荷（roundtrip 字节级还原）
    let raw = f.raw.as_ref().expect("proto 反解应填 raw");
    assert_eq!(&raw[..5], b"POST ", "载荷开头");
    assert!(raw.windows(4).any(|w| w == b"\r\n\r\n"), "空行在载荷中");
    // roundtrip
    let mut layers = r.layers.clone();
    layers.reverse();
    let spec = packet_dsl::ir::PacketSpec { layers };
    let again = DefaultSerializer::with_seed(1).serialize(&spec).unwrap();
    assert_eq!(bytes, again, "http 反解重序列化应字节一致");
}

/// DNS 响应（answers 四区 + 压缩指针追跳还原）端到端。
#[test]
fn proto_headers_dns_response_via_registry() {
    register_eng_lib();
    // 手工构造 DNS 响应报文：question example.com + answer 用压缩指针 c00c 指向
    // question 名（追跳还原）——注册表解析（ancount 等不再是常量 0）
    let msg_hex = concat!(
        "1234",
        "8180",
        "0001",
        "0001",
        "0000",
        "0000",
        "07",
        "6578616d706c65",
        "03",
        "636f6d",
        "00",
        "0001",
        "0001",
        "c00c",
        "0001",
        "0001",
        "0000012c",
        "0004",
        "5db8d822",
    );
    let src = format!(
        "q = hex(\"{msg_hex}\")\nuse(q) |> udp(sport=12345, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=17) |> eth()\n"
    );
    let bytes = build_full_pkt(&src);
    let r = dissect(&bytes);
    assert!(r.notes.is_empty(), "notes: {:?}", r.notes);
    let Layer::Dns(f) = &r.layers[3] else {
        panic!("dns 响应应转 IR 层: {:#?}", r.layers);
    };
    assert_eq!(f.id, Some(0x1234));
    assert_eq!(f.flags, Some(0x8180));
    assert_eq!(f.questions.len(), 1);
    assert_eq!(f.questions[0].name, "example.com");
    assert_eq!(f.answers.len(), 1);
    assert_eq!(f.answers[0].name, "example.com", "压缩指针应追跳还原");
    assert_eq!(f.answers[0].rdata, vec![93, 184, 216, 34]);
    assert_eq!(f.answers[0].ttl, Some(300));
}
