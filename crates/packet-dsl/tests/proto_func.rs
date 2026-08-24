//! `#[proto] func` + `#[meta]`（自表示协议的唯一声明语法）测试。
//!
//! proto 关键字语法已移除：声明式协议一律写 `#[proto] func name(params) -> bytes { concat(...) }`
//! （或 `layer("kind", concat(...))`），解析期降糖为字段表（`parser.rs::desugar_proto_funcs`）。
//! 本文件覆盖：与命令式 func 构建逐字节一致（eth/arp/icmp/ipv4/ipv6/quic golden）、
//! `#[meta(bytes=...)]` 宽度联动 / `len` 计算字段 / `#[meta(rest=...)]`、错误路径、解析侧注册表。

mod common;

use packet_dsl::ir::PacketSpec;
use packet_dsl::{DefaultSerializer, Serializer, semantic};

fn build_packets(src: &str) -> Vec<PacketSpec> {
    let m = semantic::parse_str("t", src).expect("解析失败");
    packet_dsl::resolve(&m).expect("求值失败").packets
}

fn serialize_all(pkts: &[PacketSpec]) -> Vec<Vec<u8>> {
    let ser = DefaultSerializer::with_seed(1);
    pkts.iter().map(|p| ser.serialize(p).unwrap()).collect()
}

/// 两个等价构建（命令式 func vs 声明式 proto-func）应产出逐字节一致的包。
fn assert_equiv(func_src: &str, proto_src: &str) {
    let a = serialize_all(&build_packets(func_src));
    let b = serialize_all(&build_packets(proto_src));
    assert_eq!(a.len(), b.len(), "包数一致");
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        assert_eq!(x, y, "包 {i}: proto-func 与命令式 func 构建字节不一致");
    }
}

/// 命令式 eth（`layer` 直喂 + concat），作 proto-func 的对照。
const ETH_IMP: &str = r#"
func eth_i(dst_mac="ff:ff:ff:ff:ff:ff", src_mac="00:00:00:00:00:00", ethertype=0x0800) {
    eth_bytes(concat(mac(dst_mac), mac(src_mac), be16(ethertype)))
}
"#;
/// 命令式 arp。
const ARP_IMP: &str = r#"
func arp_i(htype=1, ptype=0x0800, hlen=6, plen=4, op=request(), sha="00:00:00:00:00:00", spa="0.0.0.0", tha="00:00:00:00:00:00", tpa="0.0.0.0") {
    arp_bytes(concat(be16(htype), be16(ptype), u8(hlen), u8(plen), be16(op), mac(sha), ip4(spa), mac(tha), ip4(tpa)))
}
"#;
/// 命令式 icmp（checksum 占位 0 由序列化器覆盖头+载荷）。
const ICMP_IMP: &str = r#"
func icmp_i(type=8, code=0, id=0, seq=0, payload="") {
    icmp_bytes(concat(u8(type), u8(code), be16(0), be16(id), be16(seq), raw(payload)))
}
"#;
/// 命令式 ipv4（total/checksum 占位 0 由序列化器覆盖；src/dst 作伪头部元数据）。
const IPV4_IMP: &str = r#"
func ipv4_i(src="0.0.0.0", dst="255.255.255.255", ttl=64, proto=0, tos=0, id=0, flags=0) {
    ipv4_bytes(concat(u8(0x45), u8(tos), be16(0), be16(id), be16(flags), u8(ttl), u8(proto), be16(0), ip4(src), ip4(dst)), src, dst)
}
"#;
/// 命令式 ipv6（plen 占位 0 由序列化器覆盖）。
const IPV6_IMP: &str = r#"
func ipv6_i(src="::", dst="::", hop_limit=64, next_header=59) {
    ipv6_bytes(concat(hex("60000000"), be16(0), u8(next_header), u8(hop_limit), ip6(src), ip6(dst)), src, dst)
}
"#;

#[test]
fn proto_eth_matches_func() {
    let func = format!(
        "{ETH_IMP}q = raw(bytes=\"x\")\nfull = use(q) |> udp(sport=12345, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=17) |> eth_i(dst_mac=\"66:77:88:99:aa:bb\", src_mac=\"00:11:22:33:44:55\")\nexport:\n- full\n"
    );
    // eng_lib 的 eth（proto-func，prelude 隐式可见）
    let proto = "q = raw(bytes=\"x\")\nfull = use(q) |> udp(sport=12345, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=17) |> eth(dst_mac=\"66:77:88:99:aa:bb\", src_mac=\"00:11:22:33:44:55\")\nexport:\n- full\n";
    assert_equiv(&func, proto);
}

#[test]
fn proto_arp_matches_func() {
    let func = format!(
        "{ETH_IMP}{ARP_IMP}r = arp_i(op=request(), sha=\"00:11:22:33:44:55\", spa=\"192.168.1.1\", tha=\"00:00:00:00:00:00\", tpa=\"192.168.1.2\")\nfull = use(r) |> eth_i(src_mac=\"00:11:22:33:44:55\", dst_mac=\"ff:ff:ff:ff:ff:ff\", ethertype=0x0806)\nexport:\n- full\n"
    );
    let proto = "r = arp(op=request(), sha=\"00:11:22:33:44:55\", spa=\"192.168.1.1\", tha=\"00:00:00:00:00:00\", tpa=\"192.168.1.2\")\nfull = use(r) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"ff:ff:ff:ff:ff:ff\", ethertype=0x0806)\nexport:\n- full\n";
    assert_equiv(&func, proto);
}

#[test]
fn proto_icmp_matches_func() {
    let func = format!(
        "{IPV4_IMP}{ICMP_IMP}p = raw(bytes=\"ping\")\nfull = use(p) |> icmp_i(type=8, code=0, id=0x1234, seq=7) |> ipv4_i(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=1)\nexport:\n- full\n"
    );
    let proto = "p = raw(bytes=\"ping\")\nfull = use(p) |> icmp(type=8, code=0, id=0x1234, seq=7) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=1)\nexport:\n- full\n";
    assert_equiv(&func, proto);
}

#[test]
fn proto_ipv4_matches_func_with_inner_tcp() {
    // 内层 TCP：校验伪头部 src/dst —— proto-func ipv4 的 src/dst 字段须进入层元数据
    let func = format!(
        "{ETH_IMP}{IPV4_IMP}p = raw(bytes=\"x\")\nfull = use(p) |> tcp(sport=40000, dport=80, flags=bor(psh(), ack()), seq=1, ack=1) |> ipv4_i(src=\"1.1.1.1\", dst=\"8.8.8.8\", ttl=63, proto=6, tos=0x10, id=7) |> eth_i()\nexport:\n- full\n"
    );
    let proto = "p = raw(bytes=\"x\")\nfull = use(p) |> tcp(sport=40000, dport=80, flags=bor(psh(), ack()), seq=1, ack=1) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", ttl=63, proto=6, tos=0x10, id=7) |> eth()\nexport:\n- full\n";
    assert_equiv(&func, proto);
}

#[test]
fn proto_ipv6_matches_func() {
    // IPv6：first4 固定宽常量（字面量宽度自动推导）与 @auto plen
    let func = format!(
        "{ETH_IMP}{IPV6_IMP}p = raw(bytes=\"x\")\nfull = use(p) |> udp(sport=12345, dport=53) |> ipv6_i(src=\"2001:db8::1\", dst=\"2001:db8::2\", hop_limit=32, next_header=17) |> eth_i()\nexport:\n- full\n"
    );
    let proto = "p = raw(bytes=\"x\")\nfull = use(p) |> udp(sport=12345, dport=53) |> ipv6(src=\"2001:db8::1\", dst=\"2001:db8::2\", hop_limit=32, next_header=17) |> eth()\nexport:\n- full\n";
    assert_equiv(&func, proto);
}

#[test]
fn proto_bytes_width_linkage() {
    // #[meta(bytes="n")] 前序字段宽度联动 + #[meta(rest)]：构造校验长度一致
    let src = r#"
#[proto(kind="eth")]
func lenpkt(n=0, data="", rest="") -> bytes {
    concat(
        u8(n),
        #[meta(bytes="n")] data,
        #[meta(rest)] rest
    )
}
p = lenpkt(n=3, data=hex("aabbcc"), rest="xyz")
export:
- p
"#;
    let bytes = serialize_all(&build_packets(src));
    assert_eq!(bytes[0], vec![0x03, 0xaa, 0xbb, 0xcc, b'x', b'y', b'z']);
}

#[test]
fn proto_bytes_width_mismatch_errors() {
    let src = r#"
#[proto(kind="eth")]
func lenpkt(n=0, data="") -> bytes {
    concat(
        u8(n),
        #[meta(bytes="n")] data
    )
}
p = lenpkt(n=2, data=hex("aabbcc"))
export:
- p
"#;
    let err = semantic::parse_str("t", src)
        .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
        .unwrap_err();
    assert!(err.to_string().contains("宽度"), "{err}");
}

#[test]
fn proto_auto_length() {
    // @auto：值 = 后续字段编码字节数，用字段自身类型编码（vint prefix codec）
    let src = r#"
#[proto(kind="eth")]
func autopkt(a=1, body="hello") -> bytes {
    concat(
        u8(a),
        #[meta(len="auto", codec="prefix", prefix_bits=2, widths=[1,2,4,8])] len,
        #[meta(rest)] body
    )
}
p = autopkt()
export:
- p
"#;
    let bytes = serialize_all(&build_packets(src));
    assert_eq!(bytes[0], vec![0x01, 0x05, b'h', b'e', b'l', b'l', b'o']);
}

#[test]
fn proto_missing_field_without_default_errors() {
    let src = r#"
#[proto(kind="eth")]
func pkt(a, b=2) -> bytes {
    concat(u8(a), u8(b))
}
p = pkt()
export:
- p
"#;
    let err = semantic::parse_str("t", src)
        .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
        .unwrap_err();
    // func 形式：字段默认值 = 同名参数引用 → 必填字段未给时报「参数 `a` 未提供」
    assert!(err.to_string().contains("未提供"), "{err}");
}

/// `bytes(宽度)` / `rest(子proto)` 调用形态已移除（不是函数）：宽度/消费末尾
/// 是声明性 `#[meta]` 项，报迁移错误（指向 `#[meta(bytes=...)]` / `#[meta(rest=...)]`）。
#[test]
fn proto_bytes_rest_call_form_removed() {
    let err = |src: &str| {
        semantic::parse_str("t", src)
            .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
            .unwrap_err()
            .to_string()
    };
    let e = err(
        "#[proto(kind=\"eth\")]\nfunc pkt() -> bytes {\n    concat(bytes(4))\n}\np = pkt()\nexport:\n- p\n",
    );
    assert!(e.contains("`bytes(...)` 调用形态已移除"), "{e}");
    assert!(e.contains("#[meta(bytes=...)]"), "{e}");
    let e = err(
        "#[proto(kind=\"eth\")]\nfunc pkt() -> bytes {\n    concat(rest(\"x\"))\n}\np = pkt()\nexport:\n- p\n",
    );
    assert!(e.contains("`rest(...)` 调用形态已移除"), "{e}");
    assert!(e.contains("#[meta(rest=...)]"), "{e}");
}

#[test]
fn proto_unknown_arg_errors() {
    let src = r#"
#[proto(kind="eth")]
func pkt(a=1) -> bytes {
    concat(u8(a))
}
p = pkt(zzz=9)
export:
- p
"#;
    let err = semantic::parse_str("t", src)
        .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
        .unwrap_err();
    assert!(err.to_string().contains("没有参数"), "{err}");
}

#[test]
fn proto_auto_field_rejects_arg() {
    let src = r#"
#[proto(kind="eth")]
func pkt() -> bytes {
    concat(#[meta(len="auto", codec="prefix", prefix_bits=2, widths=[1,2,4,8])] len)
}
p = pkt(len=3)
export:
- p
"#;
    let err = semantic::parse_str("t", src)
        .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
        .unwrap_err();
    assert!(err.to_string().contains("len 计算字段"), "{err}");
}

#[test]
fn proto_export_allowed() {
    // proto-func 可导出（eng_lib prelude 依赖）；导出后仍可正常构造
    let src = r#"
#[proto(kind="eth")]
func eth(dst_mac="ff:ff:ff:ff:ff:ff", src_mac="00:00:00:00:00:00", ethertype=0x0800) -> bytes {
    concat(mac(dst_mac), mac(src_mac), be16(ethertype))
}
export:
- eth
"#;
    let m = semantic::parse_str("t", src).unwrap();
    assert!(m.protos.iter().any(|p| p.name == "eth"), "proto 应已解析");
    let _ = packet_dsl::resolve(&m).expect("导出 proto 不应阻止求值");
}

#[test]
fn proto_unknown_layer_kind_errors() {
    let src = r#"
#[proto(kind="quic")]
func q() -> bytes {
    concat(u8(1))
}
"#;
    let err = semantic::parse_str("t", src).unwrap_err();
    assert!(err.to_string().contains("层类型"), "{err}");
}

#[test]
fn proto_unknown_attr_errors() {
    // 注解但无 #[proto]
    let src = r#"
#[foo("x")]
func q() {
    concat(u8(1))
}
"#;
    let err = semantic::parse_str("t", src).unwrap_err();
    assert!(err.to_string().contains("需要 `#[proto]`"), "{err}");
}

#[test]
fn proto_bare_allowed_as_raw() {
    // 无 layer 无 rule 的裸 proto-func 合法：纯构造规格（use() 时产出 Raw 载荷层，
    // 也可作 `rest(子proto)` 解析目标，如 quic_crypto）
    let src = "#[proto]\nfunc q(a=1) -> bytes {\n    concat(u8(a))\n}\np = q()\nexport:\n- p\n";
    let m = semantic::parse_str("t", src).unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let bytes = DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    assert_eq!(bytes, vec![0x01]);
}

#[test]
fn proto_mac_ip4_ip6_encoders() {
    let src = r#"
#[proto(kind="eth")]
func addr(m="", a="", b="") -> bytes {
    concat(mac(m), ip4(a), ip6(b))
}
p = addr(m="aa-bb-cc.dd:ee:ff", a="192.168.1.1", b="2001:db8::1")
export:
- p
"#;
    let bytes = serialize_all(&build_packets(src));
    let mut expect = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    expect.extend_from_slice(&[192, 168, 1, 1]);
    expect.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    assert_eq!(bytes[0], expect);
}

/// M3 金样：proto-func quic_initial 与等价命令式字节拼接逐字节一致。
#[test]
fn quic_initial_matches_func() {
    let func = r#"
func qc(offset=0, data="") -> bytes { concat(u8(0x06), qvarint(offset), qvarint(len(data)), raw(data)) }
quic = raw(bytes=concat(
    u8(bor(0xc0, 0)), be32(0x00000001),
    u8(8), hex("8394c8f03e515708"),
    u8(8), hex("fdfd0d050a0b0c0d"),
    qvarint(0), raw(""),
    qvarint(1 + len(concat(qc(0, "CHLO"), pad(16)))), u8(0),
    concat(qc(0, "CHLO"), pad(16))
))
export:
- quic
"#;
    let proto = r#"
#[proto]
#[rule(udp(dport=443))]
#[rule(bytes(0xc0))]
func quic_initial(pnl=0, pn=u8(0), payload="") -> bytes {
    concat(
        #[meta(name="first")] u8(bor(0xc0, pnl)),
        #[meta(name="version")] be32(0x00000001),
        #[meta(len="dcid")] u8(dcid_len),
        #[meta(bytes="dcid_len")] dcid,
        #[meta(len="scid")] u8(scid_len),
        #[meta(bytes="scid_len")] scid,
        #[meta(len="token", codec="prefix", prefix_bits=2, widths=[1,2,4,8])] token_len,
        #[meta(bytes="token_len")] token,
        #[meta(len="auto", codec="prefix", prefix_bits=2, widths=[1,2,4,8])] length,
        #[meta(bytes="band(first, 3) + 1")] pn,
        #[meta(rest="quic_crypto")] payload
    )
}
func qc(offset=0, data="") -> bytes { concat(u8(0x06), qvarint(offset), qvarint(len(data)), raw(data)) }
quic = quic_initial(
    dcid=hex("8394c8f03e515708"),
    scid=hex("fdfd0d050a0b0c0d"),
    pnl=0, pn=u8(0), token="",
    payload=concat(qc(0, "CHLO"), pad(16))
)
export:
- quic
"#;
    assert_equiv(func, proto);
}

/// `#[rule(and(...))]` 显式分组与多个 `#[rule]` 注解等价（全部子条件 AND）：
/// 语义层 rule 相等 + 分派/掩码行为一致（嵌套 and 递归展开）。
#[test]
fn rule_and_form_equals_two_attrs() {
    let two = r#"
#[proto]
#[rule(udp(dport=443))]
#[rule(bytes(0xc0))]
func x(a=1) -> bytes { concat(u8(a)) }
"#;
    let and = r#"
#[proto]
#[rule(and(udp(dport=443), bytes(0xc0)))]
func x(a=1) -> bytes { concat(u8(a)) }
"#;
    let m2 = semantic::parse_str("t", two).unwrap();
    let ma = semantic::parse_str("t", and).unwrap();
    let r2 = m2.protos[0].rule.clone().expect("两属性形式应有规则");
    let ra = ma.protos[0].rule.clone().expect("and 形式应有规则");
    assert_eq!(
        r2, ra,
        "两个 `#[rule]` 注解与 `#[rule(and(...))]` 应产生同一规则"
    );

    // 分派语义：上下文条件（本层规则命中）+ 首字节掩码（解析期先验）
    let kind = packet_dsl::RuleCond::Udp {
        dport: Some(443),
        sport: Some(12345),
    };
    assert!(ra.matches_cond(&kind), "udp 443 应命中");
    let other = packet_dsl::RuleCond::Udp {
        dport: Some(53),
        sport: Some(12345),
    };
    assert!(!ra.matches_cond(&other), "非 443 端口不命中");
    let tcp = packet_dsl::RuleCond::Tcp {
        dport: Some(443),
        sport: Some(12345),
    };
    assert!(!ra.matches_cond(&tcp), "tcp 层不命中 udp 规则");
    assert!(ra.matches_first_byte(0xc1), "首字节 0xc1 过掩码");
    assert!(!ra.matches_first_byte(0x40), "首字节 0x40 不过掩码");

    // 嵌套 and 递归展开等价
    let nested = r#"
#[proto]
#[rule(and(and(udp(dport=443), bytes(0xc0))))]
func x(a=1) -> bytes { concat(u8(a)) }
"#;
    let mn = semantic::parse_str("t", nested).unwrap();
    assert_eq!(
        mn.protos[0].rule, ma.protos[0].rule,
        "嵌套 and 展开后与顶层 and 等价"
    );

    // 同层多上下文子条件 AND（如 dport=443 且 sport=53 都满足才命中）
    let multi = r#"
#[proto]
#[rule(and(udp(dport=443), udp(sport=53)))]
func x(a=1) -> bytes { concat(u8(a)) }
"#;
    let mm = semantic::parse_str("t", multi).unwrap();
    let rm = mm.protos[0].rule.clone().unwrap();
    let both = packet_dsl::RuleCond::Udp {
        dport: Some(443),
        sport: Some(53),
    };
    assert!(rm.matches_cond(&both), "dport+sport 都满足应命中");
    let only_port = packet_dsl::RuleCond::Udp {
        dport: Some(443),
        sport: Some(12345),
    };
    assert!(!rm.matches_cond(&only_port), "仅 dport 满足不命中（AND）");

    // 多掩码 AND：0xc0 与 0x01 都过才通过
    let m2m = r#"
#[proto]
#[rule(and(bytes(0xc0), bytes(0x01)))]
func x(a=1) -> bytes { concat(u8(a)) }
"#;
    let m2m = semantic::parse_str("t", m2m).unwrap();
    let r2m = m2m.protos[0].rule.clone().unwrap();
    assert!(r2m.matches_first_byte(0xc1), "0xc1 同时过 0xc0 与 0x01");
    assert!(!r2m.matches_first_byte(0xc0), "0xc0 不过 0x01 掩码");
}

/// `#[rule(or(...))]` 选一分派：多端口/多条件任一命中；与独立 `#[rule(bytes(...))]`
/// 组合仍是 AND（任一端口命中 + 掩码先验）；and/or 可嵌套。
#[test]
fn rule_or_forms() {
    // or 多端口：任一端口命中，其它不命中
    let or = r#"
#[proto]
#[rule(or(udp(dport=443), udp(dport=4433)))]
func x(a=1) -> bytes { concat(u8(a)) }
"#;
    let m = semantic::parse_str("t", or).unwrap();
    let r = m.protos[0].rule.clone().unwrap();
    for dport in [443u16, 4433] {
        let kind = packet_dsl::RuleCond::Udp {
            dport: Some(dport),
            sport: Some(12345),
        };
        assert!(r.matches_cond(&kind), "or 端口 {dport} 应命中");
    }
    let other = packet_dsl::RuleCond::Udp {
        dport: Some(8443),
        sport: Some(12345),
    };
    assert!(!r.matches_cond(&other), "非 or 端口不命中");
    let tcp = packet_dsl::RuleCond::Tcp {
        dport: Some(443),
        sport: Some(12345),
    };
    assert!(!r.matches_cond(&tcp), "tcp 层不命中 udp or 规则");

    // or + 独立掩码：两端口任一命中，且首字节过掩码（AND）
    let or_mask = r#"
#[proto]
#[rule(or(udp(dport=443), udp(dport=4433)))]
#[rule(bytes(0xc0))]
func x(a=1) -> bytes { concat(u8(a)) }
"#;
    let m = semantic::parse_str("t", or_mask).unwrap();
    let r = m.protos[0].rule.clone().unwrap();
    assert!(r.matches_first_byte(0xc1), "掩码应生效");
    assert!(!r.matches_first_byte(0x40), "掩码不符不通过");

    // or 内嵌 and：or(and(udp(dport=443), udp(sport=53)), udp(dport=4433))
    let mix = r#"
#[proto]
#[rule(or(and(udp(dport=443), udp(sport=53)), udp(dport=4433)))]
func x(a=1) -> bytes { concat(u8(a)) }
"#;
    let m = semantic::parse_str("t", mix).unwrap();
    let r = m.protos[0].rule.clone().unwrap();
    let and_hit = packet_dsl::RuleCond::Udp {
        dport: Some(443),
        sport: Some(53),
    };
    assert!(r.matches_cond(&and_hit), "and 分支（443+sport53）应命中");
    let and_miss = packet_dsl::RuleCond::Udp {
        dport: Some(443),
        sport: Some(12345),
    };
    assert!(
        !r.matches_cond(&and_miss),
        "and 分支须全部满足（sport 不符不命中）"
    );
    let or_hit = packet_dsl::RuleCond::Udp {
        dport: Some(4433),
        sport: Some(9999),
    };
    assert!(r.matches_cond(&or_hit), "or 第二分支 4433 应命中");

    // 单分支 or 退化为原子：or(udp(dport=443)) ≡ udp(dport=443)
    let single = r#"
#[proto]
#[rule(or(udp(dport=443)))]
func x(a=1) -> bytes { concat(u8(a)) }
"#;
    let plain = r#"
#[proto]
#[rule(udp(dport=443))]
func x(a=1) -> bytes { concat(u8(a)) }
"#;
    let ms = semantic::parse_str("t", single).unwrap();
    let mp = semantic::parse_str("t", plain).unwrap();
    assert_eq!(
        ms.protos[0].rule, mp.protos[0].rule,
        "单分支 or 应与普通规则等价"
    );
}

/// `#[proto(kind="kind")]` 合并层类型：裸 `#[proto]` = Raw 层；`#[proto(kind="eth")]` = IR 层 eth。
#[test]
fn proto_layer_kind_merge() {
    // #[proto(kind="eth")] ≡ #[proto] + #[layer("eth")]：semantic layer 提取
    let src = r#"
#[proto(kind="eth")]
func eth(dst_mac="ff:ff:ff:ff:ff:ff", src_mac="00:00:00:00:00:00", ethertype=0x0800) -> bytes {
    concat(mac(dst_mac), mac(src_mac), be16(ethertype))
}
"#;
    let m = semantic::parse_str("t", src).unwrap();
    let p = m.protos.iter().find(|p| p.name == "eth").unwrap();
    assert_eq!(p.layer.as_deref(), Some("eth"), "层类型应合并");
    // 裸 #[proto] = Raw 层（无 layer）
    let src2 = "#[proto]\nfunc q(a=1) -> bytes { concat(u8(a)) }\n";
    let m2 = semantic::parse_str("t", src2).unwrap();
    let p2 = m2.protos.iter().find(|p| p.name == "q").unwrap();
    assert_eq!(p2.layer, None, "裸 #[proto] 无 IR 层");
    // 非 IR 层类型 → 报错
    let err = semantic::parse_str(
        "t",
        "#[proto(kind=\"quic\")]\nfunc q(a=1) -> bytes { concat(u8(a)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("层类型"), "{err}");
    // 两个 #[proto] → 重复报错
    let err = semantic::parse_str(
        "t",
        "#[proto(kind=\"eth\")]\n#[proto(kind=\"arp\")]\nfunc q(a=1) -> bytes { concat(u8(a)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("重复"), "{err}");
    // 旧位置形式 → 键值对迁移报错
    let err = semantic::parse_str(
        "t",
        "#[proto(\"eth\")]\nfunc q(a=1) -> bytes { concat(u8(a)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("键值对"), "{err}");
}

/// 两个 dissect 测试共用的 func-form QUIC 声明（注册表注册内容一致，顺序无关）。
const QUIC_FUNC_SRC: &str = r#"
#[proto]
#[rule(udp(dport=443))]
#[rule(bytes(0xc0))]
func quic_initial(pnl=0, pn=u8(0), payload="") -> bytes {
    concat(
        #[meta(name="first")] u8(bor(0xc0, pnl)),
        #[meta(name="version")] be32(0x00000001),
        #[meta(len="dcid")] u8(dcid_len),
        #[meta(bytes="dcid_len")] dcid,
        #[meta(len="scid")] u8(scid_len),
        #[meta(bytes="scid_len")] scid,
        #[meta(len="token", codec="prefix", prefix_bits=2, widths=[1,2,4,8])] token_len,
        #[meta(bytes="token_len")] token,
        #[meta(len="auto", codec="prefix", prefix_bits=2, widths=[1,2,4,8])] length,
        #[meta(bytes="band(first, 3) + 1")] pn,
        #[meta(rest="quic_crypto")] payload
    )
}
#[proto]
func quic_crypto(offset=0, data="") -> bytes {
    concat(
        #[meta(name="frame_type")] u8(0x06),
        #[meta(codec="prefix", prefix_bits=2, widths=[1,2,4,8])] offset,
        #[meta(len="data", codec="prefix", prefix_bits=2, widths=[1,2,4,8])] length,
        #[meta(bytes="length")] data
    )
}
"#;

/// list 测试注册的 DNS 声明（与 QUIC_FUNC_SRC 一起注册，避免 OnceLock 竞争）。
const DNS_PROTO_SRC: &str = r#"
#[proto]
func dns_question(name="", qtype=1, qclass=1) -> bytes {
    concat(
        dns_name(name),
        be16(qtype), be16(qclass)
    )
}
#[proto(kind="dns")]
#[rule(udp(dport=53))]
func dns(id=0, flags=0x0100, questions=[]) -> bytes {
    concat(
        be16(id), be16(flags),
        #[meta(name="qdcount")] be16(count(questions)),
        be16(0), be16(0), be16(0),
        #[meta(list="qdcount", item="dns_question")] questions
    )
}
"#;

/// 用源码注册全局 proto 表（OnceLock 幂等；测试进程内**首次**注册生效，故所有
/// dissect 测试必须注册同一内容——eng_lib 层头 + QUIC + DNS 一起注册，顺序无关）。
/// eng_lib 提供层头（eth/ipv4/udp...，dissect 契约：层头只走注册表）；排除
/// quic_initial/dns（测试自定义版优先，避免 eng_lib 同名 proto 抢先命中）。
fn register_quic(src: &str) {
    let mut resolved = common::collect_eng_lib_protos();
    resolved.retain(|p| !matches!(p.name.as_str(), "quic_initial" | "dns" | "dns_question"));
    let combined = format!("{QUIC_FUNC_SRC}{DNS_PROTO_SRC}{src}");
    let m = semantic::parse_str("t", &combined).unwrap();
    resolved.extend(m.protos.iter().map(|p| {
        packet_dsl::ResolvedProto {
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
        }
    }));
    packet_dsl::set_proto_registry(resolved);
}

/// 解析侧：注册 func-form quic_initial 后，捕获的 QUIC 包能反解出字段
/// （含 rest(quic_crypto) 嵌套子命中）。
#[test]
fn dissect_parses_quic_initial() {
    register_quic("");
    let src = format!(
        "{QUIC_FUNC_SRC}q = quic_initial(dcid=hex(\"8394c8f03e515708\"), scid=hex(\"fdfd0d050a0b0c0d\"), token=\"\", payload=concat(quic_crypto(0, \"CHLO\"), pad(2)))\nfull = use(q) |> udp(sport=12345, dport=443) |> ipv4(src=\"127.0.0.1\", dst=\"8.8.8.8\", proto=17) |> eth()\nexport:\n- full\n"
    );
    let m = semantic::parse_str("t", &src).unwrap();
    let pkt = packet_dsl::resolve(&m)
        .unwrap()
        .packets
        .into_iter()
        .next()
        .unwrap();
    let bytes = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "quic_initial");
    assert!(hit.is_some(), "应命中 quic_initial：{r:?}");
    let hit = hit.unwrap();
    assert_eq!(hit.fields.len(), 11, "quic_initial 应反解出全部字段");
    let dcid = hit
        .fields
        .iter()
        .find(|(n, _)| n == "dcid")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert_eq!(
        dcid,
        packet_dsl::ProtoVal::Bytes(vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08])
    );
    let version = hit
        .fields
        .iter()
        .find(|(n, _)| n == "version")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert_eq!(version, packet_dsl::ProtoVal::Int(1));
    let sub = hit.subs.iter().find(|s| s.name == "quic_crypto");
    assert!(sub.is_some(), "rest(quic_crypto) 应递归反解出子命中");
}

/// 解析侧：feature 不匹配（非 QUIC 首字节）→ 不命中，回退 raw。
#[test]
fn dissect_quic_feature_mismatch() {
    let bytes = vec![0x00, 0x11, 0x22]; // 首字节 0x00，不是 0xc0
    let r = packet_dsl::dissect(&bytes);
    assert!(r.proto.is_empty(), "特征不匹配不应命中 proto");
}

/// 降糖错误路径：注解/body 形态/meta 标注的校验。
#[test]
fn proto_func_error_paths() {
    // 旧语法（无 -> bytes）→ 迁移报错「需要返回类型标注」（原「body 必须扁平 concat」
    // 错误已并入 —— proto_func_body 语法层只接受 `-> bytes { concat(...) }`）
    let err = semantic::parse_str("t", "#[proto]\nfunc x() { u8(1) |> eth() }\n").unwrap_err();
    assert!(err.to_string().contains("返回类型"), "{err}");
    // `-> bytes` 返回标注
    let err = semantic::parse_str("t", "#[proto]\nfunc x() { concat(u8(1)) }\n").unwrap_err();
    assert!(err.to_string().contains("返回类型"), "{err}");
    // 未知 meta 项
    let err = semantic::parse_str(
        "t",
        "#[proto]\nfunc x() -> bytes { concat(#[meta(foo=1)] u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("未知"), "{err}");
    // 旧调用形式 → 键值对迁移报错
    let err = semantic::parse_str(
        "t",
        "#[proto]\nfunc x() -> bytes { concat(#[meta(len(\"dcid\"))] u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("键值对"), "{err}");
    // 非字段类型调用
    let err = semantic::parse_str(
        "t",
        "#[proto]\nfunc x() -> bytes { concat(tpl(\"%x\", 1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("不是字段类型"), "{err}");
    // 字段位置 varint/qvarint 糖已移除 → 提示 codec meta
    let err = semantic::parse_str("t", "#[proto]\nfunc x() -> bytes { concat(varint(n)) }\n")
        .unwrap_err();
    assert!(err.to_string().contains("不是字段类型"), "{err}");
    assert!(err.to_string().contains("codec"), "{err}");
    // `#[meta(auto)]` 已并入 `#[meta(len="auto")]`（@auto/@len 统一为 len 目标）
    let err = semantic::parse_str(
        "t",
        "#[proto]\nfunc x() -> bytes { concat(#[meta(auto)] u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("len=\"auto\""), "{err}");
    // 哨兵 list（`#[meta(list, item=...)]` 无计数）已并入 `#[meta(rest="子proto")]`
    let err = semantic::parse_str(
        "t",
        "#[proto]\nfunc x() -> bytes { concat(#[meta(list, item=\"sub\")] payload) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("rest=\"子proto\""), "{err}");
    // 裸标识符没有 meta 类型
    let err =
        semantic::parse_str("t", "#[proto]\nfunc x() -> bytes { concat(payload) }\n").unwrap_err();
    assert!(err.to_string().contains("裸标识符"), "{err}");
    // 重复 #[proto]
    let err = semantic::parse_str(
        "t",
        "#[proto(kind=\"a\")]\n#[proto(kind=\"b\")]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("重复"), "{err}");
    // body 的 layer("kind", ...) 形态已移除：作 body 解析时报「必须是扁平 concat」
    let err = semantic::parse_str(
        "t",
        "#[proto(kind=\"eth\")]\nfunc x() -> bytes { layer(\"arp\", concat(u8(1))) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("扁平"), "{err}");
    // 参数前非 meta 注解
    let err = semantic::parse_str(
        "t",
        "#[proto]\nfunc x() -> bytes { concat(#[layer(\"eth\")] u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("注解只支持"), "{err}");
    // 旧 #[bind] / #[feature] → 已并入 #[rule] 的迁移报错
    let err = semantic::parse_str(
        "t",
        "#[proto]\n#[bind(\"udp(dport=443)\")]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("已并入"), "{err}");
    let err = semantic::parse_str(
        "t",
        "#[proto]\n#[feature(0xc0)]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("已并入"), "{err}");
    // 上下文子条件跨层（and 组合不同层）→ 报错
    let err = semantic::parse_str(
        "t",
        "#[proto]\n#[rule(and(ipv4(proto=17), udp(dport=443)))]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("跨层"), "{err}");
    // and 的子条件不是调用形式 → 报错
    let err = semantic::parse_str(
        "t",
        "#[proto]\n#[rule(and(udp(dport=443), 5))]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("调用形式"), "{err}");
    // or 分支含掩码 → 报错（掩码不能作选一分派条件）
    let err = semantic::parse_str(
        "t",
        "#[proto]\n#[rule(or(udp(dport=443), bytes(0xc0)))]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("掩码"), "{err}");
    // not → 报错（不支持否定条件）
    let err = semantic::parse_str(
        "t",
        "#[proto]\n#[rule(not(udp(dport=443)))]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("not"), "{err}");
    // 空 and / or → 报错
    let err = semantic::parse_str(
        "t",
        "#[proto]\n#[rule(and())]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("至少一个"), "{err}");
    let err = semantic::parse_str(
        "t",
        "#[proto]\n#[rule(or())]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("至少一个"), "{err}");
    // or 分支跨层 → 报错（同一规则内所有上下文原子须同层）
    let err = semantic::parse_str(
        "t",
        "#[proto]\n#[rule(or(udp(dport=443), eth(ethertype=0x0800)))]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("跨层"), "{err}");
    // 掩码越界
    let err = semantic::parse_str(
        "t",
        "#[proto]\n#[rule(bytes(0x100))]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("0..=255"), "{err}");
    // 旧字符串形式 → 调用形式迁移报错
    let err = semantic::parse_str(
        "t",
        "#[proto]\n#[rule(\"udp(dport=443)\")]\nfunc x() -> bytes { concat(u8(1)) }\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("调用形式"), "{err}");
}

/// `#[meta]` 多参数键值对（`#[meta(name="magic", bytes=4)]`）与字面量宽度自动推导
/// （`hex("60000000")` = 4 字节，无需 bytes 标注；`bytes` 机制只留给变长场合）。
#[test]
fn proto_meta_multi_kv_and_auto_width() {
    let explicit = r#"
#[proto(kind="eth")]
func pkt() -> bytes {
    concat(
        #[meta(name="magic", bytes=4)] hex("60000000"),
        u8(1)
    )
}
p = pkt()
export:
- p
"#;
    let auto = r#"
#[proto(kind="eth")]
func pkt() -> bytes {
    concat(
        #[meta(name="magic")] hex("60000000"),
        u8(1)
    )
}
p = pkt()
export:
- p
"#;
    assert_equiv(explicit, auto);
    let bytes = serialize_all(&build_packets(auto));
    assert_eq!(bytes[0], vec![0x60, 0x00, 0x00, 0x00, 0x01]);
}

/// ── list 重复字段 + DnsName + @len/@auto expr（变长标记）──
///
/// list 构造：值 = 列表，逐项调用子 proto 编码拼接（DNS question 形态）。
#[test]
fn proto_list_dns_questions() {
    let src = r#"
#[proto]
func dns_question(name="", qtype=1, qclass=1) -> bytes {
    concat(
        dns_name(name),
        be16(qtype), be16(qclass)
    )
}
#[proto(kind="dns")]
func dns(id=0, flags=0x0100, questions=[]) -> bytes {
    concat(
        be16(id), be16(flags),
        #[meta(name="qdcount")] be16(count(questions)),
        be16(0), be16(0), be16(0),
        #[meta(list="qdcount", item="dns_question")] questions
    )
}
p = dns(id=0x1234, questions=["www.baidu.com", "a.b.c"])
export:
- p
"#;
    let bytes = serialize_all(&build_packets(src));
    // 头 12B：id/flags/qdcount=2/ancount=0/nscount=0/arcount=0
    let mut expect = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // question 1：www.baidu.com + qtype A + qclass IN
    expect.extend_from_slice(&[
        3, b'w', b'w', b'w', 5, b'b', b'a', b'i', b'd', b'u', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ]);
    // question 2：a.b.c
    expect.extend_from_slice(&[1, b'a', 1, b'b', 1, b'c', 0, 0, 1, 0, 1]);
    assert_eq!(bytes[0], expect, "list 逐项编码应逐字节一致");
}

/// list 解析侧：注册 dns/dns_question 后，DNS 报文能按计数循环反解出嵌套子命中。
#[test]
fn dissect_parses_dns_questions_list() {
    // 与 quic dissect 测试共用注册（OnceLock 首次生效，须同一内容）
    register_quic("");
    // 手工构造 DNS 报文（udp 53）：1 个 question
    let mut dns_bytes = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    dns_bytes.extend_from_slice(&[
        3, b'w', b'w', b'w', 5, b'b', b'a', b'i', b'd', b'u', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ]);
    let full = format!(
        "q = raw(bytes=hex(\"{}\"))\nfull = use(q) |> udp(sport=5353, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=17) |> eth()\nexport:\n- full\n",
        dns_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let m2 = semantic::parse_str("t", &full).unwrap();
    let pkt = packet_dsl::resolve(&m2)
        .unwrap()
        .packets
        .into_iter()
        .next()
        .unwrap();
    let bytes = DefaultSerializer::with_seed(1).serialize(&pkt).unwrap();
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "dns");
    assert!(hit.is_some(), "udp 53 应命中 dns proto：{r:?}");
    let hit = hit.unwrap();
    let qd = hit
        .fields
        .iter()
        .find(|(n, _)| n == "qdcount")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert_eq!(qd, packet_dsl::ProtoVal::Int(1), "qdcount 反解");
    assert_eq!(hit.subs.len(), 1, "list 应反解出 1 个 question 子命中");
    let q = &hit.subs[0];
    assert_eq!(q.name, "dns_question");
    let name = q
        .fields
        .iter()
        .find(|(n, _)| n == "name")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert_eq!(
        name,
        packet_dsl::ProtoVal::Str("www.baidu.com".to_string()),
        "DnsName 标签序列还原为点分名字（压缩指针追跳同此）"
    );
}

/// len 计算字段的 expr 变换：TCP data_offset 联动（data offset = 5 + options/4，<<4 编码）。
#[test]
fn proto_auto_expr_tcp_data_offset() {
    let src = r#"
#[proto(kind="tcp")]
func tcp(sport=1, dport=2, options="") -> bytes {
    concat(
        be16(sport), be16(dport),
        #[meta(name="data_offset", len="auto", expr="shl(div(len, 4) + 5, 4)")] u8(0x50),
        #[meta(len="auto")] be16(checksum),
        #[meta(bytes="sub(mul(shr(data_offset, 4), 4), 20)")] options
    )
}
p = tcp(options="abcd")
export:
- p
"#;
    let bytes = serialize_all(&build_packets(src));
    // 声明字段：sport(2) dport(2) data_offset(1) checksum(2) options(4) = 11 字节
    // options 4 字节 → data offset = 5 + 4/4 = 6 → 0x60（u8 高 4 位）
    assert_eq!(bytes[0][4], 0x60, "data_offset 应为 6<<4");
    assert_eq!(bytes[0].len(), 11, "7B 定长 + 4B options");
    assert_eq!(&bytes[0][7..], b"abcd");
}

// ── bits（位字段，`#[meta(bits=N)]` u8 字段）──

/// bits 测试源码：version(4)+ihl(4) 凑一字节 + 后续普通字段；2+6 位宽组；1+7 位宽组。
const BITS_SRC: &str = r#"
#[proto]
func bits_pkt(ihl=5, a=0) -> bytes {
    concat(
        #[meta(name="version", bits=4)] u8(4),
        #[meta(name="ihl", bits=4)] u8(ihl),
        u8(a)
    )
}
#[proto]
func bits_wide(p=0, q=0) -> bytes {
    concat(
        #[meta(name="p", bits=2)] u8(p),
        #[meta(name="q", bits=6)] u8(q)
    )
}
#[proto]
func bits_flag(f=0, g=0) -> bytes {
    concat(
        #[meta(name="f", bits=1)] u8(f),
        #[meta(name="g", bits=7)] u8(g)
    )
}
"#;

/// 从源码构造 ResolvedProto 列表（parse_proto 直接反解用，不依赖全局注册表）。
fn resolve_protos(src: &str) -> Vec<packet_dsl::ResolvedProto> {
    let m = semantic::parse_str("t", src).unwrap();
    m.protos
        .iter()
        .map(|p| packet_dsl::ResolvedProto {
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
        })
        .collect()
}

/// proto 命中里取整数字段。
fn field_int(hit: &packet_dsl::ProtoHit, name: &str) -> Option<i64> {
    hit.fields
        .iter()
        .find(|(n, _)| n == name)
        .and_then(|(_, v)| v.as_int())
}

/// bits 构造打包（version+ihl = 0x45）与解析拆分（含常量校验）对称。
#[test]
fn proto_bits_pack_and_unpack() {
    // 构造：version(4 字面量)+ihl(4) 打包为首字节 0x45，a 跟随
    let src = format!("{BITS_SRC}full = bits_pkt(ihl=5, a=0x10)\nexport:\n- full\n");
    let bytes = serialize_all(&build_packets(&src));
    assert_eq!(bytes[0], vec![0x45, 0x10], "version(4)+ihl(4) 应为 0x45");
    // 构造 ihl=6（带选项的头）
    let src = format!("{BITS_SRC}full = bits_pkt(ihl=6, a=0x20)\nexport:\n- full\n");
    let bytes = serialize_all(&build_packets(&src));
    assert_eq!(bytes[0], vec![0x46, 0x20], "ihl=6 → 首字节 0x46");

    // 解析（parse_proto 直接反解）
    let resolved = resolve_protos(BITS_SRC);
    let hit = packet_dsl::parse_proto(&resolved[0], &[0x45, 0x10]).expect("应反解");
    assert_eq!(hit.name, "bits_pkt");
    assert_eq!(field_int(&hit, "version"), Some(4));
    assert_eq!(field_int(&hit, "ihl"), Some(5));
    assert_eq!(field_int(&hit, "a"), Some(0x10));
    let hit = packet_dsl::parse_proto(&resolved[0], &[0x46, 0x20]).expect("ihl=6 应反解");
    assert_eq!(field_int(&hit, "version"), Some(4));
    assert_eq!(field_int(&hit, "ihl"), Some(6));
    // 常量校验：version 字段默认是字面量 4 → 非 4 的包解析失败
    assert!(
        packet_dsl::parse_proto(&resolved[0], &[0x55, 0x00]).is_none(),
        "version=5 应触发常量校验失败"
    );
}

/// 位组内不同位宽组合（2+6 / 1+7）的打包与拆分。
#[test]
fn proto_bits_wide_group() {
    let src = format!("{BITS_SRC}full = bits_wide(p=2, q=3)\nexport:\n- full\n");
    let bytes = serialize_all(&build_packets(&src));
    assert_eq!(bytes[0], vec![0x83], "p(2 位高)=2, q(6 位低)=3 → 0x83");
    let src = format!("{BITS_SRC}full = bits_flag(f=1, g=1)\nexport:\n- full\n");
    let bytes = serialize_all(&build_packets(&src));
    assert_eq!(bytes[0], vec![0x81], "f(1 位)=1, g(7 位)=1 → 0x81");

    let resolved = resolve_protos(BITS_SRC);
    let hit = packet_dsl::parse_proto(&resolved[1], &[0x83]).expect("2+6 位应反解");
    assert_eq!(field_int(&hit, "p"), Some(2));
    assert_eq!(field_int(&hit, "q"), Some(3));
    let hit = packet_dsl::parse_proto(&resolved[2], &[0x81]).expect("1+7 位应反解");
    assert_eq!(field_int(&hit, "f"), Some(1));
    assert_eq!(field_int(&hit, "g"), Some(1));
}

/// bits 错误路径：值超位宽（构造期）、位组不对齐（语义期）、位宽越界、只配 u8。
#[test]
fn proto_bits_errors() {
    // 值超出位宽（构造期校验）：ihl 是 4 位字段，16 超范围
    let src = format!("{BITS_SRC}full = bits_pkt(ihl=16)\nexport:\n- full\n");
    let m = semantic::parse_str("t", &src).unwrap();
    let e = packet_dsl::resolve(&m).unwrap_err();
    assert!(e.to_string().contains("超出 4 位"), "{e}");
    // 2 位字段值 4 也超范围
    let src = format!("{BITS_SRC}full = bits_wide(p=4)\nexport:\n- full\n");
    let m = semantic::parse_str("t", &src).unwrap();
    let e = packet_dsl::resolve(&m).unwrap_err();
    assert!(e.to_string().contains("超出 2 位"), "{e}");
    // 位组不对齐：4 位组后直接普通字段（语义期校验）
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func bad(a=1, b=2) -> bytes {
    concat(
        #[meta(name="a", bits=4)] u8(a),
        u8(b)
    )
}
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("不是 8 的倍数"), "{e}");
    // 位宽越界（1..=8）
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func bad2(a=1) -> bytes {
    concat(#[meta(name="a", bits=9)] u8(a))
}
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("1..=8"), "{e}");
    // bits 只配 u8 字段
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func bad3(a=1) -> bytes {
    concat(#[meta(name="a", bits=4)] be16(a))
}
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("只用于 u8"), "{e}");
    // bits 字段不能是 len 计算字段（len="auto"/len="目标"）
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func bad4(a=1) -> bytes {
    concat(#[meta(name="a", len="auto", bits=4)] u8(a))
}
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("不能同时是 len 计算字段"), "{e}");
}

// ── vint codec（变长整数数据化：le128 / prefix / table 三模型）──

/// 构建 proto 出字节，并用**同一声明**反解（构造/解析共用一份声明的 roundtrip）。
/// 返回 (序列化字节, 解析命中)。
fn vint_roundtrip(src: &str, proto_name: &str) -> (Vec<u8>, packet_dsl::ProtoHit) {
    let m = semantic::parse_str("t", src).expect("解析失败");
    let p = m
        .protos
        .iter()
        .find(|p| p.name == proto_name)
        .expect("proto 存在");
    let resolved = packet_dsl::ResolvedProto {
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
    };
    let bytes = serialize_all(&build_packets(src))[0].clone();
    let hit = packet_dsl::parse_proto(&resolved, &bytes).expect("应能反解");
    (bytes, hit)
}

/// 取 ProtoHit 的整数字段值。
fn hit_int(hit: &packet_dsl::ProtoHit, name: &str) -> i64 {
    hit.fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| match v {
            packet_dsl::ProtoVal::Int(i) => *i,
            other => panic!("字段 {name} 应为 Int，得到 {other:?}"),
        })
        .expect("字段存在")
}

/// `#[meta(codec="le128")] n`：续延位模型（protobuf base-128），编码 + 反解。
/// 与值原语 `varint(n)` 期望字节一致（构造字节 [0xAC, 0x02]）。
#[test]
fn vint_le128_meta_roundtrip() {
    let meta = r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="le128")] n) }
p = v(n=300)
export:
- p
"#;
    let (bytes, hit) = vint_roundtrip(meta, "v");
    // 300 = 0b10_0101100 → [0xAC, 0x02]
    assert_eq!(bytes, vec![0xAC, 0x02], "le128 编码");
    assert_eq!(hit_int(&hit, "n"), 300, "le128 反解");
}

/// `#[meta(codec="prefix", prefix_bits=2, widths=[1,2,4,8])]`：QUIC 前缀宽度表
/// （RFC 9000 §16），编码 + 反解；含大值（8 字节档）。
#[test]
fn vint_prefix_meta_roundtrip() {
    let meta = r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="prefix", prefix_bits=2, widths=[1,2,4,8])] n) }
p = v(n=4611686018427387903)
export:
- p
"#;
    let (bytes, hit) = vint_roundtrip(meta, "v");
    assert_eq!(bytes.len(), 8, "2^62-1 走 8 字节档");
    assert_eq!(hit_int(&hit, "n"), 4611686018427387903, "prefix 反解");
}

/// prefix 自定义方案（prefix_bits=1，宽度表 [1,2]）：1 位前缀，0/1 档。
#[test]
fn vint_prefix_custom_roundtrip() {
    let src = r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="prefix", prefix_bits=1, widths=[1,2])] n) }
p = v(n=128)
export:
- p
"#;
    let (bytes, hit) = vint_roundtrip(src, "v");
    // n=128 ≥ 2^7 → 1 档（2 字节）：前缀 1 + 15 位值 0x8080
    assert_eq!(bytes, vec![0x80, 0x80], "prefix_bits=1 档 2 字节");
    assert_eq!(hit_int(&hit, "n"), 128);
    // 127 < 2^7 → 0 档（1 字节）
    let src2 = src.replace("n=128", "n=127");
    let (bytes2, hit2) = vint_roundtrip(&src2, "v");
    assert_eq!(bytes2, vec![0x7F], "prefix_bits=1 档 1 字节");
    assert_eq!(hit_int(&hit2, "n"), 127);
}

/// table LE（Bitcoin varint）：inline_max=0xFC + 哨兵 0xFD/0xFE/0xFF → 2/4/8 字节
/// **小端**值；值 ≤ inline_max 直接 1 字节内联。
#[test]
fn vint_table_bitcoin_le_roundtrip() {
    let src = r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="table", inline_max=0xFC, sentinels=[0xFD,0xFE,0xFF], widths=[2,4,8], endian="le")] n) }
p = v(n=0x100)
export:
- p
"#;
    // 256 > 0xFC → 0xFD 哨兵 + 2 字节小端 0x00 0x01
    let (bytes, hit) = vint_roundtrip(src, "v");
    assert_eq!(bytes, vec![0xFD, 0x00, 0x01], "Bitcoin 2 字节档小端");
    assert_eq!(hit_int(&hit, "n"), 0x100);
    // 内联档：0xFC 直接 1 字节
    let src2 = src.replace("n=0x100", "n=0xFC");
    let (bytes2, hit2) = vint_roundtrip(&src2, "v");
    assert_eq!(bytes2, vec![0xFC], "内联档 1 字节");
    assert_eq!(hit_int(&hit2, "n"), 0xFC);
    // 4 字节档：0x10000 → 0xFE + 4 字节小端
    let src3 = src.replace("n=0x100", "n=0x10000");
    let (bytes3, hit3) = vint_roundtrip(&src3, "v");
    assert_eq!(
        bytes3,
        vec![0xFE, 0x00, 0x00, 0x01, 0x00],
        "Bitcoin 4 字节档"
    );
    assert_eq!(hit_int(&hit3, "n"), 0x10000);
}

/// table BE（CBOR 长度编码）：inline_max=0x17 + 哨兵 0x18/0x19/0x1A/0x1B →
/// 1/2/4/8 字节**大端**值。
#[test]
fn vint_table_cbor_be_roundtrip() {
    let src = r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="table", inline_max=0x17, sentinels=[0x18,0x19,0x1A,0x1B], widths=[1,2,4,8])] n) }
p = v(n=0x100)
export:
- p
"#;
    // 256 > 0x17 → 0x19 哨兵 + 2 字节大端 0x01 0x00
    let (bytes, hit) = vint_roundtrip(src, "v");
    assert_eq!(bytes, vec![0x19, 0x01, 0x00], "CBOR 2 字节档大端");
    assert_eq!(hit_int(&hit, "n"), 0x100);
    // 内联档 + 1 字节档：0x18 → 0x18 哨兵 + 1 字节 0x18
    let src2 = src.replace("n=0x100", "n=0x18");
    let (bytes2, hit2) = vint_roundtrip(&src2, "v");
    assert_eq!(bytes2, vec![0x18, 0x18], "CBOR 1 字节档");
    assert_eq!(hit_int(&hit2, "n"), 0x18);
}

/// vint 可作 @auto/@len 字段（值 = 引擎算出的字节数，用自身方案编码）——
/// 与既有 qvarint 用法同构，验证自定义方案走自动字段路径。
#[test]
fn vint_auto_field_with_table_codec() {
    let src = r#"
#[proto]
func v(body="") -> bytes {
    concat(
        #[meta(len="auto", codec="prefix", prefix_bits=1, widths=[1,2])] length,
        #[meta(rest)] body
    )
}
p = v(body="abcd")
export:
- p
"#;
    let (bytes, hit) = vint_roundtrip(src, "v");
    // body 4 字节 → length = 4 < 2^7 → 0 档 1 字节 0x04
    assert_eq!(bytes, vec![0x04, b'a', b'b', b'c', b'd']);
    assert_eq!(hit_int(&hit, "length"), 4, "@auto 用自身方案编码");
}

/// vint codec 错误路径：参数缺省/冲突/非法组合。
#[test]
fn vint_codec_error_paths() {
    // 未知 codec 名
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="foo")] n) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("未知 codec"), "{e}");
    // prefix 缺 prefix_bits
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="prefix", widths=[1,2])] n) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("prefix_bits"), "{e}");
    // prefix 表长度 ≠ 2^prefix_bits（语义期）
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="prefix", prefix_bits=2, widths=[1,2,4])] n) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("2^prefix_bits"), "{e}");
    // prefix 宽度非严格递增
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="prefix", prefix_bits=2, widths=[1,4,2,8])] n) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("严格递增"), "{e}");
    // table 哨兵 ≤ inline_max（解码歧义）
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="table", inline_max=0xFC, sentinels=[0xFC,0xFE,0xFF], widths=[2,4,8])] n) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("大于 inline_max"), "{e}");
    // table 哨兵重复
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="table", inline_max=0xFC, sentinels=[0xFD,0xFD,0xFF], widths=[2,4,8])] n) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("重复"), "{e}");
    // table 哨兵/宽度表长度不一致
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="table", inline_max=0xFC, sentinels=[0xFD,0xFE], widths=[2,4,8])] n) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("长度不一致"), "{e}");
    // le128 带附加参数
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="le128", prefix_bits=2)] n) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("不接受"), "{e}");
    // 字段位置 varint/qvarint 糖已移除：作为字段类型调用报错（提示用 codec meta）
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(varint(n)) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("不是字段类型"), "{e}");
    assert!(e.to_string().contains("codec"), "{e}");
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(qvarint(n)) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("不是字段类型"), "{e}");
    // 裸标识符 vint 无 codec
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(n) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("codec"), "{e}");
    // endian 非法值
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="table", inline_max=0xFC, sentinels=[0xFD], widths=[2], endian="middle")] n) }
"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("be"), "{e}");
    // 构造侧范围越界（prefix 8 字节档上限 2^62-1）
    let e = semantic::parse_str(
        "t",
        r#"
#[proto]
func v(n=0) -> bytes { concat(#[meta(codec="prefix", prefix_bits=2, widths=[1,2,4,8])] n) }
p = v(n=4611686018427387904)
export:
- p
"#,
    )
    .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
    .unwrap_err();
    assert!(e.to_string().contains("超出"), "{e}");
}

/// be64/le64 字段类型：8 字节大端/小端编码（与值原语同宽；i64::MAX 封顶）——
/// 回归锁定 `encode_field_type` 的端序（此前 `_` 分支把 be64 也当小端）。
#[test]
fn proto_be64_le64_fields() {
    // be64 大端：字段值 0x0102030405060708 → 8 字节原序
    let pkts = build_packets(
        r#"
#[proto]
func be64p(v=0) -> bytes { concat(be64(v)) }
p = be64p(v=0x0102030405060708)
export:
- p
"#,
    );
    let b = serialize_all(&pkts);
    assert_eq!(
        b[0],
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        "be64 字段大端"
    );
    // le64 小端：低字节在前
    let pkts = build_packets(
        r#"
#[proto]
func le64p(v=0) -> bytes { concat(le64(v)) }
p = le64p(v=0x0102030405060708)
export:
- p
"#,
    );
    let b = serialize_all(&pkts);
    assert_eq!(
        b[0],
        vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        "le64 字段小端"
    );
}
