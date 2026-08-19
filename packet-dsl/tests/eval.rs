//! 求值测试：use 展开、层位笛卡尔积变体、包组逐包包裹、组件循环检测。

mod common;

use packet_dsl::ir::Layer;
use packet_dsl::semantic::parse_file;

fn layers_of(src: &str) -> Vec<Vec<Layer>> {
    let m = packet_dsl::semantic::parse_str("t", src).expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    built.packets.into_iter().map(|p| p.layers).collect()
}

fn layer_name(l: &Layer) -> &'static str {
    match l {
        Layer::Ethernet(_) => "eth",
        Layer::Arp(_) => "arp",
        Layer::Ipv4(_) => "ipv4",
        Layer::Ipv6(_) => "ipv6",
        Layer::Icmp(_) => "icmp",
        Layer::Tcp(_) => "tcp",
        Layer::Udp(_) => "udp",
        Layer::Http(_) => "http",
        Layer::Dns(_) => "dns",
        Layer::Raw(_) => "raw",
    }
}

fn names(p: &[Layer]) -> Vec<&'static str> {
    p.iter().map(layer_name).collect()
}

/// 多载荷 × 多协议：等价展开（原 `||>` 变体展开改为多条流水线）。
#[test]
fn multi_component_multi_transport_pipelines() {
    let built = layers_of(
        "a = http(method=\"GET\")\nb = http(method=\"POST\")\ntcp_full = use(a, b) |> tcp(dport=80)\nudp_full = use(a, b) |> udp(dport=80)\nexport:\n- tcp_full\n- udp_full\n",
    );
    assert_eq!(built.len(), 4, "期望 4 个包");
    assert_eq!(names(&built[0]), vec!["http", "tcp"]);
    assert_eq!(names(&built[1]), vec!["http", "tcp"]);
    assert_eq!(names(&built[2]), vec!["http", "udp"]);
    assert_eq!(names(&built[3]), vec!["http", "udp"]);
}

/// 多个 use 元件 × 单层包裹 → 每个元件独立成包。
#[test]
fn use_components_expand() {
    let built = layers_of("a = http()\nb = dns()\nuse(a, b) |> tcp(dport=80)\n");
    assert_eq!(built.len(), 2);
    assert_eq!(names(&built[0]), vec!["http", "tcp"]);
    assert_eq!(names(&built[1]), vec!["dns", "tcp"]);
}

/// 决策 #4：包组被 use 时逐包包裹。
#[test]
fn group_use_wraps_each_packet() {
    let built = layers_of("a = http()\nfull = use(a) |> tcp\nuse(full) |> ipv4\n");
    assert_eq!(built.len(), 1);
    assert_eq!(names(&built[0]), vec!["http", "tcp", "ipv4"]);
}

/// use 空参数 → 语法错误。
#[test]
fn use_requires_names() {
    let err = packet_dsl::semantic::parse_str("t", "use() |> tcp()\n").unwrap_err();
    assert!(err.message.contains("期望"), "{}", err.message);
}

/// 组件循环引用 → 求值报错。
#[test]
fn component_cycle_is_error() {
    let m = packet_dsl::semantic::parse_str(
        "t",
        "a = use(b) |> tcp()\nb = use(a) |> udp()\nexport:\n- a\n",
    )
    .expect("解析成功");
    let err = packet_dsl::resolve(&m).unwrap_err();
    assert!(err.message.contains("循环元件引用"), "{}", err.message);
}

/// 默认导出 + 命名导出都进入结果。
#[test]
fn resolve_includes_default_and_named_exports() {
    let m =
        packet_dsl::semantic::parse_str("t", "a = http()\nuse(a) |> tcp(dport=80)\nexport:\n- a\n")
            .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    // 默认导出 1 个（http,tcp）+ 命名导出 a 1 个（http）
    assert_eq!(built.packets.len(), 2);
    assert_eq!(names(&built.packets[0].layers), vec!["http", "tcp"]);
    assert_eq!(names(&built.packets[1].layers), vec!["http"]);
}

/// 层位引用用户元件（跨文件）参与笛卡尔积。
#[test]
fn slot_references_imported_component() {
    let dir = common::TempDir::new("slot-import");
    dir.write(
        "a.pkt",
        "export:\n- h\nh = http(method=\"GET\", path=\"/\")\n",
    );
    let b = dir.write("b.pkt", "import a { h }\nuse(h) |> tcp(dport=80)\n");
    let m = parse_file(b).expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 1);
    assert_eq!(names(&built.packets[0].layers), vec!["http", "tcp"]);
}

/// tcp 参数被正确带到 IR。
#[test]
fn tcp_args_reach_ir() {
    // headers.tcp 由 hex/raw+原语构建：参数落入字节（sport/dport/flags/window）
    let built = layers_of("a = raw()\nuse(a) |> tcp(dport=80, sport=12345, flags=\"syn,ack\")\n");
    assert!(matches!(built[0][1], Layer::Tcp(_)), "期望 tcp 层");
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&packet_dsl::ir::PacketSpec {
            layers: built[0].clone(),
        })
        .unwrap();
    assert_eq!(&bytes[0..2], &[0x30, 0x39], "sport=12345");
    assert_eq!(&bytes[2..4], &[0x00, 0x50], "dport=80");
    assert_eq!(bytes[13], 0x12, "flags syn+ack");
}

/// 命名参数后跟位置参数 → 报错。
#[test]
fn positional_after_named_is_error() {
    let m =
        packet_dsl::semantic::parse_str("t", "a = raw()\nuse(a) |> tcp(dport=80, 81)\n").unwrap();
    let err = packet_dsl::resolve(&m).unwrap_err();
    assert!(err.message.contains("位置参数"), "{}", err.message);
}

/// 未知参数 → 报错。
#[test]
fn unknown_arg_is_error() {
    let m = packet_dsl::semantic::parse_str("t", "a = raw()\nuse(a) |> tcp(nope=1)\n").unwrap();
    let err = packet_dsl::resolve(&m).unwrap_err();
    assert!(err.message.contains("没有参数"), "{}", err.message);
}

/// 类型错误 → 报错。
#[test]
fn wrong_arg_type_is_error() {
    // 字符串数字可 parse（与 --params 一致）；非数字字符串报错
    let m =
        packet_dsl::semantic::parse_str("t", "a = raw()\nuse(a) |> tcp(dport=\"abc\")\n").unwrap();
    let err = packet_dsl::resolve(&m).unwrap_err();
    assert!(err.message.contains("需要整数"), "{}", err.message);
}

// ── 运行时参数（params("name")）──────────────────────────────

use packet_dsl::semantic::parse_str;
use packet_dsl::{Params, Serializer};

fn resolve_with(src: &str, params: &[(&str, &str)]) -> Vec<packet_dsl::ir::PacketSpec> {
    let m = parse_str("t", src).expect("解析成功");
    let p: Params = params
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let built = packet_dsl::resolve_with_params(&m, &p).expect("求值成功");
    built.packets
}

/// 参数注入端口：`dport=params("port")`。
#[test]
fn params_fill_port() {
    let pkts = resolve_with(
        "a = http()\nuse(a) |> udp(dport=params(\"port\")) |> ipv4() |> eth()\n",
        &[("port", "5353")],
    );
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&pkts[0])
        .unwrap();
    // eth(14) + ipv4(20) 后是 udp 头：dport offset 2-3 = 5353
    let udp_off = 14 + 20;
    assert_eq!(
        &bytes[udp_off + 2..udp_off + 4],
        &[0x14, 0xE9],
        "dport=5353"
    );
}

/// 字符串参数：method=params("method")。
#[test]
fn params_fill_string() {
    let pkts = resolve_with(
        "a = http(method=params(\"method\"), path=params(\"path\", \"/default\"))\nuse(a) |> tcp()\n",
        &[("method", "POST")],
    );
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&pkts[0])
        .unwrap();
    assert!(
        bytes.windows(5).any(|w| w == b"POST "),
        "method=POST 应进入字节：{:02x?}",
        &bytes
    );
    // 未传 path → 用默认值 /default
    assert!(
        bytes.windows(8).any(|w| w == b"/default"),
        "默认 path=/default 应进入字节"
    );
}

/// 缺失参数且无默认值 → 报错。
#[test]
fn params_missing_is_error() {
    let m = parse_str(
        "t",
        "a = http()\nuse(a) |> udp(dport=params(\"port\")) |> ipv4() |> eth()\n",
    )
    .expect("解析成功");
    let err = packet_dsl::resolve_with_params(&m, &Params::new()).unwrap_err();
    assert!(err.message.contains("未提供"), "{}", err.message);
}

/// 参数用于地址字段。
#[test]
fn params_fill_ip() {
    let pkts = resolve_with(
        "a = raw(bytes=\"x\")\nuse(a) |> udp(dport=53) |> ipv4(dst=params(\"dst\")) |> eth()\n",
        &[("dst", "8.8.8.8")],
    );
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&pkts[0])
        .unwrap();
    // eth(14) 后 ipv4 头 dst offset 16-19
    assert_eq!(&bytes[14 + 16..14 + 20], &[8, 8, 8, 8], "dst=8.8.8.8");
}

/// 参数值类型错误 → 报错（端口不是整数）。
#[test]
fn params_wrong_type_is_error() {
    let m =
        parse_str("t", "a = http()\nuse(a) |> udp(dport=params(\"port\"))\n").expect("解析成功");
    let p: Params = [("port".to_string(), "not-a-port".to_string())].into();
    let err = packet_dsl::resolve_with_params(&m, &p).unwrap_err();
    assert!(err.message.contains("需要整数"), "{}", err.message);
}

// ── 显式随机字段（"random"）与组合函数 net4/net6 ──────────────
//
// net4/net6 已从内置迁移为 pkglang 模块（examples/net.pkt）；测试把函数定义内联进
// 源码（parse_str 不支持 import 文件），同时作为函数特性的求值测试。

const NET4_FUNC: &str = "\
func net4(dst, src=\"0.0.0.0\", ttl=64, id=0, proto, tos, flags, \
src_mac=\"00:00:00:00:00:00\", dst_mac=\"ff:ff:ff:ff:ff:ff\", ethertype=0x0800) {
    ipv4(src=src, dst=dst, ttl=ttl, proto=proto, tos=tos, id=id, flags=flags)\n\
        |> eth(src_mac=src_mac, dst_mac=dst_mac, ethertype=ethertype)\n\
}\n";

const NET6_FUNC: &str = "\
func net6(dst, src=\"::\", hop_limit=64, next_header, \
src_mac=\"00:00:00:00:00:00\", dst_mac=\"ff:ff:ff:ff:ff:ff\", ethertype=0x86dd) {
    ipv6(src=src, dst=dst, hop_limit=hop_limit, next_header=next_header)\n\
        |> eth(src_mac=src_mac, dst_mac=dst_mac, ethertype=ethertype)\n\
}\n";

/// Field::Random 序列化时随机化（headers 构建的层为字节直喂；随机由 rand 原语表达）。
#[test]
fn explicit_random_fields() {
    use packet_dsl::ir::*;
    let pkt = PacketSpec {
        layers: vec![
            Layer::Ipv4(Ipv4Fields {
                src: Field::Random,
                dst: Field::Value("8.8.8.8".parse().unwrap()),
                ttl: Field::Random,
                ..Default::default()
            }),
            Layer::Raw(RawData { bytes: vec![] }),
        ],
    };
    let b1 = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&pkt)
        .unwrap();
    let b2 = packet_dsl::DefaultSerializer::with_seed(2)
        .serialize(&pkt)
        .unwrap();
    assert_ne!(&b1[12..16], &b2[12..16], "src 随机");
    assert_ne!(&b1[8..9], &b2[8..9], "ttl 随机");
    assert_eq!(&b1[16..20], &[8, 8, 8, 8], "dst 保留");
}

/// 随机字段序列化：固定种子确定性、随机值合法（单播源 / TTL 1..=255）。
#[test]
fn random_fields_serialize_valid() {
    use packet_dsl::ir::*;
    let pkt = PacketSpec {
        layers: vec![
            Layer::Raw(RawData {
                bytes: b"x".to_vec(),
            }),
            Layer::Ipv4(Ipv4Fields {
                src: Field::Random,
                dst: Field::Value("8.8.8.8".parse().unwrap()),
                ttl: Field::Random,
                ..Default::default()
            }),
            Layer::Ethernet(EthernetFields {
                src_mac: Field::Auto,
                dst_mac: Field::Value("ff:ff:ff:ff:ff:ff".parse().unwrap()),
                ..Default::default()
            }),
        ],
    };
    let b1 = packet_dsl::DefaultSerializer::with_seed(42)
        .serialize(&pkt)
        .unwrap();
    let b2 = packet_dsl::DefaultSerializer::with_seed(42)
        .serialize(&pkt)
        .unwrap();
    assert_eq!(b1, b2, "同种子应确定性");
    // eth 头 14B 之后 IPv4：src(12..16) 首字节 1..=223，ttl 在 (14+8)
    let src = std::net::Ipv4Addr::new(b1[14 + 12], b1[14 + 13], b1[14 + 14], b1[14 + 15]);
    assert!(
        (1..=223).contains(&src.octets()[0]),
        "随机源应为单播：{src}"
    );
    let ttl = b1[14 + 8];
    assert!((1..=255).contains(&ttl), "TTL 应随机 1..=255：{ttl}");
    let b3 = packet_dsl::DefaultSerializer::with_seed(7)
        .serialize(&pkt)
        .unwrap();
    assert_ne!(b1, b3);
}

/// net4：一次生成 ipv4+eth；默认 src 随机、src_mac 随机、dst_mac 广播。
#[test]
fn net4_builds_ip_and_eth() {
    let pkts = layers_of(&format!(
        "{NET4_FUNC}a = raw(bytes=\"x\")\nuse(a) |> net4(dst=\"8.8.8.8\")\n"
    ));
    assert_eq!(names(&pkts[0]), vec!["raw", "ipv4", "eth"]);
    let Layer::Ipv4(ip) = &pkts[0][1] else {
        panic!()
    };
    assert_eq!(
        ip.dst,
        packet_dsl::ir::Field::Value("8.8.8.8".parse().unwrap())
    );
    // net4 经 headers.ipv4 字节构建：src 默认 0.0.0.0（随机由 rand 原语显式表达）
    assert_eq!(
        ip.src,
        packet_dsl::ir::Field::Value("0.0.0.0".parse().unwrap())
    );
}

/// net4 全显式 → 字节与手写 ipv4+eth 完全一致（确定性 golden）。
#[test]
fn net4_explicit_equals_manual_stack() {
    fn resolve_one(src: &str) -> packet_dsl::ir::PacketSpec {
        let m = parse_str("t", src).unwrap();
        packet_dsl::resolve(&m)
            .unwrap()
            .packets
            .into_iter()
            .next()
            .unwrap()
    }
    let manual = resolve_one(
        "a = raw(bytes=\"x\")\nuse(a) |> ipv4(src=\"1.2.3.4\", dst=\"5.6.7.8\", ttl=32, id=0) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\")\n",
    );
    let combo = resolve_one(&format!(
        "{NET4_FUNC}a = raw(bytes=\"x\")\nuse(a) |> net4(src=\"1.2.3.4\", dst=\"5.6.7.8\", ttl=32, id=0, src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\")\n"
    ));
    let b1 = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&manual)
        .unwrap();
    let b2 = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&combo)
        .unwrap();
    assert_eq!(b1, b2, "net4 显式参数应与手写栈字节一致");
}

/// net6：默认 src 随机、hop_limit 64、ethertype 0x86dd。
#[test]
fn net6_builds_ipv6_and_eth() {
    let src = format!("{NET6_FUNC}a = raw(bytes=\"x\")\nuse(a) |> net6(dst=\"2001:db8::1\")\n");
    let pkts = layers_of(&src);
    assert_eq!(names(&pkts[0]), vec!["raw", "ipv6", "eth"]);
    let Layer::Ipv6(ip) = &pkts[0][1] else {
        panic!()
    };
    assert_eq!(ip.src, packet_dsl::ir::Field::Value("::".parse().unwrap()));
    let m = parse_str("t", &src).unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let ser = packet_dsl::DefaultSerializer::with_seed(9);
    let bytes = ser.serialize(&built.packets[0]).unwrap();
    // ethertype 0x86dd，IPv6 版本 6，hop_limit 64
    assert_eq!(&bytes[12..14], &[0x86, 0xdd]);
    assert_eq!(bytes[14] >> 4, 6);
    assert_eq!(bytes[14 + 7], 64);
}

/// 独立 one's complement checksum。
fn ref_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut it = data.chunks_exact(2);
    for c in &mut it {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let &[b] = it.remainder() {
        sum += (b as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// 随机源下 TCP 伪头部与 IP 头一致（checksum 用包里实际源地址复核）。
#[test]
fn random_src_pseudo_header_consistent() {
    // 随机源（Field::Random）下 TCP 伪头部与 IP 头实际源地址一致（序列化器行为）
    use packet_dsl::ir::*;
    let pkt = PacketSpec {
        layers: vec![
            Layer::Http(HttpFields {
                method: Some("GET".into()),
                ..Default::default()
            }),
            Layer::Tcp(TcpFields {
                src_port: Some(40000),
                dst_port: Some(80),
                seq: Some(1),
                ..Default::default()
            }),
            Layer::Ipv4(Ipv4Fields {
                src: Field::Random,
                dst: Field::Value("10.0.0.2".parse().unwrap()),
                ..Default::default()
            }),
            Layer::Ethernet(EthernetFields {
                ..Default::default()
            }),
        ],
    };
    let ser = packet_dsl::DefaultSerializer::with_seed(5);
    let bytes = ser.serialize(&pkt).unwrap();
    // 独立实现：用包里实际 src/dst 算 TCP checksum，应与字段一致
    let src = std::net::Ipv4Addr::new(
        bytes[14 + 12],
        bytes[14 + 13],
        bytes[14 + 14],
        bytes[14 + 15],
    );
    let dst = std::net::Ipv4Addr::new(
        bytes[14 + 16],
        bytes[14 + 17],
        bytes[14 + 18],
        bytes[14 + 19],
    );
    let proto = bytes[14 + 9];
    let total_len = u16::from_be_bytes([bytes[14 + 2], bytes[14 + 3]]) as usize;
    let seg = &bytes[14 + 20..14 + total_len];
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(proto);
    pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    let mut all = pseudo;
    let mut seg2 = seg.to_vec();
    seg2[16] = 0;
    seg2[17] = 0;
    all.extend_from_slice(&seg2);
    let sum = ref_checksum(&all);
    assert_eq!(
        sum,
        u16::from_be_bytes([seg[16], seg[17]]),
        "TCP checksum 应与随机源一致"
    );
}

// ── 函数（func）：参数绑定 / 默认值 / 未设省略 / 嵌套 ─────────

/// 函数调用：命名参数 + 默认值 + 未设省略（→ auto）。
#[test]
fn func_args_defaults_and_unset() {
    let src = "\
func wrap(dport, flags=\"syn\", window, ttl=64) {\n\
    tcp(dport=dport, flags=flags, window=window) |> ipv4(ttl=ttl)\n\
}\n\
a = raw(bytes=\"x\")\nuse(a) |> wrap(dport=443)\n";
    let pkts = layers_of(src);
    assert_eq!(names(&pkts[0]), vec!["raw", "tcp", "ipv4"]);
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&packet_dsl::ir::PacketSpec {
            layers: pkts[0].clone(),
        })
        .unwrap();
    // layers [raw,tcp,ipv4]：ipv4 头在最前，tcp 头在 offset 20
    let tcp_off = 20;
    assert_eq!(
        &bytes[tcp_off + 2..tcp_off + 4],
        &[0x01, 0xBB],
        "命名参数绑定 dport=443"
    );
    assert_eq!(bytes[tcp_off + 13], 0x02, "默认 flags=syn");
    assert_eq!(
        &bytes[tcp_off + 14..tcp_off + 16],
        &[0xFF, 0xFF],
        "未设 window → 默认 65535"
    );
    assert_eq!(bytes[8], 64, "默认 ttl=64（ipv4 头 offset 8）");
}

/// 函数调用：位置参数按声明顺序。
#[test]
fn func_positional_args() {
    let src = "\
func wrap(dport, sport=9999) { tcp(dport=dport, sport=sport) }\n\
p = raw(bytes=\"x\")\nuse(p) |> wrap(80)\n";
    let pkts = layers_of(src);
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&packet_dsl::ir::PacketSpec {
            layers: pkts[0].clone(),
        })
        .unwrap();
    // layers [raw,tcp]：tcp 头在 offset 0
    assert_eq!(&bytes[2..4], &[0x00, 0x50], "位置参数 dport=80");
    assert_eq!(&bytes[0..2], &[0x27, 0x0F], "默认值 sport=9999");
}

/// 函数体内再调用函数（嵌套）；多层展开。
#[test]
fn func_nested_calls() {
    let src = "\
func inner(dst) { ipv4(dst=dst) }\n\
func outer(dst) { inner(dst=dst) |> eth() }\n\
p = raw(bytes=\"x\")\nuse(p) |> outer(dst=\"1.2.3.4\")\n";
    let pkts = layers_of(src);
    assert_eq!(names(&pkts[0]), vec!["raw", "ipv4", "eth"]);
    let Layer::Ipv4(ip) = &pkts[0][1] else {
        panic!()
    };
    assert_eq!(
        ip.dst,
        packet_dsl::ir::Field::Value("1.2.3.4".parse().unwrap()),
        "参数穿透两层函数"
    );
}

/// 函数循环调用 → 循环元件引用报错。
#[test]
fn func_cycle_detected() {
    let src = "func a() { b() }\nfunc b() { a() }\nuse(a)\n";
    let m = packet_dsl::semantic::parse_str("t", src).unwrap();
    let err = packet_dsl::resolve(&m).unwrap_err();
    assert!(err.to_string().contains("循环元件引用"), "{}", err);
}

/// 未知参数 / 重复参数 / 位置参数过多。
#[test]
fn func_bad_calls() {
    let src = "func f(a) { tcp(dport=a) }\nuse(f) |> f(b=1)\n";
    let m = packet_dsl::semantic::parse_str("t", src).unwrap();
    let err = packet_dsl::resolve(&m).unwrap_err();
    assert!(err.to_string().contains("没有参数 `b`"), "{}", err);

    let src2 = "func f(a) { tcp(dport=a) }\nuse(f) |> f(a=1, a=2)\n";
    let m2 = packet_dsl::semantic::parse_str("t", src2).unwrap();
    let err2 = packet_dsl::resolve(&m2).unwrap_err();
    assert!(err2.to_string().contains("重复指定"), "{}", err2);

    let src3 = "func f(a) { tcp(dport=a) }\nuse(f) |> f(1, 2)\n";
    let m3 = packet_dsl::semantic::parse_str("t", src3).unwrap();
    let err3 = packet_dsl::resolve(&m3).unwrap_err();
    assert!(err3.to_string().contains("位置参数过多"), "{}", err3);
}

/// 元件（非函数）带参数调用 → 报错。
#[test]
fn def_rejects_args() {
    let src = "x = tcp(dport=80)\nuse(x) |> x(dport=443)\n";
    let m = packet_dsl::semantic::parse_str("t", src).unwrap();
    let err = packet_dsl::resolve(&m).unwrap_err();
    assert!(err.to_string().contains("不接受参数"), "{}", err);
}

/// 函数体可用 use（包组语义）：函数返回多包。
#[test]
fn func_body_with_use_expands_packets() {
    let src = "a = http(method=\"GET\")\nb = http(method=\"POST\")\nfunc wrap() { use(a, b) |> tcp(dport=80) }\nuse(wrap)\n";
    let built = layers_of(src);
    assert_eq!(built.len(), 2, "函数体 use(a,b) → 2 包");
    assert_eq!(names(&built[0]), vec!["http", "tcp"]);
    assert_eq!(names(&built[1]), vec!["http", "tcp"]);
}

/// 参数值可为 params() 引用（函数内再读运行时参数）。
#[test]
fn func_param_via_runtime_params() {
    let src = "func f(dport) { tcp(dport=dport) }\np = raw(bytes=\"x\")\nuse(p) |> f(dport=params(\"port\", \"53\"))\n";
    let mut params = packet_dsl::Params::new();
    params.insert("port".to_string(), "5353".to_string());
    let m = packet_dsl::semantic::parse_str("t", src).unwrap();
    let built = packet_dsl::resolve_with_params(&m, &params).unwrap();
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    assert_eq!(
        &bytes[2..4],
        &[0x14, 0xE9],
        "params 穿透函数参数 → dport=5353"
    );
}

// ── 层 bytes= 直喂（hex 头）─────────────────────────────────

/// ipv4_bytes(hex(...))：该层序列化字节 = 给定 hex + 载荷（绕过语义字段与自动校验和）。
#[test]
fn layer_bytes_passthrough() {
    let src = "p = raw(bytes=\"probe\")\nuse(p) |> ipv4_bytes(hex(\"4500001c00010000400100007f0000017f000001\"))\n";
    let m = parse_str("t", src).unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    // 载荷 "probe"(5B) 前应为 20B IPv4 头：调用方给定 hex + 引擎自动补 length/checksum
    assert_eq!(&bytes[..2], &[0x45, 0x00], "版本/IHL/TOS 保持给定");
    assert_eq!(&bytes[2..4], &[0x00, 0x19], "total_length 自动补 = 20+5");
    assert_eq!(&bytes[4..6], &[0x00, 0x01], "id 保持给定");
    assert_eq!(&bytes[8..10], &[0x40, 0x01], "TTL/proto 保持给定");
    // header checksum 自动补：对修正后的 20B 头校验和为 0
    let mut hdr = bytes[..20].to_vec();
    hdr[10] = 0;
    hdr[11] = 0;
    let mut sum = 0u32;
    let mut it = hdr.chunks_exact(2);
    for ch in &mut it {
        sum += u16::from_be_bytes([ch[0], ch[1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let expect = !(sum as u16);
    assert_eq!(
        u16::from_be_bytes([bytes[10], bytes[11]]),
        expect,
        "header checksum 自动补"
    );
    assert_eq!(&bytes[12..16], &[127, 0, 0, 1], "src 保持给定");
    assert_eq!(&bytes[20..], b"probe");
}

/// eth + ipv4 双字节直喂 → 完整帧 = eth 头 + ipv4 头 + 载荷。
#[test]
fn layer_bytes_full_stack() {
    let src = "p = raw(bytes=\"x\")\nuse(p) |> ipv4_bytes(hex(\"4500001c00010000400100007f0000017f000001\")) |> eth_bytes(hex(\"ffffffffffff0011223344550800\"))\n";
    let m = parse_str("t", src).unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    assert_eq!(bytes.len(), 14 + 20 + 1);
    assert_eq!(
        &bytes[..14],
        &[0xff; 6]
            .iter()
            .chain([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00].iter())
            .copied()
            .collect::<Vec<u8>>()[..]
    );
    assert_eq!(bytes[14], 0x45, "ipv4 头起始字节");
    assert_eq!(bytes[34], b'x');
}

/// bytes= 直喂的完整栈（eth+ipv4）可反解回语义层。
#[test]
fn layer_bytes_dissects_back() {
    let src = "p = raw(bytes=\"probe1234\")\nuse(p) |> ipv4_bytes(hex(\"4500001c00010000400100007f0000017f000001\")) |> eth_bytes(hex(\"ffffffffffff0011223344550800\"))\n";
    let m = parse_str("t", src).unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    let report = packet_dsl::dissect(&bytes);
    assert_eq!(report.layers.len(), 3, "eth+ipv4+raw: {:?}", report.layers);
    assert!(
        matches!(report.layers[1], packet_dsl::ir::Layer::Ipv4(_)),
        "中间应为 ipv4 层"
    );
}

// ── eng_lib headers（hex/raw + 原语构建层头）与内置字节一致 ──

/// eng_lib/headers.pkt 的 eth/ipv4/tcp（由 hex/raw+原语构建）与引擎内置
/// 层函数（同参数）序列化字节完全一致（含自动 length/checksum）。
#[test]
fn eng_lib_headers_match_builtin_bytes() {
    let dir = std::env::temp_dir().join(format!("pkt-hdrs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("headers.pkt"),
        include_str!("../../eng_lib/headers.pkt"),
    )
    .unwrap();

    // 内置版与 eng_lib 版各构建一次，字节必须一致
    let builtin_src = "p = raw(bytes=\"x\")\nuse(p) |> tcp(sport=40000, dport=80, seq=1) |> ipv4(src=\"1.2.3.4\", dst=\"5.6.7.8\", ttl=64, proto=6, id=0) |> eth(dst_mac=\"66:77:88:99:aa:bb\", src_mac=\"00:11:22:33:44:55\", ethertype=0x0800)\n";
    let englib_src = "p = raw(bytes=\"x\")\nuse(p) |> tcp(sport=40000, dport=80, seq=1) |> ipv4(src=\"1.2.3.4\", dst=\"5.6.7.8\", ttl=64, proto=6, id=0) |> eth(dst_mac=\"66:77:88:99:aa:bb\", src_mac=\"00:11:22:33:44:55\", ethertype=0x0800)\n";

    let b1 = {
        let m = parse_str("t", builtin_src).unwrap();
        let built = packet_dsl::resolve(&m).unwrap();
        packet_dsl::DefaultSerializer::with_seed(1)
            .serialize(&built.packets[0])
            .unwrap()
    };
    let b2 = {
        // main.pkt 与 headers.pkt 同目录：库搜索兜底（headers 导出隐式可见）
        let main = dir.join("main.pkt");
        std::fs::write(&main, englib_src).unwrap();
        let m =
            packet_dsl::semantic::parse_file_with_libs(&main, std::slice::from_ref(&dir)).unwrap();
        let built = packet_dsl::resolve(&m).unwrap();
        packet_dsl::DefaultSerializer::with_seed(1)
            .serialize(&built.packets[0])
            .unwrap()
    };
    assert_eq!(b1, b2, "eng_lib headers 与内置版字节必须一致");
    assert_eq!(b1.len(), 55);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 值函数 + reduce：HTTP 头行拼接与 DNS questions 编码。
#[test]
fn value_funcs_and_reduce() {
    let src = "\
func line(acc, item) -> bytes { concat(acc, bytes(item), bytes(\"\\r\\n\")) }\n\
p = raw(bytes=concat(reduce([\"Host: a\", \"UA: b\"], bytes(\"\"), line), dns_name(\"example.com\")))\n\
use(p)\n";
    let m = parse_str("t", src).unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    assert_eq!(
        &bytes[..16],
        b"Host: a\r\nUA: b\r\n",
        "reduce 应拼接 HTTP 行"
    );
    assert_eq!(
        &bytes[16..],
        &[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
        ],
        "dns_name 长度前缀编码"
    );
}

// ── sniffer 段 ─────────────────────────────────────────────

/// sniffer 块解析并携带进 Module（字面量 = 常量；Ident = 发包同层同名字段；多子句）。
#[test]
fn sniffer_block_parses_and_carries() {
    let src = "a = raw(bytes=\"x\")\nuse(a) |> icmp() |> ipv4() |> eth()\n\
sniffer:\n  - match icmp(type=0, id=id, seq=seq)\n  - match dns(id=id)\n";
    let m = packet_dsl::semantic::parse_str("t", src).unwrap();
    let sn = m.sniffer.expect("应有 sniffer");
    assert_eq!(sn.clauses.len(), 2, "多子句列表");
    let c0 = &sn.clauses[0];
    assert_eq!(c0.layer, "icmp");
    assert_eq!(c0.fields.len(), 3);
    assert!(
        matches!(
            &c0.fields[0],
            (n, packet_dsl::SnifferValue::Literal(packet_dsl::ast::Value::Int(0))) if n == "type"
        ),
        "type=0 应是常量：{:?}",
        c0.fields[0]
    );
    assert!(
        matches!(
            &c0.fields[1],
            (n, packet_dsl::SnifferValue::SentField(f)) if n == "id" && f == "id"
        ),
        "id=id 应是 sent 字段引用：{:?}",
        c0.fields[1]
    );
    assert_eq!(sn.clauses[1].layer, "dns", "第二个子句");
}

/// 一个文件只能有一个 sniffer 段。
#[test]
fn duplicate_sniffer_errors() {
    let src = "p = raw(bytes=\"x\")\nuse(p)\nsniffer:\n  - match icmp(type=0)\n\
sniffer:\n  - match icmp(type=0)\n";
    let err = packet_dsl::semantic::parse_str("t", src).unwrap_err();
    assert!(err.to_string().contains("只能有一个 sniffer"), "{err}");
}

/// mac()/ip4() 接受字节列表直通（rand_mac 风格随机 MAC；与值位置 hex 同一哲学）。
#[test]
fn mac_accepts_byte_list() {
    let src = "func rm() -> bytes { concat(u8(1), u8(2), u8(3), u8(4), u8(5), u8(6)) }\n\
p = raw(bytes=\"x\")\nuse(p) |> icmp() |> ipv4(src=\"1.2.3.4\", dst=\"5.6.7.8\") |> eth(src_mac=rm(), dst_mac=rm())\n";
    let m = packet_dsl::semantic::parse_str("t", src).unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    assert_eq!(&bytes[..6], &[1, 2, 3, 4, 5, 6], "dst_mac 字节列表直通");
    assert_eq!(&bytes[6..12], &[1, 2, 3, 4, 5, 6], "src_mac 字节列表直通");
}

/// mac() 对错误长度的字节列表不直通，按字符串解析并报错（不静默通过）。
#[test]
fn mac_rejects_wrong_length_list() {
    let src = "func bad() -> bytes { concat(u8(1), u8(2)) }\n\
p = raw(bytes=\"x\")\nuse(p) |> eth(src_mac=bad())\n";
    let err = packet_dsl::semantic::parse_str("t", src)
        .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("字符串") || msg.contains("MAC"),
        "应报参数类型错误：{msg}"
    );
}

// ── dns() 原语 / 地址字段域名解析 ──────────────────────────

/// dns() 值原语（v4 优先字符串）+ ip4/ip6 域名回退（宿主注入解析器）。
#[test]
fn dns_resolves_hostnames() {
    // 注入固定解析器（进程级，首个生效；仅域名用例用到）
    packet_dsl::set_dns_resolver(|host| match host {
        "example.com" => vec!["2001:db8::1".parse().unwrap(), "1.2.3.4".parse().unwrap()],
        _ => Vec::new(),
    });
    let build = |src: &str| {
        let m = packet_dsl::semantic::parse_str("t", src).unwrap();
        let built = packet_dsl::resolve(&m).unwrap();
        packet_dsl::DefaultSerializer::with_seed(1)
            .serialize(&built.packets[0])
            .unwrap()
    };
    // ipv4 地址字段直接写域名（经 ip4 + 字段元数据双路径解析，取首个 IPv4）
    let b = build(
        "p = raw(bytes=\"x\")\nuse(p) |> icmp() |> ipv4(src=\"1.1.1.1\", dst=\"example.com\") |> eth()\n",
    );
    assert_eq!(&b[14 + 16..14 + 20], &[1, 2, 3, 4], "ipv4 dst 域名解析");
    // dns("host") 值原语 → v4 优先字符串，流入 ip4
    let b = build(
        "p = raw(bytes=\"x\")\nuse(p) |> icmp() |> ipv4(src=\"1.1.1.1\", dst=dns(\"example.com\")) |> eth()\n",
    );
    assert_eq!(&b[14 + 16..14 + 20], &[1, 2, 3, 4], "dns() v4 优先");
    // ip6 域名 → 取首个 IPv6（2001:db8::1 → 偏移 14+24..14+40）
    let b = build(
        "p = raw(bytes=\"x\")\nuse(p) |> icmp(type=128) |> ipv6(src=\"::\", dst=\"example.com\") |> eth()\n",
    );
    let want: [u8; 16] = "2001:db8::1"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets();
    assert_eq!(&b[14 + 24..14 + 40], &want, "ipv6 dst 域名解析（AAAA）");
    // 无法解析 → 明确报错
    let err = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=\"x\")\nuse(p) |> icmp() |> ipv4(src=\"1.1.1.1\", dst=\"no-such-host.invalid\") |> eth()\n",
    )
    .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
    .unwrap_err();
    assert!(err.to_string().contains("无法解析"), "{err}");
}
