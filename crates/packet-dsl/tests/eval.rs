//! 求值测试：use 展开、层位笛卡尔积变体、包组逐包包裹、组件循环检测。

mod common;

use packet_dsl::ast::BinOp;
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
        "a = http(start_line=\"GET / HTTP/1.1\")\nb = http(start_line=\"POST / HTTP/1.1\")\ntcp_full = use(a, b) |> tcp(dport=80)\nudp_full = use(a, b) |> udp(dport=80)\nexport:\n- tcp_full\n- udp_full\n",
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
        "export:\n- h\nh = http(start_line=\"GET / HTTP/1.1\")\n",
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
    let built =
        layers_of("a = raw()\nuse(a) |> tcp(dport=80, sport=12345, flags=bor(syn(), ack()))\n");
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

/// 字符串参数：start_line=params("start_line")。
#[test]
fn params_fill_string() {
    let pkts = resolve_with(
        "a = http(start_line=params(\"start_line\", \"GET / HTTP/1.1\"))\nuse(a) |> tcp()\n",
        &[("start_line", "POST /api HTTP/1.1")],
    );
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&pkts[0])
        .unwrap();
    assert!(
        bytes.windows(5).any(|w| w == b"POST "),
        "start_line=POST 应进入字节：{:02x?}",
        bytes
    );
    // 未传 start_line → 用默认值 GET / HTTP/1.1
    let pkts = resolve_with("a = http()\nuse(a) |> tcp()\n", &[]);
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&pkts[0])
        .unwrap();
    assert!(
        bytes.windows(14).any(|w| w == b"GET / HTTP/1.1"),
        "默认 start_line 应进入字节：{:02x?}",
        bytes
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

// ── 配方全局（global("name")）────────────────────────────────

use packet_dsl::Globals;

fn resolve_with_globals(
    src: &str,
    globals: &[(&str, packet_dsl::ast::Value)],
) -> Vec<packet_dsl::ir::PacketSpec> {
    let m = parse_str("t", src).expect("解析成功");
    let g: Globals = globals
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    let built = packet_dsl::resolve_with_globals(&m, &Params::new(), &g).expect("求值成功");
    built.packets
}

/// 全局注入端口：`dport=global("port")`（类型化 Int，不经字符串形状解析）。
#[test]
fn global_fill_port() {
    let pkts = resolve_with_globals(
        "a = http()\nuse(a) |> udp(dport=global(\"port\")) |> ipv4() |> eth()\n",
        &[("port", packet_dsl::ast::Value::Int(5353))],
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

/// 全局值可直接参与运算：`ack=global("seq") + 1`（配方 extract 场景）。
#[test]
fn global_arithmetic() {
    let pkts = resolve_with_globals(
        "a = raw(bytes=\"x\")\nuse(a) |> tcp(seq=global(\"seq\") + 1) |> ipv4()\n",
        &[("seq", packet_dsl::ast::Value::Int(0x1234))],
    );
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&pkts[0])
        .unwrap();
    // ipv4(20) 后 tcp 头：seq offset 4-7 = 0x1235
    assert_eq!(&bytes[20 + 4..20 + 8], &[0x00, 0x00, 0x12, 0x35]);
}

/// 字节列表全局：`raw(bytes=global("data"))` 直喂载荷。
#[test]
fn global_bytes_list() {
    let pkts = resolve_with_globals(
        "a = raw(bytes=global(\"data\"))\nuse(a) |> udp(dport=53) |> ipv4()\n",
        &[(
            "data",
            packet_dsl::ast::Value::List(vec![
                packet_dsl::ast::Value::Hex(0xDE),
                packet_dsl::ast::Value::Hex(0xAD),
                packet_dsl::ast::Value::Hex(0xBE),
                packet_dsl::ast::Value::Hex(0xEF),
            ]),
        )],
    );
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&pkts[0])
        .unwrap();
    assert_eq!(&bytes[20 + 8..20 + 12], &[0xDE, 0xAD, 0xBE, 0xEF]);
}

/// 未设置且无默认 → 报错；默认值延迟求值（已设置时默认表达式不求值）。
#[test]
fn global_missing_is_error() {
    let m =
        parse_str("t", "a = http()\nuse(a) |> udp(dport=global(\"port\"))\n").expect("解析成功");
    let err = packet_dsl::resolve_with_globals(&m, &Params::new(), &Globals::new()).unwrap_err();
    assert!(err.message.contains("未设置"), "{}", err.message);
}

/// 默认值：`global("port", 5353)`——未注入时用默认（与 params 一致）。
#[test]
fn global_default_value() {
    let pkts = resolve_with_globals(
        "a = http()\nuse(a) |> udp(dport=global(\"port\", 5353)) |> ipv4() |> eth()\n",
        &[],
    );
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&pkts[0])
        .unwrap();
    let udp_off = 14 + 20;
    assert_eq!(&bytes[udp_off + 2..udp_off + 4], &[0x14, 0xE9]);
}

/// sniffer 匹配值表达式可引用全局：`id=be16(global("tid"))`（数值全局须显式
/// 转字节，与 `id=be16(0x1234)` 的字节比较语义一致）。
#[test]
fn global_in_sniffer() {
    use packet_dsl::{Globals, eval_sniffer_value_with_globals};

    // 构造 `id=be16(global("tid"))` 值表达式
    let expr = packet_dsl::ast::Value::Call {
        name: "be16".to_string(),
        name_span: packet_dsl::ast::Span::new(1, 1, 1, 1),
        args: vec![packet_dsl::ast::Value::Call {
            name: "global".to_string(),
            name_span: packet_dsl::ast::Span::new(1, 1, 1, 1),
            args: vec![packet_dsl::ast::Value::Str("tid".to_string())],
            span: packet_dsl::ast::Span::new(1, 1, 1, 1),
        }],
        span: packet_dsl::ast::Span::new(1, 1, 1, 1),
    };
    let g: Globals = [("tid".to_string(), packet_dsl::ast::Value::Hex(0x1234))].into();
    let bytes = eval_sniffer_value_with_globals(None, &Params::new(), &g, &expr).expect("求值成功");
    assert_eq!(
        bytes,
        vec![0x12, 0x34],
        "id=be16(global(\"tid\")) 应算出两字节"
    );
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
            Layer::Raw(RawData {
                bytes: vec![],
                proto: None,
            }),
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
                proto: None,
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
func wrap(dport, flags=syn(), window, ttl=64) {\n\
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
    let src = "a = http(start_line=\"GET / HTTP/1.1\")\nb = http(start_line=\"POST / HTTP/1.1\")\nfunc wrap() { use(a, b) |> tcp(dport=80) }\nuse(wrap)\n";
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
    for ch in hdr.as_chunks::<2>().0 {
        sum += u16::from_be_bytes(*ch) as u32;
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
    common::register_eng_lib();
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
        include_str!("../../../eng_lib/headers.pkt"),
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

/// 值函数：字节返回函数组合（dns_name 长度前缀编码经库值函数）。
#[test]
fn value_funcs_compose() {
    let src = "\
func two(s) -> bytes { concat(raw(s), raw(\"\\r\\n\")) }\n\
p = raw(bytes=concat(two(\"Host: a\"), dns_name(\"example.com\")))\n\
use(p)\n";
    let m = parse_str("t", src).unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    assert_eq!(&bytes[..9], b"Host: a\r\n", "值函数应拼接");
    assert_eq!(
        &bytes[9..],
        &[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
        ],
        "dns_name 长度前缀编码"
    );
}

/// 库值函数（eng_lib prelude）：用户脚本在值位置直接调用。
#[test]
fn lib_value_func_callable_from_script() {
    let entry = std::env::temp_dir().join(format!("pkt-libval-entry-{}", std::process::id()));
    let lib = std::env::temp_dir().join(format!("pkt-libval-lib-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&entry);
    let _ = std::fs::remove_dir_all(&lib);
    std::fs::create_dir_all(&entry).unwrap();
    std::fs::create_dir_all(&lib).unwrap();
    // 库模块：字节构建值函数（rand_mac 风格）
    std::fs::write(
        lib.join("rand.pkt"),
        "func rand_mac() -> bytes { concat(u8(rand8()), u8(rand8()), u8(rand8()), u8(rand8()), u8(rand8()), u8(rand8())) }\n\
         export:\n- rand_mac\n",
    )
    .unwrap();
    // 值位置直接调用库值函数
    let main1 = entry.join("direct.pkt");
    std::fs::write(
        &main1,
        "p = raw(bytes=concat(rand_mac(), be16(0x1234)))\nuse(p)\n",
    )
    .unwrap();
    let m1 = packet_dsl::semantic::parse_file_with_libs(&main1, std::slice::from_ref(&lib))
        .expect("库值函数应经 prelude 解析");
    let built1 = packet_dsl::resolve(&m1).expect("求值成功");
    let bytes1 = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built1.packets[0])
        .unwrap();
    assert_eq!(bytes1.len(), 8, "6 字节随机 MAC + 2 字节 be16");
    assert_eq!(&bytes1[6..], &[0x12, 0x34], "be16 部分应确定");
    let _ = std::fs::remove_dir_all(&entry);
    let _ = std::fs::remove_dir_all(&lib);
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
        msg.contains("字符串") || msg.contains("MAC") || msg.contains("6 字节"),
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

// ── 字符串 → 数值/字节 统一规则（int_of 与 hex）────────────────

/// hex()：`0x` 前缀可选——值位置（raw(bytes=...)/val_bytes 路径）与层位置等价。
#[test]
fn hex_accepts_optional_0x_prefix() {
    let m = packet_dsl::semantic::parse_str(
        "t",
        "a = raw(bytes=hex(\"0x4242\"))\nb = raw(bytes=hex(\"4242\"))\npa = use(a)\npb = use(b)\nexport:\n- pa\n- pb\n",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    assert_eq!(ser.serialize(&built.packets[0]).unwrap(), vec![0x42, 0x42]);
    assert_eq!(ser.serialize(&built.packets[1]).unwrap(), vec![0x42, 0x42]);
    // 层位置：`|> hex("0x4500")` → Raw 层字节（头 + 载荷）
    let m2 =
        packet_dsl::semantic::parse_str("t", "p = raw(bytes=\"x\")\nuse(p) |> hex(\"0x4500\")\n")
            .expect("解析成功");
    let built2 = packet_dsl::resolve(&m2).expect("求值成功");
    let c = ser.serialize(&built2.packets[0]).unwrap();
    assert_eq!(c, vec![0x45, 0x00, b'x'], "层位置 hex 字节 = 头 + 载荷");
}

/// hex()：奇数长度/非法字符 → 求值期清晰报错（值位置与层位置，均不 panic）。
#[test]
fn hex_invalid_is_error_not_panic() {
    for bad in ["abc", "0x12 3", "zz"] {
        let err = packet_dsl::semantic::parse_str(
            "t",
            &format!("p = raw(bytes=hex(\"{bad}\"))\nexport:\n- p\n"),
        )
        .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
        .unwrap_err();
        assert!(
            err.to_string().contains("偶数长度的十六进制"),
            "{bad}: {err}"
        );
    }
    // 层位置同样报错
    let err =
        packet_dsl::semantic::parse_str("t", "p = raw(bytes=\"x\")\nuse(p) |> hex(\"abc\")\n")
            .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
            .unwrap_err();
    assert!(err.to_string().contains("偶数长度的十六进制"), "{err}");
}

/// int_of：数字字符串 `0x` 前缀 = 十六进制，否则十进制（params 传入同样适用）。
/// params 按形状解析：0x 前缀 = 十六进制、纯数字 = 十进制（取代 int()）；裸字符串字面量仍报错。
#[test]
fn params_shape_parsing_replaces_int() {
    let m = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=\"x\")\nuse(p) |> icmp(id=params(\"id\", \"0x4242\")) |> ipv4(src=\"1.2.3.4\", dst=\"8.8.8.8\") |> eth()\n",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    let b = ser.serialize(&built.packets[0]).unwrap();
    // icmp id 偏移：eth 14 + ipv4 20 + type/code(2) + checksum(2) = 38
    assert_eq!(
        &b[14 + 20 + 4..14 + 20 + 6],
        &[0x42, 0x42],
        "int(0x 前缀) = 十六进制"
    );
    // 无前缀按十进制（4242 = 0x1092），与源码里裸 0x4242 语义不同——文档化行为
    let m2 = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=\"x\")\nuse(p) |> icmp(id=params(\"id\", \"4242\")) |> ipv4(src=\"1.2.3.4\", dst=\"8.8.8.8\") |> eth()\n",
    )
    .expect("解析成功");
    let built2 = packet_dsl::resolve(&m2).expect("求值成功");
    let b2 = ser.serialize(&built2.packets[0]).unwrap();
    assert_eq!(
        &b2[14 + 20 + 4..14 + 20 + 6],
        &[0x10, 0x92],
        "int(无前缀) = 十进制"
    );
    // 裸字符串字面量进数字位置 → 报错（不隐式转换）
    let err = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=\"x\")\nuse(p) |> icmp(id=be16(\"0x4242\")) |> ipv4(src=\"1.2.3.4\", dst=\"8.8.8.8\") |> eth()\n",
    )
    .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
    .unwrap_err();
    assert!(
        err.to_string().contains("不隐式转数值"),
        "裸字符串进 be16 应报错：{err}"
    );
}

// ── 同宽字节直通（宽度即类型）──────────────────────────────

/// u8/be16/be32：同宽字节列表直通（与 ip4/ip6/mac 的字节直通同一哲学）。
#[test]
fn width_primitives_accept_same_width_bytes() {
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    // be16(hex("1234")) == be16(0x1234) == [0x12, 0x34]
    for src in [
        "p = raw(bytes=be16(hex(\"1234\")))\nexport:\n- p\n",
        "p = raw(bytes=be16(0x1234))\nexport:\n- p\n",
        "p = raw(bytes=be16([0x12, 0x34]))\nexport:\n- p\n",
    ] {
        let m = packet_dsl::semantic::parse_str("t", src).expect("解析成功");
        let built = packet_dsl::resolve(&m).expect("求值成功");
        assert_eq!(
            ser.serialize(&built.packets[0]).unwrap(),
            vec![0x12, 0x34],
            "{src}"
        );
    }
    // u8(raw("a")) == u8(0x61) == [0x61]（值位置 UTF-8 编码器是 raw()，raw 是层原语）
    for src in [
        "p = raw(bytes=u8(raw(\"a\")))\nexport:\n- p\n",
        "p = raw(bytes=u8(0x61))\nexport:\n- p\n",
        "p = raw(bytes=u8([0x61]))\nexport:\n- p\n",
    ] {
        let m = packet_dsl::semantic::parse_str("t", src).expect("解析成功");
        let built = packet_dsl::resolve(&m).expect("求值成功");
        assert_eq!(
            ser.serialize(&built.packets[0]).unwrap(),
            vec![0x61],
            "{src}"
        );
    }
}

/// u8/be16/be32：宽度不符 → 报错带字节数；字符串仍不隐式转数值。
#[test]
fn width_primitives_reject_mismatched_width() {
    // 3 字节 ≠ be16 的 2 字节
    let err = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=be16(hex(\"123456\")))\nexport:\n- p\n",
    )
    .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
    .unwrap_err();
    assert!(err.to_string().contains("恰好 2 字节"), "{err}");
    // 2 字节 ≠ u8 的 1 字节
    let err =
        packet_dsl::semantic::parse_str("t", "p = raw(bytes=u8(hex(\"4142\")))\nexport:\n- p\n")
            .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
            .unwrap_err();
    assert!(err.to_string().contains("恰好 1 字节"), "{err}");
    // 字符串仍禁止（be16("ab") 不按 UTF-8 直通）
    let err = packet_dsl::semantic::parse_str("t", "p = raw(bytes=be16(\"ab\"))\nexport:\n- p\n")
        .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
        .unwrap_err();
    assert!(err.to_string().contains("不隐式转数值"), "{err}");
}

/// le16/le32：小端编码（低字节在前）；字节输入反转（按大端解读后重编码为小端）。
#[test]
fn little_endian_primitives() {
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    // le16(0x1234) == le16(hex("1234")) == [0x34, 0x12]
    for src in [
        "p = raw(bytes=le16(0x1234))\nexport:\n- p\n",
        "p = raw(bytes=le16(hex(\"1234\")))\nexport:\n- p\n",
    ] {
        let m = packet_dsl::semantic::parse_str("t", src).expect("解析成功");
        let built = packet_dsl::resolve(&m).expect("求值成功");
        assert_eq!(
            ser.serialize(&built.packets[0]).unwrap(),
            vec![0x34, 0x12],
            "{src}"
        );
    }
    // 字节输入反转：le16([0x01, 0x02]) = [0x02, 0x01]（值 0x0102 的小端编码）
    let m =
        packet_dsl::semantic::parse_str("t", "p = raw(bytes=le16([0x01, 0x02]))\nexport:\n- p\n")
            .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(
        ser.serialize(&built.packets[0]).unwrap(),
        vec![0x02, 0x01],
        "le16([0x01,0x02]) 字节反转"
    );
    // le32(0x01020304) == le32(hex("01020304")) == [0x04, 0x03, 0x02, 0x01]
    let m = packet_dsl::semantic::parse_str(
        "t",
        "a = raw(bytes=le32(0x01020304))\nb = raw(bytes=le32(hex(\"01020304\")))\nexport:\n- a\n- b\n",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    for p in &built.packets {
        assert_eq!(
            ser.serialize(p).unwrap(),
            vec![0x04, 0x03, 0x02, 0x01],
            "le32 小端编码"
        );
    }
    // 双重反转 = 恒等：le16(le16(hex("1234"))) = [0x12, 0x34]
    let m = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=le16(le16(hex(\"1234\"))))\nexport:\n- p\n",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(
        ser.serialize(&built.packets[0]).unwrap(),
        vec![0x12, 0x34],
        "le16(le16(x)) 恒等"
    );
}

/// be64/le64：8 字节大端/小端（与字段类型编码同宽；i64::MAX 封顶）。
#[test]
fn big_little_endian_64() {
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    // be64(0x0102030405060708) == be64(hex(...)) == 8 字节大端
    for src in [
        "p = raw(bytes=be64(0x0102030405060708))\nexport:\n- p\n",
        "p = raw(bytes=be64(hex(\"0102030405060708\")))\nexport:\n- p\n",
    ] {
        let m = packet_dsl::semantic::parse_str("t", src).expect("解析成功");
        let built = packet_dsl::resolve(&m).expect("求值成功");
        assert_eq!(
            ser.serialize(&built.packets[0]).unwrap(),
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "{src}"
        );
    }
    // le64(0x0102030405060708) == le64(hex(...)) == 低字节在前
    let m = packet_dsl::semantic::parse_str(
        "t",
        "a = raw(bytes=le64(0x0102030405060708))\nb = raw(bytes=le64(hex(\"0102030405060708\")))\nexport:\n- a\n- b\n",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    for p in &built.packets {
        assert_eq!(
            ser.serialize(p).unwrap(),
            vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            "le64 小端编码"
        );
    }
    // 字节输入反转：le64([0x01..0x08]) = 反转（按大端解读后重编码为小端）
    let m = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=le64([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))\nexport:\n- p\n",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(
        ser.serialize(&built.packets[0]).unwrap(),
        vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        "le64 字节反转"
    );
    // 双重反转 = 恒等：le64(le64(hex(...))) = 原序
    let m = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=le64(le64(hex(\"0102030405060708\"))))\nexport:\n- p\n",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(
        ser.serialize(&built.packets[0]).unwrap(),
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        "le64(le64(x)) 恒等"
    );
    // 越界：2^63 超出 i64 表示 → 报错（与字段类型 be64 同一封顶）
    let err = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=be64(0x8000000000000000))\nexport:\n- p\n",
    )
    .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
    .unwrap_err();
    assert!(err.to_string().contains("超出范围"), "{err}");
}

/// params 传 "0x4242" → 形状解析为数值 → be16 直接编码（无需 int 也无需 hex）。
#[test]
fn hex_params_shape_parse_direct() {
    let m = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=\"x\")\nuse(p) |> icmp(id=be16(params(\"id\", \"0x4242\"))) |> ipv4(src=\"1.2.3.4\", dst=\"8.8.8.8\") |> eth()\n",
    )
    .expect("解析成功");
    // 用默认值 "0x4242"：hex 去前缀 → [0x42, 0x42] → be16 同宽直通
    let built = packet_dsl::resolve(&m).expect("求值成功");
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    let b = ser.serialize(&built.packets[0]).unwrap();
    assert_eq!(&b[14 + 20 + 4..14 + 20 + 6], &[0x42, 0x42], "默认 0x4242");
    // 宿主覆盖 params id=0x1234：hex 去前缀 → [0x12, 0x34]
    let mut params = packet_dsl::Params::new();
    params.insert("id".to_string(), "0x1234".to_string());
    let built2 = packet_dsl::resolve_with_params(&m, &params).expect("求值成功");
    let b2 = ser.serialize(&built2.packets[0]).unwrap();
    assert_eq!(&b2[14 + 20 + 4..14 + 20 + 6], &[0x12, 0x34], "覆盖 0x1234");
}

/// le16/le32：宽度不符、越界、字符串 → 报错。
#[test]
fn little_endian_errors() {
    // 3 字节 ≠ 2
    let err = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=le16(hex(\"123456\")))\nexport:\n- p\n",
    )
    .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
    .unwrap_err();
    assert!(err.to_string().contains("恰好 2 字节"), "{err}");
    // 越界 0x10000 > 65535
    let err = packet_dsl::semantic::parse_str("t", "p = raw(bytes=le16(0x10000))\nexport:\n- p\n")
        .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
        .unwrap_err();
    assert!(err.to_string().contains("超出范围"), "{err}");
    // 字符串仍禁止
    let err = packet_dsl::semantic::parse_str("t", "p = raw(bytes=le16(\"12\"))\nexport:\n- p\n")
        .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
        .unwrap_err();
    assert!(err.to_string().contains("不隐式转数值"), "{err}");
}

/// params 默认值可以是值表达式（be16/hex/字面量/字节列表）：未注入时求值为默认值。
#[test]
fn params_value_expression_default() {
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    // 默认 be16(0x1235) = [0x12, 0x35]；宿主注入按形状解析后由 be16 编码，结果一致
    let m = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=be16(params(\"port\", be16(0x1235))))\nexport:\n- p\n",
    )
    .expect("解析成功");
    // 未注入 → 用默认值表达式
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(
        ser.serialize(&built.packets[0]).unwrap(),
        vec![0x12, 0x35],
        "默认 be16(0x1235)"
    );
    // 宿主注入 0x1235 → 形状解析为数值 → be16 编码
    let mut params = packet_dsl::Params::new();
    params.insert("port".to_string(), "0x1235".to_string());
    let built2 = packet_dsl::resolve_with_params(&m, &params).expect("求值成功");
    assert_eq!(
        ser.serialize(&built2.packets[0]).unwrap(),
        vec![0x12, 0x35],
        "注入 0x1235"
    );
    // 宿主注入 53（十进制）→ [0x00, 0x35]
    let mut params3 = packet_dsl::Params::new();
    params3.insert("port".to_string(), "53".to_string());
    let built3 = packet_dsl::resolve_with_params(&m, &params3).expect("求值成功");
    assert_eq!(
        ser.serialize(&built3.packets[0]).unwrap(),
        vec![0x00, 0x35],
        "注入 53"
    );
}

/// params 默认值表达式：hex("...") → 字节列表，可直接进 concat（值表达式位置）。
#[test]
fn params_hex_default_in_value_expr() {
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    let m = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=concat(params(\"payload\", hex(\"deadbeef\")), raw(\"!\")))\nexport:\n- p\n",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(
        ser.serialize(&built.packets[0]).unwrap(),
        vec![0xde, 0xad, 0xbe, 0xef, b'!'],
        "hex 默认 + raw 拼接"
    );
    // 宿主注入字符串 → 按形状解析（"dead" 非数字 → 字符串 → raw 拼接为 UTF-8）
    let mut params = packet_dsl::Params::new();
    params.insert("payload".to_string(), "dead".to_string());
    let built2 = packet_dsl::resolve_with_params(&m, &params).expect("求值成功");
    assert_eq!(
        ser.serialize(&built2.packets[0]).unwrap(),
        vec![b'd', b'e', b'a', b'd', b'!'],
        "注入非数字 → 字符串"
    );
}

/// 层参数位置的 params 默认值必须是字符串字面量（值表达式默认只在值表达式位置可用）。
#[test]
fn params_non_string_default_in_layer_arg_errors() {
    let err = packet_dsl::semantic::parse_str(
        "t",
        "p = raw(bytes=params(\"payload\", hex(\"deadbeef\")))\nexport:\n- p\n",
    )
    .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
    .unwrap_err();
    assert!(err.to_string().contains("默认值需为字符串字面量"), "{err}");
}

// ── tpl 模板原语（文本 → 字节）─────────────────────────────

/// 求值值表达式 → 序列化字节（tpl 测试助手）。
fn tpl_bytes(expr: &str) -> Vec<u8> {
    let src = format!("p = raw(bytes={expr})\nuse(p)\n");
    let m = packet_dsl::semantic::parse_str("t", &src).unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap()
}

/// 求值值表达式 → 错误消息（解析/求值任一步失败）。
fn tpl_err(expr: &str) -> String {
    let src = format!("p = raw(bytes={expr})\nuse(p)\n");
    packet_dsl::semantic::parse_str("t", &src)
        .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
        .unwrap_err()
        .to_string()
}

/// tpl 基础：ip4 点分 / mac 字符类分隔符 / 宽度 / %c 通配 / %% 转义 / 无分隔重复。
#[test]
fn tpl_basic_formats() {
    // ip4：%d 默认宽度 1，{4:.} 点分四组
    assert_eq!(
        tpl_bytes("tpl(\"%d{4:.}\", \"192.168.1.1\")"),
        vec![192, 168, 1, 1]
    );
    // mac：%x 默认宽度 1，字符类 [-.:] 分隔符容忍混用
    assert_eq!(
        tpl_bytes("tpl(\"%x{6:[-.:]}\", \"aa:bb-cc.dd:ee:ff\")"),
        vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    );
    // 端口：%d2 两字节大端
    assert_eq!(tpl_bytes("tpl(\"%d2\", \"5353\")"), vec![0x14, 0xe9]);
    // %x2：四 hex 位 → 2 字节（ip6 单组）
    assert_eq!(tpl_bytes("tpl(\"%x2\", \"fe80\")"), vec![0xfe, 0x80]);
    // %d4 / %x4：4 字节大端
    assert_eq!(
        tpl_bytes("tpl(\"%d4\", \"3232235521\")"),
        vec![0xc0, 0xa8, 0x00, 0x01]
    );
    assert_eq!(
        tpl_bytes("tpl(\"%x4\", \"c0a80001\")"),
        vec![0xc0, 0xa8, 0x00, 0x01]
    );
    // %c 通配单字节；字面量匹配但不产出（scanf 式解析器，与 {n:sep} 分隔符一致）
    assert_eq!(tpl_bytes("tpl(\"a%cb\", \"axb\")"), vec![b'x']);
    // %% 转义：字面 `%` 参与模式匹配（不产出），%c 抓后续字节
    assert_eq!(tpl_bytes("tpl(\"50%%%c\", \"50%x\")"), vec![b'x']);
    // 重复无分隔：%c{4} = 4 个任意字节
    assert_eq!(tpl_bytes("tpl(\"%c{4}\", \"abcd\")"), b"abcd".to_vec());
}

/// tpl ip6：`%x2{8:}` 全形态（全 8 组 / 开头 / 中间 / 结尾 / 中段压缩）。
#[test]
fn tpl_ip6_compression() {
    let ip6 = |s: &str| tpl_bytes(&format!("tpl(\"%x2{{8:}}\", \"{s}\")"));
    for s in [
        "2001:db8:0:1:2:3:4:5",
        "::1",
        "fe80::1",
        "fe80::",
        "1:2:3:4::5:6:7",
        "::",
    ] {
        let want = s.parse::<std::net::Ipv6Addr>().unwrap().octets();
        assert_eq!(ip6(s), want, "ip6 {s}");
    }
}

/// tpl 错误：锚定全匹配 / 分隔符 / 组数不足 / 越界 / 模板语法 / 非 ASCII 字面。
#[test]
fn tpl_errors() {
    // 锚定：模板结束后仍有输入
    assert!(
        tpl_err("tpl(\"%d{4:.}\", \"1.2.3.4.5\")").contains("未消费"),
        "{}",
        tpl_err("tpl(\"%d{4:.}\", \"1.2.3.4.5\")")
    );
    // 分隔符不符
    assert!(
        tpl_err("tpl(\"%d{4:.}\", \"1.2.3-4\")").contains("分隔符"),
        "{}",
        tpl_err("tpl(\"%d{4:.}\", \"1.2.3-4\")")
    );
    // 组数不足（无 :: 压缩时不补零）
    assert!(
        tpl_err("tpl(\"%d{4:.}\", \"1.2.3\")").contains("失败"),
        "{}",
        tpl_err("tpl(\"%d{4:.}\", \"1.2.3\")")
    );
    // 越界：%d1 值 > 255
    assert!(
        tpl_err("tpl(\"%d{4:.}\", \"1.2.3.256\")").contains("超出"),
        "{}",
        tpl_err("tpl(\"%d{4:.}\", \"1.2.3.256\")")
    );
    // 非法模板类型
    assert!(
        tpl_err("tpl(\"%q\", \"x\")").contains("模板"),
        "{}",
        tpl_err("tpl(\"%q\", \"x\")")
    );
    // 非 ASCII 字面字符
    assert!(
        tpl_err("tpl(\"中\", \"中\")").contains("ASCII"),
        "{}",
        tpl_err("tpl(\"中\", \"中\")")
    );
    // 多个 :: 压缩
    assert!(
        tpl_err("tpl(\"%x2{8:}\", \"1::2::3\")").contains("多个"),
        "{}",
        tpl_err("tpl(\"%x2{8:}\", \"1::2::3\")")
    );
}

/// tpl 字节列表等宽直通（mac(rand_mac()) 风格）+ 长度不符报错。
#[test]
fn tpl_byte_list_passthrough() {
    assert_eq!(
        tpl_bytes("tpl(\"%x{6:[-.:]}\", concat(u8(1), u8(2), u8(3), u8(4), u8(5), u8(6)))"),
        vec![1, 2, 3, 4, 5, 6]
    );
    let err = tpl_err("tpl(\"%x{6:[-.:]}\", concat(u8(1), u8(2)))");
    assert!(err.contains("长度"), "{err}");
}

/// tpl `%L`：DNS 名字序列（长度前缀 + 尾 0；空标签跳过）。
#[test]
fn tpl_dns_name_spec() {
    let dns = |s: &str| tpl_bytes(&format!("tpl(\"%L\", \"{s}\")"));
    assert_eq!(
        dns("example.com"),
        vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
        ]
    );
    assert_eq!(dns("a.b"), vec![1, b'a', 1, b'b', 0]);
    assert_eq!(
        dns("www.example.co.uk"),
        vec![
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 2, b'c', b'o', 2,
            b'u', b'k', 0
        ]
    );
    // 尾点 / 连续点 / 空串：空标签跳过（与旧 dns_name 行为一致）
    assert_eq!(
        dns("example.com."),
        vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
        ]
    );
    assert_eq!(dns("a..b"), vec![1, b'a', 1, b'b', 0]);
    assert_eq!(dns(""), vec![0]);
}

/// tpl `%L` 错误：标签超长 / 总长超限 / 参数误用 / 字节列表输入。
#[test]
fn tpl_dns_name_errors() {
    // 标签 > 63 字节
    let long = "a".repeat(64);
    let err = tpl_err(&format!("tpl(\"%L\", \"{long}\")"));
    assert!(err.contains("63"), "{err}");
    // 总长 > 255（5 个 60 字节标签：5*(60+1)+1 = 306）
    let big = std::iter::repeat_with(|| "a".repeat(60))
        .take(5)
        .collect::<Vec<_>>()
        .join(".");
    let err = tpl_err(&format!("tpl(\"%L\", \"{big}\")"));
    assert!(err.contains("255"), "{err}");
    // %L 不接受宽度/重复参数
    assert!(
        tpl_err("tpl(\"%L2\", \"a\")").contains("不接受"),
        "{}",
        tpl_err("tpl(\"%L2\", \"a\")")
    );
    assert!(
        tpl_err("tpl(\"%L{2}\", \"a\")").contains("不接受"),
        "{}",
        tpl_err("tpl(\"%L{2}\", \"a\")")
    );
    // 含 %L 的模板不接受字节列表输入（动态宽度不可算）
    let err = tpl_err("tpl(\"%L\", concat(u8(1), u8(2)))");
    assert!(err.contains("动态宽度"), "{err}");
    // 锚定：%L 消费剩余全部，模板尾部还有字面量 → 未消费/期望字面量报错
    let err = tpl_err("tpl(\"%Lx\", \"a.bx\")");
    assert!(
        err.contains("期望字面量") || err.contains("未消费"),
        "{err}"
    );
}

/// eng_lib 值函数 ip4/ip6/mac（tpl 实现）可直接调用；值位置域名需显式 dns()。
#[test]
fn lib_ip4_ip6_mac_value_funcs() {
    assert_eq!(tpl_bytes("ip4(\"10.0.0.1\")"), vec![10, 0, 0, 1]);
    assert_eq!(
        tpl_bytes("ip6(\"fe80::1\")"),
        "fe80::1".parse::<std::net::Ipv6Addr>().unwrap().octets()
    );
    assert_eq!(
        tpl_bytes("mac(\"00:11:22:33:44:55\")"),
        vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    );
    // IP 字面量短路：dns() 无需解析器
    assert_eq!(tpl_bytes("ip4(dns(\"192.0.2.1\"))"), vec![192, 0, 2, 1]);
    // 字面量地址直接进值函数（headers.pkt 内部 dns 包装同一路径）
    assert_eq!(
        tpl_bytes("ip6(dns(\"2001:db8::1\", 6))"),
        "2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
    );
}

/// line 库值函数（bytes.pkt）：文本行 → 字节（值 + \r\n）——proto `line`
/// 字段的构造侧编码，双位置（proto body 内 type_of 降糖为字段声明，值表达式
/// 内走库值函数）。
#[test]
fn lib_line_value_func() {
    assert_eq!(tpl_bytes("line(\"abc\")"), b"abc\r\n");
    assert_eq!(
        tpl_bytes("line(\"Host: example.com\")"),
        b"Host: example.com\r\n"
    );
    // 空行（哨兵场景）：line("") 产 \r\n；与 proto line 字段构造侧一致
    assert_eq!(tpl_bytes("line(\"\")"), b"\r\n");
    // 与 concat 组合（HTTP 头行 + 空行结尾）
    assert_eq!(
        tpl_bytes("concat(line(\"GET / HTTP/1.1\"), line(\"Host: a\"))"),
        b"GET / HTTP/1.1\r\nHost: a\r\n"
    );
}

// ── 位运算原语（bor/band/bxor/bnot/shl/shr）─────────────────

/// 位运算整数形态：bor 变参左折叠 / band / bxor / bnot / shl / shr。
#[test]
fn bitwise_int_ops() {
    // bor 变参左折叠（Int/Hex 均可）
    assert_eq!(tpl_bytes("u8(bor(2, 16))"), vec![0x12]);
    assert_eq!(tpl_bytes("u8(bor(1, 2, 4))"), vec![0x07]);
    assert_eq!(tpl_bytes("u8(bor(0x02, 0x10))"), vec![0x12]);
    // band / bxor
    assert_eq!(tpl_bytes("u8(band(0x1f, 0x0f))"), vec![0x0f]);
    assert_eq!(tpl_bytes("u8(bxor(0xff, 0x0f))"), vec![0xf0]);
    // bnot：i64 取反后超出 u8 范围，用 band 屏蔽高位
    assert_eq!(tpl_bytes("u8(band(bnot(0x0f), 0xff))"), vec![0xf0]);
    // shl / shr
    assert_eq!(tpl_bytes("be16(shl(1, 12))"), vec![0x10, 0x00]);
    assert_eq!(tpl_bytes("be16(shr(0x8000, 4))"), vec![0x08, 0x00]);
}

/// 位运算字节列表形态：同宽元素级（eng_lib 位常量组合路径）。
#[test]
fn bitwise_byte_list_ops() {
    // bor(syn(), ack()) = [0x02] | [0x10] = [0x12]
    assert_eq!(tpl_bytes("bor(syn(), ack())"), vec![0x12]);
    assert_eq!(tpl_bytes("bor(fin(), syn(), rst())"), vec![0x07]);
    // be16 宽度：df() | mf() = 0x6000
    assert_eq!(tpl_bytes("bor(df(), mf())"), vec![0x60, 0x00]);
    assert_eq!(tpl_bytes("band(hex(\"f0\"), hex(\"0f\"))"), vec![0x00]);
    assert_eq!(tpl_bytes("bnot(u8(0x0f))"), vec![0xf0]);
}

/// 位运算错误：元数 / 宽度不一致 / 混型 / 移位量越界 / 字符串。
#[test]
fn bitwise_errors() {
    assert!(tpl_err("bor(1)").contains("至少"), "{}", tpl_err("bor(1)"));
    assert!(
        tpl_err("band(1)").contains("2 个参数"),
        "{}",
        tpl_err("band(1)")
    );
    assert!(
        tpl_err("bnot(1, 2)").contains("1 个参数"),
        "{}",
        tpl_err("bnot(1, 2)")
    );
    // 宽度不一致（syn() 1 字节 vs df() 2 字节）
    assert!(
        tpl_err("bor(syn(), df())").contains("宽度"),
        "{}",
        tpl_err("bor(syn(), df())")
    );
    // 混型：整数 + 字节列表
    assert!(
        tpl_err("bor(2, syn())").contains("全部整数或全部同宽字节列表"),
        "{}",
        tpl_err("bor(2, syn())")
    );
    // 字符串不参与位运算
    assert!(
        tpl_err("bor(\"a\", 2)").contains("全部整数或全部同宽字节列表"),
        "{}",
        tpl_err("bor(\"a\", 2)")
    );
    // 移位量越界
    assert!(
        tpl_err("shl(1, 64)").contains("0..64"),
        "{}",
        tpl_err("shl(1, 64)")
    );
}

/// eng_lib 位常量值函数（原引擎 tcpflags/ip4flags/arpop 语义下沉）与层函数组合。
#[test]
fn lib_flag_constants() {
    // 单个位常量
    assert_eq!(tpl_bytes("syn()"), vec![0x02]);
    assert_eq!(tpl_bytes("ack()"), vec![0x10]);
    assert_eq!(tpl_bytes("df()"), vec![0x40, 0x00]);
    assert_eq!(tpl_bytes("request()"), vec![0x00, 0x01]);
    assert_eq!(tpl_bytes("reply()"), vec![0x00, 0x02]);
    // ipv4 flags：bor(df(), mf()) 落进头 offset 6-7
    let built = layers_of("a = raw()\nuse(a) |> ipv4(dst=\"10.0.0.2\", flags=bor(df(), mf()))\n");
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&packet_dsl::ir::PacketSpec {
            layers: built[0].clone(),
        })
        .unwrap();
    assert_eq!(
        &bytes[6..8],
        &[0x60, 0x00],
        "ipv4 flags df|mf（offset 6-7）"
    );
    // arp op=reply() 落进 offset 6-7（htype/ptype/hlen/plen 后）
    let built = layers_of(
        "a = raw()\nuse(a) |> arp(op=reply(), spa=\"192.168.1.1\", tpa=\"192.168.1.2\")\n",
    );
    let bytes = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&packet_dsl::ir::PacketSpec {
            layers: built[0].clone(),
        })
        .unwrap();
    assert_eq!(&bytes[6..8], &[0x00, 0x02], "arp op=reply");
}

// ── 校验和 / 摘要（cksum / md5 / sha1 / sha256 引擎原语）─────────────
// words16/fold16（校验和的切分/折叠中间机制）已回退移除——cksum 是一步原语。

/// hex 字符串 → 字节（测试助手）。
fn hexvec(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// cksum：互联网校验和（RFC 1071 反码）→ 2 字节大端，与引擎自动校验和一致。
#[test]
fn cksum_primitive() {
    // 与 serialize::checksum 逐一对照（含空、奇数长度、跨 2^32 边界大输入）
    let cases: &[&[u8]] = &[
        &[],
        &[0, 0],
        &[0, 1],
        &[0x12, 0x34],
        &[0x00, 0x01, 0xff, 0xff], // 求和 0x10000 → 折叠 0x0001（原 fold16 用例）
        &[0, 1, 2],                // 奇数字节补高 8 位（0x0200）
        b"hello world",
        b"GET / HTTP/1.1\r\n",
        &[0xff; 100], // 大输入跨 2^32 边界（sum ≈ 100/2 * 0xffff）
    ];
    for data in cases {
        let hexstr = data.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let got = tpl_bytes(&format!("cksum(hex(\"{hexstr}\"))"));
        let want = packet_dsl::serialize::checksum(data).to_be_bytes();
        assert_eq!(got, want, "cksum({data:?}) 应等于引擎 checksum");
    }
    // 字符串输入（UTF-8）
    let got = tpl_bytes("cksum(\"abc\")");
    let want = packet_dsl::serialize::checksum(b"abc").to_be_bytes();
    assert_eq!(got, want);
    // 非字节/字符串 → 报错
    let err = tpl_err("cksum(1)");
    assert!(err.contains("期望字节列表或字符串"), "{err}");
}

/// md5/sha1/sha256：摘要算法原语（输入字节列表或字符串 → 定长摘要字节）。
#[test]
fn hash_primitives() {
    // RFC 标准测试向量："abc"
    assert_eq!(
        tpl_bytes("md5(\"abc\")"),
        hexvec("900150983cd24fb0d6963f7d28e17f72")
    );
    assert_eq!(
        tpl_bytes("sha1(\"abc\")"),
        hexvec("a9993e364706816aba3e25717850c26c9cd0d89d")
    );
    assert_eq!(
        tpl_bytes("sha256(\"abc\")"),
        hexvec("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    // 空输入向量
    assert_eq!(
        tpl_bytes("md5(\"\")"),
        hexvec("d41d8cd98f00b204e9800998ecf8427e")
    );
    assert_eq!(
        tpl_bytes("sha1(\"\")"),
        hexvec("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    );
    assert_eq!(
        tpl_bytes("sha256(\"\")"),
        hexvec("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    // 字节列表输入 ≡ 字符串（UTF-8）
    assert_eq!(
        tpl_bytes("sha256(hex(\"616263\"))"),
        tpl_bytes("sha256(\"abc\")")
    );
    assert_eq!(
        tpl_bytes("md5([0x61, 0x62, 0x63])"),
        tpl_bytes("md5(\"abc\")")
    );
    // 摘要可继续进字节上下文（拼接、定长）
    let joined = tpl_bytes("concat(md5(\"abc\"), sha256(\"abc\"))");
    assert_eq!(joined.len(), 16 + 32);
    // 非字节/字符串 → 报错
    let err = tpl_err("md5(1)");
    assert!(err.contains("期望字节列表或字符串"), "{err}");
}

// ── count 引擎原语 / len 库值函数（bytes.pkt `count∘raw`）────────────

/// 带函数定义前缀的 tpl_bytes（值函数测试需要本地 func）。
fn tpl_bytes_pfx(prefix: &str, expr: &str) -> Vec<u8> {
    let src = format!("{prefix}p = raw(bytes={expr})\nuse(p)\n");
    let m = packet_dsl::semantic::parse_str("t", &src).unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap()
}

/// 带函数定义前缀的 tpl_err（值函数测试需要本地 func）。
fn tpl_err_pfx(prefix: &str, expr: &str) -> String {
    let src = format!("{prefix}p = raw(bytes={expr})\nuse(p)\n");
    packet_dsl::semantic::parse_str("t", &src)
        .and_then(|m| packet_dsl::resolve(&m).map(|_| ()))
        .unwrap_err()
        .to_string()
}

/// count：任意列表长度（DNS qdcount 用 count(questions)）。
#[test]
fn count_primitive() {
    assert_eq!(tpl_bytes("u8(count([1, 2, 3]))"), vec![0x03]);
    assert_eq!(tpl_bytes("u8(count([]))"), vec![0x00]);
    assert_eq!(tpl_bytes("u8(count([\"a\", \"b\", \"c\"]))"), vec![0x03]);
    assert_eq!(tpl_bytes("u8(count(hex(\"123456\")))"), vec![0x03]);
    // 非列表 → 报错
    let err = tpl_err("count(1)");
    assert!(err.contains("需要列表"), "{err}");
}

/// len：字节数——eng_lib 库值函数（`func len(x) -> int { count(raw(x)) }`，
/// 经 prelude 隐式可见；字符串按 UTF-8、字节列表原样）。
#[test]
fn len_primitive() {
    assert_eq!(tpl_bytes("u8(len(\"abc\"))"), vec![0x03]);
    assert_eq!(tpl_bytes("u8(len(\"\"))"), vec![0x00]);
    assert_eq!(tpl_bytes("u8(len(\"中\"))"), vec![0x03], "UTF-8 三字节");
    assert_eq!(tpl_bytes("u8(len(hex(\"1234\")))"), vec![0x02]);
    assert_eq!(tpl_bytes("u8(len(hex(\"\")))"), vec![0x00]);
    // 非字符串/字节列表 → 报错（raw 值位置拒绝整数）
    let err = tpl_err("len(1)");
    assert!(err.contains("需要字符串"), "{err}");
}

/// rand_bytes(n)：构建期随机 n 字节（字节方向随机，与 rand16/rand8 整数方向互补）。
#[test]
fn rand_bytes_primitive() {
    // 长度与范围（Vec<u8> 即保证 0..255）
    let bytes = tpl_bytes("rand_bytes(4)");
    assert_eq!(bytes.len(), 4);
    // 0 长度 = 空
    assert_eq!(tpl_bytes("rand_bytes(0)"), Vec::<u8>::new());
    // 拼接进字节输出（值位置字节上下文畅通）
    let bytes = tpl_bytes("concat(hex(\"00\"), rand_bytes(2), hex(\"ff\"))");
    assert_eq!(bytes.len(), 4);
    assert_eq!(bytes[0], 0x00);
    assert_eq!(bytes[3], 0xff);
    // 库 rand_mac = rand_bytes(6) 仍产出 6 字节
    assert_eq!(tpl_bytes("rand_mac()").len(), 6);
    // 负数（无一元负号字面量，经 params 形状解析注入）→ 报错
    let err = tpl_err("rand_bytes(params(\"n\", \"-1\"))");
    assert!(err.contains("非负"), "{err}");
    // 超包长上限 → 报错
    let err = tpl_err("rand_bytes(70000)");
    assert!(err.contains("上限"), "{err}");
    // 非整数 → 报错
    let err = tpl_err("rand_bytes(\"x\")");
    assert!(err.contains("整数"), "{err}");
}

/// pad(n)：n 个零字节（确定性填充——与 rand_bytes 对称）。
#[test]
fn pad_primitive() {
    assert_eq!(tpl_bytes("pad(4)"), vec![0, 0, 0, 0]);
    assert_eq!(tpl_bytes("pad(0)"), Vec::<u8>::new());
    // 拼接（如以太网最小帧填充）
    let joined = tpl_bytes("concat(hex(\"deadbeef\"), pad(2))");
    assert_eq!(joined, vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
    // 负数（无一元负号字面量，经 params 形状解析注入）→ 报错
    let err = tpl_err("pad(params(\"n\", \"-1\"))");
    assert!(err.contains("非负"), "{err}");
    // 超包长上限 → 报错
    let err = tpl_err("pad(70000)");
    assert!(err.contains("上限"), "{err}");
    // 非整数 → 报错
    let err = tpl_err("pad(\"x\")");
    assert!(err.contains("整数"), "{err}");
}

// ── 变长整数（varint / qvarint：eng_lib/vint.pkt 库 proto 值位置调用）──

/// varint：protobuf base-128/LEB128 变长整数（最小字节数，每字节 7 位 + 续延位）。
#[test]
fn varint_primitive() {
    assert_eq!(tpl_bytes("varint(0)"), vec![0x00]);
    assert_eq!(tpl_bytes("varint(1)"), vec![0x01]);
    assert_eq!(tpl_bytes("varint(127)"), vec![0x7f]);
    assert_eq!(tpl_bytes("varint(128)"), vec![0x80, 0x01]);
    assert_eq!(tpl_bytes("varint(300)"), vec![0xac, 0x02]);
    assert_eq!(tpl_bytes("varint(16383)"), vec![0xff, 0x7f]);
    assert_eq!(tpl_bytes("varint(16384)"), vec![0x80, 0x80, 0x01]);
    // i64::MAX = 2^63-1（9 字节：8×0xff + 0x7f）
    assert_eq!(
        tpl_bytes("varint(9223372036854775807)"),
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]
    );
    // 负数（无一元负号字面量，经 params 形状解析注入）→ 报错
    let err = tpl_err("varint(params(\"n\", \"-1\"))");
    assert!(err.contains("非负"), "{err}");
    // 非整数 → 报错
    let err = tpl_err("varint(\"x\")");
    assert!(err.contains("整数"), "{err}");
}

/// qvarint：QUIC 变长整数（RFC 9000 §16 官方示例——2 位长度前缀 1/2/4/8 字节）。
#[test]
fn qvarint_primitive() {
    assert_eq!(tpl_bytes("qvarint(0)"), vec![0x00]);
    assert_eq!(tpl_bytes("qvarint(63)"), vec![0x3f]);
    assert_eq!(tpl_bytes("qvarint(64)"), vec![0x40, 0x40]);
    assert_eq!(tpl_bytes("qvarint(16383)"), vec![0x7f, 0xff]);
    assert_eq!(tpl_bytes("qvarint(16384)"), vec![0x80, 0x00, 0x40, 0x00]);
    assert_eq!(
        tpl_bytes("qvarint(1073741823)"),
        vec![0xbf, 0xff, 0xff, 0xff]
    );
    assert_eq!(
        tpl_bytes("qvarint(1073741824)"),
        vec![0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        tpl_bytes("qvarint(4611686018427387903)"),
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    // 负数 → 报错；超 2^62-1 → 报错
    let err = tpl_err("qvarint(params(\"n\", \"-1\"))");
    assert!(err.contains("非负"), "{err}");
    let err = tpl_err("qvarint(4611686018427387904)");
    assert!(err.contains("上限"), "{err}");
}

/// eng_lib/quic.pkt：Initial 长头（proto 自表示）/ 短头 / CRYPTO 帧字节结构（RFC 9000）。
#[test]
fn quic_lib_builds_initial() {
    // quic_initial 现在是 proto（声明式）：字段即参数，命名调用；产物为 Raw 层字节
    // quic_crypto 现在是 proto（层位置）；concat 里需要值函数 → 内联 func 副本遮蔽 prelude
    let inline_qc = "func quic_crypto(offset=0, data=\"\") -> bytes { concat(u8(0x06), qvarint(offset), qvarint(len(data)), raw(data)) }\n";
    let init = |extra: &str| {
        let src = format!(
            "{inline_qc}q = quic_initial(dcid=hex(\"8394c8f03e515708\"), scid=hex(\"fdfd0d050a0b0c0d\"), version=0x00000001, pnl=0, pn=u8(0), token=\"\"{extra})\nexport:\n- q\n"
        );
        let m = packet_dsl::semantic::parse_str("t", &src).unwrap();
        let built = packet_dsl::resolve(&m).unwrap();
        packet_dsl::DefaultSerializer::with_seed(1)
            .serialize(&built.packets[0])
            .unwrap()
    };
    // 空 token/payload：c0 | version | dcid(8) | scid(8) | tokenlen(0) | len(1) | pn(00)
    let got = init(", payload=\"\"");
    assert_eq!(
        got,
        hexvec("c000000001088394c8f03e51570808fdfd0d050a0b0c0d000100")
    );
    // CRYPTO 帧（06 00 02 43 48）+ PADDING(2)：@auto len = pn(1) + payload(7) = 8
    let got = init(", payload=concat(quic_crypto(0, \"CH\"), pad(2))");
    assert_eq!(
        got,
        hexvec("c000000001088394c8f03e51570808fdfd0d050a0b0c0d00080006000243480000")
    );
    // 2 字节包号（pnl=1）：首字节 c1，pn_field 宽度 = band(first,3)+1 = 2，len = 02
    let src = "q = quic_initial(dcid=hex(\"8394c8f03e515708\"), scid=hex(\"fdfd0d050a0b0c0d\"), version=0x00000001, pnl=1, pn=be16(0x1234), token=\"\", payload=\"\")\nexport:\n- q\n";
    let m = packet_dsl::semantic::parse_str("t", src).unwrap();
    let built = packet_dsl::resolve(&m).unwrap();
    let got = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&built.packets[0])
        .unwrap();
    assert_eq!(
        got,
        hexvec("c100000001088394c8f03e51570808fdfd0d050a0b0c0d00021234")
    );
    // 短头：0x40 | pnl，无 version/scid/长度字段（DCID 长度由连接上下文隐含）
    let got = tpl_bytes("quic_short(hex(\"8394c8f03e515708\"), 0, u8(0), pad(1))");
    assert_eq!(got, hexvec("408394c8f03e5157080000"));
}

/// `-> int` 值函数：整数原语/加法组合 + 返回类型运行时校验（lambda/map/filter/
/// 多态折叠已移除，整数计算由 count/len/位运算/`+` 原语提供）。
#[test]
fn int_value_func() {
    assert_eq!(
        tpl_bytes_pfx("func double(x) -> int { x + x }\n", "be16(double(0x1234))"),
        vec![0x24, 0x68],
        "double(0x1234) = 0x2468"
    );
    // -> int 返回非整数 → 报错
    let err = tpl_err_pfx("func badint(x) -> int { be16(x) }\n", "be16(badint(1))");
    assert!(err.contains("需要整数"), "{err}");
}

// ── parse_value_expr / eval_extract_value（配方 extract 表达式）────────────

/// 配方 `from:` 表达式解析：单个值表达式（含 `reply(...)` 调用形态）。
#[test]
fn parse_value_expr_basics() {
    use packet_dsl::ast::Value;
    // 纯调用
    let v = packet_dsl::parser::parse_value_expr(r#"reply("icmp", "seq") + 1"#).unwrap();
    let Value::BinOp {
        op: BinOp::Add,
        left,
        right,
        ..
    } = &v
    else {
        panic!("应为 BinOp(Add)，得到 {v:?}");
    };
    let Value::Call { name, args, .. } = &**left else {
        panic!("左操作数应为 reply 调用，得到 {left:?}");
    };
    assert_eq!(name, "reply");
    assert_eq!(args, &[Value::Str("icmp".into()), Value::Str("seq".into())]);
    assert!(matches!(**right, Value::Int(1)));

    // 嵌套：cksum(reply("icmp", "payload"))
    let v = packet_dsl::parser::parse_value_expr(r#"cksum(reply("icmp", "payload"))"#).unwrap();
    let Value::Call { name, .. } = &v else {
        panic!("应为 cksum 调用，得到 {v:?}");
    };
    assert_eq!(name, "cksum");

    // 非法表达式 → 报错
    assert!(packet_dsl::parser::parse_value_expr("reply(").is_err());
    assert!(packet_dsl::parser::parse_value_expr("1 +").is_err());
}

/// eval_extract_value：reply 访问器注入 → 表达式求值为类型化值；
/// 可组合 global/params/用户值函数。
#[test]
fn eval_extract_value_with_reply() {
    use packet_dsl::ast::Value;
    // 模块：用户值函数（from 表达式可调用同文件 func）
    let src = "func doubled(x) -> int { x + x }\n";
    let m = packet_dsl::semantic::parse_str("t", src).unwrap();
    let mut params = packet_dsl::Params::new();
    params.insert("off".to_string(), "5".to_string());
    let mut globals = packet_dsl::Globals::new();
    globals.insert("base".to_string(), Value::Int(100));

    // 回包访问器：icmp.seq = 7 → Int；icmp.payload = [0xde, 0xad] → 字节列表
    let reply = |layer: &str, field: &str| -> Option<Value> {
        match (layer, field) {
            ("icmp", "seq") => Some(Value::Int(7)),
            ("icmp", "payload") => Some(Value::List(vec![Value::Int(0xDE), Value::Int(0xAD)])),
            _ => None,
        }
    };

    // reply 叶子 + 加法
    let v = packet_dsl::parser::parse_value_expr(r#"reply("icmp", "seq") + 1"#).unwrap();
    assert_eq!(
        packet_dsl::eval_extract_value(Some(&m), &params, &globals, &reply, &v).unwrap(),
        Value::Int(8)
    );

    // 用户值函数（模块作用域）+ global + params
    let v =
        packet_dsl::parser::parse_value_expr(r#"doubled(reply("icmp", "seq")) + global("base")"#)
            .unwrap();
    assert_eq!(
        packet_dsl::eval_extract_value(Some(&m), &params, &globals, &reply, &v).unwrap(),
        Value::Int(114) // 7*2 + 100
    );

    // 字节字段原样返回（字节列表）
    let v = packet_dsl::parser::parse_value_expr(r#"reply("icmp", "payload")"#).unwrap();
    assert_eq!(
        packet_dsl::eval_extract_value(Some(&m), &params, &globals, &reply, &v).unwrap(),
        Value::List(vec![Value::Int(0xDE), Value::Int(0xAD)])
    );

    // cksum 对 payload 字节（dsl 求值 → 字节列表）
    let v = packet_dsl::parser::parse_value_expr(r#"cksum(reply("icmp", "payload"))"#).unwrap();
    let cksum = packet_dsl::eval_extract_value(Some(&m), &params, &globals, &reply, &v).unwrap();
    let Value::List(bytes) = cksum else {
        panic!("cksum 应为字节列表，得到 {cksum:?}");
    };
    assert_eq!(bytes.len(), 2);

    // 字段不存在 → 报错
    let v = packet_dsl::parser::parse_value_expr(r#"reply("icmp", "nope")"#).unwrap();
    let err = packet_dsl::eval_extract_value(Some(&m), &params, &globals, &reply, &v)
        .unwrap_err()
        .to_string();
    assert!(err.contains("回包没有 `icmp.nope` 字段"), "{err}");
}

/// eval_extract_value：无模块（None）时仅内置原语可用（用户函数报错）。
#[test]
fn eval_extract_value_builtin_only() {
    use packet_dsl::ast::Value;
    let reply = |layer: &str, field: &str| -> Option<Value> {
        match (layer, field) {
            ("icmp", "seq") => Some(Value::Int(3)),
            _ => None,
        }
    };
    let v = packet_dsl::parser::parse_value_expr(r#"be16(reply("icmp", "seq"))"#).unwrap();
    let val =
        packet_dsl::eval_extract_value(None, &Params::new(), &Globals::new(), &reply, &v).unwrap();
    assert_eq!(val, Value::List(vec![Value::Int(0), Value::Int(3)]));

    // 非 extract 上下文（reply 访问器未注入）→ reply 回退用户函数 → 未知函数报错
    let v = packet_dsl::parser::parse_value_expr(r#"reply("icmp", "seq")"#).unwrap();
    let err = packet_dsl::eval_sniffer_value(None, &Params::new(), &v)
        .unwrap_err()
        .to_string();
    assert!(err.contains("未知值函数或原语"), "{err}");
}
