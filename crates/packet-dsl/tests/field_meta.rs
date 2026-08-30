//! proto 字段原语测试：`#[meta(switch/cases)]` 判别式分派、`#[meta(if)]`
//! 条件在场、`#[meta(bits)]` 多字节位组、窗口内重复（`bytes=` + `rest=`）
//! ——构造 golden + 反解 + 降级路径。

mod common;

use packet_dsl::{DefaultSerializer, Serializer, semantic};

/// 测试协议集：与 eng_lib 一起一次注册（OnceLock 首次生效）。
const SRC: &str = r#"
# switch：rdata 按 rtype 分派（无宽度 = 窗口到缓冲区末尾）
#[proto]
func rdata_a(addr="") -> bytes {
    concat(#[meta(bytes="4")] addr)
}

#[proto]
func rdata_aaaa(addr="") -> bytes {
    concat(#[meta(bytes="16")] addr)
}

#[rule(ipv4(proto=112))]
#[proto]
func ans_sw(rtype=1, rdata="") -> bytes {
    concat(
        u8(rtype),
        #[meta(switch="rtype", cases=[[1, "rdata_a"], [28, "rdata_aaaa"]])] rdata,
    )
}

# switch 有界窗口：bytes="rdlen"（升级自 `bytes="rdlen"` 直通的 DNS rdata 形态）
#[rule(ipv4(proto=113))]
#[proto]
func ans_bounded(rtype=1, rdata="") -> bytes {
    concat(
        u8(rtype),
        #[meta(len="rdata")] be16(rdlen),
        #[meta(switch="rtype", cases=[[1, "rdata_a"]], bytes="rdlen")] rdata,
    )
}

# if 条件在场守卫：flags bit1 非零 → be32 key 在场（GRE 可选字段同构）
#[rule(ipv4(proto=114))]
#[proto]
func cond_key(flags=0, key=0) -> bytes {
    concat(
        u8(flags),
        #[meta(if="band(shr(flags, 1), 1)")] be32(key),
    )
}

# bits 多字节位组：4+8+20 = 32 位（IPv6 version/TC/flow-label 同构）
#[rule(ipv4(proto=115))]
#[proto]
func v6ish(tc=0, flow=0) -> bytes {
    concat(
        #[meta(name="version", bits=4)] u8(6),
        #[meta(bits=8)] u8(tc),
        #[meta(bits=20)] be32(flow),
    )
}

# 窗口内重复：bytes= 窗口 + rest= 子proto（TCP options 同构——
# 窗口由 doff 界定，元素 = 自描述 TLV，val 长度引用同 proto 前序字段 len）
#[proto]
func tcp_opt(kind=1, len=2, val="") -> bytes {
    concat(
        u8(kind),
        #[meta(if="band(kind, 0xFE)")] u8(len),
        #[meta(if="band(kind, 0xFE)", bytes="sub(len, 2)")] val,
    )
}

#[rule(ipv4(proto=116))]
#[proto]
func tcpish(doff=0, options="", payload="") -> bytes {
    concat(
        u8(doff),
        #[meta(bytes="doff", rest="tcp_opt")] options,
        #[meta(rest)] payload,
    )
}
"#;

fn register() {
    let mut protos = common::collect_eng_lib_protos();
    let m = semantic::parse_str("field_meta_protos", SRC).unwrap();
    protos.extend(m.protos.iter().map(|p| {
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
    packet_dsl::set_proto_registry(protos);
}

/// 构造首个包并序列化为字节（proto 定义与构建语句同一模块——库导出
/// prelude 只含 eng_lib，测试 proto 须随源拼接）。
fn build(src: &str) -> Vec<u8> {
    let combined = format!("{SRC}\n{src}");
    let m = semantic::parse_str("field_meta_test", &combined).unwrap();
    let pkt = packet_dsl::resolve(&m)
        .unwrap()
        .packets
        .into_iter()
        .next()
        .unwrap();
    DefaultSerializer::with_seed(1).serialize(&pkt).unwrap()
}

fn field<'a>(hit: &'a packet_dsl::ProtoHit, name: &str) -> Option<&'a packet_dsl::ProtoVal> {
    hit.fields.iter().find(|(n, _)| n == name).map(|(_, v)| v)
}

// ── switch：判别式分派 ─────────────────────────────────────────

/// rtype=1 → 分派到 rdata_a（4 字节），子命中进 subs，字段值 = 窗口字节。
#[test]
fn switch_dispatches_by_field_value() {
    register();
    let bytes = build(
        "p = ans_sw(rtype=1, rdata=hex(\"aabbccdd\"))\nuse(p) |> ipv4(src=\"1.1.1.1\", dst=\"2.2.2.2\", proto=112)\n",
    );
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "ans_sw").unwrap();
    assert_eq!(field(hit, "rtype"), Some(&packet_dsl::ProtoVal::Int(1)));
    assert_eq!(
        field(hit, "rdata"),
        Some(&packet_dsl::ProtoVal::Bytes(vec![0xaa, 0xbb, 0xcc, 0xdd]))
    );
    assert_eq!(hit.subs.len(), 1);
    assert_eq!(hit.subs[0].name, "rdata_a");
    assert_eq!(
        field(&hit.subs[0], "addr"),
        Some(&packet_dsl::ProtoVal::Bytes(vec![0xaa, 0xbb, 0xcc, 0xdd]))
    );
}

/// rtype=28 → 分派到 rdata_aaaa（16 字节）。
#[test]
fn switch_selects_other_case() {
    register();
    let bytes = build(
        "p = ans_sw(rtype=28, rdata=hex(\"0102030405060708090a0b0c0d0e0f10\"))\nuse(p) |> ipv4(src=\"1.1.1.1\", dst=\"2.2.2.2\", proto=112)\n",
    );
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "ans_sw").unwrap();
    assert_eq!(hit.subs.len(), 1);
    assert_eq!(hit.subs[0].name, "rdata_aaaa");
}

/// 有界窗口 + 未知判别值 → 整窗不透明字节（优雅降级，无子命中）。
#[test]
fn switch_bounded_degrades_to_opaque_on_unknown_value() {
    register();
    let bytes = build(
        "p = ans_bounded(rtype=99, rdata=hex(\"deadbeef\"))\nuse(p) |> ipv4(src=\"1.1.1.1\", dst=\"2.2.2.2\", proto=113)\n",
    );
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "ans_bounded").unwrap();
    assert_eq!(field(hit, "rdlen"), Some(&packet_dsl::ProtoVal::Int(4)));
    assert_eq!(
        field(hit, "rdata"),
        Some(&packet_dsl::ProtoVal::Bytes(vec![0xde, 0xad, 0xbe, 0xef]))
    );
    assert!(hit.subs.is_empty(), "未知 rtype 不应产生子命中");
}

/// 有界窗口 + 命中 → 结构化子命中（`bytes="rdlen"` 直通的严格超集）。
#[test]
fn switch_bounded_structured_hit() {
    register();
    let bytes = build(
        "p = ans_bounded(rtype=1, rdata=hex(\"aabbccdd\"))\nuse(p) |> ipv4(src=\"1.1.1.1\", dst=\"2.2.2.2\", proto=113)\n",
    );
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "ans_bounded").unwrap();
    assert_eq!(hit.subs.len(), 1);
    assert_eq!(hit.subs[0].name, "rdata_a");
}

// ── if：条件在场守卫 ───────────────────────────────────────────

/// flags bit1 = 0 → key 缺席（构造只有 1 字节）。
#[test]
fn if_absent_skips_field_on_construct() {
    register();
    let bytes = build("p = cond_key(flags=0)\nuse(p)\n");
    assert_eq!(bytes, vec![0x00], "条件为假：只编码 flags 一个字节");
}

/// flags bit1 = 1 → key 在场（5 字节 golden）。
#[test]
fn if_present_encodes_field() {
    register();
    let bytes = build("p = cond_key(flags=2, key=1)\nuse(p)\n");
    assert_eq!(bytes, vec![0x02, 0x00, 0x00, 0x00, 0x01]);
}

/// 解析侧对称：条件为假消费 0 位（key 缺席），为真正常解码。
#[test]
fn if_parse_symmetric() {
    register();
    // 缺席：payload = [0x00]
    let bytes = build(
        "p = cond_key(flags=0)\nuse(p) |> ipv4(src=\"1.1.1.1\", dst=\"2.2.2.2\", proto=114)\n",
    );
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "cond_key").unwrap();
    assert_eq!(field(hit, "flags"), Some(&packet_dsl::ProtoVal::Int(0)));
    assert_eq!(
        field(hit, "key"),
        Some(&packet_dsl::ProtoVal::Bytes(Vec::new())),
        "条件为假：key 消费 0 位（空字节 = 缺席）"
    );
    // 在场：payload = [0x02, 0,0,0,1]
    let bytes = build(
        "p = cond_key(flags=2, key=1)\nuse(p) |> ipv4(src=\"1.1.1.1\", dst=\"2.2.2.2\", proto=114)\n",
    );
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "cond_key").unwrap();
    assert_eq!(field(hit, "key"), Some(&packet_dsl::ProtoVal::Int(1)));
}

// ── bits：多字节位组 ───────────────────────────────────────────

/// 4+8+20 = 32 位组跨 4 字节：构造 golden 0x61 0x23 0x45 0x67。
#[test]
fn bits_multibyte_group_golden() {
    register();
    let bytes = build("p = v6ish(tc=0x12, flow=0x34567)\nuse(p)\n");
    assert_eq!(
        bytes,
        vec![0x61, 0x23, 0x45, 0x67],
        "version(6)+tc(0x12)+flow(0x34567) 大端位序打包"
    );
}

/// 解析侧对称：同一字节反解出三个位字段（IPv6 first4 常量做不到的场景）。
#[test]
fn bits_multibyte_group_parse() {
    register();
    let bytes = build(
        "p = v6ish(tc=0x12, flow=0x34567)\nuse(p) |> ipv4(src=\"1.1.1.1\", dst=\"2.2.2.2\", proto=115)\n",
    );
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "v6ish").unwrap();
    assert_eq!(field(hit, "version"), Some(&packet_dsl::ProtoVal::Int(6)));
    assert_eq!(field(hit, "tc"), Some(&packet_dsl::ProtoVal::Int(0x12)));
    assert_eq!(
        field(hit, "flow"),
        Some(&packet_dsl::ProtoVal::Int(0x34567))
    );
}

/// u8 单字节位组行为不变（IPv4 version+ihl = 0x45 回归）。
#[test]
fn bits_u8_group_unchanged() {
    register();
    let bytes = build("p = v6ish(tc=0, flow=0)\nuse(p)\n");
    assert_eq!(bytes, vec![0x60, 0x00, 0x00, 0x00]);
}

// ── 负路径：声明错误 ───────────────────────────────────────────

/// bits 超出类型容量 → 语义错误。
#[test]
fn bits_over_capacity_rejected() {
    let src = r#"
#[proto]
func bad(x=0) -> bytes {
    concat(#[meta(bits=12)] u8(x))
}
"#;
    let err = semantic::parse_str("bits_cap", src).unwrap_err();
    assert!(err.message.contains("超出该类型容量"), "{err:?}");
}

/// switch 缺 cases 表 → 解析错误。
#[test]
fn switch_requires_cases() {
    let src = r#"
#[proto]
func sub() -> bytes {
    concat(u8(1))
}

#[proto]
func bad(rtype=1, rdata="") -> bytes {
    concat(u8(rtype), #[meta(switch="rtype")] rdata)
}
"#;
    let err = semantic::parse_str("sw_cases", src).unwrap_err();
    assert!(err.message.contains("cases"), "{err:?}");
}

/// cases 缺 switch → 语义错误。
#[test]
fn cases_requires_switch() {
    let src = r#"
#[proto]
func sub() -> bytes {
    concat(u8(1))
}

#[proto]
func bad(rtype=1, rdata="") -> bytes {
    concat(u8(rtype), #[meta(cases=[[1, "sub"]])] rdata)
}
"#;
    let err = semantic::parse_str("cases_sw", src).unwrap_err();
    assert!(err.message.contains("switch"), "{err:?}");
}

/// if 条件字段与 bits 互斥 → 语义错误。
#[test]
fn if_conflicts_with_bits() {
    let src = r#"
#[proto]
func bad(flag=0, x=0) -> bytes {
    concat(
        u8(flag),
        #[meta(if="flag", bits=4)] u8(x),
    )
}
"#;
    let err = semantic::parse_str("if_bits", src).unwrap_err();
    assert!(err.message.contains("if 条件字段"), "{err:?}");
}

// ── 窗口内重复：bytes= 窗口 + rest= 子proto ────────────────────

/// 构造：元素经子 proto 逐项编码，窗口宽度校验元素总长（doff=5）。
#[test]
fn windowed_rest_construct_golden() {
    register();
    let bytes = build(
        "p = tcpish(doff=5, options=concat(tcp_opt(2, 4, hex(\"05b4\")), tcp_opt(1)), payload=hex(\"cafe\"))\nuse(p)\n",
    );
    assert_eq!(
        bytes,
        vec![0x05, 0x02, 0x04, 0x05, 0xb4, 0x01, 0xca, 0xfe],
        "doff(1B) | mss 选项(4B: kind=2 len=4 val=05b4) | nop(1B: kind=1) | payload"
    );
}

/// 窗口宽度与元素总长不符 → 构造报错（Bytes 宽度校验，在 proto 求值时触发）。
#[test]
fn windowed_rest_construct_width_mismatch() {
    register();
    let src = "p = tcpish(doff=4, options=hex(\"020405b401\"), payload=hex(\"cafe\"))\nuse(p)\n";
    let m = semantic::parse_str("field_meta_test", &format!("{SRC}\n{src}")).unwrap();
    let err = packet_dsl::resolve(&m).unwrap_err();
    assert!(err.to_string().contains("宽度"), "{err}");
}

/// 解析：窗口内恰好耗尽 → 两个子命中（mss + nop），payload 正常续读。
#[test]
fn windowed_rest_parse_structured() {
    register();
    let bytes = build(
        "p = tcpish(doff=5, options=hex(\"020405b401\"), payload=hex(\"cafe\"))\nuse(p) |> ipv4(src=\"1.1.1.1\", dst=\"2.2.2.2\", proto=116)\n",
    );
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "tcpish").unwrap();
    assert_eq!(
        field(hit, "options"),
        Some(&packet_dsl::ProtoVal::Bytes(vec![
            0x02, 0x04, 0x05, 0xb4, 0x01
        ]))
    );
    assert_eq!(hit.subs.len(), 2, "窗口内两个选项元素");
    assert_eq!(hit.subs[0].name, "tcp_opt");
    assert_eq!(
        field(&hit.subs[0], "kind"),
        Some(&packet_dsl::ProtoVal::Int(2))
    );
    assert_eq!(
        field(&hit.subs[0], "len"),
        Some(&packet_dsl::ProtoVal::Int(4))
    );
    assert_eq!(
        field(&hit.subs[0], "val"),
        Some(&packet_dsl::ProtoVal::Bytes(vec![0x05, 0xb4]))
    );
    assert_eq!(hit.subs[1].name, "tcp_opt");
    assert_eq!(
        field(&hit.subs[1], "kind"),
        Some(&packet_dsl::ProtoVal::Int(1))
    );
    assert_eq!(
        field(&hit.subs[1], "val"),
        Some(&packet_dsl::ProtoVal::Bytes(Vec::new())),
        "NOP（kind=1）无 len/val——if 条件为假各消费 0 位"
    );
    assert_eq!(
        field(hit, "payload"),
        Some(&packet_dsl::ProtoVal::Bytes(vec![0xca, 0xfe])),
        "窗口之后的 payload 由 rest 字段正常续读"
    );
}

/// 元素在窗口内截断（len 超出剩余）→ 整窗不透明字节降级，payload 不受影响。
#[test]
fn windowed_rest_parse_degrades_on_truncated_element() {
    register();
    let bytes = build(
        "p = tcpish(doff=3, options=hex(\"0205ab\"), payload=hex(\"beef\"))\nuse(p) |> ipv4(src=\"1.1.1.1\", dst=\"2.2.2.2\", proto=116)\n",
    );
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "tcpish").unwrap();
    assert_eq!(
        field(hit, "options"),
        Some(&packet_dsl::ProtoVal::Bytes(vec![0x02, 0x05, 0xab])),
        "kind=2 len=5 但窗口只剩 1 字节 → 元素失败 → 整窗不透明"
    );
    assert!(hit.subs.is_empty(), "未耗尽窗口不产生子命中");
    assert_eq!(
        field(hit, "payload"),
        Some(&packet_dsl::ProtoVal::Bytes(vec![0xbe, 0xef]))
    );
}

/// 空窗口（doff=0）→ 空字节、无子命中，后续字段照常。
#[test]
fn windowed_rest_empty_window() {
    register();
    let bytes = build("p = tcpish(doff=0, options=hex(\"\"), payload=hex(\"ff\"))\nuse(p)\n");
    assert_eq!(bytes, vec![0x00, 0xff], "裸包：doff(1B) + 空窗口 + payload");
    let bytes = build(
        "p = tcpish(doff=0, options=hex(\"\"), payload=hex(\"ff\"))\nuse(p) |> ipv4(src=\"1.1.1.1\", dst=\"2.2.2.2\", proto=116)\n",
    );
    let r = packet_dsl::dissect(&bytes);
    let hit = r.proto.iter().find(|h| h.name == "tcpish").unwrap();
    assert_eq!(
        field(hit, "options"),
        Some(&packet_dsl::ProtoVal::Bytes(Vec::new()))
    );
    assert!(hit.subs.is_empty());
    assert_eq!(
        field(hit, "payload"),
        Some(&packet_dsl::ProtoVal::Bytes(vec![0xff]))
    );
}

/// 窗口内重复与 list= 计数同设 → 语义错误（窗口本身就是停止条件）。
#[test]
fn windowed_rest_conflicts_with_list() {
    let src = r#"
#[proto]
func elem(a=1) -> bytes {
    concat(u8(a))
}

#[proto]
func bad(n=1, count=1, xs="") -> bytes {
    concat(u8(n), #[meta(bytes="n", rest="elem", list="count", item="elem")] xs)
}
"#;
    let err = semantic::parse_str("win_list", src).unwrap_err();
    assert!(err.message.contains("不与 `list=` 计数同设"), "{err:?}");
}
