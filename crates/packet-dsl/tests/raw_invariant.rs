//! raw 双轨不变式（`ir.rs` 模块文档）：proto 构造的语义层，`raw` 头字节是线上
//! 权威——序列化（raw 分支 + 定点补 length/checksum）后**层长不变**，自动字段
//! 只就地改写、不重编头。任何层构造路径破坏此不变式即在此暴露。
//!
//! 源码形态：顶层裸层调用不是合法语句（语句 = def/import/export/pipeline/use），
//! 故用 `c = <层调用>` + `export:` 构造单包单层的默认求值路径。

use packet_dsl::{DefaultSerializer, Serializer, layer_raw_bytes, parse_str, resolve};

fn check(kind: &str, layer_call: &str) {
    let src = format!("c = {layer_call}\nexport:\n- c\n");
    let module = parse_str("raw_invariant", &src).expect("解析失败");
    let built = resolve(&module).expect("求值失败");
    assert_eq!(built.packets.len(), 1, "{kind}");
    let pkt = &built.packets[0];
    assert_eq!(pkt.layers.len(), 1, "{kind}: 单层构造");
    let raw = layer_raw_bytes(&pkt.layers[0])
        .unwrap_or_else(|| panic!("{kind}: 语义层应携带 raw 头字节"))
        .to_vec();
    assert!(!raw.is_empty(), "{kind}");
    let bytes = DefaultSerializer::with_seed(1)
        .serialize(pkt)
        .unwrap_or_else(|e| panic!("{kind}: 序列化失败：{e}"));
    assert_eq!(
        bytes.len(),
        raw.len(),
        "{kind}: 序列化不得改变层长（raw 直通 + 定点补齐）"
    );
}

#[test]
fn raw_length_invariant_all_kinds() {
    // 全部 9 种层构造（headers.pkt proto 全默认字段）；
    // tcp 构造侧尚未迁移 typed_layer（产 Raw 载荷层），不变式同样适用
    for (kind, layer_call) in [
        ("eth", "eth()"),
        ("arp", "arp()"),
        ("ipv4", "ipv4()"),
        ("ipv6", "ipv6()"),
        ("icmp", "icmp()"),
        ("tcp", "tcp(dport=80)"),
        ("udp", "udp(dport=53)"),
        ("http", "http()"),
        ("dns", "dns()"),
    ] {
        check(kind, layer_call);
    }
}

#[test]
fn auto_fields_are_patched_in_place() {
    // ipv4 的 total_length/checksum 占位必须被就地补齐（输出 ≠ 构建字节），
    // 且长度不变——证明 raw 分支是"定点补齐"而不是整段重编
    let module = parse_str("raw_invariant", "c = ipv4()\nexport:\n- c\n").unwrap();
    let built = resolve(&module).unwrap();
    let pkt = &built.packets[0];
    let raw = layer_raw_bytes(&pkt.layers[0]).unwrap().to_vec();
    let bytes = DefaultSerializer::with_seed(1).serialize(pkt).unwrap();
    assert_eq!(bytes.len(), raw.len());
    assert_ne!(bytes, raw, "ipv4 自动 length/checksum 应被定点补齐");
}
