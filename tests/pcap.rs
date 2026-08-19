//! pcap 读写测试：写读往返、链路类型推断。

use std::path::PathBuf;

use prping::{LinkType, PkgOptions, SendMode, read_pcap, write_pcap};

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("prping-pcap-{name}-{}.pcap", std::process::id()))
}

#[test]
fn pcap_roundtrip() {
    let path = temp("roundtrip");
    let packets = vec![
        vec![
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
        ],
        vec![
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0, 1, 2, 3, 4, 5, 0x08, 0x00,
        ],
    ];
    write_pcap(&path, LinkType::Raw, &packets).expect("写 pcap");
    let (network, nano, records) = read_pcap(&path).expect("读 pcap");
    assert_eq!(network, LinkType::Raw as u16);
    assert!(!nano);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].data, packets[0]);
    assert_eq!(records[1].data, packets[1]);
    assert!(records[0].ts_sec > 0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn linktype_inference() {
    let m = packet_dsl::semantic::parse_str(
        "t",
        "a = http()\nuse(a) |> tcp(dport=80) |> ipv4(dst=\"8.8.8.8\") |> eth()\n",
    )
    .unwrap();
    let pkt = packet_dsl::resolve(&m)
        .unwrap()
        .packets
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(prping::linktype_of(&pkt.layers), LinkType::Ethernet);
    let m2 = packet_dsl::semantic::parse_str("t", "a = http()\nuse(a) |> tcp(dport=80)\n").unwrap();
    let pkt2 = packet_dsl::resolve(&m2)
        .unwrap()
        .packets
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(prping::linktype_of(&pkt2.layers), LinkType::Raw);
}

/// --pkg --out：构建 + 存档（不发目标也能写 pcap）。
#[test]
fn pkg_out_writes_pcap() {
    let out = temp("pkg-out");
    let src = "a = dns(questions=[\"example.com\"])\nuse(a) |> udp(dport=53) |> ipv4(dst=\"8.8.8.8\") |> eth()\n";
    let file = std::env::temp_dir().join(format!("prping-pkg-out-{}.pkt", std::process::id()));
    std::fs::write(&file, src).unwrap();
    let opts = PkgOptions {
        mode: SendMode::Payload,
        out: Some(out.clone()),
        ..Default::default()
    };
    // 目标缺失会失败，但 --out 应已写文件；这里显式给目标避免失败
    let target = "127.0.0.1:9".parse().unwrap();
    let _ = send_packets2(&file, target, &opts);
    assert!(out.exists(), "pcap 应已写出");
    let (_, _, records) = read_pcap(&out).expect("读 pcap");
    assert_eq!(records.len(), 1);
    std::fs::remove_file(&out).ok();
    std::fs::remove_file(&file).ok();
}

// 辅助：显式目标版本（target 不在 PkgOptions 里）
fn send_packets2(
    file: &std::path::Path,
    target: std::net::SocketAddr,
    opts: &PkgOptions,
) -> anyhow::Result<()> {
    let mut o = PkgOptions {
        target: Some(target),
        ..opts.clone()
    };
    o.target = Some(target);
    prping::send_packets(file, &o)
}
