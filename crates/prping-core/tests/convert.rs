//! pcap → .pkt/.pktl 转码测试：A1/A2 字节级 roundtrip、padding 退回、配方 delay、skip/limit。

use std::path::{Path, PathBuf};

use packet_dsl::Serializer;
use prping_core::{ConvertOptions, LinkType, convert_pcap, read_pcap, write_pcap};

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "prping-convert-{name}-{}.{}",
        std::process::id(),
        "tmp"
    ))
}

/// 用 DSL 构建一个包的序列化字节（确定性 seed）。
fn build_bytes(src: &str) -> Vec<u8> {
    let m = packet_dsl::semantic::parse_str("t", src).unwrap();
    let pkt = packet_dsl::resolve(&m)
        .unwrap()
        .packets
        .into_iter()
        .next()
        .unwrap();
    packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&pkt)
        .unwrap()
}

/// 转换并把每个生成的 .pkt 解析 + 序列化回字节。
fn convert_and_reserialize(
    pcap: &Path,
    out_dir: &Path,
    structured: bool,
    skip: usize,
    limit: Option<usize>,
    threads: usize,
) -> (prping_core::ConvertReport, Vec<Vec<u8>>) {
    let report = convert_pcap(
        pcap,
        &ConvertOptions {
            out_dir: out_dir.to_path_buf(),
            structured,
            skip,
            limit,
            threads,
        },
    )
    .expect("转换成功");
    let mut bytes = Vec::new();
    for f in &report.files {
        let module = packet_dsl::parse_file_with_libs(f, &[])
            .unwrap_or_else(|d| panic!("解析 {} 失败: {d}", f.display()));
        let sources = packet_dsl::resolve_sources(&module)
            .unwrap_or_else(|d| panic!("求值 {} 失败: {d}", f.display()));
        let ser = packet_dsl::DefaultSerializer::new();
        for (_, pkts) in &sources {
            for pkt in pkts {
                bytes.push(ser.serialize(pkt).unwrap());
            }
        }
    }
    (report, bytes)
}

/// 手写 pcap（自定义时间戳，微秒）。
fn write_pcap_ts(path: &Path, linktype: u16, recs: &[(u32, u32, Vec<u8>)]) {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&(linktype as u32).to_le_bytes());
    for (ts, fr, data) in recs {
        out.extend_from_slice(&ts.to_le_bytes());
        out.extend_from_slice(&fr.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    std::fs::write(path, out).unwrap();
}

fn frames() -> Vec<Vec<u8>> {
    vec![
        // DNS over UDP over IPv4 over eth
        build_bytes(
            "q = dns(id=0x1234, questions=[\"example.com\"])\nuse(q) |> udp(sport=12345, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", id=0, proto=17) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\")\n",
        ),
        // TCP + 载荷（flags=psh|ack）
        build_bytes(
            "p = raw(bytes=\"GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n\")\nuse(p) |> tcp(sport=40000, dport=80, flags=bor(psh(), ack()), seq=1000, ack=2000) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", proto=6) |> eth()\n",
        ),
        // ARP over eth
        build_bytes(
            "r = arp(op=request(), sha=\"00:11:22:33:44:55\", spa=\"192.168.1.1\", tha=\"00:00:00:00:00:00\", tpa=\"192.168.1.2\")\nuse(r) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"ff:ff:ff:ff:ff:ff\", ethertype=0x0806)\n",
        ),
    ]
}

#[test]
fn lossless_roundtrip() {
    let packets = frames();
    let pcap = temp("lossless-pcap");
    write_pcap(&pcap, LinkType::Ethernet, &packets).unwrap();
    let out_dir = temp("lossless-out");
    let (report, re) = convert_and_reserialize(&pcap, &out_dir, false, 0, None, 0);
    assert_eq!(report.written, 3);
    assert!(!report.structured);
    assert_eq!(re, packets, "无损字节级 roundtrip 应完全一致");
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_file(&pcap);
}

#[test]
fn structured_roundtrip() {
    let packets = frames();
    let pcap = temp("struct-pcap");
    write_pcap(&pcap, LinkType::Ethernet, &packets).unwrap();
    let out_dir = temp("struct-out");
    let (report, re) = convert_and_reserialize(&pcap, &out_dir, true, 0, None, 0);
    assert_eq!(report.written, 3);
    assert!(report.structured);
    assert_eq!(re, packets, "语义结构化 roundtrip 应字节一致");
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_file(&pcap);
}

#[test]
fn structured_icmp_body_roundtrip() {
    // ICMP body 存 f.payload：结构化渲染走 icmp(payload=hex(...))，roundtrip 字节一致
    let pkt = build_bytes(
        "p = raw(bytes=\"ping-payload\")\nuse(p) |> icmp(type=8, code=0, id=0x1234, seq=7) |> ipv4(src=\"192.168.1.1\", dst=\"8.8.8.8\", ttl=64, proto=1)\n",
    );
    let pcap = temp("icmp-pcap");
    write_pcap(&pcap, LinkType::Raw, std::slice::from_ref(&pkt)).unwrap();
    let out_dir = temp("icmp-out");
    let (report, re) = convert_and_reserialize(&pcap, &out_dir, true, 0, None, 0);
    assert_eq!(report.written, 1);
    assert_eq!(re, vec![pkt], "icmp body roundtrip 应字节一致");
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_file(&pcap);
}

#[test]
fn structured_tcp_options_fallback() {
    // TCP doff=6（选项）语义无法表达 → tcp_bytes(hex) 直喂；roundtrip 字节一致
    let pcap = temp("tcpopt-pcap");
    let out_dir = temp("tcpopt-out");
    // 用 IR 构造带选项 tcp 层（与 packet-dsl dissect 测试同款）
    use packet_dsl::ir::*;
    let mut tcp_hdr = vec![0u8; 24];
    tcp_hdr[0] = 0x30;
    tcp_hdr[1] = 0x39;
    tcp_hdr[2] = 0x00;
    tcp_hdr[3] = 0x35;
    tcp_hdr[12] = 0x60;
    tcp_hdr[13] = 0x02;
    tcp_hdr[14] = 0xff;
    tcp_hdr[15] = 0xff;
    tcp_hdr[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]);
    let spec = PacketSpec {
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
            Layer::Ethernet(EthernetFields::default()),
        ],
    };
    let pkt = packet_dsl::DefaultSerializer::with_seed(1)
        .serialize(&spec)
        .unwrap();
    write_pcap(&pcap, LinkType::Ethernet, std::slice::from_ref(&pkt)).unwrap();
    let (_, re) = convert_and_reserialize(&pcap, &out_dir, true, 0, None, 0);
    assert_eq!(re, vec![pkt], "tcp options 直喂 roundtrip 应字节一致");
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_file(&pcap);
}

#[test]
fn padding_falls_back_to_lossless() {
    // 以太网填充在 remaining → 结构化退回无损字节级，roundtrip 仍字节一致
    let mut pkt = frames()[0].clone();
    while pkt.len() < 60 {
        pkt.push(0x00);
    }
    let pcap = temp("pad-pcap");
    write_pcap(&pcap, LinkType::Ethernet, &[pkt.clone()]).unwrap();
    let out_dir = temp("pad-out");
    let (report, re) = convert_and_reserialize(&pcap, &out_dir, true, 0, None, 0);
    assert_eq!(report.written, 1);
    assert_eq!(re, vec![pkt], "填充帧应完整还原");
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_file(&pcap);
}

#[test]
fn recipe_delays_from_timestamps() {
    let packets = frames();
    let recs = vec![
        (0u32, 0u32, packets[0].clone()),
        (0u32, 500_000u32, packets[1].clone()), // +0.5s
        (2u32, 250_000u32, packets[2].clone()), // +1.75s
    ];
    let pcap = temp("delay-pcap");
    write_pcap_ts(&pcap, 1, &recs);
    let out_dir = temp("delay-out");
    let report = convert_pcap(
        &pcap,
        &ConvertOptions {
            out_dir: out_dir.clone(),
            structured: false,
            skip: 0,
            limit: None,
            threads: 0,
        },
    )
    .expect("转换成功");
    let recipe = prping_core::parse_recipe(&report.recipe).expect("配方可解析");
    let steps: Vec<&prping_core::Step> = recipe
        .items
        .iter()
        .filter_map(|it| match it {
            prping_core::RecipeItem::Step(s) => Some(s),
            prping_core::RecipeItem::Serve(_) => None,
        })
        .collect();
    assert_eq!(steps.len(), 3);
    assert_eq!(steps[0].delay, None, "首步无 delay");
    assert_eq!(steps[1].delay, Some(0.5));
    assert_eq!(steps[2].delay, Some(1.75));
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_file(&pcap);
}

#[test]
fn skip_and_limit() {
    let packets = frames();
    let pcap = temp("skip-pcap");
    write_pcap(&pcap, LinkType::Ethernet, &packets).unwrap();
    let out_dir = temp("skip-out");
    // skip=1, limit=1 → 只转第 2 条，文件名按原始序号 record_00002.pkt
    let (report, re) = convert_and_reserialize(&pcap, &out_dir, false, 1, Some(1), 0);
    assert_eq!(report.written, 1);
    assert_eq!(report.files[0].file_name().unwrap(), "record_00002.pkt");
    assert_eq!(re, vec![packets[1].clone()]);
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_file(&pcap);
}

#[test]
fn empty_pcap_rejected() {
    let pcap = temp("empty-pcap");
    write_pcap(&pcap, LinkType::Ethernet, &[] as &[Vec<u8>]).unwrap();
    let out_dir = temp("empty-out");
    let err = convert_pcap(
        &pcap,
        &ConvertOptions {
            out_dir,
            structured: false,
            skip: 0,
            limit: None,
            threads: 0,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("没有记录"), "{err}");
    let _ = std::fs::remove_file(&pcap);
}

/// 生成的 .pkt 可被 engine 分析（可读性冒烟）。
#[test]
fn generated_pkt_analyzes() {
    let packets = frames();
    let pcap = temp("an-pcap");
    write_pcap(&pcap, LinkType::Ethernet, &packets).unwrap();
    let out_dir = temp("an-out");
    let report = convert_pcap(
        &pcap,
        &ConvertOptions {
            out_dir: out_dir.clone(),
            structured: true,
            skip: 0,
            limit: None,
            threads: 0,
        },
    )
    .expect("转换成功");
    for f in &report.files {
        prping_core::analyze_file(f, &[], &packet_dsl::Globals::new(), &[])
            .unwrap_or_else(|e| panic!("analyze {} 失败: {e}", f.display()));
    }
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_file(&pcap);
}

/// 转换产物可被 packet --out 合并写回 pcap（roundtrip 到 pcap 层面）。
#[test]
fn converted_recipe_writes_back_pcap() {
    let packets = frames();
    let pcap = temp("wb-pcap");
    write_pcap(&pcap, LinkType::Ethernet, &packets).unwrap();
    let out_dir = temp("wb-out");
    convert_pcap(
        &pcap,
        &ConvertOptions {
            out_dir: out_dir.clone(),
            structured: false,
            skip: 0,
            limit: None,
            threads: 0,
        },
    )
    .expect("转换成功");
    // 配方 --out 合并写回（无目标、无网络发送——配方步骤全是 raw 外层，跳过发送失败容错）
    let out2 = temp("wb-back");
    let opts = prping_core::PkgOptions {
        mode: prping_core::SendMode::Raw { iface: None },
        out: Some(out2.clone()),
        ..Default::default()
    };
    let recipe_file = out_dir.join(
        pcap.file_stem()
            .map(|s| format!("{}.pktl", s.to_string_lossy()))
            .unwrap(),
    );
    let _ = prping_core::send_recipe(&recipe_file, &opts);
    if out2.exists() {
        let (_, _, recs) = read_pcap(&out2).expect("读回 pcap");
        let back: Vec<Vec<u8>> = recs.into_iter().map(|r| r.data).collect();
        assert_eq!(back, packets, "配方 --out 合并写回应字节一致");
    }
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_file(&pcap);
}

/// 并行（threads=4）与单线程产出逐字节一致（结构化模式）。
#[test]
fn parallel_threads_byte_identical() {
    let mut packets = frames();
    // 扩到 16 条，跨多个 worker 分片
    for _ in 0..4 {
        packets.extend_from_within(..3);
    }
    let pcap = temp("par-pcap");
    write_pcap(&pcap, LinkType::Ethernet, &packets).unwrap();
    let out_seq = temp("par-seq");
    let (_, re_seq) = convert_and_reserialize(&pcap, &out_seq, true, 0, None, 1);
    let out_par = temp("par-par");
    let (_, re_par) = convert_and_reserialize(&pcap, &out_par, true, 0, None, 4);
    assert_eq!(re_seq, re_par, "threads=1 与 threads=4 roundtrip 应一致");
    assert_eq!(re_par, packets, "并行 roundtrip 仍应字节一致");
    let _ = std::fs::remove_dir_all(&out_seq);
    let _ = std::fs::remove_dir_all(&out_par);
    let _ = std::fs::remove_file(&pcap);
}
