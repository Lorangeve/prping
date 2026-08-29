use packet_dsl::ir::Layer;

/// 注册 eng_lib proto 表（与 prping ensure_proto_registry 一致）。
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
    packet_dsl::set_proto_registry(protos);
}

#[test]
fn dissect_tolerates_bad_total_length() {
    register_eng_lib();
    // macOS raw ICMP socket 收到的 echo reply：IP total length = 0x0d00（异常）
    let data: Vec<u8> = vec![
        0x45, 0x00, 0x0d, 0x00, 0x9e, 0x91, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x7f, 0x00, 0x00,
        0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0xa9, 0xf8, 0x12, 0x34, 0x00, 0x01, 0x68, 0x65,
        0x6c, 0x6c, 0x6f,
    ];
    let report = packet_dsl::dissect(&data);
    let icmp = report.layers.iter().find_map(|l| match l {
        Layer::Icmp(f) => Some(f.clone()),
        _ => None,
    });
    let icmp = icmp.expect("total length 异常也应反解出 icmp 层");
    assert_eq!(icmp.icmp_type, Some(0));
    assert_eq!(icmp.id, Some(0x1234));
    assert_eq!(icmp.seq, Some(1));
    assert_eq!(icmp.payload.as_deref(), Some(&b"hello"[..]));
}
