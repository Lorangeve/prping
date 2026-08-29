//! 包反解：把原始字节解析回结构化层栈（对标 scapy 的 `Ether(bytes)` / `rdpcap()`）。
//!
//! **层头解析只走 proto 注册表**（`#[proto(kind=...)]` pkt 声明即解析）：eth/arp/ipv4/
//! ipv6/icmp/tcp/udp 按 kind 反解（`try_proto_layer`），Rust 手写 parse_* 已全部退役——
//! 未注册或字节不符时该层不产生（eth/ip 类字节留 `remaining`；icmp/tcp/udp 段按 raw
//! 保留并记 note）。调用方须先注册（`set_proto_registry`，宿主 `ensure_proto_registry`）。
//! - 应用层：只走 proto 注册表（`#[rule]` 分派，如 dns udp/tcp 53；裸载荷结构化
//!   回退 `dissect_bare_app` 按 kind 查 http/dns 声明）。硬编码 parse_dns/parse_http
//!   已退役——DNS 压缩指针/HTTP 文本行均已 proto 化。
//! - DNS 支持压缩指针；checksum 不匹配时记入 `notes` 而非报错。
//! - 反解产物复用构建侧 IR 字段结构（实际值填入 `Field::Value`），可与序列化 roundtrip。
//!
//! **层序约定**：`layers` 为展示序（外 → 内，eth 在前），与序列化器期望的
//! 内 → 外顺序相反——roundtrip（`dissect` → `DefaultSerializer::serialize`）时
//! 需 `layers.into_iter().rev()` 后再喂给序列化器。

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ir::*;

/// 反解报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DissectReport {
    /// 识别出的层栈（内 → 外；应用层载荷解析失败时该段为 Raw）。
    pub layers: Vec<Layer>,
    /// 未能归入任何层的剩余字节。
    pub remaining: Vec<u8>,
    /// 注意项（如 checksum 不匹配）。
    pub notes: Vec<String>,
    /// proto（自表示协议）解析命中（`#[rule]` 注册，如 QUIC）。
    pub proto: Vec<crate::proto::ProtoHit>,
}

/// 取裸 DNS 报文的 id（前 2 字节；DoT 2B 长度前缀容错；失败返回 None）。
/// 用于 `--wait` 应答匹配（DNS 解析已 proto 化，id 读取不再需要全量反解）。
pub fn dns_message_id(bytes: &[u8]) -> Option<u16> {
    // 可能是 DNS-over-TCP（2B 长度前缀）
    let msg = if bytes.len() >= 14 {
        let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if len + 2 <= bytes.len() && len >= 12 {
            &bytes[2..2 + len]
        } else {
            bytes
        }
    } else {
        bytes
    };
    (msg.len() >= 2).then(|| u16::from_be_bytes([msg[0], msg[1]]))
}

/// 从字节反解（自动识别以太网帧或裸 IP）。
///
/// 同时尝试「以太网路径」与「裸 IP 路径」，取解析出更多层的一侧
/// （MAC 首字节可能碰巧像 IP 版本号，反之 IP 头部字节可能碰巧像 ethertype）。
pub fn dissect(bytes: &[u8]) -> DissectReport {
    let mut p_eth = Vec::new();
    let eth = dissect_eth(bytes, &mut p_eth);
    let mut p_ip = Vec::new();
    let ip = dissect_bare_ip(bytes, &mut p_ip);
    let mut p_app = Vec::new();
    let app = dissect_bare_app(bytes, &mut p_app);
    let with = |mut r: DissectReport, mut p: Vec<crate::proto::ProtoHit>| {
        r.proto.extend(std::mem::take(&mut p));
        r
    };
    // 取解析更深的一侧：eth 派生出了内层协议 → eth；未知 ethertype 但 proto
    // 命中（如 LLDP）→ eth；否则裸 IP；再否则裸应用层。
    // 注意：eth 侧仅 1 层（只解析出 eth 头）时，裸 IP 侧更深（2 层）应选 IP，
    // 裸应用层（app）更结构化也应选 app——裸数据首字节可能碰巧被 eth proto
    // 误解析为 MAC（MAC 无约束）。
    let eth_only_head = eth.layers.len() == 1;
    let eth_proto_alone =
        eth_only_head && !eth.proto.is_empty() && ip.layers.is_empty() && app.layers.is_empty();
    if eth.layers.len() > 1
        || (eth_only_head && !eth.proto.is_empty() && !ip.layers.is_empty() && ip.layers.len() <= 1)
        || eth_proto_alone
    {
        with(eth, p_eth)
    } else if !ip.layers.is_empty() {
        with(ip, p_ip)
    } else if !app.layers.is_empty() {
        with(app, p_app)
    } else if eth_only_head {
        with(eth, p_eth) // 只解析出 eth 头（未知 ethertype），保留其注记
    } else {
        with(app, p_app)
    }
}

/// 以太网帧路径。
fn dissect_eth(bytes: &[u8], protos: &mut Vec<crate::proto::ProtoHit>) -> DissectReport {
    let mut c = Cursor::new(bytes);
    let mut layers = Vec::new();
    let mut notes = Vec::new();
    if bytes.len() < 14 {
        notes.push("字节不足 14（以太网头）".to_string());
        return DissectReport {
            layers,
            remaining: bytes.to_vec(),
            notes,
            proto: std::mem::take(protos),
        };
    }
    // 层头解析只走 proto 注册表（硬编码 parse_eth 已退役）：`#[proto(kind="eth")]`
    // 声明即解析；未注册/字节不符 → 不产生 eth 层，字节留 remaining
    // （顶层选择逻辑可能被裸 IP / 裸应用层路径捡起）。
    if let Some((layer, _)) = try_proto_layer("eth", &mut c, protos) {
        let ethertype = match &layer {
            Layer::Ethernet(f) => f.ethertype,
            _ => None,
        };
        // ethertype < 0x0600 不是以太网 II（802.3 长度字段）：不认 eth 层，
        // 字节留 remaining（可能是裸 IP 被误读为 MAC 前缀）
        if ethertype.is_none_or(|e| e < 0x0600) {
            c.pos = 0;
            protos.pop();
            notes.push("不是以太网 II 帧（ethertype < 0x0600，疑似 802.3 长度字段）".to_string());
            return DissectReport {
                layers,
                remaining: c.remaining().to_vec(),
                notes,
                proto: std::mem::take(protos),
            };
        }
        layers.push(layer);
        match ethertype {
            Some(0x0806) => {
                // ARP：proto 注册表（pkt 声明即解析：28B 定宽；htype 等常量校验
                // ≡ 旧硬编码参数校验，非以太网 ARP 解析失败）；失败 → 字节留 remaining
                if let Some((layer, _)) = try_proto_layer("arp", &mut c, protos) {
                    layers.push(layer);
                }
            }
            Some(0x0800) | Some(0x86DD) => {
                // 以太网载荷即裸 IP：委托裸 IP 路径（ipv4/ipv6 反解逻辑内联在
                // dissect_bare_ip，单处实现不重复）；内层字节留 inner.remaining，
                // proto 命中被 dissect_bare_ip 的 take 收进 inner.proto，须合并回
                let inner = dissect_bare_ip(c.remaining(), protos);
                layers.extend(inner.layers);
                notes.extend(inner.notes);
                protos.extend(inner.proto);
                c.pos = bytes.len() - inner.remaining.len();
            }
            _ => {
                notes.push(format!(
                    "未识别的 ethertype 0x{:04x}，剩余按 raw 处理",
                    ethertype.unwrap_or(0)
                ));
                // proto 注册表按 ethertype 分派（如 LLDP 等）
                let payload = c.remaining().to_vec();
                try_proto(
                    payload,
                    &crate::proto::RuleCond::Eth {
                        ethertype: Some(ethertype.unwrap_or(0)),
                    },
                    protos,
                    &mut notes,
                );
                return DissectReport {
                    layers,
                    remaining: Vec::new(),
                    notes: Vec::new(),
                    proto: std::mem::take(protos),
                };
            }
        }
    }
    // eth 层头反解失败（未注册或字节不符）：静默，字节留 remaining
    let remaining = c.remaining().to_vec();
    DissectReport {
        layers,
        remaining,
        notes,
        proto: std::mem::take(protos),
    }
}

/// 裸 IP 路径（无以太网头；校验版本与长度字段合理性）。
fn dissect_bare_ip(bytes: &[u8], protos: &mut Vec<crate::proto::ProtoHit>) -> DissectReport {
    let mut c = Cursor::new(bytes);
    let mut layers = Vec::new();
    let mut notes = Vec::new();
    let version = bytes.first().map(|b| b >> 4);
    match version {
        Some(4) => {
            let ihl = (bytes[0] & 0x0F) as usize;
            let total = bytes
                .get(2..4)
                .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize);
            // total 字段合理（>= 20）即解析；total 超出实际字节（如 macOS raw
            // socket 收包的 total 异常）由下方载荷兜底剩余全量，不跳过解析
            if ihl >= 5 && total.is_some_and(|t| t >= 20) {
                // IPv4：proto 注册表（version/ihl 位字段、options 宽度按 ihl
                // 回算、total_length 读出、checksum 校验）；失败 → 字节留 remaining
                if let Some((layer, consumed)) = try_proto_layer("ipv4", &mut c, protos) {
                    let hit = protos.last().expect("try_proto_layer 成功已 push hit");
                    let total = proto_field_int(hit, "total").map(|n| n as usize);
                    let proto = proto_field_int(hit, "proto").map(|n| n as u8);
                    // checksum 校验（raw = 头字节含 options）
                    if let Some(raw) = layer_raw_bytes(&layer)
                        && crate::serialize::checksum(raw) != 0
                    {
                        notes.push("IPv4 header checksum 不匹配".to_string());
                    }
                    layers.push(layer);
                    // 载荷 = total_length - 头字节（total 缺失/过小时按剩余全量兜底；
                    // total 超出实际字节（如 macOS raw socket 收包的 total 字段
                    // 异常）同样兜底用剩余全量——不因头字段异常中止解析，
                    // ICMP 等上层照常反解）
                    let payload = match total {
                        Some(t) if t >= consumed => match c.take(t - consumed) {
                            Some(p) => p.to_vec(),
                            None => {
                                notes.push("IPv4 total length 超出实际字节".to_string());
                                c.remaining().to_vec()
                            }
                        },
                        _ => c.remaining().to_vec(),
                    };
                    dispatch_ip_payload(
                        &payload,
                        proto,
                        "IPv4 协议",
                        crate::proto::RuleCond::Ipv4 { proto },
                        &mut layers,
                        &mut notes,
                        protos,
                    );
                }
            }
        }
        Some(6) => {
            let plen = bytes
                .get(4..6)
                .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize);
            // payload 长度 + 40 应 <= 总长（允许差一点）
            if bytes.len() >= 40 && plen.is_some_and(|p| p + 40 <= bytes.len() + 40) {
                // IPv6：proto 注册表（40B 定长头，payload_length 读出；
                // first4 常量校验挡 TC/flow label≠0 的包）；失败 → 字节留 remaining
                'ipv6: {
                    if let Some((layer, _)) = try_proto_layer("ipv6", &mut c, protos) {
                        let hit = protos.last().expect("try_proto_layer 成功已 push hit");
                        let plen = proto_field_int(hit, "plen").map(|n| n as usize);
                        let next_header = proto_field_int(hit, "next_header").map(|n| n as u8);
                        layers.push(layer);
                        let payload = match plen {
                            Some(p) => match c.take(p) {
                                Some(p) => p.to_vec(),
                                None => {
                                    notes.push("IPv6 payload length 超出实际字节".to_string());
                                    break 'ipv6;
                                }
                            },
                            None => c.remaining().to_vec(),
                        };
                        dispatch_ip_payload(
                            &payload,
                            next_header,
                            "IPv6 next header",
                            crate::proto::RuleCond::Ipv6 { next_header },
                            &mut layers,
                            &mut notes,
                            protos,
                        );
                    }
                }
            }
        }
        _ => {}
    }
    let remaining = c.remaining().to_vec();
    DissectReport {
        layers,
        remaining,
        notes,
        proto: std::mem::take(protos),
    }
}

/// 裸应用层回退：既不是以太网也不是裸 IP。无端口上下文无法用 `#[rule]`
/// 分派，但按 kind 尝试注册表声明（dns/http）——结构识别由 pkt 声明本身承担
/// （http 的空行 `hex("0d0a")` 常量校验即 `\r\n\r\n` 约束 + start_line 格式校验；
/// DNS 要求至少一个区计数非零，防任意字节误报）。供 `--wait` 应答匹配
/// （UDP 数据报内容无链路层头）与 `engine --hex` 裸字节识别。
fn dissect_bare_app(bytes: &[u8], protos: &mut Vec<crate::proto::ProtoHit>) -> DissectReport {
    let mut layers = Vec::new();
    let registry = crate::proto::proto_registry();
    for kind in ["dns", "http"] {
        let Some(p) = crate::proto::find_by_kind(registry, kind) else {
            continue;
        };
        if let Some(hit) = crate::proto::parse_proto(p, bytes)
            && let Some(mut layer) = proto_hit_to_layer(&hit).map(|(l, _)| l)
        {
            set_layer_raw(&mut layer, bytes.to_vec());
            layers.push(layer);
            protos.push(hit);
            return DissectReport {
                layers,
                remaining: Vec::new(),
                notes: Vec::new(),
                proto: std::mem::take(protos),
            };
        }
    }
    DissectReport {
        layers,
        remaining: bytes.to_vec(),
        notes: vec!["无法识别的原始载荷".to_string()],
        proto: std::mem::take(protos),
    }
}

/// 字节游标（大端读取）。
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.bytes.len() {
            return None;
        }
        let s = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }
}

/// 取 proto 命中的整数字段（辅助）。
fn proto_field_int(hit: &crate::proto::ProtoHit, name: &str) -> Option<i64> {
    hit.fields
        .iter()
        .find(|(n, _)| n == name)
        .and_then(|(_, v)| v.as_int())
}

/// 取 IR 层的 raw 头字节（辅助；proto 反解回填的层 raw 分支）。
fn layer_raw_bytes(l: &Layer) -> Option<&[u8]> {
    match l {
        Layer::Ethernet(f) => f.raw.as_deref(),
        Layer::Arp(f) => f.raw.as_deref(),
        Layer::Ipv4(f) => f.raw.as_deref(),
        Layer::Ipv6(f) => f.raw.as_deref(),
        Layer::Icmp(f) => f.raw.as_deref(),
        Layer::Tcp(f) => f.raw.as_deref(),
        Layer::Udp(f) => f.raw.as_deref(),
        _ => None,
    }
}

/// IP 载荷分派（IPv4 proto / IPv6 next_header）：icmp/tcp/udp 或 proto 注册表/raw。
fn dispatch_ip_payload(
    payload: &[u8],
    proto: Option<u8>,
    label: &str,
    cond: crate::proto::RuleCond,
    layers: &mut Vec<Layer>,
    notes: &mut Vec<String>,
    protos: &mut Vec<crate::proto::ProtoHit>,
) {
    let mut pc = Cursor::new(payload);
    match proto {
        Some(1) | Some(58) => {
            // ICMP（58 = ICMPv6）：proto 注册表（8B 头 + rest payload，遇 rest 即
            // 停）；payload 回填语义字段、头+载荷整体 checksum 校验；失败 →
            // 整段按 raw 保留（字节不丢）
            if let Some((mut layer, _)) = try_proto_layer("icmp", &mut pc, protos) {
                let body = pc.remaining().to_vec();
                if let Layer::Icmp(f) = &mut layer {
                    f.payload = if body.is_empty() {
                        None
                    } else {
                        Some(body.clone())
                    };
                }
                let mut msg = match &layer {
                    Layer::Icmp(f) => f.raw.clone().unwrap_or_default(),
                    _ => Vec::new(),
                };
                msg.extend_from_slice(&body);
                if crate::serialize::checksum(&msg) != 0 {
                    notes.push("ICMP checksum 不匹配".to_string());
                }
                layers.push(layer);
            } else {
                notes.push("icmp 层头反解失败（未注册或字节不符），按 raw 处理".to_string());
                let rest = pc.remaining().to_vec();
                if !rest.is_empty() {
                    layers.push(Layer::Raw(RawData {
                        bytes: rest,
                        proto: None,
                    }));
                }
            }
        }
        Some(6) => {
            // TCP：proto 注册表（options 宽度按 data_offset 回算）；端口 →
            // 应用层规则分派；失败 → 整段按 raw 保留（字节不丢）
            if let Some((layer, _)) = try_proto_layer("tcp", &mut pc, protos) {
                let (sport, dport, payload) = match &layer {
                    Layer::Tcp(f) => (f.src_port, f.dst_port, pc.remaining().to_vec()),
                    _ => (None, None, Vec::new()),
                };
                layers.push(layer);
                if let (Some(s), Some(d)) = (sport, dport) {
                    try_app_layer(payload, s, d, false, layers, notes, protos);
                }
            } else {
                notes.push("tcp 层头反解失败（未注册或字节不符），按 raw 处理".to_string());
                let rest = pc.remaining().to_vec();
                if !rest.is_empty() {
                    layers.push(Layer::Raw(RawData {
                        bytes: rest,
                        proto: None,
                    }));
                }
            }
        }
        Some(17) => {
            // UDP：proto 注册表（length 字段读出，按它截断载荷——length < 实际
            // 时超长部分不属本数据报）；端口 → 应用层规则分派；失败 → 整段按 raw
            if let Some((layer, _)) = try_proto_layer("udp", &mut pc, protos) {
                let (sport, dport, mut body) = match &layer {
                    Layer::Udp(f) => (f.src_port, f.dst_port, pc.remaining().to_vec()),
                    _ => (None, None, Vec::new()),
                };
                if let Some(hit) = protos.last()
                    && let Some(len) = proto_field_int(hit, "length").map(|n| n as usize)
                    && len >= 8
                {
                    let declared = len - 8;
                    if declared < body.len() {
                        body.truncate(declared);
                    }
                }
                layers.push(layer);
                if let (Some(s), Some(d)) = (sport, dport) {
                    try_app_layer(body, s, d, true, layers, notes, protos);
                }
            } else {
                notes.push("udp 层头反解失败（未注册或字节不符），按 raw 处理".to_string());
                let rest = pc.remaining().to_vec();
                if !rest.is_empty() {
                    layers.push(Layer::Raw(RawData {
                        bytes: rest,
                        proto: None,
                    }));
                }
            }
        }
        other => {
            if !payload.is_empty() {
                notes.push(format!(
                    "未识别的 {label} {}，载荷按 raw 处理",
                    other.unwrap_or(0)
                ));
                // proto 注册表按 proto 号分派
                if try_proto(payload.to_vec(), &cond, protos, notes) {
                    return;
                }
                layers.push(Layer::Raw(RawData {
                    bytes: payload.to_vec(),
                    proto: None,
                }));
            }
        }
    }
}

/// 查 proto 注册表解析：先按规则分派（端口/协议号/ethertype），规则未命中或
/// 全部解析失败时**回退内容识别**（协议识别以内容为准，端口只是可选提示）。
/// 命中返回 true 并 push 到 `protos`；全部失败 → false（调用方回退 raw）。
fn try_proto(
    payload: Vec<u8>,
    cond: &crate::proto::RuleCond,
    protos: &mut Vec<crate::proto::ProtoHit>,
    notes: &mut Vec<String>,
) -> bool {
    let registry = crate::proto::proto_registry();
    if registry.is_empty() {
        return false;
    }
    // 1. 规则分派：端口/协议号/ethertype 命中 → 候选（快速路径）
    for candidate in crate::proto::find_rule(registry, cond) {
        if let Some(hit) = crate::proto::parse_proto(candidate, &payload) {
            protos.push(hit);
            return true;
        }
        notes.push(format!(
            "proto `{}` 匹配规则但解析失败（截断或字段不符），尝试下一个",
            candidate.name
        ));
    }
    // 2. 回退内容识别：规则未命中（或已命中但解析失败）时，按内容/魔数反解
    //    应用层候选（http/dns 靠格式 + 语义校验，裸 proto 靠首字节掩码）
    for candidate in crate::proto::find_content_candidates(registry) {
        // 规则已命中的候选在上面尝试过（parse 失败），跳过避免重复
        if candidate
            .rule
            .as_ref()
            .is_some_and(|r| r.matches_cond(cond))
        {
            continue;
        }
        if let Some(hit) = crate::proto::parse_proto(candidate, &payload) {
            protos.push(hit);
            return true;
        }
    }
    false
}

/// 应用层解析：**只走 proto 注册表**（`#[rule]` 分派，如 dns proto 的
/// `udp(dport=53)`/`tcp(dport=53)`），命中即按 pkt 声明反解（dns/http 等有 IR
/// 语义的转 IR 层，裸 proto 如 quic 保留载荷为 Raw 层）；未命中回退 Raw。
/// 硬编码 parse_dns/parse_http 已退役（DNS 响应四区 + 压缩指针追跳、HTTP 文本行
/// 均已 proto 化）。
fn try_app_layer(
    payload: Vec<u8>,
    sport: u16,
    dport: u16,
    is_udp: bool,
    layers: &mut Vec<Layer>,
    notes: &mut Vec<String>,
    protos: &mut Vec<crate::proto::ProtoHit>,
) {
    // 按传输层构造分派条件（http 的 rule 是 tcp 端口，dns 是 udp/tcp 53）
    let cond = if is_udp {
        crate::proto::RuleCond::Udp {
            dport: Some(dport),
            sport: Some(sport),
        }
    } else {
        crate::proto::RuleCond::Tcp {
            dport: Some(dport),
            sport: Some(sport),
        }
    };
    if !payload.is_empty() && try_proto(payload.clone(), &cond, protos, notes) {
        // proto 命中：有 IR 语义（dns/http）→ 转 IR 层（raw 保留整段载荷，
        // roundtrip/转码依赖原始字节）；其余裸 proto → 载荷保留为 Raw 层
        let hit = protos.last().expect("try_proto 成功已 push hit");
        if let Some(mut layer) = proto_hit_to_layer(hit).map(|(l, _)| l) {
            set_layer_raw(&mut layer, payload.clone());
            layers.push(layer);
        } else {
            layers.push(Layer::Raw(RawData {
                bytes: payload,
                proto: None,
            }));
        }
        return;
    }
    if !payload.is_empty() {
        layers.push(Layer::Raw(RawData {
            bytes: payload,
            proto: None,
        }));
    }
}

/// 层头 proto 反解 → IR 语义层（解析侧回填，与构造侧 `typed_layer` 对称）：
/// 注册表按 kind 匹配（`#[proto(kind="eth")]` 等），parse_proto 反解出字段表，
/// 按字段名约定回填 IR Layer 语义字段；头字节走 raw 分支（自动 checksum/length
/// 由序列化器重算）。失败（未注册/字段不符）→ None（调用方按 raw 保留字节）。
/// 返回 (层, 层头字节数)——层头长度 = 反解消费长度：rest/payload 类字段消费到
/// 末尾，其余字段定宽，按字段类型累加。
fn proto_hit_to_layer(hit: &crate::proto::ProtoHit) -> Option<(Layer, usize)> {
    use crate::proto::ProtoVal;
    let int = |name: &str| -> Option<i64> {
        hit.fields
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_int())
    };
    let strv = |name: &str| -> Option<String> {
        hit.fields.iter().find_map(|(n, v)| match (n, v) {
            (n, ProtoVal::Str(s)) if n == name => Some(s.clone()),
            _ => None,
        })
    };
    let macv = |name: &str| -> Option<MacAddr> { strv(name).and_then(|s| s.parse().ok()) };
    let ip4v = |name: &str| -> Option<Ipv4Addr> { strv(name).and_then(|s| s.parse().ok()) };
    let ip6v = |name: &str| -> Option<Ipv6Addr> { strv(name).and_then(|s| s.parse().ok()) };
    let layer = match hit.name.as_str() {
        "eth" => Layer::Ethernet(EthernetFields {
            dst_mac: macv("dst_mac").map(Field::Value).unwrap_or(Field::Auto),
            src_mac: macv("src_mac").map(Field::Value).unwrap_or(Field::Auto),
            ethertype: int("ethertype").map(|n| n as u16),
            raw: None,
        }),
        "arp" => Layer::Arp(ArpFields {
            op: int("op").map(|n| match n {
                1 => ArpOp::Request,
                2 => ArpOp::Reply,
                // RARP(3) 等未知 opcode：保留原始值（此前丢成 None → roundtrip 失真）
                other => ArpOp::Other(u16::try_from(other).unwrap_or(0)),
            }),
            sha: macv("sha"),
            spa: ip4v("spa"),
            tha: macv("tha"),
            tpa: ip4v("tpa"),
            raw: None,
        }),
        "ipv4" => Layer::Ipv4(Ipv4Fields {
            src: ip4v("src").map(Field::Value).unwrap_or(Field::Auto),
            dst: ip4v("dst").map(Field::Value).unwrap_or(Field::Auto),
            ttl: int("ttl")
                .map(|n| Field::Value(n as u8))
                .unwrap_or(Field::Auto),
            proto: int("proto").map(|n| n as u8),
            tos: int("tos").map(|n| n as u8),
            id: int("id").map(|n| n as u16),
            flags: int("flags").map(|n| Ipv4Flags {
                df: n & 0x4000 != 0,
                mf: n & 0x2000 != 0,
                frag_offset: (n & 0x1fff) as u16,
            }),
            raw: None,
            ..Default::default()
        }),
        "ipv6" => Layer::Ipv6(Ipv6Fields {
            src: ip6v("src").map(Field::Value).unwrap_or(Field::Auto),
            dst: ip6v("dst").map(Field::Value).unwrap_or(Field::Auto),
            hop_limit: int("hop_limit")
                .map(|n| Field::Value(n as u8))
                .unwrap_or(Field::Auto),
            next_header: int("next_header").map(|n| n as u8),
            raw: None,
            ..Default::default()
        }),
        "icmp" => Layer::Icmp(IcmpFields {
            icmp_type: int("type").map(|n| n as u8),
            code: int("code").map(|n| n as u8),
            id: int("id").map(|n| n as u16),
            seq: int("seq").map(|n| n as u16),
            payload: None,
            raw: None,
        }),
        "udp" => Layer::Udp(UdpFields {
            src_port: int("sport").map(|n| n as u16),
            dst_port: int("dport").map(|n| n as u16),
            raw: None,
            ..Default::default()
        }),
        "tcp" => Layer::Tcp(TcpFields {
            src_port: int("sport").map(|n| n as u16),
            dst_port: int("dport").map(|n| n as u16),
            seq: int("seq").map(|n| n as u32),
            ack: int("ack").map(|n| n as u32),
            flags: int("flags").map(|n| flags_from_byte(n as u8)),
            window: int("window").map(|n| n as u16),
            options: Vec::new(),
            raw: None,
            ..Default::default()
        }),
        "dns" => {
            // 应用层 DNS：头 + questions/answers 列表（subs 按子 proto 名区分，
            // 前 qd 个 dns_question、前 an 个 dns_answer；authority/additional 的
            // dns_answer 在计数之后被忽略——DnsFields 无字段承载）。
            let mut qd = 0usize;
            let mut an = 0usize;
            for (n, v) in &hit.fields {
                match (n.as_str(), v) {
                    ("qdcount", ProtoVal::Int(i)) => qd = *i as usize,
                    ("ancount", ProtoVal::Int(i)) => an = *i as usize,
                    _ => {}
                }
            }
            let mut questions = Vec::new();
            let mut answers = Vec::new();
            let mut qi = 0usize;
            let mut ai = 0usize;
            for sub in &hit.subs {
                let strv = |name: &str| {
                    sub.fields.iter().find_map(|(n, v)| match (n, v) {
                        (n, ProtoVal::Str(s)) if n == name => Some(s.clone()),
                        _ => None,
                    })
                };
                let intv = |name: &str| {
                    sub.fields
                        .iter()
                        .find_map(|(n, v)| (n == name).then(|| v.as_int()).flatten())
                };
                let bytesv = |name: &str| {
                    sub.fields.iter().find_map(|(n, v)| match (n, v) {
                        (n, ProtoVal::Bytes(b)) if n == name => Some(b.clone()),
                        _ => None,
                    })
                };
                match sub.name.as_str() {
                    "dns_question" if qi < qd => {
                        qi += 1;
                        questions.push(DnsQuestion {
                            name: strv("name").unwrap_or_default(),
                            qtype: intv("qtype").map(|n| n as u16),
                            qclass: intv("qclass").map(|n| n as u16),
                        });
                    }
                    "dns_answer" if ai < an => {
                        ai += 1;
                        answers.push(DnsAnswer {
                            name: strv("name").unwrap_or_default(),
                            rtype: intv("rtype").map(|n| n as u16),
                            class: intv("class").map(|n| n as u16),
                            ttl: intv("ttl").map(|n| n as u32),
                            rdata: bytesv("rdata").unwrap_or_default(),
                        });
                    }
                    _ => {}
                }
            }
            Layer::Dns(DnsFields {
                id: int("id").map(|n| n as u16),
                flags: int("flags").map(|n| n as u16),
                opcode: None,
                questions,
                answers,
                raw: None,
            })
        }
        "http" => {
            // 应用层 HTTP：start_line（line 字段）+ headers（hdr_line subs）+
            // body（rest 字段）。method/path/version 与 `Key: value` 拆分是
            // 展示层逻辑（同 flags_from_byte，非线格式）。
            let strv = |name: &str| {
                hit.fields.iter().find_map(|(n, v)| match (n, v) {
                    (n, ProtoVal::Str(s)) if n == name => Some(s.clone()),
                    _ => None,
                })
            };
            let bytesv = |name: &str| {
                hit.fields.iter().find_map(|(n, v)| match (n, v) {
                    (n, ProtoVal::Bytes(b)) if n == name => Some(b.clone()),
                    _ => None,
                })
            };
            let start_line = strv("start_line").unwrap_or_default();
            let (method, path, version) = if let Some(rest) = start_line.strip_prefix("HTTP/") {
                (None, None, Some(format!("HTTP/{rest}")))
            } else {
                let mut parts = start_line.splitn(3, ' ');
                (
                    parts.next().filter(|s| !s.is_empty()).map(str::to_string),
                    parts.next().map(str::to_string),
                    parts.next().map(str::to_string),
                )
            };
            let mut headers = Vec::new();
            for sub in &hit.subs {
                if sub.name == "hdr_line"
                    && let Some(text) = sub.fields.iter().find_map(|(n, v)| match (n, v) {
                        (n, ProtoVal::Str(t)) if n == "text" => Some(t.clone()),
                        _ => None,
                    })
                    && let Some((k, v)) = text.split_once(':')
                {
                    headers.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
            Layer::Http(HttpFields {
                method,
                path,
                version,
                headers,
                body: bytesv("body").filter(|b| !b.is_empty()),
                raw: None,
            })
        }
        _ => return None,
    };
    Some((layer, 0))
}

/// 层头解析：按 kind 查 proto 注册表（`#[proto(kind=...)]`），命中用字段表
/// 反解回填语义层；失败 → None（调用方按 raw 保留，不再有硬编码解析兜底）。
/// 成功返回 Some((层, 消费字节数))；None = 未注册/解析失败。
fn try_proto_layer(
    kind: &str,
    c: &mut Cursor<'_>,
    protos: &mut Vec<crate::proto::ProtoHit>,
) -> Option<(Layer, usize)> {
    let registry = crate::proto::proto_registry();
    let p = crate::proto::find_by_kind(registry, kind)?;
    let bytes = c.remaining();
    let (hit, consumed) = crate::proto::parse_header(p, bytes)?;
    let (mut layer, _) = proto_hit_to_layer(&hit)?;
    // raw 分支保留原始头字节（自动字段由序列化器重算）
    set_layer_raw(&mut layer, bytes[..consumed].to_vec());
    protos.push(hit);
    c.pos += consumed;
    Some((layer, consumed))
}

/// 层 → 填入 raw 头字节（各 Fields 的 raw 字段）。
fn set_layer_raw(layer: &mut Layer, raw: Vec<u8>) {
    match layer {
        Layer::Ethernet(f) => f.raw = Some(raw),
        Layer::Arp(f) => f.raw = Some(raw),
        Layer::Ipv4(f) => f.raw = Some(raw),
        Layer::Ipv6(f) => f.raw = Some(raw),
        Layer::Icmp(f) => f.raw = Some(raw),
        Layer::Tcp(f) => f.raw = Some(raw),
        Layer::Udp(f) => f.raw = Some(raw),
        Layer::Dns(f) => f.raw = Some(raw),
        Layer::Http(f) => f.raw = Some(raw),
        _ => {}
    }
}

fn flags_from_byte(b: u8) -> TcpFlags {
    TcpFlags {
        fin: b & 0x01 != 0,
        syn: b & 0x02 != 0,
        rst: b & 0x04 != 0,
        psh: b & 0x08 != 0,
        ack: b & 0x10 != 0,
        urg: b & 0x20 != 0,
        ece: b & 0x40 != 0,
        cwr: b & 0x80 != 0,
    }
}
