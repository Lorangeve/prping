//! 包反解：把原始字节解析回结构化层栈（对标 scapy 的 `Ether(bytes)` / `rdpcap()`）。
//!
//! - 从以太网帧开始分派（ethertype → arp / ipv4 / ipv6），无以太网时自动尝试 IP 头。
//! - 传输层按 proto / next_header 分派（icmp / tcp / udp）。
//! - 应用层按端口猜测（udp/tcp 53 → dns，tcp 80/8080 → http），解析失败回退 Raw。
//! - DNS 支持压缩指针；checksum 不匹配时记入 `notes` 而非报错。
//! - 反解产物复用构建侧 IR 字段结构（实际值填入 `Field::Value`），可与序列化 roundtrip。

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
}

/// 取裸 DNS 报文的 id（无头时返回 None；用于应答匹配）。
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
    parse_dns(msg).map(|f| f.id.unwrap_or(0))
}

/// 从字节反解（自动识别以太网帧或裸 IP）。
///
/// 同时尝试「以太网路径」与「裸 IP 路径」，取解析出更多层的一侧
/// （MAC 首字节可能碰巧像 IP 版本号，反之 IP 头部字节可能碰巧像 ethertype）。
pub fn dissect(bytes: &[u8]) -> DissectReport {
    let eth = dissect_eth(bytes);
    let ip = dissect_bare_ip(bytes);
    // 取解析更深的一侧：eth 派生出了内层协议 → eth；否则裸 IP；再否则裸应用层
    if eth.layers.len() > 1 {
        eth
    } else if !ip.layers.is_empty() {
        ip
    } else {
        let app = dissect_bare_app(bytes);
        if !app.layers.is_empty() {
            app
        } else if eth.layers.len() == 1 {
            eth // 只解析出 eth 头（未知 ethertype），保留其注记
        } else {
            app
        }
    }
}

/// 以太网帧路径。
fn dissect_eth(bytes: &[u8]) -> DissectReport {
    let mut c = Cursor::new(bytes);
    let mut layers = Vec::new();
    let mut notes = Vec::new();
    if bytes.len() < 14 {
        notes.push("字节不足 14（以太网头）".to_string());
        return DissectReport {
            layers,
            remaining: bytes.to_vec(),
            notes,
        };
    }
    if let Some(f) = parse_eth(&mut c, &mut notes) {
        let ethertype = f.ethertype.expect("parse_eth 已填");
        layers.push(Layer::Ethernet(f));
        match ethertype {
            0x0806 => parse_arp(&mut c, &mut layers, &mut notes),
            0x0800 => parse_ipv4(&mut c, &mut layers, &mut notes),
            0x86DD => parse_ipv6(&mut c, &mut layers, &mut notes),
            _ => notes.push(format!(
                "未识别的 ethertype 0x{ethertype:04x}，剩余按 raw 处理"
            )),
        }
    }
    let remaining = c.remaining().to_vec();
    DissectReport {
        layers,
        remaining,
        notes,
    }
}

/// 裸 IP 路径（无以太网头；校验版本与长度字段合理性）。
fn dissect_bare_ip(bytes: &[u8]) -> DissectReport {
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
            if ihl >= 5 && total.is_some_and(|t| t >= 20 && t <= bytes.len()) {
                parse_ipv4(&mut c, &mut layers, &mut notes);
            }
        }
        Some(6) => {
            let plen = bytes
                .get(4..6)
                .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize);
            // payload 长度 + 40 应 <= 总长（允许差一点）
            if bytes.len() >= 40 && plen.is_some_and(|p| p + 40 <= bytes.len() + 40) {
                parse_ipv6(&mut c, &mut layers, &mut notes);
            }
        }
        _ => {}
    }
    let remaining = c.remaining().to_vec();
    DissectReport {
        layers,
        remaining,
        notes,
    }
}

/// 裸应用层回退：既不是以太网也不是裸 IP 时，尝试 DNS / HTTP 报文。
fn dissect_bare_app(bytes: &[u8]) -> DissectReport {
    if let Some(f) = parse_dns(bytes) {
        return DissectReport {
            layers: vec![Layer::Dns(f)],
            remaining: Vec::new(),
            notes: Vec::new(),
        };
    }
    if let Some(f) = parse_http(bytes) {
        return DissectReport {
            layers: vec![Layer::Http(f)],
            remaining: Vec::new(),
            notes: Vec::new(),
        };
    }
    DissectReport {
        layers: Vec::new(),
        remaining: bytes.to_vec(),
        notes: vec!["无法识别的原始载荷".to_string()],
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

fn mac(b: &[u8]) -> MacAddr {
    MacAddr([b[0], b[1], b[2], b[3], b[4], b[5]])
}

// ── 链路层 ──────────────────────────────────────────────────

fn parse_eth(c: &mut Cursor<'_>, notes: &mut Vec<String>) -> Option<EthernetFields> {
    let hdr = c.take(14)?;
    let ethertype = u16::from_be_bytes([hdr[12], hdr[13]]);
    if ethertype < 0x0600 {
        notes.push("不是以太网 II 帧（ethertype < 0x0600，疑似 802.3 长度字段）".to_string());
        return None;
    }
    Some(EthernetFields {
        src_mac: Field::Value(mac(&hdr[6..12])),
        dst_mac: Field::Value(mac(&hdr[0..6])),
        ethertype: Some(ethertype),
        raw: Some(hdr.to_vec()),
    })
}

fn parse_arp(c: &mut Cursor<'_>, layers: &mut Vec<Layer>, notes: &mut Vec<String>) {
    let Some(hdr) = c.take(28) else {
        notes.push("ARP 报文截断".to_string());
        return;
    };
    let htype = u16::from_be_bytes([hdr[0], hdr[1]]);
    let ptype = u16::from_be_bytes([hdr[2], hdr[3]]);
    let hlen = hdr[4];
    let plen = hdr[5];
    let op = u16::from_be_bytes([hdr[6], hdr[7]]);
    if htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4 {
        notes.push(format!(
            "不支持的 ARP 参数：htype={htype} ptype=0x{ptype:04x} hlen={hlen} plen={plen}"
        ));
        return;
    }
    let f = ArpFields {
        op: Some(if op == 1 {
            ArpOp::Request
        } else {
            ArpOp::Reply
        }),
        sha: Some(mac(&hdr[8..14])),
        spa: Some(Ipv4Addr::new(hdr[14], hdr[15], hdr[16], hdr[17])),
        tha: Some(mac(&hdr[18..24])),
        tpa: Some(Ipv4Addr::new(hdr[24], hdr[25], hdr[26], hdr[27])),
        raw: Some(hdr.to_vec()),
    };
    layers.push(Layer::Arp(f));
}

// ── 网络层 ──────────────────────────────────────────────────

fn parse_ipv4(c: &mut Cursor<'_>, layers: &mut Vec<Layer>, notes: &mut Vec<String>) {
    let Some(hdr) = c.take(20) else {
        notes.push("IPv4 报文截断".to_string());
        return;
    };
    let version = hdr[0] >> 4;
    let ihl = (hdr[0] & 0x0F) as usize;
    if version != 4 || ihl < 5 {
        notes.push(format!("非法 IPv4 头：version={version} ihl={ihl}"));
        return;
    }
    // 跳过 IPv4 选项（ihl*4 - 20 字节）
    let mut hdr_all = hdr.to_vec();
    if ihl > 5 {
        let opts = (ihl - 5) * 4;
        match c.take(opts) {
            Some(o) => hdr_all.extend_from_slice(o),
            None => {
                notes.push("IPv4 选项截断".to_string());
                return;
            }
        }
    }
    let total_len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    let frag = u16::from_be_bytes([hdr[6], hdr[7]]);
    let proto = hdr[9];
    let checksum_ok = crate::serialize::checksum(&hdr_all) == 0;
    if !checksum_ok {
        notes.push("IPv4 header checksum 不匹配".to_string());
    }
    let f = Ipv4Fields {
        src_host: None,
        dst_host: None,
        src: Field::Value(Ipv4Addr::new(hdr[12], hdr[13], hdr[14], hdr[15])),
        dst: Field::Value(Ipv4Addr::new(hdr[16], hdr[17], hdr[18], hdr[19])),
        ttl: Field::Value(hdr[8]),
        proto: Some(proto),
        tos: Some(hdr[1]),
        id: Some(u16::from_be_bytes([hdr[4], hdr[5]])),
        flags: Some(Ipv4Flags {
            df: frag & 0x4000 != 0,
            mf: frag & 0x2000 != 0,
            frag_offset: frag & 0x1FFF,
        }),
        auto_checksum: true,
        raw: Some(hdr_all),
    };
    layers.push(Layer::Ipv4(f));
    // 剩余长度：total_len - 头部（20+opts）
    let payload_len = total_len.saturating_sub(ihl * 4);
    let payload = match c.take(payload_len) {
        Some(p) => p,
        None => {
            notes.push("IPv4 total length 超出实际字节".to_string());
            return;
        }
    };
    let mut pc = Cursor::new(payload);
    match proto {
        1 => parse_icmp(&mut pc, layers, notes),
        6 => parse_tcp(&mut pc, layers, notes),
        17 => parse_udp(&mut pc, layers, notes),
        other => {
            if !payload.is_empty() {
                notes.push(format!("未识别的 IPv4 协议 {other}，载荷按 raw 处理"));
                layers.push(Layer::Raw(RawData {
                    bytes: payload.to_vec(),
                }));
            }
        }
    }
}

fn parse_ipv6(c: &mut Cursor<'_>, layers: &mut Vec<Layer>, notes: &mut Vec<String>) {
    let Some(hdr) = c.take(40) else {
        notes.push("IPv6 报文截断".to_string());
        return;
    };
    let version = hdr[0] >> 4;
    if version != 6 {
        notes.push("非法 IPv6 版本".to_string());
        return;
    }
    let payload_len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
    let next_header = hdr[6];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&hdr[8..24]);
    dst.copy_from_slice(&hdr[24..40]);
    let f = Ipv6Fields {
        src_host: None,
        dst_host: None,
        src: Field::Value(Ipv6Addr::from(src)),
        dst: Field::Value(Ipv6Addr::from(dst)),
        hop_limit: Field::Value(hdr[7]),
        next_header: Some(next_header),
        raw: Some(hdr.to_vec()),
    };
    layers.push(Layer::Ipv6(f));
    let payload = match c.take(payload_len) {
        Some(p) => p,
        None => {
            notes.push("IPv6 payload length 超出实际字节".to_string());
            return;
        }
    };
    let mut pc = Cursor::new(payload);
    match next_header {
        6 => parse_tcp(&mut pc, layers, notes),
        17 => parse_udp(&mut pc, layers, notes),
        58 => parse_icmp(&mut pc, layers, notes),
        other => {
            if !payload.is_empty() {
                notes.push(format!(
                    "未识别的 IPv6 next header {other}，载荷按 raw 处理"
                ));
                layers.push(Layer::Raw(RawData {
                    bytes: payload.to_vec(),
                }));
            }
        }
    }
}

// ── 传输层 ──────────────────────────────────────────────────

fn parse_icmp(c: &mut Cursor<'_>, layers: &mut Vec<Layer>, notes: &mut Vec<String>) {
    let Some(hdr) = c.take(8) else {
        notes.push("ICMP 报文截断".to_string());
        return;
    };
    let body = c.remaining().to_vec();
    // checksum 校验：type/code/checksum/id/seq/body 整体
    let mut msg = hdr.to_vec();
    msg.extend_from_slice(&body);
    if crate::serialize::checksum(&msg) != 0 {
        notes.push("ICMP checksum 不匹配".to_string());
    }
    let f = IcmpFields {
        icmp_type: Some(hdr[0]),
        code: Some(hdr[1]),
        id: Some(u16::from_be_bytes([hdr[4], hdr[5]])),
        seq: Some(u16::from_be_bytes([hdr[6], hdr[7]])),
        payload: if body.is_empty() {
            None
        } else {
            Some(body.clone())
        },
        raw: Some(hdr.to_vec()),
    };
    layers.push(Layer::Icmp(f));
    let _ = body;
}

fn parse_tcp(c: &mut Cursor<'_>, layers: &mut Vec<Layer>, notes: &mut Vec<String>) {
    let Some(hdr) = c.take(20) else {
        notes.push("TCP 报文截断".to_string());
        return;
    };
    let data_offset = (hdr[12] >> 4) as usize;
    if data_offset < 5 {
        notes.push("非法 TCP data offset".to_string());
        return;
    }
    let mut hdr_all = hdr.to_vec();
    if data_offset > 5 {
        match c.take((data_offset - 5) * 4) {
            Some(o) => hdr_all.extend_from_slice(o),
            None => {
                notes.push("TCP 选项截断".to_string());
                return;
            }
        }
    }
    let flags = flags_from_byte(hdr[13]);
    let sport = u16::from_be_bytes([hdr[0], hdr[1]]);
    let dport = u16::from_be_bytes([hdr[2], hdr[3]]);
    let payload = c.remaining().to_vec();
    let f = TcpFields {
        src_port: Some(sport),
        dst_port: Some(dport),
        seq: Some(u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]])),
        ack: Some(u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]])),
        flags: Some(flags),
        window: Some(u16::from_be_bytes([hdr[14], hdr[15]])),
        options: Vec::new(),
        auto_checksum: true,
        raw: Some(hdr_all),
    };
    layers.push(Layer::Tcp(f));
    try_app_layer(payload, sport, dport, layers);
}

fn parse_udp(c: &mut Cursor<'_>, layers: &mut Vec<Layer>, notes: &mut Vec<String>) {
    let Some(hdr) = c.take(8) else {
        notes.push("UDP 报文截断".to_string());
        return;
    };
    let len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
    let sport = u16::from_be_bytes([hdr[0], hdr[1]]);
    let dport = u16::from_be_bytes([hdr[2], hdr[3]]);
    let mut body = c.remaining().to_vec();
    if len >= 8 {
        let declared = len - 8;
        if declared < body.len() {
            body.truncate(declared);
        }
    }
    let f = UdpFields {
        src_port: Some(sport),
        dst_port: Some(dport),
        auto_checksum: true,
        raw: Some(hdr.to_vec()),
    };
    layers.push(Layer::Udp(f));
    try_app_layer(body, sport, dport, layers);
}

/// 按端口猜测应用层（dns / http），失败回退 Raw。
fn try_app_layer(payload: Vec<u8>, sport: u16, dport: u16, layers: &mut Vec<Layer>) {
    let is_dns_port = sport == 53 || dport == 53;
    let is_http_port = sport == 80 || sport == 8080 || dport == 80 || dport == 8080;
    if is_dns_port {
        if let Some(f) = parse_dns(&payload) {
            layers.push(Layer::Dns(f));
            return;
        }
    } else if is_http_port && let Some(f) = parse_http(&payload) {
        layers.push(Layer::Http(f));
        return;
    }
    if !payload.is_empty() {
        layers.push(Layer::Raw(RawData { bytes: payload }));
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

// ── 应用层 ──────────────────────────────────────────────────

/// DNS 反解（支持压缩指针；TCP 载荷需先剥掉 2 字节长度前缀）。
fn parse_dns(bytes: &[u8]) -> Option<DnsFields> {
    // 疑似 DNS-over-TCP（2B 长度前缀）：先剥前缀尝试，失败再试原样
    let stripped: &[u8] = if bytes.len() >= 14 {
        let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if len + 2 <= bytes.len() && len >= 12 {
            &bytes[2..2 + len]
        } else {
            bytes
        }
    } else {
        bytes
    };
    let msg = if parse_dns_msg(stripped).is_some() {
        stripped
    } else {
        bytes
    };
    parse_dns_msg(msg)
}

fn parse_dns_msg(msg: &[u8]) -> Option<DnsFields> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let ns = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    let ar = u16::from_be_bytes([msg[10], msg[11]]) as usize;
    if qd == 0 && an == 0 && ns == 0 && ar == 0 {
        return None; // 空报文不认作 DNS（避免全零载荷误判）
    }
    let mut pos = 12usize;
    let mut questions = Vec::new();
    for _ in 0..qd {
        let name = read_dns_name(msg, &mut pos)?;
        if pos + 4 > msg.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let qclass = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
        pos += 4;
        questions.push(DnsQuestion {
            name,
            qtype: Some(qtype),
            qclass: Some(qclass),
        });
    }
    let mut answers = Vec::new();
    for _ in 0..an {
        let name = read_dns_name(msg, &mut pos)?;
        if pos + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let class = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return None;
        }
        let rdata = msg[pos..pos + rdlen].to_vec();
        pos += rdlen;
        answers.push(DnsAnswer {
            name,
            rtype: Some(rtype),
            class: Some(class),
            ttl: Some(ttl),
            rdata,
        });
    }
    Some(DnsFields {
        id: Some(id),
        flags: Some(flags),
        opcode: None,
        questions,
        answers,
        raw: None,
    })
}

/// 读 DNS 域名（支持压缩指针）；返回 "a.b" 形式。
fn read_dns_name(msg: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut p = *pos;
    let mut jumped = false;
    let mut jumps = 0usize;
    let mut next_pos = None;
    loop {
        if p >= msg.len() {
            return None;
        }
        let len = msg[p] as usize;
        match len & 0xC0 {
            0x00 => {
                p += 1;
                if len == 0 {
                    break;
                }
                if p + len > msg.len() {
                    return None;
                }
                labels.push(String::from_utf8_lossy(&msg[p..p + len]).to_string());
                p += len;
            }
            0xC0 => {
                // 压缩指针
                if p + 1 >= msg.len() {
                    return None;
                }
                let target = ((len & 0x3F) << 8) | msg[p + 1] as usize;
                if jumped {
                    if jumps > 32 {
                        return None; // 防循环
                    }
                    jumps += 1;
                    p = target;
                } else {
                    next_pos = Some(p + 2);
                    p = target;
                    jumped = true;
                }
            }
            _ => return None, // 0x40/0x80 保留位
        }
    }
    *pos = next_pos.unwrap_or(p);
    Some(labels.join("."))
}

/// HTTP 请求/响应首部反解（只取头，body 按长度截断）。
fn parse_http(bytes: &[u8]) -> Option<HttpFields> {
    // 找 \r\n\r\n（头部结束）
    let head_end = bytes.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = &bytes[..head_end];
    let head_str = std::str::from_utf8(head).ok()?;
    let mut lines = head_str.split("\r\n");
    let start_line = lines.next()?;
    let (method, path, version) = if let Some(rest) = start_line.strip_prefix("HTTP/") {
        // 响应行：HTTP/1.1 200 OK
        (None, None, Some(format!("HTTP/{rest}")))
    } else {
        let mut parts = start_line.splitn(3, ' ');
        (
            Some(parts.next()?.to_string()),
            Some(parts.next()?.to_string()),
            Some(parts.next()?.to_string()),
        )
    };
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let body = bytes[head_end + 4..].to_vec();
    Some(HttpFields {
        method,
        path,
        version,
        headers,
        body: if body.is_empty() { None } else { Some(body) },
        raw: None,
    })
}
