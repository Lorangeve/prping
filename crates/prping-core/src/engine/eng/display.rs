//! 显示/渲染函数：层字段展示（含 DNS 域名来源标注）、hexdump、反解报告渲染、
//! 模块概览头。
//!
//! 忠实拆分自原 `engine/eng.rs` 的渲染段：term_width（795-856）、wrap_words /
//! render_* / describe_*（857-1545）、render_module_header（700-793）。

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use packet_dsl::DefaultSerializer;
use packet_dsl::ir::{Layer, MacAddr, PacketSpec};
use packet_dsl::semantic::Module;
use rust_i18n::t;
use termcolor::WriteColor;

use crate::engine::eng::{libs_display, value_display};
use crate::output::{
    print_cyan, print_dim, print_green, print_magenta, print_yellow, writeln_orange,
};

/// 折行宽度回退值（stdout 非 tty 或探测失败时）。
const WRAP_DEFAULT: usize = 100;

/// 终端列宽：stdout 为 tty 时查询实际宽度，失败/非 tty 回退 [`WRAP_DEFAULT`]。
fn term_width() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: TIOCGWINSZ 是纯查询 ioctl；非 tty 返回 -1 走回退。
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0
            && ws.ws_col > 0
        {
            return ws.ws_col as usize;
        }
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        struct Coord {
            x: i16,
            y: i16,
        }
        #[repr(C)]
        struct SmallRect {
            left: i16,
            top: i16,
            right: i16,
            bottom: i16,
        }
        #[repr(C)]
        struct ConsoleScreenBufferInfo {
            size: Coord,
            cursor_pos: Coord,
            attrs: u16,
            window: SmallRect,
            max_size: Coord,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetStdHandle(n: u32) -> *mut std::ffi::c_void;
            fn GetConsoleScreenBufferInfo(
                h: *mut std::ffi::c_void,
                info: *mut ConsoleScreenBufferInfo,
            ) -> i32;
        }
        // SAFETY: 控制台缓冲区信息为只读查询；非控制台/失败走回退。
        unsafe {
            let h = GetStdHandle(0xFFFF_FFF5); // STD_OUTPUT_HANDLE = (DWORD)-11
            let mut info: ConsoleScreenBufferInfo = std::mem::zeroed();
            if !h.is_null() && GetConsoleScreenBufferInfo(h, &mut info) != 0 {
                let w = i32::from(info.window.right) - i32::from(info.window.left) + 1;
                if w > 0 {
                    return w as usize;
                }
            }
        }
    }
    WRAP_DEFAULT
}

pub(crate) fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for tok in text.split_whitespace() {
        // 超宽词：先收掉当前行，再按 width 硬切，余下部分作为下一行开头
        if tok.len() > width {
            if !cur.is_empty() {
                lines.push(std::mem::take(&mut cur));
            }
            let mut rest = tok;
            while rest.len() > width {
                let mut cut = width;
                while !rest.is_char_boundary(cut) {
                    cut -= 1;
                }
                if cut == 0 {
                    // width 装不下首个字符：按单个字符切
                    cut = rest.chars().next().expect("rest 非空").len_utf8();
                }
                lines.push(rest[..cut].to_string());
                rest = &rest[cut..];
            }
            cur.push_str(rest);
            continue;
        }
        if cur.is_empty() {
            cur.push_str(tok);
        } else if cur.len() + 1 + tok.len() <= width {
            cur.push(' ');
            cur.push_str(tok);
        } else {
            lines.push(std::mem::take(&mut cur));
            cur.push_str(tok);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// 打印一层：`  [i] name  desc`，desc 过长按空格折行（续行对齐 desc 起始列）。
fn render_layer_line<W: WriteColor>(
    w: &mut W,
    i: usize,
    name: &str,
    desc: &str,
    width: usize,
) -> io::Result<()> {
    let prefix = format!("  [{i}] {name}");
    print_dim(w, &prefix)?;
    if desc.is_empty() {
        writeln!(w)?;
        return Ok(());
    }
    let indent = prefix.chars().count() + 2;
    let avail = width.saturating_sub(indent).max(1);
    let pad = " ".repeat(indent);
    for (k, seg) in wrap_words(desc, avail).iter().enumerate() {
        if k == 0 {
            print_yellow(w, format!("  {seg}"))?;
        } else {
            print_yellow(w, format!("{pad}{seg}"))?;
        }
        writeln!(w)?;
    }
    Ok(())
}

/// 渲染层栈（字段 + auto/random 标注）。
pub fn render_layers<W: WriteColor>(w: &mut W, layers: &[Layer], header: &str) -> io::Result<()> {
    print_cyan(w, header)?;
    writeln!(w)?;
    let width = term_width();
    for (i, layer) in layers.iter().enumerate() {
        render_layer_line(w, i, layer_name(layer), &describe_layer(layer), width)?;
    }
    Ok(())
}

/// 层字段渲染（无 hexdump）：`--eng` 与 `--pkt` 复用。
///
/// 每层字段：字节直喂层从「该层序列化后的字节」解析（len/checksum/proto 真实值，
/// 对标 scapy `Ether(bytes)`）；语义层（无 raw）用 IR 字段 + auto 标注。
/// `ser` 由调用方传入（`--pkt` 传实际发送用的序列化器，fuzz 与发送一致）。
/// 返回完整包字节（供调用方决定是否 hexdump）。
pub fn render_packet_fields<W: WriteColor>(
    w: &mut W,
    pkt: &PacketSpec,
    header: &str,
    ser: &DefaultSerializer,
) -> io::Result<Vec<u8>> {
    let (bytes, parts) = ser.serialize_parts(pkt).map_err(io::Error::other)?;
    print_cyan(w, header)?;
    writeln!(w)?;
    let width = term_width();
    for (i, layer) in pkt.layers.iter().enumerate() {
        let desc = if layer_raw(layer).is_some() {
            // 该层在序列化结果中的区间（内→外）；外层包含内层，取自身头部分
            let seg = parts.get(i).map(|&(s, e)| &bytes[s..e]);
            match seg {
                Some(seg) => describe_raw_bytes(layer, seg),
                None => describe_layer(layer),
            }
        } else {
            describe_layer(layer)
        };
        render_layer_line(w, i, layer_name(layer), &desc, width)?;
    }
    print_dim(w, format!("  bytes: {} B", bytes.len()))?;
    writeln!(w)?;
    Ok(bytes)
}

/// 渲染一个包：层栈字段（从序列化后的真实字节解析）+ 字节 hexdump。
pub fn render_packet<W: WriteColor>(w: &mut W, pkt: &PacketSpec, header: &str) -> io::Result<()> {
    let ser = DefaultSerializer::new();
    let bytes = render_packet_fields(w, pkt, header, &ser)?;
    render_hexdump(w, &bytes)?;
    writeln!(w)?;
    Ok(())
}

/// 层序咨询性警告（只提示不阻断）：`--eng` 展示与 `--pkt` 发送共用。
/// 无警告时静默；每条一行橙色 `note:`，风格与 fake-ip 等运行期提示一致。
pub fn print_stack_warnings<W: WriteColor>(w: &mut W, pkt: &PacketSpec) -> io::Result<()> {
    for warn in packet_dsl::stack_warnings(pkt) {
        let msg = match warn.kind {
            packet_dsl::StackWarningKind::ReversedOrder => {
                t!(
                    "engine.note_stack_reversed",
                    inner = warn.inner,
                    outer = warn.outer
                )
            }
            packet_dsl::StackWarningKind::TransportInTransport => t!(
                "engine.note_stack_transport_in_transport",
                inner = warn.inner,
                outer = warn.outer
            ),
            packet_dsl::StackWarningKind::MissingNetwork => t!(
                "engine.note_stack_missing_network",
                inner = warn.inner,
                outer = warn.outer
            ),
            packet_dsl::StackWarningKind::PayloadOnly => {
                t!(
                    "engine.note_stack_payload_only",
                    inner = warn.inner,
                    outer = warn.outer
                )
            }
            packet_dsl::StackWarningKind::UninferrableProto => t!(
                "engine.note_stack_uninferrable_proto",
                inner = warn.inner,
                outer = warn.outer
            ),
            packet_dsl::StackWarningKind::WrongCarrier => t!(
                "engine.note_stack_wrong_carrier",
                inner = warn.inner,
                outer = warn.outer,
                carriers = warn.carriers.join("/")
            ),
        };
        writeln_orange(w, format!("  {msg}"))?;
    }
    Ok(())
}

/// 渲染反解报告（层栈 + 注记 + hexdump）。
pub fn render_dissected<W: WriteColor>(
    w: &mut W,
    report: &packet_dsl::dissect::DissectReport,
    header: &str,
    bytes: &[u8],
) -> io::Result<()> {
    if report.layers.is_empty() {
        print_red_plain(w, &format!("{header} — 未能识别任何层"))?;
        writeln!(w)?;
    } else {
        render_layers(w, &report.layers, header)?;
    }
    // proto（自表示协议）解析命中，如 QUIC（含 rest(子proto) 嵌套）
    for hit in &report.proto {
        render_proto_hit(w, hit, 2)?;
    }
    for n in &report.notes {
        print_yellow(w, format!("  note: {n}"))?;
        writeln!(w)?;
    }
    if !report.remaining.is_empty() {
        print_dim(w, format!("  remaining: {} B", report.remaining.len()))?;
        writeln!(w)?;
    }
    if !bytes.is_empty() {
        render_hexdump(w, bytes)?;
    }
    writeln!(w)?;
    Ok(())
}

/// 递归渲染一条 proto 命中（子命中缩进）。
fn render_proto_hit<W: WriteColor>(
    w: &mut W,
    hit: &packet_dsl::ProtoHit,
    indent: usize,
) -> io::Result<()> {
    let pad = " ".repeat(indent);
    print_cyan(w, format!("{pad}proto: {}", hit.name))?;
    writeln!(w)?;
    for (name, val) in &hit.fields {
        print_dim(w, format!("{pad}  {name} = {}", val.display()))?;
        writeln!(w)?;
    }
    for sub in &hit.subs {
        render_proto_hit(w, sub, indent + 2)?;
    }
    Ok(())
}

fn print_red_plain<W: WriteColor>(w: &mut W, text: &str) -> io::Result<()> {
    w.set_color(termcolor::ColorSpec::new().set_fg(Some(termcolor::Color::Red)))?;
    write!(w, "{text}")?;
    w.reset()
}

fn print_bold_plain<W: WriteColor>(w: &mut W, text: &str) -> io::Result<()> {
    w.set_color(termcolor::ColorSpec::new().set_bold(true))?;
    write!(w, "{text}")?;
    w.reset()
}

/// 16 字节一行的 hexdump：偏移 + hex + ASCII。
///
/// 每行 8 空格缩进：hexdump 是 `sent:`/`reply:`/`frame:` 等标题下的内容块，
/// 用缩进与 2 空格标题层级区分。
pub fn render_hexdump<W: WriteColor>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    for (off, chunk) in bytes.chunks(16).enumerate() {
        print_dim(w, format!("        {off:04x}  "))?;
        let mut hex = String::new();
        let mut ascii = String::new();
        for b in chunk {
            hex.push_str(&format!("{b:02x} "));
            ascii.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        for _ in chunk.len()..16 {
            hex.push_str("   ");
        }
        write!(w, "{hex} ")?;
        print_green(w, format!("|{ascii}|"))?;
        writeln!(w)?;
    }
    Ok(())
}

pub fn layer_name(l: &Layer) -> &'static str {
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

/// 层字段描述：用户填的值直接显示，未填字段标 `auto`。
/// 层头 bytes= 直喂的原始字节（无则 None）。
fn layer_raw(l: &Layer) -> Option<&[u8]> {
    match l {
        Layer::Ethernet(f) => f.raw.as_deref(),
        Layer::Arp(f) => f.raw.as_deref(),
        Layer::Ipv4(f) => f.raw.as_deref(),
        Layer::Ipv6(f) => f.raw.as_deref(),
        Layer::Icmp(f) => f.raw.as_deref(),
        Layer::Tcp(f) => f.raw.as_deref(),
        Layer::Udp(f) => f.raw.as_deref(),
        Layer::Http(f) => f.raw.as_deref(),
        Layer::Dns(f) => f.raw.as_deref(),
        Layer::Raw(_) => None,
    }
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 地址展示：域名解析来源时显示 `dns(host->ip)`，否则显示 IP。
fn addr_disp(host: &Option<String>, ip: String) -> String {
    match host {
        Some(h) => format!("dns({h}->{ip})"),
        None => ip,
    }
}

/// 从层头字节解析字段描述（scapy 风格：`<IP version=4 ihl=5 ...>`）。
/// 用于 bytes 直喂 / 反解层——字节是唯一真相，字段值从头部字节读。
fn describe_raw_bytes(l: &Layer, raw: &[u8]) -> String {
    match l {
        Layer::Ethernet(_) if raw.len() >= 14 => {
            let mac = |b: &[u8]| {
                b.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            };
            format!(
                "dst={} src={} ethertype=0x{:04x}",
                mac(&raw[0..6]),
                mac(&raw[6..12]),
                u16::from_be_bytes([raw[12], raw[13]])
            )
        }
        Layer::Arp(_) if raw.len() >= 28 => {
            let mac = |b: &[u8]| {
                b.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            };
            let ip = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string();
            format!(
                "op={} sha={} spa={} tha={} tpa={}",
                u16::from_be_bytes([raw[6], raw[7]]),
                mac(&raw[8..14]),
                ip(&raw[14..18]),
                mac(&raw[18..24]),
                ip(&raw[24..28])
            )
        }
        Layer::Ipv4(f) if raw.len() >= 20 => {
            let frag = u16::from_be_bytes([raw[6], raw[7]]);
            let proto = raw[9];
            let proto_name = match proto {
                1 => "ICMP".to_string(),
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                other => format!("{other}"),
            };
            let src = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]).to_string();
            let dst = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]).to_string();
            format!(
                "version={} ihl={} tos=0x{:02x} len={} id={} flags={} frag={} ttl={} proto={} chksum=0x{:04x} src={} dst={}",
                raw[0] >> 4,
                raw[0] & 0x0F,
                raw[1],
                u16::from_be_bytes([raw[2], raw[3]]),
                u16::from_be_bytes([raw[4], raw[5]]),
                if frag & 0x4000 != 0 { "DF" } else { "-" },
                frag & 0x1FFF,
                raw[8],
                proto_name,
                u16::from_be_bytes([raw[10], raw[11]]),
                addr_disp(&f.src_host, src),
                addr_disp(&f.dst_host, dst),
            )
        }
        Layer::Ipv6(f) if raw.len() >= 40 => {
            let nh = raw[6];
            let nh_name = match nh {
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                58 => "ICMPv6".to_string(),
                other => format!("{other}"),
            };
            let ip6 = |b: &[u8]| {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                Ipv6Addr::from(a).to_string()
            };
            let src = ip6(&raw[8..24]);
            let dst = ip6(&raw[24..40]);
            format!(
                "version={} traffic_class=0x{:02x} flow_label=0x{:05x} payload_len={} next_header={} hop_limit={} src={} dst={}",
                raw[0] >> 4,
                ((raw[0] & 0x0F) << 4) | (raw[1] >> 4),
                (((raw[1] & 0x0F) as u32) << 16) | ((raw[2] as u32) << 8) | raw[3] as u32,
                u16::from_be_bytes([raw[4], raw[5]]),
                nh_name,
                raw[7],
                addr_disp(&f.src_host, src),
                addr_disp(&f.dst_host, dst),
            )
        }
        Layer::Icmp(_) if raw.len() >= 8 => {
            // payload 长度从语义字段取（反解层载荷在 payload，非头部字节）
            let payload = match l {
                Layer::Icmp(f) => f
                    .payload
                    .as_ref()
                    .map(|p| format!(" payload={} B", p.len()))
                    .unwrap_or_default(),
                _ => String::new(),
            };
            format!(
                "type={} code={} chksum=0x{:04x} id={} seq={}{}",
                raw[0],
                raw[1],
                u16::from_be_bytes([raw[2], raw[3]]),
                u16::from_be_bytes([raw[4], raw[5]]),
                u16::from_be_bytes([raw[6], raw[7]]),
                payload
            )
        }
        Layer::Tcp(_) if raw.len() >= 20 => {
            let flags = raw[13];
            let mut fs = String::new();
            for (bit, name) in [
                (0x01, "FIN"),
                (0x02, "SYN"),
                (0x04, "RST"),
                (0x08, "PSH"),
                (0x10, "ACK"),
                (0x20, "URG"),
                (0x40, "ECE"),
                (0x80, "CWR"),
            ] {
                if flags & bit != 0 {
                    if !fs.is_empty() {
                        fs.push(',');
                    }
                    fs.push_str(name);
                }
            }
            format!(
                "sport={} dport={} seq={} ack={} dataofs={} flags={} window={} chksum=0x{:04x} urgptr={}",
                u16::from_be_bytes([raw[0], raw[1]]),
                u16::from_be_bytes([raw[2], raw[3]]),
                u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
                u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]),
                raw[12] >> 4,
                if fs.is_empty() { "-".to_string() } else { fs },
                u16::from_be_bytes([raw[14], raw[15]]),
                u16::from_be_bytes([raw[16], raw[17]]),
                u16::from_be_bytes([raw[18], raw[19]])
            )
        }
        Layer::Udp(_) if raw.len() >= 8 => format!(
            "sport={} dport={} len={} chksum=0x{:04x}",
            u16::from_be_bytes([raw[0], raw[1]]),
            u16::from_be_bytes([raw[2], raw[3]]),
            u16::from_be_bytes([raw[4], raw[5]]),
            u16::from_be_bytes([raw[6], raw[7]])
        ),
        // DNS 已 proto 化：反解/构造侧都回填 questions/answers（压缩指针追跳还原），
        // 直接显示字段；头部不足时回退 bytes=0x… 摘要
        Layer::Dns(f) => {
            let mut parts = vec![
                format!("id=0x{:04x}", f.id.unwrap_or(0)),
                format!("flags=0x{:04x}", f.flags.unwrap_or(0)),
            ];
            for q in &f.questions {
                parts.push(format!("q={}({})", q.name, dns_type_name(q.qtype)));
            }
            for a in &f.answers {
                parts.push(format!(
                    "a={}:{}",
                    a.name,
                    dns_rdata_disp(a.rtype, &a.rdata)
                ));
            }
            if parts.len() > 2 {
                parts.join(" ")
            } else {
                let n = raw.len().min(12);
                format!("bytes=0x{}…", hex_str(&raw[..n]))
            }
        }
        // HTTP 已 proto 化：反解/构造侧都回填 method/path/version/headers/body
        Layer::Http(f) => format!(
            "{} {} {} headers={} body={} B",
            f.method.clone().unwrap_or_else(|| "auto".to_string()),
            f.path.clone().unwrap_or_else(|| "auto".to_string()),
            f.version.clone().unwrap_or_else(|| "auto".to_string()),
            f.headers.len(),
            opt_bytes_len(&f.body)
        ),
        _ => {
            // 头部不足：回退 bytes=0x… 摘要
            let n = raw.len().min(12);
            format!("bytes=0x{}…", hex_str(&raw[..n]))
        }
    }
}

/// DNS 类型名（未知类型显示数字）。
pub fn dns_type_name(t: Option<u16>) -> String {
    match t {
        Some(1) => "A".into(),
        Some(2) => "NS".into(),
        Some(5) => "CNAME".into(),
        Some(6) => "SOA".into(),
        Some(12) => "PTR".into(),
        Some(15) => "MX".into(),
        Some(16) => "TXT".into(),
        Some(28) => "AAAA".into(),
        Some(33) => "SRV".into(),
        Some(41) => "OPT".into(),
        Some(255) => "ANY".into(),
        Some(n) => format!("{n}"),
        None => "?".into(),
    }
}

/// DNS rdata 展示：A/AAAA 解为 IP，其余十六进制。
fn dns_rdata_disp(t: Option<u16>, rdata: &[u8]) -> String {
    match (t, rdata.len()) {
        (Some(1), 4) => Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
        (Some(28), 16) => {
            let mut a = [0u8; 16];
            a.copy_from_slice(rdata);
            Ipv6Addr::from(a).to_string()
        }
        _ => format!("0x{}", hex_str(rdata)),
    }
}

fn describe_layer(l: &Layer) -> String {
    // bytes= 直喂 / 反解层：从头部字节解析字段（scapy 风格）
    if let Some(raw) = layer_raw(l) {
        return describe_raw_bytes(l, raw);
    }
    match l {
        Layer::Ethernet(f) => format!(
            "src={} dst={} ethertype={}",
            field_mac(f.src_mac, "auto"),
            field_mac(f.dst_mac, "auto"),
            opt_hex(f.ethertype, "auto")
        ),
        Layer::Arp(f) => format!(
            "op={} sha={} spa={} tha={} tpa={}",
            opt(&f.op, "auto"),
            opt_mac(f.sha, "auto"),
            opt_ip4(f.spa, "auto"),
            opt_mac(f.tha, "auto"),
            opt_ip4(f.tpa, "auto")
        ),
        Layer::Ipv4(f) => format!(
            "src={} dst={} ttl={} proto={} tos={} id={} flags={}",
            field_ip4(f.src, "auto"),
            field_ip4(f.dst, "auto"),
            field_u8(f.ttl, "auto"),
            opt(&f.proto, "auto"),
            opt(&f.tos, "auto"),
            opt(&f.id, "auto"),
            opt_flags4(f.flags)
        ),
        Layer::Ipv6(f) => format!(
            "src={} dst={} hop_limit={} next_header={}",
            field_ip6(f.src, "auto"),
            field_ip6(f.dst, "auto"),
            field_u8(f.hop_limit, "auto"),
            opt(&f.next_header, "auto")
        ),
        Layer::Icmp(f) => format!(
            "type={} code={} id={} seq={} payload={} B",
            opt(&f.icmp_type, "auto"),
            opt(&f.code, "auto"),
            opt(&f.id, "auto"),
            opt(&f.seq, "auto"),
            opt_bytes_len(&f.payload)
        ),
        Layer::Tcp(f) => format!(
            "sport={} dport={} seq={} ack={} flags={} window={} mss={}",
            opt(&f.src_port, "auto"),
            opt(&f.dst_port, "auto"),
            opt(&f.seq, "auto"),
            opt(&f.ack, "auto"),
            opt_tcp_flags(f.flags),
            opt(&f.window, "auto"),
            match f.options.first() {
                Some(packet_dsl::ir::TcpOption::Mss(m)) => m.to_string(),
                None => "-".to_string(),
            }
        ),
        Layer::Udp(f) => format!(
            "sport={} dport={}",
            opt(&f.src_port, "auto"),
            opt(&f.dst_port, "auto")
        ),
        Layer::Http(f) => format!(
            "{} {} {} headers={} body={} B",
            f.method.clone().unwrap_or_else(|| "auto".to_string()),
            f.path.clone().unwrap_or_else(|| "auto".to_string()),
            f.version.clone().unwrap_or_else(|| "auto".to_string()),
            f.headers.len(),
            opt_bytes_len(&f.body)
        ),
        Layer::Dns(f) => {
            let mut parts = vec![
                format!("id={}", opt(&f.id, "auto")),
                format!("flags={}", opt(&f.flags, "auto")),
            ];
            for q in &f.questions {
                parts.push(format!("q={}({})", q.name, dns_type_name(q.qtype)));
            }
            parts.push(format!("answers={}", f.answers.len()));
            parts.join(" ")
        }
        Layer::Raw(r) => format!("{} bytes", r.bytes.len()),
    }
}

fn field_show<T: std::fmt::Display>(f: &packet_dsl::ir::Field<T>, auto: &str) -> String {
    use packet_dsl::ir::Field;
    match f {
        Field::Auto => auto.to_string(),
        Field::Random => "random".to_string(),
        Field::Value(v) => v.to_string(),
    }
}

fn field_mac(f: packet_dsl::ir::Field<packet_dsl::ir::MacAddr>, auto: &str) -> String {
    field_show(&f, auto)
}

fn field_ip4(f: packet_dsl::ir::Field<std::net::Ipv4Addr>, auto: &str) -> String {
    field_show(&f, auto)
}

fn field_ip6(f: packet_dsl::ir::Field<std::net::Ipv6Addr>, auto: &str) -> String {
    field_show(&f, auto)
}

fn field_u8(f: packet_dsl::ir::Field<u8>, auto: &str) -> String {
    field_show(&f, auto)
}

fn opt<T: std::fmt::Display>(o: &Option<T>, auto: &str) -> String {
    o.as_ref()
        .map(|v| v.to_string())
        .unwrap_or_else(|| auto.to_string())
}

fn opt_mac(o: Option<MacAddr>, auto: &str) -> String {
    o.map(|m| m.to_string()).unwrap_or_else(|| auto.to_string())
}

fn opt_ip4(o: Option<std::net::Ipv4Addr>, auto: &str) -> String {
    o.map(|v| v.to_string()).unwrap_or_else(|| auto.to_string())
}

fn opt_hex(o: Option<u16>, auto: &str) -> String {
    o.map(|v| format!("0x{v:04x}"))
        .unwrap_or_else(|| auto.to_string())
}

pub fn opt_bytes_len(o: &Option<Vec<u8>>) -> String {
    o.as_ref()
        .map(|v| v.len().to_string())
        .unwrap_or_else(|| "auto".to_string())
}

fn opt_flags4(f: Option<packet_dsl::ir::Ipv4Flags>) -> String {
    match f {
        Some(fl) => {
            let mut parts: Vec<String> = Vec::new();
            if fl.df {
                parts.push("df".to_string());
            }
            if fl.mf {
                parts.push("mf".to_string());
            }
            if fl.frag_offset != 0 {
                parts.push(format!("off={}", fl.frag_offset));
            }
            if parts.is_empty() {
                "0".to_string()
            } else {
                parts.join(",")
            }
        }
        None => "auto".to_string(),
    }
}

fn opt_tcp_flags(f: Option<packet_dsl::ir::TcpFlags>) -> String {
    f.map(|fl| fl.to_string())
        .unwrap_or_else(|| "auto".to_string())
}

pub(crate) fn render_module_header<W: WriteColor>(
    w: &mut W,
    module: &Module,
    total: usize,
    libs: &[PathBuf],
) -> io::Result<()> {
    print_magenta(w, "packet-dsl engine")?;
    writeln!(w)?;
    print_cyan(w, "module: ")?;
    print_bold_plain(w, &module.name)?;
    if let Some(path) = &module.path {
        print_dim(w, format!("  (file: {})", path.display()))?;
    }
    writeln!(w)?;
    if !module.imports.is_empty() {
        let imps: Vec<String> = module
            .imports
            .iter()
            .map(|i| match &i.names {
                Some(names) => format!(
                    "{} {{ {} }}",
                    i.module,
                    names
                        .iter()
                        .map(|(n, alias, _)| match alias {
                            Some(a) => format!("{n} as {a}"),
                            None => n.clone(),
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => i.module.clone(),
            })
            .collect();
        print_dim(w, format!("imports: {}   ", imps.join(", ")))?;
    }
    if !module.exports.is_empty() {
        let exps: Vec<&str> = module.exports.iter().map(|(n, _)| n.as_str()).collect();
        print_dim(w, format!("exports: {}   ", exps.join(", ")))?;
    }
    if module.default.is_some() {
        print_dim(w, "default: yes")?;
    }
    writeln!(w)?;
    if !module.defs.is_empty() {
        let defs: Vec<&str> = module.defs.iter().map(|d| d.name.as_str()).collect();
        print_dim(w, format!("defs: {}", defs.join(", ")))?;
        writeln!(w)?;
    }
    if !module.funcs.is_empty() {
        for f in &module.funcs {
            let params: Vec<String> = f
                .params
                .iter()
                .map(|p| match &p.default {
                    Some(d) => format!("{}={}", p.name, value_display(d)),
                    None => p.name.clone(),
                })
                .collect();
            print_dim(w, format!("func {}({})", f.name, params.join(", ")))?;
            writeln!(w)?;
        }
    }
    print_dim(w, format!("packets: {total}"))?;
    writeln!(w)?;
    if let Some(sn) = &module.sniffer {
        print_dim(w, "sniffer:")?;
        writeln!(w)?;
        for clause in &sn.clauses {
            let fields: Vec<String> = clause
                .fields
                .iter()
                .map(|(name, v)| match v {
                    packet_dsl::SnifferValue::Literal(l) => {
                        format!("{name}={}", value_display(l))
                    }
                    packet_dsl::SnifferValue::SentField(f) => format!("{name}={f}"),
                    packet_dsl::SnifferValue::Expr(e) => {
                        format!("{name}={}", value_display(e))
                    }
                })
                .collect();
            print_dim(
                w,
                format!("  - match {}({})", clause.layer, fields.join(", ")),
            )?;
            writeln!(w)?;
        }
    }
    print_dim(w, format!("libs: {}", libs_display(libs)))?;
    writeln!(w)?;
    writeln!(w)?;
    Ok(())
}
