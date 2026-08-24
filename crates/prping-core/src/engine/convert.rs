//! pcap → .pkt/.pktl 转码（`--eng --pcap FILE --to-pkt DIR`，`--out` 的逆操作）。
//!
//! 两种路线（`ConvertOptions.structured` 切换，缺省无损字节级）：
//!
//! - **无损字节级（A1）**：每条记录一个 `.pkt`，整帧/整包经 `layer("eth"/"ipv4"/"ipv6", hex(...))`
//!   或 `raw(bytes=hex(...))` 直喂——字节 100% 保真（不经语义字段层，checksum 不会被重算），
//!   且最外层为 eth/ipv4/ipv6 时可直接 `--raw` 发送还原捕获字节。
//! - **语义结构化（A2）**：`dissect` 反解层栈 → DSL 源码（eth/arp/ipv4/ipv6/icmp/tcp/udp
//!   语义字段 + 位常量；dns/http 及带选项/无法表达的头走 `*_bytes(hex(...))` 字节直喂兜底）。
//!   合法捕获经 `layer rev` + 每层 raw 头字节，重序列化**字节级还原**（roundtrip 保真）；
//!   有 `remaining`（如以太网填充/未知协议载荷）或无法反解时整条退回 A1。
//!
//! 每条记录生成 `record_{n:05}.pkt`（按 pcap 内原始序号，`--skip/--limit` 不影响命名），
//! 另生成一个 `.pktl` 配方按序引用全部 `.pkt`，步骤 `delay:` 携带捕获帧间隔
//! （`recipe.rs`/`pkg.rs::send_recipe` 支持；首步无 delay，第 1 步忽略）。

use std::io::Write as _;
use std::path::{Path, PathBuf};

use packet_dsl::ir::{ArpOp, Field, Layer, TcpFlags};

use crate::engine::eng::layer_name;
use crate::output::{print_cyan, print_dim, print_magenta};
use termcolor::{ColorChoice, StandardStream};

/// 转码选项。
#[derive(Debug, Clone)]
pub struct ConvertOptions {
    /// 输出目录（自动创建）。
    pub out_dir: PathBuf,
    /// 语义结构化（A2）；缺省无损字节级（A1）。
    pub structured: bool,
    /// 跳过前 N 条记录（按 pcap 原始序号）。
    pub skip: usize,
    /// 最多转换 N 条（None = 全部）。
    pub limit: Option<usize>,
    /// 解析/渲染并发线程数：0 = 自动（记录数 ≥ [`PARALLEL_THRESHOLD`] 时按
    /// `available_parallelism` 并行，否则单线程）；1 = 强制单线程；N = 精确 N 线程。
    pub threads: usize,
}

/// 自动并行的记录数下限：低于此值线程池开销得不偿失，直接单线程。
pub const PARALLEL_THRESHOLD: usize = 1024;

/// 单次转换的共享上下文（跨记录不变；并行 worker 捕获引用）。
struct ConvertCtx<'a> {
    path: &'a Path,
    total: usize,
    network: u16,
    nano: bool,
    out_dir: &'a Path,
    structured: bool,
}

/// 实际生效的线程数（0 = 自动阈值判断）。
pub fn effective_threads(total: usize, requested: usize) -> usize {
    match requested {
        0 => {
            if total < PARALLEL_THRESHOLD {
                1
            } else {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
                    .min(total)
            }
        }
        n => n.min(total).max(1),
    }
}

/// 转码报告。
#[derive(Debug, Clone)]
pub struct ConvertReport {
    /// pcap 总记录数。
    pub total: usize,
    /// 实际转换的记录数（skip/limit 后）。
    pub written: usize,
    /// 生成的 .pkt 文件（与记录一一对应，按原始序号命名）。
    pub files: Vec<PathBuf>,
    /// 生成的配方 .pktl。
    pub recipe: PathBuf,
    /// 是否语义结构化模式。
    pub structured: bool,
}

/// 单条记录的生成结果（供打印与测试）。
struct RecordOut {
    file: PathBuf,
    src: String,
    /// 实际采用的路线：structured / lossless / fallback（结构化解不开退回无损）。
    mode: &'static str,
    /// 记录原始字节数。
    len: usize,
}

/// 转码入口：读 pcap → 逐条生成 .pkt → 写配方 .pktl → 打印摘要。
pub fn convert_pcap(path: &Path, opts: &ConvertOptions) -> anyhow::Result<ConvertReport> {
    crate::engine::eng::ensure_proto_registry();
    let (network, nano, records) = crate::engine::pcap::read_pcap(path)?;
    if records.is_empty() {
        anyhow::bail!("pcap {} 没有记录", path.display());
    }
    let selected = records
        .iter()
        .enumerate()
        .skip(opts.skip)
        .filter(|(i, _)| opts.limit.is_none_or(|lim| *i - opts.skip < lim))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        anyhow::bail!(
            "pcap {} 共 {} 条记录，skip={} limit={:?} 后没有可转换的记录",
            path.display(),
            records.len(),
            opts.skip,
            opts.limit
        );
    }

    std::fs::create_dir_all(&opts.out_dir)
        .map_err(|e| anyhow::anyhow!("创建输出目录失败（{}）：{e}", opts.out_dir.display()))?;

    // 逐记录渲染 + 写文件：每条记录完全独立（dissect/渲染是纯函数，无共享状态），
    // `--threads N` 或记录数超过阈值时用 std::thread::scope 并行；结果按序号归位，
    // 与单线程输出逐字节一致（确定性）。
    let ctx = ConvertCtx {
        path,
        total: records.len(),
        network,
        nano,
        out_dir: &opts.out_dir,
        structured: opts.structured,
    };
    let nthreads = effective_threads(selected.len(), opts.threads);
    let out = if nthreads <= 1 {
        let mut out = Vec::with_capacity(selected.len());
        for (i, rec) in &selected {
            let file = ctx.out_dir.join(format!("record_{:05}.pkt", i + 1));
            let ro = if ctx.structured {
                render_structured(ctx.path, *i, ctx.total, ctx.network, ctx.nano, rec, &file)
            } else {
                render_lossless(ctx.path, *i, ctx.total, ctx.network, ctx.nano, rec, &file)
            };
            std::fs::write(&file, &ro.src)
                .map_err(|e| anyhow::anyhow!("写 {} 失败：{e}", file.display()))?;
            out.push(ro);
        }
        out
    } else {
        convert_records_parallel(&ctx, &selected, nthreads)?
    };

    // 配方 .pktl：按序引用全部 .pkt，delay = 相邻记录捕获间隔（秒，≤6 位小数）
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "pcap".to_string());
    let recipe_path = opts.out_dir.join(format!("{stem}.pktl"));
    let recipe_src = render_recipe(path, &selected, nano, &recipe_path);
    std::fs::write(&recipe_path, &recipe_src)
        .map_err(|e| anyhow::anyhow!("写 {} 失败：{e}", recipe_path.display()))?;

    let report = ConvertReport {
        total: records.len(),
        written: out.len(),
        files: out.iter().map(|r| r.file.clone()).collect(),
        recipe: recipe_path.clone(),
        structured: opts.structured,
    };
    render_summary(path, opts, &report, &out);
    Ok(report)
}

/// 并行逐记录渲染 + 写文件（`std::thread::scope`，零新依赖）。
///
/// worker 用 `AtomicUsize` 索引取记录（负载均衡），各自渲染并写自己的文件
/// （文件名按原始序号互不相同，无竞争），只回传元数据（src 已随写盘 drop，
/// 大 pcap 不堆积字符串内存）；结果按序号归位后返回，与单线程逐字节一致。
/// 任一写盘失败 → 记录到共享错误槽，其余 worker 尽快退出，join 后整体报错。
fn convert_records_parallel(
    ctx: &ConvertCtx<'_>,
    selected: &[(usize, &crate::engine::pcap::PcapRecord)],
    nthreads: usize,
) -> anyhow::Result<Vec<RecordOut>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    let next = AtomicUsize::new(0);
    let err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    let results: Mutex<Vec<(usize, RecordOut)>> = Mutex::new(Vec::with_capacity(selected.len()));
    // 提前取出 guard 供闭包捕获（避免闭包内每次 lock 的借用问题）
    let err_ref = &err;
    let results_ref = &results;

    std::thread::scope(|s| {
        for _ in 0..nthreads {
            s.spawn(|| {
                loop {
                    if err_ref.lock().unwrap().is_some() {
                        return;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= selected.len() {
                        return;
                    }
                    let (rec_idx, rec) = selected[i];
                    let file = ctx.out_dir.join(format!("record_{:05}.pkt", rec_idx + 1));
                    let ro = if ctx.structured {
                        render_structured(
                            ctx.path,
                            rec_idx,
                            ctx.total,
                            ctx.network,
                            ctx.nano,
                            rec,
                            &file,
                        )
                    } else {
                        render_lossless(
                            ctx.path,
                            rec_idx,
                            ctx.total,
                            ctx.network,
                            ctx.nano,
                            rec,
                            &file,
                        )
                    };
                    if let Err(e) = std::fs::write(&file, &ro.src) {
                        *err_ref.lock().unwrap() =
                            Some(anyhow::anyhow!("写 {} 失败：{e}", file.display()));
                        return;
                    }
                    results_ref.lock().unwrap().push((i, ro));
                }
            });
        }
    });
    let err: MutexGuard<'_, Option<anyhow::Error>> = err.lock().unwrap();
    if let Some(e) = err.as_ref() {
        return Err(anyhow::anyhow!("{}", e));
    }
    drop(err);
    let mut out = results.lock().unwrap();
    out.sort_by_key(|(i, _)| *i);
    Ok(out.drain(..).map(|(_, ro)| ro).collect())
}

// ── A1：无损字节级 ─────────────────────────────────────────────

/// 整帧/整包 → 可发送的外层标注（eth → 帧；raw linktype 按版本嗅探 ipv4/ipv6；其余 opaque raw）。
fn lossless_layer(data: &[u8], network: u16) -> String {
    match network {
        1 => format!("layer(\"eth\", hex(\"{}\"))", hex_str(data)),
        101 => match data.first().map(|b| b >> 4) {
            Some(4) => format!("layer(\"ipv4\", hex(\"{}\"))", hex_str(data)),
            Some(6) => format!("layer(\"ipv6\", hex(\"{}\"))", hex_str(data)),
            _ => format!("raw(bytes=hex(\"{}\"))", hex_str(data)),
        },
        _ => format!("raw(bytes=hex(\"{}\"))", hex_str(data)),
    }
}

fn render_lossless(
    path: &Path,
    idx: usize,
    total: usize,
    network: u16,
    nano: bool,
    rec: &crate::engine::pcap::PcapRecord,
    file: &Path,
) -> RecordOut {
    let ts = fmt_ts(rec, nano);
    let mut src = String::new();
    src.push_str(&format!(
        "# 转码自 {} 记录 {}/{}  linktype={}  t={ts}  {} B\n",
        path.display(),
        idx + 1,
        total,
        network,
        rec.data.len()
    ));
    src.push_str("# 无损字节级：整帧 hex 直喂（--raw 发送可还原捕获字节）\n");
    if network != 1 && network != 101 {
        src.push_str(&format!(
            "# 注意：未知链路类型 {network}（仅支持 1=Ethernet / 101=Raw），无法按 eth/ip 原始发送，仅存档\n"
        ));
    }
    src.push_str(&format!(
        "p = {}\nexport:\n- p\n",
        lossless_layer(&rec.data, network)
    ));
    RecordOut {
        file: file.to_path_buf(),
        src,
        mode: "lossless",
        len: rec.data.len(),
    }
}

// ── A2：语义结构化 ─────────────────────────────────────────────

/// 单条记录结构化渲染；解不开/有 remaining（填充等）→ 退回 A1（fallback）。
fn render_structured(
    path: &Path,
    idx: usize,
    total: usize,
    network: u16,
    nano: bool,
    rec: &crate::engine::pcap::PcapRecord,
    file: &Path,
) -> RecordOut {
    let ts = fmt_ts(rec, nano);
    let report = packet_dsl::dissect(&rec.data);
    let fallback = || {
        let mut ro = render_lossless(path, idx, total, network, nano, rec, file);
        ro.mode = "fallback";
        let reason = if report.layers.is_empty() {
            "无法反解".to_string()
        } else {
            format!(
                "{} 字节未归入任何层（填充/未知载荷）",
                report.remaining.len()
            )
        };
        // 在文件头插入退回原因（render_lossless 已写两行头注释，插到其后）
        let mark = "# 无损字节级：整帧 hex 直喂（--raw 发送可还原捕获字节）\n";
        if let Some(pos) = ro.src.find(mark) {
            ro.src
                .insert_str(pos + mark.len(), &format!("# 结构化退回：{reason}\n"));
        }
        ro
    };

    if report.layers.is_empty() || !report.remaining.is_empty() {
        return fallback();
    }

    // 层序：dissect 展示序（外→内），DSL 管道需 内→外
    let inner_first: Vec<Layer> = report.layers.into_iter().rev().collect();
    let mut rendered: Vec<(String, bool)> = Vec::new(); // (DSL 片段, 是否 bytes 直喂)
    for l in &inner_first {
        rendered.push(render_layer(l));
    }
    let any_bytes_feed = rendered.iter().any(|(_, fb)| *fb);

    let mut src = String::new();
    src.push_str(&format!(
        "# 转码自 {} 记录 {}/{}  linktype={}  t={ts}  {} B\n",
        path.display(),
        idx + 1,
        total,
        network,
        rec.data.len()
    ));
    if any_bytes_feed {
        src.push_str(
            "# 语义结构化；部分层字节直喂（dns/http/选项头等语义字段无法表达，hex 保真）\n",
        );
    } else {
        src.push_str("# 语义结构化（roundtrip 字节一致）\n");
    }
    for n in &report.notes {
        src.push_str(&format!("# 注：{n}\n"));
    }
    let stack: Vec<&str> = inner_first.iter().rev().map(layer_name).collect();
    src.push_str(&format!("# 层栈: {}\n", stack.join(" -> ")));

    if rendered.len() == 1 {
        // 单层包（如裸 DNS/裸 raw）：直接导出该层
        let (frag, _) = &rendered[0];
        src.push_str(&format!("p = {frag}\nexport:\n- p\n"));
    } else {
        let (seed, _) = &rendered[0];
        src.push_str(&format!("p = {seed}\n"));
        let mut line = "full = use(p)".to_string();
        for (frag, _) in &rendered[1..] {
            line.push_str(&format!("\n       |> {frag}"));
        }
        src.push_str(&format!("{line}\nexport:\n- full\n"));
    }
    RecordOut {
        file: file.to_path_buf(),
        src,
        mode: "structured",
        len: rec.data.len(),
    }
}

/// 把单个反解层渲染为 DSL 片段；返回 (片段, 是否 bytes 直喂)。
/// 语义字段可完整表达 → headers.pkt 具名函数；否则 `*_bytes(hex(...))` 直喂保真。
fn render_layer(l: &Layer) -> (String, bool) {
    match l {
        Layer::Raw(r) => (format!("raw(bytes=hex(\"{}\"))", hex_str(&r.bytes)), false),
        Layer::Ethernet(f) => {
            let dst = mac_str(&f.dst_mac);
            let src = mac_str(&f.src_mac);
            let ethertype = f.ethertype.unwrap_or(0x0800);
            (
                format!("eth(src_mac=\"{src}\", dst_mac=\"{dst}\", ethertype=0x{ethertype:04x})"),
                false,
            )
        }
        Layer::Arp(f) => {
            let op = match f.op {
                Some(ArpOp::Request) => "request()",
                Some(ArpOp::Reply) => "reply()",
                None => "request()",
            };
            let sha = f.sha.map(|m| m.to_string()).unwrap_or_default();
            let tha = f.tha.map(|m| m.to_string()).unwrap_or_default();
            let spa = f.spa.map(|a| a.to_string()).unwrap_or_default();
            let tpa = f.tpa.map(|a| a.to_string()).unwrap_or_default();
            (
                format!("arp(op={op}, sha=\"{sha}\", spa=\"{spa}\", tha=\"{tha}\", tpa=\"{tpa}\")"),
                false,
            )
        }
        Layer::Ipv4(f) => {
            let src = ip4_str(&f.src);
            let dst = ip4_str(&f.dst);
            // ihl>5（选项头）语义无法表达 → bytes 直喂
            let has_options = f
                .raw
                .as_ref()
                .is_some_and(|raw| raw.len() > 20 && (raw[0] & 0x0F) > 5);
            if has_options {
                let raw = f.raw.as_deref().unwrap_or_default();
                (
                    format!(
                        "ipv4_bytes(hex(\"{}\"), src=\"{src}\", dst=\"{dst}\")",
                        hex_str(raw)
                    ),
                    true,
                )
            } else {
                let ttl = u8_field(&f.ttl, 64);
                let proto = f.proto.unwrap_or(0);
                let tos = f.tos.unwrap_or(0);
                let id = f.id.unwrap_or(0);
                let flags = f.flags.unwrap_or_default();
                let flags_v =
                    ((flags.df as u16) << 14) | ((flags.mf as u16) << 13) | flags.frag_offset;
                let flags_s = if flags_v == 0 {
                    "0".to_string()
                } else {
                    format!("0x{flags_v:04x}")
                };
                (
                    format!(
                        "ipv4(src=\"{src}\", dst=\"{dst}\", ttl={ttl}, proto={proto}, tos=0x{tos:02x}, id={id}, flags={flags_s})"
                    ),
                    false,
                )
            }
        }
        Layer::Ipv6(f) => {
            let src = ip6_str(&f.src);
            let dst = ip6_str(&f.dst);
            // 非 0x60000000（traffic class / flow label 非零）语义无法表达 → bytes 直喂
            let plain = f
                .raw
                .as_ref()
                .is_none_or(|raw| raw.len() < 4 || raw[..4] == [0x60, 0, 0, 0]);
            if plain {
                let hop = u8_field(&f.hop_limit, 64);
                let nh = f.next_header.unwrap_or(59);
                (
                    format!(
                        "ipv6(src=\"{src}\", dst=\"{dst}\", hop_limit={hop}, next_header={nh})"
                    ),
                    false,
                )
            } else {
                let raw = f.raw.as_deref().unwrap_or_default();
                (
                    format!(
                        "ipv6_bytes(hex(\"{}\"), src=\"{src}\", dst=\"{dst}\")",
                        hex_str(raw)
                    ),
                    true,
                )
            }
        }
        Layer::Icmp(f) => {
            // 8B 头语义可完整表达（type/code/id/seq + body）；非 echo 报文也按同布局还原
            let t = f.icmp_type.unwrap_or(8);
            let c = f.code.unwrap_or(0);
            let id = f.id.unwrap_or(0);
            let seq = f.seq.unwrap_or(0);
            let payload = f
                .payload
                .as_ref()
                .map(|b| format!(", payload=hex(\"{}\")", hex_str(b)))
                .unwrap_or_default();
            (
                format!("icmp(type={t}, code={c}, id={id}, seq={seq}{payload})"),
                false,
            )
        }
        Layer::Tcp(f) => {
            // doff>5（选项）或 urg（紧急指针值无法表达）→ bytes 直喂
            let doff_ok = f
                .raw
                .as_ref()
                .is_none_or(|raw| raw.len() < 13 || (raw[12] >> 4) == 5);
            let urg = f.flags.is_some_and(|fl| fl.urg);
            if !doff_ok || urg {
                let raw = f.raw.as_deref().unwrap_or_default();
                (format!("tcp_bytes(hex(\"{}\"))", hex_str(raw)), true)
            } else {
                let sport = f.src_port.unwrap_or(0);
                let dport = f.dst_port.unwrap_or(0);
                let seq = f.seq.unwrap_or(0);
                let ack = f.ack.unwrap_or(0);
                let window = f.window.unwrap_or(65535);
                let flags_s = tcp_flags_str(f.flags.unwrap_or_default());
                (
                    format!(
                        "tcp(sport={sport}, dport={dport}, seq={seq}, ack={ack}, flags={flags_s}, window={window})"
                    ),
                    false,
                )
            }
        }
        Layer::Udp(f) => {
            let sport = f.src_port.unwrap_or(0);
            let dport = f.dst_port.unwrap_or(0);
            (format!("udp(sport={sport}, dport={dport})"), false)
        }
        // dns/http：DSL 语义字段集不足以字节级还原（压缩指针/附加段/头格式）→ 整段直喂
        Layer::Dns(f) => (
            format!(
                "dns_bytes(hex(\"{}\"))",
                hex_str(f.raw.as_deref().unwrap_or_default())
            ),
            true,
        ),
        Layer::Http(f) => (
            format!(
                "http_bytes(hex(\"{}\"))",
                hex_str(f.raw.as_deref().unwrap_or_default())
            ),
            true,
        ),
    }
}

/// TCP flags → `bor(syn(), ack())` / `0`（与 eng_lib/bytes.pkt 位常量名一致）。
fn tcp_flags_str(f: TcpFlags) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if f.fin {
        parts.push("fin()");
    }
    if f.syn {
        parts.push("syn()");
    }
    if f.rst {
        parts.push("rst()");
    }
    if f.psh {
        parts.push("psh()");
    }
    if f.ack {
        parts.push("ack()");
    }
    if f.urg {
        parts.push("urg()");
    }
    if f.ece {
        parts.push("ece()");
    }
    if f.cwr {
        parts.push("cwr()");
    }
    match parts.len() {
        0 => "0".to_string(),
        1 => parts[0].to_string(),
        _ => format!("bor({})", parts.join(", ")),
    }
}

// ── 配方 .pktl ────────────────────────────────────────────────

fn render_recipe(
    path: &Path,
    selected: &[(usize, &crate::engine::pcap::PcapRecord)],
    nano: bool,
    recipe_path: &Path,
) -> String {
    let mut src = String::new();
    src.push_str(&format!(
        "# 配方：{} → {} 条 .pkt（步骤 delay: 携带捕获帧间隔）\n",
        path.display(),
        selected.len()
    ));
    src.push_str(&format!(
        "# 运行: prping packet {} [HOST:PORT]   （--raw 原始发送；--out 合并写回 pcap）\n",
        recipe_path.display()
    ));
    src.push_str("global:\nrecipe:\n");
    for (k, (i, rec)) in selected.iter().enumerate() {
        src.push_str(&format!("- pkg: record_{:05}.pkt\n", i + 1));
        if k > 0 {
            let prev = &selected[k - 1].1;
            let gap = ts_secs(rec, nano) - ts_secs(prev, nano);
            if gap > 0.0
                && let Some(d) = fmt_delay(gap)
            {
                src.push_str(&format!("  delay: {d}\n"));
            }
        }
    }
    src
}

// ── 渲染辅助 ──────────────────────────────────────────────────

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fmt_ts(rec: &crate::engine::pcap::PcapRecord, nano: bool) -> String {
    if nano {
        format!("{}.{:09}", rec.ts_sec, rec.ts_frac)
    } else {
        format!("{}.{:06}", rec.ts_sec, rec.ts_frac)
    }
}

/// 记录时间戳（秒，f64）。
fn ts_secs(rec: &crate::engine::pcap::PcapRecord, nano: bool) -> f64 {
    let div = if nano { 1e9 } else { 1e6 };
    rec.ts_sec as f64 + rec.ts_frac as f64 / div
}

/// 间隔秒数 → 最多 6 位小数的字符串（去尾零）；小于 1μs 返回 None（不写 delay）。
fn fmt_delay(secs: f64) -> Option<String> {
    if secs < 1e-6 {
        return None;
    }
    let s = format!("{secs:.6}");
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    if trimmed == "0" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn mac_str(f: &Field<packet_dsl::ir::MacAddr>) -> String {
    match f {
        Field::Value(m) => m.to_string(),
        _ => "00:00:00:00:00:00".to_string(),
    }
}

fn ip4_str(f: &Field<std::net::Ipv4Addr>) -> String {
    match f {
        Field::Value(a) => a.to_string(),
        _ => "0.0.0.0".to_string(),
    }
}

fn ip6_str(f: &Field<std::net::Ipv6Addr>) -> String {
    match f {
        Field::Value(a) => a.to_string(),
        _ => "::".to_string(),
    }
}

fn u8_field(f: &Field<u8>, default: u8) -> u8 {
    match f {
        Field::Value(v) => *v,
        _ => default,
    }
}

// ── 摘要输出 ──────────────────────────────────────────────────

fn render_summary(path: &Path, opts: &ConvertOptions, report: &ConvertReport, out: &[RecordOut]) {
    let mut w = StandardStream::stdout(ColorChoice::Auto);
    let _ = print_magenta(&mut w, "packet-dsl convert");
    let _ = writeln!(&mut w);
    let _ = print_cyan(
        &mut w,
        format!(
            "{} → {}  ({}/{} records, {})",
            path.display(),
            opts.out_dir.display(),
            report.written,
            report.total,
            if opts.structured {
                "structured"
            } else {
                "lossless"
            }
        ),
    );
    let _ = writeln!(&mut w);
    let _ = writeln!(&mut w);
    for ro in out {
        let _ = print_dim(
            &mut w,
            format!("  {}  ({} {} B)", ro.file.display(), ro.mode, ro.len),
        );
        let _ = writeln!(&mut w);
    }
    let _ = print_dim(&mut w, format!("  recipe: {}", report.recipe.display()));
    let _ = writeln!(&mut w);
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dsl::Serializer as _;

    #[test]
    fn effective_threads_auto_threshold() {
        // 低于阈值 → 单线程（避免小文件线程池开销）
        assert_eq!(effective_threads(0, 0), 1);
        assert_eq!(effective_threads(PARALLEL_THRESHOLD - 1, 0), 1);
        // 达到阈值 → available_parallelism（≥1，且不超过记录数）
        let auto = effective_threads(PARALLEL_THRESHOLD, 0);
        assert!((1..=PARALLEL_THRESHOLD).contains(&auto));
        // 显式指定：精确线程数，clamp 到 [1, 记录数]
        assert_eq!(effective_threads(10, 4), 4);
        assert_eq!(effective_threads(10, 1), 1);
        assert_eq!(effective_threads(2, 8), 2, "线程数不超过记录数");
        assert_eq!(effective_threads(10, 0), 1, "少量记录显式 0 仍走阈值");
    }

    #[test]
    fn parallel_matches_sequential() {
        // 构造一个稍大的记录集，验证并行（显式 4 线程）与单线程产出完全一致
        let mk = |n: usize| -> Vec<Vec<u8>> {
            let src = "q = dns(id=0x1234, questions=[\"example.com\"])\nuse(q) |> udp(sport=12345, dport=53) |> ipv4(src=\"1.1.1.1\", dst=\"8.8.8.8\", id=0, proto=17) |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\")\n";
            let m = packet_dsl::semantic::parse_str("t", src).unwrap();
            let pkt = packet_dsl::resolve(&m)
                .unwrap()
                .packets
                .into_iter()
                .next()
                .unwrap();
            let b = packet_dsl::DefaultSerializer::with_seed(1)
                .serialize(&pkt)
                .unwrap();
            (0..n).map(|_| b.clone()).collect()
        };
        let packets = mk(32);
        let dir = std::env::temp_dir().join(format!("prping-pt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pcap = dir.join("x.pcap");
        crate::engine::pcap::write_pcap(&pcap, crate::engine::pcap::LinkType::Ethernet, &packets)
            .unwrap();

        let run = |threads: usize, structured: bool| -> Vec<(PathBuf, String)> {
            let out = dir.join(format!("out-{threads}-{structured}"));
            let _ = std::fs::remove_dir_all(&out);
            let report = convert_pcap(
                &pcap,
                &ConvertOptions {
                    out_dir: out.clone(),
                    structured,
                    skip: 0,
                    limit: None,
                    threads,
                },
            )
            .expect("转换成功");
            report
                .files
                .iter()
                .map(|f| {
                    let src = std::fs::read_to_string(f).unwrap();
                    (f.clone(), src)
                })
                .collect()
        };
        for structured in [false, true] {
            let seq = run(1, structured);
            let par = run(4, structured);
            assert_eq!(seq.len(), par.len());
            for ((fa, sa), (fb, sb)) in seq.iter().zip(par.iter()) {
                assert_eq!(fa.file_name(), fb.file_name());
                assert_eq!(sa, sb, "threads=1 与 threads=4 产出应逐字节一致");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
