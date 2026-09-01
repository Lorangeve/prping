//! 链路层监听（`packet --wait --raw`，裸 `--wait` = 持续监听）：持续接收**完整帧**（Linux 默认
//! AF_PACKET；macOS/Windows 与 Linux `--features pcap` 走 libpcap/Npcap），
//! 按 .pkt 的 sniffer 统一谓词匹配（`allow_sent: false`），命中只打印匹配详情与反解展示
//! ——**纯监听**：回应包的构造属编排，一律由 .pktl 配方的 `wait:` 无值步骤监听 +
//! `extract` 取值 + 后续步骤发包（见 `examples/icmp_mock/`、`examples/tcp_handshake_listen/`）。
//!
//! - 抓包复用：Linux 经 `util::socket::open_af_packet`（与 serve 抓包共用）；
//!   pcap 平台经 `rawpcap::open_capture` 多设备开线程（与 serve 同款）。
//! - 去重：最近 N 帧逐字节比较（pcap / AF_PACKET lo 双投递会把同一帧重复投递）。
//! - Ctrl+C 优雅退出（读超时轮询中断标志），结束时打印匹配统计。

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rust_i18n::t;
use termcolor::{ColorChoice, StandardStream};

use super::PkgOptions;
use crate::output::{indent, print_cyan, print_green, print_magenta};

/// 去重窗口（lo 双投递防重复计数：最近 N 帧逐字节比较）。
const DEDUP_WINDOW: usize = 8;

/// 监听共享状态（多抓包线程）：输出流 + 计数 + 去重窗口。
struct Shared {
    out: StandardStream,
    total: usize,
    matched: usize,
    /// 最近 N 个收到的帧（lo 出向+入向双投递去重）。
    recent: Vec<Vec<u8>>,
}

/// 链路层监听入口：`packet --wait --raw FILE.pkt [--iface IFACE]`（裸 `--wait` = 持续）。
///
/// **发送段先行**：文件有可发送的导出就先 raw 发送一遍再监听（含 `reply()` 叶子的
/// 文件包求值失败 → 无可发送包，直接进入监听——`reply()` 只在配方 extract 上下文可求值）。
pub fn listen_raw_packets(file: &Path, opts: &PkgOptions) -> anyhow::Result<()> {
    crate::engine::eng::ensure_dns_resolver();
    crate::engine::eng::ensure_proto_registry();
    let module =
        packet_dsl::parse_file_with_libs(file, &opts.libs).map_err(|d| anyhow::anyhow!("{d}"))?;
    let params: packet_dsl::Params = opts.params.iter().cloned().collect();
    let spec = module
        .sniffer
        .clone()
        .ok_or_else(|| anyhow::anyhow!("{}", t!("engine.listen_requires_sniffer")))?;
    // 监听规则无发包可引用（allow_sent=false；裸 Ident 引用发包字段 → 构建期报错）
    let matcher = packet_dsl::Matcher::build(&spec, Some(&module), &params, &opts.globals, false)
        .map_err(|d| anyhow::anyhow!("{d}"))?;
    // 发送段先行（"只要包含发送段就会发送"）：文件有可发送的导出先 raw 发送一遍
    // 再监听；含 reply() 叶子的文件包求值失败 → 无可发送包，直接进入监听
    if packet_dsl::resolve_sources_with_globals(&module, &params, &opts.globals)
        .is_ok_and(|s| s.iter().any(|(_, ps)| !ps.is_empty()))
    {
        // OneShot(0)：纯发送不读回显（wait 0 = 立即超时），避免绑定前阻塞
        let send_opts = PkgOptions {
            wait: super::WaitMode::OneShot(0.0),
            ..opts.clone()
        };
        if let Err(e) = super::send::send_packets(file, &send_opts) {
            // 发送段先行失败：降级为警告并继续监听——纯监听场景不应被发送失败阻断
            // （send_packets 内部已打印具体红字错误），与 listen.rs 同策略
            let mut w = crate::output::stderr();
            let _ = crate::output::writeln_orange(
                &mut w,
                rust_i18n::t!("engine.listen_send_phase_failed", error = e.to_string()),
            );
        }
    }
    let iface = match &opts.mode {
        super::SendMode::Raw { iface } => iface.clone(),
        super::SendMode::Payload => None,
    };

    let mut w = StandardStream::stdout(ColorChoice::Auto);
    print_magenta(&mut w, "prping packet --wait --raw (link-layer listen)")?;
    writeln!(&mut w)?;
    print_cyan(
        &mut w,
        t!(
            "engine.listen_raw_binding",
            iface = iface.as_deref().unwrap_or("*")
        ),
    )?;
    writeln!(&mut w)?;

    let shared = Arc::new(Mutex::new(Shared {
        out: w,
        total: 0,
        matched: 0,
        recent: Vec::new(),
    }));
    let matcher = Arc::new(matcher);

    // 平台分派：Linux 默认 AF_PACKET 单循环；pcap 平台（macOS/Windows/Linux+pcap）
    // 多设备多线程（与 serve 抓包同款路径）。
    #[cfg(all(target_os = "linux", not(feature = "pcap")))]
    let result = linux_listen(&shared, &matcher, iface.as_deref());
    #[cfg(any(windows, target_os = "macos", feature = "pcap"))]
    let result = pcap_listen(&shared, &matcher, iface.as_deref());
    #[cfg(not(any(
        all(target_os = "linux", not(feature = "pcap")),
        windows,
        target_os = "macos",
        feature = "pcap"
    )))]
    let result = Err(anyhow::anyhow!(
        "raw 链路层监听暂不支持当前平台（需要 Linux AF_PACKET 或 libpcap/Npcap）"
    ));

    // 收尾统计（Ctrl+C 或抓包错误退出后）
    {
        let g = shared.lock().expect("shared lock");
        let (matched, total) = (g.matched, g.total);
        let mut out = StandardStream::stdout(ColorChoice::Auto);
        print_cyan(
            &mut out,
            t!("engine.listen_raw_done", matched = matched, total = total),
        )?;
        writeln!(&mut out)?;
    }
    result
}

/// 配方 `wait:` 无值（持续监听）步骤（raw 链路层）：抓包循环，sniffer 匹配
/// **第一个命中帧**即返回（命中后由配方 extract 取值、后续步骤发包回应）。
/// `None` = Ctrl+C 中断。匹配器用 Arc（pcap 多设备多线程）。
pub(crate) fn listen_raw_once(
    matcher: Arc<packet_dsl::Matcher>,
    iface: Option<&str>,
    timeout: Option<Duration>,
) -> anyhow::Result<Option<Vec<u8>>> {
    let deadline = timeout.map(|d| std::time::Instant::now() + d);
    let expired = |deadline: Option<std::time::Instant>| {
        deadline.is_some_and(|dl| std::time::Instant::now() >= dl)
    };
    #[cfg(all(target_os = "linux", not(feature = "pcap")))]
    {
        let ifindex = match iface {
            Some(name) => {
                let c = std::ffi::CString::new(name).map_err(|_| {
                    anyhow::anyhow!(t!("engine.listen_raw_bad_iface", iface = name))
                })?;
                let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
                if idx == 0 {
                    anyhow::bail!(t!("engine.listen_raw_unknown_iface", iface = name));
                }
                idx as libc::c_int
            }
            None => 0, // 全接口
        };
        let fd = crate::util::socket::open_af_packet(ifindex)?;
        // 尽力开混杂（需 CAP_NET_ADMIN）：失败静默
        let _ = crate::util::socket::af_packet_promisc_all(fd);
        let mut buf = vec![0u8; crate::util::RECV_BUF_SIZE];
        let hit = loop {
            if crate::util::interrupted() || expired(deadline) {
                break None;
            }
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd, 1, 200) };
            if rc <= 0 {
                continue;
            }
            let n = unsafe {
                libc::recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if n <= 0 {
                continue;
            }
            let frame = buf[..n as usize].to_vec();
            if matcher.matches(&frame, None).is_some() {
                break Some(frame);
            }
        };
        unsafe { libc::close(fd) };
        Ok(hit)
    }
    #[cfg(any(windows, target_os = "macos", feature = "pcap"))]
    {
        let devs = crate::engine::rawpcap::list_devices()?;
        // 设备选择：--iface 匹配名称/描述子串（不区分大小写）；否则全部设备
        let wanted: Vec<usize> = match iface {
            Some(pat) => devs
                .iter()
                .enumerate()
                .filter(|(_, d)| {
                    d.name.eq_ignore_ascii_case(pat)
                        || d.desc
                            .as_deref()
                            .is_some_and(|s| s.to_lowercase().contains(&pat.to_lowercase()))
                })
                .map(|(i, _)| i)
                .collect(),
            None => (0..devs.len()).collect(),
        };
        if wanted.is_empty() {
            anyhow::bail!(t!(
                "engine.listen_raw_unknown_iface",
                iface = iface.unwrap_or("")
            ));
        }
        let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let mut handles = Vec::new();
        for idx in wanted {
            let dev = devs[idx].name.clone();
            if let Ok(mut cap) = crate::engine::rawpcap::open_capture_listen(&dev) {
                let dlt = cap.get_datalink();
                let matcher = Arc::clone(&matcher);
                let captured = Arc::clone(&captured);
                handles.push(std::thread::spawn(move || {
                    loop {
                        if crate::util::interrupted()
                            || captured.lock().expect("captured lock").is_some()
                        {
                            break;
                        }
                        match cap.next_packet() {
                            Ok(p) => {
                                // macOS lo0 是 DLT_NULL：剥 4 字节族头得裸 IP
                                let data =
                                    if dlt == pcap::Linktype::NULL || dlt == pcap::Linktype::LOOP {
                                        match crate::serve::strip_null(p.data) {
                                            Some(ip) => ip,
                                            None => continue,
                                        }
                                    } else {
                                        p.data
                                    };
                                if matcher.matches(data, None).is_some() {
                                    *captured.lock().expect("captured lock") = Some(data.to_vec());
                                    break;
                                }
                            }
                            Err(pcap::Error::TimeoutExpired) => continue,
                            Err(_) => break,
                        }
                    }
                }));
            }
        }
        if handles.is_empty() {
            anyhow::bail!(t!("engine.listen_raw_no_devices"));
        }
        // 主线程等 captured / 限时 / Ctrl+C
        let hit = loop {
            if let Some(f) = captured.lock().expect("captured lock").clone() {
                break Some(f);
            }
            if crate::util::interrupted() || expired(deadline) {
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        for h in handles {
            let _ = h.join();
        }
        Ok(hit)
    }
    #[cfg(not(any(
        all(target_os = "linux", not(feature = "pcap")),
        windows,
        target_os = "macos",
        feature = "pcap"
    )))]
    {
        Err(anyhow::anyhow!(
            "raw 链路层监听暂不支持当前平台（需要 Linux AF_PACKET 或 libpcap/Npcap）"
        ))
    }
}

// ── Linux（默认）：AF_PACKET 单 socket ────────────────────────────────────

#[cfg(all(target_os = "linux", not(feature = "pcap")))]
fn linux_listen(
    shared: &Arc<Mutex<Shared>>,
    matcher: &Arc<packet_dsl::Matcher>,
    iface: Option<&str>,
) -> anyhow::Result<()> {
    let ifindex = match iface {
        Some(name) => {
            let c = std::ffi::CString::new(name)
                .map_err(|_| anyhow::anyhow!(t!("engine.listen_raw_bad_iface", iface = name)))?;
            let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
            if idx == 0 {
                anyhow::bail!(t!("engine.listen_raw_unknown_iface", iface = name));
            }
            idx as libc::c_int
        }
        None => 0, // 全接口
    };
    let fd = crate::util::socket::open_af_packet(ifindex)?;
    // 尽力开混杂（需 CAP_NET_ADMIN）：失败静默——本机地址/广播/组播帧仍能收到
    let _ = crate::util::socket::af_packet_promisc_all(fd);
    let mut buf = vec![0u8; crate::util::RECV_BUF_SIZE];
    loop {
        if crate::util::interrupted() {
            break;
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, 200) };
        if rc <= 0 {
            continue;
        }
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut slen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut sll as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                &mut slen,
            )
        };
        if n <= 0 {
            continue;
        }
        let frame = buf[..n as usize].to_vec();
        handle_frame(shared, matcher, &frame);
    }
    unsafe { libc::close(fd) };
    Ok(())
}

// ── pcap 平台（macOS / Windows / Linux+pcap）：多设备多线程 ────────────────

#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
fn pcap_listen(
    shared: &Arc<Mutex<Shared>>,
    matcher: &Arc<packet_dsl::Matcher>,
    iface: Option<&str>,
) -> anyhow::Result<()> {
    let devs = crate::engine::rawpcap::list_devices()?;
    // 设备选择：--iface 匹配名称/描述子串（不区分大小写）；否则全部设备
    let wanted: Vec<usize> = match iface {
        Some(pat) => devs
            .iter()
            .enumerate()
            .filter(|(_, d)| {
                d.name.eq_ignore_ascii_case(pat)
                    || d.desc
                        .as_deref()
                        .is_some_and(|s| s.to_lowercase().contains(&pat.to_lowercase()))
            })
            .map(|(i, _)| i)
            .collect(),
        None => (0..devs.len()).collect(),
    };
    if wanted.is_empty() {
        anyhow::bail!(t!(
            "engine.listen_raw_unknown_iface",
            iface = iface.unwrap_or("")
        ));
    }
    let mut handles = Vec::new();
    // 抓包线程存活计数：全部退出（设备被拔/权限变化等运行期错误）时主循环
    // 不再空转等 Ctrl+C（此前线程打印错误 break 后主线程静默挂起）
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for idx in wanted {
        let dev = devs[idx].name.clone();
        // 监听专用打开：接受 DLT_NULL（macOS lo0 回环）等非 EN10MB 设备，
        // 混杂尽力而为（anpi* 等 BIOCPROMISC 不支持的设备降级不混杂）
        match crate::engine::rawpcap::open_capture_listen(&dev) {
            Ok(cap) => {
                let dlt = cap.get_datalink();
                let shared = Arc::clone(shared);
                let matcher = Arc::clone(matcher);
                active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let act = Arc::clone(&active);
                handles.push(std::thread::spawn(move || {
                    pcap_recv_loop(cap, dlt, &shared, &matcher);
                    act.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }));
            }
            Err(e) => {
                let mut g = shared.lock().expect("shared lock");
                let _ = crate::output::writeln_red(&mut g.out, format!("  ✗ {dev}: {e}"));
            }
        }
    }
    if handles.is_empty() {
        anyhow::bail!(t!("engine.listen_raw_no_devices"));
    }
    // 主线程等 Ctrl+C 或全部抓包线程退出（设备错误时线程已打印红字）
    while !crate::util::interrupted() && active.load(std::sync::atomic::Ordering::Relaxed) > 0 {
        std::thread::sleep(Duration::from_millis(100));
    }
    for h in handles {
        let _ = h.join();
    }
    if !crate::util::interrupted() {
        // 全部抓包线程退出且未 Ctrl+C：打印汇总后正常结束（错误已逐条打印）
        let mut w = crate::output::stdout();
        let _ = crate::output::writeln_red(&mut w, t!("engine.listen_raw_threads_exited"));
    }
    Ok(())
}

#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
fn pcap_recv_loop(
    mut cap: pcap::Capture<pcap::Active>,
    dlt: pcap::Linktype,
    shared: &Arc<Mutex<Shared>>,
    matcher: &Arc<packet_dsl::Matcher>,
) {
    loop {
        if crate::util::interrupted() {
            break;
        }
        match cap.next_packet() {
            Ok(p) => {
                // macOS lo0 是 DLT_NULL：剥 4 字节族头得裸 IP（与 serve 抓包一致）
                let data = if dlt == pcap::Linktype::NULL || dlt == pcap::Linktype::LOOP {
                    match crate::serve::strip_null(p.data) {
                        Some(ip) => ip,
                        None => continue,
                    }
                } else {
                    p.data
                };
                handle_frame(shared, matcher, data);
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                let mut g = shared.lock().expect("shared lock");
                let _ = crate::output::writeln_red(&mut g.out, format!("  ✗ 抓包中断：{e}"));
                break;
            }
        }
    }
}

// ── 帧处理：匹配 → 报告（纯监听） ────────────────────────────────────────

/// 处理一帧：lo 双投递去重 → sniffer 匹配 → 命中打印匹配字段与反解展示。
/// 纯监听不发包——回应包的构造属编排，走 .pktl 配方（`wait:` + extract + 发送步骤）。
fn handle_frame(shared: &Arc<Mutex<Shared>>, matcher: &Arc<packet_dsl::Matcher>, frame: &[u8]) {
    let mut g = shared.lock().expect("shared lock");
    // lo 双投递去重：重复帧不算 total（total - matched 保持 = 未命中数）
    if g.recent.iter().any(|f| f == frame) {
        return;
    }
    g.total += 1;
    g.recent.push(frame.to_vec());
    if g.recent.len() > DEDUP_WINDOW {
        g.recent.remove(0);
    }
    // 匹配（允许丢弃：监听规则用字面量/谓词，无发包引用）
    let Some(fields) = matcher.matches(frame, None) else {
        return;
    };
    g.matched += 1;
    let report = packet_dsl::dissect(frame);
    let _ = print_green(
        &mut g.out,
        t!("engine.listen_raw_matched", frame = frame.len()),
    );
    let _ = writeln!(&mut g.out);
    if !fields.is_empty() {
        let pairs: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let _ = print_green(&mut g.out, format!("{}{}", indent(1), pairs.join(" ")));
        let _ = writeln!(&mut g.out);
    }
    let _ = crate::engine::eng::render_dissected(&mut g.out, &report, "  frame:", frame);
}

#[cfg(test)]
mod tests {
    use packet_dsl::Serializer as _;

    /// 纯监听前置：`--wait --raw` 只需要 `sniffer:` 段（无需默认导出/应答模板）——
    /// 监听规则（allow_sent=false，字面量/谓词）匹配收到的请求帧即命中。
    #[test]
    fn listen_matches_sniffer_without_default_export() {
        crate::engine::eng::ensure_proto_registry();
        // 监听文件：仅命名导出（无匿名顶层流水线 = 无默认导出）+ sniffer 规则
        let m = packet_dsl::semantic::parse_str(
            "t",
            "p = raw(bytes=\"\")\nreq = use(p) |> icmp(type=8) |> ipv4()\nexport:\n- req\n\nsniffer:\n  - match icmp(type=8)\n",
        )
        .unwrap();
        assert!(m.default.is_none(), "无默认导出也可监听");
        let matcher = packet_dsl::Matcher::build(
            &m.sniffer.clone().unwrap(),
            Some(&m),
            &packet_dsl::Params::new(),
            &packet_dsl::Globals::new(),
            false,
        )
        .unwrap();
        // 请求帧：eth/ipv4/icmp echo request
        let req = packet_dsl::semantic::parse_str(
            "t",
            "p = raw(bytes=\"hello\")\nuse(p) |> icmp(type=8, id=0x1234, seq=1) |> ipv4() |> eth()\n",
        )
        .unwrap();
        let built = packet_dsl::resolve(&req).unwrap();
        let frame = packet_dsl::DefaultSerializer::with_seed(1)
            .serialize(&built.packets[0])
            .unwrap();
        let got = matcher.matches(&frame, None).expect("sniffer 应命中请求帧");
        assert!(got.iter().any(|(k, v)| k == "type" && v == "8"), "{got:?}");
    }
}
