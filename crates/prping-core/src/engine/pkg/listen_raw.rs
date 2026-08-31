//! 链路层监听（`packet --wait --raw`，裸 `--wait` = 持续监听）：持续接收**完整帧**（Linux 默认
//! AF_PACKET；macOS/Windows 与 Linux `--features pcap` 走 libpcap/Npcap），
//! 按 .pkt 的 sniffer 统一谓词匹配（`allow_sent: false`），命中后按 **应答模板**
//! （.pkt 的默认导出，可经 `reply("层","字段")` 取收到的帧字段，如
//! `icmp(type=0, id=reply("icmp","id"))`）构造应答帧并 raw 注入。
//!
//! - 抓包复用：Linux 经 `util::socket::open_af_packet`（与 serve 抓包共用）；
//!   pcap 平台经 `rawpcap::open_capture` 多设备开线程（与 serve 同款）。
//! - 自注入防护：与最近注入的应答帧逐字节相同 → 跳过（pcap 会回读自己注入的帧、
//!   AF_PACKET lo 双投递）；另按最近 N 帧去重（lo 上出向+入向各投递一次请求）。
//! - Ctrl+C 优雅退出（读超时轮询中断标志），结束时打印匹配统计。

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packet_dsl::ir::PacketSpec;
use packet_dsl::{DefaultSerializer, Serializer};
use rust_i18n::t;
use termcolor::{ColorChoice, StandardStream};

use super::{PkgOptions, SendOutcome};
use crate::output::{indent, print_cyan, print_green, print_magenta, writeln_red};

/// 去重窗口（lo 双投递/自注入的防回环护栏：最近 N 帧逐字节比较）。
const DEDUP_WINDOW: usize = 8;

/// 监听共享状态（多抓包线程）：输出流 + 计数 + 去重窗口。
struct Shared {
    out: StandardStream,
    total: usize,
    matched: usize,
    /// 最近注入的应答帧（自注入防护：与它逐字节相同 → 跳过）。
    last_injected: Vec<u8>,
    /// 最近 N 个收到的帧（lo 出向+入向双投递去重）。
    recent: Vec<Vec<u8>>,
    /// 上一条应答模板失败原因（去重：同类失败只提示一次，避免逐帧刷屏）。
    last_template_err: Option<String>,
}

/// 链路层监听入口：`packet --wait --raw FILE.pkt [--iface IFACE]`（裸 `--wait` = 持续）。
///
/// **发送段先行**：文件有可发送的导出就先 raw 发送一遍再监听；默认导出是应答模板
/// （含 `reply()` 叶子，仅在监听上下文可求值）时不可发送 → 跳过。
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
    // 应答模板 = 默认导出（可经 reply("层","字段") 引用收到的帧字段）
    if module.default.is_none() {
        anyhow::bail!("{}", t!("engine.listen_raw_requires_reply"));
    }
    // 发送段先行（"只要包含发送段就会发送"）：文件有可发送的导出先 raw 发送一遍
    // 再监听；默认导出是应答模板（含 reply() 叶子，仅在监听上下文可求值）→ 跳过
    if packet_dsl::resolve_sources_with_globals(&module, &params, &opts.globals)
        .is_ok_and(|s| s.iter().any(|(_, ps)| !ps.is_empty()))
    {
        // OneShot(0)：纯发送不读回显（wait 0 = 立即超时），避免绑定前阻塞
        let send_opts = PkgOptions {
            wait: super::WaitMode::OneShot(0.0),
            ..opts.clone()
        };
        super::send::send_packets(file, &send_opts)?;
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
        last_injected: Vec::new(),
        recent: Vec::new(),
        last_template_err: None,
    }));
    let module = Arc::new(module);
    let params = Arc::new(params);
    let globals = Arc::new(opts.globals.clone());
    let matcher = Arc::new(matcher);

    // 平台分派：Linux 默认 AF_PACKET 单循环；pcap 平台（macOS/Windows/Linux+pcap）
    // 多设备多线程（与 serve 抓包同款路径）。
    #[cfg(all(target_os = "linux", not(feature = "pcap")))]
    let result = linux_listen(
        &shared,
        &module,
        &params,
        &globals,
        &matcher,
        iface.as_deref(),
    );
    #[cfg(any(windows, target_os = "macos", feature = "pcap"))]
    let result = pcap_listen(
        &shared,
        &module,
        &params,
        &globals,
        &matcher,
        iface.as_deref(),
    );
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
/// **第一个命中帧**即返回（不做应答模板注入——命中后由配方后续步骤发包）。
/// `None` = Ctrl+C 中断。`module`/`params`/`globals`/`matcher` 用 Arc（pcap 多设备多线程）。
pub(crate) fn listen_raw_once(
    module: Arc<packet_dsl::Module>,
    params: Arc<packet_dsl::Params>,
    globals: Arc<packet_dsl::Globals>,
    matcher: Arc<packet_dsl::Matcher>,
    iface: Option<&str>,
    timeout: Option<Duration>,
) -> anyhow::Result<Option<Vec<u8>>> {
    // 匹配器已由调用方按 module/params/globals 构建，此处不再透传——显式丢弃标记有意不用
    let _ = (&module, &params, &globals);
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
    module: &Arc<packet_dsl::Module>,
    params: &Arc<packet_dsl::Params>,
    globals: &Arc<packet_dsl::Globals>,
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
        // 应答注入走接收帧的接口（若可解析出名字；否则默认 lo）
        let rx_iface = if_indextoname(sll.sll_ifindex).or_else(|| iface.map(String::from));
        handle_frame(
            shared,
            module,
            params,
            globals,
            matcher,
            rx_iface.as_deref(),
            &frame,
        );
    }
    unsafe { libc::close(fd) };
    Ok(())
}

/// sll_ifindex → 接口名（Linux）。
#[cfg(all(target_os = "linux", not(feature = "pcap")))]
fn if_indextoname(ifindex: libc::c_int) -> Option<String> {
    if ifindex <= 0 {
        return None;
    }
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let ptr = unsafe {
        libc::if_indextoname(
            ifindex as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_char,
        )
    };
    if ptr.is_null() {
        None
    } else {
        Some(
            unsafe { std::ffi::CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned(),
        )
    }
}

// ── pcap 平台（macOS / Windows / Linux+pcap）：多设备多线程 ────────────────

#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
fn pcap_listen(
    shared: &Arc<Mutex<Shared>>,
    module: &Arc<packet_dsl::Module>,
    params: &Arc<packet_dsl::Params>,
    globals: &Arc<packet_dsl::Globals>,
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
                let module = Arc::clone(module);
                let params = Arc::clone(params);
                let globals = Arc::clone(globals);
                let matcher = Arc::clone(matcher);
                // 注入走**接收设备**（用户 --iface 优先）：应答应回到请求进来的网卡
                let rx_iface = iface.map(String::from).unwrap_or_else(|| dev.clone());
                active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let act = Arc::clone(&active);
                handles.push(std::thread::spawn(move || {
                    pcap_recv_loop(
                        cap,
                        dlt,
                        &shared,
                        &module,
                        &params,
                        &globals,
                        &matcher,
                        Some(rx_iface.as_str()),
                    );
                    act.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }));
            }
            Err(e) => {
                let mut g = shared.lock().expect("shared lock");
                let _ = writeln_red(&mut g.out, format!("  ✗ {dev}: {e}"));
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
        let _ = writeln_red(&mut w, t!("engine.listen_raw_threads_exited"));
    }
    Ok(())
}

#[cfg(any(windows, target_os = "macos", feature = "pcap"))]
#[allow(clippy::too_many_arguments)]
fn pcap_recv_loop(
    mut cap: pcap::Capture<pcap::Active>,
    dlt: pcap::Linktype,
    shared: &Arc<Mutex<Shared>>,
    module: &Arc<packet_dsl::Module>,
    params: &Arc<packet_dsl::Params>,
    globals: &Arc<packet_dsl::Globals>,
    matcher: &Arc<packet_dsl::Matcher>,
    iface: Option<&str>,
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
                handle_frame(shared, module, params, globals, matcher, iface, data);
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                let mut g = shared.lock().expect("shared lock");
                let _ = writeln_red(&mut g.out, format!("  ✗ 抓包中断：{e}"));
                break;
            }
        }
    }
}

// ── 帧处理：匹配 → 应答模板构造 → 注入 ───────────────────────────────────

/// 处理一帧：去重/自注入防护 → sniffer 匹配 → 命中则按应答模板（默认导出，
/// 带 reply 访问器）构造应答帧并 raw 注入。错误打印后继续（不中断监听）。
#[allow(clippy::too_many_arguments)]
fn handle_frame(
    shared: &Arc<Mutex<Shared>>,
    module: &Arc<packet_dsl::Module>,
    params: &Arc<packet_dsl::Params>,
    globals: &Arc<packet_dsl::Globals>,
    matcher: &Arc<packet_dsl::Matcher>,
    iface: Option<&str>,
    frame: &[u8],
) {
    let mut g = shared.lock().expect("shared lock");
    // 自注入防护 + lo 双投递去重：命中不算 total（此前先 total+=1 再 return，
    // 统计口径变成 total 含被丢弃帧、matched 不含——total - matched 不再是未命中数）
    if !g.last_injected.is_empty() && frame == g.last_injected.as_slice() {
        return;
    }
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
    // 应答模板求值 + 序列化（reply("层","字段") 从收到的帧反解取值）
    let (bytes, pkt, src) = match build_reply_bytes(module, params, globals, frame) {
        Ok(v) => v,
        Err(e) => {
            // 模板不适用（如 lo0 裸 IP 帧没有 eth 层给 eth 外层模板取 src/dst）：
            // 同类原因只提示一次，后续静默跳过（避免逐帧刷屏）
            let msg = e.to_string();
            if g.last_template_err.as_deref() != Some(msg.as_str()) {
                g.last_template_err = Some(msg.clone());
                let _ = writeln_red(
                    &mut g.out,
                    format!("{}✗ 应答模板不适用（本帧及同类帧跳过）：{msg}", indent(1)),
                );
            }
            return;
        }
    };
    // raw 注入（wait=None：不问应答）：裸 IPv4 应答走内核 IP 栈路由
    // （IPPROTO_RAW + IP_HDRINCL / macOS 剥头 raw socket，回环与局域网无需 MAC
    // 解析——macOS lo0 的 DLT_NULL 裸 IP 帧也走此路径）；eth 外层走链路层注入。
    let outcome = match inject_reply(&bytes, &pkt, iface) {
        Ok(o) => o,
        Err(e) => {
            let _ = writeln_red(&mut g.out, format!("{}✗ 应答注入失败：{e}", indent(1)));
            return;
        }
    };
    g.last_injected = bytes.clone();
    let _ = print_green(
        &mut g.out,
        t!(
            "engine.listen_raw_matched",
            frame = frame.len(),
            sent = outcome.sent,
            source = src
        ),
    );
    let _ = writeln!(&mut g.out);
    if !fields.is_empty() {
        let pairs: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let _ = print_green(&mut g.out, format!("{}{}", indent(1), pairs.join(" ")));
        let _ = writeln!(&mut g.out);
    }
    let _ = crate::engine::eng::render_dissected(&mut g.out, &report, "  frame:", frame);
}

/// 按应答模板（.pkt 默认导出）构造应答帧：带 `reply("层","字段")` 访问器求值
/// （从收到的帧反解取值）→ 序列化。返回 (字节, 包, 模板来源名)。
fn build_reply_bytes(
    module: &packet_dsl::Module,
    params: &packet_dsl::Params,
    globals: &packet_dsl::Globals,
    frame: &[u8],
) -> anyhow::Result<(Vec<u8>, PacketSpec, String)> {
    let report = packet_dsl::dissect(frame);
    let reply_access: packet_dsl::ReplyAccess = &|layer: &str, field: &str| {
        crate::engine::pkg::recipe::reply_field_value(&report, layer, field)
    };
    let sources = packet_dsl::resolve_sources_with_reply(module, params, globals, reply_access)
        .map_err(|d| anyhow::anyhow!("应答模板求值失败：{d}"))?;
    let (src, mut pkts) = sources
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("应答模板没有包"))?;
    let pkt = pkts
        .drain(..)
        .next()
        .ok_or_else(|| anyhow::anyhow!("应答模板没有包"))?;
    let bytes = DefaultSerializer::new()
        .serialize(&pkt)
        .map_err(anyhow::Error::from)?;
    Ok((bytes, pkt, src_label(&src)))
}

/// 注入应答帧：裸 IPv4 外层 → 内核 IP 栈路由（`util::socket::inject_ip4`，Linux
/// IPPROTO_RAW+IP_HDRINCL 整包 / macOS 按协议 raw socket 发 IP 载荷，回环与局域网
/// 均无需 MAC 解析，macOS lo0 的 DLT_NULL 裸 IP 帧也走此路径）；其余（eth 外层等）
/// → 链路层注入 `send_raw_bytes`。
fn inject_reply(
    bytes: &[u8],
    pkt: &PacketSpec,
    iface: Option<&str>,
) -> anyhow::Result<SendOutcome> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(packet_dsl::ir::Layer::Ipv4(_)) = pkt.layers.last()
        && bytes.len() >= 20
    {
        let dst = std::net::Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
        let sent = crate::util::socket::inject_ip4(bytes, dst)
            .map_err(|e| anyhow::anyhow!("裸 IP 应答注入失败：{e}"))?;
        return Ok(SendOutcome {
            proto: "IP4",
            sent,
            received: 0,
            reply: None,
        });
    }
    super::raw::send_raw_bytes(bytes, pkt, None, iface, None, None, None)
}

/// 应答模板来源的展示名。
fn src_label(src: &packet_dsl::PacketSource) -> String {
    match src {
        packet_dsl::PacketSource::Default => "default export".to_string(),
        packet_dsl::PacketSource::Export(name) => format!("export \"{name}\""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dsl::ir::Layer;
    use packet_dsl::semantic::parse_str;

    /// 应答模板构造（不经抓包/注入，无权限依赖）：ICMP echo request →
    /// echo reply——type=0、id/seq/载荷回显、IPv4/MAC 地址互换。
    #[test]
    fn build_icmp_echo_reply_from_request() {
        crate::engine::eng::ensure_proto_registry();
        // 请求帧：eth/ipv4/icmp echo request（type=8, id=0x1234, seq=3, payload "hello"）
        let req_src = "p = raw(bytes=\"hello\")\n\
use(p) |> icmp(type=8, id=0x1234, seq=3) |> ipv4(src=\"1.2.3.4\", dst=\"5.6.7.8\") \
|> eth(src_mac=\"aa:bb:cc:dd:ee:ff\", dst_mac=\"11:22:33:44:55:66\")\n";
        let rm = parse_str("t", req_src).unwrap();
        let built = packet_dsl::resolve(&rm).unwrap();
        let frame = packet_dsl::DefaultSerializer::with_seed(1)
            .serialize(&built.packets[0])
            .unwrap();
        // 应答模板：echo reply（type=0），id/seq/载荷回显，地址互换
        // 注意：匿名顶层流水线（use(...) |> ... 不带名字）= 默认导出 = 应答模板
        let reply_src = "payload = raw(bytes=reply(\"icmp\", \"payload\"))\n\
use(payload) |> icmp(type=0, id=reply(\"icmp\",\"id\"), seq=reply(\"icmp\",\"seq\")) \
|> ipv4(dst=reply(\"ipv4\",\"src\"), src=reply(\"ipv4\",\"dst\")) \
|> eth(dst_mac=reply(\"eth\",\"src\"), src_mac=reply(\"eth\",\"dst\"))\n";
        let m = parse_str("t", reply_src).unwrap();
        let (bytes, _, src) = build_reply_bytes(
            &m,
            &packet_dsl::Params::new(),
            &packet_dsl::Globals::new(),
            &frame,
        )
        .expect("应答模板构造成功");
        assert!(src.contains("default"), "模板来源 = 默认导出：{src}");
        // 反解应答并校验
        let rep = packet_dsl::dissect(&bytes);
        let icmp = rep
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Icmp(f) => Some(f),
                _ => None,
            })
            .expect("应答有 icmp 层");
        assert_eq!(icmp.icmp_type, Some(0), "echo reply type=0");
        assert_eq!(icmp.id, Some(0x1234), "id 回显");
        assert_eq!(icmp.seq, Some(3), "seq 回显");
        assert_eq!(icmp.payload.as_deref(), Some(&b"hello"[..]), "载荷回显");
        let ip4 = rep
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Ipv4(f) => Some(f),
                _ => None,
            })
            .expect("应答有 ipv4 层");
        assert_eq!(
            ip4.src,
            "5.6.7.8"
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .map(packet_dsl::ir::Field::Value)
                .unwrap()
        );
        assert_eq!(
            ip4.dst,
            "1.2.3.4"
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .map(packet_dsl::ir::Field::Value)
                .unwrap()
        );
        let eth = rep
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Ethernet(f) => Some(f),
                _ => None,
            })
            .expect("应答有 eth 层");
        // MAC 互换：应答 dst = 请求 src（aa:bb:...），应答 src = 请求 dst
        let mac = |s: &str| packet_dsl::ir::MacAddr::from_str_loose(s).unwrap();
        assert_eq!(
            eth.dst_mac,
            packet_dsl::ir::Field::Value(mac("aa:bb:cc:dd:ee:ff"))
        );
        assert_eq!(
            eth.src_mac,
            packet_dsl::ir::Field::Value(mac("11:22:33:44:55:66"))
        );
        // 客户端 sniffer 校验 echo reply：type=0、id/seq 与发包一致
        let c_src = "p = raw(bytes=\"hello\")\nuse(p) |> icmp(id=7, seq=3) |> ipv4() |> eth()\n\
sniffer:\n  - match icmp(type=0, id=id, seq=seq)\n";
        let cm = parse_str("t", c_src).unwrap();
        let matcher = packet_dsl::Matcher::build(
            &cm.sniffer.clone().unwrap(),
            Some(&cm),
            &packet_dsl::Params::new(),
            &packet_dsl::Globals::new(),
            true,
        )
        .unwrap();
        let got = matcher
            .matches(&bytes, Some(&packet_dsl::dissect(&frame)))
            .expect("echo reply 应通过客户端 sniffer 校验");
        assert_eq!(got.len(), 3, "{got:?}");
    }

    /// DNS 发包/回包模拟：查询帧 → 服务端模板构造应答（id 回显、flags=0x8180、
    /// 含 A 记录、UDP 端口互换；**裸 IP 外层**，macOS lo0 路径）→ 客户端 sniffer 校验应答。
    #[test]
    fn dns_query_response_simulation() {
        crate::engine::eng::ensure_proto_registry();
        // 1) 客户端 DNS 查询帧（id=0x4242）
        let q_src = "q = dns(id=0x4242, questions=[\"example.com\"])\n\
use(q) |> udp(dport=53) |> ipv4(src=\"192.168.1.10\", dst=\"192.168.1.1\") \
|> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\")\n";
        let qm = parse_str("t", q_src).unwrap();
        let built = packet_dsl::resolve(&qm).unwrap();
        let query = packet_dsl::DefaultSerializer::with_seed(1)
            .serialize(&built.packets[0])
            .unwrap();
        let query_report = packet_dsl::dissect(&query);
        let q_sport = query_report
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Udp(f) => f.src_port,
                _ => None,
            })
            .expect("查询有 udp 层");
        // 2) 服务端应答模板（DNS response：id 回显、flags=0x8180、问题回显 + A 记录；
        //    裸 IP 外层——与 examples/dns_echo_listen/server.pkt 一致，macOS lo0 走此路径）
        let r_src = "resp = dns(id=reply(\"dns\", \"id\"), flags=0x8180, questions=[\"example.com\"], answers=[[\"example.com\", 1, 1, 300, ip4(\"93.184.216.34\")]])\n\
use(resp) |> udp(sport=53, dport=reply(\"udp\", \"sport\")) |> ipv4(dst=reply(\"ipv4\", \"src\"), src=reply(\"ipv4\", \"dst\"))\n";
        let rm = parse_str("t", r_src).unwrap();
        let (resp_bytes, resp_pkt, _) = build_reply_bytes(
            &rm,
            &packet_dsl::Params::new(),
            &packet_dsl::Globals::new(),
            &query,
        )
        .expect("服务端模板应构造出 DNS 应答");
        // 2.5) 应答是裸 IP 外层（无 eth）：注入经 inject_reply → inject_ip4（内核 IP 栈路由）
        assert!(
            matches!(resp_pkt.layers.last(), Some(Layer::Ipv4(_))),
            "应答外层应为裸 ipv4（无 eth）：{:?}",
            resp_pkt.layers.last()
        );
        // 3) 校验应答：id 回显、flags=0x8180、A 记录、UDP 端口互换
        let rep = packet_dsl::dissect(&resp_bytes);
        let dns = rep
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Dns(f) => Some(f),
                _ => None,
            })
            .expect("应答有 dns 层");
        assert_eq!(dns.id, Some(0x4242), "应答 id 回显请求 id");
        assert_eq!(dns.flags, Some(0x8180), "应答 flags=QR+RD+RA");
        assert!(!dns.answers.is_empty(), "应答应含 A 记录");
        let udp = rep
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Udp(f) => Some(f),
                _ => None,
            })
            .expect("应答有 udp 层");
        assert_eq!(udp.dst_port, Some(q_sport), "应答 dport = 请求 sport");
        assert_eq!(udp.src_port, Some(53));
        // 4) 客户端 sniffer 校验应答（id 与发包一致、flags=0x8180）
        let c_src = "q = dns(id=0x4242, questions=[\"example.com\"])\nuse(q) |> udp(dport=53) |> ipv4() |> eth()\n\
sniffer:\n  - match dns(id=id, flags=0x8180)\n";
        let cm = parse_str("t", c_src).unwrap();
        let matcher = packet_dsl::Matcher::build(
            &cm.sniffer.clone().unwrap(),
            Some(&cm),
            &packet_dsl::Params::new(),
            &packet_dsl::Globals::new(),
            true,
        )
        .unwrap();
        let got = matcher
            .matches(&resp_bytes, Some(&query_report))
            .expect("DNS 应答应通过客户端 sniffer 校验");
        assert!(
            got.iter().any(|(k, v)| k == "id" && v == "16962"),
            "{got:?}"
        );
    }

    /// TCP 三次握手·字节级模拟：客户端 SYN → 服务端模板构造 SYN-ACK
    /// （ack=请求 seq+1、端口/IP/MAC 互换）→ 客户端 sniffer 校验 SYN-ACK。
    /// 不依赖抓包/注入（build_reply_bytes 是监听器的核心构造路径）。
    #[test]
    fn tcp_three_way_handshake_simulation() {
        crate::engine::eng::ensure_proto_registry();
        // 1) 客户端 SYN（对应 client.pkt 的 syn_pkt）
        let syn_src = "p = raw(bytes=\"\")\n\
use(p) |> tcp(sport=12345, dport=80, seq=0x1000, flags=syn(), window=65535) |> ipv4(src=\"192.168.1.10\", dst=\"192.168.1.1\") |> eth(src_mac=\"00:11:22:33:44:55\", dst_mac=\"66:77:88:99:aa:bb\")\n";
        let sm = parse_str("t", syn_src).unwrap();
        let built = packet_dsl::resolve(&sm).unwrap();
        let syn_frame = packet_dsl::DefaultSerializer::with_seed(1)
            .serialize(&built.packets[0])
            .unwrap();
        // 2) 服务端应答模板（对应 server.pkt 的默认导出）：SYN-ACK
        let reply_src = "payload = raw(bytes=\"\")\n\
use(payload) |> tcp(sport=80, dport=reply(\"tcp\", \"sport\"), seq=0x2000, \
ack=reply(\"tcp\", \"seq\") + 1, flags=bor(syn(), ack()), window=65535) \
|> ipv4(dst=reply(\"ipv4\", \"src\"), src=reply(\"ipv4\", \"dst\")) \
|> eth(dst_mac=reply(\"eth\", \"src\"), src_mac=reply(\"eth\", \"dst\"))\n";
        let rm = parse_str("t", reply_src).unwrap();
        let (synack_bytes, _, _) = build_reply_bytes(
            &rm,
            &packet_dsl::Params::new(),
            &packet_dsl::Globals::new(),
            &syn_frame,
        )
        .expect("服务端模板应构造出 SYN-ACK");
        // 3) 校验 SYN-ACK：seq=0x2000、ack=SYN seq+1=0x1001、端口/IP/MAC 互换、flags=syn+ack
        let rep = packet_dsl::dissect(&synack_bytes);
        let tcp = rep
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Tcp(f) => Some(f),
                _ => None,
            })
            .expect("SYN-ACK 有 tcp 层");
        assert_eq!(tcp.src_port, Some(80), "sport=80");
        assert_eq!(tcp.dst_port, Some(12345), "dport=客户端 sport");
        assert_eq!(tcp.seq, Some(0x2000), "seq=服务端 ISN");
        assert_eq!(tcp.ack, Some(0x1001), "ack=请求 seq+1");
        assert_eq!(
            tcp.flags.as_ref().map(|f| f.to_string()),
            Some("syn,ack".into())
        );
        let ip4 = rep
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Ipv4(f) => Some(f),
                _ => None,
            })
            .expect("SYN-ACK 有 ipv4 层");
        let ipv = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
        assert_eq!(ip4.src, packet_dsl::ir::Field::Value(ipv("192.168.1.1")));
        assert_eq!(ip4.dst, packet_dsl::ir::Field::Value(ipv("192.168.1.10")));
        // 4) 客户端 sniffer 校验 SYN-ACK（对应 client.pkt 的 sniffer）
        let spec_src = "p = raw(bytes=\"\")\nuse(p) |> tcp(sport=12345, dport=80, seq=0x1000, flags=syn(), window=65535) |> ipv4() |> eth()\n\
sniffer:\n  - match tcp(flags=bor(syn(), ack()), ack=0x1001)\n";
        let cm = parse_str("t", spec_src).unwrap();
        let matcher = packet_dsl::Matcher::build(
            &cm.sniffer.clone().unwrap(),
            Some(&cm),
            &packet_dsl::Params::new(),
            &packet_dsl::Globals::new(),
            true,
        )
        .unwrap();
        let got = matcher
            .matches(&synack_bytes, Some(&packet_dsl::dissect(&syn_frame)))
            .expect("SYN-ACK 应通过客户端 sniffer 校验");
        assert!(
            got.iter().any(|(k, v)| k == "ack" && v == "4097"),
            "{got:?}"
        );
        // 5) 客户端最终 ACK（对应 client.pkt 的 ack_pkt）：seq=0x1001, ack=0x2001
        let ack_src = "p = raw(bytes=\"\")\n\
use(p) |> tcp(sport=12345, dport=80, seq=0x1001, ack=0x2001, flags=ack(), window=65535) |> ipv4(src=\"192.168.1.10\", dst=\"192.168.1.1\") |> eth()\n";
        let am = parse_str("t", ack_src).unwrap();
        let abuilt = packet_dsl::resolve(&am).unwrap();
        let ack_frame = packet_dsl::DefaultSerializer::with_seed(1)
            .serialize(&abuilt.packets[0])
            .unwrap();
        let arep = packet_dsl::dissect(&ack_frame);
        let atcp = arep
            .layers
            .iter()
            .find_map(|l| match l {
                Layer::Tcp(f) => Some(f),
                _ => None,
            })
            .unwrap();
        assert_eq!(atcp.seq, Some(0x1001), "ACK seq=客户端 seq+1");
        assert_eq!(atcp.ack, Some(0x2001), "ACK ack=服务端 seq+1");
        assert_eq!(
            atcp.flags.as_ref().map(|f| f.to_string()),
            Some("ack".into())
        );
    }

    /// 应答模板缺失默认导出 → 报错（--wait --raw 的前置校验）。
    #[test]
    fn listen_raw_requires_default_export() {
        let m = parse_str(
            "t",
            "q = dns(id=1, questions=[\"example.com\"])\nq2 = use(q) |> udp(dport=53) |> ipv4() |> eth()\nexport:\n- q2\nsniffer:\n  - match dns(id=1)\n",
        )
        .unwrap();
        // 该文件只有命名导出 q（无匿名顶层流水线）→ 无默认导出
        assert!(m.default.is_none());
    }
}
