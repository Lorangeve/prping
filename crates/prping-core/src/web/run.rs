//! Web 执行会话：浏览器发起的 packet 运行（当前工作区文件）→ 自身 CLI 子进程桥。
//!
//! 复用 `packet` 子命令的完整语义（构建发送/配方执行/raw/监听/校验/报错文案）而
//! 零逻辑重复：spawn 自身二进制（`current_exe()`）跑 `prping packet …`，
//! stdout/stderr 逐行打包成 `run_out` 信封回推，退出以 `run_exit` 信封收尾。
//! 取消（run_stop 信封）= kill 活跃子进程；连接断开（回推通道关闭）同样收杀——
//! 不留孤儿进程。非法选项组合不在服务端重复校验：CLI 自己的 validate_* 会报
//! 本地化错误并落在执行控制台里。
//!
//! 约束：
//! - 只运行当前工作区内的 .pkt/.pktl（`resolve_in_root(require_pkt)` 词法校验 +
//!   canonicalize 根内断言）；子进程 cwd = 工作区根（`--out` 相对路径落根内）
//! - 每连接同时最多一个子进程（槽位活跃时新 run 被拒绝）
//! - 转发行数/单行长度有上限：超限后继续排水（防子进程管道写阻塞）但不再转发，
//!   `run_exit.truncated` 标记

use std::collections::HashSet;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rust_i18n::t;
use serde_json::{Value, json};
use smol::channel::Sender;

use super::workspace;

/// 转发行数上限（超过后仅排水不再转发；run_exit.truncated = true）。
const MAX_RUN_LINES: usize = 20_000;
/// 单 run 输出转发总字节预算（行数上限的兜底：少数超长行也打不爆内存）。
const MAX_RUN_BYTES: usize = 16 * 1024 * 1024;
/// 合帧阈值：累计 64KB 或首行待发 16ms 即合并为一个 run_out 信封（前端按 \n
/// 拆行、向后兼容单行信封；大幅降帧率与 JSON 包装开销）。
const FLUSH_BYTES: usize = 64 * 1024;
const FLUSH_INTERVAL: Duration = Duration::from_millis(16);
/// 单行转发上限（字节；超长行截断后转发，行内余量丢弃）。
const MAX_LINE_BYTES: usize = 8 * 1024;
/// 子进程退出轮询间隔（kill 与 try_wait 共用一把锁，轮询避开持锁阻塞等待）。
const POLL: Duration = Duration::from_millis(100);

/// 等待应答模式（信封 wait 字段 → CLI --wait 语义）。
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum WaitOpt {
    /// `--wait SECS`：发送后等一个匹配应答。
    Seconds(f64),
    /// 裸 `--wait`：持续监听（服务端模式）。
    Continuous,
}

/// 一次运行的完整参数（信封字段已解析校验）。
pub(crate) struct RunSpec {
    /// 工作区内待运行文件（绝对路径，canonicalize 过）。
    pub file: PathBuf,
    /// 子进程工作目录 = 工作区根（`--out` 相对路径落在根内）。
    pub cwd: PathBuf,
    /// 生效库目录（`--lib` 透传，保持与页面分析一致的库解析顺序）。
    pub libs: Vec<PathBuf>,
    pub params: Vec<(String, String)>,
    pub globals: Vec<(String, String)>,
    pub count: Option<usize>,
    pub wait: Option<WaitOpt>,
    pub fuzz: bool,
    pub raw: bool,
    pub iface: Option<String>,
    /// pcap 输出（工作区内相对路径，已 validate_rel 词法校验）。
    pub out: Option<String>,
    /// `--json`：JSONL 结构化输出（前端按行渲染包/步骤/汇总；与裸 `--wait`
    /// 监听冲突——由前端禁用组合，CLI 校验兜底）。
    pub json: bool,
}

/// 活跃运行的句柄（槽位与 waiter 各持一份克隆；kill/try_wait 共用一把锁，
/// 两边都只短暂持锁——不做持锁阻塞等待，无死锁面）。
#[derive(Clone)]
pub(crate) struct RunHandle {
    child: Arc<Mutex<Child>>,
    stopped: Arc<AtomicBool>,
}

/// 每连接一个运行槽：活跃运行列表（多标签并行运行；全服并发由 MAX_CONCURRENT_RUNS 封顶）。
pub(crate) type RunSlot = Mutex<Vec<RunEntry>>;

/// 槽位条目：run_id → 句柄（waiter 收尾按 id 摘除）。
pub(crate) struct RunEntry {
    pub id: String,
    handle: RunHandle,
}

/// 每连接运行序号发生器（run 信封自增 → run_id）。
pub(crate) type RunSeq = AtomicU64;

// ── 信封 → RunSpec ────────────────────────────────────────────────────────

/// `run` 信封 → RunSpec：文件限工作区内 .pkt/.pktl（canonicalize 根内断言），
/// 数值字段快速校验（count/wait），`--out` 经 validate_rel 防逃逸；其余选项
/// 组合交给子进程 CLI 校验（报错文案落在执行控制台）。
pub(crate) fn spec_from_envelope(
    env: &Value,
    root: &Path,
    libs: Vec<PathBuf>,
) -> anyhow::Result<RunSpec> {
    let name = env.get("name").and_then(Value::as_str).unwrap_or("");
    let file = workspace::resolve_in_root(root, name, true)?;
    if !file.is_file() {
        anyhow::bail!(t!("web.run_bad_file"));
    }
    let opt_str = |key: &str| {
        env.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let count = match env.get("count") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!(t!("web.run_bad_count")))?;
            if n == 0 {
                anyhow::bail!(t!("web.run_bad_count"));
            }
            Some(usize::try_from(n).map_err(|_| anyhow::anyhow!(t!("web.run_bad_count")))?)
        }
    };
    let wait = match env.get("wait") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(true)) => Some(WaitOpt::Continuous),
        Some(v) => match v.as_f64() {
            Some(s) if s.is_finite() && s >= 0.0 => Some(WaitOpt::Seconds(s)),
            _ => anyhow::bail!(t!("web.run_bad_wait")),
        },
    };
    // CLI 的 --params/--global 值按 ',' 切 pair：含逗号的值传下去会被误拆，提前拒绝
    let params = kv_map(env.get("params"))?;
    let globals = kv_map(env.get("globals"))?;
    let out = match opt_str("out") {
        None => None,
        Some(rel) => {
            workspace::validate_rel(&rel, false)?;
            Some(rel)
        }
    };
    Ok(RunSpec {
        file,
        cwd: root.to_path_buf(),
        libs,
        // 不收 target：发包地址属于包字段（params 注入 IP 层 dst / 传输层 dport），
        // socket 目标由引擎从包内推导（resolve_send_target）；显式覆盖通道只留 CLI
        // 位置参数（prping packet FILE HOST:PORT），webui 不再开这条旁路。
        params,
        globals,
        count,
        wait,
        fuzz: env.get("fuzz").and_then(Value::as_bool).unwrap_or(false),
        raw: env.get("raw").and_then(Value::as_bool).unwrap_or(false),
        iface: opt_str("iface"),
        out,
        json: env.get("json").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// 信封 params/globals 对象 → (k, v) 列表（键非空；值含 ',' 拒绝——CLI 按 ',' 切）。
fn kv_map(v: Option<&Value>) -> anyhow::Result<Vec<(String, String)>> {
    let Some(obj) = v.and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (k, val) in obj {
        if k.trim().is_empty() {
            anyhow::bail!(t!("web.run_bad_param", name = k));
        }
        let val = match val {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if val.contains(',') {
            anyhow::bail!(t!("web.run_bad_param", name = k));
        }
        out.push((k.clone(), val));
    }
    Ok(out)
}

// ── 启动 / 停止 ───────────────────────────────────────────────────────────

/// 全服并发运行数上限（多连接 + 多标签共享；本地单用户工具，上限取宽松值）。
const MAX_CONCURRENT_RUNS: usize = 8;

/// 全服活跃运行计数（start 占位、waiter 收尾释放——所有退出路径统一在此递减）。
static ACTIVE_RUNS: AtomicUsize = AtomicUsize::new(0);

/// 活跃运行占位守卫：waiter 退出（自然结束/停止/断开收杀）即递减。
struct ActiveRunGuard;

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        ACTIVE_RUNS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 启动一次运行：全局并发占位 → 入槽 → spawn 子进程 → 挂读流与 waiter 任务。
/// 同连接可并行多个运行（多标签），全服并发由 MAX_CONCURRENT_RUNS 封顶。
/// 成功返回 run_id（调用方先回 result ack；后续经 run_out/run_exit 推送）。
pub(crate) fn start(
    spec: RunSpec,
    reply_tx: Sender<Value>,
    slot: &Arc<RunSlot>,
    seq: &RunSeq,
) -> anyhow::Result<String> {
    if ACTIVE_RUNS.fetch_add(1, Ordering::Relaxed) >= MAX_CONCURRENT_RUNS {
        ACTIVE_RUNS.fetch_sub(1, Ordering::Relaxed);
        anyhow::bail!(t!("web.run_too_many", max = MAX_CONCURRENT_RUNS));
    }
    let guard = ActiveRunGuard;
    let run_id = format!("run-{}", seq.fetch_add(1, Ordering::Relaxed));
    let mut child = spawn_child(&spec)?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    // stdin 生命线：写端由 waiter 持有，waiter 退出（收尾）才关闭；服务端进程死亡
    // 时内核关闭写端 → 子进程（PRPING_WEB_RUN=1 监视 stdin）读到 EOF 自行退出
    let stdin_lifeline = child.stdin.take();
    let handle = RunHandle {
        child: Arc::new(Mutex::new(child)),
        stopped: Arc::new(AtomicBool::new(false)),
    };
    {
        let mut s = slot
            .lock()
            .map_err(|_| anyhow::anyhow!(t!("web.run_slot_failed")))?;
        s.push(RunEntry {
            id: run_id.clone(),
            handle: handle.clone(),
        });
    }
    let truncated = Arc::new(AtomicBool::new(false));
    let budget = Arc::new(AtomicUsize::new(0));
    if let Some(pipe) = stdout {
        spawn_stream_reader(
            pipe,
            "out",
            run_id.clone(),
            reply_tx.clone(),
            budget.clone(),
            truncated.clone(),
        );
    }
    if let Some(pipe) = stderr {
        spawn_stream_reader(
            pipe,
            "err",
            run_id.clone(),
            reply_tx.clone(),
            budget,
            truncated.clone(),
        );
    }
    spawn_waiter(
        handle,
        run_id.clone(),
        reply_tx,
        truncated,
        slot.clone(),
        stdin_lifeline,
        guard,
    );
    Ok(run_id)
}

/// 停止活跃运行（kill；waiter 收尸并回报 run_exit.stopped）。
/// `id` = Some 按运行 id 精确停（任务管理），None 停当前连接全部（会话收尾/兜底）。
/// 返回确有停止的数量；被停条目即从槽位摘除（waiter 仍持句柄克隆负责收尸）。
pub(crate) fn stop(slot: &RunSlot, id: Option<&str>) -> usize {
    let Ok(mut s) = slot.lock() else { return 0 };
    let mut stopped = 0;
    s.retain(|e| {
        let matched = id.is_none_or(|i| i == e.id);
        if matched {
            e.handle.stopped.store(true, Ordering::Relaxed);
            if let Ok(mut c) = e.handle.child.lock() {
                let _ = c.kill();
            }
            stopped += 1;
            false // 摘除；waiter 凭自己的句柄克隆收尸并回报 run_exit
        } else {
            true
        }
    });
    stopped
}

/// spawn 自身二进制的 `packet` 子命令（stdin 管道化作为生命线——写端由服务端
/// 持有，服务端死亡即 EOF，子进程据此自行退出；stdout/stderr 管道化——注意
/// termcolor ColorChoice::Auto 只看 TERM/NO_COLOR、**不查 tty**，管道下去色并不
/// 自动发生，因此显式注入 NO_COLOR=1（termcolor 两平台分支都认），保证页面得到
/// 纯文本行；前端对非 JSON 回退行另有 ANSI 剥离兜底）。
fn spawn_child(spec: &RunSpec) -> anyhow::Result<Child> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!(t!("web.run_spawn_failed", err = e.to_string())))?;
    Command::new(exe)
        .args(build_args(spec))
        .current_dir(&spec.cwd)
        .env("PRPING_WEB_RUN", "1")
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!(t!("web.run_spawn_failed", err = e.to_string())))
}

/// 组装 `packet` 子命令 argv（不含程序名；不含 --json——页面要人读输出）。
/// 不传位置 HOST[:PORT]：地址一律由包字段（params）承载、引擎从包内推导。
fn build_args(spec: &RunSpec) -> Vec<String> {
    let mut args: Vec<String> = vec!["packet".into()];
    // 库目录透传：子进程自身会默认发现「exe 目录 lib/」与「cwd lib/」（cwd =
    // 工作区根），与之相同（canonicalize 等价）的条目不再透传——避免重复展示，
    // 解析语义不变。相对路径先按服务端 cwd 绝对化（子进程 cwd 已换成工作区根，
    // 服务端 effective_libs 里的相对 lib 语义必须保留在服务端一侧）。
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let mut child_default_keys: HashSet<PathBuf> = HashSet::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        child_default_keys.insert(canon(&dir.join("lib")));
    }
    child_default_keys.insert(canon(&spec.cwd.join("lib")));
    let server_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for dir in &spec.libs {
        let abs = if dir.is_absolute() {
            dir.clone()
        } else {
            server_cwd.join(dir)
        };
        if child_default_keys.contains(&canon(&abs)) {
            continue;
        }
        if seen.insert(abs.clone()) {
            args.push("--lib".into());
            args.push(abs.display().to_string());
        }
    }
    for (k, v) in &spec.params {
        args.push("--params".into());
        args.push(format!("{k}={v}"));
    }
    for (k, v) in &spec.globals {
        args.push("--global".into());
        args.push(format!("{k}={v}"));
    }
    if let Some(n) = spec.count {
        args.push("--count".into());
        args.push(n.to_string());
    }
    match &spec.wait {
        Some(WaitOpt::Seconds(s)) => {
            args.push("--wait".into());
            args.push(format!("{s}"));
        }
        Some(WaitOpt::Continuous) => args.push("--wait".into()),
        None => {}
    }
    if spec.fuzz {
        args.push("--fuzz".into());
    }
    if spec.raw {
        args.push("--raw".into());
    }
    if let Some(name) = &spec.iface {
        args.push("--iface".into());
        args.push(name.clone());
    }
    if let Some(out) = &spec.out {
        args.push("--out".into());
        args.push(out.clone());
    }
    if spec.json {
        args.push("--json".into());
    }
    args.push(display_clean(&spec.file));
    args
}

/// Windows canonicalize 产物剥 `\\?\` verbatim 前缀：fs 层两种形态等价，
/// argv 与 UI 展示用剥前缀的可读形态（其余平台原样返回）。
fn display_clean(p: &Path) -> String {
    let s = p.display().to_string();
    match s.strip_prefix(r"\\?\") {
        Some(rest) => rest.to_string(),
        None => s,
    }
}

// ── 输出转发 / 退出等待（阻塞任务，跑在 smol::unblock 线程池）────────────

/// 单流读任务：行块 → 合帧缓冲 → run_out 信封（64KB / 16ms 阈值）；行数或字节
/// 预算耗尽后仅排水不再转发（管道必须被消费，否则子进程写满缓冲即阻塞）；
/// 回推通道关闭即退出（bounded 通道满时阻塞此处 = 背压传导到子进程，内存恒定）。
fn spawn_stream_reader(
    pipe: impl std::io::Read + Send + 'static,
    stream: &'static str,
    run_id: String,
    reply_tx: Sender<Value>,
    budget: Arc<AtomicUsize>,
    truncated: Arc<AtomicBool>,
) {
    smol::unblock(move || {
        let mut r = std::io::BufReader::new(pipe);
        let mut buf = Vec::new();
        // 合帧缓冲：text 保留每行行尾 \n（前端 split('\n') 拆行、丢空行）
        let mut acc = String::new();
        let mut acc_since: Option<std::time::Instant> = None;
        let mut bytes_forwarded = 0usize;
        while matches!(read_line_chunk(&mut r, &mut buf), Ok(true)) {
            // 行预算 + 字节预算（后者兜底：少数超长行也打不爆内存）
            let within_lines = budget.fetch_add(1, Ordering::Relaxed) < MAX_RUN_LINES;
            let within_bytes = bytes_forwarded + buf.len() <= MAX_RUN_BYTES;
            if within_lines && within_bytes {
                let text = String::from_utf8_lossy(&buf);
                acc.push_str(&text);
                if !text.ends_with('\n') {
                    acc.push('\n');
                }
                bytes_forwarded += buf.len();
                if acc_since.is_none() {
                    acc_since = Some(std::time::Instant::now());
                }
                if acc.len() >= FLUSH_BYTES
                    || acc_since.is_some_and(|t| t.elapsed() >= FLUSH_INTERVAL)
                {
                    let _ = reply_tx.send_blocking(json!({
                        "type": "run_out", "run": run_id, "stream": stream, "text": acc,
                    }));
                    acc = String::new();
                    acc_since = None;
                }
            } else {
                truncated.store(true, Ordering::Relaxed);
            }
        }
        // 收尾冲刷：预算内残留行一次发出（不足 16ms/64KB 也不丢）
        if !acc.is_empty() {
            let _ = reply_tx.send_blocking(json!({
                "type": "run_out", "run": run_id, "stream": stream, "text": acc,
            }));
        }
    })
    .detach();
}

/// 退出等待任务：轮询 try_wait（kill 需要同一把锁，持锁阻塞 wait 会互斥）。
/// 退出 → 从槽位摘除 + run_exit 信封；连接断开（通道关闭）→ 收杀后静默退出。
fn spawn_waiter(
    handle: RunHandle,
    run_id: String,
    reply_tx: Sender<Value>,
    truncated: Arc<AtomicBool>,
    slot: Arc<RunSlot>,
    // stdin 生命线写端：仅由本任务持有（生命周期 = 运行收尾），服务端死亡时
    // 内核关闭写端 → 子进程的 stdin 监视线程读到 EOF 自行退出
    stdin_lifeline: Option<std::process::ChildStdin>,
    _guard: ActiveRunGuard,
) {
    smol::unblock(move || {
        // 显式移入闭包体：move 闭包只捕获 body 引用到的值——不引用会在
        // spawn_waiter 返回时被 drop，写端提前关闭 → 子进程生命线立即自杀
        let _lifeline = stdin_lifeline;
        loop {
            std::thread::sleep(POLL);
            let status = {
                let Ok(mut c) = handle.child.lock() else {
                    return;
                };
                match c.try_wait() {
                    Ok(Some(st)) => st,
                    Ok(None) => {
                        // 连接已断：不留孤儿进程，收杀后返回
                        if reply_tx.is_closed() {
                            let _ = c.kill();
                            let _ = c.wait();
                            return;
                        }
                        continue;
                    }
                    Err(_) => return,
                }
            };
            // 从槽位摘除自己（按 id；stop 已摘过则此处为空操作）
            if let Ok(mut s) = slot.lock() {
                s.retain(|e| e.id != run_id);
            }
            // 被 kill 的 unix 子进程 exit code 为 None → 前端以 stopped 展示
            let _ = reply_tx.send_blocking(json!({
                "type": "run_exit", "run": run_id,
                "code": status.code(),
                "stopped": handle.stopped.load(Ordering::Relaxed),
                "truncated": truncated.load(Ordering::Relaxed),
            }));
            return;
        }
    })
    .detach();
}

/// 从管道读一个「行块」（到 \n 为止）：超长行截断转发并丢弃行内余量；
/// 返回 Ok(false) = EOF（缓冲有残留时先返回该残留，下一次调用再报 EOF）。
fn read_line_chunk(r: &mut dyn BufRead, buf: &mut Vec<u8>) -> std::io::Result<bool> {
    buf.clear();
    let mut cut = false;
    loop {
        let available = r.fill_buf()?;
        if available.is_empty() {
            return Ok(!buf.is_empty()); // EOF：吐出最后一段无换行输出
        }
        let nl = available.iter().position(|&b| b == b'\n');
        let line_len = nl.unwrap_or(available.len());
        if buf.len() < MAX_LINE_BYTES {
            let take = line_len.min(MAX_LINE_BYTES - buf.len());
            cut |= take < line_len;
            buf.extend_from_slice(&available[..take]);
        } else {
            cut = true;
        }
        if nl.is_some() {
            r.consume(line_len + 1); // 连同 \n 一起消费
            if cut {
                buf.extend_from_slice("…".as_bytes());
            }
            return Ok(true);
        }
        let n = available.len();
        r.consume(n);
        if buf.len() >= MAX_LINE_BYTES {
            // 行长超限：丢弃该行剩余部分直到 \n（或 EOF）
            loop {
                let a = r.fill_buf()?;
                if a.is_empty() {
                    break;
                }
                match a.iter().position(|&b| b == b'\n') {
                    Some(i) => {
                        r.consume(i + 1);
                        break;
                    }
                    None => {
                        let n = a.len();
                        r.consume(n);
                    }
                }
            }
            buf.extend_from_slice("…".as_bytes());
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn spec() -> RunSpec {
        RunSpec {
            file: PathBuf::from("/ws/a.pkt"),
            cwd: PathBuf::from("/ws"),
            libs: vec![PathBuf::from("/lib")],
            params: Vec::new(),
            globals: Vec::new(),
            count: None,
            wait: None,
            fuzz: false,
            raw: false,
            iface: None,
            out: None,
            json: false,
        }
    }

    #[test]
    fn build_args_defaults_and_full() {
        // 缺省：packet + --lib + FILE（库目录透传保证与页面一致的库解析）
        assert_eq!(
            build_args(&spec()),
            ["packet", "--lib", "/lib", "/ws/a.pkt"]
        );
        let mut s = spec();
        s.params = vec![("ip".into(), "1.2.3.4".into())];
        s.globals = vec![("g".into(), "7".into())];
        s.count = Some(3);
        s.wait = Some(WaitOpt::Seconds(2.5));
        s.fuzz = true;
        s.raw = true;
        s.iface = Some("eth0".into());
        s.out = Some("run.pcap".into());
        s.json = true;
        assert_eq!(
            build_args(&s),
            [
                "packet",
                "--lib",
                "/lib",
                "--params",
                "ip=1.2.3.4",
                "--global",
                "g=7",
                "--count",
                "3",
                "--wait",
                "2.5",
                "--fuzz",
                "--raw",
                "--iface",
                "eth0",
                "--out",
                "run.pcap",
                "--json",
                "/ws/a.pkt",
            ]
        );
        // 裸 --wait（持续监听）
        let mut s = spec();
        s.wait = Some(WaitOpt::Continuous);
        assert!(
            build_args(&s)
                .windows(2)
                .any(|w| w == ["--wait", "/ws/a.pkt"])
        );
    }

    #[test]
    fn read_line_chunk_whole_split_and_eof() {
        let mut r = std::io::BufReader::with_capacity(2, Cursor::new(b"ab\ncd\r\nlast".to_vec()));
        let mut buf = Vec::new();
        assert!(read_line_chunk(&mut r, &mut buf).unwrap());
        assert_eq!(buf, b"ab");
        assert!(read_line_chunk(&mut r, &mut buf).unwrap());
        assert_eq!(buf, b"cd\r"); // \r 保留，转发层去
        assert!(read_line_chunk(&mut r, &mut buf).unwrap());
        assert_eq!(buf, b"last"); // 无换行 EOF 残留
        assert!(!read_line_chunk(&mut r, &mut buf).unwrap()); // 再读 = EOF
    }

    #[test]
    fn read_line_chunk_truncates_overlong_line() {
        let line = "x".repeat(MAX_LINE_BYTES + 100) + "\nnext";
        let mut r = std::io::BufReader::new(Cursor::new(line.into_bytes()));
        let mut buf = Vec::new();
        assert!(read_line_chunk(&mut r, &mut buf).unwrap());
        assert_eq!(buf.len(), MAX_LINE_BYTES + "…".len());
        assert!(buf.ends_with("…".as_bytes()));
        assert!(read_line_chunk(&mut r, &mut buf).unwrap());
        assert_eq!(buf, b"next");
    }

    #[test]
    fn spec_from_envelope_validates() {
        let dir = std::env::temp_dir().join(format!("prping-run-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.pkt"), "pkt {}").unwrap();
        let base = || json!({ "name": "a.pkt" });
        // 基线可用
        let s = spec_from_envelope(&base(), &dir, Vec::new()).unwrap();
        assert_eq!(s.file, dir.join("a.pkt"));
        assert_eq!(s.cwd, dir);
        // 逃逸路径 / 非 pkt 扩展名拒绝
        assert!(spec_from_envelope(&json!({"name": "../x.pkt"}), &dir, Vec::new()).is_err());
        assert!(spec_from_envelope(&json!({"name": "a.txt"}), &dir, Vec::new()).is_err());
        // count/wait 数值校验
        for (k, v) in [
            ("count", json!(0)),
            ("wait", json!(-1.0)),
            ("wait", json!("x")),
        ] {
            let mut e = base();
            e[k] = v;
            assert!(spec_from_envelope(&e, &dir, Vec::new()).is_err(), "{k}");
        }
        // wait: true → 持续监听
        let mut e = base();
        e["wait"] = json!(true);
        assert_eq!(
            spec_from_envelope(&e, &dir, Vec::new()).unwrap().wait,
            Some(WaitOpt::Continuous)
        );
        // --out 逃逸与参数值含逗号拒绝
        let mut e = base();
        e["out"] = json!("../e.pcap");
        assert!(spec_from_envelope(&e, &dir, Vec::new()).is_err());
        let mut e = base();
        e["params"] = json!({"a": "b,c"});
        assert!(spec_from_envelope(&e, &dir, Vec::new()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
