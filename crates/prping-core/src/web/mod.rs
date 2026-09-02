//! `prping web` —— Web 编辑器服务器（`prping web --open`）。
//!
//! 单进程单端口，浏览器直连：
//!
//! ```text
//! 浏览器（SolidJS SPA；默认读 UI/ 目录，--features web-embed 时内嵌二进制）
//!  ├─ CodeMirror 6 ── LSP JSON-RPC（WS 信封透传 → 内存管道 → run_lsp_on）
//!  └─ 层栈 / HEX 预览 ── analyze 信封（内存文本 → engine --json 同构文档）
//!            │ HTTP(静态) + WebSocket(/ws) 同端口
//! ── serve_web（本模块）──
//!  ├─ http.rs  极简 HTTP/1.1 GET 响应（本机回环工具，不做完整 RFC 覆盖）
//!  ├─ ws.rs    WS 会话：升级鉴权（token/Origin/Host）+ 信封分派 + LSP 桥
//!  ├─ pipe.rs  异步↔阻塞字节桥（WS 任务 ↔ LSP 阻塞线程）
//!  └─ assets.rs 静态资源双模式：默认读 UI/ 目录（二进制目录/启动目录），
//!              web-embed feature 时 rust-embed（debug 直读 dist，release 内嵌）
//! ```
//!
//! 安全模型：默认仅绑定回环（`--addr` 可改）；发包/读文件都发生在服务端进程
//! （raw socket 特权沿用现有 cap_net_raw 体系），浏览器零特权。库文件接口只读。
//! WS 升级三道校验（ws::authorize）：一次性 token（进程启动生成，经 /config.json
//! 下发）+ Origin 同源 + Host 回环（防 DNS rebinding）。

mod assets;
mod http;
mod pipe;
mod run;
mod workspace;
mod ws;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rust_i18n::t;
use termcolor::{ColorChoice, StandardStream};

use crate::engine::eng::{
    effective_libs, ensure_dns_resolver, ensure_proto_registry, libs_display,
};
use crate::output::{print_cyan, print_dim, print_magenta, print_orange};
use crate::util::interrupted;

// ── 结构化错误码（错误信封 code 字段）──────────────────────────────────────

/// 错误信封统一码表：所有 ok:false / type:error 信封都带 `code`（message 保留
/// 既有文案）；前端按码分流提示，未知码按文案兜底展示。
pub(crate) mod code {
    /// 信封/载荷不合法（JSON 解析失败、未知 type、字段校验失败）
    pub(crate) const INVALID_ENVELOPE: &str = "invalid_envelope";
    /// 目标不存在（工作区/库文件缺失、文件夹不存在）
    pub(crate) const NOT_FOUND: &str = "not_found";
    /// 大小超限（读取文件 > 8MB / 保存文本 > 4MB）
    pub(crate) const TOO_LARGE: &str = "too_large";
    /// 路径越界或非法（穿越、点段、反斜杠、盘符、扩展名不符）
    pub(crate) const ESCAPE: &str = "escape";
    /// 二进制内容（工作区读取只收 UTF-8 文本）
    pub(crate) const BINARY: &str = "binary";
    /// 状态冲突（目标已存在、并发超限；未标注的运行态 IO 失败也归此类兜底）
    pub(crate) const CONFLICT: &str = "conflict";
}

/// 带码错误：随 anyhow 链传递，错误信封构造处经 [`code_of`] 提取
/// （Display = 用户可见文案，与既有 t! 文案一致或为英文说明）。
#[derive(Debug)]
pub(crate) struct CodedError {
    code: &'static str,
    msg: String,
}

impl std::fmt::Display for CodedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for CodedError {}

/// 以给定码构造 anyhow 错误（code 取 [`code`] 常量；msg 为用户可见文案）。
pub(crate) fn coded(code: &'static str, msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(CodedError {
        code,
        msg: msg.into(),
    })
}

/// 提取错误的信封码；未标注错误（裸 io!/格式化失败等运行态错误）按冲突兜底。
pub(crate) fn code_of(e: &anyhow::Error) -> &'static str {
    e.downcast_ref::<CodedError>()
        .map(|c| c.code)
        .unwrap_or(code::CONFLICT)
}

// ── WS 鉴权 token ─────────────────────────────────────────────────────────

/// 进程启动生成一次性 WS 鉴权 token（32 hex = 128bit）。
///
/// 无 rand 依赖的实现：`RandomState` 每次 `new()` 都携带 OS 随机种子
/// （线程局部初始化自系统熵源，其后按内部计数器混淆），对固定盐值哈希取
/// 双 64bit 拼接——一次性本地会话令牌足够（无需跨进程可复现）。
fn generate_token() -> String {
    use std::hash::{BuildHasher, RandomState};
    let mix = |salt: u64| RandomState::new().hash_one(salt);
    let a = mix(0x9E37_79B9_7F4A_7C15);
    let b = mix(0xBF58_476D_1CE4_E5B9);
    format!("{a:016x}{b:016x}")
}

/// `web` 子命令配置。
#[derive(Debug, Clone)]
pub struct WebConfig {
    /// 监听地址（默认 127.0.0.1，仅回环——页面可触发引擎能力，默认不暴露到网络）。
    pub addr: std::net::IpAddr,
    /// 监听端口；0 = 自动分配。
    pub port: u16,
    /// 附加 pkglang 库目录（`--lib`；与 engine/packet 同一合并语义）。
    pub libs: Vec<PathBuf>,
    /// 启动后自动打开浏览器（`--open`）。
    pub open_browser: bool,
}

/// Web 编辑器服务器（阻塞直至 Ctrl+C；CLI 侧 `smol::block_on(serve_web(cfg))`）。
pub async fn serve_web(cfg: WebConfig) -> anyhow::Result<()> {
    ensure_dns_resolver();
    ensure_proto_registry();
    let libs = Arc::new(effective_libs(&cfg.libs));
    // 默认工作区（examples；二进制目录优先、其次启动目录，与 UI/lib 就近查找一致）
    let default_ws = workspace::default_workspace();
    // 一次性 WS 鉴权 token：经 /config.json 下发，前端拼 ?token= 完成 /ws 升级
    let token = generate_token();

    let listener = smol::net::TcpListener::bind(SocketAddr::new(cfg.addr, cfg.port)).await?;
    let url = format!("http://{}/", listener.local_addr()?);
    print_banner(&url, &libs, default_ws.as_ref());

    if cfg.open_browser {
        match open::that_detached(&url) {
            // URL 已在横幅 listening 行打印过，这里不再重复
            Ok(()) => {
                let mut w = stdout_stream();
                let _ = print_cyan(&mut w, &t!("web.opening"));
                println!();
            }
            Err(e) => {
                let mut w = stdout_stream();
                let _ = print_orange(
                    &mut w,
                    &t!("web.open_failed", err = e.to_string(), url = url.as_str()),
                );
                println!();
            }
        }
    }

    // 连接循环放独立 task；主循环轮询中断标志（accept 无超时，race 方案需统一
    // 输出类型，双 task + 轮询与 serve 的 Timer 轮询风格一致）。
    let server = smol::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    smol::spawn(handle_conn(
                        stream,
                        libs.clone(),
                        default_ws.clone(),
                        token.clone(),
                    ))
                    .detach();
                }
                Err(e) => {
                    // accept 错误退避（防 EMFILE 之类死循环烧 CPU），随后继续
                    let mut w = stdout_stream();
                    let _ = print_orange(&mut w, format!("accept: {e}"));
                    println!();
                    smol::Timer::after(Duration::from_millis(200)).await;
                }
            }
        }
    });
    while !interrupted() {
        smol::Timer::after(INTERRUPT_POLL).await;
    }
    // server task 弃之不管：本函数返回后 CLI main 返回、进程退出，连接任务随之终止
    drop(server);
    Ok(())
}

/// 打印监听横幅（与 serve 一致的 termcolor 风格）。
fn print_banner(url: &str, libs: &[PathBuf], ws: Option<&PathBuf>) {
    let mut w = stdout_stream();
    let _ = print_magenta(&mut w, format!("prping web {}", env!("CARGO_PKG_VERSION")));
    println!();
    let _ = print_cyan(&mut w, &t!("web.listening", url = url));
    println!();
    let _ = print_dim(&mut w, format!("libs: {}", libs_display(libs)));
    println!();
    // 静态资源来源：内嵌（web-embed）/ UI 目录路径 / 未找到提示
    let _ = print_dim(&mut w, format!("ui: {}", assets::source_label()));
    println!();
    // 可编辑工作区（examples 未找到时提示可从页面打开自定义文件夹）
    let ws_label = match ws {
        Some(d) => t!("web.ws_dir", dir = d.display().to_string()).to_string(),
        None => t!("web.ws_dir_missing").to_string(),
    };
    let _ = print_dim(&mut w, format!("workspace: {ws_label}"));
    println!();
    // Ctrl+C 提示已在 listening 行尾携带，不再单独重复一行
}

fn stdout_stream() -> StandardStream {
    StandardStream::stdout(ColorChoice::Auto)
}

/// 单连接处理：HTTP（静态/config.json，keep-alive 循环）或 WebSocket 升级（仅 /ws）。
async fn handle_conn(
    mut stream: smol::net::TcpStream,
    libs: Arc<Vec<PathBuf>>,
    default_ws: Option<PathBuf>,
    token: String,
) {
    loop {
        let head = match http::read_head(&mut stream).await {
            Ok(Some(h)) => h,
            // 干净断开 / 解析失败：直接关闭（回环工具，错误细节不值得往返）
            Ok(None) | Err(_) => return,
        };
        if head.wants_websocket() {
            let key = if head.path == "/ws" {
                head.ws_key()
            } else {
                None
            };
            let Some(key) = key else {
                let _ = http::respond(
                    &mut stream,
                    "404 Not Found",
                    "text/plain; charset=utf-8",
                    http::RespExtra::default(),
                    b"websocket endpoint is /ws\n",
                    false,
                    false,
                )
                .await;
                return;
            };
            // 升级鉴权：token 查询参数 + Origin 同源 + Host 回环（防 DNS rebinding）。
            // 拒绝原因回 403 正文（本机调试可见），连接随即关闭。
            if let Err(reason) = ws::authorize(&head, &token) {
                let _ = http::respond(
                    &mut stream,
                    "403 Forbidden",
                    "text/plain; charset=utf-8",
                    http::RespExtra::default(),
                    format!("websocket upgrade rejected: {reason}\n").as_bytes(),
                    false,
                    false,
                )
                .await;
                return;
            }
            // 流所有权交给 WS 层：升级后不再有 HTTP 请求
            if let Ok(ws) = ws::accept(stream, &key).await {
                ws::session(ws, (*libs).clone(), default_ws).await;
            }
            return;
        }
        if head.method != "GET" && head.method != "HEAD" {
            let _ = http::respond(
                &mut stream,
                "405 Method Not Allowed",
                "text/plain; charset=utf-8",
                http::RespExtra::default(),
                b"GET/HEAD only\n",
                false,
                false,
            )
            .await;
            return;
        }
        let keep = head.keep_alive();
        if http::dispatch(&mut stream, &head, &token).await.is_err() {
            return;
        }
        if !keep {
            return;
        }
    }
}

/// 中断轮询间隔（Ctrl+C 首次优雅退出）。
const INTERRUPT_POLL: Duration = Duration::from_millis(300);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_hex_and_unique_per_call() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        // 两次生成不同（OS 随机种子 + 计数器混淆）；128bit 碰撞概率可忽略
        assert_ne!(a, b);
    }

    #[test]
    fn coded_error_roundtrip_and_fallback() {
        let e = coded(code::TOO_LARGE, "too big");
        assert_eq!(e.to_string(), "too big");
        assert_eq!(code_of(&e), code::TOO_LARGE);
        // 未标注错误 → 冲突兜底
        let plain = anyhow::anyhow!("io failed");
        assert_eq!(code_of(&plain), code::CONFLICT);
    }
}
