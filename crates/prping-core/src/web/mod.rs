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
//!  ├─ ws.rs    WS 会话：信封分派 + LSP 桥（Content-Length 分帧解包）
//!  ├─ pipe.rs  异步↔阻塞字节桥（WS 任务 ↔ LSP 阻塞线程）
//!  └─ assets.rs 静态资源双模式：默认读 UI/ 目录（二进制目录/启动目录），
//!              web-embed feature 时 rust-embed（debug 直读 dist，release 内嵌）
//! ```
//!
//! 安全模型：默认仅绑定回环（`--addr` 可改）；发包/读文件都发生在服务端进程
//! （raw socket 特权沿用现有 cap_net_raw 体系），浏览器零特权。库文件接口只读。

mod assets;
mod http;
mod pipe;
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

    let listener = smol::net::TcpListener::bind(SocketAddr::new(cfg.addr, cfg.port)).await?;
    let url = format!("http://{}/", listener.local_addr()?);
    print_banner(&url, &libs);

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
                    smol::spawn(handle_conn(stream, libs.clone())).detach();
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
fn print_banner(url: &str, libs: &[PathBuf]) {
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
    // Ctrl+C 提示已在 listening 行尾携带，不再单独重复一行
}

fn stdout_stream() -> StandardStream {
    StandardStream::stdout(ColorChoice::Auto)
}

/// 单连接处理：HTTP（静态/config.json，keep-alive 循环）或 WebSocket 升级（仅 /ws）。
async fn handle_conn(mut stream: smol::net::TcpStream, libs: Arc<Vec<PathBuf>>) {
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
                    None,
                    b"websocket endpoint is /ws\n",
                    false,
                    false,
                )
                .await;
                return;
            };
            // 流所有权交给 WS 层：升级后不再有 HTTP 请求
            if let Ok(ws) = ws::accept(stream, &key).await {
                ws::session(ws, (*libs).clone()).await;
            }
            return;
        }
        if head.method != "GET" && head.method != "HEAD" {
            let _ = http::respond(
                &mut stream,
                "405 Method Not Allowed",
                "text/plain; charset=utf-8",
                None,
                b"GET/HEAD only\n",
                false,
                false,
            )
            .await;
            return;
        }
        let keep = head.keep_alive();
        if http::dispatch(&mut stream, &head).await.is_err() {
            return;
        }
        if !keep {
            return;
        }
    }
}

/// 中断轮询间隔（Ctrl+C 首次优雅退出）。
const INTERRUPT_POLL: Duration = Duration::from_millis(300);
