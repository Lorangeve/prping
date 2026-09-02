//! WebSocket 会话：信封协议分派 + LSP 桥 + 内存文本分析 + 库文件只读浏览。
//!
//! 信封协议（JSON，一帧一信封）：
//!
//! ```text
//! client → server
//!   { "type": "lsp",     "message": {…JSON-RPC…} }     透传给 LSP 会话
//!   { "type": "analyze", "id": 1, "uri": "file:///x.pkt",
//!     "text": "…", "params": {"k":"v"} }               engine --json 同构分析
//!   { "type": "list",    "id": 2 }                       列库文件（.pkt/.pktl，只读）
//!   { "type": "read",    "id": 3, "name": "net.pkt" }    读库文件（默认 root="lib"，只读）
//!   { "type": "read",    "id": 4, "root": "ws", "name": "sub/x.pkt" }  读工作区文件（可写）
//!   { "type": "tree",    "id": 5 }                       工作区目录树（默认 examples）
//!   { "type": "save",    "id": 6, "name": "sub/x.pkt", "text": "…" }  保存（限工作区）
//!   { "type": "delete",  "id": 7, "name": "sub/x.pkt" }  删除（限工作区；目录递归）
//!   { "type": "rename",  "id": 7, "from": "a.pkt", "to": "b/c.pkt" }  重命名/移动（限工作区）
//!   { "type": "mkdir",   "id": 7, "name": "sub/dir" }    新建目录（限工作区）
//!   { "type": "workspace", "id": 8 }                     查询当前工作区根
//!   { "type": "workspace", "id": 9, "path": "/dir" }     打开自定义文件夹（"" 重置默认）
//!   { "type": "browse",  "id": 11, "path": "/dir" }      浏览目录（文件夹选择对话框数据源；
//!                                                        path 缺省 = 用户主目录）
//!   { "type": "run",     "id": 12, "name": "a.pktl",    运行工作区 .pkt/.pktl（spawn 自身
//!                    "target": "h:p", "params": {...},  二进制 `packet` 子命令；见 run.rs）；
//!                    "count": N, "wait": SECS|true,     wait=true = 裸 --wait（持续监听）
//!                    "raw": bool, "iface": "eth0", "out": "run.pcap" }
//!   { "type": "run_stop", "id": 13, "run": "run-0" }     停止运行：带 run id 停单个
//!                                                        （多标签任务管理）；缺省停本连接全部
//! server → client
//!   { "type": "lsp", "message": {…publishDiagnostics/响应…} }
//!   { "type": "result", "id": 1, "ok": true, "data": … | "ok": false, "error": "…" }
//!   { "type": "run_out", "run": "run-0", "stream": "out"|"err", "text": "…" }  运行输出（流式）
//!   { "type": "run_exit", "run": "run-0", "code": 0|null, "stopped": bool,    运行结束
//!                         "truncated": bool }                                  （code null = 被 kill）
//! ```
//!
//! LSP 桥：每个 WS 连接一个独立 LSP 会话——客户端消息按 Content-Length 分帧写入
//! 内存管道，阻塞线程跑现有 `run_lsp_on`（零改动复用 stdio 实现），输出帧解包成
//! 信封回推。连接断开 → 请求侧发送端 drop → LSP 读 EOF 退出 → 响应侧发送端 drop
//! → 回推通道关闭 → 会话任务结束（无泄漏）。

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use async_tungstenite::WebSocketStream;
use async_tungstenite::tungstenite::Bytes;
use async_tungstenite::tungstenite::handshake::derive_accept_key;
use async_tungstenite::tungstenite::protocol::{Message, Role};
use futures_util::StreamExt;
use rust_i18n::t;
use serde_json::{Map, Value, json};
use smol::channel::{Sender, bounded, unbounded};
use smol::io::AsyncWriteExt;
use smol::net::TcpStream;

use super::code;
use super::code_of;
use super::http::RequestHead;
use super::pipe::{ChanReader, ChanWriter};
use super::run;
use super::workspace;

/// 单条 LSP 消息上限（与 lsp.rs 的 MAX_LSP_MSG 同量级，防异常帧耗内存）。
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// 完成 WS 握手：请求头已由 HTTP 层读走，这里手工回 101 后直接切协议。
pub(crate) async fn accept(
    mut stream: TcpStream,
    key: &str,
) -> std::io::Result<WebSocketStream<TcpStream>> {
    let accept = derive_accept_key(key.as_bytes());
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    // 握手已完成（上面手工 101），跳过 tungstenite 握手直接包裸流
    Ok(WebSocketStream::from_raw_socket(stream, Role::Server, None).await)
}

/// WS 升级三道校验：Host 回环（防 DNS rebinding 套取 token）→ Origin 同源
/// （浏览器跨源页面不得连 WS；空 Origin = 非浏览器客户端/本机文件，放行）→
/// token 查询参数（进程一次性 token，经 /config.json 下发；前端拼 ?token=）。
/// 逃生口：`PRPING_WEB_INSECURE=1` 仅跳过 token 校验（本地脚本/测试用）。
pub(crate) fn authorize(head: &RequestHead, token: &str) -> Result<(), String> {
    if !head.host_is_loopback() {
        return Err("host is not loopback".into());
    }
    if let Some(origin) = head.header("origin") {
        // Origin: scheme://host[:port]/path → 取 authority 与 Host 头比对
        let authority = origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(origin);
        let authority = authority.split('/').next().unwrap_or(authority);
        let same = head
            .header("host")
            .is_some_and(|host| authority.eq_ignore_ascii_case(host));
        if !same {
            return Err("cross-origin websocket".into());
        }
    }
    if std::env::var("PRPING_WEB_INSECURE").as_deref() != Ok("1") {
        match head.query_param("token") {
            Some(got) if got == token => {}
            _ => return Err("missing or invalid token".into()),
        }
    }
    Ok(())
}

/// 会话主体：读任务（WS→分派）+ 转发任务（LSP 帧→信封）+ 回推循环（信封→WS）。
/// `libs` 为 `--lib` 附加目录（与 engine/packet 同语义；默认 lib/ 目录在分析/列库函数
/// 内部合并）；`default_ws` 为本连接的初始工作区根（examples 发现结果，可被
/// workspace 信封按连接切换）。
pub(crate) async fn session(
    ws: WebSocketStream<TcpStream>,
    libs: Vec<PathBuf>,
    default_ws: Option<PathBuf>,
) {
    let (mut sink, mut source) = ws.split();
    let (in_tx, in_rx) = unbounded::<Vec<u8>>();
    let (out_tx, out_rx) = unbounded::<Vec<u8>>();
    // 回推通道 bounded：慢客户端（后台标签页/卡死）时背压传导——LSP 写端与
    // run 输出排水线程阻塞而非内存无限积压（run_out 行级丢弃由 run.rs 行预算负责）
    let (reply_tx, reply_rx) = bounded::<Value>(512);
    let sess = Arc::new(Session {
        libs: libs.clone(),
        root: Mutex::new(default_ws),
        active: Arc::new(Mutex::new(Vec::new())),
        run_seq: AtomicU64::new(0),
    });

    // LSP 会话：阻塞 run_lsp_on 放线程池；EOF/退出由管道两端 drop 传导
    let lsp = {
        let lsp_libs = libs.clone();
        smol::spawn(smol::unblock(move || {
            let reader = ChanReader::new(in_rx);
            let writer = ChanWriter::new(out_tx);
            // catch_unwind：LSP 处理器内部 panic 时优雅收尾（发送端 drop →
            // 转发任务 EOF → WS 关闭 → 前端重连），不让未捕获 panic 上抛
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::run_lsp_on(reader, writer, &lsp_libs)
            }));
            let mut w = crate::output::stderr();
            match result {
                Ok(Err(e)) => {
                    let _ = crate::output::writeln_orange(&mut w, format!("lsp session: {e}"));
                }
                Err(_) => {
                    let _ = crate::output::writeln_orange(&mut w, "lsp session: internal panic");
                }
                Ok(Ok(_)) => {}
            }
        }))
    };

    // LSP 输出字节流 → Content-Length 分帧解包 → 信封频道
    let fwd = {
        let reply_tx = reply_tx.clone();
        smol::spawn(async move {
            let mut dec = FrameDecoder::default();
            while let Ok(chunk) = out_rx.recv().await {
                for msg in dec.push(&chunk) {
                    let _ = reply_tx
                        .send(json!({ "type": "lsp", "message": msg }))
                        .await;
                }
            }
        })
    };

    // WS 读 → 信封分派（客户端断开时本任务结束，in_tx drop → LSP EOF）。
    // 断开时显式收杀活跃运行：run 的读流/waiter 任务持有 reply_tx 克隆，
    // 回推通道不会因此关闭，poller 的 is_closed 兜底探测不到——必须显式 kill
    let reader = {
        let reply_tx = reply_tx.clone();
        let sess = sess.clone();
        smol::spawn(async move {
            while let Some(Ok(msg)) = source.next().await {
                let text = match msg {
                    Message::Text(s) => s.to_string(),
                    Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                dispatch(&text, &in_tx, &reply_tx, &sess).await;
            }
            run::stop(&sess.active, None);
        })
    };
    // reply_tx 的最后持有者是上面两个任务——主动释放手中副本，客户端断开时
    // 回推通道随之关闭，主循环自然收尾
    drop(reply_tx);

    // 信封 → WS；两端发送任务都结束后通道关闭，会话收尾。
    // 空闲期每 30s 发一个 WS ping：防代理/NAT 半开连接挂着 listen 型 run。
    let mut ping = std::pin::pin!(smol::Timer::interval(std::time::Duration::from_secs(30)));
    enum Step {
        Reply(Value),
        Ping,
    }
    loop {
        let step = smol::future::or(
            async { reply_rx.recv().await.ok().map(Step::Reply) },
            async {
                let _ = ping.as_mut().await;
                Some(Step::Ping)
            },
        )
        .await;
        let msg = match step {
            Some(Step::Reply(reply)) => Message::text(reply.to_string()),
            Some(Step::Ping) => Message::Ping(Bytes::new()),
            None => break, // 回推通道关闭（两端任务已结束）
        };
        if sink.send(msg).await.is_err() {
            break;
        }
    }
    // 会话收尾兜底：无论经哪条路径退出（含 sink 失败），都不留运行中的子进程
    run::stop(&sess.active, None);
    reader.cancel().await;
    fwd.cancel().await;
    lsp.cancel().await;
}

/// 统一错误信封：error 人类文案 + 机器可读 code（前端按码分支，不必比对文案）。
fn err_reply(id: Option<Value>, code: &str, error: impl std::fmt::Display) -> Value {
    json!({ "type": "result", "id": id, "ok": false, "code": code, "error": error.to_string() })
}

/// 单连接会话状态：库目录（服务级共享）+ 工作区根（每连接独立，workspace 信封可切换）
/// + 活跃 packet 运行槽（每连接最多一个，run/run_stop 信封操作）。
struct Session {
    libs: Vec<PathBuf>,
    root: Mutex<Option<PathBuf>>,
    active: Arc<run::RunSlot>,
    run_seq: run::RunSeq,
}

/// 当前工作区根快照（Mutex 中毒按 None 处理——会话级状态，不值得传播 panic）。
fn root_of(sess: &Session) -> Option<PathBuf> {
    sess.root.lock().ok().and_then(|g| g.clone())
}

/// 信封分派：lsp 透传 / analyze / list / read / tree / save / delete / rename /
/// mkdir / workspace / browse / run / run_stop。
/// 目录树、文件读写、目录浏览、运行文件解析走 `smol::unblock`（磁盘操作不阻塞
/// 异步循环）。
async fn dispatch(
    text: &str,
    in_tx: &Sender<Vec<u8>>,
    reply_tx: &Sender<Value>,
    sess: &Arc<Session>,
) {
    let Ok(env) = serde_json::from_str::<Value>(text) else {
        let _ = reply_tx
            .send(json!({ "type": "error", "code": code::INVALID_ENVELOPE, "message": "invalid envelope" }))
            .await;
        return;
    };
    let id = env.get("id").cloned();
    match env.get("type").and_then(Value::as_str) {
        Some("lsp") => {
            // message 重新序列化成标准 JSON-RPC 帧（不信任客户端预分帧）
            let body = env
                .get("message")
                .cloned()
                .unwrap_or(Value::Null)
                .to_string();
            let frame = format!("Content-Length: {}\r\n\r\n{}", body.len(), body);
            let _ = in_tx.send(frame.into_bytes()).await;
        }
        Some("analyze") => {
            let uri = env
                .get("uri")
                .and_then(Value::as_str)
                .unwrap_or("file:///untitled.pkt")
                .to_string();
            let text = env
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let params = params_of(env.get("params"));
            let libs = sess.libs.clone();
            let tx = reply_tx.clone();
            smol::spawn(async move {
                // .pktl 配方文档：配方概览（globals / params / steps）——
                // .pkt 解析器不认配方语法
                let reply = if uri
                    .strip_prefix("file://")
                    .is_some_and(|p| p.ends_with(".pktl"))
                {
                    let display =
                        PathBuf::from(uri.strip_prefix("file://").unwrap_or("recipe.pktl"));
                    match crate::engine::recipe::parse_text(&text, &display) {
                        Ok(r) => {
                            json!({ "type": "result", "id": id, "ok": true, "data": recipe_overview(&r) })
                        }
                        Err(e) => err_reply(id, code_of(&e), e),
                    }
                } else {
                    smol::unblock(move || {
                        // 声明的运行参数（词法收集）随成功/失败都返回：构建失败时
                        // 面板仍能渲染参数输入行（LSP 诊断不含参数缺失这类错误）
                        let decl = crate::engine::eng::collect_src_params(&text).unwrap_or_default();
                        match crate::analyze_text_json(&uri, &text, &params, &libs) {
                            Ok(mut doc) => {
                                if let Some(obj) = doc.as_object_mut() {
                                    obj.insert("params".into(), params_decl_json(&decl));
                                }
                                json!({ "type": "result", "id": id, "ok": true, "data": doc })
                            }
                            Err(e) => json!({
                                "type": "result",
                                "id": id,
                                "ok": false,
                                "error": e.to_string(),
                                "data": { "params": params_decl_json(&decl) },
                            }),
                        }
                    })
                    .await
                };
                let _ = tx.send(reply).await;
            })
            .detach();
        }
        Some("list") => {
            let _ = reply_tx
                .send(json!({
                    "type": "result", "id": id, "ok": true,
                    "data": { "files": lib_file_names(&sess.libs), "dirs": lib_dirs(&sess.libs) },
                }))
                .await;
        }
        Some("read") => {
            let name = env.get("name").and_then(Value::as_str).unwrap_or("");
            // root="ws" 读工作区（可写）；缺省读库文件（只读，兼容旧客户端）
            if env.get("root").and_then(Value::as_str) == Some("ws") {
                match root_of(sess) {
                    Some(root) => {
                        let name = name.to_string();
                        let tx = reply_tx.clone();
                        smol::spawn(async move {
                            let reply =
                                match smol::unblock(move || workspace::read_file(&root, &name))
                                    .await
                                {
                                    Ok(text) => json!({ "type": "result", "id": id, "ok": true,
                                    "data": { "text": text, "writable": true } }),
                                    Err(e) => err_reply(id, code_of(&e), e),
                                };
                            let _ = tx.send(reply).await;
                        })
                        .detach();
                    }
                    None => {
                        let _ = reply_tx
                            .send(err_reply(id, code::NOT_FOUND, t!("web.ws_not_found")))
                            .await;
                    }
                }
                return;
            }
            let reply = match read_lib_file(Path::new(name), &sess.libs) {
                Ok(text) => {
                    json!({ "type": "result", "id": id, "ok": true,
                        "data": { "text": text, "writable": false } })
                }
                Err(e) => err_reply(id, code_of(&e), e),
            };
            let _ = reply_tx.send(reply).await;
        }
        Some("tree") => {
            let root = root_of(sess);
            let tx = reply_tx.clone();
            smol::spawn(async move {
                let data = match &root {
                    Some(r) => {
                        let dir = r.clone();
                        let entries = smol::unblock(move || workspace::tree(&dir)).await;
                        json!({
                            "root": r.display().to_string(),
                            "writable": true,
                            "entries": entries
                                .iter()
                                .map(|e| json!({ "path": e.path, "dir": e.dir, "pkt": e.pkt }))
                                .collect::<Vec<_>>(),
                        })
                    }
                    // 无工作区：空树 + 不可写（前端给打开文件夹提示）
                    None => json!({ "root": Value::Null, "writable": false, "entries": [] }),
                };
                let _ = tx
                    .send(json!({ "type": "result", "id": id, "ok": true, "data": data }))
                    .await;
            })
            .detach();
        }
        Some("save") | Some("delete") => {
            let name = env
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let text = env
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let is_save = env.get("type").and_then(Value::as_str) == Some("save");
            let root = root_of(sess);
            let tx = reply_tx.clone();
            smol::spawn(async move {
                let reply = match root {
                    Some(root) => {
                        let res = if is_save {
                            smol::unblock(move || workspace::save_file(&root, &name, &text)).await
                        } else {
                            smol::unblock(move || workspace::delete_entry(&root, &name)).await
                        };
                        match res {
                            Ok(()) => json!({ "type": "result", "id": id, "ok": true, "data": {} }),
                            Err(e) => err_reply(id, code_of(&e), e),
                        }
                    }
                    None => json!({ "type": "result", "id": id, "ok": false,
                        "error": t!("web.ws_not_found").to_string() }),
                };
                let _ = tx.send(reply).await;
            })
            .detach();
        }
        Some("rename") => {
            let from = env
                .get("from")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let to = env
                .get("to")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let root = root_of(sess);
            let tx = reply_tx.clone();
            smol::spawn(async move {
                let reply = match root {
                    Some(root) => {
                        let res =
                            smol::unblock(move || workspace::rename_entry(&root, &from, &to)).await;
                        match res {
                            Ok(()) => json!({ "type": "result", "id": id, "ok": true, "data": {} }),
                            Err(e) => err_reply(id, code_of(&e), e),
                        }
                    }
                    None => json!({ "type": "result", "id": id, "ok": false,
                        "error": t!("web.ws_not_found").to_string() }),
                };
                let _ = tx.send(reply).await;
            })
            .detach();
        }
        Some("mkdir") => {
            let name = env
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let root = root_of(sess);
            let tx = reply_tx.clone();
            smol::spawn(async move {
                let reply = match root {
                    Some(root) => {
                        match smol::unblock(move || workspace::mkdirs(&root, &name)).await {
                            Ok(dir) => json!({ "type": "result", "id": id, "ok": true,
                            "data": { "path": dir.display().to_string() } }),
                            Err(e) => err_reply(id, code_of(&e), e),
                        }
                    }
                    None => json!({ "type": "result", "id": id, "ok": false,
                        "error": t!("web.ws_not_found").to_string() }),
                };
                let _ = tx.send(reply).await;
            })
            .detach();
        }
        Some("workspace") => {
            match env.get("path").and_then(Value::as_str) {
                // 带 path：打开自定义文件夹（工作区根仅影响本连接）
                Some(p) if !p.is_empty() => {
                    let reply = match workspace::open_folder(p) {
                        Ok(canon) => {
                            if let Ok(mut g) = sess.root.lock() {
                                *g = Some(canon.clone());
                            }
                            json!({ "type": "result", "id": id, "ok": true,
                                "data": { "root": canon.display().to_string() } })
                        }
                        Err(e) => err_reply(id, code_of(&e), e),
                    };
                    let _ = reply_tx.send(reply).await;
                }
                // 空 path：重置为默认工作区（examples）
                Some(_) => {
                    let def = workspace::default_workspace();
                    if let Ok(mut g) = sess.root.lock() {
                        *g = def.clone();
                    }
                    let _ = reply_tx
                        .send(json!({ "type": "result", "id": id, "ok": true,
                            "data": { "root": def.map(|d| d.display().to_string()) } }))
                        .await;
                }
                // 无 path：查询当前工作区
                None => {
                    let _ = reply_tx
                        .send(json!({ "type": "result", "id": id, "ok": true,
                            "data": { "root": root_of(sess).map(|d| d.display().to_string()) } }))
                        .await;
                }
            }
        }
        Some("browse") => {
            // 文件夹选择对话框数据源：列子目录（仅目录、跳隐藏、上限截断）；
            // path 缺省 = 用户主目录。选择结果仍走 workspace path 信封确认。
            let path = env.get("path").and_then(Value::as_str).map(str::to_string);
            let tx = reply_tx.clone();
            smol::spawn(async move {
                let reply = match smol::unblock(move || workspace::browse(path.as_deref())).await {
                    Ok((cur, parent, dirs)) => json!({ "type": "result", "id": id, "ok": true,
                        "data": {
                            "path": cur.display().to_string(),
                            "parent": parent.map(|p| p.display().to_string()),
                            "dirs": dirs,
                        } }),
                    Err(e) => err_reply(id, code_of(&e), e),
                };
                let _ = tx.send(reply).await;
            })
            .detach();
        }
        Some("run") => {
            // 运行工作区 .pkt/.pktl：spawn 自身二进制 packet 子命令（run.rs 桥）。
            // 文件解析是磁盘操作 → unblock；成功即回 ack（run_id），后续输出与
            // 退出经 run_out / run_exit 信封异步推送（不受请求-应答 id 关联约束）
            let Some(root) = root_of(sess) else {
                let _ = reply_tx
                    .send(json!({ "type": "result", "id": id, "ok": false,
                        "error": t!("web.ws_not_found").to_string() }))
                    .await;
                return;
            };
            let libs = sess.libs.clone();
            let sess = sess.clone();
            let ack_tx = reply_tx.clone();
            let stream_tx = reply_tx.clone();
            smol::spawn(async move {
                let started = smol::unblock(move || {
                    run::spec_from_envelope(&env, &root, libs)
                        .and_then(|spec| run::start(spec, stream_tx, &sess.active, &sess.run_seq))
                })
                .await;
                let reply = match started {
                    Ok(run_id) => {
                        json!({ "type": "result", "id": id, "ok": true, "data": { "run": run_id } })
                    }
                    Err(e) => err_reply(id, code_of(&e), e),
                };
                let _ = ack_tx.send(reply).await;
            })
            .detach();
        }
        Some("run_stop") => {
            // 停止活跃运行：带 "run" id 停单个（任务管理），缺省停本连接全部；
            // kill 后 waiter 收尸推 run_exit
            let target = env.get("run").and_then(Value::as_str);
            let stopped = run::stop(&sess.active, target);
            let _ = reply_tx
                .send(json!({ "type": "result", "id": id, "ok": true,
                    "data": { "stopped": stopped } }))
                .await;
        }
        _ => {
            let _ = reply_tx
                .send(json!({ "type": "error", "id": id, "message": "unknown envelope type" }))
                .await;
        }
    }
}

/// .pktl 配方概览 JSON（前端 Recipe/Globals 面板数据）：globals、steps（含
/// extract 与 params）、扁平化的 params 键值表。
fn recipe_overview(r: &crate::engine::recipe::Recipe) -> Value {
    use crate::engine::eng::value_display;
    use crate::engine::pkg::WaitMode;
    use crate::engine::recipe::{FromSpec, OnError, OnTimeout, StepRaw};

    let mut params: Vec<Value> = Vec::new();
    let steps: Vec<Value> = r
        .steps
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            for (k, v) in &s.params {
                params.push(json!({ "key": k, "value": v, "step": idx + 1 }));
            }
            let wait = match s.wait {
                None | Some(WaitMode::Off) => Value::Null,
                Some(WaitMode::OneShot(secs)) => json!(format!("{secs}s")),
                Some(WaitMode::Continuous) => json!("∞"),
            };
            let on_timeout = match &s.on_timeout {
                None => Value::Null,
                Some(OnTimeout::Retry(n)) => json!(format!("retry×{n}")),
                Some(OnTimeout::Packet(p)) => {
                    json!(
                        p.file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_else(|| p.display().to_string())
                    )
                }
            };
            let raw = match &s.raw {
                None => Value::Null,
                Some(StepRaw::On { iface }) => match iface {
                    Some(name) => json!(name),
                    None => json!("true"),
                },
                Some(StepRaw::Off) => json!("false"),
            };
            let extract: Vec<Value> = s
                .extract
                .iter()
                .map(|e| {
                    let from = match &e.from {
                        FromSpec::Field { layer, field } => format!("reply.{layer}.{field}"),
                        FromSpec::SentField { layer, field } => format!("sent.{layer}.{field}"),
                        FromSpec::PeerField { field } => format!("reply.peer.{field}"),
                        FromSpec::Expr(v) => value_display(v),
                    };
                    json!({
                        "name": e.name,
                        "from": from,
                        "as": format!("{:?}", e.as_).to_lowercase(),
                    })
                })
                .collect();
            json!({
                "idx": idx + 1,
                "pkg": s
                    .pkg
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| s.pkg.display().to_string()),
                // 解析后的完整路径：前端 Recipe 面板点包名跳转用（pkg 只是展示名）
                "pkgPath": s.pkg.display().to_string(),
                "line": s.line,
                "wait": wait,
                "onTimeout": on_timeout,
                "raw": raw,
                "onError": match s.on_error {
                    OnError::Stop => "stop",
                    OnError::Continue => "continue",
                },
                "extract": extract,
            })
        })
        .collect();
    let globals: Vec<Value> = r
        .globals
        .iter()
        .map(|g| {
            json!({
                "name": g.name,
                "init": g.init.as_ref().map(value_display),
                "line": g.line,
            })
        })
        .collect();
    json!({ "globals": globals, "params": params, "steps": steps })
}

/// `params` 对象 → (k, v) 列表（非对象 → 空）。
fn params_of(v: Option<&Value>) -> Vec<(String, String)> {
    v.and_then(Value::as_object)
        .map(|m: &Map<String, Value>| {
            m.iter()
                .map(|(k, v)| {
                    let val = match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    (k.clone(), val)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 声明的运行参数 → JSON（同名去重保首个；default 为 null = 必填）。
fn params_decl_json(decl: &[(String, Option<packet_dsl::ast::Value>)]) -> Value {
    use crate::engine::eng::value_display;
    let mut seen = std::collections::HashSet::new();
    json!(
        decl.iter()
            .filter(|(n, _)| seen.insert(n.clone()))
            .map(|(n, d)| json!({ "name": n, "default": d.as_ref().map(value_display) }))
            .collect::<Vec<_>>()
    )
}

/// 生效库目录（运行时 lib/ 发现 + `--lib` 附加；展示用）。
fn lib_dirs(libs: &[PathBuf]) -> Vec<String> {
    crate::engine::eng::effective_libs(libs)
        .iter()
        .map(|p| p.display().to_string())
        .collect()
}

/// 库文件名清单（跨目录按文件名去重，先到先得——与解析器的库搜索顺序一致）。
fn lib_file_names(libs: &[PathBuf]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for dir in crate::engine::eng::effective_libs(libs) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| {
                let ext = Path::new(n).extension().and_then(|x| x.to_str());
                matches!(ext, Some("pkt") | Some("pktl"))
            })
            .collect();
        names.sort();
        for n in names {
            if seen.insert(n.clone()) {
                out.push(n);
            }
        }
    }
    out
}

/// 读库文件（只读）：名字须是纯文件名（禁路径分隔/父目录），按库目录顺序查找。
fn read_lib_file(name: &Path, libs: &[PathBuf]) -> anyhow::Result<String> {
    let simple = name.file_name().is_some_and(|f| f == name);
    if name.as_os_str().is_empty() || !simple {
        anyhow::bail!(t!("web.read_bad_name"));
    }
    let file_name = name.file_name().expect("guard: checked above");
    for dir in crate::engine::eng::effective_libs(libs) {
        let path = dir.join(file_name);
        if path.is_file() {
            return std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!(t!("web.read_failed", err = e.to_string())));
        }
    }
    anyhow::bail!(t!("web.read_not_found", name = name.display().to_string()));
}

/// Content-Length 分帧增量解码器（LSP 输出 → JSON 消息）。
#[derive(Default)]
struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    /// 追加字节，返回解出的完整消息（残帧留在内部缓冲）。
    fn push(&mut self, chunk: &[u8]) -> Vec<Value> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(head_end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
            // owned：后续分支要 drain 缓冲，避免借用冲突
            let head = String::from_utf8_lossy(&self.buf[..head_end]).to_string();
            let Some(len) = head.lines().find_map(|l| {
                let v = l.strip_prefix("Content-Length:")?;
                v.trim().parse::<usize>().ok()
            }) else {
                // 无 Content-Length（畸形头）：丢弃已缓冲头部，防卡死
                self.buf.drain(..head_end + 4);
                continue;
            };
            if len > MAX_FRAME {
                // 超限帧长度不可信、无法可靠跳过：清空缓冲（上层会话随连接关闭重建）
                self.buf.clear();
                break;
            }
            let total = head_end + 4 + len;
            if self.buf.len() < total {
                break; // 残帧：等下一段
            }
            if let Ok(msg) = serde_json::from_slice::<Value>(&self.buf[head_end + 4..total]) {
                out.push(msg);
            }
            self.buf.drain(..total);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::http;

    /// authorize 测试共用一把锁：PRPING_WEB_INSECURE 是进程级环境变量，
    /// 并行测试下会互相踩（cargo test 默认多线程）。
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 构造升级请求头（http::parse 是纯函数，直接喂原始头部字节）。
    fn ws_head(target: &str, host: &str, origin: Option<&str>) -> RequestHead {
        let origin_line = origin
            .map(|o| format!("Origin: {o}\r\n"))
            .unwrap_or_default();
        let raw = format!(
            "GET {target} HTTP/1.1\r\nHost: {host}\r\n{origin_line}\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        http::parse(raw.as_bytes()).expect("head parses")
    }

    #[test]
    fn authorize_accepts_same_origin_with_token() {
        let _env = ENV_LOCK.lock().unwrap();
        let h = ws_head(
            "/ws?token=abc123",
            "127.0.0.1:8788",
            Some("http://127.0.0.1:8788"),
        );
        assert!(authorize(&h, "abc123").is_ok());
        // 空 Origin（非浏览器客户端/本机文件）放行
        let h = ws_head("/ws?token=abc123", "localhost:8788", None);
        assert!(authorize(&h, "abc123").is_ok());
    }

    #[test]
    fn authorize_rejects_cross_origin_and_bad_token_and_host() {
        let _env = ENV_LOCK.lock().unwrap();
        // 跨源 Origin：恶意页面无法连 WS
        let h = ws_head(
            "/ws?token=abc123",
            "127.0.0.1:8788",
            Some("http://evil.example"),
        );
        assert_eq!(
            authorize(&h, "abc123"),
            Err("cross-origin websocket".into())
        );
        // token 缺失 / 不匹配
        let h = ws_head("/ws", "127.0.0.1:8788", None);
        assert_eq!(
            authorize(&h, "abc123"),
            Err("missing or invalid token".into())
        );
        let h = ws_head("/ws?token=wrong", "127.0.0.1:8788", None);
        assert_eq!(
            authorize(&h, "abc123"),
            Err("missing or invalid token".into())
        );
        // Host 非回环（DNS rebinding 域名）
        let h = ws_head("/ws?token=abc123", "attacker.example:8788", None);
        assert_eq!(authorize(&h, "abc123"), Err("host is not loopback".into()));
    }

    #[test]
    fn authorize_insecure_escape_hatches_token_only() {
        let _env = ENV_LOCK.lock().unwrap();
        // 逃生口只跳过 token：Origin/Host 校验仍在
        // SAFETY：2024 edition env API 为 unsafe；ENV_LOCK 已串行化，无并发读取方
        unsafe { std::env::set_var("PRPING_WEB_INSECURE", "1") };
        let h = ws_head("/ws", "127.0.0.1:8788", None);
        assert!(authorize(&h, "abc123").is_ok());
        let h = ws_head("/ws", "127.0.0.1:8788", Some("http://evil.example"));
        assert!(authorize(&h, "abc123").is_err());
        unsafe { std::env::remove_var("PRPING_WEB_INSECURE") };
    }

    fn frame(msg: &Value) -> Vec<u8> {
        let body = msg.to_string();
        format!("Content-Length: {}\r\n\r\n{}", body.len(), body).into_bytes()
    }

    #[test]
    fn frame_decoder_whole_and_split() {
        let mut dec = FrameDecoder::default();
        let a = frame(&json!({ "id": 1 }));
        let b = frame(&json!({ "method": "x" }));
        // 两帧整体到
        assert_eq!(dec.push(&[a.clone(), b.clone()].concat()).len(), 2);
        // 拆碎到（单字节粒度）
        let mut dec = FrameDecoder::default();
        let all = [a, b].concat();
        let mut got = Vec::new();
        for c in &all {
            got.extend(dec.push(std::slice::from_ref(c)));
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[1]["method"], "x");
    }

    #[test]
    fn frame_decoder_garbage_does_not_hang() {
        let mut dec = FrameDecoder::default();
        // 无 Content-Length 的头：跳过不卡死
        assert!(dec.push(b"garbage\r\n\r\n").is_empty());
        // 后续合法帧仍可解出
        assert_eq!(dec.push(&frame(&json!({ "ok": true }))).len(), 1);
    }

    #[test]
    fn frame_decoder_oversize_dropped() {
        let mut dec = FrameDecoder::default();
        let body = vec![b' '; MAX_FRAME + 1];
        let raw = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
        // 头部足够解析出超限长度：整帧丢弃，不再消费
        assert!(dec.push(&raw).is_empty());
    }

    #[test]
    fn params_of_shapes() {
        let v = json!({ "ip": "127.0.0.1", "n": 3 });
        let p = params_of(Some(&v));
        assert_eq!(p.len(), 2);
        assert!(p.contains(&("ip".into(), "127.0.0.1".into())));
        assert_eq!(params_of(None), Vec::<(String, String)>::new());
    }

    #[test]
    fn lib_file_read_rejects_paths() {
        for bad in ["", "../x.pkt", "a/b.pkt", "a\\b.pkt", ".", ".."] {
            assert!(read_lib_file(Path::new(bad), &[]).is_err(), "{bad}");
        }
    }
}
