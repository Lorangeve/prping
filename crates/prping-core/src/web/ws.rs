//! WebSocket 会话：信封协议分派 + LSP 桥 + 内存文本分析 + 库文件只读浏览。
//!
//! 信封协议（JSON，一帧一信封）：
//!
//! ```text
//! client → server
//!   { "type": "lsp",     "message": {…JSON-RPC…} }     透传给 LSP 会话
//!   { "type": "analyze", "id": 1, "uri": "file:///x.pkt",
//!     "text": "…", "params": {"k":"v"} }               engine --json 同构分析
//!   { "type": "list",    "id": 2 }                       列库文件（.pkt/.pktl）
//!   { "type": "read",    "id": 3, "name": "net.pkt" }    读库文件（只读）
//! server → client
//!   { "type": "lsp", "message": {…publishDiagnostics/响应…} }
//!   { "type": "result", "id": 1, "ok": true, "data": … | "ok": false, "error": "…" }
//! ```
//!
//! LSP 桥：每个 WS 连接一个独立 LSP 会话——客户端消息按 Content-Length 分帧写入
//! 内存管道，阻塞线程跑现有 `run_lsp_on`（零改动复用 stdio 实现），输出帧解包成
//! 信封回推。连接断开 → 请求侧发送端 drop → LSP 读 EOF 退出 → 响应侧发送端 drop
//! → 回推通道关闭 → 会话任务结束（无泄漏）。

use std::path::{Path, PathBuf};

use async_tungstenite::WebSocketStream;
use async_tungstenite::tungstenite::handshake::derive_accept_key;
use async_tungstenite::tungstenite::protocol::{Message, Role};
use futures_util::StreamExt;
use rust_i18n::t;
use serde_json::{Map, Value, json};
use smol::channel::{Sender, unbounded};
use smol::io::AsyncWriteExt;
use smol::net::TcpStream;

use super::pipe::{ChanReader, ChanWriter};

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

/// 会话主体：读任务（WS→分派）+ 转发任务（LSP 帧→信封）+ 回推循环（信封→WS）。
/// `libs` 为 `--lib` 附加目录（与 engine/packet 同语义；烘焙库目录在分析/列库函数
/// 内部合并）。
pub(crate) async fn session(ws: WebSocketStream<TcpStream>, libs: Vec<PathBuf>) {
    let (mut sink, mut source) = ws.split();
    let (in_tx, in_rx) = unbounded::<Vec<u8>>();
    let (out_tx, out_rx) = unbounded::<Vec<u8>>();
    let (reply_tx, reply_rx) = unbounded::<Value>();

    // LSP 会话：阻塞 run_lsp_on 放线程池；EOF/退出由管道两端 drop 传导
    let lsp = {
        let lsp_libs = libs.clone();
        smol::spawn(smol::unblock(move || {
            let reader = ChanReader::new(in_rx);
            let writer = ChanWriter::new(out_tx);
            if let Err(e) = crate::run_lsp_on(reader, writer, &lsp_libs) {
                let mut w = crate::output::stderr();
                let _ = crate::output::writeln_orange(&mut w, format!("lsp session: {e}"));
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

    // WS 读 → 信封分派（客户端断开时本任务结束，in_tx drop → LSP EOF）
    let reader = {
        let reply_tx = reply_tx.clone();
        let libs = libs.clone();
        smol::spawn(async move {
            while let Some(Ok(msg)) = source.next().await {
                let text = match msg {
                    Message::Text(s) => s.to_string(),
                    Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                dispatch(&text, &in_tx, &reply_tx, &libs).await;
            }
        })
    };
    // reply_tx 的最后持有者是上面两个任务——主动释放手中副本，客户端断开时
    // 回推通道随之关闭，主循环自然收尾
    drop(reply_tx);

    // 信封 → WS；两端发送任务都结束后通道关闭，会话收尾
    while let Ok(reply) = reply_rx.recv().await {
        if sink.send(Message::text(reply.to_string())).await.is_err() {
            break;
        }
    }
    reader.cancel().await;
    fwd.cancel().await;
    lsp.cancel().await;
}

/// 信封分派：lsp 透传 / analyze / list / read。
async fn dispatch(text: &str, in_tx: &Sender<Vec<u8>>, reply_tx: &Sender<Value>, libs: &[PathBuf]) {
    let Ok(env) = serde_json::from_str::<Value>(text) else {
        let _ = reply_tx
            .send(json!({ "type": "error", "message": "invalid envelope" }))
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
            let libs = libs.to_vec();
            let tx = reply_tx.clone();
            smol::spawn(async move {
                let reply = match smol::unblock(move || {
                    crate::analyze_text_json(&uri, &text, &params, &libs)
                })
                .await
                {
                    Ok(doc) => json!({ "type": "result", "id": id, "ok": true, "data": doc }),
                    Err(e) => {
                        json!({ "type": "result", "id": id, "ok": false, "error": e.to_string() })
                    }
                };
                let _ = tx.send(reply).await;
            })
            .detach();
        }
        Some("list") => {
            let _ = reply_tx
                .send(json!({
                    "type": "result", "id": id, "ok": true,
                    "data": { "files": lib_file_names(libs), "dirs": lib_dirs(libs) },
                }))
                .await;
        }
        Some("read") => {
            let name = env.get("name").and_then(Value::as_str).unwrap_or("");
            let reply = match read_lib_file(Path::new(name), libs) {
                Ok(text) => {
                    json!({ "type": "result", "id": id, "ok": true, "data": { "text": text } })
                }
                Err(e) => {
                    json!({ "type": "result", "id": id, "ok": false, "error": e.to_string() })
                }
            };
            let _ = reply_tx.send(reply).await;
        }
        _ => {
            let _ = reply_tx
                .send(json!({ "type": "error", "id": id, "message": "unknown envelope type" }))
                .await;
        }
    }
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

/// 生效库目录（烘焙 eng_lib + `--lib` 附加；展示用）。
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
