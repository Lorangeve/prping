//! 极简 HTTP/1.1 响应（仅 GET/HEAD，本机回环编辑器服务）。
//!
//! 只实现浏览器访问单页应用所需的最小子集：请求头读取（CRLFCRLF 截断）、
//! Content-Length 响应、keep-alive。不做 chunked/压缩/大文件流式——静态资源
//! 全部来自 rust-embed 内嵌（键名精确匹配，天然免疫路径穿越）。

use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::TcpStream;

use super::assets;

/// 请求头大小上限（防异常客户端超大头部耗内存）。
const MAX_HEAD: usize = 64 * 1024;

/// 解析后的请求头（方法/路径/小写头列表）。
pub(crate) struct RequestHead {
    pub(crate) method: String,
    /// 目标路径（去掉 query；未解码——静态键精确匹配，无需 percent-decode）。
    pub(crate) path: String,
    pub(crate) version_11: bool,
    headers: Vec<(String, String)>,
}

impl RequestHead {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// WebSocket 升级请求（`Upgrade: websocket` + `Connection: upgrade` + key）。
    pub(crate) fn wants_websocket(&self) -> bool {
        let upgrade = self
            .header("upgrade")
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
        let conn = self
            .header("connection")
            .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"));
        upgrade && conn
    }

    /// WS 握手密钥。
    pub(crate) fn ws_key(&self) -> Option<String> {
        self.header("sec-websocket-key").map(str::to_string)
    }

    /// HTTP/1.1 默认 keep-alive；显式 `Connection: close` 关闭。
    pub(crate) fn keep_alive(&self) -> bool {
        let conn = self
            .header("connection")
            .map(|v| v.to_ascii_lowercase())
            .unwrap_or_default();
        if conn.contains("close") {
            return false;
        }
        self.version_11
    }
}

/// 读取一个请求头（CRLFCRLF 结束）。连接干净关闭 → `Ok(None)`。
pub(crate) async fn read_head(stream: &mut TcpStream) -> std::io::Result<Option<RequestHead>> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(head_end) = find_head_end(&buf) {
            return Ok(parse(&buf[..head_end + 4]));
        }
        if buf.len() > MAX_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            // 半个头部即断开：当作连接关闭处理
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// 定位头部结束标记 `\r\n\r\n`，返回其起始偏移。
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 解析请求头；畸形输入返回 None（调用方按连接关闭处理）。
fn parse(head: &[u8]) -> Option<RequestHead> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let version = parts.next()?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return None;
    }
    let path = target.split(['?', '#']).next().unwrap_or("/").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Some(RequestHead {
        method,
        path,
        version_11: version == "HTTP/1.1",
        headers,
    })
}

/// 发送完整响应（headers + body；HEAD 只发头）。
pub(crate) async fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    cache: Option<&str>,
    body: &[u8],
    keep_alive: bool,
    head_only: bool,
) -> std::io::Result<()> {
    let mut resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(c) = cache {
        resp.push_str("Cache-Control: ");
        resp.push_str(c);
        resp.push_str("\r\n");
    }
    resp.push_str(if keep_alive {
        "Connection: keep-alive\r\n\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    stream.write_all(resp.as_bytes()).await?;
    if !head_only {
        stream.write_all(body).await?;
    }
    stream.flush().await
}

/// 路由分发：`/config.json`（动态）→ 内嵌静态资源 → 404（前端未构建时给构建提示）。
pub(crate) async fn dispatch(stream: &mut TcpStream, head: &RequestHead) -> std::io::Result<()> {
    let keep = head.keep_alive();
    let is_head = head.method == "HEAD";
    if head.path == "/config.json" {
        let body = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "wsPath": "/ws",
        })
        .to_string();
        return respond(
            stream,
            "200 OK",
            "application/json",
            Some("no-cache"),
            body.as_bytes(),
            keep,
            is_head,
        )
        .await;
    }
    if let Some((data, mime)) = assets::lookup(&head.path) {
        // vite 产物文件名带内容 hash：immutable 长缓存；index.html 入口不缓存
        let cache = if head.path.starts_with("/assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return respond(stream, "200 OK", &mime, Some(cache), &data, keep, is_head).await;
    }
    if head.path == "/" && assets::index_missing() {
        // 前端未构建：直接说明构建方式（比空 404 可诊断）
        return respond(
            stream,
            "503 Service Unavailable",
            "text/plain; charset=utf-8",
            Some("no-cache"),
            t_web_missing().as_bytes(),
            keep,
            is_head,
        )
        .await;
    }
    respond(
        stream,
        "404 Not Found",
        "text/plain; charset=utf-8",
        Some("no-cache"),
        b"not found\n",
        keep,
        is_head,
    )
    .await
}

/// 前端未构建提示（i18n）。
fn t_web_missing() -> String {
    rust_i18n::t!("web.frontend_missing").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head_of(raw: &str) -> RequestHead {
        parse(raw.as_bytes()).expect("parse")
    }

    #[test]
    fn parse_get_keep_alive() {
        let h = head_of("GET /assets/x.js?v=1 HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(h.method, "GET");
        assert_eq!(h.path, "/assets/x.js");
        assert!(h.version_11);
        assert!(h.keep_alive());
        // 头名已小写化，查找须传小写
        assert_eq!(h.header("host"), Some("a"));
    }

    #[test]
    fn parse_connection_close_and_http10() {
        let h = head_of("GET / HTTP/1.1\r\nConnection: close\r\n\r\n");
        assert!(!h.keep_alive());
        let h = head_of("GET / HTTP/1.0\r\n\r\n");
        assert!(!h.version_11);
        assert!(!h.keep_alive());
    }

    #[test]
    fn websocket_detection() {
        let h = head_of(
            "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        );
        assert!(h.wants_websocket());
        assert_eq!(h.ws_key().as_deref(), Some("dGhlIHNhbXBsZSBub25jZQ=="));
        // 非 upgrade / 缺 key
        let h = head_of("GET / HTTP/1.1\r\n\r\n");
        assert!(!h.wants_websocket());
        let h = head_of("GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n");
        assert!(!h.wants_websocket());
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse(b"not http").is_none());
        assert!(parse(b"GET / HTTP/9.9\r\n\r\n").is_none());
    }

    #[test]
    fn find_head_end_scans() {
        assert_eq!(find_head_end(b"ab\r\n\r\ncd"), Some(2));
        assert_eq!(find_head_end(b"ab\r\n\r"), None);
    }
}
