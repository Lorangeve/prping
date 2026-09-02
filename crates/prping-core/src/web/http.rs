//! 极简 HTTP/1.1 响应（仅 GET/HEAD，本机回环编辑器服务）。
//!
//! 只实现浏览器访问单页应用所需的最小子集：请求头读取（CRLFCRLF 截断）、
//! Content-Length 响应、keep-alive、ETag/304 协商（入口页与 /config.json）。
//! 不做 chunked/压缩/大文件流式——静态资源来自 rust-embed 内嵌（`web-embed`
//! feature）或 UI 目录（默认），键名逐段校验，天然免疫路径穿越（见 assets.rs）。
//! /config.json 为运行期动态 JSON（含一次性 WS 鉴权 token，web-embed 模式同样
//! 覆盖），并做 Host 回环校验——防 DNS rebinding 页面套取 token 后连 WS。

use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::TcpStream;

use super::assets;

/// 请求头大小上限（防异常客户端超大头部耗内存）。
const MAX_HEAD: usize = 64 * 1024;

/// 解析后的请求头（方法/路径/查询串/小写头列表）。
pub(crate) struct RequestHead {
    pub(crate) method: String,
    /// 目标路径（去 query/fragment；未解码——静态键精确匹配，无需 percent-decode）。
    pub(crate) path: String,
    /// 查询串（'?' 后、'#' 前；无则 None）——WS 升级 token 校验用。
    pub(crate) query: Option<String>,
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

    /// 取查询参数（首个 `key=value` 对；值为原文——token 为 hex 无需解码）。
    pub(crate) fn query_param(&self, key: &str) -> Option<String> {
        let q = self.query.as_deref()?;
        q.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == key).then(|| v.to_string())
        })
    }

    /// Host 头是否指向本机回环（127.0.0.1 / localhost / ::1，端口任意）。
    /// DNS rebinding 防护：rebinding 页面经攻击者域访问时 Host 为攻击者域。
    pub(crate) fn host_is_loopback(&self) -> bool {
        self.header("host").is_some_and(host_is_loopback)
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

/// Host 值 → 回环判定（独立函数便于单测；大小写不敏感）。
/// 剥端口：`[::1]:8799` 括号式 IPv6 / `host:port`；多冒号视为无括号 IPv6 字面量。
fn host_is_loopback(host: &str) -> bool {
    let host = host.trim();
    let bare = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((ip, _)) => ip,
            None => rest,
        }
    } else if host.matches(':').count() > 1 {
        host
    } else {
        host.split(':').next().unwrap_or(host)
    };
    bare.eq_ignore_ascii_case("localhost") || bare == "127.0.0.1" || bare == "::1"
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
pub(crate) fn parse(head: &[u8]) -> Option<RequestHead> {
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
    // 目标 = path[?query][#fragment]：fragment 剥离，query 保留（WS token 校验）
    let no_frag = target.split('#').next().unwrap_or(target);
    let (path, query) = match no_frag.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (no_frag.to_string(), None),
    };
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
        query,
        version_11: version == "HTTP/1.1",
        headers,
    })
}

/// 响应附加头（Cache-Control / ETag；None = 省略对应头）。
#[derive(Default)]
pub(crate) struct RespExtra<'a> {
    pub(crate) cache: Option<&'a str>,
    pub(crate) etag: Option<&'a str>,
}

/// 发送完整响应（headers + body；HEAD 只发头）。
pub(crate) async fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    extra: RespExtra<'_>,
    body: &[u8],
    keep_alive: bool,
    head_only: bool,
) -> std::io::Result<()> {
    let mut resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(c) = extra.cache {
        resp.push_str("Cache-Control: ");
        resp.push_str(c);
        resp.push_str("\r\n");
    }
    if let Some(tag) = extra.etag {
        resp.push_str("ETag: ");
        resp.push_str(tag);
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

/// ETag：内容弱哈希（`DefaultHasher` = 零键 SipHash-1-3，同二进制内确定、
/// 跨重启稳定）；仅用于本地 304 协商，不作完整性校验。
fn etag_of(body: &[u8]) -> String {
    use std::hash::{DefaultHasher, Hasher};
    let mut h = DefaultHasher::new();
    h.write(body);
    format!("\"{:016x}\"", h.finish())
}

/// If-None-Match 是否命中（仅精确匹配自身发出的强 ETag；`*`/列表形态不处理）。
fn if_none_match(head: &RequestHead, etag: &str) -> bool {
    head.header("if-none-match").is_some_and(|v| v == etag)
}

/// ETag 协商响应：If-None-Match 命中 → 304（空体、同缓存策略）；否则 200 带 ETag。
async fn respond_cached(
    stream: &mut TcpStream,
    head: &RequestHead,
    mime: &str,
    cache: &str,
    body: &[u8],
    keep: bool,
    is_head: bool,
) -> std::io::Result<()> {
    let etag = etag_of(body);
    let extra = RespExtra {
        cache: Some(cache),
        etag: Some(&etag),
    };
    if if_none_match(head, &etag) {
        return respond(stream, "304 Not Modified", mime, extra, b"", keep, is_head).await;
    }
    respond(stream, "200 OK", mime, extra, body, keep, is_head).await
}

/// 路由分发：`/config.json`（动态，含鉴权 token）→ 静态资源（内嵌 / UI 目录）
/// → 404（资源缺失时给提示）。
pub(crate) async fn dispatch(
    stream: &mut TcpStream,
    head: &RequestHead,
    token: &str,
) -> std::io::Result<()> {
    let keep = head.keep_alive();
    let is_head = head.method == "HEAD";
    if head.path == "/config.json" {
        // token 经此下发：Host 必须回环（防 rebinding 页面套取 token 后连 WS）
        if !head.host_is_loopback() {
            return respond(
                stream,
                "403 Forbidden",
                "text/plain; charset=utf-8",
                RespExtra::default(),
                b"non-loopback host\n",
                false,
                is_head,
            )
            .await;
        }
        let body = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "wsPath": "/ws",
            // 一次性 WS 鉴权 token：前端读取后拼 ?token= 完成 /ws 升级
            "token": token,
            // 内置原语名单：前端据此排除「跳不到任何定义」的调用名高亮
            "builtins": packet_dsl::builtin_docs().iter().map(|d| d.name).collect::<Vec<_>>(),
        })
        .to_string();
        return respond_cached(
            stream,
            head,
            "application/json",
            "no-cache",
            body.as_bytes(),
            keep,
            is_head,
        )
        .await;
    }
    if let Some((data, mime)) = assets::lookup(&head.path) {
        // vite 产物文件名带内容 hash：immutable 长缓存；index.html 入口不缓存
        // 但带 ETag 协商（304）；其余静态 assets 已 immutable 不动
        let cache = if head.path.starts_with("/assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        if matches!(head.path.as_str(), "/" | "/index.html") {
            return respond_cached(stream, head, &mime, cache, &data, keep, is_head).await;
        }
        return respond(
            stream,
            "200 OK",
            &mime,
            RespExtra {
                cache: Some(cache),
                etag: None,
            },
            &data,
            keep,
            is_head,
        )
        .await;
    }
    if head.path == "/" && assets::index_missing() {
        // 前端资源缺失（内嵌模式 = dist 未构建；UI 目录模式 = 未找到 UI 目录）：
        // 按模式给对应指引（比空 404 可诊断）
        return respond(
            stream,
            "503 Service Unavailable",
            "text/plain; charset=utf-8",
            RespExtra::default(),
            assets::missing_hint().as_bytes(),
            keep,
            is_head,
        )
        .await;
    }
    respond(
        stream,
        "404 Not Found",
        "text/plain; charset=utf-8",
        RespExtra::default(),
        b"not found\n",
        keep,
        is_head,
    )
    .await
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
    fn parse_preserves_query_and_strips_fragment() {
        let h = head_of("GET /ws?token=abc&x=1#frag HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(h.path, "/ws");
        assert_eq!(h.query.as_deref(), Some("token=abc&x=1"));
        assert_eq!(h.query_param("token").as_deref(), Some("abc"));
        assert_eq!(h.query_param("missing"), None);
        // 无查询串
        let h = head_of("GET / HTTP/1.1\r\n\r\n");
        assert_eq!(h.query, None);
        assert_eq!(h.query_param("token"), None);
    }

    #[test]
    fn host_loopback_detection() {
        for ok in [
            "127.0.0.1",
            "127.0.0.1:8799",
            "localhost",
            "LOCALHOST:80",
            "[::1]",
            "[::1]:8799",
            "::1",
        ] {
            assert!(host_is_loopback(ok), "{ok}");
        }
        for bad in [
            "evil.com",
            "evil.com:80",
            "127.0.0.2",
            "192.168.1.5:8799",
            "[::2]",
            "localhost.evil.com",
        ] {
            assert!(!host_is_loopback(bad), "{bad}");
        }
        // Host 头缺失 → 非回环
        let h = head_of("GET / HTTP/1.1\r\n\r\n");
        assert!(!h.host_is_loopback());
    }

    #[test]
    fn etag_stable_quoted_and_content_sensitive() {
        let a = etag_of(b"hello");
        assert_eq!(a, etag_of(b"hello"));
        assert_ne!(a, etag_of(b"world"));
        assert!(a.starts_with('"') && a.ends_with('"'));
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
