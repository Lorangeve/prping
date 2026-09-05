#!/usr/bin/env python3
"""爆破演示 · 本机 HTTP 登录靶场（仅限本机/授权环境教学使用）。

两个「故意不设防」的登录端点，供 examples/brute_http/ 下两个配方打：

  GET /login?user=..&password=..   表单查询串登录（form.pktl 的靶点）
  GET /admin                       Basic 认证（basic.pktl 的靶点）

正确凭据（演示用弱口令）：用户 admin / 口令 secret123

  - 命中 → 完整 HTTP/1.1 200 OK 响应
  - 未命中 → **不回包直接断开**（静默失败——客户端表现为 wait 超时）

为什么静默失败而不是回 401/403：prping 的 TCP 载荷模式读回的是裸响应字节，
引擎对裸响应的反解会把前 14 字节误认成以太网帧（ASCII 响应的第 13-14 字节
恰为 "\r\n" = 0x0d0a ≥ 0x0600，落在 ethertype 位置），http 层反解不出来，
配方的 extract 拿不到状态行——所以靶场用「命中才有响应」的形态，命中判定
退化为有无响应（✗ 超时 vs ✓ + 回包里可见的 200 OK）。
真实系统的爆破面在响应侧信道上更丰富（401/403 vs 200、响应时间差），见 README。

真实系统在连续失败时应有限速/锁定/告警——本靶场故意全都没有，
正是为了让配方输出里的 ✗/✓ 对比可见。

启动：python3 examples/brute_http/lab_server.py   （监听 127.0.0.1:8000）
"""
import base64
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

USER, PASS = "admin", "secret123"
OK_BODY = b"authenticated"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _ok(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(OK_BODY)))
        self.end_headers()
        self.wfile.write(OK_BODY)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/login":
            q = urllib.parse.parse_qs(url.query)
            ok = q.get("user", [""])[0] == USER and q.get("password", [""])[0] == PASS
        elif url.path == "/admin":
            want = "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()
            ok = self.headers.get("Authorization", "") == want
        else:
            ok = False
        if ok:
            self._ok()
        else:
            # 静默失败：不发响应直接断开（见模块 docstring 的原因说明）
            self.close_connection = True

    def log_message(self, *args):  # 安静模式：爆破演示的输出留给配方侧
        pass


if __name__ == "__main__":
    print("lab server on http://127.0.0.1:8000  (admin / secret123, silent on failure)")
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
