#!/usr/bin/env python3
"""Post-fix verification: token auth, responsive, run console, ws error surface."""
import json, os, time
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8788"
OUT = os.path.dirname(os.path.abspath(__file__))
res = {}

with sync_playwright() as p:
    browser = p.chromium.launch()

    # ── 1. token 拒绝：跨源 Origin 与无 token 的 WS 应被 403 ──
    import socket
    s = socket.create_connection(("127.0.0.1", 8788), timeout=5)
    s.sendall(b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:8788\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: http://evil.example\r\n\r\n")
    resp = s.recv(200).decode(errors="replace").splitlines()[0]
    s.close()
    res["ws_cross_origin_rejected"] = ("403" in resp or "400" in resp)
    res["ws_reject_line"] = resp

    s = socket.create_connection(("127.0.0.1", 8788), timeout=5)
    s.sendall(b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:8788\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    resp2 = s.recv(200).decode(errors="replace").splitlines()[0]
    s.close()
    res["ws_no_token_rejected"] = ("403" in resp2 or "400" in resp2)
    res["ws_notoken_line"] = resp2

    # ── 2. UI 正常加载 + config.json 带 token ──
    ctx = browser.new_context(viewport={"width": 1600, "height": 900})
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)[:200]))
    cfg = page.request.get(BASE + "/config.json").json()
    res["config_has_token"] = bool(cfg.get("token"))
    page.goto(BASE)
    page.wait_for_selector(".tree-file", timeout=15000)
    page.wait_for_timeout(1000)
    res["ws_connected_ui"] = page.locator("text=connected").count() > 0
    res["pageerrors_after_load"] = errors

    # ── 3. 打开文件 + Run（性能与 UX）──
    page.locator(".tree-dir", has_text="dns_flow").first.click()
    page.wait_for_timeout(300)
    page.locator(".tree-file", has_text="dns_flow.pktl").first.click()
    page.wait_for_timeout(1000)
    page.locator(".tab", has_text="Run").first.click()
    page.wait_for_timeout(200)
    page.locator(".run-go-btn").first.click()
    page.wait_for_timeout(2500)
    page.screenshot(path=os.path.join(OUT, "v-run.png"))
    res["run_console_lines"] = page.locator(".run-console > div").count()
    res["stop_all_exists"] = page.locator("button", has_text="Stop all").count() > 0
    chip_text = page.locator(".run-task-row").first.inner_text() if page.locator(".run-task-row").count() else ""
    res["run_chip_text"] = chip_text[:120]

    # ── 4. 侧栏折叠 + 响应式 ──
    toggle = page.locator(".side-toggle")
    res["side_toggle_exists"] = toggle.count() > 0
    if toggle.count():
        toggle.first.click()
        page.wait_for_timeout(200)
        res["side_hidden_class"] = page.evaluate("document.querySelector('.main').classList.contains('side-hidden')")
    page.set_viewport_size({"width": 800, "height": 600})
    page.wait_for_timeout(300)
    res["overflow_800"] = page.evaluate("document.documentElement.scrollWidth") - page.evaluate("document.documentElement.clientWidth")
    page.screenshot(path=os.path.join(OUT, "v-800.png"))
    page.set_viewport_size({"width": 1600, "height": 900})
    page.wait_for_timeout(300)
    # 800px 下 resize 处理器会自动隐藏侧栏；1600 恢复后确保展开再继续
    if page.evaluate("document.querySelector('.main').classList.contains('side-hidden')"):
        if toggle.count():
            toggle.first.click()
            page.wait_for_timeout(200)

    # ── 5. 编辑器未回归 ──
    page.locator(".tree-file", has_text="dns_query.pkt").first.click()
    page.wait_for_timeout(800)
    res["editor_opens"] = page.locator(".cm-content").count() > 0
    res["pageerrors_final"] = errors

    ctx.close()
    browser.close()

print(json.dumps(res, ensure_ascii=False, indent=1))
with open(os.path.join(OUT, "verify.json"), "w") as f:
    json.dump(res, f, indent=1, ensure_ascii=False)
