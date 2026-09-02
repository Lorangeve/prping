#!/usr/bin/env python3
"""Agent D v2：真实 UI 复现 QA 的 go-to-definition 点击（Ctrl+Click）。

每次点击后把鼠标移开并 Escape 收起 hover tooltip，再读 fileMsg 横幅。
"""
import json, os
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8788"
OUT = os.path.dirname(os.path.abspath(__file__))
log = []
ws_frames = []

def note(*a):
    line = " ".join(str(x) for x in a)
    log.append(line)
    print(line, flush=True)

with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1600, "height": 900})
    page = ctx.new_page()
    page.on("pageerror", lambda e: note("PAGEERROR:", str(e)[:300]))
    def on_ws(ws):
        ws.on("framesent", lambda f: ws_frames.append(("SEND", f)))
        ws.on("framereceived", lambda f: ws_frames.append(("RECV", f)))
    page.on("websocket", on_ws)

    page.goto(BASE)
    page.wait_for_selector(".tree-file", timeout=15000)
    page.wait_for_timeout(800)

    page.locator(".tree-dir", has_text="bad_network").first.click()
    page.wait_for_timeout(300)
    page.locator(".tree-file", has_text="http_get.pkt").first.click()
    page.wait_for_timeout(1200)

    def dismiss():
        page.mouse.move(30, 500)   # 移出编辑器，tooltip 消失
        page.keyboard.press("Escape")
        page.wait_for_timeout(600)

    def msg_banner():
        try:
            return page.locator(".file-msg").first.inner_text(timeout=400).strip()
        except Exception:
            return "<no banner>"

    def ctrl_click(word, nth=0):
        loc = page.locator(".cm-ident", has_text=word).nth(nth)
        cnt = page.locator(".cm-ident", has_text=word).count()
        if cnt == 0:
            note(f"!! '{word}' 未被高亮标记")
            return
        loc.hover()
        page.wait_for_timeout(150)
        loc.click(modifiers=["Control"], force=True)
        page.wait_for_timeout(800)
        note(f"Ctrl+Click '{word}'(#{nth}) -> banner: {msg_banner()}")
        dismiss()

    # 1) 使用处 http_req（line4 use(...) 里的第二个标记）
    ctrl_click("http_req", nth=1)
    # 2) 库调用 http(
    ctrl_click("http", nth=0)
    # 3) 定义处 http_req（line3 行首第一个标记）
    ctrl_click("http_req", nth=0)

    # 4) 已知良好对照：.pktl 步骤文件名（跨文件）
    page.locator(".tree-file", has_text="bad_network.pktl").first.click()
    page.wait_for_timeout(900)
    ctrl_click("syn.pkt", nth=0)

    # 5) 跨文件 import 跳转对照：打开 syn.pkt 后点 ipv4（库 prelude）
    # （syn.pkt 里应有 ipv4 调用）
    lines = page.locator(".cm-line").all_inner_texts()
    note("syn.pkt lines:", [l for l in lines][:6])
    ctrl_click("ipv4", nth=0)

    for d, f in ws_frames:
        try:
            payload = json.loads(f)
        except Exception:
            continue
        m = payload.get("message") if isinstance(payload, dict) else None
        if d == "SEND" and isinstance(m, dict) and m.get("method") == "textDocument/definition":
            note("WS SEND def:", json.dumps(m.get("params", {}))[:160])
        if d == "RECV" and isinstance(m, dict) and "result" in m and isinstance(m.get("id"), int) and m["id"] >= 1:
            r = m.get("result")
            if isinstance(r, list) and r and isinstance(r[0], dict) and "uri" in r[0]:
                note("WS RECV def id=%s:" % m["id"], json.dumps(r[0])[:220])
            elif r is None and isinstance(m.get("id"), int):
                note("WS RECV null id=%s" % m["id"])

    page.screenshot(path=os.path.join(OUT, "agentD-jump2.png"))
    browser.close()

with open(os.path.join(OUT, "agentD-jump2.log"), "w") as fh:
    fh.write("\n".join(log))
