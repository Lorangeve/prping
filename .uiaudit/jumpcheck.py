#!/usr/bin/env python3
"""Spot check: Ctrl+Click goto-def on local binding + lib call in real UI."""
import json, os
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8788"
OUT = os.path.dirname(os.path.abspath(__file__))
res = {}

with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1600, "height": 900})
    page = ctx.new_page()
    msgs = []
    page.on("console", lambda m: msgs.append(m.text[:100]) if m.type == "error" else None)
    page.goto(BASE)
    page.wait_for_selector(".tree-file", timeout=15000)
    page.wait_for_timeout(800)
    page.locator(".tree-dir", has_text="bad_network").first.click()
    page.wait_for_timeout(300)
    page.locator(".tree-file", has_text="http_get.pkt").first.click()
    page.wait_for_timeout(1500)  # didOpen + analyze

    # Ctrl+Click http_req 的使用处（第 5 行 http_req = http(...))
    editor = page.locator(".cm-content")
    box = editor.bounding_box()
    line_h = 20.6  # lineHeight 1.6 * 13px
    # http_req 出现在 "data_pkt = use(http_get_req)" 行 —— 用文本搜索定位更稳:
    # 直接对第 5 行 (0-based 4) 的 "http_req" 位置点击
    target_line, target_ch = 4, 13
    x = box["x"] + target_ch * 7.8 + 4
    y = box["y"] + target_line * line_h + 10
    page.keyboard.down("Control")
    page.mouse.click(x, y)
    page.keyboard.up("Control")
    page.wait_for_timeout(2500)
    body = page.locator("body").inner_text()
    res["no_def_msg"] = "no definition found" in body
    res["timeout_msg"] = "timed out" in body
    # 跳转成功的表现：当前文件标签仍为 http_get.pkt（本文件跳行）且选区存在
    res["active_file"] = page.locator(".topbar .current-file").inner_text()[:60]
    page.screenshot(path=os.path.join(OUT, "v-jump-local.png"))

    # 消息栏文案抓取（fileMsg 区域）
    res["pageerrors"] = msgs
    ctx.close()
    browser.close()

print(json.dumps(res, ensure_ascii=False, indent=1))
