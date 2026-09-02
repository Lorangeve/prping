#!/usr/bin/env python3
"""bytes.pkt 真实 UI：滚动到 L73 注释行，Ctrl+Click mac / rand_mac，看落点。"""
import json
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_context(viewport={"width": 1600, "height": 900}).new_page()
    pg.goto("http://127.0.0.1:8788")
    pg.wait_for_selector(".tree-file", timeout=15000)
    pg.wait_for_timeout(600)
    pg.locator(".lib-file", has_text="bytes.pkt").first.click()
    pg.wait_for_timeout(1200)

    def info():
        return pg.evaluate("""() => {
          const gut = document.querySelector('.cm-activeLineGutter');
          const sel = window.getSelection();
          return {
            activeLine: gut ? gut.textContent.trim() : '',
            sel: sel ? sel.toString().slice(0, 30) : '',
            file: document.querySelector('.topbar .current-file')?.textContent?.trim() || '',
          };
        }""")

    def scroll_to_line(ln):
        pg.evaluate("""(ln) => {
          const sc = document.querySelector('.cm-scroller');
          const lineH = 21; // 13px * 1.6
          sc.scrollTop = Math.max(0, ln * lineH - 300);
        }""", ln)
        pg.wait_for_timeout(300)

    def click_ident(word, nth=0):
        pg.keyboard.down("Control")
        pg.wait_for_timeout(150)
        loc = pg.locator(".cm-ident", has_text=word)
        n = loc.count()
        if n == 0:
            pg.keyboard.up("Control")
            return "no spans"
        tgt = loc.nth(min(nth, n - 1))
        bb = tgt.bounding_box()
        pg.mouse.click(bb["x"] + bb["width"] / 2, bb["y"] + bb["height"] / 2)
        pg.keyboard.up("Control")
        pg.wait_for_timeout(1800)
        return f"clicked span#{min(nth, n-1)}/{n} text={tgt.text_content()}"

    # 注释行 L73（1-based）滚入视野
    scroll_to_line(73)
    pg.wait_for_timeout(200)
    # 确认行可见
    vis = pg.evaluate("() => [...document.querySelectorAll('.cm-line')].map(l => l.textContent.slice(0,30)).filter(t => t.includes('等宽直通') || t.includes('rand_mac')).slice(0,3)")
    print("visible lines:", vis)

    # 点注释里的 rand_mac（第一个 rand_mac span 就在 L73 注释里）
    print("[1] click rand_mac:", click_ident("rand_mac", 0), "->", info())
    # 点注释里的 mac（L73 里 mac 在 rand_mac 之前；has_text=mac 会同时匹配 rand_mac 的 span？——cm-ident 是整词 span，textContent 恰为 'mac' 或 'rand_mac'）
    scroll_to_line(73); pg.wait_for_timeout(200)
    print("[2] click mac:", click_ident("mac", 0), "->", info())
    # 定义行 rand_mac 名字
    scroll_to_line(74); pg.wait_for_timeout(200)
    print("[3] click func rand_mac 名字:", click_ident("rand_mac", 0), "->", info())
    # mac 调用处（L89 注释里没有调用；用 headers.pkt 的调用）
    pg.locator(".lib-file", has_text="headers.pkt").first.click()
    pg.wait_for_timeout(1200)
    scroll_to_line(53); pg.wait_for_timeout(300)
    print("[4] click headers mac(:", click_ident("mac", 0), "->", info())
    pg.screenshot(path="/mnt/mydata/mycoding/prping/.uiaudit/mac-click-final.png")
    b.close()
