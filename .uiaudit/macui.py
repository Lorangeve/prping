#!/usr/bin/env python3
"""真实 UI：bytes.pkt 里 Ctrl+Click mac / rand_mac / mac( 调用，看实际跳转落点。"""
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

    def active_file():
        try:
            return pg.locator(".topbar .current-file").inner_text(timeout=500)
        except Exception:
            return "?"

    def cursor_info():
        return pg.evaluate("""() => {
          const sel = window.getSelection();
          const cmLine = document.querySelector('.cm-activeLine');
          const gut = document.querySelector('.cm-activeLineGutter');
          return {
            selText: sel ? sel.toString().slice(0, 40) : '',
            activeLine: gut ? gut.textContent.trim() : (cmLine ? '?(no gutter)' : '?'),
          };
        }""")

    def ctrl_click_token(word, nth=0):
        pg.keyboard.down("Control")
        pg.wait_for_timeout(120)
        loc = pg.locator(".cm-ident", has_text=word)
        n = loc.count()
        if n == 0:
            pg.keyboard.up("Control")
            return f"(no .cm-ident '{word}')"
        tgt = loc.nth(min(nth, n - 1))
        tgt.scroll_into_view_if_needed()
        bb = tgt.bounding_box()
        pg.mouse.click(bb["x"] + bb["width"] / 2, bb["y"] + bb["height"] / 2)
        pg.keyboard.up("Control")
        pg.wait_for_timeout(1800)

    # 1) 注释 L73: mac(rand_mac()) —— 点 mac
    ctrl_click_token("rand_mac")  # 先随便触发一次高亮
    # 直接定位注释行里的 token：用 evaluate 找含文本的 span 更精确
    def click_span_at_line(line_text_substr, word, occurrence=0):
        return pg.evaluate("""([sub, word, occ]) => {
          const spans = [...document.querySelectorAll('.cm-line')].filter(l => l.textContent.includes(sub));
          const line = spans[0];
          if (!line) return 'line not found: ' + sub;
          const spansIn = [...line.querySelectorAll('.cm-ident')].filter(s => s.textContent === word);
          const s = spansIn[occ];
          if (!s) return 'span not found: ' + word + ' in ' + line.textContent.slice(0,40);
          const r = s.getBoundingClientRect();
          return { x: r.x + r.width / 2, y: r.y + r.height / 2, text: s.textContent };
        }""", [line_text_substr, word, occurrence])

    # 1) 注释里的 mac（L73）
    pos = click_span_at_line("等宽直通 → 直接", "mac")
    print("注释 mac span:", pos)
    if isinstance(pos, dict):
        pg.keyboard.down("Control"); pg.wait_for_timeout(100)
        pg.mouse.click(pos["x"], pos["y"])
        pg.keyboard.up("Control"); pg.wait_for_timeout(1800)
        print("点注释 mac ->", active_file(), cursor_info())

    # 2) 注释里的 rand_mac（L73）
    pos = click_span_at_line("等宽直通 → 直接", "rand_mac")
    print("注释 rand_mac span:", pos)
    if isinstance(pos, dict):
        pg.keyboard.down("Control"); pg.wait_for_timeout(100)
        pg.mouse.click(pos["x"], pos["y"])
        pg.keyboard.up("Control"); pg.wait_for_timeout(1800)
        print("点注释 rand_mac ->", active_file(), cursor_info())

    # 3) mac 定义行旁的调用处？——headers.pkt 里点 mac(
    pg.locator(".lib-file", has_text="headers.pkt").first.click()
    pg.wait_for_timeout(1200)
    pos = click_span_at_line("concat(mac(dst_mac)", "mac", 0)
    print("headers mac span:", pos)
    if isinstance(pos, dict):
        pg.keyboard.down("Control"); pg.wait_for_timeout(100)
        pg.mouse.click(pos["x"], pos["y"])
        pg.keyboard.up("Control"); pg.wait_for_timeout(1800)
        print("点 headers mac( ->", active_file(), cursor_info())
        pg.screenshot(path="/mnt/mydata/mycoding/prping/.uiaudit/mac-click-headers.png")

    b.close()
