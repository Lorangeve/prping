#!/usr/bin/env python3
"""bytes.pkt：Outline 面板点击 + hover 内容，检查 mac/rand_mac 是否串位。"""
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_context(viewport={"width": 1600, "height": 900}).new_page()
    pg.goto("http://127.0.0.1:8788")
    pg.wait_for_selector(".tree-file", timeout=15000)
    pg.wait_for_timeout(600)
    pg.locator(".lib-file", has_text="bytes.pkt").first.click()
    pg.wait_for_timeout(1500)

    def info():
        return pg.evaluate("""() => {
          const gut = document.querySelector('.cm-activeLineGutter');
          return { activeLine: gut ? gut.textContent.trim() : '',
                   file: document.querySelector('.topbar .current-file')?.textContent?.trim() || '' };
        }""")

    # ── Outline 面板 ──
    pg.locator(".tab", has_text="Outline").first.click()
    pg.wait_for_timeout(500)
    items = pg.locator(".outline-name, .outline-item")
    n = items.count()
    texts = [items.nth(i).text_content().strip() for i in range(n)]
    print("Outline items:", texts)

    def click_outline(word):
        loc = pg.locator(".outline-name, .outline-item", has_text=word)
        cnt = loc.count()
        for i in range(cnt):
            t = loc.nth(i).text_content().strip()
            if t == word:
                loc.nth(i).click()
                pg.wait_for_timeout(1200)
                return f"clicked '{t}' -> {info()}"
        return f"'{word}' not found exactly ({cnt} partial matches)"

    print("[outline] click mac:", click_outline("mac"))
    print("[outline] click rand_mac:", click_outline("rand_mac"))

    # ── hover ──
    pg.locator(".tab", has_text="Layers").first.click()
    pg.wait_for_timeout(300)
    # 切回编辑器：点击 Layers 后编辑器仍在；hover mac 定义名 L91
    pg.evaluate("() => { const sc = document.querySelector('.cm-scroller'); sc.scrollTop = 91 * 21 - 300; }")
    pg.wait_for_timeout(300)
    pg.keyboard.down("Control"); pg.wait_for_timeout(100)
    spans = pg.locator(".cm-ident", has_text="mac")
    cnt = spans.count()
    target = None
    for i in range(cnt):
        if spans.nth(i).text_content().strip() == "mac":
            target = spans.nth(i); break
    if target:
        bb = target.bounding_box()
        pg.mouse.move(bb["x"] + bb["width"] / 2, bb["y"] + bb["height"] / 2)
        pg.wait_for_timeout(2000)
        hover = pg.locator(".cm-tooltip")
        print("[hover] mac tooltip:", hover.first.inner_text()[:200] if hover.count() else "(none)")
    else:
        print("[hover] no mac span visible")
    pg.keyboard.up("Control")
    b.close()
