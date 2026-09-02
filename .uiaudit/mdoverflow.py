#!/usr/bin/env python3
"""诊断 markdown 视图滚动溢出：找出 scrollWidth > clientWidth 的元素链。"""
import json, os
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8788"
OUT = os.path.dirname(os.path.abspath(__file__))

JS = """
() => {
  const out = [];
  const vw = document.documentElement.clientWidth;
  for (const el of document.querySelectorAll('*')) {
    const cs = getComputedStyle(el);
    const canScroll = ['auto','scroll','hidden'].includes(cs.overflowX) || ['auto','scroll'].includes(cs.overflowY);
    const overX = el.scrollWidth - el.clientWidth;
    if (overX > 2 && el.clientWidth > 0) {
      out.push({
        tag: el.tagName.toLowerCase(),
        cls: (el.className && el.className.baseVal !== undefined ? el.className.baseVal : el.className || '').toString().slice(0, 60),
        scrollW: el.scrollWidth, clientW: el.clientWidth, over: overX,
        overflowX: cs.overflowX,
      });
    }
  }
  // 文档整体水平溢出
  const doc = { scrollW: document.documentElement.scrollWidth, clientW: vw };
  return { doc, offenders: out.slice(0, 40) };
}
"""

with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1600, "height": 900})
    page = ctx.new_page()
    page.goto(BASE)
    page.wait_for_selector(".tree-file", timeout=15000)
    page.wait_for_timeout(600)
    # 打开根目录 README.md（markdown 视图）
    page.locator('.tree-file', has_text="README.md").first.click()
    page.wait_for_timeout(1200)
    res1 = page.evaluate(JS)
    print("== README.md @1600 ==")
    print(json.dumps(res1, ensure_ascii=False, indent=1))
    page.screenshot(path=os.path.join(OUT, "md-1600.png"))

    # 窄视口复现
    page.set_viewport_size({"width": 1000, "height": 700})
    page.wait_for_timeout(400)
    res2 = page.evaluate(JS)
    print("== README.md @1000 ==")
    print(json.dumps(res2, ensure_ascii=False, indent=1))
    page.screenshot(path=os.path.join(OUT, "md-1000.png"))

    # 也看普通 .pkt 视图有没有同类问题
    page.locator(".tree-dir", has_text="bad_network").first.click()
    page.wait_for_timeout(300)
    page.locator(".tree-file", has_text="http_get.pkt").first.click()
    page.wait_for_timeout(1000)
    res3 = page.evaluate(JS)
    print("== http_get.pkt @1000 ==")
    print(json.dumps(res3, ensure_ascii=False, indent=1))
    ctx.close()
    browser.close()
