#!/usr/bin/env python3
"""诊断纵向滚动：谁把 body/app 撑出了视口。"""
import json, os
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8788"

JS = """
() => {
  const de = document.documentElement;
  const info = {
    docScrollH: de.scrollHeight, docClientH: de.clientHeight,
    bodyScrollH: document.body.scrollHeight, bodyClientH: document.body.clientHeight,
    winH: window.innerHeight,
    bodyOverflowY: getComputedStyle(document.body).overflowY,
    htmlOverflowY: getComputedStyle(de).overflowY,
    appH: document.querySelector('.app')?.offsetHeight,
    mainH: document.querySelector('.main')?.offsetHeight,
  };
  // 找高度超过 .app 的后代（撑破者）
  const app = document.querySelector('.app');
  const appBottom = app ? app.getBoundingClientRect().bottom : 0;
  const culprits = [];
  for (const el of document.querySelectorAll('*')) {
    const r = el.getBoundingClientRect();
    if (r.bottom > appBottom + 2 && r.height > 40) {
      culprits.push({
        tag: el.tagName.toLowerCase(),
        cls: (el.className || '').toString().slice(0, 60),
        top: Math.round(r.top), bottom: Math.round(r.bottom), h: Math.round(r.height),
      });
    }
  }
  // 谁可滚（scrollHeight > clientHeight 的容器）
  const scrollers = [];
  for (const el of document.querySelectorAll('*')) {
    if (el.scrollHeight - el.clientHeight > 4 && el.clientHeight > 100) {
      const cs = getComputedStyle(el);
      if (['auto','scroll','hidden'].includes(cs.overflowY)) {
        scrollers.push({ cls: (el.className || '').toString().slice(0, 60), sh: el.scrollHeight, ch: el.clientHeight, oy: cs.overflowY });
      }
    }
  }
  return { info, culprits: culprits.slice(0, 20), scrollers: scrollers.slice(0, 20) };
}
"""

with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1600, "height": 900})
    page = ctx.new_page()
    page.goto(BASE)
    page.wait_for_selector(".tree-file", timeout=15000)
    page.wait_for_timeout(600)
    page.locator('.tree-file', has_text="README.md").first.click()
    page.wait_for_timeout(1200)
    res = page.evaluate(JS)
    print("== README.md @1600x900 ==")
    print(json.dumps(res, ensure_ascii=False, indent=1))
    page.screenshot(path=os.path.join(OUT, "md-vert-1600.png"), full_page=False)
    # 滚到底再截一张（看 body 是否可滚）
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
    page.wait_for_timeout(200)
    page.screenshot(path=os.path.join(OUT, "md-vert-scrolled.png"))
    ctx.close()
    browser.close()
