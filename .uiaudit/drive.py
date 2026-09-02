#!/usr/bin/env python3
"""Playwright exploration driver for prping web UI audit (screenshots + telemetry). v2"""
import json, os, time
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8788"
OUT = os.path.dirname(os.path.abspath(__file__))
report = {"console": [], "pageerrors": [], "requestfailures": [], "notes": [], "perf": {}, "a11y": {}, "ws": {}}

def shot(page, name):
    page.screenshot(path=os.path.join(OUT, name))
    report["notes"].append("shot " + name)

def click_tab(page, label, wait=350):
    page.locator(".tab", has_text=label).first.click()
    page.wait_for_timeout(wait)

with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1600, "height": 900})
    page = ctx.new_page()
    page.on("console", lambda m: report["console"].append({"type": m.type, "text": m.text[:400]}) if m.type in ("error", "warning") else None)
    page.on("pageerror", lambda e: report["pageerrors"].append(str(e)[:400]))
    page.on("requestfailed", lambda r: report["requestfailures"].append({"url": r.url, "failure": str(r.failure)}))
    def on_ws(ws):
        counters = {"sent": 0, "recv": 0}
        report["ws"]["url"] = ws.url
        ws.on("framesent", lambda f: counters.__setitem__("sent", counters["sent"] + 1))
        ws.on("framereceived", lambda f: counters.__setitem__("recv", counters["recv"] + 1))
        report["ws"]["frames"] = counters
    page.on("websocket", on_ws)

    t0 = time.time()
    page.goto(BASE)
    page.wait_for_selector(".tree-file", timeout=15000)
    report["perf"]["time_to_tree_ms"] = int((time.time() - t0) * 1000)
    page.wait_for_timeout(800)
    shot(page, "01-initial-1600x900.png")

    report["perf"]["resources"] = page.evaluate("() => performance.getEntriesByType('resource').map(r => ({name: r.name.split('/').pop(), ms: Math.round(r.duration), bytes: r.transferSize}))")
    report["perf"]["dom_nodes"] = page.evaluate("document.getElementsByTagName('*').length")

    # ── .pktl recipe flow ──────────────────────────────
    page.locator(".tree-dir", has_text="dns_flow").first.click()
    page.wait_for_timeout(300)
    page.locator(".tree-file", has_text="dns_flow.pktl").first.click()
    page.wait_for_timeout(1200)
    shot(page, "02-editor-pktl-recipe.png")

    for tab, name in [("Globals", "03-globals.png"), ("Diagnostics", "04-diagnostics-pktl.png"), ("Run", "05-run-panel.png")]:
        click_tab(page, tab)
        shot(page, name)

    # execute run then stop
    page.locator(".run-go-btn").first.click()
    page.wait_for_timeout(2500)
    shot(page, "06-run-executing.png")
    try:
        page.locator(".run-stop-btn").first.click(timeout=4000)
        report["notes"].append("run stopped via stop button")
    except Exception as e:
        report["notes"].append("stop click failed: %r" % e)
    page.wait_for_timeout(1500)
    shot(page, "07-run-after-stop.png")

    # hover tree ops + context menu
    page.locator(".tree-file", has_text="dns_query.pkt").first.hover()
    page.wait_for_timeout(250)
    shot(page, "08-tree-hover.png")
    page.locator(".tree-file", has_text="dns_query.pkt").first.click(button="right")
    page.wait_for_timeout(250)
    shot(page, "09-ctx-menu.png")
    page.keyboard.press("Escape")
    page.mouse.click(640, 500)

    # second file tab
    page.locator(".tree-file", has_text="dns_query.pkt").first.click()
    page.wait_for_timeout(900)
    shot(page, "10-two-tabs.png")

    # ── plain .pkt flow ────────────────────────────────
    page.locator(".tree-dir", has_text="bad_network").first.click()
    page.wait_for_timeout(300)
    page.locator(".tree-file", has_text="http_get.pkt").first.click()
    page.wait_for_timeout(900)
    shot(page, "11-pkt-default-view.png")
    for tab, name in [("Hex", "12-pkt-hex.png"), ("Outline", "13-pkt-outline.png"), ("Layers", "14-pkt-layers.png")]:
        try:
            click_tab(page, tab)
            shot(page, name)
        except Exception as e:
            report["notes"].append("tab %s failed: %r" % (tab, e))

    # eng_lib read-only browse
    page.locator(".lib-file", has_text="headers.pkt").first.click()
    page.wait_for_timeout(900)
    shot(page, "15-eng-lib.png")

    # a11y quick facts
    report["a11y"] = page.evaluate("""() => {
      const btns = [...document.querySelectorAll('button')];
      return {
        buttons: btns.length,
        iconOnlyButtons: btns.filter(b => !b.textContent.trim()).length,
        iconOnlyUnlabeled: btns.filter(b => !b.textContent.trim() && !b.getAttribute('title') && !b.getAttribute('aria-label')).length,
        unlabeledInputs: [...document.querySelectorAll('input,select')].filter(i => !i.labels || i.labels.length === 0).map(i => i.id || i.className).slice(0, 20),
        headings: [...document.querySelectorAll('h1,h2,h3,h4,h5')].length,
        htmlLang: document.documentElement.lang,
      };
    }""")

    # responsive checks
    for w, h, name in [(1920, 1080, "16-wide-1920.png"), (1024, 640, "17-narrow-1024.png"), (800, 600, "18-small-800.png")]:
        page.set_viewport_size({"width": w, "height": h})
        page.wait_for_timeout(350)
        shot(page, name)
    report["notes"].append("overflow@800: scrollW=%s clientW=%s" % (
        page.evaluate("document.documentElement.scrollWidth"),
        page.evaluate("document.documentElement.clientWidth")))

    browser.close()

with open(os.path.join(OUT, "report.json"), "w") as f:
    json.dump(report, f, indent=1, ensure_ascii=False)
print(json.dumps({k: report[k] for k in ("console", "pageerrors", "requestfailures", "perf", "a11y", "ws", "notes")}, ensure_ascii=False, indent=1))
