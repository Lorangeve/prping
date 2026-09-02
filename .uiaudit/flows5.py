#!/usr/bin/env python3
"""Round 5: force-click hover-revealed delete buttons; capture diagnostics data; cleanup."""
import traceback, os
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8788"
OUT = os.path.dirname(os.path.abspath(__file__))
results = []

def note(flow, ok, msg):
    results.append((flow, ok, msg))
    print(f"[{flow}] {ok}: {msg}", flush=True)

def shot(page, name):
    page.screenshot(path=os.path.join(OUT, name))

def delete_via_tree(page, path):
    row = page.locator(f'.tree-file[title="{path}"]')
    if row.count() == 0:
        return False
    row.first.hover()
    page.wait_for_timeout(250)
    btn = page.locator(f'button.tree-del[title="delete {path}"]').first
    btn.click(force=True)  # ✕ is opacity:0 until row hover
    page.wait_for_timeout(1100)
    return page.locator(f'.tree-file[title="{path}"]').count() == 0

def main():
    state = {"prompt_value": None}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1480, "height": 940})
        page = ctx.new_page()
        page.on("dialog", lambda d: d.accept(state["prompt_value"]) if (d.type == "prompt" and state["prompt_value"]) else d.accept())
        page.goto(BASE, wait_until="networkidle")
        page.wait_for_selector(".tree", timeout=10000)
        page.wait_for_timeout(600)

        # cleanup leftover from round 4
        try:
            gone1 = delete_via_tree(page, "_uiaudit_tmp.pkt")
            note("cleanup _uiaudit_tmp.pkt", "PASS" if gone1 else "FAIL", f"tree row gone: {gone1}")
        except Exception as e:
            note("cleanup tmp", "FAIL", f"{e.__class__.__name__}: {e}")

        # diagnostics on the broken file saved in round 4
        try:
            row = page.locator('.tree-file[title="_uiaudit_diag.pkt"]')
            if row.count() == 0:
                # recreate + save broken content
                state["prompt_value"] = "_uiaudit_diag.pkt"
                page.locator('button[title="new file"]').first.click()
                state["prompt_value"] = None
                page.wait_for_timeout(1200)
                page.locator(".cm-content").first.click()
                page.keyboard.type("tcp(flags=syn( )", delay=30)
                page.keyboard.press("Control+s"); page.wait_for_timeout(2200)
            else:
                row.first.click(); page.wait_for_timeout(1500)
            diag_tab = page.locator(".tab", has_text="Diagnostics").first
            badge = diag_tab.locator(".tab-badge").inner_text() if diag_tab.locator(".tab-badge").count() else "none"
            diag_tab.click(); page.wait_for_timeout(500)
            dtxt = page.locator(".panel-body").first.inner_text()[:400].replace("\n", " | ")
            shot(page, "extra-diag.png")
            note("6 DIAGNOSTICS broken file", "PASS" if badge not in ("none", "0") else "PARTIAL",
                 f"file 'tcp(flags=syn( )' -> Diagnostics badge='{badge}'; panel: {dtxt!r}")
            gone2 = delete_via_tree(page, "_uiaudit_diag.pkt")
            note("cleanup _uiaudit_diag.pkt", "PASS" if gone2 else "FAIL", f"tree row gone: {gone2}")
        except Exception as e:
            note("6 DIAGNOSTICS", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        browser.close()

if __name__ == "__main__":
    main()
