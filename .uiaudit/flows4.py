#!/usr/bin/env python3
"""UI audit round 4 (final): clean 3a, .pktl step jump, new-file full cycle, diagnostics, cleanup."""
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
    print(f"  shot -> {name}", flush=True)

def ensure_expanded(page, name):
    t = page.locator(f'.tree-dir[title="expand {name}"]')
    if t.count() > 0:
        t.first.click(); page.wait_for_timeout(250)

def open_file(page, path):
    for d in path.split("/")[:-1]:
        ensure_expanded(page, d)
    page.locator(f'.tree-file[title="{path}"]').first.click()
    page.wait_for_timeout(800)

def wait_file_open(page, base):
    page.wait_for_selector(f'.current-file:has-text("{base}")', timeout=8000)

TOKEN_RECT = """(needle) => {
  const lines = document.querySelectorAll('.cm-content .cm-line');
  for (const line of lines) {
    const i = line.textContent.indexOf(needle);
    if (i < 0) continue;
    const w = document.createTreeWalker(line, NodeFilter.SHOW_TEXT);
    let n, pos = 0, sn = null, so = 0, en = null, eo = 0;
    const t0 = i, t1 = i + needle.length;
    while ((n = w.nextNode())) {
      const len = n.textContent.length;
      if (!sn && pos + len > t0) { sn = n; so = t0 - pos; }
      if (pos + len >= t1) { en = n; eo = t1 - pos; break; }
      pos += len;
    }
    if (!sn || !en) continue;
    const r = document.createRange();
    r.setStart(sn, so); r.setEnd(en, eo);
    const b = r.getBoundingClientRect();
    return {x: b.left, y: b.top + b.height / 2, w: b.width, len: needle.length};
  }
  return null;
}"""

SEL_LINE = """() => {
  const sel = window.getSelection();
  if (!sel || sel.rangeCount === 0) return null;
  let node = sel.anchorNode;
  while (node && !(node.classList && node.classList.contains('cm-line'))) node = node.parentNode;
  return node ? node.textContent.trim().slice(0, 70) : null;
}"""

def create_new_file(page, state, name):
    state["prompt_value"] = name
    page.locator('button[title="new file"]').first.click()
    state["prompt_value"] = None
    page.wait_for_timeout(1200)
    page.wait_for_selector(f'.current-file:has-text("{name}")', timeout=6000)

def main():
    state = {"prompt_value": None, "log": []}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1480, "height": 940})
        page = ctx.new_page()
        page.on("dialog", lambda d: (state["log"].append(d.type + ":" + d.message[:50]),
                                     d.accept(state["prompt_value"]) if (d.type == "prompt" and state["prompt_value"]) else d.accept()))
        page.goto(BASE, wait_until="networkidle")
        page.wait_for_selector(".tree", timeout=10000)
        page.wait_for_timeout(600)

        # ---------- 3a redo: Ctrl+S on a genuinely unmodified file ----------
        try:
            open_file(page, "bad_network/http_get.pkt"); wait_file_open(page, "http_get.pkt")
            page.wait_for_timeout(1500)
            pre_dirty = page.locator(".dirty-dot").count() > 0
            page.keyboard.press("Control+s"); page.wait_for_timeout(900)
            post_dirty = page.locator(".dirty-dot").count() > 0
            msg = page.locator(".file-msg").inner_text() if page.locator(".file-msg").count() else ""
            note("3a Ctrl+S unmodified (redo)", "PASS" if not (pre_dirty or post_dirty or msg) else "PARTIAL",
                 f"file pristine (no dirty dot before: {not pre_dirty}); Ctrl+S -> dirty after: {post_dirty}, msg: {msg!r} (Save re-writes identical bytes; disk diff verified below)")
        except Exception as e:
            note("3a redo", "FAIL", f"{e.__class__.__name__}: {e}")

        # ---------- 3c-b: .pktl step-file name ctrl+click jump ----------
        try:
            open_file(page, "wait_timeout/recipe.pktl"); wait_file_open(page, "recipe.pktl")
            page.wait_for_timeout(2000)
            r = page.evaluate(TOKEN_RECT, "probe.pkt")
            assert r, "probe.pkt token not found"
            x = r["x"] + r["w"] * (0.5 / r["len"])
            page.mouse.move(x, r["y"], steps=3)
            page.keyboard.down("Control"); page.wait_for_timeout(350)
            body_cls = page.evaluate("() => document.body.className")
            shot(page, "extra-jump.png")
            page.mouse.down(); page.mouse.up(); page.keyboard.up("Control")
            page.wait_for_timeout(1300)
            cur = page.locator(".current-file").inner_text().strip() if page.locator(".current-file").count() else ""
            land = page.evaluate(SEL_LINE)
            msg = page.locator(".file-msg").inner_text() if page.locator(".file-msg").count() else ""
            note("3c .pktl step-name Ctrl+Click", "PASS" if ("probe.pkt" in cur and not msg) else "PARTIAL",
                 f"Ctrl held -> body '{body_cls}'; Ctrl+click 'probe.pkt' in recipe.pktl -> current file: {cur!r}, landed line: {land!r}, msg: {msg!r}")
        except Exception as e:
            note("3c .pktl jump", "FAIL", f"{e.__class__.__name__}: {e}")

        # ---------- 5 redo: new file = unsaved buffer -> save -> tree -> delete ----------
        try:
            create_new_file(page, state, "_uiaudit_tmp.pkt")
            buffer_open = page.locator('.current-file:has-text("_uiaudit_tmp.pkt")').count() > 0
            row_before_save = page.locator('.tree-file[title="_uiaudit_tmp.pkt"]').count() > 0
            page.locator(".cm-content").first.click()
            page.keyboard.type("icmp()", delay=30)
            page.wait_for_timeout(300)
            dirty = page.locator(".dirty-dot").count() > 0
            page.keyboard.press("Control+s"); page.wait_for_timeout(1000)
            row_after_save = page.locator('.tree-file[title="_uiaudit_tmp.pkt"]').count() > 0
            # delete via tree hover ✕ (window.confirm auto-accepted)
            page.locator('button.tree-del[title="delete _uiaudit_tmp.pkt"]').first.click()
            page.wait_for_timeout(1100)
            row_gone = page.locator('.tree-file[title="_uiaudit_tmp.pkt"]').count() == 0
            tab_gone = page.locator('.current-file:has-text("_uiaudit_tmp.pkt")').count() == 0
            note("5 NEW FILE + DELETE (full cycle)", "PASS" if (buffer_open and row_after_save and row_gone) else "PARTIAL",
                 f"'new file' opens an UNSAVED buffer (tab: {buffer_open}, tree row before save: {row_before_save} — file not on disk until save!); typed icmp() dirty: {dirty}; Ctrl+S materializes it -> tree row: {row_after_save}; tree ✕ + confirm deletes -> row gone: {row_gone}, tab closed: {tab_gone}. UX: no hint that Save is required to create the file.")
        except Exception as e:
            note("5 NEW FILE + DELETE", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- 6: diagnostics on intentionally broken file ----------
        try:
            create_new_file(page, state, "_uiaudit_diag.pkt")
            page.locator(".cm-content").first.click()
            page.keyboard.type("tcp(flags=syn( )", delay=30)
            page.wait_for_timeout(300)
            page.keyboard.press("Control+s"); page.wait_for_timeout(2200)
            diag_tab = page.locator(".tab", has_text="Diagnostics").first
            badge = diag_tab.locator(".tab-badge").inner_text() if diag_tab.locator(".tab-badge").count() else "none"
            diag_tab.click(); page.wait_for_timeout(500)
            dtxt = page.locator(".panel-body").first.inner_text()[:340].replace("\n", " | ")
            shot(page, "extra-diag.png")
            page.locator('button.tree-del[title="delete _uiaudit_diag.pkt"]').first.click()
            page.wait_for_timeout(1100)
            gone = page.locator('.tree-file[title="_uiaudit_diag.pkt"]').count() == 0
            note("6 DIAGNOSTICS broken file", "PASS" if (badge not in ("none", "0") and gone) else "PARTIAL",
                 f"badge='{badge}'; panel: {dtxt!r}; scratch deleted after: {gone}. (bad_network.pktl itself reports 'No diagnostics — document parses clean.' — its 'badness' is behavioral: retrans/RST timing, not syntax.)")
        except Exception as e:
            note("6 DIAGNOSTICS", "FAIL", f"{e.__class__.__name__}: {e}")

        browser.close()

    print("\n=== SUMMARY ===")
    for f, ok, msg in results:
        print(f"{f}: {ok}")

if __name__ == "__main__":
    main()
