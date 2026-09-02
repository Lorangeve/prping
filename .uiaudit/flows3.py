#!/usr/bin/env python3
"""UI audit round 3: jump deep-test, new-file WS debug, workspace restore fix, run panel."""
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

def main():
    ws_frames = []
    state = {"prompt_value": None, "log": []}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1480, "height": 940})
        page = ctx.new_page()
        page.on("dialog", lambda d: (state["log"].append(d.type + ":" + d.message[:50]),
                                     d.accept(state["prompt_value"]) if (d.type == "prompt" and state["prompt_value"]) else d.accept()))
        def on_ws(ws):
            ws.on("framesent", lambda f: ws_frames.append("S " + str(f)[:400]) if ("create" in str(f) or "read" in str(f)[:80]) else None)
            ws.on("framereceived", lambda f: ws_frames.append("R " + str(f)[:500]) if ("create" in str(f) or '"ok":false' in str(f) or "error" in str(f).lower()) else None)
        page.on("websocket", on_ws)
        page.goto(BASE, wait_until="networkidle")
        page.wait_for_selector(".tree", timeout=10000)
        page.wait_for_timeout(600)

        # ---------- FLOW 3c deep: ctrl+click jump (local symbol + library call) ----------
        try:
            open_file(page, "bad_network/http_get.pkt"); wait_file_open(page, "http_get.pkt")
            page.wait_for_timeout(2500)
            dbg = page.evaluate("""() => ({
              identTotal: document.querySelectorAll('.cm-ident').length,
              samples: [...document.querySelectorAll('.cm-ident')].slice(0,8).map(e => e.textContent),
            })""")
            r = page.evaluate(TOKEN_RECT, "(http_req)")
            assert r, "http_req ref not found"
            x = r["x"] + r["w"] * (5.0 / r["len"])
            page.mouse.move(x, r["y"], steps=3)
            page.keyboard.down("Control"); page.wait_for_timeout(400)
            body_cls = page.evaluate("() => document.body.className")
            ident_cnt = page.locator(".cm-ident").count()
            shot(page, "extra-jump.png")
            page.mouse.down(); page.mouse.up()
            page.keyboard.up("Control"); page.wait_for_timeout(1100)
            land1 = page.evaluate(SEL_LINE)
            msg1 = page.locator(".file-msg").inner_text() if page.locator(".file-msg").count() else ""
            # library call jump: http(
            r2 = page.evaluate(TOKEN_RECT, "http(start_line")
            land2 = cur2 = msg2 = ""
            if r2:
                x2 = r2["x"] + r2["w"] * (2.0 / r2["len"])
                page.mouse.move(x2, r2["y"], steps=3)
                page.keyboard.down("Control"); page.wait_for_timeout(250)
                page.mouse.down(); page.mouse.up(); page.keyboard.up("Control")
                page.wait_for_timeout(1400)
                cur2 = page.locator(".current-file").inner_text().strip() if page.locator(".current-file").count() else ""
                land2 = page.evaluate(SEL_LINE)
                msg2 = page.locator(".file-msg").inner_text() if page.locator(".file-msg").count() else ""
            back_en = None
            b = page.locator('button[title="Back (Alt+←)"]')
            if b.count(): back_en = not b.first.is_disabled()
            note("3c Ctrl+Click jump", "PARTIAL" if msg1 else "PASS",
                 f"DOM debug: .cm-ident total={dbg['identTotal']} samples={dbg['samples']}; Ctrl held -> body '{body_cls}', marks {ident_cnt}; click http_req REF -> landed line {land1!r} msg {msg1!r}; click http( -> file {cur2!r} line {land2!r} msg {msg2!r}; Back enabled after jumps: {back_en}")
        except Exception as e:
            note("3c Ctrl+Click jump", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- FLOW 5 debug: new file ----------
        try:
            state["prompt_value"] = "_uiaudit_tmp.pkt"
            page.locator('button[title="new file"]').first.click()
            page.wait_for_timeout(1600)
            state["prompt_value"] = None
            msg = page.locator(".file-msg").inner_text() if page.locator(".file-msg").count() else ""
            row = page.locator('.tree-file[title="_uiaudit_tmp.pkt"]')
            appeared = row.count() > 0
            note("5 NEW FILE", "PARTIAL",
                 f"prompt answered (dialogs: {state['log'][-2:]}); row appeared: {appeared}; msg: {msg!r}; WS frames: {ws_frames[-4:] if ws_frames else 'none captured'}")
            if appeared:
                row.first.click(); wait_file_open(page, "_uiaudit_tmp.pkt")
                page.locator(".cm-content").first.click()
                page.keyboard.type("icmp()", delay=30)
                page.locator('button.tree-del[title="delete _uiaudit_tmp.pkt"]').first.click()
                page.wait_for_timeout(1100)
            gone = page.locator('.tree-file[title="_uiaudit_tmp.pkt"]').count() == 0
            note("5 DELETE", "PASS" if gone else "FAIL", f"deleted: {gone}")
        except Exception as e:
            note("5 NEW FILE + DELETE", "FAIL", f"{e.__class__.__name__}: {e}")

        # ---------- FLOW 6: diagnostics with broken scratch (needs create to work) ----------
        try:
            state["prompt_value"] = "_uiaudit_diag.pkt"
            page.locator('button[title="new file"]').first.click()
            page.wait_for_timeout(1600)
            state["prompt_value"] = None
            row = page.locator('.tree-file[title="_uiaudit_diag.pkt"]')
            if row.count():
                row.first.click(); wait_file_open(page, "_uiaudit_diag.pkt")
                page.locator(".cm-content").first.click()
                page.keyboard.type("tcp(flags=syn( )", delay=30)
                page.wait_for_timeout(2800)
                diag_tab = page.locator(".tab", has_text="Diagnostics").first
                badge = diag_tab.locator(".tab-badge").inner_text() if diag_tab.locator(".tab-badge").count() else "none"
                diag_tab.click(); page.wait_for_timeout(400)
                dtxt = page.locator(".panel-body").first.inner_text()[:350].replace("\n", " | ")
                shot(page, "extra-diag.png")
                page.locator('button.tree-del[title="delete _uiaudit_diag.pkt"]').first.click()
                page.wait_for_timeout(1000)
                gone = page.locator('.tree-file[title="_uiaudit_diag.pkt"]').count() == 0
                note("6 DIAGNOSTICS broken scratch", "PASS" if gone else "PARTIAL",
                     f"badge='{badge}'; panel: {dtxt!r}; scratch cleaned: {gone}")
            else:
                note("6 DIAGNOSTICS broken scratch", "FAIL", "could not create scratch file (see flow 5 WS frames)")
        except Exception as e:
            note("6 DIAGNOSTICS", "FAIL", f"{e.__class__.__name__}: {e}")

        # ---------- FLOW 7 fix: folder dialog + deterministic restore ----------
        try:
            page.locator('button[title="open a custom folder"]').first.click()
            page.wait_for_selector(".dlg", timeout=4000)
            page.wait_for_function("document.querySelectorAll('.dlg-row').length > 0", timeout=4000)
            title = page.locator(".dlg-title").inner_text()
            rows = page.locator(".dlg-row").count()
            shot(page, "extra-folder.png")
            page.locator(".dlg-row", has_text="pcaps/").first.click(); page.wait_for_timeout(400)
            page.locator(".dlg-btn.dlg-primary", has_text="Open").click(); page.wait_for_timeout(1000)
            pcap_ok = page.locator('.tree-file[title="prping_http.pcap"]').count() > 0
            if pcap_ok:
                page.locator('.tree-file[title="prping_http.pcap"]').first.click(); page.wait_for_timeout(900)
                perr = page.locator(".file-msg").inner_text() if page.locator(".file-msg").count() else ""
            shot(page, "extra-pcaps.png")
            # deterministic restore: abs path in input -> Enter (jump) -> Open (confirm input value)
            page.locator('button[title="open a custom folder"]').first.click()
            page.wait_for_selector(".dlg", timeout=4000)
            page.locator(".dlg-input").first.fill("/mnt/mydata/mycoding/prping/examples")
            page.keyboard.press("Enter"); page.wait_for_timeout(800)
            rows_after = page.locator(".dlg-row").all_inner_texts()[:6]
            page.locator(".dlg-btn.dlg-primary", has_text="Open").click(); page.wait_for_timeout(1200)
            back = page.locator('.tree-file[title="bad_network/http_get.pkt"]').count() > 0
            note("7 FOLDER DIALOG", "PASS" if (pcap_ok and back) else "PARTIAL",
                 f"dialog '{title}' rows={rows}; pcaps workspace switch: {pcap_ok}; pcap open -> {perr!r}; abs-path Enter-jump listed: {rows_after}; examples root restored: {back}")
        except Exception as e:
            note("7 FOLDER DIALOG", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- FLOW 8: run panel ----------
        try:
            assert back, "workspace not restored"
            open_file(page, "icmp_ping/icmp_ping_step.pkt"); wait_file_open(page, "icmp_ping_step.pkt")
            page.locator(".tab", has_text="Run").first.click(); page.wait_for_timeout(300)
            page.locator(".run-field", has_text="target").locator("input").fill("")
            page.locator(".run-mini", has_text="count").locator("input").fill("2")
            page.wait_for_timeout(200)
            page.locator(".run-panel .run-go-btn").click()
            out8a = ""
            for _ in range(26):
                page.wait_for_timeout(500)
                out8a = page.locator(".run-panel").inner_text()
                low = out8a.lower()
                if "summary" in low or "exit" in low or "error" in low or "failed" in low:
                    break
            out8a = out8a[:560].replace("\n", " ⏎ ")
            open_file(page, "wait_timeout/recipe.pktl"); wait_file_open(page, "recipe.pktl")
            page.locator(".tab", has_text="Run").first.click(); page.wait_for_timeout(300)
            page.locator(".run-panel .run-go-btn").click()
            page.wait_for_timeout(1300)
            mode = "default (recipe wait:2)"
            if page.locator(".run-panel .run-stop-btn").count() == 0:
                page.locator(".run-check input").first.check()
                page.locator(".run-panel .run-go-btn").click(); page.wait_for_timeout(1300)
                mode = "listen mode (recipe exited too fast)"
            was_running = page.locator(".run-panel .run-stop-btn").count() > 0
            if was_running:
                page.locator(".run-panel .run-stop-btn").first.click()
                page.wait_for_timeout(1600)
            status = page.locator(".run-panel .run-status").inner_text()[:110] if page.locator(".run-panel .run-status").count() else "?"
            task_rows = " | ".join(page.locator(".run-task-row").all_inner_texts()[:3])
            shot(page, "extra-stop.png")
            note("8 RUN PANEL", "PASS" if was_running else "PARTIAL",
                 f"(a) icmp_ping_step count=2 target='': {out8a!r} || (b) recipe.pktl {mode}: running={was_running}, after ■ Stop status={status!r}, tasks={task_rows!r}")
        except Exception as e:
            note("8 RUN PANEL", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        browser.close()

    print("\n=== SUMMARY ===")
    for f, ok, msg in results:
        print(f"{f}: {ok}")
    with open(os.path.join(OUT, "results3.txt"), "w") as fh:
        for f, ok, msg in results:
            fh.write(f"### {f} — {ok}\n{msg}\n\n")

if __name__ == "__main__":
    main()
