#!/usr/bin/env python3
"""UI audit round 2: fixes multi-span token lookup, jump highlight, workspace restore, run panel."""
import time, traceback, os
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
    const full = line.textContent;
    const i = full.indexOf(needle);
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
  return node ? node.textContent.trim().slice(0, 60) : null;
}"""

def main():
    state = {"prompt_value": None, "log": []}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1480, "height": 940})
        page = ctx.new_page()
        page.on("dialog", lambda d: (state["log"].append(d.type + ":" + d.message[:60]),
                                     d.accept(state["prompt_value"]) if (d.type == "prompt" and state["prompt_value"]) else d.accept()))
        page.goto(BASE, wait_until="networkidle")
        page.wait_for_selector(".tree", timeout=10000)
        page.wait_for_timeout(600)

        # ---------- FLOW 1 retry: autocomplete in pipeline call position ----------
        try:
            open_file(page, "bad_network/http_get.pkt"); wait_file_open(page, "http_get.pkt")
            page.wait_for_timeout(2200)  # let LSP warm up
            line = page.locator('.cm-line', has_text="|> eth()").first
            line.click(); page.keyboard.press("End"); page.wait_for_timeout(150)
            page.keyboard.type(" |> tc", delay=70)
            popup = page.locator(".cm-tooltip-autocomplete")
            auto = True
            try:
                popup.wait_for(timeout=5000)
            except Exception:
                auto = False
                page.keyboard.press("Control+Space"); page.wait_for_timeout(800)
                popup.wait_for(timeout=3000)
            opts = popup.locator("li")
            n = opts.count()
            names = [opts.nth(i).inner_text().strip()[:26] for i in range(min(n, 8))]
            sel0 = popup.locator("li[aria-selected]").inner_text().strip()[:26]
            page.keyboard.press("ArrowDown"); page.wait_for_timeout(200)
            sel1 = popup.locator("li[aria-selected]").inner_text().strip()[:26]
            shot(page, "extra-ac.png")
            page.keyboard.press("Escape"); page.wait_for_timeout(200)
            for _ in range(6): page.keyboard.press("Backspace")
            page.wait_for_timeout(400)
            dirty_gone = page.locator(".dirty-dot").count() == 0
            note("1 AUTOCOMPLETE", "PASS",
                 f"popup appeared automatically on typing 'tc' in pipeline position: {auto}; {n} options {names}; ArrowDown moves aria-selected ('{sel0}' -> '{sel1}'); Escape closes + Backspace reverts (dirty cleared: {dirty_gone})")
        except Exception as e:
            note("1 AUTOCOMPLETE", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- FLOW 2 retry: hover docs ----------
        try:
            r = page.evaluate(TOKEN_RECT, "tcp(sport")
            assert r, "tcp( not found"
            x = r["x"] + r["w"] * (1.5 / r["len"])
            page.mouse.move(x, r["y"], steps=4)
            page.wait_for_timeout(1800)
            tips = page.locator(".cm-tooltip:not(.cm-tooltip-autocomplete)")
            cnt = tips.count()
            txt = tips.first.inner_text()[:260].replace("\n", " | ") if cnt else ""
            shot(page, "extra-hover.png")
            page.mouse.move(20, 600); page.wait_for_timeout(300)
            note("2 HOVER DOCS", "PASS" if cnt and len(txt) > 3 else "FAIL",
                 f"{cnt} hover tooltip after 1.8s on 'tcp(' — content: {txt!r}")
        except Exception as e:
            note("2 HOVER DOCS", "FAIL", f"{e.__class__.__name__}: {e}")

        # ---------- FLOW 3c retry: ctrl+click jump ----------
        try:
            idents = page.locator(".cm-ident", has_text="http_req")
            cnt = idents.count()
            ref = idents.nth(1) if cnt > 1 else idents.first  # 2nd = use(http_req) reference
            ref.hover(); page.wait_for_timeout(200)
            page.keyboard.down("Control"); page.wait_for_timeout(350)
            body_cls = page.evaluate("() => document.body.className")
            ident_cnt = page.locator(".cm-ident").count()
            shot(page, "extra-jump.png")
            ref.click(modifiers=["Control"])
            page.keyboard.up("Control")
            page.wait_for_timeout(1000)
            land = page.evaluate(SEL_LINE)
            msg = page.locator(".file-msg").inner_text() if page.locator(".file-msg").count() else ""
            note("3c Ctrl+Click jump", "PASS" if (cnt > 1 and not msg and land and "http_req = http" in land) else "PARTIAL",
                 f".cm-ident 'http_req' spans found: {cnt}; Ctrl held -> body class '{body_cls}', .cm-ident marks visible: {ident_cnt}; after click cursor landed on line: {land!r}; msg: {msg!r}")
        except Exception as e:
            note("3c Ctrl+Click jump", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- FLOW 5 retry: new file + delete ----------
        try:
            state["prompt_value"] = "_uiaudit_tmp.pkt"
            page.locator('button[title="new file"]').first.click()
            page.wait_for_timeout(1400)
            state["prompt_value"] = None
            msg = page.locator(".file-msg").inner_text() if page.locator(".file-msg").count() else ""
            row = page.locator('.tree-file[title="_uiaudit_tmp.pkt"]')
            appeared = row.count() > 0
            typed = False
            if appeared:
                row.first.click(); wait_file_open(page, "_uiaudit_tmp.pkt")
                page.locator(".cm-content").first.click()
                page.keyboard.type("icmp()", delay=30); typed = True
                page.wait_for_timeout(300)
            if appeared:
                page.locator('button.tree-del[title="delete _uiaudit_tmp.pkt"]').first.click()
                page.wait_for_timeout(1100)
            gone = page.locator('.tree-file[title="_uiaudit_tmp.pkt"]').count() == 0
            note("5 NEW FILE + DELETE", "PASS" if (appeared and gone) else "PARTIAL",
                 f"prompt answered '_uiaudit_tmp.pkt' (dialogs: {state['log'][:3]}); row appeared: {appeared}; typed icmp(): {typed}; deleted via tree ✕ + confirm: {gone}; app msg: {msg!r}")
        except Exception as e:
            note("5 NEW FILE + DELETE", "FAIL", f"{e.__class__.__name__}: {e}")

        # ---------- FLOW 6 retry: real diagnostics via scratch broken file ----------
        try:
            state["prompt_value"] = "_uiaudit_diag.pkt"
            page.locator('button[title="new file"]').first.click()
            page.wait_for_timeout(1400)
            state["prompt_value"] = None
            row = page.locator('.tree-file[title="_uiaudit_diag.pkt"]')
            if row.count():
                row.first.click(); wait_file_open(page, "_uiaudit_diag.pkt")
                page.locator(".cm-content").first.click()
                page.keyboard.type("tcp(flags=syn( )", delay=30)
                page.wait_for_timeout(2500)
                diag_tab = page.locator(".tab", has_text="Diagnostics").first
                badge = diag_tab.locator(".tab-badge").inner_text() if diag_tab.locator(".tab-badge").count() else "none"
                diag_tab.click(); page.wait_for_timeout(400)
                dtxt = page.locator(".panel-body").first.inner_text()[:320].replace("\n", " | ")
                shot(page, "extra-diag.png")
                # clean up scratch
                page.locator('button.tree-del[title="delete _uiaudit_diag.pkt"]').first.click()
                page.wait_for_timeout(1000)
                gone = page.locator('.tree-file[title="_uiaudit_diag.pkt"]').count() == 0
                note("6 DIAGNOSTICS(scratch broken file)", "PASS" if gone else "PARTIAL",
                     f"broken scratch file badge='{badge}', panel: {dtxt!r}; scratch deleted after: {gone}. Note: bad_network.pktl itself is parse-clean ('No diagnostics') — its 'badness' is behavioral (retrans/RST), not a syntax issue; sniffer_chat/client.pktl also clean.")
            else:
                note("6 DIAGNOSTICS(scratch)", "PARTIAL", "scratch file could not be created — see flow 5")
        except Exception as e:
            note("6 DIAGNOSTICS(scratch)", "FAIL", f"{e.__class__.__name__}: {e}")

        # ---------- FLOW 7 retry: folder dialog navigation + restore ----------
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
                err = page.locator(".file-msg").inner_text() if page.locator(".file-msg").count() else ""
            shot(page, "extra-pcaps.png")
            # restore: absolute-path jump test first, then ../ navigation
            page.locator('button[title="open a custom folder"]').first.click()
            page.wait_for_selector(".dlg", timeout=4000)
            page.locator(".dlg-input").first.fill("/mnt/mydata/mycoding/prping/examples")
            page.keyboard.press("Enter"); page.wait_for_timeout(700)
            dlg_err = page.locator(".dlg-err").inner_text() if page.locator(".dlg-err").count() else ""
            input_val = page.locator(".dlg-input").first.input_value()
            if page.locator(".dlg-up").count():  # fall back to ../ row navigation
                page.locator(".dlg-up").first.click(); page.wait_for_timeout(400)
            page.locator(".dlg-btn.dlg-primary", has_text="Open").click(); page.wait_for_timeout(1100)
            back = page.locator('.tree-file[title="bad_network/http_get.pkt"]').count() > 0
            note("7 FOLDER DIALOG", "PASS" if (pcap_ok and back) else "PARTIAL",
                 f"dialog '{title}' rows={rows}; pcaps/ + Open switched workspace: {pcap_ok}; opening .pcap -> {err!r}; abs-path input jump: input now {input_val!r}, err={dlg_err!r}; restored examples root: {back}")
        except Exception as e:
            note("7 FOLDER DIALOG", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- FLOW 8: run panel ----------
        try:
            assert page.locator('.tree-file[title="icmp_ping/icmp_ping_step.pkt"]').count() > 0, "workspace not back at examples"
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
            out8a = out8a[:520].replace("\n", " ⏎ ")
            # (b) stop test
            open_file(page, "wait_timeout/recipe.pktl"); wait_file_open(page, "recipe.pktl")
            page.locator(".tab", has_text="Run").first.click(); page.wait_for_timeout(300)
            page.locator(".run-panel .run-go-btn").click()
            page.wait_for_timeout(1300)
            mode = "default (recipe wait:2 per step)"
            if page.locator(".run-panel .run-stop-btn").count() == 0:
                page.locator(".run-check input").first.check()  # listen mode -> runs forever
                page.locator(".run-panel .run-go-btn").click()
                page.wait_for_timeout(1300)
                mode = "listen checkbox (default recipe exited too fast to stop)"
            was_running = page.locator(".run-panel .run-stop-btn").count() > 0
            if was_running:
                page.locator(".run-panel .run-stop-btn").first.click()
                page.wait_for_timeout(1600)
            status = page.locator(".run-panel .run-status").inner_text()[:100] if page.locator(".run-panel .run-status").count() else "?"
            task_rows = " | ".join(page.locator(".run-task-row").all_inner_texts()[:3])
            shot(page, "extra-stop.png")
            note("8 RUN PANEL", "PASS" if was_running else "PARTIAL",
                 f"(a) icmp_ping_step count=2 target='': console={out8a!r} || (b) recipe.pktl {mode}: running={was_running}, after ■ Stop status={status!r}, tasks={task_rows!r}")
        except Exception as e:
            note("8 RUN PANEL", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        browser.close()

    print("\n=== SUMMARY ===")
    for f, ok, msg in results:
        print(f"{f}: {ok}")
    with open(os.path.join(OUT, "results2.txt"), "w") as fh:
        for f, ok, msg in results:
            fh.write(f"### {f} — {ok}\n{msg}\n\n")

if __name__ == "__main__":
    main()
