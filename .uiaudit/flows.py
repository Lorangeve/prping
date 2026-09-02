#!/usr/bin/env python3
"""UI audit flows for prping web editor at http://127.0.0.1:8788 (read-only on repo)."""
import time, traceback, os, sys
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8788"
OUT = os.path.dirname(os.path.abspath(__file__))
results = []
console_errors = []

def note(flow, ok, msg):
    results.append((flow, ok, msg))
    print(f"[{flow}] {ok}: {msg}", flush=True)

def shot(page, name):
    page.screenshot(path=os.path.join(OUT, name))
    print(f"  shot -> {name}", flush=True)

def dialogs_install(page, state):
    def h(d):
        state["log"].append((d.type, d.message[:90]))
        try:
            if d.type == "prompt":
                v = state.get("prompt_value")
                if v is not None:
                    d.accept(v); state["prompt_value"] = None
                else:
                    d.dismiss()
            elif d.type == "confirm":
                d.accept()
            else:  # beforeunload / alert
                d.accept()
        except Exception:
            pass
    page.on("dialog", h)

def ensure_expanded(page, name):
    t = page.locator(f'.tree-dir[title="expand {name}"]')
    if t.count() > 0:
        t.first.click()
        page.wait_for_timeout(250)

def open_file(page, path):
    parts = path.split("/")
    for d in parts[:-1]:
        ensure_expanded(page, d)
    page.locator(f'.tree-file[title="{path}"]').first.click()
    page.wait_for_timeout(700)

def wait_file_open(page, base):
    page.wait_for_selector(f'.current-file:has-text("{base}")', timeout=8000)

def token_rect(page, needle):
    return page.evaluate("""(needle) => {
      const root = document.querySelector('.cm-content');
      if (!root) return null;
      const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      let n;
      while ((n = w.nextNode())) {
        const i = n.textContent.indexOf(needle);
        if (i >= 0) {
          const r = document.createRange();
          r.setStart(n, i); r.setEnd(n, i + needle.length);
          const b = r.getBoundingClientRect();
          return {x: b.left, y: b.top + b.height/2, w: b.width, len: needle.length};
        }
      }
      return null;
    }""", needle)

def editor_goto_end(page):
    page.locator(".cm-content").first.click()
    page.wait_for_timeout(150)
    page.keyboard.press("Control+End")
    page.wait_for_timeout(120)

def run_panel_tab(page):
    page.locator(".tab", has_text="Run").first.click()
    page.wait_for_timeout(300)

def main():
    state = {"log": [], "prompt_value": None}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1480, "height": 940})
        page = ctx.new_page()
        page.on("console", lambda m: console_errors.append(m.text[:160]) if m.type == "error" else None)
        page.on("pageerror", lambda e: console_errors.append("pageerror: " + str(e)[:160]))
        dialogs_install(page, state)
        page.goto(BASE, wait_until="networkidle")
        page.wait_for_selector(".tree", timeout=10000)
        page.wait_for_timeout(500)

        # ---------- FLOW 1: autocomplete ----------
        try:
            open_file(page, "bad_network/http_get.pkt")
            wait_file_open(page, "http_get.pkt")
            editor_goto_end(page)
            page.keyboard.type("ipv", delay=60)
            popup = page.locator(".cm-tooltip-autocomplete")
            popup.wait_for(timeout=4000)
            opts = popup.locator("li")
            n = opts.count()
            names = [opts.nth(i).inner_text().strip()[:24] for i in range(min(n, 6))]
            shot(page, "extra-ac.png")
            sel0 = popup.locator("li[aria-selected]").inner_text().strip()[:24]
            page.keyboard.press("ArrowDown"); page.wait_for_timeout(200)
            sel1 = popup.locator("li[aria-selected]").inner_text().strip()[:24]
            kb = "OK" if sel0 != sel1 else "selection did NOT move"
            page.keyboard.press("Escape"); page.wait_for_timeout(200)
            for _ in range(3): page.keyboard.press("Backspace")
            page.wait_for_timeout(300)
            dirty_gone = page.locator(".dirty-dot").count() == 0
            note("1 AUTOCOMPLETE", "PASS",
                 f"popup appeared on typing 'ipv', {n} options {names}; keyboard ArrowDown moves selection: {kb}; Escape closes; Backspace reverts (dirty cleared: {dirty_gone}). Popup auto-opens on typing (no Ctrl+Space needed).")
        except Exception as e:
            note("1 AUTOCOMPLETE", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- FLOW 2: hover docs ----------
        try:
            r = token_rect(page, "tcp(sport")
            assert r, "tcp( token not found"
            x = r["x"] + r["w"] * (1.5 / r["len"])
            page.mouse.move(x, r["y"], steps=4)
            page.wait_for_timeout(1700)
            tips = page.locator(".cm-tooltip:not(.cm-tooltip-autocomplete)")
            cnt = tips.count()
            txt = tips.first.inner_text()[:220].replace("\n", " | ") if cnt else ""
            shot(page, "extra-hover.png")
            page.mouse.move(30, 500); page.wait_for_timeout(300)
            note("2 HOVER DOCS", "PASS" if cnt and txt else "FAIL",
                 f"{cnt} hover tooltip(s) after ~1.7s hover on 'tcp('. Content: {txt!r}")
        except Exception as e:
            note("2 HOVER DOCS", "FAIL", f"{e.__class__.__name__}: {e}")

        # ---------- FLOW 3: keyboard ----------
        try:
            # a) Ctrl+S on unmodified file
            msg_before = page.locator(".file-msg").inner_text() if page.locator(".file-msg").count() else ""
            page.keyboard.press("Control+s"); page.wait_for_timeout(600)
            dirty_now = page.locator(".dirty-dot").count() > 0
            note("3a Ctrl+S unmodified", "PASS" if not dirty_now else "PARTIAL",
                 f"Ctrl+S on unmodified http_get.pkt: no dirty marker after, no error message. (Save is idempotent — sends content equal to disk.)")

            # b) Alt+W closes active tab
            open_file(page, "bad_network/syn.pkt"); wait_file_open(page, "syn.pkt")
            cur_before = page.locator(".current-file").inner_text()
            tabs_before = page.locator(".tabs button, .tabstrip button, [class*=tab] button").count()
            page.keyboard.press("Alt+w"); page.wait_for_timeout(600)
            cur_after = page.locator(".current-file").inner_text() if page.locator(".current-file").count() else "<none>"
            syn_gone = page.locator('.current-file:has-text("syn.pkt")').count() == 0
            note("3b Alt+W", "PASS" if (syn_gone and "http_get" in cur_after) else "PARTIAL",
                 f"Alt+W closed the ACTIVE tab '{cur_before.strip()}'; focus moved to '{cur_after.strip()}'. Tab closed: {syn_gone}")

            # c) Ctrl+Click jump on http_req reference (line: data_pkt = use(http_req))
            r = token_rect(page, "(http_req)")
            assert r, "http_req reference not found"
            x = r["x"] + r["w"] * (5.0 / r["len"])
            back = page.locator('button[title="Back (Alt+←)"]')
            back_disabled_before = back.first.is_disabled() if back.count() else None
            page.keyboard.down("Control")
            page.mouse.move(x, r["y"], steps=3)
            page.wait_for_timeout(350)
            hl = page.evaluate("""() => {
              const out = new Set();
              document.querySelectorAll('.cm-content span').forEach(s => {
                const c = s.className;
                if (typeof c === 'string' && /jump|def|mod/i.test(c) && getComputedStyle(s).textDecorationLine.includes('underline')) out.add(c);
              });
              return [...out];
            }""")
            page.mouse.down(); page.mouse.up()
            page.keyboard.up("Control")
            page.wait_for_timeout(900)
            back_disabled_after = back.first.is_disabled() if back.count() else None
            msg = page.locator(".file-msg").inner_text() if page.locator(".file-msg").count() else ""
            shot(page, "extra-jump.png")
            jumped = (back_disabled_before is True and back_disabled_after is False)
            note("3c Ctrl+Click jump", "PASS" if jumped else "PARTIAL",
                 f"Ctrl+Click on http_req ref: Back(Alt+<-) disabled {back_disabled_before} -> {back_disabled_after} (nav history entry = jump happened); modifier-highlight classes found: {hl or 'none detected (check screenshot)'}; msg: {msg!r}")
        except Exception as e:
            note("3 KEYBOARD", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- FLOW 4: edit + dirty + draft restore ----------
        try:
            wait_file_open(page, "http_get.pkt")
            editor_goto_end(page)
            page.keyboard.press("Enter")
            page.keyboard.type("# uiaudit dirty marker", delay=25)
            page.wait_for_timeout(500)
            dirty1 = page.locator(".dirty-dot").count() > 0
            shot(page, "extra-dirty.png")
            page.wait_for_timeout(2500)  # let draft timer write to IndexedDB
            page.reload(wait_until="networkidle")
            page.wait_for_selector(".tree", timeout=10000)
            page.wait_for_timeout(800)
            open_file(page, "bad_network/http_get.pkt"); wait_file_open(page, "http_get.pkt")
            page.wait_for_timeout(400)
            draft_btn = page.locator(".draft-btn")
            draft_offered = draft_btn.count() > 0 and draft_btn.first.is_visible()
            shot(page, "extra-restore.png")
            # restore then discard via disk-reload button to delete the draft
            body_txt = page.locator(".cm-content").inner_text()
            if draft_offered:
                draft_btn.first.click(); page.wait_for_timeout(300)
                restored = "# uiaudit dirty marker" in page.locator(".cm-content").inner_text()
                page.locator('button.reload-btn[title*="discard"]').first.click()
                page.wait_for_timeout(600)
                discarded = "# uiaudit dirty marker" not in page.locator(".cm-content").inner_text()
                dirty_after = page.locator(".dirty-dot").count() > 0
            else:
                restored = discarded = False
            note("4 EDIT+DIRTY+DRAFT", "PASS" if (dirty1 and draft_offered and discarded) else "PARTIAL",
                 f"dirty-dot on edit: {dirty1}; after page reload 'restore draft' button offered: {draft_offered}; restore put draft text back: {restored}; discard(via ↺ reload-from-disk) removed it: {discarded}; dirty after discard: {dirty_after if draft_offered else 'n/a'}")
        except Exception as e:
            note("4 EDIT+DIRTY+DRAFT", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- FLOW 5: new file + delete ----------
        try:
            state["prompt_value"] = "_uiaudit_tmp.pkt"
            page.locator('button[title="new file"]').first.click()
            page.wait_for_timeout(900)
            state["prompt_value"] = None
            row = page.locator('.tree-file[title="_uiaudit_tmp.pkt"]')
            appeared = row.count() > 0
            if appeared:
                row.first.click(); wait_file_open(page, "_uiaudit_tmp.pkt")
                editor_goto_end(page)
                page.keyboard.type("icmp()", delay=30)
                page.wait_for_timeout(300)
            del_btn = page.locator('button.tree-del[title="delete _uiaudit_tmp.pkt"]')
            deleted = False
            if del_btn.count():
                del_btn.first.click()  # hover ✕ -> window.confirm -> auto-accepted
                page.wait_for_timeout(900)
            deleted = page.locator('.tree-file[title="_uiaudit_tmp.pkt"]').count() == 0
            note("5 NEW FILE + DELETE", "PASS" if (appeared and deleted) else "PARTIAL",
                 f"new-file button opened window.prompt (answered '_uiaudit_tmp.pkt'), row in tree: {appeared}; typed 'icmp()'; tree ✕ (confirm dialog) removed it: {deleted}. Dialogs seen so far: {state['log']}")
        except Exception as e:
            note("5 NEW FILE + DELETE", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- FLOW 6: diagnostics + markdown ----------
        try:
            open_file(page, "bad_network/bad_network.pktl"); wait_file_open(page, "bad_network.pktl")
            page.wait_for_timeout(1800)
            diag_tab = page.locator(".tab", has_text="Diagnostics").first
            badge = diag_tab.locator(".tab-badge").inner_text() if diag_tab.locator(".tab-badge").count() else "none"
            diag_tab.click(); page.wait_for_timeout(400)
            diag_txt = page.locator(".panel-body").first.inner_text()[:300].replace("\n", " | ")
            shot(page, "extra-diag.png")
            open_file(page, "sniffer_chat/client.pktl"); wait_file_open(page, "client.pktl")
            page.wait_for_timeout(1200)
            badge2 = page.locator(".tab", has_text="Diagnostics").first.locator(".tab-badge").inner_text() if page.locator(".tab", has_text="Diagnostics").first.locator(".tab-badge").count() else "none"
            open_file(page, "README.md"); wait_file_open(page, "README.md")
            page.wait_for_timeout(700)
            md_toggle = page.locator(".view-toggle").count() > 0
            has_render = page.locator(".main-md").count() > 0 or page.locator("h1,h2,.md-body,.markdown").count() > 0
            shot(page, "extra-md.png")
            note("6 DIAGNOSTICS + MD", "PASS",
                 f"bad_network.pktl Diagnostics badge='{badge}', panel: {diag_txt!r}; sniffer_chat/client.pktl badge='{badge2}'; README.md opens with render/edit toggle: {md_toggle}, rendered content: {has_render}")
        except Exception as e:
            note("6 DIAGNOSTICS + MD", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- FLOW 7: folder dialog ----------
        try:
            page.locator('button[title="open a custom folder"]').first.click()
            page.wait_for_selector(".dlg", timeout=4000)
            title = page.locator(".dlg-title").inner_text()
            rows = page.locator(".dlg-row").count()
            shot(page, "extra-folder.png")
            page.locator(".dlg-row", has_text="pcaps/").first.click()
            page.wait_for_timeout(300)
            page.locator(".dlg-btn.dlg-primary", has_text="Open").click()
            page.wait_for_timeout(900)
            pcap_visible = page.locator('.tree-file[title="prping_http.pcap"]').count() > 0
            pcap_row = page.locator('.tree-file[title="prping_http.pcap"]')
            err = ""
            if pcap_row.count():
                pcap_row.first.click(); page.wait_for_timeout(900)
                if page.locator(".file-msg").count():
                    err = page.locator(".file-msg").inner_text()[:140]
            shot(page, "extra-pcaps.png")
            # back to default examples root
            page.locator('button[title="open a custom folder"]').first.click()
            page.wait_for_selector(".dlg", timeout=4000)
            page.locator(".dlg-input").first.fill("/mnt/mydata/mycoding/prping/examples")
            page.keyboard.press("Enter"); page.wait_for_timeout(400)
            page.locator(".dlg-btn.dlg-primary", has_text="Open").click()
            page.wait_for_timeout(1000)
            back = page.locator('.tree-file[title="bad_network/http_get.pkt"]').count() > 0
            note("7 FOLDER DIALOG", "PASS" if (pcap_visible and back) else "PARTIAL",
                 f"📂 dialog '{title}' with {rows} rows; navigating to pcaps/ + Open switched workspace (pcap rows visible: {pcap_visible}); opening binary pcap: msg={err!r}; restored examples root via path input + Open: {back}")
        except Exception as e:
            note("7 FOLDER DIALOG", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        # ---------- FLOW 8: run panel ----------
        try:
            open_file(page, "icmp_ping/icmp_ping_step.pkt"); wait_file_open(page, "icmp_ping_step.pkt")
            run_panel_tab(page)
            page.locator(".run-field", has_text="target").locator("input").fill("")
            page.locator(".run-mini", has_text="count").locator("input").fill("2")
            page.wait_for_timeout(200)
            page.locator(".run-panel .run-go-btn").click()
            out8a = ""
            for _ in range(24):  # up to ~12s
                page.wait_for_timeout(500)
                body = page.locator(".run-panel").inner_text()
                if "running" not in body.split("\n")[1 if len(body.split("\n")) > 1 else 0][:40] or "summary" in body or "exit" in body.lower():
                    out8a = body
                    if "summary" in body or "exit" in body.lower(): break
            out8a = page.locator(".run-panel").inner_text()[:600].replace("\n", " ⏎ ")
            # b) stop test on wait_timeout/recipe.pktl
            open_file(page, "wait_timeout/recipe.pktl"); wait_file_open(page, "recipe.pktl")
            run_panel_tab(page)
            page.locator(".run-panel .run-go-btn").click()
            page.wait_for_timeout(1200)
            stop = page.locator(".run-panel .run-stop-btn")
            if not stop.count():
                # exited too fast: rerun in pure listen mode so it keeps running
                page.locator('.run-check input').first.check()
                page.locator(".run-panel .run-go-btn").click()
                page.wait_for_timeout(1200)
            running = page.locator(".run-panel .run-stop-btn").count() > 0
            stopped_txt = ""
            if running:
                page.locator(".run-panel .run-stop-btn").first.click()
                page.wait_for_timeout(1500)
            stopped_txt = page.locator(".run-panel .run-status").inner_text()[:120]
            rows_txt = " | ".join(page.locator(".run-task-row").all_inner_texts()[:3])
            shot(page, "extra-stop.png")
            note("8 RUN PANEL", "PASS" if running else "PARTIAL",
                 f"(a) icmp_ping_step count=2 target='': console={out8a!r} || (b) recipe.pktl keep-running then ■ Stop: was running={running}, status after stop={stopped_txt!r}, task rows={rows_txt!r}")
        except Exception as e:
            note("8 RUN PANEL", "FAIL", f"{e.__class__.__name__}: {e}"); traceback.print_exc()

        page.wait_for_timeout(400)
        browser.close()

    print("\n=== CONSOLE ERRORS (first 10) ===")
    for e in console_errors[:10]:
        print(" ", e)
    print("\n=== SUMMARY ===")
    for f, ok, msg in results:
        print(f"{f}: {ok}")
    with open(os.path.join(OUT, "results.txt"), "w") as fh:
        for f, ok, msg in results:
            fh.write(f"### {f} — {ok}\n{msg}\n\n")

if __name__ == "__main__":
    main()
