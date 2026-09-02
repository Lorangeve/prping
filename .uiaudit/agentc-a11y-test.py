# Agent C —— a11y 冒烟：树 role/键盘、右键菜单、FolderDialog
from playwright.sync_api import sync_playwright

URL = "http://127.0.0.1:8788"
ok = []
def check(name, cond):
    ok.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1200, "height": 800})
    pg.goto(URL, wait_until="domcontentloaded", timeout=15000)
    pg.wait_for_selector('[role="tree"][aria-label="workspace files"]', timeout=15000)
    pg.wait_for_timeout(800)

    check("ws tree role/aria-label", pg.query_selector('[role="tree"][aria-label="workspace files"]') is not None)
    check("lib tree role/aria-label", pg.query_selector('[role="tree"][aria-label="eng_lib (read-only)"]') is not None)
    check("libs-dirs title has full paths", len((pg.get_attribute(".libs-dirs", "title") or "")) > 0)

    # 展开全部 → 行出现
    pg.click('button[title="expand all"]')
    pg.wait_for_selector('[role="treeitem"]', timeout=5000)
    rows = pg.query_selector_all('[role="treeitem"]')
    check("treeitem rows rendered", len(rows) > 0)
    check("row tabindex=0", all(r.get_attribute("tabindex") == "0" for r in rows))
    dirs = pg.query_selector_all('[role="treeitem"][aria-expanded]')
    check("dir rows aria-expanded", len(dirs) > 0 and all(d.get_attribute("aria-expanded") in ("true", "false") for d in dirs))
    files = pg.query_selector_all('[role="treeitem"][aria-selected]')
    check("file rows aria-selected", len(files) > 0)

    # 键盘：聚焦首行 → ArrowDown 焦点移动；Enter 打开文件；ArrowLeft 折叠回父目录
    rows[0].focus()
    first = pg.evaluate("document.activeElement.getAttribute('data-path')")
    pg.keyboard.press("ArrowDown")
    second = pg.evaluate("document.activeElement.getAttribute('data-path')")
    check("ArrowDown moves focus", first != second)
    pg.keyboard.press("Enter")
    pg.wait_for_timeout(600)
    check("Enter opens file (editor/tab)", pg.query_selector(".doc-tab") is not None)
    # 折叠/展开目录
    d0 = pg.query_selector('[role="treeitem"][aria-expanded="true"]')
    if d0:
        d0.focus()
        pg.keyboard.press("ArrowLeft")
        pg.wait_for_timeout(200)
        check("ArrowLeft collapses dir", d0.get_attribute("aria-expanded") == "false")
        pg.keyboard.press("ArrowRight")
        pg.wait_for_timeout(200)
        check("ArrowRight expands dir", d0.get_attribute("aria-expanded") == "true")

    # 右键菜单：首项自动聚焦，Escape 归还焦点
    row = pg.query_selector('[role="treeitem"]')
    row.click(button="right")
    pg.wait_for_selector('.ctx-menu[role="menu"]', timeout=3000)
    ae = pg.evaluate("document.activeElement.className")
    check("ctx menu first item focused", "ctx-item" in (ae or ""))
    pg.keyboard.press("Escape")
    pg.wait_for_timeout(200)
    back = pg.evaluate("document.activeElement.getAttribute('data-path')")
    check("Escape returns focus to trigger row", back == row.get_attribute("data-path"))

    # FolderDialog：role/aria-modal，打开焦点在输入框，容器级 Escape 关闭
    pg.click('button[title="open a custom folder"]')
    pg.wait_for_selector('.dlg[role="dialog"]', timeout=3000)
    check("dialog role/aria-modal/label",
          pg.get_attribute(".dlg", "aria-modal") == "true" and pg.get_attribute(".dlg", "aria-label") == "open folder")
    check("focus moved into dialog", pg.evaluate("document.activeElement.closest('.dlg')") is not None)
    pg.keyboard.press("Escape")
    pg.wait_for_timeout(300)
    check("Escape at container closes dialog", pg.query_selector('.dlg[role="dialog"]') is None)

    # listbox/option
    pg.click('button[title="open a custom folder"]')
    pg.wait_for_selector('.dlg-list[role="listbox"]', timeout=3000)
    check("listbox/option roles", pg.query_selector('.dlg-list[role="listbox"] [role="option"]') is not None)
    # Tab 焦点圈：从输入框 Shift+Tab 回到最后一项（Open 按钮）
    pg.focus(".dlg-input")
    pg.keyboard.press("Shift+Tab")
    last_txt = pg.evaluate("document.activeElement.textContent.trim()")
    check("focus trap wraps to last (Open)", last_txt == "Open")
    pg.keyboard.press("Escape")

    b.close()

fails = [n for n, c in ok if not c]
print(f"\n{len(ok) - len(fails)}/{len(ok)} passed" + ("; FAILED: " + ", ".join(fails) if fails else ""))
raise SystemExit(1 if fails else 0)
