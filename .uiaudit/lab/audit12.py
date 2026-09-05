# v2：两个长跑（server.pktl 监听 + listen.pkt 勾 listen 持续监听）→ 跨标签清单
import time
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8477"
OUT = "/mnt/mydata/mycoding/prping/.uiaudit"

def log(*a):
    print(*a, flush=True)

with sync_playwright() as pw:
    browser = pw.chromium.launch()
    page = browser.new_page(viewport={"width": 1600, "height": 900})
    page.goto(BASE)
    page.wait_for_selector(".tree", timeout=8000)
    time.sleep(0.8)
    page.locator(".tree-dir:has-text('brute_pin')").first.click()
    time.sleep(0.4)

    def open_file(name):
        page.locator(f".tree-file:has-text('{name}')").first.click()
        time.sleep(1.0)

    def tab(label):
        page.locator(f".tabs .tab:has-text('{label}')").first.click()
        time.sleep(0.3)

    # 1) server.pktl Run（无限监听）
    open_file("server.pktl")
    tab("Run")
    page.locator(".run-go-btn").click()
    time.sleep(1.0)

    # 2) listen.pkt → 勾 listen（裸 --wait 持续监听）→ Run
    open_file("listen.pkt")
    tab("Run")
    page.locator(".run-check:has-text('listen') input").check()
    time.sleep(0.2)
    page.locator(".run-go-btn").click()
    time.sleep(1.5)

    # 3) 第三个文件（本标签无任务）→ Run 页签 → hover Stop all
    open_file("attempt.pkt")
    tab("Run")
    time.sleep(0.5)
    stopall = page.locator(".stopall-wrap")
    log("Stop all 可见（跨标签任务存在）:", stopall.is_visible())
    stopall.hover()
    time.sleep(0.5)
    pop = page.locator(".stopall-pop")
    head = (pop.locator(".stopall-head").text_content() or "").strip()
    rows = [(r.text_content() or "").strip() for r in pop.locator(".stopall-row").all()]
    log("清单头:", head, "（期望 2）")
    for x in rows:
        log("  行:", x[:80])
    page.screenshot(path=f"{OUT}/80-stopall-hover.png")

    # 4) 点第一行 ■ 单停 → 重新 hover 看剩余
    pop.locator(".stopall-kill").first.click()
    time.sleep(1.5)
    stopall.hover()
    time.sleep(0.5)
    rows2 = [(r.text_content() or "").strip() for r in page.locator(".stopall-pop .stopall-row").all()]
    log("单停后剩余:", len(rows2), "（期望 1）", rows2)
    page.screenshot(path=f"{OUT}/81-stopall-after-single.png")

    # 5) Stop all 清场 → 按钮随 running=0 消失
    page.locator(".stopall-wrap .run-stop-btn").click()
    time.sleep(2.0)
    log("Stop all 后按钮消失:", page.locator(".stopall-wrap").count() == 0)
    browser.close()
log("DONE")
