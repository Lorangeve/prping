# Stop all 悬浮清单验证：两个标签各起一个运行 → 在第三个标签看跨标签清单
# （server.pktl 无限监听 + listen.pkt 无限监听），hover Stop all 出清单，
# 点清单行内 ■ 单停一个
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
    # 2) listen.pkt Run（也是无限监听——第二个标签的运行）
    open_file("listen.pkt")
    tab("Run")
    page.locator(".run-go-btn").click()
    time.sleep(1.5)

    # 3) 打开第三个文件 attempt.pkt（本标签无任务）→ Run 页签
    open_file("attempt.pkt")
    tab("Run")
    time.sleep(0.5)
    stopall = page.locator(".stopall-wrap")
    log("attempt.pkt 的 Run 页签里 Stop all 可见:", stopall.count() > 0)

    # 4) hover Stop all → 悬浮清单应列出 2 个跨标签运行
    stopall.hover()
    time.sleep(0.6)
    pop = page.locator(".stopall-pop")
    log("清单可见:", pop.is_visible())
    head = (pop.locator(".stopall-head").text_content() or "").strip()
    log("清单头:", head)
    rows = [(r.text_content() or "").strip() for r in pop.locator(".stopall-row").all()]
    for x in rows:
        log("  行:", x[:80])
    page.screenshot(path=f"{OUT}/80-stopall-hover.png")

    # 5) 点第一行的 ■ → 单停那一个（另一个还在跑）
    pop.locator(".stopall-kill").first.click()
    time.sleep(2.0)
    still = page.locator(".stopall-row").count() if pop.is_visible() else -1
    log("单停后清单剩余行:", still, "（期望 1）")
    page.screenshot(path=f"{OUT}/81-stopall-after-single.png")

    # 6) Stop all 清掉最后一个
    stopall.hover()
    time.sleep(0.4)
    page.locator(".stopall-pop .stopall-head").wait_for(state="visible", timeout=3000)
    page.locator(".run-stop-btn").last.click()
    time.sleep(2.0)
    log("Stop all 后按钮仍在:", stopall.count() > 0 and stopall.is_visible())
    browser.close()
log("DONE")
