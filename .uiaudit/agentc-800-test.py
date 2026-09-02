# Agent C —— 800×600 侧栏折叠态横向溢出断言（只读测试，勿改服务器文件）
from playwright.sync_api import sync_playwright

URL = "http://127.0.0.1:8788"
SHOT = "/mnt/mydata/mycoding/prping/.uiaudit/agentc-800.png"

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 800, "height": 600})
    pg.goto(URL, wait_until="domcontentloaded", timeout=15000)
    pg.wait_for_selector(".main", timeout=15000)
    pg.wait_for_timeout(1200)  # 等 WS/首屏渲染稳定

    # 模拟另一 agent 将加的折叠契约：.main.side-hidden（侧栏隐藏两栏布局）
    pg.eval_on_selector(".main", "el => el.classList.add('side-hidden')")
    pg.wait_for_timeout(300)

    sw = pg.evaluate("document.documentElement.scrollWidth")
    cw = pg.evaluate("document.documentElement.clientWidth")
    print(f"side-hidden: scrollWidth={sw} clientWidth={cw} overflow={'NO' if sw <= cw else 'YES'}")

    # 诊断：找出超出视口右缘的元素（若溢出）
    if sw > cw:
        bad = pg.evaluate("""
          () => {
            const out = [];
            for (const el of document.querySelectorAll('*')) {
              const r = el.getBoundingClientRect();
              if (r.right > document.documentElement.clientWidth + 1 && r.width > 0)
                out.push((el.className || el.tagName) + '|' + Math.round(r.right));
              if (out.length > 12) break;
            }
            return out;
          }
        """)
        print("overflow culprits:", bad)

    # 参考项：未折叠（三栏）态
    pg.eval_on_selector(".main", "el => el.classList.remove('side-hidden')")
    pg.wait_for_timeout(200)
    sw2 = pg.evaluate("document.documentElement.scrollWidth")
    print(f"three-col : scrollWidth={sw2} clientWidth={cw} overflow={'NO' if sw2 <= cw else 'YES'}")

    # 截图（折叠态供集成复核）
    pg.eval_on_selector(".main", "el => el.classList.add('side-hidden')")
    pg.wait_for_timeout(200)
    pg.screenshot(path=SHOT, full_page=False)
    print("screenshot:", SHOT)
    b.close()

assert sw <= cw, f"OVERFLOW at 800x600 side-hidden: scrollWidth={sw} > clientWidth={cw}"
print("ASSERTION PASSED")
