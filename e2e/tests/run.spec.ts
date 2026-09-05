// 冒烟 · 执行桥：run 信封 → 服务端 spawn 自身 packet 子命令 → 控制台 JSONL 渲染 /
// 任务卡终态；listen 模式持续运行 → 顶栏 ■ 停止 → 任务卡 stopped。
// 对端是 global-setup 拉起的 `prping server`（UDP echo）；端口经环境变量注入。
import { test, expect } from "@playwright/test";
import { openFile, openPanel, waitConnected } from "../helpers/ui";

const echoPort = process.env.PRPING_ECHO_PORT;
const listenPort = process.env.PRPING_LISTEN_PORT;

test("run packet against udp echo: console shows reply and summary, task exits 0", async ({ page }) => {
  await page.goto("/");
  await waitConnected(page);
  await openFile(page, "udp_echo_smoke.pkt");

  // 参数注入：port = 沙箱 echo server 端口（参数框只在 Layers 页签渲染；
  // 输入与 Run 面板共用同一 runValues）
  await page
    .locator('.params-box label.param-item:has(.param-name:text-is("port")) input.param-input')
    .fill(echoPort!);

  // Run 页签里的 ▶ Run（顶栏按钮仅在脏缓冲时出现——面板按钮才是常态入口）
  await openPanel(page, "Run");
  await page.locator(".run-panel .run-go-btn").click();

  // 控制台 JSONL：✓ 包行（含推导出的 socket 目标）+ 汇总行
  const console_ = page.locator(".run-console");
  await expect(console_.locator(".run-line-ok", { hasText: "✓ 1/1" })).toBeVisible();
  await expect(console_.locator(".run-line-ok", { hasText: "UDP" })).toBeVisible();
  // 无 target 输入的 webui 契约：地址由包字段 params 承载、引擎从包内推导
  await expect(
    console_.locator(".run-line-ok", { hasText: `127.0.0.1:${echoPort}` }),
  ).toBeVisible();
  await expect(console_.locator(".run-line-summary", { hasText: "sent 1" })).toBeVisible();

  // Run 面板状态行终态：#1 exit 0
  await expect(page.locator(".run-status")).toContainText("exit 0");

  // 顶栏任务管理器弹层：任务行 = 文件 + 终态
  await page.locator(".taskmgr-btn").click();
  await expect(
    page.locator(".taskmgr-pop .run-task-row", { hasText: "udp_echo_smoke.pkt" }),
  ).toContainText("exit 0");
  await page.locator(".taskmgr-btn").click(); // 收起，不影响后续用例
});

test("listen run keeps task running and ■ Stop lands stopped", async ({ page }) => {
  await page.goto("/");
  await waitConnected(page);
  await openFile(page, "udp_listen_smoke.pkt");

  // 监听一个无人发包的空闲端口：进程一直存活，供停止冒烟
  //（参数框只在 Layers 页签渲染——先填参数，再切 Run 页签勾 listen）
  await page
    .locator('.params-box label.param-item:has(.param-name:text-is("port")) input.param-input')
    .fill(listenPort!);
  await openPanel(page, "Run");
  await page.locator('label.run-check:has-text("listen") input').check();

  await page.locator(".run-panel .run-go-btn").click();

  // 面板状态行：running… → ■ 停止（run_exit stopped）→ stopped
  const status = page.locator(".run-status");
  await expect(status).toContainText("running…");
  await page.locator(".run-panel .run-stop-btn").click();
  await expect(status).toContainText("stopped");
});
