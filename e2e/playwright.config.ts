// prping webui 冒烟测试 —— Playwright 配置。
//
// 被测对象是真实产物路径：global-setup 把 target/debug/prping 拷进一次性沙箱
// （{prping, UI/, lib/, examples/} 布局，同 just dist 产物形态），以沙箱二进制
// 起真实 `prping web` 服务端 + UDP echo 对端，用例全程走 HTTP/WS/执行桥。
// 进程生命周期与沙箱搭建见 global-setup.ts / helpers/sandbox.ts。
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests",
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  // 单 worker 串行：所有用例共享同一个服务端沙箱工作区，文件操作互不踩踏
  workers: 1,
  fullyParallel: false,
  // 冒烟要诚实：失败不重试（重试掩盖的是环境/竞态问题，不是产品问题）
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { open: "never" }]],
  outputDir: "test-results",
  use: {
    // global-setup 注入（PRPING_WEB_URL）；沙箱 web 端口每次运行动态分配
    baseURL: process.env.PRPING_WEB_URL,
    viewport: { width: 1440, height: 900 },
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
});
