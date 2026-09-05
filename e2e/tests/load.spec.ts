// 冒烟 · 服务与外壳：/config.json 契约、页面加载、工作区树与 eng_lib 只读树。
import { test, expect } from "@playwright/test";
import { waitConnected } from "../helpers/ui";

test("config.json exposes version, ws path, one-shot token and builtins", async ({ request }) => {
  const res = await request.get("/config.json");
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.version).toMatch(/^\d+\.\d+\.\d+/);
  expect(body.wsPath).toBe("/ws");
  // 一次性 WS 鉴权 token（128-bit hex；缺 token 的 WS 升级会被服务端拒绝）
  expect(body.token).toMatch(/^[0-9a-f]{32}$/);
  // 内置原语名单（跳转高亮依据）
  expect(body.builtins?.length).toBeGreaterThan(0);
});

test("app shell loads: brand, ws connected, workspace and eng_lib trees", async ({ page }) => {
  await page.goto("/");
  await waitConnected(page);

  await expect(page.locator(".topbar .brand")).toHaveText("prping web");
  await expect(page.locator(".topbar .version")).toHaveText(/^v\d+\.\d+\.\d+$/);

  // 工作区树列出沙箱 fixture（examples/ 发现成功）
  const tree = page.locator('.tree[aria-label="workspace files"]');
  await expect(tree).toBeVisible();
  await expect(tree.locator('.tree-file:has(.tree-name:text-is("udp_echo_smoke.pkt"))')).toHaveCount(1);

  // eng_lib 只读树
  const libs = page.locator('.tree[aria-label="eng_lib (read-only)"]');
  await expect(libs).toBeVisible();
  await expect(libs.locator('.lib-file:has(.tree-name:text-is("headers.pkt"))')).toBeVisible();
});
