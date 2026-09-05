// 页面级通用操作与等待。选择器契约基于前端现有稳定 class/aria（files.tsx /
// App.tsx / panels.tsx）；前端若改版，先改这里再改用例。
import { expect, type Page } from "@playwright/test";

/** 等 WS 连接建立（顶栏状态徽标转 connected）。所有用例的第一道等。 */
export async function waitConnected(page: Page): Promise<void> {
  await expect(page.locator(".status.status-connected")).toBeVisible();
}

/** 在工作区树中点开文件，等文档页签激活。 */
export async function openFile(page: Page, name: string): Promise<void> {
  await page.locator(`.tree-file:has(.tree-name:text-is(${JSON.stringify(name)}))`).click();
  await expect(page.locator(".doc-tab.active .doc-tab-name")).toHaveText(name);
}

/** 切右侧面板页签（Layers / Hex / Diagnostics / Run …）。 */
export async function openPanel(page: Page, label: string): Promise<void> {
  await page.locator(".tabs .tab", { hasText: label }).click();
}

/** 预挂下一个 window.prompt/confirm 对话框的自动接受（prompt 用 value 作输入）。
 *  必须在触发点击**之前**挂——Playwright 对未监听的对话框默认 dismiss。 */
export function acceptNextDialog(page: Page, value = ""): void {
  page.once("dialog", (d) => void d.accept(value).catch(() => {}));
}
