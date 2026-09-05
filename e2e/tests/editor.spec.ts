// 冒烟 · 编辑器核心链路：打开 → 层栈/HEX 预览 → 语法错误诊断 → 新建/编辑/Ctrl+S 持久化。
// 注意：CodeMirror 开启 closeBrackets——键盘输入内容避开括号/引号配对字符。
import { test, expect } from "@playwright/test";
import { acceptNextDialog, openFile, openPanel, waitConnected } from "../helpers/ui";

test("open packet: editor renders, layers and hex preview populate", async ({ page }) => {
  await page.goto("/");
  await waitConnected(page);
  await openFile(page, "udp_echo_smoke.pkt");

  // CodeMirror 编辑器渲染出包定义
  await expect(page.locator(".cm-content")).toContainText("udp(");

  // Layers 页签：解析出的层栈（raw/udp/ipv4）与字段表（每个 k=v 一行；
  // 层名精确匹配——hasText 会误命中：ipv4 块文本含 proto=UDP 字段）
  await openPanel(page, "Layers");
  await expect(page.locator('.layer-name:text-is("udp")')).toBeVisible();
  await expect(page.locator('.layer-name:text-is("ipv4")')).toBeVisible();
  await expect(page.locator('.fields .fk:text-is("dport")')).toBeVisible();
  await expect(page.locator('.fields .fk:text-is("sport")')).toBeVisible();

  // Hex 页签：HEX 预览出现偏移行与字节
  await openPanel(page, "Hex");
  await expect(page.locator(".hexview .hex-row").first()).toBeVisible();
  expect(await page.locator(".hexview .hex-byte").count()).toBeGreaterThan(0);
});

test("diagnostics panel reports a parse error for broken source", async ({ page }) => {
  await page.goto("/");
  await waitConnected(page);
  await openFile(page, "syntax_error.pkt");
  await openPanel(page, "Diagnostics");
  await expect(page.locator(".diag-error").first()).toBeVisible();
});

test("new file, type, Ctrl+S persists across reload", async ({ page }) => {
  await page.goto("/");
  await waitConnected(page);

  // 新建文件（window.prompt）→ 打开未落盘的空缓冲
  acceptNextDialog(page, "editor_smoke.pkt");
  await page.locator('button[title="new file"]').click();
  await expect(page.locator(".doc-tab.active .doc-tab-name")).toHaveText("editor_smoke.pkt");

  // 输入内容（纯注释行——避开 closeBrackets 配对字符）→ 脏标记出现
  await page.locator(".cm-content").click();
  await page.keyboard.type("# webui smoke edit marker");
  await expect(page.locator(".dirty-dot").first()).toBeVisible();

  // Ctrl+S 落盘 → 脏标记消失
  await page.keyboard.press("ControlOrMeta+s");
  await expect(page.locator(".dirty-dot")).toHaveCount(0);

  // 刷新后重开：内容从服务端读回（保存真正持久化）
  await page.reload();
  await waitConnected(page);
  await openFile(page, "editor_smoke.pkt");
  await expect(page.locator(".cm-content")).toContainText("webui smoke edit marker");
});
