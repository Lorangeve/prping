// 冒烟 · 文件管理：新建/改名/删除文件、新建/删除目录、📂 文件夹选择对话框（取消不改工作区）。
import { test, expect, type Page } from "@playwright/test";
import { acceptNextDialog, waitConnected } from "../helpers/ui";

const TREE = '.tree[aria-label="workspace files"]';

function treeFile(page: Page, name: string) {
  return page.locator(`${TREE} .tree-file:has(.tree-name:text-is("${name}"))`);
}

test("create, rename, delete a file via sidebar", async ({ page }) => {
  await page.goto("/");
  await waitConnected(page);

  // 新建：prompt 输入文件名 → 空缓冲打开 → Ctrl+S 落盘 → 树出现
  acceptNextDialog(page, "files_smoke.pkt");
  await page.locator('button[title="new file"]').click();
  await page.keyboard.press("ControlOrMeta+s");
  const created = treeFile(page, "files_smoke.pkt");
  await expect(created).toHaveCount(1);

  // 改名：行悬停 → 铅笔按钮（aria-label rename/move …）→ prompt 新路径
  await created.hover();
  acceptNextDialog(page, "files_renamed.pkt");
  await created.locator('button[aria-label^="rename/move"]').click();
  const renamed = treeFile(page, "files_renamed.pkt");
  await expect(renamed).toHaveCount(1);
  await expect(created).toHaveCount(0);

  // 删除：confirm 接受 → 树中消失
  await renamed.hover();
  acceptNextDialog(page);
  await renamed.locator('button[aria-label^="delete"]').click();
  await expect(renamed).toHaveCount(0);
});

test("create and delete a folder", async ({ page }) => {
  await page.goto("/");
  await waitConnected(page);

  acceptNextDialog(page, "smoke_dir");
  await page.locator('button[title="new folder"]').click();
  const dir = page.locator(`${TREE} .tree-dir:has(.tree-name:text-is("smoke_dir"))`);
  await expect(dir).toHaveCount(1);

  // 目录删除确认文案说明递归后果 → 接受
  await dir.hover();
  acceptNextDialog(page);
  await dir.locator('button[aria-label^="delete folder"]').click();
  await expect(dir).toHaveCount(0);
});

test("open-folder dialog browses and cancels without changing workspace", async ({ page }) => {
  await page.goto("/");
  await waitConnected(page);

  await page.locator('button[title="open a custom folder"]').click();
  const dlg = page.locator(".dlg");
  await expect(dlg).toBeVisible();
  await expect(dlg.locator(".dlg-title")).toHaveText("Open folder");
  // 服务端 browse 返回目录列表（web 文件夹选择对话框唯一入口）
  await expect(dlg.locator(".dlg-row").first()).toBeVisible();

  // 取消：对话框关闭，工作区仍是沙箱 examples/
  await dlg.locator(".dlg-btn", { hasText: "Cancel" }).click();
  await expect(dlg).toHaveCount(0);
  await expect(page.locator(`${TREE} .tree-file:has(.tree-name:text-is("udp_echo_smoke.pkt"))`)).toHaveCount(1);
});
