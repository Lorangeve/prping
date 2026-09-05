// e2e/ 包内路径常量（import.meta.url 推导，与 cwd 无关）。
import path from "node:path";
import { fileURLToPath } from "node:url";

/** e2e/ 目录（本包根）。 */
export const e2eRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** 仓库根（e2e 的上一级）。 */
export const repoRoot = path.dirname(e2eRoot);

/** global-setup 写、global-teardown 读的进程状态文件（沙箱路径 + pid 列表）。 */
export const stateFile = path.join(e2eRoot, ".local", "state.json");
