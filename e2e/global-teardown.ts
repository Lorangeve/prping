// global-teardown：按状态文件收尸（web / echo 及其派生的 packet 子命令进程组）。
// 沙箱目录保留不删——失败现场（logs/、工作区改动）可供排查；下一轮 setup 会重建。
import { stateFile } from "./helpers/paths";
import { killStale } from "./helpers/sandbox";

export default async function globalTeardown(): Promise<void> {
  killStale(stateFile);
}
