// 沙箱搭建：把仓库产物组装成 just dist 同形的自包含运行目录，再拉起被测服务。
//
//   <sandbox>/
//     prping          拷贝的 target/debug/prping（拷贝而非 symlink：
//                     current_exe 会解析符号链接，exe 目录就近查找会指回 target/）
//     UI/             → frontend/dist（目录符号链接；Windows 用 junction）
//     lib/            → eng_lib（包库就近查找）
//     examples/       fixtures/workspace 拷贝（可写工作区，冒烟随便改）
//     logs/           web.log / echo.log（失败排查现场）
//
// 服务端两个进程：`prping web`（被测本体）+ `prping server`（UDP echo 对端，
// run 冒烟的回包来源，同二进制免 root）。
import fs from "node:fs";
import path from "node:path";
import { e2eRoot, repoRoot } from "./paths";
import { freePort, killPidGroup, spawnDetached, waitHttpReady, waitUdpEcho } from "./server";

export interface SandboxInfo {
  root: string;
  bin: string;
  webPort: number;
  echoPort: number;
  /** 空闲端口（无人监听）：listen 冒烟用，监听后无人发包 → 一直运行可被停。 */
  listenPort: number;
  pids: number[];
  version: string;
}

/** 组装沙箱并拉起两个服务进程（web + UDP echo），等两者就绪。
 *  每个进程 spawn 后立即把 pid 追加进状态文件——setup 中途失败 teardown 也能收尸。 */
export async function buildSandbox(stateFile: string): Promise<SandboxInfo> {
  const exeName = process.platform === "win32" ? "prping.exe" : "prping";
  const binSrc = process.env.PRPING_BIN ?? path.join(repoRoot, "target", "debug", exeName);
  if (!fs.existsSync(binSrc)) {
    throw new Error(`prping 二进制不存在：${binSrc}（先 just build，或用 PRPING_BIN 指定）`);
  }
  const distIndex = path.join(repoRoot, "frontend", "dist", "index.html");
  if (!fs.existsSync(distIndex)) {
    throw new Error(`前端产物缺失：${distIndex}（先 just build-web）`);
  }

  // 每轮全新沙箱：上次运行的文件改动/日志一律不留（根路径可用 PRPING_WEBUI_SANDBOX 固定）
  const root = process.env.PRPING_WEBUI_SANDBOX ?? path.join(e2eRoot, ".local", "sandbox");
  fs.rmSync(root, { recursive: true, force: true });
  const logs = path.join(root, "logs");
  fs.mkdirSync(logs, { recursive: true });

  const bin = path.join(root, exeName);
  fs.copyFileSync(binSrc, bin);
  fs.chmodSync(bin, 0o755);

  // 能力探测：确认拷贝的二进制带 web 子命令（无 feature 的旧产物会在这里失败，
  // 提示重编而不是启动后 "expected COMMAND" 干等超时）
  const { spawnSync } = await import("node:child_process");
  const probe = spawnSync(bin, ["web", "--help"], { timeout: 10_000 });
  if (probe.status !== 0) {
    throw new Error(
      `${binSrc} 不支持 web 子命令（可能编译时未启用 prping/web feature）——` +
        `先 just build 或用 PRPING_BIN 指定带 web 的二进制`,
    );
  }

  // UI 与包库：目录符号链接（读盘按链接目标走；Windows 用 junction 免特权）
  linkDir(path.join(repoRoot, "frontend", "dist"), path.join(root, "UI"));
  linkDir(path.join(repoRoot, "eng_lib"), path.join(root, "lib"));

  // 可写工作区：fixtures/workspace 拷为 examples/（default_workspace 就近发现命中它）
  fs.cpSync(path.join(e2eRoot, "fixtures", "workspace"), path.join(root, "examples"), {
    recursive: true,
  });

  const webPort = await freePort();
  const echoPort = await freePort();
  const listenPort = await freePort();
  const pids: number[] = [];
  const recordPid = (pid: number) => {
    pids.push(pid);
    fs.mkdirSync(path.dirname(stateFile), { recursive: true });
    fs.writeFileSync(
      stateFile,
      JSON.stringify({ sandboxRoot: root, pids, webPort, echoPort, listenPort }, null, 2),
    );
  };

  // 被测服务端：cwd 与二进制目录都在沙箱根 → UI/lib/examples 全部就近命中
  recordPid(
    spawnDetached(
      bin,
      ["web", "--addr", "127.0.0.1", "--port", String(webPort)],
      { cwd: root, logFile: path.join(logs, "web.log") },
    ),
  );
  const config = await waitHttpReady(`http://127.0.0.1:${webPort}/config.json`);

  // UDP echo 对端（run 冒烟回包源；探活 = 发探针等原样回显）
  recordPid(
    spawnDetached(bin, ["server", `127.0.0.1:${echoPort}`], {
      cwd: root,
      logFile: path.join(logs, "echo.log"),
    }),
  );
  await waitUdpEcho(echoPort);

  return { root, bin, webPort, echoPort, listenPort, pids, version: config.version };
}

function linkDir(target: string, linkPath: string): void {
  fs.symlinkSync(target, linkPath, process.platform === "win32" ? "junction" : "dir");
}

/** 清理残留：上一轮异常退出没 teardown 的服务端进程按 pid 收掉。 */
export function killStale(stateFile: string): void {
  try {
    const st = JSON.parse(fs.readFileSync(stateFile, "utf8")) as { pids?: number[] };
    for (const pid of st.pids ?? []) killPidGroup(pid);
  } catch {
    /* 无状态文件（首次运行）——无事可做 */
  }
}
