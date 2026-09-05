// 进程与网络探活工具：空闲端口获取、脱离进程组的子进程拉起/击杀、
// HTTP/UDP 就绪等待。被 global-setup（起服务端）与 global-teardown（收尸）共用。
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import dgram from "node:dgram";

/** /config.json 应答（web/http.rs 下发契约）。 */
export interface WebConfig {
  version: string;
  wsPath: string;
  token: string;
  builtins: string[];
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** 借内核取一个空闲 TCP 端口（bind :0 后关闭）。close 到实际占用之间存在被
 *  复用的理论窗口，冒烟环境可接受；需绝对固定时用 PRPING_* 环境变量。 */
export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

/** 脱离父进程组启动子进程（输出追加进日志文件；返回 pid 供 teardown 按组击杀）。
 *  detached + 进程组：web 服务端派生的 packet 子命令随组一并收掉，无孤儿。 */
export function spawnDetached(
  cmd: string,
  args: string[],
  opts: { cwd: string; logFile: string },
): number {
  const out = fs.openSync(opts.logFile, "a");
  const child = spawn(cmd, args, {
    cwd: opts.cwd,
    detached: true,
    stdio: ["ignore", out, out],
  });
  child.unref();
  return child.pid!;
}

/** 击杀整个进程组（先 TERM 后 KILL 兜底；Windows 退化为单进程 kill）。 */
export function killPidGroup(pid: number): void {
  if (process.platform === "win32") {
    try { process.kill(pid); } catch { /* 已退出 */ }
    return;
  }
  try { process.kill(-pid, "SIGTERM"); } catch { /* 已退出 */ }
  const timer = setTimeout(() => {
    try { process.kill(-pid, "SIGKILL"); } catch { /* 已退出 */ }
  }, 1500);
  timer.unref();
}

/** 轮询 /config.json 直至 200（web 服务端就绪），返回启动配置。 */
export async function waitHttpReady(url: string, timeoutMs = 60_000): Promise<WebConfig> {
  const deadline = Date.now() + timeoutMs;
  let lastErr = "";
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return (await res.json()) as WebConfig;
      lastErr = `HTTP ${res.status}`;
    } catch (e) {
      lastErr = String(e);
    }
    await sleep(250);
  }
  throw new Error(`web 服务端未就绪（${url}）：${lastErr}`);
}

/** UDP echo 探活：循环发探针数据报（500ms 重发），等 prping server 原样回显。
 *  必须重发：server 刚 spawn 未完成 bind 时发出的第一包会被内核静默丢弃
 *  （未 connect 的 UDP socket 收不到 ICMP 端口不可达），单发探针会假超时。 */
export async function waitUdpEcho(port: number, timeoutMs = 15_000): Promise<void> {
  const probe = Buffer.from(`prping-webui-probe ${process.pid}\n`);
  await new Promise<void>((resolve, reject) => {
    const sock = dgram.createSocket("udp4");
    const timer = setTimeout(() => {
      sock.close();
      reject(new Error(`UDP echo 探活超时（127.0.0.1:${port}）`));
    }, timeoutMs);
    const resend = setInterval(() => sock.send(probe, port, "127.0.0.1"), 500);
    sock.on("message", (msg, rinfo) => {
      if (rinfo.port !== port || !msg.equals(probe)) return;
      clearInterval(resend);
      clearTimeout(timer);
      sock.close();
      resolve();
    });
    sock.on("error", (e) => {
      clearInterval(resend);
      clearTimeout(timer);
      sock.close();
      reject(e);
    });
    sock.send(probe, port, "127.0.0.1");
  });
}
