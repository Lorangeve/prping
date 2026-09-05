// global-setup：清残留进程 → 搭沙箱 → 起 web + UDP echo → 把运行时参数写进
// 环境变量（playwright worker 继承）；pid 随 spawn 逐个落进状态文件（teardown 收尸）。
import { stateFile } from "./helpers/paths";
import { buildSandbox, killStale } from "./helpers/sandbox";

export default async function globalSetup(): Promise<void> {
  killStale(stateFile);
  const sb = await buildSandbox(stateFile);

  process.env.PRPING_WEB_URL = `http://127.0.0.1:${sb.webPort}/`;
  process.env.PRPING_ECHO_PORT = String(sb.echoPort);
  process.env.PRPING_LISTEN_PORT = String(sb.listenPort);

  console.log(`[webui-e2e] sandbox: ${sb.root}`);
  console.log(`[webui-e2e] prping web v${sb.version} → ${process.env.PRPING_WEB_URL}`);
}
