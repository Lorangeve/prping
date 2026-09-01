// prping web —— WS 信封传输层。
//
// 一条 WebSocket 上跑两种消息（服务端 crates/prping-core/src/web/ws.rs）：
//   { type: "lsp",    message }            LSP JSON-RPC 双向透传
//   { type: "result", id, ok, data|error } request() 的应答
//   { type: "error",  message }            服务端拒绝（坏信封等）
// request() 以自增 id 关联应答；断线自动重连（指数退避），重连后由上层重建
// LSP 会话（initialize/didOpen 重放）。

export type Status = "connected" | "connecting" | "closed";

/** run 信封参数：工作区内 .pkt/.pktl + packet 子命令选项（未给的字段不发）。 */
export interface RunOpts {
  name: string;
  target?: string;
  params?: Record<string, string>;
  globals?: Record<string, string>;
  count?: number;
  /** 数字 = --wait SECS（发后等一个应答）；true = 裸 --wait（持续监听） */
  wait?: number | true;
  raw?: boolean;
  iface?: string;
  out?: string;
  /** --json：JSONL 结构化输出（前端按行渲染包/步骤/汇总） */
  json?: boolean;
}

/** run_exit 信封数据：code null = 被 kill（stop）。 */
export interface RunExit {
  code: number | null;
  stopped: boolean;
  truncated: boolean;
}

export class PrpingClient {
  private ws: WebSocket | null = null;
  private seq = 0;
  private pending = new Map<number, (v: any) => void>();
  private retry = 0;
  private closedByUs = false;
  private timer: ReturnType<typeof setTimeout> | null = null;

  /** LSP JSON-RPC 消息回调（服务端 → 客户端方向）。 */
  onLsp: ((message: any) => void) | null = null;
  onStatus: ((s: Status) => void) | null = null;
  /** packet 运行输出（run_out 信封，流式；stream = "out" | "err"）。 */
  onRunOut: ((run: string, stream: string, text: string) => void) | null = null;
  /** packet 运行结束（run_exit 信封）。 */
  onRunExit: ((run: string, exit: RunExit) => void) | null = null;

  connect(): void {
    this.closedByUs = false;
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    this.setStatus("connecting");
    const ws = new WebSocket(`${proto}//${location.host}/ws`);
    this.ws = ws;
    ws.onopen = () => {
      this.retry = 0;
      this.setStatus("connected");
    };
    ws.onmessage = (ev) => {
      let env: any;
      try {
        env = JSON.parse(ev.data as string);
      } catch {
        return;
      }
      if (env.type === "lsp") {
        this.onLsp?.(env.message);
      } else if (env.type === "run_out") {
        this.onRunOut?.(env.run, env.stream, env.text);
      } else if (env.type === "run_exit") {
        this.onRunExit?.(env.run, {
          code: typeof env.code === "number" ? env.code : null,
          stopped: !!env.stopped,
          truncated: !!env.truncated,
        });
      } else if (env.type === "result" && typeof env.id === "number") {
        const resolve = this.pending.get(env.id);
        this.pending.delete(env.id);
        resolve?.(env);
      }
      // type === "error"：无 id 关联，忽略（上层以超时兜底）
    };
    ws.onclose = () => {
      this.ws = null;
      this.setStatus("closed");
      // 挂起的请求以失败收场，避免调用方永久悬挂
      for (const resolve of this.pending.values()) resolve({ ok: false, error: "disconnected" });
      this.pending.clear();
      if (this.closedByUs) return;
      // 指数退避重连：0.5s → 1s → 2s → 4s（上限）
      const delay = Math.min(500 * 2 ** this.retry, 4000);
      this.retry += 1;
      this.timer = setTimeout(() => this.connect(), delay);
    };
    ws.onerror = () => ws.close();
  }

  close(): void {
    this.closedByUs = true;
    if (this.timer) clearTimeout(this.timer);
    this.ws?.close();
    this.ws = null;
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  private setStatus(s: Status): void {
    this.onStatus?.(s);
  }

  private sendRaw(obj: Record<string, unknown>): void {
    // 仅 OPEN 态可发（CONNECTING/CLOSED 下 send 抛 InvalidStateError）；未连接时
    // 静默丢弃——连接建立后上层经 onStatus("connected") 重放会话初始化
    if (this.ws?.readyState !== WebSocket.OPEN) return;
    this.ws.send(JSON.stringify(obj));
  }

  /** 发送带 id 的信封并等待 result 应答。 */
  request(payload: Record<string, unknown>): Promise<any> {
    return new Promise((resolve) => {
      if (!this.isConnected) {
        resolve({ ok: false, error: "disconnected" });
        return;
      }
      const id = ++this.seq;
      this.pending.set(id, resolve);
      this.sendRaw({ ...payload, id });
    });
  }

  /** LSP JSON-RPC 消息出方向（通知或请求，服务端原样透传给会话）。 */
  lspSend(message: Record<string, unknown>): void {
    this.sendRaw({ type: "lsp", message });
  }

  /** 内存文本分析（engine --json 同构文档）。 */
  analyze(uri: string, text: string, params: Record<string, string> = {}): Promise<any> {
    return this.request({ type: "analyze", uri, text, params });
  }

  listLibs(): Promise<any> {
    return this.request({ type: "list" });
  }

  readLib(name: string): Promise<any> {
    return this.request({ type: "read", name });
  }

  /** 工作区目录树（默认 examples；应答含 root/writable/entries）。 */
  tree(): Promise<any> {
    return this.request({ type: "tree" });
  }

  /** 读工作区文件（可写；相对路径，'/' 分隔）。 */
  readWs(name: string): Promise<any> {
    return this.request({ type: "read", root: "ws", name });
  }

  /** 保存工作区文件（新建或覆盖）。 */
  saveFile(name: string, text: string): Promise<any> {
    return this.request({ type: "save", name, text });
  }

  /** 删除工作区文件。 */
  deleteFile(name: string): Promise<any> {
    return this.request({ type: "delete", name });
  }

  /** 重命名/移动工作区文件（目标已存在会被服务端拒绝）。 */
  renameFile(from: string, to: string): Promise<any> {
    return this.request({ type: "rename", from, to });
  }

  /** 新建工作区目录（父目录链一并创建）。 */
  mkdir(name: string): Promise<any> {
    return this.request({ type: "mkdir", name });
  }

  /** 打开自定义工作区文件夹（空串重置为默认 examples）。 */
  openFolder(path: string): Promise<any> {
    return this.request({ type: "workspace", path });
  }

  /** 浏览目录（文件夹选择对话框数据源；path 缺省 = 服务端用户主目录）。 */
  browse(path?: string): Promise<any> {
    return this.request(path ? { type: "browse", path } : { type: "browse" });
  }

  /** 运行工作区 .pkt/.pktl：应答 = 启动 ack（data.run = run_id）；输出/退出走
   *  onRunOut / onRunExit 推送。 */
  run(opts: RunOpts): Promise<any> {
    return this.request({ type: "run", ...opts });
  }

  /** 停止活跃运行：带 run id 停单个（任务管理）；缺省停本连接全部。
   *  kill 后子进程由服务端 waiter 收尸，终态经 run_exit 推送。 */
  runStop(run?: string): Promise<any> {
    return this.request(run ? { type: "run_stop", run } : { type: "run_stop" });
  }
}
