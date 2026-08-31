// pkt DSL 的 LSP 客户端（over PrpingClient 信封通道）。
//
// 服务端 = 现有 engine LSP（crates/prping-core/src/engine/eng/lsp.rs）：
// full sync（didChange 带全文）、publishDiagnostics 推送、completion / hover /
// documentSymbol / definition。这里只实现编辑器闭环所需的部分；请求 id 与
// JSON-RPC 应答按 id 关联，服务端通知（publishDiagnostics）走回调。

export interface LspDiagnostic {
  line: number; // 0-based
  character: number;
  message: string;
  severity: number; // 1=error 2=warning
}

export class LspClient {
  private seq = 0;
  private pending = new Map<number, (v: any) => void>();
  private docVersion = 0;
  private opened = false;
  private uri = "file:///scratch.pkt";
  private pendingText = "";
  /** 最近一次同步到服务端的全文（冗余 didChange 去重——见 change 注释）。 */
  private lastSent = "";

  /** publishDiagnostics 回调（LSP 诊断，0-based 行列）。 */
  onDiagnostics: ((diags: LspDiagnostic[]) => void) | null = null;

  constructor(private client: { lspSend(m: any): void }) {}

  /** 接入服务端透传的 LSP 消息（在 PrpingClient.onLsp 里调用）。 */
  handle(message: any): void {
    if (message?.method === "textDocument/publishDiagnostics") {
      const diags: LspDiagnostic[] = (message.params?.diagnostics ?? []).map((d: any) => ({
        line: d.range?.start?.line ?? 0,
        character: d.range?.start?.character ?? 0,
        message: d.message ?? "",
        severity: d.severity ?? 1,
      }));
      this.onDiagnostics?.(diags);
      return;
    }
    if (message?.id !== undefined && this.pending.has(message.id)) {
      const resolve = this.pending.get(message.id)!;
      this.pending.delete(message.id);
      resolve(message.result ?? null);
    }
  }

  /** 重建会话（连接/重连后调用）：initialize + initialized + didOpen。 */
  start(uri: string, text: string): void {
    this.uri = uri;
    this.docVersion = 0;
    this.opened = false;
    this.lastSent = text;
    this.lspRequest("initialize", {
      processId: null,
      capabilities: {},
      rootUri: null,
    }).then(() => {
      this.client.lspSend({ jsonrpc: "2.0", method: "initialized", params: {} });
      this.opened = true;
      this.client.lspSend({
        jsonrpc: "2.0",
        method: "textDocument/didOpen",
        params: {
          textDocument: {
            uri: this.uri,
            languageId: "pkt",
            version: ++this.docVersion,
            text,
          },
        },
      });
    });
  }

  /**
   * 全文同步（防抖 250ms，由调用方控制；补全/悬停源在查询前也会调用）。
   *
   * 内容未变时跳过——这不是省流量的优化，是修 hover 的关键：didChange 必然
   * 引发服务端 publishDiagnostics → 前端 applyDiagnostics → 视图更新，而 CM
   * hoverTooltip 在视图更新时会重启 hover（update() → 20ms 后 startHover），
   * 异步源还没等到应答 pending 就被顶掉——tooltip 永远出不来。补全/悬停的
   * 「先同步再查询」只在文本真的变过时才发。
   */
  change(text: string): void {
    if (!this.opened || text === this.lastSent) return;
    this.lastSent = text;
    this.pendingText = text;
    const version = ++this.docVersion;
    this.client.lspSend({
      jsonrpc: "2.0",
      method: "textDocument/didChange",
      params: {
        textDocument: { uri: this.uri, version },
        contentChanges: [{ text }],
      },
    });
    void this.pendingText;
  }

  /** 切换文档（打开库文件）：重放 didOpen。 */
  openDoc(uri: string, text: string): void {
    if (uri === this.uri && this.opened) return;
    this.start(uri, text);
  }

  lspRequest(method: string, params: unknown): Promise<any> {
    return new Promise((resolve) => {
      const id = ++this.seq;
      this.pending.set(id, resolve);
      this.client.lspSend({ jsonrpc: "2.0", id, method, params });
      // 超时兜底（服务端忙/断线时不悬挂补全）
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          resolve(null);
        }
      }, 3000);
    });
  }

  completion(line: number, character: number): Promise<any> {
    return this.lspRequest("textDocument/completion", {
      textDocument: { uri: this.uri },
      position: { line, character },
    });
  }

  hover(line: number, character: number): Promise<any> {
    return this.lspRequest("textDocument/hover", {
      textDocument: { uri: this.uri },
      position: { line, character },
    });
  }

  /** 文档符号（大纲用）：component def / func / export / 默认导出。 */
  documentSymbol(): Promise<any> {
    return this.lspRequest("textDocument/documentSymbol", {
      textDocument: { uri: this.uri },
    });
  }

  get documentUri(): string {
    return this.uri;
  }
}
