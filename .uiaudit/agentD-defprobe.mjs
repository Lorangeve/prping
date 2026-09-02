// Agent D：真实 web 服务器 LSP definition 探针（复现 QA Ctrl+Click 路径）。
const uri = 'file:///mnt/mydata/mycoding/prping/examples/bad_network/http_get.pkt';
const text = await Bun.file('/mnt/mydata/mycoding/prping/examples/bad_network/http_get.pkt').text();

const ws = new WebSocket('ws://127.0.0.1:38081/ws');
let seq = 0;
const pending = new Map();
const notifications = [];
ws.onmessage = (ev) => {
  const env = JSON.parse(ev.data);
  if (env.type === 'lsp' && env.message) {
    const m = env.message;
    if (m.id !== undefined && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    } else {
      notifications.push(m);
    }
  } else {
    notifications.push(env);
  }
};
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

function send(obj) { ws.send(JSON.stringify(obj)); }
function request(method, params) {
  const id = ++seq;
  return new Promise((res) => {
    pending.set(id, res);
    send({ type: 'lsp', message: { jsonrpc: '2.0', id, method, params } });
    setTimeout(() => { if (pending.has(id)) { pending.delete(id); res({ TIMEOUT: true }); } }, 5000);
  });
}
function notify(method, params) { send({ type: 'lsp', message: { jsonrpc: '2.0', method, params } }); }

await request('initialize', { processId: null, capabilities: {}, rootUri: null });
notify('initialized', {});
notify('textDocument/didOpen', { textDocument: { uri, languageId: 'pkt', version: 1, text } });
await new Promise((r) => setTimeout(r, 300));

const syms = await request('textDocument/documentSymbol', { textDocument: { uri } });
console.log('documentSymbol:', JSON.stringify(syms.result));

for (const [id, line, ch, what] of [[10, 4, 15, 'use(http_req) 使用处'], [11, 3, 11, 'http( 调用'], [12, 3, 0, 'http_req 定义处']]) {
  const r = await request('textDocument/definition', { textDocument: { uri }, position: { line, character: ch } });
  console.log(`definition(${what}) line=${line} ch=${ch} ->`, JSON.stringify(r.result ?? r));
}
console.log('notifications:', notifications.map((n) => n.method ?? n.type).join(','));
ws.close();
