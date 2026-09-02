// ssh.pkt 注释里的 @param mac 点击复测
const BASE = '/mnt/mydata/mycoding/prping/target/debug/lib/ssh.pkt';
const uri = 'file://' + BASE;
const text = await Bun.file(BASE).text();
const cfg = await (await fetch('http://127.0.0.1:8788/config.json')).json();
const ws = new WebSocket('ws://127.0.0.1:8788/ws?token=' + cfg.token);
let seq = 0; const pending = new Map();
ws.onmessage = (ev) => { const env = JSON.parse(ev.data); if (env.type === 'lsp' && env.message) { const m = env.message; if (m.id !== undefined && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } } };
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
function request(method, params) { const id = ++seq; return new Promise((res) => { pending.set(id, res); ws.send(JSON.stringify({ type: 'lsp', message: { jsonrpc: '2.0', id, method, params } })); setTimeout(() => { if (pending.has(id)) { pending.delete(id); res({ TIMEOUT: true }); } }, 6000); }); }
function notify(method, params) { ws.send(JSON.stringify({ type: 'lsp', message: { jsonrpc: '2.0', method, params } })); }
await request('initialize', { processId: null, capabilities: {}, rootUri: null });
notify('initialized', {});
notify('textDocument/didOpen', { textDocument: { uri, languageId: 'pkt', version: 1, text } });
await new Promise((r) => setTimeout(r, 400));
const lines = text.split('\n');
const l = lines[33];
console.log('L34 =', JSON.stringify(l));
const macCol = l.indexOf('mac');
console.log('mac at col', macCol);
const r = await request('textDocument/definition', { textDocument: { uri }, position: { line: 33, character: macCol + 1 } });
console.log('definition =>', JSON.stringify(r));
const h = await request('textDocument/hover', { textDocument: { uri }, position: { line: 33, character: macCol + 1 } });
console.log('hover =>', JSON.stringify(h).slice(0, 400));
process.exit(0);
