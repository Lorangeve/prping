// UTF-16 代理对（emoji）在 mac 前面时，列换算是否漂移
const BASE = '/mnt/mydata/mycoding/prping/target/debug/lib/bytes.pkt';
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

// 合成文件：注释行含 emoji + 中文 + mac(rand_mac())，正文一个合法 def 保证 parse 成功
const lines = [
  '# 🎉🎉 直接 mac(rand_mac()) 用（如随机源 MAC）',
  'x = hex("00")',
  'export:',
  '- x',
].join('\n');
const uri2 = 'file:///mnt/mydata/mycoding/prping/examples/_uiautf16.pkt';
notify('textDocument/didOpen', { textDocument: { uri: uri2, languageId: 'pkt', version: 1, text: lines } });
await new Promise((r) => setTimeout(r, 400));

const l = lines[0];
// UTF-16 列：🎉 每个 = 2 units。'# ' = 2；两个 emoji = 4 → 6；' ' → 7；'直接 ' → 10；mac @10-12
console.log('L1 UTF16[10..23] =', JSON.stringify(l.slice(10, 23)));
for (const ch of [10, 11, 12]) {
  const r = await request('textDocument/definition', { textDocument: { uri: uri2 }, position: { line: 0, character: ch } });
  let out = 'null';
  if (Array.isArray(r) && r[0]?.uri) {
    const p = r[0].uri.replace('file://', '');
    const ls = (await Bun.file(p).text()).split('\n');
    out = p.includes('bytes') ? 'bytes L' + (r[0].range.start.line + 1) + ' | ' + (ls[r[0].range.start.line] || '').slice(0, 40) : r[0].uri;
  } else { out = JSON.stringify(r); }
  console.log('char', ch, '=>', out);
}
process.exit(0);
