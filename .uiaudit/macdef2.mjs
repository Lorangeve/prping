// bytes.pkt 内部：注释 mac(rand_mac()) 上分别点 mac 与 rand_mac，看各跳到哪
const BASE = '/mnt/mydata/mycoding/prping/target/debug/lib/bytes.pkt';
const uri = 'file://' + BASE;
const text = await Bun.file(BASE).text();
const cfg = await (await fetch('http://127.0.0.1:8788/config.json')).json();
const ws = new WebSocket('ws://127.0.0.1:8788/ws?token=' + cfg.token);
let seq = 0;
const pending = new Map();
ws.onmessage = (ev) => {
  const env = JSON.parse(ev.data);
  if (env.type === 'lsp' && env.message) {
    const m = env.message;
    if (m.id !== undefined && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  }
};
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
function request(method, params) {
  const id = ++seq;
  return new Promise((res) => {
    pending.set(id, res);
    ws.send(JSON.stringify({ type: 'lsp', message: { jsonrpc: '2.0', id, method, params } }));
    setTimeout(() => { if (pending.has(id)) { pending.delete(id); res({ TIMEOUT: true }); } }, 6000);
  });
}
function notify(method, params) { ws.send(JSON.stringify({ type: 'lsp', message: { jsonrpc: '2.0', method, params } })); }

await request('initialize', { processId: null, capabilities: {}, rootUri: null });
notify('initialized', {});
notify('textDocument/didOpen', { textDocument: { uri, languageId: 'pkt', version: 1, text } });
await new Promise((r) => setTimeout(r, 400));

const lines = text.split('\n');
function utf16(c) { return c; } // 本文件含中文——LSP 列按 UTF-16
function preview(loc) {
  if (!loc || !loc.uri) return JSON.stringify(loc);
  const p = loc.uri.replace('file://', '');
  const ls = Bun.file(p).text ? null : null;
  return p.replace('/mnt/mydata/mycoding/prping/', '') + ' L' + (loc.range.start.line + 1) + ':' + loc.range.start.character;
}
async function def(line, char, label) {
  const r = await request('textDocument/definition', {
    textDocument: { uri }, position: { line, character: char },
  });
  const raw = lines[line] ?? '';
  console.log('---', label, '@L' + (line + 1) + ':' + char, '|', JSON.stringify(raw.slice(0, 60)));
  if (r === null) { console.log('  => null'); return; }
  const locs = Array.isArray(r) ? r : [r];
  for (const loc of locs) {
    if (!loc?.uri) { console.log('  =>', JSON.stringify(loc)); continue; }
    const p = loc.uri.replace('file://', '');
    const t = await Bun.file(p).text();
    const ls = t.split('\n');
    console.log('  =>', p.replace('/mnt/mydata/mycoding/prping/', ''), 'L' + (loc.range.start.line + 1), '|', (ls[loc.range.start.line] || '').slice(0, 70));
  }
}

// L73(1-based, 0-based 72): "# tpl 的字节列表等宽直通 → 直接 mac(rand_mac()) 用（如随机源 MAC）"
// UTF-16 列：mac @21-23, ( @24, rand_mac @25-32
const commentLine = 72;
// 用 text.slice 校验列号（slice 按 UTF-16 码元，与 LSP 一致）
console.log('L73[21..33] =', JSON.stringify(lines[commentLine].slice(21, 34)));
await def(commentLine, 22, '注释里的 mac');
await def(commentLine, 27, '注释里的 rand_mac');
// 定义行自身对照
await def(73, 7, 'func rand_mac 定义名');
await def(90, 7, 'func mac 定义名');
process.exit(0);
