// 全场景复测：headers 内偏移修正 + 用户自建文件场景
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

async function defOpen(uri, text, line, char, label) {
  notify('textDocument/didOpen', { textDocument: { uri, languageId: 'pkt', version: 1, text } });
  await new Promise((r) => setTimeout(r, 350));
  const r = await request('textDocument/definition', {
    textDocument: { uri }, position: { line, character: char },
  });
  const lines = text.split('\n');
  console.log('---', label, '@L' + (line + 1) + ':' + char, '|', JSON.stringify((lines[line] || '').slice(0, 60)));
  if (r === null) { console.log('  => null'); return; }
  const locs = Array.isArray(r) ? r : [r];
  for (const loc of locs) {
    if (!loc?.uri) { console.log('  =>', JSON.stringify(loc)); continue; }
    const p = loc.uri.replace('file://', '');
    const t = await Bun.file(p).text();
    const ls = t.split('\n');
    console.log('  =>', p.replace('/mnt/mydata/mycoding/prping/', ''), 'L' + (loc.range.start.line + 1) + ':' + loc.range.start.character, '|', (ls[loc.range.start.line] || '').slice(0, 70));
  }
}

const H = '/mnt/mydata/mycoding/prping/target/debug/lib/headers.pkt';
const hText = await Bun.file(H).text();
const hUri = 'file://' + H;
const hl = hText.split('\n');
// 找精确列：L53 concat(mac(...)) 与 L95 mac(sha)
const l53 = hl[52], l95 = hl[94];
console.log('L53 =', JSON.stringify(l53));
console.log('L95 =', JSON.stringify(l95));
const mac53 = l53.indexOf('mac(');
const mac95 = l95.indexOf('mac(');
const dst = l53.indexOf('dst_mac');
const src = l53.indexOf('src_mac');
await defOpen(hUri, hText, 52, mac53 + 1, 'headers mac( 第一处');
await defOpen(hUri, hText, 52, dst + 2, 'headers dst_mac 中间');
await defOpen(hUri, hText, 52, src + 2, 'headers src_mac 中间');
await defOpen(hUri, hText, 94, mac95 + 1, 'headers arp mac(sha)');

// 用户自建文件场景：无 import 直接调 mac(
const U = '/mnt/mydata/mycoding/prping/examples/_macdef_probe.pkt';
const uText = 'probe = mac("aa:bb:cc:dd:ee:ff")\n';
await defOpen('file://' + U, uText, 0, 10, '自建文件 mac( 调用');
process.exit(0);
