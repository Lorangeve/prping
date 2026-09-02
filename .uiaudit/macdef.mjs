// 复现：headers.pkt 里 Ctrl+Click mac( 的 definition 去了哪
const BASE = '/mnt/mydata/mycoding/prping/target/debug/lib/headers.pkt';
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
function show(n) { return 'L' + (n + 1) + ': ' + (lines[n] || '').slice(0, 90); }

async function def(line, char, label) {
  const r = await request('textDocument/definition', {
    textDocument: { uri }, position: { line, character: char },
  });
  console.log('---', label, '@ L' + (line + 1) + ':' + char, JSON.stringify(lines[line]?.slice(char - 4, char + 12)));
  if (r === null) { console.log('  => null (无定义)'); return; }
  const locs = Array.isArray(r) ? r : [r];
  for (const loc of locs) {
    if (!loc || !loc.uri) { console.log('  =>', JSON.stringify(loc)); continue; }
    const p = loc.uri.replace('file://', '');
    const tf = Bun.file(p);
    let preview = '(unreadable)';
    try {
      const t = await tf.text();
      const ls = t.split('\n');
      preview = 'L' + (loc.range.start.line + 1) + ': ' + (ls[loc.range.start.line] || '').slice(0, 100);
    } catch {}
    console.log('  =>', p.replace('/mnt/mydata/mycoding/prping/', ''), '|', preview);
  }
}

// L53(1-based): concat(mac(dst_mac), mac(src_mac), be16(ethertype))
await def(52, 9, 'mac( 第一处（concat 内）');
await def(52, 24, 'mac( 第二处');
// L95(1-based): mac(sha)
await def(94, 2, 'arp 里的 mac(sha)');
// dst_mac 参数位置（对照：应不是 mac）
await def(52, 14, 'dst_mac 参数（对照）');
// L73(1-based) bytes.pkt 注释提到的行——headers 里没有；补一个 bytes.pkt 自身定义处对照
process.exit(0);
