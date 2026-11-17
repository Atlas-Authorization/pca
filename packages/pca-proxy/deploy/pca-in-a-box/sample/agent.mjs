// The sample agent: a script that does what an AI agent would, through the proxies. It holds no API credential and no SDK.
//   node agent.mjs --expect observe|enforce
// Observe mode: the routine work, all of it goes through and is recorded; that is what the grant is learned from. Enforce mode: the same
// routine work (inside the signed grant, so it works) plus calls nobody ever observed or approved (outside the grant, so refused). It exits 1 if any call behaves differently from what the mode expects; the audit log is the
// real record (tools/check.mjs reads it).
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const i = process.argv.indexOf('--expect');
const expect = process.argv[i + 1];
if (expect !== 'observe' && expect !== 'enforce') throw new Error('usage: agent.mjs --expect observe|enforce');
const BASE = process.env.PCA_BOX_PROXY_URL ?? 'http://pca-proxy:8788';
const results = [];
const record = (label, got, should) => {
  const ok = got === should;
  results.push(ok);
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label.padEnd(34)} ${got ? 'worked' : 'refused'}${ok ? '' : `  (expected: ${should ? 'worked' : 'refused'})`}`);
};

// ---- the orders API, through pca-proxy (writes first: a read relays untrusted content, after which a write waits for a human) ----
async function http(method, path, body) {
  const r = await fetch(BASE + path, { method, headers: body ? { 'content-type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  await r.text();
  return r.status >= 200 && r.status < 300;
}
const enforce = expect === 'enforce';
console.log(`orders API via ${BASE} (${expect} mode)`);
record('POST /orders (create an order)', await http('POST', '/orders', { sku: 'widget', qty: 2 }), true);
record('GET /orders (list)', await http('GET', '/orders'), true);
record('GET /orders/1 (read one)', await http('GET', '/orders/1'), true);
if (enforce) {
  record('POST /orders/1/refund (outside the grant)', await http('POST', '/orders/1/refund'), false);
  record('DELETE /orders/2 (outside the grant)', await http('DELETE', '/orders/2'), false);
  record('GET /admin/export (not in the API)', await http('GET', '/admin/export'), false);
}

// ---- the notes MCP server, through `pca-proxy mcp` over stdio (what Claude Code or Cursor would launch) ----
console.log(`notes MCP server via pca-proxy mcp (${expect} mode)`);
const proxy = spawn('pca-proxy', ['mcp', '--config', '/data/config/pca-proxy-mcp.yaml'], { stdio: ['pipe', 'pipe', 'inherit'], env: process.env });
const pending = new Map();
createInterface({ input: proxy.stdout }).on('line', (l) => { try { const m = JSON.parse(l); pending.get(m.id)?.(m); } catch { /* not a response */ } });
let nextId = 1;
const rpc = (method, params) => new Promise((resolve, reject) => {
  const id = nextId++;
  const t = setTimeout(() => reject(new Error(`${method}: no answer in 30s`)), 30_000);
  pending.set(id, (m) => { clearTimeout(t); resolve(m); });
  proxy.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
});
const tool = async (name, args) => { const m = await rpc('tools/call', { name, arguments: args }); return m.error === undefined && !m.result?.isError; };
await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'box-agent', version: '1' } });
proxy.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
const listed = (await rpc('tools/list', {})).result?.tools?.map((t) => t.name) ?? [];
console.log(`     tools the model sees: ${listed.join(', ') || '(none)'}`);
record('create_note', await tool('create_note', { text: 'call the supplier' }), true);
record('search_notes', await tool('search_notes', { q: 'call' }), true);
if (enforce) record('delete_note (outside the grant)', await tool('delete_note', { id: 1 }), false);
proxy.stdin.end();

const bad = results.filter((x) => !x).length;
console.log(bad === 0 ? `\nall ${results.length} calls behaved as ${expect} mode should` : `\n${bad} call(s) did not behave as ${expect} mode should`);
process.exitCode = bad === 0 ? 0 : 1;
setTimeout(() => process.exit(), 500).unref();
