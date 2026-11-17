// A small local page showing live decisions: it tails the proxies' audit logs (read-only) and renders one row per decision.
import { existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';

const FILES = { http: '/data/audit/http.audit.jsonl', mcp: '/data/audit/mcp.audit.jsonl' };

function decisions() {
  const out = [];
  for (const [source, path] of Object.entries(FILES)) {
    if (!existsSync(path)) continue;
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const r = JSON.parse(line);
        const f = r.checks ?? {};
        out.push({ source, seq: r.seq, at: r.at, verb: r.verb, resource: r.resource, mode: f.mode ?? '', allowed: f.allowed ?? '', code: f.code ?? '', reason: f.reason ?? '', hash: String(r.hash ?? '').slice(0, 10) });
      } catch { /* a torn last line: skipped until it is complete */ }
    }
  }
  return out.sort((a, b) => a.at - b.at).slice(-300);
}

const PAGE = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PCA in a box</title>
<style>
:root{color-scheme:light dark;--bg:#fff;--fg:#17171c;--mut:#6b6b76;--ok:#117a3d;--no:#b3261e;--warn:#8a5a00;--line:#e3e3ea}
@media(prefers-color-scheme:dark){:root{--bg:#101014;--fg:#ececf1;--mut:#9a9aa6;--ok:#4cc27a;--no:#ff7b72;--warn:#e3b341;--line:#2a2a33}}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:14px/1.45 ui-sans-serif,system-ui,sans-serif}
h1{font-size:18px;margin:0 0 4px}p{color:var(--mut);margin:0 0 12px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}code{font:12px ui-monospace,monospace}
.ok{color:var(--ok);font-weight:600}.no{color:var(--no);font-weight:600}.would{color:var(--warn);font-weight:600}
.wrap{overflow-x:auto}
</style>
<h1>PCA in a box: live decisions</h1><p id="s">waiting for the first call...</p>
<div class="wrap"><table><thead><tr><th>time</th><th>via</th><th>mode</th><th>action</th><th>resource</th><th>decision</th><th>why</th></tr></thead><tbody id="b"></tbody></table></div>
<script>
const b=document.getElementById('b'),s=document.getElementById('s');
function cell(tr,t,c){const td=tr.insertCell();td.textContent=t;if(c)td.className=c;return td}
async function tick(){
 try{const r=await (await fetch('/api/decisions',{cache:'no-store'})).json();
  b.replaceChildren(...r.slice().reverse().map(d=>{const tr=document.createElement('tr');
   cell(tr,new Date(d.at).toLocaleTimeString());cell(tr,d.source);cell(tr,d.mode);cell(tr,d.verb);cell(tr,d.resource);
   const allowed=d.allowed==='true';const would=!allowed&&d.mode==='observe';
   cell(tr,allowed?'allowed':would?'would be refused':'refused',allowed?'ok':would?'would':'no');cell(tr,(d.code+' '+d.reason).trim());return tr}));
  s.textContent=r.length+' decisions (newest first). Receipts are hash-chained in /data/audit; verify with: pca-proxy audit verify <file>'}catch(e){s.textContent='dashboard cannot reach its data: '+e}
}
tick();setInterval(tick,1000);
</script>`;

createServer((req, res) => {
  if (req.url === '/api/decisions') { res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); return res.end(JSON.stringify(decisions())); }
  if (req.url === '/' || req.url === '/index.html') { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'" }); return res.end(PAGE); }
  res.writeHead(404); res.end();
}).listen(8080, '0.0.0.0', () => console.log('dashboard on :8080'));
