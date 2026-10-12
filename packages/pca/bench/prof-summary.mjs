// Summarise V8 .cpuprofile files: top self-time functions and top files. Usage: node prof-summary.mjs <dir>
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
const dir = process.argv[2];
for (const f of readdirSync(dir).filter((x) => x.endsWith('.cpuprofile'))) {
  const p = JSON.parse(readFileSync(join(dir, f), 'utf8'));
  const byId = new Map(p.nodes.map((n) => [n.id, n]));
  const cnt = new Map(); for (const s of p.samples) cnt.set(s, (cnt.get(s) ?? 0) + 1);
  const avg = (p.endTime - p.startTime) / p.samples.length / 1000;
  const fn = new Map(), file = new Map();
  for (const [id, c] of cnt) { const n = byId.get(id); const k = `${n.callFrame.functionName || '(anon)'} ${n.callFrame.url.split('/').slice(-3).join('/')}:${n.callFrame.lineNumber}`; fn.set(k, (fn.get(k) ?? 0) + c * avg); const u = n.callFrame.url.split('/').slice(-4).join('/'); file.set(u, (file.get(u) ?? 0) + c * avg); }
  const top = (m, k) => [...m].sort((a, b) => b[1] - a[1]).slice(0, k).map(([n, ms]) => `${ms.toFixed(0).padStart(7)} ms  ${n}`).join('\n');
  console.log(`== ${f} total ${((p.endTime - p.startTime) / 1000).toFixed(0)} ms\n-- functions\n${top(fn, 25)}\n-- files\n${top(file, 15)}`);
}

// Attribution: for every sample, charge its time to the innermost frame that belongs to our own code
// (packages/pca/dist, an API server's src/, or pca-verified-core), so library time is attributed to the PCA/API function that caused it.
for (const f of readdirSync(dir).filter((x) => x.endsWith('.cpuprofile'))) {
  const p = JSON.parse(readFileSync(join(dir, f), 'utf8'));
  const parent = new Map();
  for (const n of p.nodes) for (const c of n.children ?? []) parent.set(c, n.id);
  const byId = new Map(p.nodes.map((n) => [n.id, n]));
  const avg = (p.endTime - p.startTime) / p.samples.length / 1000;
  const own = (n) => /packages\/pca\/dist|\/api\/src\/|pca-verified-core/.test(n.callFrame.url);
  const charge = new Map();
  for (const s of p.samples) {
    let id = s;
    while (id !== undefined && !own(byId.get(id))) id = parent.get(id);
    const n = id === undefined ? null : byId.get(id);
    const k = n ? `${n.callFrame.functionName || '(anon)'} ${n.callFrame.url.split('/').slice(-2).join('/')}:${n.callFrame.lineNumber}` : '(outside own code)';
    charge.set(k, (charge.get(k) ?? 0) + avg);
  }
  console.log(`== ${f}: innermost own-code frame\n` + [...charge].sort((a, b) => b[1] - a[1]).slice(0, 25).map(([k, ms]) => `${ms.toFixed(0).padStart(7)} ms  ${k}`).join('\n'));
}
