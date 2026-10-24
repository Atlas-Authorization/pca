// summarize.cjs <results.jsonl> [RESULT,...]  counts per result, then every non-KILLED_ASSERT mutant (or the listed results)
const fs = require('fs'); const [f, sel] = process.argv.slice(2);
const rs = fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse).sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
const c = {}; for (const r of rs) c[r.result] = (c[r.result] || 0) + 1;
console.log('total', rs.length, JSON.stringify(c));
const want = sel ? new Set(sel.split(',')) : null;
for (const r of rs) {
  if (want ? !want.has(r.result) : r.result === 'KILLED_ASSERT') continue;
  console.log(`${r.result} L${r.line} ${r.mutator} ${JSON.stringify(r.orig)} -> ${JSON.stringify(r.repl)}${r.error?.length ? '  [' + r.error[0] + ']' : ''}`);
}
