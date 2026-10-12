import fs from 'node:fs';
const root = process.cwd();
const dir = process.env.MB_RES ?? 'tools/pca-audit/mutbatch/results';
const spec = new Map();
for (const sf of fs.readdirSync(`${root}/tools/pca-audit/mutbatch`).filter((x) => /^spec-(full|call)-\d+\.json$/.test(x))) for (const m of JSON.parse(fs.readFileSync(`${root}/tools/pca-audit/mutbatch/${sf}`, 'utf8'))) spec.set(m.name, m);
const byEntry = new Map(); // generation-time entry index -> {items:[{m,res}]}
for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.log'))) for (const l of fs.readFileSync(`${dir}/${f}`, 'utf8').split('\n')) {
  const mm = /^(e\d+v\d+(?:n\d+)?): (SURVIVED|KILLED|ERROR|ABORT)/.exec(l); if (!mm) continue;
  const m = spec.get(mm[1]); if (!m || m.to.includes('(;)')) continue;
  const a = byEntry.get(m.entry) ?? []; a.push({ m, r: mm[2] }); byEntry.set(m.entry, a);
}
// map to CURRENT ledger entries by (pkg, file, line, original->replacement variant)
const led = JSON.parse(fs.readFileSync(`${root}/tools/pca-audit/mutation-equivalents.json`, 'utf8')).equivalents;
const mut = (e) => { const paren = !['StringLiteral', 'BlockStatement'].includes(e.mutator) && !/^(case |default:)/.test(e.replacement); const repl = paren ? '(' + e.replacement + ')' : e.replacement; const out = []; let k = -1; while ((k = e.line.indexOf(e.original, k + 1)) >= 0) out.push(e.line.slice(0, k) + repl + e.line.slice(k + e.original.length)); return out; };
const idx = new Map(); led.forEach((e, i) => { for (const t of mut(e)) idx.set(JSON.stringify([e.package || 'pca', e.file, e.line, t]), i); });
const res = { killed: [], surv: 0, other: [] };
for (const [gen, items] of byEntry) {
  const all = items.every((x) => x.r === 'KILLED'); const anyS = items.some((x) => x.r === 'SURVIVED');
  const m = items[0].m; const cur = idx.get(JSON.stringify([m.pkg, 'src/' + m.file, m.from, m.to]));
  if (all) res.killed.push({ gen, cur, m }); else if (anyS) res.surv++; else res.other.push({ gen, items: items.map((x) => x.r) });
}
console.log('entries', byEntry.size, 'all-killed', res.killed.length, 'survived', res.surv, 'other', res.other.length);
for (const k of res.killed.sort((a, b) => a.gen - b.gen)) { const e = k.cur === undefined ? null : led[k.cur]; console.log(`K gen=${k.gen} cur=${k.cur} ${k.m.pkg} ${k.m.file}\n    from: ${k.m.from.trim().slice(0, 150)}\n    to:   ${k.m.to.trim().slice(0, 150)}${e ? `\n    R: ${e.reason.slice(0, 200)}` : '\n    (no current ledger entry matches)'}`); }
for (const o of res.other) console.log('O', o.gen, o.items.join(','));
if (process.argv[2]) fs.writeFileSync(process.argv[2], JSON.stringify(res.killed.map((k) => k.cur).filter((x) => x !== undefined)));
