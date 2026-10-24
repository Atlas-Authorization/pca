#!/usr/bin/env node
// Compare every language implementation's canonical output to the TS oracle, BYTE FOR BYTE.
//   node check.mjs <outDir>
// Reads corpus.jsonl, oracle.jsonl, and impl-<lang>.jsonl + status-<lang>.txt produced by run.sh.
// Exit code 0 iff every ran implementation matches the oracle on every case (canon string AND hash, or an
// identical rejection). Non-zero if any divergence is found or if no implementation ran.
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
if (!out) { console.error('usage: node check.mjs <outDir>'); process.exit(2); }
const jl = (f) => readFileSync(join(out, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

const corpus = new Map(jl('corpus.jsonl').map((c) => [c.id, c]));
const oracle = new Map(jl('oracle.jsonl').map((o) => [o.id, o]));

const LANGS = ['go', 'python', 'ruby', 'php', 'dotnet', 'rust', 'java'];
const status = {};
for (const f of readdirSync(out)) { const m = /^status-(.+)\.txt$/.exec(f); if (m) status[m[1]] = readFileSync(join(out, f), 'utf8').trim(); }
for (const l of LANGS) if (!(l in status)) status[l] = 'not available on this box';

const impls = {};
for (const [l, s] of Object.entries(status)) {
  if (s === 'ran' && existsSync(join(out, `impl-${l}.jsonl`))) impls[l] = new Map(jl(`impl-${l}.jsonl`).map((o) => [o.id, o]));
}

const isErr = (r) => r === undefined || r.error !== undefined;
// canonical equality: both error (identical rejection) OR identical canon string AND identical hash.
function compare(o, r) {
  if (r === undefined) return { cls: 'NO-OUTPUT', detail: 'implementation produced no row for this id' };
  const oe = isErr(o), re = isErr(r);
  if (oe && re) return null;                     // both reject -> converge (out of profile)
  if (oe !== re) return { cls: 'ACCEPT-VS-REJECT', detail: `oracle=${oe ? 'ERROR' : 'accept'} impl=${re ? 'ERROR' : 'accept'}` };
  if (o.canon !== r.canon) return { cls: 'CANON-BYTES', detail: `oracle_canon=${JSON.stringify(o.canon)} impl_canon=${JSON.stringify(r.canon)}` };
  if (o.hash !== r.hash) return { cls: 'HASH', detail: `same canon string but oracle_hash=${o.hash} impl_hash=${r.hash}` };
  return null;
}

const byCls = {};
for (const c of corpus.values()) byCls[c.cls] = (byCls[c.cls] ?? 0) + 1;

const report = { outDir: out, corpus: { total: corpus.size, byClass: byCls }, status, implementations: {}, divergences: [] };
let anyDiverge = false;
const everyDivergence = [];

for (const [lang, rows] of Object.entries(impls)) {
  let compared = 0, agree = 0;
  const byClsDiv = {};
  const samples = [];
  for (const [id, o] of oracle) {
    const r = rows.get(id);
    const c = corpus.get(id);
    compared++;
    const d = compare(o, r);
    if (!d) { agree++; continue; }
    anyDiverge = true;
    byClsDiv[c.cls] = (byClsDiv[c.cls] ?? 0) + 1;
    const entry = { lang, id, cls: c.cls, raw: c.raw, divergence: d.cls, detail: d.detail };
    everyDivergence.push(entry);
    if (samples.length < 40) samples.push(entry);
  }
  report.implementations[lang] = { status: 'ran', compared, agree, divergent: compared - agree, byClassDivergent: byClsDiv, samples };
}
for (const [l, s] of Object.entries(status)) if (!(l in report.implementations)) report.implementations[l] = { status: s, compared: 0, agree: 0, divergent: 0 };

report.divergences = everyDivergence;

// cross-SDK (oracle excluded): do the language impls agree among THEMSELVES on each case?
const ranLangs = Object.keys(impls);
let crossDisagree = 0;
if (ranLangs.length > 1) {
  for (const [id] of corpus) {
    const keys = new Set(ranLangs.map((l) => { const r = impls[l].get(id); return isErr(r) ? 'ERR' : 'C=' + r.canon + '|H=' + r.hash; }));
    if (keys.size > 1) crossDisagree++;
  }
}
report.crossSdkDisagreements = crossDisagree;

writeFileSync(join(out, 'canon-report.json'), JSON.stringify(report, null, 2));

// ---- human summary ----
const ran = Object.entries(report.implementations).filter(([, v]) => v.status === 'ran');
const L = [];
L.push('# PCA adversarial canonical-form cross-language convergence', '');
L.push(`Corpus: ${corpus.size} adversarial canon cases.`, '');
L.push('| impl | status | compared | agree | divergent |', '|---|---|---|---|---|');
for (const l of LANGS) { const v = report.implementations[l]; L.push(`| ${l} | ${v.status} | ${v.compared || '-'} | ${v.agree || '-'} | ${v.divergent || (v.status === 'ran' ? 0 : '-')} |`); }
L.push('', `Implementations that ran: **${ran.map(([l]) => l).join(', ') || 'none'}** (plus the TypeScript oracle).`);
L.push(`Cross-SDK (oracle excluded) cases where the ran SDKs disagree among themselves: **${crossDisagree}**.`, '');
const total = ran.reduce((a, [, v]) => a + v.divergent, 0);
if (total === 0 && ran.length) {
  L.push(`## RESULT: ZERO DIVERGENCE across ${ran.length} language implementation(s) + the TS oracle, over all ${corpus.size} adversarial cases (byte-identical canonical string AND hash, or identical rejection).`);
} else if (!ran.length) {
  L.push('## RESULT: NO implementation ran (toolchains unavailable) — convergence NOT measured.');
} else {
  L.push(`## RESULT: ${total} DIVERGENCE(S) found. Enumerated below.`, '');
  for (const e of everyDivergence.slice(0, 200)) L.push(`- **${e.lang}** [${e.cls}] ${e.divergence} — id=${e.id} raw=${JSON.stringify(e.raw).slice(0, 120)} :: ${e.detail}`);
}
writeFileSync(join(out, 'CANON-REPORT.md'), L.join('\n') + '\n');
console.log(L.join('\n'));
process.exit(anyDiverge || !ran.length ? 1 : 0);
