#!/usr/bin/env node
// Writes (a) one SMALL minimal vector per adversarial class with every implementation's verdict (evidence that the class is
// rejected everywhere), and (b) the minimal reproducer of every divergence group (if any), into counterexamples/.
//   node extract-counterexamples.mjs out
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const out = process.argv[2] ?? 'out';
const here = dirname(fileURLToPath(import.meta.url));
const rep = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
const lines = (f) => readFileSync(join(out, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const corpus = new Map(lines('corpus.jsonl').map((c) => [c.id, c]));
const metas = lines('meta.jsonl');
const oracle = new Map(lines('oracle.jsonl').map((c) => [c.id, c]));
const impls = {};
for (const n of rep.implementations) impls[n] = new Map(lines(`impl-${n}.jsonl`).map((c) => [c.id, c]));
const dir = join(here, 'counterexamples');
mkdirSync(dir, { recursive: true });
for (const f of readdirSync(dir)) rmSync(join(dir, f)); // stale (v1-era) evidence is replaced wholesale
const strip = (r) => { if (!r) return r; const { id, reason, ...rest } = r; return rest; };
const WANT = ['forge-leaf-small-order-holder-identity', 'forge-leaf-small-order-holder-order2', 'forge-hop-small-order-root-issuer', 'forge-leaf-small-order-holder-identityNoncanonY', 'sig-noncanonical-tail', 'proof-sibling-noncanonical-tail', 'proof-index-plus1', 'proof-size-zero', 'chain-too-long-17', 'conditions-digest-nonstring-resigned', 'counter-literal-1_0', 'counter-literal-9007199254740993', 'badjson-comment', 'badjson-lone-low-surrogate-escape', 'edge-deep-nest-inputs', 'aud-other-resigned', 'expired-resigned'];
const index = [];
for (const mut of WANT) {
  const ms = metas.filter((m) => m.mutator === mut && corpus.get(m.id).raw.length < 20000);
  if (!ms.length) continue;
  const m = ms.reduce((a, x) => (corpus.get(x.id).raw.length < corpus.get(a.id).raw.length ? x : a));
  const c = corpus.get(m.id);
  const results = { oracle: strip(oracle.get(m.id)), ...Object.fromEntries(Object.entries(impls).map(([n, r]) => [n, strip(r.get(m.id))])) };
  const verdicts = new Set(Object.values(results).map((r) => JSON.stringify(r)));
  const file = `${mut}.json`;
  writeFileSync(join(dir, file), JSON.stringify({ mutator: mut, case: m.id, bytes: c.raw.length, allImplementationsAgree: verdicts.size === 1, context: { now: c.now, aud: c.aud }, results, pcactn_json: c.raw, grant: c.grant }, null, 1));
  index.push({ file, allImplementationsAgree: verdicts.size === 1, allow: results.oracle.allow, bytes: c.raw.length });
}
// residual divergences, grouped by ROOT CAUSE (oracle reason class + oracle verdict + impl verdict), smallest case each, impls listed
const sig = (r) => (!r ? 'NONE' : r.error ? 'ERR' : r.canon !== undefined ? 'canon' : (r.allow ? 'A' : 'R') + ':' + (Object.keys(r.checks).filter((k) => !r.checks[k]).sort().join(',') || 'pass'));
const same = (o, r) => (o?.canon !== undefined || r?.canon !== undefined ? o?.canon === r?.canon && o?.hash === r?.hash && !o?.error === !r?.error : sig(o) === sig(r) && JSON.stringify(Object.entries(o?.checks ?? {}).sort()) === JSON.stringify(Object.entries(r?.checks ?? {}).sort()));
const roots = new Map();
for (const [n, rows] of Object.entries(impls)) for (const [id, o] of oracle) {
  const r = rows.get(id);
  if (same(o, r)) continue;
  const reason = (o.reason ?? '').replace(/\[?\d+\]?/g, '#').slice(0, 70);
  const key = `${reason}|${sig(o)}`;
  const e = roots.get(key) ?? { reason, oracle: sig(o), impls: new Map(), min: id, n: 0 };
  e.n++;
  const per = e.impls.get(n) ?? { sig: new Set(), n: 0 };
  per.sig.add(sig(r)); per.n++; e.impls.set(n, per);
  if (corpus.get(id).raw.length < corpus.get(e.min).raw.length) e.min = id;
  roots.set(key, e);
}
let ri = 0;
for (const e of [...roots.values()].sort((x, y) => y.n - x.n)) {
  const c = corpus.get(e.min);
  if (c.raw.length > 60000) continue;
  const m = metas.find((x) => x.id === e.min);
  const file = `RESIDUAL_${String(++ri).padStart(2, '0')}__${(m?.mutator ?? m?.group ?? 'x').replace(/[^A-Za-z0-9]+/g, '_')}.json`;
  const results = { oracle: strip(oracle.get(e.min)), ...Object.fromEntries(Object.entries(impls).map(([n, r]) => [n, strip(r.get(e.min))])) };
  writeFileSync(join(dir, file), JSON.stringify({ rootCause: { oracleReason: e.reason, oracleVerdict: e.oracle, cases: e.n, implsDiffering: Object.fromEntries([...e.impls].map(([n, v]) => [n, { cases: v.n, verdicts: [...v.sig] }])) }, case: e.min, mutator: m?.mutator ?? m?.group, context: { now: c.now, aud: c.aud }, results, ...(c.kind === 'verify' ? { pcactn_json: c.raw, grant: c.grant } : { raw: c.raw }) }, null, 1));
  index.push({ file, residual: true, impls: [...e.impls.keys()], cases: e.n });
}
writeFileSync(join(dir, 'INDEX.json'), JSON.stringify(index, null, 1));
console.log(`wrote ${index.length} counterexample files`);
