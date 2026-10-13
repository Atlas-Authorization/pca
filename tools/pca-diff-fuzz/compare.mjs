#!/usr/bin/env node
// Compares every implementation's output to the TS oracle; runs the metamorphic assertions.
//   node compare.mjs <outDir>   ->  <outDir>/report.json, <outDir>/REPORT.md, <outDir>/divergences/*.json
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const jl = (f) => readFileSync(join(out, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const corpus = new Map(jl('corpus.jsonl').map((c) => [c.id, c]));
const metas = new Map(jl('meta.jsonl').map((m) => [m.id, m]));
const oracle = new Map(jl('oracle.jsonl').map((o) => [o.id, o]));
// wire v2: a wire failure is {wire:false} ONLY; otherwise the eight checks in normative order. Compared as exact key->bool maps.
const ckStr = (r) => Object.keys(r.checks ?? {}).sort().map((k) => k + '=' + (r.checks[k] === true ? 1 : 0)).join(',');
const failedCheck = (r, k) => r.checks?.wire === false || r.checks?.[k] === false;

const status = {};
for (const f of readdirSync(out)) {
  const m = /^status-(.+)\.txt$/.exec(f);
  if (m) status[m[1]] = readFileSync(join(out, f), 'utf8').trim();
}
for (const n of ['go', 'python', 'ruby', 'php', 'dotnet', 'rust', 'java']) if (!(n in status)) status[n] = 'not requested';
const impls = {};
for (const [n, s] of Object.entries(status)) {
  if (s !== 'ran' || !existsSync(join(out, `impl-${n}.jsonl`))) continue;
  impls[n] = new Map(jl(`impl-${n}.jsonl`).map((o) => [o.id, o]));
}

const isErr = (r) => r === undefined || r.error !== undefined;
const accepts = (r) => !isErr(r) && r.allow === true;
const verdictKey = (r) => (isErr(r) ? `ERR(${r?.error === 'parse' ? 'parse' : 'exc'})` : `allow=${r.allow} ${ckStr(r)}`);
const cmpVerify = (o, r) => {
  // returns null if agree, else {cls, detail}
  if (r === undefined) return { cls: 'no-output', detail: 'implementation produced no row' };
  const oe = isErr(o), re = isErr(r);
  if (oe && re) return null; // both refuse to process: agree (error class compared separately below)
  if (oe !== re) {
    const acc = oe ? accepts(r) : accepts(o);
    return { cls: acc ? 'VERDICT(accept-vs-error)' : 'soft(reject-vs-error)', detail: `oracle=${verdictKey(o)} impl=${verdictKey(r)}` };
  }
  if (o.allow !== r.allow) return { cls: 'VERDICT(allow)', detail: `oracle=${verdictKey(o)} impl=${verdictKey(r)}` };
  if (ckStr(o) !== ckStr(r)) {
    const ks = [...new Set([...Object.keys(o.checks), ...Object.keys(r.checks)])].filter((k) => (o.checks[k] === true) !== (r.checks[k] === true) || (k in o.checks) !== (k in r.checks));
    return { cls: 'CHECK(per-check)', detail: `oracle=${verdictKey(o)} impl=${verdictKey(r)} checks=${ks.join(',')}` };
  }
  return null;
};
const cmpCanon = (o, r) => {
  if (r === undefined) return { cls: 'no-output', detail: '' };
  const oe = isErr(o), re = isErr(r);
  if (oe && re) return null;
  if (oe !== re) return { cls: 'CANON(error-vs-value)', detail: `oracle=${oe ? 'ERR' : JSON.stringify(o.canon).slice(0, 120)} impl=${re ? 'ERR:' + r.error : JSON.stringify(r.canon).slice(0, 120)}` };
  if (o.canon !== r.canon) return { cls: 'CANON(string)', detail: `oracle=${JSON.stringify(o.canon).slice(0, 160)} impl=${JSON.stringify(r.canon).slice(0, 160)}` };
  if (o.hash !== r.hash) return { cls: 'CANON(hash)', detail: 'same canonical string, different hash' };
  return null;
};

// shortest differing region between a mutant and its base (the "exact field")
function region(id) {
  const m = metas.get(id), c = corpus.get(id);
  if (!m?.base || !corpus.get(m.base)) return null;
  const a = corpus.get(m.base).raw, b = c.raw;
  let p = 0; while (p < a.length && p < b.length && a[p] === b[p]) p++;
  let s = 0; while (s < a.length - p && s < b.length - p && a[a.length - 1 - s] === b[b.length - 1 - s]) s++;
  const ctx = (str, from, to) => str.slice(Math.max(0, from - 30), from) + '[[' + str.slice(from, to).slice(0, 150) + ']]' + str.slice(to, to + 15);
  return { before: ctx(a, p, a.length - s), after: ctx(b, p, b.length - s) };
}

const report = { corpus: { total: corpus.size, byTag: {}, verify: 0, canon: 0 }, status, implementations: Object.keys(impls), oracleErrors: 0, divergences: {}, groups: [], metamorphic: {}, expectations: {} };
for (const m of metas.values()) { report.corpus.byTag[m.tag] = (report.corpus.byTag[m.tag] ?? 0) + 1; report.corpus[m.kind]++; }

// ---------------------------------------------------------------- differential
const groups = new Map(); // key -> {impl, cls, group, mutator, ids[]}
const perImpl = {};
for (const [name, rows] of Object.entries(impls)) {
  const s = (perImpl[name] = { compared: 0, agree: 0, byClass: {}, errorClassDiffs: 0, byNumClass: {} });
  for (const [id, o] of oracle) {
    const m = metas.get(id), c = corpus.get(id);
    const r = rows.get(id);
    s.compared++;
    const nc = (s.byNumClass[m.numClass ?? 'n/a'] ??= { compared: 0, divergent: 0 });
    nc.compared++;
    const d = c.kind === 'verify' ? cmpVerify(o, r) : cmpCanon(o, r);
    if (!d) {
      if (c.kind === 'verify' && isErr(o) && isErr(r) && (o.error === 'parse') !== (r.error === 'parse')) s.errorClassDiffs++;
      s.agree++;
      continue;
    }
    s.byClass[d.cls] = (s.byClass[d.cls] ?? 0) + 1;
    nc.divergent++;
    const key = `${name}|${m.numClass}|${d.cls}|${m.tag === 'meta-preserving' || m.tag === 'meta-numrepr' ? 'meta:' + (metas.get(m.base)?.mutator ?? metas.get(m.base)?.tag) : m.mutator ?? m.group}`;
    if (!groups.has(key)) groups.set(key, { numClass: m.numClass, impl: name, cls: d.cls, mutator: m.mutator ?? m.group, tag: m.tag, ids: [], details: new Map() });
    const g = groups.get(key);
    g.ids.push(id);
    g.details.set(id, d.detail);
  }
}
mkdirSync(join(out, 'divergences'), { recursive: true });
const toVector = (id, note) => {
  const c = corpus.get(id), o = oracle.get(id);
  if (c.kind === 'canon') return { name: id, note, kind: 'canon', raw: c.raw, expect: { canon: o.canon ?? null, hash: o.hash ?? null, error: o.error ?? null } };
  let g = null; try { g = JSON.parse(c.grant); } catch { /* keep text only */ }
  return { name: id, note, class: o.allow ? 'positive' : 'negative', description: note, grant: g, plan_nodes: [], context: { now: c.now, aud: c.aud }, pcactn_json: c.raw, expect: isErr(o) ? { error: o.error } : { allow: o.allow, checks: o.checks } };
};
let gi = 0;
const gl = [];
for (const g of groups.values()) {
  const ids = g.ids.sort((a, b) => corpus.get(a).raw.length - corpus.get(b).raw.length || (a < b ? -1 : 1));
  const min = ids[0];
  const rg = region(min);
  const entry = { numClass: g.numClass, impl: g.impl, class: g.cls, mutator: g.mutator, tag: g.tag, count: ids.length, minimal: { id: min, bytes: corpus.get(min).raw.length, detail: g.details.get(min), changed: rg, raw: corpus.get(min).raw.length <= 1500 ? corpus.get(min).raw : undefined }, otherIds: ids.slice(1, 6) };
  gl.push(entry);
  if (gi++ < 400) writeFileSync(join(out, 'divergences', `${g.impl}__${g.numClass}__${g.cls.replace(/[^A-Za-z0-9]+/g, '_')}__${(g.mutator ?? 'x').replace(/[^A-Za-z0-9]+/g, '_')}.json`), JSON.stringify({ ...entry, vector: toVector(min, g.cls) }, null, 2));
}
gl.sort((a, b) => (a.class.startsWith('soft') ? 1 : 0) - (b.class.startsWith('soft') ? 1 : 0) || b.count - a.count);
report.groups = gl;
report.divergences = perImpl;

// cross-implementation matrix on the VERIFY kind: how many cases have any pair of impls disagreeing among themselves
const names = Object.keys(impls);
let crossDisagree = 0, crossStrict = 0;
if (names.length) for (const [id, c] of corpus) {
  if (c.kind !== 'verify') continue;
  const ks = new Set([verdictKey(oracle.get(id)), ...names.map((n) => verdictKey(impls[n].get(id)))]);
  if (ks.size > 1) crossDisagree++;
  const allows = new Set([accepts(oracle.get(id)), ...names.map((n) => accepts(impls[n].get(id)))]);
  if (allows.size > 1) crossStrict++;
}
report.crossImplementation = { verifyCasesWithAnyDisagreement: crossDisagree, verifyCasesWithAcceptRejectDisagreement: crossStrict };

// ---------------------------------------------------------------- metamorphic: format-preserving
const all = { oracle: (id) => oracle.get(id), ...Object.fromEntries(names.map((n) => [n, (id) => impls[n].get(id)])) };
for (const [who, get] of Object.entries(all)) {
  const stat = { preserving: { n: 0, violated: 0 }, numrepr: { n: 0, violated: 0 }, breaking: { n: 0, violated: 0 } };
  const ex = { preserving: [], numrepr: [], breaking: [] };
  for (const [id, m] of metas) {
    if (m.tag === 'meta-preserving') {
      const k = 'preserving';
      stat[k].n++;
      const a = get(id), b = get(m.base);
      if (verdictKey(a) !== verdictKey(b)) { stat[k].violated++; if (ex[k].length < 5) ex[k].push({ id, base: m.base, variant: m.meta, was: verdictKey(b), now: verdictKey(a) }); }
    } else if ((m.tag === 'mutant' || m.tag === 'meta-numrepr') && (m.mustReject || (m.breaks && m.breaks.length))) {
      stat.breaking.n++;
      const r = get(id);
      const ok = isErr(r) ? true : (m.mustReject ? r.allow === false : true) && (m.breaks ?? []).every((k) => failedCheck(r, k));
      if (!ok) { stat.breaking.violated++; if (ex.breaking.length < 8) ex.breaking.push({ id, mutator: m.mutator, expectedFail: m.breaks, got: verdictKey(r) }); }
    }
  }
  report.metamorphic[who] = { ...stat, examples: ex };
}

// breaking-transform expectation violations by mutator, per oracle (these are properties of the REFERENCE itself)
const viol = new Map();
for (const [id, m] of metas) {
  if ((m.tag !== 'mutant' && m.tag !== 'meta-numrepr') || !(m.mustReject || m.breaks?.length)) continue;
  const r = oracle.get(id);
  if (isErr(r)) continue;
  const ok = (m.mustReject ? r.allow === false : true) && (m.breaks ?? []).every((k) => failedCheck(r, k));
  if (!ok) { const v = viol.get(m.mutator) ?? { n: 0, example: id, got: verdictKey(r), expected: m.breaks }; v.n++; viol.set(m.mutator, v); }
}
report.expectations.oracleViolatedBreakingExpectations = Object.fromEntries(viol);

writeFileSync(join(out, 'report.json'), JSON.stringify(report, null, 2));

// ---------------------------------------------------------------- markdown summary
const L = [];
L.push('# PCA cross-implementation differential audit', '');
L.push(`Corpus: ${report.corpus.total} cases (${report.corpus.verify} verify, ${report.corpus.canon} canonicalization); tags: ${JSON.stringify(report.corpus.byTag)}`, '');
L.push('## Implementations', '', '| impl | status | compared | agree | divergent |', '|---|---|---|---|---|');
for (const n of Object.keys(status)) {
  const s = perImpl[n];
  L.push(`| ${n} | ${status[n]} | ${s?.compared ?? '-'} | ${s?.agree ?? '-'} | ${s ? s.compared - s.agree : '-'} |`);
}
L.push('', `Cross-implementation (oracle + all ran impls), verify cases: ${crossDisagree} with ANY per-check/verdict disagreement; ${crossStrict} with an accept-vs-reject disagreement.`, '');
L.push('## Divergences by number-literal class of the case', '', '| impl | int-only cases: divergent/total | float/exponent cases | unsafe-int cases | non-JSON/unclassified |', '|---|---|---|---|---|');
for (const [n, s] of Object.entries(perImpl)) { const f = (k) => `${s.byNumClass[k]?.divergent ?? 0}/${s.byNumClass[k]?.compared ?? 0}`; L.push(`| ${n} | ${f('int')} | ${f('float')} | ${f('unsafe-int')} | ${f('nojson')} |`); }
L.push('', '## Divergence groups (impl | class | mutator | count | minimal case)', '');
if (!gl.length) L.push('NONE - no divergences found.');
for (const g of gl) {
  L.push(`- **${g.impl}** [${g.numClass}] ${g.class} \`${g.mutator}\` x${g.count} - minimal \`${g.minimal.id}\` (${g.minimal.bytes} B): ${g.minimal.detail}`);
  if (g.minimal.changed) L.push(`  - field: before \`${g.minimal.changed.before.replace(/`/g, "'")}\` / after \`${g.minimal.changed.after.replace(/`/g, "'")}\``);
}
// root-cause view: group by mutator/generator group, list which impls diverge from the oracle and how
const rc = new Map();
for (const g of gl) {
  const base = g.tag === 'meta-preserving' || g.tag === 'meta-numrepr' ? `(meta ${g.tag})` : g.mutator;
  const k = `${base}|${g.numClass}`;
  const e = rc.get(k) ?? { name: base, numClass: g.numClass, impls: new Map(), minimal: g.minimal };
  const cur = e.impls.get(g.impl) ?? { n: 0, classes: new Set() };
  cur.n += g.count; cur.classes.add(g.class); e.impls.set(g.impl, cur);
  if (g.minimal.bytes < e.minimal.bytes) e.minimal = g.minimal;
  rc.set(k, e);
}
L.push('', '## Root-cause view (mutator -> implementations diverging from the oracle)', '');
for (const e of [...rc.values()].sort((a, b) => b.impls.size - a.impls.size || a.name.localeCompare(b.name))) {
  L.push(`- \`${e.name}\` [${e.numClass}] -> ${[...e.impls].map(([i, v]) => `${i}(${v.n}; ${[...v.classes].join('+')})`).join(', ')}; minimal ${e.minimal.id}: ${e.minimal.detail}`);
}
// SDK-vs-SDK view: ignore the oracle; where do the language implementations disagree with EACH OTHER?
const inner = new Map();
let innerVerify = 0, innerCanon = 0, innerVerifyAccept = 0;
if (names.length > 1) for (const [id, c] of corpus) {
  const m = metas.get(id);
  const vk = (n) => (c.kind === 'verify' ? verdictKey(impls[n].get(id)) : (isErr(impls[n].get(id)) ? 'ERR' : impls[n].get(id).canon));
  const keys = names.map(vk);
  if (new Set(keys).size === 1) continue;
  if (c.kind === 'verify') { innerVerify++; if (new Set(names.map((n) => accepts(impls[n].get(id)))).size > 1) innerVerifyAccept++; } else innerCanon++;
  const part = new Map();
  names.forEach((n, i) => { const a = part.get(keys[i]) ?? []; a.push(n); part.set(keys[i], a); });
  const sig = [...part.entries()].map(([k, v]) => `{${v.join(',')}}=${String(k).slice(0, 60)}`).sort().join(' ; ');
  const nm = m.tag.startsWith('meta') ? `(meta ${m.tag})` : (m.mutator ?? m.group);
  const key = `${nm}|${m.numClass}|${sig}`;
  const e = inner.get(key) ?? { name: nm, numClass: m.numClass, sig, n: 0, min: id };
  e.n++; if (corpus.get(id).raw.length < corpus.get(e.min).raw.length) e.min = id;
  inner.set(key, e);
}
report.sdkVsSdk = { verifyCasesWhereSDKsDisagree: innerVerify, ofWhichAcceptVsReject: innerVerifyAccept, canonCasesWhereSDKsDisagree: innerCanon, groups: [...inner.values()].sort((a, b) => b.n - a.n) };
writeFileSync(join(out, 'report.json'), JSON.stringify(report, null, 2));
L.push('', '## SDK-vs-SDK disagreement (oracle excluded)', '', `Verify cases where the language SDKs do not all give the same verdict: ${innerVerify} (accept-vs-reject among SDKs: ${innerVerifyAccept}); canonicalization cases where SDKs differ: ${innerCanon}.`, '');
for (const e of report.sdkVsSdk.groups.slice(0, 120)) L.push(`- \`${e.name}\` [${e.numClass}] x${e.n} e.g. ${e.min}: ${e.sig}`);
L.push('', '## Metamorphic', '');
for (const [who, s] of Object.entries(report.metamorphic)) L.push(`- ${who}: format-preserving ${s.preserving.violated}/${s.preserving.n} violated; verdict-breaking (incl. non-canonical numeric repr) ${s.breaking.violated}/${s.breaking.n} failed to flip expected checks`);
L.push('', '## Oracle breaking-expectation violations (properties of the TS reference itself)', '');
if (!viol.size) L.push('none');
for (const [k, v] of viol) L.push(`- \`${k}\` x${v.n}: expected checks ${JSON.stringify(v.expected)} to fail; oracle got ${v.got} (e.g. ${v.example})`);
// ---------------------------------------------------------------- adversarial classes: does EVERY implementation reject them?
const CLASSES = [
  ['small-order / identity forged signature', /^forge-/],
  ['non-canonical base64url (sig / hop / sibling / slot)', /^(sig-noncanonical-tail|proof-sibling-noncanonical-tail|cap-hop-b64-bad|slot-b64-bad|sig-padded|sig-standard-b64-chars|sig-with-ws|sig-truncate|sig-oversize)$/],
  ['Merkle index/size/path tamper', /^(proof-|plan-proof-)/],
  ['>16-hop chain', /^chain-too-long-17$/],
  ['non-string conditions_digest', /^conditions-digest-nonstring-resigned$/],
  ['float / 2^53 / non-canonical numerics', /^(edge-numeric-|counter-literal-|iat-exp-|caution-bad|attestation-epoch-bad|badjson-(neg-zero|frac-trailing|exp-in-r|r-below|r-16|negative-zero|exp-capital)|ver-not-2)/],
  ['JSON comments / lone surrogate / deep nest', /^(badjson-(comment|lone|reversed|invalid-utf8|nested|bom|trailing|ws-|key-escaped|nan|infinity)|edge-deep-nest)/],
  ['audience mismatch', /^aud-/],
  ['expired / validity window', /^(expired-|exp-boundary-expired|iat-future-too-far|exp-le-iat|seconds-not-ms|lifetime-boundary)/],
];
const advRows = [];
const everyone = ['oracle', ...Object.keys(impls)];
const getRow = (who, id) => (who === 'oracle' ? oracle.get(id) : impls[who].get(id));
for (const [label, re] of CLASSES) {
  const ids = [...metas.values()].filter((m) => m.tag === 'mutant' && re.test(m.mutator ?? '')).map((m) => m.id);
  const mr = ids.filter((id) => metas.get(id).mustReject);
  const row = { label, cases: ids.length, mustReject: mr.length, acceptedByImpl: {} };
  for (const w of everyone) row.acceptedByImpl[w] = mr.filter((id) => accepts(getRow(w, id))).length;
  advRows.push(row);
}
report.adversarialClasses = advRows;
{
  const nv = [...corpus.values()].filter((c) => c.kind === 'verify').length, nc = [...corpus.values()].filter((c) => c.kind === 'canon').length;
  const totalDiv = Object.values(perImpl).reduce((a, s) => a + (s.compared - s.agree), 0);
  const H = ['## HEADLINE', '', `${corpus.size} cases (${nv} verify + ${nc} canonicalization/strict-parse) x ${Object.keys(impls).length + 1} implementations (TS oracle + ${Object.keys(impls).join(', ')}).`, `Total divergences vs the oracle: **${totalDiv}** (verify cases with any per-check/verdict disagreement among all: ${crossDisagree}; accept-vs-reject disagreement: ${crossStrict}).`, totalDiv === 0 && crossDisagree === 0 ? '**ZERO DIVERGENCE** across every implementation that ran (bit-for-bit: allow + per-check map + canonical string + hash).' : '**DIVERGENCE PRESENT** - see groups below.', '', '### Adversarial classes: how many must-reject cases each implementation ACCEPTED (0 everywhere = closed)', '', `| class | cases | must-reject | ${everyone.map((w) => w + ' accepted').join(' | ')} |`, `|---|---|---|${everyone.map(() => '---').join('|')}|`, ...advRows.map((r) => `| ${r.label} | ${r.cases} | ${r.mustReject} | ${everyone.map((w) => r.acceptedByImpl[w]).join(' | ')} |`), ''];
  L.splice(2, 0, ...H);
}
writeFileSync(join(out, 'report.json'), JSON.stringify(report, null, 2));
writeFileSync(join(out, 'REPORT.md'), L.join('\n') + '\n');
console.log(L.slice(0, 12).join('\n'));
console.log(`... full report: ${join(out, 'REPORT.md')} | ${gl.length} divergence groups`);
