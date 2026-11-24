// Oracle: @atlasauth/pca-store-conformance, the pure logic a native port carries: the register model (step, overlappingTrues, prune,
// fastCheck), the budgeted linearizability search, the per-key checker (decideKey, deletion, minimize, checkKey, checkHistory, formatOps),
// the recorder's history parser, the workload PRNG, the report folding (overall, formatReport, reportJson) and the check inventories
// of the lease / ledger / budget / bond / mesh-witness profiles. Deterministic: seeded histories, no clock.
// Conventions: a number that is not finite is the object {"$num": "Infinity" | "-Infinity"} in the ARGUMENTS (the corpus writer refuses
// a raw non-finite number); the outputs use the corpus library's own spelling of it, the same object. Ops are plain objects
// {client, kind, key, lo, w, call, ret, res}; an unknown outcome has ret {"$num": "Infinity"}.
// PORTING (fn(args) -> native entry point, comparison rule; records are compared by JSON value):
//   step(s, op)                          Model.step
//   overlappingTrues(ops)                Model.overlapping_trues (null when none)
//   prune(ops) fastCheck(ops)            Model.prune / fast_check (null when an op is unknown)
//   search(ops, budget)                  search_linearizable
//   decideKey(ops, budget)               decide_key -> {verdict, method, kept}
//   deletion(ops, i)                     deletion(ops, ops[i]) (identity of the i-th op)
//   minimize(ops, budget)                minimize
//   checkKey(ops, opts) checkHistory(ops, opts)   check_key / check_history
//   formatOps(ops)                       format_ops
//   parseHistory(text)                   parse_history -> {ops, torn, pending}
//   prng(seed, ns)                       the PRNG run once per element of ns: the list of rand(n) results
//   overall(tests) formatReport(report, maxKeys) reportJson(report)   fold a runner report; the JSON text of reportJson is compared as text
//   inventory(profile)                   the check inventory of a profile: [{name, claim, needs}] (mesh-witness, + reopen and/or damage: the case names; needs null when absent)
import { Oracle, refWrite, rng } from './lib.mjs';

const M: any = {
  ...(await import('../../../packages/pca-store-conformance/src/model.ts')),
  ...(await import('../../../packages/pca-store-conformance/src/search.ts')),
  ...(await import('../../../packages/pca-store-conformance/src/check.ts')),
  ...(await import('../../../packages/pca-store-conformance/src/recorder.ts')),
  ...(await import('../../../packages/pca-store-conformance/src/harness.ts')),
  ...(await import('../../../packages/pca-store-conformance/src/runner.ts')),
  ...(await import('../../../packages/pca-store-conformance/src/lease-conformance.ts')),
  ...(await import('../../../packages/pca-store-conformance/src/ledger-conformance.ts')),
  ...(await import('../../../packages/pca-store-conformance/src/budget-conformance.ts')),
  ...(await import('../../../packages/pca-store-conformance/src/bond-conformance.ts')),
  ...(await import('../../../packages/pca-store-conformance/src/mesh-witness.ts')),
};

const o = new Oracle('store-conformance', 'tools/pca-audit/oracles/store-conformance.mts', 'TS-reference oracle for the pure logic of the store conformance kit (register model, linearizability search and checker, history parser, report folding, profile inventories).');

const INF = { $num: 'Infinity' };
const NINF = { $num: '-Infinity' };
/** The reference's view of an argument: {"$num"} objects become numbers again. */
function dec(v: any): any {
  if (Array.isArray(v)) return v.map(dec);
  if (v !== null && typeof v === 'object') {
    if (typeof v.$num === 'string' && Object.keys(v).length === 1) return v.$num === 'Infinity' ? Infinity : v.$num === '-Infinity' ? -Infinity : NaN;
    return Object.fromEntries(Object.keys(v).map((k) => [k, dec(v[k])]));
  }
  return v;
}

const op = (client: string, kind: string, key: string, lo: number, w: number, call: number, ret: number | typeof INF, res: string) => ({ client, kind, key, lo, w, call, ret, res });

// ---- seeded histories -------------------------------------------------------------------------------------------------------------
/** A linearizable history: a real register driven in order, each op's interval around its own linearization point. */
function valid(seedN: number, n: number, kind: 'consume' | 'advance', key: string, unknownRate = 0.15): any[] {
  const r = rng(seedN);
  let s = -Infinity;
  let t = 100;
  const out: any[] = [];
  for (let i = 0; i < n; i++) {
    t += r.int(1, 5);
    const lin = t;
    const lo = kind === 'consume' ? lin : r.int(0, 6);
    const w = kind === 'consume' ? lin + r.int(0, 20) : lo;
    const fresh = s < lo;
    const call = lin - r.int(0, 4);
    const unknown = r.next() < unknownRate;
    let res = fresh ? 'true' : 'false';
    if (fresh && (!unknown || r.next() < 0.5)) s = Math.max(s, w);
    let ret: any = lin + r.int(0, 4);
    if (unknown) { res = 'unknown'; ret = INF; }
    out.push(op(`c${r.int(0, 3)}`, kind, key, lo, w, call, ret, res));
  }
  return out;
}
/** A copy with one random defect: flipped answer, an op moved out of its window, a duplicated TRUE, or a dropped op. */
function broken(h: any[], seedN: number): any[] {
  const r = rng(seedN);
  const c = h.map((x) => ({ ...x }));
  const i = r.int(0, c.length - 1);
  switch (r.int(0, 3)) {
    case 0: c[i].res = c[i].res === 'true' ? 'false' : c[i].res === 'false' ? 'true' : c[i].res; break;
    case 1: { const d = r.int(10, 60); c[i].call += d; if (c[i].ret !== INF) c[i].ret += d; break; }
    case 2: { const t = c.find((x) => x.res === 'true'); if (t) c.push({ ...t, client: 'dup' }); break; }
    default: c.splice(i, 1);
  }
  return c;
}

const histories: Array<[string, any[]]> = [];
let hn = 0;
const addH = (label: string, h: any[]) => histories.push([`${label}#${hn++}`, h]);
for (let i = 0; i < 28; i++) {
  const kind = i % 2 ? 'advance' : 'consume';
  const h = valid(1000 + i, 3 + (i % 9), kind, `k${i % 3}`, i % 4 === 0 ? 0 : 0.2);
  addH('valid', h);
  addH('broken', broken(h, 5000 + i));
  addH('broken2', broken(broken(h, 7000 + i), 9000 + i));
}
// multi-key histories (checkHistory splits by kind and key)
for (let i = 0; i < 8; i++) {
  const parts = [valid(300 + i, 4, 'consume', 'a'), valid(400 + i, 4, 'advance', 'a'), valid(500 + i, 5, 'consume', 'b'), valid(600 + i, 3, 'advance', 'c')];
  const merged = parts.flat().sort((x, y) => x.call - y.call);
  addH('multi', merged);
  addH('multi-broken', broken(merged, 800 + i));
}
// hand-built corner cases
addH('two-trues-same-key', [op('a', 'consume', 'k', 5, 50, 0, 1, 'true'), op('b', 'consume', 'k', 6, 60, 0, 2, 'true')]);
addH('disjoint-trues', [op('a', 'consume', 'k', 5, 6, 0, 1, 'true'), op('b', 'consume', 'k', 7, 9, 2, 3, 'true')]);
addH('false-unexplained', [op('a', 'consume', 'k', 5, 50, 0, 1, 'false')]);
addH('false-after-true', [op('a', 'advance', 'k', 3, 3, 0, 1, 'true'), op('b', 'advance', 'k', 3, 3, 2, 3, 'false')]);
addH('false-before-true', [op('b', 'advance', 'k', 3, 3, 0, 1, 'false'), op('a', 'advance', 'k', 3, 3, 2, 3, 'true')]);
addH('only-unknown', [op('a', 'advance', 'k', 3, 3, 0, INF, 'unknown'), op('b', 'advance', 'k', 3, 3, 1, 2, 'false')]);
addH('unknown-explains-false', [op('a', 'advance', 'k', 3, 3, 0, INF, 'unknown'), op('b', 'advance', 'k', 3, 3, 5, 6, 'false')]);
addH('unknown-then-true', [op('a', 'advance', 'k', 3, 3, 0, INF, 'unknown'), op('b', 'advance', 'k', 4, 4, 5, 6, 'true'), op('c', 'advance', 'k', 3, 3, 7, 8, 'false')]);
addH('empty-ish', [op('a', 'advance', 'k', 0, 0, 0, 1, 'true')]);
addH('concurrent-pair', [op('a', 'advance', 'k', 2, 2, 0, 10, 'true'), op('b', 'advance', 'k', 2, 2, 1, 9, 'false')]);
addH('late-ret', [op('a', 'advance', 'k', 2, 2, 5, 3, 'true')]);
addH('fraction', [op('a', 'consume', 'k', 1.5, 2.25, 0.5, 1.75, 'true'), op('b', 'consume', 'k', 3, 9, 2.5, 7.125, 'true')]);
addH('float-time', [op('a', 'advance', 'k', 1, 1, 0.0625, 0.1875, 'true'), op('b', 'advance', 'k', 1, 1, 0.5, 0.5625, 'false')]);

for (const [n, h] of histories) {
  await o.run('overlappingTrues', n, (ops: any[]) => M.overlappingTrues(dec(ops)) ?? null, [h]);
  await o.run('prune', n, (ops: any[]) => M.prune(dec(ops)), [h]);
  await o.run('fastCheck', n, (ops: any[]) => M.fastCheck(dec(ops)) ?? null, [h]);
  for (const b of [1, 4, 40, 200000]) await o.run('search', `${n} budget ${b}`, (ops: any[], bud: number) => M.searchLinearizable(dec(ops), bud), [h, b]);
  await o.run('decideKey', n, (ops: any[], bud: number) => M.decideKey(dec(ops), bud), [h, 200000]);
  await o.run('decideKey', `${n} budget 3`, (ops: any[], bud: number) => M.decideKey(dec(ops), bud), [h, 3]);
  if (h.length <= 9) await o.run('minimize', n, (ops: any[], bud: number) => M.minimize(dec(ops), bud), [h, 200000]);
  await o.run('formatOps', n, (ops: any[]) => M.formatOps(dec(ops)), [h.length ? h : [op('a', 'advance', 'k', 0, 0, 0, 1, 'true')]]);
  await o.run('checkHistory', n, (ops: any[], opts: any) => M.checkHistory(dec(ops), opts), [h, {}]);
  await o.run('checkHistory', `${n} no minimize`, (ops: any[], opts: any) => M.checkHistory(dec(ops), opts), [h, { minimize: false }]);
  await o.run('checkHistory', `${n} budget 5 limit 2`, (ops: any[], opts: any) => M.checkHistory(dec(ops), opts), [h, { budget: 5, minimizeLimit: 2 }]);
  // one key at a time
  const byKey = new Map<string, any[]>();
  for (const x of h) { const id = `${x.kind}\u0000${x.key}`; byKey.set(id, [...(byKey.get(id) ?? []), x]); }
  for (const [id, list] of byKey) await o.run('checkKey', `${n} ${JSON.stringify(id)}`, (ops: any[], opts: any) => M.checkKey(dec(ops), opts), [list, {}]);
  // sound deletion of each op
  for (let i = 0; i < Math.min(h.length, 5); i++) await o.run('deletion', `${n} #${i}`, (ops: any[], idx: number) => { const d = dec(ops); return M.deletion(d, d[idx]); }, [h, i]);
}
for (const s of [NINF, -5, 0, 3, 10]) for (const x of [
  op('a', 'advance', 'k', 3, 3, 0, 1, 'true'), op('a', 'advance', 'k', 3, 3, 0, 1, 'false'), op('a', 'advance', 'k', 3, 3, 0, INF, 'unknown'),
  op('a', 'consume', 'k', 0, 9, 0, 1, 'true'), op('a', 'consume', 'k', 0, 9, 0, 1, 'false'), op('a', 'consume', 'k', -5, 2, 0, INF, 'unknown'), op('a', 'advance', 'k', 11, 11, 0, 1, 'true'),
]) await o.run('step', `${JSON.stringify(s)} ${x.kind} ${x.res} ${x.lo}`, (st: any, p: any) => M.step(dec(st), dec(p)), [s, x]);

// ---- the history parser --------------------------------------------------------------------------------------------------------------
const I = (proc: string, id: number, call: number, client: string, kind: string, key: string, lo: number, w: number) => JSON.stringify(['i', proc, id, call, client, kind, key, lo, w]);
const R = (proc: string, id: number, at: number, res: string) => JSON.stringify(['r', proc, id, at, res]);
const texts: Array<[string, string]> = [
  ['complete', [I('p', 1, 10, 'c0', 'consume', 'k', 10, 70), R('p', 1, 12, 'true'), I('p', 2, 13, 'c1', 'advance', 'k2', 4, 4), R('p', 2, 15, 'false')].join('\n') + '\n'],
  ['pending', [I('p', 1, 10, 'c0', 'consume', 'k', 10, 70), I('q', 1, 11, 'c1', 'advance', 'k', 3, 3)].join('\n')],
  ['unknown-response', [I('p', 1, 10, 'c0', 'consume', 'k', 10, 70), R('p', 1, 12, 'unknown')].join('\n')],
  ['torn-lines', [I('p', 1, 10, 'c0', 'consume', 'k', 10, 70), '{"torn', R('p', 1, 12, 'true'), '[1,2', 'not json', '', '5', '"s"', 'null', '{}'].join('\n')],
  ['bad-lengths', [JSON.stringify(['i', 'p', 1, 10, 'c0', 'consume', 'k', 10]), JSON.stringify(['r', 'p', 1, 12]), JSON.stringify(['x', 'p', 1]), JSON.stringify(['i'])].join('\n')],
  ['response-without-invocation', R('p', 9, 12, 'true')],
  ['duplicate-response', [I('p', 1, 10, 'c0', 'consume', 'k', 10, 70), R('p', 1, 12, 'true'), R('p', 1, 13, 'false')].join('\n')],
  ['processes-interleaved', [I('a', 1, 1, 'c0', 'consume', 'k', 1, 9), I('b', 1, 2, 'c0', 'consume', 'k', 2, 9), R('b', 1, 3, 'false'), R('a', 1, 4, 'true')].join('\n')],
  ['coerced-fields', [JSON.stringify(['i', 7, 1, '10', 5, 'advance', 9, '3', '3']), JSON.stringify(['r', 7, 1, '12', 'true'])].join('\n')],
  ['crlf-and-spaces', [I('p', 1, 10, 'c0', 'consume', 'k', 10, 70) + '\r', '  ' + R('p', 1, 12, 'true')].join('\n')],
  ['empty', ''],
];
for (const [n, t] of texts) await o.run('parseHistory', n, (text: string) => { const r = M.parseHistory(text); return r; }, [t]);

// ---- the PRNG ----------------------------------------------------------------------------------------------------------------------------
for (const seed of [0, 1, 7, 12345, 2 ** 31 - 1, 2 ** 32 - 1, 4294967296 + 5, -1, 1.5]) await o.run('prng', `seed ${seed}`, (sd: number, ns: number[]) => { const r = M.prng(sd); return ns.map((n) => r(n)); }, [seed, [1, 2, 3, 20, 100, 1000, 2 ** 31, 7, 7, 7, 1, 5000]]);

// ---- report folding ----------------------------------------------------------------------------------------------------------------------
const tr = (test: string, kind: string, status: string, h: any[] | null, extra: any = {}) => {
  const hist = h ? M.checkHistory(dec(h), {}) : null;
  return { test, kind, status, ops: hist?.ops ?? 0, keys: hist?.keys ?? 0, errors: extra.errors ?? 0, violations: hist?.violations ?? [], unresolved: hist?.unresolved.length ?? 0, ...(extra.note ? { note: extra.note } : {}) };
};
const toArgs = (x: any) => JSON.parse(JSON.stringify(x, (_k, v) => (v === Infinity ? INF : v === -Infinity ? NINF : v)));
const bad = histories.find(([n]) => n.startsWith('two-trues'))![1];
const bad2 = histories.find(([n]) => n.startsWith('false-unexplained'))![1];
const good = histories.find(([n]) => n.startsWith('valid'))![1];
const reports: Array<[string, any]> = [
  ['all-pass', { adapter: 'A', status: 'pass', tests: [tr('burst', 'consume', 'pass', good), tr('durability', 'advance', 'skip', null, { note: 'the adapter declares durable: false' })] }],
  ['violation', { adapter: 'B', status: 'fail', tests: [tr('burst', 'consume', 'fail', bad), tr('retention', 'advance', 'fail', bad2, { errors: 2 })] }],
  ['unresolved', { adapter: 'C', status: 'unresolved', tests: [tr('concurrent', 'advance', 'unresolved', good, { note: 'x; y' })] }],
  ['mixed', { adapter: 'D', status: 'fail', tests: [tr('burst', 'advance', 'pass', good), tr('crash', 'consume', 'skip', null), tr('concurrent', 'consume', 'unresolved', good), tr('retention', 'consume', 'fail', bad)] }],
  ['empty', { adapter: 'E', status: 'pass', tests: [] }],
];
for (const [n, r] of reports) {
  const a = toArgs(r);
  await o.run('overall', n, (rep: any) => M.overall(dec(rep).tests), [a]);
  await o.run('formatReport', n, (rep: any, k: number) => M.formatReport(dec(rep), k), [a, 3]);
  await o.run('formatReport', `${n} maxKeys 1`, (rep: any, k: number) => M.formatReport(dec(rep), k), [a, 1]);
  await o.run('formatReport', `${n} maxKeys 0`, (rep: any, k: number) => M.formatReport(dec(rep), k), [a, 0]);
  await o.run('reportJson', n, (rep: any) => M.reportJson(dec(rep)), [a]);
}
for (const [n, ts] of [['fail-first', ['pass', 'fail', 'unresolved']], ['unresolved', ['pass', 'unresolved', 'skip']], ['pass-skip', ['pass', 'skip']], ['none', []]] as Array<[string, string[]]>)
  await o.run('overall', `statuses ${n}`, (st: string[]) => M.overall(st.map((s) => ({ status: s }))), [ts]);

// ---- profile inventories ---------------------------------------------------------------------------------------------------------------
const inv = (cs: any[]) => cs.map((c) => ({ name: c.name, claim: c.claim, needs: c.needs ?? null }));
const stub = { make: () => ({}) as any };
const INVENTORY: Record<string, () => any> = {
  lease: () => inv(M.LEASE_CHECKS), ledger: () => inv(M.LEDGER_CHECKS), budget: () => inv(M.BUDGET_CHECKS), bond: () => inv(M.BOND_CHECKS),
  'mesh-witness': () => M.meshWitnessStoreCases(stub).map((c: any) => c.name),
  'mesh-witness+reopen': () => M.meshWitnessStoreCases({ ...stub, reopen: (s: any) => s }).map((c: any) => c.name),
  'mesh-witness+damage': () => M.meshWitnessStoreCases({ ...stub, damage: () => undefined }).map((c: any) => c.name),
  'mesh-witness+reopen+damage': () => M.meshWitnessStoreCases({ ...stub, reopen: (s: any) => s, damage: () => undefined }).map((c: any) => c.name),
};
for (const p of Object.keys(INVENTORY)) await o.run('inventory', p, (profile: string) => INVENTORY[profile]!(), [p]);

refWrite(o, 'store-conformance');
