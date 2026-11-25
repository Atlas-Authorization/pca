// Oracle: @atlasauth/pca-intent outcome space (omega.ts, policy.ts, slots.ts, region.ts). Deterministic (fixed seeds, no clocks).
// All inputs are plain JSON (Omega / VerbSpace / Dim / Outcome / Region are JSON-shaped). Omegas come from deriveOmega over
// fixed policy / slot sets, plus hand-built ones. A value arriving as a number in an Outcome is a double.
// PORTING (fn(args) -> native entry point, comparison rule; all compare by JSON value):
//   deriveOmega(opts)             deriveOmega(opts{policies,slots?,domains?,extraVerbs?}) -> Omega JSON
//   numCells(dim) / cellCount(dim) / verbCellCount(vs) / decodeCell(vs,flat) / encodeCell(vs,idx)
//   catCellOf(dim,s) / cellOfValue(dim,x) / cellOf(vs,o) / catRep(dim,i) / numRep(dim,i) / repValue(dim,i) / cellRep(vs,idx)
//   harmMax(omega) / intervalWeight(dim,a,b) / dimCellStats(dim,i) / cellStats(vs,idx) / harmOf(vs,o)   (default harm model)
//   rngSeq(seed,n)                first n draws of the seeded generator: IntentOmega.rng(seed)
//   sampleOutcomes(omega,seed,n)  n draws of sampleOutcome with rng(seed) -> [{verb, values}]
//   verbSpace(omega,verb)         the verb space or null
//   normalizePolicy(p) / outcomeToAction(vs,o) / admits(policy,vs,o) / slotsToPolicy(slots)
//   regionOfCell(vs,idx) / restrictRegion(r,dim,part) / dimCellsIn(dim,rd|null,mode) / regionCells(vs,r,mode) / valueInRegionDim(path,rd,x)
// A throwing reference requires the native to throw.
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as P0 from '../../../packages/pca-intent/src/policy';
import * as S0 from '../../../packages/pca-intent/src/slots';
import * as R0 from '../../../packages/pca-intent/src/region';
import { Oracle, refWrite } from './lib.mjs';

const O: any = (O0 as any).default ?? O0;
const P: any = (P0 as any).default ?? P0;
const S: any = (S0 as any).default ?? S0;
const R: any = (R0 as any).default ?? R0;
const o = new Oracle('intent-omega', 'tools/pca-audit/oracles/intent-omega.mts', 'TS-reference oracle for the intent outcome space.');
let n = 0;
const nm = () => String(n++);
const run = (fn: string, f: any, args: any[]) => o.run(fn, nm(), f, args);

const amt = (op: string, v: number) => ({ field: 'action.params.amount', op, value: v });
const POLICIES: any[] = [
  { predicates: [{ verb: 'stripe.refund', resource: '/acct/*', where: [amt('lte', 500)] }], caveats: [] },
  { predicates: [{ verb: ['stripe.refund', 'stripe.charge'], resource: 'acct_1', where: [amt('lt', 99.5), { field: 'action.params.currency', op: 'in', value: ['usd', 'eur'] }] }] },
  { predicates: [{ verb: 'gmail.send', where: [{ field: 'action.params.to', op: 'prefix', value: 'team-' }, { field: 'env.hour', op: 'gte', value: 9 }, { field: 'env.hour', op: 'lt', value: 17 }] }] },
  { predicates: [{ verb: 'github.merge_pr', resource: '*', where: [{ any_of: [{ field: 'action.params.repo', op: 'eq', value: 'a/b' }, { field: 'action.params.repo', op: 'eq', value: 'a/c' }] }, { not: { field: 'action.params.branch', op: 'eq', value: 'main' } }] }] },
  { predicates: [{ verb: 'files.write', resource: 're:/x/.*', where: [{ field: 'action.params.path', op: 'like', value: '%.txt' }, { field: 'action.params.n', op: 'gt', ref: 'action.params.m' }, { field: 'subject.role', op: 'exists' }] }] },
  { predicates: [{ verb: 'slack.post_message', where: [{ all_of: [{ field: 'action.params.count', op: 'lte', value: 10 }, { field: 'subject.dept', op: 'eq', value: 'ops' }] }] }, { verb: 'slack.read' }] },
  { predicates: [{ verb: '*', where: [amt('lte', 10)] }] },
  { predicates: [{ verb: 'stripe.*' }, { verb: ['gmail.send', '*'] }] },
  { predicates: [{ verb: 'zzz.custom', resource: 'r', where: [{ field: 'action.params.x', op: 'eq', value: -5 }, { field: 'action.params.x', op: 'eq', value: 7 }, { field: 'action.params.y', op: 'eq', value: 'a' }, { field: 'action.params.y', op: 'prefix', value: 'ab' }] }] },
  { predicates: [] },
  {},
  { predicates: 5, caveats: 'x' },
  { predicates: [{ verb: 'stripe.payout', where: [amt('lte', 1e6)] }], caveats: [{ type: 'reversibility_max', max: 'reversible' }] },
];
const SLOTS: any[] = [
  { verbs: ['stripe.refund'], constraints: [{ path: 'action.params.amount', max: 250 }] },
  { verbs: ['stripe.refund', 'gmail.send'], constraints: [{ verb: 'stripe.refund', path: 'action.params.amount', min: 5, max: 250.5 }, { path: 'action.params.to', oneOf: ['a@x', 'b@x'], prefixOneOf: ['team-'] }, { verb: 'gmail.send', path: 'action.params.to', noneOf: ['evil@x'] }] },
  { verbs: ['files.read'], constraints: [{ path: 'action.resource', prefixOneOf: ['/shared/'] }, { path: 'env.hour', min: 9, max: 17, unit: 'hour' }] },
  { verbs: [], constraints: [] },
  { verbs: ['x.y'], constraints: [{ path: 'action.params.a', oneOf: ['only'] }, { path: 'action.params.b', prefixOneOf: ['p1', 'p2'] }] },
];
const OPTS: any[] = [];
for (const p of POLICIES) OPTS.push({ policies: [p] });
OPTS.push({ policies: [POLICIES[0], POLICIES[2]] }, { policies: [POLICIES[0], POLICIES[1], POLICIES[3]], extraVerbs: ['github.read'] });
for (const s of SLOTS) { OPTS.push({ policies: [], slots: s }); OPTS.push({ policies: [POLICIES[0]], slots: s }); }
OPTS.push({ policies: [POLICIES[0]], domains: { 'action.params.amount': { lo: 0, hi: 2 ** 40 } } });
OPTS.push({ policies: [POLICIES[1]], domains: { 'action.params.amount': { lo: -50, hi: 1000, dist: 'uniform' } } });
OPTS.push({ policies: [POLICIES[2]], domains: { 'env.hour': { lo: 0, hi: 47 } } });
OPTS.push({ policies: [{ predicates: [{ verb: 'stripe.charge', where: [amt('lte', 2 ** 52)] }] }], domains: { 'action.params.amount': { lo: 0, hi: 2 ** 53 - 1 } } });

const omegas: any[] = [];
for (const opts of OPTS) {
  await run('deriveOmega', O.deriveOmega, [opts]);
  try { omegas.push(O.deriveOmega(opts)); } catch {}
}
const hand: any = { v: 1, approximate: [], verbs: [{ verb: 'stripe.charge', reversibility: 'irreversible', weight: 0.5, dims: [
  { kind: 'num', path: 'action.params.amount', lo: 0, hi: 100000, cuts: [10, 100, 5000], dist: 'loguniform' },
  { kind: 'cat', path: 'action.params.to', values: [{ kind: 'exact', value: 'a' }, { kind: 'exact', value: 'b' }, { kind: 'prefix', value: 'team-' }, { kind: 'prefix', value: 'team-x-' }, { kind: 'other', value: '⊥' }] }] },
  { verb: 'files.read', reversibility: 'reversible', weight: 0.25, dims: [{ kind: 'num', path: 'env.hour', lo: 0, hi: 23, cuts: [9, 17], dist: 'uniform' }] },
  { verb: 'files.write', reversibility: 'rate_limited', weight: 0.25, dims: [{ kind: 'num', path: 'action.params.count', lo: -5, hi: 3000, cuts: [-5, 0, 1, 2000], dist: 'loguniform' },
    { kind: 'num', path: 'action.params.big', lo: 0, hi: 9007199254740991, cuts: [1, 1000000, 4503599627370496], dist: 'loguniform' }] }] };
omegas.push(hand);
omegas.push({ v: 1, approximate: [], verbs: [{ verb: 'v.empty', reversibility: 'reversible', weight: 1, dims: [] }] });

const dimsOf = (om: any) => om.verbs.flatMap((vs: any) => vs.dims.map((d: any) => ({ vs, d })));
const seen = new Set<string>();
for (const om of omegas.filter((x: any) => x.verbs.length < 8)) {
  await run('harmMax', O.harmMax, [om]);
  for (const vs of om.verbs) {
    await run('verbSpace', O.verbSpace, [om, vs.verb]);
    await run('verbCellCount', O.verbCellCount, [vs]);
    const total = O.verbCellCount(vs);
    const idxs: number[] = total <= 12 ? Array.from({ length: total }, (_, i) => i) : [0, 1, 2, 7, Math.floor(total / 2), total - 2, total - 1];
    for (const f of idxs) {
      const idx = O.decodeCell(vs, f);
      await run('decodeCell', O.decodeCell, [vs, f]);
      await run('encodeCell', O.encodeCell, [vs, idx]);
      await run('cellRep', O.cellRep, [vs, idx]);
      await run('cellStats', O.cellStats, [vs, idx]);
      const rep = O.cellRep(vs, idx);
      await run('cellOf', O.cellOf, [vs, rep]);
      await run('harmOf', O.harmOf, [vs, rep]);
      await run('regionOfCell', R.regionOfCell, [vs, idx]);
      const reg = R.regionOfCell(vs, idx);
      await run('regionCells', R.regionCells, [vs, reg, 'inner']);
      await run('regionCells', R.regionCells, [vs, reg, 'outer']);
      for (const x of vs.dims) { const rd = reg.dims[x.path]; await run('valueInRegionDim', R.valueInRegionDim, [x.path, rd, O.repValue(x, idx[vs.dims.indexOf(x)])]); }
    }
    await run('cellOf', O.cellOf, [vs, { verb: vs.verb, values: {} }]);
    await run('cellOf', O.cellOf, [vs, { verb: vs.verb, values: Object.fromEntries(vs.dims.map((d: any) => [d.path, d.kind === 'num' ? 'x' : 5])) }]);
    await run('regionCells', R.regionCells, [vs, { verb: 'other.verb', dims: {} }, 'inner']);
    await run('regionCells', R.regionCells, [vs, { verb: vs.verb, dims: { 'no.such.path': { kind: 'num', lo: 0, hi: 1 } } }, 'inner']);
    await run('regionCells', R.regionCells, [vs, { verb: vs.verb, dims: {} }, 'outer']);
    await run('seeded', O.cellRep, [vs, vs.dims.map(() => 0)]);
  }
  for (const seedv of [1, 7, 42, 2 ** 32 - 1]) await run('sampleOutcomes', (omg: any, s: number, k: number) => { const r = O.rng(s); return Array.from({ length: k }, () => O.sampleOutcome(omg, r).o); }, [om, seedv, 12]);
  for (const { vs, d } of dimsOf(om)) {
    const key = JSON.stringify(d); if (seen.has(key)) continue; seen.add(key);
    await run('cellCount', O.cellCount, [d]);
    const cc = O.cellCount(d);
    if (d.kind === 'num') {
      await run('numCells', O.numCells, [d]);
      const cells = O.numCells(d);
      for (let i = 0; i < Math.min(cc, 12); i++) { await run('numRep', O.numRep, [d, i]); await run('repValue', O.repValue, [d, i]); await run('dimCellStats', O.dimCellStats, [d, i]); await run('dimCellsIn', R.dimCellsIn, [d, { kind: 'num', lo: cells[i].lo, hi: cells[i].hi }, 'inner']); await run('dimCellsIn', R.dimCellsIn, [d, { kind: 'num', lo: cells[i].lo, hi: cells[i].hi + 3 }, 'outer']); await run('cellOfValue', O.cellOfValue, [d, cells[i].lo]); await run('cellOfValue', O.cellOfValue, [d, cells[i].hi]); }
      for (const x of [d.lo - 1, d.hi + 1, 'str', null, true]) await run('cellOfValue', O.cellOfValue, [d, x]);
      await run('dimCellsIn', R.dimCellsIn, [d, null, 'inner']);
      await run('dimCellsIn', R.dimCellsIn, [d, { kind: 'cat', values: [], cells: [] }, 'inner']);
      for (const [a, b] of [[d.lo, d.lo], [d.lo, Math.min(d.hi, d.lo + 4095)], [d.lo, Math.min(d.hi, d.lo + 4096)], [d.lo, d.hi], [d.hi, d.lo]]) await run('intervalWeight', O.intervalWeight, [d, a, b]);
      await run('restrictRegion', (dd: any, p: any) => R.restrictRegion({ verb: 'v', dims: {} }, dd, p), [d, { lo: 1, hi: 5 }]);
      await run('restrictRegion', (dd: any, p: any) => R.restrictRegion({ verb: 'v', dims: {} }, dd, p), [d, { cells: [0] }]);
    } else {
      for (let i = 0; i < cc; i++) { await run('catRep', O.catRep, [d, i]); await run('dimCellStats', O.dimCellStats, [d, i]); await run('dimCellsIn', R.dimCellsIn, [d, { kind: 'cat', values: d.values, cells: [i] }, 'inner']); await run('dimCellsIn', R.dimCellsIn, [d, { kind: 'cat', values: d.values.slice(-1), cells: [0] }, 'outer']); }
      for (const s of ['a', 'b', 'team-', 'team-x-1', 'team-y', 'zzz', '', 'ab', 'abc', 'x', '⊥']) { await run('catCellOf', O.catCellOf, [d, s]); await run('cellOfValue', O.cellOfValue, [d, s]); }
      await run('cellOfValue', O.cellOfValue, [d, 5]);
      await run('dimCellsIn', R.dimCellsIn, [d, { kind: 'num', lo: 0, hi: 1 }, 'inner']);
      await run('restrictRegion', (dd: any, p: any) => R.restrictRegion({ verb: 'v', dims: {} }, dd, p), [d, { cells: [0, cc - 1] }]);
      await run('restrictRegion', (dd: any, p: any) => R.restrictRegion({ verb: 'v', dims: {} }, dd, p), [d, { lo: 1, hi: 2 }]);
    }
  }
}

// ---- policy plumbing + slots ----
for (const p of POLICIES) { await run('normalizePolicy', P.normalizePolicy, [p]); }
await run('normalizePolicy', P.normalizePolicy, [null]); await run('normalizePolicy', P.normalizePolicy, ['s']);
for (const s of SLOTS) await run('slotsToPolicy', S.slotsToPolicy, [s]);
const op = (vs: any, ov: any) => P.outcomeToAction(vs, ov);
const adm = (pol: any, vs: any, ov: any) => P.admitter(pol).admits(vs, ov);
for (const om of omegas.filter((x: any) => x.verbs.length < 8)) for (const vs of om.verbs) {
  const total = O.verbCellCount(vs);
  const idxs: number[] = total <= 6 ? Array.from({ length: total }, (_, i) => i) : [0, 1, Math.floor(total / 2), total - 1];
  for (const f of idxs) {
    const ov = O.cellRep(vs, O.decodeCell(vs, f));
    await run('outcomeToAction', op, [vs, ov]);
    for (const pol of [POLICIES[0], POLICIES[2], POLICIES[3], POLICIES[8], POLICIES[12], slotsPol(SLOTS[1])]) await run('admits', adm, [pol, vs, ov]);
  }
}
function slotsPol(s: any) { return S.slotsToPolicy(s); }
const vsA: any = hand.verbs[0];
for (const ov of [{ verb: 'stripe.charge', values: { 'action.resource': 'acct_1', 'action.params.amount': 5, 'env.hour': 3, 'subject.role': 'admin', 'action.params.a.b': 'deep' } },
  { verb: 'stripe.charge', values: {} }, { verb: 'x', values: { 'action.params': 1, 'env': 2, 'subject': 3, 'zzz': 4, 'action.resource': 77 } }]) await run('outcomeToAction', op, [vsA, ov]);
await run('rngSeq', (s: number, k: number) => { const r = O.rng(s); return Array.from({ length: k }, () => r()); }, [1, 20]);
for (const s of [0, 7, 42, 123456789, 2 ** 32 - 1]) await run('rngSeq', (sd: number, k: number) => { const r = O.rng(sd); return Array.from({ length: k }, () => r()); }, [s, 8]);
// valueInRegionDim above is only ever asked about a cell's own representative (always inside). Here: the representative of EVERY cell of the
// dimension against one cell's region, the region's bounds and their neighbours, and a value of the wrong type.
for (const vs of hand.verbs) {
  const total = O.verbCellCount(vs);
  for (const f of [0, Math.floor(total / 2), total - 1]) {
    const reg = R.regionOfCell(vs, O.decodeCell(vs, f));
    for (const x of vs.dims) {
      const rd = reg.dims[x.path];
      for (let j = 0; j < O.cellCount(x); j++) await run('valueInRegionDim', R.valueInRegionDim, [x.path, rd, O.repValue(x, j)]);
      for (const v of rd.kind === 'num' ? [rd.lo, rd.hi, rd.lo - 1, rd.hi + 1, rd.lo - 0.5, rd.hi + 0.5, 'str'] : [5, '', 'zzz', 'team-q', 'team-x-9']) await run('valueInRegionDim', R.valueInRegionDim, [x.path, rd, v]);
    }
  }
}
const by: any = {}; for (const c of o.cases) by[c.fn] = (by[c.fn] || 0) + JSON.stringify(c).length; console.log(JSON.stringify(by));
refWrite(o, 'intent-omega');
