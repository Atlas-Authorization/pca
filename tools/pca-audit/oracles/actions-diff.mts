// Oracle: @atlasauth/pca-actions idpattern.ts + effective.ts + diff.ts + defdiff.ts. Writes out/ref-actions-diff.json.gz.
// PORTING table: fn(args) -> native entry point, comparison rule (a registry arg is null = the core registry; `confirmed` stands for
// ReviewOpts.attestationVerified returning that constant)
//   idPatternError(p)                      -> Actions.idPatternError is package-private: covered by the earlier action-kit oracle (not ported here)
//   idMatches(p, id)                       -> ActionIdPattern.idMatches
//   idPatternContains(outer, inner)        -> ActionIdPattern.idPatternContains
//   impliedTraits / hintTraits(def)        -> ActionEffective.hintTraits (hintTraits only; impliedTraits = hintTraits minus declared)
//   effective(def, confirmed)              -> ActionEffective.effective(def, CORE, d -> confirmed)
//   effWithTrait(def, trait)               -> ActionEffective.effWithTrait
//   prulesViolations(def)                  -> ActionEffective.prulesViolations; requiredPrulesViolated(def, effProfile)
//   join / leq / profileEq(p, q)           -> ActionEffective.join / leq / profileEq
//   diffDefs(prev, next, confirmed)        -> ActionDiff.diffDefs (diff.ts: {class, reasons}); a throw (diff_verb) must throw
//   diffIsFree(class)                      -> ActionDiff.diffIsFree
//   diffDefsAuthoring(a, b)                -> ActionDefDiff.diffDefs (defdiff.ts); diffPacks(olds, news) -> ActionDefDiff.diffPacks
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as V0 from '../../../packages/pca-actions/src/validate.ts';
import * as ID0 from '../../../packages/pca-actions/src/idpattern.ts';
import * as E0 from '../../../packages/pca-actions/src/effective.ts';
import * as DF0 from '../../../packages/pca-actions/src/diff.ts';
import * as DD0 from '../../../packages/pca-actions/src/defdiff.ts';
import * as T0 from '../../../packages/pca-actions/src/traits.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import { Oracle, variants, refWrite, clone, rng } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), DM = un(DM0), V = un(V0), ID = un(ID0), E = un(E0), DF = un(DF0), DD = un(DD0), T = un(T0), CT = un(CT0);
const CORE = CT.CORE_REGISTRY;
const o = new Oracle('actions-diff', 'tools/pca-audit/oracles/actions-diff.mts', 'TS-reference oracle for pca-actions id patterns, effective profiles, semantic diffs.');
const R = rng(0x5eed06);

const ALL: any[] = [...BI.BUILTIN_DEFS, ...DM.DOMAIN_DEFS].map((d: any) => clone(d));
const valid = (d: any) => { try { return V.validateDef(d) === null; } catch { return false; } };
const confirmedOpts = (c: boolean) => ({ attestationVerified: () => c });

// ---- id patterns ----
const PATS: any[] = ['*', { exact: 'abc' }, { exact: 'a/b:c' }, { prefix: '', class: 'digits', len: [1, 5] }, { prefix: 'inv_', class: 'alnum', len: [4, 16] }, { prefix: 'inv_', class: 'hex', len: [4, 8] }, { prefix: 'inv_a', class: 'hex', len: [1, 4] },
  { prefix: '', class: 'uuid', len: [36, 36] }, { prefix: 'x', class: 'slug', len: [1, 128] }, { prefix: 'ch_', class: 'any_safe', len: [4, 64] }, { prefix: '', class: 'any_safe', len: [1, 128] }, { exact: '0123' }, { prefix: 'a', class: 'digits', len: [2, 3] }];
const IDS = ['', 'abc', 'a/b:c', '0123', 'inv_1234', 'inv_abcd1234', 'inv_ZZZZ', 'inv_', 'inv_ab', 'ch_' + 'x'.repeat(10), '550e8400-e29b-41d4-a716-446655440000', '550E8400-E29B-41D4-A716-446655440000', 'a1', 'a12', 'a1234', 'x_-1', 'é', 'a'.repeat(129), 'a'.repeat(128)];
for (const [i, p] of PATS.entries()) {
  for (const [k, id] of IDS.entries()) await o.run("idMatches", `p${i} id${k}`, ID.idMatches, [p, id]);
  for (const [j, q] of PATS.entries()) await o.run('idPatternContains', `p${i} p${j}`, ID.idPatternContains, [p, q]);
}

// ---- profile lattice ----
const PROFS: any[] = [T.BOTTOM, T.profile({ risk: 2, rev: 'irreversible', blast_ppm: 300000, esc: 1, caveats: ['amount_cap'], context: ['idempotency'], prules: ['array_bounded'] }),
  T.profile({ risk: 1, rev: 'rate_limited', blast_ppm: 700000, esc: 2, caveats: ['amount_cap', 'window'], context: [], prules: [] }), T.profile({ risk: 3, rev: 'reversible', blast_ppm: 50000, esc: 0, caveats: [], context: ['revocable'], prules: ['pay_has_idempotency'] })];
for (const [i, p] of PROFS.entries()) for (const [j, q] of PROFS.entries()) for (const fn of ['join', 'leq', 'profileEq']) await o.run(fn, `${i} ${j}`, T[fn], [clone(p), clone(q)]);

// ---- effective on every def ----
for (const d of ALL) {
  for (const c of [true, false]) await o.run('effective', `${d.verb} ${c}`, (x: any, cc: any) => E.effective(x, CORE, confirmedOpts(cc)), [d, c]);
  await o.run('hintTraits', d.verb, E.hintTraits, [d]);
  await o.run('prulesViolations', d.verb, E.prulesViolations, [d]);
  await o.run('effWithTrait', d.verb, (x: any, t: any) => E.effWithTrait(x, t, CORE), [d, 'pca.bulk']);
  const eff = E.effective(d, CORE, confirmedOpts(true)).eff;
  await o.run('requiredPrulesViolated', d.verb, E.requiredPrulesViolated, [d, clone(eff)]);
}

// ---- diffs: each of a few seeds against its valid structural variants ----
const SEEDS = [0, 3, 7, 12, 19, 27].map((i) => ALL[i % ALL.length]);
let nPairs = 0;
for (const d of SEEDS) {
  const vs: [string, any][] = [];
  for (const [lbl, v] of variants(d, { maxPaths: 200, hostile: [null, 0, 1, 1.5, '', 'x', [], {}, true] })) if (valid(v) && JSON.stringify(v) !== JSON.stringify(d)) vs.push([lbl, v]);
  const pick = vs.filter(() => R.next() < Math.min(1, 80 / Math.max(1, vs.length)));
  for (const [lbl, v] of pick) {
    nPairs++;
    for (const c of [false]) await o.run('diffDefs', `${d.verb} ${lbl} ${c}`, (a: any, b: any, cc: any) => DF.diffDefs(a, b, CORE, confirmedOpts(cc)), [d, v, c]);
    await o.run('diffDefsAuthoring', `${d.verb} ${lbl}`, (a: any, b: any) => DD.diffDefs(a, b, CORE), [d, v]);
  }
  await o.run('diffDefs', `${d.verb} self confirmed`, (a: any, b: any, cc: any) => DF.diffDefs(a, b, CORE, confirmedOpts(cc)), [d, clone(d), true]);
  await o.run('diffDefs', `${d.verb} self`, (a: any, b: any, cc: any) => DF.diffDefs(a, b, CORE, confirmedOpts(cc)), [d, clone(d), false]);
}
// review-state flips and text edits
for (const d of SEEDS.slice(0, 3)) {
  const t = clone(d); t.title = 'Other title'; await o.run('diffDefs', `${d.verb} title`, (a: any, b: any) => DF.diffDefs(a, b, CORE, {}), [d, t]); await o.run('diffDefsAuthoring', `${d.verb} title`, (a: any, b: any) => DD.diffDefs(a, b, CORE), [d, t]);
  const r = clone(d); r.review = { state: 'confirmed', attestation: { x: 1 } }; await o.run('diffDefsAuthoring', `${d.verb} review confirmed`, (a: any, b: any) => DD.diffDefs(a, b, CORE), [r, d]);
}
// two different verbs
await o.run('diffDefs', 'verbs differ', (a: any, b: any) => DF.diffDefs(a, b, CORE, {}), [ALL[0], ALL[1]]);
await o.run('diffDefsAuthoring', 'verbs differ', (a: any, b: any) => DD.diffDefs(a, b, CORE), [ALL[0], ALL[1]]);
for (const c of ['equal', 'narrow', 'widen', 'incomparable', 'x']) await o.run('diffIsFree', c, DF.diffIsFree, [c]);
// packs
const mutated = (d: any, f: (x: any) => void) => { const c = clone(d); f(c); return c; };
await o.run('diffPacks', 'mixed', (a: any, b: any) => DD.diffPacks(a, b, CORE), [ALL.slice(0, 6), [mutated(ALL[0], (x) => (x.title = 'T')), ALL[1], mutated(ALL[2], (x) => { x.effects = [...x.effects, 'read'].filter((v: any, i: number, a2: any[]) => a2.indexOf(v) === i); }), ALL[6], ALL[7]]]);
await o.run('diffPacks', 'empty', (a: any, b: any) => DD.diffPacks(a, b, CORE), [[], []]);
await o.run('diffPacks', 'all added', (a: any, b: any) => DD.diffPacks(a, b, CORE), [[], ALL.slice(0, 3)]);
await o.run('diffPacks', 'all removed', (a: any, b: any) => DD.diffPacks(a, b, CORE), [ALL.slice(0, 3), []]);
console.log('pairs', nPairs, 'defs', ALL.length);
refWrite(o, 'actions-diff');
