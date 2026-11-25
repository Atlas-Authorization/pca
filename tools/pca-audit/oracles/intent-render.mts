// Oracle: @atlasauth/pca-intent deterministic rendering (render.ts) and boundary witnesses (witnesses.ts). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; all compare by JSON value):
//   labelOf(path) / renderCondition(c) / renderCaveat(c) / renderGrant(policy) -> IntentRender.*; strings exact
//   renderQuestion(vs, cell) / renderAction(vs, values)                                     strings exact
//   claimsOf(policy, omega) -> [VerbClaim] JSON;  backTranslationDiff(grant, slots, omega) / claimDiff(a, b, omega, names?) -> [ClaimDiff] JSON
//   boundaryWitnesses(grant, omega) -> [Witness] JSON
//   checkWitnesses(witnesses, mode) -> {questions, mismatches}; mode: "agree" (oracle = grantAllows), "flip" (negated),
//        "flip-boundary" (negated for kind == boundary), "inside-only" (oracle = side == inside and kind != unconstrained)
// A throwing reference requires the native to throw.
import * as D0 from '../../../packages/pca-intent/src/omega';
import * as R0 from '../../../packages/pca-intent/src/render';
import * as W0 from '../../../packages/pca-intent/src/witnesses';
import * as S1 from '../../../packages/pca-intent/src/slots';
const S0: any = (S1 as any).default ?? S1;
import { Oracle, refWrite } from './lib.mjs';

const O: any = (D0 as any).default ?? D0;
const R: any = (R0 as any).default ?? R0;
const W: any = (W0 as any).default ?? W0;
const o = new Oracle('intent-render', 'tools/pca-audit/oracles/intent-render.mts', 'TS-reference oracle for intent rendering and witnesses.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const amt = (op: string, v: any) => ({ field: 'action.params.amount', op, value: v });
const CONDS: any[] = [
  amt('lte', 500), amt('lt', 99.5), amt('gte', 0), amt('gt', 1e21), amt('eq', 5), amt('ne', 5), amt('in', [1, 2, 3]), amt('nin', ['a', 'b']),
  { field: 'action.params.to', op: 'prefix', value: 'team-' }, { field: 'subject.role', op: 'exists' }, { field: 'subject.role', op: 'exists', value: false }, { field: 'subject.role', op: 'exists', value: true },
  { field: 'action.params.path', op: 'like', value: '%.txt' }, { field: 'action.params.path', op: 'matches', value: '^a' }, { field: 'action.params.kind', op: 'is_a', value: 'email' }, { field: 'action.params.g', op: 'member_of', value: 'grp' },
  { field: 'action.params.big_amount_x', op: 'gt', ref: 'action.params.other_amount' }, { field: 'action.resource', op: 'eq', value: '/x' }, { field: 'a.b', op: 'weird', value: 1 }, { field: 'a.b' }, { field: 'a.b', op: 5, value: null },
  { field: 'a.b', op: 'eq', value: null }, { field: 'a.b', op: 'in', value: ['x', 5, null, true, ['n']] }, { field: 'a.b', op: 'eq', value: { k: 1 } }, { field: 'a.b', op: 'eq', value: true },
  { all_of: [amt('lte', 5), { field: 'env.hour', op: 'gte', value: 9 }] }, { any_of: [amt('lte', 5), amt('gte', 50)] }, { not: amt('eq', 1) }, { not: { any_of: [{ all_of: [] }] } },
  { all_of: [] }, { any_of: [] }, { all_of: null }, { all_of: 'x' }, { any_of: {} }, { not: null }, { not: 5 }, { not: 'x' }, {}, null, 5, 'str', [], [1], { field: 5, op: 'eq' }, { field: null },
];
for (const c of CONDS) await run('renderCondition', R.renderCondition, [c]);
for (const p of ['action.params.amount', 'action.resource', 'env.hour', 'a', '', 'x.', '.x', 'a.b_c_d', 'a__b']) await run('labelOf', R.labelOf, [p]);
const CAVS: any[] = [
  { type: 'expires', at: 1800000000000 }, { type: 'expires', at: 0 }, { type: 'expires', at: -1 }, { type: 'expires', at: 1.9 }, { type: 'expires', at: '1800000000000' }, { type: 'expires', at: '' }, { type: 'expires', at: null }, { type: 'expires', at: true },
  { type: 'expires', at: 8.64e15 }, { type: 'expires', at: 8.64e15 + 1 }, { type: 'expires', at: -8.64e15 }, { type: 'expires', at: 253402300800000 }, { type: 'expires', at: -62198755200000 }, { type: 'expires', at: 253402300799999 },
  { type: 'expires' }, { type: 'expires', at: 'abc' }, { type: 'expires', at: [] }, { type: 'not_before', at: 1700000000123 }, { type: 'not_before' },
  { type: 'rate', max: 5, per_secs: 60 }, { type: 'rate', max: 0.1 }, { type: 'rate', max: 1e21, per_secs: null }, { type: 'rate', max: 'x', per_secs: [1, 2] }, { type: 'rate', max: { a: 1 } },
  { type: 'max_blast_radius', max: 0.5 }, { type: 'max_blast_radius' }, { type: 'reversibility_max', class: 'rate_limited' }, { type: 'reversibility_max', class: 'a_b_c' }, { type: 'reversibility_max' }, { type: 'reversibility_max', class: 5 },
  { type: 'delegation_depth', max: 2 }, { type: 'budget_alloc', limit: 10 }, { type: 'budget_alloc' }, { type: 'bogus' }, { type: 5 }, { type: null }, {}, null, 5, 'x', [], { type: ['expires'] },
];
for (const c of CAVS) await run('renderCaveat', R.renderCaveat, [c]);
const POL: any[] = [
  {}, { predicates: [] }, { predicates: 5 }, { predicates: [{ verb: 'stripe.refund', resource: '/acct/*', where: [amt('lte', 500)] }], caveats: [{ type: 'expires', at: 1800000000000 }] },
  { predicates: [{ verb: ['stripe.refund', 'nope.x', '*'], resource: 'acct_1' }, { verb: '*', resource: '*' }, { verb: 'gmail.send', resource: 're:^a.*$', where: [{ field: 'action.params.to', op: 'prefix', value: 'team-' }, { any_of: [amt('lte', 1), amt('gte', 9)] }] }] },
  { predicates: [{ verb: 'files.write' }, { verb: 'files.read', resource: 5 }, { verb: 'files.delete', resource: null }, { verb: 5 }, { verb: null }, { verb: [1, null, 'x'] }, { resource: '/x/' }, {}, 'str', 7, [], { verb: 'files.read', where: null }, { verb: 'files.read', where: [] }, { verb: 'files.read', where: [{}] }] },
  { predicates: [{ verb: 'files.read', where: {} }] }, { predicates: [{ verb: 'files.read', where: 'x' }] }, { predicates: [null] },
  { predicates: [{ verb: 'github.merge_pr' }], caveats: [{ type: 'rate', max: 3, per_secs: 60 }, { type: 'reversibility_max', class: 'rate_limited' }, { type: 'bogus' }, { type: 'max_blast_radius', max: 0.2 }, { type: 'delegation_depth', max: 1 }, { type: 'budget_alloc', limit: 5 }, { type: 'not_before', at: 1700000000000 }] },
  { predicates: [{ verb: 'stripe.charge' }], caveats: [{ type: 'expires', at: 'nan' }] }, { predicates: [{ verb: 'stripe.charge' }], caveats: [null] },
  { predicates: [{ verb: 'zz.unknown', resource: '/a/b/*' }] }, null, 5,
];
for (const p of POL) await run('renderGrant', R.renderGrant, [p]);

// ---- omegas ----
const derive = (policies: any[], slots?: any) => O.deriveOmega({ policies, ...(slots ? { slots } : {}) });
const G1 = { predicates: [{ verb: 'stripe.refund', resource: '/acct/*', where: [amt('lte', 500), { field: 'action.params.currency', op: 'in', value: ['usd', 'eur'] }] }] };
const G2 = { predicates: [{ verb: 'stripe.refund', resource: '/acct/*', where: [amt('lte', 1000)] }, { verb: 'gmail.send', where: [{ field: 'action.params.to', op: 'prefix', value: 'team-' }] }] };
const G3 = { predicates: [{ verb: 'stripe.refund', where: [{ any_of: [{ all_of: [amt('lte', 100), { field: 'action.params.currency', op: 'eq', value: 'usd' }] }, { all_of: [amt('lte', 10), { field: 'action.params.currency', op: 'eq', value: 'eur' }] }] }] }] };
const G4 = { predicates: [{ verb: 'files.read', resource: '/shared/*' }, { verb: 'files.write', resource: '/shared/tmp/*', where: [{ field: 'env.hour', op: 'gte', value: 9 }, { field: 'env.hour', op: 'lt', value: 17 }] }] };
const G5 = { predicates: [{ verb: 'stripe.refund', where: [amt('lte', 250)] }] };
const G6 = { predicates: [] };
const SL1 = { verbs: ['stripe.refund'], constraints: [{ path: 'action.params.amount', max: 250 }, { path: 'action.params.currency', oneOf: ['usd'] }] };
const SL2 = { verbs: ['stripe.refund', 'files.read'], constraints: [{ verb: 'stripe.refund', path: 'action.params.amount', min: 10, max: 500 }, { verb: 'files.read', path: 'action.resource', prefixOneOf: ['/shared/'] }] };
const SL3 = { verbs: ['gmail.send'], constraints: [{ path: 'action.params.to', noneOf: ['evil@x'] }] };
const cases: [any, any, any][] = [[G1, SL1, derive([G1, G5], SL1)], [G2, SL2, derive([G2, S0.slotsToPolicy(SL2)], SL2)], [G3, SL1, derive([G3, S0.slotsToPolicy(SL1)], SL1)], [G4, SL2, derive([G4, S0.slotsToPolicy(SL2)], SL2)], [G5, SL1, derive([G5, S0.slotsToPolicy(SL1)], SL1)], [G6, SL1, derive([G1], SL1)], [G1, SL3, derive([G1, G2], SL3)], [G2, SL3, derive([G2, S0.slotsToPolicy(SL3)], SL3)]];
const witnessModes = ['agree', 'flip', 'flip-boundary', 'inside-only'];
for (const [g, sl, om] of cases) {
  await run('claimsOf', R.claimsOf, [g, om]);
  await run('backTranslationDiff', R.backTranslationDiff, [g, sl, om]);
  await run('claimDiff', R.claimDiff, [g, S0.slotsToPolicy(sl), om]);
  await run('claimDiff', R.claimDiff, [S0.slotsToPolicy(sl), g, om, ['the grant', 'the intent']]);
  await run('boundaryWitnesses', W.boundaryWitnesses, [g, om]);
  const ws = W.boundaryWitnesses(g, om);
  for (const m of witnessModes) await run('checkWitnesses', (wl: any[], mode: string) => W.checkWitnesses(wl, (w: any) => mode === 'agree' ? w.grantAllows : mode === 'flip' ? !w.grantAllows : mode === 'flip-boundary' ? (w.kind === 'boundary' ? !w.grantAllows : w.grantAllows) : (w.side === 'inside' && w.kind !== 'unconstrained')), [ws, m]);
  for (const vs of om.verbs.slice(0, 3)) {
    const total = O.verbCellCount(vs);
    for (const f of [0, 1, Math.floor(total / 2), total - 1].filter((x) => x >= 0 && x < total)) {
      const idx = O.decodeCell(vs, f);
      await run('renderQuestion', R.renderQuestion, [vs, idx]);
      await run('renderAction', R.renderAction, [vs, O.cellRep(vs, idx).values]);
    }
  }
}
const vsU: any = { verb: 'nope.verb', reversibility: 'rate_limited', weight: 1, dims: [{ kind: 'num', path: 'action.params.amount', lo: 0, hi: 10, cuts: [5], dist: 'uniform' }, { kind: 'cat', path: 'action.params.to', values: [{ kind: 'exact', value: 'a' }, { kind: 'prefix', value: 'p' }, { kind: 'other', value: '⊥' }] }, { kind: 'num', path: 'env.hour', lo: 3, hi: 3, cuts: [], dist: 'uniform' }] };
for (const idx of [[0, 0, 0], [1, 1, 0], [2, 2, 0], [0, 2, 0]]) await run('renderQuestion', R.renderQuestion, [vsU, idx]);
for (const vals of [{}, { 'action.params.amount': 5, 'action.params.to': 'a"b' }, { z: 1.5, a: 'x', 'e.f_g': 1e21, b: -0.5, 'action.resource': '/r' }, { k: true, n: null }]) await run('renderAction', R.renderAction, [vsU, vals]);
refWrite(o, 'intent-render');
