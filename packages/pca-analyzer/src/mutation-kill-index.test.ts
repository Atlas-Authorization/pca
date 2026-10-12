import { describe, expect, it } from 'vitest';
import type { Condition, Predicate } from '@atlasauth/pca';
import { collectProbes, productSize } from './enumerate';
import {
  admitsConcrete,
  alwaysAllows,
  alwaysDenies,
  disjoint,
  equivalent,
  intentConformance,
  predicateNumericSatisfiable,
  reachable,
  subsumes,
} from './index';

const cond = (field: string, op: string, value?: unknown, extra: object = {}) => ({ field, op, value, ...extra }) as unknown as Condition;
const pred = (verb: string | string[], resource: string | undefined, where?: Condition[]) => ({ verb, resource, ...(where ? { where } : {}) }) as unknown as Predicate;
const pol = (predicates: Predicate[], caveats: unknown[] = []) => ({ predicates, caveats: caveats as never });
const num = (op: string, v: number) => cond('action.params.n', op, v);
const LIKE = cond('action.params.s', 'like', 'x');
const LIKE_MSG = '`like` condition — matched by over-approximation, not enumerated exactly';
const REF = cond('action.params.n', 'eq', 1, { ref: 'env.y' });
const REF_MSG = 'cross-field `ref` condition — the relation between two fields is not resolved';
const RE_MSG = 're: regex resource matcher — resource dimension cannot be soundly enumerated';

describe('reachable', () => {
  it('caveat unsat', () => {
    expect(reachable(pol([pred('a', '*')], [{ type: 'rate', max: 0, per_secs: 1 }]), { verb: 'a', resource: 'r' })).toEqual({
      reachable: false,
      reason: 'caveats unsatisfiable: rate.max 0 < 1 forbids every action',
    });
  });
  it('reversibility cap', () => {
    const p = pol([pred('a', '*')], [{ type: 'reversibility_max', class: 'rate_limited' }]);
    expect(reachable(p, { verb: 'a', resource: 'r', reversibilityClass: 'irreversible' })).toEqual({
      reachable: false,
      reason: "reversibility class 'irreversible' exceeds the caveat cap",
    });
    expect(reachable(p, { verb: 'a', resource: 'r', reversibilityClass: 'bogus' }).reachable).toBe(false);
    const ok = reachable(p, { verb: 'a', resource: 'r', reversibilityClass: 'rate_limited' });
    expect(ok.reachable).toBe(true);
    // no class given: search over classes finds one within the cap
    const free = reachable(p, { verb: 'a', resource: 'r' });
    expect(free.reachable).toBe(true);
    expect(free.witness?.reversibilityClass).toBe('reversible');
  });
  it('class without cap is not checked', () => {
    expect(reachable(pol([pred('a', '*')]), { verb: 'a', resource: 'r', reversibilityClass: 'bogus' }).reachable).toBe(true);
  });
  it('fast path returns the action itself', () => {
    const act = { verb: 'a', resource: 'r', params: { n: 2 } };
    const r = reachable(pol([pred('a', '*', [num('gt', 1)])]), act);
    expect(r).toEqual({ reachable: true, witness: act });
    expect(r.witness).toBe(act);
  });
  it('existential search fills free params and merges witness', () => {
    const r = reachable(pol([pred('a', '*', [num('gt', 10), cond('action.params.m', 'eq', 'k')])]), {
      verb: 'a',
      resource: 'r',
      params: { m: 'k' },
    });
    expect(r.reachable).toBe(true);
    expect((r.witness?.params?.['n'] as number) > 10).toBe(true);
    expect(r.witness?.params?.['m']).toBe('k');
    expect(r.witness?.verb).toBe('a');
    expect(r.witness?.resource).toBe('r');
  });
  it('provided params pin a field (not searched)', () => {
    const p = pol([pred('a', '*', [num('gt', 10)])]);
    const r = reachable(p, { verb: 'a', resource: 'r', params: { n: 5 } });
    expect(r).toEqual({ reachable: false, reason: 'no predicate admits this action for any input (proven over the decided fragment)' });
    // inherited keys are not "provided"
    const inh = Object.create({ n: 5 }) as Record<string, unknown>;
    expect(reachable(p, { verb: 'a', resource: 'r', params: inh }).reachable).toBe(true);
    // pinned provided key for a different field path does not pin this one
    expect(reachable(p, { verb: 'a', resource: 'r', params: { other: 1 } }).reachable).toBe(true);
  });
  it('subject/env witnesses are carried; reversibility from provided preferred', () => {
    const r = reachable(pol([pred('a', '*', [cond('subject.role', 'eq', 'admin'), cond('env.z', 'eq', 'eu')])]), { verb: 'a', resource: 'r' });
    expect(r.witness?.subject).toEqual({ role: 'admin' });
    expect(r.witness?.env).toEqual({ z: 'eu' });
    const r2 = reachable(pol([pred('a', '*')]), { verb: 'a', resource: 'r', params: {} });
    expect('subject' in (r2.witness ?? {})).toBe(false);
    const r3 = reachable(pol([pred('a', '*', [cond('subject.s', 'eq', 1)])], [{ type: 'reversibility_max', class: 'irreversible' }]), {
      verb: 'a',
      resource: 'r',
      reversibilityClass: 'reversible',
    });
    expect(r3.witness?.reversibilityClass).toBe('reversible');
    expect(r3.witness?.subject).toEqual({ s: 1 });
  });
  it('witness without a class when none applies', () => {
    const r = reachable(pol([pred('a', '*', [num('gt', 1)])]), { verb: 'a', resource: 'r' });
    expect('reversibilityClass' in (r.witness ?? {})).toBe(false);
  });
  it('overflow fails safe', () => {
    const p = pol([pred('a', '*', [num('gt', 10)])]);
    expect(reachable(p, { verb: 'a', resource: 'r', params: { n: 1 } }, { maxCombinations: 100 }).reachable).toBe(false);
    const big = pol([pred('a', '*', [num('gt', 10), cond('action.params.m', 'gt', 3), cond('action.params.k', 'gt', 3)])]);
    const hard = { verb: 'a', resource: 'r', params: { n: 1 } };
    // grid = 1*1*1*(6? )... use bound just below/at the exact product
    const exact = reachable(big, hard, { maxCombinations: 1_000_000 });
    expect(exact.approximate).toBeUndefined();
    const over = reachable(big, hard, { maxCombinations: 1 });
    expect(over).toEqual({ reachable: true, approximate: true, reason: 'representative grid exceeded the bound; could not prove unreachable' });
  });
  it('overflow boundary is exact', () => {
    const preds = [pred('a', '*', [cond('action.params.m', 'gt', 100), cond('action.params.m', 'lt', 50)])];
    const fieldsOnly = productSize({ ...collectProbes({ predicateSets: [preds], varyReversibility: false }), verbs: ['a'], resources: ['r'] });
    expect(fieldsOnly).toBeGreaterThan(2);
    const free = { verb: 'a', resource: 'r' };
    const at = reachable(pol(preds), free, { maxCombinations: fieldsOnly });
    expect(at).toEqual({ reachable: false, reason: 'no predicate admits this action for any input (proven over the decided fragment)' });
    expect(reachable(pol(preds), free, { maxCombinations: fieldsOnly - 1 }).approximate).toBe(true);
    // pinned param: product 1
    expect(reachable(pol(preds), { verb: 'a', resource: 'r', params: { m: 0 } }, { maxCombinations: 1 }).reachable).toBe(false);
    expect(reachable(pol(preds), { verb: 'a', resource: 'r', params: { m: 0 } }, { maxCombinations: 0 }).approximate).toBe(true);
    // reversibility classes multiply the grid when capped
    const cap = pol(preds, [{ type: 'reversibility_max', class: 'irreversible' }]);
    expect(reachable(cap, free, { maxCombinations: fieldsOnly * 3 }).approximate).toBeUndefined();
    expect(reachable(cap, free, { maxCombinations: fieldsOnly * 3 - 1 }).approximate).toBe(true);
    expect(reachable(cap, { ...free, reversibilityClass: 'reversible' }, { maxCombinations: fieldsOnly }).approximate).toBeUndefined();
  });
  it('undecidable fails safe with reason', () => {
    const r = reachable(pol([pred('a', '*', [LIKE, REF])]), { verb: 'a', resource: 'r', params: { s: 'no' } });
    expect(r.reachable).toBe(true);
    expect(r.approximate).toBe(true);
    expect(r.reason).toBe(`over-approximated (${REF_MSG}; ${LIKE_MSG}); could not construct a witness but cannot prove unreachable`.replace(`${REF_MSG}; ${LIKE_MSG}`, r.reason!.slice('over-approximated ('.length, r.reason!.indexOf(');')).toString()));
    expect(r.reason).toContain(LIKE_MSG);
    expect(r.reason).toContain(REF_MSG);
    expect(r.reason).toMatch(/^over-approximated \(.*\); could not construct a witness but cannot prove unreachable$/);
  });
  it('multi-verb arrays and resource matchers', () => {
    const p = pol([pred(['a', 'b'], '/x/*')]);
    expect(reachable(p, { verb: 'b', resource: '/x/1' }).reachable).toBe(true);
    expect(reachable(p, { verb: 'c', resource: '/x/1' }).reachable).toBe(false);
    expect(reachable(p, { verb: 'a', resource: '/y/1' }).reachable).toBe(false);
  });
});

describe('alwaysDenies', () => {
  it('caveat unsat', () => {
    expect(alwaysDenies(pol([pred('a', '*')], [{ type: 'zzz' }]))).toEqual({
      alwaysDenies: true,
      reason: "caveats unsatisfiable: unknown caveat type 'zzz' (fail closed)",
    });
  });
  it('witness / vacuous / verb filter', () => {
    const p = pol([pred('a', '*')]);
    const r = alwaysDenies(p);
    expect(r.alwaysDenies).toBe(false);
    expect(r.witness?.verb).toBe('a');
    expect(alwaysDenies(p, 'b')).toEqual({ alwaysDenies: true });
    expect(alwaysDenies(p, 'a').alwaysDenies).toBe(false);
    expect(alwaysDenies(pol([]))).toEqual({ alwaysDenies: true });
  });
  it('overflow & undecidable', () => {
    const p = pol([pred('a', '*', [num('gt', 1), num('lt', 0)])]);
    expect(alwaysDenies(p)).toEqual({ alwaysDenies: true });
    expect(alwaysDenies(p, undefined, { maxCombinations: 1 })).toEqual({
      alwaysDenies: false,
      approximate: true,
      reason: 'grid exceeded the bound; cannot prove vacuity',
    });
    const u = alwaysDenies(pol([pred('a', 're:q')]));
    expect(u).toEqual({ alwaysDenies: false, approximate: true, reason: `over-approximated (${RE_MSG}); cannot prove vacuity` });
  });
  it('overflow boundary exact', () => {
    const preds = [pred('a', '*', [num('gt', 1), num('lt', 0)])];
    const size = productSize(collectProbes({ predicateSets: [preds], varyReversibility: false }));
    expect(alwaysDenies(pol(preds), undefined, { maxCombinations: size })).toEqual({ alwaysDenies: true });
    expect(alwaysDenies(pol(preds), undefined, { maxCombinations: size - 1 }).approximate).toBe(true);
    // a verb restriction collapses the verb dimension
    const sizeA = size / 2;
    expect(alwaysDenies(pol(preds), 'a', { maxCombinations: sizeA })).toEqual({ alwaysDenies: true });
    expect(alwaysDenies(pol(preds), 'a', { maxCombinations: sizeA - 1 }).approximate).toBe(true);
  });
  it('rev classes vary only when a cap exists', () => {
    const p = pol([pred('a', '*')], [{ type: 'reversibility_max', class: 'reversible' }]);
    const r = alwaysDenies(p);
    expect(r.alwaysDenies).toBe(false);
    expect(r.witness?.reversibilityClass).toBe('reversible');
  });
});

describe('alwaysAllows', () => {
  it('caveat unsat', () => {
    expect(alwaysAllows(pol([pred('a', '*')], [{ type: 'zzz' }]), 'a')).toEqual({
      alwaysAllows: false,
      reason: "caveats unsatisfiable: unknown caveat type 'zzz' (fail closed)",
    });
  });
  it('total / counterexample / verb restriction', () => {
    expect(alwaysAllows(pol([pred('a', '*')]), 'a')).toEqual({ alwaysAllows: true });
    expect(alwaysAllows(pol([pred('a', '*')]), 'b').alwaysAllows).toBe(false);
    const r = alwaysAllows(pol([pred('a', '*', [num('lt', 5)])]), 'a');
    expect(r.alwaysAllows).toBe(false);
    expect(r.counterexample?.verb).toBe('a');
    // total for verb a even though other verbs are denied
    expect(alwaysAllows(pol([pred('a', '*'), pred('b', 'only')]), 'a').alwaysAllows).toBe(true);
  });
  it('overflow & undecidable', () => {
    const p = pol([pred('a', '*')]);
    expect(alwaysAllows(p, 'a', { maxCombinations: 0 })).toEqual({
      alwaysAllows: false,
      approximate: true,
      reason: 'grid exceeded the bound; cannot prove totality',
    });
    expect(alwaysAllows(p, 'a', { maxCombinations: 1 })).toEqual({ alwaysAllows: true });
    expect(alwaysAllows(pol([pred('a', '*'), pred('a', '*', [LIKE])]), 'a')).toEqual({
      alwaysAllows: false,
      approximate: true,
      reason: `over-approximated (${LIKE_MSG}); cannot prove totality`,
    });
  });
});

describe('subsumes / disjoint / equivalent', () => {
  const lo = pol([pred('a', '*', [num('lt', 5)])]);
  const hi = pol([pred('a', '*', [num('lt', 10)])]);
  it('subsumes', () => {
    expect(subsumes(hi, lo)).toEqual({ subsumes: true });
    const r = subsumes(lo, hi);
    expect(r.subsumes).toBe(false);
    const n = r.counterexample?.params?.['n'] as number;
    expect(n >= 5 && n < 10).toBe(true);
    // direction: counterexample admitted by b not a
    expect(subsumes(pol([pred('a', '*')]), pol([pred('b', '*')])).counterexample?.verb).toBe('b');
  });
  it('subsumes approximate', () => {
    expect(subsumes(hi, lo, { maxCombinations: 1 })).toEqual({
      subsumes: false,
      approximate: true,
      reason: 'representative grid exceeded the bound; cannot prove the relation',
    });
    const u = pol([pred('a', 're:q')]);
    const r = subsumes(u, pol([pred('a', 'q')]));
    expect(r.subsumes).toBe(false);
    expect(r.approximate).toBe(true);
    expect(r.reason).toBe(`over-approximated (${RE_MSG}); cannot prove the relation`);
    // reasons deduped across both models
    const both = subsumes(u, u);
    expect(both.reason).toBe(`over-approximated (${RE_MSG}); cannot prove the relation`);
    // reasons from either side are listed
    expect(subsumes(pol([pred('a', '*', [LIKE])]), pol([pred('a', '*', [REF])])).reason).toBe(
      `over-approximated (${LIKE_MSG}; ${REF_MSG}); cannot prove the relation`,
    );
  });
  it('a counterexample wins over an approximate flag', () => {
    const r = subsumes(pol([pred('a', 're:q')]), pol([pred('b', '*')]));
    expect(r.subsumes).toBe(false);
    expect(r.approximate).toBeUndefined();
    expect(r.counterexample).toBeDefined();
  });
  it('caveats are part of admission', () => {
    const capped = pol([pred('a', '*')], [{ type: 'reversibility_max', class: 'reversible' }]);
    const plain = pol([pred('a', '*')]);
    expect(subsumes(plain, capped)).toEqual({ subsumes: true });
    const r = subsumes(capped, plain);
    expect(r.subsumes).toBe(false);
    expect(r.counterexample?.reversibilityClass).not.toBe('reversible');
    // revClass varied if EITHER side caps (second model)
    expect(subsumes(plain, capped).subsumes).toBe(true);
    expect(equivalent(plain, capped).equivalent).toBe(false);
  });
  it('disjoint', () => {
    expect(disjoint(lo, pol([pred('a', '*', [num('gt', 6)])]))).toEqual({ disjoint: true });
    const r = disjoint(lo, hi);
    expect(r.disjoint).toBe(false);
    expect((r.witness?.params?.['n'] as number) < 5).toBe(true);
    // both must admit: one side alone is not a witness
    expect(disjoint(pol([pred('a', '*')]), pol([pred('b', '*')]))).toEqual({ disjoint: true });
    expect(disjoint(lo, hi, { maxCombinations: 1 })).toEqual({
      disjoint: false,
      approximate: true,
      reason: 'representative grid exceeded the bound; cannot prove the relation',
    });
    const u = disjoint(pol([pred('a', 're:q')]), pol([pred('b', '*')]));
    expect(u.disjoint).toBe(false);
    expect(u.approximate).toBe(true);
    expect(u.reason).toBe(`over-approximated (${RE_MSG}); cannot prove the relation`);
  });
  it('equivalent', () => {
    expect(equivalent(lo, pol([pred('a', '*', [num('lt', 5)])]))).toEqual({ equivalent: true });
    const r = equivalent(lo, hi);
    expect(r.equivalent).toBe(false);
    expect(r.counterexample).toBeDefined();
    expect(equivalent(hi, lo).counterexample).toBeDefined();
    expect(equivalent(lo, hi, { maxCombinations: 1 })).toEqual({
      equivalent: false,
      approximate: true,
      reason: 'representative grid exceeded the bound; cannot prove the relation',
    });
    const u = equivalent(pol([pred('a', 're:q')]), pol([pred('a', 're:q')]));
    expect(u).toEqual({ equivalent: false, approximate: true, reason: `over-approximated (${RE_MSG}); cannot prove the relation` });
  });
  it('overflow boundary exact for relations', () => {
    const size = productSize(collectProbes({ predicateSets: [lo.predicates, hi.predicates], varyReversibility: false }));
    const at = { maxCombinations: size };
    const under = { maxCombinations: size - 1 };
    const hiRedundant = pol([pred('a', '*', [num('lt', 10)]), pred('a', '*', [num('lt', 5)])]);
    expect(equivalent(hi, hiRedundant, at)).toEqual({ equivalent: true });
    expect(equivalent(hi, hiRedundant, under).approximate).toBe(true);
    expect(subsumes(hi, lo, at)).toEqual({ subsumes: true });
    expect(subsumes(hi, lo, under).approximate).toBe(true);
    expect(disjoint(pol([pred('a', '*', [num('lt', 5)])]), pol([pred('a', '*', [num('gt', 10)])]), under).approximate).toBe(true);
    // rev classes multiply when EITHER side caps
    const cap = pol([pred('a', '*')], [{ type: 'reversibility_max', class: 'reversible' }]);
    const plain = pol([pred('a', '*')]);
    const sz = productSize(collectProbes({ predicateSets: [plain.predicates, cap.predicates], varyReversibility: true }));
    expect(sz).toBe(productSize(collectProbes({ predicateSets: [plain.predicates, cap.predicates], varyReversibility: false })) * 3);
    expect(subsumes(plain, cap, { maxCombinations: sz })).toEqual({ subsumes: true });
    expect(subsumes(plain, cap, { maxCombinations: sz - 1 }).approximate).toBe(true);
    expect(subsumes(cap, plain, { maxCombinations: sz - 1 }).approximate).toBe(true);
    expect(equivalent(cap, plain, { maxCombinations: sz }).equivalent).toBe(false);
  });
});

describe('intentConformance', () => {
  const stripe = pol([pred('stripe.refund', '*', [cond('action.params.amount', 'lte', 20000)])]);
  it('unsat caveats conform trivially', () => {
    expect(intentConformance(pol([pred('a', '*')], [{ type: 'zzz' }]), { verbs: [] })).toEqual({ conforms: true, violations: [] });
  });
  it('over / under amount, default amountField and minAmount', () => {
    const r = intentConformance(stripe, { verbs: ['stripe.refund'], maxAmount: 100 });
    expect(r.conforms).toBe(false);
    expect(r.violations.every((v) => v.kinds.length > 0)).toBe(true);
    expect(r.violations.some((v) => v.kinds.includes('over-amount'))).toBe(true);
    // minAmount default 0: negative amounts are under-amount
    const neg = pol([pred('stripe.refund', '*', [cond('action.params.amount', 'gte', -5)])]);
    const n = intentConformance(neg, { verbs: ['stripe.refund'], maxAmount: 100 });
    expect(n.violations.some((v) => v.kinds.includes('under-amount'))).toBe(true);
    expect(n.violations.every((v) => !v.kinds.includes('over-amount') || (v.action.params?.['amount'] as number) > 100)).toBe(true);
    const fine = intentConformance(neg, { verbs: ['stripe.refund'], maxAmount: 100, minAmount: -5 });
    expect(fine.violations.some((v) => v.kinds.includes('under-amount'))).toBe(false);
    // amount exactly at min / max is within
    const edge = pol([pred('stripe.refund', '*', [cond('action.params.amount', 'gte', 10), cond('action.params.amount', 'lte', 50)])]);
    expect(intentConformance(edge, { verbs: ['stripe.refund'], maxAmount: 50, minAmount: 10 })).toEqual({ conforms: true, violations: [] });
    expect(intentConformance(edge, { verbs: ['stripe.refund'], maxAmount: 49, minAmount: 10 }).conforms).toBe(false);
    expect(intentConformance(edge, { verbs: ['stripe.refund'], maxAmount: 50, minAmount: 11 }).conforms).toBe(false);
  });
  it('custom amountField', () => {
    const p = pol([pred('pay', '*', [cond('action.params.cents', 'lte', 500)])]);
    expect(intentConformance(p, { verbs: ['pay'], maxAmount: 100, amountField: 'cents' }).conforms).toBe(false);
    // the default field 'amount' is unconstrained by the policy, so amounts above the cap are admitted
    expect(intentConformance(p, { verbs: ['pay'], maxAmount: 100 }).violations.some((v) => v.kinds.includes('over-amount'))).toBe(true);
  });
  it('non-numeric amounts are ignored; no maxAmount => no amount checks', () => {
    const p = pol([pred('pay', '*', [cond('action.params.amount', 'eq', 'lots')])]);
    expect(intentConformance(p, { verbs: ['pay'], maxAmount: 1 }).conforms).toBe(true);
    const q = pol([pred('pay', '*', [cond('action.params.amount', 'gt', 1e9)])]);
    expect(intentConformance(q, { verbs: ['pay'] }).conforms).toBe(true);
  });
  it('verbs: wildcard and membership', () => {
    const p = pol([pred(['a', 'b'], '*')]);
    expect(intentConformance(p, { verbs: ['*'] }).conforms).toBe(true);
    const r = intentConformance(p, { verbs: ['a'] });
    expect(r.conforms).toBe(false);
    expect(r.violations).toHaveLength(1);
    expect(r.violations[0]?.action.verb).toBe('b');
    expect(r.violations[0]?.kinds).toEqual(['off-verb']);
    expect(intentConformance(p, { verbs: ['a', 'b'] }).conforms).toBe(true);
  });
  it('resource scopes: exact, star, prefix, regex, empty', () => {
    const p = pol([pred('a', '/x/*')]);
    expect(intentConformance(p, { verbs: ['a'], resourceScopes: ['/x/*'] }).conforms).toBe(true);
    expect(intentConformance(p, { verbs: ['a'], resourceScopes: ['*'] }).conforms).toBe(true);
    expect(intentConformance(p, { verbs: ['a'], resourceScopes: [] }).conforms).toBe(true);
    expect(intentConformance(p, { verbs: ['a'] }).conforms).toBe(true);
    const off = intentConformance(p, { verbs: ['a'], resourceScopes: ['/y/*'] });
    expect(off.conforms).toBe(false);
    expect(off.violations[0]?.kinds).toEqual(['off-scope']);
    // exact scope vs prefix grant
    const ex = intentConformance(p, { verbs: ['a'], resourceScopes: ['/x/'] });
    expect(ex.conforms).toBe(false);
    expect(ex.violations.some((v) => v.action.resource === '/x/x')).toBe(true);
    // the prefix boundary
    expect(intentConformance(pol([pred('a', '/xy*')]), { verbs: ['a'], resourceScopes: ['/xy*'] }).conforms).toBe(true);
    expect(intentConformance(pol([pred('a', '/x*')]), { verbs: ['a'], resourceScopes: ['/xy*'] }).conforms).toBe(false);
  });
  it('regex scopes', () => {
    const p = pol([pred('a', '/x/1')]);
    const ok = intentConformance(p, { verbs: ['a'], resourceScopes: ['re:/x/[0-9]'] });
    expect(ok).toEqual({
      conforms: false,
      approximate: true,
      violations: [],
      reason: 'over-approximated (re: intent resource scope not enumerated soundly); cannot prove conformance',
    });
    const bad = intentConformance(p, { verbs: ['a'], resourceScopes: ['re:/y/[0-9]'] });
    expect(bad.conforms).toBe(false);
    expect(bad.violations[0]?.kinds).toEqual(['off-scope']);
    // regex is a FULL match
    expect(intentConformance(p, { verbs: ['a'], resourceScopes: ['re:/x/'] }).violations[0]?.kinds).toEqual(['off-scope']);
    // regex limits: pattern length > 200 matches nothing
    expect(intentConformance(p, { verbs: ['a'], resourceScopes: ['re:' + 'a'.repeat(201)] }).violations).toHaveLength(1);
    // pattern length exactly 200 is accepted (a safe pattern)
    const long = '/x/1' + '|' + 'b'.repeat(195);
    expect(long.length).toBe(200);
    expect(intentConformance(p, { verbs: ['a'], resourceScopes: ['re:' + long] }).violations).toHaveLength(0);
    // unsafe regex matches nothing
    expect(intentConformance(p, { verbs: ['a'], resourceScopes: ['re:(a+)+b'] }).violations).toHaveLength(1);
  });
  it('regex scope mixed with a matching literal scope', () => {
    const p = pol([pred('a', '/x/1')]);
    const r = intentConformance(p, { verbs: ['a'], resourceScopes: ['/x/1', 're:zz'] });
    expect(r.approximate).toBe(true);
    expect(r.violations).toEqual([]);
  });
  it('undecidable policy: reasons listed, violations still win', () => {
    const p = pol([pred('a', '*', [LIKE])]);
    expect(intentConformance(p, { verbs: ['a'] })).toEqual({
      conforms: false,
      approximate: true,
      violations: [],
      reason: `over-approximated (${LIKE_MSG}); cannot prove conformance`,
    });
    const both = intentConformance(pol([pred('a', '*', [LIKE])]), { verbs: ['a'], resourceScopes: ['*', 're:q'] });
    expect(both.reason).toBe(`over-approximated (${LIKE_MSG}; re: intent resource scope not enumerated soundly); cannot prove conformance`);
    expect(intentConformance(p, { verbs: [] }).violations.length).toBeGreaterThan(0);
  });
  it('overflow boundary and violation cap', () => {
    const p = pol([pred('a', '*')]);
    expect(intentConformance(p, { verbs: ['a'] }, { maxCombinations: 0 })).toEqual({
      conforms: false,
      approximate: true,
      violations: [],
      reason: 'grid exceeded the bound; cannot prove conformance',
    });
    const sz = (policy: ReturnType<typeof pol>, extra: object = {}) =>
      productSize(collectProbes({ predicateSets: [policy.predicates], varyReversibility: (policy.caveats as unknown[]).length > 0, ...extra }));
    const s1 = sz(p);
    expect(intentConformance(p, { verbs: ['a'] }, { maxCombinations: s1 }).approximate).toBeUndefined();
    expect(intentConformance(p, { verbs: ['a'] }, { maxCombinations: s1 - 1 }).approximate).toBe(true);
    const cap = pol([pred('a', '*')], [{ type: 'reversibility_max', class: 'irreversible' }]);
    const s2 = sz(cap);
    expect(s2).toBe(s1 * 3);
    expect(intentConformance(cap, { verbs: ['a'] }, { maxCombinations: s2 }).approximate).toBeUndefined();
    expect(intentConformance(cap, { verbs: ['a'] }, { maxCombinations: s2 - 1 }).approximate).toBe(true);
    // extra amount field multiplies the grid: cells [-1,0? ...]; compare with the explicit probe set
    const withAmt = productSize(
      collectProbes({
        predicateSets: [p.predicates],
        extraVerbs: ['a'],
        extraFieldConditions: [
          { path: 'action.params.amount', cond: { field: 'action.params.amount', op: 'lte', value: 100 } },
          { path: 'action.params.amount', cond: { field: 'action.params.amount', op: 'gte', value: 0 } },
        ],
        varyReversibility: false,
      }),
    );
    expect(intentConformance(p, { verbs: ['a'], maxAmount: 100 }, { maxCombinations: withAmt }).approximate).toBeUndefined();
    expect(intentConformance(p, { verbs: ['a'], maxAmount: 100 }, { maxCombinations: withAmt - 1 }).approximate).toBe(true);
    const many = pol([pred('*', '*')]);
    const scopes = Array.from({ length: 40 }, (_, i) => `s${i}`);
    const r = intentConformance(many, { verbs: ['x'], resourceScopes: scopes });
    expect(r.violations).toHaveLength(16);
    expect(r.conforms).toBe(false);
  });
  it('maxAmount probes: lte/gte stamped, extra field values drive amount cells', () => {
    const p = pol([pred('a', '*')]);
    const r = intentConformance(p, { verbs: ['a'], maxAmount: 100, minAmount: 10 });
    const kinds = r.violations.flatMap((v) => v.kinds);
    // probes: 9 (under), 10, 55, 100, 101 (over), FRESH (non-number: ignored), absent
    const amts = r.violations.map((v) => v.action.params?.['amount']);
    expect(amts).toContain(101);
    expect(amts).toContain(9);
    expect(kinds).toContain('over-amount');
    expect(kinds).toContain('under-amount');
    expect(amts).not.toContain(10);
    expect(amts).not.toContain(100);
    expect(amts).not.toContain(55);
  });
  it('NaN-ish / infinite amounts are ignored', () => {
    const p = pol([pred('a', '*', [cond('action.params.amount', 'eq', Infinity)])]);
    expect(intentConformance(p, { verbs: ['a'], maxAmount: 1 }).conforms).toBe(true);
  });
  it('under- vs over-amount are exclusive branches', () => {
    const p = pol([pred('a', '*')]);
    const r = intentConformance(p, { verbs: ['a'], maxAmount: 1, minAmount: 5 });
    for (const v of r.violations) {
      expect(v.kinds.includes('over-amount') && v.kinds.includes('under-amount')).toBe(false);
    }
  });
});

describe('admitsConcrete / predicateNumericSatisfiable', () => {
  it('admitsConcrete', () => {
    const p = pol([pred('a', '*', [num('gt', 1)])]);
    expect(admitsConcrete(p, { verb: 'a', resource: 'r', params: { n: 2 } })).toBe(true);
    expect(admitsConcrete(p, { verb: 'a', resource: 'r', params: { n: 1 } })).toBe(false);
  });
  it('predicateNumericSatisfiable', () => {
    expect(predicateNumericSatisfiable(undefined)).toBe(true);
    expect(predicateNumericSatisfiable('x' as never)).toBe(true);
    expect(predicateNumericSatisfiable([num('gte', 5), num('lte', 4)])).toBe(false);
    expect(predicateNumericSatisfiable([num('gte', 5), num('lte', 5)])).toBe(true);
  });
});
