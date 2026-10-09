import { describe, expect, it } from 'vitest';
import { compilePolicy, type Caveat, type Predicate } from '@atlasauth/pca';
import {
  alwaysAllows,
  alwaysDenies,
  disjoint,
  equivalent,
  intentConformance,
  numericConjunctionSatisfiable,
  predicateNumericSatisfiable,
  reachable,
  subsumes,
  analyzeCaveats,
  toModel,
} from './index';

// Helper: a bare predicate/caveat policy.
const raw = (predicates: Predicate[], caveats: Caveat[] = []) => ({ predicates, caveats });

const broad = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$500' } });
const narrow = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100' } });
const gmail = compilePolicy({ permissions: { gmail: ['send'] } });

describe('subsumes (delegation safety)', () => {
  it('a broader policy subsumes a narrower one', () => {
    const r = subsumes(broad, narrow);
    expect(r.subsumes).toBe(true);
    expect(r.approximate).toBeFalsy();
  });

  it('a narrower policy does NOT subsume a broader one, with a counterexample', () => {
    const r = subsumes(narrow, broad);
    expect(r.subsumes).toBe(false);
    expect(r.counterexample).toBeDefined();
    const amount = r.counterexample?.params?.['amount'];
    // The witnessing action is admitted by broad ($100 < amount <= $500) but denied by narrow.
    expect(typeof amount).toBe('number');
    expect(amount as number).toBeGreaterThan(100);
    expect(amount as number).toBeLessThanOrEqual(500);
    expect(r.counterexample?.verb).toBe('stripe.refund');
  });

  it('is reflexive', () => {
    expect(subsumes(broad, broad).subsumes).toBe(true);
  });
});

describe('alwaysDenies (vacuity)', () => {
  it('an unsatisfiable numeric conjunction makes the policy vacuous', () => {
    const dead = raw([
      {
        verb: 'widget.set',
        resource: '*',
        where: [
          { field: 'action.params.amount', op: 'gte', value: 100 },
          { field: 'action.params.amount', op: 'lte', value: 10 },
        ],
      },
    ]);
    const r = alwaysDenies(dead);
    expect(r.alwaysDenies).toBe(true);
    expect(r.approximate).toBeFalsy();
  });

  it('unsatisfiable caveats make the policy vacuous', () => {
    const r = alwaysDenies(raw([{ verb: '*', resource: '*' }], [{ type: 'rate', max: 0, per_secs: 60 }]));
    expect(r.alwaysDenies).toBe(true);
  });

  it('a live policy is not vacuous and yields an admitted witness', () => {
    const r = alwaysDenies(broad);
    expect(r.alwaysDenies).toBe(false);
    expect(r.witness).toBeDefined();
    expect(r.witness?.verb).toBe('stripe.refund');
  });
});

describe('alwaysAllows (totality for a verb)', () => {
  it('a predicate with no where and a universal resource is total for its verb', () => {
    const r = alwaysAllows(gmail, 'gmail.send');
    expect(r.alwaysAllows).toBe(true);
  });

  it('a capped money verb is NOT total, with an over-cap counterexample', () => {
    const r = alwaysAllows(broad, 'stripe.refund');
    expect(r.alwaysAllows).toBe(false);
    expect(r.counterexample).toBeDefined();
  });
});

describe('reachable', () => {
  it('true on a concrete in-cap action', () => {
    const r = reachable(broad, { verb: 'stripe.refund', resource: 'charge:ch_1', params: { amount: 300 } });
    expect(r.reachable).toBe(true);
    expect(r.witness).toBeDefined();
  });

  it('false on an over-cap action (proven)', () => {
    const r = reachable(broad, { verb: 'stripe.refund', resource: 'charge:ch_1', params: { amount: 1000 } });
    expect(r.reachable).toBe(false);
    expect(r.approximate).toBeFalsy();
  });

  it('false on an ungranted verb (proven)', () => {
    const r = reachable(broad, { verb: 'stripe.payout', resource: 'acct:1', params: { amount: 1 } });
    expect(r.reachable).toBe(false);
  });

  it('fills a free param to find a witness', () => {
    const r = reachable(broad, { verb: 'stripe.refund', resource: 'charge:ch_1' });
    expect(r.reachable).toBe(true);
    expect(typeof r.witness?.params?.['amount']).toBe('number');
  });
});

describe('equivalent', () => {
  it('detects equivalent policies', () => {
    const a = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$250' } });
    const b = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$250' } });
    const r = equivalent(a, b);
    expect(r.equivalent).toBe(true);
    expect(r.approximate).toBeFalsy();
  });

  it('distinguishes different policies with a counterexample', () => {
    const r = equivalent(broad, narrow);
    expect(r.equivalent).toBe(false);
    expect(r.counterexample).toBeDefined();
  });
});

describe('disjoint', () => {
  it('policies over different verbs are disjoint', () => {
    expect(disjoint(broad, gmail).disjoint).toBe(true);
  });

  it('overlapping policies are not disjoint, with a shared witness', () => {
    const r = disjoint(broad, narrow);
    expect(r.disjoint).toBe(false);
    expect(r.witness).toBeDefined();
  });
});

describe('intentConformance', () => {
  // A policy whose own ceiling is $20k, delegated under an intent that caps spend at $10k. The policy
  // admits (and the budget may well cover) a $14k action, but that is outside the declared intent:
  // the "$14k renewal under a $10k cap still violates intent" class.
  const policy20k = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$20000' } });

  it('flags an over-cap action that still passes the policy predicates', () => {
    const r = intentConformance(policy20k, { verbs: ['stripe.refund'], maxAmount: 10000 });
    expect(r.conforms).toBe(false);
    const over = r.violations.find((v) => v.kinds.includes('over-amount'));
    expect(over).toBeDefined();
    expect((over?.action.params?.['amount'] as number) > 10000).toBe(true);
  });

  it('flags an off-scope resource the policy admits', () => {
    const r = intentConformance(policy20k, {
      verbs: ['stripe.refund'],
      resourceScopes: ['charge:*'],
      maxAmount: 1_000_000,
    });
    expect(r.conforms).toBe(false);
    expect(r.violations.some((v) => v.kinds.includes('off-scope'))).toBe(true);
  });

  it('conforms when the intent envelope contains the policy', () => {
    const r = intentConformance(policy20k, { verbs: ['stripe.refund'], maxAmount: 20000 });
    expect(r.conforms).toBe(true);
    expect(r.violations).toHaveLength(0);
  });

  it('flags an off-verb action', () => {
    const multi = compilePolicy({ permissions: { stripe: ['refund'], gmail: ['send'] } });
    const r = intentConformance(multi, { verbs: ['stripe.refund'] });
    expect(r.conforms).toBe(false);
    expect(r.violations.some((v) => v.kinds.includes('off-verb') && v.action.verb === 'gmail.send')).toBe(true);
  });
});

describe('soundness: fail-safe on undecidable features', () => {
  it('a re: regex resource makes subsumes fail safe (approximate)', () => {
    const re = raw([{ verb: 'files.read', resource: 're:/acct/[0-9]+' }]);
    const exact = raw([{ verb: 'files.read', resource: '/acct/1' }]);
    const r = subsumes(re, exact);
    // Cannot prove subsumption with a regex in play -> fail safe to not-subsumed, flagged approximate.
    expect(r.subsumes).toBe(false);
    expect(r.approximate).toBe(true);
  });

  it('a cross-field ref condition makes alwaysDenies fail safe', () => {
    const refPolicy = raw([
      {
        verb: 'session.use',
        resource: '*',
        where: [{ field: 'action.params.device', op: 'ne', ref: 'env.current_device' }],
      },
    ]);
    const r = alwaysDenies(refPolicy);
    expect(r.approximate).toBe(true);
    expect(r.alwaysDenies).toBe(false);
  });
});

describe('interval engine', () => {
  it('detects an unsatisfiable numeric conjunction', () => {
    expect(
      numericConjunctionSatisfiable([
        { field: 'action.params.n', op: 'gte', value: 100 },
        { field: 'action.params.n', op: 'lte', value: 10 },
      ]),
    ).toBe(false);
  });

  it('accepts a satisfiable numeric conjunction', () => {
    expect(
      predicateNumericSatisfiable([
        { field: 'action.params.n', op: 'gte', value: 10 },
        { field: 'action.params.n', op: 'lt', value: 100 },
      ]),
    ).toBe(true);
  });

  it('a half-open point interval (lt == gte) is unsatisfiable', () => {
    expect(
      numericConjunctionSatisfiable([
        { field: 'action.params.n', op: 'gte', value: 5 },
        { field: 'action.params.n', op: 'lt', value: 5 },
      ]),
    ).toBe(false);
  });
});

describe('caveat satisfiability', () => {
  it('an empty validity window is unsatisfiable', () => {
    const a = analyzeCaveats([
      { type: 'not_before', at: 2000 },
      { type: 'expires', at: 1000 },
    ]);
    expect(a.sat).toBe(false);
  });

  it('a valid window is satisfiable and records the reversibility cap', () => {
    const a = analyzeCaveats([
      { type: 'not_before', at: 1000 },
      { type: 'expires', at: 2000 },
      { type: 'reversibility_max', class: 'rate_limited' },
    ]);
    expect(a.sat).toBe(true);
    expect(a.revCap).toBe(1);
  });

  it('an unknown caveat type fails closed', () => {
    expect(analyzeCaveats([{ type: 'wat' }]).sat).toBe(false);
  });
});

describe('DSL extensions — soundness over the new condition forms', () => {
  it('decides nested boolean logic (any_of / not over decidable ops) EXACTLY (not approximate)', () => {
    // allow pay when amount <= 1000 AND (region eu OR us) AND NOT currency xxx
    const p: Predicate[] = [
      {
        verb: 'pay',
        where: [
          { field: 'action.params.amount', op: 'lte', value: 1000 },
          { any_of: [{ field: 'env.region', op: 'eq', value: 'eu' }, { field: 'env.region', op: 'eq', value: 'us' }] },
          { not: { field: 'action.params.currency', op: 'eq', value: 'xxx' } },
        ],
      },
    ];
    // reachable with a within-bounds action => proven true with a verified witness
    const r = reachable(raw(p), { verb: 'pay', resource: '/acct', params: { amount: 500, currency: 'usd' }, env: { region: 'eu' } });
    expect(r.reachable).toBe(true);
    expect(r.approximate).toBeFalsy();

    // alwaysAllows('pay') is PROVABLY false (region 'ap' / amount over 1000 deny) — and exactly decided
    const aa = alwaysAllows(raw(p), 'pay');
    expect(aa.alwaysAllows).toBe(false);
    expect(aa.approximate).toBeFalsy();
    expect(aa.counterexample).toBeDefined();

    // not vacuous, exactly decided
    const ad = alwaysDenies(raw(p));
    expect(ad.alwaysDenies).toBe(false);
    expect(ad.approximate).toBeFalsy();
  });

  it('flags hard ops (matches / member_of / like / is_a) as undecidable and fails safe on relations', () => {
    for (const where of [
      [{ field: 'action.params.code', op: 'matches', value: '[A-Z]+' }] as const,
      [{ field: 'subject.id', op: 'member_of', value: 'Group::g', collection: 'env.parents' }] as const,
      [{ field: 'action.params.name', op: 'like', value: '*.pdf' }] as const,
      [{ field: 'subject.id', op: 'is_a', value: 'User' }] as const,
    ]) {
      const p: Predicate[] = [{ verb: 'x', where: [...where] }];
      // the model is flagged undecidable (the soundness hook that makes verdicts fail safe)
      expect(toModel(raw(p)).undecidable.length).toBeGreaterThan(0);
      // a policy cannot even be PROVEN to subsume itself when it carries an undecidable feature:
      // the relation fails safe (never silently claims the safe "subsumes" answer).
      const s = subsumes(raw(p), raw(p));
      expect(s.subsumes).toBe(false);
      expect(s.approximate).toBe(true);
    }
  });

  it('a group condition made only of decidable ops is NOT flagged undecidable', () => {
    const p: Predicate[] = [
      { verb: 'x', where: [{ any_of: [{ field: 'env.a', op: 'eq', value: 1 }, { not: { field: 'env.b', op: 'gt', value: 5 } }] }] },
    ];
    expect(toModel(raw(p)).undecidable).toEqual([]);
  });
});
