import { describe, expect, it } from 'vitest';
import type { Caveat, ConditionOp, LeafCondition, Predicate, prohibitions } from '@atlasauth/pca';
import {
  decideAction,
  delegationEnvelope,
  diffGate,
  diffPolicies,
  escalationSurface,
  findWithBackend,
  maxExposure,
  thresholdsOf,
  toModel,
  type AnalyzerAction,
  type ExposureOptions,
  type PolicyDiff,
  type PolicyInput,
  type Veto,
  type WitnessBackend,
} from './index';
import { refund } from './k2-fixtures';

const V = 'stripe.refund';
const AMOUNT = 'action.params.amount';
const lit = (field: string, op: ConditionOp, value?: unknown): LeafCondition => ({ field, op, value });
const base: PolicyInput = { predicates: [refund(500)], caveats: [] };
const pol = (caveats: Caveat[] = []): PolicyInput => ({ predicates: [refund(500)], caveats });
const approval = (threshold: number): Veto => ({ id: `ap${threshold}`, kind: 'approval', when: { verb: V }, over: { path: AMOUNT, threshold } });
const constitution = (invariants: unknown[]): prohibitions.Constitution => ({ version: 1, principal: 'p', invariants: invariants as prohibitions.Invariant[] });
const rate = (max: number, per: number): Caveat => ({ type: 'rate', max, per_secs: per });
const revMax = (cls: string): Caveat => ({ type: 'reversibility_max', class: cls });
const win = (policy: PolicyInput, o: Partial<ExposureOptions> = {}) => maxExposure(policy, { verb: V, integer: true, ...o }).window;
const anyResource = expect.any(String);

describe('thresholdsOf', () => {
  it('collects finite numeric literals for the asked path only, through groups, arrays and vetoes', () => {
    const where = [
      { all_of: [lit(AMOUNT, 'lte', 5), { any_of: [lit(AMOUNT, 'gt', 3), { not: lit(AMOUNT, 'lt', 9) }] }] },
      lit(AMOUNT, 'in', [1, 'a', Infinity, NaN, 7]),
      lit(AMOUNT, 'eq', 'str'),
      lit(AMOUNT, 'eq', null),
      lit(AMOUNT, 'exists'),
      lit('action.params.other', 'lte', 100),
      { all_of: 5, any_of: [lit(AMOUNT, 'lte', 21)] },
      { any_of: 'x', not: lit(AMOUNT, 'gte', 23) },
      null,
      'junk',
      7,
    ];
    const vetoes: Veto[] = [
      { id: 'o1', kind: 'approval', when: { verb: 'v' }, over: { path: AMOUNT, threshold: 11 } },
      { id: 'o2', kind: 'approval', when: { verb: 'v' }, over: { path: 'action.params.other', threshold: 99 } },
      { id: 'd1', kind: 'deny', when: { verb: 'v' } },
    ];
    const m = toModel({ predicates: [{ verb: 'v', where: where as unknown as Predicate['where'] }], vetoes });
    expect(thresholdsOf(m, AMOUNT)).toEqual([1, 3, 5, 7, 9, 11, 21, 23]);
    expect(thresholdsOf(m, 'action.params.other')).toEqual([99, 100]);
  });
});

describe('thresholdsOf (veto amounts)', () => {
  it('a veto amount is a threshold of its own path, even when no condition restates it', () => {
    const veto = (path: string, threshold: number): Veto => ({ id: path, kind: 'approval', when: { verb: 'v' }, over: { path, threshold } });
    const m = toModel({ predicates: [{ verb: 'v' }], vetoes: [veto(AMOUNT, Infinity), veto('action.params.other', 4)] });
    expect(thresholdsOf(m, AMOUNT)).toEqual([Infinity]);
    expect(thresholdsOf(m, 'action.params.other')).toEqual([4]);
  });
});

describe('boundOf through the public options', () => {
  const wide: PolicyInput = { predicates: [{ verb: 'v', where: Array.from({ length: 12 }, (_, i) => lit(`env.f${i}`, 'eq', 'x')) }], vetoes: [{ id: 'a', kind: 'approval', when: { verb: 'v' } }] };
  const small: PolicyInput = { predicates: [{ verb: 'v' }], vetoes: [{ id: 'a', kind: 'approval', when: { verb: 'v' } }] };
  it('the default bound applies when none (or an unusable one) is given', () => {
    expect(escalationSurface(wide, { verb: 'v' })).toMatchObject({ approximate: true, reason: 'representative grid exceeded the bound' });
    expect(escalationSurface(wide, { verb: 'v', maxCombinations: Infinity })).toMatchObject({ approximate: true });
    expect(escalationSurface(wide, { verb: 'v', maxCombinations: NaN })).toMatchObject({ approximate: true });
    expect(escalationSurface(small, { verb: 'v', maxCombinations: -1 }).approximate).toBeUndefined();
    expect(escalationSurface(small, { verb: 'v', maxCombinations: NaN }).approximate).toBeUndefined();
  });
  it('zero is a real bound; a bound equal to the grid size passes', () => {
    expect(escalationSurface(small, { verb: 'v', maxCombinations: 0 })).toMatchObject({ approximate: true, escalates: false });
    expect(escalationSurface(small, { verb: 'v', maxCombinations: 1 })).toMatchObject({ escalates: true });
    expect(escalationSurface(small, { verb: 'v', maxCombinations: 1 }).approximate).toBeUndefined();
  });
});

describe('per-action peak', () => {
  it('an open policy: unbounded, exact witness, exact window', () => {
    const open: PolicyInput = { predicates: [{ verb: 'v' }], caveats: [] };
    const e = maxExposure(open, { verb: 'v' });
    const peak = { admitted: true, max: Infinity, attained: false, witness: { verb: 'v', resource: anyResource, params: { amount: Number.MAX_SAFE_INTEGER } } };
    expect(e.perAction).toEqual(peak);
    expect(e.autonomousPerAction).toEqual(peak);
    expect(e.perAction.witness).not.toHaveProperty('reversibilityClass');
    expect(e.window).toEqual({ maxActions: Infinity, bound: Infinity, basis: [], notApplied: [] });
    expect(e.autonomousWindow).toEqual({ maxActions: Infinity, bound: Infinity, basis: [], notApplied: [] });
    expect(e.unmodeled).toEqual([]);
    expect(e).toMatchObject({ verb: 'v', amountField: 'amount' });
    expect(e).not.toHaveProperty('approximate');
    expect(e).not.toHaveProperty('reason');
    expect(maxExposure(open, { verb: 'v', windowSecs: 60 }).window).toEqual({ secs: 60, maxActions: Infinity, bound: Infinity, basis: [], notApplied: [] });
  });

  it('a schema maximum on a custom field is attained with a witness on that field', () => {
    const open: PolicyInput = { predicates: [{ verb: 'v' }], caveats: [] };
    const e = maxExposure(open, { verb: 'v', amountField: 'value', max: 1000 });
    expect(e.amountField).toBe('value');
    expect(e.perAction).toEqual({ admitted: true, max: 1000, attained: true, witness: { verb: 'v', resource: anyResource, params: { value: 1000 } } });
  });

  it('a threshold above every literal is unbounded, also at the largest safe integer', () => {
    const gt500: PolicyInput = { predicates: [{ verb: 'v', where: [lit(AMOUNT, 'gt', 500)] }] };
    expect(maxExposure(gt500, { verb: 'v' }).perAction).toMatchObject({ admitted: true, max: Infinity, attained: false });
    const gtHuge: PolicyInput = { predicates: [{ verb: 'v', where: [lit(AMOUNT, 'gt', Number.MAX_SAFE_INTEGER)] }] };
    expect(maxExposure(gtHuge, { verb: 'v' }).perAction).toMatchObject({ admitted: true, max: Infinity, attained: false });
  });

  it('a schema maximum just above the top threshold is reachable and attained', () => {
    const gt500: PolicyInput = { predicates: [{ verb: 'v', where: [lit(AMOUNT, 'gt', 500)] }] };
    expect(maxExposure(gt500, { verb: 'v', max: 500.5 }).perAction).toEqual({
      admitted: true,
      max: 500.5,
      attained: true,
      witness: { verb: 'v', resource: anyResource, params: { amount: 500.5 } },
    });
  });

  it('an integer supremum inside an open interval uses the witness at the integer, on the right field', () => {
    const between = (field: string): PolicyInput => ({
      predicates: [{ verb: 'v', where: [lit(field, 'gt', 0.25), lit(field, 'lt', 2.75), lit('action.params.reason', 'eq', 'dup')] }],
    });
    expect(maxExposure(between(AMOUNT), { verb: 'v', integer: true }).perAction).toEqual({
      admitted: true,
      max: 2,
      attained: true,
      witness: { verb: 'v', resource: anyResource, params: { amount: 2, reason: 'dup' } },
    });
    expect(maxExposure(between(AMOUNT), { verb: 'v' }).perAction).toEqual({
      admitted: true,
      max: 2.75,
      attained: false,
      witness: { verb: 'v', resource: anyResource, params: { amount: 1.75, reason: 'dup' } },
    });
    expect(maxExposure(between('action.params.value'), { verb: 'v', integer: true, amountField: 'value' }).perAction.witness?.params).toEqual({ value: 2, reason: 'dup' });
  });

  it('an interval holding no integer below the supremum stays a non-attained supremum', () => {
    const r: PolicyInput = {
      predicates: [
        { verb: 'v', where: [lit(AMOUNT, 'gt', 100), lit(AMOUNT, 'lt', 101)] },
        { verb: 'v', where: [lit(AMOUNT, 'lte', 100)] },
      ],
    };
    for (const integer of [true, false]) {
      expect(maxExposure(r, { verb: 'v', integer }).perAction).toEqual({
        admitted: true,
        max: 101,
        attained: false,
        witness: { verb: 'v', resource: anyResource, params: { amount: 100.5 } },
      });
    }
  });

  it('an exclusive bound: the supremum for a real, the integer below it otherwise, in both levels', () => {
    const lt = (n: number) => lit(AMOUNT, 'lt', n);
    const lt100: PolicyInput = { predicates: [{ verb: 'v', where: [lt(100)] }] };
    const real = maxExposure(lt100, { verb: 'v' });
    for (const p of [real.perAction, real.autonomousPerAction]) {
      expect(p).toMatchObject({ admitted: true, max: 100, attained: false });
      expect(p.witness?.params?.amount).toBe(99);
    }
    const int = maxExposure(lt100, { verb: 'v', integer: true });
    for (const p of [int.perAction, int.autonomousPerAction]) {
      expect(p).toMatchObject({ admitted: true, max: 99, attained: true });
      expect(p.witness?.params?.amount).toBe(99);
    }
    // the supremum is the NEAREST threshold above the cell
    const two: PolicyInput = { predicates: [{ verb: 'v', where: [lt(200)] }, { verb: 'v', where: [lt(100)] }] };
    expect(maxExposure(two, { verb: 'v' }).perAction).toMatchObject({ max: 200, attained: false });
    expect(maxExposure(two, { verb: 'v' }).perAction.witness?.params?.amount).toBe(199);
  });

  it('schema bounds exclude candidates outside [min, max] (inclusive at both ends)', () => {
    const nothing = { admitted: false, max: 0, attained: false };
    expect(maxExposure({ predicates: [{ verb: 'v', where: [lit(AMOUNT, 'lte', 50)] }] }, { verb: 'v', min: 100 }).perAction).toEqual(nothing);
    expect(maxExposure({ predicates: [{ verb: 'v', where: [lit(AMOUNT, 'gt', 100)] }] }, { verb: 'v', max: 50 }).perAction).toEqual(nothing);
    const eq100: PolicyInput = { predicates: [{ verb: 'v', where: [lit(AMOUNT, 'eq', 100)] }] };
    expect(maxExposure(eq100, { verb: 'v', min: 100 }).perAction).toMatchObject({ admitted: true, max: 100, attained: true });
    expect(maxExposure(eq100, { verb: 'v', max: 100 }).perAction).toMatchObject({ admitted: true, max: 100, attained: true });
    expect(maxExposure({ predicates: [{ verb: 'v' }] }, { verb: 'v', min: Infinity }).perAction).toEqual(nothing);
    expect(maxExposure({ predicates: [{ verb: 'v' }] }, { verb: 'v', min: 5, max: 4 }).perAction).toEqual(nothing);
  });

  it('separates the level with a human from the autonomous level, with the schema maximum', () => {
    const p: PolicyInput = { predicates: [{ verb: V }], vetoes: [approval(200)] };
    const e = maxExposure(p, { verb: V, integer: true, max: 1000 });
    expect(e.perAction).toMatchObject({ admitted: true, max: 1000, attained: true });
    expect(e.autonomousPerAction).toMatchObject({ admitted: true, max: 200, attained: true });
  });

  it('own vetoes and the constitution both bind', () => {
    const p: PolicyInput = { predicates: [refund(500)], vetoes: [{ id: 'cap300', kind: 'deny', when: { verb: V, where: [lit(AMOUNT, 'gt', 300)] } }] };
    const c = constitution([{ kind: 'require_approval_over', id: 'ra', when: { verb: V }, amount: AMOUNT, threshold: 100, approved: [] }]);
    const e = maxExposure(p, { verb: V, integer: true, constitution: c });
    expect(e.perAction).toMatchObject({ max: 300, attained: true });
    expect(e.autonomousPerAction).toMatchObject({ max: 100, attained: true });
  });

  it('a reversibility cap makes the enumeration vary the class', () => {
    const e = maxExposure({ predicates: [refund(500)], caveats: [revMax('rate_limited')] }, { verb: V, integer: true });
    expect(e.perAction).toMatchObject({ admitted: true, max: 500, attained: true });
    expect(e.perAction.witness?.reversibilityClass).toBe('reversible');
    expect(maxExposure(base, { verb: V, integer: true }).perAction.witness).not.toHaveProperty('reversibilityClass');
  });

  it('pinning keeps the other fields, replaces the amount field, and honours the resource', () => {
    const gold: PolicyInput = { predicates: [{ ...refund(500), where: [lit(AMOUNT, 'lte', 500), lit('env.tier', 'eq', 'gold')] }] };
    const e = maxExposure(gold, { verb: V, integer: true, maxCombinations: 9 });
    expect(e.perAction).toMatchObject({ admitted: true, max: 500, attained: true });
    expect(e.perAction.witness?.env).toEqual({ tier: 'gold' });
    expect(e.approximate).toBeUndefined();
    // the amount's own grid is replaced by the single pinned value: 3 resources only
    const exact = maxExposure(base, { verb: V, integer: true, maxCombinations: 3 });
    expect(exact.perAction).toMatchObject({ admitted: true, max: 500, attained: true });
    expect(exact.approximate).toBeUndefined();
    // one resource: a grid of one
    const one = maxExposure(base, { verb: V, integer: true, resource: '/acct/7', maxCombinations: 1 });
    expect(one.perAction).toMatchObject({ admitted: true, max: 500, attained: true });
    expect(one.perAction.witness?.resource).toBe('/acct/7');
    expect(maxExposure(base, { verb: V, integer: true, resource: '/other/1' }).perAction).toEqual({ admitted: false, max: 0, attained: false });
  });
});

describe('overflow and approximation', () => {
  it('an overflowing grid reports unbounded exposure, with the exact flags', () => {
    const p = pol([rate(3, 86400)]);
    const e = maxExposure(p, { verb: V, integer: true, windowSecs: 86400, maxCombinations: 2 });
    const unbounded = { admitted: true, max: Infinity, attained: false };
    expect(e.perAction).toEqual(unbounded);
    expect(e.autonomousPerAction).toEqual(unbounded);
    expect(e.window).toEqual({ secs: 86400, maxActions: 3, bound: Infinity, basis: ['rate caveat 3/86400s'], notApplied: [] });
    expect(e.autonomousWindow).toEqual({ secs: 86400, maxActions: 3, bound: Infinity, basis: ['rate caveat 3/86400s'], notApplied: [] });
    expect(e.approximate).toBe(true);
    expect(e.reason).toBe('representative grid exceeded the bound; exposure reported as unbounded');
  });

  it('an undecidable construct is reported with every reason, joined', () => {
    const p: PolicyInput = { predicates: [{ verb: 'v', where: [lit('action.params.name', 'like', 'a*'), lit('action.params.code', 'matches', '[A-Z]+')] }] };
    const reasons = toModel(p).undecidable;
    expect(reasons).toHaveLength(2);
    const e = maxExposure(p, { verb: 'v' });
    expect(e.approximate).toBe(true);
    expect(e.reason).toBe(`over-approximated (${reasons[0]}; ${reasons[1]})`);
  });

  it('a decided policy carries neither flag', () => {
    const e = maxExposure(base, { verb: V, integer: true });
    expect(e.approximate).toBeUndefined();
    expect(e.reason).toBeUndefined();
  });

  it('lists the stateful invariants that cannot be modeled, and not the windowed ones', () => {
    const when = { verb: V };
    const c = constitution([
      { kind: 'cap', id: 'cp', when, amount: AMOUNT, max: 1 },
      { kind: 'rate', id: 'rt', when, max: 1, window_secs: 60 },
      { kind: 'never_after', id: 'na', after: when, forbid: when },
      { kind: 'require_prior', id: 'rp', when, prior: when },
    ]);
    expect(maxExposure(base, { verb: V, integer: true, constitution: c }).unmodeled).toEqual(['na: needs action history', 'rp: needs action history']);
  });
});

describe('budget model sources', () => {
  const alloc = (limit: unknown): Caveat => ({ type: 'budget_alloc', limit });
  const compiled = { predicates: [refund(500)], caveats: [alloc(1200)], budgetModel: 'risk', riskPolicy: { kappa: 100 } } as unknown as PolicyInput;
  it('reads the model and kappa from the policy, and an explicit option wins', () => {
    expect(win(compiled, { blastRadius: 0.5 })).toMatchObject({ maxActions: 24, bound: 12000, notApplied: [] });
    expect(win(compiled, { blastRadius: 0.5, kappa: 50 })).toMatchObject({ maxActions: 48, bound: 24000 });
    expect(win(compiled, { blastRadius: 0.5, budgetModel: 'dollars' })).toMatchObject({ maxActions: Infinity, bound: 1200 });
    const dollars = { predicates: [refund(500)], caveats: [alloc(1200)], budgetModel: 'dollars' } as unknown as PolicyInput;
    expect(win(dollars)).toMatchObject({ bound: 1200, basis: ['per-action ceiling', 'budget_alloc limit 1200'] });
    const noKappa = { predicates: [refund(500)], caveats: [alloc(1200)], budgetModel: 'risk', riskPolicy: { kappa: '100' } } as unknown as PolicyInput;
    expect(win(noKappa, { blastRadius: 0.5 }).notApplied).toEqual(['budget_alloc 1200 (trust-budget units; pass budgetModel and kappa)']);
  });

  it('a budget that cannot be related to the amount is listed, never applied', () => {
    const note = ['budget_alloc 1200 (trust-budget units; pass budgetModel and kappa)'];
    const p = pol([alloc(1200)]);
    expect(win(p, { kappa: 100, blastRadius: 0.5 }).notApplied).toEqual(note);
    expect(win(p, { budgetModel: 'risk', kappa: 0, blastRadius: 0.5 }).notApplied).toEqual(note);
    expect(win(p, { budgetModel: 'risk', kappa: '100' as unknown as number, blastRadius: 0.5 }).notApplied).toEqual(note);
    expect(win(p, { budgetModel: 'risk', blastRadius: 0.5 }).notApplied).toEqual(note);
  });

  it('only a numeric budget_alloc limit is a budget', () => {
    for (const cv of [alloc('50'), { type: 'other', limit: 5 } as Caveat, { type: 'rate', max: 3, per_secs: 3600 } as Caveat]) {
      expect(win(pol([cv])).notApplied).toEqual([]);
    }
  });

  it('dollars: a limit above the bound changes nothing, equal changes nothing, below lowers it', () => {
    const r = rate(3, 86400);
    expect(win(pol([r, alloc(2000)]), { windowSecs: 86400, budgetModel: 'dollars' })).toMatchObject({ bound: 1500, basis: ['per-action ceiling', 'rate caveat 3/86400s'] });
    expect(win(pol([r, alloc(1500)]), { windowSecs: 86400, budgetModel: 'dollars' })).toMatchObject({ bound: 1500, basis: ['per-action ceiling', 'rate caveat 3/86400s'] });
    expect(win(pol([r, alloc(1499)]), { windowSecs: 86400, budgetModel: 'dollars' })).toMatchObject({ bound: 1499, basis: ['per-action ceiling', 'rate caveat 3/86400s', 'budget_alloc limit 1499'] });
  });

  it('risk: zero blast radius never exhausts, an exhausted budget allows none, a smaller count wins', () => {
    const free = win(pol([alloc(1200)]), { budgetModel: 'risk', kappa: 100, blastRadius: 0 });
    expect(free).toMatchObject({ maxActions: Infinity, bound: Infinity, basis: ['per-action ceiling'], notApplied: [] });
    expect(win(pol([alloc(-5)]), { budgetModel: 'risk', kappa: 100, blastRadius: 0 }).maxActions).toBe(Infinity);
    const open: PolicyInput = { predicates: [{ verb: V }], caveats: [alloc(10)] };
    expect(win(open, { budgetModel: 'risk', kappa: 100, blastRadius: 1 })).toMatchObject({ maxActions: 0, bound: 0, basis: ['budget_alloc 10 / cost 100 = 0 actions'] });
  });
});

describe('rate and cap windows', () => {
  it('a rate caveat, counted per started period, with the sequence that reaches the bound', () => {
    const e = maxExposure(pol([rate(3, 86400)]), { verb: V, integer: true, windowSecs: 86400 });
    expect(e.window).toEqual({ secs: 86400, maxActions: 3, bound: 1500, basis: ['per-action ceiling', 'rate caveat 3/86400s'], notApplied: [], sequence: { action: e.perAction.witness, repeat: 3 } });
    expect(e.autonomousWindow.sequence).toEqual({ action: e.autonomousPerAction.witness, repeat: 3 });
    // the first of equal or looser limits is kept, once
    const many = win(pol([rate(3, 86400), rate(10, 86400), rate(3, 90000)]), { windowSecs: 86400 });
    expect(many).toMatchObject({ maxActions: 3, bound: 1500, basis: ['per-action ceiling', 'rate caveat 3/86400s'] });
  });

  it('a rate limit says nothing about a lifetime total', () => {
    const w = win(pol([rate(3, 86400)]));
    expect(w).toEqual({ maxActions: Infinity, bound: Infinity, basis: ['per-action ceiling'], notApplied: [] });
  });

  it('a meet contributes its rate caveats', () => {
    const p: PolicyInput = { predicates: [refund(500)], meet: [{ predicates: [refund(500)], caveats: [rate(2, 3600)] }] };
    expect(win(p, { windowSecs: 3600 })).toMatchObject({ maxActions: 2, bound: 1000, basis: ['per-action ceiling', 'rate caveat 2/3600s'] });
  });

  it('only a well-formed rate caveat counts', () => {
    const bad: Caveat[] = [
      { type: 'rate', max: '3', per_secs: 86400 },
      { type: 'rate', max: 3, per_secs: '86400' },
      { type: 'rate', max: 3, per_secs: -1 },
      { type: 'rate', max: 3, per_secs: 0 },
      { type: 'bogus', max: 3, per_secs: 86400 },
      { type: 'bogus', max: 3 },
    ];
    for (const cv of bad) {
      expect(win(pol([cv]), { windowSecs: 86400 })).toMatchObject({ maxActions: Infinity, basis: [], notApplied: [] });
    }
  });

  it('no sequence unless a finite, positive, admitted ceiling meets a finite count', () => {
    const open: PolicyInput = { predicates: [{ verb: V }], caveats: [rate(3, 86400)] };
    expect(win(open, { windowSecs: 86400 })).toEqual({ secs: 86400, maxActions: 3, bound: Infinity, basis: ['rate caveat 3/86400s'], notApplied: [] });
    expect(win(pol(), { windowSecs: 86400 })).toEqual({ secs: 86400, maxActions: Infinity, bound: Infinity, basis: ['per-action ceiling'], notApplied: [] });
    const payout = maxExposure(pol([rate(3, 86400)]), { verb: 'stripe.payout', windowSecs: 86400 });
    expect(payout.window).toEqual({ secs: 86400, maxActions: 3, bound: 0, basis: ['rate caveat 3/86400s'], notApplied: [] });
    const zero: PolicyInput = { predicates: [{ verb: V, where: [lit(AMOUNT, 'lte', 0)] }], caveats: [rate(3, 86400)] };
    const z = maxExposure(zero, { verb: V, integer: true, windowSecs: 86400 });
    expect(z.perAction).toMatchObject({ admitted: true, max: 0, attained: true });
    expect(z.window).toEqual({ secs: 86400, maxActions: 3, bound: 0, basis: ['rate caveat 3/86400s'], notApplied: [] });
  });

  const rateInv = (when: Predicate) => constitution([{ kind: 'rate', id: 'r', when, max: 4, window_secs: 3600 }]);
  it('a rate invariant applies only when its trigger covers every action of the verb', () => {
    const applied: Predicate[] = [{ verb: '*' }, { verb: V }, { verb: [V, 'x'] }, { verb: ['*'] }, { verb: '*', resource: '*' }, { verb: V, where: [] }];
    for (const when of applied) {
      expect(win(pol(), { windowSecs: 3600, constitution: rateInv(when) })).toMatchObject({ maxActions: 4, bound: 2000, basis: ['per-action ceiling', 'rate invariant r'], notApplied: [] });
    }
    const notApplied: Predicate[] = [
      { verb: 'other' },
      { verb: ['other'] },
      { verb: 'stripe.*' },
      { verb: '*', resource: '/acct/9' },
      { verb: V, where: [lit('env.a', 'eq', 1)] },
    ];
    for (const when of notApplied) {
      expect(win(pol(), { windowSecs: 3600, constitution: rateInv(when) })).toMatchObject({ maxActions: Infinity, bound: Infinity, basis: ['per-action ceiling'], notApplied: ['r'] });
    }
    // a verb that merely contains the asked verb is not the same verb
    const refundOnly: PolicyInput = { predicates: [{ verb: 'refund', where: [lit(AMOUNT, 'lte', 500)] }] };
    expect(maxExposure(refundOnly, { verb: 'refund', windowSecs: 3600, constitution: rateInv({ verb: V }) }).window.notApplied).toEqual(['r']);
  });

  const capInv = (o: Record<string, unknown>) => constitution([{ kind: 'cap', id: 'c', when: { verb: V }, amount: AMOUNT, max: 300, ...o }]);
  it('a lifetime cap bounds the total; a windowed cap needs a window', () => {
    const lifetime = win(pol(), { constitution: capInv({}) });
    expect(lifetime).toMatchObject({ bound: 300, basis: ['per-action ceiling', 'cap invariant c'], notApplied: [] });
    expect(lifetime).not.toHaveProperty('secs');
    expect(win(pol(), { constitution: capInv({ window_secs: 86400 }) })).toMatchObject({ bound: Infinity, basis: ['per-action ceiling'], notApplied: [] });
    expect(win(pol(), { windowSecs: 3 * 86400, constitution: capInv({}) })).toMatchObject({ bound: 300 });
    expect(win(pol(), { windowSecs: 100000, constitution: capInv({ window_secs: 86400 }) })).toMatchObject({ bound: 600, basis: ['per-action ceiling', 'cap invariant c'] });
    expect(win(pol(), { windowSecs: 86400, constitution: capInv({ window_secs: 86400 }) })).toMatchObject({ bound: 300 });
  });

  it('a cap on another amount, or one that does not cover the verb, is listed, not applied', () => {
    expect(win(pol(), { constitution: capInv({ amount: 'action.params.fee' }) })).toMatchObject({ bound: Infinity, notApplied: ['c'] });
    expect(win(pol(), { constitution: capInv({ when: { verb: V, resource: '/acct/9' } }) })).toMatchObject({ bound: Infinity, notApplied: ['c'] });
  });

  it('a cap not below the existing bound changes nothing', () => {
    const r = pol([rate(3, 86400)]);
    const o = { windowSecs: 86400 };
    const keep = { bound: 1500, basis: ['per-action ceiling', 'rate caveat 3/86400s'] };
    expect(win(r, { ...o, constitution: capInv({ max: 2000 }) })).toMatchObject(keep);
    expect(win(r, { ...o, constitution: capInv({ max: 1500 }) })).toMatchObject(keep);
    expect(win(r, { ...o, constitution: capInv({ max: 1499 }) })).toMatchObject({ bound: 1499, basis: [...keep.basis, 'cap invariant c'] });
  });
});

describe('escalationSurface', () => {
  const many: PolicyInput = {
    predicates: [{ verb: 'v', resource: '/r/*', where: [lit('env.region', 'in', ['a', 'b', 'c'])] }],
    vetoes: [{ id: 'ap', kind: 'approval', when: { verb: 'v' }, over: { path: AMOUNT, threshold: 200 } }],
  };
  it('collects at most limit (default 8) verified escalating actions', () => {
    const m = toModel(many);
    for (const [o, n] of [[{}, 8], [{ limit: 3 }, 3], [{ limit: 50 }, 18]] as const) {
      const s = escalationSurface(many, { verb: 'v', ...o });
      expect(s.witnesses).toHaveLength(n);
      expect(s.escalates).toBe(true);
      expect(s.approximate).toBeUndefined();
      for (const w of s.witnesses) expect(decideAction(m, w)).toBe('escalate');
    }
  });

  it('is restricted to the asked verb', () => {
    const p: PolicyInput = { predicates: [{ verb: 'a' }, { verb: 'b' }], vetoes: [{ id: 'all', kind: 'approval', when: { verb: '*' } }] };
    expect(escalationSurface(p).witnesses.map((w) => w.verb).sort()).toEqual(['a', 'b']);
    expect(escalationSurface(p, { verb: 'a' }).witnesses.map((w) => w.verb)).toEqual(['a']);
  });

  it('never returns a witness the evaluator does not confirm', () => {
    const p: PolicyInput = { predicates: [{ verb: 'v' }], tighten: [{ id: 't', when: lit('action.risk', 'eq', 'high'), signal: 'escalate' }] };
    const m = toModel(p);
    for (const w of escalationSurface(p, { verb: 'v' }).witnesses) expect(decideAction(m, w)).toBe('escalate');
  });

  it('varies the reversibility class only under a cap', () => {
    const capped: PolicyInput = { predicates: [refund(500)], caveats: [revMax('rate_limited')], vetoes: [approval(200)] };
    const s = escalationSurface(capped, { verb: V });
    expect(s.escalates).toBe(true);
    for (const w of s.witnesses) expect(['reversible', 'rate_limited']).toContain(w.reversibilityClass);
    const plain = escalationSurface({ predicates: [refund(500)], vetoes: [approval(200)] }, { verb: V });
    expect(plain.escalates).toBe(true);
    for (const w of plain.witnesses) expect(w).not.toHaveProperty('reversibilityClass');
  });

  it('says why it is approximate', () => {
    const p: PolicyInput = { predicates: [{ verb: 'v', where: [lit('action.params.name', 'like', 'a*'), lit('action.params.code', 'matches', '[A-Z]+')] }], vetoes: [{ id: 'a', kind: 'approval', when: { verb: 'v' } }] };
    const reasons = toModel(p).undecidable;
    const s = escalationSurface(p, { verb: 'v' });
    expect(s.approximate).toBe(true);
    expect(s.reason).toBe(`over-approximated (${reasons[0]}; ${reasons[1]})`);
    expect(escalationSurface(base, { maxCombinations: 0 })).toMatchObject({ approximate: true, reason: 'representative grid exceeded the bound', escalates: false });
  });
});

describe('delegationEnvelope', () => {
  it('a wildcard verb is reachable as anyVerb, named verbs are listed with their autonomy', () => {
    expect(delegationEnvelope([{ predicates: [{ verb: '*' }] }])).toMatchObject({ anyVerb: true, verbs: [] });
    const p: PolicyInput = { predicates: [{ verb: 'a' }, { verb: 'b' }], vetoes: [{ id: 'x', kind: 'approval', when: { verb: 'a' } }] };
    const e = delegationEnvelope([p]);
    expect(e.anyVerb).toBe(false);
    expect(e.verbs.map((v) => [v.verb, v.autonomous])).toEqual([['a', false], ['b', true]]);
    expect(e).not.toHaveProperty('approximate');
  });

  it('a reversibility cap varies the class', () => {
    const e = delegationEnvelope([pol([revMax('rate_limited')])]);
    expect(e.verbs.map((v) => v.verb)).toEqual([V]);
    expect(e.verbs[0]!.witness.reversibilityClass).toBe('reversible');
    expect(delegationEnvelope([base]).verbs[0]!.witness).not.toHaveProperty('reversibilityClass');
  });

  it('flags a wider child only when the class is varied for a capped hop', () => {
    const wide: PolicyInput = { predicates: [refund(900)], caveats: [revMax('irreversible')] };
    expect(delegationEnvelope([base, wide]).violations).toEqual([1]);
    // a parent whose cap admits every class is not wider-than-child in any class
    const parent: PolicyInput = { predicates: [refund(500)], caveats: [revMax('irreversible')] };
    expect(delegationEnvelope([parent, base]).violations).toEqual([]);
  });

  it('the grid for an uncapped chain is not tripled; a bound equal to its size passes', () => {
    const e = delegationEnvelope([refund(500), refund(100)].map((r) => ({ predicates: [r] })), { maxCombinations: 42 });
    expect(e.violations).toEqual([]);
    expect(e).not.toHaveProperty('approximate');
  });

  it('an overflow is reported, and a single hop has no hop to check', () => {
    const chain: PolicyInput[] = [{ predicates: [refund(500)] }, { predicates: [refund(100)] }];
    const e = delegationEnvelope(chain, { maxCombinations: 0 });
    expect(e).toMatchObject({ approximate: true, reason: 'representative grid exceeded the bound', verbs: [], violations: [1] });
    expect(delegationEnvelope([chain[0]!], { maxCombinations: 0 }).violations).toEqual([]);
  });

  it('says why it is approximate', () => {
    const p: PolicyInput = { predicates: [{ verb: 'v', where: [lit('action.params.name', 'like', 'a*'), lit('action.params.code', 'matches', '[A-Z]+')] }] };
    const reasons = toModel(p).undecidable;
    expect(delegationEnvelope([p]).reason).toBe(`over-approximated (${reasons[0]}; ${reasons[1]})`);
  });

  it('the allowed depth is the smallest cap in the chain; none means none', () => {
    const d = (n: number): PolicyInput => ({ predicates: [refund(500)], caveats: [{ type: 'delegation_depth', max: n }] });
    expect(delegationEnvelope([d(3), d(2)]).depth).toStrictEqual({ used: 1, allowed: 2, remaining: 1 });
    expect(delegationEnvelope([base, base]).depth).toStrictEqual({ used: 1 });
    expect(delegationEnvelope([d(1), base, base]).depth).toStrictEqual({ used: 2, allowed: 1, remaining: 0 });
  });
});

describe('diffPolicies', () => {
  it('caps witnesses per kind at the limit, and walks the whole grid', () => {
    for (const limit of [1, 2, 3]) {
      expect(diffPolicies(base, { predicates: [refund(1000)] }, { limit }).shifts['deny->allow']).toHaveLength(limit);
    }
  });

  it('one line per kind, naming a moved action', () => {
    const widened = diffPolicies(base, { predicates: [refund(1000)] });
    const w = widened.shifts['deny->allow']!;
    expect(w.length).toBeGreaterThan(0);
    expect(typeof w[0]!.params?.amount).toBe('number');
    expect(widened.summary).toEqual([`deny->allow: ${w.length}+ action(s), e.g. ${w[0]!.verb} ${w[0]!.resource} ${JSON.stringify(w[0]!.params)}`]);
  });

  it('widening and narrowing can both hold', () => {
    const d = diffPolicies({ predicates: [refund(500, '/a/*')] }, { predicates: [refund(500, '/b/*')] });
    expect(Object.keys(d.shifts).sort()).toEqual(['allow->deny', 'deny->allow']);
    expect(d.widens).toBe(true);
    expect(d.narrows).toBe(true);
    expect(d.summary).toHaveLength(2);
  });

  it('the reversibility class is varied when either side caps it', () => {
    const capped: PolicyInput = { predicates: [refund(500)], caveats: [revMax('irreversible')] };
    for (const [a, b] of [[capped, base], [base, capped]] as const) {
      const d = diffPolicies(a, b);
      expect(d.equivalent).toBe(true);
      expect(d.shifts).toEqual({});
    }
  });

  it('an uncapped diff does not triple its grid: a bound equal to its size passes', () => {
    const d = diffPolicies(base, { predicates: [refund(100)] }, { maxCombinations: 42 });
    expect(d.approximate).toBeUndefined();
    expect(Object.keys(d.shifts)).toEqual(['allow->deny']);
  });

  it('exposure movement is summarised in both directions and silent when unchanged', () => {
    const o = { exposure: { verb: V, integer: true } };
    const falls = diffPolicies(base, { predicates: [refund(300)] }, o);
    expect(falls.exposure).toMatchObject({ perActionDelta: -200, delta: 0, autonomousDelta: 0 });
    expect(falls.summary[falls.summary.length - 1]).toBe(`max exposure of ${V} falls by 200`);
    const same = diffPolicies(base, { predicates: [refund(500)] }, o);
    expect(same.summary).toEqual([]);
    expect(same.equivalent).toBe(true);
    const rises = diffPolicies(base, { predicates: [refund(800)] }, o);
    expect(rises.summary[rises.summary.length - 1]).toBe(`max exposure of ${V} rises by 300`);
  });

  it('an undecidable construct on either side is inconclusive, with every distinct reason', () => {
    // the extra permit can never match (one field equal to two values): only the undecidable construct is at issue
    const never = [lit('env.n', 'eq', 1), lit('env.n', 'eq', 2)];
    const like: PolicyInput = { predicates: [refund(500), { verb: 'zzz', where: [lit('action.params.name', 'like', 'a*'), ...never] }] };
    const matches: PolicyInput = { predicates: [refund(500), { verb: 'zzz', where: [lit('action.params.code', 'matches', '[A-Z]+'), ...never] }] };
    const rl = toModel(like).undecidable;
    const rm = toModel(matches).undecidable;
    expect(rl).toHaveLength(1);
    expect(rm).toHaveLength(1);
    const both = diffPolicies(like, matches);
    expect(both.approximate).toBe(true);
    expect(both.reason).toBe(`over-approximated (${rl[0]}; ${rm[0]})`);
    const onlyA = diffPolicies(like, base);
    expect(onlyA.approximate).toBe(true);
    expect(onlyA.equivalent).toBe(false);
    const onlyB = diffPolicies(base, like);
    expect(onlyB.approximate).toBe(true);
    expect(onlyB.equivalent).toBe(false);
    const same = diffPolicies(like, like);
    expect(same.reason).toBe(`over-approximated (${rl[0]})`);
    expect(same.equivalent).toBe(false);
  });
});

describe('diffGate', () => {
  const diff = (o: Partial<PolicyDiff>): PolicyDiff => ({ equivalent: false, shifts: {}, widens: false, narrows: false, summary: [], ...o });

  it('names only the widening lines', () => {
    const d = diff({ widens: true, narrows: true, summary: ['deny->allow: 1+ x', 'allow->deny: 1+ y', 'escalate->allow: 2+ z', 'max exposure of v rises by 5'] });
    expect(diffGate(d)).toEqual({ ok: false, reasons: ['widens authority: deny->allow: 1+ x; escalate->allow: 2+ z'] });
    expect(diffGate(d, { widen: true })).toEqual({ ok: true, reasons: [] });
  });

  it('gates the exposure increase at the allowed amount, using the largest movement', () => {
    const e = { before: {} as never, after: {} as never };
    const d = diff({ exposure: { ...e, perActionDelta: 300, delta: 0, autonomousDelta: 0 } });
    expect(diffGate(d)).toEqual({ ok: false, reasons: ['max exposure rises by 300'] });
    expect(diffGate(d, { maxExposureIncrease: 299 }).reasons).toEqual(['max exposure rises by 300']);
    expect(diffGate(d, { maxExposureIncrease: 300 })).toEqual({ ok: true, reasons: [] });
    expect(diffGate(diff({ exposure: { ...e, perActionDelta: -5, delta: 0, autonomousDelta: 7 } })).reasons).toEqual(['max exposure rises by 7']);
  });

  it('an approximate diff is inconclusive, with its reason or a default', () => {
    expect(diffGate(diff({ approximate: true, reason: 'why' }))).toEqual({ ok: false, reasons: ['inconclusive: why'] });
    expect(diffGate(diff({ approximate: true }))).toEqual({ ok: false, reasons: ['inconclusive: approximate'] });
  });

  it('a real diff gates both ways', () => {
    const d = diffPolicies(base, { predicates: [refund(800)] }, { exposure: { verb: V, integer: true } });
    const g = diffGate(d);
    expect(g.ok).toBe(false);
    expect(g.reasons).toHaveLength(2);
    expect(g.reasons[0]).toMatch(/^widens authority: deny->allow: \d+\+ action\(s\), e\.g\. /);
    expect(g.reasons[1]).toBe('max exposure rises by 300');
  });
});

describe('findWithBackend', () => {
  const w = (amount: number, verb = V): AnalyzerAction => ({ verb, resource: '/acct/1', params: { amount } });
  const backend = (r: Awaited<ReturnType<WitnessBackend['find']>>): WitnessBackend => ({ name: 'stub', find: async () => r });

  it('a reachable query checks the verb only when one was asked for', async () => {
    expect(await findWithBackend(backend({ witness: w(10) }), { kind: 'reachable', a: base })).toEqual({ witness: w(10) });
    expect(await findWithBackend(backend({ witness: w(10) }), { kind: 'reachable', a: base, verb: V })).toEqual({ witness: w(10) });
    expect(await findWithBackend(backend({ witness: w(10) }), { kind: 'reachable', a: base, verb: 'stripe.payout' })).toEqual({ rejected: true });
  });

  it('a differs query needs a second policy and a witness exactly one of them admits', async () => {
    const wide: PolicyInput = { predicates: [refund(1000)] };
    expect(await findWithBackend(backend({ witness: w(700) }), { kind: 'differs', a: wide })).toEqual({ rejected: true });
    expect(await findWithBackend(backend({ witness: w(700) }), { kind: 'differs', a: wide, b: base })).toEqual({ witness: w(700) });
    expect(await findWithBackend(backend({ witness: w(700) }), { kind: 'differs', a: base, b: wide })).toEqual({ witness: w(700) });
    expect(await findWithBackend(backend({ witness: w(700) }), { kind: 'differs', a: wide, b: wide })).toEqual({ rejected: true });
  });

  it('no witness and no unsat claim is an empty result; an unsat claim is labelled', async () => {
    expect(await findWithBackend(backend({}), { kind: 'reachable', a: base })).toEqual({});
    expect(await findWithBackend(backend({ unsat: false }), { kind: 'reachable', a: base })).toEqual({});
    expect(await findWithBackend(backend({ unsat: true }), { kind: 'reachable', a: base })).toEqual({ claimedUnsat: { by: 'stub', proof: 'solver-claimed, not machine-checked' } });
  });
});
