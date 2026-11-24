import { describe, expect, it } from 'vitest';
import type { Condition, Predicate } from '@atlasauth/pca';
import { minimalFlip, type FlipResult } from './flip';
import { refund, refundShape } from './k2-fixtures';
import type { AnalyzerAction, PolicyInput, VerbShape } from './types';

const c = (field: string, op: string, value?: unknown, extra: object = {}) => ({ field, op, ...(value !== undefined ? { value } : {}), ...extra }) as unknown as Condition;
const P = (verb: string, where?: Condition[], resource?: string): Predicate => ({ verb, ...(resource !== undefined ? { resource } : {}), ...(where ? { where } : {}) }) as Predicate;
const who = { holderAuthenticated: true };
const ctxAt = (now: number, blastRadius = 0) => ({ now, blastRadius, reversibilityClass: 'reversible', recentActionTimes: [] }) as never;
const act = (resource: string, params?: Record<string, unknown>): AnalyzerAction => ({ verb: 'v', resource, ...(params ? { params } : {}) });
const shapeOf = (params: VerbShape['params']): VerbShape => ({ verb: 'v', params });
const stepsOf = (r: FlipResult): unknown[] => r.repairs.map((x) => (x.repair.kind === 'combine' ? x.repair.steps : x.repair));
const NO_REPAIR = (r: FlipResult): void => {
  expect(r.repairs).toEqual([]);
  expect(r.repairExists).toBe(false);
  expect(r.humanAsk?.kind).toBe('access-request');
};

describe('minimalFlip cost of a single parameter edit', () => {
  it('a numeric lowering costs 2 plus the relative distance, capped at 1', () => {
    const r = minimalFlip({ predicates: [refund(500)] }, { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 900 } }, { holderAuthenticated: true, schema: [refundShape] });
    expect(r.repairs[0]!.repair).toEqual({ kind: 'set_param', param: 'amount', from: 900, to: 500 });
    expect(r.repairs[0]!.cost).toBeCloseTo(2 + 400 / 901, 10);
  });

  it('a string value costs 2.5, also when the current value is a number', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.p', 'in', ['a', 'b'])])] };
    const r = minimalFlip(p, act('/r', { p: 5 }), who);
    expect(r.repairs).toEqual([{ repair: { kind: 'set_param', param: 'p', from: 5, to: 'a' }, cost: 2.5, decision: 'allow', action: act('/r', { p: 'a' }) }]);
  });

  it('a number replacing a missing value costs 2.5 and is ordered by distance to zero', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.p', 'lte', 500), c('action.params.p', 'gte', -400)])] };
    const r = minimalFlip(p, act('/r', {}), { ...who, changeable: ['p'] });
    expect(r.repairs).toEqual([{ repair: { kind: 'set_param', param: 'p', from: undefined, to: 50 }, cost: 2.5, decision: 'allow', action: act('/r', { p: 50 }) }]);
  });

  it('equidistant candidates: the lower value wins', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.n', 'in', [12, 8])])] };
    const r = minimalFlip(p, act('/r', { n: 10 }), who);
    expect(r.repairs).toHaveLength(1);
    expect(r.repairs[0]!.repair).toEqual({ kind: 'set_param', param: 'n', from: 10, to: 8 });
    expect(r.repairs[0]!.cost).toBeCloseTo(2 + 2 / 11, 10);
  });
});

describe('minimalFlip integer neighbours', () => {
  const band: PolicyInput = { predicates: [P('v', [c('action.params.n', 'gt', 10), c('action.params.n', 'lt', 20)])] };

  it('a non-integer value with no integer declaration only gets the cell representatives', () => {
    const r = minimalFlip(band, act('/r', { n: 100.5 }), who);
    expect(r.repairs).toHaveLength(1);
    expect(r.repairs[0]!.repair).toEqual({ kind: 'set_param', param: 'n', from: 100.5, to: 15 });
    expect(r.repairs[0]!.cost).toBeCloseTo(2 + 85.5 / 101.5, 10);
  });

  it('an integer current value adds the neighbours of each threshold', () => {
    const r = minimalFlip(band, act('/r', { n: 100 }), who);
    expect(r.repairs).toHaveLength(1);
    expect(r.repairs[0]!.repair).toEqual({ kind: 'set_param', param: 'n', from: 100, to: 19 });
    expect(r.repairs[0]!.cost).toBeCloseTo(2 + 81 / 101, 10);
    const low = minimalFlip(band, act('/r', { n: 0 }), who);
    expect(low.repairs[0]!.repair).toEqual({ kind: 'set_param', param: 'n', from: 0, to: 11 });
    expect(low.repairs[0]!.cost).toBe(3);
  });

  it('a declared integer adds the neighbours even when the current value is not an integer', () => {
    const r = minimalFlip(band, act('/r', { n: 100.5 }), { ...who, schema: [shapeOf({ n: { type: 'integer' } })] });
    expect(r.repairs).toHaveLength(1);
    expect(r.repairs[0]!.repair).toEqual({ kind: 'set_param', param: 'n', from: 100.5, to: 19 });
    expect(r.repairs[0]!.cost).toBeCloseTo(2 + 81.5 / 101.5, 10);
  });
});

describe('minimalFlip schema bounds', () => {
  it('the declared minimum is a candidate and a lower bound', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.n', 'lt', 5), c('action.params.n', 'ne', -3)])] };
    const r = minimalFlip(p, act('/r', { n: -3 }), { ...who, schema: [shapeOf({ n: { type: 'integer', min: 0 } })] });
    expect(r.repairs).toEqual([{ repair: { kind: 'set_param', param: 'n', from: -3, to: 0 }, cost: 2.75, decision: 'allow', action: act('/r', { n: 0 }) }]);
  });

  it('the declared maximum is a candidate, an inclusive upper bound, and excludes larger values', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.n', 'gt', 5), c('action.params.n', 'lt', 50), c('action.params.n', 'ne', 20)])] };
    const r = minimalFlip(p, act('/r', { n: 100 }), { ...who, schema: [shapeOf({ n: { type: 'integer', max: 8 } })] });
    expect(r.repairs).toHaveLength(1);
    expect(r.repairs[0]!.repair).toEqual({ kind: 'set_param', param: 'n', from: 100, to: 8 });
    expect(r.repairs[0]!.cost).toBeCloseTo(2 + 92 / 101, 10);
  });

  it('a non-finite declared bound is not a candidate value', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.p', 'exists')])] };
    NO_REPAIR(minimalFlip(p, act('/r', {}), { ...who, schema: [shapeOf({ p: { max: Infinity } })] }));
  });
});

describe('minimalFlip never offers an internal sentinel or placeholder value', () => {
  it('a denied literal with only the sentinel left means no repair', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.p', 'ne', 'bad')], '/a')] };
    NO_REPAIR(minimalFlip(p, act('/a', { p: 'bad' }), who));
    NO_REPAIR(minimalFlip(p, act('/b', { p: 'bad' }), who));
  });

  it('a parameter the policy only relates to another by reference gets no invented value', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.a', 'ne', undefined, { ref: 'action.params.limit' })], '/a')] };
    NO_REPAIR(minimalFlip(p, act('/a', { a: 5, limit: 5 }), who));
    NO_REPAIR(minimalFlip(p, act('/b', { a: 5, limit: 5 }), who));
  });

  it('only a value that merely ends in the sentinel byte is kept; one that starts with it is not offered', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.p', 'in', ['\u0000h', 't\u0000'])])] };
    const r = minimalFlip(p, act('/r', { p: 'z' }), who);
    expect(r.repairs).toEqual([{ repair: { kind: 'set_param', param: 'p', from: 'z', to: 't\u0000' }, cost: 2.5, decision: 'allow', action: act('/r', { p: 't\u0000' }) }]);
    const pair: PolicyInput = { predicates: [P('v', [c('action.params.p', 'in', ['\u0000h', 't\u0000'])], '/a')] };
    const r2 = minimalFlip(pair, act('/b', { p: 'z' }), who);
    expect(stepsOf(r2)).toEqual([[{ kind: 'set_param', param: 'p', from: 'z', to: 't\u0000' }, { kind: 'set_resource', from: '/b', to: '/a' }]]);
  });
});

describe('minimalFlip waiting', () => {
  it('a caveat with no context is not a closed caveat', () => {
    const p: PolicyInput = { predicates: [refund(500)], caveats: [{ type: 'max_blast_radius', max: 0.5 }] as never };
    expect(minimalFlip(p, { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 5 } }, who)).toMatchObject({ current: 'allow', repairs: [], repairExists: false });
  });

  it('waiting is offered alone while a caveat is closed', () => {
    const p: PolicyInput = { predicates: [P('v')], caveats: [{ type: 'not_before', at: 5000 }] };
    const r = minimalFlip(p, act('/r'), { ...who, caveatContext: ctxAt(1000) });
    expect(r.current).toBe('deny');
    expect(r.repairs).toEqual([{ repair: { kind: 'wait_until', at: 5000, reason: 'a time or rate caveat opens then' }, cost: 1, decision: 'allow', action: act('/r') }]);
  });

  it('waiting does not help an action the policy denies anyway', () => {
    const p: PolicyInput = { predicates: [refund(500)], caveats: [{ type: 'not_before', at: 5000 }] };
    const r = minimalFlip(p, { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 900 } }, { ...who, caveatContext: ctxAt(1000) });
    expect(r.current).toBe('deny');
    NO_REPAIR(r);
  });

  it('waiting does not help when the caveats still fail at the later time', () => {
    const p: PolicyInput = { predicates: [refund(500)], caveats: [{ type: 'not_before', at: 5000 }, { type: 'max_blast_radius', max: 0.5 }] as never };
    NO_REPAIR(minimalFlip(p, { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 5 } }, { ...who, caveatContext: ctxAt(1000, 0.9) }));
  });

  it('a caveat that no waiting can open offers no wait', () => {
    const p: PolicyInput = { predicates: [refund(500)], caveats: [{ type: 'max_blast_radius', max: 0.5 }] as never };
    NO_REPAIR(minimalFlip(p, { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 5 } }, { ...who, caveatContext: ctxAt(1000, 0.9) }));
  });
});

describe('minimalFlip probe budget', () => {
  const policy: PolicyInput = { predicates: [refund(500)] };
  const big = { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 900 } };

  it('a probe exactly at the window edge has aged out', () => {
    const r = minimalFlip(policy, big, { ...who, probe: { limit: 1, windowSecs: 60, history: [40_000], now: 100_000 } });
    expect(r.refused).toBeUndefined();
    expect(r.probe).toEqual({ history: [100_000] });
  });

  it('an exhausted budget refuses and reports only the probes still inside the window', () => {
    const r = minimalFlip(policy, big, { ...who, probe: { limit: 2, windowSecs: 60, history: [95_000, 10_000, 99_000], now: 100_000 } });
    expect(r).toEqual({ current: 'deny', repairs: [], repairExists: false, refused: 'probe budget exhausted', probe: { history: [95_000, 99_000] } });
  });
});

describe('minimalFlip schema lookup and resources', () => {
  it('uses the shape of the action verb, not the first shape', () => {
    const other: VerbShape = { verb: 'other', params: { zzz: { type: 'integer' } } };
    const r = minimalFlip({ predicates: [refund(500)] }, { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 900 } }, { ...who, schema: [other, refundShape] });
    expect(r.repairs[0]!.repair).toMatchObject({ kind: 'set_param', param: 'amount', to: 500 });
  });

  it('another allowed resource is returned as a verified repair of cost 3', () => {
    const r = minimalFlip({ predicates: [P('v', undefined, '/a')] }, act('/b'), who);
    expect(r).toEqual({ current: 'deny', repairs: [{ repair: { kind: 'set_resource', from: '/b', to: '/a' }, cost: 3, decision: 'allow', action: act('/a') }], repairExists: true });
  });

  it('placeholder resources are never offered, alone or in a pair', () => {
    const p: PolicyInput = {
      predicates: [P('v', [c('action.params.p', 'in', ['x', 'y'])]), P('w', undefined, '\u0000s')],
      vetoes: [{ id: 'vb', kind: 'deny', when: P('v', undefined, '/b') }],
    };
    NO_REPAIR(minimalFlip(p, act('/b', { p: 'x' }), who));
  });

  it('a closed caveat offers nothing but the wait, not a stray resource', () => {
    const p: PolicyInput = { predicates: [P('v')], caveats: [{ type: 'not_before', at: 5000 }] };
    const r = minimalFlip(p, act('/r'), { ...who, caveatContext: ctxAt(1) });
    expect(r.repairs.map((x) => x.repair.kind)).toEqual(['wait_until']);
  });

  it('picks the parameter value from the matching field', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.p', 'in', ['x']), c('action.params.q', 'in', ['y'])])] };
    const r = minimalFlip(p, act('/r', { p: 'x', q: 'z' }), who);
    expect(r.repairs).toEqual([{ repair: { kind: 'set_param', param: 'q', from: 'z', to: 'y' }, cost: 2.5, decision: 'allow', action: act('/r', { p: 'x', q: 'y' }) }]);
  });
});

describe('minimalFlip pairs of edits', () => {
  it('a parameter and the resource together, keeping the other parameters', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.p', 'in', ['x']), c('action.params.q', 'in', ['y'])], '/a')] };
    const r = minimalFlip(p, act('/b', { p: 'x', q: 'z' }), who);
    expect(r.repairs).toEqual([
      {
        repair: { kind: 'combine', steps: [{ kind: 'set_param', param: 'q', from: 'z', to: 'y' }, { kind: 'set_resource', from: '/b', to: '/a' }] },
        cost: 5,
        decision: 'allow',
        action: act('/a', { p: 'x', q: 'y' }),
      },
    ]);
  });

  it('numeric values take part in a pair', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.p', 'eq', 7)], '/a')] };
    const r = minimalFlip(p, act('/b', { p: 'z' }), who);
    expect(stepsOf(r)).toEqual([[{ kind: 'set_param', param: 'p', from: 'z', to: 7 }, { kind: 'set_resource', from: '/b', to: '/a' }]]);
  });

  it('at most six values per dimension, never the current value', () => {
    const vs = ['v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7'];
    const p: PolicyInput = { predicates: [P('v', [c('action.params.p', 'nin', ['c']), c('action.params.p', 'in', vs)], '/a')] };
    const r = minimalFlip(p, act('/b', { p: 'c' }), who);
    expect(r.repairs).toHaveLength(6);
    expect(r.repairs.map((x) => (x.repair.kind === 'combine' ? (x.repair.steps[0] as { to: string }).to : null))).toEqual(['v1', 'v2', 'v3', 'v4', 'v5', 'v6']);
    for (const x of r.repairs) expect(x.cost).toBe(5);
  });

  it('a parameter the policy only relates by reference gets no invented value in a pair', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.a', 'ne', undefined, { ref: 'action.params.limit' })], '/a')] };
    expect(stepsOf(minimalFlip(p, act('/b', { a: 5, limit: 5 }), who))).toEqual([]);
  });

  // resources r0 (the action's own) .. rN; only r<valid> admits the verb, and only with p = 'x'
  const world = (n: number, valid: number): PolicyInput => ({
    predicates: Array.from({ length: n + 1 }, (_, i) => (i === valid ? P('v', [c('action.params.p', 'in', ['x'])], `/r${i}`) : P('w', undefined, `/r${i}`))),
  });

  it('the sixth other resource is still tried (the action own resource takes no slot)', () => {
    const r = minimalFlip(world(6, 6), act('/r0', { p: 'z' }), who);
    expect(r.repairs).toEqual([
      {
        repair: { kind: 'combine', steps: [{ kind: 'set_param', param: 'p', from: 'z', to: 'x' }, { kind: 'set_resource', from: '/r0', to: '/r6' }] },
        cost: 5,
        decision: 'allow',
        action: act('/r6', { p: 'x' }),
      },
    ]);
  });

  it('the seventh other resource is not tried', () => {
    NO_REPAIR(minimalFlip(world(7, 7), act('/r0', { p: 'z' }), who));
  });
});

describe('minimalFlip named facts', () => {
  it('subject and env facts are offered, keeping what the action already carries', () => {
    const p: PolicyInput = { predicates: [P('v', [c('subject.kyc', 'eq', 'done')]), P('v', [c('env.region', 'eq', 'eu')])] };
    const a: AnalyzerAction = { verb: 'v', resource: '/r', subject: { a: 1 } };
    const r = minimalFlip(p, a, who);
    expect(r.repairs).toEqual([
      { repair: { kind: 'obtain_fact', path: 'subject.kyc', value: 'done' }, cost: 4, decision: 'allow', action: { verb: 'v', resource: '/r', subject: { a: 1, kyc: 'done' } } },
      { repair: { kind: 'obtain_fact', path: 'env.region', value: 'eu' }, cost: 4, decision: 'allow', action: { verb: 'v', resource: '/r', subject: { a: 1 }, env: { region: 'eu' } } },
    ]);
    expect(a).toEqual({ verb: 'v', resource: '/r', subject: { a: 1 } });
  });

  it('a nested fact is added beside the existing nested entries', () => {
    const p: PolicyInput = { predicates: [P('v', [c('subject.org.tier', 'eq', 'gold')])] };
    const a: AnalyzerAction = { verb: 'v', resource: '/r', subject: { a: 1, org: { id: 'o1' } } };
    const r = minimalFlip(p, a, who);
    expect(r.repairs).toHaveLength(1);
    expect(r.repairs[0]!.repair).toEqual({ kind: 'obtain_fact', path: 'subject.org.tier', value: 'gold' });
    expect(r.repairs[0]!.action).toEqual({ verb: 'v', resource: '/r', subject: { a: 1, org: { id: 'o1', tier: 'gold' } } });
    expect(a.subject).toEqual({ a: 1, org: { id: 'o1' } });
  });
});

describe('minimalFlip splitting', () => {
  const big = { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 900 } };
  const kinds = (caveats: unknown[]): string[] =>
    minimalFlip({ predicates: [refund(500)], caveats: caveats as never }, big, { holderAuthenticated: true, schema: [refundShape], allowSplit: true }).repairs.map((x) => x.repair.kind);

  it('a caveat that does not meter the total leaves splitting on', () => {
    const r = minimalFlip({ predicates: [refund(500)], caveats: [{ type: 'delegation_depth', max: 3 }] as never }, big, { holderAuthenticated: true, schema: [refundShape], allowSplit: true });
    expect(r.repairs.find((x) => x.repair.kind === 'split')?.repair).toMatchObject({ kind: 'split', param: 'amount', parts: [{ amount: 500 }, { amount: 400 }] });
  });

  it('a budget allocation or a blast radius cap meters the total, so no split is offered', () => {
    expect(kinds([{ type: 'budget_alloc', limit: 1000 }])).not.toContain('split');
    expect(kinds([{ type: 'max_blast_radius', max: 0.5 }])).not.toContain('split');
    expect(kinds([{ type: 'budget_alloc', limit: 1000 }])).toContain('set_param');
  });
});
