import { describe, expect, it } from 'vitest';
import type { Caveat, Condition, Predicate } from '@atlasauth/pca';
import { alwaysDenies, coverage, delegationEnvelope, diffPolicies, escalationSurface, reachable, thresholdsOf, toModel, type AnalyzerAction, type PolicyInput } from './index';
import { toFilter } from './filter';
import type { Residual } from './residual';
import { refund, rng } from './k2-fixtures';

const leaf = (field: string, op: string, value?: unknown): Condition => ({ field, op, value }) as unknown as Condition;
const pred = (verb: string, where?: Condition[]): Predicate => ({ verb, ...(where ? { where } : {}) }) as unknown as Predicate;
const N = (op: string, v: unknown) => leaf('action.params.n', op, v);

describe('rng (seeded generator)', () => {
  it('produces the fixed mulberry32 sequence', () => {
    const r = rng(1);
    expect([r(), r(), r()]).toEqual([0.6270739405881613, 0.002735721180215478, 0.5274470399599522]);
    const q = rng(42);
    expect([q(), q()]).toEqual([0.6011037519201636, 0.44829055899754167]);
  });
});

describe('coverage: non-finite thresholds do not generate mutants', () => {
  it('a policy with an infinite threshold cannot be digested, so coverage refuses it instead of mutating it', () => {
    expect(() => coverage({ predicates: [pred('a', [N('lte', Infinity)])] }, [], { maxMutants: 100 })).toThrow(/non-finite number/);
  });
});

describe('toFilter: an unexpected internal error is reported generically', () => {
  it('a non-Unsupported failure gives the fixed compilation-error refusal', () => {
    const residual: Residual = { decision: 'conditional', policy: { predicates: [pred('v')], caveats: [], vetoes: [], tighten: [] }, policyDigest: 'd' };
    const o = Object.defineProperty({ dialect: 'postgres' }, 'columns', {
      get() {
        throw new Error('boom');
      },
    });
    expect(toFilter(residual, o as never)).toEqual({ ok: false, reason: 'filter compilation error' });
  });
});

describe('the grid bound option', () => {
  const many: PolicyInput = { predicates: Array.from({ length: 12 }, (_, i) => pred('v', [leaf(`action.params.f${i}`, 'in', ['a', 'b', 'c', 'd']), leaf(`action.params.g${i}`, 'eq', i)])) };
  const mid: PolicyInput = { predicates: [pred('v', [...[0, 1, 2, 3].map((i) => leaf(`action.params.f${i}`, 'in', ['a', 'b', 'c', 'd'])), N('gte', 10), N('lte', 1)])] };

  it('an unusable bound falls back to the default on a grid only the default rejects', () => {
    const dflt = alwaysDenies(many);
    expect(dflt).toMatchObject({ alwaysDenies: false, approximate: true });
    for (const maxCombinations of [undefined, Number.NaN, Infinity]) expect(alwaysDenies(many, undefined, { maxCombinations })).toEqual(dflt);
  });

  it('a negative or non-number bound falls back to the default on a mid-sized grid', () => {
    const dflt = alwaysDenies(mid);
    expect(dflt.alwaysDenies).toBe(true);
    expect(dflt.approximate).toBeUndefined();
    expect(alwaysDenies(mid, undefined, { maxCombinations: -1 })).toEqual(dflt);
    expect(alwaysDenies(mid, undefined, { maxCombinations: '9' as never })).toEqual(dflt);
    expect(alwaysDenies(mid, undefined, { maxCombinations: 9 })).toMatchObject({ alwaysDenies: false, approximate: true });
  });

  it('null options are treated as no options', () => {
    const a: AnalyzerAction = { verb: 'a', resource: '/r' };
    expect(reachable({ predicates: [pred('a')] }, a, null as never)).toEqual({ reachable: true, witness: a });
  });
});

describe('reachable: the reversibility dimension is searched only under a reversibility cap', () => {
  it('an action with no class is completed with the capped class', () => {
    const capped: PolicyInput = { predicates: [pred('a', [N('lte', 5)])], caveats: [{ type: 'reversibility_max', class: 'reversible' } as Caveat] };
    const r = reachable(capped, { verb: 'a', resource: '/r' });
    expect(r.reachable).toBe(true);
    expect(r.witness?.reversibilityClass).toBe('reversible');
  });
  it('without a cap the witness carries no class', () => {
    const r = reachable({ predicates: [pred('a', [N('lte', 5)])] }, { verb: 'a', resource: '/r' });
    expect(r.reachable).toBe(true);
    expect(r.witness).not.toHaveProperty('reversibilityClass');
  });
});

describe('thresholdsOf ignores a non-finite literal', () => {
  it('only finite numbers are thresholds', () => {
    const m = toModel({ predicates: [pred('v', [leaf('action.params.amount', 'lte', Infinity), leaf('action.params.amount', 'gte', 5)])] });
    expect(thresholdsOf(m, 'action.params.amount')).toEqual([5]);
  });
});

describe('escalationSurface re-checks every witness with the real evaluator', () => {
  it('a representative whose non-params fields cannot be carried in the action is not reported', () => {
    const p: PolicyInput = { predicates: [pred('v', [leaf('action.tier', 'eq', 'gold')])], vetoes: [{ id: 'a', kind: 'approval', when: pred('v') }] };
    const e = escalationSurface(p, { verb: 'v' });
    expect(e.witnesses).toEqual([]);
    expect(e.escalates).toBe(false);
  });
});

describe('delegationEnvelope', () => {
  it('a verb that merely ends with a NUL is a named verb, not the fresh-verb placeholder', () => {
    const e = delegationEnvelope([{ predicates: [pred('tail\u0000')] }]);
    expect(e.anyVerb).toBe(false);
    expect(e.verbs.map((v) => v.verb)).toEqual(['tail\u0000']);
  });

  it('delegation depth is the smallest numeric delegation_depth in the chain; other caveats and malformed entries are ignored', () => {
    const rate = { type: 'rate', max: 1, per_secs: 60 } as Caveat;
    const badDepth = { type: 'delegation_depth', max: 'x' } as unknown as Caveat;
    const chain = [
      null as never,
      'text' as never,
      7 as never,
      { predicates: [pred('v')] },
      { predicates: [pred('v')], caveats: [rate, badDepth, { type: 'delegation_depth', max: 5 } as Caveat] },
      { predicates: [pred('v')], caveats: [{ type: 'delegation_depth', max: 3 } as Caveat] },
    ] as PolicyInput[];
    const e = delegationEnvelope(chain);
    expect(e.depth).toEqual({ used: 5, allowed: 3, remaining: 0 });
    const shallow = delegationEnvelope([{ predicates: [pred('v')], caveats: [{ type: 'delegation_depth', max: 4 } as Caveat] }, { predicates: [pred('v')], caveats: [rate] }]);
    expect(shallow.depth).toEqual({ used: 1, allowed: 4, remaining: 3 });
  });
});

describe('diffPolicies overflow reason', () => {
  it('names the exceeded grid bound', () => {
    const d = diffPolicies({ predicates: [refund(500)] }, { predicates: [refund(100)] }, { maxCombinations: 0 });
    expect(d.approximate).toBe(true);
    expect(d.reason).toBe('representative grid exceeded the bound');
  });
});
