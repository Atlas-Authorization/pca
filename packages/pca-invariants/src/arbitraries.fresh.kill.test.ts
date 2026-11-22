/**
 * The arbitraries are module-level constants, so their parameters (ranges, literals, optional keys) are evaluated when the
 * module is first imported. Each test therefore imports a FRESH copy inside the test body and asserts the domain of what it
 * generates on a large fixed-seed sample, so a changed range, literal or key shows up in that very test.
 */
import fc from 'fast-check';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { verifyChain } from '@atlasauth/pca';

type Arbs = typeof import('./arbitraries');
const fresh = async (): Promise<Arbs> => import('./arbitraries');
beforeEach(() => {
  vi.resetModules();
});

const draw = <T>(arb: fc.Arbitrary<T>, n = 1500): T[] => fc.sample(arb, { numRuns: n, seed: 20261112 });
// fast-check places NaN one index above the finite maximum unless `noNaN` is set, so NaN only shows up in a large sample.
const bigDraw = <T>(arb: fc.Arbitrary<T>, n: number): T[] => fc.sample(arb, { numRuns: n, seed: 7771 });
const isInt = (x: unknown): x is number => typeof x === 'number' && Number.isInteger(x);
const inRange = (x: unknown, lo: number, hi: number): boolean => typeof x === 'number' && Number.isFinite(x) && x >= lo && x <= hi;
const sorted = (xs: Iterable<string>): string[] => [...new Set(xs)].sort();
const VERBS = ['admin', 'delete', 'list', 'read', 'transfer', 'write'];
const FIELDS = ['action.params.amount', 'action.resource', 'action.verb', 'env.ip', 'subject.role', 'subject.tier'];
const OPS = ['eq', 'exists', 'gt', 'gte', 'in', 'lt', 'lte', 'ne', 'nin', 'prefix'];

describe('fresh arbLeafCondition', () => {
  it('always has field/op/value from the fixed vocabularies; integers in [-10, 10] of both signs; at most three strings in an array', async () => {
    const { arbLeafCondition } = await fresh();
    const leaves = draw(arbLeafCondition);
    for (const l of leaves) expect(Object.keys(l).sort()).toEqual(['field', 'op', 'value']);
    expect(sorted(leaves.map((l) => l.field))).toEqual(FIELDS);
    expect(sorted(leaves.map((l) => l.op))).toEqual(OPS);
    const nums = leaves.map((l) => l.value).filter((v): v is number => typeof v === 'number');
    for (const n of nums) expect(isInt(n) && inRange(n, -10, 10)).toBe(true);
    expect(nums.some((n) => n < 0)).toBe(true);
    expect(nums.some((n) => n > 0)).toBe(true);
    const arrs = leaves.map((l) => l.value).filter((v): v is string[] => Array.isArray(v));
    for (const a of arrs) expect(a.length).toBeLessThanOrEqual(3);
    expect(arrs.some((a) => a.length === 3)).toBe(true);
  });
});

describe('fresh arbPredicate', () => {
  it('verbs, literal resources, optional keys and where length', async () => {
    const { arbPredicate } = await fresh();
    const preds = draw(arbPredicate);
    let star = 0;
    for (const p of preds) {
      expect(Object.keys(p).every((k) => ['verb', 'resource', 'where'].includes(k))).toBe(true);
      if (Array.isArray(p.verb)) {
        expect(p.verb.length >= 1 && p.verb.length <= 3).toBe(true);
        for (const v of p.verb) expect(VERBS).toContain(v);
      } else if (p.verb === '*') star++;
      else expect(VERBS).toContain(p.verb);
      if ('resource' in p) expect(typeof p.resource).toBe('string');
      if ('where' in p) {
        expect(Array.isArray(p.where)).toBe(true);
        expect(p.where!.length).toBeLessThanOrEqual(2);
      }
    }
    expect(star).toBeGreaterThan(preds.length * 0.2);
    expect(preds.some((p) => Array.isArray(p.verb) && p.verb.length === 3)).toBe(true);
    expect(preds.some((p) => !('resource' in p))).toBe(true);
    expect(preds.some((p) => 'resource' in p)).toBe(true);
    expect(preds.some((p) => !('where' in p))).toBe(true);
    expect(preds.some((p) => p.where?.length === 2)).toBe(true);
    const count = (r: string): number => preds.filter((p) => p.resource === r).length;
    expect(count('*')).toBeGreaterThan(preds.length * 0.1);
    expect(count('/acct/*')).toBeGreaterThan(preds.length * 0.05);
    expect(count('/docs/*')).toBeGreaterThan(preds.length * 0.05);
  });
});

describe('fresh arbActionContext', () => {
  it('params, subject and env are optional and drawn from their fixed domains', async () => {
    const { arbActionContext } = await fresh();
    const ctxs = draw(arbActionContext);
    for (const c of ctxs) {
      expect(Object.keys(c).every((k) => ['action', 'subject', 'env'].includes(k))).toBe(true);
      expect(Object.keys(c.action).every((k) => ['verb', 'resource', 'params'].includes(k))).toBe(true);
      if ('params' in c.action) {
        const p = c.action.params as Record<string, unknown>;
        expect(Object.keys(p).length).toBeLessThanOrEqual(3);
        for (const [k, v] of Object.entries(p)) {
          expect(['amount', 'reason', 'target']).toContain(k);
          if (typeof v === 'number') expect(isInt(v) && inRange(v, -5, 100)).toBe(true);
        }
      }
    }
    expect(sorted(ctxs.flatMap((c) => Object.keys((c.action.params as object | undefined) ?? {})))).toEqual(['amount', 'reason', 'target']);
    expect(ctxs.some((c) => !('params' in c.action))).toBe(true);
    expect(ctxs.some((c) => 'params' in c.action)).toBe(true);
    const nums = ctxs.flatMap((c) => Object.values((c.action.params as Record<string, unknown> | undefined) ?? {})).filter((v): v is number => typeof v === 'number');
    expect(nums.some((n) => n < 0)).toBe(true);
    expect(nums.some((n) => n > 5)).toBe(true);
    const withSubject = ctxs.filter((c) => c.subject !== undefined);
    const withEnv = ctxs.filter((c) => c.env !== undefined);
    expect(withSubject.length).toBeGreaterThan(100);
    expect(withSubject.length).toBeLessThan(ctxs.length - 100);
    expect(withEnv.length).toBeGreaterThan(100);
    expect(withEnv.length).toBeLessThan(ctxs.length - 100);
    for (const c of withSubject) {
      expect(Object.keys(c.subject!).sort()).toEqual(['role', 'tier']);
      expect(isInt(c.subject!.tier) && inRange(c.subject!.tier, 0, 5)).toBe(true);
    }
    expect(sorted(withSubject.map((c) => String(c.subject!.role)))).toEqual(['admin', 'guest', 'user']);
    expect(sorted(withSubject.map((c) => String(c.subject!.tier)))).toEqual(['0', '1', '2', '3', '4', '5']);
    for (const c of withEnv) {
      expect(Object.keys(c.env!)).toEqual(['ip']);
      expect(typeof c.env!.ip).toBe('string');
    }
  });
});

describe('fresh arbCaveatContext', () => {
  it('every field is within its domain and each optional field is both omitted and present', async () => {
    const { arbCaveatContext } = await fresh();
    const ctxs = draw(arbCaveatContext);
    for (const c of ctxs) {
      expect(isInt(c.now) && inRange(c.now, 0, 10_000_000)).toBe(true);
      expect(Object.keys(c).every((k) => ['now', 'blastRadius', 'reversibilityClass', 'delegationDepth', 'recentActionTimes'].includes(k))).toBe(true);
      if (c.blastRadius !== undefined) expect(inRange(c.blastRadius, 0, 1)).toBe(true);
      if (c.delegationDepth !== undefined) expect(isInt(c.delegationDepth) && inRange(c.delegationDepth, 0, 20)).toBe(true);
      if (c.recentActionTimes !== undefined) {
        expect(c.recentActionTimes.length).toBeLessThanOrEqual(6);
        for (const t of c.recentActionTimes) expect(isInt(t) && inRange(t, 0, 10_000_000)).toBe(true);
      }
    }
    for (const key of ['blastRadius', 'reversibilityClass', 'delegationDepth', 'recentActionTimes'] as const) {
      expect(ctxs.some((c) => !(key in c))).toBe(true);
      expect(ctxs.some((c) => key in c)).toBe(true);
      for (const c of ctxs) if (key in c) expect(c[key]).not.toBeUndefined();
    }
    expect(sorted(ctxs.flatMap((c) => (c.reversibilityClass === undefined ? [] : [c.reversibilityClass])))).toEqual(['irreversible', 'rate_limited', 'reversible', 'teleport']);
    expect(ctxs.some((c) => (c.recentActionTimes?.length ?? 0) === 6)).toBe(true);
  });

  it('never yields NaN', async () => {
    const { arbCaveatContext } = await fresh();
    for (const c of bigDraw(arbCaveatContext, 20000)) expect(Number.isNaN(c.blastRadius)).toBe(false);
  }, 120_000);
});

describe('fresh arbCaveatSpec', () => {
  it('draws all seven kinds, each parameter inside its domain', async () => {
    const { arbCaveatSpec } = await fresh();
    const specs = draw(arbCaveatSpec, 4000);
    expect(sorted(specs.map((s) => s.k))).toEqual(['budget_frac', 'delegation_depth', 'expires', 'max_blast_radius', 'not_before', 'rate', 'reversibility_max']);
    for (const s of specs) {
      switch (s.k) {
        case 'expires':
        case 'not_before':
          expect(isInt(s.at) && inRange(s.at, 0, 10_000_000)).toBe(true);
          break;
        case 'rate':
          expect(isInt(s.max) && inRange(s.max, 1, 10)).toBe(true);
          expect(isInt(s.per_secs) && inRange(s.per_secs, 1, 3600)).toBe(true);
          break;
        case 'max_blast_radius':
          expect(inRange(s.max, 0, 1)).toBe(true);
          expect(Math.abs(s.max * 1000 - Math.round(s.max * 1000))).toBeLessThan(1e-9);
          break;
        case 'reversibility_max':
          expect(['reversible', 'rate_limited', 'irreversible']).toContain(s.cls);
          break;
        case 'delegation_depth':
          expect(isInt(s.max) && inRange(s.max, 0, 20)).toBe(true);
          break;
        case 'budget_frac':
          expect(inRange(s.frac, 0, 1)).toBe(true);
      }
    }
    const of = (k: string) => specs.filter((s) => s.k === k);
    expect(Math.max(...of('rate').map((s) => (s as { per_secs: number }).per_secs))).toBeGreaterThan(10);
    expect(Math.max(...of('max_blast_radius').map((s) => (s as { max: number }).max))).toBeGreaterThan(0.5);
    expect(sorted(of('reversibility_max').map((s) => (s as { cls: string }).cls))).toEqual(['irreversible', 'rate_limited', 'reversible']);
    expect(Math.max(...of('delegation_depth').map((s) => (s as { max: number }).max))).toBeGreaterThan(5);
  });

  it('never yields NaN', async () => {
    const { arbCaveatSpec } = await fresh();
    for (const s of bigDraw(arbCaveatSpec, 40000)) if (s.k === 'budget_frac') expect(Number.isNaN(s.frac)).toBe(false);
  }, 120_000);
});

describe('fresh arbChain', () => {
  it('chains verify; the root carries 1..4 caveats, each hop adds at most 3, and there are at most 5 hops', async () => {
    const { arbChain } = await fresh();
    const chains = draw(arbChain, 400);
    let maxHops = 0;
    for (const g of chains) {
      expect(verifyChain(g.caps, g.rootIssuer).ok).toBe(true);
      expect(g.caps[0]!.caveats.length >= 1 && g.caps[0]!.caveats.length <= 4).toBe(true);
      expect(g.caps.length).toBeLessThanOrEqual(6);
      expect(g.holders.length).toBe(g.caps.length);
      maxHops = Math.max(maxHops, g.caps.length - 1);
      for (let i = 1; i < g.caps.length; i++) expect(g.caps[i]!.caveats.length - g.caps[i - 1]!.caveats.length).toBeLessThanOrEqual(3);
      expect(g.predicates.length >= 1 && g.predicates.length <= 4).toBe(true);
    }
    expect(maxHops).toBeGreaterThanOrEqual(3);
  }, 120_000);
});

describe('fresh risk arbitraries', () => {
  it('policies, inputs, deltas and trust budgets keep their keys and ranges', async () => {
    const { arbRiskPolicy, arbRiskInputs, arbRiskDeltas, arbTrustBudget } = await fresh();
    for (const p of draw(arbRiskPolicy)) {
      expect(Object.keys(p).sort()).toEqual(['bMax', 'kappa', 'lambda', 'rho', 'theta1', 'theta2', 'weights']);
      expect(inRange(p.theta1, 0, 1)).toBe(true);
      expect(p.theta2).toBeGreaterThanOrEqual(p.theta1);
      expect(p.theta2).toBeLessThanOrEqual(p.theta1 + 1);
      expect(inRange(p.kappa, 0.001, 5)).toBe(true);
      expect(inRange(p.lambda, 0, 0.01)).toBe(true);
      expect(inRange(p.rho, 0, 2)).toBe(true);
      expect(inRange(p.bMax, 0, 10)).toBe(true);
      expect(Object.keys(p.weights).sort()).toEqual(['alpha', 'beta', 'delta', 'epsilon', 'gamma', 'zeta']);
      for (const w of Object.values(p.weights)) expect(inRange(w, 0, 2)).toBe(true);
    }
    for (const i of draw(arbRiskInputs, 500)) {
      expect(Object.keys(i).sort()).toEqual(['age', 'blastRadius', 'confidence', 'reversibility', 'semanticDistance', 'taint']);
      for (const v of Object.values(i)) expect(inRange(v, 0, 1)).toBe(true);
    }
    for (const d of draw(arbRiskDeltas, 500)) {
      expect(Object.keys(d).sort()).toEqual(['dAge', 'dBlast', 'dConf', 'dRev', 'dSem', 'dTaint']);
      for (const v of Object.values(d)) expect(inRange(v, 0, 1)).toBe(true);
    }
    const bs = draw(arbTrustBudget);
    for (const b of bs) {
      expect(Object.keys(b).every((k) => ['B', 'tau', 'asOf'].includes(k))).toBe(true);
      expect(inRange(b.B, 0, 10)).toBe(true);
      expect(isInt(b.tau) && inRange(b.tau, 0, 10_000_000)).toBe(true);
      if ('asOf' in b) expect(isInt(b.asOf) && inRange(b.asOf, 0, 10_000_000)).toBe(true);
    }
    expect(bs.some((b) => !('asOf' in b))).toBe(true);
    expect(bs.some((b) => 'asOf' in b)).toBe(true);
  });

  it('never yield NaN', async () => {
    const { arbRiskPolicy, arbRiskInputs, arbRiskDeltas, arbTrustBudget } = await fresh();
    for (const p of bigDraw(arbRiskPolicy, 20000)) for (const v of [p.theta1, p.theta2, p.kappa, p.lambda, p.rho, p.bMax, ...Object.values(p.weights)]) expect(Number.isNaN(v)).toBe(false);
    for (const i of bigDraw(arbRiskInputs, 20000)) for (const v of Object.values(i)) expect(Number.isNaN(v)).toBe(false);
    for (const d of bigDraw(arbRiskDeltas, 20000)) for (const v of Object.values(d)) expect(Number.isNaN(v)).toBe(false);
    for (const b of bigDraw(arbTrustBudget, 20000)) expect(Number.isNaN(b.B)).toBe(false);
  }, 120_000);
});
