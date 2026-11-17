/**
 * Pins the shape, the value domains and the optional-key behaviour of every exported arbitrary, plus the deterministic
 * helpers (`buildChain`, `worsen`, `keyPairFromSeed`). A generator that silently widens a range, drops a literal or leaves a
 * key out would make the property checks vacuous, so each domain is asserted on a large fixed-seed sample.
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { validateRiskPolicy, verifyChain } from '@atlasauth/pca';
import {
  type CaveatSpec,
  arbActionContext,
  arbCaveatContext,
  arbCaveatSpec,
  arbChain,
  arbCondition,
  arbEvalPoint,
  arbKeyPair,
  arbLeafCondition,
  arbPredicate,
  arbPredicateList,
  arbRiskDeltas,
  arbRiskInputs,
  arbRiskPolicy,
  arbTrustBudget,
  buildChain,
  keyPairFromSeed,
  worsen,
} from './arbitraries';

const draw = <T>(arb: fc.Arbitrary<T>, n = 1500): T[] => fc.sample(arb, { numRuns: n, seed: 20261112 });
const sorted = (xs: Iterable<string>): string[] => [...new Set(xs)].sort();
const isInt = (x: unknown): x is number => typeof x === 'number' && Number.isInteger(x);
const inRange = (x: unknown, lo: number, hi: number): boolean => typeof x === 'number' && Number.isFinite(x) && x >= lo && x <= hi;
const VERBS = ['admin', 'delete', 'list', 'read', 'transfer', 'write'];
const LEAF_FIELDS = ['action.params.amount', 'action.resource', 'action.verb', 'env.ip', 'subject.role', 'subject.tier'];
const LEAF_OPS = ['eq', 'exists', 'gt', 'gte', 'in', 'lt', 'lte', 'ne', 'nin', 'prefix'];

describe('arbLeafCondition / arbCondition', () => {
  const leaves = draw(arbLeafCondition);

  it('has exactly the keys field/op/value, with a field and operator from the fixed vocabularies', () => {
    for (const l of leaves) expect(Object.keys(l).sort()).toEqual(['field', 'op', 'value']);
    expect(sorted(leaves.map((l) => l.field))).toEqual(LEAF_FIELDS);
    expect(sorted(leaves.map((l) => l.op))).toEqual(LEAF_OPS);
  });

  it('draws values of four kinds; numbers are integers in [-10, 10] and negatives occur; string arrays have at most 3 items', () => {
    const nums = leaves.map((l) => l.value).filter((v): v is number => typeof v === 'number');
    expect(nums.length).toBeGreaterThan(50);
    for (const n of nums) {
      expect(isInt(n)).toBe(true);
      expect(n).toBeGreaterThanOrEqual(-10);
      expect(n).toBeLessThanOrEqual(10);
    }
    expect(nums.some((n) => n < 0)).toBe(true);
    expect(nums.some((n) => n > 0)).toBe(true);
    expect(leaves.some((l) => typeof l.value === 'string')).toBe(true);
    expect(leaves.some((l) => typeof l.value === 'boolean')).toBe(true);
    const arrs = leaves.map((l) => l.value).filter((v): v is string[] => Array.isArray(v));
    expect(arrs.length).toBeGreaterThan(50);
    for (const a of arrs) {
      expect(a.length).toBeLessThanOrEqual(3);
      for (const s of a) expect(typeof s).toBe('string');
    }
    expect(arrs.some((a) => a.length === 3)).toBe(true);
  });

  it('arbCondition is the leaf arbitrary', () => {
    for (const c of draw(arbCondition, 200)) expect(Object.keys(c).sort()).toEqual(['field', 'op', 'value']);
  });
});

describe('arbPredicate / arbPredicateList', () => {
  const preds = draw(arbPredicate);

  it('verbs are one of the vocabulary, a 1..3 list of them, or the wildcard; the wildcard is a frequent draw', () => {
    let star = 0;
    for (const p of preds) {
      if (Array.isArray(p.verb)) {
        expect(p.verb.length).toBeGreaterThanOrEqual(1);
        expect(p.verb.length).toBeLessThanOrEqual(3);
        for (const v of p.verb) expect(VERBS).toContain(v);
      } else if (p.verb === '*') star++;
      else expect(VERBS).toContain(p.verb);
    }
    expect(star).toBeGreaterThan(preds.length * 0.2);
    expect(preds.some((p) => Array.isArray(p.verb) && p.verb.length === 3)).toBe(true);
  });

  it('resource and where are omitted (never present-but-undefined) or well-typed; the literal resources are frequent draws', () => {
    for (const p of preds) {
      expect(Object.keys(p).every((k) => ['verb', 'resource', 'where'].includes(k))).toBe(true);
      if ('resource' in p) expect(typeof p.resource).toBe('string');
      if ('where' in p) {
        expect(Array.isArray(p.where)).toBe(true);
        expect(p.where!.length).toBeLessThanOrEqual(2);
      }
    }
    expect(preds.some((p) => !('resource' in p))).toBe(true);
    expect(preds.some((p) => 'resource' in p)).toBe(true);
    expect(preds.some((p) => !('where' in p))).toBe(true);
    expect(preds.some((p) => 'where' in p)).toBe(true);
    expect(preds.some((p) => p.where?.length === 2)).toBe(true);
    const count = (r: string): number => preds.filter((p) => p.resource === r).length;
    expect(count('*')).toBeGreaterThan(preds.length * 0.1);
    expect(count('/acct/*')).toBeGreaterThan(preds.length * 0.05);
    expect(count('/docs/*')).toBeGreaterThan(preds.length * 0.05);
  });

  it('a predicate list has 1..4 entries', () => {
    const lens = draw(arbPredicateList).map((l) => l.length);
    expect(Math.min(...lens)).toBe(1);
    expect(Math.max(...lens)).toBe(4);
  });
});

describe('arbActionContext', () => {
  const ctxs = draw(arbActionContext);

  it('always carries a vocabulary verb and a string resource; params keys/values stay in the fixed domain', () => {
    for (const c of ctxs) {
      expect(Object.keys(c).every((k) => ['action', 'subject', 'env'].includes(k))).toBe(true);
      expect(VERBS).toContain(c.action.verb);
      expect(typeof c.action.resource).toBe('string');
      expect(Object.keys(c.action).every((k) => ['verb', 'resource', 'params'].includes(k))).toBe(true);
      if ('params' in c.action) {
        const p = c.action.params as Record<string, unknown>;
        expect(Object.keys(p).length).toBeLessThanOrEqual(3);
        for (const [k, v] of Object.entries(p)) {
          expect(['amount', 'reason', 'target']).toContain(k);
          expect(['string', 'number', 'boolean']).toContain(typeof v);
          if (typeof v === 'number') {
            expect(isInt(v)).toBe(true);
            expect(v).toBeGreaterThanOrEqual(-5);
            expect(v).toBeLessThanOrEqual(100);
          }
        }
      }
    }
    expect(sorted(ctxs.flatMap((c) => Object.keys((c.action.params as object | undefined) ?? {})))).toEqual(['amount', 'reason', 'target']);
    expect(ctxs.some((c) => !('params' in c.action))).toBe(true);
    expect(ctxs.some((c) => 'params' in c.action)).toBe(true);
    const nums = ctxs.flatMap((c) => Object.values((c.action.params as Record<string, unknown> | undefined) ?? {})).filter((v): v is number => typeof v === 'number');
    expect(nums.some((n) => n < 0)).toBe(true);
    expect(nums.some((n) => n > 5)).toBe(true);
  });

  it('subject {role, tier} and env {ip} are each present in some draws and absent in others', () => {
    const withSubject = ctxs.filter((c) => c.subject !== undefined);
    const withEnv = ctxs.filter((c) => c.env !== undefined);
    expect(withSubject.length).toBeGreaterThan(100);
    expect(withSubject.length).toBeLessThan(ctxs.length - 100);
    expect(withEnv.length).toBeGreaterThan(100);
    expect(withEnv.length).toBeLessThan(ctxs.length - 100);
    for (const c of withSubject) {
      expect(Object.keys(c.subject!).sort()).toEqual(['role', 'tier']);
      expect(isInt(c.subject!.tier)).toBe(true);
      expect(inRange(c.subject!.tier, 0, 5)).toBe(true);
    }
    expect(sorted(withSubject.map((c) => String(c.subject!.role)))).toEqual(['admin', 'guest', 'user']);
    expect(sorted(withSubject.map((c) => String(c.subject!.tier)))).toEqual(['0', '1', '2', '3', '4', '5']);
    for (const c of withEnv) {
      expect(Object.keys(c.env!)).toEqual(['ip']);
      expect(typeof c.env!.ip).toBe('string');
    }
  });
});

describe('arbCaveatContext', () => {
  const ctxs = draw(arbCaveatContext);

  it('now is an integer in [0, 10_000_000] on every draw', () => {
    for (const c of ctxs) {
      expect(isInt(c.now)).toBe(true);
      expect(inRange(c.now, 0, 10_000_000)).toBe(true);
      expect(Object.keys(c).every((k) => ['now', 'blastRadius', 'reversibilityClass', 'delegationDepth', 'recentActionTimes'].includes(k))).toBe(true);
    }
  });

  it('each optional field is omitted in some draws and, when present, defined and in its domain', () => {
    for (const key of ['blastRadius', 'reversibilityClass', 'delegationDepth', 'recentActionTimes'] as const) {
      expect(ctxs.some((c) => !(key in c))).toBe(true);
      expect(ctxs.some((c) => key in c)).toBe(true);
      for (const c of ctxs) if (key in c) expect(c[key]).not.toBeUndefined();
    }
    for (const c of ctxs) {
      if (c.blastRadius !== undefined) {
        expect(Number.isNaN(c.blastRadius)).toBe(false);
        expect(inRange(c.blastRadius, 0, 1)).toBe(true);
      }
      if (c.delegationDepth !== undefined) {
        expect(isInt(c.delegationDepth)).toBe(true);
        expect(inRange(c.delegationDepth, 0, 20)).toBe(true);
      }
      if (c.recentActionTimes !== undefined) {
        expect(c.recentActionTimes.length).toBeLessThanOrEqual(6);
        for (const t of c.recentActionTimes) {
          expect(isInt(t)).toBe(true);
          expect(inRange(t, 0, 10_000_000)).toBe(true);
        }
      }
    }
    expect(sorted(ctxs.flatMap((c) => (c.reversibilityClass === undefined ? [] : [c.reversibilityClass])))).toEqual(['irreversible', 'rate_limited', 'reversible', 'teleport']);
    expect(ctxs.some((c) => c.recentActionTimes?.length === 6)).toBe(true);
  });

  it('an eval point pairs an action context with a caveat context', () => {
    for (const p of draw(arbEvalPoint, 100)) {
      expect(Object.keys(p).sort()).toEqual(['action', 'cavCtx']);
      expect(p.action.action).toBeDefined();
      expect(isInt(p.cavCtx.now)).toBe(true);
    }
  });
});

describe('arbCaveatSpec', () => {
  const specs = draw(arbCaveatSpec);
  const of = <K extends CaveatSpec['k']>(k: K): Extract<CaveatSpec, { k: K }>[] => specs.filter((s): s is Extract<CaveatSpec, { k: K }> => s.k === k);

  it('draws all seven kinds', () => {
    expect(sorted(specs.map((s) => s.k))).toEqual(['budget_frac', 'delegation_depth', 'expires', 'max_blast_radius', 'not_before', 'rate', 'reversibility_max']);
  });

  it('keeps every parameter inside its domain', () => {
    for (const s of of('expires')) expect(inRange(s.at, 0, 10_000_000) && isInt(s.at)).toBe(true);
    for (const s of of('not_before')) expect(inRange(s.at, 0, 10_000_000) && isInt(s.at)).toBe(true);
    for (const s of of('rate')) {
      expect(inRange(s.max, 1, 10) && isInt(s.max)).toBe(true);
      expect(inRange(s.per_secs, 1, 3600) && isInt(s.per_secs)).toBe(true);
    }
    for (const s of of('max_blast_radius')) {
      expect(inRange(s.max, 0, 1)).toBe(true);
      expect(Math.round(s.max * 1000) / 1000).toBe(s.max);
    }
    expect(sorted(of('reversibility_max').map((s) => s.cls))).toEqual(['irreversible', 'rate_limited', 'reversible']);
    for (const s of of('delegation_depth')) expect(inRange(s.max, 0, 20) && isInt(s.max)).toBe(true);
    for (const s of of('budget_frac')) {
      expect(Number.isNaN(s.frac)).toBe(false);
      expect(inRange(s.frac, 0, 1)).toBe(true);
    }
    expect(of('max_blast_radius').some((s) => s.max > 0 && s.max < 1)).toBe(true);
  });
});

describe('buildChain', () => {
  const seed = (n: number): Uint8Array => new Uint8Array(32).fill(n);

  it('materialises every spec kind into its exact caveat, with a monotone floor-based allocation chain', () => {
    const g = buildChain({
      principalSeed: seed(1),
      holder0Seed: seed(2),
      rootSpecs: [
        { k: 'expires', at: 500 },
        { k: 'not_before', at: 7 },
        { k: 'rate', max: 3, per_secs: 60 },
        { k: 'max_blast_radius', max: 0.25 },
        { k: 'reversibility_max', cls: 'irreversible' },
        { k: 'delegation_depth', max: 2 },
        { k: 'budget_frac', frac: 0.5 },
      ],
      hops: [
        { holderSeed: seed(3), addedSpecs: [{ k: 'budget_frac', frac: 0.5 }] },
        { holderSeed: seed(4), addedSpecs: [{ k: 'budget_frac', frac: 1 }, { k: 'budget_frac', frac: 0.25 }] },
      ],
      predicates: [{ verb: 'read' }],
    });
    expect(g.caps).toHaveLength(3);
    expect(g.caps[0]!.caveats).toStrictEqual([
      { type: 'expires', at: 500 },
      { type: 'not_before', at: 7 },
      { type: 'rate', max: 3, per_secs: 60 },
      { type: 'max_blast_radius', max: 0.25 },
      { type: 'reversibility_max', class: 'irreversible' },
      { type: 'delegation_depth', max: 2 },
      { type: 'budget_alloc', limit: 500_000 },
    ]);
    expect(g.caps[1]!.caveats.slice(7)).toStrictEqual([{ type: 'budget_alloc', limit: 250_000 }]);
    expect(g.caps[2]!.caveats.slice(8)).toStrictEqual([
      { type: 'budget_alloc', limit: 250_000 },
      { type: 'budget_alloc', limit: 62_500 },
    ]);
    expect(verifyChain(g.caps, g.rootIssuer).ok).toBe(true);
    expect(g.predicates).toEqual([{ verb: 'read' }]);
  });

  it('starts the allocation chain at one million when the first budget_frac is below the root', () => {
    const g = buildChain({ principalSeed: seed(1), holder0Seed: seed(2), rootSpecs: [{ k: 'budget_frac', frac: 0.25 }], hops: [], predicates: [{ verb: '*' }] });
    expect(g.caps[0]!.caveats).toStrictEqual([{ type: 'budget_alloc', limit: 250_000 }]);
  });

  it('reports the root principal and the holder key at every hop, root holder first', () => {
    const g = buildChain({
      principalSeed: seed(1),
      holder0Seed: seed(2),
      rootSpecs: [{ k: 'expires', at: 9 }],
      hops: [
        { holderSeed: seed(3), addedSpecs: [] },
        { holderSeed: seed(4), addedSpecs: [] },
      ],
      predicates: [{ verb: '*' }],
    });
    expect(g.rootIssuer).toBe(keyPairFromSeed(seed(1)).pub);
    expect(g.holders).toEqual([keyPairFromSeed(seed(2)).pub, keyPairFromSeed(seed(3)).pub, keyPairFromSeed(seed(4)).pub]);
    expect(g.caps.map((c) => c.holder)).toEqual(g.holders);
    expect(g.caps[0]!.issuer).toBe(g.rootIssuer);
  });

  it('keyPairFromSeed uses the seed as the secret and exposes the b64u public key', () => {
    const kp = keyPairFromSeed(seed(5));
    expect(Array.from(kp.secretKey)).toEqual(Array.from(seed(5)));
    expect(kp.publicKey).toHaveLength(32);
    expect(kp.pub).toBe(keyPairFromSeed(seed(5)).pub);
    expect(kp.pub).not.toBe(keyPairFromSeed(seed(6)).pub);
    for (const k of draw(arbKeyPair, 5)) {
      expect(k.secretKey).toHaveLength(32);
      expect(k.pub).toBe(keyPairFromSeed(k.secretKey).pub);
    }
  });
});

describe('arbChain', () => {
  const chains = draw(arbChain, 120);

  it('every drawn chain verifies and has a bounded shape', () => {
    for (const g of chains) {
      expect(verifyChain(g.caps, g.rootIssuer).ok).toBe(true);
      expect(g.caps.length).toBeGreaterThanOrEqual(1);
      expect(g.caps.length).toBeLessThanOrEqual(6);
      expect(g.holders).toHaveLength(g.caps.length);
      expect(g.predicates.length).toBeGreaterThanOrEqual(1);
      expect(g.predicates.length).toBeLessThanOrEqual(4);
      const root = g.caps[0]!.caveats.length;
      expect(root).toBeGreaterThanOrEqual(1);
      expect(root).toBeLessThanOrEqual(4);
      for (let i = 1; i < g.caps.length; i++) {
        const added = g.caps[i]!.caveats.length - g.caps[i - 1]!.caveats.length;
        expect(added).toBeGreaterThanOrEqual(0);
        expect(added).toBeLessThanOrEqual(3);
      }
    }
    expect(chains.some((g) => g.caps.length === 1)).toBe(true);
    expect(chains.some((g) => g.caps.length === 6)).toBe(true);
  });
});

describe('risk arbitraries', () => {
  it('policies are well formed, with every parameter inside its documented range', () => {
    for (const p of draw(arbRiskPolicy)) {
      expect(validateRiskPolicy(p)).toBeNull();
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
  });

  it('inputs and deltas carry six finite unit-interval axes', () => {
    for (const i of draw(arbRiskInputs, 500)) {
      expect(Object.keys(i).sort()).toEqual(['age', 'blastRadius', 'confidence', 'reversibility', 'semanticDistance', 'taint']);
      for (const v of Object.values(i)) expect(inRange(v, 0, 1)).toBe(true);
    }
    for (const d of draw(arbRiskDeltas, 500)) {
      expect(Object.keys(d).sort()).toEqual(['dAge', 'dBlast', 'dConf', 'dRev', 'dSem', 'dTaint']);
      for (const v of Object.values(d)) expect(inRange(v, 0, 1)).toBe(true);
    }
  });

  it('trust budgets have finite B in [0, 10], an integer tau, and an asOf that is either omitted or an integer', () => {
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
});

describe('worsen', () => {
  const base = { semanticDistance: 0.3, reversibility: 0.6, blastRadius: 0.4, taint: 0.2, confidence: 0.7, age: 0.1 };

  it('raises the risk-increasing axes and lowers the protective ones by exactly the delta', () => {
    const w = worsen(base, { dSem: 0.2, dBlast: 0.1, dTaint: 0.3, dAge: 0.25, dRev: 0.5, dConf: 0.4 });
    expect(w.semanticDistance).toBeCloseTo(0.5, 12);
    expect(w.blastRadius).toBeCloseTo(0.5, 12);
    expect(w.taint).toBeCloseTo(0.5, 12);
    expect(w.age).toBeCloseTo(0.35, 12);
    expect(w.reversibility).toBeCloseTo(0.1, 12);
    expect(w.confidence).toBeCloseTo(0.3, 12);
    expect(Object.keys(w).sort()).toEqual(['age', 'blastRadius', 'confidence', 'reversibility', 'semanticDistance', 'taint']);
  });

  it('clamps every axis to [0, 1]', () => {
    const hi = worsen(
      { semanticDistance: 0.9, reversibility: 0.1, blastRadius: 0.9, taint: 0.9, confidence: 0.1, age: 0.9 },
      { dSem: 0.5, dBlast: 0.5, dTaint: 0.5, dAge: 0.5, dRev: 0.5, dConf: 0.5 },
    );
    expect(hi).toEqual({ semanticDistance: 1, blastRadius: 1, taint: 1, age: 1, reversibility: 0, confidence: 0 });
  });

  it('does not alter an in-range value and leaves a negative zero untouched', () => {
    const same = worsen(base, { dSem: 0, dBlast: 0, dTaint: 0, dAge: 0, dRev: 0, dConf: 0 });
    expect(same).toEqual(base);
    const nz = worsen({ ...base, reversibility: -0 }, { dSem: 0, dBlast: 0, dTaint: 0, dAge: 0, dRev: 0, dConf: 0 });
    expect(Object.is(nz.reversibility, -0)).toBe(true);
    expect(worsen({ ...base, semanticDistance: 1 }, { dSem: 0, dBlast: 0, dTaint: 0, dAge: 0, dRev: 0, dConf: 0 }).semanticDistance).toBe(1);
  });
});

describe('no arbitrary ever yields NaN', () => {
  // fast-check places NaN one index above the finite maximum unless `noNaN` is set, so NaN only shows up in a large sample.
  const bigDraw = <T>(arb: fc.Arbitrary<T>, n: number): T[] => fc.sample(arb, { numRuns: n, seed: 7771 });

  it('caveat contexts, caveat specs, risk policies, inputs, deltas and budgets are NaN-free', () => {
    for (const c of bigDraw(arbCaveatContext, 20000)) expect(Number.isNaN(c.blastRadius)).toBe(false);
    for (const s of bigDraw(arbCaveatSpec, 40000)) if (s.k === 'budget_frac') expect(Number.isNaN(s.frac)).toBe(false);
    for (const p of bigDraw(arbRiskPolicy, 20000)) {
      for (const v of [p.theta1, p.theta2, p.kappa, p.lambda, p.rho, p.bMax]) expect(Number.isNaN(v)).toBe(false);
    }
    for (const i of bigDraw(arbRiskInputs, 20000)) for (const v of Object.values(i)) expect(Number.isNaN(v)).toBe(false);
    for (const d of bigDraw(arbRiskDeltas, 20000)) for (const v of Object.values(d)) expect(Number.isNaN(v)).toBe(false);
    for (const b of bigDraw(arbTrustBudget, 20000)) expect(Number.isNaN(b.B)).toBe(false);
  });
});
