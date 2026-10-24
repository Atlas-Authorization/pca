/**
 * r13 mutation kills for risk.ts: validateRiskPolicy (every member, every bound, exact messages), clamping and weight
 * sanitising (negative / non-finite / signed-zero inputs; toBe is Object.is, so the sign of a zero result is part of
 * the outcome), escalateThreshold proof floors, leak / ageSinceTouch on non-finite times, subBudget asOf, and the
 * planGeodesic edge builder (references, self-links, unknown ids, malformed pre/post).
 */
import { describe, expect, it } from 'vitest';
import {
  ageSinceTouch,
  cost,
  DEFAULT_RISK_POLICY,
  escalateThreshold,
  leak,
  planGeodesic,
  riskScore,
  subBudget,
  validateRiskPolicy,
} from './risk';
import type { PlanNode } from './merkle';

const P = DEFAULT_RISK_POLICY;
const pol = (over: Record<string, unknown>) => ({ ...P, ...over });

describe('validateRiskPolicy', () => {
  it('accepts the default and zero bounds', () => {
    expect(validateRiskPolicy(P)).toBeNull();
    expect(validateRiskPolicy(pol({ theta1: 0, lambda: 0, rho: 0, bMax: 0 }))).toBeNull();
  });
  it('refuses with the exact reason', () => {
    expect(validateRiskPolicy(null)).toBe('risk_policy must be an object');
    expect(validateRiskPolicy(5)).toBe('risk_policy must be an object');
    expect(validateRiskPolicy('p')).toBe('risk_policy must be an object');
    expect(validateRiskPolicy(pol({ weights: undefined }))).toBe('risk_policy.weights missing');
    expect(validateRiskPolicy(pol({ weights: 5 }))).toBe('risk_policy.weights missing');
    expect(validateRiskPolicy(pol({ weights: 'w' }))).toBe('risk_policy.weights missing');
    for (const k of ['theta1', 'theta2', 'kappa', 'lambda', 'rho', 'bMax']) {
      expect(validateRiskPolicy(pol({ [k]: NaN }))).toBe(`risk_policy.${k} must be finite`);
      expect(validateRiskPolicy(pol({ [k]: undefined }))).toBe(`risk_policy.${k} must be finite`);
    }
    expect(validateRiskPolicy(pol({ theta1: -0.1 }))).toBe('risk_policy requires 0 <= theta1 <= theta2');
    expect(validateRiskPolicy(pol({ theta1: 0.7, theta2: 0.6 }))).toBe('risk_policy requires 0 <= theta1 <= theta2');
    const LRB = 'risk_policy lambda/rho/bMax must be >= 0';
    expect(validateRiskPolicy(pol({ lambda: -1 }))).toBe(LRB);
    expect(validateRiskPolicy(pol({ rho: -1 }))).toBe(LRB);
    expect(validateRiskPolicy(pol({ bMax: -1 }))).toBe(LRB);
  });
});

describe('clamping and weights', () => {
  it('cost clamps r into [0,1] and drops a non-positive kappa', () => {
    expect(cost(-0.5, 1)).toBe(0);
    expect(cost(0.5, -1)).toBe(0);
    expect(cost(0.5, -0)).toBe(0); // signed zero: a -0 kappa is dropped to +0
    expect(cost(0.5, NaN)).toBe(0);
    expect(cost(0.5, Infinity)).toBe(0);
    expect(cost(0.5, 2)).toBe(1);
    expect(cost(2, 1)).toBe(1);
    expect(Object.is(cost(-0, 1), -0)).toBe(true); // clamp01 passes -0 through unchanged
  });
  it('riskScore drops negative, non-finite and -0 weights', () => {
    const i = { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 };
    const z = { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 };
    expect(riskScore(i, { ...z, alpha: -1, beta: 0.3 })).toBe(0.3);
    expect(riskScore(i, { ...z, alpha: NaN, beta: 0.3 })).toBe(0.3);
    expect(riskScore(i, { ...z, alpha: Infinity, beta: 0.3 })).toBe(0.3);
    expect(riskScore(i, { ...z, alpha: -Infinity, beta: 0.3 })).toBe(0.3);
    expect(riskScore(i, { alpha: -0, beta: -0, gamma: -0, delta: -0, epsilon: -0, zeta: -0 })).toBe(0);
  });
});

describe('escalateThreshold', () => {
  it('keeps a stronger proof than the floor', () => {
    expect(escalateThreshold({ t: 1, proof: 'strong', optimisticAllowed: true }, 2)).toEqual({ t: 2, proof: 'strong', optimisticAllowed: false });
    expect(escalateThreshold({ t: 1, proof: 'claim', optimisticAllowed: true }, 2)).toEqual({ t: 2, proof: 'standard', optimisticAllowed: false });
    expect(escalateThreshold({ t: 2, proof: 'standard', optimisticAllowed: false }, 2)).toEqual({ t: 2, proof: 'standard', optimisticAllowed: false });
  });
});

describe('leak / ageSinceTouch / subBudget', () => {
  it('leak never leaks when either time is non-finite, and drops a bad lambda', () => {
    expect(leak({ B: 1, tau: NaN }, 1000, 1)).toEqual({ B: 1, tau: NaN, asOf: NaN });
    expect(leak({ B: 1, tau: 0 }, NaN, 1)).toEqual({ B: 1, tau: 0, asOf: 0 });
    expect(leak({ B: 0.5, tau: 0 }, 1000, -1)).toEqual({ B: 0.5, tau: 0, asOf: 1000 });
    expect(leak({ B: 0.5, tau: 0 }, 1000, Infinity)).toEqual({ B: 0.5, tau: 0, asOf: 1000 });
    expect(leak({ B: 0.5, tau: 0 }, 1000, 0.1)).toEqual({ B: 0.4, tau: 0, asOf: 1000 });
  });
  it('ageSinceTouch is 1 for non-finite times or a non-positive horizon', () => {
    expect(ageSinceTouch({ B: 1, tau: 0 }, NaN)).toBe(1);
    expect(ageSinceTouch({ B: 1, tau: NaN }, 5)).toBe(1);
    expect(ageSinceTouch({ B: 1, tau: 5 }, 5, 0)).toBe(1);
    expect(ageSinceTouch({ B: 1, tau: 10 }, 5, 0)).toBe(1);
    expect(ageSinceTouch({ B: 1, tau: 10 }, 5, -5)).toBe(1);
    expect(ageSinceTouch({ B: 1, tau: 0 }, 5, -5)).toBe(1);
    expect(ageSinceTouch({ B: 1, tau: 0 }, 5, 10)).toBe(0.5);
  });
  it('subBudget carries the parent asOf, else its tau', () => {
    expect(subBudget({ B: 1, tau: 3, asOf: 5 }, 0.5)).toEqual({ ok: true, sub: { B: 0.5, tau: 3, asOf: 5 } });
    expect(subBudget({ B: 1, tau: 3 }, 0.5)).toEqual({ ok: true, sub: { B: 0.5, tau: 3, asOf: 3 } });
  });
});

describe('planGeodesic', () => {
  const N = (id: string, extra: Record<string, unknown> = {}) => ({ id, verb: 'v', resource: 'r', reversibility_class: 'reversible', params_digest: 'p', ...extra }) as unknown as PlanNode;
  it('unknown ids are 1, the same id is 0', () => {
    const plan = [N('a'), N('b')];
    expect(planGeodesic(plan, 'nope', 'b')).toBe(1);
    expect(planGeodesic(plan, 'a', 'nope')).toBe(1);
    expect(planGeodesic(plan, 'a', 'a')).toBe(0);
  });
  it('no edges: index distance', () => {
    expect(planGeodesic([N('a'), N('b'), N('c'), N('d'), N('e')], 'a', 'c')).toBe(0.5);
  });
  it('self references and unknown references add no edge (index fallback)', () => {
    const plan = [N('a', { pre: 'a', post: { next: ['a', 'zz'] } }), N('b', { pre: ['zz', 7] }), N('c'), N('d'), N('e', { post: 'e' })];
    expect(planGeodesic(plan, 'a', 'c')).toBe(0.5);
  });
  it('edges from pre and post (bare, arrays and keyed) give BFS distance over the undirected graph', () => {
    // chain a - e - b (edges), c and d isolated: index distance a..b would be 0.25, BFS is 2/4
    const plan = [N('a'), N('b', { pre: { after: 'e' } }), N('c'), N('d'), N('e', { pre: ['a'] })];
    expect(planGeodesic(plan, 'a', 'b')).toBe(0.5);
    expect(planGeodesic(plan, 'b', 'a')).toBe(0.5);
    expect(planGeodesic(plan, 'a', 'c')).toBe(1); // unreachable once any edge exists
    const plan2 = [N('a', { post: { then: ['e'] } }), N('b'), N('c'), N('d'), N('e', { post: 'b' })];
    expect(planGeodesic(plan2, 'a', 'b')).toBe(0.5);
    const plan3 = [N('a', { pre: { depends_on: ['e', 5] } }), N('b', { pre: { requires: 'e' } }), N('c'), N('d'), N('e')];
    expect(planGeodesic(plan3, 'a', 'b')).toBe(0.5);
  });
  it('a duplicate edge is still one edge', () => {
    const plan = [N('a', { post: ['b'] }), N('b', { pre: 'a' }), N('c')];
    expect(planGeodesic(plan, 'a', 'b')).toBe(0.5);
    expect(planGeodesic(plan, 'a', 'c')).toBe(1);
  });
  it('a null or non-object pre/post is ignored, not dereferenced', () => {
    const plan = [N('a', { pre: null, post: 5 }), N('b', { pre: true }), N('c')];
    expect(planGeodesic(plan, 'a', 'c')).toBe(1);
  });
  it('only string references count (a non-string id never links), and no implicit reference exists', () => {
    const plan = [N('a', { pre: [7] }), N('b'), N(7 as unknown as string)];
    expect(planGeodesic(plan, 'a', 'b')).toBe(0.5);
    const plan2 = [N('a'), N('b'), N('Stryker was here')];
    expect(planGeodesic(plan2, 'a', 'b')).toBe(0.5);
  });
  it('a non-array plan is 1', () => {
    expect(planGeodesic(null as never, 'a', 'b')).toBe(1);
  });
});
