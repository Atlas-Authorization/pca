/** r14 static-mutant kills for risk.ts (fresh module): the unit / wt helpers inside riskScore and the plan-reference keys of planGeodesic. */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  return import('./risk');
}
const N = (id: string, extra: Record<string, unknown> = {}) => ({ id, verb: 'v', resource: 'r', reversibility_class: 'reversible', params_digest: 'p', ...extra }) as never;

describe('risk.ts helpers (fresh module)', () => {
  it('riskScore clamps inputs and drops bad weights', async () => {
    const m = await fresh();
    const w = { alpha: 0.5, beta: 0.25, gamma: -1, delta: NaN, epsilon: 0, zeta: 0 };
    expect(m.riskScore({ semanticDistance: 2, reversibility: 0.5, blastRadius: 1, taint: 1, confidence: 1, age: 0 }, w)).toBe(0.5 + 0.25 * 0.5);
    expect(m.riskScore({ semanticDistance: NaN, reversibility: NaN, blastRadius: 0, taint: 0, confidence: 1, age: 0 }, w)).toBe(0.5 + 0.25);
  });
  it('every pre / post reference key builds an edge', async () => {
    const m = await fresh();
    // with an edge a-c, the distance a..c is 1/3 (BFS); without it the index fallback gives 2/3
    const keys: [string, string][] = [['pre', 'after'], ['pre', 'depends_on'], ['pre', 'requires'], ['pre', 'nodes'], ['post', 'before'], ['post', 'enables'], ['post', 'then'], ['post', 'next']];
    const got = keys.map(([side, k]) => {
      const plan = side === 'pre' ? [N('a'), N('b'), N('c', { pre: { [k]: 'a' } }), N('d')] : [N('a', { post: { [k]: 'c' } }), N('b'), N('c'), N('d')];
      return [k, m.planGeodesic(plan, 'a', 'c')];
    });
    expect(got).toEqual(keys.map(([, k]) => [k, 1 / 3]));
  });
});
