import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY as P,
  admit,
  ageSinceTouch,
  cost,
  debit,
  debitConsolidated,
  debitConsolidatedPath,
  leak,
  planGeodesic,
  recharge,
  rechargeFull,
  requiredThreshold,
  riskScore,
  safetyBound,
  subBudget,
  validateRiskPolicy,
  type RiskInputs,
  type TrustBudget,
} from './risk';
import type { PlanNode } from './merkle';

const calm: RiskInputs = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const w = P.weights;

describe('riskScore', () => {
  it('0 for calm, 1 (clamped) for worst, weights sum to 1 by default', () => {
    expect(riskScore(calm, w)).toBe(0);
    const worst: RiskInputs = { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 };
    expect(riskScore(worst, w)).toBeCloseTo(1, 10);
    expect(riskScore(worst, { alpha: 5, beta: 5, gamma: 5, delta: 5, epsilon: 5, zeta: 5 })).toBe(1);
  });
  it('monotone in every input', () => {
    const inc = ['semanticDistance', 'blastRadius', 'taint', 'age'] as const;
    const dec = ['reversibility', 'confidence'] as const;
    for (const k of inc) {
      let prev = -1;
      for (const v of [0, 0.2, 0.5, 0.9, 1]) {
        const r = riskScore({ ...calm, [k]: v }, w);
        expect(r).toBeGreaterThanOrEqual(prev);
        prev = r;
      }
      expect(riskScore({ ...calm, [k]: 1 }, w)).toBeGreaterThan(0);
    }
    for (const k of dec) {
      let prev = 2;
      for (const v of [0, 0.2, 0.5, 0.9, 1]) {
        const r = riskScore({ ...calm, [k]: v }, w);
        expect(r).toBeLessThanOrEqual(prev);
        prev = r;
      }
    }
  });
  it('out-of-range clamps; NaN fails closed; negative weights ignored', () => {
    expect(riskScore({ ...calm, taint: 7 }, w)).toBe(riskScore({ ...calm, taint: 1 }, w));
    expect(riskScore({ ...calm, taint: NaN }, w)).toBe(riskScore({ ...calm, taint: 1 }, w));
    expect(riskScore({ ...calm, confidence: NaN }, w)).toBe(riskScore({ ...calm, confidence: 0 }, w));
    expect(riskScore({ ...calm, taint: 1 }, { ...w, delta: -3 })).toBe(0);
  });
});

describe('requiredThreshold', () => {
  const p = { theta1: 0.25, theta2: 0.6 };
  it('boundaries are inclusive on the lower tier', () => {
    expect(requiredThreshold(0, p)).toEqual({ t: 1, proof: 'claim', optimisticAllowed: true });
    expect(requiredThreshold(0.25, p).t).toBe(1);
    expect(requiredThreshold(0.2501, p)).toEqual({ t: 2, proof: 'standard', optimisticAllowed: false });
    expect(requiredThreshold(0.6, p).t).toBe(2);
    expect(requiredThreshold(0.6001, p)).toEqual({ t: 3, proof: 'strong', optimisticAllowed: false });
    expect(requiredThreshold(NaN, p).t).toBe(3);
  });
  it('irreversible never optimistic; t monotone in r', () => {
    expect(requiredThreshold(0.1, p, { irreversible: true }).optimisticAllowed).toBe(false);
    let prev = 0;
    for (let i = 0; i <= 100; i++) {
      const t = requiredThreshold(i / 100, p).t;
      expect(t).toBeGreaterThanOrEqual(prev);
      prev = t;
    }
  });
});

describe('trust budget', () => {
  const b0: TrustBudget = { B: 1, tau: 0 };
  it('cost, debit, leak', () => {
    expect(cost(0.2, 2)).toBeCloseTo(0.4);
    expect(debit(b0, 0.3).B).toBeCloseTo(0.7);
    expect(debit(b0, 5).B).toBe(0);
    const l = leak(b0, 1000_000, 0.0005); // 1000s * 0.0005 = 0.5
    expect(l.B).toBeCloseTo(0.5);
    expect(leak(l, 1000_000, 0.0005).B).toBeCloseTo(0.5); // idempotent at same now
    expect(leak(l, 2000_000, 0.0005).B).toBeCloseTo(0); // 0.5 - 0.5
    expect(leak(b0, -5, 1).B).toBe(1); // time going backwards: no change
    expect(l.tau).toBe(0); // leak is not a human touch
  });
  it('recharge caps at bMax and resets tau; full recharge', () => {
    const low = { B: 0.2, tau: 0 };
    expect(recharge(low, 0.5, 1, 99)).toEqual({ B: 0.7, tau: 99, asOf: 99 });
    expect(recharge(low, 5, 1, 99).B).toBe(1);
    expect(rechargeFull(low, 1, 7)).toEqual({ B: 1, tau: 7, asOf: 7 });
  });
  it('ageSinceTouch', () => {
    expect(ageSinceTouch({ B: 1, tau: 0 }, 1_800_000)).toBeCloseTo(0.5);
    expect(ageSinceTouch({ B: 1, tau: 0 }, 9e9)).toBe(1);
  });
  it('admit: low r + budget -> auto; mid/high r -> step-up; depleted low r -> step-up t=3', () => {
    expect(admit(0.1, { B: 1, tau: 0 }, P)).toEqual({ admit: true, needStepUp: false, t: 1, metered: true });
    expect(admit(0.25, { B: 0.25, tau: 0 }, P).admit).toBe(true); // B >= cost edge
    expect(admit(0.4, { B: 1, tau: 0 }, P)).toEqual({ admit: false, needStepUp: true, t: 2, metered: true }); // t=2 is metered
    expect(admit(0.4, { B: 0.3, tau: 0 }, P)).toEqual({ admit: false, needStepUp: true, t: 3, metered: false }); // t=2 unaffordable -> t=3
    expect(admit(0.9, { B: 1, tau: 0 }, P)).toEqual({ admit: false, needStepUp: true, t: 3, metered: false });
    expect(admit(0.1, { B: 0.05, tau: 0 }, P)).toEqual({ admit: false, needStepUp: true, t: 3, metered: false });
  });
  it('SAFETY INVARIANT: sum r of machine-only (t=1 AND t=2) actions between human recharges <= bMax/kappa', () => {
    for (const pol of [P, { ...P, kappa: 2, bMax: 1.5 }, { ...P, kappa: 0.5, bMax: 0.7, lambda: 0 }]) {
      // deterministic LCG so the "adversarial" sequence is reproducible
      let seed = 12345;
      const rnd = () => (seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296;
      let b: TrustBudget = { B: pol.bMax, tau: 0 };
      let sum = 0;
      let now = 0;
      let touches = 0;
      for (let i = 0; i < 5000; i++) {
        now += Math.floor(rnd() * 5000);
        b = leak(b, now, pol.lambda);
        const r = rnd() * 0.7; // spans t=1 and t=2 (machine-only band), some t=3
        const a = admit(r, b, pol);
        if (a.metered) {
          sum += r;
          b = debit(b, cost(r, pol.kappa));
          expect(sum).toBeLessThanOrEqual(safetyBound(pol) + 1e-9);
        } else if (rnd() < 0.05) {
          b = recharge(b, pol.rho, pol.bMax, now); // human touch
          touches++;
          sum = 0; // new interval: bound holds per interval since B0 <= bMax
        }
      }
      expect(touches).toBeGreaterThan(0);
    }
    expect(safetyBound({ bMax: 1, kappa: 4 })).toBe(0.25);
  });
  it('fully-compromised agent hammering free actions halts at the bound without a human', () => {
    const pol = { ...P, lambda: 0 };
    let b: TrustBudget = { B: pol.bMax, tau: 0 };
    let sum = 0;
    for (let i = 0; i < 10_000; i++) {
      const r = 0.2;
      if (!admit(r, b, pol).admit) break;
      sum += r;
      b = debit(b, cost(r, pol.kappa));
    }
    expect(sum).toBeLessThanOrEqual(safetyBound(pol));
    expect(admit(0.01, b, { ...pol, kappa: 1000 }).needStepUp).toBe(true);
  });
  it('depletion forces step-up even for low r', () => {
    let b: TrustBudget = { B: 0.3, tau: 0 };
    expect(admit(0.2, b, P).admit).toBe(true);
    b = debit(b, cost(0.2, P.kappa));
    expect(admit(0.2, b, P)).toMatchObject({ admit: false, needStepUp: true });
  });
  it('sub-budget cannot exceed parent; consolidated debit', () => {
    const parent: TrustBudget = { B: 0.6, tau: 5 };
    expect(subBudget(parent, 0.7)).toMatchObject({ ok: false });
    expect(subBudget(parent, -1)).toMatchObject({ ok: false });
    expect(subBudget(parent, NaN)).toMatchObject({ ok: false });
    const s1 = subBudget(parent, 0.6);
    expect(s1.ok && s1.sub.B).toBe(0.6);
    if (!s1.ok) throw new Error();
    const s2 = subBudget(parent, 0.6);
    if (!s2.ok) throw new Error();
    // two sub-agents each hold 0.6 but together cannot spend more than the parent's 0.6
    const a = debitConsolidated(parent, s1.sub, 0.4);
    expect(a.ok).toBe(true);
    if (!a.ok) throw new Error();
    expect(a.parent.B).toBeCloseTo(0.2);
    const b = debitConsolidated(a.parent, s2.sub, 0.4);
    expect(b).toMatchObject({ ok: false, reason: expect.stringMatching(/parent/) });
    expect(debitConsolidated(parent, { B: 0.1, tau: 0 }, 0.2)).toMatchObject({ ok: false });
  });
  it('debitConsolidatedPath: debits node + every ancestor across a 2-3 level tree; refuses if ANY cannot cover', () => {
    // A root->leaf path of carried-allocation remainings (ancestor budgets): grant-subtree 5, mid 3, leaf 2.
    const path: TrustBudget[] = [{ B: 5, tau: 0 }, { B: 3, tau: 0 }, { B: 2, tau: 0 }];
    const a = debitConsolidatedPath(path, 1.5);
    expect(a.ok).toBe(true);
    if (!a.ok) throw new Error();
    expect(a.nodes.map((n) => n.B)).toEqual([3.5, 1.5, 0.5]); // every level debited by the SAME cost
    // the tightest (leaf) node is now the binding one: a second 1.5 cannot be covered by it (0.5 < 1.5).
    const b = debitConsolidatedPath(a.nodes, 1.5);
    expect(b).toMatchObject({ ok: false, reason: expect.stringMatching(/depth 2/) });
    // an EXHAUSTED ancestor refuses the whole debit even when the leaf could cover it (containment).
    const ancestorDry: TrustBudget[] = [{ B: 0.2, tau: 0 }, { B: 9, tau: 0 }];
    expect(debitConsolidatedPath(ancestorDry, 1)).toMatchObject({ ok: false, reason: expect.stringMatching(/depth 0/) });
    // a zero-cost debit (e.g. an unmetered human-cosigned t=3) always succeeds and changes nothing.
    const z = debitConsolidatedPath(path, 0);
    expect(z.ok && z.nodes.map((n) => n.B)).toEqual([5, 3, 2]);
  });
  it('validateRiskPolicy', () => {
    expect(validateRiskPolicy(P)).toBeNull();
    expect(validateRiskPolicy({ ...P, theta1: 0.9, theta2: 0.1 })).toMatch(/theta1/);
    expect(validateRiskPolicy({ ...P, kappa: 0 })).toMatch(/kappa/);
    expect(validateRiskPolicy({ ...P, weights: { ...w, alpha: -1 } })).toMatch(/alpha/);
    expect(validateRiskPolicy(null)).toMatch(/object/);
  });
});

const node = (id: string, extra: Partial<PlanNode> = {}): PlanNode => ({ id, verb: 'v', resource: '/' + id, ...extra });

describe('planGeodesic', () => {
  it('index fallback when no edges', () => {
    const plan = [node('a'), node('b'), node('c'), node('d')];
    expect(planGeodesic(plan, 'a', 'a')).toBe(0);
    expect(planGeodesic(plan, 'a', 'd')).toBe(1);
    expect(planGeodesic(plan, 'b', 'd')).toBeCloseTo(2 / 3);
  });
  it('BFS over pre/post references (undirected)', () => {
    const plan = [
      node('a', { post: { before: ['b'] } }),
      node('b'),
      node('c', { pre: { after: 'b' } }),
      node('d', { pre: 'c' }),
      node('x'), // isolated
    ];
    expect(planGeodesic(plan, 'a', 'd')).toBeCloseTo(3 / 4);
    expect(planGeodesic(plan, 'd', 'a')).toBeCloseTo(3 / 4);
    expect(planGeodesic(plan, 'c', 'd')).toBeCloseTo(1 / 4);
    expect(planGeodesic(plan, 'a', 'x')).toBe(1); // unreachable
    expect(planGeodesic(plan, 'a', 'nope')).toBe(1);
  });
  it('single-node / bad plan', () => {
    expect(planGeodesic([node('a')], 'a', 'a')).toBe(0);
    expect(planGeodesic(null as never, 'a', 'b')).toBe(1);
  });
});
