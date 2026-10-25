/**
 * r13 mutation kills for immune.ts: baselineStd's sample gate, decay's guard against degenerate half-lives (a zero or
 * negative half-life must leave counts untouched at dt = 0 / count = 0 rather than produce NaN), assess() boundaries
 * at exactly 0.33 / 0.66 and the settled-baseline gate, and adapt()'s exact policy and rationale strings.
 */
import { describe, expect, it } from 'vitest';
import { adapt, assess, baselineStd, DEFAULT_IMMUNE_CONFIG, INITIAL_IMMUNE_STATE, observe, type ImmuneState, type ThreatAssessment } from './immune';
import { DEFAULT_RISK_POLICY } from './risk';

const st = (over: Partial<ImmuneState>): ImmuneState => ({ ...INITIAL_IMMUNE_STATE, seeded: true, ...over });
const cfg = (over: Partial<typeof DEFAULT_IMMUNE_CONFIG>) => ({ ...DEFAULT_IMMUNE_CONFIG, ...over });

describe('baselineStd', () => {
  it('is 0 below two samples and the population std from two', () => {
    expect(baselineStd({ n: 1, mean: 0, m2: 4 })).toBe(0);
    expect(baselineStd({ n: 2, mean: 0, m2: 8 })).toBe(2);
  });
});

describe('decay via observe', () => {
  it('a zero half-life leaves counts unchanged at dt = 0', () => {
    const s = observe(st({ stepUps: 2, denies: 1, lastAt: 100 }), { r: 0, at: 100 }, cfg({ halfLifeMs: 0 }));
    expect(s.stepUps).toBe(2);
    expect(s.denies).toBe(1);
  });
  it('a zero count stays 0 even under a negative half-life', () => {
    const s = observe(st({ stepUps: 0, denies: 0, lastAt: 0 }), { r: 0, at: 1000 }, cfg({ halfLifeMs: -1e-300 }));
    expect(s.stepUps).toBe(0);
    expect(s.denies).toBe(0);
  });
  it('decays by half per half-life', () => {
    const s = observe(st({ stepUps: 4, denies: 2, lastAt: 0 }), { r: 0, at: 1000, stepUp: true }, cfg({ halfLifeMs: 1000 }));
    expect(s.stepUps).toBe(3);
    expect(s.denies).toBe(1);
  });
});

describe('assess', () => {
  const settled = { n: 5, mean: 0, m2: 5 }; // std 1
  it('drift needs at least 5 samples and a non-zero std', () => {
    expect(assess(st({ baseline: settled, ewma: 0.33 }), cfg({ driftZSat: 1 })).components.drift).toBe(0.33);
    expect(assess(st({ baseline: { n: 4, mean: 0, m2: 4 }, ewma: 0.9 })).components.drift).toBe(0);
    expect(assess(st({ baseline: { n: 5, mean: 0, m2: 0 }, ewma: 0.9 })).components.drift).toBe(0);
  });
  it('the std gate is strict at 1e-9', () => {
    const b = { n: 5, mean: 0, m2: 5e-18 };
    expect(baselineStd(b)).toBe(1e-9);
    expect(assess(st({ baseline: b, ewma: 0.5 })).components.drift).toBe(0);
  });
  it('signals fire strictly above 0.33; levels at >= 0.33 and >= 0.66', () => {
    const a = assess(st({ baseline: settled, ewma: 0.33, stepUps: 0.33, denies: 0.33 }), cfg({ driftZSat: 1, stepUpSat: 1, denySat: 1 }));
    expect(a).toEqual({ level: 'elevated', score: 0.33, signals: [], components: { drift: 0.33, volatility: 0.33, violation: 0.33 } });
    const h = assess(st({ stepUps: 0.66 }), cfg({ stepUpSat: 1 }));
    expect(h.level).toBe('high');
    expect(h.signals).toEqual(['elevated step-up rate (0.7)']);
    expect(assess(st({ denies: 0.65 }), cfg({ denySat: 1 })).level).toBe('elevated');
    expect(assess(st({ denies: 0.32 }), cfg({ denySat: 1 })).level).toBe('calm');
  });
});

describe('adapt', () => {
  const A = (score: number, signals: string[] = [], level: ThreatAssessment['level'] = 'elevated'): ThreatAssessment => ({ level, score, signals, components: { drift: 0, volatility: 0, violation: 0 } });
  it('calm keeps the baseline', () => {
    expect(adapt(DEFAULT_RISK_POLICY, A(0))).toEqual({ policy: DEFAULT_RISK_POLICY, changed: false, rationale: 'calm — baseline policy' });
  });
  it('scales kappa and theta linearly in the score, with the exact rationale', () => {
    const r = adapt(DEFAULT_RISK_POLICY, A(0.5));
    expect(r.changed).toBe(true);
    expect(r.policy.kappa).toBe(DEFAULT_RISK_POLICY.kappa * 2);
    expect(r.policy.theta1).toBe(DEFAULT_RISK_POLICY.theta1 * 0.7);
    expect(r.policy.theta2).toBe(DEFAULT_RISK_POLICY.theta2 * 0.7);
    expect(r.rationale).toBe('elevated: threat score 0.50 → κ ×2.00, θ ×0.70');
    expect(adapt(DEFAULT_RISK_POLICY, A(0.5, ['a', 'b'], 'high')).rationale).toBe('high: a; b → κ ×2.00, θ ×0.70');
  });
  it('rejects an adaptation that does not validate', () => {
    const base = { ...DEFAULT_RISK_POLICY, lambda: -1 };
    expect(adapt(base, A(0.5))).toEqual({ policy: base, changed: false, rationale: 'adaptation rejected (risk_policy lambda/rho/bMax must be >= 0) — kept baseline' });
  });
});
