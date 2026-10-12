import { describe, expect, it } from 'vitest';
import {
  DEFAULT_IMMUNE_CONFIG,
  INITIAL_IMMUNE_STATE,
  adapt,
  assess,
  baselineStd,
  observe,
  updateBaseline,
} from './immune';
import { DEFAULT_RISK_POLICY, type RiskPolicy } from './risk';

const feed = (rs: Array<{ r: number; stepUp?: boolean; denied?: boolean }>, startAt = 0, stepMs = 1000) => {
  let s = INITIAL_IMMUNE_STATE;
  rs.forEach((o, i) => {
    s = observe(s, { r: o.r, at: startAt + i * stepMs, stepUp: o.stepUp, denied: o.denied });
  });
  return s;
};

describe('baseline (Welford)', () => {
  it('tracks mean and std over a stream', () => {
    let b = { n: 0, mean: 0, m2: 0 };
    for (const x of [0.2, 0.2, 0.2, 0.2]) b = updateBaseline(b, x);
    expect(b.mean).toBeCloseTo(0.2, 6);
    expect(baselineStd(b)).toBeCloseTo(0, 6);
    for (const x of [0.0, 0.4]) b = updateBaseline(b, x);
    expect(b.mean).toBeCloseTo(0.2, 6);
    expect(baselineStd(b)).toBeGreaterThan(0);
  });
});

describe('assess', () => {
  it('stays calm on a steady low-risk stream', () => {
    const s = feed(Array.from({ length: 20 }, () => ({ r: 0.1 })));
    const a = assess(s);
    expect(a.level).toBe('calm');
    expect(a.score).toBeLessThan(0.33);
  });

  it('detects an upward risk drift (mean moves above baseline)', () => {
    // settle a low baseline, then a run of much higher risk.
    let s = feed(Array.from({ length: 20 }, () => ({ r: 0.1 })));
    for (let i = 0; i < 10; i++) s = observe(s, { r: 0.8, at: 100_000 + i * 1000 });
    const a = assess(s);
    expect(a.components.drift).toBeGreaterThan(0.33);
    expect(a.level).not.toBe('calm');
    expect(a.signals.join(' ')).toMatch(/drift/);
  });

  it('fires on a burst of denies (policy violations)', () => {
    const s = feed([
      { r: 0.1 },
      { r: 0.1 },
      { r: 0.2, denied: true },
      { r: 0.2, denied: true },
      { r: 0.2, denied: true },
    ]);
    const a = assess(s);
    expect(a.components.violation).toBeGreaterThanOrEqual(0.66);
    expect(a.level).toBe('high');
  });

  it('decays recent counters over time (a lull calms things down)', () => {
    let s = feed([{ r: 0.2, stepUp: true }, { r: 0.2, stepUp: true }, { r: 0.2, stepUp: true }], 0, 1000);
    const hot = assess(s);
    // a long quiet gap, then one calm action: the step-up counter decays away.
    s = observe(s, { r: 0.1, at: 10 * DEFAULT_IMMUNE_CONFIG.halfLifeMs });
    const cooled = assess(s);
    expect(cooled.components.volatility).toBeLessThan(hot.components.volatility);
  });
});

describe('adapt', () => {
  const base: RiskPolicy = { ...DEFAULT_RISK_POLICY, kappa: 100, theta1: 0.5, theta2: 0.8 };

  it('is a no-op when calm (score 0) — baseline policy unchanged', () => {
    const out = adapt(base, { level: 'calm', score: 0, signals: [], components: { drift: 0, volatility: 0, violation: 0 } });
    expect(out.changed).toBe(false);
    expect(out.policy).toBe(base);
  });

  it('raises κ and lowers θ under threat (more paranoid)', () => {
    const out = adapt(base, { level: 'high', score: 1, signals: ['x'], components: { drift: 1, volatility: 0, violation: 0 } });
    expect(out.changed).toBe(true);
    expect(out.policy.kappa).toBeCloseTo(300, 6); // 3× at score 1
    expect(out.policy.theta1).toBeCloseTo(0.2, 6); // 0.4× at score 1
    expect(out.policy.theta2).toBeCloseTo(0.32, 6);
    expect(out.policy.kappa).toBeGreaterThan(base.kappa);
    expect(out.policy.theta2).toBeLessThan(base.theta2);
  });

  it('is reversible: derived from base, so a calm score restores base exactly', () => {
    const tightened = adapt(base, { level: 'elevated', score: 0.5, signals: [], components: { drift: 0.5, volatility: 0, violation: 0 } });
    expect(tightened.policy.kappa).not.toBe(base.kappa);
    const back = adapt(base, { level: 'calm', score: 0, signals: [], components: { drift: 0, volatility: 0, violation: 0 } });
    expect(back.policy).toEqual(base);
  });

  it('end-to-end: a drift storm tightens the policy, a return to baseline relaxes it', () => {
    let s = feed(Array.from({ length: 20 }, () => ({ r: 0.1 })));
    for (let i = 0; i < 12; i++) s = observe(s, { r: 0.9, at: 100_000 + i * 1000 });
    const hot = adapt(base, assess(s));
    expect(hot.changed).toBe(true);
    expect(hot.policy.theta2).toBeLessThan(base.theta2);
    // long calm period after → score falls, policy relaxes toward base
    for (let i = 0; i < 40; i++) s = observe(s, { r: 0.1, at: 100_000 + (12 + i) * DEFAULT_IMMUNE_CONFIG.halfLifeMs });
    const calm = adapt(base, assess(s));
    expect(calm.policy.theta2).toBeGreaterThanOrEqual(hot.policy.theta2);
  });
});
