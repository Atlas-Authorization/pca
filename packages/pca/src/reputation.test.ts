import { describe, expect, it } from 'vitest';
import { priceCoverage, reputation } from './reputation';
import type { ActivityEvent } from './console';

const ev = (outcome: ActivityEvent['outcome'], at: number): ActivityEvent => ({ at, agent: 'a', verb: 'v', resource: 'r', outcome });

describe('reputation', () => {
  it('is 0.5 (unproven) with no history', () => {
    expect(reputation({ subject: 'a' }).score).toBe(0.5);
  });

  it('a clean history scores high; denies drop it', () => {
    const clean = reputation({ subject: 'a', events: Array.from({ length: 10 }, (_, i) => ev('auto', i)) });
    expect(clean.score).toBe(1);
    const noisy = reputation({
      subject: 'a',
      events: [...Array.from({ length: 5 }, (_, i) => ev('auto', i)), ...Array.from({ length: 5 }, (_, i) => ev('deny', 5 + i))],
    });
    expect(noisy.score).toBeLessThan(clean.score);
    expect(noisy.factors.join(' ')).toMatch(/deny rate/);
  });

  it('slashed disputes dominate the penalty', () => {
    const slashed = reputation({
      subject: 'a',
      events: Array.from({ length: 10 }, (_, i) => ev('auto', i)),
      disputes: [{ subject: 'a', slashed: true, at: 1 }, { subject: 'a', slashed: true, at: 2 }],
    });
    expect(slashed.slashes).toBe(2);
    expect(slashed.score).toBeLessThan(0.5);
    expect(slashed.factors.join(' ')).toMatch(/slashed/);
  });
});

describe('priceCoverage', () => {
  it('prices a good reputation cheaply and loads a poor one', () => {
    const good = reputation({ subject: 'a', events: Array.from({ length: 10 }, (_, i) => ev('auto', i)) });
    const poor = reputation({ subject: 'b', events: [ev('auto', 0), ev('deny', 1), ev('deny', 2), ev('deny', 3)] });
    const pg = priceCoverage(good, 1000);
    const pp = priceCoverage(poor, 1000);
    expect(pg.declined).toBe(false);
    expect(pg.premium).toBeCloseTo(10, 6); // baseRate 0.01 × 1000 × load 1.0 (perfect score)
    expect(pp.premium).toBeGreaterThan(pg.premium);
    expect(pg.coverage).toBe(1000);
  });

  it('declines coverage below the underwriting floor', () => {
    const bad = reputation({
      subject: 'c',
      events: Array.from({ length: 4 }, (_, i) => ev('auto', i)),
      disputes: [{ subject: 'c', slashed: true, at: 1 }, { subject: 'c', slashed: true, at: 2 }, { subject: 'c', slashed: true, at: 3 }],
    });
    const p = priceCoverage(bad, 1000);
    expect(p.declined).toBe(true);
    expect(p.premium).toBe(0);
  });
});
