import { describe, expect, it } from 'vitest';
import { betaInc, betaQuantile, binEnt, lnGamma } from './index';

describe('lnGamma', () => {
  it('uses the reflection formula below one half (exact to the last digits)', () => {
    expect(lnGamma(0.25)).toBeCloseTo(1.288022524698077, 15);
    expect(lnGamma(0.1)).toBeCloseTo(2.252712651734206, 15);
    expect(lnGamma(0.4)).toBeCloseTo(0.796677817701783, 15);
  });
  it('terminates at one half and matches known values', () => {
    expect(lnGamma(0.5)).toBeCloseTo(0.5 * Math.log(Math.PI), 12);
    expect(lnGamma(1)).toBeCloseTo(0, 12);
    expect(lnGamma(5)).toBeCloseTo(Math.log(24), 12);
  });
});

describe('betaInc', () => {
  it('rejects non-positive shape parameters with the message', () => {
    const msg = 'betaInc: a and b must be > 0';
    expect(() => betaInc(0.5, 0, 1)).toThrow(msg);
    expect(() => betaInc(0.5, 1, 0)).toThrow(msg);
    expect(() => betaInc(0.5, -1, 1)).toThrow(msg);
    expect(() => betaInc(0.5, 1, -1)).toThrow(msg);
    expect(betaInc(0.5, 1e-3, 1e-3)).toBeGreaterThan(0);
  });
  it('clamps outside [0, 1] and at the ends', () => {
    expect(betaInc(-1, 2, 3)).toBe(0);
    expect(betaInc(0, 2, 3)).toBe(0);
    expect(betaInc(2, 2, 3)).toBe(1);
    expect(betaInc(1, 2, 3)).toBe(1);
  });
  it('matches the closed form for Beta(2, 3) on both branches', () => {
    for (const x of [0.1, 0.3, 0.4, 0.5, 0.7, 0.9]) expect(betaInc(x, 2, 3)).toBeCloseTo(6 * x ** 2 - 8 * x ** 3 + 3 * x ** 4, 12);
  });
  it('picks the series on the correct side of the switch point', () => {
    // the two continued fractions differ in the last digits, so a wrong switch point shows up
    expect(betaInc(0.5, 50, 50)).toBeCloseTo(0.5000000000000113, 14);
    expect(betaInc(0.2499, 1000, 3000)).toBeCloseTo(0.4966010120761495, 13);
    expect(betaInc(0.2503, 1000, 3000)).toBeCloseTo(0.5198946064190693, 13);
    expect(betaInc(0.095, 2, 30)).toBeCloseTo(0.8072838523362229, 13);
  });
  it('uses all 300 continued-fraction terms when convergence needs them', () => {
    expect(betaInc(0.4999, 1e6, 1e6)).toBeCloseTo(0.38864871894206, 11);
  });
});

describe('betaQuantile', () => {
  it('rejects q outside [0, 1] with the message, accepts both ends', () => {
    const msg = 'betaQuantile: q must be in [0, 1]';
    expect(() => betaQuantile(-0.1, 2, 2)).toThrow(msg);
    expect(() => betaQuantile(1.1, 2, 2)).toThrow(msg);
    expect(() => betaQuantile(Number.NaN, 2, 2)).toThrow(msg);
    expect(betaQuantile(0, 2, 2)).toBe(0);
    expect(betaQuantile(1, 2, 2)).toBe(1);
    // betaInc rounds to exactly 1 well below x = 1 here, so the q = 1 short-circuit is the only way to get 1
    expect(betaQuantile(1, 1, 5000)).toBe(1);
  });
  it('inverts betaInc', () => {
    expect(betaQuantile(0.5, 2, 2)).toBeCloseTo(0.5, 12);
    for (const q of [0.05, 0.5, 0.95]) expect(betaInc(betaQuantile(q, 2, 3), 2, 3)).toBeCloseTo(q, 12);
  });
});

describe('binEnt', () => {
  it('is zero at and outside the ends', () => {
    for (const p of [0, 1, -0.5, 2]) expect(binEnt(p)).toBe(0);
  });
  it('matches known values', () => {
    expect(binEnt(0.5)).toBeCloseTo(1, 14);
    expect(binEnt(0.25)).toBeCloseTo(0.8112781244591328, 14);
    expect(binEnt(0.75)).toBeCloseTo(0.8112781244591328, 14);
    expect(binEnt(0.1)).toBeCloseTo(0.4689955935892812, 14);
  });
});
