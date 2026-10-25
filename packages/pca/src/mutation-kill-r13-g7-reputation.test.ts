/**
 * r13 mutation kills for reputation.ts: exact Reputation records (counts, score arithmetic, factor strings including
 * pluralisation and the clean / unproven cases) and exact priceCoverage quotes (floor boundary, premium, rationale).
 */
import { describe, expect, it } from 'vitest';
import type { ActivityEvent } from './console';
import { priceCoverage, reputation, type Reputation } from './reputation';

const ev = (outcome: string) => ({ outcome }) as unknown as ActivityEvent;
const evs = (spec: Record<string, number>) => Object.entries(spec).flatMap(([o, n]) => Array.from({ length: n }, () => ev(o)));

describe('reputation', () => {
  it('no history is unproven 0.5', () => {
    expect(reputation({ subject: 's' })).toEqual({ subject: 's', actions: 0, autos: 0, stepUps: 0, denies: 0, slashes: 0, disputes: 0, score: 0.5, factors: ['unproven (no history)'] });
  });
  it('only clean actions', () => {
    expect(reputation({ subject: 's', events: evs({ auto: 3 }) })).toEqual({ subject: 's', actions: 3, autos: 3, stepUps: 0, denies: 0, slashes: 0, disputes: 0, score: 1, factors: ['clean history'] });
  });
  it('only an unslashed dispute is history (clean)', () => {
    expect(reputation({ subject: 's', disputes: [{ subject: 's', slashed: false, at: 1 }] })).toEqual({
      subject: 's', actions: 0, autos: 0, stepUps: 0, denies: 0, slashes: 0, disputes: 1, score: 1, factors: ['clean history'],
    });
  });
  it('deny and step-up rates', () => {
    const r = reputation({ subject: 's', events: evs({ auto: 5, step_up: 3, deny: 2 }) });
    expect(r).toEqual({ subject: 's', actions: 10, autos: 5, stepUps: 3, denies: 2, slashes: 0, disputes: 0, score: 1 - 0.6 * 0.2 - 0.15 * 0.3, factors: ['deny rate 20%', 'step-up rate 30%'] });
  });
  it('step-ups only', () => {
    const r = reputation({ subject: 's', events: evs({ auto: 1, step_up: 1 }) });
    expect(r).toEqual({ subject: 's', actions: 2, autos: 1, stepUps: 1, denies: 0, slashes: 0, disputes: 0, score: 1 - 0.15 * 0.5, factors: ['step-up rate 50%'] });
  });
  it('one slash, then many (saturating, plural)', () => {
    const d = (slashed: boolean) => ({ subject: 's', slashed, at: 1 });
    expect(reputation({ subject: 's', events: evs({ auto: 1 }), disputes: [d(true), d(false)] })).toEqual({
      subject: 's', actions: 1, autos: 1, stepUps: 0, denies: 0, slashes: 1, disputes: 2, score: 0.7, factors: ['1 slashed dispute'],
    });
    const r = reputation({ subject: 's', events: evs({ auto: 1 }), disputes: [d(true), d(true), d(true), d(true)] });
    expect(r.slashes).toBe(4);
    expect(r.score).toBeCloseTo(0.2, 12);
    expect(r.factors).toEqual(['4 slashed disputes']);
    const two = reputation({ subject: 's', events: evs({ auto: 1 }), disputes: [d(true), d(true)] });
    expect(two.factors).toEqual(['2 slashed disputes']);
    expect(two.score).toBeCloseTo(0.4, 12);
  });
  it('clamps at 0', () => {
    const d = { subject: 's', slashed: true, at: 1 };
    const r = reputation({ subject: 's', events: evs({ deny: 1 }), disputes: [d, d, d] });
    expect(r.score).toBe(0);
    expect(r.factors).toEqual(['deny rate 100%', '3 slashed disputes']);
  });
});

describe('priceCoverage', () => {
  const rep = (score: number) => ({ score }) as Reputation;
  it('declines strictly below the floor, with the exact rationale', () => {
    expect(priceCoverage(rep(0.2), 100)).toEqual({ declined: true, premium: 0, coverage: 0, rationale: 'reputation 0.20 below underwriting floor 0.25' });
    expect(priceCoverage(rep(0.25), 100).declined).toBe(false);
  });
  it('prices baseRate * exposure * (1 + riskLoad * (1 - score))', () => {
    expect(priceCoverage(rep(0.5), 1000)).toEqual({ declined: false, premium: 0.01 * 1000 * 3, coverage: 1000, rationale: 'base 0.01 × exposure 1000 × load 3.00 (score 0.50)' });
    expect(priceCoverage(rep(0.75), 200, { baseRate: 0.02, riskLoad: 2, minScore: 0.1 })).toEqual({
      declined: false, premium: 0.02 * 200 * 1.5, coverage: 200, rationale: 'base 0.02 × exposure 200 × load 1.50 (score 0.75)',
    });
  });
});
