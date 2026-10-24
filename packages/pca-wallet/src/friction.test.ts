import { describe, expect, it } from 'vitest';
import { rng } from '@atlasauth/pca-intent';
import { frictionFor, frictionRank, satisfiesTier, worstProvenance, type FrictionInputs, type FrictionTier } from './index';

const REV = ['reversible', 'rate_limited', 'irreversible'] as const;
const LV = ['trusted', 'first_party', 'tool', 'web', 'agent'] as const;
const T: FrictionTier[] = ['tap', 'hold', 'typed', 'device'];

describe('friction scaled by harm (§3.4 table)', () => {
  it('implements each default rule', () => {
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 1 }).tier).toBe('tap');
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 5 }).tier).toBe('hold');
    expect(frictionFor({ reversibility: 'rate_limited', expectedHarm: 1 }).tier).toBe('hold');
    expect(frictionFor({ reversibility: 'irreversible', expectedHarm: 10 }).tier).toBe('typed');
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 1, provenance: [{ path: 'p', sensitivity: 'critical', levels: ['web'] }] }).tier).toBe('typed');
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 1, provenance: [{ path: 'p', sensitivity: 'material', levels: ['web'] }] }).tier).toBe('tap');
    expect(frictionFor({ reversibility: 'irreversible', expectedHarm: 10, widensCriticalIdentity: true }).tier).toBe('device');
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 1e6 }).tier).toBe('device');
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 1, singleSource: true }).tier).toBe('hold');
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 1, siteMin: 'typed' }).tier).toBe('typed');
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: Number.NaN }).tier).toBe('device');
  });
  it('the walkthrough booking (irreversible, money, no identity widening) is a typed question', () => {
    expect(frictionFor({ reversibility: 'irreversible', expectedHarm: 10 * (1 + 778) }).tier).toBe('typed');
  });
  it('is monotone: more harm, a worse reversibility, more taint or a higher site minimum never lowers the tier (property)', () => {
    const r = rng(3);
    const pick = <X>(xs: readonly X[]) => xs[Math.floor(r() * xs.length)]!;
    for (let i = 0; i < 2000; i++) {
      const a: FrictionInputs = {
        reversibility: pick(REV),
        expectedHarm: r() * 2e5,
        provenance: [{ path: 'p', sensitivity: pick(['free', 'material', 'critical'] as const), levels: [pick(LV)] }],
        widensCriticalIdentity: r() < 0.3,
        singleSource: r() < 0.2,
        siteMin: pick(T),
      };
      const b: FrictionInputs = {
        reversibility: REV[Math.max(REV.indexOf(a.reversibility as (typeof REV)[number]), Math.floor(r() * 3))]!,
        expectedHarm: a.expectedHarm + r() * 1e5,
        provenance: [{ ...a.provenance![0]!, levels: [LV[Math.max(LV.indexOf(a.provenance![0]!.levels[0] as (typeof LV)[number]), Math.floor(r() * 5))]!] }],
        widensCriticalIdentity: a.widensCriticalIdentity || r() < 0.3,
        singleSource: a.singleSource || r() < 0.2,
        siteMin: T[Math.max(frictionRank(a.siteMin!), Math.floor(r() * 4))]!,
      };
      const ta = frictionFor(a).tier;
      const tb = frictionFor(b).tier;
      expect(frictionRank(tb)).toBeGreaterThanOrEqual(frictionRank(ta));
      expect(satisfiesTier(ta, a.siteMin!)).toBe(true);
    }
  });
  it('provenance of an unknown or empty set is the worst level (fail closed)', () => {
    expect(worstProvenance([])).toBe('agent');
    expect(worstProvenance(['trusted', 'bogus'])).toBe('agent');
    expect(worstProvenance(['trusted', 'first_party'])).toBe('first_party');
  });
});
