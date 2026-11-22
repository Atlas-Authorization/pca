import { describe, expect, it } from 'vitest';
import { frictionFor, satisfiesTier, worstProvenance, isProvenanceLevel } from './index';

describe('friction rule names and ordering', () => {
  it('a reversible low-harm question has no rules', () => {
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 0 })).toEqual({ tier: 'tap', rules: [] });
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 1 })).toEqual({ tier: 'tap', rules: [] });
  });
  it('unknown harm fails closed to device with the harm-unknown rule only', () => {
    for (const expectedHarm of [Number.NaN, -1, Number.POSITIVE_INFINITY]) {
      expect(frictionFor({ reversibility: 'reversible', expectedHarm })).toEqual({ tier: 'device', rules: ['harm-unknown'] });
    }
  });
  it('names each rule that raises or holds the tier', () => {
    expect(frictionFor({ reversibility: 'rate_limited', expectedHarm: 1 })).toEqual({ tier: 'hold', rules: ['rate-limited'] });
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 5 })).toEqual({ tier: 'hold', rules: ['harm>=h_tap'] });
    // an equal tier is still recorded
    expect(frictionFor({ reversibility: 'rate_limited', expectedHarm: 6 })).toEqual({ tier: 'hold', rules: ['rate-limited', 'harm>=h_tap'] });
    expect(frictionFor({ reversibility: 'irreversible', expectedHarm: 10 })).toEqual({ tier: 'typed', rules: ['harm>=h_tap', 'irreversible'] });
    expect(
      frictionFor({ reversibility: 'reversible', expectedHarm: 1, provenance: [{ path: 'p', sensitivity: 'critical', levels: ['agent'] }] }),
    ).toEqual({ tier: 'typed', rules: ['tainted-critical'] });
    expect(frictionFor({ reversibility: 'irreversible', expectedHarm: 10, widensCriticalIdentity: true })).toEqual({
      tier: 'device',
      rules: ['harm>=h_tap', 'irreversible', 'critical-irreversible'],
    });
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 100_000 })).toEqual({ tier: 'device', rules: ['harm>=h_tap', 'harm>=h_device'] });
  });
  it('the device threshold is inclusive and a bit below it is not device', () => {
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 99_999 }).tier).toBe('hold');
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 100_000 }).tier).toBe('device');
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 10 }, { hTap: 5, hDevice: 10 }).rules).toContain('harm>=h_device');
  });
  it('widening a critical identity only matters for an irreversible cell', () => {
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 1, widensCriticalIdentity: true })).toEqual({ tier: 'tap', rules: [] });
    expect(frictionFor({ reversibility: 'rate_limited', expectedHarm: 1, widensCriticalIdentity: true }).tier).toBe('hold');
  });
  it('single source raises one step, capped at device', () => {
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 1, singleSource: true })).toEqual({ tier: 'hold', rules: ['single-source'] });
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 1e6, singleSource: true })).toEqual({
      tier: 'device',
      rules: ['harm>=h_tap', 'harm>=h_device', 'single-source'],
    });
  });
  it('a site minimum below the current tier is not recorded; a higher or equal one is', () => {
    expect(frictionFor({ reversibility: 'irreversible', expectedHarm: 10, siteMin: 'tap' })).toEqual({ tier: 'typed', rules: ['harm>=h_tap', 'irreversible'] });
    expect(frictionFor({ reversibility: 'reversible', expectedHarm: 1, siteMin: 'device' })).toEqual({ tier: 'device', rules: ['site-minimum'] });
    expect(frictionFor({ reversibility: 'irreversible', expectedHarm: 10, siteMin: 'typed' }).rules).toEqual(['harm>=h_tap', 'irreversible', 'site-minimum']);
  });
  it('satisfiesTier is false for a weaker answer', () => {
    expect(satisfiesTier('tap', 'device')).toBe(false);
    expect(satisfiesTier('hold', 'typed')).toBe(false);
    expect(satisfiesTier('typed', 'typed')).toBe(true);
    expect(satisfiesTier('device', 'tap')).toBe(true);
  });
  it('worstProvenance picks the least trusted level and fails closed', () => {
    expect(worstProvenance(['trusted'])).toBe('trusted');
    expect(worstProvenance(['trusted', 'tool', 'first_party'])).toBe('tool');
    expect(worstProvenance([])).toBe('agent');
    expect(worstProvenance(['trusted', 'bogus'])).toBe('agent');
    expect(isProvenanceLevel('web')).toBe(true);
    expect(isProvenanceLevel('nope')).toBe(false);
  });
});
