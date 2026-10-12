import { describe, expect, it } from 'vitest';
import type { Caveat } from '@atlasauth/pca';
import { analyzeCaveats } from './caveats';

const c = (x: unknown) => x as Caveat;

describe('analyzeCaveats exact verdicts', () => {
  it('non-array', () => {
    expect(analyzeCaveats(undefined)).toEqual({ sat: false, reason: 'caveats are not an array' });
    expect(analyzeCaveats({} as never)).toEqual({ sat: false, reason: 'caveats are not an array' });
  });
  it('empty is sat with no cap', () => {
    expect(analyzeCaveats([])).toEqual({ sat: true, revCap: undefined });
  });
  it('malformed caveat', () => {
    const r = { sat: false, reason: 'malformed caveat (not an object with a string type)' };
    expect(analyzeCaveats([c(null)])).toEqual(r);
    expect(analyzeCaveats([c('x')])).toEqual(r);
    expect(analyzeCaveats([c({})])).toEqual(r);
    expect(analyzeCaveats([c({ type: 3 })])).toEqual(r);
  });
  it('unknown type', () => {
    expect(analyzeCaveats([c({ type: 'zzz' })])).toEqual({ sat: false, reason: "unknown caveat type 'zzz' (fail closed)" });
  });
  it('expires', () => {
    const r = { sat: false, reason: 'expires.at is not a finite number' };
    expect(analyzeCaveats([c({ type: 'expires' })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'expires', at: '5' })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'expires', at: Infinity })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'expires', at: NaN })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'expires', at: 5 })]).sat).toBe(true);
  });
  it('not_before', () => {
    const r = { sat: false, reason: 'not_before.at is not a finite number' };
    expect(analyzeCaveats([c({ type: 'not_before' })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'not_before', at: '5' })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'not_before', at: -Infinity })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'not_before', at: 5 })]).sat).toBe(true);
  });
  it('window: empty iff not_before >= expires, uses max/min across caveats in any order', () => {
    const exp = (at: number) => c({ type: 'expires', at });
    const nb = (at: number) => c({ type: 'not_before', at });
    expect(analyzeCaveats([nb(10), exp(10)])).toEqual({
      sat: false,
      reason: 'not_before (10) >= expires (10): the validity window is empty',
    });
    expect(analyzeCaveats([exp(10), nb(11)]).reason).toBe('not_before (11) >= expires (10): the validity window is empty');
    expect(analyzeCaveats([nb(9), exp(10)]).sat).toBe(true);
    // max of not_befores, min of expires
    expect(analyzeCaveats([nb(1), nb(8), nb(3), exp(20), exp(9), exp(30)]).sat).toBe(true);
    expect(analyzeCaveats([nb(1), nb(9), nb(3), exp(20), exp(9), exp(30)]).reason).toBe(
      'not_before (9) >= expires (9): the validity window is empty',
    );
    expect(analyzeCaveats([nb(1), nb(5), exp(30), exp(4), exp(40)]).reason).toBe(
      'not_before (5) >= expires (4): the validity window is empty',
    );
    // only one side present: satisfiable even for extreme values
    expect(analyzeCaveats([nb(1e300)]).sat).toBe(true);
    expect(analyzeCaveats([exp(-1e300)]).sat).toBe(true);
    expect(analyzeCaveats([nb(-5)]).sat).toBe(true);
    expect(analyzeCaveats([exp(-5)]).sat).toBe(true);
    expect(analyzeCaveats([nb(-5), exp(-4)]).sat).toBe(true);
  });
  it('rate', () => {
    const r = { sat: false, reason: 'rate caveat requires finite max and per_secs > 0' };
    expect(analyzeCaveats([c({ type: 'rate', per_secs: 5 })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'rate', max: 5 })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'rate', max: 5, per_secs: 0 })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'rate', max: 5, per_secs: -1 })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'rate', max: NaN, per_secs: 1 })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'rate', max: 0.5, per_secs: 1 })])).toEqual({ sat: false, reason: 'rate.max 0.5 < 1 forbids every action' });
    expect(analyzeCaveats([c({ type: 'rate', max: 1, per_secs: 0.001 })]).sat).toBe(true);
  });
  it('max_blast_radius', () => {
    expect(analyzeCaveats([c({ type: 'max_blast_radius' })])).toEqual({ sat: false, reason: 'max_blast_radius.max is not a finite number' });
    expect(analyzeCaveats([c({ type: 'max_blast_radius', max: '1' })]).reason).toBe('max_blast_radius.max is not a finite number');
    expect(analyzeCaveats([c({ type: 'max_blast_radius', max: -1 })])).toEqual({ sat: false, reason: 'max_blast_radius.max < 0 forbids every action' });
    expect(analyzeCaveats([c({ type: 'max_blast_radius', max: 0 })]).sat).toBe(true);
  });
  it('delegation_depth', () => {
    expect(analyzeCaveats([c({ type: 'delegation_depth' })])).toEqual({ sat: false, reason: 'delegation_depth.max is not a finite number' });
    expect(analyzeCaveats([c({ type: 'delegation_depth', max: Infinity })]).reason).toBe('delegation_depth.max is not a finite number');
    expect(analyzeCaveats([c({ type: 'delegation_depth', max: -1 })])).toEqual({ sat: false, reason: 'delegation_depth.max < 0 forbids every action' });
    expect(analyzeCaveats([c({ type: 'delegation_depth', max: 0 })]).sat).toBe(true);
  });
  it('budget_alloc', () => {
    const r = { sat: false, reason: 'budget_alloc.limit must be a finite number >= 0' };
    expect(analyzeCaveats([c({ type: 'budget_alloc' })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'budget_alloc', limit: -1 })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'budget_alloc', limit: '1' })])).toEqual(r);
    expect(analyzeCaveats([c({ type: 'budget_alloc', limit: 0 })]).sat).toBe(true);
  });
  it('reversibility_max picks the strictest', () => {
    expect(analyzeCaveats([c({ type: 'reversibility_max', class: 'rate_limited' })])).toEqual({ sat: true, revCap: 1 });
    expect(analyzeCaveats([c({ type: 'reversibility_max', class: 'reversible' })])).toEqual({ sat: true, revCap: 0 });
    expect(analyzeCaveats([c({ type: 'reversibility_max', class: 'irreversible' })])).toEqual({ sat: true, revCap: 2 });
    expect(
      analyzeCaveats([
        c({ type: 'reversibility_max', class: 'irreversible' }),
        c({ type: 'reversibility_max', class: 'rate_limited' }),
        c({ type: 'reversibility_max', class: 'irreversible' }),
      ]).revCap,
    ).toBe(1);
    expect(analyzeCaveats([c({ type: 'reversibility_max', class: 'bogus' })])).toEqual({ sat: false, reason: "reversibility_max.class 'bogus' is unknown" });
    expect(analyzeCaveats([c({ type: 'reversibility_max' })]).reason).toBe("reversibility_max.class 'undefined' is unknown");
  });
  it('first failing caveat short-circuits', () => {
    const r = analyzeCaveats([c({ type: 'delegation_depth', max: -1 }), c({ type: 'zzz' })]);
    expect(r.reason).toBe('delegation_depth.max < 0 forbids every action');
  });
});
