import { describe, expect, it } from 'vitest';
import type { Condition, ConditionOp } from '@atlasauth/pca';
import { FRESH_STRING, FULL_INTERVAL, fieldProbes, intervalEmpty, numericConjunctionSatisfiable, tightenInterval } from './field';

const L = (op: ConditionOp, value: unknown, extra: object = {}): Condition => ({ field: 'action.params.x', op, value, ...extra }) as Condition;
const F = FRESH_STRING;

describe('fieldProbes exact outputs', () => {
  it('empty', () => {
    expect(fieldProbes([])).toEqual([F]);
  });
  it('eq numeric', () => {
    expect(fieldProbes([L('eq', 5)])).toEqual([5, 4, 6, F]);
  });
  it('ne numeric behaves like eq', () => {
    expect(fieldProbes([L('ne', 5)])).toEqual([5, 4, 6, F]);
  });
  it('eq string: literal only, no numeric cells', () => {
    expect(fieldProbes([L('eq', 'a')])).toEqual(['a', F]);
  });
  it('eq non-finite number is a literal but not a threshold', () => {
    expect(fieldProbes([L('eq', Infinity)])).toEqual([Infinity, F]);
    expect(fieldProbes([L('eq', NaN)])).toEqual([NaN, F]);
  });
  it('in / nin members', () => {
    expect(fieldProbes([L('in', [1, 'a'])])).toEqual([1, 'a', 0, 2, F]);
    expect(fieldProbes([L('nin', ['b', 3])])).toEqual(['b', 3, 2, 4, F]);
    expect(fieldProbes([L('in', ['a', Infinity])])).toEqual(['a', Infinity, F]);
    expect(fieldProbes([L('in', 'notarray')])).toEqual([F]);
    expect(fieldProbes([L('nin', 7)])).toEqual([F]);
  });
  it('thresholds: cells between consecutive, sorted, deduped', () => {
    expect(fieldProbes([L('lt', 10), L('gt', 0)])).toEqual([-1, 0, 5, 10, 11, F]);
    expect(fieldProbes([L('gte', 10), L('lte', 0), L('lt', 10)])).toEqual([-1, 0, 5, 10, 11, F]);
    expect(fieldProbes([L('lt', 'x')])).toEqual([F]);
    expect(fieldProbes([L('gt', NaN)])).toEqual([F]);
    expect(fieldProbes([L('gte', 2), L('lte', 4), L('eq', 3)])).toEqual([3, 1, 2, 2.5, 3.5, 4, 5, F]);
  });
  it('mx+1 for non-integer top is appended after fresh', () => {
    // thresholds {0, 1}: reps -1,0,0.5,1,2 ; mx+1 = 2 dup
    expect(fieldProbes([L('lt', 0), L('lt', 1)])).toEqual([-1, 0, 0.5, 1, 2, F]);
  });
  it('prefix: literal and extension', () => {
    expect(fieldProbes([L('prefix', 'ab')])).toEqual(['ab', 'abx', F]);
    expect(fieldProbes([L('prefix', 5)])).toEqual([F]);
  });
  it('like / matches / is_a add literal but no extension', () => {
    for (const op of ['like', 'matches', 'is_a'] as const) {
      expect(fieldProbes([L(op, 'q')])).toEqual(['q', F]);
      expect(fieldProbes([L(op, 9)])).toEqual([F]);
    }
  });
  it('member_of string / array of strings', () => {
    expect(fieldProbes([L('member_of', 's')])).toEqual(['s', F]);
    expect(fieldProbes([L('member_of', ['a', 1, 'b'])])).toEqual(['a', 'b', F]);
    expect(fieldProbes([L('member_of', 5)])).toEqual([F]);
  });
  it('exists / unknown op contribute nothing', () => {
    expect(fieldProbes([L('exists', true)])).toEqual([F]);
    expect(fieldProbes([L('bogus' as ConditionOp, 4)])).toEqual([F]);
  });
  it('ref and group conditions are skipped', () => {
    expect(fieldProbes([L('eq', 5, { ref: 'env.y' })])).toEqual([F]);
    expect(fieldProbes([{ all_of: [L('eq', 5)] } as Condition])).toEqual([F]);
    expect(fieldProbes([{ not: L('eq', 5) } as Condition])).toEqual([F]);
  });
  it('dedupe is type-sensitive and ignores key collisions of different types', () => {
    expect(fieldProbes([L('eq', 1), L('eq', '1'), L('eq', 1)])).toEqual([1, '1', 0, 2, F]);
    expect(fieldProbes([L('eq', FRESH_STRING)])).toEqual([F]);
  });
  it('unserializable literals are deduplicated by type', () => {
    const big = 10n as unknown;
    const out = fieldProbes([L('eq', big), L('eq', 11n as unknown)]);
    expect(out).toEqual([10n, F]);
  });
  it('circular value does not throw', () => {
    const o: Record<string, unknown> = {};
    o['self'] = o;
    expect(fieldProbes([L('eq', o)])).toEqual([o, F]);
  });
  it('numeric cell midpoint with huge thresholds', () => {
    expect(fieldProbes([L('lt', 0), L('lt', 4)])).toEqual([-1, 0, 2, 4, 5, F]);
  });
});

describe('tightenInterval', () => {
  const iv = (lo: number, loI: boolean, hi: number, hiI: boolean) => ({ lo, loInclusive: loI, hi, hiInclusive: hiI });
  it('non-finite operand returns the same object', () => {
    const base = iv(0, true, 5, true);
    expect(tightenInterval(base, 'eq', 'x')).toBe(base);
    expect(tightenInterval(base, 'lt', NaN)).toBe(base);
    expect(tightenInterval(base, 'lt', Infinity)).toBe(base);
  });
  it('does not mutate input', () => {
    const base = iv(0, false, 5, false);
    tightenInterval(base, 'eq', 2);
    expect(base).toEqual(iv(0, false, 5, false));
  });
  it('eq', () => {
    expect(tightenInterval(FULL_INTERVAL, 'eq', 3)).toEqual(iv(3, true, 3, true));
    expect(tightenInterval(iv(0, false, 5, false), 'eq', 0)).toEqual(iv(0, true, 0, true));
    expect(tightenInterval(iv(0, true, 5, true), 'eq', 0)).toEqual(iv(0, true, 0, true));
    expect(tightenInterval(iv(0, false, 5, false), 'eq', 5)).toEqual(iv(5, true, 5, true));
    expect(tightenInterval(iv(0, true, 5, true), 'eq', 5)).toEqual(iv(5, true, 5, true));
    expect(tightenInterval(iv(1, false, 5, false), 'eq', 0)).toEqual(iv(1, false, 0, true));
    expect(tightenInterval(iv(1, false, 5, false), 'eq', 9)).toEqual(iv(9, true, 5, false));
    expect(tightenInterval(iv(1, false, 5, false), 'eq', 3)).toEqual(iv(3, true, 3, true));
  });
  it('gte', () => {
    expect(tightenInterval(iv(0, false, 9, false), 'gte', 3)).toEqual(iv(3, true, 9, false));
    expect(tightenInterval(iv(3, false, 9, false), 'gte', 3)).toEqual(iv(3, false, 9, false));
    expect(tightenInterval(iv(3, true, 9, false), 'gte', 3)).toEqual(iv(3, true, 9, false));
    expect(tightenInterval(iv(3, true, 9, false), 'gte', 1)).toEqual(iv(3, true, 9, false));
  });
  it('gt', () => {
    expect(tightenInterval(iv(0, false, 9, false), 'gt', 3)).toEqual(iv(3, false, 9, false));
    expect(tightenInterval(iv(3, true, 9, false), 'gt', 3)).toEqual(iv(3, false, 9, false));
    expect(tightenInterval(iv(3, false, 9, false), 'gt', 3)).toEqual(iv(3, false, 9, false));
    expect(tightenInterval(iv(3, true, 9, false), 'gt', 1)).toEqual(iv(3, true, 9, false));
  });
  it('lte', () => {
    expect(tightenInterval(iv(0, false, 9, false), 'lte', 3)).toEqual(iv(0, false, 3, true));
    expect(tightenInterval(iv(0, false, 3, false), 'lte', 3)).toEqual(iv(0, false, 3, false));
    expect(tightenInterval(iv(0, false, 3, true), 'lte', 3)).toEqual(iv(0, false, 3, true));
    expect(tightenInterval(iv(0, false, 3, true), 'lte', 8)).toEqual(iv(0, false, 3, true));
  });
  it('lt', () => {
    expect(tightenInterval(iv(0, false, 9, false), 'lt', 3)).toEqual(iv(0, false, 3, false));
    expect(tightenInterval(iv(0, false, 3, true), 'lt', 3)).toEqual(iv(0, false, 3, false));
    expect(tightenInterval(iv(0, false, 3, false), 'lt', 3)).toEqual(iv(0, false, 3, false));
    expect(tightenInterval(iv(0, false, 3, true), 'lt', 8)).toEqual(iv(0, false, 3, true));
  });
  it('other ops are no-ops (copy)', () => {
    const base = iv(0, true, 5, true);
    const r = tightenInterval(base, 'ne', 2);
    expect(r).toEqual(base);
    expect(r).not.toBe(base);
  });
});

describe('intervalEmpty', () => {
  it('cases', () => {
    expect(intervalEmpty({ lo: 2, loInclusive: true, hi: 1, hiInclusive: true })).toBe(true);
    expect(intervalEmpty({ lo: 1, loInclusive: true, hi: 1, hiInclusive: true })).toBe(false);
    expect(intervalEmpty({ lo: 1, loInclusive: false, hi: 1, hiInclusive: true })).toBe(true);
    expect(intervalEmpty({ lo: 1, loInclusive: true, hi: 1, hiInclusive: false })).toBe(true);
    expect(intervalEmpty({ lo: 1, loInclusive: false, hi: 1, hiInclusive: false })).toBe(true);
    expect(intervalEmpty({ lo: 1, loInclusive: false, hi: 2, hiInclusive: false })).toBe(false);
    expect(intervalEmpty(FULL_INTERVAL)).toBe(false);
  });
});

describe('numericConjunctionSatisfiable', () => {
  it('cases', () => {
    expect(numericConjunctionSatisfiable([])).toBe(true);
    expect(numericConjunctionSatisfiable([L('gt', 5), L('lt', 5)])).toBe(false);
    expect(numericConjunctionSatisfiable([L('gte', 5), L('lte', 5)])).toBe(true);
    expect(numericConjunctionSatisfiable([L('gt', 5), L('lte', 5)])).toBe(false);
    expect(numericConjunctionSatisfiable([L('eq', 5), L('eq', 6)])).toBe(false);
    expect(numericConjunctionSatisfiable([L('gt', 5), L('lt', 4, { ref: 'env.y' })])).toBe(true);
    expect(numericConjunctionSatisfiable([L('gt', 5), { any_of: [L('lt', 4)] } as Condition])).toBe(true);
    expect(numericConjunctionSatisfiable([L('gt', 5), L('lt', 'x')])).toBe(true);
  });
});
