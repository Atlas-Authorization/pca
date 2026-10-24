import { describe, expect, it } from 'vitest';
import { fastCheck, overlappingTrues, prune, step, type Op } from './model';
import { DEFAULT_SEARCH_BUDGET, searchLinearizable } from './search';

let n = 0;
/** advance-style op (lo = w = v) unless w is given. ret Infinity for unknown. */
export function op(res: Op['res'], lo: number, call: number, ret: number, w = lo, kind: Op['kind'] = 'advance'): Op {
  return { client: `c${n++}`, kind, key: 'k', lo, w, call, ret: res === 'unknown' ? Infinity : ret, res };
}

describe('step (the register model)', () => {
  it('TRUE: legal only from s < lo, moves to max(s, w)', () => {
    expect(step(-Infinity, op('true', 5, 0, 1, 9))).toEqual([9]);
    expect(step(3, op('true', 5, 0, 1, 9))).toEqual([9]);
    expect(step(5, op('true', 5, 0, 1, 9))).toEqual([]);
    expect(step(7, op('true', 5, 0, 1, 9))).toEqual([]);
  });
  it('FALSE: legal only from s >= lo, leaves s', () => {
    expect(step(-Infinity, op('false', 5, 0, 1))).toEqual([]);
    expect(step(4, op('false', 5, 0, 1))).toEqual([]);
    expect(step(5, op('false', 5, 0, 1))).toEqual([5]);
    expect(step(8, op('false', 5, 0, 1))).toEqual([8]);
  });
  it('UNKNOWN: from s < lo either effect; from s >= lo none', () => {
    expect(step(3, op('unknown', 5, 0, 0, 9))).toEqual([3, 9]);
    expect(step(5, op('unknown', 5, 0, 0, 9))).toEqual([5]);
  });
});

describe('overlappingTrues', () => {
  it('finds two definite TRUEs whose [lo, w] intervals overlap (boundary inclusive), in lo order', () => {
    const a = op('true', 5, 0, 1, 9, 'consume');
    const b = op('true', 9, 2, 3, 12, 'consume');
    expect(overlappingTrues([b, a])).toEqual([a, b]);
    const c = op('true', 10, 2, 3, 12, 'consume');
    expect(overlappingTrues([c, a])).toBeUndefined();
    expect(overlappingTrues([op('true', 4, 0, 1), op('true', 4, 5, 6)])).toHaveLength(2);
  });
  it('ignores FALSE and unknown answers, and an empty history', () => {
    expect(overlappingTrues([])).toBeUndefined();
    expect(overlappingTrues([op('true', 4, 0, 1), op('unknown', 4, 0, 0), op('false', 4, 2, 3)])).toBeUndefined();
  });
  it('compares every neighbour, not only the first pair', () => {
    const xs = [op('true', 1, 0, 1), op('true', 2, 0, 1), op('true', 3, 0, 1), op('true', 3, 4, 5)];
    expect(overlappingTrues(xs)).toEqual([xs[2], xs[3]]);
  });
});

describe('prune', () => {
  it('drops a FALSE explained by a TRUE (w >= lo) that returned strictly before it was invoked', () => {
    const t = op('true', 9, 0, 2);
    const f = op('false', 9, 3, 4);
    expect(prune([t, f])).toEqual([t]);
    expect(prune([t, op('false', 5, 3, 4)])).toEqual([t]); // w > lo
  });
  it('keeps a FALSE the TRUE cannot explain: w < lo, returned at or after the call, or not definite', () => {
    const t = op('true', 9, 0, 2);
    for (const f of [op('false', 10, 3, 4), op('false', 9, 2, 4), op('false', 9, 1, 4)]) expect(prune([t, f])).toEqual([t, f]);
    const u = op('unknown', 9, 0, 0);
    const f = op('false', 9, 3, 4);
    expect(prune([u, f])).toEqual([u, f]);
    const g = op('false', 9, 3, 4);
    const tf = op('false', 9, 0, 1);
    expect(prune([tf, g])).toEqual([tf, g]);
  });
  it('uses the largest w among the TRUEs that returned before (prefix maximum, in return order)', () => {
    const big = op('true', 10, 0, 1);
    const small = op('true', 3, 0, 2);
    const late = op('true', 50, 0, 9);
    const f = op('false', 8, 5, 6);
    expect(prune([late, small, f, big])).toEqual([late, small, big]);
    // the late TRUE (returned after the call) does not count
    expect(prune([late, small, f])).toEqual([late, small, f]);
  });
  it('is a no-op without TRUEs', () => {
    const xs = [op('false', 1, 0, 1), op('unknown', 2, 0, 0)];
    expect(prune(xs)).toEqual(xs);
  });
});

describe('fastCheck (exact, no unknown outcome)', () => {
  it('abstains when an outcome is unknown', () => {
    expect(fastCheck([op('true', 1, 0, 1), op('unknown', 2, 0, 0)])).toBeUndefined();
  });
  it('accepts the empty history and a legal one', () => {
    expect(fastCheck([])).toBe(true);
    expect(fastCheck([op('true', 1, 0, 2), op('false', 1, 1, 3), op('true', 4, 2, 5), op('false', 3, 6, 7)])).toBe(true);
  });
  it('refuses overlapping TRUEs', () => {
    expect(fastCheck([op('true', 2, 0, 1), op('true', 2, 3, 4)])).toBe(false);
    expect(fastCheck([op('true', 2, 0, 1, 5, 'consume'), op('true', 5, 3, 4, 8, 'consume')])).toBe(false);
  });
  it('refuses a TRUE order that real time forbids, and accepts the boundary t == ret', () => {
    // value order forces 1 before 5, but advance(5) returned before advance(1) was invoked
    expect(fastCheck([op('true', 5, 10, 11), op('true', 1, 12, 13)])).toBe(false);
    // advance(1) invoked at 10, advance(5) must come after it: t = 10 == its return
    expect(fastCheck([op('true', 1, 10, 12), op('true', 5, 0, 10)])).toBe(true);
  });
  it('a FALSE needs a TRUE with w >= lo whose earliest point is not after the FALSE returned', () => {
    expect(fastCheck([op('false', 5, 0, 1), op('true', 9, 2, 3)])).toBe(false);
    expect(fastCheck([op('false', 5, 0, 2), op('true', 9, 2, 3)])).toBe(true);
    expect(fastCheck([op('false', 5, 0, 9), op('true', 4, 0, 1)])).toBe(false);
    expect(fastCheck([op('false', 5, 5, 9), op('true', 4, 0, 1), op('true', 7, 0, 1)])).toBe(true);
    expect(fastCheck([op('false', 5, 0, 9)])).toBe(false);
  });
  it('the earliest point carries forward: a later-valued TRUE cannot linearize before an earlier-valued one', () => {
    // 1 must precede 5; 1 is invoked at 8, so 5's earliest point is 8 > its return 6
    expect(fastCheck([op('true', 1, 8, 9), op('true', 5, 0, 6)])).toBe(false);
  });
});

describe('searchLinearizable', () => {
  it('decides the empty history and simple ones', () => {
    expect(searchLinearizable([])).toBe('ok');
    expect(searchLinearizable([op('true', 1, 0, 1)])).toBe('ok');
    expect(searchLinearizable([op('false', 1, 0, 1)])).toBe('violation');
    expect(DEFAULT_SEARCH_BUDGET).toBe(200_000);
  });
  it('lets an operation invoked exactly when another returned linearize before it (real-time order is strict)', () => {
    // 3 must precede 5; advance(3) is invoked at 5, the instant advance(5) returned: still concurrent
    expect(searchLinearizable([op('true', 5, 0, 5), op('true', 3, 5, 6)])).toBe('ok');
    expect(searchLinearizable([op('true', 5, 0, 4), op('true', 3, 5, 6)])).toBe('violation');
  });
  it('considers every pending operation, not only the first one invoked', () => {
    expect(searchLinearizable([op('true', 9, 0, 10), op('true', 2, 1, 10), op('false', 2, 1, 10)])).toBe('ok');
  });
  it('an unknown outcome may or may not have taken effect, at any time after its invocation', () => {
    expect(searchLinearizable([op('unknown', 4, 0, 0), op('false', 4, 10, 11)])).toBe('ok');
    expect(searchLinearizable([op('unknown', 4, 0, 0), op('true', 4, 10, 11)])).toBe('ok');
    expect(searchLinearizable([op('unknown', 4, 5, 0), op('false', 4, 0, 1)])).toBe('violation');
  });
  it('is budgeted: over the budget the verdict is unresolved, never ok', () => {
    const h = [op('true', 1, 0, 1), op('true', 2, 2, 3)];
    expect(searchLinearizable(h, 0)).toBe('unresolved');
    expect(searchLinearizable(h, 1)).toBe('unresolved');
    expect(searchLinearizable(h, 2)).toBe('ok');
    expect(searchLinearizable([op('false', 1, 0, 1)], 1)).toBe('violation');
    expect(searchLinearizable([op('false', 1, 0, 1)], 0)).toBe('unresolved');
  });
  it('memoizes (set, state): a wide illegal history is refuted without enumerating orders', () => {
    const h = Array.from({ length: 13 }, (_, i) => op('unknown', 1 + (i % 2), 0, 0));
    h.push(op('false', 99, 0, 100));
    expect(searchLinearizable(h)).toBe('violation');
  }, 20_000);
});
