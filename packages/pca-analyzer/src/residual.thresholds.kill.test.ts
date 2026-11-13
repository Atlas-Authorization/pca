import { describe, expect, it } from 'vitest';
import { whatMayIDo } from './index';

// The capability envelope's numeric thresholds are collected into a list that holds numbers only: every array of numbers
// that is sorted while the envelope is built is checked before it is sorted (the sort order of a mixed list is unspecified).
describe('whatMayIDo: threshold lists hold only numbers', () => {
  it('a list of points', () => {
    const seen: unknown[][] = [];
    const orig = Array.prototype.sort;
    Array.prototype.sort = function (this: unknown[], fn?: (a: unknown, b: unknown) => number) {
      if (this.some((x) => typeof x === 'number')) seen.push([...this]);
      return orig.call(this, fn);
    } as typeof orig;
    try {
      whatMayIDo({ predicates: [{ verb: 'v', where: [{ field: 'action.params.n', op: 'in', value: [300, 100, 200] }] }] }, [{ verb: 'v', params: { n: { type: 'integer' } } }], {});
    } finally {
      Array.prototype.sort = orig;
    }
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.filter((a) => !a.every((x) => typeof x === 'number'))).toEqual([]);
  });
});
