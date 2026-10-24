/**
 * objective-risk.ts sorts canonical id lists with cmp (-1 / 1 / 0 over distinct strings). The ledger treats the "a > b" and
 * equal-key branch mutants of cmp as unobservable because V8's TimSort (Array.prototype.sort) consults a comparator result only as
 * `< 0` versus not. This test is that dependency made explicit: for every comparator variant that agrees on the sign test
 * (`< 0`), the sorted output is identical, over run-structured, rotated, reversed and duplicate-heavy arrays (the shapes that drive
 * binary insertion, run detection and galloping merges). If a V8 change ever makes the result depend on `> 0`, this fails first.
 */
import { describe, expect, it } from 'vitest';

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const notLess = (a: string, b: string): number => (a < b ? -1 : 0); // "a > b" collapsed into the equal branch
const big = (a: string, b: string): number => (a < b ? -1 : 7);
const small = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : -0.5 * 0);

let seed = 7;
const r = (): number => {
  seed = (seed * 1103515245 + 12345) & 0x7fffffff;
  return seed / 0x7fffffff;
};

describe('Array.prototype.sort depends on the comparator only through "< 0"', () => {
  it('cmp, a comparator returning 0 for "greater", and one returning 7 for "greater" sort identically', () => {
    for (let t = 0; t < 4000; t++) {
      const n = Math.floor(r() * r() * 400) + 1;
      const alpha = 1 + Math.floor(r() * 30);
      let a: string[] = Array.from({ length: n }, () => 'k' + Math.floor(r() * alpha));
      const mode = Math.floor(r() * 4);
      if (mode === 1) {
        a.sort(cmp);
        const m = Math.floor(r() * n);
        a = a.slice(m).concat(a.slice(0, m));
      } else if (mode === 2) {
        const runs = 1 + Math.floor(r() * 6);
        const w = Math.floor(n / runs) || 1;
        const b: string[] = [];
        for (let q = 0; q < runs; q++) b.push(...a.slice(q * w, (q + 1) * w).sort(cmp));
        a = b.concat(a.slice(runs * w));
      } else if (mode === 3) a = a.sort(cmp).reverse();
      const want = [...a].sort(cmp);
      expect([...a].sort(notLess)).toEqual(want);
      expect([...a].sort(big)).toEqual(want);
      expect([...a].sort(small)).toEqual(want);
    }
  });
});
