import { describe, expect, it, vi } from 'vitest';
import { b64u } from './hash';

const h = vi.hoisted(() => ({ calls: 0, make: null as null | ((i: number) => Uint8Array) }));
vi.mock('./hash', async (orig) => {
  const m = await orig<typeof import('./hash')>();
  return {
    ...m,
    hashCanonical: (v: unknown): string => {
      const o = v as { d?: string; i?: number };
      if (o !== null && typeof o === 'object' && o.d === 'atlas-pca/dp-stream/v1') {
        h.calls++;
        if (h.make !== null) return m.b64u(h.make(o.i as number));
      }
      return m.hashCanonical(v);
    },
  };
});

import { discreteLaplace, seededDraws, type Draws } from './read-vault';

const MAX = 100_000;
const reset = (make: null | ((i: number) => Uint8Array)) => {
  h.calls = 0;
  h.make = make;
};
const ones = (): Uint8Array => new Uint8Array(32).fill(255);

describe('seeded draw source', () => {
  it('gives up after exactly the step budget when every draw sits on the rejection bound', () => {
    reset(ones);
    // 2^48 mod 3 = 1, so the acceptance limit is 2^48 - 1 and every all-ones draw is rejected
    expect(() => seededDraws('s').uniform(3)).toThrow('uniform: no draw');
    expect(h.calls).toBe(MAX / 5);
    reset(null);
  });
  it('accepts the very last permitted draw and no earlier one is lost', () => {
    reset((i) => {
      const b = ones();
      if (i === MAX / 5 - 1) b.fill(0, 24, 30); // fifth draw of the last block
      return b;
    });
    expect(seededDraws('s').uniform(3)).toBe(0);
    expect(h.calls).toBe(MAX / 5);
    reset(null);
  });
  it('a bound that divides 2^48 accepts the largest draw', () => {
    reset(ones);
    expect(seededDraws('s').uniform(2)).toBe(1);
    reset(null);
  });
  it('yields five 48-bit values per block, in order, then fetches the next block', () => {
    reset((i) => {
      const b = new Uint8Array(32);
      for (let k = 0; k < 5; k++) b[k * 6 + 5] = i * 5 + k + 1;
      return b;
    });
    const d = seededDraws('s');
    expect(Array.from({ length: 12 }, () => d.uniform(2 ** 47))).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    expect(h.calls).toBe(3);
    reset(null);
  });
});

describe('discrete Laplace step budgets', () => {
  it('the inner Bernoulli loop stops after exactly the step budget', () => {
    reset(null);
    let n = 0;
    const d: Draws = { uniform: (bound) => (++n === 1 ? bound - 1 : 0) };
    expect(() => discreteLaplace(d, 1000, 1000)).toThrow('bernoulli: no termination');
    expect(n).toBe(1 + MAX);
  });
  it('the outer loop stops after exactly the step budget', () => {
    reset(null);
    let n = 0;
    const d: Draws = { uniform: (bound) => (n++ % 3 === 1 ? 0 : bound - 1) };
    expect(() => discreteLaplace(d, 1000, 1000)).toThrow('laplace: no sample');
    expect(n).toBe(3 * MAX);
  });
  it('the geometric loop stops once it passes the step budget', () => {
    reset(null);
    let threes = 0;
    const d: Draws = {
      uniform: (bound) => {
        if (bound === 3) {
          threes++;
          return 1;
        }
        return 0;
      },
    };
    expect(() => discreteLaplace(d, 1000, 1000)).toThrow('laplace: no termination');
    expect(threes).toBe(MAX + 1);
  });
  it('is unaffected by the hash mock for a normal seed', () => {
    reset(null);
    expect(b64u(new Uint8Array(1))).toBe('AA');
    expect(Number.isInteger(discreteLaplace(seededDraws('plain'), 500_000, 1_000_000))).toBe(true);
  });
});
