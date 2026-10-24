/* eslint-disable @typescript-eslint/no-explicit-any */
// The Dafny JS runtime fix (src/runtime.ts): Seq.Concat copies with a loop, so a long sequence no longer overflows the stack.
import { describe, expect, it } from 'vitest';
import { hardenDafnyRuntime } from '../src/runtime';
import { wireAcceptsText, wireCanonicalOfText } from '../src/ext-wire';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const fresh = (): any => {
  // a private copy of a generated module (and so of its runtime), not hardened yet
  const p = require.resolve('../generated/pca_merkle.js');
  delete require.cache[p];
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const m = require('../generated/pca_merkle.js');
  delete require.cache[p];
  return m._dafny;
};

describe('hardenDafnyRuntime', () => {
  it('the stock runtime overflows the stack on a long concatenation; the hardened one does not and gives the same result', () => {
    const d = fresh();
    const big = d.Seq.of();
    for (let i = 0; i < 1_000_000; i++) big.push(i);
    expect(() => d.Seq.Concat(big, d.Seq.of(1))).toThrow(RangeError);
    const stock = d.Seq.Concat;
    expect(hardenDafnyRuntime(d)).toBe(d);
    expect(d.Seq.Concat).not.toBe(stock);
    const r = d.Seq.Concat(big, d.Seq.of(-1, -2));
    expect(r).toBeInstanceOf(d.Seq);
    expect(r.length).toBe(1_000_002);
    expect([r[0], r[999_999], r[1_000_000], r[1_000_001]]).toEqual([0, 999_999, -1, -2]);
    expect(big.length).toBe(1_000_000); // operands untouched
    // small inputs: identical to the stock implementation, including empty operands and the string branch
    for (const [a, b] of [[d.Seq.of(), d.Seq.of()], [d.Seq.of(1, 2), d.Seq.of()], [d.Seq.of(), d.Seq.of(3)], [d.Seq.of(1), d.Seq.of(2, 3)]]) {
      const h = d.Seq.Concat(a, b);
      const s = stock(a, b);
      expect(h).toBeInstanceOf(d.Seq);
      expect([...h]).toEqual([...s]);
      expect(h).not.toBe(a);
      expect(h).not.toBe(b);
    }
    expect(d.Seq.Concat('ab', 'c')).toBe('abc');
    expect(d.Seq.Concat(d.Seq.of('a', 'b'), 'c')).toBe(stock(d.Seq.of('a', 'b'), 'c'));
    expect(d.Seq.Concat('a', d.Seq.of('b', 'c'))).toBe(stock('a', d.Seq.of('b', 'c')));
  });
  it('is idempotent and ignores a value without a Seq class', () => {
    const d = fresh();
    hardenDafnyRuntime(d);
    const once = d.Seq.Concat;
    hardenDafnyRuntime(d);
    expect(d.Seq.Concat).toBe(once);
    expect(hardenDafnyRuntime(undefined)).toBeUndefined();
    const o = { Seq: 5 };
    expect(hardenDafnyRuntime(o)).toBe(o);
  });
});

describe('the proved strict-JSON parser at the profile maximum (1 MiB)', () => {
  it('accepts a maximum-size string and rejects one byte more, without exhausting the stack', () => {
    expect(wireAcceptsText('"' + 'a'.repeat((1 << 20) - 2) + '"')).toBe(true);
    expect(wireAcceptsText('"' + 'a'.repeat((1 << 20) - 1) + '"')).toBe(false);
  });
  it('wireAcceptsText is the acceptance of wireCanonicalOfText', () => {
    for (const t of ['{"b":1,"a":[true,null,"é"]}', '{"a":1,"a":2}', '[1,]', '1.0', '"\\ud800"', ' [ ] ', '']) {
      expect(wireAcceptsText(t), t).toBe(wireCanonicalOfText(t) !== undefined);
    }
  });
});
