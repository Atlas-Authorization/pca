import { describe, expect, it } from 'vitest';
import { accumColumn, bigToBytes, bytesToBig, maskTail, tmmoCrh, transpose32 } from './otx';

const words = (n: number, s: number) => Uint32Array.from({ length: n }, (_, i) => (Math.imul(i + 1, 2654435761) ^ Math.imul(s + 7, 40503)) >>> 0);

describe('bigToBytes / bytesToBig', () => {
  it('keeps exactly the low len little-endian bytes of a wider value', () => {
    expect([...bigToBytes(0x1234n, 1)]).toEqual([0x34]);
    expect([...bigToBytes(0x123456n, 2)]).toEqual([0x56, 0x34]);
    expect([...bigToBytes(0xabn, 3)]).toEqual([0xab, 0, 0]);
    expect([...bigToBytes(0n, 2)]).toEqual([0, 0]);
  });
  it('maps the empty byte string to zero and is little-endian', () => {
    expect(bytesToBig(new Uint8Array(0))).toBe(0n);
    expect(bytesToBig(Uint8Array.of(1, 2))).toBe(0x0201n);
    const input = Uint8Array.of(1, 2, 3);
    bytesToBig(input);
    expect([...input]).toEqual([1, 2, 3]);
  });
});

describe('maskTail', () => {
  const run = (nbits: number, len = 3) => { const c = new Uint32Array(len).fill(0xffffffff); maskTail(c, nbits); return [...c]; };
  it('keeps the low nbits bits and zeroes every later bit', () => {
    expect(run(0)).toEqual([0, 0, 0]);
    expect(run(1)).toEqual([1, 0, 0]);
    expect(run(31)).toEqual([0x7fffffff, 0, 0]);
    expect(run(32)).toEqual([0xffffffff, 0, 0]);
    expect(run(40)).toEqual([0xffffffff, 0xff, 0]);
    expect(run(64)).toEqual([0xffffffff, 0xffffffff, 0]);
    expect(run(65)).toEqual([0xffffffff, 0xffffffff, 1]);
    expect(run(96)).toEqual([0xffffffff, 0xffffffff, 0xffffffff]);
    expect(run(7, 1)).toEqual([0x7f]);
  });
  it('is idempotent and leaves already-clear bits alone', () => {
    const c = Uint32Array.of(0x0000ff00, 0x80000001);
    maskTail(c, 12);
    expect([...c]).toEqual([0x0f00, 0]);
  });
});

describe('transpose32', () => {
  it('only touches the 32 words at the offset', () => {
    const a = words(96, 1);
    const before = [...a];
    transpose32(a, 32);
    expect([...a].slice(0, 32)).toEqual(before.slice(0, 32));
    expect([...a].slice(64)).toEqual(before.slice(64));
    expect([...a].slice(32, 64)).not.toEqual(before.slice(32, 64));
    transpose32(a, 32);
    expect([...a]).toEqual(before);
  });
  it('leaves words after the matrix untouched when the matrix is at offset 0', () => {
    const a = words(64, 2);
    const before = [...a];
    transpose32(a, 0);
    expect([...a].slice(32)).toEqual(before.slice(32));
  });
});

describe('accumColumn', () => {
  it('adds nothing for an all-zero column, whatever chi holds', () => {
    const acc = new Uint32Array(4);
    accumColumn(new Uint32Array(2), words(4 * 64, 3), acc);
    expect([...acc]).toEqual([0, 0, 0, 0]);
  });
  it('xors chi[j] for exactly the set bits', () => {
    const chi = words(4 * 64, 4);
    const col = new Uint32Array(2);
    col[0] = (1 << 3) | (1 << 31);
    col[1] = 1 << 0;
    const acc = new Uint32Array(4);
    accumColumn(col, chi, acc);
    const want = [0, 0, 0, 0];
    for (const j of [3, 31, 32]) for (let k = 0; k < 4; k++) want[k] = (want[k]! ^ chi[j * 4 + k]!) >>> 0;
    expect([...acc]).toEqual(want);
  });
});

describe('tmmoCrh argument checks', () => {
  const rows = words(8, 5);
  it('rejects an invalid tweak offset with a precise message', () => {
    for (const offset of [-1, 1.5, NaN, Infinity, 2 ** 53]) {
      expect(() => tmmoCrh(rows, 2, { offset, domain: new Uint32Array(2) })).toThrow(new RangeError('tmmoCrh: tweak offset must be a non-negative safe integer'));
    }
    expect(() => tmmoCrh(rows, 2, { offset: 2 ** 53 - 1, domain: new Uint32Array(2) })).not.toThrow();
    expect(() => tmmoCrh(rows, 2, { offset: 0, domain: new Uint32Array(2) })).not.toThrow();
  });
  it('rejects a tweak domain that is not exactly 2 words', () => {
    for (const n of [0, 1, 3, 4]) {
      expect(() => tmmoCrh(rows, 2, { offset: 0, domain: new Uint32Array(n) })).toThrow(new RangeError('tmmoCrh: tweak domain must be 2 words'));
    }
  });
});
