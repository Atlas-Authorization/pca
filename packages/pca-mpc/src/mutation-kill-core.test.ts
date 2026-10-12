import { describe, expect, it } from 'vitest';
import { FieldRng, PRIME, fadd, fmul, fneg, fsub, mod } from './field';
import {
  MAX_PARTIES, addPublicSV, addSV, negSV, notBitSV, reconstruct, scaleSV, share, shareConstant, subSV,
} from './sharing';
import { beaverMul, genTriple, genTriples, type OpenedMsg } from './beaver';
import { thermometerDecode, thermometerEncode } from './thermometer';
import { assertDecisionVectors, composeClear } from './compose';
import { composeSecure } from './runner';
import { quantizeR } from './party';

const MASK64 = (1n << 64n) - 1n;
/** Independent SplitMix64 reference. */
function splitmix(seed: bigint): () => bigint {
  let s = seed & MASK64;
  return () => {
    s = (s + 0x9e3779b97f4a7c15n) & MASK64;
    let z = s;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
    return (z ^ (z >> 31n)) & MASK64;
  };
}

describe('field', () => {
  it('mod handles negatives, zero and multiples', () => {
    expect(mod(-1n)).toBe(PRIME - 1n);
    expect(mod(0n)).toBe(0n);
    expect(mod(-PRIME)).toBe(0n);
    expect(mod(PRIME)).toBe(0n);
    expect(mod(PRIME + 5n)).toBe(5n);
    expect(mod(-PRIME - 5n)).toBe(PRIME - 5n);
  });
  it('fadd/fsub/fmul/fneg', () => {
    expect(fadd(PRIME - 1n, 2n)).toBe(1n);
    expect(fsub(1n, 2n)).toBe(PRIME - 1n);
    expect(fsub(5n, 2n)).toBe(3n);
    expect(fmul(PRIME - 1n, PRIME - 1n)).toBe(1n);
    expect(fmul(3n, 4n)).toBe(12n);
    expect(fneg(1n)).toBe(PRIME - 1n);
    expect(fneg(0n)).toBe(0n);
  });
  it('FieldRng follows the SplitMix64 stream reduced mod p (default and explicit seeds)', () => {
    for (const seed of [undefined, 0n, 12345n, (1n << 70n) + 9n]) {
      const rng = seed === undefined ? new FieldRng() : new FieldRng(seed);
      const ref = splitmix(seed === undefined ? 0x243f6a8885a308d3n : seed);
      for (let i = 0; i < 20; i++) expect(rng.next()).toBe(ref() % PRIME);
    }
  });
  it('FieldRng rejects draws at/above the largest multiple of p (2^64 - 8)', () => {
    const limit = 2n ** 64n - 8n;
    const draws = [limit, MASK64, limit - 1n];
    const rng = new FieldRng(1n) as unknown as { next(): bigint; nextU64(): bigint };
    rng.nextU64 = () => draws.shift()!;
    expect(rng.next()).toBe((limit - 1n) % PRIME);
    expect(draws.length).toBe(0);
    const d2 = [PRIME + 7n];
    rng.nextU64 = () => d2.shift()!;
    expect(rng.next()).toBe(7n);
  });
});

describe('sharing', () => {
  it('share validates n with the exact bounds and message', () => {
    const rng = new FieldRng(1n);
    for (const n of [0, -1, 1.5, NaN, MAX_PARTIES + 1, Infinity]) {
      expect(() => share(5n, n, rng)).toThrow(`share: n must be an integer in [1, ${MAX_PARTIES}]`);
      expect(() => shareConstant(5n, n)).toThrow(`shareConstant: n must be an integer in [1, ${MAX_PARTIES}]`);
    }
    expect(MAX_PARTIES).toBe(1024);
    expect(share(5n, 1, rng)).toEqual([5n]);
    expect(share(5n, MAX_PARTIES, rng)).toHaveLength(MAX_PARTIES);
    expect(shareConstant(5n, MAX_PARTIES)).toHaveLength(MAX_PARTIES);
    expect(shareConstant(5n, 1)).toEqual([5n]);
  });
  it('share: first n-1 uniform from rng in order, last is the complement, secret reduced', () => {
    const ref = new FieldRng(9n);
    const a = ref.next(), b = ref.next();
    const s = share(PRIME + 10n, 3, new FieldRng(9n));
    expect(s).toEqual([a, b, mod(10n - a - b)]);
    expect(reconstruct(s)).toBe(10n);
    expect(reconstruct(share(-1n, 4, new FieldRng(2n)))).toBe(PRIME - 1n);
  });
  it('reconstruct fails closed with exact messages', () => {
    expect(() => reconstruct([])).toThrow('reconstruct: no shares (fail closed)');
    expect(() => reconstruct([1n, undefined, 2n])).toThrow('reconstruct: missing share (fail closed)');
    expect(() => reconstruct([undefined])).toThrow('reconstruct: missing share (fail closed)');
    expect(reconstruct([PRIME - 1n, 3n])).toBe(2n);
    expect(reconstruct([7n])).toBe(7n);
  });
  it('shareConstant puts the (reduced) constant on party 0 only', () => {
    expect(shareConstant(PRIME + 4n, 3)).toEqual([4n, 0n, 0n]);
    expect(shareConstant(-1n, 2)).toEqual([PRIME - 1n, 0n]);
  });
  it('linear ops are exact and non-mutating', () => {
    const x = [PRIME - 1n, 5n, 7n], y = [3n, 6n, 9n];
    const xc = x.slice(), yc = y.slice();
    expect(addSV(x, y)).toEqual([2n, 11n, 16n]);
    expect(subSV(x, y)).toEqual([PRIME - 4n, PRIME - 1n, PRIME - 2n]);
    expect(negSV(x)).toEqual([1n, PRIME - 5n, PRIME - 7n]);
    expect(scaleSV(x, 3n)).toEqual([PRIME - 3n, 15n, 21n]);
    expect(addPublicSV(x, 4n)).toEqual([3n, 5n, 7n]);
    expect(addPublicSV(x, -1n)).toEqual([PRIME - 2n, 5n, 7n]);
    expect(addPublicSV(x, PRIME + 4n)).toEqual([3n, 5n, 7n]);
    expect(x).toEqual(xc);
    expect(y).toEqual(yc);
    expect(notBitSV([1n, 0n])).toEqual([0n, 0n]);
    expect(reconstruct(notBitSV([0n, 0n]))).toBe(1n);
    expect(reconstruct(notBitSV([1n, 0n]))).toBe(0n);
  });
  it('mismatched lengths are refused', () => {
    expect(() => addSV([1n], [1n, 2n])).toThrow('shared values must have the same party count');
    expect(() => subSV([1n, 2n], [1n])).toThrow('shared values must have the same party count');
    expect(() => addSV([1n, 2n], [1n, 2n])).not.toThrow();
  });
});

describe('beaver', () => {
  it('genTriples returns count triples that multiply correctly', () => {
    const rng = new FieldRng(5n);
    expect(genTriples(0, 3, rng)).toEqual([]);
    const ts = genTriples(4, 3, rng);
    expect(ts).toHaveLength(4);
    for (const t of ts) {
      expect(t.a).toHaveLength(3);
      expect(reconstruct(t.c)).toBe(fmul(reconstruct(t.a), reconstruct(t.b)));
    }
  });
  it('genTriple draws a, b first then shares a, b, c in order', () => {
    const ref = new FieldRng(11n);
    const a = ref.next(), b = ref.next();
    const ea = share(a, 2, ref), eb = share(b, 2, ref), ec = share(fmul(a, b), 2, ref);
    expect(genTriple(2, new FieldRng(11n))).toEqual({ a: ea, b: eb, c: ec });
  });
  it('beaverMul multiplies, records d then e, and refuses shape mismatches', () => {
    const rng = new FieldRng(21n);
    for (const n of [1, 2, 3, 5]) {
      const x = share(1234567n, n, rng), y = share(PRIME - 3n, n, rng);
      const t = genTriple(n, rng);
      const tr: OpenedMsg[] = [];
      const z = beaverMul(x, y, t, tr);
      expect(reconstruct(z)).toBe(fmul(1234567n, PRIME - 3n));
      expect(tr.map((m) => m.label)).toEqual(['d', 'e']);
      expect(tr[0]!.value).toBe(fsub(1234567n, reconstruct(t.a)));
      expect(tr[1]!.value).toBe(fsub(PRIME - 3n, reconstruct(t.b)));
      expect(tr[0]!.shares).toEqual(subSV(x, t.a));
      expect(tr[1]!.shares).toEqual(subSV(y, t.b));
      expect(reconstruct(beaverMul(x, y, t))).toBe(reconstruct(z));
    }
    const t3 = genTriple(3, rng);
    expect(() => beaverMul([1n, 2n], [1n, 2n, 3n], t3)).toThrow('beaverMul: operand party counts differ');
    for (const k of ['a', 'b', 'c'] as const) {
      const bad = { ...t3, [k]: [1n, 2n] };
      expect(() => beaverMul([1n, 2n, 3n], [1n, 2n, 3n], bad)).toThrow('beaverMul: triple party count differs from the operands');
      const bad2 = { ...t3, [k]: 'abc' } as never;
      expect(() => beaverMul([1n, 2n, 3n], [1n, 2n, 3n], bad2)).toThrow('beaverMul: triple party count differs from the operands');
    }
  });
  it('the public d*e term lives on party 0 only', () => {
    const t = { a: [0n, 0n], b: [0n, 0n], c: [0n, 0n] };
    expect(beaverMul([3n, 0n], [4n, 0n], t)).toEqual([12n, 0n]);
    expect(beaverMul([0n, 3n], [0n, 4n], t)).toEqual([12n, 0n]);
  });
});

describe('thermometer', () => {
  it('encode clamps, truncates and validates M', () => {
    expect(thermometerEncode(2, 3)).toEqual([1, 1, 0]);
    expect(thermometerEncode(0, 3)).toEqual([0, 0, 0]);
    expect(thermometerEncode(3, 3)).toEqual([1, 1, 1]);
    expect(thermometerEncode(9, 3)).toEqual([1, 1, 1]);
    expect(thermometerEncode(-4, 3)).toEqual([0, 0, 0]);
    expect(thermometerEncode(2.9, 3)).toEqual([1, 1, 0]);
    expect(thermometerEncode(-0.5, 3)).toEqual([0, 0, 0]);
    expect(thermometerEncode(1, 0)).toEqual([]);
    for (const M of [-1, 1.5, NaN]) expect(() => thermometerEncode(1, M)).toThrow('thermometerEncode: M must be a non-negative integer');
  });
  it('decode counts exactly the 1 / 1n entries', () => {
    expect(thermometerDecode([1, 1, 0])).toBe(2);
    expect(thermometerDecode([1n, 1n, 0n])).toBe(2);
    expect(thermometerDecode([2, 0, 1n, 0n, -1])).toBe(1);
    expect(thermometerDecode([])).toBe(0);
  });
});

describe('party.quantizeR', () => {
  it('rounds, clamps and maps non-finite to Q', () => {
    expect(quantizeR(0.5)).toBe(50);
    expect(quantizeR(0.004)).toBe(0);
    expect(quantizeR(0.005)).toBe(1);
    expect(quantizeR(0.126, 10)).toBe(1);
    expect(quantizeR(0.15, 10)).toBe(2);
    expect(quantizeR(-3)).toBe(0);
    expect(quantizeR(7)).toBe(100);
    expect(quantizeR(1, 7)).toBe(7);
    expect(quantizeR(NaN)).toBe(100);
    expect(quantizeR(Infinity, 9)).toBe(9);
    expect(quantizeR(-Infinity, 9)).toBe(9);
  });
});

describe('compose', () => {
  const v = (allow: 0 | 1, t: 1 | 2 | 3, rQuant: number) => ({ allow, t, rQuant });
  it('assertDecisionVectors: each check with exact message', () => {
    expect(() => assertDecisionVectors('x' as never, 100)).toThrow(new TypeError('decision vectors must be an array'));
    expect(() => assertDecisionVectors([null as never], 100)).toThrow(new TypeError('party 0: decision vector must be an object'));
    expect(() => assertDecisionVectors([v(1, 1, 0), 5 as never], 100)).toThrow(new TypeError('party 1: decision vector must be an object'));
    expect(() => assertDecisionVectors([{ ...v(1, 1, 0), allow: 2 as never }], 100)).toThrow(new RangeError('party 0: allow must be 0 or 1'));
    expect(() => assertDecisionVectors([{ ...v(1, 1, 0), t: 0 as never }], 100)).toThrow(new RangeError('party 0: t must be 1, 2 or 3'));
    expect(() => assertDecisionVectors([{ ...v(1, 1, 0), t: 4 as never }], 100)).toThrow(new RangeError('party 0: t must be 1, 2 or 3'));
    expect(() => assertDecisionVectors([v(1, 1, -1)], 100)).toThrow(new RangeError('party 0: rQuant must be an integer in [0, 100]'));
    expect(() => assertDecisionVectors([v(1, 1, 101)], 100)).toThrow(new RangeError('party 0: rQuant must be an integer in [0, 100]'));
    expect(() => assertDecisionVectors([v(1, 1, 1.5)], 100)).toThrow(new RangeError('party 0: rQuant must be an integer in [0, 100]'));
    expect(() => assertDecisionVectors([v(1, 1, 10)], 10)).not.toThrow();
    expect(() => assertDecisionVectors([v(1, 1, 0), v(0, 3, 100)], 100)).not.toThrow();
    expect(() => assertDecisionVectors([], 100)).not.toThrow();
  });
  it('composeClear: AND of allow, max t, max rQuant; empty fails closed', () => {
    expect(() => composeClear([])).toThrow('composeClear: no parties (fail closed)');
    expect(composeClear([v(1, 1, 0)])).toEqual(v(1, 1, 0));
    expect(composeClear([v(1, 2, 5), v(1, 3, 40), v(1, 1, 7)])).toEqual(v(1, 3, 40));
    expect(composeClear([v(1, 1, 5), v(0, 1, 5), v(1, 1, 5)])).toEqual(v(0, 1, 5));
    expect(composeClear([v(0, 1, 0)])).toEqual(v(0, 1, 0));
    expect(composeClear([v(1, 2, 3), v(1, 1, 9)])).toEqual(v(1, 2, 9));
    expect(composeClear([v(1, 1, 3)], 3)).toEqual(v(1, 1, 3));
    expect(() => composeClear([v(1, 1, 4)], 3)).toThrow('rQuant must be an integer in [0, 3]');
  });
});

describe('runner.composeSecure', () => {
  const v = (allow: 0 | 1, t: 1 | 2 | 3, rQuant: number) => ({ allow, t, rQuant });
  it('matches composeClear and records the transcript structure', () => {
    const vs = [v(1, 2, 4), v(1, 1, 2), v(1, 3, 3)];
    const r = composeSecure(vs, { Q: 5, seed: 3n });
    expect(r.composed).toEqual(composeClear(vs, 5));
    expect(r.parties).toBe(3);
    expect(r.Q).toBe(5);
    // allow: n-1 mults; t: 3 positions * (n-1); r: Q positions * (n-1)
    expect(r.multiplications).toBe(2 + 3 * 2 + 5 * 2);
    expect(r.opened).toHaveLength(2 * r.multiplications);
    expect(r.sharings).toHaveLength(3 + 3 * 3 + 5 * 3);
    expect(r.sharings[0]).toMatchObject({ label: 'p0.allow', party: 0, secret: 1n });
    expect(r.sharings[3]).toMatchObject({ label: 'p0.t.ge1', party: 0 });
    expect(r.sharings.map((s) => s.label)).toContain('p2.r.ge5');
    expect(r.sharings.find((s) => s.label === 'p1.r.ge3')!.secret).toBe(0n);
    expect(r.sharings.find((s) => s.label === 'p1.r.ge2')!.secret).toBe(1n);
    expect(r.sharings.find((s) => s.label === 'p1.t.ge1')!.secret).toBe(1n);
    expect(r.sharings.find((s) => s.label === 'p1.t.ge2')!.secret).toBe(0n);
    expect(r.views).toHaveLength(3);
    r.views.forEach((view, p) => {
      expect(view.party).toBe(p);
      expect(view.heldShares).toEqual(r.sharings.map((s) => s.shares[p]));
      expect(view.opened).toBe(r.opened);
      expect(view.output).toBe(r.composed);
    });
    for (const s of r.sharings) expect(reconstruct(s.shares)).toBe(s.secret);
  });
  it('is reproducible under a seed, and varies without one', () => {
    const vs = [v(1, 1, 1), v(1, 1, 1)];
    expect(composeSecure(vs, { seed: 7n }).sharings).toEqual(composeSecure(vs, { seed: 7n }).sharings);
    expect(composeSecure(vs, { seed: 7n }).sharings).not.toEqual(composeSecure(vs, { seed: 8n }).sharings);
    expect(composeSecure(vs, { seed: 0n }).sharings).not.toEqual(composeSecure(vs, { seed: 7n }).sharings);
    expect(composeSecure(vs).sharings[0]!.shares).not.toEqual(composeSecure(vs).sharings[0]!.shares);
    expect(composeSecure(vs).Q).toBe(100);
  });
  it('single party needs no multiplications; empty and bad vectors fail closed', () => {
    const r = composeSecure([v(0, 3, 9)], { Q: 9, seed: 1n });
    expect(r.composed).toEqual(v(0, 3, 9));
    expect(r.multiplications).toBe(0);
    expect(r.opened).toEqual([]);
    expect(() => composeSecure([])).toThrow('composeSecure: no parties (fail closed)');
    expect(() => composeSecure([v(1, 1, 200)], { Q: 100 })).toThrow('rQuant must be an integer in [0, 100]');
  });
  it('t is clamped within 1..3 and denies compose with any deny', () => {
    for (const t of [1, 2, 3] as const) expect(composeSecure([v(1, t, 0), v(1, 1, 0)], { seed: 4n }).composed.t).toBe(t);
    expect(composeSecure([v(1, 1, 0), v(0, 1, 0), v(1, 1, 0)], { seed: 4n }).composed.allow).toBe(0);
    expect(composeSecure([v(1, 1, 0), v(1, 1, 0)], { seed: 4n }).composed.allow).toBe(1);
  });
});
