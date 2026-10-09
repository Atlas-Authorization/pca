import { describe, expect, it } from 'vitest';
import { FieldRng } from './field';
import { reconstruct, share } from './sharing';
import { composeClear } from './compose';
import { composeSecure } from './runner';
import { thermometerDecode, thermometerEncode } from './thermometer';
import type { DecisionVector } from './party';

describe('EDGE: composition semantics', () => {
  it('one party denies => composed deny (allow 0), regardless of others', () => {
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 2 },
      { allow: 0, t: 1, rQuant: 2 }, // the single deny
      { allow: 1, t: 1, rQuant: 2 },
    ];
    const got = composeSecure(vectors, { Q: 8, seed: 1n });
    expect(got.composed.allow).toBe(0);
  });

  it('all parties allow => composed allow 1', () => {
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 0 },
      { allow: 1, t: 1, rQuant: 0 },
      { allow: 1, t: 1, rQuant: 0 },
    ];
    expect(composeSecure(vectors, { Q: 8, seed: 1n }).composed.allow).toBe(1);
  });

  it('max threshold wins', () => {
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 0 },
      { allow: 1, t: 3, rQuant: 0 }, // strictest
      { allow: 1, t: 2, rQuant: 0 },
    ];
    expect(composeSecure(vectors, { Q: 8, seed: 5n }).composed.t).toBe(3);
  });

  it('max r wins (and boundary values 0 and Q)', () => {
    const Q = 8;
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 0 }, // min
      { allow: 1, t: 1, rQuant: Q }, // max
      { allow: 1, t: 1, rQuant: 3 },
    ];
    const got = composeSecure(vectors, { Q, seed: 6n });
    expect(got.composed.rQuant).toBe(Q);
    expect(got.composed).toEqual(composeClear(vectors));
  });

  it('r = 0 for all parties composes to 0', () => {
    const Q = 8;
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 0 },
      { allow: 1, t: 1, rQuant: 0 },
    ];
    expect(composeSecure(vectors, { Q, seed: 2n }).composed.rQuant).toBe(0);
  });

  it('single party (N=1): composition is that party\'s own vector (0 multiplications)', () => {
    const Q = 8;
    const v: DecisionVector = { allow: 1, t: 2, rQuant: 5 };
    const got = composeSecure([v], { Q, seed: 1n });
    expect(got.composed).toEqual({ allow: 1, t: 2, rQuant: 5 });
    expect(got.multiplications).toBe(0);
  });

  it('two parties, both deny but different t/r: deny with max t and max r', () => {
    const Q = 8;
    const vectors: DecisionVector[] = [
      { allow: 0, t: 2, rQuant: 4 },
      { allow: 0, t: 3, rQuant: 7 },
    ];
    const got = composeSecure(vectors, { Q, seed: 8n });
    expect(got.composed).toEqual({ allow: 0, t: 3, rQuant: 7 });
  });
});

describe('EDGE: fail-closed behaviour', () => {
  it('reconstruct throws on a missing (undefined) share', () => {
    const shares = share(5n, 3, new FieldRng(1n));
    const holed: (bigint | undefined)[] = shares.slice();
    holed[1] = undefined;
    expect(() => reconstruct(holed)).toThrow(/missing share/i);
  });

  it('reconstruct throws on an empty share set', () => {
    expect(() => reconstruct([])).toThrow(/no shares/i);
  });

  it('composeSecure throws on zero parties (fail closed)', () => {
    expect(() => composeSecure([], { Q: 8 })).toThrow(/no parties/i);
  });

  it('composeClear throws on zero parties (fail closed)', () => {
    expect(() => composeClear([])).toThrow(/no parties/i);
  });
});

describe('EDGE: thermometer encoding', () => {
  it('encodes/decodes bounded values', () => {
    expect(thermometerEncode(0, 3)).toEqual([0, 0, 0]);
    expect(thermometerEncode(2, 3)).toEqual([1, 1, 0]);
    expect(thermometerEncode(3, 3)).toEqual([1, 1, 1]);
    expect(thermometerDecode(thermometerEncode(2, 3))).toBe(2);
  });

  it('clamps out-of-range values (fail-safe)', () => {
    expect(thermometerEncode(99, 3)).toEqual([1, 1, 1]);
    expect(thermometerEncode(-5, 3)).toEqual([0, 0, 0]);
  });

  it('position-wise OR of thermometers equals the thermometer of the max', () => {
    const a = thermometerEncode(2, 5);
    const b = thermometerEncode(4, 5);
    const or = a.map((x, i) => (x === 1 || b[i] === 1 ? 1 : 0));
    expect(thermometerDecode(or)).toBe(4);
    expect(or).toEqual(thermometerEncode(4, 5));
  });
});
