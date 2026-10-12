import { describe, expect, it, vi } from 'vitest';

const dec = vi.hoisted(() => ({ out: undefined as unknown, seen: [] as unknown[] }));
vi.mock('@atlasauth/pca', () => ({ decide: (i: unknown) => { dec.seen.push(i); return dec.out; } }));

import { evaluateParty } from './party';
import {
  FIELD_BITS, MIN_STAT_SEC, PLAIN_GADGET, STAT_SEC, encBits, encValue, makeGadget, plainShare, randomBits, sampleEnc,
} from './enc';
import { PRIME, mod } from './field';

describe('evaluateParty', () => {
  it('maps the decide() outcome to a decision vector', () => {
    const input = { marker: 1 } as never;
    dec.out = { releaseGuardianShare: true, requiredThreshold: { t: 2 }, r: 0.376 };
    expect(evaluateParty({ id: 'u', decideInput: input })).toEqual({ allow: 1, t: 2, rQuant: 38 });
    expect(dec.seen.at(-1)).toBe(input);
    dec.out = { releaseGuardianShare: false, requiredThreshold: { t: 3 }, r: 0.376 };
    expect(evaluateParty({ id: 'u', decideInput: input }, 10)).toEqual({ allow: 0, t: 3, rQuant: 4 });
    dec.out = { releaseGuardianShare: false, requiredThreshold: { t: 1 }, r: Infinity };
    expect(evaluateParty({ id: 'u', decideInput: input }).rQuant).toBe(100);
  });
});

describe('enc constants', () => {
  it('has the documented parameters', () => {
    expect([FIELD_BITS, STAT_SEC, MIN_STAT_SEC]).toEqual([61, 64, 40]);
    expect(encBits(0)).toBe(61);
    expect(encBits(40)).toBe(181);
    expect(encBits(64)).toBe(253);
  });
});

describe('makeGadget', () => {
  let c = 0n;
  const next = () => (c += 1n);
  it('validates s and the unsafe flag', () => {
    for (const s of [-1, 65, 1.5, NaN]) expect(() => makeGadget(s, next, true)).toThrow(new RangeError('statSec must be an integer in [0, 64]'));
    expect(() => makeGadget(39, next)).toThrow(new RangeError('statSec 39 is below 40: refused (tests may pass the explicit unsafe flag)'));
    expect(() => makeGadget(1, next)).toThrow(/below 40/);
    expect(makeGadget(39, next, true)).toHaveLength(encBits(39));
    expect(makeGadget(40, next)).toHaveLength(181);
    expect(makeGadget(64, next)).toHaveLength(253);
    expect(() => makeGadget(64, next, true)).not.toThrow();
  });
  it('s = 0 gives powers of two mod p without calling next; otherwise draws in order', () => {
    const never = () => { throw new Error('no'); };
    const g0 = makeGadget(0, never, true);
    expect(g0).toEqual(PLAIN_GADGET);
    expect(g0[0]).toBe(1n);
    expect(g0[60]).toBe(mod(1n << 60n));
    expect(PLAIN_GADGET).toHaveLength(61);
    expect(PLAIN_GADGET[61 - 1]).toBe((1n << 60n) % PRIME);
    let k = 0n;
    const g = makeGadget(40, () => ++k);
    expect(g[0]).toBe(1n);
    expect(g[180]).toBe(181n);
  });
});

describe('encValue / plainShare / randomBits / sampleEnc', () => {
  it('encValue sums gadget entries where bit == 1 and reduces', () => {
    expect(encValue([5n, 6n, 7n], [1, 0, 1])).toBe(12n);
    expect(encValue([PRIME - 1n, 4n], [1, 1])).toBe(3n);
    expect(encValue([5n, 6n], [2, 0])).toBe(0n);
    expect(encValue([], [])).toBe(0n);
    expect(() => encValue([1n], [1, 0])).toThrow(new RangeError('encValue: gadget / bits length mismatch'));
    expect(() => encValue([1n, 2n], [1])).toThrow(new RangeError('encValue: gadget / bits length mismatch'));
  });
  it('plainShare is the binary expansion of the reduced value', () => {
    const s = plainShare(PRIME + 5n);
    expect(s.value).toBe(5n);
    expect(s.bits).toHaveLength(61);
    expect(s.bits.slice(0, 4)).toEqual([1, 0, 1, 0]);
    expect(s.bits.slice(4).every((b) => b === 0)).toBe(true);
    const m = plainShare(-1n);
    expect(m.value).toBe(PRIME - 1n);
    expect(m.bits[60]).toBe(1);
    expect(encValue(PLAIN_GADGET, m.bits)).toBe(m.value);
  });
  it('randomBits takes 60 bits (LSB first) per draw and handles ragged lengths', () => {
    const draws = [0b101n, (1n << 60n) | 1n, 3n];
    const rng = { next: () => draws.shift()! };
    const b = randomBits(125, rng);
    expect(b).toHaveLength(125);
    expect(b.slice(0, 3)).toEqual([1, 0, 1]);
    expect(b[3]).toBe(0);
    expect(b[59]).toBe(0);
    expect(b[60]).toBe(1);
    expect(b[61]).toBe(0);
    expect(b[119]).toBe(0);
    expect(b[120]).toBe(1);
    expect(b[121]).toBe(1);
    expect(b[124]).toBe(0);
    expect(draws).toEqual([]);
    expect(randomBits(0, { next: () => { throw new Error('no'); } })).toEqual([]);
    let n = 0;
    expect(randomBits(60, { next: () => (n++, (1n << 60n) - 1n) })).toEqual(new Array(60).fill(1));
    expect(n).toBe(1);
    n = 0;
    randomBits(61, { next: () => (n++, 0n) });
    expect(n).toBe(2);
  });
  it('sampleEnc returns bits and their encoded value', () => {
    const g = [1n, 2n, 4n];
    const s = sampleEnc(g, { next: () => 0b101n });
    expect(s.bits).toEqual([1, 0, 1]);
    expect(s.value).toBe(5n);
  });
});
