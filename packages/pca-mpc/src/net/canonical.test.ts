/** Canonical-encoding audit of the OT-over-network wire codec: one accepted string per value. */
import { describe, expect, it } from 'vitest';
import { hexBig, unb64 } from './ot-net';

describe('ot-net wire codec is canonical', () => {
  it('hexBig accepts only minimal lowercase hex', () => {
    expect(hexBig('0')).toBe(0n);
    expect(hexBig('ff')).toBe(255n);
    for (const bad of ['00', '0f', '00ff', 'FF', '', ' 1', '1 ']) expect(() => hexBig(bad)).toThrow();
  });
  it('unb64 rejects non-canonical trailing bits and bad padding', () => {
    const ok = Buffer.from([1, 2, 3, 4]).toString('base64'); // AQIDBA==
    expect(Array.from(unb64(ok))).toEqual([1, 2, 3, 4]);
    expect(() => unb64('AQIDBB==')).toThrow(); // same bytes, different trailing bits
    expect(() => unb64('AQIDBA')).toThrow(); // missing padding
  });
});
