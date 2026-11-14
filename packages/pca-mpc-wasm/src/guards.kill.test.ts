/** pca-mpc-wasm: constants, error identity, defensive copies and per-operand labels. */
import { describe, expect, it, vi } from 'vitest';
import { BASE, IDENTITY, L, PointValidationError, Q, decodePoint, encodePoint, mulBase, mulBasePoint, sub } from './index';

describe('pca-mpc-wasm constants and copies', () => {
  it('Q and L are the Ed25519 field prime and subgroup order', () => {
    expect(Q.toString(16)).toBe('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed');
    expect(L.toString(16)).toBe('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed');
  });

  it('mulBasePoint equals mulBase', () => {
    expect(mulBasePoint(5n)).toEqual(mulBase(5n));
    expect(mulBasePoint(1n)).toEqual(BASE);
  });

  it('PointValidationError names itself', () => {
    const e = new PointValidationError('m');
    expect(e.name).toBe('PointValidationError');
    expect(e).toBeInstanceOf(Error);
    expect(e.message).toBe('m');
    expect(() => sub(BASE, new Uint8Array(3))).toThrow(new PointValidationError('sub: b: expected a 32-byte compressed point, got 3'));
  });

  it('encodePoint and decodePoint return copies, not the input', () => {
    const p = new Uint8Array(BASE);
    const e = encodePoint(p);
    expect(e).toEqual(p);
    expect(e).not.toBe(p);
    e[0] ^= 0xff;
    expect(p).toEqual(BASE);
    const d = decodePoint(p);
    expect(d).toEqual(p);
    expect(d).not.toBe(p);
    d[1] ^= 0xff;
    expect(p).toEqual(BASE);
    expect(IDENTITY[0]).toBe(1);
  });
});

describe('module constants, loaded fresh', () => {
  it('IDENTITY is the 32-byte encoding of y = 1 and the neutral element of addition', async () => {
    vi.resetModules();
    const m = await import('./index');
    const want = new Uint8Array(32);
    want[0] = 1;
    expect(m.IDENTITY).toEqual(want);
    expect(m.sub(m.BASE, m.BASE)).toEqual(m.IDENTITY);
  });
});
