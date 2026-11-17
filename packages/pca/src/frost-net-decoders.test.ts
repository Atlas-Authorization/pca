import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { MAX_FROST_SIGNING_SET, decodeCommitment, decodeCommitments, decodeVerificationShares } from './frost-net';

const P = b64u(new Uint8Array(32).fill(1));
const good = { identifier: 1, hiding: P, binding: P };

describe('frost-net wire decoders are total on hostile input', () => {
  it('decodes a well-formed commitment exactly', () => {
    const c = decodeCommitment(good);
    expect(c.identifier).toBe(1);
    expect(Array.from(c.hiding)).toEqual(new Array(32).fill(1));
    expect(Array.from(c.binding)).toEqual(new Array(32).fill(1));
  });

  it.each([null, undefined, 7, 'x', true])('decodeCommitment(%j) is a typed refusal, not a TypeError', (x) => {
    expect(() => decodeCommitment(x as never)).toThrow('bad commitment');
  });

  it.each([
    [{ ...good, identifier: 0 }, 'bad commitment identifier'],
    [{ ...good, identifier: -1 }, 'bad commitment identifier'],
    [{ ...good, identifier: 1.5 }, 'bad commitment identifier'],
    [{ ...good, identifier: '1' }, 'bad commitment identifier'],
    [{ ...good, hiding: P + '=' }, 'bad commitment point encoding'],
    [{ ...good, binding: b64u(new Uint8Array(31)) }, 'bad commitment point encoding'],
    [{ ...good, hiding: 5 }, 'bad commitment point encoding'],
  ])('decodeCommitment refuses %j', (x, msg) => {
    expect(() => decodeCommitment(x as never)).toThrow(msg);
  });

  it('decodeCommitments refuses a non-list and a list above the maximum signing set', () => {
    expect(() => decodeCommitments({} as never)).toThrow('commitments must be a list');
    expect(() => decodeCommitments(Array.from({ length: MAX_FROST_SIGNING_SET + 1 }, () => good))).toThrow('exceeds the maximum signing set');
    expect(decodeCommitments(Array.from({ length: MAX_FROST_SIGNING_SET }, () => good))).toHaveLength(MAX_FROST_SIGNING_SET);
  });

  it('decodeVerificationShares refuses non-lists, oversize lists and malformed entries', () => {
    expect(() => decodeVerificationShares(null as never)).toThrow('verification_shares must be a list');
    expect(() => decodeVerificationShares(Array.from({ length: MAX_FROST_SIGNING_SET + 1 }, () => ({ identifier: 1, publicKey: P })))).toThrow('exceeds the maximum signing set');
    expect(() => decodeVerificationShares([null as never])).toThrow('bad verification share');
    expect(() => decodeVerificationShares([{ identifier: 0, publicKey: P }])).toThrow('bad verification-share identifier');
    expect(() => decodeVerificationShares([{ identifier: 1, publicKey: 'AA' }])).toThrow('bad verification-share key encoding');
    expect(decodeVerificationShares([{ identifier: 2, publicKey: P }])[0]!.identifier).toBe(2);
  });
});
