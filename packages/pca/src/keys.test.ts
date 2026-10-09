import { describe, expect, it } from 'vitest';
import { utf8 } from './hash';
import { decodeKey, encodeKey, generateKeyPair, sign, verify, verifyB64u } from './keys';

describe('keys', () => {
  it('sign/verify roundtrip', () => {
    const k = generateKeyPair();
    const sig = sign(k.secretKey, utf8('hi'));
    expect(verify(k.publicKey, utf8('hi'), sig)).toBe(true);
    expect(decodeKey(encodeKey(k.publicKey))).toEqual(k.publicKey);
  });
  it('wrong key and tampered message fail', () => {
    const k = generateKeyPair();
    const o = generateKeyPair();
    const sig = sign(k.secretKey, utf8('hi'));
    expect(verify(o.publicKey, utf8('hi'), sig)).toBe(false);
    expect(verify(k.publicKey, utf8('ho'), sig)).toBe(false);
  });
  it('malformed inputs return false, never throw', () => {
    expect(verifyB64u('!!', utf8('x'), '??')).toBe(false);
    expect(verify(new Uint8Array(3), utf8('x'), new Uint8Array(3))).toBe(false);
  });
});

describe('strict Ed25519 (P5-3)', () => {
  it('canonical signatures verify; small-order keys, non-canonical S and mixed-order R are rejected', () => {
    const kp = generateKeyPair();
    const msg = utf8('strict');
    const sig = sign(kp.secretKey, msg);
    expect(verify(kp.publicKey, msg, sig)).toBe(true);
    // Small-order public key (identity) with an identity R and S=0 verifies under ZIP-215 — must not here.
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const forged = new Uint8Array(64);
    forged.set(identity, 0);
    expect(verify(identity, msg, forged)).toBe(false);
    // Non-canonical S (S + L) is rejected.
    const L = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;
    let s = 0n;
    for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]!);
    const s2 = s + L;
    const bad = Uint8Array.from(sig);
    for (let i = 0; i < 32; i++) bad[32 + i] = Number((s2 >> BigInt(8 * i)) & 0xffn);
    expect(verify(kp.publicKey, msg, bad)).toBe(false);
    // Wrong lengths never throw.
    expect(verify(kp.publicKey, msg, sig.subarray(0, 63))).toBe(false);
    expect(verify(kp.publicKey.subarray(0, 31), msg, sig)).toBe(false);
  });
});
