/**
 * Round-2 SECURITY: noble's BLS12-381 point parsers accept non-reduced coordinates (x + p aliases the same point).
 * An aliased public key is a different byte string for the same signer, which defeats byte-keyed distinct-witness
 * counting (RT-13); an aliased signature is a second encoding of one signature (malleability).
 */
import { bls12_381 } from '@noble/curves/bls12-381';
import { describe, expect, it } from 'vitest';
import { POP_DST, aggregate, aggregateVerify, fastAggregateVerify, keyGen, keyValidate, popVerify, sign, verify } from './core';
import { registerKey, KeyRegistry } from './bls';

const P = bls12_381.fields.Fp.ORDER;
const be48 = (v: bigint): Uint8Array => { const b = new Uint8Array(48); for (let i = 47; i >= 0; i--, v >>= 8n) b[i] = Number(v & 0xffn); return b; };
const num = (b: Uint8Array): bigint => { let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x); return n; };

/** A key pair whose public x coordinate is small enough that x + p still fits in 381 bits, and the aliased 48-byte encoding. */
function aliasedKey(): { sk: Uint8Array; pk: Uint8Array; alias: Uint8Array } {
  for (let n = 0; n < 200; n++) {
    const k = keyGen();
    const flags = k.publicKey[0]! & 0xe0;
    const x = num(Uint8Array.from([k.publicKey[0]! & 0x1f, ...k.publicKey.subarray(1)]));
    const xx = x + P;
    if (xx >> 381n !== 0n) continue;
    const alias = be48(xx);
    alias[0]! |= flags;
    return { sk: k.secretKey, pk: k.publicKey, alias };
  }
  throw new Error('no aliasable key found');
}

describe('r2: non-canonical BLS encodings are refused', () => {
  it('an aliased public key fails KeyValidate and cannot be registered, so one signer cannot be counted twice', () => {
    const { sk, pk, alias } = aliasedKey();
    expect(keyValidate(pk)).toBe(true);
    expect(keyValidate(alias)).toBe(false);
    const msg = new TextEncoder().encode('m');
    // a valid PoP over the aliased bytes, made by the true secret holder
    const pop = bls12_381.sign(alias, sk, { DST: POP_DST });
    expect(popVerify(alias, pop)).toBe(false);
    expect(registerKey(alias, pop).ok).toBe(false);
    expect(new KeyRegistry().register(alias, pop).ok).toBe(false);
    // and the raw verifiers refuse it
    const sig = sign(sk, msg);
    expect(verify(alias, msg, sig)).toBe(false);
    expect(fastAggregateVerify([pk, alias], msg, aggregate([sig, sig]))).toBe(false);
    expect(aggregateVerify([alias], [msg], sig)).toBe(false);
  });
  it('an aliased signature (c0 + p) does not verify, so each signature has exactly one encoding', () => {
    const k = keyGen();
    const msg = new TextEncoder().encode('m');
    const sig = sign(k.secretKey, msg);
    expect(verify(k.publicKey, msg, sig)).toBe(true);
    const alias = Uint8Array.from(sig);
    alias.set(be48(num(sig.subarray(48)) + P), 48);
    expect(verify(k.publicKey, msg, alias)).toBe(false);
    expect(aggregateVerify([k.publicKey], [msg], alias)).toBe(false);
    expect(fastAggregateVerify([k.publicKey], msg, alias)).toBe(false);
    expect(() => aggregate([alias])).toThrow();
    expect(popVerify(k.publicKey, alias)).toBe(false);
  });
});
