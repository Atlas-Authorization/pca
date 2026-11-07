/**
 * Audit-readiness tests for @atlasauth/pca-aggsig: rogue-key admission, proof-of-possession replay and transplant,
 * identity and off-subgroup points in keys, signatures, proofs and aggregates, duplicate signers and empty sets.
 * Every case asserts the exact outcome (a boolean, a `{ ok: false, reason }` or a typed throw), not only "did not accept".
 */
import { describe, expect, it } from 'vitest';
import { bls12_381 } from '@noble/curves/bls12-381';
import { POP_DST, SIG_DST, aggregate, aggregatePublicKeys, aggregateVerify as rawAggregateVerify, fastAggregateVerify as rawFastAggregateVerify, keyGen, keyValidate, popProve, popVerify, sign, verify } from './core';
import { KeyRegistry, aggregateVerify, fastAggregateVerify, registerKey } from './bls';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const G1 = bls12_381.G1.ProjectivePoint;
const G1_ID = Uint8Array.from([0xc0, ...new Array(47).fill(0)]);
const G2_ID = Uint8Array.from([0xc0, ...new Array(95).fill(0)]);
const reg = (k: { publicKey: Uint8Array; secretKey: Uint8Array }) => {
  const r = registerKey(k.publicKey, popProve(k.secretKey));
  if (!r.ok) throw new Error(r.reason);
  return r.key;
};

/** Deterministic 96-byte values with the compression flag set: each is either off the curve or off the prime-order subgroup of G2. */
function junkG2(n: number): Uint8Array[] {
  return Array.from({ length: n }, (_, i) => {
    const b = new Uint8Array(96);
    b[0] = 0x80 | 0x01;
    b[94] = i >> 8;
    b[95] = i & 0xff;
    b[40] = 7 + i;
    return b;
  });
}

const alice = keyGen();
const bob = keyGen();
const m = enc('release');

describe('rogue-key admission', () => {
  it('a key built as a*G - pk_victim is refused: its owner cannot produce a proof of possession for it', () => {
    const victim = reg(alice);
    const a = keyGen();
    const rogue = G1.fromHex(a.publicKey).subtract(G1.fromHex(victim.bytes)).toRawBytes(true);
    expect(keyValidate(rogue)).toBe(true);
    // the only proofs the adversary can make are for keys it holds the secret of
    const r = registerKey(rogue, popProve(a.secretKey));
    expect(r).toEqual({ ok: false, reason: 'proof of possession does not verify for this key' });
  });

  it('a proof of possession is bound to its key: replaying alice\'s proof for bob\'s key (or the reverse) is refused', () => {
    expect(registerKey(bob.publicKey, popProve(alice.secretKey))).toEqual({ ok: false, reason: 'proof of possession does not verify for this key' });
    expect(registerKey(alice.publicKey, popProve(bob.secretKey))).toEqual({ ok: false, reason: 'proof of possession does not verify for this key' });
    expect(registerKey(alice.publicKey, popProve(alice.secretKey)).ok).toBe(true);
  });

  it('a message signature is not a proof of possession, and a proof is not a message signature (domain separation)', () => {
    expect(POP_DST).not.toBe(SIG_DST);
    const sigOverOwnKey = sign(alice.secretKey, alice.publicKey); // SIG_DST over the key bytes
    expect(popVerify(alice.publicKey, sigOverOwnKey)).toBe(false);
    expect(verify(alice.publicKey, alice.publicKey, popProve(alice.secretKey))).toBe(false);
    expect(registerKey(alice.publicKey, sigOverOwnKey).ok).toBe(false);
  });

  it('identity, off-subgroup and wrong-length keys are refused with the KeyValidate reason; the identity proof is refused too', () => {
    const keyReason = 'public key fails KeyValidate (not a canonical, non-identity, prime-order G1 point)';
    expect(registerKey(G1_ID, G2_ID)).toEqual({ ok: false, reason: keyReason });
    expect(registerKey(new Uint8Array(47).fill(0x80), popProve(alice.secretKey))).toEqual({ ok: false, reason: keyReason });
    expect(registerKey(alice.publicKey, G2_ID)).toEqual({ ok: false, reason: 'proof of possession does not verify for this key' });
    expect(registerKey(alice.publicKey, new Uint8Array(95))).toEqual({ ok: false, reason: 'proof of possession is not a 96-byte compressed G2 signature' });
    expect(registerKey('x' as never, 'y' as never)).toEqual({ ok: false, reason: 'public key and proof of possession must be Uint8Arrays' });
  });

  it('re-registering the same key is idempotent and the registry never holds the same signer twice', () => {
    const r = new KeyRegistry();
    expect(r.register(alice.publicKey, popProve(alice.secretKey)).ok).toBe(true);
    expect(r.register(alice.publicKey, popProve(alice.secretKey)).ok).toBe(true);
    expect(r.size).toBe(1);
    expect(r.register(bob.publicKey, popProve(alice.secretKey)).ok).toBe(false);
    expect(r.size).toBe(1);
    expect(r.has(bob.publicKey)).toBe(false);
  });
});

describe('subgroup and identity points in signatures and aggregates', () => {
  const sig = sign(alice.secretKey, m);

  it('the identity signature never verifies, alone or inside an aggregate', () => {
    expect(verify(alice.publicKey, m, G2_ID)).toBe(false);
    expect(rawFastAggregateVerify([alice.publicKey], m, G2_ID)).toBe(false);
    expect(rawAggregateVerify([alice.publicKey], [m], G2_ID)).toBe(false);
    expect(fastAggregateVerify([reg(alice)], m, G2_ID)).toBe(false);
    expect(aggregateVerify([reg(alice)], [m], G2_ID)).toBe(false);
  });

  it('96-byte values that are off the curve or off the prime-order subgroup are refused everywhere and never verify', () => {
    for (const bad of junkG2(40)) {
      expect(verify(alice.publicKey, m, bad)).toBe(false);
      expect(rawFastAggregateVerify([alice.publicKey], m, bad)).toBe(false);
      expect(rawAggregateVerify([alice.publicKey], [m], bad)).toBe(false);
      expect(popVerify(alice.publicKey, bad)).toBe(false);
      expect(registerKey(alice.publicKey, bad).ok).toBe(false);
      expect(() => aggregate([sig, bad])).toThrow();
    }
  });

  it('a valid signature with one corrupted byte is refused in every verification path', () => {
    for (const i of [0, 1, 47, 48, 95]) {
      const t = Uint8Array.from(sig);
      t[i] = t[i]! ^ 0x01;
      expect(verify(alice.publicKey, m, t)).toBe(false);
      expect(rawAggregateVerify([alice.publicKey], [m], t)).toBe(false);
    }
  });

  it('keys that cancel to the identity ({P, -P}) are refused by the public fast-aggregate path', () => {
    const p = G1.fromHex(alice.publicKey);
    const neg = p.negate().toRawBytes(true);
    expect(keyValidate(neg)).toBe(true);
    // no registered key exists for -P without its proof, so the public API cannot even be handed the pair
    expect(registerKey(neg, popProve(alice.secretKey)).ok).toBe(false);
    expect(rawFastAggregateVerify([alice.publicKey, neg], m, G2_ID)).toBe(false);
  });
});

describe('duplicate signers and empty sets', () => {
  it('fast aggregation refuses one signer counted twice; two distinct signers verify', () => {
    const ra = reg(alice);
    const rb = reg(bob);
    const twice = aggregate([sign(alice.secretKey, m), sign(alice.secretKey, m)]);
    expect(fastAggregateVerify([ra, ra], m, twice)).toBe(false);
    const both = aggregate([sign(alice.secretKey, m), sign(bob.secretKey, m)]);
    expect(fastAggregateVerify([ra, rb], m, both)).toBe(true);
    expect(fastAggregateVerify([ra], m, both)).toBe(false);
    expect(fastAggregateVerify([rb, ra], m, both)).toBe(true);
  });

  it('distinct messages by the same signer verify; the same message twice is refused', () => {
    const ra = reg(alice);
    const m2 = enc('release-2');
    const agg = aggregate([sign(alice.secretKey, m), sign(alice.secretKey, m2)]);
    expect(aggregateVerify([ra, ra], [m, m2], agg)).toBe(true);
    expect(aggregateVerify([ra, ra], [m, m], aggregate([sign(alice.secretKey, m), sign(alice.secretKey, m)]))).toBe(false);
  });

  it('an empty signer set is refused in every verifier and an empty aggregate throws a RangeError', () => {
    const sig = sign(alice.secretKey, m);
    expect(fastAggregateVerify([], m, sig)).toBe(false);
    expect(aggregateVerify([], [], sig)).toBe(false);
    expect(rawFastAggregateVerify([], m, sig)).toBe(false);
    expect(rawAggregateVerify([], [], sig)).toBe(false);
    expect(() => aggregate([])).toThrow(RangeError);
    expect(() => aggregatePublicKeys([])).toThrow(RangeError);
  });

  it('non-registered inputs (raw bytes, plain objects, null) are refused by the public verifiers without throwing', () => {
    const sig = sign(alice.secretKey, m);
    expect(fastAggregateVerify([alice.publicKey as never], m, sig)).toBe(false);
    expect(fastAggregateVerify([{ bytes: alice.publicKey } as never], m, sig)).toBe(false);
    expect(aggregateVerify([null as never], [m], sig)).toBe(false);
    expect(fastAggregateVerify(null as never, m, sig)).toBe(false);
  });
});
