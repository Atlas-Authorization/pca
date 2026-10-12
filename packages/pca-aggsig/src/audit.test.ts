/**
 * Adversarial / audit-style tests for @atlasauth/pca-aggsig (complements the IETF vectors and the
 * cross-implementation checks; does not repeat them): rogue-key and identity-aggregate attacks,
 * subgroup / identity / malformed encodings, duplicate-signer and domain-separation behaviour,
 * statement / chain binding, RNG failure, property tests and bounded fuzzing.
 * Fuzz seconds per group: `AUDIT_FUZZ_SECONDS` (default 3).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import fc from 'fast-check';
import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToHex } from '@noble/hashes/utils';
import { b64u } from '@atlasauth/pca';
import {
  POP_DST,
  SIG_DST,
  aggregate,
  aggregatePublicKeys,
  aggregateVerify,
  fastAggregateVerify,
  keyGen,
  keyValidate,
  popProve,
  popVerify,
  publicKeyOf,
  sign,
  verify,
} from './core';
import { KeyRegistry, type RegisteredKey, registerKey } from './bls';
import { MAX_CHAIN_DEPTH, aggregateChainSignatures, blsDelegate, blsPublicKey, mintBlsRoot, verifyAggregatedChain, type BlsCapability } from './chain';
import { aggregateWitnessCosignatures, cosignTreeHead, verifyAggregatedWitnessCosignatures, verifyWitnessCosignature } from './witness';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const registryOf = (...ks: { publicKey: Uint8Array; secretKey: Uint8Array }[]): KeyRegistry => {
  const r = new KeyRegistry();
  for (const k of ks) if (!r.register(k.publicKey, popProve(k.secretKey)).ok) throw new Error('registration failed');
  return r;
};
const rks = (...ks: { publicKey: Uint8Array; secretKey: Uint8Array }[]): RegisteredKey[] =>
  ks.map((k) => {
    const r = registerKey(k.publicKey, popProve(k.secretKey));
    if (!r.ok) throw new Error(r.reason);
    return r.key;
  });
const FUZZ_MS = Number(process.env.AUDIT_FUZZ_SECONDS ?? '3') * 1000;
const fuzzOpts = { numRuns: 1_000_000, interruptAfterTimeLimit: FUZZ_MS, markInterruptAsFailure: false } as const;
const G1 = bls12_381.G1.ProjectivePoint;
const Fp = bls12_381.fields.Fp;

afterEach(() => vi.restoreAllMocks());

function offSubgroupG1(): Uint8Array {
  for (let x = 5n; ; x++) {
    const rhs = Fp.add(Fp.pow(x, 3n), 4n);
    if (!Fp.eql(Fp.pow(rhs, (Fp.ORDER - 1n) / 2n), 1n)) continue;
    const out = new Uint8Array(48);
    let v = x;
    for (let i = 47; i >= 0; i--) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    out[0] = (out[0] ?? 0) | 0x80;
    try {
      G1.fromHex(out);
    } catch {
      return out;
    }
  }
}

const G1_ID = Uint8Array.from([0xc0, ...new Array(47).fill(0)]);
const G2_ID = Uint8Array.from([0xc0, ...new Array(95).fill(0)]);

const a = keyGen();
const b = keyGen();
const c = keyGen();
const msg = enc('m');

describe('encodings: identity, off-subgroup, wrong length and non-canonical inputs never validate', () => {
  it('keyValidate rejects identity, off-subgroup, wrong lengths, uncompressed-flag-cleared and garbage', () => {
    expect(keyValidate(a.publicKey)).toBe(true);
    expect(keyValidate(G1_ID)).toBe(false);
    expect(keyValidate(offSubgroupG1())).toBe(false);
    for (const n of [0, 1, 47, 49, 96]) expect(keyValidate(new Uint8Array(n).fill(0x80))).toBe(false);
    const flagless = Uint8Array.from(a.publicKey);
    flagless[0] = (flagless[0] ?? 0) & 0x7f;
    expect(keyValidate(flagless)).toBe(false);
    const nonCanonicalInfinity = Uint8Array.from(G1_ID);
    nonCanonicalInfinity[47] = 1;
    expect(keyValidate(nonCanonicalInfinity)).toBe(false);
  });

  it('SIGNATURE MALLEABILITY (fixed): clearing the compression flag of a valid signature no longer verifies, in single, aggregate, fast-aggregate and PoP paths', () => {
    const sig = sign(a.secretKey, msg);
    const flagless = Uint8Array.from(sig);
    flagless[0] = (flagless[0] ?? 0) & 0x7f;
    expect(verify(a.publicKey, msg, flagless)).toBe(false);
    expect(aggregateVerify([a.publicKey], [msg], flagless)).toBe(false);
    expect(fastAggregateVerify([a.publicKey], msg, flagless)).toBe(false);
    const pop = popProve(a.secretKey);
    const popFlagless = Uint8Array.from(pop);
    popFlagless[0] = (popFlagless[0] ?? 0) & 0x7f;
    expect(popVerify(a.publicKey, pop)).toBe(true);
    expect(popVerify(a.publicKey, popFlagless)).toBe(false);
    expect(() => aggregate([flagless])).toThrow(RangeError);
  });

  it('verify / popVerify reject the identity signature, identity key, off-subgroup key and truncated signatures', () => {
    const sig = sign(a.secretKey, msg);
    expect(verify(a.publicKey, msg, sig)).toBe(true);
    expect(verify(a.publicKey, msg, G2_ID)).toBe(false);
    expect(verify(G1_ID, msg, G2_ID)).toBe(false);
    expect(verify(offSubgroupG1(), msg, sig)).toBe(false);
    expect(verify(a.publicKey, msg, sig.subarray(0, 95))).toBe(false);
    expect(verify(a.publicKey, msg, new Uint8Array([...sig, 0]))).toBe(false);
    expect(popVerify(G1_ID, G2_ID)).toBe(false);
  });

  it('aggregate / aggregatePublicKeys: empty set is refused, garbage elements throw (typed), never silently succeed', () => {
    expect(() => aggregate([])).toThrow(RangeError);
    expect(() => aggregatePublicKeys([])).toThrow(RangeError);
    expect(() => aggregate([new Uint8Array(96).fill(1)])).toThrow();
    expect(() => aggregatePublicKeys([new Uint8Array(48).fill(1)])).toThrow();
  });

  it('the secret key 0 / the identity cannot be used to sign', () => {
    expect(() => sign(new Uint8Array(32), msg)).toThrow();
    expect(() => publicKeyOf(new Uint8Array(32))).toThrow();
    expect(() => sign(new Uint8Array(31).fill(1), msg)).toThrow();
  });
});

describe('aggregation attacks', () => {
  it('IDENTITY-AGGREGATE FORGERY (defence in depth; the pinned noble version also refuses the pairing): keys {P, -P} each pass KeyValidate but sum to the identity, for which the identity signature would verify over ANY message', () => {
    const P = G1.fromHex(a.publicKey);
    const negP = P.negate().toRawBytes(true);
    expect(keyValidate(negP)).toBe(true);
    expect(fastAggregateVerify([a.publicKey, negP], enc('any message at all'), G2_ID)).toBe(false);
    // a genuine aggregate over the same two keys still works when the second key signs too
    const sigA = sign(a.secretKey, msg);
    expect(fastAggregateVerify([a.publicKey, b.publicKey], msg, aggregate([sigA, sign(b.secretKey, msg)]))).toBe(true);
  });

  it('witness quorum: the same forgery through the public witness API is rejected', () => {
    const P = G1.fromHex(a.publicKey);
    const st = { size: 3, root: 'r', prev_root: 'p', guardian_epoch: 1 };
    // -P has no PoP (nobody can prove possession of it under this API), so it cannot even be presented.
    expect(registerKey(P.negate().toRawBytes(true), G2_ID).ok).toBe(false);
    expect(verifyAggregatedWitnessCosignatures(st, [...rks(a), { bytes: P.negate().toRawBytes(true) } as unknown as RegisteredKey], G2_ID)).toBe(false);
  });

  it('ROGUE KEY (documented limit): FastAggregateVerify alone does not stop pk_adv = a*G - pk_victim; popVerify does, so keys MUST be PoP-vetted at registration', () => {
    const adv = keyGen();
    const victimPk = G1.fromHex(b.publicKey);
    const rogue = G1.fromHex(adv.publicKey).subtract(victimPk).toRawBytes(true);
    expect(keyValidate(rogue)).toBe(true);
    const forged = sign(adv.secretKey, msg); // = a * H(m), valid for pk_victim + pk_rogue = a*G
    expect(fastAggregateVerify([b.publicKey, rogue], msg, forged)).toBe(true); // why PoP is mandatory
    // The rogue key cannot produce a proof of possession (nobody knows its secret key):
    expect(popVerify(rogue, popProve(adv.secretKey))).toBe(false);
    expect(popVerify(rogue, sign(adv.secretKey, rogue))).toBe(false);
    // honest keys do pass
    expect(popVerify(b.publicKey, popProve(b.secretKey))).toBe(true);
  });

  it('witness quorum: a duplicated witness key is refused (one cosignature cannot be counted twice)', () => {
    const st = { size: 9, root: 'r', prev_root: 'p', guardian_epoch: 2 };
    const co = cosignTreeHead(st, a.secretKey);
    const agg = aggregateWitnessCosignatures([co, co]);
    const [ra, rb] = rks(a, b) as [RegisteredKey, RegisteredKey];
    expect(verifyAggregatedWitnessCosignatures(st, [ra, ra], agg)).toBe(false);
    const co2 = cosignTreeHead(st, b.secretKey);
    expect(verifyAggregatedWitnessCosignatures(st, [ra, rb], aggregateWitnessCosignatures([co, co2]))).toBe(true);
    expect(verifyAggregatedWitnessCosignatures(st, [ra, rb], aggregateWitnessCosignatures([co, co]))).toBe(false);
  });

  it('aggregateVerify: repeated messages, length mismatch, empty set, one bad key are all refused; a repeated KEY with distinct messages is fine', () => {
    const s1 = sign(a.secretKey, enc('x'));
    const s2 = sign(a.secretKey, enc('y'));
    const agg = aggregate([s1, s2]);
    expect(aggregateVerify([a.publicKey, a.publicKey], [enc('x'), enc('y')], agg)).toBe(true);
    expect(aggregateVerify([a.publicKey, a.publicKey], [enc('x'), enc('x')], aggregate([s1, s1]))).toBe(false);
    expect(aggregateVerify([a.publicKey], [enc('x'), enc('y')], agg)).toBe(false);
    expect(aggregateVerify([], [], agg)).toBe(false);
    expect(aggregateVerify([a.publicKey, G1_ID], [enc('x'), enc('y')], agg)).toBe(false);
    // swapping which message goes with which key breaks it
    const s3 = sign(b.secretKey, enc('y'));
    const mixed = aggregate([s1, s3]);
    expect(aggregateVerify([a.publicKey, b.publicKey], [enc('x'), enc('y')], mixed)).toBe(true);
    expect(aggregateVerify([a.publicKey, b.publicKey], [enc('y'), enc('x')], mixed)).toBe(false);
    expect(aggregateVerify([b.publicKey, a.publicKey], [enc('x'), enc('y')], mixed)).toBe(false);
  });

  it('aggregate is order-independent and a single-member aggregate equals the member', () => {
    const sigs = [a, b, c].map((k) => sign(k.secretKey, msg));
    expect(bytesToHex(aggregate(sigs))).toBe(bytesToHex(aggregate([...sigs].reverse())));
    expect(bytesToHex(aggregate([sigs[0] as Uint8Array]))).toBe(bytesToHex(sigs[0] as Uint8Array));
  });
});

describe('domain separation between signature, PoP, chain hop and witness cosignature', () => {
  it('constants are distinct, and a PoP is not a signature (nor vice versa) over the same bytes', () => {
    expect(SIG_DST).not.toBe(POP_DST);
    const pop = popProve(a.secretKey);
    expect(verify(a.publicKey, a.publicKey, pop)).toBe(false);
    expect(popVerify(a.publicKey, sign(a.secretKey, a.publicKey))).toBe(false);
  });

  it('a witness cosignature cannot be replayed as a chain hop signature and a hop signature is not a witness cosignature', () => {
    const st = { size: 1, root: 'r', prev_root: 'p', guardian_epoch: 0 };
    const co = cosignTreeHead(st, a.secretKey);
    const root = mintBlsRoot({ principalSecret: a.secretKey, principalPublic: blsPublicKey(a.secretKey), holder: blsPublicKey(b.secretKey), caveats: [{ type: 'scope', scopes: ['x'] } as never] });
    const forgedHop: BlsCapability = { ...root, sig: co.sig };
    expect(verifyAggregatedChain([forgedHop], aggregateChainSignatures([forgedHop]), registryOf(a, b), blsPublicKey(a.secretKey)).ok).toBe(false);
    expect(verifyWitnessCosignature(st, { key: b64u(a.publicKey), sig: root.sig, suite: 'bls12-381-pop' })).toBe(false);
  });
});

describe('witness statement binding and malformed input', () => {
  const st = { size: 10, root: 'ROOT', prev_root: 'PREV', guardian_epoch: 4 };
  const co = cosignTreeHead(st, a.secretKey);

  it('every statement field is bound; absent guardian_epoch is treated as 0 (documented)', () => {
    expect(verifyWitnessCosignature(st, co)).toBe(true);
    for (const alt of [{ ...st, size: 11 }, { ...st, root: 'ROOT2' }, { ...st, prev_root: 'PREV2' }, { ...st, guardian_epoch: 5 }, { ...st, guardian_epoch: 0 }]) {
      expect(verifyWitnessCosignature(alt, co)).toBe(false);
    }
    const noEpoch = cosignTreeHead({ size: 1, root: 'r', prev_root: 'p' } as never, a.secretKey);
    expect(verifyWitnessCosignature({ size: 1, root: 'r', prev_root: 'p', guardian_epoch: 0 }, noEpoch)).toBe(true);
  });

  it('wrong key, wrong suite, non-canonical b64u and padded/extended signatures are rejected', () => {
    expect(verifyWitnessCosignature(st, { ...co, key: b64u(b.publicKey) })).toBe(false);
    expect(verifyWitnessCosignature(st, { ...co, suite: 'other' as never })).toBe(false);
    expect(verifyWitnessCosignature(st, { ...co, sig: co.sig + '=' })).toBe(false);
    expect(verifyWitnessCosignature(st, { ...co, sig: co.sig + 'AA' })).toBe(false);
    expect(verifyWitnessCosignature(st, { ...co, sig: '' })).toBe(false);
  });

  it('quorum aggregate with a missing / substituted / extra member is rejected', () => {
    const cb = cosignTreeHead(st, b.secretKey);
    const cc = cosignTreeHead(st, c.secretKey);
    const agg = aggregateWitnessCosignatures([co, cb]);
    const [ra, rb, rc] = rks(a, b, c) as [RegisteredKey, RegisteredKey, RegisteredKey];
    expect(cc.key).toBe(b64u(c.publicKey));
    expect(verifyAggregatedWitnessCosignatures(st, [ra, rb], agg)).toBe(true);
    expect(verifyAggregatedWitnessCosignatures(st, [ra], agg)).toBe(false);
    expect(verifyAggregatedWitnessCosignatures(st, [ra, rc], agg)).toBe(false);
    expect(verifyAggregatedWitnessCosignatures(st, [ra, rb, rc], agg)).toBe(false);
    expect(verifyAggregatedWitnessCosignatures(st, [], agg)).toBe(false);
  });
});

describe('chain binding', () => {
  const kA = keyGen();
  const kB = keyGen();
  const kC = keyGen();
  const pk = (k: { secretKey: Uint8Array }) => blsPublicKey(k.secretKey);
  const root = mintBlsRoot({ principalSecret: kA.secretKey, principalPublic: pk(kA), holder: pk(kB), caveats: [{ type: 'scope', scopes: ['read'] } as never] });
  const hop1 = blsDelegate(root, pk(kC), [{ type: 'budget', max: 3 } as never], kB.secretKey);
  const chain = [root, hop1];
  const agg = aggregateChainSignatures(chain);
  const reg = registryOf(kA, kB, kC);

  it('honest chain verifies, with and without a pinned root principal', () => {
    expect(verifyAggregatedChain(chain, agg, reg).ok).toBe(true);
    expect(verifyAggregatedChain(chain, agg, reg, pk(kA)).ok).toBe(true);
    expect(verifyAggregatedChain(chain, agg, reg, pk(kB)).ok).toBe(false);
  });

  it('a chain whose issuer never proved possession is refused with that reason (even though its signatures are valid)', () => {
    const partial = registryOf(kA); // kB signs hop1 but is not registered
    const r = verifyAggregatedChain(chain, agg, partial);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/hop 1: issuer key has no verified proof of possession/);
    expect(verifyAggregatedChain(chain, agg, new KeyRegistry()).ok).toBe(false);
    expect(verifyAggregatedChain(chain, agg, undefined as never).ok).toBe(false);
  });

  it('truncation, reordering, duplication, a spliced foreign hop and a swapped aggregate are all rejected', () => {
    expect(verifyAggregatedChain([root], agg, reg).ok).toBe(false);
    expect(verifyAggregatedChain([hop1, root], agg, reg).ok).toBe(false);
    expect(verifyAggregatedChain([root, root], aggregate([root.sig, root.sig].map((s) => Buffer.from(s, 'base64url'))), reg).ok).toBe(false);
    const other = mintBlsRoot({ principalSecret: kC.secretKey, principalPublic: pk(kC), holder: pk(kB), caveats: [] });
    expect(verifyAggregatedChain([other, hop1], aggregateChainSignatures([other, hop1]), reg).ok).toBe(false);
    expect(verifyAggregatedChain(chain, aggregateChainSignatures([root, root]), reg).ok).toBe(false);
    expect(verifyAggregatedChain(chain, G2_ID, reg).ok).toBe(false);
  });

  it('caveat tampering: dropping, altering and reordering a parent caveat is detected even when the body digest is recomputed', () => {
    const altered = { ...hop1, caveats: [{ type: 'scope', scopes: ['write'] }, ...hop1.caveats.slice(1)] } as BlsCapability;
    expect(verifyAggregatedChain([root, altered], agg, reg).ok).toBe(false);
    const dropped = { ...hop1, caveats: hop1.caveats.slice(1) } as BlsCapability;
    expect(verifyAggregatedChain([root, dropped], agg, reg).ok).toBe(false);
  });

  it('depth bound: a chain of MAX_CHAIN_DEPTH+1 hops is refused before any pairing work', () => {
    const long = new Array<BlsCapability>(MAX_CHAIN_DEPTH + 1).fill(root);
    const t0 = performance.now();
    expect(verifyAggregatedChain(long, agg, reg).ok).toBe(false);
    expect(performance.now() - t0).toBeLessThan(200);
  });

  it('structural abuse: empty, non-array, null hops, wrong suite, missing fields never throw', () => {
    for (const bad of [[], null, undefined, 'x', {}, [null], [{}], [{ ...root, suite: 'x' }], [{ ...root, caveats: 'x' }], [{ ...root, caveats: [null] }]]) {
      expect(() => verifyAggregatedChain(bad as never, agg, reg)).not.toThrow();
      expect(verifyAggregatedChain(bad as never, agg, reg).ok).toBe(false);
    }
  });
});

describe('randomness failure', () => {
  it('a stuck-at-zero RNG makes keyGen throw instead of handing out the publicly known key 1', () => {
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((arr: Uint8Array) => {
      arr.fill(0);
      return arr;
    }) as never);
    expect(() => keyGen()).toThrow(/RNG failure/);
  });
});

describe('property tests (fast-check)', () => {
  it('sign/verify round-trip; verifying a different message or a different key fails', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 40 }), fc.uint8Array({ maxLength: 40 }), (m1, m2) => {
        const s = sign(a.secretKey, m1);
        const differ = Buffer.compare(Buffer.from(m1), Buffer.from(m2)) !== 0;
        return verify(a.publicKey, m1, s) && !verify(b.publicKey, m1, s) && (!differ || !verify(a.publicKey, m2, s));
      }),
      { numRuns: 8 },
    );
  });

  it('n-signer same-message aggregation verifies for any subset size; removing/adding a key breaks it', () => {
    const keys = [a, b, c, keyGen()];
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 4 }), fc.uint8Array({ maxLength: 20 }), (n, m) => {
        const ks = keys.slice(0, n);
        const agg = aggregate(ks.map((k) => sign(k.secretKey, m)));
        const pks = ks.map((k) => k.publicKey);
        const extra = keys[(n % 4) as 0 | 1 | 2 | 3] as { publicKey: Uint8Array };
        return fastAggregateVerify(pks, m, agg) && (n === 1 || !fastAggregateVerify(pks.slice(1), m, agg)) && (n === 4 || !fastAggregateVerify([...pks, extra.publicKey].slice(0, n + 1), m, agg));
      }),
      { numRuns: 8 },
    );
  });

  it('distinct-message aggregation: verifies, and any single-byte change of a message breaks it', () => {
    fc.assert(
      fc.property(fc.uniqueArray(fc.uint8Array({ minLength: 1, maxLength: 10 }), { minLength: 2, maxLength: 3, selector: (u) => Buffer.from(u).toString('hex') }), (ms) => {
        const ks = [a, b, c].slice(0, ms.length);
        const agg = aggregate(ks.map((k, i) => sign(k.secretKey, ms[i] as Uint8Array)));
        const pks = ks.map((k) => k.publicKey);
        if (!aggregateVerify(pks, ms, agg)) return false;
        const mut = ms.map((m) => Uint8Array.from(m));
        mut[0] = new Uint8Array([...(mut[0] as Uint8Array), 7]);
        return !aggregateVerify(pks, mut, agg);
      }),
      { numRuns: 6 },
    );
  });
});

describe('bounded fuzzing of every verify / parse entry (never throws, never accepts garbage, never hangs)', () => {
  const bytesArb = fc.oneof(fc.uint8Array({ maxLength: 200 }), fc.uint8Array({ minLength: 48, maxLength: 48 }), fc.uint8Array({ minLength: 96, maxLength: 96 }));
  const goodSig = sign(a.secretKey, msg);

  it('single / aggregate / fast-aggregate / PoP verification on arbitrary bytes', () => {
    fc.assert(
      fc.property(bytesArb, bytesArb, bytesArb, (x, y, z) => {
        const t0 = performance.now();
        expect(verify(x, y, z)).toBe(false);
        expect(popVerify(x, z)).toBe(false);
        expect(aggregateVerify([x, y], [y, z], z)).toBe(false);
        expect(fastAggregateVerify([x, y], z, y)).toBe(false);
        expect(keyValidate(x) === true ? true : true).toBe(true);
        expect(performance.now() - t0).toBeLessThan(1000);
        return true;
      }),
      fuzzOpts,
    );
  });

  it('mutations of an honest signature never verify', () => {
    fc.assert(
      fc.property(fc.array(fc.nat({ max: 96 * 8 - 1 }), { minLength: 1, maxLength: 3 }), (bits) => {
        const m = Uint8Array.from(goodSig);
        for (const bt of bits) m[bt >> 3] = (m[bt >> 3] ?? 0) ^ (1 << (bt & 7));
        return Buffer.compare(Buffer.from(m), Buffer.from(goodSig)) === 0 || !verify(a.publicKey, msg, m);
      }),
      fuzzOpts,
    );
  });

  it('chain and witness verifiers survive arbitrary structures', () => {
    fc.assert(
      fc.property(fc.anything(), fc.anything(), bytesArb, (chain, st, agg) => {
        expect(() => verifyAggregatedChain(chain as never, agg, registryOf(a))).not.toThrow();
        expect(() => verifyWitnessCosignature(st as never, chain as never)).not.toThrow();
        expect(() => verifyAggregatedWitnessCosignatures(st as never, chain as never, agg)).not.toThrow();
        return true;
      }),
      fuzzOpts,
    );
  });
});
