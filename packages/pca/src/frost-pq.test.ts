import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { b64u, unb64u, utf8 } from './hash';
import { ed25519 } from '@noble/curves/ed25519';
import { frostTrustedDealerKeygen, type FrostParticipantShare } from './frost';
import { mlDsa65Keygen, type MlDsaKeyPair } from './pq';
import {
  DEFAULT_FROST_GROUP_ALG,
  frostCosignRepresentative,
  frostSignerSetDigest,
  resolveFrostGroupAlg,
  signHybridFrostCosign,
  verifyHybridFrostCosign,
  type HybridFrostSignature,
} from './frost-pq';

const MSG = utf8('the-same-canonical-threshold-message');
const HYBRID = 'hybrid-ed25519-ml-dsa-65' as const;

/** Deterministic 2-of-3 FROST group (RFC 9591 Appendix secret/coeff) so the group key is fixed. */
const fromHex = (h: string): Uint8Array => {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
};
function group() {
  const kg = frostTrustedDealerKeygen(2, 3, {
    secret: fromHex('7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304'),
    coefficients: [fromHex('178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204')],
  });
  // quorum = participants 1 and 3 (a 2-of-3 signing set).
  const quorum: FrostParticipantShare[] = [kg.participantShares[0]!, kg.participantShares[2]!];
  return { groupPublicKey: kg.groupPublicKey, groupPublicKeyB64u: b64u(kg.groupPublicKey), quorum, ids: quorum.map((p) => p.identifier) };
}

/** Flip one data bit of a base64url byte field (keeps the decoded length, so canonicality is intact). */
function flip(b64: string, idx = 0): string {
  const bytes = unb64u(b64);
  bytes[idx] = (bytes[idx] ?? 0) ^ 0x01;
  return b64u(bytes);
}

/** A deterministic guardian ML-DSA-65 key pair. */
function guardianKey(label = 'guardian'): MlDsaKeyPair {
  const seed = new Uint8Array(32);
  for (let i = 0; i < label.length && i < 32; i++) seed[i] = label.charCodeAt(i);
  return mlDsa65Keygen(seed);
}

describe('resolveFrostGroupAlg / defaults', () => {
  it('absent resolves to the classical ed25519 default', () => {
    expect(DEFAULT_FROST_GROUP_ALG).toBe('ed25519');
    expect(resolveFrostGroupAlg(undefined)).toBe('ed25519');
    expect(resolveFrostGroupAlg('ed25519')).toBe('ed25519');
    expect(resolveFrostGroupAlg(HYBRID)).toBe(HYBRID);
  });
  it('an unknown groupAlg resolves to null (fail-closed)', () => {
    expect(resolveFrostGroupAlg('ml-dsa-65')).toBeNull();
    expect(resolveFrostGroupAlg('nonsense')).toBeNull();
    expect(resolveFrostGroupAlg(42)).toBeNull();
  });
});

describe('frostSignerSetDigest', () => {
  it('is order-insensitive and duplicate-free', () => {
    const a = frostSignerSetDigest([1, 3]);
    expect(b64u(frostSignerSetDigest([3, 1]))).toBe(b64u(a));
    expect(b64u(frostSignerSetDigest([3, 1, 1, 3]))).toBe(b64u(a));
    // a DIFFERENT quorum yields a different digest
    expect(b64u(frostSignerSetDigest([1, 2]))).not.toBe(b64u(a));
  });
  it('rejects an empty or malformed signer set', () => {
    expect(() => frostSignerSetDigest([])).toThrow(/empty/);
    expect(() => frostSignerSetDigest([0])).toThrow(/positive/);
    expect(() => frostSignerSetDigest([1.5])).toThrow(/positive/);
    expect(() => frostSignerSetDigest([-1])).toThrow(/positive/);
  });
});

describe('signHybridFrostCosign + verifyHybridFrostCosign — classical ed25519 back-compat', () => {
  it('ed25519-only (default): the artifact is just { sig } and verifies', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG);
    expect(art.sig).toBeTypeOf('string');
    expect(art.groupAlg).toBeUndefined();
    expect(art.pq_sig).toBeUndefined();
    expect(art.pq_pk).toBeUndefined();
    // the sig is a genuine plain Ed25519 signature under the group key (FROST aggregate)
    expect(ed25519.verify(unb64u(art.sig), MSG, groupPublicKey, { zip215: false })).toBe(true);

    const v = verifyHybridFrostCosign(art, MSG, groupPublicKeyB64u, ids);
    expect(v.ok).toBe(true);
    expect(v.groupAlg).toBe('ed25519');
    expect(v.edOk).toBe(true);
    expect(v.pqOk).toBe(false); // no PQ half in the classical suite
  });

  it('explicit ed25519 groupAlg verifies the same way', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: 'ed25519' });
    expect(verifyHybridFrostCosign(art, MSG, groupPublicKeyB64u, ids).ok).toBe(true);
  });

  it('a tampered ed25519 aggregate is denied', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG);
    const v = verifyHybridFrostCosign({ ...art, sig: flip(art.sig) }, MSG, groupPublicKeyB64u, ids);
    expect(v.ok).toBe(false);
    expect(v.edOk).toBe(false);
    expect(v.reason).toMatch(/Ed25519/);
  });

  it('a tampered message is denied', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG);
    expect(verifyHybridFrostCosign(art, utf8('a-different-message'), groupPublicKeyB64u, ids).ok).toBe(false);
  });
});

describe('signHybridFrostCosign + verifyHybridFrostCosign — hybrid ed25519 + ML-DSA-65 (fail-closed)', () => {
  it('honest flow: BOTH the FROST aggregate and the guardian ML-DSA co-sign verify => allow', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const g = guardianKey();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: HYBRID, guardianMlDsa: g });
    expect(art.groupAlg).toBe(HYBRID);
    expect(art.pq_sig).toBeTypeOf('string');
    expect(art.pq_pk).toBe(b64u(g.publicKey));
    // the classical half is STILL a plain Ed25519 FROST aggregate (unchanged)
    expect(ed25519.verify(unb64u(art.sig), MSG, groupPublicKey, { zip215: false })).toBe(true);

    const v = verifyHybridFrostCosign(art, MSG, groupPublicKeyB64u, ids, { guardianPqPublicKey: b64u(g.publicKey) });
    expect(v.ok).toBe(true);
    expect(v.groupAlg).toBe(HYBRID);
    expect(v.edOk).toBe(true);
    expect(v.pqOk).toBe(true);
  });

  it('tamper the Ed25519 half => deny (pq still ok, but BOTH are required)', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const g = guardianKey();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: HYBRID, guardianMlDsa: g });
    const v = verifyHybridFrostCosign({ ...art, sig: flip(art.sig, 1) }, MSG, groupPublicKeyB64u, ids, { guardianPqPublicKey: b64u(g.publicKey) });
    expect(v.ok).toBe(false);
    expect(v.edOk).toBe(false);
    expect(v.pqOk).toBe(true);
    expect(v.reason).toMatch(/Ed25519/);
  });

  it('tamper the ML-DSA half => deny (ed still ok, but BOTH are required)', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const g = guardianKey();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: HYBRID, guardianMlDsa: g });
    const v = verifyHybridFrostCosign({ ...art, pq_sig: flip(art.pq_sig!) }, MSG, groupPublicKeyB64u, ids, { guardianPqPublicKey: b64u(g.publicKey) });
    expect(v.ok).toBe(false);
    expect(v.edOk).toBe(true);
    expect(v.pqOk).toBe(false);
    expect(v.reason).toMatch(/ML-DSA/);
  });

  it('hybrid declared but the PQ co-sign is ABSENT => deny (the pq-hybrid-missing-pqsig case)', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const g = guardianKey();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: HYBRID, guardianMlDsa: g });
    const stripped: HybridFrostSignature = { sig: art.sig, groupAlg: HYBRID, pq_pk: art.pq_pk };
    const v = verifyHybridFrostCosign(stripped, MSG, groupPublicKeyB64u, ids, { guardianPqPublicKey: b64u(g.publicKey) });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/missing/);
  });

  it('hybrid with NO registered guardian key supplied => deny (cannot be verified on a self-asserted key)', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const g = guardianKey();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: HYBRID, guardianMlDsa: g });
    const v = verifyHybridFrostCosign(art, MSG, groupPublicKeyB64u, ids); // no guardianPqPublicKey
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/registered guardian/);
  });

  it('a pq_pk that disagrees with the registered guardian key => deny (no key-swap)', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const g = guardianKey();
    const impostor = guardianKey('impostor');
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: HYBRID, guardianMlDsa: g });
    // artifact self-asserts the honest pq_pk, but the verifier's REGISTERED key is the impostor's.
    const v = verifyHybridFrostCosign(art, MSG, groupPublicKeyB64u, ids, { guardianPqPublicKey: b64u(impostor.publicKey) });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/does not match/);
  });

  it('a co-sign is bound to its signer set: a different quorum at verify => deny', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum } = group();
    const g = guardianKey();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: HYBRID, guardianMlDsa: g });
    // verify under a DIFFERENT signer set than the one bound at signing (ids were [1,3]).
    const v = verifyHybridFrostCosign(art, MSG, groupPublicKeyB64u, [1, 2], { guardianPqPublicKey: b64u(g.publicKey) });
    expect(v.ok).toBe(false);
    expect(v.pqOk).toBe(false);
  });

  it('the guardian ML-DSA co-sign cannot be lifted to a different group public key', () => {
    const { groupPublicKey, quorum, ids } = group();
    const other = group(); // same deterministic key — so build a genuinely different group key instead
    const g = guardianKey();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: HYBRID, guardianMlDsa: g });
    // a syntactically-valid but WRONG 32-byte group key: the ed half fails and the representative differs.
    const wrongGpk = b64u(ed25519.getPublicKey(new Uint8Array(32).fill(7)));
    void other;
    const v = verifyHybridFrostCosign(art, MSG, wrongGpk, ids, { guardianPqPublicKey: b64u(g.publicKey) });
    expect(v.ok).toBe(false);
  });

  it('signHybridFrostCosign throws if a hybrid suite has no guardian ML-DSA key (fail-closed signer)', () => {
    const { groupPublicKey, quorum } = group();
    expect(() => signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: HYBRID })).toThrow(/guardian ML-DSA/);
  });
});

describe('verifyHybridFrostCosign — downgrade guard + robustness', () => {
  it('pinning expectGroupAlg=hybrid denies an ed25519-only artifact (no silent downgrade)', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const g = guardianKey();
    const classical = signHybridFrostCosign(groupPublicKey, quorum, MSG); // ed25519-only
    const v = verifyHybridFrostCosign(classical, MSG, groupPublicKeyB64u, ids, { expectGroupAlg: HYBRID, guardianPqPublicKey: b64u(g.publicKey) });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/does not match the required/);
  });

  it('pinning expectGroupAlg=hybrid accepts a genuine hybrid artifact', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const g = guardianKey();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: HYBRID, guardianMlDsa: g });
    expect(verifyHybridFrostCosign(art, MSG, groupPublicKeyB64u, ids, { expectGroupAlg: HYBRID, guardianPqPublicKey: b64u(g.publicKey) }).ok).toBe(true);
  });

  it('an unknown groupAlg on the artifact is denied', () => {
    const { groupPublicKey, groupPublicKeyB64u, quorum, ids } = group();
    const art = signHybridFrostCosign(groupPublicKey, quorum, MSG);
    const v = verifyHybridFrostCosign({ ...art, groupAlg: 'ml-dsa-65' as never }, MSG, groupPublicKeyB64u, ids);
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/unknown groupAlg/);
  });

  it('never throws on garbage input', () => {
    expect(() => verifyHybridFrostCosign(undefined as never, MSG, 'x', [1])).not.toThrow();
    expect(verifyHybridFrostCosign({} as never, MSG, 'x', [1]).ok).toBe(false);
    expect(verifyHybridFrostCosign({ sig: 'x' }, MSG, 'not-a-key', [1]).ok).toBe(false);
  });

  it('the exported representative binds group key, message, signer set, and suite', () => {
    const { groupPublicKeyB64u, ids } = group();
    const base = frostCosignRepresentative(groupPublicKeyB64u, MSG, ids, HYBRID);
    // changing any bound component changes the representative bytes
    expect(b64u(frostCosignRepresentative(groupPublicKeyB64u, utf8('other'), ids, HYBRID))).not.toBe(b64u(base));
    expect(b64u(frostCosignRepresentative(groupPublicKeyB64u, MSG, [1, 2], HYBRID))).not.toBe(b64u(base));
    expect(b64u(frostCosignRepresentative(groupPublicKeyB64u, MSG, ids, 'ed25519'))).not.toBe(b64u(base));
  });
});

// ---- conformance corpus (the committed golden/adversarial vectors must re-verify) ----------------

interface FrostPqVector {
  name: string;
  class: 'positive' | 'negative';
  description: string;
  message: string;
  group_public_key: string;
  signer_set: number[];
  guardian_pq_public_key?: string;
  expect_group_alg?: 'ed25519' | 'hybrid-ed25519-ml-dsa-65';
  artifact: HybridFrostSignature;
  expect: { ok: boolean; edOk: boolean; pqOk: boolean; groupAlg?: string };
}

describe('frost-pq conformance corpus', () => {
  const corpus = JSON.parse(
    readFileSync(join(__dirname, '..', 'conformance', 'frost-pq-vectors.json'), 'utf8'),
  ) as { format: number; suite: string; vectors: FrostPqVector[] };

  it('is the frost-pq hybrid co-sign suite', () => {
    expect(corpus.format).toBe(1);
    expect(corpus.suite).toBe('frost-pq-hybrid-guardian-cosign');
    expect(corpus.vectors.length).toBeGreaterThanOrEqual(8);
  });

  for (const v of corpus.vectors) {
    it(v.name, () => {
      const opts: { guardianPqPublicKey?: string; expectGroupAlg?: 'ed25519' | 'hybrid-ed25519-ml-dsa-65' } = {};
      if (v.guardian_pq_public_key !== undefined) opts.guardianPqPublicKey = v.guardian_pq_public_key;
      if (v.expect_group_alg !== undefined) opts.expectGroupAlg = v.expect_group_alg;
      const r = verifyHybridFrostCosign(v.artifact, unb64u(v.message), v.group_public_key, v.signer_set, opts);
      expect(r.ok).toBe(v.expect.ok);
      expect(r.edOk).toBe(v.expect.edOk);
      expect(r.pqOk).toBe(v.expect.pqOk);
      expect(v.expect.ok).toBe(v.class === 'positive');
    });
  }
});
