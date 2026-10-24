/**
 * r13 mutation kills for frost-pq.ts: exact refusals of frostCosignRepresentative / signHybridFrostCosign (malformed
 * group key, unknown suite, threshold forwarding) and verifyHybridFrostCosign's exact verdicts for every deny path,
 * including both fail-closed catch blocks (a throwing artifact getter and an invalid signer set) and the optional pq_pk.
 */
import { describe, expect, it } from 'vitest';
import { b64u, utf8 } from './hash';
import { frostTrustedDealerKeygen, type FrostParticipantShare } from './frost';
import { mlDsa65Keygen, type MlDsaKeyPair } from './pq';
import { frostCosignRepresentative, signHybridFrostCosign, verifyHybridFrostCosign, type HybridFrostSignature } from './frost-pq';

/** Run f, capturing its value or its error (name + message), so a mutant that throws fails an assertion, not an error. */
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
/** Async form of settle. */
const settleAsync = async <T>(f: () => Promise<T>) => {
  try {
    return { ok: true as const, value: await f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};

const MSG = utf8('r13-g7-frost-pq');
const HYBRID = 'hybrid-ed25519-ml-dsa-65' as const;
const fromHex = (h: string): Uint8Array => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
const kg = frostTrustedDealerKeygen(2, 3, {
  secret: fromHex('7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304'),
  coefficients: [fromHex('178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204')],
});
const quorum: FrostParticipantShare[] = [kg.participantShares[0]!, kg.participantShares[2]!];
const GPK = kg.groupPublicKey;
const GPK64 = b64u(GPK);
const IDS = quorum.map((p) => p.identifier);
const guardian: MlDsaKeyPair = mlDsa65Keygen(new Uint8Array(32).fill(7));
const GPQ = b64u(guardian.publicKey);

const classical = signHybridFrostCosign(GPK, quorum, MSG);
const hybrid = signHybridFrostCosign(GPK, quorum, MSG, { groupAlg: HYBRID, guardianMlDsa: guardian });

describe('frostCosignRepresentative', () => {
  it('refuses a malformed group key with the exact RangeError', () => {
    expect(() => frostCosignRepresentative('nope', MSG, IDS, 'ed25519')).toThrow(new RangeError('frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point'));
  });
});

describe('signHybridFrostCosign', () => {
  it('refuses an unknown suite before signing', () => {
    expect(() => signHybridFrostCosign(GPK, quorum, MSG, { groupAlg: 'bogus' as never, guardianMlDsa: guardian })).toThrow(new RangeError("signHybridFrostCosign: unknown groupAlg 'bogus'"));
  });
  it('forwards the threshold to the FROST round', () => {
    expect(() => signHybridFrostCosign(GPK, quorum, MSG, { threshold: 3 })).toThrow('frostCosign: quorum of 2 is below the threshold t=3');
    expect(settle(() => verifyHybridFrostCosign(signHybridFrostCosign(GPK, quorum, MSG, { threshold: 2 }), MSG, GPK64, IDS).ok)).toEqual({ ok: true, value: true });
  });
});

describe('verifyHybridFrostCosign', () => {
  it('accepts the classical and hybrid artifacts', () => {
    expect(settle(() => verifyHybridFrostCosign(classical, MSG, GPK64, IDS))).toEqual({ ok: true, value: { ok: true, groupAlg: 'ed25519', edOk: true, pqOk: false } });
    expect(settle(() => verifyHybridFrostCosign(hybrid, MSG, GPK64, IDS, { guardianPqPublicKey: GPQ }))).toEqual({ ok: true, value: { ok: true, groupAlg: HYBRID, edOk: true, pqOk: true } });
    const { pq_pk: _p, ...noPk } = hybrid;
    expect(settle(() => verifyHybridFrostCosign(noPk, MSG, GPK64, IDS, { guardianPqPublicKey: GPQ }))).toEqual({ ok: true, value: { ok: true, groupAlg: HYBRID, edOk: true, pqOk: true } });
  });
  it('malformed artifact', () => {
    const D = { ok: false, edOk: false, pqOk: false, reason: 'malformed artifact' };
    for (const a of [null, undefined, 'sig', { sig: 5 }, {}]) expect(settle(() => verifyHybridFrostCosign(a as never, MSG, GPK64, IDS))).toEqual({ ok: true, value: D });
  });
  it('malformed group key', () => {
    const D = { ok: false, edOk: false, pqOk: false, reason: 'malformed group public key' };
    expect(settle(() => verifyHybridFrostCosign(classical, MSG, 5 as never, IDS))).toEqual({ ok: true, value: D });
    expect(settle(() => verifyHybridFrostCosign(classical, MSG, 'abc', IDS))).toEqual({ ok: true, value: D });
  });
  it('unknown expected suite and a suite mismatch (with the resolved suite)', () => {
    expect(settle(() => verifyHybridFrostCosign(classical, MSG, GPK64, IDS, { expectGroupAlg: 'bogus' as never }))).toEqual({ ok: true, value: { ok: false, edOk: false, pqOk: false, reason: "unknown expected groupAlg 'bogus'" } });
    expect(settle(() => verifyHybridFrostCosign(classical, MSG, GPK64, IDS, { expectGroupAlg: HYBRID }))).toEqual({ ok: true, value: {
      ok: false, edOk: false, pqOk: false, groupAlg: 'ed25519', reason: "groupAlg 'ed25519' does not match the required 'hybrid-ed25519-ml-dsa-65'",
    } });
  });
  it('a bad classical signature', () => {
    expect(settle(() => verifyHybridFrostCosign({ sig: hybrid.pq_sig!.slice(0, 86) }, MSG, GPK64, IDS))).toEqual({ ok: true, value: { ok: false, edOk: false, pqOk: false, groupAlg: 'ed25519', reason: 'FROST Ed25519 group signature did not verify' } });
  });
  it('fails closed when reading the signature throws', () => {
    let reads = 0;
    const a = { get sig(): string { if (reads++ > 0) throw new Error('boom'); return classical.sig; } } as HybridFrostSignature;
    expect(settle(() => verifyHybridFrostCosign(a, MSG, GPK64, IDS))).toEqual({ ok: true, value: { ok: false, edOk: false, pqOk: false, groupAlg: 'ed25519', reason: 'FROST Ed25519 group signature did not verify' } });
  });
  it('hybrid needs a well-formed registered guardian key', () => {
    const D = { ok: false, edOk: false, pqOk: false, groupAlg: HYBRID, reason: 'hybrid groupAlg requires a registered guardian ML-DSA-65 public key' };
    expect(settle(() => verifyHybridFrostCosign(hybrid, MSG, GPK64, IDS))).toEqual({ ok: true, value: D });
    expect(settle(() => verifyHybridFrostCosign(hybrid, MSG, GPK64, IDS, { guardianPqPublicKey: 5 as never }))).toEqual({ ok: true, value: D });
    expect(settle(() => verifyHybridFrostCosign(hybrid, MSG, GPK64, IDS, { guardianPqPublicKey: GPK64 }))).toEqual({ ok: true, value: D });
  });
  it('a pq_pk that is not the registered key', () => {
    const other = b64u(mlDsa65Keygen(new Uint8Array(32).fill(9)).publicKey);
    expect(settle(() => verifyHybridFrostCosign(hybrid, MSG, GPK64, IDS, { guardianPqPublicKey: other }))).toEqual({ ok: true, value: { ok: false, edOk: false, pqOk: false, groupAlg: HYBRID, reason: 'artifact pq_pk does not match the registered guardian ML-DSA key' } });
  });
  it('a missing co-signature', () => {
    const { pq_sig: _s, ...noSig } = hybrid;
    expect(settle(() => verifyHybridFrostCosign(noSig, MSG, GPK64, IDS, { guardianPqPublicKey: GPQ }))).toEqual({ ok: true, value: { ok: false, edOk: false, pqOk: false, groupAlg: HYBRID, reason: 'hybrid groupAlg declared but the guardian ML-DSA co-signature is missing' } });
  });
  it('an invalid signer set fails the PQ half closed', () => {
    expect(settle(() => verifyHybridFrostCosign(hybrid, MSG, GPK64, [], { guardianPqPublicKey: GPQ }))).toEqual({ ok: true, value: { ok: false, groupAlg: HYBRID, edOk: true, pqOk: false, reason: 'guardian ML-DSA-65 co-signature did not verify' } });
    expect(settle(() => verifyHybridFrostCosign(hybrid, MSG, GPK64, [IDS[0]!], { guardianPqPublicKey: GPQ }))).toEqual({ ok: true, value: { ok: false, groupAlg: HYBRID, edOk: true, pqOk: false, reason: 'guardian ML-DSA-65 co-signature did not verify' } });
  });
});
