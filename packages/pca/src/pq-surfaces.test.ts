import { describe, expect, it } from 'vitest';
import { b64u, unb64u, utf8 } from './hash';
import { generateKeyPair } from './keys';
import { mlDsa65Keygen, signWithSuite, verifyWithSuite, bindSuiteFields } from './pq';
import { capHash, delegate, mintRoot, verifyChain } from './capability';
import {
  type Signer,
  type ThresholdShare,
  signShare,
  verifyThreshold,
} from './threshold';
import {
  TransparencyLedger,
  cosignTreeHead,
  signTreeHead,
  verifyHeadConsistency,
  verifyTreeHead,
  verifyWitnessCosignature,
  verifyWitnessCosignatures,
  verifyWitnessedHead,
} from './ledger';
import { checkRevocationEpoch, signRevocationEpoch } from './revocation';
import { issueLivenessBeacon, verifyLivenessBeacon } from './beacons';
import { BondLedger, InMemoryBondAccount, verifySettlement } from './bond-settlement';
import { createAttestationVerifier, attestationRegistry, createDevAttestor } from './attestation';
import { mintGrant } from './envelope';
import { buildPCActn, type PCActn, type VerifyContext } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';
import type { Capability } from './capability';
import { signJudgeVerdict, verifyJudgeVerdict } from './semantic-threshold';
import { issueSafetyCertificate, verifySafetyCertificate } from './safety-certificate';

const HYBRID = 'hybrid-ed25519-ml-dsa-65' as const;
const ML = 'ml-dsa-65' as const;
const ed = () => generateKeyPair();
const ml = (fill: number) => mlDsa65Keygen(new Uint8Array(32).fill(fill));
const flip = (s: string): string => {
  const bytes = unb64u(s);
  bytes[0] = bytes[0]! ^ 0x01;
  return b64u(bytes);
};

// =================================================================================================
// The general seam (pq.ts) — the single agility pair every surface routes through.
// =================================================================================================
describe('signWithSuite / verifyWithSuite (the general seam)', () => {
  const E = ed();
  const M = ml(1);
  const msg = utf8('a message for every surface');

  it('(a) ed25519 (absent/ed25519) is byte-identical to the classical signature', () => {
    const a = signWithSuite(undefined, { edSecret: E.secretKey }, msg);
    const b = signWithSuite('ed25519', { edSecret: E.secretKey }, msg);
    expect(a).toEqual(b);
    expect(a.pq_sig).toBeUndefined();
    expect(verifyWithSuite(undefined, { edPub: b64u(E.publicKey) }, msg, a)).toBe(true);
    expect(verifyWithSuite('ed25519', { edPub: b64u(E.publicKey) }, msg, a)).toBe(true);
  });

  it('(b) ml-dsa-65 and hybrid round-trip', () => {
    const pure = signWithSuite(ML, { mlDsa: M }, msg);
    expect(verifyWithSuite(ML, { mlDsaPub: b64u(M.publicKey) }, msg, pure)).toBe(true);
    const hyb = signWithSuite(HYBRID, { edSecret: E.secretKey, mlDsa: M }, msg);
    expect(typeof hyb.pq_sig).toBe('string');
    expect(verifyWithSuite(HYBRID, { edPub: b64u(E.publicKey), mlDsaPub: b64u(M.publicKey) }, msg, hyb)).toBe(true);
  });

  it('(c) hybrid requires BOTH (drop or corrupt either => fail)', () => {
    const hyb = signWithSuite(HYBRID, { edSecret: E.secretKey, mlDsa: M }, msg);
    const keys = { edPub: b64u(E.publicKey), mlDsaPub: b64u(M.publicKey) };
    expect(verifyWithSuite(HYBRID, keys, msg, { sig: hyb.sig })).toBe(false); // dropped pq_sig
    expect(verifyWithSuite(HYBRID, keys, msg, { sig: flip(hyb.sig), pq_sig: hyb.pq_sig })).toBe(false); // bad ed
    expect(verifyWithSuite(HYBRID, keys, msg, { sig: hyb.sig, pq_sig: flip(hyb.pq_sig!) })).toBe(false); // bad pq
  });

  it('(d) unknown suite is fail-closed (verify false; sign throws)', () => {
    expect(verifyWithSuite('rsa-3072', { edPub: b64u(E.publicKey) }, msg, { sig: 'x' })).toBe(false);
    expect(() => signWithSuite('rsa-3072', { edSecret: E.secretKey }, msg)).toThrow();
  });

  it('bindSuiteFields is additive: ed25519 unchanged, others add alg(+pq_pk)', () => {
    const base = { x: 1, y: 'z' };
    expect(bindSuiteFields(base, undefined)).toEqual(base);
    expect(bindSuiteFields(base, 'ed25519')).toEqual(base);
    expect(bindSuiteFields(base, ML, 'PK')).toEqual({ x: 1, y: 'z', alg: ML, pq_pk: 'PK' });
    expect(bindSuiteFields(base, HYBRID, 'PK')).toEqual({ x: 1, y: 'z', alg: HYBRID, pq_pk: 'PK' });
  });
});

// =================================================================================================
// capability.ts — hop signatures (PRIORITY: the principal ROOT key is the longest-lived)
// =================================================================================================
describe('capability hop signatures (suite-agile)', () => {
  const P = ed();
  const A = ed();
  const Pml = ml(2);
  const Aml = ml(3);
  const caveats = [{ type: 'ttl', secs: 60 }];
  const root = (suite?: { alg?: typeof ML | typeof HYBRID; mlDsa?: ReturnType<typeof ml> }) =>
    mintRoot({ principalSecret: P.secretKey, principalPublic: b64u(P.publicKey), holder: b64u(A.publicKey), caveats, suite });

  it('(a) absent suite is byte-identical to ed25519 and verifies; no suite fields', () => {
    const r0 = root();
    const r1 = root({ alg: undefined });
    expect(r0).toEqual(r1);
    expect('alg' in r0).toBe(false);
    expect('pq_pk' in r0).toBe(false);
    expect('pq_sig' in r0).toBe(false);
    expect(verifyChain([r0], b64u(P.publicKey)).ok).toBe(true);
  });

  it('(b) ml-dsa-65 and hybrid roots + hybrid child chain verify', () => {
    const rMl = root({ alg: ML, mlDsa: Pml });
    expect(rMl.alg).toBe(ML);
    expect(verifyChain([rMl], b64u(P.publicKey)).ok).toBe(true);

    const rHy = root({ alg: HYBRID, mlDsa: Pml });
    expect(rHy.alg).toBe(HYBRID);
    expect(typeof rHy.pq_sig).toBe('string');
    const child = delegate(rHy, b64u(ed().publicKey), [{ type: 'scope', v: 'x' }], A.secretKey, { alg: HYBRID, mlDsa: Aml });
    expect(child.parent).toBe(capHash(rHy));
    expect(verifyChain([rHy, child], b64u(P.publicKey)).ok).toBe(true);
  });

  it('(c) hybrid root: corrupt/drop either signature => chain fails', () => {
    const rHy = root({ alg: HYBRID, mlDsa: Pml });
    expect(verifyChain([{ ...rHy, sig: flip(rHy.sig) }], b64u(P.publicKey)).ok).toBe(false);
    expect(verifyChain([{ ...rHy, pq_sig: flip(rHy.pq_sig!) }], b64u(P.publicKey)).ok).toBe(false);
    const { pq_sig: _d, ...dropped } = rHy;
    void _d;
    expect(verifyChain([dropped as Capability], b64u(P.publicKey)).ok).toBe(false);
  });

  it('(d) unknown suite + downgrade are fail-closed', () => {
    const rHy = root({ alg: HYBRID, mlDsa: Pml });
    expect(verifyChain([{ ...rHy, alg: 'rsa-3072' as never }], b64u(P.publicKey)).ok).toBe(false);
    // strip alg to forge a downgrade to ed25519: the body digest no longer matches the signed one.
    const { alg: _a, pq_pk: _p, pq_sig: _s, ...downgraded } = rHy;
    void _a; void _p; void _s;
    expect(verifyChain([downgraded as Capability], b64u(P.publicKey)).ok).toBe(false);
  });
});

// =================================================================================================
// threshold.ts — guardian / principal cosign (PRIORITY: hybrid guardian)
// =================================================================================================
describe('threshold cosign (suite-agile guardian/principal)', () => {
  const G = ed();
  const Gml = ml(4);
  const msg = utf8('threshold message');
  const edSet: Signer[] = [{ role: 'guardian', publicKey: b64u(G.publicKey) }];
  const hySet: Signer[] = [{ role: 'guardian', publicKey: b64u(G.publicKey), pq_pk: b64u(Gml.publicKey) }];

  it('(a) absent suite is byte-identical to today and verifies', () => {
    const s0 = signShare('guardian', G.secretKey, msg, { signerSet: edSet, t: 1 });
    const s1 = signShare('guardian', G.secretKey, msg, { signerSet: edSet, t: 1 }, { alg: 'ed25519' });
    expect(s0).toEqual(s1);
    expect('alg' in s0).toBe(false);
    expect('pq_sig' in s0).toBe(false);
    expect(verifyThreshold({ shares: [s0] }, msg, edSet, 1).ok).toBe(true);
  });

  it('(b) ml-dsa-65 and hybrid guardian shares verify against the registered pq_pk', () => {
    const sMl = signShare('guardian', G.secretKey, msg, { signerSet: hySet, t: 1 }, { alg: ML, mlDsa: Gml });
    expect(sMl.alg).toBe(ML);
    expect(verifyThreshold({ shares: [sMl] }, msg, hySet, 1).ok).toBe(true);
    const sHy = signShare('guardian', G.secretKey, msg, { signerSet: hySet, t: 1 }, { alg: HYBRID, mlDsa: Gml });
    expect(typeof sHy.pq_sig).toBe('string');
    expect(verifyThreshold({ shares: [sHy] }, msg, hySet, 1).ok).toBe(true);
  });

  it('(c) hybrid share: corrupt/drop either component => not counted', () => {
    const sHy = signShare('guardian', G.secretKey, msg, { signerSet: hySet, t: 1 }, { alg: HYBRID, mlDsa: Gml });
    expect(verifyThreshold({ shares: [{ ...sHy, sig: flip(sHy.sig) }] }, msg, hySet, 1).ok).toBe(false);
    expect(verifyThreshold({ shares: [{ ...sHy, pq_sig: flip(sHy.pq_sig!) }] }, msg, hySet, 1).ok).toBe(false);
    const { pq_sig: _d, ...dropped } = sHy;
    void _d;
    expect(verifyThreshold({ shares: [dropped as ThresholdShare] }, msg, hySet, 1).ok).toBe(false);
  });

  it('(d) unknown suite + downgrade of a hybrid share are fail-closed', () => {
    const sHy = signShare('guardian', G.secretKey, msg, { signerSet: hySet, t: 1 }, { alg: HYBRID, mlDsa: Gml });
    expect(verifyThreshold({ shares: [{ ...sHy, alg: 'rsa-3072' as never }] }, msg, hySet, 1).ok).toBe(false);
    // strip alg to downgrade to ed25519: the share message (suite tag) differs => signature fails.
    const { alg: _a, pq_sig: _s, ...down } = sHy;
    void _a; void _s;
    expect(verifyThreshold({ shares: [down as ThresholdShare] }, msg, hySet, 1).ok).toBe(false);
  });
});

// =================================================================================================
// ledger.ts — signed tree heads + C2SP witness cosignatures + legacy witnessed head
// =================================================================================================
describe('ledger signed tree heads (suite-agile)', () => {
  const G = ed();
  const Gml = ml(5);
  const head = { instance_id: 'ins-1', principal: 'g1', size: 3, root: 'r3', prev_root: 'r2', timestamp: 1000 };

  it('(a) absent suite is byte-identical and verifies', () => {
    const s0 = signTreeHead(G.secretKey, head);
    const s1 = signTreeHead(G.secretKey, head, { alg: 'ed25519' });
    expect(s0).toEqual(s1);
    expect('alg' in s0).toBe(false);
    expect(verifyTreeHead(s0, b64u(G.publicKey))).toBe(true);
  });

  it('(b) ml-dsa-65 + hybrid STH verify under the guardian pq_pk', () => {
    const sMl = signTreeHead(G.secretKey, head, { alg: ML, mlDsa: Gml });
    expect(sMl.alg).toBe(ML);
    expect(verifyTreeHead(sMl, b64u(G.publicKey))).toBe(true);
    const sHy = signTreeHead(G.secretKey, head, { alg: HYBRID, mlDsa: Gml });
    expect(verifyTreeHead(sHy, b64u(G.publicKey))).toBe(true);
  });

  it('(c) hybrid STH: corrupt/drop either signature => fails', () => {
    const sHy = signTreeHead(G.secretKey, head, { alg: HYBRID, mlDsa: Gml });
    expect(verifyTreeHead({ ...sHy, sig: flip(sHy.sig) }, b64u(G.publicKey))).toBe(false);
    expect(verifyTreeHead({ ...sHy, pq_sig: flip(sHy.pq_sig!) }, b64u(G.publicKey))).toBe(false);
    const { pq_sig: _d, ...dropped } = sHy;
    void _d;
    expect(verifyTreeHead(dropped, b64u(G.publicKey))).toBe(false);
  });

  it('(d) unknown suite fails closed; hybrid heads flow through verifyHeadConsistency', () => {
    const sHy = signTreeHead(G.secretKey, head, { alg: HYBRID, mlDsa: Gml });
    expect(verifyTreeHead({ ...sHy, alg: 'rsa-3072' as never }, b64u(G.publicKey))).toBe(false);
    // A real append-only pair from a ledger: both heads hybrid, a genuine RFC-9162 consistency proof.
    const l = new TransparencyLedger('g1');
    l.append({} as never, { salt: 's1' });
    const r1 = l.head();
    const older = signTreeHead(G.secretKey, { instance_id: 'ins-1', principal: 'g1', size: 1, root: r1.root, prev_root: '', timestamp: 1 }, { alg: HYBRID, mlDsa: Gml });
    l.append({} as never, { salt: 's2' });
    const r2 = l.head();
    const newer = signTreeHead(G.secretKey, { instance_id: 'ins-1', principal: 'g1', size: 2, root: r2.root, prev_root: r1.root, timestamp: 2 }, { alg: HYBRID, mlDsa: Gml });
    const proof = l.consistencyProof(1, 2);
    expect(verifyHeadConsistency(older, newer, proof, b64u(G.publicKey))).toBe(true);
  });

  it('witness cosignature + k-of-n are suite-agile', () => {
    const sth = signTreeHead(G.secretKey, head, { alg: HYBRID, mlDsa: Gml });
    const W = ed();
    const Wml = ml(6);
    const c0 = cosignTreeHead(sth, W.secretKey);
    expect('alg' in c0).toBe(false);
    expect(verifyWitnessCosignature(sth, c0, b64u(W.publicKey))).toBe(true);
    const cHy = cosignTreeHead(sth, W.secretKey, { alg: HYBRID, mlDsa: Wml });
    expect(verifyWitnessCosignature(sth, cHy, b64u(W.publicKey))).toBe(true);
    expect(verifyWitnessCosignature(sth, { ...cHy, pq_sig: flip(cHy.pq_sig!) }, b64u(W.publicKey))).toBe(false);
    expect(verifyWitnessCosignature(sth, { ...cHy, alg: 'rsa-3072' as never }, b64u(W.publicKey))).toBe(false);
    const withWitness = { ...sth, witnesses: [cHy] };
    expect(verifyWitnessCosignatures(withWitness, { witnessKeys: [b64u(W.publicKey)], threshold: 1 })).toBe(true);
  });

  it('legacy witnessHead is suite-agile', () => {
    const l = TransparencyLedger.fromEntries([{ commit: 'c0' }], 'g1');
    const Gml2 = ml(7);
    const wh0 = l.witnessHead(G.secretKey);
    expect('alg' in wh0).toBe(false);
    expect(verifyWitnessedHead(wh0, b64u(G.publicKey))).toBe(true);
    const whHy = l.witnessHead(G.secretKey, { alg: HYBRID, mlDsa: Gml2 });
    expect(verifyWitnessedHead(whHy, b64u(G.publicKey))).toBe(true);
    expect(verifyWitnessedHead({ ...whHy, pq_sig: flip(whHy.pq_sig!) }, b64u(G.publicKey))).toBe(false);
  });
});

// =================================================================================================
// revocation.ts — signed revocation epochs
// =================================================================================================
describe('revocation epoch (suite-agile)', () => {
  const G = ed();
  const Gml = ml(8);
  const body = { instance_id: 'ins-1', grant_ref: 'g1', epoch: 2, set_size: 1, root: 'rroot', issued_at: 1000, not_after: 1000 + 60_000 };
  const opts = { guardianPublic: b64u(G.publicKey), now: 1000, grantRef: 'g1' };

  it('(a) absent suite is byte-identical and verifies', () => {
    const e0 = signRevocationEpoch(G.secretKey, body);
    const e1 = signRevocationEpoch(G.secretKey, body, { alg: 'ed25519' });
    expect(e0).toEqual(e1);
    expect('alg' in e0).toBe(false);
    expect(checkRevocationEpoch(e0, opts).ok).toBe(true);
  });

  it('(b) ml-dsa-65 + hybrid verify', () => {
    const eMl = signRevocationEpoch(G.secretKey, body, { alg: ML, mlDsa: Gml });
    expect(checkRevocationEpoch(eMl, opts).ok).toBe(true);
    const eHy = signRevocationEpoch(G.secretKey, body, { alg: HYBRID, mlDsa: Gml });
    expect(checkRevocationEpoch(eHy, opts).ok).toBe(true);
  });

  it('(c)/(d) hybrid requires both; unknown fails closed', () => {
    const eHy = signRevocationEpoch(G.secretKey, body, { alg: HYBRID, mlDsa: Gml });
    expect(checkRevocationEpoch({ ...eHy, sig: flip(eHy.sig) }, opts).ok).toBe(false);
    expect(checkRevocationEpoch({ ...eHy, pq_sig: flip(eHy.pq_sig!) }, opts).ok).toBe(false);
    expect(checkRevocationEpoch({ ...eHy, alg: 'rsa-3072' as never }, opts).ok).toBe(false);
  });
});

// =================================================================================================
// beacons.ts — liveness beacons
// =================================================================================================
describe('liveness beacon (suite-agile)', () => {
  const I = ed();
  const Iml = ml(9);
  const common = { instance: 'ins-1', seq: 1, issuedAt: 60_000 };
  const chk = { issuers: [b64u(I.publicKey)], now: 60_000, instance: 'ins-1' };

  it('(a) absent suite is byte-identical and verifies', () => {
    const b0 = issueLivenessBeacon({ issuerSecret: I.secretKey, ...common });
    const b1 = issueLivenessBeacon({ issuerSecret: I.secretKey, ...common, suite: { alg: 'ed25519' } });
    expect(b0).toEqual(b1);
    expect('alg' in b0).toBe(false);
    expect(verifyLivenessBeacon(b0, chk).ok).toBe(true);
  });

  it('(b)/(c)/(d) ml-dsa + hybrid verify; hybrid needs both; unknown fails', () => {
    const bMl = issueLivenessBeacon({ issuerSecret: I.secretKey, ...common, suite: { alg: ML, mlDsa: Iml } });
    expect(verifyLivenessBeacon(bMl, chk).ok).toBe(true);
    const bHy = issueLivenessBeacon({ issuerSecret: I.secretKey, ...common, suite: { alg: HYBRID, mlDsa: Iml } });
    expect(verifyLivenessBeacon(bHy, chk).ok).toBe(true);
    expect(verifyLivenessBeacon({ ...bHy, sig: flip(bHy.sig) }, chk).ok).toBe(false);
    expect(verifyLivenessBeacon({ ...bHy, pq_sig: flip(bHy.pq_sig!) }, chk).ok).toBe(false);
    expect(verifyLivenessBeacon({ ...bHy, alg: 'rsa-3072' as never }, chk).ok).toBe(false);
  });
});

// =================================================================================================
// bond-settlement.ts — guardian-signed settlement records
// =================================================================================================
describe('bond settlement record (suite-agile)', () => {
  const G = ed();
  const Gml = ml(10);
  const mk = (suite?: { alg?: 'ed25519' | typeof ML | typeof HYBRID; mlDsa?: ReturnType<typeof ml> }) =>
    new BondLedger({ guardianSecret: G.secretKey, suite, accounts: new InMemoryBondAccount({ dep: 100 }) });

  it('(a) absent suite is byte-identical and verifies', () => {
    const r0 = mk().openBond({ claimId: 'c1', amount: 10, depositor: 'dep', at: 5 });
    const r1 = mk({ alg: 'ed25519' }).openBond({ claimId: 'c1', amount: 10, depositor: 'dep', at: 5 });
    expect(r0).toEqual(r1);
    expect('alg' in r0).toBe(false);
    expect(verifySettlement(r0, b64u(G.publicKey))).toBe(true);
  });

  it('(b)/(c)/(d) ml-dsa + hybrid verify; hybrid needs both; unknown fails', () => {
    const lMl = mk({ alg: ML, mlDsa: Gml });
    const rMl = lMl.openBond({ claimId: 'c1', amount: 10, depositor: 'dep', at: 5 });
    expect(rMl.alg).toBe(ML);
    expect(verifySettlement(rMl, lMl.guardianPublicKey)).toBe(true);

    const lHy = mk({ alg: HYBRID, mlDsa: Gml });
    const rHy = lHy.openBond({ claimId: 'c1', amount: 10, depositor: 'dep', at: 5 });
    expect(verifySettlement(rHy, lHy.guardianPublicKey)).toBe(true);
    expect(verifySettlement({ ...rHy, sig: flip(rHy.sig) }, lHy.guardianPublicKey)).toBe(false);
    expect(verifySettlement({ ...rHy, pq_sig: flip(rHy.pq_sig!) }, lHy.guardianPublicKey)).toBe(false);
    expect(verifySettlement({ ...rHy, alg: 'rsa-3072' as never }, lHy.guardianPublicKey)).toBe(false);
  });
});

// =================================================================================================
// attestation.ts — software attestation documents
// =================================================================================================
describe('software attestation (suite-agile)', () => {
  const P = ed();
  const A = ed();
  const NONCE = 'nonce-epoch-1';
  const T = 1_000_000;
  const HOLDER = b64u(A.publicKey);
  const CLAIMS = { model_id: 'gpt-x', weights_digest: 'w1', runtime_measurement: 'm1', operator: 'acme', nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000 };
  const grant: Capability = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: b64u(P.publicKey),
    holder: HOLDER,
    goal: 'g',
    envelope: { predicates: [{ verb: 'read', resource: '/a/*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  }).grant;
  const pcactn = (): PCActn =>
    buildPCActn({
      aud: 'aud', grant, chain: [grant], plan: [{ id: 'n1', verb: 'read', resource: '/a/1', reversibility_class: 'reversible' }],
      nodeId: 'n1', counter: 1, signerSecret: A.secretKey,
      attestation: { quote_digest: NONCE, epoch: 1, model_id: 'gpt-x', measurement: 'm1', operator: 'acme' },
    });
  const expected = (ctx: VerifyContext) => ({ holderPub: HOLDER, grantRef: ctx.pcactn.grant_ref, epoch: 1, nonce: NONCE, nonceIssuedAt: T - 1000 });
  const bindOf = { holder_pub: HOLDER, grant_ref: pcactn().grant_ref, epoch: 1 };
  const run = async (doc: ReturnType<ReturnType<typeof createDevAttestor>['attest']>, trusted: string): Promise<boolean> => {
    const verify = createAttestationVerifier({ trustedAttestorKeys: [trusted], resolveDocument: attestationRegistry([doc]), expectedBinding: expected, now: () => T });
    const r = await verify({ pcactn: pcactn(), grant });
    return r.enforced === true && r.ok === true;
  };

  it('(a) absent suite is byte-identical and verifies end-to-end', async () => {
    const sec = ed().secretKey;
    const a0 = createDevAttestor(sec);
    const a1 = createDevAttestor(sec, { alg: 'ed25519' });
    const d0 = a0.attest({ ...CLAIMS, ...bindOf });
    const d1 = a1.attest({ ...CLAIMS, ...bindOf });
    expect(d0).toEqual(d1);
    expect('alg' in d0).toBe(false);
    expect(await run(d0, a0.publicKey)).toBe(true);
  });

  it('(b) ml-dsa-65 + hybrid documents verify', async () => {
    const sec = ed().secretKey;
    const aMl = createDevAttestor(sec, { alg: ML, mlDsa: ml(11) });
    const dMl = aMl.attest({ ...CLAIMS, ...bindOf });
    expect(dMl.alg).toBe(ML);
    expect(await run(dMl, aMl.publicKey)).toBe(true);
    const aHy = createDevAttestor(sec, { alg: HYBRID, mlDsa: ml(11) });
    const dHy = aHy.attest({ ...CLAIMS, ...bindOf });
    expect(await run(dHy, aHy.publicKey)).toBe(true);
  });

  it('(c)/(d) hybrid needs both; unknown suite fails closed', async () => {
    const sec = ed().secretKey;
    const aHy = createDevAttestor(sec, { alg: HYBRID, mlDsa: ml(11) });
    const dHy = aHy.attest({ ...CLAIMS, ...bindOf });
    expect(await run({ ...dHy, pq_sig: flip(dHy.pq_sig!) }, aHy.publicKey)).toBe(false);
    expect(await run({ ...dHy, sig: flip(dHy.sig) }, aHy.publicKey)).toBe(false);
    expect(await run({ ...dHy, alg: 'rsa-3072' as never }, aHy.publicKey)).toBe(false);
  });
});

// =================================================================================================
// semantic-threshold.ts — judge verdicts
// =================================================================================================
describe('semantic judge verdict (suite-agile)', () => {
  const J = ed();
  const Jml = ml(12);
  const v = { actionDigest: 'a'.repeat(43), goalCommitment: 'g'.repeat(43), faithful: true, score: 0.9 };
  const exp = { actionDigest: v.actionDigest, goalCommitment: v.goalCommitment };

  it('(a) absent suite is byte-identical and verifies', () => {
    const d0 = signJudgeVerdict(J.secretKey, v);
    const d1 = signJudgeVerdict(J.secretKey, v, { alg: 'ed25519' });
    expect(d0).toEqual(d1);
    expect('alg' in d0).toBe(false);
    expect(verifyJudgeVerdict(d0, exp)).toBe(true);
  });

  it('(b)/(c)/(d) ml-dsa + hybrid verify; hybrid needs both; unknown fails', () => {
    const dMl = signJudgeVerdict(J.secretKey, v, { alg: ML, mlDsa: Jml });
    expect(dMl.alg).toBe(ML);
    expect(verifyJudgeVerdict(dMl, exp)).toBe(true);
    const dHy = signJudgeVerdict(J.secretKey, v, { alg: HYBRID, mlDsa: Jml });
    expect(verifyJudgeVerdict(dHy, exp)).toBe(true);
    expect(verifyJudgeVerdict({ ...dHy, sig: flip(dHy.sig) }, exp)).toBe(false);
    expect(verifyJudgeVerdict({ ...dHy, pq_sig: flip(dHy.pq_sig!) }, exp)).toBe(false);
    expect(verifyJudgeVerdict({ ...dHy, alg: 'rsa-3072' as never }, exp)).toBe(false);
  });
});

// =================================================================================================
// safety-certificate.ts — guardian-signed safety certificate
// =================================================================================================
describe('safety certificate (suite-agile)', () => {
  const G = ed();
  const Gml = ml(13);
  const args = { policy: { ...DEFAULT_RISK_POLICY, bMax: 2, kappa: 2 }, guardianSecret: G.secretKey, issuedAt: 1 };

  it('(a) absent suite is byte-identical and verifies', () => {
    const c0 = issueSafetyCertificate(args);
    const c1 = issueSafetyCertificate({ ...args, suite: { alg: 'ed25519' } });
    expect(c0).toEqual(c1);
    expect('alg' in c0).toBe(false);
    expect(verifySafetyCertificate(c0).ok).toBe(true);
  });

  it('(b)/(c)/(d) ml-dsa + hybrid verify; hybrid needs both; unknown fails', () => {
    const cMl = issueSafetyCertificate({ ...args, suite: { alg: ML, mlDsa: Gml } });
    expect(cMl.alg).toBe(ML);
    expect(verifySafetyCertificate(cMl).ok).toBe(true);
    const cHy = issueSafetyCertificate({ ...args, suite: { alg: HYBRID, mlDsa: Gml } });
    expect(verifySafetyCertificate(cHy).ok).toBe(true);
    expect(verifySafetyCertificate({ ...cHy, sig: flip(cHy.sig) }).ok).toBe(false);
    expect(verifySafetyCertificate({ ...cHy, pq_sig: flip(cHy.pq_sig!) }).ok).toBe(false);
    expect(verifySafetyCertificate({ ...cHy, alg: 'rsa-3072' as never }).ok).toBe(false);
  });
});
