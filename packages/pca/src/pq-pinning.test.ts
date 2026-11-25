import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytes, utf8 } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import {
  type PqPinPolicy,
  bindSuiteFields,
  encodeMlDsaPublicKey,
  mlDsa65Keygen,
  pqPinFor,
  signPqBinding,
  signSuiteArtifact,
  verifyPinnedSuite,
} from './pq';
import { checkRevocationEpoch, signRevocationEpoch } from './revocation';
import { issueLivenessBeacon, livenessBeaconMessage, verifyLivenessBeacon } from './beacons';
import { cosignTreeHead, signTreeHead, verifyTreeHead, verifyWitnessCosignatures, verifyWitnessedHead, TransparencyLedger } from './ledger';
import { verifySettlement } from './bond-settlement';
import { BondLedger, InMemoryBondAccount } from './bond-ledger-testing';
import { attestationBindingB64u, createDevAttestor, verifyAttestation } from './attestation';
import { mintGrant } from './envelope';
import { buildPCActn } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';
import { semanticJudgeMessage, signJudgeVerdict, statementOf, verifyJudgeVerdict } from './semantic-threshold';
import { issueSafetyCertificate, verifySafetyCertificate } from './safety-certificate';
import { AttestedStateSource, verifyStateAttestation } from './progress';

/**
 * R2-01 regression: a pure-PQ / hybrid artifact is verified under the PQ key the VERIFIER pins for the named
 * identity, never under the artifact's own `pq_pk`. An attacker who holds none of the identity's secrets sets
 * alg=ml-dsa-65, embeds its own ML-DSA key, signs, and names the victim. Each surface must reject that by default,
 * reject it even when the victim's real key is pinned, and accept the genuine artifact under the pin.
 */
const ML = 'ml-dsa-65' as const;
const HY = 'hybrid-ed25519-ml-dsa-65' as const;
const ed = () => generateKeyPair();
const ml = (n: number) => mlDsa65Keygen(new Uint8Array(32).fill(n));
const pk = (m: ReturnType<typeof ml>) => encodeMlDsaPublicKey(m.publicKey);

interface Id {
  ed: ReturnType<typeof ed>;
  pub: string;
  ml: ReturnType<typeof ml>;
  pin: PqPinPolicy;
}
const identity = (n: number): Id => {
  const e = ed();
  const m = ml(n);
  const pub = b64u(e.publicKey);
  return { ed: e, pub, ml: m, pin: { pqPins: { [pub]: pk(m) } } };
};
const victim = identity(21);
const atk = { ed: ed(), ml: ml(99) };

describe('verifyPinnedSuite + pq binding', () => {
  const msg = utf8('m');
  it('ed25519 needs no pin; pure/hybrid refused without a pin; pinned key required to match', () => {
    const e = ed();
    const pub = b64u(e.publicKey);
    const s = signSuiteArtifact(undefined, { edSecret: e.secretKey }, msg);
    expect(verifyPinnedSuite(undefined, pub, undefined, msg, s)).toBe(true);
    const m = ml(1);
    for (const alg of [ML, HY] as const) {
      const a = signSuiteArtifact(alg, { edSecret: e.secretKey, mlDsa: m }, msg);
      expect(verifyPinnedSuite(alg, pub, a.pq_pk, msg, a)).toBe(false); // no pin: fail closed
      expect(verifyPinnedSuite(alg, pub, a.pq_pk, msg, a, { allowUnboundPq: true })).toBe(true);
      expect(verifyPinnedSuite(alg, pub, a.pq_pk, msg, a, { pqPins: { [pub]: pk(m) } })).toBe(true);
      expect(verifyPinnedSuite(alg, pub, a.pq_pk, msg, a, { pqPins: { [pub]: pk(ml(2)) } })).toBe(false);
    }
  });
  it('a signed binding yields a pin only when the identity signed it', () => {
    const e = ed();
    const pub = b64u(e.publicKey);
    const b = signPqBinding(e.secretKey, pub, pk(ml(3)), 1, 'inst');
    expect(pqPinFor(b, 'inst')).toEqual({ [pub]: pk(ml(3)) });
    expect(pqPinFor({ ...b, pq: pk(ml(4)) }, 'inst')).toBeNull();
    expect(pqPinFor(signPqBinding(ed().secretKey, pub, pk(ml(4)), 1, 'inst'), 'inst')).toBeNull();
  });
});

describe('revocation epoch', () => {
  const now = 1_000_000;
  const body = { instance_id: 'i', grant_ref: 'g', epoch: 9, set_size: 0, root: 'R', issued_at: now, not_after: now + 60_000 };
  const forge = () => ({ ...signRevocationEpoch(atk.ed.secretKey, body, { alg: ML, mlDsa: atk.ml }), guardian: victim.pub });
  const opts = (p: object) => ({ guardianPublic: victim.pub, now, grantRef: 'g', ...p });
  it('rejects the forged epoch (default and under the real pin); accepts the genuine one', () => {
    expect(checkRevocationEpoch(forge(), opts({ allowUnboundPq: true })).ok).toBe(true); // the PoC forgery is a valid signature: only the pin stops it
    expect(checkRevocationEpoch(forge(), opts({})).ok).toBe(false);
    expect(checkRevocationEpoch(forge(), opts(victim.pin)).ok).toBe(false);
    for (const alg of [ML, HY] as const) {
      const ok = signRevocationEpoch(victim.ed.secretKey, body, { alg, mlDsa: victim.ml });
      expect(checkRevocationEpoch(ok, opts({})).ok).toBe(false);
      expect(checkRevocationEpoch(ok, opts(victim.pin)).ok).toBe(true);
    }
  });
});

describe('liveness beacon', () => {
  const now = 60_000;
  const common = { instance: 'i', seq: 5, issuedAt: now };
  const chk = (p: object) => ({ issuers: [victim.pub], now, instance: 'i', ...p });
  it('rejects a beacon forged for the pinned issuer; accepts the genuine one under the pin', () => {
    const genuine = issueLivenessBeacon({ issuerSecret: victim.ed.secretKey, ...common, suite: { alg: ML, mlDsa: victim.ml } });
    const atkBeacon: any = issueLivenessBeacon({ issuerSecret: atk.ed.secretKey, ...common, suite: { alg: ML, mlDsa: atk.ml } });
    const { sig: _a, pq_sig: _b, ...fb } = { ...atkBeacon, issuer: victim.pub };
    void _a; void _b;
    const forged = { ...fb, ...signSuiteArtifact(ML, { edSecret: atk.ed.secretKey, mlDsa: atk.ml }, livenessBeaconMessage(fb as never)) };
    expect(verifyLivenessBeacon(forged, chk({ allowUnboundPq: true })).ok).toBe(true);
    expect(verifyLivenessBeacon(forged, chk({})).ok).toBe(false);
    expect(verifyLivenessBeacon(forged, chk(victim.pin)).ok).toBe(false);
    expect(verifyLivenessBeacon(genuine, chk({})).ok).toBe(false);
    expect(verifyLivenessBeacon(genuine, chk(victim.pin)).ok).toBe(true);
  });
});

describe('tree head, witness cosignatures, legacy witnessed head', () => {
  const head = { instance_id: 'i', principal: 'p', size: 3, root: 'ROOT', prev_root: 'x', timestamp: 5 };
  it('STH: forged rejected, genuine accepted only under the pin', () => {
    const forged = { ...signTreeHead(atk.ed.secretKey, head, { alg: ML, mlDsa: atk.ml }), guardian: victim.pub };
    expect(verifyTreeHead(forged, victim.pub, undefined, { allowUnboundPq: true })).toBe(true);
    expect(verifyTreeHead(forged, victim.pub)).toBe(false);
    expect(verifyTreeHead(forged, victim.pub, undefined, victim.pin)).toBe(false);
    const ok = signTreeHead(victim.ed.secretKey, head, { alg: HY, mlDsa: victim.ml });
    expect(verifyTreeHead(ok, victim.pub)).toBe(false);
    expect(verifyTreeHead(ok, victim.pub, undefined, victim.pin)).toBe(true);
  });
  it('2-of-2 witness cosignatures: forged rejected, genuine accepted under pins', () => {
    const w1 = identity(31);
    const w2 = identity(32);
    const sth = signTreeHead(victim.ed.secretKey, head);
    const forgedCos = (w: Id) => ({ ...cosignTreeHead(sth, atk.ed.secretKey, { alg: ML, mlDsa: atk.ml }), key: w.pub });
    const forged = { ...sth, witnesses: [forgedCos(w1), forgedCos(w2)] };
    const pins = { pqPins: { ...w1.pin.pqPins, ...w2.pin.pqPins } };
    const pol = { witnessKeys: [w1.pub, w2.pub], threshold: 2 };
    expect(verifyWitnessCosignatures(forged, pol)).toBe(false);
    expect(verifyWitnessCosignatures(forged, { ...pol, ...pins })).toBe(false);
    expect(verifyTreeHead(forged, victim.pub, { ...pol, ...pins })).toBe(false);
    const real = { ...sth, witnesses: [w1, w2].map((w) => cosignTreeHead(sth, w.ed.secretKey, { alg: ML, mlDsa: w.ml })) };
    expect(verifyWitnessCosignatures(real, pol)).toBe(false);
    expect(verifyWitnessCosignatures(real, { ...pol, ...pins })).toBe(true);
    expect(verifyTreeHead(real, victim.pub, { ...pol, ...pins })).toBe(true);
  });
  it('legacy witnessed head', () => {
    const l = TransparencyLedger.fromEntries([{ commit: 'c' }], 'p');
    const forged = { ...l.witnessHead(atk.ed.secretKey, { alg: ML, mlDsa: atk.ml }), witness: victim.pub };
    expect(verifyWitnessedHead(forged, victim.pub, victim.pin)).toBe(false);
    const ok = l.witnessHead(victim.ed.secretKey, { alg: ML, mlDsa: victim.ml });
    expect(verifyWitnessedHead(ok, victim.pub)).toBe(false);
    expect(verifyWitnessedHead(ok, victim.pub, victim.pin)).toBe(true);
  });
});

describe('settlement, safety certificate, state attestation', () => {
  it('settlement record', () => {
    const mk = (secret: Uint8Array, m: ReturnType<typeof ml>) => new BondLedger({ guardianSecret: secret, suite: { alg: ML, mlDsa: m }, accounts: new InMemoryBondAccount({ d: 100 }) });
    const forged = mk(atk.ed.secretKey, atk.ml).openBond({ claimId: 'c', amount: 10, depositor: 'd', at: 5 });
    expect(verifySettlement(forged, victim.pub, victim.pin)).toBe(false);
    const ok = mk(victim.ed.secretKey, victim.ml).openBond({ claimId: 'c', amount: 10, depositor: 'd', at: 5 });
    expect(verifySettlement(ok, victim.pub)).toBe(false);
    expect(verifySettlement(ok, victim.pub, victim.pin)).toBe(true);
  });
  it('safety certificate', () => {
    const args = (s: Uint8Array) => ({ policy: { ...DEFAULT_RISK_POLICY, bMax: 2, kappa: 2 }, guardianSecret: s, issuedAt: 1 });
    const forged = { ...issueSafetyCertificate({ ...args(atk.ed.secretKey), suite: { alg: ML, mlDsa: atk.ml } }), guardian: victim.pub };
    expect(verifySafetyCertificate(forged, { guardian: victim.pub, ...victim.pin }).ok).toBe(false);
    const ok = issueSafetyCertificate({ ...args(victim.ed.secretKey), suite: { alg: ML, mlDsa: victim.ml } });
    expect(verifySafetyCertificate(ok, { guardian: victim.pub }).ok).toBe(false);
    expect(verifySafetyCertificate(ok, { guardian: victim.pub, ...victim.pin }).ok).toBe(true);
  });
  it('state attestation', async () => {
    const src = (s: Uint8Array, m: ReturnType<typeof ml>) => new AttestedStateSource({ id: 'src', signerSecret: s, observeState: () => ({ a: 1 }), suite: { alg: ML, mlDsa: m } } as never);
    const req = { goal_commitment: 'g', action_digest: 'a', prior_digest: 'p' } as never;
    const f = src(atk.ed.secretKey, atk.ml);
    await f.observe(req);
    expect(verifyStateAttestation(f.attestations[0]!, victim.pub, victim.pin)).toBe(false);
    const g = src(victim.ed.secretKey, victim.ml);
    await g.observe(req);
    expect(verifyStateAttestation(g.attestations[0]!, victim.pub)).toBe(false);
    expect(verifyStateAttestation(g.attestations[0]!, victim.pub, victim.pin)).toBe(true);
  });
});

describe('judge verdict and software attestation', () => {
  const v = { actionDigest: 'A'.repeat(43), goalCommitment: 'B'.repeat(43), faithful: true, score: 0.99 };
  const exp = { actionDigest: v.actionDigest, goalCommitment: v.goalCommitment };
  it('judge verdict', () => {
    const j = identity(41);
    const forged: any = { ...signJudgeVerdict(atk.ed.secretKey, v, { alg: ML, mlDsa: atk.ml }), judge: j.pub };
    forged.sig = signSuiteArtifact(ML, { mlDsa: atk.ml }, semanticJudgeMessage(statementOf(forged))).sig;
    expect(verifyJudgeVerdict(forged, exp, { allowUnboundPq: true })).toBe(true);
    expect(verifyJudgeVerdict(forged, exp)).toBe(false);
    expect(verifyJudgeVerdict(forged, exp, j.pin)).toBe(false);
    const ok = signJudgeVerdict(j.ed.secretKey, v, { alg: ML, mlDsa: j.ml });
    expect(verifyJudgeVerdict(ok, exp)).toBe(false);
    expect(verifyJudgeVerdict(ok, exp, j.pin)).toBe(true);
  });
  it('software attestation', async () => {
    const P = ed(), A = ed(), TR = identity(51);
    const NONCE = 'q3Vx8mZ0aT7bLk2RwYp9Hs';
    const T = 1_000_000;
    const grant = mintGrant({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal: 'g',
      envelope: { predicates: [{ verb: 'read', resource: '/a/*' }], caveats: [], risk_policy: DEFAULT_RISK_POLICY, agent_binding: {} } as never }).grant;
    const p = buildPCActn({ aud: 'a', grant, chain: [grant], plan: [{ id: 'n1', verb: 'read', resource: '/a/1', reversibility_class: 'reversible' }], nodeId: 'n1', counter: 1, signerSecret: A.secretKey,
      attestation: { quote_digest: NONCE, epoch: 1, model_id: 'gpt-x', measurement: 'm', operator: 'o' } } as never);
    const expected = { holderPub: encodeKey(A.publicKey), grantRef: p.grant_ref, epoch: 1, nonce: NONCE, nonceIssuedAt: T - 1000 };
    const claims = { model_id: 'gpt-x', weights_digest: 'w', runtime_measurement: 'm', operator: 'o', nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000,
      holder_pub: expected.holderPub, grant_ref: expected.grantRef, epoch: 1 };
    const run = async (doc: unknown, extra: object = {}) =>
      (await verifyAttestation({ document: doc as never, ctx: { pcactn: p, grant } as never, expected, nowMs: T, trustedAttestorKeys: [TR.pub], ...extra })).ok;
    // forged: names the trusted attestor, signed by the attacker's own ML-DSA key
    const body: any = { model_id: 'gpt-x', weights_digest: 'w', runtime_measurement: 'm', operator: 'o', nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000,
      attestor: TR.pub, mode: 'software', binding: attestationBindingB64u({ holderPub: expected.holderPub, grantRef: expected.grantRef, epoch: 1, nonce: NONCE }),
      ...bindSuiteFields({}, ML, pk(atk.ml)) };
    const dom = utf8('atlas-pca/attest/v1\0');
    const d = canonicalBytes(body);
    const m = new Uint8Array(dom.length + d.length);
    m.set(dom);
    m.set(d, dom.length);
    const forged = { ...body, ...signSuiteArtifact(ML, { edSecret: atk.ed.secretKey, mlDsa: atk.ml }, m) };
    expect(await run(forged, { allowUnboundPq: true })).toBe(true);
    expect(await run(forged)).toBe(false);
    expect(await run(forged, TR.pin)).toBe(false);
    const genuine = createDevAttestor(TR.ed.secretKey, { alg: ML, mlDsa: TR.ml }).attest(claims as never);
    expect(await run(genuine)).toBe(false);
    expect(await run(genuine, TR.pin)).toBe(true);
  });
});
