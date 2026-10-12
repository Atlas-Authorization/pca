/**
 * Every PQ-signing surface accepts EVERY supported suite through one shared signer-options type
 * (`SignerSuiteOpts`), and verifies it symmetrically under the R2-01 pinning rules.
 *
 * Before this, beacons / revocation epochs / tree heads / witness cosignatures / attestations / judge verdicts /
 * state attestations / settlements / safety certificates took only `{ alg, mlDsa }`, so ML-DSA-87, SLH-DSA, FN-DSA and
 * LESS (and their hybrids) could not be signed on those surfaces at all (they threw "requires ... key material").
 *
 * Per (suite x surface): the genuine artifact carries the suite's `alg` + `pq_pk`; it verifies ONLY under a pin for
 * the named identity (no pin: refused, wrong pin: refused); a forged signer naming the identity is refused even with
 * the real pin. Real backends (FN-DSA wasm active; LESS wasm optional: its cases skip when the backend is absent).
 * SLH-DSA-SHA2-256s is exercised on one surface only (signing takes seconds).
 */
import { describe, expect, it } from 'vitest';
import { b64u, utf8 } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import {
  type FnDsaSuiteKey,
  type LessSuiteKey,
  type PqPinPolicy,
  type SigAlg,
  type SignerSuiteOpts,
  fnDsa1024Keygen,
  fnDsa512Keygen,
  isFnDsaBackendActive,
  isLessBackendActive,
  lessCat1Keygen,
  mlDsa65Keygen,
  mlDsa87Keygen,
  slhDsa128fKeygen,
  slhDsa256sKeygen,
  suitePqPublicKey,
  signSuiteArtifact,
} from './pq';
import { checkRevocationEpoch, signRevocationEpoch } from './revocation';
import { issueLivenessBeacon, verifyLivenessBeacon } from './beacons';
import { cosignTreeHead, signTreeHead, verifyTreeHead, verifyWitnessCosignatures, verifyWitnessedHead, TransparencyLedger } from './ledger';
import { BondLedger, InMemoryBondAccount, verifySettlement } from './bond-settlement';
import { createDevAttestor, verifyAttestation } from './attestation';
import { mintGrant } from './envelope';
import { buildPCActn } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';
import { signJudgeVerdict, verifyJudgeVerdict } from './semantic-threshold';
import { issueSafetyCertificate, verifySafetyCertificate } from './safety-certificate';
import { AttestedStateSource, verifyStateAttestation } from './progress';
import { type Signer, signShare, verifyThreshold } from './threshold';

const seed = (n: number, len = 32) => new Uint8Array(len).fill(n);

interface SuiteCase {
  alg: SigAlg;
  /** key material for identity `n` (distinct n => distinct key) */
  material: (n: number) => Omit<SignerSuiteOpts, 'alg'>;
  skip?: () => boolean;
}

const fn = (gen: typeof fnDsa512Keygen, n: number): FnDsaSuiteKey => ({ ...gen(seed(n)), signSeed: seed(n + 100) });
const less = (n: number): LessSuiteKey => ({ ...lessCat1Keygen(seed(n)), signSeed: seed(n + 100) });

const SUITES: SuiteCase[] = [
  { alg: 'ml-dsa-65', material: (n) => ({ mlDsa: mlDsa65Keygen(seed(n)) }) },
  { alg: 'hybrid-ed25519-ml-dsa-65', material: (n) => ({ mlDsa: mlDsa65Keygen(seed(n)) }) },
  { alg: 'hybrid-nested-ed25519-ml-dsa-65', material: (n) => ({ mlDsa: mlDsa65Keygen(seed(n)) }) },
  { alg: 'ml-dsa-87', material: (n) => ({ mlDsa87: mlDsa87Keygen(seed(n)) }) },
  { alg: 'hybrid-ed25519-ml-dsa-87', material: (n) => ({ mlDsa87: mlDsa87Keygen(seed(n)) }) },
  { alg: 'slh-dsa-sha2-128f', material: (n) => ({ slhDsa: slhDsa128fKeygen(seed(n, 48)) }) },
  { alg: 'hybrid-ed25519-slh-dsa-sha2-128f', material: (n) => ({ slhDsa: slhDsa128fKeygen(seed(n, 48)) }) },
  { alg: 'fn-dsa-512', material: (n) => ({ fnDsa512: fn(fnDsa512Keygen, n) }) },
  { alg: 'fn-dsa-1024', material: (n) => ({ fnDsa1024: fn(fnDsa1024Keygen, n) }) },
  { alg: 'less-cat1', material: (n) => ({ lessCat1: less(n) }), skip: () => !isLessBackendActive() },
  { alg: 'hybrid-ed25519-less-cat1', material: (n) => ({ lessCat1: less(n) }), skip: () => !isLessBackendActive() },
];

interface Ident {
  ed: ReturnType<typeof generateKeyPair>;
  pub: string;
}
const ident = (): Ident => {
  const ed = generateKeyPair();
  return { ed, pub: b64u(ed.publicKey) };
};

/** A surface: mint with `(identity, suite)`, verify with `(artifact, identity, pin)`. */
interface Surface {
  name: string;
  mint: (id: Ident, suite: SignerSuiteOpts) => Record<string, any>;
  verify: (a: Record<string, any>, id: Ident, pin: PqPinPolicy) => boolean;
}

const NOW = 1_000_000;
const head = { instance_id: 'i', principal: 'p', size: 3, root: 'ROOT', prev_root: 'x', timestamp: 5 };
const jv = { actionDigest: 'A'.repeat(43), goalCommitment: 'B'.repeat(43), faithful: true, score: 0.99 };

const SURFACES: Surface[] = [
  {
    name: 'revocation epoch',
    mint: (id, s) => signRevocationEpoch(id.ed.secretKey, { instance_id: 'i', grant_ref: 'g', epoch: 9, set_size: 0, root: 'R', issued_at: NOW, not_after: NOW + 60_000 }, s),
    verify: (a, id, pin) => checkRevocationEpoch(a as never, { guardianPublic: id.pub, now: NOW, grantRef: 'g', ...pin }).ok,
  },
  {
    name: 'liveness beacon',
    mint: (id, s) => issueLivenessBeacon({ issuerSecret: id.ed.secretKey, instance: 'i', seq: 5, issuedAt: 60_000, suite: s }),
    verify: (a, id, pin) => verifyLivenessBeacon(a as never, { issuers: [id.pub], now: 60_000, instance: 'i', ...pin }).ok,
  },
  {
    name: 'signed tree head',
    mint: (id, s) => signTreeHead(id.ed.secretKey, head, s),
    verify: (a, id, pin) => verifyTreeHead(a as never, id.pub, undefined, pin),
  },
  {
    name: 'legacy witnessed head',
    mint: (id, s) => TransparencyLedger.fromEntries([{ commit: 'c' }], 'p').witnessHead(id.ed.secretKey, s),
    verify: (a, id, pin) => verifyWitnessedHead(a as never, id.pub, pin),
  },
  {
    name: 'settlement record',
    mint: (id, s) => new BondLedger({ guardianSecret: id.ed.secretKey, suite: s, accounts: new InMemoryBondAccount({ d: 100 }) }).openBond({ claimId: 'c', amount: 10, depositor: 'd', at: 5 }),
    verify: (a, id, pin) => verifySettlement(a as never, id.pub, pin),
  },
  {
    name: 'safety certificate',
    mint: (id, s) => issueSafetyCertificate({ policy: { ...DEFAULT_RISK_POLICY, bMax: 2, kappa: 2 }, guardianSecret: id.ed.secretKey, issuedAt: 1, suite: s }),
    verify: (a, id, pin) => verifySafetyCertificate(a as never, { guardian: id.pub, ...pin }).ok,
  },
  {
    name: 'judge verdict',
    mint: (id, s) => signJudgeVerdict(id.ed.secretKey, jv, s),
    verify: (a, _id, pin) => verifyJudgeVerdict(a as never, { actionDigest: jv.actionDigest, goalCommitment: jv.goalCommitment }, pin),
  },
];

describe('shared signer-options type: pq_pk resolution covers every suite', () => {
  it.each(SUITES.filter((s) => !s.skip?.()))('$alg: suitePqPublicKey selects the suite key', (c) => {
    const m = c.material(1);
    const pk = suitePqPublicKey(c.alg, m);
    expect(typeof pk).toBe('string');
    expect(suitePqPublicKey(c.alg, c.material(2))).not.toBe(pk);
    // the signed artifact carries the very same key
    const art = signSuiteArtifact(c.alg, { edSecret: generateKeyPair().secretKey, ...m }, utf8('m'));
    expect(art.pq_pk).toBe(pk);
  });
  it('ed25519 and unknown algs have no pq key; a suite with the wrong key material has none (signing then throws)', () => {
    expect(suitePqPublicKey(undefined, { mlDsa: mlDsa65Keygen(seed(1)) })).toBeUndefined();
    expect(suitePqPublicKey('ed25519', { mlDsa: mlDsa65Keygen(seed(1)) })).toBeUndefined();
    expect(suitePqPublicKey('nope', { mlDsa: mlDsa65Keygen(seed(1)) })).toBeUndefined();
    expect(suitePqPublicKey('ml-dsa-87', { mlDsa: mlDsa65Keygen(seed(1)) })).toBeUndefined();
    expect(() => signRevocationEpoch(generateKeyPair().secretKey, { instance_id: 'i', grant_ref: 'g', epoch: 1, set_size: 0, root: 'R', issued_at: 1, not_after: 2 }, { alg: 'ml-dsa-87', mlDsa: mlDsa65Keygen(seed(1)) })).toThrow();
  });
});

for (const c of SUITES) {
  describe.skipIf(c.skip?.() === true)(`${c.alg} on every surface`, () => {
    const real = c.material(11);
    const other = c.material(12);
    const realPk = suitePqPublicKey(c.alg, real)!;
    const otherPk = suitePqPublicKey(c.alg, other)!;

    for (const sf of SURFACES) {
      it(`${sf.name}: carries alg + pq_pk; verifies only under the identity's pin`, () => {
        const id = ident();
        const art = sf.mint(id, { alg: c.alg, ...real });
        expect(art.alg).toBe(c.alg);
        expect(art.pq_pk).toBe(realPk);
        const pin: PqPinPolicy = { pqPins: { [id.pub]: realPk } };
        expect(sf.verify(art, id, pin)).toBe(true);
        expect(sf.verify(art, id, {})).toBe(false); // no pin: refused
        expect(sf.verify(art, id, { pqPins: { [id.pub]: otherPk } })).toBe(false); // wrong pin: refused
        expect(sf.verify(art, id, { allowUnboundPq: true })).toBe(true); // legacy opt-out still works
      });
      it(`${sf.name}: a forger signing under its own key for the named identity is refused even with the real pin`, () => {
        const id = ident();
        const forger = ident();
        const forged = { ...sf.mint(forger, { alg: c.alg, ...other }) };
        // the artifact names the victim's identity but carries/was signed with the forger's keys
        const renamed = renameIdentity(sf.name, forged, id.pub);
        expect(sf.verify(renamed, id, { pqPins: { [id.pub]: realPk } })).toBe(false);
      });
    }

    it('witness cosignature: 2-of-2 pinned cosignatures verify; unpinned or wrong-pinned are refused', () => {
      const sth = signTreeHead(generateKeyPair().secretKey, head);
      const w1 = ident();
      const w2 = ident();
      const m1 = c.material(21);
      const m2 = c.material(22);
      const cos = (w: Ident, m: Omit<SignerSuiteOpts, 'alg'>) => cosignTreeHead(sth, w.ed.secretKey, { alg: c.alg, ...m });
      const signed = { ...sth, witnesses: [cos(w1, m1), cos(w2, m2)] };
      expect(signed.witnesses[0]!.alg).toBe(c.alg);
      expect(signed.witnesses[0]!.pq_pk).toBe(suitePqPublicKey(c.alg, m1));
      const pol = { witnessKeys: [w1.pub, w2.pub], threshold: 2 };
      const pins = { pqPins: { [w1.pub]: suitePqPublicKey(c.alg, m1)!, [w2.pub]: suitePqPublicKey(c.alg, m2)! } };
      expect(verifyWitnessCosignatures(signed, pol)).toBe(false);
      expect(verifyWitnessCosignatures(signed, { ...pol, ...pins })).toBe(true);
      expect(verifyWitnessCosignatures(signed, { ...pol, pqPins: { ...pins.pqPins, [w2.pub]: suitePqPublicKey(c.alg, c.material(23))! } })).toBe(false);
    });

    it('threshold share: signs under the suite and verifies against the signer set\'s registered pq_pk only', () => {
      const id = ident();
      const msg = utf8('threshold message');
      const set = (pq: string): Signer[] => [{ role: 'agent', publicKey: id.pub, pq_pk: pq }];
      const share = signShare('agent', id.ed.secretKey, msg, { signerSet: set(realPk), t: 1 }, { alg: c.alg, ...real });
      expect(share.alg).toBe(c.alg);
      expect(verifyThreshold({ shares: [share] }, msg, set(realPk), 1).ok).toBe(true);
      // a different registered key (the share was bound to the real set) fails, as does a stripped registration
      expect(verifyThreshold({ shares: [share] }, msg, set(otherPk), 1).ok).toBe(false);
      expect(verifyThreshold({ shares: [share] }, msg, [{ role: 'agent', publicKey: id.pub }], 1).ok).toBe(false);
    });

    it('state attestation', async () => {
      const id = ident();
      const req = { goal_commitment: 'g', action_digest: 'a', prior_digest: 'p' } as never;
      const src = new AttestedStateSource({ id: 'src', signerSecret: id.ed.secretKey, observeState: () => ({ a: 1 }), suite: { alg: c.alg, ...real } } as never);
      await src.observe(req);
      const att = src.attestations[0]!;
      expect(att.alg).toBe(c.alg);
      expect(att.pq_pk).toBe(realPk);
      expect(verifyStateAttestation(att, id.pub, { pqPins: { [id.pub]: realPk } })).toBe(true);
      expect(verifyStateAttestation(att, id.pub)).toBe(false);
      expect(verifyStateAttestation(att, id.pub, { pqPins: { [id.pub]: otherPk } })).toBe(false);
    });

    it('software attestation (dev attestor)', async () => {
      const P = generateKeyPair();
      const A = generateKeyPair();
      const tr = ident();
      const NONCE = 'q3Vx8mZ0aT7bLk2RwYp9Hs';
      const T = 1_000_000;
      const grant = mintGrant({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal: 'g',
        envelope: { predicates: [{ verb: 'read', resource: '/a/*' }], caveats: [], risk_policy: DEFAULT_RISK_POLICY, agent_binding: {} } as never }).grant;
      const p = buildPCActn({ aud: 'a', grant, chain: [grant], plan: [{ id: 'n1', verb: 'read', resource: '/a/1', reversibility_class: 'reversible' }], nodeId: 'n1', counter: 1, signerSecret: A.secretKey,
        attestation: { quote_digest: NONCE, epoch: 1, model_id: 'gpt-x', measurement: 'm', operator: 'o' } } as never);
      const expected = { holderPub: encodeKey(A.publicKey), grantRef: p.grant_ref, epoch: 1, nonce: NONCE, nonceIssuedAt: T - 1000 };
      const claims = { model_id: 'gpt-x', weights_digest: 'w', runtime_measurement: 'm', operator: 'o', nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000,
        holder_pub: expected.holderPub, grant_ref: expected.grantRef, epoch: 1 };
      const doc = createDevAttestor(tr.ed.secretKey, { alg: c.alg, ...real }).attest(claims as never);
      expect((doc as any).alg).toBe(c.alg);
      expect((doc as any).pq_pk).toBe(realPk);
      const run = async (extra: object) =>
        (await verifyAttestation({ document: doc as never, ctx: { pcactn: p, grant } as never, expected, nowMs: T, trustedAttestorKeys: [tr.pub], ...extra })).ok;
      expect(await run({ pqPins: { [tr.pub]: realPk } })).toBe(true);
      expect(await run({})).toBe(false);
      expect(await run({ pqPins: { [tr.pub]: otherPk } })).toBe(false);
    });
  });
}

describe('SLH-DSA-SHA2-256s (Category 5), one surface', () => {
  it('liveness beacon: sign + pinned verify', () => {
    const id = ident();
    const kp = slhDsa256sKeygen(seed(7, 96));
    const b = issueLivenessBeacon({ issuerSecret: id.ed.secretKey, instance: 'i', seq: 1, issuedAt: 60_000, suite: { alg: 'slh-dsa-sha2-256s', slhDsa256s: kp } });
    const pk = suitePqPublicKey('slh-dsa-sha2-256s', { slhDsa256s: kp })!;
    expect(b.pq_pk).toBe(pk);
    expect(verifyLivenessBeacon(b, { issuers: [id.pub], now: 60_000, instance: 'i', pqPins: { [id.pub]: pk } }).ok).toBe(true);
    expect(verifyLivenessBeacon(b, { issuers: [id.pub], now: 60_000, instance: 'i' }).ok).toBe(false);
  }, 120_000);
});

describe('backends', () => {
  it('FN-DSA wasm is active (else the FN-DSA cases above prove nothing)', () => expect(isFnDsaBackendActive()).toBe(true));
});

/** Re-point an artifact at another signer identity (the artifact body is NOT re-signed: a forgery). */
function renameIdentity(surface: string, a: Record<string, any>, pub: string): Record<string, any> {
  switch (surface) {
    case 'revocation epoch':
    case 'signed tree head':
    case 'safety certificate':
      return { ...a, guardian: pub };
    case 'liveness beacon':
      return { ...a, issuer: pub };
    case 'legacy witnessed head':
      return { ...a, witness: pub };
    case 'judge verdict':
      return { ...a, judge: pub };
    case 'settlement record':
      return a; // the settlement is verified against the supplied guardian key directly
    default:
      return a;
  }
}
