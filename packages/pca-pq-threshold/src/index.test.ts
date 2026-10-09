import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  type FrostParticipantShare,
  type MlDsaKeyPair,
  type PCActn,
  type PlanNode,
  attenuate,
  b64u,
  buildPCActn,
  encodeKey,
  frostCosign,
  frostTrustedDealerKeygen,
  generateKeyPair,
  mintGrant,
  mlDsa65Keygen,
  mlDsa65Sign,
  thresholdMessage,
} from '@atlasauth/pca';
import {
  HYBRID_CLASSICAL_ALG,
  HYBRID_PQ_ALG,
  type HybridThresholdArtifact,
  foldHybridStepUp,
  hybridThresholdSign,
  verifyHybridStepUp,
  verifyHybridThreshold,
} from './index';

const NOW = Date.now();

function seed(n: number): Uint8Array {
  return new Uint8Array(32).fill(n & 0xff);
}

function pqKeys(m: number): MlDsaKeyPair[] {
  return Array.from({ length: m }, (_, i) => mlDsa65Keygen(seed(i + 1)));
}

/** A FROST t-of-n group plus the quorum (first t shares). */
function frostGroup(t: number, n: number): { groupPublicKey: Uint8Array; quorum: FrostParticipantShare[]; all: FrostParticipantShare[] } {
  const kg = frostTrustedDealerKeygen(t, n);
  return { groupPublicKey: kg.groupPublicKey, quorum: kg.participantShares.slice(0, t), all: kg.participantShares };
}

/** A base PCActn + grant, mirroring the core threshold.test buildLoop. */
function buildLoop(counter = 1): { grant: ReturnType<typeof mintGrant>['grant']; pcactn: PCActn } {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const { grant } = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const c1 = attenuate(grant, [{ type: 'task' }], A.secretKey);
  const nodes: PlanNode[] = [{ id: 'n1', verb: 'wire_transfer', resource: 'ledger', reversibility_class: 'R3' }];
  const pcactn = buildPCActn({
    aud: 'test-aud',
    now: NOW,
    grant,
    chain: [grant, c1],
    plan: nodes,
    nodeId: 'n1',
    counter,
    signerSecret: A.secretKey,
    riskClaim: { r: 0.9, inputs: {} },
  });
  return { grant, pcactn };
}

describe('hybrid PQ-threshold (real): classical FROST + ML-DSA co-signature quorum', () => {
  it('signs and verifies with a 2-of-3 FROST quorum AND a 2-of-3 ML-DSA co-signature quorum', () => {
    const { pcactn } = buildLoop();
    const fg = frostGroup(2, 3);
    const pk = pqKeys(3);

    const artifact = hybridThresholdSign(pcactn, {
      frost: { groupPublicKey: fg.groupPublicKey, quorum: fg.quorum, t: 2 },
      pqSigners: [{ keyPair: pk[0]! }, { keyPair: pk[1]! }],
      pqT: 2,
    });

    expect(artifact.frost.alg).toBe(HYBRID_CLASSICAL_ALG);
    expect(artifact.pq.alg).toBe(HYBRID_PQ_ALG);
    expect(artifact.pq.signers).toHaveLength(2);

    const verdict = verifyHybridThreshold(pcactn, artifact, {
      groupKey: fg.groupPublicKey,
      pqPublicKeys: pk.map((k) => k.publicKey),
      t: 2,
      pqT: 2,
    });
    expect(verdict.ok).toBe(true);
    expect(verdict.frost).toBe(true);
    expect(verdict.pq.ok).toBe(true);
    expect(verdict.pq.count).toBe(2);
  });

  it('fails CLOSED when the FROST quorum is short (both at signing and at verify)', () => {
    const { pcactn } = buildLoop();
    const fg = frostGroup(2, 3);
    const pk = pqKeys(2);

    // (a) A sub-threshold classical quorum cannot even be signed.
    expect(() =>
      hybridThresholdSign(pcactn, {
        frost: { groupPublicKey: fg.groupPublicKey, quorum: fg.quorum.slice(0, 1), t: 2 },
        pqSigners: [{ keyPair: pk[0]! }],
      }),
    ).toThrow(/below the threshold/);

    // (b) A FROST signature that is NOT a genuine t-of-n quorum of the trusted group (here a valid
    //     aggregate from a DIFFERENT / rogue group) does not verify under the trusted group key.
    const good = hybridThresholdSign(pcactn, {
      frost: { groupPublicKey: fg.groupPublicKey, quorum: fg.quorum, t: 2 },
      pqSigners: [{ keyPair: pk[0]! }, { keyPair: pk[1]! }],
      pqT: 2,
    });
    const rogue = frostGroup(2, 3);
    const rogueAgg = frostCosign(rogue.groupPublicKey, rogue.quorum, thresholdMessage(pcactn), { threshold: 2 });
    const tampered: HybridThresholdArtifact = { ...good, frost: { ...good.frost, sig: b64u(rogueAgg) } };

    const verdict = verifyHybridThreshold(pcactn, tampered, {
      groupKey: fg.groupPublicKey, // still the TRUSTED group key
      pqPublicKeys: pk.map((k) => k.publicKey),
      t: 2,
      pqT: 2,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.frost).toBe(false);
    expect(verdict.pq.ok).toBe(true); // the PQ quorum is independent and still holds
    expect(verdict.reason).toMatch(/FROST aggregate does not verify/);
  });

  it('fails CLOSED when the PQ quorum is short (independently of the classical quorum)', () => {
    const { pcactn } = buildLoop();
    const fg = frostGroup(2, 3);
    const pk = pqKeys(3);

    const artifact = hybridThresholdSign(pcactn, {
      frost: { groupPublicKey: fg.groupPublicKey, quorum: fg.quorum, t: 2 },
      pqSigners: [{ keyPair: pk[0]! }, { keyPair: pk[1]! }],
      pqT: 2,
    });

    const verdict = verifyHybridThreshold(pcactn, artifact, {
      groupKey: fg.groupPublicKey,
      pqPublicKeys: pk.map((k) => k.publicKey),
      t: 2,
      pqT: 3, // require three, only two co-signed
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.frost).toBe(true); // classical quorum is independent and still holds
    expect(verdict.pq.ok).toBe(false);
    expect(verdict.pq.count).toBe(2);
    expect(verdict.pq.need).toBe(3);
    expect(verdict.reason).toMatch(/post-quantum quorum short/);
  });

  it('fails CLOSED when a PQ co-signature is over a DIFFERENT action (it does not count)', () => {
    const { pcactn } = buildLoop(1);
    const other = buildLoop(2).pcactn; // a different action => different thresholdMessage bytes
    const fg = frostGroup(2, 3);
    const pk = pqKeys(3);

    // Two honest co-sigs over THIS action, plus one over the WRONG action.
    const msg = thresholdMessage(pcactn);
    const wrong = thresholdMessage(other);
    const artifact: HybridThresholdArtifact = {
      v: 1,
      digest: '',
      frost: {
        alg: HYBRID_CLASSICAL_ALG,
        group_pk: b64u(fg.groupPublicKey),
        sig: b64u(frostCosign(fg.groupPublicKey, fg.quorum, msg, { threshold: 2 })),
        t: 2,
        quorum: 2,
      },
      pq: {
        alg: HYBRID_PQ_ALG,
        pqT: 3,
        signers: [
          { pk: b64u(pk[0]!.publicKey), sig: b64u(mlDsa65Sign(pk[0]!.secretKey, msg)) },
          { pk: b64u(pk[1]!.publicKey), sig: b64u(mlDsa65Sign(pk[1]!.secretKey, msg)) },
          { pk: b64u(pk[2]!.publicKey), sig: b64u(mlDsa65Sign(pk[2]!.secretKey, wrong)) }, // wrong action
        ],
      },
    };

    const base = { groupKey: fg.groupPublicKey, pqPublicKeys: pk.map((k) => k.publicKey), t: 2 };
    // pqT=3 fails: the wrong-action co-sig does not count, so only 2 of 3 hold.
    const short = verifyHybridThreshold(pcactn, artifact, { ...base, pqT: 3 });
    expect(short.ok).toBe(false);
    expect(short.pq.count).toBe(2);
    // pqT=2 passes on the two honest co-sigs; the wrong-action one is simply ignored.
    const okTwo = verifyHybridThreshold(pcactn, artifact, { ...base, pqT: 2 });
    expect(okTwo.ok).toBe(true);
    expect(okTwo.pq.count).toBe(2);
  });

  it('rejects a downgraded classical threshold (artifact declares t below the required tier)', () => {
    const { pcactn } = buildLoop();
    const fg = frostGroup(2, 3);
    const pk = pqKeys(2);
    const artifact = hybridThresholdSign(pcactn, {
      frost: { groupPublicKey: fg.groupPublicKey, quorum: fg.quorum, t: 2 },
      pqSigners: [{ keyPair: pk[0]! }, { keyPair: pk[1]! }],
      pqT: 2,
    });
    const verdict = verifyHybridThreshold(pcactn, artifact, {
      groupKey: fg.groupPublicKey,
      pqPublicKeys: pk.map((k) => k.publicKey),
      t: 3, // demand a higher tier than the artifact declares
      pqT: 2,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.frost).toBe(false);
    expect(verdict.reason).toMatch(/below the required t=3|downgrade/);
  });
});

describe('PCActn step-up fold: tier-2 / tier-3 are PQ-protected', () => {
  it('tier-2: folds the hybrid into the PCActn and verifies end-to-end (FROST 2-of-3 + ML-DSA 2-of-3)', async () => {
    const { grant, pcactn } = buildLoop();
    const fg = frostGroup(2, 3);
    const pk = pqKeys(3);
    const artifact = hybridThresholdSign(pcactn, {
      frost: { groupPublicKey: fg.groupPublicKey, quorum: fg.quorum, t: 2 },
      pqSigners: [{ keyPair: pk[0]! }, { keyPair: pk[1]! }],
      pqT: 2,
    });
    const stepUp = foldHybridStepUp(pcactn, artifact);
    expect(stepUp.pcactn.threshold?.shares).toHaveLength(1);

    const res = await verifyHybridStepUp(stepUp, {
      grant,
      groupKey: fg.groupPublicKey,
      pqPublicKeys: pk.map((k) => k.publicKey),
      t: 2,
      pqT: 2,
      audience: 'test-aud',
      nowEpoch: NOW,
    });
    expect(res.allow).toBe(true);
    expect(res.core.checks.threshold).toBe('pass');
    expect(res.core.checks.leaf_signature).toBe('pass');
    expect(res.pq.ok).toBe(true);
  });

  it('tier-2 fails closed when the PQ quorum is short', async () => {
    const { grant, pcactn } = buildLoop();
    const fg = frostGroup(2, 3);
    const pk = pqKeys(3);
    const artifact = hybridThresholdSign(pcactn, {
      frost: { groupPublicKey: fg.groupPublicKey, quorum: fg.quorum, t: 2 },
      pqSigners: [{ keyPair: pk[0]! }],
      pqT: 1,
    });
    const stepUp = foldHybridStepUp(pcactn, artifact);

    const res = await verifyHybridStepUp(stepUp, {
      grant,
      groupKey: fg.groupPublicKey,
      pqPublicKeys: pk.map((k) => k.publicKey),
      t: 2,
      pqT: 2, // require two PQ co-sigs, only one is present
      audience: 'test-aud',
      nowEpoch: NOW,
    });
    expect(res.allow).toBe(false);
    expect(res.core.checks.threshold).toBe('fail');
    expect(res.pq.ok).toBe(false);
  });

  it('tier-2 fails closed when the folded FROST aggregate is tampered', async () => {
    const { grant, pcactn } = buildLoop();
    const fg = frostGroup(2, 3);
    const pk = pqKeys(2);
    const artifact = hybridThresholdSign(pcactn, {
      frost: { groupPublicKey: fg.groupPublicKey, quorum: fg.quorum, t: 2 },
      pqSigners: [{ keyPair: pk[0]! }, { keyPair: pk[1]! }],
      pqT: 2,
    });
    const rogue = frostGroup(2, 3);
    const rogueAgg = frostCosign(rogue.groupPublicKey, rogue.quorum, thresholdMessage(pcactn), { threshold: 2 });
    // Keep the trusted group_pk label but swap the signature for a rogue-group aggregate.
    const tampered: HybridThresholdArtifact = { ...artifact, frost: { ...artifact.frost, sig: b64u(rogueAgg) } };
    const stepUp = foldHybridStepUp(pcactn, tampered);

    const res = await verifyHybridStepUp(stepUp, {
      grant,
      groupKey: fg.groupPublicKey,
      pqPublicKeys: pk.map((k) => k.publicKey),
      t: 2,
      pqT: 2,
      audience: 'test-aud',
      nowEpoch: NOW,
    });
    expect(res.allow).toBe(false);
    expect(res.core.checks.threshold).toBe('fail');
  });

  it('tier-3: a higher-tier step-up (FROST 3-of-5 + ML-DSA 2-of-3) verifies', async () => {
    const { grant, pcactn } = buildLoop();
    const fg = frostGroup(3, 5);
    const pk = pqKeys(3);
    const artifact = hybridThresholdSign(pcactn, {
      frost: { groupPublicKey: fg.groupPublicKey, quorum: fg.quorum, t: 3 },
      pqSigners: [{ keyPair: pk[0]! }, { keyPair: pk[1]! }],
      pqT: 2,
    });
    const stepUp = foldHybridStepUp(pcactn, artifact);

    const res = await verifyHybridStepUp(stepUp, {
      grant,
      groupKey: fg.groupPublicKey,
      pqPublicKeys: pk.map((k) => k.publicKey),
      t: 3,
      pqT: 2,
      audience: 'test-aud',
      nowEpoch: NOW,
    });
    expect(res.allow).toBe(true);
    expect(res.core.checks.threshold).toBe('pass');
    expect(res.pq.ok).toBe(true);
  });
});
