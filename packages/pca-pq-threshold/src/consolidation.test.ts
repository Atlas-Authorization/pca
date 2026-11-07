import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  type PCActn,
  type PlanNode,
  attenuate,
  b64u,
  buildPCActn,
  encodeKey,
  generateKeyPair,
  mintGrant,
  mlDsa65Keygen,
  thresholdMessage,
} from '@atlasauth/pca';
import { frostTrustedDealerKeygen, signHybridFrostCosign, verifyHybridFrostCosign } from '@atlasauth/pca/ext/frost';
import { type HybridThresholdArtifact, hybridThresholdSign, issueGroupDescriptor, verifyHybridThreshold } from './index';

// Consolidation with the core hybrid-FROST module: the classical half of this package's verifier IS core's `ed25519` suite check,
// and a core-produced aggregate is accepted here. Drift between the two (a change in one that the other does not follow) fails these.

const AUTH = generateKeyPair();

function setup() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const { grant } = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'consolidation',
    envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const c1 = attenuate(grant, [{ type: 'task' }], A.secretKey);
  const nodes: PlanNode[] = [{ id: 'n1', verb: 'wire_transfer', resource: 'ledger', reversibility_class: 'R3' }];
  const pcactn: PCActn = buildPCActn({ aud: 'a', now: Date.now(), grant, chain: [grant, c1], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey, riskClaim: { r: 0.9, inputs: {} } });
  const kg = frostTrustedDealerKeygen(2, 3);
  const desc = issueGroupDescriptor({ authoritySecretKey: AUTH.secretKey, groupPublicKey: kg.groupPublicKey, t: 2, participants: kg.participantShares });
  const pq = [1, 2].map((i) => mlDsa65Keygen(new Uint8Array(32).fill(i)));
  return { pcactn, kg, desc, pq };
}

const verifyOpts = (s: ReturnType<typeof setup>, groupKey: Uint8Array = s.kg.groupPublicKey) => ({
  groupKey, pqPublicKeys: s.pq.map((k) => k.publicKey), t: 2, pqT: 2, groupDescriptor: s.desc, trustedAuthorities: [AUTH.publicKey],
});

describe('pq-threshold is a layer over core frost-pq', () => {
  it('an aggregate produced by core signHybridFrostCosign is accepted as the classical half', () => {
    const s = setup();
    const msg = thresholdMessage(s.pcactn);
    const core = signHybridFrostCosign(s.kg.groupPublicKey, s.kg.participantShares.slice(0, 2), msg, { threshold: 2 });
    const own = hybridThresholdSign(s.pcactn, { frost: { groupPublicKey: s.kg.groupPublicKey, quorum: s.kg.participantShares.slice(0, 2), t: 2 }, pqSigners: s.pq.map((keyPair) => ({ keyPair })) });
    const swapped: HybridThresholdArtifact = { ...own, frost: { ...own.frost, sig: core.sig } };
    expect(verifyHybridThreshold(s.pcactn, swapped, verifyOpts(s)).frost).toBe(true);
  });

  it('this package\'s aggregate is accepted by core verifyHybridFrostCosign on its ed25519 suite', () => {
    const s = setup();
    const own = hybridThresholdSign(s.pcactn, { frost: { groupPublicKey: s.kg.groupPublicKey, quorum: s.kg.participantShares.slice(0, 2), t: 2 }, pqSigners: s.pq.map((keyPair) => ({ keyPair })) });
    expect(verifyHybridFrostCosign({ sig: own.frost.sig }, thresholdMessage(s.pcactn), b64u(s.kg.groupPublicKey), [], { expectGroupAlg: 'ed25519' })).toMatchObject({ ok: true, edOk: true });
  });

  it('both verifiers agree on valid, flipped, truncated, non-canonical and wrong-key aggregates', () => {
    const s = setup();
    const msg = thresholdMessage(s.pcactn);
    const own = hybridThresholdSign(s.pcactn, { frost: { groupPublicKey: s.kg.groupPublicKey, quorum: s.kg.participantShares.slice(0, 2), t: 2 }, pqSigners: s.pq.map((keyPair) => ({ keyPair })) });
    const raw = Buffer.from(own.frost.sig, 'base64url');
    const flip = Buffer.from(raw);
    flip[10] = flip[10]! ^ 1;
    const other = frostTrustedDealerKeygen(2, 3).groupPublicKey;
    const cases: Array<[string, string, Uint8Array, boolean]> = [
      ['valid', own.frost.sig, s.kg.groupPublicKey, true],
      ['flipped', flip.toString('base64url'), s.kg.groupPublicKey, false],
      ['truncated', raw.subarray(0, 63).toString('base64url'), s.kg.groupPublicKey, false],
      ['padded (non-canonical)', raw.toString('base64') + '=', s.kg.groupPublicKey, false],
      ['wrong group key', own.frost.sig, other, false],
    ];
    for (const [name, sig, key, want] of cases) {
      const art: HybridThresholdArtifact = { ...own, frost: { ...own.frost, sig } };
      const here = verifyHybridThreshold(s.pcactn, art, verifyOpts(s, key)).frost;
      const core = verifyHybridFrostCosign({ sig }, msg, b64u(key), [], { expectGroupAlg: 'ed25519' }).ok;
      expect([name, here, core]).toEqual([name, want && key === s.kg.groupPublicKey ? true : false, want && key === s.kg.groupPublicKey ? true : false]);
    }
  });

  it('a non-string aggregate is refused without throwing', () => {
    const s = setup();
    const own = hybridThresholdSign(s.pcactn, { frost: { groupPublicKey: s.kg.groupPublicKey, quorum: s.kg.participantShares.slice(0, 2), t: 2 }, pqSigners: s.pq.map((keyPair) => ({ keyPair })) });
    const bad = { ...own, frost: { ...own.frost, sig: 42 as unknown as string } };
    expect(verifyHybridThreshold(s.pcactn, bad, verifyOpts(s))).toMatchObject({ ok: false, frost: false });
  });
});
