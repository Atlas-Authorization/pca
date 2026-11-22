/**
 * The threshold is bound to the group key by a signed group descriptor from a pinned setup authority.
 * A FROST aggregate is a plain Ed25519 signature, so without this a 1-of-n key can be presented as 3-of-n.
 */
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  type PCActn,
  type PlanNode,
  attenuate,
  b64u,
  buildPCActn,
  canonicalBytes,
  encodeKey,
  generateKeyPair,
  mintGrant,
  mlDsa65Keygen,
  sign,
} from '@atlasauth/pca';
import { frostTrustedDealerKeygen } from '@atlasauth/pca/ext/frost';
import {
  createHybridThresholdVerifier,
  foldHybridStepUp,
  hybridThresholdSign,
  issueGroupDescriptor,
  signerSetCommitment,
  verifyGroupDescriptor,
  verifyHybridStepUp,
  verifyHybridThreshold,
} from './index';

const NOW = Date.now();
const AUTH = generateKeyPair();
const pq = [mlDsa65Keygen(new Uint8Array(32).fill(1)), mlDsa65Keygen(new Uint8Array(32).fill(2))];
const pqPks = pq.map((k) => k.publicKey);

function loop(): { grant: ReturnType<typeof mintGrant>['grant']; pcactn: PCActn } {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const { grant } = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'g',
    envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const c1 = attenuate(grant, [{ type: 'task' }], A.secretKey);
  const nodes: PlanNode[] = [{ id: 'n1', verb: 'wire_transfer', resource: 'ledger', reversibility_class: 'R3' }];
  const pcactn = buildPCActn({ aud: 'aud', now: NOW, grant, chain: [grant, c1], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey, riskClaim: { r: 0.9, inputs: {} } });
  return { grant, pcactn };
}

const { grant, pcactn } = loop();

/** A real dealt group + honest descriptor. */
function dealt(t: number, n: number) {
  const kg = frostTrustedDealerKeygen(t, n);
  const desc = issueGroupDescriptor({ authoritySecretKey: AUTH.secretKey, groupPublicKey: kg.groupPublicKey, t, participants: kg.participantShares });
  return { kg, desc };
}

const base = { pqPublicKeys: pqPks, pqT: 1, trustedAuthorities: [AUTH.publicKey] };
const pqSigners = [{ keyPair: pq[0]! }];

describe('FROST threshold bound to the group key by a signed descriptor', () => {
  it('honest 3-of-5 group: verifies when 3 is required', () => {
    const { kg, desc } = dealt(3, 5);
    const art = hybridThresholdSign(pcactn, { frost: { groupPublicKey: kg.groupPublicKey, quorum: kg.participantShares.slice(0, 3), t: 3 }, pqSigners, pqT: 1 });
    expect(verifyHybridThreshold(pcactn, art, { ...base, groupKey: kg.groupPublicKey, t: 3, groupDescriptor: desc }).ok).toBe(true);
  });

  it('ATTACK: a 1-of-5 group key presented as 3-of-5 is rejected (honest descriptor says 1-of-5)', () => {
    const { kg, desc } = dealt(1, 5);
    // one participant alone produces a valid aggregate under the group key
    const solo = hybridThresholdSign(pcactn, { frost: { groupPublicKey: kg.groupPublicKey, quorum: kg.participantShares.slice(0, 1), t: 1 }, pqSigners, pqT: 1 });
    const relabelled = { ...solo, frost: { ...solo.frost, t: 3 } };
    expect(verifyHybridThreshold(pcactn, solo, { ...base, groupKey: kg.groupPublicKey, t: 1, groupDescriptor: desc }).ok).toBe(true); // control
    const v = verifyHybridThreshold(pcactn, relabelled, { ...base, groupKey: kg.groupPublicKey, t: 3, groupDescriptor: desc });
    expect(v.ok).toBe(false);
    expect(v.frost).toBe(false);
    expect(v.reason).toMatch(/set up as 1-of-5 but 3 is required/);
  });

  it('ATTACK: the attacker forges a descriptor claiming 3-of-5 - untrusted authority, edited t, and the group "signing itself" all fail', () => {
    const { kg, desc } = dealt(1, 5);
    const solo = hybridThresholdSign(pcactn, { frost: { groupPublicKey: kg.groupPublicKey, quorum: kg.participantShares.slice(0, 1), t: 1 }, pqSigners, pqT: 1 });
    const o = { ...base, groupKey: kg.groupPublicKey, t: 3 };
    // (a) own authority key
    const evil = generateKeyPair();
    const selfIssued = issueGroupDescriptor({ authoritySecretKey: evil.secretKey, groupPublicKey: kg.groupPublicKey, t: 3, participants: kg.participantShares });
    expect(verifyHybridThreshold(pcactn, solo, { ...o, groupDescriptor: selfIssued }).reason).toMatch(/authority is not trusted/);
    // (b) edit t in the honest descriptor
    const edited = { ...desc, descriptor: { ...desc.descriptor, t: 3 } };
    expect(verifyHybridThreshold(pcactn, solo, { ...o, groupDescriptor: edited }).reason).toMatch(/signature does not verify/);
    // (c) the group key signs a descriptor for itself: the group key is not an authority
    const selfSigned = issueGroupDescriptor({ authoritySecretKey: kg.participantShares[0]!.share, groupPublicKey: kg.groupPublicKey, t: 3, participants: kg.participantShares });
    expect(verifyHybridThreshold(pcactn, solo, { ...o, groupDescriptor: selfSigned }).ok).toBe(false);
    // (d) swap the authority field to the trusted one but keep the attacker's signature
    expect(verifyHybridThreshold(pcactn, solo, { ...o, groupDescriptor: { ...selfIssued, authority: b64u(AUTH.publicKey) } }).reason).toMatch(/signature does not verify/);
  });

  it('a descriptor for a different group, a missing descriptor and a malformed descriptor are refused', () => {
    const a = dealt(2, 3);
    const b = dealt(2, 3);
    const art = hybridThresholdSign(pcactn, { frost: { groupPublicKey: a.kg.groupPublicKey, quorum: a.kg.participantShares.slice(0, 2), t: 2 }, pqSigners, pqT: 1 });
    const o = { ...base, groupKey: a.kg.groupPublicKey, t: 2 };
    expect(verifyHybridThreshold(pcactn, art, { ...o, groupDescriptor: b.desc }).reason).toMatch(/different group key/);
    for (const bad of [undefined, null, {}, 'x', { descriptor: null, authority: 'a', sig: 's' }, { ...a.desc, descriptor: { ...a.desc.descriptor, t: 0 } }, { ...a.desc, sig: a.desc.sig + '=' }]) {
      const v = verifyHybridThreshold(pcactn, art, { ...o, groupDescriptor: bad as never });
      expect(v.ok).toBe(false);
      expect(v.frost).toBe(false);
    }
    expect(verifyHybridThreshold(pcactn, art, { ...o, groupDescriptor: a.desc, trustedAuthorities: [] }).ok).toBe(false);
  });

  it('the signer set can be pinned; a different membership is refused', () => {
    const a = dealt(2, 3);
    const art = hybridThresholdSign(pcactn, { frost: { groupPublicKey: a.kg.groupPublicKey, quorum: a.kg.participantShares.slice(0, 2), t: 2 }, pqSigners, pqT: 1 });
    const commit = signerSetCommitment(a.kg.participantShares);
    const o = { ...base, groupKey: a.kg.groupPublicKey, t: 2, groupDescriptor: a.desc };
    expect(verifyHybridThreshold(pcactn, art, { ...o, signerSetCommitment: commit }).ok).toBe(true);
    expect(verifyHybridThreshold(pcactn, art, { ...o, signerSetCommitment: signerSetCommitment(dealt(2, 3).kg.participantShares) }).reason).toMatch(/different signer set/);
    // order-insensitive, duplicate ids and bad shares refused
    expect(signerSetCommitment([...a.kg.participantShares].reverse())).toBe(commit);
    expect(() => signerSetCommitment([a.kg.participantShares[0]!, a.kg.participantShares[0]!])).toThrow();
    expect(() => signerSetCommitment([])).toThrow();
    expect(() => signerSetCommitment([{ identifier: 0, publicKey: a.kg.participantShares[0]!.publicKey }])).toThrow();
  });

  it('issuing refuses an impossible group and a bad authority key', () => {
    const { kg } = dealt(2, 3);
    const args = { authoritySecretKey: AUTH.secretKey, groupPublicKey: kg.groupPublicKey, t: 2, participants: kg.participantShares };
    expect(() => issueGroupDescriptor({ ...args, t: 4 })).toThrow(RangeError);
    expect(() => issueGroupDescriptor({ ...args, t: 0 })).toThrow(RangeError);
    expect(() => issueGroupDescriptor({ ...args, authoritySecretKey: new Uint8Array(3) })).toThrow();
    expect(() => issueGroupDescriptor({ ...args, groupPublicKey: 'nope' })).toThrow();
  });

  it('domain separation: a bare signature over the descriptor fields (no domain tag) is not a descriptor', () => {
    const { kg, desc } = dealt(2, 3);
    const d = desc.descriptor;
    const bare = sign(AUTH.secretKey, canonicalBytes({ v: d.v, suite: d.suite, group_pk: d.groupPublicKey, t: d.t, n: d.n, signer_set: d.signerSetCommitment }));
    const r = verifyGroupDescriptor({ ...desc, sig: b64u(bare) }, { trustedAuthorities: [AUTH.publicKey], groupKey: kg.groupPublicKey, t: 2 });
    expect(r.ok).toBe(false);
  });

  it('the folded step-up and the PCActn threshold hook enforce the descriptor too', async () => {
    const { kg, desc } = dealt(1, 3);
    const solo = hybridThresholdSign(pcactn, { frost: { groupPublicKey: kg.groupPublicKey, quorum: kg.participantShares.slice(0, 1), t: 1 }, pqSigners, pqT: 1 });
    const stepUp = foldHybridStepUp(pcactn, solo);
    const vopts = { grant, groupKey: kg.groupPublicKey, pqPublicKeys: pqPks, pqT: 1, trustedAuthorities: [AUTH.publicKey], groupDescriptor: desc, audience: 'aud', nowEpoch: NOW };
    expect((await verifyHybridStepUp(stepUp, { ...vopts, t: 1 })).allow).toBe(true);
    const asThree = await verifyHybridStepUp(stepUp, { ...vopts, t: 3 });
    expect(asThree.allow).toBe(false);
    const hook = createHybridThresholdVerifier({ groupKey: kg.groupPublicKey, pqPublicKeys: pqPks, t: 3, pqT: 1, pqBlock: solo.pq, groupDescriptor: desc, trustedAuthorities: [AUTH.publicKey] });
    expect(hook({ pcactn: stepUp.pcactn } as never)).toMatchObject({ enforced: true, ok: false, reason: expect.stringMatching(/set up as 1-of-3 but 3 is required/) });
  });
});
