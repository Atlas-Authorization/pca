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
  mlDsa65Sign,
  thresholdMessage,
} from '@atlasauth/pca';
import { PQ_QUORUM_VERSION, frostTrustedDealerKeygen, normalizePqQuorumPool, pqQuorumRepresentative, signPqQuorum, verifyPqQuorum } from '@atlasauth/pca/ext/frost';
import { type HybridThresholdArtifact, HYBRID_ARTIFACT_VERSION, hybridThresholdSign, issueGroupDescriptor, verifyHybridThreshold } from './index';

// Artifact format version 2 (0.5): one quorum implementation in core, an explicit strict version, domain-separated co-signatures.
// The pre-0.5 (version 1) artifact is rebuilt here exactly as the old code produced it: no version on the pq block, co-signatures over the
// bare threshold message.

const AUTH = generateKeyPair();
function setup() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const { grant } = mintGrant({
    principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal: 'pq-quorum-v2',
    envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const c1 = attenuate(grant, [{ type: 'task' }], A.secretKey);
  const nodes: PlanNode[] = [{ id: 'n1', verb: 'wire_transfer', resource: 'ledger', reversibility_class: 'R3' }];
  const pcactn: PCActn = buildPCActn({ aud: 'a', now: Date.now(), grant, chain: [grant, c1], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey, riskClaim: { r: 0.9, inputs: {} } });
  const kg = frostTrustedDealerKeygen(2, 3);
  const desc = issueGroupDescriptor({ authoritySecretKey: AUTH.secretKey, groupPublicKey: kg.groupPublicKey, t: 2, participants: kg.participantShares });
  const pq = [1, 2, 3].map((i) => mlDsa65Keygen(new Uint8Array(32).fill(i)));
  const art = hybridThresholdSign(pcactn, { frost: { groupPublicKey: kg.groupPublicKey, quorum: kg.participantShares.slice(0, 2), t: 2 }, pqSigners: pq.slice(0, 2).map((keyPair) => ({ keyPair })) });
  const opts = { groupKey: kg.groupPublicKey, pqPublicKeys: pq.map((k) => k.publicKey), t: 2, pqT: 2, groupDescriptor: desc, trustedAuthorities: [AUTH.publicKey] };
  return { pcactn, pq, art, opts };
}
const mut = (a: HybridThresholdArtifact, f: (x: Record<string, any>) => void): HybridThresholdArtifact => {
  const c = JSON.parse(JSON.stringify(a));
  f(c);
  return c;
};

describe('artifact format version 2', () => {
  it('a version 2 artifact is accepted and carries the version on the artifact and the pq block', () => {
    const s = setup();
    expect(s.art.v).toBe(HYBRID_ARTIFACT_VERSION);
    expect(s.art.v).toBe(2);
    expect(s.art.pq.v).toBe(PQ_QUORUM_VERSION);
    expect(verifyHybridThreshold(s.pcactn, s.art, s.opts)).toMatchObject({ ok: true, frost: true, pq: { ok: true, count: 2, need: 2 } });
  });

  it('a version 1 artifact (no pq version, bare-message co-signatures) is refused with the version 1 reason', () => {
    const s = setup();
    const msg = thresholdMessage(s.pcactn);
    const v1 = mut(s.art, (a) => {
      a.v = 1;
      delete a.pq.v;
      a.pq.signers = s.pq.slice(0, 2).map((k) => ({ pk: b64u(k.publicKey), sig: b64u(mlDsa65Sign(k.secretKey, msg)) }));
    });
    const r = verifyHybridThreshold(s.pcactn, v1, s.opts);
    expect(r).toMatchObject({ ok: false, frost: false, reason: 'artifact version 1 is no longer accepted (pre-0.5 format)' });
    expect(r.pq).toEqual({ ok: false, count: 0, need: 2, reason: 'artifact version 1 is no longer accepted (pre-0.5 format)' });
  });

  it('an artifact without a version, or with an unknown one, is refused', () => {
    const s = setup();
    expect(verifyHybridThreshold(s.pcactn, mut(s.art, (a) => { delete a.v; }), s.opts).reason).toBe('artifact version missing (pre-0.5 format is refused)');
    for (const v of [0, 3, '2', null, 2.5]) {
      expect(verifyHybridThreshold(s.pcactn, mut(s.art, (a) => { a.v = v; }), s.opts)).toMatchObject({ ok: false, reason: 'unsupported artifact version' });
    }
    expect(verifyHybridThreshold(s.pcactn, null as never, s.opts)).toMatchObject({ ok: false, reason: 'artifact version missing (pre-0.5 format is refused)' });
  });

  it('relabelling a version 1 artifact as version 2 fails: its bare-message co-signatures do not verify over the domain-separated representative', () => {
    const s = setup();
    const msg = thresholdMessage(s.pcactn);
    const relabelled = mut(s.art, (a) => {
      a.pq.signers = s.pq.slice(0, 2).map((k) => ({ pk: b64u(k.publicKey), sig: b64u(mlDsa65Sign(k.secretKey, msg)) }));
    });
    const r = verifyHybridThreshold(s.pcactn, relabelled, s.opts);
    expect(r.ok).toBe(false);
    expect(r.frost).toBe(true);
    expect(r.pq).toEqual({ ok: false, count: 0, need: 2, reason: 'post-quantum quorum short: 0 of 2 required ML-DSA co-signatures' });
  });

  it('the pq block version is checked on its own: missing, 1 and unknown are refused with their reasons', () => {
    const s = setup();
    const msg = thresholdMessage(s.pcactn);
    const pool = normalizePqQuorumPool(s.pq.map((k) => k.publicKey));
    const block = signPqQuorum(msg, s.pq.slice(0, 2));
    expect(verifyPqQuorum(block, msg, pool, 2)).toEqual({ ok: true, count: 2, need: 2 });
    const without = { ...block } as Record<string, unknown>;
    delete without.v;
    expect(verifyPqQuorum(without, msg, pool, 2).reason).toBe('pq quorum version missing (pre-0.5 format is refused)');
    expect(verifyPqQuorum({ ...block, v: 1 }, msg, pool, 2).reason).toBe('pq quorum version 1 is no longer accepted (pre-0.5 format)');
    expect(verifyPqQuorum({ ...block, v: 3 }, msg, pool, 2).reason).toBe('unsupported pq quorum version');
  });

  it('under-threshold, duplicate and wrong-set quorums are refused with exact counts', () => {
    const s = setup();
    const msg = thresholdMessage(s.pcactn);
    const pool = normalizePqQuorumPool(s.pq.slice(0, 2).map((k) => k.publicKey));
    const short = (n: number) => ({ ok: false, count: n, need: 2, reason: `post-quantum quorum short: ${n} of 2 required ML-DSA co-signatures` });
    expect(verifyPqQuorum(signPqQuorum(msg, s.pq.slice(0, 1)), msg, pool, 2)).toEqual(short(1));
    expect(verifyPqQuorum(signPqQuorum(msg, [s.pq[0]!, s.pq[0]!]), msg, pool, 2)).toEqual(short(1));
    // the third key signs correctly but is not in the pinned pool
    expect(verifyPqQuorum(signPqQuorum(msg, [s.pq[0]!, s.pq[2]!]), msg, pool, 2)).toEqual(short(1));
    // a co-signature over another message counts for nothing
    expect(verifyPqQuorum(signPqQuorum(thresholdMessage(setup().pcactn), s.pq.slice(0, 2)), msg, pool, 2)).toEqual(short(0));
  });

  it('the representative is domain-separated: it is not the bare message', () => {
    const msg = new Uint8Array([1, 2, 3]);
    const rep = pqQuorumRepresentative(msg);
    expect(rep.length).toBe(23 + 32);
    expect(Buffer.from(rep.subarray(0, 23)).toString('latin1')).toBe('atlas-pca/pq-quorum/v2\0');
  });
});
