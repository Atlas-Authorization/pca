/** A hybrid artifact with no FROST part is refused with the typed reason, not the generic throw fallback. */

import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  type PlanNode,
  attenuate,
  buildPCActn,
  encodeKey,
  generateKeyPair,
  mintGrant,
  mlDsa65Keygen,
} from '@atlasauth/pca';
import { frostTrustedDealerKeygen } from '@atlasauth/pca/ext/frost';
import { hybridThresholdSign, issueGroupDescriptor, verifyHybridThreshold } from './index';

describe('verifyHybridThreshold: missing FROST part', () => {
  it('an artifact without a frost member gets the malformed-FROST refusal', () => {
    const P = generateKeyPair();
    const A = generateKeyPair();
    const AUTH = generateKeyPair();
    const { grant } = mintGrant({
      principalSecret: P.secretKey,
      principalPublic: encodeKey(P.publicKey),
      holder: encodeKey(A.publicKey),
      goal: 'g',
      envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
    });
    const c1 = attenuate(grant, [{ type: 'task' }], A.secretKey);
    const nodes: PlanNode[] = [{ id: 'n1', verb: 'wire_transfer', resource: 'ledger', reversibility_class: 'R3' }];
    const pcactn = buildPCActn({ aud: 'aud', now: Date.now(), grant, chain: [grant, c1], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey, riskClaim: { r: 0.9, inputs: {} } });
    const kg = frostTrustedDealerKeygen(2, 3);
    const desc = issueGroupDescriptor({ authoritySecretKey: AUTH.secretKey, groupPublicKey: kg.groupPublicKey, t: 2, participants: kg.participantShares });
    const pq = [mlDsa65Keygen(new Uint8Array(32).fill(1)), mlDsa65Keygen(new Uint8Array(32).fill(2))];
    const art = hybridThresholdSign(pcactn, {
      frost: { groupPublicKey: kg.groupPublicKey, quorum: kg.participantShares.slice(0, 2), t: 2 },
      pqSigners: [{ keyPair: pq[0]! }],
      pqT: 1,
    });
    const { frost: _omit, ...rest } = art;
    const v = verifyHybridThreshold(pcactn, rest as never, {
      groupKey: kg.groupPublicKey,
      t: 2,
      pqT: 1,
      pqPublicKeys: pq.map((k) => k.publicKey),
      trustedAuthorities: [AUTH.publicKey],
      groupDescriptor: desc,
    } as never);
    expect(v.ok).toBe(false);
    expect(v.frost).toBe(false);
    expect(v.reason).toBe('malformed or missing FROST part');
  });
});
