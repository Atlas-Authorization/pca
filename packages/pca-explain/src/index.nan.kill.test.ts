import { describe, expect, it } from 'vitest';
import { type Envelope, type PlanNode, DEFAULT_RISK_POLICY, b64u, buildPCActn, generateKeyPair, mintGrant, paramsDigest, verifyPCActnCore } from '@atlasauth/pca';
import { explainVerification } from './index';

const AUD = 'ins_test';
const NOW = 1_000_000;

describe('a non-finite explain clock never reads the validity window as fine', () => {
  // pre-fix: `iat > now + skew` and `now > exp` were false for NaN, so the pinpoint fell through to "validity window invalid"
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('now of %s', async (bad) => {
    const principal = generateKeyPair();
    const holder = generateKeyPair();
    const env: Omit<Envelope, 'goal_commit'> = {
      predicates: [{ verb: 'stripe.refund', resource: 'charge:*', where: [{ field: 'action.params.amount', op: 'lte', value: 500 }] }],
      caveats: [{ type: 'expires', at: NOW + 60_000 }, { type: 'max_blast_radius', max: 0.5 }],
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    };
    const { grant } = mintGrant({ principalSecret: principal.secretKey, principalPublic: b64u(principal.publicKey), holder: b64u(holder.publicKey), goal: 'reconcile refunds for October', envelope: env });
    const params = { amount: 100 };
    const plan: PlanNode[] = [{ id: 'n0', verb: 'stripe.refund', resource: 'charge:ch_1', reversibility_class: 'reversible', params_digest: paramsDigest(params) }];
    const p = buildPCActn({ grant, chain: [grant], plan, nodeId: 'n0', params, counter: 1, signerSecret: holder.secretKey, aud: AUD, now: NOW, riskClaim: { r: 0.1, inputs: {} } });
    const later = NOW + 60 * 60_000;
    const vr = await verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant, nowEpoch: later, audience: AUD });
    expect(vr.allow).toBe(false);
    const ex = explainVerification(p, vr, { now: bad });
    expect(ex.decisive?.name).toBe('validity');
    expect(ex.decisive?.detail).toMatch(/future|expired/);
  });
});
