import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  buildPCActn,
  delegate,
  encodeKey,
  generateKeyPair,
  mintGrant,
  type CapabilityChain,
  type PlanNode,
} from '@atlasauth/pca';
import { importEd25519PrivateKey, importEd25519PublicKey, issuePcaSdJwt, present, verifyPcaSdJwt, verifyRecovered } from './index';

const now = Date.now();
function setup() {
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const pp = encodeKey(principal.publicKey);
  const ap = encodeKey(agent.publicKey);
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pp,
    holder: pp,
    goal: 'g',
    envelope: {
      predicates: [{ verb: 'revoke_session', resource: 'session:*' }],
      caveats: [{ type: 'expires', at: now + 3_600_000 }],
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    },
  });
  const chain: CapabilityChain = [grant, delegate(grant, ap, [{ type: 'expires', at: now + 600_000 }], principal.secretKey)];
  const plan: PlanNode[] = [{ id: 'n1', verb: 'revoke_session', resource: 'session:s2', params_digest: undefined, reversibility_class: 'reversible' }];
  const pcActn = buildPCActn({
    grant, chain, plan, nodeId: 'n1', counter: 1,
    signerSecret: agent.secretKey, aud: 'rs', now, ttlMs: 600_001, nonce: 'n',
  });
  return { principal, grant, pcActn };
}
const core = (grant: ReturnType<typeof setup>['grant']) => ({ grant, audience: 'rs', nowEpoch: now, insecureSkipPlanRootCheck: true });

async function verified(sdjwt: string, principal: ReturnType<typeof setup>['principal']) {
  const r = await verifyPcaSdJwt(sdjwt, { issuerKey: importEd25519PublicKey(principal.publicKey) });
  if (!r.ok) throw new Error(r.reason);
  return r;
}


describe('verifyRecovered reasons', () => {
  const base = async () => {
    const s = setup();
    const sd = await issuePcaSdJwt(s.pcActn, { issuerKey: importEd25519PrivateKey(s.principal.secretKey) });
    return { s, v: await verified(sd, s.principal) };
  };

  it('names the missing exp_ms when only exp_ms is absent', async () => {
    const { s, v } = await base();
    const { exp_ms: _e, ...noExp } = v.claims;
    void _e;
    expect((await verifyRecovered({ ...v, claims: noExp }, core(s.grant))).reason).toBe('pca-sdjwt: iat_ms/exp_ms missing; cannot rebuild the PCActn');
  });

  it('accepts an exp within the same second as iat (exp is floored to iat+1s)', async () => {
    const { s, v } = await base();
    const iat = v.claims.iat_ms as number;
    const res = { ...v, claims: { ...v.claims, exp_ms: iat }, processed: { ...v.processed, exp: Math.floor(iat / 1000) + 1 } };
    expect((await verifyRecovered(res, core(s.grant))).reason).not.toBe('pca-sdjwt: exp_ms disagrees with exp');
    const off = { ...res, processed: { ...res.processed, exp: Math.floor(iat / 1000) - 1 } };
    expect((await verifyRecovered(off, core(s.grant))).reason).toBe('pca-sdjwt: exp_ms disagrees with exp');
  });

  it('denies a non-string aud', async () => {
    const { s, v } = await base();
    const res = { ...v, processed: { ...v.processed, aud: 42 as unknown as string } };
    expect(await verifyRecovered(res, core(s.grant))).toEqual({ allow: false, checks: {}, reason: 'pca-sdjwt: aud must be a string' });
  });

  it('denies an empty or non-array cap_chain with the exact reason', async () => {
    const { s, v } = await base();
    for (const chain of [[], 'x']) {
      const res = { ...v, claims: { ...v.claims, cap_chain: chain } };
      expect(await verifyRecovered(res as typeof v, core(s.grant))).toEqual({ allow: false, checks: {}, reason: 'pca-sdjwt: cap_chain is empty' });
    }
  });

  it('turns a throw inside Core into a deny that carries the error message', async () => {
    const { v } = await base();
    const r = await verifyRecovered(v, null as never);
    expect(r.allow).toBe(false);
    expect(r.checks).toEqual({});
    expect(r.reason).toMatch(/^pca-sdjwt: core verification threw: .+/);
  });
});
