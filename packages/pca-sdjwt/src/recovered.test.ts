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

describe('verifyRecovered (re-verify recovered claims with PCA Core)', () => {
  it('accepts an untouched proof, including sub-second iat/exp (exact ms are carried)', async () => {
    const s = setup();
    const sd = await issuePcaSdJwt(s.pcActn, { issuerKey: importEd25519PrivateKey(s.principal.secretKey) });
    const r = await verifyRecovered(await verified(sd, s.principal), core(s.grant));
    expect(r.allow).toBe(true);
    expect(r.reason).toBeUndefined();
    expect(r.checks.leaf_signature).toBe('pass');
  });

  it('JWT layer passes but Core denies when a re-signed issuer JWT carries a tampered action', async () => {
    const s = setup();
    const evil = { ...s.pcActn, action: { ...s.pcActn.action, resource: 'session:other' } };
    const sd = await issuePcaSdJwt(evil, { issuerKey: importEd25519PrivateKey(s.principal.secretKey) });
    const r = await verifyRecovered(await verified(sd, s.principal), core(s.grant));
    expect(r.allow).toBe(false);
    expect(r.checks.leaf_signature).toBe('fail');
  });

  it('denies when sig is withheld at presentation', async () => {
    const s = setup();
    const sd = await issuePcaSdJwt(s.pcActn, { issuerKey: importEd25519PrivateKey(s.principal.secretKey) });
    const pres = await present(sd, ['action', 'cap_chain', 'plan', 'grant_ref', 'counter']);
    expect(await verifyRecovered(await verified(pres, s.principal), core(s.grant))).toEqual({
      allow: false, checks: {}, reason: "pca-sdjwt: required claim 'sig' was not disclosed",
    });
  });

  it('denies a wrong audience and a wrong stored grant', async () => {
    const s = setup();
    const sd = await issuePcaSdJwt(s.pcActn, { issuerKey: importEd25519PrivateKey(s.principal.secretKey) });
    const v = await verified(sd, s.principal);
    const a = await verifyRecovered(v, { ...core(s.grant), audience: 'other' });
    expect(a.allow).toBe(false);
    expect(a.checks.audience).toBe('fail');
    const b = await verifyRecovered(v, { ...core(setup().grant) });
    expect(b.allow).toBe(false);
  });

  it('denies when iat_ms/exp_ms are missing or disagree with iat/exp', async () => {
    const s = setup();
    const sd = await issuePcaSdJwt(s.pcActn, { issuerKey: importEd25519PrivateKey(s.principal.secretKey) });
    const v = await verified(sd, s.principal);
    const { iat_ms: _i, ...noIat } = v.claims;
    void _i;
    expect((await verifyRecovered({ ...v, claims: noIat }, core(s.grant))).reason).toBe('pca-sdjwt: iat_ms/exp_ms missing; cannot rebuild the PCActn');
    const skew = { ...v, claims: { ...v.claims, iat_ms: (v.claims.iat_ms as number) + 5000 } };
    expect((await verifyRecovered(skew, core(s.grant))).reason).toBe('pca-sdjwt: iat_ms disagrees with iat');
    const skewE = { ...v, claims: { ...v.claims, exp_ms: (v.claims.exp_ms as number) + 5000 } };
    expect((await verifyRecovered(skewE, core(s.grant))).reason).toBe('pca-sdjwt: exp_ms disagrees with exp');
  });

  it('denies an iss/sub that disagrees with the chain', async () => {
    const s = setup();
    const k = importEd25519PrivateKey(s.principal.secretKey);
    const badIss = await verified(await issuePcaSdJwt(s.pcActn, { issuerKey: k, iss: 'someone-else' }), s.principal);
    expect((await verifyRecovered(badIss, core(s.grant))).reason).toBe('pca-sdjwt: iss does not match the chain root issuer');
    const badSub = await verified(await issuePcaSdJwt(s.pcActn, { issuerKey: k, sub: 'someone-else' }), s.principal);
    expect((await verifyRecovered(badSub, core(s.grant))).reason).toBe('pca-sdjwt: sub does not match the chain leaf holder');
  });
});
