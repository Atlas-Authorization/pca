import { describe, expect, it } from 'vitest';
import { attenuate } from './capability';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { buildPCActn, thresholdMessage } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';
import { verifyPCActn as verifyPCActn05 } from './server/verify';
import { assembleThreshold, createThresholdVerifier, signShare } from './threshold';
const verifyPCActn = (p: Parameters<typeof verifyPCActn05>[0], o: Parameters<typeof verifyPCActn05>[1]): ReturnType<typeof verifyPCActn05> => verifyPCActn05(p, 'require' in o ? o : Object.create(o, { require: { value: [], enumerable: true } })); // report-only: these tests are not about the 0.5 default required checks (see breaking-05.test.ts)


/**
 * F-1 regression (docs/pca/security/proofs/02-threshold-hybrid.md A.3): the required threshold t is decided by
 * the SERVER. An agent-signed `risk_claim.r` must never lower it.
 */
const NOW = Date.now();
function fixture() {
  const P = generateKeyPair(), A = generateKeyPair(), G = generateKeyPair();
  const { grant } = mintGrant({
    principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal: 'g',
    envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  attenuate(grant, [{ type: 'task' }], A.secretKey);
  const nodes = [{ id: 'n1', verb: 'wire', resource: 'bank', reversibility_class: 'irreversible' }];
  const signerSet = [
    { role: 'agent' as const, publicKey: encodeKey(A.publicKey) },
    { role: 'guardian' as const, publicKey: encodeKey(G.publicKey) },
    { role: 'principal' as const, publicKey: encodeKey(P.publicKey) },
  ];
  const mk = (r: number) =>
    buildPCActn({ aud: 'x', now: NOW, grant, chain: [grant], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey, riskClaim: { r, inputs: {} } });
  const worstRisk = { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 };
  const ctx = { risk: worstRisk, budget: { B: 1, tau: NOW } };
  return { P, A, G, grant, signerSet, mk, ctx };
}

describe('F-1: the server, not the agent, decides t', () => {
  it('createThresholdVerifier refuses to be built without an explicit server-side t / requiredT', () => {
    const { signerSet } = fixture();
    expect(() => createThresholdVerifier({ signerSet } as never)).toThrow(/t.*requiredT|requiredT.*t/);
  });

  it('claimed r=0 with server t=3 and a hook pinned to t=3 -> deny (agent alone is 2 short)', async () => {
    const { grant, signerSet, mk, ctx } = fixture();
    const v = await verifyPCActn(mk(0), { insecureSkipPlanRootCheck: true, grant, audience: 'x', now: NOW, hooks: { threshold: createThresholdVerifier({ signerSet, t: 3 }) }, context: ctx });
    expect(v.requiredThreshold.t).toBe(3);
    expect(v.allow).toBe(false);
    expect(v.checks.threshold).toBe('fail');
  });

  it('a hook configured BELOW the server-derived t is rejected even though it reports pass', async () => {
    const { grant, signerSet, mk, ctx } = fixture();
    const v = await verifyPCActn(mk(0), { insecureSkipPlanRootCheck: true, grant, audience: 'x', now: NOW, hooks: { threshold: createThresholdVerifier({ signerSet, t: 1 }) }, context: ctx });
    expect(v.requiredThreshold.t).toBe(3);
    expect(v.allow).toBe(false);
    expect(v.checks.threshold).toBe('fail');
    expect(v.reasons.join('|')).toMatch(/enforced t=1.*server requires t=3|below/);
  });

  it('a custom hook that does not attest the t it enforced is rejected when the server needs t>1', async () => {
    const { grant, mk, ctx } = fixture();
    const v = await verifyPCActn(mk(0), { insecureSkipPlanRootCheck: true, grant, audience: 'x', now: NOW, hooks: { threshold: () => ({ enforced: true, ok: true }) }, context: ctx });
    expect(v.allow).toBe(false);
    expect(v.checks.threshold).toBe('fail');
  });

  it('full quorum at the server t is allowed', async () => {
    const { grant, signerSet, mk, ctx, G, P } = fixture();
    const base = mk(0);
    const msg = thresholdMessage(base);
    const bind = { signerSet, t: 3 };
    const full = { ...base, threshold: assembleThreshold([signShare('guardian', G.secretKey, msg, bind), signShare('principal', P.secretKey, msg, bind)]) };
    const v = await verifyPCActn(full, { insecureSkipPlanRootCheck: true, grant, audience: 'x', now: NOW, hooks: { threshold: createThresholdVerifier({ signerSet, t: 3 }) }, context: ctx });
    expect(v.allow, v.reasons.join('|')).toBe(true);
    expect(v.checks.threshold).toBe('pass');
  });
});
