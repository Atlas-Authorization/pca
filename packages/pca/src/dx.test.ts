import { describe, expect, it } from 'vitest';
import { delegate } from './capability';
import { mintGrant } from './envelope';
import { hashCanonical } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { EMPTY_PARAMS_DIGEST, commitPlan, paramsDigest, planNodeLeaf, type PlanNode } from './merkle';
import { buildPCActn, verifyPCActnCore } from './pcactn';
import { decide, deriveDecideInput } from './policy-vm';
import { DEFAULT_RISK_POLICY, escalateThreshold, requiredThreshold, type TrustBudget } from './risk';

const P = generateKeyPair();
const A = generateKeyPair();
const S = generateKeyPair();
const NOW = 1_000_000;
const lowRisk = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };

function mk(caveats: Record<string, unknown>[] = [{ type: 'expires', at: 9e12 }]) {
  return mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'g',
    envelope: {
      predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
      caveats: caveats as never,
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    },
  }).grant;
}
const plan: PlanNode[] = [
  { id: 'n1', verb: 'revoke_session', resource: '/acct/1', params_digest: hashCanonical({ d: 'a' }), reversibility_class: 'reversible' },
  { id: 'n2', verb: 'revoke_session', resource: '/acct/2' },
];

describe('buildPCActn', () => {
  it('output verifies; inclusion links to the node', async () => {
    const G = mk();
    const p = buildPCActn({ aud: 'test-aud', grant: G, chain: [G], plan, nodeId: 'n1', params: { d: 'a' }, counter: 1, signerSecret: A.secretKey });
    const v = await verifyPCActnCore(p, { grant: G, audience: 'test-aud' });
    expect(v.allow).toBe(true);
    expect(v.checks.plan_inclusion).toBe('pass');
    expect(v.checks.leaf_signature).toBe('pass');
    expect(p.grant_ref).toBe(G.id);
    expect(p.plan.root).toBe(commitPlan(plan).root);
  });
  it('node without params_digest round-trips (params omitted)', async () => {
    const G = mk();
    const p = buildPCActn({ aud: 'test-aud', grant: G, chain: [G], plan, nodeId: 'n2', counter: 1, signerSecret: A.secretKey });
    expect(p.action.params_digest).toBe(EMPTY_PARAMS_DIGEST);
    expect(planNodeLeaf(plan[1]!).params_digest).toBe(paramsDigest());
    expect((await verifyPCActnCore(p, { grant: G })).checks.plan_inclusion).toBe('pass');
  });
  it('param mismatch throws; unknown node throws; swapped nodeId breaks inclusion', async () => {
    const G = mk();
    const base = { grant: G, chain: [G], plan, counter: 1, signerSecret: A.secretKey };
    expect(() => buildPCActn({ aud: 'test-aud', ...base, nodeId: 'n1', params: { d: 'b' } })).toThrow(/params/);
    expect(() => buildPCActn({ aud: 'test-aud', ...base, nodeId: 'zz' })).toThrow(/unknown plan node/);
    const p = buildPCActn({ aud: 'test-aud', ...base, nodeId: 'n1', params: { d: 'a' } });
    const q = { ...p, plan: { ...p.plan, node_id: 'n2' } };
    expect((await verifyPCActnCore(q, { grant: G })).checks.plan_inclusion).toBe('fail');
    const r = { ...p, action: { ...p.action, params_digest: paramsDigest({ d: 'x' }) } };
    expect((await verifyPCActnCore(r, { grant: G })).checks.plan_inclusion).toBe('fail');
  });
});

describe('coherent threshold/proof', () => {
  it('escalateThreshold keeps proof coherent', () => {
    const t1 = requiredThreshold(0, DEFAULT_RISK_POLICY);
    expect(escalateThreshold(t1, 3)).toEqual({ t: 3, proof: 'strong', optimisticAllowed: false });
    expect(escalateThreshold(t1, 2)).toEqual({ t: 2, proof: 'standard', optimisticAllowed: false });
    expect(escalateThreshold(t1, 1)).toEqual(t1);
    const strong = requiredThreshold(1, DEFAULT_RISK_POLICY);
    expect(escalateThreshold(strong, 2)).toEqual(strong);
  });
  it('depleted budget returns {3,strong,false}, never {3,claim}', () => {
    const d = decide({ grant: mk(), action: { action: { verb: 'revoke_session', resource: '/acct/1' } }, risk: { ...lowRisk, blastRadius: 1 }, budget: { B: 0, tau: NOW, asOf: NOW }, now: NOW });
    expect(d.requiredThreshold).toEqual({ t: 3, proof: 'strong', optimisticAllowed: false });
  });
});

describe('decide with chain', () => {
  const G = mk([{ type: 'expires', at: 9e12 }, { type: 'delegation_depth', max: 1 }]);
  const act = { action: { verb: 'revoke_session', resource: '/acct/1' } };
  const base = { grant: G, action: act, risk: lowRisk, budget: fresh, now: NOW };
  it('no chain: backward compatible (depth unknown fails delegation_depth caveat)', () => {
    expect(decide(base).releaseGuardianShare).toBe(false);
  });
  it('valid chain within depth releases', () => {
    const c1 = delegate(G, encodeKey(S.publicKey), [{ type: 'expires', at: 9e12 }], A.secretKey);
    expect(decide({ ...base, chain: [G, c1] }).releaseGuardianShare).toBe(true);
  });
  it('violated delegated caveat denies with reason', () => {
    const c1 = delegate(G, encodeKey(S.publicKey), [{ type: 'expires', at: NOW - 1 }], A.secretKey);
    const d = decide({ ...base, chain: [G, c1] });
    expect(d.releaseGuardianShare).toBe(false);
    expect(d.reasons.join(' ')).toMatch(/delegated caveat.*expires/);
  });
  it('exceeding delegation depth denies; chain depth overrides caveatContext', () => {
    const c1 = delegate(G, encodeKey(S.publicKey), [], A.secretKey);
    const c2 = delegate(c1, encodeKey(generateKeyPair().publicKey), [], S.secretKey);
    const d = decide({ ...base, chain: [G, c1, c2], caveatContext: { delegationDepth: 0 } });
    expect(d.releaseGuardianShare).toBe(false);
    expect(d.reasons.join(' ')).toMatch(/delegation_depth/);
  });
  it('delegated delegation_depth caveat is enforced', () => {
    const c1 = delegate(G, encodeKey(S.publicKey), [{ type: 'delegation_depth', max: 0 }], A.secretKey);
    expect(decide({ ...base, chain: [G, c1] }).releaseGuardianShare).toBe(false);
  });
  it('empty chain denies', () => {
    expect(decide({ ...base, chain: [] }).releaseGuardianShare).toBe(false);
  });
});

describe('deriveDecideInput', () => {
  it('matches a hand-built input and decide accepts it', () => {
    const G = mk([{ type: 'expires', at: 9e12 }, { type: 'delegation_depth', max: 1 }]);
    const c1 = delegate(G, encodeKey(S.publicKey), [], A.secretKey);
    const p = buildPCActn({ aud: 'test-aud', grant: G, chain: [G, c1], plan, nodeId: 'n1', params: { d: 'a' }, counter: 1, signerSecret: S.secretKey });
    const ctx = { plan, params: { d: 'a' }, risk: lowRisk, budget: fresh, now: NOW };
    const derived = deriveDecideInput(p, ctx);
    const hand = {
      grant: G,
      chain: [G, c1],
      action: { action: { verb: 'revoke_session', resource: '/acct/1', params: { d: 'a' }, reversibility_class: 'reversible' } },
      plan,
      nodeId: 'n1',
      risk: lowRisk,
      budget: fresh,
      now: NOW,
    };
    expect(derived).toMatchObject(hand);
    expect(decide(derived)).toEqual(decide(hand));
    expect(decide(derived).releaseGuardianShare).toBe(true);
  });
});
