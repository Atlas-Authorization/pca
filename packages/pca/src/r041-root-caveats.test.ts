// 0.4.1 SECURITY FIX: caveats placed on the ROOT grant outside the `envelope` caveat were signed but never evaluated.
// They are now enforced exactly like the caveats delegation hops append (attenuation applies from the root).
import { describe, expect, it } from 'vitest';
import { agentNativeCaveatEvaluator, actionSpendUsd, describeEnvelope, envelopePermits } from './agent-native';
import { delegate, mintRoot, type Capability, type Caveat } from './capability';
import { ENVELOPE_CAVEAT, mintGrant } from './envelope';
import { hashCanonical } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { commitPlan, conditionsDigest, type PlanNode } from './merkle';
import { PCACTN_VERSION, signPCActn, type PCActn } from './pcactn';
import { decide, rootCaveats } from './policy-vm';
import { DEFAULT_RISK_POLICY } from './risk';
import { verifyPCActn as verifyPCActn05 } from './server/verify';
const verifyPCActn = (p: Parameters<typeof verifyPCActn05>[0], o: Parameters<typeof verifyPCActn05>[1]): ReturnType<typeof verifyPCActn05> => verifyPCActn05(p, 'require' in o ? o : Object.create(o, { require: { value: [], enumerable: true } })); // report-only: these tests are not about the 0.5 default required checks (see breaking-05.test.ts)


const NOW = Date.UTC(2026, 9, 11, 12, 0, 0);
const AUD = 'rs-r041';
const lowRisk = { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 };
const budget = { B: 1e9, tau: NOW, asOf: NOW };

function world(rootExtra: Caveat[], hopExtra: Caveat[] = []) {
  const principal = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const { grant: g0 } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: pPub,
    goal: 'pay invoices',
    envelope: {
      predicates: [{ verb: 'pay', resource: 'invoice:*' }],
      caveats: [{ type: 'expires', at: NOW + 3_600_000 }],
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    },
  });
  // The principal signs a root that carries the envelope AND caveats outside it (e.g. a hard spend ceiling).
  const grant: Capability = rootExtra.length
    ? mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: pPub, caveats: [...g0.caveats, ...rootExtra] })
    : g0;
  const agent = generateKeyPair();
  const task = delegate(grant, encodeKey(agent.publicKey), hopExtra, principal.secretKey);
  const chain = [grant, task];
  const mk = (params: Record<string, unknown>): { p: PCActn; plan: PlanNode[] } => {
    const plan: PlanNode[] = [{ id: 'n1', verb: 'pay', resource: 'invoice:42', params_digest: hashCanonical(params), reversibility_class: 'reversible' }];
    const c = commitPlan(plan);
    const p = signPCActn(
      {
        ver: PCACTN_VERSION,
        action: { verb: 'pay', resource: 'invoice:42', params_digest: hashCanonical(params), reversibility_class: 'reversible' },
        grant_ref: grant.id,
        cap_chain: chain,
        plan: { root: c.root, inclusion_proof: c.proofFor('n1'), node_id: 'n1', conditions_digest: conditionsDigest(undefined, undefined) },
        attestation: { quote_digest: '', epoch: 0, model_id: 'm', measurement: '', operator: 'o' },
        provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
        freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
        counter: 1,
        risk_claim: { r: 0, inputs: {} },
        aud: AUD,
        iat: NOW,
        exp: NOW + 600_000,
      } as never,
      agent.secretKey,
    );
    return { p, plan };
  };
  const verify = (params: Record<string, unknown>) => {
    const { p, plan } = mk(params);
    return verifyPCActn(p, { insecureSkipPlanRootCheck: true, grant, audience: AUD, now: NOW, context: { params, plan, planAuthorized: true, risk: lowRisk, budget } });
  };
  const dec = (params: Record<string, unknown>) =>
    decide({ grant, chain, action: { action: { verb: 'pay', resource: 'invoice:42', params, reversibility_class: 'reversible' } }, risk: lowRisk, budget, now: NOW });
  return { grant, chain, verify, dec };
}

const MAX = { type: 'max_spend', usd: 100 };

describe('0.4.1 root caveats are enforced (security fix)', () => {
  it('verifyPCActn DENIES an action that exceeds a root max_spend (was allowed: the caveat was never evaluated)', async () => {
    const v = await world([MAX]).verify({ amount: 150, currency: 'usd' });
    expect(v.allow).toBe(false);
    expect(v.checks.policy).toBe('fail');
    expect(v.reasons.join('\n')).toMatch(/root caveat\(s\) not satisfied: max_spend/);
  });

  it('verifyPCActn ALLOWS an action within the root max_spend', async () => {
    const v = await world([MAX]).verify({ amount: 100, currency: 'usd' });
    expect(v.checks.policy).toBe('pass');
    expect(v.allow).toBe(true);
  });

  it('decide() refuses the guardian share above the root ceiling and releases it within', () => {
    const w = world([MAX]);
    const over = w.dec({ amount: 100.01 });
    expect(over.releaseGuardianShare).toBe(false);
    expect(over.reasons).toContain('root caveat(s) not satisfied: max_spend');
    expect(w.dec({ amount: 99.5 }).releaseGuardianShare).toBe(true);
  });

  it('a root caveat type the policy layer does not implement fails closed (like a hop caveat)', async () => {
    const w = world([{ type: 'note', text: 'hello' }]);
    expect((await w.verify({ amount: 1 })).allow).toBe(false);
    expect(w.dec({ amount: 1 }).reasons).toContain('root caveat(s) not satisfied: note');
  });

  it('a second envelope caveat on the root is not a free pass (only the first is read as the envelope)', () => {
    const w = world([{ type: ENVELOPE_CAVEAT, predicates: [{ verb: '*', resource: '*' }] }]);
    expect(w.dec({ amount: 1 }).releaseGuardianShare).toBe(false);
  });

  it('a grant whose only root caveat is the envelope is unaffected', async () => {
    const w = world([]);
    expect(rootCaveats(w.grant)).toEqual([]);
    expect((await w.verify({ amount: 1e9 })).allow).toBe(true);
  });

  it('root and hop caveats both apply: the tighter one wins', async () => {
    const w = world([MAX], [{ type: 'max_spend', usd: 20 }]);
    expect((await w.verify({ amount: 50 })).allow).toBe(false);
    expect((await w.verify({ amount: 20 })).allow).toBe(true);
    const w2 = world([{ type: 'max_spend', usd: 20 }], [MAX]);
    expect((await w2.verify({ amount: 50 })).allow).toBe(false);
  });

  it('rootCaveats drops exactly the first envelope caveat, keeping order', () => {
    const env = { type: ENVELOPE_CAVEAT, x: 1 };
    const g = { caveats: [MAX, env, { type: 'note' }, env] } as unknown as Capability;
    expect(rootCaveats(g)).toEqual([MAX, { type: 'note' }, env]);
  });
});

describe('max_spend caveat semantics', () => {
  const ev = (cv: Record<string, unknown>, params: unknown) =>
    agentNativeCaveatEvaluator(cv as Caveat, { now: NOW, action: { action: { verb: 'pay', resource: 'r', params } } });
  it('within / at / above the ceiling', () => {
    expect(ev(MAX, { amount: 0 })).toBe(true);
    expect(ev(MAX, { amount: 100 })).toBe(true);
    expect(ev(MAX, { amount: 100.000001 })).toBe(false);
  });
  it('fails closed on a missing or malformed amount, limit or currency', () => {
    expect(ev(MAX, {})).toBe(false);
    expect(ev(MAX, undefined)).toBe(false);
    expect(ev(MAX, [])).toBe(false);
    expect(ev(MAX, { amount: '5' })).toBe(false);
    expect(ev(MAX, { amount: -1 })).toBe(false);
    expect(ev(MAX, { amount: 5, currency: 'eur' })).toBe(false);
    expect(ev(MAX, { amount: 5, currency: 'Usd' })).toBe(false);
    expect(ev(MAX, { amount: 5, currency: null })).toBe(false);
    expect(ev(MAX, { amount: 5, currency: 'USD' })).toBe(true);
    expect(ev({ type: 'max_spend' }, { amount: 0 })).toBe(false);
    expect(ev({ type: 'max_spend', usd: -1 }, { amount: 0 })).toBe(false);
    expect(ev({ type: 'max_spend', usd: '100' }, { amount: 0 })).toBe(false);
    expect(ev(MAX, Object.create({ amount: 1 }))).toBe(false); // inherited amount is not the action's
  });
  it('actionSpendUsd reads only own fields', () => {
    expect(actionSpendUsd({ action: { params: { amount: 3 } } })).toBe(3);
    expect(actionSpendUsd({ action: Object.create({ params: { amount: 3 } }) })).toBeUndefined();
    expect(actionSpendUsd(null)).toBeUndefined();
  });
  it('introspection reports the ceiling and the pre-flight honours it', () => {
    const w = world([MAX], [{ type: 'max_spend', usd: 40 }]);
    const env = describeEnvelope(w.chain, NOW);
    expect(env.unsatisfiable).toEqual([]);
    expect(env.remainingBudgetHints.maxSpendUsd).toBe(40);
    expect(envelopePermits(env, 'pay', 'invoice:1', NOW, { amount: 40 })).toBe(true);
    expect(envelopePermits(env, 'pay', 'invoice:1', NOW, { amount: 41 })).toBe(false);
    expect(envelopePermits(env, 'pay', 'invoice:1', NOW)).toBe(true);
  });
});
