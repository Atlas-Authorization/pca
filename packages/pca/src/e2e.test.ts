import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  PCACTN_VERSION,
  commitPlan,
  conditionsDigest,
  decide,
  delegate,
  encodeKey,
  generateKeyPair,
  hashCanonical,
  merkleRoot,
  mintGrant,
  pcactnDigest,
  readEnvelope,
  recharge,
  signPCActn,
  verifyChain,
  verifyPCActnCore,
  type PCActn,
  type PlanNode,
  type RiskInputs,
  type TrustBudget,
} from './index';

/** The same loop as examples/pca-loop.ts (spec §20.1), asserted. Keep the two in sync. */
describe('PCA end-to-end loop (spec §20.1)', () => {
  it('runs all 8 steps', async () => {
    let now = Date.UTC(2026, 9, 6, 12, 0, 0);
    const policy = { ...DEFAULT_RISK_POLICY, kappa: 2, rho: 0.5, bMax: 1 };

    // 1. principal mints G
    const principal = generateKeyPair();
    const pPub = encodeKey(principal.publicKey);
    const { grant: G } = mintGrant({
      principalSecret: principal.secretKey,
      principalPublic: pPub,
      holder: pPub,
      goal: 'secure my account',
      envelope: {
        predicates: [
          { verb: 'list_sessions', resource: 'session:*' },
          {
            verb: 'revoke_session',
            resource: 'session:*',
            where: [{ field: 'action.params.device', op: 'ne', ref: 'env.current_device' }],
          },
          { verb: 'rotate_recovery_keys', resource: 'account:me' },
        ],
        caveats: [{ type: 'expires', at: now + 3_600_000 }, { type: 'delegation_depth', max: 2 }],
        agent_binding: {},
        risk_policy: policy,
      },
    });
    expect(verifyChain([G], pPub)).toEqual({ ok: true });
    expect(readEnvelope(G)).not.toBeNull();

    // 2. delegate to the agent
    const agent = generateKeyPair();
    const aPub = encodeKey(agent.publicKey);
    const task = delegate(G, aPub, [{ type: 'expires', at: now + 600_000 }], principal.secretKey);
    const chain = [G, task];
    expect(verifyChain(chain, pPub)).toEqual({ ok: true });
    expect(task.holder).toBe(aPub);
    expect(task.caveats.length).toBe(G.caveats.length + 1);

    // 3. plan
    const node = (id: string, verb: string, resource: string, params: object, rev: string): PlanNode => ({
      id, verb, resource, params_digest: hashCanonical(params), reversibility_class: rev,
    });
    const P = { list: {}, r2: { device: 'a' }, r3: { device: 'b' }, r4: { device: 'c' }, rot: { scope: 'all' } };
    const plan: PlanNode[] = [
      node('n1', 'list_sessions', 'session:*', P.list, 'reversible'),
      node('n2', 'revoke_session', 'session:s2', P.r2, 'reversible'),
      node('n3', 'revoke_session', 'session:s3', P.r3, 'reversible'),
      node('n4', 'revoke_session', 'session:s4', P.r4, 'reversible'),
      node('n5', 'rotate_recovery_keys', 'account:me', P.rot, 'irreversible'),
    ];
    const committed = commitPlan(plan);

    let counter = 0;
    const emit = (n: PlanNode, params: object, proofNode = n.id): PCActn =>
      signPCActn(
        {
          ver: PCACTN_VERSION,
          action: {
            verb: n.verb,
            resource: n.resource,
            params_digest: hashCanonical(params),
            reversibility_class: n.reversibility_class ?? 'reversible',
          },
          grant_ref: G.id,
          cap_chain: chain,
          plan: {
            root: committed.root,
            inclusion_proof: committed.proofFor(proofNode),
            node_id: n.id,
            conditions_digest: conditionsDigest(n.pre, n.post),
          },
          attestation: { quote_digest: '', epoch: 0, model_id: 'm', measurement: '', operator: 'o' },
          provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
          freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
          counter: ++counter,
          risk_claim: { r: 0, inputs: {} },
          aud: 'e2e-rs',
          iat: now,
          exp: now + 600_000,
        },
        agent.secretKey,
      );

    let budget: TrustBudget = { B: policy.bMax, tau: now, asOf: now };
    const ask = (n: PlanNode, params: Record<string, unknown>, risk: Partial<RiskInputs>) =>
      decide({
        grant: G,
        action: {
          action: { verb: n.verb, resource: n.resource, params, reversibility_class: n.reversibility_class },
          env: { current_device: 'my-phone' },
        },
        plan, nodeId: n.id, risk, budget, now,
        caveatContext: { delegationDepth: 1 },
      });

    // 4-6. in-plan list_sessions: sign, decide (t=1), verify, anchor
    now += 1000;
    const pc1 = emit(plan[0]!, P.list);
    const d1 = ask(plan[0]!, P.list, { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1 });
    expect(d1.releaseGuardianShare).toBe(true);
    expect(d1.requiredThreshold.t).toBe(1);
    expect(d1.r).toBeLessThanOrEqual(policy.theta1);
    const v1 = await verifyPCActnCore(pc1, { grant: G, audience: 'e2e-rs', nowEpoch: now });
    expect(v1.allow).toBe(true);
    for (const k of ['cap_chain', 'plan_inclusion', 'leaf_signature', 'counter'])
      expect(v1.checks[k]).toBe('pass');
    expect(v1.checks.plan_root_authorized).toBe('not-enforced');
    expect(v1.checks.threshold).toBe('not-enforced');
    const ledger = [pcactnDigest(pc1)];
    expect(merkleRoot(ledger)).toEqual(expect.any(String));
    budget = d1.budget;

    // 7. out-of-plan: delete_account replaying n1's proof
    now += 1000;
    const rogueNode: PlanNode = {
      id: 'n1', verb: 'delete_account', resource: 'account:me',
      params_digest: hashCanonical({}), reversibility_class: 'irreversible',
    };
    const rogue = emit(rogueNode, {}, 'n1');
    const vr = await verifyPCActnCore(rogue, { grant: G, audience: 'e2e-rs', nowEpoch: now });
    expect(vr.allow).toBe(false);
    expect(vr.checks.plan_inclusion).toBe('fail');
    expect(vr.reason).toMatch(/plan_inclusion/);
    const dr = ask(rogueNode, {}, { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 0, confidence: 0.5 });
    expect(dr.releaseGuardianShare).toBe(false); // no predicate permits it either

    // 8. budget drain: routine revokes strictly decrease B until depletion forces step-up
    const routine = { semanticDistance: 0.2, reversibility: 0.7, blastRadius: 0.5, taint: 0, confidence: 0.9 };
    const seen: number[] = [budget.B];
    for (const [i, p] of [[1, P.r2], [2, P.r3]] as const) {
      now += 1000;
      const d = ask(plan[i]!, p, routine);
      expect(d.admit).toBe(true);
      expect(d.requiredThreshold.t).toBe(1);
      expect((await verifyPCActnCore(emit(plan[i]!, p), { grant: G, audience: 'e2e-rs', nowEpoch: now })).allow).toBe(true);
      expect(d.budget.B).toBeLessThan(budget.B);
      budget = d.budget;
      seen.push(budget.B);
    }
    expect(seen).toEqual([...seen].sort((a, b) => b - a));

    now += 1000;
    const flat = ask(plan[3]!, P.r4, routine);
    expect(flat.admit).toBe(false);
    expect(flat.needStepUp).toBe(true);
    expect(flat.requiredThreshold.t).toBe(3); // same low r, but depletion forces a human
    expect(flat.budget.B).toBeCloseTo(budget.B, 2); // not debited (only the tiny passive leak)

    // human recharge restores auto-admission
    now += 30_000;
    budget = recharge(budget, policy.rho, policy.bMax, now);
    const again = ask(plan[3]!, P.r4, routine);
    expect(again.admit).toBe(true);
    budget = again.budget;

    // high-risk, in-policy, in-plan, irreversible => t=3
    now += 1000;
    const high = ask(plan[4]!, P.rot, { semanticDistance: 0.8, reversibility: 0, blastRadius: 1, taint: 0.2, confidence: 0.7 });
    expect(high.releaseGuardianShare).toBe(true);
    expect(high.requiredThreshold.t).toBe(3);
    expect(high.admit).toBe(false);
    expect(high.needStepUp).toBe(true);
    expect(high.budget.B).toBeCloseTo(budget.B, 2);
  });
});
