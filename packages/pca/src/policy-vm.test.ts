import { describe, expect, it } from 'vitest';
import { decide, type DecideInput } from './policy-vm';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY, cost, type TrustBudget } from './risk';
import type { PlanNode } from './merkle';

const P = generateKeyPair();
const A = generateKeyPair();
const NOW = 1_000_000;

function grant(caveats: Record<string, unknown>[] = [{ type: 'expires', at: 9e12 }]) {
  return mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: {
      predicates: [
        { verb: 'revoke_session', resource: '/acct/*', where: [{ field: 'action.params.device', op: 'ne', ref: 'env.current_device' }] },
        { verb: 'delete_account', resource: '/acct/*' },
      ],
      caveats: caveats as never,
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    },
  }).grant;
}

const lowRisk = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };
const act = (over: object = {}) => ({
  action: { verb: 'revoke_session', resource: '/acct/1/s', params: { device: 'laptop' } },
  env: { current_device: 'phone' },
  ...over,
});
const input = (over: Partial<DecideInput> = {}): DecideInput => ({
  grant: grant(),
  action: act(),
  risk: lowRisk,
  budget: fresh,
  now: NOW,
  ...over,
});

describe('policy VM decide', () => {
  it('compliant low-risk action: release, t=1, auto-admit, budget unchanged at r=0', () => {
    const d = decide(input());
    expect(d).toMatchObject({ releaseGuardianShare: true, admit: true, needStepUp: false, r: 0 });
    // act() declares no reversibility_class (undefined) => the optimistic fast-path fails CLOSED
    // (optimisticAllowed: false). The auto-admit (t=1) path is unaffected.
    expect(d.requiredThreshold).toEqual({ t: 1, proof: 'claim', optimisticAllowed: false });
    expect(d.reasons).toEqual([]);
  });
  it('is deterministic', () => {
    expect(decide(input())).toEqual(decide(input()));
  });
  it('auto-admit debits the budget by kappa*r', () => {
    const risk = { ...lowRisk, blastRadius: 1 }; // r = gamma = 0.2 <= theta1
    const d = decide(input({ risk }));
    expect(d.admit).toBe(true);
    expect(d.budget.B).toBeCloseTo(1 - cost(0.2, 1));
  });
  it('out-of-policy action (no predicate matches) -> no release, with reason', () => {
    const d = decide(input({ action: act({ action: { verb: 'transfer_funds', resource: '/acct/1' } }) }));
    expect(d.releaseGuardianShare).toBe(false);
    expect(d.admit).toBe(false);
    expect(d.reasons.join(' ')).toMatch(/no predicate permits transfer_funds/);
    expect(d.budget.B).toBe(1); // not debited
  });
  it('predicate where-condition (spec example) enforced', () => {
    const d = decide(input({ action: act({ env: { current_device: 'laptop' } }) }));
    expect(d.releaseGuardianShare).toBe(false);
  });
  it('envelope caveat violation -> no release', () => {
    const d = decide(input({ grant: grant([{ type: 'expires', at: NOW - 1 }]) }));
    expect(d.releaseGuardianShare).toBe(false);
    expect(d.reasons.join(' ')).toMatch(/expires/);
  });
  it('caveats use derived blast radius, plan reversibility class and supplied context', () => {
    const g = grant([{ type: 'max_blast_radius', max: 0.5 }, { type: 'reversibility_max', class: 'rate_limited' }, { type: 'delegation_depth', max: 1 }]);
    const plan: PlanNode[] = [{ id: 'n1', verb: 'revoke_session', resource: '/acct/1/s', reversibility_class: 'reversible' }];
    const ok = decide(input({ grant: g, plan, risk: { ...lowRisk, blastRadius: 0.4 }, caveatContext: { delegationDepth: 1 } }));
    expect(ok.releaseGuardianShare).toBe(true);
    expect(decide(input({ grant: g, plan, risk: { ...lowRisk, blastRadius: 0.6 }, caveatContext: { delegationDepth: 1 } })).releaseGuardianShare).toBe(false);
    expect(decide(input({ grant: g, plan, risk: { ...lowRisk, blastRadius: 0.4 } })).releaseGuardianShare).toBe(false); // depth unknown
    const irr: PlanNode[] = [{ ...plan[0]!, reversibility_class: 'irreversible' }];
    expect(decide(input({ grant: g, plan: irr, caveatContext: { delegationDepth: 0 } })).releaseGuardianShare).toBe(false);
  });
  it('high blast radius -> t=3 needs human; guardian may still release', () => {
    const d = decide(input({ risk: { ...lowRisk, blastRadius: 1, semanticDistance: 1, reversibility: 0 } }));
    expect(d.r).toBeGreaterThan(DEFAULT_RISK_POLICY.theta2);
    expect(d.releaseGuardianShare).toBe(true);
    expect(d.requiredThreshold).toEqual({ t: 3, proof: 'strong', optimisticAllowed: false });
    expect(d.admit).toBe(false);
    expect(d.needStepUp).toBe(true);
    expect(d.budget.B).toBe(1);
  });
  it('mid risk -> t=2 step-up', () => {
    const d = decide(input({ risk: { ...lowRisk, semanticDistance: 1, blastRadius: 1 } })); // 0.45
    expect(d.requiredThreshold.t).toBe(2);
    expect(d.needStepUp).toBe(true);
  });
  it('depleted budget forces step-up even for low r', () => {
    const d = decide(input({ budget: { B: 0.01, tau: NOW, asOf: NOW }, risk: { ...lowRisk, blastRadius: 1 } }));
    expect(d.releaseGuardianShare).toBe(true);
    expect(d.admit).toBe(false);
    expect(d.needStepUp).toBe(true);
    expect(d.requiredThreshold.t).toBe(3);
    expect(d.reasons.join(' ')).toMatch(/depleted/);
  });
  it('passive leak applied to the budget before admission', () => {
    const d = decide(input({ now: NOW + 1_000_000, budget: { B: 0.4, tau: NOW, asOf: NOW }, risk: { ...lowRisk, blastRadius: 1, age: 0 } }));
    // leak = 1000s * 0.0005 = 0.5 -> B=0 < cost 0.2 -> step-up
    expect(d.needStepUp).toBe(true);
    expect(d.budget.B).toBe(0);
  });
  it('tainted lineage raises r', () => {
    const clean = decide(input());
    const tainted = decide(input({ risk: { ...lowRisk, taint: 1 } }));
    expect(tainted.r).toBeGreaterThan(clean.r);
    expect(tainted.r).toBeCloseTo(DEFAULT_RISK_POLICY.weights.delta);
  });
  it('semantic distance derived from plan geodesic; age derived from budget', () => {
    const plan: PlanNode[] = ['a', 'b', 'c'].map((x) => ({ id: x, verb: 'revoke_session', resource: '/acct/' + x }));
    const { semanticDistance: _s, age: _a, ...rest } = lowRisk;
    void _s; void _a;
    const near = decide(input({ plan, nodeId: 'c', goalNodeId: 'c', risk: rest }));
    const far = decide(input({ plan, nodeId: 'a', goalNodeId: 'c', risk: rest }));
    expect(far.r - near.r).toBeCloseTo(DEFAULT_RISK_POLICY.weights.alpha);
    const stale = decide(input({ plan, nodeId: 'c', goalNodeId: 'c', risk: rest, now: NOW + 3_600_000, budget: { B: 1, tau: NOW, asOf: NOW + 3_600_000 } }));
    expect(stale.r - near.r).toBeCloseTo(DEFAULT_RISK_POLICY.weights.zeta);
  });
  it('missing risk inputs fail closed (worst case) with a reason', () => {
    const d = decide(input({ risk: {} }));
    expect(d.r).toBeGreaterThan(DEFAULT_RISK_POLICY.theta2);
    expect(d.requiredThreshold.t).toBe(3);
    expect(d.reasons.join(' ')).toMatch(/missing/);
  });
  it('irreversible plan node is never optimistic', () => {
    const plan: PlanNode[] = [{ id: 'n', verb: 'revoke_session', resource: '/acct/1/s', reversibility_class: 'irreversible' }];
    const d = decide(input({ plan, risk: { ...lowRisk, semanticDistance: 0 } }));
    expect(d.requiredThreshold.optimisticAllowed).toBe(false);
  });

  describe('optimistic fast-path reversibility fails CLOSED (undefined/unknown => irreversible)', () => {
    // r = 0 (lowRisk) => t=1, so optimisticAllowed is decided purely by the reversibility class.
    const optAllowed = (reversibility_class?: string) =>
      decide(
        input({
          action: act({
            action: {
              verb: 'revoke_session',
              resource: '/acct/1/s',
              params: { device: 'laptop' },
              ...(reversibility_class !== undefined ? { reversibility_class } : {}),
            },
          }),
        }),
      ).requiredThreshold.optimisticAllowed;

    it("explicit 'reversible' => optimistic allowed (unchanged)", () => {
      expect(optAllowed('reversible')).toBe(true);
    });
    it('undefined class => optimistic NOT allowed (fail closed)', () => {
      expect(optAllowed(undefined)).toBe(false);
    });
    it('unrecognized string => optimistic NOT allowed (fail closed)', () => {
      expect(optAllowed('totally-made-up')).toBe(false);
    });
    it("'irreversible' => optimistic NOT allowed (unchanged)", () => {
      expect(optAllowed('irreversible')).toBe(false);
    });
    it("recognized 'rate_limited' / 'costly' stay eligible", () => {
      expect(optAllowed('rate_limited')).toBe(true);
      expect(optAllowed('costly')).toBe(true);
    });
  });
  it('total: junk input never throws and denies with a reason', () => {
    for (const bad of [{}, { grant: null }, { ...input(), grant: { ...grant(), caveats: [] } }, { ...input(), now: NaN }, { ...input(), action: null }]) {
      const d = decide(bad as never);
      expect(d.releaseGuardianShare).toBe(false);
      expect(d.reasons.length).toBeGreaterThan(0);
    }
  });
});
