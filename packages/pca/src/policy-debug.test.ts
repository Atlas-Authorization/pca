import { describe, expect, it } from 'vitest';
import {
  applyDelta,
  auditPCActn,
  counterfactual,
  explainDecision,
  explainRisk,
} from './policy-debug';
import { decide, deriveDecideInput, type DecideInput } from './policy-vm';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { buildPCActn } from './pcactn';
import { delegate } from './capability';
import { paramsDigest } from './merkle';
import { DEFAULT_RISK_POLICY, riskScore, type RiskInputs, type RiskPolicy, type TrustBudget } from './risk';
import type { PlanNode } from './merkle';

const P = generateKeyPair();
const A = generateKeyPair();
const NOW = 1_000_000;

function makeGrant(policy: RiskPolicy = DEFAULT_RISK_POLICY) {
  return mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: {
      predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
      caveats: [{ type: 'expires', at: 9e12 }] as never,
      agent_binding: {},
      risk_policy: policy,
    },
  }).grant;
}

const lowRisk: RiskInputs = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };
const act = (over: object = {}) => ({ action: { verb: 'revoke_session', resource: '/acct/1/s', params: {} }, ...over });
const input = (over: Partial<DecideInput> = {}): DecideInput => ({
  grant: makeGrant(),
  action: act(),
  risk: lowRisk,
  budget: fresh,
  now: NOW,
  ...over,
});

describe('explainRisk (per-term decomposition of the risk functional)', () => {
  it('matches a hand-computed r with its six term contributions', () => {
    // r = .25*.4 + .2*(1-.5) + .2*.5 + .2*0 + .1*(1-1) + .05*0 = .1 + .1 + .1 = .3
    const inputs: RiskInputs = { semanticDistance: 0.4, reversibility: 0.5, blastRadius: 0.5, taint: 0, confidence: 1, age: 0 };
    const e = explainRisk(inputs, DEFAULT_RISK_POLICY.weights);
    expect(e.rawSum).toBeCloseTo(0.3, 12);
    expect(e.rScore).toBeCloseTo(0.3, 12);
    expect(e.r).toBeCloseTo(0.3, 12);
    const get = (name: keyof RiskInputs) => e.terms.find((t) => t.term === name)!;
    expect(get('semanticDistance').contribution).toBeCloseTo(0.1, 12);
    expect(get('reversibility').inverted).toBe(true);
    expect(get('reversibility').effective).toBeCloseTo(0.5, 12); // 1 - rev
    expect(get('reversibility').contribution).toBeCloseTo(0.1, 12);
    expect(get('blastRadius').contribution).toBeCloseTo(0.1, 12);
    expect(get('taint').contribution).toBe(0);
    expect(get('confidence').effective).toBe(0); // 1 - conf(1)
  });

  it('all-worst inputs saturate to r=1; inputs are clamped to [0,1]', () => {
    const worst: RiskInputs = { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 };
    const e = explainRisk(worst, DEFAULT_RISK_POLICY.weights);
    expect(e.rawSum).toBeCloseTo(1, 12); // .25+.2+.2+.2+.1+.05
    expect(e.r).toBe(1);
    const over = explainRisk({ ...worst, blastRadius: 5 }, DEFAULT_RISK_POLICY.weights);
    expect(over.terms.find((t) => t.term === 'blastRadius')!.input).toBe(1);
  });

  it('a caution floor can only raise r', () => {
    const e = explainRisk(lowRisk, DEFAULT_RISK_POLICY.weights, 0.42);
    expect(e.rScore).toBe(0);
    expect(e.r).toBe(0.42);
  });
});

describe('explainDecision (replay of the deterministic decision core)', () => {
  it('reproduces decide() exactly and matches a hand-computed t=2 decision', () => {
    const risk: RiskInputs = { semanticDistance: 0.4, reversibility: 0.5, blastRadius: 0.5, taint: 0, confidence: 1, age: 0 };
    const i = input({ risk });
    const e = explainDecision(i);
    const d = decide(i);
    expect(e.decision).toEqual(d);
    // The decomposition reproduces the core's r exactly (same operand order).
    expect(e.risk.r).toBe(d.r);
    expect(e.risk.r).toBe(riskScore(e.risk.inputs, DEFAULT_RISK_POLICY.weights));
    expect(e.risk.r).toBeCloseTo(0.3, 12);
    expect(e.t).toBe(2);
    expect(e.requiredThreshold).toEqual(d.requiredThreshold);
    expect(e.budget.safetyBound).toBe(1); // bMax/κ = 1/1
    expect(e.envelopeValid).toBe(true);
  });

  it('is deterministic — same input yields a byte-identical explanation', () => {
    const i = input({ risk: { ...lowRisk, blastRadius: 0.5, taint: 0.3 } });
    expect(explainDecision(i)).toEqual(explainDecision(i));
  });

  it('reports the budget trajectory (leak + debit) for a metered auto-admit', () => {
    const risk = { ...lowRisk, blastRadius: 1 }; // r = γ = 0.2 ≤ θ1, auto-admit, metered
    const e = explainDecision(input({ risk }));
    expect(e.autoAllow).toBe(true);
    expect(e.budget.cost).toBeCloseTo(0.2, 12);
    expect(e.budget.after.B).toBeCloseTo(0.8, 12); // 1 - κ·r
  });

  it('fail-closed when the grant carries no envelope', () => {
    const e = explainDecision(input({ grant: { id: 'x', issuer: 'i', holder: 'h', caveats: [] } as never }));
    expect(e.envelopeValid).toBe(false);
    expect(e.autoAllow).toBe(false);
    expect(e.risk.r).toBe(1);
  });
});

describe('counterfactual (which single change flips allow↔deny / moves t)', () => {
  const strict: RiskPolicy = { ...DEFAULT_RISK_POLICY, theta1: 0.15 };

  it('a blast-radius increase flips allow→deny and raises t; a small one does not', () => {
    const i = input({ grant: makeGrant(strict), risk: lowRisk });
    const rep = counterfactual(i, [
      { label: 'blast=1', risk: { blastRadius: 1 } }, // r = .2 > θ1 .15 => t=2, deny
      { label: 'blast=0.1', risk: { blastRadius: 0.1 } }, // r = .02 < θ1 => still allow
    ]);
    expect(rep.baseline.autoAllow).toBe(true);
    const flip = rep.outcomes[0]!;
    expect(flip.flipsAllow).toBe(true);
    expect(flip.allow).toBe(false);
    expect(flip.t).toBe(2);
    expect(flip.thresholdDirection).toBe('raised');
    expect(flip.rDelta).toBeCloseTo(0.2, 12);
    const noflip = rep.outcomes[1]!;
    expect(noflip.flipsAllow).toBe(false);
    expect(noflip.thresholdDirection).toBe('same');
    expect(rep.flipping).toEqual(['blast=1']);
    expect(rep.thresholdChanging).toEqual(['blast=1']);
  });

  it('a human co-sign flips a budget-depleted deny back to allow (no threshold change)', () => {
    const pol: RiskPolicy = { ...DEFAULT_RISK_POLICY, theta1: 0.6 }; // keep the action at t=1
    const depleted: TrustBudget = { B: 0.05, tau: NOW, asOf: NOW };
    const i = input({ grant: makeGrant(pol), risk: { ...lowRisk, blastRadius: 0.5 }, budget: depleted });
    const rep = counterfactual(i, [{ label: 'cosign', humanCosign: true }]);
    // baseline: r = γ·0.5 = 0.1 ≤ θ1 (risk-threshold t=1) but B(0.05) < cost(0.1), so admission
    // escalates to a human step-up => effective t=3, not auto-admitted.
    expect(rep.baseline.autoAllow).toBe(false);
    expect(rep.baseline.needStepUp).toBe(true);
    expect(rep.baseline.t).toBe(3);
    const o = rep.outcomes[0]!;
    expect(o.flipsAllow).toBe(true);
    expect(o.allow).toBe(true);
    expect(o.t).toBe(1);
    expect(o.thresholdDirection).toBe('lowered'); // the recharge removes the forced step-up
    expect(rep.flipping).toEqual(['cosign']);
  });

  it('applyDelta is pure (does not mutate the baseline input)', () => {
    const i = input({ risk: lowRisk });
    const before = JSON.stringify(i.risk);
    const next = applyDelta(i, { risk: { blastRadius: 1 } });
    expect(JSON.stringify(i.risk)).toBe(before);
    expect(next.risk.blastRadius).toBe(1);
    expect(i.risk.blastRadius).toBe(0);
  });

  it('a no-op delta neither flips nor changes t', () => {
    const i = input({ grant: makeGrant(strict), risk: lowRisk });
    const rep = counterfactual(i, [{ label: 'noop', risk: { confidence: 1 } }]);
    expect(rep.outcomes[0]!.flipsAllow).toBe(false);
    expect(rep.outcomes[0]!.changesThreshold).toBe(false);
    expect(rep.flipping).toEqual([]);
  });
});

describe('auditPCActn (verifier per-check table + decision explanation)', () => {
  it('passes every M0 check and its explanation matches decide()', async () => {
    const g = makeGrant();
    const S = generateKeyPair();
    const sub = delegate(g, encodeKey(S.publicKey), [], A.secretKey);
    const nodes: PlanNode[] = [
      { id: 'n1', verb: 'revoke_session', resource: '/acct/1/s', params_digest: paramsDigest({}), reversibility_class: 'reversible' },
    ];
    const p = buildPCActn({
      grant: g,
      chain: [g, sub],
      plan: nodes,
      nodeId: 'n1',
      params: {},
      counter: 1,
      signerSecret: S.secretKey,
      aud: 'rs-1',
      now: NOW,
      iat: NOW,
      exp: NOW + 60_000,
    });
    const di = deriveDecideInput(p, { plan: nodes, params: {}, risk: lowRisk, budget: fresh, now: NOW, grant: g });
    const audit = await auditPCActn(p, di, { grant: g, nowEpoch: NOW, audience: 'rs-1' });
    expect(audit.verify.allow).toBe(true);
    expect(audit.verify.checks).toMatchObject({
      wire: 'pass',
      version: 'pass',
      audience: 'pass',
      validity: 'pass',
      cap_chain: 'pass',
      plan_inclusion: 'pass',
      leaf_signature: 'pass',
      counter: 'pass',
    });
    expect(audit.explanation.decision).toEqual(decide(di));
    expect(audit.explanation.autoAllow).toBe(true);
  });

  it('surfaces a tampered action as a verifier per-check failure', async () => {
    const g = makeGrant();
    const S = generateKeyPair();
    const sub = delegate(g, encodeKey(S.publicKey), [], A.secretKey);
    const nodes: PlanNode[] = [
      { id: 'n1', verb: 'revoke_session', resource: '/acct/1/s', params_digest: paramsDigest({}), reversibility_class: 'reversible' },
    ];
    const p = buildPCActn({
      grant: g, chain: [g, sub], plan: nodes, nodeId: 'n1', params: {}, counter: 1,
      signerSecret: S.secretKey, aud: 'rs-1', now: NOW, iat: NOW, exp: NOW + 60_000,
    });
    p.action = { ...p.action, resource: '/acct/ALL' }; // tamper after signing
    const di = deriveDecideInput(p, { plan: nodes, params: {}, risk: lowRisk, budget: fresh, now: NOW, grant: g });
    const audit = await auditPCActn(p, di, { grant: g, nowEpoch: NOW, audience: 'rs-1' });
    expect(audit.verify.allow).toBe(false);
    expect(audit.verify.checks.plan_inclusion).toBe('fail');
    expect(audit.verify.checks.leaf_signature).toBe('fail');
  });
});
