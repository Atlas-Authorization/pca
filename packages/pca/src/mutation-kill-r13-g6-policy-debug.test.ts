/**
 * r13 mutation kills for policy-debug.ts: exact risk-term clamping (inputs and weights), the fail-closed input fill, the
 * plan-geodesic semantic distance (goal node, last node, nodes without ids), derived age, the caution floor, the
 * no-envelope explanation shape, counterfactual labels, applyDelta overlays / co-sign recharges, and rDelta.
 */
import { describe, expect, it } from 'vitest';
import { applyDelta, counterfactual, explainDecision, explainRisk } from './policy-debug';
import type { DecideInput } from './policy-vm';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import type { PlanNode } from './merkle';
import { DEFAULT_RISK_POLICY, type RiskInputs, type RiskPolicy, type TrustBudget } from './risk';

const P = generateKeyPair();
const A = generateKeyPair();
const NOW = 1_000_000;
const HOUR = 3_600_000;

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
const GRANT = makeGrant();
const lowRisk: RiskInputs = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const WORST: RiskInputs = { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 };
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };
const input = (over: Partial<DecideInput> = {}): DecideInput => ({
  grant: GRANT,
  action: { action: { verb: 'revoke_session', resource: '/acct/1/s', params: {} } },
  risk: lowRisk,
  budget: fresh,
  now: NOW,
  ...over,
});
const node = (id: string | undefined): PlanNode => ({ ...(id === undefined ? {} : { id }), verb: 'revoke_session', resource: '/acct/1/s' }) as PlanNode;
const sd = (over: Partial<DecideInput>) => explainDecision(input({ risk: { ...lowRisk, semanticDistance: undefined }, ...over })).risk.inputs.semanticDistance;

describe('explainRisk: clamping', () => {
  it('inputs are clamped into [0,1]; an in-range value (even -0) is used as is', () => {
    const e = explainRisk({ ...lowRisk, semanticDistance: -0.5, blastRadius: 2, taint: -0 }, DEFAULT_RISK_POLICY.weights);
    const get = (n: keyof RiskInputs) => e.terms.find((t) => t.term === n)!;
    expect(get('semanticDistance').input).toBe(0);
    expect(get('blastRadius').input).toBe(1);
    expect(Object.is(get('taint').input, -0)).toBe(true); // clamp01 leaves an in-range value untouched
  });
  it('weights must be finite and positive; anything else contributes 0', () => {
    const w = { alpha: -1, beta: Number.POSITIVE_INFINITY, gamma: Number.NaN, delta: -0, epsilon: 0.5, zeta: 0 };
    const e = explainRisk(WORST, w);
    expect(e.terms.map((t) => t.weight)).toStrictEqual([0, 0, 0, 0, 0.5, 0]);
    expect(Object.is(e.terms[3]!.weight, 0)).toBe(true);
    expect(e.rawSum).toBe(0.5);
  });
  it('the six terms are named in the fixed order', () => {
    expect(explainRisk(WORST, DEFAULT_RISK_POLICY.weights).terms.map((t) => t.term)).toStrictEqual([
      'semanticDistance', 'reversibility', 'blastRadius', 'taint', 'confidence', 'age',
    ]);
  });
});

describe('explainDecision: resolved inputs', () => {
  it('non-finite or non-number risk inputs are filled with the worst case', () => {
    const e = explainDecision(input({ risk: { ...lowRisk, blastRadius: '0.5' as never, taint: Number.NaN } }));
    expect(e.risk.inputs.blastRadius).toBe(1);
    expect(e.risk.inputs.taint).toBe(1);
  });
  it('an absent risk object fails closed to the worst inputs (age derived) and never throws', () => {
    const e = explainDecision(input({ risk: undefined as never, plan: [node('n0')], nodeId: 'n0' }));
    expect(e.risk.inputs).toStrictEqual({ ...WORST, semanticDistance: 0, age: 0 });
    expect(e.risk.r).toBe(e.decision.r);
  });
  it('without a plan the semantic distance is the given / worst value', () => {
    expect(sd({})).toBe(1);
    expect(explainDecision(input()).risk.inputs.semanticDistance).toBe(0);
  });
  it('with a plan a GIVEN semantic distance is kept', () => {
    const e = explainDecision(input({ risk: { ...lowRisk, semanticDistance: 0.3 }, plan: [node('n0'), node('n1')], nodeId: 'n1', goalNodeId: 'n0' }));
    expect(e.risk.inputs.semanticDistance).toBe(0.3);
  });
  it('plan geodesic to the goal node, else to the last node', () => {
    const plan = [node('n0'), node('n1'), node('n2')];
    expect(sd({ plan, nodeId: 'n0', goalNodeId: 'n0' })).toBe(0);
    expect(sd({ plan, nodeId: 'n0' })).toBe(1);
    expect(sd({ plan, nodeId: 'n2' })).toBe(0);
    expect(sd({ plan, nodeId: 'n1' })).toBe(0.5);
    expect(sd({ plan: [], nodeId: 'n1' })).toBe(1);
  });
  it('an unknown node or goal id (undefined) is the worst distance, even when a plan node has no id', () => {
    expect(sd({ plan: [node('n0'), node(undefined), node('n2')] })).toBe(1); // no nodeId
    expect(sd({ plan: [node('n0'), node('n1'), node(undefined)], nodeId: 'n1' })).toBe(1); // last node has no id
  });
  it('a given age is kept; an absent one is derived from the budget touch time', () => {
    expect(explainDecision(input({ risk: { ...lowRisk, age: 0.3 } })).risk.inputs.age).toBe(0.3);
    const e = explainDecision(input({ risk: { ...lowRisk, age: undefined }, now: NOW + HOUR / 2 }));
    expect(e.risk.inputs.age).toBe(0.5);
  });
  it('the caution floor: a finite number clamped into [0,1], else 0', () => {
    const f = (rFloor: unknown) => explainDecision(input({ rFloor: rFloor as number })).risk.rFloor;
    expect(f(0.7)).toBe(0.7);
    expect(f(3)).toBe(1);
    expect(f(-2)).toBe(0);
    expect(f(Number.NaN)).toBe(0);
    expect(f('0.5')).toBe(0);
    expect(explainDecision(input({ rFloor: 0.7 })).risk.r).toBe(0.7);
  });
  it('a grant without an envelope explains the fail-closed denial with worst inputs and no terms', () => {
    const e = explainDecision(input({ grant: { ...GRANT, caveats: [] } }));
    expect(e.envelopeValid).toBe(false);
    expect(e.risk).toStrictEqual({ inputs: WORST, weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, terms: [], rawSum: e.decision.r, rScore: e.decision.r, rFloor: 0, r: e.decision.r });
  });
});

describe('counterfactual labels', () => {
  const labels = (deltas: Parameters<typeof counterfactual>[1]) => counterfactual(input(), deltas).outcomes.map((o) => o.label);
  it('every part of a delta is described, in order, comma separated', () => {
    expect(labels([
      { label: 'mine', risk: { blastRadius: 1 } },
      {},
      { humanCosign: true },
      { humanCosign: { full: false } },
      { humanCosign: { full: true } },
      { risk: { blastRadius: 0.9, taint: 0.1 }, budget: { B: 0.5 }, rFloor: 0.2, now: 5, caveatContext: { delegationDepth: 2, reversibilityClass: 'reversible' } },
    ])).toStrictEqual([
      'mine',
      'no-op',
      'human co-signs (B+ρ)',
      'human co-signs (B+ρ)',
      'human re-confirms goal (B←Bmax)',
      'blastRadius=0.9, taint=0.1, budget.B=0.5, caution=0.2, now=5, ctx.delegationDepth=2, ctx.reversibilityClass="reversible"',
    ]);
  });
  it('rDelta is the signed change in r', () => {
    const rep = counterfactual(input({ risk: { ...lowRisk, blastRadius: 0.5 } }), [{ risk: { blastRadius: 0 } }]);
    expect(rep.outcomes[0]!.rDelta).toBeCloseTo(-0.1, 12);
  });
});

describe('applyDelta', () => {
  const low: TrustBudget = { B: 0.2, tau: 0, asOf: 0 };
  it('no co-sign: the budget is only overlaid', () => {
    expect(applyDelta(input({ budget: low }), {}).budget).toStrictEqual(low);
    expect(applyDelta(input({ budget: low }), { budget: { B: 0.5 } }).budget).toStrictEqual({ ...low, B: 0.5 });
  });
  it('co-sign recharges by the ENVELOPE rho; full re-confirmation fills to bMax', () => {
    const g = makeGrant({ ...DEFAULT_RISK_POLICY, rho: 0.3 });
    const b = (humanCosign: boolean | { full?: boolean }) => applyDelta(input({ grant: g, budget: low }), { humanCosign, now: 7 }).budget;
    expect(b(true)).toStrictEqual({ B: 0.5, tau: 7, asOf: 7 });
    expect(b({ full: false })).toStrictEqual({ B: 0.5, tau: 7, asOf: 7 });
    expect(b({})).toStrictEqual({ B: 0.5, tau: 7, asOf: 7 });
    expect(b({ full: true })).toStrictEqual({ B: 1, tau: 7, asOf: 7 });
  });
  it('without an envelope the default policy recharges', () => {
    const r = applyDelta(input({ grant: { ...GRANT, caveats: [] }, budget: low }), { humanCosign: true, now: 7 });
    expect(r.budget).toStrictEqual({ B: 0.2 + DEFAULT_RISK_POLICY.rho, tau: 7, asOf: 7 });
  });
  it('caveat context overlays; rFloor is replaced only when given', () => {
    const base = input({ caveatContext: { reversibilityClass: 'reversible' }, rFloor: 0.4 });
    const n = applyDelta(base, { caveatContext: { delegationDepth: 2 } });
    expect(n.caveatContext).toStrictEqual({ reversibilityClass: 'reversible', delegationDepth: 2 });
    expect(n.rFloor).toBe(0.4);
    expect(applyDelta(base, { rFloor: 0.9 }).rFloor).toBe(0.9);
  });
});
