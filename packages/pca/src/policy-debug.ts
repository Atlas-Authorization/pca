/**
 * Replayable policy debugger / counterfactual audit (PCA evolution).
 *
 * The decision core (`decide` / `deriveDecideInput` / `verifyPCActnCore`, see policy-vm.ts + pcactn.ts)
 * is PURE and TOTAL: for the same inputs it always yields the same decision. That is exactly what makes a
 * *trustworthy* "why" possible — this module does not log a guess about what happened, it RE-RUNS the pure
 * core and decomposes its arithmetic. Everything here is deterministic and verifier-recomputable.
 *
 * Two surfaces:
 *   - {@link explainDecision}: given a {@link DecideInput} (the same object the verifier's admission path
 *     uses), decompose the decision — the derived risk `r` and its per-term contributions (the six terms of
 *     the Deep-Dive-III risk functional), the required threshold `t`, and the leak/debit budget trajectory.
 *     {@link auditPCActn} adds the verifier's per-check pass/fail table (from `verifyPCActnCore`).
 *   - {@link counterfactual}: re-run the core under hypothetical single changes ("if blastRadius were X",
 *     "if the human just co-signed", "if the budget were B") and report which change FLIPS allow↔deny or
 *     moves the threshold `t`. Because it is a replay of the pure core, every counterfactual is provable,
 *     not speculative.
 */

import type { Capability } from './capability';
import type { CaveatContext } from './predicates';
import { decide, type DecideInput, type PolicyDecision } from './policy-vm';
import { readEnvelope, type Envelope } from './envelope';
import {
  type PCActn,
  type VerifyHooks,
  type VerifyResult,
  verifyPCActnCore,
} from './pcactn';
import {
  ageSinceTouch,
  cost,
  leak,
  planGeodesic,
  recharge,
  rechargeFull,
  safetyBound,
  DEFAULT_RISK_POLICY,
  type RequiredThreshold,
  type RiskInputs,
  type RiskWeights,
  type TrustBudget,
} from './risk';

// The six risk-functional terms, in the fixed order of Deep-Dive-III.
export type RiskTerm = keyof RiskInputs;

/** Worst-case risk inputs — mirrors policy-vm's fail-closed default so this replays `decide` exactly. */
const WORST: RiskInputs = {
  semanticDistance: 1,
  reversibility: 0,
  blastRadius: 1,
  taint: 1,
  confidence: 0,
  age: 1,
};
const ZERO_WEIGHTS: RiskWeights = { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 };

const clamp01 = (x: number) => (x < 0 ? 0 : x > 1 ? 1 : x);
const wt = (x: number) => (Number.isFinite(x) && x > 0 ? x : 0);

function stripUndef(r: Partial<RiskInputs> | undefined): Partial<RiskInputs> {
  const out: Partial<RiskInputs> = {};
  if (!r) return out;
  for (const k of Object.keys(WORST) as RiskTerm[]) {
    if (typeof r[k] === 'number' && Number.isFinite(r[k])) out[k] = r[k];
  }
  return out;
}

/** One term of `r = α·d + β·(1−rev) + γ·bl + δ·taint + ε·(1−conf) + ζ·age`. */
export interface RiskTermContribution {
  term: RiskTerm;
  /** The policy weight (clamped to >= 0, as the risk functional does). */
  weight: number;
  /** The clamped [0,1] input value actually used. */
  input: number;
  /** The value fed into the weighted sum: `input` for risk-increasing terms, `1 − input` for rev/conf. */
  effective: number;
  /** `weight · effective` — this term's additive contribution to the pre-clamp sum. */
  contribution: number;
  /** True for reversibility/confidence, where higher input LOWERS risk. */
  inverted: boolean;
}

export interface RiskExplanation {
  /** The resolved risk inputs after fail-closed fill + plan-geodesic / age derivation (what `decide` used). */
  inputs: RiskInputs;
  weights: RiskWeights;
  terms: RiskTermContribution[];
  /** Σ contributions, BEFORE the final clamp to [0,1]. */
  rawSum: number;
  /** clamp(rawSum, 0, 1) — risk from the functional alone. */
  rScore: number;
  /** The signed `caution` floor applied: `r = max(rScore, rFloor)`. */
  rFloor: number;
  /** Final risk `r = max(rScore, rFloor)` — equals `decide(input).r`. */
  r: number;
}

export interface BudgetTrajectory {
  before: TrustBudget;
  /** Budget after the passive leak up to `now` (what admission is checked against). */
  leaked: TrustBudget;
  /** Budget after the debit (if the action was metered + released), else == leaked. */
  after: TrustBudget;
  /** `c(A) = κ · r` — what a metered action costs. */
  cost: number;
  /** The provable per-checkpoint ceiling Σr ≤ Bmax/κ (Deep-Dive-III safety bound). */
  safetyBound: number;
}

export interface DecisionExplanation {
  /** The full `decide()` output being explained. */
  decision: PolicyDecision;
  risk: RiskExplanation;
  /** The effective threshold the signature must meet (risk threshold escalated by budget state). */
  requiredThreshold: RequiredThreshold;
  t: 1 | 2 | 3;
  /** The autonomous allow signal: the action proceeds with NO human (auto-admit). */
  autoAllow: boolean;
  needStepUp: boolean;
  releaseGuardianShare: boolean;
  budget: BudgetTrajectory;
  reasons: string[];
  /** False when the grant carries no valid envelope (decision was fail-closed denied). */
  envelopeValid: boolean;
}

/**
 * Re-derive the resolved risk inputs EXACTLY as `decide` does (fail-closed fill, plan-geodesic for a missing
 * semantic distance, age-from-budget), so the per-term decomposition reproduces `decide(input).r`.
 */
function resolveRiskInputs(input: DecideInput, env: Envelope): { inputs: RiskInputs; rFloor: number; leaked: TrustBudget } {
  const pol = env.risk_policy;
  const leaked = leak(input.budget, input.now, pol.lambda);
  const inputs: RiskInputs = { ...WORST, ...stripUndef(input.risk) };

  let nodeId = input.nodeId;
  const plan = input.plan;
  if (plan && nodeId === undefined) {
    nodeId = plan.find((n) => n.verb === input.action?.action?.verb && n.resource === input.action?.action?.resource)?.id;
  }
  if (plan && input.risk?.semanticDistance === undefined) {
    const goal = input.goalNodeId ?? plan[plan.length - 1]?.id;
    inputs.semanticDistance = nodeId !== undefined && goal !== undefined ? planGeodesic(plan, nodeId, goal) : 1;
  }
  if (input.risk?.age === undefined) inputs.age = ageSinceTouch(leaked, input.now, input.ageHorizonMs);

  const rFloor = typeof input.rFloor === 'number' && Number.isFinite(input.rFloor) ? Math.min(1, Math.max(0, input.rFloor)) : 0;
  return { inputs, rFloor, leaked };
}

function term(name: RiskTerm, weight: number, raw: number, inverted: boolean): RiskTermContribution {
  const input = clamp01(raw);
  const effective = inverted ? 1 - input : input;
  return { term: name, weight: wt(weight), input, effective, contribution: wt(weight) * effective, inverted };
}

/** Decompose `riskScore(inputs, weights)` into its six additive terms. `rawSum` + clamp reproduce `decide`'s r. */
export function explainRisk(inputs: RiskInputs, weights: RiskWeights, rFloor = 0): RiskExplanation {
  const terms: RiskTermContribution[] = [
    term('semanticDistance', weights.alpha, inputs.semanticDistance, false),
    term('reversibility', weights.beta, inputs.reversibility, true),
    term('blastRadius', weights.gamma, inputs.blastRadius, false),
    term('taint', weights.delta, inputs.taint, false),
    term('confidence', weights.epsilon, inputs.confidence, true),
    term('age', weights.zeta, inputs.age, false),
  ];
  const rawSum = terms.reduce((s, t) => s + t.contribution, 0);
  const rScore = clamp01(rawSum);
  const r = Math.max(rScore, clamp01(rFloor));
  return { inputs, weights, terms, rawSum, rScore, rFloor: clamp01(rFloor), r };
}

/**
 * Explain a single decision: replay `decide(input)` and decompose it — risk `r` and its per-term
 * contributions, the required threshold `t`, and the leak/debit budget trajectory. Pure and deterministic
 * (same input ⇒ byte-identical explanation). Never throws.
 */
export function explainDecision(input: DecideInput): DecisionExplanation {
  const decision = decide(input);
  const env = readEnvelope(input.grant);
  const pol = env?.risk_policy ?? DEFAULT_RISK_POLICY;

  let risk: RiskExplanation;
  let leaked: TrustBudget;
  if (env) {
    const resolved = resolveRiskInputs(input, env);
    leaked = resolved.leaked;
    risk = explainRisk(resolved.inputs, pol.weights, resolved.rFloor);
  } else {
    // Fail-closed denial (no envelope): decide() returned r=1. Keep the shape coherent.
    leaked = input.budget;
    risk = {
      inputs: { ...WORST },
      weights: ZERO_WEIGHTS,
      terms: [],
      rawSum: decision.r,
      rScore: decision.r,
      rFloor: 0,
      r: decision.r,
    };
  }

  return {
    decision,
    risk,
    requiredThreshold: decision.requiredThreshold,
    t: decision.requiredThreshold.t,
    autoAllow: decision.admit,
    needStepUp: decision.needStepUp,
    releaseGuardianShare: decision.releaseGuardianShare,
    budget: {
      before: input.budget,
      leaked,
      after: decision.budget,
      cost: cost(decision.r, pol.kappa),
      safetyBound: safetyBound(pol),
    },
    reasons: decision.reasons,
    envelopeValid: env !== null,
  };
}

// ---- counterfactuals ---------------------------------------------------------------------------

/**
 * A single hypothetical change to a {@link DecideInput}. Each field overlays the corresponding part of the
 * baseline input; `humanCosign` applies a budget recharge (and resets the human-touch time τ, so `age`
 * drops) BEFORE deciding — the "if the human just co-signed" case.
 */
export interface CounterfactualDelta {
  /** Human-readable label for the report (defaults to a derived description). */
  label?: string;
  /** Overlay individual risk inputs, e.g. `{ blastRadius: 0.9 }`. */
  risk?: Partial<RiskInputs>;
  /** Overlay budget fields, e.g. `{ B: 0.9 }`. */
  budget?: Partial<TrustBudget>;
  /** Replace the signed caution floor. */
  rFloor?: number;
  /** Decide at a different time (ms); also affects leak + derived age. */
  now?: number;
  /** Overlay extra caveat context (delegationDepth, reversibilityClass, …). */
  caveatContext?: Partial<Omit<CaveatContext, 'now'>>;
  /** Apply a human co-sign recharge first: `true`/`{full:false}` = +ρ recharge; `{full:true}` = B←Bmax. */
  humanCosign?: boolean | { full?: boolean };
}

function describe(d: CounterfactualDelta): string {
  if (d.label) return d.label;
  const parts: string[] = [];
  if (d.humanCosign) parts.push(typeof d.humanCosign === 'object' && d.humanCosign.full ? 'human re-confirms goal (B←Bmax)' : 'human co-signs (B+ρ)');
  if (d.risk) for (const [k, v] of Object.entries(d.risk)) parts.push(`${k}=${v}`);
  if (d.budget) for (const [k, v] of Object.entries(d.budget)) parts.push(`budget.${k}=${v}`);
  if (d.rFloor !== undefined) parts.push(`caution=${d.rFloor}`);
  if (d.now !== undefined) parts.push(`now=${d.now}`);
  if (d.caveatContext) for (const [k, v] of Object.entries(d.caveatContext)) parts.push(`ctx.${k}=${JSON.stringify(v)}`);
  return parts.length ? parts.join(', ') : 'no-op';
}

/** Produce the hypothetical {@link DecideInput} a delta denotes. Pure — does not mutate `input`. */
export function applyDelta(input: DecideInput, d: CounterfactualDelta): DecideInput {
  const now = d.now ?? input.now;
  let budget: TrustBudget = { ...input.budget, ...(d.budget ?? {}) };
  if (d.humanCosign) {
    const pol = readEnvelope(input.grant)?.risk_policy ?? DEFAULT_RISK_POLICY;
    const full = typeof d.humanCosign === 'object' && d.humanCosign.full === true;
    budget = full ? rechargeFull(budget, pol.bMax, now) : recharge(budget, pol.rho, pol.bMax, now);
  }
  const next: DecideInput = {
    ...input,
    now,
    budget,
    risk: { ...input.risk, ...(d.risk ?? {}) },
    caveatContext: { ...input.caveatContext, ...(d.caveatContext ?? {}) },
  };
  if (d.rFloor !== undefined) next.rFloor = d.rFloor;
  return next;
}

export interface CounterfactualOutcome {
  label: string;
  delta: CounterfactualDelta;
  explanation: DecisionExplanation;
  /** allow (auto-admit) flipped relative to baseline. */
  flipsAllow: boolean;
  /** autoAllow under this delta. */
  allow: boolean;
  /** Threshold movement relative to baseline. */
  thresholdDirection: 'raised' | 'lowered' | 'same';
  changesThreshold: boolean;
  t: 1 | 2 | 3;
  /** Signed change in risk `r` vs baseline (negative = lower risk). */
  rDelta: number;
}

export interface CounterfactualReport {
  baseline: DecisionExplanation;
  outcomes: CounterfactualOutcome[];
  /** Labels of the single changes that FLIP allow↔deny. */
  flipping: string[];
  /** Labels of the single changes that move the threshold `t`. */
  thresholdChanging: string[];
}

/**
 * Replay the decision under each hypothetical single change and report which one flips allow↔deny or moves
 * the required threshold `t`. Deterministic — a pure re-run of the decision core, not a logged guess.
 */
export function counterfactual(input: DecideInput, deltas: CounterfactualDelta[]): CounterfactualReport {
  const baseline = explainDecision(input);
  const outcomes: CounterfactualOutcome[] = deltas.map((d) => {
    const explanation = explainDecision(applyDelta(input, d));
    const direction: CounterfactualOutcome['thresholdDirection'] =
      explanation.t > baseline.t ? 'raised' : explanation.t < baseline.t ? 'lowered' : 'same';
    return {
      label: describe(d),
      delta: d,
      explanation,
      flipsAllow: explanation.autoAllow !== baseline.autoAllow,
      allow: explanation.autoAllow,
      thresholdDirection: direction,
      changesThreshold: direction !== 'same',
      t: explanation.t,
      rDelta: explanation.risk.r - baseline.risk.r,
    };
  });
  return {
    baseline,
    outcomes,
    flipping: outcomes.filter((o) => o.flipsAllow).map((o) => o.label),
    thresholdChanging: outcomes.filter((o) => o.changesThreshold).map((o) => o.label),
  };
}

// ---- full audit (verifier per-check + decision explanation) ------------------------------------

export interface PolicyAudit {
  /** The verifier's per-check pass/fail/not-enforced table (`verifyPCActnCore`). */
  verify: VerifyResult;
  /** The decision decomposition for the SAME action. */
  explanation: DecisionExplanation;
}

/**
 * Full counterfactual audit of a PCActn: the verifier's per-check table (signature, plan inclusion, audience,
 * validity, …) PLUS the admission decision decomposition. `input` should be the DecideInput derived from the
 * same PCActn (see `deriveDecideInput`), so the audit reflects exactly what the admission path saw.
 */
export async function auditPCActn(
  p: PCActn,
  input: DecideInput,
  opts: { grant: Capability; nowEpoch?: number; audience?: string | null; hooks?: VerifyHooks },
): Promise<PolicyAudit> {
  const verify = await verifyPCActnCore(p, opts);
  return { verify, explanation: explainDecision(input) };
}
