/**
 * Budget forecaster + policy recommender (spec Part 2.3 planning). Given a planned sequence of actions
 * and a compiled policy, forecast how the trust budget drains, WHEN the first human co-sign will be
 * forced, and how many co-signs the whole plan needs — and, inversely, recommend κ/bMax to hit a target
 * level of autonomy. Composes the simulator + the budget algebra. Pure.
 */

import type { CompiledPolicy } from './facade';
import { type SimAction, simulate } from './policy-sim';
import { type RiskPolicy, safetyBound } from './risk';

export interface Forecast {
  steps: Array<{ verb: string; resource: string; outcome: 'auto' | 'step_up' | 'deny'; r: number; budgetAfter: number }>;
  /** Index of the first action forced to a human/guardian step-up (budget or tier), if any. */
  firstStepUpAt?: number;
  /** Total risk of the auto-admitted (machine-only) actions. */
  autonomousRisk: number;
  /** Did the plan drive the budget low enough to force a step-up? */
  forcesCosign: boolean;
  /** Rough number of human co-signs the full plan would need (step-ups that a recharge would clear). */
  cosignsNeeded: number;
  endBudget: number;
}

/** Forecast a plan against a policy. */
export function forecast(policy: CompiledPolicy, plan: SimAction[], opts: { start?: number } = {}): Forecast {
  const rep = simulate(policy, plan, { start: opts.start ?? 0 });
  const steps = rep.results.map((r) => ({ verb: r.action.verb, resource: r.action.resource, outcome: r.outcome, r: r.r, budgetAfter: r.budgetAfter }));
  const firstStepUp = steps.findIndex((s) => s.outcome === 'step_up');
  return {
    steps,
    ...(firstStepUp >= 0 ? { firstStepUpAt: firstStepUp } : {}),
    autonomousRisk: rep.autonomousRisk,
    forcesCosign: rep.stepUp > 0,
    cosignsNeeded: rep.stepUp,
    endBudget: rep.endBudget,
  };
}

export interface Recommendation {
  kappa: number;
  bMax: number;
  /** The resulting autonomous bound (bMax/κ risk units; × κ = dollars in the dollars model). */
  autonomousBound: number;
  rationale: string;
}

/**
 * Recommend κ/bMax so an agent can take `targetActions` autonomous actions of typical risk
 * `perActionRisk` ∈ (0,1] between human co-signs. By the safety theorem Σr ≤ bMax/κ, so we need
 * bMax/κ ≥ targetActions·perActionRisk. With κ fixed (default 1), bMax = targetActions·perActionRisk·κ.
 */
export function recommendPolicy(targetActions: number, perActionRisk: number, opts: { kappa?: number } = {}): Recommendation {
  const kappa = opts.kappa ?? 1;
  const r = Math.max(1e-6, Math.min(1, perActionRisk));
  const n = Math.max(0, targetActions);
  const bMax = n * r * kappa;
  return {
    kappa,
    bMax,
    autonomousBound: bMax / kappa,
    rationale: `Σr ≤ bMax/κ = ${(bMax / kappa).toFixed(3)} ≥ ${n}×${r.toFixed(3)} actions before a human co-sign`,
  };
}

/** The proven autonomous bound of a policy (bMax/κ risk units). */
export function autonomyBoundOf(p: RiskPolicy): number {
  return safetyBound(p);
}
