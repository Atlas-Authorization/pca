import type { ModelSignal } from './decision';
import type { ObjectiveRiskResolution } from './objective-binding';
import type { SemanticThresholdResult } from './semantic-threshold';
import type { RiskInputs } from './risk';

/**
 * Tighten-or-escalate typing of the intent-frontier modules (semantic judge threshold, objective risk, proof of progress).
 *
 * What these modules compute are PROXIES for "does this action serve the principal's goal": a judge ensemble's score, an
 * embedding distance, a potential function. None of them is a judgement that may grant anything. This file is the one place
 * that turns each result into a {@link ModelSignal} (`ok | escalate | deny`), the value a `tighten[]` rule or a verifier
 * gate may act on. A signal can only LOWER a decision (`tighten(d, s) <= d`, G-T9); `ok` is the neutral element, never a
 * grant. Every function is total: a missing, malformed or unrecognised result is `deny`, never `ok`.
 */

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** `ok` iff the ensemble met its quorum and the calibrated gate; a clean "not faithful" is `escalate` (ask a human); garbage is `deny`. */
export function semanticSignal(result: SemanticThresholdResult | undefined | null): ModelSignal {
  if (!isObj(result) || typeof result.ok !== 'boolean') return 'deny';
  return result.ok ? 'ok' : 'escalate';
}

/** Progress-step denial codes that mean "not enough progress, a human may decide" rather than a forged or malformed proof. */
const PROGRESS_ESCALATE = new Set(['exploration-exhausted', 'budget-exceeded']);

/** `ok` iff the step verified; running out of exploration budget escalates; every other denial (forgery, gap, mismatch, malformed) denies. */
export function progressSignal(result: { ok: boolean; reason?: string } | undefined | null): ModelSignal {
  if (!isObj(result) || typeof result.ok !== 'boolean') return 'deny';
  if (result.ok) return 'ok';
  return typeof result.reason === 'string' && PROGRESS_ESCALATE.has(result.reason) ? 'escalate' : 'deny';
}

/**
 * Objective risk: nothing committed is neutral (`ok`); a committed fact that cannot be reproduced is `deny` (the grant's own
 * `on_mismatch: 'heuristic'` falls back to the class heuristic, which is the pre-existing, server-held baseline: `ok`).
 * A reproduced result adds no signal of its own: it enters the decision only through {@link tightenRiskInputs}.
 */
export function objectiveSignal(res: ObjectiveRiskResolution | undefined | null): ModelSignal {
  if (!isObj(res)) return 'deny';
  if (res.mode === 'none' || res.mode === 'objective') return 'ok';
  if (res.mode === 'mismatch') return res.onMismatch === 'heuristic' ? 'ok' : 'deny';
  return 'deny';
}

type Baseline = Pick<RiskInputs, 'reversibility' | 'blastRadius'>;
type Objective = Pick<RiskInputs, 'reversibility' | 'blastRadius' | 'semanticDistance'>;

/**
 * Combine the server-held baseline risk inputs with the objective ones so that the objective path can only RAISE risk:
 * reversibility is the lower of the two, blast radius the higher, and a non-finite value on either side is the worst case.
 * `semanticDistance` is passed through for the caller to fold with the plan geodesic (`max`); it is not a baseline input.
 */
export function tightenRiskInputs(baseline: Baseline, objective: Objective): Objective {
  const fin = (x: unknown): x is number => typeof x === 'number' && Number.isFinite(x);
  // any non-finite risk input (on either side, in either field) makes the whole result the worst case
  const ok = fin(baseline.reversibility) && fin(objective.reversibility) && fin(baseline.blastRadius) && fin(objective.blastRadius);
  const rev = ok ? Math.min(baseline.reversibility, objective.reversibility) : 0;
  const blast = ok ? Math.max(baseline.blastRadius, objective.blastRadius) : 1;
  return { reversibility: rev, blastRadius: blast, semanticDistance: fin(objective.semanticDistance) ? objective.semanticDistance : 1 };
}
