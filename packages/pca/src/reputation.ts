/**
 * Accountability network — reputation + insurance pricing (spec Part 2.5 "the moat").
 *
 * The bond / dispute / witness substrate produces a stream of outcomes; this turns it into agent/model
 * REPUTATION and prices RISK on top of it — the watchtower-marketplace + underwriter layer, with no
 * blockchain (the Merkle log + witnesses are the substrate). Pure + offline data transforms.
 *
 * HONEST: reputation here is a transparent, explainable function of observed behaviour (deny rate,
 * step-up rate, slashes) — not an opaque oracle. It is advisory input to pricing/admission, never an
 * authorization by itself.
 */

import type { ActivityEvent } from './console';

export interface DisputeRecord {
  subject: string;
  /** The bond was slashed (the action was successfully challenged). */
  slashed: boolean;
  at: number;
  /** Optional amount at stake (for exposure-weighted reputation). */
  amount?: number;
}

export interface ReputationInput {
  subject: string;
  events?: ActivityEvent[];
  disputes?: DisputeRecord[];
}

export interface Reputation {
  subject: string;
  actions: number;
  autos: number;
  stepUps: number;
  denies: number;
  slashes: number;
  disputes: number;
  /** Explainable score in [0,1]: 1 = spotless, 0 = severely untrustworthy. */
  score: number;
  factors: string[];
}

const clamp01 = (x: number) => Math.max(0, Math.min(1, x));

/**
 * Compute reputation. Starts at 1 and subtracts explainable penalties: the policy-violation (deny)
 * rate, a milder step-up rate, and — dominant — slashed disputes (a successfully challenged action is
 * the strongest negative signal). A subject with no history scores a neutral 0.5 (unproven).
 */
export function reputation(input: ReputationInput): Reputation {
  const events = input.events ?? [];
  const disputes = input.disputes ?? [];
  const actions = events.length;
  const autos = events.filter((e) => e.outcome === 'auto').length;
  const stepUps = events.filter((e) => e.outcome === 'step_up').length;
  const denies = events.filter((e) => e.outcome === 'deny').length;
  const slashes = disputes.filter((d) => d.slashed).length;

  const factors: string[] = [];
  if (actions === 0 && disputes.length === 0) {
    return { subject: input.subject, actions, autos, stepUps, denies, slashes, disputes: disputes.length, score: 0.5, factors: ['unproven (no history)'] };
  }

  let score = 1;
  if (actions > 0) {
    const denyRate = denies / actions;
    const stepUpRate = stepUps / actions;
    if (denyRate > 0) {
      score -= 0.6 * denyRate;
      factors.push(`deny rate ${(denyRate * 100).toFixed(0)}%`);
    }
    if (stepUpRate > 0) {
      score -= 0.15 * stepUpRate;
      factors.push(`step-up rate ${(stepUpRate * 100).toFixed(0)}%`);
    }
  }
  // Slashes dominate: each slash is a heavy, saturating penalty.
  if (slashes > 0) {
    const pen = Math.min(0.8, 0.3 * slashes);
    score -= pen;
    factors.push(`${slashes} slashed dispute${slashes > 1 ? 's' : ''}`);
  }
  if (factors.length === 0) factors.push('clean history');
  return { subject: input.subject, actions, autos, stepUps, denies, slashes, disputes: disputes.length, score: clamp01(score), factors };
}

// ---- underwriting ---------------------------------------------------------------------------------

export interface PricingOptions {
  /** Premium per unit exposure at perfect reputation. Default 0.01 (1%). */
  baseRate?: number;
  /** How steeply a poor reputation raises the premium. Default 4. */
  riskLoad?: number;
  /** Decline coverage below this reputation. Default 0.25. */
  minScore?: number;
}

export interface InsurancePricing {
  declined: boolean;
  /** Premium to cover `exposure` for this subject. 0 when declined. */
  premium: number;
  coverage: number;
  rationale: string;
}

/**
 * Price coverage of `exposure` (e.g. the bond or max blast-radius in dollars) for a subject. Premium =
 * baseRate · exposure · (1 + riskLoad·(1−score)); declined below `minScore`. A transparent underwriting
 * curve — the insurer/underwriter layer pricing agent-action risk off reputation.
 */
export function priceCoverage(rep: Reputation, exposure: number, opts: PricingOptions = {}): InsurancePricing {
  const baseRate = opts.baseRate ?? 0.01;
  const riskLoad = opts.riskLoad ?? 4;
  const minScore = opts.minScore ?? 0.25;
  // Guard exposure finite before it enters the premium product: a NaN/Infinity exposure would otherwise
  // propagate straight into `premium`/`coverage` and quote a nonsensical (NaN) price. Clamp to 0.
  const exp = Number.isFinite(exposure) ? Math.max(0, exposure) : 0;
  if (rep.score < minScore) {
    return { declined: true, premium: 0, coverage: 0, rationale: `reputation ${rep.score.toFixed(2)} below underwriting floor ${minScore}` };
  }
  const premium = baseRate * exp * (1 + riskLoad * (1 - rep.score));
  return { declined: false, premium, coverage: exp, rationale: `base ${baseRate} × exposure ${exp} × load ${(1 + riskLoad * (1 - rep.score)).toFixed(2)} (score ${rep.score.toFixed(2)})` };
}
