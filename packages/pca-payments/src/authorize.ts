import {
  type ActionContext,
  type Capability,
  type DecideInput,
  type PolicyDecision,
  type RequiredThreshold,
  type TrustBudget,
  cost as budgetCost,
  decide,
  hashCanonical,
  readEnvelope,
  recharge,
  rechargeFull,
} from '@atlasauth/pca';
import { mandateCaveats, mandatePredicates, type PaymentMandate } from './mandate';

/** Reversibility class every charge is minted in (bonded / refundable — see spec §2.5). */
export const CHARGE_REVERSIBILITY_CLASS = 'reversible';
/** The action verb a charge denotes. */
export const CHARGE_VERB = 'charge';

/** A single attempted charge. */
export interface Charge {
  /** Merchant id; the action resource is `merchant:<merchant>`. */
  merchant: string;
  /** Amount in the mandate's currency (use integer minor units in production to avoid float drift). */
  amount: number;
  /** MCC category; required to pass a mandate that constrains categories. */
  category?: string;
  /** Currency; defaults to the mandate's currency (and must equal it to be authorized). */
  currency?: string;
  /** Decision time (epoch ms); default `Date.now()`. */
  now?: number;
  /** Epoch-ms timestamps of this holder's prior admitted charges (only needed for a velocity `rate` caveat). */
  recentChargeTimes?: number[];
}

export type ChargeOutcome = 'auto' | 'step_up' | 'deny';

export interface ChargeDecision {
  /**
   * - `auto`    — within caps + allowlist + ≤ Y and the budget covers it: the agent may charge alone (t=1).
   * - `step_up` — allowlisted but amount > Y, OR the cumulative budget is exhausted: a human must co-sign (t=3).
   * - `deny`    — off-allowlist / off-category / wrong currency / over the hard ceiling X / expired.
   */
  outcome: ChargeOutcome;
  /** Required threshold rung (1 = agent-only, 3 = principal-device / human co-sign). */
  t: 1 | 2 | 3;
  /** Recomputed, verifier-derivable risk r = amount/X ∈ [0,1]. */
  r: number;
  requiredThreshold: RequiredThreshold;
  /** Dollars this charge debits from the autonomous budget (= amount for `auto`; 0 otherwise). */
  cost: number;
  budgetBefore: TrustBudget;
  /** Budget after this charge: debited for `auto`, unchanged for `step_up`/`deny`. Thread it to the next charge. */
  budgetAfter: TrustBudget;
  reasons: string[];
  /** The raw PCA policy decision this was derived from. */
  decision: PolicyDecision;
}

const num = (x: unknown, fallback: number): number => (typeof x === 'number' && Number.isFinite(x) ? x : fallback);

/** Build the `ActionContext` a charge denotes (the verb/resource/params the predicates + risk read). */
export function chargeActionContext(mandate: PaymentMandate, charge: Charge): ActionContext {
  return {
    action: {
      verb: CHARGE_VERB,
      resource: `merchant:${charge.merchant}`,
      params: {
        amount: charge.amount,
        currency: charge.currency ?? mandate.terms.currency,
        ...(charge.category !== undefined ? { category: charge.category } : {}),
      },
      reversibility_class: CHARGE_REVERSIBILITY_CLASS,
    },
  };
}

/**
 * Why a mandate was refused before any decision:
 *   verified_grant_required  no verified / stored grant was supplied (the mandate's own grant is never the authority)
 *   mandate_grant_mismatch   the mandate's grant is not the verified grant (content-hash compare)
 *   mandate_terms_mismatch   the mandate's terms / policy are not the ones signed into the verified grant's envelope
 */
export class MandateGrantError extends Error {
  constructor(
    readonly code: 'verified_grant_required' | 'mandate_grant_mismatch' | 'mandate_terms_mismatch',
    message: string,
  ) {
    super(message);
    this.name = 'MandateGrantError';
  }
}

/**
 * Bind a mandate to the grant the caller VERIFIED (or loaded from its own store): the mandate's grant must be that grant,
 * and the terms / policy the decision reads must be exactly the ones signed into its envelope. Returns the mandate with
 * its budget clamped to the signed `bMax` (a budget is state, but it can never exceed what the principal signed).
 */
function bindToVerifiedGrant(mandate: PaymentMandate, verifiedGrant: Capability): PaymentMandate {
  if (verifiedGrant === null || verifiedGrant === undefined || typeof verifiedGrant !== 'object') {
    throw new MandateGrantError('verified_grant_required', "a verified (or stored) grant is required; the mandate's own grant is never the authority");
  }
  if (mandate === null || typeof mandate !== 'object' || hashCanonical(mandate.grant) !== hashCanonical(verifiedGrant)) {
    throw new MandateGrantError('mandate_grant_mismatch', 'the mandate grant is not the verified grant');
  }
  const env = readEnvelope(verifiedGrant);
  const same = (a: unknown, b: unknown) => hashCanonical(a) === hashCanonical(b);
  if (
    !env ||
    !mandate.terms ||
    !mandate.policy ||
    !same(env.predicates, mandatePredicates(mandate.terms)) ||
    !same(env.caveats, mandateCaveats(mandate.terms)) ||
    !same(env.risk_policy, mandate.policy)
  ) {
    throw new MandateGrantError('mandate_terms_mismatch', 'the mandate terms / policy are not the ones signed into the verified grant');
  }
  const bMax = env.risk_policy.bMax;
  const B = typeof mandate.budget?.B === 'number' && Number.isFinite(mandate.budget.B) ? Math.min(mandate.budget.B, bMax) : 0;
  return { ...mandate, grant: verifiedGrant, budget: { ...mandate.budget, B } };
}

/**
 * Assemble the `DecideInput` for a charge: risk is collapsed to the normalized amount (spend = risk). `verifiedGrant` is
 * the grant you verified or loaded from your own store; a mandate whose grant, terms or policy differ is refused
 * ({@link MandateGrantError}).
 */
export function chargeDecideInput(mandate0: PaymentMandate, charge: Charge, now: number, verifiedGrant: Capability): DecideInput {
  const mandate = bindToVerifiedGrant(mandate0, verifiedGrant);
  const X = mandate.terms.perTransactionCap;
  const amount = num(charge.amount, Infinity);
  // blastRadius = amount/X is the ONLY non-zero-weighted risk input; r = amount/X (clamped in riskScore).
  const blastRadius = X > 0 ? amount / X : 1;
  return {
    grant: verifiedGrant,
    action: chargeActionContext(mandate, charge),
    // All other inputs are benign and zero-weighted; supplying them avoids spurious "missing input" reasons.
    risk: { semanticDistance: 0, reversibility: 1, blastRadius, taint: 0, confidence: 1, age: 0 },
    budget: mandate.budget,
    now,
    caveatContext: {
      reversibilityClass: CHARGE_REVERSIBILITY_CLASS,
      ...(charge.recentChargeTimes !== undefined ? { recentActionTimes: charge.recentChargeTimes } : {}),
    },
  };
}

/**
 * Run a charge through the PCA decision against the grant you VERIFIED (or loaded from your own store). Pure: reads
 * `mandate.budget` (clamped to the signed bMax), returns the next budget in `budgetAfter` (thread it, or use
 * {@link settleCharge}). Throws {@link MandateGrantError} when there is no verified grant, or the mandate's grant, terms
 * or policy are not that grant's; never throws on a charge.
 */
export function authorizeCharge(mandate0: PaymentMandate, charge: Charge, verifiedGrant: Capability): ChargeDecision {
  const mandate = bindToVerifiedGrant(mandate0, verifiedGrant);
  const now = num(charge.now, Date.now());
  const input = chargeDecideInput(mandate, charge, now, verifiedGrant);
  const decision = decide(input);

  let outcome: ChargeOutcome;
  if (!decision.releaseGuardianShare) outcome = 'deny';
  else if (decision.admit) outcome = 'auto';
  else outcome = 'step_up';

  const cost = outcome === 'auto' ? budgetCost(decision.r, mandate.policy.kappa) : 0;

  return {
    outcome,
    t: decision.requiredThreshold.t,
    r: decision.r,
    requiredThreshold: decision.requiredThreshold,
    cost,
    budgetBefore: mandate.budget,
    // `decide` returns the leaked (and, for an auto charge, debited) budget.
    budgetAfter: decision.budget,
    reasons: decision.reasons,
    decision,
  };
}

/**
 * Advance the mandate's budget after a decision (functional; returns a new mandate). For `auto` this is
 * the already-debited budget from the decision; for `step_up`/`deny` the budget is unchanged.
 */
export function settleCharge(mandate: PaymentMandate, decision: ChargeDecision): PaymentMandate {
  return { ...mandate, budget: decision.budgetAfter };
}

/**
 * Apply a human co-sign: restore autonomous budget by `rho` (partial) or fully re-confirm to `bMax`.
 * This is the ONLY way the budget goes up — it models the principal approving a step-up / refreshing
 * the mandate for the next window. Returns a new mandate.
 */
export function applyHumanCosign(mandate: PaymentMandate, now: number, opts: { full?: boolean } = {}): PaymentMandate {
  const budget = opts.full
    ? rechargeFull(mandate.budget, mandate.policy.bMax, now)
    : recharge(mandate.budget, mandate.policy.rho, mandate.policy.bMax, now);
  return { ...mandate, budget };
}
