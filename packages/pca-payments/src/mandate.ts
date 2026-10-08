import {
  type Capability,
  type Caveat,
  type Predicate,
  type RiskPolicy,
  type TrustBudget,
  mintGrant,
  safetyBound,
} from '@atlasauth/pca';

/**
 * A PAYMENT MANDATE expressed as a PCA Root Intent Grant.
 *
 * See docs/specs/pca-payments-mandate.md for the full mapping. The short version: a mandate is NOT a new
 * crypto object — it is a `mintGrant` envelope whose predicates/caveats/risk_policy encode caps, an
 * allowlist, a human-co-sign line (Y) and a hard ceiling (X), tuned so that:
 *   - risk r(charge) = amount / X                              (spend = risk; `gamma=1`, other weights 0)
 *   - theta1 = theta2 = Y/X                                    (amount > Y ⇒ t=3 human co-sign)
 *   - kappa = X, bMax = cumulativeCap                          (the trust budget IS the autonomous dollars)
 *   - Σ autonomous spend between human co-signs ≤ cumulativeCap (a THEOREM: safetyBound)
 */

export interface PaymentMandateParams {
  /** Principal (human / owning org) root secret — signs the grant. */
  principalSecret: Uint8Array;
  /** Principal public key (b64u). */
  principalPublic: string;
  /** Agent public key (b64u) the grant is bound to (the holder). */
  agentPublic: string;

  /** Allowlisted merchant ids. A charge's resource is `merchant:<id>`; off-list ⇒ deny. Must be non-empty. */
  merchants: string[];
  /** Optional allowlisted MCC categories; a charge off this list ⇒ deny. Omit/empty ⇒ any category. */
  categories?: string[];
  /** ISO-4217 currency, e.g. "USD". A different-currency charge ⇒ deny (no implicit FX). */
  currency: string;

  /** X — HARD CEILING on a single charge. `amount > X` ⇒ deny. Must be > 0. */
  perTransactionCap: number;
  /** Y — at/under ⇒ autonomous (t=1); over ⇒ human co-sign (t=3). Must satisfy 0 ≤ Y ≤ X. */
  autoApproveThreshold: number;
  /** Total AUTONOMOUS spend allowed between human co-signs (the trust budget bMax). Must satisfy X ≤ cap. */
  cumulativeCap: number;

  /** Validity window (ms). The mandate is dead after `periodStart + periodMs`. Omit ⇒ no expiry caveat. */
  periodMs?: number;
  /** Window start (epoch ms); default `now`. A `not_before` caveat is added when > 0. */
  periodStart?: number;
  /** Optional velocity cap: at most this many charges within the period window (`rate` caveat). */
  maxTransactionsPerPeriod?: number;

  /** Autonomous budget a single human co-sign restores (`rho`). Default = cumulativeCap (full refill). */
  replenishPerCosign?: number;

  /** Human-readable intent; only its salted commitment goes in the grant. Default derived from the terms. */
  goal?: string;
  /** Deterministic salt for the goal commitment (tests); random 16 bytes otherwise. */
  goalSalt?: string;
  /** Decision-time anchor (epoch ms) for the initial budget + period caveats. Default `Date.now()`. */
  now?: number;
}

/** The normalized, machine-usable terms derived from the params (what the decision path reads). */
export interface MandateTerms {
  merchants: string[];
  categories: string[];
  currency: string;
  /** X */
  perTransactionCap: number;
  /** Y */
  autoApproveThreshold: number;
  cumulativeCap: number;
  periodStart: number;
  periodEnd?: number;
  maxTransactionsPerPeriod?: number;
}

export interface PaymentMandate {
  /** The PCA Root Intent Grant carrying the whole mandate in its signed `envelope` caveat. */
  grant: Capability;
  /** The derived risk policy (also embedded in the grant). */
  policy: RiskPolicy;
  /** Current autonomous budget. Starts at `{ B: cumulativeCap, ... }`; thread it across charges. */
  budget: TrustBudget;
  terms: MandateTerms;
  goalCommit: string;
  goalSalt: string;
}

const isFiniteNum = (x: unknown): x is number => typeof x === 'number' && Number.isFinite(x);

/** Validate the params and throw on anything that would make an incoherent mandate. */
function validate(p: PaymentMandateParams): void {
  if (!Array.isArray(p.merchants) || p.merchants.length === 0) {
    throw new Error('buildPaymentMandate: at least one allowlisted merchant is required');
  }
  if (p.merchants.some((m) => typeof m !== 'string' || m.length === 0)) {
    throw new Error('buildPaymentMandate: merchant ids must be non-empty strings');
  }
  if (typeof p.currency !== 'string' || p.currency.length === 0) {
    throw new Error('buildPaymentMandate: currency is required');
  }
  if (!isFiniteNum(p.perTransactionCap) || p.perTransactionCap <= 0) {
    throw new Error('buildPaymentMandate: perTransactionCap (X) must be a finite number > 0');
  }
  if (!isFiniteNum(p.autoApproveThreshold) || p.autoApproveThreshold < 0 || p.autoApproveThreshold > p.perTransactionCap) {
    throw new Error('buildPaymentMandate: autoApproveThreshold (Y) must satisfy 0 ≤ Y ≤ X');
  }
  if (!isFiniteNum(p.cumulativeCap) || p.cumulativeCap < p.perTransactionCap) {
    throw new Error('buildPaymentMandate: cumulativeCap must be a finite number ≥ perTransactionCap (X)');
  }
  if (p.periodMs !== undefined && (!isFiniteNum(p.periodMs) || p.periodMs <= 0)) {
    throw new Error('buildPaymentMandate: periodMs must be a finite number > 0 when given');
  }
  if (p.maxTransactionsPerPeriod !== undefined && (!Number.isInteger(p.maxTransactionsPerPeriod) || p.maxTransactionsPerPeriod <= 0)) {
    throw new Error('buildPaymentMandate: maxTransactionsPerPeriod must be a positive integer when given');
  }
  if (p.replenishPerCosign !== undefined && (!isFiniteNum(p.replenishPerCosign) || p.replenishPerCosign < 0)) {
    throw new Error('buildPaymentMandate: replenishPerCosign must be a finite number ≥ 0 when given');
  }
}

/** Build the allowlist predicates: one per merchant, each carrying the currency, category and hard-ceiling guards. */
export function mandatePredicates(terms: MandateTerms): Predicate[] {
  const where = (merchant: string): Predicate['where'] => {
    const conds: NonNullable<Predicate['where']> = [
      // Hard ceiling X: amount > X fails every predicate ⇒ deny.
      { field: 'action.params.amount', op: 'lte', value: terms.perTransactionCap },
      // No implicit FX: the charge currency must match the mandate.
      { field: 'action.params.currency', op: 'eq', value: terms.currency },
      // Non-negative amount (a refund/credit is a different verb, out of scope here).
      { field: 'action.params.amount', op: 'gte', value: 0 },
    ];
    if (terms.categories.length > 0) {
      conds.push({ field: 'action.params.category', op: 'in', value: terms.categories });
    }
    void merchant;
    return conds;
  };
  return terms.merchants.map((m) => ({ verb: 'charge', resource: `merchant:${m}`, where: where(m) }));
}

/** Build the envelope caveats: period window, velocity cap, and the bonded/refundable reversibility floor. */
export function mandateCaveats(terms: MandateTerms): Caveat[] {
  const caveats: Caveat[] = [];
  if (terms.periodStart > 0) caveats.push({ type: 'not_before', at: terms.periodStart });
  if (terms.periodEnd !== undefined) caveats.push({ type: 'expires', at: terms.periodEnd });
  if (terms.maxTransactionsPerPeriod !== undefined && terms.periodEnd !== undefined) {
    const perSecs = Math.max(1, Math.round((terms.periodEnd - terms.periodStart) / 1000));
    caveats.push({ type: 'rate', max: terms.maxTransactionsPerPeriod, per_secs: perSecs });
  }
  // Only a reversible (bonded / refundable, see §2.5) charge may be formed at all.
  caveats.push({ type: 'reversibility_max', class: 'reversible' });
  return caveats;
}

/**
 * Derive the risk policy that makes "spend = risk" exact:
 *   - weights: only gamma (blast radius) = 1; so r = blastRadius = amount/X.
 *   - theta1 = theta2 = Y/X: deletes the t=2 band; amount>Y ⇒ t=3 (human co-sign).
 *   - kappa = X: cost = kappa·r = amount (budget denominated in dollars).
 *   - bMax = cumulativeCap, lambda = 0 (no passive decay), rho = replenishPerCosign.
 */
export function mandateRiskPolicy(terms: MandateTerms, replenishPerCosign: number): RiskPolicy {
  return {
    weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 },
    theta1: terms.autoApproveThreshold / terms.perTransactionCap,
    theta2: terms.autoApproveThreshold / terms.perTransactionCap,
    kappa: terms.perTransactionCap,
    lambda: 0,
    rho: replenishPerCosign,
    bMax: terms.cumulativeCap,
  };
}

/**
 * The §2.4 dollar bound: the MOST an agent can spend autonomously between two human co-signs, derived
 * from the PCA safety theorem (`safetyBound = bMax/kappa`, in risk units) × kappa (dollars). Equals
 * `cumulativeCap`. A theorem over the budget algebra, not a runtime check.
 */
export function autoSpendBound(mandate: Pick<PaymentMandate, 'policy'>): number {
  return safetyBound(mandate.policy) * mandate.policy.kappa;
}

/** Build a payment mandate: encode the params as a PCA Root Intent Grant envelope + initial trust budget. */
export function buildPaymentMandate(params: PaymentMandateParams): PaymentMandate {
  validate(params);
  const now = isFiniteNum(params.now) ? params.now : Date.now();
  const periodStart = isFiniteNum(params.periodStart) ? params.periodStart : now;
  const terms: MandateTerms = {
    merchants: [...params.merchants],
    categories: params.categories ? [...params.categories] : [],
    currency: params.currency,
    perTransactionCap: params.perTransactionCap,
    autoApproveThreshold: params.autoApproveThreshold,
    cumulativeCap: params.cumulativeCap,
    periodStart,
    ...(params.periodMs !== undefined ? { periodEnd: periodStart + params.periodMs } : {}),
    ...(params.maxTransactionsPerPeriod !== undefined ? { maxTransactionsPerPeriod: params.maxTransactionsPerPeriod } : {}),
  };
  const replenish = params.replenishPerCosign ?? params.cumulativeCap;
  const policy = mandateRiskPolicy(terms, replenish);

  const goal =
    params.goal ??
    `spend ≤ ${terms.autoApproveThreshold} ${terms.currency} autonomously / ≤ ${terms.perTransactionCap} with co-sign, ` +
      `≤ ${terms.cumulativeCap} cumulative, at [${terms.merchants.join(', ')}]`;

  const { grant, goalCommit, goalSalt } = mintGrant({
    principalSecret: params.principalSecret,
    principalPublic: params.principalPublic,
    holder: params.agentPublic,
    goal,
    ...(params.goalSalt !== undefined ? { salt: params.goalSalt } : {}),
    envelope: {
      predicates: mandatePredicates(terms),
      caveats: mandateCaveats(terms),
      agent_binding: {},
      risk_policy: policy,
    },
  });

  const budget: TrustBudget = { B: terms.cumulativeCap, tau: now, asOf: now };
  return { grant, policy, budget, terms, goalCommit, goalSalt };
}
