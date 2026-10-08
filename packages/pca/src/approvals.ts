/**
 * Approval / step-up model (spec Part 2.2 "make autonomy feel safe" + 2.3 CIBA-style continuous
 * approval). "The step-up is where trust is won or lost."
 *
 * This is the HEADLESS core the approval inbox (mobile push / Slack / web) renders: given an intended
 * action, decide whether it auto-admits, is a hard deny, or needs a human — and if so, produce a
 * `StepUpRequest` carrying goal-lineage (which signed goal this traces back to), the risk tier, and a
 * stable id. Plus batching, and "approve this class for N hours" as a standing auto-approval that
 * downgrades matching step-ups without a prompt. Human co-sign recharges the trust budget (risk.ts).
 *
 * Pure + offline: it composes the agent's non-authoritative `dryRun` + the budget algebra. It signs
 * nothing except where you explicitly time-box a grant (`timeBox`, which attenuates with an `expires`
 * caveat using a holder key you pass). The resource server remains the authority at run time.
 */

import { type Capability, attenuate } from './capability';
import type { Agent } from './facade';
import { hashCanonical } from './hash';
import { readEnvelope } from './envelope';
import { type RiskPolicy, type TrustBudget, recharge, rechargeFull } from './risk';

// ---- step-up requests -----------------------------------------------------------------------------

export interface StepUpRequest {
  /** Stable id: hash of the action + request time. */
  id: string;
  verb: string;
  resource: string;
  params?: Record<string, unknown>;
  /** The tier a human/guardian must satisfy (2 guardian / 3 human). */
  tier: 2 | 3;
  reason: string;
  /** Goal-lineage: the signed goal commitment from the grant this action is under. */
  goalCommit: string;
  /** Optional plaintext goal, if the caller supplies it (for the "because you asked to …" line). */
  goal?: string;
  /** Risk value the action carries. */
  r: number;
  requestedAt: number;
}

/** The outcome of reviewing one intended action. */
export type Review =
  | { kind: 'auto' }
  | { kind: 'deny'; reason: string }
  | { kind: 'step_up'; request: StepUpRequest };

export interface ReviewOptions {
  now?: number;
  /** Plaintext goal to carry on any step-up request (shown to the approver). */
  goal?: string;
  /** Standing "approve class for N hours" grants that can downgrade a step-up to auto. */
  standing?: ClassApproval[];
}

/**
 * Review an intended action against the agent's grant. `auto` = no human needed; `deny` = the grant's
 * predicates/caveats forbid it (no approval can fix that offline); `step_up` = admissible but needs a
 * tier-2/3 co-sign, unless a standing class approval covers it (then `auto`).
 */
export function reviewAction(
  agent: Agent,
  verb: string,
  resource: string,
  params?: Record<string, unknown>,
  opts: ReviewOptions = {},
): Review {
  const now = opts.now ?? Date.now();
  const dr = agent.dryRun(verb, resource, params, { now });
  if (!dr.allowed) return { kind: 'deny', reason: dr.reason ?? 'denied by policy' };
  if (dr.t === 1 || dr.t === undefined) return { kind: 'auto' };
  if (opts.standing && coveredByAny(opts.standing, verb, resource, now)) return { kind: 'auto' };
  const tier = dr.t as 2 | 3;
  const goalCommit = readEnvelope(agent.grant)?.goal_commit ?? '';
  const request: StepUpRequest = {
    id: hashCanonical({ d: 'atlas-pca/stepup/v1', verb, resource, params: params ?? null, at: now }),
    verb,
    resource,
    ...(params !== undefined ? { params } : {}),
    tier,
    reason: dr.reason ?? `requires tier ${tier} co-sign`,
    goalCommit,
    ...(opts.goal !== undefined ? { goal: opts.goal } : {}),
    r: 0, // filled below
    requestedAt: now,
  };
  // surface the risk the admit path used (recompute via the agent's own policy for consistency)
  request.r = riskForReview(agent, verb, params);
  return { kind: 'step_up', request };
}

function riskForReview(agent: Agent, verb: string, params?: Record<string, unknown>): number {
  const spec = agent.policy.actions.find((s) => s.verb === verb);
  if (agent.policy.budgetModel === 'dollars' && spec?.amountField) {
    const amt = Number((params ?? {})[spec.amountField]);
    if (Number.isFinite(amt) && agent.policy.riskPolicy.kappa > 0) return Math.max(0, Math.min(1, amt / agent.policy.riskPolicy.kappa));
  }
  return Math.max(0, Math.min(1, spec ? spec.blastRadius : 0.8));
}

export interface IntendedCall {
  verb: string;
  resource: string;
  params?: Record<string, unknown>;
}

/** Review a batch of intended actions (the inbox's "N actions waiting"). */
export function batchReview(agent: Agent, calls: IntendedCall[], opts: ReviewOptions = {}): Review[] {
  return calls.map((c) => reviewAction(agent, c.verb, c.resource, c.params, opts));
}

/** Just the step-up requests from a batch of reviews (what the approver actually sees). */
export function pendingRequests(reviews: Review[]): StepUpRequest[] {
  return reviews.filter((r): r is Extract<Review, { kind: 'step_up' }> => r.kind === 'step_up').map((r) => r.request);
}

// ---- standing "approve class for N hours" ---------------------------------------------------------

export interface ClassApproval {
  id: string;
  /** Verbs this standing approval covers. */
  verbs: string[];
  /** Optional resource matcher (exact, `*`, or trailing-`*` prefix). Omitted => any resource. */
  resource?: string;
  grantedAt: number;
  ttlMs: number;
  /** Who approved (principal id / email), for the audit trail. */
  by: string;
}

/** Mint a standing class approval ("approve stripe.refund + gmail.send for the next 4 hours"). */
export function approveClass(verbs: string[], opts: { ttlMs: number; by: string; now?: number; resource?: string }): ClassApproval {
  const grantedAt = opts.now ?? Date.now();
  return {
    id: hashCanonical({ d: 'atlas-pca/class-approval/v1', verbs: [...verbs].sort(), resource: opts.resource ?? null, grantedAt, by: opts.by }),
    verbs: [...verbs],
    ...(opts.resource !== undefined ? { resource: opts.resource } : {}),
    grantedAt,
    ttlMs: opts.ttlMs,
    by: opts.by,
  };
}

function resourceMatches(pattern: string | undefined, resource: string): boolean {
  if (pattern === undefined || pattern === '*') return true;
  if (pattern.endsWith('*')) return resource.startsWith(pattern.slice(0, -1));
  return pattern === resource;
}

/** Does this standing approval still cover (verb, resource) at `now`? */
export function classApprovalCovers(a: ClassApproval, verb: string, resource: string, now: number): boolean {
  if (now < a.grantedAt || now >= a.grantedAt + a.ttlMs) return false;
  if (!a.verbs.includes(verb)) return false;
  return resourceMatches(a.resource, resource);
}

/** Is (verb, resource) covered by ANY active standing approval? */
export function coveredByAny(approvals: ClassApproval[], verb: string, resource: string, now: number): boolean {
  return approvals.some((a) => classApprovalCovers(a, verb, resource, now));
}

// ---- decisions + budget effects -------------------------------------------------------------------

export interface ApprovalDecision {
  requestId: string;
  decision: 'approve' | 'deny';
  by: string;
  at: number;
}

/** Record a human's decision on a request (pure data for the audit trail). */
export function recordDecision(request: StepUpRequest, decision: 'approve' | 'deny', by: string, at: number = Date.now()): ApprovalDecision {
  return { requestId: request.id, decision, by, at };
}

/**
 * Apply a human co-sign to the trust budget: a partial recharge (ρ per co-sign) by default, or a full
 * recharge to bMax with `full`. This is the §2.4 "recharge is human-sourced" step — the ONLY thing that
 * raises the budget — so the safety bound holds between two co-signs.
 */
export function applyCosign(budget: TrustBudget, policy: RiskPolicy, now: number, opts: { full?: boolean } = {}): TrustBudget {
  return opts.full ? rechargeFull(budget, policy.bMax, now) : recharge(budget, policy.rho, policy.bMax, now);
}

// ---- time-boxing a grant --------------------------------------------------------------------------

/**
 * Narrow a capability to expire `ttlMs` from `now` by appending an `expires` caveat (signed by the
 * holder). The honest way to express "approve this grant, but only for the next N hours": caveats are
 * conjunctive + append-only, so this can only ever RESTRICT, never widen.
 */
export function timeBox(parent: Capability, holderSecret: Uint8Array, ttlMs: number, now: number = Date.now()): Capability {
  return attenuate(parent, [{ type: 'expires', at: now + ttlMs }], holderSecret);
}
