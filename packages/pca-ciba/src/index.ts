/**
 * @atlasauth/pca-ciba — a CIBA on-ramp for PCA's FROST step-up.
 *
 * CIBA (OpenID Connect Client-Initiated Backchannel Authentication, OpenID CIBA Core) is the
 * convergent human-in-the-loop (HITL) primitive every modern IdP ships — Auth0 ("CIBA / push
 * authorization"), Descope, Stytch — for *asynchronous* out-of-band approval: a backend starts an
 * `auth_req_id`, the human is notified on a separate device, and the backend learns the decision by
 * polling (POLL) or via a callback (PING/PUSH). Its `binding_message` field carries the short
 * human-readable context the person sees while approving, so the thing they approve on their phone is
 * provably the thing the agent is about to do.
 *
 * This package is a BRIDGE, not a replacement. PCA's cryptographic step-up (FROST threshold cosign —
 * see `@atlasauth/pca` `threshold`/`frost`) stays the *enforcement*: a tier-3 action proceeds only once
 * a real threshold signature recharges the trust budget. CIBA is only the human-notification / decision
 * *envelope* around that cosign — it standardises how the human is asked and how the answer comes back.
 * PCA's FROST step-up is cryptographically stronger than a bare CIBA approval (an OP's yes/no is a
 * trusted single party; a FROST cosign is an unforgeable t-of-n signature); this just gives it the
 * industry-standard async-approval + binding-message on-ramp.
 *
 * Risk-adaptive gating is the point. If every action prompts a human, humans blanket-approve (Anthropic
 * observed 93% blanket-approval under always-prompt). So only a tier-3 step-up — a human-required,
 * typically irreversible/high-risk action — is routed through CIBA. Tier-2 (guardian auto-cosign) and
 * tier-1 (`auto`) never interrupt a person. `requiresCiba()` encodes exactly that gate.
 *
 * Everything here is pure or in-memory and authorises nothing on its own: the resource server's verifier
 * (`requirePCA` / the adjudicator) and the FROST cosigners remain the run-time authority.
 */

import {
  type StepUpRequest,
  type Review,
  type TrustBudget,
  type RiskPolicy,
  applyCosign,
  hashCanonical,
} from '@atlasauth/pca';

// ---- CIBA backchannel auth request ----------------------------------------------------------------

/** A CIBA backchannel authentication request derived from a PCA step-up. */
export interface CibaAuthRequest {
  /**
   * The CIBA `auth_req_id` — the opaque handle the backend polls / correlates on. Derived
   * deterministically from the step-up id, so the same step-up always maps to the same request.
   */
  auth_req_id: string;
  /**
   * The human-readable approval context shown to the person (OpenID CIBA `binding_message`): what is
   * being approved and why, traced to the goal the agent was given.
   */
  binding_message: string;
  /** CIBA `scope` (space-delimited), carrying `openid` + a PCA step-up scope for this verb. */
  scope: string;
  /** CIBA `requested_expiry` in SECONDS — how long the human has to decide. */
  requested_expiry: number;
  /** CIBA `interval` in SECONDS — minimum poll spacing for POLL mode. */
  interval: number;
  /** CIBA `login_hint` — who to notify, if the caller supplied one. */
  login_hint?: string;
  /** The PCA step-up this request fulfils (back-link for correlation). */
  stepUpId: string;
  /** The PCA risk tier that produced the step-up (2 guardian / 3 human). */
  tier: 2 | 3;
}

/** Options shared by `toCibaAuthRequest` and the broker's `start`. */
export interface CibaRequestOptions {
  /** Override the `requested_expiry` (seconds). Default 300. */
  expiresInSec?: number;
  /** CIBA `login_hint` for the OP: the identifier of the human to notify. */
  loginHint?: string;
  /**
   * The agent's human-facing name used in the binding message ("because you asked <actsFor> to …"),
   * e.g. `"support-bot"`. Default `"your agent"`.
   */
  actsFor?: string;
}

const DEFAULT_EXPIRY_SEC = 300;
const DEFAULT_INTERVAL_SEC = 5;

/** A short "$480" / "480 EUR" fragment from a step-up's params, or "" when there's no amount. */
function amountFragment(params: StepUpRequest['params']): string {
  if (!params) return '';
  const amt = params['amount'];
  if (typeof amt !== 'number' || !Number.isFinite(amt)) return '';
  const cur = params['currency'];
  if (typeof cur === 'string' && cur.length > 0 && cur.toLowerCase() !== 'usd') {
    return ` ${amt} ${cur.toUpperCase()}`;
  }
  return ` $${amt}`;
}

/**
 * Build the CIBA `binding_message`: the one-line human-readable approval context. Combines the
 * verb + optional amount + resource with the goal-lineage ("because you asked <agent> to '<goal>'").
 * Falls back to the salted goal commitment when the plaintext goal isn't carried on the step-up, so
 * lineage is always present.
 */
function bindingMessage(stepUp: StepUpRequest, actsFor: string): string {
  const head = `Approve ${stepUp.verb}${amountFragment(stepUp.params)} on ${stepUp.resource}`;
  const goalText =
    stepUp.goal !== undefined && stepUp.goal.length > 0
      ? stepUp.goal
      : stepUp.goalCommit.length > 0
        ? `goal ${stepUp.goalCommit.slice(0, 10)}…`
        : undefined;
  return goalText === undefined ? head : `${head} — because you asked ${actsFor} to '${goalText}'`;
}

/**
 * Map a PCA {@link StepUpRequest} to a {@link CibaAuthRequest}. Pure: derives a stable `auth_req_id`
 * from the step-up id, renders the `binding_message`, and carries the scope / expiry / poll interval.
 * Does not start a flow or notify anyone — that's the broker.
 */
export function toCibaAuthRequest(stepUp: StepUpRequest, opts: CibaRequestOptions = {}): CibaAuthRequest {
  const actsFor = opts.actsFor !== undefined && opts.actsFor.length > 0 ? opts.actsFor : 'your agent';
  const auth_req_id = hashCanonical({ d: 'atlas-pca/ciba/auth_req_id/v1', stepUp: stepUp.id });
  return {
    auth_req_id,
    binding_message: bindingMessage(stepUp, actsFor),
    scope: `openid urn:atlas:pca:stepup:${stepUp.verb}`,
    requested_expiry: opts.expiresInSec !== undefined ? opts.expiresInSec : DEFAULT_EXPIRY_SEC,
    interval: DEFAULT_INTERVAL_SEC,
    ...(opts.loginHint !== undefined ? { login_hint: opts.loginHint } : {}),
    stepUpId: stepUp.id,
    tier: stepUp.tier,
  };
}

// ---- in-memory broker (POLL + PING/PUSH) ----------------------------------------------------------

/** The settled outcome of a CIBA request, with `pending` while the human hasn't acted and `expired`
 *  once `requested_expiry` elapses. */
export type CibaStatus = 'pending' | 'approved' | 'denied' | 'expired';

/** A broker session: the request plus the (lazily-evaluated) decision state. */
export interface CibaSession {
  auth_req_id: string;
  request: CibaAuthRequest;
  /** Effective status computed at read time (never a stale stored flag). */
  status: CibaStatus;
  /** ms epoch the session was started. */
  createdAt: number;
  /** ms epoch the request expires (`createdAt + requested_expiry·1000`). */
  expiresAt: number;
  /** Who acted, once resolved. */
  decidedBy?: string;
  /** ms epoch the human acted, once resolved. */
  decidedAt?: number;
}

/** Options for {@link createCibaBroker}. */
export interface CibaBrokerOptions {
  /** Clock (ms). Default `Date.now`. Inject for deterministic tests / expiry. */
  now?: () => number;
  /**
   * PING/PUSH mode: called once, synchronously, the moment a session is resolved (approved or denied).
   * Omit it to use pure POLL mode (the caller drives `poll`).
   */
  onComplete?: (session: CibaSession) => void;
}

/** The in-memory CIBA broker returned by {@link createCibaBroker}. */
export interface CibaBroker {
  /** Begin a backchannel flow for a step-up; returns the CIBA auth request (status starts `pending`). */
  start(stepUp: StepUpRequest, opts?: CibaRequestOptions): CibaAuthRequest;
  /** POLL: the current effective status (`authorization_pending` semantics while `pending`). */
  poll(auth_req_id: string): { status: CibaStatus };
  /** The human acts out-of-band: approve or deny. Fires `onComplete` (PING/PUSH) if configured. */
  resolve(auth_req_id: string, decision: 'approve' | 'deny', by: string): CibaSession;
  /** Read a full session snapshot (status computed at read time), or `undefined` if unknown. */
  get(auth_req_id: string): CibaSession | undefined;
}

interface StoredSession {
  request: CibaAuthRequest;
  createdAt: number;
  expiresAt: number;
  decision?: 'approve' | 'deny';
  decidedBy?: string;
  decidedAt?: number;
}

/** Status is computed, never stored — a decision wins, else expiry, else pending (read-time truth). */
function effectiveStatus(s: StoredSession, now: number): CibaStatus {
  if (s.decision === 'approve') return 'approved';
  if (s.decision === 'deny') return 'denied';
  if (now >= s.expiresAt) return 'expired';
  return 'pending';
}

function snapshot(s: StoredSession, now: number): CibaSession {
  return {
    auth_req_id: s.request.auth_req_id,
    request: s.request,
    status: effectiveStatus(s, now),
    createdAt: s.createdAt,
    expiresAt: s.expiresAt,
    ...(s.decidedBy !== undefined ? { decidedBy: s.decidedBy } : {}),
    ...(s.decidedAt !== undefined ? { decidedAt: s.decidedAt } : {}),
  };
}

/**
 * An in-memory CIBA broker. Models the backchannel lifecycle without any network: `start` opens a
 * session, `poll` reports `pending`/`approved`/`denied`/`expired`, and `resolve` records the human's
 * decision. Supports both delivery modes — POLL (caller drives `poll`) and PING/PUSH (an `onComplete`
 * callback fires on resolution). A production deployment swaps this for the real OP + FROST cosigners;
 * the shape stays the same.
 */
export function createCibaBroker(opts: CibaBrokerOptions = {}): CibaBroker {
  const clock = opts.now ?? Date.now;
  const sessions = new Map<string, StoredSession>();

  return {
    start(stepUp, reqOpts) {
      const request = toCibaAuthRequest(stepUp, reqOpts);
      const createdAt = clock();
      const stored: StoredSession = {
        request,
        createdAt,
        expiresAt: createdAt + request.requested_expiry * 1000,
      };
      sessions.set(request.auth_req_id, stored);
      return request;
    },
    poll(auth_req_id) {
      const s = sessions.get(auth_req_id);
      if (!s) throw new Error(`ciba: unknown auth_req_id ${auth_req_id}`);
      return { status: effectiveStatus(s, clock()) };
    },
    resolve(auth_req_id, decision, by) {
      const s = sessions.get(auth_req_id);
      if (!s) throw new Error(`ciba: unknown auth_req_id ${auth_req_id}`);
      const now = clock();
      const current = effectiveStatus(s, now);
      if (current !== 'pending') {
        throw new Error(`ciba: cannot resolve ${auth_req_id} — already ${current}`);
      }
      s.decision = decision;
      s.decidedBy = by;
      s.decidedAt = now;
      const snap = snapshot(s, now);
      if (opts.onComplete) opts.onComplete(snap);
      return snap;
    },
    get(auth_req_id) {
      const s = sessions.get(auth_req_id);
      return s ? snapshot(s, clock()) : undefined;
    },
  };
}

// ---- risk-adaptive gating + the hand-off back to the cryptographic cosign -------------------------

/**
 * The gate: does this review need a CIBA human-approval round-trip? Only a tier-3 step-up (human
 * required — typically irreversible / high blast-radius) does. A tier-2 step-up is handled by the
 * guardian's auto-cosign, and an `auto`/`deny` review never notifies a human. This is the
 * risk-adaptive interrupt that avoids blanket-approval fatigue.
 */
export function requiresCiba(review: Review): boolean {
  return review.kind === 'step_up' && review.request.tier === 3;
}

/** The budget effect of a settled CIBA decision. */
export interface CibaCosignResult {
  /** The trust budget after applying the decision (recharged on approve, unchanged on deny). */
  budget: TrustBudget;
  /** Whether a (budget-level) cosign was applied. */
  cosigned: boolean;
}

/**
 * Fold a settled CIBA decision back into PCA's trust budget. On `approve`, recharge via `applyCosign`
 * (partial ρ per cosign, or full with `{ full: true }`); on `deny`, the budget is unchanged.
 *
 * NOTE: this is the BUDGET-level effect only. The actual cryptographic cosign that authorises a tier-3
 * action is a FROST threshold signature (`@atlasauth/pca` `threshold`/`frost`), produced out of band and
 * verified by the resource server — CIBA carries the human *decision*, not the signature. A real
 * integration gates `applyCosign` on a verified FROST cosign; here we model the budget recharge the
 * approval authorises.
 */
export function cibaDecisionToCosign(
  decision: 'approve' | 'deny',
  budget: TrustBudget,
  policy: RiskPolicy,
  now: number,
  opts: { full?: boolean } = {},
): CibaCosignResult {
  if (decision === 'approve') return { budget: applyCosign(budget, policy, now, opts), cosigned: true };
  return { budget, cosigned: false };
}
