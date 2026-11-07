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
 *
 * ADVISORY BY CONSTRUCTION: nothing in the verifier, `authorize()` or the gateway reads a Reputation; do not wire
 * one into an allow decision. What is guaranteed: the score is a pure deterministic function of validated input
 * (malformed input scores 0 and says why; a dispute counts once per unique `id`; a dispute for another subject is
 * invalid), and a CoverageQuote is signed and re-derivable. What is not: the score says nothing about future
 * behaviour, and the events it counts are as honest as the console feed that produced them.
 */

import type { ActivityEvent } from './console';
import { b64u, canonicalBytesLenient, utf8 } from './hash';
import { publicKeyOf, sign, verifyB64u } from './keys';

export interface DisputeRecord {
  /** Unique id of the dispute (e.g. a settlement record digest). A repeated id counts once. */
  id: string;
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
export const MAX_REPUTATION_RECORDS = 100_000;
const OUTCOMES = new Set(['auto', 'step_up', 'deny', 'executed']);

/** Why the input is unusable, or null. */
export function validateReputationInput(input: ReputationInput): string | null {
  if (typeof input?.subject !== 'string' || input.subject === '') return 'subject must be a non-empty string';
  const { events = [], disputes = [] } = input;
  if (!Array.isArray(events) || !Array.isArray(disputes)) return 'events and disputes must be arrays';
  if (events.length > MAX_REPUTATION_RECORDS || disputes.length > MAX_REPUTATION_RECORDS) return 'too many records';
  if (events.some((e) => !OUTCOMES.has(e?.outcome))) return 'event with an unknown outcome';
  for (const d of disputes) {
    if (typeof d?.id !== 'string' || d.id === '') return 'dispute without an id';
    if (d.subject !== input.subject) return 'dispute for another subject';
    if (typeof d.slashed !== 'boolean') return 'dispute.slashed must be a boolean';
    if (!Number.isFinite(d.at) || d.at < 0) return 'dispute.at must be finite and >= 0';
    if (d.amount !== undefined && (!Number.isFinite(d.amount) || d.amount < 0)) return 'dispute.amount must be finite and >= 0';
  }
  return null;
}

export function reputation(input: ReputationInput): Reputation {
  const bad = validateReputationInput(input);
  if (bad) {
    // fail closed: unusable input is the lowest score, never the neutral "unproven" 0.5
    return { subject: String(input?.subject ?? ''), actions: 0, autos: 0, stepUps: 0, denies: 0, slashes: 0, disputes: 0, score: 0, factors: [`invalid input: ${bad}`] };
  }
  const events = input.events ?? [];
  const seen = new Set<string>();
  const disputes = (input.disputes ?? []).filter((d) => !seen.has(d.id) && !!seen.add(d.id));
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
export function priceCoverage(rep: Pick<Reputation, 'score'>, exposure: number, opts: PricingOptions = {}): InsurancePricing {
  const baseRate = opts.baseRate ?? 0.01;
  const riskLoad = opts.riskLoad ?? 4;
  const minScore = opts.minScore ?? 0.25;
  // Guard exposure finite before it enters the premium product: a NaN/Infinity exposure would otherwise
  // propagate straight into `premium`/`coverage` and quote a nonsensical (NaN) price. Clamp to 0.
  if (!Number.isFinite(rep.score) || rep.score < 0 || rep.score > 1) {
    return { declined: true, premium: 0, coverage: 0, rationale: 'invalid reputation score' };
  }
  const exp = Number.isFinite(exposure) ? Math.max(0, exposure) : 0;
  if (rep.score < minScore) {
    return { declined: true, premium: 0, coverage: 0, rationale: `reputation ${rep.score.toFixed(2)} below underwriting floor ${minScore}` };
  }
  const premium = baseRate * exp * (1 + riskLoad * (1 - rep.score));
  return { declined: false, premium, coverage: exp, rationale: `base ${baseRate} × exposure ${exp} × load ${(1 + riskLoad * (1 - rep.score)).toFixed(2)} (score ${rep.score.toFixed(2)})` };
}

// ---- signed coverage quotes -----------------------------------------------------------------------

export const COVERAGE_QUOTE_DOMAIN = 'atlas-pca/coverage-quote/v1\0';

export interface CoverageQuoteClaim {
  v: 1;
  subject: string;
  /** The reputation score the quote was priced from. */
  score: number;
  exposure: number;
  baseRate: number;
  riskLoad: number;
  minScore: number;
  declined: boolean;
  premium: number;
  coverage: number;
  issued_at: number;
  expires_at: number;
  /** b64u Ed25519 key of the underwriter. */
  underwriter: string;
}
export interface CoverageQuote extends CoverageQuoteClaim {
  sig: string;
}

const quoteMessage = (c: CoverageQuoteClaim): Uint8Array => {
  const pre = utf8(COVERAGE_QUOTE_DOMAIN);
  const body = canonicalBytesLenient(c);
  const m = new Uint8Array(pre.length + body.length);
  m.set(pre);
  m.set(body, pre.length);
  return m;
};

/** Price and sign a quote. Throws on a bad score, expiry or exposure (never signs a nonsense quote). */
export function issueCoverageQuote(a: {
  rep: Reputation;
  exposure: number;
  underwriterSecret: Uint8Array;
  now: number;
  ttlMs: number;
  opts?: PricingOptions;
}): CoverageQuote {
  const { rep } = a;
  if (!Number.isFinite(a.exposure) || a.exposure < 0) throw new Error('issueCoverageQuote: exposure must be finite and >= 0');
  if (!Number.isFinite(a.now) || !(a.ttlMs > 0) || !Number.isFinite(a.ttlMs)) throw new Error('issueCoverageQuote: now and ttlMs must be finite, ttlMs > 0');
  if (!Number.isFinite(rep.score) || rep.score < 0 || rep.score > 1) throw new Error('issueCoverageQuote: invalid reputation score');
  const baseRate = a.opts?.baseRate ?? 0.01;
  const riskLoad = a.opts?.riskLoad ?? 4;
  const minScore = a.opts?.minScore ?? 0.25;
  const p = priceCoverage(rep, a.exposure, { baseRate, riskLoad, minScore });
  const claim: CoverageQuoteClaim = {
    v: 1, subject: rep.subject, score: rep.score, exposure: a.exposure, baseRate, riskLoad, minScore,
    declined: p.declined, premium: p.premium, coverage: p.coverage,
    issued_at: a.now, expires_at: a.now + a.ttlMs, underwriter: b64u(publicKeyOf(a.underwriterSecret)),
  };
  return { ...claim, sig: b64u(sign(a.underwriterSecret, quoteMessage(claim))) };
}

export type CoverageQuoteVerdict =
  | { ok: true }
  | { ok: false; reason: 'malformed' | 'underwriter' | 'signature' | 'expired' | 'not-yet-valid' | 'price-mismatch' };

/** Verify a quote: pinned underwriter, signature, validity window, and the premium RECOMPUTED from the stated inputs. Never throws. */
export function verifyCoverageQuote(q: CoverageQuote, o: { underwriter: string; now: number }): CoverageQuoteVerdict {
  try {
    if (!q || typeof q !== 'object' || q.v !== 1 || typeof q.sig !== 'string') return { ok: false, reason: 'malformed' };
    const nums = [q.score, q.exposure, q.baseRate, q.riskLoad, q.minScore, q.premium, q.coverage, q.issued_at, q.expires_at];
    if (nums.some((n) => typeof n !== 'number' || !Number.isFinite(n)) || typeof q.declined !== 'boolean' || typeof q.subject !== 'string') return { ok: false, reason: 'malformed' };
    if (typeof o.underwriter !== 'string' || o.underwriter !== q.underwriter) return { ok: false, reason: 'underwriter' };
    const { sig, ...claim } = q;
    if (!verifyB64u(q.underwriter, quoteMessage(claim), sig)) return { ok: false, reason: 'signature' };
    if (!Number.isFinite(o.now) || o.now < q.issued_at) return { ok: false, reason: 'not-yet-valid' };
    if (o.now >= q.expires_at) return { ok: false, reason: 'expired' };
    const p = priceCoverage({ score: q.score }, q.exposure, { baseRate: q.baseRate, riskLoad: q.riskLoad, minScore: q.minScore });
    if (p.declined !== q.declined || p.premium !== q.premium || p.coverage !== q.coverage) return { ok: false, reason: 'price-mismatch' };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}
