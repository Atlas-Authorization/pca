import { bundleDigest, type DecisionKind, type PolicyBundle, type PolicyBundleBody } from './bundle';
import { isObj, isSafeInt, isStr, signBody, signerOf, verifyBody } from './sig';

/**
 * SHADOW POLICY ROLLOUT (the Kubernetes ValidatingAdmissionPolicy Warn/Audit idea, with no path where "audit" lets anything through).
 *
 * An enforced bundle revision may list candidate bundles in `shadow`. {@link runShadow} computes the enforced decision FIRST,
 * hands the candidates a copy of the input, and returns the enforced decision untouched: a candidate that throws, hangs its own
 * result or tries to mutate the input cannot change the answer, because the answer already exists. Each candidate's answer is
 * recorded beside it (`{digest, decision, diverged}` in the decision record) and every divergence becomes a verifier-signed
 * {@link ShadowDiff}.
 *
 * PROMOTION is a new signed bundle revision (`promoteShadow` builds the body; the pinned signers sign it as for any revision).
 * {@link promotionGate} must pass first:
 *   1. enough observed decisions (`minSamples`);
 *   2. no candidate failures (an `error` is not a proof);
 *   3. every recorded diff verifies under the log signer;
 *   4. ZERO UNEXPLAINED WIDENINGS: each diff where the candidate is more permissive than the enforced policy has a principal-signed
 *      {@link WideningExplanation} for that exact (candidate, action);
 *   5. the static verdict on the declared surfaces (the analyzer's narrowing / diff, supplied by the caller): `narrower` or `equal`
 *      passes; `wider` or `unknown` is `advisory_wider` and needs a principal-signed {@link PromotionApproval}.
 * Nothing here decides an action. It is analysis and rollout tooling that runs beside the verifier.
 */
export const SHADOW_DIFF_DOMAIN = 'atlas-pca/shadow-diff/v1\0';
export const WIDENING_EXPLANATION_DOMAIN = 'atlas-pca/shadow-widening-explanation/v1\0';
export const PROMOTION_APPROVAL_DOMAIN = 'atlas-pca/shadow-promotion-approval/v1\0';
const RANK: Record<DecisionKind, number> = { deny: 0, escalate: 1, allow: 2 };
const isKind = (x: unknown): x is DecisionKind => x === 'deny' || x === 'escalate' || x === 'allow';

export interface ShadowCandidate<I> {
  /** The candidate bundle's digest (`bundleDigest`), as listed in the enforced revision's `shadow`. */
  digest: string;
  decide: (input: I) => DecisionKind;
}
export interface ShadowOutcome {
  digest: string;
  decision: DecisionKind | 'error';
  diverged: boolean;
  /** The candidate would have been MORE permissive than the enforced decision. */
  widening: boolean;
}

/** The enforced decision, plus what each candidate would have said. The returned `decision` is the enforced one, always. */
export function runShadow<I>(input: I, enforced: (i: I) => DecisionKind, candidates: readonly ShadowCandidate<I>[]): { decision: DecisionKind; shadow: ShadowOutcome[] } {
  const decision = enforced(input);
  const shadow = candidates.map((c): ShadowOutcome => {
    try {
      const d = c.decide(structuredClone(input));
      if (!isKind(d)) return { digest: c.digest, decision: 'error', diverged: false, widening: false };
      return { digest: c.digest, decision: d, diverged: d !== decision, widening: RANK[d] > RANK[decision] };
    } catch {
      return { digest: c.digest, decision: 'error', diverged: false, widening: false };
    }
  });
  return { decision, shadow };
}

/** The `shadow` member of a decision record, from the outcomes. */
export const shadowRecordField = (o: readonly ShadowOutcome[]): { digest: string; decision: DecisionKind | 'error'; diverged: boolean }[] =>
  o.map(({ digest, decision, diverged }) => ({ digest, decision, diverged }));

export interface ShadowDiff {
  v: 1;
  shadow_digest: string;
  enforced_digest: string;
  action_digest: string;
  enforced: DecisionKind;
  shadow: DecisionKind;
  widening: boolean;
  at: number;
  signer: string;
  sig: string;
}
const diffBody = (d: Omit<ShadowDiff, 'sig'>) => ({ v: d.v, shadow_digest: d.shadow_digest, enforced_digest: d.enforced_digest, action_digest: d.action_digest, enforced: d.enforced, shadow: d.shadow, widening: d.widening, at: d.at, signer: d.signer });
export function verifyShadowDiff(d: unknown, signer?: string): d is ShadowDiff {
  if (!isObj(d) || d.v !== 1 || !isStr(d.shadow_digest, 128) || !isStr(d.enforced_digest, 128) || !isStr(d.action_digest, 128) || !isKind(d.enforced) || !isKind(d.shadow) || typeof d.widening !== 'boolean' || !isSafeInt(d.at) || !isStr(d.signer, 128)) return false;
  if (d.enforced === d.shadow || d.widening !== RANK[d.shadow] > RANK[d.enforced]) return false;
  if (signer !== undefined && d.signer !== signer) return false;
  const { sig, ...rest } = d as unknown as ShadowDiff;
  return verifyBody(SHADOW_DIFF_DOMAIN, diffBody(rest), rest.signer, sig);
}

export interface ShadowStats { total: number; diverged: number; widened: number; tightened: number; errors: number }

/** Collects the signed diffs and counters per candidate. In memory: persist `diffs()` to the decision log for the audit trail. */
export class ShadowLog {
  private readonly stat = new Map<string, ShadowStats>();
  private readonly list = new Map<string, ShadowDiff[]>();
  constructor(private readonly secret: Uint8Array) {}
  get signer(): string { return signerOf(this.secret); }

  /** Count one observation; sign and keep a diff when the candidate diverged. */
  observe(o: { enforced_digest: string; action_digest: string; enforced: DecisionKind; outcome: ShadowOutcome; at: number }): ShadowDiff | undefined {
    const s = this.stat.get(o.outcome.digest) ?? { total: 0, diverged: 0, widened: 0, tightened: 0, errors: 0 };
    this.stat.set(o.outcome.digest, s);
    s.total++;
    if (o.outcome.decision === 'error') { s.errors++; return undefined; }
    if (!o.outcome.diverged) return undefined;
    s.diverged++;
    if (o.outcome.widening) s.widened++; else s.tightened++;
    const base = { v: 1 as const, shadow_digest: o.outcome.digest, enforced_digest: o.enforced_digest, action_digest: o.action_digest, enforced: o.enforced, shadow: o.outcome.decision, widening: o.outcome.widening, at: o.at, signer: this.signer };
    const diff: ShadowDiff = { ...base, sig: signBody(SHADOW_DIFF_DOMAIN, diffBody(base), this.secret) };
    const l = this.list.get(o.outcome.digest) ?? [];
    l.push(diff);
    this.list.set(o.outcome.digest, l);
    return diff;
  }
  stats(digest: string): ShadowStats { return { ...(this.stat.get(digest) ?? { total: 0, diverged: 0, widened: 0, tightened: 0, errors: 0 }) }; }
  diffs(digest: string): ShadowDiff[] { return [...(this.list.get(digest) ?? [])]; }
}

export interface WideningExplanation { v: 1; shadow_digest: string; action_digest: string; reason_digest: string; principal: string; sig: string }
const expBody = (e: Omit<WideningExplanation, 'sig'>) => ({ v: e.v, shadow_digest: e.shadow_digest, action_digest: e.action_digest, reason_digest: e.reason_digest, principal: e.principal });
/** A principal states that this widening is intended. `reason_digest` binds the reason text, which is display-only. */
export function signWideningExplanation(secret: Uint8Array, e: Pick<WideningExplanation, 'shadow_digest' | 'action_digest' | 'reason_digest'>): WideningExplanation {
  const base = { v: 1 as const, ...e, principal: signerOf(secret) };
  return { ...base, sig: signBody(WIDENING_EXPLANATION_DOMAIN, expBody(base), secret) };
}
function verifyExplanation(e: unknown): e is WideningExplanation {
  if (!isObj(e) || e.v !== 1 || !isStr(e.shadow_digest, 128) || !isStr(e.action_digest, 128) || !isStr(e.reason_digest, 128) || !isStr(e.principal, 128)) return false;
  const { sig, ...rest } = e as unknown as WideningExplanation;
  return verifyBody(WIDENING_EXPLANATION_DOMAIN, expBody(rest), rest.principal, sig);
}

export interface PromotionApproval { v: 1; shadow_digest: string; enforced_digest: string; at: number; principal: string; sig: string }
const apBody = (a: Omit<PromotionApproval, 'sig'>) => ({ v: a.v, shadow_digest: a.shadow_digest, enforced_digest: a.enforced_digest, at: a.at, principal: a.principal });
export function signPromotionApproval(secret: Uint8Array, a: Pick<PromotionApproval, 'shadow_digest' | 'enforced_digest' | 'at'>): PromotionApproval {
  const base = { v: 1 as const, ...a, principal: signerOf(secret) };
  return { ...base, sig: signBody(PROMOTION_APPROVAL_DOMAIN, apBody(base), secret) };
}
function verifyApproval(a: unknown): a is PromotionApproval {
  if (!isObj(a) || a.v !== 1 || !isStr(a.shadow_digest, 128) || !isStr(a.enforced_digest, 128) || !isSafeInt(a.at) || !isStr(a.principal, 128)) return false;
  const { sig, ...rest } = a as unknown as PromotionApproval;
  return verifyBody(PROMOTION_APPROVAL_DOMAIN, apBody(rest), rest.principal, sig);
}

/** The analyzer's static verdict for the candidate against the enforced policy on the declared surfaces. */
export type SurfaceVerdict = 'narrower' | 'equal' | 'wider' | 'unknown';
export interface GateOptions {
  shadow_digest: string;
  enforced_digest: string;
  minSamples: number;
  /** Principals (b64u keys) whose explanations and approvals count. */
  principals: readonly string[];
  explanations?: readonly unknown[];
  surface: SurfaceVerdict;
  approval?: unknown;
}
export type GateResult =
  | { ok: true; samples: number; widenings: number; surface: SurfaceVerdict }
  | { ok: false; code: 'bad_input' | 'too_few_samples' | 'shadow_errors' | 'bad_diff' | 'unexplained_widening' | 'advisory_wider'; unexplained?: string[]; reason: string };

export function promotionGate(log: ShadowLog, o: GateOptions): GateResult {
  const no = (code: Exclude<GateResult, { ok: true }>['code'], reason: string, unexplained?: string[]): GateResult => ({ ok: false, code, reason, ...(unexplained ? { unexplained } : {}) });
  try {
    if (!isStr(o.shadow_digest, 128) || !isStr(o.enforced_digest, 128) || !isSafeInt(o.minSamples) || o.minSamples < 1 || !Array.isArray(o.principals) || !['narrower', 'equal', 'wider', 'unknown'].includes(o.surface)) return no('bad_input', 'bad gate options');
    const s = log.stats(o.shadow_digest);
    if (s.total < o.minSamples) return no('too_few_samples', `${s.total} observation(s), need ${o.minSamples}`);
    if (s.errors > 0) return no('shadow_errors', `${s.errors} observation(s) where the candidate failed`);
    const diffs = log.diffs(o.shadow_digest);
    if (!diffs.every((d) => verifyShadowDiff(d, log.signer) && d.shadow_digest === o.shadow_digest && d.enforced_digest === o.enforced_digest) || diffs.length !== s.diverged) return no('bad_diff', 'a recorded diff does not verify, belongs to another pair, or is missing');
    const explained = new Set<string>();
    for (const e of o.explanations ?? []) if (verifyExplanation(e) && o.principals.includes(e.principal) && e.shadow_digest === o.shadow_digest) explained.add(e.action_digest);
    const unexplained = [...new Set(diffs.filter((d) => d.widening && !explained.has(d.action_digest)).map((d) => d.action_digest))].sort();
    if (unexplained.length > 0) return no('unexplained_widening', `${unexplained.length} widening(s) without a principal's explanation`, unexplained);
    if (o.surface === 'wider' || o.surface === 'unknown') {
      const a = o.approval;
      if (!verifyApproval(a) || !o.principals.includes(a.principal) || a.shadow_digest !== o.shadow_digest || a.enforced_digest !== o.enforced_digest) return no('advisory_wider', `the analyzer reports the candidate ${o.surface === 'wider' ? 'wider' : 'not provably narrower'} on the declared surfaces: a principal-signed approval is required`);
    }
    return { ok: true, samples: s.total, widenings: diffs.filter((d) => d.widening).length, surface: o.surface };
  } catch {
    return no('bad_input', 'evaluation error (fail closed)');
  }
}

/**
 * The body of the bundle revision that makes the candidate the enforced policy: the candidate's content at revision + 1, chained
 * to the enforced revision, with the shadow list cleared. Needs a passing gate for exactly this candidate and the candidate
 * must be listed in the enforced revision's `shadow`. Sign it with `signBundle` / `assembleBundle` like any revision.
 */
export function promoteShadow(enforced: PolicyBundleBody | PolicyBundle, candidate: PolicyBundleBody | PolicyBundle, gate: GateResult, now: number): PolicyBundleBody {
  const digest = bundleDigest(candidate);
  if (!gate.ok) throw new RangeError(`promoteShadow: the gate did not pass (${gate.code})`);
  if (!(enforced.shadow ?? []).includes(digest)) throw new RangeError('promoteShadow: the candidate is not listed in the enforced revision\'s shadow');
  if (!isSafeInt(now)) throw new RangeError('promoteShadow: bad time');
  const { sigs: _s, shadow: _sh, ...c } = candidate as PolicyBundle;
  const { prev: _p, ...rest } = c;
  return { ...rest, revision: enforced.revision + 1, prev: bundleDigest(enforced), issued_at: now };
}
