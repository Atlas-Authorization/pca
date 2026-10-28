import { hashCanonical, paramsDigest, type PCActn } from '@atlasauth/pca';
import {
  actionDigest,
  semanticRiskContribution,
  verdictDigest,
  verifySemanticThreshold,
  type Calibration,
  type JudgeVerdict,
  type SemanticAttestationOpts,
} from '@atlasauth/pca/ext/intent';
import { bondAmount, DEFAULT_BOND_POLICY, type BondPolicy } from '@atlasauth/pca/ext/optimistic';
import type { IntentLearner } from './learner';
import { applyDivergence } from './map';
import { cellOf, harmMax, harmOf, type Outcome, type VerbSpace } from './omega';
import { outcomeToAction } from './policy';
import { renderAction } from './render';
import type { IntentSlots } from './slots';

/**
 * RUNTIME INTENT CONFORMANCE (spec §4.4–4.5, roadmap M5).
 *
 * `routeAction` decides, from the Intent Map's posterior and the verb's reversibility, how an action that the GRANT
 * already admits is handled at run time:
 *   - deny        : the action is outside the map's conservative grant (or vetoed). The PCA verifier would deny
 *                   it anyway when the grant is the map's synthesis; for an externally minted grant this is the
 *                   map's opinion and is reported as such.
 *   - allow       : reversible / rate-limited, p_n = 1 (confirmed region) and the risk is below θ₂.
 *   - optimistic  : reversible / rate-limited but p_n < 1 or risk ≥ θ₂: run on a bonded claim (`optimistic.ts`), the
 *                   bond sized by `bondAmount` on the cell's exposure h(ω); the judge panel runs inside the window.
 *   - jit-consent : irreversible: never optimistic (already enforced by `openOptimistic`); requires a JIT approval
 *                   of the deterministically rendered action, plus the judge panel.
 * The judge panel (L3) is requested when the action is irreversible, p_n < 1 (a region the principal never
 * confirmed), or its normalised risk r = (1 − p_n)·h(ω)/H_max ≥ θ₂.
 *
 * The judge panel itself is the existing B3 primitive (`semantic-threshold.ts`), reached through the `JudgePanel`
 * hook: any implementation returns signed `JudgeVerdict`s; `checkIntentConformance` verifies them with
 * `verifySemanticThreshold` (k-of-n distinct trusted judges, optional conformal cutoff and attested-judge gate) and
 * emits the INTENT-CONFORMANCE ATTESTATION (IC-Att): the verdict digests, the calibration digest and the decision,
 * content-addressed so a v1 PCActn can carry `ic_att_digest`. The risk fold is monotone:
 * r := max(r, 1 − aggregateScore) (`foldSemanticRisk`).
 *
 * Every runtime signal (JIT decision, upheld judge deny, upheld challenge, postcondition violation) goes back into
 * the learner as a `runtime` observation; a negative one vetoes the cell (the ratchet, §4.6). See `ramp.ts`.
 */

export type Route = 'deny' | 'allow' | 'optimistic' | 'jit-consent';

export interface RouteOptions {
  /** θ₂ on the normalised risk r = (1 − p)·h(ω)/H_max. Default 0.5. */
  theta2?: number;
  /** H_max used to normalise r. Default: harmMax of the learner's Ω under its harm model. */
  hMax?: number;
  bondPolicy?: BondPolicy;
}

export interface RouteDecision {
  route: Route;
  /** p_n of the action's cell (0 outside Ω). */
  p: number;
  inGrant: boolean;
  vetoed: boolean;
  reversibility: VerbSpace['reversibility'] | 'unknown';
  /** h(ω). */
  harm: number;
  /** (1 − p)·h(ω)/H_max, clamped to [0, 1]. */
  risk: number;
  /** Ask the judge panel (L3)? */
  judges: boolean;
  /** Bond for the optimistic route (exposure = h(ω)). */
  bond?: number;
  reason: string;
}

export function routeAction(l: IntentLearner, o: Outcome, opts: RouteOptions = {}): RouteDecision {
  const vs = l.omega.verbs.find((v) => v.verb === o.verb);
  if (!vs || !cellOf(vs, o)) {
    return { route: 'deny', p: 0, inGrant: false, vetoed: false, reversibility: vs?.reversibility ?? 'unknown', harm: 0, risk: 1, judges: false, reason: 'outside the Intent Map\'s outcome space' };
  }
  const p = l.acceptance(o);
  const inGrant = l.admitsOutcome(o);
  const vetoed = l.isVetoed(o);
  const harm = harmOf(vs, o, l.harm);
  const hMax = opts.hMax ?? harmMax(l.omega, l.harm);
  const risk = Math.min(1, Math.max(0, ((1 - p) * harm) / (hMax > 0 ? hMax : 1)));
  const theta2 = opts.theta2 ?? 0.5;
  const base = { p, inGrant, vetoed, reversibility: vs.reversibility, harm, risk };
  if (!inGrant) return { ...base, route: 'deny', judges: false, reason: vetoed ? 'the cell was vetoed by a runtime divergence' : 'outside the conservative grant (p_n < τ)' };
  const judges = vs.reversibility === 'irreversible' || p < 1 - 1e-12 || risk >= theta2;
  if (vs.reversibility === 'irreversible') return { ...base, route: 'jit-consent', judges, reason: 'irreversible: just-in-time consent on the rendered action' };
  if (judges) {
    return { ...base, route: 'optimistic', judges, bond: bondAmount(opts.bondPolicy ?? DEFAULT_BOND_POLICY, harm), reason: p < 1 - 1e-12 ? 'unconfirmed region (p_n < 1): bonded claim + judges' : 'risk ≥ θ₂: bonded claim + judges' };
  }
  return { ...base, route: 'allow', judges: false, reason: 'confirmed region, reversible, low risk' };
}

// ---- L3: the judge panel hook and the IC-Att -------------------------------------------------------

/** What every judge sees: the intent (text + slots by reference), the rendered action, and the map's p. */
export interface JudgeInput {
  intentRef: string;
  mapDigest: string;
  statementText: string;
  slots: IntentSlots;
  /** Deterministic rendering (`renderAction`): judges never see raw payloads. */
  renderedAction: string;
  p: number;
  reversibility: string;
  /** The digest every verdict must bind to (semantic-threshold `actionDigest`). */
  actionDigest: string;
  /** The grant's goal commitment (it carries intent_ref, §4.1). */
  goalCommitment: string;
}

/** A judge panel: any set of model judges, local or in attested TEEs. Returns their signed verdicts. */
export interface JudgePanel {
  verdicts(input: JudgeInput): Promise<readonly JudgeVerdict[]> | readonly JudgeVerdict[];
}

/** The PCActn action shape for an outcome (params digest by the canonical rule). */
export function pcactnActionOf(vs: VerbSpace, o: Outcome): PCActn['action'] {
  const a = outcomeToAction(vs, o);
  return { verb: a.verb, resource: a.resource, params_digest: paramsDigest(a.params ?? {}), reversibility_class: vs.reversibility };
}

/** Build the judge input for an outcome. */
export function judgeInputOf(l: IntentLearner, o: Outcome, ctx: { intentRef: string; mapDigest: string; statementText: string; slots: IntentSlots; goalCommitment: string }): JudgeInput {
  const vs = l.omega.verbs.find((v) => v.verb === o.verb);
  if (!vs) throw new Error(`judgeInputOf: no verb ${o.verb} in Ω`);
  return {
    ...ctx,
    renderedAction: renderAction(vs, o.values),
    p: l.acceptance(o),
    reversibility: vs.reversibility,
    actionDigest: actionDigest(pcactnActionOf(vs, o)),
  };
}

export const IC_ATT_DOMAIN = 'atlas-pca/intent-ic-att/v1';

export interface ICAtt {
  v: 1;
  kind: 'pca-ic-att';
  intent_ref: string;
  map_digest: string;
  action_digest: string;
  goal_commitment: string;
  /** Sorted verdict digests (what the ledger anchors). */
  verdict_digests: string[];
  calibration_digest: string | null;
  k: number;
  ok: boolean;
  agree_count: number;
  aggregate_score_ppm: number;
  cutoff_ppm: number | null;
  reason?: string;
}

export interface ConformanceOptions {
  judgeKeys: readonly string[];
  k: number;
  calibration?: Calibration;
  attestation?: SemanticAttestationOpts;
}

const toPpm = (x: number) => (Number.isFinite(x) ? Math.round(x * 1_000_000) : null);

/** Digest of a calibration set (what the IC-Att commits to). */
export function calibrationDigest(c: Calibration): string {
  return hashCanonical({ d: 'atlas-pca/intent-calibration/v1', alpha: c.alpha, samples: c.samples.map((s) => ({ score: s.score, faithful: s.faithful })) });
}

/** Verify a panel's verdicts for one action (B3, unchanged) and produce the IC-Att. */
export function intentConformanceAttestation(input: JudgeInput, verdicts: readonly JudgeVerdict[], opts: ConformanceOptions): ICAtt {
  const r = verifySemanticThreshold(verdicts, {
    judgeKeys: opts.judgeKeys,
    k: opts.k,
    goalCommitment: input.goalCommitment,
    actionDigest: input.actionDigest,
    ...(opts.calibration ? { calibration: opts.calibration } : {}),
    ...(opts.attestation ? { attestation: opts.attestation } : {}),
  });
  return {
    v: 1,
    kind: 'pca-ic-att',
    intent_ref: input.intentRef,
    map_digest: input.mapDigest,
    action_digest: input.actionDigest,
    goal_commitment: input.goalCommitment,
    verdict_digests: verdicts.map(verdictDigest).sort(),
    calibration_digest: opts.calibration ? calibrationDigest(opts.calibration) : null,
    k: opts.k,
    ok: r.ok,
    agree_count: r.agreeCount,
    aggregate_score_ppm: toPpm(r.aggregateScore) ?? 0,
    cutoff_ppm: r.cutoff === undefined ? null : toPpm(r.cutoff),
    ...(r.reason ? { reason: r.reason } : {}),
  };
}

/** Ask the panel and attest (the hook form). */
export async function checkIntentConformance(panel: JudgePanel, input: JudgeInput, opts: ConformanceOptions): Promise<{ att: ICAtt; verdicts: readonly JudgeVerdict[] }> {
  const verdicts = await panel.verdicts(input);
  return { att: intentConformanceAttestation(input, verdicts, opts), verdicts };
}

/** Content address of an IC-Att (the value a v1 PCActn would carry as `ic_att_digest`). */
export function icAttDigest(a: ICAtt): string {
  return hashCanonical({ d: IC_ATT_DOMAIN, a: JSON.parse(JSON.stringify(a)) as unknown });
}

/** Re-verify an IC-Att from the verdicts it names (a relying party never trusts the `ok` bit). */
export function verifyICAtt(att: ICAtt, input: JudgeInput, verdicts: readonly JudgeVerdict[], opts: ConformanceOptions): { ok: boolean; problems: string[] } {
  const again = intentConformanceAttestation(input, verdicts, opts);
  const problems: string[] = [];
  if (icAttDigest(again) !== icAttDigest(att)) problems.push('IC-Att does not match the recomputation from its verdicts');
  if (!again.ok) problems.push(`panel does not pass: ${again.reason ?? 'unknown'}`);
  return { ok: problems.length === 0, problems };
}

/** The monotone risk fold of §4.4: r := max(r, 1 − aggregateScore). Never lowers r. */
export function foldSemanticRisk(r: number, att: ICAtt): number {
  return Math.max(r, semanticRiskContribution(att.aggregate_score_ppm / 1_000_000));
}

// ---- L4: just-in-time consent (irreversible actions) -----------------------------------------------

export interface JitConsentRequest {
  v: 1;
  kind: 'pca-intent-jit';
  intent_ref: string;
  map_digest: string;
  verb: string;
  values: Record<string, number | string>;
  reversibility: string;
  p_ppm: number;
  /** The exact text the principal is shown (deterministic). */
  text: string;
}

/** The consent prompt for an action (same renderer as judges; no model in the loop). */
export function jitConsentRequest(l: IntentLearner, o: Outcome, ctx: { intentRef: string; mapDigest: string }): JitConsentRequest {
  const vs = l.omega.verbs.find((v) => v.verb === o.verb);
  if (!vs) throw new Error(`jitConsentRequest: no verb ${o.verb} in Ω`);
  const p = l.acceptance(o);
  return {
    v: 1,
    kind: 'pca-intent-jit',
    intent_ref: ctx.intentRef,
    map_digest: ctx.mapDigest,
    verb: o.verb,
    values: { ...o.values },
    reversibility: vs.reversibility,
    p_ppm: Math.round(p * 1_000_000),
    text: `${renderAction(vs, o.values)} This cannot be undone. Approve?`,
  };
}

export function jitConsentDigest(r: JitConsentRequest): string {
  return hashCanonical({ d: 'atlas-pca/intent-jit/v1', r: JSON.parse(JSON.stringify(r)) as unknown });
}

/**
 * Record the principal's JIT decision as a runtime observation (spec §4.5 item 3, §4.6): approve → y = 1 (it
 * widens the grant only through the posterior), deny → y = 0 and the cell is vetoed.
 */
export function recordJitDecision(l: IntentLearner, req: JitConsentRequest, decision: 'approve' | 'deny'): ReturnType<typeof applyDivergence> {
  return applyDivergence(l, { verb: req.verb, values: req.values }, decision === 'approve' ? 1 : 0);
}
