import { b64u, canonicalBytesStrict, compareUtf8, decodeB64uStrict, hashCanonical, utf8 } from './hash';
import { publicKeyOf } from './keys';
import {
  type MlDsaKeyPair,
  type SigAlg,
  bindSuiteFields,
  encodeMlDsaPublicKey,
  resolveSigAlg,
  signSuiteArtifact,
  verifyWithSuite,
} from './pq';
import type { Hook, HookResult, PCActn, VerifyContext } from './pcactn';
import { type HardwareAttestationResult, type MeasuredIdentity, matchAgentBinding } from './attestation';
import type { AgentBinding } from './envelope';

/**
 * B3 — VERIFIABLE SEMANTIC JUDGMENT (PCA framework-evolution item B3).
 *
 * PCA already checks STRUCTURAL faithfulness: an action is a node of the signed plan (the Merkle
 * plan-graph geodesic, `merkle.ts` + the `plan_inclusion` check in `pcactn.ts`). Structure answers
 * "is this action ON the committed plan"; it cannot answer "is this action actually what the
 * principal MEANT" — a plan can be followed to the letter and still betray intent (goal mis-spec,
 * an adversarial-but-in-plan step, a literal-genie reading).
 *
 * B3 adds a SEMANTIC threshold ALONGSIDE the cryptographic one (`threshold.ts`'s t-of-n of
 * agent/guardian/principal keys). Instead of signing authority, a k-of-n ensemble of ATTESTED judge
 * models signs a verdict about faithfulness-to-intent:
 *
 *   - each judge emits a SIGNED verdict over {actionDigest, goalCommitment, faithful, score},
 *     domain-separated (`atlas-pca/semantic-judge/v1`) and bound to the exact action + goal, so a
 *     verdict cannot be replayed onto a different action or a different goal;
 *   - verdicts are checked against an ALLOWLIST of trusted judge keys (one-key-one-vote,
 *     distinct-key), so an attacker who controls one judge is `k-1` short, exactly as a compromised
 *     agent is `t-1` short of the cryptographic threshold;
 *   - the raw agreement (an `aggregateScore`) is turned into an ALLOW/DENY decision by a
 *     split-conformal CALIBRATION layer that bounds the empirical FALSE-ALLOW rate at a chosen
 *     alpha — a statistical guarantee in place of a magic confidence number.
 *
 * Fail-closed throughout: an unknown, duplicate, mis-bound, mis-signed, or self-contradicting
 * verdict simply does not count. Verdicts are signed + canonical, so they are ledger-anchorable
 * (feed `verdictDigest` to `ledger.ts`) and challengeable (re-run `verifySemanticThreshold` with the
 * same inputs and compare).
 *
 * ATTESTED JUDGE (now IN SCOPE): a judgment can be BOUND to a real measured TEE the SAME way the agent
 * is (`hardware-sevsnp.ts` + `attestation.ts`). The signed `judgeMeasurement` can be tied to a VERIFIED
 * measured identity — the judge runs in an attested enclave whose SEV-SNP report measurement is checked
 * up to the AMD root — via {@link verifyJudgeAttestation} and the {@link SemanticThresholdOpts.attestation}
 * gate. The gate's resolver returns the SAME `HardwareAttestationResult` a `HardwareAttestationVerifier`
 * yields (NO parallel type); the attestation must be verified + report_data-bound (`ok && bound`), its
 * measured `runtime_measurement` must EQUAL the signed `judgeMeasurement`, and the measured identity is
 * appraised against an approved reference expressed as the SAME `AgentBinding` the agent is appraised
 * with (reused `matchAgentBinding`). With `attestation.require === true` an unattested judge, a judge
 * whose enclave measurement does not match its signed label, or one whose measured identity is not in the
 * approved reference is REJECTED — its vote does not count (fail-closed), exactly like an off-allowlist
 * key. Without the gate (the default) unattested verdicts still count, so existing flows are unchanged.
 * A key on the trusted allowlist remains the floor (trusted because an operator put it there); the
 * attestation gate ADDS silicon-rooted proof of which measured judge actually produced a verdict.
 *
 * GENUINELY EXTERNAL CAVEAT: that the attested enclave is in fact running the SPECIFIC model/weights the
 * measurement names is the measurement's OWN guarantee (e.g. weights covered by the SEV-SNP launch
 * measurement, see `hardware-sevsnp.ts`), not something this file re-proves — we bind to, and appraise, the measured
 * identity the TEE reports.
 */

// ---- domain separation ------------------------------------------------------------------------

/** Domain tag for a judge verdict signature (NUL-terminated, as elsewhere in PCA). */
export const SEMANTIC_JUDGE_DOMAIN = 'atlas-pca/semantic-judge/v1\0';

/**
 * Fixed-point scale for the judge score. The score is a real in [0,1], but a real would make the
 * SIGNED statement non-portable (the strict canonical form forbids exponents and magnitudes below
 * 1e-6). So the signed statement quantizes the score to parts-per-million (an integer in
 * [0, 1_000_000]); every language reproduces the same bytes, and scores below 1e-6 collapse to 0
 * rather than throwing. `score` on the wire object stays a convenience float; the verifier RE-DERIVES
 * the quantized value from it, so tampering with `score` breaks the signature.
 */
export const SCORE_SCALE = 1_000_000;

/** Quantize a [0,1] score to an integer in [0, SCORE_SCALE]. Clamps; non-finite => 0. */
export function quantizeScore(score: number): number {
  if (!Number.isFinite(score)) return 0;
  const q = Math.round(score * SCORE_SCALE);
  return q < 0 ? 0 : q > SCORE_SCALE ? SCORE_SCALE : q;
}

/**
 * The canonical statement a judge SIGNS. `score_ppm` is the quantized score (see {@link SCORE_SCALE}).
 * `actionDigest` / `goalCommitment` are b64u(32). `judgeMeasurement` is the judge-model identity label
 * (the enclave measurement when the ATTESTED-JUDGE gate binds it to a measured TEE — see the header).
 */
export interface JudgeStatement {
  v: 1;
  actionDigest: string;
  goalCommitment: string;
  faithful: boolean;
  score_ppm: number;
  judgeMeasurement: string;
  /** Signature suite — bound into the signed statement for a non-default suite; absent == ed25519 (byte-identical). */
  alg?: SigAlg;
  /** b64u ML-DSA-65 public key of the judge — ml-dsa-65 / hybrid (bound into the statement). */
  pq_pk?: string;
}

/**
 * A judge's SIGNED verdict about faithfulness-to-intent. `judge` is the b64u Ed25519 public key that
 * produced `sig`; `sig` signs {@link semanticJudgeMessage} over the statement derived from these
 * fields. `score` is the convenience [0,1] float — the signature binds its QUANTIZED value, so a
 * tampered `score` fails verification.
 */
export interface JudgeVerdict {
  /** b64u Ed25519 public key of the judge. */
  judge: string;
  /** b64u(32) digest of the action under judgment (see {@link actionDigest}). */
  actionDigest: string;
  /** b64u(32) commitment to the principal's goal/intent. */
  goalCommitment: string;
  /** the judge's call: is this action faithful to the committed goal? */
  faithful: boolean;
  /** the judge's confidence in [0,1] (bound via its quantized value — see {@link SCORE_SCALE}). */
  score: number;
  /** judge-model identity label (carried + signed; bound to a measured TEE by the attested-judge gate). */
  judgeMeasurement: string;
  /** b64u signature over {@link semanticJudgeMessage}(statement) (Ed25519 for ed25519/hybrid, ML-DSA-65 for pure). */
  sig: string;
  /** Signature suite (crypto-agility). Absent == ed25519 (byte-identical). */
  alg?: SigAlg;
  /** b64u ML-DSA-65 public key of the judge — ml-dsa-65 / hybrid (bound into the signed statement). */
  pq_pk?: string;
  /** b64u ML-DSA-65 verdict signature — hybrid only. */
  pq_sig?: string;
}

/** Reconstruct the canonical statement that a verdict's signature covers (suite fields bound for a non-default suite). */
export function statementOf(v: {
  actionDigest: string;
  goalCommitment: string;
  faithful: boolean;
  score: number;
  judgeMeasurement: string;
  alg?: SigAlg;
  pq_pk?: string;
}): JudgeStatement {
  const base: JudgeStatement = {
    v: 1,
    actionDigest: v.actionDigest,
    goalCommitment: v.goalCommitment,
    faithful: v.faithful === true,
    score_ppm: quantizeScore(v.score),
    judgeMeasurement: String(v.judgeMeasurement ?? ''),
  };
  return bindSuiteFields(base, v.alg, v.pq_pk);
}

/** The exact bytes a judge signs: DOMAIN || strictCanonical(statement). Domain-separated + bound. */
export function semanticJudgeMessage(statement: JudgeStatement): Uint8Array {
  const dom = utf8(SEMANTIC_JUDGE_DOMAIN);
  const body = canonicalBytesStrict(statement);
  const m = new Uint8Array(dom.length + body.length);
  m.set(dom);
  m.set(body, dom.length);
  return m;
}

/**
 * The canonical action digest a judge binds to. b64u(sha256(strictCanonical(action))): the SAME
 * action object carried in the PCActn (`pcactn.action`). Using the action (not the whole PCActn)
 * lets the ensemble be collected before the leaf signature exists.
 */
export function actionDigest(action: PCActn['action']): string {
  return hashCanonical(action);
}

/** Digest of a verdict for ledger-anchoring / challenge (strict canonical over the full verdict). */
export function verdictDigest(v: JudgeVerdict): string {
  return hashCanonical(v);
}

/**
 * Produce a signed verdict. The signer's public key is derived from `secretKey` and written as
 * `judge`, so the returned object verifies as-is.
 */
export function signJudgeVerdict(
  secretKey: Uint8Array,
  v: { actionDigest: string; goalCommitment: string; faithful: boolean; score: number; judgeMeasurement?: string },
  suite?: { alg?: SigAlg; mlDsa?: MlDsaKeyPair },
): JudgeVerdict {
  const judgeMeasurement = String(v.judgeMeasurement ?? '');
  const resolved = resolveSigAlg(suite?.alg);
  if (resolved === null) throw new Error(`signJudgeVerdict: unknown signature alg '${String(suite?.alg)}'`);
  const pqPk = suite?.mlDsa ? encodeMlDsaPublicKey(suite.mlDsa.publicKey) : undefined;
  const statement = statementOf({ ...v, judgeMeasurement, alg: resolved.alg === 'ed25519' ? undefined : resolved.alg, pq_pk: pqPk });
  const fields = signSuiteArtifact(suite?.alg, { edSecret: secretKey, mlDsa: suite?.mlDsa }, semanticJudgeMessage(statement));
  return {
    judge: b64u(publicKeyOf(secretKey)),
    actionDigest: v.actionDigest,
    goalCommitment: v.goalCommitment,
    faithful: v.faithful === true,
    score: v.score,
    judgeMeasurement,
    ...fields,
  };
}

/** Verify ONE verdict against an expected action/goal binding. TOTAL — never throws. */
export function verifyJudgeVerdict(
  v: JudgeVerdict,
  expected: { actionDigest: string; goalCommitment: string },
): boolean {
  if (!v || typeof v !== 'object') return false;
  if (typeof v.judge !== 'string' || decodeB64uStrict(v.judge, 32) === null) return false;
  if (typeof v.actionDigest !== 'string' || typeof v.goalCommitment !== 'string') return false;
  if (v.actionDigest !== expected.actionDigest || v.goalCommitment !== expected.goalCommitment) return false;
  if (typeof v.faithful !== 'boolean') return false;
  if (typeof v.score !== 'number' || !Number.isFinite(v.score) || v.score < 0 || v.score > 1) return false;
  if (typeof v.judgeMeasurement !== 'string') return false;
  if (typeof v.sig !== 'string') return false;
  if (resolveSigAlg(v.alg) === null) return false; // unknown suite => fail-closed
  const msg = semanticJudgeMessage(statementOf(v));
  // Suite-agile (ed25519 == verifyB64u(judge, msg, sig)); hybrid requires BOTH; pure ml-dsa under pq_pk.
  return verifyWithSuite(v.alg, { edPub: v.judge, mlDsaPub: v.pq_pk }, msg, { sig: v.sig, pq_sig: v.pq_sig });
}

// ---- attested-judge binding (bind judgeMeasurement to a measured TEE) -------------------------

/**
 * A verified TEE attestation for a JUDGE — the SAME `HardwareAttestationResult` a
 * `HardwareAttestationVerifier` (e.g. `createAmdSnpVerifier` in `attest-amd-snp.ts`) produces for the
 * AGENT. NOT a parallel type: `ok && bound === true` means the judge's enclave was rooted in silicon
 * (VCEK→ASK→ARK) and its report_data binding confirmed, and `measured` is the hardware-measured identity
 * whose `runtime_measurement` is the judge's real enclave measurement.
 */
export type JudgeAttestation = HardwareAttestationResult;

/** Outcome of binding a judge's signed measurement to a verified measured TEE. TOTAL — never throws. */
export interface JudgeAttestationCheck {
  /** true iff the attestation is verified+bound, its measurement matches the signed label, AND it satisfies `approved`. */
  ok: boolean;
  /** why `ok` is false (absent when ok). */
  reason?: string;
  /** the hardware-measured identity the signed `judgeMeasurement` was bound to (present iff ok). */
  measured?: MeasuredIdentity;
}

/**
 * Bind a judge's SIGNED `judgeMeasurement` to a REAL measured TEE, the way the agent is bound in
 * `attestation.ts` / `hardware-sevsnp.ts`. Fail-closed and total:
 *   1. the attestation must be VERIFIED + BOUND (`ok && bound === true`) — a hardware verifier rooted the
 *      judge's enclave in silicon and confirmed its report_data binding (a software-vouched or unbound
 *      result is rejected) — and it must carry a `measured` identity;
 *   2. the measured `runtime_measurement` (the enclave measurement) must EQUAL the signed
 *      `judgeMeasurement`, so the verdict's label is backed by silicon, not merely asserted;
 *   3. the measured identity is APPRAISED against `approved` — the SAME `AgentBinding` the agent is
 *      appraised with — via the reused {@link matchAgentBinding} (min_measurement / operator /
 *      weights_allowlist / require_measured_weights / …); any mismatch fails closed.
 * Reuses `MeasuredIdentity` + `matchAgentBinding` (no parallel types). A missing/undefined attestation
 * is a denial (required-but-absent).
 */
export function verifyJudgeAttestation(
  judgeMeasurement: string,
  attestation: HardwareAttestationResult | undefined,
  approved?: AgentBinding,
): JudgeAttestationCheck {
  if (!attestation || attestation.ok !== true) {
    return { ok: false, reason: attestation?.reason ?? 'no verified attestation for this judge (fail-closed)' };
  }
  if (attestation.bound !== true) {
    return { ok: false, reason: 'judge attestation not bound to a TEE report (report_data binding unconfirmed)' };
  }
  const measured = attestation.measured;
  if (!measured || typeof measured !== 'object') {
    return { ok: false, reason: 'judge attestation carries no measured identity' };
  }
  if (typeof judgeMeasurement !== 'string' || judgeMeasurement.length === 0) {
    return { ok: false, reason: 'verdict carries no judgeMeasurement to bind to the attested identity' };
  }
  if (measured.runtime_measurement !== judgeMeasurement) {
    return { ok: false, reason: 'attested enclave measurement does not match the signed judgeMeasurement' };
  }
  const appraisal = matchAgentBinding(measured, approved);
  if (appraisal) return { ok: false, reason: appraisal };
  return { ok: true, measured };
}

/**
 * The attested-judge gate for {@link verifySemanticThreshold}. When `require` is true each candidate
 * verdict must additionally pass {@link verifyJudgeAttestation} or its vote DOES NOT COUNT (fail-closed,
 * exactly like an off-allowlist key). When `require` is false (or this opt is absent) nothing changes —
 * unattested verdicts still count (backward-compatible).
 */
export interface SemanticAttestationOpts {
  /**
   * Resolve the verified TEE attestation for a judge verdict (key off `verdict.judge` / its measurement).
   * Returns the SAME `HardwareAttestationResult` a `HardwareAttestationVerifier` yields — a real SEV-SNP
   * result (`createAmdSnpVerifier` / `verifyGenuineSevSnpReport`) plugs straight in. undefined => this
   * judge has no verified attestation.
   */
  resolve: (verdict: JudgeVerdict) => HardwareAttestationResult | undefined;
  /**
   * The approved reference the judge's MEASURED identity must satisfy, expressed as the SAME
   * `AgentBinding` the agent is appraised with and matched via {@link matchAgentBinding}. Omitted => any
   * verified+bound measured judge whose enclave measurement matches its signed label.
   */
  approved?: AgentBinding;
  /**
   * REQUIRE an attested judge. `true` => a verdict whose judge has no verified+bound attestation, whose
   * attested enclave measurement differs from the signed `judgeMeasurement`, or whose measured identity
   * fails `approved`, is REJECTED (its vote does not count). Default/`false` => unattested judges still
   * count (backward-compatible).
   */
  require: boolean;
}

// ---- split-conformal calibration --------------------------------------------------------------

/** One labeled calibration example: an ensemble `aggregateScore` with its ground-truth label. */
export interface LabeledScore {
  /** the aggregateScore the ensemble produced (in [0,1]). */
  score: number;
  /** ground truth: was the action actually faithful to intent? */
  faithful: boolean;
}

/** The calibration layer: a labeled hold-out set + the target false-allow rate `alpha` in (0,1]. */
export interface Calibration {
  samples: readonly LabeledScore[];
  /** target upper bound on the false-allow rate (fraction of UNFAITHFUL actions that pass the gate). */
  alpha: number;
}

/**
 * SPLIT-CONFORMAL CUTOFF for the semantic gate.
 *
 * The "nonconformity" scores are the aggregateScores of the UNFAITHFUL calibration examples (an
 * unfaithful action that passes the gate is a FALSE ALLOW — the error we bound). The gate allows iff
 * `aggregateScore > cutoff`. We return the conformal upper quantile of the unfaithful scores:
 *
 *     m    = #unfaithful calibration scores
 *     rank = ceil((m + 1) * (1 - alpha))               (the standard split-conformal rank)
 *     cutoff = ascending(unfaithfulScores)[rank - 1]   (or +Infinity if rank > m / m == 0)
 *
 * GUARANTEE. With the allow rule `score > cutoff`:
 *   - EMPIRICAL: #{unfaithful_i > cutoff} / m <= alpha. (Proof: cutoff sits at ascending rank
 *     `rank >= (m+1)(1-alpha)`, so at most `m - rank <= (m+1)alpha - 1` unfaithful scores are
 *     strictly greater, and `((m+1)alpha - 1)/m <= alpha` for alpha <= 1.)
 *   - DISTRIBUTIONAL: for a fresh unfaithful example exchangeable with the calibration set,
 *     P(score > cutoff) <= alpha (the (m+1) finite-sample correction is exactly this rank).
 *
 * FAIL-CLOSED: with no unfaithful examples, or too few to certify `alpha` (rank > m), the cutoff is
 * +Infinity, so the score gate denies every action (the agreement count can still carry the day only
 * if no calibration is supplied at all). MONOTONE: non-increasing in `alpha` (a looser target allows
 * a lower cutoff). TOTAL — never throws; a non-finite / out-of-range alpha clamps into (0,1].
 */
export function conformalThreshold(calibration: Calibration): number {
  const alpha = clampAlpha(calibration?.alpha);
  const unfaithful: number[] = [];
  for (const s of Array.isArray(calibration?.samples) ? calibration.samples : []) {
    if (s && s.faithful === false && typeof s.score === 'number' && Number.isFinite(s.score)) unfaithful.push(s.score);
  }
  const m = unfaithful.length;
  if (m === 0) return Infinity;
  const rank = Math.ceil((m + 1) * (1 - alpha));
  if (rank > m) return Infinity; // not enough negatives to certify this alpha
  unfaithful.sort((a, b) => a - b);
  return unfaithful[rank - 1]!;
}

/** Empirical false-allow rate of a cutoff on a labeled set (fraction of unfaithful with score > cutoff). */
export function empiricalFalseAllowRate(samples: readonly LabeledScore[], cutoff: number): number {
  let m = 0;
  let allowed = 0;
  for (const s of Array.isArray(samples) ? samples : []) {
    if (s && s.faithful === false && typeof s.score === 'number' && Number.isFinite(s.score)) {
      m++;
      if (s.score > cutoff) allowed++;
    }
  }
  return m === 0 ? 0 : allowed / m;
}

function clampAlpha(alpha: unknown): number {
  if (typeof alpha !== 'number' || !Number.isFinite(alpha)) return 1;
  if (alpha <= 0) return Number.MIN_VALUE; // (0,1]; alpha=0 is unsatisfiable => smallest positive
  return alpha > 1 ? 1 : alpha;
}

// ---- k-of-n semantic threshold ----------------------------------------------------------------

export interface SemanticThresholdOpts {
  /** allowlist of trusted judge public keys (b64u Ed25519). Unknown keys are ignored (fail-closed). */
  judgeKeys: readonly string[];
  /** quorum: distinct trusted judges that must vote `faithful`. */
  k: number;
  /** the goal/intent commitment every verdict must be bound to. */
  goalCommitment: string;
  /** the action digest every verdict must be bound to. */
  actionDigest: string;
  /** optional conformal calibration gate on the aggregateScore. Omitted => agreement-only. */
  calibration?: Calibration;
  /**
   * Optional attested-judge gate (see {@link SemanticAttestationOpts}). With `require: true` only judges
   * bound to an approved measured TEE count; omitted/`require: false` => unattested judges count (unchanged).
   */
  attestation?: SemanticAttestationOpts;
}

export interface SemanticThresholdResult {
  /** overall decision: agreement quorum met AND (if calibrated) the score gate passed. */
  ok: boolean;
  /** distinct trusted judges that cast a clean `faithful` vote. */
  agreeCount: number;
  /** mean quantized score of the agreeing judges (in [0,1]); 0 if none agree. Deterministic. */
  aggregateScore: number;
  /** the conformal cutoff applied (present iff `calibration` was supplied). */
  cutoff?: number;
  /** why `ok` is false (absent when ok). */
  reason?: string;
}

/**
 * Verify a k-of-n ensemble of signed judge verdicts and (optionally) gate the aggregate through the
 * conformal cutoff.
 *
 * ONE-KEY-ONE-VOTE / DISTINCT-KEY, fail-closed. Verdicts are grouped by judge key; a judge casts a
 * CLEAN faithful vote iff it is on the allowlist AND every one of its valid, correctly-bound verdicts
 * agrees (all `faithful === true` and all the SAME quantized score). A judge whose verdicts
 * contradict each other (mixed `faithful`, or different scores) is a CONFLICT and is dropped — it
 * counts neither toward agreement nor the aggregate. Unknown/untrusted keys, mis-bound verdicts
 * (wrong actionDigest/goalCommitment), and bad signatures never count.
 *
 * `aggregateScore` = mean of the (quantized, de-duplicated) scores of the cleanly-agreeing judges,
 * ordered by key so the sum is deterministic. `ok` requires `agreeCount >= k` AND, when a
 * calibration is supplied, `aggregateScore > conformalThreshold(calibration)`.
 */
export function verifySemanticThreshold(
  verdicts: readonly JudgeVerdict[],
  opts: SemanticThresholdOpts,
): SemanticThresholdResult {
  const k = opts?.k;
  const allow = new Set<string>();
  for (const key of Array.isArray(opts?.judgeKeys) ? opts.judgeKeys : []) {
    if (typeof key === 'string' && decodeB64uStrict(key, 32) !== null) allow.add(key);
  }
  if (typeof opts?.actionDigest !== 'string' || typeof opts?.goalCommitment !== 'string') {
    return { ok: false, agreeCount: 0, aggregateScore: 0, reason: 'missing action/goal binding' };
  }
  if (typeof k !== 'number' || !Number.isInteger(k) || k < 1) {
    return { ok: false, agreeCount: 0, aggregateScore: 0, reason: `invalid quorum k=${String(k)}` };
  }

  // Group VALID, correctly-bound, trusted verdicts by judge key. When the attested-judge gate is
  // REQUIRED, a verdict whose judge is not bound to an approved measured TEE is dropped (fail-closed).
  const att = opts.attestation;
  const byJudge = new Map<string, { faithful: Set<boolean>; scoreQ: Set<number> }>();
  for (const v of Array.isArray(verdicts) ? verdicts : []) {
    if (!v || typeof v.judge !== 'string' || !allow.has(v.judge)) continue; // unknown/untrusted
    if (!verifyJudgeVerdict(v, { actionDigest: opts.actionDigest, goalCommitment: opts.goalCommitment })) continue;
    if (att && att.require === true && !verifyJudgeAttestation(v.judgeMeasurement, att.resolve(v), att.approved).ok) {
      continue; // unattested / wrong-measurement / unapproved judge: vote does not count
    }
    let g = byJudge.get(v.judge);
    if (!g) {
      g = { faithful: new Set(), scoreQ: new Set() };
      byJudge.set(v.judge, g);
    }
    g.faithful.add(v.faithful === true);
    g.scoreQ.add(quantizeScore(v.score));
  }

  // A clean agreeing judge: unanimous `faithful === true` and a single score. Sorted keys => determinism.
  const agreeing: Array<{ judge: string; scoreQ: number }> = [];
  for (const [judge, g] of byJudge) {
    if (g.faithful.size === 1 && g.faithful.has(true) && g.scoreQ.size === 1) {
      agreeing.push({ judge, scoreQ: [...g.scoreQ][0]! });
    }
  }
  agreeing.sort((a, b) => compareUtf8(a.judge, b.judge));

  const agreeCount = agreeing.length;
  const aggregateScore =
    agreeCount === 0 ? 0 : agreeing.reduce((acc, a) => acc + a.scoreQ / SCORE_SCALE, 0) / agreeCount;

  if (agreeCount < k) {
    return { ok: false, agreeCount, aggregateScore, reason: `only ${agreeCount} distinct trusted judge(s) agree, need ${k}` };
  }
  if (opts.calibration) {
    const cutoff = conformalThreshold(opts.calibration);
    if (!(aggregateScore > cutoff)) {
      return { ok: false, agreeCount, aggregateScore, cutoff, reason: `aggregateScore ${aggregateScore} does not exceed calibrated cutoff ${cutoff}` };
    }
    return { ok: true, agreeCount, aggregateScore, cutoff };
  }
  return { ok: true, agreeCount, aggregateScore };
}

// ---- hook (pcactn.ts shape) -------------------------------------------------------------------

export interface SemanticVerifierOpts {
  /** allowlist of trusted judge public keys (b64u Ed25519). */
  judgeKeys: readonly string[];
  /** quorum: distinct trusted judges that must agree. */
  k: number;
  /** optional conformal calibration gate. */
  calibration?: Calibration;
  /** where to find the ensemble's verdicts for a given action (they are NOT on the core PCActn wire). */
  verdicts: (ctx: VerifyContext) => readonly JudgeVerdict[] | undefined;
  /** how to recover the principal's goal commitment for this action (grant/side-channel). */
  goalCommitment: (ctx: VerifyContext) => string | undefined;
  /** override the action digest the verdicts must bind to (default: {@link actionDigest}(pcactn.action)). */
  actionDigest?: (ctx: VerifyContext) => string;
  /**
   * When the goal commitment or the verdicts cannot be resolved: `true` reports the check as
   * NOT-ENFORCED (semantic judgment simply does not apply to this action); the DEFAULT (`false`) is
   * FAIL-CLOSED — a missing ensemble is a denial, mirroring the rest of PCA.
   */
  optionalWhenAbsent?: boolean;
  /**
   * Optional attested-judge gate, resolved per action (see {@link SemanticAttestationOpts}). Supply it to
   * REQUIRE the verdicts come from judges bound to an approved measured TEE. Omitted => no attestation
   * gate (unattested judges count, unchanged).
   */
  attestation?: (ctx: VerifyContext) => SemanticAttestationOpts | undefined;
}

/**
 * A SemanticVerifier HOOK, shaped like the `attestation` / `threshold` / `revocation` hooks in
 * pcactn.ts (`(ctx) => HookResult`), so it can later be passed as an extra verifier to
 * `verifyPCActnCore`. NOT wired into the core verifier this wave (the core `VerifyHooks` set is owned
 * elsewhere); this makes the primitive hook-compatible and ready to plug in.
 *
 * RISK-FUNCTIONAL FEED (spec §10 / Deep-Dive-III). As a hard GATE the hook denies on a failed
 * semantic threshold (what this returns). As a SOFT input it mirrors `caution`: a verifier may raise
 * `r := max(r, 1 - aggregateScore)` so weaker semantic agreement monotonically RAISES risk (and thus
 * the cryptographic threshold `t`) without ever lowering it — see {@link semanticRiskContribution}.
 */
export function createSemanticVerifier(opts: SemanticVerifierOpts): Hook {
  const digestOf = opts.actionDigest ?? ((ctx: VerifyContext) => actionDigest(ctx.pcactn.action));
  return (ctx: VerifyContext): HookResult => {
    const goalCommitment = opts.goalCommitment(ctx);
    const verdicts = opts.verdicts(ctx);
    if (typeof goalCommitment !== 'string' || verdicts === undefined) {
      if (opts.optionalWhenAbsent) return { enforced: false };
      return { enforced: true, ok: false, reason: 'no semantic ensemble available for this action (fail-closed)' };
    }
    const attestation = opts.attestation?.(ctx);
    const res = verifySemanticThreshold(verdicts, {
      judgeKeys: opts.judgeKeys,
      k: opts.k,
      goalCommitment,
      actionDigest: digestOf(ctx),
      calibration: opts.calibration,
      ...(attestation ? { attestation } : {}),
    });
    return res.ok ? { enforced: true, ok: true } : { enforced: true, ok: false, reason: res.reason ?? 'semantic threshold not met' };
  };
}

/**
 * Soft risk contribution (Deep-Dive-III): `1 - aggregateScore`, clamped to [0,1]. A verifier folds it
 * into `r` MONOTONICALLY (`r := max(r, this)`), exactly like `pcactn.caution` — weaker semantic
 * agreement can only RAISE risk, never lower it.
 */
export function semanticRiskContribution(aggregateScore: number): number {
  if (!Number.isFinite(aggregateScore)) return 1;
  const r = 1 - aggregateScore;
  return r < 0 ? 0 : r > 1 ? 1 : r;
}
