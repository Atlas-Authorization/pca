/**
 * §9A — Optimistic authorization with fraud proofs (latency accelerant).
 *
 * Borrowing optimistic-rollup mechanics for authorization: for a REVERSIBLE action the agent may act
 * immediately on a cheap SIGNED CLAIM of compliance, posting a bond. A CHALLENGE WINDOW lets the
 * Guardian/Principal submit a FRAUD PROOF that the claim was out-of-policy → the bond is slashed and
 * the reversible effect is rolled back. IRREVERSIBLE actions never go optimistic (spec §9A / §8.5):
 * they take the full threshold path.
 *
 * SCOPE / SEAM. This module is the PURE claim + challenge + fraud logic:
 *   - `openOptimistic` / `verifyClaim`   — mint and check the signed compliance claim.
 *   - `fileFraudProof` / `verifyFraudProof` — construct and independently re-verify a fraud proof,
 *     by RE-RUNNING the Policy VM (`decide`) on the real inputs and showing it contradicts the claim.
 *   - `withinChallengeWindow` / `claimStatus` — the challenge-window timing.
 * The economic bond itself — escrow, slashing, roll-back of effects, the ledger of settled claims —
 * is a SERVER / LEDGER concern and is NOT implemented here. `bond_ref` / `slashBondRef` are opaque
 * handles the settlement layer resolves. A fraud proof here yields the VERDICT (and which bond to
 * slash); acting on it is the ledger's job.
 */
// The optimistic claim is a server-side fast-path construct (carries claimed_r),
// never recomputed by the language verifiers — lenient canonical, not strict protocol.
import { b64u, canonicalBytesLenient as canonicalBytes, utf8 } from './hash';
import { sign, verifyB64u } from './keys';
import type { Capability } from './capability';
import { type PCActn, pcactnDigest } from './pcactn';
import { type DecideInput, type PolicyDecision, decide } from './policy-vm';

const DOMAIN = 'atlas-pca/optimistic/v1\0';

/** A reversibility class that is NEVER eligible for the optimistic fast-path. */
export const IRREVERSIBLE_CLASS = 'irreversible';

/** A signed, bonded claim of compliance for the optimistic fast-path. */
export interface BondedClaim {
  /** `pcactnDigest` of the action this claim covers. */
  pcactn_digest: string;
  /** Opaque handle to the posted bond (resolved by the settlement layer). */
  bond_ref: string;
  /** The risk `r` the agent CLAIMS for the action (checked against the real `r` by a fraud proof). */
  claimed_r: number;
  /** The action's reversibility class (must not be `irreversible`). */
  reversibility_class: string;
  /** Issued-at (epoch ms). */
  issued_at: number;
  /** How long (ms) challenges are accepted after `issued_at`. */
  challenge_window_ms: number;
  /** b64u Ed25519 signature by the agent-leaf key over the canonical body. */
  sig: string;
}

export type BondedClaimBody = Omit<BondedClaim, 'sig'>;

function claimMessage(body: BondedClaimBody): Uint8Array {
  const d = canonicalBytes(body);
  const p = utf8(DOMAIN);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}

/**
 * Server-authoritative challenge-window policy (audit finding 2 / P3-2). The window and its start are
 * a SERVER decision, never an agent-signed one: `issued_at` must sit within `maxSkewMs` of server time
 * and `challenge_window_ms` within [`minWindowMs`, `maxWindowMs`], so `window: 0` and backdating are
 * impossible.
 */
export interface ChallengeWindowPolicy {
  minWindowMs: number;
  maxWindowMs: number;
  defaultWindowMs: number;
  /** Max |claim.issued_at - serverNow| tolerated. */
  maxSkewMs: number;
}

/**
 * The REALISTIC minimum challenge window (ms) the server-authoritative {@link resolveWindow} will ever
 * derive. A sub-floor (or zero) requested window is clamped UP to this value, so a provisional optimistic
 * effect can never finalize — releasing its bond — before a human or watchtower has a realistic chance to
 * observe it and file a fraud proof.
 *
 * HARDENING (audit P3-2 follow-up). The previous floor was 1s: `resolveWindow` would clamp an agent's
 * requested window up to only 1 second, which finalizes faster than any out-of-band challenger can react.
 * 30s is the realistic lower bound on human/watchtower reaction for a reversible optimistic action.
 *
 * Why this is a SEPARATE constant and not simply `DEFAULT_WINDOW_POLICY.minWindowMs`: `minWindowMs` is the
 * HARD-REJECT absolute floor applied by {@link validateWindow} to a DIRECTLY supplied window, and is kept
 * low for backward compatibility with already-minted claims. The realistic floor is enforced on the
 * server-authoritative DERIVATION path ({@link resolveWindow}) — the path by which the server actually
 * mints a window for a new claim — so a freshly derived window is always >= 30s regardless of what the
 * agent requested, while the hard-reject floor does not change the signed-byte format of any existing claim.
 */
export const DEFAULT_MIN_CHALLENGE_WINDOW_MS = 30_000;

export const DEFAULT_WINDOW_POLICY: ChallengeWindowPolicy = {
  // Hard-reject absolute floor for a DIRECTLY supplied window (validateWindow). Kept low for backward
  // compatibility with existing direct-window claims; the server-authoritative derivation path
  // (resolveWindow) additionally enforces the realistic DEFAULT_MIN_CHALLENGE_WINDOW_MS (30s) floor.
  minWindowMs: 1_000,
  maxWindowMs: 24 * 60 * 60 * 1_000,
  defaultWindowMs: 5 * 60 * 1_000,
  maxSkewMs: 5_000,
};

/**
 * Derive the authoritative window for a new claim: `issued_at = serverNow`, window = `requestedMs`
 * clamped into the policy bounds (or the policy default when not requested). Server-authoritative: a
 * sub-floor request is CLAMPED UP — never below the realistic {@link DEFAULT_MIN_CHALLENGE_WINDOW_MS}
 * (30s) floor nor the policy minimum, and never above the policy maximum.
 */
export function resolveWindow(
  policy: ChallengeWindowPolicy,
  serverNow: number,
  requestedMs?: number,
): { issued_at: number; challenge_window_ms: number } {
  if (!Number.isFinite(serverNow)) throw new Error('resolveWindow: serverNow must be finite');
  const want = Number.isFinite(requestedMs) ? (requestedMs as number) : policy.defaultWindowMs;
  // The realistic floor (30s) is a HARD minimum no policy can dip below via the derivation path; the
  // maximum still caps the result (a policy with maxWindowMs < floor yields maxWindowMs).
  const floor = Math.max(policy.minWindowMs, DEFAULT_MIN_CHALLENGE_WINDOW_MS);
  const challenge_window_ms = Math.min(policy.maxWindowMs, Math.max(floor, want));
  return { issued_at: serverNow, challenge_window_ms };
}

/** Validate a claim's (issued_at, window) against server time + policy. Returns a reason or null. */
export function validateWindow(
  issuedAt: number,
  windowMs: number,
  serverNow: number,
  policy: ChallengeWindowPolicy = DEFAULT_WINDOW_POLICY,
): string | null {
  if (!Number.isFinite(serverNow)) return 'server time is not finite';
  if (!Number.isFinite(issuedAt) || !Number.isFinite(windowMs)) return 'malformed challenge window';
  if (Math.abs(issuedAt - serverNow) > policy.maxSkewMs) return 'issued_at is outside the allowed skew of server time';
  if (windowMs < policy.minWindowMs) return 'challenge window is below the minimum';
  if (windowMs > policy.maxWindowMs) return 'challenge window exceeds the maximum';
  return null;
}

export interface OpenOptimisticOpts {
  bondRef: string;
  claimedR: number;
  /** Requested window (ms); default = policy default. Must be within policy bounds (else throws). */
  challengeWindowMs?: number;
  /** Agent-supplied issued-at; default = `serverNow`. Must be within the policy skew of `serverNow`. */
  issuedAt?: number;
  /** Authoritative server time (epoch ms). Default `Date.now()`; pass explicitly for determinism. */
  serverNow?: number;
  /** Window policy. Default `DEFAULT_WINDOW_POLICY`. */
  windowPolicy?: ChallengeWindowPolicy;
}

/**
 * Open an optimistic claim for `pcactn`, signed by the agent-leaf `signerSecret`. REFUSES (throws)
 * when the action is irreversible — irreversible actions must take the full threshold path.
 */
export function openOptimistic(pcactn: PCActn, opts: OpenOptimisticOpts, signerSecret: Uint8Array): BondedClaim {
  const rc = pcactn?.action?.reversibility_class;
  if (rc === IRREVERSIBLE_CLASS) {
    throw new Error('openOptimistic: irreversible actions cannot use the optimistic fast-path (§9A)');
  }
  if (!Number.isFinite(opts.claimedR)) throw new Error('openOptimistic: claimedR must be finite');
  const policy = opts.windowPolicy ?? DEFAULT_WINDOW_POLICY;
  const serverNow = Number.isFinite(opts.serverNow) ? (opts.serverNow as number) : Date.now();
  const issuedAt = Number.isFinite(opts.issuedAt) ? (opts.issuedAt as number) : serverNow;
  const windowMs = opts.challengeWindowMs === undefined ? policy.defaultWindowMs : opts.challengeWindowMs;
  const bad = validateWindow(issuedAt, windowMs, serverNow, policy);
  if (bad) throw new Error(`openOptimistic: ${bad}`);
  const body: BondedClaimBody = {
    pcactn_digest: pcactnDigest(pcactn),
    bond_ref: opts.bondRef,
    claimed_r: opts.claimedR,
    reversibility_class: typeof rc === 'string' ? rc : 'unknown',
    issued_at: issuedAt,
    challenge_window_ms: windowMs,
  };
  return { ...body, sig: b64u(sign(signerSecret, claimMessage(body))) };
}

export interface ClaimVerdict {
  ok: boolean;
  reason?: string;
}

/**
 * Verify a bonded claim: the signature verifies under `signerPublic`, the claim covers THIS pcactn,
 * and the action is not irreversible. Does NOT judge policy compliance — that is a fraud proof's job
 * (an unchallenged valid claim finalizes when its window closes). Total; never throws.
 */
export function verifyClaim(
  claim: BondedClaim,
  pcactn: PCActn,
  signerPublic: string,
  opts: { serverNow?: number; windowPolicy?: ChallengeWindowPolicy } = {},
): ClaimVerdict {
  try {
    if (!claim || typeof claim !== 'object') return { ok: false, reason: 'malformed claim' };
    if (claim.reversibility_class === IRREVERSIBLE_CLASS) {
      return { ok: false, reason: 'irreversible action is ineligible for the optimistic path' };
    }
    if (claim.pcactn_digest !== pcactnDigest(pcactn)) {
      return { ok: false, reason: 'claim does not cover this PCActn' };
    }
    if (!Number.isFinite(claim.claimed_r)) return { ok: false, reason: 'claimed_r is not finite' };
    // The window is server-authoritative: reject backdating / out-of-skew issued_at and a window below
    // the minimum (window:0). Pass the OPEN-time `serverNow` when re-verifying a stored claim later.
    const serverNow = Number.isFinite(opts.serverNow) ? (opts.serverNow as number) : Date.now();
    const bad = validateWindow(claim.issued_at, claim.challenge_window_ms, serverNow, opts.windowPolicy ?? DEFAULT_WINDOW_POLICY);
    if (bad) return { ok: false, reason: bad };
    const { sig, ...body } = claim;
    if (typeof sig !== 'string' || !verifyB64u(signerPublic, claimMessage(body), sig)) {
      return { ok: false, reason: 'claim signature does not verify' };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `claim verification error: ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

// ---- challenge window --------------------------------------------------------------------

export type ClaimPhase = 'open' | 'finalized';

/** Epoch-ms at which the challenge window closes (inclusive end is `issued_at + window`). */
export function challengeWindowEnd(claim: BondedClaim): number {
  return claim.issued_at + claim.challenge_window_ms;
}

/** True while challenges are still accepted: `now <= issued_at + challenge_window_ms`. */
export function withinChallengeWindow(claim: BondedClaim, now: number): boolean {
  if (!Number.isFinite(now)) return false;
  return now <= challengeWindowEnd(claim);
}

/** `open` while challenges are accepted, else `finalized` (bond releasable, no longer challengeable). */
export function claimStatus(claim: BondedClaim, now: number): ClaimPhase {
  return withinChallengeWindow(claim, now) ? 'open' : 'finalized';
}

// ---- fraud proofs ------------------------------------------------------------------------

export type FraudKind =
  | 'policy-denied' // the Policy VM denies the action outright
  | 'risk-understated' // actual r materially exceeds the claimed_r
  | 'optimistic-not-allowed' // at the real risk, the optimistic path is not permitted
  | 'irreversible'; // the action is irreversible and never eligible

/** A summary of the decision a fraud proof carries, re-derived and re-checked by the verifier. */
export interface DecisionSummary {
  releaseGuardianShare: boolean;
  r: number;
  optimisticAllowed: boolean;
}

/**
 * A fraud proof: evidence that a bonded claim was false. It carries the Policy VM inputs (minus the
 * grant, which `verifyFraudProof` supplies) so the verifier can RE-RUN `decide` and independently
 * confirm the contradiction — the proof is only convincing because it is recomputable, not because
 * the challenger asserts it.
 */
export interface FraudProof {
  /** Must equal the claim's `pcactn_digest` — the proof targets exactly the claimed action. */
  pcactn_digest: string;
  /** The bond the proof asks to slash. */
  bond_ref: string;
  /** The risk the claim asserted (copied from the claim it refutes). */
  claimed_r: number;
  kind: FraudKind;
  /** The decision the challenger says the VM really yields (re-derived and re-checked on verify). */
  decision: DecisionSummary;
  /**
   * Informational ONLY (copy of the open-time snapshot, minus grant). `verifyFraudProof` NEVER replays
   * this — it replays the server-held frozen open-time snapshot, so challenger-supplied evidence
   * cannot influence the verdict.
   */
  evidence: Omit<DecideInput, 'grant'>;
  /** Tolerance: actual r must exceed claimed_r by at least this to count as understated (default used by filer). */
  r_margin: number;
  reason: string;
}

const DEFAULT_R_MARGIN = 1e-9;

/**
 * File a fraud proof against `claim` for `pcactn`, given the grant and the AUTHORITATIVE decision
 * (`actualDecision`, from running `decide` on the real inputs). Returns a `FraudProof` if the claim
 * was false, else `null` (a compliant claim has no fraud proof). The caller passes the SAME
 * `decideInput` it ran through `decide` as `evidence` (its grant is stripped — the verifier re-adds
 * the grant it independently trusts).
 *
 * A claim is fraudulent when ANY of:
 *   - the action is irreversible (never eligible);
 *   - the Policy VM denies (no guardian-share release);
 *   - at the real risk the optimistic path is not allowed (e.g. r crossed θ1, or the real action is
 *     irreversible per policy);
 *   - the real r materially exceeds the claimed_r (risk understated to dodge step-up).
 */
export function fileFraudProof(args: {
  claim: BondedClaim;
  pcactn: PCActn;
  grant: Capability;
  /** Ignored for the verdict: re-derived by replaying `decide` on `openSnapshot` (finding 8 / P3-3). */
  actualDecision?: PolicyDecision;
  /** FROZEN open-time `DecideInput` (now + budget snapshot captured when the claim opened). */
  openSnapshot?: DecideInput;
  /** @deprecated alias of `openSnapshot`; must be the open-time snapshot, not current inputs. */
  decideInput?: DecideInput;
  rMargin?: number;
}): FraudProof | null {
  const { claim, pcactn } = args;
  const decideInput = args.openSnapshot ?? args.decideInput;
  if (!decideInput) return null;
  // Replay against the frozen open-time inputs under the supplied grant: never trust a caller decision.
  const actualDecision = decide({ ...decideInput, grant: args.grant });
  if (claim.pcactn_digest !== pcactnDigest(pcactn)) return null; // cannot frame a different action
  const margin = Number.isFinite(args.rMargin) ? Math.max(0, args.rMargin as number) : DEFAULT_R_MARGIN;

  const decision: DecisionSummary = {
    releaseGuardianShare: actualDecision.releaseGuardianShare,
    r: actualDecision.r,
    optimisticAllowed: actualDecision.requiredThreshold.optimisticAllowed,
  };
  const { grant: _g, ...evidence } = decideInput;
  void _g;

  const base = {
    pcactn_digest: claim.pcactn_digest,
    bond_ref: claim.bond_ref,
    claimed_r: claim.claimed_r,
    decision,
    evidence,
    r_margin: margin,
  };

  let kind: FraudKind | null = null;
  let reason = '';
  if (claim.reversibility_class === IRREVERSIBLE_CLASS || pcactn.action?.reversibility_class === IRREVERSIBLE_CLASS) {
    kind = 'irreversible';
    reason = 'irreversible action took the optimistic path';
  } else if (!actualDecision.releaseGuardianShare) {
    kind = 'policy-denied';
    reason = `Policy VM denied the action: ${actualDecision.reasons.join('; ') || 'not compliant'}`;
  } else if (!actualDecision.requiredThreshold.optimisticAllowed) {
    kind = 'optimistic-not-allowed';
    reason = `optimistic path not allowed at real r=${actualDecision.r.toFixed(3)} (t=${actualDecision.requiredThreshold.t})`;
  } else if (actualDecision.r > claim.claimed_r + margin) {
    kind = 'risk-understated';
    reason = `claimed r=${claim.claimed_r} but real r=${actualDecision.r.toFixed(3)}`;
  }

  if (kind === null) return null;
  return { ...base, kind, reason };
}

export interface FraudVerdict {
  fraudulent: boolean;
  slashBondRef?: string;
  reason: string;
}

/**
 * Independently verify a fraud proof. RE-RUNS the Policy VM on the proof's evidence under the GRANT
 * THE VERIFIER TRUSTS (not one carried in the proof), confirms the recomputed decision matches the
 * decision the proof asserts, and confirms it genuinely contradicts the claim. Returns `fraudulent`
 * with the bond to slash, or a non-fraud verdict (the bond stands). Total; never throws.
 */
export function verifyFraudProof(
  claim: BondedClaim,
  proof: FraudProof,
  grant: Capability,
  openSnapshot: DecideInput,
): FraudVerdict {
  try {
    if (!proof || typeof proof !== 'object') return { fraudulent: false, reason: 'malformed fraud proof' };
    if (proof.pcactn_digest !== claim.pcactn_digest) {
      return { fraudulent: false, reason: 'fraud proof targets a different PCActn than the claim' };
    }
    if (proof.bond_ref !== claim.bond_ref) {
      return { fraudulent: false, reason: 'fraud proof names a different bond than the claim' };
    }

    if (!openSnapshot || typeof openSnapshot !== 'object') {
      return { fraudulent: false, reason: 'no frozen open-time snapshot supplied; cannot judge the claim' };
    }
    // Replay at the claim's OWN open-time inputs (frozen now + budget snapshot) under the verifier's
    // grant — never the proof's evidence, never current inputs. Drift can neither false-slash an honest
    // claim nor suppress a real overrun.
    // SERVER WAVE (done): the snapshot IS persisted server-side at open keyed by bond_ref and digest-bound.
    // The hosting layer freezes this DecideInput (grant stripped) with a canonical snapshot digest; the
    // challenge path re-verifies that digest before replaying, so adjudication runs against the exact
    // admitted snapshot, never a caller-supplied one.
    const recomputed = decide({ ...openSnapshot, grant });
    const summary: DecisionSummary = {
      releaseGuardianShare: recomputed.releaseGuardianShare,
      r: recomputed.r,
      optimisticAllowed: recomputed.requiredThreshold.optimisticAllowed,
    };
    // The challenger's asserted decision must match the recomputation (no fabricated decision).
    if (
      summary.releaseGuardianShare !== proof.decision.releaseGuardianShare ||
      summary.optimisticAllowed !== proof.decision.optimisticAllowed ||
      Math.abs(summary.r - proof.decision.r) > 1e-9
    ) {
      return { fraudulent: false, reason: 'proof decision does not match an independent recomputation' };
    }

    const margin = Number.isFinite(proof.r_margin) ? Math.max(0, proof.r_margin) : DEFAULT_R_MARGIN;
    const irreversible =
      claim.reversibility_class === IRREVERSIBLE_CLASS || openSnapshot.action?.action?.reversibility_class === IRREVERSIBLE_CLASS;

    // Confirm the recomputed decision genuinely refutes the claim.
    if (irreversible) {
      return { fraudulent: true, slashBondRef: claim.bond_ref, reason: 'irreversible action is ineligible for the optimistic path' };
    }
    if (!summary.releaseGuardianShare) {
      return { fraudulent: true, slashBondRef: claim.bond_ref, reason: `Policy VM denies the action: ${recomputed.reasons.join('; ') || 'not compliant'}` };
    }
    if (!summary.optimisticAllowed) {
      return { fraudulent: true, slashBondRef: claim.bond_ref, reason: `optimistic path not allowed at real r=${summary.r.toFixed(3)}` };
    }
    if (summary.r > claim.claimed_r + margin) {
      return { fraudulent: true, slashBondRef: claim.bond_ref, reason: `risk understated: claimed ${claim.claimed_r}, real ${summary.r.toFixed(3)}` };
    }

    return { fraudulent: false, reason: 'claim is compliant under independent recomputation; bond stands' };
  } catch (e) {
    return { fraudulent: false, reason: `fraud-proof verification error: ${e instanceof Error ? e.message : 'unknown'}` };
  }
}


// ---- contestable dispute game (optimistic bisection over a lied-about risk input) --------
//
// WHY THIS EXISTS. `fileFraudProof` / `verifyFraudProof` above REPLAY the FROZEN open-time snapshot
// unchanged, so `decide` returns the SAME verdict the fast-path admitted under — which means the only
// fraud they can ever catch is one whose evidence lives OUTSIDE the snapshot (a capability revoked after
// open). An agent that UNDERSTATED a risk input it supplied — declared `reversible` for a
// catalog-irreversible verb, or a blast radius / semantic distance lower than the truth — has baked the
// lie INTO the frozen inputs, so a straight replay re-admits it and the lie is uncontestable.
//
// THE FIX (optimistic-rollup bisection). A dispute narrows the argument to ONE contested input and resolves
// it with an OBJECTIVE ORACLE — a server-authoritative source (committed facts / a verb catalog) that does
// NOT trust the agent OR the challenger. The challenger only names WHICH input it says was understated; the
// oracle supplies the truthful value, that value is substituted into the frozen snapshot, and the action is
// RE-ADJUDICATED. If the fast-path admission would NOT survive under the truthful value, the claim is
// fraudulent → slash. If the oracle UPHOLDS the agent's value (admission survives), the dispute was
// frivolous → the challenger's counter-bond is slashed (anti-griefing). The honest-claim protection is
// intact: the oracle, never the challenger's say-so, decides, and an oracle that cannot authoritatively
// resolve the input fails CLOSED to `indeterminate` (neither side is slashed).

/** The agent-supplied Policy-VM inputs a dispute can contest (the bisection targets). */
export type DisputableInput = 'reversibility_class' | 'reversibility' | 'blastRadius' | 'semanticDistance';

/**
 * An objective oracle's AUTHORITATIVE resolution of ONE disputed input. `valid: false` means the oracle
 * could not authoritatively resolve it (fail closed — the dispute is indeterminate and slashes no one).
 * A `reversibility_class` dispute resolves a `class`; the three numeric inputs resolve a `value` in [0,1].
 */
export interface OracleResolution {
  input: DisputableInput;
  /** server-authoritative value for a numeric input (reversibility / blastRadius / semanticDistance) */
  value?: number;
  /** server-authoritative reversibility class (for a `reversibility_class` dispute) */
  class?: string;
  /** true iff the oracle could AUTHORITATIVELY resolve this input (fail-closed oracles return false) */
  valid: boolean;
  reason?: string;
}

/**
 * Resolves the TRUTHFUL value of a disputed input from server-authoritative facts (a committed registry /
 * resource graph, or a verb catalog) — NEVER from the agent's claim or the challenger's assertion. Total:
 * it reports `valid: false` rather than throwing when it cannot resolve.
 */
export interface ObjectiveOracle {
  resolve(input: DisputableInput, snapshot: DecideInput): OracleResolution;
}

/**
 * A challenger's dispute: it names ONE input it asserts the agent UNDERSTATED. The asserted value/class is
 * a TRIGGER and audit metadata ONLY — it is never substituted; the ORACLE supplies the value that decides.
 */
export interface DisputeClaim {
  /** Must equal the claim's `pcactn_digest`. */
  pcactn_digest: string;
  /** Must equal the claim's `bond_ref`. */
  bond_ref: string;
  /** Which agent-supplied input the challenger says was understated. */
  input: DisputableInput;
  /** Informational trigger only (the challenger's asserted truthful value for a numeric input). */
  asserted_value?: number;
  /** Informational trigger only (the challenger's asserted truthful class). */
  asserted_class?: string;
}

export type DisputeOutcome =
  | 'agent-fraud' // the oracle's truthful value refutes the fast-path admission → slash the agent's bond
  | 'claim-upheld' // the oracle upholds the agent → slash the challenger's counter-bond (anti-grief)
  | 'indeterminate'; // the oracle could not resolve (fail closed) → slash neither side

/** The result of re-adjudicating a dispute with the oracle's value substituted for the disputed input. */
export interface DisputeVerdict {
  outcome: DisputeOutcome;
  /** true iff `agent-fraud`: the AGENT's bond is slashed (the challenger is rewarded via the split). */
  fraudulent: boolean;
  /** The agent bond to slash (set only on `agent-fraud`). */
  slashBondRef?: string;
  /** true iff `claim-upheld`: the CHALLENGER's counter-bond is slashed (anti-griefing). */
  slashCounterBond: boolean;
  input: DisputableInput;
  /** The value the frozen snapshot carried for the disputed input (what the agent effectively relied on). */
  agentValue: number | string | undefined;
  /** The oracle's authoritative value, substituted in to re-adjudicate. */
  oracleValue: number | string | undefined;
  /** `decide` on the frozen snapshot UNCHANGED (the fast-path verdict). */
  baseline: DecisionSummary;
  /** `decide` with the oracle value substituted for the disputed input. */
  adjudicated: DecisionSummary;
  reason: string;
}

function summarizeDecision(d: PolicyDecision): DecisionSummary {
  return { releaseGuardianShare: d.releaseGuardianShare, r: d.r, optimisticAllowed: d.requiredThreshold.optimisticAllowed };
}

/** The fast-path admission predicate: the guardian released, optimistic acceptance is allowed (t=1, reversible), and r did not exceed the claimed r. */
function fastPathAdmits(s: DecisionSummary, claimedR: number, margin: number): boolean {
  return s.releaseGuardianShare && s.optimisticAllowed && s.r <= claimedR + margin;
}

/** The value the snapshot currently carries for `input` (the agent-relied-upon value). */
function snapshotValueOf(snap: DecideInput, input: DisputableInput): number | string | undefined {
  if (input === 'reversibility_class') {
    return snap.caveatContext?.reversibilityClass ?? snap.action?.action?.reversibility_class;
  }
  return snap.risk?.[input];
}

/**
 * Substitute the oracle's authoritative value for the disputed input into a COPY of the frozen snapshot.
 * Throws when the resolution is missing the value/class it needs (caught by the caller → indeterminate).
 */
function substituteDisputedInput(snap: DecideInput, res: OracleResolution): DecideInput {
  if (res.input === 'reversibility_class') {
    if (typeof res.class !== 'string' || res.class.length === 0) {
      throw new Error('oracle reversibility_class resolution carries no class');
    }
    return {
      ...snap,
      action: { ...snap.action, action: { ...snap.action?.action, reversibility_class: res.class } },
      // `decide` lets caveatContext.reversibilityClass OVERRIDE the action's; keep them consistent so the
      // substituted class is the one that actually gates `optimisticAllowed`.
      ...(snap.caveatContext?.reversibilityClass !== undefined
        ? { caveatContext: { ...snap.caveatContext, reversibilityClass: res.class } }
        : {}),
    };
  }
  if (!Number.isFinite(res.value)) throw new Error(`oracle ${res.input} resolution carries no finite value`);
  const next: DecideInput = { ...snap, risk: { ...snap.risk, [res.input]: res.value as number } };
  // blastRadius also feeds a caveat context in `decide`; override it too when the snapshot set one.
  if (res.input === 'blastRadius' && snap.caveatContext?.blastRadius !== undefined) {
    next.caveatContext = { ...snap.caveatContext, blastRadius: res.value as number };
  }
  return next;
}

/**
 * Adjudicate a contestable dispute. RE-RUNS the Policy VM on the FROZEN open-time snapshot with the ORACLE's
 * authoritative value substituted for the single disputed input, under the grant the verifier trusts. Total;
 * never throws. Fails CLOSED: a mismatched target, a missing snapshot, an oracle that cannot resolve, or any
 * error yields `indeterminate` (slashes no one). It is the oracle — not the challenger's assertion — that
 * decides: `dispute.asserted_*` is never read for the verdict.
 */
export function adjudicateDispute(args: {
  claim: BondedClaim;
  dispute: DisputeClaim;
  grant: Capability;
  /** FROZEN open-time `DecideInput` (grant may be absent; it is re-added from the trusted grant). */
  openSnapshot: DecideInput;
  /** The objective oracle resolving the truthful value of the disputed input. */
  oracle: ObjectiveOracle;
  rMargin?: number;
}): DisputeVerdict {
  const { claim, dispute, grant, openSnapshot, oracle } = args;
  const margin = Number.isFinite(args.rMargin) ? Math.max(0, args.rMargin as number) : DEFAULT_R_MARGIN;
  const WORST: DecisionSummary = { releaseGuardianShare: false, r: 1, optimisticAllowed: false };
  const indeterminate = (
    input: DisputableInput,
    reason: string,
    extra: Partial<DisputeVerdict> = {},
  ): DisputeVerdict => ({
    outcome: 'indeterminate',
    fraudulent: false,
    slashCounterBond: false,
    input,
    agentValue: undefined,
    oracleValue: undefined,
    baseline: WORST,
    adjudicated: WORST,
    reason,
    ...extra,
  });
  try {
    if (!dispute || typeof dispute !== 'object') return indeterminate('reversibility_class', 'malformed dispute');
    const input = dispute.input;
    if (input !== 'reversibility_class' && input !== 'reversibility' && input !== 'blastRadius' && input !== 'semanticDistance') {
      return indeterminate('reversibility_class', `unknown disputed input: ${String(input)}`);
    }
    if (dispute.pcactn_digest !== claim.pcactn_digest) return indeterminate(input, 'dispute targets a different PCActn than the claim');
    if (dispute.bond_ref !== claim.bond_ref) return indeterminate(input, 'dispute names a different bond than the claim');
    if (!openSnapshot || typeof openSnapshot !== 'object') return indeterminate(input, 'no frozen open-time snapshot supplied; cannot adjudicate');
    if (!oracle || typeof oracle.resolve !== 'function') return indeterminate(input, 'no objective oracle supplied');

    const snap: DecideInput = { ...openSnapshot, grant };
    const baseline = summarizeDecision(decide(snap));
    const agentValue = snapshotValueOf(snap, input);

    const res = oracle.resolve(input, snap);
    if (!res || res.input !== input || !res.valid) {
      return indeterminate(input, `objective oracle could not authoritatively resolve ${input}${res?.reason ? `: ${res.reason}` : ''}`, {
        baseline,
        agentValue,
      });
    }
    const oracleValue = res.class ?? res.value;
    const substituted = substituteDisputedInput(snap, res);
    const adjudicated = summarizeDecision(decide(substituted));

    if (!fastPathAdmits(adjudicated, claim.claimed_r, margin)) {
      // The truthful value refutes the fast-path admission → the agent understated the input to dodge step-up.
      const why = !adjudicated.releaseGuardianShare
        ? 'the Policy VM denies the action'
        : !adjudicated.optimisticAllowed
          ? `the optimistic path is not allowed (higher threshold) at r=${adjudicated.r.toFixed(3)}`
          : `the real r=${adjudicated.r.toFixed(3)} exceeds the claimed r=${claim.claimed_r}`;
      return {
        outcome: 'agent-fraud',
        fraudulent: true,
        slashBondRef: claim.bond_ref,
        slashCounterBond: false,
        input,
        agentValue,
        oracleValue,
        baseline,
        adjudicated,
        reason: `understated ${input}: agent relied on ${JSON.stringify(agentValue)}, oracle says ${JSON.stringify(oracleValue)} — ${why}`,
      };
    }
    // The oracle UPHOLDS the agent: fast-path admission survives at the truthful value → the dispute is frivolous.
    return {
      outcome: 'claim-upheld',
      fraudulent: false,
      slashCounterBond: true,
      input,
      agentValue,
      oracleValue,
      baseline,
      adjudicated,
      reason: `the objective oracle upholds the agent's ${input} (${JSON.stringify(oracleValue)}); fast-path admission survives — the dispute is frivolous`,
    };
  } catch (e) {
    return indeterminate(dispute?.input ?? 'reversibility_class', `dispute adjudication error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}


// ---- frozen open-time snapshot ------------------------------------------------------------

/** Deep-clone + deep-freeze a `DecideInput` captured at claim open (store it with the claim). */
export function freezeOpenSnapshot(input: DecideInput): DecideInput {
  const clone = JSON.parse(JSON.stringify(input)) as DecideInput;
  const freeze = (o: unknown): void => {
    if (o && typeof o === 'object' && !Object.isFrozen(o)) {
      Object.freeze(o);
      for (const v of Object.values(o as Record<string, unknown>)) freeze(v);
    }
  };
  freeze(clone);
  return clone;
}

// SERVER WAVE — IMPLEMENTED (in the settlement / hosting layer, not in this pure module; this file
// stays the pure claim + challenge + fraud logic). Where each landed:
//   - permissionless-challenge rate-limit + challenger reward split: the server challenge endpoint
//     (rate-limited per claim + per caller, fail-closed on an unavailable limiter) routes a verified slash
//     into `bond-settlement.ts` `computeSlashSplit` / `BondLedger.slashBond`, so the successful challenger
//     + victim pool + treasury are paid in one tx.
//   - finalize sweeper (release bonds of expired-window claims): a hosting-layer worker over the expired
//     open claims calls an idempotent `open -> expired` CAS that signs + persists the `release` record
//     and returns the bond atomically.
//   - provisional receipts until the window closes: the open path marks the receipt `provisional`, and
//     the claim view reports `finality` provisional -> final once the window closes unchallenged (or
//     `slashed` on a proven fraud). All gated by `auth_config.pca.optimistic` (off by default).
