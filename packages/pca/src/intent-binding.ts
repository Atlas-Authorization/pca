import { decodeB64uStrict, hashCanonical } from './hash';

/**
 * `envelope.intent`: the signed, first-class INTENT BINDING of a PCActn (PCA Intent Layer, milestone M2;
 * docs/specs/pca-intent-layer.md §4.1, §8). NORMATIVE for every verifier (TypeScript reference, the 9 native
 * verifiers, the zkVM guest); the conformance vectors `intent-*` pin every rule below.
 *
 * WIRE (the optional top-level `intent` slot is SIGNED: it is part of the canonical body like `tool_binding`). When
 * present it is an object with EXACTLY these five members, else the terminal `wire` check fails:
 *   ref               canonical base64url, 32 bytes   the IntentStatement content address (`intentRef`)
 *   map_digest        canonical base64url, 32 bytes   the Intent Map content address (`intentMapDigest`)
 *   goal_salt         non-empty string, <= 128 UTF-8 bytes   the salt of the root grant's goal commitment
 *   fidelity_ppm      safe integer in [0, 1_000_000]
 *   residual_risk_ppm safe integer >= 0                (harm-units x 10^6: may exceed 10^6)
 *
 * CHECK `intent` (evaluated after `counter`). It is PRESENT in the verdict iff the PCActn carries `intent` OR the
 * verifier has an ACTIVE intent policy; otherwise it is absent and the verdict is byte-identical to a pre-M2
 * verifier (back-compat). Steps, first failure wins:
 *   0. policy sanity: `min_fidelity_ppm` / `max_residual_risk_ppm`, when set, must be safe integers >= 0 (else fail:
 *      misconfigured, fail closed);
 *   1. absent `intent` under an active policy => fail (an agent cannot dodge a fidelity floor by omitting the field);
 *   2. ROOT GRANT BINDING: take the verifier's grant (the root Intent Grant), its FIRST caveat that is an object with
 *      `type == "envelope"`; it must carry a string `goal_commit`, and
 *        goal_commit == base64url(sha256(strictCanonical({ d: "atlas-pca/goal/v1\u0000",
 *                                                         goal: "pca-intent:v1:" || ref || ":" || map_digest,
 *                                                         salt: goal_salt })))
 *      i.e. the grant was minted (`mintGrant`, goal = `intentGoal(ref, map_digest)`) for exactly this statement and
 *      map. The goal string is fully determined by `ref` and `map_digest`, which the field already discloses, so
 *      carrying the salt reveals nothing further: it only makes the binding checkable without an out-of-band reveal;
 *   3. `fidelity_ppm >= min_fidelity_ppm` (when set);
 *   4. `residual_risk_ppm <= max_residual_risk_ppm` (when set).
 * A policy is ACTIVE iff `require === true` or either threshold is set (a threshold implies `require`).
 *
 * INTENT LAYER v2 (rule 13 amends step 2): when the PCActn also carries a wire-valid `intent_session` (see
 * intent-session.ts), the root grant is a SESSION grant (G_0 or a delta D_k) and the goal in step 2 is
 *   "pca-intent:v2:" || intent_session.session || ":" || map_digest
 * instead of the v1 goal; `ref` is then bound through the session root (`S.intent_ref == ref`, rule 13 step 3).
 * COMMITTED MAP (rule 19, V15): when `intent_session.map_form` is "commit", `map_digest` carries the SALTED map commitment
 * (intent-map-commit.ts) and the goal is
 *   "pca-intent:v2c:" || intent_session.session || ":" || map_digest
 * so a grant minted for the plain map digest never opens under the commit form and vice versa.
 *
 * GOAL BINDING v3 (0.5, goal-to-decision; closes W1). When the verifier is configured with `IntentPolicy.approved_goal`
 * ({ goal_digest, policy_digest }: the digests of the Goal IR the principal signed and of the policy compiled from it,
 * both canonical base64url 32 bytes), step 2 opens the root grant's commitment against
 *   "pca-intent:v3:" || goal_digest || ":" || policy_digest      (salt = `intent.goal_salt`, same domain and hash)
 * and ONLY that: a v1/v2 grant (identity of the statement, not its meaning) does not open it, and a v3 grant does not open
 * under a different goal or a different compiled policy. No wire change: the digests come from the verifier's own
 * configuration (what it was told the principal approved), so the 9 native verifiers' `intent` wire is untouched. A
 * verifier without `approved_goal` behaves exactly as before (v1/v2 retained).
 *
 * The two ppm figures are SIGNED CLAIMS by the leaf holder. They are bound to `map_digest`, so a relying party that
 * fetches the map (server: GET /v1/pca/intent/maps/:digest) and replays it (`verifyIntentMap` in
 * `@atlasauth/pca-intent`) can check them; the core verifier gates on them as claimed and on the binding.
 */

export const INTENT_GOAL_PREFIX = 'pca-intent:v1:';
/** Intent Layer v2 session grants (G_0 and the delta grants D_k): `pca-intent:v2:<session>:<map_digest>`. */
export const INTENT_GOAL_V2_PREFIX = 'pca-intent:v2:';
/** Intent Layer v2 session grants over a COMMITTED map (rule 19): `pca-intent:v2c:<session>:<map_commit>`. */
export const INTENT_GOAL_V2C_PREFIX = 'pca-intent:v2c:';
/** Goal binding v3 (0.5): `pca-intent:v3:<goal_digest>:<policy_digest>`: commits to the signed Goal IR AND the compiled policy. */
export const INTENT_GOAL_V3_PREFIX = 'pca-intent:v3:';
/** Domain of the grant's salted goal commitment (`envelope.ts` goalCommitOf); restated so the rule is self-contained. */
export const INTENT_GOAL_COMMIT_DOMAIN = 'atlas-pca/goal/v1\0';
export const PPM_ONE = 1_000_000;
export const MAX_INTENT_GOAL_SALT_LEN = 128;
/** Closed member set of `envelope.intent` (all required). */
export const ENVELOPE_INTENT_FIELDS = ['ref', 'map_digest', 'goal_salt', 'fidelity_ppm', 'residual_risk_ppm'] as const;

/** The signed `intent` slot of a PCActn. */
export interface EnvelopeIntent {
  /** b64u(32): the IntentStatement content address. */
  ref: string;
  /** b64u(32): the Intent Map content address. */
  map_digest: string;
  /** The salt of the root grant's goal commitment (opens it, together with `ref` and `map_digest`). */
  goal_salt: string;
  /** Integer ppm in [0, 1e6]: the map's fidelity estimate. */
  fidelity_ppm: number;
  /** Integer ppm >= 0 (harm-units x 1e6): the map's residual-risk estimate. */
  residual_risk_ppm: number;
}

/** Verifier-side intent policy (all optional; an ACTIVE policy fails closed on an absent field). */
export interface IntentPolicy {
  /** Require every PCActn to carry a bound `intent`. */
  require?: boolean;
  /** Deny when the claimed `fidelity_ppm` is below this. Setting it implies `require`. */
  min_fidelity_ppm?: number;
  /** Deny when the claimed `residual_risk_ppm` is above this. Setting it implies `require`. */
  max_residual_risk_ppm?: number;
  /** v3 goal binding: the root grant must open against exactly this approved Goal IR + compiled policy. Implies `require`. */
  approved_goal?: ApprovedGoalRef;
}

/** The digests a v3 goal commitment binds: b64u(32) of the signed Goal IR and of the policy compiled from it. */
export interface ApprovedGoalRef {
  goal_digest: string;
  policy_digest: string;
}

/** Well-formed (both canonical b64u 32 bytes)? */
export function isApprovedGoalRef(v: unknown): v is ApprovedGoalRef {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const r = v as Record<string, unknown>;
  return Object.keys(r).length === 2 && decodeB64uStrict(r.goal_digest, 32) !== null && decodeB64uStrict(r.policy_digest, 32) !== null;
}

/** The v3 goal string (what a minting wallet passes as `goal`). Throws on a malformed digest: never commit to garbage. */
export function intentGoalV3(ref: ApprovedGoalRef): string {
  if (!isApprovedGoalRef(ref)) throw new Error('intentGoalV3: goal_digest and policy_digest must be canonical base64url (32 bytes)');
  return INTENT_GOAL_V3_PREFIX + ref.goal_digest + ':' + ref.policy_digest;
}

/** The v3 goal commitment for a salt (equals `goalCommitOf(intentGoalV3(ref), salt)` of envelope.ts). */
export function intentGoalCommitV3(ref: ApprovedGoalRef, goal_salt: string): string {
  return hashCanonical({ d: INTENT_GOAL_COMMIT_DOMAIN, goal: intentGoalV3(ref), salt: goal_salt });
}

/** The goal string that binds a grant to an intent statement (and optionally an Intent Map). */
export function intentGoal(ref: string, mapDigest?: string): string {
  return INTENT_GOAL_PREFIX + ref + (mapDigest ? ':' + mapDigest : '');
}

/** Parse an intent goal string; null if it is not one. */
export function parseIntentGoal(goal: string): { intentRef: string; mapDigest?: string } | null {
  if (typeof goal !== 'string' || !goal.startsWith(INTENT_GOAL_PREFIX)) return null;
  const [ref, map, ...rest] = goal.slice(INTENT_GOAL_PREFIX.length).split(':');
  if (!ref || rest.length) return null;
  return map ? { intentRef: ref, mapDigest: map } : { intentRef: ref };
}

/**
 * The goal commitment an `envelope.intent` claims the root grant carries (`session`: the v2 session goal, rule 13;
 * `mapForm` "commit": the v2c goal over a committed map, rule 19).
 */
export function intentGoalCommit(i: Pick<EnvelopeIntent, 'ref' | 'map_digest' | 'goal_salt'>, session?: string, mapForm?: string): string {
  const goal =
    session !== undefined
      ? (mapForm === 'commit' ? INTENT_GOAL_V2C_PREFIX : INTENT_GOAL_V2_PREFIX) + session + ':' + i.map_digest
      : intentGoal(i.ref, i.map_digest);
  return hashCanonical({ d: INTENT_GOAL_COMMIT_DOMAIN, goal, salt: i.goal_salt });
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
const u8len = (s: string): number => new TextEncoder().encode(s).length;

/** Wire validation of the `intent` slot (called by `validateWireV2` when the slot is present). Null = well-formed. */
export function validateIntentWire(v: unknown): string | null {
  if (!isObj(v)) return "'intent' must be an object";
  for (const k of Object.keys(v)) if (!(ENVELOPE_INTENT_FIELDS as readonly string[]).includes(k)) return `unknown field 'intent.${k}'`;
  for (const k of ENVELOPE_INTENT_FIELDS) if (!(k in v)) return `missing field 'intent.${k}'`;
  if (decodeB64uStrict(v.ref, 32) === null) return "'intent.ref' is not canonical base64url (32 bytes)";
  if (decodeB64uStrict(v.map_digest, 32) === null) return "'intent.map_digest' is not canonical base64url (32 bytes)";
  if (typeof v.goal_salt !== 'string' || v.goal_salt.length === 0 || u8len(v.goal_salt) > MAX_INTENT_GOAL_SALT_LEN) {
    return "'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)";
  }
  if (!isInt(v.fidelity_ppm) || v.fidelity_ppm < 0 || v.fidelity_ppm > PPM_ONE) return "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]";
  if (!isInt(v.residual_risk_ppm) || v.residual_risk_ppm < 0) return "'intent.residual_risk_ppm' must be a non-negative safe integer";
  return null;
}

/** True iff the policy is active (the `intent` check runs even for a PCActn without the field). */
export function intentPolicyActive(policy: IntentPolicy | undefined): boolean {
  return !!policy && (policy.require === true || policy.min_fidelity_ppm !== undefined || policy.max_residual_risk_ppm !== undefined || policy.approved_goal !== undefined);
}

/** The root grant's goal commitment: the FIRST `envelope` caveat's string `goal_commit`, else null. */
export function rootGoalCommit(grant: unknown): string | null {
  if (!isObj(grant) || !Array.isArray(grant.caveats)) return null;
  const env = grant.caveats.find((c) => isObj(c) && c.type === 'envelope') as Record<string, unknown> | undefined;
  return env !== undefined && typeof env.goal_commit === 'string' ? env.goal_commit : null;
}

export type IntentDecision = { status: 'absent' } | { status: 'pass' } | { status: 'fail'; reason: string };

/**
 * The `intent` check (rules 0-4 above). `intent` is the PCActn's slot AFTER wire validation (so well-formed when
 * present); `grant` the verifier's own root grant. Never throws.
 */
export function decideIntentBinding(intent: EnvelopeIntent | undefined, grant: unknown, policy?: IntentPolicy, session?: string, mapForm?: string): IntentDecision {
  const active = intentPolicyActive(policy);
  if (intent === undefined && !active) return { status: 'absent' };
  try {
    const okBound = (x: unknown) => x === undefined || (isInt(x) && x >= 0);
    if (active && (!okBound(policy!.min_fidelity_ppm) || !okBound(policy!.max_residual_risk_ppm))) {
      return { status: 'fail', reason: 'intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)' };
    }
    if (active && policy!.approved_goal !== undefined && !isApprovedGoalRef(policy!.approved_goal)) {
      return { status: 'fail', reason: 'intent policy misconfigured: approved_goal digests must be canonical base64url (32 bytes) (fail closed)' };
    }
    if (intent === undefined) return { status: 'fail', reason: 'this verifier requires an intent binding but the PCActn carries none' };
    const commit = rootGoalCommit(grant);
    if (commit === null) return { status: 'fail', reason: 'the root grant carries no envelope goal commitment to bind the intent to' };
    const v3 = policy?.approved_goal;
    if (v3 !== undefined) {
      if (intentGoalCommitV3(v3, intent.goal_salt) !== commit) return { status: 'fail', reason: "the root grant's goal commitment does not open to the approved goal and compiled policy (v3)" };
    } else if (intentGoalCommit(intent, session, mapForm) !== commit) return { status: 'fail', reason: "intent ref / map_digest / goal_salt do not open the root grant's goal commitment" };
    if (policy?.min_fidelity_ppm !== undefined && !(intent.fidelity_ppm >= policy.min_fidelity_ppm)) {
      return { status: 'fail', reason: `intent fidelity ${intent.fidelity_ppm} ppm is below the policy minimum ${policy.min_fidelity_ppm}` };
    }
    if (policy?.max_residual_risk_ppm !== undefined && !(intent.residual_risk_ppm <= policy.max_residual_risk_ppm)) {
      return { status: 'fail', reason: `intent residual risk ${intent.residual_risk_ppm} ppm exceeds the policy maximum ${policy.max_residual_risk_ppm}` };
    }
    return { status: 'pass' };
  } catch (e) {
    return { status: 'fail', reason: `intent binding error (fail closed): ${(e as Error).message}` };
  }
}
