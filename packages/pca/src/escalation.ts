import type { Capability } from './capability';
import { decodeB64uStrict, hashCanonical } from './hash';
import { type PinnedSigner, artifactSuiteError, closedMembers, isBoundedString, isDigest, isPlainObject, isSafeInt, signArtifact, verifyArtifactSig } from './intent-artifacts';
import type { SignerSuiteOpts } from './pq';
import type { PCActn } from './pcactn';

/**
 * ESCALATION ON THE WIRE (goal-to-decision track T2, security contract C-51; formal/tla/Escalation.tla).
 *
 * A verifier whose decision is `escalate` (an unanswered question, a tighten rule that asks for a human) never admits the
 * action by itself. It answers with an `EscalationRequest`; the principal answers with a signed `EscalationAnswer`; the
 * guard admits the action only when the answer
 *   - is signed by a PINNED principal key (the verifier's own list, never the answer's),
 *   - is bound to exactly THIS (policy digest, action digest, history head): another grant, another PCActn, or another
 *     state of the holder's history makes it void (no replay onto a different policy or action),
 *   - is unexpired and short-lived, and says `allow`.
 * The action digest commits to the whole PCActn (counter and signature included), so the replay counter that admits the
 * action also spends the answer: one answer authorises one PCActn once. An answer can upgrade only `escalate`; a `deny`
 * decision (a hard failure) is never answerable.
 */

export const ESCALATION_ANSWER_DOMAIN = 'atlas-pca/escalation-answer/v1\0';
export const ESCALATION_POLICY_DOMAIN = 'atlas-pca/escalation-policy/v1';
export const ESCALATION_ACTION_DOMAIN = 'atlas-pca/escalation-action/v1';
export const ESCALATION_HISTORY_DOMAIN = 'atlas-pca/escalation-history/v1';
/** An answer lives at most 24 hours. */
export const ESCALATION_MAX_LIFETIME_MS = 86_400_000;

/** The digest of the policy in force: the stored grant (envelope, caveats, issuer, holder). */
export function escalationPolicyDigest(grant: Capability): string {
  return hashCanonical({ d: ESCALATION_POLICY_DOMAIN, grant });
}

/** The digest of the exact PCActn (counter and signature included): one answer, one action. */
export function escalationActionDigest(pcactn: PCActn): string {
  return hashCanonical({ d: ESCALATION_ACTION_DOMAIN, pcactn });
}

/** The head of the holder's history: its highest admitted replay counter (`undefined` = none yet). */
export function escalationHistoryHead(lastCounter: number | undefined): string {
  return hashCanonical({ d: ESCALATION_HISTORY_DOMAIN, last_counter: lastCounter ?? null });
}

export interface EscalationRequest {
  v: 1;
  kind: 'pca-escalation-request';
  aud: string;
  policy_digest: string;
  action_digest: string;
  history_head: string;
  verb: string;
  resource: string;
  /** Why the verifier escalated (the escalate-class reasons). */
  reasons: string[];
  expires_at: number;
  /** K7: H(R) of the canonical approval render the verifier computed from the executed parameters. The approver re-renders and signs it (answer.render_digest). */
  render_digest?: string;
}

export function buildEscalationRequest(a: { aud: string | undefined; grant: Capability; pcactn: PCActn; lastCounter: number | undefined; reasons: readonly string[]; now: number; ttlMs?: number; renderDigest?: string }): EscalationRequest {
  return {
    v: 1,
    kind: 'pca-escalation-request',
    aud: typeof a.aud === 'string' ? a.aud : '',
    policy_digest: escalationPolicyDigest(a.grant),
    action_digest: escalationActionDigest(a.pcactn),
    history_head: escalationHistoryHead(a.lastCounter),
    verb: String(a.pcactn?.action?.verb),
    resource: String(a.pcactn?.action?.resource),
    reasons: [...a.reasons].slice(0, 16).map((r) => String(r).slice(0, 512)),
    expires_at: a.now + (a.ttlMs ?? 3_600_000),
    ...(a.renderDigest !== undefined ? { render_digest: a.renderDigest } : {}),
  };
}

export interface EscalationAnswerBody {
  v: 1;
  kind: 'pca-escalation-answer';
  /** b64u Ed25519 identity of the answering principal (must be one of the verifier's pinned keys). */
  principal: string;
  policy_digest: string;
  action_digest: string;
  history_head: string;
  decision: 'allow' | 'deny';
  iat: number;
  expires_at: number;
  /** Random b64u (at least 16 bytes): two answers to one question are distinct artifacts. */
  nonce: string;
  /** K7: H(R), the digest of the canonical approval render the principal saw. Signed with the rest of the body. */
  render_digest?: string;
  alg?: string;
  pq_pk?: string;
}
export type EscalationAnswer = EscalationAnswerBody & { sig: string; pq_sig?: string };

const REQUIRED = ['v', 'kind', 'principal', 'policy_digest', 'action_digest', 'history_head', 'decision', 'iat', 'expires_at', 'nonce', 'sig'] as const;
const OPTIONAL = ['alg', 'pq_pk', 'pq_sig', 'render_digest'] as const;

/** Null = well-formed (closed members, canonical digests, safe-integer times, sane lifetime). */
export function escalationAnswerShapeError(a: unknown): string | null {
  if (!isPlainObject(a)) return 'not an object';
  const e = closedMembers(a, REQUIRED, OPTIONAL, 'answer');
  if (e) return e;
  if (a.v !== 1 || a.kind !== 'pca-escalation-answer') return 'not a pca-escalation-answer v1';
  if (!isBoundedString(a.principal, 64) || decodeB64uStrict(a.principal, 32) === null) return 'principal must be canonical base64url (32 bytes)';
  for (const k of ['policy_digest', 'action_digest', 'history_head']) if (!isDigest(a[k])) return `${k} must be canonical base64url (32 bytes)`;
  if (a.decision !== 'allow' && a.decision !== 'deny') return "decision must be 'allow' or 'deny'";
  if (!(isSafeInt(a.iat) && a.iat >= 0) || !(isSafeInt(a.expires_at) && a.expires_at >= 0)) return 'iat and expires_at must be non-negative safe integers';
  if (!(a.expires_at > a.iat)) return 'expires_at must be greater than iat';
  if (a.expires_at - a.iat > ESCALATION_MAX_LIFETIME_MS) return `an answer lives at most ${ESCALATION_MAX_LIFETIME_MS} ms`;
  if (a.render_digest !== undefined && !isDigest(a.render_digest)) return 'render_digest must be canonical base64url (32 bytes)';
  const nb = typeof a.nonce === 'string' ? decodeB64uStrict(a.nonce) : null;
  if (nb === null || nb.length < 16) return 'nonce must be canonical base64url of at least 16 bytes';
  if (typeof a.sig !== 'string') return 'sig must be a string';
  return artifactSuiteError(a);
}

/** The principal signs the exact bindings. Throws on a malformed body (fail closed). */
export function signEscalationAnswer(body: EscalationAnswerBody, principalSecret: Uint8Array, suite?: SignerSuiteOpts): EscalationAnswer {
  const signed = signArtifact(ESCALATION_ANSWER_DOMAIN, body as unknown as Record<string, unknown>, principalSecret, suite) as unknown as EscalationAnswer;
  const e = escalationAnswerShapeError(signed);
  if (e) throw new Error(`signEscalationAnswer: ${e}`);
  return signed;
}

export interface EscalationBinding {
  policy_digest: string;
  action_digest: string;
  history_head: string;
  /**
   * K7: the H(R) the verifier recomputed from the executed parameters and its own definition. When set, the answer MUST carry
   * exactly this `render_digest`; when absent, an answer that carries one is refused (the verifier did not check what was shown).
   */
  render_digest?: string;
}

export type EscalationVerdict = { ok: true; principal: string; decision: 'allow' | 'deny' } | { ok: false; reason: string };

/**
 * Verify an answer against the verifier's pinned principals and the binding of THIS decision. Total; every failure is a
 * `{ok:false}`. `decision: 'deny'` is a valid answer that refuses the action (`ok:true`, `decision:'deny'`): the caller
 * must not admit it.
 */
export function verifyEscalationAnswer(answer: unknown, principals: readonly (string | PinnedSigner)[], bind: EscalationBinding, now: number): EscalationVerdict {
  try {
    if (!isSafeInt(now)) return { ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' };
    const e = escalationAnswerShapeError(answer);
    if (e) return { ok: false, reason: `malformed escalation answer: ${e}` };
    const a = answer as EscalationAnswer;
    if (!Array.isArray(principals) || principals.length === 0) return { ok: false, reason: 'no principal is pinned for escalation answers' };
    const pin = principals.map((p) => (typeof p === 'string' ? { pk: p } : p)).find((p) => p !== null && typeof p === 'object' && p.pk === a.principal);
    if (!pin) return { ok: false, reason: 'the answering principal is not pinned by this verifier' };
    if (!verifyArtifactSig(ESCALATION_ANSWER_DOMAIN, a as unknown as Record<string, unknown>, pin)) return { ok: false, reason: 'escalation answer signature invalid' };
    if (a.policy_digest !== bind.policy_digest) return { ok: false, reason: 'the answer is bound to another policy' };
    if (a.action_digest !== bind.action_digest) return { ok: false, reason: 'the answer is bound to another action' };
    if (a.history_head !== bind.history_head) return { ok: false, reason: 'the answer is bound to another state of the history' };
    if (bind.render_digest !== undefined) {
      if (a.render_digest === undefined) return { ok: false, reason: 'the answer is not bound to the canonical approval render' };
      if (a.render_digest !== bind.render_digest) return { ok: false, reason: 'the answer was given for another approval render' };
    } else if (a.render_digest !== undefined) return { ok: false, reason: 'the answer carries an approval render this verifier did not recompute' };
    if (now < a.iat) return { ok: false, reason: 'the answer is from the future' };
    if (now > a.expires_at) return { ok: false, reason: 'the answer has expired' };
    return { ok: true, principal: a.principal, decision: a.decision };
  } catch (err) {
    return { ok: false, reason: `escalation answer error (fail closed): ${err instanceof Error ? err.message : 'unknown'}` };
  }
}
