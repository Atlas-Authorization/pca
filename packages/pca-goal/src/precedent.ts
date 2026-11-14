import {
  ESCALATION_ANSWER_DOMAIN, escalationActionDigest, escalationAnswerShapeError, escalationHistoryHead, escalationPolicyDigest, hashCanonical, paramsDigest, verifyEscalationAnswer,
  type Capability, type EscalationAnswer, type EscalationAnswerBody, type EscalationRequest, type PCActn,
} from '@atlasauth/pca';
import { verifyArtifactSig } from '@atlasauth/pca/ext/intent';
import { buildSpace, cellKey, decideCase, mkAct, type Case, type Space } from './examples';
import type { Decision, Goal, Hist, Ontology, Quantity, RelDecl, Value } from './ir';
import { signPayload, verifyPayload, type PinnedSigner, type SignedPayload, type SignerSecret } from './sign';

/**
 * Progressive authorization (spec F7). Widening is only by an EscalationRequest answered by a principal-signed
 * EscalationAnswer: the ONE wire of packages/pca (escalation.ts). A verified answer becomes an append-only hash-chained
 * Precedent bound to (policy digest, decision cell, the answered action's exact quantities as a ceiling). A recorded cell
 * decision is never flipped except by a principal-signed revocation. Invariants (tested; the model-checked protocol lives with
 * the escalation spec, formal/tla/Escalation.tla):
 *   P1 the effective allow set grows only by cells with a valid principal signature bound to the policy digest;
 *   P2 no replay of an answer onto another policy digest, another cell, or beyond the signed quantity ceiling;
 *   P3 a Deny (prohibition, closed world) is never turned into Allow: precedents only act on Escalate;
 *   P4 Escalate never becomes Allow implicitly (no precedent, expired, revoked, or wrong signer => Escalate stays).
 *
 * What the principal's signature covers: the escalation answer binds (principal, policy digest, the digest of the WHOLE answered
 * PCActn, the history head, decision, iat, expires_at, nonce). The PCActn commits to the action's params through `params_digest`,
 * so the quantities a precedent derives its ceilings from (the plaintext `params` kept beside the PCActn) are checked against that
 * digest at append and again at every chain verification. NOT covered by any signature: the relation facts (`rels`), which are the
 * verifier's own knowledge of the world and are part of the chain digest, and the log itself (integrity of the head is the
 * verifier's to anchor).
 */

const unitKey = (q: Quantity): string => (q.u.k === 'money' ? `money:${q.u.ccy}` : q.u.k);
/** Ceilings are keyed by parameter AND unit (kind + currency): a EUR answer never covers a GBP action. */
export const ceilingsOf = (params: Record<string, Value>): Record<string, number> =>
  Object.fromEntries(Object.entries(params).flatMap(([k, v]) => (v.k === 'q' ? [[`${k}|${unitKey(v.q)}`, v.q.n] as const] : [])));

/** The action a precedent answers: the PCActn the principal saw, its plaintext params, and the verifier's own facts. */
export interface AnsweredCase {
  pcactn: PCActn;
  /** plaintext of `pcactn.action.params_digest` */
  params: Record<string, Value>;
  /** relation facts the verifier decides this action under (never taken from the answer) */
  rels: RelDecl[];
  /** the holder's highest admitted replay counter when the question was asked (`undefined` = none): the answer's history head */
  lastCounter: number | undefined;
}
const caseOf = (a: AnsweredCase): Case => ({ act: mkAct(a.pcactn.action.verb, a.pcactn.action.resource, a.params), rels: a.rels });

export type RevocationBody = { policy_digest: string; cell: string; target_entry: string; ts: number };
export const signRevocation = (p: RevocationBody, secret: SignerSecret): SignedPayload<RevocationBody> => signPayload('precedent-revocation', p, secret);

/** The answer body for a request: bind it to the request's exact (policy, action, history head); sign it with `signEscalationAnswer`. */
export const answerBodyFor = (req: EscalationRequest, o: { principal: string; decision: 'allow' | 'deny'; iat: number; expires_at: number; nonce: string }): EscalationAnswerBody => ({
  v: 1, kind: 'pca-escalation-answer', principal: o.principal, policy_digest: req.policy_digest, action_digest: req.action_digest, history_head: req.history_head,
  decision: o.decision, iat: o.iat, expires_at: o.expires_at, nonce: o.nonce,
});

export interface Entry {
  seq: number; prev: string; kind: 'answer' | 'revocation';
  answer?: EscalationAnswer; answered?: AnsweredCase; cell?: string; ceilings?: Record<string, number>;
  revocation?: SignedPayload<RevocationBody>; digest: string;
}
const GENESIS = '0'.repeat(64);
const entryDigest = (e: Omit<Entry, 'digest'>): string =>
  hashCanonical({ d: 'atlas-pca/goal-precedent-entry/v1', seq: e.seq, prev: e.prev, kind: e.kind, answer: e.answer ?? null, answered: e.answered ? { ...e.answered, lastCounter: e.answered.lastCounter ?? null } : null, cell: e.cell ?? null, ceilings: e.ceilings ?? null, revocation: e.revocation ?? null });

export type AppendResult = { ok: true; entry: Entry } | { ok: false; reason: string };
type Pins = readonly (string | PinnedSigner)[];

export class PrecedentLog {
  readonly entries: Entry[] = [];
  /** `principals`: the pinned signers allowed to answer and revoke (the verifier's own list). */
  constructor(private readonly principals: Pins) {}

  head(): string { return this.entries.length ? this.entries[this.entries.length - 1]!.digest : GENESIS; }

  private pinFor(pk: string): string | PinnedSigner | undefined { return this.principals.find((p) => (typeof p === 'string' ? p : p.pk) === pk); }

  /** Everything about an answer that does not depend on the clock: shape, pinned signature, bindings, params digest. Null = sound. */
  private answerFault(e: { answer: EscalationAnswer; answered: AnsweredCase }): string | null {
    const a = e.answer;
    if (escalationAnswerShapeError(a) !== null) return 'malformed answer';
    const pin = this.pinFor(a.principal);
    if (!pin || !verifyArtifactSig(ESCALATION_ANSWER_DOMAIN, a as unknown as Record<string, unknown>, pin)) return 'bad signature';
    if (a.action_digest !== escalationActionDigest(e.answered.pcactn)) return 'answer is bound to another action';
    if (a.history_head !== escalationHistoryHead(e.answered.lastCounter)) return 'answer is bound to another history state';
    if (paramsDigest(e.answered.params) !== e.answered.pcactn.action.params_digest) return 'params do not match the signed action';
    return null;
  }

  /** Recompute the whole chain (append-only integrity), every signature and binding, and every derived cell and ceiling under `space`. */
  verifyChain(space: Space): boolean {
    try {
      let prev = GENESIS;
      for (const [i, e] of this.entries.entries()) {
        if (e.seq !== i || e.prev !== prev || entryDigest(e) !== e.digest) return false;
        if (e.kind === 'answer') {
          if (!e.answer || !e.answered || this.answerFault({ answer: e.answer, answered: e.answered }) !== null) return false;
          if (e.cell !== cellKey(space, caseOf(e.answered)) || JSON.stringify(e.ceilings) !== JSON.stringify(ceilingsOf(e.answered.params))) return false;
        } else if (!(e.revocation && verifyPayload(e.revocation, 'precedent-revocation', this.principals))) return false;
        prev = e.digest;
      }
      return true;
    } catch { return false; }
  }

  private live(policy: string, cell: string, now: number): Entry | undefined {
    const revoked = new Set(this.entries.filter((e) => e.kind === 'revocation').map((e) => e.revocation!.payload.target_entry));
    return [...this.entries].reverse().find((e) => e.kind === 'answer' && e.answer!.policy_digest === policy && e.cell === cell && e.answer!.expires_at > now && !revoked.has(e.digest));
  }

  /** Verify the answer (pinned signer, bound to this grant's policy digest and this exact PCActn and history, unexpired) and record it. */
  append(answer: EscalationAnswer, answered: AnsweredCase, grant: Capability, space: Space, now: number): AppendResult {
    const v = verifyEscalationAnswer(answer, this.principals, { policy_digest: escalationPolicyDigest(grant), action_digest: escalationActionDigest(answered.pcactn), history_head: escalationHistoryHead(answered.lastCounter) }, now);
    if (!v.ok) return { ok: false, reason: v.reason };
    const fault = this.answerFault({ answer, answered });
    if (fault) return { ok: false, reason: fault };
    const cell = cellKey(space, caseOf(answered));
    const existing = this.live(answer.policy_digest, cell, now);
    if (existing && existing.answer!.decision !== answer.decision) return { ok: false, reason: 'conflicts with a recorded decision; revoke it first' };
    return { ok: true, entry: this.push({ kind: 'answer', answer, answered, cell, ceilings: ceilingsOf(answered.params) }) };
  }

  revoke(rev: SignedPayload<RevocationBody>): AppendResult {
    if (!verifyPayload(rev, 'precedent-revocation', this.principals)) return { ok: false, reason: 'bad signature' };
    if (!this.entries.some((e) => e.kind === 'answer' && e.digest === rev.payload.target_entry && e.answer!.policy_digest === rev.payload.policy_digest && e.cell === rev.payload.cell)) return { ok: false, reason: 'no such precedent' };
    return { ok: true, entry: this.push({ kind: 'revocation', revocation: rev }) };
  }

  private push(e: Pick<Entry, 'kind' | 'answer' | 'answered' | 'cell' | 'ceilings' | 'revocation'>): Entry {
    const base = { seq: this.entries.length, prev: this.head(), ...Object.fromEntries(Object.entries(e).filter(([, x]) => x !== undefined)) } as Omit<Entry, 'digest'>;
    const entry: Entry = { ...base, digest: entryDigest(base) };
    this.entries.push(entry);
    return entry;
  }

  /** The recorded decision covering this case under this policy, if any (cell match, ceilings respected, unexpired, unrevoked). */
  lookup(policyDigest: string, space: Space, c: Case, now: number): { decision: 'allow' | 'deny'; entry: Entry } | undefined {
    const e = this.live(policyDigest, cellKey(space, c), now);
    if (!e) return undefined;
    const ceil = e.ceilings!;
    const now2 = ceilingsOf(c.act.params);
    for (const [k, v] of Object.entries(now2)) if (v > (ceil[k] ?? Number.NEGATIVE_INFINITY)) return undefined; // beyond the signed ceiling
    for (const k of Object.keys(ceil)) if (!(k in now2)) return undefined; // same parameters and units as the signed witness
    return { decision: e.answer!.decision, entry: e };
  }
}

export interface Authorized { decision: Decision; via: 'policy' | 'precedent'; precedent?: Entry }

/** Policy decision refined by precedents. Precedents act only on Escalate (P3, P4); a recorded deny also tightens. */
export function authorizeWithPrecedents(goal: Goal, ont: Ontology, policyDigest: string, log: PrecedentLog, c: { act: Case['act']; rels: RelDecl[]; hist?: Hist }, now: number): Authorized {
  const base = decideCase(goal, ont, c).decision;
  if (base !== 'escalate') return { decision: base, via: 'policy' };
  const space = buildSpace([goal]);
  if (!log.verifyChain(space)) return { decision: 'escalate', via: 'policy' }; // fail closed on a tampered log
  const hit = log.lookup(policyDigest, space, c, now);
  if (!hit) return { decision: 'escalate', via: 'policy' };
  return { decision: hit.decision === 'allow' ? 'allow' : 'deny', via: 'precedent', precedent: hit.entry };
}
