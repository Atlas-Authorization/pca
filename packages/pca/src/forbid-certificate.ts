import { hashCanonical } from './hash';
import { predicateMatches, type ActionContext, type Predicate } from './predicates';
import { whenMatches } from './prohibitions';

/**
 * FORBID-WINS DECISION WITNESS AND CERTIFICATE (borrowed-ideas item 7; security contract C-240, C-241).
 *
 * A policy is a flat list of CLAUSES. `permit` clauses grant (plain permission-DSL semantics: anything that cannot be decided
 * is "not matched"). `forbid` clauses veto and `escalate` clauses cap the decision at escalate; both use the prohibition
 * polarity (anything that cannot be decided is "matched": the veto applies). The decision is order-independent:
 *
 *   any forbid matched                        -> deny      (a forbid beats every permit, whoever signed either)
 *   else no permit matched                    -> deny      (default deny)
 *   else any escalate matched                 -> escalate
 *   else                                      -> allow
 *
 * `decideClauses` returns the decision with a WITNESS (the winning clause and the shadowed ones). `certify` turns that into a
 * canonical certificate and `checkForbidCertificate` re-derives it from the clauses and the action with the real evaluators,
 * so a verifier never trusts a certificate it did not recompute. `certificateConsistent` is the tiny rule over the certificate's
 * own table (no evaluator needed): the decision follows from the per-clause values alone.
 *
 * Cross-signer: every clause may name its `signer`. `precedence` lists signers from most to least authoritative (an
 * organisation constitution before a user grant); among several matching forbids the most authoritative signer is the winner,
 * and `permitSigners`, when given, drops permits from any other signer (fail closed). Signers never change WHETHER a forbid
 * applies, only which one is named, so a lower-ranked signer can never switch an org forbid off.
 *
 * Pure, total, never throws; a malformed clause or action is a `deny` with the `malformed` winner.
 */

export const FORBID_CERT_VERSION = 1;
export const FORBID_CERT_KIND = 'forbid-wins';
/** Most clauses one policy may carry (a bound on the certificate size). */
export const MAX_CLAUSES = 512;

export type ClauseKind = 'permit' | 'forbid' | 'escalate';
export type ClauseValue = 'true' | 'false' | 'unknown';
export type CertDecision = 'allow' | 'escalate' | 'deny';

export interface PolicyClause {
  /** Unique within the policy, 1..128 characters. */
  id: string;
  kind: ClauseKind;
  /** Who authored the clause (an opaque key id or name); optional. */
  signer?: string;
  when: Predicate;
}

export interface ClauseOptions {
  /** Signers, most authoritative first; decides which of several matching forbids is named the winner. */
  precedence?: readonly string[];
  /** When present, a permit from a signer outside this list is ignored. */
  permitSigners?: readonly string[];
}

export interface ClauseWitness {
  /** The clause that decided: the first matching permit (allow), the winning forbid / escalate, or none (default deny / malformed). */
  winner: { kind: ClauseKind | 'none' | 'malformed'; id: string | null };
  /** Ids of every other clause that also matched (shadowed by the winner). */
  shadowed: string[];
}

export interface ClauseDecision {
  decision: CertDecision;
  witness: ClauseWitness;
  /** Per clause, in policy order: the value the evaluators gave. `true` / `unknown` count as matched for forbid and escalate. */
  values: Array<{ id: string; kind: ClauseKind; value: ClauseValue }>;
}

export interface ForbidCertificate {
  v: typeof FORBID_CERT_VERSION;
  kind: typeof FORBID_CERT_KIND;
  /** hashCanonical of the clause list: names the exact policy the certificate is about. */
  policy: string;
  /** hashCanonical of the action context: names the exact request. */
  action: string;
  decision: CertDecision;
  winner: ClauseWitness['winner'];
  shadowed: string[];
  clauses: Array<{ id: string; kind: ClauseKind; signer?: string; value: ClauseValue }>;
}

const KINDS: readonly string[] = ['permit', 'forbid', 'escalate'];
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Null = the clause list is well formed (distinct ids, known kinds, a predicate for each). */
export function clausesError(clauses: unknown): string | null {
  if (!Array.isArray(clauses)) return 'clauses must be an array';
  if (clauses.length > MAX_CLAUSES) return `more than ${MAX_CLAUSES} clauses`;
  const seen = new Set<string>();
  for (const [i, c] of clauses.entries()) {
    if (!isObj(c)) return `clauses[${i}] must be an object`;
    if (typeof c.id !== 'string' || c.id.length === 0 || c.id.length > 128) return `clauses[${i}].id must be a string of 1..128 characters`;
    if (seen.has(c.id)) return `clauses[${i}].id '${c.id}' is a duplicate`;
    seen.add(c.id);
    if (typeof c.kind !== 'string' || !KINDS.includes(c.kind)) return `clauses[${i}].kind must be permit, forbid or escalate`;
    if (c.signer !== undefined && (typeof c.signer !== 'string' || c.signer.length > 256)) return `clauses[${i}].signer must be a string of at most 256 characters`;
    if (!isObj(c.when)) return `clauses[${i}].when must be a predicate object`;
  }
  return null;
}

function valueOf(c: PolicyClause, ctx: ActionContext): ClauseValue {
  if (c.kind === 'permit') return predicateMatches(c.when, ctx) ? 'true' : 'false';
  // veto polarity: clean match -> true; cannot-decide-but-the-veto-applies -> unknown; clean miss -> false
  if (!whenMatches(c.when, ctx)) return 'false';
  return predicateMatches(c.when, ctx) ? 'true' : 'unknown';
}

function rankOf(c: PolicyClause, precedence: readonly string[]): number {
  const i = c.signer === undefined ? -1 : precedence.indexOf(c.signer);
  return i < 0 ? precedence.length : i; // an unlisted signer ranks last
}

function malformed(): ClauseDecision {
  return { decision: 'deny', witness: { winner: { kind: 'malformed', id: null }, shadowed: [] }, values: [] };
}

/** Decide a clause list against an action. Order-independent for the decision; the named winner is deterministic. */
export function decideClauses(clauses: readonly PolicyClause[], ctx: ActionContext, opts: ClauseOptions = {}): ClauseDecision {
  try {
    if (clausesError(clauses) !== null) return malformed();
    const a = ctx?.action;
    if (!a || typeof a.verb !== 'string' || typeof a.resource !== 'string') return malformed();
    const precedence = opts.precedence ?? [];
    const active = clauses.filter((c) => c.kind !== 'permit' || opts.permitSigners === undefined || (c.signer !== undefined && opts.permitSigners.includes(c.signer)));
    const values = clauses.map((c) => ({ id: c.id, kind: c.kind, value: active.includes(c) ? valueOf(c, ctx) : ('false' as ClauseValue) }));
    const hit = (k: ClauseKind) => clauses.filter((c, i) => c.kind === k && values[i]!.value !== 'false');
    const forbids = hit('forbid').sort((x, y) => rankOf(x, precedence) - rankOf(y, precedence) || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
    const permits = hit('permit');
    const escalates = hit('escalate');
    const others = (win: PolicyClause | undefined) => [...forbids, ...permits, ...escalates].filter((c) => c !== win).map((c) => c.id);
    if (forbids.length > 0) {
      const w = forbids[0]!;
      return { decision: 'deny', witness: { winner: { kind: 'forbid', id: w.id }, shadowed: others(w) }, values };
    }
    if (permits.length === 0) return { decision: 'deny', witness: { winner: { kind: 'none', id: null }, shadowed: others(undefined) }, values };
    if (escalates.length > 0) {
      const w = escalates[0]!;
      return { decision: 'escalate', witness: { winner: { kind: 'escalate', id: w.id }, shadowed: others(w) }, values };
    }
    const w = permits[0]!;
    return { decision: 'allow', witness: { winner: { kind: 'permit', id: w.id }, shadowed: others(w) }, values };
  } catch {
    return malformed();
  }
}

/** Build the canonical certificate for a decision. */
export function certify(clauses: readonly PolicyClause[], ctx: ActionContext, opts: ClauseOptions = {}): ForbidCertificate {
  const d = decideClauses(clauses, ctx, opts);
  const byId = new Map(clauses.map((c) => [c.id, c]));
  return {
    v: FORBID_CERT_VERSION,
    kind: FORBID_CERT_KIND,
    policy: hashCanonical(clauses),
    action: hashCanonical(ctx),
    decision: d.decision,
    winner: d.witness.winner,
    shadowed: d.witness.shadowed,
    clauses: d.values.map((v) => {
      const s = byId.get(v.id)?.signer;
      return { id: v.id, kind: v.kind, ...(s !== undefined ? { signer: s } : {}), value: v.value };
    }),
  };
}

/**
 * The rule over the certificate's own table: the decision, winner and shadowed list that the per-clause values force.
 * Needs no evaluator, so it is the part a constrained verifier (or a native port) can check on its own.
 */
export function certificateConsistent(cert: ForbidCertificate, opts: ClauseOptions = {}): boolean {
  try {
    if (!isObj(cert) || cert.v !== FORBID_CERT_VERSION || cert.kind !== FORBID_CERT_KIND || !Array.isArray(cert.clauses)) return false;
    const rows = cert.clauses;
    // the one certificate with no table: a malformed policy or action, always a deny that names nothing
    if (cert.winner?.kind === 'malformed') return rows.length === 0 && cert.decision === 'deny' && cert.winner.id === null && cert.shadowed.length === 0;
    const precedence = opts.precedence ?? [];
    const rank = (r: (typeof rows)[number]) => {
      const i = r.signer === undefined ? -1 : precedence.indexOf(r.signer);
      return i < 0 ? precedence.length : i;
    };
    for (const r of rows) if (!KINDS.includes(r.kind) || !['true', 'false', 'unknown'].includes(r.value)) return false;
    const hit = (k: ClauseKind) => rows.filter((r) => r.kind === k && r.value !== 'false');
    const forbids = hit('forbid').sort((x, y) => rank(x) - rank(y) || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
    const permits = hit('permit');
    const escalates = hit('escalate');
    const win = forbids[0] ?? (permits.length === 0 ? undefined : escalates[0] ?? permits[0]);
    const decision: CertDecision = forbids.length > 0 ? 'deny' : permits.length === 0 ? 'deny' : escalates.length > 0 ? 'escalate' : 'allow';
    const kind = forbids.length > 0 ? 'forbid' : permits.length === 0 ? 'none' : escalates.length > 0 ? 'escalate' : 'permit';
    const shadowed = [...forbids, ...permits, ...escalates].filter((r) => r !== win).map((r) => r.id);
    return (
      cert.decision === decision &&
      cert.winner.kind === kind &&
      cert.winner.id === (win?.id ?? null) &&
      JSON.stringify(cert.shadowed) === JSON.stringify(shadowed)
    );
  } catch {
    return false;
  }
}

/** Recompute the certificate from the clauses and the action; it must match byte for byte (canonical form). */
export function checkForbidCertificate(cert: ForbidCertificate, clauses: readonly PolicyClause[], ctx: ActionContext, opts: ClauseOptions = {}): { ok: boolean; reason?: string } {
  try {
    if (clausesError(clauses) !== null) return { ok: false, reason: 'malformed clauses' };
    if (!certificateConsistent(cert, opts)) return { ok: false, reason: 'certificate table does not entail its decision' };
    const again = certify(clauses, ctx, opts);
    if (hashCanonical(again) !== hashCanonical(cert)) return { ok: false, reason: 'certificate does not match the recomputed decision' };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'certificate check error (fail closed)' };
  }
}
