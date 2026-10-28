/**
 * Principal review and signing for a Goal IR (goal-to-decision; closes W1 and W4).
 *
 * PolicyCard: a deterministic, template-only (no model) rendering of the WHOLE Goal, built from the same phrase table as the plain
 * text card (card.ts): every grant, prohibition, bound, validity window, delegation limit, escalation trigger, hole, wildcard and
 * confirmed boundary example, with exact numbers. Lossless-or-refuse: a clause that cannot be rendered and digested makes the card
 * fail; the card is never truncated (a truncated card would hide authority). Reviewer-fatigue limits (REVIEW_LIMITS) are hard caps
 * that REFUSE a goal or a diff that is too large to read; they never cut it down.
 *
 * semantic diff (`diffGoals`): clause-level, widenings first. Direction is conservative: anything not PROVEN narrower is counted as
 * a widening ("widen" or "unknown"). When the kernel can enumerate the actions newly allowed, they are listed first.
 *
 * GoalApproval: a pinned reviewer signs {goal_digest, policy_digest, card_digest, ontology_digest, tests_digest, nl_digest,
 * model_set_digest, expires_at (and the reviewer and approved_at)} with the suite-agile signer (sign.ts). `loadApprovedGoal` trusts
 * nothing the submission claims about itself: it recomputes the goal digest, recompiles the policy with the proved compiler,
 * re-renders the card, re-derives the tests, nl and model-set digests, and re-runs the confirmed examples, then checks the
 * signature. It refuses on holes, any digest mismatch, an unpinned reviewer, TTL, analyzer error, or an oversize card. The result
 * carries `ApprovedGoalRef`, the v3 goal binding (`goal_commit` = H(goal_digest || policy_digest), intent-binding.ts in @atlasauth/pca).
 *
 * GUARANTEED: no goal is loadable without a pinned reviewer's unexpired signature over the exact IR, compiled policy, rendered card,
 * ontology, tests, instruction and model set. NOT GUARANTEED: that the reviewer read the card, or that the instruction means what
 * the IR says (spec section 10).
 */

import { canonicalBytes, hashCanonical, type SignerSuiteOpts } from '@atlasauth/pca';
import { type ApprovedGoalRef, type IntentPolicy, intentGoalV3 } from '@atlasauth/pca/ext/intent';
import { boundLine, cond as condText, delegationLine, escalateLine, grantLine, holeLine, prohibitLine, quantity as quantityText, res as resText, validityLine } from './card';
import { compileGoal, decideGoal, policyDigest } from './compiler';
import { goalDigest, modelSetDigest, nlDigest } from './digests';
import { expectedDecision, testsDigest, type GoalTest } from './examples';
import type { Act, Bound, CompileResult, Cond, Decision, Delegation, Goal, Grant, Hist, Ontology, Policy, Prohibit, Validity } from './ir';
import { signGoalArtifact, verifyGoalArtifact, type PinnedSigner, type SignerSecret, signerId } from './sign';


/** The compiler/decision entry points this flow needs. The default is the proved compiler (`provedKernel`); tests may inject another. */
export interface ReviewKernel {
  /** C: Goal -> Policy | Escalate(reasons). Pure and total. */
  compile(goal: Goal, ont: Ontology): CompileResult;
  /** Content digest of the compiled policy. */
  policyDigest(policy: Policy): string;
  /** Error-level analyzer findings over the compiled policy; any finding refuses. */
  analyze?(policy: Policy): string[];
  /** The decision for an action (needed to re-run the confirmed examples). */
  decide?(goal: Goal, ont: Ontology, act: Act, hist: Hist): Decision;
  /** Actions allowed by `next` and not by `prev` (what a diff newly allows). */
  newlyAllowed?(prev: Goal, next: Goal, ont: Ontology, limit: number): { witnesses: Act[]; complete: boolean };
}

/** The extracted, machine-proved compiler (formal/dafny/GoalCompile.dfy) behind the typed bridge. */
export const provedKernel: ReviewKernel = { compile: compileGoal, policyDigest, decide: decideGoal };

// ---- limits (reviewer fatigue) ---------------------------------------------------------------------------

/** Hard caps on what a human is asked to read. Exceeding any REFUSES; nothing is ever truncated. */
export const REVIEW_LIMITS = {
  max_grants: 32,
  max_prohibits: 64,
  max_bounds: 32,
  max_escalate_on: 32,
  max_examples: 40,
  max_card_lines: 200,
  max_card_bytes: 24_576,
  max_diff_changes: 60,
  max_diff_widenings: 12,
  max_witnesses: 20,
} as const;
export type ReviewLimits = { -readonly [K in keyof typeof REVIEW_LIMITS]: number };

/** Caller overrides may only TIGHTEN a limit (a larger number is ignored). */
export function effectiveLimits(o?: Partial<ReviewLimits>): ReviewLimits {
  const out = { ...REVIEW_LIMITS } as ReviewLimits;
  if (o) for (const k of Object.keys(out) as Array<keyof ReviewLimits>) {
    const v = o[k];
    if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v < out[k]) out[k] = v;
  }
  return out;
}

export type ReviewRefusal = 'card_too_large' | 'unrenderable' | 'holes' | 'wildcard_unacknowledged' | 'diff_too_large' | 'too_many_widenings';
export class ReviewError extends Error {
  constructor(readonly code: ReviewRefusal, detail: string) {
    super(`goal review: ${code}: ${detail}`);
  }
}

// ---- digests ---------------------------------------------------------------------------------------------

const D_CARD = 'atlas-pca/policy-card/v1';
const D_CLAUSE = 'atlas-pca/goal-clause/v1';
export const GOAL_APPROVAL_KIND = 'goal-approval';
/** An approval may not be valid for longer than this. */
export const MAX_GOAL_APPROVAL_TTL_MS = 24 * 3_600_000;
const DEFAULT_TTL_MS = 3_600_000;

// ---- PolicyCard ------------------------------------------------------------------------------------------

export type CardKind = 'meta' | 'grant' | 'prohibit' | 'bound' | 'validity' | 'delegation' | 'escalate' | 'hole' | 'example';
export interface CardLine {
  /** Stable id of the clause (gid, pid, bid, example id, or a fixed name). */
  id: string;
  kind: CardKind;
  /** `red` for wildcards and holes: the lines a reviewer must not skim past. */
  severity: 'info' | 'red';
  text: string;
  /** Digest of the clause this line renders (the structured source of the sentence). */
  clause_digest: string;
}
export interface PolicyCard {
  v: 1;
  goal_digest: string;
  ontology_digest: string;
  nl_digest: string;
  principal: string;
  lines: CardLine[];
}

const jsonOf = (v: unknown): string => {
  try {
    return new TextDecoder().decode(canonicalBytes(v));
  } catch {
    throw new ReviewError('unrenderable', 'a clause has no canonical form (float, undefined or cycle)');
  }
};
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

function line(id: string, kind: CardKind, text: string, clause: unknown, severity: 'info' | 'red' = 'info'): CardLine {
  return { id, kind, severity, text, clause_digest: hashCanonical({ d: D_CLAUSE, kind, clause }) };
}

/** Number of clause lines a goal needs, without rendering (cheap cap check before any text is produced). */
function clauseCount(g: Goal, tests: readonly GoalTest[]): number {
  return 4 + g.grants.length + g.prohibits.length + g.bounds.length + g.escalateOn.length + g.holes.length + tests.length;
}

/** Clause text through the shared phrase table; an unknown clause shape (a future member) is shown as its canonical JSON, never dropped. */
function safeText(f: () => string, clause: unknown): string {
  try {
    const t = f();
    if (t.includes('undefined')) throw new Error('unknown clause shape');
    return t;
  } catch {
    return jsonOf(clause);
  }
}

/**
 * Render the card. Deterministic, no model, no locale. Throws ReviewError: `holes` (a draft is not reviewable for signing),
 * `wildcard_unacknowledged` (an `any` resource without a `wildcardAck` entry), `card_too_large` (a fatigue cap), `unrenderable`.
 * Pass `allowHoles` to render a DRAFT for display (the holes are rendered in red).
 */
export function renderPolicyCard(goal: Goal, tests: readonly GoalTest[] = [], opts: { limits?: Partial<ReviewLimits>; allowHoles?: boolean } = {}): PolicyCard {
  const L = effectiveLimits(opts.limits);
  const big = (what: string, n: number, max: number) => {
    if (n > max) throw new ReviewError('card_too_large', `${n} ${what} exceed the cap of ${max}: split the goal into smaller goals`);
  };
  if (!isObj(goal) || !Array.isArray(goal.grants) || !Array.isArray(goal.prohibits) || !Array.isArray(goal.bounds) || !Array.isArray(goal.escalateOn) || !Array.isArray(goal.holes) || !isObj(goal.validity) || !isObj(goal.deleg)) {
    throw new ReviewError('unrenderable', 'not a Goal IR');
  }
  big('grants', goal.grants.length, L.max_grants);
  big('prohibitions', goal.prohibits.length, L.max_prohibits);
  big('bounds', goal.bounds.length, L.max_bounds);
  big('escalation triggers', goal.escalateOn.length, L.max_escalate_on);
  big('boundary examples', tests.length, L.max_examples);
  big('card lines', clauseCount(goal, tests), L.max_card_lines);
  if (goal.holes.length > 0 && !opts.allowHoles) throw new ReviewError('holes', `${goal.holes.length} unresolved question(s): a goal with holes is a draft and cannot be signed`);

  const ack = new Set(Array.isArray(goal.wildcardAck) ? goal.wildcardAck : []);
  const lines: CardLine[] = [];
  lines.push(line('principal', 'meta', `Acting for principal ${jsonOf(goal.principal)}. Nothing outside this card is allowed (default deny).`, goal.principal));
  for (const g of goal.grants) {
    const wild = g.res?.k === 'any';
    if (wild && !ack.has(g.gid)) throw new ReviewError('wildcard_unacknowledged', `grant ${jsonOf(g.gid)} allows ANY resource without a wildcard acknowledgement`);
    lines.push(line(g.gid, 'grant', safeText(() => `${grantLine(g)}.${wild ? ' WILDCARD acknowledged by the principal.' : ''}`, g), g, wild ? 'red' : 'info'));
  }
  for (const p of goal.prohibits) lines.push(line(p.pid, 'prohibit', safeText(() => `${prohibitLine(p)}.`, p), p, p.res?.k === 'any' ? 'red' : 'info'));
  for (const b of goal.bounds) lines.push(line(b.bid, 'bound', safeText(() => `${boundLine(b)}.`, b), b));
  lines.push(line('validity', 'validity', safeText(() => `${validityLine(goal.validity)}.`, goal.validity), goal.validity));
  lines.push(line('delegation', 'delegation', safeText(() => `${delegationLine(goal.deleg)}.`, goal.deleg), goal.deleg, goal.deleg.narrowOnly ? 'info' : 'red'));
  goal.escalateOn.forEach((c, i) => lines.push(line(`escalate_on[${i}]`, 'escalate', safeText(() => `${escalateLine(c)}.`, c), c)));
  goal.holes.forEach((h, i) => lines.push(line(`hole[${i}]`, 'hole', safeText(() => `${holeLine(h)}. Everything depending on it is dropped.`, h), h, 'red')));
  for (const t of tests) {
    lines.push(line(`example:${t.id}`, 'example', `EXAMPLE you confirmed: ${jsonOf(t.act.verb)} on ${jsonOf(t.act.res)} with ${jsonOf(t.act.params)}${t.hist.adms.length > 0 ? ` after ${t.hist.adms.length} earlier admitted action(s)` : ''} must be ${t.answer === 'ask' ? 'ASKED about' : t.answer === 'allow' ? 'ALLOWED' : 'DENIED'}.`, t));
  }
  big('card lines', lines.length, L.max_card_lines);
  const card: PolicyCard = { v: 1, goal_digest: goalDigestOf(goal), ontology_digest: goal.ontDigest, nl_digest: goal.nlDigest, principal: goal.principal, lines };
  big('bytes of card', canonicalBytes(card).length, L.max_card_bytes);
  return card;
}

function goalDigestOf(goal: Goal): string {
  try {
    return goalDigest(goal);
  } catch {
    throw new ReviewError('unrenderable', 'the Goal has no canonical form (float, undefined or cycle)');
  }
}

export function cardDigest(card: PolicyCard): string {
  return hashCanonical({ d: D_CARD, card });
}

/** Plain-text form of a card for any console or terminal. Red lines are prefixed `!!`. */
export function cardToText(card: PolicyCard): string {
  return card.lines.map((l) => `${l.severity === 'red' ? '!! ' : '   '}${l.text}`).join('\n');
}

// ---- semantic diff ---------------------------------------------------------------------------------------

export type Direction = 'widen' | 'narrow' | 'neutral' | 'unknown';
export interface DiffChange {
  change: 'added' | 'removed' | 'changed';
  kind: CardKind;
  id: string;
  direction: Direction;
  text: string;
}
export interface DiffCard {
  v: 1;
  from_goal_digest: string;
  to_goal_digest: string;
  /** Actions the new goal allows and the old did not (kernel-computed), shown first. */
  newly_allowed: Act[];
  /** False when the kernel cannot list them all (or has no `newlyAllowed`): treat the diff as incomplete. */
  newly_allowed_complete: boolean;
  /** Widenings (`widen` and `unknown`) first, then the rest, each group in clause order. */
  changes: DiffChange[];
  widenings: number;
}

const same = (a: unknown, b: unknown): boolean => jsonOf(a) === jsonOf(b);
const conjuncts = (c: Cond): Cond[] => (c.k === 'and' ? [...conjuncts(c.a), ...conjuncts(c.b)] : c.k === 'true' ? [] : [c]);
/** new.cond is old.cond AND more (or equal): provably no wider. */
const whereNoWider = (oldW: Cond, newW: Cond): boolean => {
  const have = new Set(conjuncts(newW).map(jsonOf));
  return conjuncts(oldW).every((c) => have.has(jsonOf(c)));
};

function grantDir(o: Grant, n: Grant): Direction {
  if (same(o, n)) return 'neutral';
  return o.verb === n.verb && same(o.res, n.res) && whereNoWider(o.cond, n.cond) ? 'narrow' : 'unknown';
}
function prohibitDir(o: Prohibit, n: Prohibit): Direction {
  if (same(o, n)) return 'neutral';
  // A prohibition that triggers on MORE (old.cond is a conjunction containing new.cond) is a narrowing of the allow set.
  return same(o.target, n.target) && same(o.res, n.res) && whereNoWider(n.cond, o.cond) ? 'narrow' : 'unknown';
}
function boundDir(o: Bound, n: Bound): Direction {
  if (same(o, n)) return 'neutral';
  const rest = (b: Bound) => ({ ...b, cap: null });
  if (!same(rest(o), rest(n)) || !same(o.cap.u, n.cap.u)) return 'unknown';
  return n.cap.n < o.cap.n ? 'narrow' : n.cap.n > o.cap.n ? 'widen' : 'neutral';
}
/** maxIdle 0 means "no idle limit": the widest. */
const idle = (x: number): number => (x === 0 ? Number.POSITIVE_INFINITY : x);
function validityDir(o: Validity, n: Validity): Direction {
  if (same(o, n)) return 'neutral';
  const nar = n.notBefore >= o.notBefore && n.notAfter <= o.notAfter && idle(n.maxIdle) <= idle(o.maxIdle);
  const wid = n.notBefore <= o.notBefore && n.notAfter >= o.notAfter && idle(n.maxIdle) >= idle(o.maxIdle);
  return nar ? 'narrow' : wid ? 'widen' : 'unknown';
}
function delegationDir(o: Delegation, n: Delegation): Direction {
  if (same(o, n)) return 'neutral';
  const touchO = new Set(o.mayTouch);
  const touchN = new Set(n.mayTouch);
  const sub = [...touchN].every((x) => touchO.has(x));
  const sup = [...touchO].every((x) => touchN.has(x));
  const nar = n.maxDepth <= o.maxDepth && sub && (n.narrowOnly || !o.narrowOnly);
  const wid = n.maxDepth >= o.maxDepth && sup && (o.narrowOnly || !n.narrowOnly);
  return nar ? 'narrow' : wid ? 'widen' : 'unknown';
}

type Keyed<T> = Array<[string, T]>;
function pairs<T>(prev: Keyed<T>, next: Keyed<T>, kind: CardKind, dirs: { added: Direction; removed: Direction; changed: (o: T, n: T) => Direction }, text: (id: string, v: T) => string): DiffChange[] {
  const out: DiffChange[] = [];
  const pm = new Map(prev);
  const nm = new Map(next);
  for (const [id, v] of next) {
    const o = pm.get(id);
    if (o === undefined) out.push({ change: 'added', kind, id, direction: dirs.added, text: `ADDED ${text(id, v)}` });
    else if (!same(o, v)) out.push({ change: 'changed', kind, id, direction: dirs.changed(o, v), text: `CHANGED ${text(id, v)} (was: ${text(id, o)})` });
  }
  for (const [id, v] of prev) if (!nm.has(id)) out.push({ change: 'removed', kind, id, direction: dirs.removed, text: `REMOVED ${text(id, v)}` });
  return out;
}

/**
 * Clause-level semantic diff between the goal a principal approved before and the one now proposed. Widenings first.
 * Throws ReviewError `diff_too_large` / `too_many_widenings` past the fatigue caps: a diff a human cannot read is not
 * offered as one (approve a fresh, smaller goal instead). `ont` is only needed by a kernel that lists newly allowed actions.
 */
export function diffGoals(prev: Goal, next: Goal, kernel?: Pick<ReviewKernel, 'newlyAllowed'>, opts: { limits?: Partial<ReviewLimits>; ontology?: Ontology } = {}): DiffCard {
  const L = effectiveLimits(opts.limits);
  const gl = (id: string, g: Grant) => `grant ${jsonOf(id)}: ${jsonOf(g.verb)} on ${resText(g.res)} when ${condText(g.cond)}`;
  const pl = (id: string, p: Prohibit) => `prohibition ${jsonOf(id)}: ${p.target.k === 'verb' ? jsonOf(p.target.verb) : `effect class ${jsonOf(p.target.cls)}`} on ${resText(p.res)} when ${condText(p.cond)}`;
  const changes: DiffChange[] = [
    ...pairs(prev.grants.map((g) => [g.gid, g] as [string, Grant]), next.grants.map((g) => [g.gid, g] as [string, Grant]), 'grant', { added: 'widen', removed: 'narrow', changed: grantDir }, gl),
    ...pairs(prev.prohibits.map((p) => [p.pid, p] as [string, Prohibit]), next.prohibits.map((p) => [p.pid, p] as [string, Prohibit]), 'prohibit', { added: 'narrow', removed: 'widen', changed: prohibitDir }, pl),
    ...pairs(prev.bounds.map((b) => [b.bid, b] as [string, Bound]), next.bounds.map((b) => [b.bid, b] as [string, Bound]), 'bound', { added: 'narrow', removed: 'widen', changed: boundDir }, (id, b) => `bound ${jsonOf(id)}: ${boundLine(b)} (${quantityText(b.cap)})`),
    ...pairs(prev.escalateOn.map((c) => [jsonOf(c), c] as [string, Cond]), next.escalateOn.map((c) => [jsonOf(c), c] as [string, Cond]), 'escalate', { added: 'narrow', removed: 'widen', changed: () => 'unknown' }, (_id, c) => `escalation when ${condText(c)}`),
  ];
  if (!same(prev.validity, next.validity)) changes.push({ change: 'changed', kind: 'validity', id: 'validity', direction: validityDir(prev.validity, next.validity), text: `CHANGED validity: ${jsonOf(next.validity)} (was: ${jsonOf(prev.validity)})` });
  if (!same(prev.deleg, next.deleg)) changes.push({ change: 'changed', kind: 'delegation', id: 'delegation', direction: delegationDir(prev.deleg, next.deleg), text: `CHANGED delegation: ${jsonOf(next.deleg)} (was: ${jsonOf(prev.deleg)})` });
  // Identity of the actor, the vocabulary and the wildcard acknowledgements are never "neutral": a swap can widen.
  if (prev.principal !== next.principal) changes.push({ change: 'changed', kind: 'meta', id: 'principal', direction: 'unknown', text: `CHANGED principal: ${jsonOf(next.principal)} (was: ${jsonOf(prev.principal)})` });
  if (prev.ontDigest !== next.ontDigest) changes.push({ change: 'changed', kind: 'meta', id: 'ontology', direction: 'unknown', text: `CHANGED ontology: every term now means what the new vocabulary says (was ${jsonOf(prev.ontDigest)}, now ${jsonOf(next.ontDigest)})` });
  if (!same(prev.wildcardAck, next.wildcardAck)) changes.push({ change: 'changed', kind: 'meta', id: 'wildcard_ack', direction: 'unknown', text: `CHANGED wildcard acknowledgements: ${jsonOf(next.wildcardAck)} (was: ${jsonOf(prev.wildcardAck)})` });
  if (prev.nlDigest !== next.nlDigest) changes.push({ change: 'changed', kind: 'meta', id: 'instruction', direction: 'neutral', text: 'CHANGED the instruction text the goal was interpreted from' });

  const isWide = (c: DiffChange) => c.direction === 'widen' || c.direction === 'unknown';
  const widenings = changes.filter(isWide).length;
  if (changes.length > L.max_diff_changes) throw new ReviewError('diff_too_large', `${changes.length} changes exceed the cap of ${L.max_diff_changes}: review the new goal as a whole instead`);
  if (widenings > L.max_diff_widenings) throw new ReviewError('too_many_widenings', `${widenings} widenings exceed the cap of ${L.max_diff_widenings} per review`);
  const na = opts.ontology ? kernel?.newlyAllowed?.(prev, next, opts.ontology, L.max_witnesses) : undefined;
  return {
    v: 1,
    from_goal_digest: goalDigestOf(prev),
    to_goal_digest: goalDigestOf(next),
    newly_allowed: na ? na.witnesses.slice(0, L.max_witnesses) : [],
    newly_allowed_complete: na ? na.complete && na.witnesses.length <= L.max_witnesses : false,
    changes: [...changes.filter(isWide), ...changes.filter((c) => !isWide(c))],
    widenings,
  };
}

export function diffToText(d: DiffCard): string {
  const head = d.newly_allowed.map((w) => `!! NEWLY ALLOWED: ${jsonOf(w.verb)} on ${jsonOf(w.res)} with ${jsonOf(w.params)}`);
  if (!d.newly_allowed_complete) head.push('!! The list of newly allowed actions is incomplete or unavailable: read every widening below.');
  return [...head, ...d.changes.map((c) => `${c.direction === 'widen' || c.direction === 'unknown' ? '!! ' : '   '}${c.text}`)].join('\n');
}

// ---- GoalApproval ----------------------------------------------------------------------------------------

export interface GoalApproval {
  v: 1;
  goal_digest: string;
  policy_digest: string;
  card_digest: string;
  ontology_digest: string;
  tests_digest: string;
  nl_digest: string;
  model_set_digest: string;
  /** b64u Ed25519 public key of the reviewer (the pinned identity). */
  reviewer: string;
  approved_at: number;
  expires_at: number;
  sig: string;
  /** Suite members of the suite-agile signer (absent = Ed25519). */
  alg?: string;
  pq_pk?: string;
  pq_sig?: string;
}

/** The fields covered by the signature, in one place (a tamper test iterates this list). The suite members are signed too (signArtifact). */
export const GOAL_APPROVAL_SIGNED_FIELDS = ['v', 'goal_digest', 'policy_digest', 'card_digest', 'ontology_digest', 'tests_digest', 'nl_digest', 'model_set_digest', 'reviewer', 'approved_at', 'expires_at'] as const;

/** What a reviewer is shown and signs: the goal, its vocabulary, where it came from, the confirmed examples. */
export interface GoalSubmission {
  goal: Goal;
  /** The ontology the goal is typed against (its digest is `goal.ontDigest`; the host pins it with `ontology_digest`). */
  ontology: Ontology;
  /** The principal's instruction text. Its digest must equal `goal.nlDigest`. */
  instruction: string;
  /** Model ids that produced the goal (empty for the deterministic interpreter). */
  model_set: string[];
  tests?: GoalTest[];
}

export interface ApproveGoalOptions {
  kernel?: ReviewKernel;
  now?: number;
  ttlMs?: number;
  limits?: Partial<ReviewLimits>;
  /** The previously approved goal: when given, the diff must be reviewable (fatigue caps) or signing is refused. */
  base?: Goal;
  /** Post-quantum / hybrid suite of the signer (see @atlasauth/pca SignerSuiteOpts). */
  suite?: SignerSuiteOpts;
}

export type GoalRejection =
  | 'no_reviewers_pinned'
  | 'malformed_submission'
  | 'malformed_approval'
  | 'malformed_goal'
  | 'holes'
  | 'wildcard_unacknowledged'
  | 'card_too_large'
  | 'unrenderable'
  | 'instruction_mismatch'
  | 'compile_error'
  | 'analyzer_error'
  | 'tests_unverifiable'
  | 'tests_contradicted'
  | 'goal_digest_mismatch'
  | 'policy_digest_mismatch'
  | 'card_digest_mismatch'
  | 'ontology_mismatch'
  | 'tests_digest_mismatch'
  | 'nl_digest_mismatch'
  | 'model_set_digest_mismatch'
  | 'reviewer_not_pinned'
  | 'ttl_too_long'
  | 'not_yet_valid'
  | 'expired'
  | 'diff_too_large'
  | 'too_many_widenings'
  | 'bad_signature';

export interface ApprovedGoal {
  goal: Goal;
  ontology: Ontology;
  policy: Policy;
  /** What a v3 goal commitment binds (intent-binding.ts). */
  ref: ApprovedGoalRef;
  /** The `goal` string a wallet passes when it mints the root grant (commits to goal_digest || policy_digest). */
  goal_string: string;
  /** The verifier-side policy that makes `decideIntentBinding` open the grant against exactly this goal and policy. */
  intent_policy: IntentPolicy;
  instruction: string;
  reviewer: string;
  expires_at: number;
}
export type LoadedGoal = { ok: true; approved: ApprovedGoal } | { ok: false; reason: GoalRejection };

export interface LoadApprovedGoalOptions {
  kernel?: ReviewKernel;
  /** Pinned reviewers (b64u public key, or a PinnedSigner for a hybrid suite). Empty or absent: everything is refused. */
  reviewers: Array<string | PinnedSigner>;
  /** When set, the goal's ontology must be exactly this one (the host's pinned vocabulary). */
  ontology_digest?: string;
  now?: number;
  limits?: Partial<ReviewLimits>;
}

interface Digests {
  goal_digest: string;
  policy_digest: string;
  card_digest: string;
  ontology_digest: string;
  tests_digest: string;
  nl_digest: string;
  model_set_digest: string;
}

function derive(sub: GoalSubmission, kernel: ReviewKernel, limits?: Partial<ReviewLimits>): { ok: true; digests: Digests; policy: Policy } | { ok: false; reason: GoalRejection } {
  const bad = (reason: GoalRejection) => ({ ok: false as const, reason });
  if (!isObj(sub) || !isObj(sub.goal) || !isObj(sub.ontology) || typeof sub.instruction !== 'string' || !Array.isArray(sub.model_set) || sub.model_set.some((m) => typeof m !== 'string') || (sub.tests !== undefined && !Array.isArray(sub.tests))) return bad('malformed_submission');
  const tests = sub.tests ?? [];
  let card: PolicyCard;
  try {
    card = renderPolicyCard(sub.goal, tests, limits === undefined ? {} : { limits });
  } catch (e) {
    if (e instanceof ReviewError) return bad(e.code);
    return bad('malformed_goal');
  }
  let gd: string;
  let nl: string;
  let ts: string;
  let ms: string;
  try {
    gd = goalDigest(sub.goal);
    nl = nlDigest(sub.instruction);
    ts = testsDigest(tests);
    ms = modelSetDigest(sub.model_set);
  } catch {
    return bad('malformed_goal');
  }
  if (typeof sub.goal.nlDigest !== 'string' || nl !== sub.goal.nlDigest) return bad('instruction_mismatch');
  let compiled: CompileResult;
  try {
    compiled = kernel.compile(sub.goal, sub.ontology);
  } catch {
    return bad('compile_error');
  }
  if (!compiled.ok) return bad('compile_error');
  let pd: string;
  try {
    if ((kernel.analyze?.(compiled.policy) ?? []).length > 0) return bad('analyzer_error');
    pd = kernel.policyDigest(compiled.policy);
  } catch {
    return bad('analyzer_error');
  }
  if (tests.length > 0) {
    if (!kernel.decide) return bad('tests_unverifiable');
    // Regression pin (W4): the principal's confirmed examples must be reproduced by the policy we just compiled.
    for (const t of tests) {
      let got: Decision;
      try {
        got = kernel.decide(sub.goal, t.rels ? { ...sub.ontology, rels: t.rels } : sub.ontology, t.act, t.hist);
      } catch {
        return bad('tests_unverifiable');
      }
      if (got !== expectedDecision(t.answer)) return bad('tests_contradicted');
    }
  }
  return { ok: true, policy: compiled.policy, digests: { goal_digest: gd, policy_digest: pd, card_digest: cardDigest(card), ontology_digest: sub.goal.ontDigest, tests_digest: ts, nl_digest: nl, model_set_digest: ms } };
}

/**
 * The human step: sign the exact goal. Re-derives everything the loader will; throws ReviewError / Error when the goal is
 * not signable (holes, wildcard without ack, card or diff over the fatigue caps, compile or analyzer failure, a test the
 * compiled policy contradicts, an instruction that does not match `nlDigest`).
 */
export function approveGoal(sub: GoalSubmission, reviewerSecret: SignerSecret, opts: ApproveGoalOptions = {}): GoalApproval {
  const now = opts.now ?? Date.now();
  const ttl = opts.ttlMs ?? DEFAULT_TTL_MS;
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(ttl) || ttl <= 0 || ttl > MAX_GOAL_APPROVAL_TTL_MS) throw new Error('approveGoal: invalid time or ttl');
  const d = derive(sub, opts.kernel ?? provedKernel, opts.limits);
  if (!d.ok) throw new Error(`approveGoal: ${d.reason}`);
  if (opts.base) diffGoals(opts.base, sub.goal, undefined, { limits: opts.limits });
  const body = { ...d.digests, v: 1 as const, reviewer: signerId(reviewerSecret), approved_at: now, expires_at: now + ttl };
  return signGoalArtifact(GOAL_APPROVAL_KIND, body, reviewerSecret, opts.suite) as GoalApproval;
}

const fail = (reason: GoalRejection): { ok: false; reason: GoalRejection } => ({ ok: false, reason });
const isInt = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n);
const FIELD_REASON: Array<[keyof Digests, GoalRejection]> = [
  ['goal_digest', 'goal_digest_mismatch'],
  ['policy_digest', 'policy_digest_mismatch'],
  ['ontology_digest', 'ontology_mismatch'],
  ['tests_digest', 'tests_digest_mismatch'],
  ['nl_digest', 'nl_digest_mismatch'],
  ['model_set_digest', 'model_set_digest_mismatch'],
  ['card_digest', 'card_digest_mismatch'],
];

/**
 * The only door from a submitted goal to an enforceable one. Recomputes the goal digest, recompiles the policy, re-renders
 * the card and re-derives the tests, instruction and model-set digests from the submission; trusts nothing the submission
 * or the approval says about itself. Never throws.
 */
export function loadApprovedGoal(sub: GoalSubmission, approval: GoalApproval, opts: LoadApprovedGoalOptions): LoadedGoal {
  try {
    const now = opts.now ?? Date.now();
    if (!Array.isArray(opts.reviewers) || opts.reviewers.length === 0) return fail('no_reviewers_pinned');
    const a = approval as unknown;
    if (!isObj(a) || a.v !== 1 || typeof a.sig !== 'string' || typeof a.reviewer !== 'string' || !isInt(a.approved_at) || !isInt(a.expires_at) || FIELD_REASON.some(([f]) => typeof a[f] !== 'string')) return fail('malformed_approval');
    const d = derive(sub, opts.kernel ?? provedKernel, opts.limits);
    if (!d.ok) return d;
    if (opts.ontology_digest !== undefined && sub.goal.ontDigest !== opts.ontology_digest) return fail('ontology_mismatch');
    for (const [f, reason] of FIELD_REASON) if (a[f] !== d.digests[f]) return fail(reason);
    if (!opts.reviewers.some((p) => (typeof p === 'string' ? p : p.pk) === a.reviewer)) return fail('reviewer_not_pinned');
    if (a.expires_at - a.approved_at <= 0 || a.expires_at - a.approved_at > MAX_GOAL_APPROVAL_TTL_MS) return fail('ttl_too_long');
    if (a.approved_at > now) return fail('not_yet_valid');
    if (now >= a.expires_at) return fail('expired');
    if (!verifyGoalArtifact(GOAL_APPROVAL_KIND, a, 'reviewer', opts.reviewers)) return fail('bad_signature');
    const ref: ApprovedGoalRef = { goal_digest: d.digests.goal_digest, policy_digest: d.digests.policy_digest };
    return { ok: true, approved: { goal: sub.goal, ontology: sub.ontology, policy: d.policy, ref, goal_string: intentGoalV3(ref), intent_policy: { approved_goal: ref }, instruction: sub.instruction, reviewer: a.reviewer, expires_at: a.expires_at } };
  } catch {
    return fail('malformed_approval');
  }
}

