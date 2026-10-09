import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { sign, verifyB64u } from './keys';
import {
  evaluateCondition,
  evaluateConditionTri,
  isSafeRegexSource,
  MAX_RE_RESOURCE_LEN,
  predicateMatches,
  resolvePath,
  type ActionContext,
  type Condition,
  type ConditionOp,
  type Predicate,
} from './predicates';

/**
 * NEGATIVE AUTHORITY (frontier §3.2) — a principal-committed CONSTITUTION of invariants the agent
 * must NEVER violate, enforced independently of the permission plan.
 *
 *   permissions GRANT, prohibitions VETO, prohibitions WIN:   allow = permitted AND prohibitions.ok
 *
 * Pure data + pure functions, no eval, never throws (except the authoring-time `sign*` helpers).
 * Everything malformed / unknown / unresolvable FAILS CLOSED — and for a prohibition "closed" is
 * the OPPOSITE of the predicate DSL's direction: a permission predicate that cannot be evaluated
 * => not matched => denied, but a prohibition trigger that cannot be evaluated must => MATCHED
 * (the veto applies). See `whenMatches`. The single exception is a positive precondition
 * (`require_prior.prior`, `never_unless.unless`, `require_approval_over.approved`): those must hold
 * AFFIRMATIVELY, so for them "cannot evaluate" means "not satisfied" (still forbidden).
 *
 * Forms (a pragmatic safety subset; each is a runtime-verification monitor with tiny, explicit,
 * digestible state): `never`, `never_unless`, `cap`, `rate`, `never_after`, `require_prior`,
 * `require_approval_over`. See docs/pca-frontier/negative-authority.md.
 *
 * State is a canonical, digest-committed, hash-chained `MonitorState`; per-action evidence is
 * signable and bound to (action digest, constitution id, state digest).
 */

/** Constitution schema version. New invariant forms are additive: an older verifier rejects them (fail closed). */
export const CONSTITUTION_VERSION = 1;
/** Domain separator for the principal's constitution signature. */
export const CONSTITUTION_SIG_DOMAIN = 'atlas-pca/constitution/v1\0';
/** Evidence schema version. */
export const EVIDENCE_VERSION = 1;
/** Domain separator for a signer's signature over safety evidence. */
export const SAFETY_EVIDENCE_SIG_DOMAIN = 'atlas-pca/safety-evidence/v1\0';
/** Domain tag mixed into the canonical monitor-state digest. */
export const STATE_DIGEST_DOMAIN = 'atlas-pca/monitor-state/v1';
/** Domain tag mixed into the state hash-chain link. */
export const STATE_CHAIN_DOMAIN = 'atlas-pca/monitor-state-link/v1';

/** Max ledger entries kept per cap/rate invariant (older cap entries are merged, never dropped). */
export const MAX_LEDGER = 10_000;
/** Max invariants in one constitution. */
export const MAX_INVARIANTS = 256;
const MAX_STATE_ENTRIES = 100_000;
const MAX_STATE_KEYS = 1024;
const MAX_ID_LEN = 128;
/** Upper bound on a bounded-liveness deadline budget (see `MonitorState.deadlines`). */
export const MAX_DEADLINE = 1_000_000;
const FORBIDDEN_IDS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

// ---- types -----------------------------------------------------------------------------

/** Verb/resource matcher + optional conditions, same shape as the permission `Predicate`. */
export type When = Predicate;

interface InvBase {
  /** Unique within the constitution (<= 128 chars; not `__proto__`/`constructor`/`prototype`). */
  id: string;
  description?: string;
}
/** No action matching `when` may ever occur. */
export interface NeverInvariant extends InvBase {
  kind: 'never';
  when: When;
}
/** An action matching `when` is forbidden unless ALL `unless` conditions affirmatively hold (e.g. a human approved). */
export interface NeverUnlessInvariant extends InvBase {
  kind: 'never_unless';
  when: When;
  unless: Condition[];
}
/** Sum of `amount` (dotted path under `action.`) over matching actions in the window, incl. this one, must be <= max. */
export interface CapInvariant extends InvBase {
  kind: 'cap';
  when: When;
  amount: string;
  max: number;
  /** Rolling window in seconds; omitted = lifetime. */
  window_secs?: number;
}
/** At most `max` matching actions per rolling window (this one included). */
export interface RateInvariant extends InvBase {
  kind: 'rate';
  when: When;
  max: number;
  window_secs: number;
}
/** Once an action matching `after` has been admitted, no action matching `forbid` may ever follow. */
export interface NeverAfterInvariant extends InvBase {
  kind: 'never_after';
  after: When;
  forbid: When;
}
/**
 * An action matching `when` is forbidden until an action matching `prior` has been admitted (e.g.
 * "no deploy before a review"). `prior` is matched AFFIRMATIVELY (plain DSL semantics): an ambiguous
 * prerequisite never counts as satisfied.
 */
export interface RequirePriorInvariant extends InvBase {
  kind: 'require_prior';
  when: When;
  prior: When;
}
/**
 * An action matching `when` whose `amount` (an `action.*` path) is GREATER than `threshold` is
 * forbidden unless every `approved` condition affirmatively holds. A missing / negative / non-numeric
 * amount counts as over the threshold (approval required). Stateless.
 */
export interface RequireApprovalOverInvariant extends InvBase {
  kind: 'require_approval_over';
  when: When;
  amount: string;
  threshold: number;
  approved: Condition[];
}
/** Any supported invariant form. */
export type Invariant =
  | NeverInvariant
  | NeverUnlessInvariant
  | CapInvariant
  | RateInvariant
  | NeverAfterInvariant
  | RequirePriorInvariant
  | RequireApprovalOverInvariant;

/** The principal's set of invariants. */
export interface Constitution {
  version: number;
  /** Principal public key (b64u) that commits to (and signs) these prohibitions. */
  principal: string;
  invariants: Invariant[];
  issued_at?: number;
}
/** A constitution plus its content id and the principal's signature. */
export interface SignedConstitution extends Constitution {
  /** hashCanonical of the body (without `id`, `sig`). The commitment a PCActn/grant would bind. */
  id: string;
  sig: string;
}

/**
 * Running aggregate state for the stateful invariants. Plain JSON. Its CANONICAL digest
 * (`stateDigest`) goes into the evidence. Every admitted action advances it through
 * `advanceStateStrict`, which also extends a hash chain (`seq`, `parent`) so the state history is
 * tamper-evident and a server can compare-and-swap on it.
 */
export interface MonitorState {
  /** Evaluation time (epoch ms) — explicit, so the check is reproducible offline. Never before any recorded entry. */
  now: number;
  /** Number of admitted actions folded into this state (starts at 0). Monotonic CAS counter. */
  seq: number;
  /** Chain link to the previous state: hashCanonical({d, state: prevStateDigest, action: admittedActionDigest}); null at genesis. */
  parent: string | null;
  /** Per cap/rate invariant id: admitted matching actions (t = admit time ms, amount >= 0; rate uses 1). */
  ledger: Record<string, Array<{ t: number; amount: number }>>;
  /** Per never_after / require_prior invariant id: time the trigger was first observed. */
  latched: Record<string, number>;
  /**
   * OPTIONAL, additive (used only by the temporal-contract layer in `contracts.ts`): per
   * `responds_within` clause id, the remaining budget (count of upcoming actions) for its most
   * urgent open bounded-liveness obligation; the clause id is absent when no obligation is open. A
   * state without any open obligation has no `deadlines` (or an empty map) and is canonically and
   * digest-wise IDENTICAL to a plain prohibition `MonitorState` — so prohibition behavior is
   * unchanged (see `canonicalState`, which omits an empty `deadlines`).
   */
  deadlines?: Record<string, number>;
}

/** Outcome of evaluating the whole constitution against one action. */
export interface ProhibitionResult {
  ok: boolean;
  /** Ids of violated invariants (or '<constitution>' / '<action>' / '<state>' for structural failures). */
  violated: string[];
  reasons: string[];
  /** Every invariant considered, in constitution order (no short-circuit) — feeds the evidence. */
  evaluated: Array<{ id: string; kind: string; result: 'pass' | 'violated'; reason?: string }>;
}

// ---- constitution commitment -----------------------------------------------------------

/** Genesis monitor state at time `now`: empty ledger, no latches, seq 0, no parent. */
export function emptyState(now: number): MonitorState {
  return { now, seq: 0, parent: null, ledger: {}, latched: {} };
}

function body(c: Constitution): Constitution {
  const { id: _id, sig: _sig, ...rest } = c as SignedConstitution;
  void _id;
  void _sig;
  return rest;
}
function domainMessage(domain: string, id: string): Uint8Array {
  const pre = utf8(domain);
  const d = sha256(utf8(id));
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}
const sigMessage = (id: string): Uint8Array => domainMessage(CONSTITUTION_SIG_DOMAIN, id);

/** Content address of a constitution body. Throws only on non-canonicalizable input (authoring time). */
export function constitutionId(c: Constitution): string {
  return hashCanonical(body(c));
}

/** Principal signs the constitution. Refuses to sign a malformed one (authoring-time guard). */
export function signConstitution(c: Constitution, principalSecret: Uint8Array): SignedConstitution {
  const problems = validateConstitution(c);
  if (problems.length) throw new TypeError('signConstitution: ' + problems.join('; '));
  const id = constitutionId(c);
  return { ...body(c), id, sig: b64u(sign(principalSecret, sigMessage(id))) };
}

/** Verify: well-formed, id matches content, signature by `expectedPrincipal` (or the embedded one). Never throws. */
export function verifyConstitution(sc: SignedConstitution, expectedPrincipal?: string): { ok: boolean; reason?: string } {
  try {
    const problems = validateConstitution(sc);
    if (problems.length) return { ok: false, reason: problems[0] };
    if (expectedPrincipal !== undefined && sc.principal !== expectedPrincipal) return { ok: false, reason: 'principal mismatch' };
    if (typeof sc.id !== 'string' || sc.id !== constitutionId(sc)) return { ok: false, reason: 'id does not match content' };
    if (typeof sc.sig !== 'string' || !verifyB64u(sc.principal, sigMessage(sc.id), sc.sig)) return { ok: false, reason: 'bad signature' };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'verification error (fail closed)' };
  }
}

// ---- validation (strict; unknown forms are rejected, never ignored) --------------------

const OPS: ReadonlySet<string> = new Set<ConditionOp>([
  'eq',
  'ne',
  'in',
  'nin',
  'lt',
  'lte',
  'gt',
  'gte',
  'prefix',
  'exists',
  'like',
  'matches',
  'is_a',
  'member_of',
]);
const isObj = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);
const fin = (x: unknown): x is number => typeof x === 'number' && Number.isFinite(x);
const has = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** Max nesting depth of a boolean-grouping condition tree (authoring-time bound; fail closed beyond). */
const MAX_CONDITION_DEPTH = 32;

function validateCondition(c: unknown, depth = 0): string | null {
  if (!isObj(c)) return 'condition not an object';
  if (depth > MAX_CONDITION_DEPTH) return 'condition nesting too deep';
  // Boolean groupings: validate children recursively.
  if (has(c, 'all_of') || has(c, 'any_of') || has(c, 'not')) {
    if (has(c, 'not')) {
      return validateCondition(c['not'], depth + 1);
    }
    const key = has(c, 'all_of') ? 'all_of' : 'any_of';
    const arr = c[key];
    if (!Array.isArray(arr) || arr.length === 0) return `condition.${key} must be a non-empty array`;
    for (const child of arr) {
      const e = validateCondition(child, depth + 1);
      if (e) return e;
    }
    return null;
  }
  if (typeof c.field !== 'string' || !c.field) return 'condition.field missing';
  if (typeof c.op !== 'string' || !OPS.has(c.op)) return `unknown condition op ${String(c.op)}`;
  if (c.ref !== undefined && (typeof c.ref !== 'string' || !c.ref)) return 'bad condition.ref';
  if (c.op === 'member_of' && c.collection !== undefined && (typeof c.collection !== 'string' || !c.collection)) {
    return 'bad condition.collection';
  }
  return null;
}
function validateConditions(cs: unknown, label: string): string | null {
  if (!Array.isArray(cs) || cs.length === 0) return `${label} must be a non-empty array`;
  for (const c of cs) {
    const e = validateCondition(c);
    if (e) return e;
  }
  return null;
}
export function validateWhen(w: unknown, label: string): string | null {
  if (!isObj(w)) return `${label}: not an object`;
  const v = w.verb;
  const verbOk = (typeof v === 'string' && v.length > 0) || (Array.isArray(v) && v.length > 0 && v.every((x) => typeof x === 'string' && x.length > 0));
  if (!verbOk) return `${label}: bad verb`;
  if (w.resource !== undefined) {
    if (typeof w.resource !== 'string') return `${label}: bad resource`;
    if (w.resource.startsWith('re:')) {
      const src = w.resource.slice(3);
      // An unsafe/over-long/uncompilable regex would make the matcher return false => the veto would silently NOT apply.
      if (src.length > 200 || !isSafeRegexSource(src)) return `${label}: unsafe regex resource`;
      try {
        new RegExp('^(?:' + src + ')$');
      } catch {
        return `${label}: invalid regex resource`;
      }
    }
  }
  if (w.where !== undefined) {
    if (!Array.isArray(w.where)) return `${label}: where not an array`;
    for (const c of w.where) {
      const e = validateCondition(c);
      if (e) return `${label}: ${e}`;
    }
  }
  return null;
}

/** Structural problems with an invariant (empty = well-formed). */
export function validateInvariant(inv: unknown): string[] {
  if (!isObj(inv)) return ['invariant not an object'];
  const rawId = inv.id;
  if (typeof rawId !== 'string' || !rawId) return ['<no id>: missing id'];
  const id = rawId;
  const err = (m: string) => [`${id}: ${m}`];
  if (id.length > MAX_ID_LEN) return err('id too long');
  if (FORBIDDEN_IDS.has(id)) return err('forbidden id');
  let e: string | null;
  switch (inv.kind) {
    case 'never':
      return (e = validateWhen(inv.when, 'when')) ? err(e) : [];
    case 'never_unless': {
      if ((e = validateWhen(inv.when, 'when'))) return err(e);
      if ((e = validateConditions(inv.unless, 'unless'))) return err(e);
      return [];
    }
    case 'cap':
      if ((e = validateWhen(inv.when, 'when'))) return err(e);
      if (typeof inv.amount !== 'string' || !inv.amount.startsWith('action.')) return err('amount must be an action.* path');
      if (!fin(inv.max) || inv.max < 0) return err('max must be a finite number >= 0');
      if (inv.window_secs !== undefined && (!fin(inv.window_secs) || inv.window_secs <= 0)) return err('bad window_secs');
      return [];
    case 'rate':
      if ((e = validateWhen(inv.when, 'when'))) return err(e);
      if (!Number.isInteger(inv.max) || (inv.max as number) < 0 || (inv.max as number) > MAX_LEDGER) return err('max must be an integer in [0,10000]');
      if (!fin(inv.window_secs) || inv.window_secs <= 0) return err('window_secs must be > 0');
      return [];
    case 'never_after':
      if ((e = validateWhen(inv.after, 'after')) || (e = validateWhen(inv.forbid, 'forbid'))) return err(e);
      return [];
    case 'require_prior':
      if ((e = validateWhen(inv.when, 'when')) || (e = validateWhen(inv.prior, 'prior'))) return err(e);
      return [];
    case 'require_approval_over':
      if ((e = validateWhen(inv.when, 'when'))) return err(e);
      if (typeof inv.amount !== 'string' || !inv.amount.startsWith('action.')) return err('amount must be an action.* path');
      if (!fin(inv.threshold) || inv.threshold < 0) return err('threshold must be a finite number >= 0');
      if ((e = validateConditions(inv.approved, 'approved'))) return err(e);
      return [];
    default:
      return err(`unknown invariant kind ${String(inv.kind)}`);
  }
}

/** Structural problems with a constitution (empty = well-formed). */
export function validateConstitution(c: unknown): string[] {
  if (!isObj(c)) return ['constitution not an object'];
  const out: string[] = [];
  if (c.version !== CONSTITUTION_VERSION) out.push(`unsupported version ${String(c.version)}`);
  if (typeof c.principal !== 'string' || !c.principal) out.push('principal missing');
  if (!Array.isArray(c.invariants)) return [...out, 'invariants not an array'];
  if (c.invariants.length > MAX_INVARIANTS) out.push('too many invariants');
  const seen = new Set<string>();
  for (const inv of c.invariants) {
    out.push(...validateInvariant(inv));
    const id = isObj(inv) ? inv.id : undefined;
    if (typeof id === 'string') {
      if (seen.has(id)) out.push(`${id}: duplicate id`);
      seen.add(id);
    }
  }
  return out;
}

// ---- canonical monitor state ------------------------------------------------------------

/** Structural problem with a monitor state (null = well-formed). Total; never throws. */
export function stateProblem(state: unknown): string | null {
  try {
    if (!isObj(state) || !fin(state.now) || !isObj(state.ledger) || !isObj(state.latched)) return 'malformed monitor state';
    if (!Number.isInteger(state.seq) || (state.seq as number) < 0) return 'malformed monitor state: seq';
    if (state.parent !== null && typeof state.parent !== 'string') return 'malformed monitor state: parent';
    if ((state.seq as number) === 0 && state.parent !== null) return 'malformed monitor state: genesis has a parent';
    if ((state.seq as number) > 0 && state.parent === null) return 'malformed monitor state: missing chain link';
    const now = state.now;
    const lk = Object.keys(state.ledger);
    const nk = Object.keys(state.latched);
    if (lk.length > MAX_STATE_KEYS || nk.length > MAX_STATE_KEYS) return 'malformed monitor state: too many keys';
    let total = 0;
    for (const k of lk) {
      if (FORBIDDEN_IDS.has(k) || k.length > MAX_ID_LEN) return 'malformed monitor state: bad ledger key';
      const l = (state.ledger as Record<string, unknown>)[k];
      if (!Array.isArray(l) || l.length > MAX_LEDGER) return 'malformed monitor state: bad ledger';
      total += l.length;
      for (const e of l) {
        if (!isObj(e) || !fin(e.t) || !fin(e.amount) || e.amount < 0) return 'malformed monitor state: bad ledger entry';
        // an entry from the "future" would be ignored by the window and so UNDER-count: refuse (clock regression)
        if (e.t > now) return 'malformed monitor state: ledger entry after now (clock regression)';
      }
    }
    if (total > MAX_STATE_ENTRIES) return 'malformed monitor state: too many entries';
    for (const k of nk) {
      if (FORBIDDEN_IDS.has(k) || k.length > MAX_ID_LEN) return 'malformed monitor state: bad latch key';
      const t = (state.latched as Record<string, unknown>)[k];
      if (!fin(t) || t > now) return 'malformed monitor state: bad latch';
    }
    // Additive, optional: bounded-liveness deadline budgets (contracts.ts). Absent/empty is a plain state.
    if (state.deadlines !== undefined) {
      if (!isObj(state.deadlines)) return 'malformed monitor state: deadlines';
      const dk = Object.keys(state.deadlines);
      if (dk.length > MAX_STATE_KEYS) return 'malformed monitor state: too many deadline keys';
      for (const k of dk) {
        if (FORBIDDEN_IDS.has(k) || k.length > MAX_ID_LEN) return 'malformed monitor state: bad deadline key';
        const d = (state.deadlines as Record<string, unknown>)[k];
        // an open obligation always has a strictly positive, integral remaining budget (0 => it would
        // already have been a violation, never persisted)
        if (!Number.isInteger(d) || (d as number) < 1 || (d as number) > MAX_DEADLINE) return 'malformed monitor state: bad deadline';
      }
    }
    return null;
  } catch {
    return 'malformed monitor state';
  }
}

/** Canonical, digest-committed projection of a `MonitorState`. */
export interface CanonState {
  d: string;
  now: number;
  seq: number;
  parent: string | null;
  ledger: Record<string, Array<{ t: number; amount: number }>>;
  latched: Record<string, number>;
  /** Present (and digest-bound) ONLY when at least one bounded-liveness obligation is open. */
  deadlines?: Record<string, number>;
}
const cmpEntry = (a: { t: number; amount: number }, b: { t: number; amount: number }) => a.t - b.t || a.amount - b.amount;

/**
 * Canonical form of a state: unknown fields dropped, ledger entries reduced to {t, amount} and sorted
 * by (t, amount), empty ledger arrays omitted (so `{}` and `{id: []}` are the same state), keys sorted
 * by canonical serialization. Order of the input entries therefore never changes the digest. Throws
 * TypeError on a malformed state.
 */
export function canonicalState(state: MonitorState): CanonState {
  const p = stateProblem(state);
  if (p) throw new TypeError(p);
  const ledger: CanonState['ledger'] = {};
  for (const k of Object.keys(state.ledger)) {
    const l = state.ledger[k]!.map((e) => ({ t: e.t, amount: e.amount })).sort(cmpEntry);
    if (l.length) ledger[k] = l;
  }
  const latched: CanonState['latched'] = {};
  for (const k of Object.keys(state.latched)) latched[k] = state.latched[k]!;
  const base: CanonState = { d: STATE_DIGEST_DOMAIN, now: state.now, seq: state.seq, parent: state.parent, ledger, latched };
  // Additive: bind open bounded-liveness deadlines. OMITTED when empty so a plain prohibition state's
  // canonical form (and digest) is byte-identical to before this field existed (backward compatible).
  if (state.deadlines !== undefined) {
    const deadlines: Record<string, number> = {};
    let any = false;
    for (const k of Object.keys(state.deadlines)) {
      deadlines[k] = state.deadlines[k]!;
      any = true;
    }
    if (any) base.deadlines = deadlines;
  }
  return base;
}

/** Deterministic digest of the canonical state. Pins window buckets, latches, time, seq and chain link. Throws TypeError if malformed. */
export function stateDigest(state: MonitorState): string {
  return hashCanonical(canonicalState(state));
}

/**
 * Deterministic clock tick: the same state at a later `now`. Refuses regression (`now` before the
 * state's own `now`). Never throws.
 */
export function tickState(state: MonitorState, now: number): { ok: true; state: MonitorState } | { ok: false; reason: string } {
  if (stateProblem(state)) return { ok: false, reason: 'malformed monitor state' };
  if (!fin(now) || now < state.now) return { ok: false, reason: 'clock regression' };
  return { ok: true, state: { ...state, now } };
}

// ---- matching (conservative: unresolvable => MATCHED) -----------------------------------

/**
 * Condition truth for a PROHIBITION trigger: anything that cannot be evaluated cleanly counts as TRUE
 * (the veto applies). This is exactly "the condition is not CLEANLY FALSE", i.e. the shared tri-valued
 * evaluator returning anything other than `'false'`. It therefore recurses through boolean groupings
 * in the fail-safe direction automatically: a malformed/unknown/unresolvable leaf is `'unknown'` =>
 * veto; an `all_of` fires unless some child is provably false; an `any_of` fires if any child could
 * hold; a `not` fires unless its inner condition is provably true. Byte-identical to the previous
 * hand-rolled logic on every pre-existing leaf op.
 */
function conditionConservative(c: Condition, ctx: ActionContext): boolean {
  return evaluateConditionTri(c, ctx) !== 'false';
}

/**
 * Does a prohibition trigger match? verb+resource exactly as the permission DSL; where-conditions
 * conservatively. FULLY fail-closed: a malformed trigger, an unsafe/uncompilable regex, an oversized
 * regex subject, an unknown op, a missing field/ref/operand, unavailable params or incomparable
 * operands all count as MATCHED (the veto applies). Never throws.
 */
export function whenMatches(w: When, ctx: ActionContext): boolean {
  try {
    if (validateWhen(w, 'when')) return true;
    const a = ctx?.action;
    if (!a || typeof a.verb !== 'string' || typeof a.resource !== 'string') return true;
    const oversized = typeof w.resource === 'string' && w.resource.startsWith('re:') && a.resource.length > MAX_RE_RESOURCE_LEN;
    // oversized subject for a regex resource: the matcher would say "no match" — a veto must say "match"
    if (!predicateMatches({ verb: w.verb, ...(oversized ? {} : { resource: w.resource }) }, ctx)) return false;
    for (const c of w.where ?? []) if (!conditionConservative(c, ctx)) return false;
    return true;
  } catch {
    return true; // cannot evaluate => the veto applies
  }
}

/** AFFIRMATIVE trigger match (plain permission-DSL semantics, unresolvable => not matched). Used for positive preconditions and `always`/`responds_within` responses. */
export function whenAffirmative(w: When, ctx: ActionContext): boolean {
  try {
    return validateWhen(w, 'when') === null && predicateMatches(w, ctx);
  } catch {
    return false;
  }
}

const allHold = (cs: Condition[], ctx: ActionContext): boolean => cs.every((c) => evaluateCondition(c, ctx));

// ---- the monitor -----------------------------------------------------------------------

/** Window entries (sorted so float sums are order-independent). `state` must already be validated. */
const windowEntries = (state: MonitorState, id: string, windowSecs: number | undefined) => {
  const l = has(state.ledger, id) ? state.ledger[id] : undefined;
  if (!Array.isArray(l)) return [];
  const lo = windowSecs === undefined ? -Infinity : state.now - windowSecs * 1000;
  return l.filter((e) => e.t > lo && e.t <= state.now).sort(cmpEntry);
};

function evalOne(inv: Invariant, ctx: ActionContext, state: MonitorState): { ok: boolean; reason?: string } {
  switch (inv.kind) {
    case 'never':
      return whenMatches(inv.when, ctx) ? { ok: false, reason: inv.description ?? 'forbidden action' } : { ok: true };
    case 'never_unless': {
      if (!whenMatches(inv.when, ctx)) return { ok: true };
      // exceptions must hold AFFIRMATIVELY (plain DSL semantics: unresolvable => false => still forbidden)
      return allHold(inv.unless, ctx) ? { ok: true } : { ok: false, reason: inv.description ?? 'forbidden without required condition' };
    }
    case 'cap': {
      if (!whenMatches(inv.when, ctx)) return { ok: true };
      const a = resolvePath(ctx, inv.amount);
      if (!a.found || !fin(a.value) || a.value < 0) return { ok: false, reason: 'amount unresolvable (fail closed)' };
      const spent = windowEntries(state, inv.id, inv.window_secs).reduce((s, e) => s + e.amount, 0);
      return spent + a.value <= inv.max ? { ok: true } : { ok: false, reason: `cap exceeded: ${spent} + ${a.value} > ${inv.max}` };
    }
    case 'rate': {
      if (!whenMatches(inv.when, ctx)) return { ok: true };
      const n = windowEntries(state, inv.id, inv.window_secs).length;
      return n + 1 <= inv.max ? { ok: true } : { ok: false, reason: `rate exceeded: ${n + 1} > ${inv.max} per ${inv.window_secs}s` };
    }
    case 'never_after': {
      if (!has(state.latched, inv.id) || !whenMatches(inv.forbid, ctx)) return { ok: true };
      return { ok: false, reason: inv.description ?? 'forbidden after trigger' };
    }
    case 'require_prior': {
      if (!whenMatches(inv.when, ctx)) return { ok: true };
      return has(state.latched, inv.id) ? { ok: true } : { ok: false, reason: inv.description ?? 'required prior action not admitted' };
    }
    case 'require_approval_over': {
      if (!whenMatches(inv.when, ctx)) return { ok: true };
      const a = resolvePath(ctx, inv.amount);
      const over = !a.found || !fin(a.value) || a.value < 0 || a.value > inv.threshold; // unresolvable => treated as over
      if (!over) return { ok: true };
      return allHold(inv.approved, ctx) ? { ok: true } : { ok: false, reason: inv.description ?? `approval required over ${inv.threshold}` };
    }
  }
}

/**
 * Evaluate EVERY invariant (no short-circuit) against the action and running state. Pure, total,
 * fail-closed: a malformed constitution, action, state or invariant yields ok:false.
 */
export function checkProhibitions(action: ActionContext, constitution: Constitution, state: MonitorState): ProhibitionResult {
  const fail = (id: string, reason: string): ProhibitionResult => ({
    ok: false,
    violated: [id],
    reasons: [reason],
    evaluated: [{ id, kind: 'structural', result: 'violated', reason }],
  });
  try {
    const cp = validateConstitution(constitution);
    if (cp.length) return fail('<constitution>', cp[0]!);
    const a = action?.action;
    if (!a || typeof a.verb !== 'string' || typeof a.resource !== 'string') return fail('<action>', 'malformed action');
    const sp = stateProblem(state);
    if (sp) return fail('<state>', sp);
    const evaluated: ProhibitionResult['evaluated'] = [];
    for (const inv of constitution.invariants) {
      let r: { ok: boolean; reason?: string };
      try {
        r = evalOne(inv, action, state);
      } catch {
        r = { ok: false, reason: 'evaluation error (fail closed)' };
      }
      evaluated.push({ id: inv.id, kind: inv.kind, result: r.ok ? 'pass' : 'violated', ...(r.reason ? { reason: r.reason } : {}) });
    }
    const bad = evaluated.filter((e) => e.result === 'violated');
    return { ok: bad.length === 0, violated: bad.map((e) => e.id), reasons: bad.map((e) => `${e.id}: ${e.reason ?? 'violated'}`), evaluated };
  } catch {
    return fail('<monitor>', 'monitor error (fail closed)');
  }
}

/** Result of a strict state transition. */
export type AdvanceResult = { ok: true; state: MonitorState } | { ok: false; reason: string };

/**
 * Pure, deterministic state transition for an ADMITTED action (call only after the full authority
 * decision said allow). Records cap/rate contributions, latches never_after / require_prior triggers,
 * prunes expired window entries, bounds the ledger, then extends the hash chain
 * (`seq+1`, `parent = H(prev state digest, action digest)`). Returns `{ok:false}` — never a silently
 * unchanged state — on anything it cannot record faithfully (malformed input, `now` before
 * `state.now`, unresolvable cap amount, rate-ledger overflow), because a dropped contribution would
 * UNDER-count a cap. The ledger content is order-independent (sorted multiset; earliest latch);
 * the chain link is order-dependent by design. Never throws.
 */
export function advanceStateStrict(action: ActionContext, constitution: Constitution, state: MonitorState, now: number = state?.now): AdvanceResult {
  try {
    const cp = validateConstitution(constitution);
    if (cp.length) return { ok: false, reason: cp[0]! };
    const sp = stateProblem(state);
    if (sp) return { ok: false, reason: sp };
    if (!fin(now) || now < state.now) return { ok: false, reason: 'clock regression' };
    const a = action?.action;
    if (!a || typeof a.verb !== 'string' || typeof a.resource !== 'string') return { ok: false, reason: 'malformed action' };
    const canon = canonicalState(state);
    const prevDigest = hashCanonical(canon);
    const actionDigest = hashCanonical(action);
    const ledger: MonitorState['ledger'] = {};
    for (const [k, v] of Object.entries(canon.ledger)) ledger[k] = v.slice();
    const latched: MonitorState['latched'] = { ...canon.latched };
    for (const inv of constitution.invariants) {
      if (inv.kind === 'cap' || inv.kind === 'rate') {
        const prev = has(ledger, inv.id) ? ledger[inv.id]! : [];
        const lo = inv.window_secs === undefined ? -Infinity : now - inv.window_secs * 1000;
        const kept = prev.filter((e) => e.t > lo);
        if (whenMatches(inv.when, action)) {
          let amount = 1;
          if (inv.kind === 'cap') {
            const r = resolvePath(action, inv.amount);
            if (!r.found || !fin(r.value) || r.value < 0) return { ok: false, reason: `${inv.id}: amount unresolvable` };
            amount = r.value;
          }
          kept.push({ t: now, amount });
        }
        kept.sort(cmpEntry);
        if (kept.length > MAX_LEDGER) {
          if (inv.kind === 'rate') return { ok: false, reason: `${inv.id}: rate ledger overflow` };
          while (kept.length > MAX_LEDGER) {
            const [x, y] = kept.splice(0, 2); // merge oldest two; keeps the LATER time => never under-counts a cap
            kept.unshift({ t: y!.t, amount: x!.amount + y!.amount });
          }
        }
        if (kept.length) ledger[inv.id] = kept;
        else delete ledger[inv.id];
      } else if (inv.kind === 'never_after') {
        // conservative match: an ambiguous trigger latches (stricter)
        if (!has(latched, inv.id) && whenMatches(inv.after, action)) latched[inv.id] = now;
      } else if (inv.kind === 'require_prior') {
        // AFFIRMATIVE match: an ambiguous prerequisite must NOT count as satisfied
        if (!has(latched, inv.id) && whenAffirmative(inv.prior, action)) latched[inv.id] = now;
      }
    }
    const next: MonitorState = {
      now,
      seq: state.seq + 1,
      parent: hashCanonical({ d: STATE_CHAIN_DOMAIN, state: prevDigest, action: actionDigest }),
      ledger,
      latched,
    };
    if (stateProblem(next)) return { ok: false, reason: 'resulting state invalid' };
    return { ok: true, state: next };
  } catch {
    return { ok: false, reason: 'advance error (fail closed)' };
  }
}

/**
 * Convenience wrapper over `advanceStateStrict` that returns the INPUT state unchanged on failure.
 * Prefer the strict form wherever a silent no-op would be unsafe (it would under-count a cap).
 */
export function advanceState(action: ActionContext, constitution: Constitution, state: MonitorState, now: number = state?.now): MonitorState {
  const r = advanceStateStrict(action, constitution, state, now);
  return r.ok ? r.state : state;
}

// ---- per-action safety evidence --------------------------------------------------------

/** Unsigned evidence that admitting one action preserves every invariant. Re-derivable offline. */
export interface ProhibitionEvidence {
  v: number;
  /** Constitution content id the check ran against. */
  constitution: string;
  /** hashCanonical(action context). */
  action_digest: string;
  /** `stateDigest` of the monitor state the check ran against (canonical). */
  state_digest: string;
  now: number;
  /** One row per invariant, constitution order. */
  evaluated: ProhibitionResult['evaluated'];
  ok: boolean;
  violated: string[];
}

const UNHASHABLE = '<unhashable>';
const safe = (f: () => string): string => {
  try {
    return f();
  } catch {
    return UNHASHABLE;
  }
};

/**
 * Build the evidence a verifier re-checks. Never throws. Anything that cannot be digested (action,
 * constitution or state) makes the evidence ok:false with the matching structural id in `violated`.
 */
export function proveSafety(action: ActionContext, constitution: Constitution, state: MonitorState): ProhibitionEvidence {
  const r = checkProhibitions(action, constitution, state);
  const cid = safe(() => constitutionId(constitution));
  const adg = safe(() => hashCanonical(action));
  const sdg = safe(() => stateDigest(state));
  const extra: string[] = [];
  if (cid === UNHASHABLE) extra.push('<constitution>');
  if (adg === UNHASHABLE) extra.push('<action>');
  if (sdg === UNHASHABLE) extra.push('<state>');
  return {
    v: EVIDENCE_VERSION,
    constitution: cid,
    action_digest: adg,
    state_digest: sdg,
    now: fin(state?.now) ? state.now : 0,
    evaluated: r.evaluated,
    ok: r.ok && extra.length === 0,
    violated: [...r.violated, ...extra.filter((x) => !r.violated.includes(x))],
  };
}

/** Digest of an evidence record (what a PCActn `safety` field would carry). */
export const evidenceDigest = (e: ProhibitionEvidence): string => hashCanonical(e);

/**
 * Offline re-check: recompute the monitor from (action, constitution, state) and require the
 * evidence to match EXACTLY, covering every invariant. Evidence claiming ok is only accepted if the
 * recomputation also says ok, so forged "all clear" evidence is rejected. Never throws.
 */
export function verifySafetyEvidence(
  evidence: ProhibitionEvidence,
  action: ActionContext,
  constitution: Constitution,
  state: MonitorState,
): { ok: boolean; reason?: string } {
  try {
    if (!evidence || evidence.v !== EVIDENCE_VERSION) return { ok: false, reason: 'unsupported evidence version' };
    const fresh = proveSafety(action, constitution, state);
    if (fresh.constitution !== evidence.constitution) return { ok: false, reason: 'constitution mismatch' };
    if (fresh.action_digest !== evidence.action_digest) return { ok: false, reason: 'action digest mismatch' };
    if (fresh.state_digest !== evidence.state_digest) return { ok: false, reason: 'state digest mismatch' };
    if (hashCanonical(fresh) !== hashCanonical(evidence)) return { ok: false, reason: 'evidence does not reproduce' };
    if (!fresh.ok) return { ok: false, reason: 'prohibition violated: ' + fresh.violated.join(',') };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'verification error (fail closed)' };
  }
}

// ---- signed + bound safety evidence -----------------------------------------------------

/**
 * Evidence signed by a monitor/guardian key. The signature covers `id`, which commits to the signer
 * and to (evidence digest, constitution id, action digest, state digest): it cannot be lifted onto
 * another action, constitution or state, nor re-attributed to another signer.
 */
export interface SignedSafetyEvidence {
  evidence: ProhibitionEvidence;
  /** Signer public key (b64u). */
  signer: string;
  /** hashCanonical of the binding body (see `safetyBindingId`). */
  id: string;
  /** Ed25519 over SAFETY_EVIDENCE_SIG_DOMAIN || sha256(id). */
  sig: string;
}

/** Binding id: commits to signer + evidence digest + the three bound digests. Throws only on unhashable evidence. */
export function safetyBindingId(evidence: ProhibitionEvidence, signer: string): string {
  return hashCanonical({
    d: SAFETY_EVIDENCE_SIG_DOMAIN,
    signer,
    evidence: hashCanonical(evidence),
    constitution: evidence.constitution,
    action_digest: evidence.action_digest,
    state_digest: evidence.state_digest,
  });
}

/**
 * Sign evidence (Ed25519, domain-separated). Refuses evidence whose action/constitution/state could
 * not be digested (nothing to bind). Throws TypeError at signing time only. Violation evidence may be
 * signed (audit), but never verifies as an admit.
 */
export function signSafetyEvidence(evidence: ProhibitionEvidence, signerSecret: Uint8Array, signerPublic: string): SignedSafetyEvidence {
  if (!evidence || evidence.v !== EVIDENCE_VERSION) throw new TypeError('signSafetyEvidence: unsupported evidence');
  for (const d of [evidence.constitution, evidence.action_digest, evidence.state_digest]) {
    if (typeof d !== 'string' || !d || d === UNHASHABLE) throw new TypeError('signSafetyEvidence: unbound evidence');
  }
  if (typeof signerPublic !== 'string' || !signerPublic) throw new TypeError('signSafetyEvidence: signer missing');
  const id = safetyBindingId(evidence, signerPublic);
  return { evidence, signer: signerPublic, id, sig: b64u(sign(signerSecret, domainMessage(SAFETY_EVIDENCE_SIG_DOMAIN, id))) };
}

/** What the verifier already knows independently of the evidence. */
export interface SafetyEvidenceExpectations {
  /** Pinned acceptable signer public key(s). REQUIRED: unauthenticated evidence is refused. */
  signer: string | string[];
  /** The action being admitted, or its digest (e.g. the PCActn's action digest). One is required. */
  action?: ActionContext;
  actionDigest?: string;
  /** The constitution (signed form is verified against `principal` when given), or its id. One is required. */
  constitution?: Constitution | SignedConstitution;
  constitutionId?: string;
  /** Principal key to pin; requires `constitution` to be a verifying SignedConstitution. */
  principal?: string;
  /** The running state the action is evaluated against, or its digest. One is required. */
  state?: MonitorState;
  stateDigest?: string;
  /** Default true: the evidence must attest an ADMIT. Set false to verify authenticity of a veto record. */
  requireOk?: boolean;
}

/**
 * Verify signed evidence offline. Checks, in order: expectations present; signer pinned; binding id
 * recomputed; signature; evidence internally consistent; evidence bound to the expected action /
 * constitution / state (digest equality); and, when action + constitution + state are all supplied,
 * full recomputation (byte-equal evidence). Unless `requireOk:false`, evidence must attest an admit.
 * Never throws.
 */
export function verifySignedSafetyEvidence(signed: SignedSafetyEvidence, expected: SafetyEvidenceExpectations): { ok: boolean; reason?: string } {
  const no = (reason: string) => ({ ok: false as const, reason });
  try {
    if (!isObj(signed) || !isObj(signed.evidence) || !isObj(expected)) return no('malformed input');
    const ev = signed.evidence as ProhibitionEvidence;
    if (ev.v !== EVIDENCE_VERSION) return no('unsupported evidence version');
    const signers = Array.isArray(expected.signer) ? expected.signer : [expected.signer];
    if (!signers.length || signers.some((s) => typeof s !== 'string' || !s)) return no('no pinned signer');
    if (typeof signed.signer !== 'string' || !signers.includes(signed.signer)) return no('signer not trusted');
    // expected bindings
    if (expected.action === undefined && expected.actionDigest === undefined) return no('unbound: action not specified');
    if (expected.constitution === undefined && expected.constitutionId === undefined) return no('unbound: constitution not specified');
    if (expected.state === undefined && expected.stateDigest === undefined) return no('unbound: state not specified');
    if (typeof signed.id !== 'string' || signed.id !== safetyBindingId(ev, signed.signer)) return no('binding id mismatch');
    if (typeof signed.sig !== 'string' || !verifyB64u(signed.signer, domainMessage(SAFETY_EVIDENCE_SIG_DOMAIN, signed.id), signed.sig)) return no('bad signature');

    const wantAction = expected.action !== undefined ? hashCanonical(expected.action) : expected.actionDigest!;
    if (expected.action !== undefined && expected.actionDigest !== undefined && expected.actionDigest !== wantAction) return no('expected action and digest disagree');
    if (ev.action_digest !== wantAction) return no('action digest mismatch (evidence bound to another action)');

    if (expected.principal !== undefined) {
      const sc = expected.constitution as SignedConstitution | undefined;
      if (!sc || typeof sc.sig !== 'string') return no('principal pin requires a signed constitution');
      const vc = verifyConstitution(sc, expected.principal);
      if (!vc.ok) return no('constitution not authentic: ' + vc.reason);
    }
    const wantConst = expected.constitution !== undefined ? constitutionId(expected.constitution) : expected.constitutionId!;
    if (expected.constitution !== undefined && expected.constitutionId !== undefined && expected.constitutionId !== wantConst) return no('expected constitution and id disagree');
    if (ev.constitution !== wantConst) return no('constitution mismatch (evidence bound to another constitution)');

    const wantState = expected.state !== undefined ? stateDigest(expected.state) : expected.stateDigest!;
    if (expected.state !== undefined && expected.stateDigest !== undefined && expected.stateDigest !== wantState) return no('expected state and digest disagree');
    if (ev.state_digest !== wantState) return no('state digest mismatch (evidence bound to another state)');

    // internal consistency: the claimed verdict must follow from the claimed rows
    if (!Array.isArray(ev.evaluated) || !Array.isArray(ev.violated)) return no('malformed evidence');
    const badRows = ev.evaluated.filter((r) => r?.result !== 'pass').map((r) => r?.id);
    if (ev.ok !== (badRows.length === 0 && ev.violated.length === 0)) return no('evidence verdict inconsistent with rows');

    if (expected.action !== undefined && expected.constitution !== undefined && expected.state !== undefined) {
      const full = verifySafetyEvidence(ev, expected.action, expected.constitution, expected.state);
      if (!full.ok && ev.ok) return no(full.reason ?? 'evidence does not reproduce');
      if (!full.ok && !ev.ok && full.reason !== undefined && !full.reason.startsWith('prohibition violated')) return no(full.reason);
    } else if (ev.ok && expected.constitution !== undefined) {
      const ids = expected.constitution.invariants.map((i) => i.id);
      if (ev.evaluated.length !== ids.length || ev.evaluated.some((r, i) => r.id !== ids[i])) return no('evidence does not cover every invariant');
    }
    if (expected.requireOk !== false && !ev.ok) return no('prohibition violated: ' + ev.violated.join(','));
    return { ok: true };
  } catch {
    return no('verification error (fail closed)');
  }
}

// ---- composition: permissions grant, prohibitions veto ---------------------------------

/** Result of composing the permission verdict with the prohibition verdict. */
export interface ComposedDecision {
  allow: boolean;
  /** 'prohibition' whenever a veto fired (it wins even if permitted); 'permission' when merely not granted; 'none' = allowed. */
  decidedBy: 'prohibition' | 'permission' | 'none';
  permitted: boolean;
  prohibition: ProhibitionResult;
}

/**
 * The only composition rule: allow = permitted AND prohibitions.ok. `permitted` is whatever the
 * permission layer concluded (plan, predicates, policy-vm `decide`); it is an INPUT that can only
 * be ANDed, never a way to switch prohibitions off. The monitor runs unconditionally, even when
 * `permitted` is false, so denial reasons are complete.
 */
export function composeAuthority(permitted: boolean, action: ActionContext, constitution: Constitution, state: MonitorState): ComposedDecision {
  const prohibition = checkProhibitions(action, constitution, state);
  const p = permitted === true;
  return {
    allow: p && prohibition.ok,
    decidedBy: !prohibition.ok ? 'prohibition' : p ? 'none' : 'permission',
    permitted: p,
    prohibition,
  };
}

// ---- atomic check-and-advance (pure kernel; the server supplies the lock) ---------------

/** Optimistic-concurrency guards for `checkAndAdvance`. */
export interface CheckAndAdvanceOptions {
  /** Refuse unless `state.seq` equals this (compare-and-swap on the chain head). */
  expectedSeq?: number;
  /** Refuse unless `stateDigest(state)` equals this. */
  expectedStateDigest?: string;
}

/** Outcome of `checkAndAdvance`. `next` equals the input state unless `allow`. */
export interface CheckAndAdvanceResult {
  allow: boolean;
  decidedBy: ComposedDecision['decidedBy'] | 'state';
  /** Evidence over the PRE-transition state; sign it with `signSafetyEvidence`. */
  evidence: ProhibitionEvidence;
  prohibition: ProhibitionResult;
  next: MonitorState;
  reason?: string;
}

/**
 * The pure kernel of the server's critical section: guard the head (CAS), compose authority, build
 * evidence against the pre-state, and on allow compute the next state. Persisting `next` iff `allow`
 * MUST happen in the same atomic step (row lock / serializable txn) that read `state`; otherwise
 * parallel actions can each pass a cap. This function cannot provide that atomicity — it makes it
 * checkable (a stale head fails `expectedSeq` / `expectedStateDigest`). Never throws.
 */
export function checkAndAdvance(
  permitted: boolean,
  action: ActionContext,
  constitution: Constitution,
  state: MonitorState,
  opts: CheckAndAdvanceOptions = {},
): CheckAndAdvanceResult {
  const evidence = proveSafety(action, constitution, state);
  const decision = composeAuthority(permitted, action, constitution, state);
  const refuse = (decidedBy: CheckAndAdvanceResult['decidedBy'], reason?: string): CheckAndAdvanceResult => ({
    allow: false,
    decidedBy,
    evidence,
    prohibition: decision.prohibition,
    next: state,
    ...(reason ? { reason } : {}),
  });
  try {
    if (opts.expectedSeq !== undefined && (!isObj(state) || state.seq !== opts.expectedSeq)) return refuse('state', 'stale state head (seq)');
    if (opts.expectedStateDigest !== undefined && safe(() => stateDigest(state)) !== opts.expectedStateDigest) return refuse('state', 'stale state head (digest)');
    if (!decision.allow) return refuse(decision.decidedBy === 'none' ? 'permission' : decision.decidedBy);
    if (!evidence.ok) return refuse('prohibition', 'evidence not attestable');
    const adv = advanceStateStrict(action, constitution, state);
    if (!adv.ok) return refuse('state', 'advance failed: ' + adv.reason);
    return { allow: true, decidedBy: 'none', evidence, prohibition: decision.prohibition, next: adv.state };
  } catch {
    return refuse('state', 'check-and-advance error (fail closed)');
  }
}
