import { canonicalize } from './hash';
import type { Caveat, CaveatEvaluator } from './capability';

/**
 * Deterministic, non-code predicate DSL (spec §5.1 "semantic action-predicates") + the built-in
 * envelope caveat evaluator (§5.1 `caveats[]`, the M0 `CaveatEvaluator` extension point).
 *
 * Predicates are PURE DATA. There is no eval / Function / user-supplied code path. Every function
 * here is total and never throws; anything malformed, unknown or missing FAILS CLOSED (condition
 * false, caveat unsatisfied, predicate not matched).
 */

export type ConditionOp =
  | 'eq'
  | 'ne'
  | 'in'
  | 'nin'
  | 'lt'
  | 'lte'
  | 'gt'
  | 'gte'
  | 'prefix'
  | 'exists'
  /** Anchored glob match (`*` = any run, `?` = any single char, `\` escapes). Operand/field must be strings. */
  | 'like'
  /** Anchored regex match over the linear-time-safe subset (see {@link isSafeRegexSource}); fails closed. */
  | 'matches'
  /** Type/tag check: the field's `type`/`tags` (object) or `Type::id` string prefix matches the operand type. */
  | 'is_a'
  /** Membership of the field value in the operand group(s), via a bounded transitive closure over `collection`. */
  | 'member_of';

/** A single leaf comparison over a dotted path. */
export interface LeafCondition {
  /** Dotted path rooted at `action`, `subject` or `env` (e.g. `action.params.session.device`). */
  field: string;
  op: ConditionOp;
  /** Literal operand. For `exists`: `false` means "must be absent"; anything else means "present". */
  value?: unknown;
  /** Alternative to `value`: a dotted path whose resolved value is the operand
   *  (e.g. `session.device != current_device` => ref: 'env.current_device'). Missing ref => false. */
  ref?: string;
  /** `member_of` ONLY: dotted path to the adjacency/relation collection (node -> parent id(s)) the
   *  bounded, reflexive transitive closure is resolved against. Missing/non-object => fail closed. */
  collection?: string;
}

/** All children must hold (explicit AND; a bare `Condition[]` list in `where` is already an implicit AND). */
export interface AllOfCondition {
  all_of: Condition[];
}
/** At least one child must hold (OR). */
export interface AnyOfCondition {
  any_of: Condition[];
}
/** The child must NOT hold. Fails closed: if the child cannot be cleanly decided, `not` is NOT satisfied. */
export interface NotCondition {
  not: Condition;
}

export type GroupCondition = AllOfCondition | AnyOfCondition | NotCondition;

/**
 * A `where` condition: either a leaf comparison or a boolean grouping of further conditions. Groupings
 * nest arbitrarily, so a predicate's `where` can express any boolean combination. STRICTLY ADDITIVE:
 * a leaf condition evaluates byte-identically to before this union existed.
 */
export type Condition = LeafCondition | GroupCondition;

const isObjRec = (x: unknown): x is Record<string, unknown> =>
  x !== null && typeof x === 'object' && !Array.isArray(x);

/** Is this condition a boolean grouping (`all_of` / `any_of` / `not`) rather than a leaf comparison? */
export function isGroupCondition(c: Condition): c is GroupCondition {
  return isObjRec(c) && ('all_of' in c || 'any_of' in c || 'not' in c);
}
/** Is this condition a leaf comparison (has a string `field`)? */
export function isLeafCondition(c: Condition): c is LeafCondition {
  return isObjRec(c) && !isGroupCondition(c) && typeof c.field === 'string';
}

export interface Predicate {
  /** Exact verb, list of verbs, or '*'. */
  verb: string | string[];
  /**
   * Resource matcher (string, pure data): exact; `'*'` any; trailing `*` = prefix
   * (`'/acct/*'`); `'re:<pattern>'` = full-match regular expression (pattern <= 200 chars; it is
   * authored by the principal and signed into the grant, so it is trusted input).
   * Omitted = any resource.
   */
  resource?: string;
  /** ALL conditions must hold. */
  where?: Condition[];
}

export interface ActionContext {
  action: {
    verb: string;
    resource: string;
    params?: Record<string, unknown>;
    /** Optional reversibility class for the `reversibility_max` caveat: reversible|rate_limited|irreversible. */
    reversibility_class?: string;
  };
  subject?: Record<string, unknown>;
  env?: Record<string, unknown>;
  /** The PCActn's signed `tool_binding` (b64u digest of the tool signature the agent dispatches to), if any. */
  toolBinding?: string;
}

export interface PredicateResult {
  allowed: boolean;
  matched?: Predicate;
  reason?: string;
}

const ROOTS = new Set(['action', 'subject', 'env']);
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/** Resolve a dotted path into the context. Own properties only; unknown root => not found. */
export function resolvePath(ctx: ActionContext, path: unknown): { found: boolean; value?: unknown } {
  if (typeof path !== 'string' || path.length === 0) return { found: false };
  const segs = path.split('.');
  if (!ROOTS.has(segs[0]!)) return { found: false };
  let cur: unknown = (ctx as unknown as Record<string, unknown>)?.[segs[0]!];
  if (cur === undefined) return { found: false };
  for (let i = 1; i < segs.length; i++) {
    const s = segs[i]!;
    if (FORBIDDEN.has(s) || cur === null || typeof cur !== 'object') return { found: false };
    if (Array.isArray(cur)) {
      if (!/^(0|[1-9]\d*)$/.test(s)) return { found: false };
      const idx = Number(s);
      if (idx >= cur.length) return { found: false };
      cur = cur[idx];
    } else {
      if (!has(cur as object, s)) return { found: false };
      cur = (cur as Record<string, unknown>)[s];
    }
    if (cur === undefined) return { found: false };
  }
  return { found: true, value: cur };
}

function deepEq(a: unknown, b: unknown): boolean {
  try {
    return canonicalize(a) === canonicalize(b);
  } catch {
    return false;
  }
}

function ordered(a: unknown, b: unknown): number | null {
  if (typeof a === 'number' && typeof b === 'number' && Number.isFinite(a) && Number.isFinite(b)) {
    return a < b ? -1 : a > b ? 1 : 0;
  }
  if (typeof a === 'string' && typeof b === 'string') return a < b ? -1 : a > b ? 1 : 0;
  return null;
}

/**
 * Three-valued condition truth. `'true'` / `'false'` are CLEANLY DECIDED verdicts; `'unknown'` means
 * the condition could not be evaluated cleanly (malformed shape, unknown op, unavailable params,
 * unresolved field/ref, type mismatch, invalid/unsafe pattern, missing collection). This distinction
 * is what lets `not`/`any_of`/`all_of` fail closed: an `unknown` child never satisfies a `not`.
 *
 * The public boolean {@link evaluateCondition} is exactly `=== 'true'`, so every PRE-EXISTING leaf op
 * evaluates byte-identically to before (everything that used to return `false` is now `'false'` or
 * `'unknown'`, both of which map back to boolean `false`).
 */
export type Tri = 'true' | 'false' | 'unknown';

/** Longest field value a `like`/`matches` leaf is tested against (bounds polynomial-time blowup). */
export const MAX_PATTERN_SUBJECT_LEN = 512;
/** Longest `like` glob / `matches` regex source accepted (authored & signed into the grant). */
export const MAX_LIKE_PATTERN_LEN = 512;
export const MAX_MATCHES_PATTERN_LEN = 200;
/** Upper bound on nodes visited while resolving a `member_of` transitive closure. */
export const MAX_MEMBER_CLOSURE_NODES = 10_000;

function escapeRegexLiteral(ch: string): string {
  return /[.*+?^${}()|[\]\\]/.test(ch) ? '\\' + ch : ch;
}

/**
 * Compile an anchored glob to a RegExp WITHOUT any backtracking risk: `*` -> `[\s\S]*`, `?` ->
 * `[\s\S]`, `\x` -> literal x, everything else escaped. The only quantifier produced is `*` over a
 * character class (never nested, never over an alternation), so matching is linear. Null on a dangling
 * trailing backslash or a RegExp the engine rejects.
 */
function globToRegExp(glob: string): RegExp | null {
  try {
    let out = '';
    for (let i = 0; i < glob.length; i++) {
      const ch = glob[i]!;
      if (ch === '\\') {
        const n = glob[i + 1];
        if (n === undefined) return null;
        out += escapeRegexLiteral(n);
        i++;
        continue;
      }
      if (ch === '*') out += '[\\s\\S]*';
      else if (ch === '?') out += '[\\s\\S]';
      else out += escapeRegexLiteral(ch);
    }
    return new RegExp('^(?:' + out + ')$');
  } catch {
    return null;
  }
}

/** `is_a` type/tag test. Returns null when the value carries no decidable type/tag. */
function typeTagMatch(v: unknown, t: string): boolean | null {
  if (typeof v === 'string') return v === t || v.startsWith(t + '::');
  if (isObjRec(v)) {
    let decidable = false;
    let matched = false;
    if (has(v, 'type')) {
      const ty = v['type'];
      if (typeof ty === 'string') {
        decidable = true;
        if (ty === t || ty.startsWith(t + '::')) matched = true;
      }
    }
    if (has(v, 'tags')) {
      const tags = v['tags'];
      if (Array.isArray(tags)) {
        decidable = true;
        if (tags.some((x) => x === t)) matched = true;
      }
    }
    return decidable ? matched : null;
  }
  return null;
}

/** Direct neighbours of `node` in an adjacency map (own string | string[] values only; proto-safe). */
function neighboursOf(adj: Record<string, unknown>, node: string): string[] {
  if (FORBIDDEN.has(node) || !has(adj, node)) return [];
  const raw = adj[node];
  if (typeof raw === 'string') return [raw];
  if (Array.isArray(raw)) return raw.filter((x): x is string => typeof x === 'string');
  return [];
}

/** Reflexive, bounded, cycle-guarded transitive closure of `start` over an adjacency map. */
function memberClosure(start: string, adj: Record<string, unknown>): Set<string> {
  const seen = new Set<string>([start]);
  const queue: string[] = [start];
  let visited = 0;
  while (queue.length > 0 && visited < MAX_MEMBER_CLOSURE_NODES) {
    visited++;
    const node = queue.shift()!;
    for (const n of neighboursOf(adj, node)) {
      if (!seen.has(n)) {
        seen.add(n);
        queue.push(n);
      }
    }
  }
  return seen;
}

/** Tri-valued evaluation of one LEAF condition. */
function triLeaf(c: LeafCondition, ctx: ActionContext): Tri {
  if (typeof c.field !== 'string' || c.field.length === 0) return 'unknown';
  if (typeof c.op !== 'string') return 'unknown';
  // "params unavailable" (never supplied / not verified) is NOT "field absent": a params-rooted
  // condition must fail closed, otherwise `exists:false` / `nin` style checks pass vacuously.
  if (c.field === 'action.params' || c.field.startsWith('action.params.')) {
    const p = ctx?.action?.params;
    if (p === undefined || p === null || typeof p !== 'object') return 'unknown';
  }
  if (typeof c.ref === 'string' && (c.ref === 'action.params' || c.ref.startsWith('action.params.'))) {
    const p = ctx?.action?.params;
    if (p === undefined || p === null || typeof p !== 'object') return 'unknown';
  }
  const f = resolvePath(ctx, c.field);
  if (c.op === 'exists') return (c.value === false ? !f.found : f.found) ? 'true' : 'false';
  if (!f.found) return 'unknown';
  const v = f.value;

  // member_of resolves a target group (value/ref) AND an adjacency collection.
  if (c.op === 'member_of') {
    if (typeof v !== 'string') return 'unknown';
    if (typeof c.collection !== 'string' || c.collection.length === 0) return 'unknown';
    const coll = resolvePath(ctx, c.collection);
    if (!coll.found || !isObjRec(coll.value)) return 'unknown';
    let targetOperand: unknown;
    if (c.ref !== undefined) {
      const r = resolvePath(ctx, c.ref);
      if (!r.found) return 'unknown';
      targetOperand = r.value;
    } else {
      if (!has(c, 'value') || c.value === undefined) return 'unknown';
      targetOperand = c.value;
    }
    const targets = Array.isArray(targetOperand)
      ? targetOperand.filter((x): x is string => typeof x === 'string')
      : typeof targetOperand === 'string'
        ? [targetOperand]
        : [];
    if (targets.length === 0) return 'unknown';
    const reach = memberClosure(v, coll.value);
    return targets.some((t) => reach.has(t)) ? 'true' : 'false';
  }

  let operand: unknown;
  if (c.ref !== undefined) {
    const r = resolvePath(ctx, c.ref);
    if (!r.found) return 'unknown';
    operand = r.value;
  } else {
    if (!has(c, 'value') || c.value === undefined) return 'unknown';
    operand = c.value;
  }

  switch (c.op) {
    case 'eq':
      return deepEq(v, operand) ? 'true' : 'false';
    case 'ne':
      return deepEq(v, operand) ? 'false' : 'true';
    case 'in':
      return Array.isArray(operand) ? (operand.some((x) => deepEq(v, x)) ? 'true' : 'false') : 'unknown';
    case 'nin':
      return Array.isArray(operand) ? (operand.some((x) => deepEq(v, x)) ? 'false' : 'true') : 'unknown';
    case 'lt':
    case 'lte':
    case 'gt':
    case 'gte': {
      const o = ordered(v, operand);
      if (o === null) return 'unknown';
      const ok = c.op === 'lt' ? o < 0 : c.op === 'lte' ? o <= 0 : c.op === 'gt' ? o > 0 : o >= 0;
      return ok ? 'true' : 'false';
    }
    case 'prefix':
      if (typeof v !== 'string' || typeof operand !== 'string') return 'unknown';
      return v.startsWith(operand) ? 'true' : 'false';
    case 'like': {
      if (typeof v !== 'string' || typeof operand !== 'string') return 'unknown';
      if (operand.length > MAX_LIKE_PATTERN_LEN || v.length > MAX_PATTERN_SUBJECT_LEN) return 'unknown';
      const re = globToRegExp(operand);
      if (re === null) return 'unknown';
      return re.test(v) ? 'true' : 'false';
    }
    case 'matches': {
      if (typeof v !== 'string' || typeof operand !== 'string') return 'unknown';
      if (operand.length > MAX_MATCHES_PATTERN_LEN || v.length > MAX_PATTERN_SUBJECT_LEN) return 'unknown';
      if (!isSafeRegexSource(operand)) return 'unknown';
      try {
        return new RegExp('^(?:' + operand + ')$').test(v) ? 'true' : 'false';
      } catch {
        return 'unknown';
      }
    }
    case 'is_a': {
      if (typeof operand !== 'string' || operand.length === 0) return 'unknown';
      const t = typeTagMatch(v, operand);
      return t === null ? 'unknown' : t ? 'true' : 'false';
    }
    default:
      return 'unknown';
  }
}

/** Tri-valued evaluation of any condition (leaf or boolean grouping). Total; never throws. */
export function evaluateConditionTri(c: Condition, ctx: ActionContext): Tri {
  try {
    if (c === null || typeof c !== 'object') return 'unknown';
    if (isGroupCondition(c)) {
      if ('all_of' in c) {
        if (!Array.isArray(c.all_of) || c.all_of.length === 0) return 'unknown';
        let sawUnknown = false;
        for (const x of c.all_of) {
          const t = evaluateConditionTri(x, ctx);
          if (t === 'false') return 'false';
          if (t === 'unknown') sawUnknown = true;
        }
        return sawUnknown ? 'unknown' : 'true';
      }
      if ('any_of' in c) {
        if (!Array.isArray(c.any_of) || c.any_of.length === 0) return 'unknown';
        let sawUnknown = false;
        for (const x of c.any_of) {
          const t = evaluateConditionTri(x, ctx);
          if (t === 'true') return 'true';
          if (t === 'unknown') sawUnknown = true;
        }
        return sawUnknown ? 'unknown' : 'false';
      }
      // 'not'
      const inner = evaluateConditionTri(c.not, ctx);
      return inner === 'true' ? 'false' : inner === 'false' ? 'true' : 'unknown';
    }
    return triLeaf(c, ctx);
  } catch {
    return 'unknown';
  }
}

/**
 * Evaluate one condition. A leaf's semantics are unchanged: missing field / operand => false (except
 * `exists:false`), unknown op => false. Boolean groupings recurse and FAIL CLOSED (a child that cannot
 * be cleanly decided never satisfies a `not`, never completes an `all_of`, never carries an `any_of`).
 */
export function evaluateCondition(c: Condition, ctx: ActionContext): boolean {
  return evaluateConditionTri(c, ctx) === 'true';
}

function verbMatches(p: Predicate['verb'], verb: string): boolean {
  if (typeof p === 'string') return p === '*' || p === verb;
  if (Array.isArray(p)) return p.some((x) => typeof x === 'string' && (x === '*' || x === verb));
  return false;
}

/** Longest resource string a `re:` pattern is evaluated against (bounds polynomial-time blowup). */
export const MAX_RE_RESOURCE_LEN = 512;
const MAX_UNBOUNDED_QUANTIFIERS = 3;
const MAX_BOUNDED_REPEAT = 64;

/**
 * Validate that a `re:` pattern is in the linear-time-safe subset, WITHOUT a regex-engine dependency.
 * Exponential backtracking needs a quantified sub-expression that can itself match in several ways, so:
 *  - a quantifier may NOT be applied to a group that contains a quantifier or an alternation
 *    (rejects `(a+)+`, `(a*)*`, `(a|aa)+`, `(.*a){10}`);
 *  - no backreferences (`\1`, `\k<n>`), no lookaround / named / lookbehind groups (only `(?:...)`);
 *  - at most 3 unbounded quantifiers (`*`, `+`, `{n,}`) in total (polynomial degree <= 3, with the
 *    512-char subject cap) and bounded repeats `{n,m}` capped at m <= 64.
 * Well-formed ordinary patterns (`/acct/[^/]+/items/\d+`, `(?:GET|POST) /x`) are unaffected.
 */
export function isSafeRegexSource(src: string): boolean {
  type Frame = { hasQuant: boolean; hasAlt: boolean };
  const stack: Frame[] = [{ hasQuant: false, hasAlt: false }];
  let prev: 'none' | 'atom' | Frame = 'none'; // what a following quantifier would bind to
  let unbounded = 0;
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    if (ch === '\\') {
      const n = src[i + 1];
      if (n === undefined) return false;
      if ((n >= '1' && n <= '9') || n === 'k') return false; // backreference
      i += 2;
      prev = 'atom';
      continue;
    }
    if (ch === '[') {
      let j = i + 1;
      if (src[j] === '^') j++;
      if (src[j] === ']') j++;
      for (; j < src.length && src[j] !== ']'; j++) if (src[j] === '\\') j++;
      if (j >= src.length) return false;
      i = j + 1;
      prev = 'atom';
      continue;
    }
    if (ch === '(') {
      if (src[i + 1] === '?') {
        if (src[i + 2] !== ':') return false; // lookahead/lookbehind/named group
        i += 3;
      } else i += 1;
      stack.push({ hasQuant: false, hasAlt: false });
      prev = 'none';
      continue;
    }
    if (ch === ')') {
      if (stack.length < 2) return false;
      const f = stack.pop()!;
      const parent = stack[stack.length - 1]!;
      parent.hasQuant ||= f.hasQuant;
      parent.hasAlt ||= f.hasAlt;
      prev = f;
      i++;
      continue;
    }
    if (ch === '|') {
      stack[stack.length - 1]!.hasAlt = true;
      prev = 'none';
      i++;
      continue;
    }
    let q: { len: number; unbounded: boolean; max: number } | null = null;
    if (ch === '*' || ch === '+') q = { len: 1, unbounded: true, max: Infinity };
    else if (ch === '?') q = { len: 1, unbounded: false, max: 1 };
    else if (ch === '{') {
      const m = /^\{(\d+)(?:(,)(\d*))?\}/.exec(src.slice(i, i + 24));
      if (m) {
        const lo = Number(m[1]);
        const hasComma = m[2] !== undefined;
        const hi = !hasComma ? lo : m[3] === '' ? Infinity : Number(m[3]);
        if (hi < lo) return false;
        q = { len: m[0].length, unbounded: hi === Infinity, max: hi };
      }
    }
    if (q) {
      if (prev === 'none') return false; // nothing to repeat
      if (typeof prev === 'object' && (prev.hasQuant || prev.hasAlt)) return false; // nested quantifier
      if (q.unbounded && ++unbounded > MAX_UNBOUNDED_QUANTIFIERS) return false;
      if (!q.unbounded && q.max !== Infinity && q.max > MAX_BOUNDED_REPEAT) return false;
      stack[stack.length - 1]!.hasQuant = true;
      i += q.len;
      if (src[i] === '?') i++; // lazy modifier
      prev = 'none'; // a quantifier cannot be quantified again
      continue;
    }
    i++;
    prev = 'atom';
  }
  return stack.length === 1;
}

function resourceMatches(pattern: unknown, resource: string): boolean {
  if (pattern === undefined) return true;
  if (typeof pattern !== 'string') return false;
  if (pattern === '*') return true;
  if (pattern.startsWith('re:')) {
    const src = pattern.slice(3);
    if (src.length > 200) return false;
    // ReDoS defence (no dependency): only a linear-time-safe subset is evaluated, and the subject is capped.
    if (resource.length > MAX_RE_RESOURCE_LEN) return false;
    if (!isSafeRegexSource(src)) return false;
    try {
      return new RegExp('^(?:' + src + ')$').test(resource);
    } catch {
      return false;
    }
  }
  if (pattern.endsWith('*')) return resource.startsWith(pattern.slice(0, -1));
  return pattern === resource;
}

/** Does a single predicate permit the action? */
export function predicateMatches(p: Predicate, ctx: ActionContext): boolean {
  try {
    if (p === null || typeof p !== 'object') return false;
    const a = ctx?.action;
    if (!a || typeof a.verb !== 'string' || typeof a.resource !== 'string') return false;
    if (!verbMatches(p.verb, a.verb)) return false;
    if (!resourceMatches(p.resource, a.resource)) return false;
    if (p.where !== undefined) {
      if (!Array.isArray(p.where)) return false;
      for (const c of p.where) if (!evaluateCondition(c, ctx)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * An action is allowed iff it matches AT LEAST ONE predicate (verb AND resource AND all `where`).
 * Default-deny: an empty predicate list allows nothing.
 */
export function evaluatePredicates(predicates: Predicate[], ctx: ActionContext): PredicateResult {
  try {
    if (!Array.isArray(predicates) || predicates.length === 0) {
      return { allowed: false, reason: 'envelope grants no predicates' };
    }
    for (const p of predicates) {
      if (predicateMatches(p, ctx)) return { allowed: true, matched: p };
    }
    const a = ctx?.action;
    return { allowed: false, reason: `no predicate permits ${String(a?.verb)} on ${String(a?.resource)}` };
  } catch {
    return { allowed: false, reason: 'predicate evaluation error (fail closed)' };
  }
}

// ---- built-in envelope caveats ---------------------------------------------------------

/** Reversibility classes in increasing severity (spec §10: reversible < rate-limited < irreversible). */
export const REVERSIBILITY_ORDER = ['reversible', 'rate_limited', 'irreversible'] as const;

/** Data the built-in caveats are evaluated against. Epoch times in ms. Missing data FAILS CLOSED. */
export interface CaveatContext {
  now: number;
  /** Normalized blast radius in [0,1]. */
  blastRadius?: number;
  reversibilityClass?: string;
  /** Hops below the root this holder sits at (0 = the grant holder). */
  delegationDepth?: number;
  /** Epoch-ms timestamps of this holder's previously admitted actions (for `rate`). */
  recentActionTimes?: number[];
}

const fin = (x: unknown): x is number => typeof x === 'number' && Number.isFinite(x);

/**
 * Built-in caveat types (all conjunctive; unknown type => unsatisfied):
 *  - `expires`            { at: ms }        satisfied iff now < at
 *  - `not_before`         { at: ms }        satisfied iff now >= at
 *  - `rate`               { max, per_secs } satisfied iff admitted actions in (now - per_secs, now] < max
 *                                           (so this action is at most the max-th); needs ctx.recentActionTimes
 *  - `max_blast_radius`   { max: [0,1] }    satisfied iff ctx.blastRadius <= max
 *  - `reversibility_max`  { class }         satisfied iff ctx.reversibilityClass is no more severe than `class`
 *  - `delegation_depth`   { max }           satisfied iff ctx.delegationDepth <= max
 */
export const envelopeCaveatEvaluator: CaveatEvaluator = (caveat: Caveat, ctx: unknown): boolean => {
  try {
    if (caveat === null || typeof caveat !== 'object' || ctx === null || typeof ctx !== 'object') return false;
    const c = ctx as Partial<CaveatContext>;
    if (!fin(c.now)) return false;
    switch (caveat.type) {
      case 'expires':
        return fin(caveat.at) && c.now < caveat.at;
      case 'not_before':
        return fin(caveat.at) && c.now >= caveat.at;
      case 'rate': {
        if (!fin(caveat.max) || !fin(caveat.per_secs) || caveat.per_secs <= 0) return false;
        if (!Array.isArray(c.recentActionTimes)) return false;
        const lo = c.now - caveat.per_secs * 1000;
        const n = c.recentActionTimes.filter((t) => fin(t) && t > lo && t <= c.now!).length;
        return n < caveat.max;
      }
      case 'max_blast_radius':
        return fin(caveat.max) && fin(c.blastRadius) && c.blastRadius <= caveat.max;
      case 'reversibility_max': {
        const lim = (REVERSIBILITY_ORDER as readonly string[]).indexOf(String(caveat.class));
        const cur = (REVERSIBILITY_ORDER as readonly string[]).indexOf(String(c.reversibilityClass));
        return lim >= 0 && cur >= 0 && cur <= lim;
      }
      case 'delegation_depth':
        return fin(caveat.max) && fin(c.delegationDepth) && c.delegationDepth <= caveat.max;
      case 'budget_alloc': {
        // Carried per-subtree trust-budget allocation (capability.ts): it imposes NO per-action semantic
        // constraint here — its monotonicity is enforced in verifyChain and its consumption is metered
        // statefully server-side. Satisfied as long as the declared limit is a finite number >= 0.
        const lim = caveat.limit;
        return fin(lim) && lim >= 0;
      }
      default:
        return false;
    }
  } catch {
    return false;
  }
};

/** Evaluate all caveats; ok iff every caveat is satisfied. `failed` lists the unsatisfied types. */
export function evaluateCaveats(
  caveats: Caveat[],
  ctx: CaveatContext,
  evaluator: CaveatEvaluator = envelopeCaveatEvaluator,
): { ok: boolean; failed: string[] } {
  const failed: string[] = [];
  if (!Array.isArray(caveats)) return { ok: false, failed: ['<malformed caveats>'] };
  for (const cv of caveats) {
    let ok = false;
    try {
      ok = evaluator(cv, ctx);
    } catch {
      ok = false;
    }
    if (!ok) failed.push(typeof cv?.type === 'string' ? cv.type : '<malformed>');
  }
  return { ok: failed.length === 0, failed };
}
