import { isSafeRegexSourceVerified } from '@atlasauth/pca-verified-core';
import { verifiedCoreOptIn } from './verified-core-mode';
import { canonicalize, compareUtf8, hasLoneSurrogate } from './hash';
import { compileSafeRegex, safeRegexFullMatch } from './safe-regex';
import { chargeRegex, withRegexBudget } from './regex-budget';
import type { Caveat, CaveatEvaluator } from './capability';
import { INTENT_SESSION_CAVEAT, intentSessionCaveatError } from './intent-session-caveat';

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

/**
 * NORMATIVE string order for lt/lte/gt/gte: the byte-wise order of the UTF-8 encoding, which is exactly Unicode code
 * point order. JavaScript's `<` compares UTF-16 code units and would mis-order astral characters against
 * U+E000..U+FFFF (U+FFFF vs U+10000); every other implementation compares code points / UTF-8 bytes. No normalisation
 * (NFC and NFD forms of one text are different strings), no case folding, no locale. A string with a LONE surrogate
 * has no UTF-8 encoding, so it has no order: null (the ordering operators then evaluate false — fail closed).
 */
function orderUtf8(a: string, b: string): number | null {
  if (hasLoneSurrogate(a) || hasLoneSurrogate(b)) return null;
  return Math.sign(compareUtf8(a, b));
}

function ordered(a: unknown, b: unknown): number | null {
  if (typeof a === 'number' && typeof b === 'number' && Number.isFinite(a) && Number.isFinite(b)) {
    return a < b ? -1 : a > b ? 1 : 0;
  }
  if (typeof a === 'string' && typeof b === 'string') return orderUtf8(a, b);
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

type GlobToken = { kind: 'lit'; ch: string } | { kind: 'one' } | { kind: 'star' };

/**
 * Parse an anchored glob: `*` any run (including none), `?` any ONE UTF-16 code unit, `\x` the literal x, everything
 * else literal. Null on a dangling trailing backslash. Consecutive `*` collapse to one.
 */
function parseGlob(glob: string): GlobToken[] | null {
  const out: GlobToken[] = [];
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]!;
    if (ch === '\\') {
      const n = glob[i + 1];
      if (n === undefined) return null;
      out.push({ kind: 'lit', ch: n });
      i++;
    } else if (ch === '*') {
      if (out[out.length - 1]?.kind !== 'star') out.push({ kind: 'star' });
    } else if (ch === '?') out.push({ kind: 'one' });
    else out.push({ kind: 'lit', ch });
  }
  return out;
}

/**
 * Anchored glob match in O(|glob| x |s|) worst case with NO regex engine. (The earlier `[\s\S]*`-per-star RegExp
 * translation was documented as linear but is not: `*a*a*a*b` against 500 `a`s ran for 45 seconds in V8, because
 * k stars backtrack as n^k.) Null on a malformed glob. Semantics are exactly those of the translation it replaces:
 * matching is over UTF-16 code units, `*` and `?` match any code unit including line terminators.
 */
function globMatch(glob: string, s: string): boolean | null {
  const toks = parseGlob(glob);
  if (toks === null) return null;
  let ti = 0;
  let si = 0;
  let starTi = -1; // token index just after the most recent star
  let starSi = 0; // subject index that star is currently extended to
  while (si < s.length) {
    const t = toks[ti];
    if (t !== undefined && t.kind === 'star') {
      starTi = ++ti;
      starSi = si;
    } else if (t !== undefined && (t.kind === 'one' || s[si] === t.ch)) {
      ti++;
      si++;
    } else if (starTi >= 0) {
      ti = starTi;
      si = ++starSi;
    } else return false;
  }
  while (toks[ti]?.kind === 'star') ti++;
  return ti === toks.length;
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
      const m = globMatch(operand, v);
      if (m === null) return 'unknown';
      return m ? 'true' : 'false';
    }
    case 'matches': {
      if (typeof v !== 'string' || typeof operand !== 'string') return 'unknown';
      if (operand.length > MAX_MATCHES_PATTERN_LEN || v.length > MAX_PATTERN_SUBJECT_LEN) return 'unknown';
      if (!isSafeRegexSource(operand)) return 'unknown';
      if (!chargeRegex(operand, v.length)) return 'unknown'; // R4-05: per-document regex work budget (fail closed)
      const r = safeRegexFullMatch(operand, v); // R3-02: linear-time engine, never V8's backtracking RegExp
      return r === null ? 'unknown' : r ? 'true' : 'false';
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
  return withRegexBudget(() => evaluateConditionTriInner(c, ctx));
}
function evaluateConditionTriInner(c: Condition, ctx: ActionContext): Tri {
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
const MAX_BOUNDED_REPEAT = 64;
/**
 * Backtracking-cost budget, in bits (log2 of the worst-case number of distinct match paths). Every construct that lets
 * the engine choose costs bits: `|` and `?` 1 bit each, a variable bounded repeat `{m,n}` ceil(log2(n-m+1)), an unbounded
 * quantifier 8 (n^k/k! over the 512-char subject cap, ~2^8 each) in the capped subject, not exponential). Sequences of independent choices multiply (the
 * classic `a?{n}a{n}b` and `(?:a|aa){n}b` blow-ups take 2^n steps), so the SUM is capped: 2^22 steps is well under a
 * second on the 512-char subject cap, while ordinary patterns use a handful of bits.
 */
const MAX_REGEX_COST_BITS = 22;
const UNBOUNDED_QUANTIFIER_BITS = 8;

/**
 * Validate that a `re:` pattern is in the linear-time-safe subset, WITHOUT a regex-engine dependency.
 * Exponential backtracking needs a quantified sub-expression that can itself match in several ways, so:
 *  - a quantifier may NOT be applied to a group that contains a quantifier or an alternation
 *    (rejects `(a+)+`, `(a*)*`, `(a|aa)+`, `(.*a){10}`);
 *  - no backreferences (`\1`, `\k<n>`), no lookaround / named / lookbehind groups (only `(?:...)`);
 *  - unbounded quantifiers (`*`, `+`, `{n,}`) are capped by the cost budget below (at most two per pattern: polynomial degree <= 2, with the
 *    512-char subject cap) and bounded repeats `{n,m}` capped at m <= 64;
 *  - a total backtracking-cost budget of 22 bits (so, in effect, at most two unbounded quantifiers per pattern) over every `|`, `?`, variable `{m,n}` and unbounded quantifier
 *    (rejects the sequenced-choice blow-ups `a?{n}a{n}b` and `(?:a|aa){n}b`, which nest nothing but take 2^n steps).
 * Well-formed ordinary patterns (`/acct/[^/]+/items/\d+`, `(?:GET|POST) /x`) are unaffected.
 */
export function isSafeRegexSource(src: string): boolean {
  // OPT-IN (`PCA_VERIFIED_CORE=regex`): the Dafny-proved guard (formal/dafny/Regex.dfy `SafeSource`, verified-core).
  if (verifiedCoreOptIn('regex')) return isSafeRegexSourceVerified(src);
  type Frame = { hasQuant: boolean; hasAlt: boolean };
  const stack: Frame[] = [{ hasQuant: false, hasAlt: false }];
  let prev: 'none' | 'atom' | Frame = 'none'; // what a following quantifier would bind to
  let bits = 0;
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
      // R3-02: JavaScript class semantics, NOT POSIX: after `[` and an optional `^`, the class ends at the FIRST
      // unescaped `]`. There is no "leading `]` is a literal" rule: `[]` is the empty class and `[^]` matches any
      // character, so `[^](a+)+]` is `any (a+)+ ]`. (The previous POSIX reading was the round-3 guard differential.)
      let j = i + 1;
      if (src[j] === '^') j++;
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
      if (++bits > MAX_REGEX_COST_BITS) return false;
      stack[stack.length - 1]!.hasAlt = true;
      prev = 'none';
      i++;
      continue;
    }
    let q: { len: number; unbounded: boolean; max: number; options: number } | null = null;
    if (ch === '*' || ch === '+') q = { len: 1, unbounded: true, max: Infinity, options: Infinity };
    else if (ch === '?') q = { len: 1, unbounded: false, max: 1, options: 2 };
    else if (ch === '{') {
      // R2-05: match against the whole remaining source (no length window; callers cap the source at 200 chars)
      // and fail closed on a `{` that is not a well-formed quantifier instead of reading it as a literal atom.
      const m = /^\{(\d+)(?:(,)(\d*))?\}/.exec(src.slice(i));
      if (!m) return false;
      {
        const lo = Number(m[1]);
        const hasComma = m[2] !== undefined;
        const hi = !hasComma ? lo : m[3] === '' ? Infinity : Number(m[3]);
        if (hi < lo) return false;
        q = { len: m[0].length, unbounded: hi === Infinity, max: hi, options: hi === Infinity ? Infinity : hi - lo + 1 };
      }
    }
    if (q) {
      if (prev === 'none') return false; // nothing to repeat
      if (typeof prev === 'object' && (prev.hasQuant || prev.hasAlt)) return false; // nested quantifier
      if (!q.unbounded && q.max !== Infinity && q.max > MAX_BOUNDED_REPEAT) return false;
      // choice cost (see MAX_REGEX_COST_BITS): `?` is {0,1}; `{m,n}` with m<n offers n-m+1 widths; `{n}` offers one.
      bits += q.unbounded ? UNBOUNDED_QUANTIFIER_BITS : q.options > 1 ? Math.ceil(Math.log2(q.options)) : 0;
      if (bits > MAX_REGEX_COST_BITS) return false;
      stack[stack.length - 1]!.hasQuant = true;
      i += q.len;
      if (src[i] === '?') i++; // lazy modifier
      prev = 'none'; // a quantifier cannot be quantified again
      continue;
    }
    i++;
    prev = 'atom';
  }
  // R3-02: the source must ALSO compile in the linear-time engine that actually runs it (one parser decides what runs).
  return stack.length === 1 && compileSafeRegex(src) !== null;
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
    if (!chargeRegex(src, resource.length)) return false; // R4-05: per-document regex work budget (fail closed)
    // R3-02: run on the linear-time budgeted engine, never on V8's backtracking RegExp. null => unsupported/over budget => no match.
    return safeRegexFullMatch(src, resource) === true;
  }
  if (pattern.endsWith('*')) return resource.startsWith(pattern.slice(0, -1));
  return pattern === resource;
}

/** Does a single predicate permit the action? */
export function predicateMatches(p: Predicate, ctx: ActionContext): boolean {
  return withRegexBudget(() => predicateMatchesInner(p, ctx));
}
function predicateMatchesInner(p: Predicate, ctx: ActionContext): boolean {
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

const OP_TEXT: Record<string, string> = {
  eq: '==', ne: '!=', lt: '<', lte: '<=', gt: '>', gte: '>=', in: 'in', nin: 'not in', prefix: 'starts with',
  like: 'like', matches: 'matches', is_a: 'is a', member_of: 'member of',
};
const MAX_SHOWN_STRING = 64;
const MAX_SHOWN_ITEMS = 8;

/** A scalar operand in a denial reason. Deterministic across SDKs: only safe integers, booleans, null and plain short strings are spelled out. */
function showValue(v: unknown, depth = 0): string {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return String(v);
  if (typeof v === 'number') return Number.isSafeInteger(v) ? String(v) : '<number>';
  if (typeof v === 'string') return v.length <= MAX_SHOWN_STRING && !/[\u0000-\u001f"\\\ud800-\udfff]/.test(v) ? `"${v}"` : '"..."';
  if (Array.isArray(v) && depth === 0) return v.length <= MAX_SHOWN_ITEMS ? `[${v.map((x) => showValue(x, 1)).join(', ')}]` : '[...]';
  return '<value>';
}

/** The condition as the limit a reader recognises: `amount <= 500`, `currency in ["usd", "eur"]`. */
function describeCondition(c: Condition, depth = 0): string {
  if (c === null || typeof c !== 'object') return '<condition>';
  if (isGroupCondition(c)) {
    if (depth >= 2) return '(...)';
    if ('all_of' in c && Array.isArray(c.all_of)) return `all of (${c.all_of.slice(0, MAX_SHOWN_ITEMS).map((x) => describeCondition(x, depth + 1)).join('; ')})`;
    if ('any_of' in c && Array.isArray(c.any_of)) return `any of (${c.any_of.slice(0, MAX_SHOWN_ITEMS).map((x) => describeCondition(x, depth + 1)).join('; ')})`;
    if ('not' in c) return `not (${describeCondition(c.not, depth + 1)})`;
    return '<condition>';
  }
  const f = typeof c.field === 'string' ? c.field : '<field>';
  const name = f.startsWith('action.params.') ? f.slice('action.params.'.length) : f;
  if (c.op === 'exists') return c.value === false ? `${name} absent` : `${name} present`;
  const op = typeof c.op === 'string' && Object.prototype.hasOwnProperty.call(OP_TEXT, c.op) ? OP_TEXT[c.op] : undefined;
  if (op === undefined) return `${name} <condition>`;
  return `${name} ${op} ${c.ref !== undefined ? (typeof c.ref === 'string' ? c.ref : '<ref>') : showValue(c.value)}`;
}

/** Inside an unmet top-level condition, the narrowest part that failed (an `all_of` points at its first unmet child). */
function narrowestUnmet(c: Condition, ctx: ActionContext, depth = 0): Condition {
  if (depth < 4 && isGroupCondition(c) && 'all_of' in c && Array.isArray(c.all_of)) {
    for (const x of c.all_of) if (!evaluateCondition(x, ctx)) return narrowestUnmet(x, ctx, depth + 1);
  }
  return c;
}

/**
 * B6 (0.5): when the verb and resource are in scope but a `where` limit is not met, name that limit. null when no predicate
 * is in scope (the plain "no predicate permits" wording stays for that case).
 */
function firstUnmetLimit(predicates: Predicate[], ctx: ActionContext): string | null {
  const a = ctx?.action;
  if (!a || typeof a.verb !== 'string' || typeof a.resource !== 'string') return null;
  for (const p of predicates) {
    if (p === null || typeof p !== 'object' || !verbMatches(p.verb, a.verb) || !resourceMatches(p.resource, a.resource)) continue;
    if (!Array.isArray(p.where)) continue;
    for (const c of p.where) if (!evaluateCondition(c, ctx)) return describeCondition(narrowestUnmet(c, ctx));
  }
  return null;
}

/** B6 denial wording naming the unmet limit, or undefined when none is in scope. The proved evaluator (policyvm opt-in) reuses it so both paths word a denial alike. */
export function namedUnmetLimitReason(predicates: Predicate[], ctx: ActionContext): string | undefined {
  try {
    const limit = withRegexBudget(() => firstUnmetLimit(predicates, ctx));
    const a = ctx?.action;
    return limit === null ? undefined : `${limit} not satisfied for ${String(a?.verb)} on ${String(a?.resource)}`;
  } catch {
    return undefined;
  }
}

/**
 * An action is allowed iff it matches AT LEAST ONE predicate (verb AND resource AND all `where`).
 * Default-deny: an empty predicate list allows nothing.
 */
export function evaluatePredicates(predicates: Predicate[], ctx: ActionContext): PredicateResult {
  return withRegexBudget(() => evaluatePredicatesInner(predicates, ctx));
}
function evaluatePredicatesInner(predicates: Predicate[], ctx: ActionContext): PredicateResult {
  try {
    if (!Array.isArray(predicates) || predicates.length === 0) {
      return { allowed: false, reason: 'envelope grants no predicates' };
    }
    for (const p of predicates) {
      if (predicateMatches(p, ctx)) return { allowed: true, matched: p };
    }
    const a = ctx?.action;
    const limit = firstUnmetLimit(predicates, ctx);
    if (limit !== null) return { allowed: false, reason: `${limit} not satisfied for ${String(a?.verb)} on ${String(a?.resource)}` };
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
        // Strict types: `String(x)` coercion made `class: ['irreversible']` (or any object with a toString) pass as the word.
        if (typeof caveat.class !== 'string' || typeof c.reversibilityClass !== 'string') return false;
        const lim = (REVERSIBILITY_ORDER as readonly string[]).indexOf(caveat.class);
        const cur = (REVERSIBILITY_ORDER as readonly string[]).indexOf(c.reversibilityClass);
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
      case INTENT_SESSION_CAVEAT:
        // Intent Layer v2 session binding (rule 13): no per-action constraint here; satisfied iff well-formed.
        return intentSessionCaveatError(caveat) === null;
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
  return withRegexBudget(() => evaluateCaveatsInner(caveats, ctx, evaluator));
}
function evaluateCaveatsInner(
  caveats: Caveat[],
  ctx: CaveatContext,
  evaluator: CaveatEvaluator,
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
