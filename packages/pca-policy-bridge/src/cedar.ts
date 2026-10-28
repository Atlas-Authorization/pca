import type { Condition, ConditionOp, Predicate } from '@atlasauth/pca';
import type { BridgeResult, TranslationReport } from './types';

/**
 * Cedar → PCA predicate translator.
 *
 * SUPPORTED SUBSET (documented boundary — everything else fails closed)
 * --------------------------------------------------------------------
 * A policy set is `permit`/`forbid (principal, action, resource) [when {…}] [unless {…}] ;` units,
 * separated by `;`. `//` line comments and `@annotation(...)` heads are stripped.
 *
 * Scope (the parenthesised head):
 *   - `principal`                     — unconstrained
 *   - `principal == User::"alice"`    — subject.id == "User::alice"
 *   - `principal in Group::"g"`       — member_of(subject.id, "Group::g")  (entity hierarchy)
 *   - `principal is User`             — is_a(subject.id, "User")           (entity type test)
 *   - `action`                        — any verb
 *   - `action == Action::"view"`      — verb = "view"
 *   - `action in [Action::"a", …]`    — verb = ["a", …]
 *   - `resource`                      — any resource
 *   - `resource == Photo::"p1"`       — resource = "Photo::p1"
 *   - `resource in Folder::"f"`       — member_of(action.resource, "Folder::f")
 *   - `resource is Photo`             — is_a(action.resource, "Photo")
 *
 * Conditions (inside `when` / `unless`): an arbitrary boolean expression over `&&`, `||` and
 * parentheses whose atoms are:
 *   - `<lhs> == <rhs>` | `<lhs> != <rhs>`           — eq / ne
 *   - `<lhs> < | <= | > | >= <rhs>`                  — lt / lte / gt / gte (attribute comparisons)
 *   - `<lhs> in [<lit>, …]`                          — in (membership in a LITERAL set)
 *   - `<lhs> in <Entity>`                            — member_of (entity hierarchy, bounded closure)
 *   - `<lhs> is <Type>`                              — is_a (entity type test)
 *   - `<lhs> like "<glob>"`                          — like (Cedar `*` wildcard; `\*` literal star)
 *   - `<lhs> has <attr>`                             — exists(<lhs>.<attr>)
 *   where <lhs>/<rhs> name:
 *     - `principal`         → subject.id        `principal.attr` → subject.attr
 *     - `resource`          → action.resource   `resource.attr`  → env.resource.attr
 *     - `action`            → action.verb
 *     - `context` / `context.x.y`               → env / env.x.y
 *   A right-hand side that is itself one of those paths becomes a `ref`.
 *   Right-hand literals: "string", number, true/false, and `Type::"id"` (→ "Type::id").
 *
 *   `||` → an `any_of` grouping; `&&` → an `all_of` grouping.
 *   `when { E }`   → the translated E is ANDed into the predicate's `where`.
 *   `unless { E }` → `{ not: E }` is ANDed in (so a MULTI-condition `unless { A && B }` becomes
 *                    `not(all_of[A,B])`, exact Cedar semantics).
 *
 * ENTITY HIERARCHY (`in` / member_of): the group/parent graph is supplied at evaluation time as a
 * reflexive adjacency map at `env.entity_parents` — `{ "<child uid>": ["<parent uid>", …], … }`.
 * `a in b` holds iff `b` is in the bounded, cycle-guarded transitive closure of `a` (an entity is in
 * itself, matching Cedar). Supply the entities' `parents` closure under that key.
 *
 * Mapping of policy effect:
 *   - `permit` → a permit predicate (`result.predicates`)
 *   - `forbid` → a deny predicate (`result.denies`); consume with {@link decide} (deny-overrides).
 *
 * NOT MODELED (reported, fails closed) — the honest minimum:
 *   - arithmetic in a comparison (`resource.a + 1 < 10`), the set operations `.contains()` /
 *     `.containsAll()` / `.containsAny()`, `if-then-else`, record/set construction, and the
 *     extension functions (`ip(...)`, `decimal(...)`, `.isInRange(...)`, …).
 */
export function cedarToPca(policyText: string): BridgeResult {
  return translateCedar(policyText, true);
}

/**
 * Internal: `errorGuards: false` omits the trailing "no attribute was missing" guard, leaving the bare
 * structure of each expression. It is NOT exported from the package: without the guard the result is not
 * exact for policies that read attributes the request may lack. The structure tests use it.
 */
export function translateCedar(policyText: string, errorGuards: boolean): BridgeResult {
  const report: TranslationReport = { source: 'cedar', translated: [], skipped: [], errors: [] };
  const predicates: Predicate[] = [];
  const denies: Predicate[] = [];

  const cleaned = stripComments(policyText);
  const statements = splitTopLevel(cleaned, ';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  for (const stmt of statements) {
    try {
      translateStatement(stmt, predicates, denies, report, errorGuards);
    } catch (e) {
      report.errors.push(`policy "${truncate(stmt)}": ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return { predicates, denies, caveats: [], report };
}

/** The reflexive adjacency map (child uid -> parent uid[]) that `in`/member_of resolves against. */
const ENTITY_PARENTS = 'env.entity_parents';

// --- statement ---------------------------------------------------------------------------------

function translateStatement(stmt: string, permits: Predicate[], denies: Predicate[], report: TranslationReport, errorGuards: boolean): void {
  // Strip leading @annotation(...) heads.
  let body = stmt;
  const annot = /^\s*(@[A-Za-z_][\w]*\s*\([^)]*\)\s*)+/.exec(body);
  if (annot) body = body.slice(annot[0].length);

  const head = /^\s*(permit|forbid)\s*\(/i.exec(body);
  if (!head) {
    report.skipped.push(`unrecognized statement: "${truncate(stmt)}"`);
    return;
  }
  const effect = head[1]?.toLowerCase() === 'forbid' ? 'forbid' : 'permit';

  const openIdx = body.indexOf('(', head.index);
  const closeIdx = matchParen(body, openIdx);
  if (closeIdx < 0) throw new Error('unterminated scope parentheses');
  const scopeText = body.slice(openIdx + 1, closeIdx);
  const rest = body.slice(closeIdx + 1);

  const scope = parseScope(scopeText);

  const where: Condition[] = [...scope.scopeConditions];
  const guards: Condition[] = [];

  // Collect when / unless blocks.
  const blocks = parseConditionBlocks(rest);
  for (const block of blocks) {
    const parsed = parseExpr(block.text);
    if (parsed === null) {
      report.skipped.push(`unmodeled ${block.kind}-condition "${truncate(block.text)}" — policy dropped (fail closed)`);
      dropPolicy(effect, stmt, report);
      return;
    }
    where.push(block.kind === 'when' ? parsed : { not: parsed });
    const g = noError(parsed);
    if (g !== null) guards.push(g);
  }

  // Cedar skips a policy whose condition raises an error (a missing attribute), for `unless` as much as for
  // `when`; the core evaluator would instead let `not` of an undecidable leaf be decided by its siblings. The
  // trailing guard makes the policy apply only when evaluating the expressions, left to right with
  // short-circuiting, reads no absent attribute.
  const conditionCount = where.length;
  if (errorGuards && guards.length > 0) where.push(guards.length === 1 ? (guards[0] as Condition) : { all_of: guards });

  const predicate: Predicate = { verb: scope.verb };
  if (scope.resource !== undefined) predicate.resource = scope.resource;
  if (where.length > 0) predicate.where = where;

  if (effect === 'permit') {
    permits.push(predicate);
    report.translated.push(
      `permit → verb ${JSON.stringify(scope.verb)}${scope.resource ? ` on ${scope.resource}` : ''} (${conditionCount} condition(s))`,
    );
  } else {
    denies.push(predicate);
    report.translated.push(
      `forbid → deny verb ${JSON.stringify(scope.verb)}${scope.resource ? ` on ${scope.resource}` : ''} (${conditionCount} condition(s))`,
    );
  }
}

/** A dropped `permit` simply grants nothing; a dropped `forbid` is unsafe, so it is an ERROR. */
function dropPolicy(effect: 'permit' | 'forbid', stmt: string, report: TranslationReport): void {
  if (effect === 'forbid') {
    report.errors.push(`forbid could not be fully modeled and was dropped — treat result as fail-closed: "${truncate(stmt)}"`);
  }
}

// --- scope -------------------------------------------------------------------------------------

interface ScopeResult {
  verb: string | string[];
  resource?: string;
  scopeConditions: Condition[];
}

function parseScope(scopeText: string): ScopeResult {
  const clauses = splitTopLevel(scopeText, ',')
    .map((c) => c.trim())
    .filter((c) => c.length > 0);
  const result: ScopeResult = { verb: '*', scopeConditions: [] };

  for (const clause of clauses) {
    const m = /^(principal|action|resource)\b\s*(?:(==|in|is)\s*)?([\s\S]*)$/.exec(clause);
    if (!m) throw new Error(`unparseable scope clause "${truncate(clause)}"`);
    const variable = m[1];
    const op = m[2];
    const operand = (m[3] ?? '').trim();

    if (!op) continue; // unconstrained (bare principal/action/resource)

    if (variable === 'action') {
      if (op === '==') {
        const id = entityId(operand);
        if (id === null) throw new Error(`action == expects an Action entity, got "${truncate(operand)}"`);
        result.verb = id;
      } else if (op === 'in' && operand.startsWith('[')) {
        const items = splitTopLevel(operand.slice(1, -1), ',')
          .map((x) => x.trim())
          .filter((x) => x.length > 0);
        const verbs: string[] = [];
        for (const it of items) {
          const id = entityId(it);
          if (id === null) throw new Error(`action in [...] expects Action entities, got "${truncate(it)}"`);
          verbs.push(id);
        }
        result.verb = verbs;
      } else {
        throw new Error(`unsupported action scope operator "${op}"`);
      }
    } else {
      const field = variable === 'resource' ? 'action.resource' : 'subject.id';
      if (op === '==') {
        if (variable === 'resource') {
          const eid = entityUid(operand);
          if (eid === null) throw new Error(`resource == expects an entity, got "${truncate(operand)}"`);
          result.resource = eid;
        } else {
          const eid = entityUid(operand);
          if (eid === null) throw new Error(`principal == expects an entity, got "${truncate(operand)}"`);
          result.scopeConditions.push({ field, op: 'eq', value: eid });
        }
      } else if (op === 'is') {
        const type = typeName(operand);
        if (type === null) throw new Error(`${variable} is expects a type, got "${truncate(operand)}"`);
        result.scopeConditions.push({ field, op: 'is_a', value: type });
      } else {
        // op === 'in' : entity-hierarchy membership
        const mem = memberOfCondition(field, operand);
        if (mem === null) throw new Error(`${variable} in expects an entity (hierarchy), got "${truncate(operand)}"`);
        result.scopeConditions.push(mem);
      }
    }
  }
  return result;
}

// --- conditions --------------------------------------------------------------------------------

interface ConditionBlock {
  kind: 'when' | 'unless';
  text: string;
}

function parseConditionBlocks(rest: string): ConditionBlock[] {
  const blocks: ConditionBlock[] = [];
  const re = /\b(when|unless)\b\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rest)) !== null) {
    const kind = m[1] === 'unless' ? 'unless' : 'when';
    const open = rest.indexOf('{', m.index);
    const close = matchBrace(rest, open);
    if (close < 0) throw new Error(`unterminated ${kind} block`);
    blocks.push({ kind, text: rest.slice(open + 1, close) });
    re.lastIndex = close + 1;
  }
  return blocks;
}

/**
 * Parse a boolean expression: `||` (lowest precedence, → any_of) over `&&` (→ all_of) over
 * parenthesised groups over single comparison atoms. Returns null if any atom is outside the subset.
 */
function parseExpr(text: string): Condition | null {
  const t = text.trim();
  if (t.length === 0) return null;

  const ors = splitTopLevel(t, '||')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (ors.length > 1) {
    const subs = ors.map(parseExpr);
    if (subs.some((s) => s === null)) return null;
    return { any_of: subs as Condition[] };
  }

  const ands = splitTopLevel(t, '&&')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (ands.length > 1) {
    const subs = ands.map(parseExpr);
    if (subs.some((s) => s === null)) return null;
    return { all_of: subs as Condition[] };
  }

  // Single term: strip a fully-enclosing parenthesis, else parse one atom.
  if (t.startsWith('(') && matchParen(t, 0) === t.length - 1) return parseExpr(t.slice(1, -1));
  return parseAtom(t);
}

/** Parse one comparison atom → a leaf Condition, or null if outside the subset. */
function parseAtom(text: string): Condition | null {
  const t = text.trim();

  // Symbolic comparison operators, longest token first (so `<=`/`>=`/`==`/`!=` win over `<`/`>`).
  for (const [tok, op] of [
    ['==', 'eq'],
    ['!=', 'ne'],
    ['<=', 'lte'],
    ['>=', 'gte'],
    ['<', 'lt'],
    ['>', 'gt'],
  ] as const) {
    const idx = indexOfTopLevel(t, tok);
    if (idx >= 0) {
      const lhs = t.slice(0, idx).trim();
      const rhs = t.slice(idx + tok.length).trim();
      return buildComparison(lhs, op, rhs);
    }
  }

  // Word operators: `in`, `is`, `like`, `has`.
  // `\S` before the gap: a lazy `[\s\S]+?` followed by `\s+` retried the whole whitespace run from every position (quadratic).
  const wm = /^([\s\S]*?\S)\s+(in|is|like|has)\s+([\s\S]+)$/.exec(t);
  if (wm) return buildWordOp((wm[1] ?? '').trim(), wm[2] ?? '', (wm[3] ?? '').trim());

  // A bare expression (`resource.flag`, `principal.foo.contains("x")`, …) is not modeled.
  return null;
}

function buildComparison(lhsRaw: string, op: ConditionOp, rhsRaw: string): Condition | null {
  const field = toFieldPath(lhsRaw);
  if (field === null) return null; // arithmetic / method-call LHS not modeled
  if (field === 'action.verb') {
    // The verb is the entity id (`Action::"edit"` -> `edit`), exactly as in the scope. Only == and != are modeled.
    if (op !== 'eq' && op !== 'ne') return null;
    const id = entityId(rhsRaw);
    return id === null ? null : { field, op, value: id };
  }
  if (isPathExpr(rhsRaw)) {
    const refPath = toFieldPath(rhsRaw);
    if (refPath !== null) return { field, op, ref: refPath };
  }
  const lit = toLiteral(rhsRaw);
  if (!lit.ok) return null;
  return { field, op, value: lit.value };
}

function buildWordOp(lhsRaw: string, kind: string, rhsRaw: string): Condition | null {
  if (kind === 'has') {
    // `principal has department` → exists(subject.department)
    if (!/^[A-Za-z_][\w]*$/.test(rhsRaw)) return null;
    const field = toFieldPath(`${lhsRaw}.${rhsRaw}`);
    return field === null ? null : { field, op: 'exists' };
  }

  const field = toFieldPath(lhsRaw);
  if (field === null) return null;

  if (field === 'action.verb') {
    // `action in [Action::"a", ...]` / `action in Action::"a"`: the verb is one of the ids. Action groups are not modeled.
    if (kind !== 'in') return null;
    const inner = rhsRaw.startsWith('[') && rhsRaw.endsWith(']') ? rhsRaw.slice(1, -1) : rhsRaw;
    const ids = splitTopLevel(inner, ',').map((x) => x.trim()).filter((x) => x.length > 0).map(entityId);
    return ids.length > 0 && ids.every((i) => i !== null) ? { field, op: 'in', value: ids as string[] } : null;
  }

  if (kind === 'is') {
    const type = typeName(rhsRaw);
    return type === null ? null : { field, op: 'is_a', value: type };
  }

  if (kind === 'like') {
    const str = /^"([\s\S]*)"$/.exec(rhsRaw);
    if (!str) return null;
    return { field, op: 'like', value: cedarLikeToGlob(str[1] ?? '') };
  }

  // kind === 'in'
  if (rhsRaw.startsWith('[')) {
    // Membership in a LITERAL set.
    const inner = rhsRaw.endsWith(']') ? rhsRaw.slice(1, -1) : rhsRaw.slice(1);
    const items = splitTopLevel(inner, ',')
      .map((x) => x.trim())
      .filter((x) => x.length > 0);
    // A set of entities (`[Group::"a", Group::"b"]`) is still a hierarchy membership (any-of).
    if (items.every((it) => entityUid(it) !== null) && items.length > 0) {
      const uids = items.map((it) => entityUid(it)!);
      return { field, op: 'member_of', value: uids, collection: ENTITY_PARENTS };
    }
    const values: unknown[] = [];
    for (const it of items) {
      const lit = toLiteral(it);
      if (!lit.ok) return null;
      values.push(lit.value);
    }
    return { field, op: 'in', value: values };
  }
  // `lhs in Entity` → hierarchy membership (bounded closure).
  return memberOfCondition(field, rhsRaw);
}

/** A `member_of` condition for `<field> in <entity|path>` (entity literal → value; path → ref). */
function memberOfCondition(field: string, operand: string): Condition | null {
  const eid = entityUid(operand);
  if (eid !== null) return { field, op: 'member_of', value: eid, collection: ENTITY_PARENTS };
  if (isPathExpr(operand)) {
    const ref = toFieldPath(operand);
    if (ref !== null) return { field, op: 'member_of', ref, collection: ENTITY_PARENTS };
  }
  return null;
}

/** Does an expression refer to a Cedar scope variable (principal/resource/action/context)? */
function isPathExpr(expr: string): boolean {
  return /^(principal|resource|action|context)\b/.test(expr);
}

/** Map a Cedar scope-variable expression to a PCA dotted field path; null if not a path. */
function toFieldPath(expr: string): string | null {
  if (expr === 'principal') return 'subject.id';
  if (expr === 'resource') return 'action.resource';
  if (expr === 'action') return 'action.verb';
  if (expr === 'context') return 'env';
  const mp = /^principal\.([A-Za-z_][\w.]*)$/.exec(expr);
  if (mp) return `subject.${mp[1]}`;
  const mr = /^resource\.([A-Za-z_][\w.]*)$/.exec(expr);
  if (mr) return `env.resource.${mr[1]}`;
  const mc = /^context\.([A-Za-z_][\w.]*)$/.exec(expr);
  if (mc) return `env.${mc[1]}`;
  return null;
}

// --- literals / entities -----------------------------------------------------------------------

/** A Cedar type name (`User`, `Ns::User`), or null. */
function typeName(expr: string): string | null {
  const s = expr.trim();
  return /^[A-Za-z_][\w]*(::[A-Za-z_][\w]*)*$/.test(s) ? s : null;
}

/** The quoted id of an entity reference `Ns::Type::"id"`, or null. */
function entityId(expr: string): string | null {
  const m = /^.+::"([^"]*)"$/.exec(expr.trim());
  return m ? (m[1] ?? '') : null;
}

/** An entity reference rendered as its UID with quotes dropped: `Type::"id"` → `Type::id`. */
function entityUid(expr: string): string | null {
  const m = /^(.+)::"([^"]*)"$/.exec(expr.trim());
  if (!m) return null;
  return `${m[1]}::${m[2] ?? ''}`;
}

function toLiteral(expr: string): { ok: true; value: unknown } | { ok: false } {
  const s = expr.trim();
  const str = /^"([^"]*)"$/.exec(s);
  if (str) return { ok: true, value: str[1] ?? '' };
  if (s === 'true') return { ok: true, value: true };
  if (s === 'false') return { ok: true, value: false };
  if (/^-?\d+(\.\d+)?$/.test(s)) return { ok: true, value: Number(s) };
  const eid = entityUid(s);
  if (eid !== null) return { ok: true, value: eid };
  return { ok: false };
}

/**
 * Convert a Cedar `like` pattern (only `*` is a wildcard; `\*` is a literal star) to the PCA glob the
 * `like` op understands (`*`/`?` wildcards, `\` escapes). Cedar's literal `?` and `\` are escaped so
 * they stay literal.
 */
function cedarLikeToGlob(inner: string): string {
  let out = '';
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i]!;
    if (ch === '\\') {
      const n = inner[i + 1];
      if (n === '*') {
        out += '\\*'; // Cedar literal star
        i++;
        continue;
      }
      if (n !== undefined) {
        out += escapeGlobLiteral(n);
        i++;
        continue;
      }
      out += '\\\\';
      continue;
    }
    if (ch === '*') {
      out += '*'; // wildcard
      continue;
    }
    out += escapeGlobLiteral(ch);
  }
  return out;
}

function escapeGlobLiteral(ch: string): string {
  return ch === '*' || ch === '?' || ch === '\\' ? '\\' + ch : ch;
}

// --- text helpers ------------------------------------------------------------------------------

function stripComments(text: string): string {
  return text.replace(/\/\/[^\n]*/g, '');
}

function truncate(s: string): string {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > 80 ? `${one.slice(0, 77)}...` : one;
}

/** Index of `token` at bracket/quote depth 0, or -1. */
function indexOfTopLevel(text: string, token: string): number {
  let depth = 0;
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] ?? '';
    if (inStr) {
      if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (depth === 0 && text.startsWith(token, i)) return i;
  }
  return -1;
}

/** Split on a delimiter at bracket/quote depth 0. `delim` is 1 or 2 chars. */
function splitTopLevel(text: string, delim: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let inStr = false;
  let buf = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] ?? '';
    if (inStr) {
      buf += ch;
      if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      buf += ch;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    if (depth === 0 && text.startsWith(delim, i)) {
      out.push(buf);
      buf = '';
      i += delim.length - 1;
      continue;
    }
    buf += ch;
  }
  out.push(buf);
  return out;
}

function matchParen(text: string, open: number): number {
  return matchDelim(text, open, '(', ')');
}
function matchBrace(text: string, open: number): number {
  return matchDelim(text, open, '{', '}');
}
function matchDelim(text: string, open: number, o: string, c: string): number {
  let depth = 0;
  let inStr = false;
  for (let i = open; i < text.length; i++) {
    const ch = text[i] ?? '';
    if (inStr) {
      if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') inStr = true;
    else if (ch === o) depth++;
    else if (ch === c) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}


// --- Cedar evaluation-error semantics ------------------------------------------------------------

/** Fields that exist on every request, so reading them never raises a Cedar error. */
const TOTAL_FIELDS = new Set(['subject.id', 'action.verb', 'action.resource', 'env']);

/** Attribute reads that can raise a Cedar "attribute missing" error: `principal.x`, `resource.x`, `context.x`. */
function guardedPaths(field: string | undefined): string[] {
  if (field === undefined || TOTAL_FIELDS.has(field) || field.startsWith('env.entity_parents')) return [];
  return /^(subject\.|env\.)/.test(field) ? [field] : [];
}

const exists = (field: string): Condition => ({ field, op: 'exists' });
const allOf = (xs: Condition[]): Condition => (xs.length === 1 ? (xs[0] as Condition) : { all_of: xs });
const anyOf = (xs: Condition[]): Condition => (xs.length === 1 ? (xs[0] as Condition) : { any_of: xs });

/**
 * "Evaluating this expression raises no Cedar error", as a condition (null = it cannot). Cedar evaluates
 * `a && b` and `a || b` left to right and does not look at `b` once `a` has decided, so `b` only needs its
 * attributes present when `a` was true (for `&&`) or false (for `||`). Linear in the size of the expression.
 */
function noError(c: Condition): Condition | null {
  if ('not' in c) return noError(c.not);
  if ('all_of' in c || 'any_of' in c) {
    const isAnd = 'all_of' in c;
    const kids = isAnd ? c.all_of : c.any_of;
    // Fold from the right: N(k1 op rest) = N(k1) && (k1 decides ? true : N(rest)).
    let acc: Condition | null = null;
    for (let i = kids.length - 1; i >= 0; i--) {
      const kid = kids[i] as Condition;
      const n = noError(kid);
      const cont: Condition | null = acc === null ? null : anyOf([isAnd ? { not: kid } : kid, acc]);
      acc = n === null ? cont : cont === null ? n : allOf([n, cont]);
    }
    return acc;
  }
  const leaf = c as { field?: string; ref?: string; op?: string };
  if (leaf.op === 'exists' && leaf.field !== undefined) {
    // `a.b has c` raises an error when `a.b` itself is missing; `principal has c` cannot.
    const base = leaf.field.replace(/\.[^.]+$/, '');
    const deep = base.split('.').length >= (base.startsWith('env.resource') ? 3 : 2);
    const baseNeeds = deep ? guardedPaths(base).map(exists) : [];
    return baseNeeds.length === 0 ? null : allOf(baseNeeds);
  }
  const needs: Condition[] = [...guardedPaths(leaf.field), ...guardedPaths(leaf.ref)].map(exists);
  return needs.length === 0 ? null : allOf(needs);
}
