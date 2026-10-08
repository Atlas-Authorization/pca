import type { Condition, ConditionOp, Predicate } from '@atlasauth/pca';
import type { BridgeResult, TranslationReport } from './types';

/**
 * OPA/Rego → PCA predicate translator.
 *
 * Rego is Turing-complete. This translator models ONLY the ubiquitous "allow-rule as a conjunction
 * of input comparisons" idiom and fails closed on everything else — an unmodeled construct never
 * widens an allow.
 *
 * SUPPORTED SUBSET (documented boundary)
 * --------------------------------------
 *   package <name>                     — recorded, otherwise ignored
 *   default allow = false              — the only safe default; anything else is reported & ignored
 *   allow { <body> }                   — also `allow = true { }`, `allow := true { }`, `allow if { }`
 *
 * Each `allow` rule body is a conjunction of statements (one per line or `;`). Each `allow` rule is
 * an independent predicate (rules OR together — Rego's multiple-definition semantics).
 *
 * Statements, where a path is `input.<dotted>`:
 *   - `input.action == "x"`            — sets the predicate VERB (special field)
 *   - `input.action in {"a","b"}`      — verb = ["a","b"]
 *   - `input.resource == "r"`          — sets the predicate RESOURCE (special field)
 *   - `input.<p> == <lit>` / `!=`      — eq / ne condition on env.<p>
 *   - `input.<p> in {set}` / `[array]` — in condition (membership in a literal set)
 *   - `input.<p> < <num>` `<=` `>` `>=`— numeric comparison (lt/lte/gt/gte)
 *   - `input.<p> == input.<q>`         — ref comparison (env.<p> == env.<q>)
 *   - `not <stmt>`                     — negation (→ a `not` grouping); the inner must itself be a
 *                                        modeled CONDITION (not a verb/resource selector)
 *   - `startswith(input.<p>, "pre")`   — prefix condition (exact: startswith is anchored-at-start)
 *   - `glob.match("pat", [], input.<p>)` / `glob.match("pat", null, input.<p>)` — like condition
 *     (glob.match is whole-string/anchored; with empty/null delimiters `*` spans everything)
 * Literals: "string", number, true/false.
 *
 * NOT MODELED (reported; the ENTIRE containing rule is dropped — a conjunct we cannot model could
 * only be dropped by WIDENING the allow, which is unsafe). This is the honest minimum, all of it
 * genuinely beyond a finite predicate:
 *   - `:=` local assignment; `some`/`every`, comprehensions, iteration/wildcards (`input.xs[_]`) —
 *     bounded quantification / iteration with side conditions;
 *   - arbitrary function/builtin calls other than the pure anchored matchers above (`count(...)`,
 *     `regex.match(...)` — unanchored, so not faithfully an anchored `matches` — `endswith(...)` —
 *     no suffix op — `net.cidr_contains(...)`, …);
 *   - references to other rules, object/set construction in the body, bare truthiness (`input.flag`),
 *     and reverse membership `"lit" in input.coll` (a literal inside an input collection).
 */
export function regoToPca(moduleText: string): BridgeResult {
  const report: TranslationReport = { source: 'rego', translated: [], skipped: [], errors: [] };
  const predicates: Predicate[] = [];

  const src = stripComments(moduleText);

  const pkg = /\bpackage\s+([A-Za-z_][\w.]*)/.exec(src);
  if (pkg) report.translated.push(`package ${pkg[1]}`);

  const def = /\bdefault\s+allow\s*(?::?=)\s*(true|false)\b/.exec(src);
  if (def && def[1] === 'true') {
    report.skipped.push('`default allow = true` is not modeled (cannot express allow-unless); treated as default-deny');
  } else if (!def) {
    report.skipped.push('no `default allow = false` found; assuming default-deny');
  }

  for (const body of extractAllowBodies(src, report)) {
    translateRule(body, predicates, report);
  }

  return { predicates, denies: [], caveats: [], report };
}

function translateRule(body: string, predicates: Predicate[], report: TranslationReport): void {
  const statements = body
    .split(/[\n;]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  let verb: string | string[] = '*';
  let resource: string | undefined;
  const where: Condition[] = [];

  for (const stmt of statements) {
    const parsed = parseStatement(stmt);
    if (parsed.kind === 'unmodeled') {
      report.skipped.push(`unmodeled statement "${truncate(stmt)}" — rule dropped (fail closed)`);
      return; // drop the whole rule
    }
    if (parsed.kind === 'verb') {
      verb = parsed.verb;
    } else if (parsed.kind === 'resource') {
      resource = parsed.resource;
    } else {
      where.push(parsed.condition);
    }
  }

  const predicate: Predicate = { verb };
  if (resource !== undefined) predicate.resource = resource;
  if (where.length > 0) predicate.where = where;
  predicates.push(predicate);
  report.translated.push(`allow → verb ${JSON.stringify(verb)}${resource ? ` on ${resource}` : ''} (${where.length} condition(s))`);
}

type Parsed =
  | { kind: 'verb'; verb: string | string[] }
  | { kind: 'resource'; resource: string }
  | { kind: 'condition'; condition: Condition }
  | { kind: 'unmodeled' };

function parseStatement(stmt: string): Parsed {
  let s = stmt.trim();

  // `not <stmt>` — negation. The inner must resolve to a modeled CONDITION (not a verb/resource
  // selector, which cannot be negated inside a single monotone predicate).
  const nm = /^not\s+([\s\S]+)$/.exec(s);
  if (nm) {
    const inner = parseStatement((nm[1] ?? '').trim());
    if (inner.kind !== 'condition') return { kind: 'unmodeled' };
    return { kind: 'condition', condition: { not: inner.condition } };
  }

  // Pure, anchored matcher builtins map exactly onto `prefix` / `like`.
  const builtin = parseBuiltin(s);
  if (builtin !== 'skip') return builtin;

  if (/:=|\bsome\b|\bevery\b|\[.*\|.*\]/.test(s)) return { kind: 'unmodeled' };
  if (s.includes('(')) return { kind: 'unmodeled' }; // other function / builtin call
  if (/\binput\.[\w.]*\[/.test(s)) return { kind: 'unmodeled' }; // iteration / index

  // Comparison: input.<path> <op> <rhs>
  stmt = s;
  const m = /^(input\.[\w.]+)\s*(==|!=|<=|>=|<|>|\bin\b)\s*(.+)$/s.exec(stmt);
  if (!m) return { kind: 'unmodeled' };
  const path = m[1] ?? '';
  const opTok = m[2] ?? '';
  const rhsRaw = (m[3] ?? '').trim();
  const sub = path.slice('input.'.length); // the dotted remainder

  if (opTok === 'in') {
    const set = parseSetLiteral(rhsRaw);
    if (!set.ok) return { kind: 'unmodeled' };
    if (sub === 'action') {
      const verbs = set.values.filter((v): v is string => typeof v === 'string');
      if (verbs.length !== set.values.length) return { kind: 'unmodeled' };
      return { kind: 'verb', verb: verbs };
    }
    return { kind: 'condition', condition: { field: `env.${sub}`, op: 'in', value: set.values } };
  }

  // Equality to another input path => ref.
  if ((opTok === '==' || opTok === '!=') && /^input\.[\w.]+$/.test(rhsRaw)) {
    const op: ConditionOp = opTok === '!=' ? 'ne' : 'eq';
    return { kind: 'condition', condition: { field: `env.${sub}`, op, ref: `env.${rhsRaw.slice('input.'.length)}` } };
  }

  const lit = toLiteral(rhsRaw);
  if (!lit.ok) return { kind: 'unmodeled' };

  if (opTok === '==') {
    if (sub === 'action' && typeof lit.value === 'string') return { kind: 'verb', verb: lit.value };
    if (sub === 'resource' && typeof lit.value === 'string') return { kind: 'resource', resource: lit.value };
    return { kind: 'condition', condition: { field: `env.${sub}`, op: 'eq', value: lit.value } };
  }
  if (opTok === '!=') return { kind: 'condition', condition: { field: `env.${sub}`, op: 'ne', value: lit.value } };

  // Numeric comparisons only make sense against a number.
  if (typeof lit.value !== 'number') return { kind: 'unmodeled' };
  const cmp: ConditionOp = opTok === '<' ? 'lt' : opTok === '<=' ? 'lte' : opTok === '>' ? 'gt' : 'gte';
  return { kind: 'condition', condition: { field: `env.${sub}`, op: cmp, value: lit.value } };
}

/**
 * Parse a pure, anchored matcher builtin into a condition. `'skip'` means "not a builtin we model"
 * (fall through); a `{ kind: 'unmodeled' }` means "a builtin we recognise but whose argument shape is
 * outside the modeled subset" (drop the rule, fail closed).
 */
function parseBuiltin(s: string): Parsed | 'skip' {
  // startswith(input.<p>, "pre") — anchored-at-start, exactly the `prefix` op.
  const sw = /^startswith\(\s*(input\.[\w.]+)\s*,\s*"([^"]*)"\s*\)$/.exec(s);
  if (sw) {
    const sub = (sw[1] ?? '').slice('input.'.length);
    return { kind: 'condition', condition: { field: `env.${sub}`, op: 'prefix', value: sw[2] ?? '' } };
  }
  // glob.match("pat", [] | null, input.<p>) — whole-string match; empty/null delimiters => `*` spans all.
  const gm = /^glob\.match\(\s*"([^"]*)"\s*,\s*(\[\s*\]|null)\s*,\s*(input\.[\w.]+)\s*\)$/.exec(s);
  if (gm) {
    const pattern = gm[1] ?? '';
    // Only the `*` / `?` / `\`-escape / literal subset maps to the `like` glob; character classes and
    // brace alternation (`[...]`, `{...}`) do not — fail closed rather than mis-translate.
    if (/[[\]{}]/.test(pattern)) return { kind: 'unmodeled' };
    const sub = (gm[3] ?? '').slice('input.'.length);
    return { kind: 'condition', condition: { field: `env.${sub}`, op: 'like', value: pattern } };
  }
  return 'skip';
}

/** Find each `allow` rule body `{ ... }`, brace-aware (set literals inside the body use braces). */
function extractAllowBodies(src: string, report: TranslationReport): string[] {
  const bodies: string[] = [];
  const re = /\ballow\b\s*(?::?=\s*true\b|=\s*true\b|\bif\b)?\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    const open = src.indexOf('{', m.index);
    const close = matchBrace(src, open);
    if (close < 0) {
      report.errors.push('unterminated `allow { ... }` block');
      break;
    }
    bodies.push(src.slice(open + 1, close));
    re.lastIndex = close + 1;
  }
  return bodies;
}

// --- literals ----------------------------------------------------------------------------------

function toLiteral(expr: string): { ok: true; value: unknown } | { ok: false } {
  const s = expr.trim();
  const str = /^"([^"]*)"$/s.exec(s);
  if (str) return { ok: true, value: str[1] ?? '' };
  if (s === 'true') return { ok: true, value: true };
  if (s === 'false') return { ok: true, value: false };
  if (/^-?\d+(\.\d+)?$/.test(s)) return { ok: true, value: Number(s) };
  return { ok: false };
}

/** Parse a Rego set `{"a","b"}` or array `["a","b"]` of scalar literals. */
function parseSetLiteral(expr: string): { ok: true; values: unknown[] } | { ok: false } {
  const s = expr.trim();
  const isSet = s.startsWith('{') && s.endsWith('}');
  const isArr = s.startsWith('[') && s.endsWith(']');
  if (!isSet && !isArr) return { ok: false };
  const inner = s.slice(1, -1);
  const items = splitTopLevel(inner, ',').map((x) => x.trim()).filter((x) => x.length > 0);
  const values: unknown[] = [];
  for (const it of items) {
    const lit = toLiteral(it);
    if (!lit.ok) return { ok: false };
    values.push(lit.value);
  }
  return { ok: true, values };
}

// --- text helpers ------------------------------------------------------------------------------

function stripComments(text: string): string {
  return text.replace(/#[^\n]*/g, '');
}

function truncate(s: string): string {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > 80 ? `${one.slice(0, 77)}...` : one;
}

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

function matchBrace(text: string, open: number): number {
  let depth = 0;
  let inStr = false;
  for (let i = open; i < text.length; i++) {
    const ch = text[i] ?? '';
    if (inStr) {
      if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') inStr = true;
    else if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}
