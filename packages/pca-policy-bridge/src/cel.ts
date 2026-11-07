import type { Condition, Predicate } from '@atlasauth/pca';
import type { BridgeResult } from './types';

/**
 * STRICT CEL IMPORT (Google IAM Conditions / Kubernetes ValidatingAdmissionPolicy / SpiceDB caveat expressions).
 *
 * `celToCondition` turns ONE boolean CEL expression into a PCA `Condition` or REJECTS it. There is no best-effort mode: a
 * condition that is silently dropped or approximated would widen what a policy admits, so any construct outside the subset below
 * is refused with the construct named. PCA's total predicate DSL stays the only evaluator; no CEL runs anywhere.
 *
 * EXACTNESS. For every context the host maps through the schema, the translation is `true` exactly when the CEL expression
 * evaluates to `true`; an expression that errors in CEL (a missing key, a type with no overload) is `unknown` in PCA, and PCA's
 * Kleene `all_of` / `any_of` / `not` agree with CEL's error-absorbing `&&` / `||` / `!` on those. Equality across types is false
 * in both (CEL heterogeneous equality). The checked-in differential test evaluates the parsed expression with a reference
 * CEL evaluator and the translation with the PCA evaluator over a grid of contexts and requires the same answer.
 *
 * THE SUBSET (everything else is rejected):
 *  - identifiers: dotted names declared in the schema (`resource.name`, `object.spec.replicas`); each maps to one PCA path and one
 *    type (`string`, `int`, `bool`, `timestamp_ms`). Nothing is inferred.
 *  - literals: decimal integers within the safe-integer range (`-5` allowed), strings (escapes `\\ \" \' \n \t \r` only), `true`/`false`
 *    only as an operand of `==` / `!=` (a bare boolean variable is rejected: write `flag == true`), `timestamp("YYYY-MM-DDTHH:MM:SS[.mmm]Z")` (UTC, millisecond precision, compared with
 *    a `timestamp_ms` variable), list literals of one type (only as the right side of `in`).
 *  - `&&`, `||`, `!`, parentheses; `==`, `!=` (variable against literal or variable), `<`, `<=`, `>`, `>=` (int, string, timestamp),
 *    `x in [a, b]`, `s.startsWith("lit")`, `s.endsWith("lit")`, `s.contains("lit")`, and `has(v)` for a variable the schema marks
 *    `optional` (the container is always present and the field may be absent, which is when CEL `has` and PCA `exists` agree).
 * REJECTED, by name: arithmetic, `?:`, `[]` indexing, maps, `size`, `matches` (CEL's is a search, PCA's is anchored), `exists`/`all`/
 *    `map`/`filter`, type conversions, doubles, `1u`, bytes, raw and triple-quoted strings, `\u`/`\x` escapes, durations, `null`, bare
 *    boolean constants, an expression with no variable in it, comparisons of two literals, chained comparisons.
 *
 * KNOWN, STRICTER-ONLY BOUND: `endsWith` and `contains` become a glob (`like`); PCA evaluates `like` only on values of at most 512
 * characters and answers `unknown` (never true) above that, where CEL would answer. This can only withhold an allow.
 *
 * USE: the result is a PERMIT condition (`where`). To use a CEL expression as a DENY, evaluate it separately and treat `unknown` as
 * deny (IAM semantics); do not negate it here.
 */
export type CelType = 'string' | 'int' | 'bool' | 'timestamp_ms';
export interface CelVar {
  /** The PCA path (`action.params.replicas`, `env.now`, `subject.groups`) the variable reads. */
  path: string;
  type: CelType;
  /** The container is always present and the field may be absent; required for `has()`. */
  optional?: boolean;
}
export interface CelSchema {
  vars: Record<string, CelVar>;
}
export type CelErrorCode = 'syntax' | 'unsupported' | 'unknown_identifier' | 'type_mismatch' | 'too_complex' | 'constant_expression' | 'has_requires_optional' | 'bad_schema';
export interface CelError { ok: false; code: CelErrorCode; message: string; at: number }
export type CelResult = { ok: true; condition: Condition; fields: string[] } | CelError;

const MAX_EXPR = 4096;
const MAX_DEPTH = 32;
const MAX_NODES = 256;
const MAX_LIST = 64;
const MAX_STR = 256;
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/;
const PCA_PATH = /^(action|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)+$/;
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);

class Reject extends Error {
  constructor(readonly code: CelErrorCode, message: string, readonly at: number) { super(message); }
}
const rej = (code: CelErrorCode, message: string, at: number): never => { throw new Reject(code, message, at); };

// ---- tokens ---------------------------------------------------------------------------------------------------------------
type Tok = { k: 'id' | 'int' | 'str' | 'p'; v: string; at: number };
const PUNCT = ['&&', '||', '==', '!=', '<=', '>=', '<', '>', '!', '(', ')', '[', ']', ',', '.', '-'];
const UNSUPPORTED_CH: Record<string, string> = { '+': 'arithmetic (+)', '*': 'arithmetic (*)', '/': 'arithmetic (/)', '%': 'arithmetic (%)', '?': 'the conditional operator', ':': 'the conditional operator / map literal', '{': 'map or message literal', '}': 'map or message literal', '@': '@', '&': 'bitwise &', '|': 'bitwise |', '^': '^', '~': '~', '=': 'assignment', '`': 'quoted identifier' };

function lex(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue; }
    if (c === '/' && src[i + 1] === '/') rej('unsupported', 'comments', i);
    if (/[A-Za-z_]/.test(c)) {
      let j = i + 1;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) j++;
      const w = src.slice(i, j);
      if ((w === 'r' || w === 'b' || w === 'R' || w === 'B') && (src[j] === '"' || src[j] === "'")) rej('unsupported', `${w.toLowerCase() === 'r' ? 'raw string' : 'bytes'} literal`, i);
      out.push({ k: 'id', v: w, at: i });
      i = j;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9]/.test(src[j] as string)) j++;
      const nxt = src[j];
      if (nxt === '.' && /[0-9]/.test(src[j + 1] ?? '')) rej('unsupported', 'double literal', i);
      if (nxt === 'e' || nxt === 'E') rej('unsupported', 'double literal', i);
      if (nxt === 'u' || nxt === 'U') rej('unsupported', 'unsigned integer literal', i);
      if (nxt === 'x' || nxt === 'X') rej('unsupported', 'hexadecimal literal', i);
      const w = src.slice(i, j);
      if (w.length > 1 && w[0] === '0') rej('unsupported', 'integer literal with a leading zero', i);
      out.push({ k: 'int', v: w, at: i });
      i = j;
      continue;
    }
    if (c === '"' || c === "'") {
      if (src.startsWith(c.repeat(3), i)) rej('unsupported', 'triple-quoted string', i);
      let j = i + 1;
      let s = '';
      for (;;) {
        const d = src[j];
        if (d === undefined || d === '\n' || d === '\r') return rej('syntax', 'unterminated string', i);
        if (d === c) break;
        if (d === '\\') {
          const e = src[j + 1];
          const map: Record<string, string> = { '\\': '\\', '"': '"', "'": "'", n: '\n', t: '\t', r: '\r' };
          if (e === undefined || map[e] === undefined) return rej('unsupported', `string escape \\${e ?? ''}`, j);
          s += map[e] as string;
          j += 2;
          continue;
        }
        s += d;
        j++;
      }
      if (s.length > MAX_STR) rej('too_complex', `string literal longer than ${MAX_STR}`, i);
      out.push({ k: 'str', v: s, at: i });
      i = j + 1;
      continue;
    }
    const p = PUNCT.find((x) => src.startsWith(x, i));
    if (p === undefined) return rej(UNSUPPORTED_CH[c] !== undefined ? 'unsupported' : 'syntax', UNSUPPORTED_CH[c] ?? `unexpected character '${c}'`, i);
    out.push({ k: 'p', v: p, at: i });
    i += p.length;
  }
  return out;
}

// ---- parser ---------------------------------------------------------------------------------------------------------------
export type CelNode =
  | { t: 'or' | 'and'; l: CelNode; r: CelNode; at: number }
  | { t: 'not'; e: CelNode; at: number }
  | { t: 'rel'; op: '==' | '!=' | '<' | '<=' | '>' | '>=' | 'in'; l: CelNode; r: CelNode; at: number }
  | { t: 'int'; v: number; at: number }
  | { t: 'str'; v: string; at: number }
  | { t: 'bool'; v: boolean; at: number }
  | { t: 'ts'; v: number; at: number }
  | { t: 'list'; items: CelNode[]; at: number }
  | { t: 'var'; name: string; at: number }
  | { t: 'has'; e: CelNode; at: number }
  | { t: 'method'; target: CelNode; fn: 'startsWith' | 'endsWith' | 'contains'; arg: CelNode; at: number };

const RELOPS = new Set(['==', '!=', '<', '<=', '>', '>=']);
const REJECTED_FUNCS = new Set(['size', 'matches', 'exists', 'all', 'exists_one', 'map', 'filter', 'int', 'uint', 'double', 'string', 'bytes', 'bool', 'duration', 'type', 'dyn', 'min', 'max', 'getHours', 'getDayOfWeek', 'getMinutes', 'getSeconds', 'getFullYear', 'getMonth', 'getDate', 'getDayOfMonth', 'getDayOfYear', 'getMilliseconds', 'extract', 'format', 'lowerAscii', 'upperAscii', 'trim', 'split', 'join', 'replace', 'substring', 'indexOf', 'lastIndexOf', 'charAt', 'isIpv4', 'inIpRange', 'cidr', 'ip', 'isCIDR', 'containsIp', 'url', 'quantity', 'semver', 'optional']);

function parse(src: string): CelNode {
  if (typeof src !== 'string' || src.length === 0) return rej('syntax', 'empty expression', 0);
  if (src.length > MAX_EXPR) return rej('too_complex', `expression longer than ${MAX_EXPR} characters`, 0);
  const toks = lex(src);
  let pos = 0;
  let nodes = 0;
  const peek = (): Tok | undefined => toks[pos];
  const isP = (v: string): boolean => peek()?.k === 'p' && peek()?.v === v;
  const eat = (v: string): boolean => (isP(v) ? (pos++, true) : false);
  const need = (v: string): void => { if (!eat(v)) rej('syntax', `expected '${v}'`, peek()?.at ?? src.length); };
  const tick = (at: number): void => { if (++nodes > MAX_NODES) rej('too_complex', `more than ${MAX_NODES} nodes`, at); };

  function expr(d: number): CelNode {
    if (d > MAX_DEPTH) return rej('too_complex', `nesting deeper than ${MAX_DEPTH}`, peek()?.at ?? 0);
    return or(d);
  }
  function or(d: number): CelNode {
    let l = and(d);
    while (isP('||')) { const at = peek()!.at; pos++; tick(at); l = { t: 'or', l, r: and(d), at }; }
    return l;
  }
  function and(d: number): CelNode {
    let l = rel(d);
    while (isP('&&')) { const at = peek()!.at; pos++; tick(at); l = { t: 'and', l, r: rel(d), at }; }
    return l;
  }
  function rel(d: number): CelNode {
    const l = unary(d);
    const t = peek();
    if (t === undefined) return l;
    const isIn = t.k === 'id' && t.v === 'in';
    if (!isIn && !(t.k === 'p' && RELOPS.has(t.v))) return l;
    pos++;
    tick(t.at);
    const n: CelNode = { t: 'rel', op: (isIn ? 'in' : t.v) as never, l, r: unary(d), at: t.at };
    const u = peek();
    if (u !== undefined && ((u.k === 'p' && RELOPS.has(u.v)) || (u.k === 'id' && u.v === 'in'))) rej('unsupported', 'chained comparison', u.at);
    return n;
  }
  function unary(d: number): CelNode {
    const t = peek();
    if (t?.k === 'p' && t.v === '!') { pos++; tick(t.at); if (d + 1 > MAX_DEPTH) rej('too_complex', `nesting deeper than ${MAX_DEPTH}`, t.at); return { t: 'not', e: unary(d + 1), at: t.at }; }
    if (t?.k === 'p' && t.v === '-') {
      const n = toks[pos + 1];
      if (n?.k !== 'int') return rej('unsupported', 'unary minus on a non-literal', t.at);
      pos += 2;
      return intNode(`-${n.v}`, t.at);
    }
    return member(d);
  }
  function intNode(text: string, at: number): CelNode {
    tick(at);
    const v = Number(text);
    if (!Number.isSafeInteger(v)) return rej('unsupported', 'integer literal outside the safe-integer range', at);
    return { t: 'int', v: Object.is(v, -0) ? 0 : v, at };
  }
  function args(d: number): CelNode[] {
    const a: CelNode[] = [];
    if (!isP(')')) { do a.push(expr(d + 1)); while (eat(',')); }
    need(')');
    return a;
  }
  function member(d: number): CelNode {
    let n = primary(d);
    while (isP('.') ) {
      const dot = peek()!;
      pos++;
      const id = peek();
      if (id?.k !== 'id') return rej('syntax', "expected a name after '.'", dot.at);
      pos++;
      if (isP('(')) {
        pos++;
        const a = args(d);
        if (id.v !== 'startsWith' && id.v !== 'endsWith' && id.v !== 'contains') return rej('unsupported', `method '${id.v}'`, id.at);
        if (a.length !== 1) return rej('syntax', `'${id.v}' takes one argument`, id.at);
        tick(id.at);
        n = { t: 'method', target: n, fn: id.v, arg: a[0] as CelNode, at: id.at };
      } else {
        if (n.t !== 'var') return rej('unsupported', 'field selection on something that is not a declared variable', dot.at);
        n = { ...n, name: `${n.name}.${id.v}` };
      }
    }
    if (isP('[')) return rej('unsupported', 'index operator', peek()!.at);
    return n;
  }
  function primary(d: number): CelNode {
    const t = peek();
    if (t === undefined) return rej('syntax', 'unexpected end of expression', src.length);
    if (t.k === 'int') { pos++; return intNode(t.v, t.at); }
    if (t.k === 'str') { pos++; tick(t.at); return { t: 'str', v: t.v, at: t.at }; }
    if (t.k === 'p' && t.v === '(') { pos++; const e = expr(d + 1); need(')'); return e; }
    if (t.k === 'p' && t.v === '[') {
      pos++;
      const items: CelNode[] = [];
      if (!isP(']')) { do { if (items.length >= MAX_LIST) rej('too_complex', `list longer than ${MAX_LIST}`, t.at); items.push(expr(d + 1)); } while (eat(',')); }
      need(']');
      tick(t.at);
      return { t: 'list', items, at: t.at };
    }
    if (t.k === 'id') {
      pos++;
      if (t.v === 'true' || t.v === 'false') { tick(t.at); return { t: 'bool', v: t.v === 'true', at: t.at }; }
      if (t.v === 'null') return rej('unsupported', 'null', t.at);
      if (isP('(')) {
        pos++;
        const a = args(d);
        if (t.v === 'has') {
          if (a.length !== 1 || a[0]?.t !== 'var') return rej('syntax', 'has() takes one declared variable', t.at);
          tick(t.at);
          return { t: 'has', e: a[0], at: t.at };
        }
        if (t.v === 'timestamp') {
          const s = a[0];
          if (a.length !== 1 || s?.t !== 'str') return rej('unsupported', 'timestamp() of a non-literal', t.at);
          return { t: 'ts', v: parseTimestamp(s.v, t.at), at: t.at };
        }
        return rej('unsupported', REJECTED_FUNCS.has(t.v) ? `function '${t.v}'` : `unknown function '${t.v}'`, t.at);
      }
      if (t.v === 'in') return rej('syntax', "unexpected 'in'", t.at);
      tick(t.at);
      return { t: 'var', name: t.v, at: t.at };
    }
    return rej('syntax', `unexpected '${t.v}'`, t.at);
  }
  const root = expr(0);
  if (pos < toks.length) rej('syntax', `unexpected '${toks[pos]?.v}'`, toks[pos]?.at ?? 0);
  return root;
}

function parseTimestamp(s: string, at: number): number {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/.exec(s);
  if (!m) return rej('unsupported', 'timestamp() argument must be RFC 3339 UTC (Z) with at most millisecond precision', at);
  const ms = Date.parse(`${m[1]}.${(m[2] ?? '').padEnd(3, '0')}Z`);
  if (!Number.isSafeInteger(ms) || new Date(ms).toISOString() !== `${m[1]}.${(m[2] ?? '').padEnd(3, '0')}Z`) return rej('unsupported', 'timestamp() is not a real instant', at);
  return ms;
}

/** Parse a CEL expression of the supported subset into a tree (or throw nothing: returns the error). Exported for the differential test. */
export function parseCel(expression: string): { ok: true; ast: CelNode } | CelError {
  try { return { ok: true, ast: parse(expression) }; } catch (e) { if (e instanceof Reject) return { ok: false, code: e.code, message: e.message, at: e.at }; return { ok: false, code: 'syntax', message: 'internal error', at: 0 }; }
}

// ---- translation ----------------------------------------------------------------------------------------------------------
function schemaError(s: unknown): string | null {
  if (s === null || typeof s !== 'object' || Array.isArray(s)) return 'the schema must be an object';
  const vars = (s as CelSchema).vars;
  if (vars === null || typeof vars !== 'object' || Array.isArray(vars)) return 'the schema needs a vars object';
  for (const [name, v] of Object.entries(vars)) {
    if (!IDENT.test(name) || name.split('.').some((x) => FORBIDDEN.has(x))) return `bad variable name '${name}'`;
    if (v === null || typeof v !== 'object' || typeof v.path !== 'string' || !PCA_PATH.test(v.path) || v.path.split('.').some((x) => FORBIDDEN.has(x))) return `variable '${name}' needs a path rooted at action, subject or env`;
    if (!['string', 'int', 'bool', 'timestamp_ms'].includes(v.type)) return `variable '${name}' has an unsupported type`;
    if (v.optional !== undefined && typeof v.optional !== 'boolean') return `variable '${name}': optional must be a boolean`;
  }
  return null;
}

type Operand = { kind: 'var'; v: CelVar; name: string } | { kind: 'lit'; type: CelType; value: string | number | boolean };

export function celToCondition(expression: string, schema: CelSchema): CelResult {
  const se = schemaError(schema);
  if (se !== null) return { ok: false, code: 'bad_schema', message: se, at: 0 };
  const p = parseCel(expression);
  if (!p.ok) return p;
  const fields = new Set<string>();
  try {
    const own = (n: string): CelVar | undefined => (Object.prototype.hasOwnProperty.call(schema.vars, n) ? schema.vars[n] : undefined);
    const operand = (n: CelNode): Operand => {
      if (n.t === 'var') {
        const v = own(n.name);
        if (v === undefined) return rej('unknown_identifier', `'${n.name}' is not declared in the schema`, n.at);
        return { kind: 'var', v, name: n.name };
      }
      if (n.t === 'int') return { kind: 'lit', type: 'int', value: n.v };
      if (n.t === 'str') return { kind: 'lit', type: 'string', value: n.v };
      if (n.t === 'bool') return { kind: 'lit', type: 'bool', value: n.v };
      if (n.t === 'ts') return { kind: 'lit', type: 'timestamp_ms', value: n.v };
      return rej('unsupported', 'a computed value as a comparison operand', n.at);
    };
    const typeOf = (o: Operand): CelType => (o.kind === 'var' ? o.v.type : o.type);
    const read = (o: Operand & { kind: 'var' }): string => { fields.add(o.v.path); return o.v.path; };
    const flat = (n: CelNode, t: 'or' | 'and', out: CelNode[]): CelNode[] => { if (n.t === t) { flat(n.l, t, out); flat(n.r, t, out); } else out.push(n); return out; };

    const tr = (n: CelNode): Condition => {
      switch (n.t) {
        case 'or': return { any_of: flat(n, 'or', []).map(tr) };
        case 'and': return { all_of: flat(n, 'and', []).map(tr) };
        case 'not': return { not: tr(n.e) };
        case 'has': {
          const o = operand(n.e);
          if (o.kind !== 'var') return rej('syntax', 'has() takes a declared variable', n.at);
          if (o.v.optional !== true) return rej('has_requires_optional', `has(${o.name}): mark the variable optional in the schema (its container must always be present)`, n.at);
          return { field: read(o), op: 'exists', value: true };
        }
        case 'var': {
          const o = operand(n);
          // `flag` alone cannot be exact: for a non-boolean value CEL errors (and so does `!flag`), but an equality leaf is plainly false and `not` would turn that into true.
          return rej('unsupported', `a bare variable '${n.name}' as a condition${o.kind === 'var' && o.v.type === 'bool' ? ` (write ${n.name} == true)` : ''}`, n.at);
        }
        case 'method': {
          const t = operand(n.target);
          if (t.kind !== 'var' || t.v.type !== 'string') return rej('type_mismatch', `${n.fn} needs a string variable`, n.at);
          if (n.arg.t !== 'str' || n.arg.v.length === 0) return rej('unsupported', `${n.fn} of anything but a non-empty string literal`, n.at);
          const lit = n.arg.v;
          if (n.fn === 'startsWith') return { field: read(t), op: 'prefix', value: lit };
          const esc = lit.replace(/[\\*?]/g, (c) => `\\${c}`);
          const glob = n.fn === 'endsWith' ? `*${esc}` : `*${esc}*`;
          if (glob.length > 512) return rej('too_complex', 'literal too long for a glob', n.at);
          return { field: read(t), op: 'like', value: glob };
        }
        case 'rel': {
          if (n.op === 'in') {
            const l = operand(n.l);
            if (l.kind !== 'var') return rej('constant_expression', 'the left side of "in" must be a declared variable', n.at);
            if (n.r.t !== 'list' || n.r.items.length === 0) return rej('unsupported', '"in" against anything but a non-empty list literal', n.at);
            const items = n.r.items.map(operand);
            if (items.some((i) => i.kind !== 'lit' || i.type !== l.v.type)) return rej('type_mismatch', `list items must be ${l.v.type} literals`, n.at);
            return { field: read(l), op: 'in', value: items.map((i) => (i as { value: unknown }).value) };
          }
          const l = operand(n.l);
          const r = operand(n.r);
          if (l.kind === 'lit' && r.kind === 'lit') return rej('constant_expression', 'a comparison of two literals', n.at);
          if (typeOf(l) !== typeOf(r)) return rej('type_mismatch', `${typeOf(l)} against ${typeOf(r)}`, n.at);
          const ty = typeOf(l);
          const eqOp = n.op === '==' || n.op === '!=';
          if (!eqOp && ty === 'bool') return rej('type_mismatch', 'ordering of booleans', n.at);
          const pcaOp = ({ '==': 'eq', '!=': 'ne', '<': 'lt', '<=': 'lte', '>': 'gt', '>=': 'gte' } as const)[n.op];
          const flip = { eq: 'eq', ne: 'ne', lt: 'gt', lte: 'gte', gt: 'lt', gte: 'lte' } as const;
          if (l.kind === 'var' && r.kind === 'var') return { field: read(l), op: pcaOp, ref: read(r) };
          if (l.kind === 'var') return { field: read(l), op: pcaOp, value: (r as { value: unknown }).value };
          return { field: read(r as Operand & { kind: 'var' }), op: flip[pcaOp], value: (l as { value: unknown }).value };
        }
        default:
          return rej('constant_expression', 'a bare constant is not a condition', n.at);
      }
    };
    const condition = tr(p.ast);
    if (fields.size === 0) return rej('constant_expression', 'the expression reads no variable', 0);
    return { ok: true, condition, fields: [...fields].sort() };
  } catch (e) {
    if (e instanceof Reject) return { ok: false, code: e.code, message: e.message, at: e.at };
    return { ok: false, code: 'syntax', message: 'internal error', at: 0 };
  }
}


/** One expression as a permit predicate for `verb` (and optionally `resource`). */
export function celToPredicate(expression: string, schema: CelSchema, scope: { verb: string | string[]; resource?: string }): { ok: true; predicate: Predicate; fields: string[] } | CelError {
  const r = celToCondition(expression, schema);
  if (!r.ok) return r;
  return { ok: true, predicate: { verb: scope.verb, ...(scope.resource !== undefined ? { resource: scope.resource } : {}), where: [r.condition] }, fields: r.fields };
}

/**
 * A batch (an IAM policy's bindings, a VAP's validations): every expression is translated or REPORTED. One rejection makes
 * `report.errors` non-empty, and `decide()` then denies everything (an incomplete import never grants).
 */
export function celConditionsToPca(items: readonly { name: string; expression: string; verb: string | string[]; resource?: string }[], schema: CelSchema): BridgeResult {
  const predicates: Predicate[] = [];
  const translated: string[] = [];
  const errors: string[] = [];
  for (const it of items) {
    const r = celToPredicate(it.expression, schema, { verb: it.verb, ...(it.resource !== undefined ? { resource: it.resource } : {}) });
    if (r.ok) { predicates.push(r.predicate); translated.push(`${it.name}: translated exactly (reads ${r.fields.join(', ')})`); } else errors.push(`${it.name}: rejected (${r.code}) at ${r.at}: ${r.message}`);
  }
  return { predicates, denies: [], caveats: [], report: { source: 'cel', translated, skipped: [], errors } };
}
