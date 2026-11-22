import { isGroupCondition, isLeafCondition, type Condition, type Predicate } from '@atlasauth/pca';
import type { Residual, ResidualPart } from './residual';
import type { Veto } from './types';

/**
 * DATA FILTERING: a residual compiled to a SQL WHERE clause (borrowed-ideas item 5, security contract C-249).
 *
 * A list endpoint should push authorization into its query instead of fetching rows and testing each one. `toFilter` takes the
 * residual of a policy (the verb and principal known, the row attributes unknown) and a column map, and returns a
 * parameterized WHERE fragment for the rows the policy admits.
 *
 * Soundness rule: the filter may only ever return a SUBSET of what the evaluator admits. Anything it cannot express exactly
 * (a regex resource, a `ref`, `like` / `matches` / `member_of`, string ordering, a field with no column) makes the whole
 * compile fail with a reason (`ok: false`), and the caller falls back to per-row authorization. It never emits a looser
 * filter. SQL's three-valued logic is Kleene's, the same as the evaluator's: an unresolvable permit condition is NULL and the
 * row is dropped; a veto is wrapped in `COALESCE(.., TRUE)` so an unresolvable veto condition still excludes the row (veto
 * polarity). The columns are assumed to carry the types the policy compares against and a binary (byte-wise) collation.
 */

export interface FilterOptions {
  /** Policy path to SQL column. `action.resource` maps the resource id column. Only mapped fields can appear in a filter. */
  columns: Record<string, string>;
  dialect?: 'postgres' | 'sqlite' | 'mysql';
  /** `autonomous` (default): rows whose decision is allow. `admitted`: also rows that need a human (tighten rules are ignored). */
  include?: 'autonomous' | 'admitted';
}

export type FilterExpr =
  | { t: 'true' }
  | { t: 'false' }
  | { t: 'cmp'; col: string; op: 'eq' | 'ne' | 'lt' | 'lte' | 'gt' | 'gte'; v: number | string | boolean }
  | { t: 'in'; col: string; vs: Array<number | string | boolean>; neg: boolean }
  | { t: 'prefix'; col: string; prefix: string }
  | { t: 'null'; col: string; isNull: boolean }
  | { t: 'and'; xs: FilterExpr[] }
  | { t: 'or'; xs: FilterExpr[] }
  | { t: 'not'; x: FilterExpr }
  | { t: 'coalesce'; x: FilterExpr; def: boolean };

/** A UCAST node (the expanded syntax of OPA's data-filtering API, https://www.openpolicyagent.org/docs/filtering/ucast-syntax). */
export type Ucast =
  | { type: 'compound'; operator: 'and' | 'or' | 'not'; value: Ucast[] }
  | { type: 'field'; field: string; operator: 'eq' | 'ne' | 'lt' | 'lte' | 'gt' | 'gte' | 'in' | 'nin' | 'startswith'; value: number | string | boolean | null | Array<number | string | boolean> };

export type FilterResult = { ok: true; expr: FilterExpr; sql: string; params: Array<number | string | boolean>; ucast: Ucast } | { ok: false; reason: string };

class Unsupported extends Error {}

const COL_RE = /^[A-Za-z_][A-Za-z0-9_]{0,62}(\.[A-Za-z_][A-Za-z0-9_]{0,62})?$/;
const scalar = (v: unknown): v is number | string | boolean => typeof v === 'boolean' || typeof v === 'string' || (typeof v === 'number' && Number.isFinite(v));

function colOf(path: unknown, cols: Record<string, string>): string {
  const c = typeof path === 'string' && Object.prototype.hasOwnProperty.call(cols, path) ? cols[path] : undefined;
  if (c === undefined || !COL_RE.test(c)) throw new Unsupported(`field '${String(path)}' has no usable column`);
  return c;
}

const and = (xs: FilterExpr[]): FilterExpr => (xs.length === 0 ? { t: 'true' } : xs.length === 1 ? xs[0]! : { t: 'and', xs });
const or = (xs: FilterExpr[]): FilterExpr => (xs.length === 0 ? { t: 'false' } : xs.length === 1 ? xs[0]! : { t: 'or', xs });

function cond(c: Condition, cols: Record<string, string>): FilterExpr {
  if (c === null || typeof c !== 'object') throw new Unsupported('malformed condition');
  if (isGroupCondition(c)) {
    if ('all_of' in c && Array.isArray(c.all_of) && c.all_of.length > 0) return and(c.all_of.map((x) => cond(x, cols)));
    if ('any_of' in c && Array.isArray(c.any_of) && c.any_of.length > 0) return or(c.any_of.map((x) => cond(x, cols)));
    if ('not' in c) return { t: 'not', x: cond(c.not, cols) };
    throw new Unsupported('empty condition group');
  }
  if (!isLeafCondition(c)) throw new Unsupported('malformed condition');
  if (c.ref !== undefined) throw new Unsupported('cross-field ref');
  const col = colOf(c.field, cols);
  const v = c.value;
  switch (c.op) {
    case 'eq':
    case 'ne':
      if (!scalar(v)) throw new Unsupported(`${c.op} against a non-scalar`);
      return { t: 'cmp', col, op: c.op, v };
    case 'lt':
    case 'lte':
    case 'gt':
    case 'gte':
      if (typeof v !== 'number' || !Number.isFinite(v)) throw new Unsupported('string ordering follows UTF-8 byte order, which SQL collations do not guarantee');
      return { t: 'cmp', col, op: c.op, v };
    case 'in':
    case 'nin':
      if (!Array.isArray(v) || v.length === 0 || !v.every(scalar)) throw new Unsupported(`${c.op} needs a non-empty list of scalars`);
      return { t: 'in', col, vs: v as Array<number | string | boolean>, neg: c.op === 'nin' };
    case 'prefix':
      if (typeof v !== 'string') throw new Unsupported('prefix needs a string');
      return { t: 'prefix', col, prefix: v };
    case 'exists':
      return { t: 'null', col, isNull: v === false };
    default:
      throw new Unsupported(`operator '${String(c.op)}' has no exact SQL form`);
  }
}

function resourceExpr(p: Pick<Predicate, 'resource'>, cols: Record<string, string>): FilterExpr {
  const r = p.resource;
  if (r === undefined || r === '*') return { t: 'true' };
  const col = colOf('action.resource', cols);
  if (r.startsWith('re:')) throw new Unsupported('regex resource matcher');
  if (r.endsWith('*')) return { t: 'prefix', col, prefix: r.slice(0, -1) };
  return { t: 'cmp', col, op: 'eq', v: r };
}

function vetoExpr(v: Veto, cols: Record<string, string>): FilterExpr {
  const when = and([...(v.when.resource !== undefined ? [{ t: 'coalesce', x: resourceExpr(v.when, cols), def: true } as FilterExpr] : []), ...(v.when.where ?? []).map((c) => ({ t: 'coalesce', x: cond(c, cols), def: true }) as FilterExpr)]);
  const parts: FilterExpr[] = [when];
  if (v.over) {
    const col = colOf(v.over.path, cols);
    parts.push(or([{ t: 'null', col, isNull: true }, { t: 'cmp', col, op: 'lt', v: 0 }, { t: 'cmp', col, op: 'gt', v: v.over.threshold }]));
  }
  if (v.kind !== 'approval' && v.unless && v.unless.length > 0) parts.push({ t: 'not', x: and(v.unless.map((c) => ({ t: 'coalesce', x: cond(c, cols), def: false }) as FilterExpr)) });
  return and(parts);
}

function partExpr(p: ResidualPart, cols: Record<string, string>, include: 'autonomous' | 'admitted'): FilterExpr {
  const permit = or(p.predicates.map((x) => and([resourceExpr(x, cols), ...(x.where ?? []).map((c) => cond(c, cols))])));
  const gates: FilterExpr[] = [permit];
  for (const v of p.vetoes) {
    const e = vetoExpr(v, cols);
    // an approval veto sends the row to a human: it leaves the autonomous set but stays in the admitted set
    if (v.kind === 'deny' || include === 'autonomous') gates.push({ t: 'not', x: e });
  }
  if (include === 'autonomous') for (const t of p.tighten) gates.push({ t: 'not', x: { t: 'coalesce', x: cond(t.when, cols), def: true } });
  else for (const t of p.tighten) if (t.signal === 'deny') gates.push({ t: 'not', x: { t: 'coalesce', x: cond(t.when, cols), def: true } });
  return and(gates);
}

function render(e: FilterExpr, dialect: 'postgres' | 'sqlite' | 'mysql', params: Array<number | string | boolean>): string {
  const ph = (v: number | string | boolean): string => {
    params.push(v);
    return dialect === 'postgres' ? `$${params.length}` : '?';
  };
  const R = (x: FilterExpr): string => {
    switch (x.t) {
      case 'true':
        return 'TRUE';
      case 'false':
        return 'FALSE';
      case 'cmp':
        return `${x.col} ${{ eq: '=', ne: '<>', lt: '<', lte: '<=', gt: '>', gte: '>=' }[x.op]} ${ph(x.v)}`;
      case 'in':
        return `${x.col} ${x.neg ? 'NOT IN' : 'IN'} (${x.vs.map(ph).join(', ')})`;
      case 'prefix':
        return `${x.col} LIKE ${ph(x.prefix.replace(/[!%_]/g, (m) => '!' + m) + '%')} ESCAPE '!'`;
      case 'null':
        return `${x.col} IS ${x.isNull ? '' : 'NOT '}NULL`;
      case 'and':
        return `(${x.xs.map(R).join(' AND ')})`;
      case 'or':
        return `(${x.xs.map(R).join(' OR ')})`;
      case 'not':
        return `NOT (${R(x.x)})`;
      case 'coalesce':
        return `COALESCE(${R(x.x)}, ${x.def ? 'TRUE' : 'FALSE'})`;
    }
  };
  return R(e);
}

/** Compile a residual to a parameterized SQL filter, or say why it cannot be done exactly. */
export function toFilter(res: Residual, o: FilterOptions): FilterResult {
  try {
    if (res.decision === 'never') return { ok: true, expr: { t: 'false' }, sql: 'FALSE', params: [], ucast: toUcast({ t: 'false' }) };
    const include = o.include ?? 'autonomous';
    const { meet, ...own } = res.policy;
    const expr = and([own, ...(meet ?? [])].map((p) => partExpr(p, o.columns, include)));
    const params: Array<number | string | boolean> = [];
    return { ok: true, expr, sql: render(expr, o.dialect ?? 'postgres', params), params, ucast: toUcast(expr) };
  } catch (e) {
    if (e instanceof Unsupported) return { ok: false, reason: e.message };
    return { ok: false, reason: 'filter compilation error' };
  }
}

/** Evaluate a filter expression over one row (used to check the SQL's logic against the evaluator in tests; Kleene semantics). */
export function evalFilter(e: FilterExpr, row: Record<string, unknown>): boolean | null {
  const get = (c: string): unknown => (Object.prototype.hasOwnProperty.call(row, c) ? row[c] : null);
  const K = (x: FilterExpr): boolean | null => {
    switch (x.t) {
      case 'true':
        return true;
      case 'false':
        return false;
      case 'cmp': {
        const a = get(x.col);
        if (a === null || typeof a !== typeof x.v) return null;
        const b = x.v;
        return x.op === 'eq' ? a === b : x.op === 'ne' ? a !== b : x.op === 'lt' ? (a as number) < (b as number) : x.op === 'lte' ? (a as number) <= (b as number) : x.op === 'gt' ? (a as number) > (b as number) : (a as number) >= (b as number);
      }
      case 'in': {
        const a = get(x.col);
        if (a === null) return null;
        const hit = x.vs.includes(a as never);
        return x.neg ? !hit : hit;
      }
      case 'prefix': {
        const a = get(x.col);
        return typeof a === 'string' ? a.startsWith(x.prefix) : null;
      }
      case 'null':
        return (get(x.col) === null) === x.isNull;
      case 'and': {
        let unk = false;
        for (const y of x.xs) {
          const v = K(y);
          if (v === false) return false;
          if (v === null) unk = true;
        }
        return unk ? null : true;
      }
      case 'or': {
        let unk = false;
        for (const y of x.xs) {
          const v = K(y);
          if (v === true) return true;
          if (v === null) unk = true;
        }
        return unk ? null : false;
      }
      case 'not': {
        const v = K(x.x);
        return v === null ? null : !v;
      }
      case 'coalesce': {
        const v = K(x.x);
        return v === null ? x.def : v;
      }
    }
  };
  return K(e);
}

// ---- UCAST ----------------------------------------------------------------------------------------------------------

const isEmpty = (u: Ucast, op: 'and' | 'or'): boolean => u.type === 'compound' && u.operator === op && u.value.length === 0;
/** Flatten, drop the identity and short-circuit on the absorbing element: meaning-preserving, and it keeps the tree readable. */
function join(op: 'and' | 'or', xs: Ucast[]): Ucast {
  const other = op === 'and' ? 'or' : 'and';
  const flat = xs.flatMap((x) => (x.type === 'compound' && x.operator === op ? x.value : [x]));
  if (flat.some((x) => isEmpty(x, other))) return { type: 'compound', operator: other, value: [] };
  const kept = flat.filter((x) => !isEmpty(x, op));
  if (kept.length === 1) return kept[0]!;
  return { type: 'compound', operator: op, value: kept };
}
const and2 = (xs: Ucast[]): Ucast => join('and', xs);
const or2 = (xs: Ucast[]): Ucast => join('or', xs);
const not2 = (x: Ucast): Ucast => ({ type: 'compound', operator: 'not', value: [x] });
const f = (field: string, operator: Extract<Ucast, { type: 'field' }>['operator'], value: Extract<Ucast, { type: 'field' }>['value']): Ucast => ({ type: 'field', field, operator, value });
const notNull = (c: string): Ucast => f(c, 'ne', null);
const TRUE2: Ucast = and2([]);
const FALSE2: Ucast = or2([]);

/**
 * UCAST is two-valued, SQL's WHERE is Kleene. To keep the same rows, every node is compiled twice: `T(x)` = "x is definitely
 * true" and `F(x)` = "x is definitely false" (both false when a referenced column is NULL). Then T(not x) = F(x), T(and) = and of T,
 * F(and) = or of F, and so on, and a comparison carries an explicit not-null guard, so NULL never satisfies a permit and a veto
 * (`coalesce(x, TRUE)` = not F(x)) still excludes the row.
 */
function T(x: FilterExpr): Ucast {
  switch (x.t) {
    case 'true':
      return TRUE2;
    case 'false':
      return FALSE2;
    case 'cmp':
      return x.op === 'ne' ? and2([notNull(x.col), f(x.col, 'ne', x.v)]) : f(x.col, x.op, x.v);
    case 'in':
      return x.neg ? and2([notNull(x.col), f(x.col, 'nin', x.vs)]) : f(x.col, 'in', x.vs);
    case 'prefix':
      return f(x.col, 'startswith', x.prefix);
    case 'null':
      return x.isNull ? f(x.col, 'eq', null) : notNull(x.col);
    case 'and':
      return and2(x.xs.map(T));
    case 'or':
      return or2(x.xs.map(T));
    case 'not':
      return F(x.x);
    case 'coalesce':
      return x.def ? not2(F(x.x)) : T(x.x);
  }
}

function F(x: FilterExpr): Ucast {
  switch (x.t) {
    case 'true':
      return FALSE2;
    case 'false':
      return TRUE2;
    case 'cmp': {
      const inv = { eq: 'ne', ne: 'eq', lt: 'gte', lte: 'gt', gt: 'lte', gte: 'lt' } as const;
      return and2([notNull(x.col), f(x.col, inv[x.op], x.v)]);
    }
    case 'in':
      return x.neg ? f(x.col, 'in', x.vs) : and2([notNull(x.col), f(x.col, 'nin', x.vs)]);
    case 'prefix':
      return and2([notNull(x.col), not2(f(x.col, 'startswith', x.prefix))]);
    case 'null':
      return x.isNull ? notNull(x.col) : f(x.col, 'eq', null);
    case 'and':
      return or2(x.xs.map(F));
    case 'or':
      return and2(x.xs.map(F));
    case 'not':
      return T(x.x);
    case 'coalesce':
      return x.def ? F(x.x) : not2(T(x.x)); // coalesce(x, FALSE) is false exactly when x is not definitely true
  }
}

/** The filter as a UCAST tree whose rows are exactly those the SQL form selects. */
export function toUcast(e: FilterExpr): Ucast {
  return T(e);
}

/** Evaluate a UCAST tree over one row (two-valued; a comparison with NULL is false, `eq null` / `ne null` test for NULL). */
export function evalUcast(u: Ucast, row: Record<string, unknown>): boolean {
  if (u.type === 'compound') {
    if (u.operator === 'and') return u.value.every((c) => evalUcast(c, row));
    if (u.operator === 'or') return u.value.some((c) => evalUcast(c, row));
    return !evalUcast(u.value[0]!, row);
  }
  const a = Object.prototype.hasOwnProperty.call(row, u.field) ? row[u.field] : null;
  const v = u.value;
  if (u.operator === 'eq' && v === null) return a === null;
  if (u.operator === 'ne' && v === null) return a !== null;
  if (a === null) return false;
  switch (u.operator) {
    case 'eq':
      return a === v;
    case 'ne':
      return typeof a === typeof v && a !== v;
    case 'lt':
      return typeof a === typeof v && (a as number) < (v as number);
    case 'lte':
      return typeof a === typeof v && (a as number) <= (v as number);
    case 'gt':
      return typeof a === typeof v && (a as number) > (v as number);
    case 'gte':
      return typeof a === typeof v && (a as number) >= (v as number);
    case 'in':
      return (v as unknown[]).includes(a);
    case 'nin':
      return !(v as unknown[]).includes(a);
    case 'startswith':
      return typeof a === 'string' && a.startsWith(v as string);
  }
}
