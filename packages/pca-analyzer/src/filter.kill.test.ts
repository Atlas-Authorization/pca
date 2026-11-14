import { describe, expect, it } from 'vitest';
import type { Condition } from '@atlasauth/pca';
import { evalFilter, evalUcast, toFilter, toUcast, type FilterExpr, type Ucast } from './filter';
import type { Residual, ResidualPart } from './residual';
import type { Veto } from './types';

const L = (field: string, op: string, value?: unknown, extra: object = {}): Condition => ({ field, op, value, ...extra }) as Condition;
const part = (o: Partial<ResidualPart> = {}): ResidualPart => ({ predicates: [], caveats: [], vetoes: [], tighten: [], ...o });
const res = (p: ResidualPart & { meet?: ResidualPart[] }): Residual => ({ decision: 'conditional', policy: p, policyDigest: 'd' });
const cols = { 'action.resource': 'rid', x: 'cx', y: 'cy', z: 'cz', w: 'cw', bad: '1bad' };
const run = (p: ResidualPart & { meet?: ResidualPart[] }, o: Partial<{ dialect: 'postgres' | 'sqlite' | 'mysql'; include: 'autonomous' | 'admitted'; columns: Record<string, string> }> = {}) => toFilter(res(p), { columns: cols, ...o });
const where = (...w: Condition[]) => run(part({ predicates: [{ verb: 'v', where: w }] }));

const T: FilterExpr = { t: 'true' };
const Fl: FilterExpr = { t: 'false' };
const C = (col: string, op: 'eq' | 'ne' | 'lt' | 'lte' | 'gt' | 'gte', v: number | string | boolean): FilterExpr => ({ t: 'cmp', col, op, v });
const co = (x: FilterExpr, def: boolean): FilterExpr => ({ t: 'coalesce', x, def });
const NOT = (x: FilterExpr): FilterExpr => ({ t: 'not', x });
const AND = (...xs: FilterExpr[]): FilterExpr => ({ t: 'and', xs });
const OR = (...xs: FilterExpr[]): FilterExpr => ({ t: 'or', xs });
const W = (x: FilterExpr): FilterExpr => AND(T, x);
const fld = (field: string, operator: Extract<Ucast, { type: 'field' }>['operator'], value: Extract<Ucast, { type: 'field' }>['value']): Ucast => ({ type: 'field', field, operator, value });
const uAnd = (...value: Ucast[]): Ucast => ({ type: 'compound', operator: 'and', value });
const uOr = (...value: Ucast[]): Ucast => ({ type: 'compound', operator: 'or', value });
const uNot = (x: Ucast): Ucast => ({ type: 'compound', operator: 'not', value: [x] });
const nn = fld('c', 'ne', null);

describe('toFilter condition compilation', () => {
  it('compiles group conditions', () => {
    const a = L('x', 'eq', 1);
    const b = L('y', 'eq', 2);
    expect((where({ all_of: [a, b] }) as { expr: FilterExpr }).expr).toEqual(W(AND(C('cx', 'eq', 1), C('cy', 'eq', 2))));
    expect((where({ any_of: [a, b] }) as { expr: FilterExpr }).expr).toEqual(W(OR(C('cx', 'eq', 1), C('cy', 'eq', 2))));
    expect((where({ all_of: [a] }) as { expr: FilterExpr }).expr).toEqual(W(C('cx', 'eq', 1)));
    expect((where({ any_of: [a] }) as { expr: FilterExpr }).expr).toEqual(W(C('cx', 'eq', 1)));
    expect((where({ not: a } as Condition) as { expr: FilterExpr }).expr).toEqual(W(NOT(C('cx', 'eq', 1))));
  });
  it('an empty group list falls through to the next group form', () => {
    const a = L('x', 'eq', 1);
    expect((where({ all_of: [], any_of: [a] } as Condition) as { expr: FilterExpr }).expr).toEqual(W(C('cx', 'eq', 1)));
    expect((where({ all_of: [], not: a } as Condition) as { expr: FilterExpr }).expr).toEqual(W(NOT(C('cx', 'eq', 1))));
    expect((where({ any_of: [], not: a } as Condition) as { expr: FilterExpr }).expr).toEqual(W(NOT(C('cx', 'eq', 1))));
  });
  it('refuses with exact reasons', () => {
    const r = (c: unknown) => where(c as Condition);
    expect(r({ all_of: [] })).toEqual({ ok: false, reason: 'empty condition group' });
    expect(r({ any_of: [] })).toEqual({ ok: false, reason: 'empty condition group' });
    expect(r({ all_of: 'xy' })).toEqual({ ok: false, reason: 'empty condition group' });
    expect(r({ any_of: 'xy' })).toEqual({ ok: false, reason: 'empty condition group' });
    expect(r(null)).toEqual({ ok: false, reason: 'malformed condition' });
    expect(r(5)).toEqual({ ok: false, reason: 'malformed condition' });
    expect(r({})).toEqual({ ok: false, reason: 'malformed condition' });
    expect(r({ op: 'eq', value: 1 })).toEqual({ ok: false, reason: 'malformed condition' });
    expect(r({ field: 5, op: 'eq', value: 1 })).toEqual({ ok: false, reason: 'malformed condition' });
    expect(r(L('x', 'eq', 1, { ref: 'env.k' }))).toEqual({ ok: false, reason: 'cross-field ref' });
    expect(r(L('q', 'eq', 1))).toEqual({ ok: false, reason: "field 'q' has no usable column" });
    expect(r(L('bad', 'eq', 1))).toEqual({ ok: false, reason: "field 'bad' has no usable column" });
    expect(r(L('x', 'like', 'a'))).toEqual({ ok: false, reason: "operator 'like' has no exact SQL form" });
  });
  it('only own column keys count', () => {
    const inherited = Object.create({ x: 'zz' }) as Record<string, string>;
    inherited['action.resource'] = 'rid';
    expect(toFilter(res(part({ predicates: [{ verb: 'v', where: [L('x', 'eq', 1)] }] })), { columns: inherited })).toEqual({ ok: false, reason: "field 'x' has no usable column" });
  });
  it('a non-string veto over path never maps a column', () => {
    const v: Veto = { id: 'v', kind: 'deny', when: { verb: 'v' }, over: { path: 5 as unknown as string, threshold: 1 } };
    expect(run(part({ predicates: [{ verb: 'v' }], vetoes: [v] }), { columns: { '5': 'cx' } })).toEqual({ ok: false, reason: "field '5' has no usable column" });
  });
  it('eq / ne accept exactly scalars', () => {
    for (const op of ['eq', 'ne'] as const) {
      for (const v of ['a', 1, 0, true, false, '']) expect((where(L('x', op, v)) as { expr: FilterExpr }).expr).toEqual(W(C('cx', op, v)));
      for (const v of [[1], {}, null, undefined, Infinity, NaN]) expect(where(L('x', op, v))).toEqual({ ok: false, reason: `${op} against a non-scalar` });
    }
  });
  it('ordering accepts only finite numbers', () => {
    for (const op of ['lt', 'lte', 'gt', 'gte'] as const) {
      expect((where(L('x', op, 7)) as { expr: FilterExpr }).expr).toEqual(W(C('cx', op, 7)));
      for (const v of ['a', Infinity, NaN, null, true, undefined]) expect(where(L('x', op, v))).toEqual({ ok: false, reason: 'string ordering follows UTF-8 byte order, which SQL collations do not guarantee' });
    }
  });
  it('in / nin accept a non-empty list of scalars', () => {
    expect((where(L('x', 'in', [1, 'a', true])) as { expr: FilterExpr }).expr).toEqual(W({ t: 'in', col: 'cx', vs: [1, 'a', true], neg: false }));
    expect((where(L('x', 'nin', [1])) as { expr: FilterExpr }).expr).toEqual(W({ t: 'in', col: 'cx', vs: [1], neg: true }));
    for (const op of ['in', 'nin']) {
      for (const v of ['xy', [], [1, {}], [{}], [1, Infinity], undefined, 5]) expect(where(L('x', op, v))).toEqual({ ok: false, reason: `${op} needs a non-empty list of scalars` });
    }
  });
  it('prefix needs a string', () => {
    expect((where(L('x', 'prefix', 'ab')) as { expr: FilterExpr }).expr).toEqual(W({ t: 'prefix', col: 'cx', prefix: 'ab' }));
    expect((where(L('x', 'prefix', '')) as { expr: FilterExpr }).expr).toEqual(W({ t: 'prefix', col: 'cx', prefix: '' }));
    for (const v of [5, null, undefined, ['a']]) expect(where(L('x', 'prefix', v))).toEqual({ ok: false, reason: 'prefix needs a string' });
  });
  it('exists: only false means NULL', () => {
    expect((where(L('x', 'exists', false)) as { expr: FilterExpr }).expr).toEqual(W({ t: 'null', col: 'cx', isNull: true }));
    expect((where(L('x', 'exists', true)) as { expr: FilterExpr }).expr).toEqual(W({ t: 'null', col: 'cx', isNull: false }));
    expect((where(L('x', 'exists')) as { expr: FilterExpr }).expr).toEqual(W({ t: 'null', col: 'cx', isNull: false }));
  });
});

describe('toFilter resources, policy shape and rendering', () => {
  const exprOf = (p: ResidualPart & { meet?: ResidualPart[] }, o: Parameters<typeof run>[1] = {}) => (run(p, o) as { expr: FilterExpr }).expr;
  it('resource matchers', () => {
    const r = (resource?: string, columns = cols) => exprOf(part({ predicates: [{ verb: 'v', resource }] }), { columns });
    expect(r(undefined, {})).toEqual(T);
    expect(r('*', {})).toEqual(T);
    expect(r('*')).toEqual(T);
    expect(r('ab')).toEqual(C('rid', 'eq', 'ab'));
    expect(r('/acct/*')).toEqual({ t: 'prefix', col: 'rid', prefix: '/acct/' });
    expect(r('a*')).toEqual({ t: 'prefix', col: 'rid', prefix: 'a' });
    expect(run(part({ predicates: [{ verb: 'v', resource: 're:/a.*' }] }))).toEqual({ ok: false, reason: 'regex resource matcher' });
    expect(run(part({ predicates: [{ verb: 'v', resource: 'ab' }] }), { columns: {} })).toEqual({ ok: false, reason: "field 'action.resource' has no usable column" });
  });
  it('never and empty permit', () => {
    const r: Residual = { decision: 'never', policy: part({ predicates: [{ verb: 'v' }] }), policyDigest: 'd' };
    expect(toFilter(r, { columns: cols })).toEqual({ ok: true, expr: Fl, sql: 'FALSE', params: [], ucast: uOr() });
    expect(run(part())).toEqual({ ok: true, expr: Fl, sql: 'FALSE', params: [], ucast: uOr() });
  });
  it('meet parts are conjoined', () => {
    const e = exprOf({ ...part({ predicates: [{ verb: 'v', resource: '/a' }] }), meet: [part({ predicates: [{ verb: 'v', resource: '/b' }] })] });
    expect(e).toEqual(AND(C('rid', 'eq', '/a'), C('rid', 'eq', '/b')));
  });
  it('deny veto with no scope', () => {
    const v: Veto = { id: 'd', kind: 'deny', when: { verb: 'v' } };
    const r = run(part({ predicates: [{ verb: 'v' }], vetoes: [v] }));
    expect(r).toMatchObject({ ok: true, expr: AND(T, NOT(T)), sql: '(TRUE AND NOT (TRUE))', params: [] });
  });
  it('veto with resource, where, over and unless', () => {
    const v: Veto = { id: 'd', kind: 'deny', when: { verb: 'v', resource: '/r', where: [L('x', 'eq', 1)] }, over: { path: 'y', threshold: 10 }, unless: [L('z', 'eq', 2), L('w', 'eq', 3)] };
    const r = run(part({ predicates: [{ verb: 'v' }], vetoes: [v] }));
    const V = AND(AND(co(C('rid', 'eq', '/r'), true), co(C('cx', 'eq', 1), true)), OR({ t: 'null', col: 'cy', isNull: true }, C('cy', 'lt', 0), C('cy', 'gt', 10)), NOT(AND(co(C('cz', 'eq', 2), false), co(C('cw', 'eq', 3), false))));
    expect(r).toEqual({
      ok: true,
      expr: AND(T, NOT(V)),
      sql: '(TRUE AND NOT (((COALESCE(rid = $1, TRUE) AND COALESCE(cx = $2, TRUE)) AND (cy IS NULL OR cy < $3 OR cy > $4) AND NOT ((COALESCE(cz = $5, FALSE) AND COALESCE(cw = $6, FALSE))))))',
      params: ['/r', 1, 0, 10, 2, 3],
      ucast: toUcast(AND(T, NOT(V))),
    });
  });
  it('a single unless condition is negated without a wrapper', () => {
    const v: Veto = { id: 'd', kind: 'deny', when: { verb: 'v' }, unless: [L('z', 'eq', 2)] };
    expect(exprOf(part({ predicates: [{ verb: 'v' }], vetoes: [v] }))).toEqual(AND(T, NOT(AND(T, NOT(co(C('cz', 'eq', 2), false))))));
  });
  it('approval vetoes ignore unless and leave only the autonomous set', () => {
    const over = { path: 'y', threshold: 5 };
    const ap: Veto = { id: 'a', kind: 'approval', when: { verb: 'v' }, over, unless: [L('z', 'eq', 1)] };
    const dn: Veto = { id: 'd', kind: 'deny', when: { verb: 'v' }, over, unless: [] };
    const O = OR({ t: 'null', col: 'cy', isNull: true }, C('cy', 'lt', 0), C('cy', 'gt', 5));
    const V = AND(T, O);
    expect(exprOf(part({ predicates: [{ verb: 'v' }], vetoes: [ap] }))).toEqual(AND(T, NOT(V)));
    expect(exprOf(part({ predicates: [{ verb: 'v' }], vetoes: [ap] }), { include: 'admitted' })).toEqual(T);
    expect(exprOf(part({ predicates: [{ verb: 'v' }], vetoes: [dn] }))).toEqual(AND(T, NOT(V)));
    expect(exprOf(part({ predicates: [{ verb: 'v' }], vetoes: [dn] }), { include: 'admitted' })).toEqual(AND(T, NOT(V)));
    expect(exprOf(part({ predicates: [{ verb: 'v' }], vetoes: [ap, dn] }), { include: 'admitted' })).toEqual(AND(T, NOT(V)));
    expect(exprOf(part({ predicates: [{ verb: 'v' }], vetoes: [ap, dn] }))).toEqual(AND(T, NOT(V), NOT(V)));
  });
  it('tighten rules: all in autonomous, only deny in admitted', () => {
    const t = [
      { id: 't1', when: L('x', 'eq', 1), signal: 'escalate' as const },
      { id: 't2', when: L('y', 'eq', 2), signal: 'deny' as const },
    ];
    const p = part({ predicates: [{ verb: 'v' }], tighten: t });
    expect(exprOf(p)).toEqual(AND(T, NOT(co(C('cx', 'eq', 1), true)), NOT(co(C('cy', 'eq', 2), true))));
    expect(exprOf(p, { include: 'autonomous' })).toEqual(AND(T, NOT(co(C('cx', 'eq', 1), true)), NOT(co(C('cy', 'eq', 2), true))));
    expect(exprOf(p, { include: 'admitted' })).toEqual(AND(T, NOT(co(C('cy', 'eq', 2), true))));
    expect(exprOf(part({ predicates: [{ verb: 'v' }], tighten: [t[0]!] }), { include: 'admitted' })).toEqual(T);
  });
  it('renders every operator', () => {
    const w: Condition[] = [L('x', 'eq', 's'), L('x', 'ne', 't'), L('y', 'lt', 1), L('y', 'lte', 2), L('y', 'gt', 3), L('y', 'gte', 4), L('z', 'in', [5, 6]), L('z', 'nin', [7, 8]), L('w', 'prefix', 'p_q'), L('x', 'exists', true), L('x', 'exists', false)];
    const p = part({ predicates: [{ verb: 'v', resource: '/a/*', where: w }] });
    const sql =
      "(rid LIKE $1 ESCAPE '!' AND cx = $2 AND cx <> $3 AND cy < $4 AND cy <= $5 AND cy > $6 AND cy >= $7 AND cz IN ($8, $9) AND cz NOT IN ($10, $11) AND cw LIKE $12 ESCAPE '!' AND cx IS NOT NULL AND cx IS NULL)";
    const params = ['/a/%', 's', 't', 1, 2, 3, 4, 5, 6, 7, 8, 'p!_q%'];
    const r = run(p);
    expect(r).toMatchObject({ ok: true, sql, params });
    expect(run(p, { dialect: 'postgres' })).toMatchObject({ sql, params });
    const q = sql.replace(/\$\d+/g, '?');
    expect(run(p, { dialect: 'sqlite' })).toMatchObject({ sql: q, params });
    expect(run(p, { dialect: 'mysql' })).toMatchObject({ sql: q, params });
  });
  it('renders or, not and coalesce', () => {
    const v: Veto = { id: 'd', kind: 'deny', when: { verb: 'v', where: [L('x', 'eq', 1)] }, unless: [L('y', 'gt', 2)] };
    const p = part({
      predicates: [
        { verb: 'v', resource: '/a' },
        { verb: 'v', resource: '/b' },
      ],
      vetoes: [v],
      tighten: [{ id: 't', when: L('x', 'ne', 3), signal: 'escalate' }],
    });
    expect(run(p)).toMatchObject({
      ok: true,
      sql: '((rid = $1 OR rid = $2) AND NOT ((COALESCE(cx = $3, TRUE) AND NOT (COALESCE(cy > $4, FALSE)))) AND NOT (COALESCE(cx <> $5, TRUE)))',
      params: ['/a', '/b', 1, 2, 3],
    });
  });
  it('ucast is attached to the result', () => {
    const r = where(L('x', 'eq', 1));
    expect(r).toMatchObject({ ok: true, ucast: fld('cx', 'eq', 1) });
  });
});

describe('evalFilter exact semantics', () => {
  const cmp = (op: 'eq' | 'ne' | 'lt' | 'lte' | 'gt' | 'gte', v: number | string | boolean): FilterExpr => C('c', op, v);
  it('true / false constants', () => {
    expect(evalFilter(T, {})).toBe(true);
    expect(evalFilter(Fl, {})).toBe(false);
  });
  it('comparison table', () => {
    const rows: Array<['eq' | 'ne' | 'lt' | 'lte' | 'gt' | 'gte', number, number, boolean]> = [
      ['eq', 1, 1, true],
      ['eq', 2, 1, false],
      ['ne', 2, 1, true],
      ['ne', 1, 1, false],
      ['lt', 1, 2, true],
      ['lt', 2, 2, false],
      ['lt', 3, 2, false],
      ['lte', 1, 2, true],
      ['lte', 2, 2, true],
      ['lte', 3, 2, false],
      ['gt', 3, 2, true],
      ['gt', 2, 2, false],
      ['gt', 1, 2, false],
      ['gte', 3, 2, true],
      ['gte', 2, 2, true],
      ['gte', 1, 2, false],
    ];
    for (const [op, a, v, want] of rows) expect(evalFilter(cmp(op, v), { c: a })).toBe(want);
    expect(evalFilter(cmp('eq', 'a'), { c: 'a' })).toBe(true);
    expect(evalFilter(cmp('eq', true), { c: true })).toBe(true);
    expect(evalFilter(cmp('ne', true), { c: true })).toBe(false);
  });
  it('NULL and type mismatch are unknown', () => {
    for (const op of ['eq', 'ne', 'lt', 'lte', 'gt', 'gte'] as const) {
      expect(evalFilter(cmp(op, 2), {})).toBeNull();
      expect(evalFilter(cmp(op, 2), { c: null })).toBeNull();
      expect(evalFilter(cmp(op, 2), { c: '1' })).toBeNull();
      expect(evalFilter(cmp(op, 2), { c: '3' })).toBeNull();
      expect(evalFilter(cmp(op, 'a'), { c: 1 })).toBeNull();
    }
    // a null operand is never a legal comparison value, and is still unknown rather than equal
    expect(evalFilter({ t: 'cmp', col: 'c', op: 'eq', v: null as unknown as number }, { c: null })).toBeNull();
  });
  it('in / nin', () => {
    const inn = (neg: boolean): FilterExpr => ({ t: 'in', col: 'c', vs: [1, 2], neg });
    expect(evalFilter(inn(false), { c: 2 })).toBe(true);
    expect(evalFilter(inn(false), { c: 3 })).toBe(false);
    expect(evalFilter(inn(true), { c: 2 })).toBe(false);
    expect(evalFilter(inn(true), { c: 3 })).toBe(true);
    for (const neg of [false, true]) {
      expect(evalFilter(inn(neg), {})).toBeNull();
      expect(evalFilter(inn(neg), { c: null })).toBeNull();
    }
  });
  it('prefix', () => {
    const p: FilterExpr = { t: 'prefix', col: 'c', prefix: 'ab' };
    expect(evalFilter(p, { c: 'abc' })).toBe(true);
    expect(evalFilter(p, { c: 'xab' })).toBe(false);
    expect(evalFilter(p, { c: 5 })).toBeNull();
    expect(evalFilter(p, { c: true })).toBeNull();
    expect(evalFilter(p, { c: null })).toBeNull();
    expect(evalFilter(p, {})).toBeNull();
  });
  it('null test', () => {
    const n = (isNull: boolean): FilterExpr => ({ t: 'null', col: 'c', isNull });
    expect(evalFilter(n(true), { c: null })).toBe(true);
    expect(evalFilter(n(true), {})).toBe(true);
    expect(evalFilter(n(true), { c: 0 })).toBe(false);
    expect(evalFilter(n(false), { c: null })).toBe(false);
    expect(evalFilter(n(false), {})).toBe(false);
    expect(evalFilter(n(false), { c: 0 })).toBe(true);
  });
  it('Kleene and / or / not / coalesce', () => {
    const U = cmp('eq', 1); // column absent: unknown
    expect(evalFilter(AND(T, T), {})).toBe(true);
    expect(evalFilter(AND(T, Fl), {})).toBe(false);
    expect(evalFilter(AND(U, T), {})).toBeNull();
    expect(evalFilter(AND(U, Fl), {})).toBe(false);
    expect(evalFilter(AND(Fl, U), {})).toBe(false);
    expect(evalFilter(AND(), {})).toBe(true);
    expect(evalFilter(OR(Fl, Fl), {})).toBe(false);
    expect(evalFilter(OR(Fl, T), {})).toBe(true);
    expect(evalFilter(OR(U, Fl), {})).toBeNull();
    expect(evalFilter(OR(U, T), {})).toBe(true);
    expect(evalFilter(OR(T, U), {})).toBe(true);
    expect(evalFilter(OR(), {})).toBe(false);
    expect(evalFilter(NOT(T), {})).toBe(false);
    expect(evalFilter(NOT(Fl), {})).toBe(true);
    expect(evalFilter(NOT(U), {})).toBeNull();
    expect(evalFilter(co(U, true), {})).toBe(true);
    expect(evalFilter(co(U, false), {})).toBe(false);
    expect(evalFilter(co(T, false), {})).toBe(true);
    expect(evalFilter(co(Fl, true), {})).toBe(false);
  });
});

describe('toUcast exact trees', () => {
  const a = C('a', 'eq', 1);
  const b = C('b', 'eq', 2);
  const c = C('c', 'eq', 3);
  const ua = fld('a', 'eq', 1);
  const ub = fld('b', 'eq', 2);
  const uc = fld('c', 'eq', 3);
  const inE = (neg: boolean): FilterExpr => ({ t: 'in', col: 'c', vs: [1, 2], neg });
  const nl = (isNull: boolean): FilterExpr => ({ t: 'null', col: 'c', isNull });
  const x1 = C('c', 'eq', 1);
  it('T of each node', () => {
    expect(toUcast(T)).toEqual(uAnd());
    expect(toUcast(Fl)).toEqual(uOr());
    expect(toUcast(C('c', 'ne', 1))).toEqual(uAnd(nn, fld('c', 'ne', 1)));
    expect(toUcast(inE(false))).toEqual(fld('c', 'in', [1, 2]));
    expect(toUcast(inE(true))).toEqual(uAnd(nn, fld('c', 'nin', [1, 2])));
    expect(toUcast(nl(true))).toEqual(fld('c', 'eq', null));
    expect(toUcast(nl(false))).toEqual(nn);
    expect(toUcast(co(x1, true))).toEqual(uNot(uAnd(nn, fld('c', 'ne', 1))));
    expect(toUcast(co(x1, false))).toEqual(fld('c', 'eq', 1));
    expect(toUcast(NOT(x1))).toEqual(uAnd(nn, fld('c', 'ne', 1)));
  });
  it('F of each node', () => {
    expect(toUcast(NOT(T))).toEqual(uOr());
    expect(toUcast(NOT(Fl))).toEqual(uAnd());
    expect(toUcast(NOT(inE(false)))).toEqual(uAnd(nn, fld('c', 'nin', [1, 2])));
    expect(toUcast(NOT(inE(true)))).toEqual(fld('c', 'in', [1, 2]));
    expect(toUcast(NOT(nl(true)))).toEqual(nn);
    expect(toUcast(NOT(nl(false)))).toEqual(fld('c', 'eq', null));
    expect(toUcast(NOT(co(x1, true)))).toEqual(uAnd(nn, fld('c', 'ne', 1)));
    expect(toUcast(NOT(co(x1, false)))).toEqual(uNot(fld('c', 'eq', 1)));
    expect(toUcast(NOT(NOT(x1)))).toEqual(fld('c', 'eq', 1));
    expect(toUcast(NOT(AND(a, b)))).toEqual(uOr(uAnd(fld('a', 'ne', null), fld('a', 'ne', 1)), uAnd(fld('b', 'ne', null), fld('b', 'ne', 2))));
  });
  it('and / or drop identities, absorb, flatten', () => {
    expect(toUcast(AND())).toEqual(uAnd());
    expect(toUcast(OR())).toEqual(uOr());
    expect(toUcast(AND(T, T))).toEqual(uAnd());
    expect(toUcast(OR(Fl, Fl))).toEqual(uOr());
    expect(toUcast(AND(a, b))).toEqual(uAnd(ua, ub));
    expect(toUcast(OR(a, b))).toEqual(uOr(ua, ub));
    expect(toUcast(AND(T, a))).toEqual(ua);
    expect(toUcast(AND(a, T))).toEqual(ua);
    expect(toUcast(OR(Fl, a))).toEqual(ua);
    expect(toUcast(OR(a, Fl))).toEqual(ua);
    expect(toUcast(AND(a, Fl))).toEqual(uOr());
    expect(toUcast(AND(Fl, a))).toEqual(uOr());
    expect(toUcast(AND(Fl))).toEqual(uOr());
    expect(toUcast(OR(a, T))).toEqual(uAnd());
    expect(toUcast(OR(T, a))).toEqual(uAnd());
    expect(toUcast(OR(T))).toEqual(uAnd());
    expect(toUcast(AND(AND(a, b), c))).toEqual(uAnd(ua, ub, uc));
    expect(toUcast(AND(a, AND(b, c)))).toEqual(uAnd(ua, ub, uc));
    expect(toUcast(OR(OR(a, b), c))).toEqual(uOr(ua, ub, uc));
    expect(toUcast(AND(OR(a, b), c))).toEqual(uAnd(uOr(ua, ub), uc));
    expect(toUcast(OR(AND(a, b), c))).toEqual(uOr(uAnd(ua, ub), uc));
    expect(toUcast(AND(AND(a, T), AND(b, T)))).toEqual(uAnd(ua, ub));
    expect(toUcast(AND(NOT(NOT(a)), b))).toEqual(uAnd(ua, ub));
    expect(toUcast(AND(co(a, false), Fl))).toEqual(uOr());
  });
});

describe('evalUcast exact semantics', () => {
  const ev = (u: Ucast, row: Record<string, unknown>) => evalUcast(u, row);
  const table: Array<[Extract<Ucast, { type: 'field' }>['operator'], Extract<Ucast, { type: 'field' }>['value'], Array<[unknown, boolean]>]> = [
    ['eq', null, [[null, true], [undefined, true], [1, false], ['', false]]],
    ['ne', null, [[1, true], [null, false], [undefined, false], [0, true]]],
    ['eq', 1, [[1, true], [2, false], [null, false], ['1', false]]],
    ['ne', 1, [[2, true], [1, false], ['2', false], [null, false]]],
    ['lt', 5, [[4, true], [5, false], [6, false], ['4', false], [null, false]]],
    ['lte', 5, [[4, true], [5, true], [6, false], ['4', false], [null, false]]],
    ['gt', 5, [[6, true], [5, false], [4, false], ['6', false], [null, false]]],
    ['gte', 5, [[6, true], [5, true], [4, false], ['6', false], [null, false]]],
    ['lt', null, [[5, false]]],
    ['lte', null, [[5, false]]],
    ['gt', null, [[5, false]]],
    ['gte', null, [[5, false]]],
    ['in', [1, 2], [[1, true], [3, false], [null, false]]],
    ['nin', [1, 2], [[3, true], [1, false], [null, false]]],
    ['startswith', 'ab', [['abc', true], ['xab', false], [5, false], [true, false], [null, false]]],
  ];
  it('field operators', () => {
    for (const [op, v, cases] of table) for (const [a, want] of cases) expect(ev(fld('k', op, v), a === undefined ? {} : { k: a }), `${op} ${JSON.stringify(v)} ${String(a)}`).toBe(want);
  });
  it('compound operators', () => {
    const row = { k: 1 };
    expect(ev(uAnd(), row)).toBe(true);
    expect(ev(uOr(), row)).toBe(false);
    expect(ev(uAnd(fld('k', 'eq', 1), fld('k', 'gt', 0)), row)).toBe(true);
    expect(ev(uAnd(fld('k', 'eq', 1), fld('k', 'gt', 1)), row)).toBe(false);
    expect(ev(uOr(fld('k', 'eq', 2), fld('k', 'gt', 0)), row)).toBe(true);
    expect(ev(uOr(fld('k', 'eq', 2), fld('k', 'gt', 1)), row)).toBe(false);
    expect(ev(uNot(fld('k', 'eq', 1)), row)).toBe(false);
    expect(ev(uNot(fld('k', 'eq', 2)), row)).toBe(true);
  });
});
