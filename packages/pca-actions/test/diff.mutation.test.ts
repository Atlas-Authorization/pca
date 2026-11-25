// diff.mutation.test.ts - behaviour tests for the semantic diff (src/diff.ts): every dimension, every relation, every reason string.
import { describe, expect, it } from 'vitest';
import { BUILTIN_DEFS, CORE_REGISTRY, diffDefs, diffIsFree, type ActionDef, type DiffClass, type ParamDef } from '../src';
import { confirmed, testReview } from './reviewed';

const D = (over: Partial<ActionDef> = {}): ActionDef => ({
  v: 1,
  kind: 'pca-action-def',
  verb: 'acme.item.set',
  title: 'Set an item',
  effects: ['read'],
  resource: { type: 'acme.item', id: { prefix: 'i_', class: 'digits', len: [1, 8] }, scope: 'one' },
  params: { n: { type: 'integer', min: 0, max: 10 } },
  review: { state: 'authored' },
  ...over,
});
const P = (params: Record<string, ParamDef>, over: Partial<ActionDef> = {}): ActionDef => D({ params, ...over });
const pd = (type: ParamDef['type'], rest: Partial<ParamDef> = {}): ParamDef => ({ type, ...rest });
const reasons = (a: ActionDef, b: ActionDef): string[] => diffDefs(a, b, CORE_REGISTRY).reasons;
/** The reasons of one dimension (by prefix). */
const only = (a: ActionDef, b: ActionDef, prefix: string): string[] => reasons(a, b).filter((r) => r.startsWith(prefix));
const callRel = (o: ParamDef, n: ParamDef): string => {
  const r = only(P({ p: o }), P({ p: n }), 'params.accepted_calls: ')[0];
  return r === undefined ? 'eq' : r.slice('params.accepted_calls: '.length);
};
const attrs = (o: ParamDef, n: ParamDef): string[] => only(P({ p: o }), P({ p: n }), 'params.p.');
const rev = (v: unknown): unknown => (Array.isArray(v) ? v.map(rev) : v !== null && typeof v === 'object' ? Object.fromEntries(Object.keys(v).reverse().map((k) => [k, rev((v as Record<string, unknown>)[k])])) : v);

describe('diff: errors and equality', () => {
  it('two different verbs are refused with a typed error', () => {
    let err: unknown;
    try { diffDefs(D(), D({ verb: 'acme.item.get' })); } catch (e) { err = e; }
    expect((err as { code?: string }).code).toBe('diff_verb');
    expect((err as Error).message).toBe("diff compares two versions of one verb, not 'acme.item.set' and 'acme.item.get'");
  });
  it('an identical definition is equal with no reasons', () => {
    expect(diffDefs(D(), D())).toEqual({ class: 'equal', reasons: [] });
  });
  it('key order is not meaning, even inside params, units, defaults (with nulls), bindings and id patterns', () => {
    const rich = P({
      p: pd('string', { role: 'x.acme.r', tags: ['phi', 'pii'], sensitivity: 'critical', provenance_min: 'tool', accumulates: ['b', 'a'], default: { b: 1, a: [{ y: 1, x: 2 }], z: null }, principal_neutral_default: true, unit: { kind: 'money', ccy: 'USD', exp: 2 }, max_len: 5, values: ['a', 'b'] }),
      q: pd('string', { default: null }),
    }, { bindings: { mcp: { tool: 't' }, http: { method: 'GET', path: '/x' } } });
    expect(diffDefs(rich, rev(rich) as ActionDef)).toEqual({ class: 'equal', reasons: [] });
    expect(diffDefs(rev(rich) as ActionDef, rich)).toEqual({ class: 'equal', reasons: [] });
  });
  it('diffIsFree: only equal and narrow follow a pin', () => {
    const all: DiffClass[] = ['equal', 'narrow', 'widen', 'incomparable'];
    expect(all.map(diffIsFree)).toEqual([true, true, false, false]);
  });
});

describe('diff: text and ordering', () => {
  it('title, description and compensates each alone are a text-only change', () => {
    const text = ['text: title, description or compensates changed'];
    expect(diffDefs(D(), D({ title: 'Other' }))).toEqual({ class: 'equal', reasons: text });
    expect(diffDefs(D(), D({ description: 'x' }))).toEqual({ class: 'equal', reasons: text });
    expect(diffDefs(D(), D({ compensates: 'acme.item.unset' }))).toEqual({ class: 'equal', reasons: text });
  });
  it('reasons come out sorted, the text reason among them', () => {
    const r = diffDefs(D(), D({ title: 'Other', traits: ['pca.bulk'] }));
    expect(r.reasons).toContain('traits: narrow');
    expect(r.reasons).toContain('text: title, description or compensates changed');
    expect(r.reasons).toEqual([...r.reasons].sort());
  });
  it('incomparable dimensions are spelled out, and a mix of widen and narrow is incomparable', () => {
    expect(diffDefs(D({ aliases: ['a1'] }), D({ aliases: ['a2'] }))).toEqual({ class: 'incomparable', reasons: ['aliases: incomparable'] });
    const narrower = { prefix: 'i_', class: 'digits' as const, len: [2, 4] as [number, number] };
    expect(diffDefs(D(), D({ aliases: ['a1'], resource: { type: 'acme.item', id: narrower, scope: 'one' } }))).toEqual({ class: 'incomparable', reasons: ['aliases: widen', 'resource.id: narrow'] });
  });
});

describe('diff: set dimensions', () => {
  it('effects: added narrows, removed widens, swapped is incomparable', () => {
    expect(reasons(D({ effects: ['create'] }), D({ effects: ['create', 'delete'] }))).toContain('effects: narrow');
    expect(reasons(D({ effects: ['create', 'delete'] }), D({ effects: ['create'] }))).toContain('effects: widen');
    expect(reasons(D({ effects: ['create'] }), D({ effects: ['delete'] }))).toContain('effects: incomparable');
    expect(only(D({ effects: ['create'] }), D({ effects: ['create'] }), 'effects')).toEqual([]);
  });
  it('aliases extend what language can reach: added widens, dropped narrows', () => {
    expect(diffDefs(D(), D({ aliases: ['a1'] }))).toEqual({ class: 'widen', reasons: ['aliases: widen'] });
    expect(diffDefs(D({ aliases: ['a1'] }), D())).toEqual({ class: 'narrow', reasons: ['aliases: narrow'] });
  });
  it('side effects: a different target or kind is incomparable, added narrows, dropped widens', () => {
    const se = (target: string, kind: 'send' | 'delete') => ({ side_effects: [{ target, kind }] });
    expect(diffDefs(D(se('a', 'send')), D(se('b', 'send')))).toEqual({ class: 'incomparable', reasons: ['side_effects: incomparable'] });
    expect(diffDefs(D(se('a', 'send')), D(se('a', 'delete')))).toEqual({ class: 'incomparable', reasons: ['side_effects: incomparable'] });
    expect(diffDefs(D(se('a', 'send')), D(se('a', 'send')))).toEqual({ class: 'equal', reasons: [] });
    expect(diffDefs(D(), D(se('a', 'send')))).toEqual({ class: 'narrow', reasons: ['side_effects: narrow'] });
    expect(diffDefs(D(se('a', 'send')), D())).toEqual({ class: 'widen', reasons: ['side_effects: widen'] });
  });
  it('bindings: any change has no order', () => {
    expect(diffDefs(D(), D({ bindings: { mcp: { tool: 't' } } }))).toEqual({ class: 'incomparable', reasons: ['bindings: incomparable'] });
  });
  it('context, with the hint profile that carries it', () => {
    const c = (...k: string[]) => D({ context: k });
    expect(reasons(c(), c('approval_ref'))).toEqual(expect.arrayContaining(['context: narrow', 'profile: narrow']));
    expect(reasons(c('approval_ref'), c())).toEqual(expect.arrayContaining(['context: widen', 'profile: widen']));
    expect(reasons(c('approval_ref'), c('revocable'))).toEqual(expect.arrayContaining(['context: incomparable', 'profile: incomparable']));
    expect(only(c('revocable'), c('revocable'), 'context')).toEqual([]);
  });
  it('declared traits show in the hint trait set', () => {
    expect(reasons(D(), D({ traits: ['pca.bulk'] }))).toContain('traits: narrow');
    expect(reasons(D({ traits: ['pca.bulk'] }), D())).toContain('traits: widen');
  });
});

describe('diff: ranked dimensions', () => {
  it('blast: a lower value widens, a higher one narrows', () => {
    const b = (radius: 'one' | 'tenant') => D({ blast: { radius } });
    expect(only(b('tenant'), b('one'), 'blast')).toEqual(['blast: widen']);
    expect(only(b('one'), b('tenant'), 'blast')).toEqual(['blast: narrow']);
    expect(only(b('one'), b('one'), 'blast')).toEqual([]);
  });
  it('reversibility: lowered widens, raised narrows', () => {
    const r = (reversibility: 'reversible' | 'rate_limited' | 'irreversible') => D({ reversibility });
    expect(only(r('reversible'), r('irreversible'), 'reversibility')).toEqual(['reversibility: narrow']);
    expect(only(r('irreversible'), r('rate_limited'), 'reversibility')).toEqual(['reversibility: widen']);
    expect(only(r('rate_limited'), r('rate_limited'), 'reversibility')).toEqual([]);
  });
  it('idempotency: the mode orders, a different key parameter does not', () => {
    const i = (mode: 'none' | 'natural' | 'key_param', param?: string) => D({ idempotency: param === undefined ? { mode } : { mode, param } });
    const f = (a: ActionDef, b: ActionDef) => only(a, b, 'idempotency');
    expect(f(i('key_param', 'k'), i('key_param', 'k'))).toEqual([]);
    expect(f(i('key_param', 'k'), i('key_param', 'j'))).toEqual(['idempotency: incomparable']);
    expect(f(i('key_param', 'k'), i('natural'))).toEqual(['idempotency: widen']);
    expect(f(i('key_param', 'k'), i('none'))).toEqual(['idempotency: widen']);
    expect(f(i('none'), i('key_param', 'k'))).toEqual(['idempotency: narrow']);
    expect(f(i('natural'), i('key_param', 'k'))).toEqual(['idempotency: narrow']);
    expect(f(i('none'), i('natural'))).toEqual(['idempotency: narrow']);
    expect(f(i('natural'), i('none'))).toEqual(['idempotency: widen']);
    expect(f(i('none'), i('none'))).toEqual([]);
    expect(f(i('natural'), i('natural'))).toEqual([]);
  });
  it('resource scope: a bigger scope widens', () => {
    const s = (scope: 'one' | 'set' | 'tenant') => D({ resource: { type: 'acme.item', id: '*', scope } });
    expect(only(s('one'), s('tenant'), 'resource.scope')).toEqual(['resource.scope: widen']);
    expect(only(s('tenant'), s('one'), 'resource.scope')).toEqual(['resource.scope: narrow']);
    expect(only(s('set'), s('one'), 'resource.scope')).toEqual(['resource.scope: narrow']);
    expect(only(s('set'), s('set'), 'resource.scope')).toEqual([]);
  });
  it('resource id: contained narrows, containing widens, unrelated or another type is incomparable', () => {
    const id = (prefix: string, len: [number, number]) => D({ resource: { type: 'acme.item', id: { prefix, class: 'digits', len }, scope: 'one' } });
    const f = (a: ActionDef, b: ActionDef) => only(a, b, 'resource.id:');
    expect(f(id('i_', [1, 8]), id('i_', [2, 4]))).toEqual(['resource.id: narrow']);
    expect(f(id('i_', [2, 4]), id('i_', [1, 8]))).toEqual(['resource.id: widen']);
    expect(f(id('a_', [1, 8]), id('b_', [1, 8]))).toEqual(['resource.id: incomparable']);
    expect(f(id('i_', [1, 8]), id('i_', [1, 8]))).toEqual([]);
    const other = D({ resource: { type: 'acme.other', id: { prefix: 'i_', class: 'digits', len: [1, 8] }, scope: 'one' } });
    expect(diffDefs(D(), other)).toEqual({ class: 'incomparable', reasons: ['resource.id: incomparable'] });
  });
  it('a bigger resource scope also shows as a scope widening in the whole diff', () => {
    const s = (scope: 'one' | 'tenant') => D({ resource: { type: 'acme.item', id: '*', scope } });
    expect(reasons(s('one'), s('tenant'))).toContain('resource.scope: widen');
  });
});

describe('diff: confirmation and effective views', () => {
  const refund = BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!;
  it('confirmed to unconfirmed narrows the effective views, the other way widens them', () => {
    const c = confirmed(refund);
    const edited: ActionDef = { ...refund, title: 'Refund a payment', review: { state: 'authored' } };
    const o = testReview();
    const down = diffDefs(c, edited, CORE_REGISTRY, o).reasons;
    expect(down).toEqual(expect.arrayContaining(['confirmation: narrow', 'effective.profile: narrow', 'effective.traits: narrow']));
    const up = diffDefs(edited, confirmed(edited), CORE_REGISTRY, o).reasons;
    expect(up).toEqual(expect.arrayContaining(['confirmation: widen', 'effective.profile: widen', 'effective.traits: widen']));
  });
});

describe('diff: parameter call sets', () => {
  type Row = [string, ParamDef, ParamDef, string];
  const check = (rows: Row[]): void => { for (const [label, o, n, want] of rows) expect(callRel(o, n), label).toBe(want); };

  it('strings and object refs: length, values and format', () => {
    for (const t of ['string', 'object_ref'] as const) {
      check([
        [`${t} narrower length`, pd(t, { max_len: 10 }), pd(t, { max_len: 5 }), 'narrow'],
        [`${t} wider length`, pd(t, { max_len: 5 }), pd(t, { max_len: 10 }), 'widen'],
        [`${t} same`, pd(t), pd(t), 'eq'],
        [`${t} default length`, pd(t, { max_len: 1024 }), pd(t), 'eq'],
        [`${t} over default length`, pd(t, { max_len: 2000 }), pd(t), 'narrow'],
        [`${t} values narrower`, pd(t, { values: ['a', 'b'] }), pd(t, { values: ['a'] }), 'narrow'],
        [`${t} values wider`, pd(t, { values: ['a'] }), pd(t, { values: ['a', 'b'] }), 'widen'],
        [`${t} values dropped`, pd(t, { values: ['a'] }), pd(t), 'widen'],
        [`${t} values added`, pd(t), pd(t, { values: ['a'] }), 'narrow'],
        [`${t} same format`, pd(t, { format: 'email' }), pd(t, { format: 'email' }), 'eq'],
        [`${t} format dropped`, pd(t, { format: 'email' }), pd(t), 'widen'],
        [`${t} format added`, pd(t), pd(t, { format: 'email' }), 'narrow'],
        [`${t} format swapped`, pd(t, { format: 'email' }), pd(t, { format: 'url' }), 'incomparable'],
      ]);
    }
  });
  it('a parameter of another type has no order', () => {
    check([['type', pd('string'), pd('integer'), 'incomparable'], ['boolean vs string', pd('boolean'), pd('string'), 'incomparable']]);
  });
  it('integers and durations: min and max', () => {
    for (const t of ['integer', 'duration'] as const) {
      const rows: Array<[ParamDef, ParamDef, string]> = [
        [{ type: t, min: 0, max: 10 }, { type: t, min: 0, max: 10 }, 'eq'],
        [{ type: t, min: 0, max: 10 }, { type: t, min: 2, max: 8 }, 'narrow'],
        [{ type: t, min: 0, max: 10 }, { type: t, min: 0, max: 20 }, 'widen'],
        [{ type: t, min: 2, max: 10 }, { type: t, min: 0, max: 10 }, 'widen'],
        [{ type: t, min: 0, max: 10 }, { type: t, min: 5, max: 20 }, 'incomparable'],
        [{ type: t, min: 5, max: 20 }, { type: t, min: 0, max: 10 }, 'incomparable'],
        [{ type: t, min: 0, max: 10 }, { type: t, min: 5, max: 10 }, 'narrow'],
        [{ type: t, min: 0, max: 10 }, { type: t, min: 0, max: 5 }, 'narrow'],
        [{ type: t, min: 5 }, { type: t, min: 5 }, 'eq'],
        [{ type: t, max: 5 }, { type: t, max: 5 }, 'eq'],
        [{ type: t }, { type: t }, 'eq'],
        [{ type: t }, { type: t, min: 0, max: 10 }, 'narrow'],
        [{ type: t, min: 5 }, { type: t }, 'widen'],
        [{ type: t }, { type: t, min: 5 }, 'narrow'],
        [{ type: t, max: 10 }, { type: t }, 'widen'],
        [{ type: t }, { type: t, max: 10 }, 'narrow'],
      ];
      for (const [o, n, want] of rows) expect(callRel(o, n), `${t} ${JSON.stringify(o)} -> ${JSON.stringify(n)}`).toBe(want);
    }
  });
  it('a negative integer minimum is a real bound, a negative duration minimum is not', () => {
    expect(callRel(pd('integer', { min: -5 }), pd('integer', { min: 0 }))).toBe('narrow');
    expect(callRel(pd('integer', { min: 0 }), pd('integer'))).toBe('widen');
    expect(callRel(pd('duration', { min: -5 }), pd('duration', { min: 0 }))).toBe('eq');
    expect(callRel(pd('duration', { min: 0 }), pd('duration'))).toBe('eq');
  });
  it('sets: members, item counts', () => {
    const S = ['a', 'b', 'c'];
    check([
      ['same', pd('set', { values: S }), pd('set', { values: S }), 'eq'],
      ['same bounded', pd('set', { values: S, min_items: 1, max_items: 2 }), pd('set', { values: S, min_items: 1, max_items: 2 }), 'eq'],
      ['no values', pd('set'), pd('set'), 'eq'],
      ['members neither contains the other, with the same item counts', pd('set', { values: ['a', 'b'] }), pd('set', { values: ['a', 'c'] }), 'incomparable'],
      ['values narrower', pd('set', { values: S }), pd('set', { values: ['a', 'b'] }), 'narrow'],
      ['values wider', pd('set', { values: ['a', 'b'] }), pd('set', { values: S }), 'widen'],
      ['values wider than a smaller', pd('set', { values: ['a'] }), pd('set', { values: ['a', 'b'] }), 'widen'],
      ['values dropped', pd('set', { values: ['a'] }), pd('set'), 'narrow'],
      ['a set without values holds no member, whatever it is called', pd('set'), pd('set', { values: ['Stryker was here'] }), 'widen'],
      ['max items wider', pd('set', { values: S, max_items: 2 }), pd('set', { values: S, max_items: 3 }), 'widen'],
      ['max items narrower', pd('set', { values: S, max_items: 3 }), pd('set', { values: S, max_items: 2 }), 'narrow'],
      ['max items implied by the values', pd('set', { values: S }), pd('set', { values: S, max_items: 3 }), 'eq'],
      ['min items higher', pd('set', { values: S, min_items: 1 }), pd('set', { values: S, min_items: 2 }), 'narrow'],
      ['min items lower', pd('set', { values: S, min_items: 2 }), pd('set', { values: S, min_items: 1 }), 'widen'],
      ['min items zero is the default', pd('set', { values: S }), pd('set', { values: S, min_items: 0 }), 'eq'],
      ['min up while max up', pd('set', { values: S, min_items: 1, max_items: 2 }), pd('set', { values: S, min_items: 2, max_items: 3 }), 'incomparable'],
    ]);
  });
  it('arrays: item type, counts, and the bound of the items', () => {
    check([
      ['same', pd('array'), pd('array'), 'eq'],
      ['default item type', pd('array'), pd('array', { items: 'string' }), 'eq'],
      ['default item type, reversed', pd('array', { items: 'string' }), pd('array'), 'eq'],
      ['integer items', pd('array', { items: 'integer' }), pd('array', { items: 'integer' }), 'eq'],
      ['item types differ', pd('array', { items: 'integer' }), pd('array', { items: 'string' }), 'incomparable'],
      ['item types differ, reversed', pd('array', { items: 'string' }), pd('array', { items: 'integer' }), 'incomparable'],
      ['max items narrower', pd('array', { max_items: 10 }), pd('array', { max_items: 5 }), 'narrow'],
      ['max items wider', pd('array', { max_items: 5 }), pd('array', { max_items: 10 }), 'widen'],
      ['default max items', pd('array'), pd('array', { max_items: 64 }), 'eq'],
      ['over default max items', pd('array', { max_items: 100 }), pd('array'), 'narrow'],
      ['min items higher', pd('array', { min_items: 1 }), pd('array', { min_items: 2 }), 'narrow'],
      ['min items lower', pd('array', { min_items: 2 }), pd('array', { min_items: 1 }), 'widen'],
      ['min items equal', pd('array', { min_items: 2 }), pd('array', { min_items: 2 }), 'eq'],
      ['min items default', pd('array'), pd('array', { min_items: 0 }), 'eq'],
      ['string items: max_len narrower', pd('array', { max_len: 10 }), pd('array', { max_len: 5 }), 'narrow'],
      ['string items: max_len wider', pd('array', { max_len: 5 }), pd('array', { max_len: 10 }), 'widen'],
      ['string items: max_len equal', pd('array', { max_len: 10 }), pd('array', { max_len: 10 }), 'eq'],
      ['string items: default max_len', pd('array'), pd('array', { max_len: 1024 }), 'eq'],
      ['string items ignore min and max', pd('array', { min: 0 }), pd('array', { min: 5 }), 'eq'],
      ['integer items ignore max_len', pd('array', { items: 'integer', max_len: 5 }), pd('array', { items: 'integer', max_len: 10 }), 'eq'],
    ]);
    const it0 = (r: Partial<ParamDef>): ParamDef => ({ type: 'array', items: 'integer', ...r });
    const rows: Array<[Partial<ParamDef>, Partial<ParamDef>, string]> = [
      [{ min: 0, max: 10 }, { min: 0, max: 10 }, 'eq'],
      [{ min: 0, max: 10 }, { min: 2, max: 8 }, 'narrow'],
      [{ min: 0, max: 10 }, { min: 0, max: 20 }, 'widen'],
      [{ min: 2, max: 10 }, { min: 0, max: 10 }, 'widen'],
      [{ min: 0, max: 10 }, { min: 5, max: 20 }, 'incomparable'],
      [{ min: 5, max: 20 }, { min: 0, max: 10 }, 'incomparable'],
      [{ min: 0, max: 10 }, { min: 5, max: 10 }, 'narrow'],
      [{ min: 0, max: 10 }, { min: 0, max: 5 }, 'narrow'],
      [{ min: 5 }, { min: 5 }, 'eq'],
      [{ max: 5 }, { max: 5 }, 'eq'],
      [{}, {}, 'eq'],
      [{}, { min: 0, max: 10 }, 'narrow'],
      [{ min: 5 }, {}, 'widen'],
      [{}, { min: 5 }, 'narrow'],
      [{ max: 10 }, {}, 'widen'],
      [{}, { max: 10 }, 'narrow'],
    ];
    for (const [o, n, want] of rows) expect(callRel(it0(o), it0(n)), `integer items ${JSON.stringify(o)} -> ${JSON.stringify(n)}`).toBe(want);
  });
  it('types without members compare as equal', () => {
    check([['boolean', pd('boolean'), pd('boolean'), 'eq'], ['date', pd('date'), pd('date'), 'eq'], ['datetime', pd('datetime'), pd('datetime'), 'eq']]);
  });
});

describe('diff: parameter attributes', () => {
  it('role: any change has no order', () => {
    expect(attrs(pd('string', { role: 'x.acme.a' }), pd('string', { role: 'x.acme.b' }))).toEqual(['params.p.role: incomparable']);
    expect(attrs(pd('string'), pd('string', { role: 'x.acme.a' }))).toEqual(['params.p.role: incomparable']);
    expect(attrs(pd('string', { role: 'x.acme.a' }), pd('string', { role: 'x.acme.a' }))).toEqual([]);
  });
  it('sensitivity: raised narrows, lowered widens', () => {
    expect(attrs(pd('string', { sensitivity: 'free' }), pd('string', { sensitivity: 'material' }))).toEqual(['params.p.sensitivity: narrow']);
    expect(attrs(pd('string', { sensitivity: 'material' }), pd('string', { sensitivity: 'free' }))).toEqual(['params.p.sensitivity: widen']);
    expect(attrs(pd('string', { sensitivity: 'free' }), pd('string', { sensitivity: 'critical' }))).toEqual(['params.p.sensitivity: narrow']);
  });
  it('tags', () => {
    const t = (...tags: Array<'code' | 'sql'>): ParamDef => pd('string', { tags, sensitivity: 'critical' });
    expect(attrs(t('code'), t('code', 'sql'))).toEqual(['params.p.tags: narrow']);
    expect(attrs(t('code', 'sql'), t('code'))).toEqual(['params.p.tags: widen']);
    expect(attrs(t('code'), t('sql'))).toEqual(['params.p.tags: incomparable']);
    expect(attrs(pd('string', { sensitivity: 'critical' }), t('code'))).toEqual(['params.p.tags: narrow']);
    expect(attrs(t('code'), t('code'))).toEqual([]);
  });
  it('provenance_min: a stricter source narrows, an absent one is as loose as the loosest level', () => {
    const v = (provenance_min?: ParamDef['provenance_min']): ParamDef => pd('string', provenance_min === undefined ? {} : { provenance_min });
    expect(attrs(v('first_party'), v('tool'))).toEqual(['params.p.provenance_min: widen']);
    expect(attrs(v('tool'), v('first_party'))).toEqual(['params.p.provenance_min: narrow']);
    expect(attrs(v(), v('agent'))).toEqual([]);
    expect(attrs(v('agent'), v())).toEqual([]);
    expect(attrs(v(), v('first_party'))).toEqual(['params.p.provenance_min: narrow']);
    expect(attrs(v('first_party'), v())).toEqual(['params.p.provenance_min: widen']);
    expect(attrs(v('tool'), v('tool'))).toEqual([]);
  });
  it('unit: any change has no order', () => {
    expect(attrs(pd('string', { unit: { kind: 'count' } }), pd('string', { unit: { kind: 'bytes' } }))).toEqual(['params.p.unit: incomparable']);
    expect(attrs(pd('string'), pd('string', { unit: { kind: 'count' } }))).toEqual(['params.p.unit: incomparable']);
    expect(attrs(pd('string', { unit: { kind: 'count' } }), pd('string', { unit: { kind: 'count' } }))).toEqual([]);
  });
  it('accumulates', () => {
    const a = (...accumulates: string[]): ParamDef => pd('string', { accumulates });
    expect(attrs(a('a'), a('a', 'b'))).toEqual(['params.p.accumulates: narrow']);
    expect(attrs(a('a', 'b'), a('a'))).toEqual(['params.p.accumulates: widen']);
    expect(attrs(a('a'), a('b'))).toEqual(['params.p.accumulates: incomparable']);
    expect(attrs(pd('string'), a('a'))).toEqual(['params.p.accumulates: narrow']);
    expect(attrs(a('a'), a('a'))).toEqual([]);
  });
  it('default: a changed value or a changed neutrality flag has no order', () => {
    expect(attrs(pd('string', { default: 1 }), pd('string', { default: 2 }))).toEqual(['params.p.default: incomparable']);
    expect(attrs(pd('string', { default: 1, principal_neutral_default: true }), pd('string', { default: 1, principal_neutral_default: false }))).toEqual(['params.p.default: incomparable']);
    expect(attrs(pd('string', { default: 1 }), pd('string', { default: 1, principal_neutral_default: true }))).toEqual(['params.p.default: incomparable']);
    expect(attrs(pd('string', { default: 1, principal_neutral_default: true }), pd('string', { default: 2, principal_neutral_default: true }))).toEqual(['params.p.default: incomparable']);
    expect(attrs(pd('string', { default: 1, principal_neutral_default: true }), pd('string', { default: 1, principal_neutral_default: true }))).toEqual([]);
  });
});

describe('diff: profile views', () => {
  it('the hint profile and traits are named in the reasons', () => {
    expect(reasons(D({ reversibility: 'reversible', effects: ['update'] }), D({ reversibility: 'irreversible', effects: ['update'] }))).toEqual(expect.arrayContaining(['profile: narrow', 'traits: narrow']));
    expect(reasons(D({ reversibility: 'irreversible', effects: ['update'] }), D({ reversibility: 'reversible', effects: ['update'] }))).toEqual(expect.arrayContaining(['profile: widen', 'traits: widen']));
  });
});
