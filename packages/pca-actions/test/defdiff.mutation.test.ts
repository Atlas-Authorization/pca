// defdiff.mutation.test.ts - behaviour tests for the authoring diff (src/defdiff.ts): every reason string, the breaking flag, pack rows.
import { describe, expect, it } from 'vitest';
import { CORE_REGISTRY, diffDefsAuthoring as diffDefs, diffPacks, type ActionDef, type ParamDef } from '../src';

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
const P = (p: ParamDef, extra: Record<string, ParamDef> = {}): ActionDef => D({ params: { p, ...extra } });
const pd = (type: ParamDef['type'], rest: Partial<ParamDef> = {}): ParamDef => ({ type, ...rest });
const diff = (a: ActionDef, b: ActionDef) => diffDefs(a, b, CORE_REGISTRY);
/** The diff of two one-parameter defs. */
const pdiff = (o: ParamDef, n: ParamDef) => diff(P(o), P(n));

describe('authoring diff: whole definition', () => {
  it('a renamed verb is a breaking widening with its reason', () => {
    expect(diff(D(), D({ verb: 'acme.item.get' }))).toEqual({ class: 'widen', breaking: true, reasons: ['verb renamed: removed + added (grants on the old verb do not follow)'] });
  });
  it('identical definitions are equal with no reasons; a title change alone is explained', () => {
    expect(diff(D(), D())).toEqual({ class: 'equal', breaking: false, reasons: [] });
    expect(diff(D(), D({ title: 'Other' }))).toEqual({ class: 'equal', breaking: false, reasons: ['equal: only title or description changed'] });
  });
  it('the effective profile falling widens, rising narrows', () => {
    const c = (...k: string[]) => D({ context: k });
    expect(diff(c('approval_ref'), c())).toEqual({ class: 'widen', breaking: false, reasons: ['widen: the effective profile is not at least the old one'] });
    expect(diff(c(), c('approval_ref'))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: the effective profile rose'] });
  });
  it('effects added narrow, effects removed widen', () => {
    const up = D({ effects: ['read', 'update'] });
    expect(diff(D(), up)).toEqual({
      class: 'narrow', breaking: false,
      reasons: ['narrow: the effective profile rose', 'narrow: effect update added', 'narrow: reversibility raised (reversible to irreversible)'],
    });
    expect(diff(up, D())).toEqual({
      class: 'widen', breaking: false,
      reasons: ['widen: the effective profile is not at least the old one', 'widen: effect update removed', 'widen: reversibility lowered (irreversible to reversible)'],
    });
  });
  it('declared traits added narrow, removed widen', () => {
    expect(diff(D(), D({ traits: ['pca.bulk'] })).reasons).toContain('narrow: declared trait pca.bulk added');
    expect(diff(D({ traits: ['pca.bulk'] }), D()).reasons).toContain('widen: declared trait pca.bulk removed');
    expect(diff(D({ traits: ['pca.bulk'] }), D({ traits: ['pca.bulk'] }))).toEqual({ class: 'equal', breaking: false, reasons: [] });
  });
  it('reversibility, with the profile it carries', () => {
    const r = (reversibility: 'reversible' | 'rate_limited' | 'irreversible') => D({ reversibility });
    expect(diff(r('irreversible'), r('reversible'))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: the effective profile is not at least the old one', 'widen: reversibility lowered (irreversible to reversible)'] });
    expect(diff(r('reversible'), r('irreversible'))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: the effective profile rose', 'narrow: reversibility raised (reversible to irreversible)'] });
    expect(diff(r('irreversible'), r('rate_limited')).reasons).toContain('widen: reversibility lowered (irreversible to rate_limited)');
    expect(diff(r('rate_limited'), r('irreversible')).reasons).toContain('narrow: reversibility raised (rate_limited to irreversible)');
  });
  it('blast', () => {
    const b = (radius: 'one' | 'tenant') => D({ blast: { radius } });
    expect(diff(b('tenant'), b('one'))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: the effective profile is not at least the old one', 'widen: blast lowered'] });
    expect(diff(b('one'), b('tenant'))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: the effective profile rose', 'narrow: blast raised'] });
  });
  it('idempotency: any mode counts as present', () => {
    const i = (mode: 'none' | 'natural' | 'key_param') => D({ idempotency: mode === 'key_param' ? { mode, param: 'k' } : { mode } });
    expect(diff(i('none'), i('natural'))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: idempotency added'] });
    expect(diff(i('natural'), i('none'))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: idempotency loosened'] });
    expect(diff(i('key_param'), i('none')).reasons).toEqual(['widen: idempotency loosened']);
    expect(diff(i('none'), i('key_param')).reasons).toEqual(['narrow: idempotency added']);
  });
  it('resource: a different type has no order', () => {
    const other = D({ resource: { type: 'acme.other', id: { prefix: 'i_', class: 'digits', len: [1, 8] }, scope: 'one' } });
    expect(diff(D(), other)).toEqual({ class: 'incomparable', breaking: false, reasons: ['incomparable: resource type changed'] });
  });
  it('resource: scope and id pattern', () => {
    const s = (scope: 'one' | 'tenant') => D({ blast: { radius: 'tenant' }, resource: { type: 'acme.item', id: '*', scope } });
    expect(diff(s('one'), s('tenant')).reasons).toContain('widen: resource scope widened');
    expect(diff(s('tenant'), s('one')).reasons).toContain('narrow: resource scope narrowed');
    const id = (len: [number, number]) => D({ resource: { type: 'acme.item', id: { prefix: 'i_', class: 'digits', len }, scope: 'one' } });
    expect(diff(id([1, 8]), id([2, 4]))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: the resource id pattern is narrower'] });
    expect(diff(id([2, 4]), id([1, 8]))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: the resource id pattern is not contained in the old one'] });
    expect(diff(id([1, 8]), id([1, 8]))).toEqual({ class: 'equal', breaking: false, reasons: [] });
  });
  it('a def that leaves the confirmed state narrows', () => {
    const c = D({ review: { state: 'confirmed' } });
    expect(diff(c, D())).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: review state left confirmed'] });
    expect(diff(c, c)).toEqual({ class: 'equal', breaking: false, reasons: [] });
    expect(diff(D(), c).reasons).not.toContain('narrow: review state left confirmed');
  });
});

describe('authoring diff: parameters', () => {
  const m = pd('integer', { min: 0, max: 1 });
  it('a removed param narrows and is breaking', () => {
    expect(diff(D({ params: { n: m, m } }), D({ params: { n: m } }))).toEqual({ class: 'narrow', breaking: true, reasons: ['narrow: param m removed'] });
  });
  it('an added required param narrows and is breaking, an added optional one widens', () => {
    expect(diff(D({ params: { n: m } }), D({ params: { n: m, m } }))).toEqual({ class: 'narrow', breaking: true, reasons: ['narrow: required param m added'] });
    expect(diff(D({ params: { n: m } }), D({ params: { n: m, m: { ...m, required: false } } }))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: optional param m added'] });
  });
  it('required and optional', () => {
    const req = (required: boolean) => P(pd('integer', { required }));
    expect(diff(req(false), req(true))).toEqual({ class: 'narrow', breaking: true, reasons: ['narrow: param p: optional to required'] });
    expect(diff(req(true), req(false))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: required to optional'] });
    expect(diff(req(false), req(false))).toEqual({ class: 'equal', breaking: false, reasons: [] });
    expect(diff(req(true), req(true))).toEqual({ class: 'equal', breaking: false, reasons: [] });
  });
  it('numeric bounds: min, max, max_len, max_items, min_items, each with its direction', () => {
    const mn = (v: number | undefined): ParamDef => (v === undefined ? { type: 'integer' } : { type: 'integer', min: v });
    const mx = (v: number | undefined): ParamDef => (v === undefined ? { type: 'integer' } : { type: 'integer', max: v });
    expect(pdiff(mn(0), mn(5))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: min 0 to 5'] });
    expect(pdiff(mn(0), mn(-5))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: min 0 to -5'] });
    expect(pdiff(mn(undefined), mn(0))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: min undefined to 0'] });
    expect(pdiff(mn(0), mn(undefined))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: min 0 to undefined'] });
    expect(pdiff(mx(10), mx(20))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: max 10 to 20'] });
    expect(pdiff(mx(20), mx(10))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: max 20 to 10'] });
    expect(pdiff(mx(10), mx(undefined))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: max 10 to undefined'] });
    expect(pdiff(mx(undefined), mx(10))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: max undefined to 10'] });
    expect(pdiff(pd('string', { max_len: 10 }), pd('string', { max_len: 5 }))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: max_len 10 to 5'] });
    expect(pdiff(pd('string', { max_len: 5 }), pd('string', { max_len: 10 }))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: max_len 5 to 10'] });
    expect(pdiff(pd('array', { max_items: 10 }), pd('array', { max_items: 5 }))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: max_items 10 to 5'] });
    expect(pdiff(pd('array', { max_items: 5 }), pd('array', { max_items: 10 }))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: max_items 5 to 10'] });
    expect(pdiff(pd('array', { max_items: 5 }), pd('array', { max_items: 5 }))).toEqual({ class: 'equal', breaking: false, reasons: [] });
    expect(pdiff(pd('array', { max_items: 5, min_items: 1 }), pd('array', { max_items: 5, min_items: 2 }))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: min_items 1 to 2'] });
    expect(pdiff(pd('array', { max_items: 5, min_items: 2 }), pd('array', { max_items: 5, min_items: 1 }))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: min_items 2 to 1'] });
  });
  it('an unbounded side compares as an infinite bound, and an explicit infinity is not wider than none', () => {
    expect(pdiff(pd('integer', { max: undefined }), pd('integer', { max: Infinity })).reasons).toEqual(['narrow: param p: max undefined to Infinity']);
    expect(pdiff(pd('integer', { min: undefined }), pd('integer', { min: -Infinity })).reasons).toEqual(['narrow: param p: min undefined to -Infinity']);
  });
  it('a changed type or unit has no order', () => {
    expect(pdiff(pd('string'), pd('integer'))).toEqual({ class: 'incomparable', breaking: false, reasons: ['incomparable: param p: type changed'] });
    expect(pdiff(pd('integer', { unit: { kind: 'count' } }), pd('integer', { unit: { kind: 'bytes' } }))).toEqual({ class: 'incomparable', breaking: false, reasons: ['incomparable: param p: unit changed'] });
    expect(pdiff(pd('integer', { unit: { kind: 'count' } }), pd('integer', { unit: { kind: 'count' } }))).toEqual({ class: 'equal', breaking: false, reasons: [] });
  });
  it('values: restricted, unrestricted, added, removed (listed in order)', () => {
    expect(pdiff(pd('string'), pd('string', { values: ['a'] }))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: values restricted'] });
    expect(pdiff(pd('string', { values: ['a'] }), pd('string'))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: values unrestricted'] });
    expect(pdiff(pd('string', { values: ['a'] }), pd('string', { values: ['a', 'c', 'd'] }))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: values added (c, d)'] });
    expect(pdiff(pd('string', { values: ['a', 'b', 'c'] }), pd('string', { values: ['a'] }))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: values removed (b, c)'] });
    expect(pdiff(pd('string', { values: ['a', 'b'] }), pd('string', { values: ['b', 'c'] }))).toEqual({
      class: 'incomparable', breaking: false, reasons: ['widen: param p: values added (c)', 'narrow: param p: values removed (a)'],
    });
    expect(pdiff(pd('string', { values: ['a'] }), pd('string', { values: ['a'] }))).toEqual({ class: 'equal', breaking: false, reasons: [] });
  });
  it('provenance_min: a looser source widens, a stricter one narrows, an absent one is looser than any level', () => {
    const v = (provenance_min?: ParamDef['provenance_min']): ParamDef => pd('string', provenance_min === undefined ? {} : { provenance_min });
    expect(pdiff(v('first_party'), v('tool'))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: provenance_min loosened'] });
    expect(pdiff(v('tool'), v('first_party'))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: provenance_min tightened'] });
    expect(pdiff(v('agent'), v())).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: provenance_min loosened'] });
    expect(pdiff(v(), v('agent'))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: provenance_min tightened'] });
    expect(pdiff(v('tool'), v('tool'))).toEqual({ class: 'equal', breaking: false, reasons: [] });
  });
  it('sensitivity: lowered widens, raised narrows', () => {
    expect(pdiff(pd('string', { sensitivity: 'material' }), pd('string', { sensitivity: 'free' }))).toEqual({ class: 'widen', breaking: false, reasons: ['widen: param p: sensitivity lowered'] });
    expect(pdiff(pd('string', { sensitivity: 'free' }), pd('string', { sensitivity: 'material' }))).toEqual({ class: 'narrow', breaking: false, reasons: ['narrow: param p: sensitivity raised'] });
  });
  it('role: ordered by the sensitivity floor it carries, otherwise incomparable', () => {
    expect(pdiff(pd('string', { role: 'credential.secret' }), pd('string', { role: 'person.name' })).reasons).toContain('widen: param p: role changed to a lower-floor role');
    expect(pdiff(pd('string', { role: 'person.name' }), pd('string', { role: 'credential.secret' })).reasons).toContain('narrow: param p: role changed to a higher-floor role');
    expect(pdiff(pd('string', { role: 'x.acme.a' }), pd('string', { role: 'x.acme.b' }))).toEqual({ class: 'incomparable', breaking: false, reasons: ['incomparable: param p: role changed'] });
    expect(pdiff(pd('string'), pd('string', { role: 'x.acme.a' }))).toEqual({ class: 'incomparable', breaking: false, reasons: ['incomparable: param p: role changed'] });
    expect(pdiff(pd('string', { role: 'x.acme.a' }), pd('string', { role: 'x.acme.a' }))).toEqual({ class: 'equal', breaking: false, reasons: [] });
  });
});

describe('authoring diff: packs', () => {
  it('per-verb rows: added, removed and compared verbs, sorted by verb', () => {
    const a = D({ verb: 'acme.a.set' });
    const b = D({ verb: 'acme.b.set' });
    const c = D({ verb: 'acme.c.set' });
    const c2 = D({ verb: 'acme.c.set', params: { n: { type: 'integer', min: 0, max: 20 } } });
    expect(diffPacks([b, c], [a, c2], CORE_REGISTRY)).toEqual([
      { verb: 'acme.a.set', class: 'added', breaking: false, reasons: [] },
      { verb: 'acme.b.set', class: 'removed', breaking: true, reasons: ['verb removed'] },
      { verb: 'acme.c.set', class: 'widen', breaking: false, reasons: ['widen: param n: max 10 to 20'] },
    ]);
  });
});
