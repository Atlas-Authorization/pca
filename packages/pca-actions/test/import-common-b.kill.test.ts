// Boundary and branch tests for the importers' shared schema flattening and def assembly (leaf params, object flattening, emitDef, withTrait).
import { describe, expect, it } from 'vitest';
import { emitDef, flattenObject, leafParam, newBudget, newCtx, withTrait, type Ctx, type DraftSpec, type ImportOpts } from '../src/import/common';

const mk = (over: Partial<ImportOpts> = {}, root: unknown = {}): Ctx => newCtx('openapi', root, { ns: 't', ...over });
const lp = (s: Record<string, unknown>, required = true, c: Ctx = mk()) => {
  const p = leafParam(s as never, required, c, newBudget(c), 'w');
  return { p, todo: c.todo };
};
const flat = (schema: unknown, opts: { forceRequired?: ReadonlySet<string> } = {}) => {
  const c = mk();
  const out: Record<string, unknown> = {};
  flattenObject(schema as never, c, newBudget(c), 'w', out as never, opts);
  return { out, todo: c.todo };
};
const draft = (over: Partial<DraftSpec> = {}): DraftSpec => ({ name: 'createThing', effects: ['create'], scope: 'one', params: {}, bindings: {}, ...over });

describe('leafParam members and bounds', () => {
  it('lists members in a fixed order', () => {
    expect(Object.keys(lp({ type: 'integer', description: 'd', minimum: 1 }, false).p)).toEqual(['type', 'required', 'description', 'min']);
  });
  it('keeps a zero bound and drops a negative zero', () => {
    expect(lp({ type: 'integer', minimum: 0, maximum: 0 }).p).toEqual({ type: 'integer', min: 0, max: 0 });
    expect(lp({ type: 'integer', minimum: -0, maximum: -0 }).p).toEqual({ type: 'integer' });
  });
  it('ignores an exclusive flag that has no bound to apply to', () => {
    expect(lp({ type: 'integer', exclusiveMinimum: true }).p).toEqual({ type: 'integer' });
    expect(lp({ type: 'integer', exclusiveMaximum: true }).p).toEqual({ type: 'integer' });
  });
  it('treats int32 and int64 formats as integers on numbers only', () => {
    const table: [string, string, string][] = [
      ['string', 'int32', 'string'], ['string', 'int64', 'string'],
      ['boolean', 'int32', 'boolean'], ['boolean', 'int64', 'boolean'],
      ['object', 'int32', 'string'], ['object', 'int64', 'string'],
    ];
    for (const [type, format, want] of table) expect(lp({ type, format }).p, `${type} ${format}`).toEqual({ type: want });
  });
  it('ignores a format that is not a string', () => {
    expect(lp({ type: 'string', format: ['email'] }).p).toEqual({ type: 'string' });
  });
  it('notes what resolving the array items found, at the item position', () => {
    const r = lp({ type: 'array', items: { $ref: '#/nope' } });
    expect(r.p).toEqual({ type: 'array' });
    expect(r.todo).toEqual([{ where: 'w[]', code: 'unresolved_ref', message: "reference '#/nope' is not a local reference that resolves (declared string; refine or drop)" }]);
  });
});

describe('flattenObject details', () => {
  it('notes a child it cannot resolve and its placeholder at the child position', () => {
    const r = flat({ properties: { p: { $ref: '#/nope' } } });
    expect(r.out).toEqual({ p: { type: 'string', required: false } });
    expect(r.todo).toEqual([
      { where: 'w: p', code: 'unresolved_ref', message: "reference '#/nope' is not a local reference that resolves (declared string; refine or drop)" },
      { where: 'w: p', code: 'unsupported_type', message: "type 'none' has no representation (declared string; refine or drop)" },
    ]);
  });
  it('flattens an untyped schema that has properties, and keeps a typed non-object as a leaf', () => {
    const r = flat({ properties: { o: { properties: { x: { type: 'integer' } } } } });
    expect(r.out).toEqual({ 'o.x': { type: 'integer', required: false } });
    expect(r.todo).toEqual([]);
    const r2 = flat({ properties: { s: { type: 'string', properties: { x: { type: 'integer' } } } } });
    expect(r2.out).toEqual({ s: { type: 'string', required: false } });
    expect(r2.todo).toEqual([]);
  });
  it('declares an object with empty properties as a placeholder', () => {
    const r = flat({ properties: { e: { type: 'object', properties: {} } }, required: ['e'] });
    expect(r.out).toEqual({ e: { type: 'string' } });
    expect(r.todo).toEqual([{ where: 'w: e', code: 'object_leaf', message: 'an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)' }]);
  });
  it('carries the nested position into the notes of a nested leaf', () => {
    const r = flat({ properties: { n: { type: 'object', properties: { x: { type: 'number' } } } }, required: ['n'] });
    expect(r.out).toEqual({ 'n.x': { type: 'string', required: false } });
    expect(r.todo).toEqual([{ where: 'w: n: n.x', code: 'unsupported_type', message: "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)" }]);
  });
  it('requires a name seeded in forceRequired', () => {
    const r = flat({ properties: { a: { type: 'string' }, b: { type: 'string' } } }, { forceRequired: new Set(['a']) });
    expect(r.out).toEqual({ a: { type: 'string' }, b: { type: 'string', required: false } });
  });
  it('does not treat a missing required list as naming any property', () => {
    const r = flat({ properties: { 'Stryker was here': { type: 'string' } } });
    expect(r.out).toEqual({ Stryker_was_here: { type: 'string', required: false } });
    expect(r.todo).toEqual([{ where: 'w: Stryker was here', code: 'renamed_param', message: "parameter 'Stryker was here' is declared as 'Stryker_was_here'" }]);
  });
  it('collides only on a dotted prefix, not on a plain string prefix', () => {
    const r = flat({ properties: { 'a!b': { type: 'string' }, a_: { type: 'string' } } });
    expect(r.out).toEqual({ a_b: { type: 'string', required: false }, a_: { type: 'string', required: false } });
    expect(r.todo).toEqual([{ where: 'w: a!b', code: 'renamed_param', message: "parameter 'a!b' is declared as 'a_b'" }]);
  });
});

describe('emitDef assembly', () => {
  it('derives the resource type and drops an alias an earlier def took', () => {
    const c = mk({ ns: 'abc' });
    const d1 = emitDef(c, draft());
    expect(d1?.verb).toBe('abc.thing.create');
    expect(d1?.resource.type).toBe('abc.thing');
    expect(d1?.aliases).toEqual(['create_thing']);
    const d2 = emitDef(c, draft());
    expect(d2?.verb).toBe('abc.thing.create_2');
    expect(d2?.resource.type).toBe('abc.thing');
    expect(d2?.aliases).toBeUndefined();
  });
  it('uses every segment but the last as the resource type', () => {
    const table: [string, string][] = [['abc.go', 'abc'], ['abc.thing.go', 'abc.thing'], ['abc.a.b.c', 'abc.a.b'], ['abc.a.b.c.d.e', 'abc.a.b.c.d']];
    for (const [verb, want] of table) {
      const d = emitDef(mk({ ns: 'abc' }), draft({ name: 'x', verb }));
      expect(d?.verb, verb).toBe(verb);
      expect(d?.resource.type, verb).toBe(want);
    }
  });
  it('carries the idempotency declaration', () => {
    expect(emitDef(mk(), draft({ idempotency: { mode: 'natural' } }))?.idempotency).toEqual({ mode: 'natural' });
  });
  it('sorts and dedupes traits, and omits an empty list', () => {
    expect(emitDef(mk(), draft({ traits: ['pca.network_egress', 'pca.bulk', 'pca.network_egress'] }))?.traits).toEqual(['pca.bulk', 'pca.network_egress']);
    const empty = emitDef(mk(), draft({ traits: [] }));
    expect(empty?.verb).toBe('t.thing.create');
    expect(empty?.traits).toBeUndefined();
    const none = emitDef(mk(), draft());
    expect(none?.verb).toBe('t.thing.create');
    expect(none?.traits).toBeUndefined();
  });
});

describe('withTrait', () => {
  it('adds a trait once, keeping the given order', () => {
    expect(withTrait(undefined, 'a')).toEqual(['a']);
    expect(withTrait(['b'], 'a')).toEqual(['b', 'a']);
    expect(withTrait(['a', 'b'], 'a')).toEqual(['a', 'b']);
  });
});
