// Exact outcomes of the shared importer helpers that the behaviour tests left open: parameter-name hygiene, the enum rules of a string
// and of an array item, bounds written as exclusive flags, object flattening and the resource type and aliases of an emitted def.
import { describe, expect, it } from 'vitest';
import { emitDef, flattenObject, leafParam, newBudget, newCtx, paramSeg, type Ctx, type DraftSpec, type ImportOpts } from '../src/import/common';

const mk = (over: Partial<ImportOpts> = {}): Ctx => newCtx('openapi', {}, { ns: 't', ...over });
const lp = (s: Record<string, unknown>, required = true, c: Ctx = mk()) => {
  const p = leafParam(s as never, required, c, newBudget(c), 'w');
  return { p, todo: c.todo };
};
const flat = (schema: unknown, opts: Parameters<typeof flattenObject>[5] = {}, c: Ctx = mk()) => {
  const out: Record<string, unknown> = {};
  flattenObject(schema as never, c, newBudget(c), 'w', out as never, opts);
  return { out, todo: c.todo };
};
const codes = (todo: { code: string }[]): string[] => todo.map((t) => t.code);

describe('paramSeg', () => {
  it('only a name made of nothing but underscores becomes the placeholder; underscores at either end of a name stay', () => {
    expect(paramSeg('_ab_')).toBe('_ab_');
    expect(paramSeg('___')).toBe('p');
    expect(paramSeg('-')).toBe('p');
    expect(paramSeg('a-b')).toBe('a_b');
  });
});

describe('leafParam: an enum of strings', () => {
  const many = (n: number): string[] => Array.from({ length: n }, (_, i) => `v${i}`);
  it('an empty enum is no enum', () => {
    const r = lp({ type: 'string', enum: [] });
    expect(r.p).toEqual({ type: 'string' });
    expect(r.p).not.toHaveProperty('values');
    expect(r.todo).toEqual([]);
  });
  it('takes 256 values and refuses 257, noting the drop', () => {
    expect(lp({ type: 'string', enum: many(256) }).p.values).toHaveLength(256);
    const over = lp({ type: 'string', enum: many(257) });
    expect(over.p).toEqual({ type: 'string' });
    expect(codes(over.todo)).toEqual(['enum_dropped']);
  });
  it('takes a value of 256 bytes and refuses 257', () => {
    expect(lp({ type: 'string', enum: ['x'.repeat(256)] }).p.values).toEqual(['x'.repeat(256)]);
    expect(lp({ type: 'string', enum: ['x'.repeat(257)] }).p.values).toBeUndefined();
  });
  it('every value must be a non-empty NFC string: one that is not drops the whole enum, never throws', () => {
    for (const bad of [['a', 1], [''], ['é'], [['a']], ['a', ['b']]]) {
      const r = lp({ type: 'string', enum: bad });
      expect(r.p, JSON.stringify(bad)).toEqual({ type: 'string' });
      expect(codes(r.todo), JSON.stringify(bad)).toEqual(['enum_dropped']);
    }
  });
});

describe('leafParam: array items', () => {
  it('a unique array of an enum is a set of its values', () => {
    expect(lp({ type: 'array', uniqueItems: true, items: { enum: ['a', 'b'] } }).p).toEqual({ type: 'set', values: ['a', 'b'] });
  });
  it('an item enum with a value that is not a string is no enum, and never throws', () => {
    const r = lp({ type: 'array', uniqueItems: true, items: { enum: [['a']] } });
    expect(r.p).toEqual({ type: 'array' });
    expect(r.todo).toEqual([]);
  });
  it('problems inside the items are reported under the array name with []', () => {
    const r = lp({ type: 'array', items: { $ref: '#/nope' } });
    expect(r.todo).toEqual([{ where: 'w[]', code: 'unresolved_ref', message: expect.stringContaining("'#/nope'") }]);
  });
});

describe('leafParam: types, bounds and roles', () => {
  it('a string that carries an integer format stays a string', () => {
    expect(lp({ type: 'string', format: 'int32' }).p).toEqual({ type: 'string' });
  });
  it('an exclusive flag with no bound beside it sets no bound', () => {
    expect(lp({ type: 'integer', exclusiveMinimum: true }).p).toEqual({ type: 'integer' });
    expect(lp({ type: 'integer', exclusiveMaximum: true }).p).toEqual({ type: 'integer' });
  });
  it('one bound alone is kept', () => {
    expect(lp({ type: 'integer', minimum: 1 }).p).toEqual({ type: 'integer', min: 1 });
    expect(lp({ type: 'integer', maximum: 9 }).p).toEqual({ type: 'integer', max: 9 });
  });
  it('a role that is not a string is ignored without a note', () => {
    const r = lp({ type: 'string', 'x-pca-role': 5 }, true, mk({ allowExtensions: ['x-pca-role'] }));
    expect(r.p).toEqual({ type: 'string' });
    expect(r.todo).toEqual([]);
  });
});

describe('flattenObject', () => {
  it('an object schema with properties and no type is an object: its properties are flattened under its name', () => {
    expect(flat({ properties: { a: { properties: { x: { type: 'string' } } } } }).out).toEqual({ 'a.x': { type: 'string', required: false } });
  });
  it('a typed non-object is a leaf even when it carries properties', () => {
    const r = flat({ properties: { a: { type: 'string', properties: { x: { type: 'string' } } } } });
    expect(r.out).toEqual({ a: { type: 'string', required: false } });
    expect(r.todo).toEqual([]);
  });
  it('an object with no properties is a placeholder string, noted', () => {
    const r = flat({ properties: { a: { type: 'object', properties: {} } } });
    expect(r.out).toEqual({ a: { type: 'string', required: false } });
    expect(codes(r.todo)).toEqual(['object_leaf']);
  });
  it('a forced-required name is required without being listed', () => {
    expect(flat({ properties: { a: { type: 'string' } } }, { forceRequired: new Set(['a']) }).out).toEqual({ a: { type: 'string' } });
    expect(flat({ properties: { a: { type: 'string' } } }).out).toEqual({ a: { type: 'string', required: false } });
  });
  it('a name that merely begins with another is not a collision', () => {
    const r = flat({ properties: { a: { type: 'string' }, ab: { type: 'string' } } });
    expect(Object.keys(r.out)).toEqual(['a', 'ab']);
    expect(r.todo).toEqual([]);
  });
  it('without a required list nothing is required, whatever a property is called', () => {
    expect(flat({ properties: { 'Stryker was here': { type: 'string' } } }).out).toEqual({ Stryker_was_here: { type: 'string', required: false } });
  });
  it('a problem inside a property is reported under the property name', () => {
    const r = flat({ properties: { a: { $ref: '#/nope' } } });
    expect(r.todo.find((t) => t.code === 'unresolved_ref')?.where).toBe('w: a');
  });
});

describe('emitDef', () => {
  const spec = (over: Partial<DraftSpec> = {}): DraftSpec => ({ name: 'createThing', effects: ['create'], scope: 'one', params: {}, bindings: {}, ...over });
  it('the resource type is the verb without its last segment', () => {
    const c = mk();
    expect(emitDef(c, spec({ verb: 'acme.pay.send' }))?.resource.type).toBe('acme.pay');
    expect(emitDef(c, spec({ name: 'two', verb: 'acme.a.b.send' }))?.resource.type).toBe('acme.a.b');
  });
  it('an empty trait list adds no traits; the traits given are unique and sorted', () => {
    const c = mk();
    expect(emitDef(c, spec({ name: 'one', verb: 'acme.pay.one', traits: [] }))).not.toHaveProperty('traits');
    expect(emitDef(c, spec({ name: 'two', verb: 'acme.pay.two', traits: ['pca.pii_access', 'pca.bulk', 'pca.bulk'] }))?.traits).toEqual(['pca.bulk', 'pca.pii_access']);
  });
  it('an alias is given to the first def that owns it and to no later one', () => {
    const c = mk();
    const first = emitDef(c, spec());
    const second = emitDef(c, spec());
    expect(first?.aliases).toEqual(['create_thing']);
    expect(second).toBeDefined();
    expect(second).not.toHaveProperty('aliases');
    expect(c.aliases.get('create_thing')).toBe(first?.verb);
  });
});

describe('flattenObject: names that are prefixes after renaming', () => {
  it('a renamed name that another name begins with is not a collision with it', () => {
    // 'a-b' sorts before 'a_' and is declared as 'a_b', which begins with 'a_'
    const r = flat({ properties: { 'a-b': { type: 'string' }, a_: { type: 'string' } } });
    expect(Object.keys(r.out)).toEqual(['a_b', 'a_']);
    expect(codes(r.todo)).toEqual(['renamed_param']);
  });
});
