// Behaviour tests for the importers' shared helpers: context, text hygiene, verb naming, `$ref` resolution, schema flattening.
import { b64u, hashCanonicalLenient, sha256, utf8 } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { ActionKitError } from '../src';
import {
  addTodo, aliasOf, clip, emitDef, firstText, flattenObject, humanize, leafParam, newBudget, newCtx, paramSeg, pointer, resolveSchema, tokensOf,
  uniqueVerb, verbOf, type Ctx, type ImportOpts,
} from '../src/import/common';

const mk = (over: Partial<ImportOpts> = {}, root: unknown = {}): Ctx => newCtx('openapi', root, { ns: 't', ...over });
const err = (f: () => unknown): { code: string; message: string } => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(ActionKitError);
    return { code: (e as ActionKitError).code, message: (e as Error).message };
  }
  throw new Error('did not throw');
};
const lp = (s: Record<string, unknown>, required = true, c: Ctx = mk()) => {
  const p = leafParam(s as never, required, c, newBudget(c), 'w');
  return { p, todo: c.todo };
};
const rs = (s: unknown, c: Ctx = mk(), where = 'w') => resolveSchema(s, c, newBudget(c), where);

describe('newCtx', () => {
  it('refuses a bad namespace with the exact code and message', () => {
    const want = { code: 'bad_ns', message: 'ns must match [a-z][a-z0-9_]{0,31}' };
    expect(err(() => newCtx('openapi', {}, { ns: 'Bad' }))).toEqual(want);
    expect(err(() => newCtx('openapi', {}, undefined as never))).toEqual(want);
    expect(err(() => newCtx('openapi', {}, { ns: ['abc'] as never }))).toEqual(want);
  });
  it('bounds a byte source at the limit and digests each source kind', () => {
    const lim = { max_bytes: 10 };
    expect(err(() => mk({ limits: lim }, new Uint8Array(11)))).toEqual({ code: 'import_limit', message: 'the source is larger than 10 bytes' });
    const ten = new Uint8Array(10).fill(7);
    expect(mk({ limits: lim }, ten).source.spec_digest).toBe(b64u(sha256(ten)));
    expect(mk({}, 'hello').source.spec_digest).toBe(b64u(sha256(utf8('hello'))));
    const obj = { a: [1, 2], b: 'x' };
    expect(mk({}, obj).source.spec_digest).toBe(hashCanonicalLenient(obj));
  });
  it('validates now and records source defaults', () => {
    const want = { code: 'bad_opts', message: 'now must be a non-negative integer' };
    for (const now of [-1, 1.5, Number.NaN, 2 ** 60]) expect(err(() => mk({ now }))).toEqual(want);
    expect(mk({ now: 0 }).source.imported_at).toBe(0);
    expect(mk({ now: 5 }).source.imported_at).toBe(5);
    const c = mk();
    expect(c.source).toMatchObject({ kind: 'openapi', uri: 'source:openapi', licence: 'unknown', imported_at: 0 });
  });
});

describe('addTodo', () => {
  it('keeps the first 5000 notes and one sentinel', () => {
    const c = mk();
    for (let i = 0; i < 5003; i++) addTodo(c, `w${i}`, 'k', 'm');
    expect(c.todo.length).toBe(5001);
    expect(c.todo[4999]).toEqual({ where: 'w4999', code: 'k', message: 'm' });
    expect(c.todo[5000]).toEqual({ where: '*', code: 'todo_truncated', message: 'further notes omitted' });
  });
});

describe('clip and firstText', () => {
  it('cleans text', () => {
    expect(clip(5, 10)).toBe('');
    expect(clip(undefined, 10)).toBe('');
    expect(clip('  a \n b  ', 100)).toBe('a b');
    expect(clip('a\uD800b\uDC00c', 100)).toBe('abc');
    expect(clip('a\u0001b‮c', 100)).toBe('a b c');
    expect(clip('é', 10)).toBe('é');
  });
  it('cuts at a code point within the byte budget', () => {
    expect(clip('abcdef', 3)).toBe('abc');
    expect(clip('abc', 3)).toBe('abc');
    expect(clip('ab cd', 3)).toBe('ab');
    expect(clip('€€', 5)).toBe('€');
    expect(clip('€€', 6)).toBe('€€');
    expect(clip('a\u{1F600}', 4)).toBe('a');
    expect(clip('a\u{1F600}', 5)).toBe('a\u{1F600}');
  });
  it('firstText takes the first non-empty candidate', () => {
    expect(firstText(5, undefined, '', '  ', 'abc', 'zzz')).toBe('abc');
    expect(firstText(5, undefined, '', '  ')).toBe('');
    expect(firstText(5)).toBe('');
  });
});

describe('tokensOf, verbOf, aliasOf, humanize', () => {
  it('tokenises names', () => {
    expect(tokensOf('createCustomer')).toEqual(['create', 'customer']);
    expect(tokensOf('HTTPServer')).toEqual(['http', 'server']);
    expect(tokensOf('snake_case-kebab.dot/slash')).toEqual(['snake', 'case', 'kebab', 'dot', 'slash']);
    expect(tokensOf('café')).toEqual(['cafe']);
    expect(tokensOf('v2Beta')).toEqual(['v2', 'beta']);
  });
  it('builds verbs', () => {
    const table: [string, string][] = [
      ['createCustomer', 't.customer.create'],
      ['customer_delete', 't.customer.delete'],
      ['listUsers', 't.users.list'],
      ['users.list', 't.users.list'],
      ['a/b:c d', 't.a.b.c.d'],
      ['getUserById', 't.user_by_id.get'],
      ['customerOrderDelete', 't.customer_order.delete'],
      ['delete', 't.delete'],
      ['create', 't.create'],
      ['foo', 't.foo'],
      ['.create', 't.create'],
      ['!!!', 't.op'],
      ['', 't.op'],
      ['a.b.c.d.e', 't.a.b.c.d.e'],
      ['a.b.c.d.e.f', 't.a.b.d.e.f'],
      ['a.b.c.d.e.f.g', 't.a.b.e.f.g'],
    ];
    for (const [raw, want] of table) expect(verbOf('t', raw), raw).toBe(want);
  });
  it('falls back to <ns>.op when the verb is malformed or too long', () => {
    expect(verbOf('T', 'foo')).toBe('T.op');
    const seg = (ch: string, n: number) => ch.repeat(n);
    expect(verbOf('t', [seg('a', 32), seg('b', 32), seg('c', 32), seg('d', 27)].join('.'))).toBe(`t.${seg('a', 32)}.${seg('b', 32)}.${seg('c', 32)}.${seg('d', 27)}`);
    expect(verbOf('t', [seg('a', 32), seg('b', 32), seg('c', 32), seg('d', 28)].join('.'))).toBe('t.op');
    expect(verbOf('t', [seg('a', 32), seg('b', 32), seg('c', 32), seg('d', 32), seg('e', 32)].join('.'))).toBe('t.op');
  });
  it('shortens a long segment deterministically', () => {
    expect(verbOf('t', 'a'.repeat(32))).toBe(`t.${'a'.repeat(32)}`);
    for (let i = 0; i < 40; i++) {
      const s = `x${i}${'b'.repeat(40)}`;
      const h = b64u(sha256(utf8(s))).replace(/[^a-z0-9]/gi, '').toLowerCase().slice(0, 4);
      expect(verbOf('t', s)).toBe(`t.${s.slice(0, 27)}_${h}`);
    }
    const s33 = 'a'.repeat(33);
    const h33 = b64u(sha256(utf8(s33))).replace(/[^a-z0-9]/gi, '').toLowerCase().slice(0, 4);
    expect(verbOf('t', s33)).toBe(`t.${'a'.repeat(27)}_${h33}`);
  });
  it('derives aliases', () => {
    expect(aliasOf('createCustomer', 't.customer.create')).toBe('create_customer');
    expect(aliasOf('foo', 'bar')).toBe('foo');
    expect(aliasOf('foo', 'foo')).toBeUndefined();
    expect(aliasOf('!!!', 'x')).toBeUndefined();
    expect(aliasOf('9lives', 'x')).toBeUndefined();
    expect(aliasOf('a'.repeat(33), 'x')).toBeUndefined();
    expect(aliasOf('a'.repeat(32), 'x')).toBe('a'.repeat(32));
  });
  it('humanizes', () => {
    expect(humanize('createCustomer')).toBe('Create customer');
    expect(humanize('createCustomerAccount')).toBe('Create customer account');
    expect(humanize('create')).toBe('Create');
    expect(humanize('!!!')).toBe('');
    expect(humanize('')).toBe('');
  });
});

describe('uniqueVerb', () => {
  it('keeps a free verb and suffixes a taken one', () => {
    const c = mk();
    expect(uniqueVerb(c, 't.a.b', 'w')).toBe('t.a.b');
    expect(c.todo).toEqual([]);
    c.verbs.add('t.a.b');
    expect(uniqueVerb(c, 't.a.b', 'w')).toBe('t.a.b_2');
    expect(c.todo).toEqual([{ where: 'w', code: 'duplicate_verb', message: "verb 't.a.b' is taken by an earlier operation; this one is 't.a.b_2'" }]);
    c.verbs.add('t.a.b_2');
    expect(uniqueVerb(c, 't.a.b', 'w2')).toBe('t.a.b_3');
  });
  it('trims the last segment to fit the suffix', () => {
    const c = mk();
    const verb = `t.${'a'.repeat(32)}`;
    c.verbs.add(verb);
    expect(uniqueVerb(c, verb, 'w')).toBe(`t.${'a'.repeat(30)}_2`);
  });
  it('gives up after 100000 suffixes', () => {
    const c = mk();
    c.verbs.add('t.a.b');
    for (let n = 2; n < 100_000; n++) c.verbs.add(`t.a.b_${n}`);
    expect(err(() => uniqueVerb(c, 't.a.b', 'w'))).toEqual({ code: 'import_limit', message: 'too many operations map to one verb' });
  });
});

describe('pointer', () => {
  it('follows local pointers', () => {
    const root = { a: { b: { c: 1 } }, 'x/y': { 'p~q': { z: 1 } }, 'a b': { k: 1 }, '%zz': { m: 1 }, list: [{ x: 1 }], s: 'str', n: null, five: 5 };
    expect(pointer(root, '#/a/b')).toEqual({ c: 1 });
    expect(pointer(root, '#/a/b/c')).toBeUndefined();
    expect(pointer(root, '#/a/missing')).toBeUndefined();
    expect(pointer(root, '#/x~1y/p~0q')).toEqual({ z: 1 });
    expect(pointer(root, '#/a%20b')).toEqual({ k: 1 });
    expect(pointer(root, '#/%zz')).toEqual({ m: 1 });
    expect(pointer(root, '#/list/0')).toEqual({ x: 1 });
    expect(pointer(root, '#/s/length')).toBeUndefined();
    expect(pointer(root, '#/n/x')).toBeUndefined();
    expect(pointer(root, '#/n')).toBeUndefined();
    expect(pointer(root, '#/five')).toBeUndefined();
    expect(pointer(root, '#/__proto__')).toBeUndefined();
  });
  it('refuses non-local references', () => {
    const root = { a: { b: 1 } };
    expect(pointer(root, 5 as never)).toBeUndefined();
    expect(pointer(root, 'xxa')).toBeUndefined();
    expect(pointer(root, '/a')).toBeUndefined();
    expect(pointer(root, 'other.json#/a')).toBeUndefined();
  });
});

describe('resolveSchema', () => {
  it('ignores non-objects', () => {
    expect(rs('x')).toEqual({});
    expect(rs([])).toEqual({});
    expect(rs(null)).toEqual({});
  });
  it('stops when the budget is spent, noting it once', () => {
    const c = mk({ limits: { max_ref_nodes: 3 } });
    const bud = { left: 0, exhausted: false };
    expect(resolveSchema({ type: 'string' }, c, bud, 'w')).toEqual({});
    expect(resolveSchema({ type: 'string' }, c, bud, 'w')).toEqual({});
    expect(bud.exhausted).toBe(true);
    expect(c.todo).toEqual([{ where: 'w', code: 'ref_budget', message: 'schema expansion stopped after 3 nodes (declared string; refine or drop)' }]);
    const c2 = mk({ limits: { max_ref_nodes: 3 } });
    const out = rs({ allOf: [{ description: 'a' }, { description: 'b' }, { description: 'c' }] }, c2);
    expect(out).toEqual({ description: 'b', properties: {}, required: [] });
    expect(c2.todo.length).toBe(1);
  });
  it('bounds nesting and reference chains by depth', () => {
    const c = mk({ limits: { max_ref_depth: 1 } });
    expect(rs({ allOf: [{ type: 'string' }] }, c)).toEqual({ type: 'string', properties: {}, required: [] });
    expect(c.todo).toEqual([]);
    const msg = 'schema nesting or reference chain deeper than 1 (declared string; refine or drop)';
    const c2 = mk({ limits: { max_ref_depth: 1 } });
    expect(rs({ allOf: [{ allOf: [{ type: 'string' }] }] }, c2)).toEqual({ properties: {}, required: [] });
    expect(c2.todo).toEqual([{ where: 'w', code: 'ref_depth', message: msg }]);
    const c3 = mk({ limits: { max_ref_depth: 1 } });
    expect(rs({ anyOf: [{ anyOf: [{ type: 'string' }] }] }, c3)).toEqual({});
    expect(c3.todo).toEqual([{ where: 'w', code: 'ref_depth', message: msg }]);
    const c4 = mk({ limits: { max_ref_depth: 1 } }, { A: { $ref: '#/B' }, B: { type: 'string' } });
    expect(rs({ $ref: '#/A' }, c4)).toEqual({});
    expect(c4.todo).toEqual([{ where: 'w', code: 'ref_depth', message: msg }]);
  });
  it('follows a reference and lets siblings win', () => {
    const c = mk({}, { D: { type: 'string', description: 't' } });
    expect(rs({ $ref: '#/D', description: 'override', maxLength: 3 }, c)).toEqual({ type: 'string', description: 'override', maxLength: 3 });
    expect(c.todo).toEqual([]);
  });
  it('notes a cyclic reference', () => {
    const c = mk({}, { A: { $ref: '#/A' }, B: { $ref: '#/C' }, C: { $ref: '#/B' } });
    expect(rs({ $ref: '#/A' }, c)).toEqual({});
    expect(c.todo).toEqual([{ where: 'w', code: 'cyclic_ref', message: "reference '#/A' is cyclic (declared string; refine or drop)" }]);
    const c2 = mk({}, { B: { $ref: '#/C' }, C: { $ref: '#/B' } });
    expect(rs({ $ref: '#/B' }, c2)).toEqual({});
    expect(c2.todo.map((t) => t.code)).toEqual(['cyclic_ref']);
  });
  it('notes an unresolved reference', () => {
    for (const ref of ['other.json#/x', '#/nope', 'Stryker was here']) {
      const c = mk({}, { s: 'text' });
      expect(rs({ $ref: ref }, c)).toEqual({});
      expect(c.todo).toEqual([{ where: 'w', code: 'unresolved_ref', message: `reference '${ref}' is not a local reference that resolves (declared string; refine or drop)` }]);
    }
    const c = mk({}, { s: 'text' });
    expect(rs({ $ref: '#/s' }, c)).toEqual({});
    expect(c.todo.map((t) => t.code)).toEqual(['unresolved_ref']);
  });
  it('merges allOf', () => {
    const out = rs({
      type: 'object',
      allOf: [
        { properties: { a: { type: 'string' } }, required: ['a'] },
        { properties: { b: { type: 'integer' } }, required: ['b'], description: 'd' },
        { maxLength: 5 },
      ],
    });
    expect(out).toEqual({ type: 'object', description: 'd', maxLength: 5, properties: { a: { type: 'string' }, b: { type: 'integer' } }, required: ['a', 'b'] });
    expect(rs({ allOf: [] })).toEqual({});
  });
  it('collapses a nullable alternative', () => {
    expect(rs({ anyOf: [{ type: 'string', maxLength: 3 }, { type: 'null' }], description: 'd' })).toEqual({ type: 'string', maxLength: 3, description: 'd' });
    expect(rs({ oneOf: [{ type: 'integer' }, { type: 'null' }] })).toEqual({ type: 'integer' });
    expect(rs({ anyOf: [{ type: ['null'] }, { type: 'integer' }] })).toEqual({ type: 'integer' });
    expect(rs({ anyOf: [{ type: ['null', 'null'] }, { type: 'string' }] })).toEqual({ type: 'string' });
    expect(rs({ anyOf: [{ type: ['string', 'null'] }, { type: 'null' }] })).toEqual({ type: ['string', 'null'] });
    expect(rs({ anyOf: [{ type: [] }, { type: 'null' }] })).toEqual({ type: [] });
  });
  it('merges string constants and enums into one enum', () => {
    expect(rs({ anyOf: [{ const: 'a' }, { const: 'b' }] })).toEqual({ type: 'string', enum: ['a', 'b'] });
    expect(rs({ oneOf: [{ const: 'a' }, { enum: ['b', 'a'] }], description: 'd' })).toEqual({ type: 'string', enum: ['a', 'b'], description: 'd' });
  });
  it('notes a union it cannot represent', () => {
    const cases: [unknown, number, Record<string, unknown>][] = [
      [{ anyOf: [{ const: 'a' }, { type: 'integer' }], description: 'd' }, 2, { description: 'd' }],
      [{ anyOf: [{ enum: ['a', 1] }, { const: 'b' }] }, 2, {}],
      [{ anyOf: [{ type: 'string' }, { type: 'integer' }] }, 2, {}],
      [{ anyOf: [{ type: 'null' }] }, 0, {}],
    ];
    for (const [schema, n, want] of cases) {
      const c = mk();
      expect(rs(schema, c)).toEqual(want);
      expect(c.todo).toEqual([{ where: 'w', code: 'union', message: `a union of ${n} schemas has no representation (declared string; refine or drop)` }]);
    }
  });
  it('turns a string const into an enum', () => {
    expect(rs({ const: 'x', type: 'string' })).toEqual({ const: 'x', type: 'string', enum: ['x'] });
    expect(rs({ const: 5 })).toEqual({ const: 5 });
    expect(rs({ const: 'x', enum: ['y'] })).toEqual({ const: 'x', enum: ['y'] });
    expect(rs({ enum: ['a'] })).toEqual({ enum: ['a'] });
  });
});

describe('paramSeg', () => {
  it('cleans names', () => {
    expect(paramSeg('a-b c')).toBe('a_b_c');
    expect(paramSeg('')).toBe('p');
    expect(paramSeg('___')).toBe('p');
    expect(paramSeg('$')).toBe('p');
    expect(paramSeg('x'.repeat(70))).toBe('x'.repeat(64));
    expect(paramSeg('ok_1')).toBe('ok_1');
  });
});

describe('leafParam', () => {
  it('maps integers and their bounds', () => {
    expect(lp({ type: 'integer' }).p).toEqual({ type: 'integer' });
    expect(lp({ type: 'integer' }, false).p).toEqual({ type: 'integer', required: false });
    expect(lp({ type: 'integer', description: ' d  e ' }).p).toEqual({ type: 'integer', description: 'd e' });
    expect(lp({ type: 'integer', minimum: 1, maximum: 5 }).p).toEqual({ type: 'integer', min: 1, max: 5 });
    expect(lp({ type: 'integer', exclusiveMinimum: 4, exclusiveMaximum: 10 }).p).toEqual({ type: 'integer', min: 5, max: 9 });
    expect(lp({ type: 'integer', minimum: 4, exclusiveMinimum: true, maximum: 10, exclusiveMaximum: true }).p).toEqual({ type: 'integer', min: 5, max: 9 });
    expect(lp({ type: 'integer', minimum: 4, exclusiveMinimum: false, maximum: 10, exclusiveMaximum: false }).p).toEqual({ type: 'integer', min: 4, max: 10 });
    expect(lp({ type: 'integer', minimum: 5, maximum: 3 }).p).toEqual({ type: 'integer' });
    expect(lp({ type: 'integer', minimum: 3, maximum: 3 }).p).toEqual({ type: 'integer', min: 3, max: 3 });
    expect(lp({ type: 'integer', minimum: 1.5 }).p).toEqual({ type: 'integer' });
  });
  it('treats int32/int64 numbers as integers and other numbers as unsupported', () => {
    expect(lp({ type: 'number', format: 'int32' }).p).toEqual({ type: 'integer' });
    expect(lp({ type: 'number', format: 'int64' }).p).toEqual({ type: 'integer' });
    for (const s of [{ type: 'number' }, { type: 'number', format: 'float' }]) {
      const r = lp(s);
      expect(r.p).toEqual({ type: 'string' });
      expect(r.todo).toEqual([{ where: 'w', code: 'unsupported_type', message: "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)" }]);
    }
  });
  it('reads the first non-null type of a type list', () => {
    expect(lp({ type: ['null', 'integer'] }).p).toEqual({ type: 'integer' });
    expect(lp({ type: ['integer', 'null'] }).p).toEqual({ type: 'integer' });
    expect(lp({ type: ['null', 'boolean'] }).p).toEqual({ type: 'boolean' });
  });
  it('maps strings', () => {
    expect(lp({ type: 'boolean' }).p).toEqual({ type: 'boolean' });
    expect(lp({ type: 'string', format: 'date' }).p).toEqual({ type: 'date' });
    expect(lp({ type: 'string', format: 'date-time' }).p).toEqual({ type: 'datetime' });
    expect(lp({ type: 'string', format: 'email' }).p).toEqual({ type: 'string', format: 'email' });
    expect(lp({ type: 'string', format: 'uri' }).p).toEqual({ type: 'string', format: 'url' });
    expect(lp({ type: 'string', format: 'idn-email' }).p).toEqual({ type: 'string', format: 'email' });
    expect(lp({ type: 'string', format: 'weird' }).p).toEqual({ type: 'string' });
    expect(lp({ type: 'string', format: 'toString' }).p).toEqual({ type: 'string' });
    expect(lp({ type: 'string', maxLength: 100 }).p).toEqual({ type: 'string', max_len: 100 });
    expect(lp({ type: 'string', maxLength: 0 }).p).toEqual({ type: 'string' });
    expect(lp({ type: 'string', maxLength: 16_777_216 }).p).toEqual({ type: 'string', max_len: 16_777_216 });
    expect(lp({ type: 'string', maxLength: 16_777_217 }).p).toEqual({ type: 'string' });
    expect(lp({ type: 'string', enum: ['a', 'b', 'a'] }).p).toEqual({ type: 'string', values: ['a', 'b'] });
    expect(lp({ enum: ['a', 'b'] }).p).toEqual({ type: 'string', values: ['a', 'b'] });
  });
  it('notes an enum it cannot keep', () => {
    const r = lp({ type: 'string', enum: [1, 2] });
    expect(r.p).toEqual({ type: 'string' });
    expect(r.todo).toEqual([{ where: 'w', code: 'enum_dropped', message: 'enum values are not 1..256 plain strings (declared as a free string; refine)' }]);
    expect(lp({ type: 'string', enum: [] }).todo).toEqual([]);
  });
  it('declares a set only for a unique, well-formed string enum of items', () => {
    const arr = (en: unknown[]) => lp({ type: 'array', items: { type: 'string', enum: en }, uniqueItems: true }).p;
    const e256 = Array.from({ length: 256 }, (_, i) => `e${i}`);
    expect(arr(['a', 'b', 'a'])).toEqual({ type: 'set', values: ['a', 'b'] });
    expect(arr(e256)).toEqual({ type: 'set', values: e256 });
    expect(arr(['a'.repeat(256)])).toEqual({ type: 'set', values: ['a'.repeat(256)] });
    const bad: unknown[][] = [[], [...e256, 'e256'], ['a', 1], ['a', ''], ['a'.repeat(257)], ['é'], ['\uD800'], ['a', '\uDC00']];
    for (const en of bad) expect(arr(en), JSON.stringify(en).slice(0, 40)).toEqual({ type: 'array', items: 'string' });
    expect(lp({ type: 'array', items: { type: 'string', enum: ['a'] } }).p).toEqual({ type: 'array', items: 'string' });
    expect(lp({ type: 'array', items: { type: 'string', enum: ['a'] }, uniqueItems: true, maxItems: 3, minItems: 1 }, false).p).toEqual({ type: 'set', values: ['a'], max_items: 3, min_items: 1, required: false });
  });
  it('bounds arrays', () => {
    expect(lp({ type: 'array', items: { type: 'string' } }).p).toEqual({ type: 'array', items: 'string' });
    expect(lp({ type: 'array', items: { type: 'string' }, maxItems: 5, minItems: 2 }).p).toEqual({ type: 'array', items: 'string', max_items: 5, min_items: 2 });
    expect(lp({ type: 'array', items: { type: 'string' }, maxItems: 0, minItems: 0 }).p).toEqual({ type: 'array', items: 'string', max_items: 0, min_items: 0 });
    expect(lp({ type: 'array', items: { type: 'string' }, maxItems: -1, minItems: -1 }).p).toEqual({ type: 'array', items: 'string' });
    expect(lp({ type: 'array', items: { type: 'string' }, maxItems: 3 }).p).toEqual({ type: 'array', items: 'string', max_items: 3 });
    expect(lp({ type: 'array', items: { type: 'string' }, minItems: 3 }).p).toEqual({ type: 'array', items: 'string', min_items: 3 });
    expect(lp({ type: 'array', items: { type: 'string' }, maxItems: 3, minItems: 5 }).p).toEqual({ type: 'array', items: 'string' });
    expect(lp({ type: 'array', items: { type: 'string' }, maxItems: 4, minItems: 4 }).p).toEqual({ type: 'array', items: 'string', max_items: 4, min_items: 4 });
    expect(lp({ type: 'array', items: { type: 'string' }, maxItems: 5, minItems: 2.5 }).p).toEqual({ type: 'array', items: 'string', max_items: 5 });
  });
  it('declares array item types and notes the rest', () => {
    for (const it of ['integer', 'string', 'boolean'] as const) {
      const r = lp({ type: 'array', items: { type: it } });
      expect(r.p).toEqual({ type: 'array', items: it });
      expect(r.todo).toEqual([]);
    }
    expect(lp({ type: 'array', items: { type: ['null', 'integer'] } }).p).toEqual({ type: 'array', items: 'integer' });
    expect(lp({ type: 'array', items: { type: ['integer', 'null'] } }).p).toEqual({ type: 'array', items: 'integer' });
    expect(lp({ type: 'array' }).todo).toEqual([]);
    expect(lp({ items: { type: 'string' } }).p).toEqual({ type: 'array', items: 'string' });
    expect(lp({ items: [{ type: 'string' }] }).p).toEqual({ type: 'array' });
    const r = lp({ type: 'array', items: { type: 'object' } });
    expect(r.p).toEqual({ type: 'array' });
    expect(r.todo).toEqual([{ where: 'w', code: 'array_items', message: "array items of type 'object' are not declared (items left open)" }]);
    const r2 = lp({ type: 'array', items: { type: 'number' } });
    expect(r2.todo).toEqual([{ where: 'w', code: 'array_items', message: "array items of type 'number' are not declared (items left open)" }]);
  });
  it('notes unsupported types', () => {
    const r = lp({ type: 'object' });
    expect(r.p).toEqual({ type: 'string' });
    expect(r.todo).toEqual([{ where: 'w', code: 'unsupported_type', message: "type 'object' has no representation (declared string; refine or drop)" }]);
    expect(lp({}).todo).toEqual([{ where: 'w', code: 'unsupported_type', message: "type 'none' has no representation (declared string; refine or drop)" }]);
    expect(lp({ type: 'x'.repeat(50) }).todo[0]!.message).toBe(`type '${'x'.repeat(40)}' has no representation (declared string; refine or drop)`);
    expect(lp({ type: 'null' }).todo[0]!.message).toBe("type 'null' has no representation (declared string; refine or drop)");
    expect(lp({ type: ['null'] }).todo[0]!.message).toBe("type 'none' has no representation (declared string; refine or drop)");
  });
  it('applies a valid x-pca-role and notes an invalid one', () => {
    const ok = ['contact.email', 'id.user', 'x.acme.thing', 'x.ab.cd', 'x.a.b.c', 'x.a.b.c.d'];
    for (const role of ok) expect(lp({ type: 'string', 'x-pca-role': role }).p, role).toEqual({ type: 'string', role });
    for (const role of ['bogus', 'x.ab', 'x.a.b.c.d.e', 'zx.a.b', 'x.Foo.bar', 'x.a.B']) {
      const r = lp({ type: 'string', 'x-pca-role': role });
      expect(r.p, role).toEqual({ type: 'string' });
      expect(r.todo, role).toEqual([{ where: 'w', code: 'role_ignored', message: `x-pca-role '${role}' is not valid for a string parameter` }]);
    }
    expect(lp({ type: 'integer', 'x-pca-role': 'money.amount' }).p).toEqual({ type: 'integer', role: 'money.amount' });
    const r = lp({ type: 'string', 'x-pca-role': 'count.limit' });
    expect(r.p).toEqual({ type: 'string' });
    expect(r.todo[0]!.message).toBe("x-pca-role 'count.limit' is not valid for a string parameter");
    expect(lp({ type: 'boolean', 'x-pca-role': 'contact.email' }).p).toEqual({ type: 'boolean', role: 'contact.email' });
    expect(lp({ type: 'string', 'x-pca-role': 5 }).p).toEqual({ type: 'string' });
    const c = mk({ allowExtensions: [] });
    expect(lp({ type: 'string', 'x-pca-role': 'contact.email' }, true, c)).toEqual({ p: { type: 'string' }, todo: [] });
  });
});

describe('flattenObject', () => {
  const flat = (schema: unknown, c: Ctx = mk()) => {
    const out: Record<string, never> = {};
    flattenObject(schema as never, c, newBudget(c), 'w', out as never);
    return { out, todo: c.todo };
  };
  it('flattens in sorted order and marks required', () => {
    const r = flat({ properties: { b: { type: 'string' }, a: { type: 'integer' } }, required: ['a'] });
    expect(Object.keys(r.out)).toEqual(['a', 'b']);
    expect(r.out).toEqual({ a: { type: 'integer' }, b: { type: 'string', required: false } });
  });
  it('drops reserved and read-only names', () => {
    const r = flat({ properties: { constructor: { type: 'string' }, prototype: { type: 'string' }, ro: { type: 'string', readOnly: true }, ok: { type: 'string' } }, required: ['ok'] });
    expect(r.out).toEqual({ ok: { type: 'string' } });
    expect(r.todo).toEqual([
      { where: 'w: constructor', code: 'skipped_param', message: "parameter name 'constructor' is reserved; dropped" },
      { where: 'w: prototype', code: 'skipped_param', message: "parameter name 'prototype' is reserved; dropped" },
    ]);
  });
  it('stops at the parameter limit', () => {
    const properties: Record<string, unknown> = {};
    for (let i = 0; i <= 64; i++) properties[`p${String(i).padStart(2, '0')}`] = { type: 'string' };
    const r = flat({ properties });
    expect(Object.keys(r.out).length).toBe(64);
    expect(r.todo).toEqual([{ where: 'w', code: 'too_many_params', message: "more than 64 parameters; 'p64' and the rest are dropped" }]);
  });
  it('keeps the first of two names that collide', () => {
    const r = flat({ properties: { 'a-b': { type: 'integer' }, a_b: { type: 'string' } } });
    expect(r.out).toEqual({ a_b: { type: 'integer', required: false } });
    expect(r.todo).toEqual([
      { where: 'w: a-b', code: 'renamed_param', message: "parameter 'a-b' is declared as 'a_b'" },
      { where: 'w: a_b', code: 'skipped_param', message: "parameter 'a_b' collides with another; kept the first" },
    ]);
  });
  it('keeps the first of a leaf and a nested path that collide', () => {
    const r = flat({ properties: { $: { type: 'string' }, p: { type: 'object', properties: { x: { type: 'integer' } } } } });
    expect(r.out).toEqual({ p: { type: 'string', required: false } });
    expect(r.todo).toEqual([
      { where: 'w: $', code: 'renamed_param', message: "parameter '$' is declared as 'p'" },
      { where: 'w: p: p.x', code: 'skipped_param', message: "parameter 'p.x' collides with another; kept the first" },
    ]);
    const r2 = flat({ properties: { $: { type: 'object', properties: { x: { type: 'integer' } } }, p: { type: 'string' } } });
    expect(r2.out).toEqual({ 'p.x': { type: 'integer', required: false } });
    expect(r2.todo).toEqual([
      { where: 'w: $', code: 'renamed_param', message: "parameter '$' is declared as 'p'" },
      { where: 'w: p', code: 'skipped_param', message: "parameter 'p' collides with another; kept the first" },
    ]);
  });
  it('nests objects and placeholders an object without properties', () => {
    const r = flat({ properties: { o: { type: 'object', description: 'd' }, n: { type: 'object', properties: { x: { type: 'integer' } } } }, required: ['o', 'n'] });
    expect(r.out).toEqual({ 'n.x': { type: 'integer', required: false }, o: { type: 'string', description: 'd' } });
    expect(r.todo).toEqual([{ where: 'w: o', code: 'object_leaf', message: 'an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)' }]);
  });
});

describe('emitDef', () => {
  const spec = (effects: string[]) => ({ name: 'createThing', effects: effects as never, scope: 'one' as const, params: {}, bindings: {} });
  it('refuses operations past max_ops', () => {
    const c = mk({ limits: { max_ops: 1 } });
    const d = emitDef(c, spec(['create']));
    expect(d?.verb).toBe('t.thing.create');
    expect(c.defs.length).toBe(1);
    expect(err(() => emitDef(c, spec(['create'])))).toEqual({ code: 'import_limit', message: 'more than 1 operations' });
  });
  it('drops a def that fails validation, noting why', () => {
    const c = mk();
    expect(emitDef(c, spec([]))).toBeUndefined();
    expect(c.defs).toEqual([]);
    expect(c.verbs.size).toBe(0);
    expect(c.todo).toEqual([{ where: 'createThing', code: 'invalid_def', message: 'not emitted: effects must be 1..12 distinct known effects' }]);
  });
});
