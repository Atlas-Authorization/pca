// GraphQL importer: exact tokens, parse errors, introspection tolerance and the draft each root field becomes.
import { describe, expect, it } from 'vitest';
import { ActionKitError, fromIntrospection, importGraphql, parseGraphqlSdl } from '../src';

const bad = (fn: () => unknown, code: string, message: string): void => {
  let e: unknown;
  try { fn(); } catch (x) { e = x; }
  expect(e).toBeInstanceOf(ActionKitError);
  expect({ code: (e as ActionKitError).code, message: (e as ActionKitError).message }).toEqual({ code, message });
};
const INT = { k: 'named', name: 'Int' } as const;
const STR = { k: 'named', name: 'String' } as const;
const types = (src: string): Record<string, unknown> => Object.fromEntries(parseGraphqlSdl(src).types);
const O = { ns: 'g' };

describe('GraphQL SDL lexer', () => {
  it('bounds the token count at the limit', () => {
    bad(() => parseGraphqlSdl('type A', 2), 'import_limit', 'the GraphQL source has too many tokens');
    expect(parseGraphqlSdl('type A', 3).types.has('A')).toBe(true);
  });
  it('reads a block string with an escaped triple quote', () => {
    const s = parseGraphqlSdl('type Query { """a\\"""b""" f: Int }');
    expect(s.types.get('Query')!.fields[0]!.desc).toBe('a"""b');
  });
  it('reads backslash escapes in a plain string', () => {
    const s = parseGraphqlSdl('type Query { "a\\"b\\\\c" f: Int }');
    expect(s.types.get('Query')!.fields[0]!.desc).toBe('a"b\\c');
  });
  it('names the unterminated string forms', () => {
    bad(() => parseGraphqlSdl('type A { """abc'), 'bad_source', 'unterminated GraphQL block string');
    bad(() => parseGraphqlSdl('type A { "a\nb" f: Int }'), 'bad_source', 'unterminated GraphQL string');
    bad(() => parseGraphqlSdl('type A { "abc'), 'bad_source', 'unterminated GraphQL string');
  });
  it('ends a comment at the end of the source and at a newline', () => {
    expect(parseGraphqlSdl('scalar S # c').types.has('S')).toBe(true);
    expect([...parseGraphqlSdl('# c\nscalar S').types.keys()]).toEqual(['S']);
  });
  it('lexes a signed decimal exponent as one number and stops at a space', () => {
    expect(parseGraphqlSdl('scalar S @d(a: -1.5e+3 b: 2)').types.has('S')).toBe(true);
    bad(() => parseGraphqlSdl('type A { f(x: Int = 5 6): Int }'), 'bad_source', "GraphQL parse error: expected a name near '6'");
    bad(() => parseGraphqlSdl('scalar S @d(a: 12'), 'bad_source', "GraphQL parse error: expected ')' near ''");
  });
  it('lexes a spread as a punctuator and rejects an unknown character with its offset', () => {
    bad(() => parseGraphqlSdl('type A { ... }'), 'bad_source', "GraphQL parse error: expected a name near '...'");
    bad(() => parseGraphqlSdl('scalar S %'), 'bad_source', 'unexpected character in GraphQL source at offset 9');
  });
});

describe('GraphQL SDL parser', () => {
  it('reports expectation failures with the offending token', () => {
    bad(() => parseGraphqlSdl('type A { f Int }'), 'bad_source', "GraphQL parse error: expected ':' near 'Int'");
    bad(() => parseGraphqlSdl('type { }'), 'bad_source', "GraphQL parse error: expected a name near '{'");
    bad(() => parseGraphqlSdl('type Query { a(x: Int = ) : Int }'), 'bad_source', "GraphQL parse error: unexpected ')'");
    bad(() => parseGraphqlSdl('query Q { a }'), 'bad_source', "GraphQL parse error: unsupported definition 'query' (only type-system definitions are imported)");
    bad(() => parseGraphqlSdl('extend'), 'bad_source', "GraphQL parse error: expected a name near ''");
  });
  it('names each unterminated block', () => {
    bad(() => parseGraphqlSdl('type A { f(x: Int'), 'bad_source', 'GraphQL parse error: unterminated argument list');
    bad(() => parseGraphqlSdl('type A { f: Int'), 'bad_source', 'GraphQL parse error: unterminated field list');
    bad(() => parseGraphqlSdl('schema { query: Q'), 'bad_source', 'GraphQL parse error: unterminated schema block');
    bad(() => parseGraphqlSdl('enum E { A'), 'bad_source', 'GraphQL parse error: unterminated enum');
    bad(() => parseGraphqlSdl('type A { f(x: Int = [1'), 'bad_source', "GraphQL parse error: expected ']' near ''");
    bad(() => parseGraphqlSdl('type A { f(x: Int = {a: 1'), 'bad_source', "GraphQL parse error: expected '}' near ''");
  });
  it('bounds type and value nesting at 32', () => {
    const t = (n: number): string => `type Query { a(x: ${'['.repeat(n)}Int${']'.repeat(n)}): Int }`;
    expect(parseGraphqlSdl(t(32)).types.has('Query')).toBe(true);
    bad(() => parseGraphqlSdl(t(33)), 'import_limit', 'GraphQL type nesting is too deep');
    const l = (n: number): string => `type Query { a(x: Int = ${'['.repeat(n)}1${']'.repeat(n)}): Int }`;
    const o = (n: number): string => `type Query { a(x: Int = ${'{a:'.repeat(n)}1${'}'.repeat(n)}): Int }`;
    expect(parseGraphqlSdl(l(32)).types.has('Query')).toBe(true);
    expect(parseGraphqlSdl(o(32)).types.has('Query')).toBe(true);
    bad(() => parseGraphqlSdl(l(33)), 'import_limit', 'GraphQL value nesting is too deep');
    bad(() => parseGraphqlSdl(o(33)), 'import_limit', 'GraphQL value nesting is too deep');
  });
  it('skips every default value form', () => {
    const s = parseGraphqlSdl('type Query { a(x: Int = $v, y: K = RED, z: String = "s", w: [Int] = [1 2], o: I = {a: 1 b: [2]}): Int }');
    expect(s.types.get('Query')!.fields[0]!.args.map((a) => a.name)).toEqual(['x', 'y', 'z', 'w', 'o']);
  });
  it('keeps argument descriptions and nested type wrappers, and skips argument directives', () => {
    const s = parseGraphqlSdl('type Query { f("the x" x: Int @deprecated(reason: "r") y: [Int!]! = 5): Int }');
    expect(s.types.get('Query')!.fields[0]!.args).toStrictEqual([
      { name: 'x', type: INT, desc: 'the x' },
      { name: 'y', type: { k: 'nonnull', of: { k: 'list', of: { k: 'nonnull', of: INT } } } },
    ]);
  });
  it('reads the schema block and ignores unknown operations', () => {
    expect(parseGraphqlSdl('schema @d { query: Q mutation: M subscription: S foo: X }')).toStrictEqual({ types: new Map(), query: 'Q', mutation: 'M', subscription: 'S' });
    expect(parseGraphqlSdl('schema { foo: X }')).toStrictEqual({ types: new Map() });
  });
  it('accepts a leading description and a scalar with a directive', () => {
    expect(types('"doc" scalar S @d')).toStrictEqual({ S: { kind: 'scalar', name: 'S', fields: [], values: [] } });
  });
  it('accepts directive definitions in every location form', () => {
    expect([...parseGraphqlSdl('directive @d(a: Int) repeatable on FIELD | OBJECT scalar S').types.keys()]).toEqual(['S']);
    expect([...parseGraphqlSdl('directive @d on | A | B scalar S').types.keys()]).toEqual(['S']);
    expect([...parseGraphqlSdl('directive @d A scalar S').types.keys()]).toEqual(['S']);
  });
  it('builds object, interface and input definitions', () => {
    const t = types('type T implements & I & J @d { x: Int } interface N { f(a: Int): Int } input In { a: Int = 5 "doc" b: [Int] @deprecated }');
    expect(t).toStrictEqual({
      T: { kind: 'object', name: 'T', fields: [{ name: 'x', args: [], type: INT, deprecated: false }], values: [] },
      N: { kind: 'interface', name: 'N', fields: [{ name: 'f', args: [{ name: 'a', type: INT }], type: INT, deprecated: false }], values: [] },
      In: { kind: 'input', name: 'In', fields: [{ name: 'a', args: [], type: INT, deprecated: false }, { name: 'b', args: [], type: { k: 'list', of: INT }, deprecated: true, desc: 'doc' }], values: [] },
    });
  });
  it('only an @deprecated directive deprecates', () => {
    const f = parseGraphqlSdl('type T { a: Int @other(x: 1) b: Int @deprecated(reason: "r") }').types.get('T')!.fields;
    expect(f.map((x) => x.deprecated)).toEqual([false, true]);
  });
  it('builds unions and enums, merging extensions', () => {
    const t = types('union U @d = | A | B enum E @d { "d" A @deprecated B } enum F extend enum E { C } enum G');
    expect(t).toStrictEqual({
      U: { kind: 'union', name: 'U', fields: [], values: [] },
      E: { kind: 'enum', name: 'E', fields: [], values: ['A', 'B', 'C'] },
      F: { kind: 'enum', name: 'F', fields: [], values: [] },
      G: { kind: 'enum', name: 'G', fields: [], values: [] },
    });
  });
  it('input fields carry no arguments', () => {
    expect(parseGraphqlSdl('input I { a: Int }').types.get('I')!.fields[0]!.args).toStrictEqual([]);
  });
});

describe('GraphQL introspection', () => {
  const wrap = (kind: string, n: number): unknown => {
    let t: unknown = { kind: 'SCALAR', name: 'Int' };
    for (let i = 0; i < n; i++) t = { kind, ofType: t };
    return t;
  };
  const doc = (type: unknown): unknown => ({ __schema: { types: [{ kind: 'OBJECT', name: 'Query', fields: [{ name: 'f', args: [], type }] }] } });
  const MSG = 'malformed introspection type reference';
  it('bounds type nesting at 16 for both wrappers', () => {
    for (const kind of ['NON_NULL', 'LIST']) {
      expect(() => fromIntrospection(doc(wrap(kind, 16)))).not.toThrow();
      bad(() => fromIntrospection(doc(wrap(kind, 17))), 'bad_source', MSG);
    }
  });
  it('maps wrappers and rejects malformed type references', () => {
    const f = fromIntrospection(doc({ kind: 'LIST', ofType: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'Int' } } })).types.get('Query')!.fields[0]!;
    expect(f.type).toStrictEqual({ k: 'list', of: { k: 'nonnull', of: INT } });
    bad(() => fromIntrospection(doc(5)), 'bad_source', MSG);
    bad(() => fromIntrospection(doc(null)), 'bad_source', MSG);
    bad(() => fromIntrospection(doc({ kind: 'SCALAR' })), 'bad_source', MSG);
    bad(() => fromIntrospection(doc({ kind: 'LIST' })), 'bad_source', MSG);
  });
  it('refuses a document that is not an introspection result', () => {
    const M = 'not a GraphQL introspection result (no __schema.types)';
    for (const d of [{}, null, 'x', { __schema: { types: {} } }, { data: { nope: 1 } }, { __schema: {} }]) bad(() => fromIntrospection(d), 'bad_source', M);
  });
  it('reads root type names, with or without the data wrapper', () => {
    expect(fromIntrospection({ data: { __schema: { queryType: { name: 'Q' }, mutationType: { name: 5 }, subscriptionType: 'S', types: [] } } })).toStrictEqual({ types: new Map(), query: 'Q' });
    expect(fromIntrospection({ __schema: { queryType: { name: 'Q' }, mutationType: { name: 'M' }, subscriptionType: { name: 'S' }, types: [] } })).toStrictEqual({ types: new Map(), query: 'Q', mutation: 'M', subscription: 'S' });
    expect(fromIntrospection({ data: null, __schema: { queryType: { name: 'Q' }, types: [] } }).query).toBe('Q');
  });
  it('skips malformed entries and keeps well-formed ones exactly', () => {
    const S = { kind: 'SCALAR', name: 'String' };
    const s = fromIntrospection({ __schema: { types: [
      null, 5, { kind: 'OBJECT' }, { name: 'NoKind' }, { name: 5, kind: 'OBJECT' }, { name: 'Arr', kind: ['OBJECT'] }, { name: '__Schema', kind: 'OBJECT', fields: [] },
      { name: '_x', kind: 'OBJECT', fields: [] }, { name: 'W', kind: 'WEIRD' },
      { kind: 'OBJECT', name: 'Query', fields: [
        5, null, { args: [] }, { name: 5 }, { name: 'plain', type: { kind: 'SCALAR', name: 'Int' } },
        { name: 'old', description: 'd', isDeprecated: true, args: [null, 7, { type: S }, { name: 5, type: S }, { name: 'x', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } }, description: 'ax' }, { name: 'y', type: S, description: 7 }] },
        { name: 'nt', isDeprecated: false }, { name: 'ds', description: 5, isDeprecated: 'true' },
      ] },
      { kind: 'INPUT_OBJECT', name: 'In', inputFields: [{ name: 'a', type: S }], fields: [{ name: 'ignored', type: S }] },
      { kind: 'OBJECT', name: 'NoFields' },
      { kind: 'ENUM', name: 'E', enumValues: [null, {}, { name: 5 }, { name: 'A' }, 'str', { name: 'B' }] },
      { kind: 'SCALAR', name: 'Sc' }, { kind: 'INTERFACE', name: 'If', fields: [] }, { kind: 'UNION', name: 'Un' },
    ] } });
    const empty = (kind: string, name: string): unknown => ({ kind, name, fields: [], values: [] });
    expect(Object.fromEntries(s.types)).toStrictEqual({
      _x: empty('object', '_x'), NoFields: empty('object', 'NoFields'), Sc: empty('scalar', 'Sc'), If: empty('interface', 'If'), Un: empty('union', 'Un'),
      E: { kind: 'enum', name: 'E', fields: [], values: ['A', 'B'] },
      In: { kind: 'input', name: 'In', fields: [{ name: 'a', args: [], type: STR, deprecated: false }], values: [] },
      Query: { kind: 'object', name: 'Query', values: [], fields: [
        { name: 'plain', args: [], type: INT, deprecated: false },
        { name: 'old', desc: 'd', deprecated: true, type: STR, args: [{ name: 'x', type: { k: 'nonnull', of: { k: 'named', name: 'ID' } }, desc: 'ax' }, { name: 'y', type: STR }] },
        { name: 'nt', args: [], type: STR, deprecated: false },
        { name: 'ds', args: [], type: STR, deprecated: false },
      ] },
    });
  });
});

describe('importGraphql drafts', () => {
  it('gives each root operation its effect, idempotency, trait and binding', () => {
    const r = importGraphql('type Query { ping(x: Int): Int } type Mutation { poke(x: Int): Int } type Subscription { tick(x: Int): Int }', O);
    expect(r.defs.map((d) => [d.verb, d.effects, d.idempotency, d.traits, d.bindings])).toEqual([
      ['g.ping', ['read'], { mode: 'natural' }, undefined, { graphql: { op: 'query', field: 'ping' } }],
      ['g.poke', ['update'], undefined, undefined, { graphql: { op: 'mutation', field: 'poke' } }],
      ['g.tick', ['read'], { mode: 'natural' }, ['pca.bulk'], { graphql: { op: 'subscription', field: 'tick' } }],
    ]);
    expect(r.todo).toEqual([]);
  });
  it('uses the schema block root names instead of the defaults', () => {
    const r = importGraphql('schema { query: RootQ } type RootQ { a(x: Int): Int } type Query { b(x: Int): Int }', O);
    expect(r.defs.map((d) => d.verb)).toEqual(['g.a']);
  });
  it('sorts fields, takes the title from the first description line and notes deprecation', () => {
    const r = importGraphql('type Query { """first line\nsecond line""" zed(x: Int): Int  abc(x: Int): Int @deprecated }', O);
    expect(r.defs.map((d) => d.verb)).toEqual(['g.abc', 'g.zed']);
    expect(r.defs[0]!.title).toBe('abc');
    expect(r.defs[0]!.description).toBeUndefined();
    expect(r.defs[1]!.title).toBe('first line');
    expect(r.defs[1]!.description).toBe('first line second line');
    expect(r.todo).toEqual([{ where: 'query abc', code: 'deprecated', message: 'the field is marked @deprecated' }]);
  });
  it('maps built-in scalars, nullability and lists to params', () => {
    const r = importGraphql('type Query { probe(a: Int, b: String!, c: Boolean, d: DateTime, e: ID, g: [String!]!, h: [[Int]]): Int }', O);
    expect(r.defs[0]!.params).toEqual({
      a: { type: 'integer', required: false }, b: { type: 'string' }, c: { type: 'boolean', required: false }, d: { type: 'datetime', required: false },
      e: { type: 'string', required: false }, g: { type: 'array', items: 'string' }, h: { type: 'array', required: false },
    });
    expect(r.todo).toEqual([{ where: 'query probe: h', code: 'array_items', message: "array items of type 'array' are not declared (items left open)" }]);
  });
  it('a custom scalar is a string and an enum keeps its distinct values, without notes', () => {
    const r = importGraphql('scalar Json enum K { A B A } type Query { probe(j: Json, k: K): Int }', O);
    expect(r.defs[0]!.params).toEqual({ j: { type: 'string', required: false }, k: { type: 'string', required: false, values: ['A', 'B'] } });
    expect(r.todo).toEqual([]);
  });
  it('expands input objects with descriptions and requirements, and notes cycles, output types and unknown types', () => {
    const r = importGraphql('input N { """the v""" v: Int! next: N } type User { id: ID } type Query { probe("the m" m: Int, n: N!, u: User, z: Zed): Int }', O);
    expect(r.defs[0]!.params).toEqual({
      m: { type: 'integer', required: false, description: 'the m' },
      'n.v': { type: 'integer', description: 'the v' }, 'n.next': { type: 'string', required: false },
      u: { type: 'string', required: false }, z: { type: 'string', required: false },
    });
    expect(r.todo.filter((t) => t.code !== 'unsupported_type')).toEqual([
      { where: 'query probe(n)', code: 'cyclic_ref', message: "input type 'N' is recursive (declared string; refine or drop)" },
      { where: 'query probe(u)', code: 'output_type', message: "type 'User' is an output type and cannot be an argument (declared string)" },
      { where: 'query probe(z)', code: 'unknown_type', message: "type 'Zed' is not defined in the schema (declared string)" },
    ]);
    expect(r.todo.filter((t) => t.code === 'unsupported_type')).toHaveLength(3);
  });
  it('stops type expansion at the node budget and notes it once', () => {
    const r = importGraphql('type Query { probe(a: Int, b: Int, c: Int): Int }', { ...O, limits: { max_ref_nodes: 1 } });
    expect(r.todo.filter((t) => t.code === 'ref_budget')).toEqual([
      { where: 'query probe(b)', code: 'ref_budget', message: 'type expansion stopped at the node budget (declared string; refine or drop)' },
    ]);
  });
  it('imports an introspection result with its own root names and deprecation flag', () => {
    const r = importGraphql({ __schema: { queryType: { name: 'Root' }, types: [{ kind: 'OBJECT', name: 'Root', fields: [{ name: 'old', isDeprecated: true, args: [], type: { kind: 'SCALAR', name: 'Int' } }] }] } }, O);
    expect(r.defs.map((d) => d.verb)).toEqual(['g.old']);
    expect(r.todo).toEqual([{ where: 'query old', code: 'deprecated', message: 'the field is marked @deprecated' }]);
  });
});
