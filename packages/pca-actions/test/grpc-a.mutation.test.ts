// The .proto text lexer and parser (first half of the gRPC importer): exact tokens, errors, fields, enums and rpc options.
import { describe, expect, it } from 'vitest';
import { ActionKitError, parseProto } from '../src';

const P = (s: string, max?: number) => parseProto(s, max);
const err = (fn: () => unknown) => {
  try { fn(); } catch (e) {
    expect(e).toBeInstanceOf(ActionKitError);
    return { code: (e as ActionKitError).code, message: (e as Error).message };
  }
  throw new Error('expected a throw');
};
const bad = (message: string) => ({ code: 'bad_source', message });
const F = (name: string, type: string, o: Record<string, unknown> = {}, scope = 'p.M') => ({ name, type, scope, repeated: false, optional: false, behavior: [], ...o });
const methods = (...bodies: string[]) => P(`package p; message A {} service S { ${bodies.map((b, i) => `rpc R${i}(A) returns (A) { ${b} }`).join(' ')} }`).services[0]!.methods;
const H = 'option (google.api.http) =';

describe('proto lexer', () => {
  it('limits the token count exactly', () => {
    expect(P('message A {}', 4).messages.has('A')).toBe(true);
    expect(err(() => P('message A {}', 3))).toEqual({ code: 'import_limit', message: 'the proto source has too many tokens' });
  });
  it('skips line and block comments', () => {
    const m = P('// leading } {\nmessage A { /* } { */ string a = 1; /*/ x */ int32 b = 2; } // tail');
    expect([...m.messages.values()]).toEqual([{ full: 'A', mapEntry: false, fields: [F('a', 'string', {}, 'A'), F('b', 'int32', {}, 'A')] }]);
    expect(err(() => P('message A { /* never closed'))).toEqual(bad('unterminated comment in proto source'));
  });
  it('reads escapes and both quote styles in strings', () => {
    const [m] = methods(String.raw`${H} { get: "/a\"b\\c\nd" };`, `${H} { post: '/s' };`);
    expect(m!.http).toEqual({ method: 'GET', path: '/a"b\\cnd' });
    expect(methods(`${H} { post: '/s' };`)[0]!.http).toEqual({ method: 'POST', path: '/s' });
  });
  it('rejects unterminated strings and unknown characters', () => {
    expect(err(() => P('option x = "abc'))).toEqual(bad('unterminated string in proto source'));
    expect(err(() => P('option x = "a\nb";'))).toEqual(bad('unterminated string in proto source'));
    expect(err(() => P('message A { @ }'))).toEqual(bad('unexpected character in proto source at offset 12'));
  });
  it('lexes whole numbers', () => {
    expect(P('message M { string a = 100; int32 b = -2; }').messages.get('M')!.fields.map((f) => f.name)).toEqual(['a', 'b']);
    expect(methods('option idempotency_level = 2;')[0]!.idem).toBe('2');
  });
});

describe('proto parser errors', () => {
  it('formats parse errors with the nearest token', () => {
    expect(err(() => P('message'))).toEqual(bad("proto parse error: expected an identifier near '<end>'"));
    expect(err(() => P('message { }'))).toEqual(bad("proto parse error: expected an identifier near '{'"));
    expect(err(() => P('message A ['))).toEqual(bad("proto parse error: expected '{' near '['"));
  });
  it('a string token never matches punctuation', () => {
    expect(P('message M { option x = "{"; int32 a = 1; }').messages.get('M')!.fields.map((f) => f.name)).toEqual(['a']);
  });
  it('reports unterminated blocks', () => {
    expect(err(() => P('extend Foo {'))).toEqual(bad("proto parse error: unterminated block near '<end>'"));
    expect(err(() => P('enum E { A = 0;'))).toEqual(bad("proto parse error: unterminated enum near '<end>'"));
    expect(err(() => P('message A { string a = 1;'))).toEqual(bad("proto parse error: unterminated message near '<end>'"));
    expect(err(() => P('message A { oneof k { string a = 1;'))).toEqual(bad("proto parse error: unterminated oneof near '<end>'"));
    expect(err(() => P('message M { string a = 1 [deprecated = true'))).toEqual(bad("proto parse error: unterminated field options near '<end>'"));
    expect(err(() => P('service S {'))).toEqual(bad("proto parse error: unterminated service near '<end>'"));
    expect(err(() => P('service S { rpc R(A) returns (B) {'))).toEqual(bad("proto parse error: unterminated rpc body near '<end>'"));
    expect(err(() => P(`service S { rpc R(A) returns (B) { ${H} { get: "/x"`))).toEqual(bad("proto parse error: unterminated option near '<end>'"));
    expect(err(() => P(`service S { rpc R(A) returns (B) { ${H} { get:`))).toEqual(bad("proto parse error: unterminated option near '<end>'"));
  });
  it('rejects malformed declarations', () => {
    expect(err(() => P('extend Foo;'))).toEqual(bad("proto parse error: expected '{' near ';'"));
    expect(err(() => P('message A { "message" B {} }'))).toEqual(bad("proto parse error: expected an identifier near 'message'"));
    expect(err(() => P('message M { string<int32> x = 1; }'))).toEqual(bad("proto parse error: expected an identifier near '<'"));
    expect(err(() => P('service S { rpc R(A) retuns (B); }'))).toEqual(bad("proto parse error: expected 'returns' near '('"));
    expect(err(() => P('service S { rpc R(A) returns ('))).toEqual(bad("proto parse error: expected an identifier near '<end>'"));
    expect(err(() => P('service S { rpc R("stream" A) returns (B); }'))).toEqual(bad("proto parse error: expected an identifier near 'stream'"));
    expect(err(() => P('service S { rpc R(A) returns (B) { option idempotency_level ='))).toEqual(bad("proto parse error: unterminated rpc body near '<end>'"));
  });
  it('limits message nesting depth', () => {
    const nest = (n: number) => 'message M { '.repeat(n) + '}'.repeat(n);
    expect(P(nest(33)).messages.size).toBe(33);
    expect(err(() => P(nest(34)))).toEqual({ code: 'import_limit', message: 'proto message nesting is too deep' });
  });
});

describe('proto top level', () => {
  it('skips stray semicolons, extend blocks and aggregate options', () => {
    const m = P(`; ; extend Foo { optional Bar x = 1 [(a) = { b: [1] c: { d: 3 } }]; } extend Foo { option x = "{"; }
option (x) = { a: 1; message Evil { } };
message A {}`);
    expect([...m.messages.keys()]).toEqual(['A']);
  });
  it('parses enums at top level and in messages', () => {
    const m = P('package p; enum E { option allow_alias = true; reserved 5, 6; A = 0; B = 1 [deprecated = true]; } message M { enum N { X = 0; } string s = 1; }');
    expect([...m.enums.values()]).toEqual([{ full: 'p.E', values: ['A', 'B'] }, { full: 'p.M.N', values: ['X'] }]);
    expect(m.messages.get('p.M')!.fields).toEqual([F('s', 'string')]);
  });
});

describe('proto messages', () => {
  it('parses labels, maps, oneofs and skipped statements', () => {
    const m = P(`package p;
message M {
  string plain = 1;
  optional string opt = 2;
  required string req = 3;
  repeated string rep = 4;
  map<string, int32> counts = 5;
  repeated map<string, string> rmap = 6;
  map m = 7;
  oneof kind { option deprecated = true; string x = 8; int32 y = 9; }
  group Skip = 10 { optional string inner = 11; }
  option (a.b) = 1; reserved 12, 13; extensions 100 to 199;
  ;
  enum E { A = 0; }
  message N { bool z = 1; }
  .foo.Bar q = 14;
  extend Ext { optional Bar x = 15 [(a) = { b: [1] c: { d: 3 } }]; }
  int32 after = 16;
}`);
    expect([...m.messages.values()]).toEqual([
      {
        full: 'p.M', mapEntry: false,
        fields: [
          F('plain', 'string'), F('opt', 'string', { optional: true }), F('req', 'string'), F('rep', 'string', { repeated: true }),
          F('counts', 'map', { map: ['string', 'int32'] }), F('rmap', 'map', { map: ['string', 'string'] }), F('m', 'map'),
          F('x', 'string', { optional: true }), F('y', 'int32', { optional: true }), F('q', '.foo.Bar'), F('after', 'int32'),
        ],
      },
      { full: 'p.M.N', mapEntry: false, fields: [F('z', 'bool', {}, 'p.M.N')] },
    ]);
    expect(m.messages.get('p.M')!.fields[6]).not.toHaveProperty('map');
    expect([...m.enums.keys()]).toEqual(['p.M.E']);
  });
  it('collects field_behavior names only', () => {
    const f = P(`package p; message M {
 string a = 1 [(google.api.field_behavior) = REQUIRED, (google.api.field_behavior) = OUTPUT_ONLY, deprecated = true];
 string b = 2 [(x) = { y: [1, 2] z: { w: 3 } }, (google.api.field_behavior) = IMMUTABLE];
 string c = 3 [default = FOO];
 string d = 4 [(google.api.field_behavior) = REQUIRED, (other) = FOO];
 string e = 5 [(google.api.field_behavior) = fooBAR];
 string f = 6 [(google.api.field_behavior) = BARfoo];
 string g = 7 [x = "field_behavior" ZED];
 int32 h = 100;
}`).messages.get('p.M')!.fields;
    expect(f).toEqual([
      F('a', 'string', { behavior: ['REQUIRED', 'OUTPUT_ONLY'] }), F('b', 'string', { behavior: ['IMMUTABLE'] }), F('c', 'string'),
      F('d', 'string', { behavior: ['REQUIRED'] }), F('e', 'string'), F('f', 'string'), F('g', 'string'), F('h', 'int32'),
    ]);
  });
});

describe('proto services', () => {
  it('parses rpc shapes and options', () => {
    const s = P(`package p; message A {} message B {}
service S {
  ;
  option (my.opt) = true;
  rpc Plain(A) returns (B);
  rpc Both(stream A) returns (stream B) {}
  rpc Cli(stream A) returns (B) {};
  rpc Srv(A) returns (stream B) { foo bar; option idempotency_level = NO_SIDE_EFFECTS; option deprecated = true; }
  rpc Http(A) returns (B) { ${H} { selector: "s" post: "/p" body: "*" additional_bindings { get: "/g" body: "nb" } }; }
}`).services;
    const m = (name: string, input: string, output: string, cs: boolean, ss: boolean, o: Record<string, unknown> = {}) => ({ name, input, output, cs, ss, scope: 'p', ...o });
    expect(s).toEqual([{
      full: 'p.S', name: 'S',
      methods: [
        m('Plain', 'A', 'B', false, false), m('Both', 'A', 'B', true, true), m('Cli', 'A', 'B', true, false),
        m('Srv', 'A', 'B', false, true, { idem: 'NO_SIDE_EFFECTS' }), m('Http', 'A', 'B', false, false, { http: { method: 'POST', path: '/p', body: '*' } }),
      ],
    }]);
  });
  it('reads google.api.http verbs only at the top level of the http option', () => {
    const r = methods(
      `${H} { get: "/1" };`, `${H} { put: "/2" };`, `${H} { post: "/3" };`, `${H} { delete: "/4" };`, `${H} { patch: "/5" };`,
      `${H} { get: 5 };`, `${H} { x: "get" : "/g" };`, `${H} { post: "/p" y: "body" : "q" };`,
      `${H} { additional_bindings { get: "/g" body: "nb" } put: "/top" };`, `${H} { post: "/a" additional_bindings { body: "nb" } };`,
      `${H} { get: "/a" post: "/b" };`, `${H} { get { a: 1 } post: "/p" };`, `${H} { post: "/p" response_body: "r" };`,
      'option (other.thing) = { get: "/g" };', `${H} { post: "/a" }; option (other.thing) = { body: "z" };`, `${H} { head: "/h" };`,
    ).map((x) => x.http);
    expect(r).toEqual([
      { method: 'GET', path: '/1' }, { method: 'PUT', path: '/2' }, { method: 'POST', path: '/3' }, { method: 'DELETE', path: '/4' }, { method: 'PATCH', path: '/5' },
      { method: 'GET', path: '' }, undefined, { method: 'POST', path: '/p' },
      { method: 'PUT', path: '/top' }, { method: 'POST', path: '/a' },
      { method: 'GET', path: '/a' }, { method: 'POST', path: '/p' }, { method: 'POST', path: '/p' },
      undefined, { method: 'POST', path: '/a' }, undefined,
    ]);
    expect(r[7]).not.toHaveProperty('body');
    expect(r[9]).not.toHaveProperty('body');
    expect(r[14]).not.toHaveProperty('body');
  });
  it('reads idempotency_level from plain and parenthesised option names only', () => {
    expect(methods(
      'option idempotency_level = NO_SIDE_EFFECTS; option deprecated = true;', 'option (x.idempotency_level) = IDEMPOTENT;', 'option deprecated = true;',
    ).map((x) => x.idem)).toEqual(['NO_SIDE_EFFECTS', 'IDEMPOTENT', undefined]);
  });
  it('a verb key with no value consumes the next token', () => {
    const src = `package p; message M {} service S { rpc A(M) returns (M) { ${H} { get: }; } rpc B(M) returns (M); }`;
    expect(err(() => P(src))).toEqual(bad("proto parse error: unterminated service near '<end>'"));
  });
});
