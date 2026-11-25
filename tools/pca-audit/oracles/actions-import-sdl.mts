// Oracle: @atlasauth/pca-actions import/{graphql,grpc}.ts. Writes out/ref-actions-import-sdl.json.gz.
// PORTING table: fn(args) -> native entry point (net.atlasauth.pca.actions.importers), comparison rule = JSON value equality
//   parseGraphqlSdl(src) / fromIntrospection(doc) -> GraphqlImporter.parseGraphqlSdl / fromIntrospection, compared as GqlSchema.toJson()
//        = {types: [[name, {kind, name, fields: [{name, args, type, desc?, deprecated}], values}]...], query?, mutation?, subscription?}
//   parseProto(src) / parseDescriptorSet({$bytes}) -> GrpcImporter.parseProto / parseDescriptorSet(bytes), compared as ProtoModel.toJson()
//        = {messages: [[full, {full, fields, mapEntry}]...], enums: [[full, values]...], services: [...]}; a {$bytes: b64url} argument is the byte string
//   importGraphql(src|introspection, opts) -> GraphqlImporter.importGraphql;  importGrpc(src | {$bytes}, opts) -> GrpcImporter.importGrpc (the bytes decoded first)
import * as G0 from '../../../packages/pca-actions/src/import/graphql.ts';
import * as P0 from '../../../packages/pca-actions/src/import/grpc.ts';
import { Oracle, variants, refWrite, rng } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const G = un(G0), P = un(P0);
const o = new Oracle('actions-import-sdl', 'tools/pca-audit/oracles/actions-import-sdl.mts', 'TS-reference oracle for the GraphQL and gRPC importers and their parsers.');
const R = rng(0x5d1);
const take = <T,>(xs: T[], n: number): T[] => { const k = Math.max(1, Math.floor(xs.length / n)); return xs.filter((_, i) => i % k === 0).slice(0, n); };
const OPT = { ns: 'api' };

const gSchema = (s: any) => ({ types: [...s.types.entries()], ...(s.query !== undefined ? { query: s.query } : {}), ...(s.mutation !== undefined ? { mutation: s.mutation } : {}), ...(s.subscription !== undefined ? { subscription: s.subscription } : {}) });
const pModel = (m: any) => ({ messages: [...m.messages.entries()], enums: [...m.enums.entries()].map(([k, v]: any) => [k, v.values]), services: m.services });
const bytesOf = (x: any): any => (x !== null && typeof x === 'object' && typeof x.$bytes === 'string' ? new Uint8Array(Buffer.from(x.$bytes, 'base64url')) : x);

// ---- GraphQL SDL ----
const SDL = `"""Schema docs"""
schema { query: Query mutation: Mutation subscription: Sub }
scalar Date
directive @auth(role: String = "x") repeatable on FIELD_DEFINITION | OBJECT
enum Role { ADMIN USER @deprecated(reason: "old") }
input Addr { street: String! city: String zip: Int = 5 geo: Geo }
input Geo { lat: Float lng: Float self: Addr }
interface Node { id: ID! }
union Result = A | B
type A implements Node & Other @auth { id: ID! }
type Query {
  "Fetch a user."
  user(id: ID!, role: Role): User
  users(first: Int = 10, tags: [String!]!, when: DateTime, at: Date): [User]
  search(q: String! """Query text""" limit: Int): Result @deprecated
  unknown(x: Mystery, y: User): String
}
type Mutation {
  createUser(name: String!, addr: Addr, email: Email, ids: [[ID]]): User
  "Delete a user.\\nSecond line."
  deleteUser(id: ID!): Boolean
  __proto__(a: Int): Int
}
type Sub { tick(n: Int): Int }
extend type Query { more: String }
type Query { dup: String }
`;
for (const [n, opts] of [['base', OPT], ['meta', { ns: 'shop', uri: 'u', licence: 'MIT', now: 7 }], ['lim', { ns: 'api', limits: { max_ref_nodes: 4 } }], ['badns', { ns: 'X' }], ['ops', { ns: 'api', limits: { max_ops: 2 } }]] as any[]) await o.run('importGraphql', `sdl ${n}`, G.importGraphql, [SDL, opts]);
await o.run('parseGraphqlSdl', 'full', (s: string) => gSchema(G.parseGraphqlSdl(s)), [SDL]);
const SDLS = ['', '# only comment', 'type Q { a: String }', 'type Query { a(x: Int): String', 'type Query { a: [String }', 'query { a }', 'type Query { a: String } fragment', 'type Query { a(x: Int = [1, {a: $v}, "s", ENUM, -1.5e3]): Int }', '"""unterminated', '"unterminated', 'type Query { a: String } ?', 'type Query { "d" a: String, b: Int }', 'enum E { A B', 'union U = | A | B', 'type T @a(b: {c: [1]}) { f: Int }', 'type Query { a: [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[String]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]] }', 'schema { subscription: S }\ntype S { s: Int }', 'type Mutation { a: Int }\ntype Query { b: Int }', 'type Query {a: String}\n﻿type X {a:Int}', 'directive @d on A', 'directive @d repeatable on | A | B', 'input I { a: Int = 1 b: String @x }', 'type Query { a(\n"doc" x: Int ): Int }', 'extend schema { query: Q }', '"""a\\"""b"""type Query { a: Int }', 'type Query { a: Int } type Query { b: Int } enum Query { Z }'];
for (const [i, s] of SDLS.entries()) { await o.run('parseGraphqlSdl', `s${i}`, (x: string) => gSchema(G.parseGraphqlSdl(x)), [s]); await o.run('importGraphql', `s${i}`, G.importGraphql, [s, OPT]); }
// text mutations of the SDL
const cut = (s: string, k: number) => s.slice(0, k);
for (const k of take(Array.from({ length: SDL.length }, (_, i) => i), 60)) await o.run('parseGraphqlSdl', `cut ${k}`, (x: string) => gSchema(G.parseGraphqlSdl(x)), [cut(SDL, k)]);
for (const ch of ['{', '}', '(', ')', ':', '!', '@', '"', '#', '=', '|', '&', '[', ']', '$', ',', '\\', '\u0000', '\ud800']) {
  for (const at of take(Array.from({ length: SDL.length }, (_, i) => i), 5)) await o.run('parseGraphqlSdl', `ins ${JSON.stringify(ch)} ${at}`, (x: string) => gSchema(G.parseGraphqlSdl(x)), [SDL.slice(0, at) + ch + SDL.slice(at)]);
}
for (const [i, s] of take([...Array(40).keys()].map(() => { const a = R.int(0, SDL.length - 1), b = R.int(a, Math.min(SDL.length, a + 30)); return SDL.slice(0, a) + SDL.slice(b); }), 30).entries()) await o.run('importGraphql', `del ${i}`, G.importGraphql, [s, OPT]);

// ---- introspection ----
const ty = (kind: string, name: string | null, of?: any): any => ({ kind, name, ...(of ? { ofType: of } : {}) });
const INTRO: any = { data: { __schema: { queryType: { name: 'Query' }, mutationType: { name: 'Mutation' }, subscriptionType: null, types: [
  { kind: 'OBJECT', name: 'Query', fields: [{ name: 'user', description: 'Get a user', args: [{ name: 'id', type: ty('NON_NULL', null, ty('SCALAR', 'ID')), description: 'the id' }, { name: 'tags', type: ty('LIST', null, ty('SCALAR', 'String')) }], type: ty('OBJECT', 'User'), isDeprecated: true }, { name: 'ping', args: [], type: ty('SCALAR', 'String'), description: '' }] },
  { kind: 'OBJECT', name: 'Mutation', fields: [{ name: 'create', args: [{ name: 'in', type: ty('NON_NULL', null, ty('INPUT_OBJECT', 'In')) }, { name: 'e', type: ty('ENUM', 'Color') }], type: ty('OBJECT', 'User') }, { name: 'notype', args: [] }] },
  { kind: 'INPUT_OBJECT', name: 'In', inputFields: [{ name: 'a', type: ty('SCALAR', 'Int') }, { name: 'b', type: ty('NON_NULL', null, ty('SCALAR', 'String')), description: 'B' }] },
  { kind: 'ENUM', name: 'Color', enumValues: [{ name: 'RED' }, { name: 'GREEN' }, { x: 1 }] },
  { kind: 'SCALAR', name: 'Date' }, { kind: 'OBJECT', name: '__Type', fields: [] }, { kind: 'DIRECTIVE', name: 'x' }, { kind: 'UNION', name: 'U' }, { kind: 'INTERFACE', name: 'I', fields: [] }, 7, { name: 'noKind' },
] } } };
for (const [n, opts] of [['base', OPT], ['meta', { ns: 'shop', uri: 'u', now: 9 }]] as any[]) await o.run('importGraphql', `intro ${n}`, G.importGraphql, [INTRO, opts]);
await o.run('fromIntrospection', 'badtype', (d: any) => gSchema(G.fromIntrospection(d)), [{ __schema: { types: [{ kind: 'OBJECT', name: 'Query', fields: [{ name: 'bad', args: [{ name: 'x', type: { kind: 'SCALAR' } }], type: ty('SCALAR', 'String') }] }] } }]);
await o.run('fromIntrospection', 'full', (d: any) => gSchema(G.fromIntrospection(d)), [INTRO]);
await o.run('fromIntrospection', 'unwrapped', (d: any) => gSchema(G.fromIntrospection(d)), [INTRO.data]);
for (const x of [null, 5, 'x', {}, { __schema: {} }, { __schema: { types: 'x' } }, { data: { __schema: { types: [] } } }, { __schema: { types: [], queryType: { name: 'Q' } } }]) await o.run('fromIntrospection', JSON.stringify(x), (d: any) => gSchema(G.fromIntrospection(d)), [x]);
for (const [lab, v] of take([...variants(INTRO, { maxPaths: 700 })] as [string, any][], 160)) { await o.run('fromIntrospection', lab, (d: any) => gSchema(G.fromIntrospection(d)), [v]); }
for (const [lab, v] of take([...variants(INTRO, { maxPaths: 700 })] as [string, any][], 60)) await o.run('importGraphql', `intro ${lab}`, G.importGraphql, [v, OPT]);

// ---- .proto text ----
const PROTO = `syntax = "proto3";
package acme.v1;
import "google/api/annotations.proto";
option java_package = "x";
/* block */ // line
enum Color { option allow_alias = true; RED = 0; GREEN = 1 [deprecated = true]; reserved 5, 6; }
message Empty {}
message Addr { string street = 1 [(google.api.field_behavior) = REQUIRED]; string city = 2; optional int32 zip = 3; Geo geo = 4; }
message Geo { double lat = 1; double lng = 2; Addr back = 3; }
message CreateReq {
  string name = 1 [(google.api.field_behavior) = REQUIRED, (google.api.field_behavior) = INPUT_ONLY];
  Addr addr = 2;
  repeated string tags = 3;
  map<string, Addr> by_key = 4;
  Color color = 5;
  google.protobuf.Timestamp at = 6;
  google.protobuf.StringValue sv = 7;
  google.protobuf.Int64Value iv = 8;
  google.protobuf.BoolValue bv = 9;
  google.protobuf.Any any = 10;
  Missing nope = 11;
  string out = 12 [(google.api.field_behavior) = OUTPUT_ONLY];
  bytes blob = 13; fixed64 f = 14; sint32 s = 15; float fl = 16; bool ok = 17;
  oneof pick { string a = 18; int32 b = 19; option x = 1; }
  message Inner { string z = 1; enum E { A = 0; } }
  Inner inner = 20;
  .acme.v1.Geo abs = 21;
  extensions 100 to 199;
  reserved 7;
  group G = 22 { optional string q = 1; }
}
service Svc {
  rpc Create (CreateReq) returns (Empty) { option (google.api.http) = { post: "/v1/things" body: "*" }; }
  rpc Get (Addr) returns (Empty) { option (google.api.http) = { get: "/v1/things/{id}" }; option idempotency_level = NO_SIDE_EFFECTS; }
  rpc Watch (stream Geo) returns (stream Geo);
  rpc Put (Geo) returns (Empty) { option (google.api.http) = { put: "/x" }; }
  rpc Remove (Empty) returns (Empty) { option idempotency_level = IDEMPOTENT; option deprecated = true; }
  rpc Patch (Unknown) returns (Empty) { option (google.api.http) = { patch: "/p" additional_bindings { delete: "/d" } }; }
  rpc Del (Addr) returns (Empty) { option (google.api.http) = { delete: "/v1/things/{id}" body: "x" }; }
}
extend Foo { optional int32 bar = 100; }
service Second { rpc Ping(Empty) returns (Empty); }
`;
for (const [n, opts] of [['base', OPT], ['meta', { ns: 'shop', uri: 'u', now: 7 }], ['lim', { ns: 'api', limits: { max_ref_nodes: 3, max_ref_depth: 1 } }], ['ops', { ns: 'api', limits: { max_ops: 2 } }]] as any[]) await o.run('importGrpc', `proto ${n}`, (s: any, op: any) => P.importGrpc(bytesOf(s), op), [PROTO, opts]);
const pm = (s: any) => pModel(P.parseProto(s));
await o.run('parseProto', 'full', pm, [PROTO]);
const PROTOS = ['', '// c', 'syntax = "proto3";', 'message A {', 'message A { string a = 1 }', 'service S { rpc M(A) returns (B) }', 'service S { rpc M(A) B; }', 'message A { map<string,> m = 1; }', 'enum E { A = 0', '/* open', 'message A { string a = 1; } "x', 'message "A" {}', 'package p; message A { message B { message C {} } }', 'service S { rpc M(stream A) returns (stream B) { option (google.api.http) = { get: "/a" body: "b" }; } }', 'message A { optional string a = 1 [json_name = "x", (a.b) = {c: 1}]; }', 'message A { oneof o { string a = 1; } }', 'message A { oneof o { string a = 1;', 'extend A { }', 'extend A { int32 x = 1; ', 'service S { option (x) = 1; rpc M(A) returns (B) { } }', 'service S { rpc M(A) returns (B) { option (google.api.http) = { get "/a" }; } }', 'message A { string a = 1 [(google.api.field_behavior) = ]; }', "message A { string a = 1 [(f.field_behavior) = REQUIRED]; }", 'message A { int32 a = 0x1F; float b = -1.5e+3; }', 'message A { repeated map<string,string> m = 1; }', '@', 'message A { string a = 1; } service S { rpc M(A) returns (A); } service S { rpc N(A) returns (A); }', 'package a.b; service S { rpc M(.a.b.A) returns (.google.protobuf.Empty); } message A { string x = 1; }', 'service S { rpc M(google.protobuf.Empty) returns (A); }'];
for (const [i, s] of PROTOS.entries()) { await o.run('parseProto', `s${i}`, pm, [s]); await o.run('importGrpc', `s${i}`, (x: any, op: any) => P.importGrpc(bytesOf(x), op), [s, OPT]); }
for (const k of take(Array.from({ length: PROTO.length }, (_, i) => i), 70)) await o.run('parseProto', `cut ${k}`, pm, [PROTO.slice(0, k)]);
for (const ch of ['{', '}', '(', ')', ';', '"', "'", '/*', '//', '=', '<', '>', '[', ']', ',', ':', '#', '\u0000', 'stream ', 'option ']) for (const at of take(Array.from({ length: PROTO.length }, (_, i) => i), 5)) await o.run('parseProto', `ins ${JSON.stringify(ch)} ${at}`, pm, [PROTO.slice(0, at) + ch + PROTO.slice(at)]);
for (const [i, s] of take([...Array(40).keys()].map(() => { const a = R.int(0, PROTO.length - 1), b = R.int(a, Math.min(PROTO.length, a + 40)); return PROTO.slice(0, a) + PROTO.slice(b); }), 30).entries()) await o.run('importGrpc', `del ${i}`, (x: any, op: any) => P.importGrpc(bytesOf(x), op), [s, OPT]);

// ---- binary descriptor set ----
const vi = (n: number): number[] => { const out: number[] = []; while (n > 127) { out.push((n % 128) | 128); n = Math.floor(n / 128); } out.push(n); return out; };
const tg = (f: number, w: number) => vi(f * 8 + w);
const lenf = (f: number, b: number[]) => [...tg(f, 2), ...vi(b.length), ...b];
const strf = (f: number, s: string | Uint8Array) => lenf(f, [...(typeof s === 'string' ? Buffer.from(s) : s)]);
const varf = (f: number, n: number) => [...tg(f, 0), ...vi(n)];
const fld = (name: string, type: number, o: { label?: number; tn?: string; beh?: number[]; packed?: boolean; opt?: boolean } = {}) => lenf(2, [...strf(1, name), ...varf(4, o.label ?? 1), ...varf(5, type), ...(o.tn ? strf(6, o.tn) : []), ...(o.beh ? lenf(8, o.packed ? lenf(1052, o.beh.flatMap((b) => vi(b))) : o.beh.flatMap((b) => varf(1052, b))) : []), ...(o.opt ? varf(17, 1) : [])]);
const enm = (f: number, name: string, vals: string[]) => lenf(f, [...strf(1, name), ...vals.flatMap((v) => lenf(2, strf(1, v)))]);
const nestedMsg = (name: string, fields: number[][], inner: number[] = []) => lenf(3, [...strf(1, name), ...fields.flat(), ...inner]);
const rpc = (name: string, inp: string, out: string, o: { cs?: boolean; ss?: boolean; idem?: number; http?: number[] } = {}) => lenf(2, [...strf(1, name), ...strf(2, inp), ...strf(3, out), ...((o.idem !== undefined || o.http) ? lenf(4, [...(o.idem !== undefined ? varf(34, o.idem) : []), ...(o.http ? lenf(72295728, o.http) : [])]) : []), ...(o.cs ? varf(5, 1) : []), ...(o.ss ? varf(6, 1) : [])]);
const file = (pkg: string | null, parts: number[][]) => lenf(1, [...strf(1, 'f.proto'), ...(pkg !== null ? strf(2, pkg) : []), ...parts.flat()]);
const m1 = lenf(4, [...strf(1, 'Addr'), ...fld('street', 9, { beh: [2] }), ...fld('zip', 5, { opt: true }), ...fld('tags', 9, { label: 3 }), ...fld('geo', 11, { tn: '.acme.Geo' }), ...fld('color', 14, { tn: '.acme.Color' }), ...fld('out', 9, { beh: [3, 5], packed: true }), ...fld('inn', 11, { tn: 'Addr.Inner' }), ...fld('f', 6), ...fld('weird', 10), ...nestedMsg('Inner', [fld('z', 9)]), ...enm(4, 'Kind', ['K0', 'K1'])]);
const m2 = lenf(4, [...strf(1, 'Geo'), ...fld('lat', 1), ...fld('self', 11, { tn: '.acme.Geo' }), ...lenf(3, [...strf(1, 'EntryX'), ...fld('key', 9), ...lenf(7, varf(7, 1))])]);
const DESC = new Uint8Array([
  ...file('acme', [m1, m2, enm(5, 'Color', ['RED', 'GREEN']),
    lenf(6, [...strf(1, 'Svc'), ...rpc('Get', '.acme.Addr', '.acme.Geo', { idem: 1, http: [...strf(2, '/v1/a/{id}')] }), ...rpc('Create', 'Addr', 'Geo', { http: [...strf(4, '/v1/a'), ...strf(7, '*')] }), ...rpc('Watch', '.acme.Geo', '.acme.Geo', { cs: true, ss: true }), ...rpc('Same', '.acme.Geo', '.acme.Geo', { idem: 2, http: [...strf(3, '/p'), ...strf(5, '/ignored'), ...varf(9, 1)] }), ...rpc('Del', '.acme.Addr', '.acme.Geo', { idem: 0, http: [...strf(5, '/d'), ...strf(7, 'b')] }), ...rpc('Unk', '.acme.Nope', '.acme.Geo', { http: [...strf(6, '/q')] })])]),
  ...file(null, [lenf(4, [...strf(1, 'Bare'), ...fld('x', 3)]), lenf(6, [...strf(1, 'BareSvc'), ...rpc('Call', 'Bare', 'Bare')])]),
  ...lenf(1, [...lenf(6, [...strf(1, 'Late'), ...rpc('L', '.late.M', '.late.M')]), ...lenf(4, [...strf(1, 'M'), ...fld('a', 9)]), ...strf(2, 'late')]),
]);
const b64 = (u: Uint8Array | number[]) => ({ $bytes: Buffer.from(u).toString('base64url') });
const pdesc = (x: any) => pModel(P.parseDescriptorSet(bytesOf(x)));
await o.run('parseDescriptorSet', 'full', pdesc, [b64(DESC)]);
for (const [n, opts] of [['base', OPT], ['meta', { ns: 'shop', uri: 'u', now: 7 }], ['lim', { ns: 'api', limits: { max_ref_nodes: 3 } }]] as any[]) await o.run('importGrpc', `desc ${n}`, (s: any, op: any) => P.importGrpc(bytesOf(s), op), [b64(DESC), opts]);
for (const k of take(Array.from({ length: DESC.length }, (_, i) => i), 120)) await o.run('parseDescriptorSet', `cut ${k}`, pdesc, [b64(DESC.slice(0, k))]);
for (const [i, k] of take(Array.from({ length: DESC.length }, (_, i) => i), 90).entries()) { const d = DESC.slice(); d[k] = R.int(0, 255); await o.run('parseDescriptorSet', `flip ${k}/${i}`, pdesc, [b64(d)]); }
for (const [i, k] of take(Array.from({ length: DESC.length }, (_, i) => i), 30).entries()) { const d = DESC.slice(); d[k] = R.int(0, 255); await o.run('importGrpc', `flip ${k}/${i}`, (s: any, op: any) => P.importGrpc(bytesOf(s), op), [b64(d), OPT]); }
const HB: [string, number[]][] = [['empty', []], ['overlong', Array(11).fill(0x80)], ['wt3', [0x0b, 0x01]], ['wt7', [0x0f]], ['len big', [0x0a, 0xff, 0xff, 0x03]], ['skip fixed', [...tg(9, 1), 1, 2, 3, 4, 5, 6, 7, 8, ...tg(10, 5), 1, 2, 3, 4]], ['skip varint', [...varf(9, 300)]], ['bom name', [...lenf(1, [...strf(1, 'f'), ...strf(2, new Uint8Array([0xef, 0xbb, 0xbf, 0x70])), ...lenf(4, [...strf(1, new Uint8Array([0xef, 0xbb, 0xbf, 0x4d, 0xff, 0xc0, 0x80, 0xe2, 0x82]))])])]], ['bad utf8', [...lenf(1, [...strf(2, new Uint8Array([0xf0, 0x9f, 0x98, 0x80, 0xed, 0xa0, 0x80, 0xc3, 0x28, 0xf4, 0x90, 0x80, 0x80]))])]]];
for (const [n, b] of HB) { await o.run('parseDescriptorSet', `h ${n}`, pdesc, [b64(b)]); await o.run('importGrpc', `h ${n}`, (s: any, op: any) => P.importGrpc(bytesOf(s), op), [b64(b), OPT]); }
for (let i = 0; i < 40; i++) { const len = R.int(1, 60); const b = Array.from({ length: len }, () => R.int(0, 255)); await o.run('parseDescriptorSet', `rand ${i}`, pdesc, [b64(b)]); }
for (const x of [5, null, [], {}, true]) await o.run('importGrpc', `badsrc ${JSON.stringify(x)}`, (s: any, op: any) => P.importGrpc(bytesOf(s), op), [x, OPT]);
// deep nesting
const deepMsg = (n: number): number[] => (n === 0 ? [...strf(1, 'L0'), ...fld('v', 9)] : [...strf(1, `L${n}`), ...nestedMsg(`L${n - 1}`, [], []).slice(0, 0), ...lenf(3, deepMsg(n - 1))]);
await o.run('parseDescriptorSet', 'deep 20', pdesc, [b64(file('d', [lenf(4, deepMsg(20))]))]);
await o.run('parseDescriptorSet', 'deep 33', pdesc, [b64(file('d', [lenf(4, deepMsg(33))]))]);
refWrite(o, 'actions-import-sdl');
