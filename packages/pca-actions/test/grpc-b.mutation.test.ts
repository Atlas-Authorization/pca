// Descriptor-set decoding and model-to-params mapping of the gRPC importer: exact models, wire-level edge cases, exact todos.
import { describe, expect, it } from 'vitest';
import { ActionKitError, importGrpc, parseDescriptorSet, verbOf, type ActionDef, type ImportReport } from '../src';

// ---- a tiny protobuf encoder ---------------------------------------------------------------------------------------------
const vi = (n: number): number[] => { const o: number[] = []; let v = n; while (v >= 128) { o.push((v % 128) | 128); v = Math.floor(v / 128); } o.push(v); return o; };
const tg = (f: number, wt: number): number[] => vi(f * 8 + wt);
const ld = (f: number, b: number[]): number[] => [...tg(f, 2), ...vi(b.length), ...b];
const S = (f: number, s: string): number[] => ld(f, [...new TextEncoder().encode(s)]);
const I = (f: number, n: number): number[] => [...tg(f, 0), ...vi(n)];
const fx = (f: number, wt: number, n: number): number[] => [...tg(f, wt), ...new Array<number>(n).fill(7)];
// unknown fields of every wire type: they must be skipped exactly, and never mistaken for a known field
const junk = (): number[] => [...I(99, 300), ...fx(99, 1, 8), ...fx(99, 5, 4), ...ld(99, [7, 7, 7])];
const u8 = (b: number[]): Uint8Array => Uint8Array.from(b);
const err = (f: () => unknown): unknown => { try { f(); } catch (e) { return e instanceof ActionKitError ? { code: e.code, message: e.message } : String(e); } return 'no error'; };

describe('descriptor set: the full model', () => {
  const fieldId = [...I(8, 2), ...S(1, 'zz'), ...S(1, 'id'), ...I(3, 1), ...I(4, 1), ...I(5, 9),
    ...ld(8, [...I(1052, 2), ...ld(1052, [3, 4]), ...ld(5, [5]), ...I(7, 3), ...fx(1052, 5, 4), ...ld(1052, [])]),
    ...I(1, 0), ...ld(5, []), ...junk()];
  const fieldTags = [...S(1, 'tags'), ...I(4, 3), ...I(5, 14), ...S(6, '.p.q.Color'), ...I(17, 1), ...ld(8, [...ld(1052, [5, 9, 1])]), ...ld(4, []), ...I(6, 0), ...ld(17, [])];
  const fieldPlain = [...S(1, 'plain'), ...I(17, 0)];
  const msgInner = [...S(1, 'Inner'), ...ld(2, [...S(1, 'x'), ...I(5, 5)]), ...ld(3, S(1, 'Deep')), ...ld(4, [...S(1, 'Kind'), ...ld(2, S(1, 'K1'))])];
  const enumMode = [...S(1, 'Mode'), ...ld(2, S(1, 'M1')), ...ld(2, S(1, 'M2'))];
  const msgOuter = [...I(7, 2), ...S(1, 'JJ'), ...S(1, 'Outer'), ...ld(2, fieldId), ...ld(2, fieldTags), ...ld(2, fieldPlain), ...ld(2, []),
    ...ld(3, msgInner), ...ld(4, enumMode), ...I(1, 0), ...I(2, 0), ...I(3, 0), ...I(4, 0), ...junk()];
  const msgMap = [...S(1, 'MapEntryMsg'), ...ld(7, [...I(7, 1), ...junk(), ...ld(7, [])])];
  const msgNot = [...S(1, 'NotMap'), ...ld(7, [...I(7, 0), ...I(8, 1)])];
  const msgT = [...S(1, 'T'), ...Array.from({ length: 19 }, (_, k) => ld(2, [...S(1, `t${k + 1}`), ...I(5, k + 1)])).flat()];
  const enumColor = [...I(2, 4), ...S(1, 'JJ'), ...S(1, 'Color'), ...ld(2, [...S(1, 'RED'), ...I(2, 0), ...junk(), ...I(1, 0)]), ...ld(2, S(1, 'GREEN')), ...I(1, 0), ...junk()];
  const method = (body: number[]): number[] => ld(2, body);
  const http = (...b: number[][]): number[] => ld(4, ld(72295728, b.flat()));
  const svcBody = [
    ...S(1, 'Svc'),
    ...method([...I(4, 2), ...S(1, 'JJ'), ...S(1, 'Get'), ...S(2, '.p.q.Req'), ...S(3, '.p.q.Resp'), ...I(5, 1), ...I(6, 1),
      ...ld(4, [...I(34, 1), ...ld(72295728, [...S(2, '/g'), ...S(4, '/ignored'), ...S(7, '*'), ...S(1, 'zz'), ...junk()]), ...I(72295728, 3), ...I(34, 2), ...ld(34, []), ...junk()]),
      ...I(1, 0), ...I(2, 0), ...I(3, 0)]),
    ...method([...S(1, 'Dec'), ...S(2, '.p.q.Req'), ...S(3, '.p.q.Req'), ...http(I(2, 0), S(4, '/real'), I(7, 0))]),
    ...method([...S(1, 'Put'), ...http(S(3, '/p'))]),
    ...method([...S(1, 'Del'), ...http(S(5, '/d'))]),
    ...method([...S(1, 'Patch'), ...http(S(6, '/pa'))]),
    ...method([...S(1, 'BodyFirst'), ...http(S(7, '*'), S(4, '/b'))]),
    ...method([...S(1, 'Nse'), ...ld(4, I(34, 1))]),
    ...method([...S(1, 'Idem0'), ...ld(4, I(34, 0))]),
    ...method([...S(1, 'Cs'), ...I(5, 1), ...ld(5, [])]),
    ...method([...S(1, 'Ss'), ...I(6, 1), ...ld(6, [])]),
    ...ld(2, []),
    ...I(1, 0), ...I(2, 0), ...junk(),
  ];
  const fileP = [...S(1, 'p.proto'), ...ld(4, msgOuter), ...ld(4, msgMap), ...ld(4, msgNot), ...ld(4, msgT), ...ld(5, enumColor), ...ld(6, svcBody),
    ...S(2, 'p.q'), ...I(2, 0), ...I(4, 0), ...I(5, 0), ...I(6, 0), ...junk()];
  const fileBare = [...S(1, 'bare.proto'), ...ld(4, [...S(1, 'Bare'), ...ld(2, [...S(1, 'f'), ...I(5, 9)])]), ...ld(5, [...S(1, 'BareEnum'), ...ld(2, S(1, 'V'))]),
    ...ld(6, [...S(1, 'BareSvc'), ...ld(2, [...S(1, 'Op'), ...S(2, 'Bare')])])];
  const fileE = [...S(2, 'e'), ...ld(4, []), ...ld(5, []), ...ld(6, [])];
  const top = [...I(1, 5), ...ld(2, [...S(1, 'x'), ...ld(4, S(1, 'TopJunk'))]), ...junk(), ...ld(1, fileP), ...ld(1, fileBare), ...junk(), ...ld(1, fileE)];
  const m = parseDescriptorSet(u8(top));

  const fld = (scope: string, name: string, type: string, o: object = {}) => ({ name, scope, repeated: false, optional: false, type, behavior: [], ...o });
  const msg = (full: string, fields: object[], mapEntry = false) => ({ full, mapEntry, fields });
  const meth = (o: object) => ({ name: '', input: '', output: '', cs: false, ss: false, scope: 'p.q', ...o });

  it('decodes messages, nesting, fields, behaviors, map entries and every scalar type', () => {
    const T = ['double', 'float', 'int64', 'uint64', 'int32', 'fixed64', 'fixed32', 'bool', 'string', 'bytes', 'bytes', 'bytes', 'uint32', 'bytes', 'sfixed32', 'sfixed64', 'sint32', 'sint64', 'bytes'];
    expect(Object.fromEntries(m.messages)).toEqual({
      'p.q.Outer': msg('p.q.Outer', [
        fld('p.q.Outer', 'id', 'string', { behavior: ['REQUIRED', 'OUTPUT_ONLY', 'INPUT_ONLY'] }),
        fld('p.q.Outer', 'tags', '.p.q.Color', { repeated: true, optional: true, behavior: ['IMMUTABLE', '', ''] }),
        fld('p.q.Outer', 'plain', 'bytes'),
        fld('p.q.Outer', '', 'bytes'),
      ]),
      'p.q.Outer.Inner': msg('p.q.Outer.Inner', [fld('p.q.Outer.Inner', 'x', 'int32')]),
      'p.q.Outer.Inner.Deep': msg('p.q.Outer.Inner.Deep', []),
      'p.q.MapEntryMsg': msg('p.q.MapEntryMsg', [], true),
      'p.q.NotMap': msg('p.q.NotMap', []),
      'p.q.T': msg('p.q.T', T.map((t, k) => fld('p.q.T', `t${k + 1}`, t))),
      Bare: msg('Bare', [fld('Bare', 'f', 'string')]),
      'e.': msg('e.', []),
    });
  });

  it('decodes enums, including nested ones and a file with no package', () => {
    expect(Object.fromEntries(m.enums)).toEqual({
      'p.q.Color': { full: 'p.q.Color', values: ['RED', 'GREEN'] },
      'p.q.Outer.Mode': { full: 'p.q.Outer.Mode', values: ['M1', 'M2'] },
      'p.q.Outer.Inner.Kind': { full: 'p.q.Outer.Inner.Kind', values: ['K1'] },
      BareEnum: { full: 'BareEnum', values: ['V'] },
      'e.': { full: 'e.', values: [] },
    });
  });

  it('decodes services, methods, http rules (first verb wins, body only after a verb) and idempotency levels', () => {
    expect(m.services).toEqual([
      {
        full: 'p.q.Svc', name: 'Svc', methods: [
          meth({ name: 'Get', input: '.p.q.Req', output: '.p.q.Resp', cs: true, ss: true, idem: 'IDEMPOTENT', http: { method: 'GET', path: '/g', body: '*' } }),
          meth({ name: 'Dec', input: '.p.q.Req', output: '.p.q.Req', http: { method: 'POST', path: '/real' } }),
          meth({ name: 'Put', http: { method: 'PUT', path: '/p' } }),
          meth({ name: 'Del', http: { method: 'DELETE', path: '/d' } }),
          meth({ name: 'Patch', http: { method: 'PATCH', path: '/pa' } }),
          meth({ name: 'BodyFirst', http: { method: 'POST', path: '/b' } }),
          meth({ name: 'Nse', idem: 'NO_SIDE_EFFECTS' }),
          meth({ name: 'Idem0', idem: 'IDEMPOTENCY_UNKNOWN' }),
          meth({ name: 'Cs', cs: true }),
          meth({ name: 'Ss', ss: true }),
          meth({}),
        ],
      },
      { full: 'BareSvc', name: 'BareSvc', methods: [{ name: 'Op', input: 'Bare', output: '', cs: false, ss: false, scope: '' }] },
      { full: 'e.', name: '', methods: [] },
    ]);
  });
});

describe('descriptor set: wire format edges', () => {
  it('reads multi-byte lengths (2 and 3 byte varints) and 127/128 byte boundaries', () => {
    const names = ['a'.repeat(300), 'b'.repeat(20000), 'c'.repeat(128), 'd'.repeat(127)];
    const m = parseDescriptorSet(u8(ld(1, [...S(2, 'p'), ...names.flatMap((n) => ld(4, S(1, n)))])));
    expect([...m.messages.keys()]).toEqual(names.map((n) => `p.${n}`));
  });
  it('decodes invalid UTF-8 leniently', () => {
    const m = parseDescriptorSet(u8(ld(1, [...S(2, 'u'), ...ld(4, ld(1, [0x41, 0xff]))])));
    expect([...m.messages.keys()]).toEqual(['u.A�']);
  });
  it('a 10 byte varint is a valid tag; 10 continuation bytes are overlong', () => {
    expect([...parseDescriptorSet(u8([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00])).messages.keys()]).toEqual([]);
    const over = { code: 'bad_source', message: 'overlong varint in descriptor' };
    expect(err(() => importGrpc(u8(new Array<number>(10).fill(0x80)), { ns: 'g' }))).toEqual(over);
    expect(err(() => importGrpc(u8([...new Array<number>(10).fill(0x80), 0x01]), { ns: 'g' }))).toEqual(over);
  });
  it('truncation and length errors', () => {
    const trunc = { code: 'bad_source', message: 'truncated descriptor' };
    expect(err(() => importGrpc(u8([0x08]), { ns: 'g' }))).toEqual(trunc);
    expect(err(() => importGrpc(u8([0x80]), { ns: 'g' }))).toEqual(trunc);
    expect(err(() => importGrpc(u8([...tg(9, 1), ...new Array<number>(7).fill(1)]), { ns: 'g' }))).toEqual(trunc);
    expect(err(() => importGrpc(u8([...tg(9, 5), 1, 1, 1]), { ns: 'g' }))).toEqual(trunc);
    expect(importGrpc(u8([...tg(9, 1), ...new Array<number>(8).fill(1)]), { ns: 'g' }).defs).toEqual([]);
    expect(importGrpc(u8([...tg(9, 5), 1, 1, 1, 1]), { ns: 'g' }).defs).toEqual([]);
    const len = { code: 'bad_source', message: 'descriptor length exceeds the buffer' };
    expect(err(() => importGrpc(u8([...ld(1, [...tg(4, 2), 10, 1, 2]), ...new Array<number>(12).fill(0)]), { ns: 'g' }))).toEqual(len);
    expect(err(() => importGrpc(u8([...tg(9, 2), 5, 1, 1]), { ns: 'g' }))).toEqual(len);
  });
  it('unsupported wire types are named', () => {
    expect(err(() => importGrpc(u8([0x0b]), { ns: 'g' }))).toEqual({ code: 'bad_source', message: 'unsupported wire type 3 in descriptor' });
    expect(err(() => importGrpc(u8([0x0e]), { ns: 'g' }))).toEqual({ code: 'bad_source', message: 'unsupported wire type 6 in descriptor' });
  });
  it('message nesting is bounded at 32 levels below the top', () => {
    const chain = (n: number): number[] => [...S(1, 'M'), ...(n > 0 ? ld(3, chain(n - 1)) : [])];
    expect(parseDescriptorSet(u8(ld(1, ld(4, chain(32))))).messages.size).toBe(33);
    expect(err(() => parseDescriptorSet(u8(ld(1, ld(4, chain(33))))))).toEqual({ code: 'import_limit', message: 'descriptor message nesting is too deep' });
  });
  it('a source that is neither text nor bytes is refused with a code', () => {
    expect(err(() => importGrpc(42, { ns: 'g' }))).toEqual({ code: 'bad_source', message: 'a gRPC source is .proto text or a binary FileDescriptorSet' });
  });
});

// ---- model -> params and defs --------------------------------------------------------------------------------------------
const run = (proto: string, limits?: object): ImportReport => importGrpc(proto, { ns: 't', ...(limits ? { limits } : {}) });
const byMethod = (r: ImportReport, name: string): ActionDef => {
  const d = r.defs.find((x) => (x.bindings as unknown as Record<string, { method?: string }> | undefined)?.grpc?.method === name);
  if (!d) throw new Error(`no def for ${name}`);
  return d;
};
const B = (d: ActionDef) => d.bindings as unknown as Record<string, unknown>;

describe('importGrpc: effects, idempotency, bindings, streaming', () => {
  const proto = `syntax = "proto3"; package t.v1; message E {} message Leafy { string v = 1; }
    service Svc {
      rpc ByGet(E) returns (E) { option (google.api.http) = { get: "/a" }; }
      rpc ByPut(E) returns (E) { option (google.api.http) = { put: "/b" }; }
      rpc ByPost(E) returns (E) { option (google.api.http) = { post: "/c" }; }
      rpc ByPatch(E) returns (E) { option (google.api.http) = { patch: "/d" }; }
      rpc ByDelete(E) returns (E) { option (google.api.http) = { delete: "/e" }; }
      rpc ByNse(E) returns (E) { option idempotency_level = NO_SIDE_EFFECTS; }
      rpc ByIdem(E) returns (E) { option idempotency_level = IDEMPOTENT; }
      rpc ByNone(E) returns (E);
      rpc ByUnknown(E) returns (E) { option idempotency_level = IDEMPOTENCY_UNKNOWN; }
      rpc ByPostNse(E) returns (E) { option idempotency_level = NO_SIDE_EFFECTS; option (google.api.http) = { post: "/f" }; }
      rpc ByPutNse(E) returns (E) { option idempotency_level = NO_SIDE_EFFECTS; option (google.api.http) = { put: "/g" }; }
      rpc ByPatchNse(E) returns (E) { option idempotency_level = NO_SIDE_EFFECTS; option (google.api.http) = { patch: "/h" }; }
      rpc NoPath(E) returns (E) { option (google.api.http) = { get: "" }; }
      rpc GetBalance(E) returns (E);
      rpc Dotted(.t.v1.Leafy) returns (.t.v1.Leafy);
      rpc Ping(google.protobuf.Empty) returns (google.protobuf.Empty);
    }`;
  const r = run(proto);
  it('maps http verbs and idempotency levels to effects and natural idempotency', () => {
    const rows: [string, string, boolean][] = [
      ['ByGet', 'read', true], ['ByPut', 'update', true], ['ByPost', 'create', false], ['ByPatch', 'update', false], ['ByDelete', 'delete', true],
      ['ByNse', 'read', true], ['ByIdem', 'update', true], ['ByNone', 'update', false], ['ByUnknown', 'update', false],
      ['ByPostNse', 'create', true], ['ByPutNse', 'update', true], ['ByPatchNse', 'update', true],
    ];
    for (const [name, effect, natural] of rows) {
      const d = byMethod(r, name);
      expect([name, d.effects]).toEqual([name, [effect]]);
      expect([name, d.idempotency]).toEqual([name, natural ? { mode: 'natural' } : undefined]);
    }
  });
  it('binds service, method and the http rule only when it has a path', () => {
    expect(byMethod(r, 'ByGet').bindings).toEqual({ grpc: { service: 't.v1.Svc', method: 'ByGet' }, http: { method: 'GET', path: '/a' } });
    expect(byMethod(r, 'ByPatchNse').bindings).toEqual({ grpc: { service: 't.v1.Svc', method: 'ByPatchNse' }, http: { method: 'PATCH', path: '/h' } });
    expect(byMethod(r, 'NoPath').bindings).toEqual({ grpc: { service: 't.v1.Svc', method: 'NoPath' } });
    expect(byMethod(r, 'NoPath').effects).toEqual(['read']);
    expect(byMethod(r, 'ByNone').bindings).toEqual({ grpc: { service: 't.v1.Svc', method: 'ByNone' } });
  });
  it('names the verb from service and method, and spaces the title at case changes', () => {
    const d = byMethod(r, 'GetBalance');
    expect(d.verb).toBe(verbOf('t', 'Svc GetBalance'));
    expect(d.title).toBe('Get Balance');
    expect(d.verb).not.toBe('t.op');
    expect(Object.keys(B(d))).toEqual(['grpc']);
  });
  it('resolves a leading-dot request type and knows the well-known request types', () => {
    expect(byMethod(r, 'Dotted').params).toEqual({ v: { type: 'string', required: false } });
    expect(byMethod(r, 'Ping').params).toEqual({});
    expect(r.todo.filter((t) => t.code === 'unknown_type')).toEqual([]);
  });
  it('streaming methods get pca.bulk and a note; unary ones neither', () => {
    const s = run(`syntax = "proto3"; package t.v1; message E {}
      service Svc { rpc A(stream E) returns (E); rpc B(E) returns (stream E); rpc C(stream E) returns (stream E); rpc D(E) returns (E); }`);
    for (const n of ['A', 'B', 'C']) expect([n, byMethod(s, n).traits]).toEqual([n, ['pca.bulk']]);
    expect(byMethod(s, 'D').traits).toBeUndefined();
    const note = 'a streaming method: acts on many messages (pca.bulk added)';
    expect(s.todo.filter((t) => t.code === 'streaming')).toEqual(['A', 'B', 'C'].map((n) => ({ where: `Svc/${n}`, code: 'streaming', message: note })));
  });
  it('emits services and methods in name order, whatever the declaration order', () => {
    const s = run(`syntax = "proto3"; package t.v1; message E {}
      service Zed { rpc Bb(E) returns (E); rpc Aa(E) returns (E); }
      service Alpha { rpc Bb(E) returns (E); rpc Aa(E) returns (E); }`);
    expect(s.defs.map((d) => [(B(d).grpc as { service: string }).service, (B(d).grpc as { method: string }).method])).toEqual([
      ['t.v1.Alpha', 'Aa'], ['t.v1.Alpha', 'Bb'], ['t.v1.Zed', 'Aa'], ['t.v1.Zed', 'Bb'],
    ]);
  });
  it('an unknown request type is noted with its name and gives no parameters', () => {
    const s = run('syntax = "proto3"; package t.v1; service Svc { rpc Call(Missing) returns (Missing); rpc Dot(.x.Gone) returns (.x.Gone); }');
    expect(byMethod(s, 'Call').params).toEqual({});
    expect(s.todo).toEqual([
      { where: 'Svc/Call', code: 'unknown_type', message: "request type 'Missing' is not defined in the source (no parameters)" },
      { where: 'Svc/Dot', code: 'unknown_type', message: "request type '.x.Gone' is not defined in the source (no parameters)" },
    ]);
  });
});

describe('importGrpc: field types to params', () => {
  it('maps every scalar type', () => {
    const r = run(`syntax = "proto3"; package t.v1;
      message Scalars { double a = 1; float b = 2; int32 c = 3; int64 d = 4; uint32 e = 5; uint64 f = 6; sint32 g = 7; sint64 h = 8; fixed32 i = 9; fixed64 j = 10; sfixed32 k = 11; sfixed64 l = 12; bool m = 13; string n = 14; bytes o = 15; }
      service Svc { rpc DoScalars(Scalars) returns (Scalars); }`);
    const int = { type: 'integer', required: false };
    expect(byMethod(r, 'DoScalars').params).toEqual({
      a: { type: 'string', required: false }, b: { type: 'string', required: false },
      c: int, d: int, e: int, f: int, g: int, h: int, i: int, j: int, k: int, l: int,
      m: { type: 'boolean', required: false }, n: { type: 'string', required: false }, o: { type: 'string', required: false },
    });
    const fr = "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)";
    expect(r.todo).toEqual([{ where: 'Svc/DoScalars: a', code: 'unsupported_type', message: fr }, { where: 'Svc/DoScalars: b', code: 'unsupported_type', message: fr }]);
  });
  it('maps well-known types, with and without a leading dot', () => {
    const r = run(`syntax = "proto3"; package t.v1;
      message W { google.protobuf.Timestamp ts1 = 1; .google.protobuf.Timestamp ts2 = 2; google.protobuf.StringValue sv1 = 3; .google.protobuf.StringValue sv2 = 4; google.protobuf.BytesValue bv = 5;
        google.protobuf.Int32Value i1 = 6; .google.protobuf.Int64Value i2 = 7; google.protobuf.UInt32Value i3 = 8; google.protobuf.UInt64Value i4 = 9;
        google.protobuf.BoolValue b1 = 10; .google.protobuf.BoolValue b2 = 11; google.protobuf.Duration d1 = 12; .google.protobuf.Any d2 = 13; }
      service Svc { rpc DoWkt(W) returns (W); }`);
    const dt = { type: 'datetime', required: false }, str = { type: 'string', required: false }, int = { type: 'integer', required: false }, bool = { type: 'boolean', required: false };
    expect(byMethod(r, 'DoWkt').params).toEqual({ ts1: dt, ts2: dt, sv1: str, sv2: str, bv: str, i1: int, i2: int, i3: int, i4: int, b1: bool, b2: bool, d1: str, d2: str });
    const none = "type 'none' has no representation (declared string; refine or drop)";
    expect(r.todo).toEqual([{ where: 'Svc/DoWkt: d1', code: 'unsupported_type', message: none }, { where: 'Svc/DoWkt: d2', code: 'unsupported_type', message: none }]);
  });
  it('maps enums, repeated, maps, nested and unknown types, and field behavior', () => {
    const r = run(`syntax = "proto3"; package t.v1;
      enum Color { RED = 0; GREEN = 1; RED = 2; }
      message Leaf { string v = 1; }
      message Inner { string x = 1; Missing nope = 2; }
      message Req {
        Color color = 1; repeated Color colors = 2; repeated int32 nums = 3; repeated bool flags = 4; repeated string tags = 5; repeated Leaf leaves = 6;
        map<string, string> labels = 7; Missing m = 8; Inner inner = 9;
        string id = 10 [(google.api.field_behavior) = REQUIRED];
        string out = 11 [(google.api.field_behavior) = OUTPUT_ONLY];
        string inp = 12 [(google.api.field_behavior) = INPUT_ONLY];
        string both = 13 [(google.api.field_behavior) = REQUIRED, (google.api.field_behavior) = INPUT_ONLY];
      }
      service Svc { rpc Call(Req) returns (Req); }`);
    const opt = { type: 'string', required: false };
    expect(byMethod(r, 'Call').params).toEqual({
      both: { type: 'string' }, id: { type: 'string' },
      color: { type: 'string', required: false, values: ['RED', 'GREEN'] },
      colors: { type: 'array', required: false, items: 'string' },
      flags: { type: 'array', required: false, items: 'boolean' },
      nums: { type: 'array', required: false, items: 'integer' },
      tags: { type: 'array', required: false, items: 'string' },
      leaves: { type: 'array', required: false },
      'inner.nope': opt, 'inner.x': opt, inp: opt, labels: opt, m: opt,
    });
    const unk = "type 'Missing' is not defined in the proto source (declared string)";
    expect(r.todo).toContainEqual({ where: 'Svc/Call.m', code: 'unknown_type', message: unk });
    expect(r.todo).toContainEqual({ where: 'Svc/Call.inner.nope', code: 'unknown_type', message: unk });
    expect(r.todo).toContainEqual({ where: 'Svc/Call: labels', code: 'object_leaf', message: 'an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)' });
    expect(r.todo).toContainEqual({ where: 'Svc/Call: leaves', code: 'array_items', message: "array items of type 'object' are not declared (items left open)" });
    expect(r.todo).toContainEqual({ where: 'Svc/Call: m', code: 'unsupported_type', message: "type 'none' has no representation (declared string; refine or drop)" });
  });
  it('a recursive message is declared a string and noted', () => {
    const r = run('syntax = "proto3"; package t.v1; message Node { Node next = 1; string v = 2; } service Svc { rpc Walk(Node) returns (Node); }');
    expect(byMethod(r, 'Walk').params).toEqual({ next: { type: 'string', required: false }, v: { type: 'string', required: false } });
    expect(r.todo).toContainEqual({ where: 'Svc/Walk.next', code: 'cyclic_ref', message: "message 't.v1.Node' is recursive (declared string; refine or drop)" });
  });
  it('a message that is not in scope under a bare name only resolves through the package walk', () => {
    // a descriptor message literally named '.X' must not capture the request type 'X'
    const bytes = u8(ld(1, [...ld(4, [...S(1, '.X'), ...ld(2, [...S(1, 'v'), ...I(5, 9)])]), ...ld(6, [...S(1, 'Svc'), ...ld(2, [...S(1, 'Call'), ...S(2, 'X'), ...S(3, 'X')])])]));
    const r = importGrpc(bytes, { ns: 't' });
    expect(r.defs[0]!.params).toEqual({});
    expect(r.todo).toEqual([{ where: 'Svc/Call', code: 'unknown_type', message: "request type 'X' is not defined in the source (no parameters)" }]);
  });
});

describe('importGrpc: expansion bounds', () => {
  const chain = `syntax = "proto3"; package t.v1;
    message M3 { string v = 1; } message M2 { M3 n = 1; } message M1 { M2 n = 1; } message R { M1 n = 1; }
    service S { rpc Call(R) returns (R); }`;
  const note = 'message expansion stopped at the bound (declared string; refine or drop)';
  const stops = (r: ImportReport) => r.todo.filter((t) => t.code === 'ref_budget' && t.message === note);
  it('default limits expand a short chain fully', () => {
    expect(stops(run(chain))).toEqual([]);
  });
  it('stops past max_ref_depth, exactly at the bound', () => {
    expect(stops(run(chain, { max_ref_depth: 2 }))).toEqual([{ where: 'S/Call.n.n.n', code: 'ref_budget', message: note }]);
  });
  it('stops when the node budget is spent, exactly at the bound', () => {
    expect(stops(run(chain, { max_ref_nodes: 3 }))).toEqual([{ where: 'S/Call.n.n', code: 'ref_budget', message: note }]);
  });
});
