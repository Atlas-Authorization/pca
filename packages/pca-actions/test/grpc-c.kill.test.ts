// The gRPC importer's readers must step over fields they do not know, at every level of the descriptor and in the option block of a
// .proto rpc. Every input is built inside its test (input decoded when the file is collected earns no test any credit).
//
// An unknown field is written in every wire type with a payload that is itself a valid known field of the level it sits in: a reader that
// fails to skip the field reads that payload as a known field and corrupts the model, where a reader that merely mis-steps over junk would
// often land back on the next field by luck.
import { describe, expect, it } from 'vitest';
import { ActionKitError, parseDescriptorSet, parseProto } from '../src';

const vi = (n: number): number[] => { const o: number[] = []; let v = n; while (v >= 128) { o.push((v % 128) | 128); v = Math.floor(v / 128); } o.push(v); return o; };
const tg = (f: number, wt: number): number[] => vi(f * 8 + wt);
const ld = (f: number, b: number[]): number[] => [...tg(f, 2), ...vi(b.length), ...b];
const S = (f: number, s: string): number[] => ld(f, [...new TextEncoder().encode(s)]);
const I = (f: number, n: number): number[] => [...tg(f, 0), ...vi(n)];
const pad = (b: number[], n: number): number[] => [...b, ...new Array<number>(n - b.length).fill(0)];
/** Field 99 (known to nobody) once in each wire type; `p` (at most 4 bytes) is a valid known field of the level it is written at. */
const unk = (p: number[]): number[] => [...ld(99, p), ...tg(99, 1), ...pad(p, 8), ...tg(99, 5), ...pad(p, 4), ...tg(99, 0), 10];

describe('descriptor set: unknown fields are skipped at every level', () => {
  const build = (): Uint8Array => {
    const enumE = [...S(1, 'E'), ...unk(S(1, 'Z')), ...ld(2, [...S(1, 'V1'), ...unk(S(1, 'Z'))]), ...ld(2, S(1, 'V2'))];
    const field = [...S(1, 'f'), ...unk(S(1, 'Z')), ...I(5, 9), ...ld(8, [...I(1052, 2), ...unk(I(1052, 3))])];
    const msg = [...S(1, 'M'), ...unk(S(1, 'Z')), ...ld(2, field), ...ld(7, [...I(7, 0), ...unk(I(7, 1))])];
    const method = [
      ...S(1, 'Op'), ...unk(S(1, 'Z')), ...S(2, '.pk.M'), ...S(3, '.pk.M'),
      ...ld(4, [...unk(I(34, 1)), ...ld(72295728, [...unk(S(2, '/z')), ...S(3, '/real')])]),
      ...ld(99, I(34, 1)), // an unknown length-delimited field is not the option block
    ];
    const svc = [...S(1, 'Svc'), ...unk(S(1, 'Z')), ...ld(2, method)];
    const file = [...S(1, 'f.proto'), ...S(2, 'pk'), ...unk(S(2, 'q')), ...ld(4, msg), ...ld(5, enumE), ...ld(6, svc)];
    return Uint8Array.from(ld(1, file));
  };
  it('reads every known field around unknown ones of each wire type', () => {
    const m = parseDescriptorSet(build());
    expect(Object.fromEntries(m.enums)).toEqual({ 'pk.E': { full: 'pk.E', values: ['V1', 'V2'] } });
    expect(Object.fromEntries(m.messages)).toEqual({
      'pk.M': { full: 'pk.M', mapEntry: false, fields: [{ name: 'f', scope: 'pk.M', repeated: false, optional: false, type: 'string', behavior: ['REQUIRED'] }] },
    });
    expect(m.services).toEqual([
      {
        full: 'pk.Svc', name: 'Svc',
        methods: [{ name: 'Op', input: '.pk.M', output: '.pk.M', cs: false, ss: false, scope: 'pk', http: { method: 'PUT', path: '/real' } }],
      },
    ]);
  });
});

describe('proto text: the rpc option block', () => {
  const httpOf = (opts: string) => parseProto(`syntax = "proto3"; package p; message X {} service S { rpc A(X) returns (X) { option (google.api.http) = { ${opts} }; } }`).services[0]!.methods[0]!.http;
  it('a body that is not a string, or has no verb before it, is not recorded', () => {
    expect(httpOf('post: "/a" body: foo')).toEqual({ method: 'POST', path: '/a' });
    expect(httpOf('post: "/a" body: "*"')).toEqual({ method: 'POST', path: '/a', body: '*' });
    expect(httpOf('body: "*"')).toBeUndefined();
  });
  it('an option that ends where a body value should be is unterminated', () => {
    const run = (text: string) => { try { parseProto(text); } catch (e) { return e instanceof ActionKitError ? e.message : `TypeError: ${String(e)}`; } return 'no error'; };
    const head = 'syntax = "proto3"; package p; message X {} service S { rpc A(X) returns (X) { option (google.api.http) = { post: "/a" body:';
    expect(run(head)).toMatch(/unterminated option/);
    // the brace after `body:` is taken as the value, so the option closes on the next brace and the rpc body is what runs out
    expect(run(`${head} } };`)).toMatch(/unterminated rpc body/);
  });
});

describe('proto text: stream is a keyword, never a string', () => {
  it('a string that reads stream is not the stream marker', () => {
    expect(() => parseProto('syntax = "proto3"; package p; message X {} service S { rpc A("stream" X) returns (X); }')).toThrow(ActionKitError);
    expect(() => parseProto('syntax = "proto3"; package p; message X {} service S { rpc A(X) returns ("stream" X); }')).toThrow(ActionKitError);
    const ok = parseProto('syntax = "proto3"; package p; message X {} service S { rpc A(stream X) returns (stream X); }');
    expect([ok.services[0]!.methods[0]!.cs, ok.services[0]!.methods[0]!.ss]).toEqual([true, true]);
  });
});
