// Mutation-kill tests for the gRPC importer: a binary descriptor decoder that stops skipping unknown fields, and the .proto http-option body reader.
import { describe, expect, it } from 'vitest';
import { ActionKitError, parseDescriptorSet, parseProto } from '../index';

const vr = (n: number): number[] => { const o: number[] = []; let v = n; while (v >= 128) { o.push((v % 128) | 128); v = Math.floor(v / 128); } o.push(v); return o; };
const tg = (f: number, wt: number): number[] => vr(f * 8 + wt);
const ld = (f: number, b: number[]): number[] => [...tg(f, 2), ...vr(b.length), ...b];
const S = (f: number, s: string): number[] => ld(f, [...new TextEncoder().encode(s)]);
const I = (f: number, n: number): number[] => [...tg(f, 0), ...vr(n)];
// An unknown length-delimited field (99) whose LENGTH is `tagValue`: if the skip is missing, the length varint is re-read as the tag
// `tagValue`, and the payload (`head`, then zero padding that reads as harmless no-op tags) is read as that known field's content.
const lure = (tagValue: number, head: number[]): number[] => [...tg(99, 2), ...vr(tagValue), ...head, ...new Array<number>(tagValue - head.length).fill(0)];
const nameLure = lure(10, [3, 90, 90, 90]); // looks like field 1 (a name) = 'ZZZ'
const set = (...file: number[][]): Uint8Array => Uint8Array.from(ld(1, file.flat()));
const msgOf = (...parts: number[][]): number[] => ld(4, parts.flat());
const err = (f: () => unknown): unknown => { try { f(); } catch (e) { return e instanceof ActionKitError ? { code: e.code, message: e.message } : String(e); } return 'no error'; };

describe('descriptor set: a skipped unknown field never turns into a known one', () => {
  it('enum value descriptor', () => {
    const m = parseDescriptorSet(set(S(2, 'p'), ld(5, [...S(1, 'E'), ...ld(2, [...S(1, 'RED'), ...nameLure])])));
    expect(m.enums.get('p.E')).toEqual({ full: 'p.E', values: ['RED'] });
  });
  it('enum descriptor', () => {
    const m = parseDescriptorSet(set(S(2, 'p'), ld(5, [...S(1, 'E'), ...nameLure, ...ld(2, S(1, 'RED'))])));
    expect([...m.enums.keys()]).toEqual(['p.E']);
    expect(m.enums.get('p.E')!.values).toEqual(['RED']);
  });
  it('field options', () => {
    // 8416 = the tag of field 1052 (field_behavior) with wire type 0; the lure payload starts with the value 3 (OUTPUT_ONLY)
    const m = parseDescriptorSet(set(S(2, 'p'), msgOf(S(1, 'M'), ld(2, [...S(1, 'f'), ...I(5, 9), ...ld(8, lure(8416, [3]))]))));
    expect(m.messages.get('p.M')!.fields).toEqual([{ name: 'f', scope: 'p.M', repeated: false, optional: false, type: 'string', behavior: [] }]);
  });
  it('field descriptor', () => {
    const m = parseDescriptorSet(set(S(2, 'p'), msgOf(S(1, 'M'), ld(2, [...S(1, 'real'), ...nameLure, ...I(5, 9)]))));
    expect(m.messages.get('p.M')!.fields.map((f) => [f.name, f.type])).toEqual([['real', 'string']]);
  });
  it('message options', () => {
    // 56 = the tag of field 7 (map_entry) with wire type 0; the payload starts with the value 1
    const m = parseDescriptorSet(set(S(2, 'p'), msgOf(S(1, 'M'), ld(7, lure(56, [1])))));
    expect(m.messages.get('p.M')!.mapEntry).toBe(false);
  });
  it('message descriptor', () => {
    const m = parseDescriptorSet(set(S(2, 'p'), msgOf(S(1, 'M'), nameLure)));
    expect([...m.messages.keys()]).toEqual(['p.M']);
  });
  it('file descriptor', () => {
    // 18 = the tag of field 2 (package), read after the real package would overwrite it
    const m = parseDescriptorSet(set(S(2, 'pk'), lure(18, [4, 90, 90, 90, 90]), msgOf(S(1, 'M'))));
    expect([...m.messages.keys()]).toEqual(['pk.M']);
  });

  const svc = (method: number[]): Uint8Array => set(S(2, 'p'), ld(6, [...S(1, 'Svc'), ...ld(2, method)]));
  const bare = { name: 'Get', input: '', output: '', cs: false, ss: false, scope: 'p' };
  it('service descriptor', () => {
    const m = parseDescriptorSet(set(S(2, 'p'), ld(6, [...S(1, 'Svc'), ...nameLure, ...ld(2, S(1, 'Get'))])));
    expect(m.services).toEqual([{ full: 'p.Svc', name: 'Svc', methods: [bare] }]);
  });
  it('method descriptor', () => {
    expect(parseDescriptorSet(svc([...S(1, 'Get'), ...nameLure])).services[0]!.methods).toEqual([bare]);
  });
  it('an unknown length-delimited method field is not method options', () => {
    // field 99 holding an idempotency_level (34) varint would set idem if it were read as the options message
    expect(parseDescriptorSet(svc([...S(1, 'Get'), ...ld(99, I(34, 1))])).services[0]!.methods).toEqual([bare]);
    expect(parseDescriptorSet(svc([...S(1, 'Get'), ...ld(99, I(34, 1))])).services[0]!.methods[0]!.idem).toBeUndefined();
  });
  it('method options', () => {
    // 272 = the tag of field 34 (idempotency_level) with wire type 0; the payload starts with the value 1 (NO_SIDE_EFFECTS)
    const me = parseDescriptorSet(svc([...S(1, 'Get'), ...ld(4, lure(272, [1]))])).services[0]!.methods[0]!;
    expect(me.idem).toBeUndefined();
    expect(me).toEqual(bare);
  });
  it('http rule', () => {
    // 18 = the tag of field 2 (get) with a path, ahead of the real post rule
    const me = parseDescriptorSet(svc([...S(1, 'Get'), ...ld(4, ld(72295728, [...lure(18, [4, 90, 90, 90, 90]), ...S(4, '/real')]))])).services[0]!.methods[0]!;
    expect(me.http).toEqual({ method: 'POST', path: '/real' });
  });
});

describe('.proto text: the body of an http option', () => {
  const H = 'service S { rpc R(A) returns (B) { option (google.api.http) =';
  const http = (opt: string) => parseProto(`${H} ${opt}; } }`).services[0]!.methods[0]!.http;
  it('a body at the very end of the source is an unterminated option, not a crash', () => {
    expect(err(() => parseProto(`${H} { post: "/p" body:`))).toEqual({ code: 'bad_source', message: "proto parse error: unterminated option near '<end>'" });
  });
  it('a non-string body value is not a body', () => {
    expect(http('{ post: "/p" body: x }')).toEqual({ method: 'POST', path: '/p' });
    expect(http('{ post: "/p" body: x }')).not.toHaveProperty('body');
  });
  it('a body ahead of any verb does not create a rule', () => {
    expect(http('{ body: "x" post: "/p" }')).toEqual({ method: 'POST', path: '/p' });
  });
  it('the body value is consumed whole, so a verb-looking value is not read as a verb', () => {
    expect(http('{ body: post : "/x" }')).toBeUndefined();
  });
});
