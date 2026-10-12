/* eslint-disable @typescript-eslint/no-explicit-any */
// Mutation-kill tests for src/ext-wire.ts (typed adapter over the proved wire layer): differential against production strict-json /
// hash on targeted edge cases, plus pinned TypeError messages and chunk-boundary behaviour.
import { describe, expect, it } from 'vitest';
import { strictParse } from '../../pca/src/strict-json';
import { b64u, canonicalizeStrict, compareUtf8, decodeB64uStrict } from '../../pca/src/hash';
import { wireB64uEncode, wireCanonicalOfText, wireCanonicalizeStrict, wireCompareUtf8, wireDecodeB64uStrict, wireHexDecode, wireHexEncode } from '../src/ext-wire';

const tsCanon = (t: string): string | undefined => { try { return canonicalizeStrict(strictParse(t)); } catch { return undefined; } };
const tsVal = (v: unknown): string | undefined => { try { return canonicalizeStrict(v); } catch { return undefined; } };
const wVal = (v: unknown): string | undefined => { try { return wireCanonicalizeStrict(v); } catch { return undefined; } };

describe('wireCanonicalOfText', () => {
  const texts = [
    '{}', '[]', 'null', 'true', 'false', '0', '-1', '12', '1.5', '-0.25', '"a"', '"\\u00e9\\ud83d\\ude00"', '{"b":1,"a":2}', '{"a":{"d":1,"c":[3,2,{"z":null,"y":true}]}}',
    ' { "a" : 1 } ', '{"a":1,"a":2}', '[1,]', '{"a":}', '', ' ', '01', '1e5', '1E5', '-', '+1', '"\\x"', '"\u0001"', '{"é":1,"e":2,"😀":3,"￿":4}', '9007199254740993', '1.0', '[[[[]]]]',
    '"\\ud800"', '{"a":1}x', 'nul', 'tru', '"unterminated', '{"a" 1}', '[1 2]', '﻿{}', '{"__proto__":1}', '-0', '-0.0', '0.1', '100000000000000000000',
  ];
  it('agrees with strictParse + canonicalizeStrict on each text', () => {
    for (const t of texts) expect(wireCanonicalOfText(t), JSON.stringify(t)).toBe(tsCanon(t));
  });
  it('returns pinned canonical strings and undefined on rejection', () => {
    expect(wireCanonicalOfText('{"b":1,"a":[true,null]}')).toBe('{"a":[true,null],"b":1}');
    expect(wireCanonicalOfText('{"a":1,"a":2}')).toBeUndefined();
    expect(wireCanonicalOfText('')).toBeUndefined();
  });
  it('output longer than the 4096-unit chunk size is reassembled exactly', () => {
    const s = 'x'.repeat(4097);
    const text = JSON.stringify(s);
    expect(wireCanonicalOfText(text)).toBe(text);
  });
});

describe('wireCanonicalizeStrict', () => {
  const sameBehaviour = (v: unknown) => {
    expect(wVal(v)).toBe(tsVal(v));
  };
  it('agrees with canonicalizeStrict on primitives, numbers, nesting and key order', () => {
    const vs: unknown[] = [
      null, true, false, '', 'a', 'é😀', 0, 1, -1, 12345, 1.5, -1.5, 0.1, -0.001, 123.456, 1e21, 1e-7, 5e-324, 2 ** 53, -(2 ** 53), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0.000001, 1e-6, 1.25e20,
      [], {}, [1, [2, [3]]], { b: 1, a: 2 }, { 'é': 1, e: 2, '😀': 3, '￿': 4 }, { a: { b: { c: [] } } }, [null, true, 'x', { k: 'v' }], { '': 1 }, { '10': 1, '9': 2, a: 3 },
    ];
    for (const v of vs) sameBehaviour(v);
  });
  it('pinned outputs', () => {
    expect(wireCanonicalizeStrict({ b: 1, a: [true, null, 'x'] })).toBe('{"a":[true,null,"x"],"b":1}');
    expect(wireCanonicalizeStrict(1.5)).toBe('1.5');
    expect(wireCanonicalizeStrict(-0.25)).toBe('-0.25');
    expect(wireCanonicalizeStrict(-7)).toBe('-7');
    expect(wireCanonicalizeStrict(123.456)).toBe('123.456');
    expect(wireCanonicalizeStrict(0.5)).toBe('0.5');
  });
  it('rejects unrepresentable values with the documented TypeError messages', () => {
    expect(() => wireCanonicalizeStrict(Number.NaN)).toThrow(new TypeError('canonicalize: non-finite number'));
    expect(() => wireCanonicalizeStrict(Number.POSITIVE_INFINITY)).toThrow('canonicalize: non-finite number');
    expect(() => wireCanonicalizeStrict(-0)).toThrow(new TypeError('canonicalize: negative zero'));
    expect(() => wireCanonicalizeStrict(1e-7)).toThrow(new TypeError('canonicalize: exponent form'));
    expect(() => wireCanonicalizeStrict(1.5e-10)).toThrow('canonicalize: exponent form');
    expect(() => wireCanonicalizeStrict(undefined)).toThrow(new TypeError('canonicalize: unsupported type undefined'));
    expect(() => wireCanonicalizeStrict(() => 1)).toThrow('canonicalize: unsupported type function');
    expect(() => wireCanonicalizeStrict(Symbol('s'))).toThrow('canonicalize: unsupported type symbol');
    expect(() => wireCanonicalizeStrict(10n)).toThrow('canonicalize: unsupported type bigint');
    expect(() => wireCanonicalizeStrict({ a: undefined })).toThrow('canonicalize: unsupported type undefined');
    expect(() => wireCanonicalizeStrict([1, undefined])).toThrow('unsupported type undefined');
    // eslint-disable-next-line no-sparse-arrays
    expect(() => wireCanonicalizeStrict([1, , 2])).toThrow('unsupported type undefined');
    for (const o of [new Date(0), new Map(), Object.create({ x: 1 }), new (class Foo { a = 1; })(), /re/]) expect(() => wireCanonicalizeStrict(o)).toThrow(new TypeError('canonicalize: non-plain object'));
    expect(() => wireCanonicalizeStrict({ nested: new Date(0) })).toThrow('canonicalize: non-plain object');
  });
  it('null-prototype objects are plain; shared (non-cyclic) references are fine; cycles are refused', () => {
    const np = Object.create(null);
    np.k = 1;
    expect(wireCanonicalizeStrict(np)).toBe('{"k":1}');
    const shared = { s: 1 };
    expect(wireCanonicalizeStrict({ x: shared, y: shared, z: [shared, shared] })).toBe('{"x":{"s":1},"y":{"s":1},"z":[{"s":1},{"s":1}]}');
    const a: unknown[] = [];
    a.push(a);
    expect(() => wireCanonicalizeStrict(a)).toThrow(new TypeError('canonicalize: cycle'));
    const o: any = {};
    o.self = { deeper: o };
    expect(() => wireCanonicalizeStrict(o)).toThrow('canonicalize: cycle');
    // after a failure the cycle guard has no residue: the same function works again
    expect(wireCanonicalizeStrict({ ok: 1 })).toBe('{"ok":1}');
  });
  it('long printed output (past the 4096-unit chunk) is reassembled exactly', () => {
    for (const n of [4095, 4096, 4097, 8193]) expect(wireCanonicalizeStrict('y'.repeat(n))).toBe(JSON.stringify('y'.repeat(n)));
  });
  it('a lone surrogate is outside the strict string profile', () => {
    expect(() => wireCanonicalizeStrict('\ud800')).toThrow(new TypeError('canonicalize: value outside the strict profile'));
    expect(tsVal('\ud800')).toBeUndefined();
  });
  it('unsafe integers stay refused/accepted exactly as production', () => {
    for (const n of [2 ** 53 + 2, -(2 ** 53) - 2, 1e300]) sameBehaviour(n);
  });
});

describe('wireCompareUtf8', () => {
  const strs = ['', 'a', 'b', 'ab', 'é', 'z', '\u007f', '\u0080', '߿', 'ࠀ', '￿', '퟿', '', '😀', '\u{10000}', '\u{10ffff}', 'a😀', 'a￿', '￿😀'];
  it('matches production compareUtf8 on every ordered pair (UTF-8 byte order, not UTF-16)', () => {
    for (const a of strs) for (const b of strs) expect(wireCompareUtf8(a, b), `${JSON.stringify(a)} ${JSON.stringify(b)}`).toBe(Math.sign(compareUtf8(a, b)));
    expect(wireCompareUtf8('￿', '😀')).toBe(-1);
    expect(wireCompareUtf8('😀', '￿')).toBe(1);
    expect(wireCompareUtf8('a', 'a')).toBe(0);
  });
});

describe('base64url and hex', () => {
  const bytesOf = (n: number) => Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff);
  it('b64u encode agrees with production for every length 0..70 and across the chunk boundary', () => {
    for (let n = 0; n <= 70; n++) expect(wireB64uEncode(bytesOf(n))).toBe(b64u(bytesOf(n)));
    for (const n of [3072, 3073]) expect(wireB64uEncode(bytesOf(n))).toBe(b64u(bytesOf(n)));
  });
  it('b64u decode: accepts exactly what production accepts, with and without an expected length', () => {
    const inputs = ['', 'AA', 'AAA', 'AAAA', 'AAAAAA', 'AAAAAAA', 'AA==', 'AQ', 'AR', 'Aa', '-_', '+/', 'AB', 'AAB', 'A', 'AAAAA', 'a b', 'AAAA\n', ' AAAA', 'AA.A', 'é', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', b64u(bytesOf(32)), b64u(bytesOf(33)), b64u(bytesOf(64))];
    for (const s of inputs) {
      for (const len of [undefined, 0, 1, 2, 3, 32, 33, 64]) {
        const exp = decodeB64uStrict(s, len as any);
        const got = wireDecodeB64uStrict(s, len);
        expect(got === null ? null : Array.from(got), `${JSON.stringify(s)} len=${len}`).toEqual(exp === null ? null : Array.from(exp as Uint8Array));
      }
    }
    expect(Array.from(wireDecodeB64uStrict('', 0)!)).toEqual([]);
    expect(wireDecodeB64uStrict('AAAA', 2)).toBeNull();
    expect(Array.from(wireDecodeB64uStrict('AAAA', 3)!)).toEqual([0, 0, 0]);
    expect(Array.from(wireDecodeB64uStrict('AAAA')!)).toEqual([0, 0, 0]);
  });
  it('non-string input is null', () => {
    for (const v of [undefined, null, 5, {}, [], ['AAAA'], true, new Uint8Array(3)]) expect(wireDecodeB64uStrict(v)).toBeNull();
  });
  it('b64u round trip across the chunk boundary', () => {
    for (const n of [0, 1, 2, 3, 4, 3073]) expect(Array.from(wireDecodeB64uStrict(wireB64uEncode(bytesOf(n)))!)).toEqual(Array.from(bytesOf(n)));
  });
  it('hex: canonical lower-case even-length only; encode/decode round trip incl. long inputs', () => {
    expect(wireHexEncode(Uint8Array.from([0, 1, 15, 16, 255]))).toBe('00010f10ff');
    expect(wireHexEncode(new Uint8Array(0))).toBe('');
    expect(Array.from(wireHexDecode('00010f10ff')!)).toEqual([0, 1, 15, 16, 255]);
    expect(Array.from(wireHexDecode('')!)).toEqual([]);
    for (const bad of ['0', '0g', 'AB', 'aB', 'ab ', ' ab', '0x00', 'abc', 'zz', '+1']) expect(wireHexDecode(bad), bad).toBeNull();
    for (const n of [0, 1, 2048, 2049]) {
      const b = bytesOf(n);
      const h = wireHexEncode(b);
      expect(h).toBe(Buffer.from(b).toString('hex'));
      expect(Array.from(wireHexDecode(h)!)).toEqual(Array.from(b));
    }
    for (let v = 0; v < 256; v++) expect(wireHexEncode(Uint8Array.from([v]))).toBe(v.toString(16).padStart(2, '0'));
  });
});
