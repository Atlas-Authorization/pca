/** Mutation-kill tests for hash.ts: exact values, boundaries and error messages of every helper and of the canonical serializer. */
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_HASH_SUITE, HASH_LEN, MAX_DECIMAL_DIGITS, MAX_JSON_DEPTH, __canonicalizeLenientServerOnly, b64u, b64uLen, canonicalBytes, canonicalBytesLenient,
  canonicalBytesStrict, canonicalize, canonicalizeStrict, compareUtf8, decodeB64uStrict, hasLoneSurrogate, hashCanonical, hashCanonicalLenient, hashWithSuite,
  isCanonicalB64u, isHashSuite, sha256, sha384, strictNumberError, unb64u, utf8,
} from './hash';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const msg = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(TypeError);
    return (e as Error).message;
  }
  return 'NO THROW';
};

describe('hash primitives', () => {
  it('utf8 / sha256 / sha384 known answers', () => {
    expect(Array.from(utf8('a€😀'))).toEqual([0x61, 0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80]);
    expect(hex(sha256(utf8('abc')))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(hex(sha384(utf8('abc')))).toBe('cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7');
  });
  it('suite tables and guard', () => {
    expect(DEFAULT_HASH_SUITE).toBe('sha256');
    expect(HASH_LEN).toEqual({ sha256: 32, sha384: 48 });
    expect(isHashSuite('sha256')).toBe(true);
    expect(isHashSuite('sha384')).toBe(true);
    for (const x of ['', 'SHA256', 'sha512', 'sha-256', ' sha256', undefined, null, 256, {}, ['sha256']]) expect(isHashSuite(x)).toBe(false);
  });
  it('hashWithSuite dispatches on the suite and defaults to sha256', () => {
    const m = utf8('abc');
    expect(hex(hashWithSuite(m))).toBe(hex(sha256(m)));
    expect(hex(hashWithSuite(m, 'sha256'))).toBe(hex(sha256(m)));
    expect(hex(hashWithSuite(m, 'sha384'))).toBe(hex(sha384(m)));
    expect(hashWithSuite(m, 'sha384').length).toBe(48);
  });
  it('b64u / unb64u round trip, RFC vectors, url alphabet, no padding', () => {
    expect(b64u(new Uint8Array([0xfb, 0xff, 0xfe]))).toBe('-__-');
    expect(b64u(utf8('f'))).toBe('Zg');
    expect(b64u(utf8('fo'))).toBe('Zm8');
    expect(b64u(utf8('foo'))).toBe('Zm9v');
    expect(Array.from(unb64u('Zm9vYg'))).toEqual(Array.from(utf8('foob')));
    expect(b64u(new Uint8Array(0))).toBe('');
  });
  it('b64uLen is ceil(4n/3)', () => {
    expect([0, 1, 2, 3, 4, 5, 6, 32, 48, 64].map(b64uLen)).toEqual([0, 2, 3, 4, 6, 7, 8, 43, 64, 86]);
    for (let n = 0; n < 100; n++) expect(b64u(new Uint8Array(n)).length).toBe(b64uLen(n));
  });
});

describe('decodeB64uStrict / isCanonicalB64u', () => {
  it('accepts canonical input of any length class and returns the bytes', () => {
    expect(Array.from(decodeB64uStrict('')!)).toEqual([]);
    expect(Array.from(decodeB64uStrict('Zg')!)).toEqual([0x66]);
    expect(Array.from(decodeB64uStrict('Zm8')!)).toEqual([0x66, 0x6f]);
    expect(Array.from(decodeB64uStrict('Zm9v')!)).toEqual([0x66, 0x6f, 0x6f]);
    expect(Array.from(decodeB64uStrict('-__-')!)).toEqual([0xfb, 0xff, 0xfe]);
  });
  it('rejects non-strings, bad alphabet, padding, whitespace', () => {
    for (const x of [undefined, null, 5, {}, ['Zm9v'], new String('Zm9v'), Buffer.from('Zm9v')]) expect(decodeB64uStrict(x)).toBeNull();
    for (const x of ['Zm9v=', 'Zg==', 'Zm 9v', 'Zm9v\n', ' Zm9v', 'Zm+v', 'Zm/v', 'Zm9é', 'Zm9v\u0000', 'Zm9v\n\n\n\n']) expect(decodeB64uStrict(x)).toBeNull();
  });
  it('rejects length%4==1 (impossible) and non-zero trailing bits', () => {
    for (const x of ['A', 'AAAAA', 'AAAAAAAAA']) expect(decodeB64uStrict(x)).toBeNull();
    expect(decodeB64uStrict('AB')).toBeNull(); // trailing bits of 'B' are non-zero: canonical form is 'AA'
    expect(decodeB64uStrict('AA')).not.toBeNull();
    expect(decodeB64uStrict('AAB')).toBeNull();
    expect(decodeB64uStrict('AAA')).not.toBeNull();
    expect(decodeB64uStrict('Zh')).toBeNull();
  });
  it('len pins the DECODED byte length, both directions', () => {
    const k32 = b64u(new Uint8Array(32).fill(7));
    expect(k32.length).toBe(43);
    expect(decodeB64uStrict(k32, 32)!.length).toBe(32);
    expect(decodeB64uStrict(k32, 31)).toBeNull();
    expect(decodeB64uStrict(k32, 33)).toBeNull();
    expect(decodeB64uStrict(k32.slice(0, 42), 32)).toBeNull();
    expect(decodeB64uStrict(k32 + 'A', 32)).toBeNull();
    expect(decodeB64uStrict('', 0)!.length).toBe(0);
    expect(decodeB64uStrict('Zg', 0)).toBeNull();
    expect(decodeB64uStrict('', 1)).toBeNull();
    expect(decodeB64uStrict('Zg', 1)).not.toBeNull();
    expect(decodeB64uStrict('Zg', 2)).toBeNull();
    expect(decodeB64uStrict('Zm8', 2)).not.toBeNull();
    for (let n = 0; n < 70; n++) {
      const s = b64u(new Uint8Array(n).fill(0xa5));
      expect(decodeB64uStrict(s, n)!.length).toBe(n);
      expect(decodeB64uStrict(s, n + 1)).toBeNull();
      if (n > 0) expect(decodeB64uStrict(s, n - 1)).toBeNull();
    }
  });
  it('isCanonicalB64u mirrors decodeB64uStrict', () => {
    expect(isCanonicalB64u('Zm9v')).toBe(true);
    expect(isCanonicalB64u('Zm9v', 3)).toBe(true);
    expect(isCanonicalB64u('Zm9v', 4)).toBe(false);
    expect(isCanonicalB64u('AB')).toBe(false);
    expect(isCanonicalB64u(5)).toBe(false);
    expect(isCanonicalB64u('')).toBe(true);
  });
});

describe('compareUtf8', () => {
  it('orders by UTF-8 bytes (== code point order), returns the byte difference / length difference', () => {
    expect(compareUtf8('a', 'a')).toBe(0);
    expect(compareUtf8('', '')).toBe(0);
    expect(compareUtf8('a', 'b')).toBe(-1);
    expect(compareUtf8('c', 'a')).toBe(2);
    expect(compareUtf8('ab', 'ac')).toBe(-1);
    expect(compareUtf8('ab', 'a')).toBe(1);
    expect(compareUtf8('a', 'ab')).toBe(-1);
    expect(compareUtf8('abc', 'a')).toBe(2);
    expect(compareUtf8('', 'abc')).toBe(-3);
    expect(compareUtf8('xa', 'xb')).toBe(-1);
    expect(compareUtf8('\u{10000}', '￿')).toBeGreaterThan(0); // UTF-16 order would say the opposite
    expect(compareUtf8('￿', '\u{10000}')).toBeLessThan(0);
  });
  it('sorting is a total order consistent with code points', () => {
    const xs = ['b', 'a', 'ab', '', 'é', 'z', '\u{1F600}', 'A', 'aa', '￿'];
    expect([...xs].sort(compareUtf8)).toEqual(['', 'A', 'a', 'aa', 'ab', 'b', 'z', 'é', '￿', '\u{1F600}']);
  });
});

describe('strictNumberError', () => {
  it('every branch, exact text', () => {
    expect(strictNumberError(NaN)).toBe('non-finite number');
    expect(strictNumberError(Infinity)).toBe('non-finite number');
    expect(strictNumberError(-Infinity)).toBe('non-finite number');
    expect(strictNumberError(-0)).toBe('negative zero');
    expect(strictNumberError(0)).toBeNull();
    expect(strictNumberError(Number.MAX_SAFE_INTEGER)).toBeNull();
    expect(strictNumberError(-Number.MAX_SAFE_INTEGER)).toBeNull();
    expect(strictNumberError(2 ** 53)).toBe('integer outside the safe range (|n| > 2^53-1)');
    expect(strictNumberError(-(2 ** 53))).toBe('integer outside the safe range (|n| > 2^53-1)');
    expect(strictNumberError(1e21)).toBe('integer outside the safe range (|n| > 2^53-1)');
    expect(strictNumberError(1e-7)).toBe('non-integer magnitude below 1e-6 (needs an exponent form; not representable in the canonical decimal form)');
    expect(strictNumberError(-1e-7)).toBe('non-integer magnitude below 1e-6 (needs an exponent form; not representable in the canonical decimal form)');
    expect(strictNumberError(0.000001)).toBeNull(); // exactly 1e-6 is the smallest allowed
    expect(strictNumberError(0.0000011)).toBeNull();
    expect(strictNumberError(0.5)).toBeNull();
    expect(strictNumberError(-123.456)).toBeNull();
  });
  it('significant-digit limit counts digits, not leading zeros, and counts inner zeros', () => {
    expect(MAX_DECIMAL_DIGITS).toBe(15);
    expect(strictNumberError(123456789012.345)).toBeNull(); // 15 digits
    expect(strictNumberError(0.123456789012345)).toBeNull(); // 15 digits after leading zero
    expect(strictNumberError(0.0123456789012345)).toBeNull(); // leading zeros do not count
    expect(strictNumberError(-123456789012.345)).toBeNull(); // the sign is not a digit
    expect(strictNumberError(-0.0123456789012345)).toBeNull();
    expect(strictNumberError(0.000001234567890123)).toBeNull(); // many leading zeros
    expect(strictNumberError(1.2345678901234567)).toBe(`non-integer number has more than 15 significant digits`);
    expect(strictNumberError(1000000000000.123)).toBe(`non-integer number has more than 15 significant digits`); // inner zeros count
    expect(strictNumberError(-1000000000000.123)).toBe(`non-integer number has more than 15 significant digits`);
    expect(strictNumberError(0.1 + 0.2)).toBe(`non-integer number has more than 15 significant digits`);
  });
});

describe('canonical serializer', () => {
  it('sorts keys bytewise, no whitespace, recursive', () => {
    expect(canonicalizeStrict({ b: 1, a: [true, false, null, 'x'], '': 0, é: 1, Z: { y: 1, x: 2 } })).toBe('{"":0,"Z":{"x":2,"y":1},"a":[true,false,null,"x"],"b":1,"é":1}');
    expect(canonicalizeStrict([])).toBe('[]');
    expect(canonicalizeStrict({})).toBe('{}');
    expect(canonicalizeStrict(null)).toBe('null');
    expect(canonicalizeStrict('a"b\n')).toBe('"a\\"b\\n"');
    expect(canonicalizeStrict(-12.5)).toBe('-12.5');
    expect(canonicalizeStrict(true)).toBe('true');
    expect(canonicalizeStrict(false)).toBe('false');
  });
  it('plain objects: null-prototype ok, others refused; own-property order does not matter', () => {
    const np = Object.create(null) as Record<string, unknown>;
    np.b = 1;
    np.a = 2;
    expect(canonicalizeStrict(np)).toBe('{"a":2,"b":1}');
    expect(msg(() => canonicalizeStrict(new Date(0)))).toBe('canonicalize: non-plain object');
    expect(msg(() => canonicalizeStrict(new Map()))).toBe('canonicalize: non-plain object');
    expect(msg(() => canonicalizeStrict(new (class X { a = 1; })()))).toBe('canonicalize: non-plain object');
    expect(msg(() => canonicalizeStrict(Object.create({ a: 1 })))).toBe('canonicalize: non-plain object');
    expect(msg(() => __canonicalizeLenientServerOnly(new Date(0)))).toBe('canonicalize: non-plain object');
  });
  it('unsupported types, exact messages', () => {
    expect(msg(() => canonicalizeStrict(undefined))).toBe('canonicalize: unsupported type undefined');
    expect(msg(() => canonicalizeStrict(() => 1))).toBe('canonicalize: unsupported type function');
    expect(msg(() => canonicalizeStrict(Symbol('s')))).toBe('canonicalize: unsupported type symbol');
    expect(msg(() => canonicalizeStrict(1n))).toBe('canonicalize: unsupported type bigint');
    expect(msg(() => canonicalizeStrict({ a: undefined }))).toBe('canonicalize: unsupported type undefined');
    expect(msg(() => __canonicalizeLenientServerOnly(undefined))).toBe('canonicalize: unsupported type undefined');
  });
  it('numbers: strict messages carry the strictNumberError text; lenient accepts any finite number', () => {
    expect(msg(() => canonicalizeStrict(NaN))).toBe('canonicalize: non-finite number');
    expect(msg(() => __canonicalizeLenientServerOnly(Infinity))).toBe('canonicalize: non-finite number');
    expect(msg(() => canonicalizeStrict(-0))).toBe('canonicalize: negative zero');
    expect(msg(() => canonicalizeStrict(2 ** 53))).toBe('canonicalize: integer outside the safe range (|n| > 2^53-1)');
    expect(msg(() => canonicalizeStrict(0.1 + 0.2))).toBe('canonicalize: non-integer number has more than 15 significant digits');
    expect(__canonicalizeLenientServerOnly(1e21)).toBe('1e+21');
    expect(__canonicalizeLenientServerOnly(0.1 + 0.2)).toBe('0.30000000000000004');
    expect(__canonicalizeLenientServerOnly(-0)).toBe('0');
    expect(__canonicalizeLenientServerOnly(0)).toBe('0');
    expect(__canonicalizeLenientServerOnly(-5)).toBe('-5');
    expect(canonicalize).toBe(__canonicalizeLenientServerOnly);
    expect(canonicalizeStrict(0)).toBe('0');
    expect(canonicalizeStrict(1e-6)).toBe('0.000001');
  });
  it('lone surrogates: refused by the strict form (strings and keys), tolerated by the lenient form', () => {
    expect(hasLoneSurrogate('\ud800')).toBe(true);
    expect(hasLoneSurrogate('\udc00')).toBe(true);
    expect(hasLoneSurrogate('a\ud800b')).toBe(true);
    expect(hasLoneSurrogate('😀')).toBe(false);
    expect(hasLoneSurrogate('\ude00\ud83d')).toBe(true); // reversed pair: both lone
    expect(hasLoneSurrogate('plain')).toBe(false);
    expect(msg(() => canonicalizeStrict('\ud800'))).toBe('canonicalize: lone surrogate in string');
    expect(msg(() => canonicalizeStrict({ '\ud800': 1 }))).toBe('canonicalize: lone surrogate in key');
    expect(msg(() => canonicalizeStrict(['\udc00']))).toBe('canonicalize: lone surrogate in string');
    expect(canonicalizeStrict('😀')).toBe('"\u{1F600}"');
    expect(__canonicalizeLenientServerOnly('\ud800')).toBe('"\\ud800"');
    expect(__canonicalizeLenientServerOnly({ '\ud800': 1 })).toBe('{"\\ud800":1}');
  });
  it('depth: 32 nested containers are allowed by the strict form, 33 are not (arrays, objects, mixed); lenient has no limit', () => {
    expect(MAX_JSON_DEPTH).toBe(32);
    const arr = (n: number): unknown => (n === 0 ? 1 : [arr(n - 1)]);
    const obj = (n: number): unknown => (n === 0 ? 1 : { a: obj(n - 1) });
    const mix = (n: number): unknown => (n === 0 ? 1 : n % 2 ? [mix(n - 1)] : { a: mix(n - 1) });
    for (const f of [arr, obj, mix]) {
      expect(canonicalizeStrict(f(32))).toBeTypeOf('string');
      expect(msg(() => canonicalizeStrict(f(33)))).toBe('canonicalize: nesting too deep');
      expect(msg(() => canonicalizeStrict(f(200)))).toBe('canonicalize: nesting too deep');
      expect(__canonicalizeLenientServerOnly(f(200))).toBeTypeOf('string');
    }
  });
  it('cycles are refused (array and object), shared references are not cycles', () => {
    const a: unknown[] = [];
    a.push(a);
    expect(msg(() => canonicalizeStrict(a))).toBe('canonicalize: cycle');
    const o: Record<string, unknown> = {};
    o.self = { inner: o };
    expect(msg(() => __canonicalizeLenientServerOnly(o))).toBe('canonicalize: cycle');
    const shared = { x: 1 };
    expect(canonicalizeStrict({ a: shared, b: shared, c: [shared, shared] })).toBe('{"a":{"x":1},"b":{"x":1},"c":[{"x":1},{"x":1}]}');
    const arrShared = [1];
    expect(canonicalizeStrict([arrShared, arrShared])).toBe('[[1],[1]]');
  });
  it('a failed serialization leaves no state behind: the same object serializes afterwards', () => {
    const bad = { a: 1, b: undefined };
    expect(msg(() => canonicalizeStrict(bad))).toBe('canonicalize: unsupported type undefined');
    expect(msg(() => canonicalizeStrict(bad))).toBe('canonicalize: unsupported type undefined');
    const good = { a: 1 };
    expect(canonicalizeStrict([good])).toBe('[{"a":1}]');
    expect(canonicalizeStrict([good])).toBe('[{"a":1}]');
  });
});

describe('canonical bytes and digests', () => {
  it('strict bytes == utf8(strict form); hashCanonical known answers and suites', () => {
    const v = { b: [1, 2], a: 'x' };
    expect(new TextDecoder().decode(canonicalBytes(v))).toBe('{"a":"x","b":[1,2]}');
    expect(hex(canonicalBytesStrict(v))).toBe(hex(canonicalBytes(v)));
    expect(hashCanonical(v)).toBe(b64u(sha256(utf8('{"a":"x","b":[1,2]}'))));
    expect(hashCanonical(v, 'sha256')).toBe(hashCanonical(v));
    expect(hashCanonical(v, 'sha384')).toBe(b64u(sha384(utf8('{"a":"x","b":[1,2]}'))));
    expect(hashCanonical(v, 'sha384').length).toBe(64);
    expect(hashCanonical(v).length).toBe(43);
    expect(msg(() => hashCanonical({ n: 1e21 }))).toBe('canonicalize: integer outside the safe range (|n| > 2^53-1)');
    expect(msg(() => canonicalBytes({ n: 0.1 + 0.2 }))).toBe('canonicalize: non-integer number has more than 15 significant digits');
    expect(msg(() => canonicalBytesStrict({ n: -0 }))).toBe('canonicalize: negative zero');
  });
  it('lenient bytes / digest accept out-of-profile data and always use sha256 over the lenient form', () => {
    const v = { n: 1e21, s: '\ud800' };
    expect(new TextDecoder().decode(canonicalBytesLenient(v))).toBe('{"n":1e+21,"s":"\\ud800"}');
    expect(hashCanonicalLenient(v)).toBe(b64u(sha256(utf8('{"n":1e+21,"s":"\\ud800"}'))));
    expect(hashCanonicalLenient({ a: 1 })).toBe(hashCanonical({ a: 1 })); // identical on in-profile data
    expect(hashCanonicalLenient({ a: 1 })).not.toBe(hashCanonical({ a: 1 }, 'sha384'));
  });
});
