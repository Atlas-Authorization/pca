/** Mutation-kill tests for strict-json.ts: every grammar rule, error message and offset, every limit at its exact boundary. */
import { describe, expect, it } from 'vitest';
import { MAX_JSON_BYTES, StrictJsonError, strictParse, strictParseBytes } from './strict-json';

const err = (t: string): string => {
  try {
    strictParse(t);
  } catch (e) {
    expect(e).toBeInstanceOf(StrictJsonError);
    return (e as Error).message;
  }
  return 'NO THROW';
};
const E = (m: string, at: number) => `strict JSON: ${m} (at offset ${at})`;

describe('StrictJsonError', () => {
  it('has name, offset and the formatted message', () => {
    try {
      strictParse('[1 2]');
      throw new Error('no throw');
    } catch (e) {
      const x = e as StrictJsonError;
      expect(x).toBeInstanceOf(Error);
      expect(x.name).toBe('StrictJsonError');
      expect(x.offset).toBe(3);
      expect(x.message).toBe('strict JSON: expected "," or "]" (at offset 3)');
    }
  });
});

describe('inputs and size', () => {
  it('non-string input', () => {
    expect(() => strictParse(5 as unknown as string)).toThrow(E('input is not a string', 0));
    expect(() => strictParse(undefined as unknown as string)).toThrow(E('input is not a string', 0));
    expect(() => strictParse(['1'] as unknown as string)).toThrow(E('input is not a string', 0));
  });
  it('size limit is in UTF-8 bytes, inclusive at exactly MAX_JSON_BYTES', () => {
    expect(MAX_JSON_BYTES).toBe(1048576);
    expect(strictParse('"' + 'a'.repeat(MAX_JSON_BYTES - 2) + '"')).toHaveLength(MAX_JSON_BYTES - 2);
    expect(err('"' + 'a'.repeat(MAX_JSON_BYTES - 1) + '"')).toBe(E('input too large', 0));
    // 3-byte characters: fewer than MAX UTF-16 units but more than MAX bytes
    expect(err('"' + '€'.repeat(349526) + '"')).toBe(E('input too large', 0));
    expect(strictParse('"' + '€'.repeat(349524) + '"')).toHaveLength(349524);
  }, 60_000); // with PCA_VERIFIED_CORE=wire the proved parser takes a few seconds per maximum-size text
  it('strictParseBytes: type, UTF-8 validity, BOM is not stripped', () => {
    expect(strictParseBytes(new TextEncoder().encode('{"a":[1,"é"]}'))).toEqual({ a: [1, 'é'] });
    expect(strictParseBytes(Buffer.from('[1]'))).toEqual([1]);
    expect(() => strictParseBytes([49] as unknown as Uint8Array)).toThrow(E('input is not a Uint8Array', 0));
    expect(() => strictParseBytes('1' as unknown as Uint8Array)).toThrow(E('input is not a Uint8Array', 0));
    expect(() => strictParseBytes(new Uint8Array([0x22, 0xff, 0x22]))).toThrow(E('input is not valid UTF-8', 0));
    expect(() => strictParseBytes(new Uint8Array([0xc0, 0xaf]))).toThrow(E('input is not valid UTF-8', 0));
    expect(() => strictParseBytes(new Uint8Array([0xef, 0xbb, 0xbf, 0x31]))).toThrow(E('unexpected token', 0)); // BOM kept -> not JSON whitespace
    expect(() => strictParseBytes(new Uint8Array([0xed, 0xa0, 0x80]))).toThrow(E('input is not valid UTF-8', 0)); // encoded surrogate
  });
});

describe('whitespace', () => {
  it('only space, tab, LF, CR are whitespace, at every position', () => {
    for (const w of [' ', '\t', '\n', '\r']) {
      expect(strictParse(`${w}1${w}`)).toBe(1);
      expect(strictParse(`${w}[${w}1${w},${w}2${w}]${w}`)).toEqual([1, 2]);
      expect(strictParse(`${w}{${w}"a"${w}:${w}[${w}]${w},${w}"b"${w}:${w}{${w}}${w}}${w}`)).toEqual({ a: [], b: {} });
    }
    expect(strictParse('{ }')).toEqual({});
    expect(strictParse('[ ]')).toEqual([]);
    expect(strictParse('[1, 2]')).toEqual([1, 2]);
    expect(strictParse('{"a":1, "b":2}')).toEqual({ a: 1, b: 2 });
    expect(strictParse('{"a" :1}')).toEqual({ a: 1 });
    expect(strictParse('{"a":1 }')).toEqual({ a: 1 });
    expect(strictParse('[1 ]')).toEqual([1]);
    expect(strictParse('[1 ,2]')).toEqual([1, 2]);
    expect(strictParse('1 ')).toBe(1);
    expect(strictParse(' 1')).toBe(1);
    for (const w of ['\f', '\v', ' ', '﻿', ' ', '\u0085', '\u0000']) {
      expect(err(`${w}1`)).toBe(E('unexpected token', 0));
      expect(err(`1${w}`)).toBe(E('trailing characters after the JSON value', 1));
    }
  });
  it('empty / whitespace-only input', () => {
    expect(err('')).toBe(E('unexpected end of input', 0));
    expect(err(' ')).toBe(E('unexpected end of input', 1));
    expect(err(' \n\t\r ')).toBe(E('unexpected end of input', 5));
  });
});

describe('strings', () => {
  it('plain, escapes, and unicode escapes', () => {
    expect(strictParse('""')).toBe('');
    expect(strictParse('" "')).toBe(' ');
    expect(strictParse('"\\b\\f\\n\\r\\t\\/\\\\\\""')).toBe('\b\f\n\r\t/\\"');
    expect(strictParse('"\\u0041\\u00e9\\u00E9"')).toBe('Aéé');
    expect(strictParse('"\\ud83d\\ude00"')).toBe('😀');
    expect(strictParse('"a\\nb"')).toBe('a\nb');
    expect(strictParse('"😀"')).toBe('😀');
    expect(strictParse('"\u007f"')).toBe('\u007f');
  });
  it('errors: unterminated, control characters (< 0x20 only), unknown / bad escapes', () => {
    expect(err('"abc')).toBe(E('unterminated string', 4));
    expect(err('"')).toBe(E('unterminated string', 1));
    expect(err('"a\\')).toBe(E('unknown escape', 3));
    for (let c = 0; c < 0x20; c++) expect(err(`"${String.fromCharCode(c)}"`)).toBe(E('raw control character in string', 1));
    expect(strictParse(`"${String.fromCharCode(0x20)}"`)).toBe(' ');
    expect(err('"\\q"')).toBe(E('unknown escape', 2));
    expect(err('"\\a"')).toBe(E('unknown escape', 2));
    expect(err('"\\\'"')).toBe(E('unknown escape', 2));
    expect(err('"\\u12"')).toBe(E('bad \\u escape', 2));
    expect(err('"\\u12zz"')).toBe(E('bad \\u escape', 2));
    expect(err('"\\uzzzz"')).toBe(E('bad \\u escape', 2));
    expect(err('"\\u 123"')).toBe(E('bad \\u escape', 2));
    expect(err('"\\u')).toBe(E('bad \\u escape', 2));
    expect(strictParse('"\\u00fF"')).toBe('ÿ');
  });
  it('lone surrogates are refused, raw and escaped, in strings and keys', () => {
    expect(err('"\\ud800"')).toBe(E('lone surrogate in string', 8));
    expect(err('"\\ude00"')).toBe(E('lone surrogate in string', 8));
    expect(err('"\ud800"')).toBe(E('lone surrogate in string', 3));
    expect(err('"\\ude00\\ud83d"')).toBe(E('lone surrogate in string', 14));
    expect(err('{"\\ud800":1}')).toBe(E('lone surrogate in string', 9));
    expect(err('["a\\ud800b"]')).toContain('lone surrogate in string');
  });
});

describe('numbers', () => {
  it('canonical forms parse', () => {
    expect(strictParse('0')).toBe(0);
    expect(strictParse('-1')).toBe(-1);
    expect(strictParse('0.5')).toBe(0.5);
    expect(strictParse('-0.5')).toBe(-0.5);
    expect(strictParse('0.000001')).toBe(0.000001);
    expect(strictParse('-0.000001')).toBe(-0.000001);
    expect(strictParse('0.000001234')).toBe(0.000001234);
    expect(strictParse('123456789012.345')).toBe(123456789012.345);
    expect(strictParse('0.123456789012345')).toBe(0.123456789012345);
    expect(strictParse('9007199254740991')).toBe(9007199254740991);
    expect(strictParse('-9007199254740991')).toBe(-9007199254740991);
    expect(strictParse('1000000000000000')).toBe(1e15);
    expect(strictParse('[0]')).toEqual([0]);
    expect(strictParse('-123456789012.345')).toBe(-123456789012.345); // 15 digits: the sign is not a digit
    expect(strictParse('0.000001234567890123')).toBe(0.000001234567890123); // 13 significant digits behind many leading zeros
    expect(strictParse('-0.000001234567890123')).toBe(-0.000001234567890123);
  });
  it('rejections with message and offset', () => {
    expect(err('-')).toBe(E('bad number', 0));
    expect(err('-x')).toBe(E('bad number', 0));
    expect(err('1e5')).toBe(E('exponent form is not allowed (use a plain decimal)', 3));
    expect(err('1E5')).toBe(E('exponent form is not allowed (use a plain decimal)', 3));
    expect(err('1.5e-3')).toBe(E('exponent form is not allowed (use a plain decimal)', 6));
    expect(err('-0')).toBe(E('negative zero is not allowed', 2));
    expect(err('1.0')).toBe(E('trailing fractional zero is not canonical', 3));
    expect(err('1.50')).toBe(E('trailing fractional zero is not canonical', 4));
    expect(err('0.0')).toBe(E('trailing fractional zero is not canonical', 3));
    expect(err('0.000000')).toBe(E('trailing fractional zero is not canonical', 8));
    expect(err('-0.0')).toBe(E('trailing fractional zero is not canonical', 4));
    expect(err('1234567890123456.5')).toBe(E('more than 15 significant digits', 18));
    expect(err('123456789012345.5')).toBe(E('more than 15 significant digits', 17));
    expect(err('1000000000000.123')).toBe(E('more than 15 significant digits', 17)); // inner zeros count
    expect(err('0.1234567890123456')).toBe(E('more than 15 significant digits', 18));
    expect(err('0.0000001')).toBe(E('non-integer magnitude below 1e-6 is not allowed', 9));
    expect(err('-0.0000001')).toBe(E('non-integer magnitude below 1e-6 is not allowed', 10));
    expect(err('9007199254740992')).toBe(E('integer outside the safe range (|n| > 2^53-1)', 16));
    expect(err('-9007199254740992')).toBe(E('integer outside the safe range (|n| > 2^53-1)', 17));
    expect(err('12345678901234567')).toBe(E('integer outside the safe range (|n| > 2^53-1)', 17));
    expect(err('99999999999999999999')).toBe(E('integer outside the safe range (|n| > 2^53-1)', 20));
    expect(err('-12345678901234567')).toBe(E('integer outside the safe range (|n| > 2^53-1)', 18));
  });
  it('leading zeros and plus signs', () => {
    expect(err('01')).toBe(E('trailing characters after the JSON value', 1));
    expect(err('[01]')).toBe(E('expected "," or "]"', 2));
    expect(err('+1')).toBe(E('unexpected token', 0));
    expect(err('.5')).toBe(E('unexpected token', 0));
    expect(err('1.')).toBe(E('trailing characters after the JSON value', 1));
    expect(err('NaN')).toBe(E('unexpected token', 0));
    expect(err('Infinity')).toBe(E('unexpected token', 0));
    expect(err('-Infinity')).toBe(E('bad number', 0));
  });
});

describe('literals and structure', () => {
  it('literals, also in non-zero positions', () => {
    expect(strictParse('true')).toBe(true);
    expect(strictParse('false')).toBe(false);
    expect(strictParse('null')).toBeNull();
    expect(strictParse('[true,false,null]')).toEqual([true, false, null]);
    expect(strictParse('{"t":true,"f":false,"n":null}')).toEqual({ t: true, f: false, n: null });
    expect(strictParse('[null,true]')).toEqual([null, true]);
    expect(err('tru')).toBe(E('unexpected token', 0));
    expect(err('nul')).toBe(E('unexpected token', 0));
    expect(err('fals')).toBe(E('unexpected token', 0));
    expect(err('True')).toBe(E('unexpected token', 0));
    expect(err('x')).toBe(E('unexpected token', 0));
    expect(err('truefalse')).toBe(E('trailing characters after the JSON value', 4));
    expect(err('falsetrue')).toBe(E('trailing characters after the JSON value', 5));
    expect(err('nullnull')).toBe(E('trailing characters after the JSON value', 4));
    expect(err('[x,true]')).toBe(E('unexpected token', 1));
    expect(err('[1,tru]')).toBe(E('unexpected token', 3));
    expect(err("'a'")).toBe(E('unexpected token', 0));
    expect(err('//c\n1')).toBe(E('unexpected token', 0));
  });
  it('arrays and objects: shapes and exact errors', () => {
    expect(strictParse('[]')).toEqual([]);
    expect(strictParse('{}')).toEqual({});
    expect(strictParse('{"a":{"b":[1,2,{"c":null}]}}')).toEqual({ a: { b: [1, 2, { c: null }] } });
    expect(err('[')).toBe(E('unexpected end of input', 1));
    expect(err('[1')).toBe(E('expected "," or "]"', 2));
    expect(err('[1,')).toBe(E('unexpected end of input', 3));
    expect(err('[1,]')).toBe(E('unexpected token', 3));
    expect(err('[,1]')).toBe(E('unexpected token', 1));
    expect(err('[1 2]')).toBe(E('expected "," or "]"', 3));
    expect(err('[1}')).toBe(E('expected "," or "]"', 2));
    expect(err('{')).toBe(E('expected a string key', 1));
    expect(err('{"a"')).toBe(E('expected ":"', 4));
    expect(err('{"a" 1}')).toBe(E('expected ":"', 5));
    expect(err('{"a":}')).toBe(E('unexpected token', 5));
    expect(err('{"a":1,}')).toBe(E('expected a string key', 7));
    expect(err('{a:1}')).toBe(E('expected a string key', 1));
    expect(err('{1:1}')).toBe(E('expected a string key', 1));
    expect(err('{"a":1 "b":2}')).toBe(E('expected "," or "}"', 7));
    expect(err('{"a":1]')).toBe(E('expected "," or "}"', 6));
    expect(err('{"a":1')).toBe(E('expected "," or "}"', 6));
    expect(err('[1]x')).toBe(E('trailing characters after the JSON value', 3));
    expect(err('{} {}')).toBe(E('trailing characters after the JSON value', 3));
    expect(err('[] ,')).toBe(E('trailing characters after the JSON value', 3));
  });
  it('duplicate keys anywhere, with the key in the message', () => {
    expect(err('{"a":1,"a":2}')).toBe(E('duplicate key "a"', 10));
    expect(err('{"a":{"b":1,"b":2}}')).toBe(E('duplicate key "b"', 15));
    expect(err('{"a":1,"\\u0061":2}')).toContain('duplicate key "a"'); // escaped spelling of the same key
    expect(strictParse('{"a":{"a":1},"b":{"a":2}}')).toEqual({ a: { a: 1 }, b: { a: 2 } }); // siblings may reuse keys
    expect(strictParse('[{"a":1},{"a":2}]')).toEqual([{ a: 1 }, { a: 2 }]);
  });
  it('keys become plain own data properties (incl. __proto__) with full descriptors', () => {
    const o = strictParse('{"__proto__":{"x":1},"constructor":2}') as Record<string, unknown>;
    expect(Object.getPrototypeOf(o)).toBe(Object.prototype);
    expect(Object.keys(o)).toEqual(['__proto__', 'constructor']);
    expect(Object.getOwnPropertyDescriptor(o, '__proto__')).toEqual({ value: { x: 1 }, enumerable: true, writable: true, configurable: true });
    expect(Object.getOwnPropertyDescriptor(o, 'constructor')).toEqual({ value: 2, enumerable: true, writable: true, configurable: true });
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });
  it('nesting: 32 containers parse, 33 do not, arrays and objects, at the exact offset', () => {
    const arr = (n: number) => '['.repeat(n) + ']'.repeat(n);
    const obj = (n: number) => '{"a":'.repeat(n) + '1' + '}'.repeat(n);
    expect(strictParse(arr(32))).toBeTruthy();
    expect(strictParse(obj(32))).toBeTruthy();
    expect(err(arr(33))).toBe(E('nesting too deep', 32));
    expect(err(obj(33))).toBe(E('nesting too deep', 160));
    expect(err(arr(1000))).toBe(E('nesting too deep', 32));
    const mixed = (n: number): string => (n === 0 ? '1' : n % 2 ? `[${mixed(n - 1)}]` : `{"a":${mixed(n - 1)}}`);
    expect(strictParse(mixed(32))).toBeTruthy();
    expect(err(mixed(33))).toContain('nesting too deep');
  });
});
