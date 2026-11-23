// Exact bounds of the import limits: the clamping messages, the byte pre-check of a text source and every byte, depth and node
// threshold of the parsed-source walk (at the limit passes, one over refuses), with the exact code and message of each refusal.
import { describe, expect, it } from 'vitest';
import { DEFAULT_IMPORT_LIMITS, checkParsed, resolveLimits, textSizeCheck, type ImportLimits } from '../src';

const err = (f: () => unknown): string => {
  try { f(); } catch (e) { return `${(e as { code?: string }).code}: ${(e as Error).message}`; }
  return 'none';
};
const L = (over: Partial<ImportLimits> = {}): ImportLimits => ({ ...DEFAULT_IMPORT_LIMITS, ...over });

describe('resolveLimits', () => {
  it('names the limit it refuses, and accepts 1', () => {
    expect(err(() => resolveLimits({ max_ops: 0 }))).toBe('bad_limit: limit max_ops must be a positive safe integer');
    expect(err(() => resolveLimits({ max_nodes: -3 }))).toBe('bad_limit: limit max_nodes must be a positive safe integer');
    expect(err(() => resolveLimits({ max_bytes: Number.MAX_SAFE_INTEGER + 1 }))).toBe('bad_limit: limit max_bytes must be a positive safe integer');
    expect(resolveLimits({ max_ops: 1 }).max_ops).toBe(1);
  });
});

describe('textSizeCheck', () => {
  it('refuses a non-text source', () => {
    expect(err(() => textSizeCheck(5 as never, L({ max_bytes: 10 })))).toBe('bad_source: the source must be text');
    expect(err(() => textSizeCheck(undefined as never, L({ max_bytes: 10 })))).toBe('bad_source: the source must be text');
  });
  it('compares the UTF-8 length with the limit exactly: at the limit passes, one over refuses', () => {
    // 4 UTF-16 units: the 3-bytes-per-unit bound (12) exceeds 10, so the real byte length decides
    expect(err(() => textSizeCheck('abcd', L({ max_bytes: 10 })))).toBe('none');
    expect(err(() => textSizeCheck('abcd', L({ max_bytes: 4 })))).toBe('none');
    expect(err(() => textSizeCheck('abcde', L({ max_bytes: 4 })))).toBe('import_limit: the source is larger than 4 bytes');
    // multi-byte: 2 units of 3 bytes = 6 bytes
    expect(err(() => textSizeCheck('€€', L({ max_bytes: 6 })))).toBe('none');
    expect(err(() => textSizeCheck('€€', L({ max_bytes: 5 })))).toBe('import_limit: the source is larger than 5 bytes');
  });
});

describe('checkParsed', () => {
  it('counts nodes and refuses past max_nodes', () => {
    expect(checkParsed([1, 2], L())).toBe(3);
    expect(checkParsed('abc', L())).toBe(1);
    expect(checkParsed([1, 2], L({ max_nodes: 3 }))).toBe(3);
    expect(err(() => checkParsed([1, 2], L({ max_nodes: 2 })))).toBe('import_limit: the source has more than 2 nodes');
  });
  it('refuses a source nested deeper than max_json_depth', () => {
    expect(checkParsed([[1]], L({ max_json_depth: 2 }))).toBe(3);
    expect(err(() => checkParsed([[1]], L({ max_json_depth: 1 })))).toBe('import_limit: the source nests deeper than 1');
    expect(err(() => checkParsed({ a: { b: 1 } }, L({ max_json_depth: 1 })))).toBe('import_limit: the source nests deeper than 1');
    expect(checkParsed({ a: { b: 1 } }, L({ max_json_depth: 2 }))).toBe(3);
  });
  it.each([
    ['null', null, 4], ['true', true, 4], ['false', false, 4], ['a number', 1, 8], ['a string', 'abc', 3],
    ['an empty array', [], 2], ['an array of two nulls', [null, null], 12], ['an object with one null', { a: null }, 9],
  ] as const)('%s weighs exactly %d bytes: refused one under, accepted at the limit', (_n, v, bytes) => {
    expect(err(() => checkParsed(v, L({ max_bytes: bytes - 1 })))).toBe(`import_limit: the source is larger than ${bytes - 1} bytes`);
    expect(err(() => checkParsed(v, L({ max_bytes: bytes })))).toBe('none');
  });
  it('refuses what is not plain JSON data, with the reason', () => {
    expect(err(() => checkParsed(NaN, L()))).toBe('bad_source: the source holds a non-finite number');
    expect(err(() => checkParsed([Infinity], L()))).toBe('bad_source: the source holds a non-finite number');
    expect(err(() => checkParsed(undefined, L()))).toBe('bad_source: the source holds a undefined');
    expect(err(() => checkParsed(() => 1, L()))).toBe('bad_source: the source holds a function');
    expect(err(() => checkParsed(Symbol('s'), L()))).toBe('bad_source: the source holds a symbol');
    expect(err(() => checkParsed(10n, L()))).toBe('bad_source: the source holds a bigint');
    expect(err(() => checkParsed(new Date(0), L()))).toBe('bad_source: the source holds a non-plain object');
    expect(err(() => checkParsed({ a: new Map() }, L()))).toBe('bad_source: the source holds a non-plain object');
    expect(err(() => checkParsed(new (class X { a = 1; })(), L()))).toBe('bad_source: the source holds a non-plain object');
  });
  it('accepts a null-prototype object as plain data', () => {
    const o = Object.create(null) as Record<string, unknown>;
    o.a = 1;
    expect(checkParsed(o, L())).toBe(2);
  });
});
