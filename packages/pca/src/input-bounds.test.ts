/**
 * T-046 (denial of service by oversized or deep input): every public decode entry point rejects an oversized or
 * pathologically nested input with a BOUNDED, TYPED failure, in bounded time and without a stack overflow. Each test
 * carries a wall-clock budget. The size cap is normative: MAX_JSON_BYTES (1 MiB) measured in UTF-8 BYTES.
 */
import { describe, expect, it } from 'vitest';
import { MAX_JSON_BYTES, StrictJsonError, strictParse, strictParseBytes } from './strict-json';
import { MAX_JSON_DEPTH, decodeB64uStrict, b64u } from './hash';
import { decodePCActn } from './pcactn';
import { decodePcaHeader, pcaHeaders } from './adapters';
import { decodeSafetyCertificate } from './safety-certificate';
import { MAX_LIMIT_LENGTH, parseLimit } from './facade';

const BUDGET_MS = 2000;
const timed = <T>(f: () => T): { out: T; ms: number } => {
  const t0 = performance.now();
  const out = f();
  return { out, ms: performance.now() - t0 };
};
const thrown = (f: () => unknown): unknown => {
  try {
    f();
  } catch (e) {
    return e;
  }
  return undefined;
};
const rejectMessage = (f: () => unknown): string => {
  const e = thrown(f);
  expect(e, 'expected a throw').toBeInstanceOf(StrictJsonError);
  return (e as StrictJsonError).message;
};
const bigString = (bytes: number) => `"${'a'.repeat(bytes - 2)}"`;

describe('T-046: strictParse input-size cap (1 MiB of UTF-8 bytes)', () => {
  it('MAX_JSON_BYTES is exactly 1 MiB', () => {
    expect(MAX_JSON_BYTES).toBe(1_048_576);
  });
  it('a document of exactly the cap parses; one byte more is rejected with "input too large" at offset 0', () => {
    const exact = timed(() => strictParse(bigString(MAX_JSON_BYTES)));
    expect((exact.out as string).length).toBe(MAX_JSON_BYTES - 2);
    expect(exact.ms).toBeLessThan(BUDGET_MS);
    const over = timed(() => rejectMessage(() => strictParse(bigString(MAX_JSON_BYTES + 1))));
    expect(over.out).toBe('strict JSON: input too large (at offset 0)');
    expect(over.ms).toBeLessThan(BUDGET_MS);
  });
  it('the bound is in UTF-8 BYTES, not UTF-16 units: 400k euro signs are 400k units but 1.2 MB', () => {
    const s = `"${'€'.repeat(400_000)}"`;
    expect(s.length).toBeLessThan(MAX_JSON_BYTES);
    expect(rejectMessage(() => strictParse(s))).toBe('strict JSON: input too large (at offset 0)');
    const ok = `"${'€'.repeat(349_000)}"`; // 1,047,002 bytes
    expect(strictParse(ok)).toBe('€'.repeat(349_000));
  });
  it('64 MiB of garbage, of whitespace and of an open array are each refused up front (no per-byte work)', () => {
    for (const body of ['x'.repeat(64 << 20), ' '.repeat(64 << 20), '['.repeat(64 << 20)]) {
      const r = timed(() => rejectMessage(() => strictParse(body)));
      expect(r.out).toBe('strict JSON: input too large (at offset 0)');
      expect(r.ms).toBeLessThan(BUDGET_MS);
    }
  });
  it('a large-but-legal flat array (about 500k elements) parses within budget', () => {
    const text = `[${'1,'.repeat(520_000)}1]`;
    expect(text.length).toBeLessThan(MAX_JSON_BYTES);
    const r = timed(() => strictParse(text) as unknown[]);
    expect(r.out.length).toBe(520_001);
    expect(r.ms).toBeLessThan(BUDGET_MS);
  });
  it('non-string input is a typed rejection, not a crash', () => {
    for (const v of [undefined, null, 5, {}, new Uint8Array(3)]) {
      expect(rejectMessage(() => strictParse(v as unknown as string))).toBe('strict JSON: input is not a string (at offset 0)');
    }
  });
});

describe('T-046: strictParse nesting bound', () => {
  const nest = (n: number, open: string, close: string, inner = '0') => open.repeat(n) + inner + close.repeat(n);
  it('depth exactly MAX_JSON_DEPTH parses; one more is rejected as "nesting too deep"', () => {
    expect(() => strictParse(nest(MAX_JSON_DEPTH, '[', ']'))).not.toThrow();
    expect(rejectMessage(() => strictParse(nest(MAX_JSON_DEPTH + 1, '[', ']')))).toMatch(/^strict JSON: nesting too deep \(at offset \d+\)$/);
  });
  it('the same bound applies to objects and to mixed nesting', () => {
    expect(rejectMessage(() => strictParse(nest(MAX_JSON_DEPTH + 1, '{"a":', '}')))).toMatch(/^strict JSON: nesting too deep/);
    const mixed = '[{"a":'.repeat(MAX_JSON_DEPTH) + '0' + '}]'.repeat(MAX_JSON_DEPTH);
    expect(rejectMessage(() => strictParse(mixed))).toMatch(/^strict JSON: nesting too deep/);
  });
  it('a 1 MiB-minus-epsilon run of "[" (~1M levels) is cut off at the depth limit: typed error, no stack overflow, fast', () => {
    const text = '['.repeat(MAX_JSON_BYTES - 1);
    const r = timed(() => thrown(() => strictParse(text)));
    expect(r.out).toBeInstanceOf(StrictJsonError);
    expect((r.out as StrictJsonError).message).toMatch(/^strict JSON: nesting too deep \(at offset \d+\)$/);
    expect(r.ms).toBeLessThan(BUDGET_MS);
  });
  it('a deep object spelled with a million "{" is likewise cut off', () => {
    const text = '{"a":'.repeat(200_000);
    const r = timed(() => rejectMessage(() => strictParse(text)));
    expect(r.out).toMatch(/^strict JSON: nesting too deep/);
    expect(r.ms).toBeLessThan(BUDGET_MS);
  });
});

describe('T-046: every decode entry point built on the strict parser', () => {
  const OVER = 'strict JSON: input too large (at offset 0)';
  it('strictParseBytes: oversized bytes are refused with the same typed error; invalid UTF-8 is a TypeError, never a hang', () => {
    const r = timed(() => rejectMessage(() => strictParseBytes(new Uint8Array(MAX_JSON_BYTES + 1).fill(0x61))));
    expect(r.out).toBe(OVER);
    expect(r.ms).toBeLessThan(BUDGET_MS);
    const bad = thrown(() => strictParseBytes(new Uint8Array(2 * MAX_JSON_BYTES).fill(0xff)));
    expect(bad).toBeInstanceOf(TypeError);
    expect(rejectMessage(() => strictParseBytes(new Uint8Array(MAX_JSON_BYTES * 2).fill(0x5b)))).toBe(OVER);
    expect(rejectMessage(() => strictParseBytes(new TextEncoder().encode('['.repeat(5000))))).toMatch(/nesting too deep/);
  });
  it('decodePCActn: an oversized object, an oversized-by-multibyte object and a deep object are all refused', () => {
    const oversize = `{"pad":"${'a'.repeat(MAX_JSON_BYTES)}"}`;
    const r = timed(() => rejectMessage(() => decodePCActn(oversize)));
    expect(r.out).toBe(OVER);
    expect(r.ms).toBeLessThan(BUDGET_MS);
    expect(rejectMessage(() => decodePCActn(`{"pad":"${'é'.repeat(600_000)}"}`))).toBe(OVER);
    expect(rejectMessage(() => decodePCActn('{"a":'.repeat(100_000)))).toMatch(/^strict JSON: nesting too deep/);
    expect(rejectMessage(() => decodePCActn(`[${'['.repeat(40)}${']'.repeat(40)}]`))).toMatch(/nesting too deep/);
  });
  it('decodePCActn: a non-object top level is a typed TypeError (not an oversize/hang path)', () => {
    expect(() => decodePCActn('[]')).toThrow('decodePCActn: not an object');
    expect(() => decodePCActn('"x"')).toThrow('decodePCActn: not an object');
  });
  it('header path: a base64url-wrapped oversized PCActn survives decodePcaHeader (linear, unbounded by design) and is then refused by decodePCActn', () => {
    const text = `{"pad":"${'a'.repeat(4 << 20)}"}`;
    const header = pcaHeaders(text)['PCA-Action']!;
    const r = timed(() => {
      const back = decodePcaHeader(header);
      return rejectMessage(() => decodePCActn(back));
    });
    expect(r.out).toBe(OVER);
    expect(r.ms).toBeLessThan(BUDGET_MS * 2);
  });
  it('decodePcaHeader: a huge non-base64url header is a bounded rejection', () => {
    const r = timed(() => thrown(() => decodePcaHeader('!'.repeat(8 << 20))));
    expect(r.out).toBeInstanceOf(Error);
    expect(r.ms).toBeLessThan(BUDGET_MS);
  });
  it('decodeSafetyCertificate: oversized input is refused (null) even when it is otherwise a well-formed JSON object', () => {
    const r = timed(() => decodeSafetyCertificate(`{"v":1,"pad":"${'a'.repeat(MAX_JSON_BYTES)}"}`));
    expect(r.out).toBeNull();
    expect(r.ms).toBeLessThan(BUDGET_MS);
    expect(decodeSafetyCertificate('['.repeat(MAX_JSON_BYTES - 1))).toBeNull();
    expect(decodeSafetyCertificate('{"a":'.repeat(150_000))).toBeNull();
    expect(decodeSafetyCertificate(undefined as unknown as string)).toBeNull();
  });
  it('decodeB64uStrict: a 32 MiB string is rejected in linear time (alphabet/length), and a huge valid one decodes without recursion', () => {
    const bad = timed(() => decodeB64uStrict('A'.repeat((32 << 20) + 1)));
    expect(bad.out).toBeNull();
    expect(bad.ms).toBeLessThan(BUDGET_MS * 2);
    expect(decodeB64uStrict('A'.repeat(1 << 20) + '*')).toBeNull();
    expect(decodeB64uStrict('A'.repeat(1 << 20), 32)).toBeNull();
    const ok = timed(() => decodeB64uStrict(b64u(new Uint8Array(1 << 20))));
    expect(ok.out?.length).toBe(1 << 20);
    expect(ok.ms).toBeLessThan(BUDGET_MS);
  });
  it('parseLimit: a megabyte of garbage or whitespace is refused by a length cap in constant time (was quadratic backtracking)', () => {
    expect(MAX_LIMIT_LENGTH).toBe(64);
    for (const s of ['9'.repeat(MAX_JSON_BYTES) + 'x', ' '.repeat(MAX_JSON_BYTES) + 'x', '$' + '1'.repeat(MAX_JSON_BYTES) + '/' + 'a'.repeat(1000) + '!']) {
      const r = timed(() => thrown(() => parseLimit(s)));
      expect(r.out).toBeInstanceOf(Error);
      expect((r.out as Error).message).toBe('parseLimit: limit is longer than 64 characters');
      expect(r.ms).toBeLessThan(BUDGET_MS);
    }
  });
  it('parseLimit: at the cap, whitespace-heavy input is still linear and fails with the parse error (error text is bounded)', () => {
    const s = ' '.repeat(MAX_LIMIT_LENGTH - 1) + 'x';
    const e = thrown(() => parseLimit(s)) as Error;
    expect(e.message).toBe(`parseLimit: cannot parse limit '${s}'`);
    expect(e.message.length).toBeLessThan(120);
  });
  it('parseLimit still accepts the documented forms, with or without surrounding whitespace', () => {
    expect(parseLimit('  $500 / day  ')).toEqual({ amount: 500, unit: 'usd', periodMs: 86_400_000 });
    expect(parseLimit('10')).toEqual({ amount: 10, unit: 'count' });
    expect(parseLimit('$ 2.5/hour')).toEqual({ amount: 2.5, unit: 'usd', periodMs: 3_600_000 });
  });
});
