/**
 * Regression tests for defects found by the structure-aware fuzzer (tools/pca-audit/fuzz). Each test pins the
 * input class that produced an untyped exception; the typed-error contract is "a verdict or a documented error,
 * never a runtime TypeError".
 */
import { describe, expect, it } from 'vitest';
import { delegate, mintRoot, verifyChain } from './capability';
import { acceptBeacon } from './beacons';
import { generateKeyPair, encodeKey } from './keys';
import { StrictJsonError, strictParse, strictParseBytes } from './strict-json';

describe('strictParseBytes: every deviation is a StrictJsonError (fuzz finding: raw TypeError from TextDecoder)', () => {
  it.each([
    ['a lone continuation byte', [0x80]],
    ['an overlong NUL', [0xc0, 0x80]],
    ['a truncated 3-byte sequence', [0xe2, 0x82]],
    ['an encoded surrogate', [0xed, 0xa0, 0x80]],
    ['0xff', [0x22, 0xff, 0x22]],
  ])('rejects invalid UTF-8 (%s) with StrictJsonError', (_n, bytes) => {
    expect(() => strictParseBytes(Uint8Array.from(bytes))).toThrow(StrictJsonError);
    expect(() => strictParseBytes(Uint8Array.from(bytes))).toThrow(/not valid UTF-8/);
  });

  it('rejects non-byte input with StrictJsonError and still parses valid UTF-8 identically to strictParse', () => {
    for (const bad of ['{}', 5, null, undefined, [123], new ArrayBuffer(2)]) {
      expect(() => strictParseBytes(bad as never)).toThrow(StrictJsonError);
    }
    const text = '{"a":[1,"é",null]}';
    expect(strictParseBytes(new TextEncoder().encode(text))).toEqual(strictParse(text));
  });

  it('a UTF-8 BOM is not skipped (ignoreBOM) and is a strict-JSON error, not a TypeError', () => {
    expect(() => strictParseBytes(Uint8Array.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]))).toThrow(StrictJsonError);
  });
});

describe('verifyChain is total (fuzz finding: TypeError from canonicalize on an unsafe integer caveat)', () => {
  const principal = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const root = mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: pPub, caveats: [{ type: 'expires', at: 1 }] } as never);

  it.each([
    ['an integer beyond 2^53', 2 ** 60],
    ['a float that cannot canonicalize (Infinity)', Infinity],
    ['NaN', NaN],
  ])('a hop carrying %s yields {ok:false}, not an exception', (_n, at) => {
    const bad = { ...root, caveats: [{ type: 'expires', at }] };
    let r: ReturnType<typeof verifyChain> | undefined;
    expect(() => {
      r = verifyChain([bad as never]);
    }).not.toThrow();
    expect(r!.ok).toBe(false);
  });

  it('a hostile LATER hop is also a verdict', () => {
    const agent = generateKeyPair();
    const child = delegate(root, encodeKey(agent.publicKey), [{ type: 'expires', at: 2 }], principal.secretKey);
    const bad = { ...child, caveats: [...child.caveats, { type: 'x', n: 2 ** 70 }] };
    expect(verifyChain([root, bad as never]).ok).toBe(false);
  });

  it('the valid chain still verifies', () => {
    const agent = generateKeyPair();
    const child = delegate(root, encodeKey(agent.publicKey), [{ type: 'expires', at: 2 }], principal.secretKey);
    expect(verifyChain([root, child], pPub)).toEqual({ ok: true });
  });
});

describe('acceptBeacon is total (fuzz finding: TypeError reading seq of a missing beacon)', () => {
  it.each([[undefined], [null], [5], ['x'], [{}], [{ seq: '3' }], [{ seq: 1.5 }], [{ seq: -1 }], [{ seq: NaN }], [{ seq: 2 ** 60 }]])('refuses %j', (next) => {
    expect(acceptBeacon({ seq: 3 }, next as never)).toEqual({ ok: false, reason: 'malformed beacon' });
    expect(acceptBeacon(null, next as never)).toEqual({ ok: false, reason: 'malformed beacon' });
  });

  it('keeps the monotonic rule for well-formed beacons', () => {
    expect(acceptBeacon({ seq: 3 }, { seq: 4 } as never)).toEqual({ ok: true });
    expect(acceptBeacon({ seq: 3 }, { seq: 3 } as never).ok).toBe(false);
    expect(acceptBeacon({ seq: 3 }, { seq: 2 } as never).ok).toBe(false);
    expect(acceptBeacon(null, { seq: 0 } as never)).toEqual({ ok: true });
    expect(acceptBeacon(undefined, { seq: 7 } as never)).toEqual({ ok: true });
  });
});
