/**
 * Adversarial / audit-style tests for @atlasauth/pca-mpc-wasm (the WebAssembly Ed25519 group core).
 * Complements the byte-parity and vector suites: strict point decoding (non-canonical y, x = 0 with a
 * sign bit, torsion, off-curve), wrong lengths and wrong types, scalar reduction behaviour, shared
 * scratch-memory isolation between calls, algebraic laws, and bounded fuzzing of every entry point.
 * Fuzz seconds: `AUDIT_FUZZ_SECONDS` (default 3).
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  BASE,
  IDENTITY,
  L,
  PointValidationError,
  Q,
  add,
  assertInSubgroup,
  decodePoint,
  encodePoint,
  equal,
  isIdentity,
  isInSubgroup,
  isOnCurve,
  mul,
  mulBase,
  neg,
  sub,
} from './index';

const FUZZ_MS = Number(process.env.AUDIT_FUZZ_SECONDS ?? '3') * 1000;
const fuzzOpts = { numRuns: 1_000_000, interruptAfterTimeLimit: FUZZ_MS, markInterruptAsFailure: false } as const;
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

function le(v: bigint, sign = 0): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  out[31] = (out[31] ?? 0) | (sign << 7);
  return out;
}

/** The 8-element torsion subgroup (as canonical encodings), found by cofactor-clearing generic curve points. */
function torsion(): Uint8Array[] {
  const found = new Map<string, Uint8Array>([[hex(IDENTITY), IDENTITY]]);
  for (let y = 2n; found.size < 8 && y < 400n; y++) {
    const p = le(y);
    if (!isOnCurve(p)) continue;
    // [L]P: scalar_mul reduces the scalar mod L, so multiply by (L-1) and add P back
    const t = add(mul(L - 1n, p), p);
    found.set(hex(t), t);
  }
  return [...found.values()];
}

describe('canonical point decoding (a point must have exactly ONE accepted encoding)', () => {
  const nonCanonicalIdentity = le(Q + 1n); // y = 1 + q: the same field element as y = 1
  const idWithSign = le(1n, 1); // x = 0 has no "negative" root
  const yEqQ = le(Q);
  const allOnes = new Uint8Array(32).fill(0xff);
  allOnes[31] = 0x7f;

  it('non-canonical y (>= q) and x = 0 with the sign bit set are rejected everywhere, not silently reduced', () => {
    for (const bad of [nonCanonicalIdentity, idWithSign, yEqQ, allOnes, le(Q + 5n)]) {
      expect(isOnCurve(bad), hex(bad)).toBe(false);
      expect(isIdentity(bad)).toBe(false);
      expect(isInSubgroup(bad)).toBe(false);
      expect(() => assertInSubgroup(bad)).toThrow(PointValidationError);
      expect(() => decodePoint(bad)).toThrow(PointValidationError);
      expect(() => add(bad, BASE)).toThrow(PointValidationError);
      expect(() => sub(BASE, bad)).toThrow(PointValidationError);
      expect(() => neg(bad)).toThrow(PointValidationError);
      expect(() => mul(3n, bad)).toThrow(PointValidationError);
      expect(equal(bad, IDENTITY)).toBe(false);
    }
  });

  it('exhaustive over small y: accepted encodings are exactly the canonical on-curve ones, and every accepted point re-encodes to itself', () => {
    let accepted = 0;
    for (let y = 0n; y < 300n; y++) {
      for (const sign of [0, 1]) {
        const e = le(y, sign);
        if (!isOnCurve(e)) continue;
        accepted++;
        expect(hex(encodePoint(e))).toBe(hex(e));
        expect(hex(add(e, IDENTITY))).toBe(hex(e));
        expect(equal(e, e)).toBe(true);
      }
    }
    expect(accepted).toBeGreaterThan(100);
  });
});

describe('small-order and mixed-order points', () => {
  it('the torsion subgroup has 8 elements; all 7 non-identity elements are on-curve, non-identity, outside the prime-order subgroup and rejected by assertInSubgroup', () => {
    const tors = torsion();
    expect(tors.length).toBe(8);
    for (const t of tors) {
      expect(isOnCurve(t)).toBe(true);
      if (hex(t) === hex(IDENTITY)) {
        expect(isIdentity(t)).toBe(true);
        expect(() => assertInSubgroup(t)).toThrow(/identity/);
        continue;
      }
      expect(isIdentity(t)).toBe(false);
      expect(isInSubgroup(t)).toBe(false);
      expect(() => assertInSubgroup(t)).toThrow(/prime-order subgroup/);
      expect(isInSubgroup(add(mulBase(11n), t))).toBe(false); // mixed order
      expect(isInSubgroup(mulBase(11n))).toBe(true);
    }
  });

  it('the identity is on-curve but is never accepted as a base-OT point; the generator and its multiples are', () => {
    expect(isOnCurve(IDENTITY)).toBe(true);
    expect(isInSubgroup(IDENTITY)).toBe(false);
    expect(() => assertInSubgroup(IDENTITY)).toThrow();
    for (const k of [1n, 2n, L - 1n]) expect(() => assertInSubgroup(mulBase(k))).not.toThrow();
  });
});

describe('wrong lengths and wrong types', () => {
  it('every entry rejects (or reports false for) anything that is not exactly 32 bytes', () => {
    for (const n of [0, 1, 31, 33, 64]) {
      const p = new Uint8Array(n).fill(1);
      expect(isOnCurve(p)).toBe(false);
      expect(isIdentity(p)).toBe(false);
      expect(isInSubgroup(p)).toBe(false);
      expect(equal(p, BASE)).toBe(false);
      expect(() => add(p, BASE)).toThrow(PointValidationError);
      expect(() => mul(2n, p)).toThrow(PointValidationError);
      expect(() => neg(p)).toThrow(PointValidationError);
      expect(() => decodePoint(p)).toThrow(PointValidationError);
      expect(() => assertInSubgroup(p)).toThrow(PointValidationError);
    }
  });

  it('non-byte arguments never succeed silently: strings, null, plain objects and numbers are rejected or reported false', () => {
    const junk: unknown[] = [null, undefined, 'a'.repeat(32), 5, {}, { length: 32 }];
    for (const j of junk) {
      let r: unknown;
      try {
        r = isOnCurve(j as Uint8Array);
      } catch (e) {
        expect(e instanceof Error).toBe(true);
        r = false;
      }
      expect(r).toBe(false);
      expect(() => add(j as Uint8Array, BASE)).toThrow();
    }
  });
});

describe('scalar handling', () => {
  it('scalars are reduced mod L: 0, L and k+L give the documented results; negative scalars behave as -k', () => {
    expect(hex(mulBase(0n))).toBe(hex(IDENTITY));
    expect(hex(mulBase(L))).toBe(hex(IDENTITY));
    expect(hex(mulBase(L + 5n))).toBe(hex(mulBase(5n)));
    expect(hex(mulBase(-5n))).toBe(hex(neg(mulBase(5n))));
    expect(hex(mul(0n, BASE))).toBe(hex(IDENTITY));
    expect(hex(mulBase(2n ** 300n))).toBe(hex(mulBase((2n ** 300n) % L)));
  });

  it('non-bigint scalars are a typed failure (no silent coercion of numbers / strings)', () => {
    for (const k of [5, '5', null, undefined, 5.5] as unknown[]) {
      expect(() => mulBase(k as bigint)).toThrow();
      expect(() => mul(k as bigint, BASE)).toThrow();
    }
  });
});

describe('shared scratch memory: results must not leak between calls', () => {
  it('interleaved operations return independent buffers (mutating one result never changes another or a later call)', () => {
    const a = mulBase(7n);
    const b = mulBase(8n);
    const aCopy = Uint8Array.from(a);
    b.fill(0xee);
    expect(hex(a)).toBe(hex(aCopy));
    const c = add(a, mulBase(1n));
    expect(hex(c)).toBe(hex(mulBase(8n)));
    // a failed call must not poison the next one
    expect(() => add(le(Q), BASE)).toThrow(PointValidationError);
    expect(hex(add(a, mulBase(1n)))).toBe(hex(mulBase(8n)));
    // inputs are not modified
    const input = Uint8Array.from(BASE);
    mul(5n, input);
    expect(hex(input)).toBe(hex(BASE));
  });
});

describe('group laws (property)', () => {
  const k = fc.bigInt({ min: 1n, max: L - 1n });
  it('associative, commutative, inverse, homomorphism, double-negation, distributivity of scalar mul', () => {
    fc.assert(
      fc.property(k, k, k, (a, b, c) => {
        const A = mulBase(a);
        const B = mulBase(b);
        const C = mulBase(c);
        return (
          hex(add(add(A, B), C)) === hex(add(A, add(B, C))) &&
          hex(add(A, B)) === hex(add(B, A)) &&
          hex(add(A, neg(A))) === hex(IDENTITY) &&
          hex(neg(neg(A))) === hex(A) &&
          hex(mulBase((a + b) % L)) === hex(add(A, B)) &&
          hex(mul(b, A)) === hex(mulBase((a * b) % L)) &&
          hex(sub(A, B)) === hex(add(A, neg(B))) &&
          equal(A, mulBase(a)) &&
          (a === b || !equal(A, B))
        );
      }),
      { numRuns: 60 },
    );
  });
});

describe('bounded fuzzing (no uncaught non-typed exception, no hang, canonical outputs)', () => {
  it('arbitrary 32-byte inputs through every op: either a typed refusal or a canonical, on-curve result', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.bigInt({ min: -(2n ** 300n), max: 2n ** 300n }), (a, b, k) => {
        const t0 = performance.now();
        const attempt = (f: () => Uint8Array) => {
          try {
            const r = f();
            expect(r.length).toBe(32);
            expect(isOnCurve(r)).toBe(true);
          } catch (e) {
            expect(e).toBeInstanceOf(PointValidationError);
          }
        };
        attempt(() => add(a, b));
        attempt(() => sub(a, b));
        attempt(() => neg(a));
        attempt(() => mul(k, a));
        attempt(() => decodePoint(a));
        const on = isOnCurve(a);
        expect(isInSubgroup(a)).toBe(on && isInSubgroup(a));
        if (isInSubgroup(a)) expect(on).toBe(true);
        expect(performance.now() - t0).toBeLessThan(1000);
        return true;
      }),
      fuzzOpts,
    );
  });
});
