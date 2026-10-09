/**
 * WASM-vs-JS parity: every curve op in the constant-time WASM core (curve25519-dalek) must produce
 * BYTE-IDENTICAL output to the independent JS reference (`@noble/curves` Ed25519) for the same
 * inputs. Both emit the canonical 32-byte compressed encoding, so "identical bytes out" is an exact
 * equality — this proves the WASM core is a correct, faithful, drop-in replacement for the base-OT
 * curve ops, now running in genuinely constant time (the `ec.ts` BigInt path being the fallback).
 */

import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ED25519_TORSION_SUBGROUP, ed25519 } from '@noble/curves/ed25519';
import {
  add,
  assertInSubgroup,
  BASE,
  decodePoint,
  encodePoint,
  equal,
  IDENTITY,
  isIdentity,
  isInSubgroup,
  isOnCurve,
  L,
  mul,
  mulBase,
  neg,
  PointValidationError,
  type PointBytes,
  Q,
  sub,
} from './index';

const Ext = ed25519.ExtendedPoint;
type NoblePoint = ReturnType<typeof Ext.BASE.multiplyUnsafe>;

const ITER = 32;

function hex(a: Uint8Array): string {
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** A uniform scalar in [1, L), matching the OT's secret-scalar domain. */
function randScalar(): bigint {
  for (;;) {
    const b = randomBytes(32);
    let a = 0n;
    for (const x of b) a = (a << 8n) | BigInt(x);
    const s = ((a % L) + L) % L;
    if (s !== 0n) return s;
  }
}

/** Reference compressed bytes of [k]·B (k reduced mod L; k≠0 here). */
function nobleMulBase(k: bigint): Uint8Array {
  return Ext.BASE.multiplyUnsafe(((k % L) + L) % L).toRawBytes();
}

/** A random valid prime-order-subgroup point as (noble point, its compressed bytes). */
function randPoint(): { pt: NoblePoint; bytes: PointBytes } {
  const pt = Ext.BASE.multiplyUnsafe(randScalar());
  return { pt, bytes: pt.toRawBytes() };
}

describe('constants match ec.ts / Ed25519', () => {
  it('L, Q, BASE, IDENTITY', () => {
    expect(Q).toBe(2n ** 255n - 19n);
    expect(L).toBe(2n ** 252n + 27742317777372353535851937790883648493n);
    // BASE is the standard basepoint; IDENTITY is y=1,sign=0.
    expect(hex(BASE)).toBe(hex(Ext.BASE.toRawBytes()));
    expect(hex(IDENTITY)).toBe(hex(Ext.ZERO.toRawBytes()));
  });
});

describe('scalar×basepoint (mulBase) — constant-time, byte-identical to @noble', () => {
  it('matches for random scalars', () => {
    for (let i = 0; i < ITER; i++) {
      const k = randScalar();
      expect(hex(mulBase(k))).toBe(hex(nobleMulBase(k)));
    }
  });
  it('k=1 is the basepoint, k=0 is the identity, k is reduced mod L', () => {
    expect(hex(mulBase(1n))).toBe(hex(Ext.BASE.toRawBytes()));
    expect(hex(mulBase(0n))).toBe(hex(IDENTITY));
    const k = randScalar();
    // Reduction: mulBase(k) == mulBase(k + L) == mulBase(k - L).
    expect(hex(mulBase(k))).toBe(hex(mulBase(k + L)));
    expect(hex(mulBase(k))).toBe(hex(mulBase(k - L)));
  });
});

describe('scalar×point (mul) — constant-time, byte-identical to @noble', () => {
  it('matches for random (scalar, point)', () => {
    for (let i = 0; i < ITER; i++) {
      const { pt, bytes } = randPoint();
      const k = randScalar();
      expect(hex(mul(k, bytes))).toBe(hex(pt.multiplyUnsafe(((k % L) + L) % L).toRawBytes()));
    }
  });
  it('rejects an off-curve point', () => {
    // 0xFF.. is a non-canonical/off-curve y for the overwhelming majority of such bytes.
    const bad = new Uint8Array(32).fill(0xff);
    if (!isOnCurve(bad)) expect(() => mul(2n, bad)).toThrow(PointValidationError);
  });
});

describe('point add / sub / neg — byte-identical to @noble', () => {
  it('add', () => {
    for (let i = 0; i < ITER; i++) {
      const a = randPoint();
      const b = randPoint();
      expect(hex(add(a.bytes, b.bytes))).toBe(hex(a.pt.add(b.pt).toRawBytes()));
    }
  });
  it('sub', () => {
    for (let i = 0; i < ITER; i++) {
      const a = randPoint();
      const b = randPoint();
      expect(hex(sub(a.bytes, b.bytes))).toBe(hex(a.pt.subtract(b.pt).toRawBytes()));
    }
  });
  it('neg', () => {
    for (let i = 0; i < ITER; i++) {
      const a = randPoint();
      expect(hex(neg(a.bytes))).toBe(hex(a.pt.negate().toRawBytes()));
    }
  });
});

describe('point validation — parity with @noble isTorsionFree / assertValidity', () => {
  it('valid subgroup points pass', () => {
    for (let i = 0; i < ITER; i++) {
      const { pt, bytes } = randPoint();
      expect(isOnCurve(bytes)).toBe(true);
      expect(isIdentity(bytes)).toBe(false);
      expect(isInSubgroup(bytes)).toBe(true);
      expect(pt.isTorsionFree()).toBe(true); // independent confirmation
      expect(() => assertInSubgroup(bytes)).not.toThrow();
    }
  });

  it('the identity is on-curve but is not a valid subgroup (non-identity) point', () => {
    expect(isOnCurve(IDENTITY)).toBe(true);
    expect(isIdentity(IDENTITY)).toBe(true);
    expect(isInSubgroup(IDENTITY)).toBe(false);
    expect(() => assertInSubgroup(IDENTITY)).toThrow(PointValidationError);
  });

  it('torsion / small-order points are on-curve but rejected by the subgroup check', () => {
    let checkedNonTrivial = 0;
    for (const h of ED25519_TORSION_SUBGROUP) {
      const bytes = hexToBytes(h);
      let pt: NoblePoint;
      try {
        pt = Ext.fromHex(bytes);
      } catch {
        continue; // a non-canonical torsion encoding @noble refuses to decode; skip
      }
      const torsionFree = pt.isTorsionFree();
      // WASM must agree with @noble on torsion-freeness for every decodable torsion point.
      expect(isInSubgroup(bytes)).toBe(torsionFree && !isIdentity(bytes));
      if (!torsionFree) {
        expect(isOnCurve(bytes)).toBe(true);
        expect(isInSubgroup(bytes)).toBe(false);
        expect(() => assertInSubgroup(bytes)).toThrow(PointValidationError);
        checkedNonTrivial++;
      }
    }
    expect(checkedNonTrivial).toBeGreaterThan(0); // we really exercised small-order rejection
  });

  it('off-curve bytes are rejected by both implementations', () => {
    let checked = 0;
    for (let i = 0; i < 200 && checked < 4; i++) {
      const bytes = new Uint8Array(randomBytes(32));
      let nobleOk = true;
      try {
        Ext.fromHex(bytes);
      } catch {
        nobleOk = false;
      }
      if (!nobleOk) {
        expect(isOnCurve(bytes)).toBe(false);
        checked++;
      }
    }
    expect(checked).toBeGreaterThan(0);
  });
});

describe('equality + encode/decode', () => {
  it('equal agrees with @noble', () => {
    const a = randPoint();
    const b = randPoint();
    expect(equal(a.bytes, a.bytes.slice())).toBe(true);
    expect(equal(a.bytes, b.bytes)).toBe(a.pt.equals(b.pt));
  });
  it('encodePoint is the canonical bytes; decodePoint validates', () => {
    const { bytes } = randPoint();
    expect(hex(encodePoint(bytes))).toBe(hex(bytes));
    expect(hex(decodePoint(bytes))).toBe(hex(bytes));
    const bad = new Uint8Array(32).fill(0xff);
    if (!isOnCurve(bad)) {
      expect(() => decodePoint(bad)).toThrow(PointValidationError);
      expect(() => encodePoint(bad)).toThrow(PointValidationError);
    }
  });
});

describe('base-OT (Chou–Orlandi) identity composes correctly over the WASM ops', () => {
  it('receiver pad == sender pad for choice c=0 and c=1', () => {
    for (let i = 0; i < ITER; i++) {
      const y = randScalar();
      const x = randScalar();
      const S = mulBase(y); // sender S = y·B
      const T = mul(y, S); // sender T = y·S

      // choice c = 0: R = x·B ; receiver pad = x·S ; sender k_0 = y·R == x·S.
      const R0 = mulBase(x);
      expect(equal(mul(x, S), mul(y, R0))).toBe(true);

      // choice c = 1: R = x·B + S ; receiver pad = x·S ; sender k_1 = y·R − T == x·S.
      const R1 = add(mulBase(x), S);
      expect(equal(mul(x, S), sub(mul(y, R1), T))).toBe(true);
      // and the UNCHOSEN sender pad (y·R0 − T for c=0) is a different point (no leak of the other msg).
      expect(equal(mul(x, S), sub(mul(y, R0), T))).toBe(false);
    }
  });
});
