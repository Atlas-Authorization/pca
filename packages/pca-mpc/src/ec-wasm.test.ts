/**
 * Constant-time WASM curve backend wiring (Task 1): prove that
 *   (1) the WASM core (`@atlasauth/pca-mpc-wasm`) is loaded as the DEFAULT curve backend here;
 *   (2) the `Point` ⇄ 32-byte compressed bridge round-trips faithfully (so a WASM result re-enters the
 *       rest of `ec.ts`/`ot.ts` as a byte-identical `Point`);
 *   (3) the exported group ops — now dispatched through the core — still obey the Ed25519 group law and
 *       agree, byte-for-byte, with the raw WASM core (compressPoint(op) == wasm.op(...)), which is the
 *       equivalence the wiring must preserve;
 *   (4) decompression rejects non-canonical / off-curve encodings.
 */

import { createRequire } from 'node:module';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  add,
  BASE,
  compressPoint,
  decompressPoint,
  equal,
  IDENTITY,
  isWasmCurveActive,
  L,
  mul,
  mulBase,
  neg,
  PointValidationError,
  Q,
  sub,
  toAffine,
} from './ec';

/** The canonical compressed Ed25519 basepoint (little-endian y=4/5, x even): 0x5866…66. */
const BASEPOINT_HEX = '5866666666666666666666666666666666666666666666666666666666666666';

/** Load the raw WASM core directly, as an INDEPENDENT reference to diff the dispatchers against. */
const wasm = (() => {
  const require = createRequire(__filename);
  const distPath = join(__dirname, '..', '..', 'pca-mpc-wasm', 'dist', 'index.js');
  return require(distPath) as {
    mulBase(k: bigint): Uint8Array;
    mul(k: bigint, p: Uint8Array): Uint8Array;
    add(a: Uint8Array, b: Uint8Array): Uint8Array;
    sub(a: Uint8Array, b: Uint8Array): Uint8Array;
    neg(a: Uint8Array): Uint8Array;
  };
})();

function hex(a: Uint8Array): string {
  return Buffer.from(a).toString('hex');
}

/** A uniform non-zero scalar in [1, L). */
function randScalar(): bigint {
  for (;;) {
    let a = 0n;
    for (const x of crypto.getRandomValues(new Uint8Array(32))) a = (a << 8n) | BigInt(x);
    const s = ((a % L) + L) % L;
    if (s !== 0n) return s;
  }
}

describe('WASM curve backend is the default', () => {
  it('is active in this environment', () => {
    expect(isWasmCurveActive()).toBe(true);
  });
});

describe('Point ⇄ compressed bridge', () => {
  it('BASE compresses to the canonical Ed25519 basepoint bytes', () => {
    expect(hex(compressPoint(BASE))).toBe(BASEPOINT_HEX);
  });

  it('IDENTITY compresses to y=1, sign=0', () => {
    const c = compressPoint(IDENTITY);
    expect(c[0]).toBe(1);
    expect(Array.from(c.slice(1)).every((b) => b === 0)).toBe(true);
  });

  it('compress∘decompress and decompress∘compress round-trip for random subgroup points', () => {
    for (let i = 0; i < 64; i++) {
      const p = mulBase(randScalar());
      const back = decompressPoint(compressPoint(p));
      expect(equal(back, p)).toBe(true);
      const a = toAffine(p);
      const b = toAffine(back);
      expect(a.x).toBe(b.x);
      expect(a.y).toBe(b.y);
    }
  });

  it('decompressPoint rejects a non-canonical / off-curve encoding', () => {
    expect(() => decompressPoint(new Uint8Array(31))).toThrow(PointValidationError);
    // 0xFF.. clears to y = 2^255-1 ≥ q (non-canonical) for most such bytes.
    const bad = new Uint8Array(32).fill(0xff);
    expect(() => decompressPoint(bad)).toThrow(PointValidationError);
  });
});

describe('dispatched ops are byte-identical to the raw WASM core', () => {
  it('mulBase / mul / add / sub / neg match wasm.* exactly', () => {
    for (let i = 0; i < 48; i++) {
      const k = randScalar();
      const a = mulBase(randScalar());
      const b = mulBase(randScalar());
      const ac = compressPoint(a);
      const bc = compressPoint(b);
      expect(hex(compressPoint(mulBase(k)))).toBe(hex(wasm.mulBase(k)));
      expect(hex(compressPoint(mul(k, a)))).toBe(hex(wasm.mul(k, ac)));
      expect(hex(compressPoint(add(a, b)))).toBe(hex(wasm.add(ac, bc)));
      expect(hex(compressPoint(sub(a, b)))).toBe(hex(wasm.sub(ac, bc)));
      expect(hex(compressPoint(neg(a)))).toBe(hex(wasm.neg(ac)));
    }
  });
});

describe('dispatched ops still obey the Ed25519 group law', () => {
  it('[L]·B = O, homomorphism, scalar reduction mod L', () => {
    expect(equal(mul(L, BASE), IDENTITY)).toBe(true);
    const a = 12345678901234567890123456789n;
    const b = 98765432109876543210987654321n;
    expect(equal(add(mulBase(a), mulBase(b)), mulBase(a + b))).toBe(true);
    expect(equal(mul(a, mulBase(b)), mulBase((a * b) % L))).toBe(true);
    expect(equal(add(BASE, neg(BASE)), IDENTITY)).toBe(true);
    expect(equal(sub(mulBase(7n), mulBase(7n)), IDENTITY)).toBe(true);
    // k and k+L and k-L are the same point (reduction).
    const k = randScalar();
    expect(equal(mulBase(k), mulBase(k + L))).toBe(true);
    expect(equal(mulBase(k), mulBase(((k - L) % L + L) % L))).toBe(true);
    expect(Q).toBe(2n ** 255n - 19n);
  });
});
