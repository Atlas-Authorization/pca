/**
 * Mutation-kill suite for ec.ts on the PURE-BigInt backend (the WASM core is made unloadable by making
 * `createRequire` throw). Every group operation is checked against an independent affine reference
 * implementation of the Ed25519 group law written here, plus exact validation / decompression / Schnorr
 * behaviour (reason strings, boundaries, a Fiat-Shamir known-answer computed independently).
 */
import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

vi.mock('node:module', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:module')>();
  return {
    ...actual,
    createRequire: () => {
      throw new Error('createRequire unavailable (pure-path test)');
    },
  };
});

import {
  BASE,
  IDENTITY,
  L,
  PointValidationError,
  Q,
  add,
  assertInSubgroup,
  compressPoint,
  dbl,
  decompressPoint,
  encodePoint,
  equal,
  hasPrimeOrder,
  isIdentity,
  isInSubgroup,
  isOnCurve,
  isWasmCurveActive,
  modFq,
  mul,
  mulBase,
  neg,
  schnorrProve,
  schnorrVerify,
  sub,
  toAffine,
  type Point,
} from './ec';

// ---------- independent affine reference (a = -1 twisted Edwards, d = -121665/121666) ----------
const P = 2n ** 255n - 19n;
const md = (x: bigint): bigint => ((x % P) + P) % P;
const pw = (b: bigint, e: bigint): bigint => {
  let r = 1n;
  let x = md(b);
  let k = e;
  while (k > 0n) {
    if (k & 1n) r = (r * x) % P;
    x = (x * x) % P;
    k >>= 1n;
  }
  return r;
};
const inv = (a: bigint): bigint => pw(a, P - 2n);
const dC = md(-121665n * inv(121666n));
const SQRT_M1 = pw(2n, (P - 1n) / 4n);
type Aff = [bigint, bigint];
const affAdd = ([x1, y1]: Aff, [x2, y2]: Aff): Aff => {
  const t = md(dC * x1 * x2 * y1 * y2);
  return [md((x1 * y2 + y1 * x2) * inv(1n + t)), md((y1 * y2 + x1 * x2) * inv(md(1n - t)))];
};
const affMul = (k: bigint, p: Aff): Aff => {
  let acc: Aff = [0n, 1n];
  let b = p;
  let e = k;
  while (e > 0n) {
    if (e & 1n) acc = affAdd(acc, b);
    b = affAdd(b, b);
    e >>= 1n;
  }
  return acc;
};
const aff = (p: Point): Aff => {
  const zi = inv(p.Z);
  return [md(p.X * zi), md(p.Y * zi)];
};
/** Extended point from affine, scaled by a projective factor z (exercises Z != 1 everywhere). */
const ext = ([x, y]: Aff, z = 1n): Point => ({ X: md(x * z), Y: md(y * z), Z: md(z), T: md(x * y * z) });
const BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;
const B: Aff = [BX, BY];
const le = (v: bigint): number[] => Array.from({ length: 32 }, (_, i) => Number((md(v) >> BigInt(8 * i)) & 0xffn));
const T2: Aff = [0n, P - 1n]; // order 2
const T4: Aff = [SQRT_M1, 0n]; // order 4
const errOf = (f: () => unknown): Error => {
  try {
    f();
  } catch (e) {
    return e as Error;
  }
  throw new Error('did not throw');
};

describe('backend', () => {
  it('the pure path is in use when the WASM core cannot be required', () => {
    expect(isWasmCurveActive()).toBe(false);
    expect(isWasmCurveActive()).toBe(false);
  });
  it('exports the curve constants', () => {
    expect(Q).toBe(P);
    expect(L).toBe(2n ** 252n + 27742317777372353535851937790883648493n);
    expect(aff(BASE)).toEqual(B);
    expect(BASE.Z).toBe(1n);
    expect(BASE.T).toBe(md(BX * BY));
    expect(IDENTITY).toEqual({ X: 0n, Y: 1n, Z: 1n, T: 0n });
  });
  it('modFq is the canonical representative', () => {
    expect(modFq(-1n)).toBe(P - 1n);
    expect(modFq(P)).toBe(0n);
    expect(modFq(P + 5n)).toBe(5n);
    expect(modFq(0n)).toBe(0n);
    expect(modFq(-P)).toBe(0n);
  });
});

describe('group law (pure) vs the affine reference', () => {
  const P3 = affMul(3n, B);
  const P5 = affMul(5n, B);
  it('add of distinct, equal, identity and projectively-scaled operands', () => {
    expect(aff(add(ext(P3, 7n), ext(P5, 11n)))).toEqual(affAdd(P3, P5));
    expect(aff(add(ext(P3), ext(P3, 9n)))).toEqual(affAdd(P3, P3));
    expect(aff(add(IDENTITY, ext(P5, 3n)))).toEqual(P5);
    expect(aff(add(ext(T2), ext(P3)))).toEqual(affAdd(T2, P3));
    expect(aff(add(ext(T4, 5n), ext(T4)))).toEqual(affAdd(T4, T4));
  });
  it('add output keeps the extended invariant T*Z = X*Y', () => {
    const r = add(ext(P3, 7n), ext(P5, 11n));
    expect(md(r.T * r.Z)).toBe(md(r.X * r.Y));
    expect(isOnCurve(r)).toBe(true);
  });
  it('dbl matches P + P and keeps the invariant', () => {
    for (const p of [P3, P5, T4, B]) {
      const r = dbl(ext(p, 13n));
      expect(aff(r)).toEqual(affAdd(p, p));
      expect(md(r.T * r.Z)).toBe(md(r.X * r.Y));
    }
  });
  it('mul: 0, 1, 2, small k, k reduced mod L, negative k', () => {
    expect(isIdentity(mul(0n, ext(P3)))).toBe(true);
    expect(aff(mul(1n, ext(P3, 4n)))).toEqual(P3);
    expect(aff(mul(2n, ext(P3)))).toEqual(affAdd(P3, P3));
    expect(aff(mul(13n, BASE))).toEqual(affMul(13n, B));
    expect(isIdentity(mul(L, BASE))).toBe(true);
    expect(aff(mul(L + 3n, BASE))).toEqual(affMul(3n, B));
    expect(aff(mul(-1n, BASE))).toEqual([md(-BX), BY]);
    expect(aff(mul(-L - 2n, BASE))).toEqual(affMul(L - 2n, B));
  });
  it('mul reduces k mod L even for a point outside the subgroup (k = 0 and k = L give the identity)', () => {
    // [L]·T2 = T2 since L is odd; a ladder that ran L steps instead of reducing would not give O.
    expect(isIdentity(mul(0n, ext(T2)))).toBe(true);
    expect(isIdentity(mul(L, ext(T2)))).toBe(true);
    expect(aff(mul(1n, ext(T2)))).toEqual(T2);
  });
  it('mulBase is [k]B', () => {
    for (const k of [1n, 2n, 7n, 123456789n, L - 1n]) expect(aff(mulBase(k))).toEqual(affMul(k, B));
  });
  it('sub and neg', () => {
    expect(aff(neg(ext(P3, 6n)))).toEqual([md(-P3[0]), P3[1]]);
    const n = neg(ext(P3, 6n));
    expect(md(n.T * n.Z)).toBe(md(n.X * n.Y));
    expect(n.Z).toBe(6n);
    expect(aff(sub(ext(P5), ext(P3, 2n)))).toEqual(affAdd(P5, [md(-P3[0]), P3[1]]));
    expect(isIdentity(sub(ext(P5, 3n), ext(P5)))).toBe(true);
  });
});

describe('affine conversion, equality and encodings', () => {
  const P7 = affMul(7n, B);
  it('toAffine', () => {
    expect(toAffine(ext(P7, 99n))).toEqual({ x: P7[0], y: P7[1] });
    expect(toAffine(IDENTITY)).toEqual({ x: 0n, y: 1n });
  });
  it('equal compares X and Y projectively, each coordinate on its own', () => {
    expect(equal(ext(P7), ext(P7, 5n))).toBe(true);
    expect(equal(ext(P7), ext([md(-P7[0]), P7[1]]))).toBe(false); // only X differs
    expect(equal(ext(P7), ext([P7[0], md(-P7[1])]))).toBe(false); // only Y differs
    expect(equal(ext(P7, 3n), ext(P7, 8n))).toBe(true);
  });
  it('encodePoint is little-endian affine x then y', () => {
    const e = encodePoint(ext(P7, 12n));
    expect(e.length).toBe(64);
    expect([...e]).toEqual([...le(P7[0]), ...le(P7[1])]);
    expect([...encodePoint(IDENTITY)]).toEqual([...le(0n), ...le(1n)]);
  });
  it('compressPoint: y little-endian with the parity of x in bit 255', () => {
    expect(Buffer.from(compressPoint(BASE)).toString('hex')).toBe('5866666666666666666666666666666666666666666666666666666666666666');
    for (const k of [1n, 2n, 3n, 4n, 5n, 6n]) {
      const p = affMul(k, B);
      const want = le(p[1]);
      want[31] = want[31]! | (Number(p[0] & 1n) << 7);
      expect([...compressPoint(ext(p, 17n))]).toEqual(want);
    }
  });
  it('decompressPoint round-trips both parities and both square-root branches', () => {
    let odd = 0;
    for (let k = 1n; k <= 24n; k++) {
      const p = affMul(k, B);
      if (p[0] & 1n) odd++;
      const back = decompressPoint(compressPoint(ext(p)));
      expect(aff(back)).toEqual(p);
      expect(back.Z).toBe(1n);
      expect(back.T).toBe(md(p[0] * p[1]));
    }
    expect(odd).toBeGreaterThan(0);
    expect(odd).toBeLessThan(24);
    expect(aff(decompressPoint(compressPoint(ext(T4))))).toEqual(T4);
    expect(aff(decompressPoint(compressPoint(ext([md(-SQRT_M1), 0n]))))).toEqual([md(-SQRT_M1), 0n]);
  });
  it('decompressPoint rejections, with exact reasons', () => {
    const r = (b: Uint8Array): string => errOf(() => decompressPoint(b)).message;
    expect(errOf(() => decompressPoint(new Uint8Array(31)))).toBeInstanceOf(PointValidationError);
    expect(r(new Uint8Array(31))).toBe('decompressPoint: expected 32 bytes');
    expect(r(new Uint8Array(33))).toBe('decompressPoint: expected 32 bytes');
    expect(r(Uint8Array.from({ length: 32 }, (_, i) => Number((P >> BigInt(8 * i)) & 0xffn)))).toBe('decompressPoint: non-canonical y (≥ q)');
    // y = 2^255 - 1 (all ones, sign bit cleared) is >= q too.
    const big = new Uint8Array(32).fill(0xff);
    big[31] = 0x7f;
    expect(r(big)).toBe('decompressPoint: non-canonical y (≥ q)');
    // y = q - 1 is canonical: (0, -1) is the order-2 point; with the sign bit set it is a non-canonical x = 0 encoding.
    const yNeg1 = Uint8Array.from(le(P - 1n));
    expect(aff(decompressPoint(yNeg1))).toEqual(T2);
    yNeg1[31] = yNeg1[31]! | 0x80;
    expect(r(yNeg1)).toBe('decompressPoint: non-canonical sign');
    const id = Uint8Array.from(le(1n));
    expect(isIdentity(decompressPoint(id))).toBe(true);
    id[31] = 0x80;
    expect(r(id)).toBe('decompressPoint: non-canonical sign');
    // first y whose x^2 = (y^2-1)/(d y^2+1) is a non-residue: not on curve
    let y = 2n;
    for (;;) {
      const u = md(y * y - 1n);
      const v = md(dC * y * y + 1n);
      const x2 = md(u * inv(v));
      if (pw(x2, (P - 1n) / 2n) === P - 1n) break;
      y++;
    }
    expect(r(Uint8Array.from(le(y)))).toBe('decompressPoint: not on curve');
  });
  it('decompressPoint picks x by the sign bit', () => {
    const p = affMul(9n, B);
    const c = compressPoint(ext(p));
    c[31] = c[31]! ^ 0x80;
    expect(aff(decompressPoint(c))).toEqual([md(-p[0]), p[1]]);
  });
});

describe('validation', () => {
  const P11 = affMul(11n, B);
  it('isOnCurve accepts valid points at any projective scale', () => {
    expect(isOnCurve(BASE)).toBe(true);
    expect(isOnCurve(IDENTITY)).toBe(true);
    expect(isOnCurve(ext(P11, 1234567n))).toBe(true);
    expect(isOnCurve(ext(T2, 3n))).toBe(true);
    expect(isOnCurve(ext(T4, 3n))).toBe(true);
  });
  it('isOnCurve rejects Z = 0 (also Z = q), a broken T invariant, and off-curve coordinates', () => {
    expect(isOnCurve({ X: 0n, Y: 1n, Z: 0n, T: 0n })).toBe(false);
    expect(isOnCurve({ X: 0n, Y: 1n, Z: P, T: 0n })).toBe(false);
    const good = ext(P11, 5n);
    expect(isOnCurve({ ...good, T: md(good.T + 1n) })).toBe(false);
    const off: Aff = [P11[0], md(P11[1] + 1n)];
    expect(isOnCurve(ext(off, 5n))).toBe(false);
    const off2: Aff = [md(P11[0] + 1n), P11[1]];
    expect(isOnCurve(ext(off2))).toBe(false);
    expect(isOnCurve(ext([3n, 4n]))).toBe(false);
  });
  it('isIdentity', () => {
    expect(isIdentity(IDENTITY)).toBe(true);
    expect(isIdentity({ X: 0n, Y: 5n, Z: 5n, T: 0n })).toBe(true);
    expect(isIdentity(BASE)).toBe(false);
    expect(isIdentity(ext(T2))).toBe(false);
  });
  it('hasPrimeOrder (pure ladder): subgroup points and the identity pass, small and mixed order fail', () => {
    expect(hasPrimeOrder(BASE)).toBe(true);
    expect(hasPrimeOrder(ext(P11, 7n))).toBe(true);
    expect(hasPrimeOrder(IDENTITY)).toBe(true);
    expect(hasPrimeOrder(ext(T2))).toBe(false);
    expect(hasPrimeOrder(ext(T4))).toBe(false);
    expect(hasPrimeOrder(ext(affAdd(P11, T2)))).toBe(false);
    expect(hasPrimeOrder(ext(affAdd(P11, T4)))).toBe(false);
  });
  it('isInSubgroup needs on-curve AND non-identity AND prime order', () => {
    expect(isInSubgroup(BASE)).toBe(true);
    expect(isInSubgroup(ext(P11, 2n))).toBe(true);
    expect(isInSubgroup(IDENTITY)).toBe(false);
    expect(isInSubgroup(ext(T2))).toBe(false);
    expect(isInSubgroup(ext(affAdd(P11, T4)))).toBe(false);
    expect(isInSubgroup(ext([P11[0], md(P11[1] + 1n)]))).toBe(false);
  });
  it('assertInSubgroup reasons and labels', () => {
    expect(() => assertInSubgroup(BASE)).not.toThrow();
    const e1 = errOf(() => assertInSubgroup(ext([P11[0], md(P11[1] + 1n)])));
    expect(e1).toBeInstanceOf(PointValidationError);
    expect(e1.name).toBe('PointValidationError');
    expect(e1.message).toBe('point: not on curve');
    expect(errOf(() => assertInSubgroup(IDENTITY, 'S')).message).toBe('S: identity element (forbidden here)');
    expect(errOf(() => assertInSubgroup(ext(T2), 'R')).message).toBe('R: not in the prime-order subgroup (small-order/cofactor)');
    expect(errOf(() => assertInSubgroup(ext(affAdd(P11, T4)))).message).toBe('point: not in the prime-order subgroup (small-order/cofactor)');
  });
});

describe('Schnorr proof of knowledge', () => {
  const TAG = new TextEncoder().encode('atlas-pca-mpc/schnorr-dlog');
  const enc = (p: Aff): Uint8Array => Uint8Array.from([...le(p[0]), ...le(p[1])]);
  const challenge = (S: Aff, U: Aff, ctx: Uint8Array): bigint => {
    const len = Uint8Array.of((ctx.length >>> 24) & 255, (ctx.length >>> 16) & 255, (ctx.length >>> 8) & 255, ctx.length & 255);
    const d = createHash('sha512').update(TAG).update(len).update(ctx).update(enc(B)).update(enc(S)).update(enc(U)).digest();
    return BigInt('0x' + d.toString('hex')) % L;
  };
  const ctx = Uint8Array.of(1, 2, 3);
  const y = 7n;
  const S = affMul(y, B);
  it('known answer: U = [r]B and z = r + e*y mod L with the independently computed challenge', () => {
    const pr = schnorrProve(y, ext(S), () => 5n, ctx);
    const U = affMul(5n, B);
    expect(aff(pr.U)).toEqual(U);
    const e = challenge(S, U, ctx);
    expect(pr.z).toBe((5n + e * y) % L);
    expect(schnorrVerify(ext(S, 3n), pr, ctx)).toBe(true);
  });
  it('a long context uses its 4-byte big-endian length', () => {
    const big = new Uint8Array(300).fill(9);
    const pr = schnorrProve(y, ext(S), () => 11n, big);
    expect(pr.z).toBe((11n + challenge(S, affMul(11n, B), big) * y) % L);
  });
  it('nonce and secret are reduced into [0, L)', () => {
    const pr = schnorrProve(y, ext(S), () => -1n, ctx);
    const U = affMul(L - 1n, B);
    expect(aff(pr.U)).toEqual(U);
    expect(pr.z).toBe((L - 1n + challenge(S, U, ctx) * y) % L);
    const prL = schnorrProve(y, ext(S), () => L + 5n, ctx);
    expect(aff(prL.U)).toEqual(affMul(5n, B));
    const negY = schnorrProve(-y, ext(S), () => 5n, ctx);
    const e = challenge(S, affMul(5n, B), ctx);
    expect(negY.z).toBe((5n + e * (L - y)) % L);
    expect(negY.z).toBeGreaterThanOrEqual(0n);
    const bigY = schnorrProve(y + L, ext(S), () => 5n, ctx);
    expect(bigY.z).toBe((5n + e * y) % L);
  });
  it('refuses a zero nonce and an empty / non-byte binding', () => {
    expect(errOf(() => schnorrProve(y, ext(S), () => 0n, ctx)).message).toBe('schnorrProve: nonce source returned 0 (RNG failure); refusing to produce a proof');
    expect(errOf(() => schnorrProve(y, ext(S), () => L, ctx)).message).toBe('schnorrProve: nonce source returned 0 (RNG failure); refusing to produce a proof');
    expect(errOf(() => schnorrProve(y, ext(S), () => 5n, new Uint8Array(0))).message).toBe('schnorrProve: a non-empty session binding is required');
    expect(errOf(() => schnorrProve(y, ext(S), () => 5n, [1, 2, 3] as unknown as Uint8Array)).message).toBe('schnorrProve: a non-empty session binding is required');
  });
  it('verify rejects another context, an empty or non-byte context, and a wrong statement', () => {
    const pr = schnorrProve(y, ext(S), () => 5n, ctx);
    expect(schnorrVerify(ext(S), pr, Uint8Array.of(1, 2, 4))).toBe(false);
    expect(schnorrVerify(ext(S), pr, new Uint8Array(0))).toBe(false);
    expect(schnorrVerify(ext(S), pr, [1, 2, 3] as unknown as Uint8Array)).toBe(false);
    expect(schnorrVerify(ext(affMul(8n, B)), pr, ctx)).toBe(false);
    expect(schnorrVerify(ext(S), { ...pr, z: (pr.z + 1n) % L }, ctx)).toBe(false);
  });
  it('verify range-checks z: z + L and z - L satisfy the equation but are refused', () => {
    const pr = schnorrProve(y, ext(S), () => 5n, ctx);
    expect(schnorrVerify(ext(S), { ...pr, z: pr.z + L }, ctx)).toBe(false);
    expect(schnorrVerify(ext(S), { ...pr, z: pr.z - L }, ctx)).toBe(false);
    expect(schnorrVerify(ext(S), { ...pr, z: L }, ctx)).toBe(false);
  });
  it('verify refuses an empty binding even for a proof that is algebraically valid under it', () => {
    const empty = new Uint8Array(0);
    const U = affMul(5n, B);
    const z = (5n + challenge(S, U, empty) * y) % L;
    expect(schnorrVerify(ext(S), { U: ext(U), z }, empty)).toBe(false);
    // the same construction under a non-empty binding is accepted (so only the emptiness check refuses above)
    const z1 = (5n + challenge(S, U, ctx) * y) % L;
    expect(schnorrVerify(ext(S), { U: ext(U), z: z1 }, ctx)).toBe(true);
  });
  it('verify refuses an identity commitment even when the verification equation holds', () => {
    // U = O, z = e*y with e = H(S, O): z*B = O + e*S holds, so only the subgroup check on U refuses it.
    const e = challenge(S, [0n, 1n], ctx);
    expect(schnorrVerify(ext(S), { U: IDENTITY, z: (e * y) % L }, ctx)).toBe(false);
  });
});
