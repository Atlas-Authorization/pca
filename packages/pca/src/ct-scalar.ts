/**
 * Fixed-width, branch-free arithmetic modulo the edwards25519 group order L, on 32-byte little-endian scalars.
 *
 * Why: the FROST and DKG secret paths used to multiply and reduce secrets with JavaScript BigInt, whose `*` and `%`
 * take a time that depends on the operand values. Here every secret-dependent step runs the same number of
 * operations on 16-bit limbs held in small integers: bit loops have fixed bounds, and "if" is a mask select. A secret
 * never indexes an array or drives a branch.
 *
 * Honest limits: this removes BigInt `*`, `+` and `%` from the secret path. It cannot make a JIT-compiled runtime
 * constant-time (the engine may still vary with cache and optimisation state); the timing harness in
 * tools/pca-audit/timing is the evidence, not a proof. Callers that hand a scalar to @noble/curves still pass a BigInt,
 * and building that BigInt from bytes is not constant-time either. Part of the (b)-unit audit scope.
 */
import { ed25519 } from '@noble/curves/ed25519';

const LIMBS = 16;
const MASK = 0xffff;

function limbsOf(v: bigint): Int32Array {
  const out = new Int32Array(LIMBS);
  for (let i = 0; i < LIMBS; i++) {
    out[i] = Number(v & 0xffffn);
    v >>= 16n;
  }
  return out;
}
const L_LIMBS = limbsOf(ed25519.CURVE.n);

function fromBytes(b: Uint8Array): Int32Array {
  const out = new Int32Array(LIMBS);
  for (let i = 0; i < LIMBS; i++) out[i] = b[2 * i]! | (b[2 * i + 1]! << 8);
  return out;
}
function toBytes(x: Int32Array): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < LIMBS; i++) {
    out[2 * i] = x[i]! & 0xff;
    out[2 * i + 1] = x[i]! >> 8;
  }
  return out;
}

/** x - L when x >= L, else x, chosen with a mask (x < 2L). */
function condSubL(x: Int32Array): Int32Array {
  const t = new Int32Array(LIMBS);
  let borrow = 0;
  for (let i = 0; i < LIMBS; i++) {
    const d = x[i]! - L_LIMBS[i]! - borrow;
    borrow = (d >> 31) & 1; // 1 iff d < 0
    t[i] = d & MASK;
  }
  const keepT = borrow - 1; // all ones when no borrow (x >= L)
  const out = new Int32Array(LIMBS);
  for (let i = 0; i < LIMBS; i++) out[i] = (t[i]! & keepT) | (x[i]! & ~keepT);
  return out;
}

/** (a + b) mod L for a, b < L (the sum is < 2L < 2^254, so one conditional subtraction is enough). */
function addMod(a: Int32Array, b: Int32Array): Int32Array {
  const s = new Int32Array(LIMBS);
  let carry = 0;
  for (let i = 0; i < LIMBS; i++) {
    const v = a[i]! + b[i]! + carry;
    s[i] = v & MASK;
    carry = v >> 16;
  }
  return condSubL(s);
}

/** (a - b) mod L for a, b < L. */
function subMod(a: Int32Array, b: Int32Array): Int32Array {
  const d = new Int32Array(LIMBS);
  let borrow = 0;
  for (let i = 0; i < LIMBS; i++) {
    const v = a[i]! - b[i]! - borrow;
    borrow = (v >> 31) & 1;
    d[i] = v & MASK;
  }
  const addL = -borrow; // all ones iff a < b
  let carry = 0;
  const out = new Int32Array(LIMBS);
  for (let i = 0; i < LIMBS; i++) {
    const v = d[i]! + (L_LIMBS[i]! & addL) + carry;
    out[i] = v & MASK;
    carry = v >> 16;
  }
  return out;
}

/** Horner over the bits of `bits` (MSB first): acc = 2*acc + bit*addend, all mod L; `addend` < L. */
function hornerMod(bitsLE: Uint8Array, addend: Int32Array | null): Int32Array {
  let acc: Int32Array = new Int32Array(LIMBS);
  for (let i = bitsLE.length * 8 - 1; i >= 0; i--) {
    const bit = (bitsLE[i >> 3]! >> (i & 7)) & 1;
    acc = addMod(acc, acc);
    if (addend === null) {
      const one = new Int32Array(LIMBS);
      one[0] = bit;
      acc = addMod(acc, one);
    } else {
      const m = -bit;
      const t = new Int32Array(LIMBS);
      for (let k = 0; k < LIMBS; k++) t[k] = addend[k]! & m;
      acc = addMod(acc, t);
    }
  }
  return acc;
}

/** Reduce 1..64 little-endian bytes modulo L (the wide reduction RFC 9591 HashToScalar needs: 64 bytes in). */
export function ctReduce(bytesLE: Uint8Array): Uint8Array {
  if (!(bytesLE instanceof Uint8Array) || bytesLE.length < 1 || bytesLE.length > 64) {
    throw new Error('ct-scalar: reduce takes 1..64 bytes');
  }
  return toBytes(hornerMod(bytesLE, null));
}

function checkScalar(x: unknown, what: string): Uint8Array {
  if (!(x instanceof Uint8Array) || x.length !== 32) throw new Error(`ct-scalar: ${what} must be 32 bytes`);
  return x;
}

/** a + b mod L. Inputs are reduced first, so any 32 bytes are accepted. */
export function ctAdd(a: Uint8Array, b: Uint8Array): Uint8Array {
  return toBytes(addMod(fromBytes(ctReduce(checkScalar(a, 'a'))), fromBytes(ctReduce(checkScalar(b, 'b')))));
}

/** a - b mod L. */
export function ctSub(a: Uint8Array, b: Uint8Array): Uint8Array {
  return toBytes(subMod(fromBytes(ctReduce(checkScalar(a, 'a'))), fromBytes(ctReduce(checkScalar(b, 'b')))));
}

/** a * b mod L. */
export function ctMul(a: Uint8Array, b: Uint8Array): Uint8Array {
  const ra = fromBytes(ctReduce(checkScalar(a, 'a')));
  // Horner over b's raw bits is exact for any 256-bit b, so b needs no reduction.
  return toBytes(hornerMod(checkScalar(b, 'b'), ra));
}

/** True iff the 32 bytes reduce to zero mod L, without branching on the value. */
export function ctIsZero(a: Uint8Array): boolean {
  const r = ctReduce(checkScalar(a, 'a'));
  let acc = 0;
  for (let i = 0; i < 32; i++) acc |= r[i]!;
  return acc === 0;
}

/** Little-endian bytes of a BigInt scalar already in [0, 2^256). */
export function ctFromBigint(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** BigInt value of 32 little-endian bytes (the form @noble/curves wants). */
export function ctToBigint(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]!);
  return x;
}
