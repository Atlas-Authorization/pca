/**
 * @atlasauth/pca-mpc-wasm — a GENUINELY constant-time Ed25519 base-OT curve core.
 *
 * `@atlasauth/pca-mpc`'s `ec.ts` is a correct, malicious-hardened group, but its BigInt modular
 * arithmetic is not — and in pure JS cannot be — constant-time (docs §7.1: a real language/runtime
 * boundary, the JS `@noble`/BigInt path being the fallback). The base OT multiplies SECRET scalars
 * into the curve (`S = y·B`, `T = y·S`, `R = x·B (+S)`, `y·R`, `x·S`), which is exactly where a
 * timing side-channel would leak the receiver's choice bit or the sender's `y`.
 *
 * This module loads a small WebAssembly core (`../wasm/pca_mpc_wasm.wasm`) built from
 * `curve25519-dalek` (see `crate/`), whose field and scalar multiplication are audited and
 * constant-time, and re-exposes the base-OT curve-op surface of `ec.ts` on top of it. The scalar
 * multiplications — the security-critical, secret-dependent ops — run entirely inside the wasm.
 *
 * ## Point encoding
 * A point is its **canonical 32-byte compressed Ed25519 encoding** (little-endian `y`, sign of `x`
 * in the top bit) — the same bytes `@noble/curves` emits from `point.toRawBytes()`, which is what
 * makes the parity test (`index.test.ts`) an exact identical-bytes cross-check against the JS
 * reference. This is more standard than `ec.ts`'s bespoke 64-byte affine `x‖y`; the two are
 * inter-convertible (the compressed `y` plus a one-time `x`-recovery), and a deployment wiring this
 * core into `ot.ts` uses this 32-byte form consistently for its KDF/transcript hashing.
 *
 * Scalars are `bigint`, reduced `mod L` exactly as `ec.ts::mul` does, then handed to the wasm as
 * 32-byte little-endian (`Scalar::from_bytes_mod_order`).
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Field prime `q = 2^255 − 19` (mirrors `ec.ts`). */
export const Q = 2n ** 255n - 19n;

/** Prime order of the base-point subgroup. Scalars live in `[0, L)` (mirrors `ec.ts`). */
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/** A curve point as its canonical 32-byte compressed Ed25519 encoding. */
export type PointBytes = Uint8Array;

/** Raised when a received point fails on-curve / subgroup / identity validation (mirrors `ec.ts`). */
export class PointValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PointValidationError';
  }
}

// Minimal structural typings for the WebAssembly globals used here. The base tsconfig's lib is
// `ES2022` only (no DOM), which does not declare `WebAssembly` as a value/with members, so we type
// just what we touch and reach the runtime global (present in Node) through `globalThis`.
interface WasmMemory {
  readonly buffer: ArrayBuffer;
}
interface WasmInstance {
  readonly exports: Record<string, unknown>;
}
interface WasmNamespace {
  Module: new (bytes: Uint8Array) => object;
  Instance: new (module: object, imports?: Record<string, Record<string, unknown>>) => WasmInstance;
}
const WA: WasmNamespace = (globalThis as unknown as { WebAssembly: WasmNamespace }).WebAssembly;

/** The raw C-ABI surface the wasm core exports (see `crate/src/lib.rs`). */
interface WasmCore {
  readonly memory: WasmMemory;
  ptr_scalar(): number;
  ptr_pa(): number;
  ptr_pb(): number;
  ptr_out(): number;
  mul_base(): number;
  scalar_mul(): number;
  point_add(): number;
  point_sub(): number;
  point_neg(): number;
  is_on_curve(): number;
  is_identity(): number;
  is_in_subgroup(): number;
  point_equal(): number;
}

function instantiate(): WasmCore {
  // One level up from both `dist/` (built) and `src/` (vitest) is the package root, so this path is
  // stable in either run. Node permits synchronous compilation off the main browser thread.
  const bytes = readFileSync(join(__dirname, '..', 'wasm', 'pca_mpc_wasm.wasm'));
  const module = new WA.Module(new Uint8Array(bytes));
  const instance = new WA.Instance(module, {});
  return instance.exports as unknown as WasmCore;
}

const core: WasmCore = instantiate();

// Cached linear-memory addresses of the fixed I/O buffers (stable for the instance's life).
const PTR_SCALAR = core.ptr_scalar();
const PTR_PA = core.ptr_pa();
const PTR_PB = core.ptr_pb();
const PTR_OUT = core.ptr_out();

function mem(): Uint8Array {
  return new Uint8Array(core.memory.buffer);
}

function writeScalar(k: bigint): void {
  // Reduce into [0, L) exactly as `ec.ts::mul` does, then little-endian 32 bytes.
  let v = ((k % L) + L) % L;
  const buf = mem();
  for (let i = 0; i < 32; i++) {
    buf[PTR_SCALAR + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function assertLen(p: PointBytes, label: string): void {
  if (p.length !== 32) {
    throw new PointValidationError(`${label}: expected a 32-byte compressed point, got ${p.length}`);
  }
}

function writePoint(ptr: number, p: PointBytes, label: string): void {
  assertLen(p, label);
  mem().set(p, ptr);
}

function readOut(): PointBytes {
  // Copy out of the shared buffer so the caller holds a stable value across later ops.
  return mem().slice(PTR_OUT, PTR_OUT + 32);
}

/** The identity (neutral) element, as its canonical compressed encoding. */
export const IDENTITY: PointBytes = (() => {
  const out = new Uint8Array(32);
  out[0] = 1; // y = 1, x sign = 0
  return out;
})();

/** `[k]·B` — constant-time fixed-base scalar multiplication. `k` is reduced mod `L`. */
export function mulBase(k: bigint): PointBytes {
  writeScalar(k);
  core.mul_base();
  return readOut();
}

/** The standard Ed25519 base point `B`, as its canonical compressed encoding. */
export const BASE: PointBytes = mulBase(1n);

/**
 * `[k]·P` — constant-time variable-base scalar multiplication. `k` is reduced mod `L`.
 * Throws `PointValidationError` if `P` is not a valid curve point.
 */
export function mul(k: bigint, p: PointBytes): PointBytes {
  writePoint(PTR_PA, p, 'mul: point');
  writeScalar(k);
  if (core.scalar_mul() !== 1) throw new PointValidationError('mul: point not on curve');
  return readOut();
}

/** `[k]·B` (alias matching `ec.ts`). */
export function mulBasePoint(k: bigint): PointBytes {
  return mulBase(k);
}

/** `P + Q`. Throws `PointValidationError` if either input is off-curve. */
export function add(a: PointBytes, b: PointBytes): PointBytes {
  writePoint(PTR_PA, a, 'add: a');
  writePoint(PTR_PB, b, 'add: b');
  if (core.point_add() !== 1) throw new PointValidationError('add: operand not on curve');
  return readOut();
}

/** `P − Q`. Throws `PointValidationError` if either input is off-curve. */
export function sub(a: PointBytes, b: PointBytes): PointBytes {
  writePoint(PTR_PA, a, 'sub: a');
  writePoint(PTR_PB, b, 'sub: b');
  if (core.point_sub() !== 1) throw new PointValidationError('sub: operand not on curve');
  return readOut();
}

/** `−P`. Throws `PointValidationError` if off-curve. */
export function neg(a: PointBytes): PointBytes {
  writePoint(PTR_PA, a, 'neg: point');
  if (core.point_neg() !== 1) throw new PointValidationError('neg: point not on curve');
  return readOut();
}

/** Whether `p` decodes to a point on the curve (`ec.ts::isOnCurve`). */
export function isOnCurve(p: PointBytes): boolean {
  if (p.length !== 32) return false;
  mem().set(p, PTR_PA);
  return core.is_on_curve() === 1;
}

/** Whether `p` is the identity (neutral) element (`ec.ts::isIdentity`). */
export function isIdentity(p: PointBytes): boolean {
  if (p.length !== 32) return false;
  mem().set(p, PTR_PA);
  return core.is_identity() === 1;
}

/**
 * Whether `p` is a valid NON-identity point of the prime-order subgroup (`ec.ts::isInSubgroup`:
 * on-curve ∧ ¬identity ∧ the `[L]·P = O` cofactor check).
 */
export function isInSubgroup(p: PointBytes): boolean {
  if (p.length !== 32) return false;
  mem().set(p, PTR_PA);
  return core.is_in_subgroup() === 1;
}

/** Assert `p` is a valid non-identity prime-order-subgroup point, else throw (`ec.ts::assertInSubgroup`). */
export function assertInSubgroup(p: PointBytes, label = 'point'): void {
  if (!isOnCurve(p)) throw new PointValidationError(`${label}: not on curve`);
  if (isIdentity(p)) throw new PointValidationError(`${label}: identity element (forbidden here)`);
  if (!isInSubgroup(p)) {
    throw new PointValidationError(`${label}: not in the prime-order subgroup (small-order/cofactor)`);
  }
}

/** Whether `a` and `b` are valid curve points equal as group elements (`ec.ts::equal`). */
export function equal(a: PointBytes, b: PointBytes): boolean {
  if (a.length !== 32 || b.length !== 32) return false;
  const buf = mem();
  buf.set(a, PTR_PA);
  buf.set(b, PTR_PB);
  return core.point_equal() === 1;
}

/**
 * The canonical encoding of a point (`ec.ts::encodePoint` analogue). A point already IS its 32-byte
 * compressed encoding here, so this validates and returns a copy. Throws if off-curve.
 */
export function encodePoint(p: PointBytes): Uint8Array {
  if (!isOnCurve(p)) throw new PointValidationError('encodePoint: point not on curve');
  return p.slice();
}

/** Decode + validate a 32-byte compressed point (`ec.ts` decode contract). Throws if off-curve. */
export function decodePoint(bytes: PointBytes): PointBytes {
  if (!isOnCurve(bytes)) throw new PointValidationError('decodePoint: point not on curve');
  return bytes.slice();
}
