/**
 * @atlasauth/pca-fndsa-wasm — the FN-DSA (Falcon, FIPS 206) signature backend for `@atlasauth/pca`'s
 * post-quantum suite registry.
 *
 * It exposes FN-DSA key generation, signing and — the operation the PCA verifier actually performs —
 * **signature verification**, for the two standardized parameter sets FN-DSA-512 (NIST category 1)
 * and FN-DSA-1024 (category 5).
 *
 * The crypto core is NOT hand-rolled: every FN-DSA / Falcon operation runs through the vetted,
 * pure-Rust `fn-dsa` crate family by Thomas Pornin (the Falcon author; the RustSec-recommended
 * successor to `pqcrypto-falcon`) compiled to WebAssembly (`crate/`). This module only marshals bytes
 * across the wasm boundary. See `crate/src/lib.rs` for the vetted boundary.
 *
 * ## ABI / encoding (mirrors @atlasauth/pca-mpc-wasm)
 * The wasm is a `no_std`, allocator-free module driven through fixed static buffers in linear memory
 * (write inputs -> call op -> read an output buffer); it instantiates with an EMPTY import object.
 * Byte lengths come from the wasm itself (`len_*`), so the binding never hardcodes a size the crate
 * might change.
 *
 * ## Standard status (honest note)
 * FN-DSA is **FIPS 206, finalized-pending**: the final NIST text is not yet published, and the
 * `fn-dsa` crate warns its key/signature encodings MAY change before its 1.0. Signing/keygen are
 * best-effort constant-time (a known Falcon property; on wasm the crate uses a portable FP
 * emulation). Verification — the PCA verifier's only use — is the public-key operation and uses no
 * floating point.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/** A standardized FN-DSA parameter set. */
export type FnDsaVariant = 'fn-dsa-512' | 'fn-dsa-1024';

/** The degree tag the wasm ABI uses for each variant. */
const TAG: Record<FnDsaVariant, number> = {
  'fn-dsa-512': 512,
  'fn-dsa-1024': 1024,
};

/** Raised when an FN-DSA wasm op is called with a wrongly-sized buffer or an invalid argument. */
export class FnDsaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FnDsaError';
  }
}

// Minimal structural typing for the WebAssembly globals used here (the base tsconfig's lib is
// ES2022, no DOM, so `WebAssembly` is not declared as a value); reach the Node runtime global.
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
  ptr_seed(): number;
  ptr_vk(): number;
  ptr_sk(): number;
  ptr_sig(): number;
  ptr_msg(): number;
  len_vk(tag: number): number;
  len_sk(tag: number): number;
  len_sig(tag: number): number;
  len_seed(): number;
  cap_msg(): number;
  fndsa_keygen(tag: number): number;
  fndsa_sign(tag: number, msgLen: number): number;
  fndsa_verify(tag: number, msgLen: number): number;
}

function instantiate(): WasmCore {
  // One level up from both `dist/` (built) and `src/` (vitest) is the package root, so this path is
  // stable in either run. Node permits synchronous compilation off the main browser thread.
  const bytes = readFileSync(join(__dirname, '..', 'wasm', 'pca_fndsa_wasm.wasm'));
  const module = new WA.Module(new Uint8Array(bytes));
  const instance = new WA.Instance(module, {});
  return instance.exports as unknown as WasmCore;
}

const core: WasmCore = instantiate();

// Cached linear-memory addresses of the fixed I/O buffers (stable for the instance's life).
const PTR_SEED = core.ptr_seed();
const PTR_VK = core.ptr_vk();
const PTR_SK = core.ptr_sk();
const PTR_SIG = core.ptr_sig();
const PTR_MSG = core.ptr_msg();

/** Deterministic-RNG seed length in bytes (keygen/sign reproducibility; 32). */
export const SEED_BYTES = core.len_seed();
/** Maximum message length (bytes) accepted by `sign` / `verify`. */
export const MSG_CAP = core.cap_msg();

function sizesFor(variant: FnDsaVariant): { tag: number; vk: number; sk: number; sig: number } {
  const tag = TAG[variant];
  const vk = core.len_vk(tag);
  const sk = core.len_sk(tag);
  const sig = core.len_sig(tag);
  if (vk < 0 || sk < 0 || sig < 0) throw new FnDsaError(`unsupported FN-DSA variant: ${variant}`);
  return { tag, vk, sk, sig };
}

/** Byte lengths for a variant's verifying key, signing key and signature. */
export function sizes(variant: FnDsaVariant): { verifyingKey: number; signingKey: number; signature: number } {
  const { vk, sk, sig } = sizesFor(variant);
  return { verifyingKey: vk, signingKey: sk, signature: sig };
}

function mem(): Uint8Array {
  return new Uint8Array(core.memory.buffer);
}

function writeAt(ptr: number, data: Uint8Array): void {
  mem().set(data, ptr);
}

function readAt(ptr: number, len: number): Uint8Array {
  // Copy out of the shared buffer so the caller holds a stable value across later ops.
  return mem().slice(ptr, ptr + len);
}

function expectLen(buf: Uint8Array, len: number, label: string): void {
  if (buf.length !== len) {
    throw new FnDsaError(`${label}: expected ${len} bytes, got ${buf.length}`);
  }
}

function checkMessage(message: Uint8Array): void {
  if (message.length > MSG_CAP) {
    throw new FnDsaError(`message exceeds ${MSG_CAP} bytes (${message.length})`);
  }
}

/**
 * Deterministic FN-DSA key generation (vetted `fn-dsa-kgen`). The 32-byte `seed` seeds a SHAKE256
 * CryptoRng, making the key pair reproducible (for tests / KATs); production callers pass a CSPRNG
 * seed. Returns the verifying (public) key and signing (secret) key for the variant.
 */
export function keygen(
  variant: FnDsaVariant,
  seed: Uint8Array,
): { verifyingKey: Uint8Array; signingKey: Uint8Array } {
  const { tag, vk, sk } = sizesFor(variant);
  expectLen(seed, SEED_BYTES, 'keygen: seed');
  writeAt(PTR_SEED, seed);
  if (core.fndsa_keygen(tag) !== 1) throw new FnDsaError(`keygen: wasm keygen failed for ${variant}`);
  return { verifyingKey: readAt(PTR_VK, vk), signingKey: readAt(PTR_SK, sk) };
}

/**
 * FN-DSA signing (vetted `fn-dsa-sign`): sign `message` (raw, no caller pre-hash) under `signingKey`
 * with a SHAKE256-seeded RNG. `seed` (32 B) makes the signature reproducible. Returns the signature.
 */
export function sign(
  variant: FnDsaVariant,
  signingKey: Uint8Array,
  message: Uint8Array,
  seed: Uint8Array,
): Uint8Array {
  const { tag, sk, sig } = sizesFor(variant);
  expectLen(signingKey, sk, 'sign: signingKey');
  expectLen(seed, SEED_BYTES, 'sign: seed');
  checkMessage(message);
  writeAt(PTR_SK, signingKey);
  writeAt(PTR_SEED, seed);
  writeAt(PTR_MSG, message);
  if (core.fndsa_sign(tag, message.length) !== 1) throw new FnDsaError(`sign: wasm sign failed for ${variant}`);
  return readAt(PTR_SIG, sig);
}

/**
 * FN-DSA verification (vetted `fn-dsa-vrfy`) — the PCA verifier's operation. Returns true iff
 * `signature` is a valid FN-DSA signature of `message` (raw, no pre-hash) under `verifyingKey`.
 * A malformed key or wrongly-sized signature (for the variant) is a thrown `FnDsaError`; a
 * well-formed but invalid signature returns false.
 */
export function verify(
  variant: FnDsaVariant,
  verifyingKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  const { tag, vk, sig } = sizesFor(variant);
  expectLen(verifyingKey, vk, 'verify: verifyingKey');
  expectLen(signature, sig, 'verify: signature');
  checkMessage(message);
  writeAt(PTR_VK, verifyingKey);
  writeAt(PTR_SIG, signature);
  writeAt(PTR_MSG, message);
  return core.fndsa_verify(tag, message.length) === 1;
}
