/**
 * @atlasauth/pca-mpc-lwe-ot-wasm — the post-quantum lattice core for @atlasauth/pca-mpc's endemic
 * (Masny–Rindal) base oblivious transfer.
 *
 * `@atlasauth/pca-mpc`'s `kem-ot.ts` is a SEMI-HONEST post-quantum base OT: a malicious receiver can
 * keep both ML-KEM secret keys and learn both messages, and an opaque KEM cannot detect it. This
 * package removes that residue by exposing exactly the Kyber-768 **IND-CPA (K-PKE)** primitives the
 * endemic construction needs — real keygen, CPA encrypt to an ARBITRARY public key, CPA decrypt —
 * plus the ring arithmetic to derive the non-chosen branch's UNIFORM public key through a random
 * oracle (so that, under decisional Module-LWE, the receiver provably cannot decrypt it).
 *
 * The crypto core is NOT hand-rolled: every Kyber operation runs through the audited `pqc_kyber`
 * reference implementation compiled to WebAssembly (`crate/`, reached via its `hazmat`/`indcpa`
 * surface). This module only marshals bytes across the wasm boundary. See `crate/src/lib.rs` for the
 * exact boundary between the vetted arithmetic and the (non-cryptographic) serialization / modular
 * vector add / uniform sampler this core adds.
 *
 * ## ABI / encoding (mirrors @atlasauth/pca-mpc-wasm)
 * The wasm is a `no_std`, allocator-free module driven through fixed static buffers in linear memory
 * (write inputs -> call op -> read an output buffer); it instantiates with an EMPTY import object.
 * Byte formats are standard Kyber-768: a public key is `ByteEncode_12(t̂) || rho` (1184 B), an
 * IND-CPA secret key is 1152 B, a ciphertext is 1088 B, a ring vector `t̂` is 1152 B, and seeds /
 * coins / messages are 32 B.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Kyber-768 public key length (`ByteEncode_12(t̂) || rho`). */
export const PK_BYTES = 1184;
/** Kyber-768 IND-CPA secret key length. */
export const SK_BYTES = 1152;
/** Kyber-768 IND-CPA ciphertext length. */
export const CT_BYTES = 1088;
/** Length of a serialized public-key ring vector `t̂` (the first `TVEC_BYTES` of a public key). */
export const TVEC_BYTES = 1152;
/** Seed / coins / message length (Kyber `KYBER_SYMBYTES`). */
export const SYM_BYTES = 32;

/** Raised when a wasm lattice op is called with a wrongly-sized buffer. */
export class LatticeOtError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LatticeOtError';
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
  ptr_coins(): number;
  ptr_msg(): number;
  ptr_pk(): number;
  ptr_sk(): number;
  ptr_ct(): number;
  ptr_ra(): number;
  ptr_rb(): number;
  ptr_rout(): number;
  ptr_hashin(): number;
  len_pk(): number;
  len_sk(): number;
  len_ct(): number;
  len_tvec(): number;
  len_sym(): number;
  kpke_keygen(): number;
  kpke_enc(): number;
  kpke_dec(): number;
  ring_add(): number;
  ring_sub(): number;
  hash_to_ring(len: number): number;
}

function instantiate(): WasmCore {
  // One level up from both `dist/` (built) and `src/` (vitest) is the package root, so this path is
  // stable in either run. Node permits synchronous compilation off the main browser thread.
  const bytes = readFileSync(join(__dirname, '..', 'wasm', 'pca_mpc_lwe_ot_wasm.wasm'));
  const module = new WA.Module(new Uint8Array(bytes));
  const instance = new WA.Instance(module, {});
  return instance.exports as unknown as WasmCore;
}

const core: WasmCore = instantiate();

// Cached linear-memory addresses of the fixed I/O buffers (stable for the instance's life).
const PTR_SEED = core.ptr_seed();
const PTR_COINS = core.ptr_coins();
const PTR_MSG = core.ptr_msg();
const PTR_PK = core.ptr_pk();
const PTR_SK = core.ptr_sk();
const PTR_CT = core.ptr_ct();
const PTR_RA = core.ptr_ra();
const PTR_RB = core.ptr_rb();
const PTR_ROUT = core.ptr_rout();
const PTR_HASHIN = core.ptr_hashin();

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
    throw new LatticeOtError(`${label}: expected ${len} bytes, got ${buf.length}`);
  }
}

/**
 * Deterministic Kyber-768 K-PKE key generation (vetted `pqc_kyber::indcpa::indcpa_keypair`). The
 * 32-byte `seed` is Kyber's `d`. Returns the real public key `(t̂ || rho)` and the IND-CPA secret
 * key. Determinism in the seed makes the endemic OT reproducible for tests.
 */
export function kpkeKeygen(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
  expectLen(seed, SYM_BYTES, 'kpkeKeygen: seed');
  writeAt(PTR_SEED, seed);
  if (core.kpke_keygen() !== 1) throw new LatticeOtError('kpkeKeygen: wasm keygen failed');
  return { publicKey: readAt(PTR_PK, PK_BYTES), secretKey: readAt(PTR_SK, SK_BYTES) };
}

/**
 * Kyber-768 K-PKE CPA encryption (vetted `pqc_kyber::indcpa::indcpa_enc`) of a 32-byte `message`
 * under `publicKey` — which may be a real key OR the UNIFORM key the endemic construction derives for
 * the non-chosen branch (the encryptor never needs a well-formed `t̂`). `coins` (32 B) deterministically
 * expands all encryption randomness. Returns the 1088-byte ciphertext.
 */
export function kpkeEnc(publicKey: Uint8Array, message: Uint8Array, coins: Uint8Array): Uint8Array {
  expectLen(publicKey, PK_BYTES, 'kpkeEnc: publicKey');
  expectLen(message, SYM_BYTES, 'kpkeEnc: message');
  expectLen(coins, SYM_BYTES, 'kpkeEnc: coins');
  writeAt(PTR_PK, publicKey);
  writeAt(PTR_MSG, message);
  writeAt(PTR_COINS, coins);
  if (core.kpke_enc() !== 1) throw new LatticeOtError('kpkeEnc: wasm enc failed');
  return readAt(PTR_CT, CT_BYTES);
}

/**
 * Kyber-768 K-PKE CPA decryption (vetted `pqc_kyber::indcpa::indcpa_dec`): recover the 32-byte
 * message from `ciphertext` under IND-CPA secret key `secretKey`.
 */
export function kpkeDec(secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  expectLen(secretKey, SK_BYTES, 'kpkeDec: secretKey');
  expectLen(ciphertext, CT_BYTES, 'kpkeDec: ciphertext');
  writeAt(PTR_SK, secretKey);
  writeAt(PTR_CT, ciphertext);
  if (core.kpke_dec() !== 1) throw new LatticeOtError('kpkeDec: wasm dec failed');
  return readAt(PTR_MSG, SYM_BYTES);
}

/** `(a + b) mod q`, coefficient-wise over two serialized ring vectors `t̂` (the ring/group addition). */
export function ringAdd(a: Uint8Array, b: Uint8Array): Uint8Array {
  expectLen(a, TVEC_BYTES, 'ringAdd: a');
  expectLen(b, TVEC_BYTES, 'ringAdd: b');
  writeAt(PTR_RA, a);
  writeAt(PTR_RB, b);
  if (core.ring_add() !== 1) throw new LatticeOtError('ringAdd: wasm add failed');
  return readAt(PTR_ROUT, TVEC_BYTES);
}

/** `(a - b) mod q`, coefficient-wise over two serialized ring vectors `t̂`. */
export function ringSub(a: Uint8Array, b: Uint8Array): Uint8Array {
  expectLen(a, TVEC_BYTES, 'ringSub: a');
  expectLen(b, TVEC_BYTES, 'ringSub: b');
  writeAt(PTR_RA, a);
  writeAt(PTR_RB, b);
  if (core.ring_sub() !== 1) throw new LatticeOtError('ringSub: wasm sub failed');
  return readAt(PTR_ROUT, TVEC_BYTES);
}

/** Maximum length (bytes) of a `hashToRing` input (matches the wasm `HASHIN` buffer capacity). */
export const HASHIN_CAP = 4096;

/**
 * Random oracle into the Kyber public-key (ring) space: SHAKE128(`input`) expanded through the
 * standard FIPS-203 / Kyber `SampleNTT` rejection sampler to a UNIFORMLY random ring vector `t̂`
 * (1152 B). This is the exact sampler Kyber uses to expand its public matrix A, so the output is
 * uniform over the ring-vector space — which is what makes the non-chosen branch indistinguishable
 * from a real key under decisional Module-LWE while admitting no low-norm secret. The caller folds
 * its own domain-separation tag + session id + transfer index + the other branch's value into `input`.
 */
export function hashToRing(input: Uint8Array): Uint8Array {
  if (input.length > HASHIN_CAP) {
    throw new LatticeOtError(`hashToRing: input exceeds ${HASHIN_CAP} bytes (${input.length})`);
  }
  writeAt(PTR_HASHIN, input);
  if (core.hash_to_ring(input.length) !== 1) throw new LatticeOtError('hashToRing: wasm failed');
  return readAt(PTR_ROUT, TVEC_BYTES);
}
