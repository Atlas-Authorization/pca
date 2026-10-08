/**
 * @atlasauth/pca-less-wasm — EXPERIMENTAL code-based signature backend for `@atlasauth/pca`.
 *
 * LESS is a NIST "additional signatures" candidate (round 1/2) whose security rests on the
 * **code-equivalence / syndrome-decoding** problem — the genuine *third* post-quantum hardness
 * family, distinct from lattices (ML-DSA / FN-DSA) and hashes (SLH-DSA). Adding it to the PCA
 * post-quantum suite registry buys cryptographic diversity: a break of lattice assumptions does not
 * touch a code-based leaf signature.
 *
 * The crypto core is NOT hand-rolled. It is the **official LESS reference implementation**
 * (https://github.com/less-sig/LESS, public-domain) compiled verbatim to `wasm32-wasi` by
 * `~/.pca-vm-state/lessbuild.sh`. The only added C is a ~40-line seam (`less_wasm_glue.c`) that
 * seeds the reference's own SHAKE CSPRNG from WASI entropy and exposes flat byte-buffer entry
 * points. See `BUILD_NOTES.md` for the full recon (sources, defines, include dirs, randomness).
 *
 * ## Parameter set
 * One NIST Category 1 set is compiled: `CATEGORY=252, TARGET=45` — the short-signature corner
 * (q=127, n=252, k=126; ~95 KB public key, 32 B secret-key seed, ~1.3 KB signature). The exact
 * byte sizes are read from the wasm at load time (`less_*_bytes()`), never hard-coded here.
 *
 * ## ABI (differs from @atlasauth/pca-fndsa-wasm)
 * Unlike the FN-DSA backend (empty-imports, fixed static buffers), LESS is a **WASI reactor**: it
 * imports `wasi_snapshot_preview1` (for `random_get`, backing the module's `getentropy` auto-seed)
 * and allocates I/O buffers with the exported `malloc`/`free`. We instantiate via `node:wasi`,
 * `wasi.initialize()` runs `_initialize`, then we marshal bytes through linear memory.
 *
 * ## Honest status
 * EXPERIMENTAL. LESS is not standardized and not production-audited; the reference is explicitly not
 * fully constant-time (keygen/sign). **Verification is deterministic and uses no randomness** — it is
 * the only operation the PCA verifier performs, and the intended primary use of this backend. Treat
 * this as a non-default hardness-diversity suite, not a drop-in replacement for a standardized
 * signature. The `.wasm` artifact is produced off-box by the VM build and dropped into
 * `wasm/less_cat1.wasm`; until then every call throws a clear {@link LessError}.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/** The single compiled LESS parameter set (NIST Category 1, short-signature corner). */
export type LessVariant = 'less-252-45';

/** Raised on a missing wasm artifact, a wrongly-sized buffer, or a wasm op failure. */
export class LessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LessError';
  }
}

// -- Minimal structural typing for the Node WebAssembly + WASI globals ------------------------
// The base tsconfig lib is ES2022 (no DOM), so `WebAssembly` is not a declared value; reach the
// Node runtime globals structurally, exactly as @atlasauth/pca-fndsa-wasm does.
interface WasmMemory {
  readonly buffer: ArrayBuffer;
}
interface WasmInstance {
  readonly exports: Record<string, unknown>;
}
interface WasmModule {
  readonly __brand?: 'wasm-module';
}
interface WasmNamespace {
  Module: new (bytes: Uint8Array) => WasmModule;
  Instance: new (module: WasmModule, imports?: Record<string, Record<string, unknown>>) => WasmInstance;
}
const WA: WasmNamespace = (globalThis as unknown as { WebAssembly: WasmNamespace }).WebAssembly;

// `node:wasi` is loaded lazily inside instantiate() so merely importing this module (e.g. for its
// types) does not require the wasi experimental flag until a crypto op is actually invoked.
interface WasiInstance {
  readonly wasiImport: Record<string, unknown>;
  initialize(instance: WasmInstance): void;
}

/** The C-ABI surface the LESS wasm exports (see `less_wasm_glue.c` in BUILD_NOTES.md §e). */
interface WasmCore {
  readonly memory: WasmMemory;
  malloc(n: number): number;
  free(p: number): void;
  less_public_key_bytes(): number | bigint;
  less_secret_key_bytes(): number | bigint;
  less_signature_max_bytes(): number | bigint;
  less_seed_bytes(): number | bigint;
  less_autoseed(): number;
  less_seed(seedPtr: number, seedLen: number): void;
  less_keypair(pkPtr: number, skPtr: number): number;
  // (sm, smlen_out, m, mlen:i64, sk) -> 0 ok
  less_sign(smPtr: number, smlenPtr: number, mPtr: number, mlen: bigint, skPtr: number): number;
  // (m_out, mlen_out, sm, smlen:i64, pk) -> 0 ok, nonzero fail
  less_open(mPtr: number, mlenPtr: number, smPtr: number, smlen: bigint, pkPtr: number): number;
}

/** Byte lengths for the compiled parameter set, read from the wasm. */
export interface LessSizes {
  /** Public (verifying) key length. */
  publicKey: number;
  /** Secret (signing) key length. */
  secretKey: number;
  /** Worst-case signature length (the seed-tree makes the real length variable and smaller). */
  signatureMax: number;
  /** Seed length the reference CSPRNG expects (SEED_LENGTH_BYTES). */
  seed: number;
}

// -- Lazy singleton instance -------------------------------------------------------------------
let core: WasmCore | null = null;
let sizesCache: LessSizes | null = null;
let seeded = false;

function wasmPath(): string {
  // One level up from both `dist/` (built) and `src/` (vitest) is the package root.
  return join(__dirname, '..', 'wasm', 'less_cat1.wasm');
}

function instantiate(): WasmCore {
  if (core) return core;
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(readFileSync(wasmPath()));
  } catch {
    throw new LessError(
      `LESS wasm not found at ${wasmPath()}. It is cross-compiled off-box by ` +
        `~/.pca-vm-state/lessbuild.sh on a Linux VM with wasi-sdk-25, then dropped in here. ` +
        `This backend is EXPERIMENTAL and ships without a prebuilt artifact.`,
    );
  }
  // WASI reactor: provide wasi_snapshot_preview1 (random_get backs getentropy), then initialize.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { WASI } = require('node:wasi') as { WASI: new (opts: object) => WasiInstance };
  const wasi = new WASI({ version: 'preview1', args: [], env: {} });
  const module = new WA.Module(bytes);
  const instance = new WA.Instance(module, { wasi_snapshot_preview1: wasi.wasiImport });
  wasi.initialize(instance); // runs the reactor's _initialize
  core = instance.exports as unknown as WasmCore;
  return core;
}

function num(v: number | bigint): number {
  return typeof v === 'bigint' ? Number(v) : v;
}

function mem(): Uint8Array {
  return new Uint8Array(instantiate().memory.buffer);
}

function dv(): DataView {
  return new DataView(instantiate().memory.buffer);
}

/** Byte lengths for the compiled LESS parameter set, queried from the wasm. */
export function sizes(): LessSizes {
  if (sizesCache) return sizesCache;
  const c = instantiate();
  sizesCache = {
    publicKey: num(c.less_public_key_bytes()),
    secretKey: num(c.less_secret_key_bytes()),
    signatureMax: num(c.less_signature_max_bytes()),
    seed: num(c.less_seed_bytes()),
  };
  return sizesCache;
}

/**
 * Seed the reference CSPRNG from WASI host entropy (`getentropy` -> `random_get`). Call once before
 * {@link keygen} / {@link sign} in production. {@link keygen} and {@link sign} auto-seed on first use
 * if you have not seeded explicitly.
 */
export function seedFromEntropy(): void {
  const c = instantiate();
  if (c.less_autoseed() !== 0) throw new LessError('less_autoseed: WASI getentropy failed');
  seeded = true;
}

/**
 * Inject a caller-provided seed into the reference CSPRNG, making subsequent {@link keygen}/{@link sign}
 * **deterministic** (for KATs / reproducibility / BYO-RNG from `crypto.getRandomValues`). Not for
 * production unless `seed` is itself from a CSPRNG.
 */
export function seedWith(seed: Uint8Array): void {
  const c = instantiate();
  const p = c.malloc(seed.length);
  if (!p) throw new LessError('seedWith: wasm malloc failed');
  try {
    mem().set(seed, p);
    c.less_seed(p, seed.length);
    seeded = true;
  } finally {
    c.free(p);
  }
}

function ensureSeeded(): void {
  if (!seeded) seedFromEntropy();
}

/**
 * Generate a LESS key pair. Requires prior seeding; auto-seeds from entropy if you have not called
 * {@link seedFromEntropy} / {@link seedWith}. Returns the public (verifying) key and secret (signing) key.
 */
export function keygen(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const c = instantiate();
  const s = sizes();
  ensureSeeded();
  const pPk = c.malloc(s.publicKey);
  const pSk = c.malloc(s.secretKey);
  if (!pPk || !pSk) throw new LessError('keygen: wasm malloc failed');
  try {
    if (c.less_keypair(pPk, pSk) !== 0) throw new LessError('keygen: wasm keypair failed');
    return {
      publicKey: mem().slice(pPk, pPk + s.publicKey),
      secretKey: mem().slice(pSk, pSk + s.secretKey),
    };
  } finally {
    c.free(pPk);
    c.free(pSk);
  }
}

/**
 * Sign `message` under `secretKey`, producing a LESS **attached signed message** (`message || sig`),
 * the native NIST format — the opened-seed count is packed into the trailing byte, so the signature
 * is self-describing and variable-length. Verify it with {@link open}. Requires prior seeding
 * (auto-seeds from entropy otherwise). For a detached signature use {@link signDetached}.
 */
export function sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  const c = instantiate();
  const s = sizes();
  if (secretKey.length !== s.secretKey) {
    throw new LessError(`sign: secretKey must be ${s.secretKey} bytes, got ${secretKey.length}`);
  }
  ensureSeeded();
  const pSk = c.malloc(s.secretKey);
  const pMsg = c.malloc(Math.max(1, message.length));
  const pSm = c.malloc(message.length + s.signatureMax);
  const pSmlen = c.malloc(8);
  if (!pSk || !pMsg || !pSm || !pSmlen) throw new LessError('sign: wasm malloc failed');
  try {
    mem().set(secretKey, pSk);
    mem().set(message, pMsg);
    if (c.less_sign(pSm, pSmlen, pMsg, BigInt(message.length), pSk) !== 0) {
      throw new LessError('sign: wasm sign failed');
    }
    const smlen = Number(dv().getBigUint64(pSmlen, true));
    return mem().slice(pSm, pSm + smlen);
  } finally {
    c.free(pSk);
    c.free(pMsg);
    c.free(pSm);
    c.free(pSmlen);
  }
}

/**
 * Open (verify) a LESS attached signed message produced by {@link sign}. Returns `{ ok, message }`:
 * `ok` is true iff the signature is valid under `publicKey`, and `message` is the recovered payload
 * (empty on failure). Deterministic; needs no seeding.
 */
export function open(publicKey: Uint8Array, signedMessage: Uint8Array): { ok: boolean; message: Uint8Array } {
  const c = instantiate();
  const s = sizes();
  if (publicKey.length !== s.publicKey) {
    throw new LessError(`open: publicKey must be ${s.publicKey} bytes, got ${publicKey.length}`);
  }
  const pPk = c.malloc(s.publicKey);
  const pSm = c.malloc(Math.max(1, signedMessage.length));
  const pOut = c.malloc(Math.max(1, signedMessage.length));
  const pMlen = c.malloc(8);
  if (!pPk || !pSm || !pOut || !pMlen) throw new LessError('open: wasm malloc failed');
  try {
    mem().set(publicKey, pPk);
    mem().set(signedMessage, pSm);
    const rc = c.less_open(pOut, pMlen, pSm, BigInt(signedMessage.length), pPk);
    if (rc !== 0) return { ok: false, message: new Uint8Array(0) };
    const mlen = Number(dv().getBigUint64(pMlen, true));
    return { ok: true, message: mem().slice(pOut, pOut + mlen) };
  } finally {
    c.free(pPk);
    c.free(pSm);
    c.free(pOut);
    c.free(pMlen);
  }
}

/**
 * Produce a **detached** LESS signature over `message` (the attached signed message with the message
 * prefix stripped). Pair with {@link verify}. Convenience over {@link sign} for callers that keep the
 * message and signature separate (e.g. a PCA proof carrying a code-based leaf signature).
 */
export function signDetached(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  const sm = sign(secretKey, message);
  return sm.slice(message.length);
}

/**
 * Verify a **detached** LESS `signature` over `message` under `publicKey` — the PCA verifier's
 * operation. Reconstructs the attached signed message (`message || signature`) and opens it, checking
 * both validity and that the recovered payload equals `message`. Deterministic; needs no seeding.
 */
export function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  const sm = new Uint8Array(message.length + signature.length);
  sm.set(message, 0);
  sm.set(signature, message.length);
  const r = open(publicKey, sm);
  if (!r.ok || r.message.length !== message.length) return false;
  for (let i = 0; i < message.length; i++) if (r.message[i] !== message[i]) return false;
  return true;
}

/** The compiled variant tag, for registry wiring in `@atlasauth/pca`. */
export const VARIANT: LessVariant = 'less-252-45';
