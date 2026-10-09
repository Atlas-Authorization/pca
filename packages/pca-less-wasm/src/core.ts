/**
 * @atlasauth/pca-less-wasm -- code-based (code-equivalence) signature backend for `@atlasauth/pca`.
 *
 * LESS is a NIST additional-digital-signature (Round 2) CANDIDATE -- not a standard -- whose security
 * rests on the code-equivalence problem, a hardness family distinct from lattices (ML-DSA / FN-DSA) and
 * hashes (SLH-DSA). The crypto core is the official LESS reference C (https://github.com/less-sig/LESS,
 * public domain) compiled verbatim to `wasm32-wasi`; the only added C is a ~40-line seam that seeds the
 * reference CSPRNG and exposes flat byte-buffer entry points (BUILD_NOTES.md).
 *
 * ## Portable loader
 * This module imports nothing from `node:*`. The wasm needs a single host import, WASI
 * `random_get`, which we implement over `globalThis.crypto.getRandomValues` (failing closed when absent).
 * Load it with {@link initLess} (async: bytes | URL | Response) anywhere, or let the Node entry
 * (`index.ts`) load it synchronously from the package directory.
 *
 * ## Parameter set
 * One NIST Category 1 set is compiled: `CATEGORY=252, TARGET=45` (q=127, n=252, k=126; 97,484 B public
 * key, 32 B secret-key seed, signatures 1,153-1,329 B). Sizes are read from the wasm, never hard-coded
 * (except the layout constants used by the input guards, which are cross-checked against it).
 *
 * ## Status (honest)
 * Verified by the official KATs, a native-vs-wasm differential, sanitizer runs and robustness tests, but
 * UNAUDITED; no independent implementation exists; keygen/sign are not constant-time. The upstream
 * verifier has three memory-safety defects on forged signatures that this wrapper mitigates (see
 * `wellFormedSignedMessage` and the README). Prefer the classical hybrid.
 */

/** The single compiled LESS parameter set (NIST Category 1, short-signature corner). */
export type LessVariant = 'less-252-45';

/** Raised on a missing wasm artifact, a wrongly-sized buffer, or a wasm op failure. */
export class LessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LessError';
  }
}

// -- Minimal structural typing for the WebAssembly global -------------------------------------
// The base tsconfig lib is ES2022 (no DOM), so `WebAssembly` is not a declared value; reach the runtime
// global structurally. This file imports NOTHING from node:* -- it runs unchanged in Node >=20, browsers,
// Deno, Bun and edge workers.
interface WasmMemory {
  readonly buffer: ArrayBuffer;
}
interface WasmInstance {
  readonly exports: Record<string, unknown>;
}
interface WasmModule {
  readonly __brand?: 'wasm-module';
}
type WasmImports = Record<string, Record<string, unknown>>;
interface WasmNamespace {
  Module: new (bytes: Uint8Array) => WasmModule;
  Instance: new (module: WasmModule, imports?: WasmImports) => WasmInstance;
  instantiate(
    source: Uint8Array | WasmModule,
    imports?: WasmImports,
  ): Promise<WasmInstance | { instance: WasmInstance; module: WasmModule }>;
  instantiateStreaming?(
    source: unknown,
    imports?: WasmImports,
  ): Promise<{ instance: WasmInstance; module: WasmModule }>;
}
const WA: WasmNamespace = (globalThis as unknown as { WebAssembly: WasmNamespace }).WebAssembly;

/** The C-ABI surface the LESS wasm exports (see `less_wasm_glue.c` in BUILD_NOTES.md §e). */
interface WasmCore {
  readonly memory: WasmMemory;
  _initialize?(): void;
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

// -- Portable WASI preview1 shim ---------------------------------------------------------------
// The LESS wasm imports exactly ONE host function: `wasi_snapshot_preview1.random_get` (backing the
// module's `getentropy`, used only by less_autoseed). Verified by listing WebAssembly.Module.imports()
// in the test suite. We implement just that, over `globalThis.crypto.getRandomValues`. If no Web Crypto is
// present, random_get returns a non-zero errno => getentropy fails => less_autoseed returns -1 =>
// `seedFromEntropy` throws: keygen/sign FAIL CLOSED rather than seed from anything weaker. Verification
// consumes no randomness and is unaffected.
const WASI_ESUCCESS = 0;
const WASI_EFAULT = 21;
const WASI_EIO = 29;
const GRV_MAX = 65536; // Web Crypto getRandomValues quota per call

function makeImports(getMemory: () => WasmMemory | undefined): WasmImports {
  return {
    wasi_snapshot_preview1: {
      random_get(ptr: number, len: number): number {
        const mem = getMemory();
        if (!mem) return WASI_EFAULT;
        const c = (globalThis as unknown as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
        if (!c || typeof c.getRandomValues !== 'function') return WASI_EIO; // fail closed
        if (ptr < 0 || len < 0 || ptr + len > mem.buffer.byteLength) return WASI_EFAULT;
        try {
          for (let off = 0; off < len; off += GRV_MAX) {
            c.getRandomValues(new Uint8Array(mem.buffer, ptr + off, Math.min(GRV_MAX, len - off)));
          }
        } catch {
          return WASI_EIO;
        }
        return WASI_ESUCCESS;
      },
    },
  };
}

// -- Instance state ----------------------------------------------------------------------------
let core: WasmCore | null = null;
let sizesCache: LessSizes | null = null;
let seeded = false;
/** Optional synchronous wasm-bytes loader, registered ONLY by the Node entry (`index.ts`). */
let syncLoader: (() => Uint8Array) | null = null;

/** @internal Used by the Node entry to register its fs-backed loader. */
export function setSyncWasmLoader(f: () => Uint8Array): void {
  syncLoader = f;
}

function adopt(instance: WasmInstance): void {
  const c = instance.exports as unknown as WasmCore;
  if (typeof c._initialize === 'function') c._initialize(); // WASI reactor init
  core = c;
  sizesCache = null;
  seeded = false;
}

function toBytes(b: Uint8Array | ArrayBuffer): Uint8Array {
  return b instanceof Uint8Array ? b : new Uint8Array(b);
}

/**
 * Synchronously instantiate from wasm bytes. Works in Node, Deno and Bun; **browsers restrict
 * synchronous compilation of modules larger than 4 KB on the main thread**, so there use {@link initLess}.
 */
export function initLessSync(bytes: Uint8Array | ArrayBuffer): void {
  let mem: WasmMemory | undefined;
  const instance = new WA.Instance(new WA.Module(toBytes(bytes)), makeImports(() => mem));
  mem = instance.exports.memory as WasmMemory;
  adopt(instance);
}

/** What {@link initLess} can instantiate from. */
export type LessWasmSource =
  | Uint8Array
  | ArrayBuffer
  | URL
  | string
  | Response
  | Promise<Response>;

/**
 * Asynchronously instantiate the wasm (portable: browsers, workers, Deno, Bun, Node). `source` may be raw
 * bytes, a `URL` / URL string (fetched), or a `Response` (streamed when the runtime supports it). Idempotent
 * re-initialisation replaces the instance and resets seeding.
 */
export async function initLess(source: LessWasmSource): Promise<void> {
  let mem: WasmMemory | undefined;
  const imports = makeImports(() => mem);
  let instance: WasmInstance;
  const src = await source;
  if (src instanceof Uint8Array || src instanceof ArrayBuffer) {
    const r = await WA.instantiate(toBytes(src), imports);
    instance = 'instance' in r ? r.instance : r;
  } else {
    let resp: Response;
    if (typeof src === 'string' || src instanceof URL) {
      const f = (globalThis as unknown as { fetch?: (u: string | URL) => Promise<Response> }).fetch;
      if (typeof f !== 'function') throw new LessError('initLess: fetch is unavailable; pass the wasm bytes instead');
      resp = await f(src);
    } else {
      resp = src;
    }
    if (!resp.ok) throw new LessError(`initLess: fetching wasm failed (HTTP ${resp.status})`);
    const ct = resp.headers.get('content-type') ?? '';
    if (typeof WA.instantiateStreaming === 'function' && ct.startsWith('application/wasm')) {
      instance = (await WA.instantiateStreaming(resp, imports)).instance;
    } else {
      const r = await WA.instantiate(new Uint8Array(await resp.arrayBuffer()), imports);
      instance = 'instance' in r ? r.instance : r;
    }
  }
  mem = instance.exports.memory as WasmMemory;
  adopt(instance);
}

/** True once a wasm instance is loaded (via {@link initLess}, {@link initLessSync} or the Node auto-load). */
export function isInitialized(): boolean {
  return core !== null;
}

function instantiate(): WasmCore {
  if (core) return core;
  if (syncLoader) {
    let bytes: Uint8Array;
    try {
      bytes = syncLoader();
    } catch {
      throw new LessError(
        'LESS wasm could not be read from the package. Reinstall @atlasauth/pca-less-wasm, or call initLess(bytes|url).',
      );
    }
    initLessSync(bytes);
    return core as unknown as WasmCore;
  }
  throw new LessError(
    'LESS wasm is not initialised. In browsers/workers/edge call `await initLess(urlOrBytes)` (or import ' +
      '"@atlasauth/pca-less-wasm/embedded" and call `await initLessEmbedded()`) before using the API.',
  );
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
 * Layout constants for the compiled `less-252-45` set, from upstream `parameters.h` (CATEGORY=252,
 * TARGET=45): N=252, K=126, W=34, N8=32, MAX_PUBLISHED_SEEDS=11, HASH_DIGEST_LENGTH=32. The wasm does
 * not export them, so they are pinned here and `layoutMatches()` checks them against the exported
 * `signatureMax` (= 2*32 + W*N8 + 11*seed + 1 = 1329) so a differently-parameterised wasm fails loudly.
 *
 * Signature layout (upstream `sign_t`, packed): digest[32] | salt[32] | cf_monom_actions[W][N8] |
 * seed_storage[leaves*seed]  with the leaf count in the LAST byte; the attached signed message is
 * `message || signature`.
 */
export const MAX_PUBLISHED_SEEDS = 11;
const HASH_BYTES = 32;
const W_ACTIONS = 34;
const N8 = 32;
/** Bits 252..255 of each `cf_monom_actions` row are padding (N=252 occupies 252 of 256 bits). */
const PAD_MASK = 0xf0;

function layoutMatches(s: LessSizes): boolean {
  return s.signatureMax === 2 * HASH_BYTES + W_ACTIONS * N8 + MAX_PUBLISHED_SEEDS * s.seed + 1;
}

/**
 * Pre-validation of an attached signed message, rejecting what the reference would mishandle. The
 * reference is NOT modified; these two checks exist because of two upstream defects found by this
 * package's cross-check work (README "Findings"):
 *
 *  1. `crypto_sign_open` has no `smlen >= sig_len` check: a short input (including a valid signature
 *     whose final leaf-count byte has had one bit flipped upward) underflows `*mlen` and the following
 *     memcpy traps in wasm / crashes natively. We reject any input too short for the signature its own
 *     trailing byte claims.
 *  2. `CheckCanonicalAction` counts the 4 padding bits (252..255) of each `cf_monom_actions` row toward
 *     the weight-K check but `UnpackCosetRep` ignores them, so a row with padding bits set (and total
 *     weight K) makes the verifier write up to 4 elements past `permuted_G_col_pivot[252]` / the
 *     generator matrix (confirmed with AddressSanitizer on a native build; undetectable in wasm, where it
 *     silently corrupts adjacent stack memory). We reject any row with a padding bit set.
 *  3. (handled in `open`, not here) `RebuildGGM` over-reads past the signature on forged input; see the
 *     zero-filled slack allocation in `open`.
 *
 * Neither check can reject a signature that `sign` produces: every KAT and random signature in the test
 * suites passes through them.
 */
function wellFormedSignedMessage(sm: Uint8Array, s: LessSizes): boolean {
  if (!layoutMatches(s)) throw new LessError('wasm parameter set does not match the pinned less-252-45 layout');
  if (sm.length === 0) return false;
  const leaves = sm[sm.length - 1]!;
  if (leaves > MAX_PUBLISHED_SEEDS) return false;
  const sigLen = s.signatureMax - (MAX_PUBLISHED_SEEDS - leaves) * s.seed;
  if (sm.length < sigLen) return false;
  const cf = sm.length - sigLen + 2 * HASH_BYTES;
  for (let w = 0; w < W_ACTIONS; w++) {
    if ((sm[cf + w * N8 + (N8 - 1)]! & PAD_MASK) !== 0) return false;
  }
  return true;
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
  // Wrapper-level guard for two UPSTREAM DEFECTS (see wellFormedSignedMessage and README "Findings").
  if (!wellFormedSignedMessage(signedMessage, s)) return { ok: false, message: new Uint8Array(0) };
  const pPk = c.malloc(s.publicKey);
  // Upstream defect #3: `RebuildGGM` takes the number of seeds to read from the *challenge hash*, not
  // from the (attacker-chosen) trailing leaf count, so on a forged signature it can read up to
  // (T-W)*SEED = 176 bytes past the end of the signature. Give it a zero-filled tail so that over-read
  // stays inside our own allocation and yields zeros (the signature then fails the digest check).
  const slack = s.signatureMax;
  const pSm = c.malloc(signedMessage.length + slack);
  const pOut = c.malloc(Math.max(1, signedMessage.length));
  const pMlen = c.malloc(8);
  if (!pPk || !pSm || !pOut || !pMlen) throw new LessError('open: wasm malloc failed');
  try {
    mem().set(publicKey, pPk);
    mem().fill(0, pSm, pSm + signedMessage.length + slack);
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
  // A verifier must answer true/false on attacker-supplied input; a wrong-sized key is just "no".
  if (publicKey.length !== sizes().publicKey) return false;
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
