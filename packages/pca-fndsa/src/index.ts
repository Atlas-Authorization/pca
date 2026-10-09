/**
 * @atlasauth/pca-fndsa — FN-DSA / Falcon (FIPS 206 draft) for PCA's crypto-agility seam.
 *
 * FN-DSA (standardization name for Falcon) is a LATTICE signature over NTRU whose selling point is
 * COMPACTNESS: its public keys and signatures are far smaller than ML-DSA's at the same security
 * category (Falcon-512 ≈ Category 1, Falcon-1024 ≈ Category 5). That makes it the suite to reach for
 * on bandwidth-bound or storage-bound surfaces — exactly the places ML-DSA-65's 1952 B key / 3309 B
 * signature hurt.
 *
 * WHY A PLUGGABLE BACKEND (the honest part):
 *   Falcon signing needs discrete-Gaussian sampling over a lattice and an FFT/NTT in a regime that the
 *   reference implementation runs in floating point. A CONSTANT-TIME, correct, interoperable Falcon
 *   CANNOT be safely hand-rolled in TypeScript: a float-based sampler leaks the secret via timing, and a
 *   naive integer reimplementation is a research project, not a package. Shipping a "pure-TS Falcon"
 *   here would be worse than shipping nothing — it would look done while being unsafe. So this package
 *   does the one honest thing: it REGISTERS the FN-DSA suites in PCA's wire + agility framing and routes
 *   the heavy math to a PLUGGABLE, VETTED backend (a wasm build of the FIPS-206 reference, or a vetted
 *   native lib). The wire format, the suite ids, the byte-length enforcement, the PCA leaf framing and
 *   the hybrid composition are all REAL and fully tested here (against a deterministic KAT mock); only
 *   the Gaussian-sampling arithmetic is delegated. Drop in a real backend via {@link setFalconBackend}
 *   and nothing else in PCA changes.
 *
 * This mirrors the conventions of `@atlasauth/pca`'s `pq.ts` suite registry (SigAlg / SIG_SUITES /
 * signWithSuite / verifyWithSuite) so FN-DSA slots in as a PEER suite family: same `sig` / `alg` /
 * `pq_pk` / `pq_sig` wire fields, same fail-closed hybrid rule, same per-suite exact-length enforcement.
 * It lives in its own package (not in `pq.ts`) precisely because its primitive is pluggable, not bundled.
 */

import {
  ED25519_SIGNATURE_BYTES,
  type PCActn,
  type PCActnBody,
  b64u,
  decodeB64uStrict,
  sha256,
  sign,
  thresholdMessage,
  utf8,
  verifyB64u,
} from '@atlasauth/pca';

// ---------------------------------------------------------------------------------------------------
// FIPS-206 (FN-DSA / Falcon) encoded sizes
// ---------------------------------------------------------------------------------------------------
//
// FN-DSA public keys are a fixed size. Falcon SIGNATURES are natively VARIABLE-LENGTH (the signature's
// short vector is range/Huffman-"compressed", so the exact byte count depends on the sampled vector).
// FIPS 206 pins a FIXED "padded" signature encoding per parameter set — the sizes below — so a signature
// always occupies a constant number of bytes on the wire. PCA uses the PADDED encoding exclusively: it
// gives deterministic framing and a single exact length to enforce, matching how pq.ts enforces ML-DSA /
// SLH-DSA lengths. (A backend that produces the compressed variable-length form MUST pad it to these
// sizes before returning — the standard "sig" vs "sig (padded)" distinction in the reference code.)

/** FN-DSA-512 (Falcon-512, ~Category 1) public-key size, in bytes. */
export const FN_DSA_512_PUBLIC_KEY_BYTES = 897;
/** FN-DSA-512 padded (FIPS-206 fixed-length) signature size, in bytes. The compressed form averages smaller. */
export const FN_DSA_512_SIGNATURE_BYTES = 666;
/** FN-DSA-1024 (Falcon-1024, ~Category 5) public-key size, in bytes. */
export const FN_DSA_1024_PUBLIC_KEY_BYTES = 1793;
/** FN-DSA-1024 padded (FIPS-206 fixed-length) signature size, in bytes. The compressed form averages smaller. */
export const FN_DSA_1024_SIGNATURE_BYTES = 1280;

// ---------------------------------------------------------------------------------------------------
// Suite registry (mirrors pq.ts SigAlg / SIG_SUITES)
// ---------------------------------------------------------------------------------------------------

/** The two pure FN-DSA parameter sets (the backend's "variant"). */
export type FnDsaVariant = 'fn-dsa-512' | 'fn-dsa-1024';

/**
 * The FN-DSA suite ids registered in PCA's agility seam. The pure suites carry the FN-DSA signature in
 * the primary `sig` field; the `hybrid-ed25519-fn-dsa-*` suites carry an Ed25519 signature in `sig` and
 * the FN-DSA signature in `pq_sig` — classical + lattice defense-in-depth, requiring BOTH to verify.
 */
export type FnDsaSigAlg =
  | 'fn-dsa-512'
  | 'fn-dsa-1024'
  | 'hybrid-ed25519-fn-dsa-512'
  | 'hybrid-ed25519-fn-dsa-1024';

/** A single FN-DSA suite's wire contract — the FN-DSA parallel of pq.ts's {@link SigSuite}. */
export interface FnDsaSuite {
  alg: FnDsaSigAlg;
  /** The pure FN-DSA parameter set the suite uses (which `pq_pk` / FN-DSA `sig` lengths apply). */
  variant: FnDsaVariant;
  /** Suite carries an Ed25519 component (in `sig`, under the leaf holder key). */
  hasEd25519: boolean;
  /** Decoded byte length REQUIRED in the primary `sig` field (Ed25519 64 for hybrid; the FN-DSA sig for pure). */
  sigBytes: number;
  /** A `pq_pk` (FN-DSA public key) field is REQUIRED (always true for FN-DSA suites). */
  needsPqPk: boolean;
  /** Decoded byte length REQUIRED in `pq_pk`. */
  pqPkBytes: number;
  /** A `pq_sig` field is REQUIRED — i.e. the FN-DSA sig is separate from `sig` (hybrid only). */
  needsPqSig: boolean;
  /** Decoded byte length REQUIRED in `pq_sig` when `needsPqSig`; `0` when unused. */
  pqSigBytes: number;
  /** The FN-DSA signature length for this suite's variant (== sigBytes for pure, == pqSigBytes for hybrid). */
  fnSigBytes: number;
}

const VARIANT_PK_BYTES: Readonly<Record<FnDsaVariant, number>> = Object.freeze({
  'fn-dsa-512': FN_DSA_512_PUBLIC_KEY_BYTES,
  'fn-dsa-1024': FN_DSA_1024_PUBLIC_KEY_BYTES,
});
const VARIANT_SIG_BYTES: Readonly<Record<FnDsaVariant, number>> = Object.freeze({
  'fn-dsa-512': FN_DSA_512_SIGNATURE_BYTES,
  'fn-dsa-1024': FN_DSA_1024_SIGNATURE_BYTES,
});

/** The closed FN-DSA suite registry (the FN-DSA parallel of pq.ts's SIG_SUITES). */
export const FN_DSA_SUITES: Readonly<Record<FnDsaSigAlg, Readonly<FnDsaSuite>>> = Object.freeze({
  'fn-dsa-512': {
    alg: 'fn-dsa-512', variant: 'fn-dsa-512', hasEd25519: false,
    sigBytes: FN_DSA_512_SIGNATURE_BYTES, needsPqPk: true, pqPkBytes: FN_DSA_512_PUBLIC_KEY_BYTES,
    needsPqSig: false, pqSigBytes: 0, fnSigBytes: FN_DSA_512_SIGNATURE_BYTES,
  },
  'fn-dsa-1024': {
    alg: 'fn-dsa-1024', variant: 'fn-dsa-1024', hasEd25519: false,
    sigBytes: FN_DSA_1024_SIGNATURE_BYTES, needsPqPk: true, pqPkBytes: FN_DSA_1024_PUBLIC_KEY_BYTES,
    needsPqSig: false, pqSigBytes: 0, fnSigBytes: FN_DSA_1024_SIGNATURE_BYTES,
  },
  'hybrid-ed25519-fn-dsa-512': {
    alg: 'hybrid-ed25519-fn-dsa-512', variant: 'fn-dsa-512', hasEd25519: true,
    sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, pqPkBytes: FN_DSA_512_PUBLIC_KEY_BYTES,
    needsPqSig: true, pqSigBytes: FN_DSA_512_SIGNATURE_BYTES, fnSigBytes: FN_DSA_512_SIGNATURE_BYTES,
  },
  'hybrid-ed25519-fn-dsa-1024': {
    alg: 'hybrid-ed25519-fn-dsa-1024', variant: 'fn-dsa-1024', hasEd25519: true,
    sigBytes: ED25519_SIGNATURE_BYTES, needsPqPk: true, pqPkBytes: FN_DSA_1024_PUBLIC_KEY_BYTES,
    needsPqSig: true, pqSigBytes: FN_DSA_1024_SIGNATURE_BYTES, fnSigBytes: FN_DSA_1024_SIGNATURE_BYTES,
  },
});

export function isKnownFnDsaAlg(x: unknown): x is FnDsaSigAlg {
  return typeof x === 'string' && Object.prototype.hasOwnProperty.call(FN_DSA_SUITES, x);
}

/** Resolve an FN-DSA suite by id; `null` (FAIL-CLOSED) for an unknown name or non-string. */
export function resolveFnDsaAlg(alg: unknown): Readonly<FnDsaSuite> | null {
  if (isKnownFnDsaAlg(alg)) return FN_DSA_SUITES[alg];
  return null;
}

/** Is `v` one of the two pure FN-DSA parameter sets? */
export function isFnDsaVariant(v: unknown): v is FnDsaVariant {
  return v === 'fn-dsa-512' || v === 'fn-dsa-1024';
}

// ---------------------------------------------------------------------------------------------------
// The pluggable backend seam
// ---------------------------------------------------------------------------------------------------

/** An FN-DSA key pair as raw bytes (the wire/PKI boundary). */
export interface FalconKeyPair {
  /** FN-DSA public key (897 B for 512, 1793 B for 1024). */
  pk: Uint8Array;
  /** FN-DSA secret key (backend-defined encoding). */
  sk: Uint8Array;
}

/**
 * The vetted FN-DSA primitive, supplied by a real backend (wasm build of the FIPS-206 reference, or a
 * vetted native lib). `verify` is mandatory (verification is the hot path and is safe to run anywhere);
 * `sign` and `keygen` are OPTIONAL because many deployments only ever VERIFY FN-DSA signatures (signing,
 * with its constant-time Gaussian sampler, lives next to the secret key and may be absent client-side).
 *
 * All byte arguments are the padded FIPS-206 encodings; a backend that works in the compressed form MUST
 * pad to the fixed sizes before returning from `sign` and accept the padded form in `verify`.
 */
export interface FalconBackend {
  /** Verify `signature` over `message` under `pubkey`. MUST NOT throw on a bad signature — return false. */
  verify(pubkey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
  /** Sign `message` under `secretkey`, returning the padded FIPS-206 signature. Optional. */
  sign?(secretkey: Uint8Array, message: Uint8Array): Uint8Array;
  /** Generate a fresh FN-DSA key pair. Optional. */
  keygen?(): FalconKeyPair;
}

/** The clear error the default (unregistered) backend raises so misuse FAILS LOUD, not silently. */
export const NO_FN_DSA_BACKEND_MESSAGE =
  'no FN-DSA backend registered — install @atlasauth/pca-fndsa-wasm or supply a backend via setFalconBackend()';

const DEFAULT_BACKEND: FalconBackend = Object.freeze({
  verify(): boolean {
    throw new Error(NO_FN_DSA_BACKEND_MESSAGE);
  },
  sign(): Uint8Array {
    throw new Error(NO_FN_DSA_BACKEND_MESSAGE);
  },
  keygen(): FalconKeyPair {
    throw new Error(NO_FN_DSA_BACKEND_MESSAGE);
  },
});

let currentBackend: FalconBackend = DEFAULT_BACKEND;

/** Install the FN-DSA backend that performs the actual Falcon math. */
export function setFalconBackend(backend: FalconBackend): void {
  currentBackend = backend;
}

/** The currently installed FN-DSA backend (the default throws {@link NO_FN_DSA_BACKEND_MESSAGE}). */
export function getFalconBackend(): FalconBackend {
  return currentBackend;
}

/** Restore the default (throwing) backend — mainly for tests and teardown. */
export function resetFalconBackend(): void {
  currentBackend = DEFAULT_BACKEND;
}

// ---------------------------------------------------------------------------------------------------
// Primitive-level wrappers (raw bytes) — mirror pq.ts's mlDsa65Sign / mlDsa65Verify
// ---------------------------------------------------------------------------------------------------

/**
 * FN-DSA sign over raw bytes, delegating to the registered backend AFTER enforcing the suite's key/sig
 * framing. THROWS (fail-loud) when no backend is registered, when the backend is verify-only (no `sign`),
 * or when the backend returns a signature of the wrong padded length. `sk` must be a non-empty Uint8Array
 * (its exact encoding is backend-defined, so its length is not pinned here).
 */
export function fndsaSign(variant: FnDsaVariant, sk: Uint8Array, msg: Uint8Array): Uint8Array {
  if (!isFnDsaVariant(variant)) throw new RangeError(`fndsaSign: unknown FN-DSA variant '${String(variant)}'`);
  if (!(sk instanceof Uint8Array) || sk.length === 0) throw new TypeError('fndsaSign: secret key must be a non-empty Uint8Array');
  if (!(msg instanceof Uint8Array)) throw new TypeError('fndsaSign: message must be a Uint8Array');
  const backend = currentBackend;
  if (typeof backend.sign !== 'function') throw new Error('fndsaSign: FN-DSA backend is verify-only (no sign())');
  const sig = backend.sign(sk, msg);
  const expected = VARIANT_SIG_BYTES[variant];
  if (!(sig instanceof Uint8Array) || sig.length !== expected) {
    throw new Error(`fndsaSign: FN-DSA backend returned a ${sig instanceof Uint8Array ? String(sig.length) : 'non-byte'} signature; expected padded ${expected} bytes for '${variant}'`);
  }
  return sig;
}

/**
 * FN-DSA verify over raw bytes. The suite's key + signature LENGTHS are enforced HERE, BEFORE the backend
 * is ever called, so a wrong-length public key or signature is rejected (false) without reaching the
 * primitive. A registered backend that itself throws is NOT swallowed (fail-loud) — but a wrong-length
 * input, and the clear "no backend" error, surface as described: length guard returns false; the default
 * backend throws {@link NO_FN_DSA_BACKEND_MESSAGE} once the length guard has passed.
 */
export function fndsaVerify(variant: FnDsaVariant, pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (!isFnDsaVariant(variant)) return false;
  if (!(pk instanceof Uint8Array) || pk.length !== VARIANT_PK_BYTES[variant]) return false;
  if (!(sig instanceof Uint8Array) || sig.length !== VARIANT_SIG_BYTES[variant]) return false;
  if (!(msg instanceof Uint8Array)) return false;
  return currentBackend.verify(pk, msg, sig);
}

// ---------------------------------------------------------------------------------------------------
// PCA leaf / capability-hop framing (mirrors pq.ts signSuiteArtifact / verifyLeafSuite)
// ---------------------------------------------------------------------------------------------------

/**
 * The wire fields an FN-DSA-signed PCA surface carries — structurally the SAME shape pq.ts emits from
 * {@link signSuiteArtifact} (`sig` always; `alg` + `pq_pk` for every FN-DSA suite; `pq_sig` for hybrid).
 * The caller spreads these onto the artifact it transports alongside the PCActn, exactly as the core
 * suite fields ride on a PCActn. (FN-DSA is not yet a member of pq.ts's `SigAlg` union — admitting it
 * there is the mechanical follow pq.ts describes for SLH-DSA — so these fields travel as a parallel,
 * byte-compatible frame rather than being typed onto the PCActn object.)
 */
export interface FnDsaArtifactFields {
  /** b64u — the FN-DSA signature for a pure suite; the Ed25519 signature for a hybrid suite. */
  sig: string;
  /** The FN-DSA suite id (SIGNED into the leaf message, so a downgrade/key-swap invalidates the signature). */
  alg: FnDsaSigAlg;
  /** b64u FN-DSA public key (SIGNED into the leaf message). */
  pq_pk: string;
  /** b64u FN-DSA signature — hybrid suites only. */
  pq_sig?: string;
}

/** The domain separator for the FN-DSA leaf/hop binding suffix. */
export const FN_DSA_LEAF_DOMAIN = 'atlas-pca/fn-dsa/leaf/v1\0';

/**
 * The exact bytes an FN-DSA leaf/hop signature covers:
 *
 *   thresholdMessage(leaf)  ‖  FN_DSA_LEAF_DOMAIN  ‖  utf8(alg)  ‖  0x00  ‖  utf8(pq_pk b64u)
 *
 * The leading `thresholdMessage(leaf)` is the IDENTICAL canonical message pq.ts's core leaf signs, so an
 * FN-DSA signature commits to the whole action. The domain-separated suffix additively BINDS `alg` and
 * `pq_pk` into the signed bytes — the same downgrade/key-swap protection pq.ts gets by folding `alg` /
 * `pq_pk` into the canonical body via `bindSuiteFields`, achieved here without mutating the PCActn's typed
 * shape (FN-DSA is not yet in the `SigAlg` union). In a hybrid both the Ed25519 and FN-DSA halves sign
 * these same bytes, so each commits to the suite + PQ key.
 */
export function fndsaLeafMessage(leaf: PCActn | PCActnBody, alg: FnDsaSigAlg, pqPkB64u: string): Uint8Array {
  const base = thresholdMessage(leaf);
  const suffix = utf8(FN_DSA_LEAF_DOMAIN);
  const algBytes = utf8(alg);
  const pkBytes = utf8(pqPkB64u);
  const out = new Uint8Array(base.length + suffix.length + algBytes.length + 1 + pkBytes.length);
  let off = 0;
  out.set(base, off); off += base.length;
  out.set(suffix, off); off += suffix.length;
  out.set(algBytes, off); off += algBytes.length;
  out[off] = 0; off += 1;
  out.set(pkBytes, off);
  return out;
}

/** Inputs to {@link signPcaWithFndsa}. */
export interface SignPcaWithFndsaInput {
  /** The FN-DSA suite id. */
  alg: FnDsaSigAlg;
  /** The PCActn (or its body) whose leaf is being signed — its {@link thresholdMessage} is the base. */
  leaf: PCActn | PCActnBody;
  /** The FN-DSA key pair (its `pk` becomes `pq_pk`; its `sk` signs). */
  fnDsa: FalconKeyPair;
  /** Ed25519 leaf-holder secret key — REQUIRED for a `hybrid-*` suite, ignored for a pure suite. */
  edSecret?: Uint8Array;
}

/**
 * Produce an FN-DSA leaf (or capability-hop) signature for a PCActn, returning the wire fields the
 * surface carries. Pure FN-DSA: `sig` = FN-DSA signature, `pq_pk` = FN-DSA key. Hybrid: `sig` = Ed25519
 * signature, `pq_sig` = FN-DSA signature, `pq_pk` = FN-DSA key — both over the SAME leaf message, for
 * classical + lattice DEFENSE-IN-DEPTH (a forger must break Ed25519 AND Falcon). THROWS fail-closed on an
 * unknown suite, a wrong-length FN-DSA key, a hybrid suite with no `edSecret`, or a missing/limited backend.
 */
export function signPcaWithFndsa(input: SignPcaWithFndsaInput): FnDsaArtifactFields {
  const suite = resolveFnDsaAlg(input.alg);
  if (suite === null) throw new RangeError(`signPcaWithFndsa: unknown FN-DSA alg '${String(input.alg)}'`);
  if (!(input.fnDsa?.pk instanceof Uint8Array) || input.fnDsa.pk.length !== suite.pqPkBytes) {
    throw new TypeError(`signPcaWithFndsa: '${suite.alg}' requires a ${suite.pqPkBytes}-byte FN-DSA public key`);
  }
  if (!(input.fnDsa.sk instanceof Uint8Array) || input.fnDsa.sk.length === 0) {
    throw new TypeError(`signPcaWithFndsa: '${suite.alg}' requires FN-DSA secret-key material`);
  }
  const pqPkB64u = b64u(input.fnDsa.pk);
  const msg = fndsaLeafMessage(input.leaf, suite.alg, pqPkB64u);
  const fnSig = fndsaSign(suite.variant, input.fnDsa.sk, msg);

  if (!suite.hasEd25519) {
    // Pure FN-DSA: the FN-DSA signature IS the primary `sig`.
    return { sig: b64u(fnSig), alg: suite.alg, pq_pk: pqPkB64u };
  }
  // Hybrid ed25519 + fn-dsa: `sig` = Ed25519 over `msg`, `pq_sig` = FN-DSA over `msg`.
  if (!(input.edSecret instanceof Uint8Array)) {
    throw new TypeError(`signPcaWithFndsa: '${suite.alg}' requires edSecret (Ed25519 leaf-holder secret key)`);
  }
  return { sig: b64u(sign(input.edSecret, msg)), alg: suite.alg, pq_pk: pqPkB64u, pq_sig: b64u(fnSig) };
}

/** Inputs to {@link verifyPcaFndsa}. The signature fields are UNTRUSTED (every one optional/`unknown`). */
export interface VerifyPcaFndsaInput {
  /** The FN-DSA suite id from the wire (validated; an unknown value fails closed). */
  alg: unknown;
  /** The PCActn (or body) whose leaf is being verified — its {@link thresholdMessage} is recomputed. */
  leaf: PCActn | PCActnBody;
  /** The Ed25519 leaf-holder public key (b64u) — REQUIRED for a hybrid suite. */
  holder?: unknown;
  /** The FN-DSA public key (b64u) as carried in the surface's `pq_pk`. */
  pq_pk?: unknown;
  /** The primary signature (b64u): FN-DSA sig for a pure suite, Ed25519 sig for a hybrid suite. */
  sig?: unknown;
  /** The FN-DSA signature (b64u) — hybrid suites only. */
  pq_sig?: unknown;
}

/**
 * Verify an FN-DSA leaf/hop signature over a PCActn. FAIL-CLOSED and never throws for ordinary wire
 * faults: an unknown `alg`, a wrong-length/absent key or signature, a tampered action (its
 * {@link thresholdMessage} changes), or a suite/key downgrade (the binding suffix changes) all return
 * false. Hybrid requires BOTH the Ed25519 half AND the FN-DSA half. (A registered backend that itself
 * throws is not caught — that is a backend bug, which should be loud.)
 */
export function verifyPcaFndsa(input: VerifyPcaFndsaInput): boolean {
  const suite = resolveFnDsaAlg(input.alg);
  if (suite === null) return false; // unknown alg => fail-closed
  if (typeof input.pq_pk !== 'string') return false;
  const pk = decodeB64uStrict(input.pq_pk, suite.pqPkBytes);
  if (pk === null) return false; // wrong-length / non-canonical FN-DSA key — rejected before the backend
  const msg = fndsaLeafMessage(input.leaf, suite.alg, input.pq_pk);

  if (!suite.hasEd25519) {
    // Pure FN-DSA: `sig` holds the FN-DSA signature.
    if (typeof input.sig !== 'string') return false;
    const fnSig = decodeB64uStrict(input.sig, suite.sigBytes);
    if (fnSig === null) return false; // wrong-length FN-DSA sig — rejected before the backend
    return fndsaVerify(suite.variant, pk, msg, fnSig);
  }
  // Hybrid: Ed25519 `sig` under `holder` AND FN-DSA `pq_sig` under `pq_pk`, both over `msg`.
  if (typeof input.holder !== 'string' || typeof input.sig !== 'string') return false;
  const edSig = decodeB64uStrict(input.sig, suite.sigBytes); // enforce 64-byte Ed25519 sig
  if (edSig === null) return false;
  const edOk = verifyB64u(input.holder, msg, input.sig);
  if (typeof input.pq_sig !== 'string') return false;
  const fnSig = decodeB64uStrict(input.pq_sig, suite.pqSigBytes);
  if (fnSig === null) return false;
  const pqOk = fndsaVerify(suite.variant, pk, msg, fnSig);
  return edOk && pqOk; // fail-closed: BOTH required
}

// ---------------------------------------------------------------------------------------------------
// KAT / mock backend harness (so the WIRE + integration + length enforcement are fully testable
// WITHOUT the real Falcon math)
// ---------------------------------------------------------------------------------------------------

/** A known-answer vector: the backend must map `(pk, msg)` to `sig`. */
export interface FalconKat {
  pk: Uint8Array;
  msg: Uint8Array;
  sig: Uint8Array;
}

/** Tag prefixed to a MOCK secret key so the mock can recover the public key from it (mock-only encoding). */
const MOCK_SK_TAG = utf8('atlas-pca/fn-dsa/mock-sk/v1\0');

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

/**
 * Deterministic SHA-256 counter-mode stretch of `seed` to exactly `outLen` bytes. This is the mock/KAT
 * key-derivation and signature-derivation function — NOT Falcon. It exists only so the wire framing and
 * length enforcement are testable with reproducible, fixed-length byte strings.
 */
export function hashKat(seed: Uint8Array, outLen: number): Uint8Array {
  const out = new Uint8Array(outLen);
  let off = 0;
  let counter = 0;
  while (off < outLen) {
    const block = sha256(concatBytes(seed, u32be(counter)));
    const take = Math.min(block.length, outLen - off);
    out.set(block.subarray(0, take), off);
    off += take;
    counter += 1;
  }
  return out;
}

function sigLenForPk(pkLen: number): number | null {
  if (pkLen === FN_DSA_512_PUBLIC_KEY_BYTES) return FN_DSA_512_SIGNATURE_BYTES;
  if (pkLen === FN_DSA_1024_PUBLIC_KEY_BYTES) return FN_DSA_1024_SIGNATURE_BYTES;
  return null;
}

/** The mock's deterministic `(pk, msg) -> sig` derivation, padded to the variant's fixed length. */
function deriveMockSig(pk: Uint8Array, msg: Uint8Array): Uint8Array | null {
  const sigLen = sigLenForPk(pk.length);
  if (sigLen === null) return null;
  return hashKat(concatBytes(utf8('fn-dsa/mock-sig/v1\0'), pk, msg), sigLen);
}

function katKey(pk: Uint8Array, msg: Uint8Array): string {
  return `${b64u(pk)}|${b64u(msg)}`;
}

/** Constant-time byte-equality (no early return on the first differing byte). */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * Deterministically mint a MOCK FN-DSA key pair for a variant (NOT real Falcon keys). The secret key is
 * `MOCK_SK_TAG ‖ pk` so the mock backend's `sign` can recover the public key from it; the public key is a
 * reproducible stretch of `seed` to the variant's exact length, so a given `seed` always yields the same
 * pair (handy for stable KAT fixtures).
 */
export function mockKeypair(variant: FnDsaVariant, seed: Uint8Array | string = 'default'): FalconKeyPair {
  if (!isFnDsaVariant(variant)) throw new RangeError(`mockKeypair: unknown FN-DSA variant '${String(variant)}'`);
  const seedBytes = typeof seed === 'string' ? utf8(`${variant}/${seed}`) : concatBytes(utf8(`${variant}/`), seed);
  const pk = hashKat(seedBytes, VARIANT_PK_BYTES[variant]);
  const sk = concatBytes(MOCK_SK_TAG, pk);
  return { pk, sk };
}

function pkFromMockSk(sk: Uint8Array): Uint8Array | null {
  if (sk.length <= MOCK_SK_TAG.length) return null;
  if (!timingSafeEqual(sk.subarray(0, MOCK_SK_TAG.length), MOCK_SK_TAG)) return null;
  return sk.subarray(MOCK_SK_TAG.length);
}

/**
 * Install a DETERMINISTIC mock FN-DSA backend (and return it) so the wire format, PCA integration and
 * length enforcement can be tested WITHOUT the real Falcon math. The backend is keyed by `(pk, msg) -> sig`:
 *   - any explicit `vectors` take precedence (drop in real FIPS-206 known-answer vectors here);
 *   - otherwise `(pk, msg)` maps to a reproducible {@link deriveMockSig}, so sign/verify round-trip.
 * `keygen()` returns an `fn-dsa-512` {@link mockKeypair} by default; use {@link mockKeypair} directly for a
 * specific variant. This is a TEST double — never register it in production (register a vetted backend).
 */
export function registerTestBackend(vectors?: readonly FalconKat[]): FalconBackend {
  const table = new Map<string, Uint8Array>();
  if (vectors) {
    for (const v of vectors) table.set(katKey(v.pk, v.msg), v.sig);
  }
  const backend: FalconBackend = {
    verify(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
      const fromTable = table.get(katKey(pk, msg));
      const expected = fromTable ?? deriveMockSig(pk, msg);
      if (expected === null) return false;
      return timingSafeEqual(sig, expected);
    },
    sign(sk: Uint8Array, msg: Uint8Array): Uint8Array {
      const pk = pkFromMockSk(sk);
      if (pk === null) throw new Error('mock FN-DSA backend: secret key was not minted by mockKeypair()');
      const fromTable = table.get(katKey(pk, msg));
      if (fromTable) return fromTable;
      const derived = deriveMockSig(pk, msg);
      if (derived === null) throw new Error('mock FN-DSA backend: public key length matches no FN-DSA variant');
      return derived;
    },
    keygen(): FalconKeyPair {
      return mockKeypair('fn-dsa-512');
    },
  };
  setFalconBackend(backend);
  return backend;
}
