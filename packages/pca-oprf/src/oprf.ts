/**
 * `@atlasauth/pca-oprf` — RFC 9497 Oblivious Pseudorandom Functions on the
 * `ristretto255-SHA-512` ciphersuite.
 *
 * This module is a faithful, dependency-light implementation of the three modes defined by
 * RFC 9497 (<https://www.rfc-editor.org/rfc/rfc9497>):
 *
 *  - **OPRF**  (mode `0x00`, "base"): the server evaluates a PRF on a client-blinded input without
 *    learning the input, and the client unblinds to the PRF output. No verifiability.
 *  - **VOPRF** (mode `0x01`, "verifiable"): as OPRF, plus a non-interactive zero-knowledge DLEQ proof
 *    that the server used the key committed to by its public key. The client rejects a wrong/forged key.
 *  - **POPRF** (mode `0x02`, "partially oblivious"): the PRF is additionally keyed by a PUBLIC `info`
 *    tag the server sees (and proves it used), while the client's input stays hidden. Used here for a
 *    public rate-limit window.
 *
 * The group is ristretto255 (`@noble/curves` `RistrettoPoint`) and the hash is SHA-512
 * (`@noble/hashes`). All domain-separation tags and transcript framing follow the RFC so that outputs
 * match the spec's test vectors (see `rfc-vectors.test.ts`).
 *
 * Everything in this module is pure crypto with no PCA concepts; the PCA mapping (private revocation
 * checks + private rate-limiting) is built on top in `pca.ts`.
 */

import { RistrettoPoint, hashToRistretto255 } from '@noble/curves/ed25519';
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve';
import { invert, mod } from '@noble/curves/abstract/modular';
import {
  bytesToHex,
  bytesToNumberLE,
  concatBytes,
  numberToBytesBE,
  numberToBytesLE,
} from '@noble/curves/abstract/utils';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes } from '@noble/hashes/utils';

// ---------------------------------------------------------------------------------------------
// Group / ciphersuite constants (RFC 9497 §4.1, ristretto255-SHA512)
// ---------------------------------------------------------------------------------------------

/** A ristretto255 group element (opaque wrapper; (de)serialize with {@link serializeElement}). */
export type Element = InstanceType<typeof RistrettoPoint>;

/**
 * The ristretto255 prime-subgroup order L (identical to the ed25519 scalar-field order):
 * `L = 2^252 + 27742317777372353535851937790883648493`. Verified equal to the library's
 * `ed25519.CURVE.n` at build time.
 */
const ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;

/** Serialized element length in bytes (`Ne`). */
export const ELEMENT_BYTES = 32;
/** Serialized scalar length in bytes (`Ns`). */
export const SCALAR_BYTES = 32;
/** OPRF output length in bytes (`Nh`, SHA-512). */
export const OUTPUT_BYTES = 64;

/** The RFC 9497 ciphersuite identifier for this build. */
export const SUITE_ID = 'ristretto255-SHA512';

/** RFC 9497 modes. The numeric value is the `mode` byte folded into every domain-separation tag. */
export const MODE = {
  oprf: 0x00,
  voprf: 0x01,
  poprf: 0x02,
} as const;

/** The three RFC 9497 protocol modes. */
export type Mode = keyof typeof MODE;

const te = new TextEncoder();

/** `contextString = "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier` (RFC 9497 §3.1). */
function contextString(mode: Mode): Uint8Array {
  return concatBytes(te.encode('OPRFV1-'), i2osp(MODE[mode], 1), te.encode('-' + SUITE_ID));
}

// ---------------------------------------------------------------------------------------------
// Primitive encodings (RFC 9497 §2.1 + the ristretto255 group spec)
// ---------------------------------------------------------------------------------------------

/** I2OSP: non-negative integer to a fixed-length big-endian byte string. */
function i2osp(n: number, len: number): Uint8Array {
  return numberToBytesBE(n, len);
}

/** Serialize a group element to its 32-byte ristretto255 encoding. */
export function serializeElement(p: Element): Uint8Array {
  return p.toRawBytes();
}

/**
 * Deserialize a 32-byte ristretto255 encoding to an element. Rejects the identity element and any
 * non-canonical encoding, per RFC 9497 `DeserializeElement`.
 */
export function deserializeElement(bytes: Uint8Array): Element {
  const p = RistrettoPoint.fromHex(bytes);
  if (p.equals(RistrettoPoint.ZERO)) {
    throw new Error('DeserializeElement: identity element is not a valid input');
  }
  return p;
}

/** Serialize a scalar to its 32-byte little-endian encoding. */
export function serializeScalar(s: bigint): Uint8Array {
  return numberToBytesLE(mod(s, ORDER), SCALAR_BYTES);
}

/**
 * Deserialize a 32-byte little-endian scalar encoding. Rejects any value >= the group order
 * (RFC 9497 §4.1), so a scalar has exactly one valid encoding (no proof/key malleability).
 */
export function deserializeScalar(bytes: Uint8Array): bigint {
  if (bytes.length !== SCALAR_BYTES) {
    throw new Error(`DeserializeScalar: expected ${SCALAR_BYTES} bytes, got ${bytes.length}`);
  }
  const n = bytesToNumberLE(bytes);
  if (n >= ORDER) {
    throw new Error('DeserializeScalar: non-canonical scalar (value >= group order)');
  }
  return n;
}

// ---------------------------------------------------------------------------------------------
// Group helpers (RFC 9497 §2.1 + §4.1)
// ---------------------------------------------------------------------------------------------

/** `HashToGroup(input)` — maps a byte string to a ristretto255 element with the mode's DST. */
export function hashToGroup(input: Uint8Array, mode: Mode): Element {
  const dst = concatBytes(te.encode('HashToGroup-'), contextString(mode));
  return hashToRistretto255(input, { DST: dst });
}

/**
 * `HashToScalar(input, DST)` — maps a byte string to a scalar mod L. RFC 9497 §4.1: expand to a uniform
 * 64-byte string with `expand_message_xmd(SHA-512)`, interpret little-endian, and reduce mod the order.
 */
function hashToScalarWithDst(input: Uint8Array, dst: Uint8Array): bigint {
  const uniform = expand_message_xmd(input, dst, 64, sha512);
  return mod(bytesToNumberLE(uniform), ORDER);
}

/** `HashToScalar(input)` with the default `"HashToScalar-" || contextString` DST. */
function hashToScalar(input: Uint8Array, mode: Mode): bigint {
  return hashToScalarWithDst(input, concatBytes(te.encode('HashToScalar-'), contextString(mode)));
}

/** `ScalarBaseMult`: the group generator times `k`. */
function scalarBaseMult(k: bigint): Element {
  return RistrettoPoint.BASE.multiply(mod(k, ORDER));
}

/** A uniformly random non-zero scalar (RFC 9497 `RandomScalar`). */
export function randomScalar(): bigint {
  for (;;) {
    const s = mod(bytesToNumberLE(randomBytes(64)), ORDER);
    if (s !== 0n) return s;
  }
}

/** Modular inverse in the scalar field. */
function scalarInvert(s: bigint): bigint {
  return invert(mod(s, ORDER), ORDER);
}

// ---------------------------------------------------------------------------------------------
// Keys (RFC 9497 §3.2)
// ---------------------------------------------------------------------------------------------

/** A server key pair. Both halves are serialized (scalar LE / element) for portability. */
export interface KeyPair {
  /** `SerializeScalar(skS)` — the 32-byte secret key. */
  secretKey: Uint8Array;
  /** `SerializeElement(pkS)` — the 32-byte public key (`skS * G`). Used by VOPRF/POPRF. */
  publicKey: Uint8Array;
}

/**
 * `DeriveKeyPair(seed, info)` (RFC 9497 §3.2): deterministically derive a key pair from a 32-byte seed
 * and an application `info` string, rejection-sampling until a non-zero scalar is found.
 */
export function deriveKeyPair(seed: Uint8Array, info: Uint8Array, mode: Mode): KeyPair {
  const dst = concatBytes(te.encode('DeriveKeyPair'), contextString(mode));
  const deriveInput = concatBytes(seed, i2osp(info.length, 2), info);
  for (let counter = 0; counter <= 255; counter++) {
    const skS = hashToScalarWithDst(concatBytes(deriveInput, i2osp(counter, 1)), dst);
    if (skS !== 0n) {
      return { secretKey: serializeScalar(skS), publicKey: serializeElement(scalarBaseMult(skS)) };
    }
  }
  throw new Error('DeriveKeyPair: failed to derive a non-zero key after 256 attempts');
}

/** Generate a fresh random key pair (mode-independent; the public key is `skS * G`). */
export function randomKeyPair(): KeyPair {
  const skS = randomScalar();
  return { secretKey: serializeScalar(skS), publicKey: serializeElement(scalarBaseMult(skS)) };
}

/** Recover the public key (`skS * G`) that corresponds to a secret key. */
export function publicKeyFor(secretKey: Uint8Array): Uint8Array {
  return serializeElement(scalarBaseMult(deserializeScalar(secretKey)));
}

// ---------------------------------------------------------------------------------------------
// DLEQ proof (RFC 9497 §2.2) — the heart of VOPRF/POPRF verifiability
// ---------------------------------------------------------------------------------------------

/** A serialized DLEQ proof: `SerializeScalar(c) || SerializeScalar(s)` (64 bytes). */
export type Proof = Uint8Array;

/** `ComputeComposites` common prologue: the seed derived from `B` (RFC 9497 §2.2.1). */
function compositesSeed(bSer: Uint8Array, mode: Mode): Uint8Array {
  const seedDst = concatBytes(te.encode('Seed-'), contextString(mode));
  return sha512(concatBytes(i2osp(bSer.length, 2), bSer, i2osp(seedDst.length, 2), seedDst));
}

/** Per-element composite coefficient `di` (RFC 9497 §2.2.1). */
function compositeCoefficient(
  seed: Uint8Array,
  index: number,
  cSer: Uint8Array,
  dSer: Uint8Array,
  mode: Mode,
): bigint {
  const transcript = concatBytes(
    i2osp(seed.length, 2),
    seed,
    i2osp(index, 2),
    i2osp(cSer.length, 2),
    cSer,
    i2osp(dSer.length, 2),
    dSer,
    te.encode('Composite'),
  );
  return hashToScalar(transcript, mode);
}

/** `ComputeComposites(B, Cs, Ds)` (verifier path, RFC 9497 §2.2.1): returns `(M, Z)`. */
function computeComposites(b: Element, cs: Element[], ds: Element[], mode: Mode): [Element, Element] {
  const seed = compositesSeed(serializeElement(b), mode);
  let m = RistrettoPoint.ZERO;
  let z = RistrettoPoint.ZERO;
  for (let i = 0; i < cs.length; i++) {
    const ci = cs[i];
    const di = ds[i];
    if (ci === undefined || di === undefined) throw new Error('computeComposites: ragged inputs');
    const coeff = compositeCoefficient(seed, i, serializeElement(ci), serializeElement(di), mode);
    m = ci.multiplyUnsafe(coeff).add(m);
    z = di.multiplyUnsafe(coeff).add(z);
  }
  return [m, z];
}

/** `ComputeCompositesFast(k, B, Cs, Ds)` (prover path): `Z = k * M` (RFC 9497 §2.2.1). */
function computeCompositesFast(
  k: bigint,
  b: Element,
  cs: Element[],
  ds: Element[],
  mode: Mode,
): [Element, Element] {
  const seed = compositesSeed(serializeElement(b), mode);
  let m = RistrettoPoint.ZERO;
  for (let i = 0; i < cs.length; i++) {
    const ci = cs[i];
    const di = ds[i];
    if (ci === undefined || di === undefined) throw new Error('computeCompositesFast: ragged inputs');
    const coeff = compositeCoefficient(seed, i, serializeElement(ci), serializeElement(di), mode);
    m = ci.multiplyUnsafe(coeff).add(m);
  }
  return [m, m.multiplyUnsafe(mod(k, ORDER))];
}

/** The Fiat-Shamir challenge transcript hash `c` (RFC 9497 §2.2.1/§2.2.2). */
function challenge(b: Element, m: Element, z: Element, t2: Element, t3: Element, mode: Mode): bigint {
  const parts = [b, m, z, t2, t3].map((p) => {
    const ser = serializeElement(p);
    return concatBytes(i2osp(ser.length, 2), ser);
  });
  const transcript = concatBytes(
    parts[0] ?? new Uint8Array(),
    parts[1] ?? new Uint8Array(),
    parts[2] ?? new Uint8Array(),
    parts[3] ?? new Uint8Array(),
    parts[4] ?? new Uint8Array(),
    te.encode('Challenge'),
  );
  return hashToScalar(transcript, mode);
}

/**
 * `GenerateProof(k, A, B, [C], [D])` (RFC 9497 §2.2.1): a NIZK that `log_A(B) == log_C(D) == k`.
 * Single-element batch (one `(C, D)` pair), which is all the (V/PO)PRF evaluate path needs.
 */
function generateProof(
  k: bigint,
  a: Element,
  b: Element,
  c: Element,
  d: Element,
  mode: Mode,
  fixedRandomness?: Uint8Array,
): Proof {
  const [m, z] = computeCompositesFast(k, b, [c], [d], mode);
  const r = fixedRandomness === undefined ? randomScalar() : deserializeScalar(fixedRandomness);
  const t2 = a.multiply(r);
  const t3 = m.multiply(r);
  const cc = challenge(b, m, z, t2, t3, mode);
  const s = mod(r - cc * k, ORDER);
  return concatBytes(serializeScalar(cc), serializeScalar(s));
}

/** `VerifyProof(A, B, [C], [D], proof)` (RFC 9497 §2.2.2): true iff the DLEQ relation holds. */
function verifyProof(a: Element, b: Element, c: Element, d: Element, proof: Proof, mode: Mode): boolean {
  if (proof.length !== 2 * SCALAR_BYTES) return false;
  const cc = deserializeScalar(proof.subarray(0, SCALAR_BYTES));
  const s = deserializeScalar(proof.subarray(SCALAR_BYTES));
  const [m, z] = computeComposites(b, [c], [d], mode);
  // t2 = s*A + c*B, t3 = s*M + c*Z (multiplyUnsafe: s/c are public and may be zero).
  const t2 = a.multiplyUnsafe(s).add(b.multiplyUnsafe(cc));
  const t3 = m.multiplyUnsafe(s).add(z.multiplyUnsafe(cc));
  const expected = challenge(b, m, z, t2, t3, mode);
  return mod(expected - cc, ORDER) === 0n;
}

// ---------------------------------------------------------------------------------------------
// The Finalize hash (RFC 9497 §3.3.1 / §3.4.1)
// ---------------------------------------------------------------------------------------------

/** OPRF/VOPRF finalize/evaluate output hash (no `info`). */
function finalizeHash(input: Uint8Array, issued: Uint8Array): Uint8Array {
  return sha512(
    concatBytes(
      i2osp(input.length, 2),
      input,
      i2osp(issued.length, 2),
      issued,
      te.encode('Finalize'),
    ),
  );
}

/** POPRF finalize/evaluate output hash (binds the public `info`). */
function finalizeHashPoprf(input: Uint8Array, info: Uint8Array, issued: Uint8Array): Uint8Array {
  return sha512(
    concatBytes(
      i2osp(input.length, 2),
      input,
      i2osp(info.length, 2),
      info,
      i2osp(issued.length, 2),
      issued,
      te.encode('Finalize'),
    ),
  );
}

// ---------------------------------------------------------------------------------------------
// OPRF (base) + VOPRF (verifiable) — RFC 9497 §3.3
// ---------------------------------------------------------------------------------------------

/** The client's retained blinding state plus the element to send to the server. */
export interface BlindResult {
  /** The secret blinding scalar, serialized (keep this; finalize needs it). */
  blind: Uint8Array;
  /** `SerializeElement(blind * HashToGroup(input))` — the only thing the client reveals. */
  blindedElement: Uint8Array;
}

/** A server blind-evaluation. `proof` is present for VOPRF/POPRF. */
export interface EvaluateResult {
  /** `SerializeElement(evaluatedElement)`. */
  evaluatedElement: Uint8Array;
  /** The DLEQ proof (VOPRF/POPRF only). */
  proof?: Proof;
}

/**
 * `Blind(input)` (RFC 9497 §3.3.1): pick a random scalar, map the input to the group, and blind it.
 * The `mode` must match the server's. Pass `fixedBlind` only for test vectors / determinism.
 */
export function blind(input: Uint8Array, mode: Mode = 'oprf', fixedBlind?: Uint8Array): BlindResult {
  const r = fixedBlind === undefined ? randomScalar() : deserializeScalar(fixedBlind);
  const inputElement = hashToGroup(input, mode);
  if (inputElement.equals(RistrettoPoint.ZERO)) throw new Error('Blind: input maps to identity');
  const blindedElement = inputElement.multiply(r);
  return { blind: serializeScalar(r), blindedElement: serializeElement(blindedElement) };
}

/**
 * `BlindEvaluate(skS, blindedElement)` for OPRF/VOPRF (RFC 9497 §3.3.1/§3.3.2): the server multiplies
 * the blinded element by its key. For VOPRF it additionally returns a DLEQ proof against `publicKey`.
 * `fixedProofRandomness` pins the proof nonce for test vectors only; never pass it in production.
 */
export function blindEvaluate(
  secretKey: Uint8Array,
  blindedElement: Uint8Array,
  mode: 'oprf' | 'voprf' = 'oprf',
  publicKey?: Uint8Array,
  fixedProofRandomness?: Uint8Array,
): EvaluateResult {
  const skS = deserializeScalar(secretKey);
  const r = deserializeElement(blindedElement);
  const evaluated = r.multiply(skS);
  if (mode === 'oprf') {
    return { evaluatedElement: serializeElement(evaluated) };
  }
  const pk = publicKey === undefined ? scalarBaseMult(skS) : deserializeElement(publicKey);
  // Prove log_G(pkS) == log_blinded(evaluated) == skS.
  const proof = generateProof(skS, RistrettoPoint.BASE, pk, r, evaluated, 'voprf', fixedProofRandomness);
  return { evaluatedElement: serializeElement(evaluated), proof };
}

/**
 * `Finalize(input, blind, evaluatedElement[, proof, publicKey, blindedElement])` for OPRF/VOPRF
 * (RFC 9497 §3.3.1/§3.3.2). For VOPRF the DLEQ proof is verified first and a bad proof throws.
 */
export function finalize(
  input: Uint8Array,
  blindScalar: Uint8Array,
  evaluatedElement: Uint8Array,
  mode: 'oprf' | 'voprf' = 'oprf',
  opts?: { proof?: Proof; publicKey?: Uint8Array; blindedElement?: Uint8Array },
): Uint8Array {
  const r = deserializeScalar(blindScalar);
  const evaluated = deserializeElement(evaluatedElement);
  if (mode === 'voprf') {
    const proof = opts?.proof;
    const publicKey = opts?.publicKey;
    const blindedElement = opts?.blindedElement;
    if (proof === undefined || publicKey === undefined || blindedElement === undefined) {
      throw new Error('Finalize(voprf): proof, publicKey and blindedElement are required');
    }
    const pk = deserializeElement(publicKey);
    const blinded = deserializeElement(blindedElement);
    if (!verifyProof(RistrettoPoint.BASE, pk, blinded, evaluated, proof, 'voprf')) {
      throw new Error('Finalize(voprf): DLEQ proof verification failed');
    }
  }
  const n = evaluated.multiply(scalarInvert(r));
  return finalizeHash(input, serializeElement(n));
}

/**
 * `Evaluate(skS, input)` for OPRF/VOPRF (RFC 9497 §3.3.1): the server's NON-blinded reference output.
 * `finalize(input, blind, blindEvaluate(skS, blind(input)))` equals this for the same input and key.
 */
export function evaluate(secretKey: Uint8Array, input: Uint8Array, mode: 'oprf' | 'voprf' = 'oprf'): Uint8Array {
  const skS = deserializeScalar(secretKey);
  const inputElement = hashToGroup(input, mode);
  if (inputElement.equals(RistrettoPoint.ZERO)) throw new Error('Evaluate: input maps to identity');
  const evaluated = inputElement.multiply(skS);
  return finalizeHash(input, serializeElement(evaluated));
}

// ---------------------------------------------------------------------------------------------
// POPRF (partially oblivious) — RFC 9497 §3.4
// ---------------------------------------------------------------------------------------------

/** `info` → the scalar tweak `m` (RFC 9497 §3.4). */
function poprfInfoScalar(info: Uint8Array): bigint {
  const framed = concatBytes(te.encode('Info'), i2osp(info.length, 2), info);
  return hashToScalar(framed, 'poprf');
}

/** The client's POPRF blind state, including the derived `tweakedKey` it must keep for finalize. */
export interface PoprfBlindResult extends BlindResult {
  /** `SerializeElement(m*G + pkS)` — the public-info-tweaked server key the client will verify against. */
  tweakedKey: Uint8Array;
}

/**
 * `Blind(input, info, pkS)` for POPRF (RFC 9497 §3.4.1). The `info` is public; the client derives the
 * tweaked key locally so finalize can verify the proof. `fixedBlind` is for test vectors only.
 */
export function blindPoprf(
  input: Uint8Array,
  info: Uint8Array,
  publicKey: Uint8Array,
  fixedBlind?: Uint8Array,
): PoprfBlindResult {
  const m = poprfInfoScalar(info);
  const tweaked = scalarBaseMult(m).add(deserializeElement(publicKey));
  if (tweaked.equals(RistrettoPoint.ZERO)) throw new Error('Blind(poprf): tweaked key is identity');
  const base = blind(input, 'poprf', fixedBlind);
  return { ...base, tweakedKey: serializeElement(tweaked) };
}

/**
 * `BlindEvaluate(skS, blindedElement, info)` for POPRF (RFC 9497 §3.4.1). The server folds the PUBLIC
 * `info` into its key (`t = skS + m`), evaluates with `1/t`, and proves it used `t` for `info`.
 */
export function blindEvaluatePoprf(
  secretKey: Uint8Array,
  blindedElement: Uint8Array,
  info: Uint8Array,
  fixedProofRandomness?: Uint8Array,
): EvaluateResult {
  const skS = deserializeScalar(secretKey);
  const m = poprfInfoScalar(info);
  const t = mod(skS + m, ORDER);
  if (t === 0n) throw new Error('BlindEvaluate(poprf): inverse of zero (bad info/key)');
  const blinded = deserializeElement(blindedElement);
  const evaluated = blinded.multiply(scalarInvert(t));
  const tweakedKey = scalarBaseMult(t);
  // Prove log_G(tweakedKey) == log_evaluated(blinded) == t (note C=evaluated, D=blinded).
  const proof = generateProof(t, RistrettoPoint.BASE, tweakedKey, evaluated, blinded, 'poprf', fixedProofRandomness);
  return { evaluatedElement: serializeElement(evaluated), proof };
}

/**
 * `Finalize(input, blind, evaluatedElement, blindedElement, proof, info, tweakedKey)` for POPRF
 * (RFC 9497 §3.4.1). Verifies the DLEQ proof against the client-derived `tweakedKey`, then unblinds.
 */
export function finalizePoprf(
  input: Uint8Array,
  blindScalar: Uint8Array,
  evaluatedElement: Uint8Array,
  info: Uint8Array,
  opts: { proof: Proof; blindedElement: Uint8Array; tweakedKey: Uint8Array },
): Uint8Array {
  const r = deserializeScalar(blindScalar);
  const evaluated = deserializeElement(evaluatedElement);
  const blinded = deserializeElement(opts.blindedElement);
  const tweaked = deserializeElement(opts.tweakedKey);
  if (!verifyProof(RistrettoPoint.BASE, tweaked, evaluated, blinded, opts.proof, 'poprf')) {
    throw new Error('Finalize(poprf): DLEQ proof verification failed');
  }
  const n = evaluated.multiply(scalarInvert(r));
  return finalizeHashPoprf(input, info, serializeElement(n));
}

/**
 * `Evaluate(skS, input, info)` for POPRF (RFC 9497 §3.4.1): the server's NON-blinded reference output
 * for a `(input, info)` pair. Equals the client's `finalizePoprf(...)` for the same arguments.
 */
export function evaluatePoprf(secretKey: Uint8Array, input: Uint8Array, info: Uint8Array): Uint8Array {
  const skS = deserializeScalar(secretKey);
  const m = poprfInfoScalar(info);
  const t = mod(skS + m, ORDER);
  if (t === 0n) throw new Error('Evaluate(poprf): inverse of zero (bad info/key)');
  const inputElement = hashToGroup(input, 'poprf');
  if (inputElement.equals(RistrettoPoint.ZERO)) throw new Error('Evaluate(poprf): input maps to identity');
  const evaluated = inputElement.multiply(scalarInvert(t));
  return finalizeHashPoprf(input, info, serializeElement(evaluated));
}

// ---------------------------------------------------------------------------------------------
// Small utilities re-exported for the PCA layer and tests
// ---------------------------------------------------------------------------------------------

/** Lowercase-hex of a byte string (stable set-membership keys). */
export function toHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

/** Constant-time-ish byte equality (length check first, then full-width compare). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
