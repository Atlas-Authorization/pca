/**
 * BBS signatures over BLS12-381, faithful to draft-irtf-cfrg-bbs-signatures (core protocol and
 * octet encodings; validated against the draft's official BLS12-381-SHA-256 fixtures, which are unchanged
 * across drafts -06 to -12, and against the independent `zkryptium` crate).
 *
 * Ciphersuite: **BLS12-381-SHA-256** — `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_`.
 *   - signatures/generators live in G1 (48-byte compressed points), public keys in G2 (96-byte
 *     compressed points), scalars are 32 bytes big-endian in the field of order `r`;
 *   - hashing uses `expand_message_xmd` with SHA-256 (RFC 9380), `expand_len = 48`;
 *   - the api_id is `ciphersuite_id || "H2G_HM2S_"`.
 *
 * A BBS signature covers an ORDERED VECTOR of messages. From one signature a holder can produce an
 * unlimited number of zero-knowledge proofs, each revealing an arbitrary SUBSET of the messages and
 * proving knowledge of the rest — with two properties that make this the privacy frontier for agent
 * authority:
 *   - SELECTIVE DISCLOSURE: the verifier learns only the disclosed messages;
 *   - UNLINKABILITY: the signature value `A` is never shown (it is blinded into `Ā`, `B̄`, `D` with
 *     fresh randomness every time), so two presentations of the same credential cannot be correlated.
 *
 * Implementation notes:
 *   - Scalar arithmetic uses the curve's own scalar field `Fr` (order `r`); point arithmetic uses
 *     `multiplyUnsafe` (variable-time). This mirrors the draft's reference clarity and is appropriate
 *     for the public blinding operations here; it is NOT a constant-time implementation and callers
 *     holding long-lived secret keys in an adversarial co-tenant should keep that in mind.
 *   - All cross-language octet encodings (point/scalar/integer serialization, challenge and domain
 *     inputs) follow the draft so a conforming verifier in another language interoperates.
 */
import { bls12_381 } from '@noble/curves/bls12-381';
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve';
import { bytesToNumberBE, concatBytes, numberToBytesBE } from '@noble/curves/abstract/utils';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

// ---- curve handles ----------------------------------------------------------------------------

const G1 = bls12_381.G1.ProjectivePoint;
const G2 = bls12_381.G2.ProjectivePoint;
const Fr = bls12_381.fields.Fr;
const Fp12 = bls12_381.fields.Fp12;

/** A point of G1 (signatures, generators, proof commitments). */
export type G1Point = InstanceType<typeof bls12_381.G1.ProjectivePoint>;
/** A point of G2 (public keys). */
export type G2Point = InstanceType<typeof bls12_381.G2.ProjectivePoint>;

/** Order of the BBS scalar field (the prime subgroup order `r`). */
export const R: bigint = Fr.ORDER;

// ---- ciphersuite constants (BLS12-381-SHA-256) ------------------------------------------------

/** The ciphersuite identifier (without the api_id suffix). */
export const CIPHERSUITE_ID = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_';
/** api_id = ciphersuite_id || "H2G_HM2S_". */
export const API_ID = `${CIPHERSUITE_ID}H2G_HM2S_`;

const OCTET_SCALAR_LENGTH = 32;
const OCTET_POINT_LENGTH = 48; // G1, compressed
const EXPAND_LEN = 48;

const H2S_DST = `${API_ID}H2S_`;
const MAP_DST = `${API_ID}MAP_MSG_TO_SCALAR_AS_HASH_`;
const SEED_DST = `${API_ID}SIG_GENERATOR_SEED_`;
const GEN_DST = `${API_ID}SIG_GENERATOR_DST_`;
const GEN_SEED = `${API_ID}MESSAGE_GENERATOR_SEED`;
/** KeyGen DST = api_id || "KEYGEN_DST_" (draft §3.4.1); the official key-pair fixture pins this exact string. */
const KEYGEN_DST = `${API_ID}KEYGEN_DST_`;

/**
 * P1: the fixed G1 generator of the BLS12-381-SHA-256 ciphersuite (draft §7.2.2), as published.
 * Signing commits the message vector against P1, Q_1 and the per-message generators H_i.
 */
const P1_HEX = 'a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9';
const P1: G1Point = G1.fromHex(P1_HEX);
/** The base point of G2 (public keys are `SK · BP2`). */
const BP2: G2Point = G2.BASE;

// ---- small octet / scalar helpers -------------------------------------------------------------

const TEXT = new TextEncoder();
function ascii(s: string): Uint8Array {
  return TEXT.encode(s);
}

/** I2OSP: non-negative integer -> fixed-length big-endian octets (RFC 8017 §4.1). */
function i2osp(n: bigint, len: number): Uint8Array {
  return numberToBytesBE(n, len);
}

/** OS2IP: big-endian octets -> non-negative integer (RFC 8017 §4.2). */
function os2ip(b: Uint8Array): bigint {
  return bytesToNumberBE(b);
}

/** Checked array read (keeps `noUncheckedIndexedAccess` honest without non-null assertions). */
function at<T>(arr: readonly T[], i: number): T {
  const v = arr[i];
  if (v === undefined) throw new RangeError(`bbs: index ${i} out of range (len ${arr.length})`);
  return v;
}

/** expand_message_xmd with SHA-256 (RFC 9380 §5.3.1). */
function expand(msg: Uint8Array, dst: string, len: number): Uint8Array {
  return expand_message_xmd(msg, ascii(dst), len, sha256);
}

/** hash_to_scalar(msg, dst) = OS2IP(expand_message_xmd(msg, dst, 48)) mod r (draft §4.2.2). */
export function hashToScalar(msg: Uint8Array, dst: string): bigint {
  return Fr.create(os2ip(expand(msg, dst, EXPAND_LEN)));
}

/** MapMessageToScalarAsHash: one message octet string -> one scalar (draft §4.2). */
export function mapMessageToScalarAsHash(message: Uint8Array): bigint {
  return hashToScalar(message, MAP_DST);
}

/** messages_to_scalars: map each message octet string to its scalar (draft §4.2). */
export function messagesToScalars(messages: readonly Uint8Array[]): bigint[] {
  return messages.map((m) => mapMessageToScalarAsHash(m));
}

/**
 * create_generators(count): the deterministic generator sequence `(Q_1, H_1, ..., H_{count-1})`
 * (draft §4.1). Each generator is the hash-to-curve of a chained `expand_message` ratchet.
 */
export function createGenerators(count: number): G1Point[] {
  if (!Number.isInteger(count) || count < 0) throw new RangeError('bbs: generator count must be a non-negative integer');
  const gens: G1Point[] = [];
  let v = expand(ascii(GEN_SEED), SEED_DST, EXPAND_LEN);
  for (let i = 1; i <= count; i++) {
    v = expand(concatBytes(v, i2osp(BigInt(i), 8)), SEED_DST, EXPAND_LEN);
    const h2c = bls12_381.G1.hashToCurve(v, { DST: GEN_DST });
    gens.push(G1.fromAffine(h2c.toAffine()));
  }
  return gens;
}

// ---- serialization (draft §4.2.4 serialize()) -------------------------------------------------

type SerEl =
  | { readonly t: 'g1'; readonly v: G1Point }
  | { readonly t: 'g2'; readonly v: G2Point }
  | { readonly t: 'scalar'; readonly v: bigint }
  | { readonly t: 'int'; readonly v: number };

function serialize(els: readonly SerEl[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const el of els) {
    switch (el.t) {
      case 'g1':
        parts.push(el.v.toRawBytes(true));
        break;
      case 'g2':
        parts.push(el.v.toRawBytes(true));
        break;
      case 'scalar':
        parts.push(i2osp(el.v, OCTET_SCALAR_LENGTH));
        break;
      case 'int':
        parts.push(i2osp(BigInt(el.v), 8));
        break;
    }
  }
  return concatBytes(...parts);
}

// ---- point arithmetic helpers -----------------------------------------------------------------

function g1mul(P: G1Point, s: bigint): G1Point {
  const sc = Fr.create(s);
  return sc === 0n ? G1.ZERO : P.multiplyUnsafe(sc);
}

function g2mul(P: G2Point, s: bigint): G2Point {
  const sc = Fr.create(s);
  return sc === 0n ? G2.ZERO : P.multiplyUnsafe(sc);
}

// ---- key generation (draft §3.4) --------------------------------------------------------------

/**
 * KeyGen: derive a secret scalar `SK` from key material and optional context info (draft §3.4.1).
 * Requires at least 32 octets of key material. Returns the scalar; never 0.
 */
export function keyGen(keyMaterial: Uint8Array, keyInfo: Uint8Array = new Uint8Array(0)): bigint {
  if (keyMaterial.length < 32) throw new RangeError('bbs: key material must be at least 32 octets');
  if (keyInfo.length > 65535) throw new RangeError('bbs: key info must be at most 65535 octets');
  const deriveInput = concatBytes(keyMaterial, i2osp(BigInt(keyInfo.length), 2), keyInfo);
  const sk = hashToScalar(deriveInput, KEYGEN_DST);
  if (sk === 0n) throw new Error('bbs: derived SK is zero (retry with different key material)');
  return sk;
}

/** SkToPk: the public key octets `point_to_octets_E2(SK · BP2)` (draft §3.4.2). */
export function skToPk(sk: bigint): Uint8Array {
  return g2mul(BP2, sk).toRawBytes(true);
}

/** Convenience: generate a fresh (SK scalar, PK octets) pair from the system CSPRNG. */
export function generateKeyPair(): { sk: bigint; pk: Uint8Array } {
  const sk = keyGen(randomBytes(32));
  return { sk, pk: skToPk(sk) };
}

/** A 32-octet big-endian secret scalar (e.g. to serialize or parse a given SK). */
export function skToBytes(sk: bigint): Uint8Array {
  return i2osp(sk, OCTET_SCALAR_LENGTH);
}
export function skFromBytes(bytes: Uint8Array): bigint {
  if (bytes.length !== OCTET_SCALAR_LENGTH) throw new RangeError('bbs: SK must be 32 octets');
  const sk = os2ip(bytes);
  if (sk === 0n || sk >= R) throw new RangeError('bbs: SK out of range');
  return sk;
}

// ---- signature octets (draft §4.2.5 / §4.2.6) -------------------------------------------------

interface ParsedSignature {
  A: G1Point;
  e: bigint;
}

function signatureToOctets(A: G1Point, e: bigint): Uint8Array {
  return concatBytes(A.toRawBytes(true), i2osp(e, OCTET_SCALAR_LENGTH));
}

function octetsToSignature(sig: Uint8Array): ParsedSignature {
  if (sig.length !== OCTET_POINT_LENGTH + OCTET_SCALAR_LENGTH) {
    throw new RangeError('bbs: signature must be 80 octets');
  }
  const A = G1.fromHex(sig.subarray(0, OCTET_POINT_LENGTH));
  if (A.equals(G1.ZERO)) throw new Error('bbs: signature point A is the identity');
  const e = os2ip(sig.subarray(OCTET_POINT_LENGTH));
  if (e <= 0n || e >= R) throw new RangeError('bbs: signature scalar e out of range');
  return { A, e };
}

// ---- domain (draft §4.2.3) --------------------------------------------------------------------

function calculateDomain(pk: Uint8Array, Q1: G1Point, H: readonly G1Point[], header: Uint8Array): bigint {
  const els: SerEl[] = [{ t: 'int', v: H.length }, { t: 'g1', v: Q1 }];
  for (const h of H) els.push({ t: 'g1', v: h });
  const domOcts = concatBytes(serialize(els), ascii(API_ID));
  const domInput = concatBytes(pk, domOcts, i2osp(BigInt(header.length), 8), header);
  return hashToScalar(domInput, H2S_DST);
}

/** B = P1 + Q_1·domain + Σ H_i·msg_i (the common commitment used by Sign/Verify/ProofGen). */
function computeB(Q1: G1Point, H: readonly G1Point[], domain: bigint, msgScalars: readonly bigint[]): G1Point {
  let B = P1.add(g1mul(Q1, domain));
  for (let i = 0; i < msgScalars.length; i++) {
    B = B.add(g1mul(at(H, i), at(msgScalars, i)));
  }
  return B;
}

// ---- Sign / Verify (draft §3.5.1 / §3.5.2, cores §3.6.1 / §3.6.2) -----------------------------

/**
 * Sign(SK, PK, header, messages): produce an 80-octet BBS signature over the ordered message vector.
 * `header` is an optional application-bound context signed into the credential (not selectively
 * disclosable). Returns `signature_to_octets(A, e)`.
 */
export function sign(sk: bigint, pk: Uint8Array, header: Uint8Array, messages: readonly Uint8Array[]): Uint8Array {
  const msgScalars = messagesToScalars(messages);
  const L = msgScalars.length;
  const gens = createGenerators(L + 1);
  const Q1 = at(gens, 0);
  const H = gens.slice(1);
  const domain = calculateDomain(pk, Q1, H, header);

  // e = hash_to_scalar(serialize(SK, msg_1, ..., msg_L, domain), H2S_DST)   (deterministic nonce)
  const eEls: SerEl[] = [{ t: 'scalar', v: sk }];
  for (const m of msgScalars) eEls.push({ t: 'scalar', v: m });
  eEls.push({ t: 'scalar', v: domain });
  const e = hashToScalar(serialize(eEls), H2S_DST);

  const B = computeB(Q1, H, domain, msgScalars);
  const A = g1mul(B, Fr.inv(Fr.add(sk, e))); // A = B · 1/(SK + e)
  return signatureToOctets(A, e);
}

/** Why a signature or proof was rejected (stable, machine-readable). */
export type RejectReason =
  | 'malformed-signature'
  | 'malformed-public-key'
  | 'malformed-proof'
  | 'disclosed-length-mismatch'
  | 'invalid-disclosed-indexes'
  | 'pairing-mismatch'
  | 'challenge-mismatch';

/** Result of a verification that says WHY it failed. */
export type VerifyResult = { readonly ok: true } | { readonly ok: false; readonly reason: RejectReason };

/** Verify(PK, signature, header, messages) with a rejection reason; fails closed on any malformed input. */
export function verifyDetailed(
  pk: Uint8Array,
  signature: Uint8Array,
  header: Uint8Array,
  messages: readonly Uint8Array[],
): VerifyResult {
  let parsed: ParsedSignature;
  try {
    parsed = octetsToSignature(signature);
  } catch {
    return { ok: false, reason: 'malformed-signature' };
  }
  let W: G2Point;
  try {
    W = G2.fromHex(pk);
  } catch {
    return { ok: false, reason: 'malformed-public-key' };
  }
  if (W.equals(G2.ZERO)) return { ok: false, reason: 'malformed-public-key' };
  const msgScalars = messagesToScalars(messages);
  const L = msgScalars.length;
  const gens = createGenerators(L + 1);
  const Q1 = at(gens, 0);
  const H = gens.slice(1);
  const domain = calculateDomain(pk, Q1, H, header);
  const B = computeB(Q1, H, domain, msgScalars);

  // Pairing check: e(A, W + BP2·e) == e(B, BP2)  ⇔  e(A, (SK+e)·BP2) == e(B, BP2).
  const lhs = bls12_381.pairing(parsed.A, W.add(g2mul(BP2, parsed.e)));
  const rhs = bls12_381.pairing(B, BP2);
  return Fp12.eql(lhs, rhs) ? { ok: true } : { ok: false, reason: 'pairing-mismatch' };
}

/** Verify(PK, signature, header, messages): true iff the signature covers exactly these messages. */
export function verify(pk: Uint8Array, signature: Uint8Array, header: Uint8Array, messages: readonly Uint8Array[]): boolean {
  return verifyDetailed(pk, signature, header, messages).ok;
}

// ---- random scalars (draft §4.2.1) ------------------------------------------------------------

function calculateRandomScalars(count: number): bigint[] {
  const out: bigint[] = [];
  for (let i = 0; i < count; i++) out.push(Fr.create(os2ip(randomBytes(EXPAND_LEN))));
  return out;
}

// ---- challenge (draft §3.7.4 ProofChallengeCalculate) -----------------------------------------

function calculateChallenge(
  Abar: G1Point,
  Bbar: G1Point,
  D: G1Point,
  T1: G1Point,
  T2: G1Point,
  disclosedIndexes: readonly number[],
  disclosedMsgs: readonly bigint[],
  domain: bigint,
  ph: Uint8Array,
): bigint {
  const els: SerEl[] = [{ t: 'int', v: disclosedIndexes.length }];
  for (let k = 0; k < disclosedIndexes.length; k++) {
    els.push({ t: 'int', v: at(disclosedIndexes, k) });
    els.push({ t: 'scalar', v: at(disclosedMsgs, k) });
  }
  els.push({ t: 'g1', v: Abar }, { t: 'g1', v: Bbar }, { t: 'g1', v: D }, { t: 'g1', v: T1 }, { t: 'g1', v: T2 }, { t: 'scalar', v: domain });
  const cOcts = concatBytes(serialize(els), i2osp(BigInt(ph.length), 8), ph);
  return hashToScalar(cOcts, H2S_DST);
}

// ---- proof octets (draft §4.2.7 / §4.2.8) -----------------------------------------------------

interface ParsedProof {
  Abar: G1Point;
  Bbar: G1Point;
  D: G1Point;
  eHat: bigint;
  r1Hat: bigint;
  r3Hat: bigint;
  mHat: bigint[];
  c: bigint;
}

function proofToOctets(p: ParsedProof): Uint8Array {
  const parts: Uint8Array[] = [p.Abar.toRawBytes(true), p.Bbar.toRawBytes(true), p.D.toRawBytes(true)];
  parts.push(i2osp(p.eHat, OCTET_SCALAR_LENGTH), i2osp(p.r1Hat, OCTET_SCALAR_LENGTH), i2osp(p.r3Hat, OCTET_SCALAR_LENGTH));
  for (const m of p.mHat) parts.push(i2osp(m, OCTET_SCALAR_LENGTH));
  parts.push(i2osp(p.c, OCTET_SCALAR_LENGTH));
  return concatBytes(...parts);
}

function readScalar(proof: Uint8Array, offset: number): bigint {
  const v = os2ip(proof.subarray(offset, offset + OCTET_SCALAR_LENGTH));
  if (v >= R) throw new RangeError('bbs: proof scalar out of range');
  return v;
}

function octetsToProof(proof: Uint8Array): ParsedProof {
  const fixed = 3 * OCTET_POINT_LENGTH + 4 * OCTET_SCALAR_LENGTH; // 3 points + eHat,r1Hat,r3Hat,c
  if (proof.length < fixed || (proof.length - fixed) % OCTET_SCALAR_LENGTH !== 0) {
    throw new RangeError('bbs: malformed proof length');
  }
  let o = 0;
  const Abar = G1.fromHex(proof.subarray(o, (o += OCTET_POINT_LENGTH)));
  const Bbar = G1.fromHex(proof.subarray(o, (o += OCTET_POINT_LENGTH)));
  const D = G1.fromHex(proof.subarray(o, (o += OCTET_POINT_LENGTH)));
  const eHat = readScalar(proof, o);
  o += OCTET_SCALAR_LENGTH;
  const r1Hat = readScalar(proof, o);
  o += OCTET_SCALAR_LENGTH;
  const r3Hat = readScalar(proof, o);
  o += OCTET_SCALAR_LENGTH;
  const U = (proof.length - fixed) / OCTET_SCALAR_LENGTH;
  const mHat: bigint[] = [];
  for (let i = 0; i < U; i++) {
    mHat.push(readScalar(proof, o));
    o += OCTET_SCALAR_LENGTH;
  }
  const c = readScalar(proof, o);
  if (Abar.equals(G1.ZERO) || Bbar.equals(G1.ZERO) || D.equals(G1.ZERO)) {
    throw new Error('bbs: proof contains the identity point');
  }
  return { Abar, Bbar, D, eHat, r1Hat, r3Hat, mHat, c };
}

// ---- index-set helpers ------------------------------------------------------------------------

function validateIndexes(indexes: readonly number[], L: number): void {
  const seen = new Set<number>();
  for (const i of indexes) {
    if (!Number.isInteger(i) || i < 0 || i >= L) throw new RangeError(`bbs: disclosed index ${i} out of range [0, ${L})`);
    if (seen.has(i)) throw new RangeError(`bbs: duplicate disclosed index ${i}`);
    seen.add(i);
  }
}

function undisclosedAscending(disclosed: ReadonlySet<number>, L: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < L; i++) if (!disclosed.has(i)) out.push(i);
  return out;
}

// ---- ProofGen (draft §3.5.3, core §3.6.3) -----------------------------------------------------

/**
 * ProofGen(PK, signature, header, ph, messages, disclosed_indexes): a zero-knowledge
 * proof-of-knowledge of the signature that selectively discloses the messages at
 * `disclosed_indexes`. `ph` is the presentation header (binds the proof to a context, e.g. a nonce
 * or the request it authorizes). The proof is randomized: each call produces different octets.
 * `fixedRandomScalars` (5 + undisclosed count scalars) pins the randomness for test vectors only;
 * never pass it in production, since reusing it across proofs breaks zero-knowledge and unlinkability.
 */
export function proofGen(
  pk: Uint8Array,
  signature: Uint8Array,
  header: Uint8Array,
  ph: Uint8Array,
  messages: readonly Uint8Array[],
  disclosedIndexes: readonly number[],
  fixedRandomScalars?: readonly bigint[],
): Uint8Array {
  const { A, e } = octetsToSignature(signature);
  const msgScalars = messagesToScalars(messages);
  const L = msgScalars.length;
  validateIndexes(disclosedIndexes, L);

  const disclosedSet = new Set(disclosedIndexes);
  const disclosed = [...disclosedSet].sort((a, b) => a - b);
  const undisclosed = undisclosedAscending(disclosedSet, L);
  const U = undisclosed.length;

  const gens = createGenerators(L + 1);
  const Q1 = at(gens, 0);
  const H = gens.slice(1);
  const domain = calculateDomain(pk, Q1, H, header);
  const B = computeB(Q1, H, domain, msgScalars);

  const rs = fixedRandomScalars === undefined ? calculateRandomScalars(5 + U) : [...fixedRandomScalars];
  if (rs.length !== 5 + U) throw new RangeError(`bbs: expected ${5 + U} random scalars, got ${rs.length}`);
  const r1 = at(rs, 0);
  const r2 = at(rs, 1);
  const eTilde = at(rs, 2);
  const r1Tilde = at(rs, 3);
  const r3Tilde = at(rs, 4);
  const mTilde = rs.slice(5);

  const D = g1mul(B, r2);
  const Abar = g1mul(A, Fr.mul(r1, r2));
  const Bbar = g1mul(D, r1).subtract(g1mul(Abar, e));
  const T1 = g1mul(Abar, eTilde).add(g1mul(D, r1Tilde));
  let T2 = g1mul(D, r3Tilde);
  for (let k = 0; k < U; k++) T2 = T2.add(g1mul(at(H, at(undisclosed, k)), at(mTilde, k)));

  const disclosedMsgs = disclosed.map((i) => at(msgScalars, i));
  const c = calculateChallenge(Abar, Bbar, D, T1, T2, disclosed, disclosedMsgs, domain, ph);

  const r3 = Fr.inv(r2);
  const eHat = Fr.add(eTilde, Fr.mul(e, c));
  const r1Hat = Fr.sub(r1Tilde, Fr.mul(r1, c));
  const r3Hat = Fr.sub(r3Tilde, Fr.mul(r3, c));
  const mHat: bigint[] = [];
  for (let k = 0; k < U; k++) mHat.push(Fr.add(at(mTilde, k), Fr.mul(at(msgScalars, at(undisclosed, k)), c)));

  return proofToOctets({ Abar, Bbar, D, eHat, r1Hat, r3Hat, mHat, c });
}

// ---- ProofVerify (draft §3.5.4, core §3.6.4) --------------------------------------------------

/**
 * ProofVerify(PK, proof, header, ph, disclosed_messages, disclosed_indexes) with a rejection reason.
 * `disclosed_messages[k]` must correspond to `disclosed_indexes[k]`.
 */
export function proofVerifyDetailed(
  pk: Uint8Array,
  proof: Uint8Array,
  header: Uint8Array,
  ph: Uint8Array,
  disclosedMessages: readonly Uint8Array[],
  disclosedIndexes: readonly number[],
): VerifyResult {
  let p: ParsedProof;
  try {
    p = octetsToProof(proof);
  } catch {
    return { ok: false, reason: 'malformed-proof' };
  }
  let W: G2Point;
  try {
    W = G2.fromHex(pk);
  } catch {
    return { ok: false, reason: 'malformed-public-key' };
  }
  if (W.equals(G2.ZERO)) return { ok: false, reason: 'malformed-public-key' };
  if (disclosedMessages.length !== disclosedIndexes.length) return { ok: false, reason: 'disclosed-length-mismatch' };

  const U = p.mHat.length;
  const R_count = disclosedIndexes.length;
  const L = R_count + U;

  let disclosed: { idx: number; msg: bigint }[];
  try {
    validateIndexes(disclosedIndexes, L);
    const disclosedScalars = messagesToScalars(disclosedMessages);
    disclosed = disclosedIndexes.map((idx, k) => ({ idx, msg: at(disclosedScalars, k) }));
  } catch {
    return { ok: false, reason: 'invalid-disclosed-indexes' };
  }
  disclosed.sort((a, b) => a.idx - b.idx);
  const disclosedSet = new Set(disclosed.map((d) => d.idx));
  const undisclosed = undisclosedAscending(disclosedSet, L);

  const gens = createGenerators(L + 1);
  const Q1 = at(gens, 0);
  const H = gens.slice(1);
  const domain = calculateDomain(pk, Q1, H, header);

  // T1 = B̄·c + Ā·ê + D·r̂1
  const T1 = g1mul(p.Bbar, p.c).add(g1mul(p.Abar, p.eHat)).add(g1mul(p.D, p.r1Hat));
  // Bv = P1 + Q_1·domain + Σ_{disclosed} H_i·msg_i
  let Bv = P1.add(g1mul(Q1, domain));
  for (const d of disclosed) Bv = Bv.add(g1mul(at(H, d.idx), d.msg));
  // T2 = Bv·c + D·r̂3 + Σ_{undisclosed} H_j·m̂_j
  let T2 = g1mul(Bv, p.c).add(g1mul(p.D, p.r3Hat));
  for (let k = 0; k < U; k++) T2 = T2.add(g1mul(at(H, at(undisclosed, k)), at(p.mHat, k)));

  const cv = calculateChallenge(
    p.Abar,
    p.Bbar,
    p.D,
    T1,
    T2,
    disclosed.map((d) => d.idx),
    disclosed.map((d) => d.msg),
    domain,
    ph,
  );
  if (cv !== p.c) return { ok: false, reason: 'challenge-mismatch' };

  // Final pairing: e(Ā, W) == e(B̄, BP2).
  return Fp12.eql(bls12_381.pairing(p.Abar, W), bls12_381.pairing(p.Bbar, BP2))
    ? { ok: true }
    : { ok: false, reason: 'pairing-mismatch' };
}

/** ProofVerify(PK, proof, header, ph, disclosed_messages, disclosed_indexes): true iff the proof is valid. */
export function proofVerify(
  pk: Uint8Array,
  proof: Uint8Array,
  header: Uint8Array,
  ph: Uint8Array,
  disclosedMessages: readonly Uint8Array[],
  disclosedIndexes: readonly number[],
): boolean {
  return proofVerifyDetailed(pk, proof, header, ph, disclosedMessages, disclosedIndexes).ok;
}
