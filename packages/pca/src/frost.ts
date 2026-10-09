import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { utf8 } from './hash';

/**
 * FROST (Flexible Round-Optimized Schnorr Threshold) signatures for Ed25519 — RFC 9591, ciphersuite
 * FROST(Ed25519, SHA-512) ("FROST-ED25519-SHA512-v1").
 *
 * WHAT THIS IS, relative to threshold.ts
 * --------------------------------------
 * threshold.ts implements the DEFAULT t-of-n MULTI-signature: a PCActn carries a *bag* of `t`
 * independent Ed25519 signatures (agent / guardian / principal), each over `thresholdMessage(pcactn)`,
 * and the verifier counts distinct valid roles. It is simple, auditable, and needs no DKG.
 *
 * FROST is the AGGREGATION OPTIMIZATION of that idea. Instead of carrying `t` separate 64-byte shares,
 * the `t` participants interactively produce ONE ordinary 64-byte Ed25519 signature under a SINGLE
 * group public key. The group secret is Shamir-split so NO single party ever holds it; a quorum of `t`
 * shares reconstructs a signature (never the secret). The result is byte-for-byte a standard Ed25519
 * signature.
 *
 * HOW FROST PLUGS INTO PCA  (no new verifier path needed)
 * -------------------------------------------------------
 * In PCA the capability-chain LEAF names a `holder` public key, and `verifyPCActnCore` accepts the
 * action iff `pcactn.sig` is a valid Ed25519 signature over `thresholdMessage(pcactn)` under that
 * holder key (the `leaf_signature` check in pcactn.ts). FROST makes the single "signer" be the GROUP
 * public key: set the leaf `holder` to b64u(groupPublicKey) and whose shares are held by the
 * agent / guardian / principal. A FROST-aggregated `sig` is just a normal Ed25519 signature over
 * `thresholdMessage(pcactn)`, so it verifies against the group key with the EXISTING leaf-sig check —
 * there is nothing new for the verifier to learn. Where multi-sig makes the verifier count `t` shares,
 * FROST collapses them into one signature the existing M0 verifier already understands. We keep the
 * multi-signature form (threshold.ts) as the DEFAULT; FROST is the wire-size / verifier-cost
 * optimization you opt into once a DKG (or trusted-dealer) ceremony has split the group key.
 *
 * CORRECTNESS
 * -----------
 * Every scalar/point operation reuses @noble/curves edwards25519 group ops (ExtendedPoint) and the
 * scalar field order L (= ed25519.CURVE.n); SHA-512 is @noble/hashes. The hashes H1..H5, the
 * trusted-dealer key split, round 1 (commit), round 2 (sign), and aggregation are validated against
 * the official RFC 9591 Appendix test vectors in frost.test.ts — the two-of-three signing example
 * reproduces the published hiding/binding nonces, commitments, binding factors, group commitment R,
 * per-participant signature shares, and the final aggregate signature byte-exactly.
 *
 * SCOPE / SECURITY NOTE
 * ---------------------
 * This is a correct, vector-validated REFERENCE implementation of the protocol math. It is NOT
 * hardened against side channels (noble's constant-time scalar mult is used for secret base-point
 * multiplications, but the surrounding BigInt scalar arithmetic is not constant-time), and it
 * implements the trusted-dealer key split here, but a NO-DEALER interactive DKG is now available in
 * `frost-dkg.ts` (`frostDkgSimulate` / `dkgRound1`…`dkgFinalize`): its `signingShare`/`groupPublicKey`
 * output has the SAME shapes as the trusted-dealer keygen, so it is a drop-in for the group key whose
 * shares are held by the PCA agent / guardian / principal — the plug-in can split the group key by DKG
 * instead of trusting a dealer. That DKG is likewise a reference implementation needing an audit. For
 * production threshold custody, use an audited FROST library and a real DKG. PCA's DEFAULT remains the
 * multi-signature.
 */

const P = ed25519.ExtendedPoint;
/** Order of the prime-order edwards25519 scalar field. */
export const L: bigint = ed25519.CURVE.n;

/** RFC 9591 §6.1 context string for the Ed25519/SHA-512 ciphersuite. */
export const CONTEXT_STRING = 'FROST-ED25519-SHA512-v1';
const CTX = utf8(CONTEXT_STRING);

// ---- low-level scalar / point helpers (all math delegated to noble) -----------------------------

function mod(a: bigint): bigint {
  const r = a % L;
  return r >= 0n ? r : r + L;
}

/** Serialize a scalar as 32 bytes little-endian (RFC 8032 / RFC 9591 SerializeScalar for Ed25519). */
export function scalarToBytes(s: bigint): Uint8Array {
  let v = mod(s);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Parse 32-byte little-endian bytes as a scalar (reduced mod L). */
export function bytesToScalar(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]!);
  return mod(x);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

/** HashToScalar for Ed25519: OS2IP_LE(SHA-512(msg)) mod L (RFC 9591 §6.1). */
function hashToScalar(msg: Uint8Array): bigint {
  return mod(bytesToScalar(sha512(msg)));
}

/** s·B (base-point mult). 0 maps to the identity (noble's multiply rejects 0). */
function mulBase(s: bigint): InstanceType<typeof P> {
  const v = mod(s);
  return v === 0n ? P.ZERO : P.BASE.multiply(v);
}

/** s·Q (variable-base mult). 0 maps to the identity. */
function mulPoint(pt: InstanceType<typeof P>, s: bigint): InstanceType<typeof P> {
  const v = mod(s);
  return v === 0n ? P.ZERO : pt.multiply(v);
}

/**
 * Strict point decode used for EVERY point a FROST/DKG caller can influence. Rejects: wrong length,
 * non-canonical y (>= p), points not on the curve, SMALL-ORDER points (incl. the identity), and points
 * with a torsion component (not in the prime-order subgroup). A small-order / mixed-order commitment
 * would let an attacker bias R or forge a share against a cofactor-clearing verifier.
 */
export function decodeSafePoint(b: Uint8Array): InstanceType<typeof P> {
  if (!(b instanceof Uint8Array) || b.length !== 32) throw new Error('frost: point must be 32 bytes');
  const pt = P.fromHex(b); // noble's fromHex default is strict (canonical y only)
  pt.assertValidity();
  if (pt.isSmallOrder()) throw new Error('frost: small-order point rejected');
  if (!pt.isTorsionFree()) throw new Error('frost: point is not in the prime-order subgroup');
  // Canonical re-encoding must round-trip exactly.
  const re = pt.toRawBytes();
  for (let i = 0; i < 32; i++) if (re[i] !== b[i]) throw new Error('frost: non-canonical point encoding');
  return pt;
}

const decodePoint = decodeSafePoint;

/** Participant identifiers: positive safe integers (a zero id would zero every other Lagrange coefficient). */
function assertValidId(id: unknown): asserts id is number {
  if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0) {
    throw new Error('frost: participant identifier must be a positive safe integer');
  }
}

/** Validate a signing-commitment list: shape, distinct ids, safe points, and (optionally) |list| >= t. */
function validateCommitments(list: FrostCommitment[], threshold?: number): void {
  if (!Array.isArray(list) || list.length === 0) throw new Error('frost: empty commitment list');
  if (threshold !== undefined) {
    if (!Number.isSafeInteger(threshold) || threshold < 1) throw new Error('frost: invalid threshold');
    if (list.length < threshold) throw new Error(`frost: need at least t=${threshold} commitments (got ${list.length})`);
  }
  const seen = new Set<number>();
  for (const c of list) {
    if (!c || typeof c !== 'object') throw new Error('frost: malformed commitment');
    assertValidId(c.identifier);
    if (seen.has(c.identifier)) throw new Error(`frost: duplicate commitment identifier ${c.identifier}`);
    seen.add(c.identifier);
    decodeSafePoint(c.hiding);
    decodeSafePoint(c.binding);
  }
}

// ---- ciphersuite hashes H1..H5 (RFC 9591 §6.1) --------------------------------------------------

/** H1 (rho / binding factor): HashToScalar(contextString ‖ "rho" ‖ m). */
export function H1(m: Uint8Array): bigint {
  return hashToScalar(concat(CTX, utf8('rho'), m));
}

/**
 * H2 (challenge): HashToScalar(m) with NO domain separator. By design this is exactly the RFC 8032
 * Ed25519 challenge SHA-512(R ‖ A ‖ M) reduced little-endian mod L, which is what makes a FROST
 * aggregate verify as a plain Ed25519 signature.
 */
export function H2(m: Uint8Array): bigint {
  return hashToScalar(m);
}

/** H3 (nonce generation): HashToScalar(contextString ‖ "nonce" ‖ m). */
export function H3(m: Uint8Array): bigint {
  return hashToScalar(concat(CTX, utf8('nonce'), m));
}

/** H4 (message hash): SHA-512(contextString ‖ "msg" ‖ m) — returns 64 bytes. */
export function H4(m: Uint8Array): Uint8Array {
  return sha512(concat(CTX, utf8('msg'), m));
}

/** H5 (commitment-list hash): SHA-512(contextString ‖ "com" ‖ m) — returns 64 bytes. */
export function H5(m: Uint8Array): Uint8Array {
  return sha512(concat(CTX, utf8('com'), m));
}

// ---- public types -------------------------------------------------------------------------------

/** A participant identifier: a small positive integer (a nonzero scalar in the RFC). */
export type ParticipantId = number;

/** One participant's secret key share from the trusted-dealer split (plus its verification share). */
export interface FrostParticipantShare {
  identifier: ParticipantId;
  /** 32-byte little-endian secret scalar (the Shamir share f(identifier)). */
  share: Uint8Array;
  /** Verification share = share·B (32-byte point); used by frostVerifySigShare. */
  publicKey: Uint8Array;
}

export interface FrostKeygenOpts {
  /** Fixed group secret (32-byte LE scalar). Random if omitted. */
  secret?: Uint8Array;
  /** Fixed polynomial coefficients a_1..a_{t-1} (each 32-byte LE). Random if omitted. */
  coefficients?: Uint8Array[];
  /** Participant identifiers (default 1..n). Must be `n` distinct positive integers. */
  identifiers?: ParticipantId[];
}

export interface FrostKeygenResult {
  /** The single group public key (32-byte point) = secret·B = groupCommitment[0]. */
  groupPublicKey: Uint8Array;
  /** The `n` secret shares, one per participant. */
  participantShares: FrostParticipantShare[];
  /** VSS commitments [a_0·B, …, a_{t-1}·B]; index 0 is the group public key. */
  groupCommitment: Uint8Array[];
}

/** A participant's secret nonces for one signing session (never leave the participant). */
export interface FrostNonces {
  /** 32-byte LE hiding nonce scalar. */
  hiding: Uint8Array;
  /** 32-byte LE binding nonce scalar. */
  binding: Uint8Array;
}

/** A participant's PUBLIC round-1 commitment (safe to broadcast). */
export interface FrostCommitment {
  identifier: ParticipantId;
  /** hiding_nonce·B (32-byte point). */
  hiding: Uint8Array;
  /** binding_nonce·B (32-byte point). */
  binding: Uint8Array;
}

export interface FrostCommitResult {
  hidingNonce: Uint8Array;
  bindingNonce: Uint8Array;
  commitment: FrostCommitment;
}

/** Optional injected randomness for nonce generation (used to reproduce RFC vectors / for tests). */
export interface FrostCommitOpts {
  hidingRandomness?: Uint8Array;
  bindingRandomness?: Uint8Array;
}

/** A participant's round-2 signature share (a scalar). */
export interface FrostSignatureShare {
  identifier: ParticipantId;
  /** 32-byte LE scalar sig share z_i. */
  sigShare: Uint8Array;
}

// ---- trusted-dealer key generation (RFC 9591 Appendix C / §3.2 helpers) --------------------------

/**
 * Trusted-dealer t-of-n key split. Samples a degree-(t-1) polynomial f with f(0) = group secret,
 * sets participant i's share to f(i), and publishes VSS commitments to the coefficients. The group
 * public key is f(0)·B. Returns the group key, the `n` shares (with verification shares), and the
 * coefficient commitments. `opts` lets a caller inject a fixed secret / coefficients / identifiers
 * (used to reproduce the RFC vectors). Matches the RFC's trusted_dealer_keygen helper.
 */
export function frostTrustedDealerKeygen(t: number, n: number, opts: FrostKeygenOpts = {}): FrostKeygenResult {
  if (!Number.isInteger(t) || !Number.isInteger(n) || t < 1 || n < t) {
    throw new Error(`frostTrustedDealerKeygen: need 1 <= t <= n (got t=${t}, n=${n})`);
  }
  const ids = opts.identifiers ?? Array.from({ length: n }, (_, i) => i + 1);
  if (ids.length !== n) throw new Error('frostTrustedDealerKeygen: identifiers.length must equal n');
  if (new Set(ids).size !== n) throw new Error('frostTrustedDealerKeygen: identifiers must be distinct');
  if (ids.some((x) => !Number.isInteger(x) || x <= 0)) {
    throw new Error('frostTrustedDealerKeygen: identifiers must be positive integers');
  }

  // Coefficients a_0 (= secret), a_1 … a_{t-1}.
  const secret = opts.secret ? bytesToScalar(opts.secret) : bytesToScalar(ed25519.utils.randomPrivateKey());
  const coeffs: bigint[] = [secret];
  for (let i = 1; i < t; i++) {
    const c = opts.coefficients?.[i - 1];
    coeffs.push(c ? bytesToScalar(c) : bytesToScalar(ed25519.utils.randomPrivateKey()));
  }

  // f(x) = sum_j a_j x^j  (Horner).
  const evalPoly = (x: bigint): bigint => {
    let acc = 0n;
    for (let j = coeffs.length - 1; j >= 0; j--) acc = mod(acc * x + coeffs[j]!);
    return acc;
  };

  const participantShares: FrostParticipantShare[] = ids.map((id) => {
    const s = evalPoly(BigInt(id));
    return { identifier: id, share: scalarToBytes(s), publicKey: mulBase(s).toRawBytes() };
  });

  const groupCommitment = coeffs.map((a) => mulBase(a).toRawBytes());
  return { groupPublicKey: groupCommitment[0]!, participantShares, groupCommitment };
}

/**
 * The verification share for a secret signing share: PK_i = share·B (32-byte point). A FROST signing
 * share is a raw scalar (NOT an RFC-8032 clamped Ed25519 secret), so this is `mulBase` of the scalar,
 * not `publicKeyOf`. Used by custody to re-derive and check a stored verification share against its
 * (decrypted) secret share — the same derive-and-compare integrity check the single-key path does.
 */
export function frostVerifyingShare(share: Uint8Array): Uint8Array {
  return mulBase(bytesToScalar(share)).toRawBytes();
}

// ---- round 1: commit (RFC 9591 §5.1) ------------------------------------------------------------

/** nonce_generate(secret) = H3(random(32) ‖ SerializeScalar(secret)). */
function nonceGenerate(randomness: Uint8Array, secretShare: Uint8Array): bigint {
  if (randomness.length !== 32) throw new Error('frostCommit: nonce randomness must be 32 bytes');
  return H3(concat(randomness, scalarToBytes(bytesToScalar(secretShare))));
}

/**
 * Round 1. A participant generates a fresh (hiding, binding) nonce pair and the matching public
 * commitments (hiding·B, binding·B). The nonces are SECRET and must be kept for the matching round-2
 * `frostSign`; the returned `commitment` is broadcast to the coordinator. Pass `opts` to inject the
 * nonce randomness (reproducing RFC vectors); otherwise 32 fresh random bytes are used per nonce.
 */
export function frostCommit(participantShare: FrostParticipantShare, opts: FrostCommitOpts = {}): FrostCommitResult {
  const hr = opts.hidingRandomness ?? ed25519.utils.randomPrivateKey();
  const br = opts.bindingRandomness ?? ed25519.utils.randomPrivateKey();
  const hidingNonce = nonceGenerate(hr, participantShare.share);
  const bindingNonce = nonceGenerate(br, participantShare.share);
  return {
    hidingNonce: scalarToBytes(hidingNonce),
    bindingNonce: scalarToBytes(bindingNonce),
    commitment: {
      identifier: participantShare.identifier,
      hiding: mulBase(hidingNonce).toRawBytes(),
      binding: mulBase(bindingNonce).toRawBytes(),
    },
  };
}

// ---- binding factors / group commitment / challenge (RFC 9591 §4.3–§4.5) ------------------------

/** Commitment list MUST be sorted by identifier (ascending) for the hashes to be deterministic. */
function sortCommitments(list: FrostCommitment[]): FrostCommitment[] {
  return [...list].sort((a, b) => a.identifier - b.identifier);
}

/** encode_group_commitment_list: ‖ (SerializeScalar(id) ‖ hiding ‖ binding) over the sorted list. */
function encodeCommitmentList(list: FrostCommitment[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const c of list) {
    parts.push(scalarToBytes(BigInt(c.identifier)), c.hiding, c.binding);
  }
  return concat(...parts);
}

/** compute_binding_factors → Map<identifier, binding_factor scalar>. */
function computeBindingFactors(groupPublicKey: Uint8Array, list: FrostCommitment[], msg: Uint8Array): Map<ParticipantId, bigint> {
  const msgHash = H4(msg);
  const encHash = H5(encodeCommitmentList(list));
  const prefix = concat(groupPublicKey, msgHash, encHash);
  const out = new Map<ParticipantId, bigint>();
  for (const c of list) {
    out.set(c.identifier, H1(concat(prefix, scalarToBytes(BigInt(c.identifier)))));
  }
  return out;
}

/** compute_group_commitment: R = Σ (hiding_i + binding_factor_i · binding_i). */
function computeGroupCommitment(list: FrostCommitment[], bindingFactors: Map<ParticipantId, bigint>): InstanceType<typeof P> {
  let R = P.ZERO;
  for (const c of list) {
    const bf = bindingFactors.get(c.identifier)!;
    R = R.add(decodePoint(c.hiding)).add(mulPoint(decodePoint(c.binding), bf));
  }
  return R;
}

/** compute_challenge: H2(SerializeElement(R) ‖ SerializeElement(A) ‖ msg). */
function computeChallenge(R: Uint8Array, groupPublicKey: Uint8Array, msg: Uint8Array): bigint {
  return H2(concat(R, groupPublicKey, msg));
}

/** derive_interpolating_value: Lagrange coefficient λ_i for identifier `i` over `participants` at x=0. */
function deriveInterpolatingValue(participants: ParticipantId[], i: ParticipantId): bigint {
  if (!participants.includes(i)) throw new Error('frost: identifier not in participant list');
  let num = 1n;
  let den = 1n;
  const xi = BigInt(i);
  for (const j of participants) {
    if (j === i) continue;
    const xj = BigInt(j);
    num = mod(num * xj);
    den = mod(den * (xj - xi));
  }
  const lam = mod(num * modInverse(den));
  if (lam === 0n) throw new Error('frost: zero Lagrange coefficient');
  return lam;
}

function modInverse(a: bigint): bigint {
  const v = mod(a);
  if (v === 0n) throw new Error('frost: modular inverse of zero');
  // Fermat: a^(L-2) mod L (L is prime).
  return modPow(v, L - 2n);
}

function modPow(base: bigint, exp: bigint): bigint {
  let b = mod(base);
  let e = exp;
  let r = 1n;
  while (e > 0n) {
    if (e & 1n) r = mod(r * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return r;
}

// ---- round 2: sign (RFC 9591 §5.2) --------------------------------------------------------------

/**
 * Round 2. A participant produces its signature share:
 *   z_i = hiding_i + binding_i·binding_factor_i + λ_i · share_i · c
 * where c is the group challenge over the group commitment R, and λ_i is the Lagrange coefficient
 * for this participant over the signing set. `nonces` is the SECRET pair returned by this
 * participant's `frostCommit` for this session. `signingCommitments` is the full set of round-1
 * commitments from all `t` signers.
 *
 * (The RFC's `sign` takes the nonce as an explicit argument; it is required here too and placed after
 * `groupPublicKey`, matching the RFC parameter order sign(id, share, group_pk, nonce, msg, commits).)
 */
export interface FrostSignOpts {
  /** Reject a commitment set smaller than t. Strongly recommended. */
  threshold?: number;
  /** This signer's verification share (share·B). If given, it must equal share·B. */
  verificationShare?: Uint8Array;
  /**
   * Every signer's verification share. If given (and covering all signers), Σ λ_i·PK_i must equal
   * `groupPublicKey`, i.e. the group key really is the one these shares interpolate to.
   */
  verificationShares?: { identifier: ParticipantId; publicKey: Uint8Array }[];
}

/** Nonce arrays already consumed by frostSign (one-shot: reuse across two messages leaks the key share). */
const SPENT_NONCES = new WeakSet<Uint8Array>();

function isZero(b: Uint8Array): boolean {
  let acc = 0;
  for (const x of b) acc |= x;
  return acc === 0;
}

export function frostSign(
  identifier: ParticipantId,
  share: Uint8Array,
  groupPublicKey: Uint8Array,
  nonces: FrostNonces,
  message: Uint8Array,
  signingCommitments: FrostCommitment[],
  opts: FrostSignOpts = {},
): FrostSignatureShare {
  assertValidId(identifier);
  validateCommitments(signingCommitments, opts.threshold);
  decodeSafePoint(groupPublicKey);
  if (!nonces || !(nonces.hiding instanceof Uint8Array) || !(nonces.binding instanceof Uint8Array)) {
    throw new Error('frostSign: malformed nonces');
  }
  if (SPENT_NONCES.has(nonces.hiding) || SPENT_NONCES.has(nonces.binding)) {
    throw new Error('frostSign: nonces already used (one-shot; reuse would leak the signing share)');
  }
  if (isZero(nonces.hiding) || isZero(nonces.binding)) throw new Error('frostSign: zero/zeroized nonce');
  if (nonces.hiding === nonces.binding) throw new Error('frostSign: hiding and binding nonce must differ');

  const list = sortCommitments(signingCommitments);
  const mine = list.find((c) => c.identifier === identifier);
  if (!mine) throw new Error('frostSign: this identifier has no commitment in the set');

  const hiding = bytesToScalar(nonces.hiding);
  const binding = bytesToScalar(nonces.binding);
  const sk = bytesToScalar(share);
  // The signer's own published commitment must be exactly the commitment to its nonces.
  if (!mulBase(hiding).equals(decodePoint(mine.hiding)) || !mulBase(binding).equals(decodePoint(mine.binding))) {
    throw new Error('frostSign: own commitment does not match nonces');
  }
  // The share must match its verification share, and (if supplied) the group key.
  if (opts.verificationShare !== undefined) {
    if (!mulBase(sk).equals(decodePoint(opts.verificationShare))) {
      throw new Error('frostSign: share does not match verification share');
    }
  }
  const participants = list.map((c) => c.identifier);
  if (opts.verificationShares !== undefined) {
    let acc = P.ZERO;
    for (const id of participants) {
      const vs = opts.verificationShares.find((v) => v.identifier === id);
      if (!vs) throw new Error(`frostSign: missing verification share for ${id}`);
      acc = acc.add(mulPoint(decodePoint(vs.publicKey), deriveInterpolatingValue(participants, id)));
    }
    if (!acc.equals(decodePoint(groupPublicKey))) {
      throw new Error('frostSign: group public key does not match the verification shares');
    }
  }

  const bindingFactors = computeBindingFactors(groupPublicKey, list, message);
  const bf = bindingFactors.get(identifier)!;
  const R = computeGroupCommitment(list, bindingFactors);
  const lambda = deriveInterpolatingValue(participants, identifier);
  const c = computeChallenge(R.toRawBytes(), groupPublicKey, message);
  const z = mod(hiding + mod(binding * bf) + mod(mod(lambda * sk) * c));

  // One-shot: mark spent and zeroize in place so the secret nonces cannot be reused.
  SPENT_NONCES.add(nonces.hiding);
  SPENT_NONCES.add(nonces.binding);
  nonces.hiding.fill(0);
  nonces.binding.fill(0);
  return { identifier, sigShare: scalarToBytes(z) };
}

// ---- aggregation (RFC 9591 §5.3) ----------------------------------------------------------------

/**
 * Aggregate the per-participant signature shares into a STANDARD Ed25519 signature R ‖ z. The result
 * verifies under `verify(groupPublicKey, message, sig)` (RFC 9591 guarantees the aggregate is a valid
 * plain Ed25519 signature under the group key) — which is exactly PCA's existing leaf-sig check.
 * Does not itself validate the individual shares; use `frostVerifySigShare` for that (RFC §5.3).
 */
export function frostAggregate(
  message: Uint8Array,
  signingCommitments: FrostCommitment[],
  sigShares: FrostSignatureShare[],
  groupPublicKey: Uint8Array,
  opts: {
    threshold?: number;
    /** If given, every share is checked with frostVerifySigShare and a bad one is named in the error. */
    verificationShares?: { identifier: ParticipantId; publicKey: Uint8Array }[];
  } = {},
): Uint8Array {
  validateCommitments(signingCommitments, opts.threshold);
  decodeSafePoint(groupPublicKey);
  const list = sortCommitments(signingCommitments);
  if (!Array.isArray(sigShares) || sigShares.length !== list.length) {
    throw new Error('frostAggregate: need exactly one signature share per commitment');
  }
  const shareIds = new Set<number>();
  for (const s of sigShares) {
    if (!list.some((c) => c.identifier === s.identifier)) throw new Error('frostAggregate: share from non-signer');
    if (shareIds.has(s.identifier)) throw new Error('frostAggregate: duplicate signature share');
    shareIds.add(s.identifier);
  }
  if (opts.verificationShares) {
    for (const s of sigShares) {
      const vs = opts.verificationShares.find((v) => v.identifier === s.identifier);
      const commitment = list.find((c) => c.identifier === s.identifier)!;
      if (
        !vs ||
        !frostVerifySigShare({
          identifier: s.identifier,
          publicKey: vs.publicKey,
          commitment,
          sigShare: s,
          signingCommitments: list,
          groupPublicKey,
          message,
        })
      ) {
        throw new Error(`frostAggregate: invalid signature share from participant ${s.identifier}`);
      }
    }
  }
  const bindingFactors = computeBindingFactors(groupPublicKey, list, message);
  const R = computeGroupCommitment(list, bindingFactors);
  let z = 0n;
  for (const s of sigShares) z = mod(z + bytesToScalar(s.sigShare));
  const sig = concat(R.toRawBytes(), scalarToBytes(z));
  // Never return an aggregate that is not a valid signature under the group key.
  if (!ed25519.verify(sig, message, groupPublicKey, { zip215: false })) {
    throw new Error('frostAggregate: aggregate signature does not verify (a share is invalid)');
  }
  return sig;
}

/**
 * ONE-SHOT in-process signing-round coordinator (round 1 → round 2 → aggregate) over a quorum of
 * participant shares, returning the aggregate as a STANDARD Ed25519 signature under `groupPublicKey`.
 *
 * This is the "coordinator" a threshold-custody holder runs once a quorum has agreed to sign: each
 * quorum member produces its own fresh (hiding, binding) nonce pair via `frostCommit`, then its
 * signature share via `frostSign`, and the shares aggregate into a single 64-byte signature. ALL the
 * recommended safety checks are wired on by default: every share is `frostSign`-bound to its own
 * commitment and verification share, the signing set's verification shares must interpolate (Σ λ_i·PK_i)
 * to `groupPublicKey`, and `frostAggregate` re-verifies the final signature and REFUSES to return an
 * invalid aggregate — so an insufficient (< t), mismatched, or forged quorum cannot yield a valid
 * cosignature. `opts.threshold` additionally rejects a quorum smaller than `t` up front.
 *
 * SECURITY MODEL (read): this runs every participant's `frostCommit`/`frostSign` in ONE process, so it
 * is only as strong as that process is: a caller holding ALL the quorum's `share` bytes can of course
 * produce the aggregate. The threshold property "no valid signature without ≥ t independently-held
 * shares" becomes literally true ONLY when the `share` bytes live in separate trust domains (distinct
 * nodes / HSMs) and this coordinator is replaced by network round-trips that collect each remote
 * participant's commitment and signature share. See `frost-dkg.ts` for establishing the group key with
 * no trusted dealer; the per-participant `share`s it outputs are exactly the quorum members here.
 */
export function frostCosign(
  groupPublicKey: Uint8Array,
  quorum: FrostParticipantShare[],
  message: Uint8Array,
  opts: { threshold?: number } = {},
): Uint8Array {
  if (!Array.isArray(quorum) || quorum.length === 0) throw new Error('frostCosign: empty signing quorum');
  if (opts.threshold !== undefined && quorum.length < opts.threshold) {
    throw new Error(`frostCosign: quorum of ${quorum.length} is below the threshold t=${opts.threshold}`);
  }
  const ids = new Set<number>();
  for (const p of quorum) {
    assertValidId(p.identifier);
    if (ids.has(p.identifier)) throw new Error(`frostCosign: duplicate participant ${p.identifier} in quorum`);
    ids.add(p.identifier);
  }
  const vss = quorum.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
  // Round 1: each quorum member commits to a fresh nonce pair.
  const commits = quorum.map((p) => frostCommit(p));
  const commitments = commits.map((c) => c.commitment);
  // Round 2: each quorum member produces its signature share, with every safety check on.
  const sigShares = quorum.map((p, i) =>
    frostSign(
      p.identifier,
      p.share,
      groupPublicKey,
      { hiding: commits[i]!.hidingNonce, binding: commits[i]!.bindingNonce },
      message,
      commitments,
      { ...(opts.threshold !== undefined ? { threshold: opts.threshold } : {}), verificationShare: p.publicKey, verificationShares: vss },
    ),
  );
  // Aggregate (re-verifies under the group key; throws on any invalid / insufficient share set).
  return frostAggregate(message, commitments, sigShares, groupPublicKey, {
    ...(opts.threshold !== undefined ? { threshold: opts.threshold } : {}),
    verificationShares: vss,
  });
}

/**
 * Verify a single participant's signature share (RFC 9591 §5.3). Checks
 *   z_i·B == (hiding_i + binding_factor_i·binding_i) + (c · λ_i)·PK_i
 * where PK_i is the participant's verification share. Never throws — malformed inputs return false.
 */
export function frostVerifySigShare(params: {
  identifier: ParticipantId;
  /** The participant's verification share (share·B, 32-byte point). */
  publicKey: Uint8Array;
  commitment: FrostCommitment;
  sigShare: FrostSignatureShare;
  signingCommitments: FrostCommitment[];
  groupPublicKey: Uint8Array;
  message: Uint8Array;
}): boolean {
  try {
    validateCommitments(params.signingCommitments);
    const list = sortCommitments(params.signingCommitments);
    const bindingFactors = computeBindingFactors(params.groupPublicKey, list, params.message);
    const bf = bindingFactors.get(params.identifier);
    if (bf === undefined) return false;
    const R = computeGroupCommitment(list, bindingFactors);
    const commShare = decodePoint(params.commitment.hiding).add(mulPoint(decodePoint(params.commitment.binding), bf));
    const c = computeChallenge(R.toRawBytes(), params.groupPublicKey, params.message);
    const participants = list.map((x) => x.identifier);
    const lambda = deriveInterpolatingValue(participants, params.identifier);

    const lhs = mulBase(bytesToScalar(params.sigShare.sigShare));
    const rhs = commShare.add(mulPoint(decodePoint(params.publicKey), mod(c * lambda)));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}
