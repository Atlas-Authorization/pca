import {
  G,
  H,
  type Point,
  add,
  decodePoint,
  decodeScalar,
  encodePoint,
  encodeScalar,
  hashToScalar,
  mod,
  mul,
  numberToBytesLE,
  randScalar,
  scalarAdd,
  scalarMul,
  scalarSub,
  sub,
  utf8,
} from './group';

/**
 * Mechanism 2 — Homomorphic risk accumulator with a zero-knowledge spend ceiling.
 *
 * Risk is carried as a Pedersen commitment on ristretto255:
 *
 *   C = risk·G + blinding·H
 *
 * Commitments add homomorphically, so Σ commitments commits to (Σrisk, Σblinding). A compact
 * bit-decomposition range proof then shows the aggregate satisfies the control-theoretic budget
 * bound Σrisk ≤ bMax WITHOUT revealing the individual risks: it proves the slack
 * (bMax − Σrisk) lies in [0, 2^N) using a Fiat-Shamir OR Sigma-protocol per bit plus a Schnorr
 * proof that the bit-commitments aggregate to the slack commitment.
 *
 * Soundness rests on the hardness of discrete log between G and H (standard Pedersen binding):
 * a prover who could pass the aggregation check for an over-budget aggregate, or open a bit to a
 * value outside {0,1}, would have computed dlog_H(G).
 */

/** Range-proof bit length: the slack (bMax − Σrisk) must lie in [0, 2^32). */
export const N_BITS = 32;

export type RiskUnits = number | bigint;

export type AccumulatorErrorCode = 'invalid_value' | 'length_mismatch' | 'invalid_proof_shape';

export class AccumulatorError extends Error {
  readonly code: AccumulatorErrorCode;
  constructor(code: AccumulatorErrorCode, message: string) {
    super(message);
    this.name = 'AccumulatorError';
    this.code = code;
  }
}

export interface RiskCommitment {
  /** b64u ristretto255 point C = risk·G + blinding·H. */
  commitment: string;
  /** The blinding scalar (needed to open the commitment or to build a budget proof). */
  blinding: bigint;
}

/** A Fiat-Shamir OR proof that one bit commitment opens to 0 or 1 (challenges/responses per branch). */
export interface BitOrProof {
  e0: string;
  e1: string;
  z0: string;
  z1: string;
}

/** A Schnorr proof of knowledge of a discrete log w.r.t. H. */
export interface SchnorrProof {
  a: string;
  z: string;
}

export interface BudgetProof {
  /** Bit length of the range (= N_BITS). */
  n: number;
  /** b64u commitments to each bit of the slack value. */
  bitCommitments: string[];
  /** Per-bit OR proofs that each bit commitment opens to 0 or 1. */
  or: BitOrProof[];
  /** Schnorr proof that Σ 2^i·bitCommitment_i equals the slack commitment (bits aggregate correctly). */
  agg: SchnorrProof;
}

function asUnits(x: RiskUnits): bigint {
  if (typeof x === 'bigint') {
    if (x < 0n) throw new AccumulatorError('invalid_value', 'risk/budget must be >= 0');
    return x;
  }
  if (!Number.isInteger(x) || x < 0) {
    throw new AccumulatorError('invalid_value', 'risk/budget must be a non-negative integer');
  }
  return BigInt(x);
}

/** Commit to a non-negative integer `risk` in units, with a given or fresh random `blinding`. */
export function commitRisk(risk: RiskUnits, blinding?: bigint): RiskCommitment {
  const v = asUnits(risk);
  const b = blinding === undefined ? randScalar() : mod(blinding);
  const C = add(mul(G, v), mul(H, b));
  return { commitment: encodePoint(C), blinding: b };
}

/** Homomorphic sum: a commitment to (Σrisk, Σblinding). Empty input commits to (0, 0) = identity. */
export function addCommitments(commitments: readonly string[]): string {
  let acc = mul(G, 0n); // identity
  for (const c of commitments) acc = add(acc, decodePoint(c));
  return encodePoint(acc);
}

/** Check that `commitment` opens to (`risk`, `blinding`). Never throws; malformed input is false. */
export function openCommitment(commitment: string, risk: RiskUnits, blinding: bigint): boolean {
  try {
    const v = asUnits(risk);
    const expected = add(mul(G, v), mul(H, mod(blinding)));
    return decodePoint(commitment).equals(expected);
  } catch {
    return false;
  }
}

// ---- range proof ----------------------------------------------------------------------

const CTX_DOMAIN = utf8('atlas-pca-ratchet/budget/ctx/v1');
const OR_DOMAIN = utf8('atlas-pca-ratchet/budget/bit-or/v1');
const AGG_DOMAIN = utf8('atlas-pca-ratchet/budget/agg/v1');

/** The transcript context that binds every challenge to the exact public statement. */
function contextHash(n: number, bMaxUnits: bigint, commitmentSum: Point, bitCommitments: Point[]): Uint8Array {
  const parts: Uint8Array[] = [
    CTX_DOMAIN,
    Uint8Array.of(n & 0xff),
    numberToBytesLE(mod(bMaxUnits), 32),
    commitmentSum.toRawBytes(),
  ];
  for (const B of bitCommitments) parts.push(B.toRawBytes());
  // Reuse hashToScalar's length-prefixed framing, then serialize the scalar back to 32 bytes.
  return numberToBytesLE(hashToScalar(parts), 32);
}

/** Prove bit commitment `B` (= b·G + s·H) opens to 0 or 1, knowing bit `b` and blinding `s`. */
function proveBit(ctx: Uint8Array, index: number, B: Point, b: bigint, s: bigint): BitOrProof {
  const P0 = B; // commitment to 0 under H  => B = s·H
  const P1 = sub(B, G); // commitment to 1 => B − G = s·H
  const real = b === 1n ? 1 : 0;

  // Simulate the false branch with a random challenge/response.
  const eFake = randScalar();
  const zFake = randScalar();
  const Pfake = real === 1 ? P0 : P1;
  const aFake = sub(mul(H, zFake), mul(Pfake, eFake));

  // Real branch: honest Schnorr commitment on H.
  const k = randScalar();
  const aReal = mul(H, k);

  const a0 = real === 0 ? aReal : aFake;
  const a1 = real === 1 ? aReal : aFake;
  const e = hashToScalar([OR_DOMAIN, ctx, Uint8Array.of(index & 0xff), a0.toRawBytes(), a1.toRawBytes()]);
  const eReal = scalarSub(e, eFake);
  const zReal = scalarAdd(k, scalarMul(eReal, s));

  const e0 = real === 0 ? eReal : eFake;
  const e1 = real === 1 ? eReal : eFake;
  const z0 = real === 0 ? zReal : zFake;
  const z1 = real === 1 ? zReal : zFake;
  return { e0: encodeScalar(e0), e1: encodeScalar(e1), z0: encodeScalar(z0), z1: encodeScalar(z1) };
}

function verifyBit(ctx: Uint8Array, index: number, B: Point, proof: BitOrProof): boolean {
  const e0 = decodeScalar(proof.e0);
  const e1 = decodeScalar(proof.e1);
  const z0 = decodeScalar(proof.z0);
  const z1 = decodeScalar(proof.z1);
  const P0 = B;
  const P1 = sub(B, G);
  const a0 = sub(mul(H, z0), mul(P0, e0));
  const a1 = sub(mul(H, z1), mul(P1, e1));
  const e = hashToScalar([OR_DOMAIN, ctx, Uint8Array.of(index & 0xff), a0.toRawBytes(), a1.toRawBytes()]);
  return scalarAdd(e0, e1) === e;
}

/** Schnorr proof of knowledge of `w` with `D = w·H`. */
function proveSchnorr(ctx: Uint8Array, D: Point, w: bigint): SchnorrProof {
  const k = randScalar();
  const a = mul(H, k);
  const e = hashToScalar([AGG_DOMAIN, ctx, D.toRawBytes(), a.toRawBytes()]);
  const z = scalarAdd(k, scalarMul(e, w));
  return { a: encodePoint(a), z: encodeScalar(z) };
}

function verifySchnorr(ctx: Uint8Array, D: Point, proof: SchnorrProof): boolean {
  const a = decodePoint(proof.a);
  const z = decodeScalar(proof.z);
  const e = hashToScalar([AGG_DOMAIN, ctx, D.toRawBytes(), a.toRawBytes()]);
  return mul(H, z).equals(add(a, mul(D, e)));
}

/**
 * Prove that the committed aggregate satisfies Σrisk ≤ bMax, in zero knowledge over the individual
 * risks. `risks`/`blindings` are the same per-action values used to build the commitments whose sum
 * is passed to {@link verifyBudget}. If the aggregate is over budget (or the slack does not fit in
 * N_BITS), the returned proof is well-formed but will be REJECTED by the verifier — soundness lives
 * in verification, not in the prover trusting its own inputs.
 */
export function proveBudget(risks: readonly RiskUnits[], blindings: readonly bigint[], bMax: RiskUnits): BudgetProof {
  if (risks.length !== blindings.length) {
    throw new AccumulatorError('length_mismatch', 'risks and blindings must have equal length');
  }
  const bMaxUnits = asUnits(bMax);
  let sumRisk = 0n;
  let sumBlind = 0n;
  for (let i = 0; i < risks.length; i++) {
    sumRisk += asUnits(risks[i] ?? 0n);
    sumBlind = scalarAdd(sumBlind, blindings[i] ?? 0n);
  }
  // Commitment sum (= what the verifier is given) and the slack commitment V = bMax·G − C_sum.
  const cSum = add(mul(G, mod(sumRisk)), mul(H, sumBlind));
  const gamma = mod(-sumBlind); // blinding of V

  const v = bMaxUnits - sumRisk; // slack (may be negative if over budget)
  const mask = (1n << BigInt(N_BITS)) - 1n;
  const vMasked = v & mask; // low N_BITS bits (correct two's-complement low bits even if v < 0)

  const bitCommitments: Point[] = [];
  const bitBlindings: bigint[] = [];
  const bits: bigint[] = [];
  for (let i = 0; i < N_BITS; i++) {
    const bit = (vMasked >> BigInt(i)) & 1n;
    const s = randScalar();
    bits.push(bit);
    bitBlindings.push(s);
    bitCommitments.push(add(mul(G, bit), mul(H, s)));
  }

  const ctx = contextHash(N_BITS, bMaxUnits, cSum, bitCommitments);

  const or: BitOrProof[] = [];
  for (let i = 0; i < N_BITS; i++) {
    or.push(proveBit(ctx, i, bitCommitments[i]!, bits[i]!, bitBlindings[i]!));
  }

  // Aggregation: Σ 2^i·B_i = (Σ 2^i·b_i)·G + (Σ 2^i·s_i)·H = v'·G + sStar·H. When v' = v (in range),
  // D = Σ2^i·B_i − V = (sStar − gamma)·H, a pure H-multiple whose dlog the prover knows.
  let sStar = 0n;
  let aggPoint: Point = mul(G, 0n);
  for (let i = 0; i < N_BITS; i++) {
    const w = 1n << BigInt(i);
    sStar = scalarAdd(sStar, scalarMul(w, bitBlindings[i]!));
    aggPoint = add(aggPoint, mul(bitCommitments[i]!, w));
  }
  const V = sub(mul(G, mod(bMaxUnits)), cSum);
  const D = sub(aggPoint, V);
  const delta = scalarSub(sStar, gamma);
  const agg = proveSchnorr(ctx, D, delta);

  return { n: N_BITS, bitCommitments: bitCommitments.map(encodePoint), or, agg };
}

/**
 * Verify a budget proof against the commitment sum and ceiling. Returns true only if every bit
 * commitment opens to 0/1 and they aggregate to the slack commitment bMax·G − commitmentSum — i.e.
 * Σrisk ≤ bMax. Learns nothing about the individual risks. Never throws; malformed input is false.
 */
export function verifyBudget(commitmentSum: string, bMax: RiskUnits, proof: BudgetProof): boolean {
  try {
    if (proof === null || typeof proof !== 'object') return false;
    const { n, bitCommitments, or, agg } = proof;
    if (n !== N_BITS || !Array.isArray(bitCommitments) || !Array.isArray(or)) return false;
    if (bitCommitments.length !== N_BITS || or.length !== N_BITS) return false;
    if (agg === null || typeof agg !== 'object') return false;

    const bMaxUnits = asUnits(bMax);
    const cSum = decodePoint(commitmentSum);
    const B = bitCommitments.map(decodePoint);
    const ctx = contextHash(N_BITS, bMaxUnits, cSum, B);

    for (let i = 0; i < N_BITS; i++) {
      if (!verifyBit(ctx, i, B[i]!, or[i]!)) return false;
    }

    let aggPoint: Point = mul(G, 0n);
    for (let i = 0; i < N_BITS; i++) {
      aggPoint = add(aggPoint, mul(B[i]!, 1n << BigInt(i)));
    }
    const V = sub(mul(G, mod(bMaxUnits)), cSum);
    const D = sub(aggPoint, V);
    return verifySchnorr(ctx, D, agg);
  } catch {
    return false;
  }
}
