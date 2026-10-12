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
const RISK_CTX_DOMAIN = utf8('atlas-pca-ratchet/risk-range/ctx/v1');
const OR_DOMAIN = utf8('atlas-pca-ratchet/budget/bit-or/v1');
const AGG_DOMAIN = utf8('atlas-pca-ratchet/budget/agg/v1');

/** Largest ceiling the N_BITS range proof can express: a slack is proven in [0, 2^N_BITS). */
export const MAX_PROVABLE_CEILING: bigint = (1n << BigInt(N_BITS)) - 1n;

/**
 * The ceiling actually proven. A ceiling above 2^N_BITS - 1 is clamped to it: "sum <= 2^N_BITS - 1" is a
 * strictly stronger statement than "sum <= bMax", so a verifier is never weakened, and an honest prover whose
 * total fits in N_BITS is never refused (before the clamp, a ceiling >= 2^N_BITS made every small total
 * unprovable because the slack no longer fit the range).
 */
function effectiveCeiling(bMaxUnits: bigint): bigint {
  return bMaxUnits > MAX_PROVABLE_CEILING ? MAX_PROVABLE_CEILING : bMaxUnits;
}

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

/** Context for the per-commitment range proof (a different domain, so it cannot be replayed as a budget proof). */
function riskContextHash(n: number, commitment: Point, bitCommitments: Point[]): Uint8Array {
  const parts: Uint8Array[] = [RISK_CTX_DOMAIN, Uint8Array.of(n & 0xff), commitment.toRawBytes()];
  for (const B of bitCommitments) parts.push(B.toRawBytes());
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
 * Shared range-proof core. Proves that the point `V = value·G + gamma·H` (known to both sides) commits to a
 * value in [0, 2^N_BITS): bit-decompose, commit to each bit, prove each is 0/1 (OR-proof), and prove by a
 * Schnorr proof that Σ 2^i·B_i − V is a pure multiple of H (so the bits aggregate to the committed value).
 * `value` is taken modulo 2^N_BITS: an out-of-range value yields a well-formed proof that the verifier rejects.
 */
function rangeProve(
  makeCtx: (bits: Point[]) => Uint8Array,
  V: Point,
  value: bigint,
  gamma: bigint,
): { bitCommitments: Point[]; or: BitOrProof[]; agg: SchnorrProof } {
  const mask = (1n << BigInt(N_BITS)) - 1n;
  const vMasked = value & mask; // low N_BITS bits (correct two's-complement low bits even if value < 0)

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

  const ctx = makeCtx(bitCommitments);

  const or: BitOrProof[] = [];
  for (let i = 0; i < N_BITS; i++) {
    or.push(proveBit(ctx, i, bitCommitments[i]!, bits[i]!, bitBlindings[i]!));
  }

  // Aggregation: Σ 2^i·B_i = v'·G + sStar·H. When v' = value (in range), D = Σ2^i·B_i − V = (sStar − gamma)·H,
  // a pure H-multiple whose dlog the prover knows.
  let sStar = 0n;
  let aggPoint: Point = mul(G, 0n);
  for (let i = 0; i < N_BITS; i++) {
    const w = 1n << BigInt(i);
    sStar = scalarAdd(sStar, scalarMul(w, bitBlindings[i]!));
    aggPoint = add(aggPoint, mul(bitCommitments[i]!, w));
  }
  const D = sub(aggPoint, V);
  const agg = proveSchnorr(ctx, D, scalarSub(sStar, gamma));
  return { bitCommitments, or, agg };
}

function rangeVerify(
  makeCtx: (bits: Point[]) => Uint8Array,
  V: Point,
  proof: { n: number; bitCommitments: string[]; or: BitOrProof[]; agg: SchnorrProof },
): boolean {
  if (proof === null || typeof proof !== 'object') return false;
  const { n, bitCommitments, or, agg } = proof;
  if (n !== N_BITS || !Array.isArray(bitCommitments) || !Array.isArray(or)) return false;
  if (bitCommitments.length !== N_BITS || or.length !== N_BITS) return false;
  if (agg === null || typeof agg !== 'object') return false;

  const B = bitCommitments.map(decodePoint);
  const ctx = makeCtx(B);
  for (let i = 0; i < N_BITS; i++) {
    if (!verifyBit(ctx, i, B[i]!, or[i]!)) return false;
  }
  let aggPoint: Point = mul(G, 0n);
  for (let i = 0; i < N_BITS; i++) aggPoint = add(aggPoint, mul(B[i]!, 1n << BigInt(i)));
  return verifySchnorr(ctx, sub(aggPoint, V), agg);
}

/**
 * Prove that the committed aggregate satisfies Σrisk ≤ bMax, in zero knowledge over the individual
 * risks. `risks`/`blindings` are the same per-action values used to build the commitments whose sum
 * is passed to {@link verifyBudget}. If the aggregate is over budget (or the slack does not fit in
 * N_BITS), the returned proof is well-formed but will be REJECTED by the verifier — soundness lives
 * in verification, not in the prover trusting its own inputs.
 *
 * SCOPE: the proof is about the committed VALUE of the sum. It does not by itself show that each addend was a
 * non-negative amount: pair it with {@link proveRiskRange} / {@link verifyBoundedBudget}, otherwise a prover can
 * offset real risk with a commitment to a "negative" value (a field element near L).
 */
export function proveBudget(risks: readonly RiskUnits[], blindings: readonly bigint[], bMax: RiskUnits): BudgetProof {
  if (risks.length !== blindings.length) {
    throw new AccumulatorError('length_mismatch', 'risks and blindings must have equal length');
  }
  const ceiling = effectiveCeiling(asUnits(bMax));
  let sumRisk = 0n;
  let sumBlind = 0n;
  for (let i = 0; i < risks.length; i++) {
    sumRisk += asUnits(risks[i] ?? 0n);
    sumBlind = scalarAdd(sumBlind, blindings[i] ?? 0n);
  }
  // Commitment sum (= what the verifier is given) and the slack commitment V = bMax·G − C_sum.
  const cSum = add(mul(G, mod(sumRisk)), mul(H, sumBlind));
  const V = sub(mul(G, mod(ceiling)), cSum);
  const slack = ceiling - sumRisk; // may be negative if over budget
  const r = rangeProve((bits) => contextHash(N_BITS, ceiling, cSum, bits), V, slack, mod(-sumBlind));
  return { n: N_BITS, bitCommitments: r.bitCommitments.map(encodePoint), or: r.or, agg: r.agg };
}

/**
 * Verify a budget proof against the commitment sum and ceiling. Returns true only if every bit
 * commitment opens to 0/1 and they aggregate to the slack commitment bMax·G − commitmentSum — i.e.
 * Σrisk ≤ bMax. Learns nothing about the individual risks. Never throws; malformed input is false.
 * Scalars and points must be canonical (a proof is not malleable). Ceilings above 2^N_BITS - 1 are clamped.
 */
export function verifyBudget(commitmentSum: string, bMax: RiskUnits, proof: BudgetProof): boolean {
  try {
    const ceiling = effectiveCeiling(asUnits(bMax));
    const cSum = decodePoint(commitmentSum);
    const V = sub(mul(G, mod(ceiling)), cSum);
    return rangeVerify((bits) => contextHash(N_BITS, ceiling, cSum, bits), V, proof);
  } catch {
    return false;
  }
}

// ---- per-commitment range proof (closes the "negative risk" gap) --------------------------

/** A proof that a single risk commitment opens to a value in [0, 2^N_BITS). Same shape as a {@link BudgetProof}. */
export type RiskRangeProof = BudgetProof;

/**
 * Prove that the commitment `commitRisk(risk, blinding)` holds a value in [0, 2^N_BITS). Each action's
 * commitment needs one of these: the budget proof alone only constrains the SUM, and since a commitment is just a
 * group element, a prover could otherwise include one that commits to a value near the group order (a
 * "negative" risk) to cancel real risk. With every addend range-proved, the integers add without wrapping.
 */
export function proveRiskRange(risk: RiskUnits, blinding: bigint): RiskRangeProof {
  const v = asUnits(risk);
  const b = mod(blinding);
  const C = add(mul(G, mod(v)), mul(H, b));
  const r = rangeProve((bits) => riskContextHash(N_BITS, C, bits), C, v, b);
  return { n: N_BITS, bitCommitments: r.bitCommitments.map(encodePoint), or: r.or, agg: r.agg };
}

/** Verify {@link proveRiskRange} for `commitment`. Never throws; malformed input is false. */
export function verifyRiskRange(commitment: string, proof: RiskRangeProof): boolean {
  try {
    const C = decodePoint(commitment);
    return rangeVerify((bits) => riskContextHash(N_BITS, C, bits), C, proof);
  } catch {
    return false;
  }
}

/**
 * The sound end-to-end check for a budget over a set of per-action commitments: every commitment must carry a
 * valid range proof, and the budget proof must verify for their homomorphic sum. Accepting implies
 * Σ(committed risks), as integers, ≤ min(bMax, 2^N_BITS − 1). Never throws.
 */
export function verifyBoundedBudget(
  commitments: readonly string[],
  rangeProofs: readonly RiskRangeProof[],
  bMax: RiskUnits,
  budgetProof: BudgetProof,
): boolean {
  try {
    if (!Array.isArray(commitments) || !Array.isArray(rangeProofs) || commitments.length !== rangeProofs.length) return false;
    for (let i = 0; i < commitments.length; i++) {
      if (!verifyRiskRange(commitments[i] as string, rangeProofs[i] as RiskRangeProof)) return false;
    }
    return verifyBudget(addCommitments(commitments), bMax, budgetProof);
  } catch {
    return false;
  }
}
