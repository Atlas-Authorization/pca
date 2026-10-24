/**
 * EXACT CLOPPER–PEARSON UPPER BOUNDS, computed as the Lean definition is stated (code = definition).
 *
 * Lean (formal/intent/lean/PcaIntent/Stats.lean):
 *   cpUpper n α k = sup { q ∈ [0,1] : α < P_q(count ≤ k) }        (P_q: n i.i.d. Bernoulli(q) trials)
 *   P_q(count ≤ k) = cdfRec q n k, where                            (theorem `binCdf_eq_cdfRec`)
 *     cdfRec q 0 k     = 1
 *     cdfRec q (n+1) k = q · (k = 0 ? 0 : cdfRec q n (k−1)) + (1 − q) · cdfRec q n k.
 *   cdfRec is antitone in q (`cdfRec_antitone`), so
 *     cdfRec b n k ≤ α  ⇒  cpUpper n α k ≤ b                          (`cpUpper_le_of_cdf_le`)
 *     α < cdfRec a n k  ⇒  a ≤ cpUpper n α k                          (`le_cpUpper_of_lt_cdf`)
 *   and any U ≥ cpUpper keeps the coverage P_p(p ≤ U(count)) ≥ 1 − α  (`CP_coverage_of_ge`).
 *
 * This module evaluates cdfRec EXACTLY, in integer arithmetic, at dyadic points q = a / 2^52: with A = 2^52,
 * N_0[j] = 1 and N_{m+1}[j] = a · N_m[j−1] + (A − a) · N_m[j] (N_m[−1] = 0), cdfRec(a/A, n, k) = N_n[k] / A^n.
 * α (a double) is converted to its exact binary fraction. The comparison "α < cdfRec" is therefore exact.
 *
 * The returned bound hi is a dyadic with cdfRec(hi) ≤ α CERTIFIED exactly, so hi ≥ cpUpper (rounded outward:
 * conservative). It is tight to CP_TOLERANCE: either hi − 2^−44 < 0 or cdfRec(hi − 2^−44) > α was certified,
 * so hi − 2^−44 ≤ cpUpper. A floating-point bisection only supplies the starting guess and never decides the
 * result. The returned double equals the dyadic exactly (a ≤ 2^52, division by a power of two).
 *
 * Cost: one exact evaluation is n · min(k + 1, n) multiply-adds of a 52-bit integer into integers of up to 52·n
 * bits (linear-time BigInt operations); a call does a handful of evaluations.
 */

/** Grid: bounds are multiples of 2^−52. */
export const CP_GRID_BITS = 52;
/** Tightness: the returned bound is within 2^−44 above the exact Clopper–Pearson bound. */
export const CP_TOLERANCE = 2 ** -44;

const A = 1n << BigInt(CP_GRID_BITS);
const TOL_UNITS = 1n << BigInt(CP_GRID_BITS - 44);

function logFactorials(n: number): Float64Array {
  const lf = new Float64Array(n + 1);
  for (let i = 1; i <= n; i++) lf[i] = lf[i - 1]! + Math.log(i);
  return lf;
}

/** P(X <= k) for X ~ Binomial(n, p), in floating point (used for guesses and diagnostics, never for decisions). */
export function binomialCdf(k: number, n: number, p: number, lf: Float64Array = logFactorials(n)): number {
  if (k >= n) return 1;
  if (k < 0) return 0;
  if (p <= 0) return 1;
  if (p >= 1) return 0;
  const lp = Math.log(p);
  const lq = Math.log1p(-p);
  let s = 0;
  for (let i = 0; i <= k; i++) s += Math.exp(lf[n]! - lf[i]! - lf[n - i]! + i * lp + (n - i) * lq);
  return Math.min(1, s);
}

/** The exact binary fraction of a finite double x ∈ (0, 1): x = num / 2^e. */
export function doubleToDyadic(x: number): { num: bigint; exp: number } {
  if (!(Number.isFinite(x) && x > 0 && x < 1)) throw new Error('doubleToDyadic: need 0 < x < 1');
  let e = 0;
  let y = x;
  while (!Number.isInteger(y)) {
    y *= 2; // exact: scaling by 2 never rounds for a double in (0, 1)
    e++;
    if (e > 1100) throw new Error('doubleToDyadic: not reached'); // unreachable for finite doubles
  }
  return { num: BigInt(y), exp: e };
}

/**
 * The numerator N with cdfRec(a / 2^52, n, k) = N / 2^(52·n), by the recursion of the Lean definition.
 * Entries N_m[j] with j ≥ m equal A^m exactly (count ≤ m always), so only j < m are computed.
 */
export function cdfRecNumerator(n: number, k: number, a: bigint): bigint {
  if (a < 0n || a > A) throw new Error('cdfRecNumerator: a must be in [0, 2^52]');
  const b = A - a;
  const K = Math.min(k, n);
  // row[j] for j = 0..K at level m; level 0: all ones
  let row: bigint[] = new Array<bigint>(K + 1).fill(1n);
  let pow = 1n; // A^m
  for (let m = 0; m < n; m++) {
    const next = new Array<bigint>(K + 1);
    const powNext = pow * A;
    for (let j = 0; j <= K; j++) {
      if (j >= m + 1) {
        next[j] = powNext; // count ≤ m + 1 ≤ j always
      } else {
        const left = j === 0 ? 0n : row[j - 1]!;
        next[j] = a * left + b * row[j]!;
      }
    }
    row = next;
    pow = powNext;
  }
  return row[K]!;
}

/** Exactly decides α < cdfRec(a / 2^52, n, k). */
export function cdfExceeds(n: number, k: number, a: bigint, alpha: { num: bigint; exp: number }): boolean {
  const N = cdfRecNumerator(n, k, a);
  // N / A^n > num / 2^exp  ⇔  N · 2^exp > num · A^n
  return N * (1n << BigInt(alpha.exp)) > alpha.num * A ** BigInt(n);
}

function floatGuess(k: number, n: number, alpha: number): number {
  const lf = logFactorials(n);
  let lo = k / n;
  let hi = 1;
  for (let it = 0; it < 200 && hi - lo > 1e-13; it++) {
    const mid = (lo + hi) / 2;
    if (binomialCdf(k, n, mid, lf) > alpha) lo = mid;
    else hi = mid;
  }
  return hi;
}

export interface CPCertificate {
  /** The bound, a multiple of 2^−52 (as a double, exactly). */
  upper: number;
  /** Numerator of upper on the 2^−52 grid. */
  upperUnits: bigint;
  /** Lower end of the certified bracket: cdfRec(lowerUnits / 2^52) > α (exactly), so lowerUnits/2^52 ≤ cpUpper. */
  lowerUnits: bigint;
}

/**
 * Exact one-sided Clopper–Pearson upper bound with its certificate. With probability ≥ 1 − alpha the true rate is
 * at most `upper` (Lean `CP_coverage_of_ge`), and upper − 2^−44 ≤ cpUpper ≤ upper.
 */
export function clopperPearsonCertified(k: number, n: number, alpha: number): CPCertificate {
  if (!(Number.isInteger(k) && Number.isInteger(n) && k >= 0 && n >= 0 && k <= n)) throw new Error('clopperPearsonUpper: need integers 0 <= k <= n');
  if (!(alpha > 0 && alpha < 1)) throw new Error('clopperPearsonUpper: alpha must be in (0, 1)');
  // k = n (including n = 0): cdfRec ≡ 1 > α on [0, 1], so cpUpper = 1.
  if (n === 0 || k === n) return { upper: 1, upperUnits: A, lowerUnits: A };
  const al = doubleToDyadic(alpha);
  const exceeds = (a: bigint) => cdfExceeds(n, k, a, al);
  const clamp = (a: bigint) => (a < 0n ? 0n : a > A ? A : a);
  // start just above the floating-point guess
  let hi = clamp(BigInt(Math.ceil(floatGuess(k, n, alpha) * 2 ** CP_GRID_BITS)) + TOL_UNITS);
  // 1) certify the upper end: move up until cdfRec(hi) ≤ α (at q = 1, cdfRec = 0 for k < n)
  let step = TOL_UNITS;
  while (exceeds(hi)) {
    hi = clamp(hi + step);
    step *= 2n;
  }
  // 2) certify a lower end (cdfRec(lo) > α; at q = 0, cdfRec = 1 > α)
  let lo = clamp(hi - TOL_UNITS);
  step = TOL_UNITS;
  while (lo > 0n && !exceeds(lo)) {
    hi = lo; // lo itself is certified ≤ α: a better upper end
    lo = clamp(lo - step);
    step *= 2n;
  }
  if (lo === 0n && !exceeds(0n)) throw new Error('clopperPearsonUpper: unreachable (cdfRec(0) = 1)');
  // 3) exact bisection to the tolerance
  while (hi - lo > TOL_UNITS) {
    const mid = (lo + hi) / 2n;
    if (exceeds(mid)) lo = mid;
    else hi = mid;
  }
  return { upper: Number(hi) / 2 ** CP_GRID_BITS, upperUnits: hi, lowerUnits: lo };
}

/** Exact one-sided Clopper–Pearson upper bound (see {@link clopperPearsonCertified}). */
export function clopperPearsonUpper(k: number, n: number, alpha: number): number {
  return clopperPearsonCertified(k, n, alpha).upper;
}
