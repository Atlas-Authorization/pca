/**
 * DETERMINISTIC MATH (the rule every language follows). libm's log, exp, log2 and pow are not correctly rounded and differ in the last digit between
 * implementations, which moves a decision that sits on a boundary (the drift threshold, the next question, a map weight, an integer cut point). The
 * functions here use only integer arithmetic: fixed point with 96 fractional bits (a value is an integer scaled by 2^96), TRUNCATING division
 * (toward zero), and one final conversion of the integer to a double with round-to-nearest-even followed by an exact power-of-two scaling.
 *   detLn(x)   ln x    for x > 0:  x = m * 2^E, m = M / 2^52 in [1, 2) (M the 53-bit significand);  ln x = E * LN2 + 2 * atanh((M - 2^52) / (M + 2^52)),
 *              atanh summed as z + z^3/3 + z^5/5 + ... (z fixed point, z2 = (z*z)/2^96 truncated) until a term is 0;  LN2 = 2 * atanh(1/3).
 *   detLog2(x) log2 x: the same fixed value divided by LN2 in fixed point ((fixed * 2^96) / LN2, truncating): an exact power of two gives its
 *              integer exponent exactly.
 *   detExp(x)  e^x:  X = trunc(x * 2^96) (exact shift of the double's integer significand);  k = floor((X + LN2/2) / LN2) (floor division);  r = X - k * LN2;
 *              e^r = sum of r^n / n! with term_0 = 2^96, term_n = trunc(trunc(term_{n-1} * r / 2^96) / n), until a term is 0;  result = Number(sum) * 2^(k - 96)
 *              (the scaling split into two exact powers of two so that no intermediate overflows). x > 709.78 gives +Infinity, x < -745.2 gives 0, NaN gives NaN.
 *   detPowInt(b, n) b^n for an integer n >= 0: 1 multiplied by b, n times, in sequence (IEEE multiplication is exactly rounded).
 * The 2^-96 truncation error is far below a double's resolution except in the last bit, which is why the rounding steps are specified exactly.
 */
/**
 * A natural logarithm that is the same bit pattern on every platform and in every language: libm's log is not correctly rounded and differs
 * in the last digit between implementations, which moves a threshold decision that sits on the boundary. This one uses only integer arithmetic
 * (fixed point with 96 fractional bits, truncating division) and one final correctly-rounded conversion.
 *
 * ln(x) for a positive double x = m * 2^E with m in [1, 2) (m = M / 2^52, M an integer): ln(x) = E * ln2 + 2 * atanh((M - 2^52) / (M + 2^52)),
 * atanh(z) = z + z^3/3 + z^5/5 + ... summed until a term is zero; ln2 is the same series at M = 2^53 (m = 2 has z = 1/3). The fixed-point sum
 * (an integer scaled by 2^96) is converted to a double with round-to-nearest-even and divided by 2^96 (an exact power-of-two scale).
 * x = 0 (either sign) gives -Infinity and x < 0 or NaN gives NaN, as Math.log does; +Infinity gives +Infinity, x = 1 gives exactly 0. Subnormals are scaled by 2^64 first (exact).
 */
const FRAC = 96n;
const ONE = 1n << FRAC;

function atanh2(num: bigint, den: bigint): bigint {
  // 2 * atanh(z) for z = num / den, in fixed point
  const z = (num << FRAC) / den;
  const z2 = (z * z) >> FRAC;
  let term = z;
  let sum = 0n;
  for (let i = 1n; term !== 0n; i += 2n) {
    sum += term / i;
    term = (term * z2) >> FRAC;
  }
  return 2n * sum;
}

const LN2 = atanh2(1n, 3n); // ln 2 = 2 atanh(1/3)

export function detLn(x: number): number {
  if (x === 0) return Number.NEGATIVE_INFINITY; // as Math.log: a probability of 0 is a weight of 0 after detExp, never NaN
  if (!(x > 0)) return Number.NaN;
  if (x === Number.POSITIVE_INFINITY) return x;
  if (x === 1) return 0;
  let scale = 0n;
  let y = x;
  if (y < 2 ** -1022) {
    y *= 2 ** 64;
    scale = 64n;
  }
  const bits = new BigUint64Array(new Float64Array([y]).buffer)[0]!;
  const E = BigInt((bits >> 52n) & 0x7ffn) - 1023n - scale;
  const M = (bits & ((1n << 52n) - 1n)) | (1n << 52n);
  const fixed = E * LN2 + atanh2(M - (1n << 52n), M + (1n << 52n));
  return Number(fixed) / Number(ONE);
}

/** Fixed-point ln(x) (integer scaled by 2^96) of a positive finite double, or null when x is not positive and finite. */
function lnFixed(x: number): bigint | null {
  if (!(x > 0) || x === Number.POSITIVE_INFINITY) return null;
  let scale = 0n;
  let y = x;
  if (y < 2 ** -1022) {
    y *= 2 ** 64;
    scale = 64n;
  }
  const bits = new BigUint64Array(new Float64Array([y]).buffer)[0]!;
  const E = BigInt((bits >> 52n) & 0x7ffn) - 1023n - scale;
  const M = (bits & ((1n << 52n) - 1n)) | (1n << 52n);
  return E * LN2 + atanh2(M - (1n << 52n), M + (1n << 52n));
}

/** log2 x with the rule above (an exact power of two gives its exponent exactly). */
export function detLog2(x: number): number {
  if (x === 0) return Number.NEGATIVE_INFINITY; // as Math.log: a probability of 0 is a weight of 0 after detExp, never NaN
  if (!(x > 0)) return Number.NaN;
  if (x === Number.POSITIVE_INFINITY) return x;
  if (x === 1) return 0;
  const l = lnFixed(x)!;
  return Number((l << FRAC) / LN2) / Number(ONE);
}

const floorDiv = (a: bigint, b: bigint): bigint => {
  const q = a / b;
  return a % b !== 0n && a < 0n !== b < 0n ? q - 1n : q;
};

/** e^x with the rule above. */
export function detExp(x: number): number {
  if (Number.isNaN(x)) return x;
  if (x > 709.782712893384) return Number.POSITIVE_INFINITY;
  if (x < -745.2) return 0;
  if (x === 0) return 1;
  // X = trunc(x * 2^96)
  const bits = new BigUint64Array(new Float64Array([Math.abs(x)]).buffer)[0]!;
  const be = Number((bits >> 52n) & 0x7ffn);
  const frac = bits & ((1n << 52n) - 1n);
  const m = be === 0 ? frac : frac | (1n << 52n);
  const sh = (be === 0 ? 1 : be) - 1075 + 96; // |x| * 2^96 = m * 2^sh
  let X = sh >= 0 ? m << BigInt(sh) : m >> BigInt(-sh);
  if (x < 0) X = -X;
  const k = floorDiv(X + LN2 / 2n, LN2);
  const r = X - k * LN2;
  let term = ONE;
  let sum = ONE;
  for (let n = 1n; term !== 0n; n++) {
    term = (term * r) / ONE / n;
    sum += term;
  }
  const e = Number(k) - 96;
  const half = Math.trunc(e / 2);
  return Number(sum) * 2 ** half * 2 ** (e - half);
}

/** b^n for an integer n >= 0 by sequential multiplication (b * b * ... , n times, starting from 1). */
export function detPowInt(b: number, n: number): number {
  let r = 1;
  for (let i = 0; i < n; i++) r *= b;
  return r;
}
