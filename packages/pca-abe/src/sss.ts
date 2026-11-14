import { frAdd, frCreate, frInv, frMul, frSub, randomScalar, scalarToBytes } from './bls';

/**
 * Shamir secret sharing over the scalar field Z_r (prime r = the BLS12-381 subgroup order). This is the
 * Linear Secret-Sharing Scheme (LSSS) that realises the monotone access structure: a `t`-of-`n` gate
 * shares its secret along a degree `t-1` polynomial `f` with `f(0)` = the secret, handing child `i` the
 * evaluation `f(i)`. Fewer than `t` shares leave the secret information-theoretically undetermined; any
 * `t` (or more, consistent) shares reconstruct it by Lagrange interpolation at 0.
 */

export interface Share {
  /** Evaluation point (1-based branch index); never 0. */
  x: bigint;
  /** f(x) in Z_r. */
  y: bigint;
}

/**
 * Split `secret` into `n` shares with reconstruction threshold `t` (1 <= t <= n). Share `i` (1-based)
 * is `f(i)` for a random degree `t-1` polynomial with `f(0) = secret`.
 */
export function splitSecret(secret: bigint, t: number, n: number): Share[] {
  if (!Number.isInteger(t) || !Number.isInteger(n) || t < 1 || n < 1 || t > n) {
    throw new RangeError(`splitSecret: need 1 <= t(${t}) <= n(${n})`);
  }
  // Coefficients a_0 = secret, a_1..a_{t-1} random.
  const coeffs: bigint[] = [secret];
  for (let i = 1; i < t; i++) coeffs.push(randomScalar());
  const shares: Share[] = [];
  for (let i = 1; i <= n; i++) {
    const x = BigInt(i);
    // Horner evaluation of f(x) in Z_r.
    let acc = 0n;
    for (let d = coeffs.length - 1; d >= 0; d--) acc = frAdd(frMul(acc, x), coeffs[d] ?? 0n);
    shares.push({ x, y: acc });
  }
  return shares;
}

/**
 * Reconstruct `f(0)` by Lagrange interpolation at 0 over Z_r. Requires at least one share and distinct,
 * non-zero `x` coordinates. Given `>= t` consistent shares of a degree `t-1` sharing, this returns the
 * original secret; with duplicate x's it returns null (fail-closed).
 */
export function recoverSecret(shares: Share[]): bigint | null {
  const coeffs = lagrangeAtZero(shares.map((s) => s.x));
  if (coeffs === null) return null;
  let secret = 0n;
  for (let i = 0; i < shares.length; i++) {
    const si = shares[i];
    const ci = coeffs[i];
    if (si === undefined || ci === undefined) return null;
    secret = frAdd(secret, frMul(si.y, ci));
  }
  return secret;
}

/**
 * Lagrange coefficients `L_i(0) = prod_{j != i} x_j / (x_j - x_i)` for the evaluation points `xs`. The same
 * coefficients interpolate "in the exponent" (the reconstruction weights of the FAME decryption).
 * Null (fail-closed) on an empty set, a zero point, or points that coincide as field elements.
 */
export function lagrangeAtZero(xs: readonly bigint[]): bigint[] | null {
  if (xs.length === 0) return null;
  const seen = new Set<string>();
  for (const x of xs) {
    // Compare evaluation points as FIELD elements: x and x + r are the same point (and would make a Lagrange denominator 0).
    const xr = frCreate(x);
    if (xr === 0n) return null;
    const k = xr.toString();
    if (seen.has(k)) return null;
    seen.add(k);
  }
  const out: bigint[] = [];
  for (let i = 0; i < xs.length; i++) {
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < xs.length; j++) {
      if (j === i) continue;
      num = frMul(num, xs[j] ?? 0n);
      den = frMul(den, frSub(xs[j] ?? 0n, xs[i] ?? 0n));
    }
    out.push(frMul(num, frInv(den)));
  }
  return out;
}

/** Convenience: a fresh random secret scalar together with its 32-byte big-endian encoding. */
export function randomSecret(): { scalar: bigint; bytes: Uint8Array } {
  const scalar = randomScalar();
  return { scalar, bytes: scalarToBytes(scalar) };
}
