import { frAdd, frInv, frMul, frSub, randomScalar, scalarToBytes } from './bls';

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
  if (shares.length === 0) return null;
  const seen = new Set<string>();
  for (const s of shares) {
    if (s.x === 0n) return null;
    const k = s.x.toString();
    if (seen.has(k)) return null;
    seen.add(k);
  }
  let secret = 0n;
  for (let i = 0; i < shares.length; i++) {
    const si = shares[i];
    if (si === undefined) return null;
    // Lagrange basis L_i(0) = prod_{j != i} x_j / (x_j - x_i).
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < shares.length; j++) {
      if (j === i) continue;
      const sj = shares[j];
      if (sj === undefined) return null;
      num = frMul(num, sj.x);
      den = frMul(den, frSub(sj.x, si.x));
    }
    const coeff = frMul(num, frInv(den));
    secret = frAdd(secret, frMul(si.y, coeff));
  }
  return secret;
}

/** Convenience: a fresh random secret scalar together with its 32-byte big-endian encoding. */
export function randomSecret(): { scalar: bigint; bytes: Uint8Array } {
  const scalar = randomScalar();
  return { scalar, bytes: scalarToBytes(scalar) };
}
