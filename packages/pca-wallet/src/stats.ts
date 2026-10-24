import { clopperPearsonUpper as exactClopperPearsonUpper } from '@atlasauth/pca-intent';

/**
 * Small numerics for the noise estimates: log-gamma (Lanczos), the regularized incomplete beta
 * function I_x(a, b) (continued fraction, modified Lentz) and its quantile by bisection (for the Bayesian Beta
 * posterior), and the Clopper–Pearson bound (delegated to the exact implementation in @atlasauth/pca-intent).
 * Deterministic: no randomness, a fixed number of bisection steps.
 */

const LANCZOS = [676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];

export function lnGamma(x: number): number {
  if (x < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * x)) - lnGamma(1 - x);
  const z = x - 1;
  let a = 0.99999999999980993;
  const t = z + 7.5;
  for (let i = 0; i < LANCZOS.length; i++) a += LANCZOS[i]! / (z + i + 1);
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(a);
}

function betacf(a: number, b: number, x: number): number {
  const TINY = 1e-300;
  const qab = a + b;
  const qap = a + 1;
  const qam = a - 1;
  let c = 1;
  let d = 1 - (qab * x) / qap;
  if (Math.abs(d) < TINY) d = TINY;
  d = 1 / d;
  let h = d;
  for (let m = 1; m <= 300; m++) {
    const m2 = 2 * m;
    let aa = (m * (b - m) * x) / ((qam + m2) * (a + m2));
    d = 1 + aa * d;
    if (Math.abs(d) < TINY) d = TINY;
    c = 1 + aa / c;
    if (Math.abs(c) < TINY) c = TINY;
    d = 1 / d;
    h *= d * c;
    aa = (-(a + m) * (qab + m) * x) / ((a + m2) * (qap + m2));
    d = 1 + aa * d;
    if (Math.abs(d) < TINY) d = TINY;
    c = 1 + aa / c;
    if (Math.abs(c) < TINY) c = TINY;
    d = 1 / d;
    const del = d * c;
    h *= del;
    if (Math.abs(del - 1) < 1e-15) break;
  }
  return h;
}

/** Regularized incomplete beta I_x(a, b), a, b > 0, x ∈ [0, 1]. */
export function betaInc(x: number, a: number, b: number): number {
  if (!(a > 0 && b > 0)) throw new Error('betaInc: a and b must be > 0');
  if (x <= 0) return 0;
  if (x >= 1) return 1;
  const lbt = lnGamma(a + b) - lnGamma(a) - lnGamma(b) + a * Math.log(x) + b * Math.log(1 - x);
  const bt = Math.exp(lbt);
  if (x < (a + 1) / (a + b + 2)) return (bt * betacf(a, b, x)) / a;
  return 1 - (bt * betacf(b, a, 1 - x)) / b;
}

/** The q-quantile of Beta(a, b): the x with I_x(a, b) = q (bisection, 200 steps: far below double precision). */
export function betaQuantile(q: number, a: number, b: number): number {
  if (!(q >= 0 && q <= 1)) throw new Error('betaQuantile: q must be in [0, 1]');
  if (q === 0) return 0;
  if (q === 1) return 1;
  let lo = 0;
  let hi = 1;
  for (let i = 0; i < 200; i++) {
    const mid = (lo + hi) / 2;
    if (betaInc(mid, a, b) < q) lo = mid;
    else hi = mid;
  }
  return hi;
}

/**
 * One-sided Clopper–Pearson upper bound on a binomial rate: P(p ≤ bound) ≥ 1 − delta, after k successes in n.
 * Computed EXACTLY as the Lean definition states (binomial-tail inversion in integer arithmetic, rounded outward to
 * within 2^−44), not via the Beta quantile: see `@atlasauth/pca-intent` clopper.ts and
 * formal/intent/lean/PcaIntent/Stats.lean (`CP_coverage_of_ge`).
 */
export function clopperPearsonUpper(k: number, n: number, delta: number): number {
  return exactClopperPearsonUpper(k, n, delta);
}

/** Binary entropy in bits. */
export function binEnt(p: number): number {
  if (p <= 0 || p >= 1) return 0;
  return -(p * Math.log2(p) + (1 - p) * Math.log2(1 - p));
}
