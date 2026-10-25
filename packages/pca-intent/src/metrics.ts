import { cellRep, cellStats, decodeCell, DEFAULT_HARM, harmOf, rng, sampleOutcome, verbCellCount, type HarmModel, type Omega, type Outcome, type VerbSpace } from './omega';
import { admitter, type PolicyInput } from './policy';
import type { IntentLearner } from './learner';

/**
 * MEASURING A GRANT AGAINST AN INTENT (spec §2.3), by Monte Carlo over ω ~ μ with the REAL PCA evaluator on
 * both sides. `acceptability` is a: Ω → [0,1]; in the benchmark it is a hidden ground-truth policy.
 *
 *   R(G) = E_μ[1_G (1 − a) h]     B(G) = E_μ[1_{¬G} a]     R_max = E_μ[(1 − a) h]     F = 1 − R/R_max
 *
 * The Hoeffding half-width for an estimate of an expectation of a quantity bounded in [0, H] from M samples
 * at confidence 1 − δ' is H·√(ln(2/δ')/(2M)) (spec T4); it is returned so every reported number carries it.
 */

export type Acceptability = (vs: VerbSpace, o: Outcome) => number;

export function acceptabilityOf(policy: PolicyInput): Acceptability {
  const a = admitter(policy);
  return (vs, o) => (a.admits(vs, o) ? 1 : 0);
}

export interface GrantMetrics {
  risk: number;
  burden: number;
  riskMax: number;
  fidelity: number;
  samples: number;
  /** Hoeffding half-width of `risk` at δ' = 0.05 (uses H_max). */
  riskHalfWidth: number;
}

export function hoeffdingHalfWidth(range: number, samples: number, deltaPrime = 0.05): number {
  return range * Math.sqrt(Math.log(2 / deltaPrime) / (2 * samples));
}

export function measureGrant(
  omega: Omega,
  grant: PolicyInput,
  acceptability: Acceptability,
  opts: { samples?: number; seed?: number; harm?: HarmModel; hMax?: number } = {},
): GrantMetrics {
  const M = opts.samples ?? 20_000;
  const harm = opts.harm ?? DEFAULT_HARM;
  const rand = rng(opts.seed ?? 1);
  const g = admitter(grant);
  let R = 0;
  let B = 0;
  let Rm = 0;
  let hMax = 0;
  for (let i = 0; i < M; i++) {
    const { vs, o } = sampleOutcome(omega, rand, harm);
    const a = acceptability(vs, o);
    const h = harmOf(vs, o, harm);
    hMax = Math.max(hMax, h);
    const inG = g.admits(vs, o);
    if (inG) R += (1 - a) * h;
    else B += a;
    Rm += (1 - a) * h;
  }
  R /= M;
  B /= M;
  Rm /= M;
  return {
    risk: R,
    burden: B,
    riskMax: Rm,
    fidelity: Rm > 0 ? 1 - R / Rm : 1,
    samples: M,
    riskHalfWidth: hoeffdingHalfWidth(opts.hMax ?? hMax, M),
  };
}

/** R̂^MC: the Monte Carlo form of the learner's residual-risk estimate (spec §2.5), for the T4 cross-check. */
export function estimateResidualRiskMC(learner: IntentLearner, opts: { samples?: number; seed?: number } = {}): number {
  const M = opts.samples ?? 20_000;
  const rand = rng(opts.seed ?? 7);
  const g = admitter(learner.synthesize());
  let R = 0;
  for (let i = 0; i < M; i++) {
    const { vs, o } = sampleOutcome(learner.omega, rand, learner.harm);
    if (g.admits(vs, o)) R += (1 - learner.acceptance(o)) * harmOf(vs, o, learner.harm);
  }
  return R / M;
}

/**
 * EXACT R, B, R_max, F by summing over the cells of Ω (no sampling error). Valid when every literal of the grant
 * and of the acceptability policy is a cut/value of Ω, so both are constant on each cell; derive Ω from both
 * policies (`deriveOmega({ policies: [grant, truth] })`) to guarantee it.
 */
export function measureGrantExact(omega: Omega, grant: PolicyInput, acceptability: Acceptability, harm: HarmModel = DEFAULT_HARM): Omit<GrantMetrics, 'samples' | 'riskHalfWidth'> & { meanHarm: number } {
  const g = admitter(grant);
  let R = 0;
  let B = 0;
  let Rm = 0;
  let Eh = 0;
  for (const vs of omega.verbs) {
    const n = verbCellCount(vs);
    for (let c = 0; c < n; c++) {
      const idx = decodeCell(vs, c);
      const o = cellRep(vs, idx);
      const { mass, harm: h } = cellStats(vs, idx, harm);
      const a = acceptability(vs, o);
      Eh += mass * h;
      Rm += mass * (1 - a) * h;
      if (g.admits(vs, o)) R += mass * (1 - a) * h;
      else B += mass * a;
    }
  }
  return { risk: R, burden: B, riskMax: Rm, fidelity: Rm > 0 ? 1 - R / Rm : 1, meanHarm: Eh };
}

/**
 * Wilson score interval for a binomial proportion k/n at confidence 1 − α (default 95%, z = 1.96). Used for every
 * catch rate the benchmark reports (spec §9, M3 exit criterion "per-layer catch rates with CIs").
 */
export function wilsonInterval(k: number, n: number, z = 1.959963984540054): { p: number; lo: number; hi: number } {
  if (!(n > 0)) return { p: NaN, lo: 0, hi: 1 };
  const p = k / n;
  const z2 = z * z;
  const den = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / den;
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / den;
  return { p, lo: Math.max(0, centre - half), hi: Math.min(1, centre + half) };
}
