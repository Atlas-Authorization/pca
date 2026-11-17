/**
 * Pure evaluation: from one agent's record (and the fleet baseline) to the directives it justifies.
 * It reuses the immune system's threat read and its adaptation formula (kappa up, theta down); the only addition is a
 * cohort check against the fleet baseline. Everything here only ever asks for MORE restriction, and a record that
 * does not validate reads as the worst case.
 */
import { DEFAULT_ADAPT_CONFIG, DEFAULT_IMMUNE_CONFIG, assess, baselineStd, type AdaptConfig, type ImmuneConfig } from '@atlasauth/pca/ext/research';
import type { AgentRecord, DirectiveKind, DirectiveParams, FleetRecord } from './types';

export interface EvalConfig {
  immune: ImmuneConfig;
  adapt: AdaptConfig;
  /** Score at which each kind starts. */
  tightenAt: number;
  shrinkBudgetAt: number;
  stepUpAt: number;
  /** Score at which an agent is frozen automatically; null never freezes automatically. */
  freezeAt: number | null;
  /** The fleet baseline needs this many events before the cohort check counts. */
  minFleetEvents: number;
}

export const DEFAULT_EVAL_CONFIG: EvalConfig = {
  immune: DEFAULT_IMMUNE_CONFIG,
  adapt: DEFAULT_ADAPT_CONFIG,
  tightenAt: 0.33,
  shrinkBudgetAt: 0.5,
  stepUpAt: 0.66,
  freezeAt: 1,
  minFleetEvents: 50,
};

export interface Desire {
  kind: DirectiveKind;
  params: DirectiveParams;
}
export interface Evaluation {
  score: number;
  level: 'calm' | 'elevated' | 'high';
  signals: string[];
  desired: Desire[];
}

const clamp01 = (x: number) => Math.max(0, Math.min(1, x));
/** Round UP to a tenth: a coarser score means fewer distinct directives, and rounding up can only tighten. */
const up = (s: number) => Math.min(1, Math.ceil(s * 10 - 1e-9) / 10);

export function evaluateAgent(rec: AgentRecord, fleet: FleetRecord | undefined, cfg: EvalConfig = DEFAULT_EVAL_CONFIG): Evaluation {
  const a = assess(rec.immune, cfg.immune);
  const signals = [...a.signals];
  let score = a.score;
  if (fleet && fleet.immune.baseline.n >= cfg.minFleetEvents && rec.immune.baseline.n >= 5) {
    const fstd = baselineStd(fleet.immune.baseline);
    if (fstd > 1e-9) {
      const z = (rec.immune.ewma - fleet.immune.baseline.mean) / fstd;
      const cohort = Number.isFinite(z) ? clamp01(z / cfg.immune.driftZSat) : 1;
      if (cohort > 0.33) signals.push(`risk is ${Number.isFinite(z) ? z.toFixed(1) : 'unbounded'} fleet standard deviations above the fleet baseline`);
      score = Math.max(score, cohort);
    }
  }
  if (!Number.isFinite(score)) score = 1;
  const level = score >= 0.66 ? 'high' : score >= 0.33 ? 'elevated' : 'calm';
  const desired: Desire[] = [];
  if (score >= cfg.tightenAt) {
    const s = up(score);
    desired.push({
      kind: 'tighten',
      params: { kappa_mult: Math.round((1 + (cfg.adapt.maxKappaMult - 1) * s) * 1000) / 1000, theta_mult: Math.max(0.001, Math.floor((1 - (1 - cfg.adapt.minThetaMult) * s) * 1000) / 1000) },
    });
  }
  if (score >= cfg.shrinkBudgetAt) desired.push({ kind: 'shrink_budget', params: { factor: Math.max(0, Math.floor((1 - up(score)) * 100) / 100) } });
  if (score >= cfg.stepUpAt) desired.push({ kind: 'require_step_up', params: {} });
  if (cfg.freezeAt !== null && score >= cfg.freezeAt && level === 'high') desired.push({ kind: 'freeze', params: {} });
  return { score, level, signals, desired };
}
