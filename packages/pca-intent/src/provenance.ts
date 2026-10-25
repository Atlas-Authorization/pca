import type { taint } from '@atlasauth/pca';
import type { Outcome } from './omega';

/** The provenance lattice of `taint.ts`: trusted < first_party < tool < web < agent. */
export type ProvenanceLevel = taint.TaintLevel;

/**
 * PROVENANCE ON THE WALLET SIDE AND WITHIN-GRANT REGRET (Intent Layer v2 §2.8, §3.4 item 2, §3.13; milestone V7).
 *
 * The verifier classifies every material / critical parameter's provenance (`@atlasauth/pca` rule 17). The wallet
 * then (a) shows a FIXED provenance banner on the question card for a tainted value (never agent text), (b) raises
 * the friction floor for tainted critical values (typed tier, §3.4 table), and (c) accounts for WITHIN-GRANT
 * REGRET: v1's residual risk counts only outcomes the principal would reject, so injection that steers the agent to
 * an acceptable but worse option has R = 0. Regret measures it:
 *
 *     regret(ω) = max_{ω' ∈ F_t ∩ G^eff} u(ω') − u(ω)
 *
 * over the feasible options F_t at the time of the choice. u is the principal's utility, which nobody observes: the
 * benchmark plugs in a simulated principal's utility [S]. The parts of regret that can be stated become
 * acceptability constraints instead (the `excess` and `prov` dimensions of `world.ts`).
 */

export type ProvenanceFrictionTier = 'tap' | 'hold' | 'typed' | 'device';
const FRICTION_ORDER: readonly ProvenanceFrictionTier[] = ['tap', 'hold', 'typed', 'device'];

/** The fixed banner for a tainted value (null for trusted / first-party values). */
export function provenanceBanner(level: ProvenanceLevel, what = 'value'): string | null {
  switch (level) {
    case 'web':
      return `This ${what} was suggested by content on the page, not by you.`;
    case 'agent':
      return `This ${what} came from your agent, not from you or the site.`;
    case 'tool':
      return `This ${what} came from another service, not from you or this site.`;
    default:
      return null;
  }
}

/** True for the tainted levels (tool, web, agent). */
export const isTainted = (level: ProvenanceLevel): boolean => level === 'tool' || level === 'web' || level === 'agent';

/**
 * The provenance friction floor (§3.4 table, §3.13 item 4): a tainted CRITICAL value is at least `typed`; a tainted
 * material value at least `hold`; otherwise no floor (`tap`). The result is the max of `base` and the floor, so
 * provenance can only raise friction.
 */
export function provenanceFriction(base: ProvenanceFrictionTier, sensitivity: 'material' | 'critical', level: ProvenanceLevel): ProvenanceFrictionTier {
  const floor: ProvenanceFrictionTier = !isTainted(level) ? 'tap' : sensitivity === 'critical' ? 'typed' : 'hold';
  return FRICTION_ORDER[Math.max(FRICTION_ORDER.indexOf(base), FRICTION_ORDER.indexOf(floor))]!;
}

export interface RegretCase {
  /** F_t: the options feasible at the time of the choice. */
  feasible: readonly Outcome[];
  chosen: Outcome;
  /** Membership in G^eff. */
  admits: (o: Outcome) => boolean;
  /** The (simulated) principal's utility. */
  utility: (o: Outcome) => number;
}

/**
 * Within-grant regret of one choice. Only options inside G^eff compete (an option the grant denies is not a better
 * choice the agent could have made). A chosen option outside G^eff is not a regret case: it is denied (R, not regret).
 */
export function withinGrantRegret(c: RegretCase): { regret: number; best: Outcome | null; admitted: boolean } {
  const admitted = c.admits(c.chosen);
  let best: Outcome | null = null;
  let bestU = -Infinity;
  for (const o of c.feasible) {
    if (!c.admits(o)) continue;
    const u = c.utility(o);
    if (u > bestU) {
      bestU = u;
      best = o;
    }
  }
  if (!admitted || best === null) return { regret: 0, best, admitted };
  return { regret: Math.max(0, bestU - c.utility(c.chosen)), best, admitted };
}

export interface RegretReport {
  cases: number;
  /** Cases whose choice was admitted (regret is defined for them). */
  admitted: number;
  /** Admitted cases with regret > 0. */
  positive: number;
  mean: number;
  max: number;
  /** mean regret in ppm of the utility scale `scale` (the map's `metrics.regret_est_ppm`). */
  regret_est_ppm: number;
}

/** Aggregate regret over cases (benchmark INJ family, map metric `regret_est_ppm`). */
export function regretReport(cases: readonly RegretCase[], scale = 1): RegretReport {
  let admitted = 0;
  let positive = 0;
  let sum = 0;
  let max = 0;
  for (const c of cases) {
    const r = withinGrantRegret(c);
    if (!r.admitted) continue;
    admitted++;
    sum += r.regret;
    if (r.regret > 0) positive++;
    if (r.regret > max) max = r.regret;
  }
  const mean = admitted ? sum / admitted : 0;
  return { cases: cases.length, admitted, positive, mean, max, regret_est_ppm: Math.round((mean / (scale > 0 ? scale : 1)) * 1_000_000) };
}
