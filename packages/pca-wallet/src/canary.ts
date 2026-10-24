import { cellCount, type Omega, type VerbSpace } from '@atlasauth/pca-intent';
import { betaQuantile, clopperPearsonUpper } from './stats';

/**
 * ATTENTION CANARIES (§2.5, §3.4 item 5). A canary is a question about a cell whose label the system already knows:
 *   - known NO:  a cell outside the org ceiling, or a cell the principal vetoed in this session;
 *   - known YES: a cell with an earlier verified, high-friction "yes" in this session.
 * Known-no canaries are drawn NEAR THE BOUNDARY: one cell outside the confirmed region in exactly one dimension, so a
 * canary looks like a real question. Canary answers only update the per-principal noise estimates:
 *   η⁺ ~ Beta(1 + false_yes, 9 + correct_no),   η⁻ ~ Beta(1 + false_no, 9 + correct_yes).
 *
 * T16 (canary neutrality) is structural here: nothing in this module, and nothing on the channel's canary path, can
 * reach a learner, a map or a delta. `recordCanary` takes and returns a {@link NoiseCounts} value and nothing else.
 */

export interface NoiseCounts {
  falseYes: number;
  correctNo: number;
  falseNo: number;
  correctYes: number;
}

export const EMPTY_NOISE: NoiseCounts = Object.freeze({ falseYes: 0, correctNo: 0, falseNo: 0, correctYes: 0 });

/** Fold one canary answer into the counts (pure). */
export function recordCanary(n: NoiseCounts, expected: 0 | 1, y: 0 | 1): NoiseCounts {
  if (expected === 0) return y === 1 ? { ...n, falseYes: n.falseYes + 1 } : { ...n, correctNo: n.correctNo + 1 };
  return y === 0 ? { ...n, falseNo: n.falseNo + 1 } : { ...n, correctYes: n.correctYes + 1 };
}

/** Beta prior pseudo-counts of the spec: Beta(1, 9), mean 0.1. */
export const NOISE_PRIOR = Object.freeze({ a: 1, b: 9 });

export interface NoiseEstimate {
  /** Posterior means. */
  etaPos: number;
  etaNeg: number;
  /** Posterior upper bounds at level 1 − δ_c (the η̄ the learner uses, T17). */
  etaPosUpper: number;
  etaNegUpper: number;
  /** Clopper–Pearson upper bounds from the canaries alone (no prior), 1 when there are none. */
  etaPosCP: number;
  etaNegCP: number;
  asked: number;
}

export function estimateNoise(n: NoiseCounts, deltaC = 0.05): NoiseEstimate {
  if (!(deltaC > 0 && deltaC < 1)) throw new Error('estimateNoise: deltaC must be in (0, 1)');
  const ap = NOISE_PRIOR.a + n.falseYes;
  const bp = NOISE_PRIOR.b + n.correctNo;
  const an = NOISE_PRIOR.a + n.falseNo;
  const bn = NOISE_PRIOR.b + n.correctYes;
  const knownNo = n.falseYes + n.correctNo;
  const knownYes = n.falseNo + n.correctYes;
  return {
    etaPos: ap / (ap + bp),
    etaNeg: an / (an + bn),
    etaPosUpper: betaQuantile(1 - deltaC, ap, bp),
    etaNegUpper: betaQuantile(1 - deltaC, an, bn),
    etaPosCP: knownNo === 0 ? 1 : clopperPearsonUpper(n.falseYes, knownNo, deltaC),
    etaNegCP: knownYes === 0 ? 1 : clopperPearsonUpper(n.falseNo, knownYes, deltaC),
    asked: knownNo + knownYes,
  };
}

// ---- selection ------------------------------------------------------------------------------------------------------

export interface CellAt {
  verb: string;
  idx: number[];
}

export interface CanaryChoice extends CellAt {
  expected: 0 | 1;
  source: 'ceiling' | 'veto' | 'confirmed-yes';
}

export interface CanaryContext {
  omega: Omega;
  /** Cells inside the confirmed region (in the effective grant). */
  confirmed: readonly CellAt[];
  /** Why a cell is a known no, or null when it is not one. */
  knownNo: (verb: string, idx: readonly number[]) => 'ceiling' | 'veto' | null;
  /** Cells with an earlier verified high-friction yes in this session. */
  knownYes: readonly CellAt[];
  /**
   * Cells not to use, as `verb|i,j,…` keys: cells already used as a canary in this session, and cells with a real
   * question pending. (A canary may re-ask a vetoed or confirmed cell: that is what makes its label known.)
   */
  exclude: ReadonlySet<string>;
  rand: () => number;
  /** Insertion probability ρ (default 0.1). */
  rho?: number;
  /** Low-harm sessions get at most one canary. */
  lowHarmSession: boolean;
  canariesSoFar: number;
}

export const cellKey = (verb: string, idx: readonly number[]): string => `${verb}|${idx.join(',')}`;

/** Cells one step outside the confirmed region in exactly one dimension (deterministic order). */
export function boundaryNeighbours(omega: Omega, confirmed: readonly CellAt[]): CellAt[] {
  const inside = new Set(confirmed.map((c) => cellKey(c.verb, c.idx)));
  const out = new Map<string, CellAt>();
  for (const c of confirmed) {
    const vs: VerbSpace | undefined = omega.verbs.find((v) => v.verb === c.verb);
    if (!vs) continue;
    vs.dims.forEach((d, k) => {
      const n = cellCount(d);
      const alts = d.kind === 'num' ? [c.idx[k]! - 1, c.idx[k]! + 1] : Array.from({ length: n }, (_, i) => i);
      for (const a of alts) {
        if (a < 0 || a >= n || a === c.idx[k]) continue;
        const idx = [...c.idx];
        idx[k] = a;
        const key = cellKey(c.verb, idx);
        if (!inside.has(key)) out.set(key, { verb: c.verb, idx });
      }
    });
  }
  return [...out.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, v]) => v);
}

/** Decide whether to insert a canary now, and which. Null: no canary this time. */
export function pickCanary(ctx: CanaryContext): CanaryChoice | null {
  const rho = ctx.rho ?? 0.1;
  if (!(rho >= 0 && rho <= 1)) throw new Error('pickCanary: rho must be in [0, 1]');
  if (ctx.lowHarmSession && ctx.canariesSoFar >= 1) return null;
  if (!(ctx.rand() < rho)) return null;
  const no: CanaryChoice[] = [];
  for (const c of boundaryNeighbours(ctx.omega, ctx.confirmed)) {
    if (ctx.exclude.has(cellKey(c.verb, c.idx))) continue;
    const why = ctx.knownNo(c.verb, c.idx);
    if (why) no.push({ ...c, expected: 0, source: why });
  }
  const yes: CanaryChoice[] = ctx.knownYes.filter((c) => !ctx.exclude.has(cellKey(c.verb, c.idx))).map((c) => ({ verb: c.verb, idx: [...c.idx], expected: 1 as const, source: 'confirmed-yes' as const }));
  if (no.length === 0 && yes.length === 0) return null;
  const pool = no.length > 0 && yes.length > 0 ? (ctx.rand() < 0.5 ? no : yes) : no.length > 0 ? no : yes;
  return pool[Math.min(pool.length - 1, Math.floor(ctx.rand() * pool.length))]!;
}
