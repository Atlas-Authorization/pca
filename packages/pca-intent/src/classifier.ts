import { compareUtf8, hashCanonical } from '@atlasauth/pca';
import type { IntentLearner } from './learner';
import { encodeCell, type CatDim } from './omega';
import { clopperPearsonUpper } from './clopper';

/**
 * CLASSIFIER ERROR FOLDED INTO R̂ (Intent Layer v2 §2.7, §3.7, milestone V8; T20).
 *
 * A classifier κ maps content to a label ℓ̂ ∈ L. Its confusion matrix Γ(ℓ̂ | ℓ) = P(κ outputs ℓ̂ | true label ℓ) is
 * estimated on a labelled calibration set; Γ̄ holds per-entry Clopper-Pearson UPPER bounds at level δ_Γ / |L|², so by
 * the union bound every entry holds at once with probability >= 1 − δ_Γ [S].
 *
 * For a grant G over (x, ℓ̂) (x = the other coordinates of the cell), A_G(x) = {ℓ̂ : (x, ℓ̂) ∈ G}, and the risk in
 * TRUE coordinates is (T20, exact)
 *     R_κ(G) = Σ_{x,ℓ} μ(x,ℓ) · (1 − a(x,ℓ)) · h(x,ℓ) · Γ(A_G(x) | ℓ),   Γ(A | ℓ) = Σ_{ℓ̂∈A} Γ(ℓ̂ | ℓ).
 * The estimate R̂_κ replaces Γ by Γ̄ (capped: Γ̄(A | ℓ) = min(1, Σ Γ̄), still an upper bound of Γ(A | ℓ)) and a by p_n.
 * If G is LABEL-SOUND (a(x, ℓ̂) = 1 on G), R_κ(G) <= H_max · Σ_{(x,ℓ): a=0} μ(x,ℓ) · Γ(A_G(x) | ℓ).
 *
 * The ⊥ cell of a classifier dimension: rule 18 never yields ⊥ as a label (column ⊥ is 0), and a TRUE label outside
 * L is unknown, so its row is all ones (conservative) in R̂_κ. The γ_max gate ({@link classifierJitCells}) ranges
 * over the declared labels only.
 *
 * WHAT IS NOT CLAIMED: the bound assumes exchangeable, NON-ADAPTIVE content. An agent that searches for a mislabelled
 * input is not bounded by calibration; the benchmark reports adaptive success separately (§3.7, §11 CL).
 */

export interface ConfusionCalibration {
  /** L, sorted. */
  labels: string[];
  /** counts[t][p]: calibration examples with true label labels[t] that κ labelled labels[p]. */
  counts: number[][];
  /** Γ (maximum likelihood): counts / row total (a row with no example is all zeros). */
  gamma: number[][];
  /** Γ̄: per-entry one-sided Clopper-Pearson upper bounds at level delta / |L|² (1 for an empty row). */
  gammaBar: number[][];
  /** δ_Γ in ppm. */
  delta_ppm: number;
}

// Clopper–Pearson bounds are computed EXACTLY as the Lean definition states (binomial-tail inversion over exact
// integer arithmetic, rounded outward); see ./clopper.ts and formal/intent/lean/PcaIntent/Stats.lean.
export { binomialCdf, clopperPearsonUpper, clopperPearsonCertified, CP_GRID_BITS, CP_TOLERANCE } from './clopper';

/** Calibrate κ on labelled examples. Labels outside L are refused (a calibration set must be in L). */
export function calibrateConfusion(samples: readonly { truth: string; predicted: string }[], labels: readonly string[], deltaGamma = 0.05): ConfusionCalibration {
  const L = [...new Set(labels)].sort(compareUtf8);
  if (L.length === 0) throw new Error('calibrateConfusion: empty label set');
  if (!(deltaGamma > 0 && deltaGamma < 1)) throw new Error('calibrateConfusion: delta must be in (0, 1)');
  const ix = new Map(L.map((l, i) => [l, i] as const));
  const counts = L.map(() => L.map(() => 0));
  for (const s of samples) {
    const t = ix.get(s.truth);
    const p = ix.get(s.predicted);
    if (t === undefined || p === undefined) throw new Error(`calibrateConfusion: label outside L (${s.truth} / ${s.predicted})`);
    counts[t]![p] = counts[t]![p]! + 1;
  }
  const alpha = deltaGamma / (L.length * L.length);
  const gamma = counts.map((row) => {
    const n = row.reduce((a, b) => a + b, 0);
    return row.map((c) => (n ? c / n : 0));
  });
  const gammaBar = counts.map((row) => {
    const n = row.reduce((a, b) => a + b, 0);
    return row.map((c) => clopperPearsonUpper(c, n, alpha));
  });
  return { labels: L, counts, gamma, gammaBar, delta_ppm: Math.round(deltaGamma * 1_000_000) };
}

/** The calibration's content address (labels, counts, δ: everything Γ̄ is recomputed from), for the map. */
export function confusionDigest(c: ConfusionCalibration): string {
  return hashCanonical({ d: 'atlas-pca/intent-classifier-calibration/v1', labels: c.labels, counts: c.counts, delta_ppm: c.delta_ppm });
}

/** The published error rate shown on cards: max over true labels of Γ̄(any other label | ℓ), capped at 1. */
export function publishedErrorRate(c: ConfusionCalibration): number {
  let worst = 0;
  c.gammaBar.forEach((row, t) => {
    const e = Math.min(1, row.reduce((s, g, p) => (p === t ? s : s + g), 0));
    if (e > worst) worst = e;
  });
  return worst;
}

/** The fixed card note for a classifier dimension (§3.7): machine-labelled, with the published error rate. */
export function classifierCardNote(id: string, c: ConfusionCalibration): string {
  return `"${id}" is decided by an attested classifier, not by a person. Published error rate: up to ${(publishedErrorRate(c) * 100).toFixed(1)}%.`;
}

// ---- R_κ on explicit arrays (T20) --------------------------------------------------------------------------

/** R_κ over explicit arrays: x in [0, X), labels in [0, |L|); g[p][t] = Γ(p | t); inG[x][p] = (x, ℓ̂=p) ∈ G. */
export interface ClassifierRiskArrays {
  mu: number[][];
  a: number[][];
  h: number[][];
  inG: boolean[][];
  g: number[][];
}

const gammaOfSet = (g: number[][], A: readonly number[], t: number): number => Math.min(1, A.reduce((s, p) => s + g[p]![t]!, 0));

/** R_κ(G) (T20 decomposition): Σ_{x,ℓ} μ (1 − a) h Γ(A_G(x) | ℓ), with Γ(A | ℓ) capped at 1. */
export function classifierRisk(m: ClassifierRiskArrays): number {
  let r = 0;
  m.mu.forEach((row, x) => {
    const A = m.inG[x]!.flatMap((b, p) => (b ? [p] : []));
    row.forEach((mu, t) => {
      r += mu * (1 - m.a[x]![t]!) * m.h[x]![t]! * gammaOfSet(m.g, A, t);
    });
  });
  return r;
}

/** True iff a(x, ℓ̂) = 1 for every (x, ℓ̂) ∈ G. */
export function labelSound(m: Pick<ClassifierRiskArrays, 'a' | 'inG'>): boolean {
  return m.inG.every((row, x) => row.every((b, p) => !b || m.a[x]![p]! === 1));
}

/** T20's bound for a label-sound grant: H_max · Σ_{(x,ℓ): a=0} μ Γ(A_G(x) | ℓ). */
export function labelSoundBound(m: ClassifierRiskArrays, hMax: number): number {
  let s = 0;
  m.mu.forEach((row, x) => {
    const A = m.inG[x]!.flatMap((b, p) => (b ? [p] : []));
    row.forEach((mu, t) => {
      if (m.a[x]![t]! === 0) s += mu * gammaOfSet(m.g, A, t);
    });
  });
  return hMax * s;
}

// ---- R̂_κ from a learner over Ω̃ ----------------------------------------------------------------------------

/** One classifier dimension of Ω̃: `path` (env.class.<id>) of `verb`, with its calibration. */
export interface ClassDimSpec {
  verb: string;
  path: string;
  cal: ConfusionCalibration;
}

interface Group {
  /** class-cell index → { flat cell, p, mass, harm, inGrant } */
  members: Map<number, { cell: number[]; p: number; mass: number; harm: number; inGrant: boolean }>;
}

function groupsOf(l: IntentLearner, spec: ClassDimSpec): { dim: CatDim; k: number; groups: Map<string, Group> } {
  const vs = l.omega.verbs.find((v) => v.verb === spec.verb);
  if (!vs) throw new Error(`classifier: no verb ${spec.verb} in Ω`);
  const k = vs.dims.findIndex((d) => d.path === spec.path);
  const dim = vs.dims[k];
  if (k < 0 || !dim || dim.kind !== 'cat') throw new Error(`classifier: ${spec.verb} has no categorical dimension ${spec.path}`);
  const groups = new Map<string, Group>();
  for (const c of l.cells()) {
    if (c.verb !== spec.verb) continue;
    const xKey = c.cell.filter((_, i) => i !== k).join(',');
    let g = groups.get(xKey);
    if (!g) groups.set(xKey, (g = { members: new Map() }));
    g.members.set(c.cell[k]!, { cell: c.cell, p: c.p, mass: c.mass, harm: c.harm, inGrant: c.inGrant });
  }
  return { dim, k, groups };
}

/** Γ̄(ℓ̂ | ℓ) for dimension cells (⊥ column 0: never output; ⊥ row 1: unknown true label). */
function gbar(spec: ClassDimSpec, dim: CatDim, pred: number, truth: number): number {
  const pv = dim.values[pred]!;
  const tv = dim.values[truth]!;
  if (pv.kind !== 'exact') return 0;
  const pi = spec.cal.labels.indexOf(pv.value);
  if (pi < 0) return 0;
  const ti = tv.kind === 'exact' ? spec.cal.labels.indexOf(tv.value) : -1;
  if (ti < 0) return 1;
  return spec.cal.gammaBar[ti]![pi]!;
}

/**
 * R̂ of the learner's grant with classifier error folded in: verbs with a classifier dimension contribute R̂_κ,
 * every other verb the ordinary Σ_{c∈G} μ(1 − p)h. This is the number that replaces R̂ in the map's metrics when
 * the map has classifier dimensions; it is >= the classifier-blind R̂ whenever Γ̄ is at least the identity on the
 * diagonal.
 */
export function classifierAwareResidualRisk(l: IntentLearner, specs: readonly ClassDimSpec[]): { total: number; perVerb: Record<string, number> } {
  const perVerb = Object.create(null) as Record<string, number>; // a verb named like an Object.prototype member is an ordinary key
  const specOf = new Map(specs.map((s) => [s.verb, s] as const));
  for (const c of l.cells()) {
    if (specOf.has(c.verb)) continue;
    const prev = Object.prototype.hasOwnProperty.call(perVerb, c.verb) ? perVerb[c.verb]! : 0;
    perVerb[c.verb] = c.inGrant ? prev + c.mass * (1 - c.p) * c.harm : prev;
  }
  for (const spec of specs) {
    const { dim, groups } = groupsOf(l, spec);
    let r = 0;
    for (const g of groups.values()) {
      const A = [...g.members.entries()].filter(([, m]) => m.inGrant).map(([i]) => i);
      for (const [t, m] of g.members) r += m.mass * (1 - m.p) * m.harm * Math.min(1, A.reduce((s, p) => s + gbar(spec, dim, p, t), 0));
    }
    perVerb[spec.verb] = r;
  }
  return { total: Object.values(perVerb).reduce((s, x) => s + x, 0), perVerb };
}

/**
 * The γ_max gate (§3.7): a cell admitted on a classifier label is NOT admitted autonomously when, for some declared
 * true label ℓ the grant does not admit at the same x, Γ̄(A_G(x) | ℓ) > γ_max (the classifier would too often let a
 * bad label through as an admitted one). Those cells go to JIT consent on the rendered content. Returns them as
 * (verb, flat cell index) pairs.
 */
export function classifierJitCells(l: IntentLearner, spec: ClassDimSpec, gammaMax: number): { verb: string; cell: number[]; flat: number }[] {
  const { dim, groups } = groupsOf(l, spec);
  const vs = l.omega.verbs.find((v) => v.verb === spec.verb)!;
  const out: { verb: string; cell: number[]; flat: number }[] = [];
  for (const g of groups.values()) {
    const A = [...g.members.entries()].filter(([, m]) => m.inGrant).map(([i]) => i);
    if (A.length === 0) continue;
    const bad = [...g.members.entries()].filter(([t, m]) => !m.inGrant && dim.values[t]!.kind === 'exact').map(([t]) => t);
    const worst = bad.reduce((w, t) => Math.max(w, Math.min(1, A.reduce((s, p) => s + gbar(spec, dim, p, t), 0))), 0);
    if (worst > gammaMax) for (const p of A) {
      const cell = g.members.get(p)!.cell;
      out.push({ verb: spec.verb, cell, flat: encodeCell(vs, cell) });
    }
  }
  return out.sort((a, b) => a.flat - b.flat);
}
