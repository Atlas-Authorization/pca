import type { PlanNode } from './merkle';

/**
 * Risk functional + threshold map + decaying trust budget (spec §10, L3, Deep Dive III).
 * Pure and deterministic. Time is epoch milliseconds; `lambda` is budget drained PER SECOND.
 * Non-finite inputs fail closed (treated as worst case).
 */

export interface RiskWeights {
  alpha: number; // semantic distance
  beta: number; // irreversibility
  gamma: number; // blast radius
  delta: number; // taint
  epsilon: number; // agent uncertainty
  zeta: number; // age since human touch
}

export interface RiskPolicy {
  weights: RiskWeights;
  theta1: number;
  theta2: number;
  /** cost scale: c(A) = kappa * r(A) */
  kappa: number;
  /** passive leak, budget units per second */
  lambda: number;
  /** recharge per human co-sign */
  rho: number;
  bMax: number;
}

/** All normalized to [0,1]. */
export interface RiskInputs {
  semanticDistance: number;
  reversibility: number;
  blastRadius: number;
  taint: number;
  confidence: number;
  age: number;
}

export const DEFAULT_RISK_POLICY: RiskPolicy = {
  weights: { alpha: 0.25, beta: 0.2, gamma: 0.2, delta: 0.2, epsilon: 0.1, zeta: 0.05 },
  theta1: 0.25,
  theta2: 0.6,
  kappa: 1,
  lambda: 0.0005,
  rho: 0.5,
  bMax: 1,
};

/** Returns an error string if the policy is not well-formed, else null. */
export function validateRiskPolicy(p: unknown): string | null {
  if (p === null || typeof p !== 'object') return 'risk_policy must be an object';
  const r = p as Partial<RiskPolicy>;
  const w = r.weights as Partial<RiskWeights> | undefined;
  if (!w || typeof w !== 'object') return 'risk_policy.weights missing';
  for (const k of ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta'] as const) {
    if (!Number.isFinite(w[k]) || (w[k] as number) < 0) return `risk_policy.weights.${k} must be finite and >= 0`;
  }
  for (const k of ['theta1', 'theta2', 'kappa', 'lambda', 'rho', 'bMax'] as const) {
    if (!Number.isFinite(r[k])) return `risk_policy.${k} must be finite`;
  }
  if ((r.theta1 as number) < 0 || (r.theta2 as number) < (r.theta1 as number)) return 'risk_policy requires 0 <= theta1 <= theta2';
  if ((r.kappa as number) <= 0) return 'risk_policy.kappa must be > 0';
  if ((r.lambda as number) < 0 || (r.rho as number) < 0 || (r.bMax as number) < 0) return 'risk_policy lambda/rho/bMax must be >= 0';
  return null;
}

const clamp01 = (x: number) => (x < 0 ? 0 : x > 1 ? 1 : x);
/** non-finite => worst; else clamp to [0,1]. `worst` is 1 for risk-increasing inputs, 0 for rev/conf. */
const unit = (x: number, worst: 0 | 1) => (Number.isFinite(x) ? clamp01(x) : worst);
const wt = (x: number) => (Number.isFinite(x) && x > 0 ? x : 0);

/**
 * r = clamp( a·d + b·(1−rev) + g·bl + d·taint + e·(1−conf) + z·age, 0, 1 ).
 * Monotone non-decreasing in d, bl, taint, age and non-increasing in rev, conf (weights are
 * clamped to >= 0, which is what makes that hold for any policy).
 */
export function riskScore(i: RiskInputs, w: RiskWeights): number {
  const r =
    wt(w.alpha) * unit(i.semanticDistance, 1) +
    wt(w.beta) * (1 - unit(i.reversibility, 0)) +
    wt(w.gamma) * unit(i.blastRadius, 1) +
    wt(w.delta) * unit(i.taint, 1) +
    wt(w.epsilon) * (1 - unit(i.confidence, 0)) +
    wt(w.zeta) * unit(i.age, 1);
  return clamp01(r);
}

export interface RequiredThreshold {
  t: 1 | 2 | 3;
  proof: 'claim' | 'standard' | 'strong';
  optimisticAllowed: boolean;
}

/**
 * §10 piecewise map. r <= θ1 -> t=1 (claim, optimistic ok); θ1 < r <= θ2 -> t=2 (standard);
 * r > θ2 -> t=3 (strong). Optimistic acceptance is only ever allowed at t=1 and never for an
 * irreversible action (`opts.irreversible`). Monotone non-decreasing in r. NaN r => worst.
 */
export function requiredThreshold(
  r: number,
  p: Pick<RiskPolicy, 'theta1' | 'theta2'>,
  opts: { irreversible?: boolean } = {},
): RequiredThreshold {
  const x = Number.isFinite(r) ? r : 1;
  if (x <= p.theta1) return { t: 1, proof: 'claim', optimisticAllowed: !opts.irreversible };
  if (x <= p.theta2) return { t: 2, proof: 'standard', optimisticAllowed: false };
  return { t: 3, proof: 'strong', optimisticAllowed: false };
}

const PROOF_FOR_T = { 1: 'claim', 2: 'standard', 3: 'strong' } as const;
const PROOF_RANK = { claim: 0, standard: 1, strong: 2 } as const;

/**
 * Raise a RequiredThreshold to at least `minT` and keep it coherent: t=2 => proof >= 'standard',
 * t=3 => 'strong', and optimistic acceptance is never allowed when t > 1. Never lowers anything.
 */
export function escalateThreshold(rt: RequiredThreshold, minT: 1 | 2 | 3): RequiredThreshold {
  const t = (minT > rt.t ? minT : rt.t) as 1 | 2 | 3;
  const floor = PROOF_FOR_T[t];
  const proof = PROOF_RANK[rt.proof] >= PROOF_RANK[floor] ? rt.proof : floor;
  return { t, proof, optimisticAllowed: t > 1 ? false : rt.optimisticAllowed };
}

// ---- trust budget ----------------------------------------------------------------------

export interface TrustBudget {
  /** current budget in [0, bMax] */
  B: number;
  /** last human-touch time (ms) */
  tau: number;
  /** time (ms) the budget was last brought up to date by leak(); defaults to tau. Prevents double-leaking. */
  asOf?: number;
}

const nz = (x: number) => (Number.isFinite(x) && x > 0 ? x : 0);

/** c(A) = κ·r(A). Non-finite r => cost of r=1. */
export function cost(r: number, kappa: number): number {
  return nz(kappa) * clamp01(Number.isFinite(r) ? r : 1);
}

/** Passive leak dB/dt = −λ since the last update. Idempotent for repeated calls at the same `now`. */
export function leak(b: TrustBudget, now: number, lambda: number): TrustBudget {
  const from = b.asOf ?? b.tau;
  const dt = Number.isFinite(now) && Number.isFinite(from) ? Math.max(0, now - from) : 0;
  const B = Math.max(0, b.B - nz(lambda) * (dt / 1000));
  return { B, tau: b.tau, asOf: Number.isFinite(now) ? Math.max(now, from) : from };
}

/** B ← max(0, B − cost). Callers must check B >= cost first (admit() does). */
export function debit(b: TrustBudget, c: number): TrustBudget {
  return { ...b, B: Math.max(0, b.B - nz(c)) };
}

/** Human co-sign recharge: B ← min(bMax, B+ρ), τ ← now. The ONLY way budget increases. */
export function recharge(b: TrustBudget, rho: number, bMax: number, now: number): TrustBudget {
  return { B: Math.min(nz(bMax), b.B + nz(rho)), tau: now, asOf: now };
}

/** Full goal re-confirmation: B ← bMax, τ ← now. */
export function rechargeFull(b: TrustBudget, bMax: number, now: number): TrustBudget {
  void b;
  return { B: nz(bMax), tau: now, asOf: now };
}

/** Normalized age since the last human touch: clamp((now − τ)/horizonMs, 0, 1). */
export function ageSinceTouch(b: TrustBudget, now: number, horizonMs = 3_600_000): number {
  if (!Number.isFinite(now) || !Number.isFinite(b.tau) || !(horizonMs > 0)) return 1;
  return clamp01((now - b.tau) / horizonMs);
}

export interface Admission {
  /** t=1 auto path: no human, no co-signer needed. */
  admit: boolean;
  needStepUp: boolean;
  t: 1 | 2 | 3;
  /**
   * The action proceeds WITHOUT a human co-signature (t=1 auto-admit, or t=2 where the guardian
   * auto-cosigns) and so MUST be debited κ·r. Only t=3 (a human step-up) is unmetered.
   */
  metered: boolean;
}

/**
 * The machine-only band is t=1 AND t=2 (at t=2 the guardian auto-cosigns; no human is involved), so
 * BOTH are metered: an action at t<3 proceeds only if B >= c(A), and is then debited κ·r. When the
 * budget cannot cover it the action escalates to t=3 (human step-up; the recharge is human-sourced).
 * t=3 is never debited. The budget passed in must already be leaked up to the decision time (and,
 * on the hosted path, read under a row lock so the check-and-debit is atomic).
 */
export function admit(r: number, b: TrustBudget, p: RiskPolicy): Admission {
  const { t } = requiredThreshold(r, p);
  const c = cost(r, p.kappa);
  if (t < 3 && !(b.B >= c)) return { admit: false, needStepUp: true, t: 3, metered: false };
  if (t === 1) return { admit: true, needStepUp: false, t: 1, metered: true };
  if (t === 2) return { admit: false, needStepUp: true, t: 2, metered: true };
  return { admit: false, needStepUp: true, t: 3, metered: false };
}

/**
 * Safety bound: between two consecutive human recharges, the total risk of machine-only actions
 * (auto-admitted t=1 AND guardian-auto-cosigned t=2) is at most bMax/κ.
 *
 * Proof. Let B₀ ≤ bMax be the budget right after a recharge. Machine-only admission of action i requires
 * Bᵢ ≥ cᵢ = κ·rᵢ and sets Bᵢ₊₁ = Bᵢ − cᵢ ≥ 0; leak only lowers B further and nothing but a human
 * recharge raises it. Telescoping: Σcᵢ ≤ B₀ − B_last ≤ B₀ ≤ bMax, so κ·Σrᵢ ≤ bMax, i.e.
 * Σrᵢ ≤ bMax/κ — whatever the agent does, even if fully compromised.
 */
export function safetyBound(p: Pick<RiskPolicy, 'bMax' | 'kappa'>): number {
  return p.kappa > 0 ? Math.max(0, p.bMax) / p.kappa : 0;
}

// ---- multi-agent budget algebra -------------------------------------------------------

export type SubBudgetResult = { ok: true; sub: TrustBudget } | { ok: false; reason: string };

/** Allocate a sub-agent budget B_sub = alloc, guarded by 0 <= alloc <= parent.B (parent remaining). */
export function subBudget(parent: TrustBudget, alloc: number): SubBudgetResult {
  if (!Number.isFinite(alloc) || alloc < 0) return { ok: false, reason: 'allocation must be finite and >= 0' };
  if (alloc > parent.B) return { ok: false, reason: 'allocation exceeds parent remaining budget' };
  return { ok: true, sub: { B: alloc, tau: parent.tau, asOf: parent.asOf ?? parent.tau } };
}

export type ConsolidatedResult =
  | { ok: true; parent: TrustBudget; sub: TrustBudget }
  | { ok: false; reason: string };

/**
 * Consolidated debit: a sub-agent's debit ALSO debits the parent, so a swarm of sub-agents
 * collectively cannot spend more than the parent's remaining budget (the capability chain is the
 * budget tree). Fails (no state change) if either the sub or the parent cannot cover `c`.
 */
export function debitConsolidated(parent: TrustBudget, sub: TrustBudget, c: number): ConsolidatedResult {
  const x = nz(c);
  if (sub.B < x) return { ok: false, reason: 'sub-agent budget insufficient' };
  if (parent.B < x) return { ok: false, reason: 'parent budget insufficient' };
  return { ok: true, parent: debit(parent, x), sub: debit(sub, x) };
}

export type ConsolidatedPathResult = { ok: true; nodes: TrustBudget[] } | { ok: false; reason: string };

/**
 * Consolidated debit along a root->leaf budget-subtree PATH, generalizing {@link debitConsolidated} to
 * N levels. Every node on the path — the acting leaf AND each of its ancestors — must be able to cover
 * `c`; if ANY cannot, nothing is debited (fail-closed) and the first offender is named. Only when all
 * cover is each node debited by `c`. This is what makes a sub-agent's spend consume its own carried
 * allocation and every ancestor allocation at once, so a swarm under any node can never collectively
 * exceed that node's allocation (the per-child containment property). `path` ordered root..leaf.
 */
export function debitConsolidatedPath(path: TrustBudget[], c: number): ConsolidatedPathResult {
  const x = nz(c);
  for (let i = 0; i < path.length; i++) {
    if (!(path[i]!.B >= x)) return { ok: false, reason: `budget node at depth ${i} insufficient (need ${x}, have ${path[i]!.B})` };
  }
  return { ok: true, nodes: path.map((b) => debit(b, x)) };
}

// ---- plan geodesic ---------------------------------------------------------------------

const PRE_KEYS = ['after', 'depends_on', 'requires', 'nodes'];
const POST_KEYS = ['before', 'enables', 'then', 'next'];

function refsOf(x: unknown, keys: string[]): string[] {
  const out: string[] = [];
  const add = (v: unknown) => {
    if (typeof v === 'string') out.push(v);
    else if (Array.isArray(v)) for (const s of v) if (typeof s === 'string') out.push(s);
  };
  add(x);
  if (x !== null && typeof x === 'object' && !Array.isArray(x)) {
    for (const k of keys) add((x as Record<string, unknown>)[k]);
  }
  return out;
}

/**
 * Normalized geodesic distance in the committed plan DAG, in [0,1] (APPROXIMATION, documented):
 *  - Edges come from node references: ids named in `pre` (bare id/array, or under `after` /
 *    `depends_on` / `requires` / `nodes`) are predecessors; ids named in `post` (under `before` /
 *    `enables` / `then` / `next`) are successors. Only ids that exist in the plan count.
 *  - Distance is BFS hop count over the UNDIRECTED graph (an action "behind" the goal is as far
 *    from intent as one "ahead"), divided by (n−1) so it lies in [0,1]. Unreachable => 1.
 *  - If the plan declares no edges at all, falls back to index distance |i−j|/(n−1).
 *  - Unknown node id => 1 (fail closed). Same node => 0.
 * It is a deterministic, verifier-recomputable proxy; embedding distance is never used to gate.
 */
export function planGeodesic(plan: PlanNode[], fromNodeId: string, toGoalNodeId: string): number {
  if (!Array.isArray(plan)) return 1;
  const idx = new Map<string, number>();
  plan.forEach((n, i) => idx.set(n.id, i));
  const a = idx.get(fromNodeId);
  const b = idx.get(toGoalNodeId);
  if (a === undefined || b === undefined) return 1;
  if (a === b) return 0;
  const n = plan.length;
  const adj: Set<number>[] = plan.map(() => new Set<number>());
  let edges = 0;
  const link = (i: number, j: number) => {
    if (i === j) return;
    if (!adj[i]!.has(j)) edges++;
    adj[i]!.add(j);
    adj[j]!.add(i);
  };
  plan.forEach((node, i) => {
    for (const id of refsOf(node.pre, PRE_KEYS)) {
      const j = idx.get(id);
      if (j !== undefined) link(j, i);
    }
    for (const id of refsOf(node.post, POST_KEYS)) {
      const j = idx.get(id);
      if (j !== undefined) link(i, j);
    }
  });
  if (edges === 0) return clamp01(Math.abs(a - b) / (n - 1));
  const dist = new Array<number>(n).fill(-1);
  dist[a] = 0;
  const q = [a];
  for (let h = 0; h < q.length; h++) {
    const u = q[h]!;
    for (const v of [...adj[u]!].sort((x, y) => x - y)) {
      if (dist[v] === -1) {
        dist[v] = dist[u]! + 1;
        q.push(v);
      }
    }
  }
  return dist[b]! < 0 ? 1 : clamp01(dist[b]! / (n - 1));
}
