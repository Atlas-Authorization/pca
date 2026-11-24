/**
 * dagExposure: what a committed workflow (DAG) can EVER do, decided statically from its body (K5; analysis tooling, outside the
 * trusted core). Deterministic, total, no heuristics: every number is a function of the declared steps, edges and budget.
 *
 *  - `maxSteps`          the most steps one run can execute: min(steps, budget.max_steps)
 *  - `depth`             the longest dependency chain (steps)
 *  - `levelWidth`        the widest topological level (a lower bound on parallelism)
 *  - `paths`             the number of maximal source-to-leaf paths (capped; `pathsCapped` says so)
 *  - `cost`              per cap: the cap, the sum over all steps and the most one run can spend (min of the two)
 *  - `neverRunnable`     steps no run can reach: a step costing more than a cap alone, or needing more steps (itself plus all its
 *                        ancestors) than `max_steps`
 *  - `sinks`             each step with a sink, the steps whose outputs can reach it through edges (`lineage`), and whether any
 *                        label protection exists (`protected`: the step's deny/escalate labels, or an incoming edge's deny labels)
 *  - `unprotectedSinks`  the sinks with lineage and no protection: data can flow to them with nothing checking its label
 *  - `orderingOnly`      steps with dependencies but no edge into them: no dataflow constraint binds their inputs
 *  - `pipelinable`       edge indexes that may be admitted before their source has run (declared promises)
 */
import type { WorkflowBody } from '@atlasauth/pca';

const PATH_CAP = 1_000_000;

export interface DagExposure {
  steps: number;
  maxSteps: number;
  depth: number;
  levelWidth: number;
  paths: number;
  pathsCapped: boolean;
  cost: Record<string, { cap: number; total: number; maxSpend: number }>;
  neverRunnable: { step: string; reason: 'cost_over_cap' | 'needs_more_steps_than_budget' }[];
  sinks: { step: string; sink: string; lineage: string[]; protected: boolean }[];
  unprotectedSinks: string[];
  orderingOnly: string[];
  pipelinable: number[];
}

/** Throws a RangeError on a body that is not a DAG (the commitment would not verify either). */
export function dagExposure(b: WorkflowBody): DagExposure {
  const byId = new Map(b.steps.map((s) => [s.id, s] as const));
  if (byId.size !== b.steps.length) throw new RangeError('dagExposure: duplicate step id');
  const level = new Map<string, number>();
  const anc = new Map<string, Set<string>>();
  const visiting = new Set<string>();
  const visit = (id: string): void => {
    if (level.has(id)) return;
    if (visiting.has(id)) throw new RangeError('dagExposure: cycle');
    visiting.add(id);
    const s = byId.get(id);
    if (s === undefined) throw new RangeError(`dagExposure: unknown step ${id}`);
    const a = new Set<string>();
    let l = 0;
    for (const d of s.deps) {
      visit(d);
      a.add(d);
      for (const x of anc.get(d) as Set<string>) a.add(x);
      l = Math.max(l, (level.get(d) as number) + 1);
    }
    visiting.delete(id);
    anc.set(id, a);
    level.set(id, l);
  };
  for (const s of b.steps) visit(s.id);
  const depth = Math.max(0, ...[...level.values()]) + 1;
  const widths = new Map<number, number>();
  for (const l of level.values()) widths.set(l, (widths.get(l) ?? 0) + 1);
  const levelWidth = Math.max(...widths.values());

  // maximal paths: number of paths from a source to each step, summed over leaves
  const children = new Map<string, string[]>(b.steps.map((s) => [s.id, []]));
  for (const s of b.steps) for (const d of s.deps) (children.get(d) as string[]).push(s.id);
  const memo = new Map<string, number>();
  let capped = false;
  const toLeaves = (id: string): number => {
    const m = memo.get(id);
    if (m !== undefined) return m;
    const kids = children.get(id) as string[];
    let n = kids.length === 0 ? 1 : 0;
    for (const k of kids) n += toLeaves(k);
    if (n > PATH_CAP) {
      n = PATH_CAP;
      capped = true;
    }
    memo.set(id, n);
    return n;
  };
  let paths = 0;
  for (const s of b.steps) if (s.deps.length === 0) paths = Math.min(PATH_CAP, paths + toLeaves(s.id));

  const cost: DagExposure['cost'] = {};
  for (const [name, cap] of Object.entries(b.budget.caps)) {
    const total = b.steps.reduce((a, s) => a + (s.cost[name] ?? 0), 0);
    cost[name] = { cap, total, maxSpend: Math.min(cap, total) };
  }
  const neverRunnable: DagExposure['neverRunnable'] = [];
  for (const s of b.steps) {
    if (Object.entries(s.cost).some(([n, c]) => c > (b.budget.caps[n] ?? 0))) neverRunnable.push({ step: s.id, reason: 'cost_over_cap' });
    else if ((anc.get(s.id) as Set<string>).size + 1 > b.budget.max_steps) neverRunnable.push({ step: s.id, reason: 'needs_more_steps_than_budget' });
  }

  // data lineage: a step's outputs reach `t` along edges (transitively through steps that consume them)
  const feeds = new Map<string, Set<string>>(b.steps.map((s) => [s.id, new Set<string>()]));
  for (const e of b.edges) (feeds.get(e.to.step) as Set<string>).add(e.from.step);
  const lineageOf = (id: string, seen = new Set<string>()): Set<string> => {
    for (const f of feeds.get(id) as Set<string>) if (!seen.has(f)) { seen.add(f); lineageOf(f, seen); }
    return seen;
  };
  const sinks: DagExposure['sinks'] = [];
  for (const s of b.steps) {
    if (s.sink === null) continue;
    const incoming = b.edges.filter((e) => e.to.step === s.id);
    sinks.push({
      step: s.id, sink: s.sink, lineage: [...lineageOf(s.id)].sort(),
      protected: s.deny_labels.length > 0 || s.escalate_labels.length > 0 || incoming.some((e) => e.deny_labels.length > 0),
    });
  }
  const unprotectedSinks = sinks.filter((k) => !k.protected && k.lineage.length > 0).map((k) => k.step);
  const orderingOnly = b.steps.filter((s) => s.deps.length > 0 && !b.edges.some((e) => e.to.step === s.id)).map((s) => s.id);
  const pipelinable = b.edges.flatMap((e, i) => (e.promise !== null ? [i] : []));
  return { steps: b.steps.length, maxSteps: Math.min(b.steps.length, b.budget.max_steps), depth, levelWidth, paths, pathsCapped: capped, cost, neverRunnable, sinks, unprotectedSinks, orderingOnly, pipelinable };
}
