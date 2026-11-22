import { isGroupCondition, isLeafCondition, type Condition, type Predicate, type prohibitions } from '@atlasauth/pca';
import {
  DEFAULT_MAX_COMBINATIONS,
  collect,
  decide,
  decideAction,
  probeSet,
  repToAction,
  search,
  toModel,
  collectProbes,
  type PolicyModel,
  type Probes,
  type Rep,
} from './enumerate';
import { DEFAULT_CATALOG, resolveAction } from '@atlasauth/pca/ext/research';
import { vetoesFromConstitution } from './constitution';
import type { AnalyzerAction, PolicyInput } from './types';
import type { AnalyzerOptions } from './index';

/**
 * QUANTITATIVE AND TERNARY STATIC QUERIES (borrowed-ideas item 4, security contract C-244..C-246): the most that can ever be
 * spent under a policy, the actions that need a human, the reach of a delegation chain, and a first-class diff.
 *
 * All of it sits OUTSIDE the trusted core, on the same sound bounded enumeration as the rest of the analyzer. Every witness is
 * re-checked by the real evaluator (`decideAction`), and a number is exact only on the decided fragment; otherwise the result
 * carries `approximate: true` and the reason, and the bound errs on the high side (never claims a safer number than it proved).
 */

type Constitution = prohibitions.Constitution;

const HUGE = Number.MAX_SAFE_INTEGER;

function boundOf(opts: AnalyzerOptions | undefined): number {
  const m = opts?.maxCombinations;
  return typeof m === 'number' && Number.isFinite(m) && m >= 0 ? m : DEFAULT_MAX_COMBINATIONS;
}

function condThresholds(c: Condition, path: string, into: number[]): void {
  if (c === null || typeof c !== 'object') return;
  if (isGroupCondition(c)) {
    if ('all_of' in c && Array.isArray(c.all_of)) for (const x of c.all_of) condThresholds(x, path, into);
    else if ('any_of' in c && Array.isArray(c.any_of)) for (const x of c.any_of) condThresholds(x, path, into);
    else if ('not' in c) condThresholds(c.not, path, into);
    return;
  }
  if (!isLeafCondition(c) || c.field !== path) return;
  const v = c.value;
  if (typeof v === 'number' && Number.isFinite(v)) into.push(v);
  else if (Array.isArray(v)) for (const x of v) if (typeof x === 'number' && Number.isFinite(x)) into.push(x);
}

/** Every numeric literal the policy compares `path` against (conditions of permits, vetoes and tighten rules). */
export function thresholdsOf(model: PolicyModel, path: string): number[] {
  const out: number[] = [];
  for (const p of probeSet(model)) for (const c of p.where ?? []) condThresholds(c, path, out);
  for (const v of model.vetoes) if (v.over?.path === path) out.push(v.over.threshold);
  return [...new Set(out)].sort((a, b) => a - b);
}

// ---- per-action peak ------------------------------------------------------------------------------

export interface PeakResult {
  /** Some action of the verb is in the level (admitted / autonomous). */
  admitted: boolean;
  /** Largest amount (Infinity = unbounded). When `attained` is false it is a supremum no action reaches. */
  max: number;
  attained: boolean;
  /** A concrete action at the maximum (or at the supremum's cell when not attained), verified by the real evaluator. */
  witness?: AnalyzerAction;
}

export interface PeakOptions extends AnalyzerOptions {
  verb: string;
  resource?: string;
  /** `action.params.<field>` carrying the amount; default `amount`. */
  amountField?: string;
  /** The schema declares the parameter an integer: a non-attained supremum becomes the largest integer below it. */
  integer?: boolean;
  /** Schema bounds of the parameter (inclusive). */
  min?: number;
  max?: number;
}

function pinned(pr: Probes, path: string, value: number, resource: string | undefined): Probes {
  const fields = pr.fields.filter((f) => f.path !== path).concat([{ path, values: [value] }]);
  return { ...pr, resources: resource !== undefined ? [resource] : pr.resources, fields };
}

function peakAt(model: PolicyModel, o: PeakOptions, level: 'allow' | 'admit'): { peak: PeakResult; overflow: boolean } {
  const path = `action.params.${o.amountField ?? 'amount'}`;
  const max = boundOf(o);
  const base = collectProbes({ predicateSets: [probeSet(model)], varyReversibility: model.revCap !== undefined });
  base.verbs = [o.verb];
  const T = thresholdsOf(model, path);
  const lo = Math.max(0, o.min ?? 0);
  const hi = o.max ?? Infinity;
  const raw: number[] = [];
  for (let i = 0; i < T.length; i++) {
    const t = T[i]!;
    raw.push(t - 1, t);
    if (i + 1 < T.length) raw.push((t + T[i + 1]!) / 2);
  }
  raw.push(T.length > 0 ? T[T.length - 1]! + 1 : 0, HUGE, lo, ...(Number.isFinite(hi) ? [hi] : []));
  const cands = [...new Set(raw)].filter((c) => c >= lo && c <= hi && Number.isFinite(c)).sort((a, b) => b - a);
  const ok = (m: PolicyModel) => (rep: Rep) => {
    const d = decide(m, rep);
    return level === 'allow' ? d === 'allow' : d !== 'deny';
  };
  let overflow = false;
  for (const c of cands) {
    const out = search(pinned(base, path, c, o.resource), ok(model), max);
    if (out.overflow) {
      overflow = true;
      break;
    }
    if (out.hit === undefined) continue;
    const act = (v: number): AnalyzerAction => {
      const a = repToAction(out.hit!);
      a.params = { ...(a.params ?? {}), [o.amountField ?? 'amount']: v };
      return a;
    };
    const holds = (a: AnalyzerAction) => {
      const d = decideAction(model, a);
      return level === 'allow' ? d === 'allow' : d !== 'deny';
    };
    const top = T.length > 0 ? T[T.length - 1]! : -Infinity;
    if (c > top) {
      // the cell above every threshold: unbounded unless the schema caps the parameter
      if (Number.isFinite(hi)) return { peak: { admitted: true, max: hi, attained: holds(act(hi)), witness: act(hi) }, overflow: false };
      return { peak: { admitted: true, max: Infinity, attained: false, witness: act(HUGE) }, overflow: false };
    }
    if (T.includes(c)) return { peak: { admitted: true, max: c, attained: true, witness: act(c) }, overflow: false };
    const next = T.find((t) => t > c)!;
    if (o.integer === true) {
      const m = Math.ceil(next) - 1;
      if (m >= c && holds(act(m))) return { peak: { admitted: true, max: m, attained: true, witness: act(m) }, overflow: false };
    }
    return { peak: { admitted: true, max: next, attained: false, witness: act(c) }, overflow: false };
  }
  return { peak: { admitted: false, max: 0, attained: false }, overflow };
}

// ---- windowed exposure ----------------------------------------------------------------------------

export interface ExposureOptions extends PeakOptions {
  /** Window in seconds for the total (omit for the lifetime total). */
  windowSecs?: number;
  /** Constitution whose `cap` and `rate` invariants bound the total; its stateless invariants become vetoes. */
  constitution?: Constitution;
  /**
   * How a `budget_alloc` caveat bounds the amount. Read from a compiled policy (`budgetModel`, `riskPolicy.kappa`) when not given.
   * `'dollars'`: an action costs its amount (in the amount's own unit), so the allocation is a lifetime cap on the total.
   * `'risk'`: an action costs `kappa * r` where `r` is the verb's blast radius, independent of the amount, so the allocation
   * bounds the NUMBER of autonomous actions (`floor(limit / (kappa * r))`) and the total is that count times the per-action ceiling.
   * With neither a model nor `kappa`, the allocation cannot be related to the amount and is listed in `notApplied`.
   */
  budgetModel?: 'dollars' | 'risk';
  /** The risk policy's `kappa` (cost = kappa * r). */
  kappa?: number;
  /** The verb's blast radius `r` in [0,1] for the risk model (default: the connector catalog, conservative for unknown verbs). */
  blastRadius?: number;
}

export interface WindowBound {
  secs?: number;
  /** Largest number of actions the rate limits allow in the window (Infinity = unlimited). */
  maxActions: number;
  /** Upper bound on the total amount that can leave in the window, and the constraints that produced it. */
  bound: number;
  basis: string[];
  /** Cap / rate invariants left out because they do not provably apply to every action of the verb (leaving them out can only raise the bound). */
  notApplied: string[];
  /** The bounding sequence: the witness action repeated `repeat` times (when the bound is finite). */
  sequence?: { action: AnalyzerAction; repeat: number };
}

export interface Exposure {
  verb: string;
  amountField: string;
  /** Largest single action, human approval allowed. */
  perAction: PeakResult;
  /** Largest single action that proceeds with no human (decision `allow`). */
  autonomousPerAction: PeakResult;
  window: WindowBound;
  autonomousWindow: WindowBound;
  /** Invariants the enumeration could not model (the bound over-approximates because of them). */
  unmodeled: string[];
  approximate?: boolean;
  reason?: string;
}

function universal(p: Predicate, verb: string): boolean {
  const verbOk = p.verb === '*' || p.verb === verb || (Array.isArray(p.verb) && (p.verb.includes('*') || p.verb.includes(verb)));
  return verbOk && (p.resource === undefined || p.resource === '*') && (p.where === undefined || p.where.length === 0);
}

function windowBound(model: PolicyModel, c: Constitution | undefined, o: ExposureOptions, peak: PeakResult): WindowBound {
  const W = o.windowSecs;
  const path = `action.params.${o.amountField ?? 'amount'}`;
  const per = peak.admitted ? peak.max : 0;
  const basis: string[] = [];
  const notApplied: string[] = [];
  let maxActions = Infinity;
  const limitActions = (n: number, perSecs: number, why: string) => {
    const k = W === undefined ? Infinity : n * Math.ceil(W / perSecs); // a sliding limit of n per perSecs: at most n per started period
    if (k < maxActions) {
      maxActions = k;
      basis.push(why);
    }
  };
  const caveats = [...model.caveats, ...model.meets.flatMap((m) => m.caveats)];
  for (const cv of caveats) if (cv.type === 'rate' && typeof cv.max === 'number' && typeof cv.per_secs === 'number' && cv.per_secs > 0) limitActions(cv.max, cv.per_secs, `rate caveat ${cv.max}/${cv.per_secs}s`);
  for (const inv of c?.invariants ?? []) {
    if (inv.kind !== 'rate') continue;
    if (universal(inv.when, o.verb)) limitActions(inv.max, inv.window_secs, `rate invariant ${inv.id}`);
    else notApplied.push(inv.id);
  }
  let bound = per === 0 ? 0 : maxActions === Infinity ? Infinity : per * maxActions;
  if (Number.isFinite(per) && per > 0) basis.unshift('per-action ceiling');
  for (const cv of caveats) {
    if (cv.type !== 'budget_alloc' || typeof cv.limit !== 'number') continue;
    if (o.budgetModel === 'dollars') {
      if (cv.limit < bound) {
        bound = cv.limit; // in the dollar model the allocation is a lifetime cap on the total
        basis.push(`budget_alloc limit ${cv.limit}`);
      }
    } else if (o.budgetModel === 'risk' && typeof o.kappa === 'number' && o.kappa > 0) {
      const r = o.blastRadius ?? resolveAction(DEFAULT_CATALOG, o.verb).spec.blastRadius;
      const cost = o.kappa * Math.min(1, Math.max(0, r));
      const n = cost > 0 ? Math.floor(cv.limit / cost) : Infinity;
      if (n < maxActions) {
        maxActions = n;
        bound = n === 0 ? 0 : Number.isFinite(per) && per > 0 ? per * n : bound;
        basis.push(`budget_alloc ${cv.limit} / cost ${cost} = ${n} actions`);
      }
    } else notApplied.push(`budget_alloc ${cv.limit} (trust-budget units; pass budgetModel and kappa)`);
  }
  for (const inv of c?.invariants ?? []) {
    if (inv.kind !== 'cap') continue;
    if (!universal(inv.when, o.verb) || inv.amount !== path) {
      notApplied.push(inv.id);
      continue;
    }
    if (inv.window_secs !== undefined && W === undefined) continue; // a windowed cap says nothing about a lifetime total
    const cap = inv.window_secs === undefined || W === undefined ? inv.max : inv.max * Math.ceil(W / inv.window_secs);
    if (cap < bound) {
      bound = cap;
      basis.push(`cap invariant ${inv.id}`);
    }
  }
  const out: WindowBound = { maxActions, bound, basis, notApplied };
  if (W !== undefined) out.secs = W;
  if (peak.admitted && peak.witness !== undefined && Number.isFinite(maxActions) && Number.isFinite(peak.max) && peak.max > 0) out.sequence = { action: peak.witness, repeat: maxActions };
  return out;
}

/**
 * The most that can ever leave under a policy: the largest single action, the largest autonomous action, and the total over a
 * window, composing the per-action ceiling with rate limits, the grant's `budget_alloc` and a constitution's `cap` / `rate`
 * invariants. A cap or rate invariant counts only when it provably applies to every action of the verb (a universal trigger);
 * otherwise it is left out, which can only raise the bound.
 */
export function maxExposure(policy: PolicyInput, given: ExposureOptions): Exposure {
  const cp = policy as { budgetModel?: unknown; riskPolicy?: { kappa?: unknown } };
  const o: ExposureOptions = {
    ...given,
    ...(given.budgetModel === undefined && (cp.budgetModel === 'dollars' || cp.budgetModel === 'risk') ? { budgetModel: cp.budgetModel } : {}),
    ...(given.kappa === undefined && typeof cp.riskPolicy?.kappa === 'number' ? { kappa: cp.riskPolicy.kappa } : {}),
  };
  const cv = o.constitution !== undefined ? vetoesFromConstitution(o.constitution) : undefined;
  const base = toModel(policy);
  const model: PolicyModel = cv !== undefined ? { ...base, vetoes: [...base.vetoes, ...cv.vetoes] } : base;
  const field = o.amountField ?? 'amount';
  const admit = peakAt(model, o, 'admit');
  const auto = peakAt(model, o, 'allow');
  const approximate = admit.overflow || auto.overflow || model.undecidable.length > 0;
  const e: Exposure = {
    verb: o.verb,
    amountField: field,
    perAction: admit.overflow ? { admitted: true, max: Infinity, attained: false } : admit.peak,
    autonomousPerAction: auto.overflow ? { admitted: true, max: Infinity, attained: false } : auto.peak,
    window: windowBound(model, o.constitution, o, admit.overflow ? { admitted: true, max: Infinity, attained: false } : admit.peak),
    autonomousWindow: windowBound(model, o.constitution, o, auto.overflow ? { admitted: true, max: Infinity, attained: false } : auto.peak),
    unmodeled: (cv?.unmodeled ?? []).filter((u) => u.kind !== 'cap' && u.kind !== 'rate').map((u) => `${u.id}: ${u.reason}`),
  };
  if (approximate) {
    e.approximate = true;
    e.reason = admit.overflow || auto.overflow ? 'representative grid exceeded the bound; exposure reported as unbounded' : `over-approximated (${model.undecidable.join('; ')})`;
  }
  return e;
}

// ---- escalation surface ---------------------------------------------------------------------------

export interface EscalationSurface {
  /** Some action is admitted only with a human. */
  escalates: boolean;
  /** Concrete actions the policy sends to a human (verified), at most `limit`. */
  witnesses: AnalyzerAction[];
  approximate?: boolean;
  reason?: string;
}

/** The set of actions that escalate (ternary-aware: admitted, but not autonomous). */
export function escalationSurface(policy: PolicyInput, opts: AnalyzerOptions & { verb?: string; limit?: number } = {}): EscalationSurface {
  const model = toModel(policy);
  const base = collectProbes({ predicateSets: [probeSet(model)], varyReversibility: model.revCap !== undefined });
  if (opts.verb !== undefined) base.verbs = [opts.verb];
  const r = collect(base, (rep) => decide(model, rep) === 'escalate', boundOf(opts), opts.limit ?? 8);
  const witnesses = r.hits.map(repToAction).filter((a) => decideAction(model, a) === 'escalate');
  const out: EscalationSurface = { escalates: witnesses.length > 0, witnesses };
  if (r.overflow || model.undecidable.length > 0) {
    out.approximate = true;
    out.reason = r.overflow ? 'representative grid exceeded the bound' : `over-approximated (${model.undecidable.join('; ')})`;
  }
  return out;
}

// ---- delegation envelope --------------------------------------------------------------------------

export interface DelegationEnvelope {
  /** Each hop must be subsumed by the one above; the indices of hops that are not (a malformed chain). */
  violations: number[];
  /** Verbs any holder of the leaf can reach (with a witness), `'*'` when a verb never named in the policy is reachable. */
  verbs: Array<{ verb: string; witness: AnalyzerAction; autonomous: boolean }>;
  anyVerb: boolean;
  depth: { allowed?: number; used: number; remaining?: number };
  approximate?: boolean;
  reason?: string;
}

/**
 * The join of everything any holder of the leaf could do: the meet of the chain's policies (every hop must admit) with the
 * remaining `delegation_depth`. A sub-delegate can only narrow this envelope, so it is the ceiling for the whole subtree.
 */
export function delegationEnvelope(chain: PolicyInput[], opts: AnalyzerOptions = {}): DelegationEnvelope {
  const leaf = chain[chain.length - 1];
  const policy: PolicyInput = (leaf !== null && typeof leaf === 'object' ? { ...leaf, meet: [...chain.slice(0, -1), ...(('meet' in leaf && leaf.meet) || [])] } : { predicates: [] }) as PolicyInput;
  const model = toModel(policy);
  const base = collectProbes({ predicateSets: [probeSet(model)], varyReversibility: model.revCap !== undefined });
  const verbs: DelegationEnvelope['verbs'] = [];
  let anyVerb = false;
  let overflow = false;
  for (const verb of base.verbs) {
    const pr = { ...base, verbs: [verb] };
    const r = collect(pr, (rep) => decide(model, rep) !== 'deny', boundOf(opts), 1);
    if (r.overflow) {
      overflow = true;
      break;
    }
    const hit = r.hits[0];
    if (hit === undefined) continue;
    const w = repToAction(hit);
    if (verb.startsWith('\u0000')) anyVerb = true;
    else verbs.push({ verb, witness: w, autonomous: decide(model, hit) === 'allow' });
  }
  const violations: number[] = [];
  for (let i = 0; i + 1 < chain.length; i++) {
    const a = toModel(chain[i]!);
    const b = toModel(chain[i + 1]!);
    const pr = collectProbes({ predicateSets: [probeSet(a), probeSet(b)], varyReversibility: a.revCap !== undefined || b.revCap !== undefined });
    const out = search(pr, (rep) => decide(b, rep) !== 'deny' && decide(a, rep) === 'deny', boundOf(opts));
    if (out.hit !== undefined || out.overflow) violations.push(i + 1);
  }
  const depths = chain.flatMap((p) => (p !== null && typeof p === 'object' && 'caveats' in p && Array.isArray(p.caveats) ? p.caveats : [])).filter((c) => c.type === 'delegation_depth' && typeof c.max === 'number').map((c) => c.max as number);
  const used = Math.max(0, chain.length - 1);
  const allowed = depths.length > 0 ? Math.min(...depths) : undefined;
  const out: DelegationEnvelope = { violations, verbs, anyVerb, depth: { used, ...(allowed !== undefined ? { allowed, remaining: Math.max(0, allowed - used) } : {}) } };
  if (overflow || model.undecidable.length > 0) {
    out.approximate = true;
    out.reason = overflow ? 'representative grid exceeded the bound' : `over-approximated (${model.undecidable.join('; ')})`;
  }
  return out;
}

// ---- semantic diff --------------------------------------------------------------------------------

export type Shift = 'deny->allow' | 'deny->escalate' | 'escalate->allow' | 'allow->escalate' | 'allow->deny' | 'escalate->deny';

export interface PolicyDiff {
  equivalent: boolean;
  /** Per kind of change, concrete actions (verified against both policies) that moved. */
  shifts: Partial<Record<Shift, AnalyzerAction[]>>;
  /** True when something became more permissive (deny->allow, deny->escalate, escalate->allow). */
  widens: boolean;
  narrows: boolean;
  /** One line per kind of change, ready for a PR comment. */
  summary: string[];
  exposure?: { before: Exposure; after: Exposure; /** change of the largest single action */ perActionDelta: number; /** change of the windowed total (0 when both are unbounded) */ delta: number; autonomousDelta: number };
  approximate?: boolean;
  reason?: string;
}

const sub = (x: number, y: number): number => (x === y ? 0 : x - y); // Infinity - Infinity is no change
const WIDEN: Shift[] = ['deny->allow', 'deny->escalate', 'escalate->allow'];

export interface DiffOptions extends AnalyzerOptions {
  /** Max witnesses per kind of change. */
  limit?: number;
  /** When given, also report how the max exposure of this verb moved. */
  exposure?: ExposureOptions;
}

/** `diff(A, B)`: "A to B widens X, narrows Y" with witnesses, ternary-aware. */
export function diffPolicies(a: PolicyInput, b: PolicyInput, o: DiffOptions = {}): PolicyDiff {
  const ma = toModel(a);
  const mb = toModel(b);
  const pr = collectProbes({ predicateSets: [probeSet(ma), probeSet(mb)], varyReversibility: ma.revCap !== undefined || mb.revCap !== undefined });
  const limit = o.limit ?? 4;
  const shifts: PolicyDiff['shifts'] = {};
  const counts = new Map<Shift, number>();
  const walk = collect(
    pr,
    (rep) => {
      const x = decide(ma, rep);
      const y = decide(mb, rep);
      if (x === y) return false;
      const k = `${x}->${y}` as Shift;
      const n = counts.get(k) ?? 0;
      counts.set(k, n + 1);
      if (n < limit) (shifts[k] ??= []).push(repToAction(rep));
      return false; // walk the whole grid
    },
    boundOf(o),
    1,
  );
  const overflow = walk.overflow;
  const kinds = Object.keys(shifts) as Shift[];
  const widens = kinds.some((k) => WIDEN.includes(k));
  const narrows = kinds.some((k) => !WIDEN.includes(k));
  const summary = kinds.map((k) => `${k}: ${shifts[k]!.length}+ action(s), e.g. ${shifts[k]![0]!.verb} ${shifts[k]![0]!.resource} ${JSON.stringify(shifts[k]![0]!.params ?? {})}`);
  const d: PolicyDiff = { equivalent: kinds.length === 0 && !overflow && ma.undecidable.length === 0 && mb.undecidable.length === 0, shifts, widens, narrows, summary };
  if (o.exposure !== undefined) {
    const before = maxExposure(a, o.exposure);
    const after = maxExposure(b, o.exposure);
    d.exposure = { before, after, perActionDelta: sub(after.perAction.max, before.perAction.max), autonomousDelta: sub(after.autonomousWindow.bound, before.autonomousWindow.bound), delta: sub(after.window.bound, before.window.bound) };
    const worst = Math.max(d.exposure.delta, d.exposure.perActionDelta, d.exposure.autonomousDelta);
    const best = Math.min(d.exposure.delta, d.exposure.perActionDelta);
    if (worst > 0) d.summary.push(`max exposure of ${o.exposure.verb} rises by ${worst}`);
    else if (best < 0) d.summary.push(`max exposure of ${o.exposure.verb} falls by ${-best}`);
  }
  if (overflow || ma.undecidable.length > 0 || mb.undecidable.length > 0) {
    d.approximate = true;
    d.reason = overflow ? 'representative grid exceeded the bound' : `over-approximated (${[...new Set([...ma.undecidable, ...mb.undecidable])].join('; ')})`;
  }
  return d;
}

/** A CI gate over a diff: fails when the change widens authority beyond what the reviewer allowed. */
export function diffGate(d: PolicyDiff, allow: { widen?: boolean; maxExposureIncrease?: number } = {}): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (d.widens && allow.widen !== true) reasons.push(`widens authority: ${d.summary.filter((s) => WIDEN.some((k) => s.startsWith(k))).join('; ')}`);
  const rise = d.exposure ? Math.max(d.exposure.delta, d.exposure.perActionDelta, d.exposure.autonomousDelta) : 0;
  if (rise > (allow.maxExposureIncrease ?? 0)) reasons.push(`max exposure rises by ${rise}`);
  if (d.approximate) reasons.push(`inconclusive: ${d.reason ?? 'approximate'}`);
  return { ok: reasons.length === 0, reasons };
}

// ---- optional solver backend ----------------------------------------------------------------------

export interface WitnessQuery {
  kind: 'reachable' | 'differs';
  a: PolicyInput;
  b?: PolicyInput;
  verb?: string;
}

/**
 * An optional external solver (cvc5, z3) used ONLY to look for a counterexample when the grid overflows. It is never trusted:
 * a witness it returns is re-checked by the real evaluator and discarded if wrong, and an "unsat" claim is returned labelled
 * as solver-claimed, never as a proved verdict.
 */
export interface WitnessBackend {
  name: string;
  find(q: WitnessQuery): Promise<{ witness?: AnalyzerAction; unsat?: boolean }>;
}

export interface BackendResult {
  witness?: AnalyzerAction;
  /** The backend said no witness exists; this is an unchecked claim. */
  claimedUnsat?: { by: string; proof: 'solver-claimed, not machine-checked' };
  /** The backend returned a witness the real evaluator rejects. */
  rejected?: boolean;
}

export async function findWithBackend(backend: WitnessBackend, q: WitnessQuery): Promise<BackendResult> {
  const r = await backend.find(q);
  if (r.witness !== undefined) {
    const ma = toModel(q.a);
    const ok =
      q.kind === 'reachable'
        ? decideAction(ma, r.witness) !== 'deny' && (q.verb === undefined || r.witness.verb === q.verb)
        : q.b !== undefined && (decideAction(ma, r.witness) !== 'deny') !== (decideAction(toModel(q.b), r.witness) !== 'deny');
    return ok ? { witness: r.witness } : { rejected: true };
  }
  if (r.unsat === true) return { claimedUnsat: { by: backend.name, proof: 'solver-claimed, not machine-checked' } };
  return {};
}
