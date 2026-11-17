/**
 * Synthesis: the least-privilege grant that admits the observed traces. Everything here is a PROPOSAL: it reads traces and
 * emits data. Nothing in this file signs, mints or enforces; a proposal becomes authority only through `signoff.ts`.
 */
import {
  DEFAULT_RISK_POLICY, REVERSIBILITY_ORDER, hashCanonicalLenient, validateRiskPolicy,
  type Caveat, type CompiledPolicy, type Condition, type Predicate, type RiskPolicy,
} from '@atlasauth/pca';
import { DEFAULT_CATALOG, forecast, recommendPolicy, resolveAction, type ActionSpec, type SimAction } from '@atlasauth/pca/ext/research';
import { cleanText } from '@atlasauth/pca-explain';
import type { HeldItem, Proposal, RuleExplanation, SynthOptions, Trace, TraceSet } from './types';

export const DAY_MS = 86_400_000;

/** A fraction as a percentage without float noise (0.07 * 100 is 7.000000000000001). */
export const pct = (m: number): number => Math.round(m * 1000) / 10;

export interface Resolved {
  margin: number; minDistinct: number; maxEnum: number; windowSecs: number; ttlMs: number; now: number; maxRules: number;
}

const int = (name: string, v: number | undefined, d: number, lo: number, hi: number): number => {
  const x = v ?? d;
  if (!Number.isInteger(x) || x < lo || x > hi) throw new RangeError(`${name} must be an integer in [${lo}, ${hi}]`);
  return x;
};

export function resolve(o: SynthOptions): Resolved {
  const margin = o.margin ?? 0.2;
  if (typeof margin !== 'number' || !Number.isFinite(margin) || margin < 0 || margin > 10) throw new RangeError('margin must be a finite number in [0, 10]');
  const ttlMs = o.ttlMs ?? 30 * DAY_MS;
  if (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs <= 0) throw new RangeError('ttlMs must be a positive finite number');
  const now = o.now ?? Date.now();
  if (typeof now !== 'number' || !Number.isFinite(now) || now < 0) throw new RangeError('now must be a finite epoch-millisecond number');
  return {
    margin, ttlMs, now,
    minDistinct: int('minDistinct', o.minDistinct, 3, 2, 1000),
    maxEnum: int('maxEnum', o.maxEnum, 5, 0, 50),
    windowSecs: int('windowSecs', o.windowSecs, 3600, 1, 31 * 86400),
    maxRules: int('maxRules', o.maxRules, 200, 1, 10_000),
  };
}

/** Round to 12 significant digits so a derived cap is a clean canonical number (10 * 1.2 is not 12.000000000000002). */
export const clean = (x: number): number => Number(x.toPrecision(12));

/** The catalog's spec for a verb; an unknown verb is the catalog's fail-closed default (irreversible, maximum blast radius). */
export const specOf = (verb: string): ActionSpec => resolveAction(DEFAULT_CATALOG, verb).spec;

/** The compiled form the simulator and forecaster read. Policy fields come from the proposal, never from a catalog default. */
export function toCompiled(policy: { predicates: Predicate[]; caveats: Caveat[] }, riskPolicy: RiskPolicy): CompiledPolicy {
  const verbs = [...new Set(policy.predicates.flatMap((p) => (Array.isArray(p.verb) ? p.verb : [p.verb])))];
  return { predicates: policy.predicates, caveats: policy.caveats, riskPolicy, actions: verbs.map(specOf), budgetModel: 'risk', limits: {}, inputLimits: {}, approximations: [] };
}

const parentOf = (r: string): string | null => {
  const i = r.lastIndexOf('/');
  return i > 0 && i < r.length - 1 ? r.slice(0, i) : null;
};

/** Spread-free min/max: a 100k-element spread overflows the call stack. */
export const maxOf = (xs: readonly number[]): number => xs.reduce((a, b) => (b > a ? b : a), -Infinity);
export const minOf = (xs: readonly number[]): number => xs.reduce((a, b) => (b < a ? b : a), Infinity);

const allInts = (xs: number[]): boolean => xs.every((x) => Number.isInteger(x));

export interface BuiltRule { predicate: Predicate; explanation: RuleExplanation }

/** Rules for one verb's traces: the generalization ladder, then per-rule parameter bounds. Pure and deterministic. */
export function buildRules(traces: readonly Trace[], r: Resolved): BuiltRule[] {
  const byVerb = new Map<string, Trace[]>();
  for (const t of traces) (byVerb.get(t.verb) ?? byVerb.set(t.verb, []).get(t.verb)!).push(t);
  const out: BuiltRule[] = [];
  for (const verb of [...byVerb.keys()].sort()) {
    const vt = byVerb.get(verb)!;
    const resources = [...new Set(vt.map((t) => t.resource))].sort();
    const byParent = new Map<string, string[]>();
    for (const res of resources) {
      const p = parentOf(res);
      if (p !== null) (byParent.get(p) ?? byParent.set(p, []).get(p)!).push(res);
    }
    const covered = new Set<string>();
    const rules: { resource: string; rung: 0 | 1; members: string[]; why: string }[] = [];
    for (const p of [...byParent.keys()].sort()) {
      const members = byParent.get(p)!;
      if (members.length < r.minDistinct) continue;
      rules.push({ resource: `${p}/*`, rung: 1, members, why: `${members.length} different resources under ${cleanText(p)}/ were used; only the last path segment is generalized, never the parent` });
      members.forEach((m) => covered.add(m));
    }
    for (const res of resources) if (!covered.has(res)) rules.push({ resource: res, rung: 0, members: [res], why: 'seen too few times in this shape to generalize, so exactly this resource' });
    rules.sort((a, b) => (a.resource < b.resource ? -1 : a.resource > b.resource ? 1 : 0));
    for (const rule of rules) {
      const rt = vt.filter((t) => rule.members.includes(t.resource));
      const where: Condition[] = [];
      const pnotes: string[] = [];
      const keys = [...new Set(rt.flatMap((t) => Object.keys(t.params)))].sort();
      for (const k of keys) {
        const vals = rt.map((t) => t.params[k]);
        if (vals.some((v) => v === undefined)) { pnotes.push(`${k}: not sent every time, so left unconstrained`); continue; }
        const field = `action.params.${k}`;
        if (vals.every((v) => typeof v === 'number')) {
          const xs = vals as number[];
          const mx = maxOf(xs), mn = minOf(xs);
          let hi = mx >= 0 ? mx * (1 + r.margin) : mx * (1 - r.margin);
          let lo = mn >= 0 ? 0 : mn * (1 + r.margin);
          if (allInts(xs)) { hi = Math.ceil(hi); lo = Math.floor(lo); }
          hi = clean(hi); lo = clean(lo);
          if (!Number.isFinite(hi) || !Number.isFinite(lo)) throw new RangeError(`parameter ${k} produced a non-finite bound`);
          where.push({ field, op: 'lte', value: hi }, { field, op: 'gte', value: lo });
          pnotes.push(`${k}: at most ${hi} (largest seen ${mx}, margin ${pct(r.margin)}%) and at least ${lo}`);
        } else if (vals.every((v) => typeof v === 'string')) {
          const set = [...new Set(vals as string[])].sort();
          if (set.length <= r.maxEnum) {
            where.push(set.length === 1 ? { field, op: 'eq', value: set[0]! } : { field, op: 'in', value: set });
            pnotes.push(`${k}: only ${set.map((s) => `"${cleanText(s)}"`).join(', ')}`);
          } else pnotes.push(`${k}: ${set.length} different values, left unconstrained`);
        } else if (vals.every((v) => typeof v === 'boolean') && new Set(vals).size === 1) {
          where.push({ field, op: 'eq', value: vals[0] as boolean });
          pnotes.push(`${k}: always ${String(vals[0])}`);
        } else pnotes.push(`${k}: mixed types, left unconstrained`);
      }
      out.push({
        predicate: { verb, resource: rule.resource, ...(where.length ? { where } : {}) },
        explanation: { verb, resource: rule.resource, rung: rule.rung, observed: rt.length, observedResources: rule.members.slice(0, 20).map((m) => cleanText(m)), why: rule.why, params: pnotes },
      });
    }
  }
  return out;
}

/** The strictest reversibility class among the verbs, as `reversibility_max`. */
export function reversibilityCap(verbs: readonly string[]): string {
  let idx = 0;
  for (const v of verbs) idx = Math.max(idx, REVERSIBILITY_ORDER.indexOf(specOf(v).reversibility as (typeof REVERSIBILITY_ORDER)[number]));
  return REVERSIBILITY_ORDER[idx]!;
}

/** Largest number of actions in any window of `secs` seconds. */
export function peakInWindow(times: readonly number[], secs: number): number {
  const ts = [...times].sort((a, b) => a - b);
  let lo = 0, peak = 0;
  for (let hi = 0; hi < ts.length; hi++) {
    while (ts[hi]! - ts[lo]! >= secs * 1000) lo++;
    peak = Math.max(peak, hi - lo + 1);
  }
  return peak;
}

export function buildCaveats(traces: readonly Trace[], r: Resolved): Caveat[] {
  const peak = peakInWindow(traces.map((t) => t.at), r.windowSecs);
  return [
    { type: 'reversibility_max', class: reversibilityCap(traces.map((t) => t.verb)) },
    { type: 'expires', at: Math.trunc(r.now + r.ttlMs) },
    { type: 'rate', max: Math.max(1, Math.ceil(peak * (1 + r.margin))), per_secs: r.windowSecs },
  ];
}

const simOf = (traces: readonly Trace[]): SimAction[] => traces.map((t) => ({ verb: t.verb, resource: t.resource, params: t.params, at: t.at }));

/**
 * Budget from the forecast: start at what `recommendPolicy` gives for the observed volume, then raise bMax until the budget
 * itself forces no human step-up beyond the ones the risk tiers force anyway. Thresholds are never loosened.
 */
export function buildBudget(policy: { predicates: Predicate[]; caveats: Caveat[] }, traces: readonly Trace[], r: Resolved): RiskPolicy {
  const plan = simOf(traces);
  const huge: RiskPolicy = { ...DEFAULT_RISK_POLICY, bMax: 1e9 };
  const base = forecast(toCompiled(policy, huge), plan, { start: traces[0]?.at ?? 0 });
  const rs = base.steps.map((s) => s.r);
  const mean = rs.length ? rs.reduce((a, b) => a + b, 0) / rs.length : 0.5;
  const rec = recommendPolicy(Math.ceil(traces.length * (1 + r.margin)), mean);
  let bMax = Math.max(rec.bMax, rec.kappa);
  for (let i = 0; i < 40; i++) {
    const f = forecast(toCompiled(policy, { ...DEFAULT_RISK_POLICY, kappa: rec.kappa, bMax }), plan, { start: traces[0]?.at ?? 0 });
    if (f.cosignsNeeded <= base.cosignsNeeded) break;
    bMax *= 2;
  }
  const rp: RiskPolicy = { ...DEFAULT_RISK_POLICY, weights: { ...DEFAULT_RISK_POLICY.weights }, kappa: rec.kappa, bMax: clean(bMax) };
  const bad = validateRiskPolicy(rp);
  if (bad) throw new Error(`derived risk policy invalid: ${bad}`);
  return rp;
}

const segs = (res: string): string[] => res.split(/[/:]/);

/** Trace groups that are held back, one item per id. */
function held(ts: readonly Trace[], kind: HeldItem['kind'], extra: (t: Trace) => string[] = () => []): HeldItem[] {
  const m = new Map<string, HeldItem>();
  for (const t of ts) {
    const reasons = [...(kind === 'blocked' ? ['denied while observing'] : []), ...t.sensitive, ...extra(t)];
    const cur = m.get(t.id);
    if (cur) { cur.count++; cur.reasons = [...new Set([...cur.reasons, ...reasons])].sort(); } else m.set(t.id, { id: t.id, verb: t.verb, resource: cleanText(t.resource), count: 1, reasons: [...new Set(reasons)].sort(), kind });
  }
  return [...m.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
}

/** Seal a proposal body: the digest covers every member, so a signature over it covers all of them. */
export function seal(body: Omit<Proposal, 'digest'>): Proposal {
  return { ...body, digest: hashCanonicalLenient(body) };
}

/** Does `p` still carry the digest its content hashes to? A proposal edited after it was made does not. */
export function intact(p: Proposal): boolean {
  const { digest, ...body } = p;
  return typeof digest === 'string' && hashCanonicalLenient(body) === digest;
}

/** Traces the proposal was built from: its tenant's allowed actions, minus unconfirmed sensitive ones, plus the denied groups an amendment admits. */
export function includedTraces(set: { traces: readonly Trace[] }, p: Proposal): Trace[] {
  const conf = new Set(p.confirmedSensitive);
  const admit = new Set(p.admitDenied);
  const others = new Set(set.traces.map((t) => t.tenant).filter((x): x is string => x !== undefined && x !== p.tenant));
  return set.traces.filter((t) => t.tenant === p.tenant && t.at >= p.basis.from && t.at <= p.basis.to && (t.outcome === 'allow' ? true : admit.has(t.id)) && (t.sensitive.length === 0 || conf.has(t.id)) && !crossTenant(t, others));
}

const crossTenant = (t: Trace, others: ReadonlySet<string>): boolean => segs(t.resource).some((s) => others.has(s));

/** Produce a proposal from observed traces. Never signs, never mints. */
export function propose(set: TraceSet, o: SynthOptions = {}): Proposal {
  const r = resolve(o);
  const tenants = new Set(set.traces.map((t) => t.tenant ?? ''));
  if (o.tenant === undefined && tenants.size > 1) throw new Error('the traces span several tenants: pass a tenant. A proposal is never built across tenants.');
  const only = [...tenants][0];
  const tenant = o.tenant ?? (only === '' ? undefined : only);
  const mine = set.traces.filter((t) => t.tenant === tenant);
  const others = new Set(set.traces.map((t) => t.tenant).filter((x): x is string => x !== undefined && x !== tenant));
  const crossed = (t: Trace): string[] => (crossTenant(t, others) ? ['cross-tenant-resource'] : []);

  const confirmed = new Set(o.confirmed ?? []);
  const blocked = mine.filter((t) => t.outcome === 'deny');
  const allowed = mine.filter((t) => t.outcome === 'allow');
  const flagged = (t: Trace): boolean => t.sensitive.length > 0 || crossed(t).length > 0;
  const heldSensitive = allowed.filter((t) => flagged(t) && !confirmed.has(t.id) || crossed(t).length > 0);
  const takenSensitive = allowed.filter((t) => flagged(t) && confirmed.has(t.id) && crossed(t).length === 0);
  const known = new Set(allowed.filter((t) => flagged(t) && crossed(t).length === 0).map((t) => t.id));
  for (const id of confirmed) if (!known.has(id)) throw new Error(`confirmed id ${cleanText(String(id)).slice(0, 40)} is not a confirmable sensitive action in these traces`);
  const included = allowed.filter((t) => !heldSensitive.includes(t));
  if (included.length === 0) throw new Error('no admissible observed actions: nothing to propose (sensitive and blocked actions are never included unconfirmed)');

  const built = buildRules(included, r);
  if (built.length > r.maxRules) throw new RangeError(`${built.length} distinct rules exceeds maxRules ${r.maxRules}: the traces look like a flood; narrow the observation first`);
  const policy = { predicates: built.map((b) => b.predicate), caveats: buildCaveats(included, r) };
  const riskPolicy = buildBudget(policy, included, r);
  const noParams = included.every((t) => Object.keys(t.params).length === 0);
  return seal({
    v: 1, kind: 'pca-autopilot-proposal', ...(tenant !== undefined ? { tenant } : {}), policy, riskPolicy, margin: r.margin, createdAt: r.now,
    basis: { traceSetDigest: set.digest, included: included.length, from: included[0]!.at, to: included[included.length - 1]!.at },
    rules: built.map((b) => b.explanation),
    heldBack: [...held(blocked, 'blocked'), ...held(heldSensitive, 'sensitive', crossed)],
    confirmedSensitive: [...new Set(takenSensitive.map((t) => t.id))].sort(),
    admitDenied: [],
    notes: [
      `numeric caps and the rate carry a ${pct(r.margin)}% margin over the largest value seen`,
      ...(noParams ? ['no parameters were observed (receipt logs carry none), so amounts and other parameters are NOT bounded'] : []),
      `the grant expires ${Math.round(r.ttlMs / DAY_MS * 100) / 100} day(s) after it is issued`,
    ],
  });
}
