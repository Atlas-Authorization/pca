import { evaluateCaveats, type Caveat, type CaveatContext } from '@atlasauth/pca';
import { collectProbes, decideAction, probeSet, toModel, type PolicyModel } from './enumerate';
import { thresholdsOf } from './exposure';
import { policyDigestOf } from './residual';
import type { AnalyzerAction, AnalyzerDecision, PolicyInput, VerbShape } from './types';

/**
 * MINIMAL-CHANGE COUNTERFACTUAL SEARCH on a deny or escalate (borrowed-ideas item 18, security contract C-254, C-255).
 *
 * `minimalFlip` answers "what is the smallest thing the agent can change to be allowed?" with a typed patch it can apply,
 * ordered by cost: wait, lower a parameter to the largest admissible value, pick another allowed value or resource, obtain a
 * named fact (a discharge), split the action (opt-in), and only then ask a human. For an escalation it also names the cheapest
 * repair that needs no human.
 *
 *  - The search PROPOSES; the real decision VERIFIES. Every candidate is re-run through the evaluator and only a candidate that
 *    reaches the wanted decision is returned, so a bug in the search can lose a repair but never invent one.
 *  - A counterfactual teaches the holder about the policy, so it is shown only to the authenticated holder, is rate-limited by a
 *    probe budget, and redacts the values of `critical` parameters down to "a repair exists".
 *  - Splitting is off unless asked for, and is offered only when no rate, budget or cap bound would be skirted by it.
 */

export type Repair =
  | { kind: 'set_param'; param: string; from?: unknown; to?: unknown; redacted?: true }
  | { kind: 'set_resource'; from: string; to: string }
  | { kind: 'obtain_fact'; path: string; value: unknown }
  | { kind: 'wait_until'; at: number; reason: string }
  | { kind: 'split'; parts: Array<Record<string, unknown>>; param: string }
  /** Two edits that only work together (no single edit reaches the wanted decision). */
  | { kind: 'combine'; steps: Array<Extract<Repair, { kind: 'set_param' | 'set_resource' }>> };

export interface RepairCandidate {
  repair: Repair;
  /** Relative cost, lower first. */
  cost: number;
  /** The decision the repaired action gets (re-checked, equals or beats the wanted one). */
  decision: AnalyzerDecision;
  /** The repaired action, so the caller can submit it as is. */
  action: AnalyzerAction;
}

/** What to ask a human for when no repair is possible or the wanted outcome needs one. */
export interface HumanAsk {
  verb: string;
  resource: string;
  params: Record<string, unknown>;
  /** `approval` when the policy itself escalates this action; `access-request` when it denies it. */
  kind: 'approval' | 'access-request';
  policyDigest: string;
}

export interface ProbeBudget {
  limit: number;
  windowSecs: number;
  /** Epoch ms of earlier probes. */
  history: readonly number[];
  now: number;
}

export interface FlipOptions {
  desired?: 'allow' | 'escalate';
  schema?: readonly VerbShape[];
  /** The caller has authenticated as the holder of the grant. Required: counterfactuals are not shown to anyone else. */
  holderAuthenticated: boolean;
  probe?: ProbeBudget;
  /** Parameters the agent may change (default: every declared parameter, or every one the action carries). */
  changeable?: readonly string[];
  /** Offer waiting (time caveats) at this context. */
  caveatContext?: CaveatContext;
  allowSplit?: boolean;
  /** `critical` (default): hide the values of critical parameters; `all`: report only that a repair exists. */
  redact?: 'none' | 'critical' | 'all';
  maxCandidates?: number;
}

export interface FlipResult {
  current: AnalyzerDecision;
  /** Verified repairs, cheapest first. */
  repairs: RepairCandidate[];
  /** The cheapest repair that reaches `allow` without a human (for an escalation). */
  humanFree?: RepairCandidate;
  humanAsk?: HumanAsk;
  /** True when values were hidden or the answer was reduced to a boolean. */
  redacted?: boolean;
  /** At least one repair exists (always present, even when the repairs themselves are redacted). */
  repairExists: boolean;
  refused?: string;
  probe?: { history: number[] };
}

const RANK: Record<AnalyzerDecision, number> = { deny: 0, escalate: 1, allow: 2 };

function sortedByDistance(vals: number[], cur: number): number[] {
  return [...vals].sort((a, b) => Math.abs(a - cur) - Math.abs(b - cur) || a - b);
}

/** Search for the smallest verified change that gets `action` to the wanted decision. */
export function minimalFlip(policy: PolicyInput, action: AnalyzerAction, o: FlipOptions): FlipResult {
  const model = toModel(policy);
  const caveatsOk = o.caveatContext === undefined || evaluateCaveats(model.caveats, o.caveatContext).ok;
  const current: AnalyzerDecision = caveatsOk ? decideAction(model, action) : 'deny';
  const want = o.desired ?? 'allow';
  const res: FlipResult = { current, repairs: [], repairExists: false };
  if (!o.holderAuthenticated) return { ...res, refused: 'counterfactuals are shown only to the authenticated holder' };
  if (o.probe) {
    const recent = o.probe.history.filter((t) => t > o.probe!.now - o.probe!.windowSecs * 1000);
    if (recent.length >= o.probe.limit) return { ...res, refused: 'probe budget exhausted', probe: { history: recent } };
    res.probe = { history: [...recent, o.probe.now] };
  }
  const policyDigest = policyDigestOf(model);
  if (RANK[current] >= RANK[want]) return res;

  const shape = o.schema?.find((s) => s.verb === action.verb);
  const reaches = (a: AnalyzerAction): AnalyzerDecision | null => {
    const d = decideAction(model, a);
    return RANK[d] >= RANK[want] ? d : null;
  };
  const cands: RepairCandidate[] = [];
  const push = (repair: Repair, cost: number, a: AnalyzerAction): void => {
    const d = reaches(a);
    if (d !== null) cands.push({ repair, cost, decision: d, action: a });
  };

  const pr = collectProbes({ predicateSets: [probeSet(model)], varyReversibility: model.revCap !== undefined });
  const params = action.params ?? {};
  const names = o.changeable ?? (shape ? Object.keys(shape.params) : Object.keys(params));

  // 1. wait: a time caveat that is not open yet, or a rate window that will reset (decided by the caveat evaluator at that time)
  if (!caveatsOk && o.caveatContext) {
    const at = waitTime(model.caveats, o.caveatContext);
    const later = at === undefined ? undefined : { ...o.caveatContext, now: at };
    const d = decideAction(model, action);
    if (at !== undefined && later && evaluateCaveats(model.caveats, later).ok && RANK[d] >= RANK[want]) cands.push({ repair: { kind: 'wait_until', at, reason: 'a time or rate caveat opens then' }, cost: 1, decision: d, action });
  }
  const finish = !caveatsOk; // nothing else helps while a caveat is closed: the other repairs are only searched once it is open

  // 2. one parameter changed: the nearest verified value, per parameter
  for (const name of finish ? [] : names) {
    const path = `action.params.${name}`;
    const decl = shape?.params[name];
    const cur = params[name];
    const field = pr.fields.find((f) => f.path === path);
    const pool: unknown[] = [...(field?.values ?? []), ...(decl?.values ?? []), ...(decl?.min !== undefined ? [decl.min] : []), ...(decl?.max !== undefined ? [decl.max] : [])].filter((v) => typeof v !== 'symbol');
    const nums = pool.filter((v): v is number => typeof v === 'number' && Number.isFinite(v));
    const T = thresholdsOf(model, path);
    const integer = decl?.type === 'integer' || (typeof cur === 'number' && Number.isInteger(cur));
    const ints = integer ? T.flatMap((t) => [t - 1, t + 1]) : [];
    const numeric = sortedByDistance([...new Set([...nums, ...ints])].filter((v) => (decl?.min === undefined || v >= decl.min) && (decl?.max === undefined || v <= decl.max)), typeof cur === 'number' ? cur : 0);
    const strs = [...new Set(pool.filter((v): v is string => typeof v === 'string' && !v.startsWith('\u0000')))];
    let best: RepairCandidate | undefined;
    for (const v of [...numeric, ...strs]) {
      if (v === cur) continue;
      const a: AnalyzerAction = { ...action, params: { ...params, [name]: v } };
      const d = reaches(a);
      if (d !== null) {
        best = { repair: { kind: 'set_param', param: name, from: cur, to: v }, cost: 2 + (typeof v === 'number' && typeof cur === 'number' ? Math.min(1, Math.abs(v - cur) / (Math.abs(cur) + 1)) : 0.5), decision: d, action: a };
        break; // the pool is ordered nearest first
      }
    }
    if (best) cands.push(best);
  }

  // 2b. when no single edit works, the cheapest PAIR of edits (a parameter and the resource, or two parameters)
  if (!finish && cands.length === 0) {
    type Dim = { cost: number; make: (a: AnalyzerAction, v: unknown) => AnalyzerAction; step: (v: unknown) => Extract<Repair, { kind: 'set_param' | 'set_resource' }>; values: unknown[] };
    const dims: Dim[] = names.map((name) => {
      const field = pr.fields.find((f) => f.path === `action.params.${name}`);
      const decl = shape?.params[name];
      const vals = [...(field?.values ?? []), ...(decl?.values ?? [])].filter((v) => typeof v === 'string' ? !v.startsWith('\u0000') : typeof v === 'number').filter((v) => v !== params[name]);
      return { cost: 2, make: (a, v) => ({ ...a, params: { ...(a.params ?? {}), [name]: v } }), step: (v) => ({ kind: 'set_param', param: name, from: params[name], to: v }), values: [...new Set(vals)].slice(0, 6) };
    });
    dims.push({ cost: 3, make: (a, v) => ({ ...a, resource: v as string }), step: (v) => ({ kind: 'set_resource', from: action.resource, to: v as string }), values: pr.resources.filter((x) => !x.startsWith('\u0000') && x !== action.resource).slice(0, 6) });
    for (let i = 0; i < dims.length; i++) {
      for (let j = i + 1; j < dims.length; j++) {
        for (const x of dims[i]!.values) {
          for (const y of dims[j]!.values) {
            const a = dims[j]!.make(dims[i]!.make(action, x), y);
            const d = reaches(a);
            if (d !== null) cands.push({ repair: { kind: 'combine', steps: [dims[i]!.step(x), dims[j]!.step(y)] }, cost: dims[i]!.cost + dims[j]!.cost, decision: d, action: a });
          }
        }
      }
    }
  }

  // 3. another allowed resource
  for (const r of finish ? [] : pr.resources.filter((x) => !x.startsWith('\u0000') && x !== action.resource)) push({ kind: 'set_resource', from: action.resource, to: r }, 3, { ...action, resource: r });

  // 4. a named fact that is missing: a subject or env field the policy reads
  for (const f of finish ? [] : pr.fields.filter((x) => x.path.startsWith('subject.') || x.path.startsWith('env.'))) {
    const [root, ...rest] = f.path.split('.');
    for (const v of f.values.filter((x) => typeof x !== 'symbol')) {
      const a: AnalyzerAction = { ...action, [root as 'subject' | 'env']: setPath({ ...((action as unknown as Record<string, Record<string, unknown>>)[root!] ?? {}) }, rest, v) };
      const before = reaches(action);
      const d = reaches(a);
      if (d !== null && before === null) {
        cands.push({ repair: { kind: 'obtain_fact', path: f.path, value: v }, cost: 4, decision: d, action: a });
        break;
      }
    }
  }

  // 5. split (opt-in, and only when nothing meters the total)
  if (o.allowSplit === true && !meters(model)) {
    for (const name of names) {
      const cur = params[name];
      if (typeof cur !== 'number') continue;
      const flipped = cands.find((c) => c.repair.kind === 'set_param' && c.repair.param === name && typeof c.repair.to === 'number');
      const part = flipped && flipped.repair.kind === 'set_param' ? (flipped.repair.to as number) : undefined;
      if (part === undefined || part <= 0 || part >= cur) continue;
      const n = Math.ceil(cur / part);
      if (n > 8) continue;
      const parts = Array.from({ length: n }, (_, i) => ({ [name]: i < n - 1 ? part : cur - part * (n - 1) }));
      if (parts.every((p) => reaches({ ...action, params: { ...params, ...p } }) !== null)) cands.push({ repair: { kind: 'split', param: name, parts }, cost: 3 + n, decision: want, action });
    }
  }

  cands.sort((a, b) => a.cost - b.cost);
  const top = cands.slice(0, o.maxCandidates ?? 8);
  res.repairExists = top.length > 0;
  const redact = o.redact ?? 'critical';
  const hide = (c: RepairCandidate): RepairCandidate => {
    if (redact === 'none' || c.repair.kind !== 'set_param') return c;
    const sens = shape?.params[c.repair.param]?.sensitivity;
    if (redact === 'critical' && sens !== 'critical') return c;
    res.redacted = true;
    return { ...c, repair: { kind: 'set_param', param: c.repair.param, redacted: true }, action: { ...action } };
  };
  if (redact === 'all') {
    res.redacted = true;
  } else res.repairs = top.map(hide);
  const free = top.find((c) => c.decision === 'allow' && c.repair.kind !== 'split');
  if (free && current === 'escalate') res.humanFree = hide(free);
  if (current === 'escalate' || top.length === 0) {
    res.humanAsk = { verb: action.verb, resource: action.resource, params: { ...params }, kind: current === 'escalate' ? 'approval' : 'access-request', policyDigest };
  }
  return res;
}

function setPath(o: Record<string, unknown>, path: string[], v: unknown): Record<string, unknown> {
  const [k, ...rest] = path;
  if (k === undefined) return o;
  o[k] = rest.length === 0 ? v : setPath({ ...((o[k] as Record<string, unknown>) ?? {}) }, rest, v);
  return o;
}

/** Anything that bounds the total over several actions: a rate, a budget allocation. */
function meters(m: PolicyModel): boolean {
  return [...m.caveats, ...m.meets.flatMap((x) => x.caveats)].some((c) => c.type === 'rate' || c.type === 'budget_alloc' || c.type === 'max_blast_radius');
}

function waitTime(caveats: readonly Caveat[], ctx: CaveatContext): number | undefined {
  let at: number | undefined;
  for (const c of caveats) {
    if (c.type === 'not_before' && typeof c.at === 'number' && c.at > ctx.now) at = Math.max(at ?? 0, c.at);
    if (c.type === 'rate' && typeof c.max === 'number' && typeof c.per_secs === 'number') {
      const span = c.per_secs * 1000;
      const recent = (ctx.recentActionTimes ?? []).filter((t) => t > ctx.now - span).sort((a, b) => a - b);
      if (recent.length >= c.max) at = Math.max(at ?? 0, recent[recent.length - c.max]! + span);
    }
  }
  return at;
}
