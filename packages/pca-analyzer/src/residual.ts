import {
  evaluateConditionTri,
  hashCanonical,
  isGroupCondition,
  isLeafCondition,
  predicateMatches,
  resolvePath,
  type ActionContext,
  type Caveat,
  type Condition,
  type Predicate,
} from '@atlasauth/pca';
import { DEFAULT_MAX_COMBINATIONS, collectProbes, decide, decideAction, probeSet, productSize, repToAction, representatives, toModel, type PolicyModel, type Probes } from './enumerate';
import type { AnalyzerDecision, PolicyInput, TightenLike, Veto, VerbShape } from './types';
import type { AnalyzerOptions } from './index';

/**
 * PARTIAL EVALUATION, RESIDUAL POLICIES, "WHAT MAY I DO?" DISCOVERY AND DATA FILTERS
 * (borrowed-ideas item 5, security contract C-247..C-249).
 *
 * `residual(policy, known, {unknown})` specialises the policy to what is known about a request (verb, resource, principal
 * state, time, remaining budget) and leaves the unknown parameters symbolic. The residual is itself a policy
 * (`residualPolicy`), evaluated by the same evaluator, and it is EXACT: for every completion of the unknown fields the residual
 * decides what the original decides (property-tested against the real evaluator, which is the guard `residual(G)` is a subset
 * of `admits(G)` and more).
 *
 * Only constants are folded, and they are folded with the evaluator's own three-valued rules, so no condition is ever rewritten.
 * A condition that reads an unknown field stays as it was. A veto that reads an unknown field stays unknown and keeps firing
 * (an unknown that reaches a prohibition never prunes the veto): partial evaluation can only shrink the policy by facts.
 *
 * Everything here is advisory and lives outside the verifier: the verifier stays authoritative, the envelope only carries the
 * policy digest it was planned against.
 */

export interface KnownContext {
  verb?: string;
  resource?: string;
  params?: Record<string, unknown>;
  subject?: Record<string, unknown>;
  env?: Record<string, unknown>;
  reversibilityClass?: string;
}

export interface ResidualOptions {
  /** Dotted paths (or prefixes) that stay symbolic. Default: every parameter, `['action.params']`. */
  unknown?: string[];
  /** Keep the resource matcher symbolic even when `known.resource` is absent (the default: a missing resource is unknown). */
  resourceUnknown?: boolean;
}

export interface ResidualPart {
  predicates: Predicate[];
  caveats: Caveat[];
  vetoes: Veto[];
  tighten: TightenLike[];
}

export interface Residual {
  /** `never`: no completion is admitted. `always`: every completion is autonomous. `conditional`: depends on the unknowns. */
  decision: 'never' | 'always' | 'conditional';
  /** Why a `never` is certain, when it is. */
  reason?: string;
  /** The residual policy: evaluate it with the same evaluator on the full context. `meet` holds the ancestors of a delegation chain. */
  policy: ResidualPart & { meet?: ResidualPart[] };
  /** hashCanonical of the ORIGINAL policy, so a PCActn can cite the policy this was planned against. */
  policyDigest: string;
}

const isUnknownPath = (path: unknown, unknown: readonly string[]): boolean =>
  typeof path === 'string' && unknown.some((u) => path === u || path.startsWith(u + '.'));

type PE = { t: 'const'; v: 'true' | 'false' | 'unknown'; src: Condition } | { t: 'cond'; c: Condition };

function pe(c: Condition, ctx: ActionContext, unk: readonly string[]): PE {
  if (c === null || typeof c !== 'object') return { t: 'const', v: 'unknown', src: c };
  if (isGroupCondition(c)) {
    if ('all_of' in c && Array.isArray(c.all_of) && c.all_of.length > 0) {
      const rs = c.all_of.map((x) => pe(x, ctx, unk));
      if (rs.some((r) => r.t === 'const' && r.v === 'false')) return { t: 'const', v: 'false', src: c };
      const kept = rs.filter((r) => !(r.t === 'const' && r.v === 'true'));
      if (kept.length === 0) return { t: 'const', v: 'true', src: c };
      if (kept.every((r) => r.t === 'const')) return { t: 'const', v: 'unknown', src: c };
      const cs = kept.map((r) => (r.t === 'const' ? r.src : r.c));
      return { t: 'cond', c: cs.length === 1 ? cs[0]! : { all_of: cs } };
    }
    if ('any_of' in c && Array.isArray(c.any_of) && c.any_of.length > 0) {
      const rs = c.any_of.map((x) => pe(x, ctx, unk));
      if (rs.some((r) => r.t === 'const' && r.v === 'true')) return { t: 'const', v: 'true', src: c };
      const kept = rs.filter((r) => !(r.t === 'const' && r.v === 'false'));
      if (kept.length === 0) return { t: 'const', v: 'false', src: c };
      if (kept.every((r) => r.t === 'const')) return { t: 'const', v: 'unknown', src: c };
      const cs = kept.map((r) => (r.t === 'const' ? r.src : r.c));
      return { t: 'cond', c: cs.length === 1 ? cs[0]! : { any_of: cs } };
    }
    if ('not' in c) {
      const r = pe(c.not, ctx, unk);
      if (r.t === 'cond') return { t: 'cond', c: { not: r.c } };
      return { t: 'const', v: r.v === 'true' ? 'false' : r.v === 'false' ? 'true' : 'unknown', src: c };
    }
    return { t: 'const', v: 'unknown', src: c }; // empty group: the evaluator says unknown
  }
  if (isLeafCondition(c) && (isUnknownPath(c.field, unk) || isUnknownPath(c.ref, unk) || isUnknownPath(c.collection, unk))) return { t: 'cond', c };
  return { t: 'const', v: evaluateConditionTri(c, ctx), src: c };
}

/** AND of a `where` list (implicit all_of): a const, or the symbolic remainder. */
function peAll(where: readonly Condition[] | undefined, ctx: ActionContext, unk: readonly string[]): { v: 'true' | 'false' | 'unknown' } | { cs: Condition[] } {
  if (where === undefined) return { v: 'true' };
  if (!Array.isArray(where)) return { v: 'unknown' };
  const rs = where.map((w) => pe(w, ctx, unk));
  if (rs.some((r) => r.t === 'const' && r.v === 'false')) return { v: 'false' };
  const kept = rs.filter((r) => !(r.t === 'const' && r.v === 'true'));
  if (kept.length === 0) return { v: 'true' };
  if (kept.every((r) => r.t === 'const')) return { v: 'unknown' };
  return { cs: kept.map((r) => (r.t === 'const' ? r.src : r.c)) };
}

function contextOf(k: KnownContext): ActionContext {
  const action: ActionContext['action'] = { verb: k.verb ?? '\u0000unknown-verb\u0000', resource: k.resource ?? '\u0000unknown-resource\u0000', params: { ...(k.params ?? {}) } };
  if (k.reversibilityClass !== undefined) action.reversibility_class = k.reversibilityClass;
  return { action, subject: { ...(k.subject ?? {}) }, env: { ...(k.env ?? {}) } };
}

export function policyDigestOf(model: PolicyModel): string {
  return hashCanonical({ predicates: model.predicates, caveats: model.caveats, vetoes: model.vetoes, tighten: model.tighten, meet: model.meets.map(policyDigestOf) });
}

function flatten(m: PolicyModel): PolicyModel[] {
  return [m, ...m.meets.flatMap(flatten)];
}

function residualPart(part: PolicyModel, ctx: ActionContext, unk: readonly string[], verbKnown: boolean, resKnown: boolean): ResidualPart {
  const predicates: Predicate[] = [];
  for (const p of part.predicates) {
    if (p === null || typeof p !== 'object') continue;
    if (verbKnown && !predicateMatches({ verb: p.verb, resource: '*' }, ctx)) continue;
    if (resKnown && !predicateMatches({ verb: '*', resource: p.resource }, ctx)) continue;
    const w = peAll(p.where, ctx, unk);
    if ('v' in w && w.v !== 'true') continue; // false and unknown both fail closed for a permit
    predicates.push({ verb: verbKnown ? '*' : p.verb, ...(!resKnown && p.resource !== undefined ? { resource: p.resource } : {}), ...('cs' in w ? { where: w.cs } : {}) });
  }
  const vetoes = part.vetoes.map((v) => peVeto(v, ctx, unk, verbKnown, resKnown)).filter((v): v is Veto => v !== null);
  const tighten: TightenLike[] = [];
  for (const t of part.tighten) {
    const r = pe(t.when, ctx, unk);
    if (r.t === 'const' && r.v === 'false') continue; // a veto-polarity rule that cleanly cannot hold
    tighten.push({ ...t, when: r.t === 'cond' ? r.c : t.when });
  }
  return { predicates, caveats: part.caveats, vetoes, tighten };
}

/** Specialise `policy` to `known`; everything under `unknown` stays symbolic. */
export function residual(policy: PolicyInput, known: KnownContext, opts: ResidualOptions = {}): Residual {
  const model = toModel(policy);
  const digest = policyDigestOf(model);
  const verbKnown = known.verb !== undefined;
  const resKnown = known.resource !== undefined && opts.resourceUnknown !== true;
  // a verb / resource that is not known is symbolic too, or a condition on it would be folded against a placeholder
  const unk = [...(opts.unknown ?? ['action.params']), ...(verbKnown ? [] : ['action.verb']), ...(resKnown ? [] : ['action.resource'])];
  const ctx = contextOf(known);
  const empty: ResidualPart = { predicates: [], caveats: [], vetoes: [], tighten: [] };
  const never = (reason: string): Residual => ({ decision: 'never', reason, policy: empty, policyDigest: digest });
  if (!model.caveatSat) return never(`caveats unsatisfiable: ${model.caveatReason ?? 'unknown'}`);
  if (known.reversibilityClass !== undefined && model.revCap !== undefined) {
    const idx = ['reversible', 'rate_limited', 'irreversible'].indexOf(known.reversibilityClass);
    if (idx < 0 || idx > model.revCap) return never('reversibility class exceeds the caveat cap');
  }
  const parts = flatten(model).map((m) => residualPart(m, ctx, unk, verbKnown, resKnown));
  const [own, ...rest] = parts as [ResidualPart, ...ResidualPart[]];
  const res: Residual = { decision: 'conditional', policy: { ...own, ...(rest.length > 0 ? { meet: rest } : {}) }, policyDigest: digest };
  if (parts.some((p) => p.predicates.length === 0)) return never('no permit survives the known facts');
  for (const p of parts) {
    const certain = p.vetoes.find((v) => v.kind === 'deny' && (v.when.resource === undefined || v.when.resource === '*') && (v.when.where === undefined || v.when.where.length === 0) && v.unless === undefined && v.over === undefined);
    if (certain) return never(`veto ${certain.id} applies to every completion`);
  }
  if (parts.every((p) => p.predicates.some((x) => x.where === undefined) && p.vetoes.length === 0 && p.tighten.length === 0)) res.decision = 'always';
  return res;
}

function peVeto(v: Veto, ctx: ActionContext, unk: readonly string[], verbKnown: boolean, resKnown: boolean): Veto | null {
  if (verbKnown && !predicateMatches({ verb: v.when.verb, resource: '*' }, ctx)) return null;
  if (resKnown && v.when.resource !== undefined && !predicateMatches({ verb: '*', resource: v.when.resource }, ctx)) return null;
  const w = peAll(v.when.where, ctx, unk);
  // veto polarity: a clean false removes the veto; true and unknown mean it applies
  if ('v' in w && w.v === 'false') return null;
  let keep: Condition[] | undefined;
  if ('cs' in w) keep = w.cs;
  const out: Veto = { id: v.id, kind: v.kind, when: { verb: verbKnown ? '*' : v.when.verb, ...(!resKnown && v.when.resource !== undefined ? { resource: v.when.resource } : {}), ...(keep ? { where: keep } : {}) } };
  if (v.over) {
    if (isUnknownPath(v.over.path, unk)) out.over = v.over;
    else {
      const r = resolvePath(ctx, v.over.path);
      const over = !r.found || typeof r.value !== 'number' || !Number.isFinite(r.value) || r.value < 0 || r.value > v.over.threshold;
      if (!over) return null;
    }
  }
  if (v.unless && v.kind === 'approval') out.unless = v.unless; // the evidence of approval: carried, never used to drop the veto
  else if (v.unless) {
    const u = peAll(v.unless, ctx, unk);
    if ('cs' in u) out.unless = u.cs;
    else if (u.v === 'true') return null; // the exception certainly holds: the veto never applies
    // an exception that certainly fails (false / unknown) leaves the veto unconditional
  }
  return out;
}

/** The residual as a policy the analyzer and the real evaluator both understand. */
export function residualPolicy(r: Residual): PolicyInput {
  const { meet, ...own } = r.policy;
  return { ...own, ...(meet ? { meet: meet.map((m) => ({ ...m })) } : {}) };
}

/** Ternary decision of a residual once the unknown fields are bound (the exactness property is stated on this). */
export function evaluateResidual(r: Residual, ctx: ActionContext): AnalyzerDecision {
  if (r.decision === 'never') return 'deny';
  return decideAction(toModel(residualPolicy(r)), {
    verb: ctx.action.verb,
    resource: ctx.action.resource,
    ...(ctx.action.params ? { params: ctx.action.params } : {}),
    ...(ctx.subject ? { subject: ctx.subject } : {}),
    ...(ctx.env ? { env: ctx.env } : {}),
    ...(ctx.action.reversibility_class ? { reversibilityClass: ctx.action.reversibility_class } : {}),
  });
}

// ---- "what may I do?" -----------------------------------------------------------------------------

export interface NumRange {
  lo?: number;
  hi?: number;
  loInclusive?: boolean;
  hiInclusive?: boolean;
}

export type ParamDomain =
  | { kind: 'numeric'; autonomous: NumRange[]; withApproval: NumRange[] }
  | { kind: 'enum'; autonomous: string[]; withApproval: string[]; otherAutonomous: boolean; otherWithApproval: boolean }
  | { kind: 'unconstrained' };

export interface CapabilityEnvelope {
  verb: string;
  status: 'autonomous' | 'needs-approval' | 'denied';
  /** Per declared parameter, the values still allowed after the known facts are fixed. */
  params: Record<string, ParamDomain>;
  /** Resource values / classes admitted (`other: true` = a resource the policy never names is admitted too). */
  resources: { autonomous: string[]; withApproval: string[]; other: boolean };
  /** The policy this envelope was planned against; cite it in the PCActn. */
  policyDigest: string;
  /** Caller-supplied facts passed through unchanged (remaining budget, undischarged third-party caveats). */
  remaining?: Record<string, number>;
  missingDischarges?: string[];
  advisory: true;
  approximate?: boolean;
  reason?: string;
}

export interface WhatMayIDoOptions extends AnalyzerOptions {
  remaining?: Record<string, number>;
  missingDischarges?: string[];
}

function mergeRanges(rs: NumRange[]): NumRange[] {
  const sorted = [...rs].sort((a, b) => (a.lo ?? -Infinity) - (b.lo ?? -Infinity) || Number(!!b.loInclusive) - Number(!!a.loInclusive));
  const out: NumRange[] = [];
  for (const r of sorted) {
    const last = out[out.length - 1];
    if (last && (last.hi ?? Infinity) >= (r.lo ?? -Infinity) && !((last.hi ?? Infinity) === (r.lo ?? -Infinity) && !last.hiInclusive && !r.loInclusive)) {
      if ((r.hi ?? Infinity) > (last.hi ?? Infinity) || ((r.hi ?? Infinity) === (last.hi ?? Infinity) && r.hiInclusive)) {
        if (r.hi === undefined) delete last.hi;
        else last.hi = r.hi;
        if (r.hiInclusive) last.hiInclusive = true;
        else delete last.hiInclusive;
      }
    } else out.push({ ...r });
  }
  return out;
}

/** The numeric cells of a threshold list as ranges (thresholds are points; between them are open intervals). */
function cellRange(value: number, T: readonly number[]): NumRange {
  const i = T.indexOf(value);
  if (i >= 0) return { lo: value, hi: value, loInclusive: true, hiInclusive: true };
  const below = [...T].reverse().find((t) => t < value);
  const above = T.find((t) => t > value);
  return { ...(below !== undefined ? { lo: below } : {}), ...(above !== undefined ? { hi: above } : {}) };
}

/**
 * Per verb of the schema: is it autonomous, approval-only or denied for the known principal, and which parameter values are
 * still allowed. Enumerates the grid of the residual policy (sound on the decided fragment; otherwise `approximate`, and the
 * ranges are then a conservative superset only for values actually admitted by a verified representative).
 */
export function whatMayIDo(policy: PolicyInput, verbs: readonly VerbShape[], known: KnownContext = {}, o: WhatMayIDoOptions = {}): CapabilityEnvelope[] {
  const out: CapabilityEnvelope[] = [];
  const max = typeof o.maxCombinations === 'number' ? o.maxCombinations : DEFAULT_MAX_COMBINATIONS;
  for (const shape of verbs) {
    const res = residual(policy, { ...known, verb: shape.verb });
    const env: CapabilityEnvelope = {
      verb: shape.verb,
      status: 'denied',
      params: {},
      resources: { autonomous: [], withApproval: [], other: false },
      policyDigest: res.policyDigest,
      advisory: true,
    };
    if (o.remaining) env.remaining = { ...o.remaining };
    if (o.missingDischarges) env.missingDischarges = [...o.missingDischarges];
    if (res.decision === 'never') {
      env.reason = res.reason;
      out.push(env);
      continue;
    }
    const rp = toModel(residualPolicy(res));
    const extra = Object.entries(shape.params).flatMap(([name, d]) =>
      d.values !== undefined ? [{ path: `action.params.${name}`, cond: { field: `action.params.${name}`, op: 'in' as const, value: d.values } }] : [],
    );
    const extraNum = Object.entries(shape.params).flatMap(([name, d]) => [
      ...(d.min !== undefined ? [{ path: `action.params.${name}`, cond: { field: `action.params.${name}`, op: 'gte' as const, value: d.min } }] : []),
      ...(d.max !== undefined ? [{ path: `action.params.${name}`, cond: { field: `action.params.${name}`, op: 'lte' as const, value: d.max } }] : []),
    ]);
    const pr: Probes = collectProbes({ predicateSets: [probeSet(rp)], extraFieldConditions: [...extra, ...extraNum], varyReversibility: rp.revCap !== undefined });
    pr.verbs = [shape.verb];
    const declared = Object.keys(shape.params);
    for (const name of declared) {
      const path = `action.params.${name}`;
      if (!pr.fields.some((f) => f.path === path)) pr.fields.push({ path, values: [] });
    }
    if (productSize(pr) > max) {
      env.status = 'needs-approval';
      env.approximate = true;
      env.reason = 'representative grid exceeded the bound; no domain is claimed';
      out.push(env);
      continue;
    }
    if (known.resource !== undefined) pr.resources = [known.resource];
    const seen = new Map<string, Map<string, { value: unknown; allow: boolean; escalate: boolean }>>();
    const resSeen = new Map<string, { allow: boolean; escalate: boolean }>();
    let anyAllow = false;
    let anyEscalate = false;
    let freshResAllow = false;
    for (const rep of representatives(pr)) {
      const d = decide(rp, rep);
      if (d === 'deny') continue;
      if (d === 'allow') anyAllow = true;
      else anyEscalate = true;
      const act = repToAction(rep);
      for (const name of declared) {
        const v = (act.params ?? {})[name];
        const m = seen.get(name) ?? new Map();
        const k = v === undefined ? '\u0000absent' : JSON.stringify(v);
        const cur = m.get(k) ?? { value: v, allow: false, escalate: false };
        if (d === 'allow') cur.allow = true;
        else cur.escalate = true;
        m.set(k, cur);
        seen.set(name, m);
      }
      const rr = resSeen.get(act.resource) ?? { allow: false, escalate: false };
      if (d === 'allow') rr.allow = true;
      else rr.escalate = true;
      resSeen.set(act.resource, rr);
      if (act.resource.startsWith('\u0000')) freshResAllow = true;
    }
    env.status = anyAllow ? 'autonomous' : anyEscalate ? 'needs-approval' : 'denied';
    for (const name of declared) {
      const decl = shape.params[name]!;
      const path = `action.params.${name}`;
      const T = thresholdsOf(rp, path);
      const m = seen.get(name) ?? new Map();
      const vals = [...m.values()];
      const nums = vals.filter((x) => typeof x.value === 'number' && (decl.min === undefined || x.value >= decl.min) && (decl.max === undefined || x.value <= decl.max)); // a value the schema forbids is not part of the domain
      const strs = vals.filter((x) => typeof x.value === 'string');
      if (decl.type === 'integer' || nums.length > 0) {
        const lo = decl.min;
        const hi = decl.max;
        const clip = (r: NumRange): NumRange => ({
          ...r,
          ...(lo !== undefined && (r.lo === undefined || r.lo < lo) ? { lo, loInclusive: true } : {}),
          ...(hi !== undefined && (r.hi === undefined || r.hi > hi) ? { hi, hiInclusive: true } : {}),
        });
        const ranges = (pick: (x: { allow: boolean; escalate: boolean }) => boolean) => mergeRanges(nums.filter((x) => pick(x)).map((x) => clip(cellRange(x.value as number, T))));
        env.params[name] = { kind: 'numeric', autonomous: ranges((x) => x.allow), withApproval: ranges((x) => x.escalate && !x.allow) };
      } else if (decl.values !== undefined || strs.length > 0) {
        const pickList = (f: (x: { allow: boolean; escalate: boolean }) => boolean) => strs.filter((x) => f(x) && !(x.value as string).startsWith('\u0000')).map((x) => x.value as string).sort();
        const fresh = strs.find((x) => (x.value as string).startsWith('\u0000'));
        env.params[name] = {
          kind: 'enum',
          autonomous: pickList((x) => x.allow),
          withApproval: pickList((x) => x.escalate && !x.allow),
          otherAutonomous: decl.values === undefined && fresh?.allow === true,
          otherWithApproval: decl.values === undefined && fresh !== undefined && fresh.escalate && !fresh.allow,
        };
      } else env.params[name] = { kind: 'unconstrained' };
    }
    const names = [...resSeen.entries()].filter(([r]) => !r.startsWith('\u0000'));
    env.resources = {
      autonomous: names.filter(([, v]) => v.allow).map(([r]) => r).sort(),
      withApproval: names.filter(([, v]) => v.escalate && !v.allow).map(([r]) => r).sort(),
      other: freshResAllow,
    };
    if (rp.undecidable.length > 0) {
      env.approximate = true;
      env.reason = `over-approximated (${rp.undecidable.join('; ')})`;
    }
    out.push(env);
  }
  return out;
}

function thresholdsOf(model: PolicyModel, path: string): number[] {
  const out: number[] = [];
  const walk = (c: Condition): void => {
    if (c === null || typeof c !== 'object') return;
    if (isGroupCondition(c)) {
      if ('all_of' in c && Array.isArray(c.all_of)) c.all_of.forEach(walk);
      else if ('any_of' in c && Array.isArray(c.any_of)) c.any_of.forEach(walk);
      else if ('not' in c) walk(c.not);
      return;
    }
    if (!isLeafCondition(c) || c.field !== path) return;
    if (typeof c.value === 'number' && Number.isFinite(c.value)) out.push(c.value);
    else if (Array.isArray(c.value)) for (const x of c.value) if (typeof x === 'number' && Number.isFinite(x)) out.push(x);
  };
  for (const p of probeSet(model)) (p.where ?? []).forEach(walk);
  for (const v of model.vetoes) if (v.over?.path === path) out.push(v.over.threshold);
  return [...new Set(out)].sort((a, b) => a - b);
}

