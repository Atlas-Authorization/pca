/* eslint-disable @typescript-eslint/no-explicit-any */
// ext-taint.ts - typed adapter over the PROVED taint decisions (formal/dafny/Taint.dfy -> generated/pca_taint.js).
// The glue here only evaluates primitives (typeof checks, registry lookup, resource-graph lookup, string length) and hands FACTS to the
// proved code; the join, classification, fail-closed pre-checks and gate are the Dafny functions.
import BigNumber from 'bignumber.js';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const T = (require('../generated/pca_taint.js') as { _dafny: any; Taint: any }).Taint;
// eslint-disable-next-line @typescript-eslint/no-require-imports
const dafny = (require('../generated/pca_taint.js') as { _dafny: any }) ._dafny;

export const TAINT_LEVELS = ['trusted', 'first_party', 'tool', 'web', 'agent'] as const;
export type TaintLevel = (typeof TAINT_LEVELS)[number];
export type TaintLabel =
  | { kind: 'trusted' }
  | { kind: 'first_party' }
  | { kind: 'tool'; id?: string }
  | { kind: 'web' }
  | { kind: 'agent'; id?: string };

const KIND_CTOR: Record<TaintLevel, string> = {
  trusted: 'create_Trusted',
  first_party: 'create_FirstParty',
  tool: 'create_Tool',
  web: 'create_Web',
  agent: 'create_Agent',
};
const OWN = Object.prototype.hasOwnProperty;
/** Own-property kind check (the same own-key lookup production uses: inherited keys such as 'constructor' are not levels). */
export const isTaintLevel = (k: unknown): k is TaintLevel => typeof k === 'string' && OWN.call(KIND_CTOR, k);

/** Interns ids (strings or absent) to the Dafny nat the proofs reason about. Only equality matters. */
class Ids {
  private readonly m = new Map<unknown, number>();
  private readonly rev: unknown[] = [];
  to(id: unknown): any {
    if (id === undefined) return T.Option.create_None();
    let n = this.m.get(id);
    if (n === undefined) {
      n = this.rev.length;
      this.m.set(id, n);
      this.rev.push(id);
    }
    return T.Option.create_Some(new BigNumber(n));
  }
  from(o: any): unknown {
    return o.is_Some ? this.rev[(o.dtor_v as BigNumber).toNumber()] : undefined;
  }
}

const kindOut = (k: any): TaintLevel => (k.is_Trusted ? 'trusted' : k.is_FirstParty ? 'first_party' : k.is_Tool ? 'tool' : k.is_Web ? 'web' : 'agent');
function labelIn(l: { kind: TaintLevel; id?: unknown }, ids: Ids): any {
  const id = Object.hasOwn(l, 'id') ? l.id : undefined; // production labelId: own `id` only
  return T.Label.create_Label(T.Kind[KIND_CTOR[l.kind]](), ids.to(id));
}
function labelOut(d: any, ids: Ids): TaintLabel {
  const kind = kindOut(d.dtor_kind);
  const id = ids.from(d.dtor_id);
  return (id === undefined ? { kind } : { kind, id }) as TaintLabel;
}
const seq = (a: readonly unknown[]): any => {
  const s = dafny.Seq.of();
  for (let i = 0; i < a.length; i++) s.push(a[i]);
  return s;
};

export const BOTTOM: TaintLabel = { kind: 'trusted' };
export const TOP: TaintLabel = { kind: 'agent' };
/** Proved RawRank: an unknown / inherited / non-string kind is the WORST rank (4), never undefined / NaN. */
export const labelRank = (l: TaintLabel): number => {
  const k = (l as { kind?: unknown } | null | undefined)?.kind;
  return T.__default.RawRank(isTaintLevel(k) ? T.Option.create_Some(T.Kind[KIND_CTOR[k]]()) : T.Option.create_None()).toNumber();
};
export const taintValue = (l: TaintLabel): number => labelRank(l) / 4;

/** Proved join (Taint.Join). Commutative, associative, idempotent; TOP absorbing. */
export function joinLabelVerified(a: TaintLabel, b: TaintLabel): TaintLabel {
  if (!isTaintLevel(a?.kind) || !isTaintLevel(b?.kind)) throw new TypeError('taint: unknown label kind');
  const ids = new Ids();
  return labelOut(T.__default.Join(labelIn(a, ids), labelIn(b, ids)), ids);
}
/** Proved seedless fold; the empty lineage is TOP (worst case). Order-independent (Taint.JoinListPerm). */
export function joinLabelsVerified(labels: readonly TaintLabel[]): TaintLabel {
  const ids = new Ids();
  const ls: any[] = [];
  for (const l of labels) {
    if (!isTaintLevel(l?.kind)) throw new TypeError('taint: unknown label kind');
    ls.push(labelIn(l, ids));
  }
  return labelOut(T.__default.JoinOrTop(seq(ls)), ids);
}

export interface TrustedInputRegistry {
  lookup(digest: string): TaintLabel | undefined;
}
export interface TaintContext {
  registry: TrustedInputRegistry;
  resourceGraph?: { node(id: string): unknown };
}
export interface TaintRefClassification {
  ref: string;
  label: TaintLabel;
}
export interface TaintResult {
  taint: number;
  label: TaintLabel;
  refs: TaintRefClassification[];
  valid: boolean;
  reason?: string;
}

const REASON: Array<[string, string]> = [
  ['is_NoRegistry', 'taint: no trusted-input registry'],
  ['is_ProvMalformed', 'taint: provenance is absent or malformed'],
  ['is_RefsNotArray', 'taint: trusted_refs must be an array'],
  ['is_RefsBadElem', 'taint: trusted_refs must be non-empty strings'],
];

/**
 * computeTaint over the proved core (Taint.ComputeSafe). Same observable behaviour as production `computeTaint` (registry/graph call order,
 * result shape, reason strings): own-key kind lookups (an unknown kind is not a vouching), sparse holes are bad elements, and it NEVER
 * throws: the glue evaluates the facts in production order and stops at the first exception, which the proof turns into an invalid,
 * worst-case result (`taint: evaluation error (fail closed): <message>`).
 */
export function computeTaintVerified(provenance: unknown, ctx: TaintContext): TaintResult {
  let threw = false;
  let errMsg = 'unknown';
  let regOk = false;
  let provObj = false;
  let shape: any = T.Shape.create_Undef();
  const ids = new Ids();
  const facts: any[] = [];
  const refs: string[] = [];
  try {
    regOk = !!ctx && !!ctx.registry && typeof ctx.registry.lookup === 'function';
    if (regOk) provObj = provenance !== null && typeof provenance === 'object' && !Array.isArray(provenance);
    let list: unknown[] = [];
    if (regOk && provObj) {
      const raw = (provenance as { trusted_refs?: unknown }).trusted_refs;
      if (raw !== undefined) {
        if (!Array.isArray(raw)) shape = T.Shape.create_NotArr();
        else {
          let bad = false;
          for (let i = 0; i < raw.length; i++) {
            const r = raw[i];
            if (typeof r !== 'string' || r.length === 0) {
              bad = true;
              break;
            }
          }
          shape = T.Shape.create_Arr(bad);
          list = raw;
        }
      }
    }
    if (T.__default.Precheck(regOk, provObj, shape).is_Ok) {
      for (let i = 0; i < list.length; i++) {
        const ref = list[i] as string;
        let vouched: any = T.Vouch.create_VNone();
        const v = ctx.registry.lookup(ref);
        if (v) {
          const k = (v as { kind?: unknown }).kind;
          vouched = isTaintLevel(k) ? T.Vouch.create_VKnown(labelIn(v as any, ids)) : T.Vouch.create_VUnknown();
        }
        let graphHit = false;
        if (!vouched.is_VKnown) {
          try {
            if (ctx.resourceGraph?.node(ref)) graphHit = true;
          } catch {
            /* worst case */
          }
        }
        facts.push(T.RefFact.create_RefFact(vouched, graphHit, ref.length <= 128 ? ids.to(ref) : T.Option.create_None()));
        refs.push(ref);
      }
    }
  } catch (e) {
    threw = true;
    errMsg = e instanceof Error ? e.message : 'unknown';
  }
  const res = T.__default.ComputeSafe(threw, regOk, provObj, shape, seq(facts));
  if (!res.dtor_valid) {
    const why = res.dtor_reason.is_EvalError ? `taint: evaluation error (fail closed): ${errMsg}` : REASON.find(([f]) => res.dtor_reason[f])![1];
    return { taint: 1, label: { ...TOP }, refs: [], valid: false, reason: why };
  }
  const cls = T.__default.ClassifyAll(seq(facts));
  const label = labelOut(res.dtor_lab, ids);
  return {
    taint: T.__default.TaintRank(res).toNumber() / 4,
    label,
    refs: refs.map((ref, i) => ({ ref, label: labelOut(cls[i], ids) })),
    valid: true,
  };
}

export type TaintGateOutcome = { ok: true } | { ok: false; reason: string };
/**
 * The enforce.taint gate decision (pcactn.ts) over the proved Gate. `allowedMax` = largest rank r with r/4 <= maxTaint (glue; exact in
 * IEEE doubles since r/4 is a dyadic rational).
 */
export function taintGateVerified(provenance: unknown, ctx: TaintContext, maxTaint: number): TaintGateOutcome {
  try {
    const t = computeTaintVerified(provenance, ctx);
    const maxOk = (maxTaint as number) >= 0;
    let allowed = -1;
    for (let r = 0; r <= 4; r++) if (r / 4 <= maxTaint) allowed = r;
    const g = T.__default.Gate(t.valid, maxOk, new BigNumber(t.valid ? labelRank(t.label) : 4), new BigNumber(allowed));
    if (g.is_GatePass) return { ok: true };
    if (g.is_GateInvalid) return { ok: false, reason: t.reason ?? 'provenance lineage is not server-verifiable (fail closed)' };
    if (g.is_GateMisconfigured) return { ok: false, reason: 'taint gate misconfigured: maxTaint must be a non-negative number (fail closed)' };
    return { ok: false, reason: `information-flow taint ${t.taint} exceeds policy max ${maxTaint}` };
  } catch (e) {
    return { ok: false, reason: `taint gate error (fail closed): ${(e as Error).message}` };
  }
}

/** max(computed, claim) over the rank scale (Taint.Combine): the agent's claim can only raise, never lower. */
export function combineTaintRank(computedRank: number, claimRank: number): number {
  return T.__default.Combine(new BigNumber(computedRank), new BigNumber(claimRank)).toNumber();
}
