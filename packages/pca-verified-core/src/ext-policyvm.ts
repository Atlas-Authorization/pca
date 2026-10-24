/* eslint-disable @typescript-eslint/no-explicit-any */
// ext-policyvm.ts - typed adapter over the Dafny-proved predicate / caveat / Policy-VM decision core (formal/dafny/PolicyVm.dfy,
// compiled to generated/pca_policyvm.js). Takes plain JS values (as the production predicates.ts does), converts them to the
// proved value model, runs the PROVED code, and returns plain results. Dafny runtime types never leak.
//
// Out of the value model (the converter THROWS PolicyVmUnsupported, so a caller can fall back to production code):
// cyclic data, sparse-array holes, accessor properties, objects with non-Object.prototype / non-null prototypes are kept (as non-plain),
// Proxy traps are not observable here. Everything the production code reads from JSON-like data is covered.
import { hardenDafnyRuntime } from './runtime';
import BigNumber from 'bignumber.js';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const gen = require('../generated/pca_policyvm.js') as { _dafny: any; PolicyVm: any };
const D = hardenDafnyRuntime(gen._dafny);
const P = gen.PolicyVm;
const F = P.__default;

export class PolicyVmUnsupported extends Error {
  constructor(m: string) {
    super(`pca-verified-core/policyvm: unsupported input (${m})`);
    this.name = 'PolicyVmUnsupported';
  }
}

// ---- strings (UTF-16 code units, exactly like JS) ----------------------------------------------------------------------------
export function toStr(s: string): any {
  const a = D.Seq.of();
  for (let i = 0; i < s.length; i++) a.push(s.charCodeAt(i));
  return a;
}
export function fromStr(q: any): string {
  let out = '';
  const n = q.length;
  for (let i = 0; i < n; i += 4096) out += String.fromCharCode.apply(null, Array.prototype.slice.call(q, i, Math.min(n, i + 4096)));
  return out;
}

// ---- exact rationals for doubles ----------------------------------------------------------------------------------------------
const f64 = new Float64Array(1);
const u64 = new BigUint64Array(f64.buffer);
const ZERO_Q = new D.BigRational(new BigNumber(0), new BigNumber(1));
/** The exact rational value of a finite double (numerator/denominator in lowest terms; the denominator is a power of two). */
export function toRat(x: number): any {
  if (Number.isInteger(x) && Math.abs(x) <= Number.MAX_SAFE_INTEGER) return new D.BigRational(new BigNumber(x === 0 ? 0 : x), new BigNumber(1));
  f64[0] = x;
  const bits = u64[0]!;
  const sign = bits >> 63n ? -1n : 1n;
  const e = Number((bits >> 52n) & 0x7ffn);
  let m = bits & 0xfffffffffffffn;
  let exp: number;
  if (e === 0) exp = -1074;
  else {
    m |= 1n << 52n;
    exp = e - 1075;
  }
  if (m === 0n) return ZERO_Q;
  while ((m & 1n) === 0n) {
    m >>= 1n;
    exp++;
  }
  let num = new BigNumber((sign * m).toString());
  let den = new BigNumber(1);
  if (exp >= 0) num = num.multipliedBy(new BigNumber(2).pow(exp));
  else den = new BigNumber(2).pow(-exp);
  return new D.BigRational(num, den);
}
/** Inverse of {@link toRat} for rationals produced by it (power-of-two denominators). */
export function ratToDouble(q: any): number {
  const num: BigNumber = q.num;
  const den: BigNumber = q.den;
  if (den.isEqualTo(1)) return num.toNumber();
  const k = den.toString(2).length - 1;
  return num.toNumber() * 2 ** -k;
}
const HUGE = new BigNumber(2).pow(2000);
/** A double that may be +-Infinity back to a rational that compares identically with every finite double. */
function toRatSat(x: number): any {
  if (x === Infinity) return new D.BigRational(HUGE, new BigNumber(1));
  if (x === -Infinity) return new D.BigRational(HUGE.negated(), new BigNumber(1));
  return toRat(x);
}

// ---- JS value <-> proved value model --------------------------------------------------------------------------------------------
const orig = new WeakMap<object, unknown>(); // Dafny Value -> the JS object it was built from (for the tool_schema oracle)
const VNull = P.Value.create_VNull();
const VUndef = P.Value.create_VUndef();
const VNonFinite = P.Value.create_VNonFinite();
const VFn = P.Value.create_VFn();
const VTrue = P.Value.create_VBool(true);
const VFalse = P.Value.create_VBool(false);

export function toValue(x: unknown, path: object[] = []): any {
  switch (typeof x) {
    case 'undefined':
      return VUndef;
    case 'boolean':
      return x ? VTrue : VFalse;
    case 'number':
      // negz: exactly the JS -0 (Object.is), so the model sees what isNonNeg-style integer checks see (PolicyVm.dfy NegZeroWf)
      return Number.isFinite(x) ? P.Value.create_VNum(toRat(x), Object.is(x, -0)) : VNonFinite;
    case 'string':
      return P.Value.create_VStr(toStr(x));
    case 'function':
    case 'bigint':
    case 'symbol':
      return VFn;
    default:
      break;
  }
  if (x === null) return VNull;
  const o = x as object;
  if (path.includes(o)) throw new PolicyVmUnsupported('cyclic value');
  path.push(o);
  try {
    let v: any;
    if (Array.isArray(o)) {
      const xs = D.Seq.of();
      for (let i = 0; i < o.length; i++) {
        if (!(i in o)) throw new PolicyVmUnsupported('sparse array');
        xs.push(toValue(o[i], path));
      }
      v = P.Value.create_VArr(xs);
    } else {
      const names = Object.getOwnPropertyNames(o);
      const keys = Object.keys(o);
      if (names.length !== keys.length) throw new PolicyVmUnsupported('non-enumerable own property');
      const es = D.Seq.of();
      for (const k of keys) {
        const d = Object.getOwnPropertyDescriptor(o, k)!;
        if (!('value' in d)) throw new PolicyVmUnsupported('accessor property');
        es.push(P.Entry.create_Entry(toStr(k), toValue(d.value, path)));
      }
      const proto = Object.getPrototypeOf(o);
      v = P.Value.create_VObj(es, proto === Object.prototype || proto === null);
    }
    orig.set(v, o);
    return v;
  } finally {
    path.pop();
  }
}

// ---- oracles ----------------------------------------------------------------------------------------------------------------------
export interface PolicyVmOracles {
  /** isSafeRegexSource (the guard). */
  safeRegex(src: string): boolean;
  /** safeRegexFullMatch; null = unsupported / over budget. */
  regexFullMatch(src: string, subject: string): boolean | null;
  /** The `tool_schema` caveat evaluator (agent-native.ts toolSchemaEvaluator); absent => fail closed (false). */
  toolSchema?(caveat: unknown, ctx: unknown): boolean;
}

export type Tri = 'true' | 'false' | 'unknown';
const triOf = (t: any): Tri => (t.is_TT ? 'true' : t.is_TF ? 'false' : 'unknown');

export interface PredicateResultV {
  allowed: boolean;
  matched?: unknown;
  reason?: string;
}

export interface PolicyVm {
  resolvePath(ctx: unknown, path: unknown): { found: boolean; value?: unknown };
  evaluateConditionTri(c: unknown, ctx: unknown): Tri;
  evaluateCondition(c: unknown, ctx: unknown): boolean;
  predicateMatches(p: unknown, ctx: unknown): boolean;
  evaluatePredicates(predicates: unknown, ctx: unknown): PredicateResultV;
  envelopeCaveatEvaluator(caveat: unknown, ctx: unknown): boolean;
  agentNativeCaveatEvaluator(caveat: unknown, ctx: unknown): boolean;
  evaluateCaveats(caveats: unknown, ctx: unknown, evaluator?: 'envelope' | 'agent'): { ok: boolean; failed: string[] };
  /** policy-vm.ts rootCaveats over a grant's caveat list (0.4.1): every entry but the first `envelope`; a non-array is returned as is. */
  rootCaveats(caveats: unknown): unknown;
  /** Visited condition nodes and the verdict (the proved bound: visited <= size of the tree). */
  evaluateConditionCounted(c: unknown, ctx: unknown): { tri: Tri; visited: number };
}

const lo = (now: any, per: any): any => toRatSat(ratToDouble(now) - ratToDouble(per) * 1000);

export function createPolicyVm(o: PolicyVmOracles): PolicyVm {
  const rx = P.Rx.create_Rx(
    (src: any) => {
      try {
        return o.safeRegex(fromStr(src)) === true;
      } catch {
        return false;
      }
    },
    (src: any, subj: any) => {
      try {
        const r = o.regexFullMatch(fromStr(src), fromStr(subj));
        return r === null || r === undefined ? P.Option.create_None() : P.Option.create_Some(r === true);
      } catch {
        return P.Option.create_None();
      }
    },
  );
  const tool = (cv: any, ctx: any): boolean => {
    if (!o.toolSchema) return false;
    try {
      return o.toolSchema(orig.get(cv), orig.get(ctx)) === true;
    } catch {
      return false;
    }
  };
  const envelopeEv = (cv: any, ctx: any) => F.EnvelopeEv(cv, ctx, lo);
  const agentEv = (cv: any, ctx: any) => F.AgentEv(cv, ctx, rx, lo, tool);
  return {
    resolvePath(ctx, path) {
      const r = F.ResolvePath(toValue(ctx), toValue(path));
      if (!r.dtor_found) return { found: false };
      // return the ORIGINAL JS value (identity preserved), re-walking it is not needed: rebuild by following the same path
      return { found: true, value: followPath(ctx, path as string) };
    },
    evaluateConditionTri: (c, ctx) => triOf(F.EvalTri(toValue(c), toValue(ctx), rx)),
    evaluateCondition: (c, ctx) => F.EvalTri(toValue(c), toValue(ctx), rx).is_TT === true,
    predicateMatches: (p, ctx) => F.PredicateMatches(toValue(p), toValue(ctx), rx) === true,
    evaluatePredicates(predicates, ctx) {
      const pv = toValue(predicates);
      const cv = toValue(ctx);
      const r = F.EvalPredicates(pv, cv, rx);
      if (r.dtor_allowed) return { allowed: true, matched: (predicates as unknown[])[r.dtor_idx.toNumber()] };
      if (r.dtor_why.toNumber() === 1) return { allowed: false, reason: 'envelope grants no predicates' };
      const a = (ctx as any)?.action;
      return { allowed: false, reason: `no predicate permits ${String(a?.verb)} on ${String(a?.resource)}` };
    },
    envelopeCaveatEvaluator: (cv, ctx) => envelopeEv(toValue(cv), toValue(ctx)) === true,
    agentNativeCaveatEvaluator: (cv, ctx) => agentEv(toValue(cv), toValue(ctx)) === true,
    evaluateCaveats(caveats, ctx, evaluator = 'envelope') {
      const cx = toValue(ctx);
      const ev = evaluator === 'agent' ? (cv: any) => agentEv(cv, cx) : (cv: any) => envelopeEv(cv, cx);
      const r = F.EvalCaveatList(toValue(caveats), ev);
      return { ok: r.dtor_ok === true, failed: (Array.from(r.dtor_failed) as any[]).map(fromStr) };
    },
    rootCaveats(caveats) {
      if (!Array.isArray(caveats)) return caveats;
      // map the proved selection back to the ORIGINAL caveat objects (identity preserved for the evaluator's oracles)
      const vs = (caveats as unknown[]).map((c) => toValue(c));
      const kept = Array.from(F.RootCaveats(D.Seq.of(...vs)) as any[]);
      const out: unknown[] = [];
      let j = 0;
      for (let i = 0; i < vs.length && j < kept.length; i++) if (vs[i] === kept[j]) { out.push((caveats as unknown[])[i]); j++; }
      if (j !== kept.length) throw new PolicyVmUnsupported('rootCaveats: selection is not a subsequence');
      return out;
    },
    evaluateConditionCounted(c, ctx) {
      const r = F.EvalTriC(toValue(c), toValue(ctx), rx);
      return { tri: triOf(r[0]), visited: (r[1] as BigNumber).toNumber() };
    },
  };
}

function followPath(ctx: unknown, path: string): unknown {
  const segs = path.split('.');
  let cur: any = (ctx as any)?.[segs[0]!];
  for (let i = 1; i < segs.length; i++) cur = Array.isArray(cur) ? cur[Number(segs[i])] : cur[segs[i]!];
  return cur;
}

// ---- decision kernels (thresholds, admission, escalation) -----------------------------------------------------------------------
export interface RequiredThresholdV {
  t: 1 | 2 | 3;
  proof: 'claim' | 'standard' | 'strong';
  optimisticAllowed: boolean;
}
const PROOFS = ['claim', 'standard', 'strong'] as const;
const thrOf = (d: any): RequiredThresholdV => ({
  t: d.dtor_t.toNumber() as 1 | 2 | 3,
  proof: PROOFS[d.dtor_proof.toNumber()]!,
  optimisticAllowed: d.dtor_opt === true,
});
const thrTo = (r: RequiredThresholdV): any => P.Thr.create_Thr(new BigNumber(r.t), new BigNumber(PROOFS.indexOf(r.proof)), r.optimisticAllowed);

/** requiredThreshold(r, {theta1, theta2}, {irreversible}); r non-finite => 1 (as in risk.ts). theta1/theta2 must be finite. */
export function requiredThresholdVerified(r: number, theta1: number, theta2: number, irreversible: boolean): RequiredThresholdV {
  if (!Number.isFinite(theta1) || !Number.isFinite(theta2)) throw new PolicyVmUnsupported('non-finite theta');
  return thrOf(F.ReqThr(toRat(Number.isFinite(r) ? r : 1), toRat(theta1), toRat(theta2), irreversible));
}
/** escalateThreshold(rt, minT). */
export function escalateThresholdVerified(rt: RequiredThresholdV, minT: 1 | 2 | 3): RequiredThresholdV {
  return thrOf(F.Escalate(thrTo(rt), new BigNumber(minT)));
}
export interface AdmissionV {
  admit: boolean;
  needStepUp: boolean;
  t: 1 | 2 | 3;
  metered: boolean;
}
/** admit(): `t` = requiredThreshold(r).t, `budgetCoversCost` = (budget.B >= cost(r)) computed on doubles (false for NaN). */
export function admitVerified(t: 1 | 2 | 3, budgetCoversCost: boolean): AdmissionV {
  const a = F.AdmitOf(new BigNumber(t), budgetCoversCost);
  return { admit: a.dtor_admit === true, needStepUp: a.dtor_needStepUp === true, t: a.dtor_t.toNumber() as 1 | 2 | 3, metered: a.dtor_metered === true };
}
export interface CoreDecisionV {
  release: boolean;
  admit: boolean;
  needStepUp: boolean;
  threshold: RequiredThresholdV;
  debit: boolean;
}
export function decideCoreVerified(prOk: boolean, cvOk: boolean, dcvOk: boolean, chainOk: boolean, rt: RequiredThresholdV, adm: AdmissionV): CoreDecisionV {
  const d = F.DecideCore(prOk, cvOk, dcvOk, chainOk, thrTo(rt), P.Adm.create_Adm(adm.admit, adm.needStepUp, new BigNumber(adm.t), adm.metered));
  return { release: d.dtor_release === true, admit: d.dtor_admit === true, needStepUp: d.dtor_needStepUp === true, threshold: thrOf(d.dtor_thr), debit: d.dtor_debit === true };
}
