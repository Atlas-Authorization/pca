// The oracle: an INDEPENDENT second implementation of the Goal IR semantics (spec 3.2/3.3), written from formal/dafny/GoalIr.dfy
// (DG, typing) and GoalCompile.dfy (Lower) WITHOUT importing packages/pca-goal/src/refsem.ts or the compiler. Expected values in every
// vector come from here; the Go/Python/Rust runners re-implement it line for line, and CI compares the extracted compiler to it.
// Kleene truth: 0 false, 1 unknown, 2 true. Decisions: 0 deny, 1 escalate, 2 allow (meet = min, join = max); Unknown never yields Allow.
import { canon, hashCanon } from './canon.ts';
import type {
  Act, Atom, Bound, Cond, Decision, Goal, Grant, Hist, Ontology, Op, Policy, Prohibit, Quantity, ResPart, ResSel, Term, Ty, Unit, Value, Verdict, Window,
} from './types.ts';

type K = 0 | 1 | 2;
const kAnd = (a: K, b: K): K => (a < b ? a : b) as K;
const kOr = (a: K, b: K): K => (a > b ? a : b) as K;
const kNot = (a: K): K => (2 - a) as K;
const b2k = (b: boolean): K => (b ? 2 : 0);
const sameUnit = (a: Unit, b: Unit): boolean => a.k === b.k && (a.k !== 'money' || (b.k === 'money' && a.ccy === b.ccy));
const veq = (a: unknown, b: unknown): boolean => canon(a) === canon(b);

// ---------------------------------------------------------------- terms and conditions
function eqV(x: Value, y: Value): K {
  if (x.k === 'q') return y.k === 'q' && sameUnit(x.q.u, y.q.u) ? b2k(x.q.n === y.q.n) : 1;
  if (x.k === 's') return y.k === 's' ? b2k(x.s === y.s) : 1;
  return 1;
}
const ltV = (x: Value, y: Value): K => (x.k === 'q' && y.k === 'q' && sameUnit(x.q.u, y.q.u) ? b2k(x.q.n < y.q.n) : 1);
const atomV = (a: Atom): Value => (a.k === 'q' ? { k: 'q', q: a.q } : { k: 's', s: a.s });
function cmp(op: Op, x: Value | undefined, y: Value | undefined): K {
  if (x === undefined || y === undefined) return 1;
  switch (op) {
    case 'eq': return eqV(x, y);
    case 'ne': return kNot(eqV(x, y));
    case 'lt': return ltV(x, y);
    case 'gte': return kNot(ltV(x, y));
    case 'gt': return ltV(y, x);
    case 'lte': return kNot(ltV(y, x));
    case 'in':
    case 'nin': {
      const items = y.k === 'set' ? (y.items as Atom[]) : null;
      const t: K = items === null ? 1 : items.reduce<K>((acc, it) => kOr(acc, eqV(x, atomV(it))), 0);
      return op === 'in' ? t : kNot(t);
    }
  }
}
function term(t: Term, a: Act, h: Hist): Value | undefined {
  if (t.k === 'param') return Object.prototype.hasOwnProperty.call(a.params, t.path) ? a.params[t.path] : undefined;
  if (t.k === 'lit') return t.v;
  return Object.prototype.hasOwnProperty.call(h.aggs, t.bid) ? { k: 'q', q: h.aggs[t.bid]! } : undefined;
}
function cond(c: Cond, a: Act, h: Hist): K {
  switch (c.k) {
    case 'true': return 2;
    case 'cmp': return cmp(c.op, term(c.l, a, h), term(c.r, a, h));
    case 'and': return kAnd(cond(c.a, a, h), cond(c.b, a, h));
    case 'or': return kOr(cond(c.a, a, h), cond(c.b, a, h));
    case 'not': return kNot(cond(c.c, a, h));
  }
}

// ---------------------------------------------------------------- resources, verbs, bound selections
type Pat = null | string[]; // null = every resource
const inter = (x: Pat, y: Pat): Pat => (x === null ? y : y === null ? x : x.filter((i) => y.includes(i)));
const partIds = (o: Ontology, p: ResPart): string[] =>
  p.k === 'exact' ? [p.id] : p.k === 'oneof' ? p.ids : o.rels.find((r) => r.rel === p.rel && r.anchor === p.anchor)?.members ?? [];
export function resolve(o: Ontology, s: ResSel): Pat {
  if (s.k === 'any') return null;
  if (s.k === 'all_of') return s.parts.reduceRight<Pat>((rest, p) => inter(partIds(o, p), rest), null);
  return partIds(o, s);
}
const verbsOfClass = (o: Ontology, cls: string): string[] => o.verbs.filter((v) => v.cls === cls).map((v) => v.verb);
const prohVerbs = (o: Ontology, p: Prohibit): string[] => (p.target.k === 'verb' ? [p.target.verb] : verbsOfClass(o, p.target.cls));
const resOk = (p: Pat, r: string): boolean => p === null || p.includes(r);
type LSel = { gids: string[]; verbs: string[] };
const lsel = (o: Ontology, b: Bound): LSel => (b.sel.k === 'gids' ? { gids: b.sel.gids, verbs: [] } : { gids: [], verbs: verbsOfClass(o, b.sel.cls) });
const applies = (s: LSel, gid: string, verb: string): boolean => s.gids.includes(gid) || s.verbs.includes(verb);

// ---------------------------------------------------------------- bounds
const inScope = (b: Bound, a: Act, x: Act): boolean => {
  const s = b.scope;
  return s.k === 'session' ? a.sess === x.sess : s.k === 'principal' ? a.prin === x.prin : s.k === 'org' ? a.org === x.org : s.agents.includes(a.agent) && s.agents.includes(x.agent);
};
const inWindow = (w: Window, a: Act, x: Act): boolean =>
  w.k === 'sliding' ? x.t > a.t - w.ms && x.t <= a.t : w.k === 'period' ? w.ms > 0 && Math.floor((a.t - w.t0) / w.ms) === Math.floor((x.t - w.t0) / w.ms) : true;
/** true / unknown / false = exceeded / unreadable / within (aggregate over the admitted history plus the candidate). */
function exceeded(b: Bound, s: LSel, a: Act, h: Hist): K {
  const items = h.adms.filter((m) => applies(s, m.gid, m.act.verb) && inScope(b, a, m.act) && inWindow(b.window, a, m.act)).map((m) => m.act).concat([a]);
  if (b.agg === 'count') return b2k(items.length > b.cap.n);
  if (b.agg === 'distinct') {
    const vs: Value[] = [];
    for (const x of items) { if (!Object.prototype.hasOwnProperty.call(x.params, b.key)) return 1; vs.push(x.params[b.key]!); }
    return b2k(new Set(vs.map((v) => canon(v))).size > b.cap.n);
  }
  const ns: number[] = [];
  for (const x of items) {
    const v = term(b.value, x, h);
    if (v === undefined || v.k !== 'q' || !sameUnit(v.q.u, b.cap.u)) return 1;
    ns.push(v.q.n);
  }
  return b2k((b.agg === 'sum' ? ns.reduce((p, n) => p + n, 0) : Math.max(...ns)) > b.cap.n);
}
const boundDec = (b: Bound, s: LSel, a: Act, h: Hist): number => {
  const e = exceeded(b, s, a, h);
  return e === 2 ? (b.onExceed === 'deny' ? 0 : 1) : e === 1 ? 1 : 2;
};

// ---------------------------------------------------------------- the decision
/** A grant that depends on a hole is dropped (G-T7: the most restrictive completion); the compiler does the same before lowering. */
export const strip = (g: Goal): Goal => ({ ...g, holes: [], grants: g.grants.filter((x) => !g.holes.some((h) => h.global || h.affects.includes(x.gid))) });

function grantDec(g: Goal, o: Ontology, gr: Grant, a: Act, h: Hist): number {
  const delegOk = a.depth === 0 || g.deleg.mayTouch.includes(gr.gid);
  const m = kAnd(b2k(a.verb === gr.verb && delegOk), kAnd(b2k(resOk(resolve(o, gr.res), a.res)), cond(gr.cond, a, h)));
  return Math.min(m, ...g.bounds.map((b) => { const s = lsel(o, b); return applies(s, gr.gid, a.verb) ? boundDec(b, s, a, h) : 2; }));
}
function validityDec(g: Goal, a: Act, h: Hist): number {
  const v = g.validity;
  if (a.t < v.notBefore || a.t > v.notAfter) return 0;
  if (v.maxIdle > 0 && h.last >= 0 && a.t - h.last > v.maxIdle) return 0;
  if (a.depth < 0 || a.depth > g.deleg.maxDepth) return 0;
  return 2;
}
/** D_G of the goal after hole stripping. Returns the decision and, for an Allow, the first allowing grant with the bounds that apply to it (G-T3). */
export function decide(goal: Goal, o: Ontology, a: Act, h: Hist): Verdict {
  const g = strip(goal);
  let d = validityDec(g, a, h);
  for (const p of g.prohibits) {
    const m = kAnd(b2k(prohVerbs(o, p).includes(a.verb)), kAnd(b2k(resOk(resolve(o, p.res), a.res)), cond(p.cond, a, h)));
    d = Math.min(d, m === 2 ? 0 : m === 1 ? 1 : 2);
  }
  for (const c of g.escalateOn) d = Math.min(d, cond(c, a, h) === 0 ? 2 : 1);
  const per = g.grants.map((gr) => grantDec(g, o, gr, a, h));
  d = Math.min(d, per.length ? Math.max(...per) : 0);
  const decision: Decision = d === 2 ? 'allow' : d === 1 ? 'escalate' : 'deny';
  if (decision !== 'allow') return { decision, witness: null };
  const gr = g.grants[per.indexOf(2)]!;
  return { decision, witness: { gid: gr.gid, bids: g.bounds.filter((b) => applies(lsel(o, b), gr.gid, a.verb)).map((b) => b.bid) } };
}
/** G-T3 checker: re-derives the allow and compares the witness. */
export function verifyWitness(goal: Goal, o: Ontology, a: Act, h: Hist, w: Verdict['witness']): boolean {
  if (!w) return false;
  const d = decide(goal, o, a, h);
  return d.decision === 'allow' && d.witness!.gid === w.gid && veq(d.witness!.bids, w.bids);
}

// ---------------------------------------------------------------- typing (reason codes of GoalCompile.dfy TypeReasons)
const tyOf = (v: Value): Ty | null => (v.k === 'q' ? { k: 'q', u: v.q.u } : v.k === 's' ? { k: 's' } : null);
const unitOk = (u: Unit): boolean => u.k !== 'money' || u.ccy.length > 0;
const tyOk = (t: Ty): boolean => t.k === 's' || unitOk(t.u);
const valueOk = (v: Value): boolean => (v.k === 'q' ? unitOk(v.q.u) : v.k === 's' ? true : v.items.every((i) => i.k === 'q' ? unitOk(i.q.u) : true));
const termTy = (t: Term): Ty | null => (t.k === 'param' ? t.ty : t.k === 'lit' ? tyOf(t.v) : { k: 'q', u: t.u });
const termOk = (t: Term): boolean => (t.k === 'param' ? t.path.length > 0 && tyOk(t.ty) : t.k === 'lit' ? valueOk(t.v) : t.bid.length > 0 && unitOk(t.u));
function cmpTyped(op: Op, l: Term, r: Term): boolean {
  const lt = termTy(l), rt = termTy(r);
  if (!termOk(l) || !termOk(r) || lt === null) return false;
  if (op === 'eq' || op === 'ne') return veq(lt, rt);
  if (op === 'in' || op === 'nin') return r.k === 'lit' && r.v.k === 'set' && r.v.items.every((i) => veq(tyOf(atomV(i as Atom)), lt));
  return veq(lt, rt) && lt.k === 'q';
}
function condTyped(c: Cond, ok: (p: string, t: Ty) => boolean): boolean {
  if (c.k === 'true') return true;
  if (c.k === 'cmp') return cmpTyped(c.op, c.l, c.r) && [c.l, c.r].every((t) => t.k !== 'param' || ok(t.path, t.ty));
  if (c.k === 'not') return condTyped(c.c, ok);
  return condTyped(c.a, ok) && condTyped(c.b, ok);
}
const declared = (o: Ontology, verbs: string[]) => (p: string, t: Ty): boolean =>
  verbs.every((v) => o.verbs.find((d) => d.verb === v)?.params.some((q) => q.path === p && veq(q.ty, t)) ?? false);
const noConflict = (o: Ontology) => (p: string, t: Ty): boolean => o.verbs.every((d) => d.params.every((q) => q.path !== p || veq(q.ty, t)));
function partOk(o: Ontology, p: ResPart): boolean {
  return p.k === 'exact' ? p.id.length > 0 : p.k === 'oneof' ? p.ids.length > 0 : o.rels.some((r) => r.rel === p.rel && r.anchor === p.anchor);
}
const selOk = (o: Ontology, s: ResSel): boolean => (s.k === 'any' ? true : s.k === 'all_of' ? s.parts.length >= 2 && s.parts.every((p) => partOk(o, p)) : partOk(o, s));
const strictlySorted = (xs: string[]): boolean => xs.every((x, i) => i === 0 || xs[i - 1]! < x);
export function typeReasons(o: Ontology, g: Goal): string[] {
  const gids = g.grants.map((x) => x.gid);
  const grantOk = (x: Grant): boolean =>
    x.gid.length > 0 && o.verbs.some((v) => v.verb === x.verb) && selOk(o, x.res) && (x.res.k !== 'any' || g.wildcardAck.includes(x.gid)) && condTyped(x.cond, declared(o, [x.verb]));
  const prohOk = (p: Prohibit): boolean =>
    p.pid.length > 0 && selOk(o, p.res) &&
    (p.target.k === 'verb' ? o.verbs.some((v) => v.verb === (p.target as { verb: string }).verb) : p.target.cls.length > 0 && prohVerbs(o, p).length > 0) &&
    condTyped(p.cond, declared(o, prohVerbs(o, p)));
  const boundOk = (b: Bound): boolean => {
    const c = b.cap;
    if (!(b.bid.length > 0 && termOk(b.value) && unitOk(c.u) && c.n >= 0)) return false;
    if ((b.window.k === 'sliding' || b.window.k === 'period') && !(b.window.ms > 0)) return false;
    if (b.scope.k === 'fleet' && b.scope.agents.length === 0) return false;
    if (b.sel.k === 'gids' ? !(b.sel.gids.length > 0 && b.sel.gids.every((x) => gids.includes(x))) : !(b.sel.cls.length > 0)) return false;
    if (b.agg === 'count') return c.u.k === 'count';
    if (b.agg === 'distinct') return c.u.k === 'count' && b.key.length > 0;
    return veq(termTy(b.value), { k: 'q', u: c.u });
  };
  const out: string[] = [];
  if (!(strictlySorted(gids) && strictlySorted(g.prohibits.map((p) => p.pid)) && strictlySorted(g.bounds.map((b) => b.bid)) && strictlySorted(g.holes.map((h) => h.hid)))) out.push('not_canonical_order');
  if (!g.grants.every(grantOk)) out.push('ill_typed_grant');
  if (!g.prohibits.every(prohOk)) out.push('ill_typed_prohibit');
  if (!g.bounds.every(boundOk)) out.push('ill_typed_bound');
  if (!g.escalateOn.every((c) => condTyped(c, noConflict(o)))) out.push('ill_typed_escalation');
  const v = g.validity, d = g.deleg;
  if (!(v.notBefore <= v.notAfter && v.maxIdle >= 0 && d.maxDepth >= 0 && d.maxDepth <= 16 && d.narrowOnly && d.mayTouch.every((x) => gids.includes(x)))) out.push('bad_validity_or_delegation');
  if (!g.holes.every((h) => h.hid.length > 0 && h.affects.every((x) => gids.includes(x)))) out.push('bad_hole');
  return out;
}
export type CompileCheck = { ok: boolean; reasons: string[]; signable: boolean };
export function typecheck(g: Goal, o: Ontology): CompileCheck {
  const reasons = typeReasons(o, g);
  return { ok: reasons.length === 0, reasons, signable: reasons.length === 0 && g.holes.length === 0 };
}

// ---------------------------------------------------------------- lowering (GoalCompile.dfy Lower) and the policy digest
const NEG: Record<Op, Op> = { eq: 'ne', ne: 'eq', lt: 'gte', gte: 'lt', gt: 'lte', lte: 'gt', in: 'nin', nin: 'in' };
type N = Policy['preds'][number]['cond'];
function nnf(c: Cond, pos: boolean): N {
  switch (c.k) {
    case 'true': return { k: pos ? 'true' : 'false' };
    case 'cmp': return { k: 'atom', op: pos ? c.op : NEG[c.op], l: c.l, r: c.r };
    case 'and': return { k: pos ? 'and' : 'or', a: nnf(c.a, pos), b: nnf(c.b, pos) };
    case 'or': return { k: pos ? 'or' : 'and', a: nnf(c.a, pos), b: nnf(c.b, pos) };
    case 'not': return nnf(c.c, !pos);
  }
}
const toPat = (p: Pat): Policy['preds'][number]['res'] => (p === null ? { k: 'star' } : { k: 'set', ids: p });
export function lower(o: Ontology, goal: Goal): Policy {
  const g = strip(goal);
  return {
    preds: g.grants.map((x) => ({ gid: x.gid, verb: x.verb, res: toPat(resolve(o, x.res)), cond: nnf(x.cond, true) })),
    prohs: g.prohibits.map((p) => ({ pid: p.pid, verbs: prohVerbs(o, p), res: toPat(resolve(o, p.res)), cond: nnf(p.cond, true) })),
    ceils: g.bounds.map((b) => { const s = lsel(o, b); return { bid: b.bid, selGids: s.gids, selVerbs: s.verbs, agg: b.agg, value: b.value, key: b.key, window: b.window, scope: b.scope, cap: b.cap, onExceed: b.onExceed }; }),
    escs: g.escalateOn.map((c) => nnf(c, true)),
    validity: g.validity,
    deleg: g.deleg,
  };
}
/** sha256 base64url of the sorted-key JSON of the lowered policy (= `policyDigest` of pca-goal). */
export const policyDigest = (o: Ontology, g: Goal): string => hashCanon(lower(o, g));

/** Sort every clause list by id: the canonical order the typing rule `not_canonical_order` demands (G-T5). */
export function canonicalOrder(g: Goal): Goal {
  const by = <T>(xs: T[], id: (x: T) => string): T[] => [...xs].sort((a, b) => (id(a) < id(b) ? -1 : id(a) > id(b) ? 1 : 0));
  return { ...g, grants: by(g.grants, (x) => x.gid), prohibits: by(g.prohibits, (x) => x.pid), bounds: by(g.bounds, (x) => x.bid), holes: by(g.holes, (x) => x.hid) };
}
export type { Quantity };
