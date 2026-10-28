// refsem.ts - an independent TypeScript implementation of the goal semantics D_G for the grammar the tests generate (conditions,
// grants, prohibitions, count / sum bounds, validity, delegation). It is NOT trusted: it is a second, hand-written reading of
// GoalIr.dfy used to cross-check the extracted code in property tests (a disagreement is a bug in one of the two).
import type { Act, Cond, Goal, Hist, Ontology, ResSel, Term, Value } from './ir';

type T = 0 | 1 | 2; // false unknown true
const and = (a: T, b: T): T => (Math.min(a, b) as T);
const or = (a: T, b: T): T => (Math.max(a, b) as T);
const not = (a: T): T => (2 - a) as T;
const b2t = (b: boolean): T => (b ? 2 : 0);
const sameUnit = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

function val(t: Term, a: Act, h: Hist): Value | undefined {
  if (t.k === 'param') return Object.prototype.hasOwnProperty.call(a.params, t.path) ? a.params[t.path] : undefined;
  if (t.k === 'lit') return t.v;
  return Object.prototype.hasOwnProperty.call(h.aggs, t.bid) ? { k: 'q', q: h.aggs[t.bid]! } : undefined;
}
function eq(x: Value, y: Value): T {
  if (x.k === 'q' && y.k === 'q') return sameUnit(x.q.u, y.q.u) ? b2t(x.q.n === y.q.n) : 1;
  if (x.k === 's' && y.k === 's') return b2t(x.s === y.s);
  return 1;
}
function lt(x: Value, y: Value): T {
  return x.k === 'q' && y.k === 'q' && sameUnit(x.q.u, y.q.u) ? b2t(x.q.n < y.q.n) : 1;
}
function inSet(x: Value, y: Value): T {
  if (y.k !== 'set') return 1;
  return y.items.reduce<T>((acc, it) => or(acc, eq(x, it)), 0);
}
function cmp(op: string, x: Value | undefined, y: Value | undefined): T {
  if (!x || !y) return 1;
  switch (op) {
    case 'eq': return eq(x, y);
    case 'ne': return not(eq(x, y));
    case 'lt': return lt(x, y);
    case 'gte': return not(lt(x, y));
    case 'gt': return lt(y, x);
    case 'lte': return not(lt(y, x));
    case 'in': return inSet(x, y);
    default: return not(inSet(x, y));
  }
}
function evalC(c: Cond, a: Act, h: Hist): T {
  switch (c.k) {
    case 'true': return 2;
    case 'cmp': return cmp(c.op, val(c.l, a, h), val(c.r, a, h));
    case 'and': return and(evalC(c.a, a, h), evalC(c.b, a, h));
    case 'or': return or(evalC(c.a, a, h), evalC(c.b, a, h));
    case 'not': return not(evalC(c.c, a, h));
  }
}
function resOk(s: ResSel, ont: Ontology, r: string): boolean {
  switch (s.k) {
    case 'any': return true;
    case 'exact': return r === s.id;
    case 'oneof': return s.ids.includes(r);
    case 'related': return (ont.rels.find((x) => x.rel === s.rel && x.anchor === s.anchor)?.members ?? []).includes(r);
    case 'all_of': return s.parts.every((p) => resOk(p, ont, r));
  }
}
const verbsOf = (ont: Ontology, cls: string): string[] => ont.verbs.filter((v) => v.cls === cls).map((v) => v.verb);

export interface RefExplain {
  d: 0 | 1 | 2;
  /** the first grant (in goal order) whose own decision is Allow, as the proved witness picks it (GoalWitness.dfy FindAllow); null unless d = 2 */
  witness: string | null;
  /** the meet over the prohibitions alone: 0 = one fires, 1 = one is unknown, 2 = none applies */
  prohibit: 0 | 1 | 2;
}

export const refDecide = (g: Goal, ont: Ontology, a: Act, h: Hist): 0 | 1 | 2 => refExplain(g, ont, a, h).d;

export function refExplain(g: Goal, ont: Ontology, a: Act, h: Hist): RefExplain {
  let d: number = 2;
  let prohibit: number = 2;
  let witness: string | null = null;
  const meet = (x: number): void => { d = Math.min(d, x); };
  if (a.t < g.validity.notBefore || a.t > g.validity.notAfter) meet(0);
  else if (g.validity.maxIdle > 0 && h.last >= 0 && a.t - h.last > g.validity.maxIdle) meet(0);
  else if (a.depth < 0 || a.depth > g.deleg.maxDepth) meet(0);
  for (const p of g.prohibits) {
    const verbs = p.target.k === 'verb' ? [p.target.verb] : verbsOf(ont, p.target.cls);
    const m = and(b2t(verbs.includes(a.verb)), and(b2t(resOk(p.res, ont, a.res)), evalC(p.cond, a, h)));
    const pd = m === 2 ? 0 : m === 1 ? 1 : 2;
    meet(pd);
    prohibit = Math.min(prohibit, pd);
  }
  for (const c of g.escalateOn) meet(evalC(c, a, h) === 0 ? 2 : 1);
  let best = 0;
  for (const gr of g.grants) {
    const m = and(b2t(a.verb === gr.verb && (a.depth === 0 || g.deleg.mayTouch.includes(gr.gid))), and(b2t(resOk(gr.res, ont, a.res)), evalC(gr.cond, a, h)));
    let gd: number = m;
    for (const b of g.bounds) {
      const gids = b.sel.k === 'gids' ? b.sel.gids : [];
      const verbs = b.sel.k === 'effect' ? verbsOf(ont, b.sel.cls) : [];
      if (!(gids.includes(gr.gid) || verbs.includes(a.verb))) continue;
      const items: Act[] = h.adms.filter((x) => (gids.includes(x.gid) || verbs.includes(x.act.verb)) && inScope(b.scope, a, x.act) && inWin(b.window, a, x.act)).map((x) => x.act);
      items.push(a);
      let ex: T;
      if (b.agg === 'count') ex = b2t(items.length > b.cap.n);
      else if (b.agg === 'sum' || b.agg === 'max') {
        const xs: number[] = [];
        let ok = true;
        for (const it of items) {
          const v = val(b.value, it, h);
          if (!v || v.k !== 'q' || !sameUnit(v.q.u, b.cap.u)) { ok = false; break; }
          xs.push(v.q.n);
        }
        ex = !ok ? 1 : b.agg === 'sum' ? b2t(xs.reduce((s, x) => s + x, 0) > b.cap.n) : xs.length === 0 ? 1 : b2t(Math.max(...xs) > b.cap.n);
      } else {
        const ks: string[] = [];
        let ok = true;
        for (const it of items) { if (!Object.prototype.hasOwnProperty.call(it.params, b.key)) { ok = false; break; } ks.push(JSON.stringify(it.params[b.key])); }
        ex = ok ? b2t(new Set(ks).size > b.cap.n) : 1;
      }
      gd = Math.min(gd, ex === 2 ? (b.onExceed === 'deny' ? 0 : 1) : ex === 1 ? 1 : 2);
    }
    if (gd === 2 && witness === null) witness = gr.gid;
    best = Math.max(best, gd);
  }
  meet(best);
  return { d: d as 0 | 1 | 2, witness: d === 2 ? witness : null, prohibit: prohibit as 0 | 1 | 2 };
}
function inScope(sc: Goal['bounds'][number]['scope'], a: Act, x: Act): boolean {
  switch (sc.k) {
    case 'session': return a.sess === x.sess;
    case 'principal': return a.prin === x.prin;
    case 'org': return a.org === x.org;
    case 'fleet': return sc.agents.includes(a.agent) && sc.agents.includes(x.agent);
  }
}
function inWin(w: Goal['bounds'][number]['window'], a: Act, x: Act): boolean {
  switch (w.k) {
    case 'task': case 'lifetime': return true;
    case 'sliding': return x.t > a.t - w.ms && x.t <= a.t;
    case 'period': return w.ms > 0 && Math.floor((a.t - w.t0) / w.ms) === Math.floor((x.t - w.t0) / w.ms);
  }
}
