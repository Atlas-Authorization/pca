// codec.ts - the token-tape form of the IR, mirroring the encoders/decoders of formal/dafny/GoalRender.dfy and Goal.dfy tag for tag.
// Encoding is STRICT: anything that is not exactly an IR value (non-safe integer, unknown discriminant, extra shape) throws, so a
// malformed value never reaches the proved parser as something that merely happens to parse.
import type { Tape, Tok } from '@atlasauth/pca-verified-core';
import type {
  Act, Adm, Agg, Bound, Cond, Delegation, Goal, Grant, Hist, Hole, LCeil, LPred, LProh, NCond, Ontology, Op, OnExceed, ParamDecl,
  Policy, Prohibit, Quantity, RelDecl, ResPart, ResPat, ResSel, Scope, Sel, Term, Ty, Unit, Validity, Value, VerbDecl, Window,
} from './ir';

export class IrError extends Error {
  constructor(m: string) {
    super(`pca-goal: ${m}`);
    this.name = 'IrError';
  }
}
const K = (n: number): Tok => ['k', n];
const I = (n: number): Tok => {
  if (!Number.isSafeInteger(n)) throw new IrError(`${String(n)} is not a safe integer`);
  return ['i', n];
};
const S = (s: string): Tok => {
  if (typeof s !== 'string') throw new IrError('string expected');
  return ['s', s];
};
const bad = (what: string, v: unknown): never => {
  throw new IrError(`unknown ${what}: ${JSON.stringify(v)}`);
};

type Enc<T> = (x: T) => Tok[];
const list = <T>(xs: readonly T[], f: Enc<T>): Tok[] => {
  if (!Array.isArray(xs)) throw new IrError('array expected');
  return [I(xs.length), ...xs.flatMap(f)];
};
const strs = (xs: readonly string[]): Tok[] => list(xs, (s) => [S(s)]);

export const OPS: readonly Op[] = ['eq', 'ne', 'lt', 'lte', 'gt', 'gte', 'in', 'nin'];
export const AGGS: readonly Agg[] = ['count', 'sum', 'max', 'distinct'];

export function encUnit(u: Unit): Tok[] {
  switch (u.k) {
    case 'money': return [K(300), S(u.ccy)];
    case 'count': return [K(301)];
    case 'duration': return [K(302)];
    case 'instant': return [K(303)];
    case 'bytes': return [K(304)];
    case 'ratio': return [K(305)];
    default: return bad('unit', u);
  }
}
export const encQ = (q: Quantity): Tok[] => [...encUnit(q.u), I(q.n)];
const encTy = (t: Ty): Tok[] => (t.k === 'q' ? [K(310), ...encUnit(t.u)] : t.k === 's' ? [K(311)] : bad('type', t));
function encAtom(a: Value): Tok[] {
  if (a.k === 'q') return [K(320), ...encQ(a.q)];
  if (a.k === 's') return [K(321), S(a.s)];
  return bad('set member (sets hold quantities and strings only)', a);
}
export function encV(v: Value): Tok[] {
  switch (v.k) {
    case 'q': return [K(330), ...encQ(v.q)];
    case 's': return [K(331), S(v.s)];
    case 'set': return [K(332), ...list(v.items, encAtom)];
    default: return bad('value', v);
  }
}
export function encTerm(t: Term): Tok[] {
  switch (t.k) {
    case 'param': return [K(340), S(t.path), ...encTy(t.ty)];
    case 'lit': return [K(341), ...encV(t.v)];
    case 'hist': return [K(342), S(t.bid), ...encUnit(t.u)];
    default: return bad('term', t);
  }
}
const encOp = (op: Op): Tok[] => {
  const i = OPS.indexOf(op);
  return i < 0 ? bad('operator', op) : [K(350 + i)];
};
export function encCond(c: Cond): Tok[] {
  switch (c.k) {
    case 'true': return [K(360)];
    case 'cmp': return [K(361), ...encOp(c.op), ...encTerm(c.l), ...encTerm(c.r)];
    case 'and': return [K(362), ...encCond(c.a), ...encCond(c.b)];
    case 'or': return [K(363), ...encCond(c.a), ...encCond(c.b)];
    case 'not': return [K(364), ...encCond(c.c)];
    default: return bad('condition', c);
  }
}
function encPart(s: ResPart): Tok[] {
  switch (s.k) {
    case 'exact': return [K(375), S(s.id)];
    case 'oneof': return [K(376), ...strs(s.ids)];
    case 'related': return [K(377), S(s.rel), S(s.anchor)];
    default: return bad('resource part', s);
  }
}
function encRes(s: ResSel): Tok[] {
  switch (s.k) {
    case 'exact': return [K(370), S(s.id)];
    case 'oneof': return [K(371), ...strs(s.ids)];
    case 'related': return [K(372), S(s.rel), S(s.anchor)];
    case 'any': return [K(373), S(s.reason)];
    case 'all_of': return [K(374), ...list(s.parts, encPart)];
    default: return bad('resource selector', s);
  }
}
const encGrant = (g: Grant): Tok[] => [K(380), S(g.gid), S(g.verb), ...encRes(g.res), ...encCond(g.cond)];
function encTarget(t: Prohibit['target']): Tok[] {
  return t.k === 'verb' ? [K(390), S(t.verb)] : t.k === 'effect' ? [K(391), S(t.cls)] : bad('prohibit target', t);
}
const encProhibit = (p: Prohibit): Tok[] => [K(392), S(p.pid), ...encTarget(p.target), ...encRes(p.res), ...encCond(p.cond)];
const encSel = (s: Sel): Tok[] => (s.k === 'gids' ? [K(410), ...strs(s.gids)] : s.k === 'effect' ? [K(411), S(s.cls)] : bad('selection', s));
function encWindow(w: Window): Tok[] {
  switch (w.k) {
    case 'task': return [K(420)];
    case 'sliding': return [K(421), I(w.ms)];
    case 'period': return [K(422), I(w.ms), I(w.t0)];
    case 'lifetime': return [K(423)];
    default: return bad('window', w);
  }
}
function encScope(s: Scope): Tok[] {
  switch (s.k) {
    case 'session': return [K(430)];
    case 'principal': return [K(431)];
    case 'org': return [K(432)];
    case 'fleet': return [K(433), ...strs(s.agents)];
    default: return bad('scope', s);
  }
}
const encOnExceed = (o: OnExceed): Tok[] => (o === 'deny' ? [K(440)] : o === 'escalate' ? [K(441)] : bad('on_exceed', o));
type BoundCore = Pick<Bound, 'agg' | 'value' | 'key' | 'window' | 'scope' | 'cap' | 'onExceed'>;
function encBCore(b: BoundCore): Tok[] {
  const a = AGGS.indexOf(b.agg);
  if (a < 0) bad('aggregate', b.agg);
  return [K(450), K(400 + a), ...encTerm(b.value), S(b.key), ...encWindow(b.window), ...encScope(b.scope), ...encQ(b.cap), ...encOnExceed(b.onExceed)];
}
const encBound = (b: Bound): Tok[] => [K(451), S(b.bid), ...encSel(b.sel), ...encBCore(b)];
const encValidity = (v: Validity): Tok[] => [K(460), I(v.notBefore), I(v.notAfter), I(v.maxIdle)];
const encDeleg = (d: Delegation): Tok[] => [K(461), I(d.maxDepth), I(d.narrowOnly ? 1 : 0), ...strs(d.mayTouch)];
const encHole = (h: Hole): Tok[] => [K(470), S(h.hid), S(h.q), ...strs(h.domain), ...strs(h.affects), I(h.global ? 1 : 0)];

/** The goal as a token tape (the card of formal/dafny/GoalRender.dfy `Render`). */
export function encodeGoal(g: Goal): Tape {
  return [
    K(480), I(g.v), S(g.principal), S(g.ontDigest), S(g.nlDigest),
    ...strs(g.sources), ...list(g.grants, encGrant), ...list(g.prohibits, encProhibit), ...list(g.bounds, encBound),
    ...encValidity(g.validity), ...encDeleg(g.deleg), ...list(g.escalateOn, encCond), ...strs(g.wildcardAck), ...list(g.holes, encHole),
  ];
}
const encParamDecl = (p: ParamDecl): Tok[] => [K(500), S(p.path), ...encTy(p.ty)];
const encVerbDecl = (v: VerbDecl): Tok[] => [K(501), S(v.verb), S(v.cls), ...list(v.params, encParamDecl)];
const encRelDecl = (r: RelDecl): Tok[] => [K(502), S(r.rel), S(r.anchor), ...strs(r.members)];
export const encodeOntology = (o: Ontology): Tape => [K(510), ...list(o.verbs, encVerbDecl), ...list(o.rels, encRelDecl)];
function encAct(a: Act): Tok[] {
  const keys = Object.keys(a.params).sort();
  return [
    K(530), S(a.verb), S(a.res), ...list(keys, (k) => [K(520), S(k), ...encV(a.params[k]!)]),
    I(a.t), S(a.sess), S(a.prin), S(a.org), S(a.agent), I(a.depth),
  ];
}
export const encodeAct = (a: Act): Tape => encAct(a);
const encAdm = (a: Adm): Tok[] => [K(531), S(a.gid), ...encAct(a.act)];
export function encodeHist(h: Hist): Tape {
  const keys = Object.keys(h.aggs).sort();
  return [K(541), ...list(h.adms, encAdm), I(h.last), ...list(keys, (k) => [K(540), S(k), ...encQ(h.aggs[k]!)])];
}

// ---------------------------------------------------------------------------------------------- decoding of the compiler's output
class Rd {
  i = 0;
  constructor(readonly t: Tape) {}
  next(): Tok {
    const x = this.t[this.i++];
    if (!x) throw new IrError('truncated tape');
    return x;
  }
  k(): number { const x = this.next(); if (x[0] !== 'k') throw new IrError('keyword expected'); return x[1]; }
  int(): number { const x = this.next(); if (x[0] !== 'i') throw new IrError('integer expected'); return x[1]; }
  str(): string { const x = this.next(); if (x[0] !== 's') throw new IrError('string expected'); return x[1]; }
  done(): boolean { return this.i >= this.t.length; }
  list<T>(f: () => T): T[] {
    const n = this.int();
    if (n < 0) throw new IrError('negative length');
    const out: T[] = [];
    for (let j = 0; j < n; j++) out.push(f());
    return out;
  }
  strs(): string[] { return this.list(() => this.str()); }
}
function dUnit(r: Rd): Unit {
  const k = r.k();
  if (k === 300) return { k: 'money', ccy: r.str() };
  const u = ({ 301: 'count', 302: 'duration', 303: 'instant', 304: 'bytes', 305: 'ratio' } as Record<number, 'count' | 'duration' | 'instant' | 'bytes' | 'ratio'>)[k];
  if (!u) throw new IrError(`bad unit tag ${k}`);
  return { k: u };
}
const dQ = (r: Rd): Quantity => ({ u: dUnit(r), n: r.int() });
function dTy(r: Rd): Ty {
  const k = r.k();
  if (k === 310) return { k: 'q', u: dUnit(r) };
  if (k === 311) return { k: 's' };
  throw new IrError(`bad type tag ${k}`);
}
function dAtom(r: Rd): Value {
  const k = r.k();
  if (k === 320) return { k: 'q', q: dQ(r) };
  if (k === 321) return { k: 's', s: r.str() };
  throw new IrError(`bad atom tag ${k}`);
}
function dV(r: Rd): Value {
  const k = r.k();
  if (k === 330) return { k: 'q', q: dQ(r) };
  if (k === 331) return { k: 's', s: r.str() };
  if (k === 332) return { k: 'set', items: r.list(() => dAtom(r)) };
  throw new IrError(`bad value tag ${k}`);
}
function dTerm(r: Rd): Term {
  const k = r.k();
  if (k === 340) return { k: 'param', path: r.str(), ty: dTy(r) };
  if (k === 341) return { k: 'lit', v: dV(r) };
  if (k === 342) return { k: 'hist', bid: r.str(), u: dUnit(r) };
  throw new IrError(`bad term tag ${k}`);
}
const dOp = (r: Rd): Op => OPS[r.k() - 350] ?? ((): never => { throw new IrError('bad operator'); })();
function dN(r: Rd): NCond {
  const k = r.k();
  if (k === 600) return { k: 'true' };
  if (k === 601) return { k: 'false' };
  if (k === 602) return { k: 'atom', op: dOp(r), l: dTerm(r), r: dTerm(r) };
  if (k === 603) return { k: 'and', a: dN(r), b: dN(r) };
  if (k === 604) return { k: 'or', a: dN(r), b: dN(r) };
  throw new IrError(`bad condition tag ${k}`);
}
function dResPat(r: Rd): ResPat {
  const k = r.k();
  if (k === 630) return { k: 'star' };
  if (k === 631) return { k: 'set', ids: r.strs() };
  throw new IrError(`bad resource pattern tag ${k}`);
}
function dWindow(r: Rd): Window {
  const k = r.k();
  if (k === 420) return { k: 'task' };
  if (k === 421) return { k: 'sliding', ms: r.int() };
  if (k === 422) return { k: 'period', ms: r.int(), t0: r.int() };
  if (k === 423) return { k: 'lifetime' };
  throw new IrError(`bad window tag ${k}`);
}
function dScope(r: Rd): Scope {
  const k = r.k();
  if (k === 430) return { k: 'session' };
  if (k === 431) return { k: 'principal' };
  if (k === 432) return { k: 'org' };
  if (k === 433) return { k: 'fleet', agents: r.strs() };
  throw new IrError(`bad scope tag ${k}`);
}
function dCeil(r: Rd): LCeil {
  if (r.k() !== 610) throw new IrError('ceiling expected');
  const bid = r.str();
  const selGids = r.strs();
  const selVerbs = r.strs();
  if (r.k() !== 450) throw new IrError('bound core expected');
  const agg = AGGS[r.k() - 400];
  if (!agg) throw new IrError('bad aggregate');
  const value = dTerm(r);
  const key = r.str();
  const window = dWindow(r);
  const scope = dScope(r);
  const cap = dQ(r);
  const oe = r.k();
  if (oe !== 440 && oe !== 441) throw new IrError('bad on_exceed');
  return { bid, selGids, selVerbs, agg, value, key, window, scope, cap, onExceed: oe === 440 ? 'deny' : 'escalate' };
}
/** Decode the compiler's policy tape (after the leading status token has been consumed). */
export function decodePolicy(t: Tape): Policy {
  const r = new Rd(t);
  if (r.k() !== 650) throw new IrError('policy expected');
  const preds = r.list((): LPred => { if (r.k() !== 620) throw new IrError('pred'); return { gid: r.str(), verb: r.str(), res: dResPat(r), cond: dN(r) }; });
  const prohs = r.list((): LProh => { if (r.k() !== 640) throw new IrError('prohibition'); return { pid: r.str(), verbs: r.strs(), res: dResPat(r), cond: dN(r) }; });
  const ceils = r.list(() => dCeil(r));
  const escs = r.list(() => dN(r));
  if (r.k() !== 460) throw new IrError('validity');
  const validity: Validity = { notBefore: r.int(), notAfter: r.int(), maxIdle: r.int() };
  if (r.k() !== 461) throw new IrError('delegation');
  const deleg: Delegation = { maxDepth: r.int(), narrowOnly: r.int() === 1, mayTouch: r.strs() };
  if (!r.done()) throw new IrError('trailing tokens after policy');
  return { preds, prohs, ceils, escs, validity, deleg };
}
export { Rd as TapeReader };

// ---------------------------------------------------------------------------------------------- decoding of a goal tape (inverse of encodeGoal)
function dCond(r: Rd): Cond {
  const k = r.k();
  if (k === 360) return { k: 'true' };
  if (k === 361) return { k: 'cmp', op: dOp(r), l: dTerm(r), r: dTerm(r) };
  if (k === 362) return { k: 'and', a: dCond(r), b: dCond(r) };
  if (k === 363) return { k: 'or', a: dCond(r), b: dCond(r) };
  if (k === 364) return { k: 'not', c: dCond(r) };
  throw new IrError(`bad condition tag ${k}`);
}
function dPart(r: Rd): ResPart {
  const k = r.k();
  if (k === 375) return { k: 'exact', id: r.str() };
  if (k === 376) return { k: 'oneof', ids: r.strs() };
  if (k === 377) return { k: 'related', rel: r.str(), anchor: r.str() };
  throw new IrError(`bad resource part tag ${k}`);
}
function dRes(r: Rd): ResSel {
  const k = r.k();
  if (k === 370) return { k: 'exact', id: r.str() };
  if (k === 371) return { k: 'oneof', ids: r.strs() };
  if (k === 372) return { k: 'related', rel: r.str(), anchor: r.str() };
  if (k === 373) return { k: 'any', reason: r.str() };
  if (k === 374) return { k: 'all_of', parts: r.list(() => dPart(r)) };
  throw new IrError(`bad resource selector tag ${k}`);
}
function expect(r: Rd, k: number, what: string): void {
  if (r.k() !== k) throw new IrError(`${what} expected`);
}
/** Parse a goal tape; throws IrError unless the whole tape is exactly one goal. */
export function decodeGoal(t: Tape): Goal {
  const r = new Rd(t);
  expect(r, 480, 'goal');
  const v = r.int(), principal = r.str(), ontDigest = r.str(), nlDigest = r.str();
  const sources = r.strs();
  const grants = r.list((): Grant => { expect(r, 380, 'grant'); return { gid: r.str(), verb: r.str(), res: dRes(r), cond: dCond(r) }; });
  const prohibits = r.list((): Prohibit => {
    expect(r, 392, 'prohibit');
    const pid = r.str();
    const tk = r.k();
    const target: Prohibit['target'] = tk === 390 ? { k: 'verb', verb: r.str() } : tk === 391 ? { k: 'effect', cls: r.str() } : ((): never => { throw new IrError('bad prohibit target'); })();
    return { pid, target, res: dRes(r), cond: dCond(r) };
  });
  const bounds = r.list((): Bound => {
    expect(r, 451, 'bound');
    const bid = r.str();
    const sk = r.k();
    const sel: Sel = sk === 410 ? { k: 'gids', gids: r.strs() } : sk === 411 ? { k: 'effect', cls: r.str() } : ((): never => { throw new IrError('bad selection'); })();
    expect(r, 450, 'bound core');
    const agg = AGGS[r.k() - 400];
    if (!agg) throw new IrError('bad aggregate');
    const value = dTerm(r), key = r.str(), window = dWindow(r), scope = dScope(r), cap = dQ(r);
    const oe = r.k();
    if (oe !== 440 && oe !== 441) throw new IrError('bad on_exceed');
    return { bid, sel, agg, value, key, window, scope, cap, onExceed: oe === 440 ? 'deny' : 'escalate' };
  });
  expect(r, 460, 'validity');
  const validity: Validity = { notBefore: r.int(), notAfter: r.int(), maxIdle: r.int() };
  expect(r, 461, 'delegation');
  const deleg: Delegation = { maxDepth: r.int(), narrowOnly: r.int() === 1, mayTouch: r.strs() };
  const escalateOn = r.list(() => dCond(r));
  const wildcardAck = r.strs();
  const holes = r.list((): Hole => { expect(r, 470, 'hole'); return { hid: r.str(), q: r.str(), domain: r.strs(), affects: r.strs(), global: r.int() === 1 }; });
  if (!r.done()) throw new IrError('trailing tokens after goal');
  return { v, principal, ontDigest, nlDigest, sources, grants, prohibits, bounds, validity, deleg, escalateOn, wildcardAck, holes };
}
