// card.ts - the human-readable PolicyCard text. A fixed phrase table over the IR: no model, no summarising, every clause with its
// exact numbers. The lossless guarantee (G-T10) is on the token tape (`renderTape`); this text is a pure function of the same goal
// and prints every field the tape carries, so two different goals never print the same card (tested field by field).
import type { Bound, Cond, Delegation, Goal, Grant, Hole, Prohibit, Validity, Quantity, ResSel, Term, Unit, Value, Window, Scope } from './ir';

export const q = (x: string): string => JSON.stringify(x);
export const unit = (u: Unit): string => (u.k === 'money' ? `${u.ccy} minor units` : u.k);
export const quantity = (x: Quantity): string => `${x.n} ${unit(x.u)}`;
export const value = (v: Value): string => (v.k === 'q' ? quantity(v.q) : v.k === 's' ? q(v.s) : `{${v.items.map((i) => value(i.k === 'q' ? i : i)).join(', ')}}`);
export const term = (t: Term): string => (t.k === 'param' ? `param ${q(t.path)} (${t.ty.k === 'q' ? unit(t.ty.u) : 'text'})` : t.k === 'lit' ? value(t.v) : `running total of bound ${q(t.bid)} (${unit(t.u)})`);
const OPW = { eq: '=', ne: '!=', lt: '<', lte: '<=', gt: '>', gte: '>=', in: 'is one of', nin: 'is none of' } as const;
export function cond(c: Cond): string {
  switch (c.k) {
    case 'true': return 'always';
    case 'cmp': return `${term(c.l)} ${OPW[c.op]} ${term(c.r)}`;
    case 'and': return `(${cond(c.a)}) AND (${cond(c.b)})`;
    case 'or': return `(${cond(c.a)}) OR (${cond(c.b)})`;
    case 'not': return `NOT (${cond(c.c)})`;
  }
}
export const res = (s: ResSel): string =>
  s.k === 'exact' ? `exactly ${q(s.id)}` : s.k === 'oneof' ? `one of [${s.ids.map(q).join(', ')}]` : s.k === 'related' ? `${s.rel} of ${q(s.anchor)}`
  : s.k === 'all_of' ? `ALL OF (${s.parts.map(res).join(' AND ')})` : `ANY RESOURCE (reason: ${q(s.reason)})`;
export const win = (w: Window): string => (w.k === 'task' ? 'per task' : w.k === 'lifetime' ? 'over the lifetime' : w.k === 'sliding' ? `in any ${w.ms} ms window` : `per ${w.ms} ms period starting at ${w.t0}`);
export const scope = (s: Scope): string => (s.k === 'fleet' ? `fleet [${s.agents.map(q).join(', ')}]` : s.k);


export const grantLine = (x: Grant): string => `ALLOW ${q(x.gid)}: verb ${q(x.verb)} on ${res(x.res)} when ${cond(x.cond)}`;
export const prohibitLine = (x: Prohibit): string => `NEVER ${q(x.pid)}: ${x.target.k === 'verb' ? `verb ${q(x.target.verb)}` : `every verb of effect class ${q(x.target.cls)}`} on ${res(x.res)} when ${cond(x.cond)}`;
export function boundLine(b: Bound): string {
  const over = b.sel.k === 'gids' ? `grants [${b.sel.gids.map(q).join(', ')}]` : `effect class ${q(b.sel.cls)}`;
  return `LIMIT ${q(b.bid)}: ${b.agg}${b.agg === 'count' ? '' : b.agg === 'distinct' ? ` of ${q(b.key)}` : ` of ${term(b.value)}`} over ${over}, ${win(b.window)}, scope ${scope(b.scope)}, at most ${quantity(b.cap)}; beyond that: ${b.onExceed === 'deny' ? 'deny' : 'ask the principal'}`;
}
export const validityLine = (v: Validity): string => `VALID from ${v.notBefore} to ${v.notAfter}; idle limit ${v.maxIdle > 0 ? `${v.maxIdle} ms` : 'none'}`;
export const delegationLine = (d: Delegation): string => `DELEGATION depth at most ${d.maxDepth}, narrow only ${d.narrowOnly}, delegates may use grants [${d.mayTouch.map(q).join(', ')}]`;
export const escalateLine = (c: Cond): string => `ASK THE PRINCIPAL when ${cond(c)}`;
export const holeLine = (h: Hole): string => `UNRESOLVED ${q(h.hid)}: ${q(h.q)} options [${h.domain.map(q).join(', ')}] affects ${h.global ? 'everything' : `[${h.affects.map(q).join(', ')}]`}`;

/** One line per clause, in the goal's canonical order. `warnings` lists what the principal must look at twice (red on a screen). */
export function renderCard(g: Goal): { lines: string[]; warnings: string[] } {
  const lines: string[] = [`Goal v${g.v} for principal ${q(g.principal)}; ontology ${q(g.ontDigest)}; request text digest ${q(g.nlDigest)}`];
  const warnings: string[] = [];
  for (const s of g.sources) lines.push(`Source ${q(s)}`);
  for (const x of g.grants) {
    lines.push(grantLine(x));
    if (x.res.k === 'any') warnings.push(`grant ${q(x.gid)} applies to every resource${g.wildcardAck.includes(x.gid) ? ' (acknowledged)' : ' (NOT acknowledged)'}`);
  }
  for (const x of g.prohibits) lines.push(prohibitLine(x));
  for (const b of g.bounds) lines.push(boundLine(b));
  lines.push(validityLine(g.validity));
  lines.push(delegationLine(g.deleg));
  for (const c of g.escalateOn) lines.push(escalateLine(c));
  for (const a of g.wildcardAck) lines.push(`Wildcard acknowledged for ${q(a)}`);
  for (const h of g.holes) lines.push(holeLine(h));
  if (g.holes.length > 0) warnings.push('this goal has unresolved questions and cannot be signed');
  return { lines, warnings };
}
