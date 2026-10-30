// Goal-level mutation operators: each WIDENS (or breaks) one clause. The corpus must kill every non-equivalent mutant: some probe
// of the case must change its decision. Against the real compiler the same mutated goals must compile to the oracle's decisions.
import type { Goal } from './types.ts';

export type Mutant = { op: string; goal: Goal };
const clone = (g: Goal): Goal => JSON.parse(JSON.stringify(g));
export function mutants(g: Goal): Mutant[] {
  const out: Mutant[] = [];
  const push = (op: string, f: (c: Goal) => boolean): void => { const c = clone(g); if (f(c)) out.push({ op, goal: c }); };
  g.prohibits.forEach((_, i) => push('drop_prohibit', (c) => { c.prohibits.splice(i, 1); return true; }));
  g.bounds.forEach((b, i) => {
    push('drop_bound', (c) => { c.bounds.splice(i, 1); return true; });
    push('widen_cap', (c) => { c.bounds[i]!.cap = { ...c.bounds[i]!.cap, n: c.bounds[i]!.cap.n * 2 + 1 }; return true; });
    if (b.window.k === 'sliding') push('widen_window', (c) => { (c.bounds[i]!.window as { ms: number }).ms = 1; return true; });
    if (b.scope.k !== 'session') push('narrow_scope_to_session', (c) => { c.bounds[i]!.scope = { k: 'session' }; return true; });
    if (b.onExceed === 'deny') push('deny_to_escalate', (c) => { c.bounds[i]!.onExceed = 'escalate'; return true; });
  });
  g.grants.forEach((gr, i) => {
    if (gr.cond.k !== 'true') push('drop_where', (c) => { c.grants[i]!.cond = { k: 'true' }; return true; });
    if (gr.res.k !== 'any') push('widen_resource_any', (c) => { c.grants[i]!.res = { k: 'any', reason: 'm' }; if (!c.wildcardAck.includes(gr.gid)) c.wildcardAck.push(gr.gid); return true; });
    if (gr.res.k === 'all_of') push('all_of_to_first_part', (c) => { const r = c.grants[i]!.res; if (r.k === 'all_of') c.grants[i]!.res = r.parts[0]!; return true; });
  });
  push('widen_validity', (c) => { c.validity = { notBefore: 0, notAfter: 9_007_199_254_740_991, maxIdle: 0 }; return JSON.stringify(g.validity) !== JSON.stringify(c.validity); });
  push('widen_delegation', (c) => { c.deleg = { maxDepth: 16, narrowOnly: true, mayTouch: c.grants.map((x) => x.gid) }; return JSON.stringify(g.deleg) !== JSON.stringify(c.deleg); });
  push('drop_hole', (c) => { c.holes = []; return g.holes.length > 0; });
  push('drop_escalate_on', (c) => { c.escalateOn = []; return g.escalateOn.length > 0; });
  return out;
}
