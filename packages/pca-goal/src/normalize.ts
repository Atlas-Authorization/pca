import type { Goal } from './ir';

/** Stable JSON (sorted keys, undefined dropped): an in-memory key for maps and sets. NOT a signed encoding (signing uses hashCanonical). */
export function stable(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  const o = v as Record<string, unknown>;
  return '{' + Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + stable(o[k])).join(',') + '}';
}

const byId = <T>(f: (x: T) => string) => (a: T, b: T): number => (f(a) < f(b) ? -1 : f(a) > f(b) ? 1 : 0);

/**
 * Canonical form of a Goal (ir.ts): grants, prohibits, bounds and holes strictly increasing by id in code-unit order, as the
 * typechecker requires (`not_canonical_order`). Duplicated ids are NOT merged: they stay and the typechecker refuses them.
 */
export function canonicalizeGoal(g: Goal): Goal {
  return {
    ...g,
    grants: [...g.grants].sort(byId((x) => x.gid)),
    prohibits: [...g.prohibits].sort(byId((x) => x.pid)),
    bounds: [...g.bounds].sort(byId((x) => x.bid)),
    holes: [...g.holes].sort(byId((x) => x.hid)),
    wildcardAck: [...new Set(g.wildcardAck)].sort(),
    deleg: { ...g.deleg, mayTouch: [...new Set(g.deleg.mayTouch)].sort() },
  };
}
