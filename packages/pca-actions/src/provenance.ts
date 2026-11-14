// provenance.ts - the facts the default `authorize()` provenance gate reads (spec provenance-by-default, section 5), derived from
// signed ActionDefs. "Unconfirmed means maximally dangerous": a def without a valid signed confirmation reports no effects and the
// top trait set (sensitive), and its `provenance_min` relaxations are ignored. Only a confirmed def can say "this only reads" or
// "this parameter may come from a tool".

import type { ProvActionInfo, ProvFloor } from '@atlasauth/pca';
import type { ActionDef } from './def';
import { CORE_REGISTRY } from './core-traits';
import { isConfirmed, traitsOf, type ReviewOpts } from './effective';
import { normalize } from './normalize';
import type { Registry } from './traits';

/** The gate facts of one def under a trait registry (default: the core registry). */
export function provenanceInfoOf(d: ActionDef, reg: Registry = CORE_REGISTRY, opts: ReviewOpts = {}): ProvActionInfo {
  const traits = traitsOf(d, reg, opts);
  if (!isConfirmed(d, opts)) return { effects: [], traits };
  const n = normalize(d);
  const params: Record<string, ProvFloor> = {};
  for (const [name, p] of Object.entries(n.params)) if (p.provenance_min !== undefined) params[name] = p.provenance_min;
  return { effects: [...n.effects], traits, ...(Object.keys(params).length ? { params } : {}) };
}

/**
 * The `provenance.actions` resolver for `authorize()`: the facts of the def whose verb (or alias) is the operation's verb;
 * `undefined` for an unknown verb (the gate then treats the action as sensitive). Two defs claiming one name throw at build time.
 */
export function provenanceActions(defs: readonly ActionDef[], reg: Registry = CORE_REGISTRY, opts: ReviewOpts = {}): (op: { verb: string }) => ProvActionInfo | undefined {
  const byVerb = new Map<string, ProvActionInfo>();
  for (const d of defs) {
    const n = normalize(d);
    const info = provenanceInfoOf(d, reg, opts);
    for (const v of [n.verb, ...n.aliases]) {
      if (byVerb.has(v)) throw new Error(`provenanceActions: two definitions claim the verb '${v}'`);
      byVerb.set(v, info);
    }
  }
  return (op) => byVerb.get(op.verb);
}
