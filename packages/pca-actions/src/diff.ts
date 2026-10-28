// diff.ts - the semantic diff of two versions of one ActionDef (spec section 7.3). The class answers one question for a grant that
// pinned the OLD digest: is the NEW definition no more permissive?
//   equal         only text (title, description, compensates) differs
//   narrow        every call the new def accepts is accepted by the old one, and every restriction of the old one still holds
//   widen         the new def accepts calls the old one refused, or drops a restriction
//   incomparable  one dimension widens while another narrows, or the change has no order (a unit, a binding, a role swap)
// Only equal and narrow let a pin follow the change without the principal. The classification is conservative by construction:
// every dimension is compared with a sound (never optimistic) test, so a def we cannot order is `incomparable`, never `narrow`.
// The soundness oracle (test/diff.test.ts) checks: narrow/equal => conforming calls of the new def conform to the old one and the
// effective profile did not fall.

import {
  ActionKitError, REV_RANK, SENSITIVITY_RANK, PROVENANCE_LEVELS, type NormalizedDef, type ParamDef, type ResourceScope,
} from './def';
import type { ActionDef } from './def';
import { idPatternContains } from './idpattern';
import { effective, type ReviewOpts } from './effective';
import { normalize, worstReversibility } from './normalize';
import { CORE_REGISTRY } from './core-traits';
import { closure, leq, type Profile, type Registry } from './traits';

export type DiffClass = 'equal' | 'narrow' | 'widen' | 'incomparable';
export interface DiffResult {
  class: DiffClass;
  /** One line per differing dimension, sorted: `<dimension>: <narrow|widen|incomparable|text>`. */
  reasons: string[];
}

/** Relation of the NEW value to the OLD one along one dimension. */
type Rel = 'eq' | 'narrow' | 'widen' | 'inc';

const DEFAULT_MAX_LEN = 1024;
const DEFAULT_MAX_ITEMS = 64;
const INF = Number.POSITIVE_INFINITY;

const setRel = (oldS: readonly string[], newS: readonly string[]): Rel => {
  const o = new Set(oldS);
  const n = new Set(newS);
  const added = [...n].some((x) => !o.has(x));
  const removed = [...o].some((x) => !n.has(x));
  return added && removed ? 'inc' : added ? 'narrow' : removed ? 'widen' : 'eq';
};
/** More restrictive = larger. */
const rankRel = (o: number, n: number): Rel => (n === o ? 'eq' : n > o ? 'narrow' : 'widen');
const sameJson = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

// ---- parameter domains ---------------------------------------------------------------------------------------------------------------

type NP = NormalizedDef['params'][string];

/** Is every value of `inner`'s domain also a value of `outer`'s? Same declared type required. Sound, not complete. */
function domainContains(outer: NP, inner: NP): boolean {
  if (outer.type !== inner.type) return false;
  switch (outer.type) {
    case 'string':
    case 'object_ref': {
      if ((inner.max_len ?? DEFAULT_MAX_LEN) > (outer.max_len ?? DEFAULT_MAX_LEN)) return false;
      if (outer.values !== undefined && (inner.values === undefined || !inner.values.every((v) => outer.values!.includes(v)))) return false;
      return outer.format === undefined || inner.format === outer.format;
    }
    case 'integer':
      return (inner.min ?? -INF) >= (outer.min ?? -INF) && (inner.max ?? INF) <= (outer.max ?? INF);
    case 'duration':
      return Math.max(inner.min ?? 0, 0) >= Math.max(outer.min ?? 0, 0) && (inner.max ?? INF) <= (outer.max ?? INF);
    case 'set': {
      const ov = outer.values ?? [];
      const iv = inner.values ?? [];
      if (!iv.every((v) => ov.includes(v))) return false;
      const oMax = Math.min(outer.max_items ?? ov.length, ov.length);
      const iMax = Math.min(inner.max_items ?? iv.length, iv.length);
      return (inner.min_items ?? 0) >= (outer.min_items ?? 0) && iMax <= oMax;
    }
    case 'array': {
      if ((outer.items ?? 'string') !== (inner.items ?? 'string')) return false;
      if ((inner.min_items ?? 0) < (outer.min_items ?? 0) || (inner.max_items ?? DEFAULT_MAX_ITEMS) > (outer.max_items ?? DEFAULT_MAX_ITEMS)) return false;
      if (outer.items === 'integer') return (inner.min ?? -INF) >= (outer.min ?? -INF) && (inner.max ?? INF) <= (outer.max ?? INF);
      return (inner.max_len ?? DEFAULT_MAX_LEN) <= (outer.max_len ?? DEFAULT_MAX_LEN);
    }
    default:
      return true; // boolean, date, datetime: no domain members
  }
}

/** Is every call (parameter map) conforming to `inner` also conforming to `outer`? Closed world, required members, domains. */
function callsContained(outer: NormalizedDef['params'], inner: NormalizedDef['params']): boolean {
  for (const [name, ip] of Object.entries(inner)) {
    const op = Object.prototype.hasOwnProperty.call(outer, name) ? outer[name] : undefined;
    if (op === undefined || !domainContains(op, ip)) return false;
  }
  for (const [name, op] of Object.entries(outer)) {
    if (!op.required) continue;
    const ip = Object.prototype.hasOwnProperty.call(inner, name) ? inner[name] : undefined;
    if (ip === undefined || !ip.required) return false;
  }
  return true;
}

function callSetRel(oldP: NormalizedDef['params'], newP: NormalizedDef['params']): Rel {
  const sub = callsContained(oldP, newP); // accepted(new) within accepted(old)
  const sup = callsContained(newP, oldP);
  return sub && sup ? 'eq' : sub ? 'narrow' : sup ? 'widen' : 'inc';
}

const provRank = (p: ParamDef['provenance_min']): number => (p === undefined ? PROVENANCE_LEVELS.length - 1 : PROVENANCE_LEVELS.indexOf(p));
/** Smaller index = stricter source requirement = narrower. */
const provRel = (o: ParamDef['provenance_min'], n: ParamDef['provenance_min']): Rel => rankRel(-provRank(o), -provRank(n));

const SCOPE_RANK: Readonly<Record<ResourceScope, number>> = { one: 0, set: 1, tenant: 2, global: 3 };
const IDEM_RANK = { none: 0, natural: 1, key_param: 2 } as const;

// ---- the diff ------------------------------------------------------------------------------------------------------------------------

/** Per-parameter attributes that are not call-set membership (role, sensitivity, tags, provenance, unit, accumulators, default). */
function paramAttrRels(o: NP, n: NP): Array<[string, Rel]> {
  const out: Array<[string, Rel]> = [];
  if (o.role !== n.role) {
    // a role carries trait implications and a sensitivity floor: only the case where the new role is no less restrictive on both orders
    out.push(['role', 'inc']);
  }
  out.push(['sensitivity', rankRel(SENSITIVITY_RANK[o.sensitivity], SENSITIVITY_RANK[n.sensitivity])]);
  out.push(['tags', setRel(o.tags ?? [], n.tags ?? [])]);
  out.push(['provenance_min', provRel(o.provenance_min, n.provenance_min)]);
  if (!sameJson(o.unit, n.unit)) out.push(['unit', 'inc']);
  out.push(['accumulates', setRel(o.accumulates ?? [], n.accumulates ?? [])]);
  if (!sameJson(o.default, n.default) || o.principal_neutral_default !== n.principal_neutral_default) out.push(['default', 'inc']);
  return out;
}

/** The semantic diff of `next` against `prev` (both versions of the same verb). Throws `diff_verb` for two different verbs. */
export function diffDefs(prev: ActionDef, next: ActionDef, reg: Registry = CORE_REGISTRY, opts: ReviewOpts = {}): DiffResult {
  if (prev.verb !== next.verb) throw new ActionKitError('diff_verb', `diff compares two versions of one verb, not '${prev.verb}' and '${next.verb}'`);
  const o = normalize(prev);
  const n = normalize(next);
  const rels: Array<[string, Rel]> = [];
  const text = o.title !== n.title || o.description !== n.description || o.compensates !== n.compensates;

  rels.push(['effects', setRel(o.effects, n.effects)]);
  rels.push(['params.accepted_calls', callSetRel(o.params, n.params)]);
  for (const name of Object.keys(o.params).sort()) {
    if (Object.prototype.hasOwnProperty.call(n.params, name)) for (const [k, r] of paramAttrRels(o.params[name]!, n.params[name]!)) rels.push([`params.${name}.${k}`, r]);
  }
  const eo = effective(prev, reg, opts);
  const en = effective(next, reg, opts);
  // the defs as written (declared + implied traits): what each version would enforce once a reviewer signs it
  const profRel = (a: Profile, b: Profile): Rel => (leq(a, b) ? (leq(b, a) ? 'eq' : 'narrow') : leq(b, a) ? 'widen' : 'inc');
  rels.push(['traits', setRel(closure(reg, eo.hint.traits), closure(reg, en.hint.traits))]);
  rels.push(['profile', profRel(eo.hint.eff, en.hint.eff)]);
  // what each version enforces NOW: an unconfirmed def is the registry top. confirmed -> unconfirmed only tightens (narrow);
  // unconfirmed -> confirmed lowers the floors (widen): it is a narrowing only through the signed confirmation the verifier checks
  rels.push(['confirmation', rankRel(eo.confirmed ? 0 : 1, en.confirmed ? 0 : 1)]);
  rels.push(['effective.traits', setRel(closure(reg, eo.traits), closure(reg, en.traits))]);
  rels.push(['effective.profile', profRel(eo.eff, en.eff)]);
  rels.push(['reversibility', rankRel(REV_RANK[worstReversibility(o.reversibility, o.params)], REV_RANK[worstReversibility(n.reversibility, n.params)])]);
  rels.push(['blast', rankRel(o.blast.ppm, n.blast.ppm)]);
  const idem: Rel = o.idempotency.mode === 'key_param' && n.idempotency.mode === 'key_param' && o.idempotency.param !== n.idempotency.param ? 'inc' : rankRel(IDEM_RANK[o.idempotency.mode], IDEM_RANK[n.idempotency.mode]);
  rels.push(['idempotency', idem]);
  rels.push(['context', setRel(o.context, n.context)]);
  rels.push(['side_effects', setRel(o.side_effects.map((s) => `${s.target}|${s.kind}`), n.side_effects.map((s) => `${s.target}|${s.kind}`))]);
  // resource: the id pattern must be no wider; a bigger scope is wider
  let resId: Rel;
  if (sameJson(o.resource.id, n.resource.id)) resId = 'eq';
  else if (idPatternContains(o.resource.id, n.resource.id)) resId = 'narrow';
  else if (idPatternContains(n.resource.id, o.resource.id)) resId = 'widen';
  else resId = 'inc';
  rels.push(['resource.id', o.resource.type !== n.resource.type ? 'inc' : resId]);
  rels.push(['resource.scope', rankRel(-SCOPE_RANK[o.resource.scope], -SCOPE_RANK[n.resource.scope])]);
  // aliases extend what natural language can reach: new aliases widen, dropped ones narrow
  rels.push(['aliases', ((): Rel => { const r = setRel(o.aliases, n.aliases); return r === 'narrow' ? 'widen' : r === 'widen' ? 'narrow' : r; })()]);
  rels.push(['bindings', sameJson(o.bindings, n.bindings) ? 'eq' : 'inc']);

  const diffs = rels.filter(([, r]) => r !== 'eq');
  const reasons = diffs.map(([d, r]) => `${d}: ${r === 'inc' ? 'incomparable' : r}`).sort();
  if (text) reasons.push('text: title, description or compensates changed');
  reasons.sort();
  const has = (r: Rel) => diffs.some(([, x]) => x === r);
  const cls: DiffClass = has('inc') || (has('narrow') && has('widen')) ? 'incomparable' : has('widen') ? 'widen' : has('narrow') ? 'narrow' : 'equal';
  return { class: cls, reasons };
}

/** Does a pin follow this change on its own (no principal)? */
export const diffIsFree = (c: DiffClass): boolean => c === 'equal' || c === 'narrow';
