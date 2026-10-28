// normalize.ts - the canonical authoring form of an ActionDef: every default filled, every set-like array sorted, the
// members that do not define the action (review, examples, source, since) removed. Two authoring forms of the same
// action normalize to one object, hence one digest (./digest).

import {
  BLAST_PPM, REV_RANK, SCOPE_BLAST, SENSITIVITY_RANK, isReadOnly,
  type ActionDef, type DefSensitivity, type NormalizedDef, type ParamDef, type Rev, type ReversibilityDecl,
} from './def';
import { ROLE_SENSITIVITY_FLOOR, TAG_SENSITIVITY_FLOOR } from './core-traits';

export const sortUniq = <T extends string>(xs: readonly T[] | undefined): T[] => [...new Set(xs ?? [])].sort() as T[];

const prune = <T extends object>(o: T): T => {
  for (const k of Object.keys(o) as (keyof T)[]) if (o[k] === undefined) delete o[k];
  return o;
};

const maxSens = (a: DefSensitivity, b: DefSensitivity): DefSensitivity => (SENSITIVITY_RANK[a] >= SENSITIVITY_RANK[b] ? a : b);

/** The sensitivity floor a param's role and tags impose (`free` when neither names one). */
export function sensitivityFloor(p: Pick<ParamDef, 'role' | 'tags'>): DefSensitivity {
  let f: DefSensitivity = 'free';
  if (p.role !== undefined && Object.prototype.hasOwnProperty.call(ROLE_SENSITIVITY_FLOOR, p.role)) f = maxSens(f, ROLE_SENSITIVITY_FLOOR[p.role]!);
  for (const t of p.tags ?? []) if (Object.prototype.hasOwnProperty.call(TAG_SENSITIVITY_FLOOR, t)) f = maxSens(f, TAG_SENSITIVITY_FLOOR[t]!);
  return f;
}

/** The effective sensitivity: the declared value, raised to the floor. */
export const effectiveParamSensitivity = (p: Pick<ParamDef, 'role' | 'tags' | 'sensitivity'>): DefSensitivity => maxSens(p.sensitivity ?? 'free', sensitivityFloor(p));

/** The reversibility a def declares, or the fail-closed default (read-only: reversible; any write: irreversible). */
export function declaredReversibility(d: Pick<ActionDef, 'reversibility' | 'effects'>): ReversibilityDecl {
  return d.reversibility ?? (isReadOnly(d.effects) ? 'reversible' : 'irreversible');
}

const maxRev = (xs: readonly Rev[]): Rev => xs.reduce<Rev>((a, b) => (REV_RANK[b] > REV_RANK[a] ? b : a), 'reversible');

/** Conservative class of a (possibly value-dependent) reversibility declaration: the worst class any call can have. */
export function worstReversibility(r: ReversibilityDecl, params: Record<string, ParamDef>): Rev {
  if (typeof r === 'string') return r;
  const d = params[r.by];
  const mapped = Object.values(r.map);
  // the map covers the whole domain only for a boolean (both spellings) or a string enum
  const domain = d?.type === 'boolean' ? ['true', 'false'] : d?.type === 'string' && d.values ? d.values : null;
  const covered = domain !== null && domain.every((x) => Object.prototype.hasOwnProperty.call(r.map, x));
  return maxRev(covered ? mapped : [...mapped, r.default ?? 'irreversible']);
}

function normalizeParam(p: ParamDef): NormalizedDef['params'][string] {
  const out: Record<string, unknown> = { ...p };
  out.required = p.required ?? true;
  if (p.tags !== undefined) out.tags = sortUniq(p.tags);
  if (p.values !== undefined) out.values = [...p.values];
  out.sensitivity = effectiveParamSensitivity(p);
  if (p.accumulates !== undefined) out.accumulates = sortUniq(p.accumulates);
  else if (p.role === 'money.amount' && p.unit !== undefined && p.unit.kind === 'money' && typeof p.unit.ccy === 'string') out.accumulates = [`money.${p.unit.ccy.toLowerCase()}`];
  return prune(out) as unknown as NormalizedDef['params'][string];
}

/** The authoring-independent form of a def. Assumes a def that passed `validateDef`. */
export function normalize(d: ActionDef): NormalizedDef {
  const rev = declaredReversibility(d);
  const radius = d.blast?.radius ?? SCOPE_BLAST[d.resource.scope];
  const params: NormalizedDef['params'] = {};
  for (const k of Object.keys(d.params).sort()) params[k] = normalizeParam(d.params[k]!);
  const out: NormalizedDef = {
    v: 1,
    kind: d.kind,
    verb: d.verb,
    aliases: sortUniq(d.aliases),
    title: d.title,
    effects: sortUniq(d.effects),
    resource: { type: d.resource.type, id: d.resource.id, scope: d.resource.scope },
    params,
    reversibility: typeof rev === 'string' ? rev : prune({ by: rev.by, map: { ...rev.map }, default: rev.default }),
    blast: { radius, ppm: Math.max(BLAST_PPM[radius], d.blast?.ppm ?? 0) },
    side_effects: [...(d.side_effects ?? [])].map((s) => ({ target: s.target, kind: s.kind })).sort((a, b) => (a.target === b.target ? (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0) : a.target < b.target ? -1 : 1)),
    idempotency: prune({ mode: d.idempotency?.mode ?? 'none', param: d.idempotency?.param }),
    context: sortUniq(d.context),
    traits: sortUniq(d.traits),
    bindings: JSON.parse(JSON.stringify(d.bindings ?? {})) as NormalizedDef['bindings'],
  };
  if (d.description !== undefined) out.description = d.description;
  if (d.audience !== undefined) out.audience = d.audience;
  if (d.compensates !== undefined) out.compensates = d.compensates;
  return out;
}
