import type { Condition, Predicate } from '@atlasauth/pca';

/**
 * STRUCTURED INTENT SLOTS: the machine-readable half of an intent statement (spec §3.1). The natural-language
 * text is what the principal said; the slots are what intent capture extracted from it. Both are signed
 * together, so a later dispute can show exactly which reading was committed to.
 *
 * Slots are deliberately a SMALL vocabulary (verbs, numeric bounds, value sets, prefix scopes) that maps
 * one-to-one onto Ω's dimension kinds. That is what makes the back-translation diff exact.
 */

export interface SlotConstraint {
  /** Restrict to one verb; omitted = applies to every slot verb. */
  verb?: string;
  /** Dotted predicate path (`action.params.amount`, `action.params.recipient`, `env.hour`, `action.resource`). */
  path: string;
  /** Inclusive upper bound. */
  max?: number;
  /** Inclusive lower bound. */
  min?: number;
  /** Allowed exact values. */
  oneOf?: string[];
  /** Forbidden exact values. */
  noneOf?: string[];
  /** Allowed prefixes (e.g. a resource subtree). */
  prefixOneOf?: string[];
  /** Free-text unit annotation shown to the human ("USD", "hour, 24h clock"). Not interpreted. */
  unit?: string;
}

export interface IntentSlots {
  /** The verbs the principal meant to allow. */
  verbs: string[];
  constraints: SlotConstraint[];
}

function slotConds(sc: SlotConstraint): Condition[] {
  const out: Condition[] = [];
  if (sc.min !== undefined) out.push({ field: sc.path, op: 'gte', value: sc.min });
  if (sc.max !== undefined) out.push({ field: sc.path, op: 'lte', value: sc.max });
  const anyOf: Condition[] = [];
  if (sc.oneOf?.length) anyOf.push({ field: sc.path, op: 'in', value: [...sc.oneOf] });
  for (const p of sc.prefixOneOf ?? []) anyOf.push({ field: sc.path, op: 'prefix', value: p });
  if (anyOf.length === 1) out.push(anyOf[0]!);
  else if (anyOf.length > 1) out.push({ any_of: anyOf });
  if (sc.noneOf?.length) out.push({ field: sc.path, op: 'nin', value: [...sc.noneOf] });
  return out;
}

/** Compile slots into the policy they literally describe (one predicate per slot verb). */
export function slotsToPolicy(slots: IntentSlots): { predicates: Predicate[]; caveats: [] } {
  const predicates: Predicate[] = slots.verbs.map((verb) => {
    const where = slots.constraints.filter((c) => c.verb === undefined || c.verb === verb).flatMap(slotConds);
    return { verb, resource: '*', ...(where.length ? { where } : {}) };
  });
  return { predicates, caveats: [] };
}
