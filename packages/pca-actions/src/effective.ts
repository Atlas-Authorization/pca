// effective.ts - from an ActionDef to its trait set T(d), declared profile decl(d) and effective profile
// eff_R(d) = decl(d) join F_R(T(d)) (spec section 3.4), plus the structural param rules (section 3.3).

import {
  PARAM_RULE_IDS, REV_RANK, SENSITIVITY_RANK, isReadOnly,
  type ActionDef, type Effect, type NormalizedDef, type ParamRuleId, type ResourceScope, type Rev, type TraitId,
} from './def';
import { EFFECT_TRAITS, ROLE_TRAITS, TAG_TRAITS } from './core-traits';
import { effectiveParamSensitivity, normalize, sortUniq, worstReversibility } from './normalize';
import { closure, floorOf, join, profile, topTraits, type Profile, type Registry } from './traits';

/** How a verifier decides whether a `confirmed` review counts (the signature check lives in the registry layer, A3/A4). */
export interface ReviewOpts {
  /** True iff the def's attestation is valid: bound to this def digest, signed by a pinned reviewer key. Absent => never. */
  attestationVerified?: (def: ActionDef) => boolean;
}

/** What the trait implication reads. A signed schema verb carries all of it except the resource scope. */
export interface ImplFacts {
  effects: readonly Effect[];
  scope?: ResourceScope;
  worstRev: Rev;
  params: readonly { type: string; role?: string; tags?: readonly string[]; max_items?: number }[];
}

/** Traits implied by effects, roles, tags, scope and reversibility. Monotone in each. */
export function impliedFromFacts(f: ImplFacts): TraitId[] {
  const out: TraitId[] = [];
  for (const e of f.effects) out.push(...EFFECT_TRAITS[e]);
  const readOnly = isReadOnly(f.effects);
  for (const p of f.params) {
    if (p.role !== undefined) {
      if (Object.prototype.hasOwnProperty.call(ROLE_TRAITS, p.role)) out.push(...ROLE_TRAITS[p.role]!);
      if (readOnly && p.role.startsWith('money.')) out.push('pca.financial_data_read');
    }
    for (const t of p.tags ?? []) if (Object.prototype.hasOwnProperty.call(TAG_TRAITS, t)) out.push(...TAG_TRAITS[t]!);
    if (p.type === 'array' && p.max_items === undefined) out.push('pca.bulk');
  }
  if (f.scope !== undefined && f.scope !== 'one') out.push('pca.bulk');
  if (f.worstRev === 'irreversible') out.push('pca.irreversible');
  return sortUniq(out);
}

export const impliedTraits = (n: NormalizedDef): TraitId[] =>
  impliedFromFacts({ effects: n.effects, scope: n.resource.scope, worstRev: worstReversibility(n.reversibility, n.params), params: Object.values(n.params) });

/** True iff the def carries a valid human confirmation (a signed review attestation); the caller's verifier decides. Absent => never. */
export const isConfirmed = (d: ActionDef, opts: ReviewOpts = {}): boolean => opts.attestationVerified?.(d) === true;

/**
 * The machine/author view of a def's traits: declared plus implied-by-its-own-facts. A HINT: it is what the def would have if a
 * reviewer signed it as it stands. It never reaches enforcement unless a signed confirmation says so (see {@link traitsOf}).
 */
export const hintTraits = (d: ActionDef): TraitId[] => {
  const n = normalize(d);
  return sortUniq([...n.traits, ...impliedTraits(n)]);
};

/**
 * T(d), the EFFECTIVE trait set. "Unconfirmed means maximally dangerous": without a valid signed confirmation it is the TOP of the
 * registry (every trait, so every high-risk core trait and `pca.unreviewed`), whatever the def, an importer, a pack, a suggestion
 * rule or a model said. Only a signed confirmation sets it to what the reviewer signed (declared) plus what the signed def's own
 * facts imply (both only add).
 */
export function traitsOf(d: ActionDef, reg: Registry, opts: ReviewOpts = {}): TraitId[] {
  return isConfirmed(d, opts) ? hintTraits(d) : topTraits(reg);
}

/** decl(d): what the author declared (reversibility, blast, context, derived risk), without any trait floor. */
export function declProfile(d: ActionDef): Profile {
  const n = normalize(d);
  const critical = Object.values(n.params).some((p) => SENSITIVITY_RANK[effectiveParamSensitivity(p)] >= SENSITIVITY_RANK.critical);
  return profile({
    risk: critical ? 2 : isReadOnly(n.effects) ? 0 : 1,
    rev: worstReversibility(n.reversibility, n.params),
    blast_ppm: n.blast.ppm,
    context: n.context,
  });
}

export interface Clamp {
  field: 'rev' | 'blast_ppm';
  declared: Rev | number;
  floor: Rev | number;
}

/** A trait set with its closure and floor. */
export interface TraitView {
  /** The trait set. */
  traits: TraitId[];
  /** cl_R(traits). */
  closure: TraitId[];
  /** F_R(traits). */
  floor: Profile;
  /** decl join floor. */
  eff: Profile;
}

export interface Effective extends TraitView {
  /** The def has a valid signed confirmation; when false, `traits` is the top of the registry. */
  confirmed: boolean;
  decl: Profile;
  /** What the def would be if confirmed as it stands (declared + implied traits). Review and lint input ONLY: never enforcement. */
  hint: TraitView;
  /** Explicitly declared values that sit below their (hint) floor (lint LD-006); the join clamped them. */
  clamps: Clamp[];
}

export function effective(d: ActionDef, reg: Registry, opts: ReviewOpts = {}): Effective {
  const decl = declProfile(d);
  const view = (traits: TraitId[]): TraitView => {
    const floor = floorOf(reg, traits);
    return { traits, closure: closure(reg, traits), floor, eff: join(decl, floor) };
  };
  const hint = view(hintTraits(d));
  const confirmed = isConfirmed(d, opts);
  const main = confirmed ? hint : view(topTraits(reg));
  const clamps: Clamp[] = [];
  if (d.reversibility !== undefined && REV_RANK[decl.rev] < REV_RANK[hint.floor.rev]) clamps.push({ field: 'rev', declared: decl.rev, floor: hint.floor.rev });
  if (d.blast !== undefined && decl.blast_ppm < hint.floor.blast_ppm) clamps.push({ field: 'blast_ppm', declared: decl.blast_ppm, floor: hint.floor.blast_ppm });
  return { ...main, confirmed, decl, hint, clamps };
}

/** The hint profile after adding trait `t` to the declared traits (T2: never lower). Analysis only. */
export function effWithTrait(d: ActionDef, t: TraitId, reg: Registry): Profile {
  return effective({ ...d, traits: [...(d.traits ?? []), t] }, reg).hint.eff;
}

// ---- structural param rules (section 3.3) ----------------------------------------------------------------------------------

/** Rules the def violates, among `ids` (default: all). A def violating a rule that its traits require is not loadable. */
export function prulesViolations(d: ActionDef, ids: readonly ParamRuleId[] = PARAM_RULE_IDS): ParamRuleId[] {
  const n = normalize(d);
  const ps = Object.entries(n.params);
  const withRole = (pred: (r: string) => boolean) => ps.filter(([, p]) => p.role !== undefined && pred(p.role));
  const bad: ParamRuleId[] = [];
  for (const id of ids) {
    let ok = true;
    switch (id) {
      case 'money_has_currency':
        ok = withRole((r) => r === 'money.amount' || r === 'money.fee').every(([, p]) => {
          const u = p.unit;
          if (!u || u.kind !== 'money') return false;
          if (typeof u.ccy === 'string') return true;
          const c = n.params[u.ccy.from];
          return c !== undefined && c.role === 'money.currency' && c.format === 'iso_currency';
        });
        break;
      case 'money_amount_bounded':
        ok = withRole((r) => r === 'money.amount').every(([, p]) => p.type === 'integer' && p.min !== undefined && p.max !== undefined);
        break;
      case 'id_not_wildcard':
        ok = !(n.resource.id === '*' && n.resource.scope === 'one');
        break;
      case 'recipient_param_declared':
        ok = n.audience === 'resource' || withRole((r) => r === 'party.payee' || r.startsWith('contact.')).length > 0;
        break;
      case 'array_bounded':
        ok = ps.filter(([, p]) => p.type === 'array').every(([, p]) => p.max_items !== undefined);
        break;
      case 'export_bounded':
        ok = n.resource.scope === 'one' || withRole((r) => r === 'count.limit').some(([, p]) => p.max !== undefined);
        break;
      case 'secret_not_logged':
        ok = withRole((r) => r.startsWith('credential.')).every(([, p]) => (p.tags ?? []).includes('secret'));
        break;
      case 'pay_has_idempotency':
        ok = !n.effects.includes('pay') || n.idempotency.mode !== 'none';
        break;
    }
    if (!ok) bad.push(id);
  }
  return bad;
}

/** Rules the def's effective profile requires but the def does not satisfy (the load-time check). */
export function requiredPrulesViolated(d: ActionDef, eff: Profile): ParamRuleId[] {
  return prulesViolations(d, eff.prules);
}
