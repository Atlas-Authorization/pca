import { compilePolicy, type Caveat, type Condition, type ConditionOp, type Predicate } from '@atlasauth/pca';
import type { IntentSlots, SlotConstraint } from '../src';

/**
 * Shared types and tiny builders for the hand-written seed set (bench/cases.ts and bench/cases/*.ts).
 *
 * A case is: what the principal said (text), what intent capture extracted (slots), the principal's hidden ACTUAL
 * intent (truth), the single-shot grant a compiler produced (candidate), and the hand label (faithful: candidate ≡
 * truth). The harness re-derives every label exactly over a cell grid that contains both policies' literals.
 *
 * v2 features are represented by the Ω̃ dimensions they add to a grant (Intent Layer v2 §2): the predicate DSL reads
 * them like any other path. The benchmark measures grant FIDELITY over those dimensions; it does not run the v2
 * runtime machinery that fills them (ledgers, oracles, classifiers, label receipts, frame snapshots).
 *   schema        action.params.<name>, env.canon.<name> (booleans / sets as canonical text)
 *   accumulator   env.acc.<id>.post            (the post-action value of a session accumulator)
 *   monitor       env.mon.<id>.state           (a session monitor's state)
 *   session_delta a union of the task grant and principal-signed delta grants (extra predicates)
 *   offers        env.world.<name>_excess      (price above the cheapest matching signed offer)
 *   facts         env.world.<name>             (signed oracle facts)
 *   provenance    env.prov.<param path>        (first_party / trusted / tool / web / agent)
 *   classifier    env.class.<id>               (an attested classifier's label)
 *   frame         env.effect.writes            (the canonical write set of the action, frame-closed intent)
 *   read_purpose  action.params.data_class × env.session.purpose (read cells, §3.16)
 *   layers        an org / site / standing-profile ceiling intersected into the effective grant (§2.4)
 */

export type Category =
  | 'faithful'
  | 'ambiguous_phrasing'
  | 'scope_creep'
  | 'unit_error'
  | 'wrong_recipient'
  | 'prompt_injection'
  | 'off_by_one'
  | 'missing_constraint'
  | 'over_restriction'
  | 'out_of_class';

/** The website task family of a case (the original 56 are 'core': developer / ops connectors). */
export type Family =
  | 'core'
  | 'shopping'
  | 'travel'
  | 'banking'
  | 'saas_admin'
  | 'email'
  | 'calendar'
  | 'forms'
  | 'publishing'
  | 'account_settings'
  | 'data_export';

export type Feature =
  | 'schema'
  | 'accumulator'
  | 'monitor'
  | 'session_delta'
  | 'offers'
  | 'facts'
  | 'provenance'
  | 'classifier'
  | 'frame'
  | 'read_purpose'
  | 'layers';

export interface Policy {
  predicates: Predicate[];
  caveats: Caveat[];
}

export interface BenchCase {
  id: string;
  category: Category;
  text: string;
  slots: IntentSlots;
  truth: Policy;
  candidate: Policy;
  faithful: boolean;
  note?: string;
  /** Website task family (default 'core'). */
  family?: Family;
  /** v2 features the case exercises (see the header). */
  features?: Feature[];
  /** Adversarial (an attacker shaped the candidate) or ambiguous (the words admit two readings). */
  tags?: ('adversarial' | 'ambiguous')[];
}

// ---- builders ------------------------------------------------------------------------------------------
export const AMT = 'action.params.amount';
export const RCP = 'action.params.recipient';
export const CH = 'action.params.channel';
export const TO = 'action.params.to';
export const QTY = 'action.params.quantity';
export const CNT = 'action.params.count';
export const HR = 'env.hour';
export const RES = 'action.resource';
export const acc = (id: string): string => `env.acc.${id}.post`;
export const mon = (id: string): string => `env.mon.${id}.state`;
export const canon = (name: string): string => `env.canon.${name}`;
export const world = (name: string): string => `env.world.${name}`;
export const prov = (paramPath: string): string => `env.prov.${paramPath}`;
export const cls = (id: string): string => `env.class.${id}`;
export const WRITES = 'env.effect.writes';
export const DCLASS = 'action.params.data_class';
export const PURPOSE = 'env.session.purpose';

export const c = (field: string, op: ConditionOp, value: unknown): Condition => ({ field, op, value });
export const anyOf = (...conds: Condition[]): Condition => ({ any_of: conds });
export const not = (cond: Condition): Condition => ({ not: cond });
export const range = (field: string, lo: number, hi: number): Condition[] => [c(field, 'gte', lo), c(field, 'lte', hi)];
export const amtMax = (m: number, op: 'lte' | 'lt' = 'lte'): Condition[] => [c(AMT, 'gte', 0), c(AMT, op, m)];
export const hours = (lo: number, hi: number): Condition[] => range(HR, lo, hi);
export const p = (verb: string | string[], where?: Condition[], resource = '*'): Predicate => ({ verb, resource, ...(where && where.length ? { where } : {}) });
export const pol = (...predicates: Predicate[]): Policy => ({ predicates, caveats: [] });
export const S = (verbs: string[], ...constraints: SlotConstraint[]): IntentSlots => ({ verbs, constraints });
export const sMax = (path: string, m: number, verb?: string, unit?: string): SlotConstraint => ({ path, max: m, ...(unit ? { unit } : {}), ...(verb ? { verb } : {}) });
export const sRange = (path: string, lo: number, hi: number, verb?: string): SlotConstraint => ({ path, min: lo, max: hi, ...(verb ? { verb } : {}) });
export const sOne = (path: string, vals: string[], verb?: string): SlotConstraint => ({ path, oneOf: vals, ...(verb ? { verb } : {}) });
export const sNone = (path: string, vals: string[], verb?: string): SlotConstraint => ({ path, noneOf: vals, ...(verb ? { verb } : {}) });
export const sUnder = (prefix: string, verb?: string): SlotConstraint => ({ path: RES, prefixOneOf: [prefix], ...(verb ? { verb } : {}) });
/** A real compiler output (the nl.ts facade), minus the time-dependent expiry. */
export const compiled = (perms: Record<string, string[]>, limits?: Record<string, string>): Policy => {
  const cp = compilePolicy({ permissions: perms, ...(limits ? { limits } : {}), now: 0 });
  return { predicates: cp.predicates, caveats: cp.caveats.filter((x) => x.type === 'reversibility_max') };
};
