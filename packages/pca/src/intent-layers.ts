import { evaluatePredicates, type ActionContext, type Predicate } from './predicates';

/**
 * LAYERED INTENT: THE VERIFIER SIDE (Intent Layer v2 §2.4, §3.5, §5 check `layers`; milestone V5; T18).
 *
 * Layers are subsets of Ω̃: G^org (org / operator ceiling), G^site (the site's own policy), G^std (the principal's
 * standing profile rules) and G^task (the task map's grant G^task_0 and the principal-signed deltas D_1 … D_k). The
 * effective grant is G^org ∩ G^site ∩ G^std ∩ (G^task_0 ∪ D_1 ∪ … ∪ D_k) minus vetoed cells, and DENY ANYWHERE WINS:
 * an action outside a ceiling is denied with reason `ceiling` and is NEVER a question (the principal cannot widen a
 * ceiling). So whatever the task layer and its deltas admit, an admitted action is inside every ceiling (T18).
 *
 * Every layer is a predicate set evaluated by the ONE predicate evaluator (`evaluatePredicates`), with the same
 * action context as the admitting root's predicates (including the verifier-computed `env.acc`, `env.world`,
 * `env.prov`, `env.class`): no new evaluator, which is the W-A rule for native verifiers. An ABSENT layer is Ω̃ (no
 * constraint); a layer PRESENT with JSON `null` or any value that is not `{predicates: [...]}` is MALFORMED and fails
 * closed (README "absent vs null"): never read as "no constraint". The wallet-side lattice over cells, owner risk and quorum-signed shared-layer approvals live in
 * `@atlasauth/pca-intent` (`layers.ts`).
 */

export type CeilingKind = 'org' | 'site' | 'std';
export const LAYER_CEILINGS: readonly CeilingKind[] = ['org', 'site', 'std'];

/** A layer as a predicate set. */
export interface LayerPolicy {
  predicates: Predicate[];
}

export interface LayerCeilings {
  org?: LayerPolicy;
  site?: LayerPolicy;
  std?: LayerPolicy;
}

export interface LayeredGrant extends LayerCeilings {
  /** G^task_0 followed by every delta D_1 … D_k (admitting = any of them admits). */
  task: LayerPolicy[];
  /** Vetoed regions and cells with p = 0, as predicate sets: any match denies (`intent_denied`). */
  denied?: LayerPolicy[];
}

export type LayerDecision =
  | { decision: 'admit'; by: number }
  | { decision: 'ceiling'; layer: CeilingKind }
  | { decision: 'intent_denied' }
  | { decision: 'intent_required' };

const isPlain = (l: unknown): l is Record<string, unknown> =>
  l !== null && typeof l === 'object' && !Array.isArray(l) && [Object.prototype, null].includes(Object.getPrototypeOf(l));
/** Every own key of `o` is in `allowed` (closed member set). */
const closedTo = (o: Record<string, unknown>, allowed: readonly string[]): boolean => Object.keys(o).every((k) => allowed.includes(k));

/** A well-formed layer: a plain object with exactly one member, `predicates`, an array (closed member set). */
export const isLayerPolicy = (l: unknown): l is LayerPolicy =>
  isPlain(l) && closedTo(l, ['predicates']) && Object.prototype.hasOwnProperty.call(l, 'predicates') && Array.isArray(l.predicates);

const layerAdmits = (l: LayerPolicy, ctx: ActionContext): boolean => evaluatePredicates(l.predicates, ctx).allowed;

const own = (o: object, k: string): unknown => (Object.prototype.hasOwnProperty.call(o, k) ? (o as Record<string, unknown>)[k] : undefined);

/**
 * The `layers` check of the v2 verification order (§5): the action must be inside G^org, then G^site, then G^std
 * (absent = Ω̃). The first ceiling that denies is named. `layers` must be a plain object with no member other than
 * `org`, `site`, `std` (an unknown member fails, reported as `org`); a layer is exactly `{predicates: [...]}`; a ceiling present with
 * `null` or any value other than `{predicates: [...]}` is malformed and fails (named), as does an empty predicate list
 * (it admits nothing). Never throws.
 */
export function decideLayerCeilings(layers: LayerCeilings, ctx: ActionContext): { status: 'pass' } | { status: 'fail'; layer: CeilingKind; reason: string } {
  if (isPlain(layers) && !closedTo(layers, LAYER_CEILINGS)) return { status: 'fail', layer: 'org', reason: 'layers: unknown member (the layers object is {org?, site?, std?})' };
  return ceilingsOf(layers, ctx);
}

function ceilingsOf(layers: unknown, ctx: ActionContext): { status: 'pass' } | { status: 'fail'; layer: CeilingKind; reason: string } {
  try {
    if (!isPlain(layers)) return { status: 'fail', layer: 'org', reason: 'layers: the layers member is malformed (not an object)' };
    for (const k of LAYER_CEILINGS) {
      const layer = own(layers, k);
      if (layer === undefined) continue;
      if (!isLayerPolicy(layer)) return { status: 'fail', layer: k, reason: `layers: the ${k} ceiling is malformed (null or not {predicates: [...]})` };
      if (!layerAdmits(layer, ctx)) return { status: 'fail', layer: k, reason: `layers: the action is outside the ${k} ceiling (a ceiling is never a question)` };
    }
    return { status: 'pass' };
  } catch (e) {
    return { status: 'fail', layer: 'org', reason: `layers: evaluation error (fail closed): ${(e as Error).message}` };
  }
}

/**
 * The full layer decision for one action (§3.3 step 2 after the schema check), in order:
 *   1. outside G^org, then G^site, then G^std → `ceiling`;
 *   2. inside a denied region (veto, p = 0) → `intent_denied`;
 *   3. inside G^task_0 or some delta → `admit` (`by` = 0 for G^task_0, k for D_k);
 *   4. otherwise → `intent_required` (an uncertain cell: the lazy question).
 * A malformed ceiling is step 1's `ceiling`. A grant member other than org / site / std / task / denied is malformed:
 * `intent_denied`. A `denied` member that is present but not an array, or a `task` member
 * that is not an array (it is required), or any of their entries that is not `{predicates: [...]}`, is malformed and
 * yields `intent_denied` (fail closed: never a question, never an admission). Absent `denied` = []. Never throws.
 */
export function decideLayers(g: LayeredGrant, ctx: ActionContext): LayerDecision {
  try {
    if (isPlain(g) && !closedTo(g, [...LAYER_CEILINGS, 'task', 'denied'])) return { decision: 'intent_denied' };
    const c = ceilingsOf(g, ctx);
    if (c.status === 'fail') return { decision: 'ceiling', layer: c.layer };
    const deniedIn = own(g, 'denied');
    const denied = deniedIn === undefined ? [] : deniedIn;
    const task = own(g, 'task');
    if (!Array.isArray(denied) || !denied.every(isLayerPolicy) || !Array.isArray(task) || !task.every(isLayerPolicy)) return { decision: 'intent_denied' };
    for (const d of denied) if (layerAdmits(d, ctx)) return { decision: 'intent_denied' };
    for (let i = 0; i < task.length; i++) if (layerAdmits(task[i]!, ctx)) return { decision: 'admit', by: i };
    return { decision: 'intent_required' };
  } catch {
    return { decision: 'intent_denied' };
  }
}
