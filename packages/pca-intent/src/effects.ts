import { evaluatePredicates, isGroupCondition, isLeafCondition, type ActionContext, type Condition } from '@atlasauth/pca';
import type { IntentLearner } from './learner';
import { applyDivergence } from './map';
import type { Outcome, VerbSpace } from './omega';
import { outcomeToAction } from './policy';

/**
 * OUTCOME VERIFICATION: POSTCONDITIONS ON OBSERVED EFFECTS (spec §4.5 item 1, roadmap M5).
 *
 * A postcondition is a set of conditions in the ordinary predicate DSL over the requested action
 * (`action.params.*`, `action.resource`) and the OBSERVED effect, placed at `env.effect.*` (the resource server's
 * own record: a Stripe event, a git ref, a sent-mail header). It is evaluated by the one PCA evaluator
 * (`evaluatePredicates`), never re-implemented here. The effect oracle is trusted (spec §4.5 failure modes): a
 * postcondition detects a divergence only as well as the oracle reports what happened.
 *
 * Results are three-valued:
 *   ok        every applicable clause holds;
 *   violated  some applicable clause fails: a negative runtime observation, which vetoes the cell (§4.6);
 *   pending   the effect record lacks a field some clause reads (the oracle lags): nothing is concluded.
 * A clause whose `ref` names an action parameter the action does not carry is NOT APPLICABLE and skipped (e.g. a
 * recipient check on a refund whose recipient is not part of the request).
 */

export interface EffectPostcondition {
  id: string;
  verb: string;
  description: string;
  where: Condition[];
}

const eff = (field: string) => `env.effect.${field}`;

/** Postconditions for the built-in connectors' state-changing verbs. */
export const DEFAULT_POSTCONDITIONS: EffectPostcondition[] = [
  { id: 'stripe.refund.amount', verb: 'stripe.refund', description: 'the refunded amount is at most the requested amount', where: [{ field: eff('amount'), op: 'lte', ref: 'action.params.amount' }, { field: eff('amount'), op: 'gte', value: 0 }] },
  { id: 'stripe.refund.recipient', verb: 'stripe.refund', description: 'the refund went to the requested recipient', where: [{ field: eff('recipient'), op: 'eq', ref: 'action.params.recipient' }] },
  { id: 'stripe.charge.amount', verb: 'stripe.charge', description: 'the charged amount is at most the requested amount', where: [{ field: eff('amount'), op: 'lte', ref: 'action.params.amount' }, { field: eff('amount'), op: 'gte', value: 0 }] },
  { id: 'stripe.payout.amount', verb: 'stripe.payout', description: 'the paid-out amount is at most the requested amount', where: [{ field: eff('amount'), op: 'lte', ref: 'action.params.amount' }, { field: eff('amount'), op: 'gte', value: 0 }] },
  { id: 'stripe.payout.recipient', verb: 'stripe.payout', description: 'the payout went to the requested recipient', where: [{ field: eff('recipient'), op: 'eq', ref: 'action.params.recipient' }] },
  { id: 'gmail.send.to', verb: 'gmail.send', description: 'the mail went only to the requested address', where: [{ field: eff('to'), op: 'eq', ref: 'action.params.to' }] },
  { id: 'slack.post_message.channel', verb: 'slack.post_message', description: 'the message was posted in the requested channel', where: [{ field: eff('channel'), op: 'eq', ref: 'action.params.channel' }] },
  { id: 'files.write.path', verb: 'files.write', description: 'the written path is the requested resource', where: [{ field: eff('path'), op: 'eq', ref: 'action.resource' }] },
  { id: 'files.delete.path', verb: 'files.delete', description: 'the deleted path is the requested resource', where: [{ field: eff('path'), op: 'eq', ref: 'action.resource' }] },
  { id: 'github.merge_pr.repo', verb: 'github.merge_pr', description: 'the merge landed in the requested repository', where: [{ field: eff('repo'), op: 'eq', ref: 'action.resource' }] },
  { id: 'calendar.create_event.hour', verb: 'calendar.create_event', description: 'the event starts at the requested hour', where: [{ field: eff('hour'), op: 'eq', ref: 'env.hour' }] },
];

function leaves(c: Condition, out: { field: string; ref?: string }[]): void {
  if (c === null || typeof c !== 'object') return;
  if (isGroupCondition(c)) {
    if ('all_of' in c && Array.isArray(c.all_of)) c.all_of.forEach((x) => leaves(x, out));
    else if ('any_of' in c && Array.isArray(c.any_of)) c.any_of.forEach((x) => leaves(x, out));
    else if ('not' in c) leaves(c.not, out);
    return;
  }
  if (isLeafCondition(c)) out.push({ field: c.field, ...(typeof c.ref === 'string' ? { ref: c.ref } : {}) });
}

function get(root: Record<string, unknown>, path: string): unknown {
  let cur: unknown = root;
  for (const k of path.split('.')) {
    if (cur === null || typeof cur !== 'object' || !Object.prototype.hasOwnProperty.call(cur, k)) return undefined;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur;
}

export interface EffectReport {
  status: 'ok' | 'violated' | 'pending';
  violated: string[];
  /** effect fields some applicable clause needs and the record lacks. */
  missing: string[];
  checked: string[];
  notApplicable: string[];
}

/** The evaluator's context for an action plus its observed effect. */
export function effectContext(vs: VerbSpace, o: Outcome, effect: Record<string, unknown>): ActionContext {
  const a = outcomeToAction(vs, o);
  return { action: { verb: a.verb, resource: a.resource, params: a.params, reversibility_class: vs.reversibility }, ...(a.subject ? { subject: a.subject } : {}), env: { ...(a.env ?? {}), effect } };
}

export function checkPostconditions(vs: VerbSpace, o: Outcome, effect: Record<string, unknown>, pcs: readonly EffectPostcondition[] = DEFAULT_POSTCONDITIONS): EffectReport {
  const ctx = effectContext(vs, o, effect);
  const root = ctx as unknown as Record<string, unknown>;
  const rep: EffectReport = { status: 'ok', violated: [], missing: [], checked: [], notApplicable: [] };
  for (const pc of pcs) {
    if (pc.verb !== o.verb) continue;
    const ls: { field: string; ref?: string }[] = [];
    pc.where.forEach((c) => leaves(c, ls));
    if (ls.some((l) => l.ref !== undefined && !l.ref.startsWith('env.effect.') && get(root, l.ref) === undefined)) {
      rep.notApplicable.push(pc.id);
      continue;
    }
    const need = [...new Set(ls.flatMap((l) => [l.field, ...(l.ref ? [l.ref] : [])]).filter((f) => f.startsWith('env.effect.')))];
    const lacking = need.filter((f) => get(root, f) === undefined);
    if (lacking.length) {
      rep.missing.push(...lacking);
      continue;
    }
    rep.checked.push(pc.id);
    const r = evaluatePredicates([{ verb: o.verb, resource: '*', where: pc.where }], ctx);
    if (!r.allowed) rep.violated.push(pc.id);
  }
  rep.missing = [...new Set(rep.missing)].sort();
  rep.status = rep.violated.length ? 'violated' : rep.missing.length ? 'pending' : 'ok';
  return rep;
}

/**
 * Check an executed action's effect and feed the result back (spec §4.6): a violation is a negative runtime
 * observation that vetoes the action's cell. `ok` and `pending` change nothing (a met postcondition is not the
 * principal's endorsement, so it never widens the grant).
 */
export function verifyOutcome(l: IntentLearner, o: Outcome, effect: Record<string, unknown>, pcs: readonly EffectPostcondition[] = DEFAULT_POSTCONDITIONS): { report: EffectReport; divergence?: ReturnType<typeof applyDivergence> } {
  const vs = l.omega.verbs.find((v) => v.verb === o.verb);
  if (!vs) throw new Error(`verifyOutcome: no verb ${o.verb} in Ω`);
  const report = checkPostconditions(vs, o, effect, pcs);
  if (report.status !== 'violated') return { report };
  return { report, divergence: applyDivergence(l, o, 0) };
}
