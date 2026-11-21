// domain.ts - the Goal IR's domain vocabularies (payments, email, code, data, travel) as ActionDefs (spec section 10: "Ontologies
// become generated `toOntology(pack)`; aliases/templates remain in the NL layer, pointing at pack verbs"). Every verb the
// hand-written ontologies declared is a def here (the payments verbs reuse the reviewed built-ins), and a binding names the
// short NL id, the NL resource type and which def parameters the NL layer surfaces. The effect class of each verb is DERIVED
// (`effectClass`), never assigned: `domainVerbs` is the only producer of an ontology's `verbs` and `aliases`.
//
// The four send/publish/export verbs (mail.send, mail.forward, repo.release, data.export) declare `rate_limited` so that the
// derived class stays `external_send` (the class goals already prohibit by name). The trait floors still apply in full: the
// three that send or publish are irreversible in effect (a test pins that), and the export keeps its resource-scope and
// count-cap caveats. Only the 4-class adapter differs from the built-in connector verbs.

import type { ActionDef, Effect, IdPattern, ParamDef, Rev } from './def';
import { BUILTIN_DEFS } from './builtin';
import { CORE_REGISTRY } from './core-traits';
import { effectClass, toOntology, type EffectClass, type OntParamOut } from './derive';
import { blastExactOfFloat } from './compat';
import type { Registry } from './traits';

const SINCE = '0.5.0';
const pattern = (prefix: string, len: [number, number] = [4, 64]): IdPattern => ({ prefix, class: 'any_safe', len });
const usd = (): ParamDef => ({ type: 'integer', role: 'money.amount', min: 1, max: 100_000_000_00, unit: { kind: 'money', ccy: 'USD', exp: 2 } });
const idOf = (type: string, extra: Partial<ParamDef> = {}): ParamDef => ({ type: 'string', max_len: 128, role: `id.${type}`, ...extra });
const str = (max_len: number, extra: Partial<ParamDef> = {}): ParamDef => ({ type: 'string', max_len, ...extra });
const enumOf = (values: string[]): ParamDef => ({ type: 'string', values, max_len: 32 });
const count = (): ParamDef => ({ type: 'integer', min: 0, max: 1_000_000_000, unit: { kind: 'count' } });

interface Spec {
  verb: string; title: string; effects: Effect[]; rev: Rev; type: string; id: IdPattern; params: Record<string, ParamDef>;
  aliases: string[]; scope?: 'one' | 'set'; blast: number; keyed?: boolean;
}
function def(s: Spec): ActionDef {
  const params = { ...s.params };
  if (s.keyed) params.idempotency_key = str(128);
  return {
    v: 1, kind: 'pca-action-def', verb: s.verb, aliases: s.aliases, title: s.title, effects: s.effects,
    resource: { type: s.type, id: s.id, scope: s.scope ?? 'one' }, params, reversibility: s.rev, blast: blastExactOfFloat(s.blast),
    ...(s.keyed ? { idempotency: { mode: 'key_param' as const, param: 'idempotency_key' } } : {}),
    review: { state: 'authored' }, since: SINCE,
  };
}

const LABELS = ['important', 'follow_up', 'receipts', 'newsletters', 'later'];
const AIRPORTS = ['SFO', 'LAX', 'JFK', 'LHR', 'CDG', 'NRT', 'AUS', 'SEA'];

/** The defs the domain vocabularies add to the built-in pack (the payments domain also uses `stripe.charge|refund|payout`). */
export const DOMAIN_DEFS: readonly ActionDef[] = Object.freeze([
  // --- payments
  def({ verb: 'stripe.read_charge', title: 'Read a charge', effects: ['read'], rev: 'reversible', type: 'stripe.charge', id: pattern('ch_'), aliases: ['read_charge', 'view_charge'], blast: 0.05, params: { charge: idOf('stripe.charge') } }),
  def({ verb: 'stripe.transfer', title: 'Transfer funds to an account', effects: ['pay'], rev: 'irreversible', type: 'stripe.account', id: pattern('acct_'), aliases: ['transfer', 'send_money'], blast: 0.9, keyed: true, params: { amount: usd(), account: idOf('stripe.account') } }),
  def({ verb: 'stripe.cancel_subscription', title: 'Cancel a subscription', effects: ['update'], rev: 'reversible', type: 'stripe.subscription', id: pattern('sub_'), aliases: ['cancel_subscription', 'cancel_plan'], blast: 0.2, params: { subscription: idOf('stripe.subscription') } }),
  // --- email (an abstract mailbox/thread domain, distinct from the gmail connector verbs)
  def({ verb: 'mail.read_thread', title: 'Read a mail thread', effects: ['read'], rev: 'reversible', type: 'mail.thread', id: pattern('th_'), aliases: ['read_thread', 'open', 'read'], blast: 0.05, params: { thread: idOf('mail.thread') } }),
  def({ verb: 'mail.label', title: 'Label a mail thread', effects: ['update'], rev: 'reversible', type: 'mail.thread', id: pattern('th_'), aliases: ['label', 'tag'], blast: 0.2, params: { thread: idOf('mail.thread'), label: enumOf(LABELS) } }),
  def({ verb: 'mail.archive', title: 'Archive a mail thread', effects: ['update'], rev: 'reversible', type: 'mail.thread', id: pattern('th_'), aliases: ['archive', 'file_away'], blast: 0.2, params: { thread: idOf('mail.thread') } }),
  def({ verb: 'mail.delete', title: 'Permanently delete a mail thread', effects: ['delete'], rev: 'irreversible', type: 'mail.thread', id: pattern('th_'), aliases: ['delete', 'trash', 'remove'], blast: 0.8, params: { thread: idOf('mail.thread') } }),
  def({ verb: 'mail.send', title: 'Send a mail message', effects: ['send'], rev: 'rate_limited', type: 'mail.thread', id: pattern('th_'), aliases: ['send', 'reply', 'respond'], blast: 0.8, keyed: true, params: { thread: idOf('mail.thread'), to_domain: str(253) } }),
  def({ verb: 'mail.forward', title: 'Forward a mail message', effects: ['send'], rev: 'rate_limited', type: 'mail.thread', id: pattern('th_'), aliases: ['forward'], blast: 0.8, keyed: true, params: { thread: idOf('mail.thread'), to_domain: str(253) } }),
  // --- code repositories
  def({ verb: 'repo.read', title: 'Read a repository', effects: ['read'], rev: 'reversible', type: 'repo.repo', id: pattern('repo_'), aliases: ['read_repo', 'clone', 'fetch'], blast: 0.05, params: { repo: idOf('repo.repo') } }),
  def({ verb: 'repo.create_branch', title: 'Create a branch', effects: ['create'], rev: 'reversible', type: 'repo.repo', id: pattern('repo_'), aliases: ['create_branch', 'open_branch'], blast: 0.2, params: { repo: idOf('repo.repo'), branch: idOf('ref') } }),
  def({ verb: 'repo.push', title: 'Push commits to a branch', effects: ['update'], rev: 'reversible', type: 'repo.repo', id: pattern('repo_'), aliases: ['push', 'commit_and_push'], blast: 0.2, params: { repo: idOf('repo.repo'), branch: idOf('ref'), protected: enumOf(['yes', 'no']) } }),
  def({ verb: 'repo.merge', title: 'Merge a branch', effects: ['update'], rev: 'irreversible', type: 'repo.repo', id: pattern('repo_'), aliases: ['merge'], blast: 0.5, params: { repo: idOf('repo.repo'), branch: idOf('ref'), protected: enumOf(['yes', 'no']) } }),
  def({ verb: 'repo.release', title: 'Publish a release', effects: ['publish'], rev: 'rate_limited', type: 'repo.repo', id: pattern('repo_'), aliases: ['release', 'publish', 'ship'], blast: 0.8, params: { repo: idOf('repo.repo') } }),
  def({ verb: 'repo.delete_branch', title: 'Delete a branch', effects: ['delete'], rev: 'irreversible', type: 'repo.repo', id: pattern('repo_'), aliases: ['delete_branch', 'remove_branch'], blast: 0.5, params: { repo: idOf('repo.repo'), branch: idOf('ref'), protected: enumOf(['yes', 'no']) } }),
  // --- data access
  def({ verb: 'data.query', title: 'Query a dataset', effects: ['read'], rev: 'reversible', type: 'data.dataset', id: pattern('ds_'), aliases: ['query', 'select', 'read_rows'], blast: 0.05, params: { dataset: idOf('data.dataset'), column_class: enumOf(['public', 'internal', 'pii']), rows: count(), purpose: enumOf(['analytics', 'support', 'research', 'marketing']) } }),
  def({ verb: 'data.export', title: 'Export a dataset', effects: ['export'], rev: 'rate_limited', type: 'data.dataset', id: pattern('ds_'), aliases: ['export', 'download', 'dump'], blast: 0.8, params: { dataset: idOf('data.dataset'), column_class: enumOf(['public', 'internal', 'pii']), rows: count(), purpose: enumOf(['analytics', 'support', 'research', 'marketing']) } }),
  def({ verb: 'data.delete_dataset', title: 'Delete a dataset', effects: ['delete'], rev: 'irreversible', type: 'data.dataset', id: pattern('ds_'), aliases: ['delete_dataset', 'drop', 'purge'], blast: 0.8, params: { dataset: idOf('data.dataset') } }),
  // --- travel
  def({ verb: 'travel.search', title: 'Search trips', effects: ['read'], rev: 'reversible', type: 'travel.trip', id: pattern('trip_'), aliases: ['search', 'find_flights', 'look_up'], blast: 0.05, params: { destination: enumOf(AIRPORTS) } }),
  def({ verb: 'travel.hold', title: 'Hold a trip', effects: ['create'], rev: 'reversible', type: 'travel.trip', id: pattern('trip_'), aliases: ['hold', 'reserve'], blast: 0.2, params: { price: usd(), destination: enumOf(AIRPORTS) } }),
  def({ verb: 'travel.book', title: 'Book a trip', effects: ['pay'], rev: 'irreversible', type: 'travel.trip', id: pattern('trip_'), aliases: ['book', 'purchase', 'buy_ticket'], blast: 0.9, keyed: true, params: { price: usd(), destination: enumOf(AIRPORTS), depart: { type: 'datetime' } } }),
  def({ verb: 'travel.cancel_booking', title: 'Cancel a booking', effects: ['delete'], rev: 'irreversible', type: 'travel.booking', id: pattern('bk_'), aliases: ['cancel_booking', 'cancel_flight'], blast: 0.5, params: { booking: idOf('travel.booking') } }),
]);

/** Every def the domain vocabularies and the connector catalog are built from: one pack, one alias namespace. */
export const CORE_PACK_DEFS: readonly ActionDef[] = Object.freeze([...BUILTIN_DEFS, ...DOMAIN_DEFS]);

/** A domain verb: the NL short id, the def it is, the NL resource type, and which def params the NL layer surfaces (NL name -> def name). */
export interface DomainVerb { id: string; verb: string; resourceType: string; params: Record<string, string>; ccys?: readonly string[] }
export type DomainName = 'payments' | 'email' | 'code_repos' | 'data_access' | 'calendar_travel';

const CCYS = ['USD', 'EUR', 'GBP', 'JPY'] as const;
export const DOMAIN_VERBS: Readonly<Record<DomainName, readonly DomainVerb[]>> = Object.freeze<Record<DomainName, readonly DomainVerb[]>>({
  payments: [
    { id: 'read_charge', verb: 'stripe.read_charge', resourceType: 'charge', params: {} },
    { id: 'refund', verb: 'stripe.refund', resourceType: 'charge', params: { amount: 'amount' }, ccys: CCYS },
    { id: 'charge_customer', verb: 'stripe.charge', resourceType: 'customer', params: { amount: 'amount' }, ccys: CCYS },
    { id: 'transfer', verb: 'stripe.transfer', resourceType: 'account', params: { amount: 'amount' }, ccys: CCYS },
    { id: 'payout', verb: 'stripe.payout', resourceType: 'account', params: { amount: 'amount' }, ccys: CCYS },
    { id: 'cancel_subscription', verb: 'stripe.cancel_subscription', resourceType: 'subscription', params: {} },
  ],
  email: [
    { id: 'read_thread', verb: 'mail.read_thread', resourceType: 'thread', params: {} },
    { id: 'label', verb: 'mail.label', resourceType: 'thread', params: { label: 'label' } },
    { id: 'archive', verb: 'mail.archive', resourceType: 'thread', params: {} },
    { id: 'delete', verb: 'mail.delete', resourceType: 'thread', params: {} },
    { id: 'send', verb: 'mail.send', resourceType: 'thread', params: { to_domain: 'to_domain' } },
    { id: 'forward', verb: 'mail.forward', resourceType: 'thread', params: { to_domain: 'to_domain' } },
  ],
  code_repos: [
    { id: 'read_repo', verb: 'repo.read', resourceType: 'repo', params: {} },
    { id: 'create_branch', verb: 'repo.create_branch', resourceType: 'repo', params: { branch: 'branch' } },
    { id: 'push', verb: 'repo.push', resourceType: 'repo', params: { branch: 'branch', protected: 'protected' } },
    { id: 'merge', verb: 'repo.merge', resourceType: 'repo', params: { branch: 'branch', protected: 'protected' } },
    { id: 'release', verb: 'repo.release', resourceType: 'repo', params: {} },
    { id: 'delete_branch', verb: 'repo.delete_branch', resourceType: 'repo', params: { branch: 'branch', protected: 'protected' } },
  ],
  data_access: [
    { id: 'query', verb: 'data.query', resourceType: 'dataset', params: { column_class: 'column_class', rows: 'rows', purpose: 'purpose' } },
    { id: 'export', verb: 'data.export', resourceType: 'dataset', params: { column_class: 'column_class', rows: 'rows', purpose: 'purpose' } },
    { id: 'delete_dataset', verb: 'data.delete_dataset', resourceType: 'dataset', params: {} },
  ],
  calendar_travel: [
    { id: 'search', verb: 'travel.search', resourceType: 'trip', params: { destination: 'destination' } },
    { id: 'hold', verb: 'travel.hold', resourceType: 'trip', params: { price: 'price', destination: 'destination' }, ccys: CCYS },
    { id: 'book', verb: 'travel.book', resourceType: 'trip', params: { price: 'price', destination: 'destination', depart: 'depart' }, ccys: CCYS },
    { id: 'cancel_booking', verb: 'travel.cancel_booking', resourceType: 'booking', params: {} },
  ],
});

/** The def behind an NL short id; throws on a binding that names no def (a build-time defect). */
const defOf = (verb: string): ActionDef => {
  const d = CORE_PACK_DEFS.find((x) => x.verb === verb);
  if (!d) throw new Error(`domain binding names unknown def '${verb}'`);
  return d;
};

export interface DomainOntVerb { id: string; effect: EffectClass; resource_type: string; params: Record<string, OntParamOut> }

/**
 * The `verbs` and `aliases` of a domain ontology, derived from the defs. The effect class is `effectClass(def)`; each surfaced
 * parameter's kind comes from the def parameter (a money parameter lists the domain's accepted currencies when the binding names
 * them); the aliases are the defs' aliases other than the short id.
 */
export function domainVerbs(domain: DomainName, reg: Registry = CORE_REGISTRY): { verbs: DomainOntVerb[]; aliases: Record<string, string> } {
  const bindings = DOMAIN_VERBS[domain];
  const onto = toOntology(bindings.map((b) => defOf(b.verb)), reg);
  const verbs: DomainOntVerb[] = [];
  const aliases: Record<string, string> = {};
  for (const b of bindings) {
    const d = defOf(b.verb);
    if (!(d.aliases ?? []).includes(b.id)) throw new Error(`domain binding '${b.id}' is not an alias of '${b.verb}'`);
    const ov = onto.verbs.find((v) => v.id === b.verb)!;
    const params: Record<string, OntParamOut> = {};
    for (const [nl, dp] of Object.entries(b.params)) {
      const p = ov.params[dp];
      if (!p) throw new Error(`domain binding '${b.id}' surfaces unknown parameter '${dp}'`);
      params[nl] = p.kind === 'money' && b.ccys ? { kind: 'money', ccys: [...b.ccys] } : p;
    }
    verbs.push({ id: b.id, effect: effectClass(d), resource_type: b.resourceType, params });
    for (const a of d.aliases ?? []) if (a !== b.id) aliases[a] = b.id;
  }
  return { verbs, aliases };
}

/** The role map of a domain verb for the selector layer: role -> NL parameter names carrying it. */
export function domainRoles(domain: DomainName): Record<string, Record<string, string[]>> {
  const out: Record<string, Record<string, string[]>> = {};
  for (const b of DOMAIN_VERBS[domain]) {
    const d = defOf(b.verb);
    const roles: Record<string, string[]> = {};
    for (const [nl, dp] of Object.entries(b.params)) {
      const r = d.params[dp]?.role;
      if (r !== undefined) (roles[r] ??= []).push(nl);
    }
    out[b.id] = roles;
  }
  return out;
}
