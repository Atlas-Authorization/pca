// builtin.ts - the 21 built-in connector actions as hand-reviewed ActionDefs (the `core` seed of the catalog packs). This is
// where the inconsistencies between the old catalog and the old ontologies were resolved, once, explicitly: where two sources
// disagreed on a class the STRICTER one was taken (RESOLUTIONS lists each). Authoritative data for the migration shims.

import { blastExactOfFloat } from './compat';
import type { ActionDef, Effect, IdPattern, ParamDef, Rev } from './def';

const SINCE = '0.5.0';
const pattern = (prefix: string, len: [number, number] = [8, 64]): IdPattern => ({ prefix, class: 'any_safe', len });
const anyId = pattern('', [1, 128]);
const idem: ParamDef = { type: 'string', max_len: 128 };
const usd = (): ParamDef => ({ type: 'integer', role: 'money.amount', min: 1, max: 100_000_000_00, unit: { kind: 'money', ccy: 'USD', exp: 2 }, provenance_min: 'first_party' });
const str = (max_len: number, extra: Partial<ParamDef> = {}): ParamDef => ({ type: 'string', max_len, ...extra });
const idOf = (type: string, extra: Partial<ParamDef> = {}): ParamDef => ({ type: 'string', max_len: 128, role: `id.${type}`, ...extra });
const email = (): ParamDef => ({ type: 'string', role: 'contact.email', format: 'email', max_len: 254, tags: ['pii'] });

interface Spec {
  verb: string;
  title: string;
  effects: Effect[];
  rev: Rev;
  type: string;
  id: IdPattern;
  scope?: 'one' | 'set';
  params: Record<string, ParamDef>;
  aliases?: string[];
  keyed?: boolean;
  description?: string;
  traits?: string[];
  audience?: 'resource';
  compensates?: string;
  mcp?: string;
}

const DESCRIPTIONS: Readonly<Record<string, string>> = {
  'stripe.refund': 'Returns money for a charge to the customer.',
  'stripe.payout': 'Moves funds from a Stripe balance to a bank account.',
  'gmail.send': 'Sends an email to people outside your organisation.',
  'gmail.draft': 'Saves an email draft without sending it.',
  'gmail.delete': 'Permanently deletes a message.',
  'stripe.create_customer': 'Creates a customer record.',
  'github.read': 'Reads files from a repository.',
  'github.create_pr': 'Opens a pull request, which is visible to everyone with access to the repository.',
  'github.comment': 'Posts a comment, visible to everyone with access to the repository.',
  'github.merge_pr': 'Merges a pull request, which can trigger deploys and other downstream effects.',
  'github.delete_repo': 'Deletes a repository and everything in it.',
  'slack.post_message': 'Posts a message that members of the channel can read.',
  'slack.read': 'Reads the message history of a channel.',
  'calendar.create_event': 'Creates an event and sends invitations to its attendees.',
  'calendar.delete_event': 'Deletes a calendar event.',
  'files.read': 'Reads files.',
  'files.write': 'Writes or overwrites files.',
  'files.delete': 'Deletes files.',
  'http.get': 'Fetches a URL.',
  'http.post': 'Posts a body to a URL.',
};
const EXAMPLES: Readonly<Record<string, NonNullable<ActionDef['examples']>>> = {
  'stripe.charge': [{ params: { customer: 'cus_12345678', amount: 2500, idempotency_key: 'k_1' }, expect: 'escalate' }],
  'stripe.refund': [{ params: { charge: 'ch_12345678', amount: 2500, idempotency_key: 'k_1' }, expect: 'escalate' }],
  'stripe.payout': [{ params: { account: 'acct_12345678', amount: 100000, idempotency_key: 'k_1' }, expect: 'escalate' }],
  'gmail.delete': [{ params: { message: 'msg_1' }, expect: 'escalate' }],
  'github.delete_repo': [{ params: { repo: 'acme/app' }, expect: 'escalate' }],
  'calendar.delete_event': [{ params: { event: 'evt_1' }, expect: 'escalate' }],
  'files.delete': [{ params: { path: '/tmp/a.txt' }, expect: 'escalate' }],
};

function def(s: Spec): ActionDef {
  const params = { ...s.params };
  // free text in an action that sends is an injection channel: say so (lint LW-003)
  if (s.effects.includes('send')) for (const [k, p] of Object.entries(params)) if (p.type === 'string' && p.role === undefined && p.format === undefined && p.values === undefined && !(p.tags ?? []).includes('free_text_outbound')) params[k] = { ...p, tags: [...(p.tags ?? []), 'free_text_outbound'] };
  const description = s.description ?? DESCRIPTIONS[s.verb];
  const examples = EXAMPLES[s.verb];
  if (s.keyed) params.idempotency_key = idem;
  return {
    v: 1,
    kind: 'pca-action-def',
    verb: s.verb,
    ...(s.aliases ? { aliases: s.aliases } : {}),
    title: s.title,
    ...(description ? { description } : {}),
    effects: s.effects,
    resource: { type: s.type, id: s.id, scope: s.scope ?? 'one' },
    params,
    reversibility: s.rev,
    // the old catalog's blast preset, kept as the reviewed declaration so the one blast model never prices a built-in below it
    blast: blastExactOfFloat(LEGACY_CATALOG[s.verb]!.blastRadius),
    ...(s.keyed ? { idempotency: { mode: 'key_param' as const, param: 'idempotency_key' } } : {}),
    ...(s.traits ? { traits: s.traits } : {}),
    ...(s.audience ? { audience: s.audience } : {}),
    ...(s.compensates ? { compensates: s.compensates } : {}),
    ...(examples ? { examples } : {}),
    review: { state: 'authored' },
    since: SINCE,
  };
}

/** What the old catalog said per built-in verb (recorded; the old catalog is deprecated by the migration). */
export const LEGACY_CATALOG: Readonly<Record<string, { reversibility: Rev; blastRadius: number }>> = Object.freeze({
  'stripe.charge': { reversibility: 'reversible', blastRadius: 0.9 }, 'stripe.refund': { reversibility: 'rate_limited', blastRadius: 0.9 },
  'stripe.payout': { reversibility: 'irreversible', blastRadius: 0.9 }, 'stripe.create_customer': { reversibility: 'reversible', blastRadius: 0.2 },
  'gmail.send': { reversibility: 'irreversible', blastRadius: 0.8 }, 'gmail.draft': { reversibility: 'reversible', blastRadius: 0.2 },
  'gmail.delete': { reversibility: 'irreversible', blastRadius: 0.8 }, 'github.read': { reversibility: 'reversible', blastRadius: 0.05 },
  'github.create_pr': { reversibility: 'reversible', blastRadius: 0.2 }, 'github.comment': { reversibility: 'reversible', blastRadius: 0.2 },
  'github.merge_pr': { reversibility: 'rate_limited', blastRadius: 0.5 }, 'github.delete_repo': { reversibility: 'irreversible', blastRadius: 0.8 },
  'slack.post_message': { reversibility: 'rate_limited', blastRadius: 0.5 }, 'slack.read': { reversibility: 'reversible', blastRadius: 0.05 },
  'calendar.create_event': { reversibility: 'reversible', blastRadius: 0.2 }, 'calendar.delete_event': { reversibility: 'rate_limited', blastRadius: 0.5 },
  'files.read': { reversibility: 'reversible', blastRadius: 0.05 }, 'files.write': { reversibility: 'rate_limited', blastRadius: 0.5 },
  'files.delete': { reversibility: 'irreversible', blastRadius: 0.8 }, 'http.get': { reversibility: 'reversible', blastRadius: 0.05 },
  'http.post': { reversibility: 'rate_limited', blastRadius: 0.5 },
});

export const BUILTIN_DEFS: readonly ActionDef[] = Object.freeze([
  // --- Stripe (payments)
  def({ verb: 'stripe.charge', title: 'Charge a customer', effects: ['pay'], rev: 'irreversible', type: 'stripe.customer', id: pattern('cus_'), aliases: ['charge_customer', 'bill'], keyed: true,
    params: { amount: usd(), customer: idOf('stripe.customer') }, description: 'Charge a customer. Refundable in practice, but a charge is treated as final.' }),
  def({ verb: 'stripe.refund', title: 'Refund a charge', effects: ['pay'], rev: 'irreversible', type: 'stripe.charge', id: pattern('ch_'), aliases: ['refund', 'issue_refund', 'reimburse', 'refund_charge'], keyed: true,
    params: { amount: usd(), charge: idOf('stripe.charge') } }),
  def({ verb: 'stripe.payout', title: 'Pay out funds to a bank account', effects: ['pay'], rev: 'irreversible', type: 'stripe.account', id: pattern('acct_'), aliases: ['payout', 'pay_out'], keyed: true,
    params: { amount: usd(), account: idOf('stripe.account') } }),
  def({ verb: 'stripe.create_customer', title: 'Create a customer record', effects: ['create'], rev: 'rate_limited', type: 'stripe.customer', id: pattern('cus_'),
    params: { email: { ...email(), required: false }, name: str(200, { role: 'person.name', required: false, tags: ['pii'] }) } }),
  // --- Email
  def({ verb: 'gmail.send', title: 'Send an email', effects: ['send'], rev: 'irreversible', type: 'gmail.message', id: anyId, aliases: ['send_email'], keyed: true,
    params: { to: email(), subject: str(300), body: str(50_000, { role: 'text.message', tags: ['free_text_outbound'] }) } }),
  def({ verb: 'gmail.draft', title: 'Create an email draft', effects: ['create'], rev: 'reversible', compensates: 'gmail.delete', type: 'gmail.message', id: anyId,
    params: { to: email(), subject: str(300), body: str(50_000, { role: 'text.message' }) } }),
  def({ verb: 'gmail.delete', title: 'Permanently delete a message', effects: ['delete'], rev: 'irreversible', type: 'gmail.message', id: anyId,
    params: { message: idOf('gmail.message') } }),
  // --- GitHub
  def({ verb: 'github.read', title: 'Read repository contents', effects: ['read'], rev: 'reversible', type: 'github.repo', id: anyId,
    params: { repo: idOf('github.repo'), path: str(1024, { role: 'path.fs', tags: ['path'], required: false }) } }),
  def({ verb: 'github.create_pr', title: 'Open a pull request', effects: ['create', 'send'], rev: 'irreversible', audience: 'resource', type: 'github.repo', id: anyId,
    params: { repo: idOf('github.repo'), title: str(256), head: str(256), base: str(256), body: str(50_000, { required: false }) } }),
  def({ verb: 'github.comment', title: 'Comment on an issue or pull request', effects: ['create', 'send'], rev: 'irreversible', audience: 'resource', type: 'github.repo', id: anyId,
    params: { repo: idOf('github.repo'), number: { type: 'integer', min: 1, max: 1_000_000_000 }, body: str(50_000) } }),
  def({ verb: 'github.merge_pr', title: 'Merge a pull request', effects: ['update'], rev: 'irreversible', type: 'github.repo', id: anyId,
    params: { repo: idOf('github.repo'), number: { type: 'integer', min: 1, max: 1_000_000_000 } } }),
  def({ verb: 'github.delete_repo', title: 'Delete a repository', effects: ['delete'], rev: 'irreversible', type: 'github.repo', id: anyId,
    params: { repo: idOf('github.repo') } }),
  // --- Slack
  def({ verb: 'slack.post_message', title: 'Post a message to a channel', effects: ['send'], rev: 'irreversible', type: 'slack.channel', id: '*', scope: 'set', keyed: true,
    params: { channel: str(128, { role: 'contact.address' }), text: str(40_000, { role: 'text.message', tags: ['free_text_outbound'] }) } }),
  def({ verb: 'slack.read', title: 'Read channel history', effects: ['read'], rev: 'reversible', type: 'slack.channel', id: anyId,
    params: { channel: idOf('slack.channel') } }),
  // --- Calendar
  def({ verb: 'calendar.create_event', title: 'Create a calendar event', effects: ['create', 'send'], rev: 'irreversible', type: 'calendar.event', id: anyId,
    params: { summary: str(256), attendees: { type: 'array', items: 'string', role: 'contact.email', tags: ['pii'], min_items: 0, max_items: 100 }, start: { type: 'datetime' }, end: { type: 'datetime' } } }),
  def({ verb: 'calendar.delete_event', title: 'Delete a calendar event', effects: ['delete'], rev: 'rate_limited', type: 'calendar.event', id: anyId,
    params: { event: idOf('calendar.event') } }),
  // --- Files / storage (a path names a set of files: the policy narrows it with a predicate on `path`)
  def({ verb: 'files.read', title: 'Read a file', effects: ['read'], rev: 'reversible', type: 'files.file', id: '*', scope: 'set',
    params: { path: str(4096, { role: 'path.fs', tags: ['path'] }) } }),
  def({ verb: 'files.write', title: 'Write or overwrite a file', effects: ['update'], rev: 'rate_limited', type: 'files.file', id: '*', scope: 'set',
    params: { path: str(4096, { role: 'path.fs', tags: ['path'] }), content: str(1_000_000) } }),
  def({ verb: 'files.delete', title: 'Delete a file', effects: ['delete'], rev: 'irreversible', type: 'files.file', id: '*', scope: 'set',
    params: { path: str(4096, { role: 'path.fs', tags: ['path'] }) } }),
  // --- Generic HTTP
  def({ verb: 'http.get', title: 'HTTP GET', effects: ['read'], rev: 'reversible', type: 'http.endpoint', id: '*', scope: 'set',
    params: { url: str(2048, { role: 'url.target', format: 'url' }) } }),
  def({ verb: 'http.post', title: 'HTTP POST', effects: ['update'], rev: 'rate_limited', type: 'http.endpoint', id: '*', scope: 'set',
    params: { url: str(2048, { role: 'url.target', format: 'url' }), body: str(1_000_000, { required: false }) } }),
]);


/** What the old payments ontology said (effect class), for the verbs that exist in both models. */
export const LEGACY_ONTOLOGY_EFFECT: Readonly<Record<string, 'read' | 'reversible' | 'external_send' | 'irreversible'>> = Object.freeze({
  'stripe.refund': 'irreversible', 'stripe.charge': 'irreversible', 'stripe.payout': 'irreversible',
});

export interface Resolution { verb: string; field: string; was: string; now: string; reason: string }
/** Every place the old models disagreed and how it was settled. */
export const RESOLUTIONS: readonly Resolution[] = Object.freeze([
  { verb: 'stripe.refund', field: 'reversibility', was: 'catalog rate_limited / ontology irreversible', now: 'irreversible', reason: 'the stricter class; a refund cannot be taken back' },
  { verb: 'stripe.charge', field: 'reversibility', was: 'catalog reversible / ontology irreversible', now: 'irreversible', reason: 'the stricter class; a refund is a new payment, not an undo' },
  { verb: 'stripe.charge', field: 'name', was: 'catalog stripe.charge / ontology charge_customer', now: 'stripe.charge (aliases charge_customer, bill)', reason: 'one verb, the ontology id becomes an alias' },
  { verb: 'stripe.refund', field: 'name', was: 'catalog stripe.refund / ontology refund', now: 'stripe.refund (aliases refund, issue_refund, reimburse, refund_charge)', reason: 'one verb, the ontology ids become aliases' },
  { verb: 'stripe.payout', field: 'name', was: 'catalog stripe.payout / ontology payout', now: 'stripe.payout (aliases payout, pay_out)', reason: 'one verb' },
  { verb: 'slack.post_message', field: 'reversibility', was: 'catalog rate_limited', now: 'irreversible', reason: 'a send carries the external_communication floor (irreversible); the declaration says what the floor makes true' },
  { verb: 'github.merge_pr', field: 'reversibility', was: 'catalog rate_limited', now: 'irreversible', reason: 'a merge triggers deploys and downstream effects; a revert is a new action, not an undo' },
  { verb: 'github.create_pr', field: 'traits', was: 'none (reversible)', now: 'effects create+send, audience resource (irreversible)', reason: 'visible to other people; the repository is the audience' },
  { verb: 'github.comment', field: 'traits', was: 'none (reversible)', now: 'effects create+send, audience resource (irreversible)', reason: 'visible to other people; the repository is the audience' },
  { verb: 'calendar.create_event', field: 'traits', was: 'none (reversible)', now: 'effects create+send, attendees recipient param (irreversible)', reason: 'it sends invites' },
  { verb: 'stripe.create_customer', field: 'reversibility', was: 'catalog reversible', now: 'rate_limited', reason: 'the pack has no action that undoes it, and a reversible write must name one' },
  { verb: '*', field: 'blast', was: 'catalog 0.05..0.9 floats', now: 'resource radius + trait floors (ppm)', reason: 'one blast model; the money floor is 700000 ppm' },
  { verb: '*', field: 'money', was: 'amountField / semantic money.* / kind money / envelope units / toolCallRisk option', now: 'param role money.amount + unit {money, ccy, exp}', reason: 'one definition of money' },
]);
